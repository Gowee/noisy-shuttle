// Some code are ported from hyper (licensed under MIT):
// https://github.com/hyperium/hyper/blob/f9f65b7aa67fa3ec0267fe015945973726285bc2/src/proto/h2/server.rs
use std::error::Error as StdError;
use std::future::poll_fn;
use std::future::Future;
use std::future::Pending;
use std::io::{self, Cursor, IoSlice};
use std::mem;
use std::pin::Pin;
use std::task::{self, ready, Context, Poll};

use bytes::{Buf, Bytes};
// use h2::client::{ResponseFuture, SendRequest};
use h2::{Reason, RecvStream, SendStream};
use http::header::{HeaderName, CONNECTION, TE, TRAILER, TRANSFER_ENCODING, UPGRADE};
use http::response::Parts;
use http::Response;
use http::{request, HeaderMap, Request};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Duration, Instant};
use tracing::{debug, trace, warn};

use crate::ping::{self, Ponged};
use crate::stream::UpgradedSendStream;
use crate::stream::{H2Upgraded, SendBuf};
use crate::SPEC_WINDOW_SIZE;

pub struct Connection<IO: AsyncRead + AsyncWrite + Unpin> {
    conn: h2::server::Connection<IO, SendBuf<Bytes>>,
    ping: ping::Recorder,
    ponger: Option<ping::Ponger>,
}

#[derive(Clone, Debug)]
pub struct Builder {
    proto_builder: h2::server::Builder,
    adaptive_window: bool,
    keep_alive_interval: Option<Duration>,
    keep_alive_timeout: Duration,
    keep_alive_while_idle: bool,
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Connection<IO> {
    pub async fn accept(&mut self) -> Option<Result<H2Upgraded<Bytes>, crate::Error>> {
        poll_fn(|cx: &mut Context<'_>| self.poll_accept(cx)).await
    }

    pub fn poll_accept(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<H2Upgraded<Bytes>, crate::Error>>> {
        if let Some(ponger) = &mut self.ponger {
            match ponger.poll(cx) {
                Poll::Ready(ping::Ponged::SizeUpdate(wnd)) => {
                    self.conn.set_target_window_size(wnd);
                    let _ = self.conn.set_initial_window_size(wnd);
                }
                Poll::Ready(ping::Ponged::KeepAliveTimedOut) => {
                    debug!("keep-alive timed out, closing connection");
                    self.conn.abrupt_shutdown(h2::Reason::NO_ERROR);
                }
                Poll::Pending => {}
            }
        }

        match ready!(self.conn.poll_accept(cx)) {
            Some(Ok((request, mut respond))) => {
                let (head, recv_stream) = request.into_parts();
                self.ping.record_non_data();
                let send_stream =
                    match respond.send_response(Response::builder().body(()).unwrap(), false) {
                        Ok(send_stream) => send_stream,
                        Err(e) => return Poll::Ready(Some(Err(e.into()))),
                    };
                // TODO: return head
                Poll::Ready(Some(Ok(H2Upgraded {
                    ping: self.ping.clone(),
                    send_stream: unsafe { UpgradedSendStream::new(send_stream) },
                    recv_stream: recv_stream,
                    buf: Bytes::new(),
                })))
            }
            Some(Err(e)) => Poll::Ready(Some(Err(e.into()))),
            None => {
                // no more incoming streams...
                self.ping.ensure_not_timed_out()?;
                trace!("incoming connection complete");
                Poll::Ready(None)
            }
        }
    }
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            proto_builder: Default::default(),
            adaptive_window: false,
            keep_alive_interval: None, // TODO: ok?
            keep_alive_timeout: Duration::from_secs(20),
            keep_alive_while_idle: true,
        }
    }
}

// Some methods are ported from hyper (licensed under MIT).
impl Builder {
    pub fn new(proto_builder: h2::server::Builder) -> Self {
        Self {
            proto_builder,
            ..Default::default()
        }
    }

    /// Sets whether to use an adaptive flow control.
    ///
    /// Enabling this will override the limits set in
    /// `initial_stream_window_size` and
    /// `initial_connection_window_size`.
    pub fn adaptive_window(&mut self, enabled: bool) -> &mut Self {
        self.adaptive_window = enabled;
        if enabled {
            self.proto_builder
                .initial_connection_window_size(SPEC_WINDOW_SIZE);
            self.proto_builder.initial_window_size(SPEC_WINDOW_SIZE);
        }
        self
    }

    /// Sets an interval for HTTP2 Ping frames should be sent to keep a
    /// connection alive.
    ///
    /// Pass `None` to disable HTTP2 keep-alive.
    ///
    /// Default is currently disabled.
    pub fn keep_alive_interval(&mut self, interval: impl Into<Option<Duration>>) -> &mut Self {
        self.keep_alive_interval = interval.into();
        self
    }

    /// Sets a timeout for receiving an acknowledgement of the keep-alive ping.
    ///
    /// If the ping is not acknowledged within the timeout, the connection will
    /// be closed. Does nothing if `keep_alive_interval` is disabled.
    ///
    /// Default is 20 seconds.
    pub fn keep_alive_timeout(&mut self, timeout: Duration) -> &mut Self {
        self.keep_alive_timeout = timeout;
        self
    }

    /// Sets whether HTTP2 keep-alive should apply while the connection is idle.
    ///
    /// If disabled, keep-alive pings are only sent while there are open
    /// request/responses streams. If enabled, pings are also sent when no
    /// streams are active. Does nothing if `keep_alive_interval` is
    /// disabled.
    ///
    /// Default is `false`.
    pub fn keep_alive_while_idle(&mut self, enabled: bool) -> &mut Self {
        self.keep_alive_while_idle = enabled;
        self
    }

    pub async fn handshake<IO: AsyncRead + AsyncWrite + Unpin>(
        &self,
        io: IO,
    ) -> Result<Connection<IO>, crate::Error> {
        let mut conn = self.proto_builder.handshake(io).await?;

        let ping_config = ping::Config {
            bdp_initial_window: if self.adaptive_window {
                debug!(initial = SPEC_WINDOW_SIZE, "adaptive window activated");
                Some(SPEC_WINDOW_SIZE)
            } else {
                None
            },
            keep_alive_interval: self.keep_alive_interval,
            keep_alive_timeout: self.keep_alive_timeout,
            keep_alive_while_idle: self.keep_alive_while_idle,
        };

        let (ping, ponger) = if ping_config.is_enabled() {
            let pp = conn.ping_pong().unwrap();
            let (ping, ponger) = ping::channel(pp, ping_config);
            (ping, Some(ponger))
        } else {
            (ping::disabled(), None)
        };

        Ok(Connection { conn, ping, ponger })
    }
}

pub async fn handshake<IO: AsyncRead + AsyncWrite + Unpin>(
    io: IO,
) -> Result<Connection<IO>, crate::Error> {
    Builder::default()
        .adaptive_window(true)
        .keep_alive_interval(Some(Duration::from_secs(5)))
        .keep_alive_timeout(Duration::from_secs(20))
        .keep_alive_while_idle(true)
        .handshake(io)
        .await
}

// pub trait H2MuxBuilder {
//     fn handshake_h2mux<T>(&self, io: T) -> HandshakeMux<T> {

//     }
// }
