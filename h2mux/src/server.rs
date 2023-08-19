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
use tracing::{debug, trace, warn};

use crate::ping::{self, Ponged};
use crate::stream::UpgradedSendStream;
use crate::stream::{H2Upgraded, SendBuf};

pub struct Connection<IO: AsyncRead + AsyncWrite + Unpin> {
    conn: h2::server::Connection<IO, SendBuf<Bytes>>,
    ping: ping::Recorder,
    ponger: ping::Ponger,
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Connection<IO> {
    pub async fn accept(&mut self) -> Option<Result<H2Upgraded<Bytes>, crate::Error>> {
        poll_fn(|cx: &mut Context<'_>| self.poll_accept(cx)).await
    }

    pub fn poll_accept(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<H2Upgraded<Bytes>, crate::Error>>> {
        match self.ponger.poll(cx) {
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

pub async fn handshake<IO: AsyncRead + AsyncWrite + Unpin>(
    io: IO,
) -> Result<Connection<IO>, crate::Error> {
    let mut conn = h2::server::Builder::new().handshake(io).await?;

    let pp = conn.ping_pong().unwrap();
    // TODO: configurable
    let (ping, ponger) = ping::channel(
        pp,
        ping::Config {
            bdp_initial_window: Some(1024 * 1024),
            keep_alive_interval: Some(std::time::Duration::from_secs(1)),
            keep_alive_timeout: std::time::Duration::from_secs(2),
            keep_alive_while_idle: false,
        },
    );
    Ok(Connection { conn, ping, ponger })
}
