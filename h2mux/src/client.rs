//! Client implementation of h2mux.
use std::future::{poll_fn, Future};
use std::io;
use std::mem;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use h2::client::{ResponseFuture, SendRequest};
use h2::SendStream;
use http::response::Parts;
use http::Request;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Duration;
use tracing::{debug, warn};

use crate::ping::{self, Ponged, Recorder};
use crate::stream::{poll_shutdown, poll_write, H2Stream, H2Upgraded, SendBuf, UpgradedSendStream};
use crate::utils::h2_to_io_error;
use crate::SPEC_WINDOW_SIZE;

/// Client connection that wraps underlying I/O resource.
///
/// Sub-streams may be opened with [`Control`]. The object must be drived persistently with
/// [`Connection::poll`].
pub struct Connection<IO: AsyncRead + AsyncWrite + Unpin> {
    conn: h2::client::Connection<IO, SendBuf<Bytes>>,
    ponger: Option<ping::Ponger>,
}

/// Controller of [`Connection`].
pub struct Control {
    send_request: SendRequest<SendBuf<Bytes>>,
    ping: Recorder,
}

/// Builder of client connection with custom configurations.
#[derive(Clone, Debug)]
pub struct Builder {
    proto_builder: h2::client::Builder,
    adaptive_window: bool,
    keep_alive_interval: Option<Duration>,
    keep_alive_timeout: Duration,
    keep_alive_while_idle: bool,
}

/// Stream multiplexed over a HTTP/2 connection.
///
/// It exists as a prior state of [`H2Stream`] that might not be accepted by the server yet. It can
/// be converted into `H2Stream` as soon as the server responds.
pub struct InFlightH2Stream(StreamInner);

enum StreamInner {
    Pending(SendStream<SendBuf<Bytes>>, ResponseFuture, Recorder),
    Ready(Parts, H2Stream),
    Poisoned,
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Future for Connection<IO> {
    type Output = Result<(), crate::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(ponger) = &mut self.ponger {
            match ponger.poll(cx) {
                Poll::Ready(Ponged::SizeUpdate(wnd)) => {
                    debug!(wnd = wnd, "New window size calculated");
                    self.conn.set_target_window_size(wnd);
                    self.conn.set_initial_window_size(wnd)?;
                }
                Poll::Ready(Ponged::KeepAliveTimedOut) => {
                    warn!("h2 keep-alive timed out");
                    // TODO: close conn here?
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => {}
            }
        }

        Pin::new(&mut self.conn).poll(cx).map_err(|e| e.into())
    }
}

impl Control {
    /// Open a new sub stream with custom request headers.
    /// 
    /// The content of request uri, method and headers has nothing to with the functionality of
    /// h2mux. The caller may store any information or leave it to be [`Default::default`].
    pub async fn open_stream(
        &mut self,
        request: Request<()>,
    ) -> Result<InFlightH2Stream, crate::Error> {
        use StreamInner::*;

        poll_fn(|cx: &mut Context<'_>| self.send_request.poll_ready(cx)).await?;
        let (response_fut, send_stream) = self.send_request.send_request(request, false)?;
        Ok(InFlightH2Stream(Pending(
            send_stream,
            response_fut,
            self.ping.clone(),
        )))
    }
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            proto_builder: Default::default(),
            adaptive_window: false,
            keep_alive_interval: None,
            keep_alive_timeout: Duration::from_secs(20),
            keep_alive_while_idle: false,
        }
    }
}

// Some methods are ported from hyper (licensed under MIT).
impl Builder {
    /// Create a builder from a h2 builder.
    pub fn new(proto_builder: h2::client::Builder) -> Self {
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

    /// Perform h2c handshake over an I/O resource (typically a TLS stream).
    pub async fn handshake<IO: AsyncRead + AsyncWrite + Unpin>(
        &self,
        io: IO,
    ) -> Result<(Control, Connection<IO>), crate::Error> {
        let (send_request, mut conn) = self
            .proto_builder
            .handshake::<_, SendBuf<Bytes>>(io)
            .await?;
        debug!("h2 handshaked");

        let ping_config = ping::Config {
            bdp_initial_window: if self.adaptive_window {
                debug!(initial = SPEC_WINDOW_SIZE, "adaptive window activated");
                // this must match the one set on the h2 builder
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

        let connection = Connection { conn, ponger };
        Ok((Control { send_request, ping }, connection))
    }
}

impl InFlightH2Stream {
    /// Convert the inflight stream into an ready [`H2Stream`] and retrieve back the response headers.
    pub async fn into_ready(self) -> Result<(Parts, H2Stream), h2::Error> {
        match self.0 {
            StreamInner::Pending(send_stream, response_fut, ping) => {
                let (head, recv_stream) = response_fut.await?.into_parts();
                Ok((
                    head,
                    H2Upgraded {
                        ping,
                        send_stream: unsafe { UpgradedSendStream::new(send_stream) },
                        recv_stream,
                        buf: Bytes::new(),
                    },
                ))
            }
            StreamInner::Ready(head, stream) => Ok((head, stream)),
            _ => unreachable!(),
        }
    }

    /// Try to convert the inflight stream into an [`H2Stream`] and retrieve back the response headers, if they are ready.
    pub fn try_into_ready(self) -> Option<(Parts, H2Stream)> {
        match self.0 {
            StreamInner::Ready(head, stream) => Some((head, stream)),
            _ => None,
        }
    }
}

impl AsyncRead for InFlightH2Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        use StreamInner::*;

        let this = self.get_mut();
        loop {
            match mem::replace(&mut this.0, Poisoned) {
                Pending(send_stream, mut response_fut, ping) => {
                    match Pin::new(&mut response_fut).poll(cx) {
                        Poll::Ready(Ok(response)) => {
                            ping.record_non_data();

                            let (head, recv_stream) = response.into_parts();
                            // TODO: handle head
                            this.0 = Ready(
                                head,
                                H2Upgraded {
                                    ping,
                                    send_stream: unsafe { UpgradedSendStream::new(send_stream) },
                                    recv_stream,
                                    buf: Bytes::new(),
                                },
                            );
                        }
                        Poll::Ready(Err(e)) => {
                            // TODO: give back before?
                            ping.ensure_not_timed_out()
                                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

                            debug!("client response error: {}", e);
                            this.0 = Pending(send_stream, response_fut, ping);
                            return Poll::Ready(Err(h2_to_io_error(e)));
                        }
                        Poll::Pending => {
                            this.0 = Pending(send_stream, response_fut, ping);
                            return Poll::Pending;
                        }
                    }
                }
                Ready(head, mut stream) => {
                    let r = Pin::new(&mut stream).poll_read(cx, buf);
                    this.0 = Ready(head, stream);
                    return r;
                }
                Poisoned => {
                    unreachable!();
                }
            }
        }
    }
}

impl AsyncWrite for InFlightH2Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        use StreamInner::*;
        let this = self.get_mut();
        match mem::replace(&mut this.0, Poisoned) {
            Pending(send_stream, response_fut, ping) => {
                let mut send_stream = unsafe { UpgradedSendStream::new(send_stream) };
                let r = poll_write(&mut send_stream, cx, buf);
                this.0 = Pending(unsafe { send_stream.into() }, response_fut, ping);
                r
            }
            Ready(head, mut stream) => {
                let r = Pin::new(&mut stream).poll_write(cx, buf);
                this.0 = Ready(head, stream);
                r
            }
            Poisoned => {
                unreachable!();
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        use StreamInner::*;

        let this = self.get_mut();
        match mem::replace(&mut this.0, Poisoned) {
            Pending(send_stream, response_fut, ping) => {
                let mut send_stream = unsafe { UpgradedSendStream::new(send_stream) };
                let r = poll_shutdown(&mut send_stream, cx);
                this.0 = Pending(unsafe { send_stream.into() }, response_fut, ping);
                r
            }
            Ready(head, mut stream) => {
                let r = Pin::new(&mut stream).poll_shutdown(cx);
                this.0 = Ready(head, stream);
                r
            }
            Poisoned => {
                unreachable!();
            }
        }
    }
}

/// Perform h2c handshake over an I/O resource (typically a TLS stream).
///
/// It is a shortcut for [`Builder::handshake`] with default configs.
///
/// # Note
/// The default configs leaves initial connection/stream window size to the default spec value of
/// 64KiB, which is too small for general network environment. It is possible to specify reasonable
/// values (e.g. 15MiB/6MiB in [Chromium](https://source.chromium.org/search?q=kSpdySessionMaxRecvWindowSize)) or activate adaptive window with [`Builder`].
pub async fn handshake<IO: AsyncRead + AsyncWrite + Unpin>(
    io: IO,
) -> Result<(Control, Connection<IO>), crate::Error> {
    Builder::default().handshake(io).await
}
