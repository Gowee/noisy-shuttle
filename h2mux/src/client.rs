// use pin_project_lite::pin_project;
use std::error::Error as StdError;
use std::future::poll_fn;
use std::future::Future;
use std::future::Pending;
use std::io::{self, Cursor, IoSlice};
use std::mem;
use std::pin::Pin;
use std::task::{self, ready, Context, Poll};

use bytes::{Buf, Bytes};
use h2::client::{ResponseFuture, SendRequest};
use h2::{Reason, RecvStream, SendStream};
use http::header::{HeaderName, CONNECTION, TE, TRAILER, TRANSFER_ENCODING, UPGRADE};
use http::response::Parts;
use http::{request, HeaderMap, Request};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, info, trace, warn};

use crate::ping::{self, Ponged, Recorder};
use crate::stream::{
    poll_read, poll_shutdown, poll_write, H2Upgraded, SendBuf, UpgradedSendStream,
};
use crate::utils::H2MapIoErr;

#[derive(Error, Debug)]
pub enum Error {
    #[error("h2 layer error")]
    H2Error(#[from] h2::Error),
    #[error("pong timed out")]
    KeepAliveTimedOut,
}

// pub type Result = Result

pub struct Connection<IO: AsyncRead + AsyncWrite + Unpin> {
    conn: h2::client::Connection<IO, SendBuf<Bytes>>,
    ponger: ping::Ponger,
}

pub struct Control {
    send_request: SendRequest<SendBuf<Bytes>>,
    ping: Recorder,
}

pub struct PendingStream(EPendingStream);

enum EPendingStream {
    Pending(SendStream<SendBuf<Bytes>>, ResponseFuture, Recorder),
    Ready(H2Upgraded<Bytes>, Parts),
    Poisoned,
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Future for Connection<IO> {
    type Output = Result<(), crate::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.ponger.poll(cx) {
            Poll::Ready(Ponged::SizeUpdate(wnd)) => {
                info!(wnd = wnd, "New window size calculated");
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

        Pin::new(&mut self.conn).poll(cx).map_err(|e| e.into())
    }
}

impl Control {
    pub async fn open_stream(&mut self, request: Request<()>) -> Result<PendingStream, Error> {
        use EPendingStream::*;

        poll_fn(|cx: &mut Context<'_>| self.send_request.poll_ready(cx)).await?;
        let (response_fut, send_stream) = self.send_request.send_request(request, false)?;
        Ok(PendingStream(Pending(
            send_stream,
            response_fut,
            self.ping.clone(),
        )))
    }
}

impl PendingStream {
    pub async fn into_ready(self) -> Result<(H2Upgraded<Bytes>, Parts), Error> {
        match self.0 {
            EPendingStream::Pending(send_stream, response_fut, ping) => {
                let (head, recv_stream) = response_fut.await?.into_parts();
                Ok((
                    H2Upgraded {
                        ping,
                        send_stream: unsafe { UpgradedSendStream::new(send_stream) },
                        recv_stream,
                        buf: Bytes::new(),
                    },
                    head,
                ))
            }
            EPendingStream::Ready(stream, parts) => Ok((stream, parts)),
            _ => unreachable!(),
        }
    }
    pub fn try_into_ready(self) -> Option<(H2Upgraded<Bytes>, Parts)> {
        match self.0 {
            EPendingStream::Ready(stream, parts) => Some((stream, parts)),
            _ => None,
        }
    }
}

impl AsyncRead for PendingStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        use EPendingStream::*;

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
                                H2Upgraded {
                                    ping,
                                    send_stream: unsafe { UpgradedSendStream::new(send_stream) },
                                    recv_stream,
                                    buf: Bytes::new(),
                                },
                                head,
                            );
                        }
                        Poll::Ready(Err(e)) => {
                            ping.ensure_not_timed_out()
                                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

                            debug!("client response error: {}", e);
                            this.0 = Pending(send_stream, response_fut, ping);
                            return Poll::Ready(Err(e).map_io_err());
                        }
                        Poll::Pending => {
                            this.0 = Pending(send_stream, response_fut, ping);
                            return Poll::Pending;
                        }
                    }
                }
                Ready(mut stream, parts) => {
                    let r = Pin::new(&mut stream).poll_read(cx, buf);
                    this.0 = Ready(stream, parts);
                    return r;
                }
                Poisoned => {
                    unreachable!();
                }
            }
        }
    }
}

impl AsyncWrite for PendingStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        use EPendingStream::*;
        let this = self.get_mut();
        match mem::replace(&mut this.0, Poisoned) {
            Pending(send_stream, response_fut, ping) => {
                let mut send_stream = unsafe { UpgradedSendStream::new(send_stream) };
                let r = poll_write(&mut send_stream, cx, buf);
                this.0 = Pending(unsafe { send_stream.into() }, response_fut, ping);
                r
            }
            Ready(mut stream, parts) => {
                let r = Pin::new(&mut stream).poll_write(cx, buf);
                this.0 = Ready(stream, parts);
                r
            }
            Poisoned => {
                unreachable!();
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        use EPendingStream::*;

        let this = self.get_mut();
        match mem::replace(&mut this.0, Poisoned) {
            Pending(send_stream, response_fut, ping) => {
                let mut send_stream = unsafe { UpgradedSendStream::new(send_stream) };
                let r = poll_shutdown(&mut send_stream, cx);
                this.0 = Pending(unsafe { send_stream.into() }, response_fut, ping);
                r
            }
            Ready(mut stream, parts) => {
                let r = Pin::new(&mut stream).poll_shutdown(cx);
                this.0 = Ready(stream, parts);
                r
            }
            Poisoned => {
                unreachable!();
            }
        }
    }
}

pub async fn handshake<IO: AsyncRead + AsyncWrite + Unpin>(
    io: IO,
) -> Result<(Control, Connection<IO>), Error> {
    let (send_request, mut conn) = h2::client::Builder::new()
        .handshake::<_, SendBuf<Bytes>>(io)
        .await?;
    debug!("h2 handshaked");
    let pp = conn.ping_pong().unwrap();
    // TODO: configurable
    let (ping, ponger) = ping::channel(
        pp,
        ping::Config {
            bdp_initial_window: Some(1024 * 1024),
            keep_alive_interval: Some(std::time::Duration::from_secs(1)),
            keep_alive_timeout: std::time::Duration::from_secs(2),
            keep_alive_while_idle: true,
        },
    );
    let connection = Connection { conn, ponger };
    Ok((Control { send_request, ping }, connection))
}
