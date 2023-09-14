// Ported from hyper (licensed under MIT):
// https://github.com/hyperium/hyper/blob/f9f65b7aa67fa3ec0267fe015945973726285bc2/src/proto/h2/mod.rs

#![allow(dead_code)]

use bytes::{Buf, Bytes};
use h2::{Reason, RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use std::io::{self, Cursor, IoSlice};
use std::mem;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use crate::{ping::Recorder, utils::h2_to_io_error};

/// Stream multiplexed over a HTTP/2 connection.
pub type H2Stream = H2Upgraded<Bytes>;

#[repr(usize)]
pub(crate) enum SendBuf<B> {
    Buf(B),
    Cursor(Cursor<Box<[u8]>>),
    None,
}

impl<B: Buf> Buf for SendBuf<B> {
    #[inline]
    fn remaining(&self) -> usize {
        match *self {
            Self::Buf(ref b) => b.remaining(),
            Self::Cursor(ref c) => Buf::remaining(c),
            Self::None => 0,
        }
    }

    #[inline]
    fn chunk(&self) -> &[u8] {
        match *self {
            Self::Buf(ref b) => b.chunk(),
            Self::Cursor(ref c) => c.chunk(),
            Self::None => &[],
        }
    }

    #[inline]
    fn advance(&mut self, cnt: usize) {
        match *self {
            Self::Buf(ref mut b) => b.advance(cnt),
            Self::Cursor(ref mut c) => c.advance(cnt),
            Self::None => {}
        }
    }

    fn chunks_vectored<'a>(&'a self, dst: &mut [IoSlice<'a>]) -> usize {
        match *self {
            Self::Buf(ref b) => b.chunks_vectored(dst),
            Self::Cursor(ref c) => c.chunks_vectored(dst),
            Self::None => 0,
        }
    }
}

pub struct H2Upgraded<B>
where
    B: Buf,
{
    pub(crate) ping: Recorder,
    pub(crate) send_stream: UpgradedSendStream<B>,
    pub(crate) recv_stream: RecvStream,
    pub(crate) buf: Bytes,
}

impl<B> AsyncRead for H2Upgraded<B>
where
    B: Buf,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        read_buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let Self {
            buf,
            recv_stream,
            ping,
            ..
        } = self.get_mut();
        poll_read(buf, recv_stream, ping, cx, read_buf)
    }
}

pub(crate) fn poll_read(
    buf: &mut Bytes,
    recv_stream: &mut RecvStream,
    ping: &mut Recorder,
    cx: &mut Context<'_>,
    read_buf: &mut ReadBuf<'_>,
) -> Poll<Result<(), io::Error>> {
    if buf.is_empty() {
        *buf = loop {
            match ready!(recv_stream.poll_data(cx)) {
                None => return Poll::Ready(Ok(())),
                Some(Ok(buf)) if buf.is_empty() && !recv_stream.is_end_stream() => continue,
                Some(Ok(buf)) => {
                    ping.record_data(buf.len());
                    break buf;
                }
                Some(Err(e)) => {
                    return Poll::Ready(match e.reason() {
                        Some(Reason::NO_ERROR) | Some(Reason::CANCEL) => Ok(()),
                        Some(Reason::STREAM_CLOSED) => {
                            Err(io::Error::new(io::ErrorKind::BrokenPipe, e))
                        }
                        _ => Err(h2_to_io_error(e)),
                    })
                }
            }
        };
    }
    let cnt = std::cmp::min(buf.len(), read_buf.remaining());
    read_buf.put_slice(&buf[..cnt]);
    buf.advance(cnt);
    let _ = recv_stream.flow_control().release_capacity(cnt);
    Poll::Ready(Ok(()))
}

impl<B> AsyncWrite for H2Upgraded<B>
where
    B: Buf,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        poll_write(&mut self.send_stream, cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        poll_shutdown(&mut self.send_stream, cx)
    }
}

pub(crate) fn poll_write<B: Buf>(
    send_stream: &mut UpgradedSendStream<B>,
    cx: &mut Context<'_>,
    buf: &[u8],
) -> Poll<Result<usize, io::Error>> {
    if buf.is_empty() {
        return Poll::Ready(Ok(0));
    }
    send_stream.reserve_capacity(buf.len());

    // We ignore all errors returned by `poll_capacity` and `write`, as we
    // will get the correct from `poll_reset` anyway.
    let cnt = match ready!(send_stream.poll_capacity(cx)) {
        None => Some(0),
        Some(Ok(cnt)) => send_stream.write(&buf[..cnt], false).ok().map(|()| cnt),
        Some(Err(_)) => None,
    };

    if let Some(cnt) = cnt {
        return Poll::Ready(Ok(cnt));
    }

    Poll::Ready(Err(h2_to_io_error(
        match ready!(send_stream.poll_reset(cx)) {
            Ok(Reason::NO_ERROR) | Ok(Reason::CANCEL) | Ok(Reason::STREAM_CLOSED) => {
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
            }
            Ok(reason) => reason.into(),
            Err(e) => e,
        },
    )))
}

pub(crate) fn poll_shutdown<B: Buf>(
    send_stream: &mut UpgradedSendStream<B>,
    cx: &mut Context<'_>,
) -> Poll<Result<(), io::Error>> {
    if send_stream.write(&[], true).is_ok() {
        return Poll::Ready(Ok(()));
    }

    Poll::Ready(Err(h2_to_io_error(
        match ready!(send_stream.poll_reset(cx)) {
            Ok(Reason::NO_ERROR) => return Poll::Ready(Ok(())),
            Ok(Reason::CANCEL) | Ok(Reason::STREAM_CLOSED) => {
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
            }
            Ok(reason) => reason.into(),
            Err(e) => e,
        },
    )))
}

pub(crate) struct UpgradedSendStream<B>(SendStream<SendBuf<Neutered<B>>>);

impl<B> UpgradedSendStream<B>
where
    B: Buf,
{
    pub(crate) unsafe fn new(inner: SendStream<SendBuf<B>>) -> Self {
        assert_eq!(mem::size_of::<B>(), mem::size_of::<Neutered<B>>());
        Self(mem::transmute(inner))
    }

    fn reserve_capacity(&mut self, cnt: usize) {
        unsafe { self.as_inner_unchecked().reserve_capacity(cnt) }
    }

    fn poll_capacity(&mut self, cx: &mut Context<'_>) -> Poll<Option<Result<usize, h2::Error>>> {
        unsafe { self.as_inner_unchecked().poll_capacity(cx) }
    }

    fn poll_reset(&mut self, cx: &mut Context<'_>) -> Poll<Result<h2::Reason, h2::Error>> {
        unsafe { self.as_inner_unchecked().poll_reset(cx) }
    }

    fn write(&mut self, buf: &[u8], end_of_stream: bool) -> Result<(), io::Error> {
        let send_buf = SendBuf::Cursor(Cursor::new(buf.into()));
        unsafe {
            self.as_inner_unchecked()
                .send_data(send_buf, end_of_stream)
                .map_err(h2_to_io_error)
        }
    }

    unsafe fn as_inner_unchecked(&mut self) -> &mut SendStream<SendBuf<B>> {
        &mut *(&mut self.0 as *mut _ as *mut _)
    }

    pub(crate) unsafe fn into(self) -> SendStream<SendBuf<B>> {
        assert_eq!(mem::size_of::<B>(), mem::size_of::<Neutered<B>>());
        mem::transmute(self.0)
    }
}

#[repr(transparent)]
struct Neutered<B> {
    _inner: B,
    impossible: Impossible,
}

enum Impossible {}

unsafe impl<B> Send for Neutered<B> {}

impl<B> Buf for Neutered<B> {
    fn remaining(&self) -> usize {
        match self.impossible {}
    }

    fn chunk(&self) -> &[u8] {
        match self.impossible {}
    }

    fn advance(&mut self, _cnt: usize) {
        match self.impossible {}
    }
}
