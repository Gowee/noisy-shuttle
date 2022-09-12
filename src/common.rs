use blake2::{Blake2s256, Digest};
use lazy_static::lazy_static;
use rustls::internal::msgs::deframer::MessageDeframer;
use snow::params::NoiseParams;
use snow::TransportState;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use futures::ready;
use std::cmp;
use std::fmt;
use std::io::{self};
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::utils::SyncReadAdapter;

lazy_static! {
    pub static ref NOISE_PARAMS: NoiseParams =
        "Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
}

pub const TLS_RECORD_HEADER_LENGTH: usize = 5; // 1 type + 2 proto ver + 2 data len
pub const MAXIMUM_CIPHERTEXT_LENGTH: usize = u16::MAX as usize; // show::constants::MAXMSGLEN
pub const AEAD_TAG_LENGTH: usize = 16; // show::constants::TAGLEN
pub const MAXIMUM_PLAINTEXT_LENGTH: usize = MAXIMUM_CIPHERTEXT_LENGTH - AEAD_TAG_LENGTH;
pub const PSKLEN: usize = 32; // snow::constants::PSKLEN;
const CONTEXT: &[u8] = b"the secure tunnel under snow";

// #[derive(Debug)]
pub struct SnowyStream {
    pub(crate) socket: TcpStream,
    pub(crate) noise: TransportState,
    pub(crate) state: SnowyState,
    pub(crate) tls_deframer: MessageDeframer,
    pub(crate) read_buffer: Vec<u8>,
    pub(crate) read_offset: usize,
    pub(crate) write_buffer: Vec<u8>,
    pub(crate) write_offset: usize,
}

impl SnowyStream {
    pub fn new(io: TcpStream, noise: TransportState) -> Self {
        SnowyStream {
            socket: io,
            noise,
            state: SnowyState::Stream,
            tls_deframer: Default::default(),
            read_buffer: Default::default(),
            read_offset: 0,
            write_buffer: Default::default(),
            write_offset: 0,
        }
    }

    pub fn as_inner(&self) -> &TcpStream {
        &self.socket
    }

    pub fn as_inner_mut(&mut self) -> &mut TcpStream {
        &mut self.socket
    }
}

impl fmt::Debug for SnowyStream {
    fn fmt(&self, _fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        unimplemented!();
    }
}

impl AsyncRead for SnowyStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.state.readable() {
            return Poll::Ready(Ok(()));
        }

        // Ref: https://github.com/tokio-rs/tls/blob/bcf4f8e3f96983dbb7a61808b0f1fcd04fb678ae/tokio-rustls/src/common/mod.rs#L91
        let this = self.get_mut();
        let mut has_read = false;
        loop {
            if this.read_offset < this.read_buffer.len() {
                let b = unsafe {
                    &mut *(buf.unfilled_mut() as *mut [std::mem::MaybeUninit<u8>] as *mut [u8])
                };
                let len = cmp::min(this.read_buffer.len() - this.read_offset, b.len());
                b[..len]
                    .copy_from_slice(&this.read_buffer[this.read_offset..this.read_offset + len]);
                unsafe {
                    buf.assume_init(len);
                }
                buf.advance(len);
                this.read_offset += len;
                has_read = len > 0;
                if this.read_offset < this.read_buffer.len() {
                    break;
                }
            }
            this.read_offset = 0;
            this.read_buffer.clear();

            if let Some(message) = this.tls_deframer.frames.pop_front() {
                if message.payload.0.is_empty() {
                    continue;
                }
                this.read_buffer
                    .reserve_exact(MAXIMUM_PLAINTEXT_LENGTH - this.read_buffer.capacity());
                unsafe { this.read_buffer.set_len(MAXIMUM_PLAINTEXT_LENGTH) };
                let len = this
                    .noise
                    .read_message(&message.payload.0, &mut this.read_buffer)
                    .expect("TODO");
                this.read_buffer.truncate(len);
            } else {
                let n = match this.tls_deframer.read(&mut SyncReadAdapter {
                    io: &mut this.socket,
                    cx,
                }) {
                    Ok(n) => {
                        if n == 0 {
                            this.state.shutdown_read();
                            return Poll::Ready(Ok(()));
                        }
                        n
                    }
                    Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                        return if has_read {
                            Poll::Ready(Ok(()))
                        } else {
                            Poll::Pending
                        };
                    }
                    Err(err) if err.kind() == io::ErrorKind::ConnectionAborted => {
                        this.state.shutdown_read();
                        return dbg!(Poll::Ready(Err(err)));
                    }
                    Err(err) => {
                        return dbg!(Poll::Ready(Err(err)));
                    }
                };
                if n == 0 {
                    // EoF
                    return Poll::Ready(Ok(()));
                }
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for SnowyStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if !self.state.writeable() {
            return Poll::Ready(Ok(0));
        }
        let mut this = self.get_mut();
        let mut offset = 0;
        loop {
            while this.write_offset != this.write_buffer.len() {
                match Pin::new(&mut this.socket)
                    .poll_write(cx, &this.write_buffer[this.write_offset..])
                {
                    Poll::Ready(r) => {
                        let n = r?;
                        if n == 0 {
                            // TODO: clean write buffer?
                            this.state.shutdown_write();
                            return Poll::Ready(Ok(0));
                        }
                        this.write_offset += n;
                    }
                    Poll::Pending => {
                        return if offset == 0 {
                            Poll::Pending
                        } else {
                            Poll::Ready(Ok(offset))
                        };
                    }
                }
            }
            this.write_offset = 0;
            this.write_buffer.clear();
            if offset == buf.len() {
                return Poll::Ready(Ok(offset));
            }
            this.write_buffer
                .reserve_exact(TLS_RECORD_HEADER_LENGTH + MAXIMUM_CIPHERTEXT_LENGTH);
            unsafe {
                this.write_buffer
                    .set_len(TLS_RECORD_HEADER_LENGTH + MAXIMUM_CIPHERTEXT_LENGTH);
            }
            this.write_buffer[0..3].copy_from_slice(&[0x17, 0x03, 0x03]);
            let len = cmp::min(buf.len() - offset, MAXIMUM_PLAINTEXT_LENGTH);
            let n = this
                .noise
                .write_message(
                    &buf[offset..offset + len],
                    &mut this.write_buffer[TLS_RECORD_HEADER_LENGTH..],
                )
                .unwrap();
            offset += len;
            debug_assert!(offset <= buf.len());
            this.write_buffer[3..5].copy_from_slice(&(n as u16).to_be_bytes());
            this.write_buffer.truncate(TLS_RECORD_HEADER_LENGTH + n);
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut this = self.get_mut();
        // unimplemented!(); FIX:
        while this.write_offset != this.write_buffer.len() {
            match Pin::new(&mut this.socket).poll_write(cx, &this.write_buffer[this.write_offset..])
            {
                Poll::Ready(r) => {
                    this.write_offset += r?;
                }
                Poll::Pending => {
                    return Poll::Pending;
                }
            }
        }
        this.write_offset = 0;
        this.write_buffer.clear();
        Pin::new(&mut this.socket).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.state.writeable() {
            // self.session.send_close_notify();
            return Poll::Ready(Ok(()));
        }
        self.state.shutdown_write();
        ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.socket).poll_shutdown(cx)
    }
}

#[derive(Debug)]
pub enum SnowyState {
    Stream,
    ReadShutdown,
    WriteShutdown,
    FullyShutdown,
}

impl SnowyState {
    #[inline]
    pub fn shutdown_read(&mut self) {
        match *self {
            SnowyState::WriteShutdown | SnowyState::FullyShutdown => {
                *self = SnowyState::FullyShutdown
            }
            _ => *self = SnowyState::ReadShutdown,
        }
    }

    #[inline]
    pub fn shutdown_write(&mut self) {
        match *self {
            SnowyState::ReadShutdown | SnowyState::FullyShutdown => {
                *self = SnowyState::FullyShutdown
            }
            _ => *self = SnowyState::WriteShutdown,
        }
    }

    #[inline]
    pub fn writeable(&self) -> bool {
        !matches!(*self, SnowyState::WriteShutdown | SnowyState::FullyShutdown)
    }

    #[inline]
    pub fn readable(&self) -> bool {
        !matches!(*self, SnowyState::ReadShutdown | SnowyState::FullyShutdown)
    }
}

pub fn derive_psk(key: &[u8]) -> [u8; PSKLEN] {
    // Blake3 defines a key derive function, but blake2 does not.
    let mut h = Blake2s256::new();
    h.update(CONTEXT);
    h.update(key);
    h.finalize().into()
}
