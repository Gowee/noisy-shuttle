use lazy_static::lazy_static;
use rustls::internal::msgs::message::MessageError;
use rustls::internal::msgs::{codec::Reader as RustlsCodecReader, message::OpaqueMessage};
use snow::params::NoiseParams;
use snow::TransportState;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tracing::{debug, trace};

use futures::ready;
use std::cmp;
use std::fmt;
use std::io::{self};
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::utils::possibly_insecure_hash_with_key;

lazy_static! {
    pub static ref NOISE_PARAMS: NoiseParams =
        "Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
}

pub const TLS_RECORD_HEADER_LENGTH: usize = 5; // 1 type + 2 proto ver + 2 data len
                                               // TODO: match TLS length limit?
pub const MAXIMUM_CIPHERTEXT_LENGTH: usize = 2usize.pow(14); // 2**14 B = 16 KiB < show::constants::MAXMSGLEN
pub const AEAD_TAG_LENGTH: usize = 16; // show::constants::TAGLEN
pub const MAXIMUM_PLAINTEXT_LENGTH: usize = MAXIMUM_CIPHERTEXT_LENGTH - AEAD_TAG_LENGTH;
pub const PSKLEN: usize = 32; // snow::constants::PSKLEN;

pub const DEFAULT_ALPN_PROTOCOLS: [&[u8]; 2] = [b"http/2".as_slice(), b"http/1.1".as_slice()];

const CONTEXT: &[u8] = b"the secure tunnel under snow";

/// Secure tunnel on the top of TcpStream encrypted by Noise
// #[derive(Debug)]
pub struct SnowyStream {
    pub(crate) socket: TcpStream,
    pub(crate) noise: TransportState,
    pub(crate) state: SnowyState,
    // pub(crate) tls_deframer: MessageDeframer,
    /// buffer read from raw socket without deframing or decrypting
    pub(crate) pending_read_buffer: Box<[u8]>,
    pub(crate) pending_read_filled: usize,
    /// decrypted plaintext to be consumed by upper-layer app
    pub(crate) read_buffer: Vec<u8>,
    pub(crate) read_offset: usize,
    pub(crate) write_buffer: Vec<u8>,
    pub(crate) write_offset: usize,
}

impl SnowyStream {
    /// Create a snowy tunnel by wrapping a TCP connection with negotiated Noise state.
    ///
    /// Generally, it is not intended to be used directly by external callers.
    pub fn new(io: TcpStream, noise: TransportState) -> Self {
        // TODO: safe
        let mut pending_read_buffer = vec![];
        pending_read_buffer.reserve_exact(OpaqueMessage::MAX_WIRE_SIZE);
        unsafe { pending_read_buffer.set_len(OpaqueMessage::MAX_WIRE_SIZE) };

        SnowyStream {
            socket: io,
            noise,
            state: SnowyState::Stream,
            // tls_deframer: Default::default(),
            pending_read_buffer: pending_read_buffer.into_boxed_slice(),
            pending_read_filled: 0,
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
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        fmt.debug_struct("SnowyStream")
            .field("socket", &self.socket)
            .field("noise", &self.noise)
            .field("state", &self.state)
            // .field("tls_deframer.frames", &self.tls_deframer.frames) // TODO: debug?
            // .field("tls_deframer.desynced", &self.tls_deframer.desynced)
            .field(
                "pending_read_buffer",
                &&self.pending_read_buffer[..self.pending_read_filled],
            )
            .field("read_buffer", &&self.read_buffer[self.read_offset..])
            .field("write_buffer", &&self.write_buffer[self.write_offset..])
            .finish()
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
        'read_more: loop {
            'read_ready: loop {
                // first, clean pending read_buffer
                if this.read_offset < this.read_buffer.len() {
                    let len = cmp::min(this.read_buffer.len() - this.read_offset, buf.remaining());
                    // trace!(buflen=len, "get ready buf");
                    buf.put_slice(&this.read_buffer[this.read_offset..this.read_offset + len]);
                    this.read_offset += len;
                    has_read |= len > 0;
                    if this.read_offset < this.read_buffer.len() {
                        // buf is full
                        break 'read_more;
                    }
                    this.read_offset = 0;
                    this.read_buffer.clear();
                }
                debug_assert_eq!(this.read_offset, 0);
                debug_assert_eq!(this.read_buffer.len(), 0);

                // then, try to pop a ready TLS frame
                // trace!(buflen=this.pending_read_filled, "Extracting a TLS frame from buffer");
                let mut rd =
                    RustlsCodecReader::init(&this.pending_read_buffer[..this.pending_read_filled]);
                match OpaqueMessage::read(&mut rd) {
                    Ok(message) => {
                        // TODO: handle close notify
                        let n = rd.used();
                        debug_assert!(n <= this.pending_read_filled);
                        this.pending_read_buffer
                            .copy_within(n..this.pending_read_filled, 0);
                        this.pending_read_filled -= n;
                        if message.payload.0.is_empty() {
                            continue;
                        }
                        debug_assert_eq!(this.read_offset, 0);
                        this.read_buffer
                            .reserve_exact(MAXIMUM_PLAINTEXT_LENGTH - this.read_buffer.capacity());
                        unsafe { this.read_buffer.set_len(MAXIMUM_PLAINTEXT_LENGTH) };
                        // ensure message payload no empty, o.w. mysterious Decrypt error may be resulted
                        let len = this
                            .noise
                            .read_message(&message.payload.0, &mut this.read_buffer)
                            .map_err(|e| {
                                debug!(
                                    "Noise read error on {:?}, message: {:#?}",
                                    this.socket, message
                                );
                                io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    format!("Noise failed to read message: {}", e),
                                )
                            })?;
                        this.read_buffer.truncate(len);
                        trace!(
                            pldlen = message.payload.0.len(),
                            plainlen = len,
                            "tls message ready for {:?}, type: {:?}, version: {:?}",
                            this.socket,
                            message.typ,
                            message.version,
                        );
                    }
                    Err(MessageError::TooShortForHeader) | Err(MessageError::TooShortForLength) => {
                        // no ready tls frame, proceed to read the inner socket
                        // trace!("No TLS frame ready");
                        break 'read_ready;
                    }
                    Err(err) => {
                        // TODO: properly handle and alert?
                        debug!("Invalid TLS frame on {:?}: {:?}", this.socket, err);
                        this.state.shutdown_read();
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Invalid TLS frame",
                        )));
                    }
                }

                // if let Some(message) = this.tls_deframer.pop() {
                //     // TODO: handle close notify
                //     if message.payload.0.is_empty() {
                //         continue;
                //     }
                //     this.read_buffer
                //         .reserve_exact(MAXIMUM_PLAINTEXT_LENGTH - this.read_buffer.capacity());
                //     unsafe { this.read_buffer.set_len(MAXIMUM_PLAINTEXT_LENGTH) };
                //     // ensure message payload no empty, o.w. mysterious Decrypt error may be resulted
                //     let len = this
                //         .noise
                //         .read_message(&message.payload.0, &mut this.read_buffer)
                //         .map_err(|e| {
                //             debug!(
                //                 "noise read error on {:?}, message: {:#?}",
                //                 this.socket, message
                //             );
                //             io::Error::new(
                //                 io::ErrorKind::InvalidData,
                //                 format!("Noise failed to read message: {}", e),
                //             )
                //         })?;
                //     this.read_buffer.truncate(len);
                //     trace!(
                //         pldlen = message.payload.0.len(),
                //         plainlen = len,
                //         "tls message ready for {:?}, type: {:?}, version: {:?}",
                //         this.socket,
                //         message.typ,
                //         message.version,
                //     );
                // } else {
                //     // no ready tls frame, proceed to read the inner socket
                //     break 'read_ready;
                // }
            }
            // Note: the best practice is to be conservative on making syscalls
            // so here prefer to return progress if any, over proceeding to read the inner socket
            if has_read {
                break 'read_more;
            }
            // otherwise, read the underlying socket
            // trace!(prev_buflen=this.pending_read_filled, "Reading socket");
            let mut buf = ReadBuf::new(&mut this.pending_read_buffer[this.pending_read_filled..]);
            match Pin::new(&mut this.socket).poll_read(cx, &mut buf) {
                Poll::Ready(Ok(())) => {
                    // per trait's doc:
                    //    If no data was read (buf.filled().len() is unchanged), it implies
                    //    that EOF has been reached.
                    if buf.filled().is_empty() {
                        if this.pending_read_filled > 0 {
                            // ready frames in tls_deframer has been drained before reaching here
                            // so pending indicates uncompleted frame
                            // trace!(this.pending_read_filled);
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "Underlaying socket reaches EoF when a TLS frame half-read",
                            )));
                        }
                        break 'read_more;
                    }
                    this.pending_read_filled += buf.filled().len();
                    // trace!(buflen_diff=buf.filled().len(), buflen=this.pending_read_filled, "Read socket done");
                    // proceed to parse TLS frames
                }
                Poll::Ready(Err(err)) => {
                    // TODO: is this necessary?
                    //       would caller call poll_read for a second time after a fatal error at all?
                    match err.kind() {
                        // ErrorKind are copied from tokio-rustls. Why do not we handle other errors?
                        io::ErrorKind::ConnectionAborted | io::ErrorKind::UnexpectedEof => {
                            this.state.shutdown_read();
                        }
                        _ => {}
                    }
                    debug!("read socket error on {:?}: {:?}", this, err);
                    return Poll::Ready(Err(err));
                }
                Poll::Pending => {
                    return Poll::Pending;
                }
            }
            // match this.tls_deframer.read(&mut SyncReadAdapter {
            //     io: &mut this.socket,
            //     cx,
            // }) {
            //     Ok(n) => {
            //         if n == 0 {
            //             // per trait's doc:
            //             //    If no data was read (buf.filled().len() is unchanged), it implies
            //             //    that EOF has been reached.
            //             this.state.shutdown_read();
            //             if this.tls_deframer.has_pending() {
            //                 // ready frames in tls_deframer has been drained before reaching here
            //                 // so pending indicates uncompleted frame
            //                 debug_assert!(this.tls_deframer.frames.is_empty());
            //                 trace!(this.tls_deframer.desynced);
            //                 return Poll::Ready(Err(io::Error::new(
            //                     io::ErrorKind::UnexpectedEof,
            //                     "Underlaying socket reaches EoF when a TLS frame half-read",
            //                 )));
            //             }
            //             break 'read_more;
            //         }
            //         // proceed to parse TLS frames
            //     }
            //     Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
            //         return Poll::Pending;
            //     }
            //     Err(err) => {
            //         // TODO: what are we doing here?
            //         //   will caller call poll_read for a second time after a fatal error at all?
            //         match err.kind() {
            //             // ErrorKind are copied are tokio-rustls. Why do not we handle other errors?
            //             io::ErrorKind::ConnectionAborted | io::ErrorKind::UnexpectedEof => {
            //                 this.state.shutdown_read();
            //             }
            //             _ => {}
            //         }
            //         debug!("read socket error on {:?}: {:?}", this, err);
            //         return Poll::Ready(Err(err));
            //     }
            // }
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
        // WARN:
        //   In current implementation, Ready(Ok(n)) only guarantees buf has been written to the
        //   internal buffer write_buffer. It wouldn't be flushed automatically if there is no
        //   further poll_write/flush calls.
        //   So it is responsibility of the caller to call poll_flush to push.
        //
        //   It appears to be an inevitable design drawbacks in AsyncRead/AsyncWrite when working
        //   with framed protocols.
        //   ref: https://github.com/tokio-rs/tls/issues/41
        //
        //   tokio::io::copy_bidirectional will poll_flush only iff poll_read is Pending, but in
        //   such way, write might be delayed when it should have been possible to make progress.
        //   ref: https://github.com/tokio-rs/tokio/blob/42d5a9fcd4cf87fb0dd96a1850bdd2e9345a84b9/tokio/src/io/util/copy.rs#L51
        //        https://github.com/tokio-rs/tokio/pull/4001
        let mut this = self.get_mut();
        let mut offset = 0;

        loop {
            // first, clean pending write_buffer (an encoded TLS frame)

            // We should have been conservative on making syscalls as in poll_read.
            // But as noted above, Ready(Ok(n)) does not indicate data is writen out at all. We
            // choose to push the write as eagerly as possible instead of just expecting a second
            // call. Not sure if it is really proper, though.
            while this.write_offset < this.write_buffer.len() {
                match Pin::new(&mut this.socket)
                    .poll_write(cx, &this.write_buffer[this.write_offset..])
                {
                    Poll::Ready(Ok(n)) => {
                        // let n = r?;
                        this.write_offset += n;
                        if n == 0 {
                            this.state.shutdown_write();
                            debug!(
                                "write zero, stream: {:?}, state: {:?}, buffered: {}/{}",
                                this.socket,
                                this.state,
                                this.write_offset,
                                this.write_buffer.len()
                            );
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "Write zero byte to underlying socket when a TLS frame is half-written",
                            )));
                        }
                    }
                    Poll::Ready(Err(e)) => {
                        debug!("write socket error, stream: {:?}, state: {:?}, error: {:?}, buffered: {}/{}", this.socket, this.state, e, this.write_offset, this.write_buffer.len());
                        return Poll::Ready(Err(e));
                    }
                    Poll::Pending => {
                        return if offset == 0 {
                            Poll::Pending
                        } else {
                            // the waker has been registered for nothing, but it seems inevitable
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
            // then, encode buf as TLS frame in write_buffer ready to be written to socket
            // TODO: should we store more than one TLS frame in write_buffer?
            this.write_buffer
                .reserve_exact(TLS_RECORD_HEADER_LENGTH + MAXIMUM_CIPHERTEXT_LENGTH);
            unsafe {
                this.write_buffer
                    .set_len(TLS_RECORD_HEADER_LENGTH + MAXIMUM_CIPHERTEXT_LENGTH);
            }
            this.write_buffer[0..3].copy_from_slice(&[0x17, 0x03, 0x03]); // 3,3 is for TLS 1.2/1.3
            let len = cmp::min(buf.len() - offset, MAXIMUM_PLAINTEXT_LENGTH);
            let n = this
                .noise
                .write_message(
                    &buf[offset..offset + len],
                    &mut this.write_buffer[TLS_RECORD_HEADER_LENGTH..],
                )
                .unwrap();
            // plaintext.len < ciphertext.n and typically len + AEAD_TAG_LENGTH = n
            debug_assert_eq!(len + AEAD_TAG_LENGTH, n);
            offset += len;
            debug_assert!(offset <= buf.len());
            this.write_buffer[3..5].copy_from_slice(&(n as u16).to_be_bytes());
            this.write_buffer.truncate(TLS_RECORD_HEADER_LENGTH + n);
            trace!(
                plainlen = buf.len(),
                msglen = this.write_buffer.len(),
                "tls message constructed for {:?}",
                this.socket
            );
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut this = self.get_mut();
        while this.write_offset < this.write_buffer.len() {
            // should we try to poll_write the underlying more than once at all?
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
        Pin::new(&mut this.socket).poll_flush(cx) // actually, tcp flush is a no-op
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.state.writeable() {
            self.state.shutdown_write();
            // proceed even if state has already been unwritable
            // otherwise latter steps would be ignored in second poll calls
        }
        // TODO: https://www.openssl.org/docs/man1.0.2/man3/SSL_shutdown.html
        // https://github.com/tokio-rs/tls/blob/56855b71661a9bf848c1a3c3f03ead6ac3f1b49f/tokio-rustls/src/client.rs#L235
        // self.send_warning_alert_no_log(AlertDescription::CloseNotify);
        // let alert = Message::build_alert(AlertLevel::Warning, rustls::AlertDescription::CloseNotify);

        // per trait's doc, flush should be polled till ready before shutdown returns ready
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

pub fn derive_psk(key: impl AsRef<[u8]>) -> [u8; PSKLEN] {
    possibly_insecure_hash_with_key(CONTEXT, key)
}
