use futures::ready;
use lazy_static::lazy_static;
use rustls::internal::msgs::{deframer::MessageDeframer, message::OpaqueMessage};
use snow::{params::NoiseParams, TransportState};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};

use std::{
    collections::VecDeque,
    io::{self, Read, Result},
    mem,
    pin::Pin,
    task::{Context, Poll},
};

use crate::utils::SyncReadAdapter;

lazy_static! {
    pub static ref NOISE_PARAMS: NoiseParams =
        "Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
}

const MAXIMUM_MESSAGE_LENGTH: usize = u16::MAX as usize;

pub struct SnowyStream {
    pub(crate) socket: TcpStream,
    pub(crate) noise: TransportState,
    pub(crate) tls_deframer: MessageDeframer,
    pub(crate) read_buffer: Vec<u8>,
    pub(crate) read_offset: usize,
    pub(crate) write_buffer: Vec<u8>,
    pub(crate) write_offset: usize,
    // pub(crate) pending_read: VecDeque<>,
    // pub(crate) pending_write: VecDeque<Vec<u8>>,
}

impl SnowyStream {
    pub fn new(io: TcpStream, noise: TransportState) -> Self {
        SnowyStream {
            socket: io,
            noise,
            tls_deframer: Default::default(),
            read_buffer: Default::default(),
            read_offset: 0,
            write_buffer: Default::default(),
            write_offset: 0,
        }
    }
}

impl AsyncRead for SnowyStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        // Ref: https://github.com/tokio-rs/tls/blob/bcf4f8e3f96983dbb7a61808b0f1fcd04fb678ae/tokio-rustls/src/common/mod.rs#L91
        // let mut onwire_ = [0u8; OpaqueMessage::MAX_WIRE_SIZE];
        // let mut onwire = ReadBuf::new(&mut onwire_);
        let this = self.get_mut();

        loop {
            if this.read_offset < this.read_buffer.len() {
                let len = (&this.read_buffer.as_slice()[this.read_offset..])
                    .read(buf.initialize_unfilled())
                    .unwrap();
                buf.advance(len);
                this.read_offset += len;
                if len < this.read_buffer.len() - this.read_offset {
                    //  buf.initialize_unfilled().len() == 0{
                    break;
                }
            }
            this.read_offset = 0;
            // debug_assert!(this.read_buffer.is_empty());

            if let Some(message) = this.tls_deframer.frames.pop_front() {
                dbg!(&message);
                if message.payload.0.len() == 0 {
                    continue;
                }
                this.read_buffer
                    .reserve_exact(MAXIMUM_MESSAGE_LENGTH - this.read_buffer.capacity());
                unsafe { this.read_buffer.set_len(MAXIMUM_MESSAGE_LENGTH) };
                println!("R {:x?}", &message.payload.0);
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
                    Ok(n) => n,
                    Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                        return Poll::Pending
                    }
                    Err(err) => return Poll::Ready(Err(err)),
                };
                // debug_assert!(n > 0, "TODO");
                if n == 0 {
                    dbg!("shutodwning");
                    break;
                }
            }
            // if offset < cap {
            //     break
            // }
            // if let Some(message) = self.message_deframer.frames.pop_front() {

            // }
        }

        // while let Some(msg) = self.tls_deframer.frames.pop_front() {
        //     let s = buf.filled().len();
        //     let len = self
        //         .noise
        //         .read_message(&msg.payload.0, unsafe {
        //             mem::transmute(buf.unfilled_mut())
        //         })
        //         .expect("TODO");
        //     unsafe { buf.assume_init(s + len) };
        //     buf.advance(s);
        // }
        // match Pin::new(&mut self.socket).poll_read(cx, &mut onwire) {
        //     Poll::Ready(Ok(_)) => {

        //     }
        //     Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
        //     Poll::Pending => return Poll::Pending
        // }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for SnowyStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut this = self.get_mut();
        // TODO: MessageFragmenter
        // TODO: min size
        // self.pending_write.push_front(value)
        // socket.poll_write(cx, &[0x17, 0x03, 0x03])?;
        // socket.poll
        let mut offset = 0;
        loop {
            while this.write_offset != this.write_buffer.len() {
                match Pin::new(&mut this.socket)
                    .poll_write(cx, &this.write_buffer[this.write_offset..])
                {
                    Poll::Ready(r) => {
                        this.write_offset += r?;
                    }
                    Poll::Pending => {
                        if offset == 0 {
                            return Poll::Pending;
                        } else {
                            return Poll::Ready(Ok(offset));
                        }
                    }
                }
            }
            this.write_offset = 0;
            if offset == buf.len() {
                return Poll::Ready(Ok(offset));
            }
            this.write_buffer.reserve_exact(5 + MAXIMUM_MESSAGE_LENGTH);
            unsafe {
                this.write_buffer.set_len(5 + MAXIMUM_MESSAGE_LENGTH);
            }
            this.write_buffer[0..3].copy_from_slice(&[0x17, 0x03, 0x03]);
            let len = this
                .noise
                .write_message(
                    &buf[offset..buf.len().min(MAXIMUM_MESSAGE_LENGTH + offset)],
                    &mut this.write_buffer[5..],
                )
                .unwrap();
            offset += buf.len().min(MAXIMUM_MESSAGE_LENGTH + offset);
            // assert!(offset < buf.len());
            this.write_buffer[3..5].copy_from_slice(&(len as u16).to_be_bytes());
            dbg!(len, &(len as u16).to_be_bytes());
            this.write_buffer.truncate(5 + len);
            println!("W {:x?}", this.write_buffer);
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        unimplemented!();
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        unimplemented!();
    }
}

// struct TlsReader {
//     message_deframer: MessageDeframer,
//     buffer: Vec<u8>,
// }

// impl TlsReader {
//     fn read_in(&mut self, rd: &mut dyn io::Read) -> io::Result<usize> {
//         self.message_deframer.read(&mut rd)
//     }

//     fn read_out(&mut self, rd: &mut [u8]) -> io::Result<usize> {
//         let cap = rd.len();
//         let mut len = 0;
//         let mut offset = 0;
//         loop {
//             if !self.buffer.is_empty() {
//                 offset += self.buffer.as_slice().read(rd).unwrap();
//             }
//             if offset < cap {
//                 break
//             }
//             if let Some(message) = self.message_deframer.frames.pop_front() {

//             }
//         }
//         // while let Some(message)  = self.message_deframer.frames.pop_front() {
//         //     message.payload.0
//         // }

//         Ok((len))
//     }
// }
