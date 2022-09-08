use rustls::internal::msgs::codec::Reader;
use rustls::internal::msgs::handshake::{
    ClientExtension, ClientHelloPayload, HandshakeMessagePayload, HandshakePayload,
    ServerExtension, ServerHelloPayload,
};
use rustls::internal::msgs::message::MessageError;
use rustls::internal::msgs::message::{Message, MessagePayload, OpaqueMessage};
use rustls::{Error as RustlsError, ProtocolVersion};
use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};
use tokio::{self};

use std::convert::TryFrom;
use std::io::{self, Read};
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::common::TLS_RECORD_HEADER_LENGTH;

pub fn u16_from_slice(s: &[u8]) -> u16 {
    u16::from_be_bytes(<[u8; 2]>::try_from(s).unwrap())
}

pub trait HandshakeStateExt {
    fn writen<const N: usize>(&mut self) -> Result<[u8; N], snow::Error>;
}

impl HandshakeStateExt for snow::HandshakeState {
    fn writen<const N: usize>(&mut self) -> Result<[u8; N], snow::Error> {
        let mut buf = [0u8; N];
        let len = self.write_message(&[], &mut buf)?;
        assert_eq!(
            len,
            buf.len(),
            "Expected {}, got {} when writing snow handshake message",
            buf.len(),
            len
        );
        Ok(buf)
    }
}

// pub trait AsyncReadExxt<T: tokio::io::AsyncReadExt> {
//     async fn readn<const N: usize>(&mut self) -> tokio::io::Result<[u8; N]> {
//         let mut buf = [0u8; N];
//         self.read_exact(self, &mut buf).await?;
//         Ok(buf)
//     }
// }

pub struct NoCertificateVerification {}

impl rustls::client::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

// Copied from: tokio_rustls::common::SyncReadAdapter;
//   https://github.com/tokio-rs/tls/blob/bcf4f8e3f96983dbb7a61808b0f1fcd04fb678ae/tokio-rustls/src/common/mod.rs#L345
/// An adapter that implements a [`Read`] interface for [`AsyncRead`] types and an
/// associated [`Context`].
///
/// Turns `Poll::Pending` into `WouldBlock`.
pub struct SyncReadAdapter<'a, 'b, T> {
    pub io: &'a mut T,
    pub cx: &'a mut Context<'b>,
}

impl<'a, 'b, T: AsyncRead + Unpin> Read for SyncReadAdapter<'a, 'b, T> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut buf = ReadBuf::new(buf);
        match Pin::new(&mut self.io).poll_read(self.cx, &mut buf) {
            Poll::Ready(Ok(())) => Ok(buf.filled().len()),
            Poll::Ready(Err(err)) => Err(err),
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

/// Read a single TLS message into a Vec.
pub async fn read_tls_message(mut r: impl AsyncRead + Unpin, buf: &mut Vec<u8>) -> io::Result<()> {
    let mut header = [0xffu8; TLS_RECORD_HEADER_LENGTH];
    r.read_exact(&mut header).await?;
    let len = u16_from_slice(&header[3..5]) as usize;
    println!("{:x?}", header);
    dbg!(len);
    buf.reserve_exact((TLS_RECORD_HEADER_LENGTH + len).max(buf.len()) - buf.len());
    unsafe { buf.set_len(TLS_RECORD_HEADER_LENGTH + len) };
    buf[..TLS_RECORD_HEADER_LENGTH].copy_from_slice(&header);
    dbg!("ra");
    r.read_exact(&mut buf[TLS_RECORD_HEADER_LENGTH..]).await?;
    dbg!("rb");
    Ok(())
}

pub fn parse_tls_plain_message(buf: &[u8]) -> Result<Message, RustlsError> {
    println!("{:x?}", buf);
    OpaqueMessage::read(&mut Reader::init(&buf))
        .map(|om| om.into_plain_message())
        .map_err(|e| RustlsError::CorruptMessage) // invalid header
        .and_then(|pm| Message::try_from(pm))
}

pub fn get_client_hello_payload(msg: &Message) -> Option<&ClientHelloPayload> {
    if let MessagePayload::Handshake {
        parsed:
            HandshakeMessagePayload {
                payload: HandshakePayload::ClientHello(ref chp),
                ..
            },
        ..
    } = msg.payload
    {
        Some(chp)
    } else {
        None
    }
}

pub fn get_server_hello_payload(msg: &Message) -> Option<&ServerHelloPayload> {
    if let MessagePayload::Handshake {
        parsed:
            HandshakeMessagePayload {
                payload: HandshakePayload::ServerHello(ref shp),
                ..
            },
        ..
    } = msg.payload
    {
        Some(shp)
    } else {
        None
    }
}

pub fn get_server_tls_version(shp: &ServerHelloPayload) -> Option<ProtocolVersion> {
    shp.extensions
        .iter()
        .filter_map(|ext| {
            if let ServerExtension::SupportedVersions(vers) = ext {
                Some(vers)
            } else {
                None
            }
        })
        .next()
        .cloned()
}

pub fn get_client_tls_versions(shp: &ClientHelloPayload) -> Option<&Vec<ProtocolVersion>> {
    shp.extensions
        .iter()
        .filter_map(|ext| {
            if let ClientExtension::SupportedVersions(vers) = ext {
                Some(vers)
            } else {
                None
            }
        })
        .next()
}

// // https://stackoverflow.com/a/72461302/5488616
// pub fn concat_arrays<T, const M: usize, const N: usize>(a: [T; M], b: [T; N]) -> [T; M + N] {
//     let mut result = std::mem::MaybeUninit::uninit();
//     let dest = result.as_mut_ptr() as *mut T;
//     unsafe {
//         std::ptr::copy_nonoverlapping(a.as_ptr(), dest, M);
//         std::ptr::copy_nonoverlapping(b.as_ptr(), dest.add(M), N);
//         std::mem::forget(a);
//         std::mem::forget(b);
//         result.assume_init()
//     }
// }
