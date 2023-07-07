use blake2::{Blake2s256, Digest};
use rustls::internal::msgs::codec::Reader;
use rustls::internal::msgs::handshake::{
    ClientExtension, ClientHelloPayload, HandshakeMessagePayload, HandshakePayload,
    ServerExtension, ServerHelloPayload,
};
use rustls::internal::msgs::message::{Message, MessageError, MessagePayload, OpaqueMessage};

use rustls::{ContentType as TlsContentType, Error as RustlsError, ProtocolVersion};
use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};

use std::convert::TryFrom;
use std::io::{self, Read};
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::common::{MAXIMUM_CIPHERTEXT_LENGTH, TLS_RECORD_HEADER_LENGTH};

pub fn u16_from_be_slice(s: &[u8]) -> u16 {
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

// Copied from: https://github.com/Gowee/rustls-mod/blob/a94a0055e1599d82bd8e212ad2dd19410204d5b7/rustls/src/msgs/message.rs#L87
/// Read a single TLS message into a Vec.
pub async fn read_tls_message(
    mut r: impl AsyncRead + Unpin,
    buf: &mut Vec<u8>,
) -> io::Result<Result<(), MessageError>> {
    let mut header = [0xefu8; TLS_RECORD_HEADER_LENGTH];
    r.read_exact(&mut header).await?;

    let typ = TlsContentType::from(header[0]);
    // Don't accept any new content-types.
    if let TlsContentType::Unknown(_) = typ {
        return Ok(Err(MessageError::InvalidContentType));
    }

    let version = ProtocolVersion::from(u16_from_be_slice(&header[1..3]));
    // Accept only versions 0x03XX for any XX.
    match version {
        ProtocolVersion::Unknown(ref v) if (v & 0xff00) != 0x0300 => {
            return Ok(Err(MessageError::UnknownProtocolVersion));
        }
        _ => {}
    };

    let len = u16_from_be_slice(&header[3..5]) as usize;

    // Reject undersize messages
    //  implemented per section 5.1 of RFC8446 (TLSv1.3)
    //              per section 6.2.1 of RFC5246 (TLSv1.2)
    if typ != TlsContentType::ApplicationData && len == 0 {
        return Ok(Err(MessageError::InvalidEmptyPayload));
    }

    // Reject oversize messages
    if len >= MAXIMUM_CIPHERTEXT_LENGTH {
        return Ok(Err(MessageError::MessageTooLarge));
    }

    // let mut sub = r
    //     .sub(len as usize)
    //     .map_err(|_| MessageError::TooShortForLength)?;
    // let payload = Payload::read(&mut sub);

    // let typ = TlsContentType::from(header[0]);
    // let ver = ProtocolVersion::from(u16_from_be_slice(&header[1..3]));
    // let len = u16_from_be_slice(&header[3..5]) as usize;
    // // Reject undersize messages
    // //  implemented per section 5.1 of RFC8446 (TLSv1.3)
    // //              per section 6.2.1 of RFC5246 (TLSv1.2)
    // if typ != TlsContentType::ApplicationData && len == 0 {
    //     return Ok(Err(MessageError::TooShortForLength));
    // }
    // // Reject oversize messages
    // if len >= MAXIMUM_CIPHERTEXT_LENGTH {
    //     return Ok(Err(MessageError::IllegalLength));
    // }
    // // Don't accept any new content-types.
    // if let TlsContentType::Unknown(_) = typ {
    //     return Ok(Err(MessageError::IllegalContentType));
    // }

    buf.reserve_exact((TLS_RECORD_HEADER_LENGTH + len).max(buf.len()) - buf.len());
    unsafe { buf.set_len(TLS_RECORD_HEADER_LENGTH + len) };
    buf[..TLS_RECORD_HEADER_LENGTH].copy_from_slice(&header);
    r.read_exact(&mut buf[TLS_RECORD_HEADER_LENGTH..]).await?;
    Ok(Ok(()))
}

pub fn parse_tls_plain_message(buf: &[u8]) -> Result<Message, RustlsError> {
    OpaqueMessage::read(&mut Reader::init(buf))
        .map(|om| om.into_plain_message())
        .map_err(|_e| RustlsError::General(String::from("Invalid opaque message"))) // invalid header
        .and_then(Message::try_from)
}

// pub async fn read_and_parse_tls_plain_message(
//     r: impl AsyncRead + Unpin,
// ) -> io::Result<Result<Message, RustlsError>> {
//     let mut buf = Vec::new();
//     Ok(read_tls_message(r, &mut buf)
//         .await?
//         .map_err(|_e| RustlsError::CorruptMessage)
//         .and_then(|_| parse_tls_plain_message(&buf)))
// }

pub trait TlsMessageExt {
    fn as_client_hello_payload_mut(&mut self) -> Option<&mut ClientHelloPayload>;
    fn into_client_hello_payload(self) -> Option<ClientHelloPayload>;
    fn into_server_hello_payload(self) -> Option<ServerHelloPayload>;
}

impl TlsMessageExt for Message {
    fn as_client_hello_payload_mut(&mut self) -> Option<&mut ClientHelloPayload> {
        match self.payload {
            MessagePayload::Handshake {
                parsed:
                    HandshakeMessagePayload {
                        payload: HandshakePayload::ClientHello(ref mut chp),
                        ..
                    },
                ..
            } => Some(chp),
            _ => None,
        }
    }

    fn into_client_hello_payload(self) -> Option<ClientHelloPayload> {
        if let MessagePayload::Handshake {
            parsed:
                HandshakeMessagePayload {
                    payload: HandshakePayload::ClientHello(chp),
                    ..
                },
            ..
        } = self.payload
        {
            Some(chp)
        } else {
            None
        }
    }

    fn into_server_hello_payload(self) -> Option<ServerHelloPayload> {
        if let MessagePayload::Handshake {
            parsed:
                HandshakeMessagePayload {
                    payload: HandshakePayload::ServerHello(shp),
                    ..
                },
            ..
        } = self.payload
        {
            Some(shp)
        } else {
            None
        }
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

pub fn possibly_insecure_hash_with_key(key: impl AsRef<[u8]>, msg: impl AsRef<[u8]>) -> [u8; 32] {
    // Blake3 defines a key derivation function, but blake2 does not. We use blake2 to avoid
    // introducing a extra dependency.
    let mut hh = Blake2s256::new();
    hh.update(key.as_ref());
    let mut h = Blake2s256::new();
    h.update(<[u8; 32]>::from(hh.finalize()));
    h.update(msg.as_ref());
    h.finalize().into()
}

macro_rules! try_assign {
    ($left: expr, $right: expr) => {
        if let Some(v) = $right {
            $left = v;
        }
    };
}
pub(crate) use try_assign;
