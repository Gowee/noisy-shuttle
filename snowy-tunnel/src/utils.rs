use hex_literal::hex;
use ja3_rustls::Ja3;
use rustls::internal::msgs::base::Payload;
use rustls::internal::msgs::codec::{Codec, Reader};
use rustls::internal::msgs::enums::ExtensionType;
use rustls::internal::msgs::handshake::{
    ClientExtension, ClientHelloPayload, HandshakeMessagePayload, HandshakePayload,
    ServerExtension, ServerHelloPayload, UnknownExtension,
};
use rustls::internal::msgs::message::{Message, MessageError, MessagePayload, OpaqueMessage};
use rustls::{ContentType as TlsContentType, Error as RustlsError, HandshakeType, ProtocolVersion};
use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};
use tracing::{debug, trace};

use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::io::{self, Read};
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::common::{MAXIMUM_CIPHERTEXT_LENGTH, TLS_RECORD_HEADER_LENGTH};

const RFC7685_PADDING_TARGET: usize = 512;

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

/// Read a single TLS message into a Vec.
pub async fn read_tls_message(
    mut r: impl AsyncRead + Unpin,
    buf: &mut Vec<u8>,
) -> io::Result<Result<(), MessageError>> {
    let mut header = [0xefu8; TLS_RECORD_HEADER_LENGTH];
    r.read_exact(&mut header).await?;
    let typ = TlsContentType::from(header[0]);
    let ver = ProtocolVersion::from(u16_from_be_slice(&header[1..3]));
    let len = u16_from_be_slice(&header[3..5]) as usize;
    // Copied from: https://github.com/Gowee/rustls-mod/blob/a94a0055e1599d82bd8e212ad2dd19410204d5b7/rustls/src/msgs/message.rs#L87
    // Reject undersize messages
    //  implemented per section 5.1 of RFC8446 (TLSv1.3)
    //              per section 6.2.1 of RFC5246 (TLSv1.2)
    if typ != TlsContentType::ApplicationData && len == 0 {
        return Ok(Err(MessageError::IllegalLength));
    }
    // Reject oversize messages
    if len >= MAXIMUM_CIPHERTEXT_LENGTH {
        return Ok(Err(MessageError::IllegalLength));
    }
    // Don't accept any new content-types.
    if let TlsContentType::Unknown(_) = typ {
        return Ok(Err(MessageError::IllegalContentType));
    }
    match ver {
        // actually TLS 1.1 should never be present; TLS1.0 may be present as a compatiblity trick
        ProtocolVersion::TLSv1_0
        | ProtocolVersion::TLSv1_1
        | ProtocolVersion::TLSv1_2
        | ProtocolVersion::TLSv1_3 => {}
        _ => return Ok(Err(MessageError::IllegalProtocolVersion)),
    }

    buf.reserve_exact((TLS_RECORD_HEADER_LENGTH + len).max(buf.len()) - buf.len());
    unsafe { buf.set_len(TLS_RECORD_HEADER_LENGTH + len) };
    buf[..TLS_RECORD_HEADER_LENGTH].copy_from_slice(&header);
    r.read_exact(&mut buf[TLS_RECORD_HEADER_LENGTH..]).await?;
    Ok(Ok(()))
}

pub fn parse_tls_plain_message(buf: &[u8]) -> Result<Message, RustlsError> {
    OpaqueMessage::read(&mut Reader::init(buf))
        .map(|om| om.into_plain_message())
        .map_err(|_e| RustlsError::CorruptMessage) // invalid header
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

// trait ExponentialMovingAverage {
//     fn ema(&self, coeff: f64) -> Duration;
// }

// impl ExponentialMovingAverage for Duration {
//     fn ema(&self, coeff: f64) -> Duration {
//         self.as_nanos() * coeff
//     }
// }

/// Apply a JA3 fingerprint to a ClientHello [`Message`].
///
/// Cipher suites, curvres, and EC point formats are simply overwritten with the those specified by
/// a JA3. For TLS extensions, the function manages to match the sort order, **optionally** add
/// empty or hardcoded dummy records for those not in message yet but listed in JA3, and
/// **optionally** drop existing ones from client hello payload if they are not present in JA3.
///
/// It returns a list of allowed unsolicited server extensions matched with the updated message.
///
/// # Note
/// It is caller's responsibility to ensure that the message constitutes a valid ClientHello. Otherwise,
/// only the protocol version in the message header is overwritten.
pub fn overwrite_client_hello_with_ja3(
    msg: &mut Message,
    ja3: &Ja3,
    add_empty_if_extension_not_in_message: bool,
    drop_extensions_not_in_ja3: bool,
) -> Option<Vec<ExtensionType>> {
    use ExtensionType::*;
    let mut allowed_unsolicited_extensions = vec![ExtensionType::RenegotiationInfo];
    trace!("overwrite client hello of {:?} with ja3 {:?}", msg, ja3);
    msg.version = ja3.version_to_typed();
    if let MessagePayload::Handshake {
        ref mut parsed,
        ref mut encoded,
    } = msg.payload
    {
        let mut pad_per_rfc7685 = false;
        if let HandshakeMessagePayload {
            payload: HandshakePayload::ClientHello(ref mut chp),
            ..
        } = parsed
        {
            chp.cipher_suites = ja3.ciphers_as_typed().collect();
            // chp.client_version = ja3.version_as_typed(); // version in extension are not handled
            for extension in chp.extensions.iter_mut() {
                use ClientExtension::*;
                match extension {
                    NamedGroups(groups) => {
                        *groups = ja3.curves_as_typed().collect();
                    }
                    ECPointFormats(formats) => {
                        *formats = ja3.point_formats_as_typed().collect();
                    }
                    _ => {}
                }
            }
            // try to match extension order
            let mut new_extensions = Vec::with_capacity(if drop_extensions_not_in_ja3 {
                ja3.extensions.len()
            } else {
                chp.extensions.len()
            });
            let mut extmap: HashMap<u16, &ClientExtension> = chp
                .extensions
                .iter()
                .map(|extension| (extension.get_type().get_u16(), extension))
                .collect();
            for &exttyp in ja3.extensions.iter() {
                match extmap.remove(&exttyp) {
                    Some(ext) => {
                        let mut ext = ext.clone();
                        if let ClientExtension::Unknown(UnknownExtension {
                            typ: ExtensionType::Padding,
                            ref mut payload,
                        }) = ext
                        {
                            payload.0.clear();
                            pad_per_rfc7685 = true;
                        }
                        new_extensions.push(ext)
                    }
                    None => {
                        if !add_empty_if_extension_not_in_message {
                            break;
                        }
                        debug!(
                        "ja3 overwiting: missing extension {:?} in original chp, add an empty one",
                        ExtensionType::from(exttyp));
                        // Some extension expect vectored struct, we cannot just set empty.
                        let extpld = match ExtensionType::from(exttyp) {
                            // ALPN: http/1.1 + h2
                            ALProtocolNegotiation => {
                                panic!("Expect ALPN present in message if it is listed in JA3")
                                // allowed_unsolicited_extensions
                                //     .push(ExtensionType::ALProtocolNegotiation);
                                // Vec::from(hex!("000c08687474702f312e31026832"))
                            }
                            // Renegotiation Info: still empty, but an additional length field
                            RenegotiationInfo => Vec::from(hex!("00")),
                            // ALPS: supported ALPN list: h2  (TODO: what is it?)
                            ExtensionType::Unknown(0x4469) => Vec::from(hex!("0003026832")),
                            // Padding as defined in RFC7685: pad the payload to at least 512 bytes
                            // ref: https://datatracker.ietf.org/doc/html/rfc7685#section-4
                            Padding => {
                                pad_per_rfc7685 = true;
                                vec![]
                            }
                            _ => vec![],
                        };
                        let ext = ClientExtension::Unknown(UnknownExtension {
                            typ: ExtensionType::from(exttyp),
                            payload: Payload(extpld),
                        });
                        new_extensions.push(ext);
                        // Codec works fine with UnknownExtension
                    }
                }
            }
            if !extmap.is_empty() {
                debug!("ja3 overwriting: extension {:?} in original chp not present in ja3, prepend to end: {}", extmap, !drop_extensions_not_in_ja3);
                if !drop_extensions_not_in_ja3 {
                    // there might be some extensions in CHP that are not present in ja3
                    new_extensions.extend(extmap.into_iter().map(|(_typ, ext)| ext.to_owned()));
                }
            }
            chp.extensions = new_extensions;
        }
        dbg!(pad_per_rfc7685);
        if pad_per_rfc7685 {
            // previous steps ensure padding header is included already
            let pldlen = parsed.get_encoding().len();
            dbg!(pldlen);
            let vacantlen = RFC7685_PADDING_TARGET.saturating_sub(pldlen);
            dbg!(vacantlen);
            if vacantlen != 0 {
                // let padlen = if vacantlen > 4 {
                //     // 4: payload header length
                //     vacantlen - 4
                // } else {
                //     0
                // };
                // dbg!(padlen);
                if let HandshakeMessagePayload {
                    payload: HandshakePayload::ClientHello(ref mut chp),
                    ..
                } = parsed
                {
                    for extension in chp.extensions.iter_mut() {
                        if let ClientExtension::Unknown(UnknownExtension {
                            typ: ExtensionType::Padding,
                            payload,
                        }) = extension
                        {
                            payload.0.resize(vacantlen, 0);
                            break;
                        }
                    }
                }
            }
            // TODO: strip padding if final length > 512 + 4?
        }
        dbg!(parsed.get_encoding().len());
        // Payload are stored twice in struct: one typed and one bytes. Both (or at least the
        // latter) needs overwriting.
        *encoded = Payload::new(parsed.get_encoding());
    }
    Some(allowed_unsolicited_extensions)
}
