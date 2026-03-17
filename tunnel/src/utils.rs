use blake2::{Blake2s256, Digest};
use std::convert::TryFrom;
use std::io;

use crate::common::{MAXIMUM_CIPHERTEXT_LENGTH, TLS_RECORD_HEADER_LENGTH};
use rustls::{ContentType as TlsContentType, ProtocolVersion};
use tokio::io::{AsyncRead, AsyncReadExt};

pub fn u16_from_be_slice(s: &[u8]) -> u16 {
    u16::from_be_bytes(<[u8; 2]>::try_from(s).unwrap())
}

/// Read a single TLS message into a Vec.
pub async fn read_tls_message(
    mut r: impl AsyncRead + Unpin,
    buf: &mut Vec<u8>,
) -> io::Result<Result<(), ()>> {
    let mut header = [0xefu8; TLS_RECORD_HEADER_LENGTH];
    r.read_exact(&mut header).await?;

    let typ = TlsContentType::from(header[0]);
    // Don't accept any new content-types.
    if let TlsContentType::Unknown(_) = typ {
        return Ok(Err(()));
    }

    let version = ProtocolVersion::from(u16_from_be_slice(&header[1..3]));
    // Accept only versions 0x03XX for any XX.
    match version {
        ProtocolVersion::Unknown(ref v) if (v & 0xff00) != 0x0300 => {
            return Ok(Err(()));
        }
        _ => {}
    };

    let len = u16_from_be_slice(&header[3..5]) as usize;

    // Reject undersize messages
    if typ != TlsContentType::ApplicationData && len == 0 {
        return Ok(Err(()));
    }

    // Reject oversize messages
    if len >= MAXIMUM_CIPHERTEXT_LENGTH {
        return Ok(Err(()));
    }

    buf.reserve_exact((TLS_RECORD_HEADER_LENGTH + len).max(buf.len()) - buf.len());
    unsafe { buf.set_len(TLS_RECORD_HEADER_LENGTH + len) };
    buf[..TLS_RECORD_HEADER_LENGTH].copy_from_slice(&header);
    r.read_exact(&mut buf[TLS_RECORD_HEADER_LENGTH..]).await?;
    Ok(Ok(()))
}

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
