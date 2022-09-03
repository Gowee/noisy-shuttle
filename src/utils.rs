use rustls;
use snow;
use tokio::{
    self,
    io::{AsyncRead, ReadBuf},
};

use std::{
    convert::TryFrom,
    io::{self, Read},
    pin::Pin,
    task::{Context, Poll},
};

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

// fn disable_certificate_verification(cfg: &mut rustls::ClientConfig) {
//     cfg.dangerous()
//         .set_certificate_verifier(Arc::new(danger::NoCertificateVerification {}));
// }

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
