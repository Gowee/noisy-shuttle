use rand::Rng;
use rustls::ServerName;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use std::io;
use std::sync::Arc;

use crate::utils::{u16_from_slice, HandshakeStateExt, NoCertificateVerification};

use super::common::{SnowyStream, NOISE_PARAMS, PSKLEN};

#[derive(Debug, Clone)]
pub struct Client {
    pub key: [u8; PSKLEN],
    // pub remote_addr: SocketAddr,
    pub server_name: ServerName,
    // pub verify_tls: bool,
}

impl Client {
    pub async fn connect(&self, stream: TcpStream) -> io::Result<SnowyStream> {
        let mut initiator = snow::Builder::new(NOISE_PARAMS.clone())
            .psk(0, &self.key)
            .build_initiator()
            .expect("Valid NOISE params");
        // Noise: -> psk, e
        let ping = initiator.writen::<48>().expect("Valid NOISE state");
        let random = <[u8; 32]>::try_from(&ping[0..32]).unwrap();
        let mut session_id = [0u8; 32];
        session_id[..16].copy_from_slice(&ping[32..48]);
        // pad to make it of a typical size
        rand::thread_rng().fill(&mut session_id[16..]);

        let tlsconf = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification {}))
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(tlsconf.clone()));
        let tlsconn = rustls::ClientConnection::new_with_random_and_session_id(
            Arc::new(tlsconf.clone()),
            self.server_name.clone(),
            random.into(),
            session_id.as_slice().into(),
        )
        .expect("Valid TLS config");
        // perform real handshake
        let (mut socket, _tlsconn) = connector
            .connect_with(self.server_name.clone(), stream, |conn| *conn = tlsconn)
            .await?
            .into_inner();

        // Noise: <- e, ee
        let mut pong = [0u8; 5 + 48];
        socket.read_exact(&mut pong).await?;
        // println!("C: e, ee w/ header {:x?}", &pong);
        debug_assert_eq!(u16_from_slice(&pong[3..5]), 48);
        initiator
            .read_message(&pong[5..], &mut [])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?; // TODO: allow recovery?

        let noise = initiator
            .into_transport_mode()
            .expect("NOISE handshake finished");
        Ok(SnowyStream::new(socket, noise))
    }
}
