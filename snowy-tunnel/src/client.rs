use rand::Rng;

use rustls::HandshakeType;
use rustls::ProtocolVersion;
use rustls::ServerName;
use rustls::internal::msgs::message::Message;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use std::io;
use std::sync::Arc;

use crate::utils::parse_tls_plain_message;

use crate::utils::{
    get_server_tls_version, read_tls_message, HandshakeStateExt, NoCertificateVerification,
    TlsMessageExt,
};

use super::common::{
    SnowyStream, MAXIMUM_CIPHERTEXT_LENGTH, NOISE_PARAMS, PSKLEN, TLS_RECORD_HEADER_LENGTH,
};

#[derive(Debug, Clone)]
pub struct Client {
    pub key: [u8; PSKLEN],
    // pub remote_addr: SocketAddr,
    pub server_name: ServerName,
    // pub verify_tls: bool,
}

impl Client {
    #[allow(clippy::uninit_vec)]
    pub async fn connect(&self, mut stream: TcpStream) -> io::Result<SnowyStream> {
        let mut initiator = snow::Builder::new(NOISE_PARAMS.clone())
            .psk(0, &self.key)
            .build_initiator()
            .expect("Valid NOISE params");
        // Noise: -> psk, e
        let psk_e = initiator.writen::<48>().expect("Valid NOISE state");
        let random = <[u8; 32]>::try_from(&psk_e[0..32]).unwrap();
        let mut session_id = [0u8; 32];
        session_id[..16].copy_from_slice(&psk_e[32..48]);
        // pad to make it of a typical size
        rand::thread_rng().fill(&mut session_id[16..]);

        let tlsconf = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification {}))
            .with_no_client_auth();
        let mut tlsconn = rustls::ClientConnection::new_with(
            Arc::new(tlsconf.clone()),
            self.server_name.clone(),
            random.into(),
            session_id.as_slice().into(),
            None::<fn(&mut Message)>,
        )
        .expect("Valid TLS config");

        let mut buf = Vec::with_capacity(TLS_RECORD_HEADER_LENGTH + MAXIMUM_CIPHERTEXT_LENGTH);
        unsafe { buf.set_len(TLS_RECORD_HEADER_LENGTH + MAXIMUM_CIPHERTEXT_LENGTH) };
        let len = tlsconn.write_tls(&mut io::Cursor::new(&mut buf))?; // Write for Vec is dummy?
        unsafe { buf.set_len(len) };
        debug_assert!(!tlsconn.wants_write() & tlsconn.wants_read());
        stream.write_all(&buf).await?; // forward Client Hello

        // read Server Hello
        let shp = read_tls_message(&mut stream, &mut buf)
            .await?
            .ok()
            .and_then(|_| parse_tls_plain_message(&buf).ok())
            .filter(|msg| msg.is_handshake_type(HandshakeType::ServerHello))
            .and_then(|msg| msg.into_server_hello_payload())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "Not or Invalid Server Hello")
            })?;
        let mut stream = Some(stream);
        // server negotiated TLS version
        match get_server_tls_version(&shp) {
            Some(ProtocolVersion::TLSv1_3) => {
                // TLS 1.3: handshake treated as done
                // TODO: send mibble box compatibility CCS?
                // dbg!("tls13 hs done");
            }
            _ => {
                // conitnue full handshake via rustls
                let connector = TlsConnector::from(Arc::new(tlsconf.clone()));
                tlsconn.read_tls(&mut io::Cursor::new(&mut buf))?;
                let (socket, _tlsconn) = connector
                    .connect_with(self.server_name.clone(), stream.take().unwrap(), |conn| {
                        *conn = tlsconn
                    })
                    .await?
                    .into_inner();
                // dbg!("tls12 hs done");
                stream = Some(socket);
            }
        }
        let mut stream = stream.unwrap();

        // Noise: <- e, ee
        let mut pong = Vec::with_capacity(5 + 48);
        read_tls_message(&mut stream, &mut pong)
            .await?
            .map_err(|_e| {
                io::Error::new(io::ErrorKind::InvalidData, "First data frame not noise")
            })?;
        let e_ee: [u8; 48] = pong[5..]
            .try_into()
            .map_err(|_e| io::Error::new(io::ErrorKind::InvalidData, "Server not snowy"))?;
        initiator
            .read_message(&e_ee, &mut [])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?; // TODO: allow recovery?
                                                                          // dbg!("noise hs done");
        let noise = initiator
            .into_transport_mode()
            .expect("NOISE handshake finished");
        Ok(SnowyStream::new(stream, noise))
    }
}
