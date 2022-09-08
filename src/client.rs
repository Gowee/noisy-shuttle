use rand::Rng;
use rustls::internal::msgs::codec::Reader;
use rustls::internal::msgs::message::{Message, MessagePayload, OpaqueMessage};
use rustls::ServerName;
use rustls::{Error as RustlsError, ProtocolVersion};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use std::io;
use std::sync::Arc;

use crate::utils::{
    get_server_hello_payload, get_server_tls_version, parse_tls_plain_message, read_tls_message,
    u16_from_slice, HandshakeStateExt, NoCertificateVerification,
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
    pub async fn connect(&self, mut stream: TcpStream) -> io::Result<SnowyStream> {
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
        let mut tlsconn = rustls::ClientConnection::new_with_random_and_session_id(
            Arc::new(tlsconf.clone()),
            self.server_name.clone(),
            random.into(),
            session_id.as_slice().into(),
        )
        .expect("Valid TLS config");

        let mut buf = Vec::with_capacity(TLS_RECORD_HEADER_LENGTH + MAXIMUM_CIPHERTEXT_LENGTH);
        // unsafe { buf.set_len(TLS_RECORD_HEADER_LENGTH + MAXIMUM_CIPHERTEXT_LENGTH) };
        buf.resize(TLS_RECORD_HEADER_LENGTH + MAXIMUM_CIPHERTEXT_LENGTH, 0xef);
        let len = tlsconn.write_tls(&mut io::Cursor::new(&mut buf))?; // Write for Vec is dummy?
        unsafe { buf.set_len(len) };
        println!("{} {:x?}", len, &buf);
        debug_assert!(!tlsconn.wants_write() & tlsconn.wants_read());
        stream.write_all(&buf).await?; // forward Client Hello
        read_tls_message(&mut stream, &mut buf).await?; // read Server Hello
                                                        // unsafe { buf.set_len(TLS_RECORD_HEADER_LENGTH + MAXIMUM_CIPHERTEXT_LENGTH) };
                                                        // let len = stream.read_exact(&mut buf).await?;
                                                        // unsafe { buf.set_len(len) };
        let msg = parse_tls_plain_message(&buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let shp = get_server_hello_payload(&msg)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Not Server Hello"))?;

        let mut stream = Some(stream);
        // server negotiated TLS version
        if get_server_tls_version(shp) == Some(ProtocolVersion::TLSv1_3) {
            // TLS 1.3: handshake treated as done
            // e_ee[..32].copy_from_slice(&shp.random.0);
            // let s: (usize, [u8; 32]) = shp.session_id.into();
            // e_ee[32..48].copy_from_slice(&s.1[..16]);
            dbg!("tls13 hs done");
        } else {
            // conitnue full handshake via rustls
            let connector = TlsConnector::from(Arc::new(tlsconf.clone()));
            tlsconn.read_tls(&mut io::Cursor::new(&mut buf))?;
            let (socket, _tlsconn) = connector
                .connect_with(self.server_name.clone(), stream.take().unwrap(), |conn| {
                    *conn = tlsconn
                })
                .await?
                .into_inner();
            dbg!("tls12 hs done");
            stream = Some(socket);
        }
        let mut stream = stream.unwrap();

        // Noise: <- e, ee
        let mut pong = Vec::with_capacity(5 + 48);
        read_tls_message(&mut stream, &mut pong).await?;
        let e_ee: [u8; 48] = pong[5..]
            .try_into()
            .map_err(|_e| io::Error::new(io::ErrorKind::InvalidData, "Server not snowy"))?;
        dbg!("noise hs done");

        initiator
            .read_message(&e_ee, &mut [])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?; // TODO: allow recovery?
        let noise = initiator
            .into_transport_mode()
            .expect("NOISE handshake finished");
        Ok(SnowyStream::new(stream, noise))
    }
}
