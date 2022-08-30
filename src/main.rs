#![warn(rust_2018_idioms)]

use hex_literal::hex;
use rustls::internal::msgs::codec::{Codec, Reader};
use rustls::internal::msgs::handshake::HandshakePayload;
use rustls::internal::msgs::message::{Message, MessagePayload, OpaqueMessage, PlainMessage};
use tokio::io::AsyncWriteExt;
use tokio::io::{self, AsyncReadExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

// use futures::FutureExt;
use std::env;
use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;

const LISTEN_ADDR: &'static str = "127.0.0.1:44443";
const CAMOUFLAGE: &'static str = "www.aliexpress.com";
const CAMOUFLAGE_HOST: &'static str = "www.aliexpress.com:443";
const PATTERN: &'static str = "Noise_NN_25519_ChaChaPoly_BLAKE2s";
// const KEY: &'static str = "Winnie the P00h";
const KEY: &[u8] = b"i don't care for fidget spinners";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let role = env::args().nth(1);
    if role.unwrap() != "server" {
        run_client().await?;
    } else {
        run_server().await?;
    }
    Ok(())
}

async fn run_client() -> Result<(), Box<dyn Error>> {
    println!("Client is up");
    let mut initiator = snow::Builder::new(PATTERN.parse()?)
        .psk(0, KEY)
        .build_initiator()?;
    let mut buf = [0u8; 64];
    assert!(initiator.write_message(&[], &mut buf).unwrap() <= 64);

    let mut sock = TcpStream::connect(LISTEN_ADDR).await?;

    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(danger::NoCertificateVerification {}))
        .with_no_client_auth();
    let mut connector = TlsConnector::from(Arc::new(config.clone()));
    let client = rustls::ClientConnection::new_with_random_and_session_id(
        Arc::new(config.clone()),
        CAMOUFLAGE.try_into().unwrap(),
        <[u8; 32]>::try_from(&buf[0..32]).unwrap().into(),
        (&buf[32..64]).into(),
    )?;
    let connect =
        connector.connect_with(CAMOUFLAGE.try_into().unwrap(), sock, |conn| *conn = client);
    let (sock, tlsconn) = connect.await.unwrap().into_inner();

    // client.write_all(&hex!("1603010200010001fc0303")).await?;
    // client.write_all(&buf[0..32]).await?; // client random
    // client.write_all(&hex!("20")).await?;
    // client.write_all(&buf[32..64]).await?; // session id
    //                                        // client.write_all(&[0u8; 16]).await?; // TODO: gen random
    // client.write_all(&hex!("0020caca130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f003501000193baba00000000000e000c000009776569626f2e636f6d00170000ff01000100000a000a00087a7a001d00170018000b00020100002300000010000e000c02683208687474702f312e31000500050100000000000d0012001004030804040105030805050108060601001200000033002b00297a7a000100001d0020e3b3e61aa2e298c2743e203de7f9a8994845e7c9a4c094fc613f0cb838252177002d00020101002b0007068a8a03040303001b00030200024469000500030268321a1a000100001500ce0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")).await?;
    Ok(())
}

async fn run_server() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind(LISTEN_ADDR).await?;

    while let Ok((mut inbound, client_addr)) = listener.accept().await {
        dbg!(&client_addr);
        let mut responder = snow::Builder::new(PATTERN.parse()?)
            .psk(0, KEY)
            .build_responder()?;
        let mut buf = [0u8; 5 + 4 + 2 + 32 + 1 + 32];
        inbound.read_exact(&mut buf).await?;
        let mut e_psk = [0u8; 64];
        e_psk[..32].copy_from_slice(&buf[buf.len() - 65..buf.len() - 33]);
        e_psk[32..].copy_from_slice(&buf[buf.len() - 32..]);
        responder.read_message(&e_psk[..32], &mut []).unwrap();

        let msglen = u16::from_be_bytes(<[u8; 2]>::try_from(&buf[3..5]).unwrap()) as usize;
        let mut msgbuf = vec![0; msglen - (4 + 2 + 32 + 1 + 32)];
        inbound.read_exact(&mut msgbuf).await?;

        // https://github.com/Gowee/rustls-mod/blob/a94a0055e1599d82bd8e212ad2dd19410204d5b7/rustls/src/msgs/message.rs#L88
        let mut outbound =
            TcpStream::connect(CAMOUFLAGE_HOST.parse::<SocketAddr>().unwrap()).await?;
        // TODO: write once
        outbound.write_all(&buf).await?;
        outbound.write_all(&msgbuf).await?;
        
        // loop {
        //     inbound.read_exact();

        //     let rh = [0u8; 5];
        //     inbound.read_exact(buf)
        // }

        // outbound.

        // let mut buf = [0u8; 517];
        // inbound.read_exact(&mut buf).await?;
        // dbg!(buf.len());
        // let opmsg = OpaqueMessage::read(&mut Reader::init(&buf)).unwrap();
        // let msg = Message::try_from(opmsg.into_plain_message()).unwrap();

        // let hsmpayload = match msg.payload {
        //     MessagePayload::Handshake {
        //         parsed: hsmpayload, ..
        //     } => hsmpayload,
        //     _ => panic!("boom"),
        // };
        // let chpayload = match hsmpayload.payload {
        //     HandshakePayload::ClientHello(chpayload) => {
        //         dbg!(chpayload)
        //     }
        //     _ => panic!("booom"),
        // };
        // let mut e_psk = [0u8; 64];
        // e_psk[..32].copy_from_slice(&chpayload.random.0);
        // let mut sid = Vec::with_capacity(32);
        // chpayload.session_id.encode(&mut sid);
        // e_psk[32..].copy_from_slice(&sid[1..]);

        // responder.read_message(&e_psk[..32], &mut []).unwrap();

        // dbg!(msg);
        // OpaqueMessage.read()
        // let transfer = transfer(inbound, server_addr.clone()).map(|r| {
        //     if let Err(e) = r {
        //         println!("Failed to transfer; error={}", e);
        //     }
        // });

        // tokio::spawn(transfer);
    }
    Ok(())
}

mod danger {
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
}

fn disable_certificate_verification(cfg: &mut rustls::ClientConfig) {
    cfg.dangerous()
        .set_certificate_verifier(Arc::new(danger::NoCertificateVerification {}));
}
