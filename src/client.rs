use anyhow::Result;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::{lookup_host, TcpStream};
use tokio_rustls::TlsConnector;

// use futures::FutureExt;

use std::sync::Arc;

use crate::opt::Opt;
use crate::utils::NoCertificateVerification;

use super::common::NOISE_PARAMS;

const LISTEN_ADDR: &'static str = "127.0.0.1:44443";
const CAMOUFLAGE_DOMAIN: &'static str = "www.aliexpress.com";
const CAMOUFLAGE_ADDR: &'static str = "59.82.60.28:443";
// const KEY: &'static str = "Winnie the P00h";
const KEY: &[u8] = b"i don't care for fidget spinners";

// pub struct Client {
//     server_addr: SocketAddr,
//     noise_params:
// }

pub async fn run_client(opt: Opt) -> Result<()> {
    assert!(opt.role.is_client());
    let mut initiator = snow::Builder::new(NOISE_PARAMS.clone())
        .psk(0, KEY)
        .build_initiator()?;
    let mut buf = [0u8; 48];
    // Noise: -> psk, e
    assert_eq!(initiator.write_message(&[], &mut buf).unwrap(), 48);
    println!("C: e, psk {:x?}", &buf);

    let sock = TcpStream::connect(opt.remote_addr).await?;

    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(NoCertificateVerification {}))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config.clone()));
    let tlsconn = rustls::ClientConnection::new_with_random_and_session_id(
        Arc::new(config.clone()),
        CAMOUFLAGE_DOMAIN.try_into().unwrap(),
        <[u8; 32]>::try_from(&buf[0..32]).unwrap().into(),
        (&buf[32..48]).into(), // TODO: fill up to 32 bytes
    )?;
    // replace the underlying rustls::ClientConnection with a custom one
    // TODO: set at first instead of replace
    let connect = connector.connect_with(CAMOUFLAGE_DOMAIN.try_into().unwrap(), sock, |conn| {
        *conn = tlsconn
    });
    dbg!("a");
    // let tokio-rustls to make real & full handshake
    let (mut sock, _tlsconn) = connect.await.unwrap().into_inner();
    dbg!("b");
    let mut buf = [0u8; 48];
    sock.read_exact(&mut buf).await?;
    println!("C: e, ee {:x?}", &buf);
    // Noise: <- e, ee
    initiator.read_message(&buf, &mut []).unwrap();
    let mut initiator = initiator.into_transport_mode()?;

    let mut buf = [0u8; 1024];
    let len = initiator.write_message(b"ping", &mut buf).unwrap();
    println!("C ping hex: {:x?}", &buf[..len]);
    sock.write_all(&buf[0..len]).await?;
    loop {
        let len = sock.read(&mut buf).await?;
        if len == 0 {
            break;
        }
        let len = initiator.read_message(&buf.clone()[0..len], &mut buf)?;
        println!("C pong hex: {:x?}", &buf[..len]);
        println!("{}", String::from_utf8_lossy(&buf[..len]));
    }
    Ok(())
}
