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

pub async fn run_client(opt: Opt) -> Result<()> {
    assert!(opt.role.is_client());
    let mut initiator = snow::Builder::new(NOISE_PARAMS.clone())
        .psk(0, KEY)
        .build_initiator()?;
    let mut buf = [0u8; 48];
    // Noise: -> psk, e
    assert_eq!(initiator.write_message(&[], &mut buf).unwrap(), 48);

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
    // let tokio-rustls to make real & full handshake
    let (mut sock, _tlsconn) = connect.await.unwrap().into_inner();

    let mut buf = [0u8; 48];
    sock.read_exact(&mut buf).await?;
    // Noise: <- e, ee
    initiator.read_message(&buf, &mut []).unwrap();
    let mut initiator = initiator.into_transport_mode()?;

    Ok(())
}
