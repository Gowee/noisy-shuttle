use anyhow::Result;
use rustls::ServerName;

use rand::{thread_rng, Rng};
use rustls::internal::msgs::handshake::Random;
use rustls::internal::msgs::handshake::SessionID;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, Duration};
use tokio_rustls::TlsConnector;

// use futures::FutureExt;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::opt::Opt;
use crate::utils::u16_from_slice;
use crate::utils::{HandshakeStateExt, NoCertificateVerification};

use super::common::{SnowyStream, NOISE_PARAMS};

const LISTEN_ADDR: &str = "127.0.0.1:9999";
const REMOTE_ADDR: &str = "127.0.0.1:44443";
const CAMOUFLAGE_DOMAIN: &str = "www.petalsearch.com";
// const CAMOUFLAGE_ADDR: &'static str = "59.82.60.28:443";
// const KEY: &'static str = "Winnie the P00h";
const KEY: &[u8] = b"i don't care for fidget spinners";

#[derive(Debug, Clone)]
pub struct Client {
    pub key: [u8; 32],
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

pub async fn run_client(_opt: Opt) -> Result<()> {
    let client = Client {
        key: KEY.try_into().unwrap(),
        // remote_addr: REMOTE_ADDR.parse::<SocketAddr>().unwrap(),
        server_name: CAMOUFLAGE_DOMAIN.try_into().unwrap(),
    };

    let listener = TcpListener::bind(LISTEN_ADDR).await?;

    while let Ok((mut inbound, client_addr)) = listener.accept().await {
        let client = (&client).clone();
        tokio::spawn(async move {
            println!("accpeted: {}", client_addr);
            let outbound = TcpStream::connect(REMOTE_ADDR).await?;
            let mut snowys = client.clone().connect(outbound).await?;
            tokio::io::copy_bidirectional(&mut snowys, &mut inbound).await
        });
        // let mut outbound = TcpStream::connect(REMOTE_ADDR).await?;
        // let mut snowys = client.connect(outbound).await?;
        // let (mut ai, mut ao) = tokio::io::split(snowys);
        // let (mut bi, mut bo) = inbound.into_split();
        // let a = tokio::spawn(async move {
        //     let mut buf = vec![0u8; 10240];
        //     // loop {
        //     //     let len = ai.read(&mut buf).await.unwrap();
        //     //     if len == 0 {
        //     //         break;
        //     //     }
        //     //     sleep(Duration::from_secs(3)).await;
        //     //     bo.write_all(&buf[..len]).await.unwrap();
        //     // }
        //     dbg!(tokio::io::copy(&mut ai, &mut bo).await);
        // });
        // let b = tokio::spawn(async move {
        //     let mut buf = vec![0u8; 10240];
        //     // loop {
        //     //     let len = bi.read(&mut buf).await.unwrap();
        //     //     if len == 0 {
        //     //         break;
        //     //     }
        //     //     sleep(Duration::from_secs(3)).await;
        //     //     ao.write_all(&buf[..len]).await.unwrap();
        //     // }
        //     dbg!(tokio::io::copy(&mut bi, &mut ao).await);
        // });
        // a.await;
        // b.await;
        // tokio::spawn(async move {
        //     println!(
        //         "{} done {:?}",
        //         client_addr,
        //         tokio::io::copy_bidirectional(&mut snowys, &mut inbound).await
        //     );
        // });
    }
    Ok(())
}
