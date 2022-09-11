#![warn(rust_2018_idioms)]

use anyhow::Result;
use common::SnowyStream;
use structopt::StructOpt;

use futures::TryFutureExt;
use tokio::io::AsyncWriteExt;
use tokio::net::{lookup_host, TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TryRecvError;
use tokio::time::{sleep, Duration, Instant};
use tracing::{debug, info, warn, instrument};

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::client::Client;
use crate::common::derive_psk;
use crate::opt::{CltOpt, Opt, SvrOpt};
use crate::server::Server;
use crate::utils::DurationExt;

mod client;
mod common;
mod opt;
mod server;
mod utils;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let opt = Opt::from_args();
    match opt {
        Opt::Client(opt) => run_client(opt).await?,
        Opt::Server(opt) => run_server(opt).await?,
    }
    Ok(())
}

pub async fn run_server(opt: SvrOpt) -> Result<()> {
    let camouflage_addr = lookup_host(&opt.camouflage_addr)
        .await?
        .next()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "could not resolve to any address",
            )
        })?;
    info!(
        "server is up with remote: {}, camouflage: {}",
        opt.remote_addr, camouflage_addr
    );
    let server = Arc::new(Server::new(opt.key.as_bytes(), camouflage_addr, 1024));
    let opt = Arc::new(opt);
    let listener = TcpListener::bind(opt.listen_addr).await?;
    while let Ok((inbound, client_addr)) = listener.accept().await {
        let server = server.clone();
        let opt = opt.clone();
        tokio::spawn(async move {
            let r = handle_server_connection(server, inbound, client_addr, opt).await;
            info!("relay done with {}: {:?}", &client_addr, r);
        });
    }
    Ok(())
}

#[instrument]
pub async fn handle_server_connection(
    server: Arc<Server>,
    inbound: TcpStream,
    client_addr: SocketAddr,
    opt: Arc<SvrOpt>,
) -> io::Result<()> {
    info!("accepting connection from {}", &client_addr);
    use crate::server::AcceptError::*;
    match server.accept(inbound).await {
        Ok(mut snowys) => {
            let mut outbound = TcpStream::connect(&opt.remote_addr).await?;
            info!("snowy relay: {} -> {}", &client_addr, &opt.remote_addr);
            tokio::io::copy_bidirectional(&mut snowys, &mut outbound)
                .await
                .map(|_| ())
        }
        Err(IoError(e)) => Err(e),
        Err(ReplayDetected {
            buf,
            mut io,
            nounce,
            first_from,
        }) => {
            warn!(
                "replay detected from {}, nonce: {:x?}, first from: {}",
                &client_addr, &nounce, &first_from
            );
            info!(
                "camouflage relay: {} -> {} (pooh's agent)",
                &client_addr, &opt.camouflage_addr
            );
            // TODO: ban
            let mut outbound = TcpStream::connect(&opt.camouflage_addr).await?;
            outbound.write_all(&buf).await?;
            tokio::io::copy_bidirectional(&mut io, &mut outbound)
                .await
                .map(|_| ())
        }
        Err(Unauthenticated { buf, mut io }) => {
            info!(
                "camouflage relay: {} -> {} (unauthenticated)",
                &client_addr, &opt.camouflage_addr
            );
            let mut outbound = TcpStream::connect(&opt.camouflage_addr).await?;
            outbound.write_all(&buf).await?;
            tokio::io::copy_bidirectional(&mut io, &mut outbound)
                .await
                .map(|_| ())
        }
        Err(ClientHelloInvalid { buf, mut io }) => {
            info!(
                "camouflage relay: {} -> {} (client protocol unrecognized)",
                &client_addr, &opt.camouflage_addr
            );
            let mut outbound = TcpStream::connect(&opt.camouflage_addr).await?;
            outbound.write_all(&buf).await?;
            tokio::io::copy_bidirectional(&mut io, &mut outbound)
                .await
                .map(|_| ())
        }
        Err(ServerHelloInvalid { .. }) => {
            info!(
                "invalid server hello received from {} when handling {}",
                &opt.camouflage_addr, &client_addr
            );
            Ok(())
        }
    }
}

pub async fn run_client(opt: CltOpt) -> Result<()> {
    info!(
        "client is up with remote: {}, sni: {}, preflight: {}",
        &opt.remote_addr, &opt.server_name, opt.preflight
    );
    let client = Arc::new(Client {
        key: derive_psk(opt.key.as_bytes()),
        server_name: opt.server_name.as_str().try_into().unwrap(),
    });
    let opt = Arc::new(opt);

    let mut txrx = if opt.preflight > 0 {
        let (tx, rx) = mpsc::channel::<(SnowyStream, Instant)>(opt.preflight);
        // tokio::spawn(preflight(client.clone(), opt.remote_addr.clone(), tx));
        Some((tx, rx))
    } else {
        None
    };

    let listener = TcpListener::bind(opt.listen_addr).await?;

    while let Ok((mut inbound, client_addr)) = listener.accept().await {
        let client = client.clone();
        let opt = opt.clone();
        // info!("acccepting connection from: {}", client_addr);
        // preflighter is not fast enough to cover all requests
        let preflighted = txrx
            .as_mut()
            .ok_or(TryRecvError::Empty)
            .and_then(|(tx, rx)| rx.try_recv())
            .map_err(|e| {
                if e == TryRecvError::Disconnected {
                    panic!("Preflighter termintated unexpectedly")
                };
                e
            })
            .ok()
            .filter(|(s, _t)| match s.as_inner().try_write(&mut []) {
                Ok(_) => true,
                Err(e) => e.kind() == io::ErrorKind::WouldBlock,
            });
        if preflighted.is_some() { 
            let client = client.clone();
            let tx = txrx.as_ref().unwrap().0.clone();
            let remote_addr = opt.remote_addr.clone();
            tokio::spawn(async move {
                match TcpStream::connect(&remote_addr)
                .and_then(|s| client.connect(s))
                .await {
                    Ok(snowys) => tx.send((snowys, Instant::now())).await.unwrap(),
                    Err(_) => {}
                };
            });
        }
        tokio::spawn(async move {
            let mut snowys = match preflighted {
                Some((s, t)) => {
                    info!(
                        "snowy relay {} -> {} (preflighted {} ago)",
                        &client_addr,
                        &opt.remote_addr,
                        t.elapsed().autofmt()
                    );
                    s
                }
                None => {
                    let now = Instant::now();
                    let outbound = TcpStream::connect(&opt.remote_addr).await?;
                    let s = client.connect(outbound).await?;
                    info!(
                        "snowy relay {} -> {} (handshaked within {})",
                        &client_addr,
                        &opt.remote_addr,
                        now.elapsed().autofmt()
                    );
                    s
                }
            };
            let now = Instant::now();
            match tokio::io::copy_bidirectional(&mut snowys, &mut inbound).await {
                Ok((a, b)) => {
                    info!(
                        "connection from {} closed after {} with rx/tx: {}B/{}B",
                        &client_addr,
                        now.elapsed().autofmt(),
                        a,
                        b
                    );
                }
                Err(e) => {
                    info!(
                        "connection from {} terminated after {} with error: {} ",
                        &client_addr,
                        now.elapsed().autofmt(),
                        e,
                    );
                }
            }
            Ok::<(), io::Error>(())
        });
    }
    Ok(())
}

pub async fn preflight(
    client: Arc<Client>,
    remote_addr: String,
    tx: mpsc::Sender<(SnowyStream, Instant)>,
) -> io::Result<()> {
    loop {
        let now = Instant::now();
        match TcpStream::connect(&remote_addr)
            .and_then(|s| client.connect(s))
            .await
        {
            Ok(snowys) => {
                debug!(
                    "preflighted one connection within {}",
                    now.elapsed().as_millis()
                );
                tx.send((snowys, Instant::now()))
                    .await
                    .expect("Main task running");
            }
            Err(e) => {
                warn!("preflighter paused for a while due to: {}", e);
                sleep(Duration::from_secs(3)).await;
            }
        }
    }
}
