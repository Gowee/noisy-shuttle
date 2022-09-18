#![warn(rust_2018_idioms)]

use anyhow::Result;
use structopt::StructOpt;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio::time::Instant;
use tracing::{debug, info, instrument, warn};

use std::fmt::Debug;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use snowy_tunnel::{Client, Server};

mod opt;
mod preflighter;
mod utils;

use crate::opt::{CltOpt, Opt, SvrOpt};
use crate::preflighter::{Preflighter, PREFLIHGTER_CONNIDLE, PREFLIHGTER_EMA_COEFF};
use crate::utils::DurationExt;

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
    info!(
        "server is up with remote: {}, camouflage: {}",
        opt.remote_addr, &opt.camouflage_addr
    );
    let server = Arc::new(opt.build_server());
    let opt = Arc::new(opt);
    let listener = TcpListener::bind(opt.listen_addr).await?;
    while let Ok((inbound, client_addr)) = listener.accept().await {
        let server = server.clone();
        let opt = opt.clone();
        tokio::spawn(handle_server_connection(server, inbound, client_addr, opt));
    }
    Ok(())
}

#[instrument(level = "trace")]
pub async fn handle_server_connection<A: ToSocketAddrs + Debug>(
    server: Arc<Server<A>>,
    inbound: TcpStream,
    client_addr: SocketAddr,
    opt: Arc<SvrOpt>,
) -> io::Result<()> {
    debug!("accepting connection from {}", &client_addr);
    use snowy_tunnel::AcceptError::*;
    match server.accept(inbound).await {
        Ok(mut snowys) => {
            let mut outbound = TcpStream::connect(&opt.remote_addr).await?;
            info!("snowy relay: {} -> {}", &client_addr, &opt.remote_addr);
            debug!(
                peer = &client_addr.to_string(),
                local_in = snowys.as_inner().local_addr().unwrap().to_string(),
                local_out = outbound.local_addr().unwrap().to_string(),
                remote = outbound.peer_addr().unwrap().to_string(),
                "relay"
            );
            match tokio::io::copy_bidirectional(&mut snowys, &mut outbound).await {
                Ok((tx, rx)) => info!(tx, rx, "relay for {} closed", &client_addr),
                Err(e) => info!("relay for {} terminated with error {}", &client_addr, e),
            }
            Ok(())
        }
        Err(IoError(e)) => Err(e),
        Err(ReplayDetected {
            buf,
            mut io,
            nonce,
            first_from,
        }) => {
            warn!(
                "replay detected from {}, nonce: {:x?}, first from: {}",
                &client_addr, &nonce, &first_from
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
        Err(ServerHelloInvalid { outbound, .. }) => {
            warn!(
                "invalid server hello received from {} when handling {}",
                outbound.peer_addr().unwrap().to_string(),
                &client_addr
            );
            Ok(())
        }
    }
}

pub async fn run_client(opt: CltOpt) -> Result<()> {
    info!(
        "client is up with remote: {}, sni: {}, preflight: {}–{}",
        &opt.remote_addr,
        &opt.server_name,
        &opt.preflight.0,
        &opt.preflight.1.unwrap_or(usize::MAX),
    );
    if let Some(ref ja3) = opt.tls_ja3 {
        info!("ja3: {}", ja3);
        debug!(
            "ja3 version: {:?}, ciphers: {:?}, extensions: {:?}, curves: {:?}, point_formats: {:?}",
            ja3.version_to_typed(),
            ja3.ciphers_as_typed().collect::<Vec<_>>(),
            ja3.extensions_as_typed().collect::<Vec<_>>(),
            ja3.curves_as_typed().collect::<Vec<_>>(),
            ja3.point_formats_as_typed().collect::<Vec<_>>(),
        );
        // TODO: log alpn..
    }
    debug!(
        connidle = PREFLIHGTER_CONNIDLE,
        aht_ema_coeff = PREFLIHGTER_EMA_COEFF
    );
    let client = Arc::new(opt.build_client());
    let opt = Arc::new(opt);

    let preflighter = match opt.preflight {
        (0, Some(0)) => None,
        (min, max) => {
            let client = client.clone();
            let preflighter = Arc::new(Preflighter::new_bounded(
                client,
                opt.remote_addr.clone(),
                min,
                max,
            ));
            {
                let preflighter = preflighter.clone();
                tokio::spawn(async move { preflighter.run().await });
            }
            Some(preflighter)
        }
    };

    let listener = TcpListener::bind(opt.listen_addr).await?;

    while let Ok((inbound, client_addr)) = listener.accept().await {
        let client = client.clone();
        let opt = opt.clone();
        let preflighter = preflighter.clone();
        // TODO: handle error
        tokio::spawn(async move {
            handle_client_connection(client, preflighter, inbound, client_addr, opt).await
        });
    }
    Ok(())
}

#[instrument(level = "trace")]
async fn handle_client_connection(
    client: Arc<Client>,
    preflighter: Option<Arc<Preflighter>>,
    mut inbound: TcpStream,
    client_addr: SocketAddr,
    opt: Arc<CltOpt>,
) -> io::Result<()> {
    let mut snowys = match preflighter {
        Some(preflighter) => {
            let (s, t) = preflighter.get().await?;
            info!(
                "snowy relay for {} starting (preflighted {} ago)",
                &client_addr,
                t.elapsed().autofmt()
            );
            s
        }
        None => {
            let t = Instant::now();
            let s = TcpStream::connect(opt.remote_addr.as_str()).await?;
            let s = client.connect(s).await?;
            info!(
                "snowy relay for {} starting (handshaked within {})",
                &client_addr,
                t.elapsed().autofmt()
            );
            s
        }
    };
    debug!(
        peer = inbound.peer_addr().unwrap().to_string(),
        local_in = inbound.local_addr().unwrap().to_string(),
        local_out = snowys.as_inner().local_addr().unwrap().to_string(),
        remote = snowys.as_inner().peer_addr().unwrap().to_string(),
        "relay"
    );
    let now = Instant::now();
    match tokio::io::copy_bidirectional(&mut snowys, &mut inbound).await {
        Ok((a, b)) => {
            info!(
                rx = a,
                tx = b,
                "relay for {} closed after {}",
                &client_addr,
                now.elapsed().autofmt(),
            );
        }
        Err(e) => {
            warn!(
                "relay for {} terminated after {} with error: {}",
                &client_addr,
                now.elapsed().autofmt(),
                e,
            );
        }
    }
    Ok::<(), io::Error>(())
}
