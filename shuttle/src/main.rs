#![warn(rust_2018_idioms)]

use anyhow::Result;
use structopt::StructOpt;
use tokio::io::AsyncWriteExt;
use tokio::net::{lookup_host, TcpListener, TcpStream};
use tokio::time::Instant;
use tracing::{debug, info, instrument, warn};

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
        tokio::spawn(handle_server_connection(server, inbound, client_addr, opt));
    }
    Ok(())
}

#[instrument(level = "trace")]
pub async fn handle_server_connection(
    server: Arc<Server>,
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
                // preflighted = t.elapsed().as_secs_f32(),
                "relay"
            );
            match tokio::io::copy_bidirectional(&mut snowys, &mut outbound).await {
                Ok((tx, rx)) => {
                    info!(tx, rx, "relay for {} closed", &client_addr);
                }
                Err(e) => {
                    info!("relay for {} terminated with error {}", &client_addr, e);
                }
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
            dbg!(handle_client_connection(client, preflighter, inbound, client_addr, opt,).await)
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
                "snowy relay starting for {} (preflighted {} ago)",
                &client_addr,
                t.elapsed().autofmt()
            );
            debug!(
                local_in = &client_addr.to_string(),
                local_out = s.as_inner().local_addr().unwrap().to_string(),
                remote = &opt.remote_addr.to_string(),
                // preflighted = t.elapsed().as_secs_f32(),
                "relay"
            );
            s
        }
        None => {
            let t = Instant::now();
            let s = TcpStream::connect(opt.remote_addr.as_str()).await?;
            let s = client.connect(s).await?;
            info!(
                "snowy relay starting for {} (handshaked within {})",
                &client_addr,
                t.elapsed().autofmt()
            );
            debug!(
                local_in = &client_addr.to_string(),
                local_out = s.as_inner().local_addr().unwrap().to_string(),
                remote = opt.remote_addr.as_str(),
                handshake = t.elapsed().as_secs_f32(),
                "relay"
            );
            s
        }
    };
    let now = Instant::now();
    //     inbound.nodelay().unwrap();
    //     snowys.as_inner_mut().nodelay().unwrap();
    //         let (mut ai, mut ao) = tokio::io::split(snowys);
    //     let (mut bi, mut bo) = inbound.into_split();
    //     let a = tokio::spawn(async move {
    //         let mut buf = vec![0u8; 10240];
    //         loop {
    //             let len = ai.read(&mut buf).await.unwrap();
    //             if len == 0 {
    //                 dbg!("bo done");
    //                 use tokio::time::*;
    //                 sleep(Duration::from_secs(1)).await;
    //                 bo.write_all(&[]).await.unwrap();
    //                 dbg!(&bo, &client_addr);
    //                 sleep(Duration::from_secs(1)).await;
    //                 bo.shutdown().await.unwrap();
    //                 break;
    //             }
    //             // sleep(Duration::from_secs(3)).await;
    //             bo.write_all(&buf[..len]).await.unwrap();
    //             bo.flush().await.unwrap();
    //         }
    //         // dbg!(tokio::io::copy(&mut ai, &mut bo).await);
    //     });
    //     let b = tokio::spawn(async move {
    //         let mut buf = vec![0u8; 10240];
    //         loop {
    //             let len = bi.read(&mut buf).await.unwrap();
    //             if len == 0 {
    //                 dbg!("ao done");
    //                 // ao.shutdown().await.unwrap();
    //                 break;
    //             }
    //             // sleep(Duration::from_secs(3)).await;
    //             ao.write_all(&buf[..len]).await.unwrap();
    //             ao.flush().await.unwrap();
    //         }
    //         // dbg!(tokio::io::copy(&mut bi, &mut ao).await);
    //     });
    //     a.await.unwrap();
    //     b.await.unwrap();
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
