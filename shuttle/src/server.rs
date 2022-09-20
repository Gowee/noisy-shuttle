use anyhow::{Context, Result};

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tracing::{debug, info, instrument, warn};

use std::fmt::Debug;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use snowy_tunnel::Server;

use crate::opt::SvrOpt;

pub async fn run_server(opt: SvrOpt) -> Result<()> {
    info!(
        "server is up with remote: {}, camouflage: {}",
        opt.remote_addr, &opt.camouflage_addr
    );
    let server = Arc::new(opt.build_server());
    let opt = Arc::new(opt);
    let listener = TcpListener::bind(opt.listen_addr)
        .await
        .with_context(|| format!("Failed to listen on local addr: {:?}", opt.listen_addr))?;
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
) -> io::Result<(u64, u64)> {
    #[inline(always)]
    async fn fallback_relay_with(
        a: &mut TcpStream,
        client_addr: &SocketAddr,
        camouflage_addr: impl ToSocketAddrs + Debug,
        bufin: &[u8],
        note: &str,
    ) -> io::Result<(u64, u64)> {
        info!(
            "camouflage relay: {} -> {:?} ({})",
            &client_addr, &camouflage_addr, note
        );
        let mut b = TcpStream::connect(camouflage_addr).await?;
        b.write_all(bufin).await?;
        let r = tokio::io::copy_bidirectional(a, &mut b).await;
        match r {
            Ok((tx, rx)) => {
                debug!(tx, rx, "fallback relay {:?} <-> {:?} closed", a, b);
            }
            Err(ref e) => {
                debug!(
                    "fallback relay {:?} <-> {:?} terminated with error {:?}",
                    a, b, e
                );
            }
        }
        r
    }

    debug!("accepting connection from {}", &client_addr);
    use snowy_tunnel::AcceptError::*;
    match server.accept(inbound).await {
        Ok(mut snowys) => {
            let mut outbound = TcpStream::connect(&opt.remote_addr).await.map_err(|e| {
                warn!(
                    "failed to connect to remote when serving {}: e",
                    &client_addr
                );
                e
            })?;
            info!("snowy relay: {} -> {}", &client_addr, &opt.remote_addr);
            debug!(
                peer = &client_addr.to_string(),
                local_in = snowys.as_inner().local_addr().unwrap().to_string(),
                local_out = outbound.local_addr().unwrap().to_string(),
                remote = outbound.peer_addr().unwrap().to_string(),
                "relay"
            );
            let r = tokio::io::copy_bidirectional(&mut snowys, &mut outbound).await;
            match r {
                Ok((tx, rx)) => info!(tx, rx, "relay for {} closed", &client_addr),
                Err(ref e) => info!("relay for {} terminated with error {}", &client_addr, e),
            }
            r
        }
        Err(IoError(e)) => {
            warn!("failed to accept connection from {}: {}", &client_addr, e);
            Err(e)
        }
        Err(ServerHelloInvalid { outbound, .. }) => {
            warn!(
                "invalid server hello received from {} when handling {}",
                outbound.peer_addr().unwrap().to_string(),
                &client_addr
            );
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid server hello received from camouflage server",
            ))
        }
        Err(e) => {
            let (buf, mut io, note) = match e {
                ReplayDetected {
                    buf,
                    io,
                    nonce,
                    first_from,
                } => {
                    warn!(
                        "replay detected from {}, nonce: {:x?}, first from: {}",
                        &client_addr, &nonce, &first_from
                    );
                    (buf, io, "pooh's agent")
                }
                Unauthenticated { buf, io } => (buf, io, "unauthenticated"),
                ClientHelloInvalid { buf, io } => (buf, io, "client protocol unrecognized"),
                _ => unreachable!(),
            };
            // result is of no interest for unidenfitied clients
            Ok(
                fallback_relay_with(&mut io, &client_addr, &opt.camouflage_addr, &buf, note)
                    .await
                    .unwrap_or((0, 0)),
            )
        }
    }
}
