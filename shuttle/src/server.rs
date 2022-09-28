use anyhow::{Context, Result};

use lru::LruCache;
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::net::{lookup_host, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use tracing::{debug, info, instrument, trace, warn};

use std::fmt::Debug;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use snowy_tunnel::{Server, SnowyStream};

use crate::opt::SvrOpt;
use crate::trojan::{
    call_with_addr, read_trojan_like_request, Addr, TrojanUdpDatagramReceiver,
    TrojanUdpDatagramSender, MAX_DATAGRAM_SIZE,
};
use crate::utils::vec_uninit;

const MAX_CACHED_DOMAIN_ADDRS_PER_SOCKET: usize = 64;

pub async fn run_server(opt: SvrOpt) -> Result<()> {
    info!("server is up with camouflage: {}", &opt.camouflage_addr);
    let server = Arc::new(opt.build_server());
    let opt = Arc::new(opt);
    let listener = TcpListener::bind(opt.listen_addr)
        .await
        .with_context(|| format!("Failed to listen on local addr: {:?}", opt.listen_addr))?;
    while let Ok((inbound, client_addr)) = listener.accept().await {
        debug!("accepting connection from {}", &client_addr);
        let server = server.clone();
        let opt = opt.clone();
        // convention: handle_connection only returns error in early/handshake phases
        tokio::spawn(async move {
            if let Err(error) = handle_connection(server, inbound, client_addr, opt).await {
                warn!(error = %format!("{:#}", error), "failed to serve {}", &client_addr)
            }
        });
    }
    Ok(())
}

/// Serve a single inbound connection
#[instrument(name = "serve", skip(server, inbound, client_addr, opt), fields(
    peer = %client_addr
))]
pub async fn handle_connection<A: ToSocketAddrs + Debug>(
    server: Arc<Server<A>>,
    inbound: TcpStream,
    client_addr: SocketAddr,
    opt: Arc<SvrOpt>,
) -> Result<()> {
    use snowy_tunnel::AcceptError::*;
    match server.accept(inbound).await {
        Ok(mut snowys) => {
            use crate::trojan::Cmd::*;
            let req = read_trojan_like_request(&mut snowys)
                .await
                .context("failed to read request header")?;
            info!(command=?req.cmd, dest_addr=%req.dest_addr, "accepting request");
            match req.cmd {
                Connect => {
                    let mut outbound = call_with_addr!(TcpStream::connect, req.dest_addr)
                        .context("failed to connect to remote")?;
                    debug!(
                        local_out = outbound.local_addr().unwrap().to_string(),
                        remote = outbound.peer_addr().unwrap().to_string(),
                        "starting tcp relay"
                    );
                    match tokio::io::copy_bidirectional(&mut snowys, &mut outbound).await {
                        Ok((tx, rx)) => info!(tx, rx, "relay closed"),
                        Err(error) => warn!(?error, "relay terminated"),
                    }
                    Ok(())
                }
                UdpAssociate => {
                    // do not connect, allowing UDP punching
                    let mut outbound = UdpSocket::bind("0.0.0.0:0").await?;
                    debug!(
                        local_out = outbound.local_addr().unwrap().to_string(),
                        remote = req.dest_addr.to_string(),
                        "starting udp relay"
                    );
                    match relay_udp(&mut snowys, &mut outbound).await {
                        Ok((tx, rx)) => info!(tx, rx, "relay udp closed"),
                        Err(error) => warn!(?error, "relay udp terminated"),
                    }
                    Ok(())
                } // Bind => return Err(io::Error::new(io::ErrorKind::Other, "Bind command not supported"))
            }
        }
        Err(IoError(e)) => Err(e).context("failed to accept connection"),
        Err(e) => {
            let fut = async {
                match e {
                    ServerHelloInvalid {
                        buf,
                        mut inbound,
                        mut outbound,
                    } => {
                        warn!(
                            "invalid server hello received from {} when handling {}",
                            outbound.peer_addr()?.to_string(),
                            &client_addr
                        );
                        // an invalid ServerHello might be the result of a strange ClientHello fabricated by
                        // a malicious client, so just copy_bidi as usual in this case
                        inbound.write_all(&buf).await?;
                        tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await
                    }
                    ReplayDetected {
                        buf,
                        mut io,
                        nonce,
                        first_from,
                    } => {
                        warn!(
                            "replay detected from {}, nonce: {:x?}, first from: {}",
                            &client_addr, &nonce, &first_from
                        );
                        info!("fallback relay (pooh's agent)");
                        let mut b = TcpStream::connect(&opt.camouflage_addr).await?;
                        b.write_all(&buf).await?;
                        tokio::io::copy_bidirectional(&mut io, &mut b).await
                    }
                    Unauthenticated { buf, mut io } => {
                        info!("fallback relay (unauthenticated)");
                        let mut b = TcpStream::connect(&opt.camouflage_addr).await?;
                        b.write_all(&buf).await?;
                        tokio::io::copy_bidirectional(&mut io, &mut b).await
                    }
                    ClientHelloInvalid { buf, mut io } => {
                        info!("fallback relay (client protocol unrecognized)");
                        let mut b = TcpStream::connect(&opt.camouflage_addr).await?;
                        b.write_all(&buf).await?;
                        tokio::io::copy_bidirectional(&mut io, &mut b).await
                    }
                    _ => unreachable!(),
                }
            };
            match fut.await {
                Ok((tx, rx)) => {
                    debug!(tx, rx, "fallback relay closed");
                }
                Err(error) => {
                    debug!(%error, "fallback relay with error");
                }
            }
            Ok(())
        }
    }
}

/// Relay traffic between the incoming stream and the outbound UdpSocket
#[instrument(name = "udp_relay", skip(inbound, outbound), fields(local_out_udp=%outbound.local_addr().unwrap()))]
async fn relay_udp(
    inbound: &mut SnowyStream,
    outbound: &mut UdpSocket,
) -> io::Result<(usize, usize)> {
    let _client_addr = inbound.as_inner().peer_addr()?;
    // SnowyStream buffers read internally but not write.
    // Every write to SnowyStream results in a standalone TLS frame, while TrojanLikeUdpDatagram
    // may write multiple times per packet. So buffer it to avoid packet structure leakage.
    let (mut inr, inw) = tokio::io::split(inbound);
    let mut inw = BufWriter::new(inw);
    // TODO: serious global resolver
    let mut resolved_addrs: LruCache<(String, u16), SocketAddr> =
        LruCache::new(MAX_CACHED_DOMAIN_ADDRS_PER_SOCKET);
    let mut tx = 0;
    let mut rx = 0;
    let atob = async {
        let mut buf = unsafe { vec_uninit(MAX_DATAGRAM_SIZE) };
        loop {
            let (n, dest_addr) = match inr.recv_from(&mut buf).await? {
                Some(inner) => inner,
                None => return Ok(()),
            };
            trace!(%dest_addr, len = n, "sending a UDP packet");
            match dest_addr {
                Addr::SocketAddr(ref sa) => outbound.send_to(&buf[..n], sa).await?,
                Addr::Domain(h, p) => {
                    let hp = (h, p);
                    let sa = match resolved_addrs.get(&hp) {
                        Some(sa) => sa,
                        None => {
                            let sa = lookup_host(&hp).await?.next().ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::InvalidInput,
                                    "no addresses to send data to",
                                )
                            })?;
                            resolved_addrs.put(hp, sa);
                            resolved_addrs.iter().next().unwrap().1
                        }
                    };
                    outbound.send_to(&buf[..n], sa).await?
                }
            };
            tx += n;
        }
    };
    let btoa = async {
        let mut buf = unsafe { vec_uninit(MAX_DATAGRAM_SIZE) };
        loop {
            let (n, orig_addr) = outbound.recv_from(&mut buf).await?;
            // When sending udp packet from server to client, addr is the original address that the
            // UDP socket on server received.
            trace!(%orig_addr, len = n, "receiving a UDP packet");
            inw.send_to(&buf[..n], orig_addr.into()).await?;
            inw.flush().await?;
            rx += n;
        }
    };
    // Terminate the relay when inbound reaches EoF.
    // This might violate the semantics of TCP half-open. TODO: Continue btoa with timeout?
    tokio::select! {
        r1 = atob => {
            let r1: io::Result<()> = r1; // annotate type
            match r1 {
                Ok(()) => Ok((tx, rx)),
                Err(e) => Err(e)
            }
        }
        r2 = btoa => {
            let r2: io::Result<()> = r2; // annotate type
            Err(r2.unwrap_err())
        }
    }
}
