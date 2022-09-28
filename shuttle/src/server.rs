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
            use crate::trojan::Cmd::*;
            let req = read_trojan_like_request(&mut snowys).await?;
            trace!("trojan like request from {}: {:?}", &client_addr, &req);
            match req.cmd {
                Connect => {
                    let mut outbound =
                        call_with_addr!(TcpStream::connect, req.dest_addr).map_err(|e| {
                            warn!(
                                "failed to connect to remote when serving {}: {}",
                                &client_addr, e
                            );
                            e
                        })?;
                    debug!(
                        peer = &client_addr.to_string(),
                        local_in = snowys.as_inner().local_addr().unwrap().to_string(),
                        local_out = outbound.local_addr().unwrap().to_string(),
                        remote = outbound.peer_addr().unwrap().to_string(),
                        "tcp relay"
                    );
                    let r = tokio::io::copy_bidirectional(&mut snowys, &mut outbound).await;
                    match r {
                        Ok((tx, rx)) => info!(tx, rx, "relay for {} closed", &client_addr),
                        Err(ref e) => {
                            warn!("relay for {} terminated with error {}", &client_addr, e)
                        }
                    }
                    r
                }
                UdpAssociate => {
                    // do not connect, allowing UDP punching
                    let mut outbound = UdpSocket::bind("0.0.0.0:0").await?;
                    debug!(
                        peer = &client_addr.to_string(),
                        local_in = snowys.as_inner().local_addr().unwrap().to_string(),
                        local_out = outbound.local_addr().unwrap().to_string(),
                        remote = req.dest_addr.to_string(),
                        "tcp relay"
                    );
                    relay_udp(&mut snowys, &mut outbound).await?;
                    // TODO: log
                    Ok((0, 0))
                } // Bind => return Err(io::Error::new(io::ErrorKind::Other, "Bind command not supported"))
            }
        }
        Err(IoError(e)) => {
            warn!("failed to accept connection from {}: {}", &client_addr, e);
            Err(e)
        }
        Err(ServerHelloInvalid {
            buf,
            mut inbound,
            mut outbound,
        }) => {
            warn!(
                "invalid server hello received from {} when handling {}",
                outbound.peer_addr().unwrap().to_string(),
                &client_addr
            );
            // an invalid ServerHello might be the result of a strange ClientHello fabricated by
            // a malicious client, so just copy_bidi as usual in this case
            Ok(async {
                inbound.write_all(&buf).await?;
                tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await
                // TODO: log
            }
            .await
            .unwrap_or((0, 0)))
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

/// Relay traffic between the incoming stream and the outbound UdpSocket
async fn relay_udp(
    inbound: &mut SnowyStream,
    outbound: &mut UdpSocket,
) -> io::Result<(usize, usize)> {
    let client_addr = inbound.as_inner().peer_addr()?;
    // SnowyStream buffers read internally but not write.
    // Every write to SnowyStream results in a standalone TLS frame, while TrojanLikeUdpDatagram
    // may write multiple times per packet. So buffer it to avoid packet structure leakage.
    let (mut inr, inw) = tokio::io::split(inbound);
    let mut inw = BufWriter::new(inw);
    // TODO: serious global resolver
    let mut resolved_addrs: LruCache<(String, u16), SocketAddr> =
        LruCache::new(MAX_CACHED_DOMAIN_ADDRS_PER_SOCKET);
    let atob = async {
        let mut buf = unsafe { vec_uninit(MAX_DATAGRAM_SIZE) };
        loop {
            let (n, addr) = inr.recv_from(&mut buf).await?;
            trace!(
                len = n,
                "sending a UDP packet from {} to {}",
                &client_addr,
                &addr
            );
            match addr {
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
        }
        // Ok::<(), io::Error>
    };
    let btoa = async {
        let mut buf = unsafe { vec_uninit(MAX_DATAGRAM_SIZE) };
        loop {
            let (n, remote_addr) = outbound.recv_from(&mut buf).await?;
            // When sending udp packet from server to client, addr is the original address that the
            // UDP socket on server received.
            trace!(
                len = n,
                "receiving a UDP packet from {} to {}",
                &remote_addr,
                &client_addr
            );
            inw.send_to(&buf[..n], remote_addr.into()).await?;
            inw.flush().await?;
            // tx += n;
        }
    };
    // TODO: when to exit on error?
    let (_rab, _rba): (io::Result<()>, io::Result<()>) = tokio::join!(atob, btoa);
    Ok((0, 0))
}
