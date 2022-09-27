use anyhow::{Context, Result};

use rand::{thread_rng, Rng};
use tokio::io::{
    AsyncReadExt, AsyncWriteExt, BufReader, BufWriter,
};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use tracing::{debug, info, instrument, trace, warn};

use std::fmt::Debug;
use std::io;
use std::mem::{self, MaybeUninit};
use std::net::SocketAddr;

use std::sync::Arc;

use snowy_tunnel::{Server, SnowyStream};

use crate::opt::SvrOpt;
use crate::trojan::{
    call_with_addr, read_trojan_like_request, TrojanUdpDatagramReceiver, TrojanUdpDatagramSender,
    MAX_DATAGRAM_SIZE,
};
use crate::utils::vec_uninit;

const UPSTREAM_HTTP_PROXY: &str = "BUILTIN_HTTP_PROXY";

pub async fn run_server(opt: SvrOpt) -> Result<()> {
    info!(
        "server is up with remote: {}, camouflage: {}",
        opt.upstream, &opt.camouflage_addr
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
            // prefetch_read_instruction(, locality)
            use crate::trojan::Cmd::*;
            let req = read_trojan_like_request(&mut snowys).await?;
            dbg!(&req);
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
                    dbg!("b");
                    let mut outbound = dbg!(UdpSocket::bind("0.0.0.0:0").await)?;

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
            // let (buf, outbound) = match opt.upstream.as_str() {
            //     UPSTREAM_HTTP_PROXY => {
            //         let (buf, dest_addr) = upgrade_to_http_proxy_stream(&mut snowys)
            //             .await
            //             .map_err(|e| {
            //                 warn!("failed to process HTTP request: {}", e);
            //                 e
            //             })?;
            //         info!("snowy relay (proxy): {} -> {}", &client_addr, &dest_addr);
            //         (buf, TcpStream::connect(dest_addr).await)
            //     }
            //     upstream_addr => {
            //         info!("snowy relay: {} -> {}", &client_addr, upstream_addr);
            //         (vec![], TcpStream::connect(upstream_addr).await)
            //     }
            // };
            // let mut outbound = outbound.map_err(|e| {
            //     warn!(
            //         "failed to connect to remote when serving {}: {}",
            //         &client_addr, e
            //     );
            //     e
            // })?;
            // debug!(
            //     peer = &client_addr.to_string(),
            //     local_in = snowys.as_inner().local_addr().unwrap().to_string(),
            //     local_out = outbound.local_addr().unwrap().to_string(),
            //     remote = outbound.peer_addr().unwrap().to_string(),
            //     "relay"
            // );
            // let r = async {
            //     outbound.write_all(&buf).await?;
            //     tokio::io::copy_bidirectional(&mut snowys, &mut outbound).await
            // }
            // .await;
            // match r {
            //     Ok((tx, rx)) => info!(tx, rx, "relay for {} closed", &client_addr),
            //     Err(ref e) => warn!("relay for {} terminated with error {}", &client_addr, e),
            // }
            // r
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

/// Relay traffic between the incoming Trojan-like stream and the outbound UdpSocket
async fn relay_udp(
    inbound: &mut SnowyStream,
    outbound: &mut UdpSocket,
) -> io::Result<(usize, usize)> {
    // let outbound = call_with_addr!(UdpSocket::connect, req.dest_addr).await?; // TODO: no connect?
    // Every write to SnowyStream results in a standalone TLS frame, while TrojanLikeUdpDatagram
    // may write multiple times per packet. So buffer it to avoid packet structure leakage.
    let client_addr = inbound.as_inner().peer_addr()?;
    let (inr, inw) = tokio::io::split(inbound);
    let mut inr = BufReader::new(inr);
    let mut inw = BufWriter::new(inw);

    // let mut (tr, tw) = tokio::io::split(TrojanLikeUdpDatagram::new(bufferd_inbound));
    let atob = async {
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
    let btoa = async {
        let mut buf = unsafe { vec_uninit(MAX_DATAGRAM_SIZE) };
        loop {
            let (n, addr) = inr.recv_from(&mut buf).await?;
            outbound.send_to(&buf[..n], addr.to_string()).await?; // FIX: to_string
            trace!(
                len = n,
                "sending a UDP packet from {} to {}",
                &client_addr,
                &addr
            );
        }
        // Ok::<(), io::Error>
    };
    // TODO: when to exit on error?
    let (_rab, _rba): (io::Result<()>, io::Result<()>) = tokio::join!(atob, btoa);
    Ok((0, 0))
}

async fn upgrade_to_http_proxy_stream(snowys: &mut SnowyStream) -> io::Result<(Vec<u8>, String)> {
    // TODO: this is a over-simplified dirty implementation, a robust one is needed
    const HTTP_200_CONNECTION_ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection Established\r\nX-Padding: X-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-PaddingX-Padding ";
    let mut buf = unsafe { String::from_utf8_unchecked(vec![0u8; 4096]) };
    let mut start = 0;
    let mut end = 0;
    loop {
        let n = snowys
            .read(&mut (unsafe { buf.as_bytes_mut() })[start..])
            .await?;
        end += n;
        if let Some(i) = (&buf[start..]).find("\r\n\r\n") {
            start = i + 4;
            break;
        }
        if n == 0 {
            debug!("received: {}", &buf[..end]);
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "client http request incomplete",
            ));
        }
        if end == buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "client http request header invalid",
            ));
        }
    }
    let reqtriple = (&buf[..start])
        .find("\r\n")
        .and_then(|i| std::str::from_utf8(buf[..i].as_bytes()).ok())
        .map(|startline| {
            let mut startline = startline.split(' ');
            (startline.next(), startline.next(), startline.next())
        });
    match reqtriple {
        Some((Some("CONNECT"), Some(dest), Some(httpver))) => {
            trace!(
                "http proxy received CONNECT from {:?}, url: {}, version: {}",
                snowys,
                dest,
                httpver
            );
            let dest = dest.to_owned();
            let mut buf = buf.into_bytes();
            buf.drain(end..);
            buf.drain(..start);
            let n = thread_rng().gen_range(200..HTTP_200_CONNECTION_ESTABLISHED.len());
            let mut response: Vec<MaybeUninit<u8>> = Vec::with_capacity(n + 4);
            let mut response: Vec<u8> = unsafe {
                response.set_len(response.capacity());
                mem::transmute(response)
            };
            response[..n].copy_from_slice(&HTTP_200_CONNECTION_ESTABLISHED[..n]);
            response[n..].copy_from_slice(b"\r\n\r\n");
            snowys.write_all(&response).await?;
            snowys.flush().await?;
            Ok((buf, dest))
        }
        Some((Some(method), Some(url), Some(httpver @ ("HTTP/0.9" | "HTTP/1.0" | "HTTP/1.1")))) => {
            trace!(
                "http proxy received request {} from {:?}, url: {}, version: {}",
                method,
                snowys.as_inner(),
                url,
                httpver
            );
            let dest = extract_host_addr_from_url(url).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("failed to parse url: {}", url),
                )
            })?;
            let mut buf = buf.into_bytes();
            buf.drain(end..);
            snowys.flush().await?;
            Ok((buf, dest))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Request invalid or method not supported",
        )),
    }
}

fn extract_host_addr_from_url(url: &str) -> Option<String> {
    let mut components = url.split("//");
    let scheme = components.next()?;
    let host = components.next().and_then(|url| url.split('/').next())?;
    let port = match &scheme[..scheme.len() - 1] {
        "ftp" => 21,
        "https" => 443,
        "http" | "" => 80,
        _ => return None,
    };
    Some(match host.find(':').is_some() {
        true => host.to_owned(),
        false => format!("{}:{}", host, port),
    })
}
