use anyhow::{Context, Result};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tracing::{debug, info, instrument, trace, warn};

use std::fmt::Debug;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use snowy_tunnel::{Server, SnowyStream};

use crate::opt::SvrOpt;

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
            snowys.flush().await.unwrap();
            let (buf, outbound) = match opt.upstream.as_str() {
                UPSTREAM_HTTP_PROXY => {
                    let (buf, dest_addr) = upgrade_to_http_proxy_stream(&mut snowys)
                        .await
                        .map_err(|e| {
                            warn!("failed to process HTTP request: {}", e);
                            e
                        })?;
                    info!("snowy relay (proxy): {} -> {}", &client_addr, &dest_addr);
                    (buf, TcpStream::connect(dest_addr).await)
                }
                upstream_addr => {
                    info!("snowy relay: {} -> {}", &client_addr, upstream_addr);
                    (vec![], TcpStream::connect(upstream_addr).await)
                }
            };
            let mut outbound = outbound.map_err(|e| {
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
                "relay"
            );
            let r = async {
                outbound.write_all(&buf).await?;
                tokio::io::copy_bidirectional(&mut snowys, &mut outbound).await
            }
            .await;
            match r {
                Ok((tx, rx)) => info!(tx, rx, "relay for {} closed", &client_addr),
                Err(ref e) => warn!("relay for {} terminated with error {}", &client_addr, e),
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

async fn upgrade_to_http_proxy_stream(snowys: &mut SnowyStream) -> io::Result<(Vec<u8>, String)> {
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
            snowys
                .write_all(b"HTTP/1.0 200 Connection Established\r\n\r\n")
                .await?;
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
