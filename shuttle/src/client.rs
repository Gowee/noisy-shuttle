use anyhow::{anyhow, ensure, Context, Result};

use snowy_tunnel::SnowyStream;
use socks5::sync::FromIO;
use socks5_protocol as socks5;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::Instant;
use tracing::{debug, info, instrument, trace, warn};

use std::io::{self, Cursor, Write};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use crate::connector::{
    AdHocConnector, Connector, Preflighter, PREFLIHGTER_CONNIDLE, PREFLIHGTER_EMA_COEFF,
};
use crate::opt::CltOpt;
use crate::trojan::{
    self, Cmd, TrojanLikeRequest, TrojanUdpDatagramReceiver, TrojanUdpDatagramSender,
    MAX_DATAGRAM_SIZE,
};
use crate::utils::{vec_uninit, DurationExt};

const MAX_FIRST_PACKET_SIZE: usize = 8192;

pub async fn run_client(opt: CltOpt) -> Result<()> {
    info!(
        "client is up with remote: {}, sni: {}, preflight: {}–{}",
        &opt.remote_addr,
        &opt.server_name,
        &opt.preflight.0,
        &opt.preflight.1.unwrap_or(usize::MAX),
    );
    debug!(
        connidle = PREFLIHGTER_CONNIDLE,
        aht_ema_coeff = PREFLIHGTER_EMA_COEFF
    );
    let client = opt.build_client();
    if !client.fingerprint_spec.is_empty() {
        info!("tls fingerprint loaded");
        debug!("{:?}", client.fingerprint_spec);
    }

    match opt.preflight {
        (0, Some(0)) => {
            let connector = AdHocConnector::new(client, opt.remote_addr);
            serve(opt.listen_addr, connector).await?;
        }
        (min, max) => {
            let preflighter = Preflighter::new_flighting(client, opt.remote_addr, min, max);
            serve(opt.listen_addr, preflighter).await?;
        }
    };
    Ok(())
}

async fn serve(
    listen_addr: SocketAddr,
    connector: impl Connector + 'static + Send + Sync,
) -> Result<()> {
    let connector = Arc::new(connector);
    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("failed to bind on {}", listen_addr))?;

    while let Ok((inbound, client_addr)) = listener.accept().await {
        // TODO: handle error
        info!("accepting connection from {}", &client_addr);
        let connector = connector.clone();
        tokio::spawn(async move {
            match handle_client_connection(inbound, client_addr, connector).await {
                Ok(_) => {}
                Err(e) => warn!("error when serving {}: {:#}", &client_addr, e),
            }
        });
    }
    Ok(())
}

#[instrument(skip(connector))]
async fn handle_client_connection(
    inbound: TcpStream,
    client_addr: SocketAddr,
    connector: Arc<impl Connector + 'static>,
) -> Result<(u64, u64)> {
    let mut first = [0u8];
    inbound.peek(&mut first).await?;

    match first[0] {
        0x04 | 0x05 => handle_client_connection_socks5(inbound, client_addr, connector).await,
        _ => handle_client_connection_http(inbound, client_addr, connector).await,
    }
}

#[inline(always)]
async fn handle_client_connection_socks5(
    mut inbound: TcpStream,
    client_addr: SocketAddr,
    connector: Arc<impl Connector + 'static>,
) -> Result<(u64, u64)> {
    const SOCKS5_CONNECT_SUCCEEDED: &[u8] =
        &[0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    const SOCKS5_COMMAND_NOT_SUPPORTED: &[u8] = &[0x05, 0x07, 0x00];
    // the socks5 lib is hard to use, so we use it together with raw bytes alternatively
    socks5::Version::read(&mut inbound).await?;
    let req = socks5::AuthRequest::read(&mut inbound).await?;
    inbound
        .write_all(&[0x05, req.select_from(&[socks5::AuthMethod::Noauth]).into()])
        .await?;
    // CommandRequest includes VER
    let req = socks5::CommandRequest::read(&mut inbound).await?;
    trace!(
        "received socks5 command request from {}, command: {:?}, address: {}",
        &client_addr,
        req.command,
        req.address
    );
    match req.command {
        socks5::Command::Connect => {
            inbound
                .write_all(SOCKS5_CONNECT_SUCCEEDED)
                .await
                .context("failed to write socks5 response")?;
            // TODO: return error from connect?
            let mut snowys = connector
                .connect()
                .await
                .context("failed to establish snowy tunnel")?;
            debug!(
                client = client_addr.to_string(),
                local_in = inbound.local_addr().unwrap().to_string(),
                local_out = snowys.as_inner().local_addr().unwrap().to_string(),
                remote = snowys.as_inner().peer_addr().unwrap().to_string(),
                dest = req.address.to_string(),
                "relay tcp"
            );
            // Try to send the Trojan-like header along with the first inbound packet to avoid
            // fixed TLS frame size.
            //   ref: https://github.com/trojan-gfw/trojan/blob/304054008bb01d6aad51c477b6b7d4e79a5853db/src/session/clientsession.cpp#L194
            // (WON'T?) FIX: This assumes client always send before reading data after a TCP
            //   connection is established. Compatility problem might reside here.
            let now = Instant::now();
            match relay_tcp_with(
                &mut inbound,
                &mut snowys,
                Some(TrojanLikeRequest::new(Cmd::Connect, req.address).encoded()),
            )
            .await
            {
                Ok((a, b)) => {
                    info!(
                        rx = a,
                        tx = b,
                        "relay for {} closed after {}",
                        &client_addr,
                        now.elapsed().autofmt(),
                    );
                    Ok((a, b))
                }
                Err(e) => {
                    warn!(
                        "relay for {} terminated after {} with error: {}",
                        &client_addr,
                        now.elapsed().autofmt(),
                        e,
                    );
                    Err(e)
                }
            }
        }
        socks5::Command::UdpAssociate => {
            let mut inbound_udp = UdpSocket::bind("0.0.0.0:0").await?;
            // inbound_udp.connect(address.to_string()).await?; // FIX: tostring
            let mut bnd_addr = inbound.local_addr()?;
            bnd_addr.set_port(inbound_udp.local_addr()?.port());
            trace!(
                client = client_addr.to_string(),
                endpoint = bnd_addr.to_string(),
                "UDP associated"
            );
            let mut buffered_inbound = BufWriter::new(&mut inbound);
            socks5::CommandResponse::success(bnd_addr.into())
                .write(&mut buffered_inbound)
                .await
                .map_err(|e| e.to_io_err())?;
            buffered_inbound.flush().await?;

            let mut snowys = connector
                .connect()
                .await
                .context("failed to establish snowy tunnel")?;
            debug!(
                client = client_addr.to_string(),
                local_in = inbound.local_addr()?.to_string(),
                local_out = snowys.as_inner().local_addr()?.to_string(),
                remote = snowys.as_inner().peer_addr()?.to_string(),
                dest = req.address.to_string(),
                "relay udp"
            );
            let header = TrojanLikeRequest::new(Cmd::UdpAssociate, req.address);
            relay_udp_with(&mut inbound, &mut inbound_udp, &mut snowys, header)
                .await
                .map_err(|e| e.into())
        }
        // not supported
        socks5::Command::Bind => {
            inbound.write_all(SOCKS5_COMMAND_NOT_SUPPORTED).await?;
            Err(anyhow!("Socks5 BIND not supported"))
        }
    }
}

#[inline(always)]
async fn handle_client_connection_http(
    mut inbound: TcpStream,
    client_addr: SocketAddr,
    connector: Arc<impl Connector + 'static>,
) -> Result<(u64, u64)> {
    const HTTP_200_CONNECTION_ESTABLISHED: &[u8] =
        b"HTTP/1.1 200 Connection Established\r\nX-Powered-By: noisy-shuttle\r\n\r\n";
    const HTTP_400_BAD_REQUEST: &[u8] = b"HTTP/400 Bad Request\r\n\r\n<html><h1>Not Proxied Request</h1>Powered by noisy-shuttle</html>";
    const HTTP_405_METHOD_NOT_ALLOWED: &[u8] = b"HTTP/1.1 405 Method Not Allowed\r\n\r\n<html><h1>Method Not Allowed</h1>Powered by noisy-shuttle</html>";

    use httparse::{Request, Status};
    let mut buf = unsafe { vec_uninit(MAX_FIRST_PACKET_SIZE) };
    let mut end = 0;
    loop {
        let n = inbound.read(&mut buf).await?;
        ensure!(n > 0, "incompleted http request");
        end += n;
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = Request::new(&mut headers);
        if let Status::Complete(start) = req.parse(&buf[..end])? {
            let method = req.method.unwrap();
            let url = req.path.unwrap();
            let hver = req.version.unwrap();
            trace!(
                "http proxy received {} from {:?}, url: {}, version: .{}",
                method,
                inbound,
                url,
                hver
            );

            let mut host = None;
            let mut keepalive = false;
            let headers: Vec<_> = req
                .headers
                .iter_mut()
                .filter_map(|header| {
                    if header.name.len() >= 6 && header.name[..6].eq_ignore_ascii_case("Proxy-") {
                        if header.name[6..].eq_ignore_ascii_case("Connection") {
                            keepalive = header.value.eq_ignore_ascii_case(b"keep-alive");
                        }
                        None
                    } else {
                        if header.name.eq_ignore_ascii_case("Host") {
                            host = Some(header.value);
                        }
                        Some(header)
                    }
                })
                .collect();
            let host = match host {
                Some(host) => Some(std::str::from_utf8(host).context("invalid Host")?),
                None => None,
            };
            trace!(
                "http params by {:?}, host: {}, keepalive: {}",
                inbound,
                host.unwrap_or("<EMPTY>"),
                keepalive
            );

            match method {
                "CONNECT" => {
                    let dest_addr = trojan::Addr::from_str(url)
                        .ok()
                        .context("invalid address")?;
                    let mut snowys = connector
                        .connect()
                        .await
                        .context("failed to establish snowy tunnel")?;

                    inbound.write_all(HTTP_200_CONNECTION_ESTABLISHED).await?;

                    debug!(
                        via = "http CONNECT proxy",
                        client = client_addr.to_string(),
                        local_in = inbound.local_addr()?.to_string(),
                        local_out = snowys.as_inner().local_addr()?.to_string(),
                        remote = snowys.as_inner().peer_addr()?.to_string(),
                        dest = dest_addr.to_string(),
                        "relay tcp"
                    );
                    // buf.drain(end..);
                    // buf.drain(..start);
                    let header = TrojanLikeRequest::new(Cmd::Connect, dest_addr);
                    let mut outbuf = unsafe { vec_uninit(MAX_FIRST_PACKET_SIZE) };
                    let n = header.encode(&mut outbuf);
                    unsafe { outbuf.set_len(n) };
                    outbuf.extend_from_slice(&buf[start..end]);
                    return relay_tcp_with(&mut inbound, &mut snowys, Some(outbuf)).await;
                }
                method @ ("GET" | "POST" | "OPTIONS" | "HEAD" | "PUT" | "DELETE" | "OPTIONS"
                | "TRACE" | "PATCH") => {
                    if url.starts_with('/') {
                        // not proxied request
                        inbound.write_all(HTTP_400_BAD_REQUEST).await?;
                        return Err(anyhow!(
                            "not proxied request (path: {}, host:{})",
                            url,
                            host.unwrap_or("<EMPTY>")
                        ));
                    }
                    let dest_addr = extract_host_addr(url)
                        .and_then(|a| {
                            if a.0.len() < 256 {
                                Some(trojan::Addr::Domain(a.0.to_owned(), a.1))
                            } else {
                                None
                            }
                        })
                        .ok_or_else(|| anyhow!("invalid url: {}", url))?;
                    let path =
                        url_to_relative(url).ok_or_else(|| anyhow!("invalid url: {}", url))?;
                    let mut snowys = connector
                        .connect()
                        .await
                        .context("failed to establish snowy tunnel")?;
                    debug!(
                        via = "http proxy",
                        client = client_addr.to_string(),
                        local_in = inbound.local_addr()?.to_string(),
                        local_out = snowys.as_inner().local_addr()?.to_string(),
                        remote = snowys.as_inner().peer_addr()?.to_string(),
                        dest = dest_addr.to_string(),
                        "relay tcp"
                    );
                    let header = TrojanLikeRequest::new(Cmd::Connect, dest_addr);
                    let mut outbuf = unsafe { vec_uninit(MAX_FIRST_PACKET_SIZE) };
                    let n = header.encode(&mut outbuf);
                    let mut cursor = io::Cursor::new(outbuf);
                    cursor.set_position(n as u64);
                    cursor
                        .write_fmt(format_args!("{} {} HTTP/1.{}\r\n", method, path, hver))
                        .unwrap();
                    for header in headers {
                        cursor
                            .write_fmt(format_args!(
                                "{}: {}\r\n",
                                header.name,
                                std::str::from_utf8(header.value).unwrap_or("")
                            ))
                            .unwrap();
                    }
                    io::Write::write(&mut cursor, b"\r\n").unwrap();
                    let n = cursor.position();
                    let mut outbuf = cursor.into_inner();
                    unsafe { outbuf.set_len(n as usize) };
                    outbuf.extend_from_slice(&buf[start..end]);
                    trace!(
                        "sending request for {}: {:?}",
                        client_addr,
                        std::str::from_utf8(&outbuf)
                    );
                    snowys.write_all(&outbuf).await?;
                    return relay_tcp_with(&mut inbound, &mut snowys, None).await;
                }
                method => {
                    inbound.write_all(HTTP_405_METHOD_NOT_ALLOWED).await?;
                    return Err(anyhow!("unspported HTTP method: {}", method));
                }
            }
        }
    }
}

fn extract_host_addr(url: &str) -> Option<(&str, u16)> {
    let mut components = url.split("//");
    let scheme = components.next()?;
    let host = components.next().and_then(|url| url.split('/').next())?;
    let port = match &scheme[..scheme.len() - 1] {
        "ftp" => 21,
        "https" => 443,
        "http" | "" => 80,
        _ => return None,
    };
    Some(match host.find(':') {
        Some(i) => {
            let (h, p) = host.split_at(i);
            (h, p.parse().ok()?)
        }
        None => (host, port),
    })
}

fn url_to_relative(mut url: &str) -> Option<&str> {
    if let Some(i) = url.find("//") {
        url = &url[i + 2..];
    }
    url.find('/').map(|i| &url[i..])
}

#[instrument]
async fn relay_tcp_with(
    mut inbound: &mut TcpStream,
    mut outbound: &mut SnowyStream,
    outbuf: Option<Vec<u8>>,
) -> Result<(u64, u64)> {
    // TODO: bullshit API design
    if let Some(mut outbuf) = outbuf {
        let mut offset = outbuf.len();
        outbuf.reserve_exact(MAX_FIRST_PACKET_SIZE - outbuf.len());
        unsafe { outbuf.set_len(MAX_FIRST_PACKET_SIZE) };
        offset += inbound
            .read(&mut outbuf[offset..])
            .await
            .context("failed to read initial inbound data")?;
        outbound
            .write_all(&outbuf[..offset])
            .await
            .context("failed to write request header together with initial inbound data")?;
    }
    tokio::io::copy_bidirectional(&mut outbound, &mut inbound)
        .await
        .map_err(|e| e.into())
}

#[instrument]
async fn relay_udp_with(
    inbound_tcp: &mut TcpStream,
    inbound: &mut UdpSocket,
    outbound: &mut SnowyStream,
    header: TrojanLikeRequest,
) -> io::Result<(u64, u64)> {
    let _remote_addr = outbound.as_inner().peer_addr()?;
    let (outr, outw) = tokio::io::split(outbound);
    let mut outr = BufReader::new(outr);
    let mut outw = BufWriter::new(outw);
    header.write(&mut outw).await?;
    let atob = async {
        let mut buf = unsafe { vec_uninit(MAX_DATAGRAM_SIZE) };
        loop {
            // send trojan request header along with the first packet
            // NOTE: this effectively limit the max size of the first packet to be
            //   MAX_DATAGRAM_SIZE - outbuf.len()
            let (n, client_addr) = inbound.recv_from(&mut buf).await?;
            if inbound.peer_addr().is_err() {
                dbg!(&client_addr);
                inbound.connect(&client_addr).await?;
            }
            if buf[2] != 0 {
                // rejects fragments for simplicity
                continue;
            }
            let dest_addr = socks5::Address::read_from(&mut io::Cursor::new(&buf[3..n]))
                .map_err(|e| e.to_io_err())?;
            let addrlen = dest_addr.serialized_len().unwrap();

            // when sending udp packet from server to client, addr is the original address that the
            // UDP socket on server received
            trace!(
                len = n,
                "sending a UDP packet from {} to {}",
                &client_addr,
                &dest_addr
            );
            dbg!(outw.send_to(&buf[3 + addrlen..n], dest_addr).await)?;
            outw.flush().await?;
            // tx += n;
        }
    };
    let btoa = async {
        let mut buf = unsafe { vec_uninit(MAX_DATAGRAM_SIZE) }; // + header?
        loop {
            let (n, orig_addr) = outr.recv_from(&mut buf).await?;
            trace!(
                len = n,
                "receiving a UDP packet from {} to {}",
                &orig_addr,
                inbound.peer_addr().unwrap(),
            );
            let addrlen = orig_addr.serialized_len().unwrap();
            buf.copy_within(0..n, 2 + 1 + addrlen);
            buf[0..3].copy_from_slice(&[0x00, 0x00, 0x00]);
            orig_addr
                .write_to(&mut Cursor::new(&mut buf[3..3 + addrlen]))
                .unwrap();
            dbg!(inbound.send(&buf[..n + addrlen]).await)?; // FIX: to_string
        }
    };

    let (_rab, _rba): (io::Result<()>, io::Result<()>) = tokio::join!(atob, btoa);
    dbg!(inbound_tcp);
    Ok((0, 0)) // FIX: cnt
}
