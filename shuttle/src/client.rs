use anyhow::Result;

use snowy_tunnel::SnowyStream;
use socks5::sync::FromIO;
use socks5_protocol as socks5;
use tokio::io::{AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::Instant;
use tracing::{debug, info, instrument, trace, warn};

use std::io;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use crate::connector::{
    AdHocConnector, Connector, Preflighter, PREFLIHGTER_CONNIDLE, PREFLIHGTER_EMA_COEFF,
};
use crate::opt::CltOpt;
use crate::trojan::{
    call_with_addr, read_trojan_like_request, TrojanUdpDatagramReceiver, TrojanUdpDatagramSender,
    CRLF, MAX_DATAGRAM_SIZE,
};
use crate::utils::{vec_uninit, DurationExt};

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
) -> io::Result<()> {
    let connector = Arc::new(connector);
    let listener = TcpListener::bind(listen_addr).await?;

    while let Ok((inbound, client_addr)) = listener.accept().await {
        // TODO: handle error
        info!("accepting connection from {}", &client_addr);
        let connector = connector.clone();
        trace!("a");
        debug!("a");
        tokio::spawn(async move {
            dbg!(handle_client_connection(inbound, client_addr, connector).await)
        });
    }
    Ok(())
}

#[instrument(level = "trace", skip(connector))]
async fn handle_client_connection(
    mut inbound: TcpStream,
    client_addr: SocketAddr,
    connector: Arc<impl Connector + 'static>,
) -> io::Result<(u64, u64)> {
    trace!("kk");
    socks5::Version::read(&mut inbound)
        .await
        .map_err(|e| e.to_io_err())?;
    trace!("k1");
    let authreq = socks5::AuthRequest::read(&mut inbound)
        .await
        .map_err(|e| e.to_io_err())?;
    debug!(
        "received socks5 auth request from {}: {:?}",
        &client_addr, &authreq
    );
    // socks5::Version::V5
    //     .write(&mut inbound)
    //     .await
    //     .map_err(|e| e.to_io_err())?;
    // trace!("k4");
    // tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    // socks5::AuthResponse::new(authreq.select_from(&[socks5::AuthMethod::Noauth]))
    //     .write(&mut inbound)
    //     .await
    //     .map_err(|e| e.to_io_err())?;
    inbound.write_all(&[0x05, 0x00]).await?;
    // inbound.flush().await?;
    // tokio::time::sleep(tokio::time::Duration::from_secs(7)).await;
    trace!("k5");
    // socks5::Version::read(&mut inbound)
    //     .await
    //     .map_err(|e| e.to_io_err())?;
    // CommandRequest includes VER
    let socks5::CommandRequest { command, address } = socks5::CommandRequest::read(&mut inbound)
        .await
        .map_err(|e| e.to_io_err())?;
    debug!(
        "received socks5 command request from {}, command: {:?}, address: {}",
        &client_addr, command, address
    );
    match command {
        socks5::Command::Connect => {
            socks5::CommandResponse::success(SocketAddr::from_str("0.0.0.0:0").unwrap().into())
                .write(&mut inbound)
                .await
                .map_err(|e| e.to_io_err())?; // TODO: return error from connect?
            let mut snowys = connector.connect().await.map_err(|e| {
                warn!("failed to establish snowy tunnel: {}", e);
                e
            })?;
            snowys.write_u8(0x01).await?;
            address
                .write(&mut snowys)
                .await
                .map_err(|e| e.to_io_err())?;
            snowys.write_u16(CRLF).await?;
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
            // socks5::Version::V5
            //     .write(&mut inbound)
            //     .await
            //     .map_err(|e| e.to_io_err())?;
            // socks5::CommandResponse::success(dbg!(inbound_udp.local_addr()).unwrap().into())
            //     .write(&mut inbound)
            //     .await
            //     .map_err(|e| e.to_io_err())?;
            inbound.write_all(&[05, 00, 00]).await?;
            dbg!(
                socks5::Address::from(inbound_udp.local_addr().unwrap())
                    .write(&mut inbound)
                    .await
            )
            .map_err(|e| e.to_io_err())?;
            let mut snowys = connector.connect().await.map_err(|e| {
                warn!("failed to establish snowy tunnel: {}", e);
                e
            })?;
            snowys.write_u8(0x03).await?;
            dbg!(&address);
            address
                .write(&mut snowys)
                .await
                .map_err(|e| e.to_io_err())?;
            snowys.write_u16(CRLF).await?;
            debug!(
                peer = inbound.peer_addr().unwrap().to_string(),
                local_in = inbound.local_addr().unwrap().to_string(),
                local_out = snowys.as_inner().local_addr().unwrap().to_string(),
                remote = snowys.as_inner().peer_addr().unwrap().to_string(),
                "relay udp"
            );
            dbg!(relay_udp(&mut inbound_udp, &mut snowys).await) // TODO: log
        }
        // not supported
        socks5::Command::Bind => {
            // socks5::Version::V5
            //     .write(&mut inbound)
            //     .await
            //     .map_err(|e| e.to_io_err())?;
            socks5::CommandResponse::reply_error(socks5::CommandReply::CommandNotSupported)
                .write(&mut inbound)
                .await
                .map_err(|e| e.to_io_err())?;
            return Ok((0, 0));
        }
    }
}

// async fn relay_tcp(inbound: &TcpStream, outbound: &SnowyStream) -> io::Result<(0,0 )> {

// }
#[instrument]
async fn relay_udp(inbound: &mut UdpSocket, outbound: &mut SnowyStream) -> io::Result<(u64, u64)> {
    let client_addr = "unknown";
    let (outr, outw) = tokio::io::split(outbound);
    let mut outr = BufReader::new(outr);
    let mut outw = BufWriter::new(outw);

    let atob = async {
        let mut buf = unsafe { vec_uninit(MAX_DATAGRAM_SIZE) };
        loop {
            let (n, remote_addr) = inbound.recv_from(&mut buf).await?;
            // When sending udp packet from server to client, addr is the original address that the
            // UDP socket on server received.
            trace!(
                len = n,
                "receiving a UDP packet from {} to {}",
                &remote_addr,
                &client_addr
            );
            dbg!(outw.send_to(&buf[..n], remote_addr.into()).await)?;
            // tx += n;
        }
    };
    let btoa = async {
        let mut buf = unsafe { vec_uninit(MAX_DATAGRAM_SIZE) };
        loop {
            let (n, addr) = outr.recv_from(&mut buf).await?;
            dbg!(inbound.send_to(&buf[..n], client_addr).await)?; // FIX: to_string
            trace!(
                len = n,
                "sending a UDP packet from {} to {}",
                &client_addr,
                "?"
            );
        }
        // Ok::<(), io::Error>
    };

    let (rab, rba): (io::Result<()>, io::Result<()>) = tokio::join!(atob, btoa);
    Ok((0, 0)) // FIX: cnt
}
