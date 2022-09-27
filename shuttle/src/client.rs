use anyhow::Result;


use snowy_tunnel::SnowyStream;
use socks5::sync::FromIO;
use socks5_protocol as socks5;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::Instant;
use tracing::{debug, info, instrument, trace, warn};

use std::io::{self, Cursor};
use std::net::SocketAddr;

use std::sync::Arc;

use crate::connector::{
    AdHocConnector, Connector, Preflighter, PREFLIHGTER_CONNIDLE, PREFLIHGTER_EMA_COEFF,
};
use crate::opt::CltOpt;
use crate::trojan::{
    Cmd, TrojanLikeRequest,
    TrojanUdpDatagramReceiver, TrojanUdpDatagramSender, MAX_DATAGRAM_SIZE,
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
    let _authreq = socks5::AuthRequest::read(&mut inbound)
        .await
        .map_err(|e| e.to_io_err())?;
    // socks5::Version::V5
    //     .write(&mut inbound)
    //     .await
    //     .map_err(|e| e.to_io_err())?;
    // socks5::AuthResponse::new(authreq.select_from(&[socks5::AuthMethod::Noauth]))
    //     .write(&mut inbound)
    //     .await
    //     .map_err(|e| e.to_io_err())?;
    inbound.write_all(&[0x05, 0x00]).await?;
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
            // socks5::CommandResponse::success(SocketAddr::from_str("0.0.0.0:0").unwrap().into())
            //     .write(&mut inbound)
            //     .await
            //     .map_err(|e| e.to_io_err())?; // TODO: return error from connect?
            inbound
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                .await?;
            let mut snowys = connector.connect().await.map_err(|e| {
                warn!("failed to establish snowy tunnel: {}", e);
                e
            })?;
            // Try to send the Trojan-like header along with the first inbound packet to avoid
            // fixed TLS frame size.
            //   ref: https://github.com/trojan-gfw/trojan/blob/304054008bb01d6aad51c477b6b7d4e79a5853db/src/session/clientsession.cpp#L194
            // (WON'T?) FIX: This assumes client always send before reading data after a TCP
            //   connection is established. Compatility problem might reside here.
            let mut first_packet = unsafe { vec_uninit(MAX_FIRST_PACKET_SIZE) };
            let mut offset =
                TrojanLikeRequest::new(Cmd::Connect, address).encode(&mut first_packet);
            debug!(
                peer = inbound.peer_addr().unwrap().to_string(),
                local_in = inbound.local_addr().unwrap().to_string(),
                local_out = snowys.as_inner().local_addr().unwrap().to_string(),
                remote = snowys.as_inner().peer_addr().unwrap().to_string(),
                "relay"
            );
            offset += inbound.read(&mut first_packet[offset..]).await?;
            snowys.write_all(&first_packet[..offset]).await?;
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
            // inbound_udp.connect(address.to_string()).await?; // FIX: tostring
            let mut bnd_addr = inbound.local_addr().unwrap();
            dbg!(bnd_addr);
            bnd_addr.set_port(inbound_udp.local_addr().unwrap().port());
            dbg!(bnd_addr);

            let mut buffered_inbound = BufWriter::new(&mut inbound);
            // socks5::Version::V5
            //     .write(&mut buffered_inbound)
            //     .await
            //     .map_err(|e| e.to_io_err())?;
            socks5::CommandResponse::success(bnd_addr.into())
                .write(&mut buffered_inbound)
                .await
                .map_err(|e| e.to_io_err())?;
            buffered_inbound.flush().await?;
            // dbg!(
            //     socks5::Address::from(bnd_addr)
            //         .write(&mut buffered_inbound)
            //         .await
            // )
            // .map_err(|e| e.to_io_err())?;
            let mut snowys = connector.connect().await.map_err(|e| {
                warn!("failed to establish snowy tunnel: {}", e);
                e
            })?;
            let outbuf = TrojanLikeRequest::new(Cmd::UdpAssociate, address);
            debug!(
                peer = inbound.peer_addr().unwrap().to_string(),
                local_in = inbound.local_addr().unwrap().to_string(),
                local_out = snowys.as_inner().local_addr().unwrap().to_string(),
                remote = snowys.as_inner().peer_addr().unwrap().to_string(),
                "relay udp"
            );
            dbg!(
                relay_udp_with(
                    &mut inbound,
                    &mut inbound_udp,
                    &mut snowys,
                    outbuf.encoded()
                )
                .await
            )
            // TODO: log
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
            Ok((0, 0))
        }
    }
}

// async fn relay_tcp(inbound: &TcpStream, outbound: &SnowyStream) -> io::Result<(0,0 )> {

// }
#[instrument]
async fn relay_udp_with(
    inbound_tcp: &mut TcpStream,
    inbound: &mut UdpSocket,
    outbound: &mut SnowyStream,
    outbuf: Vec<u8>,
) -> io::Result<(u64, u64)> {
    // let client_addr = "unknown";
    let _remote_addr = outbound.as_inner().peer_addr().unwrap();
    let (outr, outw) = tokio::io::split(outbound);
    let mut outr = BufReader::new(outr);
    let mut outw = BufWriter::new(outw);
    outw.write_all(&outbuf).await?;
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
            let dest_addr = socks5::Address::read_from(&mut io::Cursor::new(&buf[3..n]))
                .map_err(|e| e.to_io_err())?;
            let addrlen = dest_addr.serialized_len().unwrap();

            // When sending udp packet from server to client, addr is the original address that the
            // UDP socket on server received.
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
        // Ok::<(), io::Error>
    };

    let (_rab, _rba): (io::Result<()>, io::Result<()>) = tokio::join!(atob, btoa);
    dbg!(inbound_tcp);
    Ok((0, 0)) // FIX: cnt
}
