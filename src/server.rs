use lru::LruCache;
use rustls::{HandshakeType, ProtocolVersion};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{ReadHalf, WriteHalf};
use tokio::net::TcpStream;

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Mutex;

use super::common::{SnowyStream, NOISE_PARAMS, PSKLEN};

use crate::common::derive_psk;
use crate::utils::{
    get_server_tls_version, parse_tls_plain_message, read_tls_message, u16_from_slice,
    TlsMessageExt,
};

#[derive(Debug)]
pub struct Server {
    pub key: [u8; PSKLEN],
    pub camouflage_addr: SocketAddr,
    pub replay_filter: Mutex<LruCache<[u8; 32], SocketAddr>>, // TODO: TOTP; prevent DoS attack
}

impl Server {
    pub fn new(key: &[u8], camouflage_addr: SocketAddr, replay_filter_size: usize) -> Self {
        Server {
            key: derive_psk(key),
            camouflage_addr,
            replay_filter: Mutex::new(LruCache::new(replay_filter_size)),
        }
    }

    pub async fn accept(&self, mut inbound: TcpStream) -> Result<SnowyStream, AcceptError> {
        use AcceptError::*;

        dbg!("acc init");
        let mut responder = snow::Builder::new(NOISE_PARAMS.clone())
            .psk(0, &self.key)
            .build_responder()
            .expect("Valid NOISE params");
        let mut buf = Vec::new();

        // Noise: -> psk, e
        let mut psk_e = [0u8; 48];
        // let _tls1_3 = false;
        match read_tls_message(&mut inbound, &mut buf)
            .await?
            .ok()
            .and_then(|_| parse_tls_plain_message(&buf).ok())
            .filter(|msg| msg.is_handshake_type(HandshakeType::ClientHello))
            .and_then(|msg| msg.into_client_hello_payload())
        {
            Some(chp) => {
                chp.random.write_slice(&mut psk_e[..32]); // client random
                let s: (usize, [u8; 32]) = chp.session_id.into();
                psk_e[32..].copy_from_slice(&s.1[..16]); // session id

                // tls1_3 = get_client_tls_versions(chp)
                //     .map(|vers| {
                //         vers.iter()
                //             .any(|&ver| ver == ProtocolVersion::TLSv1_3)
                //     })
                //     .unwrap_or(false);
            }
            None => {
                return Err(ClientHelloInvalid { buf, io: inbound });
            }
        }
        let e = psk_e[..32].try_into().unwrap();
        {
            let mut rf = self.replay_filter.lock().unwrap();
            if let Some(&client_id) = rf.get(&e) {
                return Err(ReplayDetected {
                    buf,
                    io: inbound,
                    nounce: e,
                    first_from: client_id,
                });
            }
            responder.read_message(&psk_e, &mut []).is_err()
                && return Err(Unauthenticated { buf, io: inbound });
            rf.put(e, inbound.peer_addr().expect("TODO"));
        }
        dbg!("noise ping confirmed");
        // Ref: https://tls12.xargs.org/
        //      https://github.com/Gowee/rustls-mod/blob/a94a0055e1599d82bd8e212ad2dd19410204d5b7/rustls/src/msgs/message.rs#L88
        //   record header + handshake header + server version + server random + session id len +
        //   session id
        let mut outbound = TcpStream::connect(self.camouflage_addr).await?;

        // forward Client Hello in whole to camouflage server
        outbound.write_all(&buf).await?;

        // read camouflage Server Hello
        let shp = match read_tls_message(&mut outbound, &mut buf)
            .await?
            .ok()
            .and_then(|_| parse_tls_plain_message(&buf).ok())
            .filter(|msg| msg.is_handshake_type(HandshakeType::ServerHello))
            .and_then(|msg| msg.into_server_hello_payload())
        {
            Some(shp) => shp,
            None => {
                return Err(ServerHelloInvalid {
                    buf,
                    inbound,
                    outbound,
                });
            }
        };

        inbound.write_all(&buf).await?;
        match get_server_tls_version(&shp) {
            Some(ProtocolVersion::TLSv1_3) => {
                // TLS 1.3: handshake done
            }
            _ => {
                // TLS 1.2: continue handshake
                relay_until_handshake_finished(&mut inbound, &mut outbound).await?;
                // force flush TCP before sending e, ee in a dirty way; TODO: fix client
                // this prevents client TLS implmentation from catching too much data in buffer
                if !inbound.nodelay()? {
                    inbound.set_nodelay(true)?;
                    inbound.write_all(&[]).await?;
                    inbound.set_nodelay(false)?;
                }
            }
        }

        dbg!("hs done");
        // handshake done, drop connection to camouflage server
        tokio::spawn(async move {
            let _ = outbound.shutdown().await;
        });

        dbg!("p2");
        // Noise: <- e, ee
        let mut pong = [0u8; 5 + 48]; // TODO: pad to some length
        pong[..5].copy_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x30]);
        let len = responder
            .write_message(&[], &mut pong[5..])
            .expect("Valid NOISE state");
        debug_assert_eq!(len, 48);
        inbound.write_all(&pong).await?;

        dbg!("p3");

        let responder = responder
            .into_transport_mode()
            .expect("NOISE handshake finished");
        // let len = responder.write_message(b"pong", &mut buf).unwrap(); // message being &mut [] resulted in mysterious Decrypt error
        Ok(SnowyStream::new(inbound, responder))
    }
}

pub enum AcceptError {
    IoError(io::Error),
    Unauthenticated {
        buf: Vec<u8>,
        io: TcpStream,
    },
    ReplayDetected {
        buf: Vec<u8>,
        io: TcpStream,
        nounce: [u8; 32],
        first_from: SocketAddr,
    },
    ClientHelloInvalid {
        buf: Vec<u8>,
        io: TcpStream,
    },
    ServerHelloInvalid {
        buf: Vec<u8>,
        inbound: TcpStream,
        outbound: TcpStream,
    },
}

impl From<io::Error> for AcceptError {
    fn from(err: io::Error) -> Self {
        Self::IoError(err)
    }
}

async fn copy_until_handshake_finished<'a>(
    mut read_half: ReadHalf<'a>,
    mut write_half: WriteHalf<'a>,
) -> io::Result<()> {
    //  Adapted from: https://github.com/ihciah/shadow-tls/blob/2bbdc26cff1120ba9c8eded39ad743c4c4f687c4/src/protocol.rs#L138
    const HANDSHAKE: u8 = 0x16;
    const CHANGE_CIPHER_SPEC: u8 = 0x14;
    // header_buf is used to read handshake frame header, will be a fixed size buffer.
    let mut header_buf = [0u8; 5];
    // data_buf is used to read and write data, and can be expanded.
    let mut data_buf = vec![0u8; 2048];
    let mut has_seen_change_cipher_spec = false;

    loop {
        // read exact 5 bytes
        read_half.read_exact(&mut header_buf).await?;

        // parse length
        let data_size = u16_from_slice(&header_buf[3..5]) as usize;

        // copy header and that much data
        write_half.write_all(&header_buf).await?;
        if data_size > data_buf.len() {
            data_buf.resize(data_size, 0);
        }
        read_half.read_exact(&mut data_buf[0..data_size]).await?;
        write_half.write_all(&data_buf[0..data_size]).await?;

        // check header type
        if header_buf[0] != HANDSHAKE {
            if header_buf[0] != CHANGE_CIPHER_SPEC {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid TLS state",
                ));
            }
            if !has_seen_change_cipher_spec {
                has_seen_change_cipher_spec = true;
                continue;
            }
        }
        if has_seen_change_cipher_spec {
            break;
        }
    }
    Ok(())
}

async fn relay_until_handshake_finished(
    inbound: &mut TcpStream,
    outbound: &mut TcpStream,
) -> io::Result<()> {
    let (rin, win) = inbound.split();
    let (rout, wout) = outbound.split();
    dbg!("copy tls hs");
    let (a, b) = tokio::join!(
        copy_until_handshake_finished(rin, wout),
        copy_until_handshake_finished(rout, win)
    );
    a?;
    b?;
    Ok(())
}
