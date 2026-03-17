use lru::LruCache;
use rustls::CipherSuite;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{ReadHalf, WriteHalf};
use tokio::net::{TcpStream, ToSocketAddrs};
use tracing::debug;

use std::fmt::Debug;
use std::io;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::common::{derive_psk, SnowyStream, NOISE_PARAMS, PSKLEN};
use crate::totp::Totp;
use crate::tls_msgs::{
    build_change_cipher_spec_record, build_server_hello_tls13, ClientHelloInjection,
};
use crate::utils::{read_tls_message, u16_from_be_slice};
use blake2::Digest;

/// Server with config to establish snowy tunnels with peer clients
#[derive(Debug)]
pub struct Server<A: ToSocketAddrs + Debug> {
    pub key: [u8; PSKLEN],
    pub camouflage_addr: A,
    pub replay_filter: Mutex<LruCache<[u8; 32], SocketAddr>>, // TODO: TOTP; prevent DoS attack
    pub totp: Totp,
}

impl<A: ToSocketAddrs + Debug> Server<A> {
    /// Create a server with a pre-shared key, a camouflage server address, and a capacity of the
    /// internal LRU-based replay filter queue.
    ///
    /// The camouflage server address is to where TLS handshakes from clients are forwarded and
    /// from where responses are forwarded backed to clients. Generally, it should match the server
    /// name specified in a tunnel's client-side.
    pub fn new(key: impl AsRef<[u8]>, camouflage_addr: A, replay_filter_size: usize) -> Self {
        let key = key.as_ref();
        Server {
            key: derive_psk(key),
            camouflage_addr,
            replay_filter: Mutex::new(LruCache::new(replay_filter_size)),
            totp: Totp::new(key, 60, 2),
        }
    }

    /// Accept a incoming TcpStream as a snowy tunnel.
    ///
    /// The server tries to authenticate a client by a Noise handshake message piggybacked by a TLS
    /// ClientHello (the first message in TLS handshakes). If the client is successfully
    /// authenticated as a tunnel peer, the server starts to forward traffic between the client and
    /// the camouflage server until TLS handshakes are finished. After that, the server sends back
    /// noise handshake in response to the client's challenge and transmute the connection into a
    /// snowy tunnel.
    ///
    /// If the client is not authenticated, it returns immediately with pending buffer exposed in
    /// [`AcceptError`]. The caller may decide to proceed to forward traffic between the client and
    /// the camouflage server on its own (falling back to dumb relay) or just reject/drop the
    /// connection.
    pub async fn accept(&self, mut inbound: TcpStream) -> Result<SnowyStream, AcceptError> {
        use AcceptError::*;

        let mut buf = Vec::new();

        // Read ClientHello record.
        match read_tls_message(&mut inbound, &mut buf).await?.ok() {
            Some(()) => {}
            None => {
                return Err(ClientHelloInvalid { buf, io: inbound });
            }
        }

        let injection = match ClientHelloInjection::locate(&buf) {
            Ok(i) => i,
            Err(_) => return Err(ClientHelloInvalid { buf, io: inbound }),
        };

        // Build prologue (zero only injection points).
        let mut prologue = buf.clone();
        prologue[injection.x25519_keyshare.clone()].fill(0);
        prologue[injection.session_id_noise.clone()].fill(0);

        let mut responder = snow::Builder::new(NOISE_PARAMS.clone())
            .psk(0, &self.key)
            .prologue(&prologue)
            .build_responder()
            .expect("Valid NOISE params");

        // Reconstruct Noise msg1 = e(32) + ct+tag(24).
        let mut msg1 = [0u8; 56];
        msg1[0..32].copy_from_slice(&buf[injection.x25519_keyshare.clone()]);
        msg1[32..56].copy_from_slice(&buf[injection.session_id_noise.clone()]);

        let mut ts_out = [0u8; 8];
        if responder.read_message(&msg1, &mut ts_out).is_err() {
            return Err(Unauthenticated { buf, io: inbound });
        }

        // Timestamp skew check (±60s).
        let ts = u64::from_be_bytes(ts_out);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if ts.abs_diff(now) > 60 {
            return Err(Unauthenticated { buf, io: inbound });
        }

        let e: [u8; 32] = buf[injection.x25519_keyshare.clone()].try_into().unwrap();
        debug!("authenticated {:?}", &inbound);
        {
            let mut rf = self.replay_filter.lock().unwrap();
            if let Some(&client_id) = rf.get(&e) {
                return Err(ReplayDetected {
                    buf,
                    io: inbound,
                    nonce: e,
                    first_from: client_id,
                });
            }
            rf.put(e, inbound.peer_addr().unwrap());
        }

        // Build a placeholder ServerHello (random + keyshare zero) to hash.
        let cipher_suite = CipherSuite::TLS13_AES_128_GCM_SHA256;
        let placeholder_random = [0u8; 32];
        let placeholder_keyshare = [0u8; 32];
        let session_id_full = buf[injection.session_id_full.clone()].to_vec();
        let sh_placeholder = build_server_hello_tls13(session_id_full.clone(), cipher_suite, placeholder_random, placeholder_keyshare);

        let h16 = {
            let digest = blake2::Blake2s256::digest(&sh_placeholder);
            let mut out = [0u8; 16];
            out.copy_from_slice(&digest[..16]);
            out
        };

        // Noise message2: "<- e, ee" with payload=hash16 => 32 (e) + 16 (ct) + 16 (tag) = 64.
        let mut msg2 = [0u8; 64];
        let len = responder
            .write_message(&h16, &mut msg2)
            .map_err(|e| AcceptError::IoError(io::Error::new(io::ErrorKind::InvalidData, e)))?;
        debug_assert_eq!(len, 64);
        let server_e: [u8; 32] = msg2[0..32].try_into().unwrap();
        let server_random: [u8; 32] = msg2[32..64].try_into().unwrap();

        let sh = build_server_hello_tls13(session_id_full, cipher_suite, server_random, server_e);
        inbound.write_all(&sh).await?;
        inbound.write_all(&build_change_cipher_spec_record()).await?;

        let responder = responder
            .into_transport_mode()
            .expect("Noise handshake done");
        Ok(SnowyStream::new(inbound, responder))
    }
}

/// Error returned by [`Server::accept`] with self-explanatory fields
pub enum AcceptError {
    IoError(io::Error),
    Unauthenticated {
        buf: Vec<u8>,
        io: TcpStream,
    },
    ReplayDetected {
        buf: Vec<u8>,
        io: TcpStream,
        nonce: [u8; 32],
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

// Adapted from: https://github.com/ihciah/shadow-tls/blob/2bbdc26cff1120ba9c8eded39ad743c4c4f687c4/src/protocol.rs#L138
async fn copy_until_tls12_handshake_finished<'a>(
    mut read_half: ReadHalf<'a>,
    mut write_half: WriteHalf<'a>,
) -> io::Result<()> {
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
        let data_size = u16_from_be_slice(&header_buf[3..5]) as usize;

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

async fn relay_until_tls12_handshake_finished(
    inbound: &mut TcpStream,
    outbound: &mut TcpStream,
) -> io::Result<()> {
    let (rin, win) = inbound.split();
    let (rout, wout) = outbound.split();
    let (a, b) = tokio::join!(
        copy_until_tls12_handshake_finished(rin, wout),
        copy_until_tls12_handshake_finished(rout, win)
    );
    a?;
    b?;
    Ok(())
}
