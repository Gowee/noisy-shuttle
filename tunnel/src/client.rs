use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::trace;

use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::totp::Totp;
use crate::utils::read_tls_message;
use blake2::Digest;

use super::common::{derive_psk, SnowyStream, NOISE_PARAMS, PSKLEN};
use crate::tls_msgs::{
    build_change_cipher_spec_record, build_chrome133_client_hello, ClientHelloInjection,
    ServerHelloInjection,
};

/// Client with config to establish snowy tunnels with a peer server
#[derive(Debug, Clone)]
pub struct Client {
    pub key: [u8; PSKLEN],
    pub server_name: String,
    pub totp: Totp,
}

impl Client {
    /// Create a client with a pre-shared key and a server name for camouflage.
    pub fn new(key: impl AsRef<[u8]>, server_name: impl AsRef<str>) -> Self {
        let key = key.as_ref();
        Client {
            key: derive_psk(key),
            server_name: server_name.as_ref().to_string(),
            totp: Totp::new(key, 60, 2),
        }
    }

    /// Handshake with a peer server of the connected `TcpStream`.
    pub async fn connect(&self, mut stream: TcpStream) -> io::Result<SnowyStream> {
        // 1) Build Chrome-133 ClientHello template record.
        let mut ch = build_chrome133_client_hello(&self.server_name);

        // 2) Locate injection points (X25519 keyshare + first 24 bytes of session id).
        let injection = ClientHelloInjection::locate(&ch)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // 3) Compute prologue: zero only injection points.
        let mut prologue = ch.clone();
        prologue[injection.x25519_keyshare.clone()].fill(0);
        prologue[injection.session_id_noise.clone()].fill(0);

        // 4) Build Noise initiator with prologue and write first message with timestamp payload.
        let mut initiator = snow::Builder::new(NOISE_PARAMS.clone())
            .psk(0, &self.key)
            .prologue(&prologue)
            .build_initiator()
            .expect("Noise params valid");

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let ts = now.to_be_bytes(); // u64

        let mut msg1 = [0u8; 56]; // 32 e + 8 ct + 16 tag = 56
        let len = initiator
            .write_message(&ts, &mut msg1)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        if len != msg1.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Noise message1 length mismatch",
            ));
        }

        // Inject e into X25519 key share, and ciphertext+tag into SessionID[0..24].
        ch[injection.x25519_keyshare.clone()].copy_from_slice(&msg1[0..32]);
        ch[injection.session_id_noise.clone()].copy_from_slice(&msg1[32..56]);

        trace!(
            "sending templated ClientHello to {:?}, ts={}, msg1={:x?}",
            &stream,
            now,
            &msg1[..]
        );
        stream.write_all(&ch).await?;

        // 5) Read fabricated ServerHello.
        let mut buf = Vec::new();
        read_tls_message(&mut stream, &mut buf)
            .await?
            .map_err(|_e| io::Error::new(io::ErrorKind::InvalidData, "Invalid TLS record"))?;

        let (server_e, sh_random_ct, sh_bytes) = parse_fabricated_serverhello(&buf)?;

        // 6) Decrypt hash in ServerRandom via Noise message2: "<- e, ee".
        let mut msg2 = Vec::with_capacity(64);
        msg2.extend_from_slice(&server_e);
        msg2.extend_from_slice(&sh_random_ct);
        let mut decrypted = [0u8; 16];
        initiator
            .read_message(&msg2, &mut decrypted)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // 7) Verify ServerHello hash (over zeroed SH injection points).
        let expected = hash_serverhello_zeroed(&sh_bytes)?;
        if decrypted != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ServerHello hash mismatch",
            ));
        }

        // 8) Drop server CCS, then send our CCS and switch to transport mode.
        let mut ccs = Vec::new();
        read_tls_message(&mut stream, &mut ccs)
            .await?
            .map_err(|_e| io::Error::new(io::ErrorKind::InvalidData, "Missing CCS"))?;
        stream.write_all(&build_change_cipher_spec_record()).await?;

        let noise = initiator
            .into_transport_mode()
            .map_err(|_e| io::Error::new(io::ErrorKind::InvalidData, "Noise not ready"))?;

        Ok(SnowyStream::new(stream, noise))
    }
}

fn parse_fabricated_serverhello(buf: &[u8]) -> io::Result<([u8; 32], [u8; 32], Vec<u8>)> {
    let injection = ServerHelloInjection::locate(buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let mut random = [0u8; 32];
    random.copy_from_slice(&buf[injection.random.clone()]);
    let mut e = [0u8; 32];
    e.copy_from_slice(&buf[injection.x25519_keyshare.clone()]);

    Ok((e, random, buf.to_vec()))
}

fn hash_serverhello_zeroed(sh_record: &[u8]) -> io::Result<[u8; 16]> {
    let mut tmp = sh_record.to_vec();
    let injection = ServerHelloInjection::locate(&tmp)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    tmp[injection.random.clone()].fill(0);
    tmp[injection.x25519_keyshare.clone()].fill(0);

    let h = blake2::Blake2s256::digest(&tmp);
    let mut out = [0u8; 16];
    out.copy_from_slice(&h[..16]);
    Ok(out)
}

