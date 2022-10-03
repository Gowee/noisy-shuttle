use ring::agreement::EphemeralPrivateKey;
use rustls::internal::msgs::enums::ExtensionType;
use rustls::{
    ClientConnection as RustlsClientConnection, ContentType as TlsContentType, HandshakeType,
    NamedGroup, ProtocolVersion, ServerName,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::warn;
use tracing::{debug, trace};

use std::io;
use std::mem::{self, MaybeUninit};
use std::sync::Arc;

use crate::ring_patch::EphemeralPrivateKeyDangerousExt;
use crate::totp::Totp;
use crate::utils::{parse_tls_plain_message, u16_from_be_slice, ServerHelloPayloadExt};
use crate::FingerprintSpec;

use crate::utils::{read_tls_message, HandshakeStateExt, NoCertificateVerification, TlsMessageExt};

use super::common::{
    derive_psk, SnowyStream, DEFAULT_ALPN_PROTOCOLS, MAXIMUM_CIPHERTEXT_LENGTH, NOISE_PARAMS,
    PSKLEN, TLS_RECORD_HEADER_LENGTH,
};

/// Client with config to establish snowy tunnels with peer servers
#[derive(Debug, Clone)]
pub struct Client {
    pub key: [u8; PSKLEN],
    pub server_name: ServerName,
    pub fingerprint_spec: Arc<FingerprintSpec>,
    pub totp: Totp,
    // pub verify_tls: bool,
}

impl Client {
    /// Create a client with a pre-shared key and a server name for camouflage
    ///
    /// The server name would be sent out as [Server Name Indication](https://en.wikipedia.org/wiki/Server_Name_Indication).
    /// Generally, it should match the camouflage server address specified on a tunnel's server-side. .
    pub fn new(key: impl AsRef<[u8]>, server_name: ServerName) -> Self {
        let key = key.as_ref();
        Client {
            key: derive_psk(key),
            server_name,
            fingerprint_spec: Default::default(),
            totp: Totp::new(key, 60, 2),
        }
    }

    /// Create a client with a pre-shared key, a server name for camouflage and additionally a
    /// fingerprint specification used to apply to TLS ClientHello
    pub fn new_with_fingerprint(
        key: impl AsRef<[u8]>,
        server_name: ServerName,
        fingerprint_spec: FingerprintSpec,
    ) -> Self {
        let key = key.as_ref();
        Client {
            key: derive_psk(key),
            server_name,
            fingerprint_spec: Arc::new(fingerprint_spec),
            totp: Totp::new(key, 60, 2),
        }
    }

    /// Handshake with a peer server of the connected `TcpStream`
    pub async fn connect(&self, mut stream: TcpStream) -> io::Result<SnowyStream> {
        let builder = snow::Builder::new(NOISE_PARAMS.clone());
        // generate the ephemeral key manually to have full control over it
        let e = builder
            .generate_keypair()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let kxkey = unsafe { EphemeralPrivateKey::x25519_from_bytes(&e.private) }.map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                "failed to convert Noise key to Ring key",
            )
        })?;
        let kxkey = (NamedGroup::X25519, kxkey);
        let mut initiator = snow::Builder::new(NOISE_PARAMS.clone())
            .psk(0, &self.key)
            .fixed_ephemeral_key_for_testing_only(&e.private)
            .build_initiator()
            .expect("Noise params valid");
        // EphemeralPrivateKey::generate(alg, rng)
        // the orthodox usage has no way to get the private key of e
        // let mut initiator = snow::Builder::new(NOISE_PARAMS.clone())
        //     .psk(0, &self.key)
        //     .build_initiator()
        //     .expect("Noise params valid");

        // Noise: -> psk, e
        let psk_e = initiator.writen::<48>().expect("Noise state valid");
        debug_assert_eq!(&psk_e[0..32], &e.public);
        let mut random = [0u8; 32];
        random[0..16].copy_from_slice(&psk_e[32..48]);
        random[16..32].copy_from_slice(&self.totp.sign_current::<16>(&psk_e[0..32]));
        // let random = <[u8; 32]>::try_from(&psk_e[0..32]).unwrap();
        // let mut session_id = [0u8; 32];
        // session_id[..16].copy_from_slice(&psk_e[32..48]);
        // session_id[16..].copy_from_slice(&self.totp.sign_current::<16>(&psk_e[0..32])); // timesig
        trace!(
            "noise ping to {:?}, psk_e {:x?}, timesig: {:x?}",
            &stream,
            psk_e,
            &random[16..]
        );

        let chwriter = self
            .fingerprint_spec
            .get_client_hello_overwriter(true, true);
        // TODO: option for verifying camouflage cert
        let mut tlsconf = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification {}))
            .with_no_client_auth();
        if let Some(ref ja3) = self.fingerprint_spec.ja3 {
            // fingerprint_spec.alpn is effective iff alpn is set in ja3
            if ja3
                .extensions_as_typed()
                .any(|ext| ext == ExtensionType::ALProtocolNegotiation)
            {
                // It is necessary to add it to conf. Only adding it to allowed_unsolicited_extensions
                // resulted in TLS client rejection when ALPN is negeotiated.
                tlsconf.alpn_protocols = self
                    .fingerprint_spec
                    .alpn
                    .as_ref()
                    .cloned()
                    .unwrap_or_else(|| Vec::from(DEFAULT_ALPN_PROTOCOLS.map(Vec::from)));
            }
        }
        // Noise pub key would be re-used as the key of TLS KeyShare only if KeyShare is activated.
        // Otherwise, Noise pub key is re-used as the key in ClientKeyExchange.
        let noise_as_keyshare = tlsconf.supports_version(ProtocolVersion::TLSv1_3)
            && self.fingerprint_spec.may_use_keyshare_curve(kxkey.0);
        let (fixed_kskey, fixed_kxkey) = if noise_as_keyshare {
            trace!("use Noise key as KeyShare key for {:?}", stream);
            (Some(kxkey), None)
        } else {
            // The caller should ensure fpspec drop TLS 1.3. Otherwise, there would be no way to 
            // send Noise pub key when TLS1.3 is negeotiated and KeyShare is unset
            // (ClientHello retry is not supported yet).
            trace!("use Noise key as ClientKeyExchange key for {:?}", stream);
            (None, Some(kxkey))
        };

        let mut tlsconn = rustls::ClientConnection::new_with(
            Arc::new(tlsconf.clone()),
            self.server_name.clone(),
            random.into(),
            None,
            fixed_kskey,
            fixed_kxkey,
            chwriter,
        )
        .expect("TLS config valid");

        let mut buf: Vec<MaybeUninit<u8>> =
            Vec::with_capacity(TLS_RECORD_HEADER_LENGTH + MAXIMUM_CIPHERTEXT_LENGTH);
        let mut buf: Vec<u8> = unsafe {
            buf.set_len(buf.capacity());
            mem::transmute(buf)
        };
        let len = tlsconn.write_tls(&mut io::Cursor::new(&mut buf))?; // Write for Vec is dummy?
        unsafe { buf.set_len(len) };
        debug_assert!(!tlsconn.wants_write() & tlsconn.wants_read());
        stream.write_all(&buf).await?; // forward Client Hello

        // read Server Hello
        let shp = read_tls_message(&mut stream, &mut buf)
            .await?
            .ok()
            .and_then(|_| parse_tls_plain_message(&buf).ok())
            .filter(|msg| msg.is_handshake_type(HandshakeType::ServerHello))
            .and_then(|msg| msg.into_server_hello_payload())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "Not or invalid Server Hello")
            })?;

        // server negotiated TLS version
        match shp.get_server_tls_version() {
            Some(ProtocolVersion::TLSv1_3) => {
                // TLS 1.3: handshake treated as done
                // In TLS 1.3, all messages after client/server hello are encrypted by the session
                // key generated by ECDHE. An eavesdropper won't be able to see certificate and
                // certificate verify (signature of ECDHE public key). So there is no need to copy
                // handshake procedures any more. Actually, even Server Hello can also be
                // fabricated locally without be distinguished. Here the fingerprint in ServerHello
                // is useful, though.
                // TODO: Cache SH for latter use instead of request camouflage server every time.
                // TODO: Send mibble box compatibility CCS and more ApplicationData frames, as
                //   in typical TLS 1.3 handshake.
            }
            _ => {
                // TLS 1.2: conitnue full handshake via rustls
                // In TLS 1.2, the handshake procedures are basically transparent. That is, an
                // eavesdropper could verify the unencrypted signature against the camouflage
                // servers' public key. So the camouflage server is requested every time.

                // feed previously read Server Hello
                tlsconn.read_tls(&mut io::Cursor::new(&mut buf))?;
                tls12_handshake(&mut tlsconn, &mut stream, false).await?;
                // TLS1.2 handshake done
            }
        }

        // Noise: <- e, ee
        let mut pong = Vec::with_capacity(5 + 48 + 24); // 0..24 random padding
        read_tls_message(&mut stream, &mut pong)
            .await?
            .map_err(|_e| {
                io::Error::new(io::ErrorKind::InvalidData, "First data frame not noise")
            })?; // TODO: timeout
        if pong.len() < 5 + 48 {
            warn!(
                "Noise handshake {} <-> {} failed. Wrong key or time out of sync?",
                stream.local_addr().unwrap(),
                stream.peer_addr().unwrap()
            );
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Noise handshake failed due to message length shorter than expected",
            ));
        }
        let e_ee: [u8; 48] = pong[5..5 + 48].try_into().unwrap(); // 32B pubkey + 16B AEAD tag
        trace!(
            pad_len = pong.len() - (5 + 48),
            "e, ee from {:?}: {:x?}",
            stream,
            &e_ee
        );
        initiator
            .read_message(&e_ee, &mut [])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?; // TODO: allow recovery?
        let noise = initiator
            .into_transport_mode()
            .expect("Noise handshake done");
        trace!("noise handshake done with {:?}", stream);
        Ok(SnowyStream::new(stream, noise))
    }
}

async fn tls12_handshake(
    tlsconn: &mut RustlsClientConnection,
    stream: &mut TcpStream,
    stop_after_server_ccs: bool,
) -> io::Result<()> {
    let mut buf: Vec<MaybeUninit<u8>> =
        Vec::with_capacity(TLS_RECORD_HEADER_LENGTH + MAXIMUM_CIPHERTEXT_LENGTH);
    let mut buf: Vec<u8> = unsafe {
        buf.set_len(buf.capacity());
        mem::transmute(buf)
    };
    let mut seen_ccs = false;
    loop {
        match (tlsconn.wants_read(), tlsconn.wants_write()) {
            (_, true) => {
                // flow: client -> server
                // always prefer to write out over reading in, to avoid deadlock-like waiting
                let len = tlsconn.write_tls(&mut io::Cursor::new(&mut buf)).unwrap();
                // typically, multiple messages are written by a single call
                trace!(
                    first_protocol = u16_from_be_slice(&buf[1..3]),
                    first_msglen = u16_from_be_slice(&buf[3..5]),
                    totallen = len,
                    "tls handshake {} => {}, first type: {:?}",
                    stream.local_addr().unwrap(),
                    stream.peer_addr().unwrap(),
                    TlsContentType::from(buf[0]),
                );
                stream.write_all(&buf[..len]).await?;
            }
            (true, false) => {
                // flow: client <- server
                stream.read_exact(&mut buf[..5]).await?;
                let len = u16_from_be_slice(&buf[3..5]) as usize;
                stream.read_exact(&mut buf[5..5 + len]).await?;
                trace!(
                    protocol = u16_from_be_slice(&buf[1..3]),
                    msglen = u16_from_be_slice(&buf[3..5]),
                    "tls handshake {} <= {}, type: {:?}",
                    stream.local_addr().unwrap(),
                    stream.peer_addr().unwrap(),
                    TlsContentType::from(buf[0]),
                );
                let n = tlsconn
                    .read_tls(&mut io::Cursor::new(&mut buf[..5 + len]))
                    .unwrap();
                debug_assert_eq!(n, 5 + len);
                tlsconn.process_new_packets().map_err(|e| {
                    debug!(
                        "tls state error when handshaking {} <-> {}: {:?}",
                        stream.local_addr().unwrap(),
                        stream.peer_addr().unwrap(),
                        e
                    );
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("TLS handshake state: {}", e),
                    )
                })?;
                match TlsContentType::from(buf[0]) {
                    TlsContentType::ChangeCipherSpec => {
                        seen_ccs = true;
                        // after server ChangeCipherSpec, the final Handshake Finished message is encrypted
                        // so it can be used to carry other data
                        if stop_after_server_ccs {
                            break;
                        }
                    }
                    _ => {
                        debug_assert_eq!(buf[0], TlsContentType::Handshake.get_u8());
                        // by default, handshake is done after the Handshake Finished message
                        if seen_ccs {
                            break;
                        }
                    }
                }
            }
            (false, false) => break,
        }
    }
    trace!(
        "tls handshake {} <-> {} done",
        stream.local_addr().unwrap(),
        stream.peer_addr().unwrap(),
    );
    Ok(())
}
