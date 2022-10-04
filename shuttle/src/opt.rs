use ja3_rustls::{ConcatenatedParser, Ja3};
use structopt::clap::AppSettings::{ColoredHelp, DeriveDisplayOrder};
use structopt::StructOpt;
use structopt_flags::QuietVerbose;

use std::fmt::Debug;
use std::net::SocketAddr;
use std::str::FromStr;

use snowy_tunnel::{Client, FingerprintSpec, Server};

type Array<T> = Vec<T>;

#[derive(Debug, Clone, StructOpt)]
#[structopt(name = "noisy-shuttle", about = "Shuttle for the Internet", global_settings(&[ColoredHelp, DeriveDisplayOrder]))]
pub struct Opt {
    #[structopt(flatten)]
    pub verbose: QuietVerbose,

    #[structopt(subcommand)]
    pub role: Role,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, StructOpt)]
pub enum Role {
    /// Run client
    Client(CltOpt),
    /// Run server
    Server(SvrOpt),
}

#[derive(Debug, Clone, StructOpt)]
pub struct CltOpt {
    /// Local HOST:PORT address for the builtin proxy server to listen on
    #[structopt(name = "LISTEN_ADDR")]
    pub listen_addr: SocketAddr,

    /// Server HOST:PORT address to connect to
    #[structopt(name = "REMOTE_ADDR")]
    pub remote_addr: String,

    /// Server name indication to send to the remote
    #[structopt(name = "SERVER_NAME")]
    pub server_name: String,

    /// Key to encrypt all traffic
    #[structopt(name = "KEY")]
    pub key: String,

    /// Activate multiplex and specify the maximum number of stream per TCP connection  
    #[structopt(short = "x", long = "mux", group = "connecetor-mode")]
    pub mux: Option<usize>,

    // /// Size hint of multiplex connection pool
    // #[structopt(long = "mux_pool_size_hint", default_value = "0")]
    // pub mux_pool_size_hint: usize,

    // pub mux_pool_size_hint: Option<usize>,

    /// Activate preflight, and specify the range of connections to establish in advance
    /// (shortening perceivable delay at risk of higher possibility of being distinguished)
    #[structopt(short ="p", long = "preflight", default_value = "0", parse(try_from_str = parse_preflight_bounds), group = "connecetor-mode")]
    pub preflight: (usize, Option<usize>),

    // UNIMPLEMENTED
    // /// Activate transparent proxy mode, instructing the client to accept raw REDIRECTed TCP
    // /// traffic and TPROXY-ed UDP traffic (plain proxy is disabled in this case)
    // #[cfg(unix)]
    // #[structopt(long = "redir")]
    // pub redir: bool,
    /// JA3 TLS fingerprint to apply to ClientHello (possbily resulted in handshake error due to unsupported algos negotiated)
    #[structopt(long = "tls-ja3", name = "ja3")]
    pub tls_ja3: Option<Ja3>,

    /// ALPN to apply to ClientHello, in text, seperated by comma
    #[structopt(long = "tls-alpn", name = "alpn", parse(try_from_str = parse_alpn_array))]
    pub tls_alpn: Option<Array<Vec<u8>>>,

    /// Signature algorithms to apply to ClientHello, in decimal, seperated by comma
    #[structopt(long = "tls-sigalgos", name = "signature algorithms", parse(try_from_str = parse_u16_array))]
    pub tls_sigalgos: Option<Array<u16>>,

    // Supported TLS versions to apply to ClientHello, in decimal, seperated by comma
    #[structopt(long = "tls-versions", name = "supported versions", parse(try_from_str = parse_u16_array))]
    pub tls_versions: Option<Array<u16>>,

    /// Key Share curves to apply to ClientHello, seperated by comma (only X25519 and GREASE are allowed so far)
    #[structopt(long = "tls-keyshare", name = "keyshare", parse(try_from_str = parse_u16_array))]
    pub tls_keyshare: Option<Array<u16>>,
}

// #[derive(Debug, Clone, StructOpt)]
// pub struct MuxOpt {
// }

#[derive(Debug, Clone, StructOpt)]
pub struct SvrOpt {
    /// Local HOST:PORT address to listen on
    #[structopt(name = "LISTEN_ADDR")]
    pub listen_addr: SocketAddr,

    /// Camouflage HOST:PORT address to connect to for replicating TLS handshaking
    #[structopt(name = "CAMOUFLAGE_ADDR")]
    pub camouflage_addr: String,

    /// Key to encrypt all traffic
    #[structopt(name = "KEY")]
    pub key: String,

    /// Size of the internal time-based LRU replay filter (time window: ±90secs)
    #[structopt(long = "rfsize", default_value = "2048", name = "size")]
    pub replay_filter_size: usize,
}

impl CltOpt {
    pub fn get_fingerprint_spec(&self) -> FingerprintSpec {
        FingerprintSpec {
            ja3: self.tls_ja3.clone(),
            alpn: self.tls_alpn.clone(),
            signature_algos: self.tls_sigalgos.clone(),
            supported_versions: self.tls_versions.clone(),
            keyshare_curves: self.tls_keyshare.clone(),
        }
    }

    pub fn build_client(&self) -> Client {
        Client::new_with_fingerprint(
            self.key.as_bytes(),
            self.server_name.as_str().try_into().unwrap(),
            self.get_fingerprint_spec(),
        )
    }
}

impl SvrOpt {
    pub fn build_server(&self) -> Server<String> {
        Server::new(
            self.key.as_bytes(),
            self.camouflage_addr.clone(),
            self.replay_filter_size,
        )
    }
}

fn parse_preflight_bounds(s: &str) -> Result<(usize, Option<usize>), &str> {
    let s = s.trim();
    if s.is_empty() {
        Ok((0, Some(0)))
    } else if let Ok(n) = s.parse::<usize>() {
        Ok((n, Some(n)))
    } else if let Some(i) = s.find(':') {
        let (a, b) = s.split_at(i);
        let a = a.trim();
        let b = b[1..].trim();
        let a = if a.is_empty() {
            0
        } else {
            a.parse::<usize>()
                .map_err(|_| "Min present but not integer")?
        };
        let b = if b.is_empty() {
            None
        } else {
            Some(
                b.parse::<usize>()
                    .map_err(|_| "Max present but not integer")?,
            )
        };
        if a == 0 && b != Some(0) {
            Err("Min cannot be 0 if max is not 0")
        } else {
            Ok((a, b))
        }
    } else {
        Err("Unrecognized bounds, expected format: NUM, MIN:MAX, MIN:, :MAX")
    }
}

fn parse_u16_array(s: &str) -> Result<Array<u16>, &'static str> {
    ConcatenatedParser::<u16, ','>::from_str(s).map(|p| p.into_inner())
}

fn parse_alpn_array(s: &str) -> Result<Array<Vec<u8>>, &'static str> {
    // TODO: this creates temporary Vec
    Ok(ConcatenatedParser::<String, ','>::from_str(s)
        .map(|p| p.into_inner())?
        .into_iter()
        .map(|e| e.into_bytes())
        .collect())
}
