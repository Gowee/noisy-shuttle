use structopt::clap::AppSettings::{ColoredHelp, DeriveDisplayOrder};
use structopt::StructOpt;
use structopt_flags::QuietVerbose;

use std::fmt::Debug;
use std::net::SocketAddr;

use snowy_tunnel::{Client, Server};

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

    /// Number or range of connections to establish in advance (shortening perceivable delay at
    /// risk of higher possibility of being distinguished)
    #[structopt(short ="p", long = "preflight", default_value = "0", parse(try_from_str = parse_preflight_bounds))]
    pub preflight: (usize, Option<usize>),

    // UNIMPLEMENTED
    // /// Activate transparent proxy mode, instructing the client to accept raw REDIRECTed TCP
    // /// traffic and TPROXY-ed UDP traffic (plain proxy is disabled in this case)
    // #[cfg(unix)]
    // #[structopt(long = "redir")]
    // pub redir: bool,
    // All TLS fingerprint-related options have been removed. We now use a fixed
    // Chrome-like ClientHello template inside the tunnel layer.
}

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
    pub fn build_client(&self) -> Client {
        Client::new(
            self.key.as_bytes(),
            self.server_name.as_str(),
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

// TLS fingerprint/JA3-related helpers removed.
