use structopt::clap::AppSettings::{ColoredHelp, DeriveDisplayOrder};
use structopt::StructOpt;

use std::net::SocketAddr;

#[derive(Debug, Clone, StructOpt)]
#[structopt(name = "noisy-shuttle", about = "Shuttle for the Internet", global_settings(&[ColoredHelp, DeriveDisplayOrder]))]
pub enum Opt {
    /// Runs client
    Client(CltOpt),
    /// Runs server
    Server(SvrOpt),
}

#[derive(Debug, Clone, StructOpt)]
pub struct CltOpt {
    /// Local HOST:PORT address to listen on
    #[structopt(name = "LISTEN_ADDR")]
    pub listen_addr: SocketAddr,

    /// Server HOST:PORT address to connect to
    #[structopt(name = "REMOTE_ADDR")]
    pub remote_addr: String,

    /// Server name indication to send to the remote
    #[structopt(name = "SERVER_NAME")]
    pub server_name: String,

    /// The key to encrypt all traffic
    #[structopt(name = "KEY")]
    pub key: String,

    /// Number or range of connections to establish in advance (shorter perceivable delay, higher possibility of being suspected)
    #[structopt(default_value = "0", parse(try_from_str = parse_preflight_bounds))]
    pub preflight: (usize, Option<usize>),
}

#[derive(Debug, Clone, StructOpt)]
pub struct SvrOpt {
    /// Local HOST:PORT address to listen on
    #[structopt(name = "LISTEN_ADDR")]
    pub listen_addr: SocketAddr,

    /// Upstream HOST:PORT address to proxy
    #[structopt(name = "REMOTE_ADDR")] //, parse(from_os_str))]
    pub remote_addr: String,

    /// Camouflage HOST:PORT address to connect to for replicating TLS handshaking
    #[structopt(name = "CAMOUFLAGE_ADDR")] //, parse(from_os_str))]
    pub camouflage_addr: String,

    /// The key to encrypt all traffic
    #[structopt(name = "KEY")]
    pub key: String,
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
