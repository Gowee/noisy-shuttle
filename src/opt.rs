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

    /// Number of connections to establish in advance (shorter perceivable delay, higher possibility of being suspected)
    #[structopt(default_value = "0")]
    pub preflight: usize,
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
