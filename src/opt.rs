use structopt::{
    clap::AppSettings::{ColoredHelp, DeriveDisplayOrder},
    StructOpt,
};

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
    #[structopt(name = "SNI")]
    pub sni: String,

    /// The key to encrypt all traffic
    #[structopt(name = "KEY")]
    pub key: String,
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
    pub camouflage_addr: String,

    /// The key to encrypt all traffic
    #[structopt(name = "KEY")]
    pub key: String,
}
