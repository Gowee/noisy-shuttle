#![warn(rust_2018_idioms)]

use anyhow::Result;
use structopt::StructOpt;
use tracing::warn;

mod client;
mod connector;
mod opt;
mod server;
mod socks5;
mod trojan;
mod utils;

use crate::opt::Opt;

use crate::{client::run_client, server::run_server};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let opt = Opt::from_args();
    match opt {
        Opt::Client(opt) => run_client(opt).await?,
        Opt::Server(opt) => run_server(opt).await?,
    }
    Ok(())
}
