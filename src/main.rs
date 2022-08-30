#![warn(rust_2018_idioms)]

use anyhow::Result;
use structopt::StructOpt;

mod client;
mod common;
mod opt;
mod server;
mod utils;

use crate::client::run_client;
use crate::opt::Opt;
use crate::server::run_server;

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::from_args();
    if opt.role.is_client() {
        run_client(opt).await?;
    } else {
        run_server(opt).await?;
    }
    Ok(())
}
