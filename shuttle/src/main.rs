#![warn(rust_2018_idioms)]

use anyhow::Result;
use structopt::StructOpt;
use tracing_subscriber::EnvFilter;

mod client;
mod connector;
mod opt;
mod server;
mod trojan;
mod utils;

use crate::opt::Opt;

use crate::{client::run_client, server::run_server};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        // Use a more compact, abbreviated log format
        // .compact()
        // // Display source code file paths
        // .with_file(true)
        // // Display source code line numbers
        // .with_line_number(true)
        // // Display the thread ID an event was recorded on
        // .with_thread_ids(true)
        // // Don't display the event's target (module path)
        // .with_target(false)
        // Build the subscriber
        .init();

    let opt = Opt::from_args();
    match opt {
        Opt::Client(opt) => run_client(opt).await?,
        Opt::Server(opt) => run_server(opt).await?,
    }
    Ok(())
}
