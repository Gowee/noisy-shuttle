#![warn(rust_2018_idioms)]

use std::str::FromStr;

use anyhow::Result;
use structopt::StructOpt;
use structopt_flags::LogLevel;

use tracing::level_filters::LevelFilter;
use tracing_subscriber::EnvFilter;

mod client;
mod opt;
mod server;
mod trojan;
mod utils;

use crate::opt::{Opt, Role};

use crate::{client::run_client, server::run_server};

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::from_args();
    let loglevel = LevelFilter::from_str(&opt.verbose.get_level_filter().to_string()).unwrap();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(loglevel.into())
                .from_env_lossy(),
        )
        // Use a more compact, abbreviated log format
        // .compact()
        // // Display source code file paths
        // .with_file(true)
        // // Display source code line numbers
        // .with_line_number(true)
        // // Display the thread ID an event was recorded on
        // .with_thread_ids(true)
        // // Don't display the event's target (module path)
        .with_target(matches!(loglevel, LevelFilter::TRACE | LevelFilter::DEBUG))
        // Build the subscriber
        .init();

    match opt.role {
        Role::Client(opt) => run_client(opt).await,
        Role::Server(opt) => run_server(opt).await,
    }
}
