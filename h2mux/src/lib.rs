//! Multiplexing streams over HTTP/2, built upon [h2](https://docs.rs/h2/).
//!
//! Unlike streams opened via the standard HTTP CONNECT method, h2mux streams can be written to
//! with data immediately after being opened by the client, without waiting 1 extra RTT for the
//! server to respond to the request.
//!
//! It supports auto-scaling HTTP/2 window size based on BDP estimation, ported from [hyper](https://docs.rs/hyper/)
//! with some params tuned.

use thiserror::Error;

pub mod client;
pub mod server;

mod ping;
mod stream;
mod utils;

pub use crate::{client::InFlightH2Stream, stream::H2Stream};

/// hyper::proto::h2::SPEC_WINDOW_SIZE: Default initial stream window size defined in HTTP2 spec.
const SPEC_WINDOW_SIZE: u32 = 65_535;

#[derive(Error, Debug)]
pub enum Error {
    #[error("h2 layer error")]
    H2Error(#[from] h2::Error),
    #[error("pong timed out")]
    KeepAliveTimedOut,
}
