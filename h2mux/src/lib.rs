// use pin_project_lite::pin_project;
use std::error::Error as StdError;
use std::future::poll_fn;
use std::future::Future;
use std::future::Pending;
use std::io::{self, Cursor, IoSlice};
use std::mem;
use std::pin::Pin;
use std::task::{self, ready, Context, Poll};

use bytes::{Buf, Bytes};
use h2::client::{ResponseFuture, SendRequest};
use h2::{Reason, RecvStream, SendStream};
use http::header::{HeaderName, CONNECTION, TE, TRAILER, TRANSFER_ENCODING, UPGRADE};
use http::response::Parts;
use http::{request, HeaderMap, Request};
use ping::{Ponged, Recorder};
use stream::SendBuf;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, trace, warn};

pub mod client;
mod ping;
pub mod server;
mod stream;
mod utils;

pub use crate::stream::H2Upgraded;
use crate::utils::H2MapIoErr;

/// hyper::proto::h2: Default initial stream window size defined in HTTP2 spec.
const SPEC_WINDOW_SIZE: u32 = 65_535;

#[derive(Error, Debug)]
pub enum Error {
    #[error("h2 layer error")]
    H2Error(#[from] h2::Error),
    #[error("pong timed out")]
    KeepAliveTimedOut,
}
