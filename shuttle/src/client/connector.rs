use async_trait::async_trait;
use deadqueue::resizable::Queue;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use tracing::{debug, warn};

use std::cmp::{self};
use std::collections::VecDeque;
use std::fmt::Debug;
use std::io;

use std::sync::{Arc, Mutex};

use crate::utils::DurationExt;

use snowy_tunnel::{Client, SnowyStream};

/// Time limit by which a preflighted connection is seen as idle
pub const PREFLIHGTER_CONNIDLE: usize = 120;
/// Coefficient for computing the exponential moving average of handshake time
pub const PREFLIHGTER_EMA_COEFF: f32 = 1.0 / 3.0;

/// Generic connector that establish a connection to peer server
#[async_trait]
pub trait Connector<S: AsyncWrite + AsyncRead + Unpin> {
    async fn connect(&self) -> io::Result<S>;
}

/// Connector that establish connections in advance based on some simple heuristic predications
///
/// A preflighter starts with a queue at its lower bound capacity, which is then filled with
/// pending connections still in progress.
/// It tracks handshake time of connection establishment by calculating a moving average. When a
/// connection is requested, it pops a connection from the queue and accumulate the delay before
/// the connection is actually ready.
///
/// If the accumulated delay exceeds an average handshake time, the queue size is increased by one.
/// If a connection is unused after `PREFLIHGTER_CONNIDLE`, the queue size is decreased by one.
#[derive(Debug)]
pub struct Preflighter {
    queue: Arc<Queue<(JoinHandle<io::Result<SnowyStream>>, Instant)>>,
    average_handshake_time: Arc<Mutex<f32>>,
    cumulative_handshake_delay: Mutex<f32>,
    min: usize,
    max: Option<usize>,
}

impl Preflighter {
    /// Create a preflighter and start it immediately by internally spawning a task.
    pub fn new_flighting(
        client: Client,
        remote_addr: String,
        min: usize,
        max: Option<usize>,
    ) -> Self {
        assert!(min > 0 && min <= max.unwrap_or(usize::MAX));
        let queue = Arc::new(Queue::new(min));
        let average_handshake_time = Arc::new(Mutex::new(0.0));
        tokio::spawn(Self::run(
            client,
            remote_addr,
            queue.clone(),
            average_handshake_time.clone(),
        ));
        Self {
            queue,
            average_handshake_time,
            cumulative_handshake_delay: Mutex::new(0.0),
            min,
            max,
        }
    }

    async fn run(
        client: Client,
        remote_addr: String,
        queue: Arc<Queue<(JoinHandle<io::Result<SnowyStream>>, Instant)>>,
        aht: Arc<Mutex<f32>>,
    ) -> io::Result<()> {
        let client = Arc::new(client);
        let mut window = VecDeque::new();
        let mut count = 0;
        loop {
            let now = Instant::now();
            let remote_addr = remote_addr.clone();
            let client = client.clone();
            let average_handshake_time = aht.clone();
            let conn = tokio::spawn(async move {
                let t = Instant::now();
                let s = TcpStream::connect(remote_addr.as_str()).await;
                let r = client.connect(s?).await;
                match &r {
                    Ok(_) => {
                        let mut aht = average_handshake_time.lock().unwrap();
                        *aht = t.elapsed().as_secs_f32() * PREFLIHGTER_EMA_COEFF
                            + *aht * (1.0 - PREFLIHGTER_EMA_COEFF);
                        debug!(aht = *aht, "update average handshake time"); // TODO: drop lock before logging
                    }
                    Err(e) => warn!("preflighter got error when handshaking: {}", e),
                }
                r
            });
            queue.push((conn, now)).await;
            window.push_back(Instant::now());
            count += 1;
            while window.front().is_some() && window.front().unwrap().elapsed().as_secs() > 60 {
                window.pop_front();
                count -= 1;
            }
            debug!(last_min = count, pending = queue.len(), "preflighting");
        }
    }

    /// Get a (hopefully) established connection
    pub async fn get(&self) -> io::Result<(SnowyStream, Instant)> {
        let mut errcnt = 0;
        loop {
            let (h, t1) = self.queue.pop().await;
            if t1.elapsed().as_secs() as usize > PREFLIHGTER_CONNIDLE {
                debug_assert!(self.queue.capacity() > 0);
                self.queue
                    .resize(cmp::max(self.queue.capacity() - 1, self.min))
                    .await;
                debug!(
                    preflight_pending = self.queue.len(),
                    preflight_capacity = self.queue.capacity(),
                    "one ready connection reaches CONNIDLE, decrease preflight",
                );
            }
            let t2 = Instant::now();
            match h.await.unwrap() {
                Ok(s) => {
                    let aht = *self.average_handshake_time.lock().unwrap(); // lock dropped immediately
                    let chd = {
                        let mut chd = self.cumulative_handshake_delay.lock().unwrap();
                        *chd += t2.elapsed().as_secs_f32();
                        let old_chd = *chd;
                        if *chd > aht {
                            *chd -= aht;
                        }
                        old_chd
                    };
                    debug!(
                        chd = chd,
                        chd_delta = t2.elapsed().as_secs_f32(),
                        aht = aht,
                        "accumulate handshake delay"
                    );
                    if chd > aht {
                        self.queue
                            .resize(cmp::min(
                                self.queue.capacity() + 1,
                                self.max.unwrap_or(usize::MAX),
                            ))
                            .await;
                        debug!(
                            preflight_capacity = self.queue.capacity(),
                            chd = chd,
                            "increase preflight to accommodate cumulative handshake delay",
                        );
                    }
                    return Ok((s, t1));
                }
                Err(e) => {
                    debug!("preflighter got error when handshaking: {}", e);
                    errcnt += 1;
                    if errcnt == self.queue.capacity() {
                        return Err(e);
                    }
                }
            }
        }
    }
}

#[async_trait]
impl Connector<SnowyStream> for Preflighter {
    async fn connect(&self) -> io::Result<SnowyStream> {
        let (s, t) = self.get().await?;
        debug!(
            "preflighted {:?} {} ago",
            s.as_inner(),
            t.elapsed().autofmt()
        );
        Ok(s)
    }
}

/// Ad-hoc connector
pub struct AdHocConnector {
    client: Client,
    remote_addr: String,
}

impl AdHocConnector {
    pub fn new(client: Client, remote_addr: String) -> Self {
        // assert!(min > 0 && min <= max.unwrap_or(usize::MAX));
        Self {
            client,
            remote_addr,
        }
    }
}

#[async_trait]
impl Connector<SnowyStream> for AdHocConnector {
    async fn connect(&self) -> io::Result<SnowyStream> {
        let t = Instant::now();
        let s = TcpStream::connect(self.remote_addr.as_str()).await?;
        debug!(stream=?s, "handshaked within {}", t.elapsed().autofmt());
        self.client.connect(s).await
    }
}
