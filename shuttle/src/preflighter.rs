use deadqueue::resizable::Queue;
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{debug, instrument, warn};

use std::cmp;
use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex};

use snowy_tunnel::{Client, SnowyStream};

pub const PREFLIHGTER_CONNIDLE: usize = 120;
pub const PREFLIHGTER_EMA_COEFF: f32 = 1.0 / 3.0;

#[derive(Debug)]
pub struct Preflighter {
    client: Arc<Client>,
    remote_addr: String,
    queue: Queue<(JoinHandle<io::Result<SnowyStream>>, Instant)>,
    average_handshake_time: Arc<Mutex<f32>>,
    cumulative_handshake_delay: Mutex<f32>,
    min: usize,
    max: Option<usize>,
}

impl Preflighter {
    pub fn new_bounded(
        client: Arc<Client>,
        remote_addr: String,
        min: usize,
        max: Option<usize>,
    ) -> Self {
        assert!(min > 0 && min <= max.unwrap_or(usize::MAX));
        Self {
            client,
            remote_addr,
            queue: Queue::new(min),
            average_handshake_time: Arc::new(Mutex::new(0.0)),
            cumulative_handshake_delay: Mutex::new(0.0),
            min,
            max,
        }
    }

    pub async fn run(&self) -> io::Result<()> {
        let mut window = VecDeque::new();
        let mut count = 0;
        loop {
            let now = Instant::now();
            let remote_addr = self.remote_addr.clone();
            let client = self.client.clone();
            let average_handshake_time = self.average_handshake_time.clone();
            let conn = tokio::spawn(async move {
                let t = Instant::now();
                let s = TcpStream::connect(remote_addr.as_str()).await;
                let r = client.connect(s?).await;
                if r.is_ok() {
                    let mut aht = average_handshake_time.lock().unwrap();
                    *aht = t.elapsed().as_secs_f32() * PREFLIHGTER_EMA_COEFF
                        + *aht * (1.0 - PREFLIHGTER_EMA_COEFF);
                    debug!(aht = *aht, "update average handshake time"); // TODO: drop lock before logging
                }
                r
            });
            self.queue.push((conn, now)).await;
            window.push_back(Instant::now());
            count += 1;
            while window.front().is_some() && window.front().unwrap().elapsed().as_secs() > 60 {
                window.pop_front();
                count -= 1;
            }
            debug!(last_min = count, pending = self.queue.len(), "preflighting");
        }
    }

    #[instrument(level = "trace")]
    pub async fn get(&self) -> io::Result<(SnowyStream, Instant)> {
        let (h, t1) = self.queue.pop().await;
        if t1.elapsed().as_secs() as usize > PREFLIHGTER_CONNIDLE {
            debug_assert!(self.queue.capacity() > 0);
            self.queue
                .resize(cmp::max(self.queue.capacity() - 1, self.min))
                .await;
            debug!(
                preflight_pending = self.queue.len(),
                preflight_capacity = self.queue.capacity(),
                "one idle ready connection timeout, decrease preflight",
            );
        }
        let t2 = Instant::now();
        match h.await.unwrap() {
            Ok(s) => {
                // (s, tt)
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
                        "PREFLIGHT: increase preflight to accommodate cumulative handshake delay",
                    );
                }
                Ok((s, t1))
            }
            Err(e) => {
                warn!("preflighter got error when handshaking: {}", e);
                Err(e)
            }
        }
    }
}
