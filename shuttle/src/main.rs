#![warn(rust_2018_idioms)]

use anyhow::Result;
use deadqueue::resizable::Queue;
use structopt::StructOpt;
use tokio::io::AsyncWriteExt;
use tokio::net::{lookup_host, TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{debug, info, warn};

use std::cmp;
use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use snowy_tunnel::{derive_psk, Client, Server, SnowyStream};

mod opt;
mod utils;

use crate::opt::{CltOpt, Opt, SvrOpt};
use crate::utils::DurationExt;

// preflighter params
const CONNIDLE: usize = 120; // in secs
const EMA_COEFF: f32 = 1.0 / 3.0;

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

pub async fn run_server(opt: SvrOpt) -> Result<()> {
    let camouflage_addr = lookup_host(&opt.camouflage_addr)
        .await?
        .next()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "could not resolve to any address",
            )
        })?;
    info!(
        "server is up with remote: {}, camouflage: {}",
        opt.remote_addr, camouflage_addr
    );
    let server = Arc::new(Server::new(opt.key.as_bytes(), camouflage_addr, 1024));
    let opt = Arc::new(opt);
    let listener = TcpListener::bind(opt.listen_addr).await?;
    while let Ok((inbound, client_addr)) = listener.accept().await {
        let server = server.clone();
        let opt = opt.clone();
        tokio::spawn(async move {
            let r = handle_server_connection(server, inbound, client_addr, opt).await;
            info!("relay done with {}: {:?}", &client_addr, r);
        });
    }
    Ok(())
}

pub async fn handle_server_connection(
    server: Arc<Server>,
    inbound: TcpStream,
    client_addr: SocketAddr,
    opt: Arc<SvrOpt>,
) -> io::Result<()> {
    info!("accepting connection from {}", &client_addr);
    use snowy_tunnel::AcceptError::*;
    match server.accept(inbound).await {
        Ok(mut snowys) => {
            let mut outbound = TcpStream::connect(&opt.remote_addr).await?;
            info!("snowy relay: {} -> {}", &client_addr, &opt.remote_addr);
            tokio::io::copy_bidirectional(&mut snowys, &mut outbound)
                .await
                .map(|_| ())
        }
        Err(IoError(e)) => Err(e),
        Err(ReplayDetected {
            buf,
            mut io,
            nounce,
            first_from,
        }) => {
            warn!(
                "replay detected from {}, nonce: {:x?}, first from: {}",
                &client_addr, &nounce, &first_from
            );
            info!(
                "camouflage relay: {} -> {} (pooh's agent)",
                &client_addr, &opt.camouflage_addr
            );
            // TODO: ban
            let mut outbound = TcpStream::connect(&opt.camouflage_addr).await?;
            outbound.write_all(&buf).await?;
            tokio::io::copy_bidirectional(&mut io, &mut outbound)
                .await
                .map(|_| ())
        }
        Err(Unauthenticated { buf, mut io }) => {
            info!(
                "camouflage relay: {} -> {} (unauthenticated)",
                &client_addr, &opt.camouflage_addr
            );
            let mut outbound = TcpStream::connect(&opt.camouflage_addr).await?;
            outbound.write_all(&buf).await?;
            tokio::io::copy_bidirectional(&mut io, &mut outbound)
                .await
                .map(|_| ())
        }
        Err(ClientHelloInvalid { buf, mut io }) => {
            info!(
                "camouflage relay: {} -> {} (client protocol unrecognized)",
                &client_addr, &opt.camouflage_addr
            );
            let mut outbound = TcpStream::connect(&opt.camouflage_addr).await?;
            outbound.write_all(&buf).await?;
            tokio::io::copy_bidirectional(&mut io, &mut outbound)
                .await
                .map(|_| ())
        }
        Err(ServerHelloInvalid { .. }) => {
            info!(
                "invalid server hello received from {} when handling {}",
                &opt.camouflage_addr, &client_addr
            );
            Ok(())
        }
    }
}

pub async fn run_client(opt: CltOpt) -> Result<()> {
    info!(
        "client is up with remote: {}, sni: {}, preflight: {}–{}",
        &opt.remote_addr,
        &opt.server_name,
        &opt.preflight.0,
        &opt.preflight.1.unwrap_or(usize::MAX)
    );
    debug!(connidle = CONNIDLE, aht_ema_coeff = EMA_COEFF);
    let client = Arc::new(Client {
        key: derive_psk(opt.key.as_bytes()),
        server_name: opt.server_name.as_str().try_into().unwrap(),
    });
    let opt = Arc::new(opt);

    let preflighter = match opt.preflight {
        (0, Some(0)) => None,
        (min, max) => {
            let client = client.clone();
            let preflighter = Arc::new(Preflighter::new_bounded(
                client,
                opt.remote_addr.clone(),
                min,
                max,
            ));
            {
                let preflighter = preflighter.clone();
                tokio::spawn(async move { preflighter.run().await });
            }
            Some(preflighter)
        }
    };

    let listener = TcpListener::bind(opt.listen_addr).await?;

    while let Ok((mut inbound, client_addr)) = listener.accept().await {
        let client = client.clone();
        let opt = opt.clone();
        let preflighter = preflighter.clone();
        // let preflighted = preflighter.get();
        // let connection =
        tokio::spawn(async move {
            let mut snowys = match preflighter {
                Some(preflighter) => {
                    let (s, t) = preflighter.get().await?;
                    info!(
                        "snowy relay starts for {} (preflighted {} ago)",
                        &client_addr,
                        t.elapsed().autofmt()
                    );
                    debug!(
                        local_in = &client_addr.to_string(),
                        local_out = s.as_inner().local_addr().unwrap().to_string(),
                        remote = &opt.remote_addr.to_string(),
                        // preflighted = t.elapsed().as_secs_f32(),
                        "relay"
                    );
                    s
                }
                None => {
                    let t = Instant::now();
                    let s = TcpStream::connect(opt.remote_addr.as_str()).await?;
                    let r = client.connect(s).await;
                    info!(
                        "snowy relay start for {} (handshaked within {})",
                        &client_addr,
                        t.elapsed().autofmt()
                    );
                    debug!(
                        local_in = &client_addr.to_string(),
                        local_out = &opt.remote_addr.to_string(),
                        remote = opt.remote_addr.as_str(),
                        handshake = t.elapsed().as_secs_f32(),
                        "relay"
                    );
                    r?
                }
            };
            let now = Instant::now();
            match tokio::io::copy_bidirectional(&mut snowys, &mut inbound).await {
                Ok((a, b)) => {
                    info!(
                        rx = a,
                        tx = b,
                        "connection from {} closed after {}",
                        &client_addr,
                        now.elapsed().autofmt(),
                    );
                }
                Err(e) => {
                    info!(
                        "connection from {} terminated after {} with error: {} ",
                        &client_addr,
                        now.elapsed().autofmt(),
                        e,
                    );
                }
            }
            Ok::<(), io::Error>(())
        });
    }
    Ok(())
}

struct Preflighter {
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
                    *aht = t.elapsed().as_secs_f32() * EMA_COEFF + *aht * (1.0 - EMA_COEFF);
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

    pub async fn get(&self) -> io::Result<(SnowyStream, Instant)> {
        let (h, t1) = self.queue.pop().await;
        if t1.elapsed().as_secs() as usize > CONNIDLE {
            debug_assert!(self.queue.capacity() > 0);
            self.queue
                .resize(cmp::max(self.queue.capacity() - 1, self.min))
                .await;
            debug!(
                preflight_enqueued = self.queue.len(),
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
                warn!(e = e.to_string());
                Err(e)
            }
        }
    }
}
