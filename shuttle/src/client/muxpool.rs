use async_trait::async_trait;
use deadqueue::resizable::Queue;
use derive_more::{Deref, DerefMut};
use priority_queue::PriorityQueue;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::{debug, trace, warn};

use std::cmp::{self, PartialEq};
use std::collections::{HashMap, VecDeque};
use std::fmt::Debug;
use std::hash::{Hash, Hasher};
use std::io;
use std::net::SocketAddr;
use std::ops::DerefMut;
use std::pin::Pin;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};

use super::connector::Connector;
use crate::utils::DurationExt;

use snowy_tunnel::{Client, SnowyStream};

/// Wrapper around `yamux::Connection` with `Hash` and `Eq` implemented
struct MuxConnection {
    id: SocketAddr,
    inner: yamux::Connection<SnowyStream>,
}

impl Hash for MuxConnection {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state)
    }
}

impl PartialEq for MuxConnection {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for MuxConnection {}

/// Wrapper around `yamux::Stream` with a extra field to tracking the number of stream for a
/// TCP connection
// #[derive(Deref, DerefMut)]
pub struct MuxStream {
    // #[deref]
    // #[deref_mut]
    inner: yamux::Stream,
    connid: ConnId,
    connpool: Arc<Mutex<ConnPool>>,
}

impl AsyncRead for MuxStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut self.deref_mut().inner;
        Pin::new(&mut this.compat()).poll_read(cx, buf)
    }
}

impl AsyncWrite for MuxStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut self.deref_mut().inner;
        Pin::new(&mut this.compat()).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut self.deref_mut().inner;
        Pin::new(&mut this.compat()).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut self.deref_mut().inner;
        Pin::new(&mut this.compat()).poll_shutdown(cx)
    }
}

impl Drop for MuxStream {
    fn drop(&mut self) {
        trace!(connid = %self.connid, "dropping multiplexing stream");
        let mut pool = self
            .connpool
            .lock()
            .expect("acquire connection pool when dropping multiplexed stream");
        pool.0.change_priority_by(&self.connid, |prio| {
            *prio = (*prio).checked_add(1).expect("synchronized");
        });
        // pool.0.change_priority_by(&self.connid, |prio| {
        //     *prio = prio.checked_add(1).unwrap()
        // });
        // if Some(prio) = pool
        //     .0
        //     .get_priority(&self.connid)
        // {
        //     debug_assert!(pool.1.get(&self.connid).is_some());
        // }

        // pool.0.change_priority(&self.connid, prio.checked_add(1).unwrap());
    }
}

pub type ConnId = SocketAddr;

pub type ConnPool = (
    PriorityQueue<SocketAddr, usize>,
    HashMap<SocketAddr, yamux::Control>,
);

// enum PoolSlot {
//     Ready(yamux::Control),

// }

// Connection pool for multiplexing
// pub struct MuxPool {
//     connmap: HashMap<ConnId, MuxConnection>,
//     prioq: PriorityQueue<ConnId, usize>,
//     max_stream_per_connection: usize,
// }

// impl MuxPool {
//     async fn get
// }

/// Connector that multiplexs over TCP connections
#[derive(Debug)]
pub struct YamuxConnector {
    client: Client,
    remote_addr: String,
    config: yamux::Config,
    connpool: Arc<Mutex<ConnPool>>,
    max_stream_per_conn: usize,
}

impl YamuxConnector {
    pub fn new(client: Client, remote_addr: String, max_stream_per_conn: usize) -> Self {
        let mut config = yamux::Config::default();

        config
            .set_split_send_size(usize::MAX)
            .set_max_buffer_size(64 * 1024);

        YamuxConnector {
            client,
            remote_addr,
            config,
            connpool: Default::default(),
            max_stream_per_conn,
        }
    }

    fn acquire_pool(&self) -> MutexGuard<'_, ConnPool> {
        self.connpool.lock().expect("acquire connection pool")
    }
}

#[async_trait]
impl Connector<MuxStream> for YamuxConnector {
    async fn connect(&self) -> io::Result<MuxStream> {
        warn!("ggg");
        let mut connref = None;
        {
            let mut pool = self.acquire_pool();
            let e = pool
                .0
                .peek()
                .map(|(id, &prio)| (id, usize::MAX - prio))
                .filter(|(_id, count)| dbg!(*count) < self.max_stream_per_conn)
                .map(|(id, count)| (id.clone(), count));
            if let Some((id, mut count)) = e {
                debug!(%id, stream_count=%count, "get a ready connection from mux pool");
                // pool.1.change_priority(&id, )
                count += 1;
                pool.0.change_priority(&id, usize::MAX - count);
                // let conn = pool.1.get_mut(&id).expect("synchronized");
                connref = Some((id, pool.1.get(&id).expect("sychronized").clone()));
            }
        }
        if connref.is_none() {
            trace!("no ready connection in pool, trying to establish");
            let t = Instant::now();
            let s = TcpStream::connect(self.remote_addr.as_str()).await?;
            let id = s.local_addr()?;
            debug!(%id, "handshaked within {}", t.elapsed().autofmt());
            let s = self.client.connect(s).await?;
            let mut conn =
                yamux::Connection::new(s.compat(), self.config.clone(), yamux::Mode::Client);
            let control = conn.control();
            {
                let mut pool = self.acquire_pool();
                pool.0.push(id, usize::MAX - 1);
                pool.1.insert(id, control.clone());
            }
            let connpool = self.connpool.clone();
            let connid = id.clone();
            tokio::spawn(async move {
                loop {
                    match conn.next_stream().await {
                        Ok(Some(stream)) => {
                            warn!("dropping expected inbound multiplexing stream {:?}", stream)
                        }
                        Ok(None) => {
                            debug!("multiplexing connection closed {:?}", conn);
                            break;
                        }
                        Err(error) => {
                            debug!(%error, "multiplexing connection {:?} terminated", conn);
                            break;
                        }
                    }
                }
                let mut pool = connpool
                    .lock()
                    .expect("acquire connection pool when dropping connection");
                let (_, prio) = pool
                    .0
                    .remove(&connid)
                    .expect("connection still present in pool queue");
                pool.1
                    .remove(&connid)
                    .expect("connection still present in pool storage");
                trace!(%connid, stream_count=usize::MAX - prio,  "dropped connection from pool");
            });
            connref = Some((id, control));
        }
        let (connid, mut control) = connref.unwrap();
        let s = control
            .open_stream()
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        // debug!(pool=?self.connpool.lock().unwrap());
        debug!(pool_size0=%self.connpool.lock().unwrap().0.len());
        debug!(pool_size1=%self.connpool.lock().unwrap().1.len());
        {
            let pool = self.connpool.lock().unwrap();

            for (item, prio) in pool.0.iter() {
                debug!(?item, count=?usize::MAX - prio);
            }
        }
        Ok(MuxStream {
            inner: s,
            connid: connid,
            connpool: self.connpool.clone(),
        })
    }
}
