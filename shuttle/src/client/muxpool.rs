use async_trait::async_trait;

use futures_util::TryFutureExt;
use priority_queue::PriorityQueue;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::Instant;
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::{debug, trace, warn};

use std::collections::HashMap;
use std::fmt::Debug;
use std::io;

use std::ops::DerefMut;
use std::pin::Pin;

use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};

use super::connector::Connector;
use crate::utils::DurationExt;

use snowy_tunnel::{Client, SnowyStream};
/// Wrapper around `yamux::Stream` with a extra field to tracking the number of stream for a
/// TCP connection
pub struct MuxStream {
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
        trace!(connid = %self.connid, streamid = %self.inner.id(), "dropping multiplexing stream");
        let mut pool = self
            .connpool
            .lock()
            .expect("acquire connection pool when dropping multiplexed stream");
        pool.0.change_priority_by(&self.connid, |prio| {
            *prio = (*prio).checked_add(1).expect("synchronized");
        });
    }
}

// it has nothing to do with Poll, we just reuse its enum variant semantics
// pub type LazyValue<T> = Arc<tokio::sync::Mutex<Poll<T>>>;

// fn create_lazy_value<T>() -> LazyValue<T> {
//     Arc::new(tokio::sync::Mutex::new(None))
// }

pub type ConnId = usize;

pub type ConnPool = (
    PriorityQueue<ConnId, usize>,
    HashMap<ConnId, Arc<tokio::sync::Mutex<Option<io::Result<yamux::Control>>>>>,
    ConnId,
);

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

        // SnowyStream is framing
        config.set_split_send_size(usize::MAX);
        // .set_max_buffer_size(64 * 1024);

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
        let t0 = Instant::now();
        // TODO: some lifetime/borrow check limits prevent dropping lock non-lexically
        let (id, maybe_control, to_connect) = {
            // Attempt to pick a vacant connection in pool.
            let mut pool = self.acquire_pool();
            match pool
                .0
                .peek()
                .map(|(id, &prio)| (id, usize::MAX - prio))
                .filter(|(_id, count)| dbg!(*count) < self.max_stream_per_conn)
                .map(|(id, count)| (*id, count))
            {
                Some((id, mut count)) => {
                    debug!(%id, stream_count=%count, "get a ready connection from mux pool");
                    count += 1;
                    pool.0.change_priority(&id, usize::MAX - count);
                    let maybe_control = pool.1.get(&id).expect("sychronized").clone();
                    // mem::drop(pool); // no way for now
                    (id, Some(maybe_control), None)
                }
                None => {
                    debug!("try to establish a new connection since no ready ones in pool");
                    // Create a new YamuxConnection is async, so pool lock must be dropped earlier.
                    // LazyValue<Control> is used a lazy value container so
                    // that we could occupy the pool without waiting for a YamuxConnection creation.
                    let maybe_control = Arc::new(tokio::sync::Mutex::new(None));
                    let to_connect = maybe_control
                        .clone()
                        .try_lock_owned()
                        .expect("Control lock vacant");
                    let id = pool.2;
                    pool.0.push(id, usize::MAX - 1);
                    pool.1.insert(id, maybe_control);
                    pool.2 += 1;
                    // mem::drop(pool); // no way for now
                    (id, None, Some(to_connect))
                }
            }
        };
        let mut control = match to_connect {
            Some(mut to_connect) => {
                // Pool lock has been released previously.
                // Now try to create a YamuxConnection and fill in the occupied slot in pool.
                let t = Instant::now();
                let s = match TcpStream::connect(self.remote_addr.as_str())
                    .and_then(|s| self.client.connect(s))
                    .await
                {
                    Ok(s) => s,
                    Err(e) => {
                        *to_connect = Some(Err(io::Error::from(e.kind())));
                        drop_conn_from_pool(id, &self.connpool);
                        return Err(e);
                    }
                };
                debug!(%id, "handshaked within {}", t.elapsed().autofmt());
                let conn =
                    yamux::Connection::new(s.compat(), self.config.clone(), yamux::Mode::Client);
                let control = conn.control();
                // let id;
                // {
                //     let mut pool = self.acquire_pool();
                //     id = pool.2;
                //     pool.2 += 1;
                //     pool.0.push(id, usize::MAX - 1);
                //     pool.1.insert(id, create);
                // }
                let connpool = self.connpool.clone();
                tokio::spawn(drive_yamux_connection(id, conn, connpool));

                *to_connect = Some(Ok(control.clone()));
                control
            }
            None => maybe_control
                .unwrap()
                .lock()
                .await
                .as_ref()
                .map(|r| match r {
                    Ok(c) => Ok(c.clone()),
                    Err(e) => Err(io::Error::new(
                        e.kind(),
                        "failed to establish underlying connection",
                    )),
                })
                .expect("Control ready")?,
        };

        let s = control
            .open_stream()
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        debug!("stream ready in {}", t0.elapsed().autofmt());
        // FIX:
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
            connid: id,
            connpool: self.connpool.clone(),
        })
    }
}

#[inline(always)]
async fn drive_yamux_connection(
    id: ConnId,
    mut conn: yamux::Connection<Compat<SnowyStream>>,
    connpool: Arc<Mutex<ConnPool>>,
) {
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
    drop_conn_from_pool(id, &connpool);
}

fn drop_conn_from_pool(id: ConnId, connpool: &Mutex<ConnPool>) {
    let mut pool = connpool
        .lock()
        .expect("acquire connection pool when dropping connection");
    let (_, prio) = pool
        .0
        .remove(&id)
        .expect("connection still present in pool queue");
    pool.1
        .remove(&id)
        .expect("connection still present in pool storage");
    trace!(connid=%id, stream_count=usize::MAX - prio,  "dropped connection from pool");
}
