use anyhow::Result;

use tokio::net::{TcpListener, TcpStream};
use tokio::time::Instant;
use tracing::{debug, info, instrument, warn};

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::opt::CltOpt;
use crate::preflighter::{
    AdHocConnector, Connector, Preflighter, PREFLIHGTER_CONNIDLE, PREFLIHGTER_EMA_COEFF,
};
use crate::utils::DurationExt;

pub async fn run_client(opt: CltOpt) -> Result<()> {
    info!(
        "client is up with remote: {}, sni: {}, preflight: {}–{}",
        &opt.remote_addr,
        &opt.server_name,
        &opt.preflight.0,
        &opt.preflight.1.unwrap_or(usize::MAX),
    );
    debug!(
        connidle = PREFLIHGTER_CONNIDLE,
        aht_ema_coeff = PREFLIHGTER_EMA_COEFF
    );
    let client = opt.build_client();
    if !client.fingerprint_spec.is_empty() {
        info!("tls fingerprint loaded");
        debug!("{:?}", client.fingerprint_spec);
    }

    match opt.preflight {
        (0, Some(0)) => {
            let connector = AdHocConnector::new(client, opt.remote_addr);
            serve(opt.listen_addr, connector).await?;
        }
        (min, max) => {
            let preflighter = Preflighter::new_flighting(client, opt.remote_addr, min, max);
            serve(opt.listen_addr, preflighter).await?;
        }
    };
    Ok(())
}

async fn serve(
    listen_addr: SocketAddr,
    connector: impl Connector + 'static + Send + Sync,
) -> io::Result<()> {
    let connector = Arc::new(connector);
    let listener = TcpListener::bind(listen_addr).await?;

    while let Ok((inbound, client_addr)) = listener.accept().await {
        // TODO: handle error
        info!("accepting connection from {}", &client_addr);
        let connector = connector.clone();
        tokio::spawn(handle_client_connection(inbound, client_addr, connector));
    }
    Ok(())
}

#[instrument(level = "trace", skip(connector))]
async fn handle_client_connection(
    mut inbound: TcpStream,
    client_addr: SocketAddr,
    connector: Arc<impl Connector + 'static>,
) -> io::Result<(u64, u64)> {
    let mut snowys = connector.connect().await.map_err(|e| {
        warn!("failed to establish snowy tunnel: {}", e);
        e
    })?;
    debug!(
        peer = inbound.peer_addr().unwrap().to_string(),
        local_in = inbound.local_addr().unwrap().to_string(),
        local_out = snowys.as_inner().local_addr().unwrap().to_string(),
        remote = snowys.as_inner().peer_addr().unwrap().to_string(),
        "relay"
    );
    let now = Instant::now();
    match tokio::io::copy_bidirectional(&mut snowys, &mut inbound).await {
        Ok((a, b)) => {
            info!(
                rx = a,
                tx = b,
                "relay for {} closed after {}",
                &client_addr,
                now.elapsed().autofmt(),
            );
            Ok((a, b))
        }
        Err(e) => {
            warn!(
                "relay for {} terminated after {} with error: {}",
                &client_addr,
                now.elapsed().autofmt(),
                e,
            );
            Err(e)
        }
    }
}
