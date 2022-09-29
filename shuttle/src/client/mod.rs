use anyhow::Result;

use tracing::{debug, info, warn};

use std::time::Duration;

use crate::opt::CltOpt;

mod connector;
mod plain;
mod redir;

use self::connector::{AdHocConnector, Preflighter, PREFLIHGTER_CONNIDLE, PREFLIHGTER_EMA_COEFF};
use self::plain::serve as serve_plain;

/// Maximum size of the initial data from inbound TCP socket which would be sent together with
/// request header
const MAX_FIRST_PACKET_SIZE: usize = 8192;
/// Time to wait for the initial data from inbound TCP socket which would be sent together with
/// request header
const FIRST_PACKET_TIMEOUT: Duration = Duration::from_millis(20);

pub async fn run_client(opt: CltOpt) -> Result<()> {
    warn!(
        "client listens at {} with remote: {}, sni: {}, preflight: {}-{}",
        &opt.listen_addr,
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
        debug!(fpspec = ?client.fingerprint_spec);
    }

    match opt.preflight {
        (0, Some(0)) => {
            let connector = AdHocConnector::new(client, opt.remote_addr);
            serve_plain(opt.listen_addr, connector).await?;
        }
        (min, max) => {
            let preflighter = Preflighter::new_flighting(client, opt.remote_addr, min, max);
            serve_plain(opt.listen_addr, preflighter).await?;
        }
    };
    Ok(())
}
