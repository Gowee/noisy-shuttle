#![warn(rust_2018_idioms)]

use anyhow::Result;
use structopt::StructOpt;

use tokio::io::AsyncWriteExt;
use tokio::net::{lookup_host, TcpListener, TcpStream};
use tracing::info;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::client::Client;
use crate::common::derive_psk;
use crate::opt::{CltOpt, Opt, SvrOpt};
use crate::server::Server;

mod client;
mod common;
mod opt;
mod server;
mod utils;

#[tokio::main]
async fn main() -> Result<()> {
    // env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
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
    let server = Arc::new(Server {
        key: derive_psk(opt.key.as_bytes()),
        camouflage_addr,
    });
    let opt = Arc::new(opt);
    let listener = TcpListener::bind(opt.listen_addr).await?;
    while let Ok((inbound, client_addr)) = listener.accept().await {
        let server = server.clone();
        let opt = opt.clone();
        tokio::spawn(async move {
            let r = handle_server_connection(server, inbound, client_addr, opt).await;
            info!("relay done: {:?}", r);
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
    use crate::server::AcceptError::*;
    match server.accept(inbound).await {
        Ok(mut snowys) => {
            let mut outbound = TcpStream::connect(&opt.remote_addr).await?;
            info!("snowy relay: {} -> {}", &client_addr, &opt.remote_addr);
            tokio::io::copy_bidirectional(&mut snowys, &mut outbound)
                .await
                .map(|_| ())
        }
        Err(IoError(e)) => Err(e),
        Err(Unauthenticated { buf, mut io }) => {
            // fallback to naive relay; TODO: option for strategy
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
            // unrecognized client protocol, just relay it to camouflage for now
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
        "client is up with remote: {}, sni: {}",
        &opt.remote_addr, &opt.sni
    );
    let client = Arc::new(Client {
        key: derive_psk(opt.key.as_bytes()),
        server_name: opt.sni.as_str().try_into().unwrap(),
    });
    let opt = Arc::new(opt);

    let listener = TcpListener::bind(opt.listen_addr).await?;

    while let Ok((mut inbound, client_addr)) = listener.accept().await {
        let client = client.clone();
        let opt = opt.clone();
        info!("accpeting connection from: {}", client_addr);
        tokio::spawn(async move {
            let outbound = TcpStream::connect(&opt.remote_addr).await?;
            info!("snowy relay {} -> {}", &client_addr, &opt.remote_addr);
            let mut snowys = client.connect(outbound).await?;
            tokio::io::copy_bidirectional(&mut snowys, &mut inbound).await
        });
    }
    Ok(())
}
