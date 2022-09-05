use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{
    tcp::{ReadHalf, WriteHalf},
    TcpListener, TcpStream,
};
use tokio::time::{sleep, Duration};

use std::io;
use std::net::SocketAddr;

use super::common::{SnowyStream, NOISE_PARAMS};
use crate::opt::Opt;
use crate::utils::u16_from_slice;

const LISTEN_ADDR: &str = "0.0.0.0:44443";
// const CAMOUFLAGE_DOMAIN: &'static str = "www.petalsearch.com";
const REMOTE_ADDR: &str = "127.0.0.1:10086";
const CAMOUFLAGE_ADDR: &str = "114.119.183.177:443";
// const KEY: &'static str = "Winnie the P00h";
const KEY: &[u8] = b"i don't care for fidget spinners";

struct Server {
    pub key: [u8; 32],
    pub camouflage_addr: SocketAddr,
}

impl Server {
    pub async fn accept(&self, mut inbound: TcpStream) -> io::Result<Accept> {
        let mut responder = snow::Builder::new(NOISE_PARAMS.clone())
            .psk(0, &self.key)
            .build_responder()
            .expect("Valid NOISE params");
        // Ref: https://tls12.xargs.org/
        //      https://github.com/Gowee/rustls-mod/blob/a94a0055e1599d82bd8e212ad2dd19410204d5b7/rustls/src/msgs/message.rs#L88
        //   record header + handshake header + server version + server random + session id len +
        //   session id
        let mut buf = [0u8; 5 + 4 + 2 + 32 + 1 + 32];
        inbound.read_exact(&mut buf).await?; // TODO: validate header
        let mut psk_e = [0u8; 48];
        psk_e[..32].copy_from_slice(&buf[buf.len() - 65..buf.len() - 33]); // client random
        psk_e[32..].copy_from_slice(&buf[buf.len() - 32..buf.len() - 16]); // session id

        // println!("S: e, psk {:x?}", &psk_e[..48]);
        if responder.read_message(&psk_e, &mut []).is_err() {
            return Ok(Accept::Unauthenticated {
                buf: buf.into(),
                io: inbound,
            });
            // tokio::spawn(async move {
            // let mut outbound = TcpStream::connect(self.camouflage_addr).await?;
            // outbound.write_all(&buf).await?;
            // tokio::io::copy_bidirectional(&mut inbound, &mut outbound)
            //     .await
            //     .map(|_| ())?;
            // })
            // .await;
            // return Err(io::Err)
            // unimplemented!();
            // return Ok(());
        }

        let mut outbound = TcpStream::connect(self.camouflage_addr).await?;

        // extract remaining part of client hello and send CH in whole to camouflage server
        let msglen = u16_from_slice(&buf[3..5]) as usize;
        let mut msgbuf = vec![0; msglen - (4 + 2 + 32 + 1 + 32)];
        inbound.read_exact(&mut msgbuf).await?;
        // TODO: write once
        outbound.write_all(&buf).await?;
        outbound.write_all(&msgbuf).await?;
        // proceed to relay TLS handshake messages
        let (rin, win) = inbound.split();
        let (rout, wout) = outbound.split();
        let (a, b) = tokio::join!(
            copy_until_handshake_finished(rin, wout),
            copy_until_handshake_finished(rout, win)
        );
        a?;
        b?;
        // handshake done, drop connection to camouflage server
        tokio::spawn(async move {
            let _ = outbound.shutdown().await;
        });
        // force flush TCP before sending e, ee in a dirty way; TODO: fix client
        // this prevents client TLS implmentation from catching too much data in buffer
        if !inbound.nodelay()? {
            inbound.set_nodelay(true)?;
            inbound.write_all(&[]).await?;
            inbound.set_nodelay(false)?;
        }

        // Noise: <- e, ee
        let mut buf = [0u8; 5 + 48]; // TODO: pad to some length
        buf[..5].copy_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x30]);
        let len = responder
            .write_message(&[], &mut buf[5..])
            .expect("Valid NOISE state");
        debug_assert_eq!(len, 48);
        // println!("S: e, ee w/ header {:x?}", &buf);
        inbound.write_all(&buf).await?;

        let responder = responder
            .into_transport_mode()
            .expect("NOISE handshake finished");
        // let len = responder.write_message(b"pong", &mut buf).unwrap(); // message being &mut [] resulted in mysterious Decrypt error
        Ok(Accept::Established(SnowyStream::new(inbound, responder)))
    }
}

pub enum Accept {
    Established(SnowyStream),
    Unauthenticated { buf: Vec<u8>, io: TcpStream },
}

pub async fn run_server(opt: Opt) -> Result<()> {
    assert!(opt.role.is_server());
    let listener = TcpListener::bind(LISTEN_ADDR).await?;

    while let Ok((inbound, client_addr)) = listener.accept().await {
        tokio::spawn(handle_connection(inbound, client_addr));
    }
    Ok(())
}

pub async fn handle_connection(inbound: TcpStream, client_addr: SocketAddr) -> Result<()> {
    dbg!(&client_addr);
    let server = Server {
        key: KEY.try_into().unwrap(),
        camouflage_addr: CAMOUFLAGE_ADDR.parse::<SocketAddr>().unwrap(),
    };
    let mut snowys = match server.accept(inbound).await? {
        Accept::Established(snowys) => snowys,
        Accept::Unauthenticated { buf, mut io } => {
            // fallback to naive relay; TODO: option for strategy
            let mut outbound = TcpStream::connect(CAMOUFLAGE_ADDR).await?;
            outbound.write_all(&buf).await?;
            tokio::io::copy_bidirectional(&mut io, &mut outbound)
                .await
                .map(|_| ())?;
            return Ok(());
        }
    };

    // dbg!("server camouflage done", REMOTE_ADDR);
    let mut outbound = dbg!(TcpStream::connect(REMOTE_ADDR).await)?;
    dbg!("server starting snowy relay to", REMOTE_ADDR);
    // let mut buf = vec![0u8; 1024];
    // let len = snowys.read(&mut buf).await?;
    // outbound.write_all(&buf[..len]).await?;
    // let len = outbound.read(&mut buf).await?;
    // snowys.write_all(&buf[..len]).await?;
    // snowys.flush().await?;
    // snowys.shutdown().await?;
    // let (mut ai, mut ao) = tokio::io::split(snowys);
    // let (mut bi, mut bo) = tokio::io::split(outbound);
    // let a = tokio::spawn(async move {
    //     let mut buf = vec![0u8; 10240];
    //     loop {
    //         let len = dbg!(ai.read(&mut buf).await).unwrap();
    //         if len == 0 {
    //             break;
    //         }
    //         dbg!(bo.write_all(&buf[..len]).await).unwrap();
    //     }
    //     // dbg!(tokio::io::copy(&mut ai, &mut bo).await);
    // });
    // let b = tokio::spawn(async move {
    //     let mut buf = vec![0u8; 10240];
    //     loop {
    //         let len = dbg!(bi.read(&mut buf).await).unwrap();
    //         if len == 0 {
    //             break;
    //         }
    //         dbg!(ao.write_all(&buf[..len]).await).unwrap();
    //     }
    //     // dbg!(tokio::io::copy(&mut bi, &mut ao).await).unwrap();
    // });
    // a.await;
    // b.await;

    println!(
        "{} done {:?}",
        client_addr,
        tokio::io::copy_bidirectional(&mut snowys, &mut outbound).await
    );

    // dbg!("server exiing!!!");
    // snowys.write_all(b"pong").await?;
    // let mut buf = [0u8; 32];
    // dbg!("beb");
    // let len = snowys.read(&mut buf).await?;
    // println!("{}", String::from_utf8_lossy(&buf[..len]));
    // dbg!("Done");

    Ok(())
}

async fn copy_until_handshake_finished<'a>(
    mut read_half: ReadHalf<'a>,
    mut write_half: WriteHalf<'a>,
) -> io::Result<()> {
    //  Adapted from: https://github.com/ihciah/shadow-tls/blob/2bbdc26cff1120ba9c8eded39ad743c4c4f687c4/src/protocol.rs#L138
    const HANDSHAKE: u8 = 0x16;
    const CHANGE_CIPHER_SPEC: u8 = 0x14;
    // header_buf is used to read handshake frame header, will be a fixed size buffer.
    let mut header_buf = [0u8; 5];
    // data_buf is used to read and write data, and can be expanded.
    let mut data_buf = vec![0u8; 2048];
    let mut has_seen_change_cipher_spec = false;

    loop {
        // read exact 5 bytes
        read_half.read_exact(&mut header_buf).await?;

        // parse length
        let data_size = u16_from_slice(&header_buf[3..5]) as usize;

        // copy header and that much data
        write_half.write_all(&mut header_buf).await?;
        if data_size > data_buf.len() {
            data_buf.resize(data_size, 0);
        }
        read_half.read_exact(&mut data_buf[0..data_size]).await?;
        write_half.write_all(&data_buf[0..data_size]).await?;

        // check header type
        // let header_ref = header_buf.insert(header_buf);
        if header_buf[0] != HANDSHAKE {
            if header_buf[0] != CHANGE_CIPHER_SPEC {
                panic!("invalid header");
            }
            if !has_seen_change_cipher_spec {
                has_seen_change_cipher_spec = true;
                continue;
            }
        }
        if has_seen_change_cipher_spec {
            break;
        }
    }
    Ok(())
}

// async fn copy_until_eof<'a>(
//     mut read_half: ReadHalf<'a>,
//     mut write_half: WriteHalf<'a>,
// ) -> Result<(), Box<dyn Error>> {
//     const HANDSHAKE: u8 = 0x16;
//     const CHANGE_CIPHER_SPEC: u8 = 0x14;
//     // header_buf is used to read handshake frame header, will be a fixed size buffer.
//     let mut header_buf = [0u8; 5];
//     // data_buf is used to read and write data, and can be expanded.
//     let mut data_buf = vec![0u8; 2048];
//     let mut has_seen_change_cipher_spec = false;

//     loop {
//         // read exact 5 bytes
//         read_half.read_exact(&mut header_buf).await?;

//         // parse length
//         let data_size = u16_from_slice(&header_buf[3..5]) as usize;

//         // copy header and that much data
//         write_half.write_all(&mut header_buf).await?;
//         if data_size > data_buf.len() {
//             data_buf.resize(data_size, 0);
//         }
//         dbg!(data_size, data_buf.len());
//         read_half.read_exact(&mut data_buf[0..data_size]).await?;
//         write_half.write_all(&data_buf[0..data_size]).await?;

//         // check header type
//         // let header_ref = header_buf.insert(header_buf);
//         if header_buf[0] != HANDSHAKE {
//             if header_buf[0] != CHANGE_CIPHER_SPEC {
//                 panic!("invalid header");
//             }
//             if !has_seen_change_cipher_spec {
//                 has_seen_change_cipher_spec = true;
//                 continue;
//             }
//         }
//         if has_seen_change_cipher_spec {
//             break;
//         }
//     }
//     Ok(())
// }
