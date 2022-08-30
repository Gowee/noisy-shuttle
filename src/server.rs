use anyhow::Result;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
// use tokio::net::unix::SocketAddr;
use tokio::net::{
    tcp::{ReadHalf, WriteHalf},
    TcpListener, TcpStream,
};
use tokio::time::{sleep, Duration};

// use futures::FutureExt;
use std::net::SocketAddr;

use super::common::NOISE_PARAMS;
use crate::opt::Opt;
use crate::utils::u16_from_slice;

const LISTEN_ADDR: &'static str = "127.0.0.1:44443";
const CAMOUFLAGE_DOMAIN: &'static str = "www.aliexpress.com";
const CAMOUFLAGE_ADDR: &'static str = "59.82.60.28:443";
// const KEY: &'static str = "Winnie the P00h";
const KEY: &[u8] = b"i don't care for fidget spinners";

pub async fn run_server(opt: Opt) -> Result<()> {
    assert!(opt.role.is_server());
    let listener = TcpListener::bind(LISTEN_ADDR).await?;

    while let Ok((mut inbound, client_addr)) = listener.accept().await {
        tokio::spawn(handle_connection(inbound, client_addr));
    }
    Ok(())
}

pub async fn handle_connection(mut inbound: TcpStream, client_addr: SocketAddr) -> Result<()> {
    let mut responder = snow::Builder::new(NOISE_PARAMS.clone())
        .psk(0, KEY)
        .build_responder()?;
    // Ref: https://tls12.xargs.org/
    let mut buf = [0u8; 5 + 4 + 2 + 32 + 1 + 32];
    inbound.read_exact(&mut buf).await?;
    let mut e_psk = [0u8; 64];
    e_psk[..32].copy_from_slice(&buf[buf.len() - 65..buf.len() - 33]);
    e_psk[32..].copy_from_slice(&buf[buf.len() - 32..]);

    let mut outbound = TcpStream::connect(CAMOUFLAGE_ADDR.parse::<SocketAddr>().unwrap()).await?;
    if responder.read_message(&e_psk[..48], &mut []).is_err() {
        // if noise auth failed, fallback to simple relay
        outbound.write_all(&buf).await?;
        tokio::io::copy_bidirectional(&mut inbound, &mut outbound)
            .await
            .map(|_| ())?;
        return Ok(());
    }

    let msglen = u16_from_slice(&buf[3..5]) as usize;
    let mut msgbuf = vec![0; msglen - (4 + 2 + 32 + 1 + 32)];
    inbound.read_exact(&mut msgbuf).await?;

    // https://github.com/Gowee/rustls-mod/blob/a94a0055e1599d82bd8e212ad2dd19410204d5b7/rustls/src/msgs/message.rs#L88
    // TODO: write once
    outbound.write_all(&buf).await?;
    outbound.write_all(&msgbuf).await?;

    let (rin, win) = inbound.split();
    let (rout, wout) = outbound.split();

    let (a, b) = tokio::join!(
        copy_until_handshake_finished(rin, wout),
        copy_until_handshake_finished(rout, win)
    );
    a?;
    b?;

    tokio::spawn(async move {
        let _ = outbound.shutdown().await;
    });

    let mut buf = [0u8; 1024];
    let len = responder.write_message(&[], &mut buf)?;
    dbg!(len);
    println!("S: e, ee {:x?}", &buf[..len]);
    inbound.write_all(&buf[0..len]).await?;

    let mut responder = responder.into_transport_mode()?;

    let len = responder.write_message(b"pong", &mut buf).unwrap(); // message being &mut [] resulted in mysterious Decrypt error
    println!("S pong hex: {:x?}", &buf[..len]);
    inbound.write_all(&buf[0..len]).await?;

    let len = inbound.read(&mut buf).await?;
    println!("S ping hex: {:x?}", &buf[..len]);
    let len = responder
        .read_message(&buf.clone()[..len], &mut buf)
        .unwrap();
    println!("{}", String::from_utf8_lossy(&buf[..len]));

    // loop {
    //     let len = sock.read(&mut buf).await?;
    //     if len == 0 {
    //         break;
    //     }
    //     dbg!(&buf[..len], String::from_utf8_lossy(&buf[..len]));
    // }
    Ok(())

    // responder.write_message(b"pong", &mut buf).unwrap();
    // inbound.write_all(&buf).await?;
}

async fn copy_until_handshake_finished<'a>(
    mut read_half: ReadHalf<'a>,
    mut write_half: WriteHalf<'a>,
) -> Result<()> {
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
        dbg!(data_size, data_buf.len());
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
