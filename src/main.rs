#![warn(rust_2018_idioms)]

use hex_literal::hex;
use rustls::internal::msgs::codec::{Codec, Reader};
use rustls::internal::msgs::handshake::HandshakePayload;
use rustls::internal::msgs::message::{Message, MessagePayload, OpaqueMessage, PlainMessage};
use tokio::io::AsyncWriteExt;
use tokio::io::{self, AsyncReadExt};
use tokio::net::{
    tcp::{ReadHalf, WriteHalf},
    TcpListener, TcpStream,
};
use tokio::time::{sleep, Duration};
use tokio_rustls::TlsConnector;

// use futures::FutureExt;
use std::env;
use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;

mod utils;

use crate::utils::{u16_from_slice, NoCertificateVerification};

const LISTEN_ADDR: &'static str = "127.0.0.1:44443";
const CAMOUFLAGE_DOMAIN: &'static str = "www.aliexpress.com";
const CAMOUFLAGE_ADDR: &'static str = "59.82.60.28:443";
const PATTERN: &'static str = "Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s";
// const KEY: &'static str = "Winnie the P00h";
const KEY: &[u8] = b"i don't care for fidget spinners";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let role = env::args().nth(1);
    if role.unwrap() != "server" {
        run_client().await?;
    } else {
        run_server().await?;
    }
    Ok(())
}

async fn run_client() -> Result<(), Box<dyn Error>> {
    println!("Client is up");
    let mut initiator = snow::Builder::new(PATTERN.parse()?)
        .psk(0, KEY)
        .build_initiator()?;
    // let mut responder = snow::Builder::new(PATTERN.parse()?)
    //     .psk(0, KEY)
    //     .build_responder()?;
    let mut buf = [0u8; 64];
    assert_eq!(dbg!(initiator.write_message(&[], &mut buf).unwrap()), 48);
    // responder.read_message(&buf[0..48], &mut [])?;
    println!("C: e, psk {:x?}", &buf[..48]);

    let sock = TcpStream::connect(LISTEN_ADDR).await?;

    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(NoCertificateVerification {}))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config.clone()));
    let client = rustls::ClientConnection::new_with_random_and_session_id(
        Arc::new(config.clone()),
        CAMOUFLAGE_DOMAIN.try_into().unwrap(),
        <[u8; 32]>::try_from(&buf[0..32]).unwrap().into(),
        (&buf[32..64]).into(),
    )?;
    let connect = connector.connect_with(CAMOUFLAGE_DOMAIN.try_into().unwrap(), sock, |conn| {
        *conn = client
    });

    let (mut sock, _tlsconn) = connect.await.unwrap().into_inner();

    sleep(Duration::from_secs(3)).await;

    let mut buf = [0u8; 48];
    let len = sock.read(&mut buf).await?;
    dbg!(len);
    println!("C: e, ee {:x?}", &buf[..len]);
    initiator.read_message(&buf[..len], &mut []).unwrap();
    let mut initiator = initiator.into_transport_mode()?;

    let mut buf = [0u8; 1024];
    let len = initiator.write_message(b"ping", &mut buf).unwrap();
    println!("C ping hex: {:x?}", &buf[..len]);
    sock.write_all(&buf[0..len]).await?;
    loop {
        let len = sock.read(&mut buf).await?;
        if len == 0 {
            break;
        }
        let len = initiator.read_message(&buf.clone()[0..len], &mut buf)?;
        println!("C pong hex: {:x?}", &buf[..len]);
        println!("{}", String::from_utf8_lossy(&buf[..len]));
    }

    // client.write_all(&hex!("1603010200010001fc0303")).await?;
    // client.write_all(&buf[0..32]).await?; // client random
    // client.write_all(&hex!("20")).await?;
    // client.write_all(&buf[32..64]).await?; // session id
    //                                        // client.write_all(&[0u8; 16]).await?; // TODO: gen random
    // client.write_all(&hex!("0020caca130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f003501000193baba00000000000e000c000009776569626f2e636f6d00170000ff01000100000a000a00087a7a001d00170018000b00020100002300000010000e000c02683208687474702f312e31000500050100000000000d0012001004030804040105030805050108060601001200000033002b00297a7a000100001d0020e3b3e61aa2e298c2743e203de7f9a8994845e7c9a4c094fc613f0cb838252177002d00020101002b0007068a8a03040303001b00030200024469000500030268321a1a000100001500ce0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")).await?;
    Ok(())
}

async fn run_server() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind(LISTEN_ADDR).await?;

    while let Ok((mut inbound, client_addr)) = listener.accept().await {
        dbg!(&client_addr);
        let mut responder = snow::Builder::new(PATTERN.parse()?)
            .psk(0, KEY)
            .build_responder()?;
        let mut buf = [0u8; 5 + 4 + 2 + 32 + 1 + 32];
        inbound.read_exact(&mut buf).await?;
        let mut e_psk = [0u8; 64];
        e_psk[..32].copy_from_slice(&buf[buf.len() - 65..buf.len() - 33]);
        e_psk[32..].copy_from_slice(&buf[buf.len() - 32..]);
        println!("S: e, psk {:x?}", &e_psk[..48]);
        let mut outbound =
            TcpStream::connect(CAMOUFLAGE_ADDR.parse::<SocketAddr>().unwrap()).await?;
        if responder.read_message(&e_psk[..48], &mut []).is_err() {
            // fallback to naive relay
            outbound.write_all(&buf).await?;
            tokio::io::copy_bidirectional(&mut inbound, &mut outbound)
                .await
                .map(|_| ())?;
            continue;
        }

        let msglen = u16_from_slice(&buf[3..5]) as usize;
        let mut msgbuf = vec![0; msglen - (4 + 2 + 32 + 1 + 32)];
        inbound.read_exact(&mut msgbuf).await?;

        // https://github.com/Gowee/rustls-mod/blob/a94a0055e1599d82bd8e212ad2dd19410204d5b7/rustls/src/msgs/message.rs#L88
        // TODO: write once
        outbound.write_all(&buf).await?;
        outbound.write_all(&msgbuf).await?;

        // loop {
        //     let mut rh = [0u8; 5];
        //     let msglen = u16_from_slice(&buf[3..5]) as usize;
        //     outbound.read_exact(&mut rh).await?;
        //     let mut buf = vec![0u8; msglen];
        //     outbound.read_exact(&mut buf).await?;
        //     inbound.write_all(&buf).await?;
        // }
        let (rin, win) = inbound.split();
        let (rout, wout) = outbound.split();

        let (a, b) = tokio::join!(
            copy_until_handshake_finished(rin, wout),
            copy_until_handshake_finished(rout, win)
        );
        a?;
        b?;

        sleep(Duration::from_secs(3)).await;

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

        // responder.write_message(b"pong", &mut buf).unwrap();
        // inbound.write_all(&buf).await?;
    }
    Ok(())
}

async fn copy_until_handshake_finished<'a>(
    mut read_half: ReadHalf<'a>,
    mut write_half: WriteHalf<'a>,
) -> Result<(), Box<dyn Error>> {
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
