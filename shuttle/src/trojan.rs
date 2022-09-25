//! The Trojan-like protocol with leading password and CRLF omitted, for communication between
//! the client and server of noisy shuttle
//!
//! Ref: [https://trojan-gfw.github.io/trojan/protocol.html]
//!      [https://github.com/trojan-gfw/trojan/tree/master/src/proto]
//!
//! # Valid noisy-shuttle protocol
//!
//! ```text
//! +----------------+---------+----------+
//! | Trojan Request |  CRLF   | Payload  |
//! +----------------+---------+----------+
//! |    Variable    | X'0D0A' | Variable |
//! +----------------+---------+----------+
//!
//! where Trojan Request is a SOCKS5-like request:
//!
//! +-----+------+----------+----------+
//! | CMD | ATYP | DST.ADDR | DST.PORT |
//! +-----+------+----------+----------+
//! |  1  |  1   | Variable |    2     |
//! +-----+------+----------+----------+
//!
//! where:
//!
//!     o  CMD
//!         o  CONNECT X'01'
//!         o  UDP ASSOCIATE X'03'
//!     o  ATYP address type of following address
//!         o  IP V4 address: X'01'
//!         o  DOMAINNAME: X'03'
//!         o  IP V6 address: X'04'
//!     o  DST.ADDR desired destination address
//!     o  DST.PORT desired destination port in network octet order
//! ```
use async_trait::async_trait;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
pub use socks5_protocol::Address as Addr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::ToSocketAddrs;

use std::convert::TryFrom;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};

use snowy_tunnel::SnowyStream;

pub const CRLF: u16 = 0x0d0a;
pub const MAX_DATAGRAM_SIZE: usize = 65_507;

#[derive(Debug)]
pub struct TrojanLikeRequest {
    pub cmd: Cmd,
    pub dest_addr: Addr,
}

#[derive(Debug, FromPrimitive, ToPrimitive)]
pub enum Cmd {
    Connect = 0x01,
    UdpAssociate = 0x03,
}

// pub enum Addr {
//     SocketAddr(SocketAddr),
//     DomainAndPort(String, u16),
// }

#[derive(FromPrimitive, ToPrimitive)]
pub enum ATyp {
    Ipv4Address = 0x01,
    DomainName = 0x03,
    IPv6Address = 0x04,
}

pub struct TrojanLikeUdpPacketHeader {
    pub dest_addr: Addr,
    pub length: u16,
}

// impl Addr {
//     async fn read(stream: impl AsyncRead + Unpin) -> io::Result<Self> {
//         Ok(
//             match Address::read(stream).await.map_err(|e| e.to_io_err())? {
//                 Address::SocketAddr(sa) => Self::SocketAddr(sa),
//                 Address::Domain(h, p) => Self::DomainAndPort(h, p),
//             },
//         )
//     }

//     async fn write(&self, stream: impl AsyncWrite + Unpin) -> io::Result<()> {
//         // FIX: insane clone
//         let address = match self {
//             Self::SocketAddr(sa) => Address::SocketAddr(sa.clone()),
//             Self::DomainAndPort(h, p) => Address::Domain(h.clone(), *p),
//         };
//         address.write(stream).await.map_err(|e| e.to_io_err())
//     }

//     // fn connect_with<R, A: ToSocketAddrs, F: Fn<A>(A) -> R>(&self, f: F) -> R {
//     //     // use Self::*;
//     //     match self {
//     //         Self::SocketAddr(sa) => f(sa.clone()),
//     //         Self::DomainAndPort(h, p)
//     //     }
//     // }
// }

#[async_trait]
pub trait TrojanUdpDatagramSender {
    async fn send_to(&mut self, data: &[u8], addr: Addr) -> io::Result<()>;
}

#[async_trait]
pub trait TrojanUdpDatagramReceiver {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, Addr)>;
}

#[async_trait]
impl<O: AsyncWrite + Unpin + Send> TrojanUdpDatagramSender for O {
    async fn send_to(&mut self, data: &[u8], addr: Addr) -> io::Result<()> {
        addr.write(&mut self).await.map_err(|e| e.to_io_err())?;
        self.write_u16(data.len() as u16).await?;
        self.write_u16(CRLF).await?;
        self.write_all(data).await
    }
}

#[async_trait]
impl<I: AsyncRead + Unpin + Send> TrojanUdpDatagramReceiver for I {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, Addr)> {
        let addr = Addr::read(&mut self).await.map_err(|e| e.to_io_err())?;
        let len = self.read_u16().await? as usize;
        if self.read_u16().await? != CRLF {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "malformed trojan-like request",
            ));
        }
        assert!(buf.len() < len); // or just discard overfill?
        self.read_exact(&mut buf[..len]).await?;
        Ok((len, addr))
    }
}

pub struct TrojanLikeUdpDatagramRecvHalf<IO: AsyncRead + Unpin>(IO);

impl<IO: AsyncRead + AsyncWrite + Unpin> TrojanLikeUdpDatagramRecvHalf<IO> {
    pub fn new(io: IO) -> Self {
        Self(io)
    }

    pub fn into_inner(self) -> IO {
        self.0
    }

    pub async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, Addr)> {
        let mut stream = &mut self.0;
        let addr = Addr::read(&mut stream).await.map_err(|e| e.to_io_err())?;
        let len = stream.read_u16().await? as usize;
        if stream.read_u16().await? != CRLF {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "malformed trojan-like request",
            ));
        }
        assert!(buf.len() < len); // or just discard overfill?
        stream.read_exact(&mut buf[..len]).await?;
        Ok((len, addr))
    }
}

pub async fn accept_trojan_like_stream(
    mut snowys: impl AsyncRead + AsyncWrite + Unpin,
) -> io::Result<TrojanLikeRequest> {
    // let req = read_trojan_like_request(&mut snowys).await?;
    // match req.cmd {
    //     Cmd::Connect => {

    //     },
    //     Cmd::UdpAssociate => {

    //     }
    // }
    unimplemented!();
}

pub async fn read_trojan_like_request(
    mut stream: impl AsyncRead + AsyncWrite + Unpin,
) -> io::Result<TrojanLikeRequest> {
    // macro_rules! parse_port {
    //     ($double_u8_slice: expr) => {
    //         unsafe { u16::from_be_bytes(<[u8; 2]>::try_from($double_u8_slice).unwrap_unchecked()) }
    //     };
    // }
    let t = stream.read_u8().await?;
    dbg!(t);
    let cmd = Cmd::from_u8(t).expect("TODO"); //.ok_or(|e|io::Error::new(io::ErrorKind::Other, "client request unspported command"))?;

    let addr = Addr::read(&mut stream).await.map_err(|e| e.to_io_err())?;
    dbg!(&addr);
    if dbg!(stream.read_u16().await?) != CRLF {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "malformed trojan-like request",
        ));
    }
    Ok(TrojanLikeRequest {
        cmd,
        dest_addr: addr,
    })
}

macro_rules! call_with_addr {
    ($fn: path, $addr: expr) => {
        match $addr {
            crate::trojan::Addr::SocketAddr(sa) => $fn(sa).await,
            crate::trojan::Addr::Domain(h, p) => $fn((h, p)).await,
        }
    };
}
pub(crate) use call_with_addr;
