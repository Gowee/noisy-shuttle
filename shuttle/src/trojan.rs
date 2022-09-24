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
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use socks5_protocol::Address;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::ToSocketAddrs;

use std::convert::TryFrom;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};

use snowy_tunnel::SnowyStream;

pub struct TrojanLikeRequest {
    pub cmd: Cmd,
    pub addr: Addr,
}

// pub struct TrojanLikeRequest {
//     pub cmd: Cmd,
//     pub dest_addr: Addr,
// }

// pub enum Addr {
//     SocketAddr(SocketAddr),
//     DomainAndPort(String, u16),
// }

#[derive(FromPrimitive, ToPrimitive)]
pub enum Cmd {
    Connect = 0x01,
    UdpAssociate = 0x03,
}

pub enum Addr {
    SocketAddr(SocketAddr),
    DomainAndPort(String, u16),
}

#[derive(FromPrimitive, ToPrimitive)]
pub enum ATyp {
    Ipv4Address = 0x01,
    DomainName = 0x03,
    IPv6Address = 0x04,
}

// impl From<IpAddr> for Addr {
//     fn from(a: IpAddr) -> Self {
//         Self::IpAddr(a)
//     }
// }

// impl From<SocketAdrV4> for Addr {
//     fn from(a: Ipv4Addr) -> Self {
//         Self::IpAddr(a.into())
//     }
// }

// impl From<Ipv6Addr> for Addr {
//     fn from(a: Ipv6Addr) -> Self {
//         Self::IpAddr(a.into())
//     }
// }

// impl From<String> for Addr {
//     fn from(s: String) -> Self {
//         Self::DomainName(s)
//     }
// }

pub struct TrojanLikeUdpPacketHeader {
    pub dest_addr: Addr,
    pub length: u16,
}

impl Addr {
    async fn read(stream: impl AsyncRead + Unpin) -> io::Result<Self> {
        Ok(
            match Address::read(stream).await.map_err(|e| e.to_io_err())? {
                Address::SocketAddr(sa) => Self::SocketAddr(sa),
                Address::Domain(h, p) => Self::DomainAndPort(h, p),
            },
        )
    }

    // fn connect_with<R, A: ToSocketAddrs, F: Fn<A>(A) -> R>(&self, f: F) -> R {
    //     // use Self::*;
    //     match self {
    //         Self::SocketAddr(sa) => f(sa.clone()),
    //         Self::DomainAndPort(h, p)
    //     }
    // }
}

struct TrojanLikeUdpDatagram<IO: AsyncRead + AsyncWrite + Unpin>(IO);

// impl <IO: AsyncRead + AsyncWrite +  Unpin> TrojanLikeUdpDatagram<IO> {
//     pub async fn send(&self, data: &[u8]) -> io::Result<()> {
//         let mut packaet =
//     }
// }

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
    // the complexity here is that we try to make as few read as possible while never reading
    // more than needed
    // let mut buf = [0u8; 1];
    let cmd = Cmd::from_u8(stream.read_u8().await?).expect("TODO"); //.ok_or(|e|io::Error::new(io::ErrorKind::Other, "client request unspported command"))?;

    // let (cmd, atyp) = match (Cmd::from_u8(buf[0]), ATyp::from_u8(buf[0])) {
    //     (Some(cmd), Some(atyp)) => (cmd, atyp),
    //     _ => {
    //         return Err(io::Error::new(
    //             io::ErrorKind::InvalidData,
    //             "trojan-like request unrecognized",
    //         ))
    //     }
    // };
    let addr = Addr::read(&mut stream).await?;
    // let first_byte = buf[2];
    // let (dst_addr, buf): (DstAddr, [u8; 4]) = match atyp {
    //     ATyp::Ipv4Address => {
    //         let mut buf = [0u8; 4 + 2 + 2];
    //         buf[0] = first_byte;
    //         stream.read_exact(&mut buf[1..]).await?;
    //         (
    //             Ipv4Addr::from(unsafe { <[u8; 4]>::try_from(&buf[..4]).unwrap_unchecked() }).into(),
    //             unsafe { <[u8; 4]>::try_from(&buf[4..8]).unwrap_unchecked() },
    //         )
    //     }
    //     ATyp::IPv6Address => {
    //         let mut buf = [0u8; 16 + 2 + 2];
    //         buf[0] = first_byte;
    //         stream.read_exact(&mut buf).await?;
    //         (
    //             Ipv6Addr::from(unsafe { <[u8; 16]>::try_from(&buf[..16]).unwrap_unchecked() })
    //                 .into(),
    //             unsafe { <[u8; 4]>::try_from(&buf[16..20]).unwrap_unchecked() },
    //         )
    //     }
    //     ATyp::DomainName => {
    //         let mut buf = vec![0u8; first_byte as usize + 2 + 2];
    //         stream.read_exact(&mut buf).await?;
    //         let remaining =
    //             unsafe { <[u8; 4]>::try_from(&buf[buf.len() - 4..]).unwrap_unchecked() };
    //         buf.resize(buf.len() - 4, 0);
    //         (
    //             String::from_utf8(buf)
    //                 .map_err(|_e| {
    //                     io::Error::new(
    //                         io::ErrorKind::InvalidData,
    //                         "invalid domain name in trojan-like request",
    //                     )
    //                 })?
    //                 .into(),
    //             remaining,
    //         )
    //     }
    // };
    if stream.read_u16().await? != 0x0d0a {
        // CRLF
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "malformed trojan-like request",
        ));
    }
    // let dst_port =
    //     unsafe { u16::from_be_bytes(<[u8; 2]>::try_from(&buf[2..4]).unwrap_unchecked()) };

    Ok(TrojanLikeRequest { cmd, addr })
}

macro_rules! call_with_addr {
    ($f: path, $addr: expr) => {
        match $addr {
            crate::trojan::Addr::SocketAddr(sa) => $f(sa),
            crate::trojan::Addr::DomainAndPort(h, p) => $f(h, p),
        }
    };
}
pub(crate) use call_with_addr;
