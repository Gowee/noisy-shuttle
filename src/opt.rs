use structopt::{
    clap::AppSettings::{ColoredHelp, DeriveDisplayOrder},
    StructOpt,
};

use std::net::SocketAddr;
use std::str::FromStr;

#[derive(StructOpt, Debug)]
#[structopt(name = "nshuttle", about = "Shuttle for the Internet", global_settings(&[ColoredHelp, DeriveDisplayOrder]))]
pub struct Opt {
    #[structopt(name = "ROLE")]
    pub role: Role,
    // #[structopt(long)]
    // foobar: bool,
    /// Local HOST:PORT address to listen on
    #[structopt(name = "LISTEN_ADDR")]
    pub listen_addr: SocketAddr,

    /// File(s) to convert in-place (omit for stdin/out)  
    #[structopt(name = "REMOTE_ADDR")] //, parse(from_os_str))]
    pub remote_addr: String,

    /// Server name indication to send to the remote
    #[structopt(name = "SNI")]
    pub sni: String,

    /// The key to encrypt all traffic
    #[structopt(name = "KEY")]
    pub key: String,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Role {
    Server,
    Client,
}

impl Role {
    pub fn is_server(self) -> bool {
        self == Role::Server
    }

    pub fn is_client(self) -> bool {
        self == Role::Client
    }
}

impl FromStr for Role {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Role, Self::Err> {
        if s.eq_ignore_ascii_case("server") {
            Ok(Role::Server)
        } else if s.eq_ignore_ascii_case("client") {
            Ok(Role::Client)
        } else {
            Err("Neither server nor client")
        }
    }
}
