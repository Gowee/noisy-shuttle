use tokio::time::Duration;

use std::fmt::{self, Display};
use std::mem::{self, MaybeUninit};

pub trait DurationExt {
    fn autofmt(&'_ self) -> DurationAutoFormatter<'_>;
}

impl DurationExt for Duration {
    fn autofmt(&'_ self) -> DurationAutoFormatter<'_> {
        DurationAutoFormatter(self)
    }
}

pub struct DurationAutoFormatter<'a>(pub &'a Duration);

impl<'a> Display for DurationAutoFormatter<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        let t = self.0.as_nanos();
        match t {
            t if t < 1000 => {
                write!(fmt, "{:.3}ns", t)
            }
            t if t < 1_000_000 => {
                write!(fmt, "{:.3}µs", t as f64 / 1000.0)
            }
            t if t < 1_000_000_000 => {
                write!(fmt, "{:.3}ms", t as f64 / 1_000_000.0)
            }
            t if t < 1_000_000_000_000 => {
                write!(fmt, "{:.3}s", t as f64 / 1_000_000_000.0)
            }
            t if t < 60_000_000_000_000 => {
                write!(fmt, "{:.3}mins", t as f64 / 1_000_000_000_000.0)
            }
            t if t < 3_600_000_000_000_000 => {
                write!(fmt, "{:.3}hrs", t / 60_000_000_000_000)
            }
            t /* if t < 24 * 3600_000_000_000_000 */ => {
                write!(fmt, "{:.3}days", t / 3_600_000_000_000_000)
            }
        }
    }
}

pub unsafe fn vec_uninit<T>(len: usize) -> Vec<T> {
    let mut buf: Vec<MaybeUninit<u8>> = Vec::with_capacity(len);
    buf.set_len(len);
    mem::transmute(buf)
}

pub fn extract_host_addr_from_url(url: &str) -> Option<(&str, u16)> {
    let mut components = url.split("//");
    let scheme = components.next()?;
    let host = components.next().and_then(|url| url.split('/').next())?;
    let port = match &scheme[..scheme.len() - 1] {
        "ftp" => 21,
        "https" => 443,
        "http" | "" => 80,
        _ => return None,
    };
    Some(match host.find(':') {
        Some(i) => {
            let (h, p) = host.split_at(i);
            (h, p.parse().ok()?)
        }
        None => (host, port),
    })
}

pub fn url_to_relative(mut url: &str) -> Option<&str> {
    if let Some(i) = url.find("//") {
        url = &url[i + 2..];
    }
    url.find('/').map(|i| &url[i..])
}
