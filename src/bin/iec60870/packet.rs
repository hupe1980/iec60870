//! Extract TCP payloads from captured link and IP headers.
use super::capture::Packet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Clone, Copy)]
pub struct Segment<'a> {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub seq: u32,
    pub flags: u8,
    pub data: &'a [u8],
}
pub enum Network<'a> {
    Tcp(Segment<'a>),
    Fragment,
    Other,
    Unsupported,
    Truncated,
}
fn word(d: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(d.get(at..at + 2)?.try_into().ok()?))
}
fn link(p: &Packet<'_>) -> Option<(usize, u16)> {
    let d = p.data;
    let (mut pos, mut proto) = match p.link {
        1 => (14, word(d, 12)?),
        113 => (16, word(d, 14)?),
        276 => (20, word(d, 0)?),
        101 | 228 | 229 | 0 | 108 => {
            let pos = usize::from(matches!(p.link, 0 | 108)) * 4;
            let kind = match p.link {
                228 => 4,
                229 => 6,
                _ => *d.get(pos)? >> 4,
            };
            (
                pos,
                match kind {
                    4 => 0x0800,
                    6 => 0x86dd,
                    _ => 0,
                },
            )
        }
        _ => return None,
    };
    while matches!(proto, 0x8100 | 0x88a8) {
        proto = word(d, pos + 2)?;
        pos += 4;
    }
    Some((pos, proto))
}
pub fn parse<'a>(p: &Packet<'a>) -> Network<'a> {
    if !matches!(p.link, 0 | 1 | 101 | 108 | 113 | 228 | 229 | 276) {
        return Network::Unsupported;
    }
    unpack(p).unwrap_or(Network::Truncated)
}
fn unpack<'a>(p: &Packet<'a>) -> Option<Network<'a>> {
    let (off, proto) = link(p)?;
    let d = p.data.get(off..)?;
    let (src, dst, tcp) = match proto {
        0x0800 => {
            let first = *d.first()?;
            let n = usize::from(first & 15) * 4;
            if first >> 4 != 4 || n < 20 {
                return None;
            }
            if word(d, 6)? & 0x3fff != 0 {
                return Some(Network::Fragment);
            }
            if *d.get(9)? != 6 {
                return Some(Network::Other);
            }
            let addr = |at| Some(IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(d.get(at..at + 4)?).ok()?)));
            (addr(12)?, addr(16)?, d.get(n..usize::from(word(d, 2)?))?)
        }
        0x86dd => {
            if *d.first()? >> 4 != 6 {
                return None;
            }
            let addr = |at| Some(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(d.get(at..at + 16)?).ok()?)));
            let mut next = *d.get(6)?;
            let mut body = d.get(40..40 + usize::from(word(d, 4)?))?;
            while next != 6 {
                let n = match next {
                    0 | 43 | 60 => (usize::from(*body.get(1)?) + 1) * 8,
                    51 => (usize::from(*body.get(1)?) + 2) * 4,
                    44 => {
                        if word(body, 2)? & 0xfff9 != 0 {
                            return Some(Network::Fragment);
                        }
                        8
                    }
                    _ => return Some(Network::Other),
                };
                next = *body.first()?;
                body = body.get(n..)?;
            }
            (addr(8)?, addr(24)?, body)
        }
        _ => return Some(Network::Other),
    };
    let n = usize::from(*tcp.get(12)? >> 4) * 4;
    if n < 20 {
        return None;
    }
    Some(Network::Tcp(Segment {
        src: SocketAddr::new(src, word(tcp, 0)?),
        dst: SocketAddr::new(dst, word(tcp, 2)?),
        seq: u32::from_be_bytes(tcp.get(4..8)?.try_into().ok()?),
        flags: *tcp.get(13)?,
        data: tcp.get(n..)?,
    }))
}
