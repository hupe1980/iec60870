//! Checked, borrowing readers for classic pcap and pcapng.
use std::io::{self, ErrorKind};

pub const FILE_LIMIT: u64 = 512 * 1024 * 1024;
const PACKET_LIMIT: usize = 256 * 1024;
pub fn invalid(s: &str) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, s)
}
fn take<'a>(input: &mut &'a [u8], n: usize) -> io::Result<&'a [u8]> {
    let (a, b) = input.split_at_checked(n).ok_or_else(|| invalid("truncated capture"))?;
    *input = b;
    Ok(a)
}
#[derive(Clone, Copy)]
struct Order(bool);
impl Order {
    fn u16(self, input: &mut &[u8]) -> io::Result<u16> {
        let b = take(input, 2)?.try_into().map_err(|_| invalid("short u16"))?;
        Ok(if self.0 { u16::from_le_bytes(b) } else { u16::from_be_bytes(b) })
    }
    fn u32(self, input: &mut &[u8]) -> io::Result<u32> {
        let b = take(input, 4)?.try_into().map_err(|_| invalid("short u32"))?;
        Ok(if self.0 { u32::from_le_bytes(b) } else { u32::from_be_bytes(b) })
    }
}
#[derive(Clone, Copy)]
pub struct Packet<'a> {
    pub time: Option<i128>,
    pub link: u32,
    pub data: &'a [u8],
}
fn packet<'a>(input: &mut &'a [u8], n: u32, original: u32, snap: u32) -> io::Result<&'a [u8]> {
    if n as usize > PACKET_LIMIT || n > original || (snap != 0 && n > snap) {
        return Err(invalid("invalid captured packet length (maximum 256 KiB)"));
    }
    take(input, n as usize)
}
pub fn read<'a>(mut input: &'a [u8], mut emit: impl FnMut(Packet<'a>) -> io::Result<()>) -> io::Result<()> {
    if input.starts_with(&[10, 13, 13, 10]) {
        return pcapng(input, emit);
    }
    let (order, scale) = match take(&mut input, 4)? {
        [0xd4, 0xc3, 0xb2, 0xa1] => (Order(true), 1_000_000),
        [0xa1, 0xb2, 0xc3, 0xd4] => (Order(false), 1_000_000),
        [0x4d, 0x3c, 0xb2, 0xa1] => (Order(true), 1_000_000_000),
        [0xa1, 0xb2, 0x3c, 0x4d] => (Order(false), 1_000_000_000),
        _ => return Err(invalid("unrecognized capture file magic")),
    };
    if (order.u16(&mut input)?, order.u16(&mut input)?) != (2, 4) {
        return Err(invalid("unsupported classic pcap version"));
    }
    take(&mut input, 8)?;
    let snap = order.u32(&mut input)?;
    let link = order.u32(&mut input)? & 0xffff;
    while !input.is_empty() {
        let sec = order.u32(&mut input)?;
        let sub = order.u32(&mut input)?;
        if sub >= scale {
            return Err(invalid("invalid capture timestamp"));
        }
        let n = order.u32(&mut input)?;
        let original = order.u32(&mut input)?;
        emit(Packet {
            time: Some(i128::from(sec) * 1_000_000_000 + i128::from(sub) * 1_000_000_000 / i128::from(scale)),
            link,
            data: packet(&mut input, n, original, snap)?,
        })?;
    }
    Ok(())
}
#[derive(Clone, Copy)]
struct Interface {
    link: u32,
    snap: u32,
    ticks_per_second: i128,
    offset: i64,
}
fn interface(order: Order, mut input: &[u8]) -> io::Result<Interface> {
    let link = u32::from(order.u16(&mut input)?);
    take(&mut input, 2)?;
    let snap = order.u32(&mut input)?;
    let mut ticks_per_second = 1_000_000;
    let mut offset = 0;
    while !input.is_empty() {
        let key = order.u16(&mut input)?;
        let n = usize::from(order.u16(&mut input)?);
        let v = take(&mut input, n)?;
        take(&mut input, (4 - n % 4) % 4)?;
        match (key, v) {
            (0, []) => break,
            (9, [resolution]) => {
                let base = if resolution & 128 == 0 { 10_i128 } else { 2_i128 };
                ticks_per_second = base.checked_pow(u32::from(resolution & 127)).unwrap_or(i128::MAX);
            }
            (14, b) if b.len() == 8 => {
                let a = b.try_into().map_err(|_| invalid("invalid timestamp offset"))?;
                offset = if order.0 { i64::from_le_bytes(a) } else { i64::from_be_bytes(a) };
            }
            (0 | 9 | 14, _) => return Err(invalid("invalid interface option length")),
            _ => (),
        }
    }
    Ok(Interface { link, snap, ticks_per_second, offset })
}
fn pcapng<'a>(mut input: &'a [u8], mut emit: impl FnMut(Packet<'a>) -> io::Result<()>) -> io::Result<()> {
    let mut order = Order(true);
    let mut interfaces = Vec::new();
    while !input.is_empty() {
        if input.starts_with(&[10, 13, 13, 10]) {
            order = match input.get(8..12) {
                Some([0x4d, 0x3c, 0x2b, 0x1a]) => Order(true),
                Some([0x1a, 0x2b, 0x3c, 0x4d]) => Order(false),
                _ => return Err(invalid("invalid pcapng byte order")),
            };
        }
        let ty = order.u32(&mut input)?;
        let size = order.u32(&mut input)?;
        if size < 12 || size % 4 != 0 {
            return Err(invalid("invalid pcapng block size"));
        }
        let mut body = take(&mut input, size as usize - 12)?;
        if order.u32(&mut input)? != size {
            return Err(invalid("mismatched pcapng block length"));
        }
        match ty {
            0x0a0d_0d0a => {
                take(&mut body, 4)?;
                if order.u16(&mut body)? != 1 {
                    return Err(invalid("unsupported pcapng version"));
                }
                take(&mut body, 10)?;
                interfaces.clear();
            }
            1 => {
                if interfaces.len() >= 65_536 {
                    return Err(invalid("too many capture interfaces"));
                }
                interfaces.push(interface(order, body)?);
            }
            3 | 6 => {
                let index = if ty == 6 { order.u32(&mut body)? } else { 0 };
                let interface = interfaces.get(index as usize).ok_or_else(|| invalid("packet references unknown interface"))?;
                let time = if ty == 6 {
                    let hi = order.u32(&mut body)?;
                    let lo = order.u32(&mut body)?;
                    let ticks = (i128::from(hi) << 32) + i128::from(lo);
                    Some((ticks * 1_000_000_000) / interface.ticks_per_second + i128::from(interface.offset) * 1_000_000_000)
                } else {
                    None
                };
                let len = order.u32(&mut body)?;
                let (n, original) = if ty == 6 { (len, order.u32(&mut body)?) } else { (if interface.snap == 0 { len } else { len.min(interface.snap) }, len) };
                let data = packet(&mut body, n, original, interface.snap)?;
                take(&mut body, (4 - n as usize % 4) % 4)?;
                if ty == 3 && !body.is_empty() {
                    return Err(invalid("invalid simple packet block length"));
                }
                emit(Packet { time, link: interface.link, data })?;
            }
            _ => (),
        }
    }
    Ok(())
}
