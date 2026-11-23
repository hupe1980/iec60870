//! Offline IEC 104 timeline and directional TCP reassembly.
use super::{
    ProfileArgs,
    capture::{self, Packet},
    decode,
    packet::{self, Network, Segment},
    render::Record,
};
use clap::Args;
use iec60870::{
    Asdu, Profile,
    cs101::AddressWidth,
    cs104::{Apci, Apdu, UFunction},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{self, Read, Write},
    net::SocketAddr,
    path::PathBuf,
};

#[derive(Args)]
pub struct Options {
    /// Local classic pcap or pcapng, or - for a finite binary capture on stdin.
    file: PathBuf,
    /// TCP server port (repeatable; default 2404).
    #[arg(long = "port", default_value = "2404")]
    ports: Vec<u16>,
    /// Interpret valid CP56 station clock readings as UTC in JSON.
    #[arg(long)]
    utc: bool,
    /// Print connection and capture totals only.
    #[arg(long)]
    summary: bool,
    #[command(flatten)]
    profile: ProfileArgs,
}
#[derive(Default)]
struct Stream<'a> {
    next: Option<u32>,
    initial_syn: Option<u32>,
    pending: Vec<(u32, &'a [u8])>,
    partial: Vec<u8>,
    expected_ns: Option<u16>,
    gaps: u64,
    skipped: u64,
}
impl Stream<'_> {
    fn bytes(&mut self, data: &[u8], ending: bool, mut frame: impl FnMut(Apdu<'_>, &[u8]) -> io::Result<()>) -> io::Result<()> {
        self.partial.extend_from_slice(data);
        let mut rest = self.partial.as_slice();
        while let Some((&first, tail)) = rest.split_first() {
            if first == 0x68 {
                let Some(&len) = tail.first() else { break };
                if (4..=253).contains(&len) {
                    let n = usize::from(len) + 2;
                    let Some((raw, after)) = rest.split_at_checked(n) else {
                        if ending {
                            self.skipped += 1;
                            rest = tail;
                            continue;
                        }
                        break;
                    };
                    if let Ok(apdu) = Apdu::decode(raw) {
                        frame(apdu, raw)?;
                        rest = after;
                        continue;
                    }
                }
            }
            self.skipped += 1;
            rest = tail;
        }
        let used = self.partial.len() - rest.len();
        self.partial.drain(..used);
        Ok(())
    }
    fn drain(&mut self, force: bool, mut emit: impl FnMut(&mut Self, &[u8]) -> io::Result<()>) -> io::Result<()> {
        while let Some(next) = self.next {
            let Some((i, delta)) = self.pending.iter().enumerate().map(|(i, (seq, _))| (i, seq.wrapping_sub(next) as i32)).min_by_key(|(_, d)| *d) else {
                break;
            };
            if delta > 0 && !force && self.pending.len() <= 64 {
                break;
            }
            let (seq, data) = self.pending.swap_remove(i);
            if delta > 0 {
                emit(self, &[])?;
                self.gaps += 1;
                self.skipped += self.partial.len() as u64;
                self.partial.clear();
                self.expected_ns = None;
            }
            let overlap = if delta < 0 { delta.unsigned_abs() as usize } else { 0 };
            if let Some(fresh) = data.get(overlap..)
                && !fresh.is_empty()
            {
                self.next = Some(seq.wrapping_add(data.len() as u32));
                emit(self, fresh)?;
            }
        }
        Ok(())
    }
}
struct Connection<'a> {
    id: usize,
    client: SocketAddr,
    server: SocketAddr,
    streams: [Stream<'a>; 2],
    start: Option<f64>,
    end: Option<f64>,
    active: bool,
    closed: bool,
    i: u64,
    s: u64,
    u: u64,
    ns_gaps: u64,
    errors: u64,
    types: BTreeMap<String, u64>,
}
struct Output<'a, W> {
    writer: &'a mut W,
    json: bool,
    color: bool,
    summary: bool,
    utc: bool,
    profile: Profile,
}
impl<W: Write> Output<'_, W> {
    fn report(&mut self, data: &Value, text: &str) -> io::Result<()> {
        if self.json {
            writeln!(self.writer, "{data}")
        } else if self.color {
            writeln!(self.writer, "\x1b[36m{text}\x1b[0m")
        } else {
            writeln!(self.writer, "{text}")
        }
    }
    fn frame(&mut self, c: &mut Connection, dir: usize, time: Option<f64>, ns: &mut Option<u16>, apdu: Apdu<'_>, bytes: &[u8]) -> io::Result<()> {
        let mut rec = Record::new(false);
        decode::control(&mut rec, &apdu, bytes.len());
        let mut warnings = Vec::new();
        match apdu.apci {
            Apci::I { send, .. } => {
                c.i += 1;
                if !c.active {
                    warnings.push("STARTDT confirmation not observed".to_owned());
                }
                if let Some(expected) = *ns
                    && send.get() != expected
                {
                    c.ns_gaps += 1;
                    warnings.push(format!("N(S) {send}, expected {expected}"));
                }
                *ns = Some(send.next().get());
                match Asdu::decode(apdu.asdu, &self.profile) {
                    Ok(a) => {
                        *c.types.entry(a.type_id().name().map_or_else(|| a.type_id().to_string(), str::to_owned)).or_default() += 1;
                        if !self.summary {
                            rec.asdu(&a, &self.profile, apdu.asdu, self.utc);
                        }
                    }
                    Err(e) => {
                        c.errors += 1;
                        rec.meta.insert("error".into(), json!(e.to_string()));
                        warnings.push(e.to_string());
                    }
                }
            }
            Apci::S { .. } => c.s += 1,
            Apci::U(f) => {
                c.u += 1;
                match f {
                    UFunction::StartDtCon => c.active = true,
                    UFunction::StopDtCon => c.active = false,
                    _ => (),
                }
            }
        }
        if self.summary {
            return Ok(());
        }
        let (src, dst, arrow, direction) = if dir == 0 { (c.client, c.server, "→", "to_server") } else { (c.server, c.client, "←", "to_client") };
        let mut v = json!({"kind":"apdu","t":time,"conn":c.id,"dir":direction,"src":src,"dst":dst});
        let mut line = format!("{} #{} {arrow}  {}", stamp(time), c.id, rec.line);
        if !warnings.is_empty() {
            let warning = warnings.join(", ");
            line.push_str("  ⚠ ");
            line.push_str(&warning);
            rec.meta.insert("warning".into(), json!(warning));
        }
        if let Some(fields) = v.as_object_mut() {
            fields.extend(rec.meta);
            if self.json {
                fields.insert("octets".into(), json!(super::render::hex(bytes)));
            }
        }
        self.report(&v, &line)
    }
    fn drain(&mut self, c: &mut Connection, dir: usize, time: Option<f64>, force: bool) -> io::Result<()> {
        let mut stream = std::mem::take(c.streams.get_mut(dir).ok_or_else(|| capture::invalid("invalid direction"))?);
        let mut emit = |st: &mut Stream, bytes: &[u8]| {
            let mut ns = st.expected_ns;
            if bytes.is_empty() {
                st.bytes(&[], true, |frame, raw| self.frame(c, dir, time, &mut ns, frame, raw))?;
            }
            for chunk in bytes.chunks(1024) {
                st.bytes(chunk, false, |frame, raw| self.frame(c, dir, time, &mut ns, frame, raw))?;
            }
            st.expected_ns = ns;
            Ok(())
        };
        stream.drain(force, &mut emit)?;
        if force {
            emit(&mut stream, &[])?;
        }
        *c.streams.get_mut(dir).ok_or_else(|| capture::invalid("invalid direction"))? = stream;
        Ok(())
    }
    fn finish(&mut self, c: &mut Connection) -> io::Result<()> {
        let skipped: u64 = c.streams.iter().map(|s| s.skipped + s.partial.len() as u64).sum();
        let gaps: u64 = c.streams.iter().map(|s| s.gaps).sum();
        let data = json!({"kind":"connection","conn":c.id,"client":c.client,"server":c.server,"start":c.start,"end":c.end,"i":c.i,"s":c.s,"u":c.u,"types":c.types,"ns_gaps":c.ns_gaps,"tcp_gaps":gaps,"skipped_octets":skipped,"decode_errors":c.errors});
        let types = c.types.iter().map(|(name, count)| format!("{name} ×{count}")).collect::<Vec<_>>().join(", ");
        self.report(
            &data,
            &format!(
                "#{} {} → {}  {}–{} s\n   I {}  S {}  U {}  {types}\n   {} N(S) gaps, {gaps} TCP gaps, {skipped} skipped octets, {} decode errors",
                c.id,
                c.client,
                c.server,
                stamp(c.start),
                stamp(c.end),
                c.i,
                c.s,
                c.u,
                c.ns_gaps,
                c.errors
            ),
        )
    }
}
fn stamp(t: Option<f64>) -> String {
    t.map_or_else(|| "unknown".into(), |t| format!("{t:.6}"))
}
#[derive(Default)]
struct Capture<'a> {
    sessions: Vec<Connection<'a>>,
    latest: BTreeMap<(SocketAddr, SocketAddr), usize>,
    origin: Option<i128>,
    last_time: Option<f64>,
    packets: u64,
    non_tcp: u64,
    fragments: u64,
    truncated: u64,
    unsupported: u64,
    dropped: u64,
}
impl<'a> Capture<'a> {
    fn accept<W: Write>(&mut self, p: Packet<'a>, ports: &[u16], out: &mut Output<W>) -> io::Result<()> {
        self.packets += 1;
        // Subtract integer timestamps first to preserve sub-microsecond intervals.
        #[allow(clippy::cast_precision_loss)]
        let time = p.time.map(|ns| (ns - *self.origin.get_or_insert(ns)) as f64 / 1e9);
        self.last_time = time;
        match packet::parse(&p) {
            Network::Tcp(s) => self.tcp(s, time, ports, out),
            kind => {
                match kind {
                    Network::Fragment => self.fragments += 1,
                    Network::Unsupported => self.unsupported += 1,
                    Network::Truncated => self.truncated += 1,
                    _ => self.non_tcp += 1,
                }
                Ok(())
            }
        }
    }
    fn tcp<W: Write>(&mut self, s: Segment<'a>, time: Option<f64>, ports: &[u16], out: &mut Output<W>) -> io::Result<()> {
        let (key, dir) =
            if ports.contains(&s.dst.port()) && !(ports.contains(&s.src.port()) && (self.latest.contains_key(&(s.dst, s.src)) || s.flags & 0x12 == 0x12)) {
                ((s.src, s.dst), 0)
            } else if ports.contains(&s.src.port()) {
                ((s.dst, s.src), 1)
            } else {
                return Ok(());
            };
        let syn = s.flags & 2 != 0;
        let existing = self.latest.get(&key).copied().filter(|&i| {
            let Some(c) = self.sessions.get(i) else { return false };
            !(syn && s.flags & 16 == 0 && (c.closed || c.streams.first().and_then(|st| st.initial_syn) != Some(s.seq)))
        });
        let i = if let Some(i) = existing {
            i
        } else {
            if self.sessions.len() >= 1024 {
                // A refused replacement session must not feed its predecessor.
                self.latest.remove(&key);
                self.dropped += 1;
                return Ok(());
            }
            let i = self.sessions.len();
            self.latest.insert(key, i);
            self.sessions.push(Connection {
                id: i + 1,
                client: key.0,
                server: key.1,
                streams: Default::default(),
                start: time,
                end: time,
                active: false,
                closed: false,
                i: 0,
                s: 0,
                u: 0,
                ns_gaps: 0,
                errors: 0,
                types: BTreeMap::new(),
            });
            i
        };
        let c = self.sessions.get_mut(i).ok_or_else(|| capture::invalid("missing connection"))?;
        if time.is_some() {
            c.start = c.start.or(time);
            c.end = time;
        }
        let stream = c.streams.get_mut(dir).ok_or_else(|| capture::invalid("invalid direction"))?;
        let seq = s.seq.wrapping_add(u32::from(syn));
        if syn {
            stream.initial_syn = Some(s.seq);
            stream.next.get_or_insert(seq);
        }
        if !s.data.is_empty() {
            stream.next.get_or_insert(seq);
            if !stream.pending.iter().any(|(start, bytes)| *start == seq && bytes.len() >= s.data.len()) {
                stream.pending.push((seq, s.data));
            }
        }
        c.closed |= s.flags & 5 != 0;
        out.drain(c, dir, time, s.flags & 5 != 0)
    }
}
pub fn run(options: &Options, json_output: bool, color: bool, writer: &mut impl Write) -> io::Result<bool> {
    let mut bytes = Vec::new();
    if options.file.as_os_str() == "-" {
        io::stdin().lock().take(capture::FILE_LIMIT + 1).read_to_end(&mut bytes)?;
    } else {
        let path = &options.file;
        if !std::fs::metadata(path)?.is_file() {
            return Err(capture::invalid("expected a regular capture file"));
        }
        let file = File::open(path)?;
        let meta = file.metadata()?;
        if !meta.is_file() {
            return Err(capture::invalid("expected a regular capture file"));
        }
        if meta.len() > capture::FILE_LIMIT {
            return Err(capture::invalid("capture exceeds 512 MiB"));
        }
        file.take(capture::FILE_LIMIT + 1).read_to_end(&mut bytes)?;
    }
    if bytes.len() as u64 > capture::FILE_LIMIT {
        return Err(capture::invalid("capture exceeds 512 MiB"));
    }
    let mut capture = Capture::default();
    let mut out = Output { writer, json: json_output, color, summary: options.summary, utc: options.utc, profile: options.profile.resolve(AddressWidth::One) };
    capture::read(&bytes, |p| capture.accept(p, &options.ports, &mut out))?;
    for c in &mut capture.sessions {
        for dir in 0..2 {
            out.drain(c, dir, capture.last_time, true)?;
        }
    }
    for c in &mut capture.sessions {
        out.finish(c)?;
    }
    let n = capture.sessions.len();
    let data = json!({"kind":"capture","packets":capture.packets,"connections":n,"non_tcp":capture.non_tcp,"fragments":capture.fragments,"truncated":capture.truncated,"unsupported_link":capture.unsupported,"dropped_connection_packets":capture.dropped});
    out.report(
        &data,
        &format!(
            "{} packets, {n} connections, {} non-TCP, {} fragments, {} truncated, {} unsupported link, {} dropped connection packets",
            capture.packets, capture.non_tcp, capture.fragments, capture.truncated, capture.unsupported, capture.dropped
        ),
    )?;
    out.writer.flush()?;
    Ok(capture.sessions.iter().all(|c| c.errors == 0))
}
