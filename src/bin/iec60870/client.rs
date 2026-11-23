//! IEC 104 station queries, clock synchronisation and point observation.
mod files;
use super::{ProfileArgs, duration, render};
use clap::{Args, Subcommand};
use iec60870::{Client, Error, cs101::AddressWidth, cs104, prelude::*, station::ClientConfig};
use serde_json::json;
use std::{
    collections::BTreeMap,
    fmt,
    io::{self, IsTerminal, Write},
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

#[derive(Args)]
pub struct Options {
    /// Host or IP address, optionally followed by a port (default 2404, or 19998 with TLS).
    host: String,
    /// Use mutual TLS with PEM trust anchors, client certificate chain and private key (requires the tls feature).
    #[arg(long, num_args=3, value_names=["CA", "CERT", "KEY"])]
    tls: Option<Vec<std::path::PathBuf>>,
    /// Certificate DNS name or IP address, when different from the connection target.
    #[arg(long, requires = "tls", value_name = "NAME")]
    tls_server_name: Option<String>,
    /// Interpret valid CP56 station clock readings as UTC in JSON.
    #[arg(long)]
    utc: bool,
    /// Station common address.
    #[arg(long, default_value_t = 1)]
    ca: u16,
    /// Maximum wait for connection, confirmation or termination (up to 255s).
    #[arg(long,default_value="10s",value_parser=parse_timeout)]
    timeout: Duration,
    /// ASDU profile for field widths.
    #[arg(long,default_value="104",value_parser=["104","101"])]
    profile: String,
    /// Common address width in octets.
    #[arg(long,value_parser=clap::value_parser!(u8).range(1..=2))]
    ca_width: Option<u8>,
    /// Cause width in octets.
    #[arg(long,value_parser=clap::value_parser!(u8).range(1..=2))]
    cot: Option<u8>,
    /// Information object address width in octets.
    #[arg(long,value_parser=clap::value_parser!(u8).range(1..=3))]
    ioa: Option<u8>,
    #[command(subcommand)]
    action: Action,
}
#[derive(Subcommand)]
enum Action {
    /// Interrogate station points, optionally in one group.
    Gi {
        #[arg(long,value_parser=clap::value_parser!(u8).range(1..=16))]
        group: Option<u8>,
    },
    /// Read counters, optionally in one counter group.
    Ci {
        #[arg(long,value_parser=clap::value_parser!(u8).range(1..=4))]
        group: Option<u8>,
    },
    /// Read a single information object address.
    Read {
        #[arg(value_parser=clap::value_parser!(u32).range(0..=16777215))]
        ioa: u32,
    },
    /// List the file records available at one station.
    Files,
    /// Download a verified record to a new local file.
    Get {
        #[arg(value_parser=clap::value_parser!(u32).range(0..=16777215))]
        ioa: u32,
        /// Numeric IEC file name from the directory.
        name: u16,
        /// Reject records larger than this many bytes (default 16777215).
        #[arg(long,value_parser=clap::value_parser!(u32).range(0..=16777215))]
        max_bytes: Option<u32>,
        /// Destination path. An existing file is preserved.
        #[arg(short, long, value_name = "PATH")]
        output: std::path::PathBuf,
    },
    /// Synchronize one station to the current UTC time of this host.
    Clock,
    /// Display live points in a terminal or stream changes to a pipe.
    Watch {
        #[arg(long)]
        no_gi: bool,
        #[arg(long="for",value_name="DURATION",value_parser=parse_duration)]
        limit: Option<Duration>,
    },
}
fn parse_duration(s: &str) -> Result<Duration, String> {
    duration(s).ok_or_else(|| "use a positive integer with ms, s or m (bare integers are seconds)".into())
}
fn parse_timeout(s: &str) -> Result<Duration, String> {
    let d = parse_duration(s)?;
    if d > Duration::from_secs(255) { Err("link timeout must be at most 255s".into()) } else { Ok(d) }
}
#[derive(Debug)]
struct Failure(u8, String);
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.1)
    }
}
impl std::error::Error for Failure {}
pub(super) fn exit_code(e: &io::Error) -> Option<u8> {
    let source = e.get_ref()?;
    if let Some(f) = source.downcast_ref::<Failure>() {
        return Some(f.0);
    }
    Some(match source.downcast_ref::<Error>()? {
        Error::Negative { .. } | Error::File(iec60870::station::FileError::NotReady) => 3,
        Error::File(_) | Error::InvalidDirectory => 1,
        Error::InvalidArgument(_) | Error::Encode(_) => 2,
        _ => 4,
    })
}
fn target(host: &str, default_port: u16) -> io::Result<String> {
    if host.chars().any(|c| !c.is_ascii() || c.is_ascii_control() || c.is_whitespace()) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "use an IP address or ASCII hostname"));
    }
    if let Ok(a) = host.parse::<SocketAddr>() {
        return Ok(a.to_string());
    }
    if let Ok(ip) = host.strip_prefix('[').and_then(|s| s.strip_suffix(']')).unwrap_or(host).parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, default_port).to_string());
    }
    let default = default_port.to_string();
    let (name, port) = host.split_once(':').unwrap_or((host, &default));
    if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')) || port.parse::<u16>().is_err() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "expected HOST[:PORT] or [IPv6]:PORT"));
    }
    Ok(format!("{name}:{port}"))
}
fn connect(options: &Options, profile: Profile) -> io::Result<Client> {
    let secure = options.tls.is_some();
    let default_port = if secure { 19998 } else { 2404 };
    let addr = target(&options.host, default_port)?;
    #[cfg(not(feature = "tls"))]
    if secure {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "install with --features cli,tls to use mutual TLS"));
    }
    #[cfg(feature = "tls")]
    let tls = match options.tls.as_deref() {
        Some([ca, cert, key]) => Some(iec60870::tls::TlsClientConfig::from_pem_files(ca, cert, key).map_err(|e| io::Error::other(Failure(1, e.to_string())))?),
        Some(_) => return Err(io::Error::new(io::ErrorKind::InvalidInput, "--tls requires CA CERT KEY")),
        None => None,
    };
    let timeout = options.timeout;
    let failure = |e: &str| {
        let hint = if secure {
            "Check the TLS listener, trust anchors and certificate names (default port 19998)"
        } else {
            "Check the station address (default port 2404) or start iec60870 sim --demo"
        };
        io::Error::other(Failure(4, format!("{addr}: {e}. {hint}")))
    };
    let started = Instant::now();
    let addrs = if let Ok(addr) = addr.parse::<SocketAddr>() {
        vec![addr]
    } else {
        let (tx, rx) = mpsc::sync_channel(1);
        let name = addr.clone();
        thread::Builder::new().name("iec60870-resolve".into()).spawn(move || {
            let _ = tx.send(name.to_socket_addrs().map(Iterator::collect::<Vec<_>>));
        })?;
        rx.recv_timeout(timeout).map_err(|_| failure("name resolution timed out"))?.map_err(|e| failure(&e.to_string()))?
    };
    let mut last = "no address available".to_owned();
    for address in addrs {
        let left = timeout.saturating_sub(started.elapsed());
        if left.is_zero() {
            break;
        }
        let link = cs104::Config { t0: left, t1: timeout, t2: timeout / 2, ..Default::default() };
        let mut cfg = ClientConfig { profile, confirmation_timeout: timeout, termination_timeout: timeout, ..Default::default() };
        if let Action::Get { max_bytes: Some(limit), .. } = options.action {
            cfg.files.max_length = limit;
        }
        let builder = Client::builder().link(link).config(cfg);
        #[cfg(feature = "tls")]
        let connected = if let Some(tls) = &tls {
            let (host, _) = addr.rsplit_once(':').ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing port"))?;
            let name = options.tls_server_name.as_deref().unwrap_or_else(|| host.trim_start_matches('[').trim_end_matches(']'));
            builder.connect_tls(address, name, tls)
        } else {
            builder.connect(address)
        };
        #[cfg(not(feature = "tls"))]
        let connected = builder.connect(address);
        match connected {
            Ok(mut c) => {
                if matches!(options.action, Action::Files | Action::Get { .. }) {
                    c.set_event_buffering(false);
                }
                c.start().map_err(|e| failure(&format!("outstation did not confirm STARTDT: {e}")))?;
                return Ok(c);
            }
            Err(e) => last = e.to_string(),
        }
    }
    Err(failure(&last))
}
#[derive(Clone, Copy)]
enum PointOutput {
    Text,
    Json { utc: bool },
}
fn write_point(p: &Point, format: PointOutput, out: &mut impl Write) -> io::Result<()> {
    let PointOutput::Json { utc } = format else {
        return writeln!(
            out,
            "{:5} {:8}  {:18} {:16}  {} {}",
            p.common_address,
            p.ioa,
            p.value.kind().to_string(),
            p.value.to_string(),
            p.cause,
            p.time.map(|t| t.to_string()).unwrap_or_default()
        );
    };
    let mut row = render::point_json(p, utc);
    if let Some(fields) = row.as_object_mut() {
        fields.extend([
            ("kind".into(), json!("point")),
            ("ca".into(), json!(p.common_address.0)),
            ("cause".into(), json!(p.cause.cause.value())),
            ("cause_name".into(), json!(p.cause.cause.name())),
            ("test".into(), json!(p.cause.test)),
            ("negative".into(), json!(p.cause.negative)),
            ("originator".into(), json!(p.cause.originator)),
        ]);
    }
    writeln!(out, "{row}")
}
fn points(replies: iec60870::Replies<'_>, mut emit: impl FnMut(Point) -> io::Result<()>) -> io::Result<()> {
    for event in replies {
        if let Event::Point(p) = event.map_err(io::Error::other)? {
            emit(p)?;
        }
    }
    Ok(())
}
pub fn run(o: &Options, json_output: bool, color: bool, out: &mut impl Write) -> io::Result<bool> {
    let profile = ProfileArgs { profile: o.profile.clone(), ca: o.ca_width, cot: o.cot, ioa: o.ioa }.resolve(AddressWidth::One);
    if o.ca > profile.ca.max() || matches!(o.action, Action::Read{ioa} | Action::Get{ioa,..} if ioa>profile.ioa.max()) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "address exceeds the selected field width"));
    }
    if matches!(o.action, Action::Clock) && o.ca == profile.ca.max() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "clock requires one station common address"));
    }
    if matches!(o.action, Action::Files | Action::Get { .. }) && o.ca == profile.ca.max() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "file operations require one station common address"));
    }
    let ca = CommonAddress(o.ca);
    if let Action::Get { ioa, name, output, .. } = &o.action {
        let destination = files::Destination::prepare(output)?;
        let mut client = connect(o, profile)?;
        return files::get(&mut client, ca, Ioa(*ioa), *name, destination, json_output, out);
    }
    let mut c = connect(o, profile)?;
    let started = Instant::now();
    if matches!(o.action, Action::Files) {
        return files::list(&mut c, ca, o.utc, json_output, out);
    }
    if matches!(o.action, Action::Clock) {
        c.clock_sync(ca).map_err(io::Error::other)?;
        if json_output {
            writeln!(out, "{}", json!({"kind":"done","action":"clock","ca":ca.0,"seconds":started.elapsed().as_secs_f64()}))?;
        } else {
            writeln!(out, "CA {ca} confirmed UTC clock synchronization")?;
        }
        return Ok(true);
    }
    let format = if json_output { PointOutput::Json { utc: o.utc } } else { PointOutput::Text };
    if let Action::Watch { no_gi, limit } = o.action {
        let station_filter = (ca.0 != profile.ca.max()).then_some(ca);
        let mut view = Watch::new(format, color, station_filter);
        watch(&mut c, ca, no_gi, limit, &mut view, out)?;
        return Ok(true);
    }
    let mut count = 0_u64;
    if !json_output {
        writeln!(out, "   CA      IOA  TYPE               VALUE             CAUSE / TIME")?;
    }
    let mut emit = |p: Point| {
        count += 1;
        write_point(&p, format, out)
    };
    let action = match o.action {
        Action::Gi { group } => {
            let r = if let Some(g) = group { c.interrogate_group(ca, g) } else { c.interrogate(ca) };
            points(r.map_err(io::Error::other)?, &mut emit)?;
            "gi"
        }
        Action::Ci { group } => {
            let q = group.and_then(CounterInterrogation::group).unwrap_or(CounterInterrogation::GENERAL);
            points(c.counter_interrogate(ca, q).map_err(io::Error::other)?, &mut emit)?;
            "ci"
        }
        Action::Read { ioa } => {
            emit(c.read(ca, Ioa(ioa)).map_err(io::Error::other)?)?;
            "read"
        }
        Action::Clock | Action::Watch { .. } | Action::Files | Action::Get { .. } => return Ok(true),
    };
    // Each responding common address sends its own termination. Keep collecting
    // within an absolute window after the first one, even with unrelated traffic.
    let broadcast_cause = match o.action {
        Action::Gi { group } => Some(group.and_then(Cause::interrogated_by_group).unwrap_or(Cause::INTERROGATED_BY_STATION)),
        Action::Ci { group } => Some(group.and_then(Cause::requested_by_counter_group).unwrap_or(Cause::REQUESTED_BY_GENERAL_COUNTER)),
        _ => None,
    };
    if ca.0 == profile.ca.max()
        && let Some(expected) = broadcast_cause
    {
        let window = Instant::now();
        while let Some(left) = o.timeout.checked_sub(window.elapsed()) {
            match c.poll_event(left).map_err(io::Error::other)? {
                Some(Event::Point(p)) if p.cause.cause == expected => emit(p)?,
                Some(Event::Disconnected(reason)) => return Err(io::Error::other(Error::Disconnected(reason))),
                None => break,
                _ => (),
            }
        }
    }
    let seconds = started.elapsed().as_secs_f64();
    if json_output {
        writeln!(out, "{}", json!({"kind":"done","action":action,"points":count,"seconds":seconds}))?;
    } else {
        let unit = if count == 1 { "point" } else { "points" };
        writeln!(out, "{count} {unit} in {seconds:.3} s")?;
    }
    Ok(true)
}
struct WatchRow {
    point: Point,
    seen: Instant,
    updates: u64,
}
struct Watch {
    rows: BTreeMap<(CommonAddress, Ioa), WatchRow>,
    started: Instant,
    updates: u64,
    last_event: String,
    overflow: u64,
    drawn: usize,
    tty: bool,
    format: PointOutput,
    color: bool,
    station: Option<CommonAddress>,
}
impl Watch {
    fn new(format: PointOutput, color: bool, station: Option<CommonAddress>) -> Self {
        let tty = matches!(format, PointOutput::Text) && io::stdout().is_terminal() && std::env::var_os("TERM").is_none_or(|v| v != "dumb");
        Self { rows: BTreeMap::new(), started: Instant::now(), updates: 0, last_event: String::new(), overflow: 0, drawn: 0, tty, format, color, station }
    }
    fn point(&mut self, p: Point, out: &mut impl Write) -> io::Result<()> {
        if self.station.is_some_and(|ca| ca != p.common_address) {
            return Ok(());
        }
        if !self.tty {
            return write_point(&p, self.format, out);
        }
        self.updates = self.updates.saturating_add(1);
        let key = (p.common_address, p.ioa);
        if let Some(row) = self.rows.get_mut(&key) {
            row.point = p;
            row.seen = Instant::now();
            row.updates = row.updates.saturating_add(1);
        } else if self.rows.len() >= 65536 {
            self.overflow = self.overflow.saturating_add(1);
        } else {
            self.rows.insert(key, WatchRow { point: p, seen: Instant::now(), updates: 1 });
        }
        Ok(())
    }
    fn draw(&mut self, out: &mut impl Write) -> io::Result<()> {
        let size = |name, default| std::env::var(name).ok().and_then(|s| s.parse::<usize>().ok()).unwrap_or(default).clamp(1, 4096);
        let height = size("LINES", 24).saturating_sub(3);
        let width = size("COLUMNS", 80).saturating_sub(1);
        if self.drawn > 0 {
            write!(out, "\x1b[{}F", self.drawn)?;
        }
        let visible = self.rows.len().min(height);
        let header = "   CA      IOA  UPDATES  TYPE               VALUE             CAUSE / TIME";
        writeln!(out, "\x1b[2K{}", header.chars().take(width).collect::<String>())?;
        let mut rendered = 1;
        for row in self.rows.values().take(visible) {
            let p = &row.point;
            let time = p.time.map(|t| t.to_string()).unwrap_or_default();
            let text = format!(
                "{:5} {:8}  {:7}  {:18} {:16}  {} {time}",
                p.common_address,
                p.ioa,
                row.updates,
                p.value.kind().to_string(),
                p.value.to_string(),
                p.cause
            );
            let line = text.chars().take(width).collect::<String>();
            write!(out, "\x1b[2K")?;
            if self.color && row.seen.elapsed() < Duration::from_secs(1) {
                writeln!(out, "\x1b[36m{line}\x1b[0m")?;
            } else {
                writeln!(out, "{line}")?;
            }
            rendered += 1;
        }
        let rate = u128::from(self.updates) * 1000 / self.started.elapsed().as_millis().max(1);
        let status = format!(
            "{} points, {} hidden, {} overflow | connected | avg {rate}/s {}",
            self.rows.len(),
            self.rows.len() - visible,
            self.overflow,
            self.last_event
        );
        writeln!(out, "\x1b[2K{}", status.chars().take(width).collect::<String>())?;
        rendered += 1;
        for _ in rendered..self.drawn {
            writeln!(out, "\x1b[2K")?;
        }
        if rendered < self.drawn {
            write!(out, "\x1b[{}F", self.drawn - rendered)?;
        }
        self.drawn = rendered;
        out.flush()
    }
}
fn watch(c: &mut Client, ca: CommonAddress, no_gi: bool, limit: Option<Duration>, view: &mut Watch, out: &mut impl Write) -> io::Result<()> {
    let tty = view.tty;
    let started = Instant::now();
    if !no_gi {
        points(c.interrogate(ca).map_err(io::Error::other)?, |p| view.point(p, out))?;
    }
    let refresh = Duration::from_millis(100);
    let mut last = None;
    loop {
        let now = Instant::now();
        if tty && last.is_none_or(|t| now.duration_since(t) >= refresh) {
            view.draw(out)?;
            last = Some(now);
        }
        let left = limit.map_or(Duration::MAX, |d| d.saturating_sub(started.elapsed()));
        if left.is_zero() {
            return Ok(());
        }
        let wait = if tty { refresh.saturating_sub(last.map_or(Duration::ZERO, |t| t.elapsed())) } else { Duration::from_secs(60) };
        if let Some(e) = c.poll_event(left.min(wait)).map_err(io::Error::other)? {
            match e {
                Event::Point(p) => view.point(p, out)?,
                Event::Disconnected(reason) => return Err(io::Error::other(Error::Disconnected(reason))),
                other if !tty && matches!(view.format, PointOutput::Json { .. }) => writeln!(out, "{}", json!({"kind":"event","text":other.to_string()}))?,
                other if !tty => writeln!(out, "{other}")?,
                other => view.last_event = super::out::clean(&other.to_string()).chars().take(160).collect(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watch_bounds_rows_and_draws_sorted_values() -> io::Result<()> {
        let mut view = Watch { tty: true, ..Watch::new(PointOutput::Text, false, None) };
        let mut out = Vec::new();
        for ioa in (0..=65_536).rev() {
            let p = Point { common_address: CommonAddress(1), ioa: Ioa(ioa), cause: Cot::new(Cause::SPONTANEOUS), value: true.into(), time: None };
            view.point(p, &mut out)?;
        }
        assert_eq!(view.rows.len(), 65_536);
        assert_eq!(view.overflow, 1);
        let key = (CommonAddress(1), Ioa(1));
        assert!(view.rows.contains_key(&key));
        let p = Point { common_address: key.0, ioa: key.1, cause: Cot::new(Cause::SPONTANEOUS), value: false.into(), time: None };
        view.point(p, &mut out)?;
        assert_eq!(view.overflow, 1);
        assert_eq!(view.rows.get(&key).map(|r| r.updates), Some(2));
        view.draw(&mut out)?;
        let frame = String::from_utf8_lossy(&out);
        assert!(frame.contains("1 overflow") || std::env::var_os("COLUMNS").is_some());
        Ok(())
    }
    #[test]
    fn endpoint_defaults_and_ipv6_brackets() -> io::Result<()> {
        assert_eq!(target("localhost", 2404)?, "localhost:2404");
        assert_eq!(target("[::1]", 2404)?, "[::1]:2404");
        assert_eq!(target("::1", 2404)?, "[::1]:2404");
        assert_eq!(target("[::1]:12345", 2404)?, "[::1]:12345");
        assert!(target("[::1", 2404).is_err());
        assert_eq!(target("[::1]", 19998)?, "[::1]:19998");
        assert_eq!(target("station.example", 19998)?, "station.example:19998");
        Ok(())
    }
}
