//! Validate a local simulator configuration before starting a station.
mod preview;
mod runtime;
use clap::{ArgGroup, Args};
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};
use toml::Spanned;

const LIMIT: u64 = 1024 * 1024;
const DEMO: &str = include_str!("../../../examples/demo-bay.toml");

#[derive(Args)]
#[command(group(ArgGroup::new("source").required(true).args(["demo", "points"])))]
pub struct Options {
    /// Validate and exit without opening a network connection.
    #[arg(long, conflicts_with_all = ["bind", "seed"])]
    check: bool,
    /// Preview one configured command against the initial point values, then exit.
    #[arg(long, num_args=3, value_names=["IOA", "KIND", "VALUE"], allow_negative_numbers=true, conflicts_with_all=["check", "bind", "seed"])]
    preview: Option<Vec<String>>,
    /// Station for the offline preview (default 1).
    #[arg(long, requires="preview", value_parser=clap::value_parser!(u16).range(..65535))]
    ca: Option<u16>,
    /// Preview direct execution. The default previews select-before-operate.
    #[arg(long, requires = "preview")]
    direct: bool,
    /// Local socket address (default 127.0.0.1:2404). Port 0 selects an available port.
    #[arg(long, default_value = "127.0.0.1:2404")]
    bind: std::net::SocketAddr,
    /// Seed for reproducible simulated point changes (default 1).
    #[arg(long)]
    seed: Option<u64>,
    /// Use the packaged demo bay.
    #[arg(long)]
    demo: bool,
    /// Read a local TOML point file.
    #[arg(long, value_name = "FILE")]
    points: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    station: Vec<Station>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Station {
    ca: Spanned<u16>,
    #[serde(default)]
    point: Vec<Point>,
    #[serde(default)]
    command: Vec<Command>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Point {
    ioa: Spanned<u32>,
    kind: Kind,
    value: Spanned<toml::Value>,
    group: Option<Spanned<u8>>,
    time: Option<Time>,
    walk: Option<Spanned<Walk>>,
}
#[derive(Clone, Copy, PartialEq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Kind {
    Single,
    Double,
    Step,
    Bitstring,
    Normalized,
    Scaled,
    Float,
    Counter,
}
#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum Time {
    None,
    Cp56,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Walk {
    step: f64,
    min: f64,
    max: f64,
    every: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Command {
    ioa: Spanned<u32>,
    kind: CommandKind,
    mode: Option<Mode>,
    accept: Option<bool>,
    status: Option<Spanned<u32>>,
    step_range: Option<Spanned<[i8; 2]>>,
}
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Mode {
    Sbo,
    Direct,
    Both,
}
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum CommandKind {
    Single,
    Double,
    Step,
    Setpoint,
    Scaled,
    Normalized,
    Bits,
}
impl Command {
    fn effective_mode(&self) -> Mode {
        self.mode.unwrap_or(if matches!(self.kind, CommandKind::Bits) { Mode::Direct } else { Mode::Sbo })
    }
}
impl CommandKind {
    fn target(self) -> Kind {
        match self {
            Self::Single => Kind::Single,
            Self::Double => Kind::Double,
            Self::Step => Kind::Step,
            Self::Setpoint => Kind::Float,
            Self::Scaled => Kind::Scaled,
            Self::Normalized => Kind::Normalized,
            Self::Bits => Kind::Bitstring,
        }
    }
}

impl Kind {
    fn numeric(self, n: f64) -> bool {
        match self {
            Self::Step => n.fract() == 0. && (-64.0..=63.).contains(&n),
            Self::Counter => n.fract() == 0. && (f64::from(i32::MIN)..=f64::from(i32::MAX)).contains(&n),
            Self::Scaled => n.fract() == 0. && (f64::from(i16::MIN)..=f64::from(i16::MAX)).contains(&n),
            Self::Normalized => (-1.0..=1.0).contains(&n),
            Self::Float => (n as f32).is_finite(),
            _ => false,
        }
    }
    fn value_hint(self) -> &'static str {
        match self {
            Self::Single => "single value must be true or false",
            Self::Double => "double value must be on, off, intermediate or indeterminate",
            Self::Step => "step value must be a whole number from -64 to 63",
            Self::Scaled => "scaled value must be a whole number from -32768 to 32767",
            Self::Counter => "counter value must be a signed 32-bit whole number",
            Self::Bitstring => "bitstring value must be an unsigned 32-bit integer",
            Self::Float => "float value must fit in a finite 32-bit float",
            Self::Normalized => "normalized value must be between -1 and 1",
        }
    }
    fn accepts(self, v: &toml::Value) -> bool {
        match self {
            Self::Single => v.is_bool(),
            Self::Double => matches!(v.as_str(), Some("on" | "off" | "intermediate" | "indeterminate")),
            Self::Bitstring => v.as_integer().is_some_and(|n| u32::try_from(n).is_ok()),
            _ => number(v).is_some_and(|n| self.numeric(n)),
        }
    }
}
#[allow(clippy::cast_precision_loss)]
fn number(v: &toml::Value) -> Option<f64> {
    v.as_float().or_else(|| v.as_integer().map(|i| i as f64))
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
fn location(source: &str, name: &str, pos: usize, why: &str) -> io::Error {
    let line = source.get(..pos).unwrap_or_default().matches('\n').count() + 1;
    invalid(format!("{name}:{line}: {why}"))
}
fn validate(source: &str, name: &str) -> io::Result<(Config, usize, usize)> {
    if let Some((pos, _)) = source.char_indices().find(|(_, c)| super::out::unsafe_character(*c) && !matches!(c, '\t' | '\r' | '\n')) {
        return Err(location(source, name, pos, "unexpected control character"));
    }
    let config: Config = toml::from_str(source).map_err(|e| {
        location(source, name, e.span().map_or(0, |s| s.start), &e.message().chars().take(240).flat_map(char::escape_debug).collect::<String>())
    })?;
    let error = |pos, why| location(source, name, pos, why);
    if config.station.is_empty() {
        return Err(error(0, "expected at least one station"));
    }
    let mut stations = BTreeSet::new();
    let mut counts = (config.station.len(), 0, 0);
    for st in &config.station {
        if *st.ca.get_ref() == u16::MAX {
            return Err(error(st.ca.span().start, "station common address 65535 is reserved for broadcast"));
        }
        if !stations.insert(*st.ca.get_ref()) {
            return Err(error(st.ca.span().start, "duplicate station common address"));
        }
        let mut points = BTreeMap::new();
        for p in &st.point {
            let ioa = *p.ioa.get_ref();
            if ioa > 0xff_ffff || points.insert(ioa, p.kind).is_some() {
                return Err(error(p.ioa.span().start, "IOA must be unique in the point table and within 0..16777215"));
            }
            if !p.kind.accepts(p.value.get_ref()) {
                return Err(error(p.value.span().start, p.kind.value_hint()));
            }
            if let Some(g) = &p.group
                && !(1..=16).contains(g.get_ref())
            {
                return Err(error(g.span().start, "group must be in 1..16"));
            }
            if matches!(p.kind, Kind::Counter)
                && let Some(g) = &p.group
                && *g.get_ref() > 4
            {
                return Err(error(g.span().start, "counter group must be in 1..4"));
            }
            if let Some(w) = &p.walk {
                let walk = w.get_ref();
                let integral = matches!(p.kind, Kind::Scaled | Kind::Step | Kind::Counter);
                let valid = p.kind.numeric(walk.min)
                    && p.kind.numeric(walk.max)
                    && number(p.value.get_ref()).is_some_and(|n| (walk.min..=walk.max).contains(&n))
                    && (walk.step as f32) > 0.
                    && (walk.step as f32).is_finite()
                    && (!integral || walk.step.fract() == 0.)
                    && super::duration(&walk.every).is_some();
                if !valid {
                    return Err(error(w.span().start, "walk needs representable bounds around the value, a positive step and a positive interval"));
                }
            }
        }
        let mut commands = BTreeSet::new();
        for c in &st.command {
            if *c.ioa.get_ref() > 0xff_ffff || !commands.insert(*c.ioa.get_ref()) {
                return Err(error(c.ioa.span().start, "IOA must be unique in the command table and within 0..16777215"));
            }
            if let Some(range) = &c.step_range {
                let [lo, hi] = *range.get_ref();
                if !matches!(c.kind, CommandKind::Step) || c.status.is_none() || lo < -64 || hi > 63 || lo > hi {
                    return Err(error(range.span().start, "step_range needs a step status and ordered limits in -64..63"));
                }
            }
            if matches!(c.kind, CommandKind::Bits) && matches!(c.mode, Some(Mode::Sbo | Mode::Both)) {
                return Err(error(c.ioa.span().start, "bitstring commands require direct mode"));
            }
            if let Some(status) = &c.status
                && points.get(status.get_ref()) != Some(&c.kind.target())
            {
                return Err(error(status.span().start, "status must name a compatible monitored point in the same station"));
            }
        }
        counts.1 += points.len();
        counts.2 += commands.len();
    }
    Ok((config, counts.1, counts.2))
}
fn read(path: &Path) -> io::Result<String> {
    let meta = fs::metadata(path)?;
    if !meta.is_file() {
        return Err(invalid("expected a regular TOML file"));
    }
    if meta.len() > LIMIT {
        return Err(invalid("point file exceeds 1 MiB"));
    }
    let mut buf = Vec::new();
    File::open(path)?.take(LIMIT + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > LIMIT {
        return Err(invalid("point file exceeds 1 MiB"));
    }
    String::from_utf8(buf).map_err(|e| {
        let offset = e.utf8_error().valid_up_to();
        let line = e.as_bytes().get(..offset).unwrap_or_default().split(|b| *b == b'\n').count();
        invalid(format!("line {line}: invalid UTF-8 at byte {offset}"))
    })
}
pub fn run(options: &Options, json_output: bool, out: &mut impl Write) -> io::Result<bool> {
    let text;
    let name;
    let (source, label) = if let Some(path) = &options.points {
        name = path.to_string_lossy().escape_debug().to_string();
        text = read(path).map_err(|e| invalid(format!("{name}: {e}")))?;
        (text.as_str(), name.as_str())
    } else {
        (DEMO, "demo bay")
    };
    let (config, points, commands) = validate(source, label)?;
    if let Some(args) = &options.preview {
        return preview::run(options, args, &config, json_output, out);
    }
    if !options.check {
        return runtime::serve(options, config, points, commands, json_output, out);
    }
    let stations = config.station.len();
    if json_output {
        writeln!(out, "{}", json!({"kind":"validation","stations":stations,"points":points,"commands":commands}))?;
    } else {
        writeln!(out, "{label} is valid. Stations: {stations}, monitored points: {points}, command points: {commands}.")?;
    }
    Ok(true)
}
