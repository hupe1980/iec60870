//! IEC 60870 tools for frame inspection, station simulation and client operations.
mod capture;
mod client;
mod decode;
mod hex;
mod out;
mod packet;
mod pcap;
mod render;
mod serial_monitor;
mod sim;

use clap::{Args, Parser, Subcommand, ValueEnum};
use iec60870::asdu::{CaWidth, CotWidth, IoaWidth, Profile};
use iec60870::cs101::AddressWidth;
use serde_json::json;
use std::io::{self, IsTerminal, Write};
use std::process::ExitCode;

#[derive(Parser)]
#[command(version, about = "Inspect IEC 60870-5-101 and -104 protocol data")]
struct Cli {
    /// Emit one JSON object per record.
    #[arg(long, global = true)]
    json: bool,
    /// Colorize human output.
    #[arg(long, global = true, value_enum, default_value = "auto")]
    color: Color,
    #[command(subcommand)]
    command: Action,
}
#[derive(Clone, Copy, ValueEnum)]
enum Color {
    Auto,
    Always,
    Never,
}
#[derive(Subcommand)]
enum Action {
    /// Decode pasted hex or one record per line on stdin.
    Decode(Decode),
    /// Read points, counters and files, watch changes, or synchronize a station clock.
    Client(client::Options),
    /// Observe IEC 101 frames from a serial tap or binary pipe.
    SerialMonitor(serial_monitor::Options),
    /// Inspect IEC 104 connections in a capture file or finite binary pipe.
    Pcap(pcap::Options),
    /// Serve a simulated IEC 104 station or validate its configuration.
    Sim(sim::Options),
}
#[derive(Args)]
struct Decode {
    /// Hex octets (default: stdin). Use # for comments on stdin.
    #[arg(value_name = "HEX")]
    hex: Vec<String>,
    /// Treat the input as a bare ASDU, including ambiguous type identifiers.
    #[arg(long)]
    asdu: bool,
    /// Annotate the byte offsets and fields in each frame.
    #[arg(long)]
    explain: bool,
    /// Interpret valid CP56 station clock readings as UTC in JSON.
    #[arg(long)]
    utc: bool,
    #[command(flatten)]
    profile: ProfileArgs,
    /// FT 1.2 link address width, in octets.
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u8).range(0..=2))]
    link_addr: u8,
}
#[derive(Args)]
struct ProfileArgs {
    /// ASDU profile and preferred framing.
    #[arg(long, default_value = "104", value_parser = ["104", "101"])]
    profile: String,
    /// Cause of transmission width, in octets.
    #[arg(long, value_parser = clap::value_parser!(u8).range(1..=2))]
    cot: Option<u8>,
    /// Common address width, in octets.
    #[arg(long, value_parser = clap::value_parser!(u8).range(1..=2))]
    ca: Option<u8>,
    /// Information object address width, in octets.
    #[arg(long, value_parser = clap::value_parser!(u8).range(1..=3))]
    ioa: Option<u8>,
}

impl ProfileArgs {
    fn resolve(&self, link: AddressWidth) -> Profile {
        let mut p = if self.profile == "101" { Profile::IEC101.with_max_asdu_len(link.max_user_data() as u8) } else { Profile::IEC104 };
        if let Some(cot) = self.cot {
            p.cot = if cot == 1 { CotWidth::One } else { CotWidth::Two };
        }
        if let Some(ca) = self.ca {
            p.ca = if ca == 1 { CaWidth::One } else { CaWidth::Two };
        }
        if let Some(ioa) = self.ioa {
            p.ioa = match ioa {
                1 => IoaWidth::One,
                2 => IoaWidth::Two,
                _ => IoaWidth::Three,
            };
        }
        p
    }
}
impl Decode {
    fn widths(&self) -> (Profile, AddressWidth) {
        let link = match self.link_addr {
            0 => AddressWidth::Zero,
            2 => AddressWidth::Two,
            _ => AddressWidth::One,
        };
        (self.profile.resolve(link), link)
    }
}
fn duration(s: &str) -> Option<std::time::Duration> {
    let (digits, multiplier) = if let Some(ms) = s.strip_suffix("ms") {
        (ms, 1)
    } else if let Some(m) = s.strip_suffix('m') {
        (m, 60_000)
    } else {
        (s.strip_suffix('s').unwrap_or(s), 1000)
    };
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse::<u64>().ok()?.checked_mul(multiplier).filter(|n| *n > 0).map(std::time::Duration::from_millis)
}
fn run(cli: &Cli, out: &mut impl Write) -> io::Result<bool> {
    let color = match cli.color {
        Color::Always => true,
        Color::Never => false,
        Color::Auto => {
            io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty()) && std::env::var_os("TERM").is_none_or(|v| v != "dumb")
        }
    };
    let options = match &cli.command {
        Action::Decode(options) => options,
        Action::Client(options) => return client::run(options, cli.json, color, out),
        Action::Sim(options) => return sim::run(options, cli.json, out),
        Action::SerialMonitor(options) => return serial_monitor::run(options, cli.json, color, out),
        Action::Pcap(options) => return pcap::run(options, cli.json, color, out),
    };
    let mut success = true;
    let mut process = |input: usize, parsed: Result<Vec<u8>, String>| -> io::Result<()> {
        let result = parsed
            .map_err(decode::Failure::Input)
            .and_then(|bytes| decode::frames(options, &bytes, |frame, bytes| frame.write(input, bytes, options.explain, cli.json, color, out)));
        match result {
            Ok(()) => (),
            Err(decode::Failure::Output(e)) => return Err(e),
            Err(decode::Failure::Asdu(error, base)) => {
                success = false;
                let message = error.to_string();
                let offset = base + error.offset;
                let field = error.field.to_string();
                writeln!(io::stderr().lock(), "iec60870: input {input}: {message} (frame offset {offset})")?;
                if cli.json {
                    writeln!(out, "{}", json!({"kind":"error","input":input,"error":message,"field":field,"offset":offset}))?;
                }
            }
            Err(decode::Failure::Input(message)) => {
                success = false;
                writeln!(io::stderr().lock(), "iec60870: input {input}: {message}")?;
                if cli.json {
                    writeln!(out, "{}", json!({"kind":"error","input":input,"error":message}))?;
                }
            }
        }
        Ok(())
    };
    if options.hex.is_empty() || options.hex == ["-"] {
        let mut reader = io::stdin().lock();
        let mut line = Vec::new();
        for input in 1.. {
            if !hex::read_line(&mut reader, &mut line)? {
                break;
            }
            process(input, hex::parse(&line))?;
        }
    } else {
        if options.hex.iter().any(|s| s == "-") {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "use '-' alone to read stdin"));
        }
        let len = options.hex.iter().map(String::len).sum::<usize>().saturating_add(options.hex.len() - 1);
        let parsed = if len > hex::LIMIT { Err("hex input exceeds 64 KiB".into()) } else { hex::parse(options.hex.join(" ").as_bytes()) };
        process(1, parsed)?;
    }
    out.flush()?;
    Ok(success)
}
fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            if error.use_stderr() {
                // Clap includes offending arguments in diagnostics. Keep untrusted
                // line breaks or bidi controls out of otherwise multiline help.
                if std::env::args_os().any(|a| a.to_string_lossy().contains(out::unsafe_character)) {
                    let _ = writeln!(io::stderr().lock(), "iec60870: invalid argument containing a control character (see --help)");
                } else {
                    let _ = error.print();
                }
                return ExitCode::from(2);
            }
            let _ = error.print();
            return ExitCode::SUCCESS;
        }
    };
    match run(&cli, &mut io::stdout().lock()) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(e) => {
            let _ = writeln!(io::stderr().lock(), "iec60870: {}", out::clean(&e.to_string()));
            ExitCode::from(client::exit_code(&e).unwrap_or(if e.kind() == io::ErrorKind::InvalidInput { 2 } else { 1 }))
        }
    }
}
