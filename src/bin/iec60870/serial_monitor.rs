//! Receive-only FT 1.2 monitoring.
use super::{Decode, ProfileArgs, decode};
use clap::{Args, ValueEnum};
use iec60870::cs101::FrameSplitter;
use std::io::{self, Read, Write};
use std::time::Instant;

#[derive(Clone, Copy, ValueEnum)]
enum Parity {
    Even,
    Odd,
    None,
}

#[derive(Args)]
pub struct Options {
    /// Serial tap device, or - for raw FT 1.2 octets on stdin.
    device: String,
    /// Serial baud rate (default 9600). Use 0 for macOS pseudo-terminals.
    #[arg(long)]
    baud: Option<u32>,
    /// Serial parity (default even).
    #[arg(long)]
    parity: Option<Parity>,
    /// Link address width in octets.
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u8).range(0..=2))]
    link_addr: u8,
    /// Cause width in octets.
    #[arg(long, value_parser = clap::value_parser!(u8).range(1..=2))]
    cot: Option<u8>,
    /// Common address width in octets.
    #[arg(long, value_parser = clap::value_parser!(u8).range(1..=2))]
    ca: Option<u8>,
    /// Information object address width in octets.
    #[arg(long, value_parser = clap::value_parser!(u8).range(1..=3))]
    ioa: Option<u8>,
    /// Treat valid full station timestamps as UTC in JSON.
    #[arg(long)]
    utc: bool,
}
pub fn run(o: &Options, json: bool, color: bool, out: &mut impl Write) -> io::Result<bool> {
    let decoder = Decode {
        hex: Vec::new(),
        asdu: false,
        explain: false,
        utc: o.utc,
        link_addr: o.link_addr,
        profile: ProfileArgs { profile: "101".into(), cot: o.cot, ca: o.ca, ioa: o.ioa },
    };
    if o.device == "-" {
        if o.baud.is_some() || o.parity.is_some() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "--baud and --parity require a serial device"));
        }
        return receive(&mut io::stdin().lock(), true, &decoder, json, color, out);
    }
    #[cfg(feature = "serial")]
    {
        if o.baud == Some(0) && !cfg!(target_os = "macos") {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "zero baud is only supported for macOS pseudo-terminals"));
        }
        let parity = match o.parity.unwrap_or(Parity::Even) {
            Parity::Even => serialport::Parity::Even,
            Parity::Odd => serialport::Parity::Odd,
            Parity::None => serialport::Parity::None,
        };
        let mut port = serialport::new(&o.device, o.baud.unwrap_or(9600))
            .preserve_dtr_on_open()
            .parity(parity)
            .data_bits(serialport::DataBits::Eight)
            .stop_bits(serialport::StopBits::One)
            .flow_control(serialport::FlowControl::None)
            .timeout(std::time::Duration::from_millis(250))
            .open()
            .map_err(|e| io::Error::other(format!("cannot open {}: {e}", o.device)))?;
        receive(&mut port, false, &decoder, json, color, out)
    }
    #[cfg(not(feature = "serial"))]
    Err(io::Error::new(io::ErrorKind::InvalidInput, "install with --features cli,serial for a serial device"))
}

fn receive(input: &mut impl Read, pipe: bool, decoder: &Decode, json: bool, color: bool, out: &mut impl Write) -> io::Result<bool> {
    let mut splitter = FrameSplitter::new(decoder.widths().1);
    let start = Instant::now();
    let mut buf = [0; 1024];
    let mut index = 0usize;
    let mut success = true;
    loop {
        let count = match input.read(&mut buf) {
            Err(e) if matches!(e.kind(), io::ErrorKind::Interrupted | io::ErrorKind::TimedOut) => continue,
            Err(e) => return Err(io::Error::other(format!("serial monitor read failed: {e}"))),
            Ok(n) => n,
        };
        if count == 0 {
            if splitter.buffered() != 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "incomplete FT 1.2 frame at end of input"));
            }
            if !pipe {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "serial device disconnected"));
            }
            return Ok(success);
        }
        let mut bytes = buf.get(..count).ok_or_else(|| io::Error::other("invalid serial read length"))?;
        let now = iec60870::time::Instant::ZERO + start.elapsed();
        while let Some(frame) = splitter.next_frame(&mut bytes, now) {
            index = index.saturating_add(1);
            let result = match frame {
                Err(e) => Err(decode::Failure::Input(e.to_string())),
                Ok(_) => decode::frames(decoder, splitter.frame_bytes(), |r, raw| r.write(index, raw, false, json, color, out)),
            };
            match result {
                Ok(()) => (),
                Err(failure) => {
                    success = false;
                    let message = match failure {
                        decode::Failure::Input(m) => m,
                        decode::Failure::Asdu(e, _) => e.to_string(),
                        decode::Failure::Output(e) => return Err(e),
                    };
                    writeln!(io::stderr().lock(), "iec60870: serial frame {index}: {message}")?;
                    if json {
                        writeln!(out, "{}", serde_json::json!({"kind":"error","input":index,"error":message}))?;
                    }
                }
            }
            out.flush()?;
        }
    }
}
