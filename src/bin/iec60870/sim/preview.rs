//! Evaluate one configured simulator policy against its initial image.
use super::{Config, Mode, Options, runtime};
use iec60870::prelude::*;
use serde_json::json;
use std::io::{self, Write};

fn input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn parse(kind: &str, value: &str) -> io::Result<Command> {
    match kind {
        "single" | "double" => {
            let on = match value {
                "on" => true,
                "off" => false,
                _ => return Err(input("single and double values must be on or off")),
            };
            Ok(if kind == "single" { Command::single(on) } else { Command::double(if on { DoublePointValue::On } else { DoublePointValue::Off }) })
        }
        "step" => match value {
            "up" => Ok(Command::step(StepDirection::Higher)),
            "down" => Ok(Command::step(StepDirection::Lower)),
            _ => Err(input("step value must be up or down")),
        },
        "scaled" => value.parse().map(Command::setpoint_scaled).map_err(|_| input("scaled value must be an integer in -32768..32767")),
        "setpoint" => {
            value.parse::<f32>().ok().filter(|v| v.is_finite()).map(Command::setpoint_float).ok_or_else(|| input("setpoint value must be a finite f32"))
        }
        "normalized" => value
            .parse::<f64>()
            .ok()
            .filter(|v| (-1.0..=1.0).contains(v))
            .map(|v| Command::setpoint_normalized(Normalized::from_f32(v as f32)))
            .ok_or_else(|| input("normalized value must be in -1..1")),
        "bits" => {
            let (digits, radix) = value.strip_prefix("0x").map_or((value, 10), |hex| (hex, 16));
            let parsed = digits.as_bytes().first().is_some_and(u8::is_ascii_hexdigit).then(|| u32::from_str_radix(digits, radix).ok()).flatten();
            parsed.map(Command::bitstring).ok_or_else(|| input("bits value must be an unsigned 32-bit decimal or 0x hexadecimal integer"))
        }
        _ => Err(input("command kind must be single, double, step, scaled, setpoint, normalized or bits")),
    }
}

pub(super) fn run(o: &Options, args: &[String], config: &Config, json_output: bool, out: &mut impl Write) -> io::Result<bool> {
    let [address, kind, value] = args else { return Err(input("--preview requires IOA KIND VALUE")) };
    let ioa = address.parse::<u32>().ok().filter(|a| *a <= 0xff_ffff).ok_or_else(|| input("preview IOA must be in 0..16777215"))?;
    let command = parse(kind, value)?;
    let ca = o.ca.unwrap_or(1);
    let station = config.station.iter().find(|s| *s.ca.get_ref() == ca);
    let policy = station.and_then(|s| s.command.iter().find(|c| *c.ioa.get_ref() == ioa));
    let direct = o.direct || matches!(command, Command::Bitstring(_));
    let mode = if direct { "direct" } else { "sbo" };
    let reason = match policy {
        None if station.is_none() => Some("unknown station"),
        None => Some("unknown command point"),
        Some(c) if command.kind() != c.kind.into() => Some("command kind mismatch"),
        Some(c) if matches!((direct, c.effective_mode()), (true, Mode::Sbo) | (false, Mode::Direct)) => Some("mode refused"),
        Some(c) if !c.accept.unwrap_or(true) => Some("policy refused"),
        _ => None,
    };
    let mut feedback = None;
    if reason.is_none()
        && let (Some(s), Some(c)) = (station, policy)
        && let Some(status) = &c.status
        && let Some(p) = s.point.iter().find(|p| p.ioa.get_ref() == status.get_ref())
    {
        let before = runtime::initial(p.kind, p.value.get_ref())?;
        if let Some(after) = runtime::feedback_value(command, Some(before), c.step_range.as_ref().map(|r| *r.get_ref())) {
            feedback = Some((*status.get_ref(), before, after));
        }
    }
    let decision = if reason.is_none() { "accepted" } else { "refused" };
    if json_output {
        let status =
            feedback.map(|(ioa, before, after)| json!({"ioa":ioa,"before":crate::render::value_json(before),"after":crate::render::value_json(after)}));
        writeln!(
            out,
            "{}",
            json!({"kind":"command_preview","ca":ca,"ioa":ioa,"command_kind":kind,"command":command.to_string(),"mode":mode,"decision":decision,"reason":reason,"feedback":status})
        )?;
    } else {
        write!(out, "Preview CA {ca} IOA {ioa} {command} ({mode}): {decision}")?;
        if let Some(why) = reason {
            write!(out, " ({why})")?;
        }
        if let Some((status, before, after)) = feedback {
            write!(out, ", status IOA {status}: {before} → {after}")?;
        }
        writeln!(out)?;
    }
    Ok(true)
}
