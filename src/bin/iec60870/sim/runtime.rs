//! Serve the validated process image using the library's controlled station.
use super::{CommandKind as ConfigCommand, Config, Kind, Mode, Options, Time, Walk, invalid, number};
use iec60870::{Server, prelude::*};
use serde_json::{Value as Json, json};
use std::{
    collections::BTreeMap,
    io::{self, Write},
    net::SocketAddr,
    time::{Duration, Instant},
};

fn numeric(kind: Kind, n: f64) -> Option<Value> {
    Some(match kind {
        Kind::Step => StepPosition::new(n as i8).into(),
        Kind::Normalized => MeasuredNormalized::new(Normalized::from_f32(n as f32)).into(),
        Kind::Scaled => (n as i16).into(),
        Kind::Float => (n as f32).into(),
        Kind::Counter => BinaryCounterReading::new(n as i32).into(),
        _ => return None,
    })
}
pub(super) fn initial(kind: Kind, v: &toml::Value) -> io::Result<Value> {
    let value = match kind {
        Kind::Single => v.as_bool().map(Value::from),
        Kind::Double => v.as_str().and_then(|s| {
            Some(
                match s {
                    "on" => DoublePointValue::On,
                    "off" => DoublePointValue::Off,
                    "intermediate" => DoublePointValue::Intermediate,
                    "indeterminate" => DoublePointValue::Indeterminate,
                    _ => return None,
                }
                .into(),
            )
        }),
        Kind::Bitstring => v.as_integer().and_then(|n| u32::try_from(n).ok()).map(|n| Bitstring32::new(n).into()),
        _ => number(v).and_then(|n| numeric(kind, n)),
    };
    value.ok_or_else(|| invalid(kind.value_hint()))
}
impl From<ConfigCommand> for CommandKind {
    fn from(k: ConfigCommand) -> Self {
        match k {
            ConfigCommand::Single => Self::Single,
            ConfigCommand::Double => Self::Double,
            ConfigCommand::Step => Self::Step,
            ConfigCommand::Normalized => Self::Normalized,
            ConfigCommand::Scaled => Self::Scaled,
            ConfigCommand::Setpoint => Self::Float,
            ConfigCommand::Bits => Self::Bitstring,
        }
    }
}

type Address = (CommonAddress, Ioa);
struct Motion {
    address: Address,
    kind: Kind,
    value: f64,
    walk: Walk,
    every: Duration,
    next: Duration,
    rng: u64,
}
impl Motion {
    fn advance(&mut self) -> io::Result<Value> {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        let delta = if self.rng & 1 == 0 { -self.walk.step } else { self.walk.step };
        self.value = (self.value + delta).clamp(self.walk.min, self.walk.max);
        numeric(self.kind, self.value).ok_or_else(|| invalid("unsupported walk kind"))
    }
}
struct Policy {
    accept: bool,
    status: Option<Ioa>,
    limits: Option<[i8; 2]>,
}
struct Handler {
    policies: BTreeMap<Address, Policy>,
}
impl Handler {
    fn decision(&self, r: &CommandRequest) -> Decision {
        Decision::from(
            self.policies.get(&(r.common_address, r.ioa)).is_some_and(|p| p.accept) && !matches!(r.command,Command::Step(v) if v.direction().is_none()),
        )
    }
}
impl CommandHandler for Handler {
    fn select(&mut self, r: &CommandRequest) -> Decision {
        self.decision(r)
    }
    fn execute(&mut self, r: &CommandRequest) -> Decision {
        self.decision(r)
    }
    fn feedback(&mut self, r: &CommandRequest, db: &dyn PointSource) -> Option<(Ioa, Value)> {
        let p = self.policies.get(&(r.common_address, r.ioa))?;
        let ioa = p.status?;
        let value = feedback_value(r.command, db.value(r.common_address, ioa), p.limits)?;
        Some((ioa, value))
    }
}
pub(super) fn feedback_value(command: Command, old: Option<Value>, limits: Option<[i8; 2]>) -> Option<Value> {
    Some(match command {
        Command::Single(v) => v.state().into(),
        Command::Double(v) => v.state().into(),
        Command::Normalized(v) => MeasuredNormalized::new(v.value).into(),
        Command::Scaled(v) => v.value.into(),
        Command::Float(v) => v.value.into(),
        Command::Bitstring(v) => Bitstring32::new(v.0).into(),
        Command::Step(v) => {
            let Value::Step(old) = old? else { return None };
            let delta = match v.direction()? {
                StepDirection::Lower => -1,
                StepDirection::Higher => 1,
            };
            let [lo, hi] = limits.unwrap_or([-64, 63]);
            StepPosition::new(old.value.saturating_add(delta).clamp(lo, hi)).into()
        }
    })
}
fn peer_text(peer: Option<SocketAddr>) -> String {
    peer.map_or_else(|| "unknown".into(), |a| a.to_string())
}
fn log(out: &mut impl Write, json_output: bool, record: &Json, text: std::fmt::Arguments<'_>) -> io::Result<()> {
    if json_output { writeln!(out, "{record}") } else { writeln!(out, "{text}") }
}
fn event(out: &mut impl Write, e: &ServerEvent, peer: Option<SocketAddr>, json_output: bool) -> io::Result<()> {
    let (id, state) = match e {
        ServerEvent::CommandDecision { request: r, cancellation, decision } => {
            let phase = if *cancellation {
                "cancel"
            } else if r.phase == Phase::Select {
                "select"
            } else {
                "execute"
            };
            let decision = if *decision == Decision::Accept { "accepted" } else { "refused" };
            let record = json!({"kind":"command","conn":r.connection.0,"peer":peer,"ca":r.common_address.0,"ioa":r.ioa.0,"phase":phase,"command":r.command.to_string(),"decision":decision});
            return log(
                out,
                json_output,
                &record,
                format_args!("{phase} {} at CA {} IOA {} from {} {decision}", r.command, r.common_address, r.ioa, peer_text(peer)),
            );
        }
        ServerEvent::Started(id) => (id, "started"),
        ServerEvent::Stopped(id) => (id, "stopped"),
        ServerEvent::Disconnected { connection, .. } => (connection, "closed"),
        ServerEvent::ClockSynchronized { connection, time } => {
            return log(
                out,
                json_output,
                &json!({"kind":"clock","conn":connection.0,"peer":peer,"time":time.to_string()}),
                format_args!("clock set to {time} by {}", peer_text(peer)),
            );
        }
        ServerEvent::ObserverLagged { count } => {
            return log(out, json_output, &json!({"kind":"log_gap","count":count}), format_args!("log missed {count} station events"));
        }
        ServerEvent::EventsLost { group, count } => {
            return log(out, json_output, &json!({"kind":"events_lost","group":group.0,"count":count}), format_args!("group {} lost {count} events", group.0));
        }
        _ => return Ok(()),
    };
    log(out, json_output, &json!({"kind":"connection","conn":id.0,"peer":peer,"state":state}), format_args!("connection {id} from {} {state}", peer_text(peer)))
}
pub(super) fn serve(o: &Options, config: Config, points: usize, commands: usize, json_output: bool, out: &mut impl Write) -> io::Result<bool> {
    let mut db = Database::new();
    let mut motions = Vec::new();
    let mut policies = BTreeMap::new();
    for s in config.station {
        let ca = CommonAddress(s.ca.into_inner());
        for p in s.point {
            let ioa = Ioa(p.ioa.into_inner());
            let value = initial(p.kind, p.value.get_ref())?;
            let format = if matches!(p.time, Some(Time::None)) { TimeFormat::None } else { TimeFormat::Cp56 };
            let opts = db.insert(ca, ioa, value).time_format(format);
            if let Some(group) = p.group {
                if matches!(p.kind, Kind::Counter) {
                    let _ = opts.counter_group(group.into_inner());
                } else {
                    let _ = opts.group(group.into_inner());
                }
            }
            if let Some(w) = p.walk {
                let walk = w.into_inner();
                let every = crate::duration(&walk.every).ok_or_else(|| invalid("invalid walk period"))?;
                let rng = o.seed.unwrap_or(1) ^ ((u64::from(ca.0) << 32) | u64::from(ioa.0));
                motions.push(Motion {
                    address: (ca, ioa),
                    kind: p.kind,
                    value: number(p.value.get_ref()).ok_or_else(|| invalid("invalid walk value"))?,
                    walk,
                    every,
                    next: every,
                    rng: if rng == 0 { 0x9e37_79b9_7f4a_7c15 } else { rng },
                });
            }
        }
        for c in s.command {
            let mode = c.effective_mode();
            let ioa = Ioa(c.ioa.into_inner());
            let opts = db.command(ca, ioa, c.kind.into());
            let _ = opts.mode(match mode {
                Mode::Sbo => CommandMode::SelectBeforeOperate,
                Mode::Direct => CommandMode::Direct,
                Mode::Both => CommandMode::DirectOrSelect,
            });
            policies.insert(
                (ca, ioa),
                Policy { accept: c.accept.unwrap_or(true), status: c.status.map(|s| Ioa(s.into_inner())), limits: c.step_range.map(toml::Spanned::into_inner) },
            );
        }
    }
    let bind = o.bind;
    let server =
        Server::bind(bind, db).map_err(|e| io::Error::other(format!("cannot bind {bind}: {e}. Choose another local address or use --bind 127.0.0.1:0")))?;
    let addr = server.local_addr()?;
    let handler = Handler { policies };
    let handle = server.spawn(handler)?;
    let local = addr.ip().is_loopback();
    let notice = if local { "loopback only" } else { "network listener: reachable peers can operate simulated points" };
    if json_output {
        writeln!(out, "{}", json!({"kind":"listening","addr":addr,"points":points,"commands":commands,"loopback":local,"notice":notice}))?;
    } else {
        writeln!(out, "listening on {addr} ({notice}), {points} monitored points, {commands} command points")?;
    }
    out.flush()?;
    let origin = Instant::now();
    loop {
        let now = origin.elapsed();
        let mut wait = Duration::from_secs(60);
        for motion in &mut motions {
            if motion.next <= now {
                let value = motion.advance()?;
                handle.update(motion.address.0, motion.address.1, value).map_err(io::Error::other)?;
                motion.next = now.saturating_add(motion.every);
            }
            wait = wait.min(motion.next.saturating_sub(now));
        }
        if let Some((e, peer)) = handle.next_event_with_peer(wait) {
            event(out, &e, peer, json_output)?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeded_walk_repeats_its_sequence_and_respects_limits() -> io::Result<()> {
        let run = |rng| -> io::Result<Vec<Value>> {
            let every = Duration::from_secs(1);
            let mut m = Motion {
                address: (CommonAddress(1), Ioa(9)),
                kind: Kind::Scaled,
                value: 0.,
                walk: Walk { min: -5., max: 5., step: 1., every: "1s".into() },
                every,
                next: every,
                rng,
            };
            (0..64).map(|_| m.advance()).collect()
        };
        let values = run(42)?;
        assert_eq!(values, run(42)?);
        assert_ne!(values, run(43)?);
        assert!(values.iter().all(|v| matches!(v,Value::Scaled(s) if (-5..=5).contains(&s.value))));
        Ok(())
    }
}
