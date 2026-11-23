//! The `controlled_station` harness, shared by the fuzz target and `tests/regressions_station.rs`.
//!
//! A controlled station with a populated database runs behind a 104 link; the input is a
//! script: each step's first octet picks an action — an ASDU from a master (through a real
//! master link, so it is numbered and acknowledged), raw octets straight into the station's
//! link, time passing, an update, a new connection — and the rest of the step is its argument.
//! Nothing may panic, and the station's buffers stay within their bounds.

#![allow(dead_code)]

use core::time::Duration;

use iec60870::cs104::Cs104Link;
use iec60870::driver::Output;
use iec60870::prelude::*;
use iec60870::station::{self, CommandHandler, ConnectionId, ControlledStation, GroupId, ServerConfig};

struct Yes;

impl CommandHandler for Yes {
    fn execute(&mut self, _: &CommandRequest) -> Decision {
        Decision::Accept
    }
}

fn clock() -> Cp56Time2a {
    Cp56Time2a::from_unix_millis(1_795_000_000_000).unwrap_or_default()
}

const CAPACITY: usize = 32;

pub fn station(data: &[u8]) {
    let ca = CommonAddress(1);
    let mut db = Database::new();
    let _ = db.insert(ca, Ioa(1), false).group(1);
    let _ = db.insert(ca, Ioa(2), DoublePointValue::On);
    let _ = db.insert(ca, Ioa(3), 1.5f32).cyclic(true);
    let _ = db.insert(ca, Ioa(4), 7i16).background(true);
    let _ = db.insert(ca, Ioa(5), BinaryCounterReading::new(9)).counter_group(1);
    let _ = db.insert(CommonAddress(2), Ioa(1), true);
    let _ = db.command(ca, Ioa(10), CommandKind::Single);
    let _ = db.command(ca, Ioa(11), CommandKind::Double).mode(CommandMode::Direct);
    let _ = db.command(ca, Ioa(12), CommandKind::Float).mode(CommandMode::DirectOrSelect);
    let _ = db.command(ca, Ioa(13), CommandKind::Bitstring);
    let config = ServerConfig {
        event_capacity: CAPACITY,
        cyclic_period: Duration::from_secs(2),
        background_period: Some(Duration::from_secs(5)),
        select_timeout: Duration::from_secs(1),
        ..ServerConfig::default()
    };
    let mut st: ControlledStation<Cs104Link> = ControlledStation::new(db, config, clock);
    let mut now = Instant::ZERO;
    let mut handler = Yes;
    let (mut id, mut master) = attach(&mut st, now);
    let mut rest = data;
    while let Some((&op, tail)) = rest.split_first() {
        let len = usize::from(tail.first().copied().unwrap_or(0) % 64);
        let arg = tail.get(1..).unwrap_or_default();
        let (arg, next) = arg.split_at(len.min(arg.len()));
        rest = next;
        match op % 6 {
            0 | 1 => {
                if !arg.is_empty() {
                    let _ = master.submit(arg, now);
                }
            }
            2 => st.handle_input(id, arg, now, &mut handler),
            3 => {
                now += Duration::from_millis(u64::from(arg.first().copied().unwrap_or(1)) * 50);
                master.handle_timeout(now);
                st.handle_timeout(now);
            }
            4 => {
                let ioa = Ioa(u32::from(arg.first().copied().unwrap_or(0) % 7));
                let _ = match arg.get(1).copied().unwrap_or(0) % 3 {
                    0 => st.update(ca, ioa, arg.len() % 2 == 0),
                    1 => st.update(ca, ioa, f32::from(arg.len() as u8)),
                    _ => st.update(ca, ioa, BinaryCounterReading::new(i32::from(op))),
                };
                st.handle_timeout(now);
            }
            _ => {
                if master.is_closed() || arg.first().is_some_and(|b| b & 1 == 1) {
                    st.handle_disconnect(id, now);
                    (id, master) = attach(&mut st, now);
                }
            }
        }
        pump(&mut st, id, &mut master, now, &mut handler);
        assert!(st.pending_events(GroupId(0)) <= CAPACITY, "the event buffer is bounded");
    }
}

fn attach(st: &mut ControlledStation<Cs104Link>, now: Instant) -> (ConnectionId, Cs104Link) {
    let id = st.attach(Cs104Link::controlled(), GroupId(0));
    let mut master = Cs104Link::controlling();
    let _ = master.start(now);
    (id, master)
}

fn pump(st: &mut ControlledStation<Cs104Link>, id: ConnectionId, master: &mut Cs104Link, now: Instant, handler: &mut Yes) {
    for _ in 0..256 {
        let mut moved = false;
        while let Some(o) = master.poll_output() {
            if let Output::Transmit(b) = o {
                moved = true;
                st.handle_input(id, &b, now, handler);
            }
        }
        while let Some(o) = st.poll_output() {
            if let station::Output::Transmit { connection, bytes } = o
                && connection == id
            {
                moved = true;
                master.handle_input(&bytes, now);
            }
        }
        if !moved {
            return;
        }
    }
}
