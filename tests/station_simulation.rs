//! Deterministic simulation of the controlled station's event delivery, on virtual time.
//!
//! Two scenarios, `SIM_SEEDS` seeds each (default 1000):
//!
//! - **reconnect**: updates arrive at random while one master connects, starts, is cut off
//!   abruptly (octets in flight lost) or stops cleanly (STOPDT, then close), and reconnects;
//! - **switch-over**: two connections of one redundancy group, and the master starts the other
//!   one at random moments with events in flight.
//!
//! The properties, per seed: every event generated is delivered or counted in an
//! `EventsLost` report (`delivered distinct + lost >= generated`, with equality when no
//! connection was cut); per point, the
//! first deliveries are in update order; an event is delivered twice only if its first copy
//! arrived on a connection that ended without a clean stop (a cut, or the close of a
//! switch-over) — with clean stops only, delivery is exactly once.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic, clippy::cast_possible_truncation)]
#![allow(clippy::assert_is_empty, clippy::too_many_lines, clippy::doc_markdown, clippy::cast_lossless, clippy::cast_precision_loss, clippy::similar_names)]

use std::collections::{BTreeMap, VecDeque};
use std::time::Duration;

use iec60870::cs104::{self, Cs104Link};
use iec60870::driver::Output;
use iec60870::prelude::*;
use iec60870::station::{self, ConnectionId, ControlledStation, GroupId, ServerConfig, ServerEvent};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.below(1000) < percent * 10
    }
    fn chance_permille(&mut self, permille: u64) -> bool {
        self.below(1000) < permille
    }
}

fn clock() -> Cp56Time2a {
    Cp56Time2a::from_unix_millis(1_795_000_000_000).unwrap()
}

#[derive(PartialEq)]
enum Phase {
    Connected,
    Stopping,
    Dead,
}

struct Conn {
    id: ConnectionId,
    master: Cs104Link,
    to_station: VecDeque<(Instant, Vec<u8>)>,
    to_master: VecDeque<(Instant, Vec<u8>)>,
    phase: Phase,
    started: bool,
    clean: bool,
}

#[derive(Default, Debug)]
struct Stats {
    generated: u64,
    delivered: u64,
    duplicates: u64,
    lost: u64,
    cuts: u64,
    clean_stops: u64,
    switch_overs: u64,
}

struct Sim {
    rng: Rng,
    now: Instant,
    station: ControlledStation<Cs104Link>,
    conns: Vec<Conn>,
    /// (ioa, value) → the connection index of the first delivery.
    first: BTreeMap<(u32, i16), usize>,
    order: BTreeMap<u32, Vec<i16>>,
    dups: Vec<((u32, i16), usize)>,
    next_value: BTreeMap<u32, i16>,
    stats: Stats,
}

const POINTS: [u32; 3] = [10, 11, 12];

impl Sim {
    fn new(seed: u64, capacity: usize) -> Sim {
        let mut db = BTreeMap::new();
        for ioa in POINTS {
            db.insert((CommonAddress(1), Ioa(ioa)), PointEntry::new(0i16));
        }
        let config = ServerConfig { event_capacity: capacity, end_of_initialization: None, ..ServerConfig::default() };
        Sim {
            rng: Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1),
            now: Instant::ZERO,
            station: ControlledStation::new(db, config, clock),
            conns: Vec::new(),
            first: BTreeMap::new(),
            order: BTreeMap::new(),
            dups: Vec::new(),
            next_value: BTreeMap::new(),
            stats: Stats::default(),
        }
    }

    fn connect(&mut self) -> usize {
        let id = self.station.attach(Cs104Link::controlled(), GroupId(0));
        self.conns.push(Conn {
            id,
            master: Cs104Link::controlling(),
            to_station: VecDeque::new(),
            to_master: VecDeque::new(),
            phase: Phase::Connected,
            started: false,
            clean: false,
        });
        self.conns.len() - 1
    }

    fn alive(&self) -> Vec<usize> {
        (0..self.conns.len()).filter(|&i| self.conns[i].phase != Phase::Dead).collect()
    }

    fn update(&mut self) {
        let ioa = POINTS[self.rng.below(3) as usize];
        let v = self.next_value.entry(ioa).or_insert(0);
        *v += 1;
        let value = *v;
        self.station.update(CommonAddress(1), Ioa(ioa), value).unwrap();
        self.stats.generated += 1;
    }

    /// The TCP connection ends: in-flight octets are lost, both sides are told.
    fn cut(&mut self, i: usize, clean: bool) {
        let c = &mut self.conns[i];
        if c.phase == Phase::Dead {
            return;
        }
        c.phase = Phase::Dead;
        c.clean = clean;
        c.to_station.clear();
        c.to_master.clear();
        c.master.handle_disconnect(self.now);
        let id = c.id;
        self.station.handle_disconnect(id, self.now);
        if clean {
            self.stats.clean_stops += 1;
        } else {
            self.stats.cuts += 1;
        }
    }

    fn delay(&mut self) -> Duration {
        Duration::from_millis(1 + self.rng.below(300))
    }

    /// Moves outputs onto the wires and delivers what is due, until quiet.
    fn step(&mut self) {
        for _ in 0..64 {
            let mut moved = false;
            for i in 0..self.conns.len() {
                while let Some(o) = self.conns[i].master.poll_output() {
                    match o {
                        Output::Transmit(b) => {
                            let at = self.now + self.delay();
                            // Random re-chunking.
                            let cut = self.rng.below(b.len() as u64 + 1) as usize;
                            let (x, y) = b.split_at(cut);
                            for part in [x, y] {
                                if !part.is_empty() && self.conns[i].phase != Phase::Dead {
                                    self.conns[i].to_station.push_back((at, part.to_vec()));
                                }
                            }
                        }
                        Output::Event(cs104::Event::Asdu(a)) => {
                            moved = true;
                            self.receive(i, &a);
                        }
                        Output::Event(cs104::Event::Started) => self.conns[i].started = true,
                        Output::Event(cs104::Event::Stopped) => {
                            if self.conns[i].phase == Phase::Stopping {
                                self.cut(i, true);
                            }
                        }
                        Output::Event(cs104::Event::Closed(reason)) => {
                            if std::env::var("SIM_DEBUG").is_ok() {
                                println!("master {i} closed: {reason}");
                            }
                            let clean = self.conns[i].phase == Phase::Dead && self.conns[i].clean;
                            self.cut(i, clean);
                        }
                        _ => {}
                    }
                }
            }
            while let Some(o) = self.station.poll_output() {
                match o {
                    station::Output::Transmit { connection, bytes } => {
                        let at = self.now + self.delay();
                        if let Some(c) = self.conns.iter_mut().find(|c| c.id == connection && c.phase != Phase::Dead) {
                            c.to_master.push_back((at, bytes));
                        }
                    }
                    station::Output::Event(ServerEvent::EventsLost { count, .. }) => self.stats.lost += count as u64,
                    station::Output::Event(ServerEvent::Disconnected { connection, .. }) => {
                        if let Some(i) = self.conns.iter().position(|c| c.id == connection) {
                            self.cut(i, false);
                        }
                    }
                    station::Output::Event(ServerEvent::SwitchedOver { .. }) => self.stats.switch_overs += 1,
                    _ => {}
                }
            }
            for i in 0..self.conns.len() {
                while self.conns[i].to_station.front().is_some_and(|(at, _)| *at <= self.now) {
                    let (_, b) = self.conns[i].to_station.pop_front().unwrap();
                    let id = self.conns[i].id;
                    self.station.handle_input(id, &b, self.now, &mut station::RefuseCommands);
                    moved = true;
                }
                while self.conns[i].to_master.front().is_some_and(|(at, _)| *at <= self.now) {
                    let (_, b) = self.conns[i].to_master.pop_front().unwrap();
                    self.conns[i].master.handle_input(&b, self.now);
                    moved = true;
                }
            }
            if !moved {
                return;
            }
        }
    }

    fn receive(&mut self, conn: usize, bytes: &[u8]) {
        let asdu = Asdu::decode(bytes, &Profile::IEC104).unwrap();
        for p in Point::from_asdu(&asdu).unwrap() {
            let Value::Scaled(v) = p.value else { panic!("{p:?}") };
            let key = (p.ioa.0, v.value);
            if let Some(&first) = self.first.get(&key) {
                self.stats.duplicates += 1;
                self.dups.push((key, first));
            } else {
                self.first.insert(key, conn);
                self.order.entry(p.ioa.0).or_default().push(v.value);
                self.stats.delivered += 1;
            }
        }
    }

    fn advance(&mut self, max_ms: u64) {
        self.now += Duration::from_millis(1 + self.rng.below(max_ms));
        for c in &mut self.conns {
            if c.phase != Phase::Dead {
                c.master.handle_timeout(self.now);
            }
        }
        self.station.handle_timeout(self.now);
        self.step();
    }

    /// Lets everything settle on one clean, started connection, then checks the properties.
    fn finish(mut self, seed: u64) -> Stats {
        for i in self.alive() {
            if !self.conns[i].started {
                self.cut(i, true);
            }
        }
        for _ in 0..400 {
            if self.alive().is_empty() {
                let i = self.connect();
                self.conns[i].master.start(self.now).unwrap();
            }
            self.advance(500);
        }
        let owed = self.station.pending_events(GroupId(0));
        let states: Vec<_> =
            self.conns.iter().map(|c| (c.phase == Phase::Dead, c.started, c.master.state(), self.station.link(c.id).map(Cs104Link::state))).collect();
        assert!(owed == 0, "seed {seed}: {owed} events still owed; connections {states:?}");
        let s = &self.stats;
        // No silent loss: every event not delivered was reported. (A report can also count an
        // event that had been transmitted, unacknowledged, before a cut and was dropped from
        // the head of the buffer while waiting to be re-sent — so `>=`, and `==` without cuts.)
        assert!(s.delivered + s.lost >= s.generated, "seed {seed}: delivered {} + lost {} < generated {}", s.delivered, s.lost, s.generated);
        if s.cuts == 0 && s.switch_overs == 0 {
            assert_eq!(s.delivered + s.lost, s.generated, "seed {seed}: delivered {} + lost {} != generated {}", s.delivered, s.lost, s.generated);
        }
        for (ioa, values) in &self.order {
            assert!(values.windows(2).all(|w| w[0] < w[1]), "seed {seed}: IOA {ioa} out of order: {values:?}");
        }
        for (key, first_conn) in &self.dups {
            assert!(
                !self.conns[*first_conn].clean && self.conns[*first_conn].phase == Phase::Dead,
                "seed {seed}: {key:?} duplicated although its first copy came on a connection that stopped cleanly"
            );
        }
        self.stats
    }
}

fn seeds() -> u64 {
    std::env::var("SIM_SEEDS").ok().and_then(|s| s.parse().ok()).unwrap_or(1000)
}

fn run_reconnect(seed: u64) -> Stats {
    let mut rng = Rng(seed | 1);
    let capacity = [8, 32, 1024][rng.below(3) as usize];
    let mut sim = Sim::new(seed, capacity);
    let clean_only = seed.is_multiple_of(4);
    for _ in 0..600 {
        let alive = sim.alive();
        if alive.is_empty() && sim.rng.chance(20) {
            let i = sim.connect();
            sim.conns[i].master.start(sim.now).unwrap();
        }
        if sim.rng.chance(30) {
            sim.update();
        }
        if let Some(&i) = alive.first()
            && sim.conns[i].started
            && sim.conns[i].phase == Phase::Connected
        {
            if !clean_only && sim.rng.chance_permille(8) {
                sim.cut(i, false);
            } else if sim.rng.chance_permille(8) {
                sim.conns[i].phase = Phase::Stopping;
                sim.conns[i].master.stop(sim.now).unwrap();
            }
        }
        sim.advance(400);
    }
    let stats = sim.finish(seed);
    if clean_only {
        assert_eq!(stats.duplicates, 0, "seed {seed}: clean stops only, yet duplicates: {stats:?}");
    }
    stats
}

fn run_switch_over(seed: u64) -> Stats {
    let mut sim = Sim::new(seed, 1024);
    let a = sim.connect();
    sim.connect();
    sim.conns[a].master.start(sim.now).unwrap();
    for _ in 0..600 {
        if sim.rng.chance(40) {
            sim.update();
        }
        let alive = sim.alive();
        if alive.len() < 2 {
            sim.connect();
        }
        // Start a standby connection with events in flight on the started one.
        if sim.rng.chance(2) {
            let standby: Vec<_> = sim.alive().into_iter().filter(|&i| !sim.conns[i].started).collect();
            if let Some(&i) = standby.first() {
                sim.conns[i].master.start(sim.now).unwrap();
            }
        }
        sim.advance(300);
    }
    sim.finish(seed)
}

fn report(name: &str, all: &[Stats]) {
    let sum = |f: fn(&Stats) -> u64| all.iter().map(f).sum::<u64>();
    println!(
        "{name}: {} seeds, {} events generated, {} delivered, {} lost by overflow (reported), {} duplicates, {} cuts, {} clean stops, {} switch-overs",
        all.len(),
        sum(|s| s.generated),
        sum(|s| s.delivered),
        sum(|s| s.lost),
        sum(|s| s.duplicates),
        sum(|s| s.cuts),
        sum(|s| s.clean_stops),
        sum(|s| s.switch_overs),
    );
}

#[test]
fn reconnect_delivers_every_event_or_reports_it_lost() {
    let all: Vec<Stats> = (1..=seeds()).map(run_reconnect).collect();
    report("reconnect", &all);
    assert!(all.iter().map(|s| s.cuts).sum::<u64>() > 0 && all.iter().map(|s| s.clean_stops).sum::<u64>() > 0);
    assert!(all.iter().map(|s| s.lost).sum::<u64>() > 0, "some seed must overflow");
}

#[test]
fn switch_over_loses_nothing_and_duplicates_only_unacknowledged_events() {
    let all: Vec<Stats> = (1..=seeds()).map(run_switch_over).collect();
    report("switch-over", &all);
    assert!(all.iter().map(|s| s.switch_overs).sum::<u64>() > 0);
    assert_eq!(all.iter().map(|s| s.lost).sum::<u64>(), 0);
}
