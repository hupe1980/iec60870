//! Deterministic simulation of the 101 link over a lossy, corrupting serial line, on virtual
//! time, under many seeds, in both modes:
//!
//! - unbalanced: one primary and two secondaries on a shared (multi-drop) half-duplex line;
//! - balanced: two ends on a full-duplex point-to-point line.
//!
//! Every end submits uniquely numbered ASDUs at random times. The line drops frames, flips one
//! bit in a frame, truncates frames, glues garbage to the front of a frame, injects bursts of
//! garbage on the idle line, and splits frames into pieces. A fault-free tail follows.
//!
//! The property, for every submitted ASDU: it is delivered at most once; if its sender saw
//! `Acknowledged` it was delivered exactly once; and by the end its sender saw `Acknowledged`
//! or `Unconfirmed`. The ordering of `Acknowledged`/`Unconfirmed` per (station, class) is FIFO.
//!
//! Timing model: a 115 200 bit/s UART (characters are instantaneous on the millisecond
//! scale), a frame arrives in up to three pieces within 2 ms, and a sender keeps the line idle
//! (one shared bus in unbalanced mode) for at least 6 ms between two frames — the FT 1.2 line-idle rule — so the inter-character
//! timeout (5 ms) tells frames apart. Garbage never contains a start character: noise that
//! forms `0x10`/`0x68` followed by a frame with a matching 8-bit sum is the residual risk FT 1.2
//! leaves to the UART's parity and its idle detection, not to the link.
//!
//! `SIM_SEEDS=n` sets the number of seeds (default 1000); `SIM_SEED=s` runs one seed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::needless_pass_by_value,
    clippy::range_plus_one,
    clippy::manual_assert
)]

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::time::Duration;

use iec60870::cs101::{Class, Config, Cs101Link, Event, LinkAddress, Role, SubmitError};
use iec60870::driver::Output;
use iec60870::time::Instant;

/// xorshift64*.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    fn chance(&mut self, per_mille: u64) -> bool {
        self.below(1000) < per_mille
    }
    fn garbage(&mut self) -> u8 {
        loop {
            let b = self.next() as u8;
            if ![0x10, 0x68, 0xE5].contains(&b) {
                return b;
            }
        }
    }
}

fn config() -> Config {
    Config {
        response_timeout: Duration::from_millis(60),
        retries: 3,
        poll_interval: Duration::from_millis(20),
        reset_interval: Duration::from_millis(300),
        test_interval: Duration::from_millis(400),
        char_timeout: Duration::from_millis(5),
        idle_gap: Duration::from_millis(2),
        queue_len: 8,
        ..Config::default()
    }
}

#[derive(Clone, Copy)]
struct Faults {
    drop: u64,
    flip: u64,
    truncate: u64,
    glue: u64,
    noise: u64,
}

const FAULTS: Faults = Faults { drop: 40, flip: 40, truncate: 20, glue: 20, noise: 30 };
const CLEAN: Faults = Faults { drop: 0, flip: 0, truncate: 0, glue: 0, noise: 0 };

#[derive(Default, Clone)]
struct Fate {
    broadcast: bool,
    delivered: u32,
    acked: bool,
    unconfirmed: bool,
}

struct Pending {
    at: u64,
    station: LinkAddress,
    class: Class,
    asdu: Vec<u8>,
}

struct Node {
    link: Cs101Link,
    deadline: Option<u64>,
    /// The wire this node transmits on (a shared bus, or its own direction of a duplex line).
    wire: usize,
    /// Who hears this node's frames.
    hears: Vec<usize>,
    /// ASDUs to submit, by time.
    pending: VecDeque<Pending>,
    /// Submitted, unresolved ids per (station, class), oldest first.
    fifo: HashMap<(LinkAddress, Class), VecDeque<u32>>,
}

struct Sim {
    rng: Rng,
    now: u64,
    nodes: Vec<Node>,
    /// When each wire is free again (line idle included).
    wire_free: Vec<u64>,
    /// (time, order) → (receiver, octets).
    line: BTreeMap<(u64, u64), (usize, Vec<u8>)>,
    order: u64,
    fates: HashMap<u32, Fate>,
    faults: Faults,
    log: Vec<String>,
}

fn id_of(asdu: &[u8]) -> u32 {
    u32::from_le_bytes([asdu[0], asdu[1], asdu[2], asdu[3]])
}

impl Sim {
    fn deliver(&mut self, at: u64, to: usize, bytes: Vec<u8>) {
        self.order += 1;
        self.line.insert((at, self.order), (to, bytes));
    }

    /// Puts one frame from `from` on the line, with faults per receiver.
    fn send(&mut self, from: usize, frame: Vec<u8>) {
        self.log.push(format!("{} node {from} tx {frame:02x?}", self.now));
        let wire = self.nodes[from].wire;
        let start = self.wire_free[wire].max(self.now) + 1;
        self.wire_free[wire] = start + 2 + 6;
        let hears = self.nodes[from].hears.clone();
        let f = self.faults;
        for to in hears {
            let mut bytes = frame.clone();
            if self.rng.chance(f.drop) {
                continue;
            }
            if self.rng.chance(f.flip) {
                let i = self.rng.below(bytes.len() as u64) as usize;
                bytes[i] ^= 1 << self.rng.below(8);
            }
            if self.rng.chance(f.truncate) && bytes.len() > 1 {
                bytes.truncate(1 + self.rng.below(bytes.len() as u64 - 1) as usize);
            }
            if self.rng.chance(f.glue) {
                let mut glued: Vec<u8> = (0..1 + self.rng.below(3)).map(|_| self.rng.garbage()).collect();
                glued.extend(bytes);
                bytes = glued;
            }
            // Up to three pieces within 2 ms.
            let pieces = 1 + self.rng.below(3.min(bytes.len() as u64)) as usize;
            let mut cuts: Vec<usize> = (1..pieces).map(|_| 1 + self.rng.below(bytes.len() as u64 - 1) as usize).collect();
            cuts.sort_unstable();
            cuts.dedup();
            let mut last = 0;
            for (k, cut) in cuts.into_iter().chain([bytes.len()]).enumerate() {
                self.deliver(start + k as u64, to, bytes[last..cut].to_vec());
                last = cut;
            }
        }
    }

    fn drain(&mut self, i: usize) {
        while let Some(output) = self.nodes[i].link.poll_output() {
            match output {
                Output::Transmit(frame) => self.send(i, frame),
                Output::Deadline(at) => self.nodes[i].deadline = Some(at.as_nanos() / 1_000_000 + u64::from(at.as_nanos() % 1_000_000 != 0)),
                Output::Event(event) => self.event(i, event),
            }
        }
    }

    fn event(&mut self, i: usize, event: Event) {
        self.log.push(format!("{} node {i}: {event:?}", self.now));
        match event {
            Event::Asdu { asdu, .. } => {
                let id = id_of(&asdu);
                let fate = self.fates.get_mut(&id).unwrap_or_else(|| panic!("ASDU {id} was never submitted"));
                fate.delivered += 1;
                assert!(fate.delivered <= if fate.broadcast { 2 } else { 1 }, "ASDU {id} delivered twice");
            }
            Event::Acknowledged { station, class, count } => {
                assert_eq!(count, 1);
                let id = self.nodes[i].fifo.get_mut(&(station, class)).and_then(VecDeque::pop_front).expect("acknowledged with nothing outstanding");
                let fate = self.fates.get_mut(&id).unwrap();
                if station != LinkAddress(255) && fate.delivered != 1 {
                    panic!("ASDU {id} acknowledged but not delivered\n{}", self.log[self.log.len().saturating_sub(30)..].join("\n"));
                }
                fate.acked = true;
            }
            Event::Unconfirmed { station, class, asdu } => {
                let id = self.nodes[i].fifo.get_mut(&(station, class)).and_then(VecDeque::pop_front).expect("unconfirmed with nothing outstanding");
                assert_eq!(id, id_of(&asdu), "Unconfirmed out of FIFO order");
                self.fates.get_mut(&id).unwrap().unconfirmed = true;
            }
            Event::Started { .. } | Event::Stopped { .. } => {}
            Event::Closed(reason) => panic!("closed: {reason}"),
        }
    }

    fn submit_due(&mut self, i: usize) {
        while let Some(p) = self.nodes[i].pending.front() {
            if p.at > self.now {
                break;
            }
            let now = Instant::from_millis(self.now);
            let (station, class, asdu) = (p.station, p.class, p.asdu.clone());
            let result = self.nodes[i].link.submit_to(station, &asdu, class, now);
            match result {
                Ok(()) => {
                    let p = self.nodes[i].pending.pop_front().unwrap();
                    self.nodes[i].fifo.entry((station, class)).or_default().push_back(id_of(&p.asdu));
                }
                Err(SubmitError::QueueFull) => {
                    // Back-pressure: try again a little later.
                    self.nodes[i].pending.front_mut().unwrap().at = self.now + 10;
                    break;
                }
                Err(e) => panic!("submit refused: {e}"),
            }
            self.drain(i);
        }
    }

    fn step(&mut self) -> bool {
        let next_line = self.line.keys().next().map(|k| k.0);
        let next_deadline = self.nodes.iter().filter_map(|n| n.deadline).min();
        let next_submit = self.nodes.iter().filter_map(|n| n.pending.front().map(|p| p.at)).min();
        let next_noise = self.now + 1 + self.rng.below(200);
        let Some(t) = [next_line, next_deadline, next_submit].into_iter().flatten().min() else { return false };
        let t = if self.faults.noise > 0 && next_noise < t { next_noise } else { t };
        self.now = self.now.max(t);
        let now = Instant::from_millis(self.now);
        // Noise bursts on the line.
        if self.faults.noise > 0 && self.rng.chance(self.faults.noise) {
            let to = self.rng.below(self.nodes.len() as u64) as usize;
            let burst: Vec<u8> = (0..1 + self.rng.below(4)).map(|_| self.rng.garbage()).collect();
            self.nodes[to].link.handle_input(&burst, now);
            self.drain(to);
        }
        while let Some((&key, _)) = self.line.iter().next() {
            if key.0 > self.now {
                break;
            }
            let (to, bytes) = self.line.remove(&key).unwrap();
            self.nodes[to].link.handle_input(&bytes, now);
            self.drain(to);
        }
        for i in 0..self.nodes.len() {
            if self.nodes[i].deadline.is_some_and(|d| d <= self.now) {
                self.nodes[i].deadline = None;
                self.nodes[i].link.handle_timeout(now);
                self.drain(i);
            }
            self.submit_due(i);
        }
        true
    }

    fn run_until(&mut self, end: u64) {
        while self.now < end {
            if !self.step() {
                break;
            }
        }
    }
}

fn asdu(rng: &mut Rng, id: u32) -> Vec<u8> {
    let mut v = id.to_le_bytes().to_vec();
    let extra = 2 + rng.below(36) as usize;
    v.extend((0..extra).map(|_| rng.next() as u8));
    v
}

fn schedule(rng: &mut Rng, next_id: &mut u32, fates: &mut HashMap<u32, Fate>, stations: &[LinkAddress], count: usize, until: u64) -> VecDeque<Pending> {
    let mut v: Vec<Pending> = (0..count)
        .map(|_| {
            *next_id += 1;
            let station = stations[rng.below(stations.len() as u64) as usize];
            fates.insert(*next_id, Fate { broadcast: station == LinkAddress(255), ..Fate::default() });
            let class = if rng.chance(500) { Class::One } else { Class::Two };
            Pending { at: rng.below(until), station, class, asdu: asdu(rng, *next_id) }
        })
        .collect();
    v.sort_by_key(|p| p.at);
    v.into()
}

const ACTIVE: u64 = 20_000;
const TAIL: u64 = 15_000;

fn node(link: Cs101Link, wire: usize, hears: Vec<usize>, pending: VecDeque<Pending>) -> Node {
    Node { link, deadline: Some(0), wire, hears, pending, fifo: HashMap::new() }
}

fn finish(mut sim: Sim, seed: u64, mode: &str) -> (usize, usize, usize, [u32; 6]) {
    sim.run_until(ACTIVE);
    sim.faults = CLEAN;
    sim.run_until(ACTIVE + TAIL);
    let mut faults = [0u32; 6];
    for n in &sim.nodes {
        let s = n.link.stats();
        for (slot, v) in
            faults.iter_mut().zip([s.bad_checksum, s.bad_end + s.bad_header, s.char_timeouts, s.stray_octets, s.retransmissions, s.repeats_answered])
        {
            *slot += v;
        }
    }
    let mut delivered = 0;
    let mut unconfirmed = 0;
    for (id, fate) in &sim.fates {
        assert!(
            fate.acked || fate.unconfirmed,
            "seed {seed} {mode}: ASDU {id} neither acknowledged nor unconfirmed\n{}",
            sim.log[sim.log.len().saturating_sub(40)..].join("\n")
        );
        assert!(fate.delivered <= if fate.broadcast { 2 } else { 1 });
        delivered += usize::from(fate.delivered > 0);
        unconfirmed += usize::from(fate.unconfirmed);
    }
    for (i, n) in sim.nodes.iter().enumerate() {
        assert!(n.pending.is_empty(), "seed {seed} {mode}: node {i} still has ASDUs to submit");
        assert!(n.fifo.values().all(VecDeque::is_empty), "seed {seed} {mode}: node {i} has unresolved ASDUs");
    }
    (sim.fates.len(), delivered, unconfirmed, faults)
}

fn unbalanced(seed: u64) -> (usize, usize, usize, [u32; 6]) {
    let mut rng = Rng::new(seed);
    let (a, b) = (LinkAddress(1), LinkAddress(2));
    let mut fates = HashMap::new();
    let mut id = 0;
    let master = schedule(&mut rng, &mut id, &mut fates, &[a, b, LinkAddress(255)], 15, ACTIVE);
    let sa = schedule(&mut rng, &mut id, &mut fates, &[a], 25, ACTIVE);
    let sb = schedule(&mut rng, &mut id, &mut fates, &[b], 25, ACTIVE);
    let c = config();
    let nodes = vec![
        node(Cs101Link::primary(&[a, b], c).unwrap(), 0, vec![1, 2], master),
        node(Cs101Link::secondary(a, c).unwrap(), 0, vec![0, 2], sa),
        node(Cs101Link::secondary(b, c).unwrap(), 0, vec![0, 1], sb),
    ];
    let sim = Sim { rng, now: 0, nodes, wire_free: vec![0], line: BTreeMap::new(), order: 0, fates, faults: FAULTS, log: Vec::new() };
    finish(sim, seed, "unbalanced")
}

fn balanced(seed: u64) -> (usize, usize, usize, [u32; 6]) {
    let mut rng = Rng::new(seed ^ 0xBA1A_11CE);
    let (a, b) = (LinkAddress(1), LinkAddress(2));
    let mut fates = HashMap::new();
    let mut id = 0;
    let pa = schedule(&mut rng, &mut id, &mut fates, &[b], 30, ACTIVE);
    let pb = schedule(&mut rng, &mut id, &mut fates, &[a], 30, ACTIVE);
    let c = config();
    let nodes = vec![
        node(Cs101Link::balanced(Role::Controlling, a, b, c).unwrap(), 0, vec![1], pa),
        node(Cs101Link::balanced(Role::Controlled, b, a, c).unwrap(), 1, vec![0], pb),
    ];
    let sim = Sim { rng, now: 0, nodes, wire_free: vec![0, 0], line: BTreeMap::new(), order: 0, fates, faults: FAULTS, log: Vec::new() };
    finish(sim, seed, "balanced")
}

fn seeds() -> Vec<u64> {
    if let Ok(s) = std::env::var("SIM_SEED") {
        return vec![s.parse().unwrap()];
    }
    let n: u64 = std::env::var("SIM_SEEDS").ok().and_then(|s| s.parse().ok()).unwrap_or(1000);
    (0..n).collect()
}

#[test]
fn every_asdu_is_delivered_at_most_once_and_ends_named() {
    let mut totals = [(0, 0, 0, [0u32; 6]); 2];
    let seeds = seeds();
    let many = seeds.len() >= 20;
    for seed in seeds {
        for (k, run) in [unbalanced as fn(u64) -> _, balanced].into_iter().enumerate() {
            let (n, d, u, f) = run(seed);
            totals[k].0 += n;
            totals[k].1 += d;
            totals[k].2 += u;
            for (t, v) in totals[k].3.iter_mut().zip(f) {
                *t += v;
            }
        }
    }
    for (mode, (n, d, u, f)) in ["unbalanced", "balanced"].iter().zip(totals) {
        println!(
            "{mode}: {n} ASDUs submitted, {d} delivered, {u} unconfirmed; bad checksum {}, bad end/header {}, char timeouts {}, stray octets {}, retransmissions {}, repeats answered {}",
            f[0], f[1], f[2], f[3], f[4], f[5]
        );
        assert!(d * 10 >= n * 9, "{mode}: most ASDUs get through ({d} of {n})");
        assert!(!many || f.iter().all(|&v| v > 0), "{mode}: every fault kind was exercised");
    }
}
