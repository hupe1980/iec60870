//! Deterministic simulation: a controlling and a controlled link over a lossy, duplicating,
//! reordering, reconnecting network, on virtual time, under many seeds.
//!
//! The property, per connection and per direction: the ASDUs the receiver got are exactly
//! the ones the sender's link accepted, in order, each once (a prefix of them); nothing is
//! acknowledged that was not delivered; and a connection always ends with both links
//! reporting `Closed` with a reason. Across connections the sender re-submits what was not
//! acknowledged — the at-least-once rule of the station layer — and every run ends with
//! everything delivered (the last connection is fault-free).
//!
//! Faults are at the segment level (a whole `Transmit`): TCP's checksum makes byte
//! corruption a different fault model, and the link cannot detect it by design.
//!
//! `SIM_SEEDS=n` sets the number of seeds (default 1000); `SIM_SEED=s` runs one seed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
#![allow(clippy::doc_markdown, clippy::too_many_lines, clippy::assert_is_empty, clippy::cast_lossless)]

use std::collections::VecDeque;
use std::time::Duration;

use iec60870::cs104::{CloseReason, CommandError, Config, Cs104Link, Event, Role, State, SubmitError};
use iec60870::driver::Output;
use iec60870::time::Instant;

/// xorshift64*: small, fast, deterministic.
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
}

#[derive(Clone, Copy, Default)]
struct Faults {
    drop: u64,
    duplicate: u64,
    jitter: u64,
    break_link: u64,
}

struct Segment {
    at: u64,
    order: u64,
    to: usize,
    bytes: Vec<u8>,
}

/// One direction of application traffic: items 0..total, sent from one side to the other.
struct Flow {
    total: usize,
    /// Items acknowledged by the peer (a prefix: acknowledgments are cumulative).
    acked: usize,
    /// Next item to submit in this connection.
    next: usize,
    /// Items submitted in this connection and not yet acknowledged, in order.
    in_flight: VecDeque<usize>,
    /// What this connection's receiver got, in order.
    received: Vec<usize>,
    /// Where this connection started submitting.
    start: usize,
    /// Every item ever received, over all connections.
    ever: Vec<bool>,
    dir: u8,
}

impl Flow {
    fn new(total: usize, dir: u8) -> Self {
        Flow { total, acked: 0, next: 0, in_flight: VecDeque::new(), received: Vec::new(), start: 0, ever: vec![false; total], dir }
    }
    fn reconnect(&mut self) {
        self.next = self.acked;
        self.start = self.acked;
        self.in_flight.clear();
        self.received.clear();
    }
    fn done(&self) -> bool {
        self.acked == self.total
    }
}

fn payload(dir: u8, item: usize, rng: &mut Rng) -> Vec<u8> {
    let mut v = vec![0xA5, dir];
    v.extend_from_slice(&(item as u32).to_le_bytes());
    let extra = rng.below(24) as usize;
    v.extend((0..extra).map(|n| (n as u8).wrapping_mul(dir.wrapping_add(7))));
    v
}

fn decode_payload(asdu: &[u8]) -> (u8, usize) {
    assert!(asdu.len() >= 6 && asdu[0] == 0xA5, "corrupted ASDU delivered: {asdu:02x?}");
    (asdu[1], u32::from_le_bytes([asdu[2], asdu[3], asdu[4], asdu[5]]) as usize)
}

struct Side {
    link: Cs104Link,
    deadline: Option<Instant>,
    closed: Option<CloseReason>,
}

#[derive(Default)]
struct Stats {
    connections: u64,
    reasons: std::collections::BTreeMap<String, u64>,
    delivered: u64,
    stops: u64,
}

fn ms(t: u64) -> Instant {
    Instant::from_millis(t)
}

fn run_seed(seed: u64, stats: &mut Stats) {
    let mut rng = Rng::new(seed);
    let k = 1 + rng.below(12) as u16;
    let w = 1 + rng.below(u64::from(k) + 2) as u16;
    let config = Config { k, w, t0: Duration::from_secs(1), t1: Duration::from_millis(1500), t2: Duration::from_millis(400), t3: Duration::from_millis(2500) };
    // flows[0]: controlling → controlled (commands); flows[1]: controlled → controlling (events).
    let mut flows = [Flow::new(10 + rng.below(90) as usize, 0), Flow::new(10 + rng.below(140) as usize, 1)];
    let max_connections = 1 + rng.below(12);
    let mut now: u64 = 0;

    for connection in 0..max_connections {
        let last = connection + 1 == max_connections;
        let faults =
            if last { Faults::default() } else { Faults { drop: rng.below(40), duplicate: rng.below(25), jitter: rng.below(60), break_link: rng.below(4) } };
        stats.connections += 1;
        for f in &mut flows {
            f.reconnect();
        }
        let mut sides = [
            Side { link: Cs104Link::new(Role::Controlling, config).unwrap(), deadline: None, closed: None },
            Side { link: Cs104Link::new(Role::Controlled, config).unwrap(), deadline: None, closed: None },
        ];
        for s in &mut sides {
            s.link.handle_timeout(ms(now));
        }
        let mut net: Vec<Segment> = Vec::new();
        let mut order = 0u64;
        let mut started = [false, false];
        let mut restart_at: Option<u64> = Some(now);
        let mut clean_close = false;
        let began = now;

        loop {
            // 1. Drain both sides.
            for (idx, side) in sides.iter_mut().enumerate() {
                while let Some(out) = side.link.poll_output() {
                    match out {
                        Output::Transmit(bytes) => {
                            if side.closed.is_some() {
                                continue;
                            }
                            let copies = if rng.chance(faults.drop) {
                                0
                            } else if rng.chance(faults.duplicate) {
                                2
                            } else {
                                1
                            };
                            for _ in 0..copies {
                                let latency = 1 + if rng.chance(faults.jitter) { rng.below(80) } else { 5 };
                                order += 1;
                                net.push(Segment { at: now + latency, order, to: 1 - idx, bytes: bytes.clone() });
                            }
                        }
                        Output::Event(event) => {
                            assert!(side.closed.is_none(), "seed {seed}: event after Closed: {event:?}");
                            match event {
                                Event::Started => started[idx] = true,
                                Event::Stopped => started[idx] = false,
                                Event::Asdu(asdu) => {
                                    let (dir, item) = decode_payload(&asdu);
                                    // Side 1 (controlled) receives flow 0, side 0 receives flow 1.
                                    assert_eq!(usize::from(dir), 1 - idx, "seed {seed}: ASDU delivered to its own sender");
                                    let flow = &mut flows[1 - idx];
                                    let expected = flow.start + flow.received.len();
                                    assert_eq!(
                                        item, expected,
                                        "seed {seed}: connection {connection}: out of order or duplicated (got {item}, expected {expected})"
                                    );
                                    flow.received.push(item);
                                    flow.ever[item] = true;
                                    stats.delivered += 1;
                                }
                                Event::Acknowledged { count } => {
                                    let flow = &mut flows[idx];
                                    for _ in 0..count {
                                        let item = flow.in_flight.pop_front().unwrap_or_else(|| panic!("seed {seed}: acknowledged more than submitted"));
                                        assert_eq!(item, flow.acked, "seed {seed}: acknowledgments out of order");
                                        flow.acked += 1;
                                    }
                                }
                                Event::Closed(reason) => side.closed = Some(reason),
                            }
                        }
                        Output::Deadline(at) => side.deadline = Some(at),
                    }
                }
            }
            // Nothing acknowledged that was not delivered.
            for (idx, flow) in flows.iter().enumerate() {
                assert!(flow.acked <= flow.start + flow.received.len(), "seed {seed}: flow {idx}: acknowledged {} > delivered", flow.acked);
            }

            // 2. A closed side tears the connection down.
            if sides.iter().any(|s| s.closed.is_some()) {
                net.clear();
                for side in &mut sides {
                    if side.closed.is_none() {
                        side.link.handle_disconnect(ms(now));
                        while let Some(out) = side.link.poll_output() {
                            if let Output::Event(Event::Closed(reason)) = out {
                                side.closed = Some(reason);
                            }
                        }
                    }
                }
                break;
            }

            // 3. Application: start, stop, submit, finish.
            if let Some(at) = restart_at
                && now >= at
                && sides[0].link.state() == State::Stopped
            {
                sides[0].link.start(ms(now)).unwrap();
                restart_at = None;
            }
            let all_done = flows.iter().all(Flow::done);
            if all_done && sides[0].link.state() == State::Started {
                match sides[0].link.stop(ms(now)) {
                    Ok(()) | Err(CommandError::Busy(_)) => {}
                    Err(e) => panic!("seed {seed}: {e}"),
                }
            }
            if all_done && sides[0].link.state() == State::Stopped && restart_at.is_none() {
                sides[0].link.close();
                clean_close = true;
                continue;
            }
            if !all_done && sides[0].link.state() == State::Started && rng.chance(3) {
                sides[0].link.stop(ms(now)).unwrap();
                stats.stops += 1;
                restart_at = Some(now + 50 + rng.below(500));
            }
            for (idx, side) in sides.iter_mut().enumerate() {
                let flow = &mut flows[idx];
                while flow.next < flow.total && rng.chance(600) {
                    let asdu = payload(flow.dir, flow.next, &mut rng);
                    match side.link.submit(&asdu, ms(now)) {
                        Ok(()) => {
                            flow.in_flight.push_back(flow.next);
                            flow.next += 1;
                        }
                        Err(SubmitError::WindowFull | SubmitError::NotStarted) => break,
                        Err(e) => panic!("seed {seed}: submit: {e}"),
                    }
                }
            }
            if rng.chance(faults.break_link) {
                for side in &mut sides {
                    side.link.handle_disconnect(ms(now));
                }
                continue;
            }

            // 4. Advance time to the next thing that happens.
            let next_segment = net.iter().map(|s| s.at).min();
            let next_deadline = sides.iter().filter_map(|s| s.deadline.map(|d| d.as_nanos() / 1_000_000 + u64::from(d.as_nanos() % 1_000_000 != 0))).min();
            let app_tick = now + 1 + rng.below(20);
            now = [next_segment, next_deadline, Some(app_tick)].into_iter().flatten().min().unwrap().max(now);
            assert!(now - began < 600_000, "seed {seed}: connection {connection} made no progress for 10 virtual minutes");

            // 5. Deliver due segments (in arrival order, then send order), in random pieces.
            net.sort_by_key(|s| (s.at, s.order));
            while net.first().is_some_and(|s| s.at <= now) {
                let segment = net.remove(0);
                let mut rest = &segment.bytes[..];
                while !rest.is_empty() {
                    let take = 1 + rng.below(rest.len() as u64) as usize;
                    let (piece, tail) = rest.split_at(take);
                    sides[segment.to].link.handle_input(piece, ms(now));
                    rest = tail;
                }
            }
            for side in &mut sides {
                if side.deadline.is_some_and(|d| ms(now) >= d) {
                    side.deadline = None;
                    side.link.handle_timeout(ms(now));
                }
            }
        }

        // The connection is over: both sides must have said why.
        for (idx, side) in sides.iter().enumerate() {
            let reason = side.closed.unwrap_or_else(|| panic!("seed {seed}: side {idx} ended without a reason"));
            *stats.reasons.entry(format!("{reason:?}").split([' ', '{', '(']).next().unwrap().to_string()).or_default() += 1;
        }
        // Per direction: received is exactly the prefix of what was accepted.
        for flow in &flows {
            let accepted: Vec<usize> = (flow.start..flow.next).collect();
            assert!(accepted.starts_with(&flow.received), "seed {seed}: received is not a prefix of accepted");
            assert!(flow.acked <= flow.start + flow.received.len(), "seed {seed}: acknowledged more than delivered");
        }
        if clean_close {
            assert!(last || flows.iter().all(Flow::done));
            break;
        }
        assert!(!last, "seed {seed}: the fault-free connection closed with {:?} / {:?}", sides[0].closed, sides[1].closed);
        now += 10;
    }
    for flow in &flows {
        assert!(flow.done(), "seed {seed}: flow {} incomplete: {}/{}", flow.dir, flow.acked, flow.total);
        assert!(flow.ever.iter().all(|&b| b), "seed {seed}: an item was never delivered");
    }
}

#[test]
fn every_accepted_i_frame_is_delivered_once_in_order_or_the_connection_closes_with_a_reason() {
    let seeds: u64 = std::env::var("SIM_SEEDS").ok().and_then(|s| s.parse().ok()).unwrap_or(1000);
    let only: Option<u64> = std::env::var("SIM_SEED").ok().and_then(|s| s.parse().ok());
    let mut stats = Stats::default();
    let range = only.map_or(0..seeds, |s| s..s + 1);
    let n = range.end - range.start;
    for seed in range {
        run_seed(seed, &mut stats);
    }
    println!(
        "simulation: {n} seeds, {} connections, {} ASDUs delivered, {} local stops; closes by reason: {:?}",
        stats.connections, stats.delivered, stats.stops, stats.reasons
    );
}
