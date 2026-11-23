//! Interop with a second stack: lib60870-C's IEC 60870-5-101 master and slave, balanced and
//! unbalanced, against this crate's `Cs101Link`.
//!
//! The peer (`tests/interop/cs101/peer101.c`, linked against lib60870-C cloned at a pinned
//! commit) runs in a container on a pseudo-terminal that `socat` bridges to TCP; this side
//! runs the link under `BlockingDriver` over a `TcpStream` — TCP-as-serial, the same octets a
//! serial line would carry. ASDUs use the 101 profile (COT, CA one octet; IOA two) and are
//! decoded with `Asdu::decode` on this side and by lib60870-C on the other.
//!
//! Skipped with a message without Docker, unless `IEC60870_REQUIRE_INTEROP=1`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
#![allow(clippy::doc_markdown, clippy::items_after_statements, clippy::manual_assert_eq)]

#[path = "support/docker.rs"]
mod docker;

use std::io::{BufRead, BufReader};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant as StdInstant};

use iec60870::cs101::{AddressWidth, Class, Config, Cs101Link, Event, LinkAddress, Role};
use iec60870::driver::BlockingDriver;
use iec60870::{Asdu, Profile, TypeId};

type Link = BlockingDriver<Cs101Link, TcpStream>;

/// The peer image, built if missing; `None` (skip) without Docker unless interop is required.
fn image() -> Option<&'static str> {
    static IMAGE: OnceLock<Option<String>> = OnceLock::new();
    IMAGE
        .get_or_init(|| {
            docker::image(
                "the lib60870-C 101 interop suite",
                "iec60870-interop-cs101",
                &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/interop/cs101"),
                "Dockerfile",
                &["peer101.c", "run.sh"],
            )
        })
        .as_deref()
}

/// A running lib60870-C 101 peer and the lines it printed.
struct Peer {
    name: String,
    child: Child,
    rx: Receiver<String>,
    lines: Vec<String>,
    port: u16,
}

impl Peer {
    fn start(args: &[&str]) -> Option<Peer> {
        let image = image()?;
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let name = format!("iec60870-interop101-{}-{}", std::process::id(), N.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
        let mut child = Command::new("docker")
            .args(["run", "--rm", "--init", "--name", &name, "-p", "127.0.0.1::2405", image])
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let mut peer = Peer { name, child, rx, lines: Vec::new(), port: 0 };
        assert!(peer.wait(Duration::from_secs(30), |l| l == "READY"), "peer did not start: {:?}", peer.lines);
        peer.port = docker::published_port(&peer.name, 2405);
        Some(peer)
    }

    /// Connects to the peer's serial line; retries while the port forward comes up.
    fn connect(&self, link: Cs101Link) -> Link {
        let start = StdInstant::now();
        loop {
            if let Ok(stream) = TcpStream::connect(("127.0.0.1", self.port)) {
                stream.set_nodelay(true).unwrap();
                return BlockingDriver::new(link, stream);
            }
            assert!(start.elapsed() < Duration::from_secs(10), "cannot reach the peer's line");
            thread::sleep(Duration::from_millis(50));
        }
    }

    fn pump(&mut self) {
        while let Ok(line) = self.rx.try_recv() {
            self.lines.push(line);
        }
    }

    fn wait(&mut self, within: Duration, want: impl Fn(&str) -> bool) -> bool {
        let end = StdInstant::now() + within;
        loop {
            self.pump();
            if self.lines.iter().any(|l| want(l)) {
                return true;
            }
            let left = end.saturating_duration_since(StdInstant::now());
            if left.is_zero() {
                return false;
            }
            if let Ok(line) = self.rx.recv_timeout(left.min(Duration::from_millis(50))) {
                self.lines.push(line);
            }
        }
    }

    fn count(&mut self, prefix: &str) -> usize {
        self.pump();
        self.lines.iter().filter(|l| l.starts_with(prefix)).count()
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        let _ = Command::new("docker").args(["rm", "-f", &self.name]).stdout(Stdio::null()).stderr(Stdio::null()).status();
        let _ = self.child.wait();
    }
}

/// C_SC_NA_1, activation, CA 1, IOA `ioa`, ON — the 101 profile.
fn command(ioa: u16) -> Vec<u8> {
    let [lo, hi] = ioa.to_le_bytes();
    vec![45, 0x01, 0x06, 0x01, lo, hi, 0x01]
}

/// M_SP_NA_1, spontaneous, CA 1, IOA `ioa`.
fn event(ioa: u16) -> Vec<u8> {
    let [lo, hi] = ioa.to_le_bytes();
    vec![1, 0x01, 0x03, 0x01, lo, hi, 0x01]
}

/// Drives `link` for up to `within` until `done` holds for the events so far; then keeps it
/// running a moment so the peer sees its last confirmation.
fn drive(link: &mut Link, peer: &mut Peer, within: Duration, mut done: impl FnMut(&[Event], &mut Peer) -> bool) -> Vec<Event> {
    let end = StdInstant::now() + within;
    let mut events = Vec::new();
    while StdInstant::now() < end {
        if let Some(e) = link.poll_event(Duration::from_millis(20)).unwrap() {
            events.push(e);
        }
        if done(&events, peer) {
            let settle = StdInstant::now() + Duration::from_millis(500);
            while StdInstant::now() < settle {
                if let Some(e) = link.poll_event(Duration::from_millis(20)).unwrap() {
                    events.push(e);
                }
            }
            if std::env::var_os("INTEROP_VERBOSE").is_some() {
                peer.pump();
                println!("events: {events:#?}\npeer: {:#?}", peer.lines);
            }
            return events;
        }
    }
    peer.pump();
    panic!("timed out\nevents: {events:?}\npeer: {:#?}", peer.lines);
}

fn types(events: &[Event]) -> Vec<(TypeId, u32)> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::Asdu { asdu, .. } => {
                let decoded = Asdu::decode(asdu, &Profile::IEC101).unwrap();
                let ioa = asdu[4..6].iter().rev().fold(0u32, |a, b| a << 8 | u32::from(*b));
                Some((decoded.objects.type_id(), ioa))
            }
            _ => None,
        })
        .collect()
}

fn config(width: AddressWidth) -> Config {
    Config { address_width: width, response_timeout: Duration::from_millis(400), poll_interval: Duration::from_millis(50), ..Config::default() }
}

fn our_primary_their_slave(width: AddressWidth, addr: u16) {
    let addr_s = addr.to_string();
    let w = width.octets().to_string();
    let Some(mut peer) = Peer::start(&["slave", "unbalanced", "--addr", &addr_s, "--width", &w, "--send", "3"]) else { return };
    let station = LinkAddress(addr);
    let mut link = peer.connect(Cs101Link::primary(&[station], config(width)).unwrap());
    link.with(|l, now| l.submit(&command(300), Class::One, now)).unwrap();
    let events = drive(&mut link, &mut peer, Duration::from_secs(20), |ev, peer| types(ev).len() >= 6 && peer.count("ASDU 45 300") >= 1);
    assert!(events.contains(&Event::Started { station }));
    let got = types(&events);
    // Class 1 (single points) before class 2 (scaled measurands), as queued by lib60870.
    let singles: Vec<_> = got.iter().filter(|(t, _)| *t == TypeId::M_SP_NA_1).map(|(_, ioa)| *ioa).collect();
    let scaled: Vec<_> = got.iter().filter(|(t, _)| *t == TypeId::M_ME_NB_1).map(|(_, ioa)| *ioa).collect();
    assert_eq!(singles, [100, 101, 102]);
    assert_eq!(scaled, [200, 201, 202]);
    assert!(events.contains(&Event::Acknowledged { station, class: Class::One, count: 1 }), "the command was confirmed");
    assert!(peer.count("ASDU 45 300 6") == 1, "the slave received the command once: {:?}", peer.lines);
    assert_eq!(link.protocol().stats().unexpected, 0);
}

#[test]
fn unbalanced_primary_against_lib60870_slave() {
    our_primary_their_slave(AddressWidth::One, 3);
}

#[test]
fn unbalanced_primary_against_lib60870_slave_two_octet_address() {
    our_primary_their_slave(AddressWidth::Two, 0x0203);
}

#[test]
fn unbalanced_secondary_against_lib60870_master() {
    let Some(mut peer) = Peer::start(&["master", "unbalanced", "--addr", "7", "--send", "2"]) else { return };
    let station = LinkAddress(7);
    let mut link = peer.connect(Cs101Link::secondary(station, config(AddressWidth::One)).unwrap());
    link.with(|l, now| {
        l.submit(&event(100), Class::One, now)?;
        l.submit(&event(101), Class::One, now)?;
        l.submit(&[11, 0x01, 0x01, 0x01, 200, 0, 0x34, 0x12, 0x00], Class::Two, now)
    })
    .unwrap();
    let events =
        drive(&mut link, &mut peer, Duration::from_secs(20), |ev, peer| types(ev).len() >= 2 && peer.count("ASDU 1 ") >= 2 && peer.count("ASDU 11 200") >= 1);
    assert!(events.contains(&Event::Started { station }));
    assert_eq!(types(&events), [(TypeId::C_SC_NA_1, 300), (TypeId::C_SC_NA_1, 301)]);
    assert!(peer.count("ASDU 1 100 3") == 1 && peer.count("ASDU 1 101 3") == 1, "{:?}", peer.lines);
    let acked = events.iter().filter(|e| matches!(e, Event::Acknowledged { .. })).count();
    assert!(acked >= 2, "polled responses confirmed by the next FCB: {events:?}");
}

#[test]
fn balanced_controlled_against_lib60870_master() {
    // lib60870's balanced master is A (address 2), this end is B (address 3).
    let Some(mut peer) = Peer::start(&["master", "balanced", "--addr", "2", "--other", "3", "--send", "2"]) else { return };
    let (own, other) = (LinkAddress(3), LinkAddress(2));
    let mut link = peer.connect(Cs101Link::balanced(Role::Controlled, own, other, config(AddressWidth::One)).unwrap());
    link.with(|l, now| l.submit(&event(100), Class::One, now)).unwrap();
    let events = drive(&mut link, &mut peer, Duration::from_secs(20), |ev, peer| types(ev).len() >= 2 && peer.count("ASDU 1 100") >= 1);
    assert!(events.contains(&Event::Started { station: other }), "our direction was reset: {events:?}");
    assert_eq!(types(&events), [(TypeId::C_SC_NA_1, 300), (TypeId::C_SC_NA_1, 301)]);
    assert!(events.contains(&Event::Acknowledged { station: other, class: Class::One, count: 1 }));
    // lib60870 does not check DIR; that both ends accepted each other's frames shows ours
    // carry DIR = 0 against its DIR = 1, which our receiver does check.
    assert_eq!(link.protocol().stats().echoes, 0);
}

#[test]
fn balanced_controlling_against_lib60870_slave() {
    let Some(mut peer) = Peer::start(&["slave", "balanced", "--addr", "3", "--other", "2", "--send", "2"]) else { return };
    let (own, other) = (LinkAddress(2), LinkAddress(3));
    let mut link = peer.connect(Cs101Link::balanced(Role::Controlling, own, other, config(AddressWidth::One)).unwrap());
    link.with(|l, now| l.submit(&command(300), Class::One, now)).unwrap();
    let events = drive(&mut link, &mut peer, Duration::from_secs(20), |ev, peer| types(ev).len() >= 4 && peer.count("ASDU 45 300") >= 1);
    assert!(events.contains(&Event::Started { station: other }));
    let got = types(&events);
    assert!(got.contains(&(TypeId::M_SP_NA_1, 100)) && got.contains(&(TypeId::M_SP_NA_1, 101)), "{got:?}");
    assert!(got.contains(&(TypeId::M_ME_NB_1, 200)) && got.contains(&(TypeId::M_ME_NB_1, 201)), "{got:?}");
    assert!(events.contains(&Event::Acknowledged { station: other, class: Class::One, count: 1 }));
    assert!(peer.count("ASDU 45 300 6") == 1);
}

#[cfg(feature = "cli")]
#[test]
fn passive_cli_decodes_independent_master_link_status() {
    use std::io::{Read, Write};
    let Some(peer) = Peer::start(&["master", "unbalanced", "--addr", "513", "--width", "2", "--send", "0"]) else { return };
    let mut stream = TcpStream::connect(("127.0.0.1", peer.port)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    // One fixed, two-address-octet link frame from the independent peer.
    let mut frame = [0; 6];
    stream.read_exact(&mut frame).unwrap();
    let mut monitor = Command::new(env!("CARGO_BIN_EXE_iec60870"))
        .args(["--json", "serial-monitor", "-", "--link-addr", "2"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    monitor.stdin.take().unwrap().write_all(&frame).unwrap();
    let out = monitor.wait_with_output().unwrap();
    assert!(out.status.success());
    let row: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(row["format"], "FT1.2");
    assert_eq!(row["address"], 513);
}
