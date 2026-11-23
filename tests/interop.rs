//! Interop with a second stack: lib60870-C, built in Docker from a pinned commit
//! (`tests/interop/Dockerfile`), driven by `tests/interop/peer.c`, in both roles.
//!
//! - lib60870-C as the controlled station (server); this crate's link as the controlling one.
//! - lib60870-C as the controlling station (client); this crate's link as the controlled one.
//!
//! Each role runs STARTDT, k/w back-pressure, t1 expiry, t2 acknowledgment, t3 TESTFR (each
//! side testing the other) and STOPDT with outstanding frames. The peer prints every frame it sends and
//! receives, so each scenario checks the sequence on the wire from the other stack's side.
//!
//! Skipped with a message when Docker is unavailable, unless `IEC60870_REQUIRE_INTEROP=1`.
//! The commit is pinned in `tests/interop/LIB60870_COMMIT`; the image is built once per hash of
//! that commit and the files it is built from.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
#![allow(clippy::doc_markdown, clippy::too_many_lines, clippy::assert_is_empty, clippy::cast_lossless)]

#[path = "support/docker.rs"]
mod docker;

use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use iec60870::cs104::{self, Awaiting, CloseReason, Config, Cs104Link, Event, SubmitError};
use iec60870::driver::BlockingDriver;

type Link = BlockingDriver<Cs104Link, TcpStream>;

/// The peer image, built if missing; `None` (skip) without Docker unless interop is required.
fn image() -> Option<&'static str> {
    static IMAGE: OnceLock<Option<String>> = OnceLock::new();
    IMAGE
        .get_or_init(|| {
            docker::image(
                "the lib60870-C link interop suite",
                "iec60870-interop",
                &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/interop"),
                "Dockerfile",
                &["peer.c"],
            )
        })
        .as_deref()
}

/// Whether containers share the host's network (Linux) or reach it through Docker Desktop.
fn host_network() -> bool {
    cfg!(target_os = "linux")
}

/// A running lib60870-C peer and the lines it printed.
struct Peer {
    name: String,
    child: Child,
    rx: Receiver<String>,
    lines: Vec<String>,
}

impl Peer {
    fn run(image: &str, ports: &[String], args: &[String]) -> Peer {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let name = format!("iec60870-interop-{}-{}", std::process::id(), N.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
        let mut cmd = Command::new("docker");
        cmd.args(["run", "--rm", "--init", "--name", &name]);
        if ports.is_empty() && host_network() {
            cmd.args(["--network", "host"]);
        } else {
            cmd.args(ports);
        }
        cmd.arg(image).args(args).stdout(Stdio::piped()).stderr(Stdio::inherit());
        let mut child = cmd.spawn().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Peer { name, child, rx, lines: Vec::new() }
    }

    /// lib60870-C as the server on a fresh host port; waits until it listens.
    fn server(args: &[&str]) -> Option<(Peer, SocketAddr)> {
        let image = image()?;
        let mut all: Vec<String> = vec!["server".into(), "-p".into(), "2404".into()];
        all.extend(args.iter().map(ToString::to_string));
        let mut peer = Peer::run(image, &["-p".into(), "127.0.0.1::2404".into()], &all);
        assert!(peer.wait(Duration::from_secs(20), |l| l == "READY"), "peer did not start: {:?}", peer.lines);
        let port = docker::published_port(&peer.name, 2404);
        Some((peer, SocketAddr::from(([127, 0, 0, 1], port))))
    }

    /// lib60870-C as the client of `port` on the host.
    fn client(port: u16, args: &[&str]) -> Option<Peer> {
        let image = image()?;
        let host = if host_network() { "127.0.0.1" } else { "host.docker.internal" };
        let mut all: Vec<String> = vec!["client".into(), "-h".into(), host.into(), "-p".into(), port.to_string()];
        all.extend(args.iter().map(ToString::to_string));
        Some(Peer::run(image, &[], &all))
    }

    fn pump(&mut self) {
        while let Ok(line) = self.rx.try_recv() {
            self.lines.push(line);
        }
    }

    /// Waits until a line satisfies `want`.
    fn wait(&mut self, within: Duration, want: impl Fn(&str) -> bool) -> bool {
        let until = Instant::now() + within;
        loop {
            if self.lines.iter().any(|l| want(l)) {
                return true;
            }
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            match self.rx.recv_timeout(left.min(Duration::from_millis(50))) {
                Ok(line) => self.lines.push(line),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => return self.lines.iter().any(|l| want(l)),
            }
        }
    }

    fn saw(&mut self, line: &str) -> bool {
        self.pump();
        self.lines.iter().any(|l| l == line)
    }

    fn count(&mut self, prefix: &str) -> usize {
        self.pump();
        self.lines.iter().filter(|l| l.starts_with(prefix)).count()
    }

    fn index(&mut self, line: &str) -> Option<usize> {
        self.pump();
        self.lines.iter().position(|l| l == line)
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        let _ = Command::new("docker").args(["rm", "-f", &self.name]).stdout(Stdio::null()).stderr(Stdio::null()).status();
        let _ = self.child.wait();
    }
}

// --- frames as lib60870 prints them -------------------------------------------------------

const TESTFR_ACT: &str = "68 04 43 00 00 00";
const TESTFR_CON: &str = "68 04 83 00 00 00";
const STOPDT_ACT: &str = "68 04 13 00 00 00";
const STOPDT_CON: &str = "68 04 23 00 00 00";

fn s_frame(recv: u16) -> String {
    format!("68 04 01 00 {:02x} {:02x}", (recv << 1) & 0xFE, recv >> 7)
}

/// C_SC_NA_1, activation, CA 1, IOA `ioa`, SCO on.
fn command(ioa: u32) -> Vec<u8> {
    let [a, b, c, _] = ioa.to_le_bytes();
    vec![45, 1, 6, 0, 1, 0, a, b, c, 1]
}

/// M_SP_NA_1, spontaneous, CA 1, IOA `ioa`, on.
fn event(ioa: u32) -> Vec<u8> {
    let [a, b, c, _] = ioa.to_le_bytes();
    vec![1, 1, 3, 0, 1, 0, a, b, c, 1]
}

fn config(k: u16, w: u16, t1_ms: u64, t2_ms: u64, t3_ms: u64) -> Config {
    Config { k, w, t0: Duration::from_secs(5), t1: Duration::from_millis(t1_ms), t2: Duration::from_millis(t2_ms), t3: Duration::from_millis(t3_ms) }
}

/// Drives `link` until `want` matches an event (returned), failing on close or timeout.
fn until(link: &mut Link, within: Duration, mut want: impl FnMut(&Event) -> bool) -> Vec<Event> {
    let end = Instant::now() + within;
    let mut seen = Vec::new();
    loop {
        assert!(Instant::now() < end, "no matching event within {within:?}; saw {seen:?}");
        if let Some(e) = link.poll_event(Duration::from_millis(20)).unwrap() {
            let hit = want(&e);
            if let Event::Closed(r) = &e
                && !hit
            {
                panic!("closed: {r}; saw {seen:?}");
            }
            seen.push(e);
            if hit {
                return seen;
            }
        }
    }
}

/// Drives `link` for `d`, asserting it stays open; returns the events.
fn idle(link: &mut Link, d: Duration) -> Vec<Event> {
    let end = Instant::now() + d;
    let mut seen = Vec::new();
    while Instant::now() < end {
        if let Some(e) = link.poll_event(Duration::from_millis(20)).unwrap() {
            assert!(!matches!(e, Event::Closed(_)), "closed: {e:?}");
            seen.push(e);
        }
    }
    seen
}

fn asdus(events: &[Event]) -> usize {
    events.iter().filter(|e| matches!(e, Event::Asdu(_))).count()
}

/// Our controlling link connected to a lib60870-C server, started.
fn to_server(args: &[&str], config: Config) -> Option<(Peer, Link)> {
    let (mut peer, addr) = Peer::server(args)?;
    // Docker publishes the port a moment after the peer listens: retry briefly.
    let end = Instant::now() + Duration::from_secs(10);
    let mut link = loop {
        match cs104::connect(addr, config) {
            Ok(link) => break link,
            Err(e) if Instant::now() < end => {
                let _ = e;
                thread::sleep(Duration::from_millis(100));
            }
            Err(e) => panic!("cannot connect to the peer: {e}"),
        }
    };
    link.start().unwrap();
    until(&mut link, Duration::from_secs(5), |e| *e == Event::Started);
    assert!(peer.wait(Duration::from_secs(5), |l| l == "ACTIVATED"), "{:?}", peer.lines);
    Some((peer, link))
}

/// A lib60870-C client connected to our controlled link; waits for its STARTDT.
fn from_client(args: &[&str], config: Config) -> Option<(Peer, Link)> {
    image()?;
    let bind = if host_network() { "127.0.0.1:0" } else { "0.0.0.0:0" };
    let listener = TcpListener::bind(bind).unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut all = vec!["--start"];
    all.extend(args);
    let mut peer = Peer::client(port, &all)?;
    let (mut link, _) = cs104::accept(&listener, config).unwrap();
    until(&mut link, Duration::from_secs(10), |e| *e == Event::Started);
    assert!(peer.wait(Duration::from_secs(5), |l| l == "STARTDT_CON"), "{:?}", peer.lines);
    Some((peer, link))
}

// ======== lib60870-C as the controlled station (server) ====================================

#[test]
fn server_startdt() {
    let Some((mut peer, mut link)) = to_server(&[], Config::default()) else { return };
    assert!(peer.saw("RX 68 04 07 00 00 00") && peer.saw("TX 68 04 0b 00 00 00"));
    link.protocol_mut().close();
    assert_eq!(link.next_event().unwrap(), Some(Event::Closed(CloseReason::Local)));
    assert!(peer.wait(Duration::from_secs(5), |l| l == "CLOSED"), "{:?}", peer.lines);
}

#[test]
fn server_k_and_w_back_pressure() {
    // Ours: k = 2, w = 2. Theirs: k = 12 sending 30 events (needs our acknowledgments), w = 3.
    let Some((mut peer, mut link)) = to_server(&["-w", "3", "--t2", "1", "--send", "30"], config(2, 2, 5000, 1000, 20_000)) else { return };
    let mut next = 0u32;
    let mut full = 0;
    let mut acked = 0u32;
    let mut received = 0;
    let end = Instant::now() + Duration::from_secs(20);
    while acked < 10 || received < 30 {
        assert!(Instant::now() < end, "stalled: sent {next}, acked {acked}, received {received}");
        while next < 10 {
            match link.submit(&command(next)) {
                Ok(()) => next += 1,
                Err(SubmitError::WindowFull) => {
                    full += 1;
                    break;
                }
                Err(e) => panic!("{e}"),
            }
        }
        match link.poll_event(Duration::from_millis(20)).unwrap() {
            Some(Event::Acknowledged { count }) => acked += u32::from(count),
            Some(Event::Asdu(a)) => {
                assert_eq!(a[0], 1);
                received += 1;
            }
            Some(Event::Closed(r)) => panic!("closed: {r}"),
            _ => {}
        }
    }
    assert!(full > 0, "our k = 2 pushed back");
    assert!(peer.wait(Duration::from_secs(5), |l| l == "ASDU 45 9"));
    assert_eq!(peer.count("ASDU 45 "), 10, "every command arrived once");
    // lib60870 sends at most k = 12 unacknowledged: 30 arrived, so ours acknowledged them.
}

#[test]
fn server_t1_expiry() {
    // Theirs never acknowledges within our t1 (w and t2 huge).
    let Some((_peer, mut link)) = to_server(&["-w", "32767", "--t1", "255", "--t2", "250"], config(12, 8, 1500, 500, 20_000)) else { return };
    link.submit(&command(1)).unwrap();
    let began = Instant::now();
    let seen = until(&mut link, Duration::from_secs(5), |e| matches!(e, Event::Closed(_)));
    assert_eq!(seen.last(), Some(&Event::Closed(CloseReason::T1Expired(Awaiting::Acknowledgment))));
    assert!(began.elapsed() >= Duration::from_millis(1400));
}

#[test]
fn server_t2_acknowledgment() {
    // Theirs sends 5 events; ours acknowledges only by t2 (w = 100).
    let Some((mut peer, mut link)) = to_server(&["--send", "5"], config(12, 100, 3000, 500, 20_000)) else { return };
    let mut got = Vec::new();
    while asdus(&got) < 5 {
        got.extend(until(&mut link, Duration::from_secs(5), |e| matches!(e, Event::Asdu(_))));
    }
    idle(&mut link, Duration::from_millis(900));
    assert!(peer.wait(Duration::from_secs(2), |l| l == format!("RX {}", s_frame(5))), "{:?}", peer.lines);
}

#[test]
fn server_t3_ours() {
    // Ours tests after 1 s idle; theirs (t3 = 20 s) answers. Any received frame restarts t3,
    // so each direction is tested on its own connection.
    let Some((mut peer, mut link)) = to_server(&["--t3", "20"], config(12, 8, 3000, 500, 1000)) else { return };
    idle(&mut link, Duration::from_millis(3500));
    assert!(peer.count(&format!("RX {TESTFR_ACT}")) >= 2 && peer.saw(&format!("TX {TESTFR_CON}")), "{:?}", peer.lines);
    assert!(!peer.saw("CLOSED"));
}

#[test]
fn server_t3_theirs() {
    // Theirs tests after 1 s idle; ours (t3 = 20 s) answers.
    let Some((mut peer, mut link)) = to_server(&["--t3", "1"], config(12, 8, 3000, 500, 20_000)) else { return };
    idle(&mut link, Duration::from_millis(3500));
    assert!(peer.count(&format!("TX {TESTFR_ACT}")) >= 2 && peer.saw(&format!("RX {TESTFR_CON}")), "{:?}", peer.lines);
    assert!(!peer.saw("CLOSED"));
}

#[test]
fn server_stopdt_with_outstanding_frames() {
    // Theirs sends 5 events that ours has not acknowledged (w = 100, t2 = 9 s); ours has 3
    // commands outstanding. stop() acknowledges first, then STOPDT act; theirs confirms.
    let Some((mut peer, mut link)) = to_server(&["--send", "5", "-w", "100", "--t2", "9"], config(12, 100, 10_000, 9000, 20_000)) else { return };
    let mut got = Vec::new();
    while asdus(&got) < 5 {
        got.extend(until(&mut link, Duration::from_secs(5), |e| matches!(e, Event::Asdu(_))));
    }
    for n in 0..3 {
        link.submit(&command(n)).unwrap();
    }
    link.stop().unwrap();
    let began = Instant::now();
    let seen = until(&mut link, Duration::from_secs(5), |e| *e == Event::Stopped);
    assert!(began.elapsed() < Duration::from_secs(3), "the con did not wait for t2");
    let acked: u16 = seen.iter().map(|e| if let Event::Acknowledged { count } = e { *count } else { 0 }).sum();
    assert_eq!(acked, 3, "theirs acknowledged our outstanding commands before the con: {seen:?}");
    // Our commands carried N(R) = 5, acknowledging their events before the act; their
    // S-frame acknowledged our commands before their con.
    assert!(peer.wait(Duration::from_secs(3), |l| l == format!("TX {STOPDT_CON}")), "{:?}", peer.lines);
    let ours =
        peer.lines.iter().position(|l| l.starts_with("RX 68 0e") && l.ends_with("0a 00 2d 01 06 00 01 00 02 00 00 01")).expect("our third command, N(R) = 5");
    let act = peer.index(&format!("RX {STOPDT_ACT}")).expect("our STOPDT act");
    let theirs = peer.index(&format!("TX {}", s_frame(3))).unwrap_or_else(|| panic!("their S-frame for our three commands: {:?}", peer.lines));
    let con = peer.index(&format!("TX {STOPDT_CON}")).expect("their STOPDT con");
    assert!(ours < act && act < theirs && theirs < con, "{:?}", peer.lines);
    assert!(peer.saw("DEACTIVATED"));
    idle(&mut link, Duration::from_millis(300));
}

// ======== lib60870-C as the controlling station (client) ===================================

#[test]
fn client_startdt() {
    let Some((mut peer, mut link)) = from_client(&[], Config::default()) else { return };
    assert!(peer.saw("TX 68 04 07 00 00 00") && peer.saw("RX 68 04 0b 00 00 00"));
    link.protocol_mut().close();
    assert_eq!(link.next_event().unwrap(), Some(Event::Closed(CloseReason::Local)));
    assert!(peer.wait(Duration::from_secs(5), |l| l == "CLOSED"), "{:?}", peer.lines);
}

#[test]
fn client_k_and_w_back_pressure() {
    // Theirs: k = 2 sending 10 commands, acknowledged by our t2 (w = 100); w = 8, t2 = 1 s.
    // Ours: k = 2 submitting 10 events, acknowledged by their t2. Both windows fill.
    let Some((mut peer, mut link)) = from_client(&["-k", "2", "-w", "8", "--t2", "1", "--send", "10"], config(2, 100, 5000, 1000, 20_000)) else { return };
    let mut next = 0u32;
    let mut full = 0;
    let mut acked = 0u32;
    let mut received = 0;
    let end = Instant::now() + Duration::from_secs(25);
    while acked < 10 || received < 10 {
        assert!(Instant::now() < end, "stalled: sent {next}, acked {acked}, received {received}");
        while next < 10 {
            match link.submit(&event(next)) {
                Ok(()) => next += 1,
                Err(SubmitError::WindowFull) => {
                    full += 1;
                    break;
                }
                Err(e) => panic!("{e}"),
            }
        }
        match link.poll_event(Duration::from_millis(20)).unwrap() {
            Some(Event::Acknowledged { count }) => acked += u32::from(count),
            Some(Event::Asdu(a)) => {
                assert_eq!(a[0], 45);
                received += 1;
            }
            Some(Event::Closed(r)) => panic!("closed: {r}"),
            _ => {}
        }
    }
    assert!(full > 0, "our k = 2 pushed back");
    assert!(peer.wait(Duration::from_secs(5), |l| l == "ASDU 1 9"));
    assert_eq!(peer.count("ASDU 1 "), 10);
    assert!(peer.saw("FULL"), "their k = 2 pushed back too");
}

#[test]
fn client_t1_expiry() {
    let Some((_peer, mut link)) = from_client(&["-w", "32767", "--t1", "255", "--t2", "250"], config(12, 8, 1500, 500, 20_000)) else { return };
    link.submit(&event(1)).unwrap();
    let began = Instant::now();
    let seen = until(&mut link, Duration::from_secs(5), |e| matches!(e, Event::Closed(_)));
    assert_eq!(seen.last(), Some(&Event::Closed(CloseReason::T1Expired(Awaiting::Acknowledgment))));
    assert!(began.elapsed() >= Duration::from_millis(1400));
}

#[test]
fn client_t2_acknowledgment() {
    let Some((mut peer, mut link)) = from_client(&["--send", "5"], config(12, 100, 3000, 500, 20_000)) else { return };
    let mut got = Vec::new();
    while asdus(&got) < 5 {
        got.extend(until(&mut link, Duration::from_secs(5), |e| matches!(e, Event::Asdu(_))));
    }
    idle(&mut link, Duration::from_millis(900));
    assert!(peer.wait(Duration::from_secs(2), |l| l == format!("RX {}", s_frame(5))), "{:?}", peer.lines);
}

#[test]
fn client_t3_ours() {
    // Ours tests after 1 s idle; theirs (t3 = 20 s) answers. Any received frame restarts t3,
    // so each direction is tested on its own connection.
    let Some((mut peer, mut link)) = from_client(&["--t3", "20"], config(12, 8, 3000, 500, 1000)) else { return };
    idle(&mut link, Duration::from_millis(3500));
    assert!(peer.count(&format!("RX {TESTFR_ACT}")) >= 2 && peer.saw(&format!("TX {TESTFR_CON}")), "{:?}", peer.lines);
    assert!(!peer.saw("CLOSED"));
}

#[test]
fn client_t3_theirs() {
    // Theirs tests after 1 s idle; ours (t3 = 20 s) answers.
    let Some((mut peer, mut link)) = from_client(&["--t3", "1"], config(12, 8, 3000, 500, 20_000)) else { return };
    idle(&mut link, Duration::from_millis(3500));
    assert!(peer.count(&format!("TX {TESTFR_ACT}")) >= 2 && peer.saw(&format!("RX {TESTFR_CON}")), "{:?}", peer.lines);
    assert!(!peer.saw("CLOSED"));
}

#[test]
fn client_stopdt_with_outstanding_frames() {
    // Ours sends 5 events that theirs would acknowledge only by its t2 (5 s); theirs sends
    // STOPDT act 300 ms after STARTDT con, while they are outstanding. lib60870-C first
    // acknowledges what it received (`CS104_Connection_sendStopDT`), then sends the act; ours
    // confirms only once nothing it sent is unacknowledged.
    let Some((mut peer, mut link)) = from_client(&["-w", "100", "--t2", "5", "--stop-after", "300"], config(12, 8, 10_000, 1000, 20_000)) else { return };
    for n in 0..5 {
        link.submit(&event(n)).unwrap();
    }
    let began = Instant::now();
    let seen = until(&mut link, Duration::from_secs(8), |e| *e == Event::Stopped);
    assert!(began.elapsed() < Duration::from_secs(4), "theirs acknowledged with the act, not by t2");
    let acked = seen.iter().position(|e| *e == Event::Acknowledged { count: 5 }).expect("acknowledged before stopping");
    assert!(acked < seen.len() - 1, "{seen:?}");
    assert_eq!(link.submit(&event(9)), Err(SubmitError::NotStarted));
    assert!(peer.wait(Duration::from_secs(3), |l| l == "STOPDT_CON"), "{:?}", peer.lines);
    let s = peer.index(&format!("TX {}", s_frame(5))).expect("their S-frame");
    let act = peer.index(&format!("TX {STOPDT_ACT}")).expect("their STOPDT act");
    let con = peer.index(&format!("RX {STOPDT_CON}")).expect("our STOPDT con");
    assert!(s < act && act < con, "their acknowledgment, their act, then our con: {:?}", peer.lines);
    assert_eq!(peer.count("ASDU 1 "), 5);
}
