//! Interop of the stations with a second stack: lib60870-C, built in Docker from a pinned
//! commit (`tests/interop/Dockerfile.station`), in both roles.
//!
//! - lib60870-C's controlling station (`station_client.c`) against this crate's [`Server`]:
//!   general and group interrogation, counter interrogation, read, clock synchronisation, the
//!   test command with time tag, every command type direct (45–51 and 58–64) and with
//!   select-before-operate (45–50 and 58–63), an unknown IOA, an execute that was never
//!   selected, and reset process — each answer checked from lib60870-C's side, and each
//!   command checked in this crate's handler.
//! - This crate's [`Client`] against lib60870-C's controlled station (`station_server.c`):
//!   general interrogation, counter interrogation, read, clock synchronisation, a direct and a
//!   select-before-operate command, a negative confirmation, a spontaneous event, a group
//!   interrogation, and a STOPDT/STARTDT cycle followed by a second general interrogation.
//!
//! Skipped with a message when Docker is unavailable, unless `IEC60870_REQUIRE_INTEROP=1`.
//! The commit is pinned in `tests/interop/LIB60870_COMMIT`; the image is built once per hash of
//! that commit and the files it is built from.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, clippy::zombie_processes)]
#![allow(clippy::assert_is_empty, clippy::too_many_lines, clippy::doc_markdown, clippy::cast_lossless, clippy::cast_precision_loss, clippy::similar_names)]

#[path = "support/docker.rs"]
mod docker;

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Command as Process, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant as StdInstant};

use iec60870::prelude::*;
use iec60870::{Client, Error, Server};

/// The peer image, built if missing; `None` (skip) without Docker unless interop is required.
fn image() -> Option<&'static str> {
    static IMAGE: OnceLock<Option<String>> = OnceLock::new();
    IMAGE
        .get_or_init(|| {
            docker::image(
                "the lib60870-C station interop suite",
                "iec60870-interop-station",
                &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/interop"),
                "Dockerfile.station",
                &["station_client.c", "station_server.c"],
            )
        })
        .as_deref()
}

fn linux() -> bool {
    cfg!(target_os = "linux")
}

const CA: CommonAddress = CommonAddress(1);

/// The outstation lib60870-C's client is pointed at.
fn database() -> Database {
    let mut db = Database::new();
    let _ = db.insert(CA, Ioa(100), true).group(1);
    let _ = db.insert(CA, Ioa(101), DoublePointValue::On);
    let _ = db.insert(CA, Ioa(200), 21.5f32);
    let _ = db.insert(CA, Ioa(201), -7i16);
    let _ = db.insert(CA, Ioa(300), BinaryCounterReading::new(1234));
    for (ioa, kind) in [
        (5000, CommandKind::Single),
        (5001, CommandKind::Double),
        (5002, CommandKind::Step),
        (5003, CommandKind::Normalized),
        (5004, CommandKind::Scaled),
        (5005, CommandKind::Float),
        (5006, CommandKind::Bitstring),
    ] {
        let _ = db.command(CA, Ioa(ioa), kind).mode(CommandMode::DirectOrSelect);
    }
    let _ = db.command(CA, Ioa(5100), CommandKind::Single); // select-before-operate only
    db
}

/// One `ASDU <type> <cot> <negative> <ca> <ioa> <count>` line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Seen {
    type_id: u8,
    cot: u8,
    negative: bool,
    ca: u16,
    ioa: i64,
}

fn parse(line: &str) -> Option<Seen> {
    let f: Vec<&str> = line.strip_prefix("ASDU ")?.split(' ').collect();
    Some(Seen { type_id: f[0].parse().ok()?, cot: f[1].parse().ok()?, negative: f[2] == "1", ca: f[3].parse().ok()?, ioa: f[4].parse().ok()? })
}

/// The ASDUs lib60870-C received after `STEP <name>`, up to the next step.
fn step(lines: &[String], name: &str) -> Vec<Seen> {
    let start = lines.iter().position(|l| l == &format!("STEP {name}")).unwrap_or_else(|| panic!("no step {name}: {lines:?}"));
    lines[start + 1..].iter().take_while(|l| !l.starts_with("STEP ")).filter_map(|l| parse(l)).collect()
}

fn causes(seen: &[Seen]) -> Vec<(u8, u8, bool)> {
    seen.iter().map(|s| (s.type_id, s.cot, s.negative)).collect()
}

#[test]
fn lib60870_client_runs_every_procedure_against_our_server() {
    let Some(image) = image() else { return };
    let builder = Server::builder();
    #[cfg(feature = "file-transfer")]
    let builder = {
        let mut store = iec60870::station::MemoryFileStore::new();
        for ioa in 1..=40 {
            store.insert(CA, Ioa(ioa), iec60870::station::FileName(2), [1, 2, 3]);
        }
        builder.files(store)
    };
    let server = builder.bind(("0.0.0.0", 0), database()).unwrap();
    let port = server.local_addr().unwrap().port();
    let executed: Arc<Mutex<Vec<CommandRequest>>> = Arc::default();
    let log = Arc::clone(&executed);
    let handle = server
        .spawn(move |r: &CommandRequest| {
            log.lock().unwrap().push(*r);
            Decision::Accept
        })
        .unwrap();

    let host = if linux() { "127.0.0.1" } else { "host.docker.internal" };
    let mut cmd = Process::new("docker");
    cmd.args(["run", "--rm", "--init"]);
    if linux() {
        cmd.args(["--network", "host"]);
    }
    #[cfg(feature = "file-transfer")]
    cmd.args(["-e", "TEST_DIRECTORY=1"]);
    let out = cmd.arg(image).args(["station-client", "-h", host, "-p", &port.to_string()]).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let lines: Vec<String> = text.lines().map(str::to_string).collect();
    assert!(lines.iter().any(|l| l == "EXIT"), "lib60870-C client did not finish: {text}\n{}", String::from_utf8_lossy(&out.stderr));

    #[cfg(feature = "file-transfer")]
    {
        let entries: Vec<_> = lines.iter().filter(|l| l.starts_with("FILE ")).cloned().collect();
        let expected: Vec<_> = (1..=40).map(|ioa| format!("FILE {ioa} 2 3 {}", u8::from(ioa == 40))).collect();
        assert_eq!(entries, expected);
        assert!(lines.iter().any(|line| line == "FILE_READY 0 0"));
    }

    // Interrogation: confirmation, the points without time tags (COT 20), termination.
    let gi = causes(&step(&lines, "gi"));
    assert_eq!(gi.first(), Some(&(100, 7, false)), "{gi:?}");
    assert_eq!(gi.last(), Some(&(100, 10, false)), "{gi:?}");
    let types: Vec<u8> = gi.iter().filter(|c| c.1 == 20).map(|c| c.0).collect();
    assert_eq!(types, [1, 3, 13, 11], "{gi:?}");
    let group = causes(&step(&lines, "group"));
    assert_eq!(group, [(100, 7, false), (1, 21, false), (100, 10, false)]);
    let counter = causes(&step(&lines, "counter"));
    assert_eq!(counter, [(101, 7, false), (15, 37, false), (101, 10, false)]);
    let read = step(&lines, "read");
    assert_eq!((read[0].type_id, read[0].cot, read[0].ioa), (13, 5, 200));
    assert_eq!(causes(&step(&lines, "clock")), [(103, 7, false)]);
    assert_eq!(causes(&step(&lines, "test")), [(107, 7, false)]);

    // Every command type, direct and select-before-operate, plain and time-tagged.
    for timed in [0, 1] {
        for kind in 0..7u8 {
            let t = if timed == 1 { [58, 59, 60, 61, 62, 63, 64][usize::from(kind)] } else { 45 + kind };
            assert_eq!(causes(&step(&lines, &format!("direct {kind} {timed}"))), [(t, 7, false), (t, 10, false)], "direct type {t}");
            if kind < 6 {
                assert_eq!(causes(&step(&lines, &format!("select {kind} {timed}"))), [(t, 7, false)], "select type {t}");
                assert_eq!(causes(&step(&lines, &format!("execute {kind} {timed}"))), [(t, 7, false), (t, 10, false)], "execute type {t}");
            }
        }
    }
    assert_eq!(causes(&step(&lines, "unknown-ioa")), [(45, 47, true)]);
    assert_eq!(causes(&step(&lines, "unselected")), [(45, 7, true)]);
    assert_eq!(causes(&step(&lines, "reset")), [(105, 7, false)]);

    let executed = executed.lock().unwrap();
    // 14 direct + 12 after a select; neither the unknown IOA nor the unselected execute.
    assert_eq!(executed.len(), 26, "{executed:?}");
    assert!(executed.iter().all(|r| r.ioa.0 >= 5000 && r.ioa.0 <= 5006));
    assert_eq!(executed.iter().filter(|r| r.time.is_some()).count(), 13);
    println!("lib60870-C client: {} ASDUs received, {} commands executed", lines.iter().filter(|l| l.starts_with("ASDU")).count(), executed.len());
    handle.shutdown();
}

#[test]
fn our_client_runs_every_procedure_against_lib60870_server() {
    let Some(image) = image() else { return };
    let name = format!("iec60870-interop-station-{}", std::process::id());
    let mut child = Process::new("docker")
        .args(["run", "--rm", "--init", "--name", &name, "-p", "127.0.0.1::2404", image, "station-server", "-p", "2404", "--duration", "20000"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    let until = StdInstant::now() + Duration::from_secs(20);
    while !line.starts_with("READY") && StdInstant::now() < until {
        line.clear();
        stdout.read_line(&mut line).unwrap();
    }
    assert!(line.starts_with("READY"), "lib60870-C server did not start");

    let addr = SocketAddr::from(([127, 0, 0, 1], docker::published_port(&name, 2404)));
    let mut client = None;
    for _ in 0..50 {
        if let Ok(c) = Client::connect(addr) {
            client = Some(c);
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let mut client = client.expect("connected");
    client.start().unwrap();

    #[cfg(feature = "file-transfer")]
    assert_eq!(client.download(CA, Ioa(30000), 2).unwrap(), (0..=255u8).cycle().take(800).collect::<Vec<_>>());
    let gi: Vec<Event> = client.interrogate(CA).unwrap().map(Result::unwrap).collect();
    let points: Vec<(u32, Value)> = gi.iter().filter_map(|e| if let Event::Point(p) = e { Some((p.ioa.0, p.value)) } else { None }).collect();
    assert_eq!(points, [(100, Value::from(true)), (101, Value::from(-7i16)), (200, Value::from(21.5f32))]);
    assert!(matches!(gi.last(), Some(Event::InterrogationComplete { .. })));

    let ci: Vec<Event> = client.counter_interrogate(CA, CounterInterrogation::GENERAL).unwrap().map(Result::unwrap).collect();
    assert!(matches!(&ci[0], Event::Point(p) if p.ioa == Ioa(300) && matches!(p.value, Value::Counter(c) if c.value() == 1234)), "{ci:?}");

    assert_eq!(client.read(CA, Ioa(200)).unwrap().value, Value::from(21.5f32));
    client.clock_sync(CA).unwrap();
    client.test_command(CA).unwrap();
    client.command(CA, Ioa(5000), Command::single(true)).unwrap().wait().unwrap();
    let steps: Vec<String> =
        client.select_and_execute(CA, Ioa(5001), Command::double(DoublePointValue::On)).unwrap().map(|s| format!("{:?}", s.unwrap())).collect();
    assert_eq!(steps, ["Selected", "Confirmed", "Completed"]);
    client.command(CA, Ioa(5002), Command::setpoint_float(3.5)).unwrap().wait().unwrap();
    match client.command(CA, Ioa(7000), Command::single(true)).unwrap().wait() {
        Err(Error::Negative { cot }) => assert_eq!(cot.cause, Cause::UNKNOWN_IOA),
        other => panic!("{other:?}"),
    }
    // The spontaneous event lib60870-C enqueues after the interrogation.
    let mut spontaneous = false;
    while let Some(e) = client.poll_event(Duration::from_millis(500)).unwrap() {
        if let Event::Point(p) = e
            && p.cause.cause == Cause::SPONTANEOUS
        {
            spontaneous = p.ioa == Ioa(100) && p.value == Value::from(false) && p.time.is_some();
        }
    }
    assert!(spontaneous, "the spontaneous M_SP_TB_1 arrived");

    // lib60870-C answers a group it has no points in with confirmation and termination only.
    let group: Vec<Event> = client.interrogate_group(CA, 1).unwrap().map(Result::unwrap).collect();
    assert!(group.iter().all(|e| !matches!(e, Event::Point(_))), "{group:?}");
    assert!(matches!(group.last(), Some(Event::InterrogationComplete { .. })), "{group:?}");

    // STOPDT, STARTDT again, and the same interrogation on the restarted transfer.
    client.stop().unwrap();
    client.start().unwrap();
    let again = client.interrogate(CA).unwrap().map(Result::unwrap).filter(|e| matches!(e, Event::Point(_))).count();
    assert_eq!(again, 3, "the general interrogation after a STOPDT/STARTDT cycle");
    client.stop().unwrap();
    let _ = child.kill();
    let mut rest = String::new();
    let _ = std::io::Read::read_to_string(&mut stdout, &mut rest);
    #[cfg(feature = "file-transfer")]
    assert!(rest.lines().any(|line| line == "DOWNLOAD 1"), "missing final file acknowledgment: {rest}");
    assert_eq!(rest.matches("GI 20").count(), 2, "two general interrogations: {rest}");
    for want in ["GI 21", "CI 5", "READ 200", "CLOCK", "COMMAND 45 5000 0", "COMMAND 46 5001 1", "COMMAND 46 5001 0", "COMMAND 50 5002 0"] {
        assert!(rest.contains(want), "lib60870-C did not see {want}: {rest}");
    }
}
