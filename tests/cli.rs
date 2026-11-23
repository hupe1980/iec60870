//! Process-level checks of the iec60870 command line.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]
use std::{
    io::Write,
    process::{Command, Output, Stdio},
};
fn run(args: &[&str], input: &[u8]) -> Output {
    let mut child =
        Command::new(env!("CARGO_BIN_EXE_iec60870")).args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}
#[test]
fn decode_pasted_and_streamed_frames() {
    let result = run(&["decode", "68:04:07:00:00:00"], b"");
    assert!(result.status.success());
    assert_eq!(result.stdout, b"U        STARTDT act\n");
    let result = run(&["--json", "decode", "--explain"], b"# input\n680401000a00680407000000\n");
    assert!(result.status.success());
    let frames: Vec<serde_json::Value> = String::from_utf8(result.stdout).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0]["recv"], 5);
    assert_eq!(frames[1]["function"], "STARTDT act");
}

#[test]
fn oversized_and_invalid_records_do_not_hide_later_frames() {
    let mut input = b"680407000000\n".to_vec();
    let mut boundary = b"680407000000 #".to_vec();
    boundary.resize(65536, b'x');
    input.extend_from_slice(&boundary);
    input.extend_from_slice(b"\r\n");
    input.extend(std::iter::repeat_n(b'0', 100_000));
    input.extend_from_slice(b"\n0x\n\x1b\n68040b000000");
    let result = run(&["decode", "--json", "-"], &input);
    assert_eq!(result.status.code(), Some(1));
    assert!(!result.stderr.contains(&27));
    let records: Vec<serde_json::Value> = String::from_utf8(result.stdout).unwrap().lines().map(|s| serde_json::from_str(s).unwrap()).collect();
    assert_eq!(records.len(), 6);
    assert_eq!(records[1]["kind"], "frame");
    assert_eq!(records[2]["kind"], "error");
    assert_eq!(records[5]["input"], 6);
    assert_eq!(records[5]["function"], "STARTDT con");
}

#[test]
fn diagnostics_do_not_emit_terminal_controls() {
    for arg in ["\x1b", "--unknown\x1b"] {
        let output = run(&["decode", arg], b"");
        assert!(!output.status.success());
        assert!(!output.stderr.contains(&27));
        assert!(!output.stdout.contains(&27));
    }
}

#[test]
fn annotations_partition_every_typed_payload() {
    use iec60870::prelude::*;
    use proptest::{
        strategy::{Strategy, ValueTree},
        test_runner::TestRunner,
    };
    use std::fmt::Write as _;
    let mut runner = TestRunner::deterministic();
    for (name, profile) in [("104", Profile::IEC104), ("101", Profile::IEC101)] {
        for sequence in [false, true] {
            for (id, strategy) in common::arms(&profile, sequence) {
                if !profile.permits(id) {
                    continue;
                }
                let objects = (0..128).map(|_| strategy.new_tree(&mut runner).unwrap().current()).find(|o| !o.is_empty()).unwrap();
                let mut asdu = Asdu::new(CommonAddress(1), Cot::SPONTANEOUS, objects);
                asdu.sequence = sequence;
                let octets = asdu.to_vec(&profile).unwrap();
                let mut input = String::new();
                for byte in octets {
                    write!(input, "{byte:02x}").unwrap();
                }
                let result = run(&["--json", "decode", "--asdu", "--explain", "--profile", name, &input], b"");
                assert!(result.status.success(), "{id} {}", String::from_utf8_lossy(&result.stderr));
                let record: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
                let mut rendered = String::new();
                for span in record["explain"].as_array().unwrap() {
                    assert_eq!(span["offset"], rendered.len() / 2);
                    let bytes = span["octets"].as_str().unwrap();
                    assert_eq!(span["len"], bytes.len() / 2);
                    rendered.push_str(bytes);
                }
                assert_eq!(rendered, input);
                assert_eq!(record["asdu"]["objects"].as_array().unwrap().len(), asdu.len());
            }
        }
    }
}
mod common;

#[test]
fn checked_examples_and_errors() {
    for (args, expected) in [
        (vec!["decode", "680401000a00"], "S(5)"),
        (vec!["decode", "680e0000000064010600010000000014"], "station interrogation"),
        (vec!["decode", "--profile", "101", "e5"], "acknowledgement"),
        (vec!["decode", "--profile", "104", "680c0c68530164010600010000000014d416"], "station interrogation"),
        (vec!["decode", "--profile", "101", "1040014116"], "address 1"),
        (vec!["decode", "--asdu", "64010600010000000014"], "station interrogation"),
        (vec!["decode", "--asdu", "--cot", "1", "--ca", "1", "--ioa", "1", "640106010014"], "station interrogation"),
    ] {
        let output = run(&args, b"");
        assert!(output.status.success(), "{:?}: {}", args, String::from_utf8_lossy(&output.stderr));
        assert!(String::from_utf8_lossy(&output.stdout).contains(expected));
    }
    let output = run(&["--json", "decode", "--asdu", "010103000100"], b"");
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["kind"], "error");
    assert_eq!(result["offset"], 6);
    assert!(result["field"].is_string());
    assert_eq!(run(&["decode", "--ioa", "4", "e5"], b"").status.code(), Some(2));
}

#[test]
fn sequential_values_and_raw_link_payload() {
    let output = run(&["--json", "decode", "--asdu", "--explain", "0182030001000a00000100"], b"");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let frame: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(frame["asdu"]["objects"][0]["ioa"], 10);
    assert_eq!(frame["asdu"]["objects"][1]["ioa"], 11);
    assert_eq!(frame["asdu"]["objects"][1]["derived"], true);
    assert_eq!(frame["asdu"]["objects"][0]["value"], true);
    let output = run(&["--json", "decode", "--profile", "101", "680303680001aaab16"], b"");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let frame: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(frame["raw"], "aa");
}

#[test]
fn truncated_remainder_and_unterminated_overflow() {
    let output = run(&["--json", "decode", "6804070000006804"], b"");
    assert_eq!(output.status.code(), Some(1));
    let lines: Vec<serde_json::Value> = String::from_utf8(output.stdout).unwrap().lines().map(|line| serde_json::from_str(line).unwrap()).collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0]["kind"], "frame");
    assert_eq!(lines[1]["kind"], "error");
    let output = run(&["--json", "decode", "-"], &vec![b'0'; 100_000]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(String::from_utf8(output.stdout).unwrap().lines().count(), 1);
}

#[test]
fn timestamps_require_an_explicit_utc_clock() {
    // Single point, IOA 100, at 2000-01-01 00:00:00.000 on the station clock.
    let input = "1e01030001006400000100000000010100";
    for (flag, utc) in [("--utc", true), ("--explain", false)] {
        let output = run(&["decode", "--asdu", "--json", flag, input], b"");
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        let frame: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let point = &frame["asdu"]["objects"][0];
        assert_eq!(point["time_text"], "2000-01-01 00:00:00.000");
        assert_eq!(point.get("time").and_then(|v| v.as_str()), utc.then_some("2000-01-01T00:00:00.000Z"));
    }
}

#[test]
fn variable_link_and_concatenated_error_boundaries() {
    let result = run(&["decode", "--profile", "101", "--json", "--explain", "68090968430101010301640001af16"], b"");
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    let frame: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(frame["format"], "FT1.2");
    assert_eq!(frame["asdu"]["objects"][0]["ioa"], 100);
    assert_eq!(frame["asdu"]["objects"][0]["value"], true);
    let result = run(&["decode", "--json", "680407000000ff"], b"");
    assert_eq!(result.status.code(), Some(1));
    let kinds: Vec<String> = String::from_utf8(result.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap()["kind"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(kinds, ["frame", "error"]);
}

#[test]
fn version_color_and_oversized_argument() {
    let version = run(&["--version"], b"");
    assert!(String::from_utf8_lossy(&version.stdout).contains(env!("CARGO_PKG_VERSION")));
    assert!(run(&["decode", "--color", "always", "e5"], b"").stdout.contains(&27));
    assert!(!run(&["decode", "--color", "never", "e5"], b"").stdout.contains(&27));
    assert!(!run(&["decode", "--color", "always", "--json", "e5"], b"").stdout.contains(&27));
    let result = run(&["decode", "--json", &"0".repeat(65537)], b"");
    assert_eq!(result.status.code(), Some(1));
    assert_eq!(serde_json::from_slice::<serde_json::Value>(&result.stdout).unwrap()["kind"], "error");
}

#[test]
fn raw_values_and_ambiguous_framing() {
    let bare = "680106000100000000aa55"; // Type 104 is raw under the 104 profile.
    assert_eq!(run(&["decode", bare], b"").status.code(), Some(1));
    let output = run(&["decode", "--json", "--asdu", bare], b"");
    let raw: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(raw["asdu"]["raw"], "000000aa55");
    let output = run(&["decode", "--json", "--asdu", "0d01030001006400000000c07fc0"], b"");
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let point = &result["asdu"]["objects"][0];
    assert_eq!(point["value_text"], "NaN");
    assert_eq!(point["quality"], serde_json::json!(["NT", "IV"]));
    let result = run(&["decode", "--json", "--asdu", "0101030001000a000001ff"], b"");
    assert_eq!(result.status.code(), Some(1));
    let error: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(error["offset"], 10);
}

#[test]
fn two_measured_objects_remain_distinct_in_an_i_frame() {
    let input = "681a000000000d02030001006400000000ac4100650000000080bf80";
    let result = run(&["--json", "decode", "--explain", input], b"");
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    let frame: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    let objects = frame["asdu"]["objects"].as_array().unwrap();
    assert_eq!(objects[0]["value"], 21.5);
    assert_eq!(objects[1]["value"], -1.0);
    assert_eq!(objects[1]["quality"], serde_json::json!(["IV"]));
    let octets: String = frame["explain"].as_array().unwrap().iter().map(|s| s["octets"].as_str().unwrap()).collect();
    assert_eq!(octets, input);
}

#[test]
fn arbitrary_short_records_produce_one_result_each() {
    use std::fmt::Write as _;
    let mut input = String::new();
    let mut state = 123_456_789_u32;
    for n in 0..128 {
        for _ in 0..=n % 43 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            write!(input, "{:02x}", state >> 24).unwrap();
        }
        input.push('\n');
    }
    let result = run(&["decode", "--json", "--asdu"], input.as_bytes());
    assert_eq!(result.status.code(), Some(1));
    let text = String::from_utf8(result.stdout).unwrap();
    assert_eq!(text.lines().count(), 128);
    for (i, line) in text.lines().enumerate() {
        let record: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(record["input"], i + 1);
    }
}

#[test]
fn installed_command_conventions() {
    let result = Command::new(env!("CARGO_BIN_EXE_iec60870")).env("NO_COLOR", "1").args(["decode", "--color", "auto", "e5"]).output().unwrap();
    assert!(result.status.success());
    assert!(!result.stdout.contains(&27));
    let result = run(&["--json", "decode", "-"], b"680407000000\n68040b000000\n");
    let records: Vec<serde_json::Value> = String::from_utf8(result.stdout).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["function"], "STARTDT act");
    assert_eq!(records[1]["function"], "STARTDT con");
}

#[path = "cli/capture.rs"]
mod capture;

#[path = "cli/sim.rs"]
mod sim;

#[cfg(feature = "tls")]
mod tls_support;

#[test]
fn tls_flags_require_a_complete_identity() {
    for args in [&["client", "127.0.0.1:9", "--tls-server-name", "localhost", "gi"][..], &["client", "127.0.0.1:9", "--tls", "ca.pem", "gi"]] {
        assert_eq!(run(args, b"").status.code(), Some(2));
    }
    #[cfg(not(feature = "tls"))]
    {
        let result = run(&["client", "127.0.0.1:9", "--tls", "ca", "cert", "key", "gi"], b"");
        assert_eq!(result.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&result.stderr).contains("--features cli,tls"));
    }
}

#[cfg(feature = "tls")]
#[test]
fn mutual_tls_query_checks_station_and_client_identities() {
    use iec60870::{Server, prelude::*, station::RefuseCommands, tls::TlsServerConfig};
    use std::fs;
    let pki = tls_support::Pki::new();
    let dir = tempfile::tempdir().unwrap();
    let pem = |name: &str, contents: &str| {
        let path = dir.path().join(name);
        fs::write(&path, contents).unwrap();
        path.to_str().unwrap().to_owned()
    };
    let ca = pem("ca.pem", &pki.ca.cert);
    let cert = pem("client.pem", &pki.client.cert);
    let key = pem("client.key", &pki.client.key);
    let foreign_ca = pem("other.pem", &pki.other_ca.cert);
    let foreign_cert = pem("foreign.pem", &pki.stranger.cert);
    let foreign_key = pem("foreign.key", &pki.stranger.key);
    let server_identity = pki.ca.issue("station", &["station.example", "localhost"]);
    let tls = TlsServerConfig::from_pem(pki.ca.cert.as_bytes(), server_identity.cert.as_bytes(), server_identity.key.as_bytes()).unwrap();
    let mut db = Database::new();
    db.insert(CommonAddress(1), Ioa(200), 21.5_f32);
    let mut store = iec60870::station::MemoryFileStore::new();
    store.insert(CommonAddress(1), Ioa(7), iec60870::station::FileName(2), [0, 255, 1]);
    let server = Server::builder().tls(tls).files(store).bind("127.0.0.1:0", db).unwrap();
    let server_addr = server.local_addr().unwrap();
    let addr = server_addr.to_string();
    let handle = server.spawn(RefuseCommands).unwrap();
    let query = |trust: &str, chain: &str, identity: &str, name: &str| {
        run(&["--json", "client", &addr, "--tls", trust, chain, identity, "--tls-server-name", name, "read", "200"], b"")
    };
    let ok = query(&ca, &cert, &key, "station.example");
    assert!(ok.status.success(), "{}", String::from_utf8_lossy(&ok.stderr));
    let rows: Vec<serde_json::Value> = serde_json::Deserializer::from_slice(&ok.stdout).into_iter().map(Result::unwrap).collect();
    assert_eq!(rows[0]["value"], 21.5);
    assert_eq!(rows[1]["kind"], "done");
    let local = format!("localhost:{}", server_addr.port());
    let implicit = run(&["--json", "client", &local, "--tls", &ca, &cert, &key, "read", "200"], b"");
    assert!(implicit.status.success(), "{}", String::from_utf8_lossy(&implicit.stderr));
    let output = dir.path().join("download.bin");
    let downloaded = run(&["client", &local, "--tls", &ca, &cert, &key, "get", "7", "2", "--output", output.to_str().unwrap()], b"");
    assert!(downloaded.status.success(), "{}", String::from_utf8_lossy(&downloaded.stderr));
    assert_eq!(fs::read(&output).unwrap(), [0, 255, 1]);
    let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let stalled = silent.local_addr().unwrap().to_string();
    let start = std::time::Instant::now();
    let timed_out = run(&["client", &stalled, "--timeout", "150ms", "--tls", &ca, &cert, &key, "gi"], b"");
    assert_eq!(timed_out.status.code(), Some(4));
    assert!(start.elapsed() < std::time::Duration::from_secs(3));
    for bad in [
        query(&ca, &cert, &key, "wrong.example"),
        query(&foreign_ca, &cert, &key, "station.example"),
        query(&ca, &foreign_cert, &foreign_key, "station.example"),
        run(&["client", &addr, "--tls", &ca, &cert, &key, "gi"], b""),
    ] {
        assert_eq!(bad.status.code(), Some(4));
        assert_eq!(bad.stdout, b"");
    }
    let bad_key = pem("malformed.key", "-----BEGIN PRIVATE KEY-----\nsecret-marker!!!");
    let malformed = query(&ca, &cert, &bad_key, "station.example");
    assert_eq!(malformed.status.code(), Some(1));
    assert!(!String::from_utf8_lossy(&malformed.stderr).contains("secret-marker"));
    fs::File::create(&bad_key).unwrap().set_len(1024 * 1024 + 1).unwrap();
    let oversized = query(&ca, &cert, &bad_key, "station.example");
    assert_eq!(oversized.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&oversized.stderr).contains("1 MiB"));
    handle.shutdown();
}

#[path = "cli/files.rs"]
mod files;

#[test]
fn passive_serial_pipe_preserves_frames_and_detects_partial_disconnect() {
    let out = run(&["--json", "serial-monitor", "-", "--link-addr", "2"], &[0xe5, 0x10, 0x40, 1, 0, 0x41, 0x16]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let frames: Vec<serde_json::Value> = serde_json::Deserializer::from_slice(&out.stdout).into_iter().map(Result::unwrap).collect();
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[1]["address"], 1);
    assert_eq!(frames[1]["format"], "FT1.2");
    let truncated = run(&["serial-monitor", "-"], &[0x10, 0x40]);
    assert_eq!(truncated.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&truncated.stderr).contains("incomplete"));
    assert_eq!(run(&["serial-monitor", "-", "--baud", "9600"], &[]).status.code(), Some(2));
}

#[cfg(all(unix, feature = "serial"))]
#[test]
fn serial_device_emits_a_frame_and_reports_hangup() {
    use serialport::{SerialPort, TTYPort};
    use std::{
        io::{BufRead, BufReader},
        sync::mpsc,
        thread,
        time::Duration,
    };
    let (master_port, slave) = TTYPort::pair().unwrap();
    // Keep the child's exec from inheriting the master and holding its own line open.
    let mut master = master_port.try_clone_native().unwrap();
    drop(master_port);
    let name = slave.name().unwrap();
    let baud = if cfg!(target_os = "macos") { "0" } else { "19200" };
    let mut monitor = Command::new(env!("CARGO_BIN_EXE_iec60870"))
        .args(["--json", "serial-monitor", &name, "--parity", "none", "--baud", baud, "--link-addr", "2"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = monitor.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    let reader = thread::spawn(move || {
        let mut lines = BufReader::new(stdout).lines();
        let _ = tx.send(lines.next());
        for line in lines {
            if line.is_err() {
                break;
            }
        }
    });
    let mut line = None;
    for _ in 0..50 {
        master.write_all(&[0x10, 0x40, 1, 0, 0x41, 0x16]).unwrap();
        if let Ok(record) = rx.recv_timeout(Duration::from_millis(100)) {
            line = record;
            break;
        }
    }
    drop(master);
    drop(slave);
    for _ in 0..50 {
        if monitor.try_wait().unwrap().is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    if monitor.try_wait().unwrap().is_none() {
        monitor.kill().unwrap();
    }
    let output = monitor.wait_with_output().unwrap();
    reader.join().unwrap();
    assert_eq!(output.status.code(), Some(1), "{}", String::from_utf8_lossy(&output.stderr));
    let row: serde_json::Value = serde_json::from_str(&line.unwrap().unwrap()).unwrap();
    assert_eq!(row["address"], 1);
}
