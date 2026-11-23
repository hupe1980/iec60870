use super::run;
use serde_json::{Value, json};
use std::{io::Write, process::Output};
use tempfile::NamedTempFile;

fn check(data: &[u8]) -> Output {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(data).unwrap();
    run(&["sim", "--check", "--points", f.path().to_str().unwrap(), "--json"], b"")
}

#[test]
fn demo_file_and_builtin_have_identical_counts() {
    let out = run(&["--json", "sim", "--check", "--demo"], b"");
    assert!(out.status.success());
    assert_eq!(out.stdout, check(include_bytes!("../../examples/demo-bay.toml")).stdout);
    assert_eq!(serde_json::from_slice::<Value>(&out.stdout).unwrap(), json!({"kind":"validation","stations":1,"points":15,"commands":5}));
    for args in [&["sim", "--check"][..], &["sim", "--check", "--demo", "--bind", "127.0.0.1:0"], &["sim", "--check", "--demo", "--points", "missing"]] {
        assert_eq!(run(args, b"").status.code(), Some(2));
    }
}
#[test]
fn forward_status_and_duplicate_addresses_follow_station_scope() {
    let source = "[[station]]\nca=1\n[[station.command]]\nioa=7\nkind='single'\nstatus=7\n[[station.point]]\nioa=7\nkind='single'\nvalue=true\n";
    assert!(check(format!("{source}{}", source.replace("ca=1", "ca=2")).as_bytes()).status.success());
    for (s, line) in [
        (source.replace("status=7", "status=8"), 6),
        (source.replace("kind='single'\nstatus", "kind='double'\nstatus"), 6),
        (format!("{source}[[station.point]]\nioa=7\nkind='single'\nvalue=false"), 12),
        (format!("{source}[[station]]\nca=1"), 12),
        (source.replace("value=true", "group=17\nvalue=true"), 10),
        (source.replace("value=true", "value=0"), 10),
    ] {
        let out = check(s.as_bytes());
        assert_eq!(out.status.code(), Some(1));
        assert!(String::from_utf8(out.stderr).unwrap().contains(&format!(":{line}:")));
    }
}
#[test]
fn bounded_files_and_diagnostics() {
    let mut src = b"[[station]]\nca=1\n#".to_vec();
    src.resize(1024 * 1024, b'x');
    assert!(check(&src).status.success());
    src.push(b'x');
    assert!(String::from_utf8(check(&src).stderr).unwrap().contains("1 MiB"));
    for data in [&b"[[station]]\nca=1\n#\x1b"[..], b"[[station]]\nca=1\nunknown=true", b"[[station]]\nca=1\n\xff"] {
        let out = check(data);
        assert_eq!(out.status.code(), Some(1));
        assert!(!out.stderr.contains(&27));
        assert_eq!(out.stdout, b"");
    }
}
#[test]
fn wire_ranges_and_walk_intervals_are_checked() {
    let prefix = "[[station]]\nca=1\n[[station.point]]\nioa=0\n";
    for (kind, value, valid) in [
        ("scaled", "-32768", true),
        ("scaled", "32768", false),
        ("step", "64", false),
        ("normalized", "1.1", false),
        ("float", "nan", false),
        ("counter", "2147483647", true),
        ("bitstring", "4294967295", true),
        ("bitstring", "-1", false),
        ("double", "'off'", true),
    ] {
        assert_eq!(check(format!("{prefix}kind='{kind}'\nvalue={value}").as_bytes()).status.success(), valid);
    }
    for (walk, valid) in [
        ("step=1,min=-5,max=10,every='500ms'", true),
        ("step=0.5,min=0,max=1,every='2s'", false),
        ("step=1,min=1,max=3,every='1s'", false),
        ("step=1,min=0,max=1,every='0ms'", false),
        ("step=1,min=0,max=1,every='18446744073709551615m'", false),
    ] {
        assert_eq!(check(format!("{prefix}kind='scaled'\nvalue=0\nwalk={{ {walk} }}").as_bytes()).status.success(), valid);
    }
}

#[cfg(unix)]
#[test]
fn filename_controls_are_escaped_in_both_output_paths() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("bay\x1b.toml");
    let args = ["sim", "--check", "--points", path.to_str().unwrap()];
    let error = run(&args, b"");
    assert_eq!(error.status.code(), Some(1));
    assert!(!error.stderr.contains(&27));
    std::fs::write(&path, "[[station]]\nca=4\n").unwrap();
    let good = run(&args, b"");
    assert!(good.status.success());
    assert!(!good.stdout.contains(&27));
}

struct Running {
    child: std::process::Child,
    logs: std::sync::mpsc::Receiver<Value>,
    banner: Value,
}
impl Running {
    fn start(args: &[&str]) -> Self {
        use std::{
            io::{BufRead, BufReader},
            process::{Command, Stdio},
            sync::mpsc,
            thread,
            time::Duration,
        };
        let mut child = Command::new(env!("CARGO_BIN_EXE_iec60870")).args(["sim", "--json"]).args(args).stdout(Stdio::piped()).spawn().unwrap();
        let input = child.stdout.take().unwrap();
        let (tx, logs) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(input).lines().map_while(Result::ok) {
                if tx.send(serde_json::from_str(&line).unwrap()).is_err() {
                    break;
                }
            }
        });
        let mut sim = Self { child, logs, banner: Value::Null };
        sim.banner = sim.logs.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(sim.banner["kind"], "listening");
        sim
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
#[test]
fn simulated_station_serves_decisions_and_records_disconnected_peer() {
    use iec60870::{Client, prelude::*};
    let sim = Running::start(&["--demo", "--bind", "127.0.0.1:0"]);
    assert_eq!(sim.banner["points"], 15);
    assert_eq!(sim.banner["commands"], 5);
    assert_eq!(sim.banner["loopback"], true);
    let ca = CommonAddress(1);
    let mut client = Client::connect(sim.banner["addr"].as_str().unwrap()).unwrap();
    client.start().unwrap();
    let points: Vec<_> = client.interrogate(ca).unwrap().map(Result::unwrap).filter_map(|e| if let Event::Point(p) = e { Some(p) } else { None }).collect();
    assert_eq!(points.len(), 14); // integrated totals use counter interrogation
    assert!(client.select_and_execute(ca, Ioa(5003), Command::single(true)).unwrap().wait().is_err());
    assert!(client.command(ca, Ioa(5000), Command::double(DoublePointValue::Off)).unwrap().wait().is_err());
    client.select_and_execute(ca, Ioa(5000), Command::double(DoublePointValue::Off)).unwrap().wait().unwrap();
    assert_eq!(client.read(ca, Ioa(100)).unwrap().value, Value::from(DoublePointValue::Off));
    client.command(ca, Ioa(5002), Command::step(StepDirection::Higher)).unwrap().wait().unwrap();
    assert_eq!(client.read(ca, Ioa(110)).unwrap().value, StepPosition::new(6).into());
    client.clock_sync(ca).unwrap();
    drop(client);
    let mut rows = Vec::new();
    loop {
        let event = sim.logs.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        let closed = event["state"] == "closed";
        rows.push(event);
        if closed {
            break;
        }
    }
    let peer = rows[0]["peer"].as_str().unwrap();
    assert!(rows.iter().all(|r| r["peer"] == peer));
    assert!(rows.iter().any(|r| r["kind"] == "clock"));
    for (ioa, phase, decision) in [(5003, "select", "refused"), (5000, "execute", "refused"), (5000, "select", "accepted"), (5000, "execute", "accepted")] {
        assert!(rows.iter().any(|r| r["ioa"] == ioa && r["phase"] == phase && r["decision"] == decision && r["ca"] == 1));
    }
}
#[test]
fn point_file_sends_bounded_spontaneous_values() {
    use iec60870::{Client, prelude::*};
    use std::time::{Duration, Instant};
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(b"[[station]]\nca=42\n[[station.point]]\nioa=9\nkind='scaled'\nvalue=3\ngroup=2\ntime='none'\nwalk={step=1,min=1,max=5,every='30ms'}").unwrap();
    let sim = Running::start(&["--points", f.path().to_str().unwrap(), "--bind", "127.0.0.1:0", "--seed", "0"]);
    let mut client = Client::connect(sim.banner["addr"].as_str().unwrap()).unwrap();
    client.start().unwrap();
    let group: Vec<_> = client.interrogate_group(CommonAddress(42), 2).unwrap().map(Result::unwrap).collect();
    assert!(group.iter().any(|e| matches!(e,Event::Point(p) if p.ioa==Ioa(9))));
    let deadline = Instant::now() + Duration::from_secs(4);
    loop {
        assert!(Instant::now() < deadline);
        if let Some(Event::Point(p)) = client.poll_event(Duration::from_millis(200)).unwrap()
            && p.cause.cause == Cause::SPONTANEOUS
        {
            assert!(matches!(p.value,Value::Scaled(v) if (1..=5).contains(&v.value)));
            break;
        }
    }
}
#[test]
fn network_exposure_and_invalid_input_are_reported_before_serving() {
    let sim = Running::start(&["--demo", "--bind", "0.0.0.0:0"]);
    assert_eq!(sim.banner["loopback"], false);
    assert!(sim.banner["notice"].as_str().unwrap().contains("network"));
    let addr = sim.banner["addr"].as_str().unwrap();
    let bad = run(&["sim", "--demo", "--bind", addr], b"");
    assert_eq!(bad.status.code(), Some(1));
    assert!(String::from_utf8(bad.stderr).unwrap().contains("--bind"));
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(b"[[station]]\nca=1\n#\x1b").unwrap();
    let bad = run(&["sim", "--points", f.path().to_str().unwrap(), "--bind", addr], b"");
    assert_eq!(bad.status.code(), Some(1));
    assert_eq!(bad.stdout, b"");
    assert!(!bad.stderr.contains(&27));
    assert!(String::from_utf8(bad.stderr).unwrap().contains(":3:"));
}

#[test]
fn default_listener_and_oversize_serving_error() {
    let help = run(&["sim", "--help"], b"");
    assert!(String::from_utf8(help.stdout).unwrap().contains("default: 127.0.0.1:2404"));
    let f = NamedTempFile::new().unwrap();
    f.as_file().set_len(1024 * 1024 + 1).unwrap();
    let out = run(&["sim", "--points", f.path().to_str().unwrap(), "--bind", "127.0.0.1:0"], b"");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(out.stdout, b"");
    assert!(String::from_utf8(out.stderr).unwrap().contains("1 MiB"));
}

#[test]
fn human_interrogation_lists_the_demo_points_and_separates_its_counter() {
    let sim = Running::start(&["--demo", "--bind", "127.0.0.1:0"]);
    let addr = sim.banner["addr"].as_str().unwrap();
    for (action, expected, summary) in
        [("gi", &[100, 101, 102, 103, 110, 4001, 4002, 4003, 4011, 4012, 4013, 4020, 4021, 4030][..], "14 points in "), ("ci", &[4100][..], "1 point in ")]
    {
        let out = run(&["client", addr, action], b"");
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        let stdout = String::from_utf8(out.stdout).unwrap();
        let mut lines = stdout.lines();
        assert!(lines.next().unwrap().contains("IOA"));
        assert!(lines.next_back().unwrap().starts_with(summary));
        let mut addresses = Vec::new();
        for line in lines {
            let mut cells = line.split_whitespace();
            assert_eq!(cells.next(), Some("1"));
            addresses.push(cells.next().unwrap().parse::<u32>().unwrap());
        }
        addresses.sort_unstable();
        assert_eq!(addresses, expected);
    }
}

#[test]
fn cli_reads_simulator_points_counters_and_streams_changes() {
    let sim = Running::start(&["--demo", "--bind", "127.0.0.1:0"]);
    let addr = sim.banner["addr"].as_str().unwrap();
    for (action, count) in [(&["gi"][..], 14), (&["ci"], 1), (&["read", "110"], 1), (&["gi", "--group", "2"], 0)] {
        let mut args = vec!["--json", "client", addr];
        args.extend_from_slice(action);
        let started = std::time::Instant::now();
        let out = run(&args, b"");
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        let rows: Vec<Value> = serde_json::Deserializer::from_slice(&out.stdout).into_iter().map(Result::unwrap).collect();
        assert_eq!(rows.len(), count + 1);
        assert_eq!(rows[count]["points"], count);
        assert_eq!(rows[count]["kind"], "done");
        if count > 0 {
            assert_eq!(rows[0]["kind"], "point");
            assert_eq!(rows[0]["ca"], 1);
        }
    }
    let out = run(&["client", addr, "--json", "watch", "--no-gi", "--for", "1200ms"], b"");
    assert!(out.status.success());
    assert!(!out.stdout.contains(&27));
    assert!(serde_json::Deserializer::from_slice(&out.stdout).into_iter::<Value>().map(Result::unwrap).any(|v| v["kind"] == "point" && v["cause"] == 3));
    assert_eq!(run(&["client", addr, "read", "777"], b"").status.code(), Some(3));
}
#[test]
fn client_connection_waits_are_bounded_and_errors_name_the_target() {
    use std::{
        net::TcpListener,
        time::{Duration, Instant},
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let started = Instant::now();
    let silent = run(&["client", &addr, "--timeout", "120ms", "gi"], b"");
    assert_eq!(silent.status.code(), Some(4));
    assert!(String::from_utf8(silent.stderr).unwrap().contains("STARTDT"));
    assert!(started.elapsed() < Duration::from_secs(2));
    drop(listener);
    let refused = run(&["client", &addr, "--timeout", "200ms", "read", "1"], b"");
    assert_eq!(refused.status.code(), Some(4));
    assert!(String::from_utf8(refused.stderr).unwrap().contains(&addr));
    for bad in ["0", "256s", "junk"] {
        assert_eq!(run(&["client", &addr, "--timeout", bad, "gi"], b"").status.code(), Some(2));
    }
}

#[test]
fn one_octet_broadcast_interrogation_reports_each_station() {
    use iec60870::{Server, prelude::*, station::ServerConfig};
    let mut db = Database::new();
    db.insert(CommonAddress(1), Ioa(2), true);
    db.insert(CommonAddress(2), Ioa(3), false);
    let mut profile = Profile::IEC104;
    profile.ca = CaWidth::One;
    let config = ServerConfig { profile, ..Default::default() };
    let server = Server::builder().config(config).bind("127.0.0.1:0", db).unwrap();
    let handle = server.spawn(|_: &CommandRequest| Decision::Refuse).unwrap();
    let out = run(&["client", &handle.local_addr().to_string(), "--ca-width", "1", "--ca", "255", "--timeout", "250ms", "--json", "gi"], b"");
    handle.shutdown();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let records: Vec<serde_json::Value> = serde_json::Deserializer::from_slice(&out.stdout).into_iter().map(Result::unwrap).collect();
    assert_eq!(records[0]["ca"], 1);
    assert_eq!(records[1]["ca"], 2);
    assert_eq!(records[2]["points"], 2);
}

#[test]
fn cli_clock_requires_one_station_and_reports_its_confirmation() {
    let sim = Running::start(&["--demo", "--bind", "127.0.0.1:0"]);
    let addr = sim.banner["addr"].as_str().unwrap();
    let out = run(&["--json", "client", addr, "clock"], b"");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let row: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(row["kind"], "done");
    assert_eq!(row["action"], "clock");
    assert_eq!(row["ca"], 1);
    assert!(row["seconds"].is_number());
    let unknown = run(&["client", addr, "--ca", "2", "clock"], b"");
    assert_eq!(unknown.status.code(), Some(3));
    assert_eq!(unknown.stdout, b"");
    let broadcast = run(&["client", "127.0.0.1:9", "--ca", "65535", "clock"], b"");
    assert_eq!(broadcast.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&broadcast.stderr).contains("one station"));
}

#[test]
fn offline_previews_predict_configured_feedback_and_refusals() {
    let preview = |args: &[&str]| {
        let mut cmd = vec!["--json", "sim", "--demo", "--preview"];
        cmd.extend(args);
        let out = run(&cmd, b"");
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        serde_json::from_slice::<Value>(&out.stdout).unwrap()
    };
    let accepted = preview(&["5002", "step", "up"]);
    assert_eq!(accepted["kind"], "command_preview");
    assert_eq!(accepted["decision"], "accepted");
    assert_eq!(accepted["mode"], "sbo");
    assert_eq!(accepted["feedback"], json!({"ioa":110,"before":5,"after":6}));
    assert_eq!(accepted, preview(&["5002", "step", "up"]));
    assert_eq!(preview(&["6000", "setpoint", "-1.5", "--direct"])["decision"], "accepted");
    for (args, reason) in [
        (&["5002", "step", "down", "--ca", "2"][..], "unknown station"),
        (&["42", "single", "on"], "unknown command point"),
        (&["5002", "single", "on"], "command kind mismatch"),
        (&["5000", "double", "on", "--direct"], "mode refused"),
        (&["5003", "single", "off"], "policy refused"),
    ] {
        let row = preview(args);
        assert_eq!(row["decision"], "refused");
        assert_eq!(row["reason"], reason);
        assert!(row["feedback"].is_null());
    }
}

#[test]
fn preview_checks_values_and_serving_option_conflicts() {
    for (kind, value) in [
        ("bits", "0x+1"),
        ("bits", "4294967296"),
        ("scaled", "-32769"),
        ("setpoint", "NaN"),
        ("setpoint", "1e99"),
        ("normalized", "1.000001"),
        ("single", "yes"),
        ("double", "1"),
        ("step", "on"),
        ("unknown", "on"),
    ] {
        let out = run(&["sim", "--demo", "--preview", "5000", kind, value], b"");
        assert_eq!(out.status.code(), Some(2), "{kind} {value}");
        assert_eq!(out.stdout, b"");
    }
    for extra in [&["--bind", "127.0.0.1:0"][..], &["--seed", "1"], &["--check"], &["--ca", "65535"]] {
        let mut args = vec!["sim", "--demo", "--preview", "5000", "double", "on"];
        args.extend(extra);
        assert_eq!(run(&args, b"").status.code(), Some(2));
    }
    let out = check(b"[[station]]\nca=65535");
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("reserved for broadcast"));
}

#[test]
fn previews_use_station_scoped_status_and_wire_value_ranges() {
    for (kind, point, initial, requested, expected, mode) in [
        ("bits", "bitstring", "1", "0xffffffff", json!(u32::MAX), "direct"),
        ("normalized", "normalized", "0", "-1", json!(-1.0), "sbo"),
        ("scaled", "scaled", "0", "-32768", json!(-32768), "sbo"),
        ("setpoint", "float", "0", "-2.5", json!(-2.5), "sbo"),
        ("double", "double", "'off'", "on", json!("ON"), "sbo"),
        ("single", "single", "false", "on", json!(true), "sbo"),
        ("step", "step", "63", "up", json!(63), "sbo"),
    ] {
        let mut f = NamedTempFile::new().unwrap();
        write!(f,"[[station]]\nca=1\n[[station]]\nca=2\n[[station.command]]\nioa=9\nkind='{kind}'\nstatus=7\n[[station.point]]\nioa=7\nkind='{point}'\nvalue={initial}").unwrap();
        let out = run(&["--json", "sim", "--points", f.path().to_str().unwrap(), "--preview", "9", kind, requested, "--ca", "2"], b"");
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        let record: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(record["feedback"]["after"], expected, "{kind}");
        assert_eq!(record["mode"], mode);
    }
}

#[test]
fn watch_scopes_points_to_the_requested_station_and_qualifies_time_on_request() {
    let mut file = NamedTempFile::new().unwrap();
    for ca in [1, 2] {
        writeln!(file, "[[station]]\nca={ca}\n[[station.point]]\nioa=9\nkind='scaled'\nvalue=2\nwalk={{step=1,min=1,max=4,every='20ms'}}").unwrap();
    }
    let sim = Running::start(&["--points", file.path().to_str().unwrap(), "--bind", "127.0.0.1:0"]);
    let addr = sim.banner["addr"].as_str().unwrap();
    for (ca, utc) in [("2", false), ("65535", true)] {
        let mut args = vec!["client", addr, "--json", "--ca", ca];
        if utc {
            args.push("--utc");
        }
        args.extend(["watch", "--no-gi", "--for", "350ms"]);
        let out = run(&args, b"");
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        let rows: Vec<Value> =
            serde_json::Deserializer::from_slice(&out.stdout).into_iter().map(Result::unwrap).filter(|r: &Value| r["kind"] == "point").collect();
        assert!(rows.iter().any(|r| r["ca"] == 2));
        assert_eq!(rows.iter().any(|r| r["ca"] == 1), utc);
        for row in rows {
            assert!(row["time_text"].is_string());
            assert_eq!(row.get("time").is_some(), utc);
            if utc {
                assert!(row["time"].as_str().unwrap().ends_with('Z'));
            }
        }
    }
}
