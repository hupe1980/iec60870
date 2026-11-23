//! Mutual TLS negotiation and station procedures with an independent lib60870-C peer.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::doc_markdown)]
#[path = "support/docker.rs"]
mod docker;
mod tls_support;

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Command as Process, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use iec60870::prelude::*;
use iec60870::tls::{SecurityEvent, TlsClientConfig, TlsServerConfig};
use iec60870::{Client, Server};
use tls_support::{Identity, Pki};

const CA: CommonAddress = CommonAddress(1);

fn peer(version: &str, role: &str, identity: &Identity, ca: &str) -> (Process, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    for (file, data) in [("ca.pem".into(), ca), (format!("{role}.pem"), &identity.cert), (format!("{role}.key"), &identity.key)] {
        std::fs::write(dir.path().join(file), data).unwrap();
    }
    let mut cmd = Process::new("docker");
    cmd.args(["run", "--rm", "--init", "-v", &format!("{}:/pki:ro", dir.path().display()), "-e", &format!("PEER_TLS_VERSION={version}")]);
    (cmd, dir)
}

fn recorder() -> (Arc<Mutex<Vec<SecurityEvent>>>, impl Fn(&SecurityEvent) + Send + Sync + 'static) {
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&events);
    (events, move |event| sink.lock().unwrap().push(event.clone()))
}

fn verified(events: &[SecurityEvent], protocol: &str) {
    assert!(
        events
            .iter()
            .any(|e| matches!(e, SecurityEvent::Established { version, peer_subject: Some(_), suite, .. } if *version == protocol && suite.contains("GCM"))),
        "{events:?}"
    );
}

fn start_server(cmd: &mut Process, image: &str) -> (u16, std::process::Child) {
    let name = format!("iec60870-interop-tls-{}", std::process::id());
    let mut child = cmd
        .args(["--name", &name, "-p", "127.0.0.1::19998", image, "station-server", "-p", "19998", "--duration", "6000"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let mut ready = String::new();
    output.read_line(&mut ready).unwrap();
    assert_eq!(ready.trim(), "READY");
    child.stdout = Some(output.into_inner());
    (docker::published_port(&name, 19998), child)
}

fn connect(port: u16, tls: &TlsClientConfig) -> Result<Client, iec60870::Error> {
    let start = std::time::Instant::now();
    loop {
        match Client::connect_tls(("127.0.0.1", port), "localhost", tls) {
            Err(iec60870::Error::Io(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused && start.elapsed() < std::time::Duration::from_secs(2) => {
                std::thread::sleep(std::time::Duration::from_millis(40));
            }
            result => return result,
        }
    }
}

fn tls12_profile_deviations(image: &str, pki: &Pki) {
    let tls = TlsClientConfig::from_pem(pki.ca.cert.as_bytes(), pki.client.cert.as_bytes(), pki.client.key.as_bytes()).unwrap();
    for policy in ["cbc", "renegotiate"] {
        let (mut cmd, _dir) = peer("1.2", "server", &pki.server, &pki.ca.cert);
        cmd.args(["-e", &format!("PEER_TLS_POLICY={policy}")]);
        let (port, mut child) = start_server(&mut cmd, image);
        let connection = connect(port, &tls);
        if policy == "cbc" {
            let Err(iec60870::Error::Io(e)) = connection else { panic!("expected TLS negotiation failure") };
            assert!(e.get_ref().and_then(|e| e.downcast_ref::<iec60870::tls::TlsError>()).is_some(), "{e}");
        } else {
            let mut client = connection.unwrap();
            client.start().unwrap();
            std::thread::sleep(std::time::Duration::from_millis(1700));
            let result = client.read(CA, Ioa(200));
            assert!(matches!(&result, Err(iec60870::Error::Io(e)) if e.kind() == std::io::ErrorKind::InvalidData), "{result:?}");
        }
        assert!(child.wait().unwrap().success());
    }
}

fn rust_client(image: &str, pki: &Pki, version: &str, protocol: &str) {
    let (mut cmd, _dir) = peer(version, "server", &pki.server, &pki.ca.cert);
    let (port, mut child) = start_server(&mut cmd, image);
    let (events, hook) = recorder();
    let tls = TlsClientConfig::from_pem(pki.ca.cert.as_bytes(), pki.client.cert.as_bytes(), pki.client.key.as_bytes()).unwrap().on_event(hook);
    let foreign = TlsClientConfig::from_pem(pki.ca.cert.as_bytes(), pki.stranger.cert.as_bytes(), pki.stranger.key.as_bytes()).unwrap();
    if let Ok(mut stranger) = connect(port, &foreign) {
        assert!(stranger.start().is_err());
    }
    let mut client = connect(port, &tls).unwrap();
    client.start().unwrap();
    let replies: Vec<_> = client.interrogate(CA).unwrap().collect::<Result<_, _>>().unwrap();
    assert!(matches!(replies.last(), Some(Event::InterrogationComplete { .. })));
    assert!(replies.iter().any(|e| matches!(e, Event::Point(p) if p.ioa == Ioa(200))));
    client.command(CA, Ioa(5000), Command::single(true)).unwrap().wait().unwrap();
    client.stop().unwrap();
    drop(client);
    verified(&events.lock().unwrap(), protocol);
    assert!(child.wait().unwrap().success());
}

fn rust_server(image: &str, pki: &Pki, version: &str, protocol: &str) {
    let (events, hook) = recorder();
    let tls = TlsServerConfig::from_pem(pki.ca.cert.as_bytes(), pki.server.cert.as_bytes(), pki.server.key.as_bytes()).unwrap().on_event(hook);
    let mut db = Database::new();
    db.insert(CA, Ioa(100), true);
    let _ = db.command(CA, Ioa(5000), CommandKind::Single).mode(CommandMode::DirectOrSelect);
    // Keep the independent peer’s socket-readiness loop active during the test.
    let link = iec60870::cs104::Config { t3: std::time::Duration::from_secs(1), ..Default::default() };
    let server = Server::builder().link(link).tls(tls).bind("127.0.0.1:0", db).unwrap();
    let port = server.local_addr().unwrap().port();
    let commands = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&commands);
    let handle = server
        .spawn(move |_: &CommandRequest| {
            count.fetch_add(1, Ordering::Relaxed);
            Decision::Accept
        })
        .unwrap();
    let (mut cmd, _dir) = peer(version, "client", &pki.client, &pki.ca.cert);
    let host = if cfg!(target_os = "linux") {
        cmd.args(["--network", "host"]);
        "127.0.0.1"
    } else {
        "host.docker.internal"
    };
    let out = cmd.args([image, "station-client", "-h", host, "-p", &port.to_string()]).output().unwrap();
    let log = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{log}\n{}", String::from_utf8_lossy(&out.stderr));
    for expected in ["ACTIVATED", "ASDU 1 20 0 1 100 1", "ASDU 100 10 0 1 0 1", "ASDU 45 10 0 1 5000 1"] {
        assert!(log.lines().any(|l| l == expected), "{log}");
    }
    assert_eq!(commands.load(Ordering::Relaxed), 1);
    verified(&events.lock().unwrap(), protocol);
    handle.shutdown();
}

#[test]
fn mutual_tls_with_lib60870_in_both_roles() {
    let Some(image) = docker::image(
        "TLS interop",
        "iec60870-interop-tls",
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/interop"),
        "Dockerfile.tls",
        &["tls_peer.h", "station_client.c", "station_server.c"],
    ) else {
        return;
    };
    let pki = Pki::new();
    for (version, protocol) in [("1.2", "TLSv1_2"), ("1.3", "TLSv1_3")] {
        rust_client(&image, &pki, version, protocol);
        rust_server(&image, &pki, version, protocol);
    }
    tls12_profile_deviations(&image, &pki);
}
