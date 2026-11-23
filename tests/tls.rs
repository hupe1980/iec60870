//! IEC 62351-3 TLS for 104 over loopback: mutual authentication, every refusal named and
//! reported before any 104 frame, the handshake bounded by t0 — at link level and station
//! level, blocking and Tokio. Certificates are generated at test time.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
#![allow(clippy::too_many_lines, clippy::doc_markdown, clippy::similar_names)]

mod tls_support;

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use iec60870::cs104::{self, Config, Event as LinkEvent};
use iec60870::prelude::*;
use iec60870::station::ServerEvent;
use iec60870::tls::{CIPHER_SUITES, PROTOCOL_VERSIONS, SecurityEvent, TlsClientConfig, TlsError, TlsServerConfig, rustls};
use iec60870::{AsyncClient, Client, Server};
use tls_support::Pki;

type Events = Arc<Mutex<Vec<SecurityEvent>>>;

fn recorder() -> (Events, impl Fn(&SecurityEvent) + Send + Sync + 'static) {
    let events = Events::default();
    let sink = Arc::clone(&events);
    (events, move |e: &SecurityEvent| sink.lock().unwrap().push(e.clone()))
}

fn client_cfg(pki: &Pki) -> TlsClientConfig {
    TlsClientConfig::from_pem(pki.ca.cert.as_bytes(), pki.client.cert.as_bytes(), pki.client.key.as_bytes()).unwrap()
}

fn server_cfg(pki: &Pki) -> TlsServerConfig {
    TlsServerConfig::from_pem(pki.ca.cert.as_bytes(), pki.server.cert.as_bytes(), pki.server.key.as_bytes()).unwrap()
}

fn quick() -> Config {
    Config { t0: Duration::from_secs(2), ..Config::default() }
}

fn tls_cause(e: &std::io::Error) -> TlsError {
    e.get_ref().and_then(|e| e.downcast_ref::<TlsError>()).cloned().unwrap_or_else(|| panic!("not a TLS error: {e:?}"))
}

/// A client configuration that trusts our CA but presents no certificate.
fn anonymous_client(pki: &Pki) -> TlsClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls::pki_types::pem::PemObject::pem_slice_iter(pki.ca.cert.as_bytes()) {
        roots.add(cert.unwrap()).unwrap();
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    TlsClientConfig::from_rustls(Arc::new(config))
}

#[test]
fn the_profile_is_tls12_and_tls13_with_aead_suites_only() {
    let versions: Vec<_> = PROTOCOL_VERSIONS.iter().map(|v| v.version).collect();
    assert_eq!(versions, [rustls::ProtocolVersion::TLSv1_3, rustls::ProtocolVersion::TLSv1_2]);
    let suites: Vec<&str> = CIPHER_SUITES.iter().map(|s| s.suite().as_str().unwrap()).collect();
    assert_eq!(
        suites,
        [
            "TLS13_AES_256_GCM_SHA384",
            "TLS13_AES_128_GCM_SHA256",
            "TLS13_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        ]
    );
    let pki = Pki::new();
    let server = server_cfg(&pki);
    assert_eq!(server.rustls_config().crypto_provider().cipher_suites, CIPHER_SUITES);
    assert_eq!(client_cfg(&pki).rustls_config().crypto_provider().cipher_suites.len(), CIPHER_SUITES.len());
}

#[test]
fn mutual_handshake_then_startdt_and_an_asdu_over_tls() {
    const GI: &[u8] = &[0x64, 1, 6, 0, 1, 0, 0, 0, 0, 0x14];
    let pki = Pki::new();
    let (server_events, on_server) = recorder();
    let (client_events, on_client) = recorder();
    let server_tls = server_cfg(&pki).on_event(on_server);
    let client_tls = client_cfg(&pki).on_event(on_client);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let outstation = thread::spawn(move || {
        let (mut link, _) = cs104::accept_tls(&listener, &server_tls, quick()).unwrap();
        assert_eq!(link.transport().protocol_version(), "TLSv1_3");
        assert!(link.transport().peer_subject().unwrap().contains("CN=master-1"));
        assert_eq!(link.next_event().unwrap(), Some(LinkEvent::Started));
        assert!(matches!(link.next_event().unwrap(), Some(LinkEvent::Asdu(bytes)) if bytes == GI));
        link.submit(&[0x64, 0x01, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x14]).unwrap();
        while let Some(event) = link.next_event().unwrap() {
            if matches!(event, LinkEvent::Closed(_)) {
                break;
            }
        }
    });
    let mut link = cs104::connect_tls(("127.0.0.1", port), "localhost", &client_tls, quick()).unwrap();
    link.start().unwrap();
    assert_eq!(link.next_event().unwrap(), Some(LinkEvent::Started));
    link.submit(GI).unwrap();
    assert_eq!(link.next_event().unwrap(), Some(LinkEvent::Acknowledged { count: 1 }));
    match link.next_event().unwrap() {
        Some(LinkEvent::Asdu(asdu)) => assert_eq!(asdu[..3], [0x64, 0x01, 0x07]),
        other => panic!("{other:?}"),
    }
    assert!(link.transport().cipher_suite().starts_with("TLS13_"));
    link.with(|l, _| l.close());
    while link.next_event().unwrap().is_some() {}
    outstation.join().unwrap();

    let server_events = server_events.lock().unwrap();
    match &server_events[..] {
        [SecurityEvent::Established { version, suite, peer_subject, .. }] => {
            assert_eq!(*version, "TLSv1_3");
            assert!(suite.starts_with("TLS13_AES_256_GCM"), "{suite}");
            assert!(peer_subject.as_deref().unwrap().contains("CN=master-1"));
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(&client_events.lock().unwrap()[..], [SecurityEvent::Established { peer_subject: Some(s), .. }] if s.contains("CN=rtu-1")));
}

#[test]
fn the_server_name_may_be_an_ip_address_in_the_certificate() {
    let pki = Pki::new();
    let server_tls = server_cfg(&pki);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let t = thread::spawn(move || cs104::accept_tls(&listener, &server_tls, quick()).map(|_| ()));
    cs104::connect_tls(("127.0.0.1", port), "127.0.0.1", &client_cfg(&pki), quick()).unwrap();
    t.join().unwrap().unwrap();
}

#[test]
fn a_client_without_a_certificate_is_refused_before_startdt() {
    let pki = Pki::new();
    let (events, on_event) = recorder();
    let server_tls = server_cfg(&pki).on_event(on_event);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let t = thread::spawn(move || cs104::accept_tls(&listener, &server_tls, quick()).map(|_| ()));
    // Over TLS 1.3 the client's side may complete; the server's alert ends it on first use.
    if let Ok(mut link) = cs104::connect_tls(("127.0.0.1", port), "localhost", &anonymous_client(&pki), quick()) {
        link.start().unwrap();
        assert!(!matches!(link.next_event(), Ok(Some(LinkEvent::Started))));
    }
    let err = t.join().unwrap().unwrap_err();
    assert_eq!(tls_cause(&err), TlsError::NoPeerCertificate);
    assert!(matches!(&events.lock().unwrap()[..], [SecurityEvent::Rejected { error: TlsError::NoPeerCertificate, .. }]));
}

#[test]
fn a_client_certificate_from_an_untrusted_ca_is_refused() {
    let pki = Pki::new();
    let (events, on_event) = recorder();
    let server_tls = server_cfg(&pki).on_event(on_event);
    let intruder = TlsClientConfig::from_pem(pki.ca.cert.as_bytes(), pki.stranger.cert.as_bytes(), pki.stranger.key.as_bytes()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let t = thread::spawn(move || cs104::accept_tls(&listener, &server_tls, quick()).map(|_| ()));
    if let Ok(mut link) = cs104::connect_tls(("127.0.0.1", port), "localhost", &intruder, quick()) {
        link.start().unwrap();
        let first = link.next_event();
        assert!(!matches!(first, Ok(Some(LinkEvent::Started))), "{first:?}");
    }
    assert_eq!(tls_cause(&t.join().unwrap().unwrap_err()), TlsError::UnknownIssuer);
    assert!(matches!(&events.lock().unwrap()[..], [SecurityEvent::Rejected { error: TlsError::UnknownIssuer, .. }]));
}

#[test]
fn a_server_certificate_from_an_untrusted_ca_is_refused() {
    let pki = Pki::new();
    let (events, on_event) = recorder();
    let impostor = TlsServerConfig::from_pem(pki.ca.cert.as_bytes(), pki.stranger.cert.as_bytes(), pki.stranger.key.as_bytes()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let t = thread::spawn(move || cs104::accept_tls(&listener, &impostor, quick()).map(|_| ()));
    let err = cs104::connect_tls(("127.0.0.1", port), "localhost", &client_cfg(&pki).on_event(on_event), quick()).unwrap_err();
    assert_eq!(tls_cause(&err), TlsError::UnknownIssuer);
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(matches!(&events.lock().unwrap()[..], [SecurityEvent::Rejected { error: TlsError::UnknownIssuer, .. }]));
    // The server can observe the socket closing before it reads the client's fatal alert.
    let peer = tls_cause(&t.join().unwrap().unwrap_err());
    assert!(
        matches!(
            peer,
            TlsError::AlertReceived(_) | TlsError::Io(std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::UnexpectedEof)
        ),
        "unexpected peer handshake result: {peer:?}"
    );
}

#[test]
fn a_server_certificate_for_another_name_is_refused() {
    let pki = Pki::new();
    let server_tls = server_cfg(&pki);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let t = thread::spawn(move || cs104::accept_tls(&listener, &server_tls, quick()).map(|_| ()));
    let err = cs104::connect_tls(("127.0.0.1", port), "rtu-2.example", &client_cfg(&pki), quick()).unwrap_err();
    assert_eq!(tls_cause(&err), TlsError::NameMismatch);
    assert!(t.join().unwrap().is_err());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let tcp = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let err = client_cfg(&pki).connect(tcp, "not a name!", quick().t0).unwrap_err();
    assert!(matches!(tls_cause(&err), TlsError::InvalidServerName(_)), "{err:?}");
}

#[test]
fn a_silent_peer_times_out_within_t0() {
    let pki = Pki::new();
    let (events, on_event) = recorder();
    let server_tls = server_cfg(&pki).on_event(on_event);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let _silent = TcpStream::connect(addr).unwrap();
    let start = Instant::now();
    let config = Config { t0: Duration::from_millis(300), ..Config::default() };
    let err = cs104::accept_tls(&listener, &server_tls, config).unwrap_err();
    assert_eq!(tls_cause(&err), TlsError::Timeout);
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    assert!(start.elapsed() < Duration::from_secs(2));
    assert!(matches!(&events.lock().unwrap()[..], [SecurityEvent::Rejected { error: TlsError::Timeout, .. }]));
}

#[test]
fn pem_errors_name_the_input_and_debug_shows_no_key() {
    let pki = Pki::new();
    match TlsClientConfig::from_pem_files("/nonexistent/ca.pem", "c.pem", "k.pem") {
        Err(TlsError::Pem { what: "trust anchors", source, .. }) => assert!(source.contains("/nonexistent/ca.pem")),
        other => panic!("{other:?}"),
    }
    match TlsServerConfig::from_pem(pki.ca.cert.as_bytes(), pki.server.cert.as_bytes(), b"not a key") {
        Err(TlsError::Pem { what: "private key", source, .. }) => assert_eq!(source, "memory"),
        other => panic!("{other:?}"),
    }
    match TlsServerConfig::from_pem(b"", pki.server.cert.as_bytes(), pki.server.key.as_bytes()) {
        Err(TlsError::Pem { what: "trust anchors", .. }) => {}
        other => panic!("{other:?}"),
    }
    let malformed = b"-----BEGIN PRIVATE KEY with sensitive data";
    match TlsServerConfig::from_pem(pki.ca.cert.as_bytes(), pki.server.cert.as_bytes(), malformed) {
        Err(TlsError::Pem { reason, .. }) => assert_eq!(reason, "invalid PEM start marker"),
        other => panic!("{other:?}"),
    }
    // A key that does not belong to the certificate.
    assert!(matches!(TlsServerConfig::from_pem(pki.ca.cert.as_bytes(), pki.server.cert.as_bytes(), pki.client.key.as_bytes()), Err(TlsError::Config(_))));

    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();
    for (name, body) in [("ca.pem", &pki.ca.cert), ("c.pem", &pki.client.cert), ("k.pem", &pki.client.key)] {
        std::fs::File::create(dir.join(name)).unwrap().write_all(body.as_bytes()).unwrap();
    }
    let client = TlsClientConfig::from_pem_files(dir.join("ca.pem"), dir.join("c.pem"), dir.join("k.pem")).unwrap();
    let server = server_cfg(&pki);
    let key_body: String = pki.client.key.lines().nth(1).unwrap().into();
    for debug in [format!("{client:?}"), format!("{server:?}")] {
        assert!(!debug.contains("PRIVATE") && !debug.contains(&key_body[..20]), "{debug}");
    }
}

#[tokio::test]
async fn the_tokio_entry_points_handshake_and_refuse_alike() {
    let pki = Pki::new();
    let (events, on_event) = recorder();
    let server_tls = server_cfg(&pki).on_event(on_event);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut link, _) = cs104::accept_tls_async(&listener, &server_tls, quick()).await.unwrap();
        assert_eq!(link.next_event().await.unwrap(), Some(LinkEvent::Started));
        link.submit(&[0x64, 0x01, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x14]).unwrap();
        let _ = link.next_event().await;
        // The second connection is an intruder.
        let err = cs104::accept_tls_async(&listener, &server_tls, quick()).await.unwrap_err();
        assert_eq!(tls_cause(&err), TlsError::UnknownIssuer);
        let _ = cs104::accept_tls_async(&listener, &server_tls, quick()).await.unwrap_err();
    });
    let mut link = cs104::connect_tls_async(("127.0.0.1", port), "localhost", &client_cfg(&pki), quick()).await.unwrap();
    link.start().unwrap();
    assert_eq!(link.next_event().await.unwrap(), Some(LinkEvent::Started));
    assert!(matches!(link.next_event().await.unwrap(), Some(LinkEvent::Asdu(_))));
    drop(link);
    let intruder = TlsClientConfig::from_pem(pki.ca.cert.as_bytes(), pki.stranger.cert.as_bytes(), pki.stranger.key.as_bytes()).unwrap();
    if let Ok(mut l) = cs104::connect_tls_async(("127.0.0.1", port), "localhost", &intruder, quick()).await {
        l.start().unwrap();
        assert!(!matches!(l.next_event().await, Ok(Some(LinkEvent::Started))));
    }
    let wrong = cs104::connect_tls_async(("127.0.0.1", port), "rtu-9.example", &client_cfg(&pki), quick()).await;
    server.await.unwrap();
    assert_eq!(tls_cause(&wrong.unwrap_err()), TlsError::NameMismatch);
    let events = events.lock().unwrap();
    assert!(matches!(events[0], SecurityEvent::Established { .. }));
    assert!(matches!(events[1], SecurityEvent::Rejected { error: TlsError::UnknownIssuer, .. }));
}

const CA: CommonAddress = CommonAddress(1);

fn database() -> Database {
    let mut db = Database::new();
    let _ = db.insert(CA, Ioa(100), true);
    let _ = db.insert(CA, Ioa(200), 21.5f32);
    let _ = db.command(CA, Ioa(5000), CommandKind::Single).mode(CommandMode::DirectOrSelect);
    db
}

#[test]
fn station_client_and_server_over_tls_and_a_refused_client_never_reaches_the_handler() {
    let pki = Pki::new();
    let (events, on_event) = recorder();
    let server = Server::builder().tls(server_cfg(&pki).on_event(on_event)).bind("127.0.0.1:0", database()).unwrap();
    let addr = server.local_addr().unwrap();
    let commands = Arc::new(Mutex::new(0));
    let count = Arc::clone(&commands);
    let handle = server
        .spawn(move |_: &CommandRequest| {
            *count.lock().unwrap() += 1;
            Decision::Accept
        })
        .unwrap();

    // A silent TCP client holds its handshake open; the server still serves the next one.
    let silent = TcpStream::connect(addr).unwrap();

    // An intruder from another CA: no link is attached, no command is executed.
    let intruder = TlsClientConfig::from_pem(pki.ca.cert.as_bytes(), pki.stranger.cert.as_bytes(), pki.stranger.key.as_bytes()).unwrap();
    if let Ok(mut c) = Client::connect_tls(addr, "localhost", &intruder) {
        assert!(c.start().is_err());
    }

    let mut client = Client::connect_tls(addr, "localhost", &client_cfg(&pki)).unwrap();
    client.start().unwrap();
    let points: Vec<_> =
        client.interrogate(CA).unwrap().map(Result::unwrap).filter_map(|e| if let Event::Point(p) = e { Some(p.ioa.0) } else { None }).collect();
    assert_eq!(points, [100, 200]);
    client.command(CA, Ioa(5000), Command::single(false)).unwrap().wait().unwrap();
    assert_eq!(*commands.lock().unwrap(), 1);
    assert_eq!(handle.connections(), 1);
    client.stop().unwrap();
    drop(client);

    let mut started = 0;
    while let Some(e) = handle.next_event(Duration::from_millis(200)) {
        if matches!(e, ServerEvent::Started(_)) {
            started += 1;
        }
    }
    assert_eq!(started, 1, "only the verified client was started");
    let events = events.lock().unwrap();
    assert!(events.iter().any(|e| matches!(e, SecurityEvent::Rejected { error: TlsError::UnknownIssuer, .. })), "{events:?}");
    assert!(events.iter().any(|e| matches!(e, SecurityEvent::Established { peer_subject: Some(s), .. } if s.contains("CN=master-1"))));
    drop(events);
    drop(silent);
    handle.shutdown();
}

#[tokio::test(flavor = "multi_thread")]
async fn async_client_and_server_over_tls() {
    let pki = Pki::new();
    let server = Server::builder().tls(server_cfg(&pki)).bind_async("127.0.0.1:0", database()).await.unwrap();
    let addr = server.local_addr();
    let handle = server.handle();
    tokio::spawn(server.run(|_: &CommandRequest| Decision::Accept));
    let mut client = AsyncClient::connect_tls(addr, "localhost", &client_cfg(&pki)).await.unwrap();
    client.start().await.unwrap();
    let mut replies = client.interrogate(CA).unwrap();
    let mut points = 0;
    while let Some(e) = replies.next().await {
        if matches!(e.unwrap(), Event::Point(_)) {
            points += 1;
        }
    }
    assert_eq!(points, 2);
    client.command(CA, Ioa(5000), Command::single(true)).unwrap().wait().await.unwrap();
    let anonymous = AsyncClient::connect_tls(addr, "localhost", &anonymous_client(&pki)).await;
    if let Ok(mut c) = anonymous {
        assert!(c.start().await.is_err());
    }
    handle.shutdown();
}
