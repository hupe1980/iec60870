//! One integration suite, run over both runners on real loopback TCP: the blocking
//! `BlockingDriver` and the Tokio `TokioDriver` (each side on its own thread; the Tokio side
//! on its own current-thread runtime, with `poll` cancelling `next_event` by timeout — which
//! exercises its cancel safety). Plus both runners over a non-TCP stream.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
#![allow(clippy::doc_markdown, clippy::too_many_lines, clippy::assert_is_empty, clippy::cast_lossless)]

use std::io::{self, Read};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant as StdInstant};

use iec60870::cs104::{self, Awaiting, CloseReason, CommandError, Config, Cs104Link, Event, Role, SubmitError};
use iec60870::driver::{BlockingDriver, TokioDriver, Transport};

#[derive(Clone, Copy, Debug)]
enum Kind {
    Blocking,
    Tokio,
}

/// The suite's view of a runner, the same for both.
trait Side: Send {
    fn next_event(&mut self) -> Option<Event>;
    fn poll(&mut self, max_wait: Duration) -> Option<Event>;
    fn submit(&mut self, asdu: &[u8]) -> Result<(), SubmitError>;
    fn start(&mut self) -> Result<(), CommandError>;
    fn stop(&mut self) -> Result<(), CommandError>;
    fn close(&mut self);
    fn closed(&self) -> bool;
}

impl<T: Transport + Send> Side for BlockingDriver<Cs104Link, T> {
    fn next_event(&mut self) -> Option<Event> {
        BlockingDriver::next_event(self).unwrap_or(None)
    }
    fn poll(&mut self, max_wait: Duration) -> Option<Event> {
        self.poll_event(max_wait).unwrap_or(None)
    }
    fn submit(&mut self, asdu: &[u8]) -> Result<(), SubmitError> {
        BlockingDriver::submit(self, asdu)
    }
    fn start(&mut self) -> Result<(), CommandError> {
        BlockingDriver::start(self)
    }
    fn stop(&mut self) -> Result<(), CommandError> {
        BlockingDriver::stop(self)
    }
    fn close(&mut self) {
        self.protocol_mut().close();
    }
    fn closed(&self) -> bool {
        self.protocol().is_closed()
    }
}

struct TokioSide<T> {
    rt: tokio::runtime::Runtime,
    driver: TokioDriver<Cs104Link, T>,
}

impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Side for TokioSide<T> {
    fn next_event(&mut self) -> Option<Event> {
        self.rt.block_on(self.driver.next_event()).unwrap_or(None)
    }
    fn poll(&mut self, max_wait: Duration) -> Option<Event> {
        let TokioSide { rt, driver } = self;
        rt.block_on(async { tokio::time::timeout(max_wait, driver.next_event()).await }).ok().and_then(|r| r.unwrap_or(None))
    }
    fn submit(&mut self, asdu: &[u8]) -> Result<(), SubmitError> {
        self.driver.submit(asdu)
    }
    fn start(&mut self) -> Result<(), CommandError> {
        self.driver.start()
    }
    fn stop(&mut self) -> Result<(), CommandError> {
        self.driver.stop()
    }
    fn close(&mut self) {
        self.driver.protocol_mut().close();
    }
    fn closed(&self) -> bool {
        self.driver.protocol().is_closed()
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
}

fn fast() -> Config {
    Config { k: 12, w: 8, t0: Duration::from_secs(2), t1: Duration::from_millis(1000), t2: Duration::from_millis(200), t3: Duration::from_millis(400) }
}

/// A listening controlled side and a connected controlling side of `kind`, with configs.
fn pair(kind: Kind, server: Config, client: Config) -> (Box<dyn Side>, Box<dyn Side>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    match kind {
        Kind::Blocking => {
            let accept = thread::spawn(move || cs104::accept(&listener, server).unwrap().0);
            let client = cs104::connect(addr, client).unwrap();
            (Box::new(accept.join().unwrap()), Box::new(client))
        }
        Kind::Tokio => {
            listener.set_nonblocking(true).unwrap();
            let accept = thread::spawn(move || {
                let rt = runtime();
                let driver = rt.block_on(async {
                    let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                    cs104::accept_async(&listener, server).await.unwrap().0
                });
                TokioSide { rt, driver }
            });
            let rt = runtime();
            let driver = rt.block_on(cs104::connect_async(addr, client)).unwrap();
            (Box::new(accept.join().unwrap()), Box::new(TokioSide { rt, driver }))
        }
    }
}

fn asdu(n: u32) -> Vec<u8> {
    let mut v = vec![0x64, 0x01, 0x06, 0x00, 0x01, 0x00];
    v.extend(n.to_le_bytes());
    v
}

/// Waits for an event matching `want`, failing after `within`.
fn expect(side: &mut dyn Side, within: Duration, want: impl Fn(&Event) -> bool) -> Event {
    let until = StdInstant::now() + within;
    while StdInstant::now() < until {
        if let Some(e) = side.poll(Duration::from_millis(20))
            && want(&e)
        {
            return e;
        }
    }
    panic!("no matching event within {within:?}");
}

/// Submits `items` (retrying on back-pressure) while collecting what arrives, until every
/// item is acknowledged and `expect_in` items were received.
fn exchange(side: &mut dyn Side, items: u32, expect_in: u32) -> (Vec<u32>, u32) {
    let mut next = 0;
    let mut acked = 0;
    let mut received = Vec::new();
    let mut full = 0;
    let until = StdInstant::now() + Duration::from_secs(20);
    while acked < items || received.len() < expect_in as usize {
        assert!(StdInstant::now() < until, "exchange stalled: sent {next}, acked {acked}, received {}", received.len());
        while next < items {
            match side.submit(&asdu(next)) {
                Ok(()) => next += 1,
                Err(SubmitError::WindowFull) => {
                    full += 1;
                    break;
                }
                Err(e) => panic!("{e}"),
            }
        }
        match side.poll(Duration::from_millis(20)) {
            Some(Event::Asdu(a)) => received.push(u32::from_le_bytes(a[6..10].try_into().unwrap())),
            Some(Event::Acknowledged { count }) => acked += u32::from(count),
            Some(Event::Closed(r)) => panic!("closed: {r} (sent {next}, acked {acked}, received {})", received.len()),
            _ => {}
        }
    }
    // Keep driving for longer than t2, so the last frames received get acknowledged.
    let linger = StdInstant::now() + Duration::from_millis(500);
    while StdInstant::now() < linger {
        assert!(!matches!(side.poll(Duration::from_millis(20)), Some(Event::Closed(_))));
    }
    (received, full)
}

fn start(server: &mut dyn Side, client: &mut dyn Side) {
    client.start().unwrap();
    let s = thread::scope(|scope| {
        let h = scope.spawn(|| expect(server, Duration::from_secs(3), |e| *e == Event::Started));
        expect(client, Duration::from_secs(3), |e| *e == Event::Started);
        h.join().unwrap()
    });
    assert_eq!(s, Event::Started);
}

fn both(scenario: fn(Kind)) {
    scenario(Kind::Blocking);
    scenario(Kind::Tokio);
}

#[test]
fn start_and_exchange_in_both_directions() {
    both(|kind| {
        let (mut server, mut client) = pair(kind, fast(), fast());
        start(&mut *server, &mut *client);
        let (from_client, from_server) = thread::scope(|scope| {
            let h = scope.spawn(|| exchange(&mut *server, 60, 40).0);
            let r = exchange(&mut *client, 40, 60).0;
            (h.join().unwrap(), r)
        });
        assert_eq!(from_client, (0..40).collect::<Vec<_>>(), "{kind:?}");
        assert_eq!(from_server, (0..60).collect::<Vec<_>>(), "{kind:?}");
    });
}

#[test]
fn back_pressure_resolves_through_acknowledgments() {
    both(|kind| {
        let (mut server, mut client) = pair(kind, Config { k: 2, ..fast() }, Config { w: 8, ..fast() });
        start(&mut *server, &mut *client);
        let (full, got) = thread::scope(|scope| {
            let h = scope.spawn(|| exchange(&mut *client, 0, 20).0);
            let full = exchange(&mut *server, 20, 0).1;
            (full, h.join().unwrap())
        });
        assert!(full > 0, "{kind:?}: k = 2 must have pushed back");
        assert_eq!(got, (0..20).collect::<Vec<_>>());
    });
}

#[test]
fn testfr_keeps_an_idle_link_open() {
    both(|kind| {
        let (mut server, mut client) = pair(kind, fast(), fast());
        start(&mut *server, &mut *client);
        thread::scope(|scope| {
            scope.spawn(|| {
                let until = StdInstant::now() + Duration::from_millis(2500);
                while StdInstant::now() < until {
                    assert!(!matches!(server.poll(Duration::from_millis(50)), Some(Event::Closed(_))));
                }
            });
            let until = StdInstant::now() + Duration::from_millis(2500);
            while StdInstant::now() < until {
                assert!(!matches!(client.poll(Duration::from_millis(50)), Some(Event::Closed(_))), "{kind:?}");
            }
        });
        assert!(!server.closed() && !client.closed());
    });
}

#[test]
fn stop_with_outstanding_frames_delivers_them_first() {
    both(|kind| {
        let (mut server, mut client) = pair(kind, Config { w: 50, t2: Duration::from_millis(900), ..fast() }, fast());
        start(&mut *server, &mut *client);
        for n in 0..5 {
            server.submit(&asdu(n)).unwrap();
        }
        let (server_events, client_events) = thread::scope(|scope| {
            let h = scope.spawn(|| {
                let mut events = Vec::new();
                let until = StdInstant::now() + Duration::from_secs(3);
                while StdInstant::now() < until && !events.contains(&Event::Stopped) {
                    events.extend(server.poll(Duration::from_millis(20)));
                }
                events
            });
            // Let the frames arrive, then stop before anything acknowledged them.
            let mut events = Vec::new();
            while events.iter().filter(|e| matches!(e, Event::Asdu(_))).count() < 5 {
                events.extend(client.poll(Duration::from_millis(20)));
            }
            client.stop().unwrap();
            events.push(expect(&mut *client, Duration::from_secs(3), |e| *e == Event::Stopped));
            (h.join().unwrap(), events)
        });
        assert_eq!(client_events.iter().filter(|e| matches!(e, Event::Asdu(_))).count(), 5, "{kind:?}");
        let acked: u16 = server_events.iter().map(|e| if let Event::Acknowledged { count } = e { *count } else { 0 }).sum();
        assert_eq!(acked, 5, "{kind:?}: acknowledged before the con");
        assert_eq!(server_events.last(), Some(&Event::Stopped));
    });
}

#[test]
fn a_peer_close_is_reported_as_peer_closed() {
    both(|kind| {
        let (mut server, mut client) = pair(kind, fast(), fast());
        start(&mut *server, &mut *client);
        client.close();
        assert_eq!(client.next_event(), Some(Event::Closed(CloseReason::Local)));
        assert_eq!(client.next_event(), None);
        assert_eq!(expect(&mut *server, Duration::from_secs(3), |e| matches!(e, Event::Closed(_))), Event::Closed(CloseReason::PeerClosed), "{kind:?}");
        assert_eq!(server.next_event(), None);
    });
}

#[test]
fn a_silent_peer_ends_in_t1_expired() {
    both(|kind| {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        // Accepts and reads, never answers.
        let silent = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 64];
            while s.read(&mut buf).is_ok_and(|n| n > 0) {}
        });
        let config = Config { t1: Duration::from_millis(300), t2: Duration::from_millis(100), ..fast() };
        let mut client: Box<dyn Side> = match kind {
            Kind::Blocking => Box::new(cs104::connect(addr, config).unwrap()),
            Kind::Tokio => {
                let rt = runtime();
                let driver = rt.block_on(cs104::connect_async(addr, config)).unwrap();
                Box::new(TokioSide { rt, driver })
            }
        };
        let began = StdInstant::now();
        client.start().unwrap();
        assert_eq!(client.next_event(), Some(Event::Closed(CloseReason::T1Expired(Awaiting::StartDtCon))));
        assert!(began.elapsed() >= Duration::from_millis(290), "{kind:?}");
        assert_eq!(client.next_event(), None);
        silent.join().unwrap();
    });
}

#[test]
fn an_invalid_configuration_and_an_unreachable_peer_are_errors() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let bad = Config { k: 0, ..fast() };
    assert_eq!(cs104::connect(addr, bad).err().map(|e| e.kind()), Some(io::ErrorKind::InvalidInput));
    drop(listener);
    assert!(cs104::connect(addr, fast()).is_err(), "nothing listens any more");
    let rt = runtime();
    assert!(rt.block_on(cs104::connect_async(addr, fast())).is_err());
}

#[test]
fn connect_gives_up_after_t0() {
    // A non-routable address: the connection attempt hangs (or fails at once where the host
    // has no route). Either way it must not outlive t0 by much.
    let addr: std::net::SocketAddr = "10.255.255.1:2404".parse().unwrap();
    let config = Config { t0: Duration::from_millis(300), ..fast() };
    let began = StdInstant::now();
    assert!(cs104::connect(addr, config).is_err());
    assert!(began.elapsed() < Duration::from_millis(1500), "blocking connect took {:?}", began.elapsed());
    let began = StdInstant::now();
    assert!(runtime().block_on(cs104::connect_async(addr, config)).is_err());
    assert!(began.elapsed() < Duration::from_millis(1500), "async connect took {:?}", began.elapsed());
}

/// A non-TCP blocking transport: a Unix socket pair behind a newtype.
#[cfg(unix)]
struct Pipe(std::os::unix::net::UnixStream);

#[cfg(unix)]
impl Read for Pipe {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

#[cfg(unix)]
impl io::Write for Pipe {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

#[cfg(unix)]
impl Transport for Pipe {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        self.0.set_read_timeout(timeout)
    }
}

#[test]
fn both_runners_drive_the_link_over_streams_that_are_not_tcp() {
    #[cfg(unix)]
    {
        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut server: Box<dyn Side> = Box::new(BlockingDriver::new(Cs104Link::new(Role::Controlled, fast()).unwrap(), Pipe(a)));
        let mut client: Box<dyn Side> = Box::new(BlockingDriver::new(Cs104Link::new(Role::Controlling, fast()).unwrap(), Pipe(b)));
        start(&mut *server, &mut *client);
        let got = thread::scope(|scope| {
            let h = scope.spawn(|| exchange(&mut *server, 0, 10).0);
            exchange(&mut *client, 10, 0);
            h.join().unwrap()
        });
        assert_eq!(got, (0..10).collect::<Vec<_>>());
    }
    // Tokio: an in-memory duplex pipe, both ends on one runtime and one task each.
    let rt = runtime();
    rt.block_on(async {
        let (a, b) = tokio::io::duplex(64);
        let mut server = TokioDriver::new(Cs104Link::new(Role::Controlled, fast()).unwrap(), a);
        let mut client = TokioDriver::new(Cs104Link::new(Role::Controlling, fast()).unwrap(), b);
        client.start().unwrap();
        let server_task = async move {
            let mut got = Vec::new();
            while let Some(event) = server.next_event().await.unwrap() {
                match event {
                    Event::Asdu(a) => got.push(a),
                    Event::Closed(_) => break,
                    _ => {}
                }
            }
            got
        };
        let client_task = async move {
            assert_eq!(client.next_event().await.unwrap(), Some(Event::Started));
            for n in 0..10 {
                client.submit(&asdu(n)).unwrap();
            }
            let mut acked = 0;
            while acked < 10 {
                if let Some(Event::Acknowledged { count }) = client.next_event().await.unwrap() {
                    acked += count;
                }
            }
            client.protocol_mut().close();
            while client.next_event().await.unwrap().is_some() {}
        };
        let (got, ()) = tokio::join!(server_task, client_task);
        assert_eq!(got, (0..10).map(asdu).collect::<Vec<_>>());
    });
}

#[test]
fn the_blocking_driver_reports_its_parts() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let h = thread::spawn(move || listener.accept().unwrap());
    let mut client = cs104::connect(addr, fast()).unwrap();
    let _peer = h.join().unwrap();
    assert!(client.now() < iec60870::time::Instant::from_millis(5000));
    assert_eq!(client.with(|link, _| link.role()), Role::Controlling);
    assert!(client.transport().peer_addr().is_ok());
    assert!(!client.can_send());
    let (link, stream): (Cs104Link, TcpStream) = client.into_parts();
    assert_eq!(link.role(), Role::Controlling);
    drop(stream);
}
