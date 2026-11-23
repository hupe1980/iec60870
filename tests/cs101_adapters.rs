//! The 101 link under the real runners: `BlockingDriver` over a pseudo-terminal pair (the
//! serial adapter, feature `serial`, Unix) and over loopback TCP (a terminal server), and
//! `TokioDriver` over Tokio TCP (feature `tokio`). Each side runs on its own thread: the
//! master sends a command, the outstation answers with class 1 and class 2 data, and both
//! see their ASDUs acknowledged.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, clippy::many_single_char_names)]

use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant as StdInstant};

use iec60870::cs101::{Class, Config, Cs101Link, Event, LinkAddress, Role};
use iec60870::driver::{BlockingDriver, Transport};

const RTU: LinkAddress = LinkAddress(5);
const COMMAND: &[u8] = &[0x2D, 0x01, 0x06, 0x01, 0x05, 0x00, 0x81];
const EVENT: &[u8] = &[0x01, 0x01, 0x03, 0x01, 0x10, 0x00, 0x01];
const CYCLIC: &[u8] = &[0x0B, 0x01, 0x01, 0x01, 0x20, 0x00, 0x34, 0x12, 0x00];

/// Runs `link` until it has received `want` and seen `acks` acknowledgments, or 10 s pass.
fn run<T: Transport>(mut driver: BlockingDriver<Cs101Link, T>, submit: &[(&[u8], Class)], want: &[&[u8]], acks: usize) -> Vec<Event> {
    for (asdu, class) in submit {
        driver.with(|link, now| link.submit(asdu, *class, now)).unwrap();
    }
    let start = StdInstant::now();
    let mut events = Vec::new();
    loop {
        let got = events.iter().filter(|e| matches!(e, Event::Asdu { asdu, .. } if want.contains(&asdu.as_slice()))).count();
        let acked = events.iter().filter(|e| matches!(e, Event::Acknowledged { .. })).count();
        if got == want.len() && acked >= acks {
            // Keep answering a little longer so the peer sees its last confirmation.
            let until = StdInstant::now() + Duration::from_millis(300);
            while StdInstant::now() < until {
                let _ = driver.poll_event(Duration::from_millis(20));
            }
            return events;
        }
        assert!(start.elapsed() < Duration::from_secs(10), "timed out: {events:?}");
        if let Some(e) = driver.poll_event(Duration::from_millis(20)).unwrap() {
            events.push(e);
        }
    }
}

fn config() -> Config {
    Config { poll_interval: Duration::from_millis(20), ..Config::default() }
}

fn unbalanced<T: Transport + Send + 'static>(master: T, outstation: T) {
    let m =
        thread::spawn(move || run(BlockingDriver::new(Cs101Link::primary(&[RTU], config()).unwrap(), master), &[(COMMAND, Class::One)], &[EVENT, CYCLIC], 1));
    let s = thread::spawn(move || {
        run(BlockingDriver::new(Cs101Link::secondary(RTU, config()).unwrap(), outstation), &[(EVENT, Class::One), (CYCLIC, Class::Two)], &[COMMAND], 2)
    });
    let m = m.join().unwrap();
    let s = s.join().unwrap();
    assert!(m.contains(&Event::Started { station: RTU }));
    assert!(s.contains(&Event::Started { station: RTU }));
    assert!(m.contains(&Event::Acknowledged { station: RTU, class: Class::One, count: 1 }));
    assert!(s.contains(&Event::Acknowledged { station: RTU, class: Class::Two, count: 1 }));
}

fn balanced<T: Transport + Send + 'static>(a: T, b: T) {
    let (x, y) = (LinkAddress(1), LinkAddress(2));
    let m = thread::spawn(move || {
        run(BlockingDriver::new(Cs101Link::balanced(Role::Controlling, x, y, config()).unwrap(), a), &[(COMMAND, Class::One)], &[EVENT], 1)
    });
    let s = thread::spawn(move || {
        run(BlockingDriver::new(Cs101Link::balanced(Role::Controlled, y, x, config()).unwrap(), b), &[(EVENT, Class::One)], &[COMMAND], 1)
    });
    let m = m.join().unwrap();
    let s = s.join().unwrap();
    assert!(m.contains(&Event::Asdu { station: y, asdu: EVENT.to_vec() }));
    assert!(s.contains(&Event::Asdu { station: x, asdu: COMMAND.to_vec() }));
}

fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (b, _) = listener.accept().unwrap();
    a.set_nodelay(true).unwrap();
    b.set_nodelay(true).unwrap();
    (a, b)
}

#[test]
fn unbalanced_over_tcp() {
    let (a, b) = tcp_pair();
    unbalanced(a, b);
}

#[test]
fn balanced_over_tcp() {
    let (a, b) = tcp_pair();
    balanced(a, b);
}

#[cfg(all(feature = "serial", unix))]
mod serial {
    use iec60870::cs101::SerialTransport;
    use serialport::{SerialPort, TTYPort};

    fn pty_pair() -> (SerialTransport, SerialTransport) {
        let (a, b) = TTYPort::pair().expect("a pseudo-terminal pair");
        let (a, b): (Box<dyn SerialPort>, Box<dyn SerialPort>) = (Box::new(a), Box::new(b));
        (SerialTransport(a), SerialTransport(b))
    }

    #[test]
    fn unbalanced_over_a_pty_pair() {
        let (a, b) = pty_pair();
        super::unbalanced(a, b);
    }

    #[test]
    fn balanced_over_a_pty_pair() {
        let (a, b) = pty_pair();
        super::balanced(a, b);
    }

    #[test]
    fn open_serial_reports_a_missing_port() {
        let link = iec60870::cs101::Cs101Link::secondary(super::RTU, super::config()).unwrap();
        assert!(iec60870::cs101::open_serial("/dev/does-not-exist-iec60870", 9600, link).is_err());
    }
}

#[cfg(feature = "tokio")]
#[test]
fn unbalanced_under_tokio() {
    use iec60870::driver::TokioDriver;

    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (a, b) = tokio::join!(tokio::net::TcpStream::connect(addr), listener.accept());
        let mut master = TokioDriver::new(Cs101Link::primary(&[RTU], config()).unwrap(), a.unwrap());
        let mut outstation = TokioDriver::new(Cs101Link::secondary(RTU, config()).unwrap(), b.unwrap().0);
        outstation.with(|l, now| l.submit(EVENT, Class::One, now)).unwrap();
        let mut got = None;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while got.is_none() {
            assert!(tokio::time::Instant::now() < deadline, "timed out");
            tokio::select! {
                e = master.next_event() => if let Some(Event::Asdu { asdu, .. }) = e.unwrap() { got = Some(asdu) },
                e = outstation.next_event() => { e.unwrap(); }
            }
        }
        assert_eq!(got.as_deref(), Some(EVENT));
    });
}
