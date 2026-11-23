//! The blocking runner over a std byte stream.

use std::collections::VecDeque;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::time::{Duration, Instant as StdInstant};
use std::vec::Vec;

use super::{Output, Protocol};
use crate::time::Instant;

const READ_BUF: usize = 4096;

/// A blocking byte stream a [`BlockingDriver`] can run a core over: a `TcpStream`, a serial
/// port, a TLS stream wrapping either.
pub trait Transport: Read + Write {
    /// Bounds the next reads: `None` blocks until data arrives. A read that times out
    /// returns `WouldBlock` or `TimedOut`.
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()>;

    /// Ends the stream once the core has closed (default: nothing to do).
    fn shutdown(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Transport for TcpStream {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        TcpStream::set_read_timeout(self, timeout)
    }

    fn shutdown(&mut self) -> io::Result<()> {
        match TcpStream::shutdown(self, Shutdown::Both) {
            Err(e) if e.kind() == ErrorKind::NotConnected => Ok(()),
            other => other,
        }
    }
}

/// Runs a [`Protocol`] over a blocking [`Transport`], on the system's monotonic clock.
///
/// The core's clock starts at zero when the driver is built. Commands go to the core through
/// [`with`](Self::with) (or the protocol's own conveniences, such as
/// `BlockingDriver::submit` for the 104 link); what they transmit is written by the next
/// [`next_event`](Self::next_event) or [`poll_event`](Self::poll_event).
#[derive(Debug)]
pub struct BlockingDriver<P: Protocol, T> {
    protocol: P,
    transport: T,
    epoch: StdInstant,
    deadline: Option<Instant>,
    events: VecDeque<P::Event>,
    buf: Vec<u8>,
    finished: bool,
}

impl<P: Protocol, T: Transport> BlockingDriver<P, T> {
    /// Takes over `transport`, already connected, and starts the core's clock.
    pub fn new(protocol: P, transport: T) -> Self {
        let mut driver = BlockingDriver {
            protocol,
            transport,
            epoch: StdInstant::now(),
            deadline: None,
            events: VecDeque::new(),
            buf: std::vec![0; READ_BUF],
            finished: false,
        };
        let now = driver.now();
        driver.protocol.handle_timeout(now);
        driver
    }

    /// The core's current time.
    pub fn now(&self) -> Instant {
        let elapsed = self.epoch.elapsed();
        Instant::from_nanos(u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX))
    }

    /// Runs `f` on the core with the current time — for commands that take `now`.
    pub fn with<R>(&mut self, f: impl FnOnce(&mut P, Instant) -> R) -> R {
        let now = self.now();
        f(&mut self.protocol, now)
    }

    /// The core.
    pub fn protocol(&self) -> &P {
        &self.protocol
    }

    /// The core, mutably (commands that take `now` are easier through [`with`](Self::with)).
    pub fn protocol_mut(&mut self) -> &mut P {
        &mut self.protocol
    }

    /// The transport.
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// The core and the transport.
    pub fn into_parts(self) -> (P, T) {
        (self.protocol, self.transport)
    }

    /// Drives I/O until the core reports an event and returns it; `Ok(None)` once the core
    /// has closed, its last output is written and the transport is shut down. An I/O error
    /// is returned after the core was told the transport is gone.
    pub fn next_event(&mut self) -> io::Result<Option<P::Event>> {
        self.drive(None)
    }

    /// Like [`next_event`](Self::next_event), but returns `Ok(None)` after `max_wait`
    /// without an event as well — for a loop that also has other work. The two `None`s are
    /// told apart by [`Protocol::is_closed`].
    pub fn poll_event(&mut self, max_wait: Duration) -> io::Result<Option<P::Event>> {
        let until = self.now() + max_wait;
        self.drive(Some(until))
    }

    fn drive(&mut self, until: Option<Instant>) -> io::Result<Option<P::Event>> {
        loop {
            if let Err(e) = self.flush() {
                let now = self.now();
                self.protocol.handle_disconnect(now);
                self.drain_events_only();
                return Err(e);
            }
            if self.protocol.is_closed() && !self.finished {
                // The last frames are written; end the stream before reporting the close.
                self.finished = true;
                let _ = self.transport.flush();
                let _ = self.transport.shutdown();
            }
            if let Some(event) = self.events.pop_front() {
                return Ok(Some(event));
            }
            if self.protocol.is_closed() {
                return Ok(None);
            }
            let now = self.now();
            if let Some(until) = until
                && now >= until
            {
                return Ok(None);
            }
            if self.deadline.is_some_and(|d| now >= d) {
                self.deadline = None;
                self.protocol.handle_timeout(now);
                continue;
            }
            let wake = [self.deadline, until].into_iter().flatten().min();
            let timeout = wake.map(|w| w.saturating_duration_since(now).max(Duration::from_millis(1)));
            self.transport.set_read_timeout(timeout)?;
            match self.transport.read(&mut self.buf) {
                Ok(0) => {
                    let now = self.now();
                    self.protocol.handle_disconnect(now);
                }
                Ok(n) => {
                    let now = self.now();
                    self.protocol.handle_input(self.buf.get(..n).unwrap_or_default(), now);
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted) => {
                    let now = self.now();
                    self.protocol.handle_timeout(now);
                }
                Err(e) => {
                    let now = self.now();
                    self.protocol.handle_disconnect(now);
                    self.drain_events_only();
                    return Err(e);
                }
            }
        }
    }

    /// Writes every pending transmit, queues the events, records the deadline.
    fn flush(&mut self) -> io::Result<()> {
        let mut wrote = false;
        while let Some(output) = self.protocol.poll_output() {
            match output {
                Output::Transmit(bytes) => {
                    if !self.finished {
                        self.transport.write_all(&bytes)?;
                        wrote = true;
                    }
                }
                Output::Event(event) => self.events.push_back(event),
                Output::Deadline(at) => self.deadline = Some(at),
            }
        }
        if wrote {
            self.transport.flush()?;
        }
        Ok(())
    }

    fn drain_events_only(&mut self) {
        while let Some(output) = self.protocol.poll_output() {
            if let Output::Event(event) = output {
                self.events.push_back(event);
            }
        }
        self.finished = true;
    }
}
