//! The Tokio runner over `AsyncRead + AsyncWrite`.

use std::collections::VecDeque;
use std::io::{self, ErrorKind};
use std::time::Duration;
use std::vec::Vec;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant as TokioInstant;

use super::{Output, Protocol};
use crate::time::Instant;

const READ_BUF: usize = 4096;

/// Runs a [`Protocol`] over a Tokio byte stream (a `TcpStream`, a TLS stream, a duplex
/// pipe), on Tokio's clock — so paused time in tests applies to the core's timers too.
///
/// [`next_event`](Self::next_event) is cancel-safe: the bytes it has yet to write and the
/// events it has yet to return stay in the driver, so it can sit in `tokio::select!` beside
/// the application's own channel:
///
#[cfg_attr(feature = "cs104", doc = "```no_run")]
#[cfg_attr(not(feature = "cs104"), doc = "```ignore")]
/// # async fn demo(mut link: iec60870::driver::TokioDriver<iec60870::cs104::Cs104Link, tokio::net::TcpStream>,
/// #               mut rx: tokio::sync::mpsc::Receiver<Vec<u8>>) -> std::io::Result<()> {
/// loop {
///     tokio::select! {
///         event = link.next_event() => match event? {
///             Some(event) => println!("{event:?}"),
///             None => break,
///         },
///         Some(asdu) = rx.recv() => { let _ = link.submit(&asdu); }
///     }
/// }
/// # Ok(()) }
/// ```
#[derive(Debug)]
pub struct TokioDriver<P: Protocol, T> {
    protocol: P,
    transport: T,
    epoch: TokioInstant,
    deadline: Option<Instant>,
    events: VecDeque<P::Event>,
    pending: Vec<u8>,
    written: usize,
    buf: Vec<u8>,
    finished: bool,
}

impl<P: Protocol, T: AsyncRead + AsyncWrite + Unpin> TokioDriver<P, T> {
    /// Takes over `transport`, already connected, and starts the core's clock.
    pub fn new(protocol: P, transport: T) -> Self {
        let mut driver = TokioDriver {
            protocol,
            transport,
            epoch: TokioInstant::now(),
            deadline: None,
            events: VecDeque::new(),
            pending: Vec::new(),
            written: 0,
            buf: std::vec![0; READ_BUF],
            finished: false,
        };
        let now = driver.now();
        driver.protocol.handle_timeout(now);
        driver
    }

    /// The core's current time.
    pub fn now(&self) -> Instant {
        Instant::from_nanos(u64::try_from(self.epoch.elapsed().as_nanos()).unwrap_or(u64::MAX))
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

    /// The core, mutably.
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
    /// has closed, its last output is written and the transport is shut down. Cancel-safe.
    pub async fn next_event(&mut self) -> io::Result<Option<P::Event>> {
        loop {
            self.collect();
            if let Err(e) = self.write_pending().await {
                self.disconnect();
                return Err(e);
            }
            if self.protocol.is_closed() && !self.finished {
                // The last frames are written; end the stream before reporting the close.
                let _ = self.transport.shutdown().await;
                self.finished = true;
            }
            if let Some(event) = self.events.pop_front() {
                return Ok(Some(event));
            }
            if self.protocol.is_closed() {
                return Ok(None);
            }
            let now = self.now();
            if self.deadline.is_some_and(|d| now >= d) {
                self.deadline = None;
                self.protocol.handle_timeout(now);
                continue;
            }
            let wake = match self.deadline {
                Some(d) => self.epoch + d.since_epoch(),
                None => TokioInstant::now() + Duration::from_secs(86_400),
            };
            tokio::select! {
                read = self.transport.read(&mut self.buf) => match read {
                    Ok(0) => {
                        let now = self.now();
                        self.protocol.handle_disconnect(now);
                    }
                    Ok(n) => {
                        let now = self.now();
                        self.protocol.handle_input(self.buf.get(..n).unwrap_or_default(), now);
                    }
                    Err(e) if e.kind() == ErrorKind::Interrupted => {}
                    Err(e) => {
                        self.disconnect();
                        return Err(e);
                    }
                },
                () = tokio::time::sleep_until(wake) => {
                    let now = self.now();
                    self.protocol.handle_timeout(now);
                }
            }
        }
    }

    fn collect(&mut self) {
        while let Some(output) = self.protocol.poll_output() {
            match output {
                Output::Transmit(bytes) => {
                    if !self.finished {
                        self.pending.extend_from_slice(&bytes);
                    }
                }
                Output::Event(event) => self.events.push_back(event),
                Output::Deadline(at) => self.deadline = Some(at),
            }
        }
    }

    async fn write_pending(&mut self) -> io::Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        while let Some(rest) = self.pending.get(self.written..).filter(|r| !r.is_empty()) {
            let n = self.transport.write(rest).await?;
            if n == 0 {
                return Err(io::Error::from(ErrorKind::WriteZero));
            }
            self.written += n;
        }
        self.pending.clear();
        self.written = 0;
        self.transport.flush().await
    }

    fn disconnect(&mut self) {
        let now = self.now();
        self.protocol.handle_disconnect(now);
        self.pending.clear();
        self.written = 0;
        self.finished = true;
        self.collect();
    }
}
