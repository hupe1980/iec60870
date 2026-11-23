//! `Cs104Link`: the sans-IO 104 link state machine.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::fmt;

use super::apci::{Apci, Apdu, FrameError, FrameSplitter, MAX_APDU_LEN, MAX_ASDU_LEN, SeqNo, UFunction};
use super::config::{Config, ConfigError, Role};
use crate::driver::{Output, Protocol};
use crate::time::Instant;

/// Where data transfer stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum State {
    /// Connected; no data transfer (the state after connecting, and after STOPDT con).
    Stopped,
    /// STARTDT act sent, its con awaited (controlling role).
    Starting,
    /// Data transfer: I-frames flow in both directions.
    Started,
    /// Stopping: the controlling role sent STOPDT act and awaits the con; the controlled role
    /// received STOPDT act and awaits the acknowledgment of its sent I-frames before it
    /// confirms.
    Stopping,
    /// The connection is closed; see the [`Event::Closed`] reason.
    Closed,
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            State::Stopped => "stopped",
            State::Starting => "starting",
            State::Started => "started",
            State::Stopping => "stopping",
            State::Closed => "closed",
        })
    }
}

/// What the link reports to the station layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// Data transfer started: STARTDT con received (controlling) or sent (controlled).
    Started,
    /// Data transfer stopped: STOPDT con received (controlling) or sent (controlled).
    Stopped,
    /// An ASDU received in an I-frame, in order, exactly once.
    Asdu(Vec<u8>),
    /// The peer acknowledged the `count` oldest outstanding I-frames — the station may
    /// release them, and the window has room again.
    Acknowledged {
        /// How many.
        count: u16,
    },
    /// The connection is closed and why; the last event. The I-frames still outstanding
    /// ([`Cs104Link::outstanding`]) were not acknowledged.
    Closed(CloseReason),
}

/// What t1 was waiting for when it expired.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Awaiting {
    /// The acknowledgment of a sent I-frame.
    Acknowledgment,
    /// STARTDT con.
    StartDtCon,
    /// STOPDT con.
    StopDtCon,
    /// TESTFR con.
    TestFrCon,
}

impl fmt::Display for Awaiting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Awaiting::Acknowledgment => "the acknowledgment of an I-frame",
            Awaiting::StartDtCon => "STARTDT con",
            Awaiting::StopDtCon => "STOPDT con",
            Awaiting::TestFrCon => "TESTFR con",
        })
    }
}

/// Why the link closed the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CloseReason {
    /// t1 expired.
    T1Expired(Awaiting),
    /// The peer's N(R) acknowledges a frame that was never sent (or one acknowledged before).
    BadAcknowledgment {
        /// The N(R) received.
        recv: SeqNo,
        /// The oldest unacknowledged N(S) (equal to `next` when none is outstanding).
        oldest: SeqNo,
        /// The N(S) the next I-frame will carry.
        next: SeqNo,
    },
    /// An I-frame's N(S) is not the one expected (a lost, repeated or reordered frame).
    SequenceError {
        /// The N(S) expected.
        expected: SeqNo,
        /// The N(S) received.
        received: SeqNo,
    },
    /// An I-frame arrived while data transfer was not started (or was being stopped by the peer).
    NotStarted,
    /// A U-frame this end did not ask for or may not receive: a STARTDT or STOPDT con with no
    /// act outstanding, or STARTDT/STOPDT act sent to the controlling station.
    UnexpectedFrame(UFunction),
    /// The octets are not a valid APDU.
    Malformed(FrameError),
    /// The transport ended.
    PeerClosed,
    /// [`Cs104Link::close`] was called.
    Local,
}

impl fmt::Display for CloseReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CloseReason::T1Expired(a) => write!(f, "t1 expired awaiting {a}"),
            CloseReason::BadAcknowledgment { recv, oldest, next } => {
                write!(f, "N(R) {recv} acknowledges outside the outstanding frames {oldest}..{next}")
            }
            CloseReason::SequenceError { expected, received } => write!(f, "N(S) {received} received, {expected} expected"),
            CloseReason::NotStarted => f.write_str("I-frame received while data transfer is not started"),
            CloseReason::UnexpectedFrame(u) => write!(f, "unexpected {u}"),
            CloseReason::Malformed(e) => write!(f, "malformed APDU: {e}"),
            CloseReason::PeerClosed => f.write_str("the peer closed the connection"),
            CloseReason::Local => f.write_str("closed locally"),
        }
    }
}

impl core::error::Error for CloseReason {}

/// Why [`Cs104Link::submit`] refused an ASDU. The ASDU stays with the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SubmitError {
    /// `k` I-frames are outstanding; wait for [`Event::Acknowledged`].
    WindowFull,
    /// Data transfer is not started (or is stopping).
    NotStarted,
    /// An empty ASDU.
    Empty,
    /// An ASDU longer than 249 octets.
    TooLong(usize),
    /// The connection is closed.
    Closed,
}

impl fmt::Display for SubmitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SubmitError::WindowFull => f.write_str("k I-frames are unacknowledged"),
            SubmitError::NotStarted => f.write_str("data transfer is not started"),
            SubmitError::Empty => f.write_str("empty ASDU"),
            SubmitError::TooLong(n) => write!(f, "ASDU of {n} octets, at most 249 fit an APDU"),
            SubmitError::Closed => f.write_str("the connection is closed"),
        }
    }
}

impl core::error::Error for SubmitError {}

/// Why [`Cs104Link::start`] or [`Cs104Link::stop`] was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CommandError {
    /// Only the controlling station starts and stops data transfer.
    WrongRole,
    /// The link is in the middle of the opposite transition.
    Busy(State),
    /// The connection is closed.
    Closed,
}

impl fmt::Display for CommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommandError::WrongRole => f.write_str("only the controlling station starts and stops data transfer"),
            CommandError::Busy(s) => write!(f, "the link is {s}"),
            CommandError::Closed => f.write_str("the connection is closed"),
        }
    }
}

impl core::error::Error for CommandError {}

/// The IEC 60870-5-104 link of one TCP connection, in either role, without I/O.
///
/// It numbers the ASDUs it is given, enforces `k` and `w`, runs t1, t2 and t3, answers and
/// sends STARTDT, STOPDT and TESTFR, and closes the connection with a [`CloseReason`] on every
/// protocol violation. Drive it through [`Protocol`] — or with a runner from
/// [`driver`](crate::driver) — and command it with [`start`](Self::start),
/// [`stop`](Self::stop), [`submit`](Self::submit) and [`close`](Self::close).
///
/// One link serves one connection: a new connection starts with a new link, at sequence
/// number 0.
#[derive(Clone, Debug)]
pub struct Cs104Link {
    role: Role,
    config: Config,
    state: State,
    /// N(S) of the next I-frame sent.
    send_seq: SeqNo,
    /// N(S) expected of the next I-frame received.
    recv_seq: SeqNo,
    /// The send time of each outstanding I-frame, oldest first.
    sent: VecDeque<Instant>,
    /// Received I-frames not yet acknowledged.
    unacked_recv: u16,
    t2: Option<Instant>,
    t3: Option<Instant>,
    /// STARTDT or STOPDT act awaiting its con.
    pending: Option<(Awaiting, Instant)>,
    testfr: Option<Instant>,
    clock_started: bool,
    splitter: FrameSplitter,
    out: VecDeque<Output<Event>>,
    deadline_dirty: bool,
}

impl Cs104Link {
    /// A link for `role` with `config`, refused if the configuration is out of range.
    pub fn new(role: Role, config: Config) -> Result<Self, ConfigError> {
        config.validate()?;
        Ok(Self::build(role, config))
    }

    fn build(role: Role, config: Config) -> Self {
        Cs104Link {
            role,
            config,
            state: State::Stopped,
            send_seq: SeqNo::ZERO,
            recv_seq: SeqNo::ZERO,
            sent: VecDeque::new(),
            unacked_recv: 0,
            t2: None,
            t3: None,
            pending: None,
            testfr: None,
            clock_started: false,
            splitter: FrameSplitter::new(),
            out: VecDeque::new(),
            deadline_dirty: false,
        }
    }

    /// A controlling-station link with the default configuration.
    pub fn controlling() -> Self {
        Self::build(Role::Controlling, Config::default())
    }

    /// A controlled-station link with the default configuration.
    pub fn controlled() -> Self {
        Self::build(Role::Controlled, Config::default())
    }

    /// This end's role.
    pub const fn role(&self) -> Role {
        self.role
    }

    /// The configuration.
    pub const fn config(&self) -> &Config {
        &self.config
    }

    /// Where data transfer stands.
    pub const fn state(&self) -> State {
        self.state
    }

    /// I-frames sent and not yet acknowledged.
    pub fn outstanding(&self) -> u16 {
        self.sent.len() as u16
    }

    /// Whether [`submit`](Self::submit) would accept an ASDU now.
    pub fn can_send(&self) -> bool {
        self.state == State::Started && self.sent.len() < usize::from(self.config.k)
    }

    /// Starts data transfer: sends STARTDT act (controlling role only). Starting a link that
    /// is starting or started does nothing.
    pub fn start(&mut self, now: Instant) -> Result<(), CommandError> {
        self.touch(now);
        if self.role != Role::Controlling {
            return Err(CommandError::WrongRole);
        }
        match self.state {
            State::Closed => Err(CommandError::Closed),
            State::Stopping => Err(CommandError::Busy(State::Stopping)),
            State::Starting | State::Started => Ok(()),
            State::Stopped => {
                self.send_u(UFunction::StartDtAct);
                self.pending = Some((Awaiting::StartDtCon, now + self.config.t1));
                self.state = State::Starting;
                Ok(())
            }
        }
    }

    /// Stops data transfer: acknowledges what was received and sends STOPDT act (controlling
    /// role only). I-frames the peer had in flight are still accepted and acknowledged until
    /// its STOPDT con. Stopping a link that is stopping or stopped does nothing.
    pub fn stop(&mut self, now: Instant) -> Result<(), CommandError> {
        self.touch(now);
        if self.role != Role::Controlling {
            return Err(CommandError::WrongRole);
        }
        match self.state {
            State::Closed => Err(CommandError::Closed),
            State::Starting => Err(CommandError::Busy(State::Starting)),
            State::Stopping | State::Stopped => Ok(()),
            State::Started => {
                if self.unacked_recv > 0 {
                    self.send_s();
                }
                self.send_u(UFunction::StopDtAct);
                self.pending = Some((Awaiting::StopDtCon, now + self.config.t1));
                self.state = State::Stopping;
                Ok(())
            }
        }
    }

    /// Sends `asdu` in the next I-frame, or refuses it — never drops it. The I-frame also
    /// acknowledges every I-frame received so far.
    pub fn submit(&mut self, asdu: &[u8], now: Instant) -> Result<(), SubmitError> {
        self.touch(now);
        match self.state {
            State::Closed => return Err(SubmitError::Closed),
            State::Started => {}
            State::Stopped | State::Starting | State::Stopping => return Err(SubmitError::NotStarted),
        }
        if asdu.is_empty() {
            return Err(SubmitError::Empty);
        }
        if asdu.len() > MAX_ASDU_LEN {
            return Err(SubmitError::TooLong(asdu.len()));
        }
        if self.sent.len() >= usize::from(self.config.k) {
            return Err(SubmitError::WindowFull);
        }
        self.transmit(&Apdu::i(self.send_seq, self.recv_seq, asdu));
        self.sent.push_back(now);
        self.send_seq = self.send_seq.next();
        self.acknowledged_received();
        Ok(())
    }

    /// Closes the connection ([`CloseReason::Local`]); the runner then shuts the transport down.
    pub fn close(&mut self) {
        self.close_with(CloseReason::Local);
    }

    /// Octets received from the peer, in pieces of any size.
    pub fn handle_input(&mut self, bytes: &[u8], now: Instant) {
        self.touch(now);
        let mut input = bytes;
        while self.state != State::Closed {
            let frame = match self.splitter.next_frame(&mut input) {
                None => break,
                Some(Ok(apdu)) => Ok((apdu.apci, apdu.asdu.to_vec())),
                Some(Err(e)) => Err(e),
            };
            match frame {
                Ok((apci, asdu)) => {
                    self.t3 = Some(now + self.config.t3);
                    self.receive(apci, asdu, now);
                }
                Err(e) => self.close_with(CloseReason::Malformed(e)),
            }
        }
    }

    /// Acts on every timer expired at `now`.
    pub fn handle_timeout(&mut self, now: Instant) {
        self.touch(now);
        if self.state == State::Closed {
            return;
        }
        if self.sent.front().is_some_and(|&at| now >= at + self.config.t1) {
            return self.close_with(CloseReason::T1Expired(Awaiting::Acknowledgment));
        }
        if let Some((awaiting, at)) = self.pending
            && now >= at
        {
            return self.close_with(CloseReason::T1Expired(awaiting));
        }
        if self.testfr.is_some_and(|at| now >= at) {
            return self.close_with(CloseReason::T1Expired(Awaiting::TestFrCon));
        }
        if self.t2.is_some_and(|at| now >= at) {
            self.send_s();
        }
        if self.t3.is_some_and(|at| now >= at) {
            if self.testfr.is_none() {
                self.send_u(UFunction::TestFrAct);
                self.testfr = Some(now + self.config.t1);
            }
            self.t3 = Some(now + self.config.t3);
        }
    }

    /// The transport ended: closes with [`CloseReason::PeerClosed`] unless already closed.
    pub fn handle_disconnect(&mut self, now: Instant) {
        self.touch(now);
        self.close_with(CloseReason::PeerClosed);
    }

    /// The next output; see [`Protocol::poll_output`].
    pub fn poll_output(&mut self) -> Option<Output<Event>> {
        if let Some(output) = self.out.pop_front() {
            return Some(output);
        }
        if self.deadline_dirty {
            self.deadline_dirty = false;
            return self.next_deadline().map(Output::Deadline);
        }
        None
    }

    /// Whether the connection is closed.
    pub fn is_closed(&self) -> bool {
        self.state == State::Closed
    }

    fn next_deadline(&self) -> Option<Instant> {
        if self.state == State::Closed {
            return None;
        }
        let t1 = self.sent.front().map(|&at| at + self.config.t1);
        [t1, self.pending.map(|(_, at)| at), self.testfr, self.t2, self.t3].into_iter().flatten().min()
    }

    fn touch(&mut self, now: Instant) {
        if !self.clock_started && self.state != State::Closed {
            self.clock_started = true;
            self.t3 = Some(now + self.config.t3);
        }
        self.deadline_dirty = true;
    }

    fn receive(&mut self, apci: Apci, asdu: Vec<u8>, now: Instant) {
        match apci {
            Apci::I { send, recv } => {
                let accepting = self.state == State::Started || (self.state == State::Stopping && self.role == Role::Controlling);
                if !accepting {
                    return self.close_with(CloseReason::NotStarted);
                }
                if send != self.recv_seq {
                    return self.close_with(CloseReason::SequenceError { expected: self.recv_seq, received: send });
                }
                if !self.acknowledge(recv) {
                    return;
                }
                self.recv_seq = self.recv_seq.next();
                self.unacked_recv = self.unacked_recv.saturating_add(1);
                if self.t2.is_none() {
                    self.t2 = Some(now + self.config.t2);
                }
                self.out.push_back(Output::Event(Event::Asdu(asdu)));
                // While stopping, acknowledge at once: a peer withholds its STOPDT con until
                // its I-frames are acknowledged.
                if self.unacked_recv >= self.config.w || self.state == State::Stopping {
                    self.send_s();
                }
            }
            Apci::S { recv } => {
                if self.acknowledge(recv) {
                    self.confirm_stop_when_drained();
                }
            }
            Apci::U(function) => self.receive_u(function),
        }
    }

    fn receive_u(&mut self, function: UFunction) {
        match (function, self.role, self.state) {
            (UFunction::TestFrAct, ..) => self.send_u(UFunction::TestFrCon),
            (UFunction::TestFrCon, ..) => self.testfr = None,
            (UFunction::StartDtAct, Role::Controlled, previous) => {
                self.state = State::Started;
                self.send_u(UFunction::StartDtCon);
                if previous == State::Stopped {
                    self.out.push_back(Output::Event(Event::Started));
                }
            }
            (UFunction::StopDtAct, Role::Controlled, State::Started) => {
                self.state = State::Stopping;
                if self.unacked_recv > 0 {
                    self.send_s();
                }
                self.confirm_stop_when_drained();
            }
            (UFunction::StopDtAct, Role::Controlled, State::Stopped) => self.send_u(UFunction::StopDtCon),
            (UFunction::StopDtAct, Role::Controlled, _) => {}
            (UFunction::StartDtCon, Role::Controlling, State::Starting) => {
                self.pending = None;
                self.state = State::Started;
                self.out.push_back(Output::Event(Event::Started));
            }
            (UFunction::StopDtCon, Role::Controlling, State::Stopping) => {
                self.pending = None;
                self.state = State::Stopped;
                self.out.push_back(Output::Event(Event::Stopped));
            }
            (UFunction::StartDtAct | UFunction::StopDtAct | UFunction::StartDtCon | UFunction::StopDtCon, ..) => {
                self.close_with(CloseReason::UnexpectedFrame(function));
            }
        }
    }

    /// Applies the peer's N(R); false (and closed) if it is outside the outstanding window.
    fn acknowledge(&mut self, recv: SeqNo) -> bool {
        let outstanding = self.sent.len() as u16;
        let oldest = self.send_seq.wrapping_sub(outstanding);
        let count = recv.distance(oldest);
        if count > outstanding {
            self.close_with(CloseReason::BadAcknowledgment { recv, oldest, next: self.send_seq });
            return false;
        }
        if count > 0 {
            self.sent.drain(..usize::from(count));
            self.out.push_back(Output::Event(Event::Acknowledged { count }));
        }
        true
    }

    fn confirm_stop_when_drained(&mut self) {
        if self.role == Role::Controlled && self.state == State::Stopping && self.sent.is_empty() {
            self.send_u(UFunction::StopDtCon);
            self.state = State::Stopped;
            self.out.push_back(Output::Event(Event::Stopped));
        }
    }

    fn send_u(&mut self, function: UFunction) {
        self.transmit(&Apdu::u(function));
    }

    fn send_s(&mut self) {
        self.transmit(&Apdu::s(self.recv_seq));
        self.acknowledged_received();
    }

    fn acknowledged_received(&mut self) {
        self.unacked_recv = 0;
        self.t2 = None;
    }

    /// Appends one APDU, coalescing with a transmit already queued at the back.
    fn transmit(&mut self, apdu: &Apdu<'_>) {
        let mut buf = [0u8; MAX_APDU_LEN];
        // Every APDU built here is valid: the ASDU length was checked by `submit`.
        let Ok(len) = apdu.encode(&mut buf) else { return };
        let bytes = buf.get(..len).unwrap_or_default();
        if let Some(Output::Transmit(queued)) = self.out.back_mut() {
            queued.extend_from_slice(bytes);
        } else {
            self.out.push_back(Output::Transmit(bytes.to_vec()));
        }
    }

    fn close_with(&mut self, reason: CloseReason) {
        if self.state == State::Closed {
            return;
        }
        self.state = State::Closed;
        self.t2 = None;
        self.t3 = None;
        self.pending = None;
        self.testfr = None;
        self.deadline_dirty = true;
        self.out.push_back(Output::Event(Event::Closed(reason)));
    }
}

impl Protocol for Cs104Link {
    type Event = Event;

    fn handle_input(&mut self, bytes: &[u8], now: Instant) {
        Cs104Link::handle_input(self, bytes, now);
    }

    fn handle_timeout(&mut self, now: Instant) {
        Cs104Link::handle_timeout(self, now);
    }

    fn handle_disconnect(&mut self, now: Instant) {
        Cs104Link::handle_disconnect(self, now);
    }

    fn poll_output(&mut self) -> Option<Output<Event>> {
        Cs104Link::poll_output(self)
    }

    fn is_closed(&self) -> bool {
        Cs104Link::is_closed(self)
    }
}
