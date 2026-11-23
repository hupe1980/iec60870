//! `Cs101Link`: the sans-IO FT 1.2 link state machine, balanced and unbalanced.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::fmt;

use super::config::{Class, Config, ConfigError, Mode, Role};
use super::frame::{Control, Frame, FrameError, FrameSplitter, LinkAddress, PrimaryFunction, SecondaryFunction};
use crate::driver::{Output, Protocol};
use crate::time::Instant;

/// Why a primary stopped talking to a station.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StopReason {
    /// No valid answer after the frame was repeated `retries` times.
    NoResponse,
    /// The station answered "link service not functioning" (it lost its link state).
    NotFunctioning,
}

impl fmt::Display for StopReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            StopReason::NoResponse => "no response after the retries",
            StopReason::NotFunctioning => "link service not functioning",
        })
    }
}

/// Why the link closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CloseReason {
    /// The transport ended.
    PeerClosed,
    /// [`Cs101Link::close`] was called.
    Local,
}

impl fmt::Display for CloseReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CloseReason::PeerClosed => "the transport ended",
            CloseReason::Local => "closed locally",
        })
    }
}

impl core::error::Error for CloseReason {}

/// What the link reports to the station layer. `station` is the link address of the
/// secondary the event concerns: the polled outstation on a primary, this station's own
/// address on a secondary, the peer on a balanced link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// The link to `station` is up: a primary's reset of remote link was confirmed, or a
    /// secondary received one.
    Started {
        /// The station.
        station: LinkAddress,
    },
    /// A primary gave up on `station`; it resets the link again after `reset_interval`.
    /// Queued ASDUs stay queued.
    Stopped {
        /// The station.
        station: LinkAddress,
        /// Why.
        reason: StopReason,
    },
    /// An ASDU received, exactly once.
    Asdu {
        /// The station it came from (or, on a secondary, the station it was sent to).
        station: LinkAddress,
        /// The ASDU octets.
        asdu: Vec<u8>,
    },
    /// The peer confirmed the `count` oldest ASDUs submitted for `station` in `class`.
    Acknowledged {
        /// The station.
        station: LinkAddress,
        /// The class.
        class: Class,
        /// How many (always 1 on FT 1.2, kept for symmetry with the 104 link).
        count: u16,
    },
    /// The link gave up on the oldest ASDU submitted for `station` in `class`: it may or may
    /// not have arrived. The link never sends it again by itself.
    Unconfirmed {
        /// The station.
        station: LinkAddress,
        /// The class.
        class: Class,
        /// The ASDU.
        asdu: Vec<u8>,
    },
    /// The link is closed; the last event. ASDUs not acknowledged were not confirmed.
    Closed(CloseReason),
}

/// Why [`Cs101Link::submit`] refused an ASDU. The ASDU stays with the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SubmitError {
    /// The queue for this station and class holds `queue_len` ASDUs.
    QueueFull,
    /// An empty ASDU.
    Empty,
    /// An ASDU longer than a variable frame carries (255 − 1 − address octets).
    TooLong(usize),
    /// A station this link does not talk to.
    UnknownStation(LinkAddress),
    /// A primary with several secondaries needs [`Cs101Link::submit_to`].
    StationRequired,
    /// The link is closed.
    Closed,
}

impl fmt::Display for SubmitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SubmitError::QueueFull => f.write_str("the queue is full"),
            SubmitError::Empty => f.write_str("empty ASDU"),
            SubmitError::TooLong(n) => write!(f, "ASDU of {n} octets does not fit a variable frame"),
            SubmitError::UnknownStation(a) => write!(f, "{a} is not a station of this link"),
            SubmitError::StationRequired => f.write_str("several secondaries: name the station with submit_to"),
            SubmitError::Closed => f.write_str("the link is closed"),
        }
    }
}

impl core::error::Error for SubmitError {}

/// Counters of what the receiver discarded and the primary repeated.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Stats {
    /// Valid frames received.
    pub frames: u32,
    /// Frames with a wrong checksum.
    pub bad_checksum: u32,
    /// Frames with a wrong end octet.
    pub bad_end: u32,
    /// Variable frames whose header cannot be right (L fields, second start octet).
    pub bad_header: u32,
    /// Partial frames thrown away by the inter-character timeout.
    pub char_timeouts: u32,
    /// Octets outside any frame.
    pub stray_octets: u32,
    /// Frames for another station.
    pub foreign_address: u32,
    /// Frames that look like this end's own transmissions (a two-wire echo, or another
    /// secondary's answer on a multi-drop line).
    pub echoes: u32,
    /// Valid frames that make no sense in the current state.
    pub unexpected: u32,
    /// Repeated frames answered with the stored response.
    pub repeats_answered: u32,
    /// Frames this primary repeated after a timeout.
    pub retransmissions: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PeerState {
    Down { retry_at: Instant },
    Up,
}

/// A station a primary half talks to.
#[derive(Clone, Debug)]
struct Peer {
    address: LinkAddress,
    state: PeerState,
    next_fcb: bool,
    acd: bool,
    dfc: bool,
    hold_until: Instant,
    class2_at: Instant,
    last_exchange: Instant,
    queues: [VecDeque<Vec<u8>>; 2],
}

impl Peer {
    fn new(address: LinkAddress) -> Self {
        Peer {
            address,
            state: PeerState::Down { retry_at: Instant::ZERO },
            next_fcb: true,
            acd: false,
            dfc: false,
            hold_until: Instant::ZERO,
            class2_at: Instant::ZERO,
            last_exchange: Instant::ZERO,
            queues: [VecDeque::new(), VecDeque::new()],
        }
    }

    fn user_data(&self) -> Option<Class> {
        [Class::One, Class::Two].into_iter().find(|c| self.queues.get(c.index()).is_some_and(|q| !q.is_empty()))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Status,
    Reset,
    Probe,
    UserData(Class),
    Request(Class),
    Test,
}

#[derive(Clone, Debug)]
struct Outstanding {
    peer: usize,
    kind: Kind,
    fcv: bool,
    frame: Vec<u8>,
    sent_at: Instant,
    repeats: u8,
}

/// The secondary half: what a secondary (and each end of a balanced link) remembers.
#[derive(Clone, Debug, Default)]
struct SecondaryHalf {
    reset_seen: bool,
    last_fcb: Option<bool>,
    last_response: Vec<u8>,
    busy: bool,
    queues: [VecDeque<Vec<u8>>; 2],
    in_flight: Option<(Class, Vec<u8>)>,
}

/// A received frame, copied out of the splitter.
enum Received {
    Single,
    Frame { control: Control, address: LinkAddress, user_data: Vec<u8> },
}

/// The IEC 60870-5-101 link of one serial line, in one [`Mode`], without I/O.
///
/// It frames ASDUs in FT 1.2, resets the link, runs the frame count bit, repeats a frame
/// whose answer is lost and gives up after `retries`, polls secondaries (unbalanced primary),
/// answers polls from its class 1 and class 2 queues (unbalanced secondary), and runs both
/// directions with the DIR bit (balanced). Every malformed or misaddressed frame is discarded
/// and counted in [`Stats`]; nothing a peer sends closes the link. Drive it through
/// [`Protocol`] — or with a runner from [`driver`](crate::driver) — and command it with
/// [`submit`](Self::submit), [`submit_to`](Self::submit_to), [`set_busy`](Self::set_busy) and
/// [`close`](Self::close).
///
/// Every ASDU it accepts ends in exactly one of [`Event::Acknowledged`],
/// [`Event::Unconfirmed`] or [`Event::Closed`], and is delivered to the peer's station at most
/// once.
///
/// ```
/// use iec60870::cs101::{Class, Config, Cs101Link, Event, LinkAddress};
/// use iec60870::driver::Output;
/// use iec60870::time::Instant;
///
/// /// Moves everything `from` transmits into `to`; returns `from`'s events.
/// fn pump(from: &mut Cs101Link, to: &mut Cs101Link, now: Instant) -> Vec<Event> {
///     let mut events = Vec::new();
///     while let Some(output) = from.poll_output() {
///         match output {
///             Output::Transmit(bytes) => to.handle_input(&bytes, now),
///             Output::Event(event) => events.push(event),
///             Output::Deadline(_) => {}
///         }
///     }
///     events
/// }
///
/// let rtu = LinkAddress(7);
/// let mut master = Cs101Link::primary(&[rtu], Config::default())?;
/// let mut outstation = Cs101Link::secondary(rtu, Config::default())?;
/// outstation.submit(&[0x01, 0x01, 0x03, 0x01, 0x01, 0x00, 0x01], Class::One, Instant::ZERO)?;
///
/// let mut asdus = Vec::new();
/// for ms in 0..20 {
///     let now = Instant::from_millis(ms * 10);
///     master.handle_timeout(now);
///     for event in pump(&mut master, &mut outstation, now).into_iter().chain(pump(&mut outstation, &mut master, now)) {
///         if let Event::Asdu { station, asdu } = event {
///             asdus.push((station, asdu));
///         }
///     }
/// }
/// assert_eq!(asdus, [(rtu, vec![0x01, 0x01, 0x03, 0x01, 0x01, 0x00, 0x01])]);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
#[derive(Clone, Debug)]
pub struct Cs101Link {
    mode: Mode,
    config: Config,
    own: LinkAddress,
    dir: bool,
    splitter: FrameSplitter,
    stats: Stats,
    out: VecDeque<Output<Event>>,
    deadline_dirty: bool,
    closed: bool,
    peers: Vec<Peer>,
    cursor: usize,
    outstanding: Option<Outstanding>,
    broadcasts: VecDeque<(Class, Vec<u8>)>,
    secondary: Option<SecondaryHalf>,
}

impl Cs101Link {
    fn build(mode: Mode, config: Config, own: LinkAddress, peers: Vec<Peer>) -> Result<Self, ConfigError> {
        config.validate()?;
        let has_secondary = !matches!(mode, Mode::Primary);
        Ok(Cs101Link {
            mode,
            config,
            own,
            dir: mode == Mode::Balanced(Role::Controlling),
            splitter: FrameSplitter::new(config.address_width).with_timing(config.char_timeout, config.idle_gap),
            stats: Stats::default(),
            out: VecDeque::new(),
            deadline_dirty: true,
            closed: false,
            peers,
            cursor: 0,
            outstanding: None,
            broadcasts: VecDeque::new(),
            secondary: has_secondary.then(SecondaryHalf::default),
        })
    }

    /// A balanced link: this end is `own`, the other end `peer` (often the same address).
    /// Frames this end sends as primary carry `peer`, its answers carry `own`; frames with
    /// either address are accepted, as point-to-point peers differ in which they use.
    pub fn balanced(role: Role, own: LinkAddress, peer: LinkAddress, config: Config) -> Result<Self, ConfigError> {
        config.check_address(own)?;
        config.check_address(peer)?;
        Self::build(Mode::Balanced(role), config, own, alloc::vec![Peer::new(peer)])
    }

    /// An unbalanced primary (the controlling station) polling `secondaries` round-robin.
    pub fn primary(secondaries: &[LinkAddress], config: Config) -> Result<Self, ConfigError> {
        if secondaries.is_empty() {
            return Err(ConfigError::NoSecondaries);
        }
        let mut peers: Vec<Peer> = Vec::with_capacity(secondaries.len());
        for &address in secondaries {
            config.check_address(address)?;
            if peers.iter().any(|p| p.address == address) {
                return Err(ConfigError::DuplicateSecondary(address));
            }
            peers.push(Peer::new(address));
        }
        Self::build(Mode::Primary, config, LinkAddress(0), peers)
    }

    /// An unbalanced secondary (the controlled station) at `address`.
    pub fn secondary(address: LinkAddress, config: Config) -> Result<Self, ConfigError> {
        config.check_address(address)?;
        Self::build(Mode::Secondary, config, address, Vec::new())
    }

    /// This station's own link address (a secondary's, or this end of a balanced link; 0 on a
    /// primary).
    pub const fn own_address(&self) -> LinkAddress {
        self.own
    }

    /// The single peer's address: the other end of a balanced link, or the only secondary of
    /// a primary; `None` on a secondary and on a primary with several secondaries.
    pub fn peer_address(&self) -> Option<LinkAddress> {
        match (self.mode, self.peers.as_slice()) {
            (Mode::Secondary, _) => None,
            (_, [only]) => Some(only.address),
            _ => None,
        }
    }

    /// The mode.
    pub const fn mode(&self) -> Mode {
        self.mode
    }

    /// The configuration.
    pub const fn config(&self) -> &Config {
        &self.config
    }

    /// What the receiver discarded and the primary repeated so far.
    pub const fn stats(&self) -> &Stats {
        &self.stats
    }

    /// Whether the link to `station` is up (on a secondary: whether its primary reset it).
    pub fn is_up(&self, station: LinkAddress) -> bool {
        match self.mode {
            Mode::Secondary => station == self.own && self.secondary.as_ref().is_some_and(|s| s.reset_seen),
            Mode::Primary | Mode::Balanced(_) => self.peers.iter().any(|p| p.address == station && p.state == PeerState::Up),
        }
    }

    /// ASDUs queued for `station` in `class` and not yet sent (or, on a secondary, not yet
    /// fetched by a poll).
    pub fn queued(&self, station: LinkAddress, class: Class) -> usize {
        self.queue(station, class).map_or(0, VecDeque::len)
    }

    /// Whether [`submit`](Self::submit) would accept an ASDU of `class` now.
    pub fn can_send(&self, class: Class) -> bool {
        !self.closed && self.default_station().is_ok_and(|s| self.queued(s, class) < usize::from(self.config.queue_len))
    }

    /// Queues `asdu` for the link's one peer: the primary on a secondary, the other end on a
    /// balanced link, the only secondary on a primary with one. Use
    /// [`submit_to`](Self::submit_to) on a primary with several.
    pub fn submit(&mut self, asdu: &[u8], class: Class, now: Instant) -> Result<(), SubmitError> {
        let station = self.default_station()?;
        self.submit_to(station, asdu, class, now)
    }

    /// Queues `asdu` for `station`, or refuses it — never drops it. A primary sends it as user
    /// data with confirmation (class 1 before class 2) once the link is up; the broadcast
    /// address sends it with no reply, reported `Acknowledged` once transmitted. A secondary
    /// hands it out when its primary polls that class. ASDUs may be submitted before the link
    /// is up.
    pub fn submit_to(&mut self, station: LinkAddress, asdu: &[u8], class: Class, now: Instant) -> Result<(), SubmitError> {
        self.deadline_dirty = true;
        if self.closed {
            return Err(SubmitError::Closed);
        }
        if asdu.is_empty() {
            return Err(SubmitError::Empty);
        }
        if asdu.len() > self.config.address_width.max_user_data() {
            return Err(SubmitError::TooLong(asdu.len()));
        }
        let limit = usize::from(self.config.queue_len);
        if self.mode == Mode::Primary && self.config.address_width.broadcast() == Some(station) {
            if self.broadcasts.len() >= limit {
                return Err(SubmitError::QueueFull);
            }
            self.broadcasts.push_back((class, asdu.to_vec()));
        } else {
            let queue = self.queue_mut(station, class).ok_or(SubmitError::UnknownStation(station))?;
            if queue.len() >= limit {
                return Err(SubmitError::QueueFull);
            }
            queue.push_back(asdu.to_vec());
        }
        self.schedule(now);
        Ok(())
    }

    /// Signals (on the secondary half) that the station cannot take more user data: answers
    /// carry DFC and user data is refused with a negative acknowledgment until cleared.
    pub fn set_busy(&mut self, busy: bool) {
        if let Some(s) = self.secondary.as_mut() {
            s.busy = busy;
        }
    }

    /// Closes the link ([`CloseReason::Local`]).
    pub fn close(&mut self) {
        self.close_with(CloseReason::Local);
    }

    /// Octets received from the line, in pieces of any size, with the time they arrived.
    pub fn handle_input(&mut self, bytes: &[u8], now: Instant) {
        self.deadline_dirty = true;
        if self.closed {
            return;
        }
        let mut input = bytes;
        loop {
            let received = match self.splitter.next_frame(&mut input, now) {
                None => break,
                Some(Ok(Frame::SingleChar)) => Received::Single,
                Some(Ok(Frame::Fixed { control, address })) => Received::Frame { control, address, user_data: Vec::new() },
                Some(Ok(Frame::Variable { control, address, user_data })) => Received::Frame { control, address, user_data: user_data.to_vec() },
                Some(Err(e)) => {
                    self.count_error(e);
                    continue;
                }
            };
            self.stats.frames = self.stats.frames.wrapping_add(1);
            self.receive(received, now);
        }
        self.schedule(now);
    }

    /// Acts on every timer expired at `now`: repeats or gives up on an unanswered frame and
    /// sends the next poll, reset or test when it is due.
    pub fn handle_timeout(&mut self, now: Instant) {
        self.deadline_dirty = true;
        if self.closed {
            return;
        }
        if let Some(out) = self.outstanding.as_mut()
            && now >= out.sent_at + self.config.response_timeout
        {
            if out.repeats < self.config.retries {
                out.repeats += 1;
                out.sent_at = now;
                let frame = out.frame.clone();
                self.stats.retransmissions = self.stats.retransmissions.wrapping_add(1);
                self.transmit(&frame);
            } else if let Some(out) = self.outstanding.take() {
                if let Kind::UserData(class) = out.kind {
                    self.unconfirm_peer_data(out.peer, class);
                }
                self.fail_peer(out.peer, StopReason::NoResponse, now + self.config.reset_interval);
            }
        }
        self.schedule(now);
    }

    /// The transport ended: closes with [`CloseReason::PeerClosed`] unless already closed.
    pub fn handle_disconnect(&mut self, _now: Instant) {
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

    /// Whether the link is closed.
    pub const fn is_closed(&self) -> bool {
        self.closed
    }

    // ── queues ────────────────────────────────────────────────────────────────

    fn default_station(&self) -> Result<LinkAddress, SubmitError> {
        match self.mode {
            Mode::Secondary => Ok(self.own),
            Mode::Balanced(_) | Mode::Primary => match self.peers.as_slice() {
                [only] => Ok(only.address),
                _ => Err(SubmitError::StationRequired),
            },
        }
    }

    fn queue(&self, station: LinkAddress, class: Class) -> Option<&VecDeque<Vec<u8>>> {
        match self.mode {
            Mode::Secondary if station == self.own => self.secondary.as_ref().and_then(|s| s.queues.get(class.index())),
            Mode::Secondary => None,
            Mode::Primary | Mode::Balanced(_) => self.peers.iter().find(|p| p.address == station).and_then(|p| p.queues.get(class.index())),
        }
    }

    fn queue_mut(&mut self, station: LinkAddress, class: Class) -> Option<&mut VecDeque<Vec<u8>>> {
        match self.mode {
            Mode::Secondary if station == self.own => self.secondary.as_mut().and_then(|s| s.queues.get_mut(class.index())),
            Mode::Secondary => None,
            Mode::Primary | Mode::Balanced(_) => self.peers.iter_mut().find(|p| p.address == station).and_then(|p| p.queues.get_mut(class.index())),
        }
    }

    // ── receive ───────────────────────────────────────────────────────────────

    fn count_error(&mut self, e: FrameError) {
        let s = &mut self.stats;
        let counter = match e {
            FrameError::BadChecksum { .. } => &mut s.bad_checksum,
            FrameError::BadEnd(_) => &mut s.bad_end,
            FrameError::BadStart(_) => &mut s.stray_octets,
            FrameError::InterCharacterTimeout { .. } => &mut s.char_timeouts,
            _ => &mut s.bad_header,
        };
        *counter = counter.wrapping_add(1);
    }

    fn receive(&mut self, received: Received, now: Instant) {
        let (control, address, user_data) = match received {
            Received::Single => {
                if self.mode == Mode::Secondary {
                    bump(&mut self.stats.echoes);
                } else {
                    self.on_response(SecondaryFunction::Ack, false, false, None, Vec::new(), now);
                }
                return;
            }
            Received::Frame { control, address, user_data } => (control, address, user_data),
        };
        if let Mode::Balanced(_) = self.mode {
            if control.dir() == self.dir {
                return bump(&mut self.stats.echoes);
            }
            let peer = self.peers.first().map(|p| p.address);
            let broadcast = self.config.address_width.broadcast() == Some(address);
            if address != self.own && Some(address) != peer && !broadcast {
                return bump(&mut self.stats.foreign_address);
            }
        }
        match control {
            Control::Primary { fcb, fcv, function, .. } => {
                if self.mode == Mode::Primary {
                    return bump(&mut self.stats.echoes);
                }
                self.on_request(function, fcb, fcv, address, user_data);
            }
            Control::Secondary { acd, dfc, function, .. } => {
                if self.mode == Mode::Secondary {
                    return bump(&mut self.stats.echoes);
                }
                self.on_response(function, acd, dfc, Some(address), user_data, now);
            }
        }
    }

    // ── primary half ──────────────────────────────────────────────────────────

    fn on_response(&mut self, function: SecondaryFunction, acd: bool, dfc: bool, address: Option<LinkAddress>, data: Vec<u8>, now: Instant) {
        let Some(out) = self.outstanding.take() else {
            return bump(&mut self.stats.unexpected);
        };
        let unbalanced = self.mode == Mode::Primary;
        let Some(peer) = self.peers.get_mut(out.peer) else { return };
        if unbalanced && address.is_some_and(|a| a != peer.address) {
            self.outstanding = Some(out);
            return bump(&mut self.stats.foreign_address);
        }
        let station = peer.address;
        let done = match (out.kind, function) {
            (Kind::Status, SecondaryFunction::LinkStatus) => {
                peer.dfc = dfc;
                self.send(out.peer, Kind::Reset, PrimaryFunction::ResetRemoteLink, false, &[], now);
                return;
            }
            (Kind::Reset, SecondaryFunction::Ack) => {
                peer.state = PeerState::Up;
                peer.next_fcb = true;
                peer.class2_at = now;
                self.out.push_back(Output::Event(Event::Started { station }));
                true
            }
            (Kind::Probe, SecondaryFunction::LinkStatus) | (Kind::Test, SecondaryFunction::Ack) => true,
            (Kind::UserData(class), SecondaryFunction::Ack) => {
                if peer.queues.get_mut(class.index()).and_then(VecDeque::pop_front).is_some() {
                    self.out.push_back(Output::Event(Event::Acknowledged { station, class, count: 1 }));
                }
                true
            }
            (Kind::UserData(_), SecondaryFunction::Nack) => {
                peer.hold_until = now + self.config.poll_interval;
                true
            }
            (Kind::UserData(class), SecondaryFunction::NotImplemented) => {
                self.unconfirm_peer_data(out.peer, class);
                true
            }
            (Kind::Request(_), SecondaryFunction::UserData) if !data.is_empty() => {
                self.out.push_back(Output::Event(Event::Asdu { station, asdu: data }));
                true
            }
            (Kind::Request(class), SecondaryFunction::NoData | SecondaryFunction::Ack | SecondaryFunction::Nack) => {
                if class == Class::Two {
                    peer.class2_at = now + self.config.poll_interval;
                }
                true
            }
            (Kind::Status | Kind::Reset, _) => false,
            (_, SecondaryFunction::NotFunctioning) => {
                // The station lost its link state: what was in flight was not accepted.
                self.fail_peer(out.peer, StopReason::NotFunctioning, now);
                return;
            }
            _ => false,
        };
        if !done {
            self.outstanding = Some(out);
            return bump(&mut self.stats.unexpected);
        }
        let Some(peer) = self.peers.get_mut(out.peer) else { return };
        if out.fcv {
            peer.next_fcb = !peer.next_fcb;
        }
        peer.last_exchange = now;
        peer.dfc = dfc;
        if unbalanced {
            peer.acd = acd;
            if acd {
                // Access demand: the station keeps the turn for its class 1 data.
                self.cursor = out.peer;
            }
        }
    }

    fn unconfirm_peer_data(&mut self, index: usize, class: Class) {
        let Some(peer) = self.peers.get_mut(index) else { return };
        let station = peer.address;
        if let Some(asdu) = peer.queues.get_mut(class.index()).and_then(VecDeque::pop_front) {
            self.out.push_back(Output::Event(Event::Unconfirmed { station, class, asdu }));
        }
    }

    fn fail_peer(&mut self, index: usize, reason: StopReason, retry_at: Instant) {
        let Some(peer) = self.peers.get_mut(index) else { return };
        let was_up = peer.state == PeerState::Up;
        peer.state = PeerState::Down { retry_at };
        peer.acd = false;
        peer.dfc = false;
        if was_up {
            let station = peer.address;
            self.out.push_back(Output::Event(Event::Stopped { station, reason }));
        }
    }

    /// Sends the next frame if the line is free and something is due.
    fn schedule(&mut self, now: Instant) {
        if self.closed || self.outstanding.is_some() || self.mode == Mode::Secondary {
            return;
        }
        while let Some((class, asdu)) = self.broadcasts.pop_front()
            && let Some(broadcast) = self.config.address_width.broadcast()
        {
            let control = Control::Primary { dir: false, fcb: false, fcv: false, function: PrimaryFunction::UserDataNoReply };
            if let Ok(frame) = (Frame::Variable { control, address: broadcast, user_data: &asdu }).to_vec(self.config.address_width) {
                self.transmit(&frame);
            }
            self.out.push_back(Output::Event(Event::Acknowledged { station: broadcast, class, count: 1 }));
        }
        let n = self.peers.len();
        for step in 0..n {
            let index = (self.cursor + step) % n;
            if let Some((kind, function, fcv)) = self.next_action(index, now) {
                self.cursor = (index + 1) % n;
                let data = match kind {
                    Kind::UserData(class) => self.peers.get(index).and_then(|p| p.queues.get(class.index())).and_then(VecDeque::front).cloned(),
                    _ => None,
                };
                self.send(index, kind, function, fcv, data.as_deref().unwrap_or_default(), now);
                return;
            }
        }
    }

    fn next_action(&self, index: usize, now: Instant) -> Option<(Kind, PrimaryFunction, bool)> {
        let peer = self.peers.get(index)?;
        match peer.state {
            PeerState::Down { retry_at } => (now >= retry_at).then_some((Kind::Status, PrimaryFunction::RequestLinkStatus, false)),
            PeerState::Up => {
                if let Some(class) = peer.user_data() {
                    if !peer.dfc && now >= peer.hold_until {
                        return Some((Kind::UserData(class), PrimaryFunction::UserDataConfirmed, true));
                    }
                    if peer.dfc && now >= peer.hold_until && self.mode != Mode::Primary {
                        return Some((Kind::Probe, PrimaryFunction::RequestLinkStatus, false));
                    }
                }
                if self.mode == Mode::Primary {
                    if peer.acd {
                        return Some((Kind::Request(Class::One), PrimaryFunction::RequestClass1, true));
                    }
                    if now >= peer.class2_at {
                        return Some((Kind::Request(Class::Two), PrimaryFunction::RequestClass2, true));
                    }
                    None
                } else {
                    (now >= peer.last_exchange + self.config.test_interval).then_some((Kind::Test, PrimaryFunction::TestLink, true))
                }
            }
        }
    }

    fn peer_due(&self, peer: &Peer) -> Option<Instant> {
        match peer.state {
            PeerState::Down { retry_at } => Some(retry_at),
            PeerState::Up => {
                let data = peer.user_data().map(|_| peer.hold_until);
                let poll = if self.mode == Mode::Primary {
                    if peer.acd { Some(Instant::ZERO) } else { Some(peer.class2_at) }
                } else {
                    Some(peer.last_exchange + self.config.test_interval)
                };
                [data, poll].into_iter().flatten().min()
            }
        }
    }

    fn send(&mut self, index: usize, kind: Kind, function: PrimaryFunction, fcv: bool, data: &[u8], now: Instant) {
        let Some(peer) = self.peers.get(index) else { return };
        let control = Control::Primary { dir: self.dir, fcb: fcv && peer.next_fcb, fcv, function };
        let frame =
            if data.is_empty() { Frame::Fixed { control, address: peer.address } } else { Frame::Variable { control, address: peer.address, user_data: data } };
        let Ok(frame) = frame.to_vec(self.config.address_width) else { return };
        self.transmit(&frame);
        self.outstanding = Some(Outstanding { peer: index, kind, fcv, frame, sent_at: now, repeats: 0 });
    }

    // ── secondary half ────────────────────────────────────────────────────────

    fn on_request(&mut self, function: PrimaryFunction, fcb: bool, fcv: bool, address: LinkAddress, data: Vec<u8>) {
        let width = self.config.address_width;
        let broadcast = width.broadcast() == Some(address);
        if self.mode == Mode::Secondary && address != self.own && !broadcast {
            return bump(&mut self.stats.foreign_address);
        }
        let from = match self.mode {
            Mode::Balanced(_) => self.peers.first().map_or(self.own, |p| p.address),
            Mode::Primary | Mode::Secondary => self.own,
        };
        let unbalanced = self.mode == Mode::Secondary;
        let Some(sec) = self.secondary.as_mut() else { return };
        if broadcast {
            // A broadcast is never answered, and only user data without reply may be one.
            if function == PrimaryFunction::UserDataNoReply && !fcv && sec.reset_seen && !data.is_empty() {
                self.out.push_back(Output::Event(Event::Asdu { station: from, asdu: data }));
            } else {
                bump(&mut self.stats.unexpected);
            }
            return;
        }
        let answer = match function {
            PrimaryFunction::ResetRemoteLink | PrimaryFunction::ResetFcb if !fcv => {
                sec.reset_seen = true;
                sec.last_fcb = Some(false);
                sec.last_response.clear();
                if let Some((class, asdu)) = sec.in_flight.take() {
                    self.out.push_back(Output::Event(Event::Unconfirmed { station: from, class, asdu }));
                }
                if unbalanced && function == PrimaryFunction::ResetRemoteLink {
                    self.out.push_back(Output::Event(Event::Started { station: from }));
                }
                Answer::Fixed(SecondaryFunction::Ack)
            }
            PrimaryFunction::RequestLinkStatus | PrimaryFunction::RequestAccessDemand if !fcv => Answer::Fixed(SecondaryFunction::LinkStatus),
            PrimaryFunction::UserDataNoReply if !fcv => {
                if sec.reset_seen && !data.is_empty() {
                    self.out.push_back(Output::Event(Event::Asdu { station: from, asdu: data }));
                } else {
                    bump(&mut self.stats.unexpected);
                }
                return;
            }
            PrimaryFunction::TestLink | PrimaryFunction::UserDataConfirmed | PrimaryFunction::RequestClass1 | PrimaryFunction::RequestClass2 if fcv => {
                return self.on_fcv_request(function, fcb, from, data);
            }
            PrimaryFunction::ResetUserProcess | PrimaryFunction::Reserved(_) => Answer::Fixed(SecondaryFunction::NotImplemented),
            PrimaryFunction::RequestClass1 | PrimaryFunction::RequestClass2 if !unbalanced => Answer::Fixed(SecondaryFunction::NotImplemented),
            _ => return bump(&mut self.stats.unexpected),
        };
        self.answer(&answer);
    }

    fn on_fcv_request(&mut self, function: PrimaryFunction, fcb: bool, from: LinkAddress, data: Vec<u8>) {
        let unbalanced = self.mode == Mode::Secondary;
        let class_request = matches!(function, PrimaryFunction::RequestClass1 | PrimaryFunction::RequestClass2);
        if class_request && !unbalanced {
            return self.answer(&Answer::Fixed(SecondaryFunction::NotImplemented));
        }
        let Some(sec) = self.secondary.as_mut() else { return };
        if !sec.reset_seen {
            return self.answer(&Answer::Fixed(SecondaryFunction::NotFunctioning));
        }
        if sec.last_fcb == Some(fcb) {
            // A repetition: the primary lost our answer. Repeat it; act on nothing.
            bump(&mut self.stats.repeats_answered);
            if !sec.last_response.is_empty() {
                let frame = sec.last_response.clone();
                return self.transmit(&frame);
            }
            let function = if class_request { SecondaryFunction::NoData } else { SecondaryFunction::Ack };
            return self.answer_stored(&Answer::Fixed(function), false);
        }
        sec.last_fcb = Some(fcb);
        if let Some((class, _)) = sec.in_flight.take() {
            self.out.push_back(Output::Event(Event::Acknowledged { station: from, class, count: 1 }));
        }
        let answer = match function {
            PrimaryFunction::UserDataConfirmed if sec.busy => Answer::Fixed(SecondaryFunction::Nack),
            PrimaryFunction::UserDataConfirmed => {
                if !data.is_empty() {
                    self.out.push_back(Output::Event(Event::Asdu { station: from, asdu: data }));
                }
                Answer::Fixed(SecondaryFunction::Ack)
            }
            PrimaryFunction::RequestClass1 | PrimaryFunction::RequestClass2 => {
                let class = if function == PrimaryFunction::RequestClass1 { Class::One } else { Class::Two };
                match sec.queues.get_mut(class.index()).and_then(VecDeque::pop_front) {
                    Some(asdu) => {
                        let frame = asdu.clone();
                        sec.in_flight = Some((class, asdu));
                        Answer::Data(frame)
                    }
                    None => Answer::Fixed(SecondaryFunction::NoData),
                }
            }
            _ => Answer::Fixed(SecondaryFunction::Ack),
        };
        self.answer_stored(&answer, true);
    }

    fn answer(&mut self, answer: &Answer) {
        self.answer_stored(answer, false);
    }

    /// Sends an answer from the secondary half; `store` keeps it for a repetition.
    fn answer_stored(&mut self, answer: &Answer, store: bool) {
        let Some(sec) = self.secondary.as_ref() else { return };
        let acd = self.mode == Mode::Secondary && sec.queues.first().is_some_and(|q| !q.is_empty());
        let dfc = sec.busy;
        let width = self.config.address_width;
        let frame = match answer {
            Answer::Fixed(SecondaryFunction::Ack | SecondaryFunction::NoData) if self.config.single_char_ack && !acd && !dfc => Frame::SingleChar.to_vec(width),
            Answer::Fixed(function) => {
                (Frame::Fixed { control: Control::Secondary { dir: self.dir, acd, dfc, function: *function }, address: self.own }).to_vec(width)
            }
            Answer::Data(asdu) => {
                let control = Control::Secondary { dir: self.dir, acd, dfc, function: SecondaryFunction::UserData };
                (Frame::Variable { control, address: self.own, user_data: asdu }).to_vec(width)
            }
        };
        let Ok(frame) = frame else { return };
        if store && let Some(sec) = self.secondary.as_mut() {
            sec.last_response.clone_from(&frame);
        }
        self.transmit(&frame);
    }

    // ── output ────────────────────────────────────────────────────────────────

    fn next_deadline(&self) -> Option<Instant> {
        if self.closed {
            return None;
        }
        if let Some(out) = &self.outstanding {
            return Some(out.sent_at + self.config.response_timeout);
        }
        self.peers.iter().filter_map(|p| self.peer_due(p)).min()
    }

    /// Queues one frame. Frames are never coalesced: each `Transmit` is exactly one frame,
    /// so a runner on a real line can keep the line idle between frames.
    fn transmit(&mut self, frame: &[u8]) {
        self.out.push_back(Output::Transmit(frame.to_vec()));
    }

    fn close_with(&mut self, reason: CloseReason) {
        if self.closed {
            return;
        }
        self.closed = true;
        self.outstanding = None;
        self.deadline_dirty = true;
        self.out.push_back(Output::Event(Event::Closed(reason)));
    }
}

enum Answer {
    Fixed(SecondaryFunction),
    Data(Vec<u8>),
}

fn bump(counter: &mut u32) {
    *counter = counter.wrapping_add(1);
}

impl Protocol for Cs101Link {
    type Event = Event;

    fn handle_input(&mut self, bytes: &[u8], now: Instant) {
        Cs101Link::handle_input(self, bytes, now);
    }

    fn handle_timeout(&mut self, now: Instant) {
        Cs101Link::handle_timeout(self, now);
    }

    fn handle_disconnect(&mut self, now: Instant) {
        Cs101Link::handle_disconnect(self, now);
    }

    fn poll_output(&mut self) -> Option<Output<Event>> {
        Cs101Link::poll_output(self)
    }

    fn is_closed(&self) -> bool {
        Cs101Link::is_closed(self)
    }
}
