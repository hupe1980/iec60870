//! The controlled station (outstation): [`ControlledStation`].

#[cfg(feature = "file-transfer")]
#[path = "serve_files.rs"]
mod serve_files;

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use core::fmt;
use core::time::Duration;

use super::command::{Command, CommandHandler, CommandKind, CommandMode, CommandRequest, Decision, Parameter, ParameterRequest, Phase, RefuseCommands};
use super::database::{PointSource, UpdateError};
use super::link::{Class, LinkClosed, LinkEvent, StationLink};
use super::value::{self, TimeFormat, Value, ValueKind};
use crate::asdu::{Asdu, InformationObject, Objects, Profile};
use crate::driver::Output as LinkOutput;
use crate::time::{Clock, Cp56Time2a, Instant};
use crate::types::{Cause, CommonAddress, Cot, CounterInterrogation, EndOfInitialization, Interrogation, Ioa, ResetProcess, TypeId};

/// A connection of a [`ControlledStation`], as returned by [`ControlledStation::attach`].
///
/// ```
/// use iec60870::station::ConnectionId;
/// assert_eq!(ConnectionId(3).to_string(), "connection 3");
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnectionId(pub u32);

impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "connection {}", self.0)
    }
}

/// A redundancy group: connections sharing one event buffer, of which one at a time is started.
/// `GroupId(0)` always exists.
///
/// ```
/// use iec60870::station::GroupId;
/// assert_eq!(GroupId::default(), GroupId(0));
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct GroupId(pub u8);

impl fmt::Display for GroupId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "group {}", self.0)
    }
}

/// How a controlled station behaves.
///
/// ```
/// use core::time::Duration;
/// use iec60870::station::ServerConfig;
///
/// let config = ServerConfig { event_capacity: 10_000, select_timeout: Duration::from_secs(5), ..ServerConfig::default() };
/// assert_eq!(config.profile, iec60870::Profile::IEC104);
/// ```
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ServerConfig {
    /// File service size and idle limits.
    #[cfg(feature = "file-transfer")]
    pub files: super::FileConfig,
    /// The field widths and permitted types (default [`Profile::IEC104`]).
    pub profile: Profile,
    /// Events each redundancy group buffers, sent and unsent (default 1024). When full, the
    /// oldest unsent event is dropped and [`ServerEvent::EventsLost`] reports it.
    pub event_capacity: usize,
    /// How long an accepted select waits for its execute (default 10 s).
    pub select_timeout: Duration,
    /// The period of cyclic transmission, COT 1 (default 60 s; only points marked cyclic).
    pub cyclic_period: Duration,
    /// The period of the background scan, COT 2 (default off).
    pub background_period: Option<Duration>,
    /// The end of initialisation sent per common address before anything else (default
    /// local power on; `None` sends none).
    pub end_of_initialization: Option<EndOfInitialization>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            profile: Profile::IEC104,
            #[cfg(feature = "file-transfer")]
            files: super::FileConfig::default(),
            event_capacity: 1024,
            select_timeout: Duration::from_secs(10),
            cyclic_period: Duration::from_secs(60),
            background_period: None,
            end_of_initialization: Some(EndOfInitialization::LOCAL_POWER_ON),
        }
    }
}

/// What a controlled station reports to the application.
///
/// ```
/// use iec60870::station::{GroupId, ServerEvent};
///
/// fn log(event: &ServerEvent) {
///     if let ServerEvent::EventsLost { group, count } = event {
///         eprintln!("{group}: {count} events dropped, the master needs a general interrogation");
///     }
/// }
/// log(&ServerEvent::EventsLost { group: GroupId(0), count: 3 });
/// ```
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum ServerEvent {
    /// The server adapter dropped this many queued notifications before the observer read them.
    ObserverLagged {
        /// Number of overwritten notifications.
        count: usize,
    },
    /// The station decided a decoded command request.
    CommandDecision {
        /// Request including the command, address and connection.
        request: CommandRequest,
        /// Whether this is a deactivation of a selection.
        cancellation: bool,
        /// The decision returned to the controlling station.
        decision: Decision,
    },
    /// A selected file transfer ended.
    #[cfg(feature = "file-transfer")]
    FileTransfer {
        /// Connection serving the transfer.
        connection: ConnectionId,
        /// Common address.
        common_address: CommonAddress,
        /// Record address.
        ioa: Ioa,
        /// Name of file.
        name: super::FileName,
        /// Reason the transfer ended.
        outcome: super::TransferOutcome,
    },
    /// A connection started data transfer.
    Started(ConnectionId),
    /// A connection stopped data transfer.
    Stopped(ConnectionId),
    /// A connection closed; its unacknowledged events are buffered again.
    Disconnected {
        /// The connection.
        connection: ConnectionId,
        /// Why.
        reason: LinkClosed,
    },
    /// Another connection of a redundancy group was started: `from` was closed and its
    /// unacknowledged events are re-sent on `to`.
    SwitchedOver {
        /// The group.
        group: GroupId,
        /// The connection closed.
        from: ConnectionId,
        /// The connection now started.
        to: ConnectionId,
    },
    /// The event buffer of `group` overflowed and `count` events were dropped.
    EventsLost {
        /// The group.
        group: GroupId,
        /// How many since the last report.
        count: usize,
    },
    /// A clock synchronisation was accepted; time tags now follow `time`.
    ClockSynchronized {
        /// The connection it came from.
        connection: ConnectionId,
        /// The time received.
        time: Cp56Time2a,
    },
}

/// What a [`ControlledStation`] yields.
///
/// ```
/// use iec60870::station::Output;
///
/// fn route(output: Output) {
///     match output {
///         Output::Transmit { connection, bytes } => println!("{connection}: {} octets", bytes.len()),
///         Output::Event(event) => println!("{event:?}"),
///         Output::Deadline(at) => println!("wake at {at:?}"),
///     }
/// }
/// # let _ = route;
/// ```
#[derive(Clone, Debug)]
pub enum Output {
    /// Octets to write to `connection`.
    Transmit {
        /// The connection.
        connection: ConnectionId,
        /// One or more whole frames.
        bytes: Vec<u8>,
    },
    /// Something for the application.
    Event(ServerEvent),
    /// Call [`ControlledStation::handle_timeout`] at this instant (or earlier). Supersedes
    /// every earlier deadline. [`Instant::ZERO`] means "as soon as possible" (an update is
    /// waiting to be sent).
    Deadline(Instant),
}

/// What a buffered event carries.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Item {
    Point { ioa: Ioa, value: Value, time: Cp56Time2a, format: TimeFormat },
    EndOfInit(EndOfInitialization),
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct Buffered {
    ca: CommonAddress,
    cause: Cause,
    item: Item,
}

impl Buffered {
    /// Events with the same key go into one ASDU.
    fn key(&self) -> Option<(CommonAddress, Cause, ValueKind, TimeFormat)> {
        match self.item {
            Item::Point { value, format, .. } => Some((self.ca, self.cause, value.kind(), format)),
            Item::EndOfInit(_) => None,
        }
    }
}

#[derive(Debug)]
struct Group {
    pending: VecDeque<Buffered>,
    in_flight: usize,
    lost: usize,
    started: Option<ConnectionId>,
}

#[derive(Debug)]
enum InFlight {
    Events(Vec<Buffered>),
    Other,
}

#[derive(Debug)]
struct Reply {
    bytes: Vec<u8>,
    /// The interrogation this reply terminates.
    terminates: Option<CommonAddress>,
}

#[derive(Debug)]
struct Connection<L> {
    #[cfg(feature = "file-transfer")]
    transfer: Option<serve_files::Transfer>,
    id: ConnectionId,
    link: L,
    group: usize,
    /// Confirmations and interrogation replies (class 1), before events.
    replies: VecDeque<Reply>,
    /// Cyclic and background data (class 2), after events.
    cyclic: VecDeque<Vec<u8>>,
    in_flight: VecDeque<(Class, InFlight)>,
    deadline: Option<Instant>,
    closed: bool,
}

#[derive(Clone, Copy, Debug)]
struct Selection {
    connection: ConnectionId,
    type_id: TypeId,
    originator: u8,
    command: Command,
    deadline: Instant,
}

/// The controlled station (outstation) of IEC 60870-5-101/104, without I/O.
///
/// It owns the [`PointSource`], answers interrogations from it, buffers spontaneous events per
/// redundancy group until the master acknowledges them, enforces select-before-operate, and
/// asks the application's [`CommandHandler`] only about requests it has checked. Connections
/// are links ([`StationLink`]) attached with [`attach`](Self::attach); feed each its octets
/// with [`handle_input`](Self::handle_input) and drain [`poll_output`](Self::poll_output).
///
/// Most applications use `Server` (features `std` and `cs104`), which does all of this over TCP.
///
#[cfg_attr(feature = "cs104", doc = "```")]
#[cfg_attr(not(feature = "cs104"), doc = "```ignore")]
/// use iec60870::cs104::Cs104Link;
/// use iec60870::prelude::*;
/// use iec60870::station::{ControlledStation, Database, Output, ServerConfig, GroupId};
///
/// let ca = CommonAddress(1);
/// let mut db = Database::new();
/// db.insert(ca, Ioa(100), false);
/// let clock = || Cp56Time2a::from_unix_millis(1_795_000_000_000).unwrap();
/// let mut station = ControlledStation::<Cs104Link>::new(db, ServerConfig::default(), clock);
/// let conn = station.attach(Cs104Link::controlled(), GroupId(0));
///
/// // STARTDT act from the master: the station confirms and sends its end of initialisation.
/// let now = Instant::ZERO;
/// station.handle_input(conn, &[0x68, 0x04, 0x07, 0x00, 0x00, 0x00], now, &mut |_: &_| Decision::Refuse);
/// let mut wire = Vec::new();
/// while let Some(output) = station.poll_output() {
///     if let Output::Transmit { bytes, .. } = output {
///         wire.extend(bytes);
///     }
/// }
/// assert_eq!(&wire[..6], [0x68, 0x04, 0x0B, 0x00, 0x00, 0x00]); // STARTDT con
/// assert_eq!(wire[12], 70); // then M_EI_NA_1
///
/// station.update(ca, Ioa(100), true)?; // a spontaneous event, time-tagged from the clock
/// # Ok::<(), iec60870::station::UpdateError>(())
/// ```
pub struct ControlledStation<L> {
    database: Box<dyn PointSource>,
    #[cfg(feature = "file-transfer")]
    pub(crate) file_store: Option<Box<dyn super::FileStore + Send>>,
    config: ServerConfig,
    clock: Box<dyn Clock + Send>,
    offset_ms: i64,
    groups: Vec<Group>,
    connections: Vec<Connection<L>>,
    next_id: u32,
    selections: BTreeMap<(CommonAddress, Ioa), Selection>,
    out: VecDeque<Output>,
    deadline_dirty: bool,
    flush_soon: bool,
    now: Instant,
    clock_started: bool,
    next_cyclic: Option<Instant>,
    next_background: Option<Instant>,
    dropped_asdus: u64,
}

impl<L> fmt::Debug for ControlledStation<L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ControlledStation")
            .field("connections", &self.connections.iter().map(|c| c.id).collect::<Vec<_>>())
            .field("pending", &self.groups.iter().map(|g| g.pending.len()).collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl<L: StationLink> ControlledStation<L> {
    /// A station serving `database`, with time tags from `clock`.
    pub fn new(database: impl PointSource + 'static, config: ServerConfig, clock: impl Clock + Send + 'static) -> Self {
        let mut station = ControlledStation {
            database: Box::new(database),
            #[cfg(feature = "file-transfer")]
            file_store: None,
            config,
            clock: Box::new(clock),
            offset_ms: 0,
            groups: Vec::new(),
            connections: Vec::new(),
            next_id: 1,
            selections: BTreeMap::new(),
            out: VecDeque::new(),
            deadline_dirty: false,
            flush_soon: false,
            now: Instant::ZERO,
            clock_started: false,
            next_cyclic: None,
            next_background: None,
            dropped_asdus: 0,
        };
        station.add_group();
        station
    }

    /// Serve directory requests from this catalog.
    #[cfg(feature = "file-transfer")]
    pub fn set_file_store(&mut self, store: impl super::FileStore + Send + 'static) {
        self.file_store = Some(Box::new(store));
    }

    /// The point database.
    pub fn database(&self) -> &dyn PointSource {
        self.database.as_ref()
    }

    /// The configuration.
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// The station's time: the clock, corrected by the last accepted clock synchronisation.
    pub fn time(&self) -> Cp56Time2a {
        let now = self.clock.now();
        if self.offset_ms == 0 {
            return now;
        }
        if now.is_invalid() {
            return now;
        }
        now.to_unix_millis()
            .and_then(|ms| ms.checked_add_signed(self.offset_ms))
            .and_then(Cp56Time2a::from_unix_millis)
            .map_or_else(|| now.with_invalid(true), |t| t.with_substituted(now.is_substituted()).with_summer_time(now.is_summer_time()))
    }

    /// Sets a point to `value`, time-tagged now; a spontaneous point also produces an event
    /// for every redundancy group.
    pub fn update(&mut self, common_address: CommonAddress, ioa: Ioa, value: impl Into<Value>) -> Result<(), UpdateError> {
        let time = self.time();
        self.update_at(common_address, ioa, value, time)
    }

    /// Sets a point to `value` with an explicit time tag (an event time-stamped at its source).
    pub fn update_at(&mut self, common_address: CommonAddress, ioa: Ioa, value: impl Into<Value>, time: Cp56Time2a) -> Result<(), UpdateError> {
        let value = value.into();
        let point = self.database.point_mut(common_address, ioa).ok_or(UpdateError::UnknownPoint { common_address, ioa })?;
        if point.value.kind() != value.kind() {
            return Err(UpdateError::KindMismatch { expected: point.value.kind(), found: value.kind() });
        }
        point.value = value;
        point.time = Some(time);
        if point.spontaneous {
            let format = value::event_format(value.kind(), point.format);
            let event = Buffered { ca: common_address, cause: Cause::SPONTANEOUS, item: Item::Point { ioa, value, time, format } };
            for g in 0..self.groups.len() {
                self.push_event(g, event);
            }
            self.flush_soon = true;
            self.deadline_dirty = true;
        }
        self.report_losses();
        Ok(())
    }

    /// Adds a redundancy group with its own event buffer and returns it.
    pub fn add_group(&mut self) -> GroupId {
        let mut group = Group { pending: VecDeque::new(), in_flight: 0, lost: 0, started: None };
        if let Some(coi) = self.config.end_of_initialization {
            for ca in self.database.addresses() {
                group.pending.push_back(Buffered { ca, cause: Cause::INITIALIZED, item: Item::EndOfInit(coi) });
            }
        }
        self.groups.push(group);
        GroupId(u8::try_from(self.groups.len() - 1).unwrap_or(u8::MAX))
    }

    /// Attaches a new connection's link to `group` (an unknown group means group 0).
    pub fn attach(&mut self, link: L, group: GroupId) -> ConnectionId {
        let id = ConnectionId(self.next_id);
        self.next_id = self.next_id.wrapping_add(1);
        let group = if usize::from(group.0) < self.groups.len() { usize::from(group.0) } else { 0 };
        self.connections.push(Connection {
            #[cfg(feature = "file-transfer")]
            transfer: None,
            id,
            link,
            group,
            replies: VecDeque::new(),
            cyclic: VecDeque::new(),
            in_flight: VecDeque::new(),
            deadline: None,
            closed: false,
        });
        self.deadline_dirty = true;
        id
    }

    /// The link of a connection.
    pub fn link(&self, connection: ConnectionId) -> Option<&L> {
        self.connections.iter().find(|c| c.id == connection).map(|c| &c.link)
    }

    /// The open connections.
    pub fn connections(&self) -> impl Iterator<Item = ConnectionId> + '_ {
        self.connections.iter().filter(|c| !c.closed).map(|c| c.id)
    }

    /// The started connection of `group`.
    pub fn started(&self, group: GroupId) -> Option<ConnectionId> {
        self.groups.get(usize::from(group.0)).and_then(|g| g.started)
    }

    /// The events of `group` not yet acknowledged (unsent and in flight).
    pub fn pending_events(&self, group: GroupId) -> usize {
        self.groups.get(usize::from(group.0)).map_or(0, |g| g.pending.len() + g.in_flight)
    }

    /// ASDUs dropped because they did not decode.
    pub fn dropped_asdus(&self) -> u64 {
        self.dropped_asdus
    }

    /// Octets received on `connection`; requests are checked and handed to `handler`.
    pub fn handle_input(&mut self, connection: ConnectionId, bytes: &[u8], now: Instant, handler: &mut dyn CommandHandler) {
        self.touch(now);
        if let Some(i) = self.index(connection) {
            if let Some(c) = self.connections.get_mut(i) {
                c.link.handle_input(bytes, now);
            }
            self.pump(i, handler);
        }
        self.finish();
    }

    /// Acts on every timer expired at `now`, and sends what updates queued.
    pub fn handle_timeout(&mut self, now: Instant) {
        self.touch(now);
        self.selections.retain(|_, s| s.deadline > now);
        self.cyclic_and_background(now);
        for i in 0..self.connections.len() {
            #[cfg(feature = "file-transfer")]
            if self.connections.get(i).and_then(|c| c.transfer).is_some_and(|t| t.deadline <= now) {
                self.end_file(i, super::TransferOutcome::TimedOut);
            }
            if let Some(c) = self.connections.get_mut(i) {
                c.link.handle_timeout(now);
            }
            self.pump(i, &mut RefuseCommands);
        }
        self.flush_soon = false;
        self.finish();
    }

    /// The transport of `connection` is gone.
    pub fn handle_disconnect(&mut self, connection: ConnectionId, now: Instant) {
        self.touch(now);
        if let Some(i) = self.index(connection) {
            if let Some(c) = self.connections.get_mut(i) {
                c.link.handle_disconnect(now);
            }
            self.pump(i, &mut RefuseCommands);
        }
        self.finish();
    }

    /// Closes `connection`.
    pub fn close(&mut self, connection: ConnectionId) {
        if let Some(i) = self.index(connection) {
            if let Some(c) = self.connections.get_mut(i) {
                c.link.close();
            }
            self.pump(i, &mut RefuseCommands);
        }
        self.finish();
    }

    /// The next output, or `None` when there is nothing more for now.
    pub fn poll_output(&mut self) -> Option<Output> {
        if let Some(o) = self.out.pop_front() {
            return Some(o);
        }
        if self.deadline_dirty {
            self.deadline_dirty = false;
            return self.next_deadline().map(Output::Deadline);
        }
        None
    }

    fn touch(&mut self, now: Instant) {
        self.now = now;
        self.deadline_dirty = true;
        if !self.clock_started {
            self.clock_started = true;
            if self.database.addresses().into_iter().any(|ca| self.database.points(ca).any(|(_, p)| p.cyclic)) {
                self.next_cyclic = Some(now + self.config.cyclic_period);
            }
            if let Some(period) = self.config.background_period
                && self.database.addresses().into_iter().any(|ca| self.database.points(ca).any(|(_, p)| p.background))
            {
                self.next_background = Some(now + period);
            }
        }
    }

    fn finish(&mut self) {
        self.connections.retain(|c| !c.closed);
        self.report_losses();
        self.deadline_dirty = true;
    }

    fn next_deadline(&self) -> Option<Instant> {
        if self.flush_soon {
            return Some(Instant::ZERO);
        }
        let links = self.connections.iter().filter(|c| !c.closed).filter_map(|c| c.deadline);
        let selections = self.selections.values().map(|s| s.deadline);
        #[cfg(feature = "file-transfer")]
        let links = links.chain(self.connections.iter().filter_map(|c| c.transfer.map(|t| t.deadline)));
        links.chain(selections).chain(self.next_cyclic).chain(self.next_background).min()
    }

    fn index(&self, connection: ConnectionId) -> Option<usize> {
        self.connections.iter().position(|c| c.id == connection && !c.closed)
    }

    fn report_losses(&mut self) {
        for (g, group) in self.groups.iter_mut().enumerate() {
            if group.lost > 0 {
                let count = core::mem::take(&mut group.lost);
                self.out.push_back(Output::Event(ServerEvent::EventsLost { group: GroupId(u8::try_from(g).unwrap_or(u8::MAX)), count }));
            }
        }
    }

    fn push_event(&mut self, g: usize, event: Buffered) {
        let capacity = self.config.event_capacity.max(1);
        let Some(group) = self.groups.get_mut(g) else { return };
        if group.pending.len() + group.in_flight >= capacity {
            group.lost += 1;
            if group.pending.pop_front().is_none() {
                return;
            }
        }
        group.pending.push_back(event);
    }

    /// Drains the link of connection `i`, acting on its events, and sends what can be sent,
    /// until nothing changes.
    fn pump(&mut self, i: usize, handler: &mut dyn CommandHandler) {
        loop {
            let mut progressed = false;
            while let Some(output) = self.connections.get_mut(i).and_then(|c| c.link.poll_output()) {
                let Some(c) = self.connections.get_mut(i) else { return };
                match output {
                    LinkOutput::Transmit(bytes) => self.out.push_back(Output::Transmit { connection: c.id, bytes }),
                    LinkOutput::Deadline(at) => c.deadline = Some(at),
                    LinkOutput::Event(event) => {
                        progressed = true;
                        self.on_link_event(i, event, handler);
                    }
                }
            }
            if self.connections.get(i).is_none_or(|c| c.closed) {
                return;
            }
            if self.flush(i) {
                progressed = true;
            }
            if !progressed {
                return;
            }
        }
    }

    fn on_link_event(&mut self, i: usize, event: LinkEvent, handler: &mut dyn CommandHandler) {
        let Some(c) = self.connections.get(i) else { return };
        let (id, g) = (c.id, c.group);
        match event {
            LinkEvent::Started => {
                let previous = self.groups.get(g).and_then(|grp| grp.started).filter(|p| *p != id);
                if let Some(previous) = previous
                    && let Some(j) = self.index(previous)
                {
                    if let Some(old) = self.connections.get_mut(j) {
                        old.link.close();
                    }
                    self.pump(j, handler);
                    self.out.push_back(Output::Event(ServerEvent::SwitchedOver { group: GroupId(u8::try_from(g).unwrap_or(u8::MAX)), from: previous, to: id }));
                }
                if let Some(grp) = self.groups.get_mut(g) {
                    grp.started = Some(id);
                }
                self.out.push_back(Output::Event(ServerEvent::Started(id)));
            }
            LinkEvent::Stopped => {
                #[cfg(feature = "file-transfer")]
                self.end_file(i, super::TransferOutcome::Disconnected);
                self.requeue(i);
                if let Some(grp) = self.groups.get_mut(g)
                    && grp.started == Some(id)
                {
                    grp.started = None;
                }
                self.out.push_back(Output::Event(ServerEvent::Stopped(id)));
            }
            LinkEvent::Asdu(bytes) => {
                let started = self.groups.get(g).is_some_and(|grp| grp.started == Some(id));
                if started {
                    self.on_asdu(i, &bytes, handler);
                }
            }
            LinkEvent::Acknowledged { class, count } => self.acknowledge(i, class, count),
            LinkEvent::Unconfirmed { class } => self.unconfirmed(i, class),
            LinkEvent::Closed(reason) => {
                #[cfg(feature = "file-transfer")]
                self.end_file(i, super::TransferOutcome::Disconnected);
                self.requeue(i);
                if let Some(grp) = self.groups.get_mut(g)
                    && grp.started == Some(id)
                {
                    grp.started = None;
                }
                self.selections.retain(|_, s| s.connection != id);
                if let Some(c) = self.connections.get_mut(i) {
                    c.closed = true;
                    c.replies.clear();
                    c.cyclic.clear();
                }
                self.out.push_back(Output::Event(ServerEvent::Disconnected { connection: id, reason }));
            }
        }
    }

    fn acknowledge(&mut self, i: usize, class: Option<Class>, count: u16) {
        let Some(c) = self.connections.get_mut(i) else { return };
        let mut released = 0usize;
        for _ in 0..count {
            let position = match class {
                None => (!c.in_flight.is_empty()).then_some(0),
                Some(class) => c.in_flight.iter().position(|(k, _)| *k == class),
            };
            let Some((_, entry)) = position.and_then(|p| c.in_flight.remove(p)) else { break };
            if let InFlight::Events(events) = entry {
                released += events.len();
            }
        }
        if let Some(grp) = self.groups.get_mut(c.group) {
            grp.in_flight = grp.in_flight.saturating_sub(released);
        }
    }

    /// The link gave up on its oldest ASDU of `class`: its events go back to the head of the
    /// buffer, to be sent again.
    fn unconfirmed(&mut self, i: usize, class: Option<Class>) {
        let Some(c) = self.connections.get_mut(i) else { return };
        let position = match class {
            None => (!c.in_flight.is_empty()).then_some(0),
            Some(class) => c.in_flight.iter().position(|(k, _)| *k == class),
        };
        let Some((_, InFlight::Events(events))) = position.and_then(|p| c.in_flight.remove(p)) else { return };
        let Some(grp) = self.groups.get_mut(c.group) else { return };
        grp.in_flight = grp.in_flight.saturating_sub(events.len());
        for e in events.into_iter().rev() {
            grp.pending.push_front(e);
        }
    }

    /// Puts the unacknowledged events of connection `i` back at the head of its group's
    /// buffer, oldest first.
    fn requeue(&mut self, i: usize) {
        let Some(c) = self.connections.get_mut(i) else { return };
        let Some(grp) = self.groups.get_mut(c.group) else { return };
        for (_, entry) in c.in_flight.drain(..).rev() {
            if let InFlight::Events(events) = entry {
                grp.in_flight = grp.in_flight.saturating_sub(events.len());
                for e in events.into_iter().rev() {
                    grp.pending.push_front(e);
                }
            }
        }
    }

    /// Submits replies, then events (on the group's started connection), then cyclic data.
    /// True if anything was submitted.
    fn flush(&mut self, i: usize) -> bool {
        let now = self.now;
        let mut any = false;
        loop {
            let Some(c) = self.connections.get_mut(i) else { return any };
            if !c.link.is_started() {
                return any;
            }
            if let Some(reply) = c.replies.front() {
                if c.link.submit(&reply.bytes, Class::One, now).is_err() {
                    return any;
                }
                c.replies.pop_front();
                c.in_flight.push_back((Class::One, InFlight::Other));
                any = true;
                continue;
            }
            let (id, g) = (c.id, c.group);
            #[cfg(feature = "file-transfer")]
            if c.link.can_send(Class::One) && self.queue_file_segment(i) {
                continue;
            }
            if self.groups.get(g).is_some_and(|grp| grp.started == Some(id) && !grp.pending.is_empty()) {
                if self.connections.get(i).is_some_and(|c| c.link.can_send(Class::One)) && self.send_events(i) {
                    any = true;
                    continue;
                }
                return any;
            }
            let Some(c) = self.connections.get_mut(i) else { return any };
            if let Some(bytes) = c.cyclic.front() {
                if c.link.submit(bytes, Class::Two, now).is_err() {
                    return any;
                }
                c.cyclic.pop_front();
                c.in_flight.push_back((Class::Two, InFlight::Other));
                any = true;
                continue;
            }
            return any;
        }
    }

    /// Packs the head of the group's buffer into one ASDU and submits it.
    fn send_events(&mut self, i: usize) -> bool {
        let profile = self.config.profile;
        let Some(c) = self.connections.get_mut(i) else { return false };
        let Some(grp) = self.groups.get_mut(c.group) else { return false };
        let Some(first) = grp.pending.front().copied() else { return false };
        let (asdu, n) = match (first.item, first.key()) {
            (Item::EndOfInit(coi), _) => (Asdu::new(first.ca, first.cause, InformationObject::new(Ioa(0), coi)), 1),
            (Item::Point { value, format, .. }, Some(key)) => {
                let run: Vec<(Ioa, Value, Cp56Time2a)> = grp
                    .pending
                    .iter()
                    .take(max_objects(&profile, value.kind(), format))
                    .take_while(|e| e.key() == Some(key))
                    .filter_map(|e| match e.item {
                        Item::Point { ioa, value, time, .. } => Some((ioa, value, time)),
                        Item::EndOfInit(_) => None,
                    })
                    .collect();
                let n = run.len().max(1);
                let Some(objects) = value::pack(value.kind(), format, &run) else {
                    // A kind with no type in this format cannot be sent: drop it.
                    grp.pending.pop_front();
                    grp.lost += 1;
                    return true;
                };
                (Asdu::new(first.ca, first.cause, objects), n)
            }
            (Item::Point { .. }, None) => return false,
        };
        let Ok(bytes) = asdu.to_vec(&profile) else {
            grp.pending.pop_front();
            grp.lost += 1;
            return true;
        };
        if c.link.submit(&bytes, Class::One, self.now).is_err() {
            return false;
        }
        let events: Vec<Buffered> = grp.pending.drain(..n.min(grp.pending.len())).collect();
        grp.in_flight += events.len();
        c.in_flight.push_back((Class::One, InFlight::Events(events)));
        true
    }

    fn cyclic_and_background(&mut self, now: Instant) {
        if self.next_cyclic.is_some_and(|at| now >= at) {
            self.next_cyclic = Some(now + self.config.cyclic_period);
            self.queue_scan(Cause::PERIODIC, |p| p.cyclic);
        }
        if let Some(period) = self.config.background_period
            && self.next_background.is_some_and(|at| now >= at)
        {
            self.next_background = Some(now + period);
            self.queue_scan(Cause::BACKGROUND_SCAN, |p| p.background);
        }
    }

    fn queue_scan(&mut self, cause: Cause, select: fn(&super::database::PointEntry) -> bool) {
        let mut asdus = Vec::new();
        for ca in self.database.addresses() {
            let points: Vec<(Ioa, Value)> = self.database.points(ca).filter(|(_, p)| select(p)).map(|(ioa, p)| (ioa, p.value)).collect();
            asdus.extend(self.encode_points(ca, Cot::new(cause), &points));
        }
        for c in self.connections.iter_mut().filter(|c| c.link.is_started()) {
            c.cyclic.extend(asdus.iter().cloned());
        }
    }

    /// Encodes `points` (values without time tags) into as few ASDUs as fit, one type each.
    fn encode_points(&self, ca: CommonAddress, cot: Cot, points: &[(Ioa, Value)]) -> Vec<Vec<u8>> {
        let profile = &self.config.profile;
        let time = self.time();
        let mut asdus = Vec::new();
        let mut rest = points;
        while let Some(((_, first), _)) = rest.split_first() {
            let kind = first.kind();
            let format = if value::has_untimed_type(kind) { TimeFormat::None } else { TimeFormat::Cp56 };
            let max = max_objects(profile, kind, format);
            let n = rest.iter().take(max).take_while(|(_, v)| v.kind() == kind).count().max(1);
            let (run, tail) = rest.split_at(n.min(rest.len()));
            rest = tail;
            let items: Vec<(Ioa, Value, Cp56Time2a)> = run.iter().map(|(ioa, v)| (*ioa, *v, time)).collect();
            if let Some(objects) = value::pack(kind, format, &items)
                && let Ok(bytes) = Asdu::new(ca, cot, objects).to_vec(profile)
            {
                asdus.push(bytes);
            }
        }
        asdus
    }

    fn reply(&mut self, i: usize, asdu: &Asdu) {
        self.reply_tagged(i, asdu, None);
    }

    fn reply_tagged(&mut self, i: usize, asdu: &Asdu, terminates: Option<CommonAddress>) {
        if let Ok(bytes) = asdu.to_vec(&self.config.profile)
            && let Some(c) = self.connections.get_mut(i)
        {
            c.replies.push_back(Reply { bytes, terminates });
        }
    }

    fn reply_bytes(&mut self, i: usize, replies: Vec<Vec<u8>>) {
        if let Some(c) = self.connections.get_mut(i) {
            c.replies.extend(replies.into_iter().map(|bytes| Reply { bytes, terminates: None }));
        }
    }

    /// Answers `asdu` mirrored with `cause` and P/N.
    fn mirror(&mut self, i: usize, asdu: &Asdu, cause: Cause, negative: bool) {
        let mut m = asdu.clone();
        m.cot = Cot { cause, negative, ..asdu.cot };
        self.reply(i, &m);
    }

    fn on_asdu(&mut self, i: usize, bytes: &[u8], handler: &mut dyn CommandHandler) {
        let Ok(asdu) = Asdu::decode(bytes, &self.config.profile) else {
            self.dropped_asdus = self.dropped_asdus.saturating_add(1);
            return;
        };
        let ca = asdu.common_address;
        let broadcast = ca.0 == self.config.profile.ca.max();
        let known_ca = self.database.has_common_address(ca);
        let type_id = asdu.type_id();
        #[cfg(feature = "file-transfer")]
        if self.file_store.is_some() && asdu.cot.cause == Cause::FILE_TRANSFER && matches!(asdu.objects, Objects::CallSelect(_) | Objects::FileAck(_)) {
            return self.file_call(i, &asdu);
        }
        #[cfg(feature = "file-transfer")]
        if let (Some(store), Objects::CallSelect(objects)) = (&self.file_store, &asdu.objects)
            && asdu.cot.cause == Cause::REQUEST
        {
            let canonical = matches!(objects.as_slice(), [entry] if entry.ioa == Ioa(0) && entry.element == super::file_store::DIRECTORY_CALL);
            if !canonical || asdu.cot.negative || broadcast {
                return self.mirror(i, &asdu, Cause::UNKNOWN_CAUSE, true);
            }
            let profile = self.config.profile;
            let Some(c) = self.connections.get(i) else { return };
            let per_frame = usize::from(profile.max_asdu_len).min(c.link.max_asdu_len()).saturating_sub(profile.header_len()) / (profile.ioa.octets() + 13);
            if per_frame == 0 || !profile.permits(TypeId::F_DR_TA_1) {
                return self.mirror(i, &asdu, Cause::REQUEST, true);
            }
            let limit = super::file_store::DIRECTORY_LIMIT;
            // Stop queuing bulk replies when the link already has a full listing to drain.
            if self.connections.get(i).is_some_and(|c| c.replies.len() >= limit.div_ceil(per_frame)) {
                return self.mirror(i, &asdu, Cause::REQUEST, true);
            }
            let files = store.directory_with_limit(ca, limit + 1);
            if files.is_empty() {
                return self.mirror(i, &asdu, if known_ca { Cause::UNKNOWN_IOA } else { Cause::UNKNOWN_COMMON_ADDRESS }, true);
            }
            if files.len() > limit || files.iter().any(|f| f.length > 0xff_ffff || f.ioa.0 > profile.ioa.max()) {
                return self.mirror(i, &asdu, Cause::REQUEST, true);
            }
            let mut remaining = files.len();
            for chunk in files.chunks(per_frame) {
                let entries: Vec<_> = chunk
                    .iter()
                    .map(|f| {
                        remaining -= 1;
                        let status = (f.status.0 & !super::FileStatus::LAST_FILE) | if remaining == 0 { super::FileStatus::LAST_FILE } else { 0 };
                        InformationObject::new(f.ioa, crate::types::DirectoryEntry { name: f.name.0, length: f.length, status }).at(f.created)
                    })
                    .collect();
                self.reply(i, &Asdu::new(ca, asdu.cot, entries));
            }
            return;
        }
        let handled = matches!(type_id.0, 45..=51 | 58..=64 | 100..=107 | 110..=113) && !matches!(asdu.objects, Objects::Raw(_));
        if !handled {
            return self.mirror(i, &asdu, Cause::UNKNOWN_TYPE_ID, true);
        }
        let may_broadcast = matches!(type_id, TypeId::C_IC_NA_1 | TypeId::C_CI_NA_1 | TypeId::C_CS_NA_1 | TypeId::C_RP_NA_1);
        let is_command = matches!(type_id.0, 45..=51 | 58..=64) && asdu.len() == 1;
        if !(known_ca || broadcast && may_broadcast || is_command) {
            return self.mirror(i, &asdu, Cause::UNKNOWN_COMMON_ADDRESS, true);
        }
        if asdu.len() != 1 {
            // Commands and system commands carry exactly one object.
            let cause = if asdu.cot.cause == Cause::DEACTIVATION { Cause::DEACTIVATION_CON } else { Cause::ACTIVATION_CON };
            return self.mirror(i, &asdu, cause, true);
        }
        let Some(c) = self.connections.get(i) else { return };
        let connection = c.id;
        match &asdu.objects {
            Objects::Interrogation(o) => self.on_interrogation(i, &asdu, o.first().map(|o| (o.ioa, o.element))),
            Objects::CounterInterrogation(o) => self.on_counter_interrogation(i, &asdu, o.first().map(|o| (o.ioa, o.element)), handler),
            Objects::Read(o) => self.on_read(i, &asdu, o.first().map(|o| o.ioa), broadcast),
            Objects::ClockSync(o) => self.on_clock_sync(i, connection, &asdu, o.first().map(|o| (o.ioa, o.time)), handler),
            Objects::TestCommand(o) => self.on_system(i, &asdu, o.first().map(|o| o.ioa), broadcast, &[Cause::ACTIVATION]),
            Objects::TestCommandCp56(o) => self.on_system(i, &asdu, o.first().map(|o| o.ioa), broadcast, &[Cause::ACTIVATION]),
            Objects::DelayAcquisition(o) => self.on_system(i, &asdu, o.first().map(|o| o.ioa), broadcast, &[Cause::ACTIVATION, Cause::SPONTANEOUS]),
            Objects::ResetProcess(o) => self.on_reset(i, &asdu, o.first().map(|o| (o.ioa, o.element)), handler),
            Objects::ParameterNormalized(o) => self.on_parameter(i, connection, &asdu, o.first().map(|o| (o.ioa, Parameter::Normalized(o.element))), handler),
            Objects::ParameterScaled(o) => self.on_parameter(i, connection, &asdu, o.first().map(|o| (o.ioa, Parameter::Scaled(o.element))), handler),
            Objects::ParameterFloat(o) => self.on_parameter(i, connection, &asdu, o.first().map(|o| (o.ioa, Parameter::Float(o.element))), handler),
            Objects::ParameterActivation(o) => self.on_parameter(i, connection, &asdu, o.first().map(|o| (o.ioa, Parameter::Activation(o.element))), handler),
            objects => match command_of(objects) {
                Some((ioa, command, time)) => self.on_command(i, connection, &asdu, ioa, command, time, handler),
                None => self.mirror(i, &asdu, Cause::UNKNOWN_TYPE_ID, true),
            },
        }
    }

    fn on_interrogation(&mut self, i: usize, asdu: &Asdu, object: Option<(Ioa, Interrogation)>) {
        let Some((ioa, qoi)) = object else { return };
        match asdu.cot.cause {
            Cause::ACTIVATION => {}
            Cause::DEACTIVATION => return self.mirror(i, asdu, Cause::DEACTIVATION_CON, true),
            _ => return self.mirror(i, asdu, Cause::UNKNOWN_CAUSE, true),
        }
        if ioa != Ioa(0) {
            return self.mirror(i, asdu, Cause::UNKNOWN_IOA, true);
        }
        let group = qoi.group_number();
        if qoi != Interrogation::STATION && group.is_none() {
            return self.mirror(i, asdu, Cause::ACTIVATION_CON, true);
        }
        for ca in self.targets(asdu.common_address) {
            let busy = self.connections.get(i).is_some_and(|c| c.replies.iter().any(|r| r.terminates == Some(ca)));
            let mut confirmation = asdu.clone();
            confirmation.common_address = ca;
            if busy {
                self.mirror(i, &confirmation, Cause::ACTIVATION_CON, true);
                continue;
            }
            self.mirror(i, &confirmation, Cause::ACTIVATION_CON, false);
            let cause = group.and_then(Cause::interrogated_by_group).unwrap_or(Cause::INTERROGATED_BY_STATION);
            let points: Vec<(Ioa, Value)> = self
                .database
                .points(ca)
                .filter(|(_, p)| match group {
                    None => p.interrogation,
                    Some(g) => p.group == Some(g),
                })
                .filter(|(_, p)| value::has_untimed_type(p.value.kind()))
                .map(|(ioa, p)| (ioa, p.value))
                .collect();
            let replies = self.encode_points(ca, Cot { cause, ..Cot::new(cause).with_originator(asdu.cot.originator) }, &points);
            self.reply_bytes(i, replies);
            let mut termination = confirmation;
            termination.cot = Cot { cause: Cause::ACTIVATION_TERMINATION, negative: false, ..asdu.cot };
            self.reply_tagged(i, &termination, Some(ca));
        }
    }

    fn on_counter_interrogation(&mut self, i: usize, asdu: &Asdu, object: Option<(Ioa, CounterInterrogation)>, handler: &mut dyn CommandHandler) {
        let Some((ioa, qcc)) = object else { return };
        match asdu.cot.cause {
            Cause::ACTIVATION => {}
            Cause::DEACTIVATION => return self.mirror(i, asdu, Cause::DEACTIVATION_CON, true),
            _ => return self.mirror(i, asdu, Cause::UNKNOWN_CAUSE, true),
        }
        if ioa != Ioa(0) {
            return self.mirror(i, asdu, Cause::UNKNOWN_IOA, true);
        }
        let request = qcc.request();
        if !(1..=5).contains(&request) {
            return self.mirror(i, asdu, Cause::ACTIVATION_CON, true);
        }
        let group = (request != 5).then_some(request);
        for ca in self.targets(asdu.common_address) {
            let mut confirmation = asdu.clone();
            confirmation.common_address = ca;
            if handler.counter_interrogation(ca, qcc) == Decision::Refuse {
                self.mirror(i, &confirmation, Cause::ACTIVATION_CON, true);
                continue;
            }
            self.mirror(i, &confirmation, Cause::ACTIVATION_CON, false);
            let mut values = Vec::new();
            for (ioa, p) in self.database.points_mut(ca) {
                let Value::Counter(current) = p.value else { continue };
                if group.is_some_and(|g| p.counter_group != Some(g)) {
                    continue;
                }
                match qcc.freeze() {
                    CounterInterrogation::READ => values.push((ioa, Value::Counter(p.frozen.unwrap_or(current)))),
                    CounterInterrogation::FREEZE => p.frozen = Some(current),
                    CounterInterrogation::FREEZE_AND_RESET => {
                        p.frozen = Some(current);
                        p.value = Value::Counter(crate::types::BinaryCounterReading::new(0).with_sequence((current.sequence() + 1) & 0x1F));
                    }
                    _ => p.value = Value::Counter(crate::types::BinaryCounterReading::new(0).with_sequence(current.sequence())),
                }
            }
            let cause = group.and_then(Cause::requested_by_counter_group).unwrap_or(Cause::REQUESTED_BY_GENERAL_COUNTER);
            let replies = self.encode_points(ca, Cot::new(cause).with_originator(asdu.cot.originator), &values);
            self.reply_bytes(i, replies);
            let mut termination = confirmation;
            termination.cot = Cot { cause: Cause::ACTIVATION_TERMINATION, negative: false, ..asdu.cot };
            self.reply(i, &termination);
        }
    }

    fn on_read(&mut self, i: usize, asdu: &Asdu, ioa: Option<Ioa>, broadcast: bool) {
        let Some(ioa) = ioa else { return };
        if asdu.cot.cause != Cause::REQUEST {
            return self.mirror(i, asdu, Cause::UNKNOWN_CAUSE, true);
        }
        if broadcast {
            return self.mirror(i, asdu, Cause::UNKNOWN_COMMON_ADDRESS, true);
        }
        let ca = asdu.common_address;
        let Some(point) = self.database.point(ca, ioa) else {
            return self.mirror(i, asdu, Cause::UNKNOWN_IOA, true);
        };
        let kind = point.value.kind();
        let format = if value::has_untimed_type(kind) { TimeFormat::None } else { TimeFormat::Cp56 };
        let time = point.time.unwrap_or_else(|| self.time());
        if let Some(objects) = value::pack(kind, format, &[(ioa, point.value, time)]) {
            let reply = Asdu::new(ca, Cot::REQUEST.with_originator(asdu.cot.originator), objects);
            self.reply(i, &reply);
        }
    }

    fn on_clock_sync(&mut self, i: usize, connection: ConnectionId, asdu: &Asdu, object: Option<(Ioa, Cp56Time2a)>, handler: &mut dyn CommandHandler) {
        let Some((ioa, time)) = object else { return };
        if asdu.cot.cause != Cause::ACTIVATION {
            return self.mirror(i, asdu, Cause::UNKNOWN_CAUSE, true);
        }
        if ioa != Ioa(0) {
            return self.mirror(i, asdu, Cause::UNKNOWN_IOA, true);
        }
        let offset = time.clock_millis().and_then(|received| Some(received - self.clock.now().clock_millis()?));
        let accepted = if let Some(offset) = offset
            && handler.clock_sync(time) == Decision::Accept
        {
            self.offset_ms = offset;
            self.out.push_back(Output::Event(ServerEvent::ClockSynchronized { connection, time }));
            true
        } else {
            false
        };
        self.mirror(i, asdu, Cause::ACTIVATION_CON, !accepted);
    }

    fn on_system(&mut self, i: usize, asdu: &Asdu, ioa: Option<Ioa>, broadcast: bool, causes: &[Cause]) {
        let Some(ioa) = ioa else { return };
        if broadcast {
            return self.mirror(i, asdu, Cause::UNKNOWN_COMMON_ADDRESS, true);
        }
        if ioa != Ioa(0) {
            return self.mirror(i, asdu, Cause::UNKNOWN_IOA, true);
        }
        if !causes.contains(&asdu.cot.cause) {
            return self.mirror(i, asdu, Cause::UNKNOWN_CAUSE, true);
        }
        self.mirror(i, asdu, Cause::ACTIVATION_CON, false);
    }

    fn on_reset(&mut self, i: usize, asdu: &Asdu, object: Option<(Ioa, ResetProcess)>, handler: &mut dyn CommandHandler) {
        let Some((ioa, qrp)) = object else { return };
        if asdu.cot.cause != Cause::ACTIVATION {
            return self.mirror(i, asdu, Cause::UNKNOWN_CAUSE, true);
        }
        if ioa != Ioa(0) {
            return self.mirror(i, asdu, Cause::UNKNOWN_IOA, true);
        }
        let accepted = handler.reset_process(asdu.common_address, qrp) == Decision::Accept;
        if accepted && qrp == ResetProcess::EVENT_BUFFER {
            for g in &mut self.groups {
                g.pending.clear();
            }
        }
        self.mirror(i, asdu, Cause::ACTIVATION_CON, !accepted);
    }

    fn on_parameter(&mut self, i: usize, connection: ConnectionId, asdu: &Asdu, object: Option<(Ioa, Parameter)>, handler: &mut dyn CommandHandler) {
        let Some((ioa, parameter)) = object else { return };
        let activation = matches!(parameter, Parameter::Activation(_));
        let cause = asdu.cot.cause;
        if !(cause == Cause::ACTIVATION || activation && cause == Cause::DEACTIVATION) {
            return self.mirror(i, asdu, Cause::UNKNOWN_CAUSE, true);
        }
        let confirm = if cause == Cause::DEACTIVATION { Cause::DEACTIVATION_CON } else { Cause::ACTIVATION_CON };
        let ca = asdu.common_address;
        let point_kind = self.database.point(ca, ioa).map(|p| p.value.kind());
        let known = match parameter {
            Parameter::Activation(qpa) => (qpa.0 == 1 && ioa == Ioa(0)) || point_kind.is_some(),
            _ => matches!(point_kind, Some(ValueKind::Normalized | ValueKind::Scaled | ValueKind::Float)),
        };
        if !known {
            return self.mirror(i, asdu, Cause::UNKNOWN_IOA, true);
        }
        let request = ParameterRequest { connection, common_address: ca, ioa, parameter };
        let accepted = handler.parameter(&request) == Decision::Accept;
        if accepted && let Some(point) = self.database.point_mut(ca, ioa) {
            let kpa = match parameter {
                Parameter::Normalized(p) => Some(p.qualifier.kind()),
                Parameter::Scaled(p) => Some(p.qualifier.kind()),
                Parameter::Float(p) => Some(p.qualifier.kind()),
                Parameter::Activation(_) => None,
            };
            if let Some(slot) = kpa.and_then(|k| usize::from(k).checked_sub(1)).and_then(|k| point.parameters.get_mut(k)) {
                *slot = Some(parameter);
            }
        }
        self.mirror(i, asdu, confirm, !accepted);
    }

    #[allow(clippy::too_many_arguments)]
    fn on_command(
        &mut self,
        i: usize,
        connection: ConnectionId,
        asdu: &Asdu,
        ioa: Ioa,
        command: Command,
        time: Option<Cp56Time2a>,
        handler: &mut dyn CommandHandler,
    ) {
        let ca = asdu.common_address;
        let cause = asdu.cot.cause;
        let select = command.is_select();
        let originator = asdu.cot.originator;
        let type_id = asdu.type_id();
        let request = CommandRequest {
            connection,
            common_address: ca,
            ioa,
            command: command.execute(),
            phase: if select { Phase::Select } else { Phase::Execute },
            originator,
            test: asdu.cot.test,
            time,
        };
        let confirm = |station: &mut Self, reply, refused: bool| {
            station.out.push_back(Output::Event(ServerEvent::CommandDecision {
                request,
                cancellation: cause == Cause::DEACTIVATION,
                decision: Decision::from(!refused),
            }));
            station.mirror(i, asdu, reply, refused);
        };
        if !self.database.has_common_address(ca) {
            return confirm(self, Cause::UNKNOWN_COMMON_ADDRESS, true);
        }
        if cause != Cause::ACTIVATION && cause != Cause::DEACTIVATION {
            return confirm(self, Cause::UNKNOWN_CAUSE, true);
        }
        let Some((kind, mode)) = self.database.command_at(ca, ioa) else {
            return confirm(self, Cause::UNKNOWN_IOA, true);
        };
        if kind != command.kind() {
            return confirm(self, Cause::UNKNOWN_IOA, true);
        }
        let now = self.now;
        let live = self.selections.get(&(ca, ioa)).copied().filter(|s| s.deadline > now);
        let matches = live.is_some_and(|s| s.connection == connection && s.type_id == type_id && s.originator == originator && s.command == request.command);
        if cause == Cause::DEACTIVATION {
            if matches {
                self.selections.remove(&(ca, ioa));
                handler.cancel(&request);
            }
            return confirm(self, Cause::DEACTIVATION_CON, !matches);
        }
        if select {
            let owned_by_other = live.is_some_and(|s| s.connection != connection || s.originator != originator);
            if mode == CommandMode::Direct || kind == CommandKind::Bitstring || owned_by_other {
                return confirm(self, Cause::ACTIVATION_CON, true);
            }
            let accepted = handler.select(&request) == Decision::Accept;
            if accepted {
                let deadline = now + self.config.select_timeout;
                self.selections.insert((ca, ioa), Selection { connection, type_id, originator, command: request.command, deadline });
                self.deadline_dirty = true;
            } else {
                self.selections.remove(&(ca, ioa));
            }
            return confirm(self, Cause::ACTIVATION_CON, !accepted);
        }
        // Execute: a live selection is consumed whether or not it matches.
        if live.is_some() {
            self.selections.remove(&(ca, ioa));
        }
        let allowed = match mode {
            CommandMode::SelectBeforeOperate => matches,
            CommandMode::Direct => live.is_none(),
            CommandMode::DirectOrSelect => live.is_none() || matches,
        };
        if !allowed {
            return confirm(self, Cause::ACTIVATION_CON, true);
        }
        let accepted = handler.execute(&request) == Decision::Accept
            && handler.feedback(&request, self.database.as_ref()).is_none_or(|(ioa, value)| self.update(ca, ioa, value).is_ok());
        confirm(self, Cause::ACTIVATION_CON, !accepted);
        if accepted {
            self.mirror(i, asdu, Cause::ACTIVATION_TERMINATION, false);
        }
    }

    /// The common addresses a request for `ca` addresses: all of them for the broadcast address.
    fn targets(&self, ca: CommonAddress) -> Vec<CommonAddress> {
        if ca.0 == self.config.profile.ca.max() { self.database.addresses() } else { alloc::vec![ca] }
    }
}

/// The most objects of `kind` in `format` one ASDU of `profile` can carry.
fn max_objects(profile: &Profile, kind: ValueKind, format: TimeFormat) -> usize {
    let sample = match kind {
        ValueKind::Single => Value::from(false),
        ValueKind::Double => Value::from(crate::types::DoublePointValue::Off),
        ValueKind::Step => Value::from(crate::types::StepPosition::new(0)),
        ValueKind::Bitstring => Value::from(crate::types::Bitstring32::new(0)),
        ValueKind::Normalized => Value::from(crate::types::MeasuredNormalized::new(crate::types::Normalized(0))),
        ValueKind::Scaled => Value::from(0i16),
        ValueKind::Float => Value::from(0f32),
        ValueKind::Counter => Value::from(crate::types::BinaryCounterReading::new(0)),
        ValueKind::PackedSingle => Value::from(crate::types::PackedSinglePoints::new(0, 0)),
        ValueKind::NormalizedRaw => Value::from(crate::types::Normalized(0)),
        ValueKind::ProtectionEvent => Value::from(crate::types::ProtectionEvent::default()),
        ValueKind::StartEvents => Value::from(crate::types::PackedStartEvents::default()),
        ValueKind::OutputCircuits => Value::from(crate::types::PackedOutputCircuits::default()),
    };
    let t = Cp56Time2a::default();
    let Some(objects) = value::pack(kind, format, &[(Ioa(0), sample, t)]) else { return 1 };
    let one = Asdu::new(CommonAddress(0), Cot::SPONTANEOUS, objects).encoded_len(profile);
    let per_object = one.saturating_sub(profile.header_len()).max(1);
    (usize::from(profile.max_asdu_len).saturating_sub(profile.header_len()) / per_object).clamp(1, 127)
}

/// The single command of a command ASDU.
fn command_of(objects: &Objects) -> Option<(Ioa, Command, Option<Cp56Time2a>)> {
    macro_rules! one {
        ($v:expr, $time:expr) => {
            $v.first().map(|o| (o.ioa, Command::from(o.element), $time(o)))
        };
    }
    fn none<T>(_: &T) -> Option<Cp56Time2a> {
        None
    }
    match objects {
        Objects::SingleCommand(v) => one!(v, none),
        Objects::SingleCommandCp56(v) => one!(v, |o: &InformationObject<_, Cp56Time2a>| Some(o.time)),
        Objects::DoubleCommand(v) => one!(v, none),
        Objects::DoubleCommandCp56(v) => one!(v, |o: &InformationObject<_, Cp56Time2a>| Some(o.time)),
        Objects::StepCommand(v) => one!(v, none),
        Objects::StepCommandCp56(v) => one!(v, |o: &InformationObject<_, Cp56Time2a>| Some(o.time)),
        Objects::SetpointNormalized(v) => one!(v, none),
        Objects::SetpointNormalizedCp56(v) => one!(v, |o: &InformationObject<_, Cp56Time2a>| Some(o.time)),
        Objects::SetpointScaled(v) => one!(v, none),
        Objects::SetpointScaledCp56(v) => one!(v, |o: &InformationObject<_, Cp56Time2a>| Some(o.time)),
        Objects::SetpointFloat(v) => one!(v, none),
        Objects::SetpointFloatCp56(v) => one!(v, |o: &InformationObject<_, Cp56Time2a>| Some(o.time)),
        Objects::BitstringCommand(v) => one!(v, none),
        Objects::BitstringCommandCp56(v) => one!(v, |o: &InformationObject<_, Cp56Time2a>| Some(o.time)),
        _ => None,
    }
}
