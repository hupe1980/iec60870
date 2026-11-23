//! The blocking 104 server: [`Server`] and [`ServerHandle`].

#[cfg(feature = "tls")]
mod tls;

use std::boxed::Box;
use std::collections::{BTreeMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant as StdInstant};
use std::vec::Vec;

use crate::client::{BoxedClock, system_clock};
use crate::cs104::{self, Cs104Link, Role};
use crate::station::{
    CommandHandler, ConnectionId, ControlledStation, GroupId, Output, RefuseCommands, ServerConfig, ServerEvent, UpdateError, Value, ValueKind,
};
use crate::time::{Clock, Cp56Time2a, Instant};
use crate::types::{CommonAddress, Ioa};

const EVENT_QUEUE: usize = 1024;

/// Where a connection's octets go: a writer thread or task.
pub(crate) trait ConnWriter: Send {
    /// Queues octets for the connection.
    fn send(&self, bytes: Vec<u8>);
    /// Ends the connection (its reader stops too).
    fn close(&self);
}

/// Redundancy groups by peer address.
pub(crate) type Groups = Vec<(GroupId, Vec<IpAddr>)>;

/// Each connection's writer.
pub(crate) type Writers = BTreeMap<ConnectionId, (SocketAddr, Box<dyn ConnWriter>)>;

struct ThreadWriter {
    tx: Sender<Vec<u8>>,
    stream: TcpStream,
}

impl ConnWriter for ThreadWriter {
    fn send(&self, bytes: Vec<u8>) {
        let _ = self.tx.send(bytes);
    }

    fn close(&self) {
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}

std::thread_local! {
    /// Set while this thread holds a server's state (and so may be inside a command handler).
    static HOLDING: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

/// An update made from inside a command handler, applied when the handler returns.
pub(crate) type Deferred = (CommonAddress, Ioa, Value, Option<Cp56Time2a>);

pub(crate) struct State {
    pub(crate) station: ControlledStation<Cs104Link>,
    pub(crate) handler: Box<dyn CommandHandler + Send>,
    pub(crate) deadline: Option<Instant>,
    events: VecDeque<(ServerEvent, Option<SocketAddr>)>,
    dropped_events: usize,
}

impl State {
    pub(crate) fn pop_event(&mut self) -> Option<(ServerEvent, Option<SocketAddr>)> {
        if self.dropped_events > 0 {
            Some((ServerEvent::ObserverLagged { count: std::mem::take(&mut self.dropped_events) }, None))
        } else {
            self.events.pop_front()
        }
    }
    /// Hands every output to `write` (per connection) and keeps the events and the deadline.
    fn dispatch(&mut self, writers: &mut Writers) {
        while let Some(output) = self.station.poll_output() {
            match output {
                Output::Transmit { connection, bytes } => {
                    if let Some((_, w)) = writers.get(&connection) {
                        w.send(bytes);
                    }
                }
                Output::Deadline(at) => self.deadline = Some(at),
                Output::Event(event) => {
                    let id = match &event {
                        ServerEvent::CommandDecision { request, .. } => Some(&request.connection),
                        ServerEvent::Started(id)
                        | ServerEvent::Stopped(id)
                        | ServerEvent::Disconnected { connection: id, .. }
                        | ServerEvent::ClockSynchronized { connection: id, .. } => Some(id),
                        _ => None,
                    };
                    let peer = id.and_then(|id| writers.get(id)).map(|(peer, _)| *peer);
                    if let ServerEvent::Disconnected { connection, .. } = &event
                        && let Some((_, w)) = writers.remove(connection)
                    {
                        w.close();
                    }
                    if self.events.len() >= EVENT_QUEUE {
                        self.events.pop_front();
                        self.dropped_events = self.dropped_events.saturating_add(1);
                    }
                    self.events.push_back((event, peer));
                }
            }
        }
    }
}

/// What a server's threads or tasks share.
pub(crate) struct Shared {
    state: Mutex<State>,
    pub(crate) writers: Mutex<Writers>,
    deferred: Mutex<Vec<Deferred>>,
    kinds: BTreeMap<(CommonAddress, Ioa), ValueKind>,
    pub(crate) timer: Condvar,
    pub(crate) events: Condvar,
    pub(crate) shutdown: AtomicBool,
    epoch: StdInstant,
    pub(crate) local: SocketAddr,
    /// Called after every change (the async server wakes its timer and event waiters).
    wake: Box<dyn Fn() + Send + Sync>,
}

impl Shared {
    pub(crate) fn new(station: ControlledStation<Cs104Link>, local: SocketAddr, wake: Box<dyn Fn() + Send + Sync>) -> Self {
        let kinds = station.database().kinds();
        Shared {
            state: Mutex::new(State { station, handler: Box::new(RefuseCommands), deadline: None, events: VecDeque::new(), dropped_events: 0 }),
            writers: Mutex::new(BTreeMap::new()),
            deferred: Mutex::new(Vec::new()),
            kinds,
            timer: Condvar::new(),
            events: Condvar::new(),
            shutdown: AtomicBool::new(false),
            epoch: StdInstant::now(),
            local,
            wake,
        }
    }

    pub(crate) fn now(&self) -> Instant {
        Instant::from_nanos(u64::try_from(self.epoch.elapsed().as_nanos()).unwrap_or(u64::MAX))
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) fn writers(&self) -> MutexGuard<'_, Writers> {
        self.writers.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) fn peer(&self, id: ConnectionId) -> Option<SocketAddr> {
        self.writers().get(&id).map(|(peer, _)| *peer)
    }

    /// Runs `f` on the state, applies the updates its handler made, then dispatches the outputs.
    pub(crate) fn with<R>(&self, f: impl FnOnce(&mut State, Instant) -> R) -> R {
        let now = self.now();
        let mut state = self.lock();
        HOLDING.set(true);
        let r = f(&mut state, now);
        HOLDING.set(false);
        let deferred = std::mem::take(&mut *self.deferred.lock().unwrap_or_else(std::sync::PoisonError::into_inner));
        if !deferred.is_empty() {
            for (ca, ioa, value, time) in deferred {
                let _ = match time {
                    Some(t) => state.station.update_at(ca, ioa, value, t),
                    None => state.station.update(ca, ioa, value),
                };
            }
            state.station.handle_timeout(now);
        }
        let mut writers = self.writers();
        let had_events = state.events.len();
        state.dispatch(&mut writers);
        if state.events.len() != had_events || !state.events.is_empty() {
            self.events.notify_all();
        }
        self.timer.notify_all();
        drop(writers);
        drop(state);
        (self.wake)();
        r
    }

    /// An update from a handle: checked against the point kinds, deferred when called from
    /// inside a command handler, else applied and sent at once.
    pub(crate) fn apply(&self, ca: CommonAddress, ioa: Ioa, value: Value, time: Option<Cp56Time2a>) -> Result<(), UpdateError> {
        check_kind(&self.kinds, ca, ioa, &value)?;
        if HOLDING.get() {
            self.deferred.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push((ca, ioa, value, time));
            return Ok(());
        }
        self.with(|state, now| {
            let r = match time {
                Some(t) => state.station.update_at(ca, ioa, value, t),
                None => state.station.update(ca, ioa, value),
            };
            state.station.handle_timeout(now);
            r
        })
    }

    /// Closes every connection.
    pub(crate) fn close_all(&self) {
        for (_, (_, w)) in std::mem::take(&mut *self.writers()) {
            w.close();
        }
    }
}

/// A controlled station (outstation) serving a [`Database`](crate::Database) over TCP, blocking.
///
/// [`run`](Self::run) accepts connections on the calling thread, with a reader and a writer
/// thread per connection and one timer thread; [`spawn`](Self::spawn) does the same in the
/// background. Updates come through a [`ServerHandle`] from any thread.
///
/// ```no_run
/// use iec60870::prelude::*;
/// use iec60870::Server;
///
/// let ca = CommonAddress(1);
/// let mut db = Database::new();
/// db.insert(ca, Ioa(100), false);
/// db.command(ca, Ioa(5000), CommandKind::Single);
///
/// let server = Server::bind("0.0.0.0:2404", db)?;
/// let handle = server.handle();
/// std::thread::spawn(move || loop {
///     std::thread::sleep(std::time::Duration::from_secs(1));
///     let _ = handle.update(ca, Ioa(100), true);
/// });
/// server.run(|request: &CommandRequest| {
///     println!("{request}");
///     Decision::Accept
/// })?;
/// # Ok::<(), std::io::Error>(())
/// ```
pub struct Server {
    listener: TcpListener,
    shared: Arc<Shared>,
    link: cs104::Config,
    groups: Vec<(GroupId, Vec<IpAddr>)>,
    #[cfg(feature = "tls")]
    tls: Option<crate::tls::TlsServerConfig>,
}

impl core::fmt::Debug for Server {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Server").field("local", &self.shared.local).finish_non_exhaustive()
    }
}

/// Builds a [`Server`] with a non-default link, station configuration, clock or redundancy
/// groups.
///
/// ```no_run
/// use iec60870::station::{Database, ServerConfig};
/// use iec60870::Server;
///
/// let server = Server::builder()
///     .config(ServerConfig { event_capacity: 10_000, ..ServerConfig::default() })
///     .group(["10.0.0.1".parse()?, "10.0.0.2".parse()?]) // one master, two connections
///     .bind("0.0.0.0:2404", Database::new())?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct ServerBuilder {
    #[cfg(feature = "file-transfer")]
    files: Option<Box<dyn crate::station::FileStore + Send>>,
    link: cs104::Config,
    config: ServerConfig,
    clock: BoxedClock,
    groups: Vec<Vec<IpAddr>>,
    #[cfg(feature = "tls")]
    pub(crate) tls: Option<crate::tls::TlsServerConfig>,
}

impl core::fmt::Debug for ServerBuilder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ServerBuilder").field("link", &self.link).field("config", &self.config).field("groups", &self.groups).finish_non_exhaustive()
    }
}

impl ServerBuilder {
    /// Install the file catalog for directory requests.
    #[cfg(feature = "file-transfer")]
    #[must_use]
    pub fn files(mut self, store: impl crate::station::FileStore + Send + 'static) -> Self {
        self.files = Some(Box::new(store));
        self
    }

    /// The 104 link parameters of every connection.
    #[must_use]
    pub fn link(mut self, link: cs104::Config) -> Self {
        self.link = link;
        self
    }

    /// The station configuration.
    #[must_use]
    pub fn config(mut self, config: ServerConfig) -> Self {
        self.config = config;
        self
    }

    /// The clock that time-tags events (default: the system clock, UTC).
    #[must_use]
    pub fn clock(mut self, clock: impl Clock + Send + 'static) -> Self {
        self.clock = BoxedClock(Box::new(clock));
        self
    }

    /// A redundancy group: connections from these addresses share one event buffer, and one
    /// at a time is started. Connections from other addresses share the default group.
    #[must_use]
    pub fn group(mut self, peers: impl IntoIterator<Item = IpAddr>) -> Self {
        self.groups.push(peers.into_iter().collect());
        self
    }

    /// Binds the listener.
    pub fn bind(self, addr: impl ToSocketAddrs, database: impl crate::station::PointSource + 'static) -> io::Result<Server> {
        self.link.validate().map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let listener = TcpListener::bind(addr)?;
        let local = listener.local_addr()?;
        #[cfg(feature = "tls")]
        let tls = self.tls.clone();
        let (link, station, groups) = self.into_station(database);
        let shared = Arc::new(Shared::new(station, local, Box::new(|| {})));
        Ok(Server {
            listener,
            shared,
            link,
            groups,
            #[cfg(feature = "tls")]
            tls,
        })
    }

    /// The station core with its redundancy groups, for the blocking and the async server.
    pub(crate) fn into_station(self, database: impl crate::station::PointSource + 'static) -> (cs104::Config, ControlledStation<Cs104Link>, Groups) {
        let mut station = ControlledStation::new(database, self.config, self.clock);
        #[cfg(feature = "file-transfer")]
        {
            station.file_store = self.files;
        }
        let groups = self.groups.into_iter().map(|peers| (station.add_group(), peers)).collect();
        (self.link, station, groups)
    }
}

impl Server {
    /// Binds a server for `database` with the default configuration.
    pub fn bind(addr: impl ToSocketAddrs, database: impl crate::station::PointSource + 'static) -> io::Result<Server> {
        Self::builder().bind(addr, database)
    }

    /// A builder for a non-default configuration.
    pub fn builder() -> ServerBuilder {
        ServerBuilder {
            #[cfg(feature = "file-transfer")]
            files: None,
            link: cs104::Config::default(),
            config: ServerConfig::default(),
            clock: system_clock(),
            groups: Vec::new(),
            #[cfg(feature = "tls")]
            tls: None,
        }
    }

    /// The address the server listens on.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// A handle for updates and events, usable from any thread.
    pub fn handle(&self) -> ServerHandle {
        ServerHandle { shared: Arc::clone(&self.shared) }
    }

    /// Serves until [`ServerHandle::shutdown`], answering commands with `handler`.
    pub fn run(self, handler: impl CommandHandler + Send + 'static) -> io::Result<()> {
        self.shared.lock().handler = Box::new(handler);
        let timer = {
            let shared = Arc::clone(&self.shared);
            thread::Builder::new().name("iec60870-timer".into()).spawn(move || timer_loop(&shared))?
        };
        for stream in self.listener.incoming() {
            if self.shared.shutdown.load(Ordering::SeqCst) {
                break;
            }
            let Ok(stream) = stream else { continue };
            #[cfg(feature = "tls")]
            if let Some(tls) = &self.tls {
                // The handshake runs on the connection's own thread; a refusal is a security event.
                let _ = self.serve_tls(stream, tls);
                continue;
            }
            if let Err(e) = self.serve(stream) {
                // One failed connection does not stop the server.
                let _ = e;
            }
        }
        self.shared.timer.notify_all();
        let _ = timer.join();
        Ok(())
    }

    /// Serves in a background thread; returns the handle (whose `shutdown` stops it).
    pub fn spawn(self, handler: impl CommandHandler + Send + 'static) -> io::Result<ServerHandle> {
        let handle = self.handle();
        thread::Builder::new().name("iec60870-server".into()).spawn(move || self.run(handler))?;
        Ok(handle)
    }

    fn serve(&self, stream: TcpStream) -> io::Result<()> {
        stream.set_nodelay(true)?;
        let peer = stream.peer_addr()?;
        let group = self.groups.iter().find(|(_, peers)| peers.contains(&peer.ip())).map_or(GroupId(0), |(g, _)| *g);
        let link = Cs104Link::new(Role::Controlled, self.link).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let mut reader = stream.try_clone()?;
        let mut writer = stream.try_clone()?;
        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        let id = self.shared.with(|state, now| {
            let id = state.station.attach(link, group);
            state.station.handle_timeout(now);
            id
        });
        self.shared.writers().insert(id, (peer, Box::new(ThreadWriter { tx, stream })));
        let detach = |_: &io::Error| self.shared.with(|state, now| state.station.handle_disconnect(id, now));
        thread::Builder::new()
            .name("iec60870-write".into())
            .spawn(move || {
                for bytes in rx {
                    if writer.write_all(&bytes).and_then(|()| writer.flush()).is_err() {
                        let _ = writer.shutdown(Shutdown::Both);
                        break;
                    }
                }
            })
            .inspect_err(&detach)?;
        let shared = Arc::clone(&self.shared);
        thread::Builder::new()
            .name("iec60870-read".into())
            .spawn(move || {
                let mut buf = [0u8; 4096];
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => shared.with(|state, now| {
                            let State { station, handler, .. } = state;
                            station.handle_input(id, buf.get(..n).unwrap_or_default(), now, &mut **handler);
                        }),
                    }
                }
                shared.with(|state, now| state.station.handle_disconnect(id, now));
            })
            .inspect_err(detach)?;
        Ok(())
    }
}

pub(crate) fn check_kind(kinds: &BTreeMap<(CommonAddress, Ioa), ValueKind>, ca: CommonAddress, ioa: Ioa, value: &Value) -> Result<(), UpdateError> {
    match kinds.get(&(ca, ioa)) {
        None => Err(UpdateError::UnknownPoint { common_address: ca, ioa }),
        Some(kind) if *kind != value.kind() => Err(UpdateError::KindMismatch { expected: *kind, found: value.kind() }),
        Some(_) => Ok(()),
    }
}

fn timer_loop(shared: &Shared) {
    let mut state = shared.lock();
    while !shared.shutdown.load(Ordering::SeqCst) {
        let now = shared.now();
        match state.deadline {
            Some(at) if at <= now => {
                state.deadline = None;
                drop(state);
                shared.with(|state, now| state.station.handle_timeout(now));
                state = shared.lock();
            }
            deadline => {
                let wait = deadline.map_or(Duration::from_secs(1), |at| at.saturating_duration_since(now)).max(Duration::from_millis(1));
                state = shared.timer.wait_timeout(state, wait).map_or_else(|e| e.into_inner().0, |(s, _)| s);
            }
        }
    }
}

/// Updates the database of a running [`Server`] and reads its events, from any thread.
///
/// ```
/// use iec60870::prelude::*;
///
/// let mut db = Database::new();
/// db.insert(CommonAddress(1), Ioa(100), 0.0f32);
/// let handle = iec60870::Server::bind("127.0.0.1:0", db)?.spawn(iec60870::station::RefuseCommands)?;
/// handle.update(CommonAddress(1), Ioa(100), 21.5f32)?;
/// assert_eq!(handle.value(CommonAddress(1), Ioa(100)), Some(21.5f32.into()));
/// handle.shutdown();
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone)]
pub struct ServerHandle {
    shared: Arc<Shared>,
}

impl core::fmt::Debug for ServerHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ServerHandle").field("local", &self.shared.local).finish_non_exhaustive()
    }
}

impl ServerHandle {
    /// Sets a point to `value`, time-tagged now; spontaneous points send an event at once.
    ///
    /// It may be called from inside the command handler (to report a breaker's new position,
    /// say); the update is then applied as soon as the handler returns.
    pub fn update(&self, ca: CommonAddress, ioa: Ioa, value: impl Into<Value>) -> Result<(), UpdateError> {
        self.apply(ca, ioa, value.into(), None)
    }

    /// Sets a point to `value` with an explicit time tag.
    pub fn update_at(&self, ca: CommonAddress, ioa: Ioa, value: impl Into<Value>, time: Cp56Time2a) -> Result<(), UpdateError> {
        self.apply(ca, ioa, value.into(), Some(time))
    }

    fn apply(&self, ca: CommonAddress, ioa: Ioa, value: Value, time: Option<Cp56Time2a>) -> Result<(), UpdateError> {
        self.shared.apply(ca, ioa, value, time)
    }

    /// The current value of a point.
    pub fn value(&self, ca: CommonAddress, ioa: Ioa) -> Option<Value> {
        self.shared.lock().station.database().value(ca, ioa)
    }

    /// The station's time (its clock, corrected by clock synchronisation).
    pub fn time(&self) -> Cp56Time2a {
        self.shared.lock().station.time()
    }

    /// The next station event, waiting at most `max_wait`. The last 1024 are kept.
    pub fn next_event(&self, max_wait: Duration) -> Option<ServerEvent> {
        self.next_event_with_peer(max_wait).map(|(event, _)| event)
    }

    /// Returns the event and its peer address captured before disconnection or queueing.
    pub fn next_event_with_peer(&self, max_wait: Duration) -> Option<(ServerEvent, Option<SocketAddr>)> {
        let until = StdInstant::now() + max_wait;
        let mut state = self.shared.lock();
        loop {
            if let Some(e) = state.pop_event() {
                return Some(e);
            }
            let left = until.saturating_duration_since(StdInstant::now());
            if left.is_zero() {
                return None;
            }
            state = self.shared.events.wait_timeout(state, left).map_or_else(|e| e.into_inner().0, |(s, _)| s);
        }
    }

    /// Returns the remote socket address while this connection is registered.
    /// A command handler can use the request's connection ID to identify its peer.
    ///
    /// ```
    /// use iec60870::{ServerHandle, station::CommandRequest};
    ///
    /// fn log_peer(handle: &ServerHandle, request: &CommandRequest) {
    ///     if let Some(peer) = handle.peer(request.connection) {
    ///         eprintln!("{peer} {request}");
    ///     }
    /// }
    /// ```
    pub fn peer(&self, id: ConnectionId) -> Option<SocketAddr> {
        self.shared.peer(id)
    }

    /// The number of open connections.
    pub fn connections(&self) -> usize {
        self.shared.lock().station.connections().count()
    }

    /// The address the server listens on.
    pub fn local_addr(&self) -> SocketAddr {
        self.shared.local
    }

    /// Stops accepting, closes every connection and ends [`Server::run`].
    pub fn shutdown(&self) {
        self.shared.shutdown.store(true, Ordering::SeqCst);
        self.shared.close_all();
        self.shared.timer.notify_all();
        // Wake the accept loop.
        let mut wake = self.shared.local;
        if wake.ip().is_unspecified() {
            wake.set_ip(if wake.is_ipv4() { IpAddr::from([127, 0, 0, 1]) } else { IpAddr::from([0u16, 0, 0, 0, 0, 0, 0, 1]) });
        }
        let _ = TcpStream::connect_timeout(&wake, Duration::from_millis(200));
    }
}
