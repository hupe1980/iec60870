//! The Tokio client and server: [`AsyncClient`], [`AsyncServer`].

#[cfg(feature = "tls")]
mod tls;

use std::boxed::Box;
use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::vec::Vec;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio::sync::{Notify, mpsc};
use tokio::task::AbortHandle;

use crate::client::{BoxedClock, disconnected, is_reply, system_clock};
use crate::cs104::{self, Cs104Link, Role};
use crate::driver::TokioDriver;
use crate::server::{ConnWriter, ServerBuilder, Shared, State};
use crate::station::{
    ClientConfig, Command, CommandHandler, ConnectionId, ControllingStation, Error, Event, GroupId, Parameter, Point, Progress, RequestId, ServerEvent,
    UpdateError, Value,
};
use crate::time::{Clock, Cp56Time2a};
use crate::transport::BoxedAsyncStream;
use crate::types::{Cause, CommonAddress, CounterInterrogation, Interrogation, Ioa, ResetProcess};

/// [`Client`](crate::Client) over Tokio: the same procedures as `async fn`s.
///
/// ```no_run
/// use iec60870::prelude::*;
///
/// # async fn run() -> Result<(), iec60870::Error> {
/// let mut client = iec60870::AsyncClient::connect("10.0.0.5:2404").await?;
/// client.start().await?;
/// let mut replies = client.interrogate(CommonAddress(1))?;
/// while let Some(event) = replies.next().await {
///     println!("{:?}", event?);
/// }
/// # Ok(()) }
/// ```
#[derive(Debug)]
pub struct AsyncClient {
    driver: TokioDriver<ControllingStation<Cs104Link>, BoxedAsyncStream>,
    backlog: VecDeque<Event>,
}

#[cfg(feature = "file-transfer")]
struct ActiveDownload<'a> {
    client: &'a mut AsyncClient,
    id: RequestId,
}

#[cfg(feature = "file-transfer")]
impl Drop for ActiveDownload<'_> {
    fn drop(&mut self) {
        self.client.driver.with(|station, now| station.cancel_download(self.id, now));
    }
}

impl AsyncClient {
    /// Connects to an outstation with the default configuration.
    pub async fn connect(addr: impl ToSocketAddrs) -> Result<AsyncClient, Error> {
        Self::connect_with(addr, cs104::Config::default(), ClientConfig::default(), system_clock()).await
    }

    /// Connects with a link configuration, a station configuration and a clock.
    pub async fn connect_with(
        addr: impl ToSocketAddrs,
        link: cs104::Config,
        config: ClientConfig,
        clock: impl Clock + Send + 'static,
    ) -> Result<AsyncClient, Error> {
        let core = Cs104Link::new(Role::Controlling, link).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let stream = tokio::time::timeout(link.t0, TcpStream::connect(addr)).await.map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        stream.set_nodelay(true)?;
        let station = ControllingStation::new(core, config, BoxedClock(Box::new(clock)));
        Ok(AsyncClient { driver: TokioDriver::new(station, Box::new(stream)), backlog: VecDeque::new() })
    }

    /// The station core.
    pub fn station(&self) -> &ControllingStation<Cs104Link> {
        self.driver.protocol()
    }

    /// Starts data transfer and waits for the confirmation.
    pub async fn start(&mut self) -> Result<(), Error> {
        self.driver.with(ControllingStation::start)?;
        loop {
            match self.raw().await? {
                Event::Started => return Ok(()),
                Event::Disconnected(reason) => return Err(Error::Disconnected(reason)),
                other => self.backlog.push_back(other),
            }
        }
    }

    /// Stops data transfer and waits for the confirmation.
    pub async fn stop(&mut self) -> Result<(), Error> {
        self.driver.with(ControllingStation::stop)?;
        loop {
            match self.raw().await? {
                Event::Stopped => return Ok(()),
                Event::Disconnected(reason) => return Err(Error::Disconnected(reason)),
                other => self.backlog.push_back(other),
            }
        }
    }

    /// Station interrogation: sends it; the replies are awaited one by one.
    pub fn interrogate(&mut self, ca: CommonAddress) -> Result<AsyncReplies<'_>, Error> {
        let id = self.driver.with(|s, now| s.interrogate(ca, Interrogation::STATION, now))?;
        Ok(AsyncReplies { client: self, id, ca, complete: None, done: false })
    }

    /// Group interrogation (group 1–16).
    pub fn interrogate_group(&mut self, ca: CommonAddress, group: u8) -> Result<AsyncReplies<'_>, Error> {
        let qoi = Interrogation::group(group).ok_or(Error::InvalidArgument("interrogation groups are 1 to 16"))?;
        let id = self.driver.with(|s, now| s.interrogate(ca, qoi, now))?;
        Ok(AsyncReplies { client: self, id, ca, complete: None, done: false })
    }

    /// Counter interrogation.
    pub fn counter_interrogate(&mut self, ca: CommonAddress, qcc: CounterInterrogation) -> Result<AsyncReplies<'_>, Error> {
        let id = self.driver.with(|s, now| s.counter_interrogate(ca, qcc, now))?;
        Ok(AsyncReplies { client: self, id, ca, complete: None, done: false })
    }

    /// Download a record and verify its length and checksums.
    #[cfg(feature = "file-transfer")]
    pub async fn download(&mut self, ca: CommonAddress, ioa: Ioa, name: impl Into<crate::station::FileName>) -> Result<Vec<u8>, Error> {
        let id = self.driver.with(|s, now| s.download(ca, ioa, name, now))?;
        let active = ActiveDownload { client: self, id };
        let mut result = None;
        loop {
            match active.client.raw().await? {
                Event::File { id: r, data, .. } if r == id => result = Some(data),
                Event::Request { id: r, progress: Progress::Failed(e) } if r == id => return Err(e),
                Event::Request { id: r, progress: Progress::Completed } if r == id => return result.ok_or(Error::InvalidArgument("missing file contents")),
                other => active.client.backlog.push_back(other),
            }
        }
    }

    /// List the file records at one station.
    #[cfg(feature = "file-transfer")]
    pub async fn files(&mut self, ca: CommonAddress) -> Result<Vec<crate::station::FileInfo>, Error> {
        let id = self.driver.with(|s, now| s.directory(ca, now))?;
        let mut result = None;
        loop {
            match self.raw().await? {
                Event::Directory { id: r, files, .. } if r == id => result = Some(files),
                Event::Request { id: r, progress: Progress::Failed(e) } if r == id => return Err(e),
                Event::Request { id: r, progress: Progress::Completed } if r == id => return result.ok_or(Error::InvalidDirectory),
                other => self.backlog.push_back(other),
            }
        }
    }

    /// Reads one point.
    pub async fn read(&mut self, ca: CommonAddress, ioa: Ioa) -> Result<Point, Error> {
        let id = self.driver.with(|s, now| s.read(ca, ioa, now))?;
        let mut point = None;
        loop {
            match self.raw().await? {
                Event::Point(p) if p.common_address == ca && p.ioa == ioa && p.cause.cause == Cause::REQUEST && point.is_none() => point = Some(p),
                Event::Request { id: r, progress } if r == id => match progress {
                    Progress::Completed => return point.ok_or(Error::Negative { cot: crate::types::Cot::REQUEST }),
                    Progress::Failed(e) => return Err(e),
                    Progress::Selected | Progress::Confirmed => {}
                },
                other => self.backlog.push_back(other),
            }
        }
    }

    /// Clock synchronisation with the clock's time.
    pub async fn clock_sync(&mut self, ca: CommonAddress) -> Result<(), Error> {
        let id = self.driver.with(|s, now| s.clock_sync(ca, now))?;
        AsyncCommandSteps { client: self, id, done: false }.wait().await
    }

    /// A direct command.
    pub fn command(&mut self, ca: CommonAddress, ioa: Ioa, command: impl Into<Command>) -> Result<AsyncCommandSteps<'_>, Error> {
        let command = command.into();
        let id = self.driver.with(|s, now| s.command(ca, ioa, command, now))?;
        Ok(AsyncCommandSteps { client: self, id, done: false })
    }

    /// Select-before-operate.
    pub fn select_and_execute(&mut self, ca: CommonAddress, ioa: Ioa, command: impl Into<Command>) -> Result<AsyncCommandSteps<'_>, Error> {
        let command = command.into();
        let id = self.driver.with(|s, now| s.select_and_execute(ca, ioa, command, now))?;
        Ok(AsyncCommandSteps { client: self, id, done: false })
    }

    /// The test command.
    pub async fn test_command(&mut self, ca: CommonAddress) -> Result<(), Error> {
        let id = self.driver.with(|s, now| s.test_command(ca, now))?;
        AsyncCommandSteps { client: self, id, done: false }.wait().await
    }

    /// Reset process.
    pub async fn reset_process(&mut self, ca: CommonAddress, qrp: ResetProcess) -> Result<(), Error> {
        let id = self.driver.with(|s, now| s.reset_process(ca, qrp, now))?;
        AsyncCommandSteps { client: self, id, done: false }.wait().await
    }

    /// Parameter loading or activation.
    pub async fn parameter(&mut self, ca: CommonAddress, ioa: Ioa, parameter: impl Into<Parameter>) -> Result<(), Error> {
        let parameter = parameter.into();
        let id = self.driver.with(|s, now| s.parameter(ca, ioa, parameter, now))?;
        AsyncCommandSteps { client: self, id, done: false }.wait().await
    }

    /// The next event; `Ok(None)` once the connection is closed. Cancel-safe.
    pub async fn next_event(&mut self) -> Result<Option<Event>, Error> {
        if let Some(e) = self.backlog.pop_front() {
            return Ok(Some(e));
        }
        Ok(self.driver.next_event().await?)
    }

    /// Like [`next_event`](Self::next_event), but `Ok(None)` after `max_wait` as well.
    pub async fn poll_event(&mut self, max_wait: Duration) -> Result<Option<Event>, Error> {
        if let Some(e) = self.backlog.pop_front() {
            return Ok(Some(e));
        }
        match tokio::time::timeout(max_wait, self.driver.next_event()).await {
            Ok(r) => Ok(r?),
            Err(_) => Ok(None),
        }
    }

    async fn raw(&mut self) -> Result<Event, Error> {
        self.driver.next_event().await?.ok_or_else(disconnected)
    }
}

/// The replies of an interrogation over Tokio; see [`Replies`](crate::Replies).
///
/// ```
/// # async fn run(client: &mut iec60870::AsyncClient) -> Result<(), iec60870::Error> {
/// let mut replies = client.interrogate(iec60870::CommonAddress(1))?;
/// while let Some(event) = replies.next().await {
///     println!("{:?}", event?);
/// }
/// # Ok(()) }
/// ```
#[derive(Debug)]
pub struct AsyncReplies<'a> {
    client: &'a mut AsyncClient,
    id: RequestId,
    ca: CommonAddress,
    complete: Option<Event>,
    done: bool,
}

impl AsyncReplies<'_> {
    /// The next reply, `None` after the last.
    pub async fn next(&mut self) -> Option<Result<Event, Error>> {
        while !self.done {
            let event = match self.client.raw().await {
                Ok(e) => e,
                Err(e) => {
                    self.done = true;
                    return Some(Err(e));
                }
            };
            match event {
                Event::Request { id, progress } if id == self.id => match progress {
                    Progress::Completed => {
                        self.done = true;
                        return self.complete.take().map(Ok);
                    }
                    Progress::Failed(e) => {
                        self.done = true;
                        return Some(Err(e));
                    }
                    Progress::Selected | Progress::Confirmed => {}
                },
                e @ (Event::InterrogationComplete { .. } | Event::CounterInterrogationComplete { .. }) if self.complete.is_none() => self.complete = Some(e),
                e if is_reply(&e, self.ca, self.client.station().config().profile.ca.max()) => return Some(Ok(e)),
                other => self.client.backlog.push_back(other),
            }
        }
        None
    }
}

/// The steps of a command over Tokio; see [`CommandSteps`](crate::CommandSteps).
///
/// ```
/// # async fn run(client: &mut iec60870::AsyncClient) -> Result<(), iec60870::Error> {
/// use iec60870::prelude::*;
/// client.select_and_execute(CommonAddress(1), Ioa(5000), Command::single(true))?.wait().await?;
/// # Ok(()) }
/// ```
#[derive(Debug)]
pub struct AsyncCommandSteps<'a> {
    client: &'a mut AsyncClient,
    id: RequestId,
    done: bool,
}

impl AsyncCommandSteps<'_> {
    /// The next step, `None` after `Completed` or an error.
    pub async fn next(&mut self) -> Option<Result<Progress, Error>> {
        while !self.done {
            let event = match self.client.raw().await {
                Ok(e) => e,
                Err(e) => {
                    self.done = true;
                    return Some(Err(e));
                }
            };
            match event {
                Event::Request { id, progress } if id == self.id => {
                    return Some(match progress {
                        Progress::Failed(e) => {
                            self.done = true;
                            Err(e)
                        }
                        Progress::Completed => {
                            self.done = true;
                            Ok(Progress::Completed)
                        }
                        p => Ok(p),
                    });
                }
                other => self.client.backlog.push_back(other),
            }
        }
        None
    }

    /// Drives the command to its end.
    pub async fn wait(mut self) -> Result<(), Error> {
        while let Some(step) = self.next().await {
            step?;
        }
        Ok(())
    }
}

struct TaskWriter {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    reader: Arc<std::sync::Mutex<Option<AbortHandle>>>,
}

impl ConnWriter for TaskWriter {
    fn send(&self, bytes: Vec<u8>) {
        let _ = self.tx.send(bytes);
    }

    fn close(&self) {
        // An empty buffer tells the writer task to shut the stream down.
        let _ = self.tx.send(Vec::new());
        if let Some(reader) = self.reader.lock().ok().and_then(|mut r| r.take()) {
            reader.abort();
        }
    }
}

/// [`Server`](crate::Server) over Tokio: connections are tasks on the current runtime.
///
/// ```no_run
/// use iec60870::prelude::*;
///
/// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let mut db = Database::new();
/// db.insert(CommonAddress(1), Ioa(100), false);
/// let server = iec60870::AsyncServer::bind("0.0.0.0:2404", db).await?;
/// let handle = server.handle();
/// tokio::spawn(server.run(|request: &CommandRequest| Decision::from(request.ioa == Ioa(5000))));
/// handle.update(CommonAddress(1), Ioa(100), true)?;
/// # Ok(()) }
/// ```
pub struct AsyncServer {
    listener: TcpListener,
    shared: Arc<Shared>,
    notify: Arc<Notify>,
    stop: Arc<Notify>,
    link: cs104::Config,
    groups: Vec<(GroupId, Vec<IpAddr>)>,
    #[cfg(feature = "tls")]
    tls: Option<crate::tls::TlsServerConfig>,
}

impl core::fmt::Debug for AsyncServer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AsyncServer").field("local", &self.shared.local).finish_non_exhaustive()
    }
}

impl ServerBuilder {
    /// Binds a Tokio listener for an [`AsyncServer`].
    pub async fn bind_async(self, addr: impl ToSocketAddrs, database: impl crate::station::PointSource + 'static) -> io::Result<AsyncServer> {
        let listener = TcpListener::bind(addr).await?;
        let local = listener.local_addr()?;
        #[cfg(feature = "tls")]
        let tls = self.tls.clone();
        let (link, station, groups) = self.into_station(database);
        link.validate().map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let notify = Arc::new(Notify::new());
        let wake = Arc::clone(&notify);
        let shared = Arc::new(Shared::new(station, local, Box::new(move || wake.notify_waiters())));
        Ok(AsyncServer {
            listener,
            shared,
            notify,
            stop: Arc::new(Notify::new()),
            link,
            groups,
            #[cfg(feature = "tls")]
            tls,
        })
    }
}

impl AsyncServer {
    /// Binds a server for `database` with the default configuration; for others use
    /// [`Server::builder`](crate::Server::builder) and [`ServerBuilder::bind_async`].
    pub async fn bind(addr: impl ToSocketAddrs, database: impl crate::station::PointSource + 'static) -> io::Result<AsyncServer> {
        crate::Server::builder().bind_async(addr, database).await
    }

    /// The address the server listens on.
    pub fn local_addr(&self) -> SocketAddr {
        self.shared.local
    }

    /// A handle for updates and events.
    pub fn handle(&self) -> AsyncServerHandle {
        AsyncServerHandle { shared: Arc::clone(&self.shared), notify: Arc::clone(&self.notify), stop: Arc::clone(&self.stop) }
    }

    /// Serves until [`AsyncServerHandle::shutdown`], answering commands with `handler`.
    pub async fn run(self, handler: impl CommandHandler + Send + 'static) -> io::Result<()> {
        self.shared.lock().handler = Box::new(handler);
        let timer = tokio::spawn(timer_task(Arc::clone(&self.shared), Arc::clone(&self.notify)));
        while !self.shared.shutdown.load(Ordering::SeqCst) {
            let accepted = tokio::select! {
                accepted = self.listener.accept() => accepted,
                () = self.stop.notified() => continue,
            };
            let Ok((stream, peer)) = accepted else { continue };
            #[cfg(feature = "tls")]
            if let Some(tls) = &self.tls {
                // The handshake runs in the connection's own task; a refusal is a security event.
                self.serve_tls(stream, peer, tls);
                continue;
            }
            let _ = self.serve(stream, peer);
        }
        timer.abort();
        Ok(())
    }

    fn serve(&self, stream: TcpStream, peer: SocketAddr) -> io::Result<()> {
        stream.set_nodelay(true)?;
        let group = self.groups.iter().find(|(_, peers)| peers.contains(&peer.ip())).map_or(GroupId(0), |(g, _)| *g);
        let link = Cs104Link::new(Role::Controlled, self.link).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let (mut read, mut write) = stream.into_split();
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let id = self.shared.with(|state, now| {
            let id = state.station.attach(link, group);
            state.station.handle_timeout(now);
            id
        });
        tokio::spawn(async move {
            while let Some(bytes) = rx.recv().await {
                if bytes.is_empty() || write.write_all(&bytes).await.is_err() {
                    break;
                }
            }
            let _ = write.shutdown().await;
        });
        let abort = Arc::new(std::sync::Mutex::new(None));
        self.shared.writers().insert(id, (peer, Box::new(TaskWriter { tx, reader: Arc::clone(&abort) })));
        let shared = Arc::clone(&self.shared);
        let reader = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                match read.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => shared.with(|state, now| {
                        let State { station, handler, .. } = state;
                        station.handle_input(id, buf.get(..n).unwrap_or_default(), now, &mut **handler);
                    }),
                }
            }
            shared.with(|state, now| state.station.handle_disconnect(id, now));
        });
        if let Ok(mut slot) = abort.lock() {
            *slot = Some(reader.abort_handle());
        }
        Ok(())
    }
}

async fn timer_task(shared: Arc<Shared>, notify: Arc<Notify>) {
    while !shared.shutdown.load(Ordering::SeqCst) {
        let now = shared.now();
        let deadline = shared.lock().deadline;
        match deadline {
            Some(at) if at <= now => {
                shared.lock().deadline = None;
                shared.with(|state, now| state.station.handle_timeout(now));
            }
            deadline => {
                let wait = deadline.map_or(Duration::from_secs(1), |at| at.saturating_duration_since(now)).max(Duration::from_millis(1));
                let notified = notify.notified();
                tokio::select! {
                    () = tokio::time::sleep(wait) => {}
                    () = notified => {}
                }
            }
        }
    }
}

/// Updates the database of a running [`AsyncServer`] and awaits its events.
///
/// ```
/// # async fn run(handle: iec60870::AsyncServerHandle) {
/// use iec60870::prelude::*;
/// let _ = handle.update(CommonAddress(1), Ioa(100), true);
/// if let Some(event) = handle.next_event(std::time::Duration::from_secs(1)).await {
///     println!("{event:?}");
/// }
/// # }
/// ```
#[derive(Clone)]
pub struct AsyncServerHandle {
    shared: Arc<Shared>,
    notify: Arc<Notify>,
    stop: Arc<Notify>,
}

impl core::fmt::Debug for AsyncServerHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AsyncServerHandle").field("local", &self.shared.local).finish_non_exhaustive()
    }
}

impl AsyncServerHandle {
    /// Sets a point to `value`, time-tagged now (callable from the command handler too).
    pub fn update(&self, ca: CommonAddress, ioa: Ioa, value: impl Into<Value>) -> Result<(), UpdateError> {
        self.shared.apply(ca, ioa, value.into(), None)
    }

    /// Sets a point to `value` with an explicit time tag.
    pub fn update_at(&self, ca: CommonAddress, ioa: Ioa, value: impl Into<Value>, time: Cp56Time2a) -> Result<(), UpdateError> {
        self.shared.apply(ca, ioa, value.into(), Some(time))
    }

    /// The current value of a point.
    pub fn value(&self, ca: CommonAddress, ioa: Ioa) -> Option<Value> {
        self.shared.lock().station.database().value(ca, ioa)
    }

    /// The next station event, waiting at most `max_wait`.
    pub async fn next_event(&self, max_wait: Duration) -> Option<ServerEvent> {
        let until = tokio::time::Instant::now() + max_wait;
        loop {
            let notified = self.notify.notified();
            if let Some((e, _)) = self.shared.lock().pop_event() {
                return Some(e);
            }
            if tokio::time::timeout_at(until, notified).await.is_err() {
                return self.shared.lock().pop_event().map(|(e, _)| e);
            }
        }
    }

    /// Returns the remote socket address while this connection is registered.
    /// A command handler can use the request's connection ID to identify its peer.
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

    /// Stops accepting, closes every connection and ends [`AsyncServer::run`].
    pub fn shutdown(&self) {
        self.shared.shutdown.store(true, Ordering::SeqCst);
        self.shared.close_all();
        self.notify.notify_waiters();
        self.stop.notify_one();
    }
}
