//! The blocking 104 client: [`Client`].

#[cfg(feature = "tls")]
mod tls;

use std::boxed::Box;
use std::collections::VecDeque;
use std::io;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::cs104::{self, CloseReason, Cs104Link, Role};
use crate::driver::BlockingDriver;
use crate::station::{ClientConfig, Command, ControllingStation, Error, Event, LinkClosed, Parameter, Point, Progress, RequestId};
use crate::time::{Clock, Cp56Time2a};
use crate::transport::ClientStream;
use crate::types::{Cause, CommonAddress, CounterInterrogation, Interrogation, Ioa, ResetProcess};

/// A clock behind a box, so builders can hold any clock.
pub(crate) struct BoxedClock(pub(crate) Box<dyn Clock + Send>);

impl Clock for BoxedClock {
    fn now(&self) -> Cp56Time2a {
        self.0.now()
    }
}

#[cfg(feature = "std")]
pub(crate) fn system_clock() -> BoxedClock {
    BoxedClock(Box::new(crate::time::SystemClock))
}

pub(crate) fn disconnected() -> Error {
    Error::Disconnected(LinkClosed::new(CloseReason::PeerClosed))
}

/// A controlling station (master) over one TCP connection, blocking.
///
/// Every procedure is one method. Those with replies return an iterator that drives the
/// connection until the outstation terminates them; everything else that arrives meanwhile —
/// spontaneous points, other confirmations — waits for [`next_event`](Self::next_event).
///
/// ```no_run
/// use iec60870::prelude::*;
///
/// let mut client = iec60870::Client::connect("10.0.0.5:2404")?;
/// client.start()?;                                   // STARTDT
/// for event in client.interrogate(CommonAddress(1))? {
///     println!("{:?}", event?);
/// }
/// # Ok::<(), iec60870::Error>(())
/// ```
#[derive(Debug)]
pub struct Client {
    driver: BlockingDriver<ControllingStation<Cs104Link>, ClientStream>,
    backlog: Option<VecDeque<Event>>,
}

/// Builds a [`Client`] with a non-default link, station configuration or clock.
///
/// ```no_run
/// use iec60870::station::ClientConfig;
/// use iec60870::{cs104, Client};
///
/// let client = Client::builder()
///     .link(cs104::Config { k: 24, ..cs104::Config::default() })
///     .config(ClientConfig { time_tagged_commands: true, ..ClientConfig::default() })
///     .connect("10.0.0.5:2404")?;
/// # Ok::<(), iec60870::Error>(())
/// ```
pub struct ClientBuilder {
    link: cs104::Config,
    config: ClientConfig,
    clock: BoxedClock,
}

impl core::fmt::Debug for ClientBuilder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClientBuilder").field("link", &self.link).field("config", &self.config).finish_non_exhaustive()
    }
}

impl ClientBuilder {
    /// The 104 link parameters (k, w, t0–t3).
    #[must_use]
    pub fn link(mut self, link: cs104::Config) -> Self {
        self.link = link;
        self
    }

    /// The station configuration (timeouts, originator, time-tagged commands).
    #[must_use]
    pub fn config(mut self, config: ClientConfig) -> Self {
        self.config = config;
        self
    }

    /// The clock that time-tags clock synchronisation, test commands and time-tagged commands
    /// (default: the system clock, UTC).
    #[must_use]
    pub fn clock(mut self, clock: impl Clock + Send + 'static) -> Self {
        self.clock = BoxedClock(Box::new(clock));
        self
    }

    /// Connects within the link's t0 per address tried. Data transfer is not started yet.
    pub fn connect(self, addr: impl ToSocketAddrs) -> Result<Client, Error> {
        let link = Cs104Link::new(Role::Controlling, self.link).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let mut last = io::Error::new(io::ErrorKind::InvalidInput, "no address to connect to");
        for addr in addr.to_socket_addrs()? {
            match TcpStream::connect_timeout(&addr, self.link.t0) {
                Ok(stream) => {
                    stream.set_nodelay(true)?;
                    let station = ControllingStation::new(link, self.config, self.clock);
                    return Ok(Client { driver: BlockingDriver::new(station, ClientStream::Tcp(stream)), backlog: Some(VecDeque::new()) });
                }
                Err(e) => last = e,
            }
        }
        Err(last.into())
    }
}

impl Client {
    /// Connects to an outstation with the default configuration.
    pub fn connect(addr: impl ToSocketAddrs) -> Result<Client, Error> {
        Self::builder().connect(addr)
    }

    /// A builder for a non-default configuration.
    pub fn builder() -> ClientBuilder {
        ClientBuilder { link: cs104::Config::default(), config: ClientConfig::default(), clock: system_clock() }
    }

    /// The station core (its configuration, its link state).
    pub fn station(&self) -> &ControllingStation<Cs104Link> {
        self.driver.protocol()
    }

    /// Controls whether a blocking procedure saves unrelated events for later
    /// [polling](Self::poll_event). Enabled by default. Turning buffering off drops
    /// queued events and skips future unrelated events while waiting for a reply.
    /// Direct event polling and the procedure's own results are unaffected.
    pub fn set_event_buffering(&mut self, enabled: bool) {
        if enabled {
            self.backlog.get_or_insert_with(VecDeque::new);
        } else {
            self.backlog = None;
        }
    }

    fn retain_event(&mut self, event: Event) {
        if let Some(backlog) = &mut self.backlog {
            backlog.push_back(event);
        }
    }

    /// Starts data transfer (STARTDT) and waits for the confirmation.
    pub fn start(&mut self) -> Result<(), Error> {
        self.driver.with(ControllingStation::start)?;
        loop {
            match self.raw()? {
                Event::Started => return Ok(()),
                Event::Disconnected(reason) => return Err(Error::Disconnected(reason)),
                other => self.retain_event(other),
            }
        }
    }

    /// Stops data transfer (STOPDT) and waits for the confirmation.
    pub fn stop(&mut self) -> Result<(), Error> {
        self.driver.with(ControllingStation::stop)?;
        loop {
            match self.raw()? {
                Event::Stopped => return Ok(()),
                Event::Disconnected(reason) => return Err(Error::Disconnected(reason)),
                other => self.retain_event(other),
            }
        }
    }

    /// Station interrogation: the iterator yields every point the outstation reports for it,
    /// then [`Event::InterrogationComplete`], and ends.
    pub fn interrogate(&mut self, ca: CommonAddress) -> Result<Replies<'_>, Error> {
        let id = self.driver.with(|s, now| s.interrogate(ca, Interrogation::STATION, now))?;
        Ok(Replies::new(self, id, ca))
    }

    /// Group interrogation (group 1–16).
    pub fn interrogate_group(&mut self, ca: CommonAddress, group: u8) -> Result<Replies<'_>, Error> {
        let qoi = Interrogation::group(group).ok_or(Error::InvalidArgument("interrogation groups are 1 to 16"))?;
        let id = self.driver.with(|s, now| s.interrogate(ca, qoi, now))?;
        Ok(Replies::new(self, id, ca))
    }

    /// Counter interrogation: the counters (for a read qualifier), then
    /// [`Event::CounterInterrogationComplete`].
    pub fn counter_interrogate(&mut self, ca: CommonAddress, qcc: CounterInterrogation) -> Result<Replies<'_>, Error> {
        let id = self.driver.with(|s, now| s.counter_interrogate(ca, qcc, now))?;
        Ok(Replies::new(self, id, ca))
    }

    /// Download a record and verify its length and checksums.
    #[cfg(feature = "file-transfer")]
    pub fn download(&mut self, ca: CommonAddress, ioa: Ioa, name: impl Into<crate::station::FileName>) -> Result<alloc::vec::Vec<u8>, Error> {
        let id = self.driver.with(|s, now| s.download(ca, ioa, name, now))?;
        let mut result = None;
        loop {
            match self.raw()? {
                Event::File { id: r, data, .. } if r == id => result = Some(data),
                Event::Request { id: r, progress: Progress::Failed(e) } if r == id => return Err(e),
                Event::Request { id: r, progress: Progress::Completed } if r == id => return result.ok_or(Error::InvalidArgument("missing file contents")),
                other => self.retain_event(other),
            }
        }
    }

    /// List the file records at one station.
    #[cfg(feature = "file-transfer")]
    pub fn files(&mut self, ca: CommonAddress) -> Result<alloc::vec::Vec<crate::station::FileInfo>, Error> {
        let id = self.driver.with(|s, now| s.directory(ca, now))?;
        let mut result = None;
        loop {
            match self.raw()? {
                Event::Directory { id: r, files, .. } if r == id => result = Some(files),
                Event::Request { id: r, progress: Progress::Failed(e) } if r == id => return Err(e),
                Event::Request { id: r, progress: Progress::Completed } if r == id => return result.ok_or(Error::InvalidDirectory),
                other => self.retain_event(other),
            }
        }
    }

    /// Reads one point.
    pub fn read(&mut self, ca: CommonAddress, ioa: Ioa) -> Result<Point, Error> {
        let id = self.driver.with(|s, now| s.read(ca, ioa, now))?;
        let mut point = None;
        loop {
            match self.raw()? {
                Event::Point(p) if p.common_address == ca && p.ioa == ioa && p.cause.cause == Cause::REQUEST && point.is_none() => point = Some(p),
                Event::Request { id: r, progress } if r == id => match progress {
                    Progress::Completed => return point.ok_or(Error::Negative { cot: crate::types::Cot::REQUEST }),
                    Progress::Failed(e) => return Err(e),
                    Progress::Selected | Progress::Confirmed => {}
                },
                other => self.retain_event(other),
            }
        }
    }

    /// Clock synchronisation with the clock's time; waits for the confirmation.
    pub fn clock_sync(&mut self, ca: CommonAddress) -> Result<(), Error> {
        let id = self.driver.with(|s, now| s.clock_sync(ca, now))?;
        self.wait(id)
    }

    /// A direct command; the steps end with [`Progress::Completed`] on the termination.
    pub fn command(&mut self, ca: CommonAddress, ioa: Ioa, command: impl Into<Command>) -> Result<CommandSteps<'_>, Error> {
        let command = command.into();
        let id = self.driver.with(|s, now| s.command(ca, ioa, command, now))?;
        Ok(CommandSteps { client: self, id, done: false })
    }

    /// Select-before-operate: `Selected`, `Confirmed`, `Completed`.
    pub fn select_and_execute(&mut self, ca: CommonAddress, ioa: Ioa, command: impl Into<Command>) -> Result<CommandSteps<'_>, Error> {
        let command = command.into();
        let id = self.driver.with(|s, now| s.select_and_execute(ca, ioa, command, now))?;
        Ok(CommandSteps { client: self, id, done: false })
    }

    /// The test command; waits for the confirmation.
    pub fn test_command(&mut self, ca: CommonAddress) -> Result<(), Error> {
        let id = self.driver.with(|s, now| s.test_command(ca, now))?;
        self.wait(id)
    }

    /// Reset process; waits for the confirmation.
    pub fn reset_process(&mut self, ca: CommonAddress, qrp: ResetProcess) -> Result<(), Error> {
        let id = self.driver.with(|s, now| s.reset_process(ca, qrp, now))?;
        self.wait(id)
    }

    /// Parameter loading or activation; waits for the confirmation.
    pub fn parameter(&mut self, ca: CommonAddress, ioa: Ioa, parameter: impl Into<Parameter>) -> Result<(), Error> {
        let parameter = parameter.into();
        let id = self.driver.with(|s, now| s.parameter(ca, ioa, parameter, now))?;
        self.wait(id)
    }

    /// The next event (spontaneous points, …); `Ok(None)` once the connection is closed.
    pub fn next_event(&mut self) -> Result<Option<Event>, Error> {
        if let Some(e) = self.backlog.as_mut().and_then(VecDeque::pop_front) {
            return Ok(Some(e));
        }
        Ok(self.driver.next_event()?)
    }

    /// Like [`next_event`](Self::next_event), but gives up after `max_wait` with `Ok(None)`.
    pub fn poll_event(&mut self, max_wait: Duration) -> Result<Option<Event>, Error> {
        if let Some(e) = self.backlog.as_mut().and_then(VecDeque::pop_front) {
            return Ok(Some(e));
        }
        Ok(self.driver.poll_event(max_wait)?)
    }

    fn raw(&mut self) -> Result<Event, Error> {
        self.driver.next_event()?.ok_or_else(disconnected)
    }

    fn wait(&mut self, id: RequestId) -> Result<(), Error> {
        CommandSteps { client: self, id, done: false }.wait()
    }
}

/// The replies of an interrogation: `Result<Event, Error>` items, ending after
/// [`Event::InterrogationComplete`] or [`Event::CounterInterrogationComplete`], or with the error
/// that failed it (a negative confirmation, [`Error::Timeout`]).
///
/// ```
/// # fn run(client: &mut iec60870::Client) -> Result<(), iec60870::Error> {
/// use iec60870::prelude::*;
///
/// let points: Vec<Point> = client
///     .interrogate(CommonAddress(1))?
///     .filter_map(|e| match e { Ok(Event::Point(p)) => Some(Ok(p)), Ok(_) => None, Err(e) => Some(Err(e)) })
///     .collect::<Result<_, _>>()?;
/// # let _ = points; Ok(()) }
/// ```
#[derive(Debug)]
pub struct Replies<'a> {
    client: &'a mut Client,
    id: RequestId,
    ca: CommonAddress,
    complete: Option<Event>,
    done: bool,
}

impl<'a> Replies<'a> {
    fn new(client: &'a mut Client, id: RequestId, ca: CommonAddress) -> Self {
        Replies { client, id, ca, complete: None, done: false }
    }
}

pub(crate) fn is_reply(event: &Event, ca: CommonAddress, broadcast: u16) -> bool {
    match event {
        Event::Point(p) => {
            let c = p.cause.cause.value();
            (p.common_address == ca || ca.0 == broadcast) && (20..=41).contains(&c)
        }
        _ => false,
    }
}

impl Iterator for Replies<'_> {
    type Item = Result<Event, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        while !self.done {
            let event = match self.client.raw() {
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
                other => self.client.retain_event(other),
            }
        }
        None
    }
}

/// The steps of a command: `Result<Progress, Error>` items — `Selected` (select-before-operate),
/// `Confirmed`, `Completed` — ending after `Completed` or with the error that failed it.
///
/// ```
/// # fn run(client: &mut iec60870::Client) -> Result<(), iec60870::Error> {
/// use iec60870::prelude::*;
///
/// for step in client.select_and_execute(CommonAddress(1), Ioa(5000), Command::single(true))? {
///     println!("{:?}", step?); // Selected, Confirmed, Completed
/// }
/// client.command(CommonAddress(1), Ioa(5001), Command::setpoint_float(42.0))?.wait()?;
/// # Ok(()) }
/// ```
#[derive(Debug)]
pub struct CommandSteps<'a> {
    client: &'a mut Client,
    id: RequestId,
    done: bool,
}

impl CommandSteps<'_> {
    /// Drives the command to its end.
    pub fn wait(self) -> Result<(), Error> {
        for step in self {
            step?;
        }
        Ok(())
    }
}

impl Iterator for CommandSteps<'_> {
    type Item = Result<Progress, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        while !self.done {
            let event = match self.client.raw() {
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
                other => self.client.retain_event(other),
            }
        }
        None
    }
}
