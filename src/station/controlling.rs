//! The controlling station (master): [`ControllingStation`].

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::fmt;
use core::fmt::Write as _;
use core::time::Duration;

use super::command::{Command, Parameter};
use super::error::{Awaiting, Error};
use super::link::{Class, LinkError, LinkEvent, StationLink};
use super::value::Point;
use crate::asdu::{Asdu, InformationObject, Objects, Profile};
use crate::driver::{Output, Protocol};
use crate::time::{Clock, Cp56Time2a, Instant};
use crate::types::{
    Cause, ClockSync, CommonAddress, Cot, CounterInterrogation, EndOfInitialization, Interrogation, Ioa, Read, ResetProcess, TestCommand, TestCounter, TypeId,
};

/// A request of a [`ControllingStation`], as its procedure methods return it.
///
/// ```
/// use iec60870::station::RequestId;
/// assert_eq!(RequestId(7).to_string(), "request 7");
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RequestId(pub u32);

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "request {}", self.0)
    }
}

/// How far a request got. Every request ends with exactly one `Completed` or `Failed`.
///
/// ```
/// use iec60870::station::{Error, Progress};
///
/// fn done(p: &Progress) -> bool {
///     matches!(p, Progress::Completed | Progress::Failed(_))
/// }
/// assert!(done(&Progress::Failed(Error::Busy)) && !done(&Progress::Selected));
/// ```
#[derive(Clone, Debug)]
pub enum Progress {
    /// The select of select-before-operate was confirmed; the execute is sent.
    Selected,
    /// The activation was confirmed; the termination (or the data) follows.
    Confirmed,
    /// Done: terminated (interrogations, commands), or confirmed (clock sync, test, reset,
    /// parameter), or answered (read).
    Completed,
    /// The request failed: a negative confirmation, a timeout, or a lost connection.
    Failed(Error),
}

// Adapter-provided errors may contain line breaks or terminal controls.
struct SingleLine<'a, 'b>(&'a mut fmt::Formatter<'b>);

impl fmt::Write for SingleLine<'_, '_> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        for c in text.chars() {
            if c.is_control() || matches!(c, '\u{2028}' | '\u{2029}') {
                write!(self.0, "{}", c.escape_default())?;
            } else {
                self.0.write_char(c)?;
            }
        }
        Ok(())
    }
}

impl fmt::Display for Progress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Selected => f.write_str("selected"),
            Self::Confirmed => f.write_str("confirmed"),
            Self::Completed => f.write_str("completed"),
            Self::Failed(error) => write!(SingleLine(f), "failed: {error}"),
        }
    }
}

/// How a controlling station behaves.
///
/// ```
/// use iec60870::station::ClientConfig;
///
/// // An outstation that confirms commands but never terminates them:
/// let config = ClientConfig { command_termination: false, ..ClientConfig::default() };
/// assert_eq!(config.confirmation_timeout.as_secs(), 15);
/// ```
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ClientConfig {
    /// Maximum received file size in octets. Defaults to the 24-bit wire maximum.
    #[cfg(feature = "file-transfer")]
    pub files: super::FileConfig,
    /// The field widths and permitted types (default [`Profile::IEC104`]).
    pub profile: Profile,
    /// The originator address put in every cause of transmission (default 0).
    pub originator: u8,
    /// How long an activation confirmation may take (default 15 s).
    pub confirmation_timeout: Duration,
    /// How long, after the confirmation, the termination may take (default 60 s).
    pub termination_timeout: Duration,
    /// Whether commands are complete only on their activation termination (default true).
    pub command_termination: bool,
    /// Whether commands carry a CP56Time2a time tag from the clock (types 58–64; default false).
    pub time_tagged_commands: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            #[cfg(feature = "file-transfer")]
            files: super::FileConfig::default(),
            profile: Profile::IEC104,
            originator: 0,
            confirmation_timeout: Duration::from_secs(15),
            termination_timeout: Duration::from_secs(60),
            command_termination: true,
            time_tagged_commands: false,
        }
    }
}

/// What a controlling station reports.
///
/// ```
/// use iec60870::station::Event;
///
/// fn show(event: &Event) {
///     println!("{event}");
/// }
/// show(&Event::Started);
/// ```
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum Event {
    /// File contents after length and checksum verification.
    #[cfg(feature = "file-transfer")]
    File {
        /// Request that selected this file.
        id: RequestId,
        /// Station that served it.
        common_address: CommonAddress,
        /// Record address.
        ioa: Ioa,
        /// Name of file.
        name: super::FileName,
        /// Verified octets.
        data: Vec<u8>,
    },
    /// Data transfer started.
    Started,
    /// Data transfer stopped.
    Stopped,
    /// A monitored point: spontaneous, interrogated, read, cyclic, …
    Point(Point),
    /// A station or group interrogation was terminated.
    InterrogationComplete {
        /// The common address.
        common_address: CommonAddress,
        /// The qualifier of interrogation.
        qualifier: Interrogation,
    },
    /// A counter interrogation was terminated.
    CounterInterrogationComplete {
        /// The common address.
        common_address: CommonAddress,
        /// The qualifier of counter interrogation.
        qualifier: CounterInterrogation,
    },
    /// The outstation (re)initialised.
    EndOfInitialization {
        /// The common address.
        common_address: CommonAddress,
        /// The cause of initialisation.
        cause: EndOfInitialization,
    },
    /// A request progressed.
    Request {
        /// The request.
        id: RequestId,
        /// How far it got.
        progress: Progress,
    },
    /// An ASDU no request expects and that carries no monitored points.
    Asdu(Asdu),
    /// All entries of one completed file directory request, in wire order.
    #[cfg(feature = "file-transfer")]
    Directory {
        /// The request that produced the listing.
        id: RequestId,
        /// The station that answered.
        common_address: CommonAddress,
        /// The complete directory.
        files: Vec<super::FileInfo>,
    },
    /// The connection closed; every outstanding request failed.
    Disconnected(super::link::LinkClosed),
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Started => f.write_str("data transfer started"),
            Self::Stopped => f.write_str("data transfer stopped"),
            Self::Point(point) => write!(f, "{point}"),
            Self::InterrogationComplete { common_address, qualifier } => {
                write!(f, "CA {common_address} ")?;
                match (qualifier, qualifier.group_number()) {
                    (&Interrogation::STATION, _) => f.write_str("station interrogation complete"),
                    (_, Some(group)) => write!(f, "group {group} interrogation complete"),
                    _ => write!(f, "interrogation complete (QOI {})", qualifier.0),
                }
            }
            Self::CounterInterrogationComplete { common_address, qualifier } => {
                write!(f, "CA {common_address} counter interrogation complete (QCC {})", qualifier.0)
            }
            Self::EndOfInitialization { common_address, cause } => {
                write!(f, "CA {common_address} initialization complete (cause {})", cause.cause())?;
                if cause.after_parameter_change() {
                    f.write_str(", local parameters changed")?;
                }
                Ok(())
            }
            Self::Request { id, progress } => write!(f, "{id} {progress}"),
            Self::Asdu(asdu) => write!(f, "{asdu}"),
            Self::Disconnected(reason) => write!(SingleLine(f), "disconnected: {reason}"),
            #[cfg(feature = "file-transfer")]
            Self::File { id, common_address, ioa, name, data } => {
                write!(f, "{id} CA {common_address} IOA {ioa} file {name} received ({} bytes)", data.len())
            }
            #[cfg(feature = "file-transfer")]
            Self::Directory { id, common_address, files } => {
                write!(f, "{id} CA {common_address} directory received ({} entries)", files.len())
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Kind {
    Interrogation(Interrogation),
    Counter(CounterInterrogation),
    Read,
    #[cfg(feature = "file-transfer")]
    Directory,
    #[cfg(feature = "file-transfer")]
    DownloadSync {
        target: Ioa,
        counter: u16,
    },
    Command {
        command: Command,
        selecting: bool,
    },
    Other,
}

#[derive(Clone, Debug)]
struct Pending {
    #[cfg(feature = "file-transfer")]
    download: Option<super::download::Download>,
    #[cfg(feature = "file-transfer")]
    files: Vec<super::FileInfo>,
    id: RequestId,
    type_id: TypeId,
    ca: CommonAddress,
    ioa: Ioa,
    kind: Kind,
    awaiting: Awaiting,
    deadline: Instant,
    time: Option<Cp56Time2a>,
}

/// The controlling station (master) of IEC 60870-5-101/104, without I/O.
///
/// One method per procedure sends the request and returns its [`RequestId`]; the outstation's
/// answers come out of [`poll_output`](Protocol::poll_output) as [`Event::Request`] progress,
/// next to every monitored value as a typed [`Event::Point`]. A request that is not confirmed
/// or terminated in time fails with [`Error::Timeout`] naming what was awaited; a negative
/// confirmation fails it with [`Error::Negative`] carrying the cause of transmission received.
///
/// It is a [`Protocol`], so `BlockingDriver` and
/// `TokioDriver` run it; `Client` wraps that.
///
#[cfg_attr(feature = "cs104", doc = "```")]
#[cfg_attr(not(feature = "cs104"), doc = "```ignore")]
/// use iec60870::cs104::Cs104Link;
/// use iec60870::prelude::*;
/// use iec60870::station::{ClientConfig, ControllingStation, Error};
///
/// let clock = || Cp56Time2a::from_unix_millis(1_795_000_000_000).unwrap();
/// let mut master = ControllingStation::new(Cs104Link::controlling(), ClientConfig::default(), clock);
/// // Nothing can be requested before data transfer is started.
/// assert!(matches!(master.interrogate(CommonAddress(1), Interrogation::STATION, Instant::ZERO), Err(Error::NotStarted)));
/// master.start(Instant::ZERO)?; // STARTDT act
/// # Ok::<(), Error>(())
/// ```
pub struct ControllingStation<L> {
    link: L,
    config: ClientConfig,
    clock: Box<dyn Clock + Send>,
    pending: Vec<Pending>,
    outgoing: VecDeque<Vec<u8>>,
    out: VecDeque<Output<Event>>,
    link_deadline: Option<Instant>,
    deadline_dirty: bool,
    next_id: u32,
    #[cfg(feature = "file-transfer")]
    download_needs_sync: bool,
    test_counter: u16,
    now: Instant,
}

impl<L: fmt::Debug> fmt::Debug for ControllingStation<L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ControllingStation").field("link", &self.link).field("pending", &self.pending.len()).finish_non_exhaustive()
    }
}

impl<L: StationLink> ControllingStation<L> {
    /// A master over `link` (not yet started), with time tags from `clock`.
    pub fn new(link: L, config: ClientConfig, clock: impl Clock + Send + 'static) -> Self {
        ControllingStation {
            link,
            config,
            clock: Box::new(clock),
            pending: Vec::new(),
            outgoing: VecDeque::new(),
            out: VecDeque::new(),
            link_deadline: None,
            deadline_dirty: false,
            next_id: 1,
            #[cfg(feature = "file-transfer")]
            download_needs_sync: false,
            test_counter: 0,
            now: Instant::ZERO,
        }
    }

    /// The link.
    pub fn link(&self) -> &L {
        &self.link
    }

    /// The configuration.
    pub fn config(&self) -> &ClientConfig {
        &self.config
    }

    /// Whether data transfer is started.
    pub fn is_started(&self) -> bool {
        self.link.is_started()
    }

    /// Whether `id` is still outstanding.
    pub fn is_pending(&self, id: RequestId) -> bool {
        self.pending.iter().any(|p| p.id == id)
    }

    /// Starts data transfer; [`Event::Started`] follows.
    pub fn start(&mut self, now: Instant) -> Result<(), Error> {
        self.touch(now);
        let r = self.link.start(now).map_err(link_error);
        self.pump();
        r
    }

    /// Stops data transfer; [`Event::Stopped`] follows.
    pub fn stop(&mut self, now: Instant) -> Result<(), Error> {
        self.touch(now);
        let r = self.link.stop(now).map_err(link_error);
        self.pump();
        r
    }

    /// Station interrogation ([`Interrogation::STATION`]) or group interrogation
    /// ([`Interrogation::group`]): ACTCON, the points, ACTTERM → [`Event::InterrogationComplete`].
    pub fn interrogate(&mut self, ca: CommonAddress, qoi: Interrogation, now: Instant) -> Result<RequestId, Error> {
        let asdu = Asdu::new(ca, self.cot(Cause::ACTIVATION), InformationObject::new(Ioa(0), qoi));
        self.request(&asdu, Kind::Interrogation(qoi), None, now)
    }

    /// Counter interrogation with its freeze/reset qualifier → [`Event::CounterInterrogationComplete`].
    pub fn counter_interrogate(&mut self, ca: CommonAddress, qcc: CounterInterrogation, now: Instant) -> Result<RequestId, Error> {
        let asdu = Asdu::new(ca, self.cot(Cause::ACTIVATION), InformationObject::new(Ioa(0), qcc));
        self.request(&asdu, Kind::Counter(qcc), None, now)
    }

    /// Download one record. A completed transfer emits an [`Event::File`].
    #[cfg(feature = "file-transfer")]
    pub fn download(&mut self, ca: CommonAddress, ioa: Ioa, name: impl Into<super::FileName>, now: Instant) -> Result<RequestId, Error> {
        if ca.0 == self.config.profile.ca.max() || !(120..=125).all(|n| self.config.profile.permits(TypeId(n))) {
            return Err(Error::InvalidArgument("download requires unicast and the file transfer types"));
        }
        if self.pending.iter().any(|p| p.download.is_some() || (p.kind == Kind::Directory && p.ca == ca && ioa == Ioa(0))) {
            return Err(Error::Busy);
        }
        let name = name.into();
        let call = crate::types::CallSelect { name: name.0, section: 0, qualifier: 1 };
        let asdu = Asdu::new(ca, self.cot(Cause::FILE_TRANSFER), InformationObject::new(ioa, call));
        let id = if self.download_needs_sync {
            // File replies have no request ID. An ordered test reply separates traffic
            // for the abandoned selection from replies for its successor.
            asdu.to_vec(&self.config.profile)?;
            let id = self.test_command(ca, now)?;
            if let Some(p) = self.pending.iter_mut().find(|p| p.id == id) {
                p.kind = Kind::DownloadSync { target: ioa, counter: self.test_counter };
            }
            id
        } else {
            self.request(&asdu, Kind::Other, None, now)?
        };
        if let Some(p) = self.pending.iter_mut().find(|p| p.id == id) {
            p.download = Some(super::download::Download::new(name));
        }
        Ok(id)
    }

    /// Cancel a pending download and queue a file deactivation for its peer.
    /// Returns false for completed requests and requests of other kinds. Before its next
    /// download the station synchronizes with the peer using a test command.
    #[cfg(feature = "file-transfer")]
    pub fn cancel_download(&mut self, id: RequestId, now: Instant) -> bool {
        let Some(i) = self.pending.iter().position(|p| p.id == id && p.download.is_some()) else { return false };
        self.touch(now);
        self.deactivate_download(i);
        self.finish(i, Progress::Failed(super::FileError::Cancelled.into()));
        self.pump();
        true
    }

    #[cfg(feature = "file-transfer")]
    fn deactivate_download(&mut self, i: usize) {
        let Some(p) = self.pending.get(i) else { return };
        let Some(d) = &p.download else { return };
        if matches!(p.kind, Kind::DownloadSync { .. }) {
            return;
        }
        self.download_needs_sync = true;
        let call = crate::types::CallSelect { name: d.name.0, section: 0, qualifier: 3 };
        let message = Asdu::new(p.ca, self.cot(Cause::FILE_TRANSFER), InformationObject::new(p.ioa, call));
        if let Ok(bytes) = message.to_vec(&self.config.profile) {
            self.submit(bytes);
        }
    }

    /// Request the directory of one station. The result is an [`Event::Directory`].
    #[cfg(feature = "file-transfer")]
    pub fn directory(&mut self, ca: CommonAddress, now: Instant) -> Result<RequestId, Error> {
        if ca.0 == self.config.profile.ca.max() || !self.config.profile.permits(TypeId::F_DR_TA_1) {
            return Err(Error::InvalidArgument("directory requires a unicast address and a profile permitting directory entries"));
        }
        if self.pending.iter().any(|p| p.ca == ca && matches!(p.kind, Kind::DownloadSync { target: Ioa(0), .. })) {
            return Err(Error::Busy);
        }
        let call = super::file_store::DIRECTORY_CALL;
        let asdu = Asdu::new(ca, self.cot(Cause::REQUEST), InformationObject::new(Ioa(0), call));
        self.request(&asdu, Kind::Directory, None, now)
    }

    /// Reads one point (COT 5); the reply is an [`Event::Point`], then `Completed`.
    pub fn read(&mut self, ca: CommonAddress, ioa: Ioa, now: Instant) -> Result<RequestId, Error> {
        let asdu = Asdu::new(ca, self.cot(Cause::REQUEST), InformationObject::new(ioa, Read));
        self.request(&asdu, Kind::Read, None, now)
    }

    /// Clock synchronisation with the time of the clock.
    pub fn clock_sync(&mut self, ca: CommonAddress, now: Instant) -> Result<RequestId, Error> {
        let time = self.clock.now();
        if time.clock_millis().is_none() {
            return Err(Error::InvalidArgument("local clock is invalid or outside the CP56Time2a calendar"));
        }
        let asdu = Asdu::new(ca, self.cot(Cause::ACTIVATION), InformationObject::new(Ioa(0), ClockSync).at(time));
        self.request(&asdu, Kind::Other, None, now)
    }

    /// A direct command (execute): ACTCON, then ACTTERM (unless `command_termination` is off).
    pub fn command(&mut self, ca: CommonAddress, ioa: Ioa, command: impl Into<Command>, now: Instant) -> Result<RequestId, Error> {
        let command = command.into().execute();
        let time = self.config.time_tagged_commands.then(|| self.clock.now());
        let asdu = Asdu::new(ca, self.cot(Cause::ACTIVATION), command_objects(ioa, command, time));
        self.request(&asdu, Kind::Command { command, selecting: false }, time, now)
    }

    /// Select-before-operate: the select, on its positive ACTCON ([`Progress::Selected`]) the
    /// execute with the same value, its ACTCON ([`Progress::Confirmed`]) and ACTTERM
    /// ([`Progress::Completed`]).
    pub fn select_and_execute(&mut self, ca: CommonAddress, ioa: Ioa, command: impl Into<Command>, now: Instant) -> Result<RequestId, Error> {
        let command = command.into().execute();
        if matches!(command, Command::Bitstring(_)) {
            return Err(Error::InvalidArgument("a bitstring command has no select"));
        }
        let time = self.config.time_tagged_commands.then(|| self.clock.now());
        let asdu = Asdu::new(ca, self.cot(Cause::ACTIVATION), command_objects(ioa, command.select(), time));
        self.request(&asdu, Kind::Command { command, selecting: true }, time, now)
    }

    /// The test command: `C_TS_TA_1` with a counter and the clock's time where the profile
    /// permits it (104), else `C_TS_NA_1`.
    pub fn test_command(&mut self, ca: CommonAddress, now: Instant) -> Result<RequestId, Error> {
        let cot = self.cot(Cause::ACTIVATION);
        let asdu = if self.config.profile.permits(TypeId::C_TS_TA_1) {
            self.test_counter = self.test_counter.wrapping_add(1);
            Asdu::new(ca, cot, InformationObject::new(Ioa(0), TestCounter(self.test_counter)).at(self.clock.now()))
        } else {
            Asdu::new(ca, cot, InformationObject::new(Ioa(0), TestCommand::PATTERN))
        };
        self.request(&asdu, Kind::Other, None, now)
    }

    /// Reset process.
    pub fn reset_process(&mut self, ca: CommonAddress, qrp: ResetProcess, now: Instant) -> Result<RequestId, Error> {
        let asdu = Asdu::new(ca, self.cot(Cause::ACTIVATION), InformationObject::new(Ioa(0), qrp));
        self.request(&asdu, Kind::Other, None, now)
    }

    /// Parameter loading (110–112) or activation (113).
    pub fn parameter(&mut self, ca: CommonAddress, ioa: Ioa, parameter: impl Into<Parameter>, now: Instant) -> Result<RequestId, Error> {
        let cot = self.cot(Cause::ACTIVATION);
        let asdu = match parameter.into() {
            Parameter::Normalized(p) => Asdu::new(ca, cot, InformationObject::new(ioa, p)),
            Parameter::Scaled(p) => Asdu::new(ca, cot, InformationObject::new(ioa, p)),
            Parameter::Float(p) => Asdu::new(ca, cot, InformationObject::new(ioa, p)),
            Parameter::Activation(p) => Asdu::new(ca, cot, InformationObject::new(ioa, p)),
        };
        self.request(&asdu, Kind::Other, None, now)
    }

    /// Sends any ASDU without tracking it (the escape hatch for what has no method).
    pub fn send(&mut self, asdu: &Asdu, now: Instant) -> Result<(), Error> {
        self.touch(now);
        if !self.link.is_started() {
            return Err(Error::NotStarted);
        }
        let bytes = asdu.to_vec(&self.config.profile)?;
        self.submit(bytes);
        self.pump();
        Ok(())
    }

    fn cot(&self, cause: Cause) -> Cot {
        Cot::new(cause).with_originator(self.config.originator)
    }

    fn touch(&mut self, now: Instant) {
        self.now = now;
        self.deadline_dirty = true;
    }

    fn request(&mut self, asdu: &Asdu, kind: Kind, time: Option<Cp56Time2a>, now: Instant) -> Result<RequestId, Error> {
        self.touch(now);
        if !self.link.is_started() {
            return Err(Error::NotStarted);
        }
        let type_id = asdu.type_id();
        let ca = asdu.common_address;
        let ioa = asdu.objects.ioa(0).unwrap_or_default();
        if self.pending.iter().any(|p| p.type_id == type_id && p.ca == ca && p.ioa == ioa) {
            return Err(Error::Busy);
        }
        let bytes = asdu.to_vec(&self.config.profile)?;
        let id = RequestId(self.next_id);
        self.next_id = self.next_id.wrapping_add(1);
        let awaiting = match kind {
            Kind::Read => Awaiting::Response,
            #[cfg(feature = "file-transfer")]
            Kind::Directory => Awaiting::Response,
            _ => Awaiting::Confirmation,
        };
        self.pending.push(Pending {
            #[cfg(feature = "file-transfer")]
            files: Vec::new(),
            #[cfg(feature = "file-transfer")]
            download: None,
            id,
            type_id,
            ca,
            ioa,
            kind,
            awaiting,
            deadline: now + self.config.confirmation_timeout,
            time,
        });
        self.submit(bytes);
        self.pump();
        Ok(id)
    }

    fn submit(&mut self, bytes: Vec<u8>) {
        if self.outgoing.is_empty() {
            if self.link.submit(&bytes, Class::One, self.now) == Err(LinkError::Busy) {
                self.outgoing.push_back(bytes);
            }
        } else {
            self.outgoing.push_back(bytes);
        }
    }

    fn flush_outgoing(&mut self) {
        while let Some(bytes) = self.outgoing.front() {
            if self.link.submit(bytes, Class::One, self.now) == Err(LinkError::Busy) {
                return;
            }
            self.outgoing.pop_front();
        }
    }

    fn pump(&mut self) {
        while let Some(output) = self.link.poll_output() {
            match output {
                Output::Transmit(bytes) => self.out.push_back(Output::Transmit(bytes)),
                Output::Deadline(at) => self.link_deadline = Some(at),
                Output::Event(event) => self.on_link_event(event),
            }
        }
    }

    fn on_link_event(&mut self, event: LinkEvent) {
        match event {
            LinkEvent::Started => self.emit(Event::Started),
            LinkEvent::Stopped => self.emit(Event::Stopped),
            LinkEvent::Acknowledged { .. } => self.flush_outgoing(),
            // The request may not have arrived; its timeout decides.
            LinkEvent::Unconfirmed { .. } => {}
            LinkEvent::Asdu(bytes) => self.on_asdu(&bytes),
            LinkEvent::Closed(reason) => {
                self.outgoing.clear();
                for p in core::mem::take(&mut self.pending) {
                    self.progress(p.id, Progress::Failed(Error::Disconnected(reason.clone())));
                }
                self.emit(Event::Disconnected(reason));
            }
        }
    }

    fn emit(&mut self, event: Event) {
        self.out.push_back(Output::Event(event));
    }

    fn progress(&mut self, id: RequestId, progress: Progress) {
        self.emit(Event::Request { id, progress });
    }

    fn finish(&mut self, index: usize, progress: Progress) {
        if index < self.pending.len() {
            let p = self.pending.remove(index);
            self.progress(p.id, progress);
        }
    }

    #[cfg(feature = "file-transfer")]
    fn on_directory(&mut self, i: usize, asdu: Asdu) {
        let ca = asdu.common_address;
        if asdu.cot.originator != self.config.originator && self.config.profile.cot.octets() == 2 || asdu.cot.test {
            return self.emit(Event::Asdu(asdu));
        }
        match &asdu.objects {
            Objects::Directory(entries) if !asdu.cot.negative && asdu.cot.cause == Cause::REQUEST => {
                let Some(p) = self.pending.get_mut(i) else { return };
                if entries.is_empty()
                    || p.files.len() + entries.len() > super::file_store::DIRECTORY_LIMIT
                    || entries.iter().take(entries.len().saturating_sub(1)).any(|e| super::FileStatus(e.element.status).is_last())
                {
                    return self.finish(i, Progress::Failed(Error::InvalidDirectory));
                }
                p.files.extend(entries.iter().map(|e| super::FileInfo {
                    ioa: e.ioa,
                    name: super::FileName(e.element.name),
                    length: e.element.length,
                    created: e.time,
                    status: super::FileStatus(e.element.status),
                }));
                p.deadline = self.now + self.config.confirmation_timeout;
                if !p.files.last().is_some_and(|f| f.status.is_last()) {
                    return;
                }
                let event = Event::Directory { id: p.id, common_address: ca, files: core::mem::take(&mut p.files) };
                self.emit(event);
                self.finish(i, Progress::Completed);
            }
            Objects::CallSelect(o)
                if asdu.cot.negative && matches!(o.as_slice(), [entry] if entry.ioa == Ioa(0) && entry.element == super::file_store::DIRECTORY_CALL) =>
            {
                if asdu.cot.cause == Cause::UNKNOWN_IOA && self.pending.get(i).is_some_and(|p| p.files.is_empty()) {
                    let Some(p) = self.pending.get(i) else { return };
                    self.emit(Event::Directory { id: p.id, common_address: ca, files: Vec::new() });
                    return self.finish(i, Progress::Completed);
                }
                self.finish(i, Progress::Failed(Error::Negative { cot: asdu.cot }));
            }
            _ => self.emit(Event::Asdu(asdu)),
        }
    }

    #[cfg(feature = "file-transfer")]
    fn on_download(&mut self, i: usize, asdu: Asdu) {
        use super::download::Step;
        let Some(p) = self.pending.get_mut(i) else { return };
        if asdu.cot.test || (self.config.profile.cot.octets() == 2 && asdu.cot.originator != self.config.originator) {
            return self.emit(Event::Asdu(asdu));
        }
        if asdu.cot.negative {
            return self.finish(i, Progress::Failed(Error::Negative { cot: asdu.cot }));
        }
        if asdu.cot.cause != Cause::FILE_TRANSFER {
            return self.emit(Event::Asdu(asdu));
        }
        let Some(d) = p.download.as_mut() else { return };
        if asdu.len() != 1 {
            self.deactivate_download(i);
            return self.finish(i, Progress::Failed(super::FileError::Protocol("file message requires one object").into()));
        }
        let step = match d.receive(&asdu.objects, self.config.files.max_length) {
            Ok(s) => s,
            Err(e) => {
                if matches!(e, super::FileError::TooLarge { .. } | super::FileError::Protocol(_)) {
                    self.deactivate_download(i);
                }
                return self.finish(i, Progress::Failed(e.into()));
            }
        };
        p.deadline = self.now + self.config.confirmation_timeout;
        let (ioa, ca) = (p.ioa, p.ca);
        let done = matches!(step, Step::Done(_));
        let event = done.then(|| Event::File { id: p.id, common_address: ca, ioa, name: d.name, data: core::mem::take(&mut d.data) });
        let reply = match step {
            Step::More => return,
            Step::Call(c) => Asdu::new(ca, asdu.cot, InformationObject::new(ioa, c)),
            Step::Ack(a) | Step::Done(a) | Step::FailedChecksum(a, _) => Asdu::new(ca, asdu.cot, InformationObject::new(ioa, a)),
        };
        match reply.to_vec(&self.config.profile) {
            Ok(bytes) => self.submit(bytes),
            Err(e) => return self.finish(i, Progress::Failed(e.into())),
        }
        if let Some(event) = event {
            self.emit(event);
            self.finish(i, Progress::Completed);
        }
        if let Step::FailedChecksum(_, section) = step {
            self.finish(i, Progress::Failed(super::FileError::Checksum { section }.into()));
        }
    }

    #[cfg(feature = "file-transfer")]
    fn on_download_sync(&mut self, i: usize, asdu: Asdu, target: Ioa, counter: u16) {
        let ca = asdu.common_address;
        let cot = asdu.cot;
        let matches_test = match &asdu.objects {
            Objects::TestCommandCp56(o) => o.first().is_some_and(|e| e.element.0 == counter),
            Objects::TestCommand(o) => o.first().is_some_and(|e| e.element == TestCommand::PATTERN),
            _ => false,
        };
        if !matches_test || cot.test || (self.config.profile.cot.octets() == 2 && cot.originator != self.config.originator) {
            return self.emit(Event::Asdu(asdu));
        }
        if cot.negative || matches!(cot.cause.value(), 44..=47) {
            return self.finish(i, Progress::Failed(Error::Negative { cot }));
        }
        if cot.cause != Cause::ACTIVATION_CON {
            return self.emit(Event::Asdu(asdu));
        }
        let select_cot = self.cot(Cause::FILE_TRANSFER);
        let Some(p) = self.pending.get_mut(i) else { return };
        let Some(d) = &p.download else { return };
        let call = crate::types::CallSelect { name: d.name.0, section: 0, qualifier: 1 };
        let select = Asdu::new(ca, select_cot, InformationObject::new(target, call));
        p.kind = Kind::Other;
        p.type_id = TypeId::F_SC_NA_1;
        p.ioa = target;
        p.deadline = self.now + self.config.confirmation_timeout;
        self.download_needs_sync = false;
        match select.to_vec(&self.config.profile) {
            Ok(bytes) => self.submit(bytes),
            Err(e) => self.finish(i, Progress::Failed(e.into())),
        }
    }

    fn on_asdu(&mut self, bytes: &[u8]) {
        let Ok(asdu) = Asdu::decode(bytes, &self.config.profile) else { return };
        let ca = asdu.common_address;
        #[cfg(feature = "file-transfer")]
        if (120..=125).contains(&asdu.type_id().0)
            && let Some(i) = self
                .pending
                .iter()
                .position(|p| p.download.is_some() && !matches!(p.kind, Kind::DownloadSync { .. }) && p.ca == ca && Some(p.ioa) == asdu.objects.ioa(0))
        {
            return self.on_download(i, asdu);
        }
        #[cfg(feature = "file-transfer")]
        if let Some(i) = self.pending.iter().position(|p| p.kind == Kind::Directory && p.ca == ca)
            && matches!(asdu.objects, Objects::Directory(_) | Objects::CallSelect(_))
        {
            return self.on_directory(i, asdu);
        }
        let broadcast = self.config.profile.ca.max();
        let matches_ca = |p: &Pending| p.ca == ca || p.ca.0 == broadcast;
        if let Some(points) = Point::from_asdu(&asdu) {
            let first = points.first().map(|p| p.ioa);
            for point in points {
                self.emit(Event::Point(point));
            }
            if asdu.cot.cause == Cause::REQUEST
                && let Some(i) = self.pending.iter().position(|p| p.kind == Kind::Read && matches_ca(p) && Some(p.ioa) == first)
            {
                self.finish(i, Progress::Completed);
            }
            return;
        }
        if let Objects::EndOfInitialization(objects) = &asdu.objects {
            for o in objects {
                self.emit(Event::EndOfInitialization { common_address: ca, cause: o.element });
            }
            return;
        }
        let type_id = asdu.type_id();
        let ioa = asdu.objects.ioa(0).unwrap_or_default();
        let Some(i) = self.pending.iter().position(|p| p.type_id == type_id && matches_ca(p) && p.ioa == ioa) else {
            return self.emit(Event::Asdu(asdu));
        };
        let Some(&Pending { id, ca, ioa, kind, time, awaiting, .. }) = self.pending.get(i) else { return };
        let cot = asdu.cot;
        #[cfg(feature = "file-transfer")]
        if let Kind::DownloadSync { target, counter } = kind {
            return self.on_download_sync(i, asdu, target, counter);
        }
        let unknown = matches!(cot.cause.value(), 44..=47);
        if cot.negative || unknown {
            return self.finish(i, Progress::Failed(Error::Negative { cot }));
        }
        match (cot.cause, kind) {
            (Cause::ACTIVATION_CON | Cause::DEACTIVATION_CON, Kind::Command { command, selecting: true }) => {
                let asdu = Asdu::new(ca, self.cot(Cause::ACTIVATION), command_objects(ioa, command, time));
                if let Ok(bytes) = asdu.to_vec(&self.config.profile) {
                    self.submit(bytes);
                }
                if let Some(q) = self.pending.get_mut(i) {
                    q.kind = Kind::Command { command, selecting: false };
                    q.deadline = self.now + self.config.confirmation_timeout;
                }
                self.progress(id, Progress::Selected);
            }
            (Cause::ACTIVATION_CON | Cause::DEACTIVATION_CON, kind) => {
                let terminates = match kind {
                    Kind::Interrogation(_) | Kind::Counter(_) => true,
                    Kind::Command { .. } => self.config.command_termination,
                    #[cfg(feature = "file-transfer")]
                    Kind::Directory | Kind::DownloadSync { .. } => false,
                    Kind::Read | Kind::Other => false,
                };
                if terminates && awaiting == Awaiting::Confirmation {
                    if let Some(q) = self.pending.get_mut(i) {
                        q.awaiting = Awaiting::Termination;
                        q.deadline = self.now + self.config.termination_timeout;
                    }
                    self.progress(id, Progress::Confirmed);
                } else if !terminates {
                    self.finish(i, Progress::Completed);
                }
            }
            (Cause::ACTIVATION_TERMINATION, kind) => {
                match kind {
                    Kind::Interrogation(qualifier) => self.emit(Event::InterrogationComplete { common_address: ca, qualifier }),
                    Kind::Counter(qualifier) => self.emit(Event::CounterInterrogationComplete { common_address: ca, qualifier }),
                    _ => {}
                }
                self.finish(i, Progress::Completed);
            }
            _ => self.emit(Event::Asdu(asdu)),
        }
    }

    fn next_deadline(&self) -> Option<Instant> {
        self.pending.iter().map(|p| p.deadline).chain(self.link_deadline).min()
    }
}

/// The objects of a command ASDU.
fn command_objects(ioa: Ioa, command: Command, time: Option<Cp56Time2a>) -> Objects {
    macro_rules! objects {
        ($e:expr) => {
            match time {
                Some(t) => Objects::from(InformationObject::new(ioa, $e).at(t)),
                None => Objects::from(InformationObject::new(ioa, $e)),
            }
        };
    }
    match command {
        Command::Single(c) => objects!(c),
        Command::Double(c) => objects!(c),
        Command::Step(c) => objects!(c),
        Command::Normalized(c) => objects!(c),
        Command::Scaled(c) => objects!(c),
        Command::Float(c) => objects!(c),
        Command::Bitstring(c) => objects!(c),
    }
}

fn link_error(e: LinkError) -> Error {
    match e {
        LinkError::NotStarted => Error::NotStarted,
        LinkError::Busy => Error::Busy,
        LinkError::Closed => Error::InvalidArgument("the connection is closed"),
        LinkError::Rejected => Error::InvalidArgument("the link refused the command"),
    }
}

impl<L: StationLink> Protocol for ControllingStation<L> {
    type Event = Event;

    fn handle_input(&mut self, bytes: &[u8], now: Instant) {
        self.touch(now);
        self.link.handle_input(bytes, now);
        self.pump();
    }

    fn handle_timeout(&mut self, now: Instant) {
        self.touch(now);
        self.link.handle_timeout(now);
        self.pump();
        while let Some(i) = self.pending.iter().position(|p| p.deadline <= now) {
            let awaiting = self.pending.get(i).map_or(Awaiting::Confirmation, |p| p.awaiting);
            #[cfg(feature = "file-transfer")]
            self.deactivate_download(i);
            self.finish(i, Progress::Failed(Error::Timeout(awaiting)));
        }
        #[cfg(feature = "file-transfer")]
        self.pump();
    }

    fn handle_disconnect(&mut self, now: Instant) {
        self.touch(now);
        self.link.handle_disconnect(now);
        self.pump();
    }

    fn poll_output(&mut self) -> Option<Output<Event>> {
        if let Some(o) = self.out.pop_front() {
            return Some(o);
        }
        if self.deadline_dirty {
            self.deadline_dirty = false;
            if !self.link.is_closed() {
                return self.next_deadline().map(Output::Deadline);
            }
        }
        None
    }

    fn is_closed(&self) -> bool {
        self.link.is_closed()
    }
}

#[cfg(test)]
mod display_tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::station::{LinkClosed, Value};
    use alloc::format;

    #[test]
    fn progress_and_events_are_readable_single_lines() {
        for (progress, expected) in [
            (Progress::Selected, "selected"),
            (Progress::Confirmed, "confirmed"),
            (Progress::Completed, "completed"),
            (Progress::Failed(Error::Busy), "failed: the same request is still outstanding"),
        ] {
            assert_eq!(format!("{progress}"), expected);
        }
        let ca = CommonAddress(1);
        let point = Point { common_address: ca, ioa: Ioa(100), cause: Cot::INTERROGATED_BY_STATION, value: Value::from(true), time: None };
        let asdu = Asdu::new(ca, Cot::ACTIVATION, InformationObject::new(Ioa(0), Interrogation::STATION));
        let events = [
            (Event::Started, "data transfer started"),
            (Event::Stopped, "data transfer stopped"),
            (Event::Point(point), "CA 1 IOA 100 = ON, interrogated by station (20)"),
            (Event::InterrogationComplete { common_address: ca, qualifier: Interrogation::STATION }, "CA 1 station interrogation complete"),
            (Event::CounterInterrogationComplete { common_address: ca, qualifier: CounterInterrogation(5) }, "CA 1 counter interrogation complete (QCC 5)"),
            (Event::EndOfInitialization { common_address: ca, cause: EndOfInitialization(0) }, "CA 1 initialization complete (cause 0)"),
            (Event::Request { id: RequestId(7), progress: Progress::Completed }, "request 7 completed"),
        ];
        for (event, expected) in events {
            assert_eq!(format!("{event}"), expected);
        }
        assert_eq!(format!("{}", Event::Asdu(asdu.clone())), format!("{asdu}"));
        let failure = Progress::Failed(Error::InvalidArgument("line\n\u{1b}\u{2028}\u{2029}"));
        let output = format!("{failure}");
        assert!(output.contains("line\\n\\u{1b}\\u{2028}\\u{2029}"));
        let reason = LinkClosed::new(Error::InvalidArgument("line\n\u{1b}\u{2028}"));
        let output = format!("{}", Event::Disconnected(reason));
        assert!(output.contains("line\\n\\u{1b}\\u{2028}"));
        assert!(!output.chars().any(|c| c.is_control() || c == '\u{2028}' || c == '\u{2029}'));
    }
}
