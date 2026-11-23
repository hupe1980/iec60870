//! File transfer in the monitor direction (types 120–127): the controlled station serves the
//! files of a [`FileStore`], the controlling station lists and downloads them.
//!
//! A file is addressed by its common address, its information object address and its
//! [`FileName`] (the NOF). The controlled station cuts it into sections of
//! [`FileConfig::section_size`] octets (at most 255 sections) and each section into segments
//! that fill the profile's maximum ASDU length; every section and the whole file carry a
//! checksum, the sum of their octets modulo 256 ([`checksum`]).
//!
//! The sequence, every ASDU with cause 13 (file transfer):
//!
//! | Master | Outstation |
//! |---|---|
//! | `F_SC_NA_1` select file | `F_FR_NA_1` file ready (length; FRQ bit 7 set = refused) |
//! | `F_SC_NA_1` call file | `F_SR_NA_1` section ready (section 1, its length) |
//! | `F_SC_NA_1` call section | `F_SG_NA_1` segments, then `F_LS_NA_1` last segment (section checksum) |
//! | `F_AF_NA_1` acknowledge section | `F_SR_NA_1` the next section, … or `F_LS_NA_1` last section (file checksum) |
//! | `F_AF_NA_1` acknowledge file | — |
//!
//! The directory is a call (`F_SC_NA_1`, cause 5 request) answered with `F_DR_TA_1` entries,
//! the last flagged [`FileStatus::LAST_FILE`].
//!
#![cfg_attr(feature = "cs104", doc = "```")]
#![cfg_attr(not(feature = "cs104"), doc = "```ignore")]
//! use iec60870::cs104::Cs104Link;
//! use iec60870::driver::{Output, Protocol};
//! use iec60870::prelude::*;
//! use iec60870::station::{self, ClientConfig, ControlledStation, ControllingStation, Event, FileName, GroupId, MemoryFileStore, ServerConfig};
//!
//! let clock = || Cp56Time2a::from_unix_millis(1_795_000_000_000).unwrap();
//! let ca = CommonAddress(1);
//! let record: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
//! let mut files = MemoryFileStore::new();
//! files.insert(ca, Ioa(30000), FileName::DISTURBANCE_DATA, record.clone());
//!
//! let mut db = Database::new();
//! db.insert(ca, Ioa(1), false);
//! let mut outstation = ControlledStation::new(db, ServerConfig::default(), clock);
//! outstation.set_file_store(files);
//! let conn = outstation.attach(Cs104Link::controlled(), GroupId(0));
//! let mut master = ControllingStation::new(Cs104Link::controlling(), ClientConfig::default(), clock);
//!
//! let now = Instant::ZERO;
//! master.start(now)?;
//! let mut downloaded = None;
//! for _ in 0..50 {
//!     while let Some(o) = master.poll_output() {
//!         match o {
//!             Output::Transmit(bytes) => outstation.handle_input(conn, &bytes, now, &mut |_: &_| Decision::Refuse),
//!             Output::Event(Event::Started) => { master.download(ca, Ioa(30000), FileName::DEFAULT, now)?; }
//!             Output::Event(Event::File { data, .. }) => downloaded = Some(data),
//!             _ => {}
//!         }
//!     }
//!     while let Some(o) = outstation.poll_output() {
//!         if let station::Output::Transmit { bytes, .. } = o {
//!             master.handle_input(&bytes, now);
//!         }
//!     }
//! }
//! assert_eq!(downloaded, Some(record));
//! # Ok::<(), iec60870::Error>(())
//! ```

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;
use core::time::Duration;

use super::controlling::RequestId;
use super::error::Error;
use crate::asdu::{Asdu, InformationObject, Objects, Profile};
use crate::time::{Cp56Time2a, Instant};
use crate::types::{CallSelect, Cause, CommonAddress, Cot, DirectoryEntry, FileAck, FileReady, Ioa, LastSection, SectionReady, Segment};

use super::file_store::{checksum, FileInfo, FileName, FileStatus, FileStore};

/// How file transfer behaves.
///
/// The controlled station uses all three fields; the controlling station only `max_length`
/// (its steps are bounded by `ClientConfig::confirmation_timeout`).
///
/// ```
/// use iec60870::station::FileConfig;
/// let config = FileConfig { section_size: 4096, ..FileConfig::default() };
/// assert_eq!(config.max_length, 0xFF_FFFF);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileConfig {
    /// Octets per section (default 64 KiB; clamped to 1..=`0xFF_FFFF`). A file that needs
    /// more than 255 sections is refused.
    pub section_size: u32,
    /// The longest file served or accepted (default and maximum `0xFF_FFFF`, what LOF carries).
    pub max_length: u32,
    /// How long the controlled station keeps an idle transfer (default 30 s).
    pub timeout: Duration,
}

impl Default for FileConfig {
    fn default() -> Self {
        FileConfig { section_size: 64 * 1024, max_length: MAX_LOF, timeout: Duration::from_secs(30) }
    }
}

/// Why a file transfer failed, as the controlling station sees it ([`Error::File`]).
///
/// ```
/// use iec60870::station::FileError;
/// assert_eq!(FileError::Checksum { section: Some(2) }.to_string(), "checksum mismatch in section 2");
/// assert_eq!(FileError::TooLarge { length: 20_000_000 }.to_string(), "the file (20000000 octets) exceeds the maximum length");
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FileError {
    /// The outstation answered "file not ready" or "section not ready".
    NotReady,
    /// The announced length exceeds [`FileConfig::max_length`].
    TooLarge {
        /// The length the outstation announced.
        length: u32,
    },
    /// A checksum did not match (`section: None` for the file checksum).
    Checksum {
        /// The section, or `None` for the whole file.
        section: Option<u8>,
    },
    /// The outstation ended the transfer with a deactivation.
    Aborted,
    /// The outstation broke the procedure (a length overrun, a short section, …).
    Protocol(&'static str),
}

impl fmt::Display for FileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FileError::NotReady => f.write_str("the file is not ready"),
            FileError::TooLarge { length } => write!(f, "the file ({length} octets) exceeds the maximum length"),
            FileError::Checksum { section: Some(s) } => write!(f, "checksum mismatch in section {s}"),
            FileError::Checksum { section: None } => f.write_str("checksum mismatch of the file"),
            FileError::Aborted => f.write_str("the outstation aborted the transfer"),
            FileError::Protocol(what) => write!(f, "file transfer protocol error: {what}"),
        }
    }
}

impl core::error::Error for FileError {}

/// How a transfer ended at the controlled station
/// ([`ServerEvent::FileTransfer`](super::ServerEvent::FileTransfer)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransferOutcome {
    /// The master acknowledged the file positively.
    Completed,
    /// The master acknowledged the file negatively or deactivated it.
    Rejected,
    /// The master stayed silent longer than [`FileConfig::timeout`].
    TimedOut,
    /// The connection closed.
    Disconnected,
    /// The master selected another file on the same connection.
    Superseded,
    /// The store could not deliver the octets it listed.
    StoreFailed,
}

/// The largest LOF: three octets.
pub(crate) const MAX_LOF: u32 = 0xFF_FFFF;
/// Directory entries a master accepts in one listing.
pub(crate) const MAX_DIRECTORY: usize = 4096;
/// Section repeats an outstation grants after negative acknowledgements.
const MAX_REPEATS: u8 = 3;

// Select-and-call qualifier (SCQ) and acknowledge qualifier (AFQ) values.
const SCQ_DEFAULT: u8 = 0;
const SCQ_SELECT_FILE: u8 = 1;
const SCQ_CALL_FILE: u8 = 2;
const SCQ_DEACTIVATE_FILE: u8 = 3;
const SCQ_CALL_SECTION: u8 = 6;
const SCQ_DEACTIVATE_SECTION: u8 = 7;
const AFQ_FILE_POSITIVE: u8 = 1;
const AFQ_FILE_NEGATIVE: u8 = 2;
const AFQ_SECTION_POSITIVE: u8 = 3;
const AFQ_SECTION_NEGATIVE: u8 = 4;
/// Error cause "checksum failed" in the high nibble of SCQ/AFQ.
const ERROR_CHECKSUM: u8 = 0x20;
// Last section or segment qualifier (LSQ).
const LSQ_FILE: u8 = 1;
const LSQ_FILE_DEACTIVATED: u8 = 2;
const LSQ_SECTION: u8 = 3;
const LSQ_SECTION_DEACTIVATED: u8 = 4;
/// FRQ and SRQ bit 7: negative / not ready.
const NOT_READY: u8 = 0x80;

/// The segment payload that fills the profile's maximum ASDU length (at most 255).
pub(crate) fn segment_size(profile: &Profile) -> usize {
    usize::from(profile.max_asdu_len).saturating_sub(profile.header_len() + profile.ioa.octets() + 4).clamp(1, 255)
}

fn file_cot(request: Cot, cause: Cause) -> Cot {
    Cot::new(cause).with_originator(request.originator)
}

// ---------------------------------------------------------------------------------------------
// The controlled station side
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ServerState {
    /// File ready sent; awaiting the call file.
    Selected,
    /// Section ready sent; awaiting the call section.
    SectionOffered,
    /// Segments and the last segment sent; awaiting the section acknowledgement.
    Sent,
    /// The last section sent; awaiting the file acknowledgement.
    FileOffered,
}

/// The transfer of one connection of a controlled station.
#[derive(Clone, Debug)]
pub(crate) struct ServerTransfer {
    pub(crate) ca: CommonAddress,
    pub(crate) ioa: Ioa,
    pub(crate) name: FileName,
    length: u32,
    section_size: u32,
    section: u8,
    sections: u8,
    section_sum: u8,
    file_sum: u8,
    repeats: u8,
    state: ServerState,
    pub(crate) deadline: Instant,
}

impl ServerTransfer {
    fn section_len(&self, section: u8) -> u32 {
        let start = u32::from(section.saturating_sub(1)).saturating_mul(self.section_size);
        self.length.saturating_sub(start).min(self.section_size)
    }

    fn matches(&self, asdu: &Asdu, ioa: Ioa, name: u16) -> bool {
        asdu.common_address == self.ca && ioa == self.ioa && (name == 0 || name == self.name.0)
    }
}

/// What the controlled station's file procedure decided.
pub(crate) struct ServerStep {
    /// ASDUs to send, in order.
    pub(crate) replies: Vec<Asdu>,
    /// A transfer that ended: its file and how.
    pub(crate) ended: Option<(CommonAddress, Ioa, FileName, TransferOutcome)>,
}

impl ServerStep {
    fn reply(asdu: Asdu) -> Self {
        ServerStep { replies: alloc::vec![asdu], ended: None }
    }
    fn none() -> Self {
        ServerStep { replies: Vec::new(), ended: None }
    }
}

fn mirror(asdu: &Asdu, cause: Cause) -> Asdu {
    let mut m = asdu.clone();
    m.cot = Cot { cause, negative: true, ..asdu.cot };
    m
}

fn end(transfer: &mut Option<ServerTransfer>, outcome: TransferOutcome) -> Option<(CommonAddress, Ioa, FileName, TransferOutcome)> {
    transfer.take().map(|t| (t.ca, t.ioa, t.name, outcome))
}

/// The controlled station's answer to one file ASDU (types 120–127) on a connection whose
/// transfer is `transfer`. `known_ca` says whether the station serves `asdu`'s common address.
pub(crate) fn serve(
    store: &mut dyn FileStore,
    transfer: &mut Option<ServerTransfer>,
    asdu: &Asdu,
    profile: &Profile,
    config: &FileConfig,
    known_ca: bool,
    now: Instant,
) -> ServerStep {
    let Objects::CallSelect(objects) = &asdu.objects else {
        if let Objects::FileAck(objects) = &asdu.objects
            && let [o] = objects.as_slice()
        {
            return acknowledge(store, transfer, asdu, profile, config, o.ioa, o.element, now);
        }
        // The control direction (a master offering a file), directories and logs from a master.
        return ServerStep::reply(mirror(asdu, Cause::UNKNOWN_TYPE_ID));
    };
    let [o] = objects.as_slice() else { return ServerStep::reply(mirror(asdu, Cause::FILE_TRANSFER)) };
    let (ioa, call) = (o.ioa, o.element);
    let scq = call.qualifier & 0x0F;
    if asdu.cot.cause == Cause::REQUEST && scq == SCQ_DEFAULT {
        return directory(store, transfer.as_ref(), asdu, profile, known_ca);
    }
    if asdu.cot.cause != Cause::FILE_TRANSFER {
        return ServerStep::reply(mirror(asdu, Cause::UNKNOWN_CAUSE));
    }
    if !known_ca {
        return ServerStep::reply(mirror(asdu, Cause::UNKNOWN_COMMON_ADDRESS));
    }
    match scq {
        SCQ_SELECT_FILE => select(store, transfer, asdu, config, ioa, call, now),
        SCQ_CALL_FILE => match transfer {
            Some(t) if t.state == ServerState::Selected && t.matches(asdu, ioa, call.name) => {
                t.deadline = now + config.timeout;
                if t.sections == 0 {
                    t.state = ServerState::FileOffered;
                    return ServerStep::reply(last_section(asdu, t));
                }
                t.section = 1;
                t.state = ServerState::SectionOffered;
                ServerStep::reply(section_ready(asdu, t))
            }
            _ => ServerStep::reply(mirror(asdu, Cause::FILE_TRANSFER)),
        },
        SCQ_CALL_SECTION => match transfer {
            Some(t) if matches!(t.state, ServerState::SectionOffered | ServerState::Sent) && t.matches(asdu, ioa, call.name) && call.section == t.section => {
                t.deadline = now + config.timeout;
                match segments(store, asdu, profile, t) {
                    Some(replies) => {
                        t.state = ServerState::Sent;
                        ServerStep { replies, ended: None }
                    }
                    None => {
                        let abort = Asdu::new(
                            t.ca,
                            file_cot(asdu.cot, Cause::FILE_TRANSFER),
                            InformationObject::new(t.ioa, LastSection { name: t.name.0, section: t.section, qualifier: LSQ_FILE_DEACTIVATED, checksum: 0 }),
                        );
                        ServerStep { replies: alloc::vec![abort], ended: end(transfer, TransferOutcome::StoreFailed) }
                    }
                }
            }
            _ => ServerStep::reply(mirror(asdu, Cause::FILE_TRANSFER)),
        },
        SCQ_DEACTIVATE_FILE | SCQ_DEACTIVATE_SECTION => match transfer {
            Some(t) if t.matches(asdu, ioa, call.name) => ServerStep { replies: Vec::new(), ended: end(transfer, TransferOutcome::Rejected) },
            _ => ServerStep::none(),
        },
        // Delete file, select section and the reserved qualifiers are not offered.
        _ => ServerStep::reply(mirror(asdu, Cause::FILE_TRANSFER)),
    }
}

fn select(store: &mut dyn FileStore, transfer: &mut Option<ServerTransfer>, asdu: &Asdu, config: &FileConfig, ioa: Ioa, call: CallSelect, now: Instant) -> ServerStep {
    let superseded = end(transfer, TransferOutcome::Superseded);
    let ca = asdu.common_address;
    let found = store.directory(ca).into_iter().find(|f| f.ioa == ioa && (call.name == 0 || f.name.0 == call.name) && !f.status.is_directory());
    let Some(file) = found else {
        return ServerStep { replies: alloc::vec![mirror(asdu, Cause::UNKNOWN_IOA)], ended: superseded };
    };
    let section_size = config.section_size.clamp(1, MAX_LOF);
    let sections = file.length.div_ceil(section_size);
    let cot = file_cot(asdu.cot, Cause::FILE_TRANSFER);
    let too_large = file.length > config.max_length.min(MAX_LOF) || sections > 255;
    let (length, qualifier) = if too_large { (0, NOT_READY) } else { (file.length, 0) };
    let ready = Asdu::new(ca, cot, InformationObject::new(ioa, FileReady { name: file.name.0, length, qualifier }));
    if !too_large {
        *transfer = Some(ServerTransfer {
            ca,
            ioa,
            name: file.name,
            length: file.length,
            section_size,
            section: 0,
            sections: u8::try_from(sections).unwrap_or(u8::MAX),
            section_sum: 0,
            file_sum: 0,
            repeats: 0,
            state: ServerState::Selected,
            deadline: now + config.timeout,
        });
    }
    ServerStep { replies: alloc::vec![ready], ended: superseded }
}

fn section_ready(request: &Asdu, t: &ServerTransfer) -> Asdu {
    let object = SectionReady { name: t.name.0, section: t.section, length: t.section_len(t.section), qualifier: 0 };
    Asdu::new(t.ca, file_cot(request.cot, Cause::FILE_TRANSFER), InformationObject::new(t.ioa, object))
}

fn last_section(request: &Asdu, t: &ServerTransfer) -> Asdu {
    let object = LastSection { name: t.name.0, section: t.sections, qualifier: LSQ_FILE, checksum: t.file_sum };
    Asdu::new(t.ca, file_cot(request.cot, Cause::FILE_TRANSFER), InformationObject::new(t.ioa, object))
}

/// The segments of the current section and its last-segment ASDU, or `None` if the store fails.
fn segments(store: &mut dyn FileStore, request: &Asdu, profile: &Profile, t: &mut ServerTransfer) -> Option<Vec<Asdu>> {
    let len = usize::try_from(t.section_len(t.section)).ok()?;
    let start = u32::from(t.section.saturating_sub(1)).saturating_mul(t.section_size);
    let mut data = alloc::vec![0u8; len];
    let mut filled = 0usize;
    while filled < len {
        let offset = start.checked_add(u32::try_from(filled).ok()?)?;
        let n = store.read(t.ca, t.ioa, t.name, offset, data.get_mut(filled..)?)?;
        if n == 0 {
            return None;
        }
        filled = filled.checked_add(n)?.min(len);
    }
    let cot = file_cot(request.cot, Cause::FILE_TRANSFER);
    let mut replies: Vec<Asdu> = data
        .chunks(segment_size(profile))
        .map(|chunk| Asdu::new(t.ca, cot, InformationObject::new(t.ioa, Segment { name: t.name.0, section: t.section, data: chunk.to_vec() })))
        .collect();
    t.section_sum = checksum(&data);
    let last = LastSection { name: t.name.0, section: t.section, qualifier: LSQ_SECTION, checksum: t.section_sum };
    replies.push(Asdu::new(t.ca, cot, InformationObject::new(t.ioa, last)));
    Some(replies)
}

#[allow(clippy::too_many_arguments)]
fn acknowledge(
    store: &mut dyn FileStore,
    transfer: &mut Option<ServerTransfer>,
    asdu: &Asdu,
    _profile: &Profile,
    config: &FileConfig,
    ioa: Ioa,
    ack: FileAck,
    now: Instant,
) -> ServerStep {
    let _ = store;
    if asdu.cot.cause != Cause::FILE_TRANSFER {
        return ServerStep::reply(mirror(asdu, Cause::UNKNOWN_CAUSE));
    }
    let Some(t) = transfer.as_mut().filter(|t| t.matches(asdu, ioa, ack.name)) else {
        return ServerStep::reply(mirror(asdu, Cause::FILE_TRANSFER));
    };
    t.deadline = now + config.timeout;
    match (ack.qualifier & 0x0F, t.state) {
        (AFQ_SECTION_POSITIVE, ServerState::Sent) if ack.section == t.section => {
            t.file_sum = t.file_sum.wrapping_add(t.section_sum);
            t.repeats = 0;
            if t.section < t.sections {
                t.section += 1;
                t.state = ServerState::SectionOffered;
                ServerStep::reply(section_ready(asdu, t))
            } else {
                t.state = ServerState::FileOffered;
                ServerStep::reply(last_section(asdu, t))
            }
        }
        (AFQ_SECTION_NEGATIVE, ServerState::Sent) if ack.section == t.section => {
            t.repeats += 1;
            if t.repeats > MAX_REPEATS {
                return ServerStep { replies: Vec::new(), ended: end(transfer, TransferOutcome::Rejected) };
            }
            t.state = ServerState::SectionOffered;
            ServerStep::reply(section_ready(asdu, t))
        }
        (AFQ_FILE_POSITIVE, ServerState::FileOffered) => ServerStep { replies: Vec::new(), ended: end(transfer, TransferOutcome::Completed) },
        (AFQ_FILE_NEGATIVE, _) => ServerStep { replies: Vec::new(), ended: end(transfer, TransferOutcome::Rejected) },
        _ => ServerStep::reply(mirror(asdu, Cause::FILE_TRANSFER)),
    }
}

/// The directory of `asdu`'s common address, packed into as few `F_DR_TA_1` as fit.
fn directory(store: &dyn FileStore, transfer: Option<&ServerTransfer>, asdu: &Asdu, profile: &Profile, known_ca: bool) -> ServerStep {
    let ca = asdu.common_address;
    let files = store.directory(ca);
    if files.is_empty() {
        let cause = if known_ca { Cause::UNKNOWN_IOA } else { Cause::UNKNOWN_COMMON_ADDRESS };
        return ServerStep::reply(mirror(asdu, cause));
    }
    let per_asdu = (usize::from(profile.max_asdu_len).saturating_sub(profile.header_len()) / (profile.ioa.octets() + 13)).max(1);
    let last = files.len().saturating_sub(1);
    let cot = file_cot(asdu.cot, Cause::REQUEST);
    let entries: Vec<InformationObject<DirectoryEntry, Cp56Time2a>> = files
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let mut status = f.status.0 & !(FileStatus::LAST_FILE | FileStatus::ACTIVE);
            if i == last {
                status |= FileStatus::LAST_FILE;
            }
            if transfer.is_some_and(|t| t.ioa == f.ioa) {
                status |= FileStatus::ACTIVE;
            }
            InformationObject::new(f.ioa, DirectoryEntry { name: f.name.0, length: f.length.min(MAX_LOF), status }).at(f.created)
        })
        .collect();
    let replies = entries.chunks(per_asdu).map(|chunk| Asdu::new(ca, cot, chunk.to_vec())).collect();
    ServerStep { replies, ended: None }
}

// ---------------------------------------------------------------------------------------------
// The controlling station side
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MasterState {
    Selecting,
    AwaitSection,
    Receiving,
}

/// One download of a controlling station.
#[derive(Debug)]
pub(crate) struct Download {
    pub(crate) id: RequestId,
    pub(crate) ca: CommonAddress,
    pub(crate) ioa: Ioa,
    name: FileName,
    state: MasterState,
    length: u32,
    data: Vec<u8>,
    section: u8,
    section_start: usize,
    section_len: usize,
    retried: bool,
    pub(crate) deadline: Instant,
}

/// One directory listing of a controlling station.
#[derive(Debug)]
pub(crate) struct Listing {
    pub(crate) id: RequestId,
    pub(crate) ca: CommonAddress,
    files: Vec<FileInfo>,
    pub(crate) deadline: Instant,
}

/// What a step of a master file procedure decided.
pub(crate) enum MasterStep {
    /// Not this procedure's ASDU.
    Ignored,
    /// Consumed; send these (possibly none) and keep going.
    Continue(Vec<Asdu>),
    /// Done: send these, then report the data.
    Done(Vec<Asdu>, Box<Finished>),
    /// Failed: send these, then fail the request.
    Failed(Vec<Asdu>, Error),
}

/// What a finished file procedure delivers.
pub(crate) enum Finished {
    File { ioa: Ioa, name: FileName, data: Vec<u8> },
    Directory(Vec<FileInfo>),
}

impl Download {
    /// The select that starts a download, and its state.
    pub(crate) fn start(id: RequestId, ca: CommonAddress, ioa: Ioa, name: FileName, cot: Cot, deadline: Instant) -> (Self, Asdu) {
        let select = Asdu::new(ca, cot, InformationObject::new(ioa, CallSelect { name: name.0, section: 0, qualifier: SCQ_SELECT_FILE }));
        let d = Download {
            id,
            ca,
            ioa,
            name,
            state: MasterState::Selecting,
            length: 0,
            data: Vec::new(),
            section: 0,
            section_start: 0,
            section_len: 0,
            retried: false,
            deadline,
        };
        (d, select)
    }

    fn call(&self, cot: Cot, section: u8, qualifier: u8) -> Asdu {
        Asdu::new(self.ca, cot, InformationObject::new(self.ioa, CallSelect { name: self.name.0, section, qualifier }))
    }

    fn ack(&self, cot: Cot, section: u8, qualifier: u8) -> Asdu {
        Asdu::new(self.ca, cot, InformationObject::new(self.ioa, FileAck { name: self.name.0, section, qualifier }))
    }

    fn fail(&self, error: FileError) -> MasterStep {
        MasterStep::Failed(Vec::new(), Error::File(error))
    }

    /// The download's answer to `asdu`, with `cot` for what it sends and `max_length` the
    /// longest file it accepts.
    pub(crate) fn on_asdu(&mut self, asdu: &Asdu, cot: Cot, max_length: u32) -> MasterStep {
        if asdu.common_address != self.ca || asdu.objects.ioa(0) != Some(self.ioa) {
            return MasterStep::Ignored;
        }
        let negative = asdu.cot.negative || matches!(asdu.cot.cause.value(), 44..=47);
        match &asdu.objects {
            Objects::CallSelect(o) if negative && o.first().is_some_and(|o| o.element.qualifier & 0x0F != SCQ_DEFAULT) => {
                MasterStep::Failed(Vec::new(), Error::Negative { cot: asdu.cot })
            }
            Objects::FileAck(_) if negative => MasterStep::Failed(Vec::new(), Error::Negative { cot: asdu.cot }),
            Objects::FileReady(o) if self.state == MasterState::Selecting => {
                let Some(ready) = o.first().map(|o| o.element) else { return MasterStep::Ignored };
                if ready.qualifier & NOT_READY != 0 || negative {
                    return self.fail(FileError::NotReady);
                }
                if ready.length > max_length.min(MAX_LOF) {
                    let deactivate = self.call(cot, 0, SCQ_DEACTIVATE_FILE);
                    return MasterStep::Failed(alloc::vec![deactivate], Error::File(FileError::TooLarge { length: ready.length }));
                }
                if ready.name != 0 {
                    self.name = FileName(ready.name);
                }
                self.length = ready.length;
                self.state = MasterState::AwaitSection;
                MasterStep::Continue(alloc::vec![self.call(cot, 0, SCQ_CALL_FILE)])
            }
            Objects::SectionReady(o) if self.state == MasterState::AwaitSection => {
                let Some(ready) = o.first().map(|o| o.element) else { return MasterStep::Ignored };
                if ready.qualifier & NOT_READY != 0 {
                    return self.fail(FileError::NotReady);
                }
                let Ok(len) = usize::try_from(ready.length) else { return self.fail(FileError::Protocol("section longer than the file")) };
                if self.data.len().saturating_add(len) > self.length as usize {
                    return self.fail(FileError::Protocol("section longer than the file"));
                }
                self.section = ready.section;
                self.section_start = self.data.len();
                self.section_len = len;
                self.state = MasterState::Receiving;
                MasterStep::Continue(alloc::vec![self.call(cot, ready.section, SCQ_CALL_SECTION)])
            }
            Objects::Segment(o) if self.state == MasterState::Receiving => {
                for segment in o.iter().map(|o| &o.element) {
                    if segment.section != self.section {
                        return self.fail(FileError::Protocol("segment of another section"));
                    }
                    let received = self.data.len() - self.section_start;
                    if received.saturating_add(segment.data.len()) > self.section_len {
                        return self.fail(FileError::Protocol("segment beyond the announced section"));
                    }
                    self.data.extend_from_slice(&segment.data);
                }
                MasterStep::Continue(Vec::new())
            }
            Objects::LastSection(o) => {
                let Some(last) = o.first().map(|o| o.element) else { return MasterStep::Ignored };
                match (last.qualifier, self.state) {
                    (LSQ_SECTION, MasterState::Receiving) if last.section == self.section => self.section_done(cot, last),
                    (LSQ_FILE, MasterState::AwaitSection) => {
                        if self.data.len() != self.length as usize {
                            return self.fail(FileError::Protocol("file shorter than announced"));
                        }
                        if checksum(&self.data) != last.checksum {
                            let nack = self.ack(cot, last.section, AFQ_FILE_NEGATIVE | ERROR_CHECKSUM);
                            return MasterStep::Failed(alloc::vec![nack], Error::File(FileError::Checksum { section: None }));
                        }
                        let ack = self.ack(cot, last.section, AFQ_FILE_POSITIVE);
                        let data = core::mem::take(&mut self.data);
                        MasterStep::Done(alloc::vec![ack], Box::new(Finished::File { ioa: self.ioa, name: self.name, data }))
                    }
                    (LSQ_FILE_DEACTIVATED | LSQ_SECTION_DEACTIVATED, _) => self.fail(FileError::Aborted),
                    _ => MasterStep::Ignored,
                }
            }
            _ => MasterStep::Ignored,
        }
    }

    fn section_done(&mut self, cot: Cot, last: LastSection) -> MasterStep {
        let section = self.data.get(self.section_start..).unwrap_or_default();
        if section.len() != self.section_len {
            return self.fail(FileError::Protocol("section shorter than announced"));
        }
        self.state = MasterState::AwaitSection;
        if checksum(section) == last.checksum {
            self.retried = false;
            return MasterStep::Continue(alloc::vec![self.ack(cot, last.section, AFQ_SECTION_POSITIVE)]);
        }
        self.data.truncate(self.section_start);
        if self.retried {
            let nack = self.ack(cot, last.section, AFQ_FILE_NEGATIVE | ERROR_CHECKSUM);
            return MasterStep::Failed(alloc::vec![nack], Error::File(FileError::Checksum { section: Some(last.section) }));
        }
        self.retried = true;
        MasterStep::Continue(alloc::vec![self.ack(cot, last.section, AFQ_SECTION_NEGATIVE | ERROR_CHECKSUM)])
    }
}

impl Listing {
    /// The call directory that starts a listing, and its state.
    pub(crate) fn start(id: RequestId, ca: CommonAddress, cot: Cot, deadline: Instant) -> (Self, Asdu) {
        let call = Asdu::new(ca, cot, InformationObject::new(Ioa(0), CallSelect { name: 0, section: 0, qualifier: SCQ_DEFAULT }));
        (Listing { id, ca, files: Vec::new(), deadline }, call)
    }

    /// The listing's answer to `asdu`.
    pub(crate) fn on_asdu(&mut self, asdu: &Asdu) -> MasterStep {
        if asdu.common_address != self.ca {
            return MasterStep::Ignored;
        }
        match &asdu.objects {
            Objects::CallSelect(o) if o.first().is_some_and(|o| o.element.qualifier & 0x0F == SCQ_DEFAULT) && asdu.cot.negative => {
                if asdu.cot.cause == Cause::UNKNOWN_IOA {
                    MasterStep::Done(Vec::new(), Box::new(Finished::Directory(Vec::new())))
                } else {
                    MasterStep::Failed(Vec::new(), Error::Negative { cot: asdu.cot })
                }
            }
            Objects::Directory(entries) if asdu.cot.cause == Cause::REQUEST => {
                let mut last = false;
                for e in entries {
                    if self.files.len() >= MAX_DIRECTORY {
                        return MasterStep::Failed(Vec::new(), Error::File(FileError::Protocol("directory longer than the master accepts")));
                    }
                    let status = FileStatus(e.element.status);
                    last |= status.is_last();
                    self.files.push(FileInfo { ioa: e.ioa, name: FileName(e.element.name), length: e.element.length, created: e.time, status });
                }
                if last {
                    MasterStep::Done(Vec::new(), Box::new(Finished::Directory(core::mem::take(&mut self.files))))
                } else {
                    MasterStep::Continue(Vec::new())
                }
            }
            _ => MasterStep::Ignored,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn segment_sizes_fill_the_profile() {
        assert_eq!(segment_size(&Profile::IEC104), 236);
        assert_eq!(segment_size(&Profile::IEC101), 243);
    }

}
