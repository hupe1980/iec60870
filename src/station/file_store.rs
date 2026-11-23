//! Local record catalogs addressed by common address, object address and name of file.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::fmt;

use crate::time::Cp56Time2a;
use crate::types::{CallSelect, CommonAddress, Ioa};

pub(crate) const DIRECTORY_LIMIT: usize = 4096;
pub(crate) const DIRECTORY_CALL: CallSelect = CallSelect { name: 0, section: 0, qualifier: 0 };

/// The name of a file (NOF): what kind of file the object at an IOA is.
///
/// ```
/// use iec60870::station::FileName;
/// assert_eq!(FileName::from(2), FileName::DISTURBANCE_DATA);
/// assert_eq!(FileName::DISTURBANCE_DATA.to_string(), "disturbance data (2)");
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct FileName(pub u16);

impl FileName {
    /// 0: in a select, whatever file is at the address.
    pub const DEFAULT: FileName = FileName(0);
    /// 1: a transparent file.
    pub const TRANSPARENT: FileName = FileName(1);
    /// 2: disturbance data of protection equipment.
    pub const DISTURBANCE_DATA: FileName = FileName(2);
    /// 3: sequences of events.
    pub const EVENTS: FileName = FileName(3);
    /// 4: sequences of recorded analogue values.
    pub const ANALOGUE_VALUES: FileName = FileName(4);
}

impl From<u16> for FileName {
    fn from(name: u16) -> Self {
        FileName(name)
    }
}

impl fmt::Display for FileName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self.0 {
            0 => "default",
            1 => "transparent file",
            2 => "disturbance data",
            3 => "sequences of events",
            4 => "sequences of analogue values",
            _ => return write!(f, "file name {}", self.0),
        };
        write!(f, "{name} ({})", self.0)
    }
}

/// The status of a file in a directory entry (SOF).
///
/// ```
/// use iec60870::station::FileStatus;
/// let sof = FileStatus(FileStatus::LAST_FILE | 3);
/// assert!(sof.is_last() && !sof.is_directory() && !sof.is_active());
/// assert_eq!(sof.status(), 3);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct FileStatus(pub u8);

impl FileStatus {
    /// Bits 0–4: the status proper (application defined).
    pub const STATUS: u8 = 0x1F;
    /// LFD: the last file of the directory.
    pub const LAST_FILE: u8 = 0x20;
    /// FOR: the entry names a subdirectory.
    pub const DIRECTORY: u8 = 0x40;
    /// FA: the file is being transferred.
    pub const ACTIVE: u8 = 0x80;

    /// The status bits 0–4.
    pub const fn status(self) -> u8 {
        self.0 & Self::STATUS
    }
    /// Whether LFD is set.
    pub const fn is_last(self) -> bool {
        self.0 & Self::LAST_FILE != 0
    }
    /// Whether FOR is set.
    pub const fn is_directory(self) -> bool {
        self.0 & Self::DIRECTORY != 0
    }
    /// Whether FA is set.
    pub const fn is_active(self) -> bool {
        self.0 & Self::ACTIVE != 0
    }
}

/// A file as a directory lists it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FileInfo {
    /// The information object address of the file.
    pub ioa: Ioa,
    /// The name of file.
    pub name: FileName,
    /// The length in octets (at most `0xFF_FFFF` can be transferred).
    pub length: u32,
    /// The creation time.
    pub created: Cp56Time2a,
    /// The status of file.
    pub status: FileStatus,
}

/// A catalog of local file-transfer records.
///
/// A record is identified by its common address, IOA and [`FileName`]. List its metadata
/// with [`directory`](Self::directory) and copy a range into caller-owned storage with [`read`](Self::read).
///
/// ```
/// use iec60870::{CommonAddress, Ioa};
/// use iec60870::station::{FileName, FileStore, MemoryFileStore};
///
/// let mut catalog = MemoryFileStore::new();
/// let ca = CommonAddress(1);
/// let ioa = Ioa(200);
/// let name = FileName::EVENTS;
/// catalog.insert(ca, ioa, name, [1, 2, 3]);
///
/// let store: &mut dyn FileStore = &mut catalog;
/// let mut buf = [0; 2];
/// assert_eq!(store.read(ca, ioa, name, 1, &mut buf), Some(2));
/// assert_eq!(buf, [2, 3]);
/// ```
pub trait FileStore {
    /// The files of `common_address` (empty if it has none).
    fn directory(&self, common_address: CommonAddress) -> Vec<FileInfo> {
        self.directory_with_limit(common_address, usize::MAX)
    }

    /// Enumerates at most `limit` records for one address. When the catalog exceeds the
    /// limit, any subset of exactly `limit` records suffices. The station requests one
    /// extra entry to distinguish a full directory from an oversized directory.
    fn directory_with_limit(&self, common_address: CommonAddress, limit: usize) -> Vec<FileInfo>;

    /// Returns the concrete file name and length of a selected record. Name zero selects
    /// the lowest available name at the requested address.
    fn select(&self, ca: CommonAddress, ioa: Ioa, name: FileName) -> Option<(FileName, u32)>;

    /// Copies octets of the file from `offset` into `buf`; the count copied (0 at the end), or
    /// `None` if the file cannot be read.
    fn read(&mut self, common_address: CommonAddress, ioa: Ioa, name: FileName, offset: u32, buf: &mut [u8]) -> Option<usize>;
}

/// Files held in memory: for tests, simulators, and outstations that build their records in RAM.
///
/// ```
/// use iec60870::prelude::*;
/// use iec60870::station::{FileName, FileStore, MemoryFileStore};
///
/// let mut files = MemoryFileStore::new();
/// files.insert(CommonAddress(1), Ioa(30000), FileName::DISTURBANCE_DATA, vec![1, 2, 3]);
/// let list = files.directory(CommonAddress(1));
/// assert_eq!((list[0].ioa, list[0].length), (Ioa(30000), 3));
/// ```
#[derive(Clone, Debug, Default)]
pub struct MemoryFileStore {
    files: BTreeMap<(CommonAddress, Ioa, FileName), (Cp56Time2a, Vec<u8>)>,
}

impl MemoryFileStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds or replaces the file at (`common_address`, `ioa`, `name`), its creation time unknown
    /// (the invalid bit set).
    pub fn insert(&mut self, common_address: CommonAddress, ioa: Ioa, name: FileName, data: impl Into<Vec<u8>>) -> &mut Self {
        self.insert_at(common_address, ioa, name, data, Cp56Time2a::default().with_invalid(true))
    }

    /// Adds or replaces the file at (`common_address`, `ioa`, `name`) with its creation time.
    pub fn insert_at(&mut self, common_address: CommonAddress, ioa: Ioa, name: FileName, data: impl Into<Vec<u8>>, created: Cp56Time2a) -> &mut Self {
        self.files.insert((common_address, ioa, name), (created, data.into()));
        self
    }

    /// Removes the file at (`common_address`, `ioa`, `name`), returning its octets.
    pub fn remove(&mut self, common_address: CommonAddress, ioa: Ioa, name: FileName) -> Option<Vec<u8>> {
        self.files.remove(&(common_address, ioa, name)).map(|(_, data)| data)
    }
}

impl FileStore for MemoryFileStore {
    fn select(&self, ca: CommonAddress, ioa: Ioa, name: FileName) -> Option<(FileName, u32)> {
        let last = if name.0 == 0 { FileName(u16::MAX) } else { name };
        let ((_, _, matched), (_, data)) = self.files.range((ca, ioa, name)..=(ca, ioa, last)).next()?;
        Some((*matched, u32::try_from(data.len()).unwrap_or(u32::MAX)))
    }

    fn directory_with_limit(&self, common_address: CommonAddress, limit: usize) -> Vec<FileInfo> {
        self.files
            .range((common_address, Ioa(0), FileName(0))..=(common_address, Ioa(u32::MAX), FileName(u16::MAX)))
            .take(limit)
            .map(|((_, ioa, name), (created, data))| FileInfo {
                ioa: *ioa,
                name: *name,
                length: u32::try_from(data.len()).unwrap_or(u32::MAX),
                created: *created,
                status: FileStatus::default(),
            })
            .collect()
    }

    fn read(&mut self, common_address: CommonAddress, ioa: Ioa, name: FileName, offset: u32, buf: &mut [u8]) -> Option<usize> {
        let (_, data) = self.files.get(&(common_address, ioa, name))?;
        let rest = data.get(usize::try_from(offset).unwrap_or(usize::MAX)..).unwrap_or_default();
        let n = rest.len().min(buf.len());
        buf.get_mut(..n)?.copy_from_slice(rest.get(..n)?);
        Some(n)
    }
}

/// The sum of `octets` modulo 256: the checksum (CHS) of a section and of a file.
///
/// ```
/// assert_eq!(iec60870::station::checksum(&[0xFF, 0x02]), 0x01);
/// ```
pub fn checksum(octets: &[u8]) -> u8 {
    octets.iter().fold(0u8, |sum, b| sum.wrapping_add(*b))
}

/// File service resource limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileConfig {
    /// Octets in each outgoing section, clamped to the wire range.
    pub section_size: u32,
    /// Maximum length of a file in octets.
    pub max_length: u32,
    /// Maximum idle time for a selected file.
    pub timeout: core::time::Duration,
}
impl Default for FileConfig {
    fn default() -> Self {
        Self { section_size: 65536, max_length: 0xff_ffff, timeout: core::time::Duration::from_secs(30) }
    }
}
/// Final status of a selected file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransferOutcome {
    /// Peer acknowledged the complete file.
    Completed,
    /// Peer rejected or deactivated the transfer.
    Rejected,
    /// Transfer deadline expired.
    TimedOut,
    /// Connection closed.
    Disconnected,
    /// Another select replaced this transfer.
    Superseded,
    /// The catalog could no longer provide the announced data.
    StoreFailed,
}

/// Reason a file could not be downloaded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FileError {
    /// Peer rejected the selected record.
    NotReady,
    /// The announced file exceeds the receive limit.
    TooLarge {
        /// Announced size in octets.
        length: u32,
    },
    /// Checksum verification failed.
    Checksum {
        /// Section number, or None for the whole file.
        section: Option<u8>,
    },
    /// Peer deactivated the transfer.
    Aborted,
    /// The local application cancelled the download.
    Cancelled,
    /// Unexpected sequence or invalid length.
    Protocol(&'static str),
}
impl fmt::Display for FileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotReady => f.write_str("file is not ready"),
            Self::TooLarge { length } => write!(f, "file length {length} exceeds the receive limit"),
            Self::Checksum { section: Some(n) } => write!(f, "checksum mismatch in section {n}"),
            Self::Checksum { section: None } => f.write_str("file checksum mismatch"),
            Self::Cancelled => f.write_str("file download cancelled"),
            Self::Aborted => f.write_str("peer aborted file transfer"),
            Self::Protocol(reason) => f.write_str(reason),
        }
    }
}
impl core::error::Error for FileError {}
impl From<FileError> for super::Error {
    fn from(e: FileError) -> Self {
        Self::File(e)
    }
}
