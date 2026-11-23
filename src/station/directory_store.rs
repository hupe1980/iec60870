//! Host filesystem record catalog.

use alloc::vec::Vec;
use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt, OpenOptionsSyncExt};
use cap_std::fs::{Dir, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use std::time::UNIX_EPOCH;

use super::{FileInfo, FileName, FileStatus, FileStore};
use crate::{CommonAddress, Cp56Time2a, Ioa};

/// Regular files in a single directory, listed in (IOA, name) order.
///
/// A filename such as `30000.2` identifies IOA 30000 and name 2. Each component uses
/// canonical unsigned decimal digits. Entries are opened relative to the directory
/// handle acquired at construction. Symlinks and subdirectories are excluded.
#[derive(Debug)]
pub struct DirectoryFileStore {
    root: Dir,
    common_address: CommonAddress,
}

impl DirectoryFileStore {
    /// Open the record directory. A missing or inaccessible root returns an I/O error.
    pub fn open(root: impl AsRef<Path>, common_address: CommonAddress) -> io::Result<Self> {
        Ok(Self { root: Dir::open_ambient_dir(root, cap_std::ambient_authority())?, common_address })
    }
}

fn parse_name(name: &str) -> Option<(Ioa, FileName)> {
    let (address, kind) = name.split_once('.')?;
    let decimal = |s: &str| s == "0" || (!s.starts_with('0') && !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()));
    if !decimal(address) || !decimal(kind) {
        return None;
    }
    let address = address.parse().ok()?;
    (address <= 0xff_ffff).then_some((Ioa(address), FileName(kind.parse().ok()?)))
}

impl FileStore for DirectoryFileStore {
    fn select(&self, ca: CommonAddress, ioa: Ioa, name: FileName) -> Option<(FileName, u32)> {
        if ca != self.common_address || ioa.0 > 0xff_ffff {
            return None;
        }
        let length = |name: FileName| {
            let m = self.root.symlink_metadata(std::format!("{}.{}", ioa.0, name.0)).ok()?;
            m.is_file().then(|| (name, u32::try_from(m.len()).unwrap_or(u32::MAX)))
        };
        if name.0 != 0 {
            return length(name);
        }
        self.root
            .entries()
            .ok()?
            .filter_map(Result::ok)
            .filter_map(|e| {
                let (address, n) = parse_name(e.file_name().to_str()?)?;
                (address == ioa).then(|| length(n)).flatten()
            })
            .min_by_key(|(n, _)| *n)
    }

    fn directory_with_limit(&self, common_address: CommonAddress, limit: usize) -> Vec<FileInfo> {
        if common_address != self.common_address {
            return Vec::new();
        }
        let Ok(entries) = self.root.entries() else { return Vec::new() };
        let mut files: Vec<_> = entries
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let filename = entry.file_name();
                let (ioa, name) = parse_name(filename.to_str()?)?;
                let metadata = self.root.symlink_metadata(filename).ok()?;
                if !metadata.is_file() {
                    return None;
                }
                let created = metadata
                    .modified()
                    .ok()
                    .and_then(|t| t.into_std().duration_since(UNIX_EPOCH).ok())
                    .and_then(|age| u64::try_from(age.as_millis()).ok())
                    .and_then(Cp56Time2a::from_unix_millis)
                    .unwrap_or_else(|| Cp56Time2a::default().with_invalid(true));
                Some(FileInfo { ioa, name, length: u32::try_from(metadata.len()).unwrap_or(u32::MAX), created, status: FileStatus::default() })
            })
            .take(limit)
            .collect();
        files.sort_unstable_by_key(|f| (f.ioa, f.name));
        files
    }

    fn read(&mut self, common_address: CommonAddress, ioa: Ioa, name: FileName, offset: u32, buf: &mut [u8]) -> Option<usize> {
        if common_address != self.common_address || ioa.0 > 0xff_ffff {
            return None;
        }
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No).nonblock(true);
        let mut file = self.root.open_with(std::format!("{}.{}", ioa.0, name.0), &options).ok()?;
        if !file.metadata().ok()?.is_file() {
            return None;
        }
        file.seek(SeekFrom::Start(u64::from(offset))).ok()?;
        loop {
            match file.read(buf) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                result => return result.ok(),
            }
        }
    }
}
