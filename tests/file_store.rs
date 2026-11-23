//! Record lookup, isolation and bounded reads through the public store API.
#![allow(clippy::unwrap_used)]

use iec60870::station::{FileName, FileStore, MemoryFileStore};
use iec60870::{CommonAddress, Ioa};

const CA: CommonAddress = CommonAddress(1);
const IOA: Ioa = Ioa(200);

fn check_records(store: &mut dyn FileStore) {
    let rows: Vec<_> = store.directory(CA).into_iter().map(|file| (file.ioa, file.name, file.length)).collect();
    assert_eq!(rows, [(IOA, FileName(1), 3), (IOA, FileName(2), 1)]);
    let mut buf = [99; 2];
    assert_eq!(store.read(CA, IOA, FileName(1), 1, &mut buf), Some(2));
    assert_eq!(buf, [2, 3]);
    assert_eq!(store.read(CA, IOA, FileName(2), 0, &mut buf), Some(1));
    assert_eq!(buf, [4, 3]);
    for offset in [3, u32::MAX] {
        assert_eq!(store.read(CA, IOA, FileName(1), offset, &mut buf), Some(0));
    }
    assert_eq!(store.read(CA, IOA, FileName(9), 0, &mut buf), None);
    assert_eq!(store.directory(CommonAddress(9)), []);
    assert_eq!(store.read(CommonAddress(9), IOA, FileName(1), 0, &mut buf), None);
}

#[test]
fn memory_files_are_addressed_by_station_object_and_name() {
    let mut store = MemoryFileStore::new();
    store.insert(CA, IOA, FileName(2), [4]);
    store.insert(CA, IOA, FileName(1), [1, 2, 3]);
    store.insert(CommonAddress(2), IOA, FileName(1), [9]);
    check_records(&mut store);
    store.insert(CA, IOA, FileName(1), []);
    assert_eq!(store.remove(CA, IOA, FileName(1)), Some(vec![]));
    assert_eq!(store.remove(CA, IOA, FileName(2)), Some(vec![4]));
    assert_eq!(store.remove(CommonAddress(2), IOA, FileName(1)), Some(vec![9]));
}

#[cfg(feature = "file-store-fs")]
#[test]
fn directory_lists_and_reads_only_canonical_regular_files() {
    use iec60870::station::DirectoryFileStore;
    use std::fs;

    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("7.1")).unwrap();
    for name in ["200.01", "00020.2", "notes", "+1.0", "16777216.0", "3.65536"] {
        fs::write(root.path().join(name), [0]).unwrap();
    }
    fs::write(root.path().join("200.1"), [1, 2, 3]).unwrap();
    fs::write(root.path().join("200.2"), [4]).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("200.1", root.path().join("4.1")).unwrap();
    let mut store = DirectoryFileStore::open(root.path(), CA).unwrap();
    check_records(&mut store);
    let mut buf = [0];
    assert_eq!(store.read(CA, Ioa(7), FileName(1), 0, &mut buf), None);
    assert_eq!(store.read(CA, Ioa(4), FileName(1), 0, &mut buf), None);
    assert_eq!(store.read(CA, Ioa(16_777_216), FileName(0), 0, &mut buf), None);
}

#[cfg(all(unix, feature = "file-store-fs"))]
#[test]
fn directory_handle_keeps_its_identity_after_rename() {
    use iec60870::station::DirectoryFileStore;
    use std::fs;

    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("records");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("200.1"), [7]).unwrap();
    let mut store = DirectoryFileStore::open(&root, CA).unwrap();
    fs::rename(&root, parent.path().join("previous")).unwrap();
    fs::create_dir(&root).unwrap();
    fs::write(root.join("200.1"), [9, 9]).unwrap();
    assert_eq!(store.directory(CA).first().unwrap().length, 1);
    let mut buf = [0];
    assert_eq!(store.read(CA, IOA, FileName(1), 0, &mut buf), Some(1));
    assert_eq!(buf, [7]);
}
