//! File retrieval through the packaged CLI interface.
use super::run;
use iec60870::{
    CommonAddress, Database, Ioa, Server,
    station::{FileName, MemoryFileStore, RefuseCommands},
};
use serde_json::Value;
use std::fs;

#[test]
fn file_directory_and_downloads_preserve_bytes_and_existing_paths() {
    let ca = CommonAddress(1);
    let mut db = Database::new();
    db.insert(CommonAddress(2), Ioa(1), false);
    let bytes: Vec<_> = (0..=255u8).cycle().take(3071).collect();
    let mut store = MemoryFileStore::new();
    store.insert(ca, Ioa(7), FileName(2), bytes.clone());
    store.insert(ca, Ioa(8), FileName(2), []);
    let server = Server::builder().files(store).bind("127.0.0.1:0", db).unwrap();
    let addr = server.local_addr().unwrap().to_string();
    let handle = server.spawn(RefuseCommands).unwrap();
    let list = run(&["--json", "client", &addr, "files"], b"");
    assert!(list.status.success(), "{}", String::from_utf8_lossy(&list.stderr));
    let rows: Vec<Value> = serde_json::Deserializer::from_slice(&list.stdout).into_iter().map(Result::unwrap).collect();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0]["kind"], "file");
    assert_eq!(rows[0]["ioa"], 7);
    assert_eq!(rows[0]["bytes"], 3071);
    assert_eq!(rows[0]["name"], 2);
    assert_eq!(rows[2]["files"], 2);
    let empty = run(&["--json", "client", &addr, "--ca", "2", "files"], b"");
    assert!(empty.status.success());
    assert_eq!(serde_json::from_slice::<Value>(&empty.stdout).unwrap()["files"], 0);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("record.bin");
    let get = |ioa, path: &std::path::Path| run(&["--json", "client", &addr, "get", ioa, "2", "-o", path.to_str().unwrap()], b"");
    let capped = run(&["client", &addr, "get", "7", "2", "--max-bytes", "1024", "-o", path.to_str().unwrap()], b"");
    assert_eq!(capped.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&capped.stderr).contains("receive limit"));
    assert!(!path.exists());
    let saved = get("7", &path);
    assert!(saved.status.success(), "{}", String::from_utf8_lossy(&saved.stderr));
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert_eq!(serde_json::from_slice::<Value>(&saved.stdout).unwrap()["bytes"], 3071);
    assert_eq!(get("8", &path).status.code(), Some(1));
    assert_eq!(fs::read(&path).unwrap(), bytes);
    let missing = dir.path().join("missing.bin");
    let refused = get("77", &missing);
    assert_eq!(refused.status.code(), Some(3));
    assert_eq!(refused.stdout, b"");
    assert!(!missing.exists());
    assert!(get("8", &missing).status.success());
    assert_eq!(fs::metadata(&missing).unwrap().len(), 0);
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
    handle.shutdown();
}

#[test]
fn file_requests_validate_the_wire_address_before_connecting() {
    for args in [
        &["client", "127.0.0.1:9", "--ca", "65535", "files"][..],
        &["client", "127.0.0.1:9", "--ca-width", "1", "--ca", "255", "get", "10", "2", "-o", "unused"],
        &["client", "127.0.0.1:9", "--ioa", "1", "get", "256", "2", "-o", "unused"],
    ] {
        let out = run(args, b"");
        assert_eq!(out.status.code(), Some(2));
        assert_eq!(out.stdout, b"");
    }
}

#[test]
fn interrupted_download_never_publishes_partial_bytes() {
    use iec60870::station::{FileInfo, FileStore};
    struct Interrupted(MemoryFileStore);
    impl FileStore for Interrupted {
        fn directory_with_limit(&self, ca: CommonAddress, limit: usize) -> Vec<FileInfo> {
            self.0.directory_with_limit(ca, limit)
        }
        fn select(&self, ca: CommonAddress, ioa: Ioa, name: FileName) -> Option<(FileName, u32)> {
            self.0.select(ca, ioa, name)
        }
        fn read(&mut self, ca: CommonAddress, ioa: Ioa, name: FileName, offset: u32, buf: &mut [u8]) -> Option<usize> {
            if offset != 0 {
                return None;
            }
            self.0.read(ca, ioa, name, offset, buf)
        }
    }
    let mut store = MemoryFileStore::new();
    store.insert(CommonAddress(1), Ioa(7), FileName(2), vec![9; 2048]);
    let server = Server::builder().files(Interrupted(store)).bind("127.0.0.1:0", Database::new()).unwrap();
    let addr = server.local_addr().unwrap().to_string();
    let handle = server.spawn(RefuseCommands).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("partial.bin");
    let out = run(&["client", &addr, "get", "7", "2", "-o", path.to_str().unwrap()], b"");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(out.stdout, b"");
    assert!(String::from_utf8_lossy(&out.stderr).contains("abort"));
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    handle.shutdown();
}

#[test]
fn unavailable_download_directory_is_reported_before_connection() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing").join("record.bin");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let out = run(&["client", &addr, "--timeout", "200ms", "get", "7", "2", "-o", path.to_str().unwrap()], b"");
    listener.set_nonblocking(true).unwrap();
    assert!(matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("cannot save"));
    assert_eq!(out.stdout, b"");
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
}
