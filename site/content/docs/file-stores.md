+++
title = "Station files and downloads"
description = "Publish a file catalog, list and download records from a remote station, and read local record data."
weight = 5
+++

## Identify a record

A record has three identifiers: the station's common address, its information object address (IOA), and the IEC name of file (NOF). Two records can share an IOA. Use all three identifiers to read or remove one.

Enable `file-transfer` for the `FileStore` trait and `MemoryFileStore`. The memory catalog works on embedded targets with an allocator.

```rust
use iec60870::{CommonAddress, Ioa};
use iec60870::station::{FileName, FileStore, MemoryFileStore};

let mut records = MemoryFileStore::new();
let station = CommonAddress(1);
let point = Ioa(30000);
let name = FileName::DISTURBANCE_DATA;
records.insert(station, point, name, [10, 20, 30]);

let mut buf = [0; 2];
assert_eq!(records.read(station, point, name, 1, &mut buf), Some(2));
assert_eq!(buf, [20, 30]);
```

`directory(station)` returns metadata in IOA and NOF order for the built-in stores. A read returns the number of bytes copied. With a nonempty buffer, zero means end of file. A missing or unreadable record returns `None`.

## List records from a station

Run the loopback example to publish a disturbance record and list it from a second station in the same process.

```sh
cargo run --locked --example files --features file-transfer
```

With the installed CLI, run `iec60870 client HOST files` to list a published catalog, then `iec60870 client HOST get 30000 2 -o record.bin` to save one record. [CLI file retrieval](../cli/#list-and-download-station-files)

Pass your populated store to `Server::builder().files(records)` before calling `bind` or `bind_async`. On a connected blocking client, start data transfer and request the catalog.

```rust
client.start()?;
for file in client.files(station)? {
    println!("{} · {} · {} bytes", file.ioa, file.name, file.length);
}
```

A blocking client retains unrelated station events for later polling by default. For a one-shot file query on a busy station, call `client.set_event_buffering(false)` before starting the session to skip those events. The CLI does this for `files` and `get`.

With a connected and started `AsyncClient`, use `client.files(station).await?`. The sans-I/O equivalent is `ControllingStation::directory`, which emits `Event::Directory` when the final entry arrives.

A request lists one common address. An empty catalog at a known station returns an empty vector. An unknown address returns a negative confirmation. Replies can span multiple frames, with the last-file bit set on the final record. Each listing supports up to 4,096 records. An interrupted or oversized response returns an error.

## Download a record

Use the IOA and file name from a directory entry to retrieve its bytes. The Tokio client accepts the same arguments and returns the bytes when awaited.

```rust
let bytes = client.download(station, file.ioa, file.name)?;
```

Both roles check file and section lengths. The client retries a section once on a checksum mismatch and returns the file after it verifies the final checksum. A failure returns a station error. Configure `ClientConfig::files.max_length` for the memory available to your application. The default is 16,777,215 bytes. Each connection can select one file at a time. By default the server sends 65,536-byte sections and expires idle selections after 30 seconds.

### Cancel a download

A Tokio caller can put a time budget around a download. If the deadline expires, Tokio drops the pending future. The client releases its local request and queues the IEC file-deactivation message. Continue driving the client to send it. Peer cleanup depends on the outstation’s support for deactivation. Before selecting another file on the same connection after local cancellation or timeout, the client waits for a test-command confirmation. This relies on the peer sending earlier file replies before its test confirmation. Use a new connection with a peer that reorders those replies. If the peer does not support the profile’s test command, reconnect before retrying.

```rust
let result = tokio::time::timeout(
    std::time::Duration::from_secs(5),
    client.download(station, file.ioa, file.name),
).await;
```

With the sans-I/O API, pass the download’s request ID and current time to `cancel_download(id, now)`, then drain the station outputs. A successful cancellation emits `FileError::Cancelled`. Calling it again returns `false`. A peer-initiated abort uses `FileError::Aborted`.

## Read from a host directory

Enable `file-store-fs` to include the host filesystem adapter. It opens the configured directory once. A regular file named `30000.2` represents IOA 30000 and NOF 2. Use unsigned decimal components without leading zeros. Subdirectories, symlinks and unrelated filenames are ignored. The directory entry's timestamp comes from the file's modification time.

```rust
use iec60870::CommonAddress;
use iec60870::station::{DirectoryFileStore, FileStore};

fn list_records() -> std::io::Result<()> {
    let station = CommonAddress(1);
    let records = DirectoryFileStore::open("records", station)?;
    for file in records.directory(station) {
        println!("{} · {} · {} bytes", file.ioa, file.name, file.length);
    }
    Ok(())
}
```
