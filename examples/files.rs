//! Publish a disturbance record and download it from a blocking client on loopback.
//!
//! Run with `cargo run --example files --features file-transfer`.

use iec60870::station::{FileName, MemoryFileStore, RefuseCommands};
use iec60870::{Client, CommonAddress, Database, Ioa, Server};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let station = CommonAddress(1);
    let mut records = MemoryFileStore::new();
    records.insert(station, Ioa(30000), FileName::DISTURBANCE_DATA, [10, 20, 30]);

    let server = Server::builder().files(records).bind("127.0.0.1:0", Database::new())?;
    let address = server.local_addr()?;
    let handle = server.spawn(RefuseCommands)?;
    let mut client = Client::connect(address)?;
    client.start()?;
    for file in client.files(station)? {
        let bytes = client.download(station, file.ioa, file.name)?;
        println!("{} · {} · {} bytes · {bytes:?}", file.ioa, file.name, bytes.len());
    }
    handle.shutdown();
    Ok(())
}
