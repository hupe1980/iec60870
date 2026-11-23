//! The ten-line client: connect, start data transfer, run a general interrogation, print every
//! point.
//!
//! ```text
//! cargo run --example client -- 10.0.0.5:2404   # a real outstation
//! cargo run --example client                    # a demo outstation in this process
//! ```

use iec60870::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = std::env::args().nth(1).map_or_else(demo_outstation, Ok)?;

    let mut client = iec60870::Client::connect(addr)?;
    client.start()?; // STARTDT
    for event in client.interrogate(CommonAddress(1))? {
        println!("{}", event?);
    }
    Ok(())
}

/// Serves a small point table on the loopback interface and returns its address.
fn demo_outstation() -> std::io::Result<String> {
    let ca = CommonAddress(1);
    let mut db = Database::new();
    db.insert(ca, Ioa(100), true);
    db.insert(ca, Ioa(101), DoublePointValue::Off);
    db.insert(ca, Ioa(200), 21.5f32);
    db.insert(ca, Ioa(201), -7i16);
    let server = iec60870::Server::bind("127.0.0.1:0", db)?;
    let addr = server.local_addr()?;
    server.spawn(iec60870::station::RefuseCommands)?;
    Ok(addr.to_string())
}
