//! An outstation serving a point table: a breaker (with a select-before-operate command that
//! moves it) and a temperature that changes every second.
//!
//! ```text
//! cargo run --example server -- 0.0.0.0:2404   # serve until stopped
//! cargo run --example server                   # serve on loopback, query itself, exit
//! ```

use std::time::Duration;

use iec60870::prelude::*;
use iec60870::{Server, ServerHandle};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = std::env::args().nth(1);
    let ca = CommonAddress(1);
    let mut db = Database::new();
    db.insert(ca, Ioa(100), false); // breaker position
    db.insert(ca, Ioa(200), 21.5f32); // temperature
    db.command(ca, Ioa(5000), CommandKind::Single); // breaker command, select-before-operate

    let server = Server::bind(addr.as_deref().unwrap_or("127.0.0.1:0"), db)?;
    let breaker = server.handle();
    let handle = server.spawn(move |cmd: &CommandRequest| {
        println!("outstation: {cmd}");
        if let Command::Single(c) = cmd.command {
            let _ = breaker.update(ca, Ioa(100), c.state());
        }
        Decision::Accept
    })?;
    for t in 0u16.. {
        handle.update(ca, Ioa(200), 20.0 + f32::from(t % 10) / 2.0)?;
        if addr.is_none() && t == 2 {
            return demo(&handle, ca);
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    Ok(())
}

/// Without an address: be our own master once, then stop.
fn demo(server: &ServerHandle, ca: CommonAddress) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = iec60870::Client::connect(server.local_addr())?;
    client.start()?;
    for event in client.interrogate(ca)? {
        println!("master: {}", event?);
    }
    client.select_and_execute(ca, Ioa(5000), Command::single(true))?.wait()?;
    while let Some(event) = client.poll_event(Duration::from_millis(200))? {
        println!("master: {event}");
    }
    server.shutdown();
    Ok(())
}
