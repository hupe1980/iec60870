//! Select-before-operate, step by step — and what the outstation does with an execute that
//! was never selected.
//!
//! ```text
//! cargo run --example sbo
//! ```

use iec60870::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ca = CommonAddress(1);
    let mut db = Database::new();
    db.command(ca, Ioa(5000), CommandKind::Double); // select-before-operate by default
    let server = iec60870::Server::bind("127.0.0.1:0", db)?.spawn(|cmd: &CommandRequest| {
        println!("  outstation asked: {cmd}");
        Decision::Accept
    })?;

    let mut client = iec60870::Client::connect(server.local_addr())?;
    client.start()?;

    println!("select, then execute:");
    for step in client.select_and_execute(ca, Ioa(5000), Command::double(DoublePointValue::On))? {
        println!("  {:?}", step?);
    }

    println!("execute without a select:");
    match client.command(ca, Ioa(5000), Command::double(DoublePointValue::Off))?.wait() {
        Err(iec60870::Error::Negative { cot }) => println!("  refused by the outstation: {cot}"),
        other => println!("  unexpected: {other:?}"),
    }
    server.shutdown();
    Ok(())
}
