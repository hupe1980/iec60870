//! Two 104 links on loopback: a controlled station that answers each command it receives
//! with an event, and a controlling station that starts data transfer, sends three commands,
//! waits for the answers and stops.
//!
//! ```text
//! cargo run --example cs104_link
//! ```

use std::net::TcpListener;
use std::thread;

use iec60870::cs104::{self, Config, Event};

/// `C_SC_NA_1` (single command), activation, CA 1, IOA `ioa`, ON.
fn command(ioa: u8) -> Vec<u8> {
    vec![45, 1, 6, 0, 1, 0, ioa, 0, 0, 1]
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;

    // The controlled station: STARTDT and TESTFR are answered by the link itself.
    let outstation = thread::spawn(move || -> std::io::Result<()> {
        let (mut link, peer) = cs104::accept(&listener, Config::default())?;
        println!("outstation: connection from {peer}");
        while let Some(event) = link.next_event()? {
            match event {
                Event::Asdu(asdu) => {
                    println!("outstation: received {asdu:02x?}");
                    // Mirror it back as an activation confirmation (COT 7).
                    let mut answer = asdu;
                    if let Some(cot) = answer.get_mut(2) {
                        *cot = 7;
                    }
                    if let Err(e) = link.submit(&answer) {
                        println!("outstation: cannot answer now: {e}");
                    }
                }
                other => println!("outstation: {other:?}"),
            }
        }
        Ok(())
    });

    // The controlling station.
    let mut link = cs104::connect(addr, Config::default())?;
    link.start()?;
    let mut answers = 0;
    while let Some(event) = link.next_event()? {
        match event {
            Event::Started => {
                for ioa in 1..=3 {
                    link.submit(&command(ioa))?;
                }
            }
            Event::Asdu(asdu) => {
                println!("master: received {asdu:02x?}");
                answers += 1;
                if answers == 3 {
                    link.stop()?;
                }
            }
            Event::Stopped => {
                println!("master: stopped");
                link.protocol_mut().close();
            }
            other => println!("master: {other:?}"),
        }
    }
    outstation.join().map_err(|_| "the outstation thread panicked")??;
    Ok(())
}
