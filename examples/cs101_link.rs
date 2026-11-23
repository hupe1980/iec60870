//! An unbalanced 101 master polling an outstation, wired back to back without I/O.
//!
//! The outstation queues a spontaneous single point (type 1) as class 1 data; the master
//! resets the link, polls class 2, sees ACD, polls class 1 and prints what it got.
//!
//! Run with `cargo run --example cs101_link --features cs101`.

use iec60870::cs101::{Class, Config, Cs101Link, Event, LinkAddress};
use iec60870::driver::Output;
use iec60870::time::Instant;
use iec60870::{Asdu, Profile};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rtu = LinkAddress(7);
    let mut master = Cs101Link::primary(&[rtu], Config::default())?;
    let mut outstation = Cs101Link::secondary(rtu, Config::default())?;

    // M_SP_NA_1, one object, COT spontaneous, CA 1, IOA 100, ON — encoded with the 101 profile.
    let asdu = [0x01, 0x01, 0x03, 0x01, 0x64, 0x00, 0x01];
    outstation.submit(&asdu, Class::One, Instant::ZERO)?;

    for ms in (0..200).step_by(10) {
        let now = Instant::from_millis(ms);
        master.handle_timeout(now);
        // Pass frames back and forth until the line is quiet.
        loop {
            let mut quiet = true;
            while let Some(output) = master.poll_output() {
                match output {
                    Output::Transmit(frame) => {
                        println!("master    → {frame:02X?}");
                        outstation.handle_input(&frame, now);
                        quiet = false;
                    }
                    Output::Event(Event::Asdu { station, asdu }) => {
                        let decoded = Asdu::decode(&asdu, &Profile::IEC101)?;
                        println!("master got from {station}: {:?}", decoded.objects);
                    }
                    Output::Event(event) => println!("master    : {event:?}"),
                    Output::Deadline(_) => {}
                }
            }
            while let Some(output) = outstation.poll_output() {
                match output {
                    Output::Transmit(frame) => {
                        println!("outstation → {frame:02X?}");
                        master.handle_input(&frame, now);
                        quiet = false;
                    }
                    Output::Event(event) => println!("outstation: {event:?}"),
                    Output::Deadline(_) => {}
                }
            }
            if quiet {
                break;
            }
        }
    }
    Ok(())
}
