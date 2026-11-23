//! The stations over 101: the same `ControllingStation` and `ControlledStation` that run over
//! the 104 link run over `Cs101Link` — unbalanced (a polling master and an outstation with
//! class queues) and balanced — with `Profile::IEC101` and no 101-specific station code. A
//! general interrogation returns every point and completes; a spontaneous update arrives.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

use std::time::Duration;

use iec60870::cs101::{Config, Cs101Link, LinkAddress, Role};
use iec60870::driver::{Output as LinkOutput, Protocol};
use iec60870::prelude::*;
use iec60870::station::{ClientConfig, ConnectionId, ControlledStation, ControllingStation, Database, Event, Output, RefuseCommands, ServerConfig};

const CA: CommonAddress = CommonAddress(1);

fn clock() -> Cp56Time2a {
    Cp56Time2a::from_unix_millis(1_795_000_000_000).unwrap()
}

struct Pair {
    master: ControllingStation<Cs101Link>,
    outstation: ControlledStation<Cs101Link>,
    connection: ConnectionId,
    events: Vec<Event>,
    now: Instant,
}

impl Pair {
    fn new(master_link: Cs101Link, outstation_link: Cs101Link) -> Pair {
        let mut db = Database::new();
        let _ = db.insert(CA, Ioa(100), true);
        let _ = db.insert(CA, Ioa(101), false);
        let _ = db.insert(CA, Ioa(200), 7i16);
        let config = ServerConfig { profile: Profile::IEC101, end_of_initialization: None, ..ServerConfig::default() };
        let mut outstation = ControlledStation::new(db, config, clock);
        let group = outstation.add_group();
        let connection = outstation.attach(outstation_link, group);
        let master = ControllingStation::new(master_link, ClientConfig { profile: Profile::IEC101, ..ClientConfig::default() }, clock);
        Pair { master, outstation, connection, events: Vec::new(), now: Instant::ZERO }
    }

    /// Moves frames both ways until the line is quiet.
    fn settle(&mut self) {
        for _ in 0..1000 {
            let mut moved = false;
            while let Some(o) = Protocol::poll_output(&mut self.master) {
                match o {
                    LinkOutput::Transmit(bytes) => {
                        moved = true;
                        self.outstation.handle_input(self.connection, &bytes, self.now, &mut RefuseCommands);
                    }
                    LinkOutput::Event(e) => self.events.push(e),
                    LinkOutput::Deadline(_) => {}
                }
            }
            while let Some(o) = self.outstation.poll_output() {
                if let Output::Transmit { bytes, .. } = o {
                    moved = true;
                    Protocol::handle_input(&mut self.master, &bytes, self.now);
                }
            }
            if !moved {
                return;
            }
        }
        panic!("the line never settles");
    }

    fn run(&mut self, ms: u64) {
        let end = self.now + Duration::from_millis(ms);
        while self.now < end {
            self.now += Duration::from_millis(10);
            Protocol::handle_timeout(&mut self.master, self.now);
            self.outstation.handle_timeout(self.now);
            self.settle();
        }
    }

    fn points(&self) -> Vec<Ioa> {
        self.events
            .iter()
            .filter_map(|e| match e {
                Event::Point(p) => Some(p.ioa),
                _ => None,
            })
            .collect()
    }

    fn gi_and_update(&mut self) {
        self.master.start(self.now).unwrap();
        self.run(300);
        assert!(self.master.is_started(), "the link came up: {:?}", self.events);
        self.master.interrogate(CA, Interrogation::STATION, self.now).unwrap();
        self.run(1000);
        let mut points = self.points();
        points.sort_unstable();
        assert_eq!(points, [Ioa(100), Ioa(101), Ioa(200)], "{:?}", self.events);
        assert!(self.events.iter().any(|e| matches!(e, Event::InterrogationComplete { common_address: CA, .. })), "{:?}", self.events);
        self.events.clear();
        self.outstation.update(CA, Ioa(101), true).unwrap();
        self.run(500);
        assert_eq!(self.points(), [Ioa(101)], "{:?}", self.events);
    }
}

#[test]
fn stations_over_an_unbalanced_link() {
    let rtu = LinkAddress(9);
    let config = Config { poll_interval: Duration::from_millis(20), ..Config::default() };
    Pair::new(Cs101Link::primary(&[rtu], config).unwrap(), Cs101Link::secondary(rtu, config).unwrap()).gi_and_update();
}

#[test]
fn stations_over_a_balanced_link() {
    let (a, b) = (LinkAddress(1), LinkAddress(2));
    let config = Config::default();
    Pair::new(Cs101Link::balanced(Role::Controlling, a, b, config).unwrap(), Cs101Link::balanced(Role::Controlled, b, a, config).unwrap()).gi_and_update();
}
