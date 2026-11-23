//! A sans-IO rig for the station tests: a controlled station with raw master links, and a
//! controlling station with a raw outstation link, moved by hand on virtual time.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

use std::time::Duration;

use iec60870::cs104::{Config, Cs104Link, Role};
use iec60870::driver::{Output, Protocol};
use iec60870::prelude::*;
use iec60870::station::{
    self, ClientConfig, CommandHandler, ConnectionId, ControlledStation, ControllingStation, Database, Decision, GroupId, ParameterRequest, ServerConfig,
    ServerEvent,
};

pub const BASE_MS: u64 = 1_795_000_000_000;

pub fn clock() -> Cp56Time2a {
    Cp56Time2a::from_unix_millis(BASE_MS).unwrap()
}

/// What the handler was asked, and what it answers.
#[derive(Default)]
pub struct Recorder {
    pub selects: Vec<CommandRequest>,
    pub executes: Vec<CommandRequest>,
    pub cancels: Vec<CommandRequest>,
    pub clock_syncs: Vec<Cp56Time2a>,
    pub resets: Vec<ResetProcess>,
    pub counters: Vec<CounterInterrogation>,
    pub parameters: Vec<ParameterRequest>,
    pub refuse: bool,
}

impl CommandHandler for Recorder {
    fn execute(&mut self, r: &CommandRequest) -> Decision {
        self.executes.push(*r);
        Decision::from(!self.refuse)
    }
    fn select(&mut self, r: &CommandRequest) -> Decision {
        self.selects.push(*r);
        Decision::from(!self.refuse)
    }
    fn cancel(&mut self, r: &CommandRequest) {
        self.cancels.push(*r);
    }
    fn clock_sync(&mut self, t: Cp56Time2a) -> Decision {
        self.clock_syncs.push(t);
        Decision::from(!self.refuse)
    }
    fn reset_process(&mut self, _: CommonAddress, q: ResetProcess) -> Decision {
        self.resets.push(q);
        Decision::from(!self.refuse)
    }
    fn counter_interrogation(&mut self, _: CommonAddress, q: CounterInterrogation) -> Decision {
        self.counters.push(q);
        Decision::from(!self.refuse)
    }
    fn parameter(&mut self, r: &ParameterRequest) -> Decision {
        self.parameters.push(*r);
        Decision::from(!self.refuse)
    }
}

pub struct Master {
    pub id: ConnectionId,
    pub link: Cs104Link,
    pub received: Vec<Asdu>,
    pub started: bool,
    pub closed: bool,
}

/// An outstation and its masters.
pub struct Rig {
    pub station: ControlledStation<Cs104Link>,
    pub masters: Vec<Master>,
    pub handler: Recorder,
    pub events: Vec<ServerEvent>,
    pub now: Instant,
    pub profile: Profile,
    /// Every octet the station transmitted, in order.
    pub wire: Vec<u8>,
}

pub fn database() -> Database {
    let ca = CommonAddress(1);
    let mut db = Database::new();
    let _ = db.insert(ca, Ioa(100), false);
    let _ = db.insert(ca, Ioa(101), DoublePointValue::Off).group(2);
    let _ = db.insert(ca, Ioa(200), 21.5f32).group(2);
    let _ = db.insert(ca, Ioa(201), 7i16);
    let _ = db.insert(ca, Ioa(300), BinaryCounterReading::new(1000)).counter_group(1);
    let _ = db.insert(ca, Ioa(301), BinaryCounterReading::new(2000)).counter_group(2);
    let _ = db.command(ca, Ioa(5000), CommandKind::Single);
    let _ = db.command(ca, Ioa(5001), CommandKind::Double).mode(CommandMode::Direct);
    let _ = db.command(ca, Ioa(5002), CommandKind::Float).mode(CommandMode::DirectOrSelect);
    let _ = db.command(ca, Ioa(5003), CommandKind::Bitstring);
    db
}

impl Rig {
    pub fn new(db: impl PointSource + 'static, config: ServerConfig) -> Rig {
        Rig {
            station: ControlledStation::new(db, config, clock),
            masters: Vec::new(),
            handler: Recorder::default(),
            events: Vec::new(),
            now: Instant::ZERO,
            profile: config.profile,
            wire: Vec::new(),
        }
    }

    pub fn default_rig() -> Rig {
        Rig::new(database(), ServerConfig { end_of_initialization: None, ..ServerConfig::default() })
    }

    /// A new master connection in `group`; returns its index.
    pub fn connect(&mut self, group: GroupId) -> usize {
        self.connect_with(group, Config::default())
    }

    /// A master connection whose outstation-side link has `config` (the master's is default).
    pub fn connect_with(&mut self, group: GroupId, config: Config) -> usize {
        let id = self.station.attach(Cs104Link::new(Role::Controlled, config).unwrap(), group);
        self.masters.push(Master { id, link: Cs104Link::controlling(), received: Vec::new(), started: false, closed: false });
        self.pump();
        self.masters.len() - 1
    }

    pub fn start(&mut self, m: usize) {
        self.masters[m].link.start(self.now).unwrap();
        self.pump();
        assert!(self.masters[m].started, "master {m} did not start");
    }

    /// Moves every octet until nothing moves.
    pub fn pump(&mut self) {
        loop {
            let mut moved = false;
            for m in 0..self.masters.len() {
                while let Some(o) = self.masters[m].link.poll_output() {
                    match o {
                        Output::Transmit(bytes) => {
                            moved = true;
                            let id = self.masters[m].id;
                            self.station.handle_input(id, &bytes, self.now, &mut self.handler);
                        }
                        Output::Event(iec60870::cs104::Event::Asdu(a)) => self.masters[m].received.push(Asdu::decode(&a, &self.profile).unwrap()),
                        Output::Event(iec60870::cs104::Event::Started) => self.masters[m].started = true,
                        Output::Event(iec60870::cs104::Event::Closed(_)) => self.masters[m].closed = true,
                        _ => {}
                    }
                }
            }
            while let Some(o) = self.station.poll_output() {
                match o {
                    station::Output::Transmit { connection, bytes } => {
                        moved = true;
                        self.wire.extend(&bytes);
                        if let Some(m) = self.masters.iter_mut().find(|m| m.id == connection) {
                            m.link.handle_input(&bytes, self.now);
                        }
                    }
                    station::Output::Event(e) => {
                        if let ServerEvent::Disconnected { connection, .. } = &e
                            && let Some(m) = self.masters.iter_mut().find(|m| m.id == *connection)
                        {
                            m.link.handle_disconnect(self.now);
                        }
                        self.events.push(e);
                    }
                    station::Output::Deadline(_) => {}
                }
            }
            if !moved {
                return;
            }
        }
    }

    /// Advances virtual time and runs every timer.
    pub fn advance(&mut self, d: Duration) {
        self.now += d;
        for m in &mut self.masters {
            m.link.handle_timeout(self.now);
        }
        self.station.handle_timeout(self.now);
        self.pump();
    }

    /// Flushes updates without moving time.
    pub fn tick(&mut self) {
        self.station.handle_timeout(self.now);
        self.pump();
    }

    pub fn send(&mut self, m: usize, asdu: &Asdu) {
        let bytes = asdu.to_vec(&self.profile).unwrap();
        self.masters[m].link.submit(&bytes, self.now).unwrap();
        self.pump();
    }

    pub fn send_bytes(&mut self, m: usize, bytes: &[u8]) {
        self.masters[m].link.submit(bytes, self.now).unwrap();
        self.pump();
    }

    pub fn take(&mut self, m: usize) -> Vec<Asdu> {
        std::mem::take(&mut self.masters[m].received)
    }

    pub fn causes(&mut self, m: usize) -> Vec<(TypeId, u8, bool)> {
        self.take(m).iter().map(|a| (a.type_id(), a.cot.cause.value(), a.cot.negative)).collect()
    }
}

/// Every point of the ASDUs.
pub fn points(asdus: &[Asdu]) -> Vec<Point> {
    asdus.iter().filter_map(Point::from_asdu).flatten().collect()
}

/// A controlling station against a raw outstation link.
pub struct MasterRig {
    pub master: ControllingStation<Cs104Link>,
    pub outstation: Cs104Link,
    pub received: Vec<Asdu>,
    pub events: Vec<Event>,
    pub now: Instant,
    /// Every octet the controlling station transmitted, in order.
    pub wire: Vec<u8>,
}

impl MasterRig {
    pub fn new(config: ClientConfig) -> MasterRig {
        let mut rig = MasterRig {
            master: ControllingStation::new(Cs104Link::controlling(), config, clock),
            outstation: Cs104Link::controlled(),
            received: Vec::new(),
            events: Vec::new(),
            now: Instant::ZERO,
            wire: Vec::new(),
        };
        rig.master.start(rig.now).unwrap();
        rig.pump();
        assert!(rig.master.is_started());
        rig.events.clear();
        rig
    }

    pub fn pump(&mut self) {
        loop {
            let mut moved = false;
            while let Some(o) = self.master.poll_output() {
                match o {
                    Output::Transmit(b) => {
                        moved = true;
                        self.wire.extend(&b);
                        self.outstation.handle_input(&b, self.now);
                    }
                    Output::Event(e) => self.events.push(e),
                    Output::Deadline(_) => {}
                }
            }
            while let Some(o) = self.outstation.poll_output() {
                match o {
                    Output::Transmit(b) => {
                        moved = true;
                        self.master.handle_input(&b, self.now);
                    }
                    Output::Event(iec60870::cs104::Event::Asdu(a)) => self.received.push(Asdu::decode(&a, &Profile::IEC104).unwrap()),
                    _ => {}
                }
            }
            if !moved {
                return;
            }
        }
    }

    /// The outstation answers.
    pub fn reply(&mut self, asdu: &Asdu) {
        self.outstation.submit(&asdu.to_vec(&Profile::IEC104).unwrap(), self.now).unwrap();
        self.pump();
    }

    /// The last request the outstation received, mirrored with `cause` (and P/N).
    pub fn mirror(&mut self, cause: Cause, negative: bool) {
        let mut a = self.received.last().cloned().expect("a request");
        a.cot = Cot { cause, negative, ..a.cot };
        self.reply(&a);
    }

    pub fn advance(&mut self, d: Duration) {
        self.now += d;
        self.outstation.handle_timeout(self.now);
        self.pump();
        self.master.handle_timeout(self.now);
        self.pump();
    }

    /// The progress events of `id`.
    pub fn progress(&self, id: station::RequestId) -> Vec<String> {
        self.events
            .iter()
            .filter_map(|e| match e {
                Event::Request { id: r, progress } if *r == id => Some(match progress {
                    Progress::Failed(e) => format!("Failed({e})"),
                    p => format!("{p:?}"),
                }),
                _ => None,
            })
            .collect()
    }
}
