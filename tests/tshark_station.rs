//! Wireshark as the oracle for what the stations put on the wire: every APDU the controlled
//! and the controlling station emit while running each procedure — confirmations positive and
//! negative, COT 44–47 mirrors, interrogation and counter replies, events, end of
//! initialisation, every command type and system command — is dissected by `tshark`, which
//! must read back the type, the cause, P/N, the originator, the common address and the first
//! IOA that the crate's own decoder reads, with no malformed or expert-error marker.
//!
//! Skipped with a message when `tshark` is not installed, unless `IEC60870_REQUIRE_TSHARK=1`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, clippy::cast_possible_truncation)]
#![allow(clippy::assert_is_empty, clippy::too_many_lines, clippy::doc_markdown, clippy::cast_lossless, clippy::cast_precision_loss, clippy::similar_names)]

#[path = "support/tshark.rs"]
mod oracle;

mod station_support;

use std::collections::BTreeSet;
use std::process::Command as Process;
use std::time::Duration;

use iec60870::cs104::{Apci, Apdu, FrameSplitter};
use iec60870::prelude::*;
use iec60870::station::{ClientConfig, GroupId, ServerConfig};
use station_support::{MasterRig, Rig, clock, database};

const CA: CommonAddress = CommonAddress(1);

fn tshark() -> Option<String> {
    oracle::tshark("station oracle")
}

/// A classic pcap: Ethernet / IPv4 / TCP to port 2404, one APDU per packet.
fn pcap(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(0xA1B2_C3D4u32.to_le_bytes());
    out.extend(2u16.to_le_bytes());
    out.extend(4u16.to_le_bytes());
    out.extend([0u8; 8]);
    out.extend(65535u32.to_le_bytes());
    out.extend(1u32.to_le_bytes());
    let mut seq: u32 = 1;
    for (n, payload) in frames.iter().enumerate() {
        let mut tcp = Vec::new();
        tcp.extend(40000u16.to_be_bytes());
        tcp.extend(2404u16.to_be_bytes());
        tcp.extend(seq.to_be_bytes());
        tcp.extend(1u32.to_be_bytes());
        tcp.extend([0x50, 0x18]);
        tcp.extend(65535u16.to_be_bytes());
        tcp.extend([0, 0, 0, 0]);
        tcp.extend(payload);
        seq = seq.wrapping_add(payload.len() as u32);
        let mut ip = vec![0x45, 0];
        ip.extend(((20 + tcp.len()) as u16).to_be_bytes());
        ip.extend([0, n as u8, 0x40, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2]);
        let sum = !ip.chunks(2).fold(0u32, |a, c| a + u32::from(u16::from_be_bytes([c[0], c[1]]))).wrapping_rem(0xFFFF) as u16;
        ip[10..12].copy_from_slice(&sum.to_be_bytes());
        let mut eth = vec![0x02, 0, 0, 0, 0, 2, 0x02, 0, 0, 0, 0, 1, 0x08, 0x00];
        eth.extend(ip);
        eth.extend(tcp);
        out.extend((n as u32).to_le_bytes());
        out.extend(0u32.to_le_bytes());
        out.extend((eth.len() as u32).to_le_bytes());
        out.extend((eth.len() as u32).to_le_bytes());
        out.extend(eth);
    }
    out
}

/// The I-frames of a byte stream, as whole APDUs.
fn i_frames(wire: &[u8]) -> Vec<Vec<u8>> {
    let mut splitter = FrameSplitter::new();
    let mut input = wire;
    let mut frames = Vec::new();
    while let Some(frame) = splitter.next_frame(&mut input) {
        let apdu = frame.unwrap();
        if matches!(apdu.apci, Apci::I { .. }) {
            frames.push(apdu.to_vec().unwrap());
        }
    }
    frames
}

/// Every procedure, from the controlled station's side.
fn outstation_frames() -> Vec<Vec<u8>> {
    let mut rig = Rig::new(database(), ServerConfig::default());
    let m = rig.connect(GroupId(0));
    rig.station.update(CA, Ioa(100), true).unwrap();
    rig.start(m);
    let act = |ioa: u32, o: Objects| Asdu::new(CA, Cot::ACTIVATION.with_originator(3), o).with_ioa_hint(ioa);
    #[cfg(feature = "file-transfer")]
    {
        let mut store = iec60870::station::MemoryFileStore::new();
        store.insert(CA, Ioa(200), iec60870::station::FileName(2), [1]);
        rig.station.set_file_store(store);
        let call = CallSelect { name: 0, section: 0, qualifier: 0 };
        rig.send(m, &Asdu::new(CA, Cot::REQUEST, InformationObject::new(Ioa(0), call)));
        for (qualifier, section) in [(1, 0), (2, 0), (6, 1)] {
            rig.send(m, &Asdu::new(CA, Cot::FILE_TRANSFER, InformationObject::new(Ioa(200), CallSelect { name: 2, section, qualifier })));
        }
        rig.send(m, &Asdu::new(CA, Cot::FILE_TRANSFER, InformationObject::new(Ioa(200), FileAck { name: 2, section: 1, qualifier: 3 })));
    }
    let t = clock();
    let asdus = [
        act(0, InformationObject::new(Ioa(0), Interrogation::STATION).into()),
        act(0, InformationObject::new(Ioa(0), Interrogation::group(2).unwrap()).into()),
        act(0, InformationObject::new(Ioa(0), CounterInterrogation::GENERAL).into()),
        act(5000, InformationObject::new(Ioa(5000), SingleCommand::new(true).select()).into()),
        act(5000, InformationObject::new(Ioa(5000), SingleCommand::new(true)).into()),
        act(5000, InformationObject::new(Ioa(5000), SingleCommand::new(true)).into()),
        act(5001, InformationObject::new(Ioa(5001), DoubleCommand::on()).at(t).into()),
        act(5002, InformationObject::new(Ioa(5002), SetpointFloat::new(2.5)).into()),
        act(5003, InformationObject::new(Ioa(5003), BitstringCommand(1)).into()),
        act(0, InformationObject::new(Ioa(0), ClockSync).at(t).into()),
        act(0, InformationObject::new(Ioa(0), TestCounter(7)).at(t).into()),
        act(0, InformationObject::new(Ioa(0), ResetProcess::GENERAL).into()),
        act(200, InformationObject::new(Ioa(200), ParameterFloat { value: 1.0, qualifier: ParameterQualifier::THRESHOLD }).into()),
        act(0, InformationObject::new(Ioa(0), ParameterActivation::LOADED_PARAMETERS).into()),
        Asdu::new(CA, Cot::REQUEST, InformationObject::new(Ioa(200), Read)),
        Asdu::new(CA, Cot::REQUEST, InformationObject::new(Ioa(9999), Read)),
        Asdu::new(CommonAddress(7), Cot::ACTIVATION, InformationObject::new(Ioa(5000), SingleCommand::new(true))),
        Asdu::new(CA, Cot::SPONTANEOUS, InformationObject::new(Ioa(5000), SingleCommand::new(true))),
        Asdu::new(CA, Cot::SPONTANEOUS, InformationObject::new(Ioa(1), SinglePoint::new(true))),
    ];
    for a in &asdus {
        rig.send(m, a);
    }
    rig.station.update(CA, Ioa(200), 3.0f32).unwrap();
    rig.station.update(CA, Ioa(201), 9i16).unwrap();
    rig.station.update(CA, Ioa(101), DoublePointValue::On).unwrap();
    rig.tick();
    rig.advance(Duration::from_secs(1));
    i_frames(&rig.wire)
}

/// Every procedure, from the controlling station's side.
fn master_frames() -> Vec<Vec<u8>> {
    let mut r = MasterRig::new(ClientConfig { originator: 5, time_tagged_commands: false, ..ClientConfig::default() });
    let now = r.now;
    #[cfg(feature = "file-transfer")]
    r.master.directory(CA, now).unwrap();
    r.master.interrogate(CA, Interrogation::STATION, now).unwrap();
    r.master.counter_interrogate(CA, CounterInterrogation::GENERAL.with_freeze(CounterInterrogation::FREEZE), now).unwrap();
    r.master.read(CA, Ioa(200), now).unwrap();
    r.master.clock_sync(CA, now).unwrap();
    r.master.test_command(CA, now).unwrap();
    r.master.reset_process(CA, ResetProcess::GENERAL, now).unwrap();
    r.master.parameter(CA, Ioa(200), ParameterScaled { value: 4, qualifier: ParameterQualifier::SMOOTHING }, now).unwrap();
    for (ioa, c) in [
        (1, Command::single(true)),
        (2, Command::double(DoublePointValue::Off)),
        (3, Command::step(StepDirection::Higher)),
        (4, Command::setpoint_normalized(Normalized(100))),
        (5, Command::setpoint_scaled(-5)),
        (6, Command::setpoint_float(0.25)),
        (7, Command::bitstring(0xFF)),
    ] {
        r.master.command(CA, Ioa(ioa), c, now).unwrap();
        r.master.select_and_execute(CA, Ioa(ioa + 100), c, now).ok();
    }
    r.pump();
    let mut timed = MasterRig::new(ClientConfig { time_tagged_commands: true, ..ClientConfig::default() });
    for (ioa, c) in [
        (1, Command::single(true)),
        (2, Command::double(DoublePointValue::On)),
        (3, Command::step(StepDirection::Lower)),
        (6, Command::setpoint_float(9.0)),
        (7, Command::bitstring(3)),
    ] {
        timed.master.command(CA, Ioa(ioa), c, timed.now).unwrap();
    }
    timed.pump();
    let mut frames = i_frames(&r.wire);
    #[cfg(feature = "file-transfer")]
    {
        let mut file = MasterRig::new(ClientConfig::default());
        file.master.download(CA, Ioa(200), 2, file.now).unwrap();
        file.reply(&Asdu::new(CA, Cot::FILE_TRANSFER, InformationObject::new(Ioa(200), FileReady { name: 2, length: 0, qualifier: 0 })));
        file.reply(&Asdu::new(CA, Cot::FILE_TRANSFER, InformationObject::new(Ioa(200), LastSection { name: 2, section: 0, qualifier: 1, checksum: 0 })));
        frames.extend(i_frames(&file.wire));
    }
    frames.extend(i_frames(&timed.wire));
    frames
}

trait IoaHint {
    fn with_ioa_hint(self, ioa: u32) -> Self;
}

impl IoaHint for Asdu {
    fn with_ioa_hint(self, ioa: u32) -> Self {
        assert_eq!(self.objects.ioa(0), Some(Ioa(ioa)));
        self
    }
}

#[test]
fn every_station_apdu_dissects_as_decoded() {
    let mut frames = outstation_frames();
    let from_outstation = frames.len();
    frames.extend(master_frames());
    let types: BTreeSet<u8> = frames.iter().map(|f| Asdu::decode(&f[6..], &Profile::IEC104).unwrap().type_id().0).collect();
    let causes: BTreeSet<(u8, bool)> =
        frames.iter().map(|f| Asdu::decode(&f[6..], &Profile::IEC104).unwrap().cot).map(|c| (c.cause.value(), c.negative)).collect();
    // The coverage this test claims.
    for t in [1, 3, 13, 11, 15, 30, 31, 35, 36, 45, 46, 47, 48, 49, 50, 51, 58, 59, 60, 63, 64, 70, 100, 101, 102, 103, 107, 105, 111, 112, 113] {
        assert!(types.contains(&t), "type {t} is not exercised: {types:?}");
    }
    #[cfg(feature = "file-transfer")]
    assert!((120..=126).all(|t| types.contains(&t)));
    for c in [
        (3, false),
        (4, false),
        (5, false),
        (6, false),
        (7, false),
        (7, true),
        (10, false),
        (20, false),
        (22, false),
        (37, false),
        (44, true),
        (46, true),
        (47, true),
    ] {
        assert!(causes.contains(&c), "cause {c:?} is not exercised: {causes:?}");
    }
    let Some(bin) = tshark() else { return };
    let dir = std::env::temp_dir().join(format!("iec60870-tshark-station-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("station.pcap");
    std::fs::write(&path, pcap(&frames)).unwrap();
    let out = Process::new(&bin)
        .args(["-r", path.to_str().unwrap(), "-d", "tcp.port==2404,iec60870_104", "-T", "fields", "-E", "separator=|", "-E", "occurrence=f"])
        .args(["-e", "iec60870_104.type", "-e", "iec60870_asdu.typeid", "-e", "iec60870_asdu.causetx", "-e", "iec60870_asdu.nega"])
        .args(["-e", "iec60870_asdu.oa", "-e", "iec60870_asdu.addr", "-e", "iec60870_asdu.numix", "-e", "iec60870_asdu.ioa"])
        .args(["-e", "_ws.malformed", "-e", "_ws.expert.severity"])
        .output()
        .unwrap();
    assert!(out.status.success(), "tshark failed: {}", String::from_utf8_lossy(&out.stderr));
    let text = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), frames.len());
    for (frame, line) in frames.iter().zip(&lines) {
        let asdu = Asdu::decode(Apdu::decode(frame).unwrap().asdu, &Profile::IEC104).unwrap();
        let f: Vec<&str> = line.split('|').collect();
        let context = format!("{asdu} dissected as {line}");
        assert_eq!(u32::from_str_radix(f[0].trim_start_matches("0x"), 16).ok(), Some(0), "I-frame: {context}");
        assert_eq!(f[1], asdu.type_id().0.to_string(), "type: {context}");
        assert_eq!(f[2], asdu.cot.cause.value().to_string(), "cause: {context}");
        assert!(matches!((f[3], asdu.cot.negative), ("True" | "1", true) | ("False" | "0", false)), "P/N: {context}");
        assert_eq!(f[4], asdu.cot.originator.to_string(), "originator: {context}");
        assert_eq!(f[5], asdu.common_address.0.to_string(), "CA: {context}");
        assert_eq!(f[6], asdu.len().to_string(), "count: {context}");
        assert_eq!(f[7], asdu.objects.ioa(0).unwrap().0.to_string(), "first IOA: {context}");
        assert_eq!(f[8], "", "malformed: {context}");
        assert!(f[9].is_empty() || !f[9].split(',').any(|s| s == "8388608" || s == "0x00800000"), "expert error: {context}");
    }
    println!(
        "tshark dissected {} station APDUs ({from_outstation} from the controlled station, {} from the controlling station) as decoded: {} types, {} causes",
        frames.len(),
        frames.len() - from_outstation,
        types.len(),
        causes.len()
    );
    let _ = std::fs::remove_dir_all(&dir);
}
