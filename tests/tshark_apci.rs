//! Wireshark as the oracle for the APCI: every frame type the link emits — the six U
//! functions, S-frames and I-frames carrying an ASDU, with sequence numbers at 0, 1, the
//! midpoint and 32767 — is written into a pcap and dissected by `tshark`, which must read
//! back the format, the U function, N(S), N(R) and the length that were encoded, with no
//! malformed or expert-error marker.
//!
//! Skipped with a message when `tshark` is not installed, unless `IEC60870_REQUIRE_TSHARK=1`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
#![allow(clippy::doc_markdown, clippy::too_many_lines, clippy::assert_is_empty, clippy::cast_lossless)]

#[path = "support/tshark.rs"]
mod oracle;

use std::process::Command;

use iec60870::cs104::{Apci, Apdu, Config, Cs104Link, FrameSplitter, Role, SeqNo, UFunction};
use iec60870::driver::Output;
use iec60870::time::Instant;

/// C_IC_NA_1, activation, CA 1, IOA 0, QOI 20 — a general interrogation.
const GI: &[u8] = &[0x64, 0x01, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x14];

fn tshark() -> Option<String> {
    oracle::tshark("APCI oracle")
}

/// A classic pcap: Ethernet / IPv4 / TCP from port 40000 to 2404, one APDU per packet.
fn pcap(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(0xA1B2_C3D4u32.to_le_bytes());
    out.extend(2u16.to_le_bytes());
    out.extend(4u16.to_le_bytes());
    out.extend([0u8; 8]);
    out.extend(65535u32.to_le_bytes());
    out.extend(1u32.to_le_bytes()); // Ethernet
    let mut seq: u32 = 1000;
    for (n, payload) in frames.iter().enumerate() {
        let mut tcp = Vec::new();
        tcp.extend(40000u16.to_be_bytes());
        tcp.extend(2404u16.to_be_bytes());
        tcp.extend(seq.to_be_bytes());
        tcp.extend(1u32.to_be_bytes());
        tcp.extend([0x50, 0x18]); // header 20 octets; PSH, ACK
        tcp.extend(65535u16.to_be_bytes());
        tcp.extend([0, 0, 0, 0]); // checksum (unchecked), urgent
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

/// The frames a real pair of links emits, split back into APDUs: STARTDT, I-frames both
/// ways, S-frames, TESTFR, STOPDT.
fn frames_emitted_by_the_link() -> Vec<Vec<u8>> {
    let config = Config { w: 2, ..Config::default() };
    let mut a = Cs104Link::new(Role::Controlling, config).unwrap();
    let mut b = Cs104Link::new(Role::Controlled, config).unwrap();
    let mut frames = Vec::new();
    let mut pump = |from: &mut Cs104Link, to: &mut Cs104Link, now: Instant| {
        while let Some(out) = from.poll_output() {
            if let Output::Transmit(bytes) = out {
                let mut splitter = FrameSplitter::new();
                let mut input = &bytes[..];
                while let Some(frame) = splitter.next_frame(&mut input) {
                    frames.push(frame.unwrap().to_vec().unwrap());
                }
                to.handle_input(&bytes, now);
            }
        }
    };
    let t = Instant::from_millis;
    a.start(t(0)).unwrap();
    pump(&mut a, &mut b, t(0));
    pump(&mut b, &mut a, t(0));
    a.submit(GI, t(1)).unwrap();
    pump(&mut a, &mut b, t(1));
    for _ in 0..3 {
        b.submit(GI, t(2)).unwrap();
    }
    pump(&mut b, &mut a, t(2));
    pump(&mut a, &mut b, t(2));
    b.handle_timeout(t(30_000)); // t3: TESTFR act
    pump(&mut b, &mut a, t(30_000));
    pump(&mut a, &mut b, t(30_000));
    a.stop(t(30_001)).unwrap();
    pump(&mut a, &mut b, t(30_001));
    pump(&mut b, &mut a, t(30_001));
    frames
}

struct Expect {
    kind: u32,
    utype: Option<u32>,
    tx: Option<u16>,
    rx: Option<u16>,
    len: usize,
}

fn expect(frame: &[u8]) -> Expect {
    let apdu = Apdu::decode(frame).unwrap();
    let len = frame.len() - 2;
    match apdu.apci {
        Apci::I { send, recv } => Expect { kind: 0, utype: None, tx: Some(send.get()), rx: Some(recv.get()), len },
        Apci::S { recv } => Expect { kind: 1, utype: None, tx: None, rx: Some(recv.get()), len },
        // Wireshark `hf_apciutype`: the control octet under mask 0xFC, shifted.
        Apci::U(f) => Expect { kind: 3, utype: Some(u32::from(f.octet() >> 2)), tx: None, rx: None, len },
    }
}

fn hex(field: &str) -> Option<u32> {
    u32::from_str_radix(field.strip_prefix("0x")?, 16).ok()
}

#[test]
fn every_emitted_apci_frame_dissects_as_encoded() {
    let Some(bin) = tshark() else { return };
    let mut frames = frames_emitted_by_the_link();
    // Every U function, and the sequence-number extremes, explicitly.
    for f in [UFunction::StartDtAct, UFunction::StartDtCon, UFunction::StopDtAct, UFunction::StopDtCon, UFunction::TestFrAct, UFunction::TestFrCon] {
        frames.push(Apdu::u(f).to_vec().unwrap());
    }
    for n in [0u16, 1, 16383, 32767] {
        let s = SeqNo::new(n).unwrap();
        frames.push(Apdu::s(s).to_vec().unwrap());
        frames.push(Apdu::i(s, SeqNo::new(32767 - n).unwrap(), GI).to_vec().unwrap());
    }
    let kinds: std::collections::BTreeSet<_> = frames.iter().map(|f| expect(f).kind).collect();
    assert_eq!(kinds.len(), 3, "I, S and U all present");

    let dir = std::env::temp_dir().join(format!("iec60870-tshark-apci-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("apci.pcap");
    std::fs::write(&path, pcap(&frames)).unwrap();
    let out = Command::new(&bin)
        .args([
            "-r",
            path.to_str().unwrap(),
            "-d",
            "tcp.port==2404,iec60870_104",
            "-T",
            "fields",
            "-E",
            "separator=|",
            "-E",
            "occurrence=a",
            "-E",
            "aggregator=,",
        ])
        .args(["-e", "iec60870_104.type", "-e", "iec60870_104.utype", "-e", "iec60870_104.tx", "-e", "iec60870_104.rx", "-e", "iec60870_104.apdulen"])
        .args(["-e", "iec60870_asdu.typeid", "-e", "_ws.malformed", "-e", "_ws.expert.severity"])
        .output()
        .unwrap();
    assert!(out.status.success(), "tshark failed: {}", String::from_utf8_lossy(&out.stderr));
    let text = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), frames.len());
    for (frame, line) in frames.iter().zip(&lines) {
        let e = expect(frame);
        let f: Vec<&str> = line.split('|').collect();
        let context = format!("{frame:02x?} dissected as {line}");
        assert_eq!(hex(f[0]), Some(e.kind), "type: {context}");
        assert_eq!(hex(f[1]), e.utype, "utype: {context}");
        assert_eq!(f[2], e.tx.map(|n| n.to_string()).unwrap_or_default(), "tx: {context}");
        assert_eq!(f[3], e.rx.map(|n| n.to_string()).unwrap_or_default(), "rx: {context}");
        assert_eq!(f[4], e.len.to_string(), "apdulen: {context}");
        if e.kind == 0 {
            assert_eq!(f[5], "100", "the wrapped ASDU dissects as C_IC_NA_1: {context}");
        }
        assert_eq!(f[6], "", "malformed: {context}");
        assert!(f[7].is_empty() || !f[7].split(',').any(|s| s == "8388608" || s == "0x00800000"), "expert error: {context}");
    }
    println!("tshark dissected {} APCI frames as encoded", frames.len());
    let _ = std::fs::remove_dir_all(&dir);
}
