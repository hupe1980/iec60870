//! Wireshark as a partial oracle for FT 1.2.
//!
//! Wireshark dissects FT 1.2 only through *Decode As* on a TCP port, with the address width as
//! a preference; it shows the checksum octet without verifying it and does not decode DIR or
//! ACD. So this oracle checks the layout — start octets, L, the control field with PRM,
//! FCB/FCV or DFC and the function code, the link address, the stop character, the ASDU type
//! behind it — and compares the checksum octet with an independent sum; the link's behaviour
//! is the interop suite's and the simulation's to prove.
//!
//! Frames: everything a primary, two secondaries and a balanced pair emit in a short run, plus
//! every function code in both directions with every flag combination, under one- and
//! two-octet addresses.
//!
//! Skipped with a message when `tshark` is not installed, unless `IEC60870_REQUIRE_TSHARK=1`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
#![allow(clippy::doc_markdown, clippy::cast_lossless, clippy::cast_possible_truncation)]

#[path = "support/tshark.rs"]
mod oracle;

use std::process::Command;

use iec60870::cs101::{AddressWidth, Class, Config, Control, Cs101Link, Frame, LinkAddress, PrimaryFunction, Role, SecondaryFunction};
use iec60870::driver::Output;
use iec60870::time::Instant;

fn tshark() -> Option<String> {
    oracle::tshark("FT 1.2 oracle")
}

/// A classic pcap: Ethernet / IPv4 / TCP from port 40000 to 2404, one frame per packet.
fn pcap(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(0xA1B2_C3D4u32.to_le_bytes());
    out.extend(2u16.to_le_bytes());
    out.extend(4u16.to_le_bytes());
    out.extend([0u8; 8]);
    out.extend(65535u32.to_le_bytes());
    out.extend(1u32.to_le_bytes());
    let mut seq: u32 = 1000;
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
        let mut sum: u32 = ip.chunks(2).map(|c| u32::from(u16::from_be_bytes([c[0], c[1]]))).sum();
        sum = (sum & 0xFFFF) + (sum >> 16);
        ip[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
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

const FIELDS: [&str; 14] = [
    "iec60870_101.header",
    "iec60870_101.ctrlfield",
    "iec60870_101.ctrl_prm",
    "iec60870_101.ctrl_fcb",
    "iec60870_101.ctrl_fcv",
    "iec60870_101.ctrl_dfc",
    "iec60870_101.ctrl_func_pri_to_sec",
    "iec60870_101.ctrl_func_sec_to_pri",
    "iec60870_101.linkaddr",
    "iec60870_101.length",
    "iec60870_101.checksum",
    "iec60870_101.stopchar",
    "iec60870_asdu.typeid",
    "_ws.malformed",
];

fn dissect(bin: &str, frames: &[Vec<u8>], width: AddressWidth) -> Vec<Vec<String>> {
    let dir = std::env::temp_dir().join(format!("iec60870-ft12-{}-{}", std::process::id(), width.octets()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("ft12.pcap");
    std::fs::write(&path, pcap(frames)).unwrap();
    let mut cmd = Command::new(bin);
    cmd.arg("-r").arg(&path).args(["-d", "tcp.port==2404,iec60870_101", "-o", &format!("iec60870_101.linkaddr_len:{}", width.octets())]);
    cmd.args(["-T", "fields", "-E", "separator=|", "-E", "occurrence=a", "-E", "aggregator=,"]);
    for f in FIELDS {
        cmd.args(["-e", f]);
    }
    cmd.args(["-e", "_ws.expert.severity"]);
    let out = cmd.output().unwrap();
    assert!(out.status.success(), "tshark failed: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).unwrap().lines().map(|l| l.split('|').map(str::to_owned).collect()).collect()
}

fn hex(v: u8) -> String {
    format!("{v:#04x}")
}

fn bit(b: bool) -> String {
    u8::from(b).to_string()
}

fn check(frame_octets: &[u8], row: &[String], width: AddressWidth) {
    let frame = Frame::decode(frame_octets, width).unwrap();
    let field = |name: &str| row[FIELDS.iter().position(|f| *f == name).unwrap()].as_str();
    assert_eq!(field("_ws.malformed"), "", "{frame_octets:02x?} malformed");
    assert!(row[FIELDS.len()].is_empty() || !row[FIELDS.len()].contains("error"), "{frame_octets:02x?}: expert {}", row[FIELDS.len()]);
    let (control, address, data) = match frame {
        Frame::SingleChar => {
            assert_eq!(field("iec60870_101.header"), "0xe5");
            return;
        }
        Frame::Fixed { control, address } => {
            assert_eq!(field("iec60870_101.header"), "0x10");
            (control, address, &[][..])
        }
        Frame::Variable { control, address, user_data } => {
            assert_eq!(field("iec60870_101.header"), "0x68,0x68");
            assert_eq!(field("iec60870_101.length"), (1 + width.octets() + user_data.len()).to_string());
            (control, address, user_data)
        }
    };
    assert_eq!(field("iec60870_101.ctrlfield"), hex(control.octet()), "{frame_octets:02x?}");
    match control {
        Control::Primary { fcb, fcv, function, .. } => {
            assert_eq!(field("iec60870_101.ctrl_prm"), "1");
            assert_eq!(field("iec60870_101.ctrl_fcb"), bit(fcb));
            assert_eq!(field("iec60870_101.ctrl_fcv"), bit(fcv));
            assert_eq!(field("iec60870_101.ctrl_func_pri_to_sec"), function.code().to_string());
        }
        Control::Secondary { dfc, function, .. } => {
            assert_eq!(field("iec60870_101.ctrl_prm"), "0");
            assert_eq!(field("iec60870_101.ctrl_dfc"), bit(dfc));
            assert_eq!(field("iec60870_101.ctrl_func_sec_to_pri"), function.code().to_string());
        }
    }
    assert_eq!(field("iec60870_101.linkaddr"), address.0.to_string());
    // Wireshark shows the checksum octet without checking it: compare with our own sum.
    let sum = data.iter().chain(&address.0.to_le_bytes()[..width.octets()]).fold(control.octet(), |s, b| s.wrapping_add(*b));
    assert_eq!(field("iec60870_101.checksum"), hex(sum));
    assert_eq!(field("iec60870_101.stopchar"), "0x16");
    if let Some(&type_id) = data.first() {
        assert_eq!(field("iec60870_asdu.typeid"), type_id.to_string());
    }
}

fn drain(link: &mut Cs101Link, frames: &mut Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut sent = Vec::new();
    while let Some(o) = link.poll_output() {
        if let Output::Transmit(b) = o {
            frames.push(b.clone());
            sent.push(b);
        }
    }
    sent
}

/// Everything the links emit in a short run.
fn emitted(width: AddressWidth) -> Vec<Vec<u8>> {
    let config = Config { address_width: width, ..Config::default() };
    let (a, b) = (LinkAddress(width.max().min(0x0102) - 1), LinkAddress(2));
    let mut frames = Vec::new();
    let mut links = [
        Cs101Link::primary(&[a, b], config).unwrap(),
        Cs101Link::secondary(a, Config { single_char_ack: false, ..config }).unwrap(),
        Cs101Link::secondary(b, config).unwrap(),
    ];
    links[1].submit(&[0x0D, 0x01, 0x03, 0x01, 0x10, 0x00, 0, 0, 0x80, 0x3F, 0], Class::One, Instant::ZERO).unwrap();
    links[2].submit(&[0x01, 0x01, 0x14, 0x02, 0x01, 0x00, 0x01], Class::Two, Instant::ZERO).unwrap();
    links[0].submit_to(a, &[0x2D, 0x01, 0x06, 0x01, 0x05, 0x00, 0x81], Class::One, Instant::ZERO).unwrap();
    let mut balanced = [Cs101Link::balanced(Role::Controlling, a, b, config).unwrap(), Cs101Link::balanced(Role::Controlled, b, a, config).unwrap()];
    balanced[1].submit(&[0x01, 0x01, 0x03, 0x01, 0x01, 0x00, 0x00], Class::One, Instant::ZERO).unwrap();
    for ms in (0..400).step_by(10) {
        let now = Instant::from_millis(ms);
        for l in links.iter_mut().chain(balanced.iter_mut()) {
            l.handle_timeout(now);
        }
        for _ in 0..8 {
            for i in 0..3 {
                for f in drain(&mut links[i], &mut frames) {
                    for j in (0..3).filter(|&j| j != i) {
                        links[j].handle_input(&f, now);
                    }
                }
            }
            for i in 0..2 {
                for f in drain(&mut balanced[i], &mut frames) {
                    balanced[1 - i].handle_input(&f, now);
                }
            }
        }
    }
    frames
}

/// Every function code, both directions, every flag combination.
fn synthesized(width: AddressWidth) -> Vec<Vec<u8>> {
    let address = LinkAddress(width.max().min(0x1234) - 1);
    let mut frames = Vec::new();
    for octet in 0..=255u8 {
        let control = Control::from_octet(octet);
        let skip = match control {
            Control::Primary { function, .. } => matches!(function, PrimaryFunction::Reserved(_)),
            Control::Secondary { function, .. } => matches!(function, SecondaryFunction::Reserved(_)),
        };
        if skip {
            continue;
        }
        frames.push(Frame::Fixed { control, address }.to_vec(width).unwrap());
        frames.push(Frame::Variable { control, address, user_data: &[0x01, 0x01, 0x03, 0x01, 0x01, 0x00, 0x01] }.to_vec(width).unwrap());
    }
    frames.push(Frame::SingleChar.to_vec(width).unwrap());
    frames
}

#[test]
fn every_emitted_frame_dissects_as_what_was_put_in() {
    let Some(bin) = tshark() else { return };
    let mut checked = 0;
    for width in [AddressWidth::One, AddressWidth::Two] {
        let mut frames = emitted(width);
        let emitted_count = frames.len();
        assert!(emitted_count > 20, "the run emitted {emitted_count} frames");
        frames.extend(synthesized(width));
        let rows = dissect(&bin, &frames, width);
        assert_eq!(rows.len(), frames.len());
        for (frame, row) in frames.iter().zip(&rows) {
            check(frame, row, width);
            checked += 1;
        }
    }
    println!("{checked} FT 1.2 frames dissected as encoded");
}
