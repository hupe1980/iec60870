//! Wireshark as the oracle: every type identification the 104 profile permits and the crate
//! encodes, with values drawn from each element's full range, in both the SQ = 0 and SQ = 1
//! forms, is framed in an APCI I-frame, written to a pcap, and dissected by `tshark`. Every
//! field Wireshark shows must equal the value that was put in, and there must be no malformed
//! packet and no expert note from the IEC 60870-5 dissectors.
//!
//! Skips with a message when `tshark` is not installed, unless `IEC60870_REQUIRE_TSHARK=1` or
//! `IEC60870_REQUIRE_FIELD_COVERAGE=1`. The latter also requires per-object fields for typed payloads.

#![allow(
    clippy::pedantic,
    clippy::complexity,
    clippy::manual_is_multiple_of,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines
)]

#[path = "support/tshark.rs"]
mod oracle;

mod common;

use std::process::Command;

use iec60870::prelude::*;
use proptest::strategy::{Strategy, ValueTree};
use proptest::test_runner::TestRunner;
use serde_json::Value;

const SAMPLES_PER_FORM: usize = 4;

// ---------------------------------------------------------------------------------------------
// The pcap, written by hand: Ethernet II / IPv4 / TCP to port 2404 / APCI I-frame / ASDU.
// ---------------------------------------------------------------------------------------------

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = header.chunks(2).map(|c| u32::from(u16::from_be_bytes([c[0], c[1]]))).sum();
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn pcap(asdus: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    // Global header: magic, version 2.4, zone 0, sigfigs 0, snaplen 65535, LINKTYPE_ETHERNET.
    out.extend_from_slice(&0xA1B2_C3D4u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&[0; 8]);
    out.extend_from_slice(&65_535u32.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    let mut seq: u32 = 1;
    for (i, asdu) in asdus.iter().enumerate() {
        // APCI: start, length, I-format control field with N(S) = i, N(R) = 0.
        let ns = ((i % 0x8000) as u16) << 1;
        let mut apdu = vec![0x68, (asdu.len() + 4) as u8];
        apdu.extend_from_slice(&ns.to_le_bytes());
        apdu.extend_from_slice(&[0, 0]);
        apdu.extend_from_slice(asdu);

        let mut tcp = Vec::new();
        tcp.extend_from_slice(&40_000u16.to_be_bytes());
        tcp.extend_from_slice(&2404u16.to_be_bytes());
        tcp.extend_from_slice(&seq.to_be_bytes());
        tcp.extend_from_slice(&1u32.to_be_bytes());
        tcp.extend_from_slice(&[0x50, 0x18]); // data offset 5, PSH|ACK
        tcp.extend_from_slice(&65_535u16.to_be_bytes());
        tcp.extend_from_slice(&[0, 0, 0, 0]); // checksum (not validated by default), urgent
        seq = seq.wrapping_add(apdu.len() as u32);

        let total = (20 + tcp.len() + apdu.len()) as u16;
        let mut ip = vec![0x45, 0];
        ip.extend_from_slice(&total.to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0x40, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2]);
        let sum = ipv4_checksum(&ip);
        ip[10..12].copy_from_slice(&sum.to_be_bytes());

        let mut frame = vec![0x02, 0, 0, 0, 0, 0x02, 0x02, 0, 0, 0, 0, 0x01, 0x08, 0x00];
        frame.extend_from_slice(&ip);
        frame.extend_from_slice(&tcp);
        frame.extend_from_slice(&apdu);

        out.extend_from_slice(&(i as u32).to_le_bytes()); // seconds
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        out.extend_from_slice(&frame);
    }
    out
}

// ---------------------------------------------------------------------------------------------
// What Wireshark must show, per information object.
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Want {
    Exact(String),
    Float(f64),
}

struct Expect {
    ioa: u32,
    fields: Vec<(Vec<String>, Want)>,
}

impl Expect {
    fn new(ioa: Ioa) -> Self {
        Self { ioa: ioa.0, fields: Vec::new() }
    }
    fn at(&mut self, path: &[&str], want: Want) -> &mut Self {
        self.fields.push((path.iter().map(|p| format!("iec60870_asdu.{p}")).collect(), want));
        self
    }
    fn eq(&mut self, path: &[&str], v: impl ToString) -> &mut Self {
        self.at(path, Want::Exact(v.to_string()))
    }
    fn hex8(&mut self, path: &[&str], v: u8) -> &mut Self {
        self.eq(path, format!("{v:#04x}"))
    }
    fn flag(&mut self, path: &[&str], on: bool) -> &mut Self {
        self.eq(path, u8::from(on))
    }
    fn float(&mut self, path: &[&str], v: f32) -> &mut Self {
        self.at(path, Want::Float(f64::from(v)))
    }

    fn qds(&mut self, q: Quality) -> &mut Self {
        let b = q.bits();
        self.hex8(&["qds"], b);
        for (name, bit) in [("ov", 0x01), ("bl", 0x10), ("sb", 0x20), ("nt", 0x40), ("iv", 0x80)] {
            self.flag(&["qds_tree", &format!("qds.{name}")], b & bit != 0);
        }
        self
    }
    fn quality_bits(&mut self, tree: &str, b: u8) -> &mut Self {
        for (name, bit) in [("bl", 0x10), ("sb", 0x20), ("nt", 0x40), ("iv", 0x80)] {
            self.flag(&[&format!("{tree}_tree"), &format!("{tree}.{name}")], b & bit != 0);
        }
        self
    }
    fn qdp(&mut self, q: ProtectionQuality) -> &mut Self {
        let b = q.bits();
        self.hex8(&["qdp"], b).flag(&["qdp_tree", "qdp.ei"], b & 0x08 != 0).quality_bits("qdp", b)
    }
    fn cp16(&mut self, t: Cp16Time2a) -> &mut Self {
        self.eq(&["cp16time"], t.milliseconds())
    }
    fn cp56_as(&mut self, tree: &str, t: Cp56Time2a) -> &mut Self {
        let tree = format!("{tree}_tree");
        let f = |s: &str| format!("cp56time.{s}");
        self.eq(&[&tree, &f("ms")], t.milliseconds())
            .eq(&[&tree, &f("min")], t.minute())
            .flag(&[&tree, &f("gen")], t.is_substituted())
            .flag(&[&tree, &f("iv")], t.is_invalid())
            .eq(&[&tree, &f("hour")], t.hour())
            .flag(&[&tree, &f("su")], t.is_summer_time())
            .eq(&[&tree, &f("day")], t.day())
            .eq(&[&tree, &f("dow")], t.weekday())
            .eq(&[&tree, &f("month")], t.month())
            .eq(&[&tree, &f("year")], t.year())
    }
    fn cp56(&mut self, t: Cp56Time2a) -> &mut Self {
        self.cp56_as("cp56time", t)
    }
    fn normalized(&mut self, v: Normalized) -> &mut Self {
        self.float(&["normval"], v.to_f32())
    }
    fn command(&mut self, name: &str, bits: u8, state: &str, state_value: u8) -> &mut Self {
        let tree = format!("{name}_tree");
        self.hex8(&[name], bits)
            .eq(&[&tree, &format!("{name}.{state}")], state_value)
            .eq(&[&tree, &format!("{name}.qu")], (bits & 0x7C) >> 2)
            .flag(&[&tree, &format!("{name}.se")], bits & 0x80 != 0)
    }
    fn qos(&mut self, q: SetpointQualifier) -> &mut Self {
        self.hex8(&["qos"], q.bits()).eq(&["qos_tree", "qos.ql"], q.ql()).flag(&["qos_tree", "qos.se"], q.is_select())
    }
    fn qpm(&mut self, q: ParameterQualifier) -> &mut Self {
        self.hex8(&["qpm"], q.bits())
            .eq(&["qpm_tree", "qpm.kpa"], q.kind())
            .eq(&["qpm_tree", "qpm.lpc"], u8::from(q.local_change()))
            .eq(&["qpm_tree", "qpm.pop"], u8::from(q.not_in_operation()))
    }
    fn bcr(&mut self, b: BinaryCounterReading) -> &mut Self {
        self.eq(&["bcr"], b.value())
            .eq(&["bcr_tree", "bcr.count"], b.value())
            .eq(&["bcr_tree", "bcr.sq"], b.sequence())
            .flag(&["bcr_tree", "bcr.cy"], b.carry())
            .flag(&["bcr_tree", "bcr.ca"], b.adjusted())
            .flag(&["bcr_tree", "bcr.iv"], b.invalid())
    }
    fn nof(&mut self, name: u16) -> &mut Self {
        self.eq(&["nof"], name)
    }
    fn split_qualifier(&mut self, name: &str, low: &str, b: u8) -> &mut Self {
        let tree = format!("{name}_tree");
        self.hex8(&[name], b).eq(&[&tree, &format!("{name}.{low}")], b & 0x0F).eq(&[&tree, &format!("{name}.qualifier")], b >> 4)
    }
    fn top_bit_qualifier(&mut self, name: &str, top: &str, b: u8) -> &mut Self {
        let tree = format!("{name}_tree");
        self.hex8(&[name], b).flag(&[&tree, &format!("{name}.{top}")], b & 0x80 != 0).eq(&[&tree, &format!("{name}.qualifier")], b & 0x7F)
    }
}

fn each<E, T>(v: &[InformationObject<E, T>], mut f: impl FnMut(&mut Expect, &E, &T)) -> Vec<Expect> {
    v.iter()
        .map(|o| {
            let mut e = Expect::new(o.ioa);
            e.eq(&["ioa"], o.ioa.0);
            f(&mut e, &o.element, &o.time);
            e
        })
        .collect()
}

fn siq(e: &mut Expect, s: SinglePoint) {
    e.hex8(&["siq"], s.bits()).flag(&["siq_tree", "siq.spi"], s.value()).quality_bits("siq", s.bits());
}
fn diq(e: &mut Expect, d: DoublePoint) {
    e.hex8(&["diq"], d.bits()).eq(&["diq_tree", "diq.dpi"], d.value() as u8).quality_bits("diq", d.bits());
}
fn vti(e: &mut Expect, s: &StepPosition) {
    let b = (s.value as u8 & 0x7F) | if s.transient { 0x80 } else { 0 };
    e.hex8(&["vti"], b).eq(&["vti_tree", "vti.v"], s.value).flag(&["vti_tree", "vti.t"], s.transient).qds(s.quality);
}
fn sep(e: &mut Expect, p: &ProtectionEvent) {
    let b = p.event.bits();
    e.hex8(&["sep"], b).eq(&["sep_tree", "sep.es"], b & 0x03).flag(&["sep_tree", "sep.ei"], b & 0x08 != 0).quality_bits("sep", b).cp16(p.elapsed);
}
fn spe(e: &mut Expect, p: &PackedStartEvents) {
    let b = p.events.bits();
    e.hex8(&["spe"], b);
    for (name, bit) in [("gs", 0x01), ("sl1", 0x02), ("sl2", 0x04), ("sl3", 0x08), ("sie", 0x10), ("srd", 0x20)] {
        e.flag(&["spe_tree", &format!("spe.{name}")], b & bit != 0);
    }
    e.qdp(p.quality).cp16(p.duration);
}
fn oci(e: &mut Expect, p: &PackedOutputCircuits) {
    let b = p.circuits.bits();
    e.hex8(&["oci"], b);
    for (name, bit) in [("gc", 0x01), ("cl1", 0x02), ("cl2", 0x04), ("cl3", 0x08)] {
        e.flag(&["oci_tree", &format!("oci.{name}")], b & bit != 0);
    }
    e.qdp(p.quality).cp16(p.operating_time);
}

/// The fields of every object, or `None` for a variant the oracle does not cover.
fn expectations(objects: &Objects, legacy_bitstrings: bool) -> Vec<Expect> {
    let bsi = |e: &mut Expect, value: u32| {
        let displayed = if legacy_bitstrings { value.swap_bytes() } else { value };
        e.eq(&["bitstring"], format!("{displayed:#010x}"));
    };
    match objects {
        Objects::SinglePoint(v) => each(v, |e, s, ()| siq(e, *s)),
        Objects::SinglePointCp56(v) => each(v, |e, s, t| {
            siq(e, *s);
            e.cp56(*t);
        }),
        Objects::DoublePoint(v) => each(v, |e, d, ()| diq(e, *d)),
        Objects::DoublePointCp56(v) => each(v, |e, d, t| {
            diq(e, *d);
            e.cp56(*t);
        }),
        Objects::StepPosition(v) => each(v, |e, s, ()| vti(e, s)),
        Objects::StepPositionCp56(v) => each(v, |e, s, t| {
            vti(e, s);
            e.cp56(*t);
        }),
        Objects::Bitstring(v) => each(v, |e, b, ()| {
            bsi(e, b.value);
            e.qds(b.quality);
        }),
        Objects::BitstringCp56(v) => each(v, |e, b, t| {
            bsi(e, b.value);
            e.qds(b.quality).cp56(*t);
        }),
        Objects::MeasuredNormalized(v) => each(v, |e, m, ()| {
            e.normalized(m.value).qds(m.quality);
        }),
        Objects::MeasuredNormalizedCp56(v) => each(v, |e, m, t| {
            e.normalized(m.value).qds(m.quality).cp56(*t);
        }),
        Objects::MeasuredScaled(v) => each(v, |e, m, ()| {
            e.eq(&["scalval"], m.value).qds(m.quality);
        }),
        Objects::MeasuredScaledCp56(v) => each(v, |e, m, t| {
            e.eq(&["scalval"], m.value).qds(m.quality).cp56(*t);
        }),
        Objects::MeasuredFloat(v) => each(v, |e, m, ()| {
            e.float(&["float"], m.value).qds(m.quality);
        }),
        Objects::MeasuredFloatCp56(v) => each(v, |e, m, t| {
            e.float(&["float"], m.value).qds(m.quality).cp56(*t);
        }),
        Objects::IntegratedTotals(v) => each(v, |e, b, ()| {
            e.bcr(*b);
        }),
        Objects::IntegratedTotalsCp56(v) => each(v, |e, b, t| {
            e.bcr(*b).cp56(*t);
        }),
        Objects::ProtectionEventCp56(v) => each(v, |e, p, t| {
            sep(e, p);
            e.cp56(*t);
        }),
        Objects::PackedStartEventsCp56(v) => each(v, |e, p, t| {
            spe(e, p);
            e.cp56(*t);
        }),
        Objects::PackedOutputCircuitsCp56(v) => each(v, |e, p, t| {
            oci(e, p);
            e.cp56(*t);
        }),
        Objects::PackedSinglePoints(v) => each(v, |e, p, ()| {
            let scd = u32::from(p.status) | (u32::from(p.change) << 16);
            e.eq(&["scd"], format!("{scd:#010x}"))
                .eq(&["scd_tree", "scd.st"], format!("{:#06x}", p.status))
                .eq(&["scd_tree", "scd.cd"], format!("{:#06x}", p.change))
                .qds(p.quality);
        }),
        Objects::NormalizedWithoutQuality(v) => each(v, |e, n, ()| {
            e.normalized(*n);
        }),
        Objects::SingleCommand(v) => each(v, |e, c, ()| {
            e.command("sco", c.bits(), "on", c.bits() & 0x01);
        }),
        Objects::SingleCommandCp56(v) => each(v, |e, c, t| {
            e.command("sco", c.bits(), "on", c.bits() & 0x01).cp56(*t);
        }),
        Objects::DoubleCommand(v) => each(v, |e, c, ()| {
            e.command("dco", c.bits(), "on", c.bits() & 0x03);
        }),
        Objects::DoubleCommandCp56(v) => each(v, |e, c, t| {
            e.command("dco", c.bits(), "on", c.bits() & 0x03).cp56(*t);
        }),
        Objects::StepCommand(v) => each(v, |e, c, ()| {
            e.command("rco", c.bits(), "up", c.bits() & 0x03);
        }),
        Objects::StepCommandCp56(v) => each(v, |e, c, t| {
            e.command("rco", c.bits(), "up", c.bits() & 0x03).cp56(*t);
        }),
        Objects::SetpointNormalized(v) => each(v, |e, s, ()| {
            e.normalized(s.value).qos(s.qualifier);
        }),
        Objects::SetpointNormalizedCp56(v) => each(v, |e, s, t| {
            e.normalized(s.value).qos(s.qualifier).cp56(*t);
        }),
        Objects::SetpointScaled(v) => each(v, |e, s, ()| {
            e.eq(&["scalval"], s.value).qos(s.qualifier);
        }),
        Objects::SetpointScaledCp56(v) => each(v, |e, s, t| {
            e.eq(&["scalval"], s.value).qos(s.qualifier).cp56(*t);
        }),
        Objects::SetpointFloat(v) => each(v, |e, s, ()| {
            e.float(&["float"], s.value).qos(s.qualifier);
        }),
        Objects::SetpointFloatCp56(v) => each(v, |e, s, t| {
            e.float(&["float"], s.value).qos(s.qualifier).cp56(*t);
        }),
        Objects::BitstringCommand(v) => each(v, |e, b, ()| bsi(e, b.0)),
        Objects::BitstringCommandCp56(v) => each(v, |e, b, t| {
            bsi(e, b.0);
            e.cp56(*t);
        }),
        Objects::EndOfInitialization(v) => each(v, |e, c, ()| {
            e.hex8(&["coi"], c.0).eq(&["coi_tree", "coi.r"], c.cause()).flag(&["coi_tree", "coi.i"], c.after_parameter_change());
        }),
        Objects::Interrogation(v) => each(v, |e, q, ()| {
            e.eq(&["qoi"], q.0);
        }),
        Objects::CounterInterrogation(v) => each(v, |e, q, ()| {
            e.hex8(&["qcc"], q.0).eq(&["qcc_tree", "qcc.rqt"], q.request()).eq(&["qcc_tree", "qcc.frz"], q.freeze());
        }),
        Objects::ClockSync(v) => each(v, |e, ClockSync, t| {
            e.cp56(*t);
        }),
        Objects::ResetProcess(v) => each(v, |e, q, ()| {
            e.eq(&["qrp"], q.0);
        }),
        Objects::TestCommandCp56(v) => each(v, |e, c, t| {
            e.eq(&["tsc"], c.0).cp56(*t);
        }),
        Objects::ParameterNormalized(v) => each(v, |e, p, ()| {
            e.normalized(p.value).qpm(p.qualifier);
        }),
        Objects::ParameterScaled(v) => each(v, |e, p, ()| {
            e.eq(&["scalval"], p.value).qpm(p.qualifier);
        }),
        Objects::ParameterFloat(v) => each(v, |e, p, ()| {
            e.float(&["float"], p.value).qpm(p.qualifier);
        }),
        Objects::ParameterActivation(v) => each(v, |e, q, ()| {
            e.eq(&["qpa"], q.0);
        }),
        Objects::FileReady(v) => each(v, |e, f, ()| {
            e.nof(f.name).eq(&["lof"], f.length).top_bit_qualifier("frq", "confirm", f.qualifier);
        }),
        Objects::SectionReady(v) => each(v, |e, f, ()| {
            e.nof(f.name).eq(&["nos"], f.section).eq(&["lof"], f.length).top_bit_qualifier("srq", "ready", f.qualifier);
        }),
        Objects::CallSelect(v) => each(v, |e, f, ()| {
            e.nof(f.name).eq(&["nos"], f.section).split_qualifier("scq", "select", f.qualifier);
        }),
        Objects::LastSection(v) => each(v, |e, f, ()| {
            e.nof(f.name).eq(&["nos"], f.section).eq(&["lsq"], f.qualifier).hex8(&["chs"], f.checksum);
        }),
        Objects::FileAck(v) => each(v, |e, f, ()| {
            e.nof(f.name).eq(&["nos"], f.section).split_qualifier("afq", "ack", f.qualifier);
        }),
        Objects::Segment(v) => each(v, |e, s, ()| {
            e.nof(s.name).eq(&["nos"], s.section).eq(&["los"], s.data.len());
            if !s.data.is_empty() {
                let hex: Vec<String> = s.data.iter().map(|b| format!("{b:02x}")).collect();
                e.eq(&["segmentdata"], hex.join(":"));
            }
        }),
        Objects::Directory(v) => each(v, |e, d, t| {
            let s = d.status;
            e.nof(d.name)
                .eq(&["lof"], d.length)
                .hex8(&["sof"], s)
                .eq(&["sof_tree", "sof.status"], s & 0x1F)
                .flag(&["sof_tree", "sof.lfd"], s & 0x20 != 0)
                .flag(&["sof_tree", "sof.for"], s & 0x40 != 0)
                .flag(&["sof_tree", "sof.fa"], s & 0x80 != 0)
                .cp56(*t);
        }),
        Objects::QueryLog(v) => each(v, |e, q, ()| {
            e.nof(q.name).cp56_as("range_start_cp56time", q.start).cp56_as("range_stop_cp56time", q.stop);
        }),
        other => panic!("the oracle has no expectations for {}", other.type_id()),
    }
}

// ---------------------------------------------------------------------------------------------
// Comparing
// ---------------------------------------------------------------------------------------------

fn get<'a>(node: &'a Value, path: &[String]) -> Option<&'a Value> {
    path.iter().try_fold(node, |n, key| n.get(key))
}

fn matches_want(got: &str, want: &Want) -> bool {
    match want {
        Want::Exact(s) => got == s,
        Want::Float(x) => {
            let Ok(g) = got.parse::<f64>().or_else(|_| if got.eq_ignore_ascii_case("nan") { Ok(f64::NAN) } else { Err(()) }) else { return false };
            if x.is_nan() {
                g.is_nan()
            } else if x.is_infinite() {
                g == *x
            } else {
                // tshark prints six significant digits.
                (g - x).abs() <= 1e-5 * x.abs().max(1e-30) + f64::from(f32::MIN_POSITIVE)
            }
        }
    }
}

fn no_expert_notes(node: &Value, path: &str, problems: &mut Vec<String>) {
    match node {
        Value::Object(map) => {
            for (k, v) in map {
                if k.starts_with("_ws.expert") || k.starts_with("_ws.malformed") {
                    problems.push(format!("{path}/{k}: {v}"));
                }
                no_expert_notes(v, &format!("{path}/{k}"), problems);
            }
        }
        Value::Array(items) => items.iter().for_each(|v| no_expert_notes(v, path, problems)),
        _ => {}
    }
}

/// Random ASDUs of every 104-permitted typed type, SQ = 0 and SQ = 1, plus fixed edge values.
fn cases() -> Vec<Asdu> {
    let profile = Profile::IEC104;
    let mut runner = TestRunner::deterministic();
    let mut out = Vec::new();
    let mut n = 0u32;
    for sequence in [false, true] {
        for (type_id, strategy) in common::arms(&profile.with_max_asdu_len(255), sequence) {
            if !profile.permits(type_id) {
                continue;
            }
            let mut made = 0;
            while made < SAMPLES_PER_FORM {
                let objects = strategy.new_tree(&mut runner).unwrap().current();
                // Wireshark keys each object's subtree by its address, so they must be distinct;
                // the read command's objects are not dissected one by one (its single IOA is).
                let ioas: Vec<_> = objects.ioas().collect();
                let mut unique = ioas.clone();
                unique.sort_unstable();
                unique.dedup();
                if objects.is_empty() || unique.len() != ioas.len() || (type_id == TypeId::C_RD_NA_1 && objects.len() != 1) {
                    continue;
                }
                n += 1;
                let cot = Cot::new(Cause::new((n % 64) as u8).unwrap());
                let cot = Cot { negative: n % 3 == 0, test: n % 5 == 0, originator: n.wrapping_mul(7) as u8, ..cot };
                let mut asdu = Asdu::new(CommonAddress((n.wrapping_mul(2_654_435_761) >> 16) as u16), cot, objects);
                asdu.sequence = sequence;
                if asdu.encoded_len(&profile) > usize::from(profile.max_asdu_len) {
                    continue;
                }
                out.push(asdu);
                made += 1;
            }
        }
    }
    // Fixed edge values on top of the random ones.
    let t = Cp56Time2a::from_octets([0x5F, 0xEA, 0xC0 | 61, 0x80 | 23, (7 << 5) | 31, 12, 99]);
    let edges: Vec<Objects> = vec![
        vec![
            InformationObject::new(Ioa(1), MeasuredNormalized::new(Normalized::MIN)),
            InformationObject::new(Ioa(2), MeasuredNormalized::new(Normalized::MAX)),
        ]
        .into(),
        vec![InformationObject::new(Ioa(1), MeasuredScaled::new(i16::MIN)), InformationObject::new(Ioa(0xFF_FFFF), MeasuredScaled::new(i16::MAX))].into(),
        vec![
            InformationObject::new(Ioa(1), MeasuredFloat::new(f32::NAN)).at(t),
            InformationObject::new(Ioa(2), MeasuredFloat::new(f32::INFINITY)).at(t),
            InformationObject::new(Ioa(3), MeasuredFloat::new(f32::NEG_INFINITY)).at(t),
        ]
        .into(),
        InformationObject::new(Ioa(5), StepPosition { value: -64, transient: true, quality: Quality::INVALID }).into(),
        InformationObject::new(Ioa(6), PackedSinglePoints::new(0xFFFF, 0x8001)).into(),
        InformationObject::new(Ioa(7), Bitstring32::new(u32::MAX)).at(t).into(),
    ];
    for objects in edges {
        out.push(Asdu::new(CommonAddress(0xFFFF), Cot::SPONTANEOUS.negative().test().with_originator(255), objects));
    }
    out
}

#[test]
fn wireshark_dissects_every_104_type_as_what_was_put_in() {
    let strict = std::env::var("IEC60870_REQUIRE_FIELD_COVERAGE").as_deref() == Ok("1");
    let Some(tshark) = oracle::tshark("ASDU oracle") else {
        assert!(!strict, "field coverage requires tshark");
        return;
    };
    let profile = Profile::IEC104;
    let cases = cases();
    let encoded: Vec<Vec<u8>> = cases.iter().map(|a| a.to_vec(&profile).unwrap()).collect();
    let dir = std::env::temp_dir().join(format!("iec60870-oracle-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("asdus.pcap");
    std::fs::write(&file, pcap(&encoded)).unwrap();

    let output = Command::new(&tshark)
        .arg("-r")
        .arg(&file)
        .args(["-T", "json", "-o", "tcp.desegment_tcp_streams:FALSE", "-o", "tcp.analyze_sequence_numbers:FALSE"])
        .output()
        .expect("run tshark");
    assert!(output.status.success(), "tshark failed: {}", String::from_utf8_lossy(&output.stderr));
    let packets: Value = serde_json::from_slice(&output.stdout).expect("tshark JSON");
    let packets = packets.as_array().expect("an array of packets");
    assert_eq!(packets.len(), cases.len());

    // Upstream added SCD dissection and fixed BSI byte order in the same change (K14).
    // Select the legacy display convention independently of the BSI values under test.
    let legacy_bitstrings = !strict
        && !cases.iter().zip(packets).any(|(asdu, packet)| {
            asdu.type_id() == TypeId::M_PS_NA_1
                && packet["_source"]["layers"]["iec60870_asdu"].as_object().is_some_and(|m| m.keys().any(|k| k.starts_with("IOA:")))
        });
    let mut problems = Vec::new();
    let mut checked = 0usize;
    let mut types = std::collections::BTreeSet::new();
    let mut raw_only = std::collections::BTreeSet::new();
    for (i, (asdu, packet)) in cases.iter().zip(packets).enumerate() {
        let layers = &packet["_source"]["layers"];
        no_expert_notes(&layers["iec60870_104"], &format!("#{i} 104"), &mut problems);
        no_expert_notes(&layers["iec60870_asdu"], &format!("#{i} asdu"), &mut problems);
        no_expert_notes(layers, &format!("#{i}"), &mut problems);
        let apci = &layers["iec60870_104"];
        let a = &layers["iec60870_asdu"];
        let mut expect = |node: &Value, path: Vec<String>, want: Want, what: &str| {
            checked += 1;
            match get(node, &path).and_then(Value::as_str) {
                Some(got) if matches_want(got, &want) => {}
                got => problems.push(format!("#{i} {}: {what} {path:?}: got {got:?}, want {want:?}", asdu.type_id())),
            }
        };
        let s = |p: &str| vec![p.to_string()];
        expect(apci, s("iec60870_104.apdulen"), Want::Exact((encoded[i].len() + 4).to_string()), "APCI");
        expect(apci, s("iec60870_104.tx"), Want::Exact(i.to_string()), "APCI");
        let h = asdu.header();
        let f = |p: &str| vec![format!("iec60870_asdu.{p}")];
        expect(a, f("typeid"), Want::Exact(h.type_id.0.to_string()), "header");
        expect(a, f("sq"), Want::Exact(u8::from(h.sequence).to_string()), "header");
        expect(a, f("numix"), Want::Exact(h.count.to_string()), "header");
        expect(a, f("causetx"), Want::Exact(h.cot.cause.value().to_string()), "header");
        expect(a, f("nega"), Want::Exact(u8::from(h.cot.negative).to_string()), "header");
        expect(a, f("test"), Want::Exact(u8::from(h.cot.test).to_string()), "header");
        expect(a, f("oa"), Want::Exact(h.cot.originator.to_string()), "header");
        expect(a, f("addr"), Want::Exact(h.common_address.0.to_string()), "header");
        let dissected = a.as_object().is_some_and(|m| m.keys().any(|k| k.starts_with("IOA:")));
        if !dissected {
            // This tshark has no case for the type (the read command never has one; older
            // releases lack the newer types): its default branch shows the first IOA and the
            // rest of the ASDU as raw data — still a check of the header, the address and the
            // length.
            expect(a, f("ioa"), Want::Exact(asdu.objects.ioa(0).unwrap().0.to_string()), "default branch");
            let rest = &encoded[i][profile.header_len() + 3..];
            if !rest.is_empty() {
                let hex: Vec<String> = rest.iter().map(|b| format!("{b:02x}")).collect();
                expect(a, f("rawdata"), Want::Exact(hex.join(":")), "default branch");
            }
            raw_only.insert(asdu.type_id());
        } else {
            for e in expectations(&asdu.objects, legacy_bitstrings) {
                let node = &a[format!("IOA: {}", e.ioa)];
                if node.is_null() {
                    expect(a, vec![format!("IOA: {}", e.ioa)], Want::Exact("a subtree".into()), "object");
                    continue;
                }
                for (path, want) in e.fields {
                    expect(node, path, want, &format!("IOA {}", e.ioa));
                }
            }
        }
        types.insert(asdu.type_id());
    }
    std::fs::remove_dir_all(&dir).ok();
    // IEC 62351 security ASDUs have opaque payloads in this codec.
    let permitted_typed = TypeSet::IEC104.iter().filter(|t| !matches!(t.0, 41 | 81..=87 | 90..=95)).collect();
    assert_eq!(types, permitted_typed, "every 104-permitted typed type was dissected");
    if strict {
        let missing: Vec<_> = raw_only.iter().filter(|t| **t != TypeId::C_RD_NA_1).map(ToString::to_string).collect();
        assert!(missing.is_empty(), "missing per-object dissection for {}", missing.join(", "));
    }
    assert!(problems.is_empty(), "{} of {checked} field checks failed:\n{}", problems.len(), problems.join("\n"));
    println!("tshark agreed on {checked} fields of {} ASDUs ({} type identifications)", cases.len(), types.len());
    let raw_only: Vec<String> = raw_only.iter().map(ToString::to_string).collect();
    println!("dissected only by tshark's default branch (no per-object case in this tshark): {}", raw_only.join(", "));
}
