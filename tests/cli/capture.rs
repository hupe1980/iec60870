//! Process-level capture and timeline fixtures.
use super::run;
use serde_json::Value;
use std::{io::Write, process::Output};
use tempfile::NamedTempFile;

fn inspect(bytes: &[u8], flags: &[&str]) -> Output {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(bytes).unwrap();
    let mut args = vec!["pcap", file.path().to_str().unwrap()];
    args.extend_from_slice(flags);
    run(&args, b"")
}
fn records(out: &Output) -> Vec<Value> {
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).lines().map(|s| serde_json::from_str(s).unwrap()).collect()
}
fn ethernet(seq: u32, payload: &[u8], from_server: bool, client: u16) -> Vec<u8> {
    let (src, dst, sp, dp) = if from_server { (2, 1, 2404, client) } else { (1, 2, client, 2404) };
    let mut b = vec![0; 54];
    b[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    b[14] = 0x45;
    b[16..18].copy_from_slice(&(40 + payload.len() as u16).to_be_bytes());
    b[23] = 6;
    b[26..30].copy_from_slice(&[192, 0, 2, src]);
    b[30..34].copy_from_slice(&[192, 0, 2, dst]);
    b[34..36].copy_from_slice(&sp.to_be_bytes());
    b[36..38].copy_from_slice(&dp.to_be_bytes());
    b[38..42].copy_from_slice(&seq.to_be_bytes());
    b[46] = 0x50;
    b.extend_from_slice(payload);
    b
}
fn classic(packets: &[Vec<u8>], be: bool, nano: bool) -> Vec<u8> {
    let n = |v: u32| if be { v.to_be_bytes() } else { v.to_le_bytes() };
    let h = |v: u16| if be { v.to_be_bytes() } else { v.to_le_bytes() };
    let mut b = Vec::from(n(if nano { 0xa1b2_3c4d } else { 0xa1b2_c3d4 }));
    b.extend(h(2));
    b.extend(h(4));
    b.extend([0; 8]);
    b.extend(n(65535));
    b.extend(n(1));
    for (i, p) in packets.iter().enumerate() {
        b.extend(n(100));
        b.extend(n(i as u32));
        b.extend(n(p.len() as u32));
        b.extend(n(p.len() as u32));
        b.extend(p);
    }
    b
}
const ACT: &[u8] = &[0x68, 4, 7, 0, 0, 0];
const CON: &[u8] = &[0x68, 4, 11, 0, 0, 0];
#[test]
fn timeline_merges_reordered_segments_and_counts_each_apdu_once() {
    let mut point = vec![0x68, 14, 0, 0, 0, 0, 1, 1, 3, 0, 1, 0, 100, 0, 0, 1];
    let mut later = point.clone();
    later[2] = 4;
    let mut packets = vec![
        ethernet(20, ACT, false, 9000),
        ethernet(99, CON, true, 9000),
        ethernet(105, &point[..3], true, 9000),
        ethernet(113, &point[8..], true, 9000),
        ethernet(108, &point[3..8], true, 9000),
        ethernet(105, &point, true, 9000),
        ethernet(121, &later, true, 9000),
    ];
    point.splice(..0, [0xff, 0xaa]);
    packets.push(ethernet(500, &point, true, 9001));
    packets.push(ethernet(1000, ACT, true, 9001)); // Missing data, drained at EOF.
    for (be, nano) in [(true, true), (false, true), (true, false), (false, false)] {
        let b = classic(&packets, be, nano);
        let rows = records(&inspect(&b, &["--json"]));
        let frames = rows.iter().filter(|r| r["kind"] == "apdu").collect::<Vec<_>>();
        assert_eq!(frames.len(), 6);
        assert_eq!(frames[2]["asdu"]["objects"][0]["value"], true);
        assert_eq!(frames[1]["dir"], "to_client");
        assert!(frames[3]["warning"].as_str().unwrap().contains("expected 1"));
        let totals = records(&inspect(&b, &["--json", "--summary"]));
        assert_eq!(totals, rows[6..]);
        assert_eq!(totals[0]["ns_gaps"], 1);
        assert_eq!(totals[0]["i"], 2);
        assert_eq!(totals[1]["skipped_octets"], 2);
        assert_eq!(totals[1]["tcp_gaps"], 1);
        assert_eq!(totals[2]["packets"], 9);
        assert_eq!(totals[2]["connections"], 2);
        assert_eq!(records(&inspect(&b, &["--port", "502", "--json"]))[0]["connections"], 0);
    }
}
fn block(b: &mut Vec<u8>, ty: u32, mut body: Vec<u8>) {
    while !body.len().is_multiple_of(4) {
        body.push(0);
    }
    let size = (12 + body.len()) as u32;
    b.extend(ty.to_le_bytes());
    b.extend(size.to_le_bytes());
    b.extend(body);
    b.extend(size.to_le_bytes());
}
fn section() -> Vec<u8> {
    let mut b = Vec::new();
    let mut body = vec![0x4d, 0x3c, 0x2b, 0x1a, 1, 0, 0, 0];
    body.extend([0xff; 8]);
    block(&mut b, 0x0a0d_0d0a, body);
    block(&mut b, 1, vec![113, 0, 0, 0, 0xff, 0xff, 0, 0, 9, 0, 1, 0, 9, 0, 0, 0]);
    b
}
fn sll6(payload: &[u8], seq: u32) -> Vec<u8> {
    let mut b = vec![0; 76];
    b[14..16].copy_from_slice(&0x86dd_u16.to_be_bytes());
    b[16] = 0x60;
    b[20..22].copy_from_slice(&(20 + payload.len() as u16).to_be_bytes());
    b[22] = 6;
    b[39] = 1;
    b[55] = 2;
    b[56..60].copy_from_slice(&[0x23, 0x28, 0x09, 0x64]);
    b[60..64].copy_from_slice(&seq.to_be_bytes());
    b[68] = 0x50;
    b.extend(payload);
    b
}
#[test]
fn pcapng_uses_interface_precision_and_simple_packets_have_unknown_time() {
    let mut b = section();
    for i in 0_u32..2 {
        let p = sll6(ACT, 6 * i);
        let mut epb = Vec::new();
        for v in [0_u32, 390_000_000, 10 + i, p.len() as u32, p.len() as u32] {
            epb.extend(v.to_le_bytes());
        }
        epb.extend(p);
        block(&mut b, 6, epb);
    }
    let p = sll6(ACT, 12);
    let mut spb = Vec::from((p.len() as u32).to_le_bytes());
    spb.extend(p);
    block(&mut b, 3, spb);
    let rows = records(&inspect(&b, &["--json"]));
    assert_eq!(rows[0]["t"], 0.0);
    assert_eq!(rows[1]["t"], 1e-9);
    assert!(rows[2]["t"].is_null());
    assert_eq!(rows[3]["u"], 3);
}
#[test]
fn invalid_containers_fail_without_trusting_lengths() {
    let mut huge = classic(&[], false, false);
    huge.extend([0; 8]);
    huge.extend([255; 8]);
    let mut bad = section();
    bad.pop();
    for bytes in [b"hello".as_slice(), &huge, &bad] {
        let out = inspect(bytes, &[]);
        assert_eq!(out.status.code(), Some(1));
        assert!(out.stderr.starts_with(b"iec60870: "));
    }
}
#[test]
fn retained_reference_capture_reports_all_frames_when_available() {
    use std::path::PathBuf;
    let root = std::env::var_os("IEC60870_REFERENCE")
        .map_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(["con", "cepts"].concat()).join("reference"), PathBuf::from);
    let Ok(bytes) = std::fs::read(root.join("pcap/iec104.pcap")) else { return };
    let rows = records(&inspect(&bytes, &["--summary", "--json"]));
    assert_eq!(rows[0]["i"], 91);
    assert_eq!(rows[0]["u"], 10);
    assert_eq!(rows[0]["s"], 14);
    assert_eq!(rows[0]["decode_errors"], 0);
    assert_eq!(rows[0]["tcp_gaps"], 0);
    assert_eq!(rows[0]["skipped_octets"], 0);
}

#[test]
fn incomplete_candidate_at_eof_does_not_hide_a_complete_frame() {
    let p = ethernet(u32::MAX - 2, &[&[0x68, 200, 0x1b][..], ACT].concat(), false, 9000);
    let b = classic(&[p], false, false);
    let rows = records(&inspect(&b, &["--json", "--color", "always"]));
    assert_eq!(rows[0]["kind"], "apdu");
    assert_eq!(rows[1]["skipped_octets"], 3);
    assert!(!inspect(&b, &["--color", "never"]).stdout.contains(&27));
    assert!(inspect(&b, &["--color", "always"]).stdout.contains(&27));
}

#[test]
fn interrogation_and_reply_cross_tcp_wrap_on_tagged_ethernet() {
    let gi = [0x68, 14, 0, 0, 0, 0, 100, 1, 6, 0, 1, 0, 0, 0, 0, 20];
    let mut reply = gi;
    reply[8] = 7;
    let mut packets = vec![
        ethernet(u32::MAX - 1, &gi[..2], false, 9000),
        ethernet(0, &gi[2..], false, 9000),
        ethernet(60, &reply[..8], true, 9000),
        ethernet(68, &reply[8..], true, 9000),
    ];
    for packet in &mut packets {
        packet.splice(12..12, [0x88, 0xa8, 0, 1, 0x81, 0, 0, 2]);
    }
    let bytes = classic(&packets, false, false);
    let rows = records(&inspect(&bytes, &["--json"]));
    assert_eq!(rows[2]["types"]["C_IC_NA_1"], 2);
    assert_eq!(rows[2]["tcp_gaps"], 0);
    let output = String::from_utf8(inspect(&bytes, &[]).stdout).unwrap();
    assert!(output.contains("#1 →") && output.contains("#1 ←"));
    assert!(output.contains("C_IC_NA_1") && output.contains("STARTDT confirmation not observed"));
}

#[test]
fn saturated_connection_table_keeps_reused_tuple_out_of_old_session() {
    let mut packets: Vec<_> = (10000..11024).map(|port| ethernet(100, ACT, false, port)).collect();
    let mut syn = ethernet(999, &[], false, 10000);
    syn[47] = 2;
    packets.push(syn);
    packets.push(ethernet(1000, ACT, false, 10000));
    let rows = records(&inspect(&classic(&packets, false, false), &["--json", "--summary"]));
    assert_eq!(rows[0]["u"], 1);
    assert_eq!(rows[1024]["connections"], 1024);
    assert_eq!(rows[1024]["dropped_connection_packets"], 2);
}

#[test]
fn utc_qualifies_only_valid_station_times_and_preserves_capture_time() {
    let frame = [0x68, 21, 0, 0, 0, 0, 30, 1, 3, 0, 1, 0, 100, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0];
    let mut invalid = frame;
    invalid[18] = 0x80;
    let bytes = classic(&[ethernet(20, &frame, true, 9000), ethernet(43, &invalid, true, 9000)], false, false);
    let local = records(&inspect(&bytes, &["--json"]));
    let utc = records(&inspect(&bytes, &["--json", "--utc"]));
    assert_eq!(utc[0]["t"], local[0]["t"]);
    assert_eq!(local[0]["asdu"]["objects"][0]["time_text"], "2000-01-01 00:00:00.000");
    assert!(local[0]["asdu"]["objects"][0].get("time").is_none());
    assert_eq!(utc[0]["asdu"]["objects"][0]["time"], "2000-01-01T00:00:00.000Z");
    assert!(utc[1]["asdu"]["objects"][0]["time_text"].as_str().unwrap().contains("IV"));
    assert!(utc[1]["asdu"]["objects"][0].get("time").is_none());
}

#[test]
fn binary_pipe_and_saved_capture_emit_identical_records() {
    let bytes = classic(&[ethernet(20, ACT, false, 9000), ethernet(99, CON, true, 9000)], true, true);
    let piped = run(&["--json", "pcap", "-"], &bytes);
    assert_eq!(records(&piped), records(&inspect(&bytes, &["--json"])));
    let truncated = run(&["--json", "pcap", "-"], &bytes[..10]);
    assert_eq!(truncated.status.code(), Some(1));
}
