//! A real 104 capture, replayed through the decoder: every ASDU in it decodes as a typed ASDU
//! under the 104 profile and re-encodes to exactly the octets on the wire.
//!
//! The capture is third-party material and is not part of the crate. The test looks for
//! `iec104.pcap` under `$IEC60870_REFERENCE/pcap/` (by default the maintainer's local corpus
//! directory) and skips with a message when it is absent.

#![allow(
    clippy::pedantic,
    clippy::complexity,
    clippy::manual_is_multiple_of,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use iec60870::{Asdu, Objects, Profile};

fn corpus() -> PathBuf {
    std::env::var_os("IEC60870_REFERENCE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(["con", "cepts"].concat()).join("reference"))
}

/// The TCP payloads of a classic pcap of Ethernet frames, in capture order, with their
/// direction and sequence number.
fn tcp_payloads(pcap: &[u8]) -> Vec<((u32, u16, u32, u16), u32, Vec<u8>)> {
    let magic = u32::from_le_bytes(pcap[0..4].try_into().unwrap());
    let le = match magic {
        0xA1B2_C3D4 | 0xA1B2_3C4D => true,
        0xD4C3_B2A1 | 0x4D3C_B2A1 => false,
        other => panic!("not a classic pcap: magic {other:#x}"),
    };
    let u32_at = |b: &[u8], at: usize| {
        let a: [u8; 4] = b[at..at + 4].try_into().unwrap();
        if le { u32::from_le_bytes(a) } else { u32::from_be_bytes(a) }
    };
    assert_eq!(u32_at(pcap, 20), 1, "link type must be Ethernet");
    let mut out = Vec::new();
    let mut at = 24;
    while at + 16 <= pcap.len() {
        let caplen = u32_at(pcap, at + 8) as usize;
        let frame = &pcap[at + 16..at + 16 + caplen];
        at += 16 + caplen;
        let mut eth = 12;
        let mut ethertype = u16::from_be_bytes([frame[eth], frame[eth + 1]]);
        if ethertype == 0x8100 {
            eth += 4;
            ethertype = u16::from_be_bytes([frame[eth], frame[eth + 1]]);
        }
        if ethertype != 0x0800 {
            continue;
        }
        let ip = &frame[eth + 2..];
        let ihl = usize::from(ip[0] & 0x0F) * 4;
        let total = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
        if ip[9] != 6 {
            continue;
        }
        let src = u32::from_be_bytes(ip[12..16].try_into().unwrap());
        let dst = u32::from_be_bytes(ip[16..20].try_into().unwrap());
        let tcp = &ip[ihl..total];
        let sport = u16::from_be_bytes([tcp[0], tcp[1]]);
        let dport = u16::from_be_bytes([tcp[2], tcp[3]]);
        let seq = u32::from_be_bytes(tcp[4..8].try_into().unwrap());
        let offset = usize::from(tcp[12] >> 4) * 4;
        let payload = tcp[offset..].to_vec();
        if !payload.is_empty() {
            out.push(((src, sport, dst, dport), seq, payload));
        }
    }
    out
}

#[test]
fn every_asdu_in_the_reference_capture_round_trips() {
    let path = corpus().join("pcap").join("iec104.pcap");
    let Ok(pcap) = std::fs::read(&path) else {
        println!("skipped: {} not found (set IEC60870_REFERENCE to the corpus directory)", path.display());
        return;
    };

    // Reassemble each direction's byte stream (dropping retransmitted octets), then cut it
    // into APDUs.
    let mut streams: BTreeMap<(u32, u16, u32, u16), (u32, Vec<u8>)> = BTreeMap::new();
    for (key, seq, payload) in tcp_payloads(&pcap) {
        let (next, buf) = streams.entry(key).or_insert((seq, Vec::new()));
        let skip = next.wrapping_sub(seq) as usize;
        if seq.wrapping_sub(*next) as i32 > 0 || skip >= payload.len() {
            continue; // a gap (not in this capture) or a pure retransmission
        }
        buf.extend_from_slice(&payload[skip..]);
        *next = seq.wrapping_add(payload.len() as u32);
    }

    let profile = Profile::IEC104;
    let mut decoded = 0;
    let mut types = BTreeSet::new();
    for (_, (_, stream)) in streams {
        let mut rest = stream.as_slice();
        while let [0x68, len, ..] = rest {
            let len = usize::from(*len);
            let apdu = &rest[..2 + len];
            rest = &rest[2 + len..];
            if apdu[2] & 0x01 != 0 {
                continue; // S- or U-frame
            }
            let octets = &apdu[6..];
            let asdu = Asdu::decode(octets, &profile).unwrap_or_else(|e| panic!("{octets:02x?}: {e}"));
            assert!(!matches!(asdu.objects, Objects::Raw(_)), "{asdu:?} should be typed");
            assert_eq!(asdu.to_vec(&profile).unwrap(), octets, "{asdu}");
            types.insert(asdu.type_id().0);
            decoded += 1;
        }
        assert!(rest.is_empty(), "stream ends mid-APDU");
    }
    println!("decoded and re-encoded {decoded} ASDUs of {} types: {types:?}", types.len());
    assert!(decoded > 0);
}
