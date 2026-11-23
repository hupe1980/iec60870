//! Every input a fuzzer once crashed on, replayed forever.
//!
//! `fuzz/regressions/<bug>.bin` holds the inputs, named after the bug. Each is fed to the
//! decoder under the three profile derivations of the fuzz targets (104, 101, and the profile
//! the first two octets select); decoding must not panic, and whatever decodes must re-encode
//! to exactly the input.

#![allow(
    clippy::pedantic,
    clippy::complexity,
    clippy::manual_is_multiple_of,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::fs;
use std::path::Path;

use iec60870::asdu::{CaWidth, CotWidth, IoaWidth};
use iec60870::types::TypeSet;
use iec60870::{Asdu, Profile};

/// The same derivation as the `asdu_any` fuzz target.
fn derived_profile(selector: u8, max: u8) -> Profile {
    let cot = if selector & 0x01 == 0 { CotWidth::One } else { CotWidth::Two };
    let ca = if selector & 0x02 == 0 { CaWidth::One } else { CaWidth::Two };
    let ioa = match (selector >> 2) & 0x03 {
        0 => IoaWidth::One,
        1 => IoaWidth::Two,
        _ => IoaWidth::Three,
    };
    let types = match (selector >> 4) & 0x03 {
        0 => TypeSet::ALL,
        1 => TypeSet::STANDARD,
        2 => TypeSet::IEC104,
        _ => TypeSet::IEC101,
    };
    Profile::IEC104.with_cot(cot).with_ca(ca).with_ioa(ioa).with_max_asdu_len(max).with_types(types)
}

fn check(input: &[u8], profile: &Profile, name: &str) {
    if let Ok(asdu) = Asdu::decode(input, profile) {
        let octets = asdu.to_vec(profile).unwrap_or_else(|e| panic!("{name}: decoded but does not re-encode: {e}"));
        assert_eq!(octets, input, "{name}: re-encoding differs");
    }
}

fn replay(input: &[u8], name: &str) {
    check(input, &Profile::IEC104, name);
    check(input, &Profile::IEC101, name);
    if let [selector, max, rest @ ..] = input {
        check(rest, &derived_profile(*selector, *max), name);
    }
}

#[test]
fn every_committed_crash_input_replays_cleanly() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz").join("regressions");
    let Ok(entries) = fs::read_dir(&dir) else {
        println!("no {} directory; nothing to replay", dir.display());
        return;
    };
    let mut replayed = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "bin") {
            replay(&fs::read(&path).unwrap(), &path.display().to_string());
            replayed += 1;
        }
    }
    println!("replayed {replayed} regression input(s)");
}

#[test]
fn the_derivation_reaches_every_width() {
    let mut seen = std::collections::BTreeSet::new();
    for s in 0..=255u8 {
        let p = derived_profile(s, 255);
        seen.insert((p.cot.octets(), p.ca.octets(), p.ioa.octets()));
    }
    assert_eq!(seen.len(), 12);
}
