//! Every standard type identification, over each information element's full declared range,
//! under every field-width combination (COT 1/2 × CA 1/2 × IOA 1/2/3) and SQ = 0 / 1:
//! encode → decode → encode reproduces the octets, and the decoded ASDU equals the original
//! (floats compared bit for bit through the octets, so NaN payloads count).

#![allow(
    clippy::pedantic,
    clippy::complexity,
    clippy::manual_is_multiple_of,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod common;

use iec60870::prelude::*;
use proptest::strategy::{Strategy, ValueTree};
use proptest::test_runner::{Config, TestRunner};

const CASES_PER_COMBINATION: u32 = 24;

fn round_trip(profile: &Profile, asdu: &Asdu) {
    let octets = asdu.to_vec(profile).unwrap_or_else(|e| panic!("{asdu:?} under {profile:?}: {e}"));
    assert_eq!(octets.len(), asdu.encoded_len(profile));
    let back = Asdu::decode(&octets, profile).unwrap_or_else(|e| panic!("{octets:02x?} under {profile:?}: {e}"));
    assert_eq!(back.to_vec(profile).unwrap(), octets, "re-encoding differs");
    // `Debug` prints every field; it differs from `==` only for NaN, which the octets cover.
    assert_eq!(format!("{back:?}"), format!("{asdu:?}"));
    assert_eq!(back.type_id(), asdu.type_id());
}

fn run(strategy: &impl Strategy<Value = Objects>, profile: &Profile, sequence: bool, cot: Cot, ca: u16) {
    let mut runner = TestRunner::new(Config { cases: CASES_PER_COMBINATION, ..Config::default() });
    for _ in 0..CASES_PER_COMBINATION {
        let objects = strategy.new_tree(&mut runner).unwrap().current();
        let mut asdu = Asdu::new(CommonAddress(ca), cot, objects);
        asdu.sequence = sequence;
        round_trip(profile, &asdu);
    }
}

/// A COT and CA that fit `profile`, varied per call.
fn header_values(profile: &Profile, seed: u32) -> (Cot, u16) {
    let cause = Cause::new((seed % 64) as u8).unwrap();
    let mut cot = Cot::new(cause);
    cot.negative = seed & 0x100 != 0;
    cot.test = seed & 0x200 != 0;
    if profile.cot == CotWidth::Two {
        cot.originator = (seed >> 12) as u8;
    }
    let ca = (seed >> 4) as u16 & profile.ca.max();
    (cot, ca)
}

#[test]
fn every_standard_type_round_trips_under_every_width_combination() {
    let mut combinations = 0;
    let mut seed = 0x1234_5678u32;
    for profile in common::all_width_profiles() {
        for sequence in [false, true] {
            let arms = common::arms(&profile, sequence);
            assert_eq!(arms.len(), 67, "one strategy per typed standard type");
            for (type_id, strategy) in &arms {
                seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                let (cot, ca) = header_values(&profile, seed);
                run(strategy, &profile, sequence, cot, ca);
                combinations += 1;
                assert!(profile.permits(*type_id));
            }
        }
    }
    assert_eq!(combinations, 67 * 12 * 2);
}

#[test]
fn untyped_types_round_trip_as_raw_under_every_width_combination() {
    for profile in common::all_width_profiles() {
        for sequence in [false, true] {
            run(&common::raw(&profile), &profile, sequence, Cot::SPONTANEOUS, 1);
        }
    }
}

#[test]
fn every_typed_variant_names_a_distinct_type() {
    let profile = common::all_width_profiles()[0];
    let mut runner = TestRunner::default();
    let mut ids: Vec<u8> = common::arms(&profile, false)
        .iter()
        .map(|(id, s)| {
            let objects = s.new_tree(&mut runner).unwrap().current();
            assert_eq!(objects.type_id(), *id);
            id.0
        })
        .collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), 67);
}
