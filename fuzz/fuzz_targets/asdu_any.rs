//! `Asdu::decode` under a profile chosen by the first two input octets (every field-width
//! combination, any maximum length, four type sets): never panics, and whatever it accepts
//! re-encodes to exactly the rest of the input.
#![no_main]

use iec60870::asdu::{CaWidth, CotWidth, IoaWidth};
use iec60870::types::TypeSet;
use iec60870::{Asdu, Profile};
use libfuzzer_sys::fuzz_target;

/// The same derivation as `tests/regressions.rs`.
fn profile(selector: u8, max: u8) -> Profile {
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

fuzz_target!(|data: &[u8]| {
    let [selector, max, asdu @ ..] = data else { return };
    let profile = profile(*selector, *max);
    if let Ok(decoded) = Asdu::decode(asdu, &profile) {
        let octets = decoded.to_vec(&profile).expect("a decoded ASDU re-encodes");
        assert_eq!(octets, asdu, "re-encoding differs from the input");
        let _ = decoded.to_string();
    }
});
