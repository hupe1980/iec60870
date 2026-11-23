//! `Asdu::decode` under the IEC 60870-5-104 profile: never panics, and whatever it accepts
//! re-encodes to exactly the input.
#![no_main]

use iec60870::{Asdu, Profile};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let profile = Profile::IEC104;
    if let Ok(asdu) = Asdu::decode(data, &profile) {
        let octets = asdu.to_vec(&profile).expect("a decoded ASDU re-encodes");
        assert_eq!(octets, data, "re-encoding differs from the input");
        let _ = asdu.to_string();
    }
});
