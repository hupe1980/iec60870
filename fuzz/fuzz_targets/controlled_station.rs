//! A controlled station fed a script of arbitrary ASDUs, raw octets, ticks, updates and
//! reconnections.
#![no_main]

#[path = "../../tests/support/harness/station.rs"]
mod harness;

libfuzzer_sys::fuzz_target!(|data: &[u8]| harness::station(data));
