//! `Cs104Link` in either role fed a script of arbitrary chunks, ticks and commands.
#![no_main]

#[path = "../../tests/support/harness/cs104.rs"]
mod harness;

libfuzzer_sys::fuzz_target!(|data: &[u8]| harness::link(data));
