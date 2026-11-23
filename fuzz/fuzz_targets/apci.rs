//! The APCI decoder and the streaming frame splitter on arbitrary octets.
#![no_main]

#[path = "../../tests/support/harness/cs104.rs"]
mod harness;

libfuzzer_sys::fuzz_target!(|data: &[u8]| harness::apci(data));
