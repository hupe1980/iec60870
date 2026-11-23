//! FT 1.2 frames: `Frame::decode` and `FrameSplitter` on arbitrary octets under every address
//! width — never panic, and whatever decodes re-encodes to exactly the input.
#![no_main]

#[path = "../../tests/support/harness/cs101.rs"]
mod harness;

libfuzzer_sys::fuzz_target!(|data: &[u8]| harness::ft12(data));
