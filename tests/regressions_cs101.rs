//! Every input the `ft12` and `cs101_link` fuzz targets once crashed on, replayed forever.
//!
//! `fuzz/regressions/ft12/<bug>.bin` and `fuzz/regressions/cs101_link/<bug>.bin` hold the
//! inputs, named after the bug; each runs through the same checks as its fuzz target.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
#![allow(clippy::doc_markdown, clippy::cast_lossless, clippy::cast_possible_truncation)]

use std::fs;
use std::path::Path;

#[path = "support/harness/cs101.rs"]
mod harness;

fn replay(dir: &str, check: fn(&[u8])) -> usize {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz").join("regressions").join(dir);
    let Ok(entries) = fs::read_dir(&dir) else {
        println!("no {} directory; nothing to replay", dir.display());
        return 0;
    };
    let mut n = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "bin") {
            check(&fs::read(&path).unwrap());
            n += 1;
        }
    }
    n
}

#[test]
fn every_committed_ft12_input_replays_cleanly() {
    println!("replayed {} ft12 inputs", replay("ft12", harness::ft12));
}

#[test]
fn every_committed_link_input_replays_cleanly() {
    println!("replayed {} cs101_link inputs", replay("cs101_link", harness::link));
}

#[test]
fn the_harness_accepts_the_shapes_it_was_written_for() {
    harness::ft12(&[0x10, 0x49, 0x01, 0x4A, 0x16]);
    harness::ft12(&[0x68, 3, 3, 0x68, 0x08, 0x01, 0x07, 0x10, 0x16, 0xE5]);
    harness::ft12(&[]);
    // Secondary, width one: reset of remote link in, a tick, a class 1 submit, a class 1 poll.
    let mut script = vec![0x01, 5 << 3, 0x10, 0x40, 0x01, 0x41, 0x16, 3 << 3 | 3];
    script.extend([(7 << 3) | 4, 1, 1, 3, 1, 1, 0, 1]);
    script.extend([5 << 3, 0x10, 0x7A, 0x01, 0x7B, 0x16]);
    harness::link(&script);
    // Primary and both balanced roles, ticking.
    for selector in [0x21, 0x41, 0x61, 0x22] {
        harness::link(&[selector, 3 | (20 << 3), 3 | (20 << 3), 3 | (31 << 3), 7 | (31 << 3)]);
    }
}
