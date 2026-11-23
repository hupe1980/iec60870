//! Every input the `apci` and `cs104_link` fuzz targets once crashed on, replayed forever.
//!
//! `fuzz/regressions/apci/<bug>.bin` and `fuzz/regressions/cs104_link/<bug>.bin` hold the
//! inputs, named after the bug; each runs through the same checks as its fuzz target.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
#![allow(clippy::doc_markdown, clippy::too_many_lines, clippy::assert_is_empty, clippy::cast_lossless)]

use std::fs;
use std::path::Path;

#[path = "support/harness/cs104.rs"]
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
fn every_committed_apci_input_replays_cleanly() {
    println!("replayed {} apci inputs", replay("apci", harness::apci));
}

#[test]
fn every_committed_link_input_replays_cleanly() {
    println!("replayed {} cs104_link inputs", replay("cs104_link", harness::link));
}

#[test]
fn the_harness_accepts_the_shapes_it_was_written_for() {
    harness::apci(&[0x68, 4, 7, 0, 0, 0, 0x68, 4, 0x0B, 0, 0, 0]);
    harness::apci(&[]);
    // Controlled role: STARTDT act in, an I-frame in, a tick, a submit.
    let mut script = vec![0x01, 6 << 3, 0x68, 4, 7, 0, 0, 0];
    script.extend([16 << 3, 0x68, 14, 0, 0, 0, 0, 0x64, 1, 6, 0, 1, 0, 0, 0, 0, 0x14]);
    script.extend([(4 << 3) | 2, (9 << 3) | 3]);
    harness::link(&script);
}
