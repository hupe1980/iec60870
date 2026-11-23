//! Every input the `controlled_station` fuzz target once crashed on, replayed forever, and a
//! few hand-written scripts through the same harness.
//!
//! `fuzz/regressions/controlled_station/<bug>.bin` holds the inputs, named after the bug.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
#![allow(clippy::assert_is_empty, clippy::too_many_lines, clippy::doc_markdown, clippy::cast_lossless, clippy::cast_precision_loss, clippy::similar_names)]

use std::fs;
use std::path::Path;

#[path = "support/harness/station.rs"]
mod harness;

#[test]
fn every_committed_controlled_station_input_replays_cleanly() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz").join("regressions").join("controlled_station");
    let mut n = 0;
    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "bin") {
                harness::station(&fs::read(&path).unwrap());
                n += 1;
            }
        }
    }
    println!("replayed {n} controlled_station inputs");
}

#[test]
fn hand_written_scripts_run_cleanly() {
    // STARTDT is sent by the harness's master; a GI, an SBO select and execute, a storm of
    // updates, time, a reconnection.
    let gi = [0x64, 0x01, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x14];
    let select = [0x2D, 0x01, 0x06, 0x00, 0x01, 0x00, 0x0A, 0x00, 0x00, 0x81];
    let execute = [0x2D, 0x01, 0x06, 0x00, 0x01, 0x00, 0x0A, 0x00, 0x00, 0x01];
    let mut script = Vec::new();
    for asdu in [&gi[..], &select, &execute] {
        script.extend([0, asdu.len() as u8]);
        script.extend(asdu);
    }
    for i in 0..100u8 {
        script.extend([4, 2, i % 7, i]);
    }
    script.extend([3, 1, 200, 5, 1, 1, 0, 10]);
    script.extend(&gi);
    harness::station(&script);
    harness::station(&[]);
    harness::station(&[2, 6, 0x68, 0x04, 0x07, 0, 0, 0]);
}
