//! The one way every Wireshark oracle finds `tshark`.
//!
//! `TSHARK` names the binary (default `tshark` on the `PATH`). Without it the oracle skips with
//! a message — unless `IEC60870_REQUIRE_TSHARK=1`, which CI sets, and which turns a missing
//! binary, or one older than the release the oracles were written against, into a failure: an
//! oracle that can quietly stop running is not an oracle.

#![allow(dead_code)]

use std::process::Command;

/// The oldest release the oracles' expectations were measured against.
pub const MIN_VERSION: (u32, u32) = (4, 6);

/// Whether `IEC60870_REQUIRE_TSHARK=1` is set.
pub fn required() -> bool {
    std::env::var("IEC60870_REQUIRE_TSHARK").as_deref() == Ok("1")
}

/// The `major.minor` in the first line of `tshark --version`, e.g. `TShark (Wireshark) 4.6.9 (…)`.
pub fn parse_version(banner: &str) -> Option<(u32, u32)> {
    let line = banner.lines().next()?;
    let word = line.split_whitespace().find(|w| w.chars().next().is_some_and(|c| c.is_ascii_digit()) && w.contains('.'))?;
    let mut parts = word.split('.');
    Some((parts.next()?.parse().ok()?, parts.next()?.trim_end_matches(|c: char| !c.is_ascii_digit()).parse().ok()?))
}

/// The binary to run, or `None` (skip) when it is absent and not required.
///
/// `oracle` names the caller in the skip message.
pub fn tshark(oracle: &str) -> Option<String> {
    let bin = std::env::var("TSHARK").unwrap_or_else(|_| "tshark".into());
    match Command::new(&bin).arg("--version").output() {
        Ok(o) if o.status.success() => {
            let banner = String::from_utf8_lossy(&o.stdout);
            match parse_version(&banner) {
                Some(v) if v >= MIN_VERSION => {}
                found => {
                    let (major, minor) = MIN_VERSION;
                    assert!(!required(), "IEC60870_REQUIRE_TSHARK=1 but {bin} is {found:?}, older than {major}.{minor} (or unreadable): {banner}");
                    println!("note: {bin} reports {found:?}; the {oracle} was written against {major}.{minor} or newer");
                }
            }
            Some(bin)
        }
        _ => {
            assert!(!required(), "IEC60870_REQUIRE_TSHARK=1 but `{bin}` was not found");
            println!("skipped: `{bin}` not found; the {oracle} needs tshark (set IEC60870_REQUIRE_TSHARK=1 to make this a failure)");
            None
        }
    }
}
