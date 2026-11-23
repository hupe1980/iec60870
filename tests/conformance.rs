//! The executable conformance case list.
//!
//! Every case in `tests/conformance/cases.rs` names the test functions that cover it, or the
//! reason it is uncovered. This target checks that every named test exists — so renaming or
//! deleting a test that a case relies on fails here, naming the case — that every case is
//! covered or explained, that the ids are our own and unique, and that no case id of the
//! conformance test specifications is filled in while they are not held. It then writes the
//! coverage table as Markdown to `target/conformance/coverage.md` (or to `$CONFORMANCE_TABLE`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

#[path = "conformance/cases.rs"]
mod cases;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use cases::{CASES, Evidence};

/// Whether IEC TS 60870-5-604/-601 are held; until they are, no case carries one of their ids.
const CONFORMANCE_SPECIFICATIONS_HELD: bool = false;

/// The id areas: the ASDU codec, the 104 link, the stations, the 101 link, the stations over
/// 101, and the security extensions.
const AREAS: [&str; 6] = ["ASDU-", "104-LINK-", "STA-", "101-LINK-", "101-STA-", "SEC-"];

/// The `#[test]` (and `#[tokio::test]`) function names in `tests/<file>.rs`.
fn test_functions(file: &str) -> BTreeSet<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join(format!("{file}.rs"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut names = BTreeSet::new();
    let mut armed = false;
    for line in text.lines().map(str::trim) {
        if line.starts_with("#[test]") || line.starts_with("#[tokio::test") {
            armed = true;
        } else if armed && let Some(at) = line.find("fn ") {
            let name: String = line[at + 3..].chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
            names.insert(name);
            armed = false;
        }
    }
    names
}

#[test]
fn every_named_test_exists() {
    let mut files: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    let mut missing = Vec::new();
    for case in CASES {
        for r in case.tests {
            let names = files.entry(r.file).or_insert_with(|| test_functions(r.file));
            if !names.contains(r.name) {
                missing.push(format!("{}: tests/{}.rs has no test `{}`", case.id, r.file, r.name));
            }
        }
    }
    assert!(missing.is_empty(), "the conformance case list names tests that do not exist:\n{}", missing.join("\n"));
}

/// A third-party check that no case names is evidence nobody can find: every test in an
/// interop or tshark target belongs to at least one case.
#[test]
fn every_third_party_test_belongs_to_a_case() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let named: BTreeSet<(&str, &str)> = CASES.iter().flat_map(|c| c.tests.iter().map(|r| (r.file, r.name))).collect();
    let mut orphans = Vec::new();
    for entry in std::fs::read_dir(&dir).unwrap().flatten() {
        let path = entry.path();
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else { continue };
        if path.extension().is_none_or(|e| e != "rs") || !matches!(Evidence::of(stem), Evidence::Interop | Evidence::Oracle) {
            continue;
        }
        for name in test_functions(stem) {
            if !named.contains(&(stem, name.as_str())) {
                orphans.push(format!("tests/{stem}.rs: `{name}`"));
            }
        }
    }
    orphans.sort();
    assert!(orphans.is_empty(), "add these interop/oracle tests to a case in tests/conformance/cases.rs:\n{}", orphans.join("\n"));
}

#[test]
fn every_case_is_covered_or_explained() {
    for case in CASES {
        assert!(!case.tests.is_empty() || case.gap.is_some(), "{} has neither a test nor a reason", case.id);
        assert!(!case.procedure.trim().is_empty(), "{} has no procedure", case.id);
        if let Some(g) = &case.gap {
            assert!(!g.note.trim().is_empty(), "{} names a gap without saying what is missing", case.id);
        }
        let mut seen = BTreeSet::new();
        for r in case.tests {
            assert!(seen.insert((r.file, r.name)), "{} names {}::{} twice", case.id, r.file, r.name);
        }
    }
}

#[test]
fn case_ids_are_ours_and_unique() {
    let mut ids = BTreeSet::new();
    for case in CASES {
        assert!(ids.insert(case.id), "duplicate case id {}", case.id);
        let rest = AREAS.iter().find_map(|a| case.id.strip_prefix(a)).unwrap_or_else(|| panic!("{} is not in an area {AREAS:?}", case.id));
        assert!(
            !rest.is_empty() && rest.split('-').all(|w| !w.is_empty() && w.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())),
            "{} is not <AREA>-<WORD>[-<WORD>…] in upper case",
            case.id
        );
        if !CONFORMANCE_SPECIFICATIONS_HELD {
            assert!(case.ts_id.is_none(), "{} carries a TS case id, but the specifications are not held", case.id);
        }
    }
}

#[test]
fn evidence_is_classified_by_target_name() {
    assert_eq!(Evidence::of("interop_station"), Evidence::Interop);
    assert_eq!(Evidence::of("tshark_apci"), Evidence::Oracle);
    assert_eq!(Evidence::of("regressions_cs104"), Evidence::Fuzz);
    assert_eq!(Evidence::of("cs101_simulation"), Evidence::Simulation);
    assert_eq!(Evidence::of("station_controlled"), Evidence::Unit);
}

#[test]
fn the_coverage_table_is_written() {
    let table = cases::markdown(CASES);
    for case in CASES {
        assert!(table.contains(&format!("| `{}` |", case.id)), "{} is missing from the table", case.id);
    }
    let path = std::env::var_os("CONFORMANCE_TABLE").map_or_else(
        || Path::new(env!("CARGO_TARGET_TMPDIR")).parent().unwrap_or(Path::new(env!("CARGO_TARGET_TMPDIR"))).join("conformance").join("coverage.md"),
        PathBuf::from,
    );
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).unwrap();
    }
    std::fs::write(&path, &table).unwrap();
    let s = cases::summary(CASES);
    println!(
        "{} cases: {} covered, {} covered with a gap, {} uncovered, {} with lib60870-C interop; table: {}",
        s.cases,
        s.covered,
        s.partial,
        s.uncovered,
        s.interop,
        path.display()
    );
}
