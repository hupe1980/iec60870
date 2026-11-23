+++
title = "Conformance coverage"
description = "Look up the evidence for an IEC 101 or 104 procedure and see which checks are still open."
weight = 3
[extra]
conformance_report = true
+++

## Read the evidence

Search by case ID, role, procedure or test name. The Role column identifies which side of the protocol the procedure describes. Use the evidence columns to see which implementations were exercised. The Wireshark column identifies checks of the encoded fields. The lib60870-C column identifies exchanges with an independent peer. The Gap column records missing evidence, including procedures that still need a physical outstation.

The case IDs belong to this project. Formal IEC test-suite mapping and laboratory certification are pending.

The [interoperability statement](@/docs/pics.md) lists what each station reports for an individual ASDU type and the defaults used to configure a peer.

## Reproduce the report

```sh
cargo test --locked --test conformance -- --nocapture
```

This checks the case list and writes `target/conformance/coverage.md`. To exercise the referenced tests with Docker and tshark 4.6 or newer, run the full suite from a checkout.

```sh
IEC60870_REQUIRE_INTEROP=1 IEC60870_REQUIRE_TSHARK=1 cargo test --locked --all-features
```

For field-by-field checks of packed status, protection events, parameter activation and file transfer, run `scripts/test-field-oracle.sh`. The first run builds the pinned Wireshark source with Docker. Subsequent runs reuse Docker's build cache. The check fails if any typed IEC 104 ASDU except the read command falls back to raw bytes. The read command carries only an information object address.

## Review the packaged Rust API

From a checkout, install the reviewer with `cargo install --locked cargo-semver-checks --version 0.51.0`, then run `scripts/review-release-api.sh 0.1.0`. The script prints the archive path, its SHA-256 digest and the published baseline. It checks the library with no optional features, default features and all features. Supply `--allow-dirty` to review local edits; use the archive digest to identify that exact build.

The patch-level comparison reports incompatible changes even across a planned major version bump. Review those findings alongside the changelog. The published 0.1.0 baseline contains only a name reservation, so the first protocol implementation still needs a manual API review. CLI behavior and wire interoperability have separate test suites.

## Procedure coverage

[Download the Markdown table](../../conformance.md). On a narrow screen, scroll the evidence table horizontally.
