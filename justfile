set positional-arguments

# List available recipes.
default:
    @just --list

# Build the library with its default features.
build:
    cargo build --locked

# Format Rust sources.
fmt:
    cargo fmt --all

# Verify formatting without editing files.
fmt-check:
    cargo fmt --all --check

# Lint all features and targets with warnings treated as errors.
lint:
    cargo clippy --locked --all-targets --all-features -- -D warnings

# Run the all-features test suite, optionally passing arguments to cargo test.
test *args:
    cargo test --locked --all-features "$@"

# Run formatting, lint, and test checks.
check: fmt-check lint test

# Run the CLI from the checkout, including TLS and serial support.
cli *args:
    cargo run --locked --features cli,tls,serial --bin iec60870 -- "$@"

# Require independent peer and dissector evidence (Docker and tshark).
interop:
    IEC60870_REQUIRE_INTEROP=1 IEC60870_REQUIRE_TSHARK=1 cargo test --locked --all-features

# Cross-build for Cortex-M4F and run the embedded example's host tests.
embedded:
    cargo build --locked --no-default-features --features cs104,cs101,file-transfer --target thumbv7em-none-eabihf
    cargo build --locked --manifest-path examples/embedded/Cargo.toml --target thumbv7em-none-eabihf
    cargo test --locked --manifest-path examples/embedded/Cargo.toml

# Check all features and targets on the minimum supported Rust version.
msrv:
    cargo +1.88.0 check --locked --all-features --all-targets

# Check dependency advisories, licenses, bans, and sources with cargo-deny.
deny:
    cargo deny --locked check

# Generate the all-features Rust API reference.
docs:
    RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps --all-features

# Build the documentation site with Zola.
site:
    zola --root site build

# Preview the documentation site with live reload.
serve:
    zola --root site serve

# Regenerate the published PICS and conformance table after intentional changes.
refresh-conformance:
    IEC60870_BLESS=1 cargo test --locked --all-features --test pics
    CONFORMANCE_TABLE=site/static/conformance.md cargo test --locked --all-features --test conformance
