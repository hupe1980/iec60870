#!/usr/bin/env bash
# Compare the distributable library API with one published crate version.
set -euo pipefail

usage() {
    echo "Usage: scripts/review-release-api.sh BASELINE_VERSION [--allow-dirty]"
}
if [[ ${1:-} == --help ]]; then usage; exit 0; fi
if [[ $# -lt 1 || $# -gt 2 || ! $1 =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.+-]+)?$ || ($# == 2 && $2 != --allow-dirty) ]]; then
    usage >&2
    exit 2
fi
baseline=$1
shift
cd "$(dirname "$0")/.."
if ! cargo semver-checks --version; then
    echo "Install the API checker with cargo install --locked cargo-semver-checks --version 0.51.0" >&2
    exit 1
fi
metadata=$(cargo metadata --locked --no-deps --format-version 1)
version=$(jq -er '.packages[] | select(.name == "iec60870") | .version' <<<"$metadata")
target=$(jq -er '.target_directory' <<<"$metadata")
# Each review retains the exact archive and extracted sources it inspected.
mkdir -p "$target/release-review"
review=$(mktemp -d "$target/release-review/run.XXXXXXXX")
cargo package --locked --target-dir "$review" "$@"
archive="$review/package/iec60870-$version.crate"
manifest="$review/package/iec60870-$version/Cargo.toml"
echo "Checkout HEAD: $(git rev-parse HEAD)"
echo "Archive SHA-256:"
shasum -a 256 "$archive"
echo "Published baseline: iec60870 $baseline"
# Keep the strict patch lens even across a major bump so intentional changes are visible.
# Run every view and return a failure if any comparison failed.
status=0
for features in --only-explicit-features --default-features --all-features; do
    echo "Reviewing $features"
    cargo semver-checks check-release --manifest-path "$manifest" --baseline-version "$baseline" --release-type patch "$features" || status=1
done
exit "$status"
