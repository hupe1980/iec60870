#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
IEC60870_ORACLE_IMAGE=$(docker build -q tests/oracle)
export IEC60870_ORACLE_IMAGE
export TSHARK="$PWD/tests/oracle/tshark"
export IEC60870_REQUIRE_FIELD_COVERAGE=1
exec cargo test --locked --test tshark_oracle -- --nocapture
