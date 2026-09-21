#!/usr/bin/env bash
# Inner test script executed inside the SplitDisk container image.
set -euo pipefail

cd /work

echo "== rustc =="
rustc --version
echo "== fmt =="
cargo fmt --all -- --check
echo "== clippy =="
cargo clippy --workspace --all-targets --offline -- -D warnings
echo "== test =="
cargo test --workspace --offline
echo "== deny =="
# Advisories need a writable DB + network to refresh; under --network none /
# --read-only we check licenses, bans, and sources. Advisories can be run
# separately when a writable DB is available.
cargo deny check licenses bans sources
echo "== all checks passed =="
