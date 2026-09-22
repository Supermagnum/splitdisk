#!/usr/bin/env bash
# Inner test script executed inside the SplitDisk container image.
set -euo pipefail

cd /work

# Host-owned vendor/ trees can trip "dubious ownership" under mapped UIDs.
# HOME may be on the read-only image root; write git config to tmpfs.
export GIT_CONFIG_GLOBAL="${GIT_CONFIG_GLOBAL:-/tmp/splitdisk-gitconfig}"
git config --global --add safe.directory '*' || true

# test-hooks: reduced Argon2 / pause harness for integration tests only.
# Never pass these features to a release profile build.
HOOK_PKGS=(
  -p splitdisk-auth
  -p splitdisk-create
  -p splitdisk-assemble
)
HOOK_FEATURES=(--features test-hooks)

echo "== rustc =="
rustc --version
echo "== fmt =="
cargo fmt --all -- --check
echo "== clippy (default features) =="
cargo clippy --workspace --all-targets --offline -- -D warnings
echo "== clippy (test-hooks packages) =="
cargo clippy "${HOOK_PKGS[@]}" --all-targets --offline "${HOOK_FEATURES[@]}" -- -D warnings
echo "== Phase 4 vendor blobs (GRUB / kernel / CCID from vendor/, offline) =="
bash scripts/build-vendor-blobs.sh
echo "== kernel bzImage byte-repro check (two cold builds, same image) =="
bash scripts/verify-kernel-repro.sh
echo "== test (default features) =="
# Image layout tests embed the release assemble binary (fits fixture sizes).
cargo build -p splitdisk-assemble --offline --release
cargo test --workspace --offline
echo "== test (test-hooks packages) =="
cargo test "${HOOK_PKGS[@]}" --offline "${HOOK_FEATURES[@]}"
echo "== release CLI help has no test hooks =="
cargo build -p splitdisk-create -p splitdisk-assemble --offline --release
CREATE_BIN="${CARGO_TARGET_DIR:-target}/release/splitdisk-create"
ASSEMBLE_BIN="${CARGO_TARGET_DIR:-target}/release/splitdisk-assemble"
# Prefer CARGO_TARGET_DIR used by the container.
CREATE_BIN="/tmp/cargo-target/release/splitdisk-create"
ASSEMBLE_BIN="/tmp/cargo-target/release/splitdisk-assemble"
help_create="$("$CREATE_BIN" --help)"
help_assemble="$("$ASSEMBLE_BIN" --help)"
echo "$help_create" | grep -Eiq 'test-argon2|test_argon2' && {
  echo "FAIL: release create --help mentions test-argon2"
  exit 1
}
echo "$help_assemble" | grep -Eiq 'test-pause|test_pause|test-argon2|mock-cooldown' && {
  echo "FAIL: release assemble --help mentions a test hook"
  exit 1
}
echo "release --help OK (no test-hook flags)"
echo "== deny =="
cargo deny check licenses bans sources
echo "== all checks passed =="
