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

HAVE_VENDOR=0
if [[ -d vendor/grub/.git && -d vendor/linux/.git && -d vendor/ccid/.git && -d vendor/gnulib/.git ]]; then
  HAVE_VENDOR=1
fi

if [[ "$HAVE_VENDOR" -eq 1 ]]; then
  echo "== Phase 4/5 vendor blobs (GRUB / kernel / CCID from vendor/, offline) =="
  # Phase 5: serial console kernel options + BOOTX64-TEST-SERIAL.EFI.
  # Rebuild when the test-serial EFI is missing (older Phase 4 caches).
  GRUB_COMMIT=d38d6a1a9b79427848976f53d474392cd29c2a71
  LINUX_COMMIT=e2acc2211022246c77740d5df08265cc27eedcc5
  CCID_COMMIT=c37cf6cb42279ce9648ff7314180c866d68f9e0d
  NEED_P5=0
  if [[ ! -f "${SPLITDISK_BLOB_CACHE}/grub/${GRUB_COMMIT}/BOOTX64-TEST-SERIAL.EFI" ]]; then
    NEED_P5=1
  fi
  if [[ ! -f "${SPLITDISK_BLOB_CACHE}/.phase5-serial-kernel-v1" ]]; then
    NEED_P5=1
  fi
  # Phase 5: GRUB embedded cfg gained `search --file /boot/vmlinuz` (memdisk
  # root otherwise cannot see the ESP). Force GRUB rebuild when stamp missing.
  # Phase 6: Info.plist required for pcscd IFD bundle (OPEN-QUESTIONS (k)).
  if [[ ! -f "${SPLITDISK_BLOB_CACHE}/ccid/${CCID_COMMIT}/Info.plist" ]]; then
    NEED_P5=1
  fi
  if [[ ! -f "${SPLITDISK_BLOB_CACHE}/.phase5-grub-rdinit-v1" ]]; then
    NEED_P5=1
  fi
  if [[ "$NEED_P5" -eq 1 ]]; then
    echo "== Phase 5/6: rebuilding blobs for serial kernel + GRUB + CCID Info.plist =="
    rm -f "${SPLITDISK_BLOB_CACHE}/linux/${LINUX_COMMIT}/bzImage"
    rm -f "${SPLITDISK_BLOB_CACHE}/grub/${GRUB_COMMIT}/BOOTX64.EFI"
    rm -f "${SPLITDISK_BLOB_CACHE}/grub/${GRUB_COMMIT}/BOOTX64-TEST-SERIAL.EFI"
    rm -f "${SPLITDISK_BLOB_CACHE}/ccid/${CCID_COMMIT}/ifd-ccid.so"
    rm -f "${SPLITDISK_BLOB_CACHE}/ccid/${CCID_COMMIT}/Info.plist"
    rm -f "${SPLITDISK_BLOB_CACHE}/.phase5-serial-kernel-v1"
    rm -f "${SPLITDISK_BLOB_CACHE}/.phase5-grub-search-v1"
    rm -f "${SPLITDISK_BLOB_CACHE}/.phase5-grub-gzio-v1"
    SPLITDISK_FORCE_BLOB_REBUILD=1 bash scripts/build-vendor-blobs.sh
    touch "${SPLITDISK_BLOB_CACHE}/.phase5-serial-kernel-v1"
    touch "${SPLITDISK_BLOB_CACHE}/.phase5-grub-search-v1"
    touch "${SPLITDISK_BLOB_CACHE}/.phase5-grub-gzio-v1"
    touch "${SPLITDISK_BLOB_CACHE}/.phase5-grub-rdinit-v1"
    echo "== Phase 5/6: new blob digests (update PIN_* in vendor.rs if cargo test fails) =="
    cargo run -p splitdisk-image --offline --bin record-blob-pins || true
  else
    bash scripts/build-vendor-blobs.sh
  fi
  echo "== kernel bzImage byte-repro check (two cold builds, same image) =="
  bash scripts/verify-kernel-repro.sh
else
  echo "== Phase 4 vendor blobs: SKIPPED (vendor/{grub,linux,ccid,gnulib} not present) =="
  echo "   Local/full runs: populate vendor/ per docs/VENDORING.md, then re-run."
  echo "   CI on GitHub Actions has no multi-GiB vendor trees (gitignored)."
fi

echo "== test (default features) =="
# Image layout tests embed the release assemble binary (fits fixture sizes).
cargo build -p splitdisk-assemble --offline --release
if [[ "$HAVE_VENDOR" -eq 1 ]]; then
  cargo test --workspace --offline
else
  # Integration tests under splitdisk-image need BLAKE3-pinned vendor blobs.
  cargo test --workspace --offline --exclude splitdisk-image
  cargo test -p splitdisk-image --offline --lib --bins
fi
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

if [[ "$HAVE_VENDOR" -eq 1 ]]; then
  echo "== Phase 6: GnuPG + vpcd PC/SC functional test (container) =="
  bash scripts/pcsc-gpg-vpcd-test.sh
  echo "== Phase 6 QEMU boot-chain (assemble --agent + pcscd) =="
  cargo build -p splitdisk-image --offline --release --bin splitdisk-init \
    --target x86_64-unknown-linux-musl
  export SPLITDISK_ASSEMBLE_BIN=/tmp/cargo-target/release/splitdisk-assemble
  export SPLITDISK_BLOB_CACHE="${SPLITDISK_BLOB_CACHE:-/work/testdata/vendor-blobs}"
  export SPLITDISK_INIT_STUB=/tmp/cargo-target/x86_64-unknown-linux-musl/release/splitdisk-init
  export SPLITDISK_QEMU_WORKDIR=/tmp/splitdisk-qemu-boot
  file "$SPLITDISK_INIT_STUB" || true
  bash scripts/qemu-boot-chain.sh
else
  echo "== Phase 6 QEMU / gpg-vpcd: SKIPPED (no vendor blobs) =="
fi

echo "== deny =="
cargo deny check licenses bans sources
echo "== all checks passed =="
