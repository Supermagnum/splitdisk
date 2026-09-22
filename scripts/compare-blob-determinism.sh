#!/usr/bin/env bash
# Twice-build-and-diff vendor blobs (determinism experiment). Offline only.
# Writes run-a / run-b under $SPLITDISK_BLOB_CACHE and compares sha256.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BASE="${SPLITDISK_DET_CACHE:-/tmp/det-blobs}"
export GIT_CONFIG_GLOBAL="${GIT_CONFIG_GLOBAL:-/tmp/splitdisk-gitconfig}"
git config --global --add safe.directory '*' 2>/dev/null || true
export TZ=UTC LC_ALL=C LANG=C
export SPLITDISK_FORCE_BLOB_REBUILD=1

compare_one() {
  local name="$1" a="$2" b="$3"
  local ha hb
  ha=$(sha256sum "$a" | awk '{print $1}')
  hb=$(sha256sum "$b" | awk '{print $1}')
  echo "=== $name ==="
  echo "  A sha256=$ha  size=$(stat -c%s "$a")"
  echo "  B sha256=$hb  size=$(stat -c%s "$b")"
  if [[ "$ha" == "$hb" ]]; then
    echo "  RESULT: BYTE_IDENTICAL"
  else
    echo "  RESULT: DIFFER"
    # Helpful hints: path strings / timestamps.
    echo "  --- strings unique-ish samples (A) ---"
    strings "$a" | grep -iE 'version|/tmp/|splitdisk|utc|20[0-9]{2}' | head -20 || true
    echo "  --- cmp first differing offset ---"
    cmp -l "$a" "$b" 2>/dev/null | head -5 || true
  fi
}

for run in a b; do
  echo "######## BUILD RUN $run ########"
  export SPLITDISK_BLOB_CACHE="$BASE/run-$run"
  export SPLITDISK_BLOB_BUILD_ROOT="/tmp/splitdisk-vendor-build-$run"
  rm -rf "$SPLITDISK_BLOB_CACHE" "$SPLITDISK_BLOB_BUILD_ROOT"
  mkdir -p "$SPLITDISK_BLOB_CACHE"
  bash scripts/build-vendor-blobs.sh
done

GRUB_C=$(git -C vendor/grub rev-parse HEAD)
LINUX_C=$(git -C vendor/linux rev-parse HEAD)
CCID_C=$(git -C vendor/ccid rev-parse HEAD)

compare_one grub \
  "$BASE/run-a/grub/$GRUB_C/BOOTX64.EFI" \
  "$BASE/run-b/grub/$GRUB_C/BOOTX64.EFI"
compare_one linux \
  "$BASE/run-a/linux/$LINUX_C/bzImage" \
  "$BASE/run-b/linux/$LINUX_C/bzImage"
compare_one ccid \
  "$BASE/run-a/ccid/$CCID_C/ifd-ccid.so" \
  "$BASE/run-b/ccid/$CCID_C/ifd-ccid.so"

echo "######## kernel version strings ########"
strings "$BASE/run-a/linux/$LINUX_C/bzImage" | grep -iE 'Linux version|splitdisk' | head -10 || true
strings "$BASE/run-b/linux/$LINUX_C/bzImage" | grep -iE 'Linux version|splitdisk' | head -10 || true
