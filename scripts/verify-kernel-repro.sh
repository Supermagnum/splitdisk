#!/usr/bin/env bash
# Verify Linux bzImage is byte-identical across two cold O= builds (same Docker image).
# GRUB/CCID are not checked here (see OPEN-QUESTIONS (j)).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export GIT_CONFIG_GLOBAL="${GIT_CONFIG_GLOBAL:-/tmp/splitdisk-gitconfig}"
git config --global --add safe.directory '*' 2>/dev/null || true
export TZ=UTC LC_ALL=C LANG=C
export SPLITDISK_FORCE_BLOB_REBUILD=1

LINUX_C="$(git -C vendor/linux rev-parse HEAD)"
BASE="${SPLITDISK_KERNEL_REPRO_CACHE:-/tmp/kernel-repro}"
rm -rf "$BASE"

for run in a b; do
  export SPLITDISK_BLOB_CACHE="$BASE/run-$run"
  export SPLITDISK_BLOB_BUILD_ROOT="/tmp/splitdisk-kernel-build-$run"
  export SPLITDISK_BUILD_ONLY=linux
  rm -rf "$SPLITDISK_BLOB_CACHE" "$SPLITDISK_BLOB_BUILD_ROOT"
  mkdir -p "$SPLITDISK_BLOB_CACHE"
  bash scripts/build-vendor-blobs.sh
done

A="$BASE/run-a/linux/$LINUX_C/bzImage"
B="$BASE/run-b/linux/$LINUX_C/bzImage"
if cmp -s "$A" "$B"; then
  echo "kernel repro: BYTE_IDENTICAL"
else
  echo "kernel repro: DIFFER" >&2
  cmp -l "$A" "$B" | head -5 >&2
  exit 1
fi
