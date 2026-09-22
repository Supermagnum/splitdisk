#!/usr/bin/env bash
set -euo pipefail
cd /work
cargo build -p splitdisk-assemble --offline --release -q
cargo build -p splitdisk-image --offline --bin mk-qemu-boot-image -q
export SPLITDISK_INIT_STUB=/usr/local/share/splitdisk/init-stub
echo "stub size $(wc -c < "$SPLITDISK_INIT_STUB")"
/tmp/cargo-target/debug/mk-qemu-boot-image \
  --output /tmp/boot.img \
  --assemble-bin /tmp/cargo-target/release/splitdisk-assemble \
  --size "$((64 * 1024 * 1024))"
python3 /work/scripts/extract-init-from-img.py /tmp/boot.img
