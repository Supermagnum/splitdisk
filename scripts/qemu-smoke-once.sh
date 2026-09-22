#!/usr/bin/env bash
set -euo pipefail
cd /work
cargo build -p splitdisk-assemble --offline --release -q
cargo build -p splitdisk-image --offline --bin mk-qemu-boot-image -q
/tmp/cargo-target/debug/mk-qemu-boot-image \
  --output /tmp/boot.img \
  --assemble-bin /tmp/cargo-target/release/splitdisk-assemble \
  --size "$((512 * 1024 * 1024))"
cp /usr/share/OVMF/OVMF_VARS_4M.fd /tmp/vars.fd
timeout 120 qemu-system-x86_64 -enable-kvm -machine q35 -m 1024 \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
  -drive if=pflash,format=raw,file=/tmp/vars.fd \
  -drive if=none,id=bootusb,format=raw,file=/tmp/boot.img,readonly=on \
  -device qemu-xhci,id=xhci \
  -device usb-storage,bus=xhci.0,drive=bootusb,id=usb0,bootindex=1,removable=true \
  -nic none -display none -serial file:/tmp/serial.log -no-reboot || true
python3 - <<'PY'
import re
text = open("/tmp/serial.log", "rb").read().decode("latin1", "replace")
text = re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", "", text)
text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", text)
for needle in [
    "file `/boot/vmlinuz'",
    "not found",
    "Linux version",
    "SPLITDISK_INIT_REACHED",
    "Command line",
    "Freeing",
]:
    print(repr(needle), "->", needle in text)
print("--- tail ---")
print(text[-6000:])
PY
