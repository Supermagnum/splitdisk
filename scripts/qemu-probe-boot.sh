#!/usr/bin/env bash
# Quick OVMF boot probe (TCG). Expects boot512.img already built at /tmp/boot512.img
set -euo pipefail
cp -f /usr/share/OVMF/OVMF_VARS_4M.fd /tmp/vars.fd
NAME=${1:-probe}
shift || true
timeout 120 qemu-system-x86_64 -machine q35 -m 1024 \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
  -drive if=pflash,format=raw,file=/tmp/vars.fd \
  "$@" \
  -nic none -display none -serial "file:/tmp/serial-${NAME}.log" -no-reboot || true
sed 's/\x1b\[[0-9;]*[a-zA-Z]//g' "/tmp/serial-${NAME}.log" | tr -d '\r' \
  | grep -E 'Linux version|SPLITDISK|BdsDxe|Shell>|Not Found|FS[0-9]|GRUB|Booting|Command line' \
  | head -50 || true
if grep -q SPLITDISK_INIT_REACHED "/tmp/serial-${NAME}.log"; then
  echo "SUCCESS ${NAME}"
else
  echo "FAIL ${NAME}"
fi
