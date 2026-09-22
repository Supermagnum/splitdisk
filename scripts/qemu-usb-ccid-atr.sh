#!/usr/bin/env bash
# Phase 6 follow-up: QEMU usb-ccid + production ifd-ccid.so ATR probe.
#
# Attaches QEMU's built-in usb-ccid + ccid-card-emulated (certificates backend)
# to the Phase 5/6 boot-chain VM and looks for serial evidence that the guest
# pcscd loaded the PRODUCTION ifd-ccid.bundle and obtained an ATR over USB.
#
# Safety: file-backed disk only, -nic none, no host /dev (optional KVM).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

WORKDIR="${SPLITDISK_QEMU_WORKDIR:-${TMPDIR:-/tmp}/splitdisk-qemu-usb-ccid}"
BLOB_CACHE="${SPLITDISK_BLOB_CACHE:-${CARGO_TARGET_DIR:-/tmp/cargo-target}/vendor-blobs}"
ASSEMBLE_BIN="${SPLITDISK_ASSEMBLE_BIN:-/tmp/cargo-target/release/splitdisk-assemble}"
OVMF_CODE="${SPLITDISK_OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}"
OVMF_VARS_SRC="${SPLITDISK_OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}"
COMMIT_GRUB="${SPLITDISK_COMMIT_GRUB:-d38d6a1a9b79427848976f53d474392cd29c2a71}"
CCID_COMMIT="${SPLITDISK_COMMIT_CCID:-c37cf6cb42279ce9648ff7314180c866d68f9e0d}"
BOOT_TIMEOUT_SEC="${SPLITDISK_QEMU_BOOT_TIMEOUT:-120}"
NSSDB="${SPLITDISK_CCID_NSSDB:-/usr/local/share/splitdisk/ccid-emulated-nssdb}"

mkdir -p "$WORKDIR" "$BLOB_CACHE"
SERIAL_LOG="$WORKDIR/serial.log"
QMP_SOCK="$WORKDIR/qmp.sock"
OVMF_VARS="$WORKDIR/OVMF_VARS.fd"
BOOT_IMG="$WORKDIR/boot.img"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "FAIL: missing command: $1" >&2
    exit 1
  }
}

need qemu-system-x86_64
test -f "$OVMF_CODE"
test -f "$OVMF_VARS_SRC"
test -x "$ASSEMBLE_BIN"
test -f "$BLOB_CACHE/grub/$COMMIT_GRUB/BOOTX64-TEST-SERIAL.EFI"
test -f "$BLOB_CACHE/ccid/$CCID_COMMIT/ifd-ccid.so"

# Confirm QEMU has the devices (no rebuild).
qemu-system-x86_64 -device help 2>&1 | grep -q 'usb-ccid' || {
  echo "FAIL: qemu lacks usb-ccid" >&2
  exit 1
}
qemu-system-x86_64 -device help 2>&1 | grep -q 'ccid-card-emulated' || {
  echo "FAIL: qemu lacks ccid-card-emulated" >&2
  exit 1
}

if [[ ! -f "$NSSDB/cert9.db" && ! -f "$NSSDB/cert8.db" ]]; then
  echo "FAIL: NSS DB missing at $NSSDB (create via scripts/build-ccid-emulated-nssdb.sh)" >&2
  exit 1
fi
echo "OK: NSS DB for ccid-card-emulated at $NSSDB"

ACCEL_ARGS=()
if [[ -r /dev/kvm && -w /dev/kvm ]]; then
  ACCEL_ARGS=(-enable-kvm)
  echo "QEMU accel: KVM"
else
  ACCEL_ARGS=(-accel tcg)
  echo "QEMU accel: TCG"
fi

echo "== stage initramfs extras (pcscd + assemble + libusb for ifd-ccid) =="
EXTRA_DIR="$WORKDIR/initramfs-extra"
bash "$ROOT/scripts/stage-initramfs-runtime.sh" \
  --out "$EXTRA_DIR" \
  --pcscd /usr/sbin/pcscd \
  --assemble "$ASSEMBLE_BIN" \
  --ccid-so "$BLOB_CACHE/ccid/$CCID_COMMIT/ifd-ccid.so"
# Drop a marker so assemble starts pcscd with --debug (serial ATR evidence).
mkdir -p "$EXTRA_DIR/etc"
: >"$EXTRA_DIR/etc/splitdisk-pcscd-debug"
export SPLITDISK_INITRAMFS_EXTRA="$EXTRA_DIR"
export SPLITDISK_BLOB_CACHE="$BLOB_CACHE"
export SPLITDISK_INIT_STUB="${SPLITDISK_INIT_STUB:-/usr/local/share/splitdisk/init-stub}"

echo "== build boot image =="
cargo run -p splitdisk-image --offline --bin mk-qemu-boot-image -- \
  --output "$BOOT_IMG" \
  --assemble-bin "$ASSEMBLE_BIN" \
  --size "$((512 * 1024 * 1024))"

cp -f "$OVMF_VARS_SRC" "$OVMF_VARS"
rm -f "$QMP_SOCK" "$SERIAL_LOG"
: >"$SERIAL_LOG"

# sql: path for NSS — QEMU wants sql:$DIR
NSS_SQL="sql:${NSSDB}"

echo "== start QEMU with usb-ccid + ccid-card-emulated =="
QEMU_ERR="$WORKDIR/qemu-stderr.log"
: >"$QEMU_ERR"
qemu-system-x86_64 \
  -machine q35 \
  -m 512 \
  "${ACCEL_ARGS[@]}" \
  -drive "if=pflash,format=raw,readonly=on,file=${OVMF_CODE}" \
  -drive "if=pflash,format=raw,file=${OVMF_VARS}" \
  -drive "if=none,id=bootusb,format=raw,file=${BOOT_IMG},readonly=on" \
  -device "qemu-xhci,id=xhci" \
  -device "usb-storage,bus=xhci.0,drive=bootusb,id=usb0,bootindex=1,removable=true" \
  -device "usb-ccid,bus=xhci.0,id=ccid0" \
  -device "ccid-card-emulated,backend=certificates,db=${NSS_SQL},cert1=id-cert,cert2=signing-cert,cert3=encryption-cert,debug=4" \
  -nic none \
  -display none \
  -serial "file:${SERIAL_LOG}" \
  -qmp "unix:${QMP_SOCK},server,wait=off" \
  2>"$QEMU_ERR" &
QEMU_PID=$!

cleanup() {
  if kill -0 "$QEMU_PID" 2>/dev/null; then
    kill "$QEMU_PID" 2>/dev/null || true
    wait "$QEMU_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

t0=$(date +%s)
while true; do
  if [[ -f "$SERIAL_LOG" ]] && grep -aqF "SPLITDISK_PCSCD_STARTED" "$SERIAL_LOG"; then
    break
  fi
  if ! kill -0 "$QEMU_PID" 2>/dev/null; then
    echo "FAIL: QEMU exited before PCSCD_STARTED" >&2
    cat "$SERIAL_LOG" >&2 || true
    exit 1
  fi
  if (( $(date +%s) - t0 >= BOOT_TIMEOUT_SEC )); then
    echo "FAIL: timeout waiting for SPLITDISK_PCSCD_STARTED" >&2
    tail -n 200 "$SERIAL_LOG" >&2 || true
    exit 1
  fi
  sleep 1
done
echo "OK: reached SPLITDISK_PCSCD_STARTED"

# Give USB enumeration + ifd-ccid probe time.
sleep 8

echo "== serial evidence (CCID / ATR / USB) =="
grep -aE 'SPLITDISK_|usb-ccid|CCID|ifd-ccid|libccid|Card ATR|ATR:|smart card|usb [0-9]|idVendor|08e6|08E6|Gemplus|QEMU USB|Open Port|init failed|hotplug' "$SERIAL_LOG" | head -n 100 || true

echo "---- QEMU host stderr (card emulator) ----"
cat "${QEMU_ERR:-/dev/null}" 2>/dev/null | head -n 80 || true

echo "---- full SPLITDISK_ lines ----"
grep -a 'SPLITDISK_' "$SERIAL_LOG" | head -n 40 || true

# Success criteria: production bundle OK + some ATR / ifd-ccid activity.
if ! grep -aqF "SPLITDISK_PCSCD_CCID_BUNDLE_OK" "$SERIAL_LOG"; then
  echo "FAIL: production ifd-ccid.bundle not reported present" >&2
  exit 1
fi
echo "OK: production ifd-ccid.bundle present in guest"

ATR_HIT=0
if grep -aEi 'Card ATR:|ATR:|Got ATR|ifdhandler.*ATR' "$SERIAL_LOG" >/dev/null; then
  ATR_HIT=1
  echo "OK: ATR-related lines present in serial"
  grep -aEi 'Card ATR:|ATR:|Got ATR' "$SERIAL_LOG" | head -n 20
fi
DRIVER_HIT=0
if grep -aEi 'ifd-ccid|libccid\.so|/ifd-ccid\.bundle/' "$SERIAL_LOG" >/dev/null; then
  DRIVER_HIT=1
  echo "OK: ifd-ccid path referenced in serial"
  grep -aEi 'ifd-ccid|libccid|Open Port|init failed|Adding USB device' "$SERIAL_LOG" | head -n 30
fi
USB_HIT=0
if grep -aEi 'usb .*ccid|new .*USB device|idVendor=08e6|CCID' "$SERIAL_LOG" >/dev/null; then
  USB_HIT=1
  echo "OK: USB/CCID enumeration evidence in serial"
fi
OPEN_FAIL=0
if grep -aqF 'Open Port' "$SERIAL_LOG"; then
  OPEN_FAIL=1
  echo "NOTE: ifd-ccid Open Port failure seen (driver loaded, channel open failed)"
fi

if [[ "$ATR_HIT" -eq 1 && "$DRIVER_HIT" -eq 1 ]]; then
  echo "== PASS: production ifd-ccid.so path obtained ATR via QEMU usb-ccid =="
  exit 0
fi

echo "== INCONCLUSIVE / FAIL detail =="
echo "ATR_HIT=$ATR_HIT DRIVER_HIT=$DRIVER_HIT USB_HIT=$USB_HIT OPEN_FAIL=$OPEN_FAIL"
echo "Reporting gap status rather than forcing a false pass."
exit 2
