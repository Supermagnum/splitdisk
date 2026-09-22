#!/usr/bin/env bash
# Phase 5: QEMU UEFI boot-chain smoke + USB hot-plug (QMP) + reset re-boot.
#
# Safety:
# - File-backed disks only under testdata/ (or TMPDIR). Never /dev on the host.
# - Guest network disabled (-nic none).
# - KVM used only if /dev/kvm is usable; otherwise TCG.
#
# Test-only console visibility:
# - Uses BOOTX64-TEST-SERIAL.EFI (built beside production BOOTX64.EFI) plus
#   GRUB_CFG_TEST_SERIAL on the ESP. Production BOOTX64.EFI and GRUB_CFG stay quiet.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MARKER="SPLITDISK_ASSEMBLE_STARTED"
MARKER_PCSCD="SPLITDISK_PCSCD_STARTED"
MARKER_INIT="SPLITDISK_INIT_MOUNTS_OK"
# Primary wait target: pcscd start (or fail) after assemble --agent.
# Waiting only for ASSEMBLE_STARTED raced the 500ms pcscd settle sleep.
MARKER_WAIT="${SPLITDISK_QEMU_WAIT_MARKER:-SPLITDISK_PCSCD_STARTED}"
BOOT_TIMEOUT_SEC="${SPLITDISK_QEMU_BOOT_TIMEOUT:-180}"
WORKDIR="${SPLITDISK_QEMU_WORKDIR:-${TMPDIR:-/tmp}/splitdisk-qemu-boot}"
BLOB_CACHE="${SPLITDISK_BLOB_CACHE:-${CARGO_TARGET_DIR:-/tmp/cargo-target}/vendor-blobs}"
ASSEMBLE_BIN="${SPLITDISK_ASSEMBLE_BIN:-/tmp/cargo-target/release/splitdisk-assemble}"
OVMF_CODE="${SPLITDISK_OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}"
OVMF_VARS_SRC="${SPLITDISK_OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}"
COMMIT_GRUB="${SPLITDISK_COMMIT_GRUB:-d38d6a1a9b79427848976f53d474392cd29c2a71}"

mkdir -p "$WORKDIR" "$BLOB_CACHE"
SERIAL_LOG="$WORKDIR/serial.log"
SERIAL_HOTPLUG="$WORKDIR/serial-hotplug.log"
SERIAL_RESET="$WORKDIR/serial-reset.log"
QMP_SOCK="$WORKDIR/qmp.sock"
OVMF_VARS="$WORKDIR/OVMF_VARS.fd"
BOOT_IMG="$WORKDIR/boot.img"
HOTPLUG_IMG="$WORKDIR/hotplug.img"
TIMING_FILE="$WORKDIR/timing.txt"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "FAIL: missing command: $1" >&2
    exit 1
  }
}

need qemu-system-x86_64
need python3
test -f "$OVMF_CODE" || {
  echo "FAIL: OVMF code missing at $OVMF_CODE" >&2
  exit 1
}
test -f "$OVMF_VARS_SRC" || {
  echo "FAIL: OVMF vars missing at $OVMF_VARS_SRC" >&2
  exit 1
}
test -x "$ASSEMBLE_BIN" || {
  echo "FAIL: assemble binary missing at $ASSEMBLE_BIN (build release first)" >&2
  exit 1
}
test -f "$BLOB_CACHE/grub/$COMMIT_GRUB/BOOTX64-TEST-SERIAL.EFI" || {
  echo "FAIL: missing BOOTX64-TEST-SERIAL.EFI — run scripts/build-vendor-blobs.sh" >&2
  exit 1
}

ACCEL_ARGS=()
ACCEL_MODE="tcg"
# SPLITDISK_QEMU_ACCEL=tcg|kvm forces a mode (for timing docs / CI without KVM).
case "${SPLITDISK_QEMU_ACCEL:-auto}" in
tcg)
  ACCEL_ARGS=(-accel tcg)
  ACCEL_MODE="tcg"
  echo "QEMU accel: TCG (forced via SPLITDISK_QEMU_ACCEL=tcg)"
  ;;
kvm)
  ACCEL_ARGS=(-enable-kvm)
  ACCEL_MODE="kvm"
  echo "QEMU accel: KVM (forced via SPLITDISK_QEMU_ACCEL=kvm)"
  ;;
*)
  if [[ -r /dev/kvm ]] && [[ -w /dev/kvm ]]; then
    ACCEL_ARGS=(-enable-kvm)
    ACCEL_MODE="kvm"
    echo "QEMU accel: KVM (/dev/kvm usable)"
  else
    ACCEL_ARGS=(-accel tcg)
    ACCEL_MODE="tcg"
    echo "QEMU accel: TCG (no usable /dev/kvm in this environment)"
  fi
  ;;
esac

echo "== Phase 6: build QEMU boot test image =="
export SPLITDISK_BLOB_CACHE="$BLOB_CACHE"
export SPLITDISK_INIT_STUB="${SPLITDISK_INIT_STUB:-/usr/local/share/splitdisk/init-stub}"
# Stage pcscd + assemble dynamic linker/libs into the initramfs extra tree.
# (Dereferenced copies; overlays any incomplete Docker-baked pcsc-runtime.)
EXTRA_DIR="$WORKDIR/initramfs-extra"
bash "$ROOT/scripts/stage-initramfs-runtime.sh" \
  --out "$EXTRA_DIR" \
  --pcscd /usr/sbin/pcscd \
  --assemble "$ASSEMBLE_BIN"
export SPLITDISK_INITRAMFS_EXTRA="$EXTRA_DIR"
cargo run -p splitdisk-image --offline --bin mk-qemu-boot-image -- \
  --output "$BOOT_IMG" \
  --assemble-bin "$ASSEMBLE_BIN" \
  --size "$((512 * 1024 * 1024))"

# Second file-backed "USB" for hot-plug (minimal FAT-like content not required).
truncate -s 8M "$HOTPLUG_IMG"

cp -f "$OVMF_VARS_SRC" "$OVMF_VARS"

qmp_send() {
  # $1 = socket path; remaining args joined as one QMP JSON command line after capabilities.
  local sock=$1
  shift
  python3 - "$sock" "$@" <<'PY'
import json, socket, sys, time

sock_path = sys.argv[1]
cmds = sys.argv[2:]

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
deadline = time.time() + 30
while True:
    try:
        s.connect(sock_path)
        break
    except OSError:
        if time.time() > deadline:
            raise
        time.sleep(0.1)

def recv_obj():
    buf = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            raise RuntimeError("QMP connection closed")
        buf += chunk
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            line = line.strip()
            if not line:
                continue
            return json.loads(line.decode())

# greeting
recv_obj()
s.sendall(b'{"execute":"qmp_capabilities"}\n')
recv_obj()
for c in cmds:
    s.sendall((c + "\n").encode())
    resp = recv_obj()
    # Skip asynchronous events until we get a return/error.
    while "return" not in resp and "error" not in resp:
        resp = recv_obj()
    if "error" in resp:
        print("QMP error for", c, "->", resp, file=sys.stderr)
        sys.exit(1)
    print("QMP OK:", c[:80], "...", sep=" " if len(c) > 80 else "")
s.close()
PY
}

wait_for_marker() {
  local log=$1
  local timeout=$2
  local label=$3
  local needle=${4:-$MARKER_WAIT}
  local t0
  t0=$(date +%s)
  while true; do
    if [[ -f "$log" ]]; then
      if grep -aqF "$needle" "$log"; then
        local t1
        t1=$(date +%s)
        echo "$label: reached $needle in $((t1 - t0))s (accel=$ACCEL_MODE)"
        echo "${label}_seconds=$((t1 - t0)) accel=$ACCEL_MODE" >>"$TIMING_FILE"
        return 0
      fi
      # Fail fast if pcscd reported failure while waiting for start.
      if [[ "$needle" == "$MARKER_PCSCD" ]] && grep -aqF "SPLITDISK_PCSCD_FAIL" "$log"; then
        echo "FAIL: SPLITDISK_PCSCD_FAIL while waiting for $needle ($label)" >&2
        grep -a 'SPLITDISK_' "$log" | head -n 40 >&2 || true
        kill "$QEMU_PID" 2>/dev/null || true
        wait "$QEMU_PID" 2>/dev/null || true
        exit 1
      fi
    fi
    if ! kill -0 "$QEMU_PID" 2>/dev/null; then
      echo "FAIL: QEMU exited before $needle ($label)" >&2
      echo "---- serial log ----" >&2
      cat "$log" >&2 || true
      exit 1
    fi
    now=$(date +%s)
    if (( now - t0 >= timeout )); then
      echo "FAIL: timeout ${timeout}s waiting for $needle ($label)" >&2
      echo "---- serial log (tail) ----" >&2
      tail -n 200 "$log" >&2 || true
      kill "$QEMU_PID" 2>/dev/null || true
      wait "$QEMU_PID" 2>/dev/null || true
      exit 1
    fi
    sleep 1
  done
}

start_qemu() {
  local serial_path=$1
  rm -f "$QMP_SOCK" "$serial_path"
  : >"$serial_path"
  local cmd=(
    qemu-system-x86_64
    -machine q35
    -m 512
    "${ACCEL_ARGS[@]}"
    -drive "if=pflash,format=raw,readonly=on,file=${OVMF_CODE}"
    -drive "if=pflash,format=raw,file=${OVMF_VARS}"
    -drive "if=none,id=bootusb,format=raw,file=${BOOT_IMG},readonly=on"
    -device "qemu-xhci,id=xhci"
    -device "usb-storage,bus=xhci.0,drive=bootusb,id=usb0,bootindex=1,removable=true"
    -nic none
    -display none
    -serial "file:${serial_path}"
    -qmp "unix:${QMP_SOCK},server,wait=off"
  )
  # Note: do not pass -no-reboot — Phase 5.3 uses QMP system_reset, which
  # would exit the process under -no-reboot instead of rebooting the guest.
  "${cmd[@]}" &
  QEMU_PID=$!
}

stop_qemu() {
  if [[ -n "${QEMU_PID:-}" ]] && kill -0 "$QEMU_PID" 2>/dev/null; then
    qmp_send "$QMP_SOCK" '{"execute":"quit"}' || kill "$QEMU_PID" 2>/dev/null || true
    wait "$QEMU_PID" 2>/dev/null || true
  fi
  QEMU_PID=""
}

assert_boot_chain() {
  local log=$1
  echo "== assert boot-chain markers in $log =="
  if ! grep -aEiq 'Linux version|Command line:|Kernel command line|Freeing unused kernel|initramfs|Unpacking initramfs|SPLITDISK' "$log"; then
    echo "FAIL: no kernel boot evidence in serial log" >&2
    cat "$log" >&2 || true
    exit 1
  fi
  if ! grep -aqF "$MARKER_INIT" "$log"; then
    echo "FAIL: missing $MARKER_INIT (/init mounts)" >&2
    exit 1
  fi
  if ! grep -aqF "$MARKER" "$log"; then
    echo "FAIL: missing $MARKER (assemble --agent)" >&2
    exit 1
  fi
  if grep -aqF "$MARKER_PCSCD" "$log"; then
    echo "OK: pcscd started ($MARKER_PCSCD)"
  elif grep -aqF "SPLITDISK_PCSCD_FAIL" "$log"; then
    echo "FAIL: pcscd failed to start (see SPLITDISK_PCSCD_FAIL in serial)" >&2
    grep -a 'SPLITDISK_PCSCD' "$log" | head -n 20 >&2 || true
    exit 1
  else
    echo "FAIL: neither $MARKER_PCSCD nor SPLITDISK_PCSCD_FAIL in serial" >&2
    exit 1
  fi
  if grep -aEiq 'Linux version' "$log"; then
    echo "OK: kernel booted (Linux version line present)"
  fi
  if grep -aEiq 'initramfs|Unpacking|Freeing initrd' "$log"; then
    echo "OK: initramfs unpack evidence present"
  fi
  echo "OK: /init mounted and exec'd assemble ($MARKER_INIT + $MARKER)"
  echo "---- evidence excerpts ----"
  grep -aE 'Linux version|Command line:|Unpacking|SPLITDISK_' "$log" | head -n 60 || true
}

: >"$TIMING_FILE"

echo "== Phase 5.1: cold boot-chain smoke =="
t_boot0=$(date +%s)
start_qemu "$SERIAL_LOG"
wait_for_marker "$SERIAL_LOG" "$BOOT_TIMEOUT_SEC" "cold_boot"
t_boot1=$(date +%s)
echo "cold_boot_wall_seconds=$((t_boot1 - t_boot0)) accel=$ACCEL_MODE" | tee -a "$TIMING_FILE"
assert_boot_chain "$SERIAL_LOG"

if [[ "${SPLITDISK_QEMU_COLD_ONLY:-}" == "1" ]]; then
  echo "== TCG/cold-only: stopping after cold boot (SPLITDISK_QEMU_COLD_ONLY=1) =="
  cat "$TIMING_FILE"
  stop_qemu
  exit 0
fi

echo "== Phase 5.2: USB hot-plug via QMP =="
# Only assert on serial lines written AFTER device_add (boot already logged usb 2-1).
HOTPLUG_MARK=$(wc -c <"$SERIAL_LOG")
qmp_send "$QMP_SOCK" \
  '{"execute":"blockdev-add","arguments":{"driver":"file","filename":"'"$HOTPLUG_IMG"'","node-name":"hotplug-file"}}' \
  '{"execute":"blockdev-add","arguments":{"driver":"raw","file":"hotplug-file","node-name":"hotplug-raw"}}' \
  '{"execute":"device_add","arguments":{"driver":"usb-storage","id":"usbhot","bus":"xhci.0","drive":"hotplug-raw"}}'

HOT_OK=0
for _ in $(seq 1 60); do
  # Slice only bytes appended since the mark.
  if [[ -f "$SERIAL_LOG" ]] && (( $(wc -c <"$SERIAL_LOG") > HOTPLUG_MARK )); then
    if tail -c +"$((HOTPLUG_MARK + 1))" "$SERIAL_LOG" | grep -aEiq \
      'usb-storage|USB Mass Storage|new high-speed USB|new SuperSpeed USB|Attached SCSI'; then
      HOT_OK=1
      break
    fi
  fi
  sleep 1
done
if [[ "$HOT_OK" -ne 1 ]]; then
  echo "FAIL: no USB hot-plug enumeration in serial log (post device_add only)" >&2
  tail -c +"$((HOTPLUG_MARK + 1))" "$SERIAL_LOG" 2>/dev/null | grep -aEi 'usb|scsi|storage' | tail -n 50 >&2 || true
  stop_qemu
  exit 1
fi
echo "OK: USB hot-plug enumeration seen (post device_add)"
tail -c +"$((HOTPLUG_MARK + 1))" "$SERIAL_LOG" | grep -aEi \
  'usb-storage|USB Mass Storage|new high-speed USB|new SuperSpeed USB|Attached SCSI|usb [0-9]' | head -n 20

DEL_MARK=$(wc -c <"$SERIAL_LOG")
qmp_send "$QMP_SOCK" '{"execute":"device_del","arguments":{"id":"usbhot"}}'
DEL_OK=0
for _ in $(seq 1 60); do
  if [[ -f "$SERIAL_LOG" ]] && (( $(wc -c <"$SERIAL_LOG") > DEL_MARK )); then
    if tail -c +"$((DEL_MARK + 1))" "$SERIAL_LOG" | grep -aEiq \
      'USB disconnect|usb .* disconnect|scsi .* Removing'; then
      DEL_OK=1
      break
    fi
  fi
  sleep 1
done
if [[ "$DEL_OK" -ne 1 ]]; then
  echo "WARN: no explicit disconnect string after device_del; QMP device_del still succeeded"
else
  echo "OK: USB disconnect seen in serial log (post device_del)"
  tail -c +"$((DEL_MARK + 1))" "$SERIAL_LOG" | grep -aEi 'USB disconnect|usb .* disconnect|Removing' | head -n 10
fi

stop_qemu

echo "== Phase 5.3: mid-boot reset then re-boot (image integrity) =="
# Honest note: /init does not write the image; this mainly checks interrupted
# read-only boot does not leave the file-backed image unbootable.
cp -f "$OVMF_VARS_SRC" "$OVMF_VARS"
rm -f "$SERIAL_RESET"
: >"$SERIAL_RESET"
start_qemu "$SERIAL_RESET"
# Interrupt early (before or around marker)
sleep 8
# Truncate serial so post-reset wait does not see a pre-reset marker.
: >"$SERIAL_RESET"
qmp_send "$QMP_SOCK" '{"execute":"system_reset"}' || true
wait_for_marker "$SERIAL_RESET" "$BOOT_TIMEOUT_SEC" "after_system_reset"
assert_boot_chain "$SERIAL_RESET"
stop_qemu

# Fresh QEMU instance against the same image
cp -f "$OVMF_VARS_SRC" "$OVMF_VARS"
rm -f "$SERIAL_HOTPLUG"
start_qemu "$SERIAL_HOTPLUG"
wait_for_marker "$SERIAL_HOTPLUG" "$BOOT_TIMEOUT_SEC" "fresh_instance_same_image"
assert_boot_chain "$SERIAL_HOTPLUG"
stop_qemu
echo "OK: reset + fresh instance both reached $MARKER (image still bootable)"
echo "NOTE: power-loss value is limited while /init is a no-write stub — proves interrupted boot does not corrupt the read-mostly image file."

echo "== Phase 5 timing =="
cat "$TIMING_FILE"
echo "WORKDIR=$WORKDIR"
echo "== Phase 5 QEMU boot-chain checks passed =="
