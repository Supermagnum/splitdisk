#!/usr/bin/env bash
# Phase 6 follow-up: live virtual-card ATR through PC/SC.
#
# Proven chain (this script):
#   gpg/scdaemon OR raw PC/SC → pcscd → OUR built libifdvpcd.so → TCP 127.0.0.1
#   → vicc (handler_test) → ATR
#
# Explicit non-claim: SplitDisk's USB ifd-ccid.so (PIN_CCID_IFD / ifd-ccid.bundle)
# is NOT on this path. USB CCID speaks a different protocol than vpcd's localhost
# TCP; proving ifd-ccid.so needs a USB CCID device (physical or QEMU usb-ccid),
# which remains deferred (OPEN-QUESTIONS (l)/(o)).
#
# Transport: vpcd IFD listens on 127.0.0.1:35963; never leaves loopback.
# Container runs with --network none; loopback still works.
set -euo pipefail

echo "== Phase 6 follow-up: live ATR via built ifd-vpcd + vicc =="

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "FAIL: missing $1" >&2
    exit 1
  }
}

need pcscd
need gpg
need python3

STAGING="${VSMARTCARD_STAGING:-/usr/local/share/splitdisk/vsmartcard-test}"
test -f "$STAGING/VERSION" || {
  echo "FAIL: missing $STAGING/VERSION — rebuild image (scripts/build-vsmartcard-test.sh)" >&2
  exit 1
}
test -f "$STAGING/lib/libifdvpcd.so" || {
  echo "FAIL: missing built libifdvpcd.so at $STAGING/lib/libifdvpcd.so" >&2
  exit 1
}
test -x "$STAGING/bin/vicc" || {
  echo "FAIL: missing vicc at $STAGING/bin/vicc" >&2
  exit 1
}
echo "OK: staging present"
cat "$STAGING/VERSION"

# Production CCID blob inputs still present (boot path), but NOT used in this hop.
CCID_COMMIT=c37cf6cb42279ce9648ff7314180c866d68f9e0d
BUNDLE_SO="${SPLITDISK_BLOB_CACHE:-/work/testdata/vendor-blobs}/ccid/${CCID_COMMIT}/ifd-ccid.so"
if [[ -f "$BUNDLE_SO" ]]; then
  echo "OK: production ifd-ccid.so blob present (not exercised by vpcd ATR path)"
else
  echo "NOTE: production ifd-ccid.so blob cache missing in this run"
fi

WORKDIR=$(mktemp -d /tmp/splitdisk-gpg-vpcd.XXXXXX)
cleanup() {
  if [[ -f "$WORKDIR/vicc.pid" ]]; then
    kill "$(cat "$WORKDIR/vicc.pid")" 2>/dev/null || true
  fi
  if [[ -f "$WORKDIR/pcscd.pid" ]]; then
    kill "$(cat "$WORKDIR/pcscd.pid")" 2>/dev/null || true
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

mkdir -p "$WORKDIR/run/pcscd" "$WORKDIR/gnupg" "$WORKDIR/etc/reader.conf.d"
chmod 700 "$WORKDIR/gnupg"
export GNUPGHOME="$WORKDIR/gnupg"
export PYTHONPATH="$STAGING/python${PYTHONPATH:+:$PYTHONPATH}"

if mkdir -p /run/pcscd 2>/dev/null; then
  echo "OK: /run/pcscd writable (using default pcscd socket)"
  unset PCSCLITE_CSOCK_NAME || true
else
  echo "NOTE: /run/pcscd not writable; using PCSCLITE_CSOCK_NAME under $WORKDIR"
  export PCSCLITE_CSOCK_NAME="$WORKDIR/run/pcscd/pcscd.comm"
fi

# Use ONLY our built IFD — disable Debian reader.conf.d for this process.
cp "$STAGING/etc/reader.conf.d/vpcd-splitdisk-test" "$WORKDIR/etc/reader.conf.d/"
# Empty drop-in dir so we do not accidentally load Debian libifdvpcd / libccidtwin.
export PCSCLITE_CONFIG_DIR="$WORKDIR/etc"
# pcsc-lite 1.9 reads /etc/reader.conf.d via compiled-in path; override by
# binding a custom config: write reader.conf that includes our drop-in only.
cat >"$WORKDIR/etc/reader.conf" <<EOF
FRIENDLYNAME "SplitDisk Test Virtual PCD"
DEVICENAME   /dev/null:0x8C7B
LIBPATH      $STAGING/lib/libifdvpcd.so
CHANNELID    0x8C7B
EOF

pkill pcscd 2>/dev/null || true
sleep 0.2

# -c points at a single reader.conf with OUR LIBPATH.
pcscd --foreground --debug --apdu -c "$WORKDIR/etc/reader.conf" \
  >"$WORKDIR/pcscd.log" 2>&1 &
echo $! >"$WORKDIR/pcscd.pid"
sleep 1

if ! kill -0 "$(cat "$WORKDIR/pcscd.pid")" 2>/dev/null; then
  echo "FAIL: pcscd did not stay up" >&2
  cat "$WORKDIR/pcscd.log" >&2 || true
  exit 1
fi
echo "OK: pcscd running with -c $WORKDIR/etc/reader.conf"

# Evidence: specifically our built IFD, not Debian's path.
if grep -F "$STAGING/lib/libifdvpcd.so" "$WORKDIR/pcscd.log"; then
  echo "OK: pcscd log references our built libifdvpcd.so"
else
  echo "FAIL: pcscd did not load $STAGING/lib/libifdvpcd.so" >&2
  grep -E 'Loading IFD|Attempting startup|LIBPATH|libifd|libccid' "$WORKDIR/pcscd.log" | head -40 >&2 || true
  exit 1
fi
if grep -E '/usr/lib/pcsc/drivers/serial/libifdvpcd\.so' "$WORKDIR/pcscd.log"; then
  echo "FAIL: pcscd also loaded Debian libifdvpcd — isolation broken" >&2
  exit 1
fi
if grep -Ei 'ifd-ccid|libccid\.so' "$WORKDIR/pcscd.log"; then
  echo "FAIL: USB ifd-ccid appeared in this vpcd test (unexpected)" >&2
  exit 1
fi
echo "OK: driver isolation — only our built ifd-vpcd"

# handler_test card: fixed plausible ATR, minimal applet SELECT behaviour.
"$STAGING/bin/vicc" -t handler_test -v >"$WORKDIR/vicc.log" 2>&1 &
echo $! >"$WORKDIR/vicc.pid"
sleep 2
if ! kill -0 "$(cat "$WORKDIR/vicc.pid")" 2>/dev/null; then
  echo "FAIL: vicc exited early" >&2
  cat "$WORKDIR/vicc.log" >&2 || true
  exit 1
fi
echo "OK: vicc (handler_test) running"

# Raw PC/SC: list readers, connect, fetch ATR.
python3 - "$WORKDIR" <<'PY'
import ctypes, ctypes.util, sys, os

workdir = sys.argv[1]
pcsclite = ctypes.CDLL(ctypes.util.find_library("pcsclite"))
SCARD_SCOPE_SYSTEM = 2
SCARD_SHARE_SHARED = 2
SCARD_PROTOCOL_T0 = 1
SCARD_PROTOCOL_T1 = 2
SCARD_LEAVE_CARD = 0
SCARD_ATTR_ATR_STRING = 0x00090303

hcontext = ctypes.c_long()
rv = pcsclite.SCardEstablishContext(SCARD_SCOPE_SYSTEM, None, None, ctypes.byref(hcontext))
print(f"EstablishContext rv={hex(rv & 0xffffffff)}")
if rv != 0:
    sys.exit(2)

pcch = ctypes.c_uint32(0)
rv = pcsclite.SCardListReaders(hcontext, None, None, ctypes.byref(pcch))
print(f"ListReaders(size) rv={hex(rv & 0xffffffff)} len={pcch.value}")
if rv != 0 or pcch.value == 0:
    sys.exit(3)
buf = ctypes.create_string_buffer(pcch.value)
rv = pcsclite.SCardListReaders(hcontext, None, buf, ctypes.byref(pcch))
readers = [r.decode() for r in buf.raw[: pcch.value].split(b"\0") if r]
print("readers:", readers)
if not readers:
    sys.exit(4)

reader = readers[0].encode()
hcard = ctypes.c_long()
active = ctypes.c_uint32()
rv = pcsclite.SCardConnect(
    hcontext,
    reader,
    SCARD_SHARE_SHARED,
    SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
    ctypes.byref(hcard),
    ctypes.byref(active),
)
print(f"Connect rv={hex(rv & 0xffffffff)} proto={active.value}")
if rv != 0:
    sys.exit(5)

attr = ctypes.create_string_buffer(64)
attrlen = ctypes.c_uint32(64)
rv = pcsclite.SCardGetAttrib(hcard, SCARD_ATTR_ATR_STRING, attr, ctypes.byref(attrlen))
print(f"GetAttrib ATR rv={hex(rv & 0xffffffff)} len={attrlen.value}")
if rv != 0 or attrlen.value == 0:
    sys.exit(6)
atr = attr.raw[: attrlen.value]
atr_hex = atr.hex()
print(f"ATR_HEX={atr_hex}")
with open(os.path.join(workdir, "atr.txt"), "w", encoding="utf-8") as f:
    f.write(atr_hex + "\n")

# Expected handler_test ATR from upstream HandlerTest.py
expected = bytes.fromhex("3bd6180080b1806d1f038051006110309e")
if atr != expected:
    print(f"FAIL: ATR mismatch want={expected.hex()} got={atr_hex}", file=sys.stderr)
    sys.exit(7)
print("OK: ATR matches handler_test fixture")

pcsclite.SCardDisconnect(hcard, SCARD_LEAVE_CARD)
pcsclite.SCardReleaseContext(hcontext)
PY

ATR=$(cat "$WORKDIR/atr.txt")
echo "OK: live ATR via PC/SC: $ATR"

# gpg --card-status: may still say "not an OpenPGP card" — that is fine if it
# saw a reader/card rather than IPC failure. Record full output.
set +e
GPG_OUT=$(gpg --card-status 2>&1)
GPG_RC=$?
set -e
echo "---- gpg --card-status (rc=$GPG_RC) ----"
printf '%s\n' "$GPG_OUT"
echo "---- end gpg output ----"

if echo "$GPG_OUT" | grep -Eiq 'service not running|IPC connect call failed|Connection refused'; then
  echo "FAIL: gpg could not reach pcscd" >&2
  exit 1
fi

# pcscd must have talked to our IFD about ATR / virtual ICC.
if grep -Eiq 'Got ATR|Waiting for virtual ICC|Connected to virtual ICC|libifdvpcd' "$WORKDIR/pcscd.log"; then
  echo "OK: pcscd verbose log shows IFD/ATR activity"
  grep -Ei 'libifdvpcd|Got ATR|virtual ICC|ATR' "$WORKDIR/pcscd.log" | head -n 30
else
  echo "FAIL: no IFD/ATR activity in pcscd log" >&2
  exit 1
fi

echo "OK: Phase 6 follow-up ATR path closed (pcscd → built ifd-vpcd → vicc)"
echo "NOTE: USB ifd-ccid.so remains unproven by this test (different IFD protocol)"
