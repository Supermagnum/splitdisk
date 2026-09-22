#!/usr/bin/env bash
# Create an NSS certificate DB for QEMU ccid-card-emulated (certificates backend).
# TEST FIXTURE ONLY — not shipped, not BLAKE3-pinned as a production blob.
#
# Non-interactive: feeds certutil a /dev/urandom noise file (no keyboard entropy).
set -euo pipefail

OUT="${1:-/usr/local/share/splitdisk/ccid-emulated-nssdb}"
need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "FAIL: need $1 (libnss3-tools)" >&2
    exit 1
  }
}
need certutil

rm -rf "$OUT"
mkdir -p "$OUT"
NOISE="$OUT/noise"
dd if=/dev/urandom of="$NOISE" bs=2048 count=1 status=none
# Empty password.
printf '' >"$OUT/pwdfile"
certutil -N -d "sql:$OUT" -f "$OUT/pwdfile"

# Self-signed CA (batch: answers for -2 via printf).
printf 'y\n0\nn\n' | certutil -S -d "sql:$OUT" -f "$OUT/pwdfile" -z "$NOISE" \
  -n ca-cert -s "CN=SplitDisk Test CA" -t "C,C,C" -x -m 1 -v 120 -2 >/dev/null

i=2
for nick in id-cert signing-cert encryption-cert; do
  dd if=/dev/urandom of="$NOISE" bs=2048 count=1 status=none
  certutil -S -d "sql:$OUT" -f "$OUT/pwdfile" -z "$NOISE" \
    -n "$nick" -s "CN=SplitDisk $nick" -t ",," -c ca-cert -m "$i" -v 120 >/dev/null
  i=$((i + 1))
done

rm -f "$OUT/pwdfile" "$NOISE"
certutil -L -d "sql:$OUT"
echo "OK: wrote NSS DB at $OUT"
ls -la "$OUT"
