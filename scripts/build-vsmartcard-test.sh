#!/usr/bin/env bash
# Build frankmorgner/vsmartcard (virtualsmartcard) for Phase 6 follow-up PC/SC tests.
#
# TEST TOOLING ONLY — not shipped in the production initramfs, not covered by
# production BLAKE3 pins (PIN_CCID_IFD / PIN_KERNEL / PIN_GRUB_EFI). Pinned by
# tag + tarball SHA-256 at Docker image build time (same pattern as other build
# tools). No signature-verification bar: this never ships on a SplitDisk drive.
#
# Architecture (FORMAT.md §13.4): upstream has no standalone "vpcd daemon"
# binary. `src/vpcd/` builds libvpcd (socket helpers linked into ifd-vpcd);
# ifd-vpcd is the PC/SC IFD that listens on 127.0.0.1 TCP; `vicc` is the
# virtual card that connects. Transport stays on loopback.
set -euo pipefail

# Tag virtualsmartcard-0.10 (annotated) → commit 39e564aaae29b99a79906bc1fd3fbf374153e893
VSMARTCARD_TAG="${VSMARTCARD_TAG:-virtualsmartcard-0.10}"
VSMARTCARD_TARBALL_SHA256="${VSMARTCARD_TARBALL_SHA256:-76897e4506e03b399a1dd394295d29621911b399d66a31acb5eb6b65131c726e}"
PREFIX="${VSMARTCARD_PREFIX:-/usr/local}"
STAGING="${VSMARTCARD_STAGING:-/usr/local/share/splitdisk/vsmartcard-test}"
BUILD_ROOT="${VSMARTCARD_BUILD_ROOT:-/tmp/vsmartcard-build}"
URL="https://github.com/frankmorgner/vsmartcard/archive/refs/tags/${VSMARTCARD_TAG}.tar.gz"

echo "== build vsmartcard test tooling (tag=${VSMARTCARD_TAG}) =="
rm -rf "$BUILD_ROOT" "$STAGING"
mkdir -p "$BUILD_ROOT" "$STAGING"
TARBALL="$BUILD_ROOT/vsmartcard.tar.gz"
curl -fsSL "$URL" -o "$TARBALL"
got=$(sha256sum "$TARBALL" | awk '{print $1}')
if [[ "$got" != "$VSMARTCARD_TARBALL_SHA256" ]]; then
  echo "FAIL: tarball SHA-256 mismatch: got=$got want=$VSMARTCARD_TARBALL_SHA256" >&2
  exit 1
fi
echo "OK: tarball SHA-256 verified"

tar -xzf "$TARBALL" -C "$BUILD_ROOT"
SRC=$(find "$BUILD_ROOT" -maxdepth 2 -type d -name 'virtualsmartcard' | head -n 1)
[[ -n "$SRC" && -f "$SRC/configure.ac" ]] || {
  echo "FAIL: virtualsmartcard source dir not found after extract" >&2
  find "$BUILD_ROOT" -maxdepth 3 -type d >&2 || true
  exit 1
}
cd "$SRC"

autoreconf --verbose --install
./configure \
  --prefix="$PREFIX" \
  --sysconfdir="$PREFIX/etc" \
  --disable-libpcsclite \
  --disable-infoplist
make -j"$(nproc)"
make install

# Normalize into a stable staging tree the test harness can depend on.
# Autotools + pcsclite pkg-config often emit awkward $prefix/usr/lib paths.
mkdir -p "$STAGING/lib" "$STAGING/bin" "$STAGING/python" "$STAGING/etc/reader.conf.d"

IFD_SRC=$(find "$PREFIX" -name 'libifdvpcd.so*' \( -type f -o -type l \) | head -n 1)
[[ -n "$IFD_SRC" ]] || {
  echo "FAIL: libifdvpcd.so not found under $PREFIX after make install" >&2
  find "$PREFIX" -name '*vpcd*' >&2 || true
  exit 1
}
# Resolve to a real ELF file and place a stable name.
IFD_REAL=$(readlink -f "$IFD_SRC")
cp -aL "$IFD_REAL" "$STAGING/lib/libifdvpcd.so"
chmod 755 "$STAGING/lib/libifdvpcd.so"

if [[ -x "$PREFIX/bin/vicc" ]]; then
  cp -a "$PREFIX/bin/vicc" "$STAGING/bin/vicc"
else
  echo "FAIL: $PREFIX/bin/vicc missing" >&2
  exit 1
fi
chmod 755 "$STAGING/bin/vicc"

# Python package: copy from source tree (avoids double-$prefix site-packages).
cp -a "$SRC/src/vpicc/virtualsmartcard" "$STAGING/python/virtualsmartcard"

# Test-only reader.conf pointing at OUR built IFD (not Debian's).
cat >"$STAGING/etc/reader.conf.d/vpcd-splitdisk-test" <<EOF
FRIENDLYNAME "SplitDisk Test Virtual PCD"
DEVICENAME   /dev/null:0x8C7B
LIBPATH      $STAGING/lib/libifdvpcd.so
CHANNELID    0x8C7B
EOF

# Marker file consumed by the functional test.
cat >"$STAGING/VERSION" <<EOF
tag=$VSMARTCARD_TAG
tarball_sha256=$VSMARTCARD_TARBALL_SHA256
ifd=$STAGING/lib/libifdvpcd.so
vicc=$STAGING/bin/vicc
EOF

# Smoke: IFD is an ELF; Python package imports; vicc --help works.
file "$STAGING/lib/libifdvpcd.so" | grep -qi elf
PYTHONPATH="$STAGING/python${PYTHONPATH:+:$PYTHONPATH}" \
  python3 -c "import virtualsmartcard; print('OK: virtualsmartcard', virtualsmartcard.__path__)"
PYTHONPATH="$STAGING/python${PYTHONPATH:+:$PYTHONPATH}" \
  "$STAGING/bin/vicc" --help >/dev/null

echo "OK: staged test tooling at $STAGING"
cat "$STAGING/VERSION"
