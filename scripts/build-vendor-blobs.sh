#!/usr/bin/env bash
# Build GRUB EFI, Linux bzImage, and CCID .so from vendor/ trees.
# Offline only: vendor/ + apt packages already in the image. No network.
#
# Outputs under $SPLITDISK_BLOB_CACHE (default: $CARGO_TARGET_DIR/vendor-blobs):
#   grub/<commit>/BOOTX64.EFI
#   linux/<commit>/bzImage
#   ccid/<commit>/ifd-ccid.so
#   pins.txt  (blake3 hex digests, for checking into vendor.rs)
#
# Skips a component when its artifact already exists for that commit, unless
# SPLITDISK_FORCE_BLOB_REBUILD=1.
#
# Reproducibility (same Dockerfile/toolchain image only):
#   - Per-component SOURCE_DATE_EPOCH = that tree's git author date (%at)
#   - Kernel: KBUILD_BUILD_USER/HOST/TIMESTAMP fixed
#   - GRUB: -ffile-prefix-map for src/build trees; SOURCE_DATE_EPOCH
#   - CCID: SOURCE_DATE_EPOCH for Meson
# Cross-host / cross-toolchain bit-identity is not claimed (OPEN-QUESTIONS (j)).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Container mounts of host-owned vendor/ often fail `git rev-parse` without this.
export GIT_CONFIG_GLOBAL="${GIT_CONFIG_GLOBAL:-/tmp/splitdisk-gitconfig}"
git config --global --add safe.directory '*' 2>/dev/null || true

CACHE="${SPLITDISK_BLOB_CACHE:-${CARGO_TARGET_DIR:-/tmp/cargo-target}/vendor-blobs}"
BUILD_ROOT="${SPLITDISK_BLOB_BUILD_ROOT:-/tmp/splitdisk-vendor-build}"
JOBS="${SPLITDISK_BUILD_JOBS:-$(nproc 2>/dev/null || echo 2)}"
FORCE="${SPLITDISK_FORCE_BLOB_REBUILD:-0}"
BUILD_ONLY="${SPLITDISK_BUILD_ONLY:-all}"

# Locale / timezone fixed so stamped strings do not vary by host.
export TZ=UTC
export LC_ALL=C
export LANG=C

GRUB_COMMIT="$(git -C vendor/grub rev-parse HEAD)"
LINUX_COMMIT="$(git -C vendor/linux rev-parse HEAD)"
CCID_COMMIT="$(git -C vendor/ccid rev-parse HEAD)"
GNULIB_COMMIT="$(git -C vendor/gnulib rev-parse HEAD)"

expect_grub=d38d6a1a9b79427848976f53d474392cd29c2a71
expect_linux=e2acc2211022246c77740d5df08265cc27eedcc5
expect_ccid=c37cf6cb42279ce9648ff7314180c866d68f9e0d
expect_gnulib=9f48fb992a3d7e96610c4ce8be969cff2d61a01b

[[ "$GRUB_COMMIT" == "$expect_grub" ]] || { echo "grub HEAD mismatch: $GRUB_COMMIT"; exit 1; }
[[ "$LINUX_COMMIT" == "$expect_linux" ]] || { echo "linux HEAD mismatch: $LINUX_COMMIT"; exit 1; }
[[ "$CCID_COMMIT" == "$expect_ccid" ]] || { echo "ccid HEAD mismatch: $CCID_COMMIT"; exit 1; }
[[ "$GNULIB_COMMIT" == "$expect_gnulib" ]] || { echo "gnulib HEAD mismatch: $GNULIB_COMMIT"; exit 1; }

# Author-date epoch per tree (deterministic, derived from verified commit).
GRUB_EPOCH="$(git -C vendor/grub show -s --format=%at HEAD)"
LINUX_EPOCH="$(git -C vendor/linux show -s --format=%at HEAD)"
CCID_EPOCH="$(git -C vendor/ccid show -s --format=%at HEAD)"

epoch_to_utc() {
  date -u -d "@$1" '+%a %b %e %H:%M:%S UTC %Y' 2>/dev/null \
    || date -u -r "$1" '+%a %b %e %H:%M:%S UTC %Y'
}

mkdir -p "$CACHE" "$BUILD_ROOT"
blake3_file() {
  local f="$1"
  if command -v b3sum >/dev/null 2>&1; then
    b3sum --no-names "$f" | awk '{print $1}'
  elif python3 -c 'import blake3' 2>/dev/null; then
    python3 -c 'import blake3,sys; print(blake3.blake3(open(sys.argv[1],"rb").read()).hexdigest())' "$f"
  else
    echo "MISSING_BLAKE3_TOOL" >&2
    return 1
  fi
}

sha256_file() {
  sha256sum "$1" | awk '{print $1}'
}

echo "== vendor blob cache: $CACHE =="
echo "grub=$GRUB_COMMIT linux=$LINUX_COMMIT ccid=$CCID_COMMIT gnulib=$GNULIB_COMMIT"
echo "epochs: grub=$GRUB_EPOCH linux=$LINUX_EPOCH ccid=$CCID_EPOCH"

# ---------- GRUB ----------
GRUB_OUT="$CACHE/grub/$GRUB_COMMIT/BOOTX64.EFI"
if [[ "$BUILD_ONLY" != "all" && "$BUILD_ONLY" != "grub" ]]; then
  :
elif [[ -f "$GRUB_OUT" && "$FORCE" != "1" ]]; then
  echo "== GRUB: cache hit $GRUB_OUT =="
else
  echo "== GRUB: building (writable copies of grub+gnulib; vendor/ untouched) =="
  t0=$(date +%s)
  export SOURCE_DATE_EPOCH="$GRUB_EPOCH"
  rm -rf "$BUILD_ROOT/grub-src" "$BUILD_ROOT/gnulib-src" "$BUILD_ROOT/grub-prefix" "$BUILD_ROOT/grub-build"
  rsync -a --delete vendor/grub/ "$BUILD_ROOT/grub-src/"
  rsync -a --delete vendor/gnulib/ "$BUILD_ROOT/gnulib-src/"
  (
    cd "$BUILD_ROOT/grub-src"
    ./bootstrap --gnulib-srcdir="$BUILD_ROOT/gnulib-src" --skip-po
    mkdir -p "$BUILD_ROOT/grub-build"
    cd "$BUILD_ROOT/grub-build"
    # Remap absolute build paths out of debug/info strings (reproducible-builds).
    export CFLAGS="${CFLAGS:-} -ffile-prefix-map=${BUILD_ROOT}/grub-src=. -ffile-prefix-map=${BUILD_ROOT}/grub-build=. -ffile-prefix-map=${BUILD_ROOT}/gnulib-src=."
    export CPPFLAGS="${CPPFLAGS:-} -ffile-prefix-map=${BUILD_ROOT}/grub-src=. -ffile-prefix-map=${BUILD_ROOT}/grub-build=. -ffile-prefix-map=${BUILD_ROOT}/gnulib-src=."
    "$BUILD_ROOT/grub-src/configure" \
      --prefix="$BUILD_ROOT/grub-prefix" \
      --with-platform=efi \
      --target=x86_64 \
      --disable-werror \
      --disable-nls
    make -j"$JOBS"
    make install
  )
  mkdir -p "$(dirname "$GRUB_OUT")"
  CFG="$BUILD_ROOT/grub.cfg"
  cat >"$CFG" <<'EOF'
set timeout=0
set default=0
menuentry "SplitDisk" {
    linux /boot/vmlinuz quiet loglevel=0 rd.udev.log_level=0
    initrd /boot/initramfs.img
}
EOF
  "$BUILD_ROOT/grub-prefix/bin/grub-mkstandalone" \
    -O x86_64-efi \
    -o "$GRUB_OUT" \
    --modules="fat part_gpt ext2 linux normal configfile search search_fs_file search_label search_fs_uuid echo test all_video gfxterm video video_fb font terminal chain" \
    "boot/grub/grub.cfg=$CFG"
  t1=$(date +%s)
  echo "GRUB build wall seconds: $((t1 - t0))"
  ls -la "$GRUB_OUT"
fi

# ---------- Linux ----------
LINUX_OUT="$CACHE/linux/$LINUX_COMMIT/bzImage"
if [[ "$BUILD_ONLY" != "all" && "$BUILD_ONLY" != "linux" ]]; then
  :
elif [[ -f "$LINUX_OUT" && "$FORCE" != "1" ]]; then
  echo "== Linux: cache hit $LINUX_OUT =="
else
  echo "== Linux: building with O= out-of-tree (vendor/linux read-only) =="
  t0=$(date +%s)
  export SOURCE_DATE_EPOCH="$LINUX_EPOCH"
  export KBUILD_BUILD_USER=splitdisk
  export KBUILD_BUILD_HOST=splitdisk
  export KBUILD_BUILD_TIMESTAMP
  KBUILD_BUILD_TIMESTAMP="$(epoch_to_utc "$LINUX_EPOCH")"
  O="$BUILD_ROOT/linux-O"
  rm -rf "$O"
  mkdir -p "$O"
  make -C vendor/linux O="$O" defconfig
  make -C vendor/linux O="$O" scripts/config
  CFGTOOL="$O/scripts/config"
  conf() { "$CFGTOOL" --file "$O/.config" "$@" || true; }
  conf --enable CONFIG_USB_SUPPORT
  conf --enable CONFIG_USB_XHCI_HCD
  conf --enable CONFIG_USB_EHCI_HCD
  conf --enable CONFIG_USB_STORAGE
  conf --enable CONFIG_USB_SERIAL
  conf --enable CONFIG_USB_CHIPIDEA
  conf --enable CONFIG_PCMCIA
  conf --enable CONFIG_SCSI
  conf --enable CONFIG_EXT4_FS
  conf --enable CONFIG_VFAT_FS
  conf --enable CONFIG_TMPFS
  conf --enable CONFIG_PROC_FS
  conf --enable CONFIG_SYSFS
  conf --enable CONFIG_TTY
  conf --enable CONFIG_VT
  conf --enable CONFIG_FB
  conf --enable CONFIG_DRM
  conf --enable CONFIG_BLK_DEV_INITRD
  conf --enable CONFIG_EFI
  conf --enable CONFIG_EFI_STUB
  conf --disable CONFIG_CRYPTO_CHACHA20
  make -C vendor/linux O="$O" olddefconfig
  make -C vendor/linux O="$O" -j"$JOBS" \
    KBUILD_BUILD_USER=splitdisk \
    KBUILD_BUILD_HOST=splitdisk \
    KBUILD_BUILD_TIMESTAMP="$KBUILD_BUILD_TIMESTAMP" \
    bzImage
  mkdir -p "$(dirname "$LINUX_OUT")"
  cp -a "$O/arch/x86/boot/bzImage" "$LINUX_OUT"
  t1=$(date +%s)
  echo "Linux build wall seconds: $((t1 - t0))"
  echo "KBUILD_BUILD_TIMESTAMP=$KBUILD_BUILD_TIMESTAMP"
  ls -la "$LINUX_OUT"
fi

# ---------- CCID (Meson) ----------
CCID_OUT="$CACHE/ccid/$CCID_COMMIT/ifd-ccid.so"
if [[ "$BUILD_ONLY" != "all" && "$BUILD_ONLY" != "ccid" ]]; then
  :
elif [[ -f "$CCID_OUT" && "$FORCE" != "1" ]]; then
  echo "== CCID: cache hit $CCID_OUT =="
else
  echo "== CCID: meson build =="
  t0=$(date +%s)
  export SOURCE_DATE_EPOCH="$CCID_EPOCH"
  export LDFLAGS="-Wl,--build-id=none"
  B="$BUILD_ROOT/ccid-build"
  rm -rf "$B"
  # CCID's meson.build installs into pcsclite usbdropdir (/usr/lib/pcsc/...),
  # which is read-only in the hardened test container. Compile only and copy
  # the built IFD shared object from the ninja build dir.
  meson setup "$B" vendor/ccid \
    --prefix="$BUILD_ROOT/ccid-prefix" \
    -Dembedded=true \
    -Dpcsclite=true \
    -Dudev-rules=false \
    -Denable-extras=false \
    -Db_ndebug=true
  meson compile -C "$B"
  mkdir -p "$(dirname "$CCID_OUT")"
  SO="$(find "$B" -type f \( -name 'libccid.so' -o -name 'libccid.so.*' \) | head -1)"
  if [[ -z "$SO" ]]; then
    echo "CCID: no libccid.so under $B; tree:" >&2
    find "$B" -type f | head -50 >&2
    exit 1
  fi
  cp -a "$SO" "$CCID_OUT"
  # Drop build-id / strip nothing — keep deterministic copy of the link output.
  # Clear mtime variance on the cache file for pin hashing of content only
  # (blake3 is content-hash; mtime does not affect digests).
  t1=$(date +%s)
  echo "CCID build wall seconds: $((t1 - t0))"
  echo "CCID source so: $SO"
  ls -la "$CCID_OUT"
fi

# ---------- pins ----------
PINS="$CACHE/pins.txt"
{
  echo "grub_commit=$GRUB_COMMIT"
  echo "linux_commit=$LINUX_COMMIT"
  echo "ccid_commit=$CCID_COMMIT"
  echo "grub_efi_path=$GRUB_OUT"
  echo "kernel_bzimage_path=$LINUX_OUT"
  echo "ccid_ifd_ccid_so_path=$CCID_OUT"
  echo "grub_source_date_epoch=$GRUB_EPOCH"
  echo "linux_source_date_epoch=$LINUX_EPOCH"
  echo "ccid_source_date_epoch=$CCID_EPOCH"
} >"$PINS"

if command -v b3sum >/dev/null 2>&1 || python3 -c 'import blake3' 2>/dev/null; then
  [[ -f "$GRUB_OUT" ]] && echo "grub_efi_blake3=$(blake3_file "$GRUB_OUT")" >>"$PINS"
  [[ -f "$LINUX_OUT" ]] && echo "kernel_bzimage_blake3=$(blake3_file "$LINUX_OUT")" >>"$PINS"
  [[ -f "$CCID_OUT" ]] && echo "ccid_ifd_ccid_so_blake3=$(blake3_file "$CCID_OUT")" >>"$PINS"
else
  [[ -f "$GRUB_OUT" ]] && echo "grub_efi_sha256=$(sha256_file "$GRUB_OUT")" >>"$PINS"
  [[ -f "$LINUX_OUT" ]] && echo "kernel_bzimage_sha256=$(sha256_file "$LINUX_OUT")" >>"$PINS"
  [[ -f "$CCID_OUT" ]] && echo "ccid_ifd_ccid_so_sha256=$(sha256_file "$CCID_OUT")" >>"$PINS"
  echo "(blake3 CLI unavailable — sha256 recorded; Rust blake3 used for PIN_*)" >>"$PINS"
fi

echo "== done; pins at $PINS =="
cat "$PINS"
