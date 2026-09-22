#!/usr/bin/env bash
# Stage pcscd (and optionally assemble) + shared-library deps into a directory
# tree suitable for embedding in the initramfs (relative paths from /).
#
# Usage:
#   stage-initramfs-runtime.sh --out DIR [--pcscd PATH] [--assemble PATH]
set -euo pipefail

OUT=""
PCSCD_BIN=""
ASSEMBLE_BIN=""
CCID_SO=""

while [[ $# -gt 0 ]]; do
  case "$1" in
  --out) OUT="${2:-}"; shift 2 ;;
  --pcscd) PCSCD_BIN="${2:-}"; shift 2 ;;
  --assemble) ASSEMBLE_BIN="${2:-}"; shift 2 ;;
  --ccid-so) CCID_SO="${2:-}"; shift 2 ;;
  *)
    echo "usage: $0 --out DIR [--pcscd PATH] [--assemble PATH] [--ccid-so PATH]" >&2
    exit 2
    ;;
  esac
done

[[ -n "$OUT" ]] || {
  echo "missing --out" >&2
  exit 2
}
rm -rf "$OUT"
mkdir -p "$OUT"

# Copy a host path into the staging tree as a real file (dereference symlinks).
# Initramfs cannot follow host absolute symlink targets.
stage_file() {
  local src=$1
  local rel=$2
  mkdir -p "$OUT/$(dirname "$rel")"
  if [[ -e "$OUT/$rel" ]]; then
    return 0
  fi
  # -L: follow symlinks so soname paths become real ELF objects in the tree.
  cp -aL "$src" "$OUT/$rel"
}

copy_with_deps() {
  local bin=$1
  local dest_rel=$2
  [[ -f "$bin" ]] || {
    echo "missing binary: $bin" >&2
    exit 1
  }
  stage_file "$bin" "$dest_rel"
  # Recursively collect DT_NEEDED libraries (skip vdso / ld-linux handled separately).
  local queue=("$bin")
  local seen=()
  while ((${#queue[@]})); do
    local cur="${queue[0]}"
    queue=("${queue[@]:1}")
    local already=0
    for s in "${seen[@]+"${seen[@]}"}"; do
      [[ "$s" == "$cur" ]] && already=1 && break
    done
    if ((already)); then
      continue
    fi
    seen+=("$cur")
    while read -r line; do
      # ldd: "libfoo.so.1 => /lib/.../libfoo.so.1 (0x...)"
      if [[ "$line" == *"=>"* ]]; then
        lib=$(echo "$line" | awk '{print $3}')
        if [[ -n "$lib" && -f "$lib" ]]; then
          local rel="${lib#/}"
          if [[ ! -e "$OUT/$rel" ]]; then
            stage_file "$lib" "$rel"
            queue+=("$lib")
          fi
        fi
      fi
      # Interpreter line: "/lib64/ld-linux-x86-64.so.2 (0x...)"
      if [[ "$line" == *ld-linux* ]]; then
        ld=$(echo "$line" | awk '{print $1}')
        if [[ -f "$ld" ]]; then
          local rel="${ld#/}"
          stage_file "$ld" "$rel"
          # Also place the real object at the glibc path if PT_INTERP is /lib64/...
          # and a second copy lives under /lib/x86_64-linux-gnu/.
          real_ld=$(readlink -f "$ld")
          if [[ -n "$real_ld" && "$real_ld" != "$ld" && -f "$real_ld" ]]; then
            stage_file "$real_ld" "${real_ld#/}"
          fi
        fi
      fi
    done < <(ldd "$cur" 2>/dev/null || true)
  done
}

if [[ -z "$PCSCD_BIN" ]]; then
  for c in /usr/sbin/pcscd /usr/bin/pcscd; do
    if [[ -x "$c" ]]; then
      PCSCD_BIN=$c
      break
    fi
  done
fi

if [[ -n "$PCSCD_BIN" ]]; then
  echo "staging pcscd from $PCSCD_BIN"
  copy_with_deps "$PCSCD_BIN" "usr/sbin/pcscd"
else
  echo "WARN: pcscd not found; initramfs will lack pcscd" >&2
fi

if [[ -n "$ASSEMBLE_BIN" ]]; then
  echo "staging assemble libs from $ASSEMBLE_BIN"
  # Binary itself is embedded separately; only collect its interpreter + libs.
  copy_with_deps "$ASSEMBLE_BIN" "usr/bin/splitdisk-assemble.dynmarker"
  rm -f "$OUT/usr/bin/splitdisk-assemble.dynmarker"
fi

if [[ -n "$CCID_SO" ]]; then
  echo "staging ifd-ccid shared-lib deps from $CCID_SO (not the .so itself)"
  [[ -f "$CCID_SO" ]] || {
    echo "missing --ccid-so file: $CCID_SO" >&2
    exit 1
  }
  # Collect DT_NEEDED (libusb, etc.) without embedding a second copy of the
  # production IFD — that already lives in ifd-ccid.bundle from vendor pins.
  copy_with_deps "$CCID_SO" "usr/lib/pcsc/drivers/ifd-ccid.bundle/Contents/Linux/libccid.so.depmarker"
  rm -f "$OUT/usr/lib/pcsc/drivers/ifd-ccid.bundle/Contents/Linux/libccid.so.depmarker"
fi

# Minimal /etc/passwd so glibc does not complain in some paths.
mkdir -p "$OUT/etc"
if [[ ! -f "$OUT/etc/passwd" ]]; then
  printf 'root:x:0:0:root:/root:/bin/false\nnobody:x:65534:65534:nobody:/nonexistent:/bin/false\n' >"$OUT/etc/passwd"
fi
if [[ ! -f "$OUT/etc/group" ]]; then
  printf 'root:x:0:\nnogroup:x:65534:\n' >"$OUT/etc/group"
fi

echo "staged runtime tree at $OUT ($(find "$OUT" -type f | wc -l) files)"
