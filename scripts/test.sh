#!/usr/bin/env bash
# Run the SplitDisk test suite inside the project container image.
# Hardened: no network, read-only root, dropped caps, non-root, no devices.
#
# Prefer Docker (`docker`). If the Docker socket is unavailable, set
# CONTAINER_ENGINE=podman (rootless) — same flags, same image.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ENGINE="${CONTAINER_ENGINE:-docker}"
IMAGE_NAME="${SPLITDISK_IMAGE:-splitdisk-test:phase4}"
TESTDATA_HOST="${ROOT}/testdata"
mkdir -p "${TESTDATA_HOST}"

# Kernel + GRUB object trees need far more than the Phase 3 2 GiB /tmp.
# This is a resource limit only (OPEN-QUESTIONS (i)), not a security change:
# still --network none, --read-only root, --cap-drop ALL, no devices.
TMPFS_SIZE="${SPLITDISK_TMPFS_SIZE:-48g}"

USERNS_ARGS=()
USER_ARGS=(--user 1000:1000)
if [[ "${ENGINE}" == *podman* ]]; then
  # Rootless podman: map container uid to host so testdata/lock writes work.
  USERNS_ARGS=(--userns=keep-id)
  USER_ARGS=()
fi

echo "Building image ${IMAGE_NAME} with ${ENGINE}..."
"${ENGINE}" build --target test -t "${IMAGE_NAME}" .

echo "Running tests (network none, read-only, cap-drop ALL, tmpfs ${TMPFS_SIZE})..."
# Use the image CARGO_HOME (prefetched deps). Target + vendor-blob builds on tmpfs.
"${ENGINE}" run --rm \
  --network none \
  --read-only \
  --tmpfs "/tmp:rw,exec,nosuid,nodev,size=${TMPFS_SIZE}" \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  "${USERNS_ARGS[@]}" \
  "${USER_ARGS[@]}" \
  -v "${ROOT}:/work:ro" \
  -v "${TESTDATA_HOST}:/work/testdata:rw" \
  -e CARGO_HOME=/home/builder/.cargo \
  -e CARGO_TARGET_DIR=/tmp/cargo-target \
  -e SPLITDISK_BLOB_CACHE=/work/testdata/vendor-blobs \
  -e HOME=/home/builder \
  "${IMAGE_NAME}" \
  bash -c 'mkdir -p "$CARGO_TARGET_DIR" "$SPLITDISK_BLOB_CACHE" && bash scripts/docker-test-inner.sh'
