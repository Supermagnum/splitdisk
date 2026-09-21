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
IMAGE_NAME="${SPLITDISK_IMAGE:-splitdisk-test:phase1}"
TESTDATA_HOST="${ROOT}/testdata"
mkdir -p "${TESTDATA_HOST}"

echo "Building image ${IMAGE_NAME} with ${ENGINE}..."
"${ENGINE}" build --target test -t "${IMAGE_NAME}" .

echo "Running tests (network none, read-only, cap-drop ALL)..."
# Use the image CARGO_HOME (prefetched deps). Target dir on tmpfs.
"${ENGINE}" run --rm \
  --network none \
  --read-only \
  --tmpfs /tmp:rw,exec,nosuid,nodev,size=2g \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --user 1000:1000 \
  -v "${ROOT}:/work:ro" \
  -v "${TESTDATA_HOST}:/work/testdata:rw" \
  -e CARGO_HOME=/home/builder/.cargo \
  -e CARGO_TARGET_DIR=/tmp/cargo-target \
  -e HOME=/home/builder \
  "${IMAGE_NAME}" \
  bash -c 'mkdir -p "$CARGO_TARGET_DIR" && bash scripts/docker-test-inner.sh'
