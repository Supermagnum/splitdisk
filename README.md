# SplitDisk

**License:** GPL-3.0 (aligned with Galdralag-firmware per the specification)  
**Normative spec:** [docs/SPEC.md](docs/SPEC.md)  
**Contributors:** [AGENTS.md](AGENTS.md) | [docs/OPEN-QUESTIONS.md](docs/OPEN-QUESTIONS.md)

---

## What this is

SplitDisk is a command-line tool and initramfs-resident assembly agent for
splitting a disk image or filesystem into **k-of-n physical USB shares**, each
bootable, such that any **k** drives inserted in sequence can reconstruct and
write the original content to a target disk. Share holders are not told their
share index, **k**, **n**, or the threshold. Optional Galdralag token integration
is specified for on-device PIN and share handling over CCID; see the spec.

This repository is **design and prototype stage** work toward that specification.
It is not production-ready and has not been deployed or field-tested as a
complete system.

---

## Current status (through Phase 4)

Implemented in Rust (file-backed Phase 1 safety model):

- Core crypto, Reed–Solomon, Shamir share wrapping, encrypted drive metadata
- `splitdisk-create` / `splitdisk-assemble` on regular files under `testdata/`
  (no `/dev` in CI; raw block devices feature off by default)
- Checkpoint/resume and mandatory post-write verification paths (per spec intent)
- `splitdisk-image`: GPT + FAT ESP + ext4 system partition (via pinned
  `e2fsprogs`; `fsck.ext4 -n -f` clean on fixtures) and initramfs layout
- **Phase 4 boot blobs:** real GRUB EFI, Linux bzImage, and CCID `libccid.so`
  built offline from human-verified `vendor/` trees ([docs/VENDORING.md](docs/VENDORING.md)),
  BLAKE3-pinned in code

**Not done yet:**

- **No QEMU or hardware boot test** — images are structurally validated, not
  booted end-to-end
- **No Galdralag / token ECDH path** — Brainpool ECDH and Mode A outer envelope
  are blocked on audited crates ([OPEN-QUESTIONS (a)](docs/OPEN-QUESTIONS.md))
- **No biometric enrollment or verification**
- **`/init` in the initramfs is still a synthetic stub** (not full mount/exec init)
- **CCID/pcscd runtime config** may be incomplete (driver copied without full
  `meson install`; see [OPEN-QUESTIONS (k)](docs/OPEN-QUESTIONS.md))
- **Reproducibility:** Linux bzImage and CCID `.so` are byte-stable across cold
  rebuilds in the pinned Docker image (canonical CCID build paths); GRUB EFI
  output may still vary — [OPEN-QUESTIONS (j)](docs/OPEN-QUESTIONS.md)

Do not treat this tree as audited or “secure” for real data until spec gaps are
closed and independent review has occurred.

---

## Build and test

All builds and tests are intended to run **inside the project container** with
**no network at test time**:

```bash
./scripts/test.sh
```

Uses Docker by default; set `CONTAINER_ENGINE=podman` if needed. The script builds
`splitdisk-test:phase4`, mounts the repo read-only, uses a large `/tmp` tmpfs
(default 48g for kernel object files), and runs `scripts/docker-test-inner.sh`
(fmt, clippy, vendor blob cache check, **kernel byte-repro check**, `cargo test`,
`cargo deny`).

Offline vendor blobs (GRUB / kernel / CCID) are expected under
`testdata/vendor-blobs/` (gitignored; produced by `scripts/build-vendor-blobs.sh`
inside the container). Do **not** point tools at paths under `/dev` for
development or CI.

Dependency crate integrity checking is tracked upstream:
https://github.com/rust-lang/cargo/issues/16850

---

## Vendoring and trust

Boot-critical third-party sources (GRUB, Linux, CCID, gnulib for GRUB bootstrap)
live under `vendor/` at commits recorded in [docs/VENDORING.md](docs/VENDORING.md).
Those trees were **independently, manually verified** (tags, peeled commit IDs,
and maintainer OpenPGP key evidence documented there — verification is human-driven,
not re-run on every CI build). Builds are offline from `vendor/` plus pinned apt
packages in the Dockerfile; BLAKE3 pins catch accidental binary swaps.

---

## Documentation map

| Document | Role |
|----------|------|
| [docs/SPEC.md](docs/SPEC.md) | Full tool specification |
| [docs/FORMAT.md](docs/FORMAT.md) | On-disk / image layout (including Phase 4 blobs) |
| [docs/VENDORING.md](docs/VENDORING.md) | Pinned upstream commits and verification notes |
| [docs/OPEN-QUESTIONS.md](docs/OPEN-QUESTIONS.md) | Unresolved spec and engineering gaps |

Historical spec text may still appear in older copies; **docs/SPEC.md wins** on
conflicts ([AGENTS.md](AGENTS.md)).
