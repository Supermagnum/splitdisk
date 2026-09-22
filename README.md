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

## Current status (through Phase 6)

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
- **Phase 5–6 boot chain (QEMU, file-backed, `-nic none`):**
  GRUB EFI → kernel → initramfs → Rust `/init` → `splitdisk-assemble --agent`
  → `pcscd`, with serial markers. A missing protective MBR and initramfs
  newc modes without `S_IFREG` each blocked that path until fixed.

**Proven with limits:**

- PC/SC client path with a live ATR via **ifd-vpcd** + `vicc` (test tooling;
  not the USB CCID driver)
- In QEMU, production **ifd-ccid.so** is selected for an emulated USB CCID
  reader (`08e6:4433`) but **ATR still fails** (`Open Port` / init failed).
  That gap is documented, not closed. The optional probe
  `scripts/qemu-usb-ccid-atr.sh` is excluded from the default suite while
  ATR fails.

**Still open** (see [docs/OPEN-QUESTIONS.md](docs/OPEN-QUESTIONS.md) rather
than a full re-list here):

- Galdralag / ClassicalKem remains an **untested stub** (`KemNotAvailable`;
  no hardware or firmware emulator in CI)
- Multi-drive interactive PIN/TUI reconstruction is **not** proven
  end-to-end on the boot path (deferred)
- USB `ifd-ccid.so` ATR over QEMU or physical CCID hardware
- Spec crypto items still marked open in OPEN-QUESTIONS (e.g. Brainpool /
  HKDF wording)

Do not treat this tree as audited or secure for real data until those gaps
are closed and independent review has occurred.

---

## Build and test

All builds and tests are intended to run **inside the project container** with
**no network at test time**:

```bash
./scripts/test.sh
```

Uses Docker by default; set `CONTAINER_ENGINE=podman` if needed. The script
builds `splitdisk-test:phase6`, mounts the repo read-only, uses a large
`/tmp` tmpfs (default 48g for kernel object files) plus a writable `/run`
tmpfs for non-root pcscd in the harness, and runs
`scripts/docker-test-inner.sh` (fmt, clippy, vendor blob cache check,
kernel byte-repro check, `cargo test`, PC/SC vpcd ATR check, QEMU boot-chain,
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
