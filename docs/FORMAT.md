# SplitDisk on-drive formats (Phase 1–3 proposal)

**Status:** Proposed — not yet ratified. Every open choice is marked **OPEN**.
**Version field:** `u16` little-endian, current value `1`.

All multi-byte integers are **little-endian**. Parsers MUST bound every
length-prefixed field (Phase 1 cap: 64 MiB) and MUST NOT panic on untrusted
input.

---

## 1. Conventions

| Symbol | Meaning |
|--------|---------|
| `u8/u16/u32/u64` | Unsigned LE integers |
| `[n]` | Exactly n bytes |
| `||` | Concatenation |

Magic values are ASCII four-byte tags.

---

## 2. Segmented AEAD stream (`SDSE`)

Used for bulk image ciphertext (ChaCha20-Poly1305 first).

### 2.1 Stream header (12 bytes)

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | Magic `SDSE` |
| 4 | 2 | `version` (= 1) |
| 6 | 2 | `suite_id` (CESS id; Mode B visible — see OPEN) |
| 8 | 4 | `segment_size` (plaintext bytes per non-final segment) |

### 2.2 Segment record (repeated)

| Offset | Size | Field |
|--------|------|-------|
| 0 | 8 | `index` (0-based, contiguous) |
| 8 | 1 | `flags` (bit0 = `FINAL`) |
| 9 | 4 | `ct_len` |
| 13 | `ct_len` | AEAD ciphertext \|\| tag |

**Nonce derivation (OPEN, Phase 1 choice):**

```
nonce_key = BLAKE3-derive_key("splitdisk-aead-nonce-v1", session_key)
nonce     = BLAKE3-keyed(nonce_key, index_le64 || flags)[0..12]
```

**AAD:** `index_le64 || flags || suite_id_le16` (11 bytes).

**Rules:**

- Exactly one segment has `FINAL`.
- Non-final segments decrypt to exactly `segment_size` bytes.
- Final segment may be shorter (including empty for empty input).
- Missing `FINAL` or trailing data after `FINAL` => truncation/format error.
- Default `segment_size` = 4 MiB.

**OPEN:** Whether Mode A should omit cleartext `suite_id` from this header
and carry it only inside an outer envelope (SPEC §4.1). Phase 1 writes
`suite_id` clear for Mode B / testing.

---

## 3. BLAKE3-framed RS shard (`SDCF`) — `chunk.bin` records

Each share file is a concatenation of frames, one per stripe.
Frames do **not** carry `share_index` (holder anonymity, SPEC §2).

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | Magic `SDCF` |
| 4 | 2 | `version` (= 1) |
| 6 | 8 | `stripe_index` |
| 14 | 4 | `original_stripe_len` (pre-pad) |
| 18 | 4 | `shard_len` |
| 22 | 32 | BLAKE3(shard bytes) |
| 54 | `shard_len` | shard payload |

Share identity for RS join comes from PIN-unlocked `meta.bin` only.

**OPEN:** Stripe size must be divisible by `k` in Phase 1. Spec implies
`ceil(image/k)` without requiring divisibility — padding policy needs ratify.

---

## 4. Metadata plaintext (`SDMT`) — contents of `meta.bin` before AEAD

SPEC: `meta.bin` is encrypted with `K_pin`.

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | Magic `SDMT` |
| 4 | 2 | `version` (= 1) |
| 6 | 1 | `share_index` |
| 7 | 1 | `k` |
| 8 | 1 | `n` |
| 9 | 2 | `suite_id` |
| 11 | 32 | `chunk_blake3` (hash over entire `chunk.bin`) |
| 43 | 32 | `drive_fingerprint` (CSPRNG; duplicate detection) |
| 75 | 4 | `stripe_size` (Phase 2; RS stripe bytes) |

Total fixed size: **79 bytes**.

**`share_index` is never stored or transmitted in cleartext** on the drive
(header, chunk frames, filenames, or logs). It exists only inside this
PIN-encrypted plaintext. Reason: holder anonymity (SPEC §2 — a drive holder
must not learn their share index).

**AEAD wrap:** ChaCha20-Poly1305 under `K_pin`. Nonce =
`BLAKE3-derive_key("splitdisk-meta-nonce-v1", K_pin)[0..12]`. AAD =
`drive_uuid` (16 random cleartext bytes from the drive header — no semantic
link to `share_index`).

**OPEN:** Whether `k`/`n` belong in every drive (needed for assembly) vs only
a hidden scheme id. SPEC stores them in meta; anonymity trade-off is accepted
for holders without PIN, but anyone with PIN learns k and n.

---

## 5. PIN hash file (`pin.hash`)

SPEC §5.2: Argon2id hash with per-drive 16-byte salt. Byte layout was
undefined.

### Layout (versioned) — implemented Phase 2

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | Magic `SDPH` |
| 4 | 2 | `version` (= 1) |
| 6 | 4 | `m_cost` (KiB; default 65536 = 64 MiB) |
| 10 | 4 | `t_cost` (default 3) |
| 14 | 4 | `p_cost` (default 4) |
| 18 | 16 | `salt` |
| 34 | 32 | `argon2id_output` |

**OPEN:** Store full Argon2 PHC string vs raw params+salt+hash. Raw is
simpler for musl/initramfs; PHC is more interoperable.

**OPEN:** Offline guessing — see `docs/OPEN-QUESTIONS.md` (f).

---

## 6. Mode A outer envelope header (`SDEV`)

Clear header before outer AEAD body. **Not implemented in Phase 2** — see
OPEN-QUESTIONS (a) (Brainpool arithmetic gated).

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | Magic `SDEV` |
| 4 | 2 | `version` (= 1) |
| 6 | 1 | `mode` (0 = B suite visible, 1 = A suite concealed) |
| 7 | 2 | `suite_id` (Mode B only; zero in Mode A) |
| 9 | 4 | `body_len` |

**OPEN:** Ephemeral Brainpool public key encoding and ciphertext framing for
Mode A KEM (SPEC §4.1). Blocked on ClassicalKem availability.

---

## 7. Encrypted key share at rest (`SDKW`)

SPEC: key share wrapped with ChaCha20-Poly1305 under `K_pin`.
**Phase 2: PIN path only — no ECDH.**

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | Magic `SDKW` |
| 4 | 2 | `version` |
| 6 | 12 | `nonce` |
| 18 | 4 | `ct_len` |
| 22 | ct_len | ciphertext \|\| tag |

AAD: `drive_uuid` (same 16-byte cleartext value as meta seal; not share_index).

---

## 8. File-backed drive container (`SDDR`) — Phase 2

Regular-file carrier used by `splitdisk-create` / `splitdisk-assemble` until
real GPT/FAT images exist (`splitdisk-image`).

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | Magic `SDDR` |
| 4 | 2 | `version` |
| 6 | 32 | `source_blake3` |
| 38 | 16 | `drive_uuid` (CSPRNG; no share-index semantics) |
| 54 | 2 | `suite_id` (Mode B visible) |
| 56 | 8 | `chunk_off` |
| 64 | 8 | `chunk_len` |
| 72 | 8 | `pin_off` |
| 80 | 8 | `pin_len` |
| 88 | 8 | `share_off` |
| 96 | 8 | `share_len` |
| 104 | 8 | `meta_off` |
| 112 | 8 | `meta_len` |

Then sequential payloads: chunk \| pin.hash \| SDKW \| sealed meta.

**`drive_uuid` role:** Opaque per-drive random 16 bytes, generated at
enrollment independently for each drive (OS/test CSPRNG). Safe to expose in
cleartext for the same reason as the EFI volume UUID (SPEC §6): it carries no
holder identity or share-index information. Used solely as AEAD AAD for
`meta.bin` and `SDKW` so those layers can authenticate without putting
`share_index` in cleartext.

**Forbidden:** Encoding `share_index` (or any monotone function of it) into
`drive_uuid`, filenames, logs, or any other cleartext field.

---

## 9. Pin.hash and meta relationship

**OPEN:** Single AEAD package vs separate files. SPEC lists separate paths
under `/share/auth/` and `/share/meta.bin`. Phase 2 keeps them separate
sections inside `SDDR`.

---

## 10. Assembly journal (`SDJN`) — Phase 2

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | Magic `SDJN` |
| 4 | 2 | `version` |
| 6 | 32 | `source_blake3` |
| 38 | 8 | `segments_committed` |
| 46 | 8 | `bytes_committed` |
| 54 | 32 | `running_blake3` (plaintext prefix) |
| 86 | 32 | `last_segment_blake3` |
| 118 | 1 | `complete` (0/1) |

---

## 11. Base USB image layout (`splitdisk-image`, Phase 4)

Standalone base image produced by:

```bash
splitdisk-image --output base.img --size 512MiB --assemble-bin path/to/splitdisk-assemble
```

Optional `--drive-uuid <32 hex chars>` fixes the 16-byte Phase 2 `drive_uuid`
(used as the seed for GPT disk/partition GUIDs, FAT volume id, and ext4 UUID).
Without it, a CSPRNG value is used (real drives).

### 11.0 Real boot blobs (GRUB / kernel / CCID)

Phase 4 replaces synthetic placeholders with binaries built **offline** from
the human-verified trees under `vendor/` (see `docs/VENDORING.md`):

| Blob | Source | Build | Cache key |
|------|--------|-------|-----------|
| `BOOTX64.EFI` | `vendor/grub` + `vendor/gnulib` | `bootstrap` / `configure --with-platform=efi` / `grub-mkstandalone` | `vendor-blobs/grub/<commit>/` |
| `bzImage` | `vendor/linux` | `make O=… defconfig` + SPEC §10.5 `scripts/config` toggles / `bzImage` | `vendor-blobs/linux/<commit>/` |
| `ifd-ccid.so` | `vendor/ccid` | Meson + Ninja from canonical `/tmp/splitdisk-ccid-src` (`-Dembedded=true`, `-ffile-prefix-map`, `--build-id=none`); copy `libccid.so` from build dir (skip `meson install` — usbdropdir under `/usr` is read-only in the test container) | `vendor-blobs/ccid/<commit>/` |

Entry point: `scripts/build-vendor-blobs.sh` (invoked by
`scripts/docker-test-inner.sh` before `cargo test`). Artifacts land under
`$SPLITDISK_BLOB_CACHE` (default `$CARGO_TARGET_DIR/vendor-blobs`). A cache
hit for the pinned commit skips rebuild.

**Expected wall-clock (cold cache, multi-core container):** observed on the
Phase 4 reference host roughly **~1 minute** GRUB and **~2 minutes** Linux
(defconfig + SPEC toggles); CCID under a minute. Other hosts may be slower.
Warm cache: seconds (copy/load only).

**Reproducibility of blob bytes:** builds use per-tree `SOURCE_DATE_EPOCH`
(git author date of the vendored commit).

- **Linux bzImage:** `KBUILD_BUILD_USER/HOST=splitdisk` and
  `KBUILD_BUILD_TIMESTAMP` from that epoch; two cold builds in the same Docker
  image are **byte-identical** (`scripts/verify-kernel-repro.sh`).
- **CCID `libccid.so`:** sources are copied to fixed `/tmp/splitdisk-ccid-src`
  and built with Meson `-Dc_args=-ffile-prefix-map…` /
  `-Dc_link_args=-Wl,--build-id=none` so bind-mount names (`/src` vs `/work`)
  do not leak via `__FILE__`. Two cold builds under different mount points in
  this image are **byte-identical**.
- **GRUB EFI:** `-ffile-prefix-map` is applied; **output may still differ**
  between cold rebuilds. The checked-in BLAKE3 pin matches a known-good cache
  entry but is not a cross-rebuild guarantee.

Reproducibility is claimed **only relative to the pinned Dockerfile/apt
toolchain**, not for arbitrary hosts or compiler versions. See OPEN-QUESTIONS (j).

`scripts/test.sh` uses a large `/tmp` tmpfs (default **48g**, override with
`SPLITDISK_TMPFS_SIZE`) so the kernel tree + object files fit. That is a
resource limit only (OPEN-QUESTIONS (i)), not a network or capability change.

### 11.1 GPT (via `gpt` crate)

| Partition | Type | Default size | Contents |
|-----------|------|--------------|----------|
| 1 | EFI System | 256 MiB when image >= 512 MiB; scaled down for smaller fixtures | FAT32 ESP |
| 2 | Linux filesystem | remainder (minus GPT backup) | ext4 system |

First usable data starts at LBA 2048 (1 MiB alignment). GUIDs are derived from
`drive_uuid` with BLAKE3 domain labels (`splitdisk-gpt-*-v1`), not a separate
UUID scheme.

### 11.2 ESP (FAT32 via `fatfs`)

```
/EFI/BOOT/BOOTX64.EFI     real GRUB x86_64-efi standalone (Phase 4)
/boot/vmlinuz             real Linux bzImage (Phase 4, SPEC §10.5 config)
/boot/initramfs.img       cpio+gzip initramfs (see 11.3)
/boot/grub/grub.cfg       SPEC §10.4 text (timeout=0, single SplitDisk entry)
```

`fatfs` is built **without** the `chrono` feature so file timestamps are fixed
(reproducibility). Phase 5 confirmed OVMF can mount this ESP **once a protective
MBR is present** (OPEN-QUESTIONS (n)); earlier boot failures were MBR-related,
not Fat-formatter-related.

### 11.3 initramfs (cpio newc + gzip via `cpio` + `flate2`)

```
/init                         Rust splitdisk-init: mount /proc,/sys,tmpfs /tmp
                              (+ /run), then execve splitdisk-assemble --agent
/usr/bin/splitdisk-assemble   workspace binary (+ glibc/ld deps staged in)
/usr/sbin/pcscd               staged from Debian pcscd (Phase 6)
/usr/lib/pcsc/drivers/ifd-ccid.bundle/Contents/Info.plist
/usr/lib/pcsc/drivers/ifd-ccid.bundle/Contents/Linux/libccid.so
/etc/reader.conf.d/           empty (USB CCID needs no serial reader.conf)
/dev/ /proc/ /sys/ /tmp/ /run/  mount points
```

**pcscd ownership (SPEC §10.3):** `splitdisk-assemble --agent` starts
`pcscd --foreground` as a subprocess after printing
`SPLITDISK_ASSEMBLE_STARTED`. `/init` does not spawn pcscd.

**CCID bundle (item (k) closed):** pcsclite loads IFDs from the bundle
layout above. Flat `ifd-ccid.so` alone is not sufficient. `Info.plist` is
copied from the Meson build dir (no full `meson install` into `/usr`).

Gzip mtime is forced to 0. Cpio entry mtimes are fixed at `1000000000`.

### 11.4 System partition (ext4 via `mke2fs` + `debugfs -w`)

**Construction (OPEN-QUESTIONS (h) option C):** the system partition is a
regular file created with the Dockerfile-pinned `e2fsprogs` tools — never a
hand-rolled serializer, never mounted, never attached via loop:

1. Truncate a staging file to the GPT system-partition size.
2. `mke2fs -t ext4 -F -b 4096 -U <uuid> -E hash_seed=<seed>,lazy_itable_init=0,nodiscard -O ^has_journal -L '' <file>`
   where `<uuid>` and `<seed>` are RFC-4122 UUIDs derived from Phase 2
   `drive_uuid` (`splitdisk-ext4-fs-uuid-v1` / `splitdisk-ext4-hash-seed-v1`).
3. Populate with `debugfs -w -f <cmds>` (mkdir + `write` for
   `usr/bin/splitdisk-assemble` and `boot/initramfs.img`; empty
   `share/` and `share/auth/`).
4. Splice the staging file into the GPT image at `system_offset`.

**Journal:** disabled (`-O ^has_journal`). The partition is written once at
enrollment and then read-mostly during assembly; a journal would add flash
write amplification without benefit for this workload.

**Volume label:** blank (`-L ''`), matching SPEC §6.

**Validation:** `fsck.ext4 -n -f` on the extracted partition must exit 0
(see `image_layout` test).

```
/usr/bin/splitdisk-assemble   real assemble binary
/boot/initramfs.img           same archive as on the ESP
/share/                       empty (share data is splitdisk-create's job)
/share/auth/                  empty
```

No `chunk.bin`, `pin.hash`, `meta.bin`, or biometric files in the base image.

**Reproducibility note:** GPT + FAT regions are byte-identical across runs
with a fixed `drive_uuid`. The ext4 region is only *structurally*
equivalent (same directory tree and file bytes): `mke2fs`/`debugfs`
stamp wall-clock times into the superblock and inodes, and
`metadata_csum` covers those fields, so full-image byte identity is not
preserved without fragile post-processing. Tests assert GPT+ESP byte
identity plus structural equivalence of the system partition.

### 11.5 Reproducibility (SPEC §10.1)

| May vary between real drives / runs | Must be identical given identical inputs |
|-------------------------------------|------------------------------------------|
| `drive_uuid` (when not fixed on CLI) | GPT structure and sizes for a given `--size` |
| Share payloads written later by `splitdisk-create` | FAT file bytes (real GRUB/kernel + grub.cfg + initramfs) |
| ext4 wall-clock timestamps / `metadata_csum` from mke2fs+debugfs | System partition **tree and file contents** (structural) |
| GRUB / kernel / CCID toolchain non-determinism across hosts | initramfs cpio+gzip bytes (fixed mtimes) |
| | Derived GPT/FAT identifiers when `drive_uuid` is fixed |

BLAKE3 pins for real blobs (checked into `vendor.rs`): `grub_efi`,
`kernel_bzimage`, `ccid_ifd_ccid_so`. Trust chain for the *source* trees is
`docs/VENDORING.md`; pins catch accidental binary swaps after build.

---

## 12. Phase 5 QEMU boot-chain testing

SPEC §§6 and §10 describe an **EFI** boot path (GPT + ESP with
`BOOTX64.EFI`, kernel, initramfs). Phase 5 therefore installs **OVMF**
(UEFI firmware) alongside `qemu-system-x86` in the Docker test image
(pinned apt versions; network only at image build time). BIOS/SeaBIOS is
not used — it would not exercise the shipped GRUB EFI layout.

### 12.1 Why UEFI firmware is required

The base image ESP contains a GRUB **x86_64-efi** standalone image at
`/EFI/BOOT/BOOTX64.EFI`. That binary is loaded by UEFI firmware, not by
legacy BIOS. QEMU must be started with OVMF `CODE`/`VARS` pflash images so
the guest firmware finds and executes the ESP bootloader the same way a
real UEFI machine would.

### 12.2 Test-only serial console (does not ship in production)

Production `grub.cfg` and the embedded config inside production
`BOOTX64.EFI` keep SPEC §10.4 quiet cmdline (`quiet loglevel=0 …`).

`BOOTX64-TEST-SERIAL.EFI` is **not** a separate GRUB build or fork. It is
produced by the **same** `scripts/build-vendor-blobs.sh` GRUB pipeline from
the same `vendor/grub` (+ gnulib) tree and the same `grub-mkstandalone`
install prefix as production `BOOTX64.EFI`. The only differences are the
embedded grub.cfg (serial / `console=ttyS0` / `rdinit=/init`) and the
extra `serial` module on the mkstandalone module list. Both artifacts land
side-by-side under `…/grub/<COMMIT_GRUB>/`.

QEMU smoke tests need serial boot evidence. That is achieved **only** by:

1. Loading `BOOTX64-TEST-SERIAL.EFI` via `ImageRequest::grub_efi_override`
   (helper bin `mk-qemu-boot-image` only).
2. Writing `GRUB_CFG_TEST_SERIAL` to the ESP via
   `ImageRequest::test_serial_console` (same helper).

**Excluded from production / pins:**

- `PIN_GRUB_EFI` digests **only** quiet `BOOTX64.EFI` (`BLOB_GRUB_EFI`).
  `BOOTX64-TEST-SERIAL.EFI` is never hashed into that pin.
- `ImageRequest::production` sets `test_serial_console: false` and
  `grub_efi_override: None`, so the CLI `splitdisk-image` path and all
  layout tests write production `BOOTX64.EFI` + quiet `GRUB_CFG` only.
  Nothing in the non-test image builder selects the test-serial EFI.

### 12.3 Harness

`scripts/qemu-boot-chain.sh` (invoked from `docker-test-inner.sh` when
`vendor/` is present):

- File-backed USB mass storage (`usb-storage` on `qemu-xhci`), `-nic none`,
  `-display none`, serial to a log file, QMP for hot-plug / reset.
- Asserts serial log contains kernel boot evidence and
  `SPLITDISK_INIT_REACHED` from the static `/init` stub.
- Demonstrates QMP `device_add`/`device_del` of a second usb-storage drive.
- `system_reset` + fresh QEMU against the same image (limited value while
  `/init` does not write the image — see OPEN-QUESTIONS (l)).

### 12.4 Resource / timing expectations

| Mode | When | Cold boot to `/init` marker (measured) |
|------|------|----------------------------------------|
| KVM (`-enable-kvm`, `/dev/kvm` into the container) | Host has KVM | **~6s** wall (Phase 5 laptop run) |
| TCG (`-accel tcg`, forced via `SPLITDISK_QEMU_ACCEL=tcg`) | Same host, no KVM | **~6s** wall (Phase 5 follow-up; guest timestamps ~2× KVM for early boot, OVMF+poll dominate wall) |

Earlier Phase 5 docs guessed “1–3+ minutes” for TCG; that was an **unmeasured estimate** and is **wrong for this workload on this host**. Timeout default remains 180s as a safety net for slower CI CPUs. Force TCG with `SPLITDISK_QEMU_ACCEL=tcg` (harness does not pass `/dev/kvm` when measuring TCG).

`scripts/test.sh` passes `--device /dev/kvm` when the host node exists;
otherwise the guest runs under TCG. With either accel, the Phase 5 QEMU
section (cold + hot-plug + reset + fresh) is typically under a minute on
a similar machine; CI time is still dominated by Phase 4 vendor blob builds.

### 12.5 Initramfs cpio modes (Phase 5 fix)

newc file entries must include `S_IFREG` (`0o100755` / `0o100644`), not
permission bits alone. Without the file-type bit, Linux’s initramfs unpacker
does not create a regular `/init`, and the kernel panics mounting a real root
instead of running the stub.

Kernel Phase 5 config additions (still SPEC §10.5 base +): `CONFIG_SERIAL_8250`,
`CONFIG_SERIAL_8250_CONSOLE`, `CONFIG_SERIAL_CONSOLE`, `CONFIG_DEVTMPFS`,
`CONFIG_DEVTMPFS_MOUNT` so test-only `console=ttyS0` works.

---

## 13. Phase 6: real `/init`, pcscd, GnuPG/vpcd validation

### 13.1 `/init` sequence

1. Print `SPLITDISK_INIT_STARTING`.
2. Mount `proc` on `/proc`, `sysfs` on `/sys`, `tmpfs` on `/tmp` and `/run`.
3. On failure: greppable `SPLITDISK_INIT_FAIL_MOUNT_*` / `SPLITDISK_INIT_FAIL_MOUNTS`, then idle (no kernel panic).
4. Print `SPLITDISK_INIT_MOUNTS_OK`, then `execve("/usr/bin/splitdisk-assemble", ["--agent"])`.
5. On exec failure: `SPLITDISK_INIT_FAIL_EXEC`, then idle.

### 13.2 Assemble agent + pcscd

`splitdisk-assemble --agent` prints `SPLITDISK_ASSEMBLE_STARTED`, checks for
`ifd-ccid.bundle`, starts `pcscd --foreground`, prints
`SPLITDISK_PCSCD_STARTED` (or `SPLITDISK_PCSCD_FAIL_*`), then idles.
Interactive multi-drive PIN/reconstruction is **deferred to Phase 7**.

### 13.3 GnuPG + vsmartcard (container)

`scripts/pcsc-gpg-vpcd-test.sh` runs **in the Docker test container** (not
inside QEMU):

`gpg --card-status` → scdaemon → pcscd → **ifd-vpcd** (Debian reader.conf)

Debian bookworm’s `vsmartcard-vpcd` ships the IFD and reader.conf but **not**
the `vpcd` TCP daemon, so a live virtual-card ATR is not available from
distro packages alone. The test therefore asserts: CCID bundle inputs present,
pcscd starts with the vpcd IFD configured, and gpg can IPC to pcscd (failure
mode is “no card”, not “pcscd unreachable”). That is real third-party PC/SC
client evidence. USB `ifd-ccid.bundle` is a different IFD (USB CCID protocol);
claiming gpg→CCID.so→vpcd would be false.

QEMU separately proves `/init` → `splitdisk-assemble --agent` → pcscd with
the CCID bundle present (`SPLITDISK_PCSCD_CCID_BUNDLE_OK`). Embedding GnuPG in
the initramfs was not done.

**Initramfs glibc staging:** `scripts/stage-initramfs-runtime.sh` copies
`pcscd` and assemble `ldd` dependencies with `cp -aL` (dereference). Plain
`cp -a` left soname symlinks without their ELF targets, so `execve` of
assemble failed with `ENOENT` (missing interpreter / libs). Docker bakes the
tree at `/usr/local/share/splitdisk/pcsc-runtime`; QEMU/tests may overlay via
`SPLITDISK_INITRAMFS_EXTRA` (overlay wins on path collision).

**Production BLAKE3 pins:** the `cp -aL` staging path and
`SPLITDISK_INITRAMFS_EXTRA` overlay do **not** touch `PIN_CCID_IFD`,
`PIN_KERNEL`, or `PIN_GRUB_EFI`. Those pins cover vendor blobs under
`testdata/vendor-blobs/` (GRUB EFI, kernel bzImage, `ifd-ccid.so`). Staged
glibc/pcscd bits are runtime initramfs extras (like Phase 5’s
`BOOTX64-TEST-SERIAL.EFI` exclusion): they affect the bootable test image’s
initramfs contents but are not production pin identities.

### 13.4 Live ATR via built ifd-vpcd + vicc (Phase 6 follow-up)

Debian bookworm’s `vsmartcard-vpcd` package is the **IFD** (`libifdvpcd.so`),
not a missing TCP daemon. Upstream has no standalone `vpcd` daemon binary:
`src/vpcd/` builds `libvpcd` (socket helpers linked into ifd-vpcd); the IFD
listens on **127.0.0.1:35963** (and 35964); `vicc` connects as the virtual
card. Transport stays on loopback and works under `--network none`.

Debian’s `python3-virtualsmartcard` / `vicc` layout is broken on Python 3.11
(module path + legacy imports), so the test image builds
**frankmorgner/vsmartcard tag `virtualsmartcard-0.10`**
(tarball SHA-256 `76897e4506e03b399a1dd394295d29621911b399d66a31acb5eb6b65131c726e`)
via `scripts/build-vsmartcard-test.sh` into
`/usr/local/share/splitdisk/vsmartcard-test/`. This is **test tooling only**:
not embedded in the production initramfs, not covered by production BLAKE3
pins (`PIN_CCID_IFD` / `PIN_KERNEL` / `PIN_GRUB_EFI`). No signature-
verification bar (unlike vendor GRUB/kernel/CCID) because it never ships.

`scripts/pcsc-gpg-vpcd-test.sh` starts pcscd with a private `reader.conf`
whose `LIBPATH` is **our** built `libifdvpcd.so`, starts
`vicc -t handler_test`, then fetches the ATR via PC/SC `SCardGetAttrib`.
Measured ATR (hex):

`3bd6180080b1806d1f038051006110309e`

(pcscd verbose: `Card ATR: 3B D6 18 00 80 B1 80 6D 1F 03 80 51 00 61 10 30 9E`).
pcscd logs show `Attempting startup … using …/vsmartcard-test/lib/libifdvpcd.so`
and `Got ATR (17 bytes)` from ifd-vpcd — not Debian’s IFD and not USB
`ifd-ccid.so`.

**Explicit non-claim:** SplitDisk’s production USB `ifd-ccid.bundle`
(`PIN_CCID_IFD`) is a different IFD protocol (USB CCID). It cannot speak to
vpcd/vicc. Proving that `.so` still needs a USB CCID device (physical or
QEMU `usb-ccid`); see OPEN-QUESTIONS (l).

`gpg --card-status` against `handler_test` still reports “OpenPGP card not
available” because the emulator is not an OpenPGP applet — that is expected;
the PC/SC ATR path is the proof requested here.

### 13.5 QEMU `usb-ccid` vs production `ifd-ccid.so` (follow-up)

Pinned QEMU 7.2 (`qemu-system-x86` in the Dockerfile) **includes**
`usb-ccid`, `ccid-card-emulated`, and `ccid-card-passthru` — no rebuild.
Probe script: `scripts/qemu-usb-ccid-atr.sh` (optional; not part of the
default green suite while ATR remains failing).

Observed on the Phase 6 boot guest:

1. Kernel enumerates `QEMU USB CCID` (`08e6:4433`).
2. pcscd loads **production**
   `…/ifd-ccid.bundle/Contents/Linux/libccid.so` (BLAKE3-pinned IFD).
3. Reader match: “Gemalto Gemplus USB SmartCard Reader 433-Swap”.
4. Then `Open Port … Failed` / `init failed` — **no ATR**.

Host `ccid-card-emulated` (certificates backend + NSS test DB) does insert
a virtual card. The remaining break is the guest IFD opening the emulated
USB CCID channel. Documented in OPEN-QUESTIONS (l) as an accepted
limitation pending quirk/stack work or physical hardware.

### 13.6 Production vs test writability (`/run`)

Production `/init` already mounts a tmpfs on `/run` (and creates
`/run/pcscd`) so assemble can start pcscd. That is a **runtime** tmpfs inside
the initramfs guest, not a change to the read-mostly GPT/ESP image layout
from Phase 3. The `--tmpfs /run` flag in `scripts/test.sh` is **only** for
the hardened Docker test harness (non-root host-side pcscd in the container);
it does not alter production image contents.

Galdralag remains untested (OPEN-QUESTIONS (o)).
