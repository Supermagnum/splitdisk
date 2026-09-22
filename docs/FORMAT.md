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
| `ifd-ccid.so` | `vendor/ccid` | Meson + Ninja compile (`-Dembedded=true`); copy `libccid.so` from the build dir (skip `meson install` — usbdropdir is under `/usr` and read-only in the test container) | `vendor-blobs/ccid/<commit>/` |

Entry point: `scripts/build-vendor-blobs.sh` (invoked by
`scripts/docker-test-inner.sh` before `cargo test`). Artifacts land under
`$SPLITDISK_BLOB_CACHE` (default `$CARGO_TARGET_DIR/vendor-blobs`). A cache
hit for the pinned commit skips rebuild.

**Expected wall-clock (cold cache, multi-core container):** observed on the
Phase 4 reference host roughly **~1 minute** GRUB and **~2 minutes** Linux
(defconfig + SPEC toggles); CCID under a minute. Other hosts may be slower.
Warm cache: seconds (copy/load only).

**Reproducibility of blob bytes:** builds use per-tree `SOURCE_DATE_EPOCH`
(git author date of the vendored commit). The Linux bzImage additionally sets
`KBUILD_BUILD_USER=splitdisk`, `KBUILD_BUILD_HOST=splitdisk`, and
`KBUILD_BUILD_TIMESTAMP` from that epoch; two cold builds in the same Docker
image are **byte-identical** (checked by `scripts/verify-kernel-repro.sh` in
the test suite). GRUB uses `-ffile-prefix-map=…` for the src/build trees;
**GRUB EFI and CCID `.so` still differ between cold rebuilds** in this image
(same size, differing bytes — likely PE/EFI packaging and link metadata).
BLAKE3 pins therefore remain the gate for those components.

Reproducibility is claimed **only relative to the pinned Dockerfile/apt
toolchain** (`gcc=4:12.2.0-3`, `meson=1.0.1-5`, `ninja-build=1.11.1-2~deb12u1`,
etc.), not for arbitrary hosts or compiler versions. See OPEN-QUESTIONS (j).

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
(reproducibility).

### 11.3 initramfs (cpio newc + gzip via `cpio` + `flate2`)

```
/init                              synthetic stub (banner + minimal ELF; no mount/exec yet)
/usr/bin/splitdisk-assemble        real workspace binary
/usr/lib/pcsc/drivers/ifd-ccid.so  real CCID IFD `.so` (Phase 4 Meson compile)
/etc/reader.conf.d/                empty directory (placeholder only)
/dev/ /proc/ /sys/ /tmp/           empty directories
```

**CCID install gap (Phase 4+):** the blob build runs `meson compile` only and
copies `libccid.so` into the initramfs path above. A full `meson install`
into pcsclite’s `usbdropdir` was skipped because that path lives under `/usr`
(read-only in the hardened test container). A normal install may also drop
bundled `Info.plist` / reader metadata and other files pcscd consults at
runtime. The initramfs therefore has the driver binary but may lack the
pcscd/CCID configuration needed for a working smart-card stack — layout
testing only until Phase 5+ (QEMU / initramfs policy). See OPEN-QUESTIONS (k).

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
