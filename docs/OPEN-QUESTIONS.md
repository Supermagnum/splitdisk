# Open questions (Phase 1)

Items discovered while implementing Phase 1. Spec references are to
`docs/SPEC.md` (currently mirrored from repository `README.md`).

Do **not** treat recommendations below as ratified security properties
(AGENTS Rule 28). Cryptographer review is required before deployment.

---

## (a) Brainpool crates: `p384` is NIST P-384, not BrainpoolP384r1

### What the spec says

§4.4 / §16 list crate `p384` for "BrainpoolP384r1 ECDH base" and comment
"BrainpoolP384r1 / BrainpoolP512r1". CESS excludes NIST-only curves.

### What is ambiguous / wrong

RustCrypto's `p384` implements **NIST P-384**, which CESS excludes. It does
not implement BrainpoolP384r1.

### Phase 2 status (2026-09) — arithmetic still unavailable

RustCrypto `bp384` / `bp256` exist for the correct curves, but **field/group
arithmetic is feature-gated** behind `wip-arithmetic-do-not-use`. With that
gate, there is **no working, audited Brainpool ECDH** usable from safe Rust
crates today. There is still **no** audited, license-compatible crate for
BrainpoolP512r1.

Phase 2 therefore:

- Does **not** implement ECDH, Mode A outer-envelope KEM wrapping, or any
  in-transit key wrap that depends on Brainpool.
- Adds `ClassicalKem` + `UnimplementedKem` in `splitdisk-core` (returns
  `Error::KemNotAvailable`).
- Uses the **PIN-derived key path only** for wrapping SSS shares at rest
  (`SDKW` under `K_pin`).
- Does **not** FFI to OpenSSL/Botan/libecc as a quiet fallback (that remains
  an explicit later decision).

### Options

| Option | Pros | Cons |
|--------|------|------|
| A. Wait for RustCrypto to un-gate `bp384`/`bp256` arithmetic | Audited ecosystem; correct curves | Blocked today |
| B. Depend on `p384` (NIST) | Compiles now | **Violates CESS** |
| C. BrainpoolP512r1 via future `bp512` | Matches full CESS | Not available |
| D. Explicit FFI to OpenSSL/Botan Brainpool | Unblocks ECDH | New audit/FFI surface; must be a recorded decision |
| E. Third-party `bp512` on crates.io | Exists | Weak audit story; license risk vs GPL-3.0 |

### What would unblock ECDH / Mode A

1. RustCrypto ships Brainpool arithmetic **without** the WIP feature (or an
   independently audited equivalent crate), **or**
2. Project explicitly accepts option D (FFI) after cryptographer + license review.

Until then, Mode A outer envelope and Galdralag-style ECDH share transport
remain out of scope for implementation.

### Recommendation

- Keep option A as the preferred path; track upstream.
- Do not enable `wip-arithmetic-do-not-use` in production code.
- Do not ship BrainpoolP512r1 until option C or D is ratified.
- Continue PIN-only share wrap for USB Mode B / Phase 2 file carriers.

---

## (b) "HKDF-BLAKE3 (HMAC-BLAKE3 as PRF)" is non-standard

### What the spec says

§4.1: KDF is HKDF-BLAKE3 with RFC 5869 structure, HMAC-BLAKE3 as PRF, with
info strings `cess-kem-v1`, `cess-pin-v1`, `cess-outer-envelope-v1`.

### What is ambiguous

- There is no widely deployed "HMAC-BLAKE3" in RustCrypto `hmac` + `blake3`.
- The `hkdf` crate expects a `digest::Mac` / digest-style PRF; BLAKE3 does not
  implement those traits the same way SHA-2 does.
- BLAKE3 itself recommends `derive_key` / keyed hash for KDF use, not HKDF-HMAC.

### Options

| Option | Pros | Cons |
|--------|------|------|
| A. BLAKE3 `derive_key(info, ikm)` with CESS info as context | Audited primitive; API intended for KDF; simple | Not RFC 5869 Extract-then-Expand; salt/extract phase absent |
| B. Implement RFC 5869 with HMAC-BLAKE3 built from keyed BLAKE3 | Matches spec wording | Custom construction; needs cryptographer review; easy to get wrong |
| C. HKDF-HMAC-SHA256 | Standard crates | Violates CESS (SHA-2 excluded) |
| D. HKDF with a BLAKE3-based PRF via a thin verified adapter | Closer to RFC 5869 | Still custom; must specify Extract salt (zeros vs random) |

### Recommendation

**Phase 1 implements option A** (`blake3::derive_key`) with the CESS info
strings as context. Label outputs as **not** claiming RFC 5869 compliance.
Ask a cryptographer whether CESS requires true Extract-Expand; if yes, adopt
a reviewed HMAC-BLAKE3 HKDF (option B/D) in a later phase and version the
KDF id in the format.

---

## (c) `vsss-rs` GF(2^8) polynomial and CSPRNG

### What the spec says

§4.3: Shamir over GF(2^8) with reduction polynomial
`x^8 + x^4 + x^3 + x + 1` (CESS §5.1), via `vsss-rs`, caller CSPRNG.

### Findings

- `vsss-rs` (v5) provides `Gf256` with constant-time field ops.
- Reduction uses byte `0x1b`, i.e. the AES/CESS polynomial
  `x^8 + x^4 + x^3 + x + 1`. **Matches.**
- `Gf256::split_bytes(threshold, limit, secret, rng)` accepts
  `RngCore + CryptoRng` — caller-supplied CSPRNG. **Matches.**
- Spec pins `vsss-rs = "3"`; current API used here is **5.x** (Gf256 helpers).

### Options if mismatch had existed

1. Pin an older vsss-rs and verify vectors against CESS.
2. Different audited SSS crate with explicit GF(2^8) AES poly.
3. Spec change (forbidden without review).

### Recommendation

Use **vsss-rs 5.x** `Gf256`, update SPEC dependency pin, add cross-check KATs
when CESS publishes byte vectors. Phase 1 includes proptest roundtrips and
k-1 non-recovery checks.

---

## (d) Chunked / segmented AEAD for large images

### What the spec says

Bulk ChaCha20-Poly1305 over the image; streaming enrollment. No segment
construction is specified. A single AEAD message cannot cover hundreds of GiB
safely or practically.

### Proposed construction (implemented in Phase 1)

See `docs/FORMAT.md` §2 (`SDSE`):

1. Fixed plaintext segment size (default 4 MiB).
2. Per-segment nonce = keyed-BLAKE3(session_key, index \|\| flags)\[0..12\].
3. AAD binds `index`, `FINAL` flag, and `suite_id`.
4. Exactly one `FINAL` segment; decrypt fails on truncation or trailing data.
5. Non-final segments must be full size (prevents silent shortening).

### Alternatives considered

| Option | Notes |
|--------|-------|
| STREAM / ChaCha20-Poly1305 STREAM designs | Good prior art; would need explicit CESS adoption |
| Random per-segment nonces stored beside CT | Extra storage; must ensure uniqueness |
| One key per segment via KDF | Heavier; similar security if done correctly |

### Recommendation

Keep Phase 1 construction; mark for cryptographer review before claiming
multi-gigabyte security. Consider aligning with an existing STREAM AEAD
profile if CESS defines one.

---

## (e) Mode A envelope, `meta.bin`, `chunk.bin`, `pin.hash` layouts

### What the spec says

File names and high-level roles (§6, §5.2); **no byte layouts**.
Holder anonymity (§2): a drive holder must not learn their share index;
`meta.bin` is encrypted with `K_pin` specifically so index/k/n stay hidden
without the PIN.

### Phase 2 mistake (corrected)

Early Phase 2 put `share_index` in the cleartext `SDDR` header so it could be
used as AEAD AAD for `meta.bin` (chicken-and-egg: need AAD before decrypting
the blob that contains the index). That **directly violated** §2 and the
purpose of encrypting meta.

### Correction

- Generate a per-drive random 16-byte `drive_uuid` (CSPRNG; no semantic link
  to share index — same class of cleartext identifier as the EFI volume UUID
  in SPEC §6).
- Use `drive_uuid` as AAD for meta seal and SDKW key-wrap.
- Keep `share_index` only inside PIN-encrypted `SDMT` plaintext.
- Remove `share_index` from cleartext SDCF chunk frames as well.

See `docs/FORMAT.md` §§3–4, §7–8. Test:
`share_index_not_in_cleartext_on_any_drive` in assemble fault-injection tests.

### Resolution (layouts)

Proposed versioned layouts in `docs/FORMAT.md`. Phase 1–2 implement parsers
for SDSE, SDCF, SDMT, SDEV stub, SDPH, SDKW, SDDR. Mode A / ECDH remains
blocked — see (a).

---

## (f) PIN design: offline guessing

### What the spec says

- Argon2id hash stored on the drive (`pin.hash`).
- Key share AEAD-wrapped under `K_pin` derived from Argon2id output.
- Software attempt counter: 5 tries per insertion, then eject; hash not wiped.

### Implications

1. **An attacker who images the drive** can run unlimited offline Argon2id
   guesses against `pin.hash` and/or trial-decrypt the wrapped share.
2. The **software attempt counter does not bind** an offline adversary.
3. Argon2id parameters (64 MiB, t=3, p=4) only slow guesses; short
   alphanumeric PINs (≥5 chars) remain weak against well-funded offline
   attack.
4. Unlike Galdralag hardware counters, USB mode has **no forced wipe** on
   limit exhaustion.

### Options

| Option | Pros | Cons |
|--------|------|------|
| A. Document as accepted risk; rely on k-of-n | Honest; matches current USB model | Weak PINs fail |
| B. Increase Argon2 cost / PIN entropy requirements | Raises offline cost | UX pain; still not hardware binding |
| C. Require Galdralag (or similar) for high assurance | Hardware counter + wipe | Not always available |
| D. Store only a verifier that needs online rate-limit | N/A — air-gapped / no network (SPEC §14) | Out of scope |
| E. Encrypt share under a key mixed with a high-entropy
    enrollment secret sealed elsewhere | Stronger | New design; breaks current UX |

### Recommendation

Record **A** as the current SPEC behaviour; warn operators that USB-mode PINs
are **not** a hard barrier against forensic imaging. Prefer Galdralag (C) when
coercion/forensics matter. Do not claim the software counter stops offline
attackers (Rule 28).

---

## Additional Phase 1 notes

### Stripe size vs `k`

RS helper requires `stripe_size % k == 0`. Spec size formula uses
`ceil(image_size / k)` without this constraint. **OPEN:** pad policy at
create time (round stripe up, or pad final stripe only — Phase 1 pads per
stripe and records `original_stripe_len`).

### `raw-devices` feature

Compiled out by default; `/dev` paths rejected. Block-device shredding not
implemented in Phase 1 (per phase instructions).

### Spec file location

Workspace layout §11 lists `docs/SPEC.md` as the specification document.
Historically the text lived in `README.md`. Phase 1 adds `docs/SPEC.md` as
the canonical copy (see commit). Keep README in sync or reduce it to a
pointer in a later docs pass.

---

## (g) GRUB / kernel / CCID vendoring deferred (Phase 3) — RESOLVED in Phase 4

### What the spec says

§10.2 / §10.6: GRUB EFI, Linux bzImage, and CCID `.so` files are fetched at
crate build time by `build.rs` from pinned upstream URLs, verified by BLAKE3,
and embedded as `include_bytes!()`.

### What Phase 3 did

`splitdisk-image` used `SyntheticBlob` placeholders plus BLAKE3 pins so GPT /
FAT / ext4 / initramfs layout could be tested without network fetches.

### Resolution (Phase 4)

- Human-verified source pins and PGP evidence live in `docs/VENDORING.md`
  (GRUB, Linux, CCID, and gnulib for GRUB bootstrap).
- Offline builds: `scripts/build-vendor-blobs.sh` from `vendor/` into a
  commit-keyed cache; `BuiltBlob` loads artifacts and asserts checked-in
  BLAKE3 pins.
- No runtime network; Docker image build installs pinned apt toolchains only.
- QEMU boot remains Phase 5.

### Status

**Resolved** for source identity + offline blob production. Historical Phase 3
placeholder approach retained above for audit context.

---

## (h) In-tree ext4 writer is not real ext4 — RESOLVED (option C)

### What the spec says

§10.2: system partition (ext4) is "Written using the `ext4-rs` or equivalent
crate". §6 requires a mountable `/dev/sdX2` ext4 tree for share data.

### What went wrong (Phase 3)

No mature, license-compatible pure-Rust **ext4 writer** was available. Phase 3
shipped `ext4_simple.rs` (hand-rolled) without logging the gap. In-tree
round-trips passed; `fsck.ext4 -n -f` rejected the image (reserved inodes
3–10 used as ordinary dirs/files, bad `i_blocks`, polluted journal/resize
inodes). See the corrective-pass report for the verbatim fsck transcript.

### Resolution (follow-up corrective pass)

**Option C chosen and implemented:** replace the hand-rolled writer with
Dockerfile-pinned `e2fsprogs` (`mke2fs` + `debugfs -w`), still without mount
or loop devices. `ext4_simple.rs` was **removed**. Active path:
`ext4_mke2fs.rs`.

Journal deliberately disabled (`-O ^has_journal`): write-once / read-mostly
USB base image. UUID and directory hash seed derived from `drive_uuid`.

### `fsck.ext4` acceptance criterion — met

`fsck.ext4 -n -f` on the GPT-extracted system partition exits **0**. Example
from the follow-up suite (e2fsprogs 1.47.0):

```
Pass 1: Checking inodes, blocks, and sizes
Pass 2: Checking directory structure
Pass 3: Checking directory connectivity
Pass 4: Checking reference counts
Pass 5: Checking group summary information
...: 18/7936 files (5.6% non-contiguous), 902/7931 blocks
```

(stderr: `e2fsck 1.47.0 (5-Feb-2023)`; exit 0.)

### Reproducibility caveat (still open as engineering note, not a blocker)

Full-image byte identity across two runs is **not** preserved for the ext4
region: `debugfs write` / `mke2fs` stamp wall-clock timestamps, and
`metadata_csum` covers them. Tests require byte-identical GPT+ESP plus
structural equivalence of the system tree/files. SPEC §10.1's "byte-for-byte
identical … except per-drive UUID and share data" is therefore met for the
Rust-built regions; the e2fsprogs-built region is structurally equivalent
only. Further work (timestamp normalization) could restore full identity if
required.

### Status

**Resolved** via option C. History retained so the hand-rolled mistake and
fsck gate remain visible.

---

## (i) Phase 4 build-system prerequisites (Meson CCID; kernel build tmpfs)

### What was assumed

The Phase 4 implementation prompt described building the CCID driver with
autotools, and the existing `scripts/test.sh` container run used a 2 GiB
`/tmp` tmpfs.

### What the pinned trees actually require

**(a) CCID 1.8.4 uses Meson, not autotools.** The vendored tree at
`vendor/ccid/` (`c37cf6cb42279ce9648ff7314180c866d68f9e0d`) has
`meson.build` / `meson.options` and no autotools `configure.ac`. Building
it needs `meson` and `ninja` in the Docker image, pinned to explicit apt
versions like other Phase 3/4 tool additions — not an autotools-only
toolchain for this component.

**(b) `vendor/linux/` is approximately 7.6 GiB** before object files. An
in-container kernel build cannot fit in the current 2 GiB `/tmp` tmpfs
used by `scripts/test.sh`. Raising that tmpfs size (or otherwise giving
the build a large writable scratch volume under `/tmp`) is a **resource /
Dockerfile-or-run-flags config change**, not a network or sandboxing
exception. Whoever edits the container run flags should call this out
explicitly so it is not mistaken for a security relaxation.

### Status

**Addressed in Phase 4 config:** Dockerfile installs pinned `meson` /
`ninja-build` (and GRUB/kernel build deps including `autoconf-archive`);
`scripts/test.sh` defaults `SPLITDISK_TMPFS_SIZE=48g` for `/tmp` with an
explicit comment that this is resource sizing only, not a sandboxing
exception. CCID is built with Meson/Ninja; the IFD `.so` is copied from the
ninja build directory because `meson install` targets pcsclite `usbdropdir`
under `/usr` (read-only in the hardened container). Retain this entry so the
Meson vs autotools mismatch and tmpfs sizing remain visible in the audit trail.

---

## (j) Cross-host bit-identical GRUB / kernel / CCID blobs

### What Phase 4 observed / expects

`SOURCE_DATE_EPOCH` alone was not enough for all three blobs. Phase 4 pins
BLAKE3 digests of artifacts built in the project Docker/Podman image.

### Determinism follow-up (2026-09-22)

Two cold builds per component in `splitdisk-test:phase4` with documented
metadata fixes (`scripts/build-vendor-blobs.sh`, `scripts/compare-blob-determinism.sh`):

| Component | Fixes tried | Result in this image |
|-----------|-------------|----------------------|
| **Linux bzImage** | Per-commit `SOURCE_DATE_EPOCH`; `KBUILD_BUILD_USER/HOST=splitdisk`; `KBUILD_BUILD_TIMESTAMP` from commit author date | **Byte-identical** across two cold `O=` builds. UTS string stable, e.g. `6.12.111 (splitdisk@splitdisk) … Mon Sep 21 13:02:51 UTC 2026`. CI runs `scripts/verify-kernel-repro.sh`. |
| **GRUB BOOTX64.EFI** | Per-commit `SOURCE_DATE_EPOCH`; `-ffile-prefix-map` for grub/gnulib/build trees | **Still differs** (same size; byte differences late in the image — likely PE/EFI packaging or timestamps in the standalone image). |
| **CCID libccid.so** | Per-commit `SOURCE_DATE_EPOCH`; `LDFLAGS=-Wl,--build-id=none` | **Still differs** (same size; early file offsets — link/metadata variance). |

### Scope of any reproducibility claim

Byte-identical kernel rebuilds are claimed **only** for the pinned Dockerfile
apt toolchain on this image (`gcc=4:12.2.0-3`, binutils 2.40, etc.). That is
**not** a guarantee on arbitrary hosts, compiler versions, or libc builds.

GRUB and CCID: rely on checked-in BLAKE3 pins; cold rebuilds may change bytes
without updating pins.

### Options (unchanged)

| Option | Notes |
|--------|-------|
| A. Accept pin-per-CI-image (current for GRUB/CCID) | Rebuild refreshes pins when intentional |
| B. Investigate GRUB mkstandalone / CCID link further | Deferred; no `faketime` without decision |

### Status

**Partially resolved:** kernel reproducible in-image; GRUB/CCID variance documented.
Cross-host bit-identity remains open for those two components.

---

## (k) CCID: skipped `meson install` and pcscd runtime configuration

### What Phase 4 did

CCID is built with Meson/Ninja (`-Dembedded=true`) and the `libccid.so` artifact
is copied from the ninja build directory into the initramfs at
`usr/lib/pcsc/drivers/ifd-ccid.so`.

### Why install was skipped

`meson install` targets pcsclite’s `usbdropdir` (typically under
`/usr/lib/pcsc/drivers/…`), which is not writable in the hardened,
read-only-root test container. Install was replaced by copying the linked
`.so` only.

### Gap

A full install may also place bundle metadata (e.g. `Info.plist`), serial
driver stubs, and paths that **pcscd** and reader configuration expect.
The initramfs currently has an empty `etc/reader.conf.d/` placeholder and
may not include whatever CCID/pcscd need to load the IFD driver correctly
at runtime. Phase 4 validates **presence and layout** of the binary, not a
working smart-card stack.

### Status

**Open (Phase 5+):** define initramfs pcscd/CCID config generation and whether
to mimic install-tree layout offline into the cpio archive. Not fixed in the
determinism/README pass.
