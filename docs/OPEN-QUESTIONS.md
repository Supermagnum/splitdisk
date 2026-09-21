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

### Options

| Option | Pros | Cons |
|--------|------|------|
| A. Use RustCrypto `bp384` (and `bp256` for the lightweight profile) | Correct curve; same ecosystem as other RustCrypto crates; audited lineage | Spec text/Cargo list must change; `bp384` 0.6 is older API than latest rc |
| B. Keep depending on `p384` | Matches written Cargo.toml | **Violates CESS**; wrong curve |
| C. BrainpoolP512r1: wait for RustCrypto `bp512` upstream (PR open) | Official home | Not merged; no audited crate today |
| D. Third-party `bp512` on crates.io | Exists as of 2026-09 | New, low download count, PolyForm-Noncommercial license may conflict with GPL-3.0 distribution needs; not independently audited |

### Recommendation

- **Adopt option A** for P-384/P-256: depend on `bp384` / `bp256`, update SPEC §4.4/§16.
- **Do not ship BrainpoolP512r1** until an audited, license-compatible crate exists
  (prefer upstream RustCrypto). Document `--cipher brainpool512` as unavailable.
- Phase 1 does not implement ECDH; this is recorded for Phase 2+.

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

### Resolution

Proposed versioned layouts in `docs/FORMAT.md`. All choices marked OPEN.
Phase 1 implements parsers/writers for:

- Segmented AEAD stream (`SDSE`)
- Chunk frames (`SDCF`)
- Meta plaintext (`SDMT`)
- Envelope header (`SDEV`) stub

`pin.hash` (`SDPH`) and key-wrap (`SDKW`) are specified in FORMAT.md but not
fully wired until `splitdisk-auth` (Phase 2+).

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
