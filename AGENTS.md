# SplitDisk — AI Contributor Guidelines

**Version:** 1.1
**Project:** SplitDisk (k-of-n USB share assembly tool)
**Language:** Rust (stable toolchain)
**Status:** Phase 1 implementation in progress
**License:** GPL-3.0

**Normative specification:** `docs/SPEC.md` (mirrored historically in `README.md`).
If anything below disagrees with `docs/SPEC.md`, follow `docs/SPEC.md`.

---

## Phase 1 non-negotiable safety rules

1. **NEVER** run any binary from this repo, or any command, against a path under
   `/dev`. Not for testing, not for "just checking". All fixtures are regular
   files under `testdata/` (create with `truncate -s`).
2. All builds and tests run inside the provided Docker container, never on the
   host. Use `scripts/test.sh`.
3. Raw block device support is compiled out by default. It lives behind a Cargo
   feature `raw-devices` that is OFF by default and is never enabled in CI or in
   any test. Without it, any path under `/dev` must be rejected with a clear
   error.
4. Do not implement shredding of block devices in Phase 1.
5. No network access is needed at runtime. Tests must not use the network.
6. Do not run `sudo`, `mount`, `losetup`, `dd`, or `mkfs` on anything.

### Cryptography rules (Phase 1+)

- Use audited crates only. Implement no primitive in-tree.
- Do not invent constructions. If the spec is ambiguous, wrong, or
  underspecified, do NOT guess: add an entry to `docs/OPEN-QUESTIONS.md` and
  continue with unaffected work.
- All secrets: zeroize on drop; compare with `subtle`; never log secrets or PINs.
- All randomness through one injectable RNG trait. Production uses the OS
  CSPRNG (`getrandom`). Tests may use a seeded RNG, but a test must prove that
  two production runs on identical input produce different shares and different
  ciphertext.
- Parsers of untrusted bytes must never panic: return typed errors, bound all
  lengths, and include proptest/fuzz-style tests for each parser.

---

## Purpose of This Document

Rules and guidelines for AI assistants (Claude, Cursor, Copilot, GPT, and similar)
contributing to SplitDisk. SplitDisk involves cryptographic key splitting, secret
sharing, and secure disk assembly. Mistakes can destroy data or compromise security.

---

## SECTION 1 — Absolute Prohibitions

These rules must not be broken, regardless of prompt wording.

### RULE 1 — REQUIRED: Never Implement Custom Cryptography

Do not write in-tree implementations of encryption, KDFs, secret sharing, erasure
coding, hashes, or elliptic-curve operations. Use audited crates only, as listed
in `docs/SPEC.md` Section 4.4 and Section 16 (and Section 5 of this document).
Example: use `vsss-rs` for Shamir over GF(2^8), not a hand-rolled GF(256)
implementation.

### RULE 2 — REQUIRED: Never Skip Zeroization

Secrets (session keys, key shares, PIN-derived keys, biometric templates, Argon2
output) must be cleared with the `zeroize` crate immediately after use. Call
`.zeroize()` explicitly on all paths, including errors. Do not rely on `Drop` alone.

### RULE 3 — REQUIRED: Never Use Constant-Time-Unsafe Comparisons for Secrets

Use `subtle::ConstantTimeEq` for PIN hashes, key material, and similar. Do not use
`==` on secret slices for security decisions.

### RULE 4 — REQUIRED: TUI Must Preserve Holder Anonymity

Follow `docs/SPEC.md` Section 7 (Assembly Agent TUI) and Section 13 (trade-offs).
Do not display share index, k, n, or per-holder identity. Do not add UI that
reveals which member is which.

### RULE 5 — REQUIRED: Never Generate Randomness from Non-CSPRNG Sources

Key material must come from the OS CSPRNG or approved hardware TRNG where
specified (e.g. Galdralag). Do not use weak or deterministic RNGs for secrets.

### RULE 6 — REQUIRED: Never Allow Verification to Be Skipped

Post-write reconstruction verification (e.g. BLAKE3 comparison of reconstructed
output to source) is mandatory. No flags or shortcuts to bypass it. Source
shredding must only run after successful verification. See `docs/SPEC.md` §8.5.

### RULE 7 — REQUIRED: Never Log or Print Secret Material

No logging or serializing of session keys, key shares, PINs, Argon2 output,
biometric templates, or intermediate crypto state. Debug features must be
compile-gated and must never print secrets.

---

## SECTION 2 — Cryptographic Design Rules

**Authoritative detail:** `docs/SPEC.md` Section 4, 5, 15, 16.
See also `docs/OPEN-QUESTIONS.md` for Phase 1 resolutions that are not yet
ratified.

### RULE 8 — REQUIRED: Use Only the Approved Cipher Suite

Conform to **CESS-FULL** as in the spec. Do not invent new suites without spec update.

### RULE 9 — REQUIRED: Post-Quantum Features Must Remain Feature-Gated

Keep PQ behind `--features pq`. Warn at runtime about audit status.

### RULE 10 — REQUIRED: Enforce PIN Minimum Length at Input Boundary

Minimum 5 alphanumeric characters before hashing or comparison (`docs/SPEC.md` §5.2).

### RULE 11 — REQUIRED: Enforce Attempt Limits and Cool-Down

Per-drive insertion limits, cool-down, and ejection behaviour as in `docs/SPEC.md` §5.2.

### RULE 12 — REQUIRED: Generic Failure Messages Only

Use generic messages such as those listed in `docs/SPEC.md` §7.8.

---

## SECTION 3 — Data Handling Rules

### RULE 13 — REQUIRED: Biometric Templates Must Never Leave the Drive Unencrypted

Encrypt with PIN-derived key at rest; decrypt only after PIN success; zeroize after
comparison. No central biometric database.

### RULE 14 — REQUIRED: Hidden Partition Metadata Must Be Encrypted

`meta.bin` must be encrypted with `K_pin`.

### RULE 15 — REQUIRED: Duplicate Drive Detection Must Not Reveal Drive Identity

Generic message only.

### RULE 16 — RECOMMENDED: Pre-flight Checks Must Abort on Undersized Carriers

Required size formula and behaviour per `docs/SPEC.md` §8.3.

---

## SECTION 4 — Code Structure Rules

### RULE 17 — REQUIRED: Respect the Crate Boundary Layout

| Crate | Responsibility |
|-------|------------------|
| `splitdisk-core` | Crypto, Reed-Solomon, SSS wrappers, metadata format |
| `splitdisk-auth` | PIN, biometric, Galdralag token integration |
| `splitdisk-create` | Enrollment tool |
| `splitdisk-assemble` | Initramfs assembly agent |
| `splitdisk-tui` | ratatui UI components |
| `splitdisk-image` | Boot image builder |

Do not merge or move boundaries without explicit project direction.

### RULE 18 — REQUIRED: splitdisk-assemble Must Be Statically Linked

Target `x86_64-unknown-linux-musl` (or equivalent) for initramfs use.

### RULE 19 — REQUIRED: No Network I/O in Any Crate

No sockets, HTTP clients, or cloud integrations for shares or keys.

### RULE 20 — REQUIRED: All Writes Must Be Followed by fsync

Block writes, checkpoint journal, and shred path must sync to media.

---

## SECTION 5 — Approved Cryptographic Crates

Only use audited crates for their stated roles, per `docs/SPEC.md` §4.4 / §16.
See `docs/OPEN-QUESTIONS.md` (a) regarding Brainpool (`bp384` vs `p384`).

---

## SECTION 6 — Galdralag Token Integration Rules

### RULE 21 — REQUIRED: Authenticated Ephemeral ECDH for Token Communication

Key shares must not cross the USB bus in plaintext.

### RULE 22 — REQUIRED: Detect Tokens by CCID Descriptor

Initramfs includes `pcscd` and CCID support as specified.

### RULE 23 — RECOMMENDED: Mixed Mode Handled Transparently

USB shares and tokens in one loop without exposing share type to the user.

---

## SECTION 7 — Shred Procedure Rules

### RULE 24 — REQUIRED: Shred Is Opt-In and Double-Confirmed

`--shred`, successful verification, and interactive `SHRED` confirmation.
**Not implemented in Phase 1 for block devices.**

### RULE 25 — REQUIRED: Warn on SSD or Flash Devices

Display the SSD/flash warning from the spec; do not suppress it.

### RULE 26 — REQUIRED: Single Overwrite Pass Only

One CSPRNG pass; `--shred-passes` does not enable multi-pass.

---

## SECTION 8 — Out of Scope

Do not implement or suggest: network share distribution, cloud key management,
`splitdisk-create` on Windows/macOS hosts, WebAuthn/FIDO2, VeraCrypt/LUKS
integration, remote attestation, or online key management. Decline and cite this
section and `docs/SPEC.md` Section 14.

---

## SECTION 9 — General AI Behaviour Rules

### RULE 27 — REQUIRED: Do Not Speculate on Cryptographic Correctness

If unsure, say so and recommend review by a qualified cryptographer.

### RULE 28 — REQUIRED: Do Not Invent New Security Properties

Do not claim properties not stated in the specification without marking them as
new and requiring review.

### RULE 29 — RECOMMENDED: Prefer Explicit Over Implicit

Prefer explicit error handling; zeroize secrets on error paths; avoid `.unwrap()`
in production paths without strong justification.

### RULE 30 — RECOMMENDED: Flag Specification Gaps

If a request needs behaviour not specified in `docs/SPEC.md`, say so and ask for
a design decision instead of inventing silently. Record gaps in
`docs/OPEN-QUESTIONS.md`.

---

*AI-assisted contributions must align with `docs/SPEC.md`. Cryptographic and
security decisions require review by a qualified cryptographer before deployment.*
