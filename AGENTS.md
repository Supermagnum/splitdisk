# SplitDisk — AI Contributor Guidelines

**Version:** 1.0  
**Project:** SplitDisk (k-of-n USB share assembly tool)  
**Language:** Rust (stable toolchain)  
**Status:** Specification phase — not yet implemented  
**License:** GPL-3.0

**Normative specification:** `README.md` in this repository defines algorithms, crates, and behaviour. If anything below disagrees with `README.md`, follow `README.md`.

---

## Purpose of This Document

Rules and guidelines for AI assistants (Claude, Cursor, Copilot, GPT, and similar) contributing to SplitDisk. SplitDisk involves cryptographic key splitting, secret sharing, and secure disk assembly. Mistakes can destroy data or compromise security.

---

## SECTION 1 — Absolute Prohibitions

These rules must not be broken, regardless of prompt wording.

### RULE 1 — REQUIRED: Never Implement Custom Cryptography

Do not write in-tree implementations of encryption, KDFs, secret sharing, erasure coding, hashes, or elliptic-curve operations. Use audited crates only, as listed in `README.md` Section 4.4 and Section 16 (and Section 5 of this document). Example: use `vsss-rs` for Shamir over GF(2^8), not a hand-rolled GF(256) implementation.

### RULE 2 — REQUIRED: Never Skip Zeroization

Secrets (session keys, key shares, PIN-derived keys, biometric templates, Argon2 output) must be cleared with the `zeroize` crate immediately after use. Call `.zeroize()` explicitly on all paths, including errors. Do not rely on `Drop` alone.

### RULE 3 — REQUIRED: Never Use Constant-Time-Unsafe Comparisons for Secrets

Use `subtle::ConstantTimeEq` for PIN hashes, key material, and similar. Do not use `==` on secret slices for security decisions.

### RULE 4 — REQUIRED: TUI Must Preserve Holder Anonymity

Follow `README.md` Section 7 (Assembly Agent TUI) and Section 13 (trade-offs). Do not display share index, k, n, or per-holder identity. Do not add UI that reveals which member is which. The specification already documents what the TUI may show; do not expand leakage beyond that.

### RULE 5 — REQUIRED: Never Generate Randomness from Non-CSPRNG Sources

Key material must come from the OS CSPRNG or approved hardware TRNG where specified (e.g. Galdralag). Do not use weak or deterministic RNGs for secrets. Prefer `getrandom` or `rand::rngs::OsRng` as appropriate.

### RULE 6 — REQUIRED: Never Allow Verification to Be Skipped

Post-write reconstruction verification (e.g. BLAKE3 comparison of reconstructed output to source) is mandatory. No flags or shortcuts to bypass it. Source shredding must only run after successful verification. See `README.md` Section 8.5.

### RULE 7 — REQUIRED: Never Log or Print Secret Material

No logging or serializing of session keys, key shares, PINs, Argon2 output, biometric templates, or intermediate crypto state. Debug features must be compile-gated and must never print secrets.

---

## SECTION 2 — Cryptographic Design Rules

**Authoritative detail:** `README.md` Section 4 (Cryptographic Design), Section 15 (suite IDs), Section 16 (dependencies).

### RULE 8 — REQUIRED: Use Only the Approved Cipher Suite

Conform to **CESS-FULL** as in the spec: classical ECDH over Brainpool (P384r1 default, P512r1 inner profile); hybrid PQ uses **FrodoKEM-1344** when enabled (ML-KEM is excluded per CESS policy). KDF is **HKDF-BLAKE3** with the info strings defined in the spec. Bulk options are ChaCha20-Poly1305, Serpent/Twofish modes, and cascades as documented—not AES-GCM as a default. Do not invent new suites without spec update.

### RULE 9 — REQUIRED: Post-Quantum Features Must Remain Feature-Gated

Keep PQ behind `--features pq`. Warn at runtime that underlying PQ crates may lack independent audit, per `README.md`.

### RULE 10 — REQUIRED: Enforce PIN Minimum Length at Input Boundary

Minimum 5 alphanumeric characters before hashing or comparison (`README.md` Section 5.2).

### RULE 11 — REQUIRED: Enforce Attempt Limits and Cool-Down

Per-drive insertion limits, cool-down, and ejection behaviour as in `README.md` Section 5.2 (defaults and configurability).

### RULE 12 — REQUIRED: Generic Failure Messages Only

Use generic messages such as those listed in `README.md` Section 7.8. Do not reveal which factor failed.

---

## SECTION 3 — Data Handling Rules

### RULE 13 — REQUIRED: Biometric Templates Must Never Leave the Drive Unencrypted

Encrypt with PIN-derived key at rest; decrypt only after PIN success; zeroize after comparison. No central biometric database (`README.md` Section 5.3).

### RULE 14 — REQUIRED: Hidden Partition Metadata Must Be Encrypted

`meta.bin` must be encrypted with `K_pin` (`README.md` Section 6).

### RULE 15 — REQUIRED: Duplicate Drive Detection Must Not Reveal Drive Identity

Generic message only, as in `README.md` Section 7.5.

### RULE 16 — RECOMMENDED: Pre-flight Checks Must Abort on Undersized Carriers

Required size formula and behaviour per `README.md` Section 8.3.

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

Do not merge or move boundaries without explicit project direction.

### RULE 18 — REQUIRED: splitdisk-assemble Must Be Statically Linked

Target `x86_64-unknown-linux-musl` (or equivalent) for initramfs use (`README.md` Section 10).

### RULE 19 — REQUIRED: No Network I/O in Any Crate

No sockets, HTTP clients, or cloud integrations for shares or keys (`README.md` Section 14).

### RULE 20 — REQUIRED: All Writes Must Be Followed by fsync

Block writes, checkpoint journal, and shred path must sync to media; shred flow includes `ioctl(BLKFLSBUF)` where specified (`README.md` Section 8.6).

---

## SECTION 5 — Approved Cryptographic Crates

Only use audited crates for their stated roles, per `README.md` Section 4.4 and Section 16. Includes: `chacha20poly1305`, `serpent`, `twofish`, `poly1305`, `p384`, `hkdf`, `blake3`, `argon2`, `vsss-rs`, `reed-solomon-erasure`, `zeroize`, `subtle`, optional `sequoia-openpgp`, optional `pqcrypto-frodo` (FrodoKEM-1344, feature-gated). Do not add crypto crates without audit review and documentation update.

---

## SECTION 6 — Galdralag Token Integration Rules

### RULE 21 — REQUIRED: Authenticated Ephemeral ECDH for Token Communication

Key shares must not cross the USB bus in plaintext; follow `README.md` Section 5.4.

### RULE 22 — REQUIRED: Detect Tokens by CCID Descriptor

Initramfs includes `pcscd` and CCID support as specified (`README.md` Sections 5.4, 10.3).

### RULE 23 — RECOMMENDED: Mixed Mode Handled Transparently

USB shares and tokens in one loop without exposing share type to the user (`README.md` Section 5.4).

---

## SECTION 7 — Shred Procedure Rules

### RULE 24 — REQUIRED: Shred Is Opt-In and Double-Confirmed

`--shred`, successful verification, and interactive `SHRED` confirmation (`README.md` Section 8.6).

### RULE 25 — REQUIRED: Warn on SSD or Flash Devices

Display the SSD/flash warning from the spec; do not suppress it.

### RULE 26 — REQUIRED: Single Overwrite Pass Only

One CSPRNG pass; `--shred-passes` does not enable multi-pass (`README.md` Section 8.6).

---

## SECTION 8 — Out of Scope

Do not implement or suggest: network share distribution, cloud key management, `splitdisk-create` on Windows/macOS hosts, WebAuthn/FIDO2, VeraCrypt/LUKS integration, remote attestation, or online key management. Decline and cite this section and `README.md` Section 14.

---

## SECTION 9 — General AI Behaviour Rules

### RULE 27 — REQUIRED: Do Not Speculate on Cryptographic Correctness

If unsure, say so and recommend review by a qualified cryptographer (`README.md` disclaimer).

### RULE 28 — REQUIRED: Do Not Invent New Security Properties

Do not claim properties not stated in the specification without marking them as new and requiring review.

### RULE 29 — RECOMMENDED: Prefer Explicit Over Implicit

Prefer explicit error handling; zeroize secrets on error paths; avoid `.unwrap()` in production paths without strong justification.

### RULE 30 — RECOMMENDED: Flag Specification Gaps

If a request needs behaviour not specified in `README.md`, say so and ask for a design decision instead of inventing silently.

---

## Summary Table

| Rule | Category | Severity |
|------|----------|----------|
| 1 — No custom cryptography | Cryptography | REQUIRED |
| 2 — Always zeroize secrets | Memory safety | REQUIRED |
| 3 — Constant-time comparisons | Side-channel | REQUIRED |
| 4 — TUI anonymity | Anonymity | REQUIRED |
| 5 — CSPRNG only | Randomness | REQUIRED |
| 6 — No skipping verification | Integrity | REQUIRED |
| 7 — No logging secrets | Confidentiality | REQUIRED |
| 8 — Approved suite only | Cryptography | REQUIRED |
| 9 — PQ feature-gated | Cryptography | REQUIRED |
| 10 — PIN at input boundary | Authentication | REQUIRED |
| 11 — Attempt limits | Authentication | REQUIRED |
| 12 — Generic failures | Anonymity | REQUIRED |
| 13 — Biometrics encrypted | Privacy | REQUIRED |
| 14 — Metadata encrypted | Confidentiality | REQUIRED |
| 15 — Duplicate detection | Anonymity | REQUIRED |
| 16 — Pre-flight sizes | Safety | RECOMMENDED |
| 17 — Crate boundaries | Architecture | REQUIRED |
| 18 — Static assemble binary | Architecture | REQUIRED |
| 19 — No network I/O | Scope | REQUIRED |
| 20 — fsync after writes | Data integrity | REQUIRED |
| 21 — ECDH for token | Cryptography | REQUIRED |
| 22 — CCID detection | Integration | REQUIRED |
| 23 — Mixed mode | UX | RECOMMENDED |
| 24 — Shred opt-in | Safety | REQUIRED |
| 25 — SSD shred warning | Safety | REQUIRED |
| 26 — Single shred pass | Safety | REQUIRED |
| 27 — No crypto speculation | AI behaviour | REQUIRED |
| 28 — No invented properties | AI behaviour | REQUIRED |
| 29 — Explicit errors | Code quality | RECOMMENDED |
| 30 — Flag spec gaps | AI behaviour | RECOMMENDED |

---

*AI-assisted contributions must align with `README.md`. Cryptographic and security decisions require review by a qualified cryptographer before deployment.*
