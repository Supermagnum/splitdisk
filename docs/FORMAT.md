# SplitDisk on-drive formats (Phase 1 proposal)

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

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | Magic `SDCF` |
| 4 | 2 | `version` (= 1) |
| 6 | 1 | `share_index` |
| 7 | 8 | `stripe_index` |
| 15 | 4 | `original_stripe_len` (pre-pad) |
| 19 | 4 | `shard_len` |
| 23 | 32 | BLAKE3(shard bytes) |
| 55 | `shard_len` | shard payload |

**OPEN:** Whether `share_index` should be omitted from the on-disk frame to
reduce leakage if `chunk.bin` is inspected without PIN (holder anonymity is
about TUI; raw bytes still expose index today). Alternative: encrypt frames
under `K_pin` (heavier).

**OPEN:** Stripe size must be divisible by `k` in Phase 1. Spec implies
`ceil(image/k)` without requiring divisibility — padding policy needs ratify.

---

## 4. Metadata plaintext (`SDMT`) — contents of `meta.bin` before AEAD

SPEC: `meta.bin` is encrypted with `K_pin`. Phase 1 defines plaintext only.

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

Total fixed size: **75 bytes**.

**OPEN:** AEAD wrapping of this blob (nonce, AAD binding to share file UUID,
algorithm). Recommend ChaCha20-Poly1305 with nonce from
`BLAKE3-derive_key("splitdisk-meta-nonce-v1", K_pin)` truncated to 12 bytes
and AAD = `drive_fingerprint` (once known) or empty at first write.

**OPEN:** Whether `k`/`n` belong in every drive (needed for assembly) vs only
a hidden scheme id. SPEC stores them in meta; anonymity trade-off is accepted
for holders without PIN, but anyone with PIN learns k and n.

---

## 5. PIN hash file (`pin.hash`)

SPEC §5.2: Argon2id hash with per-drive 16-byte salt. Byte layout was
undefined.

### Proposed layout (versioned)

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | Magic `SDPH` |
| 4 | 2 | `version` (= 1) |
| 6 | 4 | `m_cost` (KiB; default 65536 = 64 MiB) |
| 10 | 4 | `t_cost` (default 3) |
| 14 | 4 | `p_cost` (default 4) |
| 18 | 16 | `salt` |
| 34 | 32 | `argon2id_output` (or hash length field — OPEN) |

**OPEN:** Store full Argon2 PHC string vs raw params+salt+hash. Raw is
simpler for musl/initramfs; PHC is more interoperable.

**OPEN:** Offline guessing — see `docs/OPEN-QUESTIONS.md` (f).

---

## 6. Mode A outer envelope header (`SDEV`)

Clear header before outer AEAD body (Phase 2+ completes wrapping).

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | Magic `SDEV` |
| 4 | 2 | `version` (= 1) |
| 6 | 1 | `mode` (0 = B suite visible, 1 = A suite concealed) |
| 7 | 2 | `suite_id` (Mode B only; zero in Mode A) |
| 9 | 4 | `body_len` |

**OPEN:** Ephemeral Brainpool public key encoding and ciphertext framing for
Mode A KEM (SPEC §4.1). Not implemented in Phase 1.

---

## 7. Encrypted key share at rest

SPEC: key share wrapped with ChaCha20-Poly1305 under `K_pin`.

### Proposed blob (`share.enc` logical; may live beside meta)

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | Magic `SDKW` |
| 4 | 2 | `version` |
| 6 | 12 | `nonce` |
| 18 | 4 | `ct_len` |
| 22 | ct_len | ciphertext \|\| tag |

AAD: `share_index || scheme_id` (**OPEN** scheme_id definition).

---

## 8. Pin.hash and meta relationship

**OPEN:** Single AEAD package vs separate files. SPEC lists separate paths
under `/share/auth/` and `/share/meta.bin`. Phase 1 keeps them separate.
