# SplitDisk — Tool Specification

**Version:** 0.1-draft  
**Language:** Rust (stable toolchain)  
**Status:** Specification only — not yet implemented  
**License:** GPL-3.0 (matching Galdralag-firmware)

---

## 1. Purpose

SplitDisk is a command-line tool and initramfs-resident assembly agent for
splitting a disk image or filesystem into **k-of-n physical USB shares**, each
bootable, such that any k drives inserted in sequence can reconstruct and write
the original content to a target disk. Members holding drives are not informed
of their share index, the total number of shares, or the threshold required.

Optional integration with the **Galdralag hardware security token** (Baochip-1x
running Galdralag firmware) provides on-device PIN verification, Shamir
key-share storage, and Brainpool/post-quantum encryption without requiring any
custom host-side cryptographic driver beyond a standard CCID stack.

---

## 2. Threat Model and Design Goals

| Goal | Description |
|------|-------------|
| **Holder anonymity** | A drive holder does not know their share index, the value of k or n, or the content. |
| **Coercion resistance** | A holder genuinely cannot answer "how many others are there?" or "are you required?" |
| **Physical confidentiality** | Drive contents look like opaque binary blobs. No filenames, labels, or metadata reveal the scheme. |
| **Multi-factor unlock** | Each drive requires PIN (≥ 5 alphanumeric characters) and optionally biometric before its share is accepted. |
| **Long-term security** | Encryption must remain secure for decades. Hybrid classical + post-quantum where available. |
| **Fault tolerance** | n > k so that absent or unavailable members do not prevent reconstruction. |
| **Integrity** | Each share chunk is hashed; corruption is detected before reconstruction begins. |
| **Resumable assembly** | If power is lost mid-write, assembly can resume from a checkpoint. |
| **Verified write** | Reconstruction is dry-run tested against the source hash before the operator is permitted to destroy the original. |
| **Source destruction** | After verified write, the source drive or image file can be overwritten with random data so the plaintext cannot be recovered from the enrollment machine. |

Non-goals: network transmission of shares, online key management, integration
with cloud storage.

---

## 3. Architecture Overview

SplitDisk consists of two programs:

- **`splitdisk-create`** — run once on an air-gapped enrollment machine to
  produce n share carriers (USB drives, Galdralag tokens, or a mix) from a
  source disk image.
- **`splitdisk-assemble`** — a statically linked binary embedded in the
  initramfs of every share USB drive, or invoked on the assembly machine when
  all shares are Galdralag tokens. Orchestrates reconstruction.

**USB drive mode:**

```
┌─────────────────────────────────────────────────────┐
│                  splitdisk-create                   │
│                                                     │
│  source image ──► [encrypt] ──► [Reed-Solomon       │
│                                  split k-of-n]      │
│                       │                             │
│               [SSS split of session key]            │
│                       │                             │
│          ┌────────────┼────────────┐                │
│        USB 1        USB 2  ...   USB n              │
│   (bootable,    (bootable,      (bootable,           │
│    chunk 1,      chunk 2,        chunk n,            │
│    key share 1)  key share 2)    key share n)        │
└─────────────────────────────────────────────────────┘

At boot time on any share USB:

┌─────────────────────────────────────────────────────┐
│               splitdisk-assemble (initramfs)        │
│                                                     │
│  Boot USB ──► read own chunk + key share silently   │
│  Loop until k shares collected:                     │
│    insert drive ──► PIN check ──► biometric check   │
│    ──► read chunk + key share ──► progress bar +1   │
│  Reconstruct session key via SSS                    │
│  Decrypt + Reed-Solomon decode                      │
│  Write to target disk with checkpoint journal        │
└─────────────────────────────────────────────────────┘
```

**Galdralag token mode:**

```
┌─────────────────────────────────────────────────────┐
│                  splitdisk-create                   │
│                                                     │
│  source image ──► [encrypt] ──► [Reed-Solomon       │
│                                  split k-of-n]      │
│                       │                             │
│               [SSS split of session key]            │
│                       │                             │
│     ┌─────────────────┼─────────────────┐           │
│  Token 1           Token 2  ...      Token n        │
│  RRAM: key share   RRAM: key share   RRAM: key share│
│  SD:   chunk 1     SD:   chunk 2     SD:   chunk n  │
└─────────────────────────────────────────────────────┘

At assembly time (any machine, no bootable share USB needed):

┌─────────────────────────────────────────────────────┐
│               splitdisk-assemble                    │
│                                                     │
│  Loop until k tokens inserted:                      │
│    insert token ──► CCID session ──► PIN on token   │
│    ──► read chunk from SD ──► read key share        │
│        from RRAM ──► progress bar +1                │
│  Reconstruct session key via SSS                    │
│  Decrypt + Reed-Solomon decode                      │
│  Write to target disk with checkpoint journal        │
└─────────────────────────────────────────────────────┘
```

Mixed mode (some USB drives, some tokens) is also supported within the same
scheme. The assembly agent handles both share types transparently.
```

---

## 4. Cryptographic Design

### 4.1 Encryption Layer

All encryption uses a **hybrid** scheme for long-term security:

```
Session key: 32 random bytes from OS CSPRNG

Classical KEM:    ECDH over BrainpoolP384r1 or BrainpoolP512r1
                  (RFC 5639, BSI TR-03111)
Post-quantum KEM: ML-KEM-768 / ML-KEM-1024 (FIPS 203)
                  feature-gated behind --features pq

Combined:  session_key = HKDF-SHA512(classical_shared || pq_shared)

Bulk cipher:  AES-256-GCM  (primary)
              ChaCha20-Poly1305  (alternative, --cipher chacha20)
              Serpent-256 + ChaCha20-Poly1305 cascade (--cipher cascade)
```

GnuPG / Sequoia-PGP compatibility: the session key may optionally be wrapped in
an OpenPGP message (RFC 4880 / rfc4880bis) encrypted to one or more recipients'
Brainpool keys, allowing standard `gpg` decryption on the reconstructed output
after assembly.

### 4.2 Data Splitting

Reed-Solomon erasure coding (crate: `reed-solomon-erasure`) splits the
encrypted image into n chunks, any k of which suffice to reconstruct.

```
chunk_size ≈ image_size / k   (plus RS parity overhead)
```

Each chunk is prefixed with a Blake3 hash for integrity verification before
reconstruction begins.

### 4.3 Key Splitting

The 32-byte session key is split using Shamir's Secret Sharing over GF(2⁸)
(crate: `vsss-rs`, same crate used by Galdralag firmware) into n shares,
threshold k.

Each key share is then encrypted at rest on the USB using the PIN-derived key
(see §5.2), so raw access to the drive bytes does not expose the share.

### 4.4 Crate Policy

All cryptographic primitives come from audited crates. Nothing is implemented
in-tree.

| Crate | Purpose | Audit status |
|-------|---------|--------------|
| `aes-gcm` | Bulk AEAD | RustCrypto audited |
| `chacha20poly1305` | Bulk AEAD alternative | RustCrypto audited |
| `p384`, `p521` | Brainpool ECDH base | RustCrypto audited |
| `hkdf` | Key derivation | RustCrypto audited |
| `blake3` | Chunk integrity hashing | Audited |
| `argon2` | PIN hashing | RustCrypto audited |
| `vsss-rs` | Shamir secret sharing | Independent review |
| `reed-solomon-erasure` | Data splitting | Review pending |
| `zeroize` | Secret memory clearing | RustCrypto audited |
| `subtle` | Constant-time comparisons | RustCrypto audited |
| `sequoia-openpgp` | Optional GPG envelope | Active maintenance |
| `pqcrypto-kyber` | ML-KEM (feature-gated) | Pending independent audit |

Post-quantum features are gated behind `--features pq` and carry a warning that
the underlying crates have not been independently audited, matching the policy
in Galdralag firmware.

---

## 5. Authentication Per Drive

### 5.1 Factor Overview

Each drive requires the holder to present:

| Factor | Mechanism | Required |
|--------|-----------|----------|
| Something they have | The USB drive | Always |
| Something they know | PIN ≥ 5 alphanumeric characters | Always |
| Something they are | Biometric (iris/retina scan) | Optional per drive |

All factors are checked before the drive's key share is released into memory.
Failure in any factor does not indicate which factor failed — the UI reports
only "Authentication failed. Please remove drive."

### 5.2 PIN

- Minimum length: 5 alphanumeric characters, enforced at input boundary before
  any hash comparison.
- Hashing: `Argon2id` with a per-drive random 16-byte salt, memory = 64 MiB,
  iterations = 3, parallelism = 4.
- The Argon2id hash is stored in the drive's hidden data partition.
- The PIN-derived key `K_pin = HKDF-SHA256(argon2id_output, "splitdisk-pin-v1")`
  wraps the key share using AES-256-GCM.
- Attempt limit: 5 per drive insertion (configurable 3–10 at creation time).
- On limit exhaustion: drive is ejected and must be re-inserted. The PIN hash
  is not modified (no lockout wipe, unlike a hardware token — the drive has no
  secure element enforcing this; rely on the attempt counter in the assembly
  agent's in-memory state).
- Cool-down: 30-second delay after each failed attempt.

### 5.3 Biometric

Biometric support is **optional** and configured per drive at enrollment time.

Supported hardware: USB iris scanners with Linux drivers (e.g. IriShield MK
series, or compatible devices exposing a V4L2 or proprietary SDK interface).

Enrollment flow:
1. Capture iris image on the enrollment machine using the scanner.
2. Extract ISO/IEC 19794-6 feature template.
3. Encrypt template with `K_pin` (PIN must be correct first).
4. Store encrypted template in hidden partition alongside PIN hash.

Verification flow:
1. PIN verified first.
2. `K_pin` derived → template decrypted in memory.
3. Iris capture performed.
4. Feature extraction and comparison against stored template, within a
   configurable tolerance threshold (Hamming distance on iris codes,
   threshold ≤ 0.32 by default, following ISO recommendations).
5. On match: key share released. Template and derived keys zeroized from memory.
6. On failure: 3 biometric attempts per successful PIN entry, then drive ejected.

The biometric template never leaves the drive unencrypted. No central biometric
database exists.

### 5.4 Galdralag Hardware Token Integration (Optional)

When `--galdralag` mode is used, the Galdralag Baochip-1x token is the
**complete share** — no separate USB drive is needed or issued to the member.
The token holds both the encrypted data chunk and the key share in its
on-device storage (RRAM vault or optional SD card), and presents itself to
the assembly machine over USB. The member carries only the token.

**Storage tiers on the token:**

| Storage | Capacity | Used for |
|---------|----------|----------|
| RRAM vault | Small (key material only) | SSS key share, PIN policy, metadata |
| Optional SD card | Large (bulk data) | Encrypted data chunk |

If the token has an SD card fitted, the data chunk is stored there. If no SD
card is present, the token cannot hold a data chunk and `--galdralag` mode
requires SD card presence — `splitdisk-create` will check and abort if the
card is absent or insufficient at enrollment time.

**What the token provides during assembly:**

- **Data chunk** — streamed from SD card over USB to the assembly machine.
- **Key share** — held in RRAM vault, released only after PIN and optional
  biometric verification on the token itself.
- **BrainpoolP384r1 or BrainpoolP512r1 ECDH** — wraps the key share
  in transit using the token's on-device keys.
- **Authenticated ephemeral ECDH session** — forward-secret channel between
  token and assembly agent; the key share never appears on the USB bus in
  plaintext.
- **Hardware TRNG** — used for all randomness during enrollment and assembly.
- **Hardware PIN counter with zeroization** — 3–10 configurable attempts;
  on exhaustion the token zeroizes its RRAM, permanently destroying the share.

**Assembly agent behaviour:**

The agent detects a Galdralag token by its CCID descriptor on any USB port.
When detected, it opens an ephemeral ECDH session, requests PIN entry (handled
on the token's own PIN policy, not the software attempt counter), reads the
data chunk from the SD card, and retrieves the decrypted key share over the
authenticated channel. No separate USB drive insertion is prompted for that
share.

**Requirements:**

- CCID-capable host (`pcscd` + `ccid` driver included in initramfs)
- Token fitted with SD card of sufficient capacity (`ceil(image_size / k) + 10%`)
- Token provisioned at enrollment via `galdra device shamir-store` and
  `galdra device chunk-write`

**Mixed modes** are supported: some members can hold USB drives (standard
mode) and others can hold Galdralag tokens, within the same k-of-n scheme.
The assembly agent handles both transparently in the same insertion loop.

---

## 6. USB Drive Layout

Each drive presents a standard bootable layout. To an observer mounting the
drive on any operating system, it looks like a minimal bootable Linux USB with
some unremarkable binary files.

```
/dev/sdX1   FAT32  ~256 MiB   EFI System Partition
  /EFI/BOOT/BOOTX64.EFI       Standard EFI bootloader (GRUB or systemd-boot)
  /boot/vmlinuz               Linux kernel (minimal config)
  /boot/initramfs.img         initramfs containing splitdisk-assemble

/dev/sdX2   ext4   remainder  System partition
  /usr/bin/splitdisk-assemble (statically linked, stripped)
  /share/chunk.bin            Encrypted RS data chunk (opaque bytes)
  /share/auth/pin.hash        Argon2id PIN hash
  /share/auth/retina.enc      Encrypted biometric template (if enrolled)
  /share/meta.bin             Encrypted metadata (share index, k, n, chunk hash)
```

`meta.bin` is encrypted with `K_pin`, so share index and scheme parameters are
not visible without the correct PIN. The partition label is blank. The volume
UUID is randomly generated and not reused across drives.

GRUB is configured with `GRUB_TIMEOUT=0` and no menu. The screen is blank
during boot until the assembly agent TUI appears.

---

## 7. Assembly Agent TUI

The TUI is built with `ratatui` and runs fullscreen. It intentionally reveals
no information about share indices or member count.

### 7.1 Startup Screen

```
┌─────────────────────────────────────────────────────┐
│                                                     │
│            SECURE ASSEMBLY SYSTEM                   │
│                                                     │
│   Insert drives one at a time.                      │
│   Remove each drive when prompted.                  │
│                                                     │
│   Progress: ░░░░░░░░░░                              │
│                                                     │
│   Waiting for first drive...                        │
│                                                     │
└─────────────────────────────────────────────────────┘
```

The booting drive's own share is read silently and automatically at startup.
Progress advances by one without user interaction.

### 7.2 PIN Entry

```
┌─────────────────────────────────────────────────────┐
│                                                     │
│   Drive detected.                                   │
│                                                     │
│   Enter PIN: ▓▓▓▓▓▓▓▓░                             │
│              (minimum 5 characters)                 │
│                                                     │
│   Press Enter to confirm.                           │
│                                                     │
└─────────────────────────────────────────────────────┘
```

Input is masked with `▓` characters. Backspace supported. No character count
displayed (avoid leaking PIN length).

### 7.3 Biometric Prompt (if enrolled)

```
┌─────────────────────────────────────────────────────┐
│                                                     │
│   Look into the scanner.                            │
│                                                     │
│   [ Scanning... ████████░░ ]                        │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### 7.4 Progress

```
┌─────────────────────────────────────────────────────┐
│                                                     │
│            SECURE ASSEMBLY SYSTEM                   │
│                                                     │
│   Progress: ████████░░░░░░░░░░░░   3 drives read    │
│                                                     │
│   Please insert another drive.                      │
│                                                     │
└─────────────────────────────────────────────────────┘
```

No member names, no share IDs, no indication of how many remain.

### 7.5 Duplicate Detection

If the same drive is inserted twice (detected by comparing a hidden drive
fingerprint stored in `meta.bin`), the progress bar does not advance:

```
   This drive has already been read. Please insert a different one.
```

No indication that it is "drive 4" or "already seen drive 4."

### 7.6 Reconstruction

When k shares are collected:

```
┌─────────────────────────────────────────────────────┐
│                                                     │
│   All required drives collected.                    │
│                                                     │
│   Verifying integrity...      ████████████  100%   │
│   Reconstructing...           ████████████  100%   │
│   Decrypting...               ██████░░░░░░   63%   │
│   Writing to disk...          ████░░░░░░░░   41%   │
│                                                     │
│   Target: /dev/sdb  (238.5 GiB)                    │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### 7.7 Target Disk Selection

Before writing, the agent lists available block devices (excluding share USBs)
and prompts for confirmation. It checks that the target is large enough and
warns if it is not.

### 7.8 Failure Screens

All failure messages are generic:

```
   Authentication failed. Please remove drive.
   Integrity check failed. Drive may be corrupted.
   Target disk too small. Minimum required: 128.4 GiB.
```

---

## 8. splitdisk-create CLI

### 8.1 Basic Usage

```bash
splitdisk-create \
  --input /dev/sda \
  --drives /dev/sdb /dev/sdc /dev/sdd /dev/sde /dev/sdf /dev/sdg \
  --threshold 3 \
  --cipher brainpool384 \
  --pin-attempts 5 \
  --shred
```

This creates a 3-of-6 scheme. The tool will announce required drive sizes,
write all 6 drives, verify reconstruction with 3 drives, then offer to shred
the source.

### 8.2 Options

| Flag | Description | Default |
|------|-------------|---------|
| `--input <path>` | Source block device or image file | Required |
| `--drives <paths>` | Target USB devices (exactly n) | Required |
| `--threshold <k>` | Minimum shares for reconstruction | Required |
| `--cipher <name>` | `brainpool384`, `brainpool512`, `cascade` | `brainpool384` |
| `--bulk-cipher <name>` | `aes256gcm`, `chacha20`, `cascade` | `aes256gcm` |
| `--gpg-recipients <fps>` | Wrap session key for GPG recipients (Brainpool keys) | None |
| `--pin-attempts <n>` | Failed PIN attempts before cooldown per insertion | `5` |
| `--biometric` | Enroll biometric at creation time (requires scanner) | Off |
| `--galdralag` | Store key shares on Galdralag tokens instead of drives | Off |
| `--features pq` | Enable ML-KEM post-quantum KEM (unaudited, feature-gated) | Off |
| `--label <text>` | Boot-time display label (shown before PIN prompt) | None |
| `--checkpoint-dir <path>` | Directory on target disk for resume journal | `/var/splitdisk` |
| `--shred` | Offer to overwrite source with random data after verified write | Off |
| `--shred-passes <n>` | Reserved; always 1 (multiple passes not meaningful on modern media) | `1` |

### 8.3 Pre-flight: Carrier Requirement Announcement

Before any writes, `splitdisk-create` inspects the source image and the chosen
k and n parameters, then prints a clear human-readable summary and requires
explicit confirmation before proceeding.

**USB drive mode example:**

```
Source:        /dev/sda  (476.9 GiB)
Scheme:        3-of-6 (any 3 drives reconstruct the content)
Cipher:        BrainpoolP384r1 + AES-256-GCM

You will need:   6 × USB drives, each at least 128 GiB
                 (chunk size: ~159 GiB per drive including boot environment
                  and Reed-Solomon parity overhead)

Drives provided: /dev/sdb  256 GiB  ✓
                 /dev/sdc  256 GiB  ✓
                 /dev/sdd  256 GiB  ✓
                 /dev/sde  256 GiB  ✓
                 /dev/sdf  256 GiB  ✓
                 /dev/sdg  128 GiB  ✗  INSUFFICIENT — need 159 GiB

WARNING: /dev/sdg is too small. Aborting.
```

**Galdralag token mode example:**

```
Source:        /dev/sda  (476.9 GiB)
Scheme:        3-of-6 (any 3 tokens reconstruct the content)
Cipher:        BrainpoolP384r1 + AES-256-GCM

You will need:   6 × Galdralag tokens, each with SD card ≥ 159 GiB
                 Key shares fit in RRAM — no minimum RRAM size beyond firmware.

Tokens detected:
  Token A  SD: 256 GiB  RRAM: OK  ✓
  Token B  SD: 256 GiB  RRAM: OK  ✓
  Token C  SD: 256 GiB  RRAM: OK  ✓
  Token D  SD: 256 GiB  RRAM: OK  ✓
  Token E  SD: 256 GiB  RRAM: OK  ✓
  Token F  SD:  64 GiB  RRAM: OK  ✗  INSUFFICIENT — SD needs ≥ 159 GiB

WARNING: Token F SD card is too small. Aborting.
```

If all carriers are sufficient, the summary ends with:

```
All 6 carriers are sufficient.

This operation will DESTROY all data on the 6 carriers listed above.
Type YES to continue, or press Ctrl-C to abort: _
```

Required size per carrier is calculated as:

```
required_per_carrier = ceil(image_size / k)
                     + rs_parity_overhead       (~10% of chunk size)
                     + boot_environment_size    (512 MiB, USB drives only)
```

For Galdralag tokens the boot environment is not stored on the token, so the
SD card requirement is simply `ceil(image_size / k) + 10%`. The tool refuses
to proceed if any carrier is undersized.

### 8.4 Enrollment Session

`splitdisk-create` performs enrollment interactively after pre-flight passes:

1. Reads and Blake3-hashes the source image (streaming, reports progress).
2. Generates 32-byte session key from OS CSPRNG.
3. Encrypts image with chosen cipher suite (streaming, reports progress).
4. Splits ciphertext into n chunks via Reed-Solomon.
5. Splits session key into n shares via SSS (vsss-rs).
6. For each drive in sequence:
   a. Writes bootloader, kernel, initramfs.
   b. Writes data chunk.
   c. Prompts operator to set PIN for this drive (entered twice for confirmation,
      minimum 5 alphanumeric characters enforced before hashing).
   d. If `--biometric`: prompts to scan iris for this drive's holder.
   e. Encrypts key share and metadata with PIN-derived key.
   f. Writes encrypted share data.
   g. Reads back and verifies written chunk against source Blake3 hash.
7. **Post-write verification** — see §8.5.
8. **Source shredding** — see §8.6.

The session key is zeroized from memory immediately after step 6 completes.

### 8.5 Post-write Verification

After all n drives are written, `splitdisk-create` performs a mandatory
reconstruction dry-run using exactly k drives to confirm the scheme is viable
before the operator is permitted to shred the source.

The operator is prompted to insert any k of the n drives one at a time. For
each inserted drive:

```
Verification — insert any 3 of your 6 drives for reconstruction test.

Drive 1 of 3: insert a drive now...
  ✓ Drive accepted. Chunk hash verified.

Drive 2 of 3: insert a drive now...
  ✓ Drive accepted. Chunk hash verified.

Drive 3 of 3: insert a drive now...
  ✓ Drive accepted. Chunk hash verified.

Reconstructing session key...   ✓
Decrypting and decoding...      ✓
Output hash matches source:     ✓  (Blake3: a3f9…c214)

Verification successful. All 3 tested drives can reconstruct the content.
```

The reconstructed output is written to a temporary file or memory-mapped
buffer and its Blake3 hash is compared against the hash of the source image
taken in step 1 of §8.4. The temporary output is zeroized and discarded
after verification; it is never written to a persistent disk.

If verification fails:

```
ERROR: Reconstruction hash mismatch. Do NOT shred the source.
       Re-run splitdisk-create to recreate the drives.
```

The tool exits with a non-zero status. Source shredding is blocked.

**Verification is not optional and cannot be skipped.**

### 8.6 Source Shredding

Source shredding is offered only after §8.5 verification succeeds. It is
explicitly opt-in — the operator must pass `--shred` at invocation time, and
confirm again interactively before shredding begins.

```
Verification complete. The source drive or image can now be securely erased.

Target for shredding:  /dev/sda  (476.9 GiB)

WARNING: This will PERMANENTLY AND IRRECOVERABLY destroy all data on /dev/sda.
         The content now exists only on the 6 USB drives.
         Ensure all drives are physically secured before proceeding.

Type SHRED to overwrite with random data, or press Ctrl-C to skip: _
```

Shred procedure:

1. Open the source block device or file for writing.
2. Stream random bytes from the OS CSPRNG (`/dev/urandom` via `getrandom(2)`)
   over the entire device in 4 MiB blocks, reporting progress.
3. Call `fsync(2)` after each block to ensure writes reach the storage medium.
4. On completion, call `ioctl(BLKFLSBUF)` to flush the kernel block cache.
5. Report final status with bytes written and time elapsed.

```
Shredding /dev/sda...

  ████████████████████████████  100%   476.9 GiB / 476.9 GiB
  Time elapsed: 14m 32s
  Bytes written: 512,110,190,592

Shred complete. The source has been overwritten with random data.
```

Notes on shred effectiveness:

- On **HDDs**: a single overwrite pass with random data is sufficient to
  prevent software-based recovery. Multiple passes provide no meaningful
  additional protection on modern drives and are not offered.
- On **SSDs and flash storage**: due to wear levelling and overprovisioning,
  a single-pass overwrite may not reach all physical cells. The tool prints
  a warning for detected SSDs:

```
WARNING: /dev/sda appears to be an SSD or flash device.
         Wear levelling may preserve some data in overprovisioned cells.
         For maximum assurance, use the drive manufacturer's secure erase
         command (ATA Secure Erase or NVMe Format) after this overwrite.
```

- On **image files**: the file is overwritten in place, then the filesystem
  entry is unlinked. The tool warns that filesystem journalling or snapshots
  on the host may retain copies.

The `--shred` flag and all confirmations are required. If `--shred` is not
passed, the tool prints a reminder at the end:

```
Source NOT shredded (--shred not specified).
Remember to securely erase /dev/sda before the drives leave your control.
```

---

## 9. Checkpoint and Resume

If assembly is interrupted mid-write, a journal file is written to the target
disk (once enough of it is writable) tracking:

- Which chunks have been fully written
- The byte offset of the last confirmed write
- A Blake3 hash of each written segment

On next boot, if a partial journal is detected, the agent offers to resume
rather than restart. Resume requires the same k drives to be re-inserted (key
material is not cached between boots).

---

## 10. Workspace Layout

```
splitdisk/
├── Cargo.toml              (workspace)
├── crates/
│   ├── splitdisk-create/   (enrollment tool)
│   ├── splitdisk-assemble/ (initramfs agent)
│   ├── splitdisk-core/     (shared: crypto, RS, SSS wrappers, metadata format)
│   ├── splitdisk-auth/     (PIN, biometric, Galdralag token integration)
│   └── splitdisk-tui/      (ratatui UI components)
├── initramfs/
│   ├── build.sh            (build script: produces initramfs.img)
│   └── init                (init script invoking splitdisk-assemble)
└── docs/
    ├── SPEC.md             (this document)
    ├── CRYPTO.md           (detailed cryptographic rationale)
    └── GALDRALAG.md        (Galdralag integration guide)
```

---

## 11. Galdralag Integration Summary

When `--galdralag` is passed to `splitdisk-create`, each member receives only
a **Galdralag Baochip-1x token**. No separate USB drive is issued. The token
is the complete share — it holds both the encrypted data chunk (on SD card)
and the key share (in RRAM vault).

| Aspect | USB drive mode | Galdralag token mode |
|--------|----------------|----------------------|
| What the member carries | USB drive | Galdralag token only |
| Data chunk storage | USB drive partition | Token SD card |
| Key share storage | Encrypted in USB hidden partition | On-device RRAM vault |
| PIN enforcement | Software attempt counter | Hardware PIN counter with zeroization |
| Biometric | USB iris scanner + software | Optional; token PIN suffices |
| Encryption of key share | Argon2id-derived AES-256-GCM | BrainpoolP384r1 ECDH on-device |
| Forward secrecy | Not applicable | Authenticated ephemeral ECDH session |
| TRNG | OS CSPRNG | Hardware TRNG on Baochip-1x |
| SD card required | No | Yes (for data chunk storage) |
| Mixed mode with USB shares | N/A | Yes — both types can coexist in one scheme |

The assembly machine boots from any standard Linux USB or its own disk. The
Galdralag tokens are inserted one at a time into any USB port. The initramfs
includes `pcscd` and the `ccid` driver so no additional host setup is needed.

---

## 12. Security Considerations

- **Enrollment machine must be air-gapped** and have its memory securely erased
  after creating drives. `splitdisk-create` calls `zeroize` on all key material,
  but physical RAM remanence is a risk.
- **Drive firmware attacks**: an adversary with physical access to a drive before
  it reaches its holder could modify the bootloader or initramfs. Mitigations:
  tamper-evident packaging, and optionally signing the initramfs with Ed25519
  (same pattern as Galdralag firmware's boot0 verification).
- **Rubber hose**: a holder can be coerced into providing their PIN. The
  k-of-n threshold ensures that one holder's coercion is insufficient for
  reconstruction. The holder genuinely does not know how many others exist.
- **Share count leakage**: the progress bar reveals how many shares have been
  collected, which after k successes reveals k to an observer watching the
  screen. This is an acceptable trade-off; the total n remains hidden.
- **Post-quantum**: ML-KEM is feature-gated and marked unaudited. Enable only
  when an independently audited `no_std` Rust crate is available, following
  the same policy as Galdralag firmware.
- **Biometric template privacy**: templates are stored only on the individual's
  own drive, encrypted at rest. No operator or other member can access another
  member's biometric data.

---

## 13. Out of Scope

- Network-based share distribution or retrieval
- Cloud key management
- Windows or macOS host support for `splitdisk-create` (Linux only; assembly
  runs on the embedded Linux in initramfs on any x86-64 machine)
- WebAuthn / FIDO2
- VeraCrypt or LUKS integration (SplitDisk manages its own encryption layer)

---

## 14. Dependencies Summary

```toml
# Core crypto
aes-gcm = "0.10"
chacha20poly1305 = "0.10"
hkdf = "0.12"
argon2 = "0.5"
blake3 = "1"
zeroize = { version = "1", features = ["derive"] }
subtle = "2"

# Curves
p384 = "0.13"          # used for Brainpool via custom parameters

# Key splitting
vsss-rs = "3"          # Shamir, GF(256)

# Data splitting
reed-solomon-erasure = "6"

# TUI
ratatui = "0.26"

# OpenPGP (optional GPG envelope)
sequoia-openpgp = "1"

# USB / block device I/O
nix = "0.29"
rusb = "0.9"           # USB device enumeration

# Post-quantum (feature-gated, unaudited)
pqcrypto-kyber = { version = "0.7", optional = true }
```

---

*This specification is a design document. No warranty of correctness is made.
Cryptographic choices and security decisions should be reviewed by a qualified
cryptographer before implementation or deployment.*
