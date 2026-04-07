# SplitDisk glossary

Plain-language explanations of technical terms used in this project. Entries are sorted alphabetically by letter, then by term name.

## A

### AEAD (authenticated encryption with associated data)

A way to scramble data so it stays secret and comes with a built-in seal that proves nothing was changed or corrupted in transit.

### Air-gapped

A computer that is not connected to the internet or other networks, so secrets are less likely to leak out electronically.

### Argon2id

A slow, memory-heavy way to turn a password (like a PIN) into a fixed fingerprint for storage. It is meant to resist guessing attacks.

### Assembly agent (`splitdisk-assemble`)

The small program that runs when you are putting the split pieces back together: it asks for drives or tokens, checks PINs, rebuilds the data, and writes it to the target disk.

### Authentication

Proving you are allowed to use something; here, usually you have the drive, you know the PIN, and sometimes your eye matches what was enrolled.

## B

### Baochip-1x

The hardware chip family used by the Galdralag security token in this design.

### Biometric

A body measurement used like a password; here, an iris or eye scan, so only the intended person can unlock their piece.

### BLAKE3

A fast way to compute a short fingerprint (hash) of data so you can check that nothing changed.

### Block device

Storage seen by the computer as raw sectors (like a whole disk or USB stick) rather than as files inside a folder.

### Bootloader / EFI

Software that runs first when a PC starts from a USB stick and loads the operating system (here, a minimal Linux setup).

### Brainpool curves

A family of mathematical curves used for key agreement (agreeing on a secret over an open channel). The spec prefers these over some common NIST curves.

## C

### Carrier

Whatever holds one share: a USB drive or a Galdralag token (sometimes with an SD card).

### CCID

A standard USB way to talk to smart cards and similar security devices, so the host does not need special vendor drivers.

### ChaCha20-Poly1305

A common combination: ChaCha20 hides the data; Poly1305 tags it so tampering is detected.

### Checkpoint / resume journal

A small record on the target disk of how far writing got. If power fails, the process can continue from there instead of starting over.

### CESS

A defined set of approved cryptographic building blocks and rules this project aims to follow (conformance).

### Classical cryptography

Pre-quantum-era techniques; here, contrasted with post-quantum add-ons for long-term safety.

### Cleartext / plaintext

Data in readable form, not scrambled.

### Coercion resistance

Design so a person with one piece honestly cannot answer questions like how many others exist, because the system never told them.

### Command-line interface (CLI)

A text-based program you run by typing commands and flags rather than using a graphical wizard.

### Constant-time comparisons

Programming discipline so checking secrets does not accidentally leak hints through timing.

### Crate

Rust's name for a library or package of code.

### CSPRNG (cryptographically secure random number generator)

A source of randomness suitable for keys and secrets, not like casual randomness in a game.

## D

### Decryption

Reversing encryption to recover the original content when you have the right keys.

### Disk image

A file that is a byte-for-byte copy of a disk's contents, treated like a virtual drive.

### Dry run

A full rehearsal that checks the math and data without relying on assumptions; here, rebuilding and hashing before you are allowed to destroy the original.

### Duplicate detection

Recognizing the same physical drive inserted twice so progress does not count it twice.

## E

### ECDH (Elliptic Curve Diffie-Hellman)

A way for two parties to agree on a shared secret over an untrusted channel using elliptic-curve math.

### Embedded

Software built to run in a minimal environment (here, early boot from a USB) with few dependencies.

### Encryption

Scrambling data so it is useless without the right key.

### Enrollment

The one-time setup on a trusted machine where the original is read, split, PINs are set, and carriers are prepared.

### Erasure coding / Reed-Solomon

Splitting data into pieces with extra repair information so you only need *k* out of *n* pieces to rebuild (similar in spirit to redundant storage schemes).

## F

### Fault tolerance

If some members or drives are missing, the scheme still works as long as enough pieces (*k*) are present.

### Forward secrecy

Past messages stay protected even if long-term keys leak later; relevant for token sessions in the spec.

### FrodoKEM

A post-quantum key-exchange candidate; in the spec it is optional and feature-gated.

## G

### Galdralag

A hardware security token platform in this design; it can hold a key share and data chunk instead of a separate USB share.

### GPG / OpenPGP

Optional standard for encrypting a session key for specific recipients' keys.

### GPT

A modern style of partition table on a disk (how slices of the drive are laid out).

### GRUB

A common bootloader used to start Linux from the EFI partition.

## H

### Hamming distance (on iris codes)

A measure of how two bit-patterns differ; used to decide if a new scan matches the stored template within tolerance.

### Hardware TRNG

A random-number generator inside hardware, used where the spec wants strong physical randomness.

### Hash

A short fingerprint of data. If the fingerprint matches, the data is almost certainly unchanged.

### Hidden partition

A disk area not meant to look like a normal user-visible drive; it stores sensitive material.

### HKDF

A standard way to stretch a shared secret into proper cryptographic keys of the right length.

### Holder anonymity

People holding shares are not told their position, *k*, *n*, or what the content is.

### Hybrid encryption

Combining classical and post-quantum pieces so you get both established practice and future resistance.

## I

### Initramfs

A small filesystem loaded into memory at boot, before the main system; here it contains `splitdisk-assemble`.

### Integrity

Confidence that data was not altered; often checked with hashes before trusting a rebuild.

### Iris / retina scanner

USB eye scanner hardware mentioned for optional biometrics.

### ISO/IEC 19794-6

A standard format for iris biometric templates.

## K

### k-of-n (threshold scheme)

You split something into *n* pieces; any *k* pieces are enough to recover it (like needing a minimum number of keys to open a vault).

### KDF (key derivation function)

Turns passwords or shared secrets into proper encryption keys.

### KEM (key encapsulation mechanism)

A modern way to wrap a random key for someone using public-key techniques.

## L

### Linux kernel

The core of the Linux operating system; the spec bundles a minimal one for bootable USB shares.

## M

### Metadata

Extra data about the split (indexes, parameters); here it is kept encrypted so casual inspection does not reveal the scheme.

### Mixed mode

Some members use USB shares and others use Galdralag tokens in the same *k*-of-*n* setup.

### musl

A compact C library used for static Linux binaries that should run without extra shared libraries on the stick.

## N

### Nonce

A one-time value used with encryption so the same key never scrambles two blocks identically.

### NIST

US standards body; the spec deliberately avoids some NIST-only curves for policy reasons.

### no_std

Rust code that can run without the full standard library, useful for tiny embedded builds.

## P

### Parity / overhead

Extra bytes Reed-Solomon adds so missing pieces can still be reconstructed; roughly spare capacity for repair.

### Partition

A labeled section of a disk (for example EFI versus data).

### pcscd

A background service on Linux that speaks CCID to smart cards and tokens.

### Physical confidentiality

Drives look like opaque blobs; no helpful filenames or labels that explain the secret sharing.

### PIN

A short secret the holder types, combined with possession of the carrier.

### Poly1305

A MAC (authenticator) often paired with ciphers in AEAD modes.

### Post-quantum cryptography

Algorithms meant to resist attacks by future large quantum computers; optional here.

### Progress bar (trade-off)

The user interface shows how many shares succeeded, which can hint at *k* to someone watching; total *n* stays hidden.

## R

### Random UUID

A unique ID for a volume so drives do not look linked by shared serials.

### Reconstruction

Putting chunks and key shares back together to recover the original encrypted content, then decrypting and writing it out.

### Reed-Solomon

See erasure coding: splits data with redundancy so *k* of *n* chunks suffice.

### RRAM

Non-volatile memory on the token used for small, sensitive material like key shares.

### Rust

The programming language targeted for implementation.

## S

### Salt

Random data mixed into password hashing so two identical PINs do not produce the same stored fingerprint.

### SD card

Removable card in a Galdralag token for the larger chunk of data.

### Serpent / Twofish

Alternative bulk ciphers in the design; they can be layered in cascade modes.

### Session key

The main random key used to encrypt the disk image for one enrollment run; it is split across members.

### Shamir's Secret Sharing (SSS)

A mathematical way to split a secret into *n* pieces where any *k* reassemble it; fewer pieces reveal nothing useful.

### Share

One participant's piece: encrypted data chunk plus protected key share and authentication.

### Shredding (source)

Overwriting the original disk or file with random data so the plaintext should not remain on that media.

### Smart card

A chip card or token that can do crypto operations; CCID is how the PC talks to it.

### splitdisk-create

The tool run once on the enrollment machine to build all carriers from a source.

### splitdisk-image

Builds the bootable USB layout (partitions, kernel, initramfs) without relying on external shell toolchains for that assembly.

### Static linking

The program is bundled with what it needs so it runs in a bare initramfs without missing libraries.

### Suite ID

A numeric label for which exact cipher combination was used; in Mode A it is hidden inside the outer encryption.

## T

### Threshold (*k*)

The minimum number of shares needed to rebuild; the *k* in *k*-of-*n*.

### TRNG

True random number generator: physical randomness, not just math.

### TUI (text user interface)

Fullscreen terminal interface (here using ratatui) for assembly, without a full desktop.

## U

### USB mass storage

A USB stick that looks like a normal external drive to the computer.

## V

### Verified write

Rebuilding and checking against a hash before the operator is allowed to erase the original, so mistakes are caught early.

### Volume label / UUID

Human or machine identifiers for a partition; the spec avoids revealing labels and randomizes UUIDs.

## Z

### Zeroize / zeroisation

Securely wiping secrets from memory, or destroying token contents after too many failed PIN attempts on hardware.
