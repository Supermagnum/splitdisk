//! Streaming segmented AEAD for multi-hundred-GiB images.
//!
//! A single AEAD message cannot cover a full disk image (memory and nonce
//! uniqueness). Construction (see `docs/FORMAT.md` and OPEN-QUESTIONS (d)):
//!
//! - Fixed-size segments (default 4 MiB plaintext).
//! - Per-segment nonce derived via keyed BLAKE3 from (index, final_flag).
//! - AAD binds segment index, final flag, and suite id (anti-reordering /
//!   anti-truncation).
//! - Exactly one segment must carry the FINAL flag; decrypt fails otherwise.

pub mod chacha;
mod stub;

use crate::error::{Error, Result};
use std::io::{Read, Write};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub use chacha::ChaCha20Poly1305Cipher;
pub use stub::{CascadeStub, SerpentStub, TwofishStub};

/// Default plaintext segment size: 4 MiB.
pub const DEFAULT_SEGMENT_SIZE: usize = 4 * 1024 * 1024;

/// Flag bit: this segment is the last in the stream.
pub const FLAG_FINAL: u8 = 0x01;

/// CESS suite id for brainpool384 + chacha20 (SPEC §15).
pub const SUITE_CHACHA20: u16 = 0x0001;

/// Bulk cipher selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadSuite {
    ChaCha20Poly1305,
    SerpentCtrPoly1305,
    TwofishCtrPoly1305,
    CascadeCs,
    CascadeCt,
    CascadeTs,
    CascadeCst,
}

impl AeadSuite {
    pub fn from_suite_id(id: u16) -> Result<Self> {
        match id {
            0x0001 | 0x0011 => Ok(Self::ChaCha20Poly1305),
            0x0002 | 0x0012 => Ok(Self::SerpentCtrPoly1305),
            0x0004 | 0x0014 => Ok(Self::TwofishCtrPoly1305),
            0x0003 | 0x0013 => Ok(Self::CascadeCs),
            0x0005 | 0x0015 => Ok(Self::CascadeCt),
            0x0006 | 0x0016 => Ok(Self::CascadeTs),
            0x0007 | 0x0017 => Ok(Self::CascadeCst),
            other => Err(Error::UnsupportedSuite(other)),
        }
    }

    pub fn suite_id(self) -> u16 {
        match self {
            Self::ChaCha20Poly1305 => 0x0001,
            Self::SerpentCtrPoly1305 => 0x0002,
            Self::CascadeCs => 0x0003,
            Self::TwofishCtrPoly1305 => 0x0004,
            Self::CascadeCt => 0x0005,
            Self::CascadeTs => 0x0006,
            Self::CascadeCst => 0x0007,
        }
    }
}

/// Trait for one AEAD segment encrypt/decrypt. Cascades/Serpent/Twofish are
/// stubbed in Phase 1 behind the same interface.
pub trait BulkCipher {
    fn encrypt_segment(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>>;

    fn decrypt_segment(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>>;
}

fn cipher_for(suite: AeadSuite) -> Result<Box<dyn BulkCipher>> {
    match suite {
        AeadSuite::ChaCha20Poly1305 => Ok(Box::new(ChaCha20Poly1305Cipher)),
        AeadSuite::SerpentCtrPoly1305 => Ok(Box::new(SerpentStub)),
        AeadSuite::TwofishCtrPoly1305 => Ok(Box::new(TwofishStub)),
        AeadSuite::CascadeCs
        | AeadSuite::CascadeCt
        | AeadSuite::CascadeTs
        | AeadSuite::CascadeCst => Ok(Box::new(CascadeStub { suite })),
    }
}

/// Session key material; zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AeadKey(pub [u8; 32]);

impl AeadKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Derive a 12-byte nonce from key, segment index, and flags.
pub fn derive_segment_nonce(key: &[u8; 32], index: u64, flags: u8) -> [u8; 12] {
    let nonce_key = blake3::derive_key("splitdisk-aead-nonce-v1", key);
    let mut hasher = blake3::Hasher::new_keyed(&nonce_key);
    hasher.update(&index.to_le_bytes());
    hasher.update(&[flags]);
    let out = hasher.finalize();
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&out.as_bytes()[..12]);
    nonce
}

/// Build AAD binding index, flags, and suite id.
pub fn segment_aad(index: u64, flags: u8, suite_id: u16) -> [u8; 11] {
    let mut aad = [0u8; 11];
    aad[..8].copy_from_slice(&index.to_le_bytes());
    aad[8] = flags;
    aad[9..11].copy_from_slice(&suite_id.to_le_bytes());
    aad
}

/// Encrypt a plaintext stream into the segmented AEAD wire format.
///
/// Wire layout per segment (after a one-time stream header written by caller
/// or by this function when `write_header` is true):
/// `index(u64 LE) | flags(u8) | ct_len(u32 LE) | ciphertext||tag`
pub fn encrypt_stream<R: Read, W: Write>(
    key: &AeadKey,
    suite: AeadSuite,
    segment_size: usize,
    mut input: R,
    mut output: W,
) -> Result<u64> {
    if segment_size == 0 || segment_size > (64 * 1024 * 1024) {
        return Err(Error::InvalidParameter("segment_size out of range"));
    }
    let cipher = cipher_for(suite)?;
    let suite_id = suite.suite_id();

    // Stream header: magic + version + suite_id + segment_size
    output.write_all(b"SDSE")?;
    output.write_all(&1u16.to_le_bytes())?;
    output.write_all(&suite_id.to_le_bytes())?;
    output.write_all(&(segment_size as u32).to_le_bytes())?;

    let mut buf = vec![0u8; segment_size];
    let mut index: u64 = 0;
    let mut total_pt: u64 = 0;
    let mut pending: Option<Vec<u8>> = None;

    loop {
        let n = read_fill(&mut input, &mut buf)?;
        if n == 0 {
            break;
        }
        total_pt = total_pt.saturating_add(n as u64);
        let chunk = buf[..n].to_vec();
        if let Some(prev) = pending.take() {
            write_segment(
                &mut output,
                cipher.as_ref(),
                key.as_bytes(),
                index,
                0,
                suite_id,
                &prev,
            )?;
            index = index
                .checked_add(1)
                .ok_or(Error::InvalidParameter("segment index overflow"))?;
        }
        pending = Some(chunk);
    }

    match pending {
        Some(last) => {
            write_segment(
                &mut output,
                cipher.as_ref(),
                key.as_bytes(),
                index,
                FLAG_FINAL,
                suite_id,
                &last,
            )?;
        }
        None => {
            // Empty plaintext: single empty FINAL segment.
            write_segment(
                &mut output,
                cipher.as_ref(),
                key.as_bytes(),
                0,
                FLAG_FINAL,
                suite_id,
                &[],
            )?;
        }
    }

    output.flush()?;
    buf.zeroize();
    Ok(total_pt)
}

/// Decrypt a segmented AEAD stream. On any auth/truncation error, no
/// successful plaintext is considered committed; partial writes may have
/// occurred to `output` only for prior verified segments. Callers that need
/// all-or-nothing should buffer or write to a temp file.
pub fn decrypt_stream<R: Read, W: Write>(key: &AeadKey, input: R, output: W) -> Result<u64> {
    decrypt_stream_with_progress(key, input, output, 0, |_| Ok(()))
}

/// Progress after a verified plaintext segment is written.
#[derive(Debug, Clone, Copy)]
pub struct DecryptSegmentProgress {
    pub segments_done: u64,
    pub bytes_written: u64,
    pub segment_plaintext_blake3: [u8; 32],
    pub is_final: bool,
}

/// Decrypt with resume support: skip writing the first `skip_segments` segments
/// (still authenticated), then invoke `on_segment` after each newly written
/// segment so callers can update a checkpoint journal.
pub fn decrypt_stream_with_progress<R, W, F>(
    key: &AeadKey,
    mut input: R,
    mut output: W,
    skip_segments: u64,
    mut on_segment: F,
) -> Result<u64>
where
    R: Read,
    W: Write,
    F: FnMut(DecryptSegmentProgress) -> Result<()>,
{
    let mut magic = [0u8; 4];
    read_exact(&mut input, &mut magic)?;
    if &magic != b"SDSE" {
        return Err(Error::Format("bad AEAD stream magic"));
    }
    let mut ver = [0u8; 2];
    read_exact(&mut input, &mut ver)?;
    if u16::from_le_bytes(ver) != 1 {
        return Err(Error::Format("unsupported AEAD stream version"));
    }
    let mut suite_b = [0u8; 2];
    read_exact(&mut input, &mut suite_b)?;
    let suite_id = u16::from_le_bytes(suite_b);
    let suite = AeadSuite::from_suite_id(suite_id)?;
    let cipher = cipher_for(suite)?;

    let mut seg_sz_b = [0u8; 4];
    read_exact(&mut input, &mut seg_sz_b)?;
    let segment_size = u32::from_le_bytes(seg_sz_b) as usize;
    if segment_size == 0 || segment_size > (64 * 1024 * 1024) {
        return Err(Error::Format("invalid segment_size in header"));
    }

    let mut total_pt: u64 = 0;
    let mut expected_index: u64 = 0;
    let mut saw_final = false;

    loop {
        let mut idx_b = [0u8; 8];
        match read_exact_or_eof(&mut input, &mut idx_b)? {
            ReadStart::Eof if saw_final => break,
            ReadStart::Eof => return Err(Error::AeadTruncation),
            ReadStart::Got => {}
        }
        if saw_final {
            return Err(Error::Format("data after FINAL segment"));
        }
        let index = u64::from_le_bytes(idx_b);
        if index != expected_index {
            return Err(Error::Format("segment index mismatch"));
        }

        let mut flags_b = [0u8; 1];
        read_exact(&mut input, &mut flags_b)?;
        let flags = flags_b[0];

        let mut len_b = [0u8; 4];
        read_exact(&mut input, &mut len_b)?;
        let ct_len = u32::from_le_bytes(len_b) as usize;
        let max_ct = segment_size
            .checked_add(16)
            .ok_or(Error::Format("segment size overflow"))?;
        if ct_len > max_ct {
            return Err(Error::LengthBound {
                declared: ct_len as u64,
                max: max_ct as u64,
            });
        }

        let mut ct = vec![0u8; ct_len];
        read_exact(&mut input, &mut ct)?;

        let nonce = derive_segment_nonce(key.as_bytes(), index, flags);
        let aad = segment_aad(index, flags, suite_id);
        let pt = match cipher.decrypt_segment(key.as_bytes(), &nonce, &aad, &ct) {
            Ok(p) => p,
            Err(e) => {
                ct.zeroize();
                return Err(e);
            }
        };
        ct.zeroize();

        if pt.len() > segment_size {
            return Err(Error::Format("plaintext exceeds segment_size"));
        }
        if flags & FLAG_FINAL == 0 && pt.len() != segment_size {
            return Err(Error::Format("non-final segment has short plaintext"));
        }

        let is_final = flags & FLAG_FINAL != 0;
        let segment_plaintext_blake3 = *blake3::hash(&pt).as_bytes();

        if index >= skip_segments {
            output.write_all(&pt)?;
            output.flush()?;
            total_pt = total_pt.saturating_add(pt.len() as u64);
            on_segment(DecryptSegmentProgress {
                segments_done: index + 1,
                bytes_written: total_pt,
                segment_plaintext_blake3,
                is_final,
            })?;
        } else {
            // Resumed past this segment: count toward total for journal math.
            total_pt = total_pt.saturating_add(pt.len() as u64);
        }

        if is_final {
            saw_final = true;
        }
        expected_index = expected_index
            .checked_add(1)
            .ok_or(Error::InvalidParameter("segment index overflow"))?;
    }

    if !saw_final {
        return Err(Error::AeadTruncation);
    }
    output.flush()?;
    Ok(total_pt)
}

fn write_segment<W: Write>(
    output: &mut W,
    cipher: &dyn BulkCipher,
    key: &[u8; 32],
    index: u64,
    flags: u8,
    suite_id: u16,
    plaintext: &[u8],
) -> Result<()> {
    let nonce = derive_segment_nonce(key, index, flags);
    let aad = segment_aad(index, flags, suite_id);
    let ct = cipher.encrypt_segment(key, &nonce, &aad, plaintext)?;
    output.write_all(&index.to_le_bytes())?;
    output.write_all(&[flags])?;
    let len = u32::try_from(ct.len()).map_err(|_| Error::InvalidParameter("ct too large"))?;
    output.write_all(&len.to_le_bytes())?;
    output.write_all(&ct)?;
    Ok(())
}

fn read_fill<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<usize> {
    let mut off = 0;
    while off < buf.len() {
        match r.read(&mut buf[off..]) {
            Ok(0) => break,
            Ok(n) => off += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(Error::Io(e)),
        }
    }
    Ok(off)
}

fn read_exact_or_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<ReadStart> {
    let mut off = 0;
    while off < buf.len() {
        match r.read(&mut buf[off..]) {
            Ok(0) if off == 0 => return Ok(ReadStart::Eof),
            Ok(0) => return Err(Error::AeadTruncation),
            Ok(n) => off += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(Error::Io(e)),
        }
    }
    Ok(ReadStart::Got)
}

enum ReadStart {
    Eof,
    Got,
}

fn read_exact<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<()> {
    let mut off = 0;
    while off < buf.len() {
        match r.read(&mut buf[off..]) {
            Ok(0) => return Err(Error::AeadTruncation),
            Ok(n) => off += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(Error::Io(e)),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn roundtrip(pt: &[u8], seg: usize) {
        let key = AeadKey::new([9u8; 32]);
        let mut ct = Vec::new();
        encrypt_stream(
            &key,
            AeadSuite::ChaCha20Poly1305,
            seg,
            Cursor::new(pt),
            &mut ct,
        )
        .unwrap();
        let mut out = Vec::new();
        decrypt_stream(&key, Cursor::new(&ct), &mut out).unwrap();
        assert_eq!(out, pt);
    }

    #[test]
    fn empty_and_small_roundtrip() {
        roundtrip(b"", 64);
        roundtrip(b"hello", 64);
        roundtrip(&[0xABu8; 200], 64);
        roundtrip(&[0xCDu8; 128], 64);
    }

    #[test]
    fn multi_segment_roundtrip() {
        let pt = vec![0x11u8; 250];
        roundtrip(&pt, 64);
    }

    #[test]
    fn wrong_key_fails() {
        let key = AeadKey::new([1u8; 32]);
        let mut ct = Vec::new();
        encrypt_stream(
            &key,
            AeadSuite::ChaCha20Poly1305,
            64,
            Cursor::new(b"data"),
            &mut ct,
        )
        .unwrap();
        let bad = AeadKey::new([2u8; 32]);
        let mut out = Vec::new();
        assert!(matches!(
            decrypt_stream(&bad, Cursor::new(&ct), &mut out),
            Err(Error::AeadAuth)
        ));
    }

    #[test]
    fn serpent_stub_errors() {
        let key = AeadKey::new([1u8; 32]);
        let mut ct = Vec::new();
        let err = encrypt_stream(
            &key,
            AeadSuite::SerpentCtrPoly1305,
            64,
            Cursor::new(b"x"),
            &mut ct,
        );
        assert!(matches!(err, Err(Error::CipherStub(_))));
    }
}
