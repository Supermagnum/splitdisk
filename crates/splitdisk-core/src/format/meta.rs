//! `meta.bin` plaintext layout (encrypted with K_pin at rest).

use super::{FORMAT_VERSION, MAX_FRAMED_LEN};
use crate::error::{Error, Result};
use std::io::{Read, Write};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Magic: "SDMT" (SplitDisk Meta).
pub const META_MAGIC: &[u8; 4] = b"SDMT";

/// Fixed plaintext size including Phase 2 `stripe_size` field.
pub const META_PLAINTEXT_LEN: usize = 4 + 2 + 3 + 2 + 32 + 32 + 4;

/// Plaintext metadata revealed only after PIN success.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct MetaPlaintext {
    pub version: u16,
    pub share_index: u8,
    pub k: u8,
    pub n: u8,
    pub suite_id: u16,
    pub chunk_blake3: [u8; 32],
    /// Per-drive fingerprint for duplicate detection (not shown in TUI).
    pub drive_fingerprint: [u8; 32],
    /// RS stripe size used at enrollment (must be divisible by k).
    pub stripe_size: u32,
}

pub fn write_meta<W: Write>(w: &mut W, m: &MetaPlaintext) -> Result<()> {
    w.write_all(META_MAGIC)?;
    w.write_all(&m.version.to_le_bytes())?;
    w.write_all(&[m.share_index, m.k, m.n])?;
    w.write_all(&m.suite_id.to_le_bytes())?;
    w.write_all(&m.chunk_blake3)?;
    w.write_all(&m.drive_fingerprint)?;
    w.write_all(&m.stripe_size.to_le_bytes())?;
    Ok(())
}

pub fn parse_meta(bytes: &[u8]) -> Result<MetaPlaintext> {
    if bytes.len() < META_PLAINTEXT_LEN {
        return Err(Error::Format("meta too short"));
    }
    if bytes.len() as u64 > MAX_FRAMED_LEN {
        return Err(Error::LengthBound {
            declared: bytes.len() as u64,
            max: MAX_FRAMED_LEN,
        });
    }
    if bytes.len() != META_PLAINTEXT_LEN {
        return Err(Error::Format("unexpected meta length"));
    }
    if &bytes[0..4] != META_MAGIC {
        return Err(Error::Format("bad meta magic"));
    }
    let version = u16::from_le_bytes([bytes[4], bytes[5]]);
    if version != FORMAT_VERSION {
        return Err(Error::Format("unsupported meta version"));
    }
    let share_index = bytes[6];
    let k = bytes[7];
    let n = bytes[8];
    let suite_id = u16::from_le_bytes([bytes[9], bytes[10]]);
    let mut chunk_blake3 = [0u8; 32];
    chunk_blake3.copy_from_slice(&bytes[11..43]);
    let mut drive_fingerprint = [0u8; 32];
    drive_fingerprint.copy_from_slice(&bytes[43..75]);
    let stripe_size = u32::from_le_bytes([bytes[75], bytes[76], bytes[77], bytes[78]]);
    if stripe_size == 0 {
        return Err(Error::Format("stripe_size must be non-zero"));
    }
    Ok(MetaPlaintext {
        version,
        share_index,
        k,
        n,
        suite_id,
        chunk_blake3,
        drive_fingerprint,
        stripe_size,
    })
}

/// Read exactly the fixed-size meta plaintext from a reader.
pub fn read_meta<R: Read>(r: &mut R) -> Result<MetaPlaintext> {
    let mut buf = [0u8; META_PLAINTEXT_LEN];
    let mut off = 0;
    while off < buf.len() {
        match r.read(&mut buf[off..]) {
            Ok(0) => return Err(Error::Format("truncated meta")),
            Ok(n) => off += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(Error::Io(e)),
        }
    }
    parse_meta(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meta_roundtrip() {
        let m = MetaPlaintext {
            version: 1,
            share_index: 2,
            k: 3,
            n: 5,
            suite_id: 0x0001,
            chunk_blake3: [0x11; 32],
            drive_fingerprint: [0x22; 32],
            stripe_size: 4096,
        };
        let mut buf = Vec::new();
        write_meta(&mut buf, &m).unwrap();
        assert_eq!(buf.len(), META_PLAINTEXT_LEN);
        let p = parse_meta(&buf).unwrap();
        assert_eq!(p.share_index, 2);
        assert_eq!(p.k, 3);
        assert_eq!(p.n, 5);
        assert_eq!(p.chunk_blake3, m.chunk_blake3);
        assert_eq!(p.stripe_size, 4096);
    }

    #[test]
    fn meta_tamper_magic() {
        let mut buf = vec![0u8; META_PLAINTEXT_LEN];
        buf[0..4].copy_from_slice(b"XXXX");
        assert!(parse_meta(&buf).is_err());
    }
}
