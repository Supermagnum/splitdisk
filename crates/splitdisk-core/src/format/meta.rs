//! `meta.bin` plaintext layout (encrypted with K_pin at rest — Phase 2+).
//!
//! This module only defines the plaintext byte layout and a length-safe parser.

use super::{FORMAT_VERSION, MAX_FRAMED_LEN};
use crate::error::{Error, Result};
use std::io::{Read, Write};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Magic: "SDMT" (SplitDisk Meta).
pub const META_MAGIC: &[u8; 4] = b"SDMT";

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
}

pub fn write_meta<W: Write>(w: &mut W, m: &MetaPlaintext) -> Result<()> {
    w.write_all(META_MAGIC)?;
    w.write_all(&m.version.to_le_bytes())?;
    w.write_all(&[m.share_index, m.k, m.n])?;
    w.write_all(&m.suite_id.to_le_bytes())?;
    w.write_all(&m.chunk_blake3)?;
    w.write_all(&m.drive_fingerprint)?;
    Ok(())
}

pub fn parse_meta(bytes: &[u8]) -> Result<MetaPlaintext> {
    const MIN: usize = 4 + 2 + 3 + 2 + 32 + 32;
    if bytes.len() < MIN {
        return Err(Error::Format("meta too short"));
    }
    if bytes.len() as u64 > MAX_FRAMED_LEN {
        return Err(Error::LengthBound {
            declared: bytes.len() as u64,
            max: MAX_FRAMED_LEN,
        });
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
    Ok(MetaPlaintext {
        version,
        share_index,
        k,
        n,
        suite_id,
        chunk_blake3,
        drive_fingerprint,
    })
}

/// Read exactly the fixed-size meta plaintext from a reader.
#[allow(dead_code)] // used by Phase 2 auth; kept for parser completeness
pub fn read_meta<R: Read>(r: &mut R) -> Result<MetaPlaintext> {
    let mut buf = [0u8; 75];
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
        };
        let mut buf = Vec::new();
        write_meta(&mut buf, &m).unwrap();
        let p = parse_meta(&buf).unwrap();
        assert_eq!(p.share_index, 2);
        assert_eq!(p.k, 3);
        assert_eq!(p.n, 5);
        assert_eq!(p.chunk_blake3, m.chunk_blake3);
    }

    #[test]
    fn meta_tamper_magic() {
        let mut buf = vec![0u8; 75];
        buf[0..4].copy_from_slice(b"XXXX");
        assert!(parse_meta(&buf).is_err());
    }
}
