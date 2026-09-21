//! Proposed Mode A outer envelope header (cleartext outer AEAD still TBD).
//!
//! OPEN CHOICE: full Mode A wrapping is Phase 2+. This records the versioned
//! clear header that identifies an envelope blob before PIN unlock.

use super::FORMAT_VERSION;
use crate::error::{Error, Result};
use std::io::{Read, Write};

/// Magic: "SDEV" (SplitDisk Envelope).
pub const ENVELOPE_MAGIC: &[u8; 4] = b"SDEV";

/// Outer envelope header (not secret; suite_id concealed only after Mode A
/// AEAD in a later phase — see OPEN-QUESTIONS / FORMAT.md).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeHeader {
    pub version: u16,
    /// Provisional: 0 = Mode B (suite visible), 1 = Mode A (suite inside AEAD).
    pub mode: u8,
    /// Present only when mode == 0 (Mode B). Zeroed/ignored in Mode A header.
    pub suite_id: u16,
    /// Length of following ciphertext blob (bounded).
    pub body_len: u32,
}

pub fn write_envelope_header<W: Write>(w: &mut W, h: &EnvelopeHeader) -> Result<()> {
    w.write_all(ENVELOPE_MAGIC)?;
    w.write_all(&h.version.to_le_bytes())?;
    w.write_all(&[h.mode])?;
    w.write_all(&h.suite_id.to_le_bytes())?;
    w.write_all(&h.body_len.to_le_bytes())?;
    Ok(())
}

pub fn parse_envelope_header<R: Read>(r: &mut R) -> Result<EnvelopeHeader> {
    let mut magic = [0u8; 4];
    read_exact(r, &mut magic)?;
    if &magic != ENVELOPE_MAGIC {
        return Err(Error::Format("bad envelope magic"));
    }
    let mut ver = [0u8; 2];
    read_exact(r, &mut ver)?;
    let version = u16::from_le_bytes(ver);
    if version != FORMAT_VERSION {
        return Err(Error::Format("unsupported envelope version"));
    }
    let mut mode = [0u8; 1];
    read_exact(r, &mut mode)?;
    let mut suite = [0u8; 2];
    read_exact(r, &mut suite)?;
    let mut len = [0u8; 4];
    read_exact(r, &mut len)?;
    let body_len = u32::from_le_bytes(len);
    if body_len as u64 > super::MAX_FRAMED_LEN {
        return Err(Error::LengthBound {
            declared: body_len as u64,
            max: super::MAX_FRAMED_LEN,
        });
    }
    Ok(EnvelopeHeader {
        version,
        mode: mode[0],
        suite_id: u16::from_le_bytes(suite),
        body_len,
    })
}

fn read_exact<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<()> {
    let mut off = 0;
    while off < buf.len() {
        match r.read(&mut buf[off..]) {
            Ok(0) => return Err(Error::Format("truncated envelope header")),
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

    #[test]
    fn envelope_roundtrip() {
        let h = EnvelopeHeader {
            version: 1,
            mode: 0,
            suite_id: 0x0001,
            body_len: 100,
        };
        let mut buf = Vec::new();
        write_envelope_header(&mut buf, &h).unwrap();
        let p = parse_envelope_header(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(p, h);
    }
}
