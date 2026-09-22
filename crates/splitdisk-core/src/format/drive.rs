//! File-backed share drive container (`SDDR`).
//!
//! Phase 2 uses a single regular file per carrier (not a real FAT volume).
//! Layout mirrors SPEC §6 paths as length-prefixed sections:
//! `chunk.bin`, `pin.hash`, `share.enc` (SDKW), `meta.bin` (AEAD ciphertext).
//!
//! `share_index` is **never** stored in this cleartext header (holder anonymity,
//! SPEC §2). Domain separation for AEAD uses [`DRIVE_UUID_LEN`]-byte
//! `drive_uuid` instead.

use super::{FORMAT_VERSION, MAX_FRAMED_LEN};
use crate::error::{Error, Result};
use std::io::{Read, Write};

/// Magic: "SDDR" (SplitDisk Drive).
pub const DRIVE_MAGIC: &[u8; 4] = b"SDDR";

/// Per-drive random UUID length (cleartext; no semantic link to share index).
pub const DRIVE_UUID_LEN: usize = 16;

/// Fixed header size before section payloads.
/// magic(4)+ver(2)+source(32)+drive_uuid(16)+suite_id(2)+8*u64 sections
pub const DRIVE_HEADER_LEN: usize = 4 + 2 + 32 + DRIVE_UUID_LEN + 2 + 8 * 8;

/// Parsed drive header (section offsets are absolute file offsets).
#[derive(Debug, Clone)]
pub struct DriveHeader {
    pub version: u16,
    pub source_blake3: [u8; 32],
    /// Random per-drive id for AEAD AAD; carries no share-index information.
    pub drive_uuid: [u8; DRIVE_UUID_LEN],
    pub suite_id: u16,
    pub chunk_off: u64,
    pub chunk_len: u64,
    pub pin_off: u64,
    pub pin_len: u64,
    pub share_off: u64,
    pub share_len: u64,
    pub meta_off: u64,
    pub meta_len: u64,
}

/// In-memory sections written into a drive file.
#[derive(Debug, Clone)]
pub struct DriveSections {
    pub source_blake3: [u8; 32],
    pub drive_uuid: [u8; DRIVE_UUID_LEN],
    pub suite_id: u16,
    pub chunk: Vec<u8>,
    pub pin_hash: Vec<u8>,
    pub share_wrap: Vec<u8>,
    pub meta_sealed: Vec<u8>,
}

pub fn write_drive<W: Write>(w: &mut W, sections: &DriveSections) -> Result<()> {
    for len in [
        sections.chunk.len(),
        sections.pin_hash.len(),
        sections.share_wrap.len(),
        sections.meta_sealed.len(),
    ] {
        if len == 0 {
            return Err(Error::InvalidParameter("empty drive section"));
        }
        if len as u64 > MAX_FRAMED_LEN {
            return Err(Error::LengthBound {
                declared: len as u64,
                max: MAX_FRAMED_LEN,
            });
        }
    }

    let chunk_off = DRIVE_HEADER_LEN as u64;
    let pin_off = chunk_off + sections.chunk.len() as u64;
    let share_off = pin_off + sections.pin_hash.len() as u64;
    let meta_off = share_off + sections.share_wrap.len() as u64;

    let hdr = DriveHeader {
        version: FORMAT_VERSION,
        source_blake3: sections.source_blake3,
        drive_uuid: sections.drive_uuid,
        suite_id: sections.suite_id,
        chunk_off,
        chunk_len: sections.chunk.len() as u64,
        pin_off,
        pin_len: sections.pin_hash.len() as u64,
        share_off,
        share_len: sections.share_wrap.len() as u64,
        meta_off,
        meta_len: sections.meta_sealed.len() as u64,
    };
    write_drive_header(w, &hdr)?;
    w.write_all(&sections.chunk)?;
    w.write_all(&sections.pin_hash)?;
    w.write_all(&sections.share_wrap)?;
    w.write_all(&sections.meta_sealed)?;
    w.flush()?;
    Ok(())
}

pub fn write_drive_header<W: Write>(w: &mut W, hdr: &DriveHeader) -> Result<()> {
    w.write_all(DRIVE_MAGIC)?;
    w.write_all(&hdr.version.to_le_bytes())?;
    w.write_all(&hdr.source_blake3)?;
    w.write_all(&hdr.drive_uuid)?;
    w.write_all(&hdr.suite_id.to_le_bytes())?;
    w.write_all(&hdr.chunk_off.to_le_bytes())?;
    w.write_all(&hdr.chunk_len.to_le_bytes())?;
    w.write_all(&hdr.pin_off.to_le_bytes())?;
    w.write_all(&hdr.pin_len.to_le_bytes())?;
    w.write_all(&hdr.share_off.to_le_bytes())?;
    w.write_all(&hdr.share_len.to_le_bytes())?;
    w.write_all(&hdr.meta_off.to_le_bytes())?;
    w.write_all(&hdr.meta_len.to_le_bytes())?;
    Ok(())
}

pub fn parse_drive_header(bytes: &[u8]) -> Result<DriveHeader> {
    if bytes.len() < DRIVE_HEADER_LEN {
        return Err(Error::Format("drive header too short"));
    }
    if &bytes[0..4] != DRIVE_MAGIC {
        return Err(Error::Format("bad drive magic"));
    }
    let version = u16::from_le_bytes([bytes[4], bytes[5]]);
    if version != FORMAT_VERSION {
        return Err(Error::Format("unsupported drive version"));
    }
    let mut source_blake3 = [0u8; 32];
    source_blake3.copy_from_slice(&bytes[6..38]);
    let mut drive_uuid = [0u8; DRIVE_UUID_LEN];
    drive_uuid.copy_from_slice(&bytes[38..54]);
    let suite_id = u16::from_le_bytes([bytes[54], bytes[55]]);
    let mut o = 56;
    let chunk_off = read_u64(bytes, &mut o)?;
    let chunk_len = read_u64(bytes, &mut o)?;
    let pin_off = read_u64(bytes, &mut o)?;
    let pin_len = read_u64(bytes, &mut o)?;
    let share_off = read_u64(bytes, &mut o)?;
    let share_len = read_u64(bytes, &mut o)?;
    let meta_off = read_u64(bytes, &mut o)?;
    let meta_len = read_u64(bytes, &mut o)?;
    for len in [chunk_len, pin_len, share_len, meta_len] {
        if len == 0 || len > MAX_FRAMED_LEN {
            return Err(Error::LengthBound {
                declared: len,
                max: MAX_FRAMED_LEN,
            });
        }
    }
    Ok(DriveHeader {
        version,
        source_blake3,
        drive_uuid,
        suite_id,
        chunk_off,
        chunk_len,
        pin_off,
        pin_len,
        share_off,
        share_len,
        meta_off,
        meta_len,
    })
}

/// Read an entire drive file into sections (bounded).
pub fn read_drive_sections<R: Read>(r: &mut R) -> Result<(DriveHeader, DriveSections)> {
    let mut hdr_buf = vec![0u8; DRIVE_HEADER_LEN];
    read_exact(r, &mut hdr_buf)?;
    let hdr = parse_drive_header(&hdr_buf)?;

    if hdr.chunk_off != DRIVE_HEADER_LEN as u64 {
        return Err(Error::Format("unexpected chunk offset"));
    }
    let mut chunk = vec![0u8; hdr.chunk_len as usize];
    read_exact(r, &mut chunk)?;
    let mut pin_hash = vec![0u8; hdr.pin_len as usize];
    read_exact(r, &mut pin_hash)?;
    let mut share_wrap = vec![0u8; hdr.share_len as usize];
    read_exact(r, &mut share_wrap)?;
    let mut meta_sealed = vec![0u8; hdr.meta_len as usize];
    read_exact(r, &mut meta_sealed)?;

    let mut extra = [0u8; 1];
    match r.read(&mut extra) {
        Ok(0) => {}
        Ok(_) => return Err(Error::Format("trailing data after drive sections")),
        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
        Err(e) => return Err(Error::Io(e)),
    }

    Ok((
        hdr.clone(),
        DriveSections {
            source_blake3: hdr.source_blake3,
            drive_uuid: hdr.drive_uuid,
            suite_id: hdr.suite_id,
            chunk,
            pin_hash,
            share_wrap,
            meta_sealed,
        },
    ))
}

fn read_u64(bytes: &[u8], o: &mut usize) -> Result<u64> {
    if *o + 8 > bytes.len() {
        return Err(Error::Format("truncated drive header field"));
    }
    let mut le = [0u8; 8];
    le.copy_from_slice(&bytes[*o..*o + 8]);
    *o += 8;
    Ok(u64::from_le_bytes(le))
}

fn read_exact<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<()> {
    let mut off = 0;
    while off < buf.len() {
        match r.read(&mut buf[off..]) {
            Ok(0) => return Err(Error::UnexpectedEof),
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
    fn drive_roundtrip() {
        let sections = DriveSections {
            source_blake3: [0xAAu8; 32],
            drive_uuid: [0x11u8; DRIVE_UUID_LEN],
            suite_id: 0x0001,
            chunk: vec![1, 2, 3, 4],
            pin_hash: vec![5; 66],
            share_wrap: vec![6; 40],
            meta_sealed: vec![7; 91],
        };
        let mut buf = Vec::new();
        write_drive(&mut buf, &sections).unwrap();
        let (hdr, got) = read_drive_sections(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(hdr.source_blake3, [0xAAu8; 32]);
        assert_eq!(hdr.drive_uuid, [0x11u8; DRIVE_UUID_LEN]);
        assert_eq!(got.chunk, sections.chunk);
        assert_eq!(got.pin_hash, sections.pin_hash);
        assert_eq!(got.share_wrap, sections.share_wrap);
        assert_eq!(got.meta_sealed, sections.meta_sealed);
    }
}
