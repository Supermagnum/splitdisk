//! BLAKE3-framed Reed-Solomon shard records (`chunk.bin` stripes).

use super::{FORMAT_VERSION, MAX_FRAMED_LEN};
use crate::error::{Error, Result};
use std::io::{Read, Write};

/// Magic for a chunk frame: "SDCF" (SplitDisk Chunk Frame).
pub const CHUNK_MAGIC: &[u8; 4] = b"SDCF";

/// One framed shard for a single stripe on one share.
#[derive(Debug, Clone)]
pub struct ChunkFrame {
    pub version: u16,
    pub share_index: u8,
    pub stripe_index: u64,
    /// Unpadded plaintext/ciphertext bytes in this stripe before zero-pad.
    pub original_stripe_len: u32,
    pub shard_len: u32,
    pub hash: [u8; 32],
    pub data: Vec<u8>,
}

/// Serialize a chunk frame.
pub fn write_chunk_frame<W: Write>(w: &mut W, frame: &ChunkFrame) -> Result<()> {
    if frame.data.len() != frame.shard_len as usize {
        return Err(Error::Format("shard_len does not match data"));
    }
    if frame.data.len() as u64 > MAX_FRAMED_LEN {
        return Err(Error::LengthBound {
            declared: frame.data.len() as u64,
            max: MAX_FRAMED_LEN,
        });
    }
    w.write_all(CHUNK_MAGIC)?;
    w.write_all(&frame.version.to_le_bytes())?;
    w.write_all(&[frame.share_index])?;
    w.write_all(&frame.stripe_index.to_le_bytes())?;
    w.write_all(&frame.original_stripe_len.to_le_bytes())?;
    w.write_all(&frame.shard_len.to_le_bytes())?;
    w.write_all(&frame.hash)?;
    w.write_all(&frame.data)?;
    Ok(())
}

/// Parse one chunk frame. Returns [`Error::UnexpectedEof`] only when no bytes
/// of a new frame could be read (clean end). Partial headers are format errors.
pub fn parse_chunk_frame<R: Read>(r: &mut R) -> Result<ChunkFrame> {
    let mut magic = [0u8; 4];
    match read_exact_or_eof(r, &mut magic)? {
        ReadStart::Eof => return Err(Error::UnexpectedEof),
        ReadStart::Got => {}
    }
    if &magic != CHUNK_MAGIC {
        return Err(Error::Format("bad chunk frame magic"));
    }

    let mut ver_b = [0u8; 2];
    read_exact(r, &mut ver_b)?;
    let version = u16::from_le_bytes(ver_b);
    if version != FORMAT_VERSION {
        return Err(Error::Format("unsupported chunk frame version"));
    }

    let mut share_index = [0u8; 1];
    read_exact(r, &mut share_index)?;

    let mut stripe_b = [0u8; 8];
    read_exact(r, &mut stripe_b)?;
    let stripe_index = u64::from_le_bytes(stripe_b);

    let mut orig_b = [0u8; 4];
    read_exact(r, &mut orig_b)?;
    let original_stripe_len = u32::from_le_bytes(orig_b);

    let mut len_b = [0u8; 4];
    read_exact(r, &mut len_b)?;
    let shard_len = u32::from_le_bytes(len_b);
    if shard_len as u64 > MAX_FRAMED_LEN {
        return Err(Error::LengthBound {
            declared: shard_len as u64,
            max: MAX_FRAMED_LEN,
        });
    }

    let mut hash = [0u8; 32];
    read_exact(r, &mut hash)?;

    let mut data = vec![0u8; shard_len as usize];
    read_exact(r, &mut data)?;

    Ok(ChunkFrame {
        version,
        share_index: share_index[0],
        stripe_index,
        original_stripe_len,
        shard_len,
        hash,
        data,
    })
}

enum ReadStart {
    Eof,
    Got,
}

fn read_exact_or_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<ReadStart> {
    let mut off = 0;
    while off < buf.len() {
        match r.read(&mut buf[off..]) {
            Ok(0) if off == 0 => return Ok(ReadStart::Eof),
            Ok(0) => return Err(Error::Format("truncated chunk frame header")),
            Ok(n) => off += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(Error::Io(e)),
        }
    }
    Ok(ReadStart::Got)
}

fn read_exact<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<()> {
    let mut off = 0;
    while off < buf.len() {
        match r.read(&mut buf[off..]) {
            Ok(0) => return Err(Error::Format("truncated chunk frame")),
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
    fn frame_roundtrip() {
        let data = vec![1u8, 2, 3, 4, 5];
        let hash = *blake3::hash(&data).as_bytes();
        let frame = ChunkFrame {
            version: 1,
            share_index: 2,
            stripe_index: 7,
            original_stripe_len: 100,
            shard_len: data.len() as u32,
            hash,
            data,
        };
        let mut buf = Vec::new();
        write_chunk_frame(&mut buf, &frame).unwrap();
        let parsed = parse_chunk_frame(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(parsed.share_index, 2);
        assert_eq!(parsed.stripe_index, 7);
        assert_eq!(parsed.data, frame.data);
        assert_eq!(parsed.hash, hash);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"BAD!");
        buf.extend_from_slice(&[0u8; 50]);
        let err = parse_chunk_frame(&mut Cursor::new(&buf));
        assert!(matches!(err, Err(Error::Format(_))));
    }

    #[test]
    fn rejects_huge_length() {
        let mut buf = Vec::new();
        buf.extend_from_slice(CHUNK_MAGIC);
        buf.extend_from_slice(&1u16.to_le_bytes());
        buf.push(0);
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&u32::MAX.to_le_bytes());
        buf.extend_from_slice(&[0u8; 32]);
        let err = parse_chunk_frame(&mut Cursor::new(&buf));
        assert!(matches!(err, Err(Error::LengthBound { .. })));
    }

    #[test]
    fn eof_on_empty() {
        let err = parse_chunk_frame(&mut Cursor::new(&[]));
        assert!(matches!(err, Err(Error::UnexpectedEof)));
    }
}
