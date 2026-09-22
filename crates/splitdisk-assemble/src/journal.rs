//! Checkpoint journal for resumable assembly (SPEC §9).

use splitdisk_core::error::{Error, Result};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

/// Journal file name under the checkpoint directory.
pub const JOURNAL_NAME: &str = "splitdisk.journal";

const MAGIC: &[u8; 4] = b"SDJN";
const VERSION: u16 = 1;
/// Fixed journal body size.
pub const JOURNAL_LEN: usize = 4 + 2 + 32 + 8 + 8 + 32 + 32 + 1;

#[derive(Debug, Clone)]
pub struct JournalState {
    pub source_blake3: [u8; 32],
    pub segments_committed: u64,
    pub bytes_committed: u64,
    pub running_blake3: [u8; 32],
    pub last_segment_blake3: [u8; 32],
    pub complete: bool,
}

impl JournalState {
    pub fn new(source_blake3: [u8; 32]) -> Self {
        Self {
            source_blake3,
            segments_committed: 0,
            bytes_committed: 0,
            running_blake3: *blake3::hash(b"").as_bytes(),
            last_segment_blake3: [0u8; 32],
            complete: false,
        }
    }

    pub fn store(&self, path: &Path) -> Result<()> {
        let mut buf = Vec::with_capacity(JOURNAL_LEN);
        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&VERSION.to_le_bytes());
        buf.extend_from_slice(&self.source_blake3);
        buf.extend_from_slice(&self.segments_committed.to_le_bytes());
        buf.extend_from_slice(&self.bytes_committed.to_le_bytes());
        buf.extend_from_slice(&self.running_blake3);
        buf.extend_from_slice(&self.last_segment_blake3);
        buf.push(u8::from(self.complete));
        let mut f = File::create(path)?;
        f.write_all(&buf)?;
        f.sync_all()?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let mut f = File::open(path)?;
        let mut buf = [0u8; JOURNAL_LEN];
        let mut off = 0;
        while off < buf.len() {
            match f.read(&mut buf[off..]) {
                Ok(0) => return Err(Error::Journal("truncated journal")),
                Ok(n) => off += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(Error::Io(e)),
            }
        }
        if &buf[0..4] != MAGIC {
            return Err(Error::Journal("bad journal magic"));
        }
        let ver = u16::from_le_bytes([buf[4], buf[5]]);
        if ver != VERSION {
            return Err(Error::Journal("unsupported journal version"));
        }
        let mut source_blake3 = [0u8; 32];
        source_blake3.copy_from_slice(&buf[6..38]);
        let mut seg_b = [0u8; 8];
        seg_b.copy_from_slice(&buf[38..46]);
        let segments_committed = u64::from_le_bytes(seg_b);
        let mut bytes_b = [0u8; 8];
        bytes_b.copy_from_slice(&buf[46..54]);
        let bytes_committed = u64::from_le_bytes(bytes_b);
        let mut running_blake3 = [0u8; 32];
        running_blake3.copy_from_slice(&buf[54..86]);
        let mut last_segment_blake3 = [0u8; 32];
        last_segment_blake3.copy_from_slice(&buf[86..118]);
        let complete = buf[118] != 0;
        Ok(Self {
            source_blake3,
            segments_committed,
            bytes_committed,
            running_blake3,
            last_segment_blake3,
            complete,
        })
    }
}
