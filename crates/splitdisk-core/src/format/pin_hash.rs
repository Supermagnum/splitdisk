//! `pin.hash` layout (`SDPH`) — Argon2id parameters, salt, and output.

use super::{FORMAT_VERSION, MAX_FRAMED_LEN};
use crate::error::{Error, Result};
use std::io::Write;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Magic: "SDPH" (SplitDisk PIN Hash).
pub const PIN_HASH_MAGIC: &[u8; 4] = b"SDPH";

/// Fixed serialized size of [`PinHashRecord`].
pub const PIN_HASH_LEN: usize = 4 + 2 + 4 + 4 + 4 + 16 + 32;

/// SPEC §5.2 default Argon2id memory cost (KiB) = 64 MiB.
pub const DEFAULT_ARGON2_M_KIB: u32 = 65536;
/// SPEC §5.2 default iterations.
pub const DEFAULT_ARGON2_T_COST: u32 = 3;
/// SPEC §5.2 default parallelism.
pub const DEFAULT_ARGON2_P_COST: u32 = 4;

/// On-drive PIN hash record (plaintext file `pin.hash`).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PinHashRecord {
    pub version: u16,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub salt: [u8; 16],
    pub argon2id_output: [u8; 32],
}

impl PinHashRecord {
    pub fn new(
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
        salt: [u8; 16],
        argon2id_output: [u8; 32],
    ) -> Self {
        Self {
            version: FORMAT_VERSION,
            m_cost,
            t_cost,
            p_cost,
            salt,
            argon2id_output,
        }
    }
}

pub fn write_pin_hash<W: Write>(w: &mut W, rec: &PinHashRecord) -> Result<()> {
    w.write_all(PIN_HASH_MAGIC)?;
    w.write_all(&rec.version.to_le_bytes())?;
    w.write_all(&rec.m_cost.to_le_bytes())?;
    w.write_all(&rec.t_cost.to_le_bytes())?;
    w.write_all(&rec.p_cost.to_le_bytes())?;
    w.write_all(&rec.salt)?;
    w.write_all(&rec.argon2id_output)?;
    Ok(())
}

pub fn parse_pin_hash(bytes: &[u8]) -> Result<PinHashRecord> {
    if bytes.len() < PIN_HASH_LEN {
        return Err(Error::Format("pin.hash too short"));
    }
    if bytes.len() as u64 > MAX_FRAMED_LEN {
        return Err(Error::LengthBound {
            declared: bytes.len() as u64,
            max: MAX_FRAMED_LEN,
        });
    }
    if &bytes[0..4] != PIN_HASH_MAGIC {
        return Err(Error::Format("bad pin.hash magic"));
    }
    let version = u16::from_le_bytes([bytes[4], bytes[5]]);
    if version != FORMAT_VERSION {
        return Err(Error::Format("unsupported pin.hash version"));
    }
    let m_cost = u32::from_le_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]);
    let t_cost = u32::from_le_bytes([bytes[10], bytes[11], bytes[12], bytes[13]]);
    let p_cost = u32::from_le_bytes([bytes[14], bytes[15], bytes[16], bytes[17]]);
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&bytes[18..34]);
    let mut argon2id_output = [0u8; 32];
    argon2id_output.copy_from_slice(&bytes[34..66]);
    Ok(PinHashRecord {
        version,
        m_cost,
        t_cost,
        p_cost,
        salt,
        argon2id_output,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_hash_roundtrip() {
        let rec = PinHashRecord::new(8, 1, 1, [3u8; 16], [9u8; 32]);
        let mut buf = Vec::new();
        write_pin_hash(&mut buf, &rec).unwrap();
        assert_eq!(buf.len(), PIN_HASH_LEN);
        let p = parse_pin_hash(&buf).unwrap();
        assert_eq!(p.m_cost, 8);
        assert_eq!(p.salt, [3u8; 16]);
        assert_eq!(p.argon2id_output, [9u8; 32]);
    }

    #[test]
    fn pin_hash_bad_magic() {
        let buf = vec![0u8; PIN_HASH_LEN];
        assert!(parse_pin_hash(&buf).is_err());
    }
}
