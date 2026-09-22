//! PIN-wrapped key share (`SDKW`) — ChaCha20-Poly1305 under `K_pin`.
//!
//! No ECDH: Phase 2 wraps shares with the PIN-derived key only
//! (`docs/OPEN-QUESTIONS.md` (a)).
//!
//! AAD is the cleartext `drive_uuid` (not `share_index`) so the share index
//! never appears outside the PIN-encrypted meta payload.

use super::drive::DRIVE_UUID_LEN;
use super::{FORMAT_VERSION, MAX_FRAMED_LEN};
use crate::error::{Error, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use std::io::Write;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Magic: "SDKW" (SplitDisk Key Wrap).
pub const KEY_WRAP_MAGIC: &[u8; 4] = b"SDKW";

/// Header size before ciphertext: magic + version + nonce + ct_len.
pub const KEY_WRAP_HEADER_LEN: usize = 4 + 2 + 12 + 4;

/// Wrapped SSS share blob.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KeyWrapBlob {
    pub version: u16,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

/// AAD for key-wrap and meta seal: the per-drive random UUID (FORMAT.md).
pub fn pin_aead_aad(drive_uuid: &[u8; DRIVE_UUID_LEN]) -> &[u8; DRIVE_UUID_LEN] {
    drive_uuid
}

/// Encrypt an SSS share under `k_pin`.
pub fn wrap_key_share(
    k_pin: &[u8; 32],
    nonce: &[u8; 12],
    drive_uuid: &[u8; DRIVE_UUID_LEN],
    share_plaintext: &[u8],
) -> Result<KeyWrapBlob> {
    if share_plaintext.is_empty() || share_plaintext.len() as u64 > MAX_FRAMED_LEN {
        return Err(Error::InvalidParameter("share plaintext length"));
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(k_pin));
    let aad = pin_aead_aad(drive_uuid);
    let ct = cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: share_plaintext,
                aad,
            },
        )
        .map_err(|_| Error::AeadAuth)?;
    Ok(KeyWrapBlob {
        version: FORMAT_VERSION,
        nonce: *nonce,
        ciphertext: ct,
    })
}

/// Decrypt an SSS share under `k_pin`.
pub fn unwrap_key_share(
    k_pin: &[u8; 32],
    blob: &KeyWrapBlob,
    drive_uuid: &[u8; DRIVE_UUID_LEN],
) -> Result<Vec<u8>> {
    if blob.version != FORMAT_VERSION {
        return Err(Error::Format("unsupported key-wrap version"));
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(k_pin));
    let aad = pin_aead_aad(drive_uuid);
    cipher
        .decrypt(
            Nonce::from_slice(&blob.nonce),
            Payload {
                msg: &blob.ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::AeadAuth)
}

pub fn write_key_wrap<W: Write>(w: &mut W, blob: &KeyWrapBlob) -> Result<()> {
    let ct_len = u32::try_from(blob.ciphertext.len())
        .map_err(|_| Error::InvalidParameter("key-wrap ciphertext too large"))?;
    if ct_len as u64 > MAX_FRAMED_LEN {
        return Err(Error::LengthBound {
            declared: ct_len as u64,
            max: MAX_FRAMED_LEN,
        });
    }
    w.write_all(KEY_WRAP_MAGIC)?;
    w.write_all(&blob.version.to_le_bytes())?;
    w.write_all(&blob.nonce)?;
    w.write_all(&ct_len.to_le_bytes())?;
    w.write_all(&blob.ciphertext)?;
    Ok(())
}

pub fn parse_key_wrap(bytes: &[u8]) -> Result<KeyWrapBlob> {
    if bytes.len() < KEY_WRAP_HEADER_LEN {
        return Err(Error::Format("key-wrap too short"));
    }
    if bytes.len() as u64 > MAX_FRAMED_LEN {
        return Err(Error::LengthBound {
            declared: bytes.len() as u64,
            max: MAX_FRAMED_LEN,
        });
    }
    if &bytes[0..4] != KEY_WRAP_MAGIC {
        return Err(Error::Format("bad key-wrap magic"));
    }
    let version = u16::from_le_bytes([bytes[4], bytes[5]]);
    if version != FORMAT_VERSION {
        return Err(Error::Format("unsupported key-wrap version"));
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&bytes[6..18]);
    let ct_len = u32::from_le_bytes([bytes[18], bytes[19], bytes[20], bytes[21]]) as usize;
    if ct_len as u64 > MAX_FRAMED_LEN {
        return Err(Error::LengthBound {
            declared: ct_len as u64,
            max: MAX_FRAMED_LEN,
        });
    }
    if bytes.len() < KEY_WRAP_HEADER_LEN + ct_len {
        return Err(Error::Format("truncated key-wrap ciphertext"));
    }
    if bytes.len() != KEY_WRAP_HEADER_LEN + ct_len {
        return Err(Error::Format("trailing data after key-wrap"));
    }
    Ok(KeyWrapBlob {
        version,
        nonce,
        ciphertext: bytes[KEY_WRAP_HEADER_LEN..KEY_WRAP_HEADER_LEN + ct_len].to_vec(),
    })
}

/// Encrypt meta plaintext under `K_pin` (ChaCha20-Poly1305).
///
/// Nonce = BLAKE3-derive_key("splitdisk-meta-nonce-v1", K_pin)\[0..12\].
/// AAD = `drive_uuid` (cleartext; no share-index leakage).
pub fn seal_meta(
    k_pin: &[u8; 32],
    drive_uuid: &[u8; DRIVE_UUID_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let nonce = meta_nonce(k_pin);
    let aad = pin_aead_aad(drive_uuid);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(k_pin));
    cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::AeadAuth)
}

/// Decrypt meta ciphertext under `K_pin`.
pub fn open_meta(
    k_pin: &[u8; 32],
    drive_uuid: &[u8; DRIVE_UUID_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let nonce = meta_nonce(k_pin);
    let aad = pin_aead_aad(drive_uuid);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(k_pin));
    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::AeadAuth)
}

fn meta_nonce(k_pin: &[u8; 32]) -> [u8; 12] {
    let key = blake3::derive_key("splitdisk-meta-nonce-v1", k_pin);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&key[..12]);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_roundtrip() {
        let k_pin = [7u8; 32];
        let nonce = [1u8; 12];
        let uuid = [0xABu8; DRIVE_UUID_LEN];
        let share = b"sss-share-bytes-here-padded!!!!!";
        let blob = wrap_key_share(&k_pin, &nonce, &uuid, share).unwrap();
        let mut ser = Vec::new();
        write_key_wrap(&mut ser, &blob).unwrap();
        let parsed = parse_key_wrap(&ser).unwrap();
        let pt = unwrap_key_share(&k_pin, &parsed, &uuid).unwrap();
        assert_eq!(pt, share);
    }

    #[test]
    fn wrong_aad_fails() {
        let k_pin = [7u8; 32];
        let nonce = [1u8; 12];
        let uuid = [0xABu8; DRIVE_UUID_LEN];
        let bad = [0xCDu8; DRIVE_UUID_LEN];
        let blob = wrap_key_share(&k_pin, &nonce, &uuid, b"share").unwrap();
        assert!(unwrap_key_share(&k_pin, &blob, &bad).is_err());
    }

    #[test]
    fn meta_seal_open() {
        let k = [5u8; 32];
        let uuid = [9u8; DRIVE_UUID_LEN];
        let pt = b"SDMT-meta-plaintext";
        let ct = seal_meta(&k, &uuid, pt).unwrap();
        let out = open_meta(&k, &uuid, &ct).unwrap();
        assert_eq!(out, pt);
    }
}
