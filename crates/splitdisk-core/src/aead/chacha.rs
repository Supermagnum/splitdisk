//! ChaCha20-Poly1305 segment cipher (RFC 8439).

use super::BulkCipher;
use crate::error::{Error, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use zeroize::Zeroize;

pub struct ChaCha20Poly1305Cipher;

impl BulkCipher for ChaCha20Poly1305Cipher {
    fn encrypt_segment(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        let n = Nonce::from_slice(nonce);
        cipher
            .encrypt(
                n,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| Error::AeadAuth)
    }

    fn decrypt_segment(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        let n = Nonce::from_slice(nonce);
        let out = cipher
            .decrypt(
                n,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| Error::AeadAuth)?;
        Ok(out)
    }
}

/// Known-answer helper used by RFC 8439 tests.
pub fn encrypt_detached_kat(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let c = ChaCha20Poly1305Cipher;
    let ct = c.encrypt_segment(key, nonce, aad, plaintext)?;
    let mut key_copy = *key;
    key_copy.zeroize();
    Ok(ct)
}
