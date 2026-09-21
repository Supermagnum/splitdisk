//! Serpent / Twofish / cascade stubs behind [`BulkCipher`].

use super::{AeadSuite, BulkCipher};
use crate::error::{Error, Result};

pub struct SerpentStub;
pub struct TwofishStub;
pub struct CascadeStub {
    pub suite: AeadSuite,
}

impl BulkCipher for SerpentStub {
    fn encrypt_segment(
        &self,
        _key: &[u8; 32],
        _nonce: &[u8; 12],
        _aad: &[u8],
        _plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        Err(Error::CipherStub("Serpent-256-CTR+Poly1305"))
    }

    fn decrypt_segment(
        &self,
        _key: &[u8; 32],
        _nonce: &[u8; 12],
        _aad: &[u8],
        _ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        Err(Error::CipherStub("Serpent-256-CTR+Poly1305"))
    }
}

impl BulkCipher for TwofishStub {
    fn encrypt_segment(
        &self,
        _key: &[u8; 32],
        _nonce: &[u8; 12],
        _aad: &[u8],
        _plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        Err(Error::CipherStub("Twofish-256-CTR+Poly1305"))
    }

    fn decrypt_segment(
        &self,
        _key: &[u8; 32],
        _nonce: &[u8; 12],
        _aad: &[u8],
        _ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        Err(Error::CipherStub("Twofish-256-CTR+Poly1305"))
    }
}

impl BulkCipher for CascadeStub {
    fn encrypt_segment(
        &self,
        _key: &[u8; 32],
        _nonce: &[u8; 12],
        _aad: &[u8],
        _plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        Err(Error::CipherStub(match self.suite {
            AeadSuite::CascadeCs => "cascade-cs",
            AeadSuite::CascadeCt => "cascade-ct",
            AeadSuite::CascadeTs => "cascade-ts",
            AeadSuite::CascadeCst => "cascade-cst",
            _ => "cascade",
        }))
    }

    fn decrypt_segment(
        &self,
        _key: &[u8; 32],
        _nonce: &[u8; 12],
        _aad: &[u8],
        _ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        self.encrypt_segment(_key, _nonce, _aad, _ciphertext)
    }
}
