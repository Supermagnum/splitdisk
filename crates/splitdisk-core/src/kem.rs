//! Classical KEM / ECDH trait for Mode A outer envelope (SPEC §4.1).
//!
//! Phase 2 does **not** implement Brainpool ECDH. RustCrypto `bp384`/`bp256`
//! gate curve arithmetic behind `wip-arithmetic-do-not-use`, and there is no
//! audited BrainpoolP512r1 crate. See `docs/OPEN-QUESTIONS.md` (a).
//!
//! Call sites that would wrap a session key via ECDH must use
//! [`UnimplementedKem`] (returns [`Error::KemNotAvailable`]) and the
//! PIN-derived key-wrap path only.

use crate::error::{Error, Result};
use zeroize::Zeroize;

/// Classical (non-PQ) key-encapsulation / ECDH interface for future Mode A.
///
/// Method signatures match the eventual design: encapsulate a 32-byte session
/// key to a peer public key, and decapsulate with a local secret.
pub trait ClassicalKem {
    /// Wrap `session_key` for transport to a peer identified by `peer_public`.
    ///
    /// Returns an opaque ciphertext blob (ephemeral public || wrapped key).
    fn encapsulate_session_key(
        &self,
        session_key: &[u8; 32],
        peer_public: &[u8],
    ) -> Result<Vec<u8>>;

    /// Recover a session key from `wrapped` using `local_secret`.
    fn decapsulate_session_key(&self, wrapped: &[u8], local_secret: &[u8]) -> Result<[u8; 32]>;
}

/// Stub KEM that always fails with [`Error::KemNotAvailable`].
#[derive(Debug, Default, Clone, Copy)]
pub struct UnimplementedKem;

impl ClassicalKem for UnimplementedKem {
    fn encapsulate_session_key(
        &self,
        session_key: &[u8; 32],
        _peer_public: &[u8],
    ) -> Result<Vec<u8>> {
        let mut sk = *session_key;
        sk.zeroize();
        Err(Error::KemNotAvailable)
    }

    fn decapsulate_session_key(&self, _wrapped: &[u8], local_secret: &[u8]) -> Result<[u8; 32]> {
        let mut wipe = local_secret.to_vec();
        wipe.zeroize();
        Err(Error::KemNotAvailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unimplemented_returns_kem_not_available() {
        let kem = UnimplementedKem;
        let err = kem.encapsulate_session_key(&[0u8; 32], &[0u8; 48]);
        assert!(matches!(err, Err(Error::KemNotAvailable)));
        let err = kem.decapsulate_session_key(&[0u8; 16], &[0u8; 48]);
        assert!(matches!(err, Err(Error::KemNotAvailable)));
    }
}
