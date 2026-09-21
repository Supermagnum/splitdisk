//! Key derivation wrappers.
//!
//! Spec §4.1 says "HKDF-BLAKE3 (RFC 5869 structure, HMAC-BLAKE3 as PRF)".
//! That construction is not a standard crate API. Phase 1 uses BLAKE3's
//! native `derive_key` with the CESS info strings as context. See
//! `docs/OPEN-QUESTIONS.md` entry (b).

use zeroize::Zeroize;

/// CESS info string for KEM combiner (§4.1).
pub const INFO_KEM: &str = "cess-kem-v1";
/// CESS info string for PIN wrap (§5.2).
pub const INFO_PIN: &str = "cess-pin-v1";
/// CESS info string for Mode A outer envelope (§4.1).
pub const INFO_OUTER_ENVELOPE: &str = "cess-outer-envelope-v1";

/// Domain-separated 32-byte key derivation.
///
/// `info` must be one of the CESS info strings (or a documented extension).
/// Input key material is not zeroized here; callers own that responsibility.
pub fn derive_key(ikm: &[u8], info: &str) -> [u8; 32] {
    blake3::derive_key(info, ikm)
}

/// Derive then immediately allow caller to wrap in zeroizing types.
pub fn derive_key_owned(ikm: &[u8], info: &str) -> zeroize::Zeroizing<[u8; 32]> {
    zeroize::Zeroizing::new(derive_key(ikm, info))
}

/// Explicit wipe helper for temporary IKM buffers owned by the caller.
pub fn wipe_ikm(buf: &mut [u8]) {
    buf.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_is_deterministic() {
        let ikm = b"test-ikm-material-32-bytes-pad!!";
        let a = derive_key(ikm, INFO_KEM);
        let b = derive_key(ikm, INFO_KEM);
        assert_eq!(a, b);
    }

    #[test]
    fn info_strings_domain_separate() {
        let ikm = b"test-ikm-material-32-bytes-pad!!";
        let a = derive_key(ikm, INFO_KEM);
        let b = derive_key(ikm, INFO_PIN);
        let c = derive_key(ikm, INFO_OUTER_ENVELOPE);
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    #[test]
    fn different_ikm_different_out() {
        let a = derive_key(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", INFO_KEM);
        let b = derive_key(b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", INFO_KEM);
        assert_ne!(a, b);
    }
}
