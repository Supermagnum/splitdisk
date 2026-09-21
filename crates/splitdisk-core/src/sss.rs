//! Shamir secret sharing for the 32-byte session key over GF(2^8).
//!
//! Uses `vsss-rs` `Gf256`. Reduction polynomial matches AES/CESS
//! (`x^8 + x^4 + x^3 + x + 1`, reduction byte `0x1b`). See OPEN-QUESTIONS (c).
//!
//! API note: vsss-rs 5.x exposes `split_array` / `combine_array` (not
//! `split_bytes`).

use crate::error::{Error, Result};
use crate::rng::SecureRng;
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use vsss_rs::Gf256;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Session key length in bytes.
pub const SESSION_KEY_LEN: usize = 32;

/// 32-byte session key; zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SessionKey(pub [u8; SESSION_KEY_LEN]);

impl SessionKey {
    pub fn new(bytes: [u8; SESSION_KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn generate(rng: &mut dyn SecureRng) -> Result<Self> {
        let mut bytes = [0u8; SESSION_KEY_LEN];
        rng.fill(&mut bytes)?;
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; SESSION_KEY_LEN] {
        &self.0
    }

    /// Constant-time equality.
    pub fn ct_eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

/// One opaque share blob from vsss-rs (identifier + share body).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KeyShare(pub Vec<u8>);

impl KeyShare {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Validate `2 <= k <= n <= 255`.
pub fn validate_threshold(k: usize, n: usize) -> Result<()> {
    if k < 2 || k > n || n > 255 {
        return Err(Error::InvalidThreshold { k, n });
    }
    Ok(())
}

/// Adapter so injectable [`SecureRng`] satisfies vsss-rs RNG bounds.
struct RngAdapter<'a> {
    inner: &'a mut dyn SecureRng,
}

impl RngCore for RngAdapter<'_> {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.inner.fill(&mut b).expect("RNG failure in SSS");
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.inner.fill(&mut b).expect("RNG failure in SSS");
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.inner.fill(dest).expect("RNG failure in SSS");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), rand_core::Error> {
        self.inner
            .fill(dest)
            .map_err(|_| rand_core::Error::from(core::num::NonZeroU32::new(1).unwrap()))
    }
}

impl CryptoRng for RngAdapter<'_> {}

/// Split a 32-byte session key into `n` shares, threshold `k`.
pub fn split_session_key(
    secret: &SessionKey,
    k: usize,
    n: usize,
    rng: &mut dyn SecureRng,
) -> Result<Vec<KeyShare>> {
    validate_threshold(k, n)?;
    let mut adapter = RngAdapter { inner: rng };
    let shares =
        Gf256::split_array(k, n, secret.as_bytes(), &mut adapter).map_err(Error::from_vsss)?;
    Ok(shares.into_iter().map(KeyShare).collect())
}

/// Combine any `k` shares to recover the session key.
pub fn combine_session_key(shares: &[KeyShare]) -> Result<SessionKey> {
    if shares.is_empty() {
        return Err(Error::NotEnoughShares { need: 2, have: 0 });
    }
    let owned: Vec<Vec<u8>> = shares.iter().map(|s| s.as_bytes().to_vec()).collect();
    let recovered = Gf256::combine_array(&owned).map_err(Error::from_vsss)?;
    if recovered.len() != SESSION_KEY_LEN {
        return Err(Error::SecretSharing(
            "recovered secret has unexpected length".into(),
        ));
    }
    let mut bytes = [0u8; SESSION_KEY_LEN];
    bytes.copy_from_slice(&recovered);
    Ok(SessionKey(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::SeededRng;

    #[test]
    fn threshold_validation() {
        assert!(validate_threshold(2, 2).is_ok());
        assert!(validate_threshold(2, 255).is_ok());
        assert!(validate_threshold(1, 2).is_err());
        assert!(validate_threshold(3, 2).is_err());
        assert!(validate_threshold(2, 256).is_err());
    }

    #[test]
    fn split_combine_roundtrip() {
        let mut rng = SeededRng::from_seed([42u8; 32]);
        let secret = SessionKey::new([0x5Au8; 32]);
        let shares = split_session_key(&secret, 3, 5, &mut rng).unwrap();
        assert_eq!(shares.len(), 5);
        let recovered = combine_session_key(&shares[0..3]).unwrap();
        assert!(secret.ct_eq(&recovered));
        let recovered2 = combine_session_key(&shares[2..5]).unwrap();
        assert!(secret.ct_eq(&recovered2));
    }

    #[test]
    fn k_minus_one_does_not_equal_secret() {
        let mut rng = SeededRng::from_seed([99u8; 32]);
        let secret = SessionKey::new([0x11u8; 32]);
        let shares = split_session_key(&secret, 3, 5, &mut rng).unwrap();
        if let Ok(fake) = combine_session_key(&shares[0..2]) {
            assert!(!secret.ct_eq(&fake));
        }
    }
}
