//! Injectable CSPRNG trait. Production uses the OS; tests may seed.

use crate::error::{Error, Result};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use zeroize::Zeroize;

/// Cryptographic RNG used for all key material and share polynomials.
///
/// Production code must use [`OsRng`]. Tests may use [`SeededRng`], but a
/// regression test proves two production runs differ (see `tests/rng_regression.rs`).
pub trait SecureRng {
    fn fill(&mut self, dest: &mut [u8]) -> Result<()>;
}

/// OS CSPRNG via `getrandom`.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsRng;

impl SecureRng for OsRng {
    fn fill(&mut self, dest: &mut [u8]) -> Result<()> {
        getrandom::getrandom(dest).map_err(|_| Error::Rng("getrandom failed"))
    }
}

impl RngCore for OsRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        getrandom::getrandom(&mut b).expect("OS CSPRNG unavailable");
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        getrandom::getrandom(&mut b).expect("OS CSPRNG unavailable");
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::getrandom(dest).expect("OS CSPRNG unavailable");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), rand_core::Error> {
        getrandom::getrandom(dest).map_err(rand_core::Error::from)
    }
}

impl CryptoRng for OsRng {}

/// Seeded ChaCha20 RNG for tests only. Stores the seed so it can be zeroized.
pub struct SeededRng {
    seed: [u8; 32],
    inner: ChaCha20Rng,
}

impl SeededRng {
    /// Create from a 32-byte seed. Do not use for production key material.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            seed,
            inner: ChaCha20Rng::from_seed(seed),
        }
    }
}

impl Drop for SeededRng {
    fn drop(&mut self) {
        self.seed.zeroize();
        // Re-seed from zeros to scrub ChaCha state as far as the API allows.
        self.inner = ChaCha20Rng::from_seed([0u8; 32]);
    }
}

impl SecureRng for SeededRng {
    fn fill(&mut self, dest: &mut [u8]) -> Result<()> {
        self.inner.fill_bytes(dest);
        Ok(())
    }
}

impl RngCore for SeededRng {
    fn next_u32(&mut self) -> u32 {
        self.inner.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.inner.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.inner.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), rand_core::Error> {
        self.inner.try_fill_bytes(dest)
    }
}

impl CryptoRng for SeededRng {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeded_is_deterministic() {
        let mut a = SeededRng::from_seed([7u8; 32]);
        let mut b = SeededRng::from_seed([7u8; 32]);
        let mut xa = [0u8; 16];
        let mut xb = [0u8; 16];
        SecureRng::fill(&mut a, &mut xa).unwrap();
        SecureRng::fill(&mut b, &mut xb).unwrap();
        assert_eq!(xa, xb);
    }

    #[test]
    fn os_rng_fills() {
        let mut rng = OsRng;
        let mut buf = [0u8; 32];
        SecureRng::fill(&mut rng, &mut buf).unwrap();
        assert!(buf.iter().any(|&b| b != 0));
    }
}
