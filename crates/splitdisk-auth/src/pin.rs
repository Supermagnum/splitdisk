//! PIN validation and Argon2id hashing (SPEC §5.2).

use argon2::{Algorithm, Argon2, Params, Version};
use splitdisk_core::format::{
    PinHashRecord, DEFAULT_ARGON2_M_KIB, DEFAULT_ARGON2_P_COST, DEFAULT_ARGON2_T_COST,
};
use splitdisk_core::kdf::INFO_PIN;
use splitdisk_core::rng::SecureRng;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Minimum alphanumeric PIN length (SPEC §5.2).
pub const MIN_PIN_LEN: usize = 5;
/// Default / minimum configurable attempt limit.
pub const MIN_PIN_ATTEMPTS: u32 = 3;
/// Maximum configurable attempt limit.
pub const MAX_PIN_ATTEMPTS: u32 = 10;

/// Argon2id parameters (memory in KiB).
#[derive(Debug, Clone, Copy)]
pub struct Argon2Params {
    pub m_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            m_kib: DEFAULT_ARGON2_M_KIB,
            t_cost: DEFAULT_ARGON2_T_COST,
            p_cost: DEFAULT_ARGON2_P_COST,
        }
    }
}

impl Argon2Params {
    /// Reduced cost for unit/integration tests (never for production enrollment).
    /// Only available with the `test-hooks` Cargo feature.
    #[cfg(feature = "test-hooks")]
    pub fn for_tests() -> Self {
        Self {
            m_kib: 8,
            t_cost: 1,
            p_cost: 1,
        }
    }
}

/// PIN-related errors (generic externally where required).
#[derive(Debug, Error)]
pub enum PinError {
    #[error("PIN must be at least {MIN_PIN_LEN} alphanumeric characters")]
    TooShort,
    #[error("PIN must contain only alphanumeric characters")]
    NotAlphanumeric,
    #[error("authentication failed")]
    AuthFailed,
    #[error("argon2 parameter error")]
    Argon2Params,
    #[error("RNG failure")]
    Rng,
}

/// Validate PIN at the input boundary **before** hashing (Rule 10 / SPEC §5.2).
pub fn validate_pin(pin: &str) -> Result<(), PinError> {
    if pin.len() < MIN_PIN_LEN {
        return Err(PinError::TooShort);
    }
    if !pin.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(PinError::NotAlphanumeric);
    }
    Ok(())
}

/// Hash a validated PIN into a [`PinHashRecord`] with a fresh salt.
pub fn hash_pin(
    pin: &str,
    params: Argon2Params,
    rng: &mut dyn SecureRng,
) -> Result<PinHashRecord, PinError> {
    validate_pin(pin)?;
    let mut salt = [0u8; 16];
    rng.fill(&mut salt).map_err(|_| PinError::Rng)?;
    let output = argon2id(pin.as_bytes(), &salt, params)?;
    Ok(PinHashRecord::new(
        params.m_kib,
        params.t_cost,
        params.p_cost,
        salt,
        output,
    ))
}

/// Verify PIN against a stored record (constant-time compare of Argon2 output).
pub fn verify_pin(pin: &str, record: &PinHashRecord) -> Result<[u8; 32], PinError> {
    validate_pin(pin)?;
    let params = Argon2Params {
        m_kib: record.m_cost,
        t_cost: record.t_cost,
        p_cost: record.p_cost,
    };
    let mut computed = argon2id(pin.as_bytes(), &record.salt, params)?;
    let ok = bool::from(computed.ct_eq(&record.argon2id_output));
    if !ok {
        computed.zeroize();
        return Err(PinError::AuthFailed);
    }
    Ok(computed)
}

/// Derive `K_pin` from Argon2id output via Phase 1 KDF (`cess-pin-v1`).
pub fn derive_k_pin(argon2_output: &[u8; 32]) -> zeroize::Zeroizing<[u8; 32]> {
    splitdisk_core::kdf::derive_key_owned(argon2_output, INFO_PIN)
}

fn argon2id(password: &[u8], salt: &[u8; 16], params: Argon2Params) -> Result<[u8; 32], PinError> {
    let p = Params::new(params.m_kib, params.t_cost, params.p_cost, Some(32))
        .map_err(|_| PinError::Argon2Params)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut out)
        .map_err(|_| PinError::Argon2Params)?;
    Ok(out)
}

/// Zeroizing wrapper around a PIN string buffer owned by callers who need wipe.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PinBytes(pub Vec<u8>);

#[cfg(test)]
mod tests {
    use super::*;
    use splitdisk_core::rng::SeededRng;

    #[test]
    fn rejects_short_and_non_alnum() {
        assert!(matches!(validate_pin("ab12"), Err(PinError::TooShort)));
        assert!(matches!(
            validate_pin("abc!1"),
            Err(PinError::NotAlphanumeric)
        ));
        assert!(validate_pin("abc12").is_ok());
    }

    #[test]
    #[cfg(feature = "test-hooks")]
    fn hash_verify_roundtrip() {
        let mut rng = SeededRng::from_seed([1u8; 32]);
        let rec = hash_pin("secret1", Argon2Params::for_tests(), &mut rng).unwrap();
        let out = verify_pin("secret1", &rec).unwrap();
        assert!(bool::from(out.ct_eq(&rec.argon2id_output)));
        assert!(matches!(
            verify_pin("wrong1", &rec),
            Err(PinError::AuthFailed)
        ));
    }

    #[test]
    #[cfg(feature = "test-hooks")]
    fn k_pin_domain_separated() {
        let mut rng = SeededRng::from_seed([2u8; 32]);
        let rec = hash_pin("pinok1", Argon2Params::for_tests(), &mut rng).unwrap();
        let k = derive_k_pin(&rec.argon2id_output);
        assert_ne!(&*k, &rec.argon2id_output);
    }
}
