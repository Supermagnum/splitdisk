#![forbid(unsafe_code)]
//! PIN entry, Argon2id hashing, and software attempt limiting.
//!
//! Biometric and Galdralag paths are out of Phase 2 scope.

mod attempts;
mod pin;

pub use attempts::{AttemptLimiter, AttemptPolicy, Clock, InstantClock, MockClock};
pub use pin::{
    derive_k_pin, hash_pin, validate_pin, verify_pin, Argon2Params, PinError, MAX_PIN_ATTEMPTS,
    MIN_PIN_ATTEMPTS, MIN_PIN_LEN,
};
