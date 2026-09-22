//! Typed errors for splitdisk-core. Parsers never panic on untrusted input.

use std::io;
use thiserror::Error;

/// Crate-wide result type.
pub type Result<T> = std::result::Result<T, Error>;

/// Explicit error enum; no stringly-typed failures for crypto/format paths.
#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("invalid parameter: {0}")]
    InvalidParameter(&'static str),

    #[error("threshold k must satisfy 2 <= k <= n <= 255 (got k={k}, n={n})")]
    InvalidThreshold { k: usize, n: usize },

    #[error("not enough shares: need {need}, have {have}")]
    NotEnoughShares { need: usize, have: usize },

    #[error("secret sharing failed: {0}")]
    SecretSharing(String),

    #[error("reed-solomon failed: {0}")]
    ReedSolomon(String),

    #[error("AEAD authentication failed")]
    AeadAuth,

    #[error("AEAD truncation: final segment flag missing or inconsistent")]
    AeadTruncation,

    #[error("unsupported bulk cipher suite id {0:#06x}")]
    UnsupportedSuite(u16),

    #[error("bulk cipher not implemented in this phase: {0}")]
    CipherStub(&'static str),

    #[error("format parse error: {0}")]
    Format(&'static str),

    #[error("length bound exceeded: declared {declared}, max {max}")]
    LengthBound { declared: u64, max: u64 },

    #[error("integrity check failed (BLAKE3 mismatch)")]
    Integrity,

    #[error("path under /dev rejected (enable feature raw-devices for block devices)")]
    RawDeviceRejected,

    #[error("RNG failure: {0}")]
    Rng(&'static str),

    #[error("unexpected end of input")]
    UnexpectedEof,

    #[error("output refused: operation failed before any plaintext was emitted")]
    OutputRefused,

    #[error(
        "classical KEM / ECDH not available (Brainpool arithmetic gated; see OPEN-QUESTIONS (a))"
    )]
    KemNotAvailable,

    #[error("authentication failed")]
    AuthFailed,

    #[error("PIN attempt limit reached; cool-down required")]
    AttemptLimitReached,

    #[error("this drive has already been read; please insert a different one")]
    DuplicateCarrier,

    #[error("checkpoint journal error: {0}")]
    Journal(&'static str),
}

impl Error {
    /// Map vsss-rs failures without leaking share material.
    pub(crate) fn from_vsss(e: impl std::fmt::Display) -> Self {
        Self::SecretSharing(e.to_string())
    }

    pub(crate) fn from_rs(e: impl std::fmt::Display) -> Self {
        Self::ReedSolomon(e.to_string())
    }
}
