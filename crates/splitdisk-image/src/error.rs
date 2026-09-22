//! Error type for `splitdisk-image`.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(String),
    #[error("invalid parameter: {0}")]
    InvalidParameter(String),
    #[error("vendor blob pin mismatch for {role}: expected {expected}, got {got}")]
    BlobPinMismatch {
        role: String,
        expected: String,
        got: String,
    },
    #[error("format error: {0}")]
    Format(String),
    #[error("GPT error: {0}")]
    Gpt(String),
}
