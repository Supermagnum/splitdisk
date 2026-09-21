#![forbid(unsafe_code)]
//! SplitDisk core: crypto wrappers, streaming RS/SSS, and on-drive format parsers.
//!
//! Phase 1 scope: RNG, segmented AEAD, KDF, Shamir, streaming Reed-Solomon,
//! BLAKE3-framed chunks, and file carriers. See `docs/SPEC.md` and
//! `docs/OPEN-QUESTIONS.md`.

pub mod aead;
pub mod carrier;
pub mod error;
pub mod format;
pub mod kdf;
pub mod path;
pub mod rng;
pub mod rs;
pub mod sss;

pub use aead::{decrypt_stream, encrypt_stream, AeadSuite, BulkCipher, DEFAULT_SEGMENT_SIZE};
pub use carrier::{FileCarrier, ShareCarrier};
pub use error::{Error, Result};
pub use format::{
    parse_chunk_frame, parse_envelope_header, parse_meta, write_chunk_frame, ChunkFrame,
    EnvelopeHeader, MetaPlaintext, CHUNK_MAGIC, ENVELOPE_MAGIC, FORMAT_VERSION, META_MAGIC,
};
pub use kdf::{derive_key, INFO_KEM, INFO_OUTER_ENVELOPE, INFO_PIN};
pub use path::validate_carrier_path;
pub use rng::{OsRng, SecureRng, SeededRng};
pub use rs::{join_stripes, split_stripes, DEFAULT_STRIPE_SIZE};
pub use sss::{combine_session_key, split_session_key, SessionKey, SESSION_KEY_LEN};
