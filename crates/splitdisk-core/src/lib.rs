#![forbid(unsafe_code)]
//! SplitDisk core: crypto wrappers, streaming RS/SSS, and on-drive format parsers.
//!
//! Phase 1–2: RNG, segmented AEAD, KDF, Shamir, streaming Reed-Solomon,
//! BLAKE3-framed chunks, file carriers, PIN key-wrap, and ClassicalKem stub.
//! See `docs/SPEC.md` and `docs/OPEN-QUESTIONS.md`.

pub mod aead;
pub mod carrier;
pub mod error;
pub mod format;
pub mod kdf;
pub mod kem;
pub mod path;
pub mod rng;
pub mod rs;
pub mod sss;

pub use aead::{
    decrypt_stream, decrypt_stream_with_progress, encrypt_stream, AeadKey, AeadSuite, BulkCipher,
    DecryptSegmentProgress, DEFAULT_SEGMENT_SIZE, SUITE_CHACHA20,
};
pub use carrier::{FileCarrier, ShareCarrier};
pub use error::{Error, Result};
pub use format::{
    open_meta, parse_chunk_frame, parse_drive_header, parse_envelope_header, parse_key_wrap,
    parse_meta, parse_pin_hash, read_drive_sections, seal_meta, unwrap_key_share, wrap_key_share,
    write_chunk_frame, write_drive, write_key_wrap, write_meta, write_pin_hash, ChunkFrame,
    DriveHeader, DriveSections, EnvelopeHeader, KeyWrapBlob, MetaPlaintext, PinHashRecord,
    CHUNK_MAGIC, DEFAULT_ARGON2_M_KIB, DEFAULT_ARGON2_P_COST, DEFAULT_ARGON2_T_COST,
    DRIVE_HEADER_LEN, DRIVE_MAGIC, DRIVE_UUID_LEN, ENVELOPE_MAGIC, FORMAT_VERSION, KEY_WRAP_MAGIC,
    META_MAGIC, META_PLAINTEXT_LEN, PIN_HASH_LEN, PIN_HASH_MAGIC,
};
pub use kdf::{derive_key, derive_key_owned, INFO_KEM, INFO_OUTER_ENVELOPE, INFO_PIN};
pub use kem::{ClassicalKem, UnimplementedKem};
pub use path::validate_carrier_path;
pub use rng::{OsRng, SecureRng, SeededRng};
pub use rs::{join_stripes, split_stripes, DEFAULT_STRIPE_SIZE};
pub use sss::{
    combine_session_key, split_session_key, validate_threshold, KeyShare, SessionKey,
    SESSION_KEY_LEN,
};
