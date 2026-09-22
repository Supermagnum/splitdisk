//! On-drive byte formats (versioned, length-prefixed, BLAKE3-framed).
//!
//! Normative proposals live in `docs/FORMAT.md`. Parsers never panic:
//! untrusted lengths are bounded and failures return [`Error::Format`].

mod chunk;
mod drive;
mod envelope;
mod meta;
mod pin_hash;
mod share_wrap;

pub use chunk::{parse_chunk_frame, write_chunk_frame, ChunkFrame, CHUNK_MAGIC};
pub use drive::{
    parse_drive_header, read_drive_sections, write_drive, write_drive_header, DriveHeader,
    DriveSections, DRIVE_HEADER_LEN, DRIVE_MAGIC, DRIVE_UUID_LEN,
};
pub use envelope::{parse_envelope_header, write_envelope_header, EnvelopeHeader, ENVELOPE_MAGIC};
pub use meta::{parse_meta, read_meta, write_meta, MetaPlaintext, META_MAGIC, META_PLAINTEXT_LEN};
pub use pin_hash::{
    parse_pin_hash, write_pin_hash, PinHashRecord, DEFAULT_ARGON2_M_KIB, DEFAULT_ARGON2_P_COST,
    DEFAULT_ARGON2_T_COST, PIN_HASH_LEN, PIN_HASH_MAGIC,
};
pub use share_wrap::{
    open_meta, parse_key_wrap, pin_aead_aad, seal_meta, unwrap_key_share, wrap_key_share,
    write_key_wrap, KeyWrapBlob, KEY_WRAP_HEADER_LEN, KEY_WRAP_MAGIC,
};

/// Shared format version for Phase 1/2 proposals.
pub const FORMAT_VERSION: u16 = 1;

/// Hard cap on any length-prefixed field read from untrusted media (64 MiB).
pub const MAX_FRAMED_LEN: u64 = 64 * 1024 * 1024;
