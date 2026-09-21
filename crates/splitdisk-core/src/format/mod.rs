//! On-drive byte formats (versioned, length-prefixed, BLAKE3-framed).
//!
//! Normative proposals live in `docs/FORMAT.md`. Parsers never panic:
//! untrusted lengths are bounded and failures return [`Error::Format`].

mod chunk;
mod envelope;
mod meta;

pub use chunk::{parse_chunk_frame, write_chunk_frame, ChunkFrame, CHUNK_MAGIC};
pub use envelope::{parse_envelope_header, write_envelope_header, EnvelopeHeader, ENVELOPE_MAGIC};
pub use meta::{parse_meta, write_meta, MetaPlaintext, META_MAGIC};

/// Shared format version for Phase 1 proposals.
pub const FORMAT_VERSION: u16 = 1;

/// Hard cap on any length-prefixed field read from untrusted media (64 MiB).
pub const MAX_FRAMED_LEN: u64 = 64 * 1024 * 1024;
