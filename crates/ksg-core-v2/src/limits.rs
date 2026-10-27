//! Limits. Spec v2 §14.
//!
//! A verifier that takes any size of input takes on any amount of work. Every
//! limit here is checked **before** the work it bounds — before parsing,
//! before a signature is verified, before a path is walked — and an input
//! past a limit is refused, never truncated.

use crate::error::Invalid;

/// Bytes of one core document.
pub const MAX_DOC_BYTES: usize = 64 * 1024;
/// Bytes of one journal export.
pub const MAX_EXPORT_BYTES: usize = 8 * 1024 * 1024;
/// Signatures in one document.
pub const MAX_SIGNATURES: usize = 8;
/// Anchors of one subject.
pub const MAX_ANCHORS: usize = 16;
/// Siblings on one Merkle path.
pub const MAX_PROOF_DEPTH: usize = 64;
/// Links of the key-inclusion chain.
pub const MAX_KEY_INCLUSIONS: usize = 1024;
/// Records of one status section. A container's life is a few dozen changes;
/// the ceiling is far above that and still bounds a verifier's work (§14).
pub const MAX_STATUS_RECORDS: usize = 1024;
/// The largest integer a signed document may carry: 2^53 − 1 (spec v2 §3.2).
pub const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// Refuses more than `max` items of `what`.
///
/// # Errors
///
/// [`Invalid::Limit`] past the limit.
pub fn at_most(n: usize, max: usize, what: &'static str) -> Result<(), Invalid> {
    if n > max {
        Err(Invalid::Limit(what))
    } else {
        Ok(())
    }
}

/// Parses a core document from bytes: the size first, then a strict parse.
///
/// # Errors
///
/// [`Invalid::Limit`] past [`MAX_DOC_BYTES`]; [`Invalid::Schema`] for bytes
/// that are not the document (an unknown field included — every core
/// document denies them).
pub fn parse_doc<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, Invalid> {
    at_most(bytes.len(), MAX_DOC_BYTES, "document size")?;
    serde_json::from_slice(bytes).map_err(|_| Invalid::Schema("the bytes are not this document"))
}
