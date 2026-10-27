//! SHA-256 and multihash. Specification §4. **Part 1** — implemented in full.
//!
//! The representation is a multihash with the `1220` prefix: code `0x12`
//! (sha2-256) and length `0x20` (32 bytes), then the digest itself; all in
//! lowercase hex. Parsing MUST reject an unknown code and a length mismatch.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::error::Invalid;

/// The multihash code for sha2-256.
const MULTIHASH_CODE: u8 = 0x12;
/// The digest length in bytes.
const DIGEST_LEN: usize = 32;

/// A SHA-256 digest.
///
/// Serialized as the multihash string `1220<64 hex characters>`; comparison is
/// byte-wise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hash([u8; DIGEST_LEN]);

impl Hash {
    /// The digest of arbitrary bytes.
    #[must_use]
    pub fn sha256(data: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update(data);
        Self(h.finalize().into())
    }

    /// The digest of two pieces concatenated, with no intermediate allocation.
    ///
    /// Needed by the tree (§11.1), where a node hash is taken over `0x01 || l || r`.
    #[must_use]
    pub fn sha256_parts(parts: &[&[u8]]) -> Self {
        let mut h = Sha256::new();
        for p in parts {
            h.update(p);
        }
        Self(h.finalize().into())
    }

    /// SHA-256 over a **sequence of fields**, each preceded by its length.
    ///
    /// # Why this exists beside `sha256_parts`
    ///
    /// Plain concatenation is ambiguous: `("ab", "c")` and `("a", "bc")` hash to
    /// the same value. Where the parts are a fixed-size hash and a fixed tag
    /// that is harmless; where any part is variable-length — a URI, a reason,
    /// an optional field that is sometimes absent and sometimes 32 bytes — two
    /// different subjects can produce one digest, and a signature over one
    /// becomes a signature over the other (security audit of 2026-09-13,
    /// finding 11).
    ///
    /// Each field goes in as a 4-byte big-endian length followed by its bytes,
    /// so the boundaries are part of what is hashed. A field longer than
    /// `u32::MAX` is not representable and saturates — it cannot arise from any
    /// document this crate accepts.
    #[must_use]
    pub fn sha256_fields(fields: &[&[u8]]) -> Self {
        let mut h = Sha256::new();
        for f in fields {
            let len = u32::try_from(f.len()).unwrap_or(u32::MAX);
            h.update(len.to_be_bytes());
            h.update(f);
        }
        Self(h.finalize().into())
    }

    /// The raw 32 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; DIGEST_LEN] {
        &self.0
    }

    /// Construction from a ready digest.
    #[must_use]
    pub const fn from_bytes(b: [u8; DIGEST_LEN]) -> Self {
        Self(b)
    }

    /// The multihash representation: `1220` followed by the digest in hex.
    #[must_use]
    pub fn to_multihash(&self) -> String {
        let mut s = String::with_capacity(4 + DIGEST_LEN * 2);
        s.push_str("1220");
        s.push_str(&hex::encode(self.0));
        s
    }

    /// Parses a multihash string.
    ///
    /// # Errors
    ///
    /// [`Invalid::Schema`] if the string is not hex, if the code differs from
    /// `0x12`, or if the digest length differs from 32. Specification §4:
    /// silently accepting another algorithm would mean two implementations
    /// agreeing on different trees.
    pub fn from_multihash(s: &str) -> Result<Self, Invalid> {
        // Lower case only. `hex::decode` accepts both, so `"1220AB…"` and
        // `"1220ab…"` gave **one** `Hash` — while remaining two different
        // strings in the document, with two different canonical forms and two
        // different signatures. A reference by hash must name one document
        // (security audit of 2026-09-13, finding 19).
        if s.bytes().any(|c| c.is_ascii_uppercase()) {
            return Err(Invalid::Schema("multihash: hex must be lower case"));
        }
        let raw = hex::decode(s).map_err(|_| Invalid::Schema("multihash: not hex"))?;
        let [code, len, rest @ ..] = raw.as_slice() else {
            return Err(Invalid::Schema("multihash: shorter than the prefix"));
        };
        if *code != MULTIHASH_CODE {
            return Err(Invalid::Schema("multihash: code is not sha2-256"));
        }
        if usize::from(*len) != DIGEST_LEN || rest.len() != DIGEST_LEN {
            return Err(Invalid::Schema("multihash: length is not 32 bytes"));
        }
        let mut out = [0u8; DIGEST_LEN];
        out.copy_from_slice(rest);
        Ok(Self(out))
    }
}

impl core::fmt::Display for Hash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_multihash())
    }
}

impl Serialize for Hash {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_multihash())
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::from_multihash(&s).map_err(serde::de::Error::custom)
    }
}
