//! Canonical serialization and the signing rule. Specification §3, §4.1. **Part 1.**
//!
//! A signature is computed over the bytes of the JCS canonical form (RFC 8785).
//! JCS comes from a crate and is not written by hand: a canonicalizer of one's
//! own is a separate implementation of escaping and number-formatting rules —
//! that is, a source of divergence between verifiers.
//!
//! An absent field and a field whose value is `null` are **different
//! documents**. Optional fields are omitted when absent; every `Option` in a
//! document requires `#[serde(skip_serializing_if = "Option::is_none")]`. A
//! missing attribute is a defect, and it is caught by a test, not by review.

use serde::Serialize;
use serde_json::Value;

use crate::error::Invalid;

/// A document for which the signing rule is defined.
///
/// Implementing the trait is the only way into [`canonical_bytes`], and
/// [`canonical_bytes`] is the only entry to signing: calling
/// `serde_json::to_vec` directly is not permitted inside this crate.
pub trait Signable: Serialize {
    /// The value of the document's `type` field. Used for diagnostics and to
    /// check that the document signed is of the expected kind.
    const DOC_TYPE: &'static str;

    /// The signing view: the document **without** the `signatures` field.
    ///
    /// **Only** `signatures` is excluded from the signing view. Everything else
    /// is included, optional fields among them when present: a signature that
    /// does not cover part of a document leaves that part substitutable.
    fn signing_view(&self) -> Value {
        let mut v = serde_json::to_value(self).unwrap_or(Value::Null);
        if let Some(obj) = v.as_object_mut() {
            obj.remove("signatures");
        }
        v
    }
}

/// Every number is an integer in 0…2^53 − 1 (spec v2 §3.2): the only numbers
/// RFC 8785 serializes identically in every language. A fraction, a negative
/// number or a larger integer would canonicalize to bytes another
/// implementation does not reproduce, and its signature would not verify
/// there.
fn safe_numbers(v: &Value) -> Result<(), Invalid> {
    match v {
        Value::Number(n) => match n.as_u64() {
            Some(x) if x <= crate::limits::MAX_SAFE_INTEGER => Ok(()),
            _ => Err(Invalid::Number),
        },
        Value::Array(a) => a.iter().try_for_each(safe_numbers),
        Value::Object(o) => o.values().try_for_each(safe_numbers),
        _ => Ok(()),
    }
}

/// The canonical bytes of a document's signing view.
///
/// # Errors
///
/// [`Invalid::Canonicalization`] if the view is not a JSON object, or does not
/// canonicalize under RFC 8785.
pub fn canonical_bytes<T: Signable>(doc: &T) -> Result<Vec<u8>, Invalid> {
    canonicalize(&doc.signing_view())
}

/// The canonical bytes of an arbitrary JSON object.
///
/// Needed where what is signed is not a whole document but a part of one (a log
/// leaf is an act's canonical form, §11.1).
///
/// # Errors
///
/// [`Invalid::Canonicalization`] if the value is not an object, or does not
/// canonicalize.
pub fn canonicalize(value: &Value) -> Result<Vec<u8>, Invalid> {
    if !value.is_object() {
        return Err(Invalid::Canonicalization);
    }
    safe_numbers(value)?;
    serde_json_canonicalizer::to_vec(value).map_err(|_| Invalid::Canonicalization)
}

/// A document's hash, taken over its canonical signing form.
///
/// This is the value by which documents refer to one another (`binding`,
/// `prev_closure`, `parents[].act`).
///
/// # Errors
///
/// [`Invalid::Canonicalization`] if the document does not canonicalize.
pub fn doc_hash<T: Signable>(doc: &T) -> Result<crate::crypto::hash::Hash, Invalid> {
    Ok(crate::crypto::hash::Hash::sha256(&canonical_bytes(doc)?))
}

/// The part of verification common to every document: version, type, signature
/// coverage.
///
/// Public because it is the envelope **rule**, not a helper. A crate defining a
/// signed document of its own — `ksg-custody` and its succession certificates
/// are the first — needs exactly this check, and leaving it private would mean
/// every such crate rewriting it. Rewritten rules drift, and this one decides
/// whether a signature counts.
///
/// # Errors
///
/// [`Invalid::Schema`] on a foreign version or a foreign `type`,
/// [`Invalid::Signature`] on an uncovered profile.
pub fn check_envelope<T: Signable>(
    doc: &T,
    v: u32,
    doc_type: &str,
    sigs: &crate::crypto::sign::SignatureSet,
    keys: &crate::crypto::sign::KeySet,
    profile: &crate::crypto::sign::Profile,
) -> Result<(), Invalid> {
    crate::version::check(v)?;
    crate::limits::at_most(sigs.len(), crate::limits::MAX_SIGNATURES, "signatures")?;
    if doc_type != T::DOC_TYPE {
        return Err(Invalid::Schema(
            "the type field does not match the document",
        ));
    }
    sigs.verify(&canonical_bytes(doc)?, keys, profile)
}
