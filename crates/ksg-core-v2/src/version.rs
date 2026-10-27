//! Core versioning. Spec v2 §13.
//!
//! Core v2 issues and verifies **major version 3** only. Documents of majors 1
//! and 2 are verified by core v1, which is kept unchanged (architecture v0.3
//! §5.3: "old documents are verified by the old code, kept in the
//! implementation indefinitely"). The two cores share no code.
//!
//! The §14 rules fall into two **different** ranges that are easy to conflate:
//!
//! - which versions an implementation can **verify** — every previously issued
//!   major version, otherwise history is devalued at each release;
//! - which version it **issues** — only the current one.
//!
//! One `SUPPORTED_V` for both roles looks sufficient exactly until the second
//! major version appears, after which the implementation either stops reading
//! old documents or starts issuing obsolete ones. So the roles are separated
//! here, rather than when it becomes necessary.

use crate::error::Invalid;

/// The earliest major version the implementation is obliged to verify.
///
/// There is no version `0`: numbering starts at the first one issued.
pub const MIN_VERIFIABLE_V: u32 = 3;

/// The latest version understood. A document above it is rejected (§14).
///
/// Raised to 2 by KS-1: step 4 changed meaning from "signed by the `agent` key"
/// to "signed by a key of the set rooted at `agent`". §14 counts a change to an
/// existing field's semantics as a new major version, and the check is
/// concrete: an act signed by K3 is rejected by a v1 implementation, whereas
/// a minor change must stay readable by one.
pub const MAX_VERIFIABLE_V: u32 = 3;

/// The version new documents are signed with.
///
/// Always equal to [`MAX_VERIFIABLE_V`] or lower: issuing a version the
/// implementation itself cannot read is pointless.
pub const CURRENT_V: u32 = 3;

// The issued-version invariant is checked by the compiler, not by a test:
// issuing a version the implementation itself cannot read should not even be
// possible to build.
const _: () = assert!(CURRENT_V <= MAX_VERIFIABLE_V);
const _: () = assert!(CURRENT_V >= MIN_VERIFIABLE_V);
const _: () = assert!(MIN_VERIFIABLE_V <= MAX_VERIFIABLE_V);

/// Checks a document's `v` field (§14).
///
/// # Errors
///
/// [`Invalid::Schema`] if the version is above the supported one or below the
/// earliest issued one. The second case is not pedantry: `v: 0` in a document
/// means either corruption or an implementation that invented its own
/// numbering, and accepting it would mean verifying the document under rules it
/// did not follow.
pub fn check(v: u32) -> Result<(), Invalid> {
    if v > MAX_VERIFIABLE_V {
        return Err(Invalid::Schema(
            "document version is above the supported one",
        ));
    }
    if v < MIN_VERIFIABLE_V {
        return Err(Invalid::Schema("document version is below the issued ones"));
    }
    Ok(())
}

/// The version is compatible with the current one under the minor-change rules
/// (§14).
///
/// Adding an optional field is minor and does not change the version: an old
/// document stays valid, and a new one is readable by an old implementation —
/// it simply does not see the new field. Changing the meaning or the
/// requiredness of an existing field is never minor and needs a new major
/// version; that cannot be checked in code, so this is only a reminder in the
/// documentation.
#[must_use]
pub const fn is_current(v: u32) -> bool {
    v == CURRENT_V
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_both_ends_not_only_the_upper_one() {
        assert!(check(CURRENT_V).is_ok());
        assert_eq!(
            check(MAX_VERIFIABLE_V + 1).unwrap_err(),
            Invalid::Schema("document version is above the supported one")
        );
        // The lower bound is checked too: `v: 0` is not "an ancient version".
        assert_eq!(
            check(0).unwrap_err(),
            Invalid::Schema("document version is below the issued ones")
        );
    }
}
