//! A block's closing allocation. Specification §12. **The type is part 1,
//! validation part 2.**
//!
//! Three sets cover the block entirely and are pairwise disjoint. Coverage and
//! non-overlap are checked **separately**: the length sum equalling the block
//! size lets an overlap through together with a gap.
//!
//! For the `heavy` class the `used_not_submitted` set MUST be empty.
//!
//! Once the closure exists, the absence of gaps becomes a **provable
//! statement** rather than an assumption: an unpresented serial is either in
//! `cancelled`, or the block is not closed.

use serde::{Deserialize, Serialize};

use crate::canonical::{check_envelope, Signable};
use crate::crypto::sign::{KeySet, Profile, SignatureSet};
use crate::error::{Coverage, Invalid};

use super::ranges::{complement, validate_partition};
use super::Class;

use super::{Range, Timestamp};

/// The holder's report on the fate of every serial in the block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockClosure {
    /// Always [`crate::doc::CONTEXT`] (spec v2 §3.3).
    #[serde(rename = "@context")]
    pub context: crate::doc::Context,
    /// Always `"BlockClosure"`.
    #[serde(rename = "type")]
    pub doc_type: String,
    /// The major core version.
    pub v: u32,
    /// The emission identifier.
    pub emission: String,
    /// The block being closed.
    pub block: Range,
    /// An act was issued and submitted for fixation under an anchored root.
    pub used_submitted: Vec<Range>,
    /// An act was issued but never submitted for fixation — **it proves nothing about time**.
    pub used_not_submitted: Vec<Range>,
    /// The serial was not used and is cancelled.
    pub cancelled: Vec<Range>,
    /// The moment of closing.
    pub closed_at: Timestamp,
    /// The holder's signature.
    pub signatures: SignatureSet,
}

impl Signable for BlockClosure {
    const DOC_TYPE: &'static str = "BlockClosure";
}

impl BlockClosure {
    /// Builds a closure, **deriving** `cancelled` instead of taking it.
    ///
    /// `[decision] 11.09` Two buckets are reported — used and submitted, used and not
    /// submitted — and cancellation is the difference: the packet minus both.
    /// Automatic cancellation is a function of the container, not a statement
    /// by the holder, and this is the constructor that makes that true.
    ///
    /// The unsigned document comes back; signing is the caller's, since the
    /// core holds no keys.
    #[must_use]
    pub fn draft(
        emission: String,
        block: Range,
        used_submitted: Vec<Range>,
        used_not_submitted: Vec<Range>,
        closed_at: Timestamp,
    ) -> Self {
        let cancelled = complement(block, &[&used_submitted, &used_not_submitted]);
        Self {
            context: crate::doc::Context,
            doc_type: "BlockClosure".into(),
            v: crate::version::CURRENT_V,
            emission,
            block,
            used_submitted,
            used_not_submitted,
            cancelled,
            closed_at,
            signatures: SignatureSet::default(),
        }
    }

    /// Verifies a closing allocation (§12). **Part 2.**
    ///
    /// # Errors
    ///
    /// [`Invalid::ClosureCoverage`] naming the specific serial on a gap or an
    /// overlap, or [`Coverage::UsedNotSubmittedInHeavy`];
    /// [`Invalid::Signature`] on an uncovered profile.
    pub fn validate(&self, class: Class, keys: &KeySet, profile: &Profile) -> Result<(), Invalid> {
        // For heavy, inclusion is mandatory by definition of the class, so
        // "issued but not submitted" is a state that cannot occur there.
        if class == Class::Heavy && !self.used_not_submitted.is_empty() {
            return Err(Invalid::ClosureCoverage(Coverage::UsedNotSubmittedInHeavy));
        }
        validate_partition(
            self.block,
            [
                &self.used_submitted,
                &self.used_not_submitted,
                &self.cancelled,
            ],
        )?;
        check_envelope(
            self,
            self.v,
            &self.doc_type,
            &self.signatures,
            keys,
            profile,
        )
    }
}
