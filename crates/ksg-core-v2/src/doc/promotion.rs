//! Raising a container's class after it was issued. Specification KS-8 C-2, E-10.
//!
//! # Why a document and not a field the holder edits
//!
//! The class is a property of the **packet** ([`super::BlockAllocation`]): it
//! was bought, and its price was paid for the inclusion regime it names. A
//! container that could quietly claim a higher class would be claiming that its
//! pages were anchored when they were not — the one thing the journal exists to
//! make unclaimable.
//!
//! So the raise is an act: signed by two parties, carrying its own moment, and
//! recorded. What the container keeps afterwards is the act, not a flag.
//!
//! # Upward only, and once per step
//!
//! `[decision] 2026-09-19` (CT-01): the field is laid in before the first sale, empty
//! until the first raise. A raise that went downward would retroactively
//! weaken pages already anchored under the stronger regime — the pages stay
//! anchored, but the container would stop admitting it. Refused here rather
//! than left to the caller.

use serde::{Deserialize, Serialize};

use crate::canonical::{check_envelope, Signable};
use crate::crypto::hash::Hash;
use crate::crypto::sign::{KeySet, Profile, SignatureSet};
use crate::error::Invalid;

use super::Class;

/// A signed raise of one container's class (KS-8 E-10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassPromotion {
    /// Always [`crate::doc::CONTEXT`] (spec v2 §3.3).
    #[serde(rename = "@context")]
    pub context: crate::doc::Context,
    /// Always `"ClassPromotion"`.
    #[serde(rename = "type")]
    pub doc_type: String,
    /// The major core version.
    pub v: u32,
    /// The container being raised — its identifier, not its serial.
    pub container: Hash,
    /// The class it is leaving.
    pub from: Class,
    /// The class it is entering.
    pub to: Class,
    /// Milliseconds since the packet's genesis, as everywhere else (KS-2).
    pub offset_ms: u64,
    /// Two signatures: the issuer's and the holder's. The issuer because the
    /// stronger regime is work it takes on; the holder because it is paid for.
    pub signatures: SignatureSet,
}

impl Signable for ClassPromotion {
    const DOC_TYPE: &'static str = "ClassPromotion";
}

impl ClassPromotion {
    /// Verifies a raise against the container it names and the class it has now.
    ///
    /// # Errors
    ///
    /// [`Invalid::Schema`] if the document names another container, if `from`
    /// is not the class the container holds now, if the raise does not go
    /// strictly upward, or if fewer than two distinct parties signed;
    /// [`Invalid::Signature`] on an uncovered profile.
    pub fn validate(
        &self,
        container: &Hash,
        current: Class,
        keys: &KeySet,
        profile: &Profile,
    ) -> Result<(), Invalid> {
        if &self.container != container {
            return Err(Invalid::Schema("ClassPromotion names another container"));
        }
        if self.from != current {
            return Err(Invalid::Schema(
                "ClassPromotion.from is not the class the container holds",
            ));
        }
        if self.to.rank() <= self.from.rank() {
            return Err(Invalid::Schema("ClassPromotion does not go upward"));
        }
        // Two parties, counted by distinct signers rather than by set length:
        // one party signing twice is a set of two and is not two parties.
        if self.signatures.signers().len() < 2 {
            return Err(Invalid::Schema(
                "ClassPromotion needs two signatures from two different parties",
            ));
        }
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
