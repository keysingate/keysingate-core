//! Block allocation. Specification §7. **The type is part 1, validation part 2.**
//!
//! A new block once the previous one is drawn down by at least 80%; from the
//! second block onward `prev_closure` is mandatory; after `expires_at` the
//! block's unused serials are invalid.
//!
//! Coordination is required only here. Using the serials inside a block is
//! offline, in any order.

use serde::{Deserialize, Serialize};

use crate::canonical::{check_envelope, Signable};
use crate::crypto::hash::Hash;
use crate::crypto::sign::{KeySet, Profile, SignatureSet};
use crate::error::Invalid;

use super::{Class, Emission, Serial};

use super::{Range, Timestamp, Uri};

/// The allocation of a contiguous subrange to one holder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockAllocation {
    /// Always [`crate::doc::CONTEXT`] (spec v2 §3.3).
    #[serde(rename = "@context")]
    pub context: crate::doc::Context,
    /// Always `"BlockAllocation"`.
    #[serde(rename = "type")]
    pub doc_type: String,
    /// The major core version.
    pub v: u32,
    /// The emission identifier.
    pub emission: String,
    /// The subrange allocated.
    pub block: Range,
    /// The class of this packet: the inclusion regime (Section 10).
    ///
    /// Moved here from `Emission` on 2026-09-11: packets of different classes
    /// and sizes live in one release, so the class is a property of the packet.
    /// The size needs no field — it is `block.to - block.from + 1`.
    pub class: Class,
    /// The holder — an opaque URI.
    pub holder: Uri,
    /// The moment the packet was initiated: when this group of serials was
    /// paid for and so became this packet's, within the release (`[decision]` 19.09).
    ///
    /// The zero point every offset in the packet is measured from — see
    /// [`origin`](Self::origin), which is the name to use when that is what is
    /// meant.
    pub allocated_at: Timestamp,
    /// The moment after which the block's unused serials are invalid.
    pub expires_at: Timestamp,
    /// A reference to the previous block's closing allocation.
    ///
    /// For the first block it is **omitted**, not set to `null`: an absent field
    /// and `null` are different documents (§3), and the first block's signature
    /// must not depend on how an implementation depicts absence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_closure: Option<Hash>,
    /// The issuer's signature.
    pub signatures: SignatureSet,
}

impl Signable for BlockAllocation {
    const DOC_TYPE: &'static str = "BlockAllocation";
}

impl BlockAllocation {
    /// Verifies a block allocation (§7). **Part 2.**
    ///
    /// `is_first_block` is passed by the caller: "the second block" is a
    /// property of the sequence of allocations to a holder, not of the document
    /// itself, and it cannot be derived from a single document.
    ///
    /// `ceiling` raises the top of the class's size range for one named
    /// partner (`[decision]` 19.09, CT-29). `None` means the class's own range. It is
    /// passed in for the same reason as `is_first_block`: an agreement is not
    /// part of the document, and a document that carried its own ceiling would
    /// be raising it by itself.
    ///
    /// The 80% rule (§7 rule 2) is **not** checked here, for the same reason: it
    /// requires knowledge of the previous block's drawdown. Its place is the
    /// issuer layer, not an act verifier.
    ///
    /// # Errors
    ///
    /// [`Invalid::Schema`] on a mismatched emission, a block running past the
    /// emission's range, unordered timestamps, or a missing `prev_closure` where
    /// it is required.
    pub fn validate(
        &self,
        emission: &Emission,
        is_first_block: bool,
        ceiling: Option<u64>,
        keys: &KeySet,
        profile: &Profile,
    ) -> Result<(), Invalid> {
        if self.emission != emission.id {
            return Err(Invalid::Schema(
                "BlockAllocation.emission is a different emission",
            ));
        }
        if self.block.is_empty() {
            return Err(Invalid::Schema("BlockAllocation.block is inverted"));
        }
        if !emission.range.contains(self.block.from) || !emission.range.contains(self.block.to) {
            return Err(Invalid::OutOfRange {
                serial: self.block.from.0,
            });
        }
        // A packet cannot be handed out before the release it comes from was
        // printed. Structurally hard to violate — the issuer would have to sign
        // against himself — so this is a sanity check, not a security property.
        if self.allocated_at < emission.issued_at {
            return Err(Invalid::Schema(
                "BlockAllocation.allocated_at is before the emission",
            ));
        }
        if self.expires_at <= self.allocated_at {
            return Err(Invalid::Schema("expires_at is not later than allocated_at"));
        }
        // The size against the class (`[decision]` 19.09, CT-29). Until now the sizes
        // of 09.09 lived in prose: nothing stopped a packet of five million
        // `bare` serials, and the price of a class was worked out for a
        // hundred thousand.
        //
        // `ceiling` is the named exception the decision allows — a ceiling
        // raised by agreement for one partner. It can only move the top **up**:
        // an agreement that lowered the floor would be selling a class by its
        // name while delivering less than the class is.
        let (floor, top) = self.class.block_size_limits();
        let top = match ceiling {
            Some(agreed) if agreed > top => agreed,
            _ => top,
        };
        let size = self.block.len();
        if size < floor || size > top {
            return Err(Invalid::Schema(
                "BlockAllocation.block is not a size this class is sold in",
            ));
        }
        if !is_first_block && self.prev_closure.is_none() {
            return Err(Invalid::Schema(
                "prev_closure is required from the second block onward",
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

    /// The zero point every offset in this packet is measured from.
    ///
    /// `[decision] 19.09` (CT-25), the owner's definition: *the initiation of a packet
    /// is the moment a release passes into the state of a packet — the fixed
    /// time at which a group of container serials is assigned to a particular
    /// packet within the release.* That is this field, `allocated_at`.
    ///
    /// **What performs the passage is payment.** `[decision]` 19.09: *serials that
    /// have been paid for are what actually become a packet's, not serials
    /// merely earmarked for one.* Assignment without payment is the issuer's
    /// intention, and an intention has nothing for an origin to count from.
    ///
    /// The protocol has no separate document for payment, so this field is the
    /// only record of the passage: an allocation issued before payment would
    /// put the zero where there is not yet a packet.
    ///
    /// **One origin per packet.** Every container of the packet inherits it.
    /// The initiation of a *container* — a different event, stage 4 — is
    /// recorded as an event and is **not** an origin: an origin per container
    /// would not be one origin, and offsets from two containers of a packet
    /// would stop being comparable.
    ///
    /// This also settles the disagreement KS-2 §6 carried openly: `[decision]` 12.09
    /// read the origin as the release's moment, `[decision]` 10.09 as the packet's.
    /// The packet's it is, and the release's moment keeps the job it already
    /// had — the **lower bound**, not the origin.
    ///
    /// The method exists so that "the origin" is one place in the code rather
    /// than a field name repeated in prose.
    #[must_use]
    pub const fn origin(&self) -> &Timestamp {
        &self.allocated_at
    }

    /// The serial lies inside the allocated block.
    #[must_use]
    pub const fn covers(&self, serial: Serial) -> bool {
        self.block.contains(serial)
    }
}
