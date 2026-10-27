//! The emission. Specification §5. **The type is part 1, validation part 2.**
//!
//! One signed document about a range; blanks are derived from it
//! deterministically. Printing the whole range costs one signature.

use serde::{Deserialize, Serialize};

use crate::canonical::{check_envelope, Signable};
use crate::crypto::sign::{KeySet, Profile, PublicKey, SignatureSet};
use crate::error::Invalid;

use super::{Range, Timestamp, Uri};

/// The emission class (spec v2 §9): the **tariff and the form the journal
/// opens in**, not an anchoring regime for the whole life (core audit of 30.09,
/// finding 3; the owner's decisions on the journal forms).
///
/// | class | page 0 | may go Pro | anchors |
/// |---|---|---|---|
/// | `heavy` | Pro | already | every seal while Pro |
/// | `light` | light | yes, by a page that changes the form | only while Pro |
/// | `bare` | light | never | none |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Class {
    /// Packets of 1 … 1 000; the journal opens in Pro.
    Heavy,
    /// Packets of 10 000 … 100 000; the journal opens light and may go Pro. A
    /// seal written light has no time bound — this MUST NOT be presented
    /// otherwise.
    Light,
    /// No anchors ever: authenticity and authorship are proved, **time is
    /// not**.
    Bare,
}

/// The form the container's anchors take in the public chain — chosen at birth
/// and never changed. Specification `Resheniya_13.09` §8.3, `[decision]` 13.09.
///
/// # Two forms by design, not one evolving into the other
///
/// The **plain** form is the playground: a container that will never be shown
/// outside, that anchors nothing, and that therefore has nothing to version.
/// The **controlled** form is everything meant to be presented.
///
/// # Why it cannot be converted
///
/// `[decision]` 13.09, reading A: if a playground container could be turned into a
/// presentable one later, work would be proved after the fact and the decision
/// to buy would come after the valuable work rather than before it. The same
/// rule as the decision of 10.09 that a playground's history cannot be carried
/// over — seen from the other side.
///
/// What this type does about it: there is no method that changes it. The field
/// that holds it is private and set once, at assembly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MemoFormat {
    /// Playground: no anchors at all, never presented outside, free.
    Plain,
    /// Meant to be presented: anchored, registered, priced.
    Controlled,
}

impl Class {
    /// How much of the journal this class buys, as an order.
    ///
    /// Exists so that a raise can be checked for direction (KS-8 E-10). The
    /// order is the one the classes are sold in: `bare` proves no time,
    /// `light` proves it for what the holder submits, `heavy` for everything.
    /// The sizes a packet of this class is sold in, as an inclusive range.
    ///
    /// `[decision]` 09.09: packets of different sizes and classes live in one release —
    /// `heavy` by the piece and by the thousand, `light` by ten to a hundred
    /// thousand, `bare` free. The numbers were named then and checked nowhere,
    /// so a block of five million `bare` serials was accepted by the code while
    /// the cost of anchoring had been worked out for a hundred thousand.
    ///
    /// `bare` is unbounded on purpose, not by omission: it takes no journal
    /// operations at all, so there is no cost that a size could outrun.
    #[must_use]
    pub const fn block_size_limits(self) -> (u64, u64) {
        match self {
            Self::Heavy => (1, 1_000),
            Self::Light => (10_000, 100_000),
            Self::Bare => (1, u64::MAX),
        }
    }

    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::Bare => 0,
            Self::Light => 1,
            Self::Heavy => 2,
        }
    }
}

/// A signed declaration of a range of serials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Emission {
    /// Always [`crate::doc::CONTEXT`] (spec v2 §3.3).
    #[serde(rename = "@context")]
    pub context: crate::doc::Context,
    /// Always `"Emission"`.
    #[serde(rename = "type")]
    pub doc_type: String,
    /// The major core version. A document with `v` above the supported one is rejected (§14).
    pub v: u32,
    /// The emission identifier, of the form `ksg:em:NNNNNN`.
    pub id: String,
    /// The declared range of serials.
    pub range: Range,
    /// The block's lifetime in days.
    pub block_ttl_days: u32,
    /// The issuer — an opaque URI.
    pub issuer: Uri,
    /// The moment of issuance. Gives the **lower time bound** for any act on
    /// a blank of this emission (§6).
    pub issued_at: Timestamp,
    /// The issuer's keys.
    pub keys: Vec<PublicKey>,
    /// The issuer's signatures — an array (§4.1).
    pub signatures: SignatureSet,
}

/// The longest a container may wait without a journal work before it turns
/// into a brick: **two years**, channel allowances included.
///
/// `[decision]` 23.09: a created container cannot be changed at all (`KS-8` A-3), so
/// its software is the software of its release, and containers of old and new
/// releases live side by side. Containers **without a journal work**, already
/// signed by a distributor and/or agents (statuses 1–3), may exist only two or
/// three years and then become bricks — status 10 when the term ran out
/// unused, 20 when initiation was attempted after it. The owner left the choice
/// of two or three to the executor; two was chosen (executor's audit of 23.09, §7):
///
/// - the ceiling is the oldest the software can be at the moment work starts;
///   the frozen software of a release should not begin a journal work years
///   after newer releases are out;
/// - verification loses nothing: `crate::version` keeps every issued version
///   verifiable, so a two-year limit on *starting* costs no history;
/// - the channel still fits: the deepest channel (`MAX_DEPTH` = 4) multiplies
///   the base term by 1.4, so any base up to 521 days keeps its full allowance
///   under the ceiling.
///
/// **Status 4 is outside the ceiling** (`[decision]` 23.09): an initiated container
/// belongs to the end user, who decides how long it lives, even on outdated
/// software. The ceiling bounds the channel's stock, not the owner's property.
///
/// A ceiling rather than a rule on `block_ttl_days`: before this, a release
/// could declare any term at all, and a declared number was the only limit.
pub const MAX_UNUSED_LIFETIME_MS: u64 = 730 * 86_400_000;

impl Emission {
    /// How long a packet of this release may be opened for, in milliseconds,
    /// allowing for how far down the channel it was handed.
    ///
    /// `[decision] 19.09` (CT-24): unused serials burn — *not in time, gone* — and the
    /// one exception is the lifetime itself. **A distributor gets +10%, and
    /// each further agent another +10%.** The reason is the channel, not
    /// generosity: a packet that passed through three hands spent part of its
    /// life travelling, and a lifetime counted from the packet's own origin
    /// would charge the last agent for the journey.
    ///
    /// Integer arithmetic, `base * (10 + depth) / 10`: no floating point in a
    /// rule that decides whether a container is valid. `depth` is the channel
    /// depth and is bounded by [`crate::doc::MAX_DEPTH`], so the multiplier
    /// cannot run away. Never above [`MAX_UNUSED_LIFETIME_MS`].
    #[must_use]
    pub const fn lifetime_ms(&self, depth: u8) -> u64 {
        let base = (self.block_ttl_days as u64).saturating_mul(86_400_000);
        // Saturating throughout: a release declaring a ttl near u64::MAX must
        // give a long lifetime, not a wrapped short one.
        let term = base.saturating_mul(10u64.saturating_add(depth as u64)) / 10;
        // The brick ceiling (`[decision]` 23.09) holds whatever the release declared.
        if term > MAX_UNUSED_LIFETIME_MS {
            MAX_UNUSED_LIFETIME_MS
        } else {
            term
        }
    }
}

impl Signable for Emission {
    const DOC_TYPE: &'static str = "Emission";
}

impl Emission {
    /// The issuer keys declared in the emission itself.
    ///
    /// An emission is self-contained: its signature is verified with the keys in
    /// its own `keys` field. Trust in those keys is a question for a layer
    /// outside the core (§4.2).
    #[must_use]
    pub fn declared_keys(&self) -> KeySet {
        self.keys.iter().cloned().collect()
    }

    /// Verifies an emission (§5). **Part 2.**
    ///
    /// # Errors
    ///
    /// [`Invalid::Schema`] on an inverted range, empty keys, or a foreign
    /// version; [`Invalid::Signature`] on an uncovered profile.
    pub fn validate(&self, profile: &Profile) -> Result<(), Invalid> {
        if self.range.is_empty() {
            return Err(Invalid::Schema("Emission.range is inverted"));
        }
        if self.keys.is_empty() {
            return Err(Invalid::Schema("Emission.keys is empty"));
        }
        check_envelope(
            self,
            self.v,
            &self.doc_type,
            &self.signatures,
            &self.declared_keys(),
            profile,
        )
    }
}
