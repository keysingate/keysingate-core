//! Delegation of issuance. Specification KS-4 §5, §5b, §7.2-sexies.
//!
//! # Two things at once, and that is the point
//!
//! The same document serves a **distributor** — another organization issuing
//! packets inside a range it was granted — and the issuer's **own second key**.
//! The key split the owner asked for on 11.09 is the degenerate case where the
//! delegate is the same party:
//!
//! ```text
//! root key  ──delegation──▶  operational key  ──▶  BlockAllocation
//! (offline, 3 of 5)          (online, rotatable)
//! ```
//!
//! Releases are rare — a hundred million serials each. Packets are sold, so
//! they are frequent. One key for both means the most valuable key works often
//! and online, which is the main way such a key leaks. With the split, a leaked
//! operational key is revoked by a new delegation and the root key survives it.
//!
//! That the same type covers both cases is not a coincidence to be tidied away:
//! delegating to yourself and delegating to a distributor are the same act, and
//! a second type for one of them would be a second set of rules to keep in
//! agreement.
//!
//! # Form B, and the freeze chose it
//!
//! KS-4 §6 offers two forms: (A) a field added to `BlockAllocation`, (B) a
//! separate type. A is a structural change to a frozen schema and B touches
//! nothing, so the constraint already in force decides it. Not a preference.
//!
//! # What deliberately does not change
//!
//! `BlockAllocation::validate` already takes an arbitrary `KeySet` rather than
//! wired-in issuer keys, so sub-issuance verifies through the same code once the
//! verifier is told whose keys to accept. KS-4 §5 says so outright — "the
//! document type need not change" — and [`resolve`] is the missing piece that
//! computes which keys those are.
//!
//! # Verification is not delegated (KS-4 §5a)
//!
//! Nothing here makes a distributor necessary to check anything. The chain is a
//! set of documents; whoever holds them gets the same answer. A distributor is
//! where the documents live, not a party anyone must ask.

use serde::{Deserialize, Serialize};

use crate::canonical::{check_envelope, doc_hash, Signable};
use crate::crypto::hash::Hash;
use crate::crypto::sign::{KeySet, Profile, PublicKey, SignatureSet};
use crate::error::Invalid;

use super::{Emission, Range, Timestamp, Uri};

/// A day in milliseconds — the unit the terms below are stated in.
const DAY_MS: u64 = 24 * 60 * 60 * 1000;

/// How long an operational grant runs — **90 days**. `[decision] 12.09`
///
/// # Why a quarter, and not a month or a year
///
/// The cost on one side is a **ceremony**: renewing a grant means turning on the
/// root key, which lives offline under 3-of-5 shares in two countries and a
/// notary's safe. That is days of work and travel, not a command. Monthly
/// renewal would mean twelve of them a year and would not survive contact with
/// reality — and a term nobody can keep is renewed late, which is worse than a
/// longer one kept.
///
/// The cost on the other side is a **leaked operational key living out its
/// term**. A year of that is a year of forged packets.
///
/// A quarter is where the two meet: four ceremonies a year is a schedule an
/// organization actually keeps, and ninety days is short enough that a leak has
/// an end in sight.
pub const GRANT_MS: u64 = 90 * DAY_MS;

/// How long the new grant and the old one overlap — **30 days**. `[decision] 12.09`
///
/// This is the margin, and it is the point of naming the term at all. The new
/// grant is issued **before** the old one ends, and both are valid in between,
/// so a ceremony delayed by a missed flight, an illness or an air raid costs
/// nothing. Without the overlap a term is a cliff, and the way organizations
/// cope with cliffs is by making the term longer — which is the outcome the
/// term was chosen to avoid.
pub const GRANT_OVERLAP_MS: u64 = 30 * DAY_MS;

/// The longest an operational grant may run — **180 days**.
///
/// Twice the term, so a deployment with a slower ceremony has room, and no
/// more: past half a year the operational key stops being the cheap, rotatable
/// half of the pair and becomes a second root key that happens to be online.
pub const GRANT_MAX_MS: u64 = 180 * DAY_MS;

/// Whether a grant's span is a term this protocol will stand behind.
///
/// **Takes the span as an argument**, because nothing in this codebase does
/// arithmetic on dates: `Timestamp` is an RFC 3339 string whose lexicographic
/// order is its chronological one, and the calendar belongs to the caller. The
/// same shape as the elapsed time a succession claim is judged by.
///
/// # Errors
///
/// [`Invalid::Schema`] for a span of zero — a grant that ends when it starts —
/// or one past [`GRANT_MAX_MS`].
pub fn check_term(span_ms: u64) -> Result<(), Invalid> {
    if span_ms == 0 {
        return Err(Invalid::Schema("a grant that ends when it begins"));
    }
    if span_ms > GRANT_MAX_MS {
        return Err(Invalid::Schema(
            "the grant runs longer than 180 days; an operational key is not a second root",
        ));
    }
    Ok(())
}

/// The deepest a delegation chain may go (KS-7 §7.2-sexies).
///
/// Four intermediary levels: distributor, general agent, regional or sectoral
/// agent, local or individual agent. The consequence worth naming is that the
/// set of parties trusted by construction gets a **ceiling** — KS-4 §5e's
/// objection that depth grows that set indefinitely stops being open.
pub const MAX_DEPTH: u8 = 4;

/// A grant of the right to issue inside a range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delegation {
    /// Always [`crate::doc::CONTEXT`] (spec v2 §3.3).
    #[serde(rename = "@context")]
    pub context: crate::doc::Context,
    /// Always `"Delegation"`.
    #[serde(rename = "type")]
    pub doc_type: String,
    /// The major core version. Introduced in v2.
    pub v: u32,
    /// The emission this grant lives inside.
    pub emission: String,
    /// The range the delegate may issue within. Nested in the grantor's (§5b).
    pub range: Range,
    /// Who the delegate is — an opaque URI, as `holder` is.
    pub delegate: Uri,
    /// The keys the delegate will sign allocations with.
    ///
    /// A list, so the delegate can hold more than one and rotate without a new
    /// delegation — the same reason `Emission.keys` is a list.
    pub keys: Vec<PublicKey>,
    /// The hash of the delegation above this one; absent at depth 0, where the
    /// grantor is the emission's issuer.
    ///
    /// **Omitted, not null.** §3: an absent field and a `null` are different
    /// documents, and a root grant's signature must not depend on how an
    /// implementation depicts absence. Same rule as `BlockAllocation`'s
    /// `prev_closure`, and it is a rule rather than a style because the
    /// signature covers the canonical form.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<Hash>,
    /// How far down the chain this is. 0 is granted by the issuer itself.
    pub depth: u8,
    /// When the grant was made.
    pub delegated_at: Timestamp,
    /// **How long the grant runs, in milliseconds.** `[decision] 12.09`
    ///
    /// # Why the length is a field and not a subtraction
    ///
    /// The bound of [`GRANT_MAX_MS`] has to be checkable by **anyone** holding
    /// the document, and nothing in this codebase reads a calendar: `Timestamp`
    /// is an RFC 3339 string whose lexicographic order is its chronological one.
    /// A verifier with no calendar therefore cannot subtract two dates, and a
    /// rule it cannot apply is a rule that is not enforced.
    ///
    /// Stating the length **in the signed document** makes it a claim the
    /// grantor is bound by: [`Delegation::validate`] holds it to the bounds
    /// without a calendar, and anyone who does have one can check it against
    /// the two dates with [`Delegation::term_matches`]. A lie about it is a
    /// signed lie, provable by anybody.
    pub term_ms: u64,
    /// When it ends.
    ///
    /// Not optional, and that is the whole point of the operational key. A grant
    /// without an end cannot be rotated away without a revocation mechanism, and
    /// a leaked operational key would then be valid forever — which is exactly
    /// what splitting the key was meant to prevent. An end date makes rotation
    /// the default and revocation the exception.
    pub expires_at: Timestamp,
    /// The grantor's signature.
    pub signatures: SignatureSet,
}

impl Signable for Delegation {
    const DOC_TYPE: &'static str = "Delegation";
}

impl Delegation {
    /// Whether the stated term matches the span a caller computed from the dates.
    ///
    /// For whoever **does** have a calendar. The document binds the grantor to a
    /// number; this is how a verifier with a clock catches a number that does
    /// not match the dates beside it.
    #[must_use]
    pub const fn term_matches(&self, span_ms: u64) -> bool {
        self.term_ms == span_ms
    }

    /// Whether the renewal of this grant is due.
    ///
    /// `[decision] 12.09` — the new grant is issued **before** the old one ends, and
    /// both are valid through [`GRANT_OVERLAP_MS`]. Takes the elapsed time as an
    /// argument, as everything about time here does.
    #[must_use]
    pub const fn renewal_due(&self, elapsed_ms: u64) -> bool {
        // Saturating: `elapsed_ms` comes from the caller and `term_ms` from the
        // document, and a wrap would answer "not due yet" at the one moment it
        // matters most (audit finding 20).
        elapsed_ms.saturating_add(GRANT_OVERLAP_MS) >= self.term_ms
    }

    /// Verifies one link of the chain.
    ///
    /// `grantor_keys` are the keys entitled to make this grant: the issuer's at
    /// depth 0, the parent delegation's keys below that. Working out which is
    /// [`resolve`]'s job, not this one — a single link cannot know where it sits.
    ///
    /// # Errors
    ///
    /// [`Invalid::Schema`] on a foreign emission, a range not nested in the
    /// grantor's, a depth past [`MAX_DEPTH`], a parent that is present when it
    /// should not be or absent when it should, or dates out of order;
    /// [`Invalid::Signature`] on an uncovered profile.
    pub fn validate(
        &self,
        emission: &Emission,
        parent: Option<&Self>,
        grantor_keys: &KeySet,
        profile: &Profile,
    ) -> Result<(), Invalid> {
        // The version gates everything below it, for the reason it does in
        // `AgentBinding`: `depth` and `parent` mean what v2 says they mean.
        crate::version::check(self.v)?;

        if self.emission != emission.id {
            return Err(Invalid::Schema(
                "Delegation.emission is a different emission",
            ));
        }
        if self.depth > MAX_DEPTH {
            return Err(Invalid::Schema(
                "Delegation.depth is past the channel limit",
            ));
        }
        if self.keys.is_empty() {
            return Err(Invalid::Schema("Delegation grants no keys"));
        }

        // The grantor's range, and whether a parent belongs here at all. Depth
        // and parent must agree: a depth-0 link with a parent claims two
        // grantors, and a deeper one without a parent claims none.
        let outer = match (self.depth, parent) {
            (0, None) => emission.range,
            (0, Some(_)) => {
                return Err(Invalid::Schema("a depth-0 Delegation has no parent"));
            }
            (_, None) => {
                return Err(Invalid::Schema("a sub-Delegation must present its parent"));
            }
            (_, Some(p)) => {
                // Saturating: a parent at depth 255 would otherwise wrap to 0
                // and let a child claim depth 0 — the root's own place.
                if self.depth != p.depth.saturating_add(1) {
                    return Err(Invalid::Schema(
                        "Delegation.depth does not follow its parent",
                    ));
                }
                if self.parent != Some(doc_hash(p)?) {
                    return Err(Invalid::Schema(
                        "Delegation.parent does not point at this parent",
                    ));
                }
                if self.delegated_at < p.delegated_at {
                    return Err(Invalid::Schema(
                        "Delegation precedes the grant it comes from",
                    ));
                }
                // A grant cannot outlive the grant it came from: otherwise the
                // chain ends and the leaf goes on issuing.
                if self.expires_at > p.expires_at {
                    return Err(Invalid::Schema(
                        "Delegation outlives the grant it comes from",
                    ));
                }
                p.range
            }
        };

        // §5b — nesting. Without it a delegate issues outside what it was given.
        if self.range.from < outer.from || self.range.to > outer.to {
            return Err(Invalid::Schema(
                "Delegation.range is not inside the grantor's",
            ));
        }
        if self.range.is_empty() {
            return Err(Invalid::Schema("Delegation.range is empty"));
        }
        // `[decision]` 12.09 — the term's bounds, checked here rather than left in a
        // function nobody calls. Before this, a grant for five years passed
        // validation while a ceiling of 180 days sat in a constant.
        check_term(self.term_ms)?;
        if self.expires_at <= self.delegated_at {
            return Err(Invalid::Schema("Delegation expires before it begins"));
        }
        // Finding 12, closed by CT-20: with the verifier's clock, a grant that
        // has run out is refused — "rotation instead of revocation" finally
        // protects the offline verifier. A comparison of two checked RFC 3339
        // strings, never a subtraction: the core does no arithmetic on time.
        // A grant not yet in force is refused for the same reason — it is not
        // authority *now*, whatever it will be later.
        if let Some(now) = &profile.now {
            if now.as_str() > self.expires_at.as_str() {
                return Err(Invalid::Schema(
                    "the delegation has expired by the verifier's clock",
                ));
            }
            if now.as_str() < self.delegated_at.as_str() {
                return Err(Invalid::Schema(
                    "the delegation is not yet in force by the verifier's clock",
                ));
            }
        }

        check_envelope(
            self,
            self.v,
            &self.doc_type,
            &self.signatures,
            grantor_keys,
            profile,
        )
    }

    /// The keys this grant hands to its delegate.
    #[must_use]
    pub fn key_set(&self) -> KeySet {
        self.keys.iter().cloned().collect()
    }
}

/// Walks a delegation chain and returns the keys entitled to sign allocations
/// in the leaf's range, together with that range.
///
/// The chain is presented **in order**, outermost first. Each link is checked
/// against the one above it, and one link that does not fit refuses the whole
/// chain — the same rule as the key-inclusion chain of KS-1, and for the same
/// reason: a chain checked only at its ends lets a mistake in the middle pass.
///
/// An empty chain is not an error. It means no delegation was made, and the
/// keys entitled to sign are the issuer's own — which is the arrangement
/// everything worked under before this type existed.
///
/// # Errors
///
/// Whatever [`Delegation::validate`] returns, for the link that failed.
pub fn resolve(
    emission: &Emission,
    chain: &[Delegation],
    issuer_keys: &KeySet,
    profile: &Profile,
) -> Result<(KeySet, Range), Invalid> {
    let Some(leaf) = chain.last() else {
        return Ok((issuer_keys.clone(), emission.range));
    };
    if chain.len() > MAX_DEPTH as usize + 1 {
        return Err(Invalid::Schema(
            "the delegation chain is past the channel limit",
        ));
    }

    let mut granted = issuer_keys.clone();
    let mut parent: Option<&Delegation> = None;
    for link in chain {
        link.validate(emission, parent, &granted, profile)?;
        granted = link.key_set();
        parent = Some(link);
    }
    Ok((granted, leaf.range))
}
