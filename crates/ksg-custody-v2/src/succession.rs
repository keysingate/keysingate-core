//! A successor signed in advance, so that losing a key stops being final.
//!
//! # The problem, stated exactly
//!
//! Rotating a key needs the key. So the one situation rotation is for — the key
//! is gone — is the one situation rotation cannot handle. A successor named
//! **while the current key is still intact** breaks that circle: "must never be
//! lost" becomes "must never be lost without a prepared successor", and that is
//! achievable.
//!
//! It is the same accumulation KS-1 already gives agents, pointed at the issuer.
//!
//! # The certificate alone MUST NOT activate anything
//!
//! This is the whole design, and getting it wrong would make the feature worse
//! than useless.
//!
//! If merely holding a signed certificate made the successor current, then the
//! successor key would be exactly as powerful as the key it replaces, from the
//! day it was written. There would be no gain and twice the exposure: two keys
//! that can both mint releases, one of them sitting in a drawer for years.
//!
//! So activation takes three things, and time is one of them:
//!
//! | Step | Who signs | When |
//! |---|---|---|
//! | [`Succession`] — the certificate | the **current** key | in advance, while it is intact |
//! | [`SuccessionClaim`] — "the key is gone, I am taking over" | the **successor** key | when the loss is discovered |
//! | the notice period runs out | nobody | after the claim |
//! | [`SuccessionVeto`] — "no it is not" | the **current** key | any time during the notice |
//!
//! The veto is what makes this safe rather than merely convenient. If the
//! successor's key is stolen and a claim is filed, the current key — which by
//! assumption is *not* lost in that scenario — vetoes, and the theft is caught
//! instead of succeeding. If the current key really is gone, no veto can come,
//! and the succession completes on its own.
//!
//! Both the claim and the veto are **anchored**: their times are what the whole
//! mechanism turns on, and a time asserted by an interested party is not a time.
//!
//! # The notice period — `[decision] 12.09`, with the reasoning kept
//!
//! It is carried in the certificate rather than fixed here, because a deployment
//! may need longer. What is fixed is a **floor and a ceiling**, and a recommended
//! value: `[decision] 12.09` asked for "the optimal logical term with a possible and
//! necessary margin", and this is that term with its margin shown.
//!
//! | | | |
//! |---|---|---|
//! | [`NOTICE_RECOMMENDED_MS`] | **30 days** | the term |
//! | [`NOTICE_MIN_MS`] | **30 days** | below it the certificate is refused |
//! | [`NOTICE_MAX_MS`] | **365 days** | above it, it is a promise rather than a succession |
//!
//! **Why thirty days is the margin and not the guess.** The veto has to be cast
//! by a *person* who has to **notice** first. Two weeks is inside a single
//! plausible absence — leave, illness, a trip, and in a country at war a good
//! deal more. Thirty days spans a holiday plus a handover, which is the shortest
//! span in which "nobody objected" means anything.
//!
//! **And why a month is affordable.** Because of the two-tier key: the root key
//! signs releases and delegations, the operational key signs packets. A
//! succession of the **root** key does not stop the business — packets keep being
//! sold under a live operational grant — so the wait costs availability almost
//! nothing and buys the whole safety of the veto. The floor and the ceiling
//! follow from that, not from taste.
//!
//! **The floor is a floor, not a default to override downward.** A certificate
//! naming five days would look prudent and would hand a thief a window nobody is
//! awake for.

use serde::{Deserialize, Serialize};

use ksg_core_v2::canonical::{check_envelope, doc_hash, Signable};
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{KeySet, Profile, PublicKey, SignatureSet};
use ksg_core_v2::doc::{Timestamp, Uri};

use crate::CustodyError;

/// A day in milliseconds — the unit the terms below are stated in.
const DAY_MS: u64 = 24 * 60 * 60 * 1000;

/// The notice period to use unless there is a reason not to — **30 days**.
pub const NOTICE_RECOMMENDED_MS: u64 = 30 * DAY_MS;

/// The shortest notice a certificate may name — **30 days**.
///
/// Shorter looks prudent and is not: the veto is cast by a person who has to
/// notice first, and anything inside a single plausible absence is a window a
/// thief can wait out.
pub const NOTICE_MIN_MS: u64 = 30 * DAY_MS;

/// The longest notice a certificate may name — **365 days**.
///
/// Past a year a successor is not prepared, it is promised: the loss it is for
/// would be lived through rather than repaired.
pub const NOTICE_MAX_MS: u64 = 365 * DAY_MS;

/// A successor named in advance by the key it will replace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Succession {
    /// Always [`ksg_core_v2::doc::CONTEXT`] (spec v2 §3.3).
    #[serde(rename = "@context")]
    pub context: ksg_core_v2::doc::Context,
    /// Always `"Succession"`.
    #[serde(rename = "type")]
    pub doc_type: String,
    /// The major core version.
    pub v: u32,
    /// Whose keys these are — an opaque URI, as `issuer` is in an emission.
    pub issuer: Uri,
    /// The key being succeeded.
    pub current: PublicKey,
    /// The key that will replace it.
    pub successor: PublicKey,
    /// How long a claim must stand unvetoed before it takes effect.
    pub notice_ms: u64,
    /// When the certificate was written.
    pub declared_at: Timestamp,
    /// The **current** key's signature. Written while it is still intact —
    /// which is the only moment it can be written at all.
    pub signatures: SignatureSet,
}

impl Signable for Succession {
    const DOC_TYPE: &'static str = "Succession";
}

/// "The key is gone; I am taking over." Signed by the successor, anchored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuccessionClaim {
    /// Always [`ksg_core_v2::doc::CONTEXT`] (spec v2 §3.3).
    #[serde(rename = "@context")]
    pub context: ksg_core_v2::doc::Context,
    /// Always `"SuccessionClaim"`.
    #[serde(rename = "type")]
    pub doc_type: String,
    /// The major core version.
    pub v: u32,
    /// The certificate being claimed under.
    pub succession: Hash,
    /// When the claim was filed — **as the anchor says**, not as the claimant does.
    pub claimed_at: Timestamp,
    /// The **successor** key's signature.
    pub signatures: SignatureSet,
}

impl Signable for SuccessionClaim {
    const DOC_TYPE: &'static str = "SuccessionClaim";
}

/// "No it is not." Signed by the current key, anchored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuccessionVeto {
    /// Always [`ksg_core_v2::doc::CONTEXT`] (spec v2 §3.3).
    #[serde(rename = "@context")]
    pub context: ksg_core_v2::doc::Context,
    /// Always `"SuccessionVeto"`.
    #[serde(rename = "type")]
    pub doc_type: String,
    /// The major core version.
    pub v: u32,
    /// The certificate being vetoed under.
    pub succession: Hash,
    /// When the veto was filed.
    pub vetoed_at: Timestamp,
    /// The **current** key's signature — proof that it is not lost at all.
    pub signatures: SignatureSet,
}

impl Signable for SuccessionVeto {
    const DOC_TYPE: &'static str = "SuccessionVeto";
}

/// Where a succession stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// A certificate exists and nothing has been claimed. The current key is
    /// still the only one that signs.
    Prepared,
    /// A claim is standing and the notice has not run out.
    Pending {
        /// Milliseconds still to wait.
        remaining_ms: u64,
    },
    /// The notice ran out unvetoed. The successor is the key now.
    Effective,
    /// The current key answered, so it was not lost. The claim is dead, and
    /// **the certificate is dead with it** — see [`Succession::standing`].
    Vetoed,
}

impl Succession {
    /// Verifies the certificate itself.
    ///
    /// `keys` must contain the **current** key: a certificate names its own
    /// signer, and one signed by anybody else is a stranger's opinion about
    /// whose key this is.
    ///
    /// # Errors
    ///
    /// [`CustodyError::Succession`] on a certificate that succeeds a key to
    /// itself or carries no notice period; whatever the envelope check returns
    /// otherwise.
    pub fn validate(&self, keys: &KeySet, profile: &Profile) -> Result<(), CustodyError> {
        if self.current.kid == self.successor.kid {
            return Err(CustodyError::Succession("the successor is the current key"));
        }
        if self.notice_ms < NOTICE_MIN_MS {
            return Err(CustodyError::Succession(
                "the notice period is shorter than the floor of 30 days",
            ));
        }
        if self.notice_ms > NOTICE_MAX_MS {
            return Err(CustodyError::Succession(
                "the notice period is longer than the ceiling of 365 days",
            ));
        }
        if !self.signatures.signed_by(&self.current.kid) {
            return Err(CustodyError::Succession(
                "the certificate is not signed by the key it succeeds",
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
        .map_err(|_| CustodyError::Succession("the certificate's signature did not verify"))
    }

    /// Where this succession stands, given what was filed and how long the
    /// claim has stood.
    ///
    /// # `waited_ms` comes from outside, and that is not laziness
    ///
    /// This codebase does no date arithmetic anywhere: `Timestamp` is a fixed
    /// RFC 3339 string whose lexicographic order is its chronological order, and
    /// nothing parses a calendar. Doing it here would make this the one place
    /// that needs a calendar library and the one place a timezone bug could
    /// live.
    ///
    /// More to the point, the elapsed time that matters is **the anchor's**,
    /// not the document's. A claim says when it was filed; an anchor proves it.
    /// Taking the figure as an argument puts the question "whose clock?" where
    /// it belongs — with the caller, who knows which anchor it trusts.
    ///
    /// A veto kills the certificate outright rather than only the claim. The
    /// reason is the scenario the veto exists for: a veto means the successor's
    /// key was used without authority, so that key is compromised and naming it
    /// again would be naming a key an attacker holds. Recovery from a veto is a
    /// **new certificate**, which the current key can write, because the veto
    /// proved it can still sign.
    ///
    /// # A veto counts only within the notice
    ///
    /// The veto is cast "at any moment of the term" (`Khranenie_klyucha_emitenta`,
    /// the succession table) — of the term, not after it. `veto` carries, next
    /// to the document, how long after the claim's anchor the veto's anchor
    /// came: the same anchor-to-anchor distance as `waited_ms`, and for the same
    /// reason — `vetoed_at` is written by the vetoing key and proves nothing.
    /// A veto anchored once the notice has run out is late: the successor is
    /// the key, and an old key that surfaces afterwards is exactly what the
    /// notice was there to wait out (audit of 2026-10-01, finding Sh-10). With
    /// no claim filed, a veto kills the certificate whenever it comes.
    ///
    /// # Errors
    ///
    /// [`CustodyError::Succession`] if a document refers to a different
    /// certificate, or is signed by the wrong party.
    pub fn standing(
        &self,
        claim: Option<&SuccessionClaim>,
        veto: Option<(&SuccessionVeto, u64)>,
        waited_ms: u64,
        profile: &Profile,
    ) -> Result<Standing, CustodyError> {
        let mine = doc_hash(self)
            .map_err(|_| CustodyError::Succession("the certificate does not canonicalize"))?;

        if let Some((v, after_claim_ms)) = veto {
            if v.succession != mine {
                return Err(CustodyError::Succession(
                    "the veto is of another certificate",
                ));
            }
            let mut keys = KeySet::new();
            keys.insert(self.current.clone());
            check_envelope(v, v.v, &v.doc_type, &v.signatures, &keys, profile)
                .map_err(|_| CustodyError::Succession("the veto is not the current key's"))?;
            if claim.is_none() || after_claim_ms < self.notice_ms {
                return Ok(Standing::Vetoed);
            }
        }

        let Some(c) = claim else {
            return Ok(Standing::Prepared);
        };
        if c.succession != mine {
            return Err(CustodyError::Succession(
                "the claim is of another certificate",
            ));
        }
        let mut keys = KeySet::new();
        keys.insert(self.successor.clone());
        check_envelope(c, c.v, &c.doc_type, &c.signatures, &keys, profile)
            .map_err(|_| CustodyError::Succession("the claim is not the successor's"))?;

        if c.claimed_at < self.declared_at {
            return Err(CustodyError::Succession(
                "the claim precedes the certificate it claims under",
            ));
        }

        if waited_ms >= self.notice_ms {
            Ok(Standing::Effective)
        } else {
            Ok(Standing::Pending {
                remaining_ms: self.notice_ms - waited_ms,
            })
        }
    }

    /// The key that signs for this issuer right now.
    ///
    /// The whole point, in one call: before the notice runs out it is still the
    /// current key, and only after it is the successor.
    ///
    /// # Errors
    ///
    /// As [`Self::standing`].
    pub fn key_now(
        &self,
        claim: Option<&SuccessionClaim>,
        veto: Option<(&SuccessionVeto, u64)>,
        waited_ms: u64,
        profile: &Profile,
    ) -> Result<PublicKey, CustodyError> {
        Ok(match self.standing(claim, veto, waited_ms, profile)? {
            Standing::Effective => self.successor.clone(),
            _ => self.current.clone(),
        })
    }
}
