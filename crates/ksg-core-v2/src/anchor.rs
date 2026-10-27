//! Anchors. Specification §11.3. **Part 1** — the type, **part 2** — the checks.
//!
//! An array, not a field: adding a second network changes neither the schema
//! nor the validity of already-issued acts. Only addition, never replacement
//! (§15, the extension rule).

use serde::{Deserialize, Serialize};

use crate::crypto::hash::Hash;
use crate::doc::{Timestamp, Uri};

/// A root's set of anchors — **an array by construction**.
///
/// The type offers neither `Deref<Target = Vec<_>>` nor a single-element
/// constructor: the temptation of "a field with one value" is removed at the API
/// level, not by convention. How many anchors are required, and of what kind, is
/// decided by the verification policy, not by the core.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Anchors(Vec<Attestation>);

impl Anchors {
    /// A set of the anchors listed. An empty set is permitted: a root may not
    /// have been anchored yet — and then it gives no upper time bound.
    #[must_use]
    pub const fn new(anchors: Vec<Attestation>) -> Self {
        Self(anchors)
    }

    /// The anchors in the order presented.
    #[must_use]
    pub fn as_slice(&self) -> &[Attestation] {
        &self.0
    }

    /// Adds an anchor. Addition is the only way the set grows.
    pub fn push(&mut self, anchor: Attestation) {
        self.0.push(anchor);
    }

    /// The number of anchors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// There are no anchors.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Evidence that **something** existed no later than a moment.
///
/// One type for every anchor the protocol knows: the root an act is fixed
/// under (§11), a seal of the journal, a status change. Until 30.09 the core
/// had a second one, `Anchor`, for the checkpoints of the issuer's
/// transparency log; with the log out of the core (`[decision]` 30.09) the
/// root an act is fixed under is anchored directly, and a log — where one is
/// kept — is a layer above that anchors its checkpoint root the same way.
///
/// # What it proves, everywhere it is used
///
/// **This subject existed no later than `anchored_at`.** Not that the subject is
/// correct, not that it is complete, not that anyone still holds it. The one gap
/// it closes is backdating: the party that made the subject cannot claim it was
/// published earlier than it was.
///
/// A limitation that MUST NOT be glossed over: this gives the **upper** bound
/// and no lower one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attestation {
    /// The anchor's kind — an opaque URI.
    #[serde(rename = "type")]
    pub kind: Uri,
    /// What is attested: the hash of the thing.
    pub subject: Hash,
    /// The evidence, in the format `kind` names.
    ///
    /// **Opaque**, because the format follows
    /// the network, and the network is the owner's decision rather than the
    /// protocol's (§17). Storing it and interpreting it are different jobs, and
    /// the second one lives in a network profile.
    pub proof: Vec<u8>,
    /// The moment of anchoring, according to the anchor's source.
    pub anchored_at: Timestamp,
}

impl Attestation {
    /// Whether this anchor is about that subject.
    ///
    /// # Errors
    ///
    /// [`crate::error::Invalid::Schema`] when the subjects differ — the case
    /// worth naming, because "there is an anchor" reads like an answer, and an
    /// anchor of *something else* proves nothing about *this*.
    pub fn covers(&self, subject: &Hash) -> Result<(), crate::error::Invalid> {
        if &self.subject == subject {
            Ok(())
        } else {
            Err(crate::error::Invalid::Schema(
                "the anchor attests a different subject",
            ))
        }
    }
}

/// Whoever can actually check an [`Attestation`]'s `proof`.
///
/// # Why the core needs an outside party for this
///
/// The core knows nothing of Solana, OpenTimestamps or Rekor: `proof` is
/// opaque to it by design (§11.3). Opaque is not accepted: an anchor fabricated
/// with an empty `proof` and any `anchored_at` bought an upper time bound out
/// of nothing while the core only counted anchors (security audit of
/// 2026-09-13, finding 6; audit of 2026-09-23, K4). So the core keeps not
/// knowing what a `proof` means and asks whoever does know.
pub trait AttestationVerifier: core::fmt::Debug {
    /// Checks one attestation's `proof`.
    ///
    /// Returns the moment the network really proves for `attestation.subject`
    /// — the one to report, not the one the attestation asserts.
    ///
    /// # Errors
    ///
    /// Any [`Invalid`](crate::error::Invalid): the caller treats a failure as
    /// "this anchor proves nothing".
    fn verify(&self, attestation: &Attestation) -> Result<Timestamp, crate::error::Invalid>;

    /// Whether this verifier reads attestations of that kind.
    fn handles(&self, kind: &Uri) -> bool;
}

/// The upper time bound of `subject` (spec v2 §7.2) — the **one** procedure
/// for everything anchored: a seal of the journal, a status record, a release.
///
/// 1. every anchor must be of `subject`;
/// 2. an anchor of a kind the reader handles must verify — a forgery is a
///    refusal, not "not found";
/// 3. an anchor of a kind nobody reads is skipped;
/// 4. fewer than `profile.min_anchors` read: **no** bound (`Ok(None)`);
/// 5. the bound is the earliest moment among those read.
///
/// With no reader at all, nothing is read, and the answer is `Ok(None)`: the
/// subject stands, its time is not established.
///
/// # Errors
///
/// [`crate::error::Invalid::Schema`] for an anchor of another subject;
/// [`crate::error::Invalid::Limit`] past [`crate::limits::MAX_ANCHORS`];
/// whatever the reader returns for an anchor it handles and cannot confirm.
pub fn upper_bound(
    anchors: &[Attestation],
    subject: &Hash,
    profile: &crate::crypto::sign::Profile,
    reader: Option<&dyn AttestationVerifier>,
) -> Result<Option<Timestamp>, crate::error::Invalid> {
    crate::limits::at_most(anchors.len(), crate::limits::MAX_ANCHORS, "anchors")?;
    for a in anchors {
        a.covers(subject)?;
    }
    let Some(r) = reader else {
        return Ok(None);
    };
    let mut earliest: Option<Timestamp> = None;
    let mut read = 0usize;
    for a in anchors {
        if !r.handles(&a.kind) {
            continue;
        }
        let t = r.verify(a)?;
        read = read.saturating_add(1);
        if earliest.as_ref().map_or(true, |e| t < *e) {
            earliest = Some(t);
        }
    }
    Ok(if read >= profile.min_anchors.get() {
        earliest
    } else {
        None
    })
}
