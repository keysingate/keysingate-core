//! Declaring that shares are lost, and the window in which that can be argued.
//!
//! # What this is for
//!
//! The split is three of five. Losing one share is nothing; losing three means
//! the key is gone. In between — **two lost, three left** — the key is fine and
//! the set is not: any further loss is fatal, so the set has to be cut anew.
//!
//! That re-split has to be provably the same secret, or the new set is just
//! five numbers somebody produced. `[decision]` 19.09: the container carries the
//! commitments of all five shares, the holders present what they have, the
//! container checks it against them and writes the result into the journal —
//! and the record, being anchored like every record, is what the window is
//! measured from.
//!
//! # Why a declaration and not a timer
//!
//! `[decision]` 19.09, the owner's question answered: a container learns nothing by
//! itself. Nothing tells it that shares went missing — silence is what it hears
//! when nothing is happening at all. So the window starts at a **presentation**,
//! not at the onset of quiet: the holders of what is left press the key button,
//! the container verifies against the commitments it holds, and the declaration
//! is the record of that.
//!
//! # Why the owner's signature is on it
//!
//! `[decision]` 19.09: *to cut the thieves off more sharply.* Without it a thief who
//! took two shares could open the window and wait it out; the theft would be
//! caught at the far end, by the issuer, thirty days later. With it the thief
//! does not start: no signature of the key's owner, no declaration.
//!
//! The cost is named rather than hidden: if the owner's signing key is lost
//! **together with** the shares, nothing can be signed and the set can never be
//! re-cut. That is the [`LongWindow`](Window::Long) case — the issuer signs
//! instead, and the window is longer, because a stranger's word needs more time
//! to be argued with than the owner's.

use serde::{Deserialize, Serialize};

use ksg_core_v2::canonical::{check_envelope, doc_hash, Signable};
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{KeySet, Profile, PublicKey, SignatureSet};
use ksg_core_v2::doc::Timestamp;

use crate::set::CustodySet;
use crate::{CustodyError, Share};

/// A day, in milliseconds.
const DAY_MS: u64 = 86_400_000;

/// The window a declaration signed by the key's owner stands for.
///
/// `[decision]` 19.09: **thirty actual days**, waiting for the missing shares or for a
/// statement that they are gone for good.
pub const WINDOW_MS: u64 = 30 * DAY_MS;

/// The window when the owner's key went with the shares and the issuer declares
/// instead.
///
/// Longer on purpose: the owner is not there to object, so the time that
/// objection would have taken has to be given to someone else noticing.
pub const WINDOW_WITHOUT_OWNER_MS: u64 = 90 * DAY_MS;

/// Who signed the declaration, and therefore how long it stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Window {
    /// Declared by the owner of the split key: thirty days.
    Short,
    /// Declared by the issuer because the owner's key is gone too: ninety days.
    Long,
}

impl Window {
    /// How long this window runs.
    #[must_use]
    pub const fn ms(self) -> u64 {
        match self {
            Self::Short => WINDOW_MS,
            Self::Long => WINDOW_WITHOUT_OWNER_MS,
        }
    }
}

/// "These shares are what is left." Signed, and anchored like every record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LossDeclaration {
    /// Always [`ksg_core_v2::doc::CONTEXT`] (spec v2 §3.3).
    #[serde(rename = "@context")]
    pub context: ksg_core_v2::doc::Context,
    /// Always `"LossDeclaration"`.
    #[serde(rename = "type")]
    pub doc_type: String,
    /// The major core version.
    pub v: u32,
    /// The root of the set being declared incomplete — not the commitments.
    ///
    /// The root is what the chain already carries; naming the commitments here
    /// would put four hashes of shares nobody lost into a signed document.
    pub set_root: Hash,
    /// How many of the five were presented and checked out.
    pub presented: u8,
    /// When it was declared — as the anchor says, not as the declarant does.
    pub declared_at: Timestamp,
    /// The signatures: the owner of the split key, or the issuer.
    pub signatures: SignatureSet,
}

impl Signable for LossDeclaration {
    const DOC_TYPE: &'static str = "LossDeclaration";
}

impl LossDeclaration {
    /// Verifies a declaration against the set it names and the shares presented.
    ///
    /// The shares are checked against the commitments the set holds, and the
    /// count is checked to be **below the threshold**: presenting three of five
    /// is not a loss, it is a reconstruction, and calling it a loss would open a
    /// window where none is needed.
    ///
    /// `owner` is the key of whoever the split key belongs to; `issuer` is the
    /// fallback. Which of them signed decides the window — and a declaration
    /// signed by neither is not a declaration.
    ///
    /// # Errors
    ///
    /// [`CustodyError::Succession`] if the declaration names another set, if the
    /// count is not below the threshold, or if neither key signed;
    /// [`CustodyError::Substituted`] if a presented share does not match its
    /// commitment; [`CustodyError::RepeatedIndex`] if one share is presented
    /// twice.
    pub fn validate(
        &self,
        set: &CustodySet,
        presented: &[Share],
        owner: &PublicKey,
        issuer: &PublicKey,
        profile: &Profile,
    ) -> Result<Window, CustodyError> {
        if self.set_root != set.root() {
            return Err(CustodyError::Succession(
                "the declaration is of another set",
            ));
        }
        if presented.is_empty() {
            return Err(CustodyError::Succession(
                "a declaration with nothing presented proves nothing",
            ));
        }
        if presented.len() >= usize::from(set.threshold()) {
            return Err(CustodyError::Succession(
                "enough shares to reconstruct is not a loss",
            ));
        }
        if presented.len() != usize::from(self.presented) {
            return Err(CustodyError::Succession(
                "the declaration does not count what was presented",
            ));
        }
        // Every presented share against the commitments the set holds. This is
        // the whole proof that the declarant has what they say: without it the
        // window could be opened by anyone with the root, which is public.
        //
        // `contains` one by one rather than `check_all`: that one refuses
        // anything below the threshold, because it exists for reconstruction.
        // Here being below the threshold is the entire point.
        //
        // The same share twice is one share counted twice: refused, or one
        // holder could declare "two left" with one (audit of 2026-10-01,
        // finding Sh-7).
        for (i, s) in presented.iter().enumerate() {
            if presented[..i].iter().any(|p| p.index == s.index) {
                return Err(CustodyError::RepeatedIndex(s.index));
            }
            set.contains(s)?;
        }

        // The owner first: a declaration the owner signed is the ordinary case
        // and gets the short window.
        let mut owner_only = KeySet::new();
        owner_only.insert(owner.clone());
        if check_envelope(
            self,
            self.v,
            &self.doc_type,
            &self.signatures,
            &owner_only,
            profile,
        )
        .is_ok()
        {
            return Ok(Window::Short);
        }

        let mut issuer_only = KeySet::new();
        issuer_only.insert(issuer.clone());
        check_envelope(
            self,
            self.v,
            &self.doc_type,
            &self.signatures,
            &issuer_only,
            profile,
        )
        .map_err(|_| {
            CustodyError::Succession(
                "the declaration is signed by neither the owner nor the issuer",
            )
        })?;
        Ok(Window::Long)
    }

    /// The hash a re-split has to name to be a re-split of this declaration.
    ///
    /// # Errors
    ///
    /// [`CustodyError::Succession`] if the declaration does not canonicalize.
    pub fn id(&self) -> Result<Hash, CustodyError> {
        doc_hash(self)
            .map_err(|_| CustodyError::Succession("the declaration does not canonicalize"))
    }
}

/// What a declaration is allowed to lead to, given how long it has stood.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// The window is still running: the missing shares may yet turn up.
    Open,
    /// The window ran out: the set may be cut anew.
    MayResplit,
}

/// Where a declaration stands after `waited_ms` of its window.
///
/// Time is passed in rather than read: this crate has no clock, and the caller
/// is the one who knows which anchors it trusts. The distance between the
/// declaration's anchor and the next one **is** the elapsed time, and neither
/// side of it is the declarant's to write.
#[must_use]
pub const fn standing(window: Window, waited_ms: u64) -> Standing {
    if waited_ms >= window.ms() {
        Standing::MayResplit
    } else {
        Standing::Open
    }
}
