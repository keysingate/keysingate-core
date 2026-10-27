//! The dispute: the copy of the claim, the review deadline, the settlement.
//! KS-2 §6, KS-7 §7.2, `[decision]` 10.09 and 12.09.
//!
//! # Without a copy of the claim, a 30 is nothing
//!
//! `[decision] 12.09`, the owner: "a copy of the claim must be filed; without it a 30 is nothing".
//!
//! That is the rule this module exists for. Before it, status 30 could be
//! reached by handing the container an anchored statement that somebody was
//! contesting something — and a statement is cheap. A **copy of the claim**
//! is not: it is dated, it names the court, and the court has set a hearing.
//!
//! `[inference]` The container reads none of it. It holds the **digest** of the copy and
//! the two moments the copy states, and refuses a 30 that carries neither. What
//! it gains is not knowledge of the claim but the impossibility of a dispute
//! nobody filed.
//!
//! # The deadline comes from the jurisdiction, empirically
//!
//! `[decision] 12.09` The term is `(filing → decision) + (time allowed for an appeal)`,
//! taken from the jurisdiction the claim was filed in. It is **stated in the
//! record**, not computed here: jurisdictions differ, they change, and a table
//! of them inside a container would be wrong somewhere on the day it was
//! written.
//!
//! `[inference]` What is checkable without knowing any jurisdiction is the **shape** of
//! the statement — filed, then heard, then the deadline — and that is what
//! [`Filing::validate`] checks. A deadline before the hearing is not a term of
//! any jurisdiction; it is a typo or a lie, and either way it does not stand.
//!
//! # What the clock runs on
//!
//! Every moment here is an **offset in milliseconds from the packet's origin**,
//! the one frame the whole container already uses (KS-2 §2, `[decision]` 10.09).
//!
//! `?` `[decision] 12.09` said "origin point 0 is the release/issue creation time",
//! while `[decision] 10.09` fixed the origin at the **packet's** date-time. The two
//! differ by the interval between a release and the sale of a packet out of it.
//! **For this mechanism it changes nothing** — the deadline runs from the moment
//! 30 arose, and every moment is in one frame either way — so the existing frame
//! is kept and the discrepancy is named rather than silently resolved.
//!
//! # Silence costs the silent
//!
//! If none of 31, 32, 34 or 35 arrives before the deadline, the container
//! **blocks itself**. `[decision] 10.09`: "the mechanism is a timer, not goodwill".
//!
//! Twelve years blocked and it dies of prescription (`[decision]` 12.09). Not because
//! anything was decided — because nothing was, for long enough that nothing
//! ever will be.

use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::status::{Event, Status};

/// Twelve years, in milliseconds. `[decision] 12.09`
///
/// `[inference]` The number is the owner's and the reason is plain: a dispute nobody
/// moved for twelve years is not a dispute anybody is going to move. It is far
/// longer than any jurisdiction's limitation period, which is the point — the
/// container outlasts the argument rather than joining it.
pub const PRESCRIPTION_MS: u64 = 12 * 365 * 24 * 60 * 60 * 1000;

/// What can be wrong with a dispute's paperwork.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DisputeError {
    /// A dispute handed in without the copy of the claim.
    #[error("a dispute takes a copy of the claim; without one a 30 is nothing")]
    NoClaim,
    /// The stated moments are not in order.
    #[error("filed, heard, deadline must run in that order")]
    OutOfOrder,
    /// The jurisdiction was not named.
    #[error("the term comes from a jurisdiction, and the record does not name one")]
    NoJurisdiction,
    /// The deadline has not been reached.
    #[error("the review deadline has not passed: {at} is before {deadline}")]
    TooEarly {
        /// The moment presented.
        at: u64,
        /// The deadline the filing states.
        deadline: u64,
    },
    /// Twelve years have not passed.
    #[error("the container has been blocked for less than twelve years")]
    NotPrescribed,
}

/// The copy of the claim and the term it sets. Handed in with a 30.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Filing {
    /// The digest of the copy of the claim. The container never reads it.
    pub claim: Hash,
    /// Which jurisdiction's terms were used. Opaque, and named so that a reader
    /// can check the term against that jurisdiction rather than take it on
    /// trust.
    pub jurisdiction: String,
    /// When the claim was filed, as an offset from the packet's origin.
    pub filed_ms: u64,
    /// The hearing the court appointed, same frame.
    pub hearing_ms: u64,
    /// **The review deadline**: filing → decision → the time allowed to appeal.
    ///
    /// Until this moment the container waits for 31, 32, 34 or 35. After it,
    /// silence blocks the container.
    pub deadline_ms: u64,
}

impl Filing {
    /// The value the parties sign and the chain anchors.
    #[must_use]
    pub fn subject(&self, container: &Hash) -> Hash {
        Hash::sha256_fields(&[
            b"ksg:dispute-filing:v1",
            container.as_bytes(),
            self.claim.as_bytes(),
            self.jurisdiction.as_bytes(),
            &self.filed_ms.to_be_bytes(),
            &self.hearing_ms.to_be_bytes(),
            &self.deadline_ms.to_be_bytes(),
        ])
    }

    /// Whether this filing is one a container will accept a 30 on.
    ///
    /// # Errors
    ///
    /// [`DisputeError::NoClaim`] for an empty digest — the copy of the claim is
    /// the whole substance of the rule; [`DisputeError::NoJurisdiction`] when
    /// the term is stated with no source; [`DisputeError::OutOfOrder`] when the
    /// three moments do not run forward.
    pub fn validate(&self) -> Result<(), DisputeError> {
        if self.claim == Hash::sha256(b"") {
            return Err(DisputeError::NoClaim);
        }
        if self.jurisdiction.trim().is_empty() {
            return Err(DisputeError::NoJurisdiction);
        }
        // Equality is allowed between filing and hearing — some jurisdictions
        // hear on the day — but the deadline must be strictly past the hearing,
        // or there is no term at all.
        if self.filed_ms > self.hearing_ms || self.deadline_ms <= self.hearing_ms {
            return Err(DisputeError::OutOfOrder);
        }
        Ok(())
    }

    /// Whether the review deadline has passed at this moment.
    ///
    /// Returns the event to record, so that "the deadline passed" is something
    /// the record shows rather than something a caller asserts.
    ///
    /// # Errors
    ///
    /// [`DisputeError::TooEarly`] before the deadline. That is the half that
    /// matters: without it, blocking a container would be available to anyone
    /// who pressed the button early.
    pub const fn deadline_passed(&self, at_ms: u64) -> Result<Event, DisputeError> {
        if at_ms >= self.deadline_ms {
            Ok(Event::ReviewDeadlinePassed)
        } else {
            Err(DisputeError::TooEarly {
                at: at_ms,
                deadline: self.deadline_ms,
            })
        }
    }

    /// The moment at which a blocked container dies of prescription.
    #[must_use]
    pub const fn prescribed_at(&self) -> u64 {
        self.deadline_ms + PRESCRIPTION_MS
    }

    /// Whether twelve years have passed since the deadline.
    ///
    /// # Errors
    ///
    /// [`DisputeError::NotPrescribed`] before that.
    pub const fn prescribed(&self, at_ms: u64) -> Result<Event, DisputeError> {
        if at_ms >= self.prescribed_at() {
            Ok(Event::PrescriptionPassed)
        } else {
            Err(DisputeError::NotPrescribed)
        }
    }

    /// The statuses whose arrival before the deadline keeps the container out
    /// of the block.
    ///
    /// `[decision] 12.09` — four ways out, and the fourth is new: the two sides
    /// settling. Kept as a function rather than as prose so that adding a fifth
    /// is one edit rather than a search.
    #[must_use]
    pub const fn resolves(status: Status) -> bool {
        matches!(
            status,
            Status::DisputeProven | Status::DisputeUnproven | Status::Appealed | Status::Settled
        )
    }
}

/// The two sides settling — status 35. `[decision] 12.09`
///
/// # What is recorded, and what deliberately is not
///
/// "Shook hands on it": the rights may stay where they are, may pass, may become
/// shared, may be split in any way the two of them wrote down. `[decision]` That is
/// **their private business** and it is not published.
///
/// So the container holds the **digest of the terms** and nothing else. Either
/// side can later show the terms and have the digest confirm them; nobody
/// learns them from the container, and the container cannot be made to say what
/// was agreed because it does not know.
///
/// `[inference]` **And no arbiter signs.** That is the difference between 35 and a
/// decision: a settlement is the parties' own act, and requiring a third party
/// would turn "shook hands on it" into a small trial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settlement {
    /// The digest of what was agreed. Never the terms.
    pub terms: Hash,
    /// When, in the container's frame.
    pub at_ms: u64,
}

impl Settlement {
    /// The value the two sides sign.
    #[must_use]
    pub fn subject(&self, container: &Hash, claim: &Hash) -> Hash {
        Hash::sha256_fields(&[
            b"ksg:dispute-settlement:v1",
            container.as_bytes(),
            claim.as_bytes(),
            self.terms.as_bytes(),
            &self.at_ms.to_be_bytes(),
        ])
    }

    /// Whether the settlement landed before the review deadline.
    ///
    /// A settlement after the block is still a settlement — it is one of the
    /// four ways out — but only one before the deadline keeps the container from
    /// blocking at all, and a reader is entitled to tell the two apart.
    #[must_use]
    pub const fn in_time(&self, filing: &Filing) -> bool {
        self.at_ms < filing.deadline_ms
    }
}
