//! The basis for an action, and the key that confirms it. KS-8 C-7.
//!
//! # Why an action needs a basis at all
//!
//! `[decision] 04.09`: processing or creating an artefact is done **on some grounds**,
//! and the grounds are attached. Four of them, and nothing else:
//!
//! | Basis | What is recorded |
//! |---|---|
//! | the **owner** | the owner's order |
//! | an **orchestrator** — another agent | the orchestrator's order |
//! | a **protocol** | the substance of the protocol |
//! | the agent's **own initiative** | **on what grounds** — a short justification |
//!
//! `[decision]` All of it is journal entries, and **every order is somebody's and is
//! confirmed by keys**.
//!
//! `[inference]` What this closes is the substitution of intent: **a divergence between
//! the order and what was done becomes visible.** Not prevented — visible. That
//! distinction is the honest one, and this module holds to it: nothing here reads
//! an artefact or judges whether the work matched its instruction. What it does is
//! make the pair inspectable and refuse the shapes that could never be inspected.
//!
//! # What is checkable and what is not
//!
//! | Checkable | Not |
//! |---|---|
//! | the basis names a party, and **that party signed** | whether the work served the order |
//! | own initiative carries a **non-empty** justification | whether the justification is any good |
//! | a record of work **points at** an order, or is marked as having none | |
//!
//! `[inference]` The second column is not a gap to be filled later. A container cannot
//! read the artefact (F-7 makes the issuer the blindest party, and the container
//! itself reads nothing), so a rule about whether work matched an instruction
//! would be a rule nobody can apply. A property nothing checks is a property that
//! is absent — better to name the pair and let a human read it.

use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{KeySet, Profile, PublicKey, SignatureSet};
use ksg_core_v2::doc::Uri;

use crate::command::Roster;
use crate::operation::Role;

/// What can go wrong with an order.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OrderError {
    /// The basis names a party that did not sign.
    #[error("an order on the basis of {basis:?} must be signed by that party")]
    WrongParty {
        /// The basis claimed.
        basis: BasisKind,
    },
    /// Own initiative with nothing said about why.
    #[error("own initiative is a basis only with a stated reason")]
    NoReason,
    /// A protocol cited by name only, with no substance.
    #[error("a protocol is a basis only with its substance recorded")]
    NoSubstance,
    /// A signature did not verify.
    #[error("the order's signature did not verify")]
    Signature,
    /// The signer holds no role the container knows.
    #[error("{0} signed the order, and the container knows no role for that key")]
    NoRole(Uri),
    /// The work points at an order that is not this one.
    #[error("the work cites another order")]
    OtherOrder,
}

/// Which of the four grounds, without its content — for error messages and for
/// asking questions of a basis without matching on its payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BasisKind {
    /// The owner's order.
    Owner,
    /// An orchestrator's order.
    Orchestrator,
    /// A protocol.
    Protocol,
    /// The agent's own initiative.
    OwnInitiative,
}

impl BasisKind {
    /// The role whose signature an order on this basis must carry.
    ///
    /// A protocol and own initiative are both the **client's** act: a protocol is
    /// not a party and cannot sign, so what is recorded is the client saying which
    /// protocol it acted under. Pretending a protocol signs would invent a
    /// signatory, and inventing one is how "confirmed by keys" turns into a phrase.
    #[must_use]
    pub const fn signer(self) -> Role {
        match self {
            Self::Owner => Role::Owner,
            Self::Orchestrator => Role::Orchestrator,
            Self::Protocol | Self::OwnInitiative => Role::Client,
        }
    }
}

/// The grounds an action was taken on, with what each one has to carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Basis {
    /// The owner ordered it.
    Owner,
    /// An orchestrator ordered it.
    Orchestrator,
    /// A protocol applies, and its substance is recorded — not merely its name.
    Protocol {
        /// The substance. `[decision]` C-7 says "the substance of the protocol", so a bare name is not
        /// enough: a name is a pointer to a document the container cannot read.
        substance: String,
    },
    /// The agent acted on its own, and says on what grounds.
    OwnInitiative {
        /// The short justification C-7 requires.
        reason: String,
    },
}

impl Basis {
    /// Which of the four this is.
    #[must_use]
    pub const fn kind(&self) -> BasisKind {
        match self {
            Self::Owner => BasisKind::Owner,
            Self::Orchestrator => BasisKind::Orchestrator,
            Self::Protocol { .. } => BasisKind::Protocol,
            Self::OwnInitiative { .. } => BasisKind::OwnInitiative,
        }
    }
}

/// An order, attached and signed. KS-8 E-7.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Order {
    /// The container this order is for.
    pub container: Hash,
    /// The grounds.
    pub basis: Basis,
    /// What was asked for, as the parties stated it. Opaque here.
    pub instruction: String,
    /// The signature of the party the basis names.
    pub signatures: SignatureSet,
}

impl Order {
    /// The value the signature covers.
    #[must_use]
    pub fn subject(&self) -> Hash {
        let kind = format!("{:?}", self.basis.kind());
        let detail = match &self.basis {
            Basis::Protocol { substance } => substance.as_str(),
            Basis::OwnInitiative { reason } => reason.as_str(),
            Basis::Owner | Basis::Orchestrator => "",
        };
        Hash::sha256_fields(&[
            b"ksg:order:v1",
            self.container.as_bytes(),
            kind.as_bytes(),
            detail.as_bytes(),
            self.instruction.as_bytes(),
        ])
    }

    /// The digest by which a record of work cites this order.
    #[must_use]
    pub fn id(&self) -> Hash {
        self.subject()
    }

    /// Whether the order is one the container will record.
    ///
    /// # Errors
    ///
    /// [`OrderError::NoSubstance`] or [`OrderError::NoReason`] for a basis that
    /// carries nothing; [`OrderError::NoRole`] for a signer with no role;
    /// [`OrderError::WrongParty`] when the signer's role is not the one the basis
    /// names; [`OrderError::Signature`] when it does not verify.
    pub fn validate(
        &self,
        roster: &Roster,
        keys: &KeySet,
        profile: &Profile,
    ) -> Result<(), OrderError> {
        match &self.basis {
            Basis::Protocol { substance } if substance.trim().is_empty() => {
                return Err(OrderError::NoSubstance)
            }
            Basis::OwnInitiative { reason } if reason.trim().is_empty() => {
                return Err(OrderError::NoReason)
            }
            _ => {}
        }

        let wanted = self.basis.kind().signer();
        let signed_by_the_right_party = self
            .signatures
            .signers()
            .into_iter()
            .map(|kid| {
                roster
                    .roles_of(kid)
                    .into_iter()
                    .any(|r| r == wanted)
                    .then_some(())
                    .ok_or_else(|| kid.clone())
            })
            .any(|r| r.is_ok());
        if !signed_by_the_right_party {
            // Distinguish "signed by a stranger" from "signed by the wrong one of
            // ours": the first is a key the container cannot place at all, and a
            // presenter fixes the two differently.
            if let Some(stranger) = self
                .signatures
                .signers()
                .into_iter()
                .find(|kid| roster.role_of(kid).is_none())
            {
                return Err(OrderError::NoRole(stranger.clone()));
            }
            return Err(OrderError::WrongParty {
                basis: self.basis.kind(),
            });
        }

        // Against the keys the container pinned (audit of 2026-09-23, K1).
        let trusted = roster.trusted(keys).map_err(|_| OrderError::Signature)?;
        self.signatures
            .verify(self.subject().as_bytes(), trusted, profile)
            .map_err(|_| OrderError::Signature)
    }
}

/// What was done, and under which order — the pair C-7 makes inspectable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Work {
    /// The container.
    pub container: Hash,
    /// The order this cites, or `None`.
    ///
    /// **`Option`, and not a lie either way.** Work with no order happens — an
    /// agent acting on its own is one of the four bases — and the way C-7 handles
    /// it is to make it *say so*, with a justification. What must never be
    /// possible is work that quietly implies an order it does not have.
    pub under: Option<Hash>,
    /// What was done, as the agent recorded it. Opaque here.
    pub did: String,
    /// The agent's signature.
    pub signatures: SignatureSet,
}

impl Work {
    /// Whether this record of work and that order belong together.
    ///
    /// **This is not a check that the work served the order** — nothing here can
    /// read either. It checks that the pair is the pair being claimed, which is
    /// what makes a divergence visible to somebody who *can* read them.
    ///
    /// # Errors
    ///
    /// [`OrderError::OtherOrder`] when the work cites a different order or none.
    pub fn under_order(&self, order: &Order) -> Result<(), OrderError> {
        match self.under {
            Some(id) if id == order.id() => Ok(()),
            _ => Err(OrderError::OtherOrder),
        }
    }

    /// Whether this work stands on its own account.
    ///
    /// True when no order is cited. A reader sees it immediately, which is the
    /// whole mechanism: the divergence between an instruction and what was done
    /// becomes **visible**, and so does the absence of an instruction.
    #[must_use]
    pub const fn on_own_account(&self) -> bool {
        self.under.is_none()
    }

    /// The value the agent's signature covers.
    #[must_use]
    pub fn subject(&self) -> Hash {
        let under = self.under.map_or_else(Vec::new, |h| h.as_bytes().to_vec());
        Hash::sha256_fields(&[
            b"ksg:work:v1",
            self.container.as_bytes(),
            &under,
            self.did.as_bytes(),
        ])
    }

    /// Whether the work is signed by the client it claims to be from.
    ///
    /// # Errors
    ///
    /// [`OrderError::WrongParty`] when no client signed;
    /// [`OrderError::Signature`] when a signature does not verify.
    pub fn validate(
        &self,
        roster: &Roster,
        keys: &KeySet,
        profile: &Profile,
        expected: &PublicKey,
    ) -> Result<(), OrderError> {
        if !self.signatures.signed_by(&expected.kid) {
            return Err(OrderError::WrongParty {
                basis: BasisKind::OwnInitiative,
            });
        }
        if !roster.holds(expected, Role::Client) {
            return Err(OrderError::WrongParty {
                basis: BasisKind::OwnInitiative,
            });
        }
        // Against the keys the container pinned (audit of 2026-09-23, K1).
        let trusted = roster.trusted(keys).map_err(|_| OrderError::Signature)?;
        self.signatures
            .verify(self.subject().as_bytes(), trusted, profile)
            .map_err(|_| OrderError::Signature)
    }
}
