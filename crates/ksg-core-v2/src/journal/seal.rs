//! The seals of the bound journal.
//!
//! | Seal | Who | Removed? | Decision |
//! |---|---|---|---|
//! | [`Seal`] — the movable one | the current agent; Ed25519 **and** ML-DSA-65 | yes: moved to the next record | CH-2, CH-5 |
//! | [`TransferSeal`] — of a hand-off or a change of owner | agent/agent, or agent+owner / agent+owner | never | CH-3, CH-15 |
//! | [`CoSeal`] — the owner's second seal | the owner | never | CH-9, CH-19, CH-20 |

use serde::{Deserialize, Serialize};

use crate::canonical::{doc_hash, Signable};
use crate::crypto::hash::Hash;
use crate::crypto::sign::SignatureSet;
use crate::doc::Uri;

use super::page::{Mode, Party};

/// How many pages of each zone are written (CH-13: the number of the seal is
/// all of them together).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Counts {
    /// Working pages.
    pub work: u64,
    /// Pages of sales and transfers between owners.
    pub transfer: u64,
    /// Pages of the coupling.
    pub coupling: u64,
}

/// The movable seal.
///
/// "After the record the page is turned over and sealed with a seal bearing
/// the key and the signature; at the next record the seal is lifted, the page
/// turned, and the same seal put on again with number 2" (CH-2). Each record
/// has one: its number is the record's last page, and it covers every page
/// before it through the chain and the tree.
///
/// **Every field is derived from the pages.** A verifier holding the pages
/// recomputes every seal that was ever put on — the lifted ones included —
/// which is what lets an owner's second seal and a Pro anchor be checked long
/// after the seal they were given to has moved on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Seal {
    /// Always [`crate::doc::CONTEXT`] (spec v2 §3.3).
    #[serde(rename = "@context")]
    pub context: crate::doc::Context,
    /// Always `"JournalSeal"`.
    #[serde(rename = "type")]
    pub doc_type: String,
    /// The major core version.
    pub v: u32,
    /// The container.
    pub container: Hash,
    /// The seal's number: the last page it covers (CH-13).
    pub number: u64,
    /// The record it seals.
    pub batch: u64,
    /// The hash of page `number`.
    pub head: Hash,
    /// RFC 6962 root over the hashes of pages `0..=number`.
    pub root: Hash,
    /// Pages written in each zone.
    pub counts: Counts,
    /// The agent whose seal this is.
    pub agent: Uri,
    /// The owner at this moment.
    pub owner: Uri,
    /// The rule of two seals in force after this record, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<Hash>,
    /// The form after this record. A Pro seal is anchored (CH-7).
    pub mode: Mode,
    /// The previous seal, lifted to put this one on; absent for the first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev: Option<Hash>,
    /// The record's time mark.
    pub offset_ms: u64,
    /// The agent's signatures: Ed25519 and ML-DSA-65.
    pub signatures: SignatureSet,
}

impl Signable for Seal {
    const DOC_TYPE: &'static str = "JournalSeal";
}

impl Seal {
    /// The value of `type`.
    pub const TYPE: &'static str = "JournalSeal";

    /// The seal's hash — what an anchor attests and what the next seal links
    /// to. Signatures are outside it, so it is known before anyone signs.
    ///
    /// # Errors
    ///
    /// [`crate::error::Invalid::Canonicalization`].
    pub fn hash(&self) -> Result<Hash, crate::error::Invalid> {
        doc_hash(self)
    }
}

/// Which kind of transfer a transfer page records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferKind {
    /// To another agent of the same owner: a working page, sealed agent/agent,
    /// no owner (CH-15, CH-16).
    Handoff,
    /// To another owner — a sale, or a transfer between owners: a page of the
    /// transfer zone, sealed agent+owner / agent+owner (CH-14, CH-15).
    OwnerChange,
}

/// A transfer page.
///
/// It pins the keys of whoever takes over. The new agent **replaces** the old
/// one (CH-17): the movable seal after this page is the new agent's alone, and
/// the old agent's keys no longer seal anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferRecord {
    /// Which kind.
    pub kind: TransferKind,
    /// The agent handing over.
    pub from_agent: Uri,
    /// The agent taking over, with its keys.
    pub to_agent: Party,
    /// The owner handing over — only for a change of owner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_owner: Option<Uri>,
    /// The owner taking over, with its keys — only for a change of owner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_owner: Option<Party>,
    /// The terms of the transfer, by digest, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terms: Option<Hash>,
}

/// The seal of a transfer page — never removed.
///
/// What is signed is the transfer page's hash: the page pins the new keys, so
/// the signatures cover them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferSeal {
    /// Always [`crate::doc::CONTEXT`] (spec v2 §3.3).
    #[serde(rename = "@context")]
    pub context: crate::doc::Context,
    /// Always `"TransferSeal"`.
    #[serde(rename = "type")]
    pub doc_type: String,
    /// The major core version.
    pub v: u32,
    /// The transfer page.
    pub page: u64,
    /// Its hash.
    pub subject: Hash,
    /// agent/agent, or agent+owner / agent+owner.
    pub signatures: SignatureSet,
}

impl Signable for TransferSeal {
    const DOC_TYPE: &'static str = "TransferSeal";
}

impl TransferSeal {
    /// The value of `type`.
    pub const TYPE: &'static str = "TransferSeal";
}

/// The owner's second seal over a record the rule of two seals covers.
///
/// Never removed: the movable seal it was given to moves on, but every field
/// of that seal is derived from the pages, so the verifier recomputes it and
/// checks this against it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoSeal {
    /// Always [`crate::doc::CONTEXT`] (spec v2 §3.3).
    #[serde(rename = "@context")]
    pub context: crate::doc::Context,
    /// Always `"CoSeal"`.
    #[serde(rename = "type")]
    pub doc_type: String,
    /// The major core version.
    pub v: u32,
    /// The record.
    pub batch: u64,
    /// The hash of the movable seal put on that record.
    pub subject: Hash,
    /// The owner's signatures.
    pub signatures: SignatureSet,
}

impl Signable for CoSeal {
    const DOC_TYPE: &'static str = "CoSeal";
}

impl CoSeal {
    /// The value of `type`.
    pub const TYPE: &'static str = "CoSeal";
}

/// What the rule of two seals covers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleScope {
    /// Every record of content.
    All,
    /// Records of these content types (CH-19).
    Types(Vec<Uri>),
    /// Nothing: the rule is lifted.
    Lifted,
}

/// A page of the rule of two seals (CH-19, variant A: its own page, so the
/// rule is an event in the journal).
///
/// Setting it and lifting it both take the owner's second seal: an agent alone
/// cannot lift a rule that exists to bind it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealRule {
    /// What it covers.
    pub scope: RuleScope,
}

impl SealRule {
    /// Whether a record of this content type is covered.
    #[must_use]
    pub fn covers(&self, content_type: Option<&Uri>) -> bool {
        match &self.scope {
            RuleScope::All => true,
            RuleScope::Types(types) => content_type.is_some_and(|t| types.contains(t)),
            RuleScope::Lifted => false,
        }
    }
}

/// A page of the coupling of containers (CH-12).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum CouplingRecord {
    /// Slot 1: this container is attached, as the trailer, to a leading one.
    AttachedTo {
        /// The leading container.
        leader: Hash,
    },
    /// Slot 2: this container pulls a trailer.
    Pulls {
        /// The trailing container.
        trailer: Hash,
        /// The trailer's last seal.
        trailer_seal: Hash,
    },
}

impl CouplingRecord {
    /// The slot of the coupling zone this record occupies.
    #[must_use]
    pub const fn slot(&self) -> u64 {
        match self {
            Self::AttachedTo { .. } => 1,
            Self::Pulls { .. } => 2,
        }
    }
}
