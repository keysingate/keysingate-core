//! The list of an agent's blocks, signed by the issuer. Specification KS-1 §13.
//!
//! In core v1 this was a core document (`ksg_core::doc::history`). Core v2
//! leaves it out (spec v2 §17): it is the issuer's statement about its own
//! records, verified against the issuer's signature and nothing else, so it
//! lives with the issuer. The rules of v3 still hold: `@context`, `v` = 3, a
//! closed set of fields.
//!
//! # The gap this closes, and the one it opens
//!
//! Inside one block the completeness of an agent's history is held by the
//! consecutive serials: a missing work is a missing number, and the number is
//! there. **Between** blocks nothing holds it. That the agent had an earlier
//! block is not visible from the container, and "the agent's whole history" is
//! one of the things that is sold.
//!
//! `[decision] 2026-09-19` (CT-31, variant A): the issuer signs a list — these blocks
//! belong to this agent — and the blocks become one chain.
//!
//! The price is named here rather than hidden: a verifier who relies on this
//! document must trust **the issuer's** signature, and elsewhere the product
//! rests on the opposite (a proof is arithmetic; our availability is not
//! needed). So the document is **additional**, never required: a container
//! verifies exactly as before without one, and only the claim "the whole
//! history, across blocks" leans on it.
//!
//! # Why the allocation hash and not the range alone
//!
//! A range is a pair of numbers and says nothing about which release handed it
//! out or on what terms. The entry therefore carries the hash of the
//! [`BlockAllocation`](ksg_core_v2::doc::BlockAllocation) itself, and the verifier that
//! holds the allocation can check it is the same document rather than one with
//! the same bounds.

use serde::{Deserialize, Serialize};

use ksg_core_v2::canonical::{check_envelope, Signable};
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{KeySet, Profile, PublicKey, SignatureSet};
use ksg_core_v2::doc::{Range, Timestamp, Uri};
use ksg_core_v2::error::Invalid;

/// One block in an agent's history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryEntry {
    /// The emission the block was issued inside.
    pub emission: String,
    /// The block's subrange.
    pub block: Range,
    /// The hash of the `BlockAllocation` that handed it out.
    pub allocation: Hash,
}

/// The issuer's signed list of the blocks belonging to one agent (KS-1 §13).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentHistory {
    /// Always [`ksg_core_v2::doc::CONTEXT`] (spec v2 §3.3).
    #[serde(rename = "@context")]
    pub context: ksg_core_v2::doc::Context,
    /// Always `"AgentHistory"`.
    #[serde(rename = "type")]
    pub doc_type: String,
    /// The major core version.
    pub v: u32,
    /// The holder the blocks were allocated to.
    pub holder: Uri,
    /// The agent key the blocks are bound to.
    pub agent: PublicKey,
    /// The blocks, oldest first.
    pub blocks: Vec<HistoryEntry>,
    /// When the issuer drew the list up.
    pub issued_at: Timestamp,
    /// The issuer's signature. One party: this is the issuer's statement about
    /// its own records, and nobody else is in a position to make it.
    pub signatures: SignatureSet,
}

impl Signable for AgentHistory {
    const DOC_TYPE: &'static str = "AgentHistory";
}

impl AgentHistory {
    /// Verifies the list as a document (KS-1 §13). **Part 2.**
    ///
    /// What is checked here is that the list is internally a list: it names an
    /// agent, it is not empty, its entries are in order, and no block appears
    /// twice. Whether the issuer told the truth about its own records is not
    /// checkable from the document and is not claimed to be — see the module
    /// note on what this document costs.
    ///
    /// # Errors
    ///
    /// [`Invalid::Schema`] if the list is empty, if it names another holder or
    /// agent, if two entries of one emission overlap or run backwards, or if an
    /// allocation hash repeats; [`Invalid::Signature`] on an uncovered profile.
    pub fn validate(
        &self,
        holder: &Uri,
        agent: &PublicKey,
        keys: &KeySet,
        profile: &Profile,
    ) -> Result<(), Invalid> {
        if self.blocks.is_empty() {
            return Err(Invalid::Schema("AgentHistory lists no blocks"));
        }
        if &self.holder != holder {
            return Err(Invalid::Schema("AgentHistory names another holder"));
        }
        if &self.agent != agent {
            return Err(Invalid::Schema("AgentHistory names another agent"));
        }
        for (i, e) in self.blocks.iter().enumerate() {
            if e.block.to.0 < e.block.from.0 {
                return Err(Invalid::Schema("AgentHistory holds an inverted block"));
            }
            // A repeated allocation would let one block be counted twice and
            // make a short history look long — the one thing a list of blocks
            // is read for.
            if self.blocks[..i]
                .iter()
                .any(|p| p.allocation == e.allocation)
            {
                return Err(Invalid::Schema("AgentHistory repeats a block"));
            }
            // Order is checked within an emission only: two releases number
            // independently, and comparing their serials would be comparing
            // different scales.
            if let Some(prev) = self.blocks[..i]
                .iter()
                .rev()
                .find(|p| p.emission == e.emission)
            {
                if e.block.from.0 <= prev.block.to.0 {
                    return Err(Invalid::Schema(
                        "AgentHistory blocks of one emission overlap or run backwards",
                    ));
                }
            }
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

    /// Whether the list covers this allocation.
    ///
    /// The question a verifier actually asks: I hold a container whose block
    /// was allocated by *this* document — is it one of the agent's?
    #[must_use]
    pub fn covers(&self, allocation: &Hash) -> bool {
        self.blocks.iter().any(|e| &e.allocation == allocation)
    }

    /// The number of serials across every block listed.
    ///
    /// Saturating, for the same reason [`Range::len`](ksg_core_v2::doc::Range::len) is:
    /// the list is reachable from untrusted JSON, and a total that wrapped to a
    /// small number would read as a short history.
    #[must_use]
    pub fn serials(&self) -> u64 {
        self.blocks
            .iter()
            .fold(0u64, |acc, e| acc.saturating_add(e.block.len()))
    }
}
