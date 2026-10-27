//! Agent binding. Specification §8. **The type is part 1, validation part 2.**
//!
//! A block has **exactly one** binding; a second one is invalid — this is what
//! stops a block from being re-incarnatable and makes a stolen blank useless.
//! It is signed by the agent itself and needs no contact with the issuer.
//!
//! `agent.key` proves **continuity**, not identity: anyone can generate a key.
//! It is a pseudonym; binding it to an organization is a layer outside the core.

use serde::{Deserialize, Serialize};

use crate::canonical::{check_envelope, doc_hash, Signable};
use crate::crypto::sign::{KeySet, Profile, PublicKey, SignatureSet};
use crate::error::Invalid;

use super::BlockAllocation;

use super::{Range, Timestamp};

/// A one-time binding of a block to an agent key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentBinding {
    /// Always [`crate::doc::CONTEXT`] (spec v2 §3.3).
    #[serde(rename = "@context")]
    pub context: crate::doc::Context,
    /// Always `"AgentBinding"`.
    #[serde(rename = "type")]
    pub doc_type: String,
    /// The major core version.
    pub v: u32,
    /// The emission identifier.
    pub emission: String,
    /// The block the key is bound to.
    pub block: Range,
    /// The agent key, born inside the agent's runtime.
    pub agent: PublicKey,
    /// The moment of binding.
    pub bound_at: Timestamp,
    /// The agent's own signature.
    pub signatures: SignatureSet,
}

impl Signable for AgentBinding {
    const DOC_TYPE: &'static str = "AgentBinding";
}

impl AgentBinding {
    /// Verifies a binding (§8). **Part 2.**
    ///
    /// The agent's own signature is checked with the key from its **own**
    /// `agent` field: in that part a binding is self-attesting and needs no
    /// contact with the issuer. Uniqueness per block is checked separately
    /// ([`check_binding_uniqueness`]) — it requires visibility of every binding,
    /// not just this one.
    ///
    /// # The holder's authorization (KS-4 §4), from v2
    ///
    /// From v2 the binding must also be signed by the **holder** the packet was
    /// allocated to. Without it nothing in verification compares `agent` with
    /// `allocation.holder`, so a binding laid on someone else's packet is
    /// **accepted**: the mismatch is visible to anyone who puts the two
    /// documents side by side, and invisible to every verifier. That is the
    /// standard the project is built on — a property claimed and checked by
    /// nothing is to be counted as absent — and the authorization is what turns
    /// "an auditor could have noticed" into "a verifier rejects".
    ///
    /// `holder_keys` comes from outside for the same reason the issuer keys do:
    /// the core does not decide which key stands for a holder URI. On v1 the set
    /// is not consulted at all — an old document must not change meaning
    /// because new ones lie beside it.
    ///
    /// # Errors
    ///
    /// [`Invalid::Schema`] on a reference to a different emission or a different
    /// block, on a binding dated before its allocation, or — from v2 — on a
    /// binding not signed by both the agent and the holder;
    /// [`Invalid::Signature`] on an uncovered profile.
    pub fn validate(
        &self,
        allocation: &BlockAllocation,
        holder_keys: &KeySet,
        profile: &Profile,
    ) -> Result<(), Invalid> {
        // The version gates everything below it. A document whose version this
        // implementation cannot read must be rejected **as that**, not judged
        // against the rules of a version it does not claim: `v >= 2` is true of
        // v3 as well, and without this line a v3 binding came back diagnosed as
        // missing the holder's authorization. `check_envelope` checks the
        // version too, but it runs last, which is too late to order the errors.
        crate::version::check(self.v)?;

        if self.emission != allocation.emission {
            return Err(Invalid::Schema(
                "AgentBinding.emission is a different emission",
            ));
        }
        if self.block != allocation.block {
            return Err(Invalid::Schema("AgentBinding.block is a different block"));
        }
        // A packet cannot be bound before it was handed out: binding is done
        // with the buyer's keys, and before the purchase there is nothing to do
        // it with. Same footing as the check above — sanity, not security: a
        // holder who controls both documents can keep them consistent.
        if self.bound_at < allocation.allocated_at {
            return Err(Invalid::Schema(
                "AgentBinding.bound_at is before the allocation",
            ));
        }
        let mut keys = KeySet::new();
        keys.insert(self.agent.clone());

        if self.v >= 2 {
            // The agent's own signature. Required explicitly rather than left to
            // the envelope check: with the holder's keys now in the set, a
            // binding signed by the holder alone would otherwise pass, and a
            // holder could bind a packet to a key the agent never produced.
            if !self.signatures.signed_by(&self.agent.kid) {
                return Err(Invalid::Schema(
                    "AgentBinding is not signed by the agent it names",
                ));
            }
            // The holder's authorization. Any key of the presented set will do:
            // which key stands for the holder URI is decided a layer above, and
            // the core must not invent that mapping.
            if !self
                .signatures
                .as_slice()
                .iter()
                .any(|s| holder_keys.get(&s.kid).is_some())
            {
                return Err(Invalid::Schema(
                    "AgentBinding is not authorized by the holder of the packet",
                ));
            }
            for key in holder_keys.keys() {
                keys.insert(key.clone());
            }
        }

        check_envelope(
            self,
            self.v,
            &self.doc_type,
            &self.signatures,
            &keys,
            profile,
        )
    }
}

/// The uniqueness rule (§8 rule 1): a block has EXACTLY ONE binding.
///
/// The caller presents every known binding for this "emission + block" pair; one
/// **different** from the one presented makes the result invalid. This is what
/// stops a block from being re-incarnatable and makes a stolen blank useless.
///
/// The comparison goes by document hash, not by the block matching: otherwise a
/// list containing the binding under check would reject it as its own rival, and
/// the caller would have to clean the list by hand — that is, decide for the
/// verifier which binding is the real one.
///
/// The check was deliberately kept out of [`AgentBinding::validate`]: uniqueness
/// is not derivable from a single document, and a function pretending to have
/// derived it would be worse than none.
///
/// # Errors
///
/// [`Invalid::DuplicateBinding`] if this block carries another binding.
pub fn check_binding_uniqueness(
    known: &[AgentBinding],
    candidate: &AgentBinding,
) -> Result<Uniqueness, Invalid> {
    let mine = doc_hash(candidate)?;
    let mut saw_this_block = false;
    for b in known {
        if b.emission == candidate.emission && b.block == candidate.block {
            if doc_hash(b)? != mine {
                return Err(Invalid::DuplicateBinding);
            }
            saw_this_block = true;
        }
    }
    // An empty list, or one that holds nothing about this block, is "I have
    // seen no rival" — which is not "there is none". Returning `Ok(())` for
    // both cases let a verifier who checked nothing report the block as
    // one-time-only (security audit of 2026-09-13, finding 9).
    if saw_this_block {
        Ok(Uniqueness::Proven)
    } else {
        Ok(Uniqueness::Unknown)
    }
}

/// Whether uniqueness was **established**, as opposed to merely not refuted.
///
/// The same shape as an unread upper time bound, and for the same reason:
/// a verifier that was shown nothing must say "not known", never "proven".
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Uniqueness {
    /// The bindings of this block were presented, and this is the only one.
    Proven,
    /// Nothing was presented about this block. **Not** "there are no rivals".
    Unknown,
}
