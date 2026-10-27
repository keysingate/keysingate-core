//! Building the agent's key set from the inclusion chain. Specification KS-1.
//!
//! The set grows and never shrinks. Every key that ever entered it stays valid,
//! so an act signed by K1 verifies while the set already holds K121.
//!
//! Walking the chain is the only way into the set: there is no direct link from
//! K1 to K3, and no way to skip a link. One link that does not resolve refuses
//! the whole chain, and the refusal names **which** link — see
//! [`ChainFail`].

use crate::canonical::doc_hash;
use crate::crypto::sign::{KeySet, Profile, PublicKey};
use crate::doc::{AgentBinding, KeyInclusion};
use crate::error::{ChainFail, Invalid};

/// Builds the agent's key set from the binding and the chain of inclusions.
///
/// An empty slice of inclusions is a correct input, not missing data: an agent
/// that never added a key has no chain, and its set is the binding key alone.
/// That is also exactly the v1 behaviour.
///
/// # Order of the checks
///
/// Chain position is checked **before** the signature. A break is the earlier
/// and the more intelligible cause, and diagnostics must name it rather than
/// report a signature that could not have matched anyway.
///
/// # Errors
///
/// [`Invalid::KeyChain`] naming the link: [`ChainFail::Foreign`] for a link of
/// another emission or block, [`ChainFail::Break`] when it does not follow its
/// predecessor, [`ChainFail::Signature`] when the predecessor's key does not
/// cover it, [`ChainFail::Duplicate`] for a key already in the set.
pub fn build_key_set(
    binding: &AgentBinding,
    inclusions: &[KeyInclusion],
    profile: &Profile,
) -> Result<KeySet, Invalid> {
    crate::limits::at_most(
        inclusions.len(),
        crate::limits::MAX_KEY_INCLUSIONS,
        "key inclusions",
    )?;
    let mut keys = KeySet::new();
    keys.insert(binding.agent.clone());

    let mut prev_hash = doc_hash(binding)?;
    let mut prev_key: PublicKey = binding.agent.clone();

    for (link, inc) in inclusions.iter().enumerate() {
        if inc.emission != binding.emission || inc.block != binding.block {
            return Err(Invalid::KeyChain(ChainFail::Foreign { link }));
        }
        if inc.predecessor != prev_hash {
            return Err(Invalid::KeyChain(ChainFail::Break { link }));
        }
        inc.validate(&prev_key, profile)
            .map_err(|_| Invalid::KeyChain(ChainFail::Signature { link }))?;
        if keys.get(&inc.key.kid).is_some() {
            // Re-including the same `kid` is not dangerous, it is meaningless,
            // and it points at a defect in whoever built the chain. Accepting it
            // silently would hide that defect.
            return Err(Invalid::KeyChain(ChainFail::Duplicate { link }));
        }

        keys.insert(inc.key.clone());
        prev_hash = doc_hash(inc)?;
        prev_key = inc.key.clone();
    }

    Ok(keys)
}

/// The key of the set that actually signed the document, if any.
///
/// Used for the report's `author_key`: on a chain, the author is the key that
/// signed, not the key the chain is rooted at. A verifier that reported the
/// root would name a key the record was not signed with.
#[must_use]
pub fn signing_key(
    signatures: &crate::crypto::sign::SignatureSet,
    keys: &KeySet,
) -> Option<PublicKey> {
    signatures
        .as_slice()
        .iter()
        .find_map(|s| keys.get(&s.kid).cloned())
}
