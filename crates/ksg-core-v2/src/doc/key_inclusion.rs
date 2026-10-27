//! Inclusion of a key into the agent's key set. Specification KS-1.
//!
//! An agent key is **not replaced**. A new key is laid **on top of** the
//! previous one: K2 on K1, K3 on K2. Every key in the set stays valid, and
//! nothing is revoked.
//!
//! # What to call this, and what not to
//!
//! The **linkage** is a chain: links are joined by the `predecessor` hash and
//! are checked one at a time. The **result** is a set of simultaneously valid
//! keys, a layer on top of a layer.
//!
//! The words *succession*, *inheritance*, *rotation* and *replacement* are
//! wrong here: each implies that only the latest key is in force. An act
//! signed by K1 stays valid when the set already holds K121. The chain is a way
//! to prove membership of the set, not an order of succession.
//!
//! An implementation that read "succession" and checked only the last link
//! would pass its own tests and start rejecting valid acts under older
//! keys.

use serde::{Deserialize, Serialize};

use crate::canonical::{check_envelope, Signable};
use crate::crypto::hash::Hash;
use crate::crypto::sign::{KeySet, Profile, PublicKey, SignatureSet};
use crate::error::Invalid;

use super::Range;

/// One link of the inclusion chain: a key laid on top of the previous one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyInclusion {
    /// Always [`crate::doc::CONTEXT`] (spec v2 §3.3).
    #[serde(rename = "@context")]
    pub context: crate::doc::Context,
    /// Always `"KeyInclusion"`.
    #[serde(rename = "type")]
    pub doc_type: String,
    /// The major core version. Introduced in v2.
    pub v: u32,
    /// The emission identifier.
    pub emission: String,
    /// The block the key set belongs to.
    pub block: Range,
    /// The hash of the previous link: the [`super::AgentBinding`] for the first
    /// inclusion, the previous `KeyInclusion` after that.
    ///
    /// A hash rather than a `kid`: the hash pins the whole previous link — its
    /// key, its offset and its signatures. A reference by `kid` would pin only
    /// the key's name, leaving the rest of the link substitutable without
    /// breaking the chain. The same device is already used by
    /// `ContainerInit.binding` and `prev_closure`.
    pub predecessor: Hash,
    /// The key being added.
    pub key: PublicKey,
    /// Milliseconds since the container's genesis (KS-2).
    ///
    /// Not a timestamp and MUST NOT be displayed as a date: without anchors it
    /// does not convert to absolute time at all. Its force comes from being
    /// bracketed between two anchors.
    pub offset_ms: u64,
    /// The signature of the **previous** link's key.
    pub signatures: SignatureSet,
}

impl Signable for KeyInclusion {
    const DOC_TYPE: &'static str = "KeyInclusion";
}

impl KeyInclusion {
    /// Verifies one link against its predecessor's key.
    ///
    /// The signature is checked with the key of the **previous** link, not with
    /// the key being added: a signature by the key being added would prove
    /// nothing, since whoever generated it a second ago holds it.
    ///
    /// Chain position, block membership and set uniqueness are checked by
    /// [`crate::keychain::build_key_set`] — none of them is derivable
    /// from a single link.
    ///
    /// # Errors
    ///
    /// [`Invalid::Schema`] on a foreign version or type; [`Invalid::Signature`]
    /// if the predecessor's key does not cover the profile.
    pub fn validate(&self, predecessor_key: &PublicKey, profile: &Profile) -> Result<(), Invalid> {
        let mut keys = KeySet::new();
        keys.insert(predecessor_key.clone());
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
