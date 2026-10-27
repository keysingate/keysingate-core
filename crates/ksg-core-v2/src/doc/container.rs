//! The container's birth and its personal identifier. Specification KS-8 C-3, E-4.
//!
//! # Number and identity are different things
//!
//! The **serial** is a position in the release: one of a hundred million, known
//! before the container exists, handed out by the issuer in order. It is an
//! address.
//!
//! The **container identifier** is the container's identity: it comes into being
//! at initiation, one out of a space of 2^256, and says nothing about the
//! position. Reading a serial as an identity is the mistake this type exists to
//! prevent.
//!
//! # The identifier is derived, not assigned
//!
//! It is a function of the act of initiation. Two consequences follow, and both
//! are the reason for the choice:
//!
//! * it cannot be handed out twice — it is not handed out at all;
//! * no registry of issued identifiers is needed, and therefore no party whose
//!   registry one would have to trust.
//!
//! An assigned identifier would require both.

use serde::{Deserialize, Serialize};

use crate::canonical::{check_envelope, Signable};
use crate::crypto::hash::Hash;
use crate::crypto::sign::{KeySet, Profile, PublicKey, SignatureSet};
use crate::error::Invalid;

use super::{AgentBinding, Emission, Serial, Timestamp, Uri};

/// The domain separator for the identifier's derivation.
///
/// Present so that the digest cannot collide with any other hash in the
/// protocol: the same bytes hashed for another purpose give a different result.
const DOMAIN: &[u8] = b"ksg:container-id:v1";

/// Derives the container's personal identifier from the act of initiation.
///
/// The serial takes part so that two initiations differing only in position stay
/// distinct; the key and the offset, so that the identifier is a function of the
/// act rather than of the address.
///
/// `issued_at` is the release's moment. The owner's decision of 2026-09-19
/// (CT-28) names what makes a container unique: **identifier + release id +
/// serial in the release + the release's time**. Without the release's time two
/// releases that reused an id would derive colliding identifiers for the same
/// position — the id is a string we mint, and nothing outside this function
/// stops it from being minted twice.
#[must_use]
pub fn derive_container_id(
    emission: &str,
    issued_at: &Timestamp,
    serial: Serial,
    agent: &PublicKey,
    artifact: &Uri,
    offset_ms: u64,
) -> Hash {
    Hash::sha256_fields(&[
        DOMAIN,
        emission.as_bytes(),
        issued_at.as_str().as_bytes(),
        &serial.0.to_be_bytes(),
        agent.key.as_bytes(),
        artifact.as_str().as_bytes(),
        &offset_ms.to_be_bytes(),
    ])
}

/// The birth of a container: the client agent's key and the artifact bound at
/// one and the same moment (KS-8 E-4).
///
/// Before it there is a template and rights; after it there is a container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerInit {
    /// Always [`crate::doc::CONTEXT`] (spec v2 §3.3).
    #[serde(rename = "@context")]
    pub context: crate::doc::Context,
    /// Always `"ContainerInit"`.
    #[serde(rename = "type")]
    pub doc_type: String,
    /// The major core version. Introduced in v2.
    pub v: u32,
    /// The emission identifier.
    pub emission: String,
    /// The serial this container occupies — its **position**, not its identity.
    pub serial: Serial,
    /// The hash of the packet's [`AgentBinding`].
    pub binding: Hash,
    /// The client agent's key. Initiation is the moment it is laid on.
    pub agent: PublicKey,
    /// The artifact bound at the same moment (KS-8 C-3).
    pub artifact: Uri,
    /// Milliseconds since the **packet's** origin, not the container's (KS-2).
    ///
    /// The origin is one per packet — [`crate::doc::BlockAllocation::origin`], which is the
    /// packet's own moment. Every container of a packet inherits it, and the
    /// moment this container was initiated is recorded as an event rather than
    /// becoming an origin of its own (`[decision]` 19.09, CT-25): an origin per
    /// container would not be one origin, and offsets from different
    /// containers of a packet would stop being comparable.
    pub offset_ms: u64,
    /// The personal identifier — **derived**, never assigned. See the module
    /// documentation.
    pub container: Hash,
    /// Two signatures: the client agent's and the owner's or orchestrator's
    /// (KS-8 D-5). They arrive in one command and are checked together.
    pub signatures: SignatureSet,
}

impl Signable for ContainerInit {
    const DOC_TYPE: &'static str = "ContainerInit";
}

impl ContainerInit {
    /// Verifies the birth of a container.
    ///
    /// The identifier is **recomputed** rather than trusted: an initiation that
    /// carries an arbitrary identifier is rejected. That is what makes the
    /// identifier evidence instead of a claim.
    ///
    /// # Errors
    ///
    /// [`Invalid::Schema`] if the emission differs from the binding's, if the
    /// serial is outside the binding's block, if the carried identifier does not
    /// match the derived one, if the signatures come from fewer than two
    /// distinct parties, or if the named agent is not among the signers;
    /// [`Invalid::ActivationAfterExpiry`] if the offset runs past the packet's
    /// declared lifetime; [`Invalid::Signature`] on an uncovered profile.
    pub fn validate(
        &self,
        emission: &Emission,
        binding: &AgentBinding,
        chain_depth: u8,
        keys: &KeySet,
        profile: &Profile,
    ) -> Result<(), Invalid> {
        if self.emission != binding.emission {
            return Err(Invalid::Schema(
                "ContainerInit.emission is a different emission",
            ));
        }
        if !binding.block.contains(self.serial) {
            return Err(Invalid::OutOfRange {
                serial: self.serial.0,
            });
        }

        let derived = derive_container_id(
            &self.emission,
            &emission.issued_at,
            self.serial,
            &self.agent,
            &self.artifact,
            self.offset_ms,
        );
        if derived != self.container {
            return Err(Invalid::Schema(
                "ContainerInit.container is not the derived identifier",
            ));
        }

        // Initiation not later than the packet's lifetime (KS-2, invariant 3).
        //
        // Checked on the OFFSET, not on a wall clock: `offset_ms` runs from the
        // packet's origin, and the packet's lifetime is declared in the
        // issuance. No date arithmetic is needed, and no untrusted clock takes
        // part. The absolute form would need both.
        //
        // The outcome the owner decided on is **status 20**, a state rather than
        // a refusal; until statuses exist in the implementation the error names
        // it so the mapping stays unambiguous.
        // The lifetime allows for the channel: a distributor gets +10% and each
        // further agent another +10% (`[decision]` 19.09, CT-24). Everything else about
        // unused serials stays as it was — they burn.
        let lifetime_ms = emission.lifetime_ms(chain_depth);
        if self.offset_ms > lifetime_ms {
            return Err(Invalid::ActivationAfterExpiry);
        }

        // Two signatures in one command (KS-8 D-5). Checked here rather than by
        // the caller: a sequential pair leaves a window in which the first
        // signature waits for the second and can be held or replayed.
        //
        // Counted by **distinct signers**, not by the length of the set: one
        // party signing twice is a set of length two and is not two parties.
        // Counting the length would have left the dual-key rule satisfiable by
        // the very party it exists to constrain.
        if self.signatures.signers().len() < 2 {
            return Err(Invalid::Schema(
                "ContainerInit needs two signatures from two different parties",
            ));
        }
        // One of them must be the agent whose key is being laid on. Without
        // this the pair could be any two keys the holder controls, and the
        // initiation would say nothing about the agent it names.
        if !self.signatures.signed_by(&self.agent.kid) {
            return Err(Invalid::Schema(
                "ContainerInit is not signed by the agent it names",
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
    }
}
