//! The error taxonomy. Specification §13. **Part 1.**
//!
//! Three states are kept distinct and never collapsed into two:
//! - `Invalid` — the document breaks a rule;
//! - `Unknown` — the check cannot be performed, the data is absent (a missing
//!   inclusion proof on the `light` class is a normal state, not an error);
//! - `NotApplicable` — the check does not apply to this class.
//!
//! In the types this comes out as: **only the first is an error**. "Unknown" is
//! `None` — an upper time bound nobody could read
//! ([`crate::anchor::upper_bound`]) or uniqueness nobody was shown
//! ([`crate::doc::binding::Uniqueness`]); "not applicable" is a property of the emission
//! class. Neither is a variant of `Invalid`.

use crate::crypto::sign::Alg;

/// A violation of a specification rule.
///
/// The enumeration is closed: extending it is a new major core version (§14).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Invalid {
    /// An input past a limit of spec v2 §14 — refused before any work.
    #[error("past the limit: {0}")]
    Limit(&'static str),

    /// A number a signed document may not carry: not an integer in
    /// 0…2^53 − 1 (spec v2 §3.2).
    #[error("a number outside 0…2^53-1 in a signed document")]
    Number,

    /// The canonical form (§3) did not match the bytes received, or the document
    /// is not a JSON object.
    #[error("the canonical form did not match")]
    Canonicalization,

    /// The signature of the algorithm presented failed verification (§4.1).
    #[error("signature {alg}: {reason}")]
    Signature {
        /// The algorithm whose signature was rejected.
        alg: Alg,
        /// The reason for the refusal.
        reason: SigFail,
    },

    /// The `alg` value was not recognized. Specification §4.1: the verifier MUST
    /// reject the document — this is a **refusal, not a pass over an unknown
    /// signature**.
    #[error("unknown signature algorithm: {0}")]
    UnknownAlg(String),

    /// `serial` is outside the emission range (§6) or outside the allocated block (§13 step 5).
    #[error("serial {serial} is out of range")]
    OutOfRange {
        /// The rejected serial.
        serial: u64,
    },

    /// A second binding to the same block (§8 rule 1).
    #[error("the block already has a binding")]
    DuplicateBinding,

    /// The closing allocation does not cover the block correctly (§12).
    #[error("closing allocation: {0}")]
    ClosureCoverage(Coverage),

    /// The document does not match the schema: a required field is missing, `v`
    /// is above the supported one, or a reference does not match.
    #[error("schema: {0}")]
    Schema(&'static str),

    /// The block's validity has expired: `created_at` is later than `expires_at` (§7 rule 4).
    #[error("expired")]
    Expired,

    /// A v2 act was presented without the container's initiation.
    ///
    /// A record presupposes a container, and a container comes into being at
    /// initiation. Accepting a record without one would mean affirming a
    /// container whose birth was never shown.
    #[error("the container's initiation was not presented")]
    MissingInitiation,

    /// Initiation was attempted after the packet's lifetime had run out.
    ///
    /// Distinct from [`Invalid::Expired`] on purpose. `Expired` is about a
    /// record made on a live packet; this is about a container that never
    /// legitimately came into being. When statuses land in the implementation
    /// this maps to **status 20**, which is the form the owner decided on: not a
    /// refusal in the abstract, but a state the container is left in. Statuses
    /// landed on 2026-09-11 and the mapping is now code, not a promise:
    /// [`crate::status::status_after`].
    #[error("activation after the packet's lifetime")]
    ActivationAfterExpiry,

    /// The agent's key-inclusion chain did not resolve (KS-1).
    #[error("key chain: {0}")]
    KeyChain(ChainFail),

    /// The event is refused in the container's current status (KS-7 §7.2).
    ///
    /// Carries the reason rather than the pair, because the pair is what the
    /// caller already has: what it lacks is which rule refused — an explicit
    /// refusal of §7.2-bis, or the closing default of §7.2-ter.
    #[error("status: {0}")]
    StatusRefused(&'static str),
}

/// The way in which a key-inclusion chain failed (KS-1 §8).
///
/// Every variant but the last names the **link number**, counting from 0. The
/// reason is the same as for [`Coverage::Gap`]: "the chain did not resolve"
/// without a position gives the holder no way to repair it. On a chain of 121
/// links that is the difference between a minute and a day.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ChainFail {
    /// Link N does not refer to the previous one.
    #[error("link {link} does not follow the previous one")]
    Break {
        /// The link's position, counting from 0.
        link: usize,
    },

    /// Link N is not signed by its predecessor's key.
    #[error("link {link} is not signed by its predecessor")]
    Signature {
        /// The link's position, counting from 0.
        link: usize,
    },

    /// Link N belongs to a different emission or a different block.
    #[error("link {link} belongs to a different emission or block")]
    Foreign {
        /// The link's position, counting from 0.
        link: usize,
    },

    /// The key of link N is already in the set.
    #[error("the key of link {link} is already in the set")]
    Duplicate {
        /// The link's position, counting from 0.
        link: usize,
    },

    /// The act's signature is covered by no key of the set.
    #[error("the signature is covered by no key of the set")]
    NotInSet,
}

/// The reason a particular signature was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SigFail {
    /// The signature or key value does not parse (length, base64url).
    #[error("malformed encoding")]
    BadEncoding,
    /// No key with the given `kid` was found in the set presented.
    #[error("key not found")]
    UnknownKey,
    /// The key was found but is unusable: it does not parse as a key of its
    /// algorithm, or it is declared for a different algorithm than the signature.
    #[error("key is unusable for this algorithm")]
    BadKey,
    /// The signature parsed but does not match the message and the key.
    #[error("does not match the message")]
    Mismatch,
    /// The algorithm is required by the profile (`required_algs`), but there is
    /// no valid signature for it.
    ///
    /// `required_algs` coverage is a logical **AND** (§4.1): a missing algorithm
    /// is a refusal, not a lowered level of trust.
    #[error("a signature required by the profile is absent")]
    MissingRequired,
}

/// The way in which the closing allocation fails to cover the block (§12).
///
/// A gap and an overlap are separated deliberately: the three sets' length sum
/// equalling the block size lets an overlap through **together with** a gap, so
/// the checks are performed separately and the errors are not merged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Coverage {
    /// The serial fell into none of the three sets.
    #[error("serial {serial} is not covered")]
    Gap {
        /// The first uncovered serial.
        serial: u64,
    },
    /// The serial fell into more than one set.
    #[error("serial {serial} is covered twice")]
    Overlap {
        /// The first serial encountered twice.
        serial: u64,
    },
    /// For the `heavy` class the `used_not_submitted` set MUST be empty (§12):
    /// inclusion is mandatory there by definition of the class.
    #[error("non-empty used_not_submitted on the heavy class")]
    UsedNotSubmittedInHeavy,
}
