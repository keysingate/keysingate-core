//! # ksg-core-v2 — the Keysingate core, second version
//!
//! Implements the core specification, published as `draft-nam-ksg-core-00`
//! (`research/draft-nam-ksg-core-00.md`; documents of major version 3, context `urn:keysingate:core:v3`). Core v1
//! (the first version of the core) is kept as it is and verifies the
//! documents of versions 1 and 2 (architecture v0.3 §5.3); nothing here links
//! to it.
//!
//! What the core holds: signatures and keys ([`crypto`]), the canonical form
//! ([`canonical`]), the Merkle tree ([`merkle`]), anchors and the one rule of
//! the upper time bound ([`anchor::upper_bound`]), the documents of the chain
//! from release to container ([`doc`]), the key chain ([`keychain`]), the
//! statuses and their section ([`status`], [`section`]) and the journal under
//! the movable seal ([`journal`]).
//!
//! What it does not hold, by the owner's decisions of 30.09: the transparency
//! log and its checkpoints, the act and the steps 1–9 built on it, the view
//! notice and the disclosure request.
//!
//! Stability rules the whole crate keeps (spec v2 §3, §14): no panics outside
//! tests (`unwrap`, `expect`, `panic!`, indexing are denied by lint), integers
//! only within 2^53 − 1, one form of time, a ceiling on every list and every
//! input, unknown fields refused.
//!
//! The extension rule, expressed in the types: **do not choose where a set can
//! be accepted.** Signatures and anchors are arrays by construction, not fields
//! that happen to allow several values. Neither [`crypto::sign::SignatureSet`]
//! nor [`anchor::Anchors`] offers a `Deref<Target = Vec<_>>` or a single-element
//! constructor: the temptation to treat an array as a field is removed at the
//! API level, not by convention.

#![forbid(unsafe_code)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]
#![allow(missing_docs)]

pub mod anchor;
pub mod canonical;
pub mod crypto;
pub mod doc;
pub mod error;
pub mod journal;
pub mod keychain;
pub mod limits;
pub mod merkle;
pub mod section;
pub mod status;
pub mod version;
