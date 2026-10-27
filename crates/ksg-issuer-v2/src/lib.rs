//! # ksg-issuer-v2 — the party that issues blanks, on core v2
//!
//! Core v1's `ksg-issuer` carried over to `ksg-core-v2`. The
//! issuer's list of an agent's blocks ([`history::AgentHistory`]) moved here
//! from the core (spec v2 §17).
//!
//! Implements §5 (the emission), §7 (block allocation), and the intake of
//! closing allocations
//! §12.
//!
//! # Why this is separate from the verifier
//!
//! The 80% rule (§7 rule 2) and the requirement for `prev_closure` from the
//! second block onward (§7 rule 3) are properties of a **sequence of allocations
//! to one holder**, not of a single document. An act verifier cannot derive
//! them: it sees one allocation and does not know whether there was a previous
//! one. Putting them into act verification would mean either demanding
//! knowledge the verifier does not have, or pretending a check took place.
//!
//! Here that knowledge exists by definition: the issuer is the only party that
//! keeps the sequence.
//!
//! # The one place coordination is needed
//!
//! Blocks are allocated consecutively and without overlap — that requires shared
//! state. Everything else in the protocol is offline: binding, filling in,
//! verification. Hence the engine's shape: the state is handed out whole
//! ([`Issuer::snapshot`]), and the operator chooses the storage (§17).

#![forbid(unsafe_code)]

pub mod error;
pub mod fulfilment;
pub mod history;
pub mod issuer;
pub mod ledger;

pub use error::IssuerError;
pub use fulfilment::{Book, Event, FulfilmentError, Stage};
pub use history::{AgentHistory, HistoryEntry};
pub use issuer::{Issuer, IssuerSnapshot, PacketTerms, Terms};
pub use ledger::{Ledger, LedgerSnapshot};
