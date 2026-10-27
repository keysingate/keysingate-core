//! # ksg-container-v2 — the three entry points, on core v2
//!
//! Core v1's `ksg-container`, carried over to core
//! v2 (`ksg-core-v2`, documents of major version 3). What changed in the move:
//! the work journal is the core's bound journal (`ksg_core_v2::journal`); the
//! voluntary opening and the court-appointed expert, which spec v2 §17 keeps
//! out of the core, live here ([`voluntary`], [`expert`]); every document is
//! `v` = 3 with `@context` = `urn:keysingate:core:v3` and the one form of time.
//! Core v1's container is not touched and nothing here links to it (`[decision]`
//! 30.09).
//!
//! KS-8 part D. The axiom the whole surface is built on:
//!
//! > **An entry point is a break-in point.**
//!
//! There are three buttons and no others. Everything a container can be asked to
//! do arrives at one of them, and an operation offered at the wrong one is
//! refused — not because it would be harmful there, but because "there are three
//! entry points" is only true if it is enforced.
//!
//! | | Button | What passes | Who presses |
//! |---|---|---|---|
//! | **D-1** | issuer's | entering data · reading the status · finalization | the issuer |
//! | **D-2** | signatures | signing · activating keys · records of work | agent, owner, orchestrator, buyer |
//! | **D-3** | export | full export in a dispute | the parties to the dispute |
//!
//! # What is here and what is not
//!
//! Here: which operation reaches which button, how many keys it takes and from
//! how many parties, what the status must be for it to be allowed, and the fact
//! that a refusal is an ordinary outcome rather than an error (F-9).
//!
//! **Not here: noise filling, packing and layer encryption** (plan §2.1
//! `noise.rs`, `pack.rs`, `layers.rs`). Those are how a container is stored, and
//! the specification gives an order — compress, pad to a constant size, encrypt
//! — without the detail to implement one. Writing a placeholder that "wraps"
//! nothing would make D-4 look implemented while it was not, and a security
//! property that only looks implemented is worse than an absent one.
//!
//! What of D-4 **can** be held now is held: the payload is opaque bytes that
//! nothing on this path parses. The rule is "wrap before checking", and a path
//! that never reads the material cannot check it early by accident.

#![forbid(unsafe_code)]

pub mod artifact;
pub mod capsule;
pub mod client_key;
pub mod command;
pub mod container;
pub mod dispute;
pub mod event;
pub mod expert;
pub mod followup;
pub mod identity;
pub mod layers;
pub mod layout;
pub mod noise;
pub mod operation;
pub mod order;
pub mod pack;
pub mod pq_key;
pub mod sample;
pub mod seal;
pub mod stages;
pub mod store;
pub mod timecheck;
pub mod unload_gate;
pub mod view;
pub mod voluntary;

pub use artifact::{
    ArtifactError, Attachment, End, Kind, Process, Source, SourceFrom, TaskArtifact,
};
pub use command::{Attempt, Command, Refusal, Refused, Roster, Strength};
pub use container::{Container, Evidence, Release, Stopped, UnloadRoute, Writes};
pub use dispute::{DisputeError, Filing, Settlement, PRESCRIPTION_MS};
pub use event::{Event, Head, View, Wrapped};
pub use followup::{Discharge, FollowupError, Proof, Raised, Task, Ticket, MAX_REFUSALS};
pub use unload_gate::{
    authorize as authorize_unload, Denied, Granted, Presenters, Route, Subject, Unload,
};

pub use identity::{
    carried_line, id_hash, Challenge, IdDisclosure, IdSuccession, IdentityError, OwnershipClaim,
    Publication,
};
/// Re-exported so a caller of [`Command::press`] need not reach into the core
/// for the two values it always passes.
pub use ksg_core_v2::status::{Blocked, Status};
pub use layers::{
    hand_over, hand_over_in, receive, receive_in, Handover, Held, LayerError, LayerKey, Level,
    OpenWith, SealTo, Suite,
};
pub use layout::{Fields, Layout, LayoutError, Slot, Zone, CUSTOM_SLOTS, JOURNAL_PAGES};
pub use operation::{Button, Keys, Operation, Role, Seat};
pub use order::{Basis, BasisKind, Order, OrderError, Work};
pub use pack::{Aead, ChaCha20Poly1305Aead, Compressor, Deflate, NoCompression, PackError, Packer};
pub use stages::Stage;
pub use timecheck::{
    TimeRefusal, Where, BARE_IDLE_AFTER_ISSUE_MS, BARE_IDLE_AFTER_RECORD_MS, DAY_MS,
};
