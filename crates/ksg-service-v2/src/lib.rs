//! # ksg-service-v2 — the network side, on core v2
//!
//! Core v1's `ksg-service` carried over to core v2. Everything
//! below the network is in the other crates — the documents, the container,
//! the memo formats, the reading of anchors. What this crate adds is the part
//! that **acts**:
//!
//! | Module | What it does | Decision |
//! |---|---|---|
//! | [`desk`] | the door for requests to someone else's anchor: challenges, path A, the price by look number, the notice for the container that was looked at | Ts-5, CT-13, CT-14, CT-15, CT-38 |
//! | [`ladder`] | the two streams and the price of each look | CT-14, CT-38, CT-37 |
//! | [`anchoring`] | the queue of memos that loses nothing: retries, and a sent memo checked by its signature before it is ever sent again | CT-04 |
//! | [`solana`] | the queue's network: memo transactions on Solana, paid by the holder's payer | CT-04 |
//! | [`registry`] | path A's lookup: an owner-watcher's key, shown present in a chain by its own channel bundle and status section | Ts-5, finding 6 |
//! | `server` | the process: HTTP, the holder's signature on its requests, the state on disk, the queue's ticker | CT-04, Ts-5 |
//!
//! # What is behind an interface, and why
//!
//! The network itself — sending a transaction, asking for its status — sits
//! behind [`anchoring::ChainSender`]; who stands behind an owner-watcher's key
//! behind [`desk::Registry`]. Both are the service's deployment, not its
//! logic: the logic is complete and tested here, and a deployment writes one
//! adapter per trait.
//!
//! # What we see, said where the code is
//!
//! `[decision]` 13.09 §8.2: we see the facts of requests — who, to which
//! anchor, when — and the owner-watcher's ID disclosed in them; we do **not**
//! see the inside of a container. The desk keeps what billing and delivery
//! need and nothing else: no product journal "who looked" exists on our side
//! — the notice goes to the client's container (§8.1).

#![forbid(unsafe_code)]

pub mod anchoring;
pub mod auth;
pub mod desk;
pub mod ladder;
pub mod registry;
#[cfg(feature = "server")]
pub mod server;
pub mod solana;
