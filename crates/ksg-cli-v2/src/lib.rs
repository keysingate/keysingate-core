//! # ksg-cli-v2 — the reader, on core v2
//!
//! Core v1's `ksg-cli` carried over to `ksg-core-v2`. The
//! transparency log's process (`ksg log`) is not carried over: core v2 has no
//! log (spec v2 §17).
//!
//! ## The reader
//!
//! Item P-5 of the MVP plan (`[doc:MVP-PLAN]`). The stand
//! (`ksg-container/tests/stand`) drives a container through its three buttons
//! in memory; this crate does the same with the container **on a disk** and the
//! client's mobile half **in another process**.
//!
//! | Piece | Where it lives | Module |
//! |---|---|---|
//! | the container | sealed bytes in the home directory (`ksg-container::store`) | [`home`] |
//! | the client's mobile half | its own file, read only by `ksg mobile serve` | [`mobile`] |
//! | the parties other than the client (issuer, owner, buyer) | seeds in the home directory | [`home`] |
//! | pressing a button | [`Reader::press`], the stand's orchestration | [`reader`] |
//!
//! # The test stand
//!
//! `[decision]` 23.09: on the stand the container is sealed under the holder's
//! layer key (`layer.key` in the home directory); the product seals to a TEE.
//! The issuer, the owner and the buyer are seeds in one file: on the stand one
//! person plays every party. The stand is for tests only (`[decision]` 25.10).
//!
//! # Anchors
//!
//! A container printed with `--anchor solana:CLUSTER` anchors on Solana
//! ([`anchoring`], item P-6): every seal its journal puts on in Pro (the full
//! class opens Pro; a light journal goes Pro by a form page; the base class
//! never does — spec v2 §9), and **every status record**, record 0 included,
//! in every class (spec v2 §11). `ksg-verify-v2 --rpc` reads both. Without
//! `--anchor`, seals and status records carry the placeholder
//! [`LOCAL_ANCHOR`], which no reader of a network accepts: `ksg-verify-v2`
//! **refuses** them rather than pretend a network confirmed them — a status
//! with no read anchor has no time.

pub mod anchoring;
pub mod base_anchor;
pub mod channel;
pub use ksg_verify_v2::clock;
pub mod home;
pub mod issue_label;
pub mod mobile;
pub mod reader;
#[cfg(feature = "rpc")]
pub mod service;
pub mod testkeys;
pub mod web_mobile;

pub use reader::{init, ChannelInit, InitOptions, PageSpec, PrintSource, Reader, Who};

/// The anchor kind of the MVP until an anchoring profile is wired in (P-6).
pub const LOCAL_ANCHOR: &str = "urn:ksg:anchor:local:v1";
