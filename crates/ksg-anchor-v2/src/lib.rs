//! # ksg-anchor-v2 — writing anchors on Solana, for core v2
//!
//! Core v1's `ksg-anchor` carried the transparency log's checkpoint profile,
//! the batching of checkpoints, the blind memo writer and the service's price
//! registry. With the log out of the core (`[decision]` 30.09) none of that has
//! a reader in core v2: seals are memoed blind by the container's own scan key
//! (`ksg_verify_v2::solana::SealMemo`), status records with an open memo
//! (`ksg_verify_v2::solana::StatusMemo`). What is left to write is the
//! transaction itself — and that is this crate: one memo instruction, built
//! and signed by hand, without an SDK.
//!
//! The verifier reads what is written here; nothing here is needed to verify.

#![forbid(unsafe_code)]

pub mod evm;
pub mod solana_tx;
pub mod user_op;
