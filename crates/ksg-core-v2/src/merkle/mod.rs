//! A Merkle tree with RFC 6962 semantics. Specification §11.1. **Part 1.**
//!
//! ```text
//! hash_leaf(d)    = SHA-256( 0x00 || d )
//! hash_node(l, r) = SHA-256( 0x01 || l || r )
//! ```
//!
//! There is **no** `prev_hash` field in the leaf: immutability is provided by
//! the tree, so a chain would be redundant and would serialize writes.
//!
//! The tree is split **not in half** but at the largest power of two strictly
//! less than `n`. This is the main source of divergence in independent
//! implementations.
//!
//! Correctness is confirmed by comparison against the Certificate Transparency
//! reference vectors (`tests/ct_vectors.rs`). A divergence there is an error
//! here, not a reason to adjust the expected value.
pub mod inclusion;
pub mod tree;

pub use inclusion::{inclusion_proof, verify_inclusion, Proof};
pub use tree::{hash_children, hash_leaf, root};
