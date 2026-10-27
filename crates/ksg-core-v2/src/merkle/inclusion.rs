//! The inclusion proof. Specification §11.1, §13 step 6. **Part 1.**
//!
//! `PATH(m, D[n])` from RFC 6962: the sequence of sibling hashes along the path
//! from leaf `m` to the root, bottom-up.

use crate::crypto::hash::Hash;
use crate::error::Invalid;

use super::tree::{hash_children, root, split_point};

/// A path of sibling hashes, bottom-up.
///
/// The order matters: a shuffled order yields a different root, not a parse error.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct Proof(Vec<Hash>);

impl Proof {
    /// An empty path is a correct proof for a tree of one leaf.
    #[must_use]
    pub const fn new(path: Vec<Hash>) -> Self {
        Self(path)
    }

    /// The path hashes, bottom-up.
    #[must_use]
    pub fn path(&self) -> &[Hash] {
        &self.0
    }

    /// The path length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// The path is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// An inclusion proof for leaf `index` in the tree over `leaves`.
///
/// # Errors
///
/// [`Invalid::OutOfRange`] when `index >= leaves.len()`, the empty tree
/// included: a tree of size 0 has no leaf whose inclusion could be proved.
pub fn inclusion_proof(leaves: &[Hash], index: u64) -> Result<Proof, Invalid> {
    let n = leaves.len();
    let m = usize::try_from(index).map_err(|_| Invalid::OutOfRange { serial: index })?;
    if m >= n {
        return Err(Invalid::OutOfRange { serial: index });
    }
    let mut path = Vec::new();
    collect_path(leaves, m, &mut path);
    Ok(Proof(path))
}

/// `PATH(m, D[n])`, recursively; the result accumulates bottom-up.
fn collect_path(leaves: &[Hash], m: usize, out: &mut Vec<Hash>) {
    let n = leaves.len();
    if n <= 1 {
        return;
    }
    let k = split_point(n).min(n);
    let (left, right) = leaves.split_at(k);
    if m < k {
        collect_path(left, m, out);
        out.push(root(right));
    } else {
        collect_path(right, m - k, out);
        out.push(root(left));
    }
}

/// Verifies an inclusion proof.
///
/// Returns `bool`, not `Result`: a root mismatch is not a schema violation but a
/// negative answer to the question asked. What to do about it is for the calling
/// verification step to decide.
///
/// Rejects `size == 0`, `index >= size`, and a path of the wrong length: the
/// path length is determined uniquely by the pair `(index, size)`, so an extra
/// or missing element is a forgery, not a permissible variation.
#[must_use]
pub fn verify_inclusion(
    leaf: &Hash,
    index: u64,
    size: u64,
    proof: &Proof,
    root_hash: &Hash,
) -> bool {
    if size == 0 || index >= size || proof.path().len() > crate::limits::MAX_PROOF_DEPTH {
        return false;
    }
    let mut fn_ = index;
    let mut sn = size - 1;
    let mut acc = *leaf;
    let mut it = proof.path().iter();

    while sn > 0 {
        let Some(sibling) = it.next() else {
            return false;
        };
        if fn_ % 2 == 1 || fn_ == sn {
            acc = hash_children(sibling, &acc);
            // Climbing past left siblings: while the current node is a right child, go up.
            while fn_ % 2 == 0 && fn_ != 0 {
                fn_ /= 2;
                sn /= 2;
            }
        } else {
            acc = hash_children(&acc, sibling);
        }
        fn_ /= 2;
        sn /= 2;
    }

    it.next().is_none() && acc == *root_hash
}
