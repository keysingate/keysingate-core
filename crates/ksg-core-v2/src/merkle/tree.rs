//! Tree construction and root computation. Specification §11.1. **Part 1.**
//!
//! ```text
//! hash_leaf(d)     = SHA-256( 0x00 || d )
//! hash_children(l, r) = SHA-256( 0x01 || l || r )
//! MTH({})          = SHA-256( )
//! ```
//!
//! The `0x00` and `0x01` prefixes are domain separation: without them a leaf
//! whose data happens to equal the concatenation of two digests would be
//! indistinguishable from a node. The separation is not subject to change
//! (see "Division of work", item 2 of the prohibitions).

use crate::crypto::hash::Hash;

/// The leaf prefix.
pub(crate) const LEAF_PREFIX: [u8; 1] = [0x00];
/// The internal-node prefix.
pub(crate) const NODE_PREFIX: [u8; 1] = [0x01];

/// A leaf hash: `SHA-256(0x00 || data)`.
#[must_use]
pub fn hash_leaf(data: &[u8]) -> Hash {
    Hash::sha256_parts(&[&LEAF_PREFIX, data])
}

/// An internal-node hash: `SHA-256(0x01 || left || right)`.
#[must_use]
pub fn hash_children(left: &Hash, right: &Hash) -> Hash {
    Hash::sha256_parts(&[&NODE_PREFIX, left.as_bytes(), right.as_bytes()])
}

/// The root of a tree over already-computed leaf hashes (`MTH` from RFC 6962).
///
/// An empty tree yields `SHA-256` of the empty string — that is the definition,
/// not a special case: a checkpoint with `tree_size: 0` must have a
/// reproducible root.
#[must_use]
pub fn root(leaves: &[Hash]) -> Hash {
    match leaves {
        [] => Hash::sha256(&[]),
        [single] => *single,
        _ => {
            let (left, right) = leaves.split_at(split_point(leaves.len()).min(leaves.len()));
            hash_children(&root(left), &root(right))
        }
    }
}

/// The split point of a tree of `n` leaves: **the largest power of two strictly
/// less than `n`**.
///
/// This is where most independent implementations break. The tree is split
/// **not in half**: for `n = 7` the left subtree holds 4 leaves, not 3. A
/// divergence from the Certificate Transparency reference vectors
/// (`tests/ct_vectors.rs`) almost always points here.
///
/// Defined for `n >= 2`; for smaller `n` it returns `n`, so that a caller
/// splitting at it gets an empty right half instead of an overflow.
#[must_use]
pub(crate) fn split_point(n: usize) -> usize {
    if n < 2 {
        return n;
    }
    // The largest power of two strictly less than n.
    let shift = usize::BITS - 1 - (n - 1).leading_zeros();
    1usize.checked_shl(shift).unwrap_or(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::inclusion::{inclusion_proof, verify_inclusion};

    /// Eight leaves from the RFC 6962 reference set (the same ones as in the
    /// `certificate-transparency-go` test data).
    const LEAF_DATA: [&str; 8] = [
        "",
        "00",
        "10",
        "2021",
        "3031",
        "40414243",
        "5051525354555657",
        "606162636465666768696a6b6c6d6e6f",
    ];

    /// The roots of trees of sizes 0..=8 from the same set.
    ///
    /// A divergence here means an error in the implementation, **not** a reason
    /// to adjust the expected value.
    const ROOTS: [&str; 9] = [
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
        "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
        "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
        "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
        "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
        "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
    ];

    fn leaves(n: usize) -> Vec<Hash> {
        LEAF_DATA[..n]
            .iter()
            .map(|h| hash_leaf(&hex::decode(h).unwrap()))
            .collect()
    }

    #[test]
    fn split_point_is_largest_power_of_two_below_n() {
        // The tree is split NOT in half: for n = 7 the left side has 4 leaves, not 3.
        assert_eq!(split_point(2), 1);
        assert_eq!(split_point(3), 2);
        assert_eq!(split_point(4), 2);
        assert_eq!(split_point(5), 4);
        assert_eq!(split_point(7), 4);
        assert_eq!(split_point(8), 4);
        assert_eq!(split_point(9), 8);
    }

    #[test]
    fn roots_match_rfc6962_reference() {
        for (n, expected) in ROOTS.iter().enumerate() {
            assert_eq!(
                hex::encode(root(&leaves(n)).as_bytes()),
                *expected,
                "the root of a tree of size {n} diverged from the RFC 6962 reference"
            );
        }
    }

    #[test]
    fn inclusion_round_trip_for_every_leaf() {
        for n in 1..=8usize {
            let ls = leaves(n);
            let r = root(&ls);
            for i in 0..n {
                let idx = i as u64;
                let p = inclusion_proof(&ls, idx).expect("leaf in the tree");
                assert!(
                    verify_inclusion(&ls[i], idx, n as u64, &p, &r),
                    "inclusion of leaf {i} in a tree of size {n}"
                );
                // A substituted root must be noticed.
                assert!(!verify_inclusion(&ls[i], idx, n as u64, &p, &ls[0]) || n == 1);
            }
        }
    }

    #[test]
    fn inclusion_rejects_out_of_range() {
        assert!(inclusion_proof(&leaves(0), 0).is_err());
        assert!(inclusion_proof(&leaves(3), 3).is_err());
        let p = inclusion_proof(&leaves(3), 0).unwrap();
        let ls = leaves(3);
        assert!(!verify_inclusion(&ls[0], 0, 0, &p, &root(&ls)));
        assert!(!verify_inclusion(&ls[0], 5, 3, &p, &root(&ls)));
    }

    /// Synthetic leaves: eight reference ones are too few to catch a split error
    /// at sizes where the power of two is far from the middle.
    fn synthetic(n: usize) -> Vec<Hash> {
        (0..n)
            .map(|i| hash_leaf(&(i as u32).to_be_bytes()))
            .collect()
    }

    #[test]
    fn inclusion_holds_up_to_size_33() {
        for n in 1..=33usize {
            let ls = synthetic(n);
            let r2 = root(&ls);
            for i in 0..n {
                let p = inclusion_proof(&ls, i as u64).unwrap();
                assert!(
                    verify_inclusion(&ls[i], i as u64, n as u64, &p, &r2),
                    "inclusion of {i} in {n}"
                );
            }
        }
    }
}
