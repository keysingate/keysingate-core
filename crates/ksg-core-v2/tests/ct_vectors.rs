//! Checking the tree against the Certificate Transparency reference vectors.
//! Specification §16 item 6.
//!
//! The most important check in the project. A divergence means an error in the
//! implementation and is escalated immediately — the expected value is **not
//! adjusted** to whatever the program returned.
//!
//! So that the check is external rather than closed on itself, the expected root
//! is taken everywhere from the **published constant** [`ROOTS`], not from our
//! own `root()`. A test that compares a program's output with the same program's
//! output passes on a completely wrong tree — it checks determinism, not
//! conformance to RFC 6962.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::merkle::inclusion::{inclusion_proof, verify_inclusion, Proof};
use ksg_core_v2::merkle::tree::{hash_children, hash_leaf, root};

/// The eight leaves of the RFC 6962 reference set (the `certificate-transparency-go`
/// test data), in hex.
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

/// The published roots of trees of sizes 0..=8 for the [`LEAF_DATA`] set.
///
/// These are external values. They are not computed here and are not edited.
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
        .map(|h| hash_leaf(&hex_decode(h)))
        .collect()
}

/// The reference root as an object rather than a string: this is what is
/// substituted into the checks in place of our own `root()`.
fn published_root(n: usize) -> Hash {
    let mut b = [0u8; 32];
    b.copy_from_slice(&hex_decode(ROOTS[n]));
    Hash::from_bytes(b)
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn ct_roots_match_published_values() {
    for n in 0..=8 {
        assert_eq!(
            root(&leaves(n)),
            published_root(n),
            "the root of a tree of size {n} diverged from the published RFC 6962 value"
        );
    }
}

#[test]
fn ct_inclusion_folds_to_the_published_root() {
    // The expected root is an external constant. If the tree is built wrongly,
    // the path will not resolve to it, even if it is self-consistent.
    for n in 1..=8usize {
        let ls = leaves(n);
        let expected = published_root(n);
        for i in 0..n {
            let idx = i as u64;
            let p = inclusion_proof(&ls, idx).expect("leaf in the tree");
            assert!(
                verify_inclusion(&ls[i], idx, n as u64, &p, &expected),
                "leaf {i} of a tree of size {n} does not resolve to the published root"
            );
        }
    }
}

#[test]
fn ct_inclusion_negative_wrong_leaf() {
    let n = 8usize;
    let ls = leaves(n);
    let p = inclusion_proof(&ls, 3).unwrap();
    // The same path but a foreign leaf — must not resolve.
    assert!(!verify_inclusion(
        &ls[4],
        3,
        n as u64,
        &p,
        &published_root(n)
    ));
    // The same leaf but a foreign index.
    assert!(!verify_inclusion(
        &ls[3],
        4,
        n as u64,
        &p,
        &published_root(n)
    ));
}

#[test]
fn ct_largest_power_of_two_trap() {
    // The tree is not split in half: for n = 7 the left side has 4 leaves, not 3.
    // Checked through the root: one assembled by hand under the "4 + 3" rule
    // must match the published value, and one under "3 + 4" must not.
    let ls = leaves(7);
    let correct = hash_children(&root(&ls[..4]), &root(&ls[4..]));
    let halved = hash_children(&root(&ls[..3]), &root(&ls[3..]));
    assert_eq!(correct, published_root(7));
    assert_ne!(halved, published_root(7));
}

#[test]
fn ct_domain_separation() {
    // Without the 0x00/0x01 prefixes, a leaf whose data equals the
    // concatenation of two digests would be indistinguishable from a node.
    let a = hash_leaf(b"x");
    let b = hash_leaf(b"y");
    let node = hash_children(&a, &b);
    let mut concat = Vec::new();
    concat.extend_from_slice(a.as_bytes());
    concat.extend_from_slice(b.as_bytes());
    assert_ne!(node, hash_leaf(&concat));
}

#[test]
fn ct_edge_cases() {
    let ls = leaves(3);
    assert!(inclusion_proof(&ls, 3).is_err());
    assert!(inclusion_proof(&[], 0).is_err());
    // A tree of size 0: inclusion cannot be proved.
    assert!(!verify_inclusion(
        &ls[0],
        0,
        0,
        &Proof::new(vec![]),
        &published_root(0)
    ));
}
