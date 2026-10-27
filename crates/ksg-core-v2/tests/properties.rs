//! Property tests of the core (gap 13.10: mutations, property tests and
//! fuzzing — run 1 of 2–3): what must hold for every input, not only for the
//! vectors the other tests pick.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use ksg_core_v2::canonical::canonicalize;
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::merkle::{hash_leaf, inclusion_proof, root, verify_inclusion};
use proptest::prelude::*;
use serde_json::{Map, Number, Value};

fn digest() -> impl Strategy<Value = [u8; 32]> {
    any::<[u8; 32]>()
}

/// JSON a document can hold: non-negative safe integers (the only numbers
/// the core takes), strings, booleans, null, nested.
fn json() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        (0..=ksg_core_v2::limits::MAX_SAFE_INTEGER).prop_map(|n| Value::Number(Number::from(n))),
        ".{0,12}".prop_map(Value::String),
    ];
    leaf.prop_recursive(3, 32, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
            prop::collection::btree_map(".{0,8}", inner, 0..6)
                .prop_map(|m| Value::Object(m.into_iter().collect::<Map<_, _>>())),
        ]
    })
}

fn object() -> impl Strategy<Value = Value> {
    prop::collection::btree_map(".{0,8}", json(), 0..6)
        .prop_map(|m| Value::Object(m.into_iter().collect::<Map<_, _>>()))
}

proptest! {
    /// A multihash names exactly the digest it was made from.
    #[test]
    fn a_multihash_round_trips(b in digest()) {
        let h = Hash::from_bytes(b);
        prop_assert_eq!(Hash::from_multihash(&h.to_multihash()).unwrap(), h);
    }

    /// Any string either parses to a hash whose multihash is that very
    /// string, or is refused — one document, one name (audit finding 19).
    #[test]
    fn a_multihash_parses_only_to_itself(s in "[0-9a-fA-F]{0,72}|.{0,40}") {
        if let Ok(h) = Hash::from_multihash(&s) {
            prop_assert_eq!(h.to_multihash(), s);
        }
    }

    /// Field boundaries are hashed: moving bytes between fields changes the
    /// hash (audit finding 11).
    #[test]
    fn fields_keep_their_boundaries(
        a in prop::collection::vec(any::<u8>(), 0..16),
        b in prop::collection::vec(any::<u8>(), 0..16),
        cut in 0usize..32,
    ) {
        let joined: Vec<u8> = a.iter().chain(&b).copied().collect();
        let cut = cut.min(joined.len());
        let (c, d) = joined.split_at(cut);
        // The same cut is the same fields: nothing to tell apart.
        if (c, d) != (a.as_slice(), b.as_slice()) {
            prop_assert_ne!(
                Hash::sha256_fields(&[&a, &b]),
                Hash::sha256_fields(&[c, d])
            );
        }
    }

    /// Every leaf of every tree proves its inclusion under the root, at its
    /// own index only, and no other leaf proves with its proof.
    #[test]
    fn every_leaf_proves_under_the_root(
        data in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..8), 1..40),
        pick in any::<prop::sample::Index>(),
        other in any::<[u8; 8]>(),
    ) {
        let leaves: Vec<Hash> = data.iter().map(|d| hash_leaf(d)).collect();
        let size = leaves.len() as u64;
        let r = root(&leaves);
        let i = pick.index(leaves.len());
        let proof = inclusion_proof(&leaves, i as u64).unwrap();
        prop_assert!(verify_inclusion(&leaves[i], i as u64, size, &proof, &r));
        let stranger = hash_leaf(&other);
        prop_assume!(!leaves.contains(&stranger));
        prop_assert!(!verify_inclusion(&stranger, i as u64, size, &proof, &r));
        if size > 1 {
            let j = (i + 1) % leaves.len();
            if leaves[j] != leaves[i] {
                prop_assert!(!verify_inclusion(&leaves[i], j as u64, size, &proof, &r));
            }
        }
        prop_assert!(inclusion_proof(&leaves, size).is_err());
    }

    /// Canonical bytes are a fixed point: parsing them and canonicalizing
    /// again gives the same bytes, and key order on input does not matter.
    #[test]
    fn canonical_form_is_a_fixed_point(v in object()) {
        let once = canonicalize(&v).unwrap();
        let back: Value = serde_json::from_slice(&once).unwrap();
        prop_assert_eq!(&back, &v);
        prop_assert_eq!(canonicalize(&back).unwrap(), once);
    }

    /// A negative number, or one past the safe range, refuses the document
    /// wherever it sits.
    #[test]
    fn an_unsafe_number_refuses_the_document(
        v in object(),
        n in prop_oneof![i64::MIN..0i64, Just(1i64 << 53)],
        key in ".{0,8}",
    ) {
        let mut v = v;
        v.as_object_mut().unwrap().insert(key, Value::Number(Number::from(n)));
        prop_assert!(canonicalize(&v).is_err());
    }

    /// Only an object canonicalizes: a bare value is not a document.
    #[test]
    fn only_an_object_canonicalizes(v in json()) {
        prop_assert_eq!(canonicalize(&v).is_ok(), v.is_object());
    }
}

/// The guards of `verify_inclusion` at their edges (mutation run of 16.10):
/// an empty tree and an index past the end answer `false` (no panic), and a
/// path of exactly `MAX_PROOF_DEPTH` is still read — one past it is not.
#[test]
fn inclusion_guards_hold_at_their_edges() {
    use ksg_core_v2::limits::MAX_PROOF_DEPTH;
    use ksg_core_v2::merkle::{hash_children, Proof};
    let leaf = hash_leaf(b"leaf");
    let one = Proof::new(vec![]);
    assert!(verify_inclusion(&leaf, 0, 1, &one, &leaf));
    assert!(!verify_inclusion(&leaf, 0, 0, &one, &leaf), "an empty tree");
    assert!(
        !verify_inclusion(&leaf, 1, 1, &one, &leaf),
        "an index past the end"
    );

    // Leaf 0 of a tree of u64::MAX leaves: 64 siblings, all on the right.
    let siblings: Vec<Hash> = (0..MAX_PROOF_DEPTH as u8)
        .map(|i| hash_leaf(&[i]))
        .collect();
    let top = siblings.iter().fold(leaf, |acc, s| hash_children(&acc, s));
    let deep = Proof::new(siblings.clone());
    assert_eq!(deep.len(), MAX_PROOF_DEPTH);
    assert!(
        verify_inclusion(&leaf, 0, u64::MAX, &deep, &top),
        "depth 64 is read"
    );
    let mut longer = siblings;
    longer.push(hash_leaf(b"one more"));
    assert!(!verify_inclusion(
        &leaf,
        0,
        u64::MAX,
        &Proof::new(longer),
        &top
    ));
}

/// The small accessors the mutation run of 16.10 found unread: what a hash
/// and an algorithm print as, and when a set or a path is empty.
#[test]
fn display_and_emptiness_say_what_they_hold() {
    use ksg_core_v2::crypto::sign::{Alg, Ed25519Signer, KeySet, SignatureSet};
    use ksg_core_v2::doc::Uri;
    use ksg_core_v2::merkle::Proof;
    let h = Hash::from_bytes([7; 32]);
    assert_eq!(h.to_string(), h.to_multihash());
    assert_eq!(Alg::Ed25519.to_string(), "Ed25519");
    assert_eq!(Alg::MlDsa65.to_string(), "ML-DSA-65");

    let s = Ed25519Signer::from_seed(Uri::parse("did:key:zA#k".to_owned()).unwrap(), [1; 32]);
    assert!(SignatureSet::new(vec![]).is_empty());
    assert!(!SignatureSet::new(vec![s.sign(b"m")]).is_empty());
    assert!(KeySet::default().is_empty());
    let one: KeySet = std::iter::once(s.public()).collect();
    assert!(!one.is_empty());
    assert!(Proof::new(vec![]).is_empty());
    assert!(!Proof::new(vec![h]).is_empty());
}
