//! Finding 11 of the hardening audit — ambiguous concatenation in the signed
//! subjects.
//!
//! A property is checked, not concrete values: length-prefix-free concatenation
//! maps distinct field sets to one hash, and a signature over one becomes
//! a signature over the other.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use ksg_core_v2::crypto::hash::Hash;

#[test]
fn concatenation_collides_and_field_hashing_does_not() {
    // The classic pair: ("ab","c") vs ("a","bc").
    let a: &[&[u8]] = &[b"ab", b"c"];
    let b: &[&[u8]] = &[b"a", b"bc"];

    assert_eq!(
        Hash::sha256_parts(a),
        Hash::sha256_parts(b),
        "the concatenation must collide — or the test shows nothing"
    );
    assert_ne!(
        Hash::sha256_fields(a),
        Hash::sha256_fields(b),
        "with lengths, field boundaries enter the hash"
    );
}

#[test]
fn an_absent_field_differs_from_an_empty_one() {
    // The case from the code: `under` is now absent, now 32 bytes. An empty field
    // and an absent field must not yield one subject.
    let with_empty: &[&[u8]] = &[b"ksg:work:v1", b"", b"did:key:z"];
    let without: &[&[u8]] = &[b"ksg:work:v1", b"did:key:z"];

    assert_eq!(
        Hash::sha256_parts(with_empty),
        Hash::sha256_parts(without),
        "concatenation does not tell them apart"
    );
    assert_ne!(
        Hash::sha256_fields(with_empty),
        Hash::sha256_fields(without),
        "fields with lengths tell them apart"
    );
}

#[test]
fn moving_a_byte_across_the_boundary_changes_the_subject() {
    // Content picked so one field "eats" the neighbor's edge.
    let left: &[&[u8]] = &[b"ksg:order:v1", b"Protocol", b"substance"];
    let shifted: &[&[u8]] = &[b"ksg:order:v1", b"Protocols", b"ubstance"];
    assert_eq!(Hash::sha256_parts(left), Hash::sha256_parts(shifted));
    assert_ne!(Hash::sha256_fields(left), Hash::sha256_fields(shifted));
}
