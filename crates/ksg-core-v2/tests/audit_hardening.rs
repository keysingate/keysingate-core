//! Findings 17, 19, 20 of the hardening audit — the hygiene the bigger
//! claims stand on.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::doc::{Range, Serial};

// --- finding 19: one hash from two different strings -------------------------------

#[test]
fn a_multihash_in_upper_case_is_refused() {
    let lower = "1220".to_string() + &"ab".repeat(32);
    let upper = "1220".to_string() + &"AB".repeat(32);

    Hash::from_multihash(&lower).expect("lower case is canonical");
    assert!(
        Hash::from_multihash(&upper).is_err(),
        "upper case gave the same Hash under different canonical bytes \
         of the document and a different signature — a hash link stopped naming \
         one document"
    );
}

// --- finding 20: overflows on untrusted input --------------------------

#[test]
fn the_widest_range_does_not_wrap_to_empty() {
    let whole = Range {
        from: Serial(0),
        to: Serial(u64::MAX),
    };
    assert_eq!(
        whole.len(),
        u64::MAX,
        "a length must saturate, not wrap to zero"
    );
    assert!(
        !whole.is_empty(),
        "a range over the whole space cannot read as empty"
    );
}

#[test]
fn an_inverted_range_is_still_empty() {
    let inverted = Range {
        from: Serial(10),
        to: Serial(1),
    };
    assert_eq!(inverted.len(), 0);
    assert!(inverted.is_empty());
}
