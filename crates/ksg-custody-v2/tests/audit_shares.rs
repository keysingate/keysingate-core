//! Security audit of 13.09, finding 18 — Shamir without checking shares against the set.

use ksg_custody_v2::{split_3_of_5, CustodyError, CustodySet, Share};

fn secret() -> Vec<u8> {
    (0u8..32).collect()
}
fn entropy() -> Vec<u8> {
    (0u8..224)
        .map(|i| i.wrapping_mul(7).wrapping_add(3))
        .collect()
}

fn set_and_shares() -> (CustodySet, Vec<Share>) {
    let shares = split_3_of_5(&secret(), &entropy()).expect("split");
    let set = CustodySet::of(&shares, 3).expect("set");
    (set, shares)
}

#[test]
fn a_substituted_share_is_caught_instead_of_yielding_another_secret() {
    // The point of the finding: Shamir has no integrity of its own. A substituted
    // share yields **another** secret — silently and confidently, with no error at all.
    let (set, shares) = set_and_shares();

    let mut tampered = shares[0].clone();
    tampered.body[0] ^= 0xFF;
    let picked = vec![tampered, shares[1].clone(), shares[2].clone()];

    // combine on its own "succeeds" and returns garbage.
    let quietly_wrong = ksg_custody_v2::combine_3_of_5(&picked).expect("combine does not complain");
    assert_ne!(*quietly_wrong, secret(), "that is exactly the danger");

    // combine_checked checks the shares against the set and refuses.
    let err = set
        .combine_checked(&picked)
        .expect_err("a substituted share must be named");
    assert!(matches!(err, CustodyError::Substituted(_)), "got {err:?}");
}

#[test]
fn honest_shares_reconstruct_through_the_checked_path() {
    let (set, shares) = set_and_shares();
    let got = set
        .combine_checked(&shares[..3])
        .expect("three honest shares restore the secret");
    assert_eq!(*got, secret());
}

#[test]
fn below_the_threshold_the_checked_path_refuses_early() {
    let (set, shares) = set_and_shares();
    let err = set
        .combine_checked(&shares[..2])
        .expect_err("two shares are not enough");
    assert!(matches!(err, CustodyError::NotEnough { .. }), "got {err:?}");
}
