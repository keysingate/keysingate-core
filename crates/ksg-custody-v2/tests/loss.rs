//! Declaring that shares are lost, and the window that follows.
//! `[decision]` 19.09, CT-22.

use ksg_core_v2::crypto::sign::{sign_doc, Ed25519Signer, Profile, SignatureSet};
use ksg_core_v2::doc::{Timestamp, Uri};
use ksg_custody_v2::loss::{
    standing, LossDeclaration, Standing, Window, WINDOW_MS, WINDOW_WITHOUT_OWNER_MS,
};
use ksg_custody_v2::{entropy_needed, split_3_of_5, CustodySet, Share};

fn uri(s: &str) -> Uri {
    Uri::parse(s).expect("uri")
}
fn owner() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:web:owner.example#k1"), [21u8; 32])
}
fn issuer() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:web:issuer.example#k1"), [22u8; 32])
}
fn stranger() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:web:stranger.example#k1"), [23u8; 32])
}
fn ts() -> Timestamp {
    Timestamp::parse("2026-09-19T00:00:00.000Z").expect("ts")
}
fn shares() -> Vec<Share> {
    let secret = b"the issuer's key, split five ways";
    split_3_of_5(secret, &vec![7u8; entropy_needed(secret.len(), 3, 5)]).expect("split")
}
fn set(shares: &[Share]) -> CustodySet {
    CustodySet::of(shares, 3).expect("set")
}

/// A declaration over `presented`, signed by whoever the caller names.
fn declare(set: &CustodySet, presented: &[Share], by: &Ed25519Signer) -> LossDeclaration {
    let doc = LossDeclaration {
        context: ksg_core_v2::doc::Context,
        doc_type: "LossDeclaration".into(),
        v: 3,
        set_root: set.root(),
        presented: u8::try_from(presented.len()).expect("a handful"),
        declared_at: ts(),
        signatures: SignatureSet::default(),
    };
    let s = sign_doc(&doc, by).expect("sign");
    LossDeclaration {
        signatures: SignatureSet::new(vec![s]),
        ..doc
    }
}

#[test]
fn two_of_five_opens_a_thirty_day_window() {
    // The case the mechanism is for: the key is fine, the set is not. Any
    // further loss would be fatal, so the set has to be cut anew — and the
    // re-split has to be provably of the same secret.
    let all = shares();
    let s = set(&all);
    let left = &all[..2];

    let d = declare(&s, left, &owner());
    let window = d
        .validate(
            &s,
            left,
            &owner().public(),
            &issuer().public(),
            &Profile::default(),
        )
        .expect("what is left, presented and checked");
    assert_eq!(window, Window::Short);
    assert_eq!(window.ms(), WINDOW_MS, "thirty days");
}

#[test]
fn a_thief_with_two_shares_does_not_open_the_window() {
    // `[decision]` 19.09, and this is what the owner's signature buys. Without it a
    // thief who took two shares could open the window and wait it out; the
    // theft would be caught at the far end, thirty days later, by the issuer.
    // With it the thief does not start.
    let all = shares();
    let s = set(&all);
    let stolen = &all[..2];

    declare(&s, stolen, &stranger())
        .validate(
            &s,
            stolen,
            &owner().public(),
            &issuer().public(),
            &Profile::default(),
        )
        .expect_err("holding the shares is not the same as being their owner");
}

#[test]
fn the_issuer_can_declare_when_the_owners_key_went_too_but_waits_longer() {
    // The cost of the owner's signature, named rather than hidden: if the
    // owner's key is lost together with the shares, nothing can be signed and
    // the set could never be re-cut. So the issuer may declare instead — and
    // the window is longer, because a stranger's word needs more time to be
    // argued with than the owner's.
    let all = shares();
    let s = set(&all);
    let left = &all[..2];

    let window = declare(&s, left, &issuer())
        .validate(
            &s,
            left,
            &owner().public(),
            &issuer().public(),
            &Profile::default(),
        )
        .expect("the issuer's declaration stands");
    assert_eq!(window, Window::Long);
    assert_eq!(window.ms(), WINDOW_WITHOUT_OWNER_MS, "ninety days");
}

#[test]
fn presenting_enough_to_reconstruct_is_not_a_loss() {
    // Three of five is a reconstruction, not a loss. Calling it a loss would
    // open a window where none is needed — and a window is a period in which
    // the set can be replaced.
    let all = shares();
    let s = set(&all);
    let three = &all[..3];

    declare(&s, three, &owner())
        .validate(
            &s,
            three,
            &owner().public(),
            &issuer().public(),
            &Profile::default(),
        )
        .expect_err("three of five reconstructs; nothing is lost");
}

#[test]
fn a_declaration_of_another_set_is_refused() {
    let all = shares();
    let s = set(&all);
    let other_secret = b"a different secret entirely";
    let other = split_3_of_5(
        other_secret,
        &vec![9u8; entropy_needed(other_secret.len(), 3, 5)],
    )
    .expect("split");
    let other_set = set(&other);

    declare(&other_set, &other[..2], &owner())
        .validate(
            &s,
            &all[..2],
            &owner().public(),
            &issuer().public(),
            &Profile::default(),
        )
        .expect_err("the declaration names another set's root");
}

#[test]
fn the_window_runs_on_anchors_not_on_a_clock() {
    // The crate has no clock on purpose. Elapsed time is the distance between
    // the declaration's anchor and the next one, and neither side of it is the
    // declarant's to write.
    assert_eq!(standing(Window::Short, 0), Standing::Open);
    assert_eq!(standing(Window::Short, WINDOW_MS - 1), Standing::Open);
    assert_eq!(standing(Window::Short, WINDOW_MS), Standing::MayResplit);

    // And the long window really is longer: the same wait that ends a short
    // one leaves a long one running.
    assert_eq!(standing(Window::Long, WINDOW_MS), Standing::Open);
    assert_eq!(
        standing(Window::Long, WINDOW_WITHOUT_OWNER_MS),
        Standing::MayResplit
    );
}

#[test]
fn a_declaration_with_nothing_presented_proves_nothing() {
    // The degenerate case, refused explicitly: an empty presentation passes
    // every per-share check trivially, because there are no shares to check.
    // Without this the window would open on a signature alone.
    let all = shares();
    let s = set(&all);
    declare(&s, &[], &owner())
        .validate(
            &s,
            &[],
            &owner().public(),
            &issuer().public(),
            &Profile::default(),
        )
        .expect_err("nothing presented is not a presentation");
}

#[test]
fn a_share_that_is_not_this_sets_does_not_count() {
    // The check that makes the presentation proof rather than assertion: the
    // root is public, so anyone can name the set. Only the holder can present
    // a share that matches a commitment inside it.
    let all = shares();
    let s = set(&all);
    let foreign = split_3_of_5(
        b"somebody else's secret",
        &vec![3u8; entropy_needed(22, 3, 5)],
    )
    .expect("split");

    let mixed = vec![all[0].clone(), foreign[1].clone()];
    declare(&s, &mixed, &owner())
        .validate(
            &s,
            &mixed,
            &owner().public(),
            &issuer().public(),
            &Profile::default(),
        )
        .expect_err("a share from another split matches no commitment here");
}
