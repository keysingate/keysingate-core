//! The issuance label of a `bare` (owner's decisions 17.10): sealed to the
//! owner's read key, signed by the issuer, passed on by the former owner.

use ksg_cli_v2::issue_label::{open, read_public, read_secret, seal, Label};
use ksg_core_v2::crypto::sign::Ed25519Signer;
use ksg_core_v2::doc::Uri;

fn signer(kid: &str, byte: u8) -> Ed25519Signer {
    Ed25519Signer::from_seed(Uri::parse(kid).unwrap(), [byte; 32])
}

fn evm(byte: u8) -> ksg_anchor_v2::evm::EvmKey {
    ksg_anchor_v2::evm::EvmKey::from_slice(&[byte; 32]).unwrap()
}

fn issued() -> (Label, Ed25519Signer) {
    let owner = signer("did:key:zOwnerA#k1", 1);
    (
        Label::issue(owner.public(), 1_000, &evm(0x43)).unwrap(),
        owner,
    )
}

#[test]
fn a_label_opens_with_the_read_key_it_was_sealed_to_and_no_other() {
    let (label, _) = issued();
    let read = read_secret(&[9u8; 32]);
    let memo = seal(&label, &read_public(&read), &[3u8; 56]).unwrap();
    assert_eq!(open(&memo, &read).unwrap(), label);
    let other = read_secret(&[8u8; 32]);
    assert!(
        open(&memo, &other).is_err(),
        "another read key opens nothing"
    );
    // The read key is not the owner's seed: it signs nothing.
    assert_ne!(*read, [9u8; 32]);
}

#[test]
fn a_label_claiming_another_issuer_does_not_verify() {
    let (mut label, _) = issued();
    label.issuer =
        ksg_anchor_v2::evm::hex0x(&ksg_anchor_v2::evm::address_of(evm(0x44).verifying_key()));
    assert!(
        label.verify().is_err(),
        "\"issued by X\" cannot be rewritten"
    );
    let (mut label, _) = issued();
    label.issued_ms += 1;
    assert!(label.verify().is_err(), "nor the date");
}

#[test]
fn only_the_current_owner_passes_the_label_on_and_a_pass_cannot_be_rewritten() {
    let (label, a) = issued();
    let b = signer("did:key:zOwnerB#k1", 2);
    let c = signer("did:key:zOwnerC#k1", 3);
    assert!(
        label.pass_to(&b, c.public(), 2_000).is_err(),
        "a stranger does not pass it on"
    );
    let to_b = label.pass_to(&a, b.public(), 2_000).unwrap();
    to_b.verify().unwrap();
    assert_eq!(to_b.current_owner(), &b.public());
    let to_c = to_b.pass_to(&b, c.public(), 3_000).unwrap();
    to_c.verify().unwrap();
    assert!(
        to_b.pass_to(&a, c.public(), 3_000).is_err(),
        "the former owner no longer does"
    );

    let mut forged = to_c.clone();
    forged.passes[0].to = c.public();
    assert!(forged.verify().is_err(), "a pass cannot be redirected");
}
