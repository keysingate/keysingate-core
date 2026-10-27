//! The unload gate — K-1 of the blocker registry.
//!
//! What the gate is for: the work journal's contents are reached by exactly
//! three paths, there is no fourth, and every refused attempt leaves a record
//! that sits under the anchor (`[decision]` 11.09, B-6).

use ksg_container_v2::operation::Role;
use ksg_container_v2::{
    authorize_unload, Granted, Operation, Presenters, Refusal, Roster, Route, Subject,
};
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{Ed25519Signer, Profile, PublicKey};
use ksg_core_v2::doc::{MemoFormat, Uri};

fn uri(s: &str) -> Uri {
    Uri::parse(s).expect("uri")
}
fn signer(seed: u8, kid: &str) -> Ed25519Signer {
    Ed25519Signer::from_seed(uri(kid), [seed; 32])
}
fn container() -> Hash {
    Hash::sha256(b"the container")
}

fn client() -> PublicKey {
    signer(1, "did:key:zClient#c1").public()
}
fn owner() -> PublicKey {
    signer(2, "did:key:zOwner#o1").public()
}
fn issuer() -> PublicKey {
    signer(3, "did:key:zIssuer#i1").public()
}

fn roster() -> Roster {
    let mut r = Roster::new();
    r.add(client(), Role::Client)
        .add(owner(), Role::Owner)
        .add(issuer(), Role::Issuer);
    r
}

fn gate(
    op: Operation,
    signers: &[PublicKey],
) -> Result<ksg_container_v2::Unload, Box<ksg_container_v2::Denied>> {
    gate_formed(MemoFormat::Controlled, op, signers)
}

/// The same gate, for a container born in the memo form the caller names.
fn gate_formed(
    memo: MemoFormat,
    op: Operation,
    signers: &[PublicKey],
) -> Result<ksg_container_v2::Unload, Box<ksg_container_v2::Denied>> {
    let roster = roster();
    authorize_unload(
        Subject {
            container: container(),
            memo,
        },
        op,
        &Route::Principals,
        Presenters {
            signers,
            roster: &roster,
        },
        &Profile::default(),
        1_000,
    )
}

#[test]
fn the_principals_together_open_the_gate() {
    let unload = gate(Operation::FullExport, &[client(), owner()])
        .expect("the owner and the client together");
    assert_eq!(unload.how, Granted::Principals);
    assert_eq!(unload.container, container());
}

#[test]
fn one_principal_alone_does_not() {
    // Exactly the hole closed on 17.09 in the operation seats: the export
    // is not pressed alone.
    let denied = gate(Operation::FullExport, &[owner()]).expect_err("one owner is not enough");
    assert!(
        matches!(denied.reason, Refusal::RoleMissing { .. }),
        "got {:?}",
        denied.reason
    );
}

#[test]
fn a_key_with_a_role_that_is_not_a_seat_does_not_open_it_either() {
    // The issuer key is always in the container set, and before 17.09 it pressed
    // the export alone.
    let denied = gate(Operation::FullExport, &[issuer(), owner()])
        .expect_err("the issuer does not take the client seat");
    assert!(matches!(denied.reason, Refusal::RoleMissing { .. }));
}

#[test]
fn the_gate_refuses_an_operation_that_is_not_an_unload() {
    let denied = gate(Operation::RecordWork, &[client(), owner()])
        .expect_err("the gate handles only the export");
    assert!(
        matches!(denied.reason, Refusal::WrongButton { .. }),
        "got {:?}",
        denied.reason
    );
}

#[test]
fn every_refusal_carries_the_record_of_the_attempt() {
    // `[decision]` 11.09 on B-6: the attempt is written under the anchor. Silence
    // would mean someone rattled the door and no one would ever know.
    let denied = gate(Operation::FullExport, &[owner()]).expect_err("refusal");
    let attempt = &denied.attempt;

    assert_eq!(attempt.container, container());
    assert_eq!(attempt.offset_ms, 1_000);
    assert_eq!(
        attempt.presented,
        vec![owner().kid],
        "the attempt is not anonymous: it holds whoever signed"
    );
    assert!(
        !attempt.reason.is_empty(),
        "the refusal reason must be recorded"
    );
}

#[test]
fn the_disclosure_to_an_expert_goes_through_the_same_gate() {
    // The second export operation — by the same path and the same seats.
    let unload = gate(Operation::DiscloseToExpert, &[client(), owner()])
        .expect("disclosure to the expert by the principals");
    assert_eq!(unload.how, Granted::Principals);
}

#[test]
fn a_plain_format_container_does_not_go_outside_at_all() {
    // `[decision]` 13.09 §8.3, the second half of the rule. The first half — a plain
    // container takes no anchors — was not enough by itself: a playground that
    // anchors nothing could still be handed out as evidence, and then the two
    // forms would differ only in how they were filled, not in what they are.
    //
    // Checked before roles and signatures: a playground's refusal does not
    // depend on who signed, and working through the roster first would be
    // answering a question that should not have arisen.
    for op in [Operation::FullExport, Operation::DiscloseToExpert] {
        let denied = gate_formed(MemoFormat::Plain, op, &[owner(), client()])
            .expect_err("a playground is not presented");
        assert!(
            matches!(denied.reason, Refusal::PlainIsNotPresented),
            "{:?}",
            denied.reason
        );
        // And the attempt is still recorded: trying to carry a playground
        // outside is the more reason for the attempt to sit under an anchor.
        assert_eq!(denied.attempt.container, container());
    }

    // The same signatures on a controlled container get through the gate.
    gate_formed(
        MemoFormat::Controlled,
        Operation::FullExport,
        &[owner(), client()],
    )
    .expect("the controlled form is what unloading is for");
}
