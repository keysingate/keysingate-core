//! The composition of an event. KS-7 §4 — O-1, and O-4 with it.
//!
//! The two checks an event makes of its own are about identity and freshness:
//! that this is the right container, and that the presenter is looking at it as
//! it is. That is the work the code phrase was for, done with no secret to store.

use ksg_container_v2::{
    Blocked, Button, Event, Head, Operation, Refusal, Role, Roster, Status, View, Wrapped,
};
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{Ed25519Signer, KeySet, Profile, SignatureSet};
use ksg_core_v2::doc::Uri;

fn uri(s: &str) -> Uri {
    Uri::parse(s).expect("uri")
}
fn client() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:key:zAgent#a1"), [42u8; 32])
}
fn owner() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:key:zOwner#o1"), [44u8; 32])
}
fn p() -> Profile {
    Profile::default()
}
fn keys() -> KeySet {
    [client().public(), owner().public()].into_iter().collect()
}
fn roster() -> Roster {
    Roster::of([
        (client().public(), Role::Client),
        (owner().public(), Role::Owner),
    ])
}
fn container() -> Hash {
    Hash::sha256(b"this container")
}
fn head(counter: u64) -> Head {
    Head {
        counter,
        page: Hash::sha256(format!("page {counter}").as_bytes()),
    }
}

// The event is signed over its subject(): arbitrary bytes are no longer
// accepted — otherwise one command's signature carries over to another
// (13.09 security audit, finding 2).

fn event(op: Operation, at: Option<Head>, signers: &[&Ed25519Signer]) -> Event {
    let mut e = Event {
        op,
        button: op.button(),
        container: container(),
        payload: Wrapped::received(b"already wrapped".to_vec()),
        signatures: SignatureSet::default(),
        covered: Vec::new(),
        head: at,
    };
    e.covered = e.subject();
    e.signatures = SignatureSet::new(signers.iter().map(|s| s.sign(&e.covered)).collect());
    e
}

fn press(e: &Event, at: Option<Head>) -> Result<(), Refusal> {
    press_at(e, at, Status::InWork)
}

/// Some operations belong to a status of their own — opening the journal is the
/// move INTO work, so it is not offered from inside it.
fn press_at(e: &Event, at: Option<Head>, status: Status) -> Result<(), Refusal> {
    e.press(&view(at, status), &keys(), &p())
        .map(|_| ())
        .map_err(|r| r.reason)
}

fn view(head: Option<Head>, status: Status) -> View<'static> {
    // Leaked so the view can borrow for the whole test; a real caller holds its
    // own container id and roster and lends them.
    View {
        container: Box::leak(Box::new(container())),
        head,
        status,
        blocked: Blocked::No,
        roster: Box::leak(Box::new(roster())),
    }
}

#[test]
fn an_event_of_the_agreed_composition_goes_through() {
    let e = event(Operation::RecordWork, Some(head(7)), &[&client()]);
    press(&e, Some(head(7))).expect("the composition O-1 settles");
}

#[test]
fn an_event_for_another_container_is_refused() {
    // §3.1 keeps containers from seeing each other. It does nothing to stop a
    // command captured at one being presented at another — naming the container
    // inside the signed bytes does, and this is that check.
    let mut e = event(Operation::RecordWork, Some(head(7)), &[&client()]);
    e.container = Hash::sha256(b"the neighbour");
    assert_eq!(press(&e, Some(head(7))), Err(Refusal::WrongContainer));
}

#[test]
fn a_stale_view_of_the_journal_is_refused() {
    // O-4 without a secret: a captured command dies the moment anything is
    // written, because the head it names is no longer the head.
    let e = event(Operation::RecordWork, Some(head(7)), &[&client()]);
    assert_eq!(press(&e, Some(head(8))), Err(Refusal::StaleHead));
}

#[test]
fn a_head_from_the_future_is_no_better_than_one_from_the_past() {
    // Equality both ways. A presenter naming a page that does not exist yet is
    // not looking at this container either.
    let e = event(Operation::RecordWork, Some(head(9)), &[&client()]);
    assert_eq!(press(&e, Some(head(8))), Err(Refusal::StaleHead));
}

#[test]
fn the_same_counter_with_another_page_is_still_stale() {
    // The digest is in the claim, not only the number: two different pages can
    // hold one counter across a fork, and the number alone would not tell them
    // apart.
    let mut claimed = head(7);
    claimed.page = Hash::sha256(b"some other page 7");
    let e = event(Operation::RecordWork, Some(claimed), &[&client()]);
    assert_eq!(press(&e, Some(head(7))), Err(Refusal::StaleHead));
}

#[test]
fn a_container_with_no_journal_has_no_head_to_claim() {
    // Before page 0 there is nothing to refer to, and requiring a reference
    // would make the first event impossible.
    let e = event(Operation::OpenJournal, None, &[&client()]);
    press_at(&e, None, Status::Initiated).expect("no journal, no head");
    // And claiming one anyway is refused.
    let lying = event(Operation::OpenJournal, Some(head(0)), &[&client()]);
    assert_eq!(
        press_at(&lying, None, Status::Initiated),
        Err(Refusal::StaleHead)
    );
}

#[test]
fn the_event_carries_no_keys_and_the_signatures_still_check() {
    // The field was dropped on purpose: the container knows the keys from its
    // own layers, and each signature names its own. Two sources of one truth
    // diverge, and then the question is which of them decides.
    let e = event(
        Operation::AttachArtifactOrRights,
        Some(head(3)),
        &[&client(), &owner()],
    );
    press(&e, Some(head(3))).expect("keys come from the layers, not from the event");
    // A signature over other bytes is still caught — and since 13.09 it is
    // caught one step earlier and by name: the bytes are not this event's
    // subject at all, so the signatures say nothing about this command.
    let mut tampered = e.clone();
    tampered.covered = b"other bytes entirely".to_vec();
    assert_eq!(
        press(&tampered, Some(head(3))),
        Err(Refusal::UnboundSignature)
    );
}

#[test]
fn nothing_on_this_path_opens_the_payload() {
    // §4.2: the event is data and executes nothing. The payload goes in wrapped
    // and comes out of `command()` as the same bytes, unparsed.
    let e = event(Operation::RecordWork, Some(head(1)), &[&client()]);
    assert_eq!(e.command().payload, b"already wrapped".to_vec());
    assert_eq!(e.payload.bytes(), b"already wrapped");
}

#[test]
fn a_refused_event_still_hands_over_the_record() {
    // O-2 holds here too: the refusals an event adds of its own are refusals
    // like any other, and each arrives with the attempt to anchor.
    let mut e = event(Operation::RecordWork, Some(head(7)), &[&client()]);
    e.container = Hash::sha256(b"the neighbour");
    let refused = e
        .press(&view(Some(head(7)), Status::InWork), &keys(), &p())
        .expect_err("another container");
    assert_eq!(refused.attempt.op, Operation::RecordWork);
    assert_eq!(refused.attempt.reason, Refusal::WrongContainer);
    assert_eq!(refused.attempt.signers, vec![client().public().kid]);
}

#[test]
fn the_door_the_event_names_is_the_door_it_is_judged_at() {
    // The button is a field of the event, so an event offered at the wrong door
    // is refused by the same rule as a command — not by a separate one.
    // The door is signed over, so it is changed the way a presenter would have
    // to: the whole event is re-made and re-signed at the wrong door. Editing
    // the field after signing is a different failure now — see below.
    let mut e = event(Operation::RecordWork, Some(head(2)), &[&client()]);
    e.button = Button::Export;
    e.covered = e.subject();
    e.signatures = SignatureSet::new(vec![client().sign(&e.covered)]);
    assert!(matches!(
        press(&e, Some(head(2))),
        Err(Refusal::WrongButton { .. })
    ));

    // And the swap the audit named: take a signed event and edit the door on
    // it. The signatures no longer cover the event they arrive with.
    let mut swapped = event(Operation::RecordWork, Some(head(2)), &[&client()]);
    swapped.button = Button::Export;
    assert_eq!(
        press(&swapped, Some(head(2))),
        Err(Refusal::UnboundSignature)
    );
}
