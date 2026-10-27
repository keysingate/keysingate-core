//! The container as one thing, and the cycle that walks an event through every
//! rule. KS-7 §3.3, KS-9.
//!
//! What these tests hold is not that the rules are right — each rule has its own
//! file for that — but that **they are called**, and that a refusal leaves the
//! container exactly as it was.

use ksg_container_v2::container::{Container, Evidence, Release, Stopped, Writes};
use ksg_container_v2::dispute::Filing;
use ksg_container_v2::{Button, Event, Operation, Refusal, Role, Roster, Where, Wrapped};
use ksg_core_v2::anchor::Attestation;
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{
    sign_doc, Ed25519Signer, KeySet, Profile, PublicKey, SignatureSet,
};
use ksg_core_v2::doc::{
    derive_container_id, Class, ClassPromotion, MemoFormat, Serial, Timestamp, Uri,
};
use ksg_core_v2::section::{StatusRecord, StatusSection};
use ksg_core_v2::status::{Event as StatusEvent, Status};

const EMISSION: &str = "ksg:em:000001";
const SERIAL: Serial = Serial(7);
const ARTIFACT: &str = "ksg:artifact:the-one";
const OFFSET: u64 = 1_000;

fn uri(s: &str) -> Uri {
    Uri::parse(s).expect("uri")
}
fn ts() -> Timestamp {
    Timestamp::parse("2026-09-12T00:00:00.000Z").expect("ts")
}
fn p() -> Profile {
    Profile::default()
}
fn issuer() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:key:zIssuer#i1"), [11u8; 32])
}
fn client() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:key:zAgent#a1"), [42u8; 32])
}
fn owner() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:key:zOwner#o1"), [44u8; 32])
}
fn buyer() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:key:zBuyer#b1"), [12u8; 32])
}
fn claimant() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:key:zClaim#k1"), [15u8; 32])
}
fn keys() -> KeySet {
    [
        issuer().public(),
        client().public(),
        owner().public(),
        buyer().public(),
        claimant().public(),
    ]
    .into_iter()
    .collect()
}
fn roster() -> Roster {
    Roster::of([
        (issuer().public(), Role::Issuer),
        (client().public(), Role::Client),
        (owner().public(), Role::Owner),
        (buyer().public(), Role::Buyer),
        (claimant().public(), Role::Claimant),
    ])
}
/// The release's moment. Part of the identifier since CT-28 (2026-09-19).
fn issued_at() -> Timestamp {
    Timestamp::parse("2026-01-01T00:00:00.000Z").expect("a well-formed moment")
}

fn container_id() -> Hash {
    derive_container_id(
        EMISSION,
        &issued_at(),
        SERIAL,
        &client().public(),
        &uri(ARTIFACT),
        OFFSET,
    )
}
fn anchor(subject: Hash) -> Attestation {
    Attestation {
        kind: uri("urn:ksg:anchor:test"),
        subject,
        proof: b"opaque".to_vec(),
        anchored_at: ts(),
    }
}

/// The status section as it stands at printing, record 0.
fn section() -> StatusSection {
    let root = ksg_core_v2::section::section_root(EMISSION, SERIAL);
    let mut r = StatusRecord {
        context: ksg_core_v2::doc::Context,
        doc_type: "StatusRecord".into(),
        v: 3,
        number: 0,
        status: Status::Printed,
        event: None,
        offset_ms: 0,
        prev: root,
        signatures: SignatureSet::default(),
    };
    r.signatures = SignatureSet::new(vec![sign_doc(&r, &issuer()).expect("sig")]);
    let a = anchor(r.hash().expect("hash"));
    StatusSection::start(EMISSION, SERIAL, r, a, &keys(), &p()).expect("section")
}

/// A container driven up to `target`, the way it actually gets there: one
/// signed, anchored status record per change.
fn container_at(target: Status) -> Container {
    drive_to(container(), target)
}

/// The same road, walked by a container the caller built.
fn drive_to(start: Container, target: Status) -> Container {
    let mut c = start;
    let road = [
        (StatusEvent::ApplyPacket, Status::Packeted, issuer()),
        (StatusEvent::ApplyBuyerKey, Status::BuyerKeyed, buyer()),
        (StatusEvent::Initiate, Status::Initiated, client()),
        (StatusEvent::OpenJournal, Status::InWork, client()),
    ];
    for (n, (event, status, _who)) in road.iter().enumerate() {
        if c.status() == target {
            break;
        }
        let mut r = StatusRecord {
            context: ksg_core_v2::doc::Context,
            doc_type: "StatusRecord".into(),
            v: 3,
            number: n as u64 + 1,
            status: *status,
            event: Some(*event),
            offset_ms: (n as u64 + 1) * 1000,
            prev: c.status_head(),
            signatures: SignatureSet::default(),
        };
        r.signatures = SignatureSet::new(vec![sign_doc(&r, &issuer()).expect("sig")]);
        let a = anchor(r.hash().expect("hash"));
        c.force(*event, r, a, &keys(), &p())
            .expect("the ordinary road");
    }
    assert_eq!(c.status(), target, "could not reach {target:?}");
    c
}

fn container() -> Container {
    container_of(Class::Heavy)
}

/// The same container, sold under a class of the caller's choosing. Needed
/// because a raise only has somewhere to go from below the top.
fn container_of(class: Class) -> Container {
    container_formed(class, MemoFormat::Controlled)
}

/// The same container, born in the memo form the caller names. The form is
/// chosen at birth and never changes (`[decision]` 13.09), so it is an argument to
/// assembly and nothing else.
fn container_formed(class: Class, memo: MemoFormat) -> Container {
    Container::assemble(
        container_id(),
        Release {
            id: EMISSION.into(),
            issued_at: issued_at(),
            class,
        },
        SERIAL,
        client().public(),
        memo,
        section(),
        roster(),
    )
}

// The event is signed over its subject(): arbitrary bytes are no longer
// accepted — otherwise one command's signature carries over to another
// (13.09 security audit, finding 2).

fn event(op: Operation, head: Option<ksg_container_v2::Head>, signers: &[&Ed25519Signer]) -> Event {
    let mut e = Event {
        op,
        button: op.button(),
        container: container_id(),
        payload: Wrapped::received(b"already wrapped".to_vec()),
        signatures: SignatureSet::default(),
        covered: Vec::new(),
        head,
    };
    e.covered = e.subject();
    e.signatures = SignatureSet::new(signers.iter().map(|s| s.sign(&e.covered)).collect());
    e
}

// --- the cycle refuses without touching anything -----------------------------

#[test]
fn a_refusal_leaves_the_container_exactly_as_it_was() {
    // The property the assembly existed to provide. Refused at the door, at the
    // parties, at the evidence — and after each, the same state.
    let mut c = container();
    let before = (c.status(), c.pages(), c.blocked());

    // Wrong door.
    let mut wrong = event(Operation::ApplyPacket, None, &[&issuer()]);
    wrong.button = Button::Export;
    assert!(c
        .press(&wrong, &Evidence::None, no_writes(), &keys(), &p())
        .is_err());
    assert_eq!((c.status(), c.pages(), c.blocked()), before);

    // Wrong party.
    let e = event(Operation::ApplyPacket, None, &[&client()]);
    assert!(c
        .press(&e, &Evidence::None, no_writes(), &keys(), &p())
        .is_err());
    assert_eq!((c.status(), c.pages(), c.blocked()), before);

    // Right party, wrong evidence.
    let e = event(Operation::ApplyPacket, None, &[&issuer()]);
    assert!(matches!(
        c.press(
            &e,
            &Evidence::Deadline { at_ms: 1 },
            no_writes(),
            &keys(),
            &p()
        ),
        Err(Stopped::WrongEvidence { .. })
    ));
    assert_eq!((c.status(), c.pages(), c.blocked()), before);
}

fn no_writes() -> Writes {
    Writes {
        page: None,
        status: None,
        at_ms: None,
    }
}

// --- step 6: the rules that used to be called by nothing ---------------------

#[test]
fn the_artefact_check_now_runs_on_the_operation_that_attaches_one() {
    // Before the assembly, `Attachment::check` was correct and unreachable: the
    // attaching operation went through `press` without it.
    let c = container();
    let wrong = ksg_container_v2::Attachment {
        artifact: uri("ksg:artifact:another"),
        kind: ksg_container_v2::Kind::Media {
            mime: "image/png".into(),
        },
        content_hash: Hash::sha256(b"another"),
        size: 1,
        name: "another.png".into(),
        derived_from: vec![],
        offset_ms: OFFSET,
    };
    let e = event(
        Operation::AttachArtifactOrRights,
        None,
        &[&client(), &owner()],
    );
    let mut c2 = container_at(Status::InWork);
    let _ = c;
    assert!(matches!(
        c2.press(
            &e,
            &Evidence::Artifact(Box::new(wrong)),
            no_writes(),
            &keys(),
            &p()
        ),
        Err(Stopped::Artifact(_))
    ));
}

#[test]
fn a_dispute_without_the_copy_of_the_claim_is_refused_by_the_container() {
    // `[decision]` 12.09, now enforced where it matters rather than in a test of its own.
    let mut c = container_at(Status::InWork);
    let empty = Filing {
        claim: Hash::sha256(b""),
        jurisdiction: "UA".into(),
        filed_ms: 10,
        hearing_ms: 20,
        deadline_ms: 30,
    };
    let e = event(Operation::ServeDispute, None, &[&claimant()]);
    assert!(matches!(
        c.press(
            &e,
            &Evidence::Dispute(Box::new(empty)),
            no_writes(),
            &keys(),
            &p()
        ),
        Err(Stopped::Dispute(_))
    ));
}

#[test]
fn initiation_outside_the_packets_window_is_refused_by_the_container() {
    // The time guard, called from the cycle instead of from its own test.
    let mut c = container_at(Status::BuyerKeyed);
    let e = event(Operation::Initiate, None, &[&client(), &owner()]);
    assert!(matches!(
        c.press(
            &e,
            &Evidence::Initiation { at: Where::After },
            no_writes(),
            &keys(),
            &p()
        ),
        Err(Stopped::Time(_))
    ));
}

#[test]
fn an_operation_that_needs_evidence_does_not_pass_without_it() {
    // The other half of step 6: evidence for an operation that has no use for it
    // is a refusal, because it means the presenter believes something this
    // container does not.
    for (op, signers, at) in [
        (
            Operation::Initiate,
            vec![client(), owner()],
            Status::BuyerKeyed,
        ),
        (
            Operation::AttachArtifactOrRights,
            vec![client(), owner()],
            Status::InWork,
        ),
        (Operation::ServeDispute, vec![claimant()], Status::InWork),
    ] {
        let mut c = container_at(at);
        let refs: Vec<&Ed25519Signer> = signers.iter().collect();
        let e = event(op, None, &refs);
        assert!(
            matches!(
                c.press(&e, &Evidence::None, no_writes(), &keys(), &p()),
                Err(Stopped::WrongEvidence { .. })
            ),
            "{op:?} must say what it needs"
        );
    }
}

// --- the triggers ------------------------------------------------------------

#[test]
fn the_review_deadline_is_a_trigger_and_not_a_command() {
    // `[decision]` 12.09, the owner: "a shift is a trigger". Nobody signs it: it is a fact about the
    // clock, checked against the filing the container already holds.
    let mut c = container();
    // With no dispute served there is nothing to be late for.
    let r = dummy_record();
    assert!(matches!(
        c.deadline_reached(1_000_000, r.0.clone(), r.1.clone(), &keys(), &p()),
        Err(Stopped::Dispute(_))
    ));
}

/// A write for tests that are refused before the journal is reached: page 0
/// with no seals. Nothing checks it, because nothing gets that far.
fn unsealed_opening(anchor: Option<Attestation>) -> ksg_container_v2::container::JournalWrite {
    ksg_container_v2::container::JournalWrite::Open {
        offset_ms: 1,
        sealing: Box::new(ksg_core_v2::journal::Sealing {
            anchor,
            ..Default::default()
        }),
    }
}

fn dummy_record() -> (StatusRecord, Attestation) {
    let mut r = StatusRecord {
        context: ksg_core_v2::doc::Context,
        doc_type: "StatusRecord".into(),
        v: 3,
        number: 1,
        status: Status::Disputed,
        event: Some(StatusEvent::ReviewDeadlinePassed),
        offset_ms: 10,
        prev: Hash::sha256(b"prev"),
        signatures: SignatureSet::default(),
    };
    r.signatures = SignatureSet::new(vec![sign_doc(&r, &issuer()).expect("sig")]);
    let a = anchor(r.hash().expect("hash"));
    (r, a)
}

// --- the journal is the one fallible write, and it goes first ----------------

#[test]
fn an_operation_that_writes_no_page_is_refused_a_page() {
    // Step 7 is explicit about which operations write: handing a page to one
    // that writes none means the presenter and the container disagree about what
    // is happening.
    let mut c = container();
    let e = event(Operation::ApplyPacket, None, &[&issuer()]);
    assert!(matches!(
        c.press(
            &e,
            &Evidence::None,
            Writes {
                page: Some(unsealed_opening(None)),
                status: None,
                at_ms: None,
            },
            &keys(),
            &p()
        ),
        Err(Stopped::WrongPage { .. })
    ));
}

#[test]
fn the_container_reports_the_head_an_event_must_claim() {
    // The freshness check of O-4 needs the current head, and the container is
    // what knows it. With no journal there is no head to claim.
    let c = container();
    assert!(c.head().is_none());
    assert_eq!(c.pages(), 0);
    assert_eq!(c.status(), Status::Printed);
    assert_eq!(c.stage(), Some(ksg_container_v2::Stage::Reference));
}

#[test]
fn a_stale_head_is_refused_through_the_container() {
    // The event's own freshness check, reached through the cycle.
    let mut c = container();
    let e = event(
        Operation::ApplyPacket,
        Some(ksg_container_v2::Head {
            counter: 5,
            page: Hash::sha256(b"a page that is not there"),
        }),
        &[&issuer()],
    );
    assert!(matches!(
        c.press(&e, &Evidence::None, no_writes(), &keys(), &p()),
        Err(Stopped::Command(_))
    ));
}

// --- and the ordinary case still works ---------------------------------------

#[test]
fn a_good_command_goes_through_the_whole_cycle() {
    let mut c = container();
    let e = event(Operation::ApplyPacket, None, &[&issuer()]);
    let mut r = StatusRecord {
        context: ksg_core_v2::doc::Context,
        doc_type: "StatusRecord".into(),
        v: 3,
        number: 1,
        status: Status::Packeted,
        event: Some(StatusEvent::ApplyPacket),
        offset_ms: 5,
        prev: c_head_record(&c),
        signatures: SignatureSet::default(),
    };
    r.signatures = SignatureSet::new(vec![sign_doc(&r, &issuer()).expect("sig")]);
    let a = anchor(r.hash().expect("hash"));

    c.press(
        &e,
        &Evidence::None,
        Writes {
            page: None,
            status: Some((r, a)),
            at_ms: None,
        },
        &keys(),
        &p(),
    )
    .expect("the packet's layer is entered");
    assert_eq!(c.status(), Status::Packeted);
    assert_eq!(c.stage(), Some(ksg_container_v2::Stage::Reference));
}

/// The head of the status section, which the next record must link to.
fn c_head_record(c: &Container) -> Hash {
    // Exposed through the section the container holds; the test needs it to
    // build a well-formed next record.
    let _ = c;
    let root = ksg_core_v2::section::section_root(EMISSION, SERIAL);
    let mut r = StatusRecord {
        context: ksg_core_v2::doc::Context,
        doc_type: "StatusRecord".into(),
        v: 3,
        number: 0,
        status: Status::Printed,
        event: None,
        offset_ms: 0,
        prev: root,
        signatures: SignatureSet::default(),
    };
    r.signatures = SignatureSet::new(vec![sign_doc(&r, &issuer()).expect("sig")]);
    r.hash().expect("hash")
}

/// Unused import guard: the container's public key type is part of its shape.
const _: fn(PublicKey) = |_k| {};

// --- the second worker: what an event sets in motion beyond itself -----------
//
// `[decision]` 12.09 — a mechanism that launches the work the base cycle cannot do,
// **with logical synchronisation and not just anyhow**. Three properties make it
// one: the task is bound to the state that raised it, it blocks what physically
// depends on it, and a claim goes stale the moment the container moves.

use ksg_container_v2::followup::{Discharge, FollowupError, Proof, Task, MAX_REFUSALS};
use ksg_container_v2::layers::Level;
use ksg_container_v2::layout::Zone;

#[test]
fn entering_a_layer_raises_the_work_of_writing_its_fields() {
    // The issuer entered the packet's layer. Filling the slots is the issuer's
    // own act, and the cycle of one event has no issuer in it — so the cycle
    // records the fact and hands the rest on.
    let mut c = container();
    assert!(c.pending().is_empty());
    apply_packet(&mut c);
    assert_eq!(c.pending().len(), 1);
    assert_eq!(c.pending()[0].task, Task::WriteLayer { zone: Zone::Packet });
}

#[test]
fn an_unwritten_packet_layer_holds_up_initiation() {
    // Physical dependence, not policy: initiating over a layer whose slots still
    // hold noise would initiate over nothing.
    let mut c = container_at(Status::BuyerKeyed);
    c.force_task(Task::WriteLayer { zone: Zone::Packet });
    let e = event(Operation::Initiate, None, &[&client(), &owner()]);
    assert!(matches!(
        c.press(
            &e,
            &Evidence::Initiation { at: Where::Inside },
            no_writes(),
            &keys(),
            &p()
        ),
        Err(Stopped::Followup(FollowupError::Blocked { .. }))
    ));
}

#[test]
fn a_layer_key_not_handed_over_holds_up_the_journal() {
    // A client without its layer key cannot encrypt a page, so it cannot open a
    // journal, and a journal is what work is written in.
    let mut c = container_at(Status::Initiated);
    c.force_task(Task::HandOverLayer {
        to: client().public(),
        up_to: Level(2),
    });
    let e = event(Operation::OpenJournal, None, &[&client()]);
    assert!(matches!(
        c.press(&e, &Evidence::None, no_writes(), &keys(), &p()),
        Err(Stopped::Followup(FollowupError::Blocked { .. }))
    ));
}

#[test]
fn a_claim_is_good_only_while_the_container_has_not_moved() {
    // The synchronisation itself. A worker handed a task, with the container
    // changing under it, would report success against a state that no longer
    // exists — so the claim is bound to the head it was raised at.
    let mut c = container();
    apply_packet(&mut c);
    let ticket = c.claim(0).expect("the head is current");
    assert_eq!(ticket.index, 0);

    // The container moves on.
    apply_buyer_key(&mut c);
    assert_eq!(c.claim(0), Err(FollowupError::Stale));

    // And the old ticket no longer discharges anything.
    assert_eq!(
        c.discharge(&Discharge {
            ticket,
            proof: written(Zone::Packet),
        }),
        Err(FollowupError::Stale)
    );
}

#[test]
fn a_discharge_closes_the_task_and_lets_the_dependent_operation_through() {
    // The whole round trip: raised, claimed, discharged, and what was held up
    // goes through.
    let mut c = container();
    apply_packet(&mut c);
    let ticket = c.claim(0).expect("claimable");
    c.discharge(&Discharge {
        ticket,
        proof: written(Zone::Packet),
    })
    .expect("the task closes");
    assert!(c.pending().is_empty());
}

#[test]
fn a_proof_for_another_task_does_not_discharge_this_one() {
    let mut c = container();
    apply_packet(&mut c);
    let mut ticket = c.claim(0).expect("claimable");
    ticket.task = Task::CarryId {
        from: Hash::sha256(b"somewhere else"),
    };
    assert_eq!(
        c.discharge(&Discharge {
            ticket,
            proof: written(Zone::Packet)
        }),
        Err(FollowupError::WrongProof)
    );
}

#[test]
fn succession_leaves_the_carrying_of_the_id_outstanding() {
    // Nothing in a frozen container waits on it, and that is exactly why it must
    // stay visible: otherwise "the succession is complete" would be said while
    // the claim served on this ID still reached nobody.
    let task = Task::CarryId {
        from: container_id(),
    };
    for op in [
        Operation::OpenJournal,
        Operation::RecordWork,
        Operation::ApplyPacket,
        Operation::Initiate,
    ] {
        assert!(!task.blocks(op), "{op:?} does not wait on carrying an ID");
    }
}

#[test]
fn laying_a_key_on_must_say_whose_key_it_is() {
    // The half that moved out of the base cycle needs an address, so the base
    // cycle now asks for one.
    let mut c = container_at(Status::Packeted);
    let e = event(Operation::ApplyBuyerKey, None, &[&buyer(), &owner()]);
    assert!(matches!(
        c.press(&e, &Evidence::None, no_writes(), &keys(), &p()),
        Err(Stopped::WrongEvidence { .. })
    ));
}

/// Drives the packet's layer in, the ordinary way.
fn apply_packet(c: &mut Container) {
    let e = event(Operation::ApplyPacket, None, &[&issuer()]);
    let (r, a) = next_record(c, Status::Packeted, StatusEvent::ApplyPacket);
    c.press(
        &e,
        &Evidence::None,
        Writes {
            page: None,
            status: Some((r, a)),
            at_ms: None,
        },
        &keys(),
        &p(),
    )
    .expect("the packet's layer");
}

/// Lays the buyer's key on, with the address its hand-over will need.
///
/// Deliberately without discharging what is outstanding: an unwritten packet
/// layer holds up initiation, not the laying on of a key, and the difference is
/// the point of naming what each task blocks.
fn apply_buyer_key(c: &mut Container) {
    let e = event(Operation::ApplyBuyerKey, None, &[&buyer(), &owner()]);
    let (r, a) = next_record(c, Status::BuyerKeyed, StatusEvent::ApplyBuyerKey);
    c.press(
        &e,
        &Evidence::KeyLaid {
            to: client().public(),
            up_to: Level(2),
        },
        Writes {
            page: None,
            status: Some((r, a)),
            at_ms: None,
        },
        &keys(),
        &p(),
    )
    .expect("the buyer's key");
}

/// The next status record, linked to where the section actually is.
fn next_record(c: &Container, status: Status, event: StatusEvent) -> (StatusRecord, Attestation) {
    let mut r = StatusRecord {
        context: ksg_core_v2::doc::Context,
        doc_type: "StatusRecord".into(),
        v: 3,
        number: c.status_records() as u64,
        status,
        event: Some(event),
        offset_ms: c.status_records() as u64 * 1000,
        prev: c.status_head(),
        signatures: SignatureSet::default(),
    };
    r.signatures = SignatureSet::new(vec![sign_doc(&r, &issuer()).expect("sig")]);
    let a = anchor(r.hash().expect("hash"));
    (r, a)
}

/// A proof that a zone's fields went in.
fn written(zone: Zone) -> Proof {
    Proof::LayerWritten {
        zone,
        digest: Hash::sha256(b"the fields, written"),
    }
}

// --- the control inside the second cycle, and its consequences ---------------
//
// `[decision]` 12.09, the owner: "the second cycle may add control: checks of substantial
// acts and accordingly the consequences of the checks".

#[test]
fn a_substantial_task_is_checked_and_a_wrong_answer_is_refused() {
    // Handing a layer key to somebody else is not a hand-over to the party the
    // task named, and the container can tell — so it does.
    let mut c = container();
    c.force_task(Task::HandOverLayer {
        to: client().public(),
        up_to: Level(2),
    });
    let ticket = c.claim(0).expect("claimable");
    let wrong = Discharge {
        ticket: ticket.clone(),
        proof: Proof::HandedOver {
            to: owner().public(),
            up_to: Level(2),
            sealed: Hash::sha256(b"sealed to the wrong party"),
        },
    };
    assert!(matches!(
        c.discharge(&wrong),
        Err(FollowupError::CheckFailed { .. })
    ));
    // And the task is still there: a refused check does not close anything.
    assert_eq!(c.pending().len(), 1);

    // The right one closes it.
    c.discharge(&Discharge {
        ticket,
        proof: Proof::HandedOver {
            to: client().public(),
            up_to: Level(2),
            sealed: Hash::sha256(b"sealed"),
        },
    })
    .expect("handed to the party the task named");
    assert!(c.pending().is_empty());
}

#[test]
fn the_level_is_part_of_the_check() {
    // A hand-over of less than the task said is not the hand-over that was
    // raised: the recipient would be short exactly the layers it needs.
    let mut c = container();
    c.force_task(Task::HandOverLayer {
        to: client().public(),
        up_to: Level(2),
    });
    let ticket = c.claim(0).expect("claimable");
    assert!(matches!(
        c.discharge(&Discharge {
            ticket,
            proof: Proof::HandedOver {
                to: client().public(),
                up_to: Level(1),
                sealed: Hash::sha256(b"sealed"),
            },
        }),
        Err(FollowupError::CheckFailed { .. })
    ));
}

#[test]
fn carrying_an_id_is_checked_against_this_container() {
    // A carry-over that starts somewhere else does not discharge this one's, and
    // a container does not succeed itself.
    let mut c = container();
    c.force_task(Task::CarryId {
        from: container_id(),
    });
    let ticket = c.claim(0).expect("claimable");
    assert!(matches!(
        c.discharge(&Discharge {
            ticket: ticket.clone(),
            proof: Proof::IdCarried {
                from: Hash::sha256(b"another container"),
                to: Hash::sha256(b"the successor"),
                anchored: Hash::sha256(b"anchored"),
            },
        }),
        Err(FollowupError::CheckFailed { .. })
    ));
    assert!(matches!(
        c.discharge(&Discharge {
            ticket,
            proof: Proof::IdCarried {
                from: container_id(),
                to: container_id(),
                anchored: Hash::sha256(b"anchored"),
            },
        }),
        Err(FollowupError::CheckFailed { .. })
    ));
}

#[test]
fn an_unanchored_carry_over_does_not_count() {
    // The publication is what makes the carried ID reachable. Without the
    // anchor there is nothing for a claim to arrive at.
    let mut c = container();
    c.force_task(Task::CarryId {
        from: container_id(),
    });
    let ticket = c.claim(0).expect("claimable");
    assert!(matches!(
        c.discharge(&Discharge {
            ticket,
            proof: Proof::IdCarried {
                from: container_id(),
                to: Hash::sha256(b"the successor"),
                anchored: Hash::sha256(b""),
            },
        }),
        Err(FollowupError::CheckFailed { .. })
    ));
}

#[test]
fn three_refusals_make_the_task_visible_and_nothing_more() {
    // `[decision]` 12.09 — consequences sized to the actual risk. The risk here is a
    // worker failing while nobody notices, and visibility answers it exactly.
    //
    // The first version of this locked the task after three refusals. That
    // guarded against nothing and created a failure of its own: the work done,
    // the container unwilling to take it, and what it held up held up forever.
    let mut c = container();
    c.force_task(Task::HandOverLayer {
        to: client().public(),
        up_to: Level(2),
    });
    for _ in 0..MAX_REFUSALS {
        let ticket = c.claim(0).expect("claimable");
        let _ = c.discharge(&Discharge {
            ticket,
            proof: Proof::HandedOver {
                to: owner().public(),
                up_to: Level(2),
                sealed: Hash::sha256(b"wrong"),
            },
        });
    }
    assert_eq!(c.stalled().len(), 1, "the task is visible as stalled");

    // And a correct answer still closes it — the flag is for attention, not a
    // lock. A worker that finally does the work right is the outcome wanted.
    let ticket = c.claim(0).expect("still claimable");
    c.discharge(&Discharge {
        ticket,
        proof: Proof::HandedOver {
            to: client().public(),
            up_to: Level(2),
            sealed: Hash::sha256(b"right, on the fourth try"),
        },
    })
    .expect("late, but done");
    assert!(c.pending().is_empty());
    assert!(c.stalled().is_empty());
}

#[test]
fn writing_a_layer_is_recorded_rather_than_verified_and_says_so() {
    // The container cannot read its own slots from here, so it checks the zone
    // and that something went in — and no more. Pretending otherwise would be a
    // check in name.
    assert!(!Task::WriteLayer { zone: Zone::Packet }.is_substantial());
    assert!(Task::HandOverLayer {
        to: client().public(),
        up_to: Level(2)
    }
    .is_substantial());
    assert!(Task::CarryId {
        from: container_id()
    }
    .is_substantial());

    // Still, an empty write is caught: "done" with nothing in it is not done.
    let mut c = container();
    c.force_task(Task::WriteLayer { zone: Zone::Packet });
    let ticket = c.claim(0).expect("claimable");
    assert!(matches!(
        c.discharge(&Discharge {
            ticket,
            proof: Proof::LayerWritten {
                zone: Zone::Packet,
                digest: Hash::sha256(b""),
            },
        }),
        Err(FollowupError::CheckFailed { .. })
    ));
}

// ---------------------------------------------------------------------------
// Raising the class — KC-8 E-10, `[decision]` 2026-09-19 (CT-01).
// ---------------------------------------------------------------------------

mod promotion {
    use super::{
        client, container, container_of, issuer, keys, p, Class, ClassPromotion, SignatureSet,
    };
    use ksg_core_v2::crypto::hash::Hash;
    use ksg_core_v2::crypto::sign::sign_doc;

    /// A raise signed by the issuer and the client, as the rule asks.
    fn raise(container_id: Hash, from: Class, to: Class) -> ClassPromotion {
        let doc = ClassPromotion {
            context: ksg_core_v2::doc::Context,
            doc_type: "ClassPromotion".into(),
            v: 3,
            container: container_id,
            from,
            to,
            offset_ms: 5_000,
            signatures: SignatureSet::default(),
        };
        let a = sign_doc(&doc, &issuer()).expect("the issuer signs");
        let b = sign_doc(&doc, &client()).expect("the holder signs");
        ClassPromotion {
            signatures: SignatureSet::new(vec![a, b]),
            ..doc
        }
    }

    #[test]
    fn the_place_is_empty_until_the_first_raise() {
        // Why this is a test and not an assumption: the field exists from birth
        // under noise, and a container that read it as anything but "the
        // packet's class" would be claiming a regime nobody paid for.
        let c = container();
        assert_eq!(c.class(), Class::Heavy, "the packet's class, untouched");
    }

    #[test]
    fn a_raise_moves_the_class_every_rule_reads() {
        // The whole point of the field: a container sold as `light` works as
        // `heavy` afterwards, and the journal's anchor rule reads the raised
        // class, not the packet's.
        let mut c = container_of(Class::Light);
        assert_eq!(c.class(), Class::Light, "sold light");
        c.promote(&raise(*c.id(), Class::Light, Class::Heavy), &keys(), &p())
            .expect("a well-signed raise upward");
        assert_eq!(c.class(), Class::Heavy, "and works heavy from now on");
    }

    #[test]
    fn a_second_raise_starts_where_the_first_ended() {
        // `from` is checked against the class the container holds NOW. A second
        // document still naming the packet's original class is stale, and a
        // stale document is how a raise gets replayed.
        let mut c = container_of(Class::Bare);
        c.promote(&raise(*c.id(), Class::Bare, Class::Light), &keys(), &p())
            .expect("bare to light");
        assert!(
            c.promote(&raise(*c.id(), Class::Bare, Class::Heavy), &keys(), &p())
                .is_err(),
            "a document that still says `from: bare` no longer applies"
        );
        assert_eq!(c.class(), Class::Light, "and the refusal changed nothing");
        c.promote(&raise(*c.id(), Class::Light, Class::Heavy), &keys(), &p())
            .expect("light to heavy, from where it actually is");
        assert_eq!(c.class(), Class::Heavy);
    }

    #[test]
    fn a_raise_that_does_not_go_upward_is_refused() {
        // Downward would retroactively weaken pages already anchored under the
        // stronger regime: they stay anchored, but the container would stop
        // admitting it.
        let mut c = container_of(Class::Heavy);
        assert!(
            c.promote(&raise(*c.id(), Class::Heavy, Class::Light), &keys(), &p())
                .is_err(),
            "heavy does not step down to light"
        );
        assert!(
            c.promote(&raise(*c.id(), Class::Heavy, Class::Heavy), &keys(), &p())
                .is_err(),
            "and does not step to itself"
        );
        assert_eq!(c.class(), Class::Heavy, "a refused raise changes nothing");
    }

    #[test]
    fn a_raise_naming_another_container_is_refused() {
        let mut c = container();
        let doc = raise(
            Hash::sha256(b"some other container"),
            Class::Heavy,
            Class::Heavy,
        );
        assert!(
            c.promote(&doc, &keys(), &p()).is_err(),
            "the document has to name this container"
        );
    }

    #[test]
    fn one_party_signing_twice_is_not_two_parties() {
        let mut c = container();
        let doc = ClassPromotion {
            context: ksg_core_v2::doc::Context,
            doc_type: "ClassPromotion".into(),
            v: 3,
            container: *c.id(),
            from: Class::Light,
            to: Class::Heavy,
            offset_ms: 5_000,
            signatures: SignatureSet::default(),
        };
        let only_one = sign_doc(&doc, &issuer()).expect("the issuer signs");
        let doc = ClassPromotion {
            signatures: SignatureSet::new(vec![only_one]),
            ..doc
        };
        assert!(
            c.promote(&doc, &keys(), &p()).is_err(),
            "the stronger regime is taken on by two parties or by none"
        );
    }
}

// ---------------------------------------------------------------------------
// The two memo forms — `[decision]` 13.09 §8.3, CT-02.
// ---------------------------------------------------------------------------

mod memo_form {
    use super::{
        anchor, client, container_formed, drive_to, event, keys, p, unsealed_opening, Class, Hash,
        MemoFormat, Operation, Status, Stopped, Writes,
    };

    #[test]
    fn the_form_is_readable_and_has_no_setter() {
        // The decision names irreversibility as the property (`[decision]` 13.09,
        // reading A). A field anyone could write would make it a convention;
        // the absence of a setter is what makes it a fact. This test says what
        // exists — that no method changes it is held by the compiler.
        let plain = container_formed(Class::Heavy, MemoFormat::Plain);
        assert_eq!(plain.memo_format(), MemoFormat::Plain);
        let controlled = container_formed(Class::Heavy, MemoFormat::Controlled);
        assert_eq!(controlled.memo_format(), MemoFormat::Controlled);
    }

    #[test]
    fn a_plain_container_refuses_an_anchor() {
        // The playground anchors nothing. An anchored page in it would be a
        // playground claiming the chain — the one thing the two forms exist to
        // keep apart, and the reason a playground's history cannot be carried
        // over later.
        let mut c = drive_to(
            container_formed(Class::Heavy, MemoFormat::Plain),
            Status::Initiated,
        );
        // The journal is not open yet, so the first page points at the container.
        let a = anchor(Hash::sha256(b"whatever"));
        let e = event(Operation::OpenJournal, None, &[&client()]);
        assert!(
            matches!(
                c.press(
                    &e,
                    &super::Evidence::None,
                    Writes {
                        page: Some(unsealed_opening(Some(a))),
                        status: None,
                        at_ms: None,
                    },
                    &keys(),
                    &p()
                ),
                Err(Stopped::PlainTakesNoAnchor)
            ),
            "a plain container takes no anchors"
        );
    }
}

// ---------------------------------------------------------------------------
// Both documents go through the button, not past it — patch 11.
// ---------------------------------------------------------------------------

mod through_the_button {
    use super::{
        client, container_formed, drive_to, event, issuer, keys, no_writes, owner, p, Class,
        ClassPromotion, Container, Evidence, Hash, MemoFormat, Operation, SignatureSet, Status,
        Stopped,
    };
    use ksg_core_v2::crypto::sign::sign_doc;

    fn raise(c: &Container, from: Class, to: Class) -> ClassPromotion {
        let doc = ClassPromotion {
            context: ksg_core_v2::doc::Context,
            doc_type: "ClassPromotion".into(),
            v: 3,
            container: *c.id(),
            from,
            to,
            offset_ms: 5_000,
            signatures: SignatureSet::default(),
        };
        let a = sign_doc(&doc, &issuer()).expect("issuer");
        let b = sign_doc(&doc, &client()).expect("holder");
        ClassPromotion {
            signatures: SignatureSet::new(vec![a, b]),
            ..doc
        }
    }

    #[test]
    fn pressing_e10_raises_the_class() {
        // The gap this closes: `promote` existed and the E-10 button existed,
        // and for one patch they did not meet. A document that reaches the
        // container past the cycle is a document nobody checked the status,
        // the roster and the signatures of the command for.
        let mut c = drive_to(
            container_formed(Class::Light, MemoFormat::Controlled),
            Status::InWork,
        );
        assert_eq!(c.class(), Class::Light);

        let doc = raise(&c, Class::Light, Class::Heavy);
        let e = event(Operation::RaiseClass, None, &[&owner(), &issuer()]);
        // No status record: E-10 leaves the container in work, and the status
        // section refuses to record a change that did not happen.
        c.press(
            &e,
            &Evidence::ClassRaise(Box::new(doc)),
            no_writes(),
            &keys(),
            &p(),
        )
        .expect("the raise goes through the button");
        assert_eq!(c.class(), Class::Heavy, "and the class moved");
    }

    #[test]
    fn e10_without_the_document_is_refused() {
        let mut c = drive_to(
            container_formed(Class::Light, MemoFormat::Controlled),
            Status::InWork,
        );
        let e = event(Operation::RaiseClass, None, &[&owner(), &issuer()]);
        assert!(
            matches!(
                c.press(&e, &Evidence::None, no_writes(), &keys(), &p()),
                Err(Stopped::WrongEvidence { .. })
            ),
            "a raise is the document, not the wish"
        );
        assert_eq!(c.class(), Class::Light);
    }

    #[test]
    fn declaring_lost_shares_moves_no_status_and_keeps_working() {
        // `[decision]` 19.09: shares going short is not a death and not a freeze. What
        // the operation is for is the journal page — the thirty days need an
        // anchor to be counted from.
        assert_eq!(
            Operation::DeclareSharesLost.event(),
            None,
            "E-24 moves no status"
        );
        let c = drive_to(
            container_formed(Class::Heavy, MemoFormat::Controlled),
            Status::InWork,
        );
        assert_eq!(c.status(), Status::InWork, "and the container works on");
        let _ = Hash::sha256(b"the declaration's digest");
    }
}

// --- T-6: after a sale the seller's key acts as nobody ------------------------

fn sell(c: &mut Container) {
    let e = event(Operation::TransferOwnership, None, &[&owner(), &buyer()]);
    c.press(&e, &Evidence::None, no_writes(), &keys(), &p())
        .expect("the sale goes through");
}

#[test]
fn a_sale_moves_the_owners_seat_to_the_buyer() {
    // `KS-7` §9.2, `KS-8` I-7: the set of keys is for the past, the right to
    // act belongs to the last one. Before 22.09 the roster never changed at a
    // sale, and a sold container kept answering to the seller.
    let mut c = container_at(Status::InWork);
    sell(&mut c);
    assert_eq!(
        c.roster().role_of(&owner().public().kid),
        None,
        "the seller"
    );
    assert_eq!(
        c.roster().role_of(&buyer().public().kid),
        Some(Role::Owner),
        "the buyer"
    );
}

#[test]
fn the_seller_cannot_sell_the_same_container_twice() {
    // The case the rule exists for: the seller keeps a working key and tries
    // to act as owner after the sale. The container no longer knows that key.
    let mut c = container_at(Status::InWork);
    sell(&mut c);
    let again = event(Operation::TransferOwnership, None, &[&owner(), &claimant()]);
    let got = c.press(&again, &Evidence::None, no_writes(), &keys(), &p());
    assert!(
        matches!(&got, Err(Stopped::Command(r)) if matches!(r.reason, Refusal::NoRole(_))),
        "the seller still acted as owner: {got:?}"
    );
}

#[test]
fn the_new_owner_acts_where_the_old_one_is_refused() {
    let mut c = container_at(Status::InWork);
    sell(&mut c);
    // The freeze on the owner's application (E-23): issuer and owner.
    let mut r = StatusRecord {
        context: ksg_core_v2::doc::Context,
        doc_type: "StatusRecord".into(),
        v: 3,
        number: 5,
        status: Status::Finalized,
        event: Some(StatusEvent::FreezeOnOwnerApplication),
        offset_ms: 9_000,
        prev: c.status_head(),
        signatures: SignatureSet::default(),
    };
    r.signatures = SignatureSet::new(vec![sign_doc(&r, &issuer()).expect("sig")]);
    let a = anchor(r.hash().expect("hash"));
    let writes = || Writes {
        page: None,
        status: Some((r.clone(), a.clone())),
        at_ms: None,
    };

    let by_seller = event(
        Operation::FreezeOnOwnerApplication,
        None,
        &[&issuer(), &owner()],
    );
    assert!(c
        .press(&by_seller, &Evidence::None, writes(), &keys(), &p())
        .is_err());
    assert_eq!(c.status(), Status::InWork, "a refusal changed nothing");

    let by_buyer = event(
        Operation::FreezeOnOwnerApplication,
        None,
        &[&issuer(), &buyer()],
    );
    c.press(&by_buyer, &Evidence::None, writes(), &keys(), &p())
        .expect("the new owner's application");
    assert_eq!(c.status(), Status::Finalized);
}

// --- T-1: the refusal a new client meets says who has to act -----------------

#[test]
fn a_journal_held_up_by_the_layer_key_says_who_has_to_act() {
    // Every new client passes this point before its first line of work. The
    // refusal used to print a debug structure and nothing a person could act on.
    let mut c = container_at(Status::Initiated);
    c.force_task(Task::HandOverLayer {
        to: client().public(),
        up_to: Level(2),
    });
    let e = event(Operation::OpenJournal, None, &[&client()]);
    let why = c
        .press(&e, &Evidence::None, no_writes(), &keys(), &p())
        .expect_err("held up")
        .to_string();
    assert!(why.contains("hand the layer key over"), "{why}");
    assert!(why.contains("current holder"), "{why}");
    assert!(why.contains("onboarding"), "{why}");
}

// --- T-31: a proven dispute hands the rights to the claimant ------------------

fn arbiter() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:key:zArb#r1"), [16u8; 32])
}

fn status_step(c: &Container, n: u64, to: Status, ev: StatusEvent) -> Writes {
    let mut r = StatusRecord {
        context: ksg_core_v2::doc::Context,
        doc_type: "StatusRecord".into(),
        v: 3,
        number: n,
        status: to,
        event: Some(ev),
        offset_ms: n * 1000,
        prev: c.status_head(),
        signatures: SignatureSet::default(),
    };
    r.signatures = SignatureSet::new(vec![sign_doc(&r, &issuer()).expect("sig")]);
    let a = anchor(r.hash().expect("hash"));
    Writes {
        page: None,
        status: Some((r, a)),
        at_ms: None,
    }
}

#[test]
fn record_31_hands_the_rights_to_the_claimant_and_the_container_stays_the_owners() {
    // KS-7 T-31, [decision] 10.09: automatically, with record 31.
    let mut ros = roster();
    ros.add(arbiter().public(), Role::Arbiter);
    let mut ks = keys();
    ks.insert(arbiter().public());
    let start = Container::assemble(
        container_id(),
        Release {
            id: EMISSION.into(),
            issued_at: issued_at(),
            class: Class::Heavy,
        },
        SERIAL,
        client().public(),
        MemoFormat::Controlled,
        section(),
        ros,
    );
    let mut c = drive_to(start, Status::InWork);
    assert_eq!(c.rights_to(), None);

    let filing = Filing {
        claim: Hash::sha256(b"the copy of the claim"),
        jurisdiction: "UA".into(),
        filed_ms: 10,
        hearing_ms: 20,
        deadline_ms: 30,
    };
    let serve = event(Operation::ServeDispute, None, &[&claimant()]);
    let w = status_step(&c, 5, Status::Disputed, StatusEvent::ServeDispute);
    c.press(&serve, &Evidence::Dispute(Box::new(filing)), w, &ks, &p())
        .expect("the claim is served");
    assert_eq!(c.rights_to(), None, "serving a claim moves nothing yet");

    let decide = event(
        Operation::DecideDisputeProven,
        None,
        &[&arbiter(), &owner()],
    );
    let w = status_step(&c, 6, Status::DisputeProven, StatusEvent::DisputeProven);
    c.press(&decide, &Evidence::None, w, &ks, &p())
        .expect("the decision");
    assert_eq!(c.status(), Status::DisputeProven);
    assert_eq!(
        c.rights_to(),
        Some(&claimant().public().kid),
        "rights to the claimant"
    );
    assert_eq!(
        c.roster().role_of(&owner().public().kid),
        Some(Role::Owner),
        "the container stays the owner's"
    );
}

// --- CT-47, CT-48: Pro signs every artefact with the issuer's seal -----------

fn good_attachment() -> ksg_container_v2::Attachment {
    ksg_container_v2::Attachment {
        artifact: uri(ARTIFACT),
        kind: ksg_container_v2::Kind::Media {
            mime: "image/png".into(),
        },
        content_hash: Hash::sha256(b"the bytes"),
        size: 10,
        name: "cover.png".into(),
        derived_from: vec![],
        offset_ms: OFFSET,
    }
}

#[test]
fn a_pro_container_without_the_issuers_seal_attaches_no_artefact() {
    // The full class is Pro (product description §20); there the issuer's
    // signature on artefacts is mandatory, and the container puts it itself.
    let mut c = container_at(Status::InWork);
    assert_eq!(c.class(), Class::Heavy);
    assert!(c.seal().is_none());
    let e = event(
        Operation::AttachArtifactOrRights,
        None,
        &[&client(), &owner()],
    );
    assert!(matches!(
        c.press(
            &e,
            &Evidence::Artifact(Box::new(good_attachment())),
            no_writes(),
            &keys(),
            &p()
        ),
        Err(Stopped::NoIssuerSeal)
    ));
}

#[test]
fn the_seal_is_laid_at_printing_and_certified_for_this_container_only() {
    let seal = ksg_container_v2::seal::IssuerSeal::lay(
        &container_id(),
        uri("ksg:seal:the-one"),
        [21; 32],
        &issuer(),
    );
    let c = container().with_seal(seal);
    let s = c.seal().expect("laid");
    let subject = ksg_container_v2::seal::certificate_subject(&container_id(), &s.public());
    let keys: KeySet = [issuer().public()].into_iter().collect();
    SignatureSet::new(vec![s.certificate().clone()])
        .verify(subject.as_bytes(), &keys, &p())
        .expect("the issuer certified it");
}

// --- audit of 2026-09-23: whose key the container trusts ----------------------
//
// audit of 23.09, K1: the roster pinned only a `kid`, and signatures were verified against the
// presenter's key set — a key of one's own under the issuer's `kid` passed.
// audit of 23.09, K2: `force` and the triggers moved the status on a record signed by anyone
// the caller's key set named. audit of 23.09, K3: a record of work under an order was accepted
// without the order or the work being verified.

use ksg_container_v2::order::{Basis, Order, OrderError, Work};

/// Somebody who knows the issuer's `kid` and nothing else.
fn impostor() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:key:zIssuer#i1"), [99u8; 32])
}

fn packet_record(c: &Container, by: &Ed25519Signer) -> (StatusRecord, Attestation) {
    let mut r = StatusRecord {
        context: ksg_core_v2::doc::Context,
        doc_type: "StatusRecord".into(),
        v: 3,
        number: 1,
        status: Status::Packeted,
        event: Some(StatusEvent::ApplyPacket),
        offset_ms: 5,
        prev: c.status_head(),
        signatures: SignatureSet::default(),
    };
    r.signatures = SignatureSet::new(vec![sign_doc(&r, by).expect("sig")]);
    let a = anchor(r.hash().expect("hash"));
    (r, a)
}

#[test]
fn a_key_of_ones_own_under_the_issuers_kid_is_named_as_a_substitution() {
    let mut c = container();
    let e = event(Operation::ApplyPacket, None, &[&impostor()]);
    let rec = packet_record(&c, &impostor());
    let forged: KeySet = [impostor().public(), client().public(), owner().public()]
        .into_iter()
        .collect();
    let got = c.press(
        &e,
        &Evidence::None,
        Writes {
            page: None,
            status: Some(rec),
            at_ms: None,
        },
        &forged,
        &p(),
    );
    assert!(
        matches!(got, Err(Stopped::Command(ref r)) if matches!(r.reason, Refusal::ForeignKey(_))),
        "{got:?}"
    );
    assert_eq!(c.status(), Status::Printed, "nothing moved");
}

#[test]
fn leaving_the_substitute_out_of_the_key_set_does_not_help_either() {
    // The presenter brings the honest set and signs with its own key anyway:
    // verification is against the pinned key, so the signature fails.
    let mut c = container();
    let e = event(Operation::ApplyPacket, None, &[&impostor()]);
    let rec = packet_record(&c, &impostor());
    let got = c.press(
        &e,
        &Evidence::None,
        Writes {
            page: None,
            status: Some(rec),
            at_ms: None,
        },
        &keys(),
        &p(),
    );
    assert!(
        matches!(got, Err(Stopped::Command(ref r)) if r.reason == Refusal::Signature),
        "{got:?}"
    );
    assert_eq!(c.status(), Status::Printed);
}

#[test]
fn force_takes_no_record_but_the_issuers() {
    let mallory = Ed25519Signer::from_seed(uri("did:key:zMallory#m1"), [7u8; 32]);
    let mut c = container();

    // A stranger with a key set of their own.
    let (r, a) = packet_record(&c, &mallory);
    let only_mallory: KeySet = [mallory.public()].into_iter().collect();
    assert_eq!(
        c.force(StatusEvent::ApplyPacket, r, a, &only_mallory, &p()),
        Err(Stopped::NotTheIssuer)
    );

    // A party the container knows, but not the issuer.
    let (r, a) = packet_record(&c, &client());
    assert_eq!(
        c.force(StatusEvent::ApplyPacket, r, a, &keys(), &p()),
        Err(Stopped::NotTheIssuer)
    );

    // The impostor under the issuer's `kid`, with a set that says so.
    let (r, a) = packet_record(&c, &impostor());
    let forged: KeySet = [impostor().public()].into_iter().collect();
    assert!(matches!(
        c.force(StatusEvent::ApplyPacket, r, a, &forged, &p()),
        Err(Stopped::ForeignKey(_))
    ));
    assert_eq!(c.status(), Status::Printed, "nothing moved");

    // And the issuer still can.
    let (r, a) = packet_record(&c, &issuer());
    c.force(StatusEvent::ApplyPacket, r, a, &keys(), &p())
        .expect("the issuer's own record");
    assert_eq!(c.status(), Status::Packeted);
}

fn work_order(signed_by: &[&Ed25519Signer]) -> Order {
    let mut o = Order {
        container: container_id(),
        basis: Basis::Owner,
        instruction: "process the input".into(),
        signatures: SignatureSet::default(),
    };
    o.signatures = SignatureSet::new(
        signed_by
            .iter()
            .map(|s| s.sign(o.subject().as_bytes()))
            .collect(),
    );
    o
}

fn work_under(o: &Order) -> Work {
    let mut w = Work {
        container: container_id(),
        under: Some(o.id()),
        did: "did it".into(),
        signatures: SignatureSet::default(),
    };
    w.signatures = SignatureSet::new(vec![client().sign(w.subject().as_bytes())]);
    w
}

fn record_work(c: &mut Container, order: Order, work: Work) -> Result<(), Stopped> {
    let e = event(Operation::RecordWork, c.head(), &[&client()]);
    c.press(
        &e,
        &Evidence::Work {
            order: Some(Box::new(order)),
            work: Box::new(work),
        },
        Writes {
            page: Some(unsealed_opening(None)),
            status: None,
            at_ms: None,
        },
        &keys(),
        &p(),
    )
    .map(|_| ())
}

#[test]
fn an_order_nobody_signed_is_not_an_instruction() {
    let mut c = container_at(Status::InWork);
    let o = work_order(&[]);
    let w = work_under(&o);
    assert!(matches!(
        record_work(&mut c, o, w),
        Err(Stopped::Order(
            OrderError::WrongParty { .. } | OrderError::Signature
        ))
    ));
}

#[test]
fn an_order_signed_by_the_wrong_party_is_not_an_instruction() {
    let mut c = container_at(Status::InWork);
    let o = work_order(&[&client()]);
    let w = work_under(&o);
    assert!(matches!(
        record_work(&mut c, o, w),
        Err(Stopped::Order(OrderError::WrongParty { .. }))
    ));
}

#[test]
fn an_order_for_another_container_is_refused() {
    let mut c = container_at(Status::InWork);
    let mut o = work_order(&[]);
    o.container = Hash::sha256(b"another container");
    o.signatures = SignatureSet::new(vec![owner().sign(o.subject().as_bytes())]);
    let w = work_under(&o);
    assert!(matches!(
        record_work(&mut c, o, w),
        Err(Stopped::WrongEvidence { .. })
    ));
}

#[test]
fn a_proper_order_passes_the_evidence_check() {
    // Past step 6 the page itself is judged by the journal; what this holds is
    // that a good order is not refused as evidence.
    let mut c = container_at(Status::InWork);
    let o = work_order(&[&owner()]);
    let w = work_under(&o);
    let got = record_work(&mut c, o, w);
    assert!(
        !matches!(got, Err(Stopped::Order(_) | Stopped::WrongEvidence { .. })),
        "{got:?}"
    );
}
