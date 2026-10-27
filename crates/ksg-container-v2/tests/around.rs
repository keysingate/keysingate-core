//! The layer around the container: stages, orders, the artefact, the time guard.
//!
//! Four small modules with one thing in common — each makes a sentence from the
//! specification into something a machine refuses, and each stops exactly where
//! the container stops being able to know.

use ksg_container_v2::order::{Basis, BasisKind, Order, OrderError, Work};
use ksg_container_v2::timecheck::{
    event_for, expired_unused, may_follow, may_initiate, window_sane,
};
use ksg_container_v2::{ArtifactError, Attachment, Kind, Role, Roster, Stage, TimeRefusal, Where};
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{Ed25519Signer, KeySet, Profile, SignatureSet};
use ksg_core_v2::doc::{derive_container_id, Serial, Timestamp, Uri};
use ksg_core_v2::status::{Event, Status};

fn uri(s: &str) -> Uri {
    Uri::parse(s).expect("uri")
}
fn client() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:key:zAgent#a1"), [42u8; 32])
}
fn owner() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:key:zOwner#o1"), [44u8; 32])
}
fn orch() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:key:zOrch#r1"), [14u8; 32])
}
fn stranger() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:key:zNobody#x"), [99u8; 32])
}
fn p() -> Profile {
    Profile::default()
}
fn keys() -> KeySet {
    [
        client().public(),
        owner().public(),
        orch().public(),
        stranger().public(),
    ]
    .into_iter()
    .collect()
}
fn roster() -> Roster {
    Roster::of([
        (client().public(), Role::Client),
        (owner().public(), Role::Owner),
        (orch().public(), Role::Orchestrator),
    ])
}

// --- stages ------------------------------------------------------------------

#[test]
fn every_status_reads_as_a_stage_except_the_reserved_blanks() {
    // A status with no stage would be a container in no part of its life. The two
    // reserved places (8 and 33) are the exception, and they are `None` rather
    // than a guess: calling them closed would say something ended there.
    for &s in Status::all() {
        let stage = Stage::of(s);
        assert_eq!(
            stage.is_none(),
            s.is_reserved(),
            "status {} disagrees about being a blank",
            s.number()
        );
    }
}

#[test]
fn the_stages_agree_with_the_status_machine_about_what_working_means() {
    // The whole reason stages are a reading of statuses rather than a second
    // machine: two machines that must agree eventually do not. This is the test
    // that would catch them drifting.
    for &s in Status::all() {
        assert_eq!(
            Stage::of(s) == Some(Stage::Working),
            s.is_working(),
            "status {} disagrees about working",
            s.number()
        );
    }
}

#[test]
fn a_template_is_not_a_container() {
    // `[decision]` 11.09, and the reason this module was planned: status 4 is ready for
    // registration and for resale, NOT for work. A working container must already
    // hold record 0 of the client key and page 0 of the journal.
    assert!(!Stage::of(Status::Initiated).expect("a stage").can_work());
    assert!(!Stage::of(Status::BuyerKeyed).expect("a stage").can_work());
    assert!(Stage::of(Status::InWork).expect("a stage").can_work());
    // And the converse: what can be sold as a template is what has no work in it.
    for &s in Status::all() {
        if let Some(stage) = Stage::of(s) {
            assert!(
                !(stage.can_work() && stage.tradable_as_template()),
                "status {} would be both workable and sellable as a blank",
                s.number()
            );
        }
    }
}

#[test]
fn a_frozen_container_can_still_be_exported_from() {
    // Closed is not empty. Status 6 is a valid archive, and that is what makes
    // succession work at all: the client key is current, so an export out of the
    // old container is possible. A template has nothing to export.
    assert!(Stage::of(Status::Finalized).expect("a stage").exportable());
    assert!(!Stage::of(Status::BuyerKeyed).expect("a stage").exportable());
}

// --- orders ------------------------------------------------------------------

fn order(basis: Basis, who: &Ed25519Signer) -> Order {
    let mut o = Order {
        container: Hash::sha256(b"container"),
        basis,
        instruction: "process the input and attach the result".into(),
        signatures: SignatureSet::default(),
    };
    o.signatures = SignatureSet::new(vec![who.sign(o.subject().as_bytes())]);
    o
}

#[test]
fn each_basis_is_confirmed_by_the_party_it_names() {
    // `[decision]` C-7: every order is somebody's and is confirmed by keys. So the basis
    // and the signature have to be the same party — otherwise "the owner ordered
    // it" is a sentence the orchestrator can write.
    order(Basis::Owner, &owner())
        .validate(&roster(), &keys(), &p())
        .expect("the owner's order, signed by the owner");
    order(Basis::Orchestrator, &orch())
        .validate(&roster(), &keys(), &p())
        .expect("the orchestrator's order, signed by the orchestrator");

    assert_eq!(
        order(Basis::Owner, &orch())
            .validate(&roster(), &keys(), &p())
            .unwrap_err(),
        OrderError::WrongParty {
            basis: BasisKind::Owner
        }
    );
}

#[test]
fn a_protocol_does_not_sign_and_the_client_signs_for_it() {
    // A protocol is not a party. Pretending it signs would invent a signatory,
    // and inventing one is how "confirmed by keys" becomes a phrase. What is
    // recorded is the client saying which protocol it acted under.
    order(
        Basis::Protocol {
            substance: "on act of an order, verify the checksum first".into(),
        },
        &client(),
    )
    .validate(&roster(), &keys(), &p())
    .expect("the client cites the protocol");
    assert_eq!(BasisKind::Protocol.signer(), Role::Client);
}

#[test]
fn a_protocol_cited_by_name_only_is_refused() {
    // C-7 asks for "the substance of the protocol". A bare name points at a document the
    // container cannot read, which is the same as pointing at nothing.
    assert_eq!(
        order(
            Basis::Protocol {
                substance: "   ".into()
            },
            &client()
        )
        .validate(&roster(), &keys(), &p())
        .unwrap_err(),
        OrderError::NoSubstance
    );
}

#[test]
fn own_initiative_without_a_reason_is_refused() {
    // The one basis that has no other party behind it is the one that must say
    // why. Otherwise it becomes the basis everything is filed under.
    assert_eq!(
        order(
            Basis::OwnInitiative {
                reason: String::new()
            },
            &client()
        )
        .validate(&roster(), &keys(), &p())
        .unwrap_err(),
        OrderError::NoReason
    );
    order(
        Basis::OwnInitiative {
            reason: "the input was malformed and the owner was unreachable".into(),
        },
        &client(),
    )
    .validate(&roster(), &keys(), &p())
    .expect("own initiative, with grounds");
}

#[test]
fn an_order_signed_by_a_key_with_no_role_is_named_as_such() {
    // Two different mistakes: a key the container cannot place at all, and the
    // wrong one of ours. A presenter fixes them differently, so they are told
    // apart.
    assert_eq!(
        order(Basis::Owner, &stranger())
            .validate(&roster(), &keys(), &p())
            .unwrap_err(),
        OrderError::NoRole(stranger().public().kid)
    );
}

#[test]
fn work_cites_the_order_it_was_done_under() {
    let o = order(Basis::Owner, &owner());
    let mut w = Work {
        container: o.container,
        under: Some(o.id()),
        did: "processed and attached".into(),
        signatures: SignatureSet::default(),
    };
    w.signatures = SignatureSet::new(vec![client().sign(w.subject().as_bytes())]);
    w.under_order(&o).expect("the pair is the pair claimed");
    w.validate(&roster(), &keys(), &p(), &client().public())
        .expect("signed by the client");

    // Another order's work does not pass for this one's.
    let other = order(Basis::Orchestrator, &orch());
    assert_eq!(w.under_order(&other).unwrap_err(), OrderError::OtherOrder);
}

#[test]
fn work_with_no_order_is_visible_as_such_rather_than_refused() {
    // The honest half of C-7. Work on the agent's own account happens — it is one
    // of the four bases — and what the mechanism does is make it *say so*. What
    // must never be possible is work that quietly implies an order it has not got.
    let w = Work {
        container: Hash::sha256(b"container"),
        under: None,
        did: "acted alone".into(),
        signatures: SignatureSet::default(),
    };
    assert!(w.on_own_account());
    // And it cannot borrow somebody else's order after the fact.
    assert_eq!(
        w.under_order(&order(Basis::Owner, &owner())).unwrap_err(),
        OrderError::OtherOrder
    );
}

#[test]
fn nothing_here_claims_to_judge_whether_the_work_served_the_order() {
    // The container reads neither the instruction nor the result, so a rule about
    // whether they match would be a rule nobody can apply. C-7 says the
    // divergence becomes *visible*, and that is what is implemented: the pair is
    // inspectable, and a human reads it.
    let o = order(Basis::Owner, &owner());
    let mut w = Work {
        container: o.container,
        under: Some(o.id()),
        did: "did something else entirely".into(),
        signatures: SignatureSet::default(),
    };
    w.signatures = SignatureSet::new(vec![client().sign(w.subject().as_bytes())]);
    w.under_order(&o)
        .expect("the pair is recorded; judging it is not this layer's job");
}

// --- the artefact ------------------------------------------------------------

const EMISSION: &str = "ksg:emission:1";

fn attachment(art: &str, offset: u64) -> Attachment {
    Attachment {
        artifact: uri(art),
        kind: Kind::Media {
            mime: "image/png".into(),
        },
        content_hash: Hash::sha256(b"the bytes of the artefact"),
        size: 4_096,
        name: "cover.png".into(),
        derived_from: vec![uri("ksg:artifact:source-1")],
        offset_ms: offset,
    }
}

/// The release's moment. Part of the identifier since CT-28 (2026-09-19).
fn issued_at() -> Timestamp {
    Timestamp::parse("2026-01-01T00:00:00.000Z").expect("a well-formed moment")
}

fn container_for(art: &str, offset: u64) -> Hash {
    derive_container_id(
        EMISSION,
        &issued_at(),
        Serial(7),
        &client().public(),
        &uri(art),
        offset,
    )
}

#[test]
fn the_attached_artefact_is_checked_against_the_identifier_itself() {
    // The strongest check in this layer, and it costs one hash: the identifier is
    // derived from the artefact, so attaching a different one is arithmetic that
    // does not come out.
    let a = attachment("ksg:artifact:the-one", 1_000);
    a.check(
        &container_for("ksg:artifact:the-one", 1_000),
        EMISSION,
        &issued_at(),
        Serial(7),
        &client().public(),
    )
    .expect("this artefact is this container");
}

#[test]
fn a_substituted_artefact_does_not_pass() {
    // Without this, "one container, one artefact" would be a sentence in a
    // specification and a substitution after the fact would be invisible.
    let swapped = attachment("ksg:artifact:another", 1_000);
    assert_eq!(
        swapped
            .check(
                &container_for("ksg:artifact:the-one", 1_000),
                EMISSION,
                &issued_at(),
                Serial(7),
                &client().public()
            )
            .unwrap_err(),
        ArtifactError::NotThisContainer
    );
}

#[test]
fn one_comparison_covers_the_serial_the_agent_and_the_offset_too() {
    // All four are inputs to the derivation, so the single check catches a wrong
    // serial, a wrong agent and a wrong offset without a rule for each.
    let a = attachment("ksg:artifact:the-one", 1_000);
    let right = container_for("ksg:artifact:the-one", 1_000);
    assert!(a
        .check(
            &right,
            EMISSION,
            &issued_at(),
            Serial(8),
            &client().public()
        )
        .is_err());
    assert!(a
        .check(&right, EMISSION, &issued_at(), Serial(7), &owner().public())
        .is_err());
    assert!(attachment("ksg:artifact:the-one", 2_000)
        .check(
            &right,
            EMISSION,
            &issued_at(),
            Serial(7),
            &client().public()
        )
        .is_err());
}

#[test]
fn an_attachment_that_says_nothing_about_what_it_is_is_refused() {
    let mut a = attachment("ksg:artifact:the-one", 1_000);
    a.kind = Kind::Media {
        mime: String::new(),
    };
    assert_eq!(
        a.check(
            &container_for("ksg:artifact:the-one", 1_000),
            EMISSION,
            &issued_at(),
            Serial(7),
            &client().public()
        )
        .unwrap_err(),
        ArtifactError::NoMedia
    );
}

#[test]
fn provenance_is_inside_what_the_parties_sign() {
    // Provenance that is signed cannot be edited afterwards; provenance that is
    // not signed is a note rather than a record.
    let c = container_for("ksg:artifact:the-one", 1_000);
    let a = attachment("ksg:artifact:the-one", 1_000);
    let mut b = a.clone();
    b.derived_from = vec![uri("ksg:artifact:source-2")];
    assert_ne!(a.subject(&c), b.subject(&c));
}

// --- the time guard ----------------------------------------------------------

#[test]
fn initiation_is_allowed_only_inside_the_packets_window() {
    may_initiate(Where::Inside).expect("inside");
    assert_eq!(may_initiate(Where::Before), Err(TimeRefusal::TooEarly));
    assert_eq!(may_initiate(Where::After), Err(TimeRefusal::TooLate));
}

#[test]
fn too_late_is_a_terminal_status_and_too_early_is_nothing_at_all() {
    // The distinction the statuses make: 20 is somebody using a packet after it
    // died, and it does not come back. Too early means nothing happened, so
    // nothing is recorded.
    assert_eq!(
        event_for(TimeRefusal::TooLate),
        Some(Event::InitiateTooLate)
    );
    assert_eq!(event_for(TimeRefusal::TooEarly), None);
}

#[test]
fn a_packet_dying_unused_is_a_different_event_from_one_used_too_late() {
    // 10 and 20 were kept distinct on purpose, and the two guards keep them so.
    assert_eq!(
        expired_unused(Where::After, Status::Packeted),
        Some(Event::PacketTermExpired)
    );
    // Already in work: the packet's term is spent, not violated.
    assert_eq!(expired_unused(Where::After, Status::InWork), None);
    assert_eq!(expired_unused(Where::Inside, Status::Packeted), None);
}

#[test]
fn an_initiated_container_is_its_owners_and_never_turns_into_a_brick() {
    // `[decision]` 23.09: at status 4 the container belongs to the end user, who
    // decides how long it lives — even on outdated software. The two-year
    // brick ceiling holds for statuses 1–3 only.
    for s in [Status::Packeted, Status::BuyerKeyed, Status::SubAgentKeyed] {
        assert_eq!(
            expired_unused(Where::After, s),
            Some(Event::PacketTermExpired),
            "{s:?} is still the channel's"
        );
    }
    assert_eq!(expired_unused(Where::After, Status::Initiated), None);
}

#[test]
fn the_offset_must_increase_and_equality_is_not_an_increase() {
    // F-3, `[decision]` 11.09: a refusal rather than a mark. Equality is exactly the
    // case a "not less than" rule would have let through, which is why it is the
    // case named here.
    may_follow(11, 10).expect("forward");
    assert_eq!(
        may_follow(10, 10),
        Err(TimeRefusal::OffsetWentBack {
            presented: 10,
            last: 10
        })
    );
    assert_eq!(
        may_follow(9, 10),
        Err(TimeRefusal::OffsetWentBack {
            presented: 9,
            last: 10
        })
    );
}

#[test]
fn an_inverted_window_is_named_instead_of_expiring_everything() {
    // A window that ends before it starts makes every moment `After`, which would
    // read as "every packet has expired" — a wrong answer delivered confidently.
    window_sane(true).expect("sane");
    assert_eq!(window_sane(false), Err(TimeRefusal::WindowInverted));
}

#[test]
fn the_guard_never_reads_a_date() {
    // The property that keeps two implementations in agreement: the comparisons
    // arrive already made. Nothing in this module takes a timestamp, and this
    // test exists to make that visible where somebody might otherwise add one.
    //
    // Expressed as it can be — the guard's whole input vocabulary is three
    // variants and two integers.
    for at in [Where::Before, Where::Inside, Where::After] {
        let _ = may_initiate(at);
    }
}

// --- CT-43, CT-46: kinds of artefact ------------------------------------------

fn process(end: ksg_container_v2::End) -> Attachment {
    let mut a = attachment("ksg:artifact:the-one", 1_000);
    a.kind = Kind::Process(ksg_container_v2::Process {
        start: Timestamp::parse("2026-10-01T08:00:00.000Z").expect("ts"),
        end,
        role: "monitoring".into(),
        sources: vec![],
        rules: vec![],
    });
    a
}

fn check(a: &Attachment) -> Result<(), ArtifactError> {
    a.check(
        &container_for("ksg:artifact:the-one", 1_000),
        EMISSION,
        &issued_at(),
        Serial(7),
        &client().public(),
    )
}

#[test]
fn a_watch_is_a_start_and_an_end_and_whether_it_repeats() {
    // [decision] 22.09, CT-46: the schedule and its deviations are not ours.
    let until = Timestamp::parse("2026-10-15T08:00:00.000Z").expect("ts");
    let once = process(ksg_container_v2::End::Watch {
        until: until.clone(),
        repeats: false,
    });
    let again = process(ksg_container_v2::End::Watch {
        until,
        repeats: true,
    });
    check(&once).expect("a one-off watch");
    check(&again).expect("a recurring watch");
    let c = container_for("ksg:artifact:the-one", 1_000);
    assert_ne!(
        once.subject(&c),
        again.subject(&c),
        "one-off and recurring are signed apart"
    );
}

#[test]
fn a_watch_cannot_end_before_it_starts() {
    let a = process(ksg_container_v2::End::Watch {
        until: Timestamp::parse("2026-09-01T08:00:00.000Z").expect("ts"),
        repeats: false,
    });
    assert_eq!(check(&a), Err(ArtifactError::EndsBeforeStart));
}

#[test]
fn the_name_is_required_and_an_empty_artefact_is_refused() {
    let mut a = attachment("ksg:artifact:the-one", 1_000);
    a.name = " ".into();
    assert_eq!(check(&a), Err(ArtifactError::NoName));
    let mut b = attachment("ksg:artifact:the-one", 1_000);
    b.size = 0;
    assert_eq!(check(&b), Err(ArtifactError::Empty));
}

#[test]
fn the_hash_size_and_name_are_under_the_signature() {
    let c = container_for("ksg:artifact:the-one", 1_000);
    let a = attachment("ksg:artifact:the-one", 1_000);
    let mut b = a.clone();
    b.content_hash = Hash::sha256(b"other bytes");
    assert_ne!(a.subject(&c), b.subject(&c));
    let mut d = a.clone();
    d.size += 1;
    assert_ne!(a.subject(&c), d.subject(&c));
}
