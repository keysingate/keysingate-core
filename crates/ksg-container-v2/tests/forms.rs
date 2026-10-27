//! The forms of the journal inside the container: light and Pro (CH-21…CH-30).
//!
//! | Decision | What is checked |
//! |---|---|
//! | CH-21, CH-22 | a light container opens its journal in the light form, unanchored |
//! | CH-26, CH-30 | to Pro by E-10: owner **and** issuer; without the issuer — refused |
//! | CH-23, CH-27, CH-30 | back to light by E-10: the owner alone |
//! | CH-29 | an artefact: in light, the agent alone; in Pro, the owner too — the record waits |
//! | CH-25 | only what is anchored has force; runs without a gap |

mod stand;

use ksg_container_v2::container::{Evidence, JournalWrite, Stopped, UnloadRoute};
use ksg_container_v2::layers::Level;
use ksg_container_v2::{Attachment, Kind, Operation as Op, Status, Where};
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::SignatureSet;
use ksg_core_v2::doc::Class;
use ksg_core_v2::journal::{
    verify_bound, BinderError, Mode, Piece, RecordKind, RecordMeta, Sealing,
};
use stand::EventKind;
use stand::{uri, Page, Stand, Who};

/// Print → packet → buyer's key → initiation → page 0.
/// Goal 1, `bare` v2: `bare` has no packet, so the packet step is skipped and
/// the buyer's key goes straight onto the printed release.
fn opened(class: Class, seed: u64) -> Stand {
    opened_from(Stand::new(class, seed))
}

fn opened_from(mut s: Stand) -> Stand {
    if s.c.class() != Class::Bare {
        s.press(Op::ApplyPacket, &[Who::Issuer], Evidence::None, Page::None)
            .expect("packet");
    }
    let buyer = s.parties.buyer.public();
    s.press(
        Op::ApplyBuyerKey,
        &[Who::Buyer, Who::Owner],
        Evidence::KeyLaid {
            to: buyer,
            up_to: Level(2),
        },
        Page::None,
    )
    .expect("buyer's key");
    s.press(
        Op::Initiate,
        &[Who::Client, Who::Owner],
        Evidence::Initiation { at: Where::Inside },
        Page::None,
    )
    .expect("initiation");
    s.press(
        Op::OpenJournal,
        &[Who::Client],
        Evidence::None,
        Page::Opening,
    )
    .expect("journal opened");
    assert_eq!(s.c.status(), Status::InWork);
    s
}

fn attachment() -> Attachment {
    Attachment {
        artifact: uri(stand::ARTIFACT),
        kind: Kind::Media {
            mime: "image/png".into(),
        },
        content_hash: Hash::sha256(b"the artefact"),
        size: 12,
        name: "artefact.png".into(),
        derived_from: vec![],
        offset_ms: stand::OFFSET,
    }
}

fn work(s: &mut Stand) {
    let w = signed_work(s);
    s.press(
        Op::RecordWork,
        &[Who::Client],
        Evidence::Work {
            order: None,
            work: Box::new(w),
        },
        Page::Of(EventKind::Work),
    )
    .expect("record of work");
}

fn signed_work(s: &mut Stand) -> ksg_container_v2::Work {
    let mut w = ksg_container_v2::Work {
        container: *s.c.id(),
        under: None,
        did: "a step".into(),
        signatures: SignatureSet::default(),
    };
    let subject = w.subject();
    w.signatures = SignatureSet::new(s.client_signs(subject.as_bytes()));
    w
}

fn to_form(s: &mut Stand, to: Mode, who: &[Who]) -> Result<(), Stopped> {
    s.press(Op::RaiseClass, who, Evidence::Form { to }, Page::Form(to))
}

#[test]
fn a_light_container_opens_light() {
    let s = opened(Class::Light, 21);
    assert_eq!(s.c.form(), Some(Mode::Local));
    assert!(!s.c.waiting());
}

#[test]
fn the_full_class_opens_pro() {
    let s = opened(Class::Heavy, 22);
    assert_eq!(s.c.form(), Some(Mode::Pro));
}

#[test]
fn to_pro_takes_the_issuer_too() {
    let mut s = opened(Class::Light, 23);
    let e = to_form(&mut s, Mode::Pro, &[Who::Owner]).expect_err("the owner alone");
    assert!(matches!(e, Stopped::IssuerMissing(Op::RaiseClass)), "{e:?}");
    assert_eq!(
        s.c.form(),
        Some(Mode::Local),
        "stays light, nothing anchored"
    );

    to_form(&mut s, Mode::Pro, &[Who::Owner, Who::Issuer]).expect("owner and issuer");
    assert_eq!(s.c.form(), Some(Mode::Pro));
}

#[test]
fn back_to_light_takes_the_owner_alone() {
    let mut s = opened(Class::Heavy, 24);
    assert!(
        to_form(&mut s, Mode::Local, &[Who::Client]).is_err(),
        "the agent cannot take the container back to light"
    );
    to_form(&mut s, Mode::Local, &[Who::Owner]).expect("the owner alone");
    assert_eq!(s.c.form(), Some(Mode::Local));
    // And up again, as long as pages last (CH-23).
    to_form(&mut s, Mode::Pro, &[Who::Owner, Who::Issuer]).expect("up again");
    assert_eq!(s.c.form(), Some(Mode::Pro));
}

#[test]
fn the_base_class_never_goes_pro() {
    let mut s = opened(Class::Bare, 25);
    assert_eq!(s.c.form(), Some(Mode::Local));
    // Goal 1, `bare` v2: `RaiseClass` does not exist in `bare`, so the
    // refusal comes from the class guard before any form check — bare still
    // never goes Pro.
    let e = to_form(&mut s, Mode::Pro, &[Who::Owner, Who::Issuer]).expect_err("bare");
    assert!(matches!(e, Stopped::NotInClass { .. }), "{e:?}");
}

#[test]
fn a_form_page_to_the_form_in_place_is_refused() {
    let s = opened(Class::Light, 26);
    let e =
        s.c.draft_form(Mode::Local, s.clock_ms + 1_000)
            .expect_err("no change");
    assert!(
        matches!(e, Stopped::Journal(BinderError::FormUnchanged(_))),
        "{e:?}"
    );
}

#[test]
fn in_light_the_agent_attaches_alone() {
    let mut s = opened(Class::Light, 27);
    s.press(
        Op::AttachArtifactOrRights,
        &[Who::Client],
        Evidence::Artifact(Box::new(attachment())),
        Page::Of(EventKind::ArtifactOrRights),
    )
    .expect("light: the owner is not asked (CH-29)");
    assert_eq!(s.c.artifact_seals().len(), 1);
}

#[test]
fn in_pro_an_artefact_waits_for_the_owner() {
    let mut s = opened(Class::Heavy, 28);
    let offset = s.clock_ms + 1_000;
    s.clock_ms = offset;
    let draft =
        s.c.draft_record(
            vec![Piece::Digest(Hash::sha256(b"the artefact"))],
            RecordMeta {
                kind: RecordKind::ArtifactOrRights,
                ..RecordMeta::default()
            },
            offset,
        )
        .expect("draft");
    assert!(draft.needs_owner());
    let bytes = draft.seal_bytes().expect("bytes");

    // The agent seals; the owner has not yet: the record waits (CH-20).
    let agent_only = JournalWrite::Record {
        draft: Box::new(draft.clone()),
        sealing: Box::new(Sealing {
            seal: SignatureSet::new(s.client_signs(&bytes)),
            ..Sealing::default()
        }),
    };
    let e = s
        .press_write(
            Op::AttachArtifactOrRights,
            &[Who::Client],
            Evidence::Artifact(Box::new(attachment())),
            Some(agent_only),
        )
        .expect_err("waits");
    assert!(matches!(e, Stopped::WaitsForOwner), "{e:?}");
    assert!(s.c.waiting());
    assert!(s.c.artifact_seals().is_empty(), "nothing after the page");

    // The same record, now with the owner's seal and the anchor.
    let full = s.seal_draft(draft);
    s.press_write(
        Op::AttachArtifactOrRights,
        &[Who::Client],
        Evidence::Artifact(Box::new(attachment())),
        Some(full),
    )
    .expect("completed by the owner");
    assert!(!s.c.waiting());
    assert_eq!(s.c.artifact_seals().len(), 1);
}

#[test]
fn only_what_is_anchored_has_force() {
    let mut s = opened(Class::Light, 29); // page 0, light
    work(&mut s); // page 1, light
    to_form(&mut s, Mode::Pro, &[Who::Owner, Who::Issuer]).expect("to Pro"); // page 2
    work(&mut s); // page 3, anchored
    s.press(
        Op::AttachArtifactOrRights,
        &[Who::Client],
        Evidence::Artifact(Box::new(attachment())),
        Page::Of(EventKind::ArtifactOrRights),
    )
    .expect("the stand's owner seals it"); // page 4

    s.press(Op::Finalize, &[Who::Issuer], Evidence::None, Page::None)
        .expect("finalized");
    s.press(
        Op::FullExport,
        &[Who::Owner, Who::Client],
        Evidence::Unload(Box::new(UnloadRoute::Principals)),
        Page::None,
    )
    .expect("full export");
    let x = s.c.take_export().expect("the export");
    let r = verify_bound(&x, &stand::p()).expect("the export checks");
    assert_eq!(r.mode, Mode::Pro);
    assert_eq!(r.runs, vec![(2, 4)], "one run from the form page on");
    assert!(
        !r.has_force(0) && !r.has_force(1),
        "light pages have no force"
    );
    assert!(r.has_force(2) && r.has_force(4));
    assert_eq!(r.cosealed.len(), 2, "the form page and the artefact");
}

/// Audit of 30.09, O-1: the anchors of the record just written can be
/// swapped for the network's — and nothing else can: another subject is
/// refused, and the history's anchors are out of reach.
#[test]
fn only_the_last_records_anchors_are_swapped_and_only_for_their_own() {
    use ksg_core_v2::anchor::Attestation;
    let mut s = opened(Class::Heavy, 330);
    let att = |subject| Attestation {
        kind: uri("urn:ksg:anchor:solana:seal:v1"),
        subject,
        proof: b"from the network".to_vec(),
        anchored_at: stand::ts("2026-09-30T12:00:00.000Z"),
    };
    let top = s.c.top_seal_hash().expect("a seal on page 0");
    let other = ksg_core_v2::crypto::hash::Hash::sha256(b"another");
    assert!(s.c.reanchor_last(Some(att(other)), None).is_err());
    let last =
        s.c.status_export()
            .records
            .last()
            .unwrap()
            .0
            .hash()
            .unwrap();
    assert!(s.c.reanchor_last(None, Some(att(other))).is_err());
    s.c.reanchor_last(Some(att(top)), Some(att(last)))
        .expect("the record's own anchors");
    let x = s.c.status_export();
    assert_eq!(x.records.last().unwrap().1.proof, b"from the network");
    // The history below the last record keeps its anchors.
    assert_ne!(x.records[0].1.proof, b"from the network".to_vec());
}

/// CH-22: a light container that went Pro takes on Pro's requirements — the
/// issuer's seal on every artefact (CT-48) among them. Pro is the journal's
/// form, not only the class it opened in.
#[test]
fn a_light_container_gone_pro_seals_its_artefacts_like_pro() {
    let mut s = opened(Class::Light, 31);
    assert!(!s.c.is_pro());
    to_form(&mut s, Mode::Pro, &[Who::Owner, Who::Issuer]).expect("to Pro");
    assert!(s.c.is_pro());
    let draft = {
        let offset = s.clock_ms + 1_000;
        s.clock_ms = offset;
        s.c.draft_record(
            vec![Piece::Digest(Hash::sha256(b"the artefact"))],
            RecordMeta {
                kind: RecordKind::ArtifactOrRights,
                ..RecordMeta::default()
            },
            offset,
        )
        .expect("draft")
    };
    let full = s.seal_draft(draft);
    s.press_write(
        Op::AttachArtifactOrRights,
        &[Who::Client],
        Evidence::Artifact(Box::new(attachment())),
        Some(full),
    )
    .expect("attached in Pro");
    assert_eq!(s.c.artifact_seals().len(), 1, "sealed by the issuer's seal");
}

/// Without the issuer's seal a container does not go Pro: refused at the
/// change of form, not at its first artefact.
#[test]
fn a_container_without_the_issuers_seal_does_not_go_pro() {
    let mut s = opened_from(Stand::unsealed(Class::Light, 32));
    let e = to_form(&mut s, Mode::Pro, &[Who::Owner, Who::Issuer]).expect_err("no seal");
    assert!(matches!(e, Stopped::NoIssuerSeal), "{e:?}");
    assert_eq!(s.c.form(), Some(Mode::Local));
    // In light it attaches as before, unsealed.
    s.press(
        Op::AttachArtifactOrRights,
        &[Who::Client],
        Evidence::Artifact(Box::new(attachment())),
        Page::Of(EventKind::ArtifactOrRights),
    )
    .expect("light, no seal needed");
    assert!(s.c.artifact_seals().is_empty());
}

/// A full-class container returned to light sheds Pro's requirements
/// (CH-23): without a seal it attaches; with one it still seals.
#[test]
fn a_full_container_back_in_light_is_held_to_light() {
    let mut s = opened_from(Stand::unsealed(Class::Heavy, 33));
    assert!(s.c.is_pro());
    let e = s
        .press(
            Op::AttachArtifactOrRights,
            &[Who::Client],
            Evidence::Artifact(Box::new(attachment())),
            Page::Of(EventKind::ArtifactOrRights),
        )
        .expect_err("Pro without the seal");
    assert!(matches!(e, Stopped::NoIssuerSeal), "{e:?}");
    to_form(&mut s, Mode::Local, &[Who::Owner]).expect("back to light");
    assert!(!s.c.is_pro());
    s.press(
        Op::AttachArtifactOrRights,
        &[Who::Client],
        Evidence::Artifact(Box::new(attachment())),
        Page::Of(EventKind::ArtifactOrRights),
    )
    .expect("light: attached");
}
