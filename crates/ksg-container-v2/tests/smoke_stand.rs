//! Smoke on the stand: the container assembles, each of the three buttons
//! answers, and each refuses what is not its own. Seconds, not minutes — run
//! before anything else.
mod stand;

use ksg_container_v2::container::{Evidence, Stopped};
use ksg_container_v2::{Operation as Op, Status};
use ksg_core_v2::doc::Class;
use stand::{Page, Stand, Who};

#[test]
fn smoke_the_stand_assembles_with_the_clients_key_in_two_halves() {
    let mut s = Stand::new(Class::Heavy, 100);
    assert_eq!(s.c.status(), Status::Printed);
    let sigs = s.client_signs(b"smoke");
    assert_eq!(
        sigs.len(),
        1,
        "Ed25519 of both halves; the ML-DSA key signs the file outside (CH-5a)"
    );
}

#[test]
fn smoke_button_d1_issuer_answers() {
    let mut s = Stand::new(Class::Heavy, 101);
    s.press(Op::ApplyPacket, &[Who::Issuer], Evidence::None, Page::None)
        .expect("D-1");
    assert_eq!(s.c.status(), Status::Packeted);
}

#[test]
fn smoke_button_d2_signatures_answers_and_refuses_a_stranger() {
    let mut s = Stand::new(Class::Heavy, 102);
    s.press(Op::ApplyPacket, &[Who::Issuer], Evidence::None, Page::None)
        .expect("D-1");
    // The owner alone is not the buyer and the owner.
    assert!(matches!(
        s.press(Op::ApplyBuyerKey, &[Who::Owner], Evidence::None, Page::None),
        Err(Stopped::Command(_))
    ));
    assert_eq!(s.c.status(), Status::Packeted, "a refusal changes nothing");
}

#[test]
fn smoke_button_d3_export_refuses_without_a_road() {
    let mut s = Stand::new(Class::Heavy, 103);
    assert!(s
        .press(
            Op::FullExport,
            &[Who::Owner, Who::Client],
            Evidence::None,
            Page::None
        )
        .is_err());
    assert!(s.c.take_export().is_none());
}

/// The status section leaves the container for a third party and replays
/// there to the same status (spec v2 §11, §12) — without opening anything.
#[test]
fn smoke_the_status_section_leaves_and_replays() {
    let mut s = Stand::new(Class::Heavy, 104);
    s.press(Op::ApplyPacket, &[Who::Issuer], Evidence::None, Page::None)
        .expect("D-1");
    let x = s.c.status_export();
    let bytes = serde_json::to_vec(&x).expect("json");
    let x: ksg_core_v2::section::StatusExport = serde_json::from_slice(&bytes).expect("parses");
    let keys: ksg_core_v2::crypto::sign::KeySet = [s.parties.issuer.public()].into_iter().collect();
    let r = ksg_core_v2::section::verify_status_export(
        &x,
        &keys,
        &ksg_core_v2::crypto::sign::Profile::default(),
        None,
    )
    .expect("the section replays");
    assert_eq!(r.current, Status::Packeted);
    assert_eq!(r.current, s.c.status());
    assert_eq!(x.records.len(), s.c.status_records());
}

#[test]
fn smoke_the_distributor_takes_its_seat_before_initiation_only() {
    // C-12, owner's decisions 17.10: the seat is the distributor's own act,
    // once, before the client's key is born, and never the issuer's.
    let mut s = Stand::printed(Class::Heavy, 102);
    let issuer = s.parties.issuer.public();
    assert!(matches!(
        s.c.seat_distributor(issuer),
        Err(Stopped::Birth(_))
    ));
    let d = s.parties.distributor.public();
    s.c.seat_distributor(d.clone()).expect("the seller's seat");
    assert!(s.c.seat_distributor(d.clone()).is_err(), "once");
    let born = Stand::new(Class::Heavy, 103);
    let mut born = born;
    assert!(born.c.seat_distributor(d).is_err(), "after the birth: no");
}
