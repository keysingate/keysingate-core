//! The status section. KS-7 §7.3, §7.3-bis.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use ksg_core_v2::anchor::Attestation;
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{sign_doc, Ed25519Signer, KeySet, Profile, SignatureSet};
use ksg_core_v2::doc::{Serial, Timestamp, Uri};
use ksg_core_v2::error::Invalid;
use ksg_core_v2::section::{section_root, StatusRecord, StatusSection};
use ksg_core_v2::status::{Event, Outcome, Status};

const EMISSION: &str = "ksg:em:000001";
const SERIAL: Serial = Serial(4_700_007);

fn uri(s: &str) -> Uri {
    Uri::parse(s).expect("uri")
}
fn issuer() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:web:issuer.example#k1"), [7u8; 32])
}
fn keys() -> KeySet {
    [issuer().public()].into_iter().collect()
}
fn p() -> Profile {
    Profile::default()
}

fn record(number: u64, status: Status, event: Option<Event>, prev: Hash) -> StatusRecord {
    let doc = StatusRecord {
        context: ksg_core_v2::doc::Context,
        doc_type: "StatusRecord".into(),
        v: 3,
        number,
        status,
        event,
        offset_ms: number * 1000,
        prev,
        signatures: SignatureSet::default(),
    };
    let sig = sign_doc(&doc, &issuer()).expect("signature");
    StatusRecord {
        signatures: SignatureSet::new(vec![sig]),
        ..doc
    }
}

fn anchor_for(r: &StatusRecord) -> Attestation {
    Attestation {
        kind: uri("urn:ksg:anchor:test"),
        subject: r.hash().expect("hash"),
        proof: b"opaque".to_vec(),
        anchored_at: Timestamp::parse("2026-09-01T00:00:00.000Z").expect("ts"),
    }
}

fn started() -> StatusSection {
    let zero = record(0, Status::Printed, None, section_root(EMISSION, SERIAL));
    let a = anchor_for(&zero);
    StatusSection::start(EMISSION, SERIAL, zero, a, &keys(), &p()).expect("start")
}

/// Applies an event, writing the record the change needs.
fn step(s: &mut StatusSection, event: Event) -> Result<Outcome, Invalid> {
    let n = s.counter() + 1;
    let head = s.records().last().expect("head").0.hash().expect("hash");
    // What status this will land on is the machine's business, so ask it by
    // trying — but build the record for the status the machine reports.
    let mut probe = ksg_core_v2::status::StatusHistory::new();
    for (r, _) in s.records().iter().skip(1) {
        probe.apply(r.event.expect("an event")).expect("replay");
    }
    let outcome = ksg_core_v2::status::transition(probe.current(), probe.blocked(), event);
    match outcome {
        Outcome::Moves(next) => {
            let r = record(n, next, Some(event), head);
            let a = anchor_for(&r);
            s.apply(event, Some(r), Some(a), &keys(), &p())
        }
        _ => s.apply(event, None, None, &keys(), &p()),
    }
}

// --- the section starts at the address ---------------------------------------

#[test]
fn the_section_is_rooted_in_the_address_because_identity_comes_later() {
    // At status 0 there is no container and no personal identifier, only a
    // position: an emission and a serial.
    let s = started();
    assert_eq!(s.root(), &section_root(EMISSION, SERIAL));
    assert_eq!(s.current(), Status::Printed);
    assert_eq!(s.counter(), 0);

    // And the root is of THIS position: a neighbouring serial roots elsewhere.
    assert_ne!(
        section_root(EMISSION, SERIAL),
        section_root(EMISSION, Serial(SERIAL.0 + 1))
    );
    assert_ne!(
        section_root(EMISSION, SERIAL),
        section_root("ksg:em:000002", SERIAL)
    );
}

#[test]
fn a_record_zero_that_does_not_link_to_the_root_is_refused() {
    let zero = record(0, Status::Printed, None, Hash::sha256(b"somewhere else"));
    let a = anchor_for(&zero);
    assert_eq!(
        StatusSection::start(EMISSION, SERIAL, zero, a, &keys(), &p()).unwrap_err(),
        Invalid::Schema("record 0 does not link to the section root")
    );
}

#[test]
fn the_section_starts_at_status_zero_and_nowhere_else() {
    let wrong = record(0, Status::InWork, None, section_root(EMISSION, SERIAL));
    let a = anchor_for(&wrong);
    assert_eq!(
        StatusSection::start(EMISSION, SERIAL, wrong, a, &keys(), &p()).unwrap_err(),
        Invalid::Schema("the status section starts at record 0 with status 0")
    );
}

// --- every change is recorded, with an anchor --------------------------------

#[test]
fn a_change_without_a_record_is_refused() {
    // §7.3: every change MUST be written to the section with an anchor. Trying
    // to move without writing it down is not a move.
    let mut s = started();
    assert_eq!(
        s.apply(Event::ApplyPacket, None, None, &keys(), &p())
            .unwrap_err(),
        Invalid::Schema("a status change MUST be recorded with an anchor")
    );
}

#[test]
fn a_change_recorded_without_an_anchor_is_refused() {
    let mut s = started();
    let r = record(1, Status::Packeted, Some(Event::ApplyPacket), *s.root());
    assert!(s
        .apply(Event::ApplyPacket, Some(r), None, &keys(), &p())
        .is_err());
}

#[test]
fn the_ordinary_path_is_written_down_step_by_step() {
    let mut s = started();
    for (event, expected) in [
        (Event::ApplyPacket, Status::Packeted),
        (Event::ApplyBuyerKey, Status::BuyerKeyed),
        (Event::Initiate, Status::Initiated),
        (Event::OpenJournal, Status::InWork),
    ] {
        step(&mut s, event).expect("the step is in the table");
        assert_eq!(s.current(), expected);
    }
    assert_eq!(s.counter(), 4, "four changes, four records");
    assert_eq!(s.records().len(), 5, "plus record 0");
    assert!(
        s.records()
            .iter()
            .all(|(r, a)| a.covers(&r.hash().unwrap()).is_ok()),
        "every record is anchored, and to itself"
    );
}

#[test]
fn a_move_the_machine_refuses_writes_nothing() {
    // Both checks must pass, and in that order: a record of a move that may not
    // happen should not exist even as a rejected one.
    let mut s = started();
    assert!(matches!(
        step(&mut s, Event::RecordWork),
        Err(Invalid::StatusRefused(_))
    ));
    assert_eq!(s.counter(), 0, "and the section did not grow");
}

#[test]
fn a_status_that_stays_writes_nothing() {
    // A status that does not change is not a change. Recording it would inflate
    // the section with pages saying "still 5" — and let a count of status
    // records stand in for a count of the work, which KS-8 I-5 keeps from the
    // issuer precisely.
    let mut s = started();
    for e in [
        Event::ApplyPacket,
        Event::ApplyBuyerKey,
        Event::Initiate,
        Event::OpenJournal,
    ] {
        step(&mut s, e).unwrap();
    }
    let before = s.counter();
    assert_eq!(step(&mut s, Event::RecordWork).unwrap(), Outcome::Stays);
    assert_eq!(s.counter(), before, "nothing was written");

    // And offering a record for a non-change is refused rather than ignored, so
    // that a caller who built one learns it was pointless.
    let r = record(
        before + 1,
        Status::InWork,
        Some(Event::RecordWork),
        *s.root(),
    );
    let a = anchor_for(&r);
    assert_eq!(
        s.apply(Event::RecordWork, Some(r), Some(a), &keys(), &p())
            .unwrap_err(),
        Invalid::Schema("nothing changed, so nothing is recorded")
    );
}

// --- the record must say what happened ---------------------------------------

#[test]
fn a_record_carrying_the_wrong_status_or_event_is_refused() {
    // Otherwise the section could say one thing while the machine did another,
    // and the section is what a buyer reads.
    let mut s = started();
    let head = s.records().last().unwrap().0.hash().unwrap();

    let lying = record(1, Status::InWork, Some(Event::ApplyPacket), head);
    let a = anchor_for(&lying);
    assert_eq!(
        s.apply(Event::ApplyPacket, Some(lying), Some(a), &keys(), &p())
            .unwrap_err(),
        Invalid::Schema("the status record carries a different status than the move")
    );
}

#[test]
fn a_record_off_the_chain_or_out_of_order_is_refused() {
    let mut s = started();
    let head = s.records().last().unwrap().0.hash().unwrap();

    let off = record(
        1,
        Status::Packeted,
        Some(Event::ApplyPacket),
        Hash::sha256(b"x"),
    );
    let a = anchor_for(&off);
    assert_eq!(
        s.apply(Event::ApplyPacket, Some(off), Some(a), &keys(), &p())
            .unwrap_err(),
        Invalid::Schema("the status record does not link to the one before it")
    );

    let mut s = started();
    let skipped = record(5, Status::Packeted, Some(Event::ApplyPacket), head);
    let a = anchor_for(&skipped);
    assert_eq!(
        s.apply(Event::ApplyPacket, Some(skipped), Some(a), &keys(), &p())
            .unwrap_err(),
        Invalid::Schema("the status record is out of order")
    );
}

#[test]
fn an_anchor_of_another_record_does_not_count() {
    let mut s = started();
    let head = s.records().last().unwrap().0.hash().unwrap();
    let r = record(1, Status::Packeted, Some(Event::ApplyPacket), head);
    let other = record(
        1,
        Status::Packeted,
        Some(Event::ApplyPacket),
        Hash::sha256(b"other"),
    );
    assert!(s
        .apply(
            Event::ApplyPacket,
            Some(r),
            Some(anchor_for(&other)),
            &keys(),
            &p()
        )
        .is_err());
}

// --- what the section is read for --------------------------------------------

#[test]
fn the_section_keeps_every_status_ever_set() {
    // §7.2-quater: what cannot be revoked is the record. 31 stays true of a
    // container that now reads 34.
    let mut s = started();
    for e in [
        Event::ApplyPacket,
        Event::ApplyBuyerKey,
        Event::Initiate,
        Event::OpenJournal,
        Event::ServeDispute,
        Event::DisputeProven,
        Event::Appeal,
    ] {
        step(&mut s, e).expect("the step is in the table");
    }
    assert_eq!(s.current(), Status::Appealed);
    assert!(s.ever(Status::DisputeProven), "31 stays in the section");
    assert!(s.ever(Status::InWork));
    assert_eq!(s.records().len(), 8);
}

#[test]
fn a_status_survives_a_round_trip_through_its_number() {
    // The section is serialized by the NORMATIVE numbers, not by Rust's names:
    // the numbers are what KS-8 part J fixes, and the gaps are gaps on purpose.
    for &s in Status::all() {
        let json = serde_json::to_string(&s).expect("serialize");
        assert_eq!(json, s.number().to_string(), "a status is its number");
        assert_eq!(
            serde_json::from_str::<Status>(&json).expect("deserialize"),
            s
        );
    }
    // 11 and 13 through 19 are not statuses, and a document carrying one is not
    // a document about a status this implementation knows. 21 and 35 became
    // statuses on 12.09 — prescription and a settlement — so they are no longer
    // in this list, and 13 takes the place of 11's neighbour.
    for n in [11u8, 13, 15, 19, 23, 29, 200] {
        assert!(
            serde_json::from_str::<Status>(&n.to_string()).is_err(),
            "{n}"
        );
    }
}

// --- core v2 §7.2: a status record's time comes from the one rule --------------

#[derive(Debug)]
struct Reader;

impl ksg_core_v2::anchor::AttestationVerifier for Reader {
    fn verify(&self, a: &Attestation) -> Result<Timestamp, Invalid> {
        Ok(a.anchored_at.clone())
    }
    fn handles(&self, kind: &Uri) -> bool {
        kind.as_str() == "urn:ksg:anchor:test"
    }
}

#[test]
fn a_status_record_has_a_time_only_when_its_anchor_is_read() {
    // Audit Ya-2: the anchor's proof used to be never read. Now the section
    // answers "when" only through a reader, and without one says "unknown".
    let s = started();
    assert_eq!(s.times(&p(), None).expect("times"), vec![None]);
    let read = s.times(&p(), Some(&Reader)).expect("times");
    assert_eq!(
        read.first().and_then(|t| t.as_ref()).map(Timestamp::as_str),
        Some("2026-09-01T00:00:00.000Z")
    );
}

// --- the section as it leaves the container (spec v2 §11, §12) ----------------

#[test]
fn an_exported_section_replays_to_the_same_state_and_reads_its_times() {
    use ksg_core_v2::section::{verify_status_export, StatusExport};
    let mut s = started();
    step(&mut s, Event::ApplyPacket).expect("packet");
    step(&mut s, Event::ApplyBuyerKey).expect("buyer");
    let x = s.export();
    assert_eq!(x.doc_type, StatusExport::TYPE);
    // Through JSON, as a third party gets it.
    let x: StatusExport = serde_json::from_slice(&serde_json::to_vec(&x).unwrap()).unwrap();
    let r = verify_status_export(&x, &keys(), &p(), None).expect("replays");
    assert_eq!(r.current, s.current());
    assert_eq!(
        r.layers,
        vec![Status::Printed, Status::Packeted, Status::BuyerKeyed]
    );
    // No reader: every status stands, none has a time (spec v2 §7.2).
    assert_eq!(r.times, vec![None, None, None]);
}

#[test]
fn an_exported_section_that_was_tampered_with_is_refused() {
    use ksg_core_v2::section::verify_status_export;
    let mut s = started();
    step(&mut s, Event::ApplyPacket).expect("packet");
    step(&mut s, Event::ApplyBuyerKey).expect("buyer");
    // A record taken out of the middle: the chain breaks.
    let mut x = s.export();
    x.records.remove(1);
    assert!(verify_status_export(&x, &keys(), &p(), None).is_err());
    // A record's status rewritten: its signature no longer holds.
    let mut x = s.export();
    x.records[1].0.status = Status::Finalized;
    assert!(verify_status_export(&x, &keys(), &p(), None).is_err());
    // Another address: record 0 no longer links to the root.
    let mut x = s.export();
    x.serial = Serial(1);
    assert!(verify_status_export(&x, &keys(), &p(), None).is_err());
    // An empty section, and another type.
    let mut x = s.export();
    x.records.clear();
    assert!(verify_status_export(&x, &keys(), &p(), None).is_err());
    let mut x = s.export();
    x.doc_type = "BoundJournalExport".into();
    assert!(verify_status_export(&x, &keys(), &p(), None).is_err());
}

/// Record 0 has no event (draft-nam-ksg-core §Status Records): one carrying
/// `print_release` is another document with another hash, and two
/// implementations would start two different sections. Found in the audit of
/// the drafts, 03.10: the reader wrote the event, the core let it pass.
#[test]
fn record_zero_carries_no_event() {
    let zero = record(
        0,
        Status::Printed,
        Some(Event::PrintRelease),
        section_root(EMISSION, SERIAL),
    );
    let a = anchor_for(&zero);
    assert!(StatusSection::start(EMISSION, SERIAL, zero, a, &keys(), &p()).is_err());
}

/// H-10 (KS-8): a release cannot be dated back — record 0 starts the
/// section only with an anchor of **that** record; an anchor of anything
/// else is refused.
#[test]
fn record_zero_starts_only_on_its_own_anchor() {
    let zero = record(0, Status::Printed, None, section_root(EMISSION, SERIAL));
    let other = record(0, Status::Printed, None, Hash::sha256(b"another section"));
    let foreign = anchor_for(&other);
    assert!(StatusSection::start(EMISSION, SERIAL, zero.clone(), foreign, &keys(), &p()).is_err());
    let own = anchor_for(&zero);
    assert!(StatusSection::start(EMISSION, SERIAL, zero, own, &keys(), &p()).is_ok());
}
