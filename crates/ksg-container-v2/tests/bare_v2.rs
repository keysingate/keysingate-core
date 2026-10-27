//! Goal 1, `bare` v2 (owner's decision 08.10): sixteen cut operations refuse,
//! eight remain (criterion G1-1, `[doc:BARE-V2-TABLE]` §2).
//!
//! * On a `Bare` container every cut operation ends in
//!   `Stopped::NotInClass` and changes nothing (status, journal head).
//! * On a `Bare` container a kept operation never ends in `NotInClass`
//!   (it may still refuse for its own reasons).
//! * On a `Heavy` container `NotInClass` never appears.
//!
//! The sweep runs over an explicit full list of 24 so that a new operation
//! cannot slip past: it also asserts the list covers `Operation::all()`.

mod stand;

use ksg_container_v2::container::{Evidence, Stopped, UnloadRoute};
use ksg_container_v2::layers::Level;
use ksg_container_v2::Operation as Op;
use ksg_container_v2::{
    Container, Role, Status, Where, Work, BARE_IDLE_AFTER_ISSUE_MS, BARE_IDLE_AFTER_RECORD_MS,
    DAY_MS,
};
use ksg_core_v2::crypto::sign::SignatureSet;
use ksg_core_v2::doc::Class;
use ksg_core_v2::journal::{
    BinderError, CouplingRecord, BARE_POINT_LIMIT, PAGES_PER_EXPORT, POINT_LIMIT,
};
use stand::{EventKind, Page, Stand, Who};

/// The eight operations that exist in `bare`
/// (`[doc:BARE-V2-TABLE]` §2).
fn kept() -> Vec<Op> {
    vec![
        Op::PrintRelease,
        Op::ApplyBuyerKey,
        Op::ApplySubAgentKey,
        Op::Initiate,
        Op::OpenJournal,
        Op::RecordWork,
        Op::FullExport,
        Op::ExportPoint,
        // 13.10: the owner's change in one shape (the attachment's) and the
        // detachment.
        Op::TransferOwnership,
        Op::Detach,
    ]
}

/// Every operation: 10 kept + 15 cut = 25.
fn full() -> Vec<Op> {
    vec![
        Op::PrintRelease,
        Op::ApplyPacket,
        Op::ApplyBuyerKey,
        Op::ApplySubAgentKey,
        Op::Initiate,
        Op::OpenJournal,
        Op::RecordWork,
        Op::AttachArtifactOrRights,
        Op::TransferOwnership,
        Op::RaiseClass,
        Op::FullExport,
        Op::OpenVoluntarily,
        Op::AppointExpert,
        Op::DiscloseToExpert,
        Op::ExportPoint,
        Op::ServeDispute,
        Op::DecideDisputeProven,
        Op::DecideDisputeUnproven,
        Op::Settle,
        Op::Finalize,
        Op::Succeed,
        Op::DeclareKeyLost,
        Op::FreezeOnOwnerApplication,
        Op::DeclareSharesLost,
        Op::Detach,
    ]
}

fn is_not_in_class(r: &Result<(), Stopped>) -> bool {
    matches!(r, Err(Stopped::NotInClass { .. }))
}

#[test]
fn the_sweep_covers_every_operation() {
    let all = full();
    assert_eq!(all.len(), 25, "10 kept + 15 cut");
    for &op in Op::all() {
        assert!(all.contains(&op), "{op:?} is missing from the sweep");
    }
    let kept = kept();
    assert_eq!(kept.len(), 10);
    for &op in &all {
        assert_eq!(
            op.in_bare(),
            kept.contains(&op),
            "{op:?}: in_bare disagrees with the kept list"
        );
    }
}

#[test]
fn bare_refuses_the_fifteen_cut_operations_and_changes_nothing() {
    let kept = kept();
    let cut: Vec<Op> = full().into_iter().filter(|op| !kept.contains(op)).collect();
    assert_eq!(cut.len(), 15);
    for (i, op) in cut.iter().enumerate() {
        let mut s = Stand::new(Class::Bare, 1000 + i as u64);
        let status = s.c.status();
        let head = s.c.head();
        let r = s.press(*op, &[Who::Client, Who::Owner], Evidence::None, Page::None);
        assert!(
            is_not_in_class(&r),
            "{op:?} on Bare must refuse with NotInClass, got {r:?}"
        );
        assert_eq!(s.c.status(), status, "{op:?} changed the status");
        assert_eq!(s.c.head(), head, "{op:?} changed the journal head");
    }
}

#[test]
fn bare_never_answers_not_in_class_for_the_ten_kept() {
    for (i, op) in kept().iter().enumerate() {
        let mut s = Stand::new(Class::Bare, 2000 + i as u64);
        let r = s.press(*op, &[Who::Client, Who::Owner], Evidence::None, Page::None);
        assert!(
            !is_not_in_class(&r),
            "{op:?} exists in Bare and must never answer NotInClass"
        );
    }
}

#[test]
fn heavy_never_answers_not_in_class() {
    for (i, op) in full().iter().enumerate() {
        let mut s = Stand::new(Class::Heavy, 3000 + i as u64);
        let r = s.press(*op, &[Who::Client, Who::Owner], Evidence::None, Page::None);
        assert!(
            !is_not_in_class(&r),
            "{op:?} on Heavy must never answer NotInClass, got {r:?}"
        );
    }
}

// Goal 1, step G1-2b: the `bare` route out of `Printed`.
//
// `bare` has no packet (K5) and its distributor is optional (K6): it leaves
// `Printed` straight to the buyer's key or straight to initiation, with no
// new statuses. Every other class keeps refusing those two pairs.
fn record_work(s: &mut Stand, did: &str) {
    try_record_work(s, did).expect("record of work");
}

fn try_record_work(s: &mut Stand, did: &str) -> Result<(), Stopped> {
    let mut w = Work {
        container: *s.c.id(),
        under: None,
        did: did.into(),
        signatures: SignatureSet::default(),
    };
    let subject = w.subject();
    w.signatures = SignatureSet::new(s.client_signs(subject.as_bytes()));
    s.press(
        Op::RecordWork,
        &[Who::Client],
        Evidence::Work {
            order: None,
            work: Box::new(w),
        },
        Page::Of(EventKind::Work),
    )
}

/// The holder's layer key for the save/load round trip below.
const KEY: [u8; 32] = [7u8; 32];

/// Writes the stand's container to bytes and puts the one read back in its
/// place — the status section replays through the class-aware route.
fn round_trip(s: &mut Stand) {
    let bytes = s.c.seal_to_bytes(&KEY, &mut s.rng).expect("sealed");
    let id = s.c.template_id();
    s.c = Container::open_sealed(&bytes, &id, &KEY).expect("opened");
}

#[test]
fn bare_full_chain_of_eight_runs_end_to_end() {
    let mut s = Stand::new(Class::Bare, 4100);
    // PrintRelease is record 0: the stand starts printed.
    assert_eq!(s.c.status(), Status::Printed);

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
    .expect("bare: Printed + ApplyBuyerKey -> BuyerKeyed");
    assert_eq!(s.c.status(), Status::BuyerKeyed);

    let sub = s.parties.subagent.public();
    s.press(
        Op::ApplySubAgentKey,
        &[Who::SubAgent, Who::Client],
        Evidence::KeyLaid {
            to: sub,
            up_to: Level(3),
        },
        Page::None,
    )
    .expect("bare: BuyerKeyed + ApplySubAgentKey -> SubAgentKeyed");
    assert_eq!(s.c.status(), Status::SubAgentKeyed);

    s.press(
        Op::Initiate,
        &[Who::Client, Who::Owner],
        Evidence::Initiation { at: Where::Inside },
        Page::None,
    )
    .expect("bare: SubAgentKeyed + Initiate -> Initiated");
    assert_eq!(s.c.status(), Status::Initiated);

    s.press(
        Op::OpenJournal,
        &[Who::Client],
        Evidence::None,
        Page::Opening,
    )
    .expect("bare: Initiated + OpenJournal -> InWork");
    assert_eq!(s.c.status(), Status::InWork);

    record_work(&mut s, "bare work");
    assert_eq!(s.c.status(), Status::InWork);

    s.press(
        Op::ExportPoint,
        &[Who::Owner],
        Evidence::Point { number: 1 },
        Page::None,
    )
    .expect("bare: pointwise export");
    s.c.take_point().expect("the page");

    s.press(
        Op::FullExport,
        &[Who::Owner, Who::Client],
        Evidence::Unload(Box::new(UnloadRoute::Principals)),
        Page::None,
    )
    .expect("bare: full export");
    // Goal 1, step G1-4 (`Bare_v2_spec.md` §4): the whole-journal export
    // does not block a `bare` container — the status stands, the export is
    // handed out, and the journal works on.
    assert_eq!(s.c.status(), Status::InWork);
    s.c.take_export().expect("the export");
    record_work(&mut s, "work after the export");
    assert_eq!(s.c.status(), Status::InWork);

    // All eight ran at least once: PrintRelease is record 0 (asserted at the
    // start), the other seven went through the buttons.
    // The attachment's owner's change and the detachment are the
    // attachment's own; the tests of the coupling drive them.
    for op in kept()
        .iter()
        .filter(|op| !matches!(**op, Op::PrintRelease | Op::TransferOwnership | Op::Detach))
    {
        assert!(s.pressed.contains(&format!("{op:?}")), "{op:?} never ran");
    }
}

#[test]
fn bare_without_distributor_initiates_straight_from_printed() {
    let mut s = Stand::new(Class::Bare, 4200);
    assert_eq!(s.c.status(), Status::Printed);
    s.press(
        Op::Initiate,
        &[Who::Client, Who::Owner],
        Evidence::Initiation { at: Where::Inside },
        Page::None,
    )
    .expect("bare: Printed + Initiate -> Initiated");
    assert_eq!(s.c.status(), Status::Initiated);
}

#[test]
fn pro_still_refuses_printed_to_buyer_key_and_initiate() {
    for (i, class) in [Class::Heavy, Class::Light].iter().enumerate() {
        let mut s = Stand::new(*class, 4300 + i as u64);
        let buyer = s.parties.buyer.public();
        let r = s.press(
            Op::ApplyBuyerKey,
            &[Who::Buyer, Who::Owner],
            Evidence::KeyLaid {
                to: buyer,
                up_to: Level(2),
            },
            Page::None,
        );
        assert!(
            r.is_err(),
            "{class:?}: Printed + ApplyBuyerKey must refuse, got {r:?}"
        );
        assert!(
            !is_not_in_class(&r),
            "{class:?}: a Pro refusal is never NotInClass, got {r:?}"
        );
        assert_eq!(s.c.status(), Status::Printed);

        let mut s = Stand::new(*class, 4400 + i as u64);
        let r = s.press(
            Op::Initiate,
            &[Who::Client, Who::Owner],
            Evidence::Initiation { at: Where::Inside },
            Page::None,
        );
        assert!(
            r.is_err(),
            "{class:?}: Printed + Initiate must refuse, got {r:?}"
        );
        assert!(
            !is_not_in_class(&r),
            "{class:?}: a Pro refusal is never NotInClass, got {r:?}"
        );
        assert_eq!(s.c.status(), Status::Printed);
    }
}

#[test]
fn bare_section_round_trip_replays_and_goes_on() {
    let mut s = Stand::new(Class::Bare, 4500);
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
    .expect("journal");
    record_work(&mut s, "before");
    assert_eq!(s.c.status(), Status::InWork);

    let (status, head) = (s.c.status(), s.c.head());
    round_trip(&mut s);

    assert_eq!(s.c.status(), status);
    assert_eq!(s.c.head(), head, "the journal is the same, page for page");
    record_work(&mut s, "after");
    assert_eq!(s.c.status(), Status::InWork);
}

// Goal 1, criterion G1-2 (step G1-3): the `bare` idle term.
//
// Two years from initiation with no record of work, one year from the last
// record — then a brick: every button refuses with `Stopped::Bricked`, the
// export ones included, and the status and the journal stand as they were.
// The tests jump the stand's clock instead of pressing thousands of times.

/// A `bare` stand driven to `Initiated`, with the initiation's own time mark.
///
/// The mark is the stand's clock right after the initiation went through —
// the same mark the press carried, so the term counts from exactly here.
fn bare_initiated(seed: u64) -> (Stand, u64) {
    let mut s = Stand::new(Class::Bare, seed);
    assert_eq!(s.c.status(), Status::Printed);
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
    .expect("buyer key");
    let sub = s.parties.subagent.public();
    s.press(
        Op::ApplySubAgentKey,
        &[Who::SubAgent, Who::Client],
        Evidence::KeyLaid {
            to: sub,
            up_to: Level(3),
        },
        Page::None,
    )
    .expect("subagent key");
    s.press(
        Op::Initiate,
        &[Who::Client, Who::Owner],
        Evidence::Initiation { at: Where::Inside },
        Page::None,
    )
    .expect("initiation");
    assert_eq!(s.c.status(), Status::Initiated);
    let initiated_at = s.clock_ms;
    (s, initiated_at)
}

/// The stand above, with its journal opened: `InWork`, still no record.
fn bare_in_work(seed: u64) -> (Stand, u64) {
    let (mut s, initiated_at) = bare_initiated(seed);
    s.press(
        Op::OpenJournal,
        &[Who::Client],
        Evidence::None,
        Page::Opening,
    )
    .expect("journal");
    assert_eq!(s.c.status(), Status::InWork);
    (s, initiated_at)
}

fn is_bricked_since(r: &Result<(), Stopped>, since_ms: u64) -> bool {
    matches!(r, Err(Stopped::Bricked { since_ms: s }) if *s == since_ms)
}

#[test]
fn bare_idle_without_work_bricks_two_years_after_initiation() {
    assert_eq!(BARE_IDLE_AFTER_ISSUE_MS, 730 * DAY_MS);
    // 729 days, no records: work goes through.
    let (mut s, _) = bare_in_work(5100);
    s.advance(729 * DAY_MS);
    record_work(&mut s, "day 729");
    assert_eq!(s.c.status(), Status::InWork);
    // 731 days: a brick, timed from the initiation plus the term.
    // (The exact 730-day line is not probed: the stand's clock ticks past it
    // while building the press, and `>` — not `>=` — is what bricks.)
    let (mut s, initiated_at) = bare_in_work(5102);
    s.advance(731 * DAY_MS);
    let status = s.c.status();
    let head = s.c.head();
    let r = try_record_work(&mut s, "day 731");
    assert!(
        is_bricked_since(&r, initiated_at + BARE_IDLE_AFTER_ISSUE_MS),
        "731 days idle must brick, got {r:?}"
    );
    assert_eq!(s.c.status(), status, "a refusal changes nothing");
    assert_eq!(s.c.head(), head, "a refusal changes nothing");
}

#[test]
fn bare_idle_after_work_bricks_one_year_after_the_last_record() {
    assert_eq!(BARE_IDLE_AFTER_RECORD_MS, 365 * DAY_MS);
    // Work on day 100 restarts the count; 364 days after it still goes.
    let (mut s, _) = bare_in_work(5200);
    s.advance(100 * DAY_MS);
    record_work(&mut s, "day 100");
    s.advance(364 * DAY_MS);
    record_work(&mut s, "day 464");
    assert_eq!(s.c.status(), Status::InWork);
    // 366 days after the last record: a brick, timed from that record.
    // (The exact 365-day line is not probed, same tick reason as above.)
    // The term's marks survive the sealed round trip first.
    let (mut s, _) = bare_in_work(5202);
    s.advance(100 * DAY_MS);
    record_work(&mut s, "day 100");
    let last_work_at = s.clock_ms;
    round_trip(&mut s);
    s.advance(366 * DAY_MS);
    let status = s.c.status();
    let head = s.c.head();
    let r = try_record_work(&mut s, "day 466");
    assert!(
        is_bricked_since(&r, last_work_at + BARE_IDLE_AFTER_RECORD_MS),
        "366 days after the last record must brick, got {r:?}"
    );
    assert_eq!(s.c.status(), status, "a refusal changes nothing");
    assert_eq!(s.c.head(), head, "a refusal changes nothing");
}

#[test]
fn bare_bricked_refuses_all_eight_operations() {
    let (mut s, initiated_at) = bare_in_work(5300);
    s.advance(731 * DAY_MS);
    let r = try_record_work(&mut s, "too late");
    assert!(
        is_bricked_since(&r, initiated_at + BARE_IDLE_AFTER_ISSUE_MS),
        "the stand must be bricked first, got {r:?}"
    );
    let status = s.c.status();
    let head = s.c.head();
    let buyer = s.parties.buyer.public();
    let sub = s.parties.subagent.public();
    let presses: Vec<(&str, Result<(), Stopped>)> = vec![
        (
            "PrintRelease",
            s.press(
                Op::PrintRelease,
                &[Who::Client, Who::Owner],
                Evidence::None,
                Page::None,
            ),
        ),
        (
            "ApplyBuyerKey",
            s.press(
                Op::ApplyBuyerKey,
                &[Who::Buyer, Who::Owner],
                Evidence::KeyLaid {
                    to: buyer,
                    up_to: Level(2),
                },
                Page::None,
            ),
        ),
        (
            "ApplySubAgentKey",
            s.press(
                Op::ApplySubAgentKey,
                &[Who::SubAgent, Who::Client],
                Evidence::KeyLaid {
                    to: sub,
                    up_to: Level(3),
                },
                Page::None,
            ),
        ),
        (
            "Initiate",
            s.press(
                Op::Initiate,
                &[Who::Client, Who::Owner],
                Evidence::Initiation { at: Where::Inside },
                Page::None,
            ),
        ),
        (
            "OpenJournal",
            s.press(
                Op::OpenJournal,
                &[Who::Client],
                Evidence::None,
                Page::Opening,
            ),
        ),
        ("RecordWork", try_record_work(&mut s, "no")),
        (
            "FullExport",
            s.press(
                Op::FullExport,
                &[Who::Owner, Who::Client],
                Evidence::Unload(Box::new(UnloadRoute::Principals)),
                Page::None,
            ),
        ),
        (
            "ExportPoint",
            s.press(
                Op::ExportPoint,
                &[Who::Owner],
                Evidence::Point { number: 1 },
                Page::None,
            ),
        ),
    ];
    assert_eq!(presses.len(), 8);
    for (name, r) in &presses {
        assert!(
            matches!(r, Err(Stopped::Bricked { .. })),
            "{name} on a bricked container must refuse with Bricked, got {r:?}"
        );
    }
    assert_eq!(s.c.status(), status, "refusals change nothing");
    assert_eq!(s.c.head(), head, "refusals change nothing");
}

#[test]
fn heavy_and_light_do_not_brick_on_the_same_terms() {
    for (i, class) in [Class::Heavy, Class::Light].iter().enumerate() {
        let mut s = Stand::new(*class, 5400 + i as u64);
        // The ordinary road to work, then two years of silence.
        s.press(Op::ApplyPacket, &[Who::Issuer], Evidence::None, Page::None)
            .expect("packet");
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
        .expect("buyer key");
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
        .expect("journal");
        assert_eq!(s.c.status(), Status::InWork);
        s.advance(731 * DAY_MS);
        record_work(&mut s, "two years later");
        assert_eq!(s.c.status(), Status::InWork, "{class:?} never bricks");
        // And two more years on top of the record.
        s.advance(2 * 365 * DAY_MS + 1);
        record_work(&mut s, "later still");
        assert_eq!(s.c.status(), Status::InWork, "{class:?} never bricks");
    }
}

// Goal 1, criterion G1-4 (step G1-5): `bare` without post-quantum wrapping
// and without journal anchors (`Bare_v2_spec.md` §3: `pq_key.rs` cut, no
// ML-KEM half in the layers; K2: the working journal is never anchored).
//
// * (a) printing → initiation → 3 records: the `bare` container holds no PQ
//   key and its file carries no outer signature — absent, not empty;
// * (b) the stand-in for the anchorer counts 0 calls over 3 `bare` records
//   and more than 0 over 3 Pro records;
// * (c) the `bare` file is smaller than the Pro file over the same data.

/// The outer file's magic, `ksg-container-v2::store` layout v4.
const STORE_MAGIC: &[u8] = b"ksg:store:v4";

/// The trailing signature section of a sealed file: its length, big-endian.
/// Zero means the file carries no outer signature at all.
fn outer_sig_len(bytes: &[u8]) -> usize {
    assert!(
        bytes.starts_with(STORE_MAGIC),
        "not a stored container file"
    );
    let len_at = bytes.len().checked_sub(4).expect("truncated file");
    u32::from_be_bytes(bytes[len_at..].try_into().expect("length")) as usize
}

/// Opens the local store envelope with the test's own key so the test can
/// assert the serialized state omits the optional PQ field, rather than only
/// observing that the live container has no PQ key.
fn stored_state(bytes: &[u8], template: &ksg_core_v2::crypto::hash::Hash) -> serde_json::Value {
    use ksg_container_v2::{ChaCha20Poly1305Aead, Deflate, Packer};

    assert_eq!(outer_sig_len(bytes), 0, "the bare envelope is unsigned");
    let body = &bytes[STORE_MAGIC.len()..bytes.len() - 4];
    let (nonce, sealed) = body.split_at(12);
    let aad = [STORE_MAGIC, template.as_bytes()].concat();
    let packer = Packer::new(
        ChaCha20Poly1305Aead,
        Deflate {
            limit: ksg_container_v2::store::MAX_STATE,
        },
        ksg_container_v2::store::STORE_SIZE,
    );
    let plain = packer
        .open(sealed, &KEY, nonce, &aad)
        .expect("opened state");
    serde_json::from_slice(&plain).expect("JSON state")
}

/// A stand driven to `InWork` with `n` records of work, for any class: the
/// ordinary road — through the packet where the class has one, straight
/// from printing for `bare`.
fn in_work_with_records(class: Class, seed: u64, n: usize) -> Stand {
    let mut s = Stand::new(class, seed);
    if class != Class::Bare {
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
    .expect("buyer key");
    if class == Class::Bare {
        let sub = s.parties.subagent.public();
        s.press(
            Op::ApplySubAgentKey,
            &[Who::SubAgent, Who::Client],
            Evidence::KeyLaid {
                to: sub,
                up_to: Level(3),
            },
            Page::None,
        )
        .expect("subagent key");
    }
    s.press(
        Op::Initiate,
        &[Who::Client, Who::Owner],
        Evidence::Initiation { at: Where::Inside },
        Page::None,
    )
    .expect("initiation");
    assert!(s.c.pq_public().is_none() == (class == Class::Bare));
    s.press(
        Op::OpenJournal,
        &[Who::Client],
        Evidence::None,
        Page::Opening,
    )
    .expect("journal");
    assert_eq!(s.c.status(), Status::InWork);
    for i in 0..n {
        record_work(&mut s, &format!("work {i}"));
    }
    s
}

#[test]
fn bare_print_initiate_and_three_records_carry_no_pq() {
    use ksg_container_v2::store::verify_absent_outer;
    // Printing sets no PQ layer on `bare`.
    let printed = Stand::new(Class::Bare, 7100);
    assert_eq!(printed.c.status(), Status::Printed);
    assert!(
        printed.c.pq_public().is_none(),
        "printing sets no post-quantum key on bare"
    );
    // Initiation and three records store none either.
    let mut s = in_work_with_records(Class::Bare, 7100, 3);
    assert!(
        s.c.pq_public().is_none(),
        "initiation and work store no post-quantum key on bare"
    );
    let bytes = s.c.seal_to_bytes(&KEY, &mut s.rng).expect("sealed");
    // No PQ fields in the saved file: the outer signature is absent, not empty.
    assert_eq!(
        outer_sig_len(&bytes),
        0,
        "the bare file carries no outer signature"
    );
    let state = stored_state(&bytes, &s.c.template_id());
    assert!(
        state.get("pq_key").is_none(),
        "the serialized bare state omits pq_key rather than storing null"
    );
    verify_absent_outer(&bytes).expect("the bare file shape");
    // The file opens without any key — nothing was signed outside.
    let id = s.c.template_id();
    let back = Container::open_sealed(&bytes, &id, &KEY).expect("opened");
    assert!(back.pq_public().is_none());
}

#[test]
fn bare_work_records_never_call_the_anchorer_while_pro_calls_it() {
    // Three records past the opening, on each side.
    let mut bare = in_work_with_records(Class::Bare, 7200, 0);
    let mut pro = in_work_with_records(Class::Heavy, 7200, 0);
    let (bare_before, pro_before) = (bare.anchor_calls, pro.anchor_calls);
    for i in 0..3 {
        record_work(&mut bare, &format!("bare {i}"));
        record_work(&mut pro, &format!("pro {i}"));
    }
    assert_eq!(
        bare.anchor_calls, bare_before,
        "bare work records never call the anchorer"
    );
    assert_eq!(bare.c.journal_anchor_count(), 0);
    assert!(
        pro.anchor_calls > pro_before,
        "Pro work records call the anchorer"
    );
    assert!(pro.c.journal_anchor_count() > 0);
}

#[test]
fn bare_file_is_smaller_than_pro_over_the_same_data() {
    let mut bare = in_work_with_records(Class::Bare, 7300, 3);
    let mut pro = in_work_with_records(Class::Heavy, 7300, 3);
    let bare_bytes = bare
        .c
        .seal_to_bytes(&KEY, &mut bare.rng)
        .expect("bare sealed");
    let pro_bytes = pro.c.seal_to_bytes(&KEY, &mut pro.rng).expect("pro sealed");
    eprintln!(
        "G1-4 sizes: bare file {} bytes; pro file {} bytes",
        bare_bytes.len(),
        pro_bytes.len()
    );
    assert!(
        bare_bytes.len() < pro_bytes.len(),
        "bare file ({}) is smaller than pro file ({})",
        bare_bytes.len(),
        pro_bytes.len()
    );
}
//
// A pointwise export carries 1–24 pages and counts once against the twelve;
// a thirteenth is refused. `bare` has no expert (`DiscloseToExpert` is cut),
// so there is no road around the twelve. The whole-journal export leaves the
// container working: a second export and the work between go through, and the
// status stands as it was. In Pro the whole export still ends the container
// at status 7.

// Goal 1, criterion G1-3 (step G1-4): the `bare` export to the owner
// (`Bare_v2_spec.md` §4).
//
// A pointwise export carries 1–24 pages and counts once against the twelve;
// a thirteenth is refused. `bare` has no expert (`DiscloseToExpert` is cut),
// so there is no road around the twelve. The whole-journal export leaves the
// container working: a second export and the work between go through, and the
// status stands as it was. In Pro the whole export still ends the container
// at status 7.

/// A `bare` stand in work with `n` records of work on the journal (page 0 is
/// the opening, work records are pages 1 and up).
fn bare_in_work_with_records(seed: u64, n: usize) -> Stand {
    let (mut s, _) = bare_in_work(seed);
    for i in 0..n {
        record_work(&mut s, &format!("work {i}"));
    }
    s
}

#[test]
fn bare_pointwise_export_carries_1_to_24_pages() {
    assert_eq!(PAGES_PER_EXPORT, 24);
    assert_eq!(BARE_POINT_LIMIT, 48);
    let mut s = bare_in_work_with_records(6100, 24);
    // One page in one export.
    s.press(
        Op::ExportPoint,
        &[Who::Owner],
        Evidence::Points { numbers: vec![1] },
        Page::None,
    )
    .expect("one page");
    assert_eq!(s.c.take_points().expect("the page").len(), 1);
    // Twenty-four pages in one export.
    let all: Vec<u64> = (1..=24).collect();
    s.press(
        Op::ExportPoint,
        &[Who::Owner],
        Evidence::Points { numbers: all },
        Page::None,
    )
    .expect("twenty-four pages");
    assert_eq!(s.c.take_points().expect("the pages").len(), 24);
    // Twenty-five pages do not go out.
    let too_many: Vec<u64> = (1..=25).collect();
    let r = s.press(
        Op::ExportPoint,
        &[Who::Owner],
        Evidence::Points { numbers: too_many },
        Page::None,
    );
    assert!(
        matches!(r, Err(Stopped::Journal(BinderError::PageCount(25)))),
        "25 pages must refuse with PageCount, got {r:?}"
    );
    assert_eq!(s.c.status(), Status::InWork, "a refusal changes nothing");
}

#[test]
fn bare_pointwise_export_stops_at_forty_eight_with_no_expert_road_around() {
    // `[decision]` 11.10: `bare` allows 48 pointwise exports; the other
    // classes keep twelve.
    assert_eq!(BARE_POINT_LIMIT, 48);
    assert_eq!(POINT_LIMIT, 12);
    let mut s = bare_in_work_with_records(6200, 2);
    for _ in 0..BARE_POINT_LIMIT {
        s.press(
            Op::ExportPoint,
            &[Who::Owner],
            Evidence::Point { number: 1 },
            Page::None,
        )
        .expect("a pointwise export within the forty-eight");
        s.c.take_point().expect("the page");
    }
    let r = s.press(
        Op::ExportPoint,
        &[Who::Owner],
        Evidence::Point { number: 1 },
        Page::None,
    );
    assert!(
        matches!(r, Err(Stopped::Journal(BinderError::PointLimit(48)))),
        "the 49th export must refuse with PointLimit, got {r:?}"
    );
    // `bare` has no expert: the cut operation stays cut, so the forty-eight
    // have no road around them.
    let r = s.press(
        Op::DiscloseToExpert,
        &[Who::Client, Who::Owner],
        Evidence::None,
        Page::None,
    );
    assert!(
        is_not_in_class(&r),
        "no expert road around the forty-eight, got {r:?}"
    );
    assert_eq!(s.c.status(), Status::InWork, "refusals change nothing");
}

#[test]
fn bare_full_export_twice_with_work_between_leaves_it_working() {
    let mut s = bare_in_work_with_records(6300, 2);
    assert_eq!(s.c.status(), Status::InWork);
    s.press(
        Op::FullExport,
        &[Who::Owner, Who::Client],
        Evidence::Unload(Box::new(UnloadRoute::Principals)),
        Page::None,
    )
    .expect("first full export");
    assert_eq!(s.c.status(), Status::InWork, "the export moves nothing");
    let first = s.c.take_export().expect("the first export");
    record_work(&mut s, "between the exports");
    s.press(
        Op::FullExport,
        &[Who::Owner, Who::Client],
        Evidence::Unload(Box::new(UnloadRoute::Principals)),
        Page::None,
    )
    .expect("second full export");
    assert_eq!(s.c.status(), Status::InWork, "the export moves nothing");
    let second = s.c.take_export().expect("the second export");
    assert_eq!(
        second.pages.len(),
        first.pages.len() + 1,
        "the second export carries the work between"
    );
    // Pointwise exports work on after the whole one.
    s.press(
        Op::ExportPoint,
        &[Who::Owner],
        Evidence::Point { number: 1 },
        Page::None,
    )
    .expect("pointwise after full");
    s.c.take_point().expect("the page");
    assert_eq!(s.c.status(), Status::InWork);
}

#[test]
fn pro_full_export_still_ends_at_seven() {
    let mut s = Stand::new(Class::Heavy, 6400);
    s.press(Op::ApplyPacket, &[Who::Issuer], Evidence::None, Page::None)
        .expect("packet");
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
    .expect("buyer key");
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
    .expect("journal");
    assert_eq!(s.c.status(), Status::InWork);
    s.press(
        Op::FullExport,
        &[Who::Owner, Who::Client],
        Evidence::Unload(Box::new(UnloadRoute::Principals)),
        Page::None,
    )
    .expect("full export");
    assert_eq!(s.c.status(), Status::Exported);
    s.c.take_export().expect("the export");
    // Nothing works after a Pro export: the journal is spent, and the status
    // refuses (O-02). `ExportPoint` needs no journal page, so the stand can
    // press it without tripping on the draft first.
    let r = s.press(
        Op::ExportPoint,
        &[Who::Owner],
        Evidence::Point { number: 1 },
        Page::None,
    );
    assert!(
        matches!(r, Err(Stopped::Unload(_))),
        "nothing works after a Pro export, got {r:?}"
    );
    assert_eq!(s.c.status(), Status::Exported);
}

// Goal 1, criterion G1-6 (`Bare_v2_spec.md` §5, §8.3, `[decision]` 06.10): the
// coupling — `bare` is a follower only.
//
// * light → bare and Pro → bare: the leader writes slot 2 (`Pulls{bare}`)
//   at E-5, the bare trailer writes slot 1 (`AttachedTo{leader}`) at E-5
//   too — its E-14 is cut, and the page changes no status.
// * A `bare` as a leader: `Pulls` is refused in it, whatever the trailer —
//   `bare` never pulls.
// * bare → bare: refused on both sides — the would-be leader refuses slot 2,
//   and the pair has no completing write.
// * The coupled `bare` goes on recording work and exporting; its idle term
//   is untouched (the coupling page counts as work, not more).

/// The coupling presses ride E-5: sealed by the client alone.
fn coupling(s: &mut Stand, record: CouplingRecord) -> Result<(), Stopped> {
    s.clock_ms += 1_000;
    let d = s.c.draft_coupling(record.clone(), s.clock_ms)?;
    let w = s.seal_draft(d);
    s.press_write(
        Op::RecordWork,
        &[Who::Client],
        Evidence::Coupling(record),
        Some(w),
    )
}

/// The new agent signs with its mobile half and the container's half of its
/// key, staged during a hand-off.
fn new_agent_signs(
    s: &mut Stand,
    m: &ksg_container_v2::client_key::MobileHalf,
    msg: &[u8],
) -> Vec<ksg_core_v2::crypto::sign::Signature> {
    let (nonces, commitment) = m.commit(&mut s.rng);
    let round =
        s.c.begin_signing_incoming(msg, &commitment, &mut s.rng)
            .expect("round");
    let share = m.respond(nonces, &round).expect("share");
    s.c.finish_signing_incoming(&share, &mut s.rng)
        .expect("both halves")
}

fn ed25519_only(
    sigs: Vec<ksg_core_v2::crypto::sign::Signature>,
) -> Vec<ksg_core_v2::crypto::sign::Signature> {
    sigs.into_iter()
        .filter(|x| x.alg == ksg_core_v2::crypto::sign::Alg::Ed25519)
        .collect()
}

/// The hand-off to the leader's agent: its key born inside, the page sealed
/// by it and signed over by both agents; the stand then holds its half.
fn hand_off_to_leaders_agent(s: &mut Stand) -> Result<(), Stopped> {
    let m =
        s.c.stage_handoff(stand::uri("did:key:zLeaderAgent#key-1"), &mut s.rng)?;
    s.clock_ms += 1_000;
    let d = s.c.draft_handoff(s.clock_ms)?;
    let bytes = d.seal_bytes().expect("bytes");
    let tb = d.transfer_bytes().expect("bytes").expect("a transfer");
    let seal = new_agent_signs(s, &m, &bytes);
    let mut transfer = ed25519_only(s.client_signs(&tb));
    transfer.extend(ed25519_only(new_agent_signs(s, &m, &tb)));
    let w = ksg_container_v2::container::JournalWrite::Record {
        draft: Box::new(d),
        sealing: Box::new(ksg_core_v2::journal::Sealing {
            seal: SignatureSet::new(seal),
            transfer: Some(SignatureSet::new(transfer)),
            ..ksg_core_v2::journal::Sealing::default()
        }),
    };
    s.press_write(Op::RecordWork, &[Who::Client], Evidence::Handoff, Some(w))?;
    // The former client's mobile half stays with the stand: its other half
    // stays inside for the detachment (13.10, variant A).
    s.former_mobile = Some(std::mem::replace(&mut s.mobile, m));
    Ok(())
}

/// The owner's change of the attachment (E-9 in `bare`, 13.10): the leader's
/// owner arrives with the command. On the stand it is the buyer's key — the
/// one the stand signs the transfer with.
fn owners_change_for_attachment(s: &mut Stand) -> Result<(), Stopped> {
    let new_owner = s.parties.buyer.public();
    s.press(
        Op::TransferOwnership,
        &[Who::Owner, Who::Buyer],
        Evidence::NewOwner(new_owner),
        Page::None,
    )
}

/// The whole attachment of a `bare` (13.10): the owner's change, the
/// hand-off to the leader's agent, the coupling page — in that order.
fn attach(s: &mut Stand, leader: ksg_core_v2::crypto::hash::Hash) -> Result<(), Stopped> {
    owners_change_for_attachment(s)?;
    hand_off_to_leaders_agent(s)?;
    coupling(s, CouplingRecord::AttachedTo { leader })
}

/// A stand of the given class driven to `InWork` with the journal open.
fn coupled(class: Class, seed: u64) -> Stand {
    in_work_with_records(class, seed, 0)
}

#[test]
fn bare_attaches_as_trailer_through_record_work() {
    // The trailer's marker rides E-5 in `bare`: the same page, the same slot,
    // without the death of the cut E-14 — and it changes no status. The
    // leader is Pro only (owner's decision 13.10): a `bare` sees its leader
    // by identifier alone, so the class is checked by the verifier on the
    // pair of exports, not here.
    for (i, leader_class) in [Class::Heavy].iter().enumerate() {
        let seed = 8100 + i as u64;
        let mut trailer = coupled(Class::Bare, seed);
        let leader = coupled(*leader_class, seed + 50);
        let attached = CouplingRecord::AttachedTo {
            leader: *leader.c.id(),
        };
        let head = trailer.c.head();
        attach(&mut trailer, *leader.c.id())
            .expect("bare trailer: the attachment, slot 1 at E-5 last");
        assert_ne!(trailer.c.head(), head, "the trace went on the journal");
        assert_eq!(
            trailer.c.status(),
            Status::InWork,
            "the bare trailer stays in work"
        );
        let r = coupling(&mut trailer, attached);
        assert!(
            matches!(r, Err(Stopped::Journal(_))),
            "slot 1 is spent: {r:?}"
        );
    }
    // And a bare cannot attach to itself.
    let mut s = coupled(Class::Bare, 8290);
    let me = CouplingRecord::AttachedTo { leader: *s.c.id() };
    assert!(
        matches!(coupling(&mut s, me), Err(Stopped::WrongEvidence { .. })),
        "a container is not its own leader"
    );
}

#[test]
fn bare_never_pulls() {
    // Slot 2 is the leader's page: a `bare` refuses it whatever the trailer —
    // and so a bare → bare coupling has no side that could complete it.
    for (i, trailer_class) in [Class::Bare, Class::Light, Class::Heavy].iter().enumerate() {
        let mut leader = coupled(Class::Bare, 8200 + i as u64);
        let trailer = coupled(*trailer_class, 8250 + i as u64);
        let pulls = CouplingRecord::Pulls {
            trailer: *trailer.c.id(),
            trailer_seal: trailer.c.top_seal_hash().expect("the trailer's seal"),
        };
        let status = leader.c.status();
        let head = leader.c.head();
        let r = coupling(&mut leader, pulls);
        assert!(
            matches!(r, Err(Stopped::WrongEvidence { .. })),
            "a bare never leads, whatever the trailer ({trailer_class:?}): {r:?}"
        );
        assert_eq!(leader.c.status(), status, "a refusal changes nothing");
        assert_eq!(leader.c.head(), head, "a refusal changes nothing");
    }
    // A bare trailer may name a bare leader — the marker is the trailer's own
    // page; completion is the leader's, and the loop above refuses it.
    let mut one = coupled(Class::Bare, 8300);
    let two = coupled(Class::Bare, 8350);
    assert!(
        attach(&mut one, *two.c.id()).is_ok(),
        "the bare trailer marks the leader; the pair stays incomplete by rule"
    );
}

#[test]
fn pro_pulls_a_bare_trailer() {
    // Pro → bare: the leader writes slot 2 at E-5, once. The trailer's seal
    // it carries is final — the attached bare writes nothing after it.
    for (i, leader_class) in [Class::Heavy].iter().enumerate() {
        let seed = 8400 + i as u64;
        let mut trailer = coupled(Class::Bare, seed);
        let mut leader = coupled(*leader_class, seed + 50);
        attach(&mut trailer, *leader.c.id()).expect("the trailer marks its leader");
        let seal = trailer.c.top_seal_hash().expect("the trailer's last seal");
        assert!(try_record_work(&mut trailer, "after").is_err());
        assert_eq!(
            trailer.c.top_seal_hash().expect("the seal"),
            seal,
            "the trailer's last seal does not move after the coupling"
        );
        let pulls = CouplingRecord::Pulls {
            trailer: *trailer.c.id(),
            trailer_seal: seal,
        };
        let head = leader.c.head();
        coupling(&mut leader, pulls.clone()).expect("the leader writes slot 2");
        assert_ne!(leader.c.head(), head, "the leader's journal moved");
        coupling(&mut leader, pulls).expect_err("slot 2 is spent");
    }
}

#[test]
fn an_attached_bare_only_reads() {
    // Owner's decisions 11.10 and 13.10: the coupling page closes the
    // journal of a `bare` for good — no work, no second coupling — and only
    // the exports go out. A refusal changes nothing.
    let (mut trailer, _) = bare_in_work(8400);
    record_work(&mut trailer, "before the coupling");
    let leader = coupled(Class::Heavy, 8450);
    let attached = CouplingRecord::AttachedTo {
        leader: *leader.c.id(),
    };
    assert!(!trailer.c.bare_attached());
    attach(&mut trailer, *leader.c.id()).expect("the trailer marks its leader");
    assert!(trailer.c.bare_attached());

    let status = trailer.c.status();
    let head = trailer.c.head();
    let r = try_record_work(&mut trailer, "after the coupling");
    assert!(
        matches!(r, Err(Stopped::Attached { op: Op::RecordWork })),
        "work is refused once attached, got {r:?}"
    );
    let r = coupling(&mut trailer, attached);
    assert!(
        matches!(r, Err(Stopped::Journal(_))),
        "no second coupling page — the slot is spent, got {r:?}"
    );
    assert_eq!(trailer.c.status(), status, "a refusal changes nothing");
    assert_eq!(trailer.c.head(), head, "a refusal changes nothing");

    // The owner changed with the attachment: the one the bare had holds no
    // seat now, the leader's owner (the stand's buyer key) does.
    let r = trailer.press(
        Op::ExportPoint,
        &[Who::Owner],
        Evidence::Point { number: 1 },
        Page::None,
    );
    assert!(r.is_err(), "the former owner exports nothing, got {r:?}");
    // The pointwise export still goes out — to the leader's owner.
    trailer
        .press(
            Op::ExportPoint,
            &[Who::Buyer],
            Evidence::Point { number: 1 },
            Page::None,
        )
        .expect("the attached bare still exports a page");
    trailer.c.take_point().expect("the page");
}

#[test]
fn an_attached_bare_never_bricks() {
    // Nothing is written any more, so there is no idle term to run out
    // (owner's decision 13.10): years past the ordinary brick, the export
    // still goes out — and the same idle time bricks a bare left unattached.
    let (mut trailer, _) = bare_in_work(8500);
    let leader = coupled(Class::Heavy, 8550);
    attach(&mut trailer, *leader.c.id()).expect("the coupling");
    trailer.advance(3 * 366 * DAY_MS);
    trailer
        .press(
            Op::ExportPoint,
            &[Who::Buyer],
            Evidence::Point { number: 1 },
            Page::None,
        )
        .expect("no brick on an attached bare");
    trailer.c.take_point().expect("the page");

    let (mut plain, _) = bare_in_work(8600);
    plain.advance(100 * DAY_MS);
    record_work(&mut plain, "work");
    let plain_mark = plain.clock_ms;
    plain.advance(366 * DAY_MS);
    let r = try_record_work(&mut plain, "past the record's year");
    assert!(is_bricked_since(&r, plain_mark + BARE_IDLE_AFTER_RECORD_MS));
}

fn whole_journal(s: &mut Stand, who: &[Who]) -> ksg_core_v2::journal::BoundExport {
    s.press(
        Op::FullExport,
        who,
        Evidence::Unload(Box::new(UnloadRoute::Principals)),
        Page::None,
    )
    .expect("the whole journal");
    s.c.take_export().expect("the export")
}

#[test]
fn the_verifier_confirms_a_bare_pro_pair_and_nothing_else() {
    use ksg_core_v2::crypto::sign::Profile;
    use ksg_verify_v2::coupling::{verify_pair, Pair};
    // Owner's decisions 13.10: the pair is confirmed only with both exports —
    // each names the other, the leader carries the trailer's last seal, and
    // the leader is Pro.
    let mut trailer = coupled(Class::Bare, 9100);
    record_work(&mut trailer, "the trailer's own work");
    let mut leader = coupled(Class::Heavy, 9150);
    let mut stranger = coupled(Class::Heavy, 9160);
    attach(&mut trailer, *leader.c.id()).expect("slot 1");
    let seal = trailer.c.top_seal_hash().expect("the trailer's last seal");
    coupling(
        &mut leader,
        CouplingRecord::Pulls {
            trailer: *trailer.c.id(),
            trailer_seal: seal,
        },
    )
    .expect("slot 2");
    // A Pro that never was the leader claims the trailer all the same.
    coupling(
        &mut stranger,
        CouplingRecord::Pulls {
            trailer: *trailer.c.id(),
            trailer_seal: seal,
        },
    )
    .expect("a claim is only a page");

    let t = whole_journal(&mut trailer, &[Who::Buyer, Who::Client]);
    let l = whole_journal(&mut leader, &[Who::Owner, Who::Client]);
    let x = whole_journal(&mut stranger, &[Who::Owner, Who::Client]);
    let profile = Profile::default();

    assert!(
        matches!(verify_pair(&t, &l, &profile), Pair::Confirmed { trailer: a, leader: b }
            if a == *trailer.c.id() && b == *leader.c.id()),
        "the real pair is confirmed"
    );
    assert!(
        matches!(verify_pair(&t, &x, &profile), Pair::Refused(ref why) if why.contains("another leader")),
        "the stranger's claim is refused: the trailer names someone else"
    );
    // The leader carrying an older seal of the trailer does not hold.
    let mut stale = l.clone();
    for p in &mut stale.pages {
        if let ksg_core_v2::journal::Body::Coupling(CouplingRecord::Pulls {
            trailer_seal, ..
        }) = &mut p.body
        {
            *trailer_seal = t.seal.prev.expect("an earlier seal");
        }
    }
    assert!(
        matches!(verify_pair(&t, &stale, &profile), Pair::Refused(_)),
        "a changed page breaks the leader's export or the seal match"
    );
}

#[test]
fn the_verifier_refuses_a_light_leader() {
    use ksg_core_v2::crypto::sign::Profile;
    use ksg_verify_v2::coupling::{verify_pair, Pair};
    // Owner's decision 13.10: a `bare` is attached to Pro only. The container
    // sees its leader by identifier alone, so the pair is where it shows.
    let mut trailer = coupled(Class::Bare, 9200);
    let mut leader = coupled(Class::Light, 9250);
    attach(&mut trailer, *leader.c.id()).expect("slot 1");
    let seal = trailer.c.top_seal_hash().expect("the seal");
    coupling(
        &mut leader,
        CouplingRecord::Pulls {
            trailer: *trailer.c.id(),
            trailer_seal: seal,
        },
    )
    .expect("slot 2");
    let t = whole_journal(&mut trailer, &[Who::Buyer, Who::Client]);
    let l = whole_journal(&mut leader, &[Who::Owner, Who::Client]);
    assert!(
        matches!(verify_pair(&t, &l, &Profile::default()), Pair::Refused(ref why) if why.contains("not Pro")),
        "a light leader is refused"
    );
}

#[test]
fn the_attachment_goes_in_its_order() {
    // 13.10: the owner's change (E-9, in `bare` only this one shape), the
    // hand-off to the leader's agent, the coupling page — in that order, and
    // nothing else while it runs. A refusal changes nothing.
    let leader = coupled(Class::Heavy, 9300);
    let id = *leader.c.id();

    // The coupling page alone is refused: the owner did not change.
    let mut b = coupled(Class::Bare, 9310);
    let r = coupling(&mut b, CouplingRecord::AttachedTo { leader: id });
    assert!(matches!(r, Err(Stopped::Attaching { .. })), "got {r:?}");
    assert!(!b.c.bare_attached());

    // E-9 in `bare` brings the arriving owner, or it is refused.
    let r = b.press(
        Op::TransferOwnership,
        &[Who::Owner, Who::Buyer],
        Evidence::None,
        Page::None,
    );
    assert!(matches!(r, Err(Stopped::WrongEvidence { .. })), "got {r:?}");
    owners_change_for_attachment(&mut b).expect("the owner's change");
    assert!(b.c.bare_attaching());
    assert!(b.c.roster().holds(&b.parties.buyer.public(), Role::Owner));

    // While attaching: no work, no second owner's change, no coupling
    // before the hand-off.
    let head = b.c.head();
    assert!(matches!(
        try_record_work(&mut b, "work"),
        Err(Stopped::Attaching { .. })
    ));
    let again = b.parties.claimant.public();
    let r = b.press_write(
        Op::TransferOwnership,
        &[Who::Owner, Who::Buyer],
        Evidence::NewOwner(again),
        None,
    );
    assert!(matches!(r, Err(Stopped::Attaching { .. })), "got {r:?}");
    let r = coupling(&mut b, CouplingRecord::AttachedTo { leader: id });
    assert!(matches!(r, Err(Stopped::Attaching { .. })), "got {r:?}");
    assert_eq!(b.c.head(), head, "a refusal changes nothing");

    // The hand-off: the client the bare had keeps its own seat.
    let before = b.c.roster().holder(Role::Client).cloned().expect("client");
    hand_off_to_leaders_agent(&mut b).expect("the hand-off");
    assert_eq!(
        b.c.roster()
            .holder(Role::FormerClient)
            .map(|k| k.kid.clone()),
        Some(before.kid)
    );
    coupling(&mut b, CouplingRecord::AttachedTo { leader: id }).expect("slot 1");
    assert!(b.c.bare_attached());
    assert!(!b.c.bare_attaching());

    // In Pro, E-9 stays the sale to the buyer laid at E-3: an arriving
    // owner brought by the command is not its shape.
    let mut pro = coupled(Class::Heavy, 9320);
    let newcomer = pro.parties.claimant.public();
    let head = pro.c.head();
    let r = pro.press_write(
        Op::TransferOwnership,
        &[Who::Owner, Who::Buyer],
        Evidence::NewOwner(newcomer),
        None,
    );
    assert!(r.is_err(), "got {r:?}");
    assert_eq!(pro.c.head(), head, "a refusal changes nothing");
}

#[test]
fn only_an_attached_bare_detaches() {
    // 13.10: the detachment is an attached `bare`'s; elsewhere it is refused
    // and changes nothing. Its seats are the leader's owner and the client
    // the `bare` had — the operation's own table says so.
    use ksg_container_v2::operation::{Keys, Seat};
    assert_eq!(
        Op::Detach.keys(),
        Keys::Seats(&[
            Seat::Exactly(Role::Owner),
            Seat::Exactly(Role::FormerClient)
        ])
    );
    let mut b = coupled(Class::Bare, 9400);
    let head = b.c.head();
    let r = b.press(
        Op::Detach,
        &[Who::Owner, Who::Client],
        Evidence::None,
        Page::None,
    );
    assert!(r.is_err(), "a bare not attached does not detach, got {r:?}");
    assert_eq!(b.c.head(), head);
    assert!(!b.c.burned());
}

#[test]
fn detaching_takes_both_words_and_burns_the_copy() {
    // 13.10: the detachment of an attached `bare` takes the leader's owner
    // and the client the `bare` had — that client signing with the half the
    // container kept for it (variant A) — and burns this copy: no journal, no
    // keys, every button refused, and so after the store.
    const KEY: [u8; 32] = [9u8; 32];
    let leader = coupled(Class::Heavy, 9500);
    let mut b = coupled(Class::Bare, 9510);
    record_work(&mut b, "the history");
    attach(&mut b, *leader.c.id()).expect("the attachment");

    // One word is not enough, and the leader's agent is not the former client.
    let head = b.c.head();
    let r = b.press(Op::Detach, &[Who::Buyer], Evidence::None, Page::None);
    assert!(r.is_err(), "the owner alone does not detach, got {r:?}");
    let r = b.press(
        Op::Detach,
        &[Who::Buyer, Who::Client],
        Evidence::None,
        Page::None,
    );
    assert!(
        r.is_err(),
        "the leader's agent is not the former client, got {r:?}"
    );
    assert!(!b.c.burned());
    assert_eq!(b.c.head(), head, "a refusal changes nothing");

    // Both words: the copy burns.
    b.press(
        Op::Detach,
        &[Who::Buyer, Who::FormerClient],
        Evidence::None,
        Page::None,
    )
    .expect("the detachment");
    assert!(b.c.burned());
    assert_eq!(b.c.head(), None, "no journal is left in this copy");
    let r = b.press(
        Op::ExportPoint,
        &[Who::Buyer],
        Evidence::Point { number: 1 },
        Page::None,
    );
    assert!(matches!(r, Err(Stopped::Burned)), "got {r:?}");

    // Burned for good: the stored copy opens burned and answers no button.
    let bytes = b.c.seal_to_bytes(&KEY, &mut b.rng).expect("stored");
    b.c = Container::open_sealed(&bytes, &b.c.template_id(), &KEY).expect("opens");
    assert!(b.c.burned());
    assert_eq!(b.c.head(), None);
    let r = b.press(
        Op::ExportPoint,
        &[Who::Buyer],
        Evidence::Point { number: 1 },
        Page::None,
    );
    assert!(matches!(r, Err(Stopped::Burned)), "got {r:?}");
}

/// Opens a `bare` file with `key`, lets `change` edit its state, seals it
/// back the way the store does — what somebody holding the layer key could
/// write. The container must refuse what it would never have written.
fn tampered(
    bytes: &[u8],
    template: &ksg_core_v2::crypto::hash::Hash,
    key: &[u8; 32],
    change: impl FnOnce(&mut serde_json::Value),
) -> Vec<u8> {
    use ksg_container_v2::{ChaCha20Poly1305Aead, Deflate, Packer};
    assert_eq!(outer_sig_len(bytes), 0, "the bare envelope is unsigned");
    let body = &bytes[STORE_MAGIC.len()..bytes.len() - 4];
    let (nonce, sealed) = body.split_at(12);
    let aad = [STORE_MAGIC, template.as_bytes()].concat();
    let packer = Packer::new(
        ChaCha20Poly1305Aead,
        Deflate {
            limit: ksg_container_v2::store::MAX_STATE,
        },
        ksg_container_v2::store::STORE_SIZE,
    );
    let plain = packer.open(sealed, key, nonce, &aad).expect("opened state");
    let mut state: serde_json::Value = serde_json::from_slice(&plain).expect("JSON state");
    change(&mut state);
    let plain = serde_json::to_vec(&state).expect("JSON");
    let noise = vec![0u8; packer.noise_needed(&plain)];
    let sealed = packer
        .seal(&plain, &noise, key, nonce, &aad)
        .expect("sealed");
    [STORE_MAGIC, nonce, &sealed, &0u32.to_be_bytes()].concat()
}

#[test]
fn a_stored_copy_keeps_the_former_half_of_the_former_client_only() {
    // 13.10, variant A: the half kept inside is the former client's — the
    // key in the former client's seat. A file whose kept half is another key
    // (here: the leader's agent's) is refused at opening.
    const KEY: [u8; 32] = [11u8; 32];
    let leader = coupled(Class::Heavy, 9600);
    let mut b = coupled(Class::Bare, 9610);
    attach(&mut b, *leader.c.id()).expect("the attachment");
    let template = b.c.template_id();
    let bytes = b.c.seal_to_bytes(&KEY, &mut b.rng).expect("stored");
    Container::open_sealed(&bytes, &template, &KEY).expect("the honest file opens");
    let swapped = tampered(&bytes, &template, &KEY, |s| {
        let client = s["client_half"].clone();
        assert!(!s["former_half"].is_null(), "the former half is stored");
        s["former_half"] = client;
    });
    let r = Container::open_sealed(&swapped, &template, &KEY);
    assert!(
        matches!(&r, Err(e) if e.to_string().contains("former client's half")),
        "got {:?}",
        r.err()
    );
    // A burned copy holding a journal again is refused as well.
    let burned = tampered(&bytes, &template, &KEY, |s| {
        s["burned"] = serde_json::Value::Bool(true);
    });
    assert!(Container::open_sealed(&burned, &template, &KEY).is_err());
}

#[test]
fn the_arriving_owner_under_a_pinned_identifier_is_refused() {
    // E-9 in `bare` (13.10): the container pins the first key it sees under an
    // identifier. An arriving owner under the identifier of a key it already
    // pinned would take a seat checked against that other key — refused, and
    // nothing changes.
    let mut b = coupled(Class::Bare, 9700);
    let pinned = b.parties.owner.public().kid;
    let impostor = ksg_core_v2::crypto::sign::Ed25519Signer::from_seed(pinned, [42u8; 32]).public();
    let head = b.c.head();
    let roster = b.c.roster().clone();
    let r = b.press(
        Op::TransferOwnership,
        &[Who::Owner, Who::Buyer],
        Evidence::NewOwner(impostor),
        Page::None,
    );
    assert!(matches!(r, Err(Stopped::WrongEvidence { .. })), "got {r:?}");
    assert_eq!(b.c.head(), head, "a refusal changes nothing");
    assert_eq!(b.c.roster(), &roster);
    assert!(!b.c.bare_attaching());
}

/// The transfer of a `bare` outside an attachment (owner's decision 17.10,
/// PCh-14 of 30.09): the new owner arrives with the command and takes the owner's
/// seat; the page goes into the transfer zone, and the `bare` is not taken
/// for one being attached — work goes on. Without a journal it is refused.
#[test]
fn bare_transfers_to_a_new_owner_and_keeps_working() {
    let mut early = Stand::new(Class::Bare, 8600);
    let buyer = early.parties.buyer.public();
    assert!(
        matches!(
            early.press(
                Op::TransferOwnership,
                &[Who::Owner, Who::Buyer],
                Evidence::Transfer(buyer),
                Page::None,
            ),
            Err(Stopped::WrongEvidence { .. })
        ),
        "a bare's transfer is written on a page: no journal, no transfer"
    );

    let mut s = coupled(Class::Bare, 8601);
    record_work(&mut s, "backend done");
    let new_owner = s.parties.buyer.public();
    s.press(
        Op::TransferOwnership,
        &[Who::Owner, Who::Buyer],
        Evidence::Transfer(new_owner.clone()),
        Page::None,
    )
    .expect("the transfer goes in");
    assert_eq!(s.c.roster().holder(Role::Owner), Some(&new_owner));
    assert!(!s.c.bare_attaching(), "a transfer is not an attachment");
    assert!(!s.c.bare_attached());
    record_work(&mut s, "frontend begins");
}

/// The owner's read key of the issuance label (owner's decision 17.10): set
/// by the owner alone, answered by the container, forgotten at an owner's
/// change — the new owner sets its own.
#[test]
fn the_owners_read_key_is_set_by_the_owner_and_forgotten_at_a_transfer() {
    let mut s = coupled(Class::Bare, 8700);
    let read = [7u8; 32];
    let msg = s.c.owner_read_message(&read);
    let by_client = s.parties.buyer.sign(&msg);
    assert!(
        s.c.set_owner_read_key(read, by_client).is_err(),
        "not the owner's"
    );
    assert_eq!(s.c.owner_read_key(), None);
    let by_owner = s.parties.owner.sign(&msg);
    s.c.set_owner_read_key(read, by_owner).expect("the owner's");
    assert_eq!(s.c.owner_read_key(), Some(read));

    let new_owner = s.parties.buyer.public();
    s.press(
        Op::TransferOwnership,
        &[Who::Owner, Who::Buyer],
        Evidence::Transfer(new_owner),
        Page::None,
    )
    .expect("the transfer goes in");
    assert_eq!(
        s.c.owner_read_key(),
        None,
        "the former owner's key is forgotten"
    );
}
