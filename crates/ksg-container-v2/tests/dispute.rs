//! The dispute: a copy of the claim, a term from a jurisdiction, four ways out,
//! and what silence costs. `[decision]` 10.09 and 12.09.

use ksg_container_v2::dispute::{DisputeError, Filing, Settlement, PRESCRIPTION_MS};
use ksg_container_v2::{Command, Operation, Refusal, Refused, Role, Roster, Strength};
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{Ed25519Signer, KeySet, Profile, SignatureSet};
use ksg_core_v2::doc::Uri;
use ksg_core_v2::status::{Blocked, Event, Outcome, Status, StatusHistory};

/// A history driven up to a served dispute, the way a container gets there.
fn disputed() -> StatusHistory {
    let mut h = StatusHistory::new();
    for e in [
        Event::ApplyPacket,
        Event::ApplyBuyerKey,
        Event::Initiate,
        Event::OpenJournal,
        Event::ServeDispute,
    ] {
        h.apply(e).expect("the ordinary road to a dispute");
    }
    assert_eq!(h.current(), Status::Disputed);
    h
}

fn uri(s: &str) -> Uri {
    Uri::parse(s).expect("uri")
}
fn client() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:key:zAgent#a1"), [42u8; 32])
}
fn owner() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:key:zOwner#o1"), [44u8; 32])
}
fn claimant() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:key:zClaim#k1"), [15u8; 32])
}
fn arbiter() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:key:zArbA#j1"), [70u8; 32])
}
fn p() -> Profile {
    Profile::default()
}
fn keys() -> KeySet {
    [
        client().public(),
        owner().public(),
        claimant().public(),
        arbiter().public(),
    ]
    .into_iter()
    .collect()
}
fn roster() -> Roster {
    Roster::of([
        (client().public(), Role::Client),
        (owner().public(), Role::Owner),
        (claimant().public(), Role::Claimant),
        (arbiter().public(), Role::Arbiter),
    ])
}

const DAY: u64 = 24 * 60 * 60 * 1000;

fn filing() -> Filing {
    Filing {
        claim: Hash::sha256(b"the copy of the claim, as filed"),
        jurisdiction: "UA".into(),
        filed_ms: 100 * DAY,
        hearing_ms: 130 * DAY,
        // (filing → decision) + (time to appeal), taken from the jurisdiction.
        deadline_ms: 100 * DAY + 210 * DAY,
    }
}

// --- the copy of the claim ---------------------------------------------------

#[test]
fn a_proper_filing_stands() {
    filing().validate().expect("a dated copy and a term");
}

#[test]
fn without_a_copy_of_the_claim_a_thirty_is_nothing() {
    // `[decision]` 12.09, the rule this module exists for. A statement that somebody is
    // contesting something is cheap; a copy of the claim is dated, names the
    // court, and the court has set a hearing.
    let mut f = filing();
    f.claim = Hash::sha256(b"");
    assert_eq!(f.validate().unwrap_err(), DisputeError::NoClaim);
}

#[test]
fn a_term_with_no_jurisdiction_behind_it_is_refused() {
    // The term is empirical — it comes from somewhere. A number with no source
    // cannot be checked by anyone, and a number nobody can check is a number
    // whoever writes it chooses freely.
    let mut f = filing();
    f.jurisdiction = "  ".into();
    assert_eq!(f.validate().unwrap_err(), DisputeError::NoJurisdiction);
}

#[test]
fn the_three_moments_must_run_forward() {
    // A deadline before the hearing is not the term of any jurisdiction: it is a
    // typo or a lie, and either way it does not stand.
    let mut f = filing();
    f.deadline_ms = f.hearing_ms - 1;
    assert_eq!(f.validate().unwrap_err(), DisputeError::OutOfOrder);

    let mut f = filing();
    f.hearing_ms = f.filed_ms - 1;
    assert_eq!(f.validate().unwrap_err(), DisputeError::OutOfOrder);

    // Heard on the day of filing is allowed — some jurisdictions do that.
    let mut f = filing();
    f.hearing_ms = f.filed_ms;
    f.validate().expect("filed and heard the same day");
}

// --- the clock ---------------------------------------------------------------

#[test]
fn the_deadline_cannot_be_declared_passed_early() {
    // Without this the block would be available to anyone who pressed early,
    // and a block is what silence is supposed to cost — not haste.
    let f = filing();
    assert_eq!(
        f.deadline_passed(f.deadline_ms - 1).unwrap_err(),
        DisputeError::TooEarly {
            at: f.deadline_ms - 1,
            deadline: f.deadline_ms
        }
    );
    assert_eq!(
        f.deadline_passed(f.deadline_ms).expect("at the deadline"),
        Event::ReviewDeadlinePassed
    );
}

#[test]
fn silence_blocks_the_container_and_only_a_decision_unblocks_it() {
    // `[decision]` 10.09: "the mechanism is a timer, not goodwill". The block falls on
    // whoever was silent, and nothing but 31 or 32 lifts it.
    let mut h = disputed();
    assert_eq!(
        h.apply(Event::ReviewDeadlinePassed).expect("blocks"),
        Outcome::Blocks
    );
    assert_eq!(h.blocked(), Blocked::AwaitingDecision);
    h.apply(Event::DisputeUnproven).expect("a decision");
    assert_eq!(h.blocked(), Blocked::No);
}

#[test]
fn twelve_years_blocked_and_the_container_dies_of_prescription() {
    // `[decision]` 12.09. Not because anything was decided — because nothing was, for
    // long enough that nothing ever will be.
    let f = filing();
    assert_eq!(f.prescribed_at(), f.deadline_ms + PRESCRIPTION_MS);
    assert_eq!(
        f.prescribed(f.prescribed_at() - 1).unwrap_err(),
        DisputeError::NotPrescribed
    );
    assert_eq!(
        f.prescribed(f.prescribed_at()).expect("twelve years"),
        Event::PrescriptionPassed
    );

    let mut h = disputed();
    h.apply(Event::ReviewDeadlinePassed).expect("blocks");
    h.apply(Event::PrescriptionPassed).expect("prescription");
    assert_eq!(h.current(), Status::Prescribed);
    assert!(Status::Prescribed.is_terminal(), "there is no way back");
}

#[test]
fn the_dead_status_of_prescription_is_not_the_dead_of_a_lost_key() {
    // A status records WHY. Here the key may be intact and the container in
    // hand: what ran out is the time in which anyone could still decide.
    assert_ne!(Status::Prescribed, Status::KeyLost);
    assert_ne!(Status::Prescribed, Status::Lost);
    assert_eq!(Status::Prescribed.number(), 21);
}

// --- four ways out -----------------------------------------------------------

#[test]
fn four_statuses_keep_the_container_out_of_the_block() {
    // `[decision]` 12.09 added the fourth: the two sides settling.
    for s in [
        Status::DisputeProven,
        Status::DisputeUnproven,
        Status::Appealed,
        Status::Settled,
    ] {
        assert!(Filing::resolves(s), "{s:?} must resolve a dispute");
    }
    for s in [Status::InWork, Status::Disputed, Status::Opened] {
        assert!(!Filing::resolves(s), "{s:?} does not resolve anything");
    }
}

// --- the settlement ----------------------------------------------------------

fn command(op: Operation, signers: &[&Ed25519Signer]) -> Command {
    const BODY: &[u8] = b"what is being asked for";
    Command {
        op,
        payload: b"opaque".to_vec(),
        signatures: SignatureSet::new(signers.iter().map(|s| s.sign(BODY)).collect()),
        signed_bytes: BODY.to_vec(),
    }
}

fn press(op: Operation, signers: &[&Ed25519Signer], at: Status) -> Result<Strength, Refused> {
    command(op, signers).press(op.button(), at, Blocked::No, &roster(), &keys(), &p())
}

#[test]
fn the_two_sides_settle_between_themselves_and_no_arbiter_signs() {
    // "A handshake" is the parties' own act. Requiring a third would turn
    // it into a small trial, which is the thing they are settling to avoid.
    press(
        Operation::Settle,
        &[&claimant(), &owner()],
        Status::Disputed,
    )
    .expect("the claimant and the owner");
    press(
        Operation::Settle,
        &[&claimant(), &owner()],
        Status::Appealed,
    )
    .expect("from an appeal too");
}

#[test]
fn a_settlement_without_the_claimant_is_not_one() {
    // The claimant is the other side. An owner settling with the client would be
    // settling with themselves.
    assert!(matches!(
        press(Operation::Settle, &[&client(), &owner()], Status::Disputed),
        Err(Refused {
            reason: Refusal::RoleMissing { .. },
            ..
        })
    ));
    assert!(matches!(
        press(Operation::Settle, &[&arbiter(), &owner()], Status::Disputed),
        Err(Refused {
            reason: Refusal::RoleMissing { .. },
            ..
        })
    ));
}

#[test]
fn a_settlement_does_not_reopen_a_decided_dispute() {
    // Available from 30 and 34 and from neither 31 nor 32: a settlement ends a
    // dispute, it does not undo a decision.
    for decided in [Status::DisputeProven, Status::DisputeUnproven] {
        assert!(matches!(
            press(Operation::Settle, &[&claimant(), &owner()], decided),
            Err(Refused {
                reason: Refusal::WrongStatus { .. },
                ..
            })
        ));
    }
}

#[test]
fn the_container_records_that_they_settled_and_not_what_they_agreed() {
    // `[decision]` 12.09 — the rights may stay, pass, become shared, be anything they
    // wrote down. It is their private business, and the container holds the
    // digest so either of them can prove it later while nobody else learns it.
    let s = Settlement {
        terms: Hash::sha256(b"rights shared 50/50, royalties quarterly"),
        at_ms: 200 * DAY,
    };
    let subject = s.subject(&Hash::sha256(b"container"), &filing().claim);
    let printed = format!("{s:?}");
    assert!(
        !printed.contains("royalties"),
        "the terms must not be in the record"
    );
    // The digest is stable, so a term shown later either matches or does not.
    assert_eq!(
        subject,
        s.subject(&Hash::sha256(b"container"), &filing().claim)
    );
}

#[test]
fn a_settlement_in_time_is_told_apart_from_one_after_the_block() {
    // Both are settlements — it is one of the four ways out either way — but a
    // reader is entitled to see which happened.
    let f = filing();
    let early = Settlement {
        terms: Hash::sha256(b"terms"),
        at_ms: f.deadline_ms - 1,
    };
    let late = Settlement {
        terms: Hash::sha256(b"terms"),
        at_ms: f.deadline_ms + 1,
    };
    assert!(early.in_time(&f));
    assert!(!late.in_time(&f));
}

#[test]
fn work_goes_on_under_a_settlement() {
    // 35 is a working status: the dispute is over, and nothing about it stopped
    // the work in the first place.
    assert!(Status::Settled.is_working());
    let mut h = disputed();
    h.apply(Event::Settle).expect("settled");
    assert_eq!(h.current(), Status::Settled);
    assert_eq!(h.apply(Event::RecordWork).expect("work"), Outcome::Stays);
}
