//! P-04 of the fix plan: status 10 and filling `cancelled` — automatically,
//! not by the holder's declaration.
//!
//! The tests pin both halves of the link, never before checked whole: a packet's
//! term ran out → the container gets status 10, and unused numbers land in
//! `cancelled` as the **difference**, not as what the holder wrote about itself.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use ksg_core_v2::doc::{BlockClosure, Range, Serial, Timestamp};
use ksg_core_v2::error::Invalid;
use ksg_core_v2::status::{status_after, transition, Blocked, Event, Outcome, Status};

fn r(from: u64, to: u64) -> Range {
    Range {
        from: Serial(from),
        to: Serial(to),
    }
}
fn ts(s: &str) -> Timestamp {
    Timestamp::parse(s).expect("timestamp")
}

// --- first half: the status arrives by itself ------------------------------------

#[test]
fn a_packet_whose_term_ran_out_moves_to_ten_by_itself() {
    // T-15: nobody "declares" death by term — it happens.
    for from in [Status::Packeted, Status::BuyerKeyed, Status::SubAgentKeyed] {
        assert_eq!(
            transition(from, Blocked::No, Event::PacketTermExpired),
            Outcome::Moves(Status::Expired),
            "from {from:?} expiry must lead to 10"
        );
    }
}

#[test]
fn ten_and_twenty_are_different_deaths() {
    // 10 means no attempt ever; 20 means attempted, but late. Different
    // errors and different statuses: confusing them lies in the audit report.
    assert_eq!(status_after(&Invalid::Expired), Some(Status::Expired));
    assert_eq!(
        status_after(&Invalid::ActivationAfterExpiry),
        Some(Status::ActivatedTooLate)
    );
    assert_ne!(Status::Expired, Status::ActivatedTooLate);
}

// --- second half: cancelled is derived, not declared --------------------

#[test]
fn cancellation_is_the_difference_and_not_a_statement() {
    // Packet 1..100, used 1..10 and 50..59. The rest is cancelled,
    // and the holder is not asked about it.
    let closure = BlockClosure::draft(
        "ksg:em:000001".into(),
        r(1, 100),
        vec![r(1, 10)],
        vec![r(50, 59)],
        ts("2026-11-25T10:00:00.000Z"),
    );

    let total: u64 = closure.cancelled.iter().map(Range::len).sum();
    assert_eq!(total, 100 - 10 - 10, "everything unused is cancelled");

    // And gapless cover: the three sets add up to exactly the packet.
    let covered: u64 = closure
        .used_submitted
        .iter()
        .chain(closure.used_not_submitted.iter())
        .chain(closure.cancelled.iter())
        .map(Range::len)
        .sum();
    assert_eq!(covered, 100, "the partition must cover the whole packet");
}

#[test]
fn a_packet_nobody_touched_is_cancelled_whole() {
    // The edge case the rule was written for: the holder bought and never
    // started. The audit report still adds up.
    let closure = BlockClosure::draft(
        "ksg:em:000001".into(),
        r(1, 1000),
        vec![],
        vec![],
        ts("2026-11-25T10:00:00.000Z"),
    );
    assert_eq!(closure.cancelled, vec![r(1, 1000)]);
}
