//! Cancellation is derived, not declared. §12; plan item P-04.
//!
//! `[decision]` 11.09: two buckets are reported — used and submitted, used and not
//! submitted — and `cancelled` is the difference between the packet and both.
//! Automatic cancellation is a **function of the container**, not a statement
//! by the holder.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use ksg_core_v2::doc::ranges::complement;
use ksg_core_v2::doc::{BlockClosure, Range, Serial, Timestamp};

fn r(from: u64, to: u64) -> Range {
    Range {
        from: Serial(from),
        to: Serial(to),
    }
}
fn block() -> Range {
    r(1000, 1999)
}
fn ts() -> Timestamp {
    Timestamp::parse("2026-11-25T10:00:00.000Z").expect("timestamp")
}

fn draft(used_submitted: Vec<Range>, used_not_submitted: Vec<Range>) -> BlockClosure {
    BlockClosure::draft(
        "ksg:em:000001".into(),
        block(),
        used_submitted,
        used_not_submitted,
        ts(),
    )
}

#[test]
fn what_was_not_used_is_cancelled() {
    let c = draft(vec![r(1000, 1099)], vec![r(1100, 1199)]);
    assert_eq!(c.cancelled, vec![r(1200, 1999)]);
}

#[test]
fn cancellation_fills_every_hole_including_the_ones_in_the_middle() {
    // The holes are what make this worth computing: a holder writing the set by
    // hand gets the ends right and loses a gap in the middle.
    let c = draft(vec![r(1000, 1099), r(1500, 1599)], vec![r(1300, 1399)]);
    assert_eq!(
        c.cancelled,
        vec![r(1100, 1299), r(1400, 1499), r(1600, 1999)]
    );
}

#[test]
fn a_wholly_unused_packet_is_wholly_cancelled() {
    // The case P-04 is really about: the term ran out and nothing was ever
    // activated. Every serial gets status 10, and no one had to say so.
    let c = draft(vec![], vec![]);
    assert_eq!(c.cancelled, vec![block()]);
}

#[test]
fn a_wholly_used_packet_cancels_nothing() {
    let c = draft(vec![block()], vec![]);
    assert!(c.cancelled.is_empty());
}

#[test]
fn the_three_sets_always_partition_the_packet() {
    // The property the derivation exists for: a closure built this way cannot
    // be built wrong. Previously the partition check caught a bad `cancelled`
    // afterwards; now there is nothing to catch.
    for (subm, not_subm) in [
        (vec![], vec![]),
        (vec![r(1000, 1000)], vec![]),
        (vec![r(1000, 1499)], vec![r(1500, 1999)]),
        (vec![r(1001, 1099), r(1700, 1799)], vec![r(1300, 1300)]),
        (vec![block()], vec![]),
    ] {
        let c = draft(subm, not_subm);
        let total: u64 = c
            .used_submitted
            .iter()
            .chain(&c.used_not_submitted)
            .chain(&c.cancelled)
            .map(Range::len)
            .sum();
        assert_eq!(total, block().len(), "the sets do not cover the packet");
    }
}

#[test]
fn adjacent_and_overlapping_reports_still_leave_the_right_remainder() {
    // Ranges that touch cover the join with no hole, and a range repeated in
    // both buckets is still used once. Neither may invent a cancelled serial.
    let touching = complement(block(), &[&[r(1000, 1499)], &[r(1500, 1599)]]);
    assert_eq!(touching, vec![r(1600, 1999)]);

    let repeated = complement(block(), &[&[r(1000, 1099)], &[r(1050, 1199)]]);
    assert_eq!(repeated, vec![r(1200, 1999)]);
}
