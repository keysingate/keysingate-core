//! The field layout. KS-8 part C, A-6, F-4.
//!
//! The property everything here serves: **the size does not say how full the
//! container is.**

use ksg_container_v2::{Fields, Layout, LayoutError, Slot, Zone, CUSTOM_SLOTS, JOURNAL_PAGES};
use ksg_core_v2::status::Status;

// --- the size is a constant --------------------------------------------------

#[test]
fn the_size_does_not_change_as_fields_are_written() {
    // A container one page into its journal and one at its thousandth are the
    // same size. Without that, the size is a side channel about the work — and
    // by KS-8 F-7 the issuer is meant to be the blindest party there is.
    let empty = Fields::new();
    let before = empty.slots();

    let mut filled = Fields::new();
    filled
        .write(Zone::Release, 0, Status::Printed, b"release id".to_vec())
        .expect("the release layer opens at 0");
    for i in 0..CUSTOM_SLOTS {
        filled
            .write(Zone::Custom, i, Status::Initiated, vec![7u8; 32])
            .expect("a custom slot");
    }
    assert_eq!(filled.slots(), before, "writing changed the size");
}

#[test]
fn every_zone_holds_its_slots_from_birth() {
    // "The journal exists from birth under noise" (A-6) and "a hundred places,
    // noise until filled" (C-5), generalized: no zone grows.
    let f = Fields::new();
    assert_eq!(f.slots(), Layout::slots());
    assert_eq!(Zone::Custom.slots(), CUSTOM_SLOTS);
    assert_eq!(Zone::Journal.slots(), JOURNAL_PAGES);
    for &z in Zone::all() {
        assert!(z.slots() > 0, "{z:?} holds nothing");
    }
}

// --- a field is written once -------------------------------------------------

#[test]
fn a_slot_is_written_once() {
    // A container whose fields could be rewritten makes every layer under them a
    // claim about the present rather than a record of the past.
    let mut f = Fields::new();
    f.write(Zone::Release, 0, Status::Printed, b"first".to_vec())
        .expect("first write");
    assert_eq!(
        f.write(Zone::Release, 0, Status::Printed, b"second".to_vec())
            .unwrap_err(),
        LayoutError::AlreadyWritten
    );
}

#[test]
fn a_slot_that_is_not_there_is_named() {
    let mut f = Fields::new();
    assert_eq!(
        f.write(Zone::Identity, 9, Status::InWork, b"x".to_vec())
            .unwrap_err(),
        LayoutError::NoSuchSlot {
            zone: Zone::Identity,
            slots: 2,
            asked: 9
        }
    );
}

// --- stages ------------------------------------------------------------------

#[test]
fn a_zone_cannot_be_written_before_it_opens() {
    // The release layer is what the issuer signs. A container whose release
    // layer could be filled later is one whose earliest layer proves nothing.
    let mut f = Fields::new();
    assert_eq!(
        f.write(Zone::Packet, 0, Status::Printed, b"early".to_vec())
            .unwrap_err(),
        LayoutError::TooEarly {
            zone: Zone::Packet,
            opens_at: 1
        }
    );
    f.write(Zone::Packet, 0, Status::Packeted, b"in time".to_vec())
        .expect("at 1 it opens");
}

#[test]
fn the_zones_open_in_the_order_the_container_is_built() {
    // C-1 at printing, C-2 at the sale, C-3 from the buyer's key onward, C-4 and
    // C-5 once a container exists.
    assert_eq!(Zone::Release.opens_at(), Status::Printed);
    assert_eq!(Zone::Packet.opens_at(), Status::Packeted);
    assert_eq!(Zone::Chain.opens_at(), Status::BuyerKeyed);
    assert_eq!(Zone::Identity.opens_at(), Status::Initiated);
    assert_eq!(Zone::Custom.opens_at(), Status::Initiated);

    // And the status section is open from the very start, because status 0 is
    // itself something to record.
    assert_eq!(Zone::Status.opens_at(), Status::Printed);
}

#[test]
fn finalization_and_death_close_every_zone() {
    // O-01 again, from the other side: after finalization there are no
    // additions, ever. One rule, and the zones do not each keep their own copy
    // of it — two places for one rule disagree.
    for &z in Zone::all() {
        assert!(
            !Layout::may_write(z, Status::Finalized),
            "{z:?} took an addition after finalization"
        );
        for s in Status::all().iter().copied().filter(|s| s.is_terminal()) {
            assert!(
                !Layout::may_write(z, s),
                "{z:?} took an addition at {}",
                s.number()
            );
        }
    }

    let mut f = Fields::new();
    assert_eq!(
        f.write(Zone::Custom, 0, Status::Finalized, b"x".to_vec())
            .unwrap_err(),
        LayoutError::Closed(6)
    );
    assert_eq!(
        f.write(Zone::Custom, 0, Status::Exported, b"x".to_vec())
            .unwrap_err(),
        LayoutError::Closed(7)
    );
}

#[test]
fn an_open_journal_still_takes_additions() {
    // Status 12 makes the pages readable; it does not close the container. The
    // two are different things and this is where they could be confused.
    for &z in Zone::all() {
        assert!(Layout::may_write(z, Status::Opened), "{z:?} at 12");
    }
}

// --- noise -------------------------------------------------------------------

#[test]
fn a_fresh_container_is_noise_throughout() {
    let f = Fields::new();
    assert_eq!(f.slots(), Layout::slots());
    // And what this test cannot show, said where it will be read: that noise is
    // indistinguishable from written bytes to somebody looking at stored data is
    // the packing layer's job (pack.rs, noise.rs), which is deliberately not
    // implemented. Here the two states are distinguishable, and inside an
    // implementation that already has the container open they may be.
    let mut one = Fields::new();
    one.write(Zone::Release, 0, Status::Printed, b"x".to_vec())
        .unwrap();
    assert_eq!(one.slots(), f.slots(), "but the size tells nothing apart");
}

#[test]
fn a_slot_reports_nothing_about_its_neighbours() {
    // There is no count of written slots, no "is this zone complete", no
    // iteration. A container is not read; the layout is not a way in.
    let mut s = Slot::Noise;
    s.write(b"x".to_vec()).expect("write");
    assert!(matches!(s, Slot::Filled(_)));
}
