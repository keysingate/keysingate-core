//! The status transition table. KS-7 §7.2-bis, §7.2-ter, §7.2-quater.
//!
//! The point these tests hold down is not that the listed transitions work — it
//! is that **no pair is left without an outcome** (§7.2: "an empty cell MUST NOT
//! exist"), and that what cannot be revoked is the record rather than the state.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use ksg_core_v2::error::Invalid;
use ksg_core_v2::status::{may_sign, transition, Blocked, Event, Outcome, Status, StatusHistory};

/// Every event, for the exhaustiveness sweep. Kept beside `Status::all()` for
/// the same reason: a table checked by eye is a table with a hole in it.
const EVENTS: &[Event] = &[
    Event::PrintRelease,
    Event::ApplyPacket,
    Event::ApplyBuyerKey,
    Event::ApplySubAgentKey,
    Event::Initiate,
    Event::InitiateTooLate,
    Event::RecordWork,
    Event::RecordArtifactOrRights,
    Event::TransferOwnership,
    Event::RaiseClass,
    Event::FullExport,
    Event::Finalize,
    Event::DeclareKeyLost,
    Event::DeclareContainerLost,
    Event::ServeDispute,
    Event::DisputeProven,
    Event::DisputeUnproven,
    Event::Appeal,
    Event::AppealWon,
    Event::AppealLost,
    Event::ExtendReview,
    Event::ReviewDeadlinePassed,
    Event::PacketTermExpired,
    Event::Succeed,
    Event::FreezeOnOwnerApplication,
    Event::OpenJournal,
];

// --- §7.2: no empty cells ----------------------------------------------------

#[test]
fn every_pair_has_a_definite_outcome() {
    // §7.2: "for EVERY status × event pair there is either a transition or an
    // explicit refusal. An empty cell MUST NOT exist." Checked by enumeration,
    // machine-wise (§14) — the whole reason the table is flat and closed by a
    // default rather than drawn as a matrix.
    let mut pairs = 0;
    for &s in Status::all() {
        for &e in EVENTS {
            for blocked in [Blocked::No, Blocked::AwaitingDecision] {
                // The call itself is total: it returns an Outcome, never panics
                // and never falls through. What is asserted is that exhausting
                // the space finds no combination the table cannot answer.
                let _: Outcome = transition(s, blocked, e);
                pairs += 1;
            }
        }
    }
    assert_eq!(pairs, Status::all().len() * EVENTS.len() * 2);
}

#[test]
fn a_pair_outside_the_table_is_refused_not_ignored() {
    // §7.2-ter, the closing rule. "Raise the class of a container that is not
    // born" is in no row, and the answer must be a refusal rather than silence.
    assert_eq!(
        transition(Status::Printed, Blocked::No, Event::RaiseClass),
        Outcome::Refused("no such transition")
    );
}

// --- the path of a life ------------------------------------------------------

#[test]
fn the_ordinary_path_runs_from_printing_to_finalization() {
    let mut h = StatusHistory::new();
    assert_eq!(h.current(), Status::Printed);
    for (event, expected) in [
        (Event::ApplyPacket, Status::Packeted),
        (Event::ApplyBuyerKey, Status::BuyerKeyed),
        (Event::Initiate, Status::Initiated),
        (Event::OpenJournal, Status::InWork),
    ] {
        h.apply(event).expect("the step is in the table");
        assert_eq!(h.current(), expected);
    }
    // T-08: further work records keep it in work without adding a layer.
    let before = h.layers().len();
    assert_eq!(h.apply(Event::RecordWork).unwrap(), Outcome::Stays);
    assert_eq!(
        h.layers().len(),
        before,
        "a status that stays adds no layer"
    );

    h.apply(Event::Finalize).expect("T-12");
    assert_eq!(h.current(), Status::Finalized);
}

#[test]
fn work_is_refused_before_birth() {
    // O-04. The container does not exist yet, so there is nothing to record in.
    for s in [
        Status::Printed,
        Status::Packeted,
        Status::BuyerKeyed,
        Status::SubAgentKeyed,
    ] {
        assert_eq!(
            transition(s, Blocked::No, Event::RecordWork),
            Outcome::Refused("the container is not born yet"),
            "status {}",
            s.number()
        );
    }
}

#[test]
fn initiation_happens_once() {
    // O-06.
    let mut h = StatusHistory::new();
    h.apply(Event::ApplyPacket).unwrap();
    h.apply(Event::ApplyBuyerKey).unwrap();
    h.apply(Event::Initiate).unwrap();
    assert_eq!(
        h.apply(Event::Initiate).unwrap_err(),
        Invalid::StatusRefused("initiation happens once")
    );
}

#[test]
fn finalization_takes_no_additions_but_death_is_not_an_addition() {
    // O-01 against T-30: finalization forbids additions to the CONTENT, and a
    // declaration of death is not one. Both rows in one test because the pair
    // is the point — either alone reads as a contradiction.
    let refusal = Outcome::Refused("after finalization the container takes no additions");
    for e in [
        Event::RecordWork,
        Event::RecordArtifactOrRights,
        Event::RaiseClass,
    ] {
        assert_eq!(transition(Status::Finalized, Blocked::No, e), refusal);
    }
    assert_eq!(
        transition(Status::Finalized, Blocked::No, Event::DeclareKeyLost),
        Outcome::Moves(Status::KeyLost)
    );
    assert_eq!(
        transition(Status::Finalized, Blocked::No, Event::FullExport),
        Outcome::Moves(Status::Exported)
    );
}

// --- the two deaths and the two expiries -------------------------------------

#[test]
fn ten_and_twenty_are_told_apart_by_whether_it_was_attempted() {
    // T-15 against T-16, and the distinction the owner insisted on: 10 is "never
    // attempted", 20 is "attempted too late".
    assert_eq!(
        transition(Status::BuyerKeyed, Blocked::No, Event::PacketTermExpired),
        Outcome::Moves(Status::Expired)
    );
    assert_eq!(
        transition(Status::BuyerKeyed, Blocked::No, Event::InitiateTooLate),
        Outcome::Moves(Status::ActivatedTooLate)
    );
}

#[test]
fn terminal_statuses_take_nothing_at_all() {
    // O-02, O-03. Not "most events" — nothing.
    for s in Status::all().iter().copied().filter(|s| s.is_terminal()) {
        for &e in EVENTS {
            assert!(
                matches!(transition(s, Blocked::No, e), Outcome::Refused(_)),
                "status {} accepted {e:?}",
                s.number()
            );
        }
    }
}

#[test]
fn reserved_statuses_have_no_transitions_in_or_out() {
    // T-B1, closed 10.09: 8 is a blank, a place held open. 33 likewise.
    for s in [Status::Reserved8, Status::Reserved33] {
        assert!(s.is_reserved());
        for &e in EVENTS {
            assert!(matches!(transition(s, Blocked::No, e), Outcome::Refused(_)));
        }
        // And nothing leads into them: no row anywhere produces a reserved one.
        for &from in Status::all() {
            for &e in EVENTS {
                assert_ne!(transition(from, Blocked::No, e), Outcome::Moves(s));
            }
        }
    }
}

// --- the dispute -------------------------------------------------------------

#[test]
fn a_missed_review_deadline_blocks_and_only_a_decision_unblocks() {
    // T-23 and T-25, and the correction of T-B15: nothing inside the container
    // decides whether to record a defeat. The record of 30 carries its deadline,
    // and when it passes the container blocks. A timer, not good will.
    let mut h = disputed();
    assert_eq!(
        h.apply(Event::ReviewDeadlinePassed).unwrap(),
        Outcome::Blocks
    );
    assert_eq!(h.blocked(), Blocked::AwaitingDecision);

    // While blocked, everything else is refused — including moving the deadline.
    for e in [Event::ExtendReview, Event::TransferOwnership, Event::Appeal] {
        assert!(h.clone().apply(e).is_err(), "{e:?} passed while blocked");
    }

    h.apply(Event::DisputeUnproven).expect("T-25");
    assert_eq!(h.current(), Status::DisputeUnproven);
    assert_eq!(h.blocked(), Blocked::No, "a decision unblocks");
}

#[test]
fn the_deadline_can_be_moved_before_it_passes() {
    // T-24. Distinct from the test above on purpose: extending is allowed while
    // the deadline stands and refused once it has passed.
    let mut h = disputed();
    assert_eq!(h.apply(Event::ExtendReview).unwrap(), Outcome::Stays);
    assert_eq!(h.current(), Status::Disputed);
}

#[test]
fn thirty_one_survives_an_appeal_as_a_record_though_not_as_the_status() {
    // T-26, T-27 and §7.2-quater — the distinction the whole history type
    // exists for: "what is irreversible is the record, not the state".
    let mut h = disputed();
    h.apply(Event::DisputeProven).expect("T-19");
    h.apply(Event::Appeal).expect("T-26");
    assert_eq!(h.apply(Event::AppealWon).unwrap(), Outcome::Stays);

    assert_eq!(h.current(), Status::Appealed, "a won appeal stays 34");
    assert!(
        h.ever(Status::DisputeProven),
        "31 stays in the history forever, even once 34 overlays it"
    );
}

#[test]
fn a_lost_appeal_makes_thirty_one_current_again() {
    // T-28.
    let mut h = disputed();
    h.apply(Event::DisputeProven).unwrap();
    h.apply(Event::Appeal).unwrap();
    h.apply(Event::AppealLost).expect("T-28");
    assert_eq!(h.current(), Status::DisputeProven);
}

#[test]
fn the_container_is_alienable_throughout_a_dispute() {
    // O-07 and O-08, withdrawn 10.09. The dispute is over rights to the
    // ARTIFACT; the container is a thing and goes on being sold.
    for s in [
        Status::Disputed,
        Status::DisputeProven,
        Status::DisputeUnproven,
        Status::Appealed,
    ] {
        assert_eq!(
            transition(s, Blocked::No, Event::TransferOwnership),
            Outcome::Stays,
            "status {} refused a transfer",
            s.number()
        );
    }
}

#[test]
fn thirty_and_thirty_two_are_working_statuses() {
    // T-21, settled by the owner on 11.09. The reading is NOT "back to 5": the
    // status reads 32, and 30 and 32 are working statuses in their own right.
    //
    // The reason is what they record. The path 5 → 30 → 32 says that the rights
    // over the artifact were contested and the claim failed; a container that
    // fell back to 5 would have erased exactly that, keeping the work and losing
    // why it is worth anything.
    for s in [Status::Disputed, Status::DisputeUnproven] {
        assert!(
            s.is_working(),
            "status {} must be a working status",
            s.number()
        );
        for e in [
            Event::RecordWork,
            Event::RecordArtifactOrRights,
            Event::RaiseClass,
        ] {
            assert_eq!(
                transition(s, Blocked::No, e),
                Outcome::Stays,
                "status {} refused {e:?}",
                s.number()
            );
        }
    }
}

#[test]
fn a_disputed_container_keeps_its_number_while_it_works() {
    // The same rule seen from the history: working under 30 adds no layer, so
    // the number stays put and the record of the dispute is not diluted.
    let mut h = disputed();
    let layers = h.layers().len();
    h.apply(Event::RecordWork)
        .expect("T-21: 30 is a working status");
    assert_eq!(h.current(), Status::Disputed);
    assert_eq!(h.layers().len(), layers);

    h.apply(Event::DisputeUnproven).expect("T-20");
    h.apply(Event::RecordWork)
        .expect("T-21: 32 is a working status");
    assert_eq!(
        h.current(),
        Status::DisputeUnproven,
        "the status reads 32, not 5"
    );
    assert!(h.ever(Status::InWork), "5 stays in the history");
    assert!(h.ever(Status::Disputed), "so does 30");
}

#[test]
fn no_dispute_status_stops_the_work() {
    // Settled 11.09, 31 included — the case that reads wrong until the reason
    // is stated. The rights have passed to the claimant, but for the agent to
    // STOP there must be an explicit prohibition from that claimant; with none
    // served, the agent may lawfully go on by the norms of its jurisdiction.
    //
    // And once a prohibition is served, obeying it is the responsibility of the
    // client and the owner — never of the container, which knows nothing of
    // jurisdictions and must not pretend to.
    for s in [
        Status::Disputed,
        Status::DisputeProven,
        Status::DisputeUnproven,
        Status::Appealed,
    ] {
        assert!(s.is_working(), "status {} must work", s.number());
        assert_eq!(
            transition(s, Blocked::No, Event::RecordWork),
            Outcome::Stays,
            "status {} stopped the work",
            s.number()
        );
        // And the container goes on being alienable throughout (§7.2-octies).
        assert_eq!(
            transition(s, Blocked::No, Event::TransferOwnership),
            Outcome::Stays
        );
    }
}

#[test]
fn the_owner_freezes_through_the_issuer_not_through_the_container() {
    // E-23. The container refuses to police a prohibition, so the owner is not
    // left without a lever — it is just not a lever inside the container. The
    // issuer's signature together with the owner's key, and the container goes
    // to 6.
    for s in Status::all().iter().copied().filter(|s| s.is_working()) {
        assert_eq!(
            transition(s, Blocked::No, Event::FreezeOnOwnerApplication),
            Outcome::Moves(Status::Finalized),
            "status {} could not be frozen",
            s.number()
        );
    }
    // Freezing means nothing where there is no work: already frozen, or past it.
    assert!(matches!(
        transition(
            Status::Finalized,
            Blocked::No,
            Event::FreezeOnOwnerApplication
        ),
        Outcome::Refused(_)
    ));
    for s in Status::all().iter().copied().filter(|s| s.is_terminal()) {
        assert!(matches!(
            transition(s, Blocked::No, Event::FreezeOnOwnerApplication),
            Outcome::Refused(_)
        ));
    }
}

#[test]
fn a_frozen_container_still_takes_no_additions() {
    // The freeze is a real freeze, however it was reached: E-13, E-14 or E-23
    // all land on 6, and 6 means the same thing in each case (O-01).
    let mut h = disputed();
    h.apply(Event::DisputeProven).unwrap();
    h.apply(Event::RecordWork).expect("31 works");
    h.apply(Event::FreezeOnOwnerApplication).expect("E-23");
    assert_eq!(h.current(), Status::Finalized);
    assert!(h.apply(Event::RecordWork).is_err());
    assert!(h.ever(Status::DisputeProven), "31 stays in the history");
}

#[test]
fn succession_leaves_the_old_container_frozen_but_valid() {
    // T-B3, settled 11.09. Losing the OWNER's key is not a death: the new
    // container is coupled in front, carrying the client's current key, and this
    // one becomes the archive it pulls behind it.
    let mut h = StatusHistory::new();
    h.apply(Event::ApplyPacket).unwrap();
    h.apply(Event::ApplyBuyerKey).unwrap();
    h.apply(Event::Initiate).unwrap();
    h.apply(Event::OpenJournal).unwrap();

    h.apply(Event::Succeed).expect("T-B3");
    assert_eq!(h.current(), Status::Finalized);
    assert!(!h.current().is_terminal(), "the archive is valid, not dead");
    assert!(!h.current().is_working(), "no more work goes in here");

    // The property that makes it worth coupling at all: the client's key can
    // still pull everything out of it.
    assert_eq!(
        transition(Status::Finalized, Blocked::No, Event::FullExport),
        Outcome::Moves(Status::Exported),
        "a frozen archive must stay exportable"
    );
    // And it takes no additions, which is what "frozen" means (O-01).
    assert!(h.apply(Event::RecordWork).is_err());
}

#[test]
fn six_is_the_only_status_that_fits_succession() {
    // The derivation itself, as a test rather than as a comment: the old
    // container must be non-terminal, non-working, and still exportable.
    // Exactly one status satisfies all three, which is why T-B3 has an answer
    // at all instead of a preference.
    let fits: Vec<_> = Status::all()
        .iter()
        .copied()
        .filter(|s| {
            !s.is_terminal()
                && !s.is_working()
                && transition(*s, Blocked::No, Event::FullExport)
                    == Outcome::Moves(Status::Exported)
        })
        .collect();
    assert_eq!(fits, vec![Status::Finalized]);
}

#[test]
fn succession_works_from_an_already_frozen_container() {
    // T-33, settled 11.09. Coupling behind an archive is the same act as
    // coupling behind a container just frozen — the new one is working and
    // current and continues the work already fixed in the old one, rather than
    // starting from zero. The old one is at 6 already and does not move.
    assert_eq!(
        transition(Status::Finalized, Blocked::No, Event::Succeed),
        Outcome::Stays
    );
}

#[test]
fn succession_from_four_is_refused_because_four_cannot_work() {
    // T-34, settled 11.09. Status 4 is a finished asset — registrable, sellable,
    // resellable — and not valid for work, so there is no fixed work for a
    // successor to continue.
    assert!(!Status::Initiated.is_working());
    assert_eq!(
        transition(Status::Initiated, Blocked::No, Event::Succeed),
        Outcome::Refused("status 4 is not valid for work: there is no fixed work to continue")
    );
}

#[test]
fn every_working_status_can_be_succeeded_and_no_dead_one_can() {
    // The shape of the rule rather than its rows: succession is available
    // exactly where there is work to freeze, plus the already-frozen 6.
    for &s in Status::all() {
        let allowed = !matches!(
            transition(s, Blocked::No, Event::Succeed),
            Outcome::Refused(_)
        );
        assert_eq!(
            allowed,
            s.is_working() || s == Status::Finalized,
            "status {} disagrees about succession",
            s.number()
        );
    }
}

// --- helper ------------------------------------------------------------------

/// A container in work with a dispute served on it.
fn disputed() -> StatusHistory {
    let mut h = StatusHistory::new();
    h.apply(Event::ApplyPacket).unwrap();
    h.apply(Event::ApplyBuyerKey).unwrap();
    h.apply(Event::Initiate).unwrap();
    h.apply(Event::OpenJournal).unwrap();
    h.apply(Event::ServeDispute).expect("T-18");
    h
}

#[test]
fn the_two_refusals_that_leave_a_state_map_to_it() {
    // The promise `error.rs` carried since 11.09 — "when statuses land this maps
    // to status 20" — checked rather than commented.
    use ksg_core_v2::status::status_after;
    assert_eq!(
        status_after(&Invalid::ActivationAfterExpiry),
        Some(Status::ActivatedTooLate)
    );
    assert_eq!(status_after(&Invalid::Expired), Some(Status::Expired));
    // Everything else is a refusal and nothing more. Inventing a status for a
    // schema error would put a number in the record that no decision assigned.
    assert_eq!(status_after(&Invalid::MissingInitiation), None);
    assert_eq!(status_after(&Invalid::Schema("anything")), None);
}

// --- the journal opens at record 0 -------------------------------------------

#[test]
fn record_zero_opens_the_journal_and_is_not_work() {
    // `[decision]` 11.09: record №0 is always the first and is never a work record —
    // it certifies that the journal started. Work begins at №1.
    let mut h = StatusHistory::new();
    h.apply(Event::ApplyPacket).unwrap();
    h.apply(Event::ApplyBuyerKey).unwrap();
    h.apply(Event::Initiate).unwrap();

    // At 4 the journal is not open, so there is no №0 and hence no №1 to write.
    assert_eq!(
        h.clone().apply(Event::RecordWork).unwrap_err(),
        Invalid::StatusRefused("the journal is not open: record 0 has not been written")
    );

    h.apply(Event::OpenJournal).expect("T-07");
    assert_eq!(h.current(), Status::InWork);
    // Now work is possible, and it is what happens at 5 rather than what causes it.
    assert_eq!(h.apply(Event::RecordWork).unwrap(), Outcome::Stays);
}

#[test]
fn the_journal_opens_once() {
    // Record №0 is what makes this journal this one. A second opening would be
    // a second identity for the same container.
    for s in Status::all()
        .iter()
        .copied()
        .filter(|s| s.is_working() || *s == Status::Finalized)
    {
        assert_eq!(
            transition(s, Blocked::No, Event::OpenJournal),
            Outcome::Refused("the journal is already open"),
            "status {} let the journal open twice",
            s.number()
        );
    }
}

// --- the status is read before the ink ---------------------------------------

#[test]
fn a_signer_reads_the_status_before_signing() {
    // `[decision]` 11.09: the issuer reads the current status at the moment it signs
    // and does not sign on a mismatch; likewise the owner.
    //
    // The point is that this is EARLIER than verification. A signature already
    // given is a fact in the world — it can be kept, replayed, or shown to
    // someone who never runs the check.
    assert!(may_sign(Status::InWork, Blocked::No, Event::Finalize));
    assert!(!may_sign(Status::Finalized, Blocked::No, Event::Finalize));
    assert!(!may_sign(Status::Initiated, Blocked::No, Event::RecordWork));

    // The two checks agree by construction: whatever a signer refuses to sign,
    // a verifier refuses to accept, and the other way round.
    for &s in Status::all() {
        for &e in EVENTS {
            for b in [Blocked::No, Blocked::AwaitingDecision] {
                assert_eq!(
                    may_sign(s, b, e),
                    !matches!(transition(s, b, e), Outcome::Refused(_)),
                    "signer and verifier disagree on {}/{e:?}",
                    s.number()
                );
            }
        }
    }
}

// --- 12: the journal voluntarily opened --------------------------------------

#[test]
fn opening_the_journal_voluntarily_is_status_twelve() {
    // `[decision]` 11.09. Not the full export: that is 7 and kills the container. This
    // one leaves it working — the pages become readable, and the work goes on.
    assert_eq!(Status::Opened.number(), 12);
    assert!(Status::Opened.is_working());
    assert!(!Status::Opened.is_terminal());

    let mut h = StatusHistory::new();
    for e in [
        Event::ApplyPacket,
        Event::ApplyBuyerKey,
        Event::Initiate,
        Event::OpenJournal,
    ] {
        h.apply(e).unwrap();
    }
    h.apply(Event::OpenVoluntarily).expect("T-36");
    assert_eq!(h.current(), Status::Opened);

    // The work goes on, and the container is still alienable.
    assert_eq!(h.apply(Event::RecordWork).unwrap(), Outcome::Stays);
    assert_eq!(h.apply(Event::TransferOwnership).unwrap(), Outcome::Stays);
    assert!(h.ever(Status::InWork), "5 stays in the history");
}

#[test]
fn a_journal_is_opened_voluntarily_once() {
    // A second opening would change nothing and would put a second record of
    // one fact in the section.
    assert_eq!(
        transition(Status::Opened, Blocked::No, Event::OpenVoluntarily),
        Outcome::Refused("the journal is already open")
    );
}

#[test]
fn voluntary_opening_needs_a_container_that_has_one() {
    // Before the journal exists there is nothing to open, and after the
    // container is dead there is nobody to open it.
    for s in [
        Status::Printed,
        Status::Packeted,
        Status::BuyerKeyed,
        Status::SubAgentKeyed,
        Status::Initiated,
    ] {
        assert!(
            matches!(
                transition(s, Blocked::No, Event::OpenVoluntarily),
                Outcome::Refused(_)
            ),
            "status {} opened a journal it has not got",
            s.number()
        );
    }
    for s in Status::all().iter().copied().filter(|s| s.is_terminal()) {
        assert!(matches!(
            transition(s, Blocked::No, Event::OpenVoluntarily),
            Outcome::Refused(_)
        ));
    }
    // A frozen container still has a journal worth reading.
    assert_eq!(
        transition(Status::Finalized, Blocked::No, Event::OpenVoluntarily),
        Outcome::Moves(Status::Opened)
    );
}

#[test]
fn an_opened_journal_can_still_be_fully_exported() {
    // The two are different things: 12 makes the work readable, 7 hands
    // everything over and ends the container. One does not preclude the other.
    assert_eq!(
        transition(Status::Opened, Blocked::No, Event::FullExport),
        Outcome::Moves(Status::Exported)
    );
}

/// T-22 (KS-7) · E-19, J-9 (KS-8): the container itself declared lost goes
/// to 9 from 4, 5, 6 and 12, and from nowhere earlier.
#[test]
fn a_container_declared_lost_goes_to_nine_from_four_five_six_and_twelve() {
    for from in [
        Status::Initiated,
        Status::InWork,
        Status::Finalized,
        Status::Opened,
    ] {
        assert_eq!(
            transition(from, Blocked::No, Event::DeclareContainerLost),
            Outcome::Moves(Status::Lost),
            "from {from:?}"
        );
    }
    for from in [Status::Printed, Status::Packeted, Status::BuyerKeyed] {
        assert!(
            !matches!(
                transition(from, Blocked::No, Event::DeclareContainerLost),
                Outcome::Moves(_)
            ),
            "a container not yet born is declared lost from {from:?}"
        );
    }
}

/// T-17 (KS-7): death by a lost client key (E-15) from 4 and 5 — beside T-30
/// from 6, which `finalization_takes_no_additions_but_death_is_not_an_addition`
/// holds.
#[test]
fn a_lost_client_key_kills_from_four_and_five() {
    for from in [Status::Initiated, Status::InWork] {
        assert_eq!(
            transition(from, Blocked::No, Event::DeclareKeyLost),
            Outcome::Moves(Status::KeyLost),
            "from {from:?}"
        );
    }
}

/// T-29 (KS-7): an appeal (34) whose own review deadline passes blocks, as
/// a dispute (30) does under T-23.
#[test]
fn an_appeal_blocks_when_its_own_deadline_passes() {
    assert_eq!(
        transition(Status::Appealed, Blocked::No, Event::ReviewDeadlinePassed),
        Outcome::Blocks
    );
}
