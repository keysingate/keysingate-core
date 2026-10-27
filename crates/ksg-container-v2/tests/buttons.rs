//! The three entry points. KS-8 part D.
//!
//! The axiom under all of it: **an entry point is a break-in point**. Three
//! buttons is a claim about the whole surface, and these tests are what makes it
//! a claim rather than a sentence.

use ksg_container_v2::{
    Button, Command, Keys, Operation, Refusal, Refused, Role, Roster, Strength,
};
use ksg_core_v2::crypto::sign::{Ed25519Signer, KeySet, Profile, SignatureSet};
use ksg_core_v2::doc::Uri;
use ksg_core_v2::status::{Blocked, Status};

fn uri(s: &str) -> Uri {
    Uri::parse(s).expect("uri")
}
fn agent() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:key:zAgent#a1"), [42u8; 32])
}
fn owner() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:key:zOwner#o1"), [44u8; 32])
}
fn issuer() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:key:zIssuer#i1"), [11u8; 32])
}
fn buyer() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:key:zBuyer#b1"), [12u8; 32])
}
fn subagent() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:key:zSub#s1"), [13u8; 32])
}
fn orchestrator() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:key:zOrch#r1"), [14u8; 32])
}
fn claimant() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:key:zClaim#k1"), [15u8; 32])
}

fn keys() -> KeySet {
    everyone().into_iter().map(|(s, _)| s.public()).collect()
}

/// Every party the container knows, with the role it holds — O-3.
fn everyone() -> Vec<(Ed25519Signer, Role)> {
    vec![
        (issuer(), Role::Issuer),
        (owner(), Role::Owner),
        (agent(), Role::Client),
        (subagent(), Role::SubAgent),
        (buyer(), Role::Buyer),
        (orchestrator(), Role::Orchestrator),
        (arbiter_a(), Role::Arbiter),
        (arbiter_b(), Role::Arbiter),
        (claimant(), Role::Claimant),
        // 13.10: the client a `bare` had before its attachment.
        (former_client(), Role::FormerClient),
        // 17.10, C-12 "B": the distributor that sold the packet.
        (distributor(), Role::Distributor),
    ]
}

fn distributor() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:key:zDist#d1"), [72u8; 32])
}

fn former_client() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:key:zFormer#c0"), [71u8; 32])
}

fn roster() -> Roster {
    Roster::of(everyone().into_iter().map(|(s, r)| (s.public(), r)))
}
fn p() -> Profile {
    Profile::default()
}

const BODY: &[u8] = b"what is being asked for";

/// The right parties for whatever the operation asks — O-3.
///
/// Picks by **role** rather than taking the first N of a pool, which is the
/// point: after O-3 a pool of any two parties no longer passes a two-party
/// operation, and a test harness that still did would be testing nothing.
fn signers_for(op: Operation) -> Vec<Ed25519Signer> {
    let Keys::Seats(seats) = op.keys() else {
        return vec![agent()];
    };
    let mut used: Vec<Uri> = Vec::new();
    let mut out = Vec::new();
    for seat in seats {
        let (who, _) = everyone()
            .into_iter()
            .find(|(s, r)| seat.admits(*r) && !used.contains(&s.public().kid))
            .expect("a party for every seat");
        used.push(who.public().kid.clone());
        out.push(who);
    }
    out
}
fn arbiter_a() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:key:zArbA#j1"), [70u8; 32])
}
fn arbiter_b() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:key:zArbB#j2"), [71u8; 32])
}

/// A command signed by the given parties.
fn command(op: Operation, signers: &[&Ed25519Signer]) -> Command {
    let sigs = signers.iter().map(|s| s.sign(BODY)).collect();
    Command {
        op,
        payload: b"opaque material".to_vec(),
        signatures: SignatureSet::new(sigs),
        signed_bytes: BODY.to_vec(),
    }
}

// --- three buttons, and the claim is enforced --------------------------------

#[test]
fn every_operation_arrives_at_exactly_one_button() {
    // The routing table of KS-8 part E, swept. Every operation has a button, and
    // offering it at either of the other two is refused — not because it would
    // be harmful there, but because otherwise "three entry points" is a sentence
    // rather than a property.
    for &op in Operation::all() {
        let right = op.button();
        let holder: Vec<Ed25519Signer> = signers_for(op);
        let refs: Vec<&Ed25519Signer> = holder.iter().collect();
        let c = command(op, &refs);

        for b in [Button::Issuer, Button::Signatures, Button::Export] {
            if b == right {
                continue;
            }
            assert_eq!(
                c.press(b, Status::Printed, Blocked::No, &roster(), &keys(), &p())
                    .unwrap_err()
                    .reason,
                Refusal::WrongButton {
                    op,
                    expected: right,
                    offered: b
                },
                "{op:?} was accepted at {b:?}"
            );
        }
    }
}

#[test]
fn the_issuers_button_carries_data_and_finalization() {
    // KS-8 D-1, and its second function added on 10.09: finalization. Reading the
    // status used to be here; `[decision]` 12.09 removed the port entirely.
    for op in [
        Operation::PrintRelease,
        Operation::ApplyPacket,
        Operation::Finalize,
        Operation::Succeed,
        Operation::FreezeOnOwnerApplication,
    ] {
        assert_eq!(op.button(), Button::Issuer, "{op:?}");
    }
}

#[test]
fn the_export_button_carries_one_thing_only() {
    // D-3 exists for the full export in a dispute and for nothing else. An
    // entry point with one job is the smallest an entry point can be.
    let on_export: Vec<_> = Operation::all()
        .iter()
        .copied()
        .filter(|o| o.button() == Button::Export)
        .collect();
    assert_eq!(
        on_export,
        // The pointwise export joined on 24.09: it hands one page out, which is
        // the same one job.
        vec![
            Operation::FullExport,
            Operation::DiscloseToExpert,
            Operation::ExportPoint
        ],
        "the export button carries handing data out, and only that"
    );
}

// --- the dual key ------------------------------------------------------------

#[test]
fn two_signatures_must_come_from_two_parties() {
    // KS-8 D-5. Counted by distinct signers, not by length: one party signing
    // twice is a set of two and is not two parties, and counting length would
    // leave the rule satisfiable by exactly the party it constrains.
    let doubled = Command {
        signatures: SignatureSet::new(vec![agent().sign(BODY), agent().sign(BODY)]),
        ..command(Operation::TransferOwnership, &[&agent()])
    };
    assert_eq!(
        doubled
            .press(
                Button::Signatures,
                Status::InWork,
                Blocked::No,
                &roster(),
                &keys(),
                &p()
            )
            .unwrap_err()
            .reason,
        Refusal::OneParty(agent().public().kid)
    );

    // And the same command from the two parties the operation names goes
    // through. O-3: "two parties" is no longer enough — a sale is the owner in
    // place and the buyer arriving, and this test used to pass with the client
    // standing in for the buyer.
    command(Operation::TransferOwnership, &[&owner(), &buyer()])
        .press(
            Button::Signatures,
            Status::InWork,
            Blocked::No,
            &roster(),
            &keys(),
            &p(),
        )
        .expect("two parties, one command");
}

#[test]
fn a_routine_record_of_work_takes_one_key_and_nothing_else_does() {
    // The rule stated as a shape rather than as a list: work is the one routine
    // thing an agent does alone; everything that changes what the container is
    // worth takes two.
    assert_eq!(Operation::RecordWork.keys().parties(), 1);
    // CH-29, CH-30 (30.09): the owner's consent to an artefact is the owner's
    // seal on the record in Pro, and in light it is not asked; E-10 takes the
    // issuer only on the way up, which the container checks in step 6.
    assert_eq!(Operation::AttachArtifactOrRights.keys().parties(), 1);
    assert_eq!(Operation::RaiseClass.keys().parties(), 1);
    for op in [
        Operation::ApplyBuyerKey,
        Operation::Initiate,
        Operation::TransferOwnership,
        Operation::FreezeOnOwnerApplication,
    ] {
        assert_eq!(op.keys().parties(), 2, "{op:?}");
    }
}

#[test]
fn a_command_with_no_signature_never_goes_through() {
    for &op in Operation::all() {
        let bare = Command {
            signatures: SignatureSet::default(),
            ..command(op, &[])
        };
        assert!(matches!(
            bare.press(
                op.button(),
                Status::InWork,
                Blocked::No,
                &roster(),
                &keys(),
                &p()
            ),
            Err(Refused {
                reason: Refusal::NotEnoughSignatures { .. },
                ..
            })
        ));
    }
}

#[test]
fn a_signature_from_a_key_the_container_does_not_know_is_refused() {
    // Since O-3 the refusal comes earlier and says more: a key with no role is
    // named as such, rather than reported as a signature that did not verify.
    // Both are refusals; this one tells the presenter which thing is wrong.
    let stranger = Ed25519Signer::from_seed(uri("did:key:zNobody#x"), [99u8; 32]);
    let c = command(Operation::RecordWork, &[&stranger]);
    assert_eq!(
        c.press(
            Button::Signatures,
            Status::InWork,
            Blocked::No,
            &roster(),
            &keys(),
            &p()
        )
        .unwrap_err()
        .reason,
        Refusal::NoRole(stranger.public().kid.clone())
    );
}

#[test]
fn a_signature_over_other_bytes_is_refused() {
    let mut c = command(Operation::RecordWork, &[&agent()]);
    c.signed_bytes = b"something else entirely".to_vec();
    assert_eq!(
        c.press(
            Button::Signatures,
            Status::InWork,
            Blocked::No,
            &roster(),
            &keys(),
            &p()
        )
        .unwrap_err()
        .reason,
        Refusal::Signature
    );
}

// --- the status is read before the ink ---------------------------------------

#[test]
fn an_operation_the_status_does_not_admit_is_refused_at_the_button() {
    // §7.3-bis. The point is that this happens BEFORE anything is signed into
    // the container: a signature already given is a fact in the world.
    let c = command(Operation::RecordWork, &[&agent()]);
    assert_eq!(
        c.press(
            Button::Signatures,
            Status::Initiated,
            Blocked::No,
            &roster(),
            &keys(),
            &p()
        )
        .unwrap_err()
        .reason,
        Refusal::WrongStatus {
            op: Operation::RecordWork,
            status: 4
        },
        "the journal is not open at status 4"
    );
    c.press(
        Button::Signatures,
        Status::InWork,
        Blocked::No,
        &roster(),
        &keys(),
        &p(),
    )
    .expect("and it is admitted at 5");
}

#[test]
fn a_blocked_container_says_so_rather_than_blaming_the_status() {
    // Two different answers to "why not": "not in this state" and "not until
    // somebody decides" send the presenter to different places.
    let c = command(Operation::RecordWork, &[&agent()]);
    assert_eq!(
        c.press(
            Button::Signatures,
            Status::Disputed,
            Blocked::AwaitingDecision,
            &roster(),
            &keys(),
            &p()
        )
        .unwrap_err()
        .reason,
        Refusal::Blocked
    );
}

#[test]
fn there_is_no_operation_that_reads_the_status() {
    // `[decision]` 12.09, the owner: "yes, drop the read — there should be none at all". E-12 had an
    // operation and now has none, and nothing on any button asks the container
    // what its status is.
    //
    // Nothing is lost, which is why this is a strengthening and not a
    // subtraction: §7.3 already requires every change of status to be anchored,
    // so the current status follows from the chain — publicly, with its whole
    // history, and without a port into a sealed container. By the axiom that an
    // entry point is a break-in point, the best port is the absent one.
    for &op in Operation::all() {
        assert!(
            op.event().is_some()
                || matches!(
                    op,
                    Operation::AppointExpert
                        | Operation::DiscloseToExpert
                        | Operation::ExportPoint
                        | Operation::Detach
                ),
            "{op:?} does nothing to the status and is not one of the four that may"
        );
    }
    // The status still reaches the check — as an argument, the way elapsed time
    // does. It is read from the chain by the caller, not from the container.
    let c = command(Operation::RecordWork, &[&agent()]);
    c.press(
        Button::Signatures,
        Status::InWork,
        Blocked::No,
        &roster(),
        &keys(),
        &p(),
    )
    .expect("the status arrives as a value");
}

#[test]
fn the_one_operation_that_writes_nothing_is_the_one_that_is_not_anchored() {
    // It was two until the read port went. A disclosure to an expert is the
    // expert reading, and the appointment behind it is anchored by the record the
    // expert publishes themselves.
    for &op in Operation::all() {
        assert_eq!(
            op.anchored(),
            // The pointwise export (24.09) writes nothing either: the count of
            // pages out is kept inside the journal.
            // The detachment (13.10) writes nothing: the attached `bare`
            // only reads, and burning it wipes this copy.
            !matches!(
                op,
                Operation::DiscloseToExpert | Operation::ExportPoint | Operation::Detach
            ),
            "{op:?} disagrees about anchoring"
        );
    }
}

// --- the three operations added on 11.09 -------------------------------------

#[test]
fn the_voluntary_opening_takes_four_parties() {
    // Client, owner and two arbiters, all on one command. Counted in parties,
    // as everything here is: four signatures from three people are three
    // parties.
    assert_eq!(Operation::OpenVoluntarily.keys().parties(), 4);

    let four = signers_for(Operation::OpenVoluntarily);
    let refs: Vec<&Ed25519Signer> = four.iter().collect();
    command(Operation::OpenVoluntarily, &refs)
        .press(
            Button::Signatures,
            Status::InWork,
            Blocked::No,
            &roster(),
            &keys(),
            &p(),
        )
        .expect("four parties on one command");

    let three = [agent(), owner(), arbiter_a(), agent()];
    let refs: Vec<&Ed25519Signer> = three.iter().collect();
    assert!(matches!(
        command(Operation::OpenVoluntarily, &refs).press(
            Button::Signatures,
            Status::InWork,
            Blocked::No,
            &roster(),
            &keys(),
            &p()
        ),
        Err(Refused {
            reason: Refusal::OneParty(_),
            ..
        })
    ));
}

#[test]
fn naming_an_expert_takes_one_principal_and_disclosing_to_one_takes_two() {
    // The owner's wording, kept: a court order binds each principal separately,
    // so either may name the expert alone and letting one stall the appointment
    // is avoided. Handing over the contents is a disclosure, and every
    // disclosure here takes the pair.
    assert_eq!(Operation::AppointExpert.keys().parties(), 1);
    assert_eq!(Operation::DiscloseToExpert.keys().parties(), 2);

    command(Operation::AppointExpert, &[&agent()])
        .press(
            Button::Signatures,
            Status::InWork,
            Blocked::No,
            &roster(),
            &keys(),
            &p(),
        )
        .expect("either principal alone");

    assert!(matches!(
        command(Operation::DiscloseToExpert, &[&agent()]).press(
            Button::Export,
            Status::InWork,
            Blocked::No,
            &roster(),
            &keys(),
            &p()
        ),
        Err(Refused {
            reason: Refusal::NotEnoughSignatures { .. },
            ..
        })
    ));
}

#[test]
fn a_disclosure_to_an_expert_does_not_end_the_container() {
    // It arrives at the export button beside the full export, and the two are
    // not the same act: one hands data to a named expert and leaves the
    // container working; the other ends it. Held as a test because they share a
    // button, which is exactly where that could be lost.
    assert_eq!(Operation::DiscloseToExpert.event(), None);
    assert_eq!(
        Operation::FullExport.event(),
        Some(ksg_core_v2::status::Event::FullExport)
    );
}

#[test]
fn the_voluntary_opening_needs_a_journal_to_open() {
    // The status check, running before anything is signed into the container.
    let four = signers_for(Operation::OpenVoluntarily);
    let refs: Vec<&Ed25519Signer> = four.iter().collect();
    let c = command(Operation::OpenVoluntarily, &refs);

    assert_eq!(
        c.press(
            Button::Signatures,
            Status::Initiated,
            Blocked::No,
            &roster(),
            &keys(),
            &p()
        )
        .unwrap_err()
        .reason,
        Refusal::WrongStatus {
            op: Operation::OpenVoluntarily,
            status: 4
        },
        "at 4 the journal is not open yet"
    );
    c.press(
        Button::Signatures,
        Status::Opened,
        Blocked::No,
        &roster(),
        &keys(),
        &p(),
    )
    .expect_err("and an open journal does not open twice");
}

// --- O-3: whose second key, per operation ------------------------------------
//
// `[decision]` 12.09. Counting to two let any second party stand in for the one the
// operation means. These tests are the difference between a count and a rule.

/// Presses an operation with exactly these parties, at its own button.
fn press_as(op: Operation, signers: &[&Ed25519Signer]) -> Result<Strength, Refused> {
    command(op, signers).press(
        op.button(),
        Status::InWork,
        Blocked::No,
        &roster(),
        &keys(),
        &p(),
    )
}

#[test]
fn every_operation_names_its_parties() {
    // The sweep that makes O-3 a property rather than a table in a document:
    // no operation is left with an unnamed second key.
    for &op in Operation::all() {
        match op.keys() {
            Keys::Seats(seats) => assert!(!seats.is_empty(), "{op:?} names no parties at all"),
            // The one exception, and it is declared: the composition of a full
            // export is decided above the core.
            Keys::Set => assert_eq!(op, Operation::FullExport),
            // Alternatives (C-12, 17.10): each one names its parties.
            Keys::AnyOf(alts) => {
                assert_eq!(op, Operation::DeclareKeyLost);
                assert!(alts.iter().all(|a| !a.is_empty()), "{op:?}");
            }
        }
    }
}

#[test]
fn the_party_count_did_not_change_when_the_roles_were_named() {
    // Naming the roles must not quietly re-decide how many keys an operation
    // takes — those numbers are decided rows of KS-8 part E.
    assert_eq!(Operation::RecordWork.keys().parties(), 1);
    assert_eq!(Operation::OpenVoluntarily.keys().parties(), 4);
    // CH-29, CH-30 (30.09) re-decided two rows of KS-8 part E; see
    // `a_routine_record_of_work_takes_one_key_and_nothing_else_does`.
    assert_eq!(Operation::AttachArtifactOrRights.keys().parties(), 1);
    assert_eq!(Operation::RaiseClass.keys().parties(), 1);
    for op in [
        Operation::ApplyBuyerKey,
        Operation::ApplySubAgentKey,
        Operation::Initiate,
        Operation::TransferOwnership,
        Operation::FreezeOnOwnerApplication,
        Operation::DiscloseToExpert,
    ] {
        assert_eq!(op.keys().parties(), 2, "{op:?}");
    }
}

#[test]
fn two_parties_of_the_wrong_roles_no_longer_pass() {
    // The defect O-3 closes, stated as a test. Before this, a sale signed by the
    // client and a sub-agent satisfied "two parties" and went through.
    assert!(matches!(
        press_as(Operation::TransferOwnership, &[&agent(), &subagent()]),
        Err(Refused {
            reason: Refusal::RoleMissing { .. },
            ..
        })
    ));
    press_as(Operation::TransferOwnership, &[&owner(), &buyer()])
        .expect("the owner in place and the buyer arriving");
}

#[test]
fn the_freeze_takes_the_issuer_and_the_owner_and_no_other_pair() {
    // E-23 is the owner's lever, and the price is the issuer's signature beside
    // it. Any other pair is a different operation wearing its name.
    press_as(Operation::FreezeOnOwnerApplication, &[&issuer(), &owner()])
        .expect("the pair E-23 names");
    for pair in [
        [&issuer(), &agent()],
        [&owner(), &agent()],
        [&owner(), &arbiter_a()],
    ] {
        assert!(
            matches!(
                press_as(Operation::FreezeOnOwnerApplication, &pair),
                Err(Refused {
                    reason: Refusal::RoleMissing { .. },
                    ..
                })
            ),
            "{pair:?} must not freeze a container"
        );
    }
}

#[test]
fn the_issuer_cannot_stand_in_for_the_owner_where_the_owner_consents() {
    // E-4: the client initiates and the owner consents (was E-6…E-8 until
    // CH-29 moved the owner's consent there onto the record's seal). The issuer is the
    // blindest party by construction (F-7) and has no business consenting here.
    assert!(matches!(
        press_as(Operation::Initiate, &[&agent(), &issuer()]),
        Err(Refused {
            reason: Refusal::RoleMissing { .. },
            ..
        })
    ));
    command(Operation::Initiate, &[&agent(), &owner()])
        .press(
            Button::Signatures,
            Status::BuyerKeyed,
            Blocked::No,
            &roster(),
            &keys(),
            &p(),
        )
        .expect("client and owner, at the status initiation is signed in");
}

#[test]
fn a_sub_agents_key_is_authorized_by_the_client_not_by_the_owner() {
    // KS-4: the delegating agent authorizes the delegate. The owner is not in
    // that chain, and a check counting to two could not tell the difference.
    // At the status that admits it: a sub-agent's key is laid on after the
    // buyer's and before the work starts.
    let at = |signers: &[&Ed25519Signer]| {
        command(Operation::ApplySubAgentKey, signers).press(
            Button::Signatures,
            Status::BuyerKeyed,
            Blocked::No,
            &roster(),
            &keys(),
            &p(),
        )
    };
    at(&[&subagent(), &agent()]).expect("sub-agent and client");
    assert!(matches!(
        at(&[&subagent(), &owner()]),
        Err(Refused {
            reason: Refusal::RoleMissing { .. },
            ..
        })
    ));
}

#[test]
fn either_of_a_pair_fills_a_shared_seat() {
    // The operations deliberately left to whoever is there: declaring a key lost
    // (owner or orchestrator), naming an expert (either principal), deciding a
    // dispute (the arbiter plus either side). Both sides of each must pass.
    for who in [&owner(), &orchestrator()] {
        press_as(Operation::DeclareKeyLost, &[who]).expect("the owner or the orchestrator");
    }
    for who in [&agent(), &owner()] {
        press_as(Operation::AppointExpert, &[who]).expect("either principal alone");
    }
}

#[test]
fn a_shared_seat_is_not_a_free_seat() {
    // "Either of two" is still a named pair: a third party does not fill it.
    assert!(matches!(
        press_as(Operation::DeclareKeyLost, &[&arbiter_a()]),
        Err(Refused {
            reason: Refusal::RoleMissing { .. },
            ..
        })
    ));
    assert!(matches!(
        press_as(Operation::AppointExpert, &[&issuer()]),
        Err(Refused {
            reason: Refusal::RoleMissing { .. },
            ..
        })
    ));
}

#[test]
fn a_shared_seat_does_not_eat_the_party_a_later_seat_needs() {
    // Why the seating is an exhaustive match and not a loop. Naming an expert
    // takes either principal; a disclosure takes both. A greedy pass over
    // [Either(Client, Owner), Exactly(Owner)] would hand the owner to the first
    // seat and then refuse a perfectly good command.
    //
    // Built here from the operation that has that shape today, and kept as a
    // test so the shape stays safe when another operation acquires it.
    press_as(Operation::DiscloseToExpert, &[&owner(), &agent()])
        .expect("order of signatures must not matter");
    press_as(Operation::DiscloseToExpert, &[&agent(), &owner()]).expect("nor the other order");
}

#[test]
fn one_party_holding_two_roles_still_fills_one_seat() {
    // A client that also owns its own container is ordinary. It is still one
    // party, and a two-party operation is not satisfied by it signing twice —
    // which is the rule O-3 makes checkable rather than conventional.
    let both = Ed25519Signer::from_seed(uri("did:key:zBoth#c1"), [55u8; 32]);
    let mut r = Roster::of(everyone().into_iter().map(|(s, role)| (s.public(), role)));
    r.add(both.public(), Role::Client)
        .add(both.public(), Role::Owner);
    let mut ks = keys();
    ks.insert(both.public());

    let c = command(Operation::Initiate, &[&both, &both]);
    assert!(matches!(
        c.press(
            Button::Signatures,
            Status::InWork,
            Blocked::No,
            &r,
            &ks,
            &p()
        ),
        Err(Refused {
            reason: Refusal::OneParty(_) | Refusal::NotEnoughSignatures { .. },
            ..
        })
    ));
    assert_eq!(r.roles_of(&both.public().kid).len(), 2);
}

#[test]
fn the_arbiters_must_be_two_different_arbiters() {
    // Status 12 seats the arbiter role twice, and two seats are two distinct
    // parties. One arbiter signing for both would be one side seating the panel.
    press_as(
        Operation::OpenVoluntarily,
        &[&agent(), &owner(), &arbiter_a(), &arbiter_b()],
    )
    .expect("four parties on one command");
    assert!(matches!(
        press_as(
            Operation::OpenVoluntarily,
            &[&agent(), &owner(), &arbiter_a()]
        ),
        Err(Refused {
            reason: Refusal::NotEnoughSignatures { .. },
            ..
        })
    ));
}

// --- O-2: what happens when the set of signatures is incomplete --------------
//
// Closed by consequence rather than by a new decision. `[decision]` 11.09 on B-6 —
// **the attempt is recorded under an anchor** — and the sentence that settled it
// settles this too: silence means the door was rattled and you never learn of it.

#[test]
fn a_refusal_hands_over_the_record_of_the_attempt() {
    // The record is not optional, and that is enforced by the type: there is no
    // way to receive a refusal without also receiving the thing to anchor.
    let half = command(Operation::Initiate, &[&agent()]);
    let refused = half
        .press(
            Button::Signatures,
            Status::InWork,
            Blocked::No,
            &roster(),
            &keys(),
            &p(),
        )
        .expect_err("one of two parties");
    assert!(matches!(
        refused.reason,
        Refusal::NotEnoughSignatures { .. }
    ));
    assert_eq!(refused.attempt.op, Operation::Initiate);
    assert_eq!(refused.attempt.button, Button::Signatures);
    assert_eq!(refused.attempt.at_status, Status::InWork.number());
    assert_eq!(refused.attempt.signers, vec![agent().public().kid]);
    assert_eq!(refused.attempt.reason, refused.reason);
}

#[test]
fn an_attempt_names_who_rattled_the_door() {
    // B-6's whole point. An attempt by a party with no business here records
    // that party, so "somebody tried" is never the most that can be said.
    let stranger = Ed25519Signer::from_seed(uri("did:key:zNobody#x"), [99u8; 32]);
    let refused = command(Operation::RecordWork, &[&stranger])
        .press(
            Button::Signatures,
            Status::InWork,
            Blocked::No,
            &roster(),
            &keys(),
            &p(),
        )
        .expect_err("no role");
    assert_eq!(refused.attempt.signers, vec![stranger.public().kid.clone()]);
}

#[test]
fn an_attempt_carries_a_digest_and_not_the_material() {
    // An attempt proves what was presented without disclosing it. The payload
    // does not appear at all, and the signed bytes appear only as a hash.
    let c = command(Operation::TransferOwnership, &[&agent()]);
    let refused = c
        .press(
            Button::Signatures,
            Status::InWork,
            Blocked::No,
            &roster(),
            &keys(),
            &p(),
        )
        .expect_err("one party");
    let printed = format!("{:?}", refused.attempt);
    assert!(!printed.contains("opaque material"), "the payload leaked");
    assert!(
        !printed.contains(std::str::from_utf8(BODY).expect("utf8")),
        "the signed bytes leaked"
    );
    assert_eq!(
        refused.attempt.signed,
        ksg_core_v2::crypto::hash::Hash::sha256(BODY)
    );
}

#[test]
fn two_attempts_that_differ_anchor_differently() {
    // The subject covers the operation, the door, the status, the signers and
    // the reason. Two different rattles must not share one anchor, or a record
    // of one would pass for a record of the other.
    let a = command(Operation::TransferOwnership, &[&agent()])
        .press(
            Button::Signatures,
            Status::InWork,
            Blocked::No,
            &roster(),
            &keys(),
            &p(),
        )
        .expect_err("one party");
    let b = command(Operation::TransferOwnership, &[&owner()])
        .press(
            Button::Signatures,
            Status::InWork,
            Blocked::No,
            &roster(),
            &keys(),
            &p(),
        )
        .expect_err("one party");
    assert_ne!(a.attempt.subject(), b.attempt.subject());
    // And the same attempt hashes the same way, or an anchor could never be
    // checked against it.
    assert_eq!(a.attempt.subject(), a.attempt.subject());
}

#[test]
fn halves_presented_separately_never_add_up() {
    // §5.3: both signatures arrive on ONE command. A sequential scheme would let
    // the first wait for the second, and the wait is the window. Nothing here
    // retains a half — `press` takes `&self` and keeps nothing — so the same two
    // parties signing separately are two refusals rather than one success.
    for who in [&agent(), &owner()] {
        let refused = command(Operation::Initiate, &[who])
            .press(
                Button::Signatures,
                Status::InWork,
                Blocked::No,
                &roster(),
                &keys(),
                &p(),
            )
            .expect_err("a half is not a command");
        assert!(matches!(
            refused.reason,
            Refusal::NotEnoughSignatures { .. }
        ));
    }
    // Together, on one command, it goes through.
    // At the status initiation is signed in: the buyer's key laid on.
    command(Operation::Initiate, &[&agent(), &owner()])
        .press(
            Button::Signatures,
            Status::BuyerKeyed,
            Blocked::No,
            &roster(),
            &keys(),
            &p(),
        )
        .expect("both on one command");
}

#[test]
fn a_refused_attempt_can_be_recorded_without_pressing_anything() {
    // A platform may anchor an attempt it turned away earlier. The record is
    // reachable directly, and it agrees with the one a refusal hands over.
    let c = command(Operation::Finalize, &[&agent()]);
    let by_hand = c.record(
        Button::Issuer,
        Status::InWork,
        Refusal::RoleMissing {
            op: Operation::Finalize,
            seat: ksg_container_v2::Seat::Exactly(Role::Issuer),
        },
    );
    let refused = c
        .press(
            Button::Issuer,
            Status::InWork,
            Blocked::No,
            &roster(),
            &keys(),
            &p(),
        )
        .expect_err("the client cannot finalize");
    assert_eq!(by_hand, *refused.attempt);
}

// --- O-13: whose key decides a dispute ---------------------------------------
//
// `[decision]` 12.09, the owner: "minimum the arbiter + either side, optimum the arbiter + both sides."
// Two tiers, so the rule holds both: the minimum is enforced, and which of the
// two was met travels with the decision instead of disappearing into "it passed".

/// A dispute is served first, so the status admits a decision.
fn press_disputed(op: Operation, signers: &[&Ed25519Signer]) -> Result<Strength, Refused> {
    command(op, signers).press(
        op.button(),
        Status::Disputed,
        Blocked::No,
        &roster(),
        &keys(),
        &p(),
    )
}

#[test]
fn a_dispute_is_served_by_the_claimant_and_nobody_else() {
    // T-B10: delivery is the claimant's key. The container does not learn of a
    // dispute — it is handed the anchored statement, and the claimant has already
    // named themselves in the chain (C-11), so there is nobody else it could be.
    command(Operation::ServeDispute, &[&claimant()])
        .press(
            Button::Signatures,
            Status::InWork,
            Blocked::No,
            &roster(),
            &keys(),
            &p(),
        )
        .expect("the claimant serves");
    for who in [&owner(), &agent(), &arbiter_a()] {
        assert!(
            matches!(
                command(Operation::ServeDispute, &[who]).press(
                    Button::Signatures,
                    Status::InWork,
                    Blocked::No,
                    &roster(),
                    &keys(),
                    &p()
                ),
                Err(Refused {
                    reason: Refusal::RoleMissing { .. },
                    ..
                })
            ),
            "a dispute is not served by anyone but the claimant"
        );
    }
}

#[test]
fn an_arbiter_alone_cannot_decide() {
    // The tightening `[decision]` 12.09 brings to T-B10, which had allowed a decision
    // "by the arbiter's key". A minimum of the arbiter AND one side means an
    // arbiter on their own is no longer enough.
    for op in [
        Operation::DecideDisputeProven,
        Operation::DecideDisputeUnproven,
    ] {
        assert!(
            matches!(
                press_disputed(op, &[&arbiter_a()]),
                Err(Refused {
                    reason: Refusal::NotEnoughSignatures { .. },
                    ..
                })
            ),
            "{op:?} must not be decided by an arbiter alone"
        );
    }
}

#[test]
fn neither_can_the_sides_decide_without_an_arbiter() {
    // The other half of the same rule: the parties to a dispute do not resolve it
    // between themselves under the name of a decision.
    assert!(matches!(
        press_disputed(Operation::DecideDisputeProven, &[&agent(), &owner()]),
        Err(Refused {
            reason: Refusal::RoleMissing { .. },
            ..
        })
    ));
}

#[test]
fn the_minimum_is_an_arbiter_and_one_side_and_it_says_so() {
    // Either side fills the shared seat, and the decision is accepted — and
    // reported as the minimum, because one side was not there.
    for side in [&agent(), &owner()] {
        let got = press_disputed(Operation::DecideDisputeProven, &[&arbiter_a(), side])
            .expect("the minimum O-13 sets");
        assert_eq!(got, Strength::Minimum, "one side absent is not the optimum");
    }
}

#[test]
fn the_optimum_is_an_arbiter_and_both_sides_and_it_says_that_too() {
    // A decision both sides stood at is stronger than one taken with a side
    // absent, and that difference is the thing worth carrying forward: the
    // platform anchors it beside the status change, so a later reader sees which.
    let got = press_disputed(
        Operation::DecideDisputeProven,
        &[&arbiter_a(), &agent(), &owner()],
    )
    .expect("the optimum O-13 sets");
    assert_eq!(got, Strength::Full);
}

#[test]
fn the_strength_is_reported_and_never_a_condition() {
    // The minimum is the rule. The optimum is a fact about this command, asked
    // after it is accepted — not a second gate that quietly rejects decisions the
    // owner said are valid.
    let minimum = press_disputed(Operation::DecideDisputeUnproven, &[&arbiter_a(), &owner()]);
    assert!(minimum.is_ok(), "the minimum is accepted, not merely noted");
    assert_eq!(minimum.expect("ok"), Strength::Minimum);
}

#[test]
fn everything_else_is_full_strength_because_it_has_one_standard() {
    // Most operations have a single set of parties, and asking which tier was met
    // would be a question with one answer. Only the two decisions have two tiers.
    for &op in Operation::all() {
        let two_tier = matches!(
            op,
            Operation::DecideDisputeProven | Operation::DecideDisputeUnproven
        );
        assert_eq!(
            op.keys() == op.keys_optimum(),
            !two_tier,
            "{op:?} disagrees about having two tiers"
        );
    }
}

#[test]
fn a_second_arbiter_does_not_substitute_for_a_side() {
    // Two arbiters and no principal is not "an arbiter plus one more party": the
    // seat the rule leaves open is a SIDE's seat.
    assert!(matches!(
        press_disputed(
            Operation::DecideDisputeProven,
            &[&arbiter_a(), &arbiter_b()]
        ),
        Err(Refused {
            reason: Refusal::RoleMissing { .. },
            ..
        })
    ));
}

fn seats_of(op: Operation) -> Vec<ksg_container_v2::operation::Seat> {
    let Keys::Seats(seats) = op.keys() else {
        panic!("{op:?} takes seats");
    };
    seats.to_vec()
}

/// E-3 (KS-8 D-5): the buyer's key is laid by the buyer **and** the owner —
/// the roles, not just their number.
#[test]
fn the_buyers_key_is_laid_by_the_buyer_and_the_owner() {
    use ksg_container_v2::operation::Seat::Exactly;
    assert_eq!(
        seats_of(Operation::ApplyBuyerKey),
        [Exactly(Role::Buyer), Exactly(Role::Owner)]
    );
}

/// E-1 · E-2 · E-13 · E-14 (KS-8 D-5): the issuer acts alone — printing,
/// the packet, finalization, succession.
#[test]
fn the_issuer_alone_prints_applies_the_packet_finalizes_and_succeeds() {
    use ksg_container_v2::operation::Seat::Exactly;
    for op in [
        Operation::PrintRelease,
        Operation::ApplyPacket,
        Operation::Finalize,
        Operation::Succeed,
    ] {
        assert_eq!(seats_of(op), [Exactly(Role::Issuer)], "{op:?}");
    }
}

/// L item 1 (C-1), `[decision]` 19.09 (CT-27): the release layer is the
/// number, the moment of issuance and the class — those three and nothing
/// else.
#[test]
fn the_release_is_number_moment_and_class() {
    let r = ksg_container_v2::container::Release {
        id: "ksg:em:000001".into(),
        issued_at: ksg_core_v2::doc::Timestamp::parse("2026-10-01T00:00:00.000Z").unwrap(),
        class: ksg_core_v2::doc::Class::Light,
    };
    let v = serde_json::to_value(&r).unwrap();
    let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["class", "id", "issued_at"]);
}

/// C-12, owner's decision 17.10 "B": who declares a container dead in the
/// client's stead — the owner alone; or the orchestrator alone; or the
/// distributor that sold the packet together with the client. The issuer
/// never takes the distributor's seat, and on a direct sale there is no
/// distributor in the roster to take it.
#[test]
fn a_container_is_declared_dead_by_one_of_three_sets() {
    let op = Operation::DeclareKeyLost;
    press_as(op, &[&owner()]).expect("the owner alone");
    press_as(op, &[&orchestrator()]).expect("the orchestrator alone");
    press_as(op, &[&distributor(), &agent()]).expect("the distributor with the client");
    for alone in [&distributor(), &agent()] {
        assert!(press_as(op, &[alone]).is_err(), "half of the third set");
    }
    assert!(
        press_as(op, &[&issuer(), &agent()]).is_err(),
        "the issuer does not stand in for the distributor"
    );
    // A direct sale: no distributor in the roster, its key is nobody's.
    let direct = Roster::of(
        everyone()
            .into_iter()
            .filter(|(_, r)| *r != Role::Distributor)
            .map(|(s, r)| (s.public(), r)),
    );
    let refused = command(op, &[&distributor(), &agent()]).press(
        op.button(),
        Status::InWork,
        Blocked::No,
        &direct,
        &keys(),
        &p(),
    );
    assert!(refused.is_err(), "no distributor seated, no third path");
    assert_eq!(op.keys().parties(), 1, "the smallest set is one party");
}
