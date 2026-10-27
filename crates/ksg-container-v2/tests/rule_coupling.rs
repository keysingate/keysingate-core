//! The rule of two seals (CH-19) and the coupling of containers (CH-12),
//! through the buttons: E-7 sets and lifts the rule, E-14 writes slot 1 into
//! the trailer, E-5 slot 2 into the leader.

mod stand;

use ksg_container_v2::container::Evidence;
use ksg_container_v2::layers::Level;
use ksg_container_v2::{Operation as Op, Stopped, Where, Work};
use ksg_core_v2::crypto::sign::SignatureSet;
use ksg_core_v2::doc::Class;
use ksg_core_v2::journal::{verify_bound, CouplingRecord, RuleScope, SealRule};
use stand::EventKind;
use stand::{p, Page, Stand, Who};

fn to_work(s: &mut Stand) {
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
}

fn work(s: &mut Stand, did: &str) -> Result<(), Stopped> {
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

fn rule(s: &mut Stand, scope: RuleScope) -> Result<(), Stopped> {
    let r = SealRule { scope };
    s.clock_ms += 1_000;
    let d =
        s.c.draft_rule(r.clone(), s.clock_ms)
            .expect("the rule page");
    let w = s.seal_draft(d);
    s.press_write(
        Op::AttachArtifactOrRights,
        &[Who::Client],
        Evidence::Rule(r),
        Some(w),
    )
}

#[test]
fn the_rule_of_two_seals_is_set_and_lifted_through_e7() {
    let mut s = Stand::new(Class::Light, 71);
    to_work(&mut s);
    rule(&mut s, RuleScope::All).expect("set: agent and owner seal the page");
    // Under the rule every record takes the owner's seal — the stand gives it.
    work(&mut s, "under the rule").expect("work with the owner's seal");
    rule(&mut s, RuleScope::Lifted).expect("lifted: again with the owner");
    work(&mut s, "free again").expect("work");
}

#[test]
fn a_rule_page_must_be_the_rule_asked_for() {
    let mut s = Stand::new(Class::Light, 72);
    to_work(&mut s);
    s.clock_ms += 1_000;
    let d =
        s.c.draft_rule(
            SealRule {
                scope: RuleScope::All,
            },
            s.clock_ms,
        )
        .expect("page");
    let w = s.seal_draft(d);
    let err = s
        .press_write(
            Op::AttachArtifactOrRights,
            &[Who::Client],
            Evidence::Rule(SealRule {
                scope: RuleScope::Lifted,
            }),
            Some(w),
        )
        .expect_err("another rule than the page");
    assert!(matches!(err, Stopped::WrongRecord { .. }), "{err:?}");
}

/// Succession (E-14) couples a new container in front of the old one: the
/// old one takes slot 1, "attached to the leader", and goes to 6; the new one
/// takes slot 2, "pulls the trailer", naming the trailer's last seal.
#[test]
fn succession_couples_the_trailer_and_the_leader() {
    let mut a = Stand::new(Class::Light, 73);
    to_work(&mut a);
    work(&mut a, "in the old container").expect("work");
    let mut b = Stand::new(Class::Light, 74);
    to_work(&mut b);

    let attached = CouplingRecord::AttachedTo { leader: *b.c.id() };
    a.clock_ms += 1_000;
    let d =
        a.c.draft_coupling(attached.clone(), a.clock_ms)
            .expect("slot 1");
    let w = a.seal_draft(d);
    a.press_write(
        Op::Succeed,
        &[Who::Issuer],
        Evidence::Coupling(attached.clone()),
        Some(w),
    )
    .expect("E-14 with slot 1");
    assert_eq!(a.c.status(), ksg_core_v2::status::Status::Finalized);
    let trailer_seal = a.c.top_seal_hash().expect("the old container's last seal");

    let pulls = CouplingRecord::Pulls {
        trailer: *a.c.id(),
        trailer_seal,
    };
    b.clock_ms += 1_000;
    let d =
        b.c.draft_coupling(pulls.clone(), b.clock_ms)
            .expect("slot 2");
    let w = b.seal_draft(d);
    b.press_write(
        Op::RecordWork,
        &[Who::Client],
        Evidence::Coupling(pulls.clone()),
        Some(w),
    )
    .expect("E-5 with slot 2");
    // Each slot is written once.
    b.clock_ms += 1_000;
    assert!(b.c.draft_coupling(pulls, b.clock_ms).is_err());
    work(&mut b, "the work goes on in the new one").expect("work");

    // E-14 without naming the successor writes nothing, as before.
    let mut c = Stand::new(Class::Light, 75);
    to_work(&mut c);
    c.press(Op::Succeed, &[Who::Issuer], Evidence::None, Page::None)
        .expect("E-14 alone");

    b.press(Op::Finalize, &[Who::Issuer], Evidence::None, Page::None)
        .expect("finalize");
    b.press(
        Op::FullExport,
        &[Who::Owner, Who::Client],
        Evidence::Unload(Box::new(
            ksg_container_v2::container::UnloadRoute::Principals,
        )),
        Page::None,
    )
    .expect("the leader's export");
    let x = b.c.take_export().expect("export");
    let r = verify_bound(&x, &p()).expect("the leader's export checks");
    assert_eq!(r.records.len(), 3, "page 0, slot 2, work");
}

#[test]
fn a_container_does_not_pull_itself() {
    let mut s = Stand::new(Class::Light, 76);
    to_work(&mut s);
    let me = CouplingRecord::Pulls {
        trailer: *s.c.id(),
        trailer_seal: s.c.top_seal_hash().expect("seal"),
    };
    s.clock_ms += 1_000;
    let d = s.c.draft_coupling(me.clone(), s.clock_ms).expect("page");
    let w = s.seal_draft(d);
    assert!(matches!(
        s.press_write(
            Op::RecordWork,
            &[Who::Client],
            Evidence::Coupling(me),
            Some(w)
        ),
        Err(Stopped::WrongEvidence { .. })
    ));
}
