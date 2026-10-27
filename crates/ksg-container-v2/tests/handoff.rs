//! The hand-off from one agent to another of the same owner (CH-16, CH-17):
//! a working page sealed agent/agent, the new agent's key made inside the
//! container, the old agent sealing nothing afterwards.

mod stand;

use ksg_container_v2::client_key::MobileHalf;
use ksg_container_v2::container::{Evidence, JournalWrite};
use ksg_container_v2::layers::Level;
use ksg_container_v2::{Operation as Op, Stopped, Where, Work};
use ksg_core_v2::crypto::sign::{Alg, SignatureSet};
use ksg_core_v2::doc::Class;
use ksg_core_v2::journal::{verify_bound, Sealing};
use stand::EventKind;
use stand::{p, uri, Page, Stand, Who};

const KEY: [u8; 32] = [7u8; 32];

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

fn record_work(s: &mut Stand, did: &str) -> Result<(), Stopped> {
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

/// The new agent signs at the reader with its mobile half and the container's
/// half of its key — staged, not yet the agent's.
fn new_agent_signs(
    s: &mut Stand,
    m: &MobileHalf,
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

fn ed(
    sigs: Vec<ksg_core_v2::crypto::sign::Signature>,
) -> Vec<ksg_core_v2::crypto::sign::Signature> {
    sigs.into_iter().filter(|x| x.alg == Alg::Ed25519).collect()
}

/// The hand-off page, sealed by the new agent and signed over the transfer by
/// both agents — or, with `old_signs` false, by the new one alone.
fn handoff_write(s: &mut Stand, m: &MobileHalf, old_signs: bool) -> JournalWrite {
    s.clock_ms += 1_000;
    let d = s.c.draft_handoff(s.clock_ms).expect("the hand-off page");
    let bytes = d.seal_bytes().expect("bytes");
    let tb = d.transfer_bytes().expect("bytes").expect("a transfer");
    let seal = new_agent_signs(s, m, &bytes);
    let mut transfer = if old_signs {
        ed(s.client_signs(&tb))
    } else {
        Vec::new()
    };
    transfer.extend(ed(new_agent_signs(s, m, &tb)));
    JournalWrite::Record {
        draft: Box::new(d),
        sealing: Box::new(Sealing {
            seal: SignatureSet::new(seal),
            transfer: Some(SignatureSet::new(transfer)),
            ..Sealing::default()
        }),
    }
}

#[test]
fn a_handoff_makes_the_new_agent_the_agent() {
    let mut s = Stand::new(Class::Light, 61);
    to_work(&mut s);
    record_work(&mut s, "by the first agent").expect("work");
    let old =
        s.c.roster()
            .holder(ksg_container_v2::Role::Client)
            .cloned()
            .expect("client");

    let m =
        s.c.stage_handoff(uri("did:key:zAgentTwo#key-1"), &mut s.rng)
            .expect("staged");
    let w = handoff_write(&mut s, &m, true);
    s.press_write(Op::RecordWork, &[Who::Client], Evidence::Handoff, Some(w))
        .expect("the hand-off page goes in");

    // The seat moved; the old key stays pinned for the past.
    let now =
        s.c.roster()
            .holder(ksg_container_v2::Role::Client)
            .cloned()
            .expect("client");
    assert_eq!(now.kid.as_str(), "did:key:zAgentTwo#key-1");
    assert!(s.c.roster().keys().get(&old.kid).is_some());

    // The old agent's halves seal nothing any more: the stand's mobile half
    // is the old one, and the container now holds the new half.
    let before = s.c.pages();
    s.mobile = m;
    record_work(&mut s, "by the second agent").expect("the new agent works");
    assert_eq!(s.c.pages(), before + 1);

    // The journal checks as a whole, and it survives the store.
    s.press(Op::Finalize, &[Who::Issuer], Evidence::None, Page::None)
        .expect("finalize");
    let bytes = s.c.seal_to_bytes(&KEY, &mut s.rng).expect("stored");
    let c =
        ksg_container_v2::Container::open_sealed(&bytes, &s.c.template_id(), &KEY).expect("opens");
    assert_eq!(
        c.roster().holder(ksg_container_v2::Role::Client),
        Some(&now)
    );

    // CH-5b: the post-quantum key is the container's, not the agent's — the
    // hand-off does not move it, and the key the issuer vouched for at
    // printing still signs the file.
    use ksg_container_v2::store::verify_outer;
    assert_eq!(c.pq_public(), Some(&s.pq));
    assert_eq!(verify_outer(&bytes, &s.c.template_id(), &s.pq), Ok(()));
}

#[test]
fn a_handoff_without_the_old_agent_does_not_go_in() {
    let mut s = Stand::new(Class::Light, 62);
    to_work(&mut s);
    let m =
        s.c.stage_handoff(uri("did:key:zAgentTwo#key-1"), &mut s.rng)
            .expect("staged");
    let w = handoff_write(&mut s, &m, false);
    let err = s
        .press_write(Op::RecordWork, &[Who::Client], Evidence::Handoff, Some(w))
        .expect_err("the old agent must sign the transfer");
    assert!(matches!(err, Stopped::Journal(_)), "{err:?}");
    // Nothing moved: the old agent still works.
    s.c.cancel_handoff();
    record_work(&mut s, "still the first agent").expect("work");
}

#[test]
fn a_handoff_is_refused_where_it_does_not_belong() {
    let mut s = Stand::new(Class::Light, 63);
    to_work(&mut s);
    // No hand-off staged: the evidence alone is not one.
    s.clock_ms += 1_000;
    assert!(s.c.draft_handoff(s.clock_ms).is_err());
    let d =
        s.c.draft_record(
            vec![ksg_core_v2::journal::Piece::Inline(b"x".to_vec())],
            ksg_core_v2::journal::RecordMeta::default(),
            s.clock_ms,
        )
        .expect("draft");
    let w = s.seal_draft(d);
    assert!(matches!(
        s.press_write(Op::RecordWork, &[Who::Client], Evidence::Handoff, Some(w)),
        Err(Stopped::WrongEvidence { .. })
    ));
    // A key id the container knows already is not a new agent.
    let known =
        s.c.roster()
            .holder(ksg_container_v2::Role::Client)
            .cloned()
            .expect("client");
    assert!(s.c.stage_handoff(known.kid.clone(), &mut s.rng).is_err());
    // A work page is not a hand-off page, even with a hand-off staged.
    let _m =
        s.c.stage_handoff(uri("did:key:zAgentTwo#key-1"), &mut s.rng)
            .expect("staged");
    s.clock_ms += 1_000;
    let d =
        s.c.draft_record(
            vec![ksg_core_v2::journal::Piece::Inline(b"x".to_vec())],
            ksg_core_v2::journal::RecordMeta::default(),
            s.clock_ms,
        )
        .expect("draft");
    let w = s.seal_draft(d);
    assert!(matches!(
        s.press_write(Op::RecordWork, &[Who::Client], Evidence::Handoff, Some(w)),
        Err(Stopped::WrongRecord { .. })
    ));
}

#[test]
fn the_export_after_a_handoff_verifies() {
    let mut s = Stand::new(Class::Light, 64);
    to_work(&mut s);
    let m =
        s.c.stage_handoff(uri("did:key:zAgentTwo#key-1"), &mut s.rng)
            .expect("staged");
    let w = handoff_write(&mut s, &m, true);
    s.press_write(Op::RecordWork, &[Who::Client], Evidence::Handoff, Some(w))
        .expect("hand-off");
    s.mobile = m;
    record_work(&mut s, "after").expect("work");
    s.press(Op::Finalize, &[Who::Issuer], Evidence::None, Page::None)
        .expect("finalize");
    s.press(
        Op::FullExport,
        &[Who::Owner, Who::Client],
        Evidence::Unload(Box::new(
            ksg_container_v2::container::UnloadRoute::Principals,
        )),
        Page::None,
    )
    .expect("export");
    let x = s.c.take_export().expect("the export");
    let r = verify_bound(&x, &p()).expect("the export checks");
    assert_eq!(r.records.len(), 3, "page 0, the hand-off, work");
}

/// CH-5b: the new agent's key is born without a dealer — the new agent's
/// mobile side and the container exchange three messages, and neither holds
/// the whole key. The hand-off then goes in as with a key the container made.
#[test]
fn the_new_agents_key_is_born_without_a_dealer() {
    use ksg_container_v2::client_key::MobileKeygen;
    let mut s = Stand::new(Class::Light, 65);
    to_work(&mut s);
    let kid = uri("did:key:zAgentTwo#key-1");
    let (keygen, hello) = MobileKeygen::start(kid.clone(), &mut s.rng).expect("start");
    let reply =
        s.c.begin_handoff_birth(kid, &hello, &mut s.rng)
            .expect("the container answers");
    let (m, public, fin) = keygen.finish(&reply).expect("the new agent keeps its half");
    assert_eq!(s.c.finish_handoff_birth(&fin).expect("staged"), public);
    let w = handoff_write(&mut s, &m, true);
    s.press_write(Op::RecordWork, &[Who::Client], Evidence::Handoff, Some(w))
        .expect("the hand-off page goes in");
    assert_eq!(
        s.c.roster().holder(ksg_container_v2::Role::Client),
        Some(&public)
    );
    s.mobile = m;
    record_work(&mut s, "by the agent born without a dealer").expect("works");
}
