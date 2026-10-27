//! The bound journal: pages under a movable seal (Plan_MVP §9, CH-1…CH-20).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use fips204::ml_dsa_65;
use fips204::traits::{KeyGen, SerDes, Signer as _};

use ksg_core_v2::anchor::Attestation as EntryAnchor;
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{
    b64_encode, Alg, Ed25519Signer, Profile, PublicKey, Signature, SignatureSet,
};
use ksg_core_v2::doc::{Timestamp, Uri};
use ksg_core_v2::journal::{
    verify_bound, verify_bound_point, Binder, BinderError, BoundExport, CouplingRecord, Mode,
    Outcome, Party, Piece, RecordKind, RecordMeta, RuleScope, SealRule, Sealing, TransferKind,
    TransferRecord, Zone, BATCH_CONTENT_PAGES, PAGE_BYTES, POINT_LIMIT, TRANSFER_PAGES, WORK_PAGES,
};

fn uri(s: &str) -> Uri {
    Uri::parse(s.to_owned()).expect("uri")
}

/// A party with an Ed25519 and an ML-DSA-65 key, both from public test seeds.
struct Keys {
    id: Uri,
    ed: Ed25519Signer,
    pq: ml_dsa_65::PrivateKey,
    pq_pub: PublicKey,
}

impl Keys {
    fn new(name: &str) -> Self {
        let id = uri(&format!("did:key:z{name}"));
        let seed = Hash::sha256(format!("ksg:test-key:v1:{name}").as_bytes());
        let ed = Ed25519Signer::from_seed(uri(&format!("did:key:z{name}#ed")), *seed.as_bytes());
        let (pk, pq) = ml_dsa_65::KG::keygen_from_seed(seed.as_bytes());
        let pq_pub = PublicKey {
            kid: uri(&format!("did:key:z{name}#pq")),
            alg: Alg::MlDsa65,
            key: b64_encode(&pk.into_bytes()),
        };
        Self { id, ed, pq, pq_pub }
    }

    fn party(&self) -> Party {
        Party {
            id: self.id.clone(),
            keys: vec![self.ed.public(), self.pq_pub.clone()],
        }
    }

    /// Ed25519 and ML-DSA-65: the movable seal.
    fn both(&self, msg: &[u8]) -> Vec<Signature> {
        let pq = self.pq.try_sign(msg, &[]).expect("ml-dsa");
        vec![
            self.ed.sign(msg),
            Signature {
                kid: self.pq_pub.kid.clone(),
                alg: Alg::MlDsa65,
                value: b64_encode(&pq),
            },
        ]
    }

    /// Ed25519 only: the seals that are never removed.
    fn ed(&self, msg: &[u8]) -> Vec<Signature> {
        vec![self.ed.sign(msg)]
    }
}

fn set(v: Vec<Signature>) -> SignatureSet {
    SignatureSet::new(v)
}

fn container() -> Hash {
    Hash::sha256(b"container-1")
}

fn profile() -> Profile {
    Profile::default()
}

fn anchor(subject: Hash) -> EntryAnchor {
    EntryAnchor {
        kind: uri("urn:ksg:anchor:test"),
        subject,
        // The size of a real Solana proof (`ksg-verify` `PageProof`: an
        // 88-character signature, a slot, a cluster — about 130 bytes of
        // JSON), each byte written as three digits and a comma.
        proof: vec![200; 130],
        anchored_at: Timestamp::parse("2026-09-30T10:00:00.000Z".to_owned()).expect("ts"),
    }
}

fn open(agent: &Keys, owner: &Keys, pro: bool) -> Binder {
    let mode = if pro { Mode::Pro } else { Mode::Local };
    let (bytes, hash) =
        Binder::opening_seal(container(), mode, agent.party(), owner.party(), 1).expect("seal 0");
    // Pro from the start: the owner confirms and only then is it anchored (CH-26).
    let sealing = Sealing {
        seal: set(agent.both(&bytes)),
        owner: pro.then(|| set(owner.ed(&bytes))),
        anchor: pro.then(|| anchor(hash)),
        ..Sealing::default()
    };
    Binder::open(
        container(),
        mode,
        agent.party(),
        owner.party(),
        1,
        &sealing,
        &profile(),
    )
    .expect("open")
}

/// Seals a draft with the agent's movable seal and, in Pro, its anchor.
fn seal_by(
    b: &mut Binder,
    d: ksg_core_v2::journal::Draft,
    agent: &Keys,
) -> Result<Outcome, BinderError> {
    let sealing = Sealing {
        seal: set(agent.ed(&d.seal_bytes().expect("bytes"))),
        anchor: (d.is_pro() && !d.needs_owner()).then(|| anchor(d.seal_hash().expect("hash"))),
        ..Sealing::default()
    };
    b.seal(d, sealing, &profile())
}

fn write(b: &mut Binder, agent: &Keys, text: &[u8], at: u64) -> u64 {
    let d = b
        .draft_record(
            vec![Piece::Inline(text.to_vec())],
            RecordMeta::default(),
            at,
        )
        .expect("draft");
    match seal_by(b, d, agent).expect("seal") {
        Outcome::Written(n) => n,
        Outcome::Waiting => panic!("nothing should wait"),
    }
}

#[test]
fn every_record_moves_the_seal_by_its_pages_and_the_export_checks() {
    let (a, o) = (Keys::new("Agent"), Keys::new("Owner"));
    let mut b = open(&a, &o, false);
    assert_eq!(b.number(), 0, "page 0 is outside the thousand");
    assert_eq!(write(&mut b, &a, b"first", 10), 1);
    assert_eq!(write(&mut b, &a, b"second", 20), 2);
    // A record of three pieces: three pages and the service page, one seal.
    let d = b
        .draft_record(
            vec![
                Piece::Inline(vec![1; PAGE_BYTES]),
                Piece::Inline(vec![2; PAGE_BYTES]),
                Piece::Digest(Hash::sha256(b"elsewhere")),
            ],
            RecordMeta {
                media: Some("application/octet-stream".into()),
                ..RecordMeta::default()
            },
            30,
        )
        .expect("draft");
    assert_eq!(d.number(), 6);
    assert_eq!(seal_by(&mut b, d, &a).expect("seal"), Outcome::Written(6));
    assert_eq!(b.counts().work, 6);
    let x = b.export_final();
    let r = verify_bound(&x, &profile()).expect("checks");
    assert_eq!(r.number, 6);
    assert_eq!(r.mode, Mode::Local);
    assert!(
        r.runs.is_empty() && !r.has_force(1),
        "a light journal is never anchored: nothing has force (CH-25)"
    );
    assert!(
        x.pages[3..7].iter().all(|p| p.offset_ms == 30),
        "one time mark per record"
    );
}

#[test]
fn a_page_holds_2_kb_and_a_record_99_pages_and_its_service_page() {
    let (a, o) = (Keys::new("Agent"), Keys::new("Owner"));
    let b = open(&a, &o, false);
    let over = b.draft_record(
        vec![Piece::Inline(vec![0; PAGE_BYTES + 1])],
        RecordMeta::default(),
        5,
    );
    assert!(matches!(over, Err(BinderError::PageTooLarge(1))));
    let long = b.draft_record(
        vec![Piece::Inline(vec![0; 8]); BATCH_CONTENT_PAGES + 1],
        RecordMeta::default(),
        5,
    );
    assert!(matches!(long, Err(BinderError::RecordTooLong(_))));
    let full = b
        .draft_record(
            vec![Piece::Inline(vec![7; PAGE_BYTES]); BATCH_CONTENT_PAGES],
            RecordMeta::default(),
            5,
        )
        .expect("99 pages of 2 KB and the service page is one record");
    assert_eq!(full.number(), 100);
}

#[test]
fn a_record_of_several_pages_is_refused_when_its_service_page_lies() {
    let (a, o) = (Keys::new("Agent"), Keys::new("Owner"));
    let mut b = open(&a, &o, false);
    let d = b
        .draft_record(
            vec![Piece::Inline(b"a".to_vec()), Piece::Inline(b"b".to_vec())],
            RecordMeta::default(),
            5,
        )
        .expect("draft");
    // Tamper with the service page through the serialized draft.
    let mut v = serde_json::to_value(&d).expect("json");
    v["pages"][2]["body"]["manifest"]["length"] = serde_json::json!(999);
    let forged: ksg_core_v2::journal::Draft = serde_json::from_value(v).expect("draft");
    let err = seal_by(&mut b, forged, &a).expect_err("a lying service page");
    assert_eq!(err, BinderError::Stale);
}

#[test]
fn the_seal_is_the_agents_ed25519_and_a_stranger_cannot_put_it_on() {
    let (a, o, m) = (Keys::new("Agent"), Keys::new("Owner"), Keys::new("Mallory"));
    let mut b = open(&a, &o, false);
    let d = b
        .draft_record(vec![Piece::Inline(b"x".to_vec())], RecordMeta::default(), 5)
        .expect("draft");
    let bytes = d.seal_bytes().expect("bytes");
    // CH-5a (`[decision]` 02.10): the seal is Ed25519 — no ML-DSA on it; the
    // post-quantum signature is on the container, outside. A seal without the
    // agent's Ed25519 does not go on.
    let no_ed = Sealing {
        seal: set(vec![]),
        ..Sealing::default()
    };
    assert!(b.seal(d.clone(), no_ed, &profile()).is_err());
    // Mallory's seal, with Mallory's keys named: not the pinned agent.
    let stranger = Sealing {
        seal: set(m.both(&bytes)),
        ..Sealing::default()
    };
    assert!(matches!(
        b.seal(d.clone(), stranger, &profile()),
        Err(BinderError::Signature(_))
    ));
    assert_eq!(
        seal_by(&mut b, d, &a).expect("the agent's"),
        Outcome::Written(1)
    );
}

#[test]
fn a_hand_off_is_agent_to_agent_on_a_working_page_and_the_new_agent_replaces_the_old() {
    let (a, o, a2) = (Keys::new("Agent"), Keys::new("Owner"), Keys::new("Agent2"));
    let mut b = open(&a, &o, false);
    write(&mut b, &a, b"work", 5);
    let d = b
        .draft_transfer(
            TransferRecord {
                kind: TransferKind::Handoff,
                from_agent: a.id.clone(),
                to_agent: a2.party(),
                from_owner: None,
                to_owner: None,
                terms: None,
            },
            6,
        )
        .expect("draft");
    let tb = d.transfer_bytes().expect("bytes").expect("a transfer");
    // The movable seal after a hand-off is the new agent's alone (CH-3, CH-17).
    let mut sigs = a.ed(&tb);
    sigs.extend(a2.ed(&tb));
    let sealing = Sealing {
        seal: set(a2.both(&d.seal_bytes().expect("bytes"))),
        transfer: Some(set(sigs)),
        ..Sealing::default()
    };
    assert_eq!(
        b.seal(d, sealing, &profile()).expect("sealed"),
        Outcome::Written(2)
    );
    assert_eq!(b.counts().work, 2, "a hand-off is a working page (CH-16)");
    assert_eq!(b.counts().transfer, 0, "and spends none of the hundred");
    assert_eq!(b.agent().id, a2.id);
    // The old agent seals nothing any more.
    let d = b
        .draft_record(
            vec![Piece::Inline(b"late".to_vec())],
            RecordMeta::default(),
            7,
        )
        .expect("draft");
    assert!(matches!(
        seal_by(&mut b, d.clone(), &a),
        Err(BinderError::Signature(_))
    ));
    seal_by(&mut b, d, &a2).expect("the new agent seals");
    let r = verify_bound(&b.export_final(), &profile()).expect("checks");
    assert_eq!(r.transfers, vec![2]);
    assert_eq!(r.agent.id, a2.id);
}

#[test]
fn a_hand_off_without_the_new_agents_signature_is_refused() {
    let (a, o, a2) = (Keys::new("Agent"), Keys::new("Owner"), Keys::new("Agent2"));
    let mut b = open(&a, &o, false);
    let d = b
        .draft_transfer(
            TransferRecord {
                kind: TransferKind::Handoff,
                from_agent: a.id.clone(),
                to_agent: a2.party(),
                from_owner: None,
                to_owner: None,
                terms: None,
            },
            6,
        )
        .expect("draft");
    let tb = d.transfer_bytes().expect("bytes").expect("a transfer");
    let sealing = Sealing {
        seal: set(a2.both(&d.seal_bytes().expect("bytes"))),
        transfer: Some(set(a.ed(&tb))),
        ..Sealing::default()
    };
    assert!(matches!(
        b.seal(d, sealing, &profile()),
        Err(BinderError::Signature(_))
    ));
}

fn owner_change(
    b: &Binder,
    a: &Keys,
    o: &Keys,
    a2: &Keys,
    o2: &Keys,
    at: u64,
) -> (ksg_core_v2::journal::Draft, Sealing) {
    let d = b
        .draft_transfer(
            TransferRecord {
                kind: TransferKind::OwnerChange,
                from_agent: a.id.clone(),
                to_agent: a2.party(),
                from_owner: Some(o.id.clone()),
                to_owner: Some(o2.party()),
                terms: Some(Hash::sha256(b"price")),
            },
            at,
        )
        .expect("draft");
    let tb = d.transfer_bytes().expect("bytes").expect("a transfer");
    let mut sigs = a.ed(&tb);
    sigs.extend(o.ed(&tb));
    sigs.extend(a2.ed(&tb));
    sigs.extend(o2.ed(&tb));
    let sealing = Sealing {
        seal: set(a2.both(&d.seal_bytes().expect("bytes"))),
        transfer: Some(set(sigs)),
        ..Sealing::default()
    };
    (d, sealing)
}

#[test]
fn a_sale_is_agent_and_owner_on_both_sides_and_takes_a_page_of_the_hundred() {
    let (a, o) = (Keys::new("Agent"), Keys::new("Owner"));
    let (a2, o2) = (Keys::new("Agent2"), Keys::new("Owner2"));
    let mut b = open(&a, &o, false);
    let (d, s) = owner_change(&b, &a, &o, &a2, &o2, 5);
    assert_eq!(b.seal(d, s, &profile()).expect("sold"), Outcome::Written(1));
    assert_eq!(
        b.counts().transfer,
        1,
        "CH-14: a change of owner spends a page of the hundred"
    );
    assert_eq!(b.counts().work, 0);
    assert_eq!(b.owner().id, o2.id);
    // And back: every change of owner spends a page, a return included (CH-14: variant B, a free return, was rejected).
    let (d, s) = owner_change(&b, &a2, &o2, &a, &o, 6);
    b.seal(d, s, &profile()).expect("back");
    assert_eq!(b.counts().transfer, 2);
    verify_bound(&b.export_final(), &profile()).expect("checks");
}

#[test]
fn a_sale_missing_one_owner_is_refused() {
    let (a, o) = (Keys::new("Agent"), Keys::new("Owner"));
    let (a2, o2) = (Keys::new("Agent2"), Keys::new("Owner2"));
    let mut b = open(&a, &o, false);
    let (d, mut s) = owner_change(&b, &a, &o, &a2, &o2, 5);
    let tb = d.transfer_bytes().expect("bytes").expect("a transfer");
    let mut sigs = a.ed(&tb);
    sigs.extend(a2.ed(&tb));
    sigs.extend(o2.ed(&tb));
    s.transfer = Some(set(sigs));
    assert!(matches!(
        b.seal(d, s, &profile()),
        Err(BinderError::Signature(_))
    ));
}

#[test]
fn the_hundred_transfer_pages_run_out_and_the_working_pages_are_untouched() {
    let (a, o) = (Keys::new("Agent"), Keys::new("Owner"));
    let (a2, o2) = (Keys::new("Agent2"), Keys::new("Owner2"));
    let mut b = open(&a, &o, false);
    for i in 0..TRANSFER_PAGES {
        let (x, y, x2, y2) = if i % 2 == 0 {
            (&a, &o, &a2, &o2)
        } else {
            (&a2, &o2, &a, &o)
        };
        let (d, s) = owner_change(&b, x, y, x2, y2, 10 + i);
        b.seal(d, s, &profile()).expect("a transfer");
    }
    let err = b
        .draft_transfer(
            TransferRecord {
                kind: TransferKind::OwnerChange,
                from_agent: a.id.clone(),
                to_agent: a2.party(),
                from_owner: Some(o.id.clone()),
                to_owner: Some(o2.party()),
                terms: None,
            },
            1000,
        )
        .expect_err("the 101st");
    assert_eq!(err, BinderError::Full(Zone::Transfer));
    assert_eq!(b.counts().work, 0);
}

#[test]
fn a_thousand_working_pages_and_then_a_refusal() {
    let (a, o) = (Keys::new("Agent"), Keys::new("Owner"));
    let mut b = open(&a, &o, false);
    let mut at: u64 = 1;
    let mut written = 0;
    while written < WORK_PAGES {
        at += 1;
        let n = usize::try_from((WORK_PAGES - written).min(100)).expect("n");
        let pieces = if n == 1 {
            vec![Piece::Inline(at.to_be_bytes().to_vec())]
        } else {
            vec![Piece::Inline(at.to_be_bytes().to_vec()); n - 1]
        };
        let d = b
            .draft_record(pieces, RecordMeta::default(), at)
            .expect("draft");
        seal_by(&mut b, d, &a).expect("seal");
        written = b.counts().work;
    }
    assert_eq!(b.counts().work, WORK_PAGES);
    let err = b
        .draft_record(
            vec![Piece::Inline(b"one more".to_vec())],
            RecordMeta::default(),
            at + 1,
        )
        .expect_err("the 1001st");
    assert_eq!(err, BinderError::Full(Zone::Work));
    verify_bound(&b.export_final(), &profile()).expect("a full journal checks");
}

#[test]
fn the_coupling_has_two_slots_each_written_once() {
    let (a, o) = (Keys::new("Agent"), Keys::new("Owner"));
    let mut b = open(&a, &o, false);
    let d = b
        .draft_coupling(
            CouplingRecord::Pulls {
                trailer: Hash::sha256(b"A"),
                trailer_seal: Hash::sha256(b"A-seal"),
            },
            5,
        )
        .expect("slot 2");
    seal_by(&mut b, d, &a).expect("seal");
    assert_eq!(
        b.draft_coupling(
            CouplingRecord::Pulls {
                trailer: Hash::sha256(b"C"),
                trailer_seal: Hash::sha256(b"C-seal"),
            },
            6
        )
        .expect_err("no fork"),
        BinderError::CouplingUsed(2)
    );
    let d = b
        .draft_coupling(
            CouplingRecord::AttachedTo {
                leader: Hash::sha256(b"B"),
            },
            6,
        )
        .expect("slot 1");
    seal_by(&mut b, d, &a).expect("seal");
    assert_eq!(b.counts().coupling, 2);
    assert_eq!(b.counts().work, 0);
}

fn rule_types(t: &str) -> SealRule {
    SealRule {
        scope: RuleScope::Types(vec![uri(t)]),
    }
}

#[test]
fn the_rule_of_two_seals_is_a_page_the_owner_seals_too() {
    let (a, o) = (Keys::new("Agent"), Keys::new("Owner"));
    let mut b = open(&a, &o, false);
    let d = b
        .draft_rule(rule_types("urn:ksg:type:licence"), 5)
        .expect("draft");
    assert!(d.needs_owner(), "setting the rule takes the owner (CH-19)");
    // The agent alone: the rule waits (CH-20).
    assert_eq!(seal_by(&mut b, d, &a).expect("waits"), Outcome::Waiting);
    assert!(b.waiting());
    // Nothing else is written meanwhile.
    assert_eq!(
        b.draft_record(vec![Piece::Inline(b"x".to_vec())], RecordMeta::default(), 6)
            .expect_err("waiting"),
        BinderError::Waiting
    );
    assert_eq!(b.number(), 0, "the waiting page is not in the journal");
    // The owner's seal is over the same seal bytes.
    let bytes = {
        let st = b.state();
        let (d, _) = st.pending.expect("pending");
        d.seal_bytes().expect("bytes")
    };
    // A stranger's seal does not complete it.
    let m = Keys::new("Mallory");
    assert!(b.complete(set(m.ed(&bytes)), None, &profile()).is_err());
    assert!(
        b.waiting(),
        "a refused owner's seal leaves the record waiting"
    );
    assert_eq!(
        b.complete(set(o.ed(&bytes)), None, &profile())
            .expect("owner"),
        1
    );
    assert!(!b.waiting());

    // A licence now waits for the owner; another type does not.
    let meta = RecordMeta {
        content_type: Some(uri("urn:ksg:type:licence")),
        ..RecordMeta::default()
    };
    let d = b
        .draft_record(vec![Piece::Inline(b"MIT".to_vec())], meta, 7)
        .expect("draft");
    assert!(d.needs_owner());
    let bytes = d.seal_bytes().expect("bytes");
    let sealing = Sealing {
        seal: set(a.both(&bytes)),
        owner: Some(set(o.ed(&bytes))),
        ..Sealing::default()
    };
    assert_eq!(
        b.seal(d, sealing, &profile()).expect("both"),
        Outcome::Written(2)
    );
    let d = b
        .draft_record(
            vec![Piece::Inline(b"work".to_vec())],
            RecordMeta::default(),
            8,
        )
        .expect("draft");
    assert!(!d.needs_owner());
    seal_by(&mut b, d, &a).expect("the agent alone");

    let x = b.export_final();
    let r = verify_bound(&x, &profile()).expect("checks");
    assert_eq!(r.cosealed, vec![1, 2]);
    // Stripping an owner's seal from the export is caught.
    let mut stripped = x.clone();
    stripped.coseals.pop();
    assert!(verify_bound(&stripped, &profile()).is_err());
}

#[test]
fn the_agent_alone_cannot_lift_the_rule() {
    let (a, o) = (Keys::new("Agent"), Keys::new("Owner"));
    let mut b = open(&a, &o, false);
    let d = b
        .draft_rule(
            SealRule {
                scope: RuleScope::All,
            },
            5,
        )
        .expect("draft");
    let bytes = d.seal_bytes().expect("bytes");
    b.seal(
        d,
        Sealing {
            seal: set(a.both(&bytes)),
            owner: Some(set(o.ed(&bytes))),
            ..Sealing::default()
        },
        &profile(),
    )
    .expect("set");
    let d = b
        .draft_rule(
            SealRule {
                scope: RuleScope::Lifted,
            },
            6,
        )
        .expect("draft");
    assert!(d.needs_owner());
    assert_eq!(seal_by(&mut b, d, &a).expect("waits"), Outcome::Waiting);
    b.withdraw().expect("withdrawn");
    assert!(!b.waiting());
    assert_eq!(b.number(), 1);
}

/// Moves the journal to Pro: the owner seals the form page, and only then is
/// its seal anchored (CH-26).
fn to_pro(b: &mut Binder, a: &Keys, o: &Keys, at: u64) {
    let d = b.draft_form(Mode::Pro, at).expect("form page");
    assert!(d.needs_owner(), "a change of form takes the owner (CH-26)");
    let bytes = d.seal_bytes().expect("bytes");
    let hash = d.seal_hash().expect("hash");
    assert_eq!(
        seal_by(b, d, a).expect("the agent's part"),
        Outcome::Waiting,
        "without the owner the journal stays light"
    );
    b.complete(set(o.ed(&bytes)), Some(anchor(hash)), &profile())
        .expect("the owner confirms, then the anchor");
}

#[test]
fn light_takes_no_anchor_and_goes_pro_only_with_the_owners_seal() {
    let (a, o) = (Keys::new("Agent"), Keys::new("Owner"));
    let mut b = open(&a, &o, false);
    write(&mut b, &a, b"local 1", 5);
    // An anchor in the light form: refused (CH-22).
    let d = b
        .draft_record(vec![Piece::Inline(b"x".to_vec())], RecordMeta::default(), 6)
        .expect("draft");
    let with_anchor = Sealing {
        seal: set(a.both(&d.seal_bytes().expect("bytes"))),
        anchor: Some(anchor(d.seal_hash().expect("hash"))),
        ..Sealing::default()
    };
    assert_eq!(
        b.seal(d, with_anchor, &profile()).expect_err("light"),
        BinderError::AnchorInLocal
    );
    // The form page without the owner: it waits, nothing is anchored — and
    // an anchor made before the owner confirms is refused (CH-26).
    let d = b.draft_form(Mode::Pro, 7).expect("form");
    let early = Sealing {
        seal: set(a.both(&d.seal_bytes().expect("bytes"))),
        anchor: Some(anchor(d.seal_hash().expect("hash"))),
        ..Sealing::default()
    };
    assert_eq!(
        b.seal(d.clone(), early, &profile()).expect_err("early"),
        BinderError::AnchoredBeforeOwner
    );
    assert_eq!(seal_by(&mut b, d, &a).expect("waits"), Outcome::Waiting);
    assert!(!b.is_pro());
    // The owner refuses: withdrawn, still light, nothing written (CH-26).
    b.withdraw().expect("refused");
    assert!(!b.is_pro());
    assert_eq!(b.number(), 1);
    // The owner confirms.
    to_pro(&mut b, &a, &o, 8);
    assert!(b.is_pro());
    // Pro: every seal anchored, or refused (CH-7).
    let d = b
        .draft_record(
            vec![Piece::Inline(b"pro".to_vec())],
            RecordMeta::default(),
            9,
        )
        .expect("draft");
    let no_anchor = Sealing {
        seal: set(a.both(&d.seal_bytes().expect("bytes"))),
        ..Sealing::default()
    };
    assert_eq!(
        b.seal(d.clone(), no_anchor, &profile())
            .expect_err("no anchor"),
        BinderError::NoAnchor
    );
    let wrong = Sealing {
        seal: set(a.both(&d.seal_bytes().expect("bytes"))),
        anchor: Some(anchor(Hash::sha256(b"other"))),
        ..Sealing::default()
    };
    assert_eq!(
        b.seal(d.clone(), wrong, &profile())
            .expect_err("wrong anchor"),
        BinderError::WrongAnchor
    );
    seal_by(&mut b, d, &a).expect("anchored");
    let r = verify_bound(&b.export_final(), &profile()).expect("checks");
    assert_eq!(r.mode, Mode::Pro);
    assert!(!r.has_force(1), "the light page is not anchored (CH-25)");
    assert!(
        r.has_force(2) && r.has_force(3),
        "the form page and the Pro page are"
    );
    assert_eq!(r.runs, vec![(2, 3)], "one run, no gap");
}

#[test]
fn only_the_owner_takes_it_back_to_light_and_the_runs_break_at_the_gap() {
    let (a, o) = (Keys::new("Agent"), Keys::new("Owner"));
    let mut b = open(&a, &o, false);
    to_pro(&mut b, &a, &o, 5); // page 1
    write(&mut b, &a, b"pro 1", 6); // page 2 — anchored by seal_by in Pro
                                    // Back to light: the agent alone waits; the owner seals it (CH-27).
    let d = b.draft_form(Mode::Local, 7).expect("form"); // page 3
    assert!(d.needs_owner());
    let bytes = d.seal_bytes().expect("bytes");
    assert_eq!(seal_by(&mut b, d, &a).expect("waits"), Outcome::Waiting);
    b.complete(set(o.ed(&bytes)), None, &profile())
        .expect("the owner takes it back");
    assert!(!b.is_pro());
    write(&mut b, &a, b"light again", 8); // page 4, not anchored
    to_pro(&mut b, &a, &o, 9); // page 5
    write(&mut b, &a, b"pro 2", 10); // page 6
    assert_eq!(
        b.draft_form(Mode::Pro, 11).expect_err("already"),
        BinderError::FormUnchanged(Mode::Pro)
    );
    let r = verify_bound(&b.export_final(), &profile()).expect("checks");
    assert_eq!(
        r.runs,
        vec![(1, 2), (5, 6)],
        "anchored records one after another confirm their links; the light gap breaks the run (CH-25)"
    );
    assert!(!r.has_force(3) && !r.has_force(4));
    assert_eq!(
        r.counts.work, 6,
        "every change of form spends a working page (CH-23)"
    );
}

#[test]
fn in_pro_an_artefact_takes_the_owner_and_in_light_it_does_not() {
    let (a, o) = (Keys::new("Agent"), Keys::new("Owner"));
    let artefact = RecordMeta {
        kind: RecordKind::ArtifactOrRights,
        ..RecordMeta::default()
    };
    let mut b = open(&a, &o, false);
    let d = b
        .draft_record(
            vec![Piece::Inline(b"licence".to_vec())],
            artefact.clone(),
            5,
        )
        .expect("draft");
    assert!(!d.needs_owner(), "light: the owner is not asked (CH-29)");
    seal_by(&mut b, d, &a).expect("the agent alone");
    to_pro(&mut b, &a, &o, 6);
    let d = b
        .draft_record(vec![Piece::Inline(b"rights".to_vec())], artefact, 7)
        .expect("draft");
    assert!(d.needs_owner(), "Pro: agent and owner (CH-29)");
    let d2 = b
        .draft_record(
            vec![Piece::Inline(b"work".to_vec())],
            RecordMeta::default(),
            7,
        )
        .expect("draft");
    assert!(!d2.needs_owner(), "work stays the agent's in Pro too");
    let bytes = d.seal_bytes().expect("bytes");
    let hash = d.seal_hash().expect("hash");
    let sealing = Sealing {
        seal: set(a.both(&bytes)),
        owner: Some(set(o.ed(&bytes))),
        anchor: Some(anchor(hash)),
        ..Sealing::default()
    };
    b.seal(d, sealing, &profile()).expect("both");
    let r = verify_bound(&b.export_final(), &profile()).expect("checks");
    assert_eq!(r.cosealed, vec![2, 3], "the form page and the rights");
}

#[test]
fn an_export_with_a_page_changed_or_the_seal_replaced_is_refused() {
    let (a, o, m) = (Keys::new("Agent"), Keys::new("Owner"), Keys::new("Mallory"));
    let mut b = open(&a, &o, false);
    write(&mut b, &a, b"one", 5);
    write(&mut b, &a, b"two", 6);
    let x: BoundExport = b.export_final();
    let mut changed = x.clone();
    if let ksg_core_v2::journal::Body::Content { content, .. } = &mut changed.pages[1].body {
        *content = Piece::Inline(b"ONE".to_vec());
    }
    assert!(verify_bound(&changed, &profile()).is_err());
    // Mallory re-seals it with her own keys: the seal is checked against the
    // agent pinned in page 0.
    let mut resealed = x.clone();
    resealed.seal.signatures =
        set(m.both(&ksg_core_v2::canonical::canonical_bytes(&resealed.seal).expect("b")));
    assert!(verify_bound(&resealed, &profile()).is_err());
    let mut dropped = x;
    dropped.pages.pop();
    assert!(
        verify_bound(&dropped, &profile()).is_err(),
        "a dropped page"
    );
}

#[test]
fn one_page_is_shown_with_its_proof_under_the_seal() {
    let (a, o) = (Keys::new("Agent"), Keys::new("Owner"));
    let mut b = open(&a, &o, false);
    write(&mut b, &a, b"one", 5);
    write(&mut b, &a, b"two", 6);
    write(&mut b, &a, b"three", 7);
    let p = b.export_one(2).expect("page 2");
    verify_bound_point(&p, &container(), &a.party(), &profile()).expect("under the seal");
    let mut forged = p.clone();
    forged.page.offset_ms = 99;
    assert!(verify_bound_point(&forged, &container(), &a.party(), &profile()).is_err());
    assert!(verify_bound_point(&p, &Hash::sha256(b"other"), &a.party(), &profile()).is_err());
}

#[test]
fn up_to_24_pages_go_out_in_one_export_and_count_once() {
    // `[decision]` 06.10: one pointwise export carries 1 to 24 pages; the
    // journal allows twelve exports, not twelve pages.
    let (a, o) = (Keys::new("Agent"), Keys::new("Owner"));
    let mut b = open(&a, &o, false);
    for i in 0..30u64 {
        write(&mut b, &a, format!("page {i}").as_bytes(), 5 + i);
    }
    let pages: Vec<u64> = (1..=24).collect();
    let out = b.export_pages(&pages).expect("24 pages in one export");
    assert_eq!(out.len(), 24);
    for (p, seq) in out.iter().zip(&pages) {
        assert_eq!(p.page.seq, *seq);
        verify_bound_point(p, &container(), &a.party(), &profile()).expect("each under the seal");
    }
    assert_eq!(b.disclosed(), 1, "one export, not 24");

    // Refused, and nothing counted: none, 25, a page twice, a page not there.
    let too_many: Vec<u64> = (1..=25).collect();
    assert!(matches!(
        b.export_pages(&[]),
        Err(BinderError::PageCount(0))
    ));
    assert!(matches!(
        b.export_pages(&too_many),
        Err(BinderError::PageCount(25))
    ));
    assert!(matches!(
        b.export_pages(&[2, 2]),
        Err(BinderError::PageCount(2))
    ));
    assert!(matches!(
        b.export_pages(&[1, 999]),
        Err(BinderError::NoSuchPage(999))
    ));
    assert_eq!(b.disclosed(), 1);

    // Eleven more exports, then the twelve are spent — single and multi alike.
    for i in 0..10u64 {
        b.export_pages(&[i, i + 1]).expect("within twelve");
    }
    b.export_one(3).expect("the twelfth");
    assert_eq!(b.disclosed(), POINT_LIMIT);
    assert!(matches!(
        b.export_pages(&[1]),
        Err(BinderError::PointLimit(POINT_LIMIT))
    ));
    assert!(matches!(
        b.export_one(1),
        Err(BinderError::PointLimit(POINT_LIMIT))
    ));

    // `[decision]` 19.09 (CT-21), confirmed 06.10: the 13th goes through the
    // export to the expert — outside the twelve, up to 24 pages, nothing counted.
    let expert = b
        .expert_pages(&[4, 5, 6])
        .expect("the expert past the twelve");
    assert_eq!(expert.len(), 3);
    for p in &expert {
        verify_bound_point(p, &container(), &a.party(), &profile()).expect("under the seal");
    }
    assert_eq!(b.disclosed(), POINT_LIMIT, "the expert counts nothing");
    assert!(matches!(
        b.expert_pages(&too_many),
        Err(BinderError::PageCount(25))
    ));
}

#[test]
fn the_time_mark_grows_and_ten_identical_records_owe_a_confirmation() {
    let (a, o) = (Keys::new("Agent"), Keys::new("Owner"));
    let mut b = open(&a, &o, false);
    write(&mut b, &a, b"x", 5);
    assert!(matches!(
        b.draft_record(vec![Piece::Inline(b"y".to_vec())], RecordMeta::default(), 5),
        Err(BinderError::OffsetNotGrowing { .. })
    ));
    for i in 0..9 {
        write(&mut b, &a, b"x", 6 + i);
    }
    assert_eq!(
        b.draft_record(
            vec![Piece::Inline(b"z".to_vec())],
            RecordMeta::default(),
            50
        )
        .expect_err("owed"),
        BinderError::ConfirmationOwed
    );
    let d = b.draft_confirmation(50).expect("confirmation");
    seal_by(&mut b, d, &a).expect("confirmed");
    write(&mut b, &a, b"x", 51);
    verify_bound(&b.export_final(), &profile()).expect("checks");
}

#[test]
fn the_state_restores_through_the_same_check_and_a_waiting_record_survives() {
    let (a, o) = (Keys::new("Agent"), Keys::new("Owner"));
    let mut b = open(&a, &o, false);
    write(&mut b, &a, b"one", 5);
    let d = b
        .draft_rule(
            SealRule {
                scope: RuleScope::All,
            },
            6,
        )
        .expect("draft");
    seal_by(&mut b, d, &a).expect("waits");
    let json = serde_json::to_vec(&b.state()).expect("state");
    let back: ksg_core_v2::journal::BinderState = serde_json::from_slice(&json).expect("state");
    let mut r = Binder::restore(back, &profile()).expect("restored");
    assert!(r.waiting());
    assert_eq!(r.number(), 1);
    let bytes = {
        let (d, _) = r.state().pending.expect("pending");
        d.seal_bytes().expect("bytes")
    };
    assert_eq!(
        r.complete(set(o.ed(&bytes)), None, &profile())
            .expect("owner"),
        2
    );
}

/// The worst case the container must hold: every page of every zone written,
/// every working page carrying its full 2 KB. Prints the size; the container's
/// constant size is set from this number (`ksg-container` `STORE_SIZE`).
#[test]
fn a_full_journal_of_1_1000_100_2_measured() {
    let (a, o) = (Keys::new("Agent"), Keys::new("Owner"));
    let (a2, o2) = (Keys::new("Agent2"), Keys::new("Owner2"));
    let mut b = open(&a, &o, true);
    let mut at: u64 = 1;
    let mut cur = (&a, &o, &a2, &o2);
    for _ in 0..TRANSFER_PAGES {
        at += 1;
        let (d, mut s) = owner_change(&b, cur.0, cur.1, cur.2, cur.3, at);
        s.anchor = Some(anchor(d.seal_hash().expect("h")));
        b.seal(d, s, &profile()).expect("transfer");
        cur = (cur.2, cur.3, cur.0, cur.1);
    }
    for c in [
        CouplingRecord::AttachedTo {
            leader: Hash::sha256(b"L"),
        },
        CouplingRecord::Pulls {
            trailer: Hash::sha256(b"T"),
            trailer_seal: Hash::sha256(b"S"),
        },
    ] {
        at += 1;
        let d = b.draft_coupling(c, at).expect("coupling");
        seal_by(&mut b, d, cur.0).expect("seal");
    }
    // Working pages at full 2 KB, in records of 99 pages and a service page;
    // bytes differ per page so nothing repeats.
    while b.counts().work < WORK_PAGES {
        at += 1;
        let left = usize::try_from(WORK_PAGES - b.counts().work).expect("n");
        let n = left.min(100);
        let pieces: Vec<Piece> = (0..n.saturating_sub(1).max(1))
            .map(|i| {
                let mut v = vec![0u8; PAGE_BYTES];
                v[..8].copy_from_slice(&at.to_be_bytes());
                v[8] = u8::try_from(i % 256).expect("byte");
                Piece::Inline(v)
            })
            .collect();
        let d = b
            .draft_record(pieces, RecordMeta::default(), at)
            .expect("draft");
        seal_by(&mut b, d, cur.0).expect("seal");
    }
    assert_eq!(b.counts().work, WORK_PAGES);
    assert_eq!(b.counts().transfer, TRANSFER_PAGES);
    assert_eq!(b.counts().coupling, 2);
    let json = serde_json::to_vec(&b.state()).expect("json");
    let pages_only: usize = b
        .state()
        .export
        .pages
        .iter()
        .map(|p| serde_json::to_vec(p).expect("p").len())
        .sum();
    println!(
        "FULL JOURNAL: state {} bytes ({:.2} MiB); pages {} bytes; number {}",
        json.len(),
        json.len() as f64 / 1048576.0,
        pages_only,
        b.number()
    );
    verify_bound(&b.export_final(), &profile()).expect("checks");
}

/// What each zone of a full journal takes, with anchors the size of a real
/// Solana proof — the numbers the container's store size is set from.
#[test]
fn a_full_journal_by_zone_measured() {
    let (a, o) = (Keys::new("Agent"), Keys::new("Owner"));
    let (a2, o2) = (Keys::new("Agent2"), Keys::new("Owner2"));
    let mut b = open(&a, &o, true);
    let mut at: u64 = 1;
    let mut cur = (&a, &o, &a2, &o2);
    let size = |b: &Binder| serde_json::to_vec(&b.state()).expect("json").len();
    let s0 = size(&b);
    for _ in 0..TRANSFER_PAGES {
        at += 1;
        let (d, mut s) = owner_change(&b, cur.0, cur.1, cur.2, cur.3, at);
        s.anchor = Some(anchor(d.seal_hash().expect("h")));
        b.seal(d, s, &profile()).expect("transfer");
        cur = (cur.2, cur.3, cur.0, cur.1);
    }
    let s1 = size(&b);
    println!(
        "ZONES: opening {s0}; transfer zone +{} ({:.2} MiB); seals {}",
        s1 - s0,
        (s1 - s0) as f64 / 1_048_576.0,
        b.number()
    );
}

// --- core v2 §7.2: the seal's time comes from the one rule ---------------------

/// A reader of the test anchor kind: confirms `anchored_at`, or refuses all.
#[derive(Debug)]
struct TestReader {
    honest: bool,
}

impl ksg_core_v2::anchor::AttestationVerifier for TestReader {
    fn verify(&self, a: &EntryAnchor) -> Result<Timestamp, ksg_core_v2::error::Invalid> {
        if self.honest {
            Ok(a.anchored_at.clone())
        } else {
            Err(ksg_core_v2::error::Invalid::Schema(
                "the network does not confirm",
            ))
        }
    }
    fn handles(&self, kind: &Uri) -> bool {
        kind.as_str() == "urn:ksg:anchor:test"
    }
}

#[test]
fn the_anchors_of_seals_are_read_by_the_one_rule_of_the_core() {
    let (a, o) = (Keys::new("Agent"), Keys::new("Owner"));
    let mut b = open(&a, &o, true);
    write(&mut b, &a, b"first", 10);
    let x = b.export_final();

    // Without a reader the journal stands and no time is claimed.
    let (_, none) = ksg_core_v2::journal::verify_bound_read(&x, &profile(), None).expect("checks");
    assert!(none.iter().all(|r| r.not_after.is_none()));

    // With a reader every anchored record gets the moment the network proves.
    let honest = TestReader { honest: true };
    let (_, read) =
        ksg_core_v2::journal::verify_bound_read(&x, &profile(), Some(&honest)).expect("checks");
    assert!(!read.is_empty(), "a Pro journal has anchored records");
    assert!(read
        .iter()
        .all(|r| r.not_after.as_ref().map(Timestamp::as_str) == Some("2026-09-30T10:00:00.000Z")));

    // A forged anchor is a refusal, not "no time".
    let liar = TestReader { honest: false };
    assert!(ksg_core_v2::journal::verify_bound_read(&x, &profile(), Some(&liar)).is_err());
}

/// Audit of 30.09, Ya-6: the journal carries its own format version, and a page
/// or a seal of another format is refused — before its signature is weighed.
#[test]
fn a_page_or_a_seal_of_another_format_is_refused() {
    use ksg_core_v2::journal::{check_format, FORMAT_V};
    assert!(check_format(FORMAT_V).is_ok());
    assert!(check_format(FORMAT_V + 1).is_err());
    let (a, o) = (Keys::new("Agent"), Keys::new("Owner"));
    let mut b = open(&a, &o, false);
    write(&mut b, &a, b"first", 10);
    let x = b.export_final();
    assert!(verify_bound(&x, &profile()).is_ok());
    let mut page = x.clone();
    page.pages[1].v = FORMAT_V + 1;
    assert_eq!(
        verify_bound(&page, &profile()).unwrap_err(),
        BinderError::Misplaced("journal format version")
    );
    // The movable seal is recomputed from the pages first, so a seal of
    // another version is refused there; `check_seal` refuses it again by its
    // version wherever a seal is presented on its own.
    let mut seal = x;
    seal.seal.v = FORMAT_V + 1;
    assert!(verify_bound(&seal, &profile()).is_err());
}

/// §8.1-bis (KS-7): number 0 is page 0 of the journal and nothing else —
/// an export whose page 0 is not the opening is refused for that; a second
/// opening is refused by the record's shape (an opening is a service page,
/// and a service page stands only after content) before `Chain::place`
/// could say "only page 0 opens", which stays as the second line.
#[test]
fn only_page_zero_opens_and_page_zero_only_opens() {
    let (a, o) = (Keys::new("Agent"), Keys::new("Owner"));
    let mut b = open(&a, &o, false);
    write(&mut b, &a, b"first", 10);
    let x = b.export_final();
    assert!(verify_bound(&x, &profile()).is_ok());

    let mut work_first = x.clone();
    work_first.pages.swap(0, 1);
    assert_eq!(
        verify_bound(&work_first, &profile()).unwrap_err(),
        BinderError::Misplaced("page 0 must be the opening")
    );

    let mut two_openings = x.clone();
    // Page 1 as it stands, but carrying an opening: the refusal is for that.
    two_openings.pages[1].body = x.pages[0].body.clone();
    assert_eq!(
        verify_bound(&two_openings, &profile()).unwrap_err(),
        BinderError::Misplaced("a service page stands only after content")
    );
}

/// §7.2-sexies, K-15 (KS-7): the four-level limit is the **channel's**; the
/// chain of ownership is not limited by it — ten sales, ten owners in a
/// row, and the journal checks (its own limit is the hundred transfer pages).
#[test]
fn the_chain_of_ownership_goes_past_four_owners() {
    let names: Vec<(String, String)> = (0..11)
        .map(|i| (format!("Agent{i}"), format!("Owner{i}")))
        .collect();
    let keys: Vec<(Keys, Keys)> = names
        .iter()
        .map(|(a, o)| (Keys::new(a), Keys::new(o)))
        .collect();
    let mut b = open(&keys[0].0, &keys[0].1, false);
    for i in 0..10 {
        let (a, o) = &keys[i];
        let (a2, o2) = &keys[i + 1];
        let (d, s) = owner_change(&b, a, o, a2, o2, 10 + i as u64);
        b.seal(d, s, &profile()).expect("sold");
        assert_eq!(b.owner().id, o2.id);
    }
    assert_eq!(b.counts().transfer, 10);
    verify_bound(&b.export_final(), &profile()).expect("ten owners check");
}

/// Every refusal of a transfer page (`Chain::check_transfer`), one by one —
/// the mutation run of 16.10 found none of them under a test.
#[test]
fn a_transfer_that_does_not_hold_is_refused_for_its_own_reason() {
    let (a, o) = (Keys::new("Agent"), Keys::new("Owner"));
    let (a2, o2) = (Keys::new("Agent2"), Keys::new("Owner2"));
    let b = open(&a, &o, false);
    let sale =
        |from_agent: Uri, to_agent: Party, from_owner: Option<Uri>, to_owner| TransferRecord {
            kind: TransferKind::OwnerChange,
            from_agent,
            to_agent,
            from_owner,
            to_owner,
            terms: None,
        };
    let handoff = |to_agent: Party, from_owner: Option<Uri>| TransferRecord {
        kind: TransferKind::Handoff,
        from_agent: a.id.clone(),
        to_agent,
        from_owner,
        to_owner: None,
        terms: None,
    };
    // The agent kept, but with keys of its own name that are not its keys.
    let impostor = Ed25519Signer::from_seed(
        a.ed.public().kid.clone(),
        *Hash::sha256(b"not the agent's seed").as_bytes(),
    );
    let same_name = Party {
        id: a.id.clone(),
        keys: vec![impostor.public(), a.pq_pub.clone()],
    };
    let cases: Vec<(TransferRecord, &str)> = vec![
        (
            sale(
                a2.id.clone(),
                a2.party(),
                Some(o.id.clone()),
                Some(o2.party()),
            ),
            "the handing agent is not the current one",
        ),
        (
            handoff(a.party(), None),
            "a hand-off to oneself is not a hand-off",
        ),
        (
            sale(
                a.id.clone(),
                same_name,
                Some(o.id.clone()),
                Some(o2.party()),
            ),
            "the agent kept across a change of owner keeps its keys",
        ),
        (
            handoff(a2.party(), Some(o.id.clone())),
            "a hand-off between agents of one owner names no owner",
        ),
        (
            sale(
                a.id.clone(),
                a2.party(),
                Some(o2.id.clone()),
                Some(o2.party()),
            ),
            "the handing owner is not the current one",
        ),
        (
            sale(a.id.clone(), a2.party(), Some(o.id.clone()), None),
            "a change of owner names the new owner",
        ),
        (
            sale(
                a.id.clone(),
                a2.party(),
                Some(o.id.clone()),
                Some(o.party()),
            ),
            "the owner does not change: that is a hand-off",
        ),
    ];
    for (t, why) in cases {
        assert_eq!(
            b.draft_transfer(t, 5).map(|_| ()).unwrap_err(),
            BinderError::Transfer(why),
            "{why}"
        );
    }
}

/// Every refusal of a record's service page (`Chain::check_manifest`) that
/// an export can carry — the mutation run of 16.10 found none of them under a
/// test: a verifier must refuse a service page that does not describe its
/// record.
#[test]
fn a_service_page_that_does_not_describe_its_record_is_refused() {
    let (a, o) = (Keys::new("Agent"), Keys::new("Owner"));
    let mut b = open(&a, &o, false);
    let d = b
        .draft_record(
            vec![Piece::Inline(b"a".to_vec()), Piece::Inline(b"b".to_vec())],
            RecordMeta::default(),
            5,
        )
        .expect("draft");
    seal_by(&mut b, d, &a).expect("sealed");
    let x = serde_json::to_value(b.export_final()).expect("json");
    assert!(verify_bound(&serde_json::from_value(x.clone()).unwrap(), &profile()).is_ok());
    // Page 3 is the service page of the record on pages 1–3.
    assert!(
        x["pages"][3]["body"]["manifest"].is_object(),
        "{}",
        x["pages"][3]
    );
    let cases: Vec<(&str, serde_json::Value, &str)> = vec![
        ("format", serde_json::json!(999), "an unknown format"),
        (
            "pages",
            serde_json::json!(3),
            "the record's number, first page or page count",
        ),
        (
            "length",
            serde_json::json!(999),
            "the record's hash or length",
        ),
        (
            "offset_ms",
            serde_json::json!(6),
            "the split rule or the time mark",
        ),
        (
            "author",
            serde_json::json!("did:key:zStranger"),
            "the author is not the agent",
        ),
    ];
    for (field, value, why) in cases {
        let mut forged = x.clone();
        forged["pages"][3]["body"]["manifest"][field] = value;
        let forged: BoundExport = serde_json::from_value(forged).expect("still an export");
        assert_eq!(
            verify_bound(&forged, &profile()).unwrap_err(),
            BinderError::Manifest(why),
            "{field}"
        );
    }
}

/// Each field that makes page 0 the opening is checked on its own
/// (`Chain::open`; the mutation run of 16.10 found them held only together).
#[test]
fn every_mark_of_the_opening_is_checked_on_its_own() {
    let (a, o) = (Keys::new("Agent"), Keys::new("Owner"));
    let mut b = open(&a, &o, false);
    write(&mut b, &a, b"first", 10);
    let x = serde_json::to_value(b.export_final()).expect("json");
    let work_zone = x["pages"][1]["zone"].clone();
    let cases: Vec<(&str, Option<&str>, serde_json::Value)> = vec![
        ("seq", None, serde_json::json!(1)),
        ("zone", None, work_zone),
        ("slot", None, serde_json::json!(1)),
        ("batch", Some("id"), serde_json::json!(1)),
        ("batch", Some("index"), serde_json::json!(1)),
        ("batch", Some("of"), serde_json::json!(2)),
    ];
    for (field, inner, value) in cases {
        let mut forged = x.clone();
        match inner {
            None => forged["pages"][0][field] = value,
            Some(i) => forged["pages"][0][field][i] = value,
        }
        let forged: BoundExport = serde_json::from_value(forged).expect("still an export");
        assert_eq!(
            verify_bound(&forged, &profile()).unwrap_err(),
            BinderError::Misplaced("the opening is page 0, record 0"),
            "{field} {inner:?}"
        );
    }
}

/// A journal of four kinds of page: page 0, a one-page record, a record of
/// two pages and its service page, a sale.
fn mixed(a: &Keys, o: &Keys) -> Binder {
    let (a2, o2) = (Keys::new("Agent2"), Keys::new("Owner2"));
    let mut b = open(a, o, false);
    write(&mut b, a, b"first", 10);
    let d = b
        .draft_record(
            vec![Piece::Inline(b"a".to_vec()), Piece::Inline(b"b".to_vec())],
            RecordMeta::default(),
            20,
        )
        .expect("draft");
    seal_by(&mut b, d, a).expect("sealed");
    let (d, s) = owner_change(&b, a, o, &a2, &o2, 30);
    b.seal(d, s, &profile()).expect("sold");
    b
}

/// Each guard of the replay names its own refusal when only its own field is
/// wrong (mutation run 2 of 16.10: these were held only by later checks), and
/// pages take the slots they are numbered by.
#[test]
fn every_guard_of_the_replay_names_its_own_refusal() {
    let (a, o) = (Keys::new("Agent"), Keys::new("Owner"));
    let b = mixed(&a, &o);
    let x = serde_json::to_value(b.export_final()).expect("json");
    assert!(verify_bound(&serde_json::from_value(x.clone()).unwrap(), &profile()).is_ok());

    // Slots: work pages 1..4 in order, the sale the first of the hundred.
    let slots: Vec<(String, u64)> = x["pages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            (
                p["zone"].as_str().unwrap().to_owned(),
                p["slot"].as_u64().unwrap(),
            )
        })
        .collect();
    let want: Vec<(String, u64)> = [
        ("opening", 0),
        ("work", 1),
        ("work", 2),
        ("work", 3),
        ("work", 4),
        ("transfer", 1),
    ]
    .iter()
    .map(|(z, n)| ((*z).to_owned(), *n))
    .collect();
    assert_eq!(slots, want);

    let other = serde_json::json!(Hash::sha256(b"another").to_multihash());
    let m = "/pages/4/body/manifest";
    let cases: Vec<(String, serde_json::Value, BinderError)> = vec![
        (
            "/pages/1/batch/id".into(),
            serde_json::json!(9),
            BinderError::BatchMark(1),
        ),
        (
            "/pages/3/batch/index".into(),
            serde_json::json!(0),
            BinderError::BatchMark(3),
        ),
        (
            "/pages/1/batch/of".into(),
            serde_json::json!(0),
            BinderError::BatchMark(1),
        ),
        (
            "/pages/1/batch/of".into(),
            serde_json::json!(99),
            BinderError::BatchMark(1),
        ),
        (
            "/pages/1/zone".into(),
            serde_json::json!("transfer"),
            BinderError::WrongPlace(1),
        ),
        (
            "/pages/1/slot".into(),
            serde_json::json!(7),
            BinderError::WrongPlace(1),
        ),
        (
            format!("{m}/batch"),
            serde_json::json!(9),
            BinderError::Manifest("the record's number, first page or page count"),
        ),
        (
            format!("{m}/first"),
            serde_json::json!(3),
            BinderError::Manifest("the record's number, first page or page count"),
        ),
        (
            format!("{m}/content_type"),
            serde_json::json!("urn:ksg:page:other:v1"),
            BinderError::Manifest("a page of another content type or kind"),
        ),
        (
            format!("{m}/prev_seal"),
            other.clone(),
            BinderError::Manifest("the previous seal or the rule in force"),
        ),
        (
            format!("{m}/rule"),
            other,
            BinderError::Manifest("the previous seal or the rule in force"),
        ),
    ];
    for (at, value, want) in cases {
        let mut forged = x.clone();
        let (parent, key) = at.rsplit_once('/').expect("a path");
        forged
            .pointer_mut(parent)
            .and_then(serde_json::Value::as_object_mut)
            .unwrap_or_else(|| panic!("{parent} missing"))
            .insert(key.to_owned(), value);
        let forged: BoundExport = serde_json::from_value(forged).expect("still an export");
        assert_eq!(verify_bound(&forged, &profile()).unwrap_err(), want, "{at}");
    }
}

/// What an export carries and nothing reads is refused: a transfer seal with
/// no transfer page to seal (`replay`, mutation run 2 of 16.10).
#[test]
fn an_export_carrying_an_unused_seal_is_refused() {
    let (a, o) = (Keys::new("Agent"), Keys::new("Owner"));
    let b = mixed(&a, &o);
    let mut x = serde_json::to_value(b.export_final()).expect("json");
    let t = x["transfers"][0].clone();
    x["transfers"].as_array_mut().unwrap().push(t);
    let forged: BoundExport = serde_json::from_value(x).expect("still an export");
    assert!(verify_bound(&forged, &profile()).is_err());
}

/// One page under the seal: the newest page itself is checkable (its number
/// equals the seal's), and a page numbered past the seal is not.
#[test]
fn the_newest_page_checks_on_its_own_and_one_past_the_seal_does_not() {
    let (a, o) = (Keys::new("Agent"), Keys::new("Owner"));
    let mut b = open(&a, &o, false);
    write(&mut b, &a, b"first", 10);
    write(&mut b, &a, b"second", 20);
    let last = b.number();
    let p = b.export_one(last).expect("the newest page");
    assert_eq!(p.page.seq, p.seal.number);
    verify_bound_point(&p, &container(), &a.party(), &profile()).expect("the newest page checks");
    let mut past = p.clone();
    past.page.seq = p.seal.number + 1;
    assert!(verify_bound_point(&past, &container(), &a.party(), &profile()).is_err());
}

/// Seals a draft with the agent's and the owner's seals.
fn seal_both(b: &mut Binder, d: ksg_core_v2::journal::Draft, a: &Keys, o: &Keys) -> u64 {
    let bytes = d.seal_bytes().expect("bytes");
    let sealing = Sealing {
        seal: set(a.both(&bytes)),
        owner: Some(set(o.ed(&bytes))),
        ..Sealing::default()
    };
    match b.seal(d, sealing, &profile()).expect("sealed") {
        Outcome::Written(n) => n,
        Outcome::Waiting => panic!("both sealed"),
    }
}

/// The rule of two seals, set and then lifted (CH-19): under it a covered
/// record takes the owner's seal, after the lift it does not — on drafting
/// and on the verifier's replay (mutation run 2 of 16.10: the lift's arm and
/// the "covered or owner's kind" condition were held by nothing).
#[test]
fn a_lifted_rule_no_longer_takes_the_owner() {
    let (a, o) = (Keys::new("Agent"), Keys::new("Owner"));
    let mut b = open(&a, &o, false);
    let d = b
        .draft_rule(rule_types("urn:ksg:type:licence"), 5)
        .expect("draft");
    seal_both(&mut b, d, &a, &o);
    let licence = || RecordMeta {
        content_type: Some(uri("urn:ksg:type:licence")),
        ..RecordMeta::default()
    };
    let d = b
        .draft_record(vec![Piece::Inline(b"MIT".to_vec())], licence(), 6)
        .expect("draft");
    assert!(d.needs_owner(), "covered by the rule");
    let covered = seal_both(&mut b, d, &a, &o);

    let lift = SealRule {
        scope: RuleScope::Lifted,
    };
    let d = b.draft_rule(lift, 7).expect("draft");
    assert!(d.needs_owner(), "lifting takes the owner too");
    let lifted = seal_both(&mut b, d, &a, &o);

    let d = b
        .draft_record(vec![Piece::Inline(b"GPL".to_vec())], licence(), 8)
        .expect("draft");
    assert!(!d.needs_owner(), "the rule is lifted");
    let free = match seal_by(&mut b, d, &a).expect("the agent alone") {
        Outcome::Written(n) => n,
        Outcome::Waiting => panic!("nothing waits after the lift"),
    };

    let r = verify_bound(&b.export_final(), &profile()).expect("checks");
    assert!(r.cosealed.contains(&covered) && r.cosealed.contains(&lifted));
    assert!(!r.cosealed.contains(&free), "{:?}", r.cosealed);
}

/// Two sales in a row take transfer slots 1 and 2 (the count of transfer
/// pages grows by one each — mutation run 2 of 16.10).
#[test]
fn two_sales_take_transfer_slots_one_and_two() {
    let (a, o) = (Keys::new("Agent"), Keys::new("Owner"));
    let (a2, o2) = (Keys::new("Agent2"), Keys::new("Owner2"));
    let mut b = open(&a, &o, false);
    let (d, s) = owner_change(&b, &a, &o, &a2, &o2, 5);
    b.seal(d, s, &profile()).expect("sold");
    let (d, s) = owner_change(&b, &a2, &o2, &a, &o, 6);
    b.seal(d, s, &profile()).expect("back");
    let x = serde_json::to_value(b.export_final()).expect("json");
    assert_eq!(x["pages"][1]["slot"], 1);
    assert_eq!(x["pages"][2]["slot"], 2);
    verify_bound(&serde_json::from_value(x).unwrap(), &profile()).expect("checks");
}

/// Page 0 with the owner's keys under another name: the parties do not hold
/// together — refused for that, even when the agent's keys are fine.
#[test]
fn an_opening_whose_owner_keys_are_not_its_own_is_refused() {
    let (a, o) = (Keys::new("Agent"), Keys::new("Owner"));
    let mut b = open(&a, &o, false);
    write(&mut b, &a, b"first", 10);
    let mut x = serde_json::to_value(b.export_final()).expect("json");
    x["pages"][0]["body"]["opening"]["owner"]["keys"][0]["kid"] =
        serde_json::json!("did:key:zSomebodyElse#ed");
    let forged: BoundExport = serde_json::from_value(x).expect("still an export");
    assert_eq!(
        verify_bound(&forged, &profile()).unwrap_err(),
        BinderError::Parties
    );
}

/// The rule of two seals over a record of several pages: covered, it takes
/// the owner; after the lift its service page names no rule and it does not
/// (`Chain::apply`, the branch of records with a service page — mutation
/// run 3 of 16.10).
#[test]
fn the_rule_reaches_records_of_several_pages_and_its_lift_too() {
    let (a, o) = (Keys::new("Agent"), Keys::new("Owner"));
    let mut b = open(&a, &o, false);
    let d = b
        .draft_rule(rule_types("urn:ksg:type:licence"), 5)
        .expect("draft");
    seal_both(&mut b, d, &a, &o);
    let licence = || RecordMeta {
        content_type: Some(uri("urn:ksg:type:licence")),
        ..RecordMeta::default()
    };
    let two = || vec![Piece::Inline(b"a".to_vec()), Piece::Inline(b"b".to_vec())];
    let d = b.draft_record(two(), licence(), 6).expect("draft");
    assert!(d.needs_owner(), "a covered record of several pages");
    let covered = seal_both(&mut b, d, &a, &o);
    let d = b
        .draft_rule(
            SealRule {
                scope: RuleScope::Lifted,
            },
            7,
        )
        .expect("draft");
    seal_both(&mut b, d, &a, &o);
    let d = b.draft_record(two(), licence(), 8).expect("draft");
    assert!(!d.needs_owner(), "lifted");
    let free = match seal_by(&mut b, d, &a).expect("the agent alone") {
        Outcome::Written(n) => n,
        Outcome::Waiting => panic!("nothing waits after the lift"),
    };
    let x = b.export_final();
    let last = serde_json::to_value(x.pages.last().expect("a page")).expect("json");
    assert!(
        last["body"]["manifest"].get("rule").is_none(),
        "the service page after the lift names no rule: {}",
        last["body"]["manifest"]
    );
    let r = verify_bound(&x, &profile()).expect("checks");
    // By record: the rule (1), the covered record (2), the lift (3); the
    // record after the lift (4) is the agent's alone.
    assert_eq!(r.cosealed, vec![1, 2, 3]);
    assert!(covered < free);
}

/// An anchor of nothing in the journal is refused even when every other seal
/// is used (`replay`, mutation run 3 of 16.10).
#[test]
fn an_extra_anchor_alone_refuses_the_export() {
    let (a, o) = (Keys::new("Agent"), Keys::new("Owner"));
    let mut b = open(&a, &o, true);
    write(&mut b, &a, b"first", 10);
    let x = b.export_final();
    assert!(verify_bound(&x, &profile()).is_ok());
    let mut extra = x.clone();
    let mut a2 = extra.anchors[0].clone();
    a2.batch += 100;
    extra.anchors.push(a2);
    assert_eq!(
        verify_bound(&extra, &profile()).unwrap_err(),
        BinderError::Export("a seal or an anchor of nothing in the journal")
    );
}
