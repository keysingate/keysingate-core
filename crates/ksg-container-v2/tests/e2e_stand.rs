//! E2E on the stand: whole lives of a container, every step through a button.
mod stand;

use ksg_container_v2::container::{Evidence, Stopped, UnloadRoute};
use ksg_container_v2::dispute::{Filing, Settlement};
use ksg_container_v2::expert::{
    ExpertDisclosure, ExpertEntry, ExpertRecord, Scope, EXPERT_ENTRY_PAGE,
};
use ksg_container_v2::followup::Task;
use ksg_container_v2::layers::Level;
use ksg_container_v2::voluntary::{ArbiterAttestation, OpeningDeclaration, VoluntaryOpening};
use ksg_container_v2::{Attachment, Kind, Operation as Op, Role, Status, Where, Work};
use ksg_core_v2::anchor::Attestation;
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::Ed25519Signer;
use ksg_core_v2::crypto::sign::{sign_doc, SignatureSet};
use ksg_core_v2::doc::Class;
use ksg_core_v2::doc::ClassPromotion;
use stand::uri;
use stand::EventKind;
use stand::{Page, Stand, Who};

/// Print → packet → buyer's key → initiation → journal → work → artefact →
/// finalization → full export.
fn main_life(s: &mut Stand) {
    s.press(Op::ApplyPacket, &[Who::Issuer], Evidence::None, Page::None)
        .expect("packet");
    assert_eq!(s.c.status(), Status::Packeted);

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
    assert_eq!(s.c.status(), Status::BuyerKeyed);

    s.press(
        Op::Initiate,
        &[Who::Client, Who::Owner],
        Evidence::Initiation { at: Where::Inside },
        Page::None,
    )
    .expect("initiation");
    assert_eq!(s.c.status(), Status::Initiated);

    s.press(
        Op::OpenJournal,
        &[Who::Client],
        Evidence::None,
        Page::Opening,
    )
    .expect("journal opened");
    assert_eq!(s.c.status(), Status::InWork);
}

/// A record of work on the agent's own account, signed at the reader.
fn record_work(s: &mut Stand, did: &str) {
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
    .expect("record of work");
}

fn attach(s: &mut Stand) {
    let a = Attachment {
        artifact: uri(stand::ARTIFACT),
        kind: Kind::Media {
            mime: "image/png".into(),
        },
        content_hash: Hash::sha256(b"the artefact"),
        size: 12,
        name: "artefact.png".into(),
        derived_from: vec![],
        offset_ms: stand::OFFSET,
    };
    s.press(
        Op::AttachArtifactOrRights,
        &[Who::Client, Who::Owner],
        Evidence::Artifact(Box::new(a)),
        Page::Of(EventKind::ArtifactOrRights),
    )
    .expect("artefact attached");
    assert_eq!(s.c.artifact_seals().len(), 1, "sealed by the container");
}

fn sc_main_life() -> Stand {
    let mut s = Stand::new(Class::Heavy, 1);
    main_life(&mut s);
    record_work(&mut s, "first step");
    record_work(&mut s, "second step");
    attach(&mut s);

    // The pointwise export (24.09): one named page leaves, the container lives
    // on. The owner may, the agent may — the product description §15.
    s.press(
        Op::ExportPoint,
        &[Who::Owner],
        Evidence::Point { number: 1 },
        Page::None,
    )
    .expect("pointwise export by the owner");
    let page = s.c.take_point().expect("the page");
    assert_eq!(page.page.seq, 1);
    assert!(s.c.take_point().is_none(), "handed out once");
    s.press(
        Op::ExportPoint,
        &[Who::Client],
        Evidence::Point { number: 2 },
        Page::None,
    )
    .expect("pointwise export by the agent");
    assert_eq!(s.c.take_point().expect("the page").page.seq, 2);
    // Several pages in one export (`[decision]` 06.10): up to 24, the
    // container lives on, the pages are handed out once.
    s.press(
        Op::ExportPoint,
        &[Who::Owner],
        Evidence::Points {
            numbers: vec![1, 2],
        },
        Page::None,
    )
    .expect("pointwise export of two pages");
    let pages = s.c.take_points().expect("the pages");
    assert_eq!(
        pages.iter().map(|p| p.page.seq).collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert!(s.c.take_points().is_none(), "handed out once");
    // Nobody else: the buyer holds no seat for it.
    assert!(s
        .press(
            Op::ExportPoint,
            &[Who::Buyer],
            Evidence::Point { number: 1 },
            Page::None
        )
        .is_err());
    // A page that is not there does not go out.
    assert!(s
        .press(
            Op::ExportPoint,
            &[Who::Owner],
            Evidence::Point { number: 99 },
            Page::None
        )
        .is_err());
    assert_eq!(s.c.status(), Status::InWork, "the container lives on");

    // Sale: the buyer becomes the owner, the seller stops being one.
    s.press(
        Op::TransferOwnership,
        &[Who::Owner, Who::Buyer],
        Evidence::None,
        Page::None,
    )
    .expect("sale");
    assert!(s.c.roster().holds(&s.parties.buyer.public(), Role::Owner));
    assert!(!s.c.roster().holds(&s.parties.owner.public(), Role::Owner));

    s.press(Op::Finalize, &[Who::Issuer], Evidence::None, Page::None)
        .expect("finalized");
    assert_eq!(s.c.status(), Status::Finalized);

    // The new owner and the client export everything; the container dies.
    // Without saying by which road, the gate does not open.
    assert!(s
        .press(
            Op::FullExport,
            &[Who::Buyer, Who::Client],
            Evidence::None,
            Page::None
        )
        .is_err());
    s.press(
        Op::FullExport,
        &[Who::Buyer, Who::Client],
        Evidence::Unload(Box::new(UnloadRoute::Principals)),
        Page::None,
    )
    .expect("full export");
    assert_eq!(s.c.status(), Status::Exported);
    // The pages leave, once: opening, two records of work, the artefact, and
    // the sale's page in the zone of sales and transfers (CH-14).
    let pages = s.c.take_export().expect("the export");
    assert_eq!(pages.pages.len(), 5);
    // The export checks as a whole, by the procedure that wrote it: the full
    // class runs in Pro, so every record is anchored — one run, no gap (CH-25).
    let r = ksg_core_v2::journal::verify_bound(&pages, &stand::p()).expect("the export checks");
    assert_eq!(r.counts.transfer, 1, "one page of the hundred spent");
    assert_eq!(r.mode, ksg_core_v2::journal::Mode::Pro);
    assert_eq!(r.runs, vec![(0, 4)]);
    assert_eq!(
        r.owner.id.as_str(),
        "did:key:zBuyer",
        "the buyer owns it now"
    );
    assert!(s.c.take_export().is_none(), "handed out once");
    s
}

#[test]
fn e2e_main_life() {
    sc_main_life();
}

/// Up to work, through a sub-agent's key rather than straight from the buyer.
fn to_work_via_subagent(s: &mut Stand) {
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
    .expect("sub-agent's key");
    assert_eq!(s.c.status(), Status::SubAgentKeyed);
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
    .expect("journal opened");
}

/// The court's expert on both sides (`[decision]` 11.09): the owner names the
/// key on a page of the journal of work (AppointExpert); the expert's own
/// record, which the chain anchors.
struct Appointed {
    entry: ExpertEntry,
    record: ExpertRecord,
    anchor: Attestation,
}

fn expert_signer() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:key:zExpert#e1"), [80u8; 32])
}

fn expert_record(s: &Stand, demanded: Scope) -> (ExpertRecord, Attestation) {
    let mut record = ExpertRecord {
        context: ksg_core_v2::doc::Context,
        doc_type: "ExpertRecord".into(),
        v: 3,
        container: *s.c.id(),
        expert: expert_signer().public(),
        parameters: "page 1 only".into(),
        demanded,
        signatures: SignatureSet::default(),
    };
    record.signatures =
        SignatureSet::new(vec![sign_doc(&record, &expert_signer()).expect("expert")]);
    let anchor = Attestation {
        kind: uri("urn:ksg:anchor:stand"),
        subject: ksg_core_v2::canonical::doc_hash(&record).expect("hash"),
        proof: b"stand".to_vec(),
        anchored_at: stand::ts("2026-09-12T00:00:00.000Z"),
    };
    (record, anchor)
}

fn expert_entry(s: &Stand, key: ksg_core_v2::crypto::sign::PublicKey, case: &str) -> ExpertEntry {
    let mut entry = ExpertEntry {
        context: ksg_core_v2::doc::Context,
        doc_type: "ExpertEntry".into(),
        v: 3,
        container: *s.c.id(),
        expert: key,
        appointment: case.into(),
        signatures: SignatureSet::default(),
    };
    entry.signatures = SignatureSet::new(vec![sign_doc(&entry, &s.parties.owner).expect("owner")]);
    entry
}

fn name_in_journal(s: &mut Stand, entry: &ExpertEntry) -> Result<(), Stopped> {
    use ksg_core_v2::journal::{Piece, RecordKind, RecordMeta};
    s.clock_ms += 1_000;
    let draft =
        s.c.draft_record(
            vec![Piece::Digest(
                ksg_core_v2::canonical::doc_hash(entry).expect("hash"),
            )],
            RecordMeta {
                kind: RecordKind::Work,
                content_type: Some(uri(EXPERT_ENTRY_PAGE)),
                ..RecordMeta::default()
            },
            s.clock_ms,
        )
        .expect("draft");
    let write = s.seal_draft(draft);
    s.press_write(
        Op::AppointExpert,
        &[Who::Owner],
        Evidence::ExpertNamed(Box::new(entry.clone())),
        Some(write),
    )
}

fn appoint_expert(s: &mut Stand, case: &str) -> Appointed {
    let (record, anchor) = expert_record(s, Scope::Pages(vec![1]));
    let entry = expert_entry(s, expert_signer().public(), case);
    name_in_journal(s, &entry).expect("the expert named in the journal");
    Appointed {
        entry,
        record,
        anchor,
    }
}

fn disclose_evidence(a: &Appointed, disclosure: ExpertDisclosure) -> Evidence {
    Evidence::Disclose {
        entry: Box::new(a.entry.clone()),
        record: Box::new(a.record.clone()),
        record_anchor: Box::new(a.anchor.clone()),
        disclosure: Box::new(disclosure),
    }
}

fn sc_expert_voluntary_opening_and_loss() -> Stand {
    let mut s = Stand::new(Class::Heavy, 2);
    to_work_via_subagent(&mut s);
    record_work(&mut s, "work before the court");

    s.press(
        Op::DeclareSharesLost,
        &[Who::Owner],
        Evidence::SharesLost(Hash::sha256(b"declaration: 2 of 5 shares short")),
        Page::Of(EventKind::SharesDeclaredLost),
    )
    .expect("shares declared lost");
    assert_eq!(
        s.c.status(),
        Status::InWork,
        "the container goes on working"
    );

    let appointed = appoint_expert(&mut s, "urn:court:ua:case-1");
    // Without the expert and the principals' command, nothing is disclosed.
    assert!(s
        .press(
            Op::DiscloseToExpert,
            &[Who::Client, Who::Owner],
            Evidence::None,
            Page::None
        )
        .is_err());
    let expert_key = expert_signer().public();
    let mut disclosure = ExpertDisclosure {
        context: ksg_core_v2::doc::Context,
        doc_type: "ExpertDisclosure".into(),
        v: 3,
        container: *s.c.id(),
        expert: expert_key,
        scope: Scope::Pages(vec![1]),
        signatures: SignatureSet::default(),
    };
    let bytes = ksg_core_v2::canonical::canonical_bytes(&disclosure).expect("canonical");
    disclosure.signatures = SignatureSet::new(vec![
        client_ed25519(&mut s, &bytes),
        sign_doc(&disclosure, &s.parties.owner).expect("owner"),
    ]);
    // Wider than the expert demanded — refused, and the quota is not spent.
    let mut wider = disclosure.clone();
    wider.scope = Scope::Pages(vec![0, 1]);
    assert!(s
        .press(
            Op::DiscloseToExpert,
            &[Who::Client, Who::Owner],
            disclose_evidence(&appointed, wider),
            Page::None,
        )
        .is_err());
    s.press(
        Op::DiscloseToExpert,
        &[Who::Client, Who::Owner],
        disclose_evidence(&appointed, disclosure),
        Page::None,
    )
    .expect("disclosed to the expert");
    let shown = s.c.take_disclosure().expect("the pages");
    assert_eq!(shown.len(), 1);
    assert_eq!(shown[0].page.seq, 1);
    assert!(s.c.take_disclosure().is_none(), "handed out once");

    s.press(
        Op::OpenVoluntarily,
        &[Who::Client, Who::Owner, Who::ArbiterA, Who::ArbiterB],
        Evidence::None,
        Page::None,
    )
    .expect("opened voluntarily");
    assert_eq!(s.c.status(), Status::Opened);

    s.press(
        Op::DeclareKeyLost,
        &[Who::Owner],
        Evidence::None,
        Page::None,
    )
    .expect("client's key declared lost");
    assert_eq!(s.c.status(), Status::KeyLost);
    s
}

#[test]
fn e2e_expert_voluntary_opening_and_loss() {
    sc_expert_voluntary_opening_and_loss();
}

fn filing() -> Filing {
    Filing {
        claim: Hash::sha256(b"the copy of the claim, as filed"),
        jurisdiction: "UA".into(),
        filed_ms: 100 * stand::DAY,
        hearing_ms: 130 * stand::DAY,
        deadline_ms: 310 * stand::DAY,
    }
}

fn serve(s: &mut Stand) {
    s.press(
        Op::ServeDispute,
        &[Who::Claimant],
        Evidence::Dispute(Box::new(filing())),
        Page::None,
    )
    .expect("dispute served");
    assert_eq!(s.c.status(), Status::Disputed);
}

fn sc_dispute_proven() -> Stand {
    let mut s = Stand::new(Class::Heavy, 3);
    main_life(&mut s);
    serve(&mut s);
    s.press(
        Op::DecideDisputeProven,
        &[Who::ArbiterA, Who::Owner],
        Evidence::None,
        Page::None,
    )
    .expect("decided for the claimant");
    assert_eq!(s.c.status(), Status::DisputeProven);
    s
}

#[test]
fn e2e_dispute_proven() {
    sc_dispute_proven();
}

fn sc_dispute_unproven() -> Stand {
    let mut s = Stand::new(Class::Heavy, 4);
    main_life(&mut s);
    serve(&mut s);
    s.press(
        Op::DecideDisputeUnproven,
        &[Who::ArbiterA, Who::Client],
        Evidence::None,
        Page::None,
    )
    .expect("decided against the claimant");
    assert_eq!(s.c.status(), Status::DisputeUnproven);
    s
}

#[test]
fn e2e_dispute_unproven() {
    sc_dispute_unproven();
}

fn sc_dispute_settled() -> Stand {
    let mut s = Stand::new(Class::Heavy, 5);
    main_life(&mut s);
    serve(&mut s);
    let settled = Settlement {
        terms: Hash::sha256(b"rights shared 50/50"),
        at_ms: 200 * stand::DAY,
    };
    s.press(
        Op::Settle,
        &[Who::Claimant, Who::Owner],
        Evidence::Settled(Box::new(settled)),
        Page::None,
    )
    .expect("settled");
    assert_eq!(s.c.status(), Status::Settled);
    s
}

#[test]
fn e2e_dispute_settled() {
    sc_dispute_settled();
}

fn sc_freeze_on_owner_application() -> Stand {
    let mut s = Stand::new(Class::Heavy, 6);
    main_life(&mut s);
    s.press(
        Op::FreezeOnOwnerApplication,
        &[Who::Issuer, Who::Owner],
        Evidence::None,
        Page::None,
    )
    .expect("frozen");
    assert_eq!(s.c.status(), Status::Finalized);
    s
}

#[test]
fn e2e_freeze_on_owner_application() {
    sc_freeze_on_owner_application();
}

fn sc_succession() -> Stand {
    let mut s = Stand::new(Class::Heavy, 7);
    main_life(&mut s);
    s.press(Op::Succeed, &[Who::Issuer], Evidence::None, Page::None)
        .expect("succession");
    assert_eq!(s.c.status(), Status::Finalized);
    assert!(
        s.c.pending()
            .iter()
            .any(|r| matches!(r.task, Task::CarryId { .. })),
        "carrying the ID to the successor stays outstanding"
    );
    s
}

#[test]
fn e2e_succession() {
    sc_succession();
}

fn sc_class_raised() -> Stand {
    let mut s = Stand::new(Class::Light, 8);
    main_life(&mut s);
    let mut doc = ClassPromotion {
        context: ksg_core_v2::doc::Context,
        doc_type: "ClassPromotion".into(),
        v: 3,
        container: *s.c.id(),
        from: Class::Light,
        to: Class::Heavy,
        offset_ms: 50_000,
        signatures: SignatureSet::default(),
    };
    let bytes = ksg_core_v2::canonical::canonical_bytes(&doc).expect("canonical");
    let mut sigs = vec![sign_doc(&doc, &s.parties.issuer).expect("issuer")];
    sigs.extend(s.client_signs(&bytes));
    doc.signatures = SignatureSet::new(sigs);
    s.press(
        Op::RaiseClass,
        &[Who::Owner, Who::Issuer],
        Evidence::ClassRaise(Box::new(doc)),
        Page::None,
    )
    .expect("class raised");
    assert_eq!(s.c.class(), Class::Heavy);
    s
}

#[test]
fn e2e_class_raised() {
    sc_class_raised();
}

/// Every operation of the three buttons went through on the stand at least
/// once. `PrintRelease` is the one exception, and not by omission: printing is
/// record 0 of the status section, laid at assembly, before any button exists.
#[test]
fn e2e_every_operation_of_the_three_buttons_went_through() {
    let mut pressed = std::collections::BTreeSet::new();
    // Each stand owns an ML-DSA key. Keep only the operation set between
    // scenarios instead of retaining nine large stands on Rust's small test
    // thread stack while the next ML-DSA key is being generated.
    pressed.extend(sc_main_life().pressed);
    pressed.extend(sc_expert_voluntary_opening_and_loss().pressed);
    pressed.extend(sc_dispute_proven().pressed);
    pressed.extend(sc_dispute_unproven().pressed);
    pressed.extend(sc_dispute_settled().pressed);
    pressed.extend(sc_freeze_on_owner_application().pressed);
    pressed.extend(sc_succession().pressed);
    pressed.extend(sc_class_raised().pressed);
    pressed.extend(sc_export_by_voluntary_opening().pressed);
    // The detachment of an attached `bare` (13.10) is a `bare`'s own: its
    // whole life — print, work, attachment, detachment — is the one scenario
    // here that is not Pro's.
    pressed.extend(sc_bare_attached_and_detached().pressed);
    // For the registry (`scripts/container_registry.py`): which operations
    // went through, written only when asked for.
    if let Ok(path) = std::env::var("KSG_STAND_REPORT") {
        let list: Vec<&String> = pressed.iter().collect();
        std::fs::write(&path, format!("{list:?}")).expect("stand report");
    }
    let missing: Vec<String> = Op::all()
        .iter()
        .map(|op| format!("{op:?}"))
        .filter(|op| op != "PrintRelease" && !pressed.contains(op))
        .collect();
    assert!(
        missing.is_empty(),
        "never went through a button: {missing:?}"
    );
}

// --- the export by the road of a voluntary opening ---------------------------

fn client_ed25519(s: &mut Stand, bytes: &[u8]) -> ksg_core_v2::crypto::sign::Signature {
    // The reader gives Ed25519 of both halves and the container's ML-DSA; a
    // document whose key set names only the client's Ed25519 key takes the first.
    s.client_signs(bytes).remove(0)
}

fn voluntary_opening(s: &mut Stand) -> (VoluntaryOpening, Attestation) {
    let id = *s.c.id();
    let client = s.client.clone();
    let owner = s.parties.owner.public();
    let (a, b) = (s.parties.arbiter_a.public(), s.parties.arbiter_b.public());

    let mut decl = OpeningDeclaration {
        context: ksg_core_v2::doc::Context,
        doc_type: "OpeningDeclaration".into(),
        v: 3,
        container: id,
        client: client.clone(),
        owner: owner.clone(),
        signatures: SignatureSet::default(),
    };
    let bytes = ksg_core_v2::canonical::canonical_bytes(&decl).expect("canonical");
    decl.signatures = SignatureSet::new(vec![
        client_ed25519(s, &bytes),
        sign_doc(&decl, &s.parties.owner).expect("owner"),
    ]);

    let mut attestations = Vec::new();
    let (arb_a, arb_b) = (
        Ed25519Signer::from_seed(uri("did:key:zArbA#j1"), [70u8; 32]),
        Ed25519Signer::from_seed(uri("did:key:zArbB#j1"), [71u8; 32]),
    );
    for (arbiter, other) in [(&a, &arb_b), (&b, &arb_a)] {
        let base = ArbiterAttestation {
            context: ksg_core_v2::doc::Context,
            doc_type: "ArbiterAttestation".into(),
            v: 3,
            container: id,
            attestor: client.kid.clone(),
            arbiter: arbiter.clone(),
            signatures: SignatureSet::default(),
        };
        let mut by_client = base.clone();
        let bytes = ksg_core_v2::canonical::canonical_bytes(&by_client).expect("canonical");
        by_client.signatures = SignatureSet::new(vec![client_ed25519(s, &bytes)]);
        let mut by_owner = ArbiterAttestation {
            attestor: owner.kid.clone(),
            ..base.clone()
        };
        by_owner.signatures =
            SignatureSet::new(vec![sign_doc(&by_owner, &s.parties.owner).expect("o")]);
        let mut by_other = ArbiterAttestation {
            attestor: other.public().kid,
            ..base
        };
        by_other.signatures = SignatureSet::new(vec![sign_doc(&by_other, other).expect("a")]);
        attestations.extend([by_client, by_owner, by_other]);
    }

    let mut opening = VoluntaryOpening {
        context: ksg_core_v2::doc::Context,
        doc_type: "VoluntaryOpening".into(),
        v: 3,
        container: id,
        client,
        owner,
        arbiters: [a, b],
        attestations,
        declaration: decl.clone(),
        signatures: SignatureSet::default(),
    };
    let bytes = ksg_core_v2::canonical::canonical_bytes(&opening).expect("canonical");
    opening.signatures = SignatureSet::new(vec![
        client_ed25519(s, &bytes),
        sign_doc(&opening, &s.parties.owner).expect("owner"),
        sign_doc(&opening, &s.parties.arbiter_a).expect("a"),
        sign_doc(&opening, &s.parties.arbiter_b).expect("b"),
    ]);
    let anchor = Attestation {
        kind: uri("urn:ksg:anchor:stand"),
        subject: ksg_core_v2::canonical::doc_hash(&decl).expect("hash"),
        proof: b"stand".to_vec(),
        anchored_at: stand::ts("2026-09-12T00:00:00.000Z"),
    };
    (opening, anchor)
}

fn sc_export_by_voluntary_opening() -> Stand {
    let mut s = Stand::new(Class::Heavy, 9);
    main_life(&mut s);
    record_work(&mut s, "work to be shown");
    let (opening, anchor) = voluntary_opening(&mut s);

    // A forged opening does not open the gate, and nothing leaves.
    let mut forged = opening.clone();
    forged.signatures = SignatureSet::default();
    assert!(matches!(
        s.press(
            Op::FullExport,
            &[Who::Owner, Who::Client],
            Evidence::Unload(Box::new(UnloadRoute::Voluntary {
                opening: Box::new(forged),
                anchor: anchor.clone()
            })),
            Page::None,
        ),
        Err(Stopped::Unload(_))
    ));
    assert!(s.c.take_export().is_none());

    s.press(
        Op::FullExport,
        &[Who::Owner, Who::Client],
        Evidence::Unload(Box::new(UnloadRoute::Voluntary {
            opening: Box::new(opening),
            anchor,
        })),
        Page::None,
    )
    .expect("exported by the road of a voluntary opening");
    assert_eq!(s.c.take_export().expect("pages").pages.len(), 2);
    s
}

#[test]
fn e2e_export_by_voluntary_opening() {
    sc_export_by_voluntary_opening();
}

/// Goal 2, criterion G2-5 (`[decision]` 19.09, CT-21; 06.10): a Pro container
/// spends its twelve pointwise exports, the 13th is refused — and the road
/// past the twelve is the disclosure to an expert, which is not counted and
/// leaves the container working.
#[test]
fn e2e_pro_thirteenth_page_goes_only_through_the_expert() {
    use ksg_core_v2::journal::{BinderError, POINT_LIMIT};
    let mut s = Stand::new(Class::Heavy, 2);
    to_work_via_subagent(&mut s);
    record_work(&mut s, "the page the court will want");
    for _ in 0..POINT_LIMIT {
        s.press(
            Op::ExportPoint,
            &[Who::Owner],
            Evidence::Point { number: 1 },
            Page::None,
        )
        .expect("a pointwise export within the twelve");
        s.c.take_point().expect("the page");
    }
    let r = s.press(
        Op::ExportPoint,
        &[Who::Owner],
        Evidence::Point { number: 1 },
        Page::None,
    );
    assert!(
        matches!(r, Err(Stopped::Journal(BinderError::PointLimit(12)))),
        "the 13th pointwise export must refuse, got {r:?}"
    );

    let appointed = appoint_expert(&mut s, "urn:court:ua:case-13");
    let expert_key = expert_signer().public();
    let mut disclosure = ExpertDisclosure {
        context: ksg_core_v2::doc::Context,
        doc_type: "ExpertDisclosure".into(),
        v: 3,
        container: *s.c.id(),
        expert: expert_key,
        scope: Scope::Pages(vec![1]),
        signatures: SignatureSet::default(),
    };
    let bytes = ksg_core_v2::canonical::canonical_bytes(&disclosure).expect("canonical");
    disclosure.signatures = SignatureSet::new(vec![
        client_ed25519(&mut s, &bytes),
        sign_doc(&disclosure, &s.parties.owner).expect("owner"),
    ]);
    s.press(
        Op::DiscloseToExpert,
        &[Who::Client, Who::Owner],
        disclose_evidence(&appointed, disclosure),
        Page::None,
    )
    .expect("past the twelve, the expert still gets the page");
    let shown = s.c.take_disclosure().expect("the pages");
    assert_eq!(shown.len(), 1);
    assert_eq!(shown[0].page.seq, 1);
    assert_eq!(s.c.status(), Status::InWork, "the container lives on");
    record_work(&mut s, "work goes on after the disclosure");
}

/// C-12 end to end on the stand (owner's decisions 17.10): the distributor
/// that sold the packet takes its seat at the packet; the container is born
/// and works; the distributor alone, or the client alone, cannot declare it
/// dead; together they do, and nothing is written after.
#[test]
fn e2e_the_distributor_and_the_client_declare_the_container_dead() {
    let mut s = Stand::printed(Class::Heavy, 300);
    s.press(Op::ApplyPacket, &[Who::Issuer], Evidence::None, Page::None)
        .expect("packet");
    s.c.seat_distributor(s.parties.distributor.public())
        .expect("the seller takes its seat");
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
    s.give_birth();
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
    .expect("journal opened");
    record_work(&mut s, "before");
    for alone in [Who::Distributor, Who::Client] {
        assert!(
            s.press(Op::DeclareKeyLost, &[alone], Evidence::None, Page::None)
                .is_err(),
            "{alone:?} alone"
        );
    }
    s.press(
        Op::DeclareKeyLost,
        &[Who::Distributor, Who::Client],
        Evidence::None,
        Page::None,
    )
    .expect("the distributor with the client");
    assert_eq!(s.c.status(), Status::KeyLost);
}

// --- the attachment of a `bare` and its detachment (13.10) -------------------

/// A `bare` from printing to work: no packet (K5), the buyer's key and the
/// sub-agent's straight onto the printed release, initiation, page 0.
fn bare_to_work(s: &mut Stand) {
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
    .expect("sub-agent's key");
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
    .expect("journal opened");
    assert_eq!(s.c.status(), Status::InWork);
}

/// The new agent signs with its mobile half and the container's half of its
/// key, staged during the hand-off.
fn incoming_signs(
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

/// The attachment of a `bare` to `leader` (13.10), in its order: the owner's
/// change to the leader's owner (the stand's buyer), the hand-off to the
/// leader's agent, the trailer's coupling page.
fn attach_bare(s: &mut Stand, leader: Hash) {
    use ksg_container_v2::container::JournalWrite;
    use ksg_core_v2::journal::{CouplingRecord, Sealing};
    let new_owner = s.parties.buyer.public();
    s.press(
        Op::TransferOwnership,
        &[Who::Owner, Who::Buyer],
        Evidence::NewOwner(new_owner),
        Page::None,
    )
    .expect("the owner's change of the attachment");

    let m =
        s.c.stage_handoff(uri("did:key:zLeaderAgent#key-1"), &mut s.rng)
            .expect("the leader's agent staged");
    s.clock_ms += 1_000;
    let d = s.c.draft_handoff(s.clock_ms).expect("the hand-off page");
    let bytes = d.seal_bytes().expect("bytes");
    let tb = d.transfer_bytes().expect("bytes").expect("a transfer");
    let seal = incoming_signs(s, &m, &bytes);
    let mut transfer = ed25519_only(s.client_signs(&tb));
    transfer.extend(ed25519_only(incoming_signs(s, &m, &tb)));
    let w = JournalWrite::Record {
        draft: Box::new(d),
        sealing: Box::new(Sealing {
            seal: SignatureSet::new(seal),
            transfer: Some(SignatureSet::new(transfer)),
            ..Sealing::default()
        }),
    };
    s.press_write(Op::RecordWork, &[Who::Client], Evidence::Handoff, Some(w))
        .expect("the hand-off to the leader's agent");
    // The former client keeps its mobile half; its other half stays inside
    // for the detachment (13.10, variant A).
    s.former_mobile = Some(std::mem::replace(&mut s.mobile, m));

    let record = CouplingRecord::AttachedTo { leader };
    s.clock_ms += 1_000;
    let d =
        s.c.draft_coupling(record.clone(), s.clock_ms)
            .expect("the coupling page");
    let w = s.seal_draft(d);
    s.press_write(
        Op::RecordWork,
        &[Who::Client],
        Evidence::Coupling(record),
        Some(w),
    )
    .expect("attached as a trailer");
}

/// Print → work → attachment to a Pro leader → detachment: the leader's
/// owner and the client the `bare` had, both, and the copy burns.
fn sc_bare_attached_and_detached() -> Stand {
    let leader = {
        let mut l = Stand::new(Class::Heavy, 30);
        main_life(&mut l);
        *l.c.id()
    };
    let mut s = Stand::new(Class::Bare, 31);
    bare_to_work(&mut s);
    record_work(&mut s, "the history before the attachment");
    attach_bare(&mut s, leader);
    // An attached `bare` only reads: the leader writes for it now.
    let mut w = Work {
        container: *s.c.id(),
        under: None,
        did: "work as a trailer".into(),
        signatures: SignatureSet::default(),
    };
    let subject = w.subject();
    w.signatures = SignatureSet::new(s.client_signs(subject.as_bytes()));
    assert!(matches!(
        s.press(
            Op::RecordWork,
            &[Who::Client],
            Evidence::Work {
                order: None,
                work: Box::new(w),
            },
            Page::Of(EventKind::Work),
        ),
        Err(Stopped::Attached { .. })
    ));

    // One word does not detach; the leader's agent is not the former client.
    let head = s.c.head();
    assert!(s
        .press(Op::Detach, &[Who::Buyer], Evidence::None, Page::None)
        .is_err());
    assert!(s
        .press(
            Op::Detach,
            &[Who::Buyer, Who::Client],
            Evidence::None,
            Page::None
        )
        .is_err());
    assert!(!s.c.burned());
    assert_eq!(s.c.head(), head, "a refusal changes nothing");

    s.press(
        Op::Detach,
        &[Who::Buyer, Who::FormerClient],
        Evidence::None,
        Page::None,
    )
    .expect("detached");
    assert!(s.c.burned(), "this copy burns");
    assert_eq!(s.c.head(), None, "no journal is left in it");
    assert!(matches!(
        s.press(
            Op::ExportPoint,
            &[Who::Buyer],
            Evidence::Point { number: 1 },
            Page::None
        ),
        Err(Stopped::Burned)
    ));
    s
}

#[test]
fn e2e_bare_attached_and_detached() {
    sc_bare_attached_and_detached();
}

/// The gap of 17.10 closed (`[decision]` 11.09): the container establishes the
/// court's expert itself, from both sides — the principals' entry on a page of
/// the journal and the expert's own anchored record — and takes no seated
/// expert from whoever presses. A key the principals control, named without
/// the expert's own record, or a record the journal never named, is refused.
#[test]
fn the_container_establishes_the_expert_from_the_journal_and_the_chain() {
    let mut s = Stand::new(Class::Heavy, 2);
    to_work_via_subagent(&mut s);
    record_work(&mut s, "the page the court will want");
    let disclosure_for = |s: &mut Stand, key| {
        let mut d = ExpertDisclosure {
            context: ksg_core_v2::doc::Context,
            doc_type: "ExpertDisclosure".into(),
            v: 3,
            container: *s.c.id(),
            expert: key,
            scope: Scope::Pages(vec![1]),
            signatures: SignatureSet::default(),
        };
        let bytes = ksg_core_v2::canonical::canonical_bytes(&d).expect("canonical");
        d.signatures = SignatureSet::new(vec![
            client_ed25519(s, &bytes),
            sign_doc(&d, &s.parties.owner).expect("owner"),
        ]);
        d
    };
    let refused = |s: &mut Stand, e: Evidence| {
        let r = s.press(
            Op::DiscloseToExpert,
            &[Who::Client, Who::Owner],
            e,
            Page::None,
        );
        assert!(r.is_err(), "got {r:?}");
        assert!(s.c.take_disclosure().is_none());
    };

    // No entry on a page of the journal: the expert's record alone is not
    // an appointment.
    let (record, anchor) = expert_record(&s, Scope::Pages(vec![1]));
    let entry = expert_entry(&s, expert_signer().public(), "urn:court:ua:case-7");
    let d = disclosure_for(&mut s, expert_signer().public());
    let unnamed = Appointed {
        entry: entry.clone(),
        record: record.clone(),
        anchor: anchor.clone(),
    };
    refused(&mut s, disclose_evidence(&unnamed, d.clone()));

    // An entry not signed by a principal is not taken into the journal.
    let mut forged = entry.clone();
    forged.signatures =
        SignatureSet::new(vec![sign_doc(&forged, &expert_signer()).expect("expert")]);
    assert!(matches!(
        name_in_journal(&mut s, &forged),
        Err(Stopped::WrongEvidence { .. })
    ));

    // The principals name a key they control; it has no record of its own in
    // the chain, so it is never established.
    let theirs = Ed25519Signer::from_seed(uri("did:key:zExpert#e1"), [99u8; 32]);
    let their_entry = expert_entry(&s, theirs.public(), "urn:court:ua:case-7");
    name_in_journal(&mut s, &their_entry).expect("named");
    let own = Appointed {
        entry: their_entry,
        record: record.clone(),
        anchor: anchor.clone(),
    };
    let d_theirs = disclosure_for(&mut s, theirs.public());
    refused(&mut s, disclose_evidence(&own, d_theirs));

    // The record not under its anchor.
    name_in_journal(&mut s, &entry).expect("named");
    let elsewhere = Appointed {
        entry: entry.clone(),
        record: record.clone(),
        anchor: Attestation {
            subject: Hash::sha256(b"another record"),
            ..anchor.clone()
        },
    };
    refused(&mut s, disclose_evidence(&elsewhere, d.clone()));

    // Both sides, the same key: disclosed.
    let both = Appointed {
        entry,
        record,
        anchor,
    };
    s.press(
        Op::DiscloseToExpert,
        &[Who::Client, Who::Owner],
        disclose_evidence(&both, d),
        Page::None,
    )
    .expect("established from both sides");
    assert_eq!(s.c.take_disclosure().expect("the pages").len(), 1);
}
