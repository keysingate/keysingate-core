//! Tests written for the functions the registry found never executed
//! (`[doc:CONTAINER-FUNCTIONS]`, 23.09). One test per gap, named
//! after what it holds rather than after the function.
mod stand;

use ksg_container_v2::container::Evidence;
use ksg_container_v2::container::{JournalWrite, Stopped, UnloadRoute, Writes};
use ksg_container_v2::dispute::Filing;
use ksg_container_v2::followup::{Discharge, Proof, Task, Ticket};
use ksg_container_v2::layout::{Fields, Zone};
use ksg_container_v2::store::StoreError;
use ksg_container_v2::{
    Attachment, ChaCha20Poly1305Aead, Kind, NoCompression, Operation as Op, Packer, Stage, Status,
    Where,
};
use ksg_container_v2::{Container, Role, Roster, Work};
use ksg_core_v2::anchor::Attestation;
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{Ed25519Signer, SignatureSet};
use ksg_core_v2::doc::{Class, ClassPromotion};
use ksg_core_v2::journal::{Body, Piece, RecordKind, RecordMeta, Sealing};
use ksg_core_v2::status::Event as StatusEvent;
use stand::EventKind;
use stand::{uri, Page, Stand, Who};

fn to_work(s: &mut Stand) {
    s.press(Op::ApplyPacket, &[Who::Issuer], Evidence::None, Page::None)
        .expect("packet");
    let buyer = s.parties.buyer.public();
    s.press(
        Op::ApplyBuyerKey,
        &[Who::Buyer, Who::Owner],
        Evidence::KeyLaid {
            to: buyer,
            up_to: ksg_container_v2::layers::Level(2),
        },
        Page::None,
    )
    .expect("buyer");
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

fn filing() -> Filing {
    Filing {
        claim: Hash::sha256(b"claim"),
        jurisdiction: "UA".into(),
        filed_ms: 100 * stand::DAY,
        hearing_ms: 130 * stand::DAY,
        deadline_ms: 310 * stand::DAY,
    }
}

#[test]
fn the_container_keeps_the_filing_and_dies_of_prescription_twelve_years_after_the_deadline() {
    let mut s = Stand::new(Class::Heavy, 200);
    to_work(&mut s);
    assert!(s.c.filing().is_none());
    s.press(
        Op::ServeDispute,
        &[Who::Claimant],
        Evidence::Dispute(Box::new(filing())),
        Page::None,
    )
    .expect("served");
    assert_eq!(s.c.filing(), Some(&filing()));

    let (r, a) = s.trigger_record(StatusEvent::PrescriptionPassed);
    let keys = s.c.roster().keys().clone();
    // Before twelve years: refused.
    assert!(s
        .c
        .prescribed(
            filing().prescribed_at() - 1,
            r.clone(),
            a.clone(),
            &keys,
            &stand::p()
        )
        .is_err());
    s.c.prescribed(filing().prescribed_at(), r, a, &keys, &stand::p())
        .expect("prescribed");
    assert_eq!(s.c.status(), Status::Prescribed);
}

#[test]
fn would_record_names_the_status_event_of_an_operation() {
    let s = Stand::new(Class::Heavy, 201);
    assert_eq!(
        s.c.would_record(Op::ApplyPacket),
        Some(StatusEvent::ApplyPacket)
    );
    assert_eq!(s.c.would_record(Op::AppointExpert), None);
}

#[test]
fn a_promotion_with_a_key_other_than_the_pinned_one_is_refused() {
    let mut s = Stand::new(Class::Light, 202);
    let doc = ClassPromotion {
        context: ksg_core_v2::doc::Context,
        doc_type: "ClassPromotion".into(),
        v: 3,
        container: *s.c.id(),
        from: Class::Light,
        to: Class::Heavy,
        offset_ms: 1,
        signatures: Default::default(),
    };
    let impostor =
        ksg_core_v2::crypto::sign::Ed25519Signer::from_seed(uri("did:key:zIssuer#i1"), [99u8; 32]);
    let forged: ksg_core_v2::crypto::sign::KeySet = [impostor.public()].into_iter().collect();
    assert!(s.c.promote(&doc, &forged, &stand::p()).is_err());
    assert_eq!(s.c.class(), Class::Light);
}

#[test]
fn packing_checks_its_own_work_and_keeps_the_size_constant() {
    let packer = Packer::new(ChaCha20Poly1305Aead, NoCompression, 256);
    assert_eq!(packer.size(), 256);
    let key = [7u8; 32];
    let nonce = [1u8; 12];
    let noise = vec![0xA5u8; 256];
    let a = packer
        .seal_checked(b"short", &noise, &key, &nonce, b"aad")
        .expect("sealed");
    let b = packer
        .seal_checked(b"a somewhat longer content", &noise, &key, &nonce, b"aad")
        .expect("sealed");
    assert_eq!(a.len(), b.len(), "the size does not depend on the content");
    assert_eq!(
        packer.open(&a, &key, &nonce, b"aad").expect("opens"),
        b"short"
    );
    // Too large for the size: refused, not truncated.
    assert!(packer
        .seal_checked(&[0u8; 512], &noise, &key, &nonce, b"aad")
        .is_err());
    // Wrapping at the reader uses the same packer.
    let w = ksg_container_v2::Wrapped::seal(&packer, b"cmd", &noise, &key, &nonce, b"aad")
        .expect("wrapped");
    let _ = w;
}

#[test]
fn a_discharge_names_its_digest_and_its_subject_binds_the_task() {
    let t = Ticket {
        index: 0,
        task: Task::WriteLayer { zone: Zone::Packet },
        head: Hash::sha256(b"h"),
    };
    assert_eq!(t.task.name(), "write the layer's fields");
    let d = Discharge {
        ticket: t.clone(),
        proof: Proof::LayerWritten {
            zone: Zone::Packet,
            digest: Hash::sha256(b"d"),
        },
    };
    assert_eq!(d.digest(), Hash::sha256(b"d"));
    let other = Discharge {
        ticket: Ticket {
            task: Task::CarryId {
                from: Hash::sha256(b"c"),
            },
            ..t
        },
        proof: d.proof.clone(),
    };
    assert_ne!(
        d.subject(),
        other.subject(),
        "the task is part of the subject"
    );
    assert_eq!(
        Task::CarryId {
            from: Hash::sha256(b"c")
        }
        .name(),
        "carry the ID to the successor"
    );
}

#[test]
fn every_stage_is_listed_and_fields_start_empty() {
    assert_eq!(Stage::all().len(), 5);
    assert_eq!(Fields::default(), Fields::new());
}

#[test]
fn the_source_of_a_task_artefact_is_part_of_what_is_attached() {
    use ksg_container_v2::{Source, SourceFrom, TaskArtifact};
    let with = |from: SourceFrom| Attachment {
        artifact: uri(stand::ARTIFACT),
        kind: Kind::Task(TaskArtifact {
            description: "summarise".into(),
            sources: vec![Source {
                from,
                by: Some(uri("did:key:zOwner")),
                reference: Some(uri("urn:ref:brief-1")),
            }],
            references: vec![],
        }),
        content_hash: Hash::sha256(b"a"),
        size: 1,
        name: "a".into(),
        derived_from: vec![],
        offset_ms: stand::OFFSET,
    };
    let id = Hash::sha256(b"container");
    assert_ne!(
        with(SourceFrom::Owner).subject(&id),
        with(SourceFrom::Orchestrator).subject(&id)
    );
}

#[test]
fn no_key_material_in_the_debug_output_of_the_containers_secrets() {
    let mut rng = stand::StandRng(203);
    let (inside, mobile) =
        ksg_container_v2::client_key::split(uri("did:key:zA#a1"), &mut rng).expect("split");
    let seal = ksg_container_v2::seal::IssuerSeal::lay(
        &Hash::sha256(b"c"),
        uri("did:key:zSeal#s1"),
        [90u8; 32],
        &ksg_core_v2::crypto::sign::Ed25519Signer::from_seed(uri("did:key:zI#i1"), [11u8; 32]),
    );
    for printed in [
        format!("{inside:?}"),
        format!("{mobile:?}"),
        format!("{seal:?}"),
    ] {
        assert!(
            printed.len() < 120,
            "short and without key bytes: {printed}"
        );
        assert!(
            !printed.contains("signing_share") && !printed.contains("[90"),
            "{printed}"
        );
    }
}

#[test]
fn an_anchor_alone_proves_nothing() {
    let a = ksg_core_v2::anchor::Attestation {
        kind: uri("urn:ksg:anchor:test"),
        subject: Hash::sha256(b"x"),
        proof: vec![],
        anchored_at: stand::ts("2026-09-12T00:00:00.000Z"),
    };
    // Core v2 §7.2: an anchor nobody read gives no time bound — `Ok(None)`,
    // "not established". Core v1 said the same through a helper of the work
    // journal that always answered `false`; here the core's one rule answers.
    let bound = ksg_core_v2::anchor::upper_bound(
        std::slice::from_ref(&a),
        &a.subject,
        &ksg_core_v2::crypto::sign::Profile::default(),
        None,
    );
    assert_eq!(bound, Ok(None));
}

#[test]
fn the_page_count_follows_the_journal() {
    let mut s = Stand::new(Class::Heavy, 204);
    assert_eq!(s.c.pages(), 0, "no journal yet");
    to_work(&mut s);
    assert_eq!(s.c.pages(), 1, "page 0, the opening");
}

#[test]
fn a_sample_record_is_exported_as_the_fields_it_signed() {
    use ksg_container_v2::sample::{SampleRecord, Span};
    let r = SampleRecord {
        spans: vec![Span { offset: 0, len: 4 }],
        sample: Hash::sha256(b"s"),
        clean: Hash::sha256(b"c"),
        signed: Hash::sha256(b"g"),
    };
    let bytes = r.to_bytes();
    assert!(!bytes.is_empty());
    let other = SampleRecord {
        signed: Hash::sha256(b"other"),
        ..r
    };
    assert_ne!(bytes, other.to_bytes(), "every field is in the bytes");
}

#[test]
fn the_gates_expert_road_refuses_a_disclosure_for_another_expert() {
    use ksg_container_v2::expert::{AppointedExpert, ExpertDisclosure, Scope};
    use ksg_container_v2::unload_gate::{authorize, Presenters, Route, Subject};
    let s = Stand::new(Class::Heavy, 205);
    let expert = AppointedExpert {
        key: s.parties.arbiter_a.public(),
        named_by: uri("urn:court:1"),
        parameters: "p".into(),
        demanded: Scope::Pages(vec![1]),
    };
    let disclosure = ExpertDisclosure {
        context: ksg_core_v2::doc::Context,
        doc_type: "ExpertDisclosure".into(),
        v: 3,
        container: *s.c.id(),
        expert: s.parties.arbiter_b.public(),
        scope: Scope::Pages(vec![1]),
        signatures: Default::default(),
    };
    let owner = s.parties.owner.public();
    let got = authorize(
        Subject {
            container: *s.c.id(),
            memo: ksg_core_v2::doc::MemoFormat::Controlled,
        },
        Op::DiscloseToExpert,
        &Route::Expert {
            expert: &expert,
            disclosure: &disclosure,
            client: &s.client,
            owner: &owner,
        },
        Presenters {
            signers: &[s.client.clone(), owner.clone()],
            roster: s.c.roster(),
        },
        &stand::p(),
        0,
    );
    assert!(got.is_err());
}

// --- gaps of 17.10 ------------------------------------------------------------

/// The layer key the stored-copy tests seal with.
const STORE_KEY: [u8; 32] = [5u8; 32];

fn attestation(subject: Hash) -> Attestation {
    Attestation {
        kind: uri("urn:ksg:anchor:stand"),
        subject,
        proof: b"stand".to_vec(),
        anchored_at: stand::ts("2026-09-12T00:00:00.000Z"),
    }
}

fn work_evidence(s: &mut Stand, did: &str) -> Evidence {
    let mut w = Work {
        container: *s.c.id(),
        under: None,
        did: did.into(),
        signatures: SignatureSet::default(),
    };
    let subject = w.subject();
    w.signatures = SignatureSet::new(s.client_signs(subject.as_bytes()));
    Evidence::Work {
        order: None,
        work: Box::new(w),
    }
}

fn record_work(s: &mut Stand, did: &str) {
    let e = work_evidence(s, did);
    s.press(Op::RecordWork, &[Who::Client], e, Page::Of(EventKind::Work))
        .expect("record of work");
}

/// A `bare` driven to `InWork` with its journal open: straight from printing,
/// the buyer's key and the sub-agent's, initiation, page 0.
fn bare_in_work(seed: u64) -> Stand {
    let mut s = Stand::new(Class::Bare, seed);
    let buyer = s.parties.buyer.public();
    s.press(
        Op::ApplyBuyerKey,
        &[Who::Buyer, Who::Owner],
        Evidence::KeyLaid {
            to: buyer,
            up_to: ksg_container_v2::layers::Level(2),
        },
        Page::None,
    )
    .expect("buyer key");
    let sub = s.parties.subagent.public();
    s.press(
        Op::ApplySubAgentKey,
        &[Who::SubAgent, Who::Client],
        Evidence::KeyLaid {
            to: sub,
            up_to: ksg_container_v2::layers::Level(3),
        },
        Page::None,
    )
    .expect("subagent key");
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
    s
}

const STORE_MAGIC: &[u8] = b"ksg:store:v4";

/// Opens a stored file with `key`, lets `change` edit its state and seals it
/// back without the outer signature — what somebody holding the layer key
/// could write. The container must refuse what it would never have written;
/// a refusal of the state comes before the outer signature is looked at.
fn tampered(
    bytes: &[u8],
    template: &Hash,
    key: &[u8; 32],
    change: impl FnOnce(&mut serde_json::Value),
) -> Vec<u8> {
    use ksg_container_v2::{ChaCha20Poly1305Aead, Deflate};
    let len_at = bytes.len() - 4;
    let sig_len = u32::from_be_bytes(bytes[len_at..].try_into().expect("length")) as usize;
    let body = &bytes[STORE_MAGIC.len()..len_at - sig_len];
    let (nonce, sealed) = body.split_at(12);
    let aad = [STORE_MAGIC, template.as_bytes()].concat();
    let packer = Packer::new(
        ChaCha20Poly1305Aead,
        Deflate {
            limit: ksg_container_v2::store::MAX_STATE,
        },
        ksg_container_v2::store::STORE_SIZE,
    );
    let plain = packer.open(sealed, key, nonce, &aad).expect("opened state");
    let mut state: serde_json::Value = serde_json::from_slice(&plain).expect("JSON state");
    change(&mut state);
    let plain = serde_json::to_vec(&state).expect("JSON");
    let noise = vec![0u8; packer.noise_needed(&plain)];
    let sealed = packer
        .seal(&plain, &noise, key, nonce, &aad)
        .expect("sealed");
    [STORE_MAGIC, nonce, &sealed, &0u32.to_be_bytes()].concat()
}

/// The stored copy of `s` with `change` applied, opened again.
fn reopened_tampered(
    s: &mut Stand,
    change: impl FnOnce(&mut serde_json::Value),
) -> Result<Container, StoreError> {
    let template = s.c.template_id();
    let bytes = s.c.seal_to_bytes(&STORE_KEY, &mut s.rng).expect("stored");
    Container::open_sealed(&bytes, &template, &STORE_KEY).expect("the honest file opens");
    Container::open_sealed(
        &tampered(&bytes, &template, &STORE_KEY, change),
        &template,
        &STORE_KEY,
    )
}

fn restore_refused(r: Result<Container, StoreError>, needle: &str) {
    match r {
        Err(StoreError::Restore(msg)) => assert!(msg.contains(needle), "{msg}"),
        other => panic!("expected a refused restore naming {needle:?}, got {other:?}"),
    }
}

#[test]
fn a_companion_key_signs_for_its_party_and_fills_no_seat_of_its_own() {
    use ksg_container_v2::{Button, Command, Refusal, Refused};
    use ksg_core_v2::status::{Blocked, Status as S};
    let s = |kid: &str, seed: u8| Ed25519Signer::from_seed(uri(kid), [seed; 32]);
    let (owner, buyer) = (s("did:key:zOwner#o1", 44), s("did:key:zBuyer#b1", 12));
    // The owner's second key: it signs for the owner and is not a party.
    let companion = s("did:key:zOwner#o2", 45);
    let mut roster = Roster::of([(owner.public(), Role::Owner), (buyer.public(), Role::Buyer)]);
    roster.add_companion(companion.public(), &owner.public().kid);
    assert_eq!(
        roster.principal(&companion.public().kid),
        &owner.public().kid
    );
    assert_eq!(roster.principal(&buyer.public().kid), &buyer.public().kid);

    const BODY: &[u8] = b"the sale";
    let cmd = |by: &[&Ed25519Signer]| Command {
        op: Op::TransferOwnership,
        payload: BODY.to_vec(),
        signatures: SignatureSet::new(by.iter().map(|k| k.sign(BODY)).collect()),
        signed_bytes: BODY.to_vec(),
    };
    let press = |c: Command| {
        c.press(
            Button::Signatures,
            S::InWork,
            Blocked::No,
            &roster,
            roster.keys(),
            &stand::p(),
        )
    };
    // The owner and its companion are one party: a two-party sale refuses.
    assert!(matches!(
        press(cmd(&[&owner, &companion])),
        Err(Refused {
            reason: Refusal::OneParty(_),
            ..
        })
    ));
    press(cmd(&[&owner, &buyer])).expect("two parties");
}

#[test]
fn the_anchor_put_on_a_write_later_is_the_one_the_journal_checks() {
    let mut s = Stand::new(Class::Heavy, 206);
    to_work(&mut s);
    s.clock_ms += 1_000;
    let draft =
        s.c.draft_record(
            vec![Piece::Digest(Hash::sha256(b"anchored later"))],
            RecordMeta {
                kind: RecordKind::Work,
                ..RecordMeta::default()
            },
            s.clock_ms,
        )
        .expect("draft");
    let right = attestation(draft.seal_hash().expect("hash"));
    let mut w = s.seal_draft(draft);
    let head = s.c.head();

    // A placeholder of another subject in its place: the write refuses whole.
    w.set_anchor(attestation(Hash::sha256(b"another subject")));
    let e = work_evidence(&mut s, "anchored later");
    assert!(s
        .press_write(Op::RecordWork, &[Who::Client], e, Some(w.clone()))
        .is_err());
    assert_eq!(s.c.head(), head, "a refusal changes nothing");

    // The network's anchor of this record: it goes in.
    w.set_anchor(right);
    let e = work_evidence(&mut s, "anchored later");
    s.press_write(Op::RecordWork, &[Who::Client], e, Some(w))
        .expect("the anchor of this record");
    assert_ne!(s.c.head(), head);
}

#[test]
fn the_containers_debug_output_names_its_keys_by_id_and_prints_no_key_bytes() {
    let mut s = Stand::printed(Class::Heavy, 207);
    s.give_birth();
    let printed = format!("{:?}", s.c);
    // The birth under way and the container's post-quantum key are printed
    // by hand: their key id, nothing of the secret.
    assert!(printed.contains("Birth { kid: "), "{printed}");
    assert!(printed.contains("ContainerPqKey { kid: "), "{printed}");
    assert!(!printed.contains("sk:"), "{printed}");
    assert!(!printed.contains("signing_share"), "{printed}");
}

#[test]
fn a_cancelled_birth_leaves_a_template_that_can_give_birth_again() {
    let mut s = Stand::printed(Class::Heavy, 208);
    s.press(Op::ApplyPacket, &[Who::Issuer], Evidence::None, Page::None)
        .expect("packet");
    s.give_birth();
    let first = s.c.birth_key().cloned().expect("a key born");
    s.c.cancel_birth();
    assert!(s.c.birth_key().is_none(), "the key is gone");
    // Nothing signs as the client: the half went with the birth.
    let (_, commitment) = s.mobile.commit(&mut s.rng);
    assert!(s.c.begin_signing(b"m", &commitment, &mut s.rng).is_err());
    let buyer = s.parties.buyer.public();
    s.press(
        Op::ApplyBuyerKey,
        &[Who::Buyer, Who::Owner],
        Evidence::KeyLaid {
            to: buyer,
            up_to: ksg_container_v2::layers::Level(2),
        },
        Page::None,
    )
    .expect("buyer's key");
    // A new birth, a new key.
    s.give_birth();
    assert_ne!(s.c.birth_key().expect("born again"), &first);
    s.press(
        Op::Initiate,
        &[Who::Client, Who::Owner],
        Evidence::Initiation { at: Where::Inside },
        Page::None,
    )
    .expect("initiation with the new key");
    assert_eq!(s.c.status(), Status::Initiated);
}

/// A Solana-shaped proof of transaction `sig`, as the reader writes it.
fn solana_proof(sig: &str) -> Vec<u8> {
    let proof = serde_json::json!({"signature": sig, "slot": 5, "cluster": "devnet"});
    ksg_core_v2::canonical::canonicalize(&proof).expect("json")
}

const TX: &str =
    "5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUW";

fn view_notice(n: u8) -> ksg_container_v2::view::ViewNotice {
    use ksg_container_v2::view::{AnchorRef, DisclosureRequest, ViewNotice};
    let by = Ed25519Signer::from_seed(uri("did:key:zWatcher#w1"), [99; 32]);
    let mut r = DisclosureRequest {
        doc_type: DisclosureRequest::TYPE.into(),
        v: 3,
        owner: vec![by.public()],
        audience: uri("https://desk.keysingate.example/v1"),
        anchor: AnchorRef {
            cluster: "devnet".into(),
            signature: TX.into(),
        },
        challenge: format!("{n:02x}").repeat(32),
        issued_at: stand::ts("2026-10-01T10:00:00.000Z"),
        expires_at: stand::ts("2026-10-01T10:05:00.000Z"),
        signatures: SignatureSet::default(),
    };
    r.signatures = SignatureSet::new(vec![
        by.sign(&ksg_core_v2::canonical::canonical_bytes(&r).expect("bytes"))
    ]);
    ViewNotice::of(r, stand::ts("2026-10-01T10:01:00.000Z"))
}

#[test]
fn a_look_at_a_status_anchor_is_recorded_on_a_working_container_too() {
    // With the journal open, the anchors the notice may point at are the
    // journal's seals and the status records' both: a look at the status
    // record's transaction is ours.
    let mut s = Stand::new(Class::Heavy, 209);
    to_work(&mut s);
    let att = Attestation {
        kind: uri("urn:ksg:anchor:solana:status:v1"),
        subject: s.c.status_head(),
        proof: solana_proof(TX),
        anchored_at: stand::ts("2026-09-12T00:00:01.000Z"),
    };
    s.c.reanchor_last(None, Some(att))
        .expect("the record's anchor");
    s.c.record_view(view_notice(1), &stand::p())
        .expect("recorded");
    assert_eq!(s.c.views().seen(), 1);
}

#[test]
fn a_stored_notice_that_no_longer_checks_does_not_open() {
    let mut s = Stand::new(Class::Heavy, 210);
    let att = Attestation {
        kind: uri("urn:ksg:anchor:solana:status:v1"),
        subject: s.c.status_head(),
        proof: solana_proof(TX),
        anchored_at: stand::ts("2026-09-12T00:00:01.000Z"),
    };
    s.c.reanchor_last(None, Some(att))
        .expect("the record's anchor");
    s.c.record_view(view_notice(1), &stand::p())
        .expect("recorded");
    // The holder edits who looked: the watcher's signature no longer covers it.
    restore_refused(
        reopened_tampered(&mut s, |st| {
            st["views"][0]["request"]["challenge"] = serde_json::json!("ff".repeat(32));
        }),
        "view notice",
    );
}

#[test]
fn a_stored_journal_claiming_more_pointwise_exports_than_its_class_allows_does_not_open() {
    // Pro's twelve (`[decision]` 19.09, CT-21): a file saying thirteen went out
    // would never have been written by a Pro container.
    let mut s = Stand::new(Class::Heavy, 211);
    to_work(&mut s);
    restore_refused(
        reopened_tampered(&mut s, |st| {
            st["journal"]["disclosed"] = serde_json::json!(13);
        }),
        "journal",
    );
}

#[test]
fn a_stored_former_half_that_does_not_read_does_not_open() {
    let mut s = Stand::new(Class::Heavy, 212);
    restore_refused(
        reopened_tampered(&mut s, |st| {
            let mut half = st["client_half"].clone();
            half["signing_share"] = serde_json::json!([1, 2, 3]);
            st["former_half"] = half;
        }),
        "former client's half",
    );
}

#[test]
fn a_stored_container_key_of_the_wrong_length_does_not_open() {
    let mut s = Stand::new(Class::Heavy, 213);
    restore_refused(
        reopened_tampered(&mut s, |st| {
            st["pq_key"]["sk"] = serde_json::json!([0, 0, 0]);
        }),
        "post-quantum key",
    );
}

#[test]
fn a_stored_half_rewritten_to_sign_alone_signs_nothing() {
    // A `bare` file carries no outer signature, so a holder of the layer key
    // can rewrite its state. A half whose group names no second signer and
    // asks for one signature only would sign alone: it must refuse instead.
    // Written for the registry's gap `finish::{closure#1}`, which it shows
    // unreachable: the refusal comes one step earlier.
    let mut s = bare_in_work(214);
    // An honest share of the client's, kept from an earlier round.
    let (nonces, commitment) = s.mobile.commit(&mut s.rng);
    let round =
        s.c.begin_signing(b"a message", &commitment, &mut s.rng)
            .expect("a round opens");
    let share = s.mobile.respond(nonces, &round).expect("the mobile half");
    s.c.finish_signing(&share, &mut s.rng)
        .expect("the honest round");

    let c = reopened_tampered(&mut s, |st| {
        let own = st["client_half"]["id"].clone();
        let group = st["client_half"]["group"]
            .as_array()
            .expect("the group")
            .iter()
            .filter(|e| e[0] == own)
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(group.len(), 1, "the container's own share stays");
        st["client_half"]["group"] = serde_json::Value::Array(group);
        st["client_half"]["min_signers"] = serde_json::json!(1);
        st["client_half"]["group_min"] = serde_json::json!(1);
    });
    // Opening does not check the group against the client's key; signing
    // does — whichever refuses, nothing is signed by one half.
    s.c = c.expect("the rewritten file opens");
    let (_, commitment) = s.mobile.commit(&mut s.rng);
    s.c.begin_signing(b"another message", &commitment, &mut s.rng)
        .expect("a round opens");
    // `begin` pairs the client's commitment with the only signer the group
    // names — the container itself — and FROST refuses the container's share
    // under a commitment that is not its own. This is why "no second signer"
    // in `finish` is never reached (registry, `UNREACHABLE`).
    let r = s.c.finish_signing(&share, &mut s.rng);
    assert!(
        matches!(
            r,
            Err(ksg_container_v2::client_key::ClientKeyError::Frost(_))
        ),
        "one half alone signs nothing, got {r:?}"
    );
}

/// A generator whose `try_fill_bytes` fails: what an RNG that broke between
/// the noise and the signature looks like.
struct BrokenAtSigning(stand::StandRng);

impl frost_ed25519::rand_core::RngCore for BrokenAtSigning {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }
    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), frost_ed25519::rand_core::Error> {
        let code = core::num::NonZeroU32::new(frost_ed25519::rand_core::Error::CUSTOM_START)
            .expect("a nonzero code");
        Err(code.into())
    }
}
impl frost_ed25519::rand_core::CryptoRng for BrokenAtSigning {}

#[test]
fn a_generator_that_fails_at_the_outer_signature_leaves_no_file() {
    let s = Stand::new(Class::Heavy, 215);
    let mut rng = BrokenAtSigning(stand::StandRng(1));
    assert!(matches!(
        s.c.seal_to_bytes(&STORE_KEY, &mut rng),
        Err(StoreError::Encode(_))
    ));
}

#[test]
fn a_copy_from_the_bytes_takes_over_a_staged_handoff_and_completes_it() {
    let mut s = bare_in_work(216);
    record_work(&mut s, "before the hand-off");
    let m =
        s.c.stage_handoff(uri("did:key:zNextAgent#key-1"), &mut s.rng)
            .expect("staged");
    let template = s.c.template_id();
    let bytes = s.c.seal_to_bytes(&STORE_KEY, &mut s.rng).expect("stored");
    let mut copy = Container::open_sealed(&bytes, &template, &STORE_KEY).expect("opens");
    // The staged hand-off is not stored: the copy has none.
    assert!(copy.draft_handoff(s.clock_ms + 1_000).is_err());
    copy.carry_staged_handoff(&s.c).expect("carried");
    s.c = copy;

    s.clock_ms += 1_000;
    let d = s.c.draft_handoff(s.clock_ms).expect("the hand-off page");
    let bytes = d.seal_bytes().expect("bytes");
    let tb = d.transfer_bytes().expect("bytes").expect("a transfer");
    let new_agent = |s: &mut Stand, msg: &[u8]| {
        let (nonces, commitment) = m.commit(&mut s.rng);
        let round =
            s.c.begin_signing_incoming(msg, &commitment, &mut s.rng)
                .expect("round");
        let share = m.respond(nonces, &round).expect("share");
        s.c.finish_signing_incoming(&share, &mut s.rng)
            .expect("both halves")
    };
    let ed = |v: Vec<ksg_core_v2::crypto::sign::Signature>| {
        v.into_iter()
            .filter(|x| x.alg == ksg_core_v2::crypto::sign::Alg::Ed25519)
            .collect::<Vec<_>>()
    };
    let seal = new_agent(&mut s, &bytes);
    let mut transfer = ed(s.client_signs(&tb));
    transfer.extend(ed(new_agent(&mut s, &tb)));
    let w = JournalWrite::Record {
        draft: Box::new(d),
        sealing: Box::new(Sealing {
            seal: SignatureSet::new(seal),
            transfer: Some(SignatureSet::new(transfer)),
            ..Sealing::default()
        }),
    };
    s.press_write(Op::RecordWork, &[Who::Client], Evidence::Handoff, Some(w))
        .expect("the copy completes the hand-off");
    s.former_mobile = Some(std::mem::replace(&mut s.mobile, m));
    record_work(&mut s, "the new agent works");
}

#[test]
fn an_owners_change_to_a_key_without_a_fragment_names_the_key_as_the_party() {
    let mut s = Stand::new(Class::Heavy, 217);
    to_work(&mut s);
    let owner_of = |kid: &str, s: &Stand| {
        let key = Ed25519Signer::from_seed(uri(kid), [73u8; 32]).public();
        let d =
            s.c.draft_owner_change_to_key(&key, s.clock_ms + 1_000)
                .expect("the owner's change page");
        let Body::Transfer(t) = &d.pages()[0].body else {
            panic!("a transfer page");
        };
        t.to_owner.clone().expect("an arriving owner")
    };
    let bare_kid = owner_of("did:key:zLeaderOwner", &s);
    assert_eq!(bare_kid.id, uri("did:key:zLeaderOwner"));
    let with_fragment = owner_of("did:key:zLeaderOwner#o1", &s);
    assert_eq!(with_fragment.id, bare_kid.id, "one party either way");
}

/// A record of work whose content is the same every time — what the repeat
/// rule (KS-8 F-6) counts.
fn identical_record(s: &mut Stand) -> Result<(), Stopped> {
    s.clock_ms += 1_000;
    let d = s.c.draft_record(
        vec![Piece::Digest(Hash::sha256(b"the same work"))],
        RecordMeta {
            kind: RecordKind::Work,
            ..RecordMeta::default()
        },
        s.clock_ms,
    )?;
    let w = s.seal_draft(d);
    let e = work_evidence(s, "the same work");
    s.press_write(Op::RecordWork, &[Who::Client], e, Some(w))
}

#[test]
fn ten_identical_records_owe_the_journals_confirmation_before_anything_else() {
    use ksg_core_v2::journal::{BinderError, REPEAT_LIMIT};
    let mut s = Stand::new(Class::Heavy, 218);
    to_work(&mut s);
    // Not owed yet.
    assert!(s.c.draft_confirmation(s.clock_ms + 1_000).is_err());
    for _ in 0..REPEAT_LIMIT {
        identical_record(&mut s).expect("an identical record");
    }
    let r = identical_record(&mut s);
    assert!(
        matches!(r, Err(Stopped::Journal(BinderError::ConfirmationOwed))),
        "the eleventh waits for the confirmation, got {r:?}"
    );
    let e = work_evidence(&mut s, "pressing on");
    s.press(
        Op::RecordWork,
        &[Who::Client],
        e,
        Page::Of(EventKind::RepeatConfirmation),
    )
    .expect("the journal's confirmation");
    identical_record(&mut s).expect("the run starts over");
}

fn artefact() -> Attachment {
    Attachment {
        artifact: uri(stand::ARTIFACT),
        kind: Kind::Media {
            mime: "image/png".into(),
        },
        content_hash: Hash::sha256(b"the artefact"),
        size: 12,
        name: "artefact.png".into(),
        derived_from: vec![],
        offset_ms: stand::OFFSET,
    }
}

#[test]
fn the_record_that_waits_for_the_owner_is_exactly_the_one_drafted() {
    let mut s = Stand::new(Class::Heavy, 219);
    to_work(&mut s);
    assert!(s.c.waiting_draft().is_none());
    s.clock_ms += 1_000;
    let draft =
        s.c.draft_record(
            vec![Piece::Digest(Hash::sha256(b"the artefact"))],
            RecordMeta {
                kind: RecordKind::ArtifactOrRights,
                ..RecordMeta::default()
            },
            s.clock_ms,
        )
        .expect("draft");
    assert!(draft.needs_owner(), "Pro: the owner seals an artefact too");
    let bytes = draft.seal_bytes().expect("bytes");
    let agent_only = JournalWrite::Record {
        draft: Box::new(draft.clone()),
        sealing: Box::new(Sealing {
            seal: SignatureSet::new(s.client_signs(&bytes)),
            ..Sealing::default()
        }),
    };
    let r = s.press_write(
        Op::AttachArtifactOrRights,
        &[Who::Client],
        Evidence::Artifact(Box::new(artefact())),
        Some(agent_only),
    );
    assert!(matches!(r, Err(Stopped::WaitsForOwner)), "{r:?}");
    assert_eq!(s.c.waiting_draft(), Some(&draft));
}

#[test]
fn a_pointwise_export_that_names_no_moment_is_judged_at_the_latest_mark_the_container_holds() {
    // A `bare` initiated, with work recorded: its latest mark is the latest of
    // its initiation, its last record and its last status record. The press
    // names no moment and writes nothing — it is judged at that mark.
    let mut s = bare_in_work(220);
    record_work(&mut s, "the page");
    let mut e = ksg_container_v2::Event {
        op: Op::ExportPoint,
        button: Op::ExportPoint.button(),
        container: *s.c.id(),
        payload: ksg_container_v2::Wrapped::received(b"wrapped at the reader".to_vec()),
        signatures: SignatureSet::default(),
        covered: Vec::new(),
        head: s.c.head(),
    };
    e.covered = e.subject();
    e.signatures = SignatureSet::new(vec![s.parties.owner.sign(&e.covered)]);
    let keys = s.c.roster().keys().clone();
    s.c.press(
        &e,
        &Evidence::Points { numbers: vec![1] },
        Writes {
            page: None,
            status: None,
            at_ms: None,
        },
        &keys,
        &stand::p(),
    )
    .expect("a working bare exports");
    assert_eq!(s.c.take_points().expect("the page").len(), 1);
}

#[test]
fn an_expert_is_established_only_when_the_journal_and_the_chain_name_the_same_key() {
    use ksg_container_v2::expert::{establish, ExpertEntry, ExpertRecord, Scope};
    use ksg_container_v2::voluntary::GateError;
    use ksg_core_v2::crypto::sign::{sign_doc, KeySet};
    let s = Stand::new(Class::Heavy, 221);
    let id = *s.c.id();
    let expert = Ed25519Signer::from_seed(uri("did:key:zExpert#e1"), [80u8; 32]);
    let other = Ed25519Signer::from_seed(uri("did:key:zExpert#e1"), [81u8; 32]);
    let principals: KeySet = [s.parties.owner.public(), s.client.clone()]
        .into_iter()
        .collect();
    let entry_for = |key: &Ed25519Signer| {
        let mut e = ExpertEntry {
            context: ksg_core_v2::doc::Context,
            doc_type: "ExpertEntry".into(),
            v: 3,
            container: id,
            expert: key.public(),
            appointment: "urn:court:ua:case-13".into(),
            signatures: SignatureSet::default(),
        };
        e.signatures = SignatureSet::new(vec![sign_doc(&e, &s.parties.owner).expect("owner")]);
        e
    };
    let mut record = ExpertRecord {
        context: ksg_core_v2::doc::Context,
        doc_type: "ExpertRecord".into(),
        v: 3,
        container: id,
        expert: expert.public(),
        parameters: "page 1 only".into(),
        demanded: Scope::Pages(vec![1]),
        signatures: SignatureSet::default(),
    };
    record.signatures = SignatureSet::new(vec![sign_doc(&record, &expert).expect("expert")]);
    let anchor = attestation(ksg_core_v2::canonical::doc_hash(&record).expect("hash"));
    let p = stand::p();

    let seated = establish(&id, &entry_for(&expert), &record, &anchor, &principals, &p)
        .expect("both sides name one key");
    assert_eq!(seated.key, expert.public());
    assert_eq!(seated.named_by, s.parties.owner.public().kid);
    assert_eq!(seated.demanded, Scope::Pages(vec![1]));

    // The journal names another key than the chain.
    assert_eq!(
        establish(&id, &entry_for(&other), &record, &anchor, &principals, &p),
        Err(GateError::Opening(
            "the journal and the chain name different experts"
        ))
    );
    // The chain's record is not the one anchored.
    let elsewhere = attestation(Hash::sha256(b"another record"));
    assert!(establish(
        &id,
        &entry_for(&expert),
        &record,
        &elsewhere,
        &principals,
        &p
    )
    .is_err());
}

#[test]
fn a_disclosure_to_an_expert_hands_over_exactly_the_pages_named_or_refuses() {
    use ksg_container_v2::expert::{AppointedExpert, ExpertDisclosure, Scope};
    use ksg_container_v2::voluntary::GateError;
    use ksg_core_v2::crypto::sign::sign_doc;
    let mut s = Stand::new(Class::Heavy, 222);
    to_work(&mut s);
    let draft =
        s.c.draft_record(
            vec![Piece::Digest(Hash::sha256(b"examined"))],
            RecordMeta {
                kind: RecordKind::Work,
                ..RecordMeta::default()
            },
            s.clock_ms + 1_000,
        )
        .expect("draft");
    let pages = draft.pages().to_vec();
    let seq = pages[0].seq;
    let expert_key = Ed25519Signer::from_seed(uri("did:key:zExpert#e1"), [80u8; 32]).public();
    let id = *s.c.id();
    let for_scope = |s: &mut Stand, scope: Scope| {
        let expert = AppointedExpert {
            key: expert_key.clone(),
            named_by: uri("urn:court:ua:case-13"),
            parameters: "named pages".into(),
            demanded: scope.clone(),
        };
        let mut d = ExpertDisclosure {
            context: ksg_core_v2::doc::Context,
            doc_type: "ExpertDisclosure".into(),
            v: 3,
            container: id,
            expert: expert_key.clone(),
            scope,
            signatures: SignatureSet::default(),
        };
        let bytes = ksg_core_v2::canonical::canonical_bytes(&d).expect("canonical");
        d.signatures = SignatureSet::new(vec![
            s.client_signs(&bytes).remove(0),
            sign_doc(&d, &s.parties.owner).expect("owner"),
        ]);
        (expert, d)
    };
    let owner = s.parties.owner.public();
    let client = s.client.clone();
    let p = stand::p();

    let (expert, d) = for_scope(&mut s, Scope::Pages(vec![seq]));
    let got = d
        .authorize(&id, &expert, &pages, &client, &owner, &p)
        .expect("the page named");
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].seq, seq);

    let (expert, d) = for_scope(&mut s, Scope::Pages(vec![999]));
    assert_eq!(
        d.authorize(&id, &expert, &pages, &client, &owner, &p),
        Err(GateError::NoSuchPage(999))
    );

    let (expert, d) = for_scope(&mut s, Scope::Everything);
    assert_eq!(
        d.authorize(&id, &expert, &pages, &client, &owner, &p)
            .expect("everything")
            .len(),
        pages.len()
    );
}

#[test]
fn the_issuers_word_on_the_post_quantum_key_binds_the_template_and_the_key() {
    use ksg_container_v2::store::pq_cert_message;
    let s = Stand::new(Class::Heavy, 223);
    let template = s.c.template_id();
    let key = s.c.pq_public().expect("a Pro container holds one").clone();
    let m = pq_cert_message(&template, &key);
    assert!(m.ends_with(key.key.as_bytes()));
    assert_ne!(m, pq_cert_message(&Hash::sha256(b"another template"), &key));
    let other = ksg_core_v2::crypto::sign::PublicKey {
        key: "another".into(),
        ..key
    };
    assert_ne!(m, pq_cert_message(&template, &other));
}

#[test]
fn an_opened_journal_shows_an_anchored_reader_its_content_pages_only() {
    use ksg_container_v2::voluntary::{read_opened, GateError, Reader};
    let mut s = bare_in_work(224);
    record_work(&mut s, "first");
    record_work(&mut s, "second");
    s.press(
        Op::FullExport,
        &[Who::Owner, Who::Client],
        Evidence::Unload(Box::new(UnloadRoute::Principals)),
        Page::None,
    )
    .expect("full export");
    let pages = s.c.take_export().expect("the export").pages;
    let key = Ed25519Signer::from_seed(uri("did:key:zReader#r1"), [74u8; 32]).public();
    let reader = Reader {
        key: key.clone(),
        anchor: attestation(Reader::subject(&key)),
    };
    let shown = read_opened(&pages, &reader).expect("an anchored reader");
    assert_eq!(shown.len(), 2, "the two records, not page 0");
    assert!(shown.iter().all(|p| p.kind == RecordKind::Work));
    assert_eq!(
        shown.iter().map(|p| p.number).collect::<Vec<_>>(),
        vec![1, 2]
    );
    let unanchored = Reader {
        key,
        anchor: attestation(Hash::sha256(b"somebody else")),
    };
    assert_eq!(
        read_opened(&pages, &unanchored),
        Err(GateError::ReaderNotAnchored)
    );
}
