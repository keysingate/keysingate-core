//! Tests written for the functions of the core the container registry found
//! never executed (`[doc:CONTAINER-FUNCTIONS]`, 17.10). One test
//! per gap, named after what it holds rather than after the function.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use fips204::ml_dsa_65;
use fips204::traits::{KeyGen, SerDes, Signer as _};

use ksg_core_v2::anchor::{Anchors, Attestation};
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{
    b64_encode, sign_doc, Alg, Ed25519Signer, KeySet, Profile, PublicKey, Signature, SignatureSet,
};
use ksg_core_v2::doc::{BlockAllocation, Class, Emission, Range, Serial, Timestamp, Uri};
use ksg_core_v2::error::{Invalid, SigFail};
use ksg_core_v2::journal::{
    rule_types, Binder, Mode, Party, Piece, RuleScope, SealRule, Sealing, BARE_POINT_LIMIT,
    POINT_LIMIT,
};
use ksg_core_v2::status::{Status, StatusHistory};

fn uri(s: &str) -> Uri {
    Uri::parse(s.to_owned()).expect("uri")
}

fn ts(s: &str) -> Timestamp {
    Timestamp::parse(s.to_owned()).expect("ts")
}

fn attestation(subject: Hash) -> Attestation {
    Attestation {
        kind: uri("urn:ksg:anchor:test"),
        subject,
        proof: b"proof".to_vec(),
        anchored_at: ts("2026-09-30T10:00:00.000Z"),
    }
}

#[test]
fn a_set_of_anchors_only_grows_and_keeps_the_order_presented() {
    let mut set = Anchors::new(Vec::new());
    assert!(set.is_empty(), "a root not anchored yet");
    assert_eq!(set.len(), 0);
    let (a, b) = (
        attestation(Hash::sha256(b"a")),
        attestation(Hash::sha256(b"b")),
    );
    set.push(a.clone());
    set.push(b.clone());
    assert!(!set.is_empty());
    assert_eq!(set.len(), 2);
    assert_eq!(set.as_slice(), &[a.clone(), b.clone()][..]);
    assert_eq!(Anchors::new(vec![a, b]), set);
}

/// One signature of `alg` under `key`, verified against a key set holding
/// only `key`: what comes back is the verifier's whole answer.
fn verify_with(alg: Alg, key: &str, sig: &str) -> Result<(), Invalid> {
    let kid = uri("did:key:zSigner#k1");
    let keys: KeySet = [PublicKey {
        kid: kid.clone(),
        alg,
        key: key.to_owned(),
    }]
    .into_iter()
    .collect();
    SignatureSet::new(vec![Signature {
        kid,
        alg,
        value: sig.to_owned(),
    }])
    // The profile asks for the algorithm under test, so that a verified
    // signature is the whole answer and not a gap in coverage.
    .verify(
        b"message",
        &keys,
        &Profile {
            required_algs: [alg].into_iter().collect(),
            ..Profile::default()
        },
    )
}

fn refused_as(r: Result<(), Invalid>, alg: Alg, why: SigFail) {
    assert!(
        matches!(r, Err(Invalid::Signature { alg: a, reason }) if a == alg && reason == why),
        "{alg:?}: expected {why:?}, got {r:?}"
    );
}

#[test]
fn an_unreadable_signature_or_key_is_refused_as_unreadable_not_as_a_mismatch() {
    let good = Ed25519Signer::from_seed(uri("did:key:zSigner#k1"), [5u8; 32]);
    let good_key = good.public().key;
    let good_sig = good.sign(b"message").value;

    // Ed25519: the key not in base64url, of the wrong length, not a point.
    refused_as(
        verify_with(Alg::Ed25519, "not base64!", &good_sig),
        Alg::Ed25519,
        SigFail::BadEncoding,
    );
    refused_as(
        verify_with(Alg::Ed25519, &b64_encode(&[1u8; 31]), &good_sig),
        Alg::Ed25519,
        SigFail::BadKey,
    );
    // y = 7 has no x on the curve: thirty-two bytes that are not a point.
    let mut off_curve = [0u8; 32];
    off_curve[0] = 7;
    refused_as(
        verify_with(Alg::Ed25519, &b64_encode(&off_curve), &good_sig),
        Alg::Ed25519,
        SigFail::BadKey,
    );
    // Ed25519: the signature not in base64url, of the wrong length.
    refused_as(
        verify_with(Alg::Ed25519, &good_key, "not base64!"),
        Alg::Ed25519,
        SigFail::BadEncoding,
    );
    refused_as(
        verify_with(Alg::Ed25519, &good_key, &b64_encode(&[0u8; 63])),
        Alg::Ed25519,
        SigFail::BadEncoding,
    );
    // The honest pair still verifies: the refusals above are about encoding.
    assert_eq!(verify_with(Alg::Ed25519, &good_key, &good_sig), Ok(()));

    // ML-DSA-65: the key not in base64url; the signature not in base64url.
    let (pk, sk) = ml_dsa_65::KG::keygen_from_seed(&[6u8; 32]);
    let pq_key = b64_encode(&pk.into_bytes());
    let pq_sig = b64_encode(&sk.try_sign(b"message", &[]).expect("ml-dsa"));
    refused_as(
        verify_with(Alg::MlDsa65, "not base64!", &pq_sig),
        Alg::MlDsa65,
        SigFail::BadEncoding,
    );
    refused_as(
        verify_with(Alg::MlDsa65, &pq_key, "not base64!"),
        Alg::MlDsa65,
        SigFail::BadEncoding,
    );
    assert_eq!(verify_with(Alg::MlDsa65, &pq_key, &pq_sig), Ok(()));
}

fn range(from: u64, to: u64) -> Range {
    Range {
        from: Serial(from),
        to: Serial(to),
    }
}

#[test]
fn a_packets_origin_is_its_allocation_and_it_covers_only_its_block() {
    let a = BlockAllocation {
        context: ksg_core_v2::doc::Context,
        doc_type: "BlockAllocation".into(),
        v: 3,
        emission: "ksg:em:000001".into(),
        block: range(4_700_000, 4_700_999),
        class: Class::Heavy,
        holder: uri("did:web:holder.example"),
        allocated_at: ts("2026-08-27T10:00:00.000Z"),
        expires_at: ts("2026-11-25T10:00:00.000Z"),
        prev_closure: None,
        signatures: SignatureSet::default(),
    };
    // `[decision]` 19.09 (CT-25): one origin per packet, the allocation's moment.
    assert_eq!(a.origin(), &ts("2026-08-27T10:00:00.000Z"));
    assert!(a.covers(Serial(4_700_000)));
    assert!(a.covers(Serial(4_700_999)));
    assert!(!a.covers(Serial(4_699_999)));
    assert!(!a.covers(Serial(4_701_000)));
}

#[test]
fn an_emission_verifies_under_its_own_keys_and_refuses_an_inverted_range_or_no_keys() {
    let root = Ed25519Signer::from_seed(uri("did:key:zRoot#r1"), [21u8; 32]);
    let doc = Emission {
        context: ksg_core_v2::doc::Context,
        doc_type: "Emission".into(),
        v: 3,
        id: "ksg:em:000001".into(),
        range: range(1, 100_000_000),
        block_ttl_days: 90,
        issuer: uri("did:web:issuer.example"),
        issued_at: ts("2026-08-27T00:00:00.000Z"),
        keys: vec![root.public()],
        signatures: SignatureSet::default(),
    };
    let signed = |d: &Emission, by: &Ed25519Signer| Emission {
        signatures: SignatureSet::new(vec![sign_doc(d, by).expect("signature")]),
        ..d.clone()
    };
    let p = Profile::default();
    let em = signed(&doc, &root);
    assert_eq!(
        em.declared_keys(),
        [root.public()].into_iter().collect::<KeySet>()
    );
    em.validate(&p)
        .expect("self-contained: its own keys verify it");

    // Signed by a key it does not declare.
    let stranger = Ed25519Signer::from_seed(uri("did:key:zRoot#r1"), [22u8; 32]);
    assert!(signed(&doc, &stranger).validate(&p).is_err());
    // An inverted range, and no keys at all.
    let inverted = signed(
        &Emission {
            range: range(10, 1),
            ..doc.clone()
        },
        &root,
    );
    assert_eq!(
        inverted.validate(&p),
        Err(Invalid::Schema("Emission.range is inverted"))
    );
    let keyless = signed(
        &Emission {
            keys: Vec::new(),
            ..doc
        },
        &root,
    );
    assert_eq!(
        keyless.validate(&p),
        Err(Invalid::Schema("Emission.keys is empty"))
    );
}

/// A party with an Ed25519 and an ML-DSA-65 key, from public test seeds.
fn party(name: &str) -> (Party, Ed25519Signer, ml_dsa_65::PrivateKey) {
    let seed = Hash::sha256(format!("ksg:test-key:v1:{name}").as_bytes());
    let ed = Ed25519Signer::from_seed(uri(&format!("did:key:z{name}#ed")), *seed.as_bytes());
    let (pk, pq) = ml_dsa_65::KG::keygen_from_seed(seed.as_bytes());
    let pq_pub = PublicKey {
        kid: uri(&format!("did:key:z{name}#pq")),
        alg: Alg::MlDsa65,
        key: b64_encode(&pk.into_bytes()),
    };
    let p = Party {
        id: uri(&format!("did:key:z{name}")),
        keys: vec![ed.public(), pq_pub],
    };
    (p, ed, pq)
}

#[test]
fn a_journal_allows_twelve_pointwise_exports_and_moves_the_limit_only_within_the_bare_ceiling() {
    let container = Hash::sha256(b"container-gaps");
    let (agent, agent_ed, agent_pq) = party("GapAgent");
    let (owner, _, _) = party("GapOwner");
    let (bytes, _) = Binder::opening_seal(container, Mode::Local, agent.clone(), owner.clone(), 1)
        .expect("seal 0");
    let pq = agent_pq.try_sign(&bytes, &[]).expect("ml-dsa");
    let sealing = Sealing {
        seal: SignatureSet::new(vec![
            agent_ed.sign(&bytes),
            Signature {
                kid: agent.keys[1].kid.clone(),
                alg: Alg::MlDsa65,
                value: b64_encode(&pq),
            },
        ]),
        ..Sealing::default()
    };
    let mut b = Binder::open(
        container,
        Mode::Local,
        agent,
        owner,
        1,
        &sealing,
        &Profile::default(),
    )
    .expect("open");
    assert_eq!(b.point_limit(), POINT_LIMIT, "Pro's twelve by default");
    b.set_point_limit(BARE_POINT_LIMIT).expect("bare's ceiling");
    assert_eq!(b.point_limit(), BARE_POINT_LIMIT);
    assert!(b.set_point_limit(BARE_POINT_LIMIT + 1).is_err());
    assert_eq!(b.point_limit(), BARE_POINT_LIMIT, "a refusal moves nothing");
}

#[test]
fn a_rule_of_two_seals_names_the_content_types_it_covers() {
    let licence = uri("urn:ksg:type:licence");
    let policy = uri("urn:ksg:type:policy");
    let types = rule_types(&SealRule {
        scope: RuleScope::Types(vec![licence.clone(), policy.clone()]),
    });
    assert_eq!(
        types.into_iter().collect::<Vec<_>>(),
        vec![licence.as_str().to_owned(), policy.as_str().to_owned()]
    );
    let all = rule_types(&SealRule {
        scope: RuleScope::All,
    });
    assert_eq!(all.into_iter().collect::<Vec<_>>(), vec!["*".to_owned()]);
    assert!(rule_types(&SealRule {
        scope: RuleScope::Lifted
    })
    .is_empty());
}

#[test]
fn a_piece_of_content_never_prints_its_bytes() {
    let inline = format!("{:?}", Piece::Inline(b"the client's secret".to_vec()));
    assert_eq!(inline, "Inline(<19 bytes>)");
    assert!(!inline.contains("secret"));
    let h = Hash::sha256(b"elsewhere");
    assert_eq!(format!("{:?}", Piece::Digest(h)), format!("Digest({h:?})"));
}

#[test]
fn an_empty_status_history_is_the_default() {
    let h = StatusHistory::default();
    assert_eq!(h, StatusHistory::new());
    assert_eq!(h.current(), Status::Printed);
}

#[test]
fn only_the_current_major_version_is_current() {
    use ksg_core_v2::version::{is_current, CURRENT_V};
    assert!(is_current(CURRENT_V));
    assert!(!is_current(CURRENT_V - 1));
    assert!(!is_current(CURRENT_V + 1));
}
