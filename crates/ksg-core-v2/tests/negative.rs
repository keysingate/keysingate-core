//! Negative cases. Specification §16 items 3, 4, 5, 8, 11.
//!
//! They check that the implementation **refuses where it should** — and refuses
//! for the reason it should: a test satisfied by any error will let through a
//! refusal for a completely different cause.
//!
//! The fixtures are shared with `skeleton.rs` but are built afresh here: a test
//! that depends on another test's execution order catches something other than
//! what it names.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::collections::BTreeSet;

use ksg_core_v2::canonical::canonical_bytes;
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{
    sign_doc, Alg, Ed25519Signer, KeySet, Profile, Signature, SignatureSet,
};
use ksg_core_v2::doc::binding::check_binding_uniqueness;
use ksg_core_v2::doc::ranges::validate_partition;
use ksg_core_v2::doc::{
    AgentBinding, BlockAllocation, BlockClosure, Class, Emission, Range, Serial, Timestamp, Uri,
};
use ksg_core_v2::error::{Coverage, Invalid, SigFail};

fn uri(s: &str) -> Uri {
    Uri::parse(s).unwrap()
}
fn ts(s: &str) -> Timestamp {
    Timestamp::parse(s).unwrap()
}
fn issuer() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:web:issuer.example#k1"), [7u8; 32])
}
fn agent() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:key:zAgent#a1"), [42u8; 32])
}
fn r(from: u64, to: u64) -> Range {
    Range {
        from: Serial(from),
        to: Serial(to),
    }
}
fn block() -> Range {
    r(4_700_000, 4_700_999)
}

fn seal<T: ksg_core_v2::canonical::Signable, F: Fn(&mut T, SignatureSet)>(
    mut doc: T,
    signer: &Ed25519Signer,
    put: F,
) -> T {
    let sig = sign_doc(&doc, signer).unwrap();
    put(&mut doc, SignatureSet::new(vec![sig]));
    doc
}

fn emission() -> Emission {
    let doc = Emission {
        context: ksg_core_v2::doc::Context,
        doc_type: "Emission".into(),
        v: 3,
        id: "ksg:em:000001".into(),
        range: r(1, 100_000_000),
        block_ttl_days: 90,
        issuer: uri("did:web:issuer.example"),
        issued_at: ts("2026-08-27T00:00:00.000Z"),
        keys: vec![issuer().public()],
        signatures: SignatureSet::default(),
    };
    seal(doc, &issuer(), |d, s| d.signatures = s)
}

fn allocation() -> BlockAllocation {
    allocation_of(Class::Heavy)
}

/// The class lives on the packet since 2026-09-11, so tests that vary it
/// build the allocation, not the emission.
fn allocation_of(class: Class) -> BlockAllocation {
    let doc = BlockAllocation {
        context: ksg_core_v2::doc::Context,
        doc_type: "BlockAllocation".into(),
        v: 3,
        emission: "ksg:em:000001".into(),
        block: block(),
        class,
        holder: uri("did:web:holder.example"),
        allocated_at: ts("2026-08-27T10:00:00.000Z"),
        expires_at: ts("2026-11-25T10:00:00.000Z"),
        prev_closure: None,
        signatures: SignatureSet::default(),
    };
    seal(doc, &issuer(), |d, s| d.signatures = s)
}

fn binding_by(signer: &Ed25519Signer) -> AgentBinding {
    let doc = AgentBinding {
        context: ksg_core_v2::doc::Context,
        doc_type: "AgentBinding".into(),
        v: 3,
        emission: "ksg:em:000001".into(),
        block: block(),
        agent: signer.public(),
        bound_at: ts("2026-08-27T10:05:00.000Z"),
        signatures: SignatureSet::default(),
    };
    seal(doc, signer, |d, s| d.signatures = s)
}

fn agent_keys() -> KeySet {
    [agent().public()].into_iter().collect()
}

// --- §16 item 3: negative signature cases -----------------------------------

#[test]
fn rejects_modified_byte_in_signed_doc() {
    // One byte of the document changed — the signature no longer matches.
    //
    // Until 2026-09-13 the refusal came out as `MissingRequired`: a mismatched
    // signature merely failed to cover its algorithm. It now comes out as
    // `Mismatch`, which is the truthful reason — and, more to the point, a
    // mismatched signature now rejects the document instead of being skipped.
    // The old reading let one party forge a two-sided authorization (security
    // audit, finding 1).
    let bind = binding_by(&agent());
    let mut tampered = bind.clone();
    tampered.bound_at = ts("2026-08-27T10:05:01.000Z");

    let msg = canonical_bytes(&tampered).unwrap();
    let err = tampered
        .signatures
        .verify(&msg, &agent_keys(), &Profile::default())
        .unwrap_err();
    assert_eq!(
        err,
        Invalid::Signature {
            alg: Alg::Ed25519,
            reason: SigFail::Mismatch
        },
        "a tampered document must be refused outright"
    );

    // The original document passes the same check — so the refusal is caused by
    // the tampering, not by broken test scaffolding.
    assert!(bind
        .signatures
        .verify(
            &canonical_bytes(&bind).unwrap(),
            &agent_keys(),
            &Profile::default()
        )
        .is_ok());
}

#[test]
fn alg_outside_the_enum_never_parses() {
    // §4.1's "reject on an unknown alg value" at the type level means such a
    // signature must not come out of JSON at all: the enumeration is closed, and
    // parsing refuses before anything is verified.
    let json = r#"{"kid":"did:key:zA#k1","alg":"RSA-2048","value":"AAAA"}"#;
    assert!(serde_json::from_str::<Signature>(json).is_err());
}

#[test]
fn a_key_declared_ml_dsa_but_shaped_like_ed25519_rejects_the_document() {
    // ML-DSA-65 is implemented since 2026-09-17, so the old form of this test —
    // "there is nothing to verify it with" — no longer applies. What stays is
    // the rule it guarded: a signature the verifier cannot check does not get
    // skipped. Here the key is declared as ML-DSA-65 and is 32 bytes long,
    // which no ML-DSA key is; the document is refused rather than passed over,
    // even though the profile requires only Ed25519 and that signature is valid.
    let bind = binding_by(&agent());
    let mut pq_key = agent().public();
    pq_key.kid = uri("did:key:zAgent#pq");
    pq_key.alg = Alg::MlDsa65;

    let mut sigs: Vec<Signature> = bind.signatures.as_slice().to_vec();
    sigs.push(Signature {
        kid: pq_key.kid.clone(),
        alg: Alg::MlDsa65,
        value: "AAAA".into(),
    });
    let set = SignatureSet::new(sigs);
    let keys: KeySet = [agent().public(), pq_key].into_iter().collect();

    let err = set
        .verify(&canonical_bytes(&bind).unwrap(), &keys, &Profile::default())
        .unwrap_err();
    assert!(
        matches!(
            err,
            Invalid::Signature {
                alg: Alg::MlDsa65,
                reason: SigFail::BadKey
            }
        ),
        "got {err:?}, expected a refusal naming the unusable key"
    );
}

#[test]
fn required_algs_is_logical_and_not_or() {
    // §16 item 3: ML-DSA removed while required_algs holds two → a refusal.
    // A valid Ed25519 signature is not enough: coverage is a logical AND.
    let bind = binding_by(&agent());
    let both: BTreeSet<Alg> = [Alg::Ed25519, Alg::MlDsa65].into_iter().collect();
    let strict = Profile {
        required_algs: both,
        ..Profile::default()
    };

    let err = bind
        .signatures
        .verify(&canonical_bytes(&bind).unwrap(), &agent_keys(), &strict)
        .unwrap_err();
    assert_eq!(
        err,
        Invalid::Signature {
            alg: Alg::MlDsa65,
            reason: SigFail::MissingRequired
        }
    );

    // The same document passes under the default profile — the difference is in
    // the requirement, not in the document.
    assert!(bind
        .signatures
        .verify(
            &canonical_bytes(&bind).unwrap(),
            &agent_keys(),
            &Profile::default()
        )
        .is_ok());
}

#[test]
fn rejects_key_declared_under_another_alg() {
    // A key declared for the wrong algorithm is an inconsistent key set, not
    // "the signature did not match".
    let bind = binding_by(&agent());
    let mut wrong = agent().public();
    wrong.alg = Alg::MlDsa65;
    let keys: KeySet = [wrong].into_iter().collect();

    let err = bind
        .signatures
        .verify(&canonical_bytes(&bind).unwrap(), &keys, &Profile::default())
        .unwrap_err();
    assert_eq!(
        err,
        Invalid::Signature {
            alg: Alg::Ed25519,
            reason: SigFail::BadKey
        }
    );
}

// --- §16 item 5: binding uniqueness -----------------------------------------

#[test]
fn rejects_second_binding_on_the_same_block() {
    let mine = binding_by(&agent());
    let rival = binding_by(&Ed25519Signer::from_seed(
        uri("did:key:zRival#a1"),
        [13u8; 32],
    ));

    // A copy of itself does not count as a rival.
    assert!(check_binding_uniqueness(std::slice::from_ref(&mine), &mine).is_ok());
    // A foreign binding of the same block — invalidity.
    assert_eq!(
        check_binding_uniqueness(&[mine.clone(), rival], &mine).unwrap_err(),
        Invalid::DuplicateBinding
    );
}

// --- §16 items 8 and 11: the closing allocation -----------------------------

fn closure(class_fixture: (Vec<Range>, Vec<Range>, Vec<Range>)) -> BlockClosure {
    let (used_submitted, used_not_submitted, cancelled) = class_fixture;
    let doc = BlockClosure {
        context: ksg_core_v2::doc::Context,
        doc_type: "BlockClosure".into(),
        v: 3,
        emission: "ksg:em:000001".into(),
        block: block(),
        used_submitted,
        used_not_submitted,
        cancelled,
        closed_at: ts("2026-08-28T00:00:00.000Z"),
        signatures: SignatureSet::default(),
    };
    seal(doc, &agent(), |d, s| d.signatures = s)
}

#[test]
fn rejects_ledger_gap_naming_the_serial() {
    let c = closure((
        vec![r(4_700_000, 4_700_398)],
        vec![],
        vec![r(4_700_400, 4_700_999)],
    ));
    assert_eq!(
        c.validate(Class::Heavy, &agent_keys(), &Profile::default())
            .unwrap_err(),
        Invalid::ClosureCoverage(Coverage::Gap { serial: 4_700_399 })
    );
}

#[test]
fn rejects_ledger_overlap_even_when_lengths_sum_to_block_size() {
    // The length sum equals the block size, yet there is both an overlap and a
    // gap — the case the naive sum check lets through.
    let err = validate_partition(
        block(),
        [
            &[r(4_700_000, 4_700_400)],
            &[r(4_700_400, 4_700_599)],
            &[r(4_700_601, 4_700_999)],
        ],
    )
    .unwrap_err();
    assert!(matches!(
        err,
        Invalid::ClosureCoverage(Coverage::Overlap { .. })
    ));
}

#[test]
fn rejects_used_not_submitted_for_heavy() {
    // §12: for heavy, inclusion is mandatory, so "issued but not submitted" does
    // not occur there. Coverage is complete — the refusal is caused by the class.
    let c = closure((
        vec![r(4_700_000, 4_700_998)],
        vec![r(4_700_999, 4_700_999)],
        vec![],
    ));
    assert_eq!(
        c.validate(Class::Heavy, &agent_keys(), &Profile::default())
            .unwrap_err(),
        Invalid::ClosureCoverage(Coverage::UsedNotSubmittedInHeavy)
    );
    // The same closure is permissible for light.
    assert!(c
        .validate(Class::Light, &agent_keys(), &Profile::default())
        .is_ok());
}

// --- §3: an absent field versus null ----------------------------------------

#[test]
fn absent_field_and_null_are_different_documents() {
    // An error here breaks every signature at once, so it is checked on a real
    // document rather than on arbitrary JSON.
    let first = allocation();
    let mut second = first.clone();
    second.prev_closure = Some(Hash::sha256(b"prev"));

    let a = canonical_bytes(&first).unwrap();
    let b = canonical_bytes(&second).unwrap();
    assert_ne!(a, b);
    assert!(!String::from_utf8(a).unwrap().contains("prev_closure"));

    // The first document's signature does not cover the second.
    assert!(second
        .signatures
        .verify(
            &canonical_bytes(&second).unwrap(),
            &[issuer().public()].into_iter().collect(),
            &Profile::default()
        )
        .is_err());
}

#[test]
fn signatures_are_excluded_from_the_signed_view() {
    // Otherwise a signature would depend on itself, and a document could not be
    // signed with a second algorithm without breaking the first signature.
    let bind = binding_by(&agent());
    let mut stripped = bind.clone();
    stripped.signatures = SignatureSet::default();
    assert_eq!(
        canonical_bytes(&bind).unwrap(),
        canonical_bytes(&stripped).unwrap()
    );
}

// --- §14: versioning ---------------------------------------------------------

#[test]
fn rejects_document_version_above_and_below_the_supported_range() {
    // §14: a document with `v` above the supported one is rejected. The lower
    // bound is checked too — `v: 0` means not "an ancient version" but corruption
    // or someone else's numbering.
    let bind = binding_by(&agent());
    let alloc = allocation();
    let profile = Profile::default();

    let mut too_new = bind.clone();
    too_new.v = ksg_core_v2::version::MAX_VERIFIABLE_V + 1;
    let too_new = seal(
        AgentBinding {
            signatures: SignatureSet::default(),
            ..too_new
        },
        &agent(),
        |d, s| d.signatures = s,
    );
    assert_eq!(
        too_new
            .validate(&alloc, &KeySet::new(), &profile)
            .unwrap_err(),
        Invalid::Schema("document version is above the supported one")
    );

    let zero = seal(
        AgentBinding {
            v: 0,
            signatures: SignatureSet::default(),
            ..bind.clone()
        },
        &agent(),
        |d, s| d.signatures = s,
    );
    assert_eq!(
        zero.validate(&alloc, &KeySet::new(), &profile).unwrap_err(),
        Invalid::Schema("document version is below the issued ones")
    );

    // The current version is accepted — the refusals above are caused by the version, not the fixture.
    // Core v2 has no v1 binding: the holder's authorization is always asked for.
    assert!(binding_v2(true)
        .validate(&alloc, &holder_key_set(), &profile)
        .is_ok());
}

#[test]
fn adding_an_optional_field_stays_within_the_major_version() {
    // §14: adding an optional field is minor. A document with the field and one
    // without are different bytes and different signatures, but both stay in one major version.
    let without = allocation();
    let with = seal(
        BlockAllocation {
            prev_closure: Some(Hash::sha256(b"prev")),
            signatures: SignatureSet::default(),
            ..without.clone()
        },
        &issuer(),
        |d, s| d.signatures = s,
    );
    assert_eq!(without.v, with.v);
    assert_ne!(
        canonical_bytes(&without).unwrap(),
        canonical_bytes(&with).unwrap()
    );

    let em = emission();
    let keys: KeySet = [issuer().public()].into_iter().collect();
    // A first block without the field and a second with it are both valid.
    assert!(without
        .validate(&em, true, None, &keys, &Profile::default())
        .is_ok());
    assert!(with
        .validate(&em, false, None, &keys, &Profile::default())
        .is_ok());
}

// --- the three time invariants of KS-2 ----------------------------------------
//
// All three were once proposed as "unverifiable holes", and the owner retired
// them: two are structurally hard to violate, and the third had the wrong form.
// They are checked here anyway, for a reason worth stating plainly: a check that
// is cheap and can only fire on a malformed document costs nothing and removes a
// class of silent nonsense. None of the three is a security property — a holder
// who controls both documents keeps them consistent — and the comments in the
// implementation say so.

#[test]
fn a_packet_handed_out_before_its_release_is_rejected() {
    // Invariant 2: allocated_at >= emission.issued_at. The issuer would have to
    // sign against himself to produce this, so it catches sloppiness, not fraud.
    let em = emission();
    let early = seal(
        BlockAllocation {
            allocated_at: ts("2026-08-26T00:00:00.000Z"),
            signatures: SignatureSet::default(),
            ..allocation()
        },
        &issuer(),
        |d, s| d.signatures = s,
    );
    let err = early
        .validate(
            &em,
            true,
            None,
            &[issuer().public()].into_iter().collect(),
            &Profile::default(),
        )
        .expect_err("a packet cannot predate its release");
    assert!(format!("{err}").contains("before the emission"), "{err}");
}

#[test]
fn a_binding_made_before_the_packet_was_handed_out_is_rejected() {
    // Invariant 1: bound_at >= allocation.allocated_at. Binding is done with the
    // buyer's keys, and before the purchase there is nothing to do it with.
    let alloc = allocation();
    let early = seal(
        AgentBinding {
            bound_at: ts("2026-08-27T09:00:00.000Z"),
            signatures: SignatureSet::default(),
            ..binding_by(&agent())
        },
        &agent(),
        |d, s| d.signatures = s,
    );
    let err = early
        .validate(&alloc, &KeySet::new(), &Profile::default())
        .expect_err("a binding cannot predate its packet");
    assert!(format!("{err}").contains("before the allocation"), "{err}");
}

// --- KS-4 §4: the holder authorizes the binding ------------------------------

/// The holder the packet was allocated to — the buyer, not the agent.
fn holder_signer() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:web:holder.example#h1"), [61u8; 32])
}

fn holder_key_set() -> KeySet {
    [holder_signer().public()].into_iter().collect()
}

/// A v2 binding signed by the agent and, optionally, by the holder.
fn binding_v2(with_holder: bool) -> AgentBinding {
    let doc = AgentBinding {
        context: ksg_core_v2::doc::Context,
        doc_type: "AgentBinding".into(),
        v: 3,
        emission: "ksg:em:000001".into(),
        block: block(),
        agent: agent().public(),
        bound_at: ts("2026-08-27T10:05:00.000Z"),
        signatures: SignatureSet::default(),
    };
    let mut sigs = vec![sign_doc(&doc, &agent()).unwrap()];
    if with_holder {
        sigs.push(sign_doc(&doc, &holder_signer()).unwrap());
    }
    AgentBinding {
        signatures: SignatureSet::new(sigs),
        ..doc
    }
}

#[test]
fn a_v2_binding_without_the_holders_authorization_is_rejected() {
    // KS-4 §4: without this the mismatch between `agent` and `allocation.holder`
    // is visible to anyone reading both documents and to no verifier at all. A
    // property checked by nothing counts as absent.
    let err = binding_v2(false)
        .validate(&allocation(), &holder_key_set(), &Profile::default())
        .unwrap_err();
    assert_eq!(
        err,
        Invalid::Schema("AgentBinding is not authorized by the holder of the packet")
    );
}

#[test]
fn a_v2_binding_with_the_holders_authorization_is_accepted() {
    // The refusal above is caused by the missing authorization, not by the
    // fixture: the same binding with the holder's signature passes.
    binding_v2(true)
        .validate(&allocation(), &holder_key_set(), &Profile::default())
        .expect("an authorized binding verifies");
}

#[test]
fn a_v2_binding_signed_by_the_holder_alone_is_rejected() {
    // The agent's own signature stays required. Without it a holder could bind
    // its packet to a key the agent never produced — the theft of KS-4 §4 run
    // in the other direction.
    let doc = AgentBinding {
        context: ksg_core_v2::doc::Context,
        doc_type: "AgentBinding".into(),
        v: 3,
        emission: "ksg:em:000001".into(),
        block: block(),
        agent: agent().public(),
        bound_at: ts("2026-08-27T10:05:00.000Z"),
        signatures: SignatureSet::default(),
    };
    let sig = sign_doc(&doc, &holder_signer()).unwrap();
    let holder_only = AgentBinding {
        context: ksg_core_v2::doc::Context,
        signatures: SignatureSet::new(vec![sig]),
        ..doc
    };
    let err = holder_only
        .validate(&allocation(), &holder_key_set(), &Profile::default())
        .unwrap_err();
    assert_eq!(
        err,
        Invalid::Schema("AgentBinding is not signed by the agent it names")
    );
}
