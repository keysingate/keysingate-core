//! "Who looked" inside the container (`ksg_container_v2::view`,
//! `[decision]` 13.09 §8.1, 19.09 CT-15, CT-16).
//!
//! | Rule | What is checked |
//! |---|---|
//! | the notice is attached to an anchor the container holds | a notice of another transaction is refused |
//! | the owner-watcher's signature is the evidence | a request signed by another key, or out of its window, is refused |
//! | one look, one notice | the same request delivered twice is recorded once |
//! | the ring never grows | past [`NOTICE_RING`] the oldest drop and are counted |
//! | the trail survives storage | sealed and opened again, the notices are there and re-checked |

mod stand;

use ksg_container_v2::view::{
    AnchorRef, DisclosureRequest, ViewError, ViewNotice, MAX_NOTICE_BYTES, NOTICE_RING,
};
use ksg_container_v2::Container;
use ksg_core_v2::anchor::Attestation;
use ksg_core_v2::canonical::canonical_bytes;
use ksg_core_v2::crypto::sign::{
    b64_encode, Alg, Ed25519Signer, Profile, PublicKey, Signature, SignatureSet,
};
use ksg_core_v2::doc::{Class, Timestamp};
use stand::*;

const SIG: &str =
    "5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUW";
const KEY: [u8; 32] = [7; 32];

fn audience() -> ksg_core_v2::doc::Uri {
    uri("https://desk.keysingate.example/v1")
}

/// A printed container whose status record 0 carries a Solana-shaped proof
/// of transaction [`SIG`] — as the reader writes it.
fn container() -> Stand {
    let mut s = Stand::new(Class::Heavy, 91);
    let proof = serde_json::json!({"signature": SIG, "slot": 5, "cluster": "devnet"});
    let att = Attestation {
        kind: uri("urn:ksg:anchor:solana:status:v1"),
        subject: s.c.status_head(),
        proof: ksg_core_v2::canonical::canonicalize(&proof).expect("json"),
        anchored_at: ts("2026-09-12T00:00:01.000Z"),
    };
    s.c.reanchor_last(None, Some(att))
        .expect("the record's own anchor");
    s
}

fn watcher() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:key:zWatcher#w1"), [99; 32])
}

fn request(by: &Ed25519Signer, n: u8, tx: &str) -> DisclosureRequest {
    let mut r = DisclosureRequest {
        doc_type: DisclosureRequest::TYPE.into(),
        v: 3,
        owner: vec![by.public()],
        audience: audience(),
        anchor: AnchorRef {
            cluster: "devnet".into(),
            signature: tx.into(),
        },
        challenge: format!("{n:02x}").repeat(32),
        issued_at: ts("2026-10-01T10:00:00.000Z"),
        expires_at: ts("2026-10-01T10:05:00.000Z"),
        signatures: SignatureSet::default(),
    };
    r.signatures = SignatureSet::new(vec![by.sign(&canonical_bytes(&r).expect("bytes"))]);
    r
}

fn notice(r: DisclosureRequest, at: &str) -> ViewNotice {
    ViewNotice::of(r, ts(at))
}

#[test]
fn a_signed_look_at_our_anchor_is_recorded_once() {
    let mut s = container();
    let n = notice(request(&watcher(), 1, SIG), "2026-10-01T10:01:00.000Z");
    s.c.record_view(n.clone(), &Profile::default())
        .expect("recorded");
    assert_eq!(s.c.views().seen(), 1);
    assert_eq!(s.c.views().as_slice()[0].owner_id(), "did:key:zWatcher");
    assert_eq!(
        s.c.record_view(n, &Profile::default()),
        Err(ViewError::Again)
    );
    assert_eq!(s.c.views().seen(), 1);
}

#[test]
fn a_look_at_another_anchor_is_not_ours() {
    let mut s = container();
    let other =
        "4VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUW";
    let n = notice(request(&watcher(), 1, other), "2026-10-01T10:01:00.000Z");
    assert_eq!(
        s.c.record_view(n, &Profile::default()),
        Err(ViewError::NotOurs)
    );
}

#[test]
fn a_notice_without_the_watchers_own_signature_is_refused() {
    let mut s = container();
    // Signed by somebody else, but naming the watcher's key.
    let mut r = request(&watcher(), 1, SIG);
    let thief = Ed25519Signer::from_seed(uri("did:key:zWatcher#w1"), [3; 32]);
    r.signatures = SignatureSet::new(vec![thief.sign(&canonical_bytes(&r).expect("bytes"))]);
    let got =
        s.c.record_view(notice(r, "2026-10-01T10:01:00.000Z"), &Profile::default());
    assert!(matches!(got, Err(ViewError::Invalid(_))), "{got:?}");

    // The fabricated trail: the holder edits who looked.
    let mut r = request(&watcher(), 2, SIG);
    r.owner[0].kid = uri("did:key:zCompetitor#c1");
    let got =
        s.c.record_view(notice(r, "2026-10-01T10:01:00.000Z"), &Profile::default());
    assert!(matches!(got, Err(ViewError::Invalid(_))), "{got:?}");
}

#[test]
fn a_view_outside_the_requests_window_is_refused() {
    let mut s = container();
    for at in ["2026-10-01T09:59:59.999Z", "2026-10-01T10:05:00.001Z"] {
        let got =
            s.c.record_view(notice(request(&watcher(), 1, SIG), at), &Profile::default());
        assert!(matches!(got, Err(ViewError::Invalid(_))), "{at}: {got:?}");
    }
}

#[test]
fn malformed_requests_are_refused() {
    let w = watcher();
    let base = request(&w, 1, SIG);
    let p = Profile::default();
    let resign = |mut r: DisclosureRequest| {
        r.signatures = SignatureSet::new(vec![w.sign(&canonical_bytes(&r).expect("bytes"))]);
        r
    };
    let mut short = base.clone();
    short.challenge = "ab".repeat(8);
    let mut upper = base.clone();
    upper.challenge = "AB".repeat(32);
    let mut net = base.clone();
    net.anchor.cluster = "localnet".into();
    let mut tx = base.clone();
    tx.anchor.signature = "0OIl".repeat(20);
    let mut backwards = base.clone();
    backwards.expires_at = backwards.issued_at.clone();
    let mut none = base.clone();
    none.owner.clear();
    for (what, r) in [
        ("short challenge", short),
        ("upper-case challenge", upper),
        ("unknown network", net),
        ("not base58", tx),
        ("backwards window", backwards),
        ("no owner-watcher", none),
    ] {
        assert!(resign(r).check_signed(None, &p).is_err(), "{what}");
    }
    // Addressed to another service; owner-watcher's container dead.
    assert!(base
        .validate(
            &uri("https://other.example"),
            ksg_core_v2::status::Status::InWork,
            None,
            &p
        )
        .is_err());
    assert!(base
        .validate(&audience(), ksg_core_v2::status::Status::Exported, None, &p)
        .is_err());
    base.validate(&audience(), ksg_core_v2::status::Status::InWork, None, &p)
        .expect("the request itself is sound");
}

#[test]
fn the_ring_keeps_its_size_and_counts_what_it_dropped() {
    let mut s = container();
    let extra = 8u8;
    for i in 0..(NOTICE_RING as u8 + extra) {
        s.c.record_view(
            notice(request(&watcher(), i, SIG), "2026-10-01T10:01:00.000Z"),
            &Profile::default(),
        )
        .expect("recorded");
    }
    let v = s.c.views();
    assert_eq!(v.as_slice().len(), NOTICE_RING);
    assert_eq!(v.dropped(), u64::from(extra));
    assert_eq!(v.seen(), NOTICE_RING as u64 + u64::from(extra));
    // The oldest went first.
    assert_eq!(
        v.as_slice()[0].request.challenge,
        format!("{extra:02x}").repeat(32)
    );
    // The aggregate form: a count by period, not the moment of each look.
    assert_eq!(
        v.in_period(
            &ts("2026-10-01T00:00:00.000Z"),
            &ts("2026-10-01T23:59:59.999Z")
        ),
        NOTICE_RING
    );
    assert_eq!(
        v.in_period(
            &ts("2026-10-02T00:00:00.000Z"),
            &ts("2026-10-02T23:59:59.999Z")
        ),
        0
    );
}

#[test]
fn the_trail_survives_storage_and_is_checked_again() {
    let mut s = container();
    for i in 0..3 {
        s.c.record_view(
            notice(request(&watcher(), i, SIG), "2026-10-01T10:01:00.000Z"),
            &Profile::default(),
        )
        .expect("recorded");
    }
    let bytes = s.c.seal_to_bytes(&KEY, &mut s.rng).expect("sealed");
    let back = Container::open_sealed(&bytes, &s.c.template_id(), &KEY).expect("opens");
    assert_eq!(back.views(), s.c.views());
}

/// The largest notice a request can make — two keys, Ed25519 and ML-DSA-65,
/// and both signatures — fits [`MAX_NOTICE_BYTES`], and a container takes it.
#[test]
fn a_post_quantum_notice_fits_its_bound() {
    use fips204::traits::{SerDes as _, Signer as _};
    let mut s = container();
    let ed = watcher();
    let (pk, sk) = fips204::ml_dsa_65::try_keygen_with_rng(&mut s.rng).expect("keygen");
    let pq = PublicKey {
        kid: uri("did:key:zWatcher#pq1"),
        alg: Alg::MlDsa65,
        key: b64_encode(&pk.into_bytes()),
    };
    let mut r = request(&ed, 1, SIG);
    r.owner.push(pq.clone());
    let msg = canonical_bytes(&r).expect("bytes");
    let pq_sig = sk.try_sign_with_rng(&mut s.rng, &msg, &[]).expect("sign");
    r.signatures = SignatureSet::new(vec![
        ed.sign(&msg),
        Signature {
            kid: pq.kid,
            alg: Alg::MlDsa65,
            value: b64_encode(&pq_sig),
        },
    ]);
    let n = notice(r, "2026-10-01T10:01:00.000Z");
    let len = serde_json::to_vec(&n).expect("json").len();
    println!("POST-QUANTUM NOTICE: {len} bytes of {MAX_NOTICE_BYTES}");
    assert!(len <= MAX_NOTICE_BYTES);
    s.c.record_view(n, &Profile::default().with_ed25519_and_ml_dsa())
        .expect("recorded");
}

#[test]
fn timestamps_compare_as_moments() {
    // The window check leans on the fixed `.mmmZ` form: order of the strings
    // is the order of the moments.
    assert!(
        Timestamp::parse("2026-10-01T10:00:00.000Z").unwrap()
            < Timestamp::parse("2026-10-01T10:00:00.001Z").unwrap()
    );
}
