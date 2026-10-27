//! The desk (Ts-5 path A; CT-13, CT-14, CT-15, CT-38): a challenge, a signed
//! request, one charge, one notice — and the notice taken by the container
//! that was looked at.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use ksg_container_v2::view::{AnchorRef, DisclosureRequest};
use ksg_core_v2::canonical::canonical_bytes;
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{Ed25519Signer, Profile, SignatureSet};
use ksg_core_v2::doc::{Timestamp, Uri};
use ksg_core_v2::status::Status;
use ksg_service_v2::desk::{Desk, DeskError, StaticRegistry, CHALLENGE_TTL_MS, MAX_WINDOW_MS};
use ksg_service_v2::ladder::{price_of_period_cents, Stream, LADDER_CENTS, TOP_CENTS};

const SIG: &str =
    "5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUW";

fn uri(s: &str) -> Uri {
    Uri::parse(s).unwrap()
}
fn at(ms: u64) -> Timestamp {
    Timestamp::from_unix_ms(ms).unwrap()
}
const T0: u64 = 1_790_000_000_000;

fn anchor() -> AnchorRef {
    AnchorRef {
        cluster: "devnet".into(),
        signature: SIG.into(),
    }
}

fn watcher() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:key:zWatcher#w1"), [99; 32])
}

fn request(by: &Ed25519Signer, challenge: &str, width_ms: u64) -> DisclosureRequest {
    let mut r = DisclosureRequest {
        doc_type: DisclosureRequest::TYPE.into(),
        v: 3,
        owner: vec![by.public()],
        audience: uri("https://desk.example/v1"),
        anchor: anchor(),
        challenge: challenge.into(),
        issued_at: at(T0),
        expires_at: at(T0 + width_ms),
        signatures: SignatureSet::default(),
    };
    r.signatures = SignatureSet::new(vec![by.sign(&canonical_bytes(&r).unwrap())]);
    r
}

fn desk() -> (Desk, StaticRegistry, Hash) {
    let mut d = Desk::new(uri("https://desk.example/v1"));
    let container = Hash::sha256(b"the container looked at");
    d.linkage_mut().record(anchor(), container, "2026-10");
    let mut reg = StaticRegistry::default();
    reg.insert(&watcher().public(), Status::InWork);
    (d, reg, container)
}

#[test]
fn a_look_is_charged_by_its_number_and_leaves_one_notice() {
    let (mut d, reg, container) = desk();
    let p = Profile::default();
    for look in 1..=3u64 {
        let c = d.challenge([look as u8; 32], T0).unwrap();
        let a = d
            .accept(
                &request(&watcher(), &c, 60_000),
                &reg,
                Stream::Curious,
                "2026-10",
                &at(T0 + 1),
                &p,
            )
            .expect("accepted");
        assert_eq!(a.charge.look, look);
        assert_eq!(a.charge.cents, LADDER_CENTS[look as usize - 1]);
        assert_eq!(a.charge.payer, "did:key:zWatcher");
        assert_eq!(a.container, container);
    }
    let (notices, dropped) = d.take_notices(&container);
    assert_eq!((notices.len(), dropped), (3, 0));
    assert_eq!(d.take_notices(&container).0.len(), 0, "taken once");
    assert_eq!(d.drain_charges().len(), 3);
    assert!(d.drain_charges().is_empty());
    // A new period starts the ladder over.
    d.close_period("2026-10");
    let c = d.challenge([9; 32], T0).unwrap();
    let a = d
        .accept(
            &request(&watcher(), &c, 60_000),
            &reg,
            Stream::Curious,
            "2026-10",
            &at(T0 + 1),
            &p,
        )
        .unwrap();
    assert_eq!(a.charge.look, 1);
}

#[test]
fn the_legal_checker_climbs_no_ladder() {
    let (mut d, reg, _) = desk();
    let c = d.challenge([1; 32], T0).unwrap();
    let a = d
        .accept(
            &request(&watcher(), &c, 60_000),
            &reg,
            Stream::LegalChecker,
            "2026-10",
            &at(T0 + 1),
            &Profile::default(),
        )
        .unwrap();
    assert_eq!(a.charge.cents, 0);
}

#[test]
fn a_replayed_or_unissued_or_expired_challenge_is_refused() {
    let (mut d, reg, _) = desk();
    let p = Profile::default();
    let c = d.challenge([1; 32], T0).unwrap();
    let r = request(&watcher(), &c, 60_000);
    d.accept(&r, &reg, Stream::Curious, "p", &at(T0 + 1), &p)
        .unwrap();
    assert_eq!(
        d.accept(&r, &reg, Stream::Curious, "p", &at(T0 + 2), &p),
        Err(DeskError::Replay)
    );
    let never = "ab".repeat(32);
    assert_eq!(
        d.accept(
            &request(&watcher(), &never, 60_000),
            &reg,
            Stream::Curious,
            "p",
            &at(T0 + 1),
            &p
        ),
        Err(DeskError::Replay)
    );
    // Issued, but past its life: the request is still in its own window.
    let late = d.challenge([2; 32], T0).unwrap();
    let r = request(&watcher(), &late, MAX_WINDOW_MS);
    assert_eq!(
        d.accept(
            &r,
            &reg,
            Stream::Curious,
            "p",
            &at(T0 + CHALLENGE_TTL_MS + 1),
            &p
        ),
        Err(DeskError::Replay)
    );
    // Nothing was charged for the refusals.
    assert_eq!(d.drain_charges().len(), 1);
}

#[test]
fn path_a_refuses_a_key_in_no_chain_and_a_dead_container() {
    let (mut d, mut reg, _) = desk();
    let p = Profile::default();
    let stranger = Ed25519Signer::from_seed(uri("did:key:zStranger#s1"), [5; 32]);
    let c = d.challenge([1; 32], T0).unwrap();
    assert_eq!(
        d.accept(
            &request(&stranger, &c, 60_000),
            &reg,
            Stream::Curious,
            "p",
            &at(T0 + 1),
            &p
        ),
        Err(DeskError::NotInChain)
    );
    reg.insert(&stranger.public(), Status::Exported);
    let got = d.accept(
        &request(&stranger, &c, 60_000),
        &reg,
        Stream::Curious,
        "p",
        &at(T0 + 1),
        &p,
    );
    assert!(matches!(got, Err(DeskError::Invalid(_))), "{got:?}");
}

#[test]
fn a_wide_window_or_an_unknown_anchor_is_refused() {
    let (mut d, reg, _) = desk();
    let p = Profile::default();
    let c = d.challenge([1; 32], T0).unwrap();
    assert_eq!(
        d.accept(
            &request(&watcher(), &c, MAX_WINDOW_MS + 1),
            &reg,
            Stream::Curious,
            "p",
            &at(T0 + 1),
            &p
        ),
        Err(DeskError::WindowTooWide)
    );
    // The period of the anchor is dropped: we can no longer tell whose it is.
    assert_eq!(d.linkage_mut().forget("2026-10"), 1);
    assert_eq!(
        d.accept(
            &request(&watcher(), &c, 60_000),
            &reg,
            Stream::Curious,
            "p",
            &at(T0 + 1),
            &p
        ),
        Err(DeskError::UnknownAnchor)
    );
}

#[test]
fn the_desk_survives_a_restart() {
    let (mut d, reg, _) = desk();
    let c = d.challenge([1; 32], T0).unwrap();
    let mut back = Desk::from_json(&d.to_json().unwrap()).unwrap();
    assert_eq!(back, d);
    back.accept(
        &request(&watcher(), &c, 60_000),
        &reg,
        Stream::Curious,
        "p",
        &at(T0 + 1),
        &Profile::default(),
    )
    .expect("the challenge issued before the restart is still live");
}

#[test]
fn the_ladder_is_the_owners() {
    assert_eq!(price_of_period_cents(Stream::Curious, 20), 59_092_600);
    assert_eq!(
        price_of_period_cents(Stream::Curious, 21),
        59_092_600 + TOP_CENTS
    );
    assert_eq!(price_of_period_cents(Stream::LegalChecker, 100), 0);
}
