//! The agent's key set and the inclusion chain. Specification KS-1.
//!
//! What is checked is that the set **accumulates**: an act signed by the
//! first key stays valid when the set already holds many more. An
//! implementation built on "succession" — one that treats only the latest key
//! as current — passes most of these and fails
//! [`a_act_under_the_first_key_stays_valid`] (named for the act of core v1; in core v2 the set is read by the journal), which is why that case exists.
//!
//! The break cases run at the first, a middle and the last link. A test that
//! only checks the ends lets a mistake in the middle of the loop through.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use ksg_core_v2::canonical::doc_hash;
use ksg_core_v2::crypto::sign::{sign_doc, Ed25519Signer, Profile, PublicKey, SignatureSet};
use ksg_core_v2::doc::{AgentBinding, KeyInclusion, Range, Serial, Timestamp, Uri};
use ksg_core_v2::error::{ChainFail, Invalid};
use ksg_core_v2::keychain::{build_key_set, signing_key};

fn uri(s: &str) -> Uri {
    Uri::parse(s).unwrap()
}
fn ts(s: &str) -> Timestamp {
    Timestamp::parse(s).unwrap()
}
/// Key number `n` of the chain: 0 is the binding key, 1.. are the included ones.
fn key(n: u8) -> Ed25519Signer {
    Ed25519Signer::from_seed(uri(&format!("did:key:zAgent#k{n}")), [40 + n; 32])
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

fn binding() -> AgentBinding {
    let signer = key(0);
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
    seal(doc, &signer, |d, s| d.signatures = s)
}

/// One link: `added` laid on top of `predecessor`, signed by `signer`.
fn link(
    predecessor: ksg_core_v2::crypto::hash::Hash,
    added: &PublicKey,
    signer: &Ed25519Signer,
    offset_ms: u64,
) -> KeyInclusion {
    let doc = KeyInclusion {
        context: ksg_core_v2::doc::Context,
        doc_type: "KeyInclusion".into(),
        v: 3,
        emission: "ksg:em:000001".into(),
        block: block(),
        predecessor,
        key: added.clone(),
        offset_ms,
        signatures: SignatureSet::default(),
    };
    seal(doc, signer, |d, s| d.signatures = s)
}

/// A well-formed chain of `n` links: K0→K1→…→Kn.
fn chain(n: u8) -> (AgentBinding, Vec<KeyInclusion>) {
    let b = binding();
    let mut out = Vec::new();
    let mut prev_hash = doc_hash(&b).unwrap();
    for i in 1..=n {
        let inc = link(
            prev_hash,
            &key(i).public(),
            &key(i - 1),
            u64::from(i) * 1_000,
        );
        prev_hash = doc_hash(&inc).unwrap();
        out.push(inc);
    }
    (b, out)
}

/// The key of the set that signed a document signed by key number `n`, if any.
///
/// Core v2 has no act: the set is consumed by whoever checks a signature with
/// it (the journal's pages, the container's commands). What is pinned here is
/// that the set answers for every key it ever took in, not only the newest.
fn author(bind: &AgentBinding, inclusions: &[KeyInclusion], n: u8) -> Option<PublicKey> {
    let keys = build_key_set(bind, inclusions, &Profile::default()).unwrap();
    let sig = sign_doc(bind, &key(n)).unwrap();
    signing_key(&SignatureSet::new(vec![sig]), &keys)
}

// --- the set builds -----------------------------------------------------------

#[test]
fn an_empty_chain_is_the_binding_key_alone() {
    let (b, _) = chain(0);
    let keys = build_key_set(&b, &[], &Profile::default()).unwrap();
    assert_eq!(keys.len(), 1, "no chain means the binding key alone");
    assert!(keys.get(&b.agent.kid).is_some());
}

#[test]
fn every_link_adds_exactly_one_key() {
    let (b, inc) = chain(3);
    let keys = build_key_set(&b, &inc, &Profile::default()).unwrap();
    assert_eq!(keys.len(), 4, "the binding key plus three included ones");
    for i in 0..=3 {
        assert!(
            keys.get(&key(i).public().kid).is_some(),
            "key {i} must be in the set"
        );
    }
}

#[test]
fn a_chain_of_121_links_resolves() {
    let (b, inc) = chain(120);
    let keys = build_key_set(&b, &inc, &Profile::default()).unwrap();
    assert_eq!(keys.len(), 121, "length is not bounded");
}

// --- the set accumulates, it does not supersede -------------------------------

#[test]
fn a_act_under_the_first_key_stays_valid() {
    // KS-1 §1.1. This is the case an implementation built on "succession" fails:
    // it treats only the latest key as current and rejects an act signed by
    // the first, while passing every other case in this file.
    let (b, inc) = chain(3);
    let author = author(&b, &inc, 0).expect("the oldest key stays valid while the set holds four");
    assert_eq!(author.kid, key(0).public().kid);
}

#[test]
fn a_act_under_the_newest_key_is_valid() {
    let (b, inc) = chain(3);
    let author = author(&b, &inc, 3).unwrap();
    assert_eq!(author.kid, key(3).public().kid);
}

#[test]
fn a_act_under_a_middle_key_is_valid() {
    let (b, inc) = chain(3);
    let author = author(&b, &inc, 2).unwrap();
    assert_eq!(
        author.kid,
        key(2).public().kid,
        "the author is the key that signed, not the root of the chain"
    );
}

// --- a break refuses, and names the link --------------------------------------

/// Replaces link `at` with one whose predecessor points nowhere.
fn break_at(inc: &mut [KeyInclusion], at: usize) {
    let wrong = ksg_core_v2::crypto::hash::Hash::sha256(b"not a link of this chain");
    let mut broken = inc[at].clone();
    broken.predecessor = wrong;
    let signer = if at == 0 { key(0) } else { key(at as u8) };
    inc[at] = seal(broken, &signer, |d, s| d.signatures = s);
}

#[test]
fn a_break_at_the_first_link_is_refused() {
    let (b, mut inc) = chain(3);
    break_at(&mut inc, 0);
    assert_eq!(
        build_key_set(&b, &inc, &Profile::default()).unwrap_err(),
        Invalid::KeyChain(ChainFail::Break { link: 0 })
    );
}

#[test]
fn a_break_in_the_middle_is_refused_and_names_the_link() {
    // 60 of 121: a test that only checks the ends lets a mistake in the middle
    // of the loop through.
    let (b, mut inc) = chain(120);
    break_at(&mut inc, 60);
    assert_eq!(
        build_key_set(&b, &inc, &Profile::default()).unwrap_err(),
        Invalid::KeyChain(ChainFail::Break { link: 60 })
    );
}

#[test]
fn a_break_at_the_last_link_is_refused() {
    let (b, mut inc) = chain(120);
    break_at(&mut inc, 119);
    assert_eq!(
        build_key_set(&b, &inc, &Profile::default()).unwrap_err(),
        Invalid::KeyChain(ChainFail::Break { link: 119 })
    );
}

#[test]
fn a_link_signed_by_the_wrong_key_is_refused() {
    let (b, mut inc) = chain(3);
    // Link 1 must be signed by K1; sign it by K0 instead. The chain position is
    // intact, so this must be a Signature failure, not a Break.
    let unsigned = KeyInclusion {
        context: ksg_core_v2::doc::Context,
        signatures: SignatureSet::default(),
        ..inc[1].clone()
    };
    inc[1] = seal(unsigned, &key(0), |d, s| d.signatures = s);
    assert_eq!(
        build_key_set(&b, &inc, &Profile::default()).unwrap_err(),
        Invalid::KeyChain(ChainFail::Signature { link: 1 })
    );
}

#[test]
fn a_link_of_another_block_is_refused() {
    let (b, mut inc) = chain(2);
    let foreign = KeyInclusion {
        context: ksg_core_v2::doc::Context,
        block: r(9_000_000, 9_000_999),
        signatures: SignatureSet::default(),
        ..inc[0].clone()
    };
    inc[0] = seal(foreign, &key(0), |d, s| d.signatures = s);
    assert_eq!(
        build_key_set(&b, &inc, &Profile::default()).unwrap_err(),
        Invalid::KeyChain(ChainFail::Foreign { link: 0 })
    );
}

#[test]
fn re_including_the_same_key_is_refused() {
    let b = binding();
    let first = link(doc_hash(&b).unwrap(), &key(1).public(), &key(0), 1_000);
    let again = link(doc_hash(&first).unwrap(), &key(1).public(), &key(1), 2_000);
    assert_eq!(
        build_key_set(&b, &[first, again], &Profile::default()).unwrap_err(),
        Invalid::KeyChain(ChainFail::Duplicate { link: 1 })
    );
}

#[test]
fn a_key_outside_the_set_is_refused() {
    let (b, inc) = chain(2);
    // K5 was never included.
    assert!(
        author(&b, &inc, 5).is_none(),
        "a key outside the set must not be named the author"
    );
}

#[test]
fn a_chain_longer_than_the_limit_is_refused() {
    // Core v2 §14: every list the verifier walks has a ceiling.
    let (b, inc) = chain(1);
    let many = vec![inc[0].clone(); ksg_core_v2::limits::MAX_KEY_INCLUSIONS + 1];
    assert!(matches!(
        build_key_set(&b, &many, &Profile::default()).unwrap_err(),
        Invalid::Limit(_)
    ));
}
