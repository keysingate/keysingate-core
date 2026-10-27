//! Finding 4 of the 13.09 hardening audit — bypassing KS-4 by withholding the chain.
//!
//! Until 17.09 `resolve()` was never called in `src/` once: it existed, was
//! covered by tests, and was never applied. The holder of a leaked operational key
//! simply never presented the delegation chain, so neither the depth limit (≤ 4),
//! nor range nesting (§5b), nor each link's term was checked against anything.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use ksg_core_v2::canonical::doc_hash;
use ksg_core_v2::crypto::sign::{sign_doc, Ed25519Signer, KeySet, Profile, SignatureSet};
use ksg_core_v2::doc::{
    BlockAllocation, Class, Delegation, Emission, Range, Serial, Timestamp, Uri, MAX_DEPTH,
};

fn uri(s: &str) -> Uri {
    Uri::parse(s).expect("uri")
}
fn ts(s: &str) -> Timestamp {
    Timestamp::parse(s).expect("timestamp")
}
fn r(from: u64, to: u64) -> Range {
    Range {
        from: Serial(from),
        to: Serial(to),
    }
}

/// The root key: signs releases and delegations.
fn root() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:web:issuer.example#root"), [90u8; 32])
}
/// The operational key: signs packets — but only by delegation.
fn operational() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:web:issuer.example#ops1"), [91u8; 32])
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
        keys: vec![root().public()],
        signatures: SignatureSet::default(),
    };
    let sig = sign_doc(&doc, &root()).expect("signature");
    Emission {
        signatures: SignatureSet::new(vec![sig]),
        ..doc
    }
}

fn grant(range: Range, depth: u8, parent: Option<&Delegation>, by: &Ed25519Signer) -> Delegation {
    let doc = Delegation {
        context: ksg_core_v2::doc::Context,
        doc_type: "Delegation".into(),
        v: 3,
        emission: "ksg:em:000001".into(),
        range,
        delegate: uri("did:web:issuer.example"),
        keys: vec![operational().public()],
        parent: parent.map(|p| doc_hash(p).expect("hash")),
        depth,
        delegated_at: ts("2026-08-27T01:00:00.000Z"),
        expires_at: ts("2027-08-27T00:00:00.000Z"),
        term_ms: ksg_core_v2::doc::GRANT_MS,
        signatures: SignatureSet::default(),
    };
    let sig = sign_doc(&doc, by).expect("signature");
    Delegation {
        signatures: SignatureSet::new(vec![sig]),
        ..doc
    }
}

/// A packet signed by the operational key, over the given range.
fn allocation(block: Range) -> BlockAllocation {
    let doc = BlockAllocation {
        context: ksg_core_v2::doc::Context,
        doc_type: "BlockAllocation".into(),
        v: 3,
        emission: "ksg:em:000001".into(),
        block,
        class: Class::Heavy,
        holder: uri("did:web:holder.example"),
        allocated_at: ts("2026-08-27T10:00:00.000Z"),
        expires_at: ts("2026-11-25T10:00:00.000Z"),
        prev_closure: None,
        signatures: SignatureSet::default(),
    };
    let sig = sign_doc(&doc, &operational()).expect("signature");
    BlockAllocation {
        signatures: SignatureSet::new(vec![sig]),
        ..doc
    }
}

/// The verifier that **trusts** the operational key: exactly the situation
/// the finding starts from — the key leaked into the set.
fn trusting_keys() -> KeySet {
    [root().public(), operational().public()]
        .into_iter()
        .collect()
}

fn validate_with(chain: &[Delegation], block: Range) -> Result<(), ksg_core_v2::error::Invalid> {
    let em = emission();
    let al = allocation(block);
    let keys = trusting_keys();
    let root_set: KeySet = em
        .keys
        .iter()
        .filter(|k| keys.get(&k.kid).is_some())
        .cloned()
        .collect();
    let (signing, permitted) =
        ksg_core_v2::doc::resolve(&em, chain, &root_set, &Profile::default())?;
    al.validate(&em, true, None, &signing, &Profile::default())?;
    if !permitted.contains(al.block.from) || !permitted.contains(al.block.to) {
        return Err(ksg_core_v2::error::Invalid::OutOfRange {
            serial: al.block.from.0,
        });
    }
    Ok(())
}

#[test]
fn an_operational_key_without_its_chain_is_not_the_issuer() {
    // The finding's scenario: the chain is simply never presented. It used to pass
    // because the key sat in the verifier's set and nobody asked where its
    // right to issue came from.
    let err = validate_with(&[], r(1000, 1999))
        .expect_err("a key absent from the emission issues no packets without a delegation");
    let _ = err;
}

#[test]
fn the_same_key_with_its_chain_works() {
    // The flip side: a presented chain grants exactly the right written into it —
    // otherwise the fix would stop a lawful delegate from working.
    let d = grant(r(1, 1_000_000), 0, None, &root());
    validate_with(&[d], r(1000, 1999)).expect("a delegate inside its range issues");
}

#[test]
fn a_delegate_issuing_outside_its_range_is_refused() {
    // §5b: the delegate's range nests inside the grantor's, and the packet inside
    // the delegate's. Checking the range against the emission misses this: the
    // packet is inside the emission but outside the grant.
    let d = grant(r(1, 1000), 0, None, &root());
    validate_with(&[d], r(5000, 5999))
        .expect_err("a packet outside the granted range must be refused");
}

#[test]
fn a_chain_past_the_depth_limit_is_refused() {
    // The KS-4 limit: depth at most MAX_DEPTH. A longer chain is refused whole —
    // it used not to be considered at all.
    let mut chain: Vec<Delegation> = Vec::new();
    let mut parent: Option<Delegation> = None;
    for depth in 0..=(MAX_DEPTH + 1) {
        let by = if depth == 0 { root() } else { operational() };
        let d = grant(r(1, 1_000_000), depth, parent.as_ref(), &by);
        parent = Some(d.clone());
        chain.push(d);
    }
    assert!(
        chain.len() > MAX_DEPTH as usize + 1,
        "the chain must exceed the limit, or the test checks nothing"
    );
    validate_with(&chain, r(1000, 1999)).expect_err("a chain past the depth limit is refused");
}
