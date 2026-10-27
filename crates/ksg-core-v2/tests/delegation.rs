//! Delegation of issuance, and the issuer's two-tier key. KS-4 §5, §5b.
//!
//! The two cases share one type on purpose: the issuer delegating to its own
//! operational key is the same act as delegating to a distributor, only with
//! depth 1 and the same party at both ends.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use ksg_core_v2::canonical::doc_hash;
use ksg_core_v2::crypto::sign::{sign_doc, Ed25519Signer, KeySet, Profile, SignatureSet};
use ksg_core_v2::doc::{
    resolve, BlockAllocation, Class, Delegation, Emission, Range, Serial, Timestamp, Uri, MAX_DEPTH,
};

fn uri(s: &str) -> Uri {
    Uri::parse(s).expect("uri")
}
fn ts(s: &str) -> Timestamp {
    Timestamp::parse(s).expect("timestamp")
}

/// The root key: offline, split 3 of 5, signs releases and delegations only.
fn root() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:web:issuer.example#root"), [90u8; 32])
}
/// The operational key: online, rotatable, signs packets.
fn operational() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:web:issuer.example#ops1"), [91u8; 32])
}
fn distributor() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:web:dist.example#d1"), [92u8; 32])
}
fn agent() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:web:agent.example#a1"), [93u8; 32])
}
fn stranger() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:web:nobody.example#x1"), [94u8; 32])
}
fn root_keys() -> KeySet {
    [root().public()].into_iter().collect()
}

fn emission() -> Emission {
    let doc = Emission {
        context: ksg_core_v2::doc::Context,
        doc_type: "Emission".into(),
        v: 3,
        id: "ksg:em:000001".into(),
        range: Range {
            from: Serial(1),
            to: Serial(100_000_000),
        },
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

/// One link, signed by `grantor`.
fn link(
    depth: u8,
    parent: Option<&Delegation>,
    delegate: &str,
    keys: Vec<Ed25519Signer>,
    range: Range,
    grantor: &Ed25519Signer,
    expires: &str,
) -> Delegation {
    let doc = Delegation {
        context: ksg_core_v2::doc::Context,
        doc_type: "Delegation".into(),
        v: 3,
        emission: "ksg:em:000001".into(),
        range,
        delegate: uri(delegate),
        keys: keys.iter().map(Ed25519Signer::public).collect(),
        parent: parent.map(|p| doc_hash(p).expect("hash")),
        depth,
        delegated_at: ts("2026-08-27T01:00:00.000Z"),
        expires_at: ts(expires),
        term_ms: ksg_core_v2::doc::GRANT_MS,
        signatures: SignatureSet::default(),
    };
    let sig = sign_doc(&doc, grantor).expect("signature");
    Delegation {
        signatures: SignatureSet::new(vec![sig]),
        ..doc
    }
}

fn r(from: u64, to: u64) -> Range {
    Range {
        from: Serial(from),
        to: Serial(to),
    }
}

/// The case the owner asked for: the root key hands issuance to the
/// operational key, over the whole release.
fn two_tier() -> Delegation {
    link(
        0,
        None,
        "did:web:issuer.example",
        vec![operational()],
        r(1, 100_000_000),
        &root(),
        "2027-08-27T00:00:00.000Z",
    )
}

// --- the two-tier key --------------------------------------------------------

#[test]
fn the_root_key_hands_packets_to_the_operational_key() {
    // What the split buys: the key that signs often is not the key that must
    // never leak.
    let (keys, range) = resolve(
        &emission(),
        std::slice::from_ref(&two_tier()),
        &root_keys(),
        &Profile::default(),
    )
    .expect("the chain resolves");

    assert!(
        keys.get(&operational().public().kid).is_some(),
        "packets are signed by the operational key"
    );
    assert!(
        keys.get(&root().public().kid).is_none(),
        "the root key is out of the packet path entirely"
    );
    assert_eq!(range, emission().range);
}

#[test]
fn an_allocation_signed_by_the_operational_key_verifies_through_it() {
    // KS-4 §5: "the document type need not change". This is that claim, run.
    let em = emission();
    let (keys, _) = resolve(
        &em,
        std::slice::from_ref(&two_tier()),
        &root_keys(),
        &Profile::default(),
    )
    .expect("resolve");

    let doc = BlockAllocation {
        context: ksg_core_v2::doc::Context,
        doc_type: "BlockAllocation".into(),
        v: 3,
        emission: "ksg:em:000001".into(),
        block: r(4_700_000, 4_700_999),
        class: Class::Heavy,
        holder: uri("did:web:holder.example"),
        allocated_at: ts("2026-08-27T10:00:00.000Z"),
        expires_at: ts("2026-11-25T10:00:00.000Z"),
        prev_closure: None,
        signatures: SignatureSet::default(),
    };
    let sig = sign_doc(&doc, &operational()).expect("signature");
    let alloc = BlockAllocation {
        context: ksg_core_v2::doc::Context,
        signatures: SignatureSet::new(vec![sig]),
        ..doc
    };

    alloc
        .validate(&em, true, None, &keys, &Profile::default())
        .expect("the allocation verifies under the delegated keys");

    // And the same allocation fails against the root keys alone, which is the
    // point: the root key is genuinely not in that path.
    assert!(alloc
        .validate(&em, true, None, &root_keys(), &Profile::default())
        .is_err());
}

#[test]
fn rotating_the_operational_key_needs_no_new_root_signature_within_a_grant() {
    // The grant lists keys, so a second operational key can be carried by the
    // same delegation. Replacing the grant entirely is what needs the root key,
    // and that is the rare event the split exists to make rare.
    let two = link(
        0,
        None,
        "did:web:issuer.example",
        vec![operational(), agent()],
        r(1, 100_000_000),
        &root(),
        "2027-08-27T00:00:00.000Z",
    );
    let (keys, _) =
        resolve(&emission(), &[two], &root_keys(), &Profile::default()).expect("resolve");
    assert_eq!(keys.len(), 2);
}

#[test]
fn no_delegation_at_all_leaves_the_issuer_signing_for_itself() {
    // An empty chain is not an error but the arrangement everything worked
    // under before this type existed.
    let (keys, range) =
        resolve(&emission(), &[], &root_keys(), &Profile::default()).expect("resolve");
    assert_eq!(keys, root_keys());
    assert_eq!(range, emission().range);
}

// --- the chain ---------------------------------------------------------------

/// issuer → distributor → agent, each narrower than the last.
fn chain_of_two() -> Vec<Delegation> {
    let d = link(
        0,
        None,
        "did:web:dist.example",
        vec![distributor()],
        r(1, 1_000_000),
        &root(),
        "2027-08-27T00:00:00.000Z",
    );
    let a = link(
        1,
        Some(&d),
        "did:web:agent.example",
        vec![agent()],
        r(1000, 1999),
        &distributor(),
        "2027-01-01T00:00:00.000Z",
    );
    vec![d, a]
}

#[test]
fn the_chain_narrows_at_every_step_and_the_leaf_keys_win() {
    let (keys, range) = resolve(
        &emission(),
        &chain_of_two(),
        &root_keys(),
        &Profile::default(),
    )
    .expect("resolve");
    assert!(keys.get(&agent().public().kid).is_some());
    assert!(
        keys.get(&distributor().public().kid).is_none(),
        "only the leaf issues"
    );
    assert_eq!(range, r(1000, 1999));
}

#[test]
fn a_delegate_cannot_grant_outside_what_it_was_given() {
    // §5b. Without the nesting check a sub-delegate issues serials its grantor
    // never held.
    let d = &chain_of_two()[0];
    let wider = link(
        1,
        Some(d),
        "did:web:agent.example",
        vec![agent()],
        r(1000, 5_000_000),
        &distributor(),
        "2027-01-01T00:00:00.000Z",
    );
    let err = resolve(
        &emission(),
        &[d.clone(), wider],
        &root_keys(),
        &Profile::default(),
    )
    .unwrap_err();
    assert!(format!("{err}").contains("not inside the grantor"), "{err}");
}

#[test]
fn a_link_signed_by_the_wrong_party_refuses_the_whole_chain() {
    // One link that does not fit refuses everything, as in KS-1: a chain
    // checked only at its ends lets a mistake in the middle through.
    let d = &chain_of_two()[0];
    let forged = link(
        1,
        Some(d),
        "did:web:agent.example",
        vec![agent()],
        r(1000, 1999),
        &stranger(),
        "2027-01-01T00:00:00.000Z",
    );
    assert!(resolve(
        &emission(),
        &[d.clone(), forged],
        &root_keys(),
        &Profile::default()
    )
    .is_err());
}

#[test]
fn a_grant_may_not_outlive_the_grant_it_came_from() {
    // Otherwise the chain above it ends and the leaf goes on issuing — the
    // expiry would be decorative.
    let d = &chain_of_two()[0];
    let longer = link(
        1,
        Some(d),
        "did:web:agent.example",
        vec![agent()],
        r(1000, 1999),
        &distributor(),
        "2028-01-01T00:00:00.000Z",
    );
    let err = resolve(
        &emission(),
        &[d.clone(), longer],
        &root_keys(),
        &Profile::default(),
    )
    .unwrap_err();
    assert!(format!("{err}").contains("outlives"), "{err}");
}

#[test]
fn depth_and_parent_must_agree() {
    // A depth-0 link with a parent claims two grantors; a deeper one without a
    // parent claims none. Both are refused rather than guessed at.
    let d = &chain_of_two()[0];

    let mut orphan = chain_of_two()[1].clone();
    orphan.parent = None;
    assert!(resolve(
        &emission(),
        &[d.clone(), orphan],
        &root_keys(),
        &Profile::default()
    )
    .is_err());

    let mut wrong_depth = chain_of_two()[1].clone();
    wrong_depth.depth = 3;
    assert!(resolve(
        &emission(),
        &[d.clone(), wrong_depth],
        &root_keys(),
        &Profile::default()
    )
    .is_err());
}

#[test]
fn the_channel_limit_is_four_intermediary_levels() {
    // KS-7 §7.2-sexies: distributor, general agent, regional, local. The
    // consequence worth keeping is that the set of parties trusted by
    // construction has a ceiling.
    assert_eq!(MAX_DEPTH, 4);

    let mut chain: Vec<Delegation> = Vec::new();
    let mut signer = root();
    for depth in 0..=MAX_DEPTH {
        let parent = chain.last().cloned();
        let next = Ed25519Signer::from_seed(
            uri(&format!("did:web:level{depth}.example#k")),
            [100 + depth; 32],
        );
        chain.push(link(
            depth,
            parent.as_ref(),
            &format!("did:web:level{depth}.example"),
            vec![next.clone()],
            r(1000, 1999),
            &signer,
            "2027-01-01T00:00:00.000Z",
        ));
        signer = next;
    }
    resolve(&emission(), &chain, &root_keys(), &Profile::default())
        .expect("four intermediary levels are allowed");

    // One deeper is refused, and by the depth field rather than by the length.
    let deeper = link(
        MAX_DEPTH + 1,
        chain.last(),
        "did:web:toodeep.example",
        vec![stranger()],
        r(1000, 1999),
        &signer,
        "2027-01-01T00:00:00.000Z",
    );
    chain.push(deeper);
    let err = resolve(&emission(), &chain, &root_keys(), &Profile::default()).unwrap_err();
    assert!(format!("{err}").contains("channel limit"), "{err}");
}

#[test]
fn a_foreign_emission_and_an_empty_range_are_refused() {
    let mut foreign = two_tier();
    foreign.emission = "ksg:em:000002".into();
    assert!(resolve(&emission(), &[foreign], &root_keys(), &Profile::default()).is_err());

    let empty = link(
        0,
        None,
        "did:web:issuer.example",
        vec![operational()],
        Range {
            from: Serial(500),
            to: Serial(499),
        },
        &root(),
        "2027-08-27T00:00:00.000Z",
    );
    assert!(resolve(&emission(), &[empty], &root_keys(), &Profile::default()).is_err());
}

#[test]
fn a_grant_of_no_keys_is_refused() {
    // A delegation that hands over nothing is not a narrower grant — it is a
    // grant nobody can act on, and it would silently empty the key set.
    let none = link(
        0,
        None,
        "did:web:issuer.example",
        vec![],
        r(1, 1000),
        &root(),
        "2027-08-27T00:00:00.000Z",
    );
    let err = resolve(&emission(), &[none], &root_keys(), &Profile::default()).unwrap_err();
    assert!(format!("{err}").contains("grants no keys"), "{err}");
}

// --- the term of an operational grant — `[decision]` 12.09 --------------------------

#[test]
fn the_grant_term_and_its_margin_are_named_numbers() {
    // 90 days with a 30-day overlap. The overlap is the point: a term without
    // one is a cliff, and organizations cope with cliffs by lengthening the
    // term — which is the outcome the term was chosen to avoid.
    assert_eq!(ksg_core_v2::doc::GRANT_MS, 90 * 24 * 60 * 60 * 1000);
    assert_eq!(ksg_core_v2::doc::GRANT_OVERLAP_MS, 30 * 24 * 60 * 60 * 1000);
    // The renewal is issued while the old grant still has the overlap to run,
    // so a ceremony delayed by that much costs nothing.
    const _: () = assert!(ksg_core_v2::doc::GRANT_OVERLAP_MS < ksg_core_v2::doc::GRANT_MS);
}

#[test]
fn a_term_of_zero_or_past_the_ceiling_is_refused() {
    ksg_core_v2::doc::check_term(ksg_core_v2::doc::GRANT_MS).expect("the standard term");
    ksg_core_v2::doc::check_term(ksg_core_v2::doc::GRANT_MAX_MS).expect("the ceiling itself");
    assert!(ksg_core_v2::doc::check_term(0).is_err());
    assert!(ksg_core_v2::doc::check_term(ksg_core_v2::doc::GRANT_MAX_MS + 1).is_err());
}

#[test]
fn the_span_arrives_as_an_argument_and_not_from_a_calendar() {
    // Nothing here reads dates: `Timestamp` is a string whose lexicographic
    // order is its chronological one, and the calendar is the caller's. The same
    // shape as the elapsed time a succession claim is judged by.
    let span = 45 * 24 * 60 * 60 * 1000;
    ksg_core_v2::doc::check_term(span).expect("a shorter term is a deployment's business");
}

#[test]
fn a_grant_past_the_ceiling_no_longer_passes_validation() {
    // The finding of the completeness review: the bound sat in a constant, the
    // check sat in a function nobody called, and a five-year grant validated.
    let mut d = two_tier();
    d.term_ms = 5 * 365 * 24 * 60 * 60 * 1000;
    d.signatures = SignatureSet::new(vec![sign_doc(&d, &root()).expect("sig")]);
    assert!(
        d.validate(&emission(), None, &root_keys(), &Profile::default())
            .is_err(),
        "a five-year operational grant must not validate"
    );
    // And the standard term still does.
    two_tier()
        .validate(&emission(), None, &root_keys(), &Profile::default())
        .expect("ninety days stands");
}

#[test]
fn the_stated_term_is_checkable_against_the_dates_by_whoever_has_a_calendar() {
    // The document binds the grantor to a number; a verifier with a clock
    // catches a number that does not match the dates beside it.
    let d = two_tier();
    assert!(d.term_matches(ksg_core_v2::doc::GRANT_MS));
    assert!(!d.term_matches(ksg_core_v2::doc::GRANT_MS + 1));
}

#[test]
fn renewal_is_due_one_overlap_before_the_end() {
    // `[decision]` 12.09 — the new grant is issued before the old one ends, and both
    // are valid through the overlap. A ceremony delayed by that much costs
    // nothing, which is the whole reason the overlap exists.
    let d = two_tier();
    let day = 24 * 60 * 60 * 1000;
    assert!(!d.renewal_due(59 * day), "at 59 days there is no hurry");
    assert!(
        d.renewal_due(60 * day),
        "at 60 days the overlap window opens"
    );
    assert!(d.renewal_due(90 * day), "and it stays due after that");
}

// ---------------------------------------------------------------------------
// Security audit of 2026-09-13, finding 12 — closed by [decision] 19.09, CT-20:
// the verifier's clock arrives in the profile.
// ---------------------------------------------------------------------------

fn at(now: &str) -> Profile {
    Profile {
        now: Some(ts(now)),
        ..Profile::default()
    }
}

#[test]
fn a_leaked_operational_key_stops_working_once_its_grant_runs_out() {
    // The attack: the operational key leaks. The grant runs to 27.08.2027.
    // A verifier checking offline a year after that date used to accept the
    // key — nothing in the core compared `expires_at` with now, so "rotation
    // instead of revocation" protected nobody who checked late.
    let chain = [two_tier()];

    resolve(
        &emission(),
        &chain,
        &root_keys(),
        &at("2027-03-01T00:00:00.000Z"),
    )
    .expect("inside the grant, the key is the issuer's hand");

    assert_eq!(
        resolve(
            &emission(),
            &chain,
            &root_keys(),
            &at("2028-08-27T00:00:00.000Z"),
        )
        .unwrap_err(),
        ksg_core_v2::error::Invalid::Schema("the delegation has expired by the verifier's clock"),
        "a year after the grant ran out, the leaked key still issued — finding 12"
    );
}

#[test]
fn a_grant_not_yet_in_force_is_not_authority_now() {
    let chain = [two_tier()];
    assert_eq!(
        resolve(
            &emission(),
            &chain,
            &root_keys(),
            &at("2026-08-27T00:30:00.000Z"),
        )
        .unwrap_err(),
        ksg_core_v2::error::Invalid::Schema(
            "the delegation is not yet in force by the verifier's clock"
        )
    );
}

#[test]
fn without_a_clock_the_claim_is_narrower_but_it_still_verifies() {
    // [decision] 19.09: time in the profile is the verifier's responsibility. A
    // verifier who brings none gets authenticity proved and the currency of
    // the authority unchecked — the old behaviour, now named as such.
    resolve(
        &emission(),
        std::slice::from_ref(&two_tier()),
        &root_keys(),
        &Profile::default(),
    )
    .expect("no clock, no currency check — and no refusal either");
}

#[test]
fn every_link_of_a_deep_chain_answers_to_the_same_clock() {
    // A clock checked only at the leaf would let an expired middle link stand
    // behind a fresh one. Each link is validated against the profile.
    let top = two_tier();
    let mid = link(
        1,
        Some(&top),
        "did:web:distributor.example",
        vec![distributor()],
        r(1, 1_000_000),
        &operational(),
        "2027-01-01T00:00:00.000Z",
    );
    let chain = [top, mid];
    resolve(
        &emission(),
        &chain,
        &root_keys(),
        &at("2026-12-01T00:00:00.000Z"),
    )
    .expect("both links in force");
    assert!(
        resolve(
            &emission(),
            &chain,
            &root_keys(),
            &at("2027-06-01T00:00:00.000Z")
        )
        .is_err(),
        "the distributor's link had run out while the top one had not"
    );
}
