//! The birth of a container and its personal identifier (KS-8 C-3, E-4).
//!
//! The point these tests hold down: the identifier is **derived**, so it cannot
//! be asserted. A container that carries an identifier of its own choosing is
//! rejected — which is the whole difference between evidence and a claim.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use ksg_core_v2::canonical::doc_hash;
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{sign_doc, Ed25519Signer, KeySet, Profile, SignatureSet};
use ksg_core_v2::doc::{
    derive_container_id, AgentBinding, ContainerInit, Emission, Range, Serial, Timestamp, Uri,
};

fn uri(s: &str) -> Uri {
    Uri::parse(s).expect("uri")
}
/// The release's moment used across this file — part of the identifier since
/// CT-28 (2026-09-19). Matches `issued_at` of [`emission`].
fn issued() -> Timestamp {
    ts("2026-08-27T00:00:00.000Z")
}

fn ts(s: &str) -> Timestamp {
    Timestamp::parse(s).expect("timestamp")
}
fn agent() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:key:zAgent#k0"), [40u8; 32])
}
fn client() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:key:zClient#c1"), [43u8; 32])
}
fn owner() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:key:zOwner#o1"), [44u8; 32])
}
fn keys() -> KeySet {
    [client().public(), owner().public()].into_iter().collect()
}
fn block() -> Range {
    Range {
        from: Serial(4_700_000),
        to: Serial(4_700_999),
    }
}
fn artifact() -> Uri {
    uri("did:web:artifact.example")
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
        keys: vec![issuer().public()],
        signatures: SignatureSet::default(),
    };
    let sig = sign_doc(&doc, &issuer()).expect("signature");
    Emission {
        signatures: SignatureSet::new(vec![sig]),
        ..doc
    }
}

fn issuer() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:key:zIssuer#i1"), [45u8; 32])
}

fn binding() -> AgentBinding {
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
    let sig = sign_doc(&doc, &agent()).expect("signature");
    AgentBinding {
        signatures: SignatureSet::new(vec![sig]),
        ..doc
    }
}

/// An initiation, signed by both keys in one command.
fn init(serial: Serial, emission: &str, container: Option<Hash>) -> ContainerInit {
    init_at(serial, emission, container, 12_345)
}

fn init_at(
    serial: Serial,
    emission: &str,
    container: Option<Hash>,
    offset_ms: u64,
) -> ContainerInit {
    let derived = derive_container_id(
        emission,
        &issued(),
        serial,
        &client().public(),
        &artifact(),
        offset_ms,
    );
    let doc = ContainerInit {
        context: ksg_core_v2::doc::Context,
        doc_type: "ContainerInit".into(),
        v: 3,
        emission: emission.into(),
        serial,
        binding: doc_hash(&binding()).expect("binding hash"),
        agent: client().public(),
        artifact: artifact(),
        offset_ms,
        container: container.unwrap_or(derived),
        signatures: SignatureSet::default(),
    };
    let s1 = sign_doc(&doc, &client()).expect("client signature");
    let s2 = sign_doc(&doc, &owner()).expect("owner signature");
    ContainerInit {
        signatures: SignatureSet::new(vec![s1, s2]),
        ..doc
    }
}

fn good() -> ContainerInit {
    init(Serial(4_700_007), "ksg:em:000001", None)
}

#[test]
fn a_birth_with_a_derived_identifier_is_accepted() {
    good()
        .validate(&emission(), &binding(), 0, &keys(), &Profile::default())
        .expect("the initiation verifies");
}

#[test]
fn an_asserted_identifier_is_rejected() {
    // The identifier a verifier trusts is the one it recomputed. An initiation
    // carrying any other value is not a container with a different name — it is
    // not a container.
    let forged = init(
        Serial(4_700_007),
        "ksg:em:000001",
        Some(Hash::sha256(b"an identifier of my own choosing")),
    );
    let err = forged
        .validate(&emission(), &binding(), 0, &keys(), &Profile::default())
        .expect_err("an asserted identifier is rejected");
    assert!(format!("{err}").contains("derived"), "{err}");
}

#[test]
fn the_release_time_is_part_of_the_identifier() {
    // CT-28, `[decision]` 2026-09-19: what makes a container unique is the identifier
    // together with the release id, the serial in the release and **the
    // release's time**.
    //
    // Why the time has to be in there: the release id is a string we mint. If
    // it were ever minted twice — a restored backup, a renumbered series, a
    // second issuer under white-label — two different releases would derive the
    // same identifier for the same position, and two containers would answer to
    // one identity. The release's moment is the one part of a release that
    // cannot repeat.
    let same_everything_but_time = |issued: &str| {
        derive_container_id(
            "ksg:em:000001",
            &ts(issued),
            Serial(4_700_007),
            &client().public(),
            &artifact(),
            12_345,
        )
    };
    assert_ne!(
        same_everything_but_time("2026-08-27T00:00:00.000Z"),
        same_everything_but_time("2026-08-27T00:00:01.000Z"),
        "two releases sharing an id and a position must still differ by their moment"
    );
}

#[test]
fn the_identifier_changes_with_the_act() {
    // Identity is a function of the act, not of the address: two initiations
    // differing in any part of the act get different identifiers.
    let base = derive_container_id(
        "ksg:em:000001",
        &issued(),
        Serial(4_700_007),
        &client().public(),
        &artifact(),
        12_345,
    );
    let other_serial = derive_container_id(
        "ksg:em:000001",
        &issued(),
        Serial(4_700_008),
        &client().public(),
        &artifact(),
        12_345,
    );
    let other_key = derive_container_id(
        "ksg:em:000001",
        &issued(),
        Serial(4_700_007),
        &owner().public(),
        &artifact(),
        12_345,
    );
    let other_offset = derive_container_id(
        "ksg:em:000001",
        &issued(),
        Serial(4_700_007),
        &client().public(),
        &artifact(),
        12_346,
    );
    let other_artifact = derive_container_id(
        "ksg:em:000001",
        &issued(),
        Serial(4_700_007),
        &client().public(),
        &uri("did:web:other.example"),
        12_345,
    );
    for (what, id) in [
        ("serial", other_serial),
        ("key", other_key),
        ("offset", other_offset),
        ("artifact", other_artifact),
    ] {
        assert_ne!(base, id, "the identifier did not change with the {what}");
    }
}

#[test]
fn one_signature_is_not_enough() {
    // Two signatures arrive in ONE command and are checked together. A
    // sequential pair leaves a window in which the first waits for the second.
    let doc = good();
    let single = ContainerInit {
        context: ksg_core_v2::doc::Context,
        signatures: SignatureSet::new(vec![doc.signatures.as_slice()[0].clone()]),
        ..doc
    };
    let err = single
        .validate(&emission(), &binding(), 0, &keys(), &Profile::default())
        .expect_err("one signature is rejected");
    assert!(format!("{err}").contains("two signatures"), "{err}");
}

#[test]
fn a_serial_outside_the_block_is_rejected() {
    let outside = init(Serial(9_000_000), "ksg:em:000001", None);
    let err = outside
        .validate(&emission(), &binding(), 0, &keys(), &Profile::default())
        .expect_err("a serial outside the block is rejected");
    assert!(format!("{err}").contains("9000000"), "{err}");
}

#[test]
fn a_foreign_emission_is_rejected() {
    let foreign = init(Serial(4_700_007), "ksg:em:000002", None);
    let err = foreign
        .validate(&emission(), &binding(), 0, &keys(), &Profile::default())
        .expect_err("a foreign emission is rejected");
    assert!(format!("{err}").contains("different emission"), "{err}");
}

#[test]
fn initiation_past_the_packet_lifetime_is_rejected() {
    // Invariant 3 of KS-2, in the form the owner decided on: the offset is
    // compared with the packet's declared lifetime, not with a wall clock.
    // Ninety days is 7 776 000 000 ms; one millisecond past it is too late.
    let late = init_at(Serial(4_700_007), "ksg:em:000001", None, 7_776_000_001);
    let err = late
        .validate(&emission(), &binding(), 0, &keys(), &Profile::default())
        .expect_err("activation after the lifetime is rejected");
    assert!(format!("{err}").contains("activation after"), "{err}");

    // The last millisecond of the lifetime is still in time.
    let just_in_time = init_at(Serial(4_700_007), "ksg:em:000001", None, 7_776_000_000);
    just_in_time
        .validate(&emission(), &binding(), 0, &keys(), &Profile::default())
        .expect("the last millisecond still counts");
}

#[test]
fn the_same_party_signing_twice_is_not_two_parties() {
    // The dual-key rule exists to stop one party acting alone. A rule counting
    // signatures rather than signers is satisfied by that very party signing
    // twice — which is why the check counts distinct signers.
    let doc = good();
    let first = doc.signatures.as_slice()[0].clone();
    let doubled = ContainerInit {
        context: ksg_core_v2::doc::Context,
        signatures: SignatureSet::new(vec![first.clone(), first]),
        ..doc
    };
    let err = doubled
        .validate(&emission(), &binding(), 0, &keys(), &Profile::default())
        .expect_err("one party signing twice is rejected");
    assert!(format!("{err}").contains("two different parties"), "{err}");
}

#[test]
fn an_initiation_not_signed_by_its_own_agent_is_rejected() {
    // Two distinct signers are not enough on their own: without this check the
    // pair could be any two keys the holder controls, and the initiation would
    // say nothing about the agent it names.
    let doc = good();
    let s1 = sign_doc(&doc, &owner()).expect("owner signature");
    let s2 = sign_doc(&doc, &issuer()).expect("issuer signature");
    let strangers = ContainerInit {
        context: ksg_core_v2::doc::Context,
        signatures: SignatureSet::new(vec![s1, s2]),
        ..doc
    };
    let mut ks = keys();
    ks.insert(issuer().public());
    let err = strangers
        .validate(&emission(), &binding(), 0, &ks, &Profile::default())
        .expect_err("an initiation without its agent's signature is rejected");
    assert!(format!("{err}").contains("agent it names"), "{err}");
}

// ---------------------------------------------------------------------------
// The lifetime allows for the channel — `[decision]` 19.09, CT-24.
// ---------------------------------------------------------------------------

#[test]
fn each_step_down_the_channel_adds_a_tenth_to_the_lifetime() {
    // The rule: unused serials burn — not in time, gone. The single exception
    // is the lifetime itself: a distributor gets +10%, each further agent
    // another +10%. The reason is the channel rather than generosity — a
    // packet that passed through three hands spent part of its life
    // travelling, and a lifetime counted from the packet's own origin would
    // charge the last agent for the journey.
    let em = emission();
    let day = 86_400_000u64;
    let base = u64::from(em.block_ttl_days) * day;

    assert_eq!(em.lifetime_ms(0), base, "sold direct: no allowance");
    assert_eq!(em.lifetime_ms(1), base * 11 / 10, "distributor: +10%");
    assert_eq!(
        em.lifetime_ms(2),
        base * 12 / 10,
        "and the agent below: +20%"
    );
    assert_eq!(
        em.lifetime_ms(4),
        base * 14 / 10,
        "at the channel's limit: +40%"
    );
}

#[test]
fn the_allowance_is_what_decides_a_late_initiation() {
    // Not arithmetic for its own sake: the same initiation is refused when the
    // packet was sold direct and accepted when it came through a distributor.
    let em = emission();
    let day = 86_400_000u64;
    let base = u64::from(em.block_ttl_days) * day;
    let just_past_base = base + 1;

    let doc = init_at(Serial(4_700_007), "ksg:em:000001", None, just_past_base);
    let err = doc
        .validate(&em, &binding(), 0, &keys(), &Profile::default())
        .expect_err("past the plain lifetime, sold direct");
    assert!(format!("{err}").contains("activation after"), "{err}");

    doc.validate(&em, &binding(), 1, &keys(), &Profile::default())
        .expect("and inside the distributor's allowance");
}

// ---------------------------------------------------------------------------
// The brick ceiling — `[decision]` 23.09: a container without a journal work lives two
// years at most, whatever the release declared and however deep the channel.
// ---------------------------------------------------------------------------

fn emission_with_ttl(days: u32) -> Emission {
    let doc = Emission {
        block_ttl_days: days,
        signatures: SignatureSet::default(),
        ..emission()
    };
    let sig = sign_doc(&doc, &issuer()).expect("signature");
    Emission {
        signatures: SignatureSet::new(vec![sig]),
        ..doc
    }
}

#[test]
fn no_release_can_declare_a_life_past_two_years() {
    use ksg_core_v2::doc::MAX_UNUSED_LIFETIME_MS;
    let day = 86_400_000u64;
    assert_eq!(MAX_UNUSED_LIFETIME_MS, 730 * day);
    for days in [731, 1_095, 36_500, u32::MAX] {
        let em = emission_with_ttl(days);
        for depth in 0..=4 {
            assert_eq!(
                em.lifetime_ms(depth),
                MAX_UNUSED_LIFETIME_MS,
                "{days} days at depth {depth}"
            );
        }
    }
}

#[test]
fn the_deepest_channel_keeps_its_full_allowance_up_to_521_days() {
    use ksg_core_v2::doc::MAX_UNUSED_LIFETIME_MS;
    let day = 86_400_000u64;
    let fits = emission_with_ttl(521);
    assert_eq!(fits.lifetime_ms(4), 521 * day * 14 / 10);
    assert!(fits.lifetime_ms(4) <= MAX_UNUSED_LIFETIME_MS);
    let over = emission_with_ttl(522);
    assert_eq!(
        over.lifetime_ms(4),
        MAX_UNUSED_LIFETIME_MS,
        "cut at the ceiling"
    );
}

#[test]
fn initiation_past_two_years_is_refused_even_on_a_release_that_promised_more() {
    let day = 86_400_000u64;
    let em = emission_with_ttl(3_650);
    let late = init_at(Serial(4_700_007), "ksg:em:000001", None, 730 * day + 1);
    let err = late
        .validate(&em, &binding(), 4, &keys(), &Profile::default())
        .expect_err("a brick by now");
    assert!(format!("{err}").contains("activation after"), "{err}");

    let in_time = init_at(Serial(4_700_007), "ksg:em:000001", None, 730 * day);
    in_time
        .validate(&em, &binding(), 4, &keys(), &Profile::default())
        .expect("the last day still counts");
}
