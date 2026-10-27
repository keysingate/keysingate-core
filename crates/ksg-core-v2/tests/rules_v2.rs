//! The rules core v2 adds for stability (spec v2 §3, §5, §7.2, §14).
//!
//! Each one closes a way the same input could be read two ways, or a way a
//! verifier could be made to take on unbounded work.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use core::num::NonZeroUsize;

use ksg_core_v2::anchor::{upper_bound, Attestation, AttestationVerifier};
use ksg_core_v2::canonical::canonicalize;
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::Profile;
use ksg_core_v2::doc::{Context, Timestamp, Uri, CONTEXT};
use ksg_core_v2::error::Invalid;
use ksg_core_v2::limits::{self, MAX_ANCHORS, MAX_DOC_BYTES, MAX_SAFE_INTEGER};

fn uri(s: &str) -> Uri {
    Uri::parse(s).expect("uri")
}
fn ts(s: &str) -> Timestamp {
    Timestamp::parse(s).expect("ts")
}

// --- §3: one form of time -------------------------------------------------------

#[test]
fn only_the_millisecond_form_of_time_parses() {
    for bad in [
        "2026-09-30T10:00:00Z",
        "2026-09-30T10:00:00.5Z",
        "2026-09-30T10:00:00.0000Z",
        "2026-09-30T10:00:00.000+00:00",
        "2026-09-31T10:00:00.000Z",
        "2027-02-29T10:00:00.000Z",
        "2026-09-30T24:00:00.000Z",
        "2026-09-30T10:60:00.000Z",
        "2026-09-30t10:00:00.000z",
    ] {
        assert!(Timestamp::parse(bad).is_err(), "accepted {bad}");
    }
    for good in [
        "2026-09-30T10:00:00.000Z",
        "2028-02-29T23:59:59.999Z",
        "1970-01-01T00:00:00.000Z",
    ] {
        assert!(Timestamp::parse(good).is_ok(), "refused {good}");
    }
}

#[test]
fn the_order_of_time_is_the_order_of_milliseconds() {
    let a = ts("2026-09-30T10:00:00.000Z");
    let b = ts("2026-09-30T10:00:00.500Z");
    let c = ts("2026-10-01T00:00:00.000Z");
    assert!(a < b && b < c);
    assert_eq!(b.unix_ms() - a.unix_ms(), 500);
}

#[test]
fn unix_milliseconds_round_trip() {
    for s in [
        "1970-01-01T00:00:00.000Z",
        "2000-02-29T12:34:56.789Z",
        "2026-09-30T10:00:00.123Z",
        "2100-12-31T23:59:59.999Z",
    ] {
        let t = ts(s);
        let back = Timestamp::from_unix_ms(t.unix_ms()).expect("in range");
        assert_eq!(back.as_str(), s);
    }
}

// --- §3: integers only, within 2^53 - 1 -----------------------------------------

#[test]
fn canonical_form_refuses_numbers_other_languages_would_write_differently() {
    let ok = serde_json::json!({ "n": MAX_SAFE_INTEGER, "m": 0 });
    assert!(canonicalize(&ok).is_ok());
    for bad in [
        serde_json::json!({ "n": MAX_SAFE_INTEGER + 1 }),
        serde_json::json!({ "n": 1.5 }),
        serde_json::json!({ "n": -1 }),
        serde_json::json!({ "deep": [ { "n": 0.1 } ] }),
    ] {
        assert_eq!(canonicalize(&bad).unwrap_err(), Invalid::Number, "{bad}");
    }
}

// --- §5: the context names the major version ------------------------------------

#[test]
fn the_context_is_one_value_and_nothing_else_parses() {
    assert_eq!(CONTEXT, "urn:keysingate:core:v3");
    assert_eq!(
        serde_json::to_value(Context).expect("json"),
        serde_json::json!(CONTEXT)
    );
    assert!(serde_json::from_value::<Context>(serde_json::json!(CONTEXT)).is_ok());
    for other in ["urn:keysingate:core:v1", "urn:keysingate:core:v2", ""] {
        assert!(serde_json::from_value::<Context>(serde_json::json!(other)).is_err());
    }
}

#[test]
fn only_version_three_is_verified_here() {
    use ksg_core_v2::version::check;
    assert!(check(3).is_ok());
    assert!(check(2).is_err(), "v2 documents are core v1's");
    assert!(check(4).is_err());
    assert!(check(0).is_err());
}

// --- §14: limits ---------------------------------------------------------------

#[test]
fn a_document_past_the_size_limit_is_not_parsed() {
    let big = vec![b' '; MAX_DOC_BYTES + 1];
    assert!(matches!(
        limits::parse_doc::<serde_json::Value>(&big).unwrap_err(),
        Invalid::Limit(_)
    ));
}

#[test]
fn an_unknown_field_is_refused() {
    let a = serde_json::json!({
        "type": "urn:ksg:anchor:test",
        "subject": Hash::sha256(b"x"),
        "proof": [],
        "anchored_at": "2026-09-30T10:00:00.000Z",
        "extra": 1,
    });
    let bytes = serde_json::to_vec(&a).expect("bytes");
    assert!(limits::parse_doc::<Attestation>(&bytes).is_err());
}

// --- §7.2: the one rule of the upper time bound ---------------------------------

#[derive(Debug)]
struct Reader;

impl AttestationVerifier for Reader {
    fn verify(&self, a: &Attestation) -> Result<Timestamp, Invalid> {
        if a.proof == b"forged" {
            Err(Invalid::Schema("the network does not confirm"))
        } else {
            Ok(a.anchored_at.clone())
        }
    }
    fn handles(&self, kind: &Uri) -> bool {
        kind.as_str() == "urn:ksg:anchor:test"
    }
}

fn anchor(subject: &Hash, kind: &str, at: &str, proof: &[u8]) -> Attestation {
    Attestation {
        kind: uri(kind),
        subject: *subject,
        proof: proof.to_vec(),
        anchored_at: ts(at),
    }
}

#[test]
fn the_bound_is_the_earliest_anchor_read() {
    let s = Hash::sha256(b"subject");
    let anchors = [
        anchor(&s, "urn:ksg:anchor:test", "2026-09-30T12:00:00.000Z", b"p"),
        anchor(&s, "urn:ksg:anchor:test", "2026-09-30T10:00:00.000Z", b"p"),
        // Earliest of all, but of a kind nobody reads: it proves nothing.
        anchor(&s, "urn:ksg:anchor:other", "2026-09-30T08:00:00.000Z", b"p"),
    ];
    let t = upper_bound(&anchors, &s, &Profile::default(), Some(&Reader)).expect("reads");
    assert_eq!(
        t.as_ref().map(Timestamp::as_str),
        Some("2026-09-30T10:00:00.000Z")
    );
}

#[test]
fn no_reader_means_no_time_and_not_an_error() {
    let s = Hash::sha256(b"subject");
    let anchors = [anchor(
        &s,
        "urn:ksg:anchor:test",
        "2026-09-30T10:00:00.000Z",
        b"p",
    )];
    assert_eq!(
        upper_bound(&anchors, &s, &Profile::default(), None),
        Ok(None)
    );
}

#[test]
fn a_forged_anchor_refuses_and_a_foreign_subject_refuses() {
    let s = Hash::sha256(b"subject");
    let forged = [anchor(
        &s,
        "urn:ksg:anchor:test",
        "2026-09-30T10:00:00.000Z",
        b"forged",
    )];
    assert!(upper_bound(&forged, &s, &Profile::default(), Some(&Reader)).is_err());
    let foreign = [anchor(
        &Hash::sha256(b"other"),
        "urn:ksg:anchor:test",
        "2026-09-30T10:00:00.000Z",
        b"p",
    )];
    assert!(upper_bound(&foreign, &s, &Profile::default(), Some(&Reader)).is_err());
}

#[test]
fn fewer_anchors_read_than_the_profile_asks_give_no_bound() {
    let s = Hash::sha256(b"subject");
    let anchors = [anchor(
        &s,
        "urn:ksg:anchor:test",
        "2026-09-30T10:00:00.000Z",
        b"p",
    )];
    let profile = Profile {
        min_anchors: NonZeroUsize::new(2).expect("two"),
        ..Profile::default()
    };
    assert_eq!(upper_bound(&anchors, &s, &profile, Some(&Reader)), Ok(None));
}

#[test]
fn more_anchors_than_the_limit_are_refused_before_any_is_read() {
    let s = Hash::sha256(b"subject");
    let a = anchor(&s, "urn:ksg:anchor:test", "2026-09-30T10:00:00.000Z", b"p");
    let many = vec![a; MAX_ANCHORS + 1];
    assert!(matches!(
        upper_bound(&many, &s, &Profile::default(), Some(&Reader)).unwrap_err(),
        Invalid::Limit(_)
    ));
}

#[test]
fn a_document_part_with_an_unknown_field_is_refused() {
    use ksg_core_v2::doc::Range;
    assert!(serde_json::from_str::<Range>(r#"{"from":1,"to":2}"#).is_ok());
    assert!(serde_json::from_str::<Range>(r#"{"from":1,"to":2,"x":0}"#).is_err());
}

/// Audit of 30.09, O-5: one constructor per rule of the seals, and it only
/// adds — whatever the caller required stays required.
#[test]
fn the_seal_profiles_add_and_never_take_away() {
    use ksg_core_v2::crypto::sign::{Alg, Profile};
    let mut p = Profile::default();
    p.required_algs.clear();
    p.required_algs.insert(Alg::MlDsa65);
    let plain = p.with_ed25519();
    assert!(plain.required_algs.contains(&Alg::Ed25519));
    assert!(
        plain.required_algs.contains(&Alg::MlDsa65),
        "the caller's stays"
    );
    let both = Profile::default().with_ed25519_and_ml_dsa();
    assert!(both.required_algs.contains(&Alg::Ed25519));
    assert!(both.required_algs.contains(&Alg::MlDsa65));
    assert_eq!(both.min_anchors, Profile::default().min_anchors);
}
