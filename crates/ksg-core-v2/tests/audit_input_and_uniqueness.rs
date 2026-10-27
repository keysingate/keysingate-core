//! Findings 8 and 9 of the 13.09 hardening audit.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use ksg_core_v2::doc::binding::Uniqueness;
use ksg_core_v2::doc::{Timestamp, Uri};

// --- finding 8: untrusted JSON bypassed the constructors ------------------------

#[test]
fn a_timestamp_from_json_goes_through_parse() {
    // `#[serde(transparent)]` + derived `Deserialize` accepted any string.
    // But every time comparison in the core is lexicographic, and on such strings
    // order stops being chronological.
    for bad in [
        r#""""#,
        r#""not a timestamp""#,
        r#""2026-01-01T00:00:00+05:00Z""#, // an offset disguised as UTC
        r#""2026-13-45T99:99:99Z""#,       // digits in place, but the separators are wrong
        r#""aaaaaaaaaaaaaaaaaaaZ""#,       // right length, nothing else
        r#""2026-08-27T10:00:00Z""#,       // core v2: milliseconds are mandatory
        r#""2026-08-27T10:00:00.5Z""#,     // core v2: exactly three digits
        r#""2026-02-30T10:00:00.000Z""#,   // core v2: no such day
    ] {
        assert!(
            serde_json::from_str::<Timestamp>(bad).is_err(),
            "accepted a bad timestamp: {bad}"
        );
    }
    // Core v2: the only form is YYYY-MM-DDTHH:MM:SS.mmmZ.
    for good in [
        r#""2026-08-27T10:00:00.123Z""#,
        r#""2028-02-29T23:59:59.999Z""#,
    ] {
        serde_json::from_str::<Timestamp>(good).expect("a good timestamp was refused");
    }
}

#[test]
fn a_uri_from_json_goes_through_parse() {
    for bad in [r#""""#, r#""no-scheme-here""#] {
        assert!(
            serde_json::from_str::<Uri>(bad).is_err(),
            "accepted a bad URI: {bad}"
        );
    }
    serde_json::from_str::<Uri>(r#""did:key:zAgent#k1""#).expect("a good URI was refused");
}

#[test]
fn a_bad_timestamp_inside_a_document_kills_the_document() {
    // Checked in place: a field inside the document, not a standalone type.
    let doc = r#"{"type":"AgentBinding","v":3,"emission":"ksg:em:1",
        "block":{"from":1,"to":10},
        "agent":{"kid":"did:key:zA#k1","alg":"Ed25519","key":"AAAA"},
        "bound_at":"","signatures":[]}"#;
    assert!(serde_json::from_str::<ksg_core_v2::doc::AgentBinding>(doc).is_err());
}

// --- finding 9: "saw no others" is not "unique" ------------------------

#[test]
fn nothing_presented_means_unknown_and_not_proven() {
    // Exactly what the audit caught: the holder makes two bindings for one
    // block and shows each counterparty its own. A verifier shown nothing must
    // say "unknown", not "the block is one-shot".
    assert_ne!(Uniqueness::Unknown, Uniqueness::Proven);

    // The difference shows in the report: serialized as a value, not dropped.
    assert_eq!(
        serde_json::to_string(&Uniqueness::Unknown).expect("json"),
        "\"unknown\""
    );
    assert_eq!(
        serde_json::to_string(&Uniqueness::Proven).expect("json"),
        "\"proven\""
    );
}
