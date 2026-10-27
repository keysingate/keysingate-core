//! The custody documents are documents of core v2: major version 3, the
//! `@context` of v3, no field the signer did not sign (spec v2 §3.3; executor decisions I-16, I-18).

use ksg_core_v2::canonical::doc_hash;
use ksg_core_v2::crypto::sign::{sign_doc, Ed25519Signer, KeySet, Profile, SignatureSet};
use ksg_core_v2::doc::{Context, Timestamp, Uri};
use ksg_custody_v2::{CustodyError, Succession, SuccessionVeto, NOTICE_RECOMMENDED_MS};

fn uri(s: &str) -> Uri {
    Uri::parse(s).expect("uri")
}
fn current() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:web:issuer.example#root1"), [90u8; 32])
}
fn successor() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:web:issuer.example#root2"), [95u8; 32])
}
fn keys() -> KeySet {
    [current().public()].into_iter().collect()
}

fn certificate(v: u32) -> Succession {
    let doc = Succession {
        context: Context,
        doc_type: "Succession".into(),
        v,
        issuer: uri("did:web:issuer.example"),
        current: current().public(),
        successor: successor().public(),
        notice_ms: NOTICE_RECOMMENDED_MS,
        declared_at: Timestamp::parse("2026-10-01T00:00:00.000Z").expect("ts"),
        signatures: SignatureSet::default(),
    };
    let sig = sign_doc(&doc, &current()).expect("signature");
    Succession {
        signatures: SignatureSet::new(vec![sig]),
        ..doc
    }
}

#[test]
fn a_certificate_of_version_3_verifies_and_carries_the_v3_context() {
    let c = certificate(3);
    c.validate(&keys(), &Profile::default()).expect("verifies");
    let json = serde_json::to_value(&c).expect("json");
    assert_eq!(json["@context"], "urn:keysingate:core:v3");
}

#[test]
fn a_certificate_of_an_older_version_is_not_ours() {
    // Signed correctly, but by the rules of core v1: core v2 does not read it.
    let got = certificate(2).validate(&keys(), &Profile::default());
    assert!(matches!(got, Err(CustodyError::Succession(_))), "{got:?}");
}

#[test]
fn a_document_without_the_context_or_with_an_extra_field_does_not_parse() {
    let mut json = serde_json::to_value(certificate(3)).expect("json");
    let mut extra = json.clone();
    extra["note"] = "unsigned".into();
    assert!(serde_json::from_value::<Succession>(extra).is_err());

    json.as_object_mut().expect("object").remove("@context");
    assert!(serde_json::from_value::<Succession>(json).is_err());

    let mut v1 = serde_json::to_value(certificate(3)).expect("json");
    v1["@context"] = "urn:keysingate:core:v2".into();
    assert!(serde_json::from_value::<Succession>(v1).is_err());
}

#[test]
fn a_veto_round_trips_through_json_unchanged() {
    let c = certificate(3);
    let doc = SuccessionVeto {
        context: Context,
        doc_type: "SuccessionVeto".into(),
        v: 3,
        succession: doc_hash(&c).expect("hash"),
        vetoed_at: Timestamp::parse("2026-10-02T00:00:00.000Z").expect("ts"),
        signatures: SignatureSet::default(),
    };
    let back: SuccessionVeto =
        serde_json::from_slice(&serde_json::to_vec(&doc).expect("bytes")).expect("parses");
    assert_eq!(back, doc);
}
