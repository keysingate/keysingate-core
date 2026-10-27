//! Conformance of documents to the published JSON Schemas.
//!
//! A schema is a normative artifact on a par with the specification text, and it
//! is what a third-party implementation parses a document by before it has any
//! of our code. A schema that nothing exercises drifts from the implementation
//! silently: the person who notices a drifted schema is not the author but
//! whoever wrote a parser against it.
//!
//! So here the documents are **built by the reference implementation** and
//! validated against the schemas. A divergence is a defect, no matter which side
//! it is on.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::PathBuf;

use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{sign_doc, Ed25519Signer, SignatureSet};
use ksg_core_v2::doc::{
    AgentBinding, BlockAllocation, BlockClosure, Class, Emission, Range, Serial, Timestamp, Uri,
};
use serde_json::Value;

fn schemas_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("schemas")
}

fn load_schema(name: &str) -> Value {
    let raw = std::fs::read_to_string(schemas_dir().join(name))
        .unwrap_or_else(|e| panic!("schema {name} is unreadable: {e}"));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("schema {name} is not JSON: {e}"))
}

/// Resolves references between schemas **from the `schemas/` directory**, not
/// from the network.
///
/// The references are relative (`common.json#/$defs/...`) and resolve against
/// the referring schema's `$id`, that is, within `https://schema.keysingate.com/core/v2/…`.
/// Fetching them over HTTP at validation time is not allowed: a schema that
/// needs the network is unverifiable where there is no network, and it is
/// validated precisely at integration time.
struct LocalSchemas;

impl jsonschema::Retrieve for LocalSchemas {
    fn retrieve(
        &self,
        uri: &jsonschema::Uri<String>,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        let name = uri
            .path()
            .as_str()
            .rsplit('/')
            .next()
            .ok_or("empty reference path")?;
        let raw = std::fs::read_to_string(schemas_dir().join(name))?;
        Ok(serde_json::from_str(&raw)?)
    }
}

fn validator_for(name: &str) -> jsonschema::Validator {
    jsonschema::options()
        .with_retriever(LocalSchemas)
        .build(&load_schema(name))
        .unwrap_or_else(|e| panic!("schema {name} does not compile: {e}"))
}

fn assert_valid(schema: &str, doc: &Value, what: &str) {
    let v = validator_for(schema);
    let errors: Vec<String> = v
        .iter_errors(doc)
        .map(|e| format!("{}: {e}", e.instance_path()))
        .collect();
    assert!(
        errors.is_empty(),
        "{what} does not pass {schema}:\n  {}",
        errors.join("\n  ")
    );
}

fn assert_invalid(schema: &str, doc: &Value, what: &str) {
    let v = validator_for(schema);
    assert!(
        !v.is_valid(doc),
        "{what}: schema {schema} accepted a document it must reject"
    );
}

// --- fixtures built by the reference implementation ---------------------------

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
fn block() -> Range {
    Range {
        from: Serial(4_700_000),
        to: Serial(4_700_999),
    }
}
fn seal<T: ksg_core_v2::canonical::Signable, F: Fn(&mut T, SignatureSet)>(
    mut doc: T,
    s: &Ed25519Signer,
    put: F,
) -> T {
    let sig = sign_doc(&doc, s).unwrap();
    put(&mut doc, SignatureSet::new(vec![sig]));
    doc
}
fn json_of<T: serde::Serialize>(v: &T) -> Value {
    serde_json::to_value(v).expect("serialization")
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
    seal(doc, &issuer(), |d, s| d.signatures = s)
}

fn allocation(prev: Option<Hash>) -> BlockAllocation {
    let doc = BlockAllocation {
        context: ksg_core_v2::doc::Context,
        doc_type: "BlockAllocation".into(),
        v: 3,
        emission: "ksg:em:000001".into(),
        block: block(),
        class: Class::Heavy,
        holder: uri("did:web:holder.example"),
        allocated_at: ts("2026-08-27T10:00:00.000Z"),
        expires_at: ts("2026-11-25T10:00:00.000Z"),
        prev_closure: prev,
        signatures: SignatureSet::default(),
    };
    seal(doc, &issuer(), |d, s| d.signatures = s)
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
    seal(doc, &agent(), |d, s| d.signatures = s)
}

fn closure() -> BlockClosure {
    let doc = BlockClosure {
        context: ksg_core_v2::doc::Context,
        doc_type: "BlockClosure".into(),
        v: 3,
        emission: "ksg:em:000001".into(),
        block: block(),
        used_submitted: vec![Range {
            from: Serial(4_700_000),
            to: Serial(4_700_399),
        }],
        used_not_submitted: vec![],
        cancelled: vec![Range {
            from: Serial(4_700_400),
            to: Serial(4_700_999),
        }],
        closed_at: ts("2026-08-28T00:00:00.000Z"),
        signatures: SignatureSet::default(),
    };
    seal(doc, &agent(), |d, s| d.signatures = s)
}

/// A key inclusion: K1 laid on top of the binding key (KS-1).
fn key_inclusion() -> ksg_core_v2::doc::KeyInclusion {
    let predecessor = ksg_core_v2::canonical::doc_hash(&binding()).unwrap();
    let added = Ed25519Signer::from_seed(uri("did:key:zAgent#k1"), [41u8; 32]);
    let doc = ksg_core_v2::doc::KeyInclusion {
        context: ksg_core_v2::doc::Context,
        doc_type: "KeyInclusion".into(),
        v: 3,
        emission: "ksg:em:000001".into(),
        block: block(),
        predecessor,
        key: added.public(),
        offset_ms: 12_345,
        signatures: SignatureSet::default(),
    };
    seal(doc, &agent(), |d, s| d.signatures = s)
}

fn container_init() -> ksg_core_v2::doc::ContainerInit {
    let binding_hash = ksg_core_v2::canonical::doc_hash(&binding()).unwrap();
    let client = Ed25519Signer::from_seed(uri("did:key:zClient#c1"), [43u8; 32]);
    let owner = Ed25519Signer::from_seed(uri("did:key:zOwner#o1"), [44u8; 32]);
    let artifact = uri("did:web:artifact.example");
    let serial = ksg_core_v2::doc::Serial(4_700_007);
    let container = ksg_core_v2::doc::derive_container_id(
        "ksg:em:000001",
        &ts("2026-08-27T00:00:00.000Z"),
        serial,
        &client.public(),
        &artifact,
        12_345,
    );
    let doc = ksg_core_v2::doc::ContainerInit {
        context: ksg_core_v2::doc::Context,
        doc_type: "ContainerInit".into(),
        v: 3,
        emission: "ksg:em:000001".into(),
        serial,
        binding: binding_hash,
        agent: client.public(),
        artifact,
        offset_ms: 12_345,
        container,
        signatures: SignatureSet::default(),
    };
    // Two signatures in one command: the client agent's and the owner's.
    let s1 = sign_doc(&doc, &client).unwrap();
    let s2 = sign_doc(&doc, &owner).unwrap();
    ksg_core_v2::doc::ContainerInit {
        signatures: SignatureSet::new(vec![s1, s2]),
        ..doc
    }
}

// --- the checks ---------------------------------------------------------------

#[test]
fn every_schema_compiles() {
    for s in [
        "emission.json",
        "allocation.json",
        "binding.json",
        "closure.json",
        "key-inclusion.json",
        "container-init.json",
        "delegation.json",
        "class-promotion.json",
        "status-record.json",
    ] {
        let _ = validator_for(s);
    }
}

#[test]
fn documents_produced_by_the_implementation_validate() {
    assert_valid("emission.json", &json_of(&emission()), "Emission");
    assert_valid(
        "allocation.json",
        &json_of(&allocation(None)),
        "the first block",
    );
    assert_valid(
        "allocation.json",
        &json_of(&allocation(Some(Hash::sha256(b"prev")))),
        "the second block",
    );
    assert_valid("binding.json", &json_of(&binding()), "AgentBinding");
    assert_valid("closure.json", &json_of(&closure()), "BlockClosure");
    assert_valid(
        "key-inclusion.json",
        &json_of(&key_inclusion()),
        "KeyInclusion",
    );
    assert_valid(
        "container-init.json",
        &json_of(&container_init()),
        "ContainerInit",
    );
    // Both shapes of a delegation: the root grant, which carries no parent,
    // and a sub-grant, which must. The schema has to accept each and only each.
    let (root_grant, sub_grant) = delegations();
    assert_valid(
        "delegation.json",
        &json_of(&root_grant),
        "a root Delegation",
    );
    assert_valid("delegation.json", &json_of(&sub_grant), "a sub-Delegation");
}

/// A root grant and a sub-grant under it.
fn delegations() -> (ksg_core_v2::doc::Delegation, ksg_core_v2::doc::Delegation) {
    let root = Ed25519Signer::from_seed(uri("did:web:issuer.example#root"), [90u8; 32]);
    let ops = Ed25519Signer::from_seed(uri("did:web:issuer.example#ops1"), [91u8; 32]);
    let dist = Ed25519Signer::from_seed(uri("did:web:dist.example#d1"), [92u8; 32]);

    let doc = ksg_core_v2::doc::Delegation {
        context: ksg_core_v2::doc::Context,
        doc_type: "Delegation".into(),
        v: 3,
        emission: "ksg:em:000001".into(),
        range: ksg_core_v2::doc::Range {
            from: ksg_core_v2::doc::Serial(1),
            to: ksg_core_v2::doc::Serial(100_000_000),
        },
        delegate: uri("did:web:issuer.example"),
        keys: vec![ops.public()],
        parent: None,
        depth: 0,
        delegated_at: ts("2026-08-27T01:00:00.000Z"),
        term_ms: ksg_core_v2::doc::GRANT_MS,
        expires_at: ts("2027-08-27T00:00:00.000Z"),
        signatures: SignatureSet::default(),
    };
    let sig = sign_doc(&doc, &root).expect("signature");
    let first = ksg_core_v2::doc::Delegation {
        context: ksg_core_v2::doc::Context,
        signatures: SignatureSet::new(vec![sig]),
        ..doc
    };

    let doc = ksg_core_v2::doc::Delegation {
        context: ksg_core_v2::doc::Context,
        doc_type: "Delegation".into(),
        v: 3,
        emission: "ksg:em:000001".into(),
        range: ksg_core_v2::doc::Range {
            from: ksg_core_v2::doc::Serial(1000),
            to: ksg_core_v2::doc::Serial(1999),
        },
        delegate: uri("did:web:dist.example"),
        keys: vec![dist.public()],
        parent: Some(ksg_core_v2::canonical::doc_hash(&first).expect("hash")),
        depth: 1,
        delegated_at: ts("2026-08-27T02:00:00.000Z"),
        term_ms: ksg_core_v2::doc::GRANT_MS,
        expires_at: ts("2027-01-01T00:00:00.000Z"),
        signatures: SignatureSet::default(),
    };
    let sig = sign_doc(&doc, &ops).expect("signature");
    let second = ksg_core_v2::doc::Delegation {
        context: ksg_core_v2::doc::Context,
        signatures: SignatureSet::new(vec![sig]),
        ..doc
    };
    (first, second)
}

#[test]
fn absent_optional_field_is_omitted_not_null() {
    // §3: an absent field and null are different documents. The schema forbids
    // additionalProperties, but it would let a null in a declared field through,
    // so what is checked is the absence of the key itself.
    let first = json_of(&allocation(None));
    assert!(
        first.get("prev_closure").is_none(),
        "on the first block prev_closure must be absent, not null"
    );
    let mut with_null = first.clone();
    with_null["prev_closure"] = Value::Null;
    assert_invalid("allocation.json", &with_null, "prev_closure: null");
}

#[test]
fn schemas_reject_what_the_specification_forbids() {
    // A version below the issued ones (§14).
    let mut v0 = json_of(&binding());
    v0["v"] = serde_json::json!(0);
    assert_invalid("binding.json", &v0, "v: 0");

    // An algorithm outside the enumeration (§4.1) — a refusal, not a pass.
    let mut bad_alg = json_of(&binding());
    bad_alg["signatures"][0]["alg"] = serde_json::json!("RSA-2048");
    assert_invalid("binding.json", &bad_alg, "unknown alg");

    // Signatures as a concatenated string instead of an array (§4.1).
    let mut glued = json_of(&binding());
    glued["signatures"] = serde_json::json!("ed25519:AAAA");
    assert_invalid("binding.json", &glued, "signatures as a string");

    // A hash not in multihash form with the 1220 prefix (§4).
    let mut raw_hash = json_of(&container_init());
    raw_hash["binding"] = serde_json::json!("aabbcc");
    assert_invalid(
        "container-init.json",
        &raw_hash,
        "a hash without the multihash prefix",
    );

    // KS-1: `predecessor` not in multihash form — the chain link would then be
    // unresolvable, and the schema must not let it through.
    let mut raw_pred = json_of(&key_inclusion());
    raw_pred["predecessor"] = serde_json::json!("deadbeef");
    assert_invalid(
        "key-inclusion.json",
        &raw_pred,
        "a predecessor without the multihash prefix",
    );

    // KS-1: a negative offset. Milliseconds since genesis are monotonic and
    // cannot run backwards past zero.
    let mut back_in_time = json_of(&key_inclusion());
    back_in_time["offset_ms"] = serde_json::json!(-1);
    assert_invalid("key-inclusion.json", &back_in_time, "a negative offset");

    // KS-1: an inclusion with no predecessor is not a link of any chain.
    let mut rootless = json_of(&key_inclusion());
    rootless.as_object_mut().unwrap().remove("predecessor");
    assert_invalid(
        "key-inclusion.json",
        &rootless,
        "an inclusion with no predecessor",
    );

    // A timestamp without the Z (§3, the fixed form).
    let mut local_time = json_of(&binding());
    local_time["bound_at"] = serde_json::json!("2026-08-27T11:01:00+03:00");
    assert_invalid("binding.json", &local_time, "a timestamp not in UTC");

    // Core v2 §3: the milliseconds are part of the one form, not optional.
    let mut no_millis = json_of(&binding());
    no_millis["bound_at"] = serde_json::json!("2026-08-27T11:01:00Z");
    assert_invalid(
        "binding.json",
        &no_millis,
        "a timestamp without milliseconds",
    );

    // Core v2 §5: the context names the major version; another one is refused.
    let mut old_ctx = json_of(&binding());
    old_ctx["@context"] = serde_json::json!("urn:keysingate:core:v1");
    assert_invalid("binding.json", &old_ctx, "the context of core v1");
    let mut no_ctx = json_of(&binding());
    no_ctx.as_object_mut().unwrap().remove("@context");
    assert_invalid("binding.json", &no_ctx, "no context");

    // Core v2 §5: exactly v = 3; a v2 document belongs to core v1.
    let mut v2 = json_of(&binding());
    v2["v"] = serde_json::json!(2);
    assert_invalid("binding.json", &v2, "v: 2");

    // Core v2 §3: integers above 2^53 - 1 are refused.
    let mut huge = json_of(&key_inclusion());
    huge["offset_ms"] = serde_json::json!(9_007_199_254_740_992_u64);
    assert_invalid("key-inclusion.json", &huge, "an integer above 2^53 - 1");

    // A foreign emission class (§10).
    let mut bad_class = json_of(&emission());
    bad_class["class"] = serde_json::json!("medium");
    assert_invalid(
        "emission.json",
        &bad_class,
        "a class outside the enumeration",
    );

    // An unknown field: the schema is closed, otherwise an extension would slip
    // through silently and without a new major version (§14).
    let mut extra = json_of(&binding());
    extra["extra_field"] = serde_json::json!(1);
    assert_invalid("binding.json", &extra, "an unknown field");
}

// --- class promotion and status record (core v2 §8.7, §11) ---------------------

fn promotion() -> ksg_core_v2::doc::ClassPromotion {
    let owner = Ed25519Signer::from_seed(uri("did:key:zOwner#o1"), [44u8; 32]);
    let doc = ksg_core_v2::doc::ClassPromotion {
        context: ksg_core_v2::doc::Context,
        doc_type: "ClassPromotion".into(),
        v: 3,
        container: Hash::sha256(b"container"),
        from: Class::Light,
        to: Class::Heavy,
        offset_ms: 86_400_000,
        signatures: SignatureSet::default(),
    };
    let s1 = sign_doc(&doc, &issuer()).unwrap();
    let s2 = sign_doc(&doc, &owner).unwrap();
    ksg_core_v2::doc::ClassPromotion {
        signatures: SignatureSet::new(vec![s1, s2]),
        ..doc
    }
}

fn status_record(
    number: u64,
    status: ksg_core_v2::status::Status,
    event: Option<ksg_core_v2::status::Event>,
) -> ksg_core_v2::section::StatusRecord {
    let doc = ksg_core_v2::section::StatusRecord {
        context: ksg_core_v2::doc::Context,
        doc_type: "StatusRecord".into(),
        v: 3,
        number,
        status,
        event,
        offset_ms: 1_000,
        prev: ksg_core_v2::section::section_root("ksg:em:000001", Serial(4_700_007)),
        signatures: SignatureSet::default(),
    };
    seal(doc, &issuer(), |d, s| d.signatures = s)
}

#[test]
fn promotion_and_status_record_validate() {
    use ksg_core_v2::status::{Event, Status};
    assert_valid(
        "class-promotion.json",
        &json_of(&promotion()),
        "ClassPromotion",
    );
    assert_valid(
        "status-record.json",
        &json_of(&status_record(0, Status::Printed, None)),
        "status record 0",
    );
    assert_valid(
        "status-record.json",
        &json_of(&status_record(
            1,
            Status::Packeted,
            Some(Event::ApplyPacket),
        )),
        "status record 1",
    );
    // Every status and every event the code knows is in the schema's enums:
    // a schema that lagged behind the table would reject lawful records.
    for s in Status::all() {
        let r = status_record(1, *s, Some(Event::ServeDispute));
        assert_valid("status-record.json", &json_of(&r), "every status");
    }
}

#[test]
fn status_record_zero_omits_the_event_rather_than_null() {
    use ksg_core_v2::status::Status;
    let first = json_of(&status_record(0, Status::Printed, None));
    assert!(
        first.get("event").is_none(),
        "event must be absent, not null"
    );
    let mut with_null = first;
    with_null["event"] = Value::Null;
    assert_invalid("status-record.json", &with_null, "event: null");
}

#[test]
fn promotion_and_status_schemas_reject_what_the_specification_forbids() {
    use ksg_core_v2::status::{Event, Status};
    // §8.7: two parties sign; one signature is not a raise.
    let mut one = json_of(&promotion());
    one["signatures"].as_array_mut().unwrap().pop();
    assert_invalid("class-promotion.json", &one, "one signature");
    // §9: there is nothing above heavy.
    let mut from_heavy = json_of(&promotion());
    from_heavy["from"] = serde_json::json!("heavy");
    assert_invalid("class-promotion.json", &from_heavy, "a raise from heavy");
    let mut bad_class = json_of(&promotion());
    bad_class["to"] = serde_json::json!("medium");
    assert_invalid(
        "class-promotion.json",
        &bad_class,
        "a class outside the enumeration",
    );
    // §11: 11 and 13-19 are not statuses.
    let mut no_status = json_of(&status_record(
        1,
        Status::Packeted,
        Some(Event::ApplyPacket),
    ));
    no_status["status"] = serde_json::json!(11);
    assert_invalid("status-record.json", &no_status, "status 11");
    let mut bad_event = json_of(&status_record(
        1,
        Status::Packeted,
        Some(Event::ApplyPacket),
    ));
    bad_event["event"] = serde_json::json!("make_it_so");
    assert_invalid("status-record.json", &bad_event, "an unknown event");
    // §14: at most 8 signatures in one document.
    let mut many = json_of(&status_record(0, Status::Printed, None));
    let sig = many["signatures"][0].clone();
    many["signatures"] = Value::Array(vec![sig; 9]);
    assert_invalid("status-record.json", &many, "nine signatures");
}
