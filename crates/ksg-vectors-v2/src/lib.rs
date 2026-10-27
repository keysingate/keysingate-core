//! Test vectors of core v2 — documents of major version 3 (spec v2 §16 item 5).
//!
//! Deterministic: a re-run produces **byte-identical files**. No system
//! randomness, no current time, no `HashMap` iteration order; keys come from
//! fixed seeds, ML-DSA-65 signs in its deterministic mode (FIPS 204 with a
//! fixed `rnd`), timestamps are constants.
//!
//! Every value is **computed by calls into `ksg-core-v2`**, never typed in by
//! hand: a hand-typed vector tests the author's memory, not the program. A
//! verdict is what the core returned, and a refusal carries the core's reason.
//!
//! Core v1 keeps its own vectors for documents of
//! versions 1 and 2; nothing here is shared with them (`[decision]` 30.09).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use fips204::ml_dsa_65;
use fips204::traits::{KeyGen, SerDes, Signer as _};
use serde::Serialize;
use serde_json::{json, Value};

use ksg_core_v2::anchor::{upper_bound, Attestation, AttestationVerifier};
use ksg_core_v2::canonical::{canonical_bytes, canonicalize, doc_hash, Signable};
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{
    b64_encode, sign_doc, Alg, Ed25519Signer, KeySet, Profile, PublicKey, Signature, SignatureSet,
};
use ksg_core_v2::doc::{
    derive_container_id, resolve, AgentBinding, BlockAllocation, BlockClosure, Class,
    ClassPromotion, ContainerInit, Context, Delegation, Emission, KeyInclusion, Range, Serial,
    Timestamp, Uri, GRANT_MS,
};
use ksg_core_v2::error::Invalid;
use ksg_core_v2::journal::{
    verify_bound, verify_bound_read, Binder, BoundExport, Mode, Outcome as Sealed, Party, Piece,
    RecordMeta, Sealing,
};
use ksg_core_v2::keychain::build_key_set;
use ksg_core_v2::merkle::inclusion::{inclusion_proof, verify_inclusion};
use ksg_core_v2::merkle::tree::{hash_leaf, root};
use ksg_core_v2::section::{section_root, StatusRecord, StatusSection};
use ksg_core_v2::status::{transition, Blocked, Event, Outcome, Status};

/// Where the files go, relative to the workspace root.
pub const VECTORS_DIR: &str = "vectors";

/// The anchor kind the vector reader handles (set 10).
pub const VECTOR_ANCHOR: &str = "urn:ksg:anchor:vector";
/// A proof the vector reader refuses: the network does not confirm it.
pub const FORGED_PROOF: &[u8] = b"forged";

const EM: &str = "ksg:em:000001";
const T0: &str = "2026-08-27T00:00:00.000Z";
const T_DELEGATED: &str = "2026-08-27T01:00:00.000Z";
const T_ALLOC: &str = "2026-08-27T10:00:00.000Z";
const T_EXPIRE: &str = "2026-11-25T10:00:00.000Z";
const T_BOUND: &str = "2026-08-27T10:05:00.000Z";
const T_CLOSED: &str = "2026-08-28T00:00:00.000Z";

/// Every set, in file order.
#[must_use]
pub fn generate() -> Vec<(&'static str, Value)> {
    vec![
        ("01_jcs.json", gen_jcs()),
        ("02_time.json", gen_time()),
        ("03_signature.json", gen_signature()),
        ("04_channel.json", gen_channel()),
        ("05_key_chain.json", gen_key_chain()),
        ("06_closure.json", gen_closure()),
        ("07_promotion.json", gen_promotion()),
        ("08_status_table.json", gen_status_table()),
        ("09_status_section.json", gen_status_section()),
        ("10_upper_bound.json", gen_upper_bound()),
        ("11_journal.json", gen_journal()),
        ("12_merkle.json", gen_merkle()),
        ("13_limits.json", gen_limits()),
    ]
}

/// One file's bytes: pretty JSON and a final newline.
#[must_use]
pub fn render(value: &Value) -> String {
    serde_json::to_string_pretty(value).expect("vector serialization") + "\n"
}

// --- verdicts ----------------------------------------------------------------

/// `accept`, or `reject` with the core's reason.
fn verdict<T, E: core::fmt::Display>(r: Result<T, E>) -> Value {
    match r {
        Ok(_) => json!({ "verdict": "accept" }),
        Err(e) => json!({ "verdict": "reject", "reason": e.to_string() }),
    }
}

fn j<T: Serialize>(v: &T) -> Value {
    serde_json::to_value(v).expect("serialization")
}

fn hx(h: &Hash) -> String {
    h.to_multihash()
}

// --- fixed participants ------------------------------------------------------

fn uri(s: &str) -> Uri {
    Uri::parse(s).expect("URI")
}
fn ts(s: &str) -> Timestamp {
    Timestamp::parse(s).expect("Timestamp")
}
fn signer(kid: &str, seed: u8) -> Ed25519Signer {
    Ed25519Signer::from_seed(uri(kid), [seed; 32])
}
fn root_key() -> Ed25519Signer {
    signer("did:web:issuer.example#root", 90)
}
fn ops_key() -> Ed25519Signer {
    signer("did:web:issuer.example#ops1", 91)
}
fn dist_key() -> Ed25519Signer {
    signer("did:web:dist.example#d1", 92)
}
fn holder_key() -> Ed25519Signer {
    signer("did:web:holder.example#h1", 93)
}
fn agent_key(n: u8) -> Ed25519Signer {
    signer(&format!("did:key:zAgent#k{n}"), 40 + n)
}
fn client_key() -> Ed25519Signer {
    signer("did:key:zClient#c1", 60)
}
fn owner_key() -> Ed25519Signer {
    signer("did:key:zOwner#o1", 61)
}
fn stranger_key() -> Ed25519Signer {
    signer("did:web:nobody.example#x1", 13)
}
fn set_of(keys: &[&Ed25519Signer]) -> KeySet {
    keys.iter().map(|k| k.public()).collect()
}

fn rng(from: u64, to: u64) -> Range {
    Range {
        from: Serial(from),
        to: Serial(to),
    }
}
fn block() -> Range {
    rng(4_700_000, 4_700_999)
}
fn artifact() -> Uri {
    uri("did:web:artifact.example")
}

/// Signs with every signer, in order, over the same canonical bytes.
fn signed<T: Signable + Clone>(doc: &T, by: &[&Ed25519Signer]) -> SignatureSet {
    SignatureSet::new(by.iter().map(|s| sign_doc(doc, s).expect("sign")).collect())
}

fn ed_profile() -> Profile {
    Profile::default()
}

/// A party of the journal: Ed25519 and ML-DSA-65 keys from public seeds. Seals
/// carry Ed25519 alone (CH-5a, `[decision]` 02.10); the ML-DSA key stays in the
/// party, as the container pins it.
struct Pq {
    id: Uri,
    ed: Ed25519Signer,
    sk: ml_dsa_65::PrivateKey,
    pk: PublicKey,
}

impl Pq {
    fn new(name: &str, seed: u8) -> Self {
        let ed = signer(&format!("did:key:z{name}#ed"), seed);
        let (pk, sk) = ml_dsa_65::KG::keygen_from_seed(&[seed; 32]);
        Self {
            id: uri(&format!("did:key:z{name}")),
            ed,
            sk,
            pk: PublicKey {
                kid: uri(&format!("did:key:z{name}#pq")),
                alg: Alg::MlDsa65,
                key: b64_encode(&pk.into_bytes()),
            },
        }
    }
    fn party(&self) -> Party {
        Party {
            id: self.id.clone(),
            keys: vec![self.ed.public(), self.pk.clone()],
        }
    }
    /// ML-DSA-65 in its deterministic mode: `rnd` = 32 zero bytes (FIPS 204
    /// §3.4), so the same message gives the same signature on every run.
    fn pq_sign(&self, msg: &[u8]) -> Signature {
        let sig = self
            .sk
            .try_sign_with_seed(&[0u8; 32], msg, &[])
            .expect("ml-dsa");
        Signature {
            kid: self.pk.kid.clone(),
            alg: Alg::MlDsa65,
            value: b64_encode(&sig),
        }
    }
    fn ed_only(&self, msg: &[u8]) -> SignatureSet {
        SignatureSet::new(vec![self.ed.sign(msg)])
    }
}

/// The reader of set 10, described in the file so another implementation can
/// write the same one: it handles [`VECTOR_ANCHOR`]; the proof is the UTF-8 of
/// the moment the network proves, and [`FORGED_PROOF`] is refused.
#[derive(Debug)]
pub struct VectorReader;

impl AttestationVerifier for VectorReader {
    fn verify(&self, a: &Attestation) -> Result<Timestamp, Invalid> {
        if a.proof == FORGED_PROOF {
            return Err(Invalid::Schema("the network does not confirm the anchor"));
        }
        let s = String::from_utf8(a.proof.clone())
            .map_err(|_| Invalid::Schema("the proof is not a moment"))?;
        Timestamp::parse(s)
    }
    fn handles(&self, kind: &Uri) -> bool {
        kind.as_str() == VECTOR_ANCHOR
    }
}

fn vanchor(subject: Hash, proved: &str) -> Attestation {
    Attestation {
        kind: uri(VECTOR_ANCHOR),
        subject,
        proof: proved.as_bytes().to_vec(),
        anchored_at: ts(proved),
    }
}

fn reader_description() -> Value {
    json!({
        "kind": VECTOR_ANCHOR,
        "rule": "an attestation of this kind is read; its proof is the UTF-8 of the moment the network proves, and that moment is returned; a proof equal to the bytes of \"forged\" is refused; every other kind is not read",
    })
}

// --- 01 JCS ------------------------------------------------------------------

fn gen_jcs() -> Value {
    let accept = [
        json!({ "b": 2, "a": 1 }),
        json!({ "z": { "y": [3, 2, 1], "x": "é" }, "a": "\u{20ac}" }),
        json!({ "max": 9_007_199_254_740_991_u64, "zero": 0 }),
        json!({ "s": "line\nbreak\t\"q\"", "u": "\u{1f600}" }),
    ];
    let reject = [
        ("negative", json!({ "n": -1 })),
        ("fraction", json!({ "n": 1.5 })),
        ("above 2^53-1", json!({ "n": 9_007_199_254_740_992_u64 })),
        ("not an object", json!([1, 2, 3])),
    ];
    let cases: Vec<Value> = accept
        .iter()
        .map(|v| {
            let bytes = canonicalize(v).expect("canonical");
            json!({
                "input": v,
                "canonical": String::from_utf8(bytes.clone()).expect("utf-8"),
                "sha256": hx(&Hash::sha256(&bytes)),
                "verdict": "accept",
            })
        })
        .chain(reject.iter().map(|(name, v)| {
            let mut c = verdict(canonicalize(v));
            c["name"] = json!(name);
            c["input"] = v.clone();
            c
        }))
        .collect();
    json!({
        "set": "01_jcs",
        "spec": "core v2 §3: RFC 8785; integers only, 0 … 2^53 − 1",
        "cases": cases,
    })
}

// --- 02 time -----------------------------------------------------------------

fn gen_time() -> Value {
    let accept = [
        "1970-01-01T00:00:00.000Z",
        "2026-08-27T00:00:00.000Z",
        "2026-08-27T00:00:00.500Z",
        "2024-02-29T23:59:59.999Z",
        "9999-12-31T23:59:59.999Z",
    ];
    let reject = [
        "2026-08-27T00:00:00Z",
        "2026-08-27T00:00:00.5Z",
        "2026-08-27T00:00:00.5000Z",
        "2026-08-27T03:00:00.000+03:00",
        "2026-08-27 00:00:00.000Z",
        "2025-02-29T00:00:00.000Z",
        "2026-04-31T00:00:00.000Z",
        "2026-08-27T24:00:00.000Z",
        "2026-08-27T23:59:60.000Z",
        "1969-12-31T23:59:59.999Z",
    ];
    let mut cases: Vec<Value> = accept
        .iter()
        .map(|s| json!({ "input": s, "verdict": "accept", "unix_ms": ts(s).unix_ms() }))
        .collect();
    cases.extend(reject.iter().map(|s| {
        let mut c = verdict(Timestamp::parse(*s));
        c["input"] = json!(s);
        c
    }));
    // The order of moments: what v1 got wrong by comparing strings (Ya-5).
    let a = ts("2026-08-27T00:00:00.500Z");
    let b = ts("2026-08-27T00:00:01.000Z");
    json!({
        "set": "02_time",
        "spec": "core v2 §5: exactly YYYY-MM-DDTHH:MM:SS.mmmZ; compared as milliseconds",
        "cases": cases,
        "order": [{ "earlier": a.as_str(), "later": b.as_str(), "earlier_ms": a.unix_ms(), "later_ms": b.unix_ms() }],
    })
}

// --- 03 signatures -----------------------------------------------------------

fn emission() -> Emission {
    let doc = Emission {
        context: Context,
        doc_type: "Emission".into(),
        v: 3,
        id: EM.into(),
        range: rng(1, 100_000_000),
        block_ttl_days: 90,
        issuer: uri("did:web:issuer.example"),
        issued_at: ts(T0),
        keys: vec![root_key().public()],
        signatures: SignatureSet::default(),
    };
    Emission {
        signatures: signed(&doc, &[&root_key()]),
        ..doc
    }
}

fn gen_signature() -> Value {
    let doc = emission();
    let message = canonical_bytes(&doc).expect("canonical");
    let pq = Pq::new("Signer", 77);
    let pq_sig = pq.pq_sign(&message);
    let both = SignatureSet::new(vec![root_key().sign(&message), pq_sig.clone()]);
    let mut pq_keys = set_of(&[&root_key()]);
    pq_keys.insert(pq.pk.clone());
    let mut pq_profile = ed_profile();
    pq_profile.required_algs.insert(Alg::MlDsa65);

    let mut flipped = doc.signatures.as_slice()[0].clone();
    let mut raw = flipped.value.into_bytes();
    raw[0] = if raw[0] == b'A' { b'B' } else { b'A' };
    flipped.value = String::from_utf8(raw).expect("ascii");

    let ed_keys = set_of(&[&root_key()]);
    let cases = vec![
        json!({ "name": "Ed25519 over the canonical form", "keys": [root_key().public()], "profile": ["Ed25519"],
                "signatures": doc.signatures, "result": verdict(doc.signatures.verify(&message, &ed_keys, &ed_profile())) }),
        json!({ "name": "Ed25519 and ML-DSA-65 (deterministic, rnd = 0^32)", "keys": [root_key().public(), pq.pk],
                "profile": ["Ed25519", "ML-DSA-65"], "signatures": both,
                "result": verdict(both.verify(&message, &pq_keys, &pq_profile)) }),
        json!({ "name": "the profile asks for ML-DSA-65 and only Ed25519 is there", "profile": ["Ed25519", "ML-DSA-65"],
                "signatures": doc.signatures, "result": verdict(doc.signatures.verify(&message, &pq_keys, &pq_profile)) }),
        json!({ "name": "one character of the signature changed", "profile": ["Ed25519"],
                "signatures": [flipped.clone()],
                "result": verdict(SignatureSet::new(vec![flipped]).verify(&message, &ed_keys, &ed_profile())) }),
        json!({ "name": "a key outside the presented set", "profile": ["Ed25519"],
                "signatures": [stranger_key().sign(&message)],
                "result": verdict(SignatureSet::new(vec![stranger_key().sign(&message)]).verify(&message, &ed_keys, &ed_profile())) }),
    ];
    json!({
        "set": "03_signature",
        "spec": "core v2 §4: the signature covers the canonical form without `signatures`",
        "document": doc,
        "message": String::from_utf8(message).expect("utf-8"),
        "cases": cases,
    })
}

// --- 04 channel --------------------------------------------------------------

fn delegation(
    depth: u8,
    parent: Option<&Delegation>,
    delegate: &str,
    key: &Ed25519Signer,
    range: Range,
    grantor: &Ed25519Signer,
    expires: &str,
) -> Delegation {
    let doc = Delegation {
        context: Context,
        doc_type: "Delegation".into(),
        v: 3,
        emission: EM.into(),
        range,
        delegate: uri(delegate),
        keys: vec![key.public()],
        parent: parent.map(|p| doc_hash(p).expect("hash")),
        depth,
        delegated_at: ts(T_DELEGATED),
        term_ms: GRANT_MS,
        expires_at: ts(expires),
        signatures: SignatureSet::default(),
    };
    Delegation {
        signatures: signed(&doc, &[grantor]),
        ..doc
    }
}

fn chain() -> Vec<Delegation> {
    let first = delegation(
        0,
        None,
        "did:web:issuer.example",
        &ops_key(),
        rng(1, 100_000_000),
        &root_key(),
        "2027-08-27T00:00:00.000Z",
    );
    let second = delegation(
        1,
        Some(&first),
        "did:web:dist.example",
        &dist_key(),
        rng(4_000_000, 4_999_999),
        &ops_key(),
        "2027-01-01T00:00:00.000Z",
    );
    vec![first, second]
}

fn allocation() -> BlockAllocation {
    let doc = BlockAllocation {
        context: Context,
        doc_type: "BlockAllocation".into(),
        v: 3,
        emission: EM.into(),
        block: block(),
        class: Class::Heavy,
        holder: uri("did:web:holder.example"),
        allocated_at: ts(T_ALLOC),
        expires_at: ts(T_EXPIRE),
        prev_closure: None,
        signatures: SignatureSet::default(),
    };
    BlockAllocation {
        signatures: signed(&doc, &[&dist_key()]),
        ..doc
    }
}

fn binding_with(agent: &Ed25519Signer) -> AgentBinding {
    let doc = AgentBinding {
        context: Context,
        doc_type: "AgentBinding".into(),
        v: 3,
        emission: EM.into(),
        block: block(),
        agent: agent.public(),
        bound_at: ts(T_BOUND),
        signatures: SignatureSet::default(),
    };
    AgentBinding {
        signatures: signed(&doc, &[agent, &holder_key()]),
        ..doc
    }
}

fn binding() -> AgentBinding {
    binding_with(&agent_key(0))
}

fn init_with(container: Option<Hash>, offset_ms: u64, serial: u64) -> ContainerInit {
    let derived = derive_container_id(
        EM,
        &ts(T0),
        Serial(serial),
        &client_key().public(),
        &artifact(),
        offset_ms,
    );
    let doc = ContainerInit {
        context: Context,
        doc_type: "ContainerInit".into(),
        v: 3,
        emission: EM.into(),
        serial: Serial(serial),
        binding: doc_hash(&binding()).expect("hash"),
        agent: client_key().public(),
        artifact: artifact(),
        offset_ms,
        container: container.unwrap_or(derived),
        signatures: SignatureSet::default(),
    };
    ContainerInit {
        signatures: signed(&doc, &[&client_key(), &owner_key()]),
        ..doc
    }
}

fn init() -> ContainerInit {
    init_with(None, 12_345, 4_700_007)
}

fn gen_channel() -> Value {
    let p = ed_profile();
    let em = emission();
    let chain = chain();
    let resolved = resolve(&em, &chain, &em.declared_keys(), &p);
    let (packet_keys, granted) = resolved.clone().expect("the chain resolves");
    let alloc = allocation();
    let bind = binding();
    let holder = set_of(&[&holder_key()]);
    let birth = init();
    let birth_keys = set_of(&[&client_key(), &owner_key()]);

    // Refusals, each built by the implementation and then broken in one place.
    let mut v2 = j(&bind);
    v2["v"] = json!(2);
    let mut old_ctx = j(&bind);
    old_ctx["@context"] = json!("urn:keysingate:core:v1");
    let mut extra = j(&bind);
    extra["extra"] = json!(1);
    // What a verifier does with bytes it was handed: parse strictly, then
    // validate. The version is checked by `validate`, the context and the
    // closed field set already by the parse.
    let parse = |v: &Value| {
        verdict(
            serde_json::from_value::<AgentBinding>(v.clone())
                .map_err(|e| e.to_string())
                .and_then(|b| b.validate(&alloc, &holder, &p).map_err(|e| e.to_string())),
        )
    };

    let asserted = init_with(
        Some(Hash::sha256(b"an identifier of my own choosing")),
        12_345,
        4_700_007,
    );
    let late = init_with(None, em.lifetime_ms(1) + 1, 4_700_007);
    let outside = init_with(None, 12_345, 4_701_000);
    let agent_only = AgentBinding {
        signatures: signed(&bind, &[&agent_key(0)]),
        ..bind.clone()
    };

    json!({
        "set": "04_channel",
        "spec": "core v2 §8: release → delegations → packet → binding → initiation → container ID",
        "documents": {
            "emission": em,
            "delegations": chain,
            "allocation": alloc,
            "binding": bind,
            "container_init": birth,
        },
        "presented_keys": {
            "holder": [holder_key().public()],
            "initiation": [client_key().public(), owner_key().public()],
            "chain_depth": 1,
        },
        "derived": {
            "emission_hash": hx(&doc_hash(&em).expect("hash")),
            "binding_hash": hx(&doc_hash(&bind).expect("hash")),
            "granted_range": granted,
            "packet_keys": packet_keys.keys().cloned().collect::<Vec<_>>(),
            "container_id": hx(&birth.container),
            "container_id_inputs": "SHA-256 of length-prefixed fields: domain, emission id, emission issued_at, serial (u64 big-endian), agent key (base64url text), artifact URI, offset_ms (u64 big-endian)",
            "lifetime_ms_at_depth_1": em.lifetime_ms(1),
        },
        "cases": [
            { "name": "emission", "result": verdict(em.validate(&p)) },
            { "name": "delegation chain", "result": verdict(resolved) },
            { "name": "allocation signed by the distributor's granted key", "result": verdict(alloc.validate(&em, true, None, &packet_keys, &p)) },
            { "name": "binding signed by the agent and the holder", "result": verdict(bind.validate(&alloc, &holder, &p)) },
            { "name": "binding signed by the agent alone", "document": agent_only, "result": verdict(agent_only.validate(&alloc, &holder, &p)) },
            { "name": "initiation with the derived identifier", "result": verdict(birth.validate(&em, &bind, 1, &birth_keys, &p)) },
            { "name": "initiation asserting its own identifier", "document": asserted, "result": verdict(asserted.validate(&em, &bind, 1, &birth_keys, &p)) },
            { "name": "initiation after the packet's lifetime", "document": late, "result": verdict(late.validate(&em, &bind, 1, &birth_keys, &p)) },
            { "name": "initiation of a serial outside the block", "document": outside, "result": verdict(outside.validate(&em, &bind, 1, &birth_keys, &p)) },
            { "name": "a binding of version 2 belongs to core v1", "input": v2, "result": parse(&v2) },
            { "name": "a binding in the context of core v1", "input": old_ctx, "result": parse(&old_ctx) },
            { "name": "a binding with an unknown field", "input": extra, "result": parse(&extra) },
        ],
    })
}

// --- 05 key chain ------------------------------------------------------------

fn inclusion(
    predecessor: Hash,
    key: &Ed25519Signer,
    by: &Ed25519Signer,
    offset_ms: u64,
) -> KeyInclusion {
    let doc = KeyInclusion {
        context: Context,
        doc_type: "KeyInclusion".into(),
        v: 3,
        emission: EM.into(),
        block: block(),
        predecessor,
        key: key.public(),
        offset_ms,
        signatures: SignatureSet::default(),
    };
    KeyInclusion {
        signatures: signed(&doc, &[by]),
        ..doc
    }
}

fn gen_key_chain() -> Value {
    let p = ed_profile();
    let bind = binding();
    let first = inclusion(
        doc_hash(&bind).expect("hash"),
        &agent_key(1),
        &agent_key(0),
        1_000,
    );
    let second = inclusion(
        doc_hash(&first).expect("hash"),
        &agent_key(2),
        &agent_key(1),
        2_000,
    );
    let good = build_key_set(&bind, &[first.clone(), second.clone()], &p);
    let kids = good
        .as_ref()
        .map(|k| {
            k.keys()
                .map(|k| k.kid.as_str().to_owned())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let skipped = inclusion(
        doc_hash(&bind).expect("hash"),
        &agent_key(2),
        &agent_key(1),
        2_000,
    );
    let wrong_signer = inclusion(
        doc_hash(&first).expect("hash"),
        &agent_key(2),
        &agent_key(0),
        2_000,
    );
    let again = inclusion(
        doc_hash(&first).expect("hash"),
        &agent_key(1),
        &agent_key(1),
        2_000,
    );
    json!({
        "set": "05_key_chain",
        "spec": "core v2 §8.6: a key is laid on top, never replaced; every key of the chain stays valid",
        "binding": bind,
        "inclusions": [first, second],
        "result": verdict(good),
        "key_set": kids,
        "cases": [
            { "name": "a link that does not follow its predecessor", "inclusions": [first, skipped],
              "result": verdict(build_key_set(&bind, &[first.clone(), skipped.clone()], &p)) },
            { "name": "a link signed by a key other than its predecessor's", "inclusions": [first, wrong_signer],
              "result": verdict(build_key_set(&bind, &[first.clone(), wrong_signer.clone()], &p)) },
            { "name": "a key already in the set", "inclusions": [first, again],
              "result": verdict(build_key_set(&bind, &[first.clone(), again.clone()], &p)) },
        ],
    })
}

// --- 06 closure --------------------------------------------------------------

fn closure(
    submitted: Vec<Range>,
    not_submitted: Vec<Range>,
    cancelled: Option<Vec<Range>>,
) -> BlockClosure {
    let mut doc = BlockClosure::draft(EM.into(), block(), submitted, not_submitted, ts(T_CLOSED));
    if let Some(c) = cancelled {
        doc.cancelled = c;
    }
    BlockClosure {
        signatures: signed(&doc, &[&agent_key(0)]),
        ..doc
    }
}

fn gen_closure() -> Value {
    let p = ed_profile();
    let keys = set_of(&[&agent_key(0)]);
    let good = closure(vec![rng(4_700_000, 4_700_399)], vec![], None);
    let light = closure(
        vec![rng(4_700_000, 4_700_099)],
        vec![rng(4_700_100, 4_700_199)],
        None,
    );
    let gap = closure(
        vec![rng(4_700_000, 4_700_399)],
        vec![],
        Some(vec![rng(4_700_401, 4_700_999)]),
    );
    let overlap = closure(
        vec![rng(4_700_000, 4_700_399)],
        vec![],
        Some(vec![rng(4_700_399, 4_700_999)]),
    );
    let case = |name: &str, d: &BlockClosure, class: Class| json!({ "name": name, "class": class, "document": d, "result": verdict(d.validate(class, &keys, &p)) });
    json!({
        "set": "06_closure",
        "spec": "core v2 §8.4: used-submitted, used-not-submitted and cancelled partition the packet exactly",
        "cases": [
            case("heavy, cancelled is the complement", &good, Class::Heavy),
            case("light, both used buckets", &light, Class::Light),
            case("heavy cannot have used-not-submitted", &light, Class::Heavy),
            case("a serial covered by nothing", &gap, Class::Heavy),
            case("a serial covered twice", &overlap, Class::Heavy),
        ],
    })
}

// --- 07 promotion ------------------------------------------------------------

fn promotion(from: Class, to: Class, by: &[&Ed25519Signer]) -> ClassPromotion {
    let doc = ClassPromotion {
        context: Context,
        doc_type: "ClassPromotion".into(),
        v: 3,
        container: init().container,
        from,
        to,
        offset_ms: 86_400_000,
        signatures: SignatureSet::default(),
    };
    ClassPromotion {
        signatures: signed(&doc, by),
        ..doc
    }
}

fn gen_promotion() -> Value {
    let p = ed_profile();
    let keys = set_of(&[&root_key(), &owner_key()]);
    let container = init().container;
    let up = promotion(Class::Light, Class::Heavy, &[&root_key(), &owner_key()]);
    let down = promotion(Class::Heavy, Class::Light, &[&root_key(), &owner_key()]);
    let alone = promotion(Class::Light, Class::Heavy, &[&root_key()]);
    let case = |name: &str, d: &ClassPromotion, current: Class| {
        json!({ "name": name, "current": current, "document": d,
                "result": verdict(d.validate(&container, current, &keys, &p)) })
    };
    json!({
        "set": "07_promotion",
        "spec": "core v2 §8.7: upward only, signed by the issuer and the holder",
        "container": hx(&container),
        "cases": [
            case("light to heavy, two parties", &up, Class::Light),
            case("heavy to light", &down, Class::Heavy),
            case("one party", &alone, Class::Light),
            case("from a class the container does not hold", &up, Class::Bare),
        ],
    })
}

// --- 08 status table ---------------------------------------------------------

/// Every event, in declaration order. `Event` has no list of its own; the
/// replay test checks this one against the schema's enumeration.
pub const EVENTS: [Event; 29] = [
    Event::PrintRelease,
    Event::ApplyPacket,
    Event::ApplyBuyerKey,
    Event::ApplySubAgentKey,
    Event::Initiate,
    Event::InitiateTooLate,
    Event::OpenJournal,
    Event::RecordWork,
    Event::RecordArtifactOrRights,
    Event::TransferOwnership,
    Event::RaiseClass,
    Event::FullExport,
    Event::Finalize,
    Event::OpenVoluntarily,
    Event::FreezeOnOwnerApplication,
    Event::Succeed,
    Event::DeclareKeyLost,
    Event::DeclareContainerLost,
    Event::ServeDispute,
    Event::DisputeProven,
    Event::DisputeUnproven,
    Event::Appeal,
    Event::AppealWon,
    Event::AppealLost,
    Event::ExtendReview,
    Event::ReviewDeadlinePassed,
    Event::Settle,
    Event::PrescriptionPassed,
    Event::PacketTermExpired,
];

/// An outcome as the vectors write it.
#[must_use]
pub fn outcome_json(o: &Outcome) -> Value {
    match o {
        Outcome::Moves(s) => json!({ "moves": s.number() }),
        Outcome::Stays => json!("stays"),
        Outcome::Blocks => json!("blocks"),
        Outcome::Refused(_) => json!("refused"),
    }
}

fn gen_status_table() -> Value {
    let row = |s: Status, b: Blocked| {
        let mut m = serde_json::Map::new();
        for e in EVENTS {
            m.insert(
                j(&e).as_str().expect("name").to_owned(),
                outcome_json(&transition(s, b, e)),
            );
        }
        Value::Object(m)
    };
    let mut table = serde_json::Map::new();
    for s in Status::all() {
        table.insert(s.number().to_string(), row(*s, Blocked::No));
    }
    json!({
        "set": "08_status_table",
        "spec": "core v2 §11, KS-7 §7.2-bis/ter: every status × event pair has exactly one outcome; a pair not listed is refused",
        "statuses": Status::all().iter().map(|s| s.number()).collect::<Vec<_>>(),
        "terminal": Status::all().iter().filter(|s| s.is_terminal()).map(|s| s.number()).collect::<Vec<_>>(),
        "working": Status::all().iter().filter(|s| s.is_working()).map(|s| s.number()).collect::<Vec<_>>(),
        "table": table,
        "while_blocked": row(Status::Disputed, Blocked::AwaitingDecision),
        "while_blocked_note": "a blocked container takes only a decision, a settlement or the prescription, whatever its status",
    })
}

// --- 09 status section -------------------------------------------------------

fn status_record(
    number: u64,
    status: Status,
    event: Option<Event>,
    prev: Hash,
    offset_ms: u64,
) -> StatusRecord {
    let doc = StatusRecord {
        context: Context,
        doc_type: "StatusRecord".into(),
        v: 3,
        number,
        status,
        event,
        offset_ms,
        prev,
        signatures: SignatureSet::default(),
    };
    StatusRecord {
        signatures: signed(&doc, &[&root_key()]),
        ..doc
    }
}

fn gen_status_section() -> Value {
    let p = ed_profile();
    let keys = set_of(&[&root_key()]);
    let serial = Serial(4_700_007);
    let root_hash = section_root(EM, serial);
    let moments = [
        "2026-08-27T00:00:01.000Z",
        "2026-08-27T10:00:01.000Z",
        "2026-08-27T10:05:01.000Z",
        "2026-08-27T11:00:01.000Z",
        "2026-08-27T11:30:01.000Z",
    ];
    let steps = [
        (Status::Printed, None),
        (Status::Packeted, Some(Event::ApplyPacket)),
        (Status::BuyerKeyed, Some(Event::ApplyBuyerKey)),
        (Status::Initiated, Some(Event::Initiate)),
        (Status::InWork, Some(Event::OpenJournal)),
    ];
    let mut prev = root_hash;
    let mut records = Vec::new();
    for (n, ((status, event), at)) in steps.iter().zip(moments).enumerate() {
        let r = status_record(n as u64, *status, *event, prev, 1_000 * n as u64);
        prev = r.hash().expect("hash");
        let a = vanchor(prev, at);
        records.push((r, a));
    }
    let mut section = StatusSection::start(
        EM,
        serial,
        records[0].0.clone(),
        records[0].1.clone(),
        &keys,
        &p,
    )
    .expect("start");
    for ((r, a), (_, e)) in records.iter().zip(steps).skip(1) {
        section
            .apply(
                e.expect("event"),
                Some(r.clone()),
                Some(a.clone()),
                &keys,
                &p,
            )
            .expect("apply");
    }
    let times = section.times(&p, Some(&VectorReader)).expect("times");

    // Refusals against the section after record 4.
    let after = |r: StatusRecord, a: Attestation, e: Event| {
        let mut s = StatusSection::start(
            EM,
            serial,
            records[0].0.clone(),
            records[0].1.clone(),
            &keys,
            &p,
        )
        .expect("start");
        for ((r, a), (_, e)) in records.iter().zip(steps).skip(1) {
            s.apply(
                e.expect("event"),
                Some(r.clone()),
                Some(a.clone()),
                &keys,
                &p,
            )
            .expect("apply");
        }
        json!({ "event": e, "record": r, "anchor": a, "result": verdict(s.apply(e, Some(r.clone()), Some(a), &keys, &p)) })
    };
    let head = section.head();
    let disputed = status_record(5, Status::Disputed, Some(Event::ServeDispute), head, 9_000);
    let off_chain = status_record(
        5,
        Status::Disputed,
        Some(Event::ServeDispute),
        root_hash,
        9_000,
    );
    let out_of_order = status_record(7, Status::Disputed, Some(Event::ServeDispute), head, 9_000);
    let wrong_status = status_record(5, Status::Finalized, Some(Event::ServeDispute), head, 9_000);
    let a5 = vanchor(disputed.hash().expect("hash"), "2026-09-01T00:00:00.000Z");
    let other = vanchor(Hash::sha256(b"another record"), "2026-09-01T00:00:00.000Z");
    let refused = status_record(5, Status::Packeted, Some(Event::ApplyPacket), head, 9_000);

    json!({
        "set": "09_status_section",
        "spec": "core v2 §11: a status change is a record and its anchor; record 0 links to the section root; the anchor is read under §7.2",
        "reader": reader_description(),
        "emission": EM,
        "serial": serial,
        "section_root": hx(&root_hash),
        "section_root_inputs": "SHA-256 of length-prefixed fields: \"ksg:status-section:v1\", emission id, serial (u64 big-endian)",
        "records": records.iter().map(|(r, a)| json!({ "record": r, "hash": hx(&r.hash().expect("hash")), "anchor": a })).collect::<Vec<_>>(),
        "current": section.current().number(),
        "times": times,
        "cases": [
            json!({ "name": "the next change, linked and anchored", "case": after(disputed.clone(), a5.clone(), Event::ServeDispute) }),
            json!({ "name": "a record that does not link to the head", "case": after(off_chain, a5.clone(), Event::ServeDispute) }),
            json!({ "name": "a record out of order", "case": after(out_of_order, a5.clone(), Event::ServeDispute) }),
            json!({ "name": "a record carrying another status than the move", "case": after(wrong_status, a5, Event::ServeDispute) }),
            json!({ "name": "an anchor of another record", "case": after(disputed, other, Event::ServeDispute) }),
            json!({ "name": "a move the table refuses", "case": after(refused, vanchor(Hash::sha256(b"x"), "2026-09-01T00:00:00.000Z"), Event::ApplyPacket) }),
        ],
    })
}

// --- 10 upper bound ----------------------------------------------------------

fn gen_upper_bound() -> Value {
    let subject = Hash::sha256(b"subject");
    let p = ed_profile();
    let mut two = ed_profile();
    two.min_anchors = core::num::NonZeroUsize::new(2).expect("two");
    let early = vanchor(subject, "2026-09-01T10:00:00.000Z");
    let late = vanchor(subject, "2026-09-02T10:00:00.000Z");
    let unread = Attestation {
        kind: uri("urn:ksg:anchor:unknown-network"),
        ..vanchor(subject, "2026-08-01T00:00:00.000Z")
    };
    let forged = Attestation {
        proof: FORGED_PROOF.to_vec(),
        ..early.clone()
    };
    let other = vanchor(Hash::sha256(b"another subject"), "2026-09-01T10:00:00.000Z");
    let many: Vec<Attestation> = (0..17).map(|_| early.clone()).collect();
    let case = |name: &str, anchors: &[Attestation], profile: &Profile, with_reader: bool| {
        let reader: Option<&dyn AttestationVerifier> = if with_reader {
            Some(&VectorReader)
        } else {
            None
        };
        let r = upper_bound(anchors, &subject, profile, reader);
        let mut v = verdict(r.clone());
        if let Ok(b) = r {
            v["bound"] = json!(b);
        }
        json!({ "name": name, "anchors": anchors, "min_anchors": profile.min_anchors.get(), "reader": with_reader, "result": v })
    };
    json!({
        "set": "10_upper_bound",
        "spec": "core v2 §7.2: the one rule of the upper time bound for seals, statuses and releases",
        "reader": reader_description(),
        "subject": hx(&subject),
        "cases": [
            case("one anchor read", std::slice::from_ref(&early), &p, true),
            case("the earliest of two", &[late.clone(), early.clone()], &p, true),
            case("no reader: no bound, not a refusal", std::slice::from_ref(&early), &p, false),
            case("a kind nobody reads is skipped", std::slice::from_ref(&unread), &p, true),
            case("a kind nobody reads beside one read", &[unread, late.clone()], &p, true),
            case("two required, one read: no bound", std::slice::from_ref(&early), &two, true),
            case("two required, two read", &[early.clone(), late], &two, true),
            case("a forgery is a refusal, not \"not found\"", &[forged], &p, true),
            case("an anchor of another subject", &[other], &p, true),
            case("seventeen anchors: past the limit", &many, &p, true),
        ],
    })
}

// --- 11 journal --------------------------------------------------------------

fn journal(pro: bool) -> (BoundExport, Party, Hash) {
    let agent = Pq::new("Agent", 101);
    let owner = Pq::new("Owner", 102);
    let container = init().container;
    let mode = if pro { Mode::Pro } else { Mode::Local };
    let p = ed_profile();
    let (bytes, hash) =
        Binder::opening_seal(container, mode, agent.party(), owner.party(), 1).expect("seal 0");
    let opening = Sealing {
        seal: agent.ed_only(&bytes),
        owner: pro.then(|| owner.ed_only(&bytes)),
        anchor: pro.then(|| vanchor(hash, "2026-09-01T10:00:00.000Z")),
        ..Sealing::default()
    };
    let mut b = Binder::open(
        container,
        mode,
        agent.party(),
        owner.party(),
        1,
        &opening,
        &p,
    )
    .expect("open");
    let texts: [(&[u8], u64, &str); 2] = [
        (b"first record", 10, "2026-09-01T10:01:00.000Z"),
        (b"second record", 20, "2026-09-01T10:02:00.000Z"),
    ];
    for (text, at, proved) in texts {
        let d = b
            .draft_record(
                vec![Piece::Inline(text.to_vec())],
                RecordMeta::default(),
                at,
            )
            .expect("draft");
        let sealing = Sealing {
            seal: agent.ed_only(&d.seal_bytes().expect("bytes")),
            anchor: d
                .is_pro()
                .then(|| vanchor(d.seal_hash().expect("hash"), proved)),
            ..Sealing::default()
        };
        match b.seal(d, sealing, &p).expect("seal") {
            Sealed::Written(_) => {}
            Sealed::Waiting => panic!("nothing waits in the vectors"),
        }
    }
    (b.export_final(), agent.party(), container)
}

fn report_json(x: &BoundExport, pro: bool) -> Value {
    let p = ed_profile();
    match verify_bound_read(
        x,
        &p,
        pro.then_some(&VectorReader as &dyn AttestationVerifier),
    ) {
        Ok((r, bounds)) => json!({
            "verdict": "accept",
            "number": r.number,
            "mode": r.mode,
            "records": r.records.iter().map(|rec| json!({
                "batch": rec.batch, "first": rec.first, "last": rec.last,
                "anchored": rec.anchored, "seal": hx(&rec.seal),
            })).collect::<Vec<_>>(),
            "runs": r.runs,
            "bounds": bounds.iter().map(|b| json!({ "batch": b.batch, "not_after": b.not_after })).collect::<Vec<_>>(),
        }),
        Err(e) => json!({ "verdict": "reject", "reason": e.to_string() }),
    }
}

fn gen_journal() -> Value {
    let (light, agent, container) = journal(false);
    let (pro, _, _) = journal(true);
    let mut tampered = j(&light);
    tampered["pages"][1]["offset_ms"] = json!(11);
    let tampered: BoundExport = serde_json::from_value(tampered).expect("export");
    let mut no_anchor = pro.clone();
    no_anchor.anchors.pop();
    json!({
        "set": "11_journal",
        "spec": "core v2 §10: pages under the movable seal; Ed25519 and ML-DSA-65 (deterministic, rnd = 0^32); in Pro every seal is anchored",
        "reader": reader_description(),
        "container": hx(&container),
        "agent": agent,
        "cases": [
            { "name": "light: two records, no anchors", "export": light, "result": report_json(&light, false) },
            { "name": "Pro: every seal anchored and read", "export": pro, "result": report_json(&pro, true) },
            { "name": "a page changed after sealing", "export": tampered, "result": report_json(&tampered, false) },
            { "name": "Pro: the last seal's anchor missing", "export": no_anchor, "result": report_json(&no_anchor, true) },
        ],
        "structure_only": verdict(verify_bound(&light, &ed_profile())),
    })
}

// --- 12 merkle ---------------------------------------------------------------

fn gen_merkle() -> Value {
    let leaves: Vec<Hash> = (0u8..7).map(|i| hash_leaf(&[i])).collect();
    let r = root(&leaves);
    let proofs: Vec<Value> = (0..7u64)
        .map(|i| {
            let proof = inclusion_proof(&leaves, i).expect("proof");
            json!({
                "index": i,
                "path": proof.path().iter().map(hx).collect::<Vec<_>>(),
                "verifies": verify_inclusion(&leaves[i as usize], i, 7, &proof, &r),
            })
        })
        .collect();
    let wrong = inclusion_proof(&leaves, 2).expect("proof");
    json!({
        "set": "12_merkle",
        "spec": "core v2 §10.3: RFC 6962, hash_leaf = SHA-256(0x00‖d), hash_node = SHA-256(0x01‖l‖r); external CT values are checked in ksg-core-v2/tests/ct_vectors.rs",
        "leaf_data_hex": (0u8..7).map(|i| hex::encode([i])).collect::<Vec<_>>(),
        "leaf_hashes": leaves.iter().map(hx).collect::<Vec<_>>(),
        "root": hx(&r),
        "proofs": proofs,
        "negative": { "name": "the path of leaf 2 presented for leaf 3", "verifies": verify_inclusion(&leaves[3], 3, 7, &wrong, &r) },
    })
}

// --- 13 limits ---------------------------------------------------------------

fn gen_limits() -> Value {
    let p = ed_profile();
    let big = vec![b' '; ksg_core_v2::limits::MAX_DOC_BYTES + 1];
    let nine = SignatureSet::new(
        (0..9)
            .map(|_| sign_doc(&emission(), &root_key()).expect("sign"))
            .collect(),
    );
    let crowded = Emission {
        signatures: nine,
        ..emission()
    };
    let too_deep: Vec<Delegation> = {
        let mut v = chain();
        let mut grantor = dist_key();
        for d in 2u8..=5 {
            let next = signer(&format!("did:web:sub{d}.example#s"), 110 + d);
            let parent = v.last().cloned().expect("parent");
            v.push(delegation(
                d,
                Some(&parent),
                &format!("did:web:sub{d}.example"),
                &next,
                rng(4_000_000, 4_999_999),
                &grantor,
                "2027-01-01T00:00:00.000Z",
            ));
            grantor = next;
        }
        v
    };
    let em = emission();
    json!({
        "set": "13_limits",
        "spec": "core v2 §14: every input has a ceiling, checked before the work it bounds",
        "limits": {
            "document_bytes": ksg_core_v2::limits::MAX_DOC_BYTES,
            "export_bytes": ksg_core_v2::limits::MAX_EXPORT_BYTES,
            "signatures": ksg_core_v2::limits::MAX_SIGNATURES,
            "anchors": ksg_core_v2::limits::MAX_ANCHORS,
            "merkle_path": ksg_core_v2::limits::MAX_PROOF_DEPTH,
            "delegation_depth": ksg_core_v2::doc::MAX_DEPTH,
            "key_inclusions": ksg_core_v2::limits::MAX_KEY_INCLUSIONS,
            "status_records": ksg_core_v2::limits::MAX_STATUS_RECORDS,
            "journal_pages": ksg_core_v2::journal::TOTAL_PAGES,
        },
        "cases": [
            { "name": "a document one byte past 64 KiB", "bytes": big.len(),
              "result": verdict(ksg_core_v2::limits::parse_doc::<Emission>(&big)) },
            { "name": "nine signatures", "document": crowded, "result": verdict(crowded.validate(&p)) },
            { "name": "six links of delegation", "delegations": too_deep.len(),
              "result": verdict(resolve(&em, &too_deep, &em.declared_keys(), &p)) },
        ],
    })
}
