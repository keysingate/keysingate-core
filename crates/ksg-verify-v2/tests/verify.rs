//! The third party's side on core v2, end to end: a journal under the movable
//! seal written in one place, its export read as bytes in another, a verdict
//! without the issuer — and the status section the same way.

use std::process::Command;

use fips204::ml_dsa_65;
use fips204::traits::{KeyGen, SerDes, Signer as _};

use ksg_core_v2::anchor::{Attestation, AttestationVerifier};
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{
    b64_encode, sign_doc, Alg, Ed25519Signer, KeySet, Profile, PublicKey, Signature, SignatureSet,
};
use ksg_core_v2::doc::{Class, Context, Serial, Timestamp, Uri};
use ksg_core_v2::error::Invalid;
use ksg_core_v2::journal::{Binder, BoundExport, Mode, Outcome, Party, Piece, RecordMeta, Sealing};
use ksg_core_v2::section::{section_root, StatusRecord, StatusSection};
use ksg_core_v2::status::{Event, Status};
use ksg_verify_v2::{keys_from_json, verify_bytes, Expected, Form, NoReader};

/// The network of the tests: an anchor of kind `urn:ksg:anchor:test` holds
/// when its proof is the moment the network proves.
#[derive(Debug)]
struct Net;
impl AttestationVerifier for Net {
    fn verify(&self, a: &Attestation) -> Result<Timestamp, Invalid> {
        let s = String::from_utf8(a.proof.clone()).map_err(|_| Invalid::Schema("proof"))?;
        Timestamp::parse(s).map_err(|_| Invalid::Schema("not confirmed"))
    }
    fn handles(&self, kind: &Uri) -> bool {
        kind.as_str() == "urn:ksg:anchor:test"
    }
}

fn uri(s: &str) -> Uri {
    Uri::parse(s).expect("uri")
}
fn container() -> Hash {
    Hash::sha256(b"container No. 7")
}
fn anchor(subject: Hash, proved: &str) -> Attestation {
    Attestation {
        kind: uri("urn:ksg:anchor:test"),
        subject,
        proof: proved.as_bytes().to_vec(),
        anchored_at: Timestamp::parse(proved).expect("ts"),
    }
}

/// The agent: Ed25519 and ML-DSA-65 from public seeds.
///
/// G-1: the agent is named by the `did:key` of its Ed25519 key — the same
/// string a verifier computes — and not by a label the stand made up.
struct Agent {
    ed: Ed25519Signer,
    sk: ml_dsa_65::PrivateKey,
    pk: PublicKey,
    id: Uri,
}

impl Agent {
    fn new(seed: u8) -> Self {
        let (pk, sk) = ml_dsa_65::KG::keygen_from_seed(&[seed; 32]);
        let first = Ed25519Signer::from_seed(uri("urn:ksg:test:agent#ed"), [seed; 32]);
        let did = ksg_core_v2::crypto::did_key::of_ed25519_b64(&first.public().key)
            .expect("the key's own did:key");
        let id = uri(&did);
        Self {
            ed: Ed25519Signer::from_seed(
                uri(&format!("{did}#{}", ksg_core_v2::crypto::did_key::FRAGMENT)),
                [seed; 32],
            ),
            sk,
            pk: PublicKey {
                kid: uri(&format!("{did}#pq")),
                alg: Alg::MlDsa65,
                key: b64_encode(&pk.into_bytes()),
            },
            id,
        }
    }
    fn party(&self) -> Party {
        Party {
            id: self.id.clone(),
            keys: vec![self.ed.public(), self.pk.clone()],
        }
    }
    fn both(&self, msg: &[u8]) -> SignatureSet {
        let pq = self
            .sk
            .try_sign_with_seed(&[0; 32], msg, &[])
            .expect("ml-dsa");
        SignatureSet::new(vec![
            self.ed.sign(msg),
            Signature {
                kid: self.pk.kid.clone(),
                alg: Alg::MlDsa65,
                value: b64_encode(&pq),
            },
        ])
    }
    fn keys(&self) -> KeySet {
        [self.ed.public(), self.pk.clone()].into_iter().collect()
    }
}

/// A journal of two records, in the form the class opens it in.
fn journal(class: Class) -> (Binder, Agent) {
    let agent = Agent::new(31);
    let owner = Agent::new(32);
    let pro = class == Class::Heavy;
    let mode = if pro { Mode::Pro } else { Mode::Local };
    let p = Profile::default();
    let (bytes, hash) = Binder::opening_seal(
        container(),
        mode,
        agent.party(),
        owner.party(),
        1,
    )
    .expect("seal 0");
    let opening = Sealing {
        seal: agent.both(&bytes),
        owner: pro.then(|| SignatureSet::new(vec![owner.ed.sign(&bytes)])),
        anchor: pro.then(|| anchor(hash, "2026-09-01T10:00:00.000Z")),
        ..Sealing::default()
    };
    let mut b = Binder::open(
        container(),
        mode,
        agent.party(),
        owner.party(),
        1,
        &opening,
        &p,
    )
    .expect("open");
    for (text, at, proved) in [
        (&b"first"[..], 10, "2026-09-01T10:01:00.000Z"),
        (&b"second"[..], 20, "2026-09-01T10:02:00.000Z"),
    ] {
        let d = b
            .draft_record(
                vec![Piece::Inline(text.to_vec())],
                RecordMeta::default(),
                at,
            )
            .expect("draft");
        let sealing = Sealing {
            seal: agent.both(&d.seal_bytes().expect("bytes")),
            anchor: d
                .is_pro()
                .then(|| anchor(d.seal_hash().expect("hash"), proved)),
            ..Sealing::default()
        };
        assert_eq!(
            b.seal(d, sealing, &p).expect("seal"),
            Outcome::Written(at / 10)
        );
    }
    (b, agent)
}

fn export_bytes(class: Class) -> (Vec<u8>, KeySet) {
    let (b, agent) = journal(class);
    (
        serde_json::to_vec(&b.export_final()).expect("json"),
        agent.keys(),
    )
}

fn expected(class: Class, keys: KeySet, anchors: &dyn AttestationVerifier) -> Expected<'_> {
    Expected {
        container: container(),
        class,
        keys,
        // G-1, the product's rule: the agent is named by the `did:key` of its
        // own key (the stand's keys are made that way).
        client_id_from_key: true,
        anchors,
    }
}

#[test]
fn a_light_journal_is_accepted_without_any_network() {
    let (bytes, keys) = export_bytes(Class::Light);
    let r = verify_bytes(&bytes, &expected(Class::Light, keys, &NoReader));
    assert!(r.accepted, "{r:?}");
    assert_eq!(r.form, Some(Form::Bound));
    assert_eq!(r.counter, Some(2));
    assert!(r.bounds.is_empty(), "a light journal has no time");
    assert_eq!(r.runs, Some(vec![]));
}

#[test]
fn a_pro_journal_is_refused_when_its_anchors_cannot_be_read() {
    let (bytes, keys) = export_bytes(Class::Heavy);
    let r = verify_bytes(&bytes, &expected(Class::Heavy, keys, &NoReader));
    assert!(!r.accepted);
    assert!(r.reason.unwrap().contains("no reader"));
}

#[test]
fn a_pro_journal_reports_the_bound_of_every_record() {
    let (bytes, keys) = export_bytes(Class::Heavy);
    let r = verify_bytes(&bytes, &expected(Class::Heavy, keys, &Net));
    assert!(r.accepted, "{r:?}");
    let bounds: Vec<(u64, &str)> = r
        .bounds
        .iter()
        .map(|b| (b.record, b.not_after.as_str()))
        .collect();
    assert_eq!(
        bounds,
        vec![
            (0, "2026-09-01T10:00:00.000Z"),
            (1, "2026-09-01T10:01:00.000Z"),
            (2, "2026-09-01T10:02:00.000Z"),
        ]
    );
    assert_eq!(r.runs, Some(vec![(0, 2)]));
}

#[test]
fn the_class_decides_the_form_and_another_container_is_refused() {
    let (bytes, keys) = export_bytes(Class::Light);
    let r = verify_bytes(&bytes, &expected(Class::Heavy, keys.clone(), &Net));
    assert!(!r.accepted, "a light journal does not pass as heavy");
    let mut e = expected(Class::Light, keys, &NoReader);
    e.container = Hash::sha256(b"another");
    assert!(!verify_bytes(&bytes, &e).accepted);
}

#[test]
fn keys_the_verifier_does_not_accept_are_refused() {
    let (bytes, _) = export_bytes(Class::Light);
    let stranger = Agent::new(77);
    let r = verify_bytes(&bytes, &expected(Class::Light, stranger.keys(), &NoReader));
    assert!(!r.accepted);
    assert!(r.reason.unwrap().contains("does not accept"));
}

/// G-1: the export names its author, and the name must be the `did:key` of
/// the key the pages are signed with. Another name — the keys left as they
/// were — is another agent's name, and the export is refused.
#[test]
fn an_author_named_by_another_key_is_refused() {
    let (bytes, keys) = export_bytes(Class::Light);
    let theirs =
        ksg_core_v2::crypto::did_key::of_ed25519_b64(&b64_encode(&[9u8; 32])).expect("a did:key");
    let mut v: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    v["pages"][0]["body"]["opening"]["agent"]["id"] = theirs.clone().into();
    let r = verify_bytes(
        &serde_json::to_vec(&v).expect("json"),
        &expected(Class::Light, keys, &NoReader),
    );
    assert!(!r.accepted, "{r:?}");
    let reason = r.reason.unwrap_or_default();
    assert!(reason.contains("G-1"), "{reason}");
    assert!(reason.contains(&theirs), "{reason}");
}

#[test]
fn one_page_is_verified_on_its_own_with_its_seals_bound() {    let (mut b, agent) = journal(Class::Heavy);
    let point = b.export_one(1).expect("page 1");
    let bytes = serde_json::to_vec(&point).expect("json");
    let r = verify_bytes(&bytes, &expected(Class::Heavy, agent.keys(), &Net));
    assert!(r.accepted, "{r:?}");
    assert_eq!(r.form, Some(Form::BoundPoint));
    assert_eq!(r.anchored_at.as_deref(), Some("2026-09-01T10:02:00.000Z"));
}

// --- the status section --------------------------------------------------------

fn issuer() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:web:issuer.example#k1"), [7; 32])
}

fn record(n: u64, status: Status, event: Option<Event>, prev: Hash) -> StatusRecord {
    let doc = StatusRecord {
        context: Context,
        doc_type: "StatusRecord".into(),
        v: 3,
        number: n,
        status,
        event,
        offset_ms: n * 1000,
        prev,
        signatures: SignatureSet::default(),
    };
    StatusRecord {
        signatures: SignatureSet::new(vec![sign_doc(&doc, &issuer()).expect("sign")]),
        ..doc
    }
}

fn section() -> StatusSection {
    let keys: KeySet = [issuer().public()].into_iter().collect();
    let p = Profile::default();
    let root = section_root("ksg:em:000001", Serial(7));
    let r0 = record(0, Status::Printed, None, root);
    let a0 = anchor(r0.hash().unwrap(), "2026-08-27T00:00:01.000Z");
    let mut s = StatusSection::start("ksg:em:000001", Serial(7), r0, a0, &keys, &p).unwrap();
    let r1 = record(1, Status::Packeted, Some(Event::ApplyPacket), s.head());
    let a1 = anchor(r1.hash().unwrap(), "2026-08-27T10:00:01.000Z");
    s.apply(Event::ApplyPacket, Some(r1), Some(a1), &keys, &p)
        .unwrap();
    s
}

#[test]
fn the_status_section_is_verified_with_the_time_of_every_change() {
    let bytes = serde_json::to_vec(&section().export()).unwrap();
    let keys: KeySet = [issuer().public()].into_iter().collect();
    let r = verify_bytes(&bytes, &expected(Class::Heavy, keys.clone(), &Net));
    assert!(r.accepted, "{r:?}");
    assert_eq!(r.form, Some(Form::Statuses));
    assert_eq!(r.counter, Some(1), "the current status is 1");
    assert_eq!(r.bounds.len(), 2);
    assert_eq!(r.bounds[1].not_after, "2026-08-27T10:00:01.000Z");
    // Without a reader a status has no time, and the section is refused
    // rather than reported without it (audit of 30.09, Ya-2).
    let r = verify_bytes(&bytes, &expected(Class::Heavy, keys, &NoReader));
    assert!(!r.accepted);
}

#[test]
fn a_status_section_with_a_record_taken_out_is_refused() {
    let mut x = section().export();
    let keys: KeySet = [issuer().public()].into_iter().collect();
    x.records.remove(0);
    let bytes = serde_json::to_vec(&x).unwrap();
    assert!(!verify_bytes(&bytes, &expected(Class::Heavy, keys, &Net)).accepted);
}

#[test]
fn bytes_that_are_none_of_the_forms_are_refused() {
    let r = verify_bytes(
        b"{\"hello\": 1}",
        &expected(Class::Light, KeySet::new(), &NoReader),
    );
    assert!(!r.accepted);
    assert_eq!(r.form, None);
    let _: Option<BoundExport> = None;
}

#[test]
fn keys_are_read_from_json_and_an_empty_set_is_refused() {
    let agent = Agent::new(31);
    let json = serde_json::to_vec(&vec![agent.ed.public(), agent.pk.clone()]).unwrap();
    assert_eq!(keys_from_json(&json).unwrap().len(), 2);
    assert!(keys_from_json(b"[]").is_err());
    assert!(keys_from_json(b"{}").is_err());
}

fn run(args: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_ksg-verify-v2"))
        .args(args)
        .output()
        .expect("runs");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

#[test]
fn the_program_answers_with_its_exit_code() {
    let dir = std::env::temp_dir().join(format!("ksg-verify-v2-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let light = dir.join("light.json");
    let heavy = dir.join("heavy.json");
    let keyfile = dir.join("keys.json");
    let (lb, keys) = export_bytes(Class::Light);
    std::fs::write(&light, lb).unwrap();
    std::fs::write(&heavy, export_bytes(Class::Heavy).0).unwrap();
    std::fs::write(
        &keyfile,
        serde_json::to_vec(&keys.keys().cloned().collect::<Vec<_>>()).unwrap(),
    )
    .unwrap();
    let c = container().to_multihash();

    let (code, out) = run(&[
        "--export",
        light.to_str().unwrap(),
        "--container",
        &c,
        "--class",
        "light",
        "--keys",
        keyfile.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{out}");
    assert!(out.starts_with("ACCEPTED"), "{out}");

    // A Pro journal without --rpc: its anchors cannot be read.
    let (code, out) = run(&[
        "--export",
        heavy.to_str().unwrap(),
        "--container",
        &c,
        "--class",
        "heavy",
        "--keys",
        keyfile.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(code, 1, "{out}");
    let v: serde_json::Value = serde_json::from_str(&out).expect("json report");
    assert_eq!(v["accepted"], false);

    let (code, _) = run(&["--export", light.to_str().unwrap()]);
    assert_eq!(code, 2);

    std::fs::remove_dir_all(&dir).ok();
}

// --- fuzzing the verifier's input (gap 13.10, run 1 of 2–3) -----------------
//
// Property-based, not coverage-guided: random bytes and one-byte changes of a
// real export. What must hold: the verifier never panics, never accepts
// noise, and accepts a changed export only if it still says the same thing.

fn light_export() -> &'static (Vec<u8>, KeySet) {
    static E: std::sync::OnceLock<(Vec<u8>, KeySet)> = std::sync::OnceLock::new();
    E.get_or_init(|| export_bytes(Class::Light))
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(512))]

    #[test]
    fn noise_is_never_accepted(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..2048)) {
        let (_, keys) = light_export();
        let r = verify_bytes(&bytes, &expected(Class::Light, keys.clone(), &NoReader));
        proptest::prop_assert!(!r.accepted);
    }

    #[test]
    fn a_changed_byte_is_accepted_only_if_nothing_changed(
        at in proptest::prelude::any::<proptest::sample::Index>(),
        to in proptest::prelude::any::<u8>(),
    ) {
        let (bytes, keys) = light_export();
        let mut changed = bytes.clone();
        let i = at.index(changed.len());
        proptest::prop_assume!(changed[i] != to);
        changed[i] = to;
        let r = verify_bytes(&changed, &expected(Class::Light, keys.clone(), &NoReader));
        if r.accepted {
            let a: serde_json::Value = serde_json::from_slice(bytes).unwrap();
            let b: serde_json::Value = serde_json::from_slice(&changed).unwrap();
            proptest::prop_assert_eq!(a, b, "a changed export was accepted (byte {})", i);
        }
    }
}

/// `Bare_v2_spec` K2: a `bare` journal is never anchored — an export that
/// carries anchors is refused when checked as `bare`.
#[test]
fn a_bare_export_with_anchors_is_refused() {
    // A local journal, as a `bare` keeps, with one anchor slipped in.
    let (bytes, keys) = export_bytes(Class::Light);
    let mut x: BoundExport = serde_json::from_slice(&bytes).unwrap();
    let pro: BoundExport = serde_json::from_slice(&export_bytes(Class::Heavy).0).unwrap();
    x.anchors = pro.anchors[..1].to_vec();
    let bytes = serde_json::to_vec(&x).unwrap();
    let r = verify_bytes(&bytes, &expected(Class::Bare, keys, &Net));
    assert!(!r.accepted);
    assert!(
        r.reason.as_deref().unwrap_or("").contains("never anchored"),
        "{:?}",
        r.reason
    );
}

/// `Bare_v2_spec` §9, `[decision]` 09.10: a `bare` file is not checked from
/// outside as a wrapper — without a post-quantum key in its claim the
/// program says NOT VERIFIABLE with exit code 3, not REJECTED.
#[test]
fn a_bare_file_is_not_verifiable_from_outside() {
    let dir = std::env::temp_dir().join(format!("ksg-verify-v2-bare-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (file, meta, ik) = (dir.join("c.ksg"), dir.join("c.json"), dir.join("ik.json"));
    std::fs::write(&file, b"a bare container's file").unwrap();
    std::fs::write(&meta, br#"{"emission":"ksg:em:000001","serial":1}"#).unwrap();
    std::fs::write(&ik, serde_json::to_vec(&[issuer().public()]).unwrap()).unwrap();
    let (code, out) = run(&[
        "--file",
        file.to_str().unwrap(),
        "--meta",
        meta.to_str().unwrap(),
        "--issuer-keys",
        ik.to_str().unwrap(),
    ]);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(code, 3, "{out}");
    assert!(out.starts_with("NOT VERIFIABLE"), "{out}");
}

/// K-12 (KS-7 §10-bis.3): a verdict that did not walk the chain is marked
/// incomplete; the status section read with its anchors is the walk.
#[test]
fn a_verdict_without_the_chain_is_marked_incomplete() {
    let (bytes, keys) = export_bytes(Class::Light);
    let r = verify_bytes(&bytes, &expected(Class::Light, keys, &NoReader));
    assert!(r.accepted);
    assert!(!r.complete);
    assert!(r.limits.contains(&ksg_verify_v2::INCOMPLETE));

    let s = serde_json::to_vec(&section().export()).unwrap();
    let issuer_keys: KeySet = [issuer().public()].into_iter().collect();
    let r = verify_bytes(&s, &expected(Class::Heavy, issuer_keys, &Net));
    assert!(r.accepted, "{:?}", r.reason);
    assert!(r.complete);
    assert!(!r.limits.contains(&ksg_verify_v2::INCOMPLETE));
}
