//! The vectors are executable: read back **from the files**, the documents
//! parse and verify to the verdicts the files state. This is how another
//! implementation uses them — it has the JSON, not our structs — so the test
//! takes the same road and never touches the generator's values.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

use serde_json::Value;

use ksg_core_v2::anchor::AttestationVerifier;
use ksg_core_v2::canonical::canonicalize;
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{KeySet, Profile};
use ksg_core_v2::doc::{
    resolve, AgentBinding, BlockAllocation, ContainerInit, Delegation, Emission, KeyInclusion,
    Serial, Timestamp,
};
use ksg_core_v2::journal::{verify_bound_read, BoundExport};
use ksg_core_v2::keychain::build_key_set;
use ksg_core_v2::section::{StatusRecord, StatusSection};
use ksg_core_v2::status::{transition, Blocked, Event, Status};
use ksg_vectors_v2::{outcome_json, VectorReader, EVENTS};

fn load(name: &str) -> Value {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(ksg_vectors_v2::VECTORS_DIR)
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(p).expect("vector file")).expect("JSON")
}

fn de<T: serde::de::DeserializeOwned>(v: &Value) -> T {
    serde_json::from_value(v.clone()).expect("the document parses")
}

#[test]
fn jcs_and_time_recompute() {
    for c in load("01_jcs.json")["cases"].as_array().unwrap() {
        let got = canonicalize(&c["input"]);
        if c["verdict"] == "accept" {
            let bytes = got.expect("canonical");
            assert_eq!(c["canonical"], String::from_utf8(bytes.clone()).unwrap());
            assert_eq!(c["sha256"], Hash::sha256(&bytes).to_multihash());
        } else {
            assert!(got.is_err(), "{c}");
        }
    }
    for c in load("02_time.json")["cases"].as_array().unwrap() {
        let got = Timestamp::parse(c["input"].as_str().unwrap());
        match c["verdict"].as_str().unwrap() {
            "accept" => assert_eq!(c["unix_ms"], got.unwrap().unix_ms()),
            _ => assert!(got.is_err(), "{c}"),
        }
    }
}

#[test]
fn the_channel_verifies_from_its_json() {
    let v = load("04_channel.json");
    let d = &v["documents"];
    let p = Profile::default();
    let em: Emission = de(&d["emission"]);
    em.validate(&p).expect("emission");
    let chain: Vec<Delegation> = de(&d["delegations"]);
    let (keys, _) = resolve(&em, &chain, &em.declared_keys(), &p).expect("chain");
    let alloc: BlockAllocation = de(&d["allocation"]);
    alloc
        .validate(&em, true, None, &keys, &p)
        .expect("allocation");
    let bind: AgentBinding = de(&d["binding"]);
    let holder: KeySet =
        de::<Vec<ksg_core_v2::crypto::sign::PublicKey>>(&v["presented_keys"]["holder"])
            .into_iter()
            .collect();
    bind.validate(&alloc, &holder, &p).expect("binding");
    let init: ContainerInit = de(&d["container_init"]);
    assert_eq!(v["derived"]["container_id"], init.container.to_multihash());
    let birth: KeySet =
        de::<Vec<ksg_core_v2::crypto::sign::PublicKey>>(&v["presented_keys"]["initiation"])
            .into_iter()
            .collect();
    let depth = u8::try_from(v["presented_keys"]["chain_depth"].as_u64().unwrap()).unwrap();
    init.validate(&em, &bind, depth, &birth, &p)
        .expect("initiation");
    assert_eq!(
        v["derived"]["binding_hash"],
        ksg_core_v2::canonical::doc_hash(&bind)
            .unwrap()
            .to_multihash()
    );
}

#[test]
fn the_key_chain_rebuilds_from_its_json() {
    let v = load("05_key_chain.json");
    let bind: AgentBinding = de(&v["binding"]);
    let inc: Vec<KeyInclusion> = de(&v["inclusions"]);
    let set = build_key_set(&bind, &inc, &Profile::default()).expect("chain");
    let kids: Vec<String> = set.keys().map(|k| k.kid.as_str().to_owned()).collect();
    assert_eq!(v["key_set"], serde_json::json!(kids));
    for c in v["cases"].as_array().unwrap() {
        let inc: Vec<KeyInclusion> = de(&c["inclusions"]);
        assert!(
            build_key_set(&bind, &inc, &Profile::default()).is_err(),
            "{}",
            c["name"]
        );
    }
}

#[test]
fn the_status_table_recomputes_and_names_every_event() {
    let v = load("08_status_table.json");
    for s in Status::all() {
        let row = &v["table"][s.number().to_string()];
        let row = row.as_object().unwrap();
        assert_eq!(row.len(), EVENTS.len(), "status {}", s.number());
        for (name, want) in row {
            let e: Event = serde_json::from_value(Value::String(name.clone())).unwrap();
            assert_eq!(&outcome_json(&transition(*s, Blocked::No, e)), want);
        }
    }
    // The event list here and the enumeration in the schema are one list.
    let schema: Value = serde_json::from_str(
        &std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schemas/status-record.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let names: Vec<Value> = EVENTS
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .collect();
    assert_eq!(schema["properties"]["event"]["enum"], Value::Array(names));
}

#[test]
fn the_status_section_replays_from_its_json() {
    let v = load("09_status_section.json");
    let p = Profile::default();
    let records = v["records"].as_array().unwrap();
    // The issuer's key signed every record: take it from the first signature
    // of the channel's emission, which the same root key signed.
    let em: Emission = de(&load("04_channel.json")["documents"]["emission"]);
    let keys = em.declared_keys();
    let first: StatusRecord = de(&records[0]["record"]);
    let mut s = StatusSection::start(
        v["emission"].as_str().unwrap(),
        Serial(v["serial"].as_u64().unwrap()),
        first,
        de(&records[0]["anchor"]),
        &keys,
        &p,
    )
    .expect("record 0");
    assert_eq!(v["section_root"], s.root().to_multihash());
    for r in &records[1..] {
        let rec: StatusRecord = de(&r["record"]);
        assert_eq!(r["hash"], rec.hash().unwrap().to_multihash());
        let e = rec.event.expect("an event after record 0");
        s.apply(e, Some(rec), Some(de(&r["anchor"])), &keys, &p)
            .expect("the next record");
    }
    assert_eq!(v["current"], s.current().number());
    let reader: &dyn AttestationVerifier = &VectorReader;
    let times = s.times(&p, Some(reader)).unwrap();
    assert_eq!(v["times"], serde_json::to_value(times).unwrap());
}

#[test]
fn the_journal_exports_verify_to_their_stated_verdicts() {
    let v = load("11_journal.json");
    let p = Profile::default();
    for c in v["cases"].as_array().unwrap() {
        let x: BoundExport = de(&c["export"]);
        let pro = c["name"].as_str().unwrap().starts_with("Pro");
        let reader: Option<&dyn AttestationVerifier> = if pro { Some(&VectorReader) } else { None };
        let got = verify_bound_read(&x, &p, reader);
        match c["result"]["verdict"].as_str().unwrap() {
            "accept" => {
                let (r, _) = got.expect("accept");
                assert_eq!(c["result"]["number"], r.number);
            }
            _ => assert_eq!(
                c["result"]["reason"],
                got.expect_err("reject").to_string(),
                "{}",
                c["name"]
            ),
        }
    }
}
