//! The Solana reader of core v2 — seals and status records: a ledger in
//! memory stands for the node.

use std::cell::RefCell;
use std::collections::BTreeMap;

use ksg_core_v2::anchor::{Attestation, AttestationVerifier};
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::doc::{Timestamp, Uri};
use ksg_verify_v2::solana::{
    find_status_forks, is_status_fork, status_commit, status_link, AnchorProof, Rpc, SolanaReader,
    StatusMemo, GENESIS, MEMO_PROGRAM, STATUS_KIND,
};
use serde_json::{json, Value};

/// Transactions by signature: (slot, payer, memo, failed).
#[derive(Default)]
struct Ledger {
    genesis: String,
    txs: RefCell<BTreeMap<String, (u64, String, String, bool)>>,
}

impl Ledger {
    fn devnet() -> Self {
        Self {
            genesis: GENESIS[1].1.into(),
            ..Self::default()
        }
    }
    fn put(&self, sig: &str, slot: u64, payer: &str, memo: &str) {
        self.txs
            .borrow_mut()
            .insert(sig.into(), (slot, payer.into(), memo.into(), false));
    }
}

impl Rpc for Ledger {
    fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        match method {
            "getGenesisHash" => Ok(json!(self.genesis)),
            "getTransaction" => {
                let sig = params[0].as_str().unwrap();
                Ok(match self.txs.borrow().get(sig) {
                    None => Value::Null,
                    Some((slot, payer, memo, failed)) => json!({
                        "slot": slot,
                        "blockTime": 1_790_000_000 + slot,
                        "meta": {"err": if *failed { json!({"InstructionError": [0, "x"]}) } else { Value::Null }},
                        "transaction": {"message": {
                            "accountKeys": [payer, MEMO_PROGRAM],
                            "instructions": [{"programIdIndex": 1, "accounts": [], "data": bs58::encode(memo).into_string()}]
                        }}
                    }),
                })
            }
            "getSignaturesForAddress" => {
                let who = params[0].as_str().unwrap();
                Ok(json!(self
                    .txs
                    .borrow()
                    .iter()
                    .filter(|(_, (_, p, _, _))| p == who)
                    .map(|(s, _)| json!({"signature": s, "err": null}))
                    .collect::<Vec<_>>()))
            }
            m => Err(format!("unknown method {m}")),
        }
    }
}

fn anchor(page: Hash, sig: &str, slot: u64, cluster: &str) -> Attestation {
    Attestation {
        kind: Uri::parse(STATUS_KIND).unwrap(),
        subject: page,
        proof: AnchorProof {
            signature: sig.into(),
            slot,
            cluster: cluster.into(),
        }
        .to_bytes()
        .unwrap(),
        anchored_at: Timestamp::parse("2026-09-24T00:00:00.000Z").unwrap(),
    }
}

#[test]
fn memo_round_trip_and_fork_rule() {
    let (prev, a, b) = (
        Hash::sha256(b"prev"),
        Hash::sha256(b"a"),
        Hash::sha256(b"b"),
    );
    let m = StatusMemo::of(&prev, &a);
    assert_eq!(StatusMemo::parse(&m.to_string()), Some(m));
    assert!(m.to_string().starts_with("ksg:st:v1 "));
    // Neither the record hash nor prev appears in the clear.
    assert!(!m.to_string().contains(&a.to_multihash()));
    assert!(!m.to_string().contains(&prev.to_multihash()));
    assert!(is_status_fork(&m, &StatusMemo::of(&prev, &b)));
    assert!(!is_status_fork(&m, &m));
    assert!(
        !is_status_fork(&m, &StatusMemo::of(&a, &b)),
        "different heads"
    );
    assert_eq!(StatusMemo::parse("hello"), None);
    assert_eq!(StatusMemo::parse(&format!("{m} extra")), None);
    assert_ne!(status_link(&a), status_commit(&a), "domain-separated");
}

#[test]
fn the_reader_confirms_a_status_record_and_names_the_moment() {
    let l = Ledger::devnet();
    let page = Hash::sha256(b"page");
    l.put(
        "S1",
        100,
        "PAYER",
        &StatusMemo::of(&Hash::sha256(b"p"), &page).to_string(),
    );
    let r = SolanaReader::connect(&l, "devnet").unwrap();
    assert!(r.handles(&Uri::parse(STATUS_KIND).unwrap()));
    let t = r.verify(&anchor(page, "S1", 100, "devnet")).unwrap();
    assert_eq!(
        t.as_str(),
        ksg_verify_v2::clock::utc((1_790_000_000 + 100) * 1000).as_str()
    );
}

#[test]
fn the_reader_refuses_what_it_cannot_confirm() {
    let l = Ledger::devnet();
    let page = Hash::sha256(b"page");
    l.put(
        "S1",
        100,
        "PAYER",
        &StatusMemo::of(&Hash::sha256(b"p"), &page).to_string(),
    );
    l.txs.borrow_mut().insert(
        "FAILED".into(),
        (
            7,
            "PAYER".into(),
            StatusMemo::of(&Hash::sha256(b"p"), &page).to_string(),
            true,
        ),
    );
    let r = SolanaReader::connect(&l, "devnet").unwrap();
    // another record
    assert!(r
        .verify(&anchor(Hash::sha256(b"other"), "S1", 100, "devnet"))
        .is_err());
    // a slot rewritten
    assert!(r.verify(&anchor(page, "S1", 101, "devnet")).is_err());
    // no such transaction
    assert!(r.verify(&anchor(page, "S9", 100, "devnet")).is_err());
    // a failed transaction carries the memo and proves nothing
    assert!(r.verify(&anchor(page, "FAILED", 7, "devnet")).is_err());
    // another cluster, declared by the anchor
    assert!(r.verify(&anchor(page, "S1", 100, "mainnet-beta")).is_err());
    // proof bytes that are not an anchor proof
    let mut a = anchor(page, "S1", 100, "devnet");
    a.proof = b"local".to_vec();
    assert!(r.verify(&a).is_err());
}

#[test]
fn a_node_of_another_cluster_is_not_connected() {
    let l = Ledger::devnet();
    assert!(SolanaReader::connect(&l, "mainnet-beta").is_err());
    assert!(SolanaReader::connect(&l, "moonnet").is_err());
}

#[test]
fn a_rival_status_record_after_the_same_head_is_found() {
    use ksg_core_v2::crypto::sign::{sign_doc, Ed25519Signer, SignatureSet};
    use ksg_core_v2::doc::{Context, Serial};
    use ksg_core_v2::section::{section_root, StatusExport, StatusRecord};
    use ksg_core_v2::status::Status;
    let l = Ledger::devnet();
    let issuer =
        Ed25519Signer::from_seed(Uri::parse("did:web:issuer.example#k1").unwrap(), [7; 32]);
    let root = section_root("ksg:em:000001", Serial(7));
    let doc = StatusRecord {
        context: Context,
        doc_type: "StatusRecord".into(),
        v: 3,
        number: 0,
        status: Status::Printed,
        event: None,
        offset_ms: 1,
        prev: root,
        signatures: SignatureSet::default(),
    };
    let record = StatusRecord {
        signatures: SignatureSet::new(vec![sign_doc(&doc, &issuer).unwrap()]),
        ..doc
    };
    let h = record.hash().unwrap();
    l.put("S1", 10, "PAYER", &StatusMemo::of(&root, &h).to_string());
    let x = StatusExport {
        context: Context,
        doc_type: StatusExport::TYPE.into(),
        emission: "ksg:em:000001".into(),
        serial: Serial(7),
        records: vec![(record, anchor(h, "S1", 10, "devnet"))],
    };
    assert!(find_status_forks(&l, &x, 100).unwrap().is_empty());
    // The same payer anchors another record 0 of the same section: a
    // rewritten status history.
    l.put(
        "S2",
        11,
        "PAYER",
        &StatusMemo::of(&root, &Hash::sha256(b"rival")).to_string(),
    );
    // Somebody else's memo does not count.
    l.put("S3", 12, "PAYER", "gm");
    let forks = find_status_forks(&l, &x, 100).unwrap();
    assert_eq!(forks.len(), 1);
    assert_eq!((forks[0].number, forks[0].signature.as_str()), (0, "S2"));
}

/// Reads real devnet: the node's genesis and the newest memo transaction.
/// `cargo test -p ksg-verify-v2 --test solana -- --ignored`
#[cfg(feature = "rpc")]
#[test]
#[ignore = "goes to the network"]
fn live_devnet_read() {
    use ksg_verify_v2::solana::{check_cluster, get_transaction, signatures_for, HttpRpc};
    let rpc = HttpRpc::new("https://api.devnet.solana.com").unwrap();
    check_cluster(&rpc, "devnet").unwrap();
    let sigs = signatures_for(&rpc, MEMO_PROGRAM, None, 5).unwrap();
    assert!(!sigs.is_empty());
    let found = sigs
        .iter()
        .filter_map(|s| get_transaction(&rpc, s).ok().flatten())
        .find(|t| !t.memos.is_empty());
    let tx = found.expect("a memo transaction among the newest");
    eprintln!(
        "slot {} payer {} memo {:?}",
        tx.slot, tx.fee_payer, tx.memos[0]
    );
}

fn seal_anchor(subject: Hash, sig: &str, slot: u64) -> Attestation {
    let mut a = anchor(subject, sig, slot, "devnet");
    a.kind = Uri::parse(ksg_verify_v2::solana::SEAL_KIND).unwrap();
    a
}

/// `[decision]` 13.09: an observer sees that an anchor exists and nothing
/// else. The seal memo carries neither the seal nor its predecessor, is of one
/// length, and without the holder's scan key nobody links two memos.
#[test]
fn a_seal_memo_is_blind_without_the_scan_key() {
    use ksg_verify_v2::solana::{SealMemo, SealScanKey};
    let k = SealScanKey::new([7; 32]);
    let other = SealScanKey::new([8; 32]);
    let (id, s1, s2) = (
        Hash::sha256(b"id"),
        Hash::sha256(b"s1"),
        Hash::sha256(b"s2"),
    );
    let m1 = SealMemo::of(&k, &id, &s1);
    let m2 = SealMemo::of(&k, &s1, &s2);
    assert_eq!(SealMemo::parse(&m1.to_string()), Some(m1));
    assert_eq!(m1.to_string().len(), m2.to_string().len());
    for m in [m1.to_string(), m2.to_string()] {
        for h in [id, s1, s2] {
            assert!(!m.contains(&h.to_multihash()));
            assert!(!m.contains(&h.to_multihash()[4..20]));
        }
    }
    // An open memo joins: record N's commit input is record N+1's link input.
    // Here m1's commit and m2's link are different values of one hash.
    assert_ne!(m1.commit, m2.link);
    // Another key, other values: the series is the key holder's.
    assert_ne!(SealMemo::of(&other, &id, &s1), m1);
    assert_eq!(SealMemo::parse("ksg:bs:v1 00 11"), None, "wrong width");
    assert_eq!(SealMemo::parse(&format!("{m1} x")), None);
    // The key file round-trips and prints nothing.
    assert_eq!(SealScanKey::from_hex(&k.to_hex()).unwrap(), k);
    assert_eq!(format!("{k:?}"), "SealScanKey(…)");
    assert!(SealScanKey::from_hex("zz").is_err());
}

#[test]
fn the_reader_confirms_a_blind_seal_only_with_the_scan_key() {
    use ksg_verify_v2::solana::{SealMemo, SealScanKey};
    let l = Ledger::devnet();
    let k = SealScanKey::new([7; 32]);
    let seal = Hash::sha256(b"seal");
    l.put(
        "S1",
        100,
        "PAYER",
        &SealMemo::of(&k, &Hash::sha256(b"prev"), &seal).to_string(),
    );
    let blind = SolanaReader::connect(&l, "devnet").unwrap();
    assert!(blind.handles(&Uri::parse(ksg_verify_v2::solana::SEAL_KIND).unwrap()));
    assert!(blind.verify(&seal_anchor(seal, "S1", 100)).is_err());
    let r = SolanaReader::connect(&l, "devnet")
        .unwrap()
        .with_scan_key(k.clone());
    assert!(r.verify(&seal_anchor(seal, "S1", 100)).is_ok());
    assert!(r
        .verify(&seal_anchor(Hash::sha256(b"x"), "S1", 100))
        .is_err());
    let wrong = SolanaReader::connect(&l, "devnet")
        .unwrap()
        .with_scan_key(SealScanKey::new([9; 32]));
    assert!(wrong.verify(&seal_anchor(seal, "S1", 100)).is_err());
}

/// A local node (`solana-test-validator`) is connected only when named, and
/// a public cluster cannot be passed off as one; anchors declared for a
/// public cluster do not verify on it.
#[test]
fn a_local_node_is_connected_only_as_localnet() {
    use ksg_verify_v2::solana::{check_cluster, LOCALNET};
    let local = Ledger {
        genesis: "7nYiZf1CbH1yYGZeGMAvMNbJVNZKbtsaVEemSZvEMDYP".into(),
        ..Ledger::default()
    };
    check_cluster(&local, LOCALNET).unwrap();
    // A local node is no public cluster.
    assert!(check_cluster(&local, "devnet").is_err());
    assert!(check_cluster(&local, "mainnet-beta").is_err());
    // A public cluster is not a local node.
    let err = check_cluster(&Ledger::devnet(), LOCALNET).unwrap_err();
    assert!(err.contains("devnet"), "{err}");
    // An anchor of the local node verifies only as the local node's.
    let page = Hash::sha256(b"page");
    local.put(
        "S1",
        100,
        "PAYER",
        &StatusMemo::of(&Hash::sha256(b"p"), &page).to_string(),
    );
    let r = SolanaReader::connect(&local, LOCALNET).unwrap();
    r.verify(&anchor(page, "S1", 100, LOCALNET)).unwrap();
    assert!(r.verify(&anchor(page, "S1", 100, "devnet")).is_err());
}

/// §10.2 (KS-7): only hashes go to the chain — a memo is its tag and two
/// words derived from hashes (16 bytes each in the blind seal memo,
/// multihashes in the open status memo), whatever the page held.
#[test]
fn a_memo_carries_a_tag_and_two_words_and_nothing_of_the_page() {
    use ksg_core_v2::crypto::hash::Hash;
    use ksg_verify_v2::solana::{SealMemo, SealScanKey, StatusMemo};
    let secret = b"the text of the page, which must never reach the chain";
    let page = Hash::sha256(secret);
    let prev = Hash::sha256(b"the seal before");
    for memo in [
        SealMemo::of(&SealScanKey::new([9; 32]), &prev, &page).to_string(),
        StatusMemo::of(&prev, &page).to_string(),
    ] {
        let parts: Vec<&str> = memo.split(' ').collect();
        assert_eq!(parts.len(), 3, "{memo}");
        assert!(parts[0].starts_with("ksg:"), "{memo}");
        for w in &parts[1..] {
            let blind = w.len() == 32;
            let multihash = w.len() == 68 && w.starts_with("1220");
            assert!(blind || multihash, "{memo}");
            assert!(w.bytes().all(|c| c.is_ascii_hexdigit()), "{memo}");
        }
        assert!(!memo.contains("page"), "{memo}");
    }
}
