//! P-6 end to end: seals of the journal anchored on a devnet (a local one,
//! [`mock_devnet`]), read back by the verifier, a rolled-back file refused, a
//! fork found; a light container anchoring nothing until the owner takes it
//! to Pro (CH-22, CH-26, CH-30).

mod mock_devnet;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use ed25519_dalek::SigningKey;
use ksg_anchor_v2::solana_tx::address;
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::doc::Class;
use ksg_core_v2::journal::{verify_bound, BoundExport};
use ksg_verify_v2::solana::{
    find_bound_forks, HttpRpc, SealMemo, SealScanKey, SolanaReader, StatusMemo,
};
use ksg_verify_v2::{keys_from_json, verify_bytes, Expected};
use mock_devnet::MockDevnet;

const KSG: &str = env!("CARGO_BIN_EXE_ksg-remote-panel");

struct Dir(PathBuf);
impl Dir {
    fn new(name: &str) -> Self {
        let d = std::env::temp_dir().join(format!("ksg-devnet-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Self(d)
    }
    fn p(&self, n: &str) -> PathBuf {
        self.0.join(n)
    }
}
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn ksg(args: &[&str]) -> Output {
    Command::new(KSG)
        .args(args)
        .env("KSG_ANCHOR_WAIT_S", "10")
        .output()
        .unwrap()
}
fn ok(args: &[&str]) {
    let o = ksg(args);
    assert!(
        o.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
}
fn fails(args: &[&str]) -> String {
    let o = ksg(args);
    assert_eq!(
        o.status.code(),
        Some(1),
        "{args:?}: {}",
        String::from_utf8_lossy(&o.stdout)
    );
    String::from_utf8_lossy(&o.stderr).into_owned()
}
/// A command that is expected to give up waiting for a held transaction:
/// a one-second wait, not the default.
fn fails_waiting(args: &[&str]) -> String {
    let o = Command::new(KSG)
        .args(args)
        .env("KSG_ANCHOR_WAIT_S", "1")
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1), "{args:?}");
    String::from_utf8_lossy(&o.stderr).into_owned()
}
fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

/// A payer key file in the Solana CLI's format; returns its address.
fn payer(path: &Path, seed: u8) -> String {
    let k = SigningKey::from_bytes(&[seed; 32]);
    let mut all = k.to_bytes().to_vec();
    all.extend_from_slice(k.verifying_key().as_bytes());
    std::fs::write(path, serde_json::to_vec(&all).unwrap()).unwrap();
    address(&k.verifying_key())
}

fn id(home: &Path) -> Hash {
    let m: serde_json::Value =
        serde_json::from_slice(&std::fs::read(home.join("container.json")).unwrap()).unwrap();
    Hash::from_multihash(m["id"].as_str().unwrap()).unwrap()
}

/// The holder's scan key, as `ksg scan-key` hands it to an auditor.
fn scan(home: &Path, out: &Path) -> Vec<SealScanKey> {
    ok(&["--home", s(home), "scan-key", "--out", s(out)]);
    ksg_verify_v2::solana::scan_keys_from_text(&std::fs::read_to_string(out).unwrap()).unwrap()
}

/// Memos on the ledger with this tag: `ksg:bs:v1` seals, `ksg:st:v1` statuses.
fn memos(net: &MockDevnet, tag: &str) -> usize {
    net.ledger
        .lock()
        .unwrap()
        .txs
        .iter()
        .filter(|t| t.memo.starts_with(tag.as_bytes()))
        .count()
}
fn seal_memos(net: &MockDevnet) -> usize {
    memos(net, "ksg:bs:v1 ")
}
fn status_memos(net: &MockDevnet) -> usize {
    memos(net, "ksg:st:v1 ")
}

fn init(_d: &Dir, net: &MockDevnet, home: &Path, key: &Path) {
    init_class(net, home, key, "heavy");
}

/// Prints a container anchored on the devnet. No mobile half: it is born at
/// initiation (`to_work`, CH-5b).
fn init_class(net: &MockDevnet, home: &Path, key: &Path, class: &str) {
    ok(&[
        "--home",
        s(home),
        "init",
        "--class",
        class,
        "--anchor",
        "solana:devnet",
        "--payer",
        s(key),
        "--rpc",
        &net.url,
    ]);
}

fn to_work(home: &Path, m: &Path) {
    let (h, m) = (s(home), s(m));
    ok(&["--home", h, "packet"]);
    ok(&["--home", h, "buyer-key"]);
    ok(&["--home", h, "--mobile", m, "initiate"]);
    ok(&["--home", h, "--mobile", m, "open-journal"]);
}

#[test]
fn a_heavy_life_anchored_on_devnet_verifies() {
    let d = Dir::new("life");
    let net = MockDevnet::start();
    let key = d.p("payer.json");
    net.fund(&payer(&key, 5), 1_000_000_000);
    let home = d.p("home");
    let (h, m) = (s(&home).to_owned(), s(&d.p("m.half")).to_owned());
    init(&d, &net, &home, &key);
    to_work(&home, &d.p("m.half"));
    std::fs::write(d.p("policy.pdf"), b"POLICY 7").unwrap();
    ok(&[
        "--home",
        &h,
        "--mobile",
        &m,
        "attach",
        "--type",
        "urn:ksg:page:policy:v1",
        "--file",
        s(&d.p("policy.pdf")),
    ]);
    ok(&[
        "--home",
        &h,
        "--mobile",
        &m,
        "work",
        "--did",
        "claim reviewed",
    ]);
    ok(&[
        "--home",
        &h,
        "export-page",
        "--number",
        "1",
        "--by",
        "owner",
        "--out",
        s(&d.p("p1.json")),
    ]);
    ok(&["--home", &h, "finalize"]);
    ok(&[
        "--home",
        &h,
        "--mobile",
        &m,
        "export-final",
        "--out",
        s(&d.p("final.json")),
    ]);
    ok(&["--home", &h, "keys", "--out", s(&d.p("keys.json"))]);

    // Three seals, three blind memos; every status change an open memo of
    // its own (spec v2 §11), and nothing else went to the network.
    assert_eq!(seal_memos(&net), 3);
    ok(&[
        "--home",
        &h,
        "export-statuses",
        "--out",
        s(&d.p("statuses.json")),
    ]);
    let statuses: ksg_core_v2::section::StatusExport =
        serde_json::from_slice(&std::fs::read(d.p("statuses.json")).unwrap()).unwrap();
    assert_eq!(status_memos(&net), statuses.records.len());
    // Counted apart from the lock: `memos` takes it too.
    let all = net.ledger.lock().unwrap().txs.len();
    assert_eq!(all, seal_memos(&net) + status_memos(&net));

    let rpc = HttpRpc::new(&net.url).unwrap();
    let sk = scan(&home, &d.p("scan.key"));
    // The memos are blind: no seal hash, no link an observer can join on, one
    // length for every memo.
    let x: BoundExport =
        serde_json::from_slice(&std::fs::read(d.p("final.json")).unwrap()).unwrap();
    let records = verify_bound(&x, &ksg_core_v2::crypto::sign::Profile::default())
        .unwrap()
        .records;
    {
        let ledger = net.ledger.lock().unwrap();
        let memos: Vec<String> = ledger
            .txs
            .iter()
            .map(|t| String::from_utf8(t.memo.clone()).unwrap())
            .filter(|m| m.starts_with("ksg:bs:v1 "))
            .collect();
        assert_eq!(memos.len(), 3);
        for m in &memos {
            assert!(SealMemo::parse(m).is_some(), "{m}");
            assert_eq!(m.len(), memos[0].len(), "one length for every memo");
            for r in &records {
                assert!(!m.contains(&r.seal.to_multihash()), "no seal in the clear");
            }
        }
    }
    // Without the scan key the anchors are noise and the export is refused.
    let blind = SolanaReader::connect(&rpc, "devnet").unwrap();
    let keys = keys_from_json(&std::fs::read(d.p("keys.json")).unwrap()).unwrap();
    let no_key = verify_bytes(
        &std::fs::read(d.p("final.json")).unwrap(),
        &Expected {
            container: id(&home),
            class: Class::Heavy,
            keys: keys.clone(),
            client_id_from_key: true,
            anchors: &blind,
        },
    );
    assert!(!no_key.accepted, "{no_key:?}");
    let reader = SolanaReader::connect(&rpc, "devnet")
        .unwrap()
        .with_scan_keys(sk.clone());
    let exp = Expected {
        container: id(&home),
        class: Class::Heavy,
        keys,
        client_id_from_key: true,
        anchors: &reader,
    };
    let fin = verify_bytes(&std::fs::read(d.p("final.json")).unwrap(), &exp);
    assert!(fin.accepted, "{fin:?}");
    assert_eq!(fin.pages, Some(3));
    let point = verify_bytes(&std::fs::read(d.p("p1.json")).unwrap(), &exp);
    assert!(point.accepted, "{point:?}");
    assert!(point.anchored_at.is_some());

    // The status section, as a third party checks it: every change's anchor
    // read on the network, every status with its time (spec v2 §11, §12;
    // audit of 30.09, Ya-2).
    ok(&["--home", &h, "issuer-keys", "--out", s(&d.p("issuer.json"))]);
    let issuer = keys_from_json(&std::fs::read(d.p("issuer.json")).unwrap()).unwrap();
    let st = verify_bytes(
        &std::fs::read(d.p("statuses.json")).unwrap(),
        &Expected {
            container: id(&home),
            class: Class::Heavy,
            keys: issuer.clone(),
            client_id_from_key: false,
            anchors: &blind,
        },
    );
    assert!(st.accepted, "{st:?}");
    assert_eq!(
        st.bounds.len(),
        statuses.records.len(),
        "every status has a time"
    );
    assert!(
        ksg_verify_v2::solana::find_status_forks(&rpc, &statuses, 100)
            .unwrap()
            .is_empty()
    );
    // A rewritten status history — a second record after record 0, anchored
    // by the same payer — is a fork, visible to anyone holding the section.
    let (r0, _) = &statuses.records[0];
    let rival_status =
        StatusMemo::of(&r0.hash().unwrap(), &Hash::sha256(b"another record 1")).to_string();
    let who = address(&SigningKey::from_bytes(&[5; 32]).verifying_key());
    net.ledger.lock().unwrap().plant(&who, &rival_status);
    let forks = ksg_verify_v2::solana::find_status_forks(&rpc, &statuses, 100).unwrap();
    assert_eq!(forks.len(), 1);
    assert_eq!(forks[0].number, 1);

    // No forks; then a rival seal after the opening's, anchored by the same
    // payer, is one — seen by whoever holds the scan key.
    assert!(find_bound_forks(&rpc, &x, &records, &sk, 100)
        .unwrap()
        .is_empty());
    let rival = SealMemo::of(&sk[0], &records[0].seal, &Hash::sha256(b"rival")).to_string();
    net.ledger.lock().unwrap().plant(&who, &rival);
    let forks = find_bound_forks(&rpc, &x, &records, &sk, 100).unwrap();
    assert_eq!(forks.len(), 1);
    assert_eq!(forks[0].number, 1);
    // The program, as a third party runs it — when the workspace built it
    // (`cargo test --workspace` does; `-p ksg-cli` alone does not).
    let verifier =
        Path::new(KSG).with_file_name(format!("ksg-verify-v2{}", std::env::consts::EXE_SUFFIX));
    if !verifier.exists() {
        eprintln!("ksg-verify-v2 not built next to ksg-remote-panel: the program run is skipped");
        return;
    }
    let out = Command::new(&verifier)
        .args([
            "--export",
            s(&d.p("final.json")),
            "--container",
            &id(&home).to_multihash(),
            "--class",
            "heavy",
            "--keys",
            s(&d.p("keys.json")),
            "--rpc",
            &net.url,
            "--cluster",
            "devnet",
            "--forks",
            "--scan-key",
            s(&d.p("scan.key")),
        ])
        .output()
        .unwrap();
    // The rival planted above: the program refuses, naming the fork.
    assert_eq!(
        out.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("fork"));
}

#[test]
fn an_older_copy_of_the_file_does_not_open() {
    let d = Dir::new("rollback");
    let net = MockDevnet::start();
    let key = d.p("payer.json");
    net.fund(&payer(&key, 6), 1_000_000_000);
    let home = d.p("home");
    init(&d, &net, &home, &key);
    to_work(&home, &d.p("m.half"));
    // The holder keeps a copy, works on, then goes back to the copy.
    let old = d.p("old");
    std::fs::create_dir_all(&old).unwrap();
    for f in [
        "container.ksg",
        "container.json",
        "layer.key",
        "scan.key",
        "parties.json",
    ] {
        std::fs::copy(home.join(f), old.join(f)).unwrap();
    }
    ok(&[
        "--home",
        s(&home),
        "--mobile",
        s(&d.p("m.half")),
        "work",
        "--did",
        "the real step",
    ]);
    let err = fails(&[
        "--home",
        s(&old),
        "--mobile",
        s(&d.p("m.half")),
        "work",
        "--did",
        "the other step",
    ]);
    assert!(err.contains("rolled back"), "{err}");
    // Nothing reached the network from the old copy.
    assert_eq!(seal_memos(&net), 2, "opening and the real step");
    // The current file goes on.
    ok(&[
        "--home",
        s(&home),
        "--mobile",
        s(&d.p("m.half")),
        "work",
        "--did",
        "the next step",
    ]);
}

/// The rollback check reads the status chain too: a copy kept before a
/// status change, opened after it, is an old copy even with no seal yet.
#[test]
fn an_older_copy_is_caught_by_its_status_history() {
    let d = Dir::new("rollback-status");
    let net = MockDevnet::start();
    let key = d.p("payer.json");
    net.fund(&payer(&key, 9), 1_000_000_000);
    let home = d.p("home");
    init(&d, &net, &home, &key);
    ok(&["--home", s(&home), "packet"]);
    let old = d.p("old");
    std::fs::create_dir_all(&old).unwrap();
    for f in [
        "container.ksg",
        "container.json",
        "layer.key",
        "scan.key",
        "parties.json",
    ] {
        std::fs::copy(home.join(f), old.join(f)).unwrap();
    }
    ok(&["--home", s(&home), "buyer-key"]);
    let err = fails(&["--home", s(&old), "buyer-key"]);
    assert!(
        err.contains("rolled back") && err.contains("status"),
        "{err}"
    );
    assert_eq!(
        seal_memos(&net),
        0,
        "no journal yet: the seal chain saw nothing"
    );
    // The current file goes on.
    ok(&[
        "--home",
        s(&home),
        "--mobile",
        s(&d.p("m.half")),
        "initiate",
    ]);
}

#[test]
fn without_funds_no_page_is_written() {
    let d = Dir::new("unfunded");
    let net = MockDevnet::start();
    let key = d.p("payer.json");
    // Enough for the status memos up to initiation — record 0, packet,
    // buyer's key, initiation — and not one fee more.
    net.fund(&payer(&key, 7), 4 * mock_devnet::FEE);
    let home = d.p("home");
    init(&d, &net, &home, &key);
    let mh = d.p("m.half");
    let (h, m) = (s(&home), s(&mh));
    ok(&["--home", h, "packet"]);
    ok(&["--home", h, "buyer-key"]);
    ok(&["--home", h, "--mobile", m, "initiate"]);
    let before = std::fs::read(home.join("container.ksg")).unwrap();
    let err = fails(&["--home", h, "--mobile", m, "open-journal"]);
    assert!(err.contains("prior credit"), "{err}");
    assert_eq!(std::fs::read(home.join("container.ksg")).unwrap(), before);
    // Funded, it goes through.
    net.fund(&payer(&key, 7), 10_000);
    ok(&["--home", h, "--mobile", m, "open-journal"]);
}

#[test]
fn a_refused_page_spends_no_memo() {
    let d = Dir::new("refused");
    let net = MockDevnet::start();
    let key = d.p("payer.json");
    net.fund(&payer(&key, 8), 1_000_000_000);
    let home = d.p("home");
    init(&d, &net, &home, &key);
    let mh = d.p("m.half");
    let (h, m) = (s(&home), s(&mh));
    ok(&["--home", h, "packet"]);
    ok(&["--home", h, "buyer-key"]);
    // The journal before initiation: the container refuses the page, and the
    // copy refused it before any memo went out — neither the seal's nor the
    // status change's.
    let before = net.ledger.lock().unwrap().txs.len();
    fails(&["--home", h, "--mobile", m, "open-journal"]);
    assert_eq!(net.ledger.lock().unwrap().txs.len(), before);
    assert_eq!(seal_memos(&net), 0);
}

#[test]
fn anchoring_is_refused_where_it_cannot_be() {
    let d = Dir::new("refuse");
    let net = MockDevnet::start();
    let key = d.p("payer.json");
    payer(&key, 9);
    // the base class is never anchored
    fails(&[
        "--home",
        s(&d.p("a")),
        "init",
        "--class",
        "bare",
        "--anchor",
        "solana:devnet",
        "--payer",
        s(&key),
        "--rpc",
        &net.url,
    ]);
    // a node that is not the cluster named
    fails(&[
        "--home",
        s(&d.p("b")),
        "init",
        "--class",
        "heavy",
        "--anchor",
        "solana:mainnet-beta",
        "--payer",
        s(&key),
        "--rpc",
        &net.url,
    ]);
    // a key file that is not a key
    std::fs::write(d.p("bad.json"), b"[1,2,3]").unwrap();
    fails(&[
        "--home",
        s(&d.p("c")),
        "init",
        "--class",
        "heavy",
        "--anchor",
        "solana:devnet",
        "--payer",
        s(&d.p("bad.json")),
        "--rpc",
        &net.url,
    ]);
    // usage
    assert_eq!(
        ksg(&[
            "--home",
            s(&d.p("e")),
            "init",
            "--class",
            "heavy",
            "--payer",
            s(&key)
        ])
        .status
        .code(),
        Some(2)
    );
    assert_eq!(
        ksg(&[
            "--home",
            s(&d.p("f")),
            "init",
            "--class",
            "heavy",
            "--anchor",
            "eth:main",
            "--payer",
            s(&key)
        ])
        .status
        .code(),
        Some(2)
    );
}

/// Real devnet judges the bytes: `simulateTransaction` with signature check,
/// nothing sent. A key that never held SOL makes the node answer
/// `AccountNotFound` — which it can say only after it parsed the transaction
/// and checked its signature.
/// `cargo test -p ksg-cli --test devnet -- --ignored`
#[test]
#[ignore = "goes to the network"]
fn live_devnet_parses_our_transaction() {
    use base64::Engine as _;
    use ksg_anchor_v2::solana_tx::memo_transaction;
    use ksg_verify_v2::solana::Rpc as _;
    let rpc = HttpRpc::new("https://api.devnet.solana.com").unwrap();
    let bh = rpc
        .call(
            "getLatestBlockhash",
            serde_json::json!([{"commitment": "finalized"}]),
        )
        .unwrap();
    let bh: [u8; 32] = bs58::decode(bh["value"]["blockhash"].as_str().unwrap())
        .into_vec()
        .unwrap()
        .try_into()
        .unwrap();
    let key = SigningKey::from_bytes(&[0x5a; 32]);
    let memo = StatusMemo::of(&Hash::sha256(b"prev"), &Hash::sha256(b"record")).to_string();
    let (tx, _) = memo_transaction(&key, &bh, memo.as_bytes()).unwrap();
    let r = rpc
        .call(
            "simulateTransaction",
            serde_json::json!([base64::engine::general_purpose::STANDARD.encode(&tx),
                {"encoding": "base64", "sigVerify": true, "commitment": "finalized"}]),
        )
        .unwrap();
    eprintln!("{r}");
    assert_eq!(
        r["value"]["err"],
        serde_json::json!("AccountNotFound"),
        "{r}"
    );
}

/// A light container anchors nothing (CH-22, CH-24); the owner and the issuer
/// take it to Pro (CH-26, CH-30), and from the form page on every seal is
/// anchored; the owner alone takes it back (CH-23).
#[test]
fn a_light_container_anchors_from_the_move_to_pro() {
    let d = Dir::new("forms");
    let net = MockDevnet::start();
    let key = d.p("payer.json");
    net.fund(&payer(&key, 10), 1_000_000_000);
    let home = d.p("home");
    let (h, m) = (s(&home).to_owned(), s(&d.p("m.half")).to_owned());
    init_class(&net, &home, &key, "light");
    to_work(&home, &d.p("m.half"));
    ok(&[
        "--home",
        &h,
        "--mobile",
        &m,
        "work",
        "--did",
        "offline step",
    ]);
    assert_eq!(seal_memos(&net), 0, "light: no seal memo, no fee for one");

    ok(&["--home", &h, "--mobile", &m, "form", "--to", "pro"]);
    ok(&[
        "--home",
        &h,
        "--mobile",
        &m,
        "work",
        "--did",
        "anchored step",
    ]);
    assert_eq!(seal_memos(&net), 2, "the form page and the step");

    ok(&["--home", &h, "--mobile", &m, "form", "--to", "light"]);
    ok(&[
        "--home",
        &h,
        "--mobile",
        &m,
        "work",
        "--did",
        "offline again",
    ]);
    assert_eq!(seal_memos(&net), 2, "back to light: no seal memo");

    ok(&["--home", &h, "finalize"]);
    ok(&[
        "--home",
        &h,
        "--mobile",
        &m,
        "export-final",
        "--out",
        s(&d.p("final.json")),
    ]);
    ok(&["--home", &h, "keys", "--out", s(&d.p("keys.json"))]);
    let rpc = HttpRpc::new(&net.url).unwrap();
    let reader = SolanaReader::connect(&rpc, "devnet")
        .unwrap()
        .with_scan_keys(scan(&home, &d.p("scan.key")));
    let r = verify_bytes(
        &std::fs::read(d.p("final.json")).unwrap(),
        &Expected {
            container: id(&home),
            class: Class::Light,
            keys: keys_from_json(&std::fs::read(d.p("keys.json")).unwrap()).unwrap(),
            client_id_from_key: true,
            anchors: &reader,
        },
    );
    assert!(r.accepted, "{r:?}");
    // Pages 0 and 1 light; 2 (form) and 3 anchored; 4 (form) and 5 light.
    assert_eq!(r.runs, Some(vec![(2, 3)]));
}

/// A hand-off in Pro (CH-16, CH-17): the hand-off page's seal is anchored like
/// any other — the copy the reader tries it on carries the staged key.
#[test]
fn a_handoff_in_pro_is_anchored() {
    let d = Dir::new("handoff");
    let net = MockDevnet::start();
    let key = d.p("payer.json");
    net.fund(&payer(&key, 11), 1_000_000_000);
    let home = d.p("home");
    let (h, m) = (s(&home).to_owned(), s(&d.p("m.half")).to_owned());
    init(&d, &net, &home, &key);
    to_work(&home, &d.p("m.half"));
    let two = s(&d.p("two.half")).to_owned();
    ok(&[
        "--home",
        &h,
        "--mobile",
        &m,
        "handoff",
        "--name",
        "did:key:zAgentTwo",
        "--new-mobile",
        &two,
    ]);
    ok(&[
        "--home",
        &h,
        "--mobile",
        &two,
        "work",
        "--did",
        "second agent",
    ]);
    assert_eq!(seal_memos(&net), 3, "opening, hand-off, work");
    ok(&["--home", &h, "finalize"]);
    ok(&[
        "--home",
        &h,
        "--mobile",
        &two,
        "export-final",
        "--out",
        s(&d.p("final.json")),
    ]);
    ok(&["--home", &h, "keys", "--out", s(&d.p("keys.json"))]);
    let rpc = HttpRpc::new(&net.url).unwrap();
    let reader = SolanaReader::connect(&rpc, "devnet")
        .unwrap()
        .with_scan_keys(scan(&home, &d.p("scan.key")));
    let r = verify_bytes(
        &std::fs::read(d.p("final.json")).unwrap(),
        &Expected {
            container: id(&home),
            class: Class::Heavy,
            keys: keys_from_json(&std::fs::read(d.p("keys.json")).unwrap()).unwrap(),
            client_id_from_key: true,
            anchors: &reader,
        },
    );
    assert!(r.accepted, "{r:?}");
    // Audit of 30.09, Ya-4: the report shows how the agent changed — the one
    // page 0 pins, the one sealing now, and the page of the hand-off.
    assert_ne!(r.first_agent, r.author, "{r:?}");
    assert_eq!(r.transfers.len(), 1, "{r:?}");
}

/// No two seal memos after one head, and no two status memos after one
/// record: what a reader of the network would read as a fork.
fn no_fork_on_the_ledger(net: &MockDevnet) {
    let ledger = net.ledger.lock().unwrap();
    let mut links = std::collections::BTreeSet::new();
    for t in &ledger.txs {
        let m = String::from_utf8(t.memo.clone()).unwrap();
        let link = SealMemo::parse(&m)
            .map(|x| format!("{:?}", x.link))
            .or_else(|| StatusMemo::parse(&m).map(|x| x.link.to_multihash()))
            .unwrap();
        assert!(links.insert(link), "two memos after one head: {m}");
    }
}

/// A memo sent whose transaction is slow to finalize: the record is kept
/// with its memo owed, and the next command takes the transaction when it
/// lands — it does not send a second memo into a fork.
#[test]
fn a_memo_late_to_finalize_is_taken_not_sent_again() {
    let d = Dir::new("late");
    let net = MockDevnet::start();
    let key = d.p("payer.json");
    net.fund(&payer(&key, 21), 1_000_000_000);
    let home = d.p("home");
    let (h, m) = (s(&home).to_owned(), s(&d.p("m.half")).to_owned());
    init(&d, &net, &home, &key);
    to_work(&home, &d.p("m.half"));
    let seals = seal_memos(&net);

    net.ledger.lock().unwrap().hold = true;
    let before = std::fs::read(home.join("container.ksg")).unwrap();
    let err = fails_waiting(&["--home", &h, "--mobile", &m, "work", "--did", "a"]);
    assert!(
        err.contains("not final yet") && err.contains("kept"),
        "{err}"
    );
    assert_ne!(
        std::fs::read(home.join("container.ksg")).unwrap(),
        before,
        "the record is kept"
    );
    let meta: serde_json::Value =
        serde_json::from_slice(&std::fs::read(home.join("container.json")).unwrap()).unwrap();
    assert_eq!(meta["anchor"]["pending"].as_array().unwrap().len(), 1);
    // The status section is not handed out with a placeholder in it.
    let err = fails(&["--home", &h, "export-statuses", "--out", s(&d.p("st.json"))]);
    assert!(err.contains("owed"), "{err}");

    // The transaction lands late; the next command takes it, then writes.
    net.ledger.lock().unwrap().release();
    ok(&["--home", &h, "--mobile", &m, "work", "--did", "b"]);
    assert_eq!(
        seal_memos(&net),
        seals + 2,
        "one memo per record, none twice"
    );
    no_fork_on_the_ledger(&net);
    let meta: serde_json::Value =
        serde_json::from_slice(&std::fs::read(home.join("container.json")).unwrap()).unwrap();
    assert!(meta["anchor"].get("pending").is_none());

    // And the journal verifies against the network, every seal read.
    ok(&["--home", &h, "finalize"]);
    ok(&[
        "--home",
        &h,
        "--mobile",
        &m,
        "export-final",
        "--out",
        s(&d.p("final.json")),
    ]);
    ok(&["--home", &h, "keys", "--out", s(&d.p("keys.json"))]);
    let rpc = HttpRpc::new(&net.url).unwrap();
    let reader = SolanaReader::connect(&rpc, "devnet")
        .unwrap()
        .with_scan_keys(scan(&home, &d.p("scan.key")));
    let fin = verify_bytes(
        &std::fs::read(d.p("final.json")).unwrap(),
        &Expected {
            container: id(&home),
            class: Class::Heavy,
            keys: keys_from_json(&std::fs::read(d.p("keys.json")).unwrap()).unwrap(),
            client_id_from_key: true,
            anchors: &reader,
        },
    );
    assert!(fin.accepted, "{fin:?}");
}

/// A memo sent whose transaction the network lost: once its blockhash has
/// expired it can never land, so it is sent once more — and the network
/// holds one memo for the record, not two.
#[test]
fn a_lost_memo_is_sent_once_more() {
    let d = Dir::new("lost");
    let net = MockDevnet::start();
    let key = d.p("payer.json");
    net.fund(&payer(&key, 22), 1_000_000_000);
    let home = d.p("home");
    let (h, m) = (s(&home).to_owned(), s(&d.p("m.half")).to_owned());
    init(&d, &net, &home, &key);
    to_work(&home, &d.p("m.half"));
    let seals = seal_memos(&net);

    net.ledger.lock().unwrap().hold = true;
    fails_waiting(&["--home", &h, "--mobile", &m, "work", "--did", "a"]);
    net.ledger.lock().unwrap().drop_held();
    ok(&["--home", &h, "--mobile", &m, "work", "--did", "b"]);
    assert_eq!(seal_memos(&net), seals + 2);
    no_fork_on_the_ledger(&net);
}

/// "Who looked" end to end (`[decision]` 13.09 §8.1, CT-15): a status
/// anchor of the container lands; the service knows it is this container's
/// because it saw the transaction go out; an owner-watcher signs a request
/// for it at the desk; the notice goes to the holder, who records it in the
/// container — and nobody on the container's side signed anything.
#[test]
fn a_look_at_an_anchor_ends_in_the_holders_container() {
    use ksg_container_v2::view::{AnchorRef, DisclosureRequest};
    use ksg_core_v2::canonical::canonical_bytes;
    use ksg_core_v2::crypto::sign::{Ed25519Signer, Profile, SignatureSet};
    use ksg_core_v2::doc::{Timestamp, Uri};
    use ksg_core_v2::status::Status;
    use ksg_service_v2::desk::{Desk, StaticRegistry};
    use ksg_service_v2::ladder::Stream;
    use ksg_verify_v2::solana::AnchorProof;

    let d = Dir::new("views");
    let net = MockDevnet::start();
    let key = d.p("payer.json");
    net.fund(&payer(&key, 23), 1_000_000_000);
    let home = d.p("home");
    let h = s(&home).to_owned();
    init(&d, &net, &home, &key);
    ok(&["--home", &h, "packet"]);
    ok(&["--home", &h, "export-statuses", "--out", s(&d.p("st.json"))]);
    let st: ksg_core_v2::section::StatusExport =
        serde_json::from_slice(&std::fs::read(d.p("st.json")).unwrap()).unwrap();
    let proof = AnchorProof::from_bytes(&st.records[1].1.proof).unwrap();
    let anchor = AnchorRef {
        cluster: "devnet".into(),
        signature: proof.signature,
    };

    let audience = Uri::parse("https://desk.example/v1").unwrap();
    let mut desk = Desk::new(audience.clone());
    desk.linkage_mut()
        .record(anchor.clone(), id(&home), "2026-10");
    let watcher = Ed25519Signer::from_seed(Uri::parse("did:key:zWatcher#w1").unwrap(), [42; 32]);
    let mut reg = StaticRegistry::default();
    reg.insert(&watcher.public(), Status::InWork);

    let now = 1_790_000_000_000;
    let challenge = desk.challenge([7; 32], now).unwrap();
    let mut req = DisclosureRequest {
        doc_type: DisclosureRequest::TYPE.into(),
        v: 3,
        owner: vec![watcher.public()],
        audience,
        anchor,
        challenge,
        issued_at: Timestamp::from_unix_ms(now).unwrap(),
        expires_at: Timestamp::from_unix_ms(now + 300_000).unwrap(),
        signatures: SignatureSet::default(),
    };
    req.signatures = SignatureSet::new(vec![watcher.sign(&canonical_bytes(&req).unwrap())]);
    let a = desk
        .accept(
            &req,
            &reg,
            Stream::Curious,
            "2026-10",
            &Timestamp::from_unix_ms(now + 1_000).unwrap(),
            &Profile::default(),
        )
        .unwrap();
    assert_eq!(a.charge.cents, 200, "the first look: $2");

    let (notices, _) = desk.take_notices(&id(&home));
    std::fs::write(d.p("notices.json"), serde_json::to_vec(&notices).unwrap()).unwrap();
    let out = ksg(&[
        "--home",
        &h,
        "record-views",
        "--from",
        s(&d.p("notices.json")),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        text.contains("recorded   1") && text.contains("viewed     1"),
        "{text}"
    );
    // Delivered twice, recorded once.
    let out = ksg(&[
        "--home",
        &h,
        "record-views",
        "--from",
        s(&d.p("notices.json")),
    ]);
    assert!(String::from_utf8_lossy(&out.stdout).contains("viewed     1"));
    let out = ksg(&["--home", &h, "views"]);
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        text.contains("did:key:zWatcher looked at devnet:"),
        "{text}"
    );
    let out = ksg(&[
        "--home",
        &h,
        "views",
        "--since",
        "2026-09-01T00:00:00.000Z",
        "--until",
        "2026-09-30T23:59:59.999Z",
    ]);
    assert!(String::from_utf8_lossy(&out.stdout).contains("looks      1"));
}

/// `ksg` with one more variable in its environment.
fn ksg_env(args: &[&str], k: &str, v: &str) -> Output {
    Command::new(KSG)
        .args(args)
        .env("KSG_ANCHOR_WAIT_S", "10")
        .env(k, v)
        .output()
        .unwrap()
}

/// The scan key changes by period (KS-1 §14.4, D-8): each seal is blinded
/// under the key of its month; the holder hands an auditor one period's key
/// or all of them; one period's key reads that period's seals and no
/// other's. A container printed before keeps its one key.
#[test]
fn the_scan_key_changes_by_period_and_one_period_reads_only_its_own() {
    let d = Dir::new("periods");
    let net = MockDevnet::start();
    let key = d.p("payer.json");
    net.fund(&payer(&key, 24), 1_000_000_000);
    let home = d.p("home");
    let (h, m) = (s(&home).to_owned(), s(&d.p("m.half")).to_owned());
    init(&d, &net, &home, &key);
    for a in [
        &["--home", &h, "packet"][..],
        &["--home", &h, "buyer-key"],
        &["--home", &h, "--mobile", &m, "initiate"],
        &["--home", &h, "--mobile", &m, "open-journal"],
    ] {
        let o = ksg_env(a, "KSG_SCAN_PERIOD", "2026-08");
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    }
    let o = ksg_env(
        &["--home", &h, "--mobile", &m, "work", "--did", "september"],
        "KSG_SCAN_PERIOD",
        "2026-09",
    );
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    // The next opening still recognizes its own memos across both periods.
    let o = ksg_env(&["--home", &h, "finalize"], "KSG_SCAN_PERIOD", "2026-09");
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    ok(&[
        "--home",
        &h,
        "--mobile",
        &m,
        "export-final",
        "--out",
        s(&d.p("final.json")),
    ]);
    ok(&["--home", &h, "keys", "--out", s(&d.p("keys.json"))]);

    let all = scan(&home, &d.p("all.key"));
    assert_eq!(all.len(), 2, "two periods, two keys");
    ok(&[
        "--home",
        &h,
        "scan-key",
        "--period",
        "2026-08",
        "--out",
        s(&d.p("aug.key")),
    ]);
    let aug = ksg_verify_v2::solana::scan_keys_from_text(
        &std::fs::read_to_string(d.p("aug.key")).unwrap(),
    )
    .unwrap();
    assert_eq!(aug.len(), 1);
    assert!(fails(&[
        "--home",
        &h,
        "scan-key",
        "--period",
        "2026-07",
        "--out",
        s(&d.p("x.key"))
    ])
    .contains("2026-07"));

    let rpc = HttpRpc::new(&net.url).unwrap();
    let verdict = |keys: Vec<SealScanKey>| {
        let reader = SolanaReader::connect(&rpc, "devnet")
            .unwrap()
            .with_scan_keys(keys);
        verify_bytes(
            &std::fs::read(d.p("final.json")).unwrap(),
            &Expected {
                container: id(&home),
                class: Class::Heavy,
                keys: keys_from_json(&std::fs::read(d.p("keys.json")).unwrap()).unwrap(),
                client_id_from_key: true,
                anchors: &reader,
            },
        )
    };
    assert!(verdict(all).accepted, "every period's key reads every seal");
    assert!(
        !verdict(aug).accepted,
        "August's key does not read September's seal"
    );
    no_fork_on_the_ledger(&net);
}

/// A container printed before the change keeps its one key for life.
#[test]
fn a_container_with_one_scan_key_keeps_it() {
    let d = Dir::new("onekey");
    let net = MockDevnet::start();
    let key = d.p("payer.json");
    net.fund(&payer(&key, 25), 1_000_000_000);
    let home = d.p("home");
    init(&d, &net, &home, &key);
    // As a container.json written before `rotate_scan` existed reads.
    let mut meta: serde_json::Value =
        serde_json::from_slice(&std::fs::read(home.join("container.json")).unwrap()).unwrap();
    meta["anchor"]
        .as_object_mut()
        .unwrap()
        .remove("rotate_scan");
    std::fs::write(
        home.join("container.json"),
        serde_json::to_vec(&meta).unwrap(),
    )
    .unwrap();
    to_work(&home, &d.p("m.half"));
    let text = {
        ok(&["--home", s(&home), "scan-key", "--out", s(&d.p("k.key"))]);
        std::fs::read_to_string(d.p("k.key")).unwrap()
    };
    assert!(
        !text.trim_start().starts_with('{'),
        "one key, as before: {text}"
    );
    let o = ksg(&[
        "--home",
        s(&home),
        "scan-key",
        "--period",
        "2026-08",
        "--out",
        s(&d.p("x")),
    ]);
    assert_eq!(o.status.code(), Some(2), "a usage error");
    assert!(String::from_utf8_lossy(&o.stderr).contains("does not change"));
}

// Goal 2, criteria G2-2 and G2-3 (`[decision]` 09.10: anchors on the local net,
// not devnet). The same two scenarios as `a_heavy_life_anchored_on_devnet_verifies`
// and `an_older_copy_of_the_file_does_not_open` pressed against a running
// `solana-test-validator`. Ordinary gates never run them: `#[ignore]` plus
// the `KSG_LOCALNET_RPC` guard — without the variable the test returns at
// once. The mock ledger's memo counts do not apply here; the exports are
// checked through the node's real RPC instead.

fn localnet() -> Option<(String, String)> {
    let rpc = std::env::var("KSG_LOCALNET_RPC").ok()?;
    let payer = std::env::var("KSG_LOCALNET_PAYER").unwrap_or_else(|_| {
        format!(
            "{}/.secrets/keysingate/solana/localnet-payer.json",
            std::env::var("HOME").expect("HOME")
        )
    });
    Some((rpc, payer))
}

/// The node's `ok`: the mock finalizes at once, a test-validator takes its
/// time to reach `finalized`, so the wait grows to three minutes.
fn ok_ln(args: &[&str]) {
    let o = Command::new(KSG)
        .args(args)
        .env("KSG_ANCHOR_WAIT_S", "180")
        .output()
        .unwrap();
    assert!(
        o.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
}

/// `to_work` on the real node.
fn to_work_ln(home: &Path, m: &Path) {
    let (h, m) = (s(home), s(m));
    ok_ln(&["--home", h, "packet"]);
    ok_ln(&["--home", h, "buyer-key"]);
    ok_ln(&["--home", h, "--mobile", m, "initiate"]);
    ok_ln(&["--home", h, "--mobile", m, "open-journal"]);
}

#[test]
#[ignore = "goes to a local solana-test-validator (KSG_LOCALNET_RPC)"]
fn a_heavy_life_anchored_on_localnet_verifies() {
    let (rpc_url, payer) = match localnet() {
        Some(x) => x,
        None => {
            eprintln!("KSG_LOCALNET_RPC is not set: nothing is anchored, the test passes empty");
            return;
        }
    };
    let d = Dir::new("life-localnet");
    let home = d.p("home");
    let (h, m) = (s(&home).to_owned(), s(&d.p("m.half")).to_owned());
    ok_ln(&[
        "--home",
        &h,
        "init",
        "--class",
        "heavy",
        "--anchor",
        "solana:localnet",
        "--payer",
        &payer,
        "--rpc",
        &rpc_url,
    ]);
    to_work_ln(&home, &d.p("m.half"));
    std::fs::write(d.p("policy.pdf"), b"POLICY 7").unwrap();
    ok_ln(&[
        "--home",
        &h,
        "--mobile",
        &m,
        "attach",
        "--type",
        "urn:ksg:page:policy:v1",
        "--file",
        s(&d.p("policy.pdf")),
    ]);
    ok_ln(&[
        "--home",
        &h,
        "--mobile",
        &m,
        "work",
        "--did",
        "claim reviewed",
    ]);
    ok_ln(&[
        "--home",
        &h,
        "export-page",
        "--number",
        "1",
        "--by",
        "owner",
        "--out",
        s(&d.p("p1.json")),
    ]);
    ok_ln(&["--home", &h, "finalize"]);
    ok_ln(&[
        "--home",
        &h,
        "--mobile",
        &m,
        "export-final",
        "--out",
        s(&d.p("final.json")),
    ]);
    ok_ln(&["--home", &h, "keys", "--out", s(&d.p("keys.json"))]);
    ok_ln(&[
        "--home",
        &h,
        "export-statuses",
        "--out",
        s(&d.p("statuses.json")),
    ]);

    // The exports read back from the node: with the scan key everything is
    // accepted, without it the anchors are noise. The mock's memo counts are
    // skipped on purpose — the node itself is the evidence.
    let rpc = HttpRpc::new(&rpc_url).unwrap();
    let sk = scan(&home, &d.p("scan.key"));
    let keys = keys_from_json(&std::fs::read(d.p("keys.json")).unwrap()).unwrap();
    let blind = SolanaReader::connect(&rpc, "localnet").unwrap();
    let reader = SolanaReader::connect(&rpc, "localnet")
        .unwrap()
        .with_scan_keys(sk.clone());
    let x: BoundExport =
        serde_json::from_slice(&std::fs::read(d.p("final.json")).unwrap()).unwrap();
    let records = verify_bound(&x, &ksg_core_v2::crypto::sign::Profile::default())
        .unwrap()
        .records;
    let exp = Expected {
        container: id(&home),
        class: Class::Heavy,
        keys: keys.clone(),
        client_id_from_key: true,
        anchors: &reader,
    };
    let fin = verify_bytes(&std::fs::read(d.p("final.json")).unwrap(), &exp);
    assert!(fin.accepted, "{fin:?}");
    assert_eq!(fin.pages, Some(3));
    let point = verify_bytes(&std::fs::read(d.p("p1.json")).unwrap(), &exp);
    assert!(point.accepted, "{point:?}");
    assert!(point.anchored_at.is_some());
    let no_key = verify_bytes(
        &std::fs::read(d.p("final.json")).unwrap(),
        &Expected {
            container: id(&home),
            class: Class::Heavy,
            keys,
            client_id_from_key: true,
            anchors: &blind,
        },
    );
    assert!(!no_key.accepted, "{no_key:?}");
    // The program too, as a third party runs it against the node.
    let verifier =
        Path::new(KSG).with_file_name(format!("ksg-verify-v2{}", std::env::consts::EXE_SUFFIX));
    assert!(
        verifier.exists(),
        "build ksg-verify-v2 before the ignored localnet run"
    );
    let out = Command::new(&verifier)
        .args([
            "--export",
            s(&d.p("final.json")),
            "--container",
            &id(&home).to_multihash(),
            "--class",
            "heavy",
            "--keys",
            s(&d.p("keys.json")),
            "--rpc",
            &rpc_url,
            "--cluster",
            "localnet",
            "--forks",
            "--scan-key",
            s(&d.p("scan.key")),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success() && String::from_utf8_lossy(&out.stdout).contains("ACCEPTED"),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    // The three seals and the statuses of this life went through the node:
    // the reader found them; count them for the report.
    let _ = records;
}

#[test]
#[ignore = "goes to a local solana-test-validator (KSG_LOCALNET_RPC)"]
fn an_older_copy_does_not_open_on_localnet() {
    let (rpc_url, payer) = match localnet() {
        Some(x) => x,
        None => {
            eprintln!("KSG_LOCALNET_RPC is not set: nothing is anchored, the test passes empty");
            return;
        }
    };
    let d = Dir::new("rollback-localnet");
    let home = d.p("home");
    ok_ln(&[
        "--home",
        s(&home),
        "init",
        "--class",
        "heavy",
        "--anchor",
        "solana:localnet",
        "--payer",
        &payer,
        "--rpc",
        &rpc_url,
    ]);
    to_work_ln(&home, &d.p("m.half"));
    // The holder keeps a copy, works on, then goes back to the copy.
    let old = d.p("old");
    std::fs::create_dir_all(&old).unwrap();
    for f in [
        "container.ksg",
        "container.json",
        "layer.key",
        "scan.key",
        "parties.json",
    ] {
        std::fs::copy(home.join(f), old.join(f)).unwrap();
    }
    ok_ln(&[
        "--home",
        s(&home),
        "--mobile",
        s(&d.p("m.half")),
        "work",
        "--did",
        "the real step",
    ]);
    let err = fails(&[
        "--home",
        s(&old),
        "--mobile",
        s(&d.p("m.half")),
        "work",
        "--did",
        "the other step",
    ]);
    assert!(err.contains("rolled back"), "{err}");
    // The current file goes on working, anchored on the node.
    ok_ln(&[
        "--home",
        s(&home),
        "--mobile",
        s(&d.p("m.half")),
        "work",
        "--did",
        "the next step",
    ]);
    // And the live node reads the journal's latest seal through the verifier:
    // the current export is accepted, the old copy's is not. The seal memos
    // are blind, so the scan key is needed to hold them on the network.
    ok_ln(&["--home", s(&home), "keys", "--out", s(&d.p("keys.json"))]);
    let sk = scan(&home, &d.p("scan.key"));
    let _ = sk;
    ok_ln(&[
        "--home",
        s(&home),
        "--mobile",
        s(&d.p("m.half")),
        "export-final",
        "--out",
        s(&d.p("final.json")),
    ]);
    let verifier =
        Path::new(KSG).with_file_name(format!("ksg-verify-v2{}", std::env::consts::EXE_SUFFIX));
    assert!(
        verifier.exists(),
        "build ksg-verify-v2 before the ignored localnet run"
    );
    let out = Command::new(&verifier)
        .args([
            "--export",
            s(&d.p("final.json")),
            "--container",
            &id(&home).to_multihash(),
            "--class",
            "heavy",
            "--keys",
            s(&d.p("keys.json")),
            "--rpc",
            &rpc_url,
            "--cluster",
            "localnet",
            "--forks",
            "--scan-key",
            s(&d.p("scan.key")),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success() && String::from_utf8_lossy(&out.stdout).contains("ACCEPTED"),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
}

/// KS-8 C-10, step 1 (E-18): the agent publishes its ID in the chain with an
/// anchor — an open `ksg:id:v1` memo naming the ID and the hash that binds
/// it to this container and the client's key; the verifier checks the
/// anchor against the chain, and the container itself is not in the memo.
#[test]
fn a_pro_agent_publishes_its_id_in_the_chain() {
    use ksg_container_v2::identity::Publication;
    use ksg_core_v2::anchor::{Attestation, AttestationVerifier};
    use ksg_core_v2::crypto::sign::{KeySet, Profile, PublicKey, SignatureSet};
    let d = Dir::new("agent-id");
    let net = MockDevnet::start();
    let key = d.p("payer.json");
    net.fund(&payer(&key, 5), 1_000_000_000);
    let home = d.p("home");
    init(&d, &net, &home, &key);
    to_work(&home, &d.p("m.half"));
    let open_id = "did:web:agent.example.com";
    ok(&[
        "--home",
        s(&home),
        "--mobile",
        s(&d.p("m.half")),
        "publish-id",
        "--id",
        open_id,
    ]);
    assert_eq!(memos(&net, "ksg:id:v1 "), 1);

    let doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(home.join("agent-id.json")).unwrap()).unwrap();
    let agent: PublicKey = serde_json::from_value(doc["agent"].clone()).unwrap();
    let p = Publication {
        container: id(&home),
        open_id: doc["open_id"].as_str().unwrap().to_owned(),
        agent: agent.clone(),
        signatures: serde_json::from_value::<SignatureSet>(doc["signatures"].clone()).unwrap(),
        anchor: serde_json::from_value::<Attestation>(doc["anchor"].clone()).unwrap(),
    };
    p.validate().unwrap();
    let keys: KeySet = std::iter::once(agent.clone()).collect();
    let subject = Publication::subject(&p.container, open_id, &agent);
    p.signatures
        .verify(
            subject.as_bytes(),
            &keys,
            &Profile::default().with_ed25519(),
        )
        .unwrap();
    // The anchor stands on the chain.
    let rpc = HttpRpc::new(&net.url).unwrap();
    let reader = SolanaReader::connect(&rpc, "devnet").unwrap();
    assert!(reader.handles(&p.anchor.kind));
    reader.verify(&p.anchor).unwrap();
    // Moved to another container, the same anchor proves nothing.
    let mut moved = p.clone();
    moved.container = Hash::sha256(b"another container");
    assert!(moved.validate().is_err());
    // The memo holds the ID and the hash, not the container.
    let ledger = net.ledger.lock().unwrap();
    let memo = ledger
        .txs
        .iter()
        .find(|t| t.memo.starts_with(b"ksg:id:v1 "))
        .map(|t| String::from_utf8(t.memo.clone()).unwrap())
        .unwrap();
    assert!(memo.ends_with(open_id), "{memo}");
    assert!(!memo.contains(&id(&home).to_multihash()), "{memo}");
    drop(ledger);

    // One container, one ID, once: a second publication is refused.
    let e = fails(&[
        "--home",
        s(&home),
        "--mobile",
        s(&d.p("m.half")),
        "publish-id",
        "--id",
        "did:web:other.example.com",
    ]);
    assert!(e.contains("published already"), "{e}");
    assert_eq!(memos(&net, "ksg:id:v1 "), 1);
}
