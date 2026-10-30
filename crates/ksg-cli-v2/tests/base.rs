//! `light` on Base Sepolia through the program, against a node in a thread
//! (`mock_base`): the minimal anchors, the ten offline records, the copy
//! check — and the issuance anchor of a `bare` (owner's decisions 14.10).

mod mock_base;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use ksg_anchor_v2::evm::unhex;
use ksg_verify_v2::base::head;
use ksg_verify_v2::solana::HttpRpc;
use mock_base::MockBase;

const KSG: &str = env!("CARGO_BIN_EXE_ksg-remote-panel");

struct Dir(PathBuf);

impl Dir {
    fn new(name: &str) -> Self {
        let d = std::env::temp_dir().join(format!("ksg-base-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Self(d)
    }
    fn p(&self, name: &str) -> String {
        self.0.join(name).to_string_lossy().into_owned()
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
        .env("KSG_BASE_WAIT_SECS", "10")
        .output()
        .expect("the program runs")
}

fn ok(args: &[&str]) -> String {
    let out = ksg(args);
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn fails(args: &[&str]) -> String {
    let out = ksg(args);
    assert!(!out.status.success(), "{args:?} should fail");
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn key_file(d: &Dir, name: &str, byte: u8) -> String {
    let path = d.p(name);
    std::fs::write(&path, hex::encode([byte; 32])).unwrap();
    path
}

fn count(node: &MockBase, home: &str) -> u64 {
    chain_head(node, home).count
}

fn chain_head(node: &MockBase, home: &str) -> ksg_verify_v2::base::Head {
    let meta: serde_json::Value =
        serde_json::from_slice(&std::fs::read(Path::new(home).join("container.json")).unwrap())
            .unwrap();
    let template =
        ksg_core_v2::crypto::hash::Hash::from_multihash(meta["template"].as_str().unwrap())
            .unwrap();
    let salt: [u8; 32] = unhex(meta["base"]["salt"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let key = ksg_verify_v2::base::anchor_key(template.as_bytes(), &salt);
    let contract: [u8; 20] = unhex(&node.contract()).unwrap().try_into().unwrap();
    let rpc = HttpRpc::new(&node.url).unwrap();
    // Nothing goes under the template itself: the chain does not see it.
    assert_eq!(
        head(&rpc, &contract, template.as_bytes()).unwrap().count,
        0,
        "the template is on the chain"
    );
    head(&rpc, &contract, &key).unwrap()
}

fn light(d: &Dir, node: &MockBase, home: &str, half: &str) {
    let key = key_file(d, "evm.key", 0x42);
    let contract = node.contract();
    let out = ok(&[
        "--home",
        home,
        "init",
        "--class",
        "light",
        "--base-rpc",
        &node.url,
        "--base-contract",
        &contract,
        "--evm-key",
        &key,
    ]);
    assert!(out.contains("anchored   Base Sepolia"), "{out}");
    ok(&["--home", home, "packet"]);
    ok(&["--home", home, "buyer-key"]);
    ok(&["--home", home, "--mobile", half, "initiate"]);
    ok(&["--home", home, "--mobile", half, "open-journal"]);
}

#[test]
fn light_anchors_at_birth_at_initiation_and_every_ten_records() {
    let d = Dir::new("schedule");
    let node = MockBase::start();
    let (home, half) = (d.p("home"), d.p("m.half"));
    light(&d, &node, &home, &half);
    // Ya-1 at printing, Ya-2 at initiation.
    assert_eq!(count(&node, &home), 2);

    // The network goes down: ten records go without it…
    node.chain.lock().unwrap().down = true;
    for i in 0..9 {
        ok(&[
            "--home",
            &home,
            "--mobile",
            &half,
            "work",
            "--did",
            &format!("step {i}"),
        ]);
    }
    // (open-journal wrote the first record: nine more make ten.)
    let e = fails(&[
        "--home",
        &home,
        "--mobile",
        &half,
        "work",
        "--did",
        "the eleventh",
    ]);
    assert!(e.contains("Base Sepolia"), "{e}");

    // …and the eleventh goes once the network is back, on a fresh anchor.
    node.chain.lock().unwrap().down = false;
    ok(&[
        "--home",
        &home,
        "--mobile",
        &half,
        "work",
        "--did",
        "the eleventh",
    ]);
    assert_eq!(count(&node, &home), 3);
}

#[test]
fn a_page_goes_out_only_on_a_fresh_anchor() {
    let d = Dir::new("value");
    let node = MockBase::start();
    let (home, half) = (d.p("home"), d.p("m.half"));
    light(&d, &node, &home, &half);
    ok(&["--home", &home, "--mobile", &half, "work", "--did", "one"]);

    node.chain.lock().unwrap().down = true;
    let e = fails(&[
        "--home",
        &home,
        "--mobile",
        &half,
        "export-page",
        "--number",
        "1",
        "--by",
        "client",
        "--out",
        &d.p("p.json"),
    ]);
    assert!(e.contains("Base Sepolia"), "{e}");

    node.chain.lock().unwrap().down = false;
    ok(&[
        "--home",
        &home,
        "--mobile",
        &half,
        "export-page",
        "--number",
        "1",
        "--by",
        "client",
        "--out",
        &d.p("p.json"),
    ]);
    assert_eq!(count(&node, &home), 3);
}

fn copy_dir(from: &str, to: &str) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap().flatten() {
        if e.file_type().unwrap().is_file() && e.file_name() != "lock" {
            std::fs::copy(e.path(), Path::new(to).join(e.file_name())).unwrap();
        }
    }
}

#[test]
fn a_copy_learns_it_is_one_and_only_exports_in_full() {
    let d = Dir::new("copy");
    let node = MockBase::start();
    let (home, half) = (d.p("home"), d.p("m.half"));
    light(&d, &node, &home, &half);
    ok(&[
        "--home",
        &home,
        "--mobile",
        &half,
        "work",
        "--did",
        "shared past",
    ]);

    // The file is copied; the original goes on and anchors (a page out).
    let copy = d.p("copy");
    copy_dir(&home, &copy);
    ok(&[
        "--home",
        &home,
        "--mobile",
        &half,
        "work",
        "--did",
        "the original's",
    ]);
    ok(&[
        "--home",
        &home,
        "--mobile",
        &half,
        "export-page",
        "--number",
        "1",
        "--by",
        "client",
        "--out",
        &d.p("p.json"),
    ]);

    // The copy opens behind the head: it writes nothing, exports no page…
    let e = fails(&[
        "--home",
        &copy,
        "--mobile",
        &half,
        "work",
        "--did",
        "the copy's",
    ]);
    assert!(e.contains("copy"), "{e}");
    let e = fails(&[
        "--home",
        &copy,
        "--mobile",
        &half,
        "export-page",
        "--number",
        "1",
        "--by",
        "client",
        "--out",
        &d.p("q.json"),
    ]);
    assert!(e.contains("copy"), "{e}");
    // …and still hands over everything it holds.
    ok(&[
        "--home",
        &copy,
        "--mobile",
        &half,
        "export-final",
        "--out",
        &d.p("all.json"),
    ]);

    // The original is untouched by the copy's attempts.
    ok(&[
        "--home",
        &home,
        "--mobile",
        &half,
        "work",
        "--did",
        "still working",
    ]);
}

/// Base Sepolia takes `light` (anchors) and Pro (E-19 only, owner's
/// decision 16.10 "A"); a `bare` is never anchored and is refused.
#[test]
fn base_takes_light_and_pro_but_not_bare() {
    let d = Dir::new("class");
    let node = MockBase::start();
    let key = key_file(&d, "evm.key", 0x42);
    let init = |home: &str, class: &str| {
        ksg(&[
            "--home",
            &d.p(home),
            "init",
            "--class",
            class,
            "--base-rpc",
            &node.url,
            "--base-contract",
            &node.contract(),
            "--evm-key",
            &key,
        ])
    };
    let out = init("bare", "bare");
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("never anchored"));
    let out = init("pro", "heavy");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Pro's anchors are Solana's: printing puts nothing on Base.
    assert_eq!(count(&node, &d.p("pro")), 0);
}

#[test]
fn the_issuance_anchor_refuses_the_second_bare() {
    let d = Dir::new("issue");
    let node = MockBase::start();
    let key = key_file(&d, "evm.key", 0x43);
    let check = d.p("check.key");
    std::fs::write(&check, hex::encode([0x77u8; 32])).unwrap();
    let contract = node.contract();
    let run = |sub: &str, docs: &str, version: &str| {
        let mut a = vec![
            "issue-anchor",
            sub,
            "--check-key",
            &check,
            "--docs",
            docs,
            "--release",
            "ksg:em:test:000001",
            "--version",
            version,
            "--base-rpc",
            &node.url,
            "--base-contract",
            &contract,
        ];
        if sub == "put" {
            a.extend_from_slice(&["--evm-key", &key, "--year", "2026"]);
        }
        ok(&a)
    };
    assert!(run("check", "email:alice@example.com", "0.2").contains("free"));
    assert!(run(
        "put",
        "email:alice@example.com,did-web:did:web:example.org:alice",
        "0.2"
    )
    .contains("anchored"));
    // The same e-mail, written differently, of the same release and version:
    // the beta repeats neither free nor for payment (owner's decision 27.10).
    let out = run("check", "email:ALICE@Example.COM", "0.2");
    assert!(out.contains("refused"), "{out}");
    // The issuance label: who issued (the issuer's key 0x43…) and when.
    assert!(out.contains("issued     block "), "{out}");
    assert!(
        out.contains(&ksg_anchor_v2::evm::hex0x(&evm_address(0x43))),
        "{out}"
    );
    // The same did:web alone is enough to refuse too.
    assert!(run("check", "did-web:did:web:example.org:Alice", "0.2").contains("refused"));
    // Another person, or another version of the software: free.
    assert!(run("check", "email:bob@example.com", "0.2").contains("free"));
    assert!(run("check", "email:alice@example.com", "0.3").contains("free"));
}

/// The container's blind anchor key, as `initiate` left it beside the half.
fn anchor_key(half: &str) -> String {
    std::fs::read_to_string(format!("{half}.anchor")).unwrap()
}

fn lost(node: &MockBase, cmd: &str, key: &str, extra: &[&str]) -> Output {
    let contract = node.contract();
    let mut a = vec![
        cmd,
        "--anchor-key",
        key,
        "--base-rpc",
        &node.url,
        "--base-contract",
        &contract,
    ];
    a.extend_from_slice(extra);
    ksg(&a)
}

#[test]
fn the_mobile_half_alone_declares_its_container_lost() {
    let d = Dir::new("lost");
    let node = MockBase::start();
    let (home, half) = (d.p("home"), d.p("m.half"));
    light(&d, &node, &home, &half);
    let t = anchor_key(&half);
    let status = |n: &MockBase| {
        String::from_utf8_lossy(&lost(n, "lost-status", &t, &[]).stdout).into_owned()
    };
    assert!(status(&node).contains("in use"), "{}", status(&node));

    // Another client's half is not this container's: the chain does not take
    // its declaration for one.
    // (Printed from the same test template, it lives on another node.)
    let elsewhere = MockBase::start();
    let (other, other_half) = (d.p("other"), d.p("o.half"));
    light(&d, &elsewhere, &other, &other_half);
    let payer = key_file(&d, "payer.key", 0x51);
    let out = lost(
        &node,
        "declare-lost",
        &t,
        &["--half", &other_half, "--evm-key", &payer],
    );
    assert!(!out.status.success());
    assert!(status(&node).contains("in use"));

    // The client's own half, alone, declares it lost: the time and the hash of
    // the client's identifier are in the declaration.
    let out = lost(
        &node,
        "declare-lost",
        &t,
        &["--half", &half, "--evm-key", &payer],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let s = status(&node);
    assert!(s.contains("lost       declared at"), "{s}");
    assert!(s.contains("client 0x"), "{s}");

    // The container does not open any more — a copy of it neither.
    let e = fails(&["--home", &home, "--mobile", &half, "work", "--did", "after"]);
    assert!(e.contains("declared this container lost"), "{e}");
}

#[test]
fn without_a_commitment_the_status_stays_frozen() {
    let d = Dir::new("frozen");
    let node = MockBase::start();
    let (home, half) = (d.p("home"), d.p("m.half"));
    // Printed and anchored (Ya-1), initiated while the network was down: no
    // commitment to the half went on the chain.
    let key = key_file(&d, "evm.key", 0x42);
    let contract = node.contract();
    ok(&[
        "--home",
        &home,
        "init",
        "--class",
        "light",
        "--base-rpc",
        &node.url,
        "--base-contract",
        &contract,
        "--evm-key",
        &key,
    ]);
    ok(&["--home", &home, "packet"]);
    ok(&["--home", &home, "buyer-key"]);
    node.chain.lock().unwrap().down = true;
    ok(&["--home", &home, "--mobile", &half, "initiate"]);
    node.chain.lock().unwrap().down = false;

    let t = anchor_key(&half);
    let out = lost(&node, "lost-status", &t, &[]);
    assert!(String::from_utf8_lossy(&out.stdout).contains("frozen"));
    let payer = key_file(&d, "payer.key", 0x51);
    let out = lost(
        &node,
        "declare-lost",
        &t,
        &["--half", &half, "--evm-key", &payer],
    );
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("frozen"));

    // The next anchor carries the waiting commitment: from then on the half
    // can declare.
    ok(&["--home", &home, "--mobile", &half, "open-journal"]);
    let out = lost(&node, "lost-status", &t, &[]);
    assert!(String::from_utf8_lossy(&out.stdout).contains("in use"));
}

fn evm_address(byte: u8) -> [u8; 20] {
    let key = ksg_anchor_v2::evm::key_from_secret(&[byte; 32]).unwrap();
    ksg_anchor_v2::evm::address_of(key.verifying_key())
}

fn base_cfg(home: &str) -> serde_json::Value {
    let meta: serde_json::Value =
        serde_json::from_slice(&std::fs::read(Path::new(home).join("container.json")).unwrap())
            .unwrap();
    meta["base"].clone()
}

fn export(home: &str, half: &str, by: &str, out: &str) -> String {
    ok(&[
        "--home",
        home,
        "--mobile",
        half,
        "export-page",
        "--number",
        "1",
        "--by",
        by,
        "--out",
        out,
    ])
}

/// A transfer of rights (E-9) moves the writer's seat on the contract to the
/// new owner's EVM key (`handOver`), and the new owner anchors from it; the
/// old key is out (gap 15.10).
#[test]
fn a_transfer_of_rights_hands_the_writer_over() {
    let d = Dir::new("handover");
    let node = MockBase::start();
    let (home, half) = (d.p("home"), d.p("m.half"));
    light(&d, &node, &home, &half);
    ok(&["--home", &home, "--mobile", &half, "work", "--did", "one"]);
    assert_eq!(chain_head(&node, &home).writer, evm_address(0x42));

    // Without the new owner's key the seat would stay the seller's: refused.
    let e = fails(&["--home", &home, "--mobile", &half, "owner-change"]);
    assert!(e.contains("--evm-key"), "{e}");

    let buyer = key_file(&d, "buyer.key", 0x43);
    let out = ok(&[
        "--home",
        &home,
        "--mobile",
        &half,
        "owner-change",
        "--evm-key",
        &buyer,
    ]);
    assert!(out.contains("handed     Base Sepolia"), "{out}");
    // The transfer went out on a fresh anchor, from the seller's key.
    let h = chain_head(&node, &home);
    assert_eq!((h.count, h.writer), (3, evm_address(0x43)));
    assert_eq!(base_cfg(&home)["key"], buyer.as_str());
    assert!(base_cfg(&home)["hand_to"].is_null());

    // The new owner signs and anchors from its own key.
    export(&home, &half, "owner", &d.p("p.json"));
    let h = chain_head(&node, &home);
    assert_eq!((h.count, h.writer), (4, evm_address(0x43)));
}

/// The network drops between the fresh anchor and the hand-over: the owner's
/// change stays in, the hand-over waits in `container.json` and goes, from
/// the seller's key, before the next anchor.
#[test]
fn a_hand_over_the_network_missed_goes_before_the_next_anchor() {
    let d = Dir::new("handover-late");
    let node = MockBase::start();
    let (home, half) = (d.p("home"), d.p("m.half"));
    light(&d, &node, &home, &half);
    ok(&["--home", &home, "--mobile", &half, "work", "--did", "one"]);

    let buyer = key_file(&d, "buyer.key", 0x43);
    node.chain.lock().unwrap().drop =
        Some(ksg_anchor_v2::evm::selector("handOver(bytes32,address)"));
    let out = ok(&[
        "--home",
        &home,
        "--mobile",
        &half,
        "owner-change",
        "--evm-key",
        &buyer,
    ]);
    assert!(out.contains("waits for Base Sepolia"), "{out}");
    assert_eq!(chain_head(&node, &home).writer, evm_address(0x42));
    assert!(base_cfg(&home)["key"]
        .as_str()
        .unwrap()
        .ends_with("evm.key"));
    assert_eq!(
        base_cfg(&home)["hand_to"]["to"],
        ksg_anchor_v2::evm::hex0x(&evm_address(0x43)).as_str()
    );

    // While it is owed, the next value waits for it.
    let e = fails(&[
        "--home",
        &home,
        "--mobile",
        &half,
        "export-page",
        "--number",
        "1",
        "--by",
        "owner",
        "--out",
        &d.p("p.json"),
    ]);
    assert!(e.contains("hand-over"), "{e}");

    node.chain.lock().unwrap().drop = None;
    export(&home, &half, "owner", &d.p("p.json"));
    let h = chain_head(&node, &home);
    assert_eq!((h.count, h.writer), (4, evm_address(0x43)));
    assert_eq!(base_cfg(&home)["key"], buyer.as_str());
    assert!(base_cfg(&home)["hand_to"].is_null());
}

/// Where nothing anchors on Base Sepolia the owner's change takes no EVM key.
#[test]
fn an_owner_change_off_base_takes_no_evm_key() {
    let d = Dir::new("handover-off");
    let home = d.p("home");
    let half = d.p("m.half");
    ok(&["--home", &home, "init", "--class", "light"]);
    ok(&["--home", &home, "packet"]);
    ok(&["--home", &home, "buyer-key"]);
    ok(&["--home", &home, "--mobile", &half, "initiate"]);
    ok(&["--home", &home, "--mobile", &half, "open-journal"]);
    let k = key_file(&d, "buyer.key", 0x43);
    let e = fails(&[
        "--home",
        &home,
        "--mobile",
        &half,
        "owner-change",
        "--evm-key",
        &k,
    ]);
    assert!(e.contains("only where"), "{e}");
    ok(&["--home", &home, "--mobile", &half, "owner-change"]);
}

/// The copy learns what it is at its own anchor, not only when it opens:
/// the head cannot be read at opening (the network drops that call), the
/// copy goes as far as an anchor, and the contract's refusal
/// (`StalePredecessor`) tells it.
#[test]
fn a_copy_learns_it_is_one_when_its_anchor_is_refused() {
    let d = Dir::new("copy-at-anchor");
    let node = MockBase::start();
    let (home, half) = (d.p("home"), d.p("m.half"));
    light(&d, &node, &home, &half);
    ok(&[
        "--home", &home, "--mobile", &half, "work", "--did", "shared",
    ]);
    let copy = d.p("copy");
    copy_dir(&home, &copy);
    ok(&[
        "--home",
        &home,
        "--mobile",
        &half,
        "work",
        "--did",
        "the original's",
    ]);
    export(&home, &half, "client", &d.p("p.json"));

    // Reading the head is cut at the two openings below, then the network
    // is back: the check at opening cannot run, the check before the anchor
    // can (16.10: nothing is written without reading the loss first).
    {
        let mut c = node.chain.lock().unwrap();
        c.drop = Some(ksg_verify_v2::base::HEAD_SELECTOR);
        c.drop_left = Some(2);
    }
    ok(&[
        "--home",
        &copy,
        "--mobile",
        &half,
        "work",
        "--did",
        "the copy's",
    ]);
    let e = fails(&[
        "--home",
        &copy,
        "--mobile",
        &half,
        "export-page",
        "--number",
        "1",
        "--by",
        "client",
        "--out",
        &d.p("c.json"),
    ]);
    assert!(e.contains("refused the anchor"), "{e}");
    assert!(e.contains("copy"), "{e}");
    assert!(!Path::new(&d.p("c.json")).exists());
}

/// E-19 for Pro (owner's decision 16.10 "A"): Base Sepolia is Pro's second
/// network for the loss alone — at initiation one anchor makes the key the
/// writer and the commitment to the mobile half follows; the half declares
/// the loss, and the Pro container does not open any more.
#[test]
fn a_pro_container_is_declared_lost_on_base() {
    let d = Dir::new("pro-lost");
    let node = MockBase::start();
    let (home, half) = (d.p("pro"), d.p("m.half"));
    let key = key_file(&d, "evm.key", 0x42);
    ok(&[
        "--home",
        &home,
        "init",
        "--class",
        "heavy",
        "--base-rpc",
        &node.url,
        "--base-contract",
        &node.contract(),
        "--evm-key",
        &key,
    ]);
    ok(&["--home", &home, "packet"]);
    ok(&["--home", &home, "buyer-key"]);
    ok(&["--home", &home, "--mobile", &half, "initiate"]);
    // One anchor (the writer's seat) and the commitment — nothing else of Pro.
    assert_eq!(count(&node, &home), 1);
    assert!(
        base_cfg(&home)["share"].is_null(),
        "the commitment went out"
    );
    ok(&["--home", &home, "--mobile", &half, "open-journal"]);
    ok(&["--home", &home, "--mobile", &half, "work", "--did", "one"]);
    assert_eq!(
        count(&node, &home),
        1,
        "Pro's records do not anchor on Base"
    );

    let t = anchor_key(&half);
    let payer = key_file(&d, "payer.key", 0x51);
    let out = lost(
        &node,
        "declare-lost",
        &t,
        &["--half", &half, "--evm-key", &payer],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let e = fails(&["--home", &home, "--mobile", &half, "work", "--did", "after"]);
    assert!(e.contains("declared this container lost"), "{e}");
}

/// After a transfer of rights the commitment still identifies the half: it
/// was put by the writer of its moment, and the hand-over is on the chain
/// (`HandedOver`) — a declaration of loss still holds.
#[test]
fn a_loss_is_declared_after_a_transfer_of_rights() {
    let d = Dir::new("lost-after-sale");
    let node = MockBase::start();
    let (home, half) = (d.p("home"), d.p("m.half"));
    light(&d, &node, &home, &half);
    let buyer = key_file(&d, "buyer.key", 0x43);
    ok(&[
        "--home",
        &home,
        "--mobile",
        &half,
        "owner-change",
        "--evm-key",
        &buyer,
    ]);
    assert_eq!(chain_head(&node, &home).writer, evm_address(0x43));

    let t = anchor_key(&half);
    let payer = key_file(&d, "payer.key", 0x51);
    let out = lost(
        &node,
        "declare-lost",
        &t,
        &["--half", &half, "--evm-key", &payer],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let s = String::from_utf8_lossy(&lost(&node, "lost-status", &t, &[]).stdout).into_owned();
    assert!(s.contains("lost       declared at"), "{s}");
}

fn ok_env(args: &[&str], env: &[(&str, &str)]) -> String {
    let out = Command::new(KSG)
        .args(args)
        .env("KSG_BASE_WAIT_SECS", "10")
        .envs(env.iter().copied())
        .output()
        .expect("the program runs");
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The sponsor pays the gas (owner's decisions 14.10, 15.10 "A"): with
/// `--gas sponsor` the writer on the contract is the smart account of the
/// `--evm-key`, every anchor goes as a UserOperation through the bundler and
/// paymaster at `KSG_PAYMASTER_URL`, and the key itself never sends a
/// transaction; a transfer of rights hands the seat to the buyer's account.
#[test]
fn sponsored_gas_anchors_from_the_smart_account() {
    use mock_base::account_of;
    let d = Dir::new("sponsored");
    let node = MockBase::start();
    let key = key_file(&d, "evm.key", 0x42);
    let contract = node.contract();
    let init = |home: &str, gas: &str| {
        vec![
            "--home".to_owned(),
            home.to_owned(),
            "init".into(),
            "--class".into(),
            "light".into(),
            "--base-rpc".into(),
            node.url.clone(),
            "--base-contract".into(),
            contract.clone(),
            "--evm-key".into(),
            key.clone(),
            "--gas".into(),
            gas.into(),
        ]
    };
    let fails_v = |v: Vec<String>| fails(&v.iter().map(String::as_str).collect::<Vec<_>>());

    // The flag is checked, and the sponsor's address is not optional.
    let e = fails_v(init(&d.p("x"), "maybe"));
    assert!(e.contains("--gas must be self or sponsor"), "{e}");
    let e = fails(&[
        "--home",
        &d.p("y"),
        "init",
        "--class",
        "light",
        "--gas",
        "sponsor",
    ]);
    assert!(e.contains("--gas sponsor goes with --base-rpc"), "{e}");
    let e = fails_v(init(&d.p("z"), "sponsor"));
    assert!(e.contains("KSG_PAYMASTER_URL"), "{e}");

    let env = [("KSG_PAYMASTER_URL", node.url.as_str())];
    let (home, half) = (d.p("home"), d.p("m.half"));
    let v = init(&home, "sponsor");
    let out = ok_env(&v.iter().map(String::as_str).collect::<Vec<_>>(), &env);
    assert!(out.contains("anchored   Base Sepolia"), "{out}");
    assert_eq!(base_cfg(&home)["sponsored"], true);
    for a in [
        vec!["--home", &home, "packet"],
        vec!["--home", &home, "buyer-key"],
        vec!["--home", &home, "--mobile", &half, "initiate"],
        vec!["--home", &home, "--mobile", &half, "open-journal"],
        vec!["--home", &home, "--mobile", &half, "work", "--did", "one"],
    ] {
        ok_env(&a, &env);
    }
    let seller = account_of(&evm_address(0x42));
    let h = chain_head(&node, &home);
    assert_eq!(h.writer, seller, "the smart account writes");
    {
        let c = node.chain.lock().unwrap();
        assert!(c.ops.len() >= 2 && c.ops.iter().all(|o| o.2), "{:?}", c.ops);
        assert_eq!(
            c.pm_calls,
            2 * c.ops.len() as u32,
            "stub and final per operation"
        );
        assert!(c.nonces.is_empty(), "no plain transaction was sent");
    }

    // A transfer of rights: the seat goes to the buyer's smart account.
    let buyer = key_file(&d, "buyer.key", 0x43);
    let out = ok_env(
        &[
            "--home",
            &home,
            "--mobile",
            &half,
            "owner-change",
            "--evm-key",
            &buyer,
        ],
        &env,
    );
    assert!(out.contains("handed     Base Sepolia"), "{out}");
    assert_eq!(
        chain_head(&node, &home).writer,
        account_of(&evm_address(0x43))
    );
    export_env(&home, &half, &d.p("p.json"), &env);
    let h = chain_head(&node, &home);
    assert_eq!(h.writer, account_of(&evm_address(0x43)));
    assert!(node.chain.lock().unwrap().nonces.is_empty());
}

fn export_env(home: &str, half: &str, out: &str, env: &[(&str, &str)]) {
    ok_env(
        &[
            "--home",
            home,
            "--mobile",
            half,
            "export-page",
            "--number",
            "1",
            "--by",
            "owner",
            "--out",
            out,
        ],
        env,
    );
}

fn run_env(args: &[&str], env: &[(&str, &str)]) -> Output {
    Command::new(KSG)
        .args(args)
        .env("KSG_BASE_WAIT_SECS", "10")
        .envs(env.iter().copied())
        .output()
        .expect("the program runs")
}

/// The live run of 16.10: a node that answers but will not give the logs
/// (a free node limits `eth_getLogs` to a few blocks) let a container its
/// client declared lost open as offline and anchor again. Now nothing goes
/// on the chain until the loss is read, and the logs are read from the
/// block before the first anchor in spans such a node answers.
#[test]
fn a_node_without_logs_lets_nothing_go_out_over_a_loss() {
    let d = Dir::new("nologs");
    let node = MockBase::start();
    let (home, half) = (d.p("home"), d.p("m.half"));
    light(&d, &node, &home, &half);
    let from = base_cfg(&home)["from_block"]
        .as_u64()
        .expect("the first anchor records where the logs start");
    ok(&["--home", &home, "--mobile", &half, "work", "--did", "one"]);
    let payer = key_file(&d, "payer.key", 0x51);
    let t = anchor_key(&half);
    let out = lost(
        &node,
        "declare-lost",
        &t,
        &["--half", &half, "--evm-key", &payer],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let before = count(&node, &home);

    // The node refuses every log question: the file opens as offline, but
    // a page — which goes out only on a fresh anchor — does not.
    node.chain.lock().unwrap().log_span = Some(0);
    let out = run_env(
        &[
            "--home",
            &home,
            "--mobile",
            &half,
            "export-page",
            "--number",
            "1",
            "--by",
            "client",
            "--out",
            &d.p("p.json"),
        ],
        &[],
    );
    assert!(!out.status.success());
    let e = String::from_utf8_lossy(&out.stderr);
    assert!(e.contains("loss check"), "{e}");
    assert_eq!(count(&node, &home), before, "nothing went on the chain");

    // A node limited to ten blocks answers in spans: the loss is read and
    // the container does not open.
    node.chain.lock().unwrap().log_span = Some(10);
    let span = [("KSG_BASE_LOG_SPAN", "10")];
    let out = run_env(
        &["--home", &home, "--mobile", &half, "work", "--did", "two"],
        &span,
    );
    assert!(!out.status.success());
    let e = String::from_utf8_lossy(&out.stderr);
    assert!(e.contains("declared this container lost"), "{e}");
    // lost-status reads it the same way from the block it is given.
    let contract = node.contract();
    let from_s = from.to_string();
    let out = run_env(
        &[
            "lost-status",
            "--anchor-key",
            &t,
            "--base-rpc",
            &node.url,
            "--base-contract",
            &contract,
            "--from-block",
            &from_s,
        ],
        &span,
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("lost       declared at"));
    assert_eq!(count(&node, &home), before);
}

/// A node limited to a range of blocks (GetBlock: 1 000) on a chain far
/// past block 1 000: printing a `light` reads the loss from the block it is
/// printed at, not from block 0, and the first anchor goes out.
#[test]
fn a_range_limited_node_prints_a_light() {
    let d = Dir::new("ranged");
    let node = MockBase::start();
    {
        let mut c = node.chain.lock().unwrap();
        c.block = 5_000;
        c.log_span = Some(1_000);
    }
    let (home, half) = (d.p("home"), d.p("m.half"));
    light(&d, &node, &home, &half);
    let from = base_cfg(&home)["from_block"].as_u64().unwrap();
    assert!(from >= 4_999, "{from}");
    ok(&["--home", &home, "--mobile", &half, "work", "--did", "one"]);
    let payer = key_file(&d, "payer.key", 0x51);
    let t = anchor_key(&half);
    let from_s = from.to_string();
    let out = lost(
        &node,
        "declare-lost",
        &t,
        &[
            "--half",
            &half,
            "--evm-key",
            &payer,
            "--from-block",
            &from_s,
        ],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let e = fails(&["--home", &home, "--mobile", &half, "work", "--did", "two"]);
    assert!(e.contains("declared this container lost"), "{e}");
}

/// The live run of 17.10: a node's address carries the provider's key, and
/// `container.json` is not a secret file. `--base-rpc env:NAME` keeps the
/// address in the environment: the file holds the name, the anchors go.
#[test]
fn the_node_address_may_stay_in_the_environment() {
    let d = Dir::new("env-rpc");
    let node = MockBase::start();
    let key = key_file(&d, "evm.key", 0x42);
    let (home, half) = (d.p("home"), d.p("m.half"));
    let env = [("KSG_TEST_BASE_RPC", node.url.as_str())];
    let contract = node.contract();
    let out = ok_env(
        &[
            "--home",
            &home,
            "init",
            "--class",
            "light",
            "--base-rpc",
            "env:KSG_TEST_BASE_RPC",
            "--base-contract",
            &contract,
            "--evm-key",
            &key,
        ],
        &env,
    );
    assert!(out.contains("anchored   Base Sepolia"), "{out}");
    assert_eq!(base_cfg(&home)["rpc"], "env:KSG_TEST_BASE_RPC");
    let meta = std::fs::read_to_string(Path::new(&home).join("container.json")).unwrap();
    assert!(
        !meta.contains(&node.url),
        "the address is in container.json"
    );
    for a in [
        vec!["--home", &home, "packet"],
        vec!["--home", &home, "buyer-key"],
        vec!["--home", &home, "--mobile", &half, "initiate"],
    ] {
        ok_env(&a, &env);
    }
    assert_eq!(count(&node, &home), 2, "Ya-1 and Ya-2 went out");
    // Without the variable: a plain refusal that names it.
    let out = run_env(&["--home", &home, "--mobile", &half, "open-journal"], &[]);
    let e = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success() || e.contains("KSG_TEST_BASE_RPC"),
        "{e}"
    );
}

/// The issuance label of a `bare` (owner's decisions 17.10): the owner sets
/// a read key of its own, the container answers with it, the issuer seals
/// the label (whose, when, by whom) to it on the network; whoever holds the
/// read key reads it, and nobody else does. At an owner's change the former
/// owner passes it on: a duplicate sealed to the new owner's read key, on
/// the network and in the journal.
#[test]
fn the_issuance_label_is_read_with_the_owners_key_and_passes_on_with_the_owner() {
    let d = Dir::new("label");
    let node = MockBase::start();
    let contract = node.contract();
    let issuer_key = key_file(&d, "issuer.key", 0x43);
    let payer = key_file(&d, "payer.key", 0x44);
    let check = d.p("check.key");
    std::fs::write(&check, hex::encode([0x77u8; 32])).unwrap();
    let (home, half) = (d.p("bare"), d.p("a.half"));
    ok(&["--home", &home, "init", "--class", "bare"]);
    ok(&["--home", &home, "buyer-key"]);
    ok(&["--home", &home, "--mobile", &half, "initiate"]);
    ok(&["--home", &home, "--mobile", &half, "open-journal"]);

    // 1–2: the owner's read key and the container's answer with it.
    let read_a = d.p("a.read");
    let printed = ok(&["--home", &home, "owner-read-key", "--out", &read_a]);
    let answer = d.p("answer.json");
    let answered = ok(&["--home", &home, "label-key", "--out", &answer]);
    assert_eq!(
        printed.lines().find(|l| l.starts_with("read key")),
        answered.lines().find(|l| l.starts_with("read key")),
        "the container answers with the key the owner set"
    );

    // The issuer: the issuance anchor and the label, sealed to that key.
    let put = ok(&[
        "issue-anchor",
        "put",
        "--check-key",
        &check,
        "--docs",
        "email:alice@example.com",
        "--release",
        "ksg:em:test:000001",
        "--version",
        "0.2",
        "--base-rpc",
        &node.url,
        "--base-contract",
        &contract,
        "--evm-key",
        &issuer_key,
        "--year",
        "2026",
        "--label-for",
        &answer,
    ]);
    assert!(put.contains("labelled"), "{put}");
    let read_label = |key: &str| {
        ok(&[
            "issue-anchor",
            "label",
            "--read-key",
            key,
            "--base-rpc",
            &node.url,
            "--base-contract",
            &contract,
            "--from-block",
            "0",
        ])
    };
    let mine = read_label(&read_a);
    let issuer = ksg_anchor_v2::evm::hex0x(&evm_address(0x43));
    assert!(mine.contains(&issuer), "who issued: {mine}");
    assert!(mine.contains("passes     0"), "{mine}");
    // Another key reads nothing: the network does not see the label.
    let stranger = d.p("stranger.read");
    std::fs::write(&stranger, hex::encode([0x55u8; 32])).unwrap();
    assert!(read_label(&stranger).contains("none opens"));

    // 3: the owner's change; the label passes on with the owner.
    let new_owner = d.p("new-owner");
    ok(&["--home", &new_owner, "init", "--class", "bare"]);
    let pages = |h: &str| -> u64 {
        ok(&["--home", h, "status"])
            .lines()
            .find_map(|l| l.strip_prefix("pages").map(|v| v.trim().parse().unwrap()))
            .unwrap()
    };
    let before = pages(&home);
    let moved = ok(&[
        "--home",
        &home,
        "--mobile",
        &half,
        "owner-change",
        "--new-owner-home",
        &new_owner,
        "--base-rpc",
        &node.url,
        "--base-contract",
        &contract,
        "--evm-key",
        &payer,
        "--from-block",
        "0",
    ]);
    assert!(moved.contains("label      passed on"), "{moved}");
    // The transfer page and the label's record in the journal.
    assert!(
        pages(&home) >= before + 2,
        "the duplicate is in the journal"
    );
    let read_b = d.p("b.read");
    ok(&["--home", &home, "owner-read-key", "--out", &read_b]);
    let theirs = read_label(&read_b);
    assert!(theirs.contains("passes     1"), "{theirs}");
    assert!(
        theirs.contains(&issuer),
        "still issued by the issuer: {theirs}"
    );
    // The former owner still reads the label as it was issued.
    assert!(read_label(&read_a).contains("passes     0"));
    assert_ne!(
        std::fs::read(&read_a).unwrap(),
        std::fs::read(&read_b).unwrap(),
        "a new owner, a new read key"
    );
}

/// The issuance label passes on at an attachment too, as a step of it
/// (owner's decision 17.10 "B"): the owner's change, the label (a record in
/// the journal and a note on the network, sealed to the leader's owner's
/// read key), the hand-off, the coupling page.
#[test]
fn the_issuance_label_passes_to_the_leaders_owner_as_a_step_of_the_attachment() {
    let d = Dir::new("label-attach");
    let node = MockBase::start();
    let contract = node.contract();
    let issuer_key = key_file(&d, "issuer.key", 0x43);
    let payer = key_file(&d, "payer.key", 0x44);
    let check = d.p("check.key");
    std::fs::write(&check, hex::encode([0x77u8; 32])).unwrap();
    let (home, half) = (d.p("bare"), d.p("a.half"));
    ok(&["--home", &home, "init", "--class", "bare"]);
    ok(&["--home", &home, "buyer-key"]);
    ok(&["--home", &home, "--mobile", &half, "initiate"]);
    ok(&["--home", &home, "--mobile", &half, "open-journal"]);
    let answer = d.p("answer.json");
    ok(&["--home", &home, "label-key", "--out", &answer]);
    let read_a = d.p("a.read");
    ok(&["--home", &home, "owner-read-key", "--out", &read_a]);
    ok(&[
        "issue-anchor",
        "put",
        "--check-key",
        &check,
        "--docs",
        "email:alice@example.com",
        "--release",
        "ksg:em:test:000001",
        "--version",
        "0.2",
        "--base-rpc",
        &node.url,
        "--base-contract",
        &contract,
        "--evm-key",
        &issuer_key,
        "--year",
        "2026",
        "--label-for",
        &answer,
    ]);

    let (leader, lh) = (d.p("leader"), d.p("leader.half"));
    ok(&["--home", &leader, "init", "--class", "heavy"]);
    ok(&["--home", &leader, "packet"]);
    ok(&["--home", &leader, "buyer-key"]);
    ok(&["--home", &leader, "--mobile", &lh, "initiate"]);
    ok(&["--home", &leader, "--mobile", &lh, "open-journal"]);

    let out = ok(&[
        "--home",
        &home,
        "--mobile",
        &half,
        "attach-to",
        "--leader-home",
        &leader,
        "--agent",
        "did:key:zLeaderAgent",
        "--new-mobile",
        &d.p("leader-agent.half"),
        "--base-rpc",
        &node.url,
        "--base-contract",
        &contract,
        "--evm-key",
        &payer,
        "--from-block",
        "0",
    ]);
    assert!(out.contains("attached"), "{out}");
    let status = ok(&["--home", &home, "status"]);
    assert!(
        status.contains("attached as a trailer: read-only"),
        "{status}"
    );

    // The leader's owner — the bare's owner now — reads the label passed on.
    let read_b = d.p("b.read");
    ok(&["--home", &home, "owner-read-key", "--out", &read_b]);
    let label = |key: &str| {
        ok(&[
            "issue-anchor",
            "label",
            "--read-key",
            key,
            "--base-rpc",
            &node.url,
            "--base-contract",
            &contract,
            "--from-block",
            "0",
        ])
    };
    let theirs = label(&read_b);
    assert!(theirs.contains("passes     1"), "{theirs}");
    assert!(
        theirs.contains(&ksg_anchor_v2::evm::hex0x(&evm_address(0x43))),
        "still issued by the issuer: {theirs}"
    );
    assert!(
        label(&read_a).contains("passes     0"),
        "the former owner reads its own"
    );
}

/// Where the issuance label is read from the network, `--from-block` is
/// required (owner's decision 18.10): reading from block 0 is not done.
#[test]
fn reading_the_label_from_the_network_needs_a_starting_block() {
    let d = Dir::new("label-from");
    let node = MockBase::start();
    let contract = node.contract();
    let key = d.p("r.read");
    std::fs::write(&key, hex::encode([0x55u8; 32])).unwrap();
    let e = fails(&[
        "issue-anchor",
        "label",
        "--read-key",
        &key,
        "--base-rpc",
        &node.url,
        "--base-contract",
        &contract,
    ]);
    assert!(e.contains("--from-block"), "{e}");
    let payer = key_file(&d, "payer.key", 0x44);
    let (home, half, other) = (d.p("bare"), d.p("a.half"), d.p("other"));
    ok(&["--home", &home, "init", "--class", "bare"]);
    ok(&["--home", &home, "buyer-key"]);
    ok(&["--home", &home, "--mobile", &half, "initiate"]);
    ok(&["--home", &home, "--mobile", &half, "open-journal"]);
    ok(&["--home", &other, "init", "--class", "bare"]);
    let e = fails(&[
        "--home",
        &home,
        "--mobile",
        &half,
        "owner-change",
        "--new-owner-home",
        &other,
        "--base-rpc",
        &node.url,
        "--base-contract",
        &contract,
        "--evm-key",
        &payer,
    ]);
    assert!(e.contains("--from-block"), "{e}");
}

/// Transfers to new owners one after another on Base Sepolia (owner's
/// decision 18.10 "A"): each hands the writer's seat on the contract to the
/// arriving owner's EVM key, and the next anchor is that key's.
#[test]
fn transfers_to_new_owners_hand_the_writer_over_each_time() {
    let d = Dir::new("handover-chain");
    let node = MockBase::start();
    let (home, half) = (d.p("home"), d.p("m.half"));
    light(&d, &node, &home, &half);
    ok(&["--home", &home, "--mobile", &half, "work", "--did", "one"]);
    for (n, byte) in [0x51u8, 0x52, 0x53].into_iter().enumerate() {
        let o = d.p(&format!("owner{n}"));
        ok(&["--home", &o, "init", "--class", "light"]);
        let e = fails(&[
            "--home",
            &home,
            "--mobile",
            &half,
            "owner-change",
            "--new-owner-home",
            &o,
        ]);
        assert!(e.contains("--evm-key"), "{n}: {e}");
        let k = key_file(&d, &format!("o{n}.key"), byte);
        ok(&[
            "--home",
            &home,
            "--mobile",
            &half,
            "owner-change",
            "--new-owner-home",
            &o,
            "--evm-key",
            &k,
        ]);
        assert_eq!(chain_head(&node, &home).writer, evm_address(byte), "{n}");
        assert_eq!(base_cfg(&home)["key"], k.as_str());
        assert!(base_cfg(&home)["hand_to"].is_null());
        export(&home, &half, "owner", &d.p("p.json"));
        assert_eq!(chain_head(&node, &home).writer, evm_address(byte), "{n}");
    }
}

/// Sent, landed, the confirmation never seen (a timeout, the node gone half-way):
/// the anchor is this file's own. The next opening finds it at the head and
/// takes it as `last` — the file is not a copy, and goes on anchoring.
#[test]
fn an_anchor_landed_unconfirmed_is_settled_at_the_next_opening() {
    let d = Dir::new("unconfirmed-open");
    let node = MockBase::start();
    let (home, half) = (d.p("home"), d.p("m.half"));
    light(&d, &node, &home, &half);
    ok(&["--home", &home, "--mobile", &half, "work", "--did", "one"]);
    let before = count(&node, &home);

    node.chain.lock().unwrap().lose_confirmations = true;
    let e = fails(&[
        "--home", &home, "--mobile", &half, "export-page", "--number", "1", "--by", "owner",
        "--out", &d.p("p.json"),
    ]);
    assert!(e.contains("did not take it"), "{e}");
    // It landed all the same; the file only knows it was sent.
    assert_eq!(count(&node, &home), before + 1);
    assert_eq!(base_cfg(&home)["pending"].as_array().map(Vec::len), Some(1));
    let head = ksg_anchor_v2::evm::hex0x(&chain_head(&node, &home).last);
    assert_ne!(base_cfg(&home)["last"].as_str(), Some(head.as_str()));

    node.chain.lock().unwrap().lose_confirmations = false;
    ok(&["--home", &home, "--mobile", &half, "work", "--did", "two"]);
    assert_eq!(base_cfg(&home)["last"].as_str(), Some(head.as_str()));
    assert!(base_cfg(&home)["pending"].is_null());
    export(&home, &half, "owner", &d.p("p.json"));
    assert_eq!(count(&node, &home), before + 2);
}

/// The same, when the opening could not read the head: the anchor that is
/// due reads it first and settles the lost one before it continues it.
#[test]
fn an_anchor_landed_unconfirmed_is_settled_before_the_next_anchor() {
    let d = Dir::new("unconfirmed-anchor");
    let node = MockBase::start();
    let (home, half) = (d.p("home"), d.p("m.half"));
    light(&d, &node, &home, &half);
    ok(&["--home", &home, "--mobile", &half, "work", "--did", "one"]);
    let before = count(&node, &home);

    node.chain.lock().unwrap().lose_confirmations = true;
    fails(&[
        "--home", &home, "--mobile", &half, "export-page", "--number", "1", "--by", "owner",
        "--out", &d.p("p.json"),
    ]);
    assert_eq!(count(&node, &home), before + 1);
    {
        let mut c = node.chain.lock().unwrap();
        c.lose_confirmations = false;
        // The check at opening is cut once; the anchor's own read is not.
        c.drop = Some(ksg_verify_v2::base::HEAD_SELECTOR);
        c.drop_left = Some(1);
    }
    ok(&["--home", &home, "--mobile", &half, "work", "--did", "two"]);
    export(&home, &half, "owner", &d.p("p2.json"));
    assert!(base_cfg(&home)["pending"].is_null());
    assert_eq!(count(&node, &home), before + 2);
}
