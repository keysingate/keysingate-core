//! P-8: the channel end to end — the issuer, a distributor, its agents, a
//! packet, a container on one of its serials — and every way the chain is
//! refused when one link does not hold.

mod mock_base;
mod mock_devnet;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use ed25519_dalek::SigningKey;
use ksg_anchor_v2::solana_tx::address;
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::KeySet;
use ksg_core_v2::doc::Class;
use ksg_verify_v2::channel::{verify_channel, ChannelProof};
use ksg_verify_v2::solana::{HttpRpc, SolanaReader};
use ksg_verify_v2::{keys_from_json, verify_bytes, Expected, NoReader};
use mock_devnet::MockDevnet;

const KSG: &str = env!("CARGO_BIN_EXE_ksg-remote-panel");

struct Dir(PathBuf);
impl Dir {
    fn new(name: &str) -> Self {
        let d = std::env::temp_dir().join(format!("ksg-channel-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Self(d)
    }
    fn p(&self, n: &str) -> String {
        self.0.join(n).to_str().unwrap().to_owned()
    }
}
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run(args: &[&str]) -> Output {
    Command::new(KSG)
        .args(args)
        .env("KSG_ANCHOR_WAIT_S", "10")
        .output()
        .unwrap()
}

/// Runs `ksg`. `ROLE sell … --out FILE` in these tests is the seller's two
/// commands: `order` (no serials taken), then `confirm-payment` on the order
/// it opened, which issues the packet into FILE.
fn ksg(args: &[&str]) -> Output {
    if args.get(1) != Some(&"sell") {
        return run(args);
    }
    let at = args.iter().position(|a| *a == "--out").expect("sell --out");
    let desk = args[args.iter().position(|a| *a == "--desk").unwrap() + 1];
    let mut ord: Vec<&str> = vec![args[0], "order"];
    ord.extend(args[2..at].iter());
    ord.extend(args[at + 2..].iter());
    let o = run(&ord);
    if !o.status.success() {
        return o;
    }
    let out = String::from_utf8_lossy(&o.stdout).into_owned();
    let id = out
        .split_whitespace()
        .find(|w| w.starts_with("ord-"))
        .expect("an order number")
        .to_owned();
    run(&[
        args[0],
        "confirm-payment",
        "--desk",
        desk,
        "--order",
        &id,
        "--out",
        args[at + 1],
    ])
}
fn ok(args: &[&str]) -> String {
    let o = ksg(args);
    assert!(
        o.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8_lossy(&o.stdout).into_owned()
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

/// The issuer and one distributor; returns the distributor's desk.
fn issuer_and_distributor(d: &Dir) {
    ok(&[
        "issuer",
        "init",
        "--desk",
        &d.p("issuer"),
        "--release",
        "ksg:em:test:000001",
        "--range",
        "1-1000000",
    ]);
    ok(&[
        "distributor",
        "init",
        "--desk",
        &d.p("dist"),
        "--name",
        "did:key:zDist",
    ]);
    ok(&[
        "issuer",
        "grant",
        "--desk",
        &d.p("issuer"),
        "--to",
        "did:key:zDist",
        "--keys",
        &d.p("dist/keys.json"),
        "--size",
        "200000",
        "--out",
        &d.p("g-dist.json"),
    ]);
    ok(&[
        "distributor",
        "accept",
        "--desk",
        &d.p("dist"),
        "--grant",
        &d.p("g-dist.json"),
        "--emission",
        &d.p("issuer/emission.json"),
    ]);
}

/// A sub-agent `name` of desk `from`, granted `size` serials.
fn agent(d: &Dir, from: &str, name: &str, size: &str) {
    let did = format!("did:key:z{name}");
    ok(&["distributor", "init", "--desk", &d.p(name), "--name", &did]);
    ok(&[
        "distributor",
        "grant",
        "--desk",
        &d.p(from),
        "--to",
        &did,
        "--keys",
        &d.p(&format!("{name}/keys.json")),
        "--size",
        size,
        "--out",
        &d.p(&format!("g-{name}.json")),
    ]);
    ok(&[
        "distributor",
        "accept",
        "--desk",
        &d.p(name),
        "--grant",
        &d.p(&format!("g-{name}.json")),
        "--emission",
        &d.p("issuer/emission.json"),
    ]);
}

fn live(d: &Dir, home: &str, extra_init: &[&str]) {
    let m = d.p("m.half");
    let (sale, issuer) = (d.p("sale.json"), d.p("issuer"));
    let mut init = vec![
        "--home",
        home,
        "init",
        "--sale",
        &sale,
        "--issuer-desk",
        &issuer,
    ];
    init.extend_from_slice(extra_init);
    ok(&init);
    std::fs::write(d.p("policy.txt"), b"POLICY 1").unwrap();
    ok(&["--home", home, "packet"]);
    ok(&["--home", home, "buyer-key"]);
    ok(&["--home", home, "--mobile", &m, "initiate"]);
    ok(&["--home", home, "--mobile", &m, "open-journal"]);
    ok(&[
        "--home",
        home,
        "--mobile",
        &m,
        "attach",
        "--type",
        "urn:ksg:page:policy:v1",
        "--file",
        &d.p("policy.txt"),
    ]);
    ok(&["--home", home, "finalize"]);
    ok(&[
        "--home",
        home,
        "--mobile",
        &m,
        "export-final",
        "--out",
        &d.p("export.json"),
    ]);
    ok(&["--home", home, "keys", "--out", &d.p("keys.json")]);
    ok(&["--home", home, "channel", "--out", &d.p("channel.json")]);
}

/// The holder URI of `home`'s owner, to sell a packet to (KS-5).
fn holder(d: &Dir, home: &str) -> String {
    ok(&["--home", &d.p(home), "holder"]).trim().to_owned()
}

fn id(home: &str) -> Hash {
    let m: serde_json::Value =
        serde_json::from_slice(&std::fs::read(Path::new(home).join("container.json")).unwrap())
            .unwrap();
    Hash::from_multihash(m["id"].as_str().unwrap()).unwrap()
}

fn read_proof(d: &Dir) -> ChannelProof {
    serde_json::from_slice(&std::fs::read(d.p("channel.json")).unwrap()).unwrap()
}
fn issuer_keys(d: &Dir) -> KeySet {
    keys_from_json(&std::fs::read(d.p("issuer/issuer-keys.json")).unwrap()).unwrap()
}
fn client_keys(d: &Dir) -> KeySet {
    keys_from_json(&std::fs::read(d.p("keys.json")).unwrap()).unwrap()
}

#[test]
fn issuer_distributor_agent_enterprise_container_verified_alone() {
    let d = Dir::new("life");
    issuer_and_distributor(&d);
    agent(&d, "dist", "AgentB", "50000");
    ok(&[
        "distributor",
        "sell",
        "--desk",
        &d.p("AgentB"),
        "--to",
        &holder(&d, "box"),
        "--class",
        "light",
        "--size",
        "10000",
        "--out",
        &d.p("sale.json"),
    ]);
    let home = d.p("box");
    live(&d, &home, &["--serial", "7"]);

    let proof = read_proof(&d);
    let r = verify_channel(&proof, &id(&home), &issuer_keys(&d), &client_keys(&d)).unwrap();
    assert_eq!((r.serial, r.class), (7, Class::Light));
    assert_eq!(r.channel, ["did:key:zDist", "did:key:zAgentB"]);
    assert_eq!(r.holder, holder(&d, "box"));

    // The export, checked as the class the packet names.
    let rep = verify_bytes(
        &std::fs::read(d.p("export.json")).unwrap(),
        &Expected {
            container: id(&home),
            class: r.class,
            keys: client_keys(&d),
            anchors: &NoReader,
        },
    );
    assert!(rep.accepted, "{rep:?}");
}

#[test]
fn every_broken_link_refuses_the_channel() {
    let d = Dir::new("broken");
    issuer_and_distributor(&d);
    ok(&[
        "distributor",
        "sell",
        "--desk",
        &d.p("dist"),
        "--to",
        &holder(&d, "box"),
        "--class",
        "light",
        "--size",
        "10000",
        "--out",
        &d.p("sale.json"),
    ]);
    let home = d.p("box");
    live(&d, &home, &[]);
    let (p, c, ik, ck) = (read_proof(&d), id(&home), issuer_keys(&d), client_keys(&d));
    assert!(verify_channel(&p, &c, &ik, &ck).is_ok());

    // Another container.
    assert!(verify_channel(&p, &Hash::sha256(b"other"), &ik, &ck)
        .unwrap_err()
        .contains("another container"));
    // Keys the verifier does not hold as the issuer's.
    let stranger: KeySet = [ksg_core_v2::crypto::sign::Ed25519Signer::from_seed(
        ksg_core_v2::doc::Uri::parse("did:key:zKsgIssuer#k1").unwrap(),
        [1; 32],
    )
    .public()]
    .into_iter()
    .collect();
    assert!(verify_channel(&p, &c, &stranger, &ck)
        .unwrap_err()
        .contains("release"));
    // Pages checked with another client's keys.
    let other_client: KeySet = [ksg_core_v2::crypto::sign::Ed25519Signer::from_seed(
        ksg_core_v2::doc::Uri::parse("did:key:zKsgClient#k1").unwrap(),
        [2; 32],
    )
    .public()]
    .into_iter()
    .collect();
    assert!(verify_channel(&p, &c, &ik, &other_client).is_err());
    // A bigger packet than was sold: the seller's signature no longer holds.
    let mut q = p.clone();
    q.packet.block.to.0 += 1;
    assert!(verify_channel(&q, &c, &ik, &ck)
        .unwrap_err()
        .contains("packet"));
    // A wider grant than was given.
    let mut q = p.clone();
    q.chain[0].range.to.0 += 1;
    assert!(verify_channel(&q, &c, &ik, &ck)
        .unwrap_err()
        .contains("channel"));
    // The grant left out: the distributor's signature is not the issuer's.
    let mut q = p.clone();
    q.chain.clear();
    assert!(verify_channel(&q, &c, &ik, &ck)
        .unwrap_err()
        .contains("packet"));
    // Another serial claimed for the same container.
    let mut q = p.clone();
    q.init.serial.0 += 1;
    assert!(verify_channel(&q, &c, &ik, &ck).is_err());
    // The binding swapped for another.
    let mut q = p.clone();
    q.binding.bound_at = ksg_core_v2::doc::Timestamp::parse("2099-01-01T00:00:00.000Z").unwrap();
    assert!(verify_channel(&q, &c, &ik, &ck).is_err());
    // KS-5: someone else signs the binding as the holder and presents their
    // own key under the owner's key id. The packet pins the buyer's key.
    use ksg_core_v2::crypto::sign::{sign_doc, Ed25519Signer, SignatureSet};
    let mallory = Ed25519Signer::from_seed(
        ksg_core_v2::doc::Uri::parse("did:key:zKsgOwner#k1").unwrap(),
        [9; 32],
    );
    let mut q = p.clone();
    let mut sigs: Vec<_> = q
        .binding
        .signatures
        .as_slice()
        .iter()
        .filter(|s| s.kid.as_str() != "did:key:zKsgOwner#k1")
        .cloned()
        .collect();
    sigs.push(sign_doc(&q.binding, &mallory).unwrap());
    q.binding.signatures = SignatureSet::new(sigs);
    q.holder_keys = vec![mallory.public()];
    assert!(verify_channel(&q, &c, &ik, &ck)
        .unwrap_err()
        .contains("not by the key the packet was sold to"));
    // The same, with the buyer's key presented next to the forger's.
    q.holder_keys.push(p.holder_keys[0].clone());
    assert!(verify_channel(&q, &c, &ik, &ck).is_err());
    // A packet whose holder names no key is nobody's to bind.
    let mut q = p.clone();
    q.packet.holder = ksg_core_v2::doc::Uri::parse("did:key:zEnterprise").unwrap();
    assert!(verify_channel(&q, &c, &ik, &ck).is_err());
}

#[test]
fn a_packet_prints_only_for_the_one_it_was_sold_to() {
    let d = Dir::new("ks5");
    issuer_and_distributor(&d);
    // Sold to Alice.
    ok(&[
        "distributor",
        "sell",
        "--desk",
        &d.p("dist"),
        "--to",
        &holder(&d, "alice"),
        "--class",
        "light",
        "--size",
        "10000",
        "--out",
        &d.p("sale.json"),
    ]);
    // Bob holds a copy of Alice's sale file: it does not print for him.
    holder(&d, "bob");
    let err = fails(&[
        "--home",
        &d.p("bob"),
        "init",
        "--sale",
        &d.p("sale.json"),
        "--issuer-desk",
        &d.p("issuer"),
    ]);
    assert!(err.contains("was sold to"), "{err}");
    // Nor for a home with no holder made beforehand.
    fails(&[
        "--home",
        &d.p("carol"),
        "init",
        "--sale",
        &d.p("sale.json"),
        "--issuer-desk",
        &d.p("issuer"),
    ]);
    // A seller cannot sell to a name that carries no key.
    let err = fails(&[
        "distributor",
        "sell",
        "--desk",
        &d.p("dist"),
        "--to",
        "did:key:zAlice",
        "--class",
        "light",
        "--size",
        "10000",
        "--out",
        &d.p("s2.json"),
    ]);
    assert!(err.contains("holder URI"), "{err}");
    // Alice prints it; asking her holder again gives the same URI.
    let a = holder(&d, "alice");
    live(&d, &d.p("alice"), &[]);
    assert_eq!(holder(&d, "alice"), a);
    let r = verify_channel(
        &read_proof(&d),
        &id(&d.p("alice")),
        &issuer_keys(&d),
        &client_keys(&d),
    )
    .unwrap();
    assert_eq!(r.holder, a);
}

#[test]
fn serials_go_out_once_and_only_inside_the_grant() {
    let d = Dir::new("serials");
    issuer_and_distributor(&d);
    let s1 = ok(&[
        "distributor",
        "sell",
        "--desk",
        &d.p("dist"),
        "--to",
        &holder(&d, "x"),
        "--class",
        "heavy",
        "--size",
        "10",
        "--out",
        &d.p("s1.json"),
    ]);
    let s2 = ok(&[
        "distributor",
        "sell",
        "--desk",
        &d.p("dist"),
        "--to",
        &holder(&d, "hb"),
        "--class",
        "heavy",
        "--size",
        "10",
        "--out",
        &d.p("s2.json"),
    ]);
    assert!(s1.contains("serials 1-10"), "{s1}");
    assert!(s2.contains("serials 11-20"), "{s2}");
    // The issuer's own sales start after what it granted.
    let s3 = ok(&[
        "issuer",
        "sell",
        "--desk",
        &d.p("issuer"),
        "--to",
        &holder(&d, "hc"),
        "--class",
        "heavy",
        "--size",
        "10",
        "--out",
        &d.p("s3.json"),
    ]);
    assert!(s3.contains("serials 200001-200010"), "{s3}");
    // Past the grant: refused.
    agent(&d, "dist", "Small", "15");
    fails(&[
        "distributor",
        "sell",
        "--desk",
        &d.p("Small"),
        "--to",
        &holder(&d, "hd"),
        "--class",
        "heavy",
        "--size",
        "16",
        "--out",
        &d.p("s4.json"),
    ]);
    // A size the class is not sold in.
    fails(&[
        "distributor",
        "sell",
        "--desk",
        &d.p("dist"),
        "--to",
        &holder(&d, "he"),
        "--class",
        "light",
        "--size",
        "10",
        "--out",
        &d.p("s5.json"),
    ]);
    // A serial outside the packet does not print.
    std::fs::copy(d.p("s1.json"), d.p("sale.json")).unwrap();
    fails(&[
        "--home",
        &d.p("x"),
        "init",
        "--sale",
        &d.p("sale.json"),
        "--issuer-desk",
        &d.p("issuer"),
        "--serial",
        "11",
    ]);
    // Nor on a desk that is not the release's issuer.
    ok(&[
        "issuer",
        "init",
        "--desk",
        &d.p("issuer2"),
        "--release",
        "ksg:em:test:000002",
        "--range",
        "1-100",
    ]);
    fails(&[
        "--home",
        &d.p("y"),
        "init",
        "--sale",
        &d.p("sale.json"),
        "--issuer-desk",
        &d.p("issuer2"),
    ]);
    fails(&[
        "--home",
        &d.p("z"),
        "init",
        "--sale",
        &d.p("sale.json"),
        "--issuer-desk",
        &d.p("dist"),
    ]);
}

#[test]
fn the_channel_stops_four_levels_below_the_issuer_and_at_180_days() {
    let d = Dir::new("depth");
    issuer_and_distributor(&d); // level 0
    agent(&d, "dist", "L1", "100000");
    agent(&d, "L1", "L2", "50000");
    agent(&d, "L2", "L3", "20000");
    agent(&d, "L3", "L4", "10000");
    // A fifth level is past the channel limit.
    ok(&[
        "distributor",
        "init",
        "--desk",
        &d.p("L5"),
        "--name",
        "did:key:zL5",
    ]);
    let err = fails(&[
        "distributor",
        "grant",
        "--desk",
        &d.p("L4"),
        "--to",
        "did:key:zL5",
        "--keys",
        &d.p("L5/keys.json"),
        "--size",
        "10",
        "--out",
        &d.p("g-L5.json"),
    ]);
    assert!(err.contains("limit"), "{err}");
    // A grant longer than 180 days.
    ok(&[
        "distributor",
        "init",
        "--desk",
        &d.p("long"),
        "--name",
        "did:key:zLong",
    ]);
    let err = fails(&[
        "issuer",
        "grant",
        "--desk",
        &d.p("issuer"),
        "--to",
        "did:key:zLong",
        "--keys",
        &d.p("long/keys.json"),
        "--size",
        "10",
        "--days",
        "181",
        "--out",
        &d.p("g-long.json"),
    ]);
    assert!(err.contains("180 days"), "{err}");
    // A grant for other keys is not accepted by this desk.
    ok(&[
        "distributor",
        "init",
        "--desk",
        &d.p("thief"),
        "--name",
        "did:key:zThief",
    ]);
    let err = fails(&[
        "distributor",
        "accept",
        "--desk",
        &d.p("thief"),
        "--grant",
        &d.p("g-L1.json"),
        "--emission",
        &d.p("issuer/emission.json"),
    ]);
    assert!(err.contains("other keys"), "{err}");
}

#[test]
fn a_heavy_container_of_the_channel_anchored_on_devnet() {
    let d = Dir::new("heavy");
    let net = MockDevnet::start();
    let k = SigningKey::from_bytes(&[3; 32]);
    let mut all = k.to_bytes().to_vec();
    all.extend_from_slice(k.verifying_key().as_bytes());
    std::fs::write(d.p("payer.json"), serde_json::to_vec(&all).unwrap()).unwrap();
    net.fund(&address(&k.verifying_key()), 1_000_000_000);

    issuer_and_distributor(&d);
    ok(&[
        "distributor",
        "sell",
        "--desk",
        &d.p("dist"),
        "--to",
        &holder(&d, "box"),
        "--class",
        "heavy",
        "--size",
        "10",
        "--out",
        &d.p("sale.json"),
    ]);
    let home = d.p("box");
    live(
        &d,
        &home,
        &[
            "--anchor",
            "solana:devnet",
            "--payer",
            &d.p("payer.json"),
            "--rpc",
            &net.url,
        ],
    );

    let r = verify_channel(
        &read_proof(&d),
        &id(&home),
        &issuer_keys(&d),
        &client_keys(&d),
    )
    .unwrap();
    assert_eq!(r.class, Class::Heavy);
    let rpc = HttpRpc::new(&net.url).unwrap();
    let out = d.p("scan.key");
    ok(&["--home", &home, "scan-key", "--out", &out]);
    let reader = SolanaReader::connect(&rpc, "devnet")
        .unwrap()
        .with_scan_keys(
            ksg_verify_v2::solana::scan_keys_from_text(&std::fs::read_to_string(&out).unwrap())
                .unwrap(),
        );
    let rep = verify_bytes(
        &std::fs::read(d.p("export.json")).unwrap(),
        &Expected {
            container: id(&home),
            class: r.class,
            keys: client_keys(&d),
            anchors: &reader,
        },
    );
    assert!(rep.accepted, "{rep:?}");
}

#[test]
fn the_issuer_prints_one_container_per_serial() {
    let d = Dir::new("once");
    issuer_and_distributor(&d);
    ok(&[
        "distributor",
        "sell",
        "--desk",
        &d.p("dist"),
        "--to",
        &holder(&d, "a"),
        "--class",
        "heavy",
        "--size",
        "10",
        "--out",
        &d.p("sale.json"),
    ]);
    let print = |home: &str, serial: &str| {
        ksg(&[
            "--home",
            &d.p(home),
            "init",
            "--sale",
            &d.p("sale.json"),
            "--issuer-desk",
            &d.p("issuer"),
            "--serial",
            serial,
        ])
    };
    // A print refused before the serial is spent leaves it free: here the
    // home belongs to someone the packet was not sold to.
    holder(&d, "stranger");
    assert!(!print("stranger", "3").status.success());
    assert!(print("a", "3").status.success());
    // The same holder's keys in a second home: the issuer does not print
    // serial 3 again.
    std::fs::create_dir_all(d.p("b")).unwrap();
    std::fs::copy(d.p("a/parties.json"), d.p("b/parties.json")).unwrap();
    let o = print("b", "3");
    assert_eq!(o.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("printed already"),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(!Path::new(&d.p("b/container.ksg")).exists());
    // Another serial of the packet prints.
    assert!(print("b", "4").status.success());
    // Both containers of the packet carry one binding: the same document, so
    // neither is the other's rival. The documents are made at initiation
    // (CH-5b).
    for home in ["a", "b"] {
        ok(&["--home", &d.p(home), "packet"]);
        ok(&["--home", &d.p(home), "buyer-key"]);
        ok(&[
            "--home",
            &d.p(home),
            "--mobile",
            &d.p(&format!("{home}.half")),
            "initiate",
        ]);
    }
    let proof = |home: &str| -> ChannelProof {
        serde_json::from_slice(&std::fs::read(d.p(&format!("{home}/channel.json"))).unwrap())
            .unwrap()
    };
    let (pa, pb) = (proof("a"), proof("b"));
    assert_eq!(pa.binding, pb.binding);
    assert_ne!(
        pa.init.agent, pb.init.agent,
        "each container has its own client key"
    );
    use ksg_core_v2::doc::binding::{check_binding_uniqueness, Uniqueness};
    assert_eq!(
        check_binding_uniqueness(std::slice::from_ref(&pa.binding), &pb.binding).unwrap(),
        Uniqueness::Proven
    );
    let ik = issuer_keys(&d);
    for (home, p) in [("a", &pa), ("b", &pb)] {
        let ck: KeySet = [p.init.agent.clone()].into_iter().collect();
        verify_channel(p, &id(&d.p(home)), &ik, &ck).unwrap();
    }
    // A desk left locked by a print in progress refuses a second print.
    std::fs::create_dir_all(d.p("c")).unwrap();
    std::fs::copy(d.p("a/parties.json"), d.p("c/parties.json")).unwrap();
    std::fs::write(d.p("issuer/lock"), b"").unwrap();
    let o = print("c", "5");
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("another reader"),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    std::fs::remove_file(d.p("issuer/lock")).unwrap();
    assert!(print("c", "5").status.success());
}

#[test]
fn every_key_of_the_prototype_is_a_public_test_key() {
    use ksg_verify_v2::testkeys::{is_test_issuer_key, seed};
    let d = Dir::new("testkeys");
    // Only test releases are issued.
    let o = ksg(&[
        "issuer",
        "init",
        "--desk",
        &d.p("real"),
        "--release",
        "ksg:em:000001",
        "--range",
        "1-1000",
    ]);
    let err = String::from_utf8_lossy(&o.stderr);
    assert_eq!(o.status.code(), Some(2), "{err}");
    assert!(err.contains("only test releases"), "{err}");
    assert!(!Path::new(&d.p("real/desk.json")).exists());
    issuer_and_distributor(&d);
    // The issuer's key is the public test key, recomputable by anybody.
    let ik = issuer_keys(&d);
    assert!(ik.keys().all(is_test_issuer_key));
    // The owner's key is the test key named after the home.
    let owner = ksg_core_v2::crypto::sign::Ed25519Signer::from_seed(
        ksg_core_v2::doc::Uri::parse("did:key:zKsgOwner#k1").unwrap(),
        seed("owner:alice"),
    );
    assert_eq!(
        holder(&d, "alice"),
        ksg_verify_v2::channel::holder_uri(&owner.public()).unwrap()
    );
    // A container of the prototype reports its release as a test one.
    ok(&[
        "distributor",
        "sell",
        "--desk",
        &d.p("dist"),
        "--to",
        &holder(&d, "alice"),
        "--class",
        "light",
        "--size",
        "10000",
        "--out",
        &d.p("sale.json"),
    ]);
    live(&d, &d.p("alice"), &[]);
    let r = verify_channel(&read_proof(&d), &id(&d.p("alice")), &ik, &client_keys(&d)).unwrap();
    assert!(r.test);
}

#[test]
fn a_packet_is_issued_only_on_confirmed_payment() {
    let d = Dir::new("pay");
    issuer_and_distributor(&d);
    let order = |to: &str, size: &str| {
        let out = ok(&[
            "distributor",
            "order",
            "--desk",
            &d.p("dist"),
            "--to",
            to,
            "--class",
            "heavy",
            "--size",
            size,
        ]);
        assert!(out.contains("awaiting payment"), "{out}");
        out.split_whitespace()
            .find(|w| w.starts_with("ord-"))
            .unwrap()
            .to_owned()
    };
    let confirm = |id: &str, out: &str| {
        ksg(&[
            "distributor",
            "confirm-payment",
            "--desk",
            &d.p("dist"),
            "--order",
            id,
            "--out",
            &d.p(out),
        ])
    };
    let (a, b) = (holder(&d, "a"), holder(&d, "b"));
    let o1 = order(&a, "10");
    let o2 = order(&b, "10");
    assert_ne!(o1, o2);
    // An order takes no serials: the one paid first gets the first ones.
    let s2 = String::from_utf8_lossy(&confirm(&o2, "s2.json").stdout).into_owned();
    assert!(s2.contains("serials 1-10"), "{s2}");
    let s1 = String::from_utf8_lossy(&confirm(&o1, "s1.json").stdout).into_owned();
    assert!(s1.contains("serials 11-20"), "{s1}");
    // Paid once: the order is closed.
    assert_eq!(confirm(&o1, "again.json").status.code(), Some(1));
    assert!(!Path::new(&d.p("again.json")).exists());
    // No such order.
    assert_eq!(confirm("ord-99", "x.json").status.code(), Some(1));
    // An order that can never be served is not taken: past the grant.
    let err = fails(&[
        "distributor",
        "order",
        "--desk",
        &d.p("dist"),
        "--to",
        &a,
        "--class",
        "heavy",
        "--size",
        "999999999",
    ]);
    assert!(!err.is_empty());
    // The packet's origin is the payment, not the order.
    let sale: serde_json::Value =
        serde_json::from_slice(&std::fs::read(d.p("s1.json")).unwrap()).unwrap();
    let paid = sale["packet"]["allocated_at"].as_str().unwrap().to_owned();
    let desk: serde_json::Value =
        serde_json::from_slice(&std::fs::read(d.p("dist/desk.json")).unwrap()).unwrap();
    assert!(desk.get("orders").is_none(), "all orders paid");
    assert!(!paid.is_empty());
}

#[test]
fn containers_of_a_packet_are_printed_from_its_template() {
    let d = Dir::new("template");
    issuer_and_distributor(&d);
    ok(&[
        "distributor",
        "sell",
        "--desk",
        &d.p("dist"),
        "--to",
        &holder(&d, "a"),
        "--class",
        "heavy",
        "--size",
        "3",
        "--out",
        &d.p("sale.json"),
    ]);
    let t = d.p("template.json");
    let out = ok(&[
        "issuer",
        "template",
        "--desk",
        &d.p("issuer"),
        "--sale",
        &d.p("sale.json"),
        "--out",
        &t,
    ]);
    assert!(out.contains("3 to print"), "{out}");
    // Once per packet.
    let err = fails(&[
        "issuer",
        "template",
        "--desk",
        &d.p("issuer"),
        "--sale",
        &d.p("sale.json"),
        "--out",
        &d.p("t2.json"),
    ]);
    assert!(err.contains("issued already"), "{err}");
    // Only the release's issuer issues it.
    ok(&[
        "issuer",
        "init",
        "--desk",
        &d.p("issuer2"),
        "--release",
        "ksg:em:test:000002",
        "--range",
        "1-100",
    ]);
    fails(&[
        "issuer",
        "template",
        "--desk",
        &d.p("issuer2"),
        "--sale",
        &d.p("sale.json"),
        "--out",
        &d.p("t3.json"),
    ]);

    let print = |home: &str, extra: &[&str]| {
        let mut a = vec![
            "--home".to_owned(),
            d.p(home),
            "init".into(),
            "--template".into(),
            t.clone(),
        ];
        a.extend(extra.iter().map(|s| (*s).to_owned()));
        let a: Vec<&str> = a.iter().map(String::as_str).collect();
        ksg(&a)
    };
    let copy_parties = |home: &str| {
        std::fs::create_dir_all(d.p(home)).unwrap();
        std::fs::copy(d.p("a/parties.json"), d.p(&format!("{home}/parties.json"))).unwrap();
    };

    // The first container: the earliest serial of the quota, at status 2.
    let o = print("a", &[]);
    let so = String::from_utf8_lossy(&o.stdout).into_owned();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(
        so.contains("serial     1") && so.contains("status     2"),
        "{so}"
    );
    // Its life goes on from the template's state: initiation, journal, export.
    let (home, m) = (d.p("a"), d.p("a.half"));
    std::fs::write(d.p("policy.txt"), b"POLICY 1").unwrap();
    ok(&["--home", &home, "--mobile", &m, "initiate"]);
    ok(&["--home", &home, "--mobile", &m, "open-journal"]);
    ok(&[
        "--home",
        &home,
        "--mobile",
        &m,
        "attach",
        "--type",
        "urn:ksg:page:policy:v1",
        "--file",
        &d.p("policy.txt"),
    ]);
    ok(&["--home", &home, "finalize"]);
    ok(&["--home", &home, "keys", "--out", &d.p("keys.json")]);
    ok(&["--home", &home, "channel", "--out", &d.p("channel.json")]);
    let r = verify_channel(
        &read_proof(&d),
        &id(&home),
        &issuer_keys(&d),
        &client_keys(&d),
    )
    .unwrap();
    assert_eq!((r.serial, r.class, r.test), (1, Class::Heavy, true));

    // The desk no longer prints the packet's serials itself.
    copy_parties("desk");
    let err = fails(&[
        "--home",
        &d.p("desk"),
        "init",
        "--sale",
        &d.p("sale.json"),
        "--issuer-desk",
        &d.p("issuer"),
        "--serial",
        "3",
    ]);
    assert!(err.contains("template"), "{err}");
    // A serial printed from the template is not printed again.
    copy_parties("b");
    let o = print("b", &["--serial", "1"]);
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("printed already"),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    // Outside the quota: refused.
    assert!(!print("b", &["--serial", "4"]).status.success());
    // A print in progress holds the template.
    std::fs::write(format!("{t}.lock"), b"").unwrap();
    assert!(!print("b", &[]).status.success());
    std::fs::remove_file(format!("{t}.lock")).unwrap();
    // The rest of the quota, then no more.
    let o = print("b", &[]);
    assert!(String::from_utf8_lossy(&o.stdout).contains("serial     2"));
    copy_parties("c");
    let o = print("c", &[]);
    assert!(String::from_utf8_lossy(&o.stdout).contains("serial     3"));
    copy_parties("e");
    let o = print("e", &[]);
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("used up"),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    // Someone the packet was not sold to prints nothing from it.
    holder(&d, "stranger");
    assert!(!print("stranger", &[]).status.success());
    // --template prints on its own.
    let o = ksg(&[
        "--home",
        &d.p("z"),
        "init",
        "--template",
        &t,
        "--sale",
        &d.p("sale.json"),
    ]);
    assert_eq!(o.status.code(), Some(2));
}

#[test]
fn the_test_kit_holds_every_party_and_works_with_templates() {
    let d = Dir::new("kit");
    let kit = d.p("kit");
    let o = Command::new("bash")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../demo/testkit.sh"
        ))
        .env("KIT", &kit)
        .env("KSG", KSG)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let m: serde_json::Value =
        serde_json::from_slice(&std::fs::read(format!("{kit}/MANIFEST.json")).unwrap()).unwrap();
    let roles: Vec<&str> = m["parties"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["role"].as_str().unwrap())
        .collect();
    for r in ["issuer", "channel", "holder"] {
        assert!(roles.contains(&r), "{r} missing from {roles:?}");
    }
    // Core v2 has no transparency log, so its kit has no log key.
    assert!(!roles.contains(&"log"), "a log key in the kit of core v2");
    // Every key is the public test key of its label.
    for p in m["parties"].as_array().unwrap() {
        let label = p["label"].as_str().unwrap();
        let kid = ksg_core_v2::doc::Uri::parse(p["kid"].as_str().unwrap()).unwrap();
        let expect = ksg_core_v2::crypto::sign::Ed25519Signer::from_seed(
            kid,
            ksg_verify_v2::testkeys::seed(label),
        )
        .public();
        assert_eq!(p["key"].as_str().unwrap(), expect.key, "{label}");
    }
    // Each of the kit's packets goes into a template, and a container is
    // printed from it with no change to either.
    for (sale, h, issuer) in [
        ("sale-a", "holder-a", "issuer"),
        ("sale-b", "holder-b", "issuer"),
        ("sale-c", "holder-c", "issuer-light"),
    ] {
        let t = format!("{kit}/holders/{h}/template.json");
        ok(&[
            "issuer",
            "template",
            "--desk",
            &format!("{kit}/{issuer}"),
            "--sale",
            &format!("{kit}/sales/{sale}.json"),
            "--out",
            &t,
        ]);
        ok(&[
            "--home",
            &format!("{kit}/holders/{h}"),
            "init",
            "--template",
            &t,
        ]);
    }
}

/// Audit of 30.09, Ya-7: the holder closes the packet, the bundle carries the
/// statement, and the verifier sees the packet accounted for — or refuses a
/// statement that cancels the container's own serial.
#[test]
fn the_holders_closing_statement_accounts_for_the_packet() {
    let d = Dir::new("closure");
    issuer_and_distributor(&d);
    ok(&[
        "distributor",
        "sell",
        "--desk",
        &d.p("dist"),
        "--to",
        &holder(&d, "box"),
        "--class",
        "light",
        "--size",
        "10000",
        "--out",
        &d.p("sale.json"),
    ]);
    let home = d.p("box");
    live(&d, &home, &[]);
    let p = read_proof(&d);
    let r = verify_channel(&p, &id(&home), &issuer_keys(&d), &client_keys(&d)).unwrap();
    assert!(!r.closed, "no statement yet");
    let (block, serial) = (p.packet.block, p.init.serial.0);

    // A statement that leaves this container's serial unused: cancelled by
    // its own holder — refused, and nothing is laid.
    let other = if serial == block.from.0 {
        format!("{}-{}", block.to.0, block.to.0)
    } else {
        format!("{}-{}", block.from.0, block.from.0)
    };
    let err = fails(&["--home", &home, "close-packet", "--used", &other]);
    assert!(err.contains("cancelled serial"), "{err}");

    // The serial used: the packet is closed, and the bundle says so.
    ok(&[
        "--home",
        &home,
        "close-packet",
        "--used",
        &format!("{serial}-{serial}"),
    ]);
    ok(&["--home", &home, "channel", "--out", &d.p("channel.json")]);
    let p = read_proof(&d);
    let c = p.closure.as_ref().expect("the statement is in the bundle");
    assert_eq!(c.block, block);
    let r = verify_channel(&p, &id(&home), &issuer_keys(&d), &client_keys(&d)).unwrap();
    assert!(r.closed);
    // Closed once.
    let err = fails(&[
        "--home",
        &home,
        "close-packet",
        "--used",
        &format!("{serial}-{serial}"),
    ]);
    assert!(err.contains("already closed"), "{err}");
    // A statement altered after signing does not hold.
    let mut forged = p.clone();
    if let Some(c) = forged.closure.as_mut() {
        c.cancelled.clear();
    }
    assert!(verify_channel(&forged, &id(&home), &issuer_keys(&d), &client_keys(&d)).is_err());
}

/// The desk keeps every order with what happened to it
/// (`ksg_issuer_v2::fulfilment`): placed, then paid, issued and handed over in
/// one act; an unpaid order may be cancelled, a paid one may not.
#[test]
fn the_desk_keeps_the_road_of_every_order() {
    let d = Dir::new("orders");
    issuer_and_distributor(&d);
    let buyer = holder(&d, "box");
    let place = |size: &str| {
        let out = ok(&[
            "distributor",
            "order",
            "--desk",
            &d.p("dist"),
            "--to",
            &buyer,
            "--class",
            "light",
            "--size",
            size,
        ]);
        out.split_whitespace()
            .find(|w| w.starts_with("ord-"))
            .expect("an order number")
            .to_owned()
    };
    let first = place("10000");
    let second = place("10000");
    let book = ok(&["distributor", "orders", "--desk", &d.p("dist")]);
    assert!(book.contains(&format!("{first:<10} Ordered")), "{book}");

    ok(&[
        "distributor",
        "confirm-payment",
        "--desk",
        &d.p("dist"),
        "--order",
        &first,
        "--out",
        &d.p("sale.json"),
    ]);
    ok(&[
        "distributor",
        "cancel",
        "--desk",
        &d.p("dist"),
        "--order",
        &second,
        "--reason",
        "buyer withdrew",
    ]);
    let book = ok(&["distributor", "orders", "--desk", &d.p("dist")]);
    assert!(book.contains(&format!("{first:<10} Delivered")), "{book}");
    assert!(book.contains(&format!("{second:<10} Cancelled")), "{book}");

    // Paid is not cancelled; cancelled is not paid.
    fails(&[
        "distributor",
        "cancel",
        "--desk",
        &d.p("dist"),
        "--order",
        &first,
        "--reason",
        "late",
    ]);
    fails(&[
        "distributor",
        "confirm-payment",
        "--desk",
        &d.p("dist"),
        "--order",
        &second,
        "--out",
        &d.p("sale2.json"),
    ]);
    // Nothing has run out yet.
    assert!(ok(&["distributor", "expire", "--desk", &d.p("dist")]).contains("expired    none"));
}

/// Step 8 of the order: the desk takes the holder's closing statement from
/// the channel bundle, and the order is closed — once, by the holder the
/// packet was sold to, and only for that packet.
#[test]
fn the_desk_closes_an_order_on_the_holders_statement() {
    let d = Dir::new("desk-close");
    issuer_and_distributor(&d);
    let buyer = holder(&d, "box");
    let out = ok(&[
        "distributor",
        "order",
        "--desk",
        &d.p("dist"),
        "--to",
        &buyer,
        "--class",
        "light",
        "--size",
        "10000",
    ]);
    let id = out
        .split_whitespace()
        .find(|w| w.starts_with("ord-"))
        .expect("an order number")
        .to_owned();
    ok(&[
        "distributor",
        "confirm-payment",
        "--desk",
        &d.p("dist"),
        "--order",
        &id,
        "--out",
        &d.p("sale.json"),
    ]);
    let home = d.p("box");
    live(&d, &home, &[]);
    let close = |order: &str| {
        ksg(&[
            "distributor",
            "close",
            "--desk",
            &d.p("dist"),
            "--order",
            order,
            "--channel",
            &d.p("channel.json"),
        ])
    };

    // No statement in the bundle yet: nothing to accept.
    assert_eq!(close(&id).status.code(), Some(1));

    let serial = read_proof(&d).init.serial.0;
    ok(&[
        "--home",
        &home,
        "close-packet",
        "--used",
        &format!("{serial}-{serial}"),
    ]);
    ok(&["--home", &home, "channel", "--out", &d.p("channel.json")]);
    let pristine = std::fs::read(d.p("channel.json")).unwrap();

    // A statement altered after signing is refused, and the order stays open.
    let mut forged = read_proof(&d);
    if let Some(c) = forged.closure.as_mut() {
        c.cancelled.clear();
    }
    std::fs::write(d.p("channel.json"), serde_json::to_vec(&forged).unwrap()).unwrap();
    assert_eq!(close(&id).status.code(), Some(1));
    let book = ok(&["distributor", "orders", "--desk", &d.p("dist")]);
    assert!(book.contains(&format!("{id:<10} Delivered")), "{book}");

    // The bundle is not the holder's to re-key: a stranger's keys do not sign.
    let mut rekeyed = read_proof(&d);
    rekeyed.closure = serde_json::from_slice::<ChannelProof>(&pristine)
        .unwrap()
        .closure;
    rekeyed.holder_keys.clear();
    std::fs::write(d.p("channel.json"), serde_json::to_vec(&rekeyed).unwrap()).unwrap();
    assert_eq!(close(&id).status.code(), Some(1));

    // The statement as signed: closed, one serial used.
    std::fs::write(d.p("channel.json"), &pristine).unwrap();
    let done = String::from_utf8_lossy(&close(&id).stdout).into_owned();
    assert!(done.contains("1 serial(s) used"), "{done}");
    let book = ok(&["distributor", "orders", "--desk", &d.p("dist")]);
    assert!(book.contains(&format!("{id:<10} Closed")), "{book}");
    // Taking the same statement again changes nothing.
    assert_eq!(close(&id).status.code(), Some(0));
    // An order with no packet issued has nothing to close.
    assert_eq!(close("ord-99").status.code(), Some(1));
}

/// The holder who closed a packet can buy the next one: the desk keeps the
/// closures it took and hands the last one to the ledger (§7 rule 3 —
/// `prev_closure` from the second block on). Before the fix the desk passed
/// none, and the second packet to the same holder was always refused.
#[test]
fn a_holder_who_closed_a_packet_buys_the_next_one() {
    let d = Dir::new("desk-second");
    issuer_and_distributor(&d);
    let buyer = holder(&d, "box");
    let order_one = || {
        let out = ok(&[
            "distributor",
            "order",
            "--desk",
            &d.p("dist"),
            "--to",
            &buyer,
            "--class",
            "heavy",
            "--size",
            "1",
        ]);
        out.split_whitespace()
            .find(|w| w.starts_with("ord-"))
            .expect("an order number")
            .to_owned()
    };
    let pay = |id: &str, out: &str| {
        ok(&[
            "distributor",
            "confirm-payment",
            "--desk",
            &d.p("dist"),
            "--order",
            id,
            "--out",
            &d.p(out),
        ])
    };

    let first = order_one();
    pay(&first, "sale.json");
    let home = d.p("box");
    live(&d, &home, &[]);

    // The first packet is not closed yet: the next one is refused.
    let early = fails(&[
        "distributor",
        "order",
        "--desk",
        &d.p("dist"),
        "--to",
        &buyer,
        "--class",
        "heavy",
        "--size",
        "1",
    ]);
    assert!(early.contains("closure"), "{early}");

    let serial = read_proof(&d).init.serial.0;
    ok(&[
        "--home",
        &home,
        "close-packet",
        "--used",
        &format!("{serial}-{serial}"),
    ]);
    ok(&["--home", &home, "channel", "--out", &d.p("channel.json")]);
    ok(&[
        "distributor",
        "close",
        "--desk",
        &d.p("dist"),
        "--order",
        &first,
        "--channel",
        &d.p("channel.json"),
    ]);

    // Closed in full: the second packet is ordered, paid and chained to the
    // first one's closure.
    let second = order_one();
    pay(&second, "sale2.json");
    let sale: serde_json::Value =
        serde_json::from_slice(&std::fs::read(d.p("sale2.json")).unwrap()).unwrap();
    assert!(
        sale["packet"]["prev_closure"].is_string(),
        "the second packet names the first one's closure: {sale}"
    );
}

/// A `light` export read on Base Sepolia (gap 15.10, the key in the export):
/// the verifier makes the blind key itself — the template from the release
/// and serial the channel proves, and the salt written beside the export —
/// and finds where the export's seal stands among the container's anchors.
#[test]
fn a_light_export_is_read_on_base_under_the_key_the_channel_makes() {
    use ksg_verify_v2::base::{export_on_base, OnChain};
    let d = Dir::new("base-export");
    issuer_and_distributor(&d);
    agent(&d, "dist", "AgentB", "50000");
    ok(&[
        "distributor",
        "sell",
        "--desk",
        &d.p("AgentB"),
        "--to",
        &holder(&d, "box"),
        "--class",
        "light",
        "--size",
        "10000",
        "--out",
        &d.p("sale.json"),
    ]);
    let node = mock_base::MockBase::start();
    let evm = d.p("evm.key");
    std::fs::write(&evm, hex::encode([0x42u8; 32])).unwrap();
    let (home, m) = (d.p("box"), d.p("m.half"));
    ok(&[
        "--home",
        &home,
        "init",
        "--sale",
        &d.p("sale.json"),
        "--issuer-desk",
        &d.p("issuer"),
        "--serial",
        "7",
        "--base-rpc",
        &node.url,
        "--base-contract",
        &node.contract(),
        "--evm-key",
        &evm,
    ]);
    ok(&["--home", &home, "packet"]);
    ok(&["--home", &home, "buyer-key"]);
    ok(&["--home", &home, "--mobile", &m, "initiate"]);
    ok(&["--home", &home, "--mobile", &m, "open-journal"]);
    let page = |did: &str, n: &str, out: &str| {
        ok(&["--home", &home, "--mobile", &m, "work", "--did", did]);
        let o = ok(&[
            "--home",
            &home,
            "--mobile",
            &m,
            "export-page",
            "--number",
            n,
            "--by",
            "client",
            "--out",
            &d.p(out),
        ]);
        assert!(o.contains(".base.json"), "{o}");
    };
    page("one", "1", "p1.json");
    ok(&["--home", &home, "keys", "--out", &d.p("keys.json")]);
    ok(&["--home", &home, "channel", "--out", &d.p("channel.json")]);
    let r = verify_channel(
        &read_proof(&d),
        &id(&home),
        &issuer_keys(&d),
        &client_keys(&d),
    )
    .unwrap();

    let side: serde_json::Value =
        serde_json::from_slice(&std::fs::read(d.p("p1.json.base.json")).unwrap()).unwrap();
    let contract: [u8; 20] =
        hex::decode(side["contract"].as_str().unwrap().trim_start_matches("0x"))
            .unwrap()
            .try_into()
            .unwrap();
    let salt: [u8; 32] = hex::decode(side["salt"].as_str().unwrap().trim_start_matches("0x"))
        .unwrap()
        .try_into()
        .unwrap();
    let rpc = HttpRpc::new(&node.url).unwrap();
    let at = |f: &str, salt: &[u8; 32]| {
        export_on_base(
            &rpc,
            &contract,
            &r.release,
            r.serial,
            salt,
            &std::fs::read(d.p(f)).unwrap(),
            0,
        )
    };
    assert!(matches!(at("p1.json", &salt), Ok(OnChain::Last { .. })));

    // The container goes on: the first page's seal is passed, the new one is last.
    page("two", "2", "p2.json");
    assert!(matches!(
        at("p1.json", &salt),
        Ok(OnChain::Passed { after: 1, .. })
    ));
    assert!(matches!(at("p2.json", &salt), Ok(OnChain::Last { .. })));

    // Another salt makes a key no container anchors under: the page is refused.
    let e = at("p2.json", &[7u8; 32]).unwrap_err();
    assert!(e.contains("never anchored"), "{e}");
}

/// C-bis, `[decision]` 10.09 (KS-8): time counts from the purchase of the
/// packet — the initiation's offset is the time since the packet was
/// allocated (`BlockAllocation::origin`), not since the release.
#[test]
fn the_initiations_offset_counts_from_the_packets_purchase() {
    let d = Dir::new("origin");
    issuer_and_distributor(&d);
    ok(&[
        "distributor",
        "sell",
        "--desk",
        &d.p("dist"),
        "--to",
        &holder(&d, "box"),
        "--class",
        "light",
        "--size",
        "10000",
        "--out",
        &d.p("sale.json"),
    ]);
    let sale: serde_json::Value =
        serde_json::from_slice(&std::fs::read(d.p("sale.json")).unwrap()).unwrap();
    let allocated = ksg_verify_v2::clock::parse_ms(
        &serde_json::from_value(sale["packet"]["allocated_at"].clone()).unwrap(),
    )
    .unwrap();
    let issued = ksg_verify_v2::clock::parse_ms(
        &serde_json::from_value(sale["emission"]["issued_at"].clone()).unwrap(),
    )
    .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let before = ksg_verify_v2::clock::now_ms();
    live(&d, &d.p("box"), &[]);
    let after = ksg_verify_v2::clock::now_ms();
    let offset = read_proof(&d).init.offset_ms;
    assert!(
        (before - allocated..=after - allocated).contains(&offset),
        "offset {offset} is not the time since the packet ({}..={})",
        before - allocated,
        after - allocated
    );
    assert!(allocated > issued, "the packet was sold after the release");
    assert!(
        offset < after - issued,
        "counted from the release, not the packet"
    );
}

/// T-05 (KS-7), G-2 and H-7 (KS-8): a container is made only within the
/// quota bought — a serial outside the packet does not print, so it never
/// reaches initiation.
#[test]
fn a_serial_outside_the_packet_does_not_print() {
    let d = Dir::new("quota");
    issuer_and_distributor(&d);
    ok(&[
        "distributor",
        "sell",
        "--desk",
        &d.p("dist"),
        "--to",
        &holder(&d, "box"),
        "--class",
        "light",
        "--size",
        "10000",
        "--out",
        &d.p("sale.json"),
    ]);
    let e = fails(&[
        "--home",
        &d.p("box"),
        "init",
        "--sale",
        &d.p("sale.json"),
        "--issuer-desk",
        &d.p("issuer"),
        "--serial",
        "999999",
    ]);
    assert!(e.contains("is not in the packet"), "{e}");
    assert!(!Path::new(&d.p("box")).join("container.json").exists());
}

fn sold_and_working(d: &Dir, home: &str, sale: &str, half: &str, seat: Option<&str>) {
    ok(&[
        "--home",
        home,
        "init",
        "--sale",
        sale,
        "--issuer-desk",
        &d.p("issuer"),
    ]);
    match seat {
        Some(seat) => ok(&["--home", home, "packet", "--seat", seat]),
        None => ok(&["--home", home, "packet"]),
    };
    ok(&["--home", home, "buyer-key"]);
    ok(&["--home", home, "--mobile", half, "initiate"]);
    ok(&["--home", home, "--mobile", half, "open-journal"]);
}

fn sell(d: &Dir, desk: &str, who: &str, home: &str, out: &str) {
    ok(&[
        who,
        "sell",
        "--desk",
        &d.p(desk),
        "--to",
        &holder(d, home),
        "--class",
        "heavy",
        "--size",
        "10",
        "--out",
        &d.p(out),
    ]);
}

/// C-12, owner's decisions 17.10 ("B"; "give the distributor a module to add
/// its key"): the distributor that sold a packet signs its seat at its desk
/// (`distributor seat`), the holder hands it to `packet --seat`, and the
/// container takes it only when the document checks against the sale and the
/// container's issuer. Then `declare-dead` — the owner alone, or the
/// distributor with the client.
#[test]
fn the_distributor_seats_itself_and_declares_a_container_dead_with_the_client() {
    let d = Dir::new("dead");
    issuer_and_distributor(&d);

    // The distributor's module: its seat for the packet it sold.
    let (home, half) = (d.p("box"), d.p("box.half"));
    sell(&d, "dist", "distributor", "box", "sale.json");
    let out = ok(&[
        "distributor",
        "seat",
        "--desk",
        &d.p("dist"),
        "--sale",
        &d.p("sale.json"),
        "--out",
        &d.p("seat.json"),
    ]);
    assert!(out.contains("seat       did:key:zDist"), "{out}");
    // Only the seller signs a seat: the issuer's desk, another distributor's — no.
    let e = fails(&[
        "distributor",
        "seat",
        "--desk",
        &d.p("issuer"),
        "--sale",
        &d.p("sale.json"),
        "--out",
        &d.p("x.json"),
    ]);
    assert!(e.contains("not a distributor's desk"), "{e}");
    agent(&d, "dist", "Other", "100");
    let e = fails(&[
        "distributor",
        "seat",
        "--desk",
        &d.p("Other"),
        "--sale",
        &d.p("sale.json"),
        "--out",
        &d.p("x.json"),
    ]);
    assert!(e.contains("did not sell this packet"), "{e}");

    // A seat altered on the way does not seat anybody.
    let mut forged: serde_json::Value =
        serde_json::from_slice(&std::fs::read(d.p("seat.json")).unwrap()).unwrap();
    forged["holder"] = serde_json::json!(holder(&d, "elsewhere"));
    std::fs::write(d.p("forged.json"), serde_json::to_vec(&forged).unwrap()).unwrap();
    ok(&[
        "--home",
        &home,
        "init",
        "--sale",
        &d.p("sale.json"),
        "--issuer-desk",
        &d.p("issuer"),
    ]);
    let e = fails(&["--home", &home, "packet", "--seat", &d.p("forged.json")]);
    assert!(e.contains("another packet or another holder"), "{e}");

    // The real one seats the distributor; with the client it declares dead.
    let out = ok(&["--home", &home, "packet", "--seat", &d.p("seat.json")]);
    assert!(out.contains("seated     did:key:zDist"), "{out}");
    ok(&["--home", &home, "buyer-key"]);
    ok(&["--home", &home, "--mobile", &half, "initiate"]);
    ok(&["--home", &home, "--mobile", &half, "open-journal"]);
    let e = fails(&[
        "--home",
        &home,
        "--mobile",
        &half,
        "declare-dead",
        "--distributor-desk",
        &d.p("issuer"),
    ]);
    assert!(e.contains("not a distributor's desk"), "{e}");
    let out = ok(&[
        "--home",
        &home,
        "--mobile",
        &half,
        "declare-dead",
        "--distributor-desk",
        &d.p("dist"),
    ]);
    assert!(
        out.contains("declared by the distributor with the client"),
        "{out}"
    );
    assert!(ok(&["--home", &home, "status"]).contains("KeyLost"));
    fails(&["--home", &home, "--mobile", &half, "work", "--did", "after"]);

    // Sold through the distributor, but no seat handed over: nobody seated.
    let (home3, half3) = (d.p("box3"), d.p("box3.half"));
    sell(&d, "dist", "distributor", "box3", "sale3.json");
    sold_and_working(&d, &home3, &d.p("sale3.json"), &half3, None);
    let e = fails(&[
        "--home",
        &home3,
        "--mobile",
        &half3,
        "declare-dead",
        "--distributor-desk",
        &d.p("dist"),
    ]);
    assert!(e.contains("no distributor is seated"), "{e}");
    // Another packet's seat does not fit this container.
    let (home4, half4) = (d.p("box4"), d.p("box4.half"));
    sell(&d, "dist", "distributor", "box4", "sale4.json");
    ok(&[
        "--home",
        &home4,
        "init",
        "--sale",
        &d.p("sale4.json"),
        "--issuer-desk",
        &d.p("issuer"),
    ]);
    let e = fails(&["--home", &home4, "packet", "--seat", &d.p("seat.json")]);
    assert!(e.contains("another packet or another holder"), "{e}");
    let _ = half4;

    // A direct sale by the issuer: there is no seat to sign.
    let (home2, half2) = (d.p("box2"), d.p("box2.half"));
    sell(&d, "issuer", "issuer", "box2", "sale2.json");
    let e = fails(&[
        "distributor",
        "seat",
        "--desk",
        &d.p("dist"),
        "--sale",
        &d.p("sale2.json"),
        "--out",
        &d.p("x.json"),
    ]);
    assert!(e.contains("sold this packet directly"), "{e}");
    sold_and_working(&d, &home2, &d.p("sale2.json"), &half2, None);
    // The owner alone always can.
    let out = ok(&["--home", &home2, "declare-dead"]);
    assert!(out.contains("declared by the owner"), "{out}");
    assert!(ok(&["--home", &home2, "status"]).contains("KeyLost"));
    fails(&[
        "--home", &home2, "--mobile", &half2, "work", "--did", "after",
    ]);
}

/// `check_seat` link by link: the seller's signature, the container's issuer.
#[test]
fn a_seat_checks_its_signature_and_the_containers_issuer() {
    use ksg_cli_v2::channel::{check_seat, DistributorSeat, Sale};
    let d = Dir::new("seatcheck");
    issuer_and_distributor(&d);
    sell(&d, "dist", "distributor", "box", "sale.json");
    ok(&[
        "distributor",
        "seat",
        "--desk",
        &d.p("dist"),
        "--sale",
        &d.p("sale.json"),
        "--out",
        &d.p("seat.json"),
    ]);
    let sale: Sale = serde_json::from_slice(&std::fs::read(d.p("sale.json")).unwrap()).unwrap();
    let seat: DistributorSeat =
        serde_json::from_slice(&std::fs::read(d.p("seat.json")).unwrap()).unwrap();
    let issuer = sale.emission.keys[0].clone();
    assert_eq!(check_seat(&seat, &sale, &issuer).unwrap(), seat.key);

    // Another key's signature over the same seat.
    let mut bad = seat.clone();
    let other = ksg_core_v2::crypto::sign::Ed25519Signer::from_seed(seat.key.kid.clone(), [9; 32]);
    bad.signature = other.sign(b"anything");
    assert!(check_seat(&bad, &sale, &issuer)
        .unwrap_err()
        .contains("signature"));
    // A sale whose release is not this container's issuer's.
    let stranger = other.public();
    assert!(check_seat(&seat, &sale, &stranger)
        .unwrap_err()
        .contains("not of this container's issuer"));
}
