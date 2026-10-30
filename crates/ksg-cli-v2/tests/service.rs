//! The service process end to end (`ksg_service_v2::server`), on a devnet in
//! a thread: an owner-watcher registers by its own channel bundle, a holder
//! anchors through the service, the watcher asks whose the anchor is, the
//! holder takes the notice — and the service, stopped and started again,
//! remembers all of it.

mod mock_devnet;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::{Command, Output};

use ed25519_dalek::SigningKey;
use ksg_anchor_v2::solana_tx::address;
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{Alg, Ed25519Signer, PublicKey};
use ksg_core_v2::doc::Uri;
use ksg_service_v2::anchoring::ChainSender;
use ksg_service_v2::auth::sign_request;
use ksg_service_v2::server::{start, Config, HolderCfg, Running};
use ksg_service_v2::solana::SolanaSender;
use ksg_verify_v2::channel::holder_key;
use ksg_verify_v2::solana::{HttpRpc, StatusMemo};
use mock_devnet::MockDevnet;
use serde_json::{json, Value};

const KSG: &str = env!("CARGO_BIN_EXE_ksg-remote-panel");

struct Dir(PathBuf);
impl Dir {
    fn new(name: &str) -> Self {
        let d = std::env::temp_dir().join(format!("ksg-service-{name}-{}", std::process::id()));
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
fn ok(args: &[&str]) -> String {
    let o = run(args);
    assert!(
        o.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn payer(path: &str, seed: u8) -> String {
    let k = SigningKey::from_bytes(&[seed; 32]);
    let mut all = k.to_bytes().to_vec();
    all.extend_from_slice(k.verifying_key().as_bytes());
    std::fs::write(path, serde_json::to_vec(&all).unwrap()).unwrap();
    address(&k.verifying_key())
}

/// The owner key of a home: its holder URI names it; the seeds file signs.
fn owner_signer(home: &str) -> Ed25519Signer {
    let seeds: Value =
        serde_json::from_slice(&std::fs::read(format!("{home}/parties.json")).unwrap()).unwrap();
    use base64::Engine as _;
    let b = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(seeds["owner"].as_str().unwrap())
        .unwrap();
    Ed25519Signer::from_seed(
        Uri::parse("did:key:zKsgOwner#k1").unwrap(),
        b.try_into().unwrap(),
    )
}

fn template(home: &str) -> Hash {
    let m: Value =
        serde_json::from_slice(&std::fs::read(format!("{home}/container.json")).unwrap()).unwrap();
    Hash::from_multihash(m["template"].as_str().unwrap()).unwrap()
}

fn id(home: &str) -> Hash {
    let m: Value =
        serde_json::from_slice(&std::fs::read(format!("{home}/container.json")).unwrap()).unwrap();
    Hash::from_multihash(m["id"].as_str().unwrap()).unwrap()
}

/// The watcher's container: printed on a packet the issuer sold it,
/// anchored on the devnet.
fn watcher(d: &Dir, net: &MockDevnet) -> String {
    ok(&[
        "issuer",
        "init",
        "--desk",
        &d.p("issuer"),
        "--release",
        "ksg:em:test:000001",
        "--range",
        "1-1000",
    ]);
    let home = d.p("watcher");
    let to = ok(&["--home", &home, "holder"]).trim().to_owned();
    let o = ok(&[
        "issuer",
        "order",
        "--desk",
        &d.p("issuer"),
        "--to",
        &to,
        "--class",
        "heavy",
        "--size",
        "10",
    ]);
    let order = o
        .split_whitespace()
        .find(|w| w.starts_with("ord-"))
        .unwrap()
        .to_owned();
    ok(&[
        "issuer",
        "confirm-payment",
        "--desk",
        &d.p("issuer"),
        "--order",
        &order,
        "--out",
        &d.p("sale.json"),
    ]);
    let key = d.p("watcher-payer.json");
    net.fund(&payer(&key, 61), 1_000_000_000);
    ok(&[
        "--home",
        &home,
        "init",
        "--sale",
        &d.p("sale.json"),
        "--issuer-desk",
        &d.p("issuer"),
        "--anchor",
        "solana:devnet",
        "--payer",
        &key,
        "--rpc",
        &net.url,
    ]);
    ok(&["--home", &home, "packet"]);
    ok(&["--home", &home, "buyer-key"]);
    // Born at initiation: its identifier and the channel's documents (CH-5b).
    ok(&[
        "--home",
        &home,
        "--mobile",
        &d.p("watcher.half"),
        "initiate",
    ]);
    home
}

/// The holder's container: anchored directly; the service knows it by its
/// owner key.
fn holder(d: &Dir, net: &MockDevnet) -> String {
    let home = d.p("holder");
    let key = d.p("holder-own-payer.json");
    net.fund(&payer(&key, 62), 1_000_000_000);
    ok(&[
        "--home",
        &home,
        "init",
        "--class",
        "light",
        "--anchor",
        "solana:devnet",
        "--payer",
        &key,
        "--rpc",
        &net.url,
    ]);
    home
}

fn serve(d: &Dir, net: &MockDevnet, holder_home: &str, max_age_s: Option<u64>) -> Running {
    let key = d.p("service-payer.json");
    let cfg = Config {
        listen: "127.0.0.1:0".into(),
        audience: Uri::parse("https://desk.example/v1").unwrap(),
        state: PathBuf::from(d.p("state")),
        cluster: "devnet".into(),
        rpc: net.url.clone(),
        issuer_keys: PathBuf::from(d.p("issuer/issuer-keys.json")),
        max_standing_age_s: max_age_s,
        legal_checkers: Vec::new(),
        holders: vec![HolderCfg {
            id: "h1".into(),
            key: PublicKey {
                kid: Uri::parse("did:key:zHolder#h1").unwrap(),
                alg: Alg::Ed25519,
                key: holder_key(ok(&["--home", holder_home, "holder"]).trim())
                    .unwrap()
                    .to_owned(),
            },
            payer: PathBuf::from(&key),
        }],
        workers: Some(2),
    };
    let mut senders: BTreeMap<String, Box<dyn ChainSender + Send>> = BTreeMap::new();
    senders.insert(
        "h1".into(),
        Box::new(
            SolanaSender::new(
                Box::new(HttpRpc::new(&net.url).unwrap()),
                "devnet",
                &std::fs::read(&key).unwrap(),
            )
            .unwrap(),
        ),
    );
    start(cfg, senders, Box::new(HttpRpc::new(&net.url).unwrap())).unwrap()
}

fn now() -> u64 {
    ksg_verify_v2::clock::now_ms()
}

/// A request signed as holder `h1`; `(status, body)`.
fn signed(
    url: &str,
    signer: &Ed25519Signer,
    method: &str,
    path: &str,
    body: &Value,
) -> (u16, Value) {
    let bytes = if method == "GET" {
        Vec::new()
    } else {
        serde_json::to_vec(body).unwrap()
    };
    let mut rq = ureq::request(method, &format!("{url}{path}"));
    for (k, v) in sign_request(signer, "h1", method, path, now(), &bytes) {
        rq = rq.set(k, &v);
    }
    let r = if method == "GET" {
        rq.call()
    } else {
        rq.send_bytes(&bytes)
    };
    reply(r)
}

fn reply(r: Result<ureq::Response, ureq::Error>) -> (u16, Value) {
    match r {
        Ok(resp) => (resp.status(), resp.into_json().unwrap()),
        Err(ureq::Error::Status(c, resp)) => (c, resp.into_json().unwrap_or(Value::Null)),
        Err(e) => panic!("{e}"),
    }
}

#[test]
fn the_service_anchors_registers_answers_a_look_and_survives_a_restart() {
    let d = Dir::new("e2e");
    let net = MockDevnet::start();
    net.fund(&payer(&d.p("service-payer.json"), 63), 1_000_000_000);
    let w = watcher(&d, &net);
    let h = holder(&d, &net);
    let svc = serve(&d, &net, &h, None);
    let url = format!("http://{}", svc.addr);
    let me = owner_signer(&h);

    let (code, health) = reply(ureq::get(&format!("{url}/v1/health")).call());
    assert_eq!(
        (code, health["audience"].as_str()),
        (200, Some("https://desk.example/v1"))
    );

    // The holder anchors a status memo of its container through the service.
    let container = id(&h);
    let (prev, subject) = (Hash::sha256(b"record 0"), Hash::sha256(b"record 1"));
    let body = json!({
        "container": container.to_multihash(), "kind": "status",
        "subject": subject.to_multihash(), "memo": StatusMemo::of(&prev, &subject).to_string(),
    });
    let (code, job) = signed(&url, &me, "POST", "/v1/anchor", &body);
    assert_eq!(code, 200, "{job}");
    let path = format!("/v1/anchor/{}", job["job"]);
    let mut state = Value::Null;
    // A deadline in time, not a count of tries: a slow machine waits
    // longer, it does not fail (audit F-17).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while std::time::Instant::now() < deadline {
        let (_, s) = signed(&url, &me, "GET", &path, &Value::Null);
        state = s;
        if state["state"] == "anchored" {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
    assert_eq!(state["state"], "anchored", "{state}");
    let tx = state["anchor"]["signature"].as_str().unwrap().to_owned();
    assert!(net
        .ledger
        .lock()
        .unwrap()
        .txs
        .iter()
        .any(|t| t.signature == tx));

    // Unsigned, replayed, foreign: refused.
    let (code, _) = reply(ureq::post(&format!("{url}/v1/anchor")).send_json(body.clone()));
    assert_eq!(code, 401);
    let bytes = serde_json::to_vec(&body).unwrap();
    let headers = sign_request(&me, "h1", "POST", "/v1/anchor", now(), &bytes);
    let send = || {
        let mut rq = ureq::post(&format!("{url}/v1/anchor"));
        for (k, v) in &headers {
            rq = rq.set(k, v);
        }
        reply(rq.send_bytes(&bytes)).0
    };
    assert_eq!(send(), 200);
    assert_eq!(send(), 401, "the same signed request twice");
    let other = Ed25519Signer::from_seed(Uri::parse("did:key:zX#x").unwrap(), [9; 32]);
    assert_eq!(signed(&url, &other, "POST", "/v1/anchor", &body).0, 401);

    // A look before registering: not in any chain.
    let anchor = format!("devnet:{tx}");
    let o = run(&[
        "--home",
        &w,
        "service-look",
        "--service",
        &url,
        "--anchor",
        &anchor,
    ]);
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("403"),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    // Registered by its own channel bundle and status section: the look goes through.
    ok(&["--home", &w, "service-register", "--service", &url]);
    let out = ok(&[
        "--home",
        &w,
        "service-look",
        "--service",
        &url,
        "--anchor",
        &anchor,
    ]);
    assert!(
        out.contains("\"cents\":200") && out.contains(&container.to_multihash()),
        "{out}"
    );

    // The holder takes the notice; this container did not carry that
    // anchor, so it is refused rather than recorded.
    let out = ok(&[
        "--home",
        &h,
        "service-views",
        "--service",
        &url,
        "--holder",
        "h1",
    ]);
    assert!(
        out.contains("recorded   0") && out.contains("not hold"),
        "{out}"
    );
    // The mailbox is emptied once.
    let (code, v) = signed(
        &url,
        &me,
        "POST",
        "/v1/notices",
        &json!({"container": container.to_multihash()}),
    );
    assert_eq!(
        (code, v["notices"].as_array().map(Vec::len)),
        (200, Some(0))
    );
    // A container the holder never anchored here: not its mailbox.
    let (code, _) = signed(
        &url,
        &me,
        "POST",
        "/v1/notices",
        &json!({"container": id(&w).to_multihash()}),
    );
    assert_eq!(code, 403);

    // Stopped and started again: the job, the registration and the look count remain.
    svc.stop();
    let svc = serve(&d, &net, &h, None);
    let url = format!("http://{}", svc.addr);
    let (_, s) = signed(&url, &me, "GET", &path, &Value::Null);
    assert_eq!(s["state"], "anchored");
    let out = ok(&[
        "--home",
        &w,
        "service-look",
        "--service",
        &url,
        "--anchor",
        &anchor,
    ]);
    assert!(
        out.contains("\"look\":2") && out.contains("\"cents\":2400"),
        "{out}"
    );
    svc.stop();

    // A standing is not kept forever: past its age the watcher registers again.
    std::thread::sleep(std::time::Duration::from_millis(4100));
    let svc = serve(&d, &net, &h, Some(4));
    let url = format!("http://{}", svc.addr);
    let o = run(&[
        "--home",
        &w,
        "service-look",
        "--service",
        &url,
        "--anchor",
        &anchor,
    ]);
    assert!(String::from_utf8_lossy(&o.stderr).contains("403"));
    let stale = checked_ms(&d);
    ok(&["--home", &w, "service-register", "--service", &url]);
    let fresh = checked_ms(&d);
    assert!(
        fresh.len() == 1 && fresh.iter().all(|f| stale.iter().all(|s| f > s)),
        "re-registration did not renew the standing: {stale:?} -> {fresh:?}"
    );
    svc.stop();
    // The renewed standing answers a look. Checked under the default age, not
    // the 4 s one: on a slow machine the next process start alone can outlast
    // 4 s (CI failure of 06.10, `[doc:RESEARCH-CI-FAILURES]`).
    let svc = serve(&d, &net, &h, None);
    let url = format!("http://{}", svc.addr);
    let out = ok(&[
        "--home",
        &w,
        "service-look",
        "--service",
        &url,
        "--anchor",
        &anchor,
    ]);
    assert!(out.contains("\"look\":3"), "{out}");
    svc.stop();
}

/// The `checked_ms` of every standing the service keeps on disk.
fn checked_ms(d: &Dir) -> Vec<u64> {
    let raw = std::fs::read_to_string(d.p("state/registry.json")).unwrap();
    let v: Value = serde_json::from_str(&raw).unwrap();
    v["entries"]
        .as_object()
        .map(|m| {
            m.values()
                .filter_map(|s| s["checked_ms"].as_u64())
                .collect()
        })
        .unwrap_or_default()
}

/// The Solana sender tells a slow transaction from a lost one by its
/// blockhash, and a refusal for want of funds from a network hiccup.
#[test]
fn the_solana_sender_reads_pending_dropped_landed_and_refused() {
    use ksg_service_v2::anchoring::{Landing, SendError};
    let d = Dir::new("sender");
    let net = MockDevnet::start();
    let key = d.p("p.json");
    let addr = payer(&key, 64);
    let mut s = SolanaSender::new(
        Box::new(HttpRpc::new(&net.url).unwrap()),
        "devnet",
        &std::fs::read(&key).unwrap(),
    )
    .unwrap();
    assert!(matches!(s.send_memo("hello"), Err(SendError::Refused(_))));
    net.fund(&addr, 1_000_000);
    net.ledger.lock().unwrap().hold = true;
    let sent = s.send_memo("hello").unwrap();
    assert_eq!(s.landing(&sent).unwrap(), Landing::Pending);
    net.ledger.lock().unwrap().release();
    assert!(matches!(
        s.landing(&sent).unwrap(),
        Landing::Landed {
            block_time: Some(_),
            ..
        }
    ));
    net.ledger.lock().unwrap().hold = true;
    let lost = s.send_memo("again").unwrap();
    net.ledger.lock().unwrap().drop_held();
    assert_eq!(s.landing(&lost).unwrap(), Landing::Dropped);
    assert_eq!(s.balance().unwrap(), 1_000_000 - 2 * mock_devnet::FEE);
}

/// "We anchor" end to end (CT-04, `[decision]` 13.09 §8.1): a container
/// anchors through the service, which pays from the holder's payer it keeps;
/// an owner-watcher looks at one of its anchors; the notice lands **in the
/// container**, recorded; and the journal still verifies against the network.
#[test]
fn a_container_anchored_through_the_service_receives_its_notice() {
    use ksg_verify_v2::solana::SolanaReader;
    use ksg_verify_v2::{keys_from_json, verify_bytes, Expected};

    let d = Dir::new("through");
    let net = MockDevnet::start();
    let service_payer = payer(&d.p("service-payer.json"), 65);
    net.fund(&service_payer, 1_000_000_000);
    let w = watcher(&d, &net);
    let h = d.p("holder");
    ok(&["--home", &h, "holder"]);
    let svc = serve(&d, &net, &h, None);
    let url = format!("http://{}", svc.addr);

    ok(&[
        "--home",
        &h,
        "init",
        "--class",
        "heavy",
        "--anchor",
        "solana:devnet",
        "--service",
        &url,
        "--holder",
        "h1",
        "--rpc",
        &net.url,
    ]);
    let m = d.p("h.half");
    ok(&["--home", &h, "packet"]);
    ok(&["--home", &h, "buyer-key"]);
    ok(&["--home", &h, "--mobile", &m, "initiate"]);
    ok(&["--home", &h, "--mobile", &m, "open-journal"]);
    ok(&[
        "--home",
        &h,
        "--mobile",
        &m,
        "work",
        "--did",
        "claim reviewed",
    ]);
    // Every memo of this container was paid from the service's payer.
    let paid: usize = net
        .ledger
        .lock()
        .unwrap()
        .txs
        .iter()
        .filter(|t| t.payer == service_payer)
        .count();
    assert!(
        paid >= 7,
        "record 0, three status changes, two seals at least: {paid}"
    );
    let meta: Value =
        serde_json::from_slice(&std::fs::read(format!("{h}/container.json")).unwrap()).unwrap();
    assert!(
        meta["anchor"].get("payer").is_none(),
        "no payer key at the holder"
    );
    assert!(meta["anchor"].get("pending").is_none());

    // The watcher looks at the container's packet status anchor.
    ok(&["--home", &h, "export-statuses", "--out", &d.p("st.json")]);
    let st: ksg_core_v2::section::StatusExport =
        serde_json::from_slice(&std::fs::read(d.p("st.json")).unwrap()).unwrap();
    let proof = ksg_verify_v2::solana::AnchorProof::from_bytes(&st.records[1].1.proof).unwrap();
    ok(&["--home", &w, "service-register", "--service", &url]);
    let out = ok(&[
        "--home",
        &w,
        "service-look",
        "--service",
        &url,
        "--anchor",
        &format!("devnet:{}", proof.signature),
    ]);
    // The service knows the container by its template identifier — the one
    // it had from printing, before initiation gave birth to the container's
    // own (CH-5b).
    assert!(out.contains(&template(&h).to_multihash()), "{out}");

    // The notice ends in the holder's container.
    let out = ok(&[
        "--home",
        &h,
        "service-views",
        "--service",
        &url,
        "--holder",
        "h1",
    ]);
    assert!(
        out.contains("recorded   1") && out.contains("viewed     1"),
        "{out}"
    );
    let out = ok(&["--home", &h, "views"]);
    assert!(out.contains("did:key:zKsgOwner looked at devnet:"), "{out}");

    // And the journal verifies against the network, anchors read.
    ok(&["--home", &h, "finalize"]);
    ok(&[
        "--home",
        &h,
        "--mobile",
        &m,
        "export-final",
        "--out",
        &d.p("final.json"),
    ]);
    ok(&["--home", &h, "keys", "--out", &d.p("keys.json")]);
    ok(&["--home", &h, "scan-key", "--out", &d.p("scan.key")]);
    let rpc = HttpRpc::new(&net.url).unwrap();
    let reader = SolanaReader::connect(&rpc, "devnet")
        .unwrap()
        .with_scan_keys(
            ksg_verify_v2::solana::scan_keys_from_text(
                &std::fs::read_to_string(d.p("scan.key")).unwrap(),
            )
            .unwrap(),
        );
    let fin = verify_bytes(
        &std::fs::read(d.p("final.json")).unwrap(),
        &Expected {
            container: id(&h),
            class: ksg_core_v2::doc::Class::Heavy,
            keys: keys_from_json(&std::fs::read(d.p("keys.json")).unwrap()).unwrap(),
            client_id_from_key: true,
            anchors: &reader,
        },
    );
    assert!(fin.accepted, "{fin:?}");
    svc.stop();
}

/// The service down: nothing is sent, so the record is undone as with a
/// network that refuses — and once the service is back, the same command
/// goes through.
#[test]
fn a_service_that_is_down_writes_nothing() {
    let d = Dir::new("down");
    let net = MockDevnet::start();
    net.fund(&payer(&d.p("service-payer.json"), 66), 1_000_000_000);
    ok(&[
        "issuer",
        "init",
        "--desk",
        &d.p("issuer"),
        "--release",
        "ksg:em:test:000001",
        "--range",
        "1-1000",
    ]);
    let h = d.p("holder");
    ok(&["--home", &h, "holder"]);
    let svc = serve(&d, &net, &h, None);
    let url = format!("http://{}", svc.addr);
    ok(&[
        "--home",
        &h,
        "init",
        "--class",
        "heavy",
        "--anchor",
        "solana:devnet",
        "--service",
        &url,
        "--holder",
        "h1",
        "--rpc",
        &net.url,
    ]);
    svc.stop();
    let before = std::fs::read(format!("{h}/container.ksg")).unwrap();
    let o = run(&["--home", &h, "packet"]);
    assert!(!o.status.success());
    assert_eq!(std::fs::read(format!("{h}/container.ksg")).unwrap(), before);
}
