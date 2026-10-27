//! The `ksg` program end to end: the insurance scenario through separate
//! processes, the container on a disk between them, and a third party's
//! verdict on what came out. Item P-5.4 of the MVP plan.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::doc::Class;
use ksg_verify_v2::{keys_from_json, verify_bytes, Expected, NoReader};

const KSG: &str = env!("CARGO_BIN_EXE_ksg-remote-panel");

struct Dir(PathBuf);

impl Dir {
    fn new(name: &str) -> Self {
        let d = std::env::temp_dir().join(format!("ksg-cli-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Self(d)
    }
    fn p(&self, name: &str) -> PathBuf {
        self.0.join(name)
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
        .output()
        .expect("the program runs")
}

fn ok(args: &[&str]) {
    let out = ksg(args);
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn code(args: &[&str]) -> i32 {
    ksg(args).status.code().expect("exited")
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

fn id(home: &Path) -> Hash {
    let meta: serde_json::Value =
        serde_json::from_slice(&std::fs::read(home.join("container.json")).unwrap()).unwrap();
    Hash::from_multihash(meta["id"].as_str().unwrap()).unwrap()
}

#[test]
fn bare_init_omits_post_quantum_metadata_and_outer_signature() {
    let d = Dir::new("bare-no-pq");
    let home = d.p("home");
    ok(&["--home", s(&home), "init", "--class", "bare"]);

    let meta: serde_json::Value =
        serde_json::from_slice(&std::fs::read(home.join("container.json")).unwrap()).unwrap();
    assert!(meta.get("pq").is_none(), "bare metadata omits pq");
    assert!(meta.get("pq_cert").is_none(), "bare metadata omits pq_cert");

    let bytes = std::fs::read(home.join("container.ksg")).unwrap();
    let signature_len = u32::from_be_bytes(bytes[bytes.len() - 4..].try_into().unwrap());
    assert_eq!(signature_len, 0, "bare file has no outer PQ signature");
}

/// Downgrade: a Pro file stripped of its outer signature and relabelled
/// `bare` in container.json must not open — the class sealed inside counts.
#[test]
fn a_pro_file_relabelled_bare_does_not_open() {
    let d = Dir::new("pro-as-bare");
    let home = d.p("home");
    ok(&["--home", s(&home), "init", "--class", "heavy"]);
    // Д-4: the post-quantum key — and with it the outer signature — is born at
    // initiation, so the downgrade is tried on an initiated container.
    ok(&["--home", s(&home), "packet"]);
    ok(&["--home", s(&home), "buyer-key"]);
    let mobile = d.p("mobile.half");
    ok(&["--home", s(&home), "--mobile", s(&mobile), "initiate"]);

    let path = home.join("container.ksg");
    let bytes = std::fs::read(&path).unwrap();
    let n = bytes.len();
    let sig_len = u32::from_be_bytes(bytes[n - 4..].try_into().unwrap()) as usize;
    assert!(sig_len > 0, "a Pro file carries an outer signature");
    let mut stripped = bytes[..n - 4 - sig_len].to_vec();
    stripped.extend_from_slice(&0u32.to_be_bytes());
    std::fs::write(&path, stripped).unwrap();

    let meta_path = home.join("container.json");
    let mut meta: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&meta_path).unwrap()).unwrap();
    let bare = {
        let b = d.p("bare");
        ok(&["--home", s(&b), "init", "--class", "bare"]);
        let m: serde_json::Value =
            serde_json::from_slice(&std::fs::read(b.join("container.json")).unwrap()).unwrap();
        m["class"].clone()
    };
    let obj = meta.as_object_mut().unwrap();
    obj.insert("class".into(), bare);
    obj.remove("pq");
    obj.remove("pq_cert");
    std::fs::write(&meta_path, serde_json::to_vec(&meta).unwrap()).unwrap();

    let out = ksg(&["--home", s(&home), "status"]);
    assert!(!out.status.success(), "a relabelled Pro file opened");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("outer signature"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Printing to a final export, every step its own process.
fn life(d: &Dir, class: &str) -> (PathBuf, PathBuf) {
    let (home, mobile) = (d.p("home"), d.p("mobile.half"));
    let (h, m) = (s(&home), s(&mobile));
    std::fs::write(d.p("policy.pdf"), b"POLICY 123: third-party liability").unwrap();

    ok(&["--home", h, "init", "--class", class]);
    ok(&["--home", h, "packet"]);
    ok(&["--home", h, "buyer-key"]);
    ok(&["--home", h, "--mobile", m, "initiate"]);
    // Д-4: the outer signature is born with the post-quantum key at initiation;
    // from then on the size is fixed, whatever the work.
    let size = std::fs::metadata(home.join("container.ksg")).unwrap().len();
    ok(&["--home", h, "--mobile", m, "open-journal"]);
    ok(&[
        "--home",
        h,
        "--mobile",
        m,
        "attach",
        "--type",
        "urn:ksg:page:policy:v1",
        "--file",
        s(&d.p("policy.pdf")),
        "--mime",
        "application/pdf",
    ]);
    ok(&[
        "--home",
        h,
        "--mobile",
        m,
        "work",
        "--did",
        "claim reviewed",
    ]);
    // The size says nothing about the work (store.rs, padding).
    assert_eq!(
        std::fs::metadata(home.join("container.ksg")).unwrap().len(),
        size
    );

    ok(&[
        "--home",
        h,
        "export-page",
        "--number",
        "1",
        "--by",
        "owner",
        "--out",
        s(&d.p("p1.json")),
    ]);
    ok(&[
        "--home",
        h,
        "--mobile",
        m,
        "export-page",
        "--number",
        "2",
        "--by",
        "client",
        "--out",
        s(&d.p("p2.json")),
    ]);
    ok(&["--home", h, "finalize"]);
    ok(&[
        "--home",
        h,
        "--mobile",
        m,
        "export-final",
        "--out",
        s(&d.p("final.json")),
    ]);
    ok(&["--home", h, "keys", "--out", s(&d.p("keys.json"))]);
    (home, d.p("final.json"))
}

fn verdict(d: &Dir, home: &Path, export: &Path, class: Class) -> ksg_verify_v2::Report {
    let keys = keys_from_json(&std::fs::read(d.p("keys.json")).unwrap()).unwrap();
    verify_bytes(
        &std::fs::read(export).unwrap(),
        &Expected {
            container: id(home),
            class,
            keys,
            client_id_from_key: true,
            anchors: &NoReader,
        },
    )
}

#[test]
fn light_life_verifies_without_the_issuer() {
    let d = Dir::new("light");
    let (home, export) = life(&d, "light");
    let r = verdict(&d, &home, &export, Class::Light);
    assert!(r.accepted, "{r:?}");
    assert_eq!(r.pages, Some(3), "opening, policy, work");

    let exp: serde_json::Value = serde_json::from_slice(&std::fs::read(&export).unwrap()).unwrap();
    assert_eq!(
        exp["pages"][1]["body"]["content"]["content_type"],
        "urn:ksg:page:policy:v1"
    );
    // Declared as heavy, the same bytes are refused: the class is the
    // verifier's, not the export's.
    assert!(!verdict(&d, &home, &export, Class::Heavy).accepted);
}

#[test]
fn heavy_life_is_refused_until_a_network_reads_its_anchors() {
    let d = Dir::new("heavy");
    let (home, export) = life(&d, "heavy");
    let r = verdict(&d, &home, &export, Class::Heavy);
    assert!(!r.accepted);
    assert!(
        r.reason.unwrap().contains("anchor"),
        "the local anchor is not evidence"
    );
    let p = verdict(&d, &home, &d.p("p1.json"), Class::Heavy);
    assert!(
        !p.accepted,
        "a page with a local anchor is not evidence either"
    );
}

#[test]
fn a_refusal_leaves_the_file_as_it_was() {
    let d = Dir::new("refusal");
    let (home, mobile) = (d.p("home"), d.p("mobile.half"));
    let (h, m) = (s(&home), s(&mobile));
    ok(&["--home", h, "init", "--class", "light"]);
    let before = std::fs::read(home.join("container.ksg")).unwrap();
    // The buyer's key before the packet: out of order.
    assert_eq!(code(&["--home", h, "buyer-key"]), 1);
    // The client signs nothing without its mobile half.
    ok(&["--home", h, "packet"]);
    ok(&["--home", h, "buyer-key"]);
    let mid = std::fs::read(home.join("container.ksg")).unwrap();
    assert_ne!(before, mid);
    // Initiation with nowhere to put the mobile half born: a usage error.
    assert_eq!(code(&["--home", h, "initiate"]), 2);
    assert_eq!(std::fs::read(home.join("container.ksg")).unwrap(), mid);
    // A half never overwrites a file: refused, nothing written.
    std::fs::write(&mobile, b"something").unwrap();
    assert_eq!(code(&["--home", h, "--mobile", m, "initiate"]), 1);
    assert_eq!(std::fs::read(home.join("container.ksg")).unwrap(), mid);
    assert_eq!(std::fs::read(&mobile).unwrap(), b"something");
}

#[test]
fn another_containers_mobile_half_does_not_sign() {
    let d = Dir::new("other-half");
    let (a, b) = (d.p("a"), d.p("b"));
    ok(&["--home", s(&a), "init", "--class", "light"]);
    ok(&["--home", s(&b), "init", "--class", "light"]);
    for (home, half) in [(&a, "a.half"), (&b, "b.half")] {
        ok(&["--home", s(home), "packet"]);
        ok(&["--home", s(home), "buyer-key"]);
        ok(&["--home", s(home), "--mobile", s(&d.p(half)), "initiate"]);
    }
    // Each key is born for its own container: b's half signs nothing in a.
    assert_eq!(
        code(&[
            "--home",
            s(&a),
            "--mobile",
            s(&d.p("b.half")),
            "open-journal"
        ]),
        1
    );
    ok(&[
        "--home",
        s(&a),
        "--mobile",
        s(&d.p("a.half")),
        "open-journal",
    ]);
    // And a container is initiated once.
    assert_eq!(
        code(&["--home", s(&a), "--mobile", s(&d.p("c.half")), "initiate"]),
        1
    );
}

#[test]
fn a_tampered_or_swapped_file_does_not_open() {
    let d = Dir::new("tamper");
    let (a, b) = (d.p("a"), d.p("b"));
    ok(&["--home", s(&a), "init", "--class", "light"]);
    ok(&["--home", s(&b), "init", "--class", "light"]);
    // One byte changed.
    let f = a.join("container.ksg");
    let mut bytes = std::fs::read(&f).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    std::fs::write(&f, &bytes).unwrap();
    assert_eq!(code(&["--home", s(&a), "status"]), 1);
    // Another container's bytes under this one's name and key.
    std::fs::copy(b.join("container.ksg"), &f).unwrap();
    assert_eq!(code(&["--home", s(&a), "status"]), 1);
}

#[test]
fn init_does_not_overwrite_and_usage_errors_exit_2() {
    let d = Dir::new("usage");
    let (h, m) = (s(&d.p("home")).to_owned(), s(&d.p("m.half")).to_owned());
    ok(&["--home", &h, "init", "--class", "light"]);
    // The mobile half is born at initiation, not at printing (CH-5b).
    assert_eq!(
        code(&["--home", &h, "--mobile", &m, "init", "--class", "light"]),
        2
    );
    assert_eq!(code(&["--home", &h, "init", "--class", "light",]), 1);
    assert_eq!(code(&["--home", &h, "init", "--class", "golden",]), 2);
    assert_eq!(code(&["--home", &h, "fly"]), 2);
    assert_eq!(code(&["--home", &h, "work"]), 2);
    assert_eq!(code(&["status"]), 2);
}

#[test]
fn one_reader_at_a_time() {
    let d = Dir::new("lock");
    let home = d.p("home");
    ok(&["--home", s(&home), "init", "--class", "light"]);
    std::fs::write(home.join("lock"), b"").unwrap();
    assert_eq!(code(&["--home", s(&home), "packet"]), 1, "held by another");
    std::fs::remove_file(home.join("lock")).unwrap();
    ok(&["--home", s(&home), "packet"]);
    assert!(!home.join("lock").exists(), "released on close");
}

#[cfg(unix)]
#[test]
fn secrets_are_written_for_the_owner_only() {
    use std::os::unix::fs::PermissionsExt as _;
    let d = Dir::new("modes");
    let home = d.p("home");
    ok(&["--home", s(&home), "init", "--class", "light"]);
    ok(&["--home", s(&home), "packet"]);
    ok(&["--home", s(&home), "buyer-key"]);
    ok(&[
        "--home",
        s(&home),
        "--mobile",
        s(&d.p("m.half")),
        "initiate",
    ]);
    for f in [
        home.join("layer.key"),
        home.join("parties.json"),
        d.p("m.half"),
    ] {
        let mode = std::fs::metadata(&f).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{}", f.display());
    }
}

/// The hand-off to another agent of the same owner (CH-16, CH-17), each step
/// its own process: the new agent's half comes out of the container, the old
/// half signs nothing afterwards, and the export checks.
#[test]
fn a_container_is_handed_to_another_agent() {
    let d = Dir::new("handoff");
    let (home, m1, m2) = (d.p("home"), d.p("one.half"), d.p("two.half"));
    let (h, a, b) = (s(&home), s(&m1), s(&m2));
    ok(&["--home", h, "init", "--class", "light"]);
    ok(&["--home", h, "packet"]);
    ok(&["--home", h, "buyer-key"]);
    ok(&["--home", h, "--mobile", a, "initiate"]);
    ok(&["--home", h, "--mobile", a, "open-journal"]);
    ok(&["--home", h, "--mobile", a, "work", "--did", "first agent"]);
    ok(&[
        "--home",
        h,
        "--mobile",
        a,
        "handoff",
        "--name",
        "did:key:zAgentTwo",
        "--new-mobile",
        b,
    ]);
    assert!(m2.exists());
    // The old half: refused. The new one: works.
    assert_eq!(
        code(&["--home", h, "--mobile", a, "work", "--did", "old agent"]),
        1
    );
    ok(&["--home", h, "--mobile", b, "work", "--did", "second agent"]);
    // A second hand-off to a name the container knows is refused, and leaves
    // no half behind.
    assert_eq!(
        code(&[
            "--home",
            h,
            "--mobile",
            b,
            "handoff",
            "--name",
            "did:key:zAgentTwo",
            "--new-mobile",
            s(&d.p("three.half")),
        ]),
        1
    );
    assert!(!d.p("three.half").exists());
    ok(&["--home", h, "finalize"]);
    ok(&[
        "--home",
        h,
        "--mobile",
        b,
        "export-final",
        "--out",
        s(&d.p("final.json")),
    ]);
    ok(&["--home", h, "keys", "--out", s(&d.p("keys.json"))]);
    let r = verify_bytes(
        &std::fs::read(d.p("final.json")).unwrap(),
        &Expected {
            container: id(&home),
            class: Class::Light,
            keys: keys_from_json(&std::fs::read(d.p("keys.json")).unwrap()).unwrap(),
            client_id_from_key: true,
            anchors: &NoReader,
        },
    );
    assert!(r.accepted, "{r:?}");
    assert_eq!(r.pages, Some(4), "page 0, work, hand-off, work");
}

fn status_line(home: &Path, key: &str) -> String {
    let o = ksg(&["--home", s(home), "status"]);
    String::from_utf8_lossy(&o.stdout)
        .lines()
        .find_map(|l| l.strip_prefix(key).map(|v| v.trim().to_owned()))
        .unwrap()
}

fn to_work(home: &Path, m: &Path) {
    let (h, m) = (s(home), s(m));
    ok(&["--home", h, "init", "--class", "light"]);
    ok(&["--home", h, "packet"]);
    ok(&["--home", h, "buyer-key"]);
    ok(&["--home", h, "--mobile", m, "initiate"]);
    ok(&["--home", h, "--mobile", m, "open-journal"]);
}

/// The rule of two seals (E-7, CH-19) and the coupling at succession (E-14 and
/// E-5, CH-12), each step its own process.
#[test]
fn the_rule_and_the_coupling_through_the_program() {
    let d = Dir::new("rule");
    let (a, am, b, bm) = (d.p("a"), d.p("a.half"), d.p("b"), d.p("b.half"));
    to_work(&a, &am);
    let (h, m) = (s(&a), s(&am));
    ok(&["--home", h, "--mobile", m, "rule", "--scope", "all"]);
    ok(&[
        "--home",
        h,
        "--mobile",
        m,
        "work",
        "--did",
        "under the rule",
    ]);
    ok(&["--home", h, "--mobile", m, "rule", "--scope", "lift"]);
    assert_eq!(
        code(&["--home", h, "--mobile", m, "rule", "--scope", "sometimes"]),
        2,
        "usage"
    );

    to_work(&b, &bm);
    let leader = status_line(&b, "container ");
    ok(&["--home", h, "--mobile", m, "succeed", "--leader", &leader]);
    let trailer = status_line(&a, "container ");
    let seal = status_line(&a, "top seal ");
    ok(&[
        "--home",
        s(&b),
        "--mobile",
        s(&bm),
        "pull",
        "--trailer",
        &trailer,
        "--trailer-seal",
        &seal,
    ]);
    // Slot 2 is written once.
    assert_eq!(
        code(&[
            "--home",
            s(&b),
            "--mobile",
            s(&bm),
            "pull",
            "--trailer",
            &trailer,
            "--trailer-seal",
            &seal,
        ]),
        1
    );
    ok(&[
        "--home",
        s(&b),
        "--mobile",
        s(&bm),
        "work",
        "--did",
        "goes on here",
    ]);
}

/// CH-5a, CH-5b: a container's file checks from outside, without the layer
/// key — before initiation and after it — against the issuer's keys alone;
/// a changed byte, or another container's file, does not.
#[test]
fn the_file_checks_from_outside_against_the_issuers_word() {
    use ksg_verify_v2::file::{verify_file, FileClaim};
    let d = Dir::new("outside");
    let (a, b) = (d.p("a"), d.p("b"));
    ok(&["--home", s(&a), "init", "--class", "light"]);
    ok(&["--home", s(&b), "init", "--class", "light", "--serial", "2"]);
    ok(&[
        "--home",
        s(&a),
        "issuer-keys",
        "--out",
        s(&d.p("issuer.json")),
    ]);
    let keys = keys_from_json(&std::fs::read(d.p("issuer.json")).unwrap()).unwrap();
    let claim =
        |h: &Path| FileClaim::from_meta(&std::fs::read(h.join("container.json")).unwrap()).unwrap();
    let file = |h: &Path| std::fs::read(h.join("container.ksg")).unwrap();

    // Д-4: before initiation there is no post-quantum key, so nothing is
    // signed outside and the metadata names no key to check against.
    assert!(
        verify_file(&file(&a), &claim(&a), &keys).is_err(),
        "a printed template carries no post-quantum key: there is nothing to check outside"
    );
    ok(&["--home", s(&a), "packet"]);
    ok(&["--home", s(&a), "buyer-key"]);
    ok(&["--home", s(&a), "--mobile", s(&d.p("a.half")), "initiate"]);
    // Born: the same key signs, the issuer's word still holds.
    let t = verify_file(&file(&a), &claim(&a), &keys).expect("initiated");
    assert_ne!(
        t.to_multihash(),
        id(&a).to_multihash(),
        "the template is not the container"
    );

    // A byte of the ciphertext changed.
    let mut bad = file(&a);
    bad[ksg_verify_v2::file::MAGIC.len() + 12 + 50] ^= 1;
    assert!(verify_file(&bad, &claim(&a), &keys).is_err());
    // Another container's file under this one's claim.
    assert!(verify_file(&file(&b), &claim(&a), &keys).is_err());
    // Keys other than the issuer's vouch for nothing.
    let other = keys_from_json(
        br#"[{"kid":"did:key:zX#k1","alg":"Ed25519","key":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]"#,
    )
    .unwrap();
    assert!(verify_file(&file(&a), &claim(&a), &other).is_err());
}

fn to_work_as(home: &Path, m: &Path, class: &str) {
    let (h, m) = (s(home), s(m));
    ok(&["--home", h, "init", "--class", class]);
    if class != "bare" {
        ok(&["--home", h, "packet"]);
    }
    ok(&["--home", h, "buyer-key"]);
    ok(&["--home", h, "--mobile", m, "initiate"]);
    ok(&["--home", h, "--mobile", m, "open-journal"]);
}

fn read_export(p: &Path) -> ksg_core_v2::journal::BoundExport {
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

/// The attachment of a `bare` and its detachment through the program
/// (13.10), each step its own process: the owner's change to the leader's
/// owner, the hand-off to the leader's agent, slot 1; the leader's slot 2;
/// the pair confirmed from the two exports; read-only while attached; the
/// detachment by the owner and the former client, which burns the copy.
#[test]
fn a_bare_attaches_to_a_pro_leader_and_detaches_through_the_program() {
    use ksg_core_v2::crypto::sign::Profile;
    use ksg_verify_v2::coupling::{verify_pair, Pair};
    let d = Dir::new("attach");
    let (l, lm) = (d.p("leader"), d.p("leader.half"));
    let (t, t1, t2) = (d.p("trailer"), d.p("trailer.half"), d.p("agent.half"));
    to_work_as(&l, &lm, "heavy");
    to_work_as(&t, &t1, "bare");
    let (th, a, b) = (s(&t), s(&t1), s(&t2));
    ok(&[
        "--home",
        th,
        "--mobile",
        a,
        "work",
        "--did",
        "before the attachment",
    ]);

    // Only a bare attaches, and only to a leader that is not bare.
    let (x, xm) = (d.p("other-bare"), d.p("other.half"));
    to_work_as(&x, &xm, "bare");
    let attach = |home: &Path, mobile: &str, leader: &Path, out: &Path| {
        code(&[
            "--home",
            s(home),
            "--mobile",
            mobile,
            "attach-to",
            "--leader-home",
            s(leader),
            "--agent",
            "did:key:zLeaderAgent",
            "--new-mobile",
            s(out),
        ])
    };
    assert_eq!(
        attach(&t, a, &x, &d.p("x.half")),
        1,
        "a bare leader is refused"
    );
    assert!(!d.p("x.half").exists());
    assert_eq!(
        attach(&l, s(&lm), &x, &d.p("y.half")),
        1,
        "a Pro is not a trailer"
    );
    // Detaching a bare not attached is refused.
    assert_eq!(code(&["--home", th, "detach", "--former-mobile", a]), 1);

    assert_eq!(attach(&t, a, &l, &t2), 0, "the attachment goes in");
    assert_eq!(
        status_line(&t, "coupling "),
        "attached as a trailer: read-only"
    );
    assert!(t2.exists(), "the leader's agent's half is written");
    // Read-only now: no work, neither by the former client nor by the new agent.
    assert_eq!(
        code(&["--home", th, "--mobile", b, "work", "--did", "after"]),
        1
    );
    assert_eq!(
        code(&["--home", th, "--mobile", a, "work", "--did", "after"]),
        1
    );
    // A second attachment is refused.
    assert_eq!(attach(&t, b, &l, &d.p("z.half")), 1);

    // The leader pulls the trailer, naming its last seal.
    let trailer = status_line(&t, "container ");
    let seal = status_line(&t, "top seal ");
    ok(&[
        "--home",
        s(&l),
        "--mobile",
        s(&lm),
        "pull",
        "--trailer",
        &trailer,
        "--trailer-seal",
        &seal,
    ]);
    // The exports: the trailer's by its owner (now the leader's) and its
    // agent (the leader's); the leader's after it ends.
    ok(&[
        "--home",
        th,
        "--mobile",
        b,
        "export-final",
        "--out",
        s(&d.p("t.json")),
    ]);
    ok(&["--home", s(&l), "finalize"]);
    ok(&[
        "--home",
        s(&l),
        "--mobile",
        s(&lm),
        "export-final",
        "--out",
        s(&d.p("l.json")),
    ]);
    let (te, le) = (read_export(&d.p("t.json")), read_export(&d.p("l.json")));
    assert!(
        matches!(
            verify_pair(&te, &le, &Profile::default()),
            Pair::Confirmed { .. }
        ),
        "{:?}",
        verify_pair(&te, &le, &Profile::default())
    );

    // The detachment needs the former client's half: the new agent's is not it.
    assert_eq!(code(&["--home", th, "detach", "--former-mobile", b]), 1);
    ok(&[
        "--home",
        th,
        "--mobile",
        b,
        "export-page",
        "--number",
        "1",
        "--by",
        "owner",
        "--out",
        s(&d.p("p.json")),
    ]);
    ok(&["--home", th, "detach", "--former-mobile", a]);
    assert_eq!(status_line(&t, "coupling "), "detached, the copy burned");
    // Burned: nothing answers any more, the exports included.
    assert_eq!(
        code(&[
            "--home",
            th,
            "--mobile",
            b,
            "export-final",
            "--out",
            s(&d.p("t2.json"))
        ]),
        1
    );
    assert_eq!(code(&["--home", th, "detach", "--former-mobile", a]), 1);
}

/// E-3 (gap 16.10): laying the buyer's key on hands the layer keys over for
/// real — a sealed hand-over beside the container, X25519 alone in `bare`
/// (`[decision]` 07.10), hybrid with the ML-KEM-768 ciphertext in Pro.
#[test]
fn laying_the_buyers_key_on_hands_the_layer_over() {
    use base64::Engine as _;
    let d = Dir::new("handover");
    for (class, suite, kem) in [("bare", "X25519", 0), ("heavy", "Hybrid", 1088)] {
        let home = d.p(class);
        ok(&["--home", s(&home), "init", "--class", class]);
        assert!(!home.join("handovers.json").exists(), "nothing before E-3");
        if class != "bare" {
            ok(&["--home", s(&home), "packet"]);
        }
        ok(&["--home", s(&home), "buyer-key"]);
        let all: Vec<serde_json::Value> =
            serde_json::from_slice(&std::fs::read(home.join("handovers.json")).unwrap()).unwrap();
        assert_eq!(all.len(), 1, "{class}");
        let h = &all[0];
        assert_eq!(h["to"], "did:key:zKsgBuyer#k1", "{class}");
        assert_eq!(h["up_to"], 2, "{class}");
        assert_eq!(h["suite"], suite, "{class}");
        let kem_len = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(h["kem"].as_str().unwrap())
            .unwrap()
            .len();
        assert_eq!(kem_len, kem, "{class}");
        // Levels 0, 1, 2: three keys of 33 bytes, sealed with a 16-byte tag.
        let sealed_len = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(h["sealed"].as_str().unwrap())
            .unwrap()
            .len();
        assert_eq!(sealed_len, 3 * 33 + 16, "{class}");
    }
}

/// K4 (`Bare_v2_spec`, owner's decision 06.10): the owner deletes a `bare`
/// with everything in it, confirming with its template; `light` and Pro are
/// not deleted this way.
#[test]
fn the_owner_deletes_a_bare_with_everything_in_it() {
    let d = Dir::new("delete");
    let (home, m) = (d.p("bare"), d.p("m.half"));
    to_work_as(&home, &m, "bare");
    ok(&[
        "--home",
        s(&home),
        "--mobile",
        s(&m),
        "work",
        "--did",
        "one",
    ]);
    let meta: serde_json::Value =
        serde_json::from_slice(&std::fs::read(home.join("container.json")).unwrap()).unwrap();
    let template = meta["template"].as_str().unwrap().to_owned();

    // Not its template: nothing goes.
    assert_eq!(
        code(&["--home", s(&home), "delete", "--template", "zQm-wrong"]),
        1
    );
    assert!(home.join("container.ksg").exists());

    ok(&["--home", s(&home), "delete", "--template", &template]);
    for f in [
        "container.ksg",
        "layer.key",
        "scan.key",
        "parties.json",
        "container.json",
        "handovers.json",
        "lock",
    ] {
        assert!(!home.join(f).exists(), "{f} is still there");
    }
    assert_ne!(code(&["--home", s(&home), "--mobile", s(&m), "status"]), 0);

    // `light` keeps its journal: refused, nothing removed.
    let (light, lm) = (d.p("light"), d.p("l.half"));
    to_work_as(&light, &lm, "light");
    let meta: serde_json::Value =
        serde_json::from_slice(&std::fs::read(light.join("container.json")).unwrap()).unwrap();
    let out = ksg(&[
        "--home",
        s(&light),
        "delete",
        "--template",
        meta["template"].as_str().unwrap(),
    ]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("only a bare"));
    assert!(light.join("container.ksg").exists());
}

/// `Bare_v2_spec` §3 `identity.rs`: no publication of the agent's ID for
/// `bare` (K2: its only anchor is the issuance anchor) — and none for
/// `light`; Pro publishes (KS-8 C-10, step 1), only once initiated, only
/// once. On the stand without a network the anchor is the local one.
#[test]
fn only_pro_publishes_an_agents_id() {
    let d = Dir::new("agent-id");
    let id = "did:web:agent.example.com";
    for class in ["bare", "light"] {
        let (home, m) = (d.p(class), d.p(&format!("{class}.half")));
        to_work_as(&home, &m, class);
        let out = ksg(&[
            "--home",
            s(&home),
            "--mobile",
            s(&m),
            "publish-id",
            "--id",
            id,
        ]);
        assert!(!out.status.success(), "{class}");
        assert!(String::from_utf8_lossy(&out.stderr).contains("Pro container"));
        assert!(!home.join("agent-id.json").exists());
    }
    // Pro before initiation: no client's key, nothing to publish with.
    let early = d.p("early");
    ok(&["--home", s(&early), "init", "--class", "heavy"]);
    ok(&["--home", s(&early), "packet"]);
    assert_eq!(code(&["--home", s(&early), "publish-id", "--id", id]), 1);

    let (home, m) = (d.p("heavy"), d.p("heavy.half"));
    to_work_as(&home, &m, "heavy");
    // Not a URI: refused.
    assert_eq!(
        code(&[
            "--home",
            s(&home),
            "--mobile",
            s(&m),
            "publish-id",
            "--id",
            "no spaces allowed"
        ]),
        1
    );
    let out = ksg(&[
        "--home",
        s(&home),
        "--mobile",
        s(&m),
        "publish-id",
        "--id",
        id,
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("anchored   local"));
    let doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(home.join("agent-id.json")).unwrap()).unwrap();
    assert_eq!(doc["open_id"], id);
    assert_eq!(doc["container"], id_of(&home));
    assert_eq!(
        code(&[
            "--home",
            s(&home),
            "--mobile",
            s(&m),
            "publish-id",
            "--id",
            id
        ]),
        1,
        "a second publication"
    );
}

fn id_of(home: &Path) -> String {
    id(home).to_multihash()
}

/// A file kept whole in the journal (`[decision]` 17.10 "kept in the journal
/// whole or outside the container"): the file is cut into pages under a
/// service page that names its media type, the final export carries the
/// bytes and verifies, and the pages put back together give the file the
/// attachment's hash names. A file larger than one record, or an unknown
/// `--keep`, is refused and leaves the container as it was.
#[test]
fn a_file_kept_whole_in_the_journal_comes_back_from_the_export() {
    let d = Dir::new("attach-whole");
    let (home, mobile) = (d.p("home"), d.p("mobile.half"));
    let (h, m) = (s(&home), s(&mobile));
    let file: Vec<u8> = (0..5000u32).map(|i| (i * 7 % 251) as u8).collect();
    std::fs::write(d.p("model.bin"), &file).unwrap();
    std::fs::write(d.p("big.bin"), vec![1u8; 99 * 2048 + 1]).unwrap();

    ok(&["--home", h, "init", "--class", "light"]);
    ok(&["--home", h, "packet"]);
    ok(&["--home", h, "buyer-key"]);
    ok(&["--home", h, "--mobile", m, "initiate"]);
    ok(&["--home", h, "--mobile", m, "open-journal"]);
    let attach = |file: &Path, keep: &str| {
        code(&[
            "--home",
            h,
            "--mobile",
            m,
            "attach",
            "--type",
            "urn:ksg:page:artifact:v1",
            "--file",
            s(file),
            "--mime",
            "application/octet-stream",
            "--keep",
            keep,
        ])
    };
    let before = std::fs::read(home.join("container.ksg")).unwrap();
    assert_eq!(
        attach(&d.p("big.bin"), "journal"),
        1,
        "larger than a record"
    );
    assert_eq!(attach(&d.p("model.bin"), "inside"), 2, "an unknown --keep");
    assert_eq!(std::fs::read(home.join("container.ksg")).unwrap(), before);

    assert_eq!(attach(&d.p("model.bin"), "journal"), 0);
    ok(&["--home", h, "finalize"]);
    ok(&[
        "--home",
        h,
        "--mobile",
        m,
        "export-final",
        "--out",
        s(&d.p("final.json")),
    ]);
    ok(&["--home", h, "keys", "--out", s(&d.p("keys.json"))]);

    let r = verdict(&d, &home, &d.p("final.json"), Class::Light);
    assert!(r.accepted, "{r:?}");
    assert_eq!(
        r.pages,
        Some(5),
        "opening, three pages of the file, service page"
    );

    let exp: serde_json::Value =
        serde_json::from_slice(&std::fs::read(d.p("final.json")).unwrap()).unwrap();
    let mut back = Vec::new();
    for n in 1..=3 {
        let content = &exp["pages"][n]["body"]["content"];
        assert_eq!(content["content_type"], "urn:ksg:page:artifact:v1");
        let b64 = content["content"]["inline"]
            .as_str()
            .unwrap_or_else(|| panic!("page {n} carries the bytes: {content}"));
        back.extend(base64_decode(b64));
    }
    assert_eq!(back, file, "the pages put back together are the file");
    assert_eq!(
        exp["pages"][4]["body"]["manifest"]["media"],
        "application/octet-stream"
    );
}

fn base64_decode(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s))
        .unwrap()
}

/// The working chain of a `bare` (owner's decision 17.10, decision PCh-14 of 30.09): a site is
/// built backend → frontend → design → marketing; at each step the agent
/// hands off to the next one and the owner may change too. Each transfer is
/// signed by the owner and the arriving owner, writes a page of the transfer
/// zone, and leaves the agent until a hand-off; the former owner's key no
/// longer signs. After the transfers the `bare` still attaches to a leader.
#[test]
fn a_bare_passes_from_backend_to_frontend_to_design_to_marketing() {
    let d = Dir::new("bare-chain");
    let (h, a) = (d.p("site"), d.p("backend.half"));
    to_work_as(&h, &a, "bare");
    let hs = s(&h);
    // Three other owners: the frontend's, the designer's, the marketer's.
    let owners: Vec<PathBuf> = ["front-owner", "design-owner", "market-owner"]
        .iter()
        .map(|n| {
            let o = d.p(n);
            ok(&["--home", s(&o), "init", "--class", "bare"]);
            o
        })
        .collect();
    ok(&[
        "--home",
        hs,
        "--mobile",
        s(&a),
        "work",
        "--did",
        "backend done",
    ]);

    // No journal page without a new owner's home; the same home is refused.
    assert_eq!(code(&["--home", hs, "--mobile", s(&a), "owner-change"]), 1);
    assert_eq!(
        code(&[
            "--home",
            hs,
            "--mobile",
            s(&a),
            "owner-change",
            "--new-owner-home",
            hs
        ]),
        1
    );

    let mut half = a.clone();
    let mut previous_owner_kid = String::new();
    for (i, (owner, agent)) in owners
        .iter()
        .zip([
            "did:key:zFrontend",
            "did:key:zDesigner",
            "did:key:zMarketer",
        ])
        .enumerate()
    {
        let before = status_line(&h, "pages ");
        ok(&[
            "--home",
            hs,
            "--mobile",
            s(&half),
            "owner-change",
            "--new-owner-home",
            s(owner),
        ]);
        let parties: serde_json::Value =
            serde_json::from_slice(&std::fs::read(h.join("parties.json")).unwrap()).unwrap();
        let theirs: serde_json::Value =
            serde_json::from_slice(&std::fs::read(owner.join("parties.json")).unwrap()).unwrap();
        assert_eq!(
            parties["owner"], theirs["owner"],
            "the new owner takes the seat: {i}"
        );
        let kid = parties["owner_kid"].as_str().unwrap().to_owned();
        assert_ne!(kid, previous_owner_kid);
        previous_owner_kid = kid;
        assert_ne!(
            status_line(&h, "pages "),
            before,
            "the transfer writes a page"
        );
        assert_eq!(
            status_line(&h, "coupling "),
            "none",
            "a transfer is not an attachment"
        );

        // The agent stays until the hand-off; then the next agent works.
        let next = d.p(&format!("agent{i}.half"));
        ok(&[
            "--home",
            hs,
            "--mobile",
            s(&half),
            "handoff",
            "--name",
            agent,
            "--new-mobile",
            s(&next),
        ]);
        assert_eq!(
            code(&["--home", hs, "--mobile", s(&half), "work", "--did", "after"]),
            1,
            "the former agent's half no longer signs"
        );
        half = next;
        ok(&["--home", hs, "--mobile", s(&half), "work", "--did", agent]);
    }

    // After three transfers the bare still attaches to a Pro leader.
    let (l, lm) = (d.p("leader"), d.p("leader.half"));
    to_work_as(&l, &lm, "heavy");
    ok(&[
        "--home",
        hs,
        "--mobile",
        s(&half),
        "attach-to",
        "--leader-home",
        s(&l),
        "--agent",
        "did:key:zLeaderAgent",
        "--new-mobile",
        s(&d.p("leader-agent.half")),
    ]);
    assert_eq!(
        status_line(&h, "coupling "),
        "attached as a trailer: read-only"
    );
}

/// The layers written zone by zone through the program (owner's decision
/// 18.10 "A"): printing writes the release zone under level 0's key, the
/// packet the packet zone under level 1's; each opens with its own level's
/// key and not with the one below; the rest is noise of the same width.
#[test]
fn the_release_and_packet_zones_are_sealed_under_their_own_levels() {
    use ksg_cli_v2::reader::Reader;
    use ksg_container_v2::layout::{open_zone, ZONE_BYTES, ZONE_POSITIONS};
    let d = Dir::new("zones");
    let home = d.p("home");
    let h = s(&home);
    ok(&["--home", h, "init", "--class", "light"]);
    ok(&["--home", h, "packet"]);
    let r = Reader::open(&home, Box::new(ksg_cli_v2::mobile::NoMobile)).unwrap();
    let meta: serde_json::Value =
        serde_json::from_slice(&std::fs::read(home.join("container.json")).unwrap()).unwrap();
    let template =
        ksg_core_v2::crypto::hash::Hash::from_multihash(meta["template"].as_str().unwrap())
            .unwrap();
    for p in 0..ZONE_POSITIONS {
        assert_eq!(r.c.sealed_zone(p).unwrap().len(), ZONE_BYTES);
    }
    let release = open_zone(
        &r.zone_key(0),
        template.as_bytes(),
        0,
        r.c.sealed_zone(0).unwrap(),
    )
    .expect("the release zone opens with level 0's key");
    assert!(release.starts_with(&[0, 7]) && release[2..9] == *b"Release");
    let packet = open_zone(
        &r.zone_key(1),
        template.as_bytes(),
        1,
        r.c.sealed_zone(1).unwrap(),
    )
    .expect("the packet zone opens with level 1's key");
    assert!(packet[2..8] == *b"Packet");
    assert!(
        open_zone(
            &r.zone_key(0),
            template.as_bytes(),
            1,
            r.c.sealed_zone(1).unwrap()
        )
        .is_err(),
        "the level below does not open the packet zone"
    );
    assert!(
        open_zone(
            &r.zone_key(2),
            template.as_bytes(),
            2,
            r.c.sealed_zone(2).unwrap()
        )
        .is_err(),
        "a chain position never written is noise"
    );
}

/// `light` and Pro change owner as many times as the chain has positions
/// (owner's decision 18.10 "A", CH-15's hundred transfers): seven owners in a
/// row — past the six C-3 gave — each takes the seat, the former one's key
/// no longer signs, and each change writes its own chain position under the
/// writing level's key.
#[test]
fn light_and_pro_pass_through_seven_owners() {
    use ksg_cli_v2::reader::Reader;
    use ksg_container_v2::layout::open_zone;
    for class in ["light", "heavy"] {
        let d = Dir::new(&format!("seven-{class}"));
        let (home, half) = (d.p("home"), d.p("m.half"));
        to_work_as(&home, &half, class);
        let (h, m) = (s(&home), s(&half));
        ok(&["--home", h, "--mobile", m, "work", "--did", "first"]);
        let mut kids = Vec::new();
        for n in 0..7 {
            let o = d.p(&format!("owner{n}"));
            ok(&["--home", s(&o), "init", "--class", class]);
            let before = status_line(&home, "pages ");
            ok(&[
                "--home",
                h,
                "--mobile",
                m,
                "owner-change",
                "--new-owner-home",
                s(&o),
            ]);
            assert_ne!(status_line(&home, "pages "), before, "{class} {n}: a page");
            let parties: serde_json::Value =
                serde_json::from_slice(&std::fs::read(home.join("parties.json")).unwrap()).unwrap();
            let theirs: serde_json::Value =
                serde_json::from_slice(&std::fs::read(o.join("parties.json")).unwrap()).unwrap();
            assert_eq!(parties["owner"], theirs["owner"], "{class} {n}: the seat");
            kids.push(parties["owner_kid"].as_str().unwrap().to_owned());
            ok(&[
                "--home",
                h,
                "--mobile",
                m,
                "work",
                "--did",
                &format!("after {n}"),
            ]);
        }
        kids.dedup();
        assert_eq!(kids.len(), 7, "{class}: seven different owners");
        assert_eq!(
            code(&[
                "--home",
                h,
                "--mobile",
                m,
                "owner-change",
                "--new-owner-home",
                h
            ]),
            1,
            "{class}: not to itself"
        );

        let r = Reader::open(&home, Box::new(ksg_cli_v2::mobile::NoMobile)).unwrap();
        let meta: serde_json::Value =
            serde_json::from_slice(&std::fs::read(home.join("container.json")).unwrap()).unwrap();
        let template =
            ksg_core_v2::crypto::hash::Hash::from_multihash(meta["template"].as_str().unwrap())
                .unwrap();
        for p in 2..2 + 7 {
            let f = open_zone(
                &r.zone_key(p),
                template.as_bytes(),
                p,
                r.c.sealed_zone(p).unwrap(),
            )
            .unwrap_or_else(|_| panic!("{class}: chain position {p} opens with its key"));
            assert!(f[2..7] == *b"Chain");
        }
        assert!(!r.c.sealed_zone_written(9), "{class}: the eighth is noise");
    }
}

/// KS-8 C-10, step 3 (`[decision]` 10.09, owner's word 19.10): the claim
/// `hash(artifact) + hash(agent ID)` goes into the journal only after step 1
/// — this container's agent ID published in the chain. Without it, with a
/// publication of another container or with an ID other than the one
/// published, the container refuses it.
#[test]
fn a_claim_of_ownership_follows_the_published_agent_id() {
    let d = Dir::new("claim");
    let artifact = d.p("artifact.png");
    std::fs::write(&artifact, b"the artefact").unwrap();
    let (home, m) = (d.p("heavy"), d.p("heavy.half"));
    to_work_as(&home, &m, "heavy");
    let (h, mh, a) = (s(&home), s(&m), s(&artifact));
    let claim = |h: &str, m: &str| {
        let out = ksg(&["--home", h, "--mobile", m, "claim", "--artifact-file", a]);
        assert!(!out.status.success());
        String::from_utf8_lossy(&out.stderr).into_owned()
    };

    // Step 3 without step 1.
    let e = claim(h, mh);
    assert!(e.contains("step 1 first"), "{e}");

    // A publication made for another container does not serve here.
    let (other, om) = (d.p("other"), d.p("other.half"));
    to_work_as(&other, &om, "heavy");
    ok(&[
        "--home",
        s(&other),
        "--mobile",
        s(&om),
        "publish-id",
        "--id",
        "did:web:other.example.com",
    ]);
    std::fs::copy(other.join("agent-id.json"), home.join("agent-id.json")).unwrap();
    let e = claim(h, mh);
    assert!(e.contains("step 1: this container's agent ID"), "{e}");
    std::fs::remove_file(home.join("agent-id.json")).unwrap();

    ok(&[
        "--home",
        h,
        "--mobile",
        mh,
        "publish-id",
        "--id",
        "did:web:agent.example.com",
    ]);
    // The ID claimed is not the one published.
    let kept = std::fs::read(home.join("agent-id.json")).unwrap();
    let mut doc: serde_json::Value = serde_json::from_slice(&kept).unwrap();
    doc["open_id"] = "did:web:someone-else.example.com".into();
    std::fs::write(
        home.join("agent-id.json"),
        serde_json::to_vec(&doc).unwrap(),
    )
    .unwrap();
    let e = claim(h, mh);
    assert!(e.contains("step 1: this container's agent ID"), "{e}");
    std::fs::write(home.join("agent-id.json"), &kept).unwrap();

    let before = status_line(&home, "pages ");
    ok(&["--home", h, "--mobile", mh, "claim", "--artifact-file", a]);
    assert_ne!(status_line(&home, "pages "), before, "the claim is a page");
}
