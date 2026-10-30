//! Orchestrator `challenge` / `proof` tests (этап 11, in-process).
//!
//! The tests drive `Shared::bare_route` in-process — no network port, no
//! signer, no database. `challenge` never leaves the process; `proof` cases
//! below stop before the `did.json` fetch (400 malformed, 404 unknown id,
//! 403 foreign worker) or right after its refusal (503 unreachable, then a
//! 404 replay proving one challenge works once).
//!
//! Three paths need the outside world and stay a manual stand:
//! - a valid proof (200 `issued`) needs the domain's `did.json` over HTTPS
//!   carrying the signing key, plus Postgres (`KSG_BARE_DATABASE_URL` +
//!   `KSG_BARE_RELEASE`): see the skipped `orch_valid_proof_is_manual_stand`;
//! - a foreign signature (403 `bad signature`) needs the same stand with a
//!   key that is not the domain's;
//! - the per-domain limit (second issuance 409) needs Postgres with migration
//!   `core-v2/migrations/001_bare_issuance.sql`.
//!
//! Contact values below are `example.com` / `invalid` placeholders, never
//! real domains.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ksg_service_v2::server::{Shared, BARE_WORKER_DOMAIN_ENV};
use std::sync::{Mutex, OnceLock};

const T0: u64 = 1_790_000_000_000;

/// A well-formed 64-byte Ed25519 signature in base64url, all zeros: parses
/// as a signature but verifies against nothing.
const ZERO_SIG: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// Serializes the tests that rewrite the worker-domain env variable.
fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn shared() -> Shared {
    Shared::bare_only("https://svc.example/v1").unwrap()
}

/// Points the worker domain at `domain`; restores the previous value on drop.
fn worker_is(domain: &str) -> TempEnv {
    let previous = std::env::var(BARE_WORKER_DOMAIN_ENV).ok();
    std::env::set_var(BARE_WORKER_DOMAIN_ENV, domain);
    TempEnv { previous }
}

struct TempEnv {
    previous: Option<String>,
}

impl Drop for TempEnv {
    fn drop(&mut self) {
        match self.previous.take() {
            Some(v) => std::env::set_var(BARE_WORKER_DOMAIN_ENV, v),
            None => std::env::remove_var(BARE_WORKER_DOMAIN_ENV),
        }
    }
}

fn challenge_body(did_web: &str) -> Vec<u8> {
    serde_json::json!({"did_web": did_web})
        .to_string()
        .into_bytes()
}

fn proof_body(id: &str, signature: &str) -> Vec<u8> {
    serde_json::json!({"id": id, "signature": signature})
        .to_string()
        .into_bytes()
}

/// Starts one challenge for `did_web`, returns `(id, code)`.
fn start_for(s: &Shared, did_web: &str) -> (String, String) {
    let r = s.bare_route(
        "POST",
        "/v1/bare/orchestrator/challenge",
        &challenge_body(did_web),
        T0,
    );
    assert_eq!(r.status(), 200, "challenge {did_web}");
    let id = r.body()["id"].as_str().expect("id").to_owned();
    let code = r.body()["code"].as_str().expect("code").to_owned();
    assert!(!id.is_empty(), "id is present");
    assert!(!code.is_empty(), "code is present");
    (id, code)
}

#[test]
fn orch_challenge_malformed_is_400() {
    let s = shared();
    for body in [
        b"not json".to_vec(),
        br#"{}"#.to_vec(),
        br#"{"did_web":"web:example.com"}"#.to_vec(),
        br#"{"did_web":"did:web:"}"#.to_vec(),
        br#"{"did_web":"did:web:exa mple.com"}"#.to_vec(),
        br#"{"did_web":"did:web:example.com","extra":1}"#.to_vec(),
    ] {
        let r = s.bare_route("POST", "/v1/bare/orchestrator/challenge", &body, T0);
        assert_eq!(r.status(), 400, "body {:?}", String::from_utf8_lossy(&body));
    }
}

#[test]
fn orch_challenge_ok_returns_id_and_code() {
    let s = shared();
    let (id1, code1) = start_for(&s, "did:web:example.com");
    let (id2, code2) = start_for(&s, "did:web:example.com");
    assert_ne!(id1, id2, "challenge ids differ");
    assert_ne!(code1, code2, "challenge codes differ");
}

#[test]
fn orch_proof_malformed_is_400() {
    let s = shared();
    for body in [
        b"not json".to_vec(),
        br#"{}"#.to_vec(),
        br#"{"id":"x"}"#.to_vec(),
        br#"{"signature":"x"}"#.to_vec(),
        proof_body("", ZERO_SIG),
        proof_body("x", ""),
        proof_body("x", "not-a-signature!!"),
        proof_body("x", "AAAA"),
    ] {
        let r = s.bare_route("POST", "/v1/bare/orchestrator/proof", &body, T0);
        assert_eq!(r.status(), 400, "body {:?}", String::from_utf8_lossy(&body));
    }
}

#[test]
fn orch_proof_unknown_id_is_404() {
    let s = shared();
    let r = s.bare_route(
        "POST",
        "/v1/bare/orchestrator/proof",
        &proof_body("no-such-challenge", ZERO_SIG),
        T0,
    );
    assert_eq!(r.status(), 404);
}

#[test]
fn orch_proof_worker_mismatch_is_403() {
    let _guard = env_lock().lock().expect("env lock");
    let _worker = worker_is("other.example");
    let s = shared();
    // The challenge is for `example.com`, the worker serves another domain.
    let (id, _) = start_for(&s, "did:web:example.com");
    let r = s.bare_route(
        "POST",
        "/v1/bare/orchestrator/proof",
        &proof_body(&id, ZERO_SIG),
        T0,
    );
    assert_eq!(r.status(), 403);
}

#[test]
fn orch_proof_consumed_once_replay_is_404() {
    let _guard = env_lock().lock().expect("env lock");
    // `.invalid` never resolves (RFC 2606): the `did.json` fetch fails fast
    // with 503, but the challenge is consumed either way.
    let _worker = worker_is("unreachable.invalid");
    let s = shared();
    let (id, _) = start_for(&s, "did:web:unreachable.invalid");
    let first = s.bare_route(
        "POST",
        "/v1/bare/orchestrator/proof",
        &proof_body(&id, ZERO_SIG),
        T0,
    );
    assert_ne!(first.status(), 404, "first proof reaches past the ledger");
    assert_ne!(first.status(), 200, "zero signature never issues");
    // Same challenge again: spent, no pending challenge anymore.
    let r = s.bare_route(
        "POST",
        "/v1/bare/orchestrator/proof",
        &proof_body(&id, ZERO_SIG),
        T0,
    );
    assert_eq!(r.status(), 404);
}

#[test]
fn orch_valid_proof_is_manual_stand() {
    eprintln!(
        "skipped: a 200 `issued` proof needs the domain's did.json over HTTPS \
         (first verificationMethod entry: Ed25519 publicKeyMultibase) holding \
         the signing key, a signature over the challenge code, plus Postgres \
         with migration core-v2/migrations/001_bare_issuance.sql, \
         KSG_BARE_DATABASE_URL, KSG_BARE_RELEASE and KSG_BARE_WORKER_DOMAIN \
         set to the challenge domain; run by hand"
    );
}

#[test]
fn orch_bad_signature_and_domain_limit_is_manual_stand() {
    eprintln!(
        "skipped: a 403 `bad signature` proof needs the manual stand above \
         with a key that is not the domain's; the per-domain limit (second \
         issuance for the same domain 409 `already issued`) needs Postgres \
         with the same stand run twice; run by hand"
    );
}

#[test]
fn orch_fourth_challenge_of_one_domain_is_429() {
    let s = shared();
    for _ in 0..ksg_service_v2::server::ORCH_MAX_PER_DOMAIN {
        start_for(&s, "did:web:example.com");
    }
    let r = s.bare_route(
        "POST",
        "/v1/bare/orchestrator/challenge",
        &challenge_body("did:web:EXAMPLE.com"),
        T0,
    );
    assert_eq!(r.status(), 429);
    start_for(&s, "did:web:other.example");
}
