//! `mail` intake tests: malformed / unknown / foreign / replay.
//!
//! The tests drive `Shared::bare_route` in-process — no network port, no
//! signer. Cases that stop before the DKIM check (400 malformed, 404 no
//! pending match) always run and need neither Postgres nor DNS.
//!
//! Two paths need the outside world and skip without it:
//! - replay after a DKIM refusal needs live DNS
//!   (`KSG_BARE_TEST_LIVE_DNS=1`): the first delivery consumes the code
//!   (403, DKIM of `example.com` never passes), the replay finds nothing
//!   (404);
//! - a fully valid delivery (200 `issued`) needs a real DKIM-signed letter
//!   plus Postgres (`KSG_BARE_DATABASE_URL` + `KSG_BARE_RELEASE`): a manual
//!   stand, see the skipped `mail_valid_delivery_is_manual_stand` test.
//!
//! The DKIM-refusal-keeps-request test below needs no live DNS: whether the
//! refusal comes from "no key for `example.com`" or from "no network", the
//! unsigned forged letter always fails closed with 403 while the request
//! stays pending (С13 `find_match` + consume-after-DKIM, С14 double-From
//! guard).
//!
//! Contact values below are `example.com` placeholders, never real holders.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ksg_service_v2::bare_db::HMAC_KEY_FILE_ENV;
use ksg_service_v2::server::{Shared, BARE_WORKER_SECRET_FILE_ENV};
use std::sync::{Mutex, OnceLock};

const T0: u64 = 1_790_000_000_000;

/// Serializes the tests that rewrite the HMAC key-file env variable.
fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn shared() -> Shared {
    Shared::bare_only("https://svc.example/v1").unwrap()
}

fn raw(from: &str, subject: &str, body: &str) -> String {
    format!("From: {from}\r\nSubject: {subject}\r\n\r\n{body}\r\n")
}

fn mail_body(id: &str, raw: &str) -> Vec<u8> {
    serde_json::json!({"id": id, "raw": raw})
        .to_string()
        .into_bytes()
}

/// Points the HMAC key at a fresh temp file; returns a guard restoring the
/// previous value and removing the file on drop.
fn temp_key() -> TempKey {
    let path = std::env::temp_dir().join(format!(
        "ksg-bare-mail-test-key-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("wall clock before epoch")
            .as_nanos()
    ));
    std::fs::write(&path, b"bare-mail-test-hmac-key").expect("write key file");
    let previous = std::env::var(HMAC_KEY_FILE_ENV).ok();
    std::env::set_var(HMAC_KEY_FILE_ENV, &path);
    TempKey { path, previous }
}

struct TempKey {
    path: std::path::PathBuf,
    previous: Option<String>,
}

impl Drop for TempKey {
    fn drop(&mut self) {
        match self.previous.take() {
            Some(v) => std::env::set_var(HMAC_KEY_FILE_ENV, v),
            None => std::env::remove_var(HMAC_KEY_FILE_ENV),
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

fn mail_auth_body(_shared: &Shared, id: &str, raw: &str) -> Vec<u8> {
    mail_body(id, raw)
}

/// Points the worker bearer secret at a fresh temp file; returns the header
/// value plus a guard restoring the previous env value on drop.
fn temp_worker_secret(secret: &[u8]) -> (String, TempWorkerSecret) {
    let path = std::env::temp_dir().join(format!(
        "ksg-bare-mail-worker-secret-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("wall clock before epoch")
            .as_nanos()
    ));
    std::fs::write(&path, secret).expect("write worker secret file");
    let previous = std::env::var(BARE_WORKER_SECRET_FILE_ENV).ok();
    std::env::set_var(BARE_WORKER_SECRET_FILE_ENV, &path);
    let header = format!("Bearer {}", String::from_utf8_lossy(secret));
    (header, TempWorkerSecret { path, previous })
}

struct TempWorkerSecret {
    path: std::path::PathBuf,
    previous: Option<String>,
}

impl Drop for TempWorkerSecret {
    fn drop(&mut self) {
        match self.previous.take() {
            Some(v) => std::env::set_var(BARE_WORKER_SECRET_FILE_ENV, v),
            None => std::env::remove_var(BARE_WORKER_SECRET_FILE_ENV),
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Starts one request for `contact`, returns `(id, code)`.
fn start_for(s: &Shared, contact: &str) -> (String, String) {
    let body = format!(r#"{{"email":"{contact}"}}"#);
    let r = s.bare_route("POST", "/v1/bare/start", body.as_bytes(), T0);
    assert_eq!(r.status(), 200, "start {contact}");
    let id = r.body()["id"].as_str().expect("id").to_owned();
    let code = r.body()["code"].as_str().expect("code").to_owned();
    (id, code)
}

#[test]
fn mail_malformed_is_400() {
    let _guard = env_lock().lock().expect("env lock");
    let _key = temp_key();
    let (header, _secret) = temp_worker_secret(b"worker-secret-malformed-test");
    let s = shared();
    let bad: Vec<Vec<u8>> = vec![
        b"not json".to_vec(),
        br#"{}"#.to_vec(),
        br#"{"id":"x"}"#.to_vec(),
        br#"{"raw":"x"}"#.to_vec(),
        mail_body("", &raw("user@example.com", "code 123456", "123456")),
        mail_body("x", "Subject: 123456\r\n\r\nno from header"),
        mail_body("x", &raw("user@example.com", "hello", "no digits here")),
        mail_body("x", &raw("not-an-email", "code 123456", "123456")),
    ];
    for body in &bad {
        let r = s.bare_route_auth("POST", "/v1/bare/mail", body, Some(&header), T0);
        assert_eq!(r.status(), 400, "body {:?}", String::from_utf8_lossy(body));
    }
}

/// С17: without the worker bearer secret `mail` refuses with 401 before any
/// parsing — no header, wrong scheme, wrong secret, or no secret file.
#[test]
fn mail_worker_secret_is_required() {
    let _guard = env_lock().lock().expect("env lock");
    let _key = temp_key();
    let s = shared();
    let (id, code) = start_for(&s, "owner@example.com");
    let letter = raw("owner@example.com", &format!("code {code}"), &code);
    let body = mail_auth_body(&s, &id, &letter);
    // No header and a non-Bearer scheme: 401 without touching the ledger.
    for auth in [None, Some("Basic abc"), Some("Bearer wrong-secret-value")] {
        let r = s.bare_route_auth("POST", "/v1/bare/mail", &body, auth, T0);
        assert_eq!(r.status(), 401, "auth {:?}", auth.map(|a| &a[..a.len().min(12)]));
    }
    // No secret file configured even with a header: still 401.
    std::env::remove_var(BARE_WORKER_SECRET_FILE_ENV);
    let r = s.bare_route_auth("POST", "/v1/bare/mail", &body, Some("Bearer whatever"), T0);
    assert_eq!(r.status(), 401);
    // Right secret: the request is found (DKIM then fails closed with 403,
    // `example.com` never passes — but auth itself passed).
    let (header, _secret) = temp_worker_secret(b"worker-secret-for-test-17");
    let r = s.bare_route_auth("POST", "/v1/bare/mail", &body, Some(&header), T0);
    assert_eq!(r.status(), 403, "valid bearer must reach DKIM");
    // The request is still pending for its real owner.
    let r = s.bare_route("GET", &format!("/v1/bare/status/{id}"), &[], T0);
    assert_eq!(r.status(), 200);
    assert_eq!(r.body()["state"].as_str().unwrap(), "pending");
}

#[test]
fn mail_unknown_request_is_404() {
    let _guard = env_lock().lock().expect("env lock");
    let _key = temp_key();
    let (header, _secret) = temp_worker_secret(b"worker-secret-unknown-test");
    let s = shared();
    // Code in the subject.
    let r = s.bare_route_auth(
        "POST",
        "/v1/bare/mail",
        &mail_body("no-such-id", &raw("user@example.com", "code 123456", "see 123456")),
        Some(&header),
        T0,
    );
    assert_eq!(r.status(), 404);
    // Code in the text body instead of the subject.
    let r = s.bare_route_auth(
        "POST",
        "/v1/bare/mail",
        &mail_body("no-such-id", &raw("user@example.com", "hello", "your code is 654321")),
        Some(&header),
        T0,
    );
    assert_eq!(r.status(), 404);
}

#[test]
fn mail_foreign_from_is_404() {
    let _guard = env_lock().lock().expect("env lock");
    let _key = temp_key();
    let (header, _secret) = temp_worker_secret(b"worker-secret-foreign-test");
    let s = shared();
    let (id, code) = start_for(&s, "owner@example.com");
    // The code is right but the From address is someone else's: no match.
    let r = s.bare_route_auth(
        "POST",
        "/v1/bare/mail",
        &mail_body(&id, &raw("stranger@example.com", &format!("code {code}"), &code)),
        Some(&header),
        T0,
    );
    assert_eq!(r.status(), 404);
    // The request is still pending for its real owner.
    let r = s.bare_route(
        "GET",
        &format!("/v1/bare/status/{id}"),
        &[],
        T0,
    );
    assert_eq!(r.status(), 200);
    assert_eq!(r.body()["state"].as_str().unwrap(), "pending");
}

#[test]
fn mail_dkim_refusal_keeps_request_pending() {
    // С13: an unsigned forged letter always fails closed (403) without
    // consuming the request — the true owner can still deliver later. No
    // live DNS needed: `example.com` never passes either way.
    let _guard = env_lock().lock().expect("env lock");
    let _key = temp_key();
    let (header, _secret) = temp_worker_secret(b"worker-secret-refusal-test");
    let s = shared();
    let (id, code) = start_for(&s, "owner@example.com");
    let letter = raw("owner@example.com", &format!("code {code}"), &code);
    let r = s.bare_route_auth("POST", "/v1/bare/mail", &mail_body(&id, &letter), Some(&header), T0);
    assert_eq!(r.status(), 403, "unsigned forgery must fail closed");
    // The request is still pending for its real owner.
    let r = s.bare_route(
        "GET",
        &format!("/v1/bare/status/{id}"),
        &[],
        T0,
    );
    assert_eq!(r.status(), 200);
    assert_eq!(r.body()["state"].as_str().unwrap(), "pending");
}

#[test]
fn mail_double_from_is_400() {
    // С14: two `From` headers or two addresses in one `From` → 400, and the
    // request stays pending (never consumed by a malformed letter).
    let _guard = env_lock().lock().expect("env lock");
    let _key = temp_key();
    let (header, _secret) = temp_worker_secret(b"worker-secret-double-from-test");
    let s = shared();
    for (n, letter) in [
        (
            "two headers",
            format!(
                "From: owner@example.com\r\nFrom: stranger@example.com\r\nSubject: code {0}\r\n\r\n{0}\r\n",
                "123456"
            ),
        ),
        (
            "two addresses",
            "From: owner@example.com, stranger@example.com\r\nSubject: code 123456\r\n\r\n123456\r\n"
                .to_owned(),
        ),
    ] {
        let (id, code) = start_for(&s, "owner@example.com");
        let letter = letter.replace("123456", &code);
        let r = s.bare_route_auth("POST", "/v1/bare/mail", &mail_body(&id, &letter), Some(&header), T0);
        assert_eq!(r.status(), 400, "{n}");
        let r = s.bare_route(
            "GET",
            &format!("/v1/bare/status/{id}"),
            &[],
            T0,
        );
        assert_eq!(r.status(), 200, "{n} still pending");
        assert_eq!(r.body()["state"].as_str().unwrap(), "pending", "{n} still pending");
    }
}

#[test]
fn mail_replay_after_dkim_refusal_is_404() {
    let _guard = env_lock().lock().expect("env lock");
    if std::env::var("KSG_BARE_TEST_LIVE_DNS").is_err() {
        eprintln!("skipped: set KSG_BARE_TEST_LIVE_DNS=1 for the DKIM replay test");
        return;
    }
    let _key = temp_key();
    let (header, _secret) = temp_worker_secret(b"worker-secret-replay-test");
    let s = shared();
    let (id, code) = start_for(&s, "owner@example.com");
    let letter = raw("owner@example.com", &format!("code {code}"), &code);
    // `example.com` carries no DKIM key for us: 403, but the code is consumed.
    let r = s.bare_route_auth("POST", "/v1/bare/mail", &mail_body(&id, &letter), Some(&header), T0);
    assert_eq!(r.status(), 403);
    // Same letter again: no pending request anymore.
    let r = s.bare_route_auth("POST", "/v1/bare/mail", &mail_body(&id, &letter), Some(&header), T0);
    assert_eq!(r.status(), 404);
}

#[test]
fn mail_valid_delivery_is_manual_stand() {
    eprintln!(
        "skipped: a 200 `issued` delivery needs a real DKIM-signed letter \
         (DNS TXT at <selector>._domainkey.<domain>) plus Postgres with \
         migration core-v2/migrations/001_bare_issuance.sql, \
         KSG_BARE_DATABASE_URL and KSG_BARE_RELEASE set; run by hand"
    );
}
