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
//! Contact values below are `example.com` placeholders, never real holders.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ksg_service_v2::bare_db::HMAC_KEY_FILE_ENV;
use ksg_service_v2::server::Shared;
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
        let r = s.bare_route("POST", "/v1/bare/mail", body, T0);
        assert_eq!(r.status(), 400, "body {:?}", String::from_utf8_lossy(body));
    }
}

#[test]
fn mail_unknown_request_is_404() {
    let _guard = env_lock().lock().expect("env lock");
    let _key = temp_key();
    let s = shared();
    // Code in the subject.
    let r = s.bare_route(
        "POST",
        "/v1/bare/mail",
        &mail_body("no-such-id", &raw("user@example.com", "code 123456", "see 123456")),
        T0,
    );
    assert_eq!(r.status(), 404);
    // Code in the text body instead of the subject.
    let r = s.bare_route(
        "POST",
        "/v1/bare/mail",
        &mail_body("no-such-id", &raw("user@example.com", "hello", "your code is 654321")),
        T0,
    );
    assert_eq!(r.status(), 404);
}

#[test]
fn mail_foreign_from_is_404() {
    let _guard = env_lock().lock().expect("env lock");
    let _key = temp_key();
    let s = shared();
    let (id, code) = start_for(&s, "owner@example.com");
    // The code is right but the From address is someone else's: no match.
    let r = s.bare_route(
        "POST",
        "/v1/bare/mail",
        &mail_body(&id, &raw("stranger@example.com", &format!("code {code}"), &code)),
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
fn mail_replay_after_dkim_refusal_is_404() {
    let _guard = env_lock().lock().expect("env lock");
    if std::env::var("KSG_BARE_TEST_LIVE_DNS").is_err() {
        eprintln!("skipped: set KSG_BARE_TEST_LIVE_DNS=1 for the DKIM replay test");
        return;
    }
    let _key = temp_key();
    let s = shared();
    let (id, code) = start_for(&s, "owner@example.com");
    let letter = raw("owner@example.com", &format!("code {code}"), &code);
    // `example.com` carries no DKIM key for us: 403, but the code is consumed.
    let r = s.bare_route("POST", "/v1/bare/mail", &mail_body(&id, &letter), T0);
    assert_eq!(r.status(), 403);
    // Same letter again: no pending request anymore.
    let r = s.bare_route("POST", "/v1/bare/mail", &mail_body(&id, &letter), T0);
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
