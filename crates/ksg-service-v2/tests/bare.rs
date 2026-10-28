//! `bare` issuance, этап 1: routes without a database.
//!
//! The tests drive `Shared::bare_route` in-process — no network port, no
//! signer, no database. Contact values (email / did:web) never reach logs.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ksg_service_v2::server::Shared;

const T0: u64 = 1_790_000_000_000;

fn shared() -> Shared {
    Shared::bare_only("https://svc.example/v1").unwrap()
}

#[test]
fn bad_email_is_400() {
    let s = shared();
    for body in [
        r#"{"email":"not-an-email"}"#,
        r#"{"email":"a@b"}"#,
        r#"{"email":"a b@c.de"}"#,
        r#"{}"#,
        r#"{"email":"a@b.co","did_web":"did:web:x"}"#,
        r#"{"did_web":"did:web:"}"#,
        r#"{"did_web":"web:example.com"}"#,
    ] {
        let r = s.bare_route("POST", "/v1/bare/start", body.as_bytes(), T0);
        assert_eq!(r.status(), 400, "body {body}");
    }
}

#[test]
fn good_contact_returns_six_digits() {
    let s = shared();
    for body in [
        r#"{"email":"user@example.com"}"#,
        r#"{"did_web":"did:web:example.com"}"#,
    ] {
        let r = s.bare_route("POST", "/v1/bare/start", body.as_bytes(), T0);
        assert_eq!(r.status(), 200, "body {body}");
        let code = r.body()["code"].as_str().unwrap();
        assert_eq!(code.len(), 6, "code {code}");
        assert!(code.bytes().all(|b: u8| b.is_ascii_digit()), "code {code}");
        let id = r.body()["id"].as_str().unwrap();
        assert!(!id.is_empty(), "id is present");
        assert_eq!(
            r.body()["send_to"].as_str().unwrap(),
            "verify@keysingate.com"
        );
    }
}

#[test]
fn unknown_status_id_is_404() {
    let s = shared();
    let r = s.bare_route("GET", "/v1/bare/status/no-such-id", &[], T0);
    assert_eq!(r.status(), 404);
}

#[test]
fn count_is_zero() {
    let s = shared();
    let r = s.bare_route("GET", "/v1/bare/count", &[], T0);
    assert_eq!(r.status(), 200);
    assert_eq!(r.body()["issued"], 0);
}

#[test]
fn started_request_is_pending() {
    let s = shared();
    let r = s.bare_route(
        "POST",
        "/v1/bare/start",
        br#"{"email":"user@example.com"}"#,
        T0,
    );
    assert_eq!(r.status(), 200);
    let id = r.body()["id"].as_str().unwrap().to_owned();
    let r = s.bare_route("GET", &format!("/v1/bare/status/{id}"), &[], T0);
    assert_eq!(r.status(), 200);
    assert_eq!(r.body()["state"].as_str().unwrap(), "pending");
}
