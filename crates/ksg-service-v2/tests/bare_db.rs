//! `bare_db` ledger tests: HMAC determinism, insert/duplicate/count.
//!
//! Pure-hash tests always run. Database tests need a Postgres with migration
//! `core-v2/migrations/001_bare_issuance.sql` applied and the connection
//! string in `KSG_BARE_TEST_DATABASE_URL`; without it they print a notice and
//! pass without touching the database.
//!
//! Run with a database:
//! `KSG_BARE_TEST_DATABASE_URL="host=127.0.0.1 user=... dbname=..." cargo test -p ksg-service-v2 --test bare_db`
//!
//! Contact values below are `example.com` placeholders, never real holders.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ksg_service_v2::bare_db::{
    did_web_domain, domain_hmac, holder_hmac, insert_issuance, issued_count, load_hmac_key,
    next_free_number, BareDbError, HMAC_KEY_FILE_ENV,
};
use std::sync::{Mutex, OnceLock};

const TEST_KEY: &[u8] = b"bare-db-test-hmac-key";

/// Serializes the one test that rewrites the key-file env variable.
fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn unique_release(tag: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("wall clock before epoch")
        .as_nanos();
    format!("bare-test-{tag}-{}-{nanos}", std::process::id())
}

/// Database client, or `None` when no test database is configured.
fn test_client() -> Option<postgres::Client> {
    let url = std::env::var("KSG_BARE_TEST_DATABASE_URL").ok()?;
    postgres::Client::connect(&url, postgres::NoTls).ok()
}

fn require_client() -> Option<postgres::Client> {
    let client = test_client();
    if client.is_none() {
        eprintln!("skipped: set KSG_BARE_TEST_DATABASE_URL for bare_db database tests");
    }
    client
}

fn ensure_release(client: &mut postgres::Client, id: &str, size: i32) {
    client
        .execute(
            "INSERT INTO releases (id, size) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING",
            &[&id, &size],
        )
        .expect("insert test release");
}

#[test]
fn hmac_is_deterministic() {
    let a = holder_hmac(TEST_KEY, "user@example.com");
    let b = holder_hmac(TEST_KEY, "user@example.com");
    assert_eq!(a, b);
    let c = domain_hmac(TEST_KEY, "example.com");
    let d = domain_hmac(TEST_KEY, "example.com");
    assert_eq!(c, d);
}

#[test]
fn hmac_separates_contacts_keys_and_kinds() {
    let email = holder_hmac(TEST_KEY, "user@example.com");
    assert_ne!(email, holder_hmac(TEST_KEY, "other@example.com"));
    assert_ne!(email, holder_hmac(b"another-key", "user@example.com"));
    assert_ne!(email, holder_hmac(TEST_KEY, "did:web:example.com"));
    assert_ne!(
        domain_hmac(TEST_KEY, "example.com"),
        domain_hmac(TEST_KEY, "other.org")
    );
}

#[test]
fn did_web_domain_cases() {
    assert_eq!(did_web_domain("did:web:example.com"), Some("example.com"));
    assert_eq!(
        did_web_domain("did:web:example.com:path:to:did"),
        Some("example.com")
    );
    assert_eq!(did_web_domain("did:web:"), None);
    assert_eq!(did_web_domain("web:example.com"), None);
    assert_eq!(did_web_domain("did:web:example.com"), Some("example.com"));
    assert_eq!(did_web_domain("mailto:user@example.com"), None);
}

#[test]
fn load_key_missing_env_and_empty_file() {
    let _guard = env_lock().lock().expect("env lock");
    let previous = std::env::var(HMAC_KEY_FILE_ENV).ok();

    std::env::remove_var(HMAC_KEY_FILE_ENV);
    assert!(matches!(load_hmac_key(), Err(BareDbError::Env)));

    let path = std::env::temp_dir().join(format!(
        "ksg-bare-test-empty-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("wall clock before epoch")
            .as_nanos()
    ));
    std::fs::write(&path, b"").expect("write empty key file");
    std::env::set_var(HMAC_KEY_FILE_ENV, &path);
    assert!(matches!(load_hmac_key(), Err(BareDbError::KeyFile)));
    std::fs::remove_file(&path).expect("remove empty key file");

    std::env::set_var(HMAC_KEY_FILE_ENV, path.with_extension("no-such-file"));
    assert!(matches!(load_hmac_key(), Err(BareDbError::KeyFile)));

    match previous {
        Some(v) => std::env::set_var(HMAC_KEY_FILE_ENV, v),
        None => std::env::remove_var(HMAC_KEY_FILE_ENV),
    }
}

#[test]
fn load_key_reads_file_bytes() {
    let _guard = env_lock().lock().expect("env lock");
    let previous = std::env::var(HMAC_KEY_FILE_ENV).ok();

    let path = std::env::temp_dir().join(format!(
        "ksg-bare-test-key-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("wall clock before epoch")
            .as_nanos()
    ));
    std::fs::write(&path, b"file-secret-bytes").expect("write key file");
    std::env::set_var(HMAC_KEY_FILE_ENV, &path);
    let key = load_hmac_key().expect("key file reads");
    assert_eq!(key.as_slice(), b"file-secret-bytes");
    std::fs::remove_file(&path).expect("remove key file");

    match previous {
        Some(v) => std::env::set_var(HMAC_KEY_FILE_ENV, v),
        None => std::env::remove_var(HMAC_KEY_FILE_ENV),
    }
}

#[test]
fn db_insert_count_and_next_free() {
    let Some(mut client) = require_client() else {
        return;
    };
    let release = unique_release("insert");
    ensure_release(&mut client, &release, 3);

    assert_eq!(
        next_free_number(&mut client, &release).expect("next free"),
        Some(1)
    );
    let holder = holder_hmac(TEST_KEY, "user@example.com");
    insert_issuance(&mut client, &release, 1, &holder, None).expect("insert");
    assert_eq!(issued_count(&mut client, &release).expect("count"), 1);
    assert_eq!(
        next_free_number(&mut client, &release).expect("next free"),
        Some(2)
    );
}

#[test]
fn db_duplicate_holder_is_refused() {
    let Some(mut client) = require_client() else {
        return;
    };
    let release = unique_release("dupholder");
    ensure_release(&mut client, &release, 3);

    let holder = holder_hmac(TEST_KEY, "repeat@example.com");
    insert_issuance(&mut client, &release, 1, &holder, None).expect("first insert");
    let err = insert_issuance(&mut client, &release, 2, &holder, None).expect_err("duplicate");
    assert!(matches!(err, BareDbError::AlreadyIssued));
    assert_eq!(issued_count(&mut client, &release).expect("count"), 1);
}

#[test]
fn db_duplicate_domain_is_refused() {
    let Some(mut client) = require_client() else {
        return;
    };
    let release = unique_release("dupdomain");
    ensure_release(&mut client, &release, 3);

    let domain = domain_hmac(TEST_KEY, "example.com");
    let first = holder_hmac(TEST_KEY, "did:web:example.com");
    let second = holder_hmac(TEST_KEY, "did:web:example.com:other");
    insert_issuance(&mut client, &release, 1, &first, Some(&domain)).expect("first insert");
    let err = insert_issuance(&mut client, &release, 2, &second, Some(&domain))
        .expect_err("duplicate domain");
    assert!(matches!(err, BareDbError::AlreadyIssued));
}

#[test]
fn db_full_release_has_no_free_number() {
    let Some(mut client) = require_client() else {
        return;
    };
    let release = unique_release("full");
    ensure_release(&mut client, &release, 1);

    let holder = holder_hmac(TEST_KEY, "only@example.com");
    insert_issuance(&mut client, &release, 1, &holder, None).expect("insert");
    assert_eq!(next_free_number(&mut client, &release).expect("next free"), None);
}

#[test]
fn db_unknown_release_errors() {
    let Some(mut client) = require_client() else {
        return;
    };
    let err = next_free_number(&mut client, &unique_release("unknown")).expect_err("unknown");
    assert!(matches!(err, BareDbError::UnknownRelease));
}
