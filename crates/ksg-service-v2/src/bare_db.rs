//! The `bare` issuance ledger in Postgres: number N went to hash X.
//!
//! The database never sees a contact value (no email, no `did:web`, no time):
//! it stores only the irreversible hashes — `holder_hmac` for the holder and
//! `domain_hmac` for the orchestrator's domain — beside the issued number.
//! The HMAC secret lives in the issuance service, in a file whose path comes
//! from the `KSG_BARE_HMAC_KEY_FILE` environment variable, so the hashes
//! cannot be recomputed from the database alone. Schema and privacy rationale:
//! `core-v2/migrations/001_bare_issuance.sql`.
//!
//! [`load_hmac_key`] reads the secret; [`holder_hmac`] and [`domain_hmac`]
//! derive the stored hashes; [`next_free_number`] finds the smallest free
//! number within `releases.size`; [`insert_issuance`] writes one row (a
//! unique violation means this holder already took its free `bare`);
//! [`issued_count`] answers the public "issued N" page with a number only.

use std::collections::BTreeSet;
use std::env;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

/// The environment variable naming the file with the HMAC secret.
pub const HMAC_KEY_FILE_ENV: &str = "KSG_BARE_HMAC_KEY_FILE";

type HmacSha256 = Hmac<Sha256>;

/// What the `bare` ledger refuses or fails with.
///
/// Contact values (email / `did:web`) are never included: errors name the
/// kind of refusal, never who asked.
#[derive(Debug, thiserror::Error)]
pub enum BareDbError {
    /// The `KSG_BARE_HMAC_KEY_FILE` variable is missing or not Unicode.
    #[error("hmac key file env: not set or not readable")]
    Env,
    /// The secret file did not read, or it holds no key material.
    #[error("hmac key file: unreadable or empty")]
    KeyFile,
    /// The database refused the statement or the connection broke.
    #[error("database: {0}")]
    Db(String),
    /// No release with this id in `releases`.
    #[error("release: unknown")]
    UnknownRelease,
    /// The release's `size` is not a usable range (must be >= 1).
    #[error("release: bad size")]
    BadSize,
    /// Every number `1..=size` is already issued.
    #[error("release: full")]
    ReleaseFull,
    /// A unique row already covers this holder (or domain) in this release:
    /// the free `bare` was already taken.
    #[error("already issued")]
    AlreadyIssued,
}

/// Reads the HMAC secret from the file named by [`HMAC_KEY_FILE_ENV`].
///
/// The bytes are returned zeroizing: they are wiped on drop. Empty files and
/// missing variables are refused — an empty key would make every hash
/// computable by anyone.
///
/// # Errors
///
/// The variable is missing, the file does not read, or it is empty.
pub fn load_hmac_key() -> Result<Zeroizing<Vec<u8>>, BareDbError> {
    let path = env::var(HMAC_KEY_FILE_ENV).map_err(|_| BareDbError::Env)?;
    let bytes = std::fs::read(&path).map_err(|_| BareDbError::KeyFile)?;
    if bytes.is_empty() {
        return Err(BareDbError::KeyFile);
    }
    Ok(Zeroizing::new(bytes))
}

/// The stored holder hash: `HMAC(secret, contact)`.
///
/// `contact` is the raw `email` or `did:web` value the applicant stated.
/// The value itself is never stored — only this hash goes to `issuances`.
#[must_use]
pub fn holder_hmac(key: &[u8], contact: &str) -> [u8; 32] {
    hmac_of(key, contact.as_bytes())
}

/// The stored domain hash: `HMAC(secret, domain)`.
///
/// `domain` is the orchestrator's domain (the host part of its `did:web`);
/// `None` is stored for an owner issuance. One free `bare` per domain per
/// release rides on the partial unique index over this column.
#[must_use]
pub fn domain_hmac(key: &[u8], domain: &str) -> [u8; 32] {
    hmac_of(key, domain.as_bytes())
}

/// The host part of a `did:web:<host>[:path...]` value.
///
/// Returns the first segment after the prefix, or `None` when the value is
/// not a `did:web` contact. Used to derive the domain hash for orchestrator
/// issuance.
#[must_use]
pub fn did_web_domain(did_web: &str) -> Option<&str> {
    let rest = did_web.strip_prefix("did:web:")?;
    let host = rest.split(':').next()?;
    if host.is_empty() {
        return None;
    }
    Some(host)
}

/// The smallest free number of a release, `1..=releases.size`.
///
/// Reads the release size, then the taken numbers, and returns the first
/// gap. `None` means the release is fully issued.
///
/// # Errors
///
/// The release is unknown, its size is unusable, or the database failed.
pub fn next_free_number(
    client: &mut postgres::Client,
    release_id: &str,
) -> Result<Option<i32>, BareDbError> {
    let row = client
        .query_opt("SELECT size FROM releases WHERE id = $1", &[&release_id])
        .map_err(|e| BareDbError::Db(e.to_string()))?;
    let Some(row) = row else {
        return Err(BareDbError::UnknownRelease);
    };
    let size: i32 = row
        .try_get(0)
        .map_err(|e| BareDbError::Db(e.to_string()))?;
    if size < 1 {
        return Err(BareDbError::BadSize);
    }
    let rows = client
        .query(
            "SELECT number FROM issuances WHERE release_id = $1 ORDER BY number",
            &[&release_id],
        )
        .map_err(|e| BareDbError::Db(e.to_string()))?;
    let mut taken = BTreeSet::new();
    for r in &rows {
        let n: i32 = r
            .try_get(0)
            .map_err(|e| BareDbError::Db(e.to_string()))?;
        taken.insert(n);
    }
    let mut n: i32 = 1;
    while n <= size {
        if !taken.contains(&n) {
            return Ok(Some(n));
        }
        n = n.saturating_add(1);
    }
    Ok(None)
}

/// Writes one issuance row: number N went to the two hashes.
///
/// `domain` is `Some` for orchestrator issuance, `None` for an owner.
/// A unique violation on `(release_id, holder_hmac)` — or on the partial
/// `(release_id, domain_hmac)` index — becomes [`BareDbError::AlreadyIssued`]:
/// this holder (or domain) already took its free `bare` in this release.
///
/// # Errors
///
/// [`BareDbError::AlreadyIssued`] on a duplicate, [`BareDbError::Db`] on any
/// other database failure.
pub fn insert_issuance(
    client: &mut postgres::Client,
    release_id: &str,
    number: i32,
    holder: &[u8],
    domain: Option<&[u8]>,
) -> Result<i32, BareDbError> {
    match client.execute(
        "INSERT INTO issuances (release_id, number, holder_hmac, domain_hmac) VALUES ($1, $2, $3, $4)",
        &[&release_id, &number, &holder, &domain],
    ) {
        Ok(_) => Ok(number),
        Err(e) => {
            if e.code() == Some(&postgres::error::SqlState::UNIQUE_VIOLATION) {
                return Err(BareDbError::AlreadyIssued);
            }
            Err(BareDbError::Db(e.to_string()))
        }
    }
}

/// How many numbers a release issued: the public "issued N" page.
///
/// Only a count leaves the database — no row, no hash.
///
/// # Errors
///
/// The database failed.
pub fn issued_count(
    client: &mut postgres::Client,
    release_id: &str,
) -> Result<i64, BareDbError> {
    let row = client
        .query_one("SELECT issued_count($1)", &[&release_id])
        .map_err(|e| BareDbError::Db(e.to_string()))?;
    row.try_get(0)
        .map_err(|e| BareDbError::Db(e.to_string()))
}

fn hmac_of(key: &[u8], data: &[u8]) -> [u8; 32] {
    // An empty key would make every hash public; refuse it loudly at the
    // type level available here — HMAC takes any length, so guard ourselves.
    let effective: &[u8] = if key.is_empty() { b"\x00" } else { key };
    let mac = match HmacSha256::new_from_slice(effective) {
        Ok(m) => m,
        // HMAC takes a key of any size: a const fallback key never fails,
        // and if it ever did, zeros keep the shape without a panic path.
        Err(_) => match HmacSha256::new_from_slice(b"\x00") {
            Ok(m) => m,
            Err(_) => return [0u8; 32],
        },
    };
    let mut mac = mac;
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut h = [0u8; 32];
    for (i, b) in h.iter_mut().zip(out.iter()) {
        *i = *b;
    }
    h
}
