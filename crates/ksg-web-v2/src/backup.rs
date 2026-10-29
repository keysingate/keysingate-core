//! The holder's encrypted copy of the mobile half: Argon2id stretches the
//! holder's password into a key, XChaCha20 Poly1305 seals the half with it.
//!
//! The page stores one sealed blob ([`seal`]) instead of the bare half: the
//! blob lives anywhere (a file the holder downloads, the page's storage),
//! and only the password opens it ([`open`]). A wrong password refuses
//! ([`BackupError::Sealed`]) — the blob says nothing about what is inside.
//!
//! The format is versioned ([`VERSION`]): salt (16 bytes) plus nonce
//! (24 bytes) plus ciphertext. Argon2id runs with the crate's parameters
//! [`M_COST_KIB`], [`T_COST`], [`LANES`] — heavy enough to slow guessing,
//! light enough for a page to run.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    Key, XChaCha20Poly1305, XNonce,
};
use rand_core::{CryptoRng, RngCore};

/// The blob's version, its first byte: `open` refuses anything else.
pub const VERSION: u8 = 1;
/// Argon2id memory cost, KiB.
pub const M_COST_KIB: u32 = 19 * 1024;
/// Argon2id time cost, passes.
pub const T_COST: u32 = 2;
/// Argon2id parallelism, lanes.
pub const LANES: u32 = 1;
/// The salt's length, bytes.
pub const SALT_LEN: usize = 16;
/// The XChaCha20-Poly1305 nonce's length, bytes.
pub const NONCE_LEN: usize = 24;
/// What the holder's password becomes: a 256-bit sealing key.
pub const KEY_LEN: usize = 32;

/// Why the copy did not seal or open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackupError {
    /// The password is empty: there is nothing to stretch.
    EmptyPassword,
    /// The blob is not one: wrong version, too short, or the password is
    /// wrong. One answer for all — the blob does not say which.
    Sealed,
}

impl core::fmt::Display for BackupError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EmptyPassword => f.write_str("the password is empty"),
            Self::Sealed => f.write_str("the backup does not open"),
        }
    }
}

impl std::error::Error for BackupError {}

/// Argon2id with this module's parameters.
fn kdf() -> Result<Argon2<'static>, BackupError> {
    let params = Params::new(M_COST_KIB, T_COST, LANES, Some(KEY_LEN))
        .map_err(|_| BackupError::Sealed)?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Seals the half's bytes with the holder's password: `VERSION | salt |
/// nonce | ciphertext`. The salt and the nonce come from `rng` — a fresh
/// copy each time, so two seals of the same half read differently.
///
/// # Errors
///
/// [`BackupError::EmptyPassword`] when the password is empty.
pub fn seal<R: RngCore + CryptoRng>(
    half: &[u8],
    password: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>, BackupError> {
    if password.is_empty() {
        return Err(BackupError::EmptyPassword);
    }
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce);
    let mut key = [0u8; KEY_LEN];
    kdf()?
        .hash_password_into(password, &salt, &mut key)
        .map_err(|_| BackupError::Sealed)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let mut out = Vec::with_capacity(1 + SALT_LEN + NONCE_LEN + half.len() + 16);
    out.push(VERSION);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    let sealed = cipher
        .encrypt(XNonce::from_slice(&nonce), half)
        .map_err(|_| BackupError::Sealed)?;
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Opens a sealed copy with the holder's password: the half's bytes back.
///
/// # Errors
///
/// [`BackupError::EmptyPassword`] when the password is empty;
/// [`BackupError::Sealed`] for a blob that is not one or a wrong password.
pub fn open(blob: &[u8], password: &[u8]) -> Result<Vec<u8>, BackupError> {
    if password.is_empty() {
        return Err(BackupError::EmptyPassword);
    }
    if blob.first() != Some(&VERSION) {
        return Err(BackupError::Sealed);
    }
    let blob = blob.get(..).ok_or(BackupError::Sealed)?;
    let salt = blob.get(1..1 + SALT_LEN).ok_or(BackupError::Sealed)?;
    let nonce = blob.get(1 + SALT_LEN..1 + SALT_LEN + NONCE_LEN).ok_or(BackupError::Sealed)?;
    let sealed = blob.get(1 + SALT_LEN + NONCE_LEN..).ok_or(BackupError::Sealed)?;
    if sealed.is_empty() {
        return Err(BackupError::Sealed);
    }
    let mut key = [0u8; KEY_LEN];
    kdf()?
        .hash_password_into(password, salt, &mut key)
        .map_err(|_| BackupError::Sealed)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    cipher
        .decrypt(XNonce::from_slice(nonce), sealed)
        .map_err(|_| BackupError::Sealed)
}

#[cfg(test)]
mod tests {
    use super::{VERSION, NONCE_LEN, SALT_LEN, open, seal, BackupError};

    #[test]
    fn empty_password_seals_nothing() {
        assert_eq!(
            seal(b"half", b"", &mut rand_core::OsRng),
            Err(BackupError::EmptyPassword)
        );
        assert_eq!(
            open(b"blob", b""),
            Err(BackupError::EmptyPassword)
        );
    }

    #[test]
    fn what_is_not_a_backup_does_not_open() {
        assert_eq!(open(b"", b"pw"), Err(BackupError::Sealed));
        assert_eq!(open(&[2u8; 64], b"pw"), Err(BackupError::Sealed));
        assert_eq!(
            open(&[VERSION; 1 + SALT_LEN + NONCE_LEN], b"pw"),
            Err(BackupError::Sealed),
            "a header alone is not a blob: no ciphertext, no panic"
        );
    }
}
