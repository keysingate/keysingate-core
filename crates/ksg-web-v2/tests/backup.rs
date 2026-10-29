//! The holder's encrypted copy (track I18): what [`seal`][ksg_web_v2::backup::seal]
//! seals with the password [`open`][ksg_web_v2::open] gives back; a wrong
//! password, a cut blob, or another version's blob refuses with
//! [`Sealed`][ksg_web_v2::backup::BackupError::Sealed].

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use ksg_web_v2::backup::{open, seal, BackupError, NONCE_LEN, SALT_LEN, VERSION};

fn half() -> Vec<u8> {
    let kid = ksg_core_v2::doc::Uri::parse("urn:ksg:test:client").unwrap();
    let (_inside, half) =
        ksg_container_v2::client_key::split(kid, &mut rand_core::OsRng).unwrap();
    half.to_bytes().unwrap().to_vec()
}

#[test]
fn what_is_sealed_with_the_password_opens_with_it() {
    let bytes = half();
    let blob = seal(&bytes, b"the holder's words", &mut rand_core::OsRng).unwrap();
    assert_eq!(blob[0], VERSION, "the blob carries its version first");
    assert_eq!(open(&blob, b"the holder's words").unwrap(), bytes);
}

#[test]
fn two_seals_of_the_same_half_read_differently() {
    let bytes = half();
    let mut rng = rand_core::OsRng;
    let first = seal(&bytes, b"pw", &mut rng).unwrap();
    let second = seal(&bytes, b"pw", &mut rng).unwrap();
    assert_ne!(first, second, "a fresh salt and nonce each time");
    assert_eq!(open(&first, b"pw").unwrap(), bytes);
    assert_eq!(open(&second, b"pw").unwrap(), bytes);
}

#[test]
fn a_stranger_password_does_not_open() {
    let blob = seal(&half(), b"mine", &mut rand_core::OsRng).unwrap();
    assert_eq!(open(&blob, b"somebody else's"), Err(BackupError::Sealed));
    assert_eq!(open(&blob, b""), Err(BackupError::EmptyPassword));
}

#[test]
fn an_empty_password_seals_nothing() {
    assert_eq!(
        seal(&half(), b"", &mut rand_core::OsRng),
        Err(BackupError::EmptyPassword)
    );
}

#[test]
fn what_is_not_a_backup_does_not_open() {
    // Too short, and a blob of another version: both refuse the same way.
    assert_eq!(open(b"", b"pw"), Err(BackupError::Sealed));
    let short = [VERSION];
    assert_eq!(open(&short, b"pw"), Err(BackupError::Sealed));
    let mut other = vec![0u8; 1 + SALT_LEN + NONCE_LEN + 16];
    other[0] = VERSION.wrapping_add(1);
    assert_eq!(open(&other, b"pw"), Err(BackupError::Sealed));
    // Cut in the middle: the seal does not check out either.
    let mut cut = seal(&half(), b"pw", &mut rand_core::OsRng).unwrap();
    cut.truncate(cut.len() / 2);
    assert_eq!(open(&cut, b"pw"), Err(BackupError::Sealed));
}
