//! Where every secret of the prototype comes from: a public label.
//!
//! `ksg` makes no secret of its own. Each key is the test key of a label
//! (`ksg_verify_v2::testkeys::seed`) that names who holds it and, for a
//! container, which one: the issuer, a distributor by its name, the owner of
//! a home directory by the directory's name, the client key and storage key
//! of a container by its home, release and serial. Anybody can recompute
//! them, so nothing the prototype signs can be passed off as real.
//!
//! Randomness that is not a key — signing nonces, padding — stays the
//! operating system's.

use std::path::Path;

use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

pub use ksg_verify_v2::testkeys::{is_test_release, seed, ISSUER, SEAL, TEST_RELEASE_PREFIX};

/// The label of a home directory: its last path component.
///
/// # Errors
///
/// A path with no last component (`/`, `..`).
pub fn home_label(home: &Path) -> Result<String, String> {
    home.file_name()
        .and_then(|n| n.to_str())
        .map(str::to_owned)
        .ok_or_else(|| format!("{}: a home directory needs a name", home.display()))
}

/// The test seed of `label`, as a secret-shaped buffer.
#[must_use]
pub fn secret(label: &str) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(seed(label))
}

/// Checks that `release` is named as a test release.
///
/// # Errors
///
/// It is not: the prototype issues only test releases.
pub fn check_release(release: &str) -> Result<(), String> {
    if release.starts_with(TEST_RELEASE_PREFIX) && release.len() > TEST_RELEASE_PREFIX.len() {
        Ok(())
    } else {
        Err(format!(
            "the prototype issues only test releases: {TEST_RELEASE_PREFIX}NNNNNN, not {release:?}"
        ))
    }
}

/// A byte stream derived from a test seed, for key generation that takes a
/// random number generator (the client key's split).
///
/// Block `i` is `SHA-256(fields "ksg:test-rng:v1", seed, i)`. It is marked
/// [`CryptoRng`] only because what it makes is meant to be public: it is a
/// generator of test keys, never of secrets.
pub struct TestRng {
    seed: Zeroizing<[u8; 32]>,
    counter: u64,
    buf: Zeroizing<[u8; 32]>,
    pos: usize,
}

impl TestRng {
    /// The stream of `label`.
    #[must_use]
    pub fn of(label: &str) -> Self {
        Self {
            seed: secret(label),
            counter: 0,
            buf: Zeroizing::new([0; 32]),
            pos: 32,
        }
    }

    fn refill(&mut self) {
        let block = ksg_core_v2::crypto::hash::Hash::sha256_fields(&[
            b"ksg:test-rng:v1",
            &*self.seed,
            &self.counter.to_be_bytes(),
        ]);
        self.buf.copy_from_slice(block.as_bytes());
        self.counter += 1;
        self.pos = 0;
    }
}

impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for b in dest {
            if self.pos == self.buf.len() {
                self.refill();
            }
            *b = self.buf[self.pos];
            self.pos += 1;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for TestRng {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stream_is_fixed_by_its_label() {
        let (mut a, mut b, mut c) = (TestRng::of("x"), TestRng::of("x"), TestRng::of("y"));
        let (mut x, mut y, mut z) = ([0u8; 100], [0u8; 100], [0u8; 100]);
        a.fill_bytes(&mut x);
        b.fill_bytes(&mut y[..33]);
        b.fill_bytes(&mut y[33..]);
        c.fill_bytes(&mut z);
        assert_eq!(x, y);
        assert_ne!(x, z);
    }

    #[test]
    fn only_test_releases_are_issued() {
        assert!(check_release("ksg:em:test:000001").is_ok());
        assert!(check_release("ksg:em:000001").is_err());
        assert!(check_release("ksg:em:test:").is_err());
    }
}
