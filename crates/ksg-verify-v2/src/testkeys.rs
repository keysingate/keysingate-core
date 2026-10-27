//! Test keys: every secret the prototype makes is derived from a public label.
//!
//! The prototype (`ksg`) signs only with keys anybody can recompute from this
//! file: `seed(label) = SHA-256(fields "ksg:test-key:v1", label)`. A document
//! signed with them proves nothing — whoever reads this can sign the same — so
//! no container of the prototype can be passed off as a real one. Releases of
//! the prototype are named `ksg:em:test:…`, and the issuer's key is the test
//! key of the label [`ISSUER`]; either marks a release as a test one, and the
//! verifier refuses it unless asked to check a test.
//!
//! The core is not touched: these are ordinary Ed25519 keys and ordinary
//! documents. Only their secrets are public.

use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{Alg, Ed25519Signer, PublicKey};
use ksg_core_v2::doc::{Emission, Uri};

/// The prefix of every release the prototype issues.
pub const TEST_RELEASE_PREFIX: &str = "ksg:em:test:";

/// The label of the issuer's test key.
pub const ISSUER: &str = "issuer";

/// The label of the issuer's seal key.
pub const SEAL: &str = "seal";

/// The public 32-byte seed of `label`.
#[must_use]
pub fn seed(label: &str) -> [u8; 32] {
    *Hash::sha256_fields(&[b"ksg:test-key:v1", label.as_bytes()]).as_bytes()
}

/// The test signer of `label` under key identifier `kid`.
#[must_use]
pub fn signer(kid: Uri, label: &str) -> Ed25519Signer {
    Ed25519Signer::from_seed(kid, seed(label))
}

/// Whether `key` is the issuer's test key, whatever key identifier it carries.
#[must_use]
pub fn is_test_issuer_key(key: &PublicKey) -> bool {
    let kid = Uri::parse("did:key:zKsgTest#k1").expect("a constant URI");
    key.alg == Alg::Ed25519 && key.key == signer(kid, ISSUER).public().key
}

/// Whether `emission` is a test release: named as one, or signed by the
/// issuer's test key.
#[must_use]
pub fn is_test_release(emission: &Emission) -> bool {
    emission.id.starts_with(TEST_RELEASE_PREFIX) || emission.keys.iter().any(is_test_issuer_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeds_are_public_and_distinct() {
        assert_eq!(seed("issuer"), seed("issuer"));
        assert_ne!(seed("issuer"), seed("seal"));
        // Fixed forever: a verifier elsewhere recomputes the same key.
        assert_eq!(
            Hash::from_bytes(seed(ISSUER)).to_multihash(),
            Hash::sha256_fields(&[b"ksg:test-key:v1", b"issuer"]).to_multihash()
        );
    }

    #[test]
    fn the_issuer_key_is_recognised_under_any_kid() {
        let k = signer(Uri::parse("did:key:zAnyone#x").unwrap(), ISSUER).public();
        assert!(is_test_issuer_key(&k));
        let other = signer(Uri::parse("did:key:zAnyone#x").unwrap(), "owner:a").public();
        assert!(!is_test_issuer_key(&other));
    }
}
