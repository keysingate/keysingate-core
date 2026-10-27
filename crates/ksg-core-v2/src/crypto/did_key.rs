//! `did:key` — an identifier computed from a public key. **Г-1.**
//!
//! # Why a computed identifier
//!
//! A `kid` is a name, not a key (audit of 23.09, K1): anyone can generate a
//! key and call it `did:key:zKsgClient`. An identifier that is *computed* from
//! the key it names cannot be borrowed — there is no registry and no trusted
//! party in the middle, because the key itself is the identifier.
//!
//! The client agent's identifier is the `did:key` of the group key its working
//! key is born under (`ksg-container-v2::client_key`, FROST over Ed25519, two
//! of two): the key exists from the container's initiation, both halves sign
//! under it, and a verifier holding the agent's public key computes the same
//! string as the one the pages are named with.
//!
//! # The form
//!
//! `did:key:z<base58btc(multicodec || key)>` — the multicodec of the key's
//! kind, then the key material, then base58btc with its `z` prefix. Ed25519 is
//! `0xed 0x01` (unsigned varint of `0xed`); the key is its 32 bytes.
//!
//! A fragment is not part of the identifier: `<did:key>#<fragment>` names one
//! key of a party, and the party is the `did:key` alone. [`kid`] builds the
//! fragment form the core's documents carry.

use crate::crypto::sign::{b64_decode, Alg, PublicKey};
use crate::doc::Uri;
use crate::error::Invalid;

/// The multicodec of an Ed25519 public key, as an unsigned varint.
pub const ED25519_MULTICODEC: [u8; 2] = [0xed, 0x01];

/// The fragment of a key named by its own `did:key`: `<did:key>#k1`.
pub const FRAGMENT: &str = "k1";

/// The length of an Ed25519 public key.
const ED25519_LEN: usize = 32;

/// The `did:key` of an Ed25519 public key given in base64url without padding —
/// the form a [`PublicKey`] keeps its material in.
///
/// # Errors
///
/// [`Invalid::Schema`] when the material is not base64url or is not 32 bytes:
/// an identifier computed from a key that is not that key would name nothing.
pub fn of_ed25519_b64(key: &str) -> Result<String, Invalid> {
    let bytes = b64_decode(key).map_err(|()| Invalid::Schema("did:key: the key is not base64url"))?;
    if bytes.len() != ED25519_LEN {
        return Err(Invalid::Schema("did:key: an Ed25519 key is 32 bytes"));
    }
    let mut both = Vec::with_capacity(ED25519_MULTICODEC.len() + ED25519_LEN);
    both.extend_from_slice(&ED25519_MULTICODEC);
    both.extend_from_slice(&bytes);
    Ok(format!("did:key:z{}", bs58::encode(both).into_string()))
}

/// The `did:key` of a public key — what the key is called by its own material.
///
/// # Errors
///
/// [`Invalid::Schema`] for an algorithm with no multicodec here: the post-quantum
/// key of a container is not a party's identifier, and an identifier computed
/// under a rule nobody else implements names nobody.
pub fn of_public(key: &PublicKey) -> Result<String, Invalid> {
    match key.alg {
        Alg::Ed25519 => of_ed25519_b64(&key.key),
        Alg::MlDsa65 => Err(Invalid::Schema(
            "did:key: ML-DSA-65 has no identifier in the core",
        )),
    }
}

/// The identifier of a key named by its own `did:key`: `<did:key>#k1`.
///
/// # Errors
///
/// See [`of_public`].
pub fn kid(key: &PublicKey) -> Result<Uri, Invalid> {
    let did = of_public(key)?;
    Uri::parse(format!("{did}#{FRAGMENT}"))
}

/// Whether `party` is the `did:key` of `key` — the one check that makes a name
/// a claim: the identifier of the client agent is the key it signs under.
///
/// A key of an algorithm with no `did:key` here (ML-DSA-65) is not what names
/// a party: it signs beside the Ed25519 key, it does not become the party.
#[must_use]
pub fn names(party: &Uri, key: &PublicKey) -> bool {
    of_public(key).is_ok_and(|did| did == party.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sign::b64_encode;

    fn key(name: &str, alg: Alg, bytes: &[u8]) -> PublicKey {
        PublicKey {
            kid: Uri::parse(format!("{name}#k1")).unwrap(),
            alg,
            key: b64_encode(bytes),
        }
    }

    /// The identifier is the key, byte for byte: base58btc over the multicodec
    /// and the 32 bytes of the key, with `z` for the base — the shape every
    /// `did:key` of an Ed25519 key has.
    #[test]
    fn the_identifier_is_the_multicodec_and_the_key_in_base58btc() {
        let bytes: Vec<u8> = (0u8..32).collect();
        let k = key("did:key:zAny", Alg::Ed25519, &bytes);
        let did = of_public(&k).unwrap();
        let body = did.strip_prefix("did:key:z").expect("the did:key form");
        // Every Ed25519 did:key begins with these three symbols: the varint
        // 0xed 0x01 pushes them out, in base58 as in the specification.
        assert!(body.starts_with("6Mk"), "{did}");
        let back = bs58::decode(body).into_vec().unwrap();
        assert_eq!(back.len(), 2 + bytes.len());
        assert_eq!(back.get(..2), Some(&ED25519_MULTICODEC[..]));
        assert_eq!(back.get(2..), Some(&bytes[..]));
    }

    /// Two keys, two identifiers; one key, one identifier — whatever it is
    /// called.
    #[test]
    fn the_name_follows_the_key_and_not_the_other_way_round() {
        let (a, b) = ([1u8; 32], [2u8; 32]);
        let (ka, kb) = (
            key("did:key:zSame", Alg::Ed25519, &a),
            key("did:key:zSame", Alg::Ed25519, &b),
        );
        assert_ne!(of_public(&ka).unwrap(), of_public(&kb).unwrap());
        // The kid the documents carry is the identifier with the core's
        // fragment, and the party is the identifier alone.
        let kid = kid(&ka).unwrap();
        assert_eq!(kid.as_str(), format!("{}#k1", of_public(&ka).unwrap()));
        assert!(names(&Uri::parse(of_public(&ka).unwrap()).unwrap(), &ka));
        assert!(!names(&Uri::parse(of_public(&kb).unwrap()).unwrap(), &ka));
        assert!(!names(&Uri::parse("did:key:zKsgClient").unwrap(), &ka));
    }

    /// A key of an algorithm the core does not name by its material is not an
    /// identifier: a name nobody else can compute names nobody.
    #[test]
    fn material_that_is_not_an_ed25519_key_is_refused() {
        assert!(of_public(&key("did:key:zPq", Alg::MlDsa65, &[3u8; 1952])).is_err());
        assert!(of_public(&key("did:key:zShort", Alg::Ed25519, &[0u8; 31])).is_err());
        let not_b64 = PublicKey {
            kid: Uri::parse("did:key:zX#k1").unwrap(),
            alg: Alg::Ed25519,
            key: "!!!".into(),
        };
        assert!(of_public(&not_b64).is_err());
    }
}
