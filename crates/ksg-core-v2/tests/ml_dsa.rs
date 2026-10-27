//! ML-DSA-65 (FIPS 204) — the second signature algorithm. K-4 roster blocker.
//!
//! Until 17.09 the algorithm was declared in the enum and not implemented: the
//! verifier answered "nothing to check with". A profile with two required
//! algorithms could not be satisfied at all.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer as PqSigner};
use ksg_core_v2::crypto::sign::{
    b64_encode, Alg, KeySet, Profile, PublicKey, Signature, SignatureSet,
};
use ksg_core_v2::doc::Uri;
use ksg_core_v2::error::{Invalid, SigFail};

fn uri(s: &str) -> Uri {
    Uri::parse(s).expect("uri")
}

/// An ML-DSA-65 key pair and a signature over the message.
fn signed(msg: &[u8]) -> (PublicKey, Signature) {
    let (pk, sk) = ml_dsa_65::try_keygen().expect("keygen");
    let sig = sk.try_sign(msg, &[]).expect("sign");
    let key = PublicKey {
        kid: uri("did:key:zPq#k1"),
        alg: Alg::MlDsa65,
        key: b64_encode(&pk.into_bytes()),
    };
    let signature = Signature {
        kid: key.kid.clone(),
        alg: Alg::MlDsa65,
        value: b64_encode(&sig),
    };
    (key, signature)
}

#[test]
fn a_real_ml_dsa_signature_verifies() {
    let msg = b"the document, canonicalized";
    let (key, signature) = signed(msg);
    let keys: KeySet = [key].into_iter().collect();

    let profile = Profile {
        required_algs: [Alg::MlDsa65].into_iter().collect(),
        ..Profile::default()
    };
    SignatureSet::new(vec![signature])
        .verify(msg, &keys, &profile)
        .expect("an ML-DSA-65 signature must verify");
}

#[test]
fn a_signature_over_other_bytes_is_refused() {
    let (key, signature) = signed(b"one message");
    let keys: KeySet = [key].into_iter().collect();
    let profile = Profile {
        required_algs: [Alg::MlDsa65].into_iter().collect(),
        ..Profile::default()
    };
    let err = SignatureSet::new(vec![signature])
        .verify(b"another message", &keys, &profile)
        .expect_err("a signature over other bytes fails");
    assert_eq!(
        err,
        Invalid::Signature {
            alg: Alg::MlDsa65,
            reason: SigFail::Mismatch
        }
    );
}

#[test]
fn a_truncated_signature_is_an_encoding_refusal_not_a_mismatch() {
    // The difference matters: a "wrong-length signature" is document corruption,
    // not an honest mismatch. It tells the verifier different things.
    let (key, mut signature) = signed(b"msg");
    signature.value = b64_encode(&[0u8; 100]);
    let keys: KeySet = [key].into_iter().collect();
    let profile = Profile {
        required_algs: [Alg::MlDsa65].into_iter().collect(),
        ..Profile::default()
    };
    let err = SignatureSet::new(vec![signature])
        .verify(b"msg", &keys, &profile)
        .expect_err("a truncated signature is refused");
    assert_eq!(
        err,
        Invalid::Signature {
            alg: Alg::MlDsa65,
            reason: SigFail::BadEncoding
        }
    );
}

#[test]
fn the_sizes_are_the_ones_fips_204_names() {
    // If the crate or the set's parameter is swapped, the test says so before
    // some foreign implementation notices.
    assert_eq!(ml_dsa_65::PK_LEN, 1952);
    assert_eq!(ml_dsa_65::SIG_LEN, 3309);
}
