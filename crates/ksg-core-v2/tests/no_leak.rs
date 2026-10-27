//! A signing-key leak through formatting — 13.09 audit, finding 7.
//!
//! What `Debug` prints for someone else's `SigningKey` this library cannot promise
//! for upstream: in 1.x it printed the secret bytes. Our own `Debug` drops
//! the version dependence.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use ksg_core_v2::crypto::sign::Ed25519Signer;
use ksg_core_v2::doc::Uri;

#[test]
fn the_signer_prints_only_its_kid() {
    let seed = [0x7Au8; 32];
    let signer = Ed25519Signer::from_seed(Uri::parse("did:example:issuer#k1").expect("uri"), seed);
    let shown = format!("{signer:?}");

    assert_eq!(shown, "Ed25519Signer(kid=did:example:issuer#k1)");
    assert!(!shown.contains("122"), "a seed byte in the output: {shown}");
    assert!(!shown.contains("key"), "a key field in the output: {shown}");
}
