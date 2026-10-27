//! Attacks from the 13.09 hardening audit — finding 1.
//!
//! The test pins the rule: **a presented signature must verify**. While it
//! stands, the old reading ("an invalid signature just covers nothing of its
//! algorithm") cannot be quietly restored.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use ksg_core_v2::crypto::sign::{Alg, Ed25519Signer, KeySet, Profile, Signature, SignatureSet};
use ksg_core_v2::doc::Uri;
use ksg_core_v2::error::{Invalid, SigFail};

fn signer(seed: u8, kid: &str) -> Ed25519Signer {
    Ed25519Signer::from_seed(Uri::parse(kid).expect("uri"), [seed; 32])
}

#[test]
fn a_garbage_signature_under_someone_elses_kid_is_refused() {
    // The audit's scenario: the packet holder wants to bind the container to someone
    // else's agent key. Puts garbage under the agent's kid plus its own real signature.
    let agent = signer(1, "did:example:agent#k1");
    let holder = signer(2, "did:example:holder#k1");
    let msg = b"AgentBinding as the holder wants it to read";

    let keys: KeySet = [agent.public(), holder.public()].into_iter().collect();

    let forged = SignatureSet::new(vec![
        Signature {
            alg: Alg::Ed25519,
            kid: agent.public().kid.clone(),
            // The agent's signature, which the holder does not have: take the holder's
            // signature over another message — it will not verify.
            value: holder.sign(b"something else entirely").value,
        },
        holder.sign(msg),
    ]);

    // Before 13.09 this was Ok: Ed25519 was "covered" by the holder's signature, while
    // the garbage under the agent's kid fell into no coverage — and signed_by(agent)
    // still answered "yes".
    let err = forged
        .verify(msg, &keys, &Profile::default())
        .expect_err("a signature under someone else's kid must refuse the document");
    assert_eq!(
        err,
        Invalid::Signature {
            alg: Alg::Ed25519,
            reason: SigFail::Mismatch
        }
    );
}

#[test]
fn signed_by_alone_proves_nothing_until_verify_passed() {
    // The finding's second half: signed_by answers "is such a kid there",
    // not "did it sign". A garbage entry's presence satisfies it.
    let agent = signer(1, "did:example:agent#k1");
    let holder = signer(2, "did:example:holder#k1");

    let set = SignatureSet::new(vec![Signature {
        alg: Alg::Ed25519,
        kid: agent.public().kid.clone(),
        value: holder.sign(b"x").value,
    }]);

    assert!(
        set.signed_by(&agent.public().kid),
        "signed_by looks at the kid — presence, not proof"
    );

    // So the only defense is verify, and it now refuses.
    let keys: KeySet = [agent.public()].into_iter().collect();
    assert!(set.verify(b"y", &keys, &Profile::default()).is_err());
}

#[test]
fn honest_signatures_still_pass() {
    // The flip side: strictness must not break the honest case.
    let a = signer(3, "did:example:a#k1");
    let b = signer(4, "did:example:b#k1");
    let msg = b"a command both parties really signed";
    let keys: KeySet = [a.public(), b.public()].into_iter().collect();

    let set = SignatureSet::new(vec![a.sign(msg), b.sign(msg)]);
    set.verify(msg, &keys, &Profile::default())
        .expect("two honest signatures pass");
    assert!(set.signed_by(&a.public().kid) && set.signed_by(&b.public().kid));
}
