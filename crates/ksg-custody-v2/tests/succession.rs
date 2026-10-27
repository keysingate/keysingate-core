//! A successor signed in advance, and the anchored commitment of a share set.
//!
//! The property held down here is the one that makes the successor safe rather
//! than merely convenient: **a certificate on its own changes nothing**. If
//! holding it made the successor current, the successor key would be as
//! powerful as the key it replaces from the day it was written — no gain, twice
//! the exposure.

use ksg_core_v2::canonical::doc_hash;
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{sign_doc, Ed25519Signer, KeySet, Profile, SignatureSet};
use ksg_core_v2::doc::{Timestamp, Uri};
use ksg_custody_v2::succession::Standing;
use ksg_custody_v2::{
    entropy_needed, gf, split_3_of_5, CustodyAnchor, CustodyError, CustodySet, Share, Succession,
    SuccessionClaim, SuccessionVeto, THRESHOLD,
};

fn uri(s: &str) -> Uri {
    Uri::parse(s).expect("uri")
}
fn ts(s: &str) -> Timestamp {
    Timestamp::parse(s).expect("timestamp")
}
fn current() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:web:issuer.example#root1"), [90u8; 32])
}
fn successor() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:web:issuer.example#root2"), [95u8; 32])
}
fn thief() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:web:nobody.example#x"), [96u8; 32])
}
fn current_keys() -> KeySet {
    [current().public()].into_iter().collect()
}

/// A day.
const DAY_MS: u64 = 86_400_000;

/// Ninety days, as a stand-in. The real figure is the owner's.
const NOTICE_MS: u64 = 90 * 86_400_000;

fn certificate() -> Succession {
    let doc = Succession {
        context: ksg_core_v2::doc::Context,
        doc_type: "Succession".into(),
        v: 3,
        issuer: uri("did:web:issuer.example"),
        current: current().public(),
        successor: successor().public(),
        notice_ms: NOTICE_MS,
        declared_at: ts("2026-08-27T00:00:00.000Z"),
        signatures: SignatureSet::default(),
    };
    let sig = sign_doc(&doc, &current()).expect("signature");
    Succession {
        signatures: SignatureSet::new(vec![sig]),
        ..doc
    }
}

fn claim_by(signer: &Ed25519Signer, cert: &Succession) -> SuccessionClaim {
    let doc = SuccessionClaim {
        context: ksg_core_v2::doc::Context,
        doc_type: "SuccessionClaim".into(),
        v: 3,
        succession: doc_hash(cert).expect("hash"),
        claimed_at: ts("2026-09-01T00:00:00.000Z"),
        signatures: SignatureSet::default(),
    };
    let sig = sign_doc(&doc, signer).expect("signature");
    SuccessionClaim {
        signatures: SignatureSet::new(vec![sig]),
        ..doc
    }
}

fn veto(cert: &Succession) -> SuccessionVeto {
    let doc = SuccessionVeto {
        context: ksg_core_v2::doc::Context,
        doc_type: "SuccessionVeto".into(),
        v: 3,
        succession: doc_hash(cert).expect("hash"),
        vetoed_at: ts("2026-09-02T00:00:00.000Z"),
        signatures: SignatureSet::default(),
    };
    let sig = sign_doc(&doc, &current()).expect("signature");
    SuccessionVeto {
        signatures: SignatureSet::new(vec![sig]),
        ..doc
    }
}

fn p() -> Profile {
    Profile::default()
}

// --- the certificate alone does nothing --------------------------------------

#[test]
fn a_certificate_on_its_own_changes_nothing() {
    // The whole design. Writing down a successor must not make it current, or
    // the drawer would hold a key as powerful as the one in use.
    let c = certificate();
    c.validate(&current_keys(), &p())
        .expect("the certificate verifies");

    assert_eq!(c.standing(None, None, 0, &p()).unwrap(), Standing::Prepared);
    assert_eq!(
        c.key_now(None, None, u64::MAX, &p()).unwrap().kid,
        current().public().kid,
        "with no claim filed, waiting forever changes nothing"
    );
}

#[test]
fn a_claim_takes_effect_only_after_the_notice_runs_out() {
    let c = certificate();
    let cl = claim_by(&successor(), &c);

    assert_eq!(
        c.standing(Some(&cl), None, 0, &p()).unwrap(),
        Standing::Pending {
            remaining_ms: NOTICE_MS
        }
    );
    assert_eq!(
        c.standing(Some(&cl), None, NOTICE_MS - 1, &p()).unwrap(),
        Standing::Pending { remaining_ms: 1 },
        "the last millisecond still belongs to the current key"
    );
    assert_eq!(
        c.key_now(Some(&cl), None, NOTICE_MS - 1, &p()).unwrap().kid,
        current().public().kid
    );

    assert_eq!(
        c.standing(Some(&cl), None, NOTICE_MS, &p()).unwrap(),
        Standing::Effective
    );
    assert_eq!(
        c.key_now(Some(&cl), None, NOTICE_MS, &p()).unwrap().kid,
        successor().public().kid,
        "and then the successor signs"
    );
}

// --- the veto is what makes it safe ------------------------------------------

#[test]
fn a_stolen_successor_key_is_caught_by_the_veto() {
    // The scenario the veto exists for. A claim filed with a stolen successor
    // key is answered by the current key — which, in that scenario, is by
    // definition NOT lost. The theft fails instead of succeeding.
    let c = certificate();
    let cl = claim_by(&successor(), &c);
    let v = veto(&c);

    assert_eq!(
        c.standing(Some(&cl), Some((&v, DAY_MS)), NOTICE_MS * 10, &p())
            .unwrap(),
        Standing::Vetoed,
        "a veto cast within the notice holds however late it is read"
    );
    assert_eq!(
        c.key_now(Some(&cl), Some((&v, DAY_MS)), NOTICE_MS * 10, &p())
            .unwrap()
            .kid,
        current().public().kid
    );
}

#[test]
fn a_veto_after_the_notice_ran_out_is_late() {
    // "At any moment of the term" — of the term. Once the notice has run out
    // unvetoed the successor is the key; an old key surfacing afterwards is
    // what the notice waited out, not a reason to hand the key back.
    let c = certificate();
    let cl = claim_by(&successor(), &c);
    let v = veto(&c);
    assert_eq!(
        c.standing(Some(&cl), Some((&v, NOTICE_MS)), NOTICE_MS * 2, &p())
            .unwrap(),
        Standing::Effective
    );
    assert_eq!(
        c.standing(Some(&cl), Some((&v, NOTICE_MS - 1)), NOTICE_MS * 2, &p())
            .unwrap(),
        Standing::Vetoed,
        "one millisecond inside the notice is inside"
    );
}

#[test]
fn a_veto_kills_the_certificate_and_not_merely_the_claim() {
    // Because a veto means the successor's key was used without authority. That
    // key is compromised, and naming it again would be naming a key an attacker
    // holds. Recovery is a NEW certificate — which the current key can write,
    // since the veto just proved it can still sign.
    let c = certificate();
    let v = veto(&c);
    assert_eq!(
        c.standing(None, Some((&v, 0)), 0, &p()).unwrap(),
        Standing::Vetoed
    );
}

#[test]
fn only_the_successor_may_claim_and_only_the_current_key_may_veto() {
    let c = certificate();

    let stolen = claim_by(&thief(), &c);
    assert_eq!(
        c.standing(Some(&stolen), None, NOTICE_MS, &p())
            .unwrap_err(),
        CustodyError::Succession("the claim is not the successor's")
    );

    // The current key must not be able to claim under its own certificate
    // either: that is not a succession, it is the key still working.
    let self_claim = claim_by(&current(), &c);
    assert!(c
        .standing(Some(&self_claim), None, NOTICE_MS, &p())
        .is_err());

    let mut forged = veto(&c);
    let doc = SuccessionVeto {
        signatures: SignatureSet::default(),
        ..forged.clone()
    };
    forged.signatures = SignatureSet::new(vec![sign_doc(&doc, &thief()).expect("sig")]);
    assert!(c.standing(None, Some((&forged, 0)), 0, &p()).is_err());
}

#[test]
fn documents_about_another_certificate_are_refused() {
    // A claim naming a different certificate is not evidence about this one.
    let c = certificate();
    let mut other = claim_by(&successor(), &c);
    other.succession = Hash::sha256(b"some other certificate");
    assert_eq!(
        c.standing(Some(&other), None, NOTICE_MS, &p()).unwrap_err(),
        CustodyError::Succession("the claim is of another certificate")
    );
}

#[test]
fn a_claim_cannot_predate_the_certificate_it_claims_under() {
    let c = certificate();
    let mut early = claim_by(&successor(), &c);
    early.claimed_at = ts("2026-01-01T00:00:00.000Z");
    // Re-sign, or it fails for the wrong reason.
    let doc = SuccessionClaim {
        signatures: SignatureSet::default(),
        ..early.clone()
    };
    early.signatures = SignatureSet::new(vec![sign_doc(&doc, &successor()).expect("sig")]);
    assert_eq!(
        c.standing(Some(&early), None, NOTICE_MS, &p()).unwrap_err(),
        CustodyError::Succession("the claim precedes the certificate it claims under")
    );
}

// --- the certificate itself --------------------------------------------------

#[test]
fn a_certificate_must_be_signed_by_the_key_it_succeeds() {
    // It names its own signer. One signed by anybody else is a stranger's
    // opinion about whose key this is.
    let doc = Succession {
        signatures: SignatureSet::default(),
        ..certificate()
    };
    let forged = Succession {
        signatures: SignatureSet::new(vec![sign_doc(&doc, &thief()).expect("sig")]),
        ..doc
    };
    let keys: KeySet = [thief().public()].into_iter().collect();
    assert_eq!(
        forged.validate(&keys, &p()).unwrap_err(),
        CustodyError::Succession("the certificate is not signed by the key it succeeds")
    );
}

#[test]
fn a_notice_below_the_floor_and_a_self_succession_are_refused() {
    // `[decision]` 12.09 put a floor of 30 days under the notice. Anything shorter
    // looks prudent and is not: the veto is cast by a person who has to notice
    // first, and a window inside one plausible absence is a window a thief waits
    // out. Succeeding a key to itself is a no-op dressed as a plan.
    let base = certificate();

    let mut instant = Succession {
        notice_ms: 14 * 24 * 60 * 60 * 1000,
        signatures: SignatureSet::default(),
        ..base.clone()
    };
    instant.signatures = SignatureSet::new(vec![sign_doc(&instant, &current()).expect("sig")]);
    assert_eq!(
        instant.validate(&current_keys(), &p()).unwrap_err(),
        CustodyError::Succession("the notice period is shorter than the floor of 30 days")
    );

    let mut itself = Succession {
        successor: current().public(),
        signatures: SignatureSet::default(),
        ..base
    };
    itself.signatures = SignatureSet::new(vec![sign_doc(&itself, &current()).expect("sig")]);
    assert_eq!(
        itself.validate(&current_keys(), &p()).unwrap_err(),
        CustodyError::Succession("the successor is the current key")
    );
}

// --- the set, and what goes on the chain -------------------------------------

fn entropy(len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut x: u8 = 0xA5;
    for _ in 0..len {
        x = gf::mul(x, 0x1d) ^ 0x63;
        out.push(x);
    }
    out
}

fn shares() -> Vec<Share> {
    let s: Vec<u8> = (0u8..32).collect();
    split_3_of_5(&s, &entropy(entropy_needed(s.len(), THRESHOLD, 5))).expect("split")
}

#[test]
fn one_root_covers_all_five_commitments() {
    // Five commitments would be five things to publish, five to keep in step and
    // five chances to publish four. One root is one transaction.
    let set = CustodySet::of(&shares(), THRESHOLD).expect("set");
    assert_eq!(set.commitments().len(), 5);
    for s in shares() {
        set.contains(&s).expect("each share belongs to the set");
    }
}

#[test]
fn the_root_binds_the_scheme_and_not_only_the_shares() {
    // "Three of five" and "two of five" over the same shares must not share a
    // root, or a set could be re-presented as an easier scheme.
    let sh = shares();
    let three = CustodySet::of(&sh, 3).expect("set");
    let two = CustodySet::of(&sh, 2).expect("set");
    assert_ne!(three.root(), two.root());
}

#[test]
fn a_substituted_share_is_named_before_it_can_corrupt_anything() {
    // Shamir has no integrity of its own, so checking against the set first
    // turns a silent wrong answer into a named failure.
    let set = CustodySet::of(&shares(), THRESHOLD).expect("set");
    let mut bad = shares();
    bad[1].body[0] ^= 1;
    assert_eq!(
        set.check_all(&bad[..3]).unwrap_err(),
        CustodyError::Substituted(bad[1].index)
    );
    set.check_all(&shares()[..3]).expect("good shares pass");
}

#[test]
fn a_share_cannot_pass_at_someone_elses_position() {
    let set = CustodySet::of(&shares(), THRESHOLD).expect("set");
    let mut moved = shares()[0].clone();
    moved.index = 2;
    assert!(set.contains(&moved).is_err());
}

#[test]
fn an_anchor_of_another_set_proves_nothing_about_this_one() {
    // The case worth naming, because "there is an anchor" reads like an answer.
    let set = CustodySet::of(&shares(), THRESHOLD).expect("set");
    let good = CustodyAnchor {
        kind: uri("urn:ksg:anchor:test"),
        subject: set.root(),
        proof: b"opaque".to_vec(),
        anchored_at: ts("2026-08-27T00:00:00.000Z"),
    };
    good.covers(&set.root()).expect("it is this set's anchor");

    let elsewhere = CustodyAnchor {
        subject: Hash::sha256(b"another set"),
        ..good
    };
    assert!(elsewhere.covers(&set.root()).is_err());
}

#[test]
fn below_the_threshold_the_set_refuses_before_reconstruction() {
    let set = CustodySet::of(&shares(), THRESHOLD).expect("set");
    assert_eq!(
        set.check_all(&shares()[..2]).unwrap_err(),
        CustodyError::NotEnough {
            presented: 2,
            threshold: 3
        }
    );
}

#[test]
fn a_notice_past_the_ceiling_is_refused_too() {
    // Past a year a successor is not prepared, it is promised: the loss it is
    // for would be lived through rather than repaired.
    let mut far = Succession {
        notice_ms: ksg_custody_v2::NOTICE_MAX_MS + 1,
        signatures: SignatureSet::default(),
        ..certificate()
    };
    far.signatures = SignatureSet::new(vec![sign_doc(&far, &current()).expect("sig")]);
    assert_eq!(
        far.validate(&current_keys(), &p()).unwrap_err(),
        CustodyError::Succession("the notice period is longer than the ceiling of 365 days")
    );
}

#[test]
fn the_recommended_notice_is_inside_its_own_bounds() {
    // A recommendation the validator would refuse is worse than none. Checked at
    // compile time, since all three are constants and a runtime assertion over
    // constants only pretends to be a test.
    const _: () = assert!(ksg_custody_v2::NOTICE_RECOMMENDED_MS >= ksg_custody_v2::NOTICE_MIN_MS);
    const _: () = assert!(ksg_custody_v2::NOTICE_RECOMMENDED_MS <= ksg_custody_v2::NOTICE_MAX_MS);
    let mut ok = Succession {
        notice_ms: ksg_custody_v2::NOTICE_RECOMMENDED_MS,
        signatures: SignatureSet::default(),
        ..certificate()
    };
    ok.signatures = SignatureSet::new(vec![sign_doc(&ok, &current()).expect("sig")]);
    ok.validate(&current_keys(), &p())
        .expect("the recommended term stands");
}
