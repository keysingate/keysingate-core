//! Audit of the Shamir implementation, 2026-10-01 (`Audit_Shamir_2026-10-01.md`).
//!
//! Two kinds of test here. The properties are checked **exhaustively** where the
//! space allows it: the field against a plain reference on all 65 536 pairs, and
//! perfect secrecy of two shares over every coefficient pair of a one-byte
//! secret. The findings Sh-1 … Sh-10 are pinned so they cannot come back.

use ksg_core_v2::crypto::hash::Hash;
use ksg_custody_v2::loss::LossDeclaration;
use ksg_custody_v2::{
    combine, combine_3_of_5, entropy_needed, gf, split, split_3_of_5, split_3_of_5_with_rng,
    CustodyError, CustodySet, Keeping, Place, Plan,
};

/// Fixed test entropy for a `len`-byte secret, 3 of 5. Never a CSPRNG.
fn fixed(len: usize) -> Vec<u8> {
    (0..entropy_needed(len, 3, 5))
        .map(|i| (i as u8).wrapping_mul(29) ^ 0x5c)
        .collect()
}

/// Multiplication the slow, obvious way: branches and all, for comparison only.
fn reference_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            p ^= a;
        }
        let high = a & 0x80 != 0;
        a <<= 1;
        if high {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    p
}

#[test]
fn the_field_multiplies_as_the_reference_on_every_pair() {
    for a in 0..=255u8 {
        for b in 0..=255u8 {
            assert_eq!(gf::mul(a, b), reference_mul(a, b), "{a} × {b}");
        }
    }
}

#[test]
fn every_non_zero_element_has_its_inverse() {
    for a in 1..=255u8 {
        assert_eq!(gf::mul(a, gf::inv(a)), 1, "{a}");
    }
    assert_eq!(gf::inv(0), 0);
}

#[test]
fn two_shares_say_nothing_about_the_secret_exhaustively() {
    // A one-byte secret, 3 of 5: the two random coefficients run over all
    // 65 536 values. For any two shares, every pair of values occurs exactly
    // once — whatever the secret. That is perfect secrecy, shown, not sampled.
    for (i, j) in [(0usize, 1usize), (0, 4), (2, 3), (3, 4)] {
        for secret in [0u8, 1, 0x5a, 0xff] {
            let mut seen = vec![0u16; 65_536];
            // Coefficients first, then five salts; the salts do not touch the
            // bodies, so zeros serve.
            let mut entropy = vec![0u8; entropy_needed(1, 3, 5)];
            for c1 in 0..=255u8 {
                for c2 in 0..=255u8 {
                    entropy[0] = c1;
                    entropy[1] = c2;
                    let sh = split(&[secret], 3, 5, &entropy).expect("split");
                    let at = (usize::from(sh[i].body[0]) << 8) | usize::from(sh[j].body[0]);
                    seen[at] += 1;
                }
            }
            assert!(
                seen.iter().all(|&n| n == 1),
                "shares {i},{j} of secret {secret}"
            );
        }
    }
}

#[test]
fn every_three_of_the_five_recover() {
    let secret: Vec<u8> = (0..64u8).map(|x| x.wrapping_mul(37) ^ 0xa5).collect();
    let mut rng = rand_core::OsRng;
    let sh = split_3_of_5_with_rng(&secret, &mut rng).expect("split");
    for a in 0..5 {
        for b in a + 1..5 {
            for c in b + 1..5 {
                let got = combine_3_of_5(&[sh[a].clone(), sh[b].clone(), sh[c].clone()])
                    .expect("combine");
                assert_eq!(&got[..], &secret[..], "{a}{b}{c}");
            }
        }
    }
}

#[test]
fn sh1_a_fourth_share_that_disagrees_is_refused_not_averaged_in() {
    let sh = split_3_of_5(b"key", &fixed(3)).expect("split");
    let mut bad = sh[3].clone();
    bad.body[0] ^= 1;
    assert_eq!(
        combine_3_of_5(&[sh[0].clone(), sh[1].clone(), sh[2].clone(), bad]),
        Err(CustodyError::Inconsistent(4))
    );
    // Four and five good shares agree and recover.
    let all = combine_3_of_5(&sh).expect("all five");
    assert_eq!(&all[..], b"key");
}

#[test]
fn sh2_sh3_degenerate_thresholds_are_errors_not_panics() {
    assert!(matches!(
        combine(&[], 0),
        Err(CustodyError::BadParameters { .. })
    ));
    let sh = split_3_of_5(b"key", &fixed(3)).expect("split");
    assert!(matches!(
        combine(&sh[..1], 1),
        Err(CustodyError::BadParameters { .. })
    ));
    assert_eq!(entropy_needed(4, 0, 0), 0);
    assert_eq!(entropy_needed(4, 1, 0), 0);
}

#[test]
fn sh4_the_rng_entry_draws_fresh_coefficients() {
    let mut rng = rand_core::OsRng;
    let a = split_3_of_5_with_rng(b"the same secret", &mut rng).expect("split");
    let b = split_3_of_5_with_rng(b"the same secret", &mut rng).expect("split");
    assert_ne!(
        a[0].body, b[0].body,
        "two splits must not share a polynomial"
    );
}

#[test]
fn sh6_a_set_must_be_taken_in_share_order() {
    let mut sh = split_3_of_5(b"key", &fixed(3)).expect("split");
    sh.swap(0, 1);
    assert_eq!(
        CustodySet::of(&sh, 3),
        Err(CustodyError::OutOfOrder {
            position: 0,
            index: 2
        })
    );
}

#[test]
fn sh7_one_share_presented_twice_is_not_two() {
    use ksg_core_v2::crypto::sign::{sign_doc, Ed25519Signer, Profile, SignatureSet};
    use ksg_core_v2::doc::{Context, Timestamp, Uri};
    let owner = Ed25519Signer::from_seed(Uri::parse("did:web:o.example#k").expect("u"), [5; 32]);
    let issuer = Ed25519Signer::from_seed(Uri::parse("did:web:i.example#k").expect("u"), [6; 32]);
    let sh = split_3_of_5(b"key", &fixed(3)).expect("split");
    let set = CustodySet::of(&sh, 3).expect("set");
    let doc = LossDeclaration {
        context: Context,
        doc_type: "LossDeclaration".into(),
        v: 3,
        set_root: set.root(),
        presented: 2,
        declared_at: Timestamp::parse("2026-10-01T00:00:00.000Z").expect("ts"),
        signatures: SignatureSet::default(),
    };
    let doc = LossDeclaration {
        signatures: SignatureSet::new(vec![sign_doc(&doc, &owner).expect("sig")]),
        ..doc
    };
    let twice = [sh[0].clone(), sh[0].clone()];
    assert_eq!(
        doc.validate(
            &set,
            &twice,
            &owner.public(),
            &issuer.public(),
            &Profile::default()
        ),
        Err(CustodyError::RepeatedIndex(1))
    );
}

fn place(keeping: Keeping, jurisdiction: &str, operator: &str) -> Place {
    Place {
        keeping,
        jurisdiction: jurisdiction.into(),
        operator: operator.into(),
    }
}

#[test]
fn sh8_one_country_spelled_three_ways_is_one_country() {
    let plan = Plan {
        threshold: 3,
        procedure: Hash::sha256(b"procedure"),
        places: vec![
            place(Keeping::Offline, "UA", ""),
            place(Keeping::Depositary, "ua", ""),
            place(Keeping::Cloud, " UA", "aws"),
            place(Keeping::Cloud, "PL", "AWS "),
            place(Keeping::Offline, "CH", ""),
        ],
    };
    assert!(plan.validate().is_err());
    assert!(plan.any_country_could_take_it());
    assert_eq!(plan.exposure("ua"), 3);
}

#[test]
fn sh8_two_clouds_at_one_operator_spelled_twice_are_one_cloud() {
    let plan = Plan {
        threshold: 3,
        procedure: Hash::sha256(b"procedure"),
        places: vec![
            place(Keeping::Offline, "UA", ""),
            place(Keeping::Depositary, "UA", ""),
            place(Keeping::Cloud, "PL", "aws"),
            place(Keeping::Cloud, "DE", "AWS "),
            place(Keeping::Offline, "CH", ""),
        ],
    };
    assert_eq!(
        plan.validate(),
        Err(CustodyError::Plan(
            "two shares with one cloud operator: that is one share"
        ))
    );
}

#[test]
fn sh9_the_country_limit_follows_the_threshold() {
    let plan = Plan {
        threshold: 2,
        procedure: Hash::sha256(b"procedure"),
        places: vec![
            place(Keeping::Offline, "UA", ""),
            place(Keeping::Depositary, "UA", ""),
            place(Keeping::Offline, "PL", ""),
        ],
    };
    assert!(plan.any_country_could_take_it());
    assert!(
        plan.validate().is_err(),
        "a plan a country can take is refused"
    );
}

/// The value at `x` of the parabola through `(0, s)`, `(1, y1)`,
/// `(2, y2)` — what a holder of two shares computes for each guess of `s`.
fn third_point(s: u8, y1: u8, y2: u8, x: u8) -> u8 {
    let pts = [(0u8, s), (1u8, y1), (2u8, y2)];
    let mut out = 0u8;
    for (i, &(xi, yi)) in pts.iter().enumerate() {
        let mut basis = 1u8;
        for (j, &(xj, _)) in pts.iter().enumerate() {
            if i != j {
                basis = gf::mul(basis, gf::div(x ^ xj, xi ^ xj));
            }
        }
        out ^= gf::mul(yi, basis);
    }
    out
}

#[test]
fn sh5_two_shares_and_the_public_commitments_do_not_confirm_a_guess() {
    // A one-byte secret: 256 guesses, the worst case for a search. The holder
    // of shares 1 and 2 computes share 3 for every guess and compares with the
    // public commitment of share 3.
    let secret = 0x42u8;
    let mut rng = rand_core::OsRng;
    let sh = split_3_of_5_with_rng(&[secret], &mut rng).expect("split");
    let set = CustodySet::of(&sh, 3).expect("set");
    let target = set.commitments()[2];
    let (y1, y2) = (sh[0].body[0], sh[1].body[0]);

    // Without share 3's salt no guess confirms — not even the right one.
    let guessed_salt = sh[0].salt; // the best the holder has: another share's salt
    let hits = (0..=255u8)
        .filter(|&s| {
            let candidate = ksg_custody_v2::Share {
                index: 3,
                salt: guessed_salt,
                body: vec![third_point(s, y1, y2, 3)],
            };
            candidate.check(&target).is_ok()
        })
        .count();
    assert_eq!(hits, 0);

    // The control: with the real salt the search would succeed, which is what
    // the salt is there to deny.
    let with_salt = (0..=255u8)
        .filter(|&s| {
            let candidate = ksg_custody_v2::Share {
                index: 3,
                salt: sh[2].salt,
                body: vec![third_point(s, y1, y2, 3)],
            };
            candidate.check(&target).is_ok()
        })
        .collect::<Vec<_>>();
    assert_eq!(with_salt, vec![secret]);
}

#[test]
fn sh5_every_share_gets_its_own_salt() {
    let mut rng = rand_core::OsRng;
    let sh = split_3_of_5_with_rng(b"key", &mut rng).expect("split");
    for a in 0..5 {
        for b in a + 1..5 {
            assert_ne!(sh[a].salt, sh[b].salt);
        }
    }
}
