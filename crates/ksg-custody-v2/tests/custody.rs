//! Three of five. The tests check the two PROPERTIES the scheme is bought for —
//! any three recover, any two recover nothing — rather than fixed outputs.
//!
//! A test comparing bytes against bytes this same code produced would pass on a
//! broken scheme just as happily.

use ksg_custody_v2::{
    combine, combine_3_of_5, entropy_needed, gf, split, split_3_of_5, CustodyError, Share, SHARES,
    THRESHOLD,
};

/// A 32-byte key, as an Ed25519 seed is.
fn secret() -> Vec<u8> {
    (0u8..32)
        .map(|i| i.wrapping_mul(7).wrapping_add(3))
        .collect()
}

/// Test entropy. NOT a substitute for a CSPRNG — see the crate documentation.
/// Here it only has to be fixed, so that a failure is reproducible.
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
    let s = secret();
    split_3_of_5(&s, &entropy(entropy_needed(s.len(), THRESHOLD, SHARES))).expect("split")
}

// --- the property that makes it usable ---------------------------------------

#[test]
fn any_three_of_the_five_recover_the_secret() {
    // Every one of the ten triples, not a convenient one: a scheme that works
    // for {1,2,3} and fails for {2,4,5} is a scheme with a bug in it.
    let all = shares();
    let mut triples = 0;
    for i in 0..5 {
        for j in (i + 1)..5 {
            for k in (j + 1)..5 {
                let picked = [all[i].clone(), all[j].clone(), all[k].clone()];
                assert_eq!(
                    *combine_3_of_5(&picked).expect("combine"),
                    secret(),
                    "triple {i}{j}{k} did not recover"
                );
                triples += 1;
            }
        }
    }
    assert_eq!(triples, 10, "there are ten triples of five");
}

#[test]
fn four_and_five_shares_recover_it_too() {
    // Extra shares beyond the threshold must not spoil the interpolation.
    let all = shares();
    assert_eq!(*combine_3_of_5(&all[..4]).expect("four"), secret());
    assert_eq!(*combine_3_of_5(&all).expect("five"), secret());
}

// --- the property that makes it worth the trouble ----------------------------

#[test]
fn two_shares_are_refused_rather_than_answered_badly() {
    // The scheme's point: below the threshold there is no answer, not a worse
    // one. Returning something plausible would be far more dangerous than
    // refusing, because it would be used.
    let all = shares();
    assert_eq!(
        combine_3_of_5(&all[..2]).unwrap_err(),
        CustodyError::NotEnough {
            presented: 2,
            threshold: 3
        }
    );
}

#[test]
fn two_shares_leave_every_secret_equally_possible() {
    // The formal statement behind "a leak of one place is not an event": with
    // two shares in hand, for ANY guess at the secret there exists a third share
    // making that guess come out. So the two shares rule out nothing.
    //
    // Shown by construction: take two real shares, pick an arbitrary target,
    // and solve for the third share's body. It is a valid share of the target.
    let all = shares();
    let (a, b) = (&all[0], &all[1]);
    let target = vec![0xEEu8; secret().len()];

    // Solve for the body of a third share at index 4 that makes {a, b, x}
    // interpolate to `target`. In GF(2^8) this is one linear equation per byte.
    let x_index = all[3].index;
    let basis_x = lagrange_basis(x_index, &[a.index, b.index, x_index]);
    let basis_a = lagrange_basis(a.index, &[a.index, b.index, x_index]);
    let basis_b = lagrange_basis(b.index, &[a.index, b.index, x_index]);

    let body: Vec<u8> = (0..target.len())
        .map(|i| {
            let known = gf::mul(a.body[i], basis_a) ^ gf::mul(b.body[i], basis_b);
            gf::div(target[i] ^ known, basis_x)
        })
        .collect();

    let forged = Share {
        index: x_index,
        salt: [0; ksg_custody_v2::SALT_LEN],
        body,
    };
    assert_eq!(
        *combine_3_of_5(&[a.clone(), b.clone(), forged]).expect("combine"),
        target,
        "two shares must be consistent with any secret at all"
    );
    assert_ne!(target, secret(), "the target was a different secret");
}

/// The Lagrange coefficient of `at` within `points`, evaluated at zero.
fn lagrange_basis(at: u8, points: &[u8]) -> u8 {
    let mut basis = 1u8;
    for &p in points {
        if p != at {
            basis = gf::mul(basis, gf::div(p, p ^ at));
        }
    }
    basis
}

// --- substitution ------------------------------------------------------------

#[test]
fn a_changed_share_is_caught_by_its_commitment() {
    // What the chain is for: the commitment says a share was not swapped. It
    // carries nothing that helps recover the secret.
    let all = shares();
    let c = all[2].commitment();
    all[2]
        .check(&c)
        .expect("the share matches its own commitment");

    let mut tampered = all[2].clone();
    tampered.body[0] ^= 1;
    assert_eq!(
        tampered.check(&c).unwrap_err(),
        CustodyError::Substituted(tampered.index)
    );
}

#[test]
fn commitments_cannot_be_traded_between_shares() {
    // The index is hashed with the body, so share 1 cannot present itself under
    // share 2's commitment even if an attacker holds both.
    let all = shares();
    assert!(all[0].check(&all[1].commitment()).is_err());
}

#[test]
fn a_substituted_share_silently_corrupts_the_result_which_is_why_commitments_exist() {
    // Stated as a test because it is the reason the commitment is not optional:
    // Shamir has no integrity of its own. A wrong share does not fail — it
    // produces a different secret, confidently.
    let all = shares();
    let mut bad = all[0].clone();
    bad.body[0] ^= 0xFF;
    let got = combine_3_of_5(&[bad, all[1].clone(), all[2].clone()]).expect("it does not fail");
    assert_ne!(*got, secret(), "it returns the wrong answer instead");
}

// --- misuse ------------------------------------------------------------------

#[test]
fn the_same_share_twice_is_not_two_shares() {
    // Not a duplicate to skip: two claims about one point, which interpolation
    // answers with a division by zero. Refused instead.
    let all = shares();
    assert_eq!(
        combine_3_of_5(&[all[0].clone(), all[0].clone(), all[1].clone()]).unwrap_err(),
        CustodyError::RepeatedIndex(all[0].index)
    );
}

#[test]
fn index_zero_is_the_secret_and_is_never_a_share() {
    let all = shares();
    assert!(all.iter().all(|s| s.index != 0));
    let forged = Share {
        index: 0,
        salt: [0; ksg_custody_v2::SALT_LEN],
        body: secret(),
    };
    assert_eq!(
        combine_3_of_5(&[forged, all[0].clone(), all[1].clone()]).unwrap_err(),
        CustodyError::ZeroIndex
    );
}

#[test]
fn too_little_entropy_is_refused_rather_than_stretched() {
    // Stretching short entropy is the failure that looks like success: the
    // shares come out, and the secret is no longer hidden.
    let s = secret();
    let needed = entropy_needed(s.len(), THRESHOLD, SHARES);
    assert_eq!(
        needed,
        s.len() * 2 + 5 * ksg_custody_v2::SALT_LEN,
        "3 of 5 needs two coefficients per byte and a salt per share"
    );
    assert_eq!(
        split_3_of_5(&s, &entropy(needed - 1)).unwrap_err(),
        CustodyError::ShortEntropy {
            supplied: needed - 1,
            needed
        }
    );
}

#[test]
fn impossible_schemes_are_refused() {
    let e = entropy(1024);
    // A threshold of one is not a threshold — every share would be the secret.
    assert!(matches!(
        split(&secret(), 1, 5, &e),
        Err(CustodyError::BadParameters { .. })
    ));
    // More needed than made is a secret nobody can recover.
    assert!(matches!(
        split(&secret(), 4, 3, &e),
        Err(CustodyError::BadParameters { .. })
    ));
    assert!(matches!(
        split(&[], 3, 5, &e),
        Err(CustodyError::EmptySecret)
    ));
}

#[test]
fn the_owner_asked_for_three_of_five() {
    assert_eq!((THRESHOLD, SHARES), (3, 5));
    assert_eq!(shares().len(), 5);
}

// --- the field ---------------------------------------------------------------

#[test]
fn the_field_is_a_field() {
    // Checked over the whole field rather than on samples: 256 by 256 is small
    // enough that there is no excuse for sampling.
    for a in 0..=255u8 {
        assert_eq!(gf::mul(a, 1), a, "one is the unit");
        assert_eq!(gf::mul(a, 0), 0, "zero absorbs");
        for b in 0..=255u8 {
            assert_eq!(gf::mul(a, b), gf::mul(b, a), "multiplication commutes");
        }
        if a != 0 {
            assert_eq!(gf::mul(a, gf::inv(a)), 1, "every non-zero element inverts");
            assert_eq!(gf::div(a, a), 1);
        }
    }
    assert_eq!(gf::inv(0), 0, "the inverse of zero is defined as zero");
}

#[test]
fn a_single_byte_secret_works_as_a_long_one_does() {
    // The degenerate length, where an off-by-one in the coefficient slicing
    // would hide.
    let s = [0x42u8];
    let sh = split_3_of_5(&s, &entropy(entropy_needed(1, THRESHOLD, SHARES))).expect("split");
    assert_eq!(*combine_3_of_5(&sh[1..4]).expect("combine"), s);
}

#[test]
fn other_schemes_work_too_even_though_the_owner_chose_one() {
    // The 3-of-5 helpers are a decision, not a limitation of the code.
    for (t, n) in [(2u8, 3u8), (2, 2), (5, 9), (3, 255 - 1)] {
        let s = secret();
        let sh = split(&s, t, n, &entropy(entropy_needed(s.len(), t, n))).expect("split");
        assert_eq!(sh.len(), n as usize);
        assert_eq!(*combine(&sh[..t as usize], t).expect("combine"), s);
    }
}
