//! # ksg-custody — the issuer's key, split three ways out of five
//!
//! `[decision] 11.09` of the owner: **3 of 5**.
//!
//! # Why a threshold and not three copies
//!
//! Because losing the issuer's key and leaking it are not the same size of
//! disaster, and treating them as one produces the wrong design.
//!
//! Losing it stops issuance: no new releases, no new packets. Every container
//! already issued stays verifiable, since the public keys sit inside the
//! self-attesting `Emission`. Expensive, and reversible.
//!
//! Leaking it allows forged releases and forged packets, indistinguishable from
//! real ones at the first layer. Irreversible, including backwards: a container
//! minted with a stolen key is as good as a real one for as long as the key was
//! out.
//!
//! So the arithmetic of copies is wrong for this key:
//!
//! | | to lose it | to leak it |
//! |---|---|---|
//! | three copies | lose all three | **one is enough** |
//! | **3 of 5** | lose three | **gather three** |
//!
//! The threshold makes the two failures cost the same. That is the whole reason
//! this crate exists.
//!
//! # What is NOT here, deliberately
//!
//! * **No randomness.** [`split`] takes entropy as an argument. The crate has no
//!   dependencies and the tests are exact, and — more to the point — where the
//!   randomness comes from is the operator's decision, as the keys are
//!   everywhere else in this codebase. **A caller feeding this anything but a
//!   cryptographic RNG destroys the scheme**, and no type can prevent that; see
//!   [`split`].
//! * **No storage, no transport, no cloud.** Five places were named by the
//!   owner and none of them is code.
//! * **No key material on a chain.** The chain gets [`Commitment`]s — the
//!   commitment proves a share existed and was not substituted, and carries
//!   nothing that helps recover it. A ciphertext published on a chain is public
//!   and permanent and is broken by any later advance; this codebase already
//!   treats that as real, since ML-DSA-65 is planned for exactly that reason.
//!
//! # A word on this implementation
//!
//! Shamir over GF(2^8) is one of the few primitives simple enough to write out
//! and check by eye, which is why it is written out here. That is not a claim
//! that it is audited. It is table-free and branch-free on secret data (see
//! [`gf`]), and the tests check the properties rather than the outputs — that
//! any three shares recover, that any two recover **nothing**, and that a
//! changed share is caught by its commitment. For production, weigh an audited
//! implementation against this one; the interface would not change.

#![forbid(unsafe_code)]

pub mod gf;
pub mod loss;
pub mod plan;
pub mod set;
pub mod succession;

pub use plan::{Keeping, Place, Plan, MAX_PER_JURISDICTION};
pub use set::{CustodyAnchor, CustodySet};
pub use succession::{
    Succession, SuccessionClaim, SuccessionVeto, NOTICE_MAX_MS, NOTICE_MIN_MS,
    NOTICE_RECOMMENDED_MS,
};

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// The owner's threshold: three shares reconstruct.
pub const THRESHOLD: u8 = 3;

/// The owner's count: five shares are made.
pub const SHARES: u8 = 5;

/// What can go wrong.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CustodyError {
    /// Fewer shares than the threshold were presented.
    #[error("{presented} shares presented, {threshold} needed")]
    NotEnough {
        /// How many arrived.
        presented: usize,
        /// How many are needed.
        threshold: u8,
    },
    /// The plan of places does not hold up — §2.4.
    #[error("the custody plan does not hold: {0}")]
    Plan(&'static str),
    /// Two shares carry the same index, so they are not two shares.
    #[error("share index {0} appears twice")]
    RepeatedIndex(u8),
    /// A share's index is zero, which is the secret's own position.
    #[error("share index 0 is the secret's position and is not a share")]
    ZeroIndex,
    /// The shares are of different lengths and cannot be from one secret.
    #[error("shares differ in length: {0} and {1}")]
    LengthMismatch(usize, usize),
    /// Not enough entropy was supplied for the split.
    #[error("{supplied} bytes of entropy supplied, {needed} needed")]
    ShortEntropy {
        /// How many bytes arrived.
        supplied: usize,
        /// How many are needed.
        needed: usize,
    },
    /// The secret is empty, so there is nothing to share.
    #[error("the secret is empty")]
    EmptySecret,
    /// The parameters do not make a scheme.
    #[error("a {threshold}-of-{shares} scheme is not possible")]
    BadParameters {
        /// The threshold asked for.
        threshold: u8,
        /// The share count asked for.
        shares: u8,
    },
    /// A share does not match the commitment it was checked against.
    #[error("share {0} does not match its commitment")]
    Substituted(u8),
    /// An anchor attests a different set than the one presented.
    #[error("the anchor is of a different set")]
    WrongSet,
    /// A share beyond the threshold does not lie on the polynomial the first
    /// `threshold` shares define: one of the presented shares is not of this
    /// secret (audit of 2026-10-01, finding Sh-1).
    #[error("share {0} does not agree with the others")]
    Inconsistent(u8),
    /// The shares handed to [`CustodySet::of`] are not the split in order:
    /// position `i` must hold the share with index `i + 1`.
    #[error("the share at position {position} has index {index}")]
    OutOfOrder {
        /// Where in the list.
        position: usize,
        /// The index found there.
        index: u8,
    },
    /// A succession document did not verify.
    #[error("succession: {0}")]
    Succession(&'static str),
}

/// How long a share's salt is.
pub const SALT_LEN: usize = 32;

/// One share. Useless on its own, and useless with one other.
///
/// `Debug` is written by hand below, and `PartialEq` compares the body in
/// constant time: a share is key material of the issuer, and the derived forms
/// of both traits leaked it (audit of 2026-09-13, findings 1 and 8).
///
/// `ZeroizeOnDrop` wipes `body` when the share goes out of scope: without it the
/// bytes stay in freed heap and reach a core dump, swap or the next allocation
/// in the same process (same audit, finding 2). `index` is not secret and is
/// skipped.
///
/// `salt` is drawn afresh for every share and kept **with** it, under the same
/// care as the body. It enters the commitment so that the commitments of the
/// shares one does not hold cannot be tested against guesses: without it, two
/// shares and the five public commitments let anyone check a candidate secret,
/// and a secret with little entropy falls to the search (audit of 2026-10-01,
/// finding Sh-5).
#[derive(Clone, Eq, zeroize::ZeroizeOnDrop)]
pub struct Share {
    /// The evaluation point, `1..=SHARES`. Never zero: zero is the secret.
    pub index: u8,
    /// This share's salt — see above.
    pub salt: [u8; SALT_LEN],
    /// The polynomial's value at `index`, byte by byte.
    pub body: Vec<u8>,
}

// Written by hand so that a share never lands in a log, a panic message or a
// CI transcript through a derived formatter: three shares in one log are the
// issuer's key, and its loss is irreversible. The same reason `LayerKey` in
// `ksg-container-v2` prints nothing.
impl core::fmt::Debug for Share {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Share(index={}, ..)", self.index)
    }
}

// Byte-by-byte comparison with an early exit tells the caller how many leading
// bytes matched, which is a byte-at-a-time search for the share. `gf.rs` is
// branch-free on secret data for the same reason; the derived `PartialEq` was
// the one place where that requirement was not held.
impl PartialEq for Share {
    fn eq(&self, other: &Self) -> bool {
        if self.index != other.index || self.body.len() != other.body.len() {
            return false;
        }
        let mut diff = 0u8;
        for (a, b) in self.body.iter().zip(other.body.iter()) {
            diff |= a ^ b;
        }
        for (a, b) in self.salt.iter().zip(other.salt.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }
}

impl Share {
    /// The commitment to this share — what goes on the chain.
    ///
    /// A hash and not the share: it proves the share existed at a time and was
    /// not swapped afterwards, and it helps nobody recover the secret. The index
    /// is hashed with the body so that two shares cannot trade commitments, and
    /// the salt so that a commitment cannot be tested against a guessed share
    /// (finding Sh-5). Every field has a fixed length but the body, which comes
    /// last, so the encoding is unambiguous.
    #[must_use]
    pub fn commitment(&self) -> Commitment {
        let mut h = Sha256::new();
        h.update(b"ksg:custody:share:v2");
        h.update([self.index]);
        h.update(self.salt);
        h.update(&self.body);
        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize());
        Commitment(out)
    }

    /// Whether this share is the one the commitment was taken of.
    ///
    /// # Errors
    ///
    /// [`CustodyError::Substituted`] when it is not.
    pub fn check(&self, against: &Commitment) -> Result<(), CustodyError> {
        // Constant-time: the commitment is not itself secret, but the timing of
        // a derived `==` tells "matched in the first byte" from "matched almost
        // entirely", and that helps a search for the share behind it (security
        // audit of 2026-09-13, finding 22).
        if self.commitment().ct_eq(against) {
            Ok(())
        } else {
            Err(CustodyError::Substituted(self.index))
        }
    }
}

/// A commitment to a share. This, and only this, is what a chain may carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Commitment([u8; 32]);

impl Commitment {
    /// Equality in constant time — see [`Share::check`].
    #[must_use]
    fn ct_eq(&self, other: &Self) -> bool {
        let mut diff = 0u8;
        for (a, b) in self.0.iter().zip(other.0.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }
}

impl Commitment {
    /// The digest.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// A commitment read back from where it was kept — a set file, a chain.
    /// Public data: nothing here is checked but the length, which the type holds.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl std::fmt::Display for Commitment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// How many bytes of entropy [`split`] will want: `threshold − 1` coefficients
/// per secret byte, then [`SALT_LEN`] bytes of salt per share.
#[must_use]
pub const fn entropy_needed(secret_len: usize, threshold: u8, shares: u8) -> usize {
    secret_len
        .saturating_mul((threshold as usize).saturating_sub(1))
        .saturating_add(SALT_LEN.saturating_mul(shares as usize))
}

/// Splits a secret into `shares`, of which `threshold` reconstruct.
///
/// # The entropy argument is the whole security of this function
///
/// Each secret byte gets its own polynomial whose constant term is that byte
/// and whose remaining `threshold - 1` coefficients come from `entropy`; the
/// salts of the shares come after them, [`SALT_LEN`] bytes each. Those
/// coefficients are what hides the secret: with fewer than `threshold` shares,
/// every possible secret remains exactly as likely, and that statement is true
/// **only if the coefficients are uniform and unpredictable**.
///
/// Feed this a counter, a timestamp, or a seeded PRNG and the scheme does not
/// weaken gracefully — it stops working, while continuing to look identical.
/// Use the operating system's CSPRNG.
///
/// # Errors
///
/// [`CustodyError::EmptySecret`], [`CustodyError::BadParameters`] if the scheme
/// is impossible, [`CustodyError::ShortEntropy`] if too little was supplied.
pub fn split(
    secret: &[u8],
    threshold: u8,
    shares: u8,
    entropy: &[u8],
) -> Result<Vec<Share>, CustodyError> {
    if secret.is_empty() {
        return Err(CustodyError::EmptySecret);
    }
    if threshold < 2 || shares < threshold || shares == u8::MAX {
        return Err(CustodyError::BadParameters { threshold, shares });
    }
    let needed = entropy_needed(secret.len(), threshold, shares);
    if entropy.len() < needed {
        return Err(CustodyError::ShortEntropy {
            supplied: entropy.len(),
            needed,
        });
    }

    let degree = threshold as usize - 1;
    let salts = &entropy[secret.len() * degree..needed];
    let mut out: Vec<Share> = (1..=shares)
        .zip(salts.chunks_exact(SALT_LEN))
        .map(|(index, s)| {
            let mut salt = [0u8; SALT_LEN];
            salt.copy_from_slice(s);
            Share {
                index,
                salt,
                body: Vec::with_capacity(secret.len()),
            }
        })
        .collect();

    for (i, &byte) in secret.iter().enumerate() {
        // coefficients[0] is the secret byte; the rest are random.
        let coeffs = &entropy[i * degree..(i + 1) * degree];
        for share in &mut out {
            // Horner, from the top coefficient down.
            let mut acc = 0u8;
            for &c in coeffs.iter().rev() {
                acc = gf::mul(acc, share.index) ^ c;
            }
            acc = gf::mul(acc, share.index) ^ byte;
            share.body.push(acc);
        }
    }
    Ok(out)
}

/// Reconstructs the secret from `threshold` or more shares.
///
/// The first `threshold` shares define the polynomial; every share beyond them
/// must lie on it, or the whole reconstruction is refused. There is no majority
/// vote, because a vote would let two bad shares outweigh one good one whenever
/// the threshold is met without them — and no silent use of extra shares
/// either: interpolating through `k + 1` points that disagree returns a
/// confident wrong secret (audit of 2026-10-01, finding Sh-1).
///
/// Returns [`Zeroizing`] rather than a bare `Vec`: this is the reconstructed
/// key of the issuer, and it is wiped when the caller drops it whether the
/// caller remembered to or not.
///
/// Shamir has no integrity of its own: a set of exactly `threshold` shares
/// with one substituted still yields *a* secret. When the commitments are at
/// hand, use [`CustodySet::combine_checked`].
///
/// # Errors
///
/// [`CustodyError::BadParameters`] below a threshold of two,
/// [`CustodyError::NotEnough`], [`CustodyError::ZeroIndex`],
/// [`CustodyError::RepeatedIndex`], [`CustodyError::LengthMismatch`],
/// [`CustodyError::Inconsistent`].
pub fn combine(shares: &[Share], threshold: u8) -> Result<Zeroizing<Vec<u8>>, CustodyError> {
    if threshold < 2 {
        return Err(CustodyError::BadParameters {
            threshold,
            shares: u8::try_from(shares.len()).unwrap_or(u8::MAX),
        });
    }
    if shares.len() < threshold as usize {
        return Err(CustodyError::NotEnough {
            presented: shares.len(),
            threshold,
        });
    }
    let len = shares[0].body.len();
    for (i, s) in shares.iter().enumerate() {
        if s.index == 0 {
            return Err(CustodyError::ZeroIndex);
        }
        if s.body.len() != len {
            return Err(CustodyError::LengthMismatch(len, s.body.len()));
        }
        // Repeated indices are not a duplicate to ignore but two claims about
        // the same point: interpolating through them divides by zero.
        if shares[..i].iter().any(|p| p.index == s.index) {
            return Err(CustodyError::RepeatedIndex(s.index));
        }
    }

    let (base, extra) = shares.split_at(threshold as usize);
    for s in extra {
        let expected = interpolate(base, s.index);
        let mut diff = 0u8;
        for (a, b) in expected.iter().zip(&s.body) {
            diff |= a ^ b;
        }
        if diff != 0 {
            return Err(CustodyError::Inconsistent(s.index));
        }
    }
    Ok(interpolate(base, 0))
}

/// The polynomial through `points`, evaluated at `x`, byte by byte.
///
/// Lagrange: `f(x) = Σ y_i · Π_{j≠i} (x − x_j) / (x_i − x_j)`. Subtraction in
/// this field is XOR, and `x_i ^ x_j` is non-zero because the caller has
/// refused repeated indices. The indices are public; the arithmetic on the
/// share bodies goes through [`gf::mul`], which does not branch on them.
fn interpolate(points: &[Share], x: u8) -> Zeroizing<Vec<u8>> {
    let len = points.first().map_or(0, |s| s.body.len());
    let mut out = Zeroizing::new(vec![0u8; len]);
    for (i, si) in points.iter().enumerate() {
        let mut basis = 1u8;
        for (j, sj) in points.iter().enumerate() {
            if i != j {
                basis = gf::mul(basis, gf::div(x ^ sj.index, si.index ^ sj.index));
            }
        }
        for (o, &y) in out.iter_mut().zip(&si.body) {
            *o ^= gf::mul(y, basis);
        }
    }
    out
}

/// Splits with coefficients drawn from `rng`, which must be a cryptographic
/// generator — the type says so, which is the point of this entry: [`split`]
/// takes bytes and cannot tell a counter from a CSPRNG (audit of 2026-10-01,
/// finding Sh-4). The drawn coefficients are wiped when the split is done.
///
/// # Errors
///
/// As [`split`].
pub fn split_with_rng<R: rand_core::CryptoRngCore + ?Sized>(
    secret: &[u8],
    threshold: u8,
    shares: u8,
    rng: &mut R,
) -> Result<Vec<Share>, CustodyError> {
    let mut entropy = Zeroizing::new(vec![0u8; entropy_needed(secret.len(), threshold, shares)]);
    rng.fill_bytes(&mut entropy);
    split(secret, threshold, shares, &entropy)
}

/// [`split_with_rng`] under the owner's decision of 11.09: three of five.
///
/// # Errors
///
/// As [`split`].
pub fn split_3_of_5_with_rng<R: rand_core::CryptoRngCore + ?Sized>(
    secret: &[u8],
    rng: &mut R,
) -> Result<Vec<Share>, CustodyError> {
    split_with_rng(secret, THRESHOLD, SHARES, rng)
}

/// Splits under the owner's decision of 11.09: three of five.
///
/// # Errors
///
/// As [`split`].
pub fn split_3_of_5(secret: &[u8], entropy: &[u8]) -> Result<Vec<Share>, CustodyError> {
    split(secret, THRESHOLD, SHARES, entropy)
}

/// Reconstructs under the owner's decision of 11.09: three of five.
///
/// # Errors
///
/// As [`combine`].
pub fn combine_3_of_5(shares: &[Share]) -> Result<Zeroizing<Vec<u8>>, CustodyError> {
    combine(shares, THRESHOLD)
}
