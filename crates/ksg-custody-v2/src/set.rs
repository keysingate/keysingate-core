//! The set of shares, and the one value that goes on a chain.
//!
//! # Why the chain gets a root and not the commitments
//!
//! Five commitments would be five things to publish, five to keep in step and
//! five chances to publish four. One root is one transaction, and a share still
//! proves its membership: the holder shows the share, its position, and the
//! other four commitments, which give away nothing.
//!
//! # What an anchor here proves, and what it does not
//!
//! The same thing anchoring proves everywhere in this codebase and no more:
//! **this set existed no later than such a moment**. It does not say the shares
//! are good, that anyone still holds them, or that three can be gathered. It
//! closes exactly one gap — that a set cannot be assembled after the fact and
//! claimed to have been the set all along.
//!
//! And the thing it must never carry: **no key material**. A ciphertext on a
//! chain is public, permanent and withdrawn by nobody, and any later advance
//! opens it retroactively. The commitments are hashes; a root of hashes is a
//! hash.

use ksg_core_v2::crypto::hash::Hash;

use crate::{Commitment, CustodyError, Share};

/// Separates this digest from every other hash in the protocol.
const DOMAIN: &[u8] = b"ksg:custody:set:v1";

/// The commitments to one split, in share order, and their root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustodySet {
    commitments: Vec<Commitment>,
    threshold: u8,
}

impl CustodySet {
    /// Takes the commitments of a freshly split secret.
    ///
    /// # Errors
    ///
    /// [`CustodyError::BadParameters`] if the shares do not make a scheme,
    /// [`CustodyError::OutOfOrder`] if position `i` does not hold index `i + 1`:
    /// [`CustodySet::contains`] finds a commitment by the share's index, so a
    /// set taken out of order would refuse the very shares it was made of
    /// (audit of 2026-10-01, finding Sh-6).
    pub fn of(shares: &[Share], threshold: u8) -> Result<Self, CustodyError> {
        let n = u8::try_from(shares.len()).unwrap_or(u8::MAX);
        if threshold < 2 || n < threshold || shares.len() > usize::from(u8::MAX - 1) {
            return Err(CustodyError::BadParameters {
                threshold,
                shares: n,
            });
        }
        for (position, s) in shares.iter().enumerate() {
            if usize::from(s.index) != position + 1 {
                return Err(CustodyError::OutOfOrder {
                    position,
                    index: s.index,
                });
            }
        }
        Ok(Self {
            commitments: shares.iter().map(Share::commitment).collect(),
            threshold,
        })
    }

    /// A set read back from its commitments — the form it is kept in once the
    /// shares are dealt out and no longer in one place.
    ///
    /// # Errors
    ///
    /// [`CustodyError::BadParameters`] if the commitments do not make a scheme.
    pub fn from_commitments(
        commitments: Vec<Commitment>,
        threshold: u8,
    ) -> Result<Self, CustodyError> {
        let n = u8::try_from(commitments.len()).unwrap_or(u8::MAX);
        if threshold < 2 || n < threshold || commitments.len() > usize::from(u8::MAX - 1) {
            return Err(CustodyError::BadParameters {
                threshold,
                shares: n,
            });
        }
        Ok(Self {
            commitments,
            threshold,
        })
    }

    /// The single value to anchor.
    ///
    /// The threshold and the count are hashed in along with the commitments, so
    /// a set cannot later be presented as a different scheme over the same
    /// shares — "three of five" and "two of five" would otherwise share a root.
    #[must_use]
    pub fn root(&self) -> Hash {
        let mut parts: Vec<&[u8]> = Vec::with_capacity(self.commitments.len() + 3);
        let counts = [
            self.threshold,
            u8::try_from(self.commitments.len()).unwrap_or(u8::MAX),
        ];
        parts.push(DOMAIN);
        parts.push(&counts);
        for c in &self.commitments {
            parts.push(c.as_bytes());
        }
        Hash::sha256_fields(&parts)
    }

    /// The commitments, in share order.
    #[must_use]
    pub fn commitments(&self) -> &[Commitment] {
        &self.commitments
    }

    /// The threshold this set was made under.
    #[must_use]
    pub const fn threshold(&self) -> u8 {
        self.threshold
    }

    /// Whether a share belongs to this set at the position its index names.
    ///
    /// # Errors
    ///
    /// [`CustodyError::Substituted`] if it does not, or if the index falls
    /// outside the set.
    pub fn contains(&self, share: &Share) -> Result<(), CustodyError> {
        let at = usize::from(share.index).checked_sub(1);
        let Some(expected) = at.and_then(|i| self.commitments.get(i)) else {
            return Err(CustodyError::Substituted(share.index));
        };
        share.check(expected)
    }

    /// Reconstructs the secret **after** checking every share against this set.
    ///
    /// Shamir has no integrity of its own: a substituted share yields a
    /// different secret silently and confidently. [`crate::combine`] on
    /// its own therefore answers with something that looks like a key and is
    /// not one, and the check that would have caught it sat in a separate
    /// function nobody was obliged to call (security audit of 2026-09-13,
    /// finding 18). This is the entry point to use when a set is at hand.
    ///
    /// # Errors
    ///
    /// Whatever [`CustodySet::check_all`] returns, then whatever
    /// [`crate::combine`] returns.
    pub fn combine_checked(
        &self,
        shares: &[Share],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, CustodyError> {
        self.check_all(shares)?;
        crate::combine(shares, self.threshold)
    }

    /// Checks every share against this set, without reconstructing anything.
    ///
    /// # Errors
    ///
    /// [`CustodyError::NotEnough`] below the threshold; whatever
    /// [`CustodySet::contains`] returns for the first share that does not match.
    pub fn check_all(&self, shares: &[Share]) -> Result<(), CustodyError> {
        if shares.len() < self.threshold as usize {
            return Err(CustodyError::NotEnough {
                presented: shares.len(),
                threshold: self.threshold,
            });
        }
        for s in shares {
            self.contains(s)?;
        }
        Ok(())
    }
}

/// Evidence that a set existed no later than a moment.
///
/// The core's [`ksg_core_v2::anchor::Attestation`], under a name that says what it
/// attests here. It carries a **root of hashes** and never key material: a
/// ciphertext on a chain is public, permanent, withdrawn by nobody, and opened
/// retroactively by any later advance.
pub type CustodyAnchor = ksg_core_v2::anchor::Attestation;
