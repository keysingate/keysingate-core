//! Where the shares lie, and the rules that make five places five. §2.4.
//!
//! # What was prose and is now a refusal
//!
//! The custody document names five places and two rules about them — at most
//! two shares in one country, and the two clouds at **different providers in
//! different jurisdictions**, the owner: "otherwise 4 and 5 fall together". Those rules decide
//! whether 3-of-5 is worth anything: two shares that one revocation, one
//! sanction or one court order takes together are **one share**, and a scheme
//! written for five places standing on four is not the scheme.
//!
//! Until now they were sentences in a document. Here they are checks.
//!
//! # What stays out of the chain, and why that is the whole design
//!
//! The chain gets **one digest of this plan** and nothing else.
//!
//! `[inference]` The temptation is to anchor the places themselves — it would make the
//! independence publicly checkable. It would also publish the topology of the
//! custody: which country to subpoena, which provider to pressure, where the
//! paper envelope is. That is a map drawn for the one reader who should not have
//! it, and the gain is small — the people who need to check independence (the
//! owner, an auditor) hold the plan anyway.
//!
//! So: the plan is private, the digest is anchored, and the anchor proves only
//! that **the plan has not been quietly rewritten** since. Which is the property
//! actually needed: a plan that can be edited after the fact is not a plan.
//!
//! # The recovery procedure is part of it
//!
//! §2.4 says the chain carries "an obligation for each share **+ the hash of the
//! recovery procedure**". A set of shares with no written procedure is five envelopes
//! and a guess; pinning the procedure's digest is what makes "restore it the way
//! it was planned" mean something two years later.

use ksg_core_v2::crypto::hash::Hash;

use crate::CustodyError;

/// What kind of place a share lies in.
///
/// Kinds, not names: the plan says "a cloud in that jurisdiction", never which
/// account. What the rules need is the **shape** of the independence, and a name
/// adds nothing to it except exposure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Keeping {
    /// An offline medium, never connected to a network.
    Offline,
    /// A third party holding it under law — a notary, a bank's box.
    Depositary,
    /// A cloud provider, the share encrypted under a key not kept there.
    Cloud,
}

/// One place, as the plan names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Place {
    /// What kind.
    pub keeping: Keeping,
    /// Which jurisdiction, as a plain label — "UA", "PL", "CH". Compared, never
    /// interpreted: this crate knows nothing of countries beyond whether two
    /// labels are the same.
    pub jurisdiction: String,
    /// Which operator, for clouds — a label, again compared and not interpreted.
    /// Empty for the other kinds.
    pub operator: String,
}

/// The five places and the procedure that restores from them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// The places, in share order.
    pub places: Vec<Place>,
    /// How many shares reconstruct the secret.
    pub threshold: u8,
    /// The digest of the written recovery procedure.
    pub procedure: Hash,
}

/// How many shares one jurisdiction may hold.
///
/// `[decision] 12.09`, from the choice of a Ukrainian notary: with the threshold at
/// three, any event covering a country must be able to take **at most two**.
/// Three in one country is a country that can take the key.
pub const MAX_PER_JURISDICTION: usize = 2;

/// A label as the rules compare it: trimmed, ASCII upper case.
///
/// "UA", "ua" and " UA" are one country. Compared raw they were three, and the
/// rule of two per jurisdiction let three shares into one country by spelling
/// alone (audit of 2026-10-01, finding Sh-8). The same holds for operators.
/// The digest keeps the labels as written: it pins the plan, not its reading.
fn label(s: &str) -> String {
    s.trim().to_ascii_uppercase()
}

impl Plan {
    /// Whether this plan is one the scheme actually stands on.
    ///
    /// # Errors
    ///
    /// [`CustodyError::Plan`] naming the rule that failed. Each of them is the
    /// difference between five places and fewer.
    pub fn validate(&self) -> Result<(), CustodyError> {
        if self.threshold < 2 {
            return Err(CustodyError::Plan(
                "a threshold below two is a copy, not a split",
            ));
        }
        if self.places.len() < self.threshold as usize {
            return Err(CustodyError::Plan(
                "fewer places than the threshold: the secret cannot be recovered at all",
            ));
        }
        if self.procedure == Hash::sha256(b"") {
            return Err(CustodyError::Plan(
                "no recovery procedure: five envelopes and a guess",
            ));
        }
        if self.places.iter().any(|p| p.jurisdiction.trim().is_empty()) {
            return Err(CustodyError::Plan(
                "a place with no jurisdiction: independence cannot be judged",
            ));
        }

        // At most two per country, and never as many as the threshold: with a
        // threshold of three, one country that holds three holds the key; with
        // a threshold of two, one that holds two does (finding Sh-9).
        let limit = MAX_PER_JURISDICTION.min(usize::from(self.threshold) - 1);
        for p in &self.places {
            if self.exposure(&p.jurisdiction) > limit {
                return Err(CustodyError::Plan("too many shares in one jurisdiction"));
            }
        }

        // Two clouds at one operator are one cloud: a revoked account, a
        // sanction or one order takes both at once.
        for p in self.places.iter().filter(|p| p.keeping == Keeping::Cloud) {
            if p.operator.trim().is_empty() {
                return Err(CustodyError::Plan("a cloud place with no operator named"));
            }
            let same = self
                .places
                .iter()
                .filter(|q| q.keeping == Keeping::Cloud && label(&q.operator) == label(&p.operator))
                .count();
            if same > 1 {
                return Err(CustodyError::Plan(
                    "two shares with one cloud operator: that is one share",
                ));
            }
        }

        // The kinds must not collapse either: a set held entirely by technical
        // means falls to one technical event, and one held entirely under law
        // falls to one jurisdiction's process.
        let kinds = self
            .places
            .iter()
            .map(|p| p.keeping)
            .collect::<std::collections::BTreeSet<_>>();
        if kinds.len() < 2 {
            return Err(CustodyError::Plan(
                "every share kept the same way: one kind of event takes them all",
            ));
        }
        Ok(())
    }

    /// How many shares an event covering one jurisdiction would take.
    ///
    /// The question the rules exist to answer, asked directly. Anything at or
    /// above the threshold means that country can take the key.
    #[must_use]
    pub fn exposure(&self, jurisdiction: &str) -> usize {
        let j = label(jurisdiction);
        self.places
            .iter()
            .filter(|p| label(&p.jurisdiction) == j)
            .count()
    }

    /// Whether any single jurisdiction could reconstruct the secret.
    #[must_use]
    pub fn any_country_could_take_it(&self) -> bool {
        self.places
            .iter()
            .any(|p| self.exposure(&p.jurisdiction) >= self.threshold as usize)
    }

    /// The digest the chain carries — and the only part of this that is public.
    #[must_use]
    pub fn digest(&self) -> Hash {
        let mut parts: Vec<Vec<u8>> = vec![
            b"ksg:custody-plan:v1".to_vec(),
            vec![self.threshold],
            self.procedure.as_bytes().to_vec(),
        ];
        for p in &self.places {
            parts.push(format!("{:?}", p.keeping).into_bytes());
            parts.push(p.jurisdiction.as_bytes().to_vec());
            parts.push(p.operator.as_bytes().to_vec());
        }
        let refs: Vec<&[u8]> = parts.iter().map(std::vec::Vec::as_slice).collect();
        Hash::sha256_fields(&refs)
    }
}
