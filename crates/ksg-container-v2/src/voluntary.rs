//! Voluntary opening of the journal. `Mekhanizm_vygruzki_v_spore.md`, `[decision]` 11.09.
//!
//! # The arbiter problem, dissolved rather than solved
//!
//! The standing difficulty was that the container does not know the arbiter's
//! key, and the three cryptographic routes to accepting an unknown key each cost
//! something: publishing the dispute in the chain makes the dispute public, and
//! a registry of arbiters introduces a trusted party where one was just removed.
//!
//! `[decision] 11.09` **both sides supply the arbiter's key.** Agreement is the
//! identification: if the client and the owner independently name the same key,
//! that key is the arbiter's, and no registry and no publication is needed.
//!
//! The owner's own caution is worth keeping: it *looks* as if the arbiter's key
//! were unnecessary — and that impression is false. It is needed; what changes
//! is **who establishes it**.
//!
//! # Why two arbiters, and why they attest each other
//!
//! `[decision] 11.09`: the client and the owner each supply both arbiters' keys, and
//! **each arbiter supplies the other's**. So every arbiter is named by three
//! independent parties.
//!
//! To seat a FAKE arbiter A, three parties must name it: the client, the owner
//! and arbiter B. So an outsider cannot impose an arbiter, and neither can any
//! one of the four acting alone — whether by a stolen key, by coercion, or by
//! being dishonest themselves — because the others name a different key and the
//! count never reaches three.
//!
//! **What it does not stop is the client and the owner together**, since they
//! choose both arbiters and those two then vouch for each other. Whether that is
//! a hole depends on what the arbiters are for: as witnesses that an opening is
//! voluntary it is not, because being voluntary is exactly the principals' right
//! to open their own journal. As an independent check that the opening was not
//! coerced it is, and the fix would be that neither side names both — each
//! arbiter put forward by one side. The first reading is what is implemented.
//!
//! Self-attestation is refused under either reading: a key vouching for itself
//! adds nothing to what it already claims by signing.
//!
//! # What opening does and does not reveal
//!
//! `[decision] 11.09`: the container **stops keeping the pages' secrets**, but
//! signatures, keys and registrations stay secret. What comes out is the work —
//! pages with their dates and times.
//!
//! So an opened journal is for **reading**, not for **proving**. A reader sees
//! what was done and when; with the signatures withheld they cannot verify it
//! themselves. That is not a shortcoming but the division of labour: proving one
//! record is what an anchored pointwise disclosure is for
//! ([`ksg_core_v2::journal::verify_bound_point`]), and it does not require opening anything.
//!
//! # Reading is not anonymous
//!
//! `[decision] 11.09`: a reader presents their own key, **anchored in the chain**. The
//! price of reading an opened journal is being on record as having read it —
//! which is what keeps "anyone may look" from meaning "and nobody knows who
//! did".

use ksg_core_v2::anchor::Attestation;
use ksg_core_v2::canonical::{check_envelope, Signable};
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{KeySet, Profile, PublicKey, SignatureSet};
use ksg_core_v2::doc::Uri;
use serde::{Deserialize, Serialize};

use ksg_core_v2::journal::{Body, BoundPage, Piece, RecordKind};

/// Why an opening, an expert's appointment or a disclosure did not hold.
///
/// Was `ksg_journal::JournalError` in core v1's workspace; the gate documents
/// moved into the container with core v2 (spec v2 §17: the opening and the
/// disclosure are not core), and the work journal there is the bound journal,
/// which has errors of its own (`BinderError`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GateError {
    /// A rule of the opening, the appointment or the disclosure failed.
    #[error("opening: {0}")]
    Opening(&'static str),
    /// A signature does not verify.
    #[error("a signature does not verify")]
    Signature,
    /// A document does not canonicalize.
    #[error("the canonical form failed")]
    Canonicalization,
    /// The reader of an opened journal is not on record.
    #[error("the reader is not anchored")]
    ReaderNotAnchored,
    /// A page the disclosure names is not in the journal.
    #[error("no page {0}")]
    NoSuchPage(u64),
}

/// How many independent parties must name a key before it is an arbiter's.
///
/// Three: the client, the owner, and the other arbiter. Not a tuning knob — it
/// is what the owner's arrangement produces, and lowering it would let one
/// captured party seat an arbiter.
pub const ATTESTATIONS_PER_ARBITER: usize = 3;

/// The client's and the owner's joint declaration, **published in the chain**.
///
/// `[decision] 11.09` This is what makes an opening voluntary in a way anyone can
/// check. The arbiters witness it; the chain **records** it.
///
/// # Why the arbiters were not enough on their own
///
/// The client and the owner choose both arbiters, and the two appointees then
/// vouch for each other — so four signatures inside one document say only that
/// four keys agreed, and say it only to whoever holds the document. Neither
/// property is what "voluntary" needs.
///
/// The declaration fixes both at once. It is **public**, so the claim does not
/// depend on anyone producing a document; and it is **anchored**, so the two
/// principals cannot later say they never made it or made it under duress at
/// some other time.
///
/// # Keys and signatures on a chain are not material on a chain
///
/// Elsewhere in this codebase a chain carries a hash and never the thing —
/// custody shares, for one. The rule is about **secrets**. A public key is
/// public by construction and a signature reveals nothing that the key does not,
/// so both belong here: the point is precisely that a stranger can read who
/// declared what without asking either of them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpeningDeclaration {
    /// Always [`ksg_core_v2::doc::CONTEXT`] (spec v2 §3.3).
    #[serde(rename = "@context")]
    pub context: ksg_core_v2::doc::Context,
    /// Always `"OpeningDeclaration"`.
    #[serde(rename = "type")]
    pub doc_type: String,
    /// The major core version.
    pub v: u32,
    /// The container being opened.
    pub container: Hash,
    /// The client's key.
    pub client: PublicKey,
    /// The owner's key.
    pub owner: PublicKey,
    /// Both signatures, on one declaration.
    pub signatures: SignatureSet,
}

impl Signable for OpeningDeclaration {
    const DOC_TYPE: &'static str = "OpeningDeclaration";
}

impl OpeningDeclaration {
    /// Verifies the declaration and that the chain carries it.
    ///
    /// # Errors
    ///
    /// [`GateError::Opening`] on a declaration of another container, one
    /// party standing in both places, a missing signature, or an anchor of
    /// something else; [`GateError::Signature`] if a signature fails.
    pub fn validate(
        &self,
        container: &Hash,
        anchor: &Attestation,
        profile: &Profile,
    ) -> Result<(), GateError> {
        if self.container != *container {
            return Err(GateError::Opening(
                "the declaration is of another container",
            ));
        }
        if self.client.kid == self.owner.kid {
            return Err(GateError::Opening("the client and the owner are one party"));
        }
        for k in [&self.client, &self.owner] {
            if !self.signatures.signed_by(&k.kid) {
                return Err(GateError::Opening(
                    "the declaration needs both the client's and the owner's signature",
                ));
            }
        }
        let mut keys = KeySet::new();
        keys.insert(self.client.clone());
        keys.insert(self.owner.clone());
        check_envelope(
            self,
            self.v,
            &self.doc_type,
            &self.signatures,
            &keys,
            profile,
        )
        .map_err(|_| GateError::Signature)?;

        let h = ksg_core_v2::canonical::doc_hash(self).map_err(|_| GateError::Canonicalization)?;
        anchor
            .covers(&h)
            .map_err(|_| GateError::Opening("the anchor is of another declaration"))
    }
}

/// One party saying "this key is that arbiter's".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArbiterAttestation {
    /// Always [`ksg_core_v2::doc::CONTEXT`] (spec v2 §3.3).
    #[serde(rename = "@context")]
    pub context: ksg_core_v2::doc::Context,
    /// Always `"ArbiterAttestation"`.
    #[serde(rename = "type")]
    pub doc_type: String,
    /// The major core version.
    pub v: u32,
    /// The container the opening concerns.
    pub container: Hash,
    /// Who is saying it.
    pub attestor: Uri,
    /// The key they say is the arbiter's.
    pub arbiter: PublicKey,
    /// The attestor's signature.
    pub signatures: SignatureSet,
}

impl Signable for ArbiterAttestation {
    const DOC_TYPE: &'static str = "ArbiterAttestation";
}

/// The authorization to open a journal voluntarily.
///
/// Four parties sign one command: client, owner and both arbiters. The
/// attestations carried alongside are what make the arbiters' keys mean
/// anything — without them the two arbiter signatures are two strangers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VoluntaryOpening {
    /// Always [`ksg_core_v2::doc::CONTEXT`] (spec v2 §3.3).
    #[serde(rename = "@context")]
    pub context: ksg_core_v2::doc::Context,
    /// Always `"VoluntaryOpening"`.
    #[serde(rename = "type")]
    pub doc_type: String,
    /// The major core version.
    pub v: u32,
    /// The container being opened.
    pub container: Hash,
    /// The client's key.
    pub client: PublicKey,
    /// The owner's key.
    pub owner: PublicKey,
    /// The two arbiters' keys.
    pub arbiters: [PublicKey; 2],
    /// Who named whom.
    pub attestations: Vec<ArbiterAttestation>,
    /// The client's and the owner's declaration, as published in the chain.
    pub declaration: OpeningDeclaration,
    /// Four signatures, on one command.
    pub signatures: SignatureSet,
}

impl Signable for VoluntaryOpening {
    const DOC_TYPE: &'static str = "VoluntaryOpening";
}

impl VoluntaryOpening {
    /// Verifies the authorization.
    ///
    /// # Errors
    ///
    /// [`GateError::Opening`] naming which of the rules failed;
    /// [`GateError::Signature`] if a signature does not verify.
    pub fn validate(
        &self,
        container: &Hash,
        declaration_anchor: &Attestation,
        profile: &Profile,
    ) -> Result<(), GateError> {
        if self.container != *container {
            return Err(GateError::Opening("the opening is of another container"));
        }
        // The chain record comes first: without it there is no public evidence
        // that this was voluntary, and the four signatures below only say that
        // four keys agreed — to whoever is holding the document.
        self.declaration
            .validate(container, declaration_anchor, profile)?;
        if self.declaration.client.key != self.client.key
            || self.declaration.owner.key != self.owner.key
        {
            return Err(GateError::Opening(
                "the declaration names different principals than the opening",
            ));
        }
        if self.arbiters[0].kid == self.arbiters[1].kid {
            return Err(GateError::Opening("the two arbiters are one arbiter"));
        }
        let parties = [
            &self.client,
            &self.owner,
            &self.arbiters[0],
            &self.arbiters[1],
        ];
        // Four distinct parties, and all four sign. Counted by identifier, for
        // the reason it is counted that way everywhere here: a party signing
        // twice is not two parties.
        for (i, a) in parties.iter().enumerate() {
            for b in &parties[..i] {
                if a.kid == b.kid {
                    return Err(GateError::Opening("the same party stands in two places"));
                }
            }
            if !self.signatures.signed_by(&a.kid) {
                return Err(GateError::Opening("all four parties must sign the opening"));
            }
        }

        let mut keys = KeySet::new();
        for k in parties {
            keys.insert(k.clone());
        }
        check_envelope(
            self,
            self.v,
            &self.doc_type,
            &self.signatures,
            &keys,
            profile,
        )
        .map_err(|_| GateError::Signature)?;

        // Each arbiter named by three independent parties: the client, the owner
        // and the OTHER arbiter.
        for (i, arbiter) in self.arbiters.iter().enumerate() {
            let expected: [&PublicKey; 3] = [&self.client, &self.owner, &self.arbiters[1 - i]];
            for who in expected {
                // An arbiter vouching for themselves adds nothing to what they
                // already claim by signing, so it is refused rather than counted.
                if who.kid == arbiter.kid {
                    return Err(GateError::Opening("an arbiter cannot attest itself"));
                }
                let found = self
                    .attestations
                    .iter()
                    .find(|a| a.attestor == who.kid && a.arbiter.kid == arbiter.kid);
                let Some(att) = found else {
                    return Err(GateError::Opening(
                        "an arbiter is not named by all three parties",
                    ));
                };
                if att.container != *container {
                    return Err(GateError::Opening("an attestation is of another container"));
                }
                if att.arbiter.key != arbiter.key {
                    return Err(GateError::Opening(
                        "two parties named different keys for one arbiter",
                    ));
                }
                let mut k = KeySet::new();
                k.insert(who.clone());
                check_envelope(att, att.v, &att.doc_type, &att.signatures, &k, profile)
                    .map_err(|_| GateError::Signature)?;
            }
        }
        Ok(())
    }
}

/// A reader of an opened journal, on record as having read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reader {
    /// The reader's key.
    pub key: PublicKey,
    /// The anchor putting that key in the chain. **Not optional**: the price of
    /// reading is being on record, and an unanchored reader is not on record.
    pub anchor: Attestation,
}

impl Reader {
    /// Whether this reader is entitled to look.
    ///
    /// The check is not "is this key allowed" — anyone may read an opened
    /// journal. It is "is this key **anchored**", which is the whole condition.
    ///
    /// # Errors
    ///
    /// [`GateError::ReaderNotAnchored`] if the anchor is of something other
    /// than this reader's key.
    pub fn check(&self) -> Result<(), GateError> {
        let subject = Hash::sha256_parts(&[b"ksg:journal:reader:v1", self.key.key.as_bytes()]);
        self.anchor
            .covers(&subject)
            .map_err(|_| GateError::ReaderNotAnchored)
    }

    /// The value a reader's anchor must attest.
    #[must_use]
    pub fn subject(key: &PublicKey) -> Hash {
        Hash::sha256_parts(&[b"ksg:journal:reader:v1", key.key.as_bytes()])
    }
}

/// A page as an opened journal shows it.
///
/// What is here is the work: when, of what kind, and what. What is **not** here
/// is the cryptographic material — the author, the signatures, the link to the
/// previous page — because `[decision]` 11.09 keeps signatures, keys and registrations
/// secret even when the journal is open.
///
/// The consequence, said plainly: a reader **cannot verify this**. An opened
/// journal is read, not checked. Whoever needs to check one record uses an
/// anchored pointwise disclosure instead, which proves without opening anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenPage {
    /// The page's place in the journal.
    pub number: u64,
    /// Milliseconds since the packet's origin — the date and time of the work.
    pub offset_ms: u64,
    /// What kind of record the page belongs to.
    pub kind: RecordKind,
    /// The work itself, or its digest where the client keeps it elsewhere.
    pub content: Piece,
}

/// Shows an opened journal to an anchored reader: the content pages only.
///
/// The opening, the service pages, transfers, rules and the coupling carry
/// keys and seals, which `[decision]` 11.09 keeps secret even when the journal
/// is open — so they are not shown at all rather than shown in part.
///
/// # Errors
///
/// [`GateError::ReaderNotAnchored`] if the reader is not on record.
pub fn read_opened(pages: &[BoundPage], reader: &Reader) -> Result<Vec<OpenPage>, GateError> {
    reader.check()?;
    Ok(pages
        .iter()
        .filter_map(|p| match &p.body {
            Body::Content { kind, content, .. } => Some(OpenPage {
                number: p.seq,
                offset_ms: p.offset_ms,
                kind: *kind,
                content: content.clone(),
            }),
            _ => None,
        })
        .collect())
}

/// An attempt to open that did not carry what it needed.
///
/// `[decision] 11.09` on B-6: an attempt is recorded **under an anchor**. An attempt at
/// an export is an event of the same weight as an export, and its trace is worth
/// more than silence — silence means somebody tried the door and nobody will
/// ever know.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefusedAttempt {
    /// Always [`ksg_core_v2::doc::CONTEXT`] (spec v2 §3.3).
    #[serde(rename = "@context")]
    pub context: ksg_core_v2::doc::Context,
    /// Always `"RefusedAttempt"`.
    #[serde(rename = "type")]
    pub doc_type: String,
    /// The major core version.
    pub v: u32,
    /// The container somebody tried to open.
    pub container: Hash,
    /// Why it did not go through.
    pub reason: String,
    /// Whoever did sign, so that an attempt is not anonymous either.
    pub presented: Vec<Uri>,
    /// Milliseconds since the packet's origin.
    pub offset_ms: u64,
}

impl Signable for RefusedAttempt {
    const DOC_TYPE: &'static str = "RefusedAttempt";
}

impl RefusedAttempt {
    /// Builds the record of a refused attempt.
    #[must_use]
    pub fn of(container: Hash, refusal: &GateError, presented: Vec<Uri>, offset_ms: u64) -> Self {
        Self {
            context: ksg_core_v2::doc::Context,
            doc_type: "RefusedAttempt".into(),
            v: 3,
            container,
            reason: refusal.to_string(),
            presented,
            offset_ms,
        }
    }
}
