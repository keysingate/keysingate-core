//! A page of the bound journal and what it may carry.
//!
//! `[decision]` 30.09 (Plan_MVP §9, CH-1): signatures and keys are not part of
//! a page. A page is room for content — at least 2 KB — and nothing on it says
//! who sealed it: that is the seal's job, and the seal moves.

use serde::{Deserialize, Serialize};

use crate::canonical::{doc_hash, Signable};
use crate::crypto::hash::Hash;
use crate::crypto::sign::PublicKey;
use crate::doc::Uri;

use super::manifest::BatchManifest;
use super::seal::{CouplingRecord, SealRule, TransferRecord};

/// A page's content: the bytes, or their digest.
///
/// Not `Content` of `ksg-journal`: that one serializes bytes as a JSON array of
/// numbers — up to four characters a byte — and a thousand pages of 2 KB would
/// not fit any container. Here the bytes travel as base64url, a third over
/// their size. `Debug` does not print the bytes, as with `Content` of `ksg-journal`
/// (audit of 2026-09-13, finding 6).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum Piece {
    /// The content itself.
    Inline(#[serde(with = "b64")] Vec<u8>),
    /// Its digest, when the client keeps the content elsewhere.
    Digest(Hash),
}

impl core::fmt::Debug for Piece {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Inline(b) => write!(f, "Inline(<{} bytes>)", b.len()),
            Self::Digest(h) => write!(f, "Digest({h:?})"),
        }
    }
}

impl Piece {
    /// What this piece commits to — for the record's hash and the repeat rule.
    #[must_use]
    pub fn commitment(&self) -> Hash {
        match self {
            Self::Inline(b) => Hash::sha256_parts(&[b"ksg:bound:inline:v1", b]),
            Self::Digest(h) => Hash::sha256_parts(&[b"ksg:bound:digest:v1", h.as_bytes()]),
        }
    }

    /// Bytes carried inline; a digest carries none.
    #[must_use]
    pub fn inline_len(&self) -> usize {
        match self {
            Self::Inline(b) => b.len(),
            Self::Digest(_) => 0,
        }
    }
}

mod b64 {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&URL_SAFE_NO_PAD.encode(b))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        URL_SAFE_NO_PAD
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

/// Where in the layout a page stands (CH-12: `1+1000+100+2`, CH-15).
///
/// The zones are one chain: they differ in what may be written into them and
/// how many slots they hold, not in how pages are linked (CH-13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Zone {
    /// Page 0, the opening. Outside the thousand working pages (CH-12).
    Opening,
    /// The thousand working pages: records, their service pages, hand-offs
    /// between agents of one owner (CH-16), the rule of two seals (CH-19).
    Work,
    /// The hundred pages of sales and transfers between owners (CH-14, CH-15).
    Transfer,
    /// The two pages of the coupling of containers (CH-12).
    Coupling,
}

/// A party the journal knows by its keys: the agent, or the owner.
///
/// The keys are **pinned in the journal itself** — in page 0 and in every
/// transfer page — and every seal is checked against the pinned keys, never
/// against keys the presenter brings. The same lesson as the container's roster
/// (audit of 23.09, K1): a `kid` is a name, not a key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Party {
    /// Who: the party a key identifier `<party>#<fragment>` belongs to.
    pub id: Uri,
    /// Its public keys.
    pub keys: Vec<PublicKey>,
}

impl Party {
    /// Whether every key belongs to this party by its identifier, and there is
    /// at least one.
    #[must_use]
    pub fn is_consistent(&self) -> bool {
        !self.keys.is_empty() && self.keys.iter().all(|k| belongs(&k.kid, &self.id))
    }
}

/// Whether a key identifier belongs to a party: the identifier itself, or
/// `<party>#<fragment>`.
#[must_use]
pub fn belongs(kid: &Uri, party: &Uri) -> bool {
    let kid = kid.as_str();
    kid == party.as_str()
        || kid
            .split_once('#')
            .is_some_and(|(p, _fragment)| p == party.as_str())
}

/// The form the journal runs in (CH-21…CH-27).
///
/// | Form | Anchors | Internet | Owner signs |
/// |---|---|---|---|
/// | [`Mode::Local`] — light | none | not needed (CH-24) | a change of owner, a change of form (CH-29) |
/// | [`Mode::Pro`] | every seal (CH-7) | needed (CH-6) | also artefact, disposition, rights (CH-29) |
///
/// The form changes only by a page of its own ([`Body::Form`]) that the owner
/// seals (CH-26, CH-27): without the owner's seal the journal stays light,
/// nothing is anchored and nothing is charged. Back and forth as long as pages
/// last (CH-23).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Local, the light form (CH-21): no anchors, no internet.
    Local,
    /// Pro: every seal anchored; its pages have force (CH-25).
    Pro,
}

/// What a record of content is — what decides whose seals it needs.
///
/// The container's table of who signs what (container
/// architecture §6): work is the agent's; an artefact, a disposition, rights are the
/// agent's **and the owner's** — in Pro (CH-29). In the light form the owner
/// is not asked for them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordKind {
    /// A record of work (E-5).
    #[default]
    Work,
    /// The artefact, a disposition, or rights (E-6 · E-7 · E-8).
    ArtifactOrRights,
    /// Shares of the split key declared short of the threshold (CT-22).
    SharesDeclaredLost,
    /// A signed binding of a selective hash of the artefact (CT-44).
    HashBinding,
}

impl RecordKind {
    /// Whether the owner seals this kind of record in the given form (CH-29).
    #[must_use]
    pub const fn needs_owner(self, form: Mode) -> bool {
        matches!((self, form), (Self::ArtifactOrRights, Mode::Pro))
    }
}

/// Which record a page belongs to, and where in it (CH-8: "markers of
/// belonging to the batch").
///
/// Every page belongs to a record, a single-page record included. One record,
/// one seal: the seal's number is the last page of its record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchMark {
    /// The record's number; the opening is record 0.
    pub id: u64,
    /// The page's place in the record, from 0.
    pub index: u32,
    /// How many pages the record has, the service page included.
    pub of: u32,
}

/// What a page carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum Body {
    /// Page 0: the opening. Pins the first agent and owner and roots the chain
    /// in the container.
    Opening {
        /// The container the journal belongs to.
        container: Hash,
        /// The form the journal opens in; Pro only with the owner's seal.
        mode: Mode,
        /// The first agent.
        agent: Party,
        /// The first owner.
        owner: Party,
    },
    /// Content: a piece of a record.
    Content {
        /// What the record is.
        kind: RecordKind,
        /// The content, or its digest.
        content: Piece,
        /// What it is, as a URI (a licence, a policy, …).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        content_type: Option<Uri>,
    },
    /// The service page of a record of more than one page (CH-18). Always the
    /// last page of its record.
    Manifest(BatchManifest),
    /// A hand-off (work zone, CH-16) or a change of owner (transfer zone,
    /// CH-14). Carries a seal of its own that is never removed.
    Transfer(TransferRecord),
    /// A page of the coupling of containers (CH-12).
    Coupling(CouplingRecord),
    /// The rule of two seals, set or lifted (CH-19).
    Rule(SealRule),
    /// A change of form (CH-26, CH-27): always the owner's seal too. To Pro,
    /// the seal of this page is the first anchored one.
    Form {
        /// The form after this page.
        to: Mode,
    },
    /// The journal's confirmation of ten identical records (KS-8 F-6).
    RepeatConfirmation,
}

/// A page of the bound journal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundPage {
    /// Always [`crate::doc::CONTEXT`] (spec v2 §3.3).
    #[serde(rename = "@context")]
    pub context: crate::doc::Context,
    /// Always `"BoundPage"`.
    #[serde(rename = "type")]
    pub doc_type: String,
    /// The major core version.
    pub v: u32,
    /// The page's place in the one chain (CH-13). Page 0 is the opening.
    pub seq: u64,
    /// Its zone.
    pub zone: Zone,
    /// Its slot within the zone, from 1; 0 for the opening.
    pub slot: u64,
    /// Its record.
    pub batch: BatchMark,
    /// Milliseconds since the packet's origin. One for the whole record (CH-8).
    pub offset_ms: u64,
    /// What it carries.
    pub body: Body,
    /// The previous page's hash; for page 0, the container's identifier.
    pub prev: Hash,
}

impl Signable for BoundPage {
    const DOC_TYPE: &'static str = "BoundPage";
}

impl BoundPage {
    /// The value of `type`.
    pub const TYPE: &'static str = "BoundPage";

    /// The page's hash — what the next page links to and what the seal's tree
    /// is built over.
    ///
    /// # Errors
    ///
    /// [`crate::error::Invalid::Canonicalization`] if it does not canonicalize.
    pub fn hash(&self) -> Result<Hash, crate::error::Invalid> {
        doc_hash(self)
    }

    /// The bytes of inline content this page carries.
    #[must_use]
    pub fn inline_len(&self) -> usize {
        match &self.body {
            Body::Content { content, .. } => content.inline_len(),
            _ => 0,
        }
    }
}
