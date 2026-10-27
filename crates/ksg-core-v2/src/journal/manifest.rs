//! The service page of a record (CH-18).
//!
//! `[decision]` 30.09: "the last page may be a service one — it forms the batch
//! and is answerable for it being read and interpreted correctly". What it
//! holds is the proposal accepted the same day: identification, composition,
//! integrity, interpretation, time, basis, mode, the rule in force — and room
//! to grow.
//!
//! A record of one page has no service page: it would spend two pages on every
//! short record and halve what the journal holds.

use serde::{Deserialize, Serialize};

use crate::crypto::hash::Hash;
use crate::doc::Uri;

use super::page::{Mode, RecordKind};

/// The format of the service page this code writes.
pub const MANIFEST_FORMAT: u32 = 1;

/// How the pieces of a record are put back together.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Split {
    /// The inline bytes of the pages, in page order, concatenated.
    Concat,
}

/// An extension of the service page.
///
/// Room for fields a later format adds without breaking what reads this one:
/// a reader that does not know an extension skips it, unless the extension is
/// **critical** — then the reader refuses the record rather than misread it.
/// The journal's documents otherwise refuse unknown fields, and a new field
/// would make every old reader refuse every new record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Extension {
    /// What the extension is.
    pub id: Uri,
    /// Whether a reader that does not know it must refuse the record.
    pub critical: bool,
    /// Its value.
    pub value: serde_json::Value,
}

/// The service page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchManifest {
    /// Always [`crate::doc::CONTEXT`] (spec v2 §3.3).
    #[serde(rename = "@context")]
    pub context: crate::doc::Context,
    /// The format of this page: the rules it is to be read by.
    pub format: u32,
    /// The record's number (its batch mark).
    pub batch: u64,
    /// What the record is.
    pub kind: RecordKind,
    /// The first page of the record.
    pub first: u64,
    /// How many content pages the record has (1..=99).
    pub pages: u32,
    /// RFC 6962 root over the content pages' hashes: one page can be shown
    /// without the others.
    pub root: Hash,
    /// The hash of the whole record: the commitments of its pieces, in order.
    pub record: Hash,
    /// The inline bytes of the record, all pages together.
    pub length: u64,
    /// What the record is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<Uri>,
    /// Its media type, e.g. `application/json`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media: Option<String>,
    /// Its compression, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compression: Option<String>,
    /// Its character set, for text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub charset: Option<String>,
    /// How the pages are put back together.
    pub split: Split,
    /// The record's one time mark (CH-8).
    pub offset_ms: u64,
    /// Who wrote it: the agent.
    pub author: Uri,
    /// The instruction the record answers, if any (`[decision]` 04.09).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order: Option<Hash>,
    /// The form the record was written in (CH-21).
    pub mode: Mode,
    /// The previous seal, whose anchor the record follows (CH-7).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_seal: Option<Hash>,
    /// The rule of two seals in force, if one is (CH-19).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<Hash>,
    /// Extensions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ext: Vec<Extension>,
}

/// What the writer says about a record — everything on the service page that
/// is not derived from the pages themselves.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecordMeta {
    /// What kind of record: work, or an artefact, a disposition, rights.
    pub kind: RecordKind,
    /// What the record is.
    pub content_type: Option<Uri>,
    /// Its media type.
    pub media: Option<String>,
    /// Its compression.
    pub compression: Option<String>,
    /// Its character set.
    pub charset: Option<String>,
    /// The instruction it answers.
    pub order: Option<Hash>,
    /// Extensions.
    pub ext: Vec<Extension>,
}
