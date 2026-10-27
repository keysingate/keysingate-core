//! The status section — where a status change is written. KS-7 §7.3.
//!
//! > Every change **MUST** be written **to the status section** with an anchor
//! > and be part of the export.
//!
//! [`crate::status`] holds the machine: which event moves which status where.
//! This is the place those moves are kept, and the two are separate on purpose —
//! a transition table that also stored records would be a table nobody could
//! reason about without a container in hand.
//!
//! # Not the journal, and the difference is not cosmetic
//!
//! KS-8 F-5 corrected an earlier formulation outright: **the journal is what the
//! client writes**, and a status change is an **operation**. They also differ in
//! who may look:
//!
//! | | the journal | the status section |
//! |---|---|---|
//! | written by | the client | the operation, with signatures |
//! | may be read | **no** — appended, signed, exported, nothing else | **yes** — a buyer must see the state of the rights (§7.2-octies) |
//!
//! So this type offers [`StatusSection::current`] and [`StatusSection::records`]
//! where [`ksg_journal::Journal`](../../ksg_journal/struct.Journal.html) offers
//! neither. That asymmetry is the specification's, not an oversight in one of
//! them.
//!
//! `?` **Open (KS-7 §7.3-bis):** whether outside parties read the status *here*
//! or take it *from the chain*, where every change is anchored anyway. This type
//! has to hold it either way; who may call `current` is a question for the layer
//! above.
//!
//! # Rooted in the address, because identity comes later
//!
//! The section starts at status 0, when the release is printed — and at 0 there
//! is no container and no personal identifier, only a **position**: an emission
//! and a serial. So record 0 links to the hash of those two.
//!
//! This is the same rule as the journal's page 0 linking to the container's
//! identifier, applied to a moment when that identifier does not exist yet. The
//! container's own identifier enters the section later, in the record that
//! carries the move to status 4.

use serde::{Deserialize, Serialize};

use crate::anchor::Attestation;
use crate::canonical::{check_envelope, doc_hash, Signable};
use crate::crypto::hash::Hash;
use crate::crypto::sign::{KeySet, Profile, SignatureSet};
use crate::doc::{Class, Serial};
use crate::error::Invalid;
use crate::status::{transition_for, Blocked, Event, Outcome, Status, StatusHistory};

/// Separates the section's root from every other hash in the protocol.
const DOMAIN: &[u8] = b"ksg:status-section:v1";

/// What the section is rooted in before a container exists: the **address**.
///
/// Deliberately not the container's identifier, which is not there yet. A serial
/// is a position in a release and is known before the container is; the identity
/// arrives at initiation (KS-8 C-3).
#[must_use]
pub fn section_root(emission: &str, serial: Serial) -> Hash {
    Hash::sha256_fields(&[DOMAIN, emission.as_bytes(), &serial.0.to_be_bytes()])
}

/// One change of status, written down.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusRecord {
    /// Always [`crate::doc::CONTEXT`] (spec v2 §3.3).
    #[serde(rename = "@context")]
    pub context: crate::doc::Context,
    /// Always `"StatusRecord"`.
    #[serde(rename = "type")]
    pub doc_type: String,
    /// The major core version.
    pub v: u32,
    /// The counter. Record 0 is the printing; every change adds one.
    pub number: u64,
    /// The status **after** the change.
    pub status: Status,
    /// The event that caused it. Kept because a status alone does not say why
    /// it is that status, and "why" is what a buyer reads it for.
    ///
    /// **Omitted, not null**, on record 0, which no event caused: an absent
    /// field and `null` are different documents (spec v2 §3), and the record's
    /// signature must not depend on how an implementation depicts absence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event: Option<Event>,
    /// Milliseconds since the packet's origin (KS-2).
    pub offset_ms: u64,
    /// The previous record's hash; for record 0, the section root.
    pub prev: Hash,
    /// The signatures the operation required.
    pub signatures: SignatureSet,
}

impl Signable for StatusRecord {
    const DOC_TYPE: &'static str = "StatusRecord";
}

impl StatusRecord {
    /// This record's hash — what the next record links to.
    ///
    /// # Errors
    ///
    /// [`Invalid::Canonicalization`] if it does not canonicalize.
    pub fn hash(&self) -> Result<Hash, Invalid> {
        doc_hash(self)
    }
}

/// The status section of one container.
///
/// Like the journal, it is append-only and can only be started, never assembled:
/// there is no `Default` and no way to build one from records. Unlike the
/// journal it may be read, because that is what it is for.
#[derive(Debug)]
pub struct StatusSection {
    emission: String,
    serial: Serial,
    root: Hash,
    records: Vec<(StatusRecord, Attestation)>,
    history: StatusHistory,
    head: Hash,
}

impl StatusSection {
    /// Starts the section with record 0: the release was printed.
    ///
    /// # Errors
    ///
    /// [`Invalid::Schema`] if the record is not numbered 0, does not carry
    /// status 0, carries an event, or does not link to the section root;
    /// [`Invalid::MissingInitiation`] is not used here — an unanchored record is
    /// [`Invalid::Schema`] with its own message, since §7.3 makes the anchor
    /// part of what a status change **is**.
    pub fn start(
        emission: &str,
        serial: Serial,
        record: StatusRecord,
        anchor: Attestation,
        keys: &KeySet,
        profile: &Profile,
    ) -> Result<Self, Invalid> {
        let root = section_root(emission, serial);
        if record.number != 0 || record.status != Status::Printed {
            return Err(Invalid::Schema(
                "the status section starts at record 0 with status 0",
            ));
        }
        if record.prev != root {
            return Err(Invalid::Schema(
                "record 0 does not link to the section root",
            ));
        }
        // No event caused record 0 (spec v2 §11, draft-nam-ksg-core §Status
        // Records): a record 0 carrying one is another document, with another
        // hash — two implementations would start two different sections.
        if record.event.is_some() {
            return Err(Invalid::Schema("record 0 carries no event"));
        }
        check_record(&record, &anchor, keys, profile)?;
        let head = record.hash()?;
        Ok(Self {
            emission: emission.to_owned(),
            serial,
            root,
            records: vec![(record, anchor)],
            history: StatusHistory::new(),
            head,
        })
    }

    /// The head of the chain — what the next record must link to.
    ///
    /// Public because a caller builds the next record **before** presenting it
    /// and cannot link it without this. It discloses nothing: the section's
    /// records are anchored and public by construction.
    #[must_use]
    pub const fn head(&self) -> Hash {
        self.head
    }

    /// Applies an event and writes the change down.
    ///
    /// The Pro default: exactly [`StatusSection::apply_for`] with
    /// [`Class::Heavy`], because [`transition_for`] with `Heavy` is
    /// [`transition`](crate::status::transition) unchanged. (Goal 1 debt, step G1-2b: one body, not two
    /// copies of it — the same shape as [`StatusHistory::apply`].)
    ///
    /// The machine decides **whether** the move is allowed; this decides whether
    /// it was recorded properly. Both have to pass, and in that order: a record
    /// of a move that may not happen should not exist even as a rejected one.
    ///
    /// An [`Outcome::Stays`] writes **nothing**. A status that does not change
    /// is not a change, and recording it would inflate the section with pages
    /// that say "still 5" — and, worse, would let a counter of status records
    /// stand in for a count of the work, which KS-8 I-5 keeps from the issuer
    /// precisely.
    ///
    /// # Errors
    ///
    /// [`Invalid::StatusRefused`] if the machine refuses; [`Invalid::Schema`] on
    /// a record out of order, off the chain, or unanchored.
    pub fn apply(
        &mut self,
        event: Event,
        record: Option<StatusRecord>,
        anchor: Option<Attestation>,
        keys: &KeySet,
        profile: &Profile,
    ) -> Result<Outcome, Invalid> {
        self.apply_for(Class::Heavy, event, record, anchor, keys, profile)
    }

    /// Applies an event for a container of the class given and writes the
    /// change down. Goal 1, `bare` v2 (owner's decision 08.10): the
    /// class-aware twin of [`StatusSection::apply`]; [`StatusSection::apply`]
    /// itself stays as the Pro default so the section-replay tests keep
    /// reading the Pro table.
    ///
    /// A `bare` section saved and loaded back replays through this same
    /// route (`ksg-container-v2`, `Container::from_state`), which is what
    /// keeps the two reads from disagreeing.
    ///
    /// # Errors
    ///
    /// [`Invalid::StatusRefused`] if the machine refuses; [`Invalid::Schema`] on
    /// a record out of order, off the chain, or unanchored.
    pub fn apply_for(
        &mut self,
        class: Class,
        event: Event,
        record: Option<StatusRecord>,
        anchor: Option<Attestation>,
        keys: &KeySet,
        profile: &Profile,
    ) -> Result<Outcome, Invalid> {
        // **Checked before anything moves.** The earlier version applied the
        // transition first and validated the record afterwards, so a bad record
        // left the status moved with nothing written down — the section then
        // said one thing and its records another. Nothing here mutates until
        // every check has passed.
        let outcome = transition_for(class, self.current(), self.blocked(), event);
        if let Outcome::Refused(why) = outcome {
            return Err(Invalid::StatusRefused(why));
        }
        let moved = matches!(outcome, Outcome::Moves(_));
        if !moved {
            // Nothing changed, so nothing is written — and presenting a record
            // for a non-change is refused rather than ignored, so that a caller
            // building one learns it was pointless.
            return if record.is_some() || anchor.is_some() {
                Err(Invalid::Schema("nothing changed, so nothing is recorded"))
            } else {
                Ok(outcome)
            };
        }

        let (Some(record), Some(anchor)) = (record, anchor) else {
            return Err(Invalid::Schema(
                "a status change MUST be recorded with an anchor",
            ));
        };
        let Outcome::Moves(next) = outcome else {
            return Err(Invalid::Schema("a non-move cannot be recorded"));
        };
        if record.number != self.counter() + 1 {
            return Err(Invalid::Schema("the status record is out of order"));
        }
        if record.prev != self.head {
            return Err(Invalid::Schema(
                "the status record does not link to the one before it",
            ));
        }
        if record.status != next {
            return Err(Invalid::Schema(
                "the status record carries a different status than the move",
            ));
        }
        if record.event != Some(event) {
            return Err(Invalid::Schema("the status record names a different event"));
        }
        check_record(&record, &anchor, keys, profile)?;
        let head = record.hash()?;

        // Only now, with nothing left that can fail.
        let applied = self.history.apply_for(class, event)?;
        debug_assert_eq!(applied, outcome, "the table answered twice differently");
        self.head = head;
        self.records.push((record, anchor));
        Ok(outcome)
    }

    /// Replaces the anchor of the **last** record with another anchor of the
    /// same record — see `Binder::reanchor_top` for why (audit of 30.09, O-1).
    /// Only the last record: the anchors of the history stay as they were.
    ///
    /// # Errors
    ///
    /// [`Invalid::Schema`] for an anchor of another record.
    pub fn reanchor_last(&mut self, anchor: Attestation) -> Result<(), Invalid> {
        let (record, current) = self
            .records
            .last_mut()
            .ok_or(Invalid::Schema("the status section is empty"))?;
        anchor.covers(&record.hash()?)?;
        *current = anchor;
        Ok(())
    }

    /// The current status — the last layer.
    ///
    /// This is the read §7.3-bis turns on: the issuer reads it as it signs and
    /// the owner reads it as it signs, and on a mismatch neither signs.
    #[must_use]
    pub fn current(&self) -> Status {
        self.history.current()
    }

    /// Whether the container is blocked.
    #[must_use]
    pub const fn blocked(&self) -> Blocked {
        self.history.blocked()
    }

    /// Whether this status was ever set (§7.2-quater).
    #[must_use]
    pub fn ever(&self, status: Status) -> bool {
        self.history.ever(status)
    }

    /// The number of the last record.
    #[must_use]
    pub fn counter(&self) -> u64 {
        // A section is built with record 0 and never shrinks.
        self.records.last().map_or(0, |(r, _)| r.number)
    }

    /// When each status change happened **no later than**, by its anchor read
    /// under spec v2 §7.2 — oldest first, `None` where the anchor was not read.
    ///
    /// Core v1 only checked that a status record's anchor named the record
    /// (audit of 30.09, Ya-2): the anchor stood, nobody read it, and a status
    /// had no proved time. Here the same one procedure reads it as reads a
    /// seal of the journal.
    ///
    /// # Errors
    ///
    /// Whatever [`crate::anchor::upper_bound`] refuses: an anchor of another
    /// record, or one the reader handles and cannot confirm.
    pub fn times(
        &self,
        profile: &crate::crypto::sign::Profile,
        reader: Option<&dyn crate::anchor::AttestationVerifier>,
    ) -> Result<Vec<Option<crate::doc::Timestamp>>, Invalid> {
        self.records
            .iter()
            .map(|(r, a)| {
                crate::anchor::upper_bound(core::slice::from_ref(a), &r.hash()?, profile, reader)
            })
            .collect()
    }

    /// Every record with its anchor, oldest first — §7.3's "part of the export".
    ///
    /// Readable, unlike the journal's pages, and for the reason §7.2-octies
    /// gives: a buyer takes the container with whatever state of rights is
    /// written in it and **sees** that state.
    #[must_use]
    pub fn records(&self) -> &[(StatusRecord, Attestation)] {
        &self.records
    }

    /// What the section is rooted in.
    #[must_use]
    pub const fn root(&self) -> &Hash {
        &self.root
    }

    /// The whole section, for a third party: every record with its anchor
    /// and the address it is rooted in (spec v2 §11, §12).
    #[must_use]
    pub fn export(&self) -> StatusExport {
        StatusExport {
            context: crate::doc::Context,
            doc_type: StatusExport::TYPE.to_owned(),
            emission: self.emission.clone(),
            serial: self.serial,
            records: self.records.clone(),
        }
    }
}

/// The status section as it leaves the container (spec v2 §11, §12).
///
/// Not signed as a whole: every record in it is signed and anchored, and the
/// chain from the section root fixes their order — a whole-document signature
/// would add a party, not a check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusExport {
    /// Always [`crate::doc::CONTEXT`] (spec v2 §3.3).
    #[serde(rename = "@context")]
    pub context: crate::doc::Context,
    /// Always [`StatusExport::TYPE`].
    #[serde(rename = "type")]
    pub doc_type: String,
    /// The release the serial belongs to.
    pub emission: String,
    /// The serial: with the release, the address the section is rooted in.
    pub serial: Serial,
    /// Every record with its anchor, oldest first.
    pub records: Vec<(StatusRecord, Attestation)>,
}

impl StatusExport {
    /// The value of `type`.
    pub const TYPE: &'static str = "StatusSectionExport";
}

/// What a checked status section establishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusReport {
    /// The current status: the last layer.
    pub current: Status,
    /// Whether the container is blocked.
    pub blocked: Blocked,
    /// Every status ever set, oldest first.
    pub layers: Vec<Status>,
    /// The bound of each record's anchor under §7.2, oldest first; `None`
    /// where no reader confirmed it.
    pub times: Vec<Option<crate::doc::Timestamp>>,
}

/// Checks an exported status section the way the container admitted it:
/// record 0 from the address, every next record through the transition table,
/// linked, signed and anchored — and reads every anchor under the one rule of
/// the time bound (spec v2 §7.2).
///
/// # Errors
///
/// [`Invalid::Limit`] past [`crate::limits::MAX_STATUS_RECORDS`];
/// [`Invalid::Schema`] for another `type`, an empty section, or a record past
/// 0 without its event; whatever [`StatusSection::start`],
/// [`StatusSection::apply`] or [`StatusSection::times`] refuse.
pub fn verify_status_export(
    x: &StatusExport,
    keys: &KeySet,
    profile: &Profile,
    reader: Option<&dyn crate::anchor::AttestationVerifier>,
) -> Result<StatusReport, Invalid> {
    crate::limits::at_most(
        x.records.len(),
        crate::limits::MAX_STATUS_RECORDS,
        "status records",
    )?;
    if x.doc_type != StatusExport::TYPE {
        return Err(Invalid::Schema("not a status section export"));
    }
    let mut records = x.records.iter();
    let (first, first_anchor) = records
        .next()
        .ok_or(Invalid::Schema("the status section is empty"))?;
    let mut s = StatusSection::start(
        &x.emission,
        x.serial,
        first.clone(),
        first_anchor.clone(),
        keys,
        profile,
    )?;
    for (record, anchor) in records {
        let event = record
            .event
            .ok_or(Invalid::Schema("a status record past 0 without its event"))?;
        s.apply(
            event,
            Some(record.clone()),
            Some(anchor.clone()),
            keys,
            profile,
        )?;
    }
    Ok(StatusReport {
        current: s.current(),
        blocked: s.blocked(),
        layers: s.history.layers().to_vec(),
        times: s.times(profile, reader)?,
    })
}

/// A status change is a record **and** an anchor; §7.3 makes the anchor part of
/// what the change is, not an attachment to it.
fn check_record(
    record: &StatusRecord,
    anchor: &Attestation,
    keys: &KeySet,
    profile: &Profile,
) -> Result<(), Invalid> {
    anchor.covers(&record.hash()?)?;
    check_envelope(
        record,
        record.v,
        &record.doc_type,
        &record.signatures,
        keys,
        profile,
    )
}
