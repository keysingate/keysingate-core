//! # The bound journal — pages under a movable seal
//!
//! The owner's mechanism of 30.09 (Plan_MVP §9, CH-1…CH-20), in place of a
//! signature on every page:
//!
//! * a page is room for content, **2 KB**, and carries no signature (CH-1);
//! * one **movable seal** covers every page before it through the chain and a
//!   tree; each record lifts it and puts it on again, number + 1 (CH-2);
//! * the layout is **1+1000+100+2**: the opening, a thousand working pages, a
//!   hundred pages of sales and transfers between owners, two of the coupling
//!   (CH-12, CH-15); one chain through all of them (CH-13);
//! * a record is up to 99 pages and a service page, 200 KB, with one time mark
//!   and one seal (CH-8, CH-18);
//! * a hand-off between agents of one owner is sealed agent/agent on a working
//!   page (CH-16); a sale or a transfer between owners — agent+owner /
//!   agent+owner on a page of its own zone (CH-14, CH-15); the new agent
//!   **replaces** the old one (CH-17); those seals are never removed (CH-3);
//! * the rule of two seals is a page of its own; setting and lifting it take
//!   the owner (CH-19); a record it covers **waits** for the owner's seal, and
//!   nothing else is written meanwhile (CH-20);
//! * two forms: light (Local) — no anchors, no internet; Pro — every seal
//!   anchored. The form changes only by a page the owner seals — to Pro and
//!   back, as long as pages last; without the owner the journal stays light
//!   and nothing is anchored (CH-21…CH-27). In Pro an artefact, a disposition,
//!   rights also take the owner's seal (CH-29);
//! * what is anchored has force; records anchored one after another with no
//!   gap confirm their links (CH-25);
//! * the movable seal is signed Ed25519 (CH-5, as clarified `[decision]` 02.10,
//!   CH-5a): the post-quantum signature is on the whole container, outside —
//!   not on each seal inside it.
//!
//! As with the working journal of `ksg-journal`, nothing here reads the pages back: what leaves
//! is an export — one page with its proof, or everything, once.

pub mod chain;
pub mod manifest;
pub mod page;
pub mod seal;
pub mod verify;

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::canonical::canonical_bytes;
use crate::crypto::hash::Hash;
use crate::crypto::sign::{KeySet, Profile, SignatureSet};

use crate::anchor::Attestation as EntryAnchor;
use chain::{record_hash, Chain, TransferParties};
pub use manifest::{BatchManifest, Extension, RecordMeta, Split, MANIFEST_FORMAT};
pub use page::{belongs, BatchMark, Body, BoundPage, Mode, Party, Piece, RecordKind, Zone};
pub use seal::{
    CoSeal, Counts, CouplingRecord, RuleScope, Seal, SealRule, TransferKind, TransferRecord,
    TransferSeal,
};
pub use verify::{
    verify_bound, verify_bound_point, verify_bound_read, BoundPoint, BoundReport, RecordBound,
    RecordReport,
};

/// The journal's own format version: what `v` its pages and seals carry.
///
/// Audit of 30.09, Ya-6: the journal took the core's version, so a new major
/// version of the core would have renamed every page and seal although their
/// format had not changed. Equal to the core's today (3); the two move
/// independently from here on, and a page of another format is refused.
pub const FORMAT_V: u32 = 3;

/// Checks a journal document's `v` against [`FORMAT_V`].
///
/// # Errors
///
/// [`BinderError::Misplaced`] for any other version.
pub fn check_format(v: u32) -> Result<(), BinderError> {
    if v == FORMAT_V {
        Ok(())
    } else {
        Err(BinderError::Misplaced("journal format version"))
    }
}

/// Identical records in a row before the journal writes its confirmation
/// (KS-8 F-6).
pub const REPEAT_LIMIT: usize = 10;
/// Pointwise exports a journal allows (`[decision]` 19.09).
pub const POINT_LIMIT: u64 = 12;
/// Pointwise exports a `bare` journal allows (`[decision]` 11.10): 48 exports
/// of up to [`PAGES_PER_EXPORT`] pages cover the 1 000 working pages.
pub const BARE_POINT_LIMIT: u64 = 48;
/// Pages one pointwise export may carry (`[decision]` 06.10): up to 24 pages
/// go out at once, and the export counts once against [`POINT_LIMIT`].
pub const PAGES_PER_EXPORT: usize = 24;

/// Working pages (CH-12).
pub const WORK_PAGES: u64 = 1000;
/// Pages of sales and transfers between owners (CH-15).
pub const TRANSFER_PAGES: u64 = 100;
/// Pages of the coupling (CH-12).
pub const COUPLING_PAGES: u64 = 2;
/// Every page: the opening and the three zones — 1103.
pub const TOTAL_PAGES: u64 = 1 + WORK_PAGES + TRANSFER_PAGES + COUPLING_PAGES;
/// The content room of a page, in bytes (CH-1: "at least 2 KB").
pub const PAGE_BYTES: usize = 2048;
/// Pages of one record, the service page included (CH-8).
pub const BATCH_PAGES: usize = 100;
/// Content pages of one record (CH-8).
pub const BATCH_CONTENT_PAGES: usize = 99;
/// Bytes of one record (CH-8: "max 200 KB").
pub const BATCH_BYTES: usize = 200 * 1024;

// CH-8 holds by the page count alone: 99 content pages of at most 2 KB are
// 198 KB, under the 200 KB of a record — so `RecordTooLarge` never fires
// today. If a page grows past that, the build stops here, before a record
// could outgrow the limit unseen (owner's decision 16.10 "A").
const _: () = assert!(BATCH_CONTENT_PAGES * PAGE_BYTES <= BATCH_BYTES);

/// What can go wrong with a bound journal.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BinderError {
    /// A page is not where it may stand.
    #[error("misplaced: {0}")]
    Misplaced(&'static str),
    /// The chain is broken at this page.
    #[error("the chain is broken at page {0}")]
    BrokenChain(u64),
    /// A page came out of order.
    #[error("page {got} where {expected} was expected")]
    OutOfOrder {
        /// The page's number.
        got: u64,
        /// The number expected.
        expected: u64,
    },
    /// A page's record mark does not fit its record.
    #[error("the record mark of page {0} does not fit its record")]
    BatchMark(u64),
    /// A page's time mark differs from its record's.
    #[error("page {0}: a record has one time mark")]
    OneTimeMark(u64),
    /// A page's zone or slot is not the one it takes.
    #[error("page {0} is not in its zone and slot")]
    WrongPlace(u64),
    /// The time mark did not grow.
    #[error("the time mark {got} does not follow {last}")]
    OffsetNotGrowing {
        /// The record's mark.
        got: u64,
        /// The last one.
        last: u64,
    },
    /// A zone is full.
    #[error("the {0:?} zone is full")]
    Full(Zone),
    /// This coupling slot is written.
    #[error("coupling slot {0} is already written")]
    CouplingUsed(u64),
    /// A record of more pages than a record holds.
    #[error("a record of {0} pages: at most 99 and the service page")]
    RecordTooLong(usize),
    /// A page over its content room.
    #[error("page {0} is over 2 KB of content")]
    PageTooLarge(u64),
    /// A record over 200 KB.
    #[error("a record of {0} bytes: at most 200 KB")]
    RecordTooLarge(usize),
    /// The service page does not describe its record.
    #[error("the service page: {0}")]
    Manifest(&'static str),
    /// A transfer that is not one.
    #[error("transfer: {0}")]
    Transfer(&'static str),
    /// A party without keys, or with keys of another party.
    #[error("a party's keys are missing or are not its own")]
    Parties,
    /// A rule that covers no type.
    #[error("a rule of types names no type; lifting is its own scope")]
    EmptyRule,
    /// Ten identical records stand unconfirmed.
    #[error("ten identical records: the confirmation is owed first")]
    ConfirmationOwed,
    /// A confirmation nobody owes.
    #[error("no confirmation is owed")]
    NoConfirmationOwed,
    /// An anchor made for a record the owner has not sealed yet (CH-26).
    #[error("anchored before the owner's seal: nothing is anchored until the owner confirms")]
    AnchoredBeforeOwner,
    /// A change of form to the form already in force.
    #[error("the journal is already in the {0:?} form")]
    FormUnchanged(Mode),
    /// An anchor in the light form: nothing is anchored there until the owner
    /// confirms the move to Pro (CH-22, CH-26).
    #[error("the light form takes no anchor: the move to Pro comes first, with the owner's seal")]
    AnchorInLocal,
    /// A Pro seal without its anchor (CH-6, CH-7).
    #[error("a Pro seal is anchored or refused")]
    NoAnchor,
    /// The anchor is of something else.
    #[error("the anchor attests another seal")]
    WrongAnchor,
    /// A seal's signatures do not hold.
    #[error("seal: {0}")]
    Signature(&'static str),
    /// A record is waiting for the owner's seal; nothing else is written.
    #[error("a record waits for the owner's seal")]
    Waiting,
    /// Nothing is waiting.
    #[error("nothing waits for the owner's seal")]
    NothingWaiting,
    /// A draft made before the journal moved on.
    #[error("the draft is stale: the journal moved on")]
    Stale,
    /// The export does not hold together.
    #[error("export: {0}")]
    Export(&'static str),
    /// The page does not exist.
    #[error("no page {0}")]
    NoSuchPage(u64),
    /// The pointwise limit is spent.
    #[error("the pointwise limit of {0} is spent")]
    PointLimit(u64),
    /// A pointwise export names no page, more than [`PAGES_PER_EXPORT`]
    /// pages, or one page twice.
    #[error("a pointwise export takes 1 to 24 distinct pages, not {0}")]
    PageCount(usize),
    /// Canonicalization failed.
    #[error("canonicalization failed")]
    Canonicalization,
}

/// A record prepared for sealing: its pages and the seal that goes on it.
///
/// Signatures are made outside — the agent's client key is split and signs in
/// rounds — over [`Draft::seal_bytes`], [`Draft::transfer_bytes`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Draft {
    pages: Vec<BoundPage>,
    seal: Seal,
    needs_owner: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transfer: Option<TransferSeal>,
}

impl Draft {
    /// The seal this record will carry, before anyone signs it.
    #[must_use]
    pub const fn seal(&self) -> &Seal {
        &self.seal
    }

    /// The bytes the agent signs — and the owner, where the rule asks.
    ///
    /// # Errors
    ///
    /// [`BinderError::Canonicalization`].
    pub fn seal_bytes(&self) -> Result<Vec<u8>, BinderError> {
        canonical_bytes(&self.seal).map_err(|_| BinderError::Canonicalization)
    }

    /// The seal's hash — what an anchor must attest.
    ///
    /// # Errors
    ///
    /// [`BinderError::Canonicalization`].
    pub fn seal_hash(&self) -> Result<Hash, BinderError> {
        self.seal.hash().map_err(|_| BinderError::Canonicalization)
    }

    /// The bytes every party of a transfer signs, if this is one.
    ///
    /// # Errors
    ///
    /// [`BinderError::Canonicalization`].
    pub fn transfer_bytes(&self) -> Result<Option<Vec<u8>>, BinderError> {
        self.transfer
            .as_ref()
            .map(|t| canonical_bytes(t).map_err(|_| BinderError::Canonicalization))
            .transpose()
    }

    /// Whether the rule of two seals asks for the owner's seal.
    #[must_use]
    pub const fn needs_owner(&self) -> bool {
        self.needs_owner
    }

    /// Whether the seal goes on in Pro, and so needs an anchor.
    #[must_use]
    pub fn is_pro(&self) -> bool {
        self.seal.mode == Mode::Pro
    }

    /// The pages of the record, for the container to see what the record is
    /// before it lets it in. The pages are the caller's own draft.
    #[must_use]
    pub fn pages(&self) -> &[BoundPage] {
        &self.pages
    }

    /// The number the seal will bear.
    #[must_use]
    pub const fn number(&self) -> u64 {
        self.seal.number
    }
}

/// The signatures and the anchor that come back for a draft.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sealing {
    /// The agent's signatures over the seal: Ed25519 and ML-DSA-65.
    pub seal: SignatureSet,
    /// Every party's signatures over the transfer seal, for a transfer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transfer: Option<SignatureSet>,
    /// The owner's signatures over the seal, where the rule asks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<SignatureSet>,
    /// The anchor of the seal — required in Pro.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<EntryAnchor>,
}

/// What became of a sealing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The record is in the journal under a seal of this number.
    Written(u64),
    /// The record waits for the owner's seal (CH-20): nothing else is written
    /// until it comes or the record is withdrawn.
    Waiting,
}

/// The anchor of one movable seal, kept for as long as the journal lives:
/// the seal is lifted, but what it fixed stays fixed (CH-25).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealAnchor {
    /// The record whose seal was anchored.
    pub batch: u64,
    /// The anchor.
    pub anchor: EntryAnchor,
}

/// A record waiting for the owner's seal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    draft: Draft,
    sealing: Sealing,
}

/// The bound journal of one container.
///
/// Like the working journal of `ksg-journal` it is not `Clone` and offers no way to read a page
/// back: one journal per container, and pages leave only by export.
#[derive(Debug)]
pub struct Binder {
    chain: Chain,
    pages: Vec<BoundPage>,
    seal: Seal,
    anchors: Vec<SealAnchor>,
    transfers: Vec<TransferSeal>,
    coseals: Vec<CoSeal>,
    pending: Option<Pending>,
    disclosed: u64,
    point_limit: u64,
}

fn keyset(parties: &[&Party]) -> KeySet {
    let mut ks = KeySet::new();
    for p in parties {
        for k in &p.keys {
            ks.insert(k.clone());
        }
    }
    ks
}

/// Checks that `sigs` verify over `msg` under these parties' keys only, and
/// that each party signed.
fn check_parties(
    sigs: &SignatureSet,
    msg: &[u8],
    parties: &[&Party],
    profile: &Profile,
    what: &'static str,
) -> Result<(), BinderError> {
    if sigs.is_empty() {
        return Err(BinderError::Signature(what));
    }
    sigs.verify(msg, &keyset(parties), profile)
        .map_err(|_| BinderError::Signature(what))?;
    for p in parties {
        if !sigs.as_slice().iter().any(|s| belongs(&s.kid, &p.id)) {
            return Err(BinderError::Signature(what));
        }
    }
    Ok(())
}

/// Checks the agent's signatures on a movable seal.
pub(crate) fn check_seal(seal: &Seal, agent: &Party, profile: &Profile) -> Result<(), BinderError> {
    // The signature covers `v`, so it cannot be altered — but a seal written
    // under another format would verify and be read under this one's rules.
    check_format(seal.v)?;
    if seal.agent != agent.id {
        return Err(BinderError::Signature("the seal names another agent"));
    }
    let msg = canonical_bytes(seal).map_err(|_| BinderError::Canonicalization)?;
    check_parties(
        &seal.signatures,
        &msg,
        &[agent],
        &profile.with_ed25519(),
        "the agent's seal",
    )
}

/// Checks a transfer seal against the parties who must have signed it.
pub(crate) fn check_transfer_seal(
    t: &TransferSeal,
    parties: &TransferParties,
    profile: &Profile,
) -> Result<(), BinderError> {
    check_format(t.v)?;
    if t.doc_type != TransferSeal::TYPE || t.page != parties.page || t.subject != parties.subject {
        return Err(BinderError::Signature(
            "the transfer seal is of another page",
        ));
    }
    let msg = canonical_bytes(t).map_err(|_| BinderError::Canonicalization)?;
    let who: Vec<&Party> = parties.parties.iter().collect();
    check_parties(
        &t.signatures,
        &msg,
        &who,
        &profile.with_ed25519(),
        "the transfer seal",
    )
}

/// Checks the owner's second seal over a movable seal.
pub(crate) fn check_coseal(
    c: &CoSeal,
    seal: &Seal,
    owner: &Party,
    profile: &Profile,
) -> Result<(), BinderError> {
    check_format(c.v)?;
    let subject = seal.hash().map_err(|_| BinderError::Canonicalization)?;
    if c.doc_type != CoSeal::TYPE || c.batch != seal.batch || c.subject != subject {
        return Err(BinderError::Signature(
            "the owner's seal is of another record",
        ));
    }
    let msg = canonical_bytes(seal).map_err(|_| BinderError::Canonicalization)?;
    check_parties(
        &c.signatures,
        &msg,
        &[owner],
        &profile.with_ed25519(),
        "the owner's seal",
    )
}

/// Checks a seal's anchor against the form: Pro — anchored, and by an anchor
/// of this seal (CH-7); light — no anchor at all (CH-22, CH-26).
pub(crate) fn check_anchor(seal: &Seal, anchor: Option<&EntryAnchor>) -> Result<(), BinderError> {
    match (seal.mode, anchor) {
        (Mode::Pro, None) => Err(BinderError::NoAnchor),
        (Mode::Pro, Some(a)) => {
            let h = seal.hash().map_err(|_| BinderError::Canonicalization)?;
            a.covers(&h).map_err(|_| BinderError::WrongAnchor)
        }
        (Mode::Local, Some(_)) => Err(BinderError::AnchorInLocal),
        (Mode::Local, None) => Ok(()),
    }
}

impl Binder {
    /// Opens the journal: page 0 pins the first agent and owner, and the first
    /// seal goes on it. Opening in Pro takes the owner's seal and the anchor
    /// (CH-26); a light journal opens with the agent's seal alone.
    ///
    /// # Errors
    ///
    /// Whatever page 0 or its seals fail.
    pub fn open(
        container: Hash,
        mode: Mode,
        agent: Party,
        owner: Party,
        offset_ms: u64,
        sealing: &Sealing,
        profile: &Profile,
    ) -> Result<Self, BinderError> {
        let page = Self::opening_page(container, mode, agent, owner, offset_ms);
        let (chain, bare) = Chain::open(&page)?;
        let mut seal = bare.clone();
        seal.signatures = sealing.seal.clone();
        check_seal(&seal, &chain.agent, profile)?;
        check_anchor(&seal, sealing.anchor.as_ref())?;
        let mut coseals = Vec::new();
        if mode == Mode::Pro {
            let sigs = sealing
                .owner
                .clone()
                .ok_or(BinderError::Signature("Pro opens with the owner's seal"))?;
            let c = CoSeal {
                context: crate::doc::Context,
                doc_type: CoSeal::TYPE.to_owned(),
                v: FORMAT_V,
                batch: 0,
                subject: bare.hash().map_err(|_| BinderError::Canonicalization)?,
                signatures: sigs,
            };
            check_coseal(&c, &bare, &chain.owner, profile)?;
            coseals.push(c);
        }
        Ok(Self {
            chain,
            pages: vec![page],
            seal,
            anchors: sealing
                .anchor
                .clone()
                .map(|anchor| SealAnchor { batch: 0, anchor })
                .into_iter()
                .collect(),
            transfers: Vec::new(),
            coseals,
            pending: None,
            disclosed: 0,
            point_limit: POINT_LIMIT,
        })
    }

    /// Page 0, for the first seal to be signed over before [`Binder::open`].
    #[must_use]
    pub fn opening_page(
        container: Hash,
        mode: Mode,
        agent: Party,
        owner: Party,
        offset_ms: u64,
    ) -> BoundPage {
        BoundPage {
            context: crate::doc::Context,
            doc_type: BoundPage::TYPE.to_owned(),
            v: FORMAT_V,
            seq: 0,
            zone: Zone::Opening,
            slot: 0,
            batch: BatchMark {
                id: 0,
                index: 0,
                of: 1,
            },
            offset_ms,
            body: Body::Opening {
                container,
                mode,
                agent,
                owner,
            },
            prev: container,
        }
    }

    /// The bytes and the hash of the first seal, for signing and anchoring
    /// before [`Binder::open`].
    ///
    /// # Errors
    ///
    /// Whatever page 0 fails.
    pub fn opening_seal(
        container: Hash,
        mode: Mode,
        agent: Party,
        owner: Party,
        offset_ms: u64,
    ) -> Result<(Vec<u8>, Hash), BinderError> {
        let page = Self::opening_page(container, mode, agent, owner, offset_ms);
        let (_, seal) = Chain::open(&page)?;
        let bytes = canonical_bytes(&seal).map_err(|_| BinderError::Canonicalization)?;
        let hash = seal.hash().map_err(|_| BinderError::Canonicalization)?;
        Ok((bytes, hash))
    }

    fn refuse_if_waiting(&self) -> Result<(), BinderError> {
        if self.pending.is_some() {
            Err(BinderError::Waiting)
        } else {
            Ok(())
        }
    }

    /// Builds pages after the current head and checks them on a copy.
    fn draft(&self, bodies: Vec<Body>, offset_ms: u64) -> Result<Draft, BinderError> {
        self.refuse_if_waiting()?;
        let n = bodies.len();
        let id = self.chain.batch + 1;
        let mut pages = Vec::with_capacity(n);
        let mut placed = Counts::default();
        let mut prev = self.chain.head;
        for (i, body) in bodies.into_iter().enumerate() {
            let (zone, slot) = self.chain.place(&body, &placed)?;
            match zone {
                Zone::Work => placed.work += 1,
                Zone::Transfer => placed.transfer += 1,
                Zone::Coupling => placed.coupling += 1,
                Zone::Opening => {}
            }
            let page = BoundPage {
                context: crate::doc::Context,
                doc_type: BoundPage::TYPE.to_owned(),
                v: FORMAT_V,
                seq: self.chain.next_seq + i as u64,
                zone,
                slot,
                batch: BatchMark {
                    id,
                    index: u32::try_from(i).map_err(|_| BinderError::RecordTooLong(n))?,
                    of: u32::try_from(n).map_err(|_| BinderError::RecordTooLong(n))?,
                },
                offset_ms,
                body,
                prev,
            };
            prev = page.hash().map_err(|_| BinderError::Canonicalization)?;
            pages.push(page);
        }
        let mut copy = self.chain.clone();
        let applied = copy.apply(&pages)?;
        let transfer = applied.transfer.map(|t| TransferSeal {
            context: crate::doc::Context,
            doc_type: TransferSeal::TYPE.to_owned(),
            v: FORMAT_V,
            page: t.page,
            subject: t.subject,
            signatures: SignatureSet::new(vec![]),
        });
        Ok(Draft {
            pages,
            seal: applied.seal,
            needs_owner: applied.needs_owner,
            transfer,
        })
    }

    /// A record of content: one page, or up to 99 and the service page.
    ///
    /// One piece without anything to say beyond its content type is one page.
    /// Anything more — several pieces, or a media type, compression, charset,
    /// an instruction, an extension — takes the service page, because a page
    /// of content has nowhere else to say it.
    ///
    /// # Errors
    ///
    /// Whatever the record fails.
    pub fn draft_record(
        &self,
        pieces: Vec<Piece>,
        meta: RecordMeta,
        offset_ms: u64,
    ) -> Result<Draft, BinderError> {
        self.refuse_if_waiting()?;
        if pieces.is_empty() {
            return Err(BinderError::Misplaced("an empty record"));
        }
        if pieces.len() > BATCH_CONTENT_PAGES {
            return Err(BinderError::RecordTooLong(pieces.len() + 1));
        }
        let plain = pieces.len() == 1
            && meta.media.is_none()
            && meta.compression.is_none()
            && meta.charset.is_none()
            && meta.order.is_none()
            && meta.ext.is_empty();
        let bodies: Vec<Body> = pieces
            .iter()
            .map(|p| Body::Content {
                kind: meta.kind,
                content: p.clone(),
                content_type: meta.content_type.clone(),
            })
            .collect();
        if plain {
            return self.draft(bodies, offset_ms);
        }
        // The service page describes the content pages as they will stand:
        // build them first, then the page that names their tree.
        let probe = self.draft_pages_only(&bodies, offset_ms, pieces.len() + 1)?;
        let leaves: Vec<Hash> = probe
            .iter()
            .map(chain::page_leaf)
            .collect::<Result<_, _>>()?;
        let commitments: Vec<Hash> = pieces.iter().map(Piece::commitment).collect();
        let manifest = BatchManifest {
            context: crate::doc::Context,
            format: MANIFEST_FORMAT,
            batch: self.chain.batch + 1,
            kind: meta.kind,
            first: self.chain.next_seq,
            pages: u32::try_from(pieces.len())
                .map_err(|_| BinderError::RecordTooLong(pieces.len()))?,
            root: crate::merkle::root(&leaves),
            record: record_hash(&commitments),
            length: pieces.iter().map(|p| p.inline_len() as u64).sum(),
            content_type: meta.content_type,
            media: meta.media,
            compression: meta.compression,
            charset: meta.charset,
            split: Split::Concat,
            offset_ms,
            author: self.chain.agent.id.clone(),
            order: meta.order,
            mode: self.chain.mode,
            prev_seal: self.chain.prev_seal,
            rule: self.chain.rule.as_ref().map(|(h, _)| *h),
            ext: meta.ext,
        };
        let mut all = bodies;
        all.push(Body::Manifest(manifest));
        self.draft(all, offset_ms)
    }

    /// The content pages of a record as they will stand in a record of `of`
    /// pages — to compute the service page's tree before it exists.
    fn draft_pages_only(
        &self,
        bodies: &[Body],
        offset_ms: u64,
        of: usize,
    ) -> Result<Vec<BoundPage>, BinderError> {
        let id = self.chain.batch + 1;
        let mut out = Vec::with_capacity(bodies.len());
        let mut prev = self.chain.head;
        let mut placed = Counts::default();
        for (i, body) in bodies.iter().enumerate() {
            let (zone, slot) = self.chain.place(body, &placed)?;
            placed.work += 1;
            let page = BoundPage {
                context: crate::doc::Context,
                doc_type: BoundPage::TYPE.to_owned(),
                v: FORMAT_V,
                seq: self.chain.next_seq + i as u64,
                zone,
                slot,
                batch: BatchMark {
                    id,
                    index: u32::try_from(i).map_err(|_| BinderError::RecordTooLong(of))?,
                    of: u32::try_from(of).map_err(|_| BinderError::RecordTooLong(of))?,
                },
                offset_ms,
                body: body.clone(),
                prev,
            };
            prev = page.hash().map_err(|_| BinderError::Canonicalization)?;
            out.push(page);
        }
        Ok(out)
    }

    /// A hand-off (CH-16) or a change of owner (CH-14).
    ///
    /// # Errors
    ///
    /// Whatever the transfer fails.
    pub fn draft_transfer(
        &self,
        record: TransferRecord,
        offset_ms: u64,
    ) -> Result<Draft, BinderError> {
        self.draft(vec![Body::Transfer(record)], offset_ms)
    }

    /// A page of the coupling (CH-12).
    ///
    /// # Errors
    ///
    /// Whatever the page fails; a slot already written.
    pub fn draft_coupling(
        &self,
        record: CouplingRecord,
        offset_ms: u64,
    ) -> Result<Draft, BinderError> {
        self.draft(vec![Body::Coupling(record)], offset_ms)
    }

    /// The rule of two seals, set or lifted (CH-19). Always takes the owner.
    ///
    /// # Errors
    ///
    /// Whatever the page fails.
    pub fn draft_rule(&self, rule: SealRule, offset_ms: u64) -> Result<Draft, BinderError> {
        self.draft(vec![Body::Rule(rule)], offset_ms)
    }

    /// A change of form (CH-26, CH-27): always sealed by the owner too. To Pro,
    /// its seal is the first anchored one; without the owner's seal the record
    /// waits and nothing is anchored.
    ///
    /// # Errors
    ///
    /// [`BinderError::FormUnchanged`]; whatever the page fails.
    pub fn draft_form(&self, to: Mode, offset_ms: u64) -> Result<Draft, BinderError> {
        self.draft(vec![Body::Form { to }], offset_ms)
    }

    /// The journal's confirmation of ten identical records (KS-8 F-6).
    ///
    /// # Errors
    ///
    /// [`BinderError::NoConfirmationOwed`].
    pub fn draft_confirmation(&self, offset_ms: u64) -> Result<Draft, BinderError> {
        self.draft(vec![Body::RepeatConfirmation], offset_ms)
    }

    /// Puts the seal on: the record enters the journal — or waits for the
    /// owner's seal, if the rule asks for it and it has not come (CH-20).
    ///
    /// # Errors
    ///
    /// [`BinderError::Waiting`] while another record waits;
    /// [`BinderError::Stale`] for a draft of a journal that moved on; whatever
    /// the signatures or the anchor fail.
    pub fn seal(
        &mut self,
        draft: Draft,
        sealing: Sealing,
        profile: &Profile,
    ) -> Result<Outcome, BinderError> {
        self.refuse_if_waiting()?;
        self.put_on(draft, sealing, profile)
    }

    /// The owner's seal for the record that waits — and, where the record's
    /// seal goes on in Pro, its anchor, made only now that the owner has
    /// confirmed (CH-26: no owner's seal, no anchoring, no charge).
    ///
    /// # Errors
    ///
    /// [`BinderError::NothingWaiting`]; whatever the owner's seal or the anchor
    /// fail — and then the record still waits.
    pub fn complete(
        &mut self,
        owner: SignatureSet,
        anchor: Option<EntryAnchor>,
        profile: &Profile,
    ) -> Result<u64, BinderError> {
        let pending = self.pending.take().ok_or(BinderError::NothingWaiting)?;
        let mut sealing = pending.sealing.clone();
        sealing.owner = Some(owner);
        if anchor.is_some() {
            sealing.anchor = anchor;
        }
        match self.put_on(pending.draft.clone(), sealing, profile) {
            Ok(Outcome::Written(n)) => Ok(n),
            Ok(Outcome::Waiting) => {
                self.pending = Some(pending);
                Err(BinderError::Signature("the owner's seal did not take"))
            }
            Err(e) => {
                self.pending = Some(pending);
                Err(e)
            }
        }
    }

    /// Withdraws the record that waits: nothing of it was written.
    ///
    /// # Errors
    ///
    /// [`BinderError::NothingWaiting`].
    pub fn withdraw(&mut self) -> Result<(), BinderError> {
        self.pending
            .take()
            .map(|_| ())
            .ok_or(BinderError::NothingWaiting)
    }

    /// Whether a record waits for the owner's seal.
    #[must_use]
    pub const fn waiting(&self) -> bool {
        self.pending.is_some()
    }

    /// The record that waits for the owner's seal, if one does — the owner
    /// seals exactly this, not a record presented in its place.
    #[must_use]
    pub fn waiting_draft(&self) -> Option<&Draft> {
        self.pending.as_ref().map(|p| &p.draft)
    }

    /// The form the journal is in.
    #[must_use]
    pub const fn mode(&self) -> Mode {
        self.chain.mode
    }

    fn put_on(
        &mut self,
        draft: Draft,
        sealing: Sealing,
        profile: &Profile,
    ) -> Result<Outcome, BinderError> {
        // The draft is re-derived on the current state: a draft of a journal
        // that moved on, or one whose seal was edited, does not match.
        let mut next = self.chain.clone();
        let applied = next.apply(&draft.pages).map_err(|_| BinderError::Stale)?;
        if applied.seal != draft.seal {
            return Err(BinderError::Stale);
        }
        let mut seal = draft.seal.clone();
        seal.signatures = sealing.seal.clone();
        check_seal(&seal, &next.agent, profile)?;
        let transfer = match (&applied.transfer, &draft.transfer) {
            (Some(parties), Some(t)) => {
                let mut t = t.clone();
                t.signatures = sealing
                    .transfer
                    .clone()
                    .ok_or(BinderError::Signature("the transfer seal"))?;
                check_transfer_seal(&t, parties, profile)?;
                Some(t)
            }
            (None, None) => None,
            _ => return Err(BinderError::Stale),
        };
        let coseal = if applied.needs_owner {
            match &sealing.owner {
                None => {
                    // Nothing is anchored before the owner confirms (CH-26).
                    if sealing.anchor.is_some() {
                        return Err(BinderError::AnchoredBeforeOwner);
                    }
                    self.pending = Some(Pending { draft, sealing });
                    return Ok(Outcome::Waiting);
                }
                Some(sigs) => {
                    let c = CoSeal {
                        context: crate::doc::Context,
                        doc_type: CoSeal::TYPE.to_owned(),
                        v: FORMAT_V,
                        batch: draft.seal.batch,
                        subject: draft
                            .seal
                            .hash()
                            .map_err(|_| BinderError::Canonicalization)?,
                        signatures: sigs.clone(),
                    };
                    check_coseal(&c, &draft.seal, &next.owner, profile)?;
                    Some(c)
                }
            }
        } else {
            None
        };
        // The anchor last: a record that waits for the owner is not anchored
        // before the owner has sealed it (CH-26).
        check_anchor(&seal, sealing.anchor.as_ref())?;
        let number = seal.number;
        self.chain = next;
        self.pages.extend(draft.pages);
        if let Some(anchor) = sealing.anchor {
            self.anchors.push(SealAnchor {
                batch: seal.batch,
                anchor,
            });
        }
        self.seal = seal;
        self.transfers.extend(transfer);
        self.coseals.extend(coseal);
        Ok(Outcome::Written(number))
    }

    /// Replaces the anchor of the **top** seal with another anchor of the same
    /// seal: a placeholder, written while the record was being admitted, by
    /// the network's attestation that came back for it.
    ///
    /// Why this exists (audit of 30.09, O-1): a caller that anchors must not
    /// spend a memo on a record the journal would refuse, and used to find
    /// out by pressing a whole copy of the container — a second replay of the
    /// whole journal on every anchored record. Admitting with a placeholder,
    /// sending the memo, then swapping the anchor costs nothing of the kind.
    ///
    /// Narrow on purpose: only the top seal's anchor, only in Pro, only an
    /// anchor of that very seal. An anchor is evidence attached to a seal, not
    /// part of what anybody signed; swapping it changes no signature, and any
    /// anchor still has to be read by a verifier to count (spec v2 §7.2).
    ///
    /// # Errors
    ///
    /// [`BinderError::NoAnchor`] when the top seal carries none (light form);
    /// [`BinderError::WrongAnchor`] for an anchor of another subject.
    pub fn reanchor_top(&mut self, anchor: EntryAnchor) -> Result<(), BinderError> {
        let batch = self.seal.batch;
        check_anchor(&self.seal, Some(&anchor))?;
        let last = self
            .anchors
            .last_mut()
            .filter(|a| a.batch == batch)
            .ok_or(BinderError::NoAnchor)?;
        last.anchor = anchor;
        Ok(())
    }

    /// The anchors of the seals, oldest first — one per anchored record.
    #[must_use]
    pub fn anchors(&self) -> &[SealAnchor] {
        &self.anchors
    }

    /// The number of the movable seal: every page written, of all zones.
    #[must_use]
    pub const fn number(&self) -> u64 {
        self.seal.number
    }

    /// Pages written in each zone.
    #[must_use]
    pub const fn counts(&self) -> Counts {
        self.chain.counts
    }

    /// The current agent.
    #[must_use]
    pub fn agent(&self) -> &Party {
        &self.chain.agent
    }

    /// The current owner.
    #[must_use]
    pub fn owner(&self) -> &Party {
        &self.chain.owner
    }

    /// The movable seal as it stands.
    #[must_use]
    pub const fn top_seal(&self) -> &Seal {
        &self.seal
    }

    /// The container.
    #[must_use]
    pub const fn container(&self) -> &Hash {
        &self.chain.container
    }

    /// Whether the journal is in the Pro form.
    #[must_use]
    pub fn is_pro(&self) -> bool {
        self.chain.mode == Mode::Pro
    }

    /// The anchor of the movable seal as it stands, in Pro.
    fn top_anchor(&self) -> Option<EntryAnchor> {
        self.anchors
            .last()
            .filter(|a| a.batch == self.seal.batch)
            .map(|a| a.anchor.clone())
    }

    /// One page with its proof under the movable seal. Counts against
    /// [`POINT_LIMIT`], as the journal of pages does.
    ///
    /// # Errors
    ///
    /// [`BinderError::PointLimit`], [`BinderError::NoSuchPage`].
    pub fn export_one(&mut self, seq: u64) -> Result<BoundPoint, BinderError> {
        if self.disclosed >= self.point_limit {
            return Err(BinderError::PointLimit(self.point_limit));
        }
        let page = self
            .pages
            .get(usize::try_from(seq).map_err(|_| BinderError::NoSuchPage(seq))?)
            .cloned()
            .ok_or(BinderError::NoSuchPage(seq))?;
        let proof = crate::merkle::inclusion_proof(&self.chain.leaves, seq)
            .map_err(|_| BinderError::NoSuchPage(seq))?;
        self.disclosed += 1;
        Ok(BoundPoint {
            context: crate::doc::Context,
            page,
            proof,
            seal: self.seal.clone(),
            anchor: self.top_anchor(),
        })
    }

    /// Up to [`PAGES_PER_EXPORT`] pages, each with its proof under the movable
    /// seal — one pointwise export, counted **once** against [`POINT_LIMIT`]
    /// (`[decision]` 06.10). Each page is the same [`BoundPoint`] that
    /// [`Binder::export_one`] gives and is checked the same way; nothing is
    /// counted unless every page is found.
    ///
    /// # Errors
    ///
    /// [`BinderError::PointLimit`], [`BinderError::PageCount`],
    /// [`BinderError::NoSuchPage`].
    pub fn export_pages(&mut self, seqs: &[u64]) -> Result<Vec<BoundPoint>, BinderError> {
        if self.disclosed >= self.point_limit {
            return Err(BinderError::PointLimit(self.point_limit));
        }
        let mut distinct = seqs.to_vec();
        distinct.sort_unstable();
        distinct.dedup();
        if seqs.is_empty() || seqs.len() > PAGES_PER_EXPORT || distinct.len() != seqs.len() {
            return Err(BinderError::PageCount(seqs.len()));
        }
        let anchor = self.top_anchor();
        let mut out = Vec::with_capacity(seqs.len());
        for &seq in seqs {
            let page = self
                .pages
                .get(usize::try_from(seq).map_err(|_| BinderError::NoSuchPage(seq))?)
                .cloned()
                .ok_or(BinderError::NoSuchPage(seq))?;
            let proof = crate::merkle::inclusion_proof(&self.chain.leaves, seq)
                .map_err(|_| BinderError::NoSuchPage(seq))?;
            out.push(BoundPoint {
                context: crate::doc::Context,
                page,
                proof,
                seal: self.seal.clone(),
                anchor: anchor.clone(),
            });
        }
        self.disclosed += 1;
        Ok(out)
    }

    /// Up to [`PAGES_PER_EXPORT`] pages for a court-appointed expert, each
    /// with its proof under the movable seal — **outside** [`POINT_LIMIT`]:
    /// `[decision]` 19.09 (CT-21) "the 13th goes through the export to the
    /// expert, the container lives", confirmed 06.10. Nothing is counted; who
    /// may ask is the container's to check (the expert's appointment and the
    /// principals' disclosure).
    ///
    /// # Errors
    ///
    /// [`BinderError::PageCount`], [`BinderError::NoSuchPage`].
    pub fn expert_pages(&self, seqs: &[u64]) -> Result<Vec<BoundPoint>, BinderError> {
        let mut distinct = seqs.to_vec();
        distinct.sort_unstable();
        distinct.dedup();
        if seqs.is_empty() || seqs.len() > PAGES_PER_EXPORT || distinct.len() != seqs.len() {
            return Err(BinderError::PageCount(seqs.len()));
        }
        let anchor = self.top_anchor();
        seqs.iter()
            .map(|&seq| {
                let page = self
                    .pages
                    .get(usize::try_from(seq).map_err(|_| BinderError::NoSuchPage(seq))?)
                    .cloned()
                    .ok_or(BinderError::NoSuchPage(seq))?;
                let proof = crate::merkle::inclusion_proof(&self.chain.leaves, seq)
                    .map_err(|_| BinderError::NoSuchPage(seq))?;
                Ok(BoundPoint {
                    context: crate::doc::Context,
                    page,
                    proof,
                    seal: self.seal.clone(),
                    anchor: anchor.clone(),
                })
            })
            .collect()
    }

    /// Whether a page of content of `content_type` commits to one of `pieces`
    /// — a fact the container checks without handing a page out (the
    /// appointed expert's entry, `[decision]` 11.09).
    #[must_use]
    pub fn holds_content(&self, content_type: &str, pieces: &[Piece]) -> bool {
        let wanted: Vec<Hash> = pieces.iter().map(Piece::commitment).collect();
        self.pages.iter().any(|p| {
            matches!(&p.body, Body::Content { content, content_type: Some(t), .. }
                if t.as_str() == content_type && wanted.contains(&content.commitment()))
        })
    }

    /// How many pointwise exports have gone out, of [`Binder::point_limit`].
    #[must_use]
    pub const fn disclosed(&self) -> u64 {
        self.disclosed
    }

    /// Pointwise exports this journal allows: [`POINT_LIMIT`] unless the
    /// container's class set another.
    #[must_use]
    pub const fn point_limit(&self) -> u64 {
        self.point_limit
    }

    /// Sets the pointwise-export limit of the container's class
    /// ([`POINT_LIMIT`], or [`BARE_POINT_LIMIT`] for `bare`).
    ///
    /// # Errors
    ///
    /// [`BinderError::PointLimit`] when more exports have already gone out.
    pub fn set_point_limit(&mut self, limit: u64) -> Result<(), BinderError> {
        if self.disclosed > limit || limit > BARE_POINT_LIMIT {
            return Err(BinderError::PointLimit(self.disclosed));
        }
        self.point_limit = limit;
        Ok(())
    }

    /// The hash of the last page — the head an event claims to have seen.
    #[must_use]
    pub const fn head_page(&self) -> Hash {
        self.seal.head
    }

    /// Everything, once: the journal is spent.
    #[must_use]
    pub fn export_final(self) -> BoundExport {
        BoundExport {
            context: crate::doc::Context,
            doc_type: BoundExport::TYPE.to_owned(),
            pages: self.pages,
            seal: self.seal,
            anchors: self.anchors,
            transfers: self.transfers,
            coseals: self.coseals,
        }
    }

    /// The journal's state, for the container's sealed storage.
    #[must_use]
    pub fn state(&self) -> BinderState {
        BinderState {
            export: BoundExport {
                context: crate::doc::Context,
                doc_type: BoundExport::TYPE.to_owned(),
                pages: self.pages.clone(),
                seal: self.seal.clone(),
                anchors: self.anchors.clone(),
                transfers: self.transfers.clone(),
                coseals: self.coseals.clone(),
            },
            pending: self.pending.clone().map(|p| (p.draft, p.sealing)),
            disclosed: self.disclosed,
        }
    }

    /// The journal again, from its state — by the same check an export gets.
    ///
    /// # Errors
    ///
    /// Whatever [`verify_bound`] refuses; a waiting record that no longer
    /// fits; a disclosure count past the limit.
    pub fn restore(state: BinderState, profile: &Profile) -> Result<Self, BinderError> {
        let (chain, _) = verify::replay(&state.export, profile)?;
        if state.disclosed > BARE_POINT_LIMIT {
            return Err(BinderError::PointLimit(state.disclosed));
        }
        let mut b = Self {
            chain,
            pages: state.export.pages,
            seal: state.export.seal,
            anchors: state.export.anchors,
            transfers: state.export.transfers,
            coseals: state.export.coseals,
            pending: None,
            disclosed: state.disclosed,
            point_limit: POINT_LIMIT.max(state.disclosed),
        };
        if let Some((draft, sealing)) = state.pending {
            let mut copy = b.chain.clone();
            let applied = copy.apply(&draft.pages).map_err(|_| BinderError::Stale)?;
            if applied.seal != draft.seal || !applied.needs_owner {
                return Err(BinderError::Stale);
            }
            b.pending = Some(Pending { draft, sealing });
        }
        Ok(b)
    }
}

/// Everything a bound journal is: its pages and every seal still on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundExport {
    /// Always [`crate::doc::CONTEXT`] (spec v2 §3.3).
    #[serde(rename = "@context")]
    pub context: crate::doc::Context,
    /// Always `"BoundJournalExport"`.
    #[serde(rename = "type")]
    pub doc_type: String,
    /// Every page, from page 0.
    pub pages: Vec<BoundPage>,
    /// The movable seal.
    pub seal: Seal,
    /// The anchors of every anchored seal (CH-25).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub anchors: Vec<SealAnchor>,
    /// The seals of transfers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transfers: Vec<TransferSeal>,
    /// The owner's second seals.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub coseals: Vec<CoSeal>,
}

impl BoundExport {
    /// The value of `type`.
    pub const TYPE: &'static str = "BoundJournalExport";
}

/// What a bound journal is made of, for the container's sealed storage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BinderState {
    /// Everything written.
    pub export: BoundExport,
    /// A record waiting for the owner's seal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<(Draft, Sealing)>,
    /// Pages that went out one at a time.
    pub disclosed: u64,
}

/// The content types a rule covers — for display.
#[must_use]
pub fn rule_types(rule: &SealRule) -> BTreeSet<String> {
    match &rule.scope {
        RuleScope::Types(t) => t.iter().map(|u| u.as_str().to_owned()).collect(),
        RuleScope::All => BTreeSet::from(["*".to_owned()]),
        RuleScope::Lifted => BTreeSet::new(),
    }
}
