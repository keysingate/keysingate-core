//! Checking a bound journal from its export — by the procedure that wrote it.

use serde::{Deserialize, Serialize};

use crate::crypto::hash::Hash;
use crate::crypto::sign::Profile;
use crate::merkle::{verify_inclusion, Proof};

use super::chain::{page_leaf, Chain};
use super::page::{BoundPage, Mode, Party};
use super::seal::{Counts, Seal, SealRule};
use super::{
    check_anchor, check_coseal, check_seal, check_transfer_seal, BinderError, BoundExport,
};
use crate::anchor::Attestation as EntryAnchor;

/// One record as the check sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordReport {
    /// The record's number.
    pub batch: u64,
    /// Its first page.
    pub first: u64,
    /// Its last page — the number of its seal.
    pub last: u64,
    /// Whether its seal is anchored: the record has force (CH-25).
    pub anchored: bool,
    /// The hash of its seal — what its anchor attests, and what the next
    /// seal links to.
    pub seal: Hash,
}

/// What a checked export establishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundReport {
    /// The movable seal's number: every page written.
    pub number: u64,
    /// Pages in each zone.
    pub counts: Counts,
    /// The agent now.
    pub agent: Party,
    /// The owner now.
    pub owner: Party,
    /// The form now.
    pub mode: Mode,
    /// The rule of two seals in force.
    pub rule: Option<SealRule>,
    /// Hand-offs and changes of owner, by page.
    pub transfers: Vec<u64>,
    /// Records sealed by the owner too.
    pub cosealed: Vec<u64>,
    /// Every record, the opening included.
    pub records: Vec<RecordReport>,
    /// Runs of records anchored one after another with no gap, as page
    /// ranges: inside a run the links between records are confirmed; across a
    /// gap they are not (CH-25).
    pub runs: Vec<(u64, u64)>,
}

impl BoundReport {
    /// Whether a page has force: its record's seal is anchored (CH-25).
    #[must_use]
    pub fn has_force(&self, seq: u64) -> bool {
        self.records
            .iter()
            .any(|r| r.anchored && r.first <= seq && seq <= r.last)
    }
}

fn runs(records: &[RecordReport]) -> Vec<(u64, u64)> {
    let mut out: Vec<(u64, u64)> = Vec::new();
    let mut open: Option<(u64, u64)> = None;
    for r in records {
        match (r.anchored, open) {
            (true, Some((f, _))) => open = Some((f, r.last)),
            (true, None) => open = Some((r.first, r.last)),
            (false, Some(run)) => {
                out.push(run);
                open = None;
            }
            (false, None) => {}
        }
    }
    out.extend(open);
    out
}

/// Replays an export: every page through the procedure that writes it, every
/// seal that was ever put on recomputed, every seal still on — the movable
/// one, the transfers', the owner's, the anchors — checked.
pub(crate) fn replay(
    x: &BoundExport,
    profile: &Profile,
) -> Result<(Chain, BoundReport), BinderError> {
    if x.doc_type != BoundExport::TYPE {
        return Err(BinderError::Export("not a bound journal export"));
    }
    let first = x.pages.first().ok_or(BinderError::Export("no pages"))?;
    let (mut chain, opening_seal) = Chain::open(first)?;
    let mut transfers_used = vec![false; x.transfers.len()];
    let mut coseals_used = vec![false; x.coseals.len()];
    let mut anchors_used = vec![false; x.anchors.len()];
    let mut report_transfers = Vec::new();
    let mut report_cosealed = Vec::new();
    let mut records = Vec::new();

    // A seal and what the export holds for it: its anchor where the form asks
    // for one and nowhere else; the owner's seal where the record needs it.
    let mut settle =
        |seal: &Seal, first: u64, needs_owner: bool, owner: &Party| -> Result<(), BinderError> {
            let k = x.anchors.iter().position(|a| a.batch == seal.batch);
            if let Some(k) = k {
                let used = anchors_used
                    .get_mut(k)
                    .ok_or(BinderError::Export("an anchor out of range"))?;
                if *used {
                    return Err(BinderError::Export("one anchor twice"));
                }
                *used = true;
            }
            check_anchor(seal, k.and_then(|k| x.anchors.get(k)).map(|a| &a.anchor))?;
            if needs_owner {
                let c = x.coseals.iter().position(|c| c.batch == seal.batch).ok_or(
                    BinderError::Export("a record that takes the owner's seal is without it"),
                )?;
                let (Some(used), Some(coseal)) = (coseals_used.get_mut(c), x.coseals.get(c)) else {
                    return Err(BinderError::Export("an owner's seal out of range"));
                };
                if *used {
                    return Err(BinderError::Export("one owner's seal twice"));
                }
                check_coseal(coseal, seal, owner, profile)?;
                *used = true;
                report_cosealed.push(seal.batch);
            }
            records.push(RecordReport {
                batch: seal.batch,
                first,
                last: seal.number,
                anchored: k.is_some(),
                seal: seal.hash().map_err(|_| BinderError::Canonicalization)?,
            });
            Ok(())
        };

    // Opening in Pro takes the owner's seal (CH-26).
    settle(
        &opening_seal,
        0,
        opening_seal.mode == Mode::Pro,
        &chain.owner.clone(),
    )?;
    let mut last = opening_seal;

    let mut rest = x.pages.get(1..).unwrap_or(&[]);
    while let Some(head) = rest.first() {
        let of = head.batch.of as usize;
        if of == 0 || of > rest.len() {
            return Err(BinderError::BatchMark(head.seq));
        }
        let (record, tail) = rest.split_at(of);
        // The owner who seals a record is the one in place for it: a change
        // of owner is sealed by both owners on its own seal, not here.
        let owner = chain.owner.clone();
        let applied = chain.apply(record)?;
        if let Some(parties) = &applied.transfer {
            let k = x
                .transfers
                .iter()
                .position(|t| t.page == parties.page)
                .ok_or(BinderError::Export("a transfer without its seal"))?;
            let (Some(used), Some(t)) = (transfers_used.get_mut(k), x.transfers.get(k)) else {
                return Err(BinderError::Export("a transfer seal out of range"));
            };
            if *used {
                return Err(BinderError::Export("one transfer seal twice"));
            }
            check_transfer_seal(t, parties, profile)?;
            *used = true;
            report_transfers.push(parties.page);
        }
        settle(&applied.seal, head.seq, applied.needs_owner, &owner)?;
        last = applied.seal;
        rest = tail;
    }
    if transfers_used.iter().any(|u| !u)
        || coseals_used.iter().any(|u| !u)
        || anchors_used.iter().any(|u| !u)
    {
        return Err(BinderError::Export(
            "a seal or an anchor of nothing in the journal",
        ));
    }
    // The movable seal on the export is the one the pages give — field for
    // field — and it is the current agent's.
    let mut derived = last;
    derived.signatures = x.seal.signatures.clone();
    if derived != x.seal {
        return Err(BinderError::Export(
            "the movable seal is not the one the pages give",
        ));
    }
    check_seal(&x.seal, &chain.agent, profile)?;
    let report = BoundReport {
        number: x.seal.number,
        counts: chain.counts,
        agent: chain.agent.clone(),
        owner: chain.owner.clone(),
        mode: x.seal.mode,
        rule: chain.rule.as_ref().map(|(_, r)| r.clone()),
        transfers: report_transfers,
        cosealed: report_cosealed,
        runs: runs(&records),
        records,
    };
    Ok((chain, report))
}

/// Checks a whole export of a bound journal.
///
/// Every page is run through the procedure that writes one, every seal that
/// was ever put on is recomputed from the pages, and every seal still on —
/// the movable one, the transfers', the owner's — and every anchor is checked
/// against keys **pinned in the journal**, not keys anyone presents.
///
/// That an anchor's proof holds on the network is the verifier's with a reader
/// of the network to check (CH-6): this crate has no network.
///
/// # Errors
///
/// The first thing that does not hold.
pub fn verify_bound(x: &BoundExport, profile: &Profile) -> Result<BoundReport, BinderError> {
    replay(x, profile).map(|(_, r)| r)
}

/// The bound of one anchored record, read (spec v2 §7.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordBound {
    /// The record's number.
    pub batch: u64,
    /// The earliest moment a read anchor proves for the record's seal;
    /// `None` when no anchor of it could be read.
    pub not_after: Option<crate::doc::Timestamp>,
}

/// Checks a whole export **and reads the anchors of its seals** under the one
/// rule of the core (spec v2 §7.2) — the same procedure that reads a status
/// record's anchor, so there is one model of time, not two (audit of 30.09,
/// Ya-1).
///
/// With `reader` present, every seal the form asks to be anchored must have
/// its anchor read: a seal in Pro whose anchor no reader confirms is refused,
/// because in Pro an unanchored seal does not exist (CH-7). Without a reader,
/// the structure is checked and every bound is `None` — "not established",
/// never "absent".
///
/// # Errors
///
/// The first thing that does not hold, the anchors included.
pub fn verify_bound_read(
    x: &BoundExport,
    profile: &Profile,
    reader: Option<&dyn crate::anchor::AttestationVerifier>,
) -> Result<(BoundReport, Vec<RecordBound>), BinderError> {
    crate::limits::at_most(
        x.pages.len(),
        usize::try_from(super::TOTAL_PAGES).unwrap_or(usize::MAX),
        "journal pages",
    )
    .map_err(|_| BinderError::Export("more pages than a journal holds"))?;
    let report = verify_bound(x, profile)?;
    let mut bounds = Vec::new();
    for r in report.records.iter().filter(|r| r.anchored) {
        let anchor = x
            .anchors
            .iter()
            .find(|a| a.batch == r.batch)
            .ok_or(BinderError::Export("an anchored record without its anchor"))?;
        let not_after = crate::anchor::upper_bound(
            core::slice::from_ref(&anchor.anchor),
            &r.seal,
            profile,
            reader,
        )
        .map_err(|_| BinderError::Export("an anchor of a seal does not hold on its network"))?;
        if reader.is_some() && not_after.is_none() {
            return Err(BinderError::Export(
                "an anchored seal whose anchor no reader confirms",
            ));
        }
        bounds.push(RecordBound {
            batch: r.batch,
            not_after,
        });
    }
    Ok((report, bounds))
}

/// One page with its proof under the movable seal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundPoint {
    /// Always [`crate::doc::CONTEXT`] (spec v2 §3.3).
    #[serde(rename = "@context")]
    pub context: crate::doc::Context,
    /// The page.
    pub page: BoundPage,
    /// Its inclusion under the seal's tree.
    pub proof: Proof,
    /// The movable seal.
    pub seal: Seal,
    /// Its anchor, in Pro.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<EntryAnchor>,
}

/// Checks one page against the movable seal and the agent the verifier knows.
///
/// The agent's keys come from the verifier — from a registration, or from an
/// earlier export it trusts — never from the point itself.
///
/// # Errors
///
/// The first thing that does not hold.
pub fn verify_bound_point(
    point: &BoundPoint,
    container: &Hash,
    agent: &Party,
    profile: &Profile,
) -> Result<(), BinderError> {
    if &point.seal.container != container {
        return Err(BinderError::Export("the seal is of another container"));
    }
    check_seal(&point.seal, agent, profile)?;
    check_anchor(&point.seal, point.anchor.as_ref())?;
    let leaf = page_leaf(&point.page)?;
    if point.page.seq > point.seal.number
        || !verify_inclusion(
            &leaf,
            point.page.seq,
            point.seal.number + 1,
            &point.proof,
            &point.seal.root,
        )
    {
        return Err(BinderError::Export("the page is not under the seal"));
    }
    Ok(())
}
