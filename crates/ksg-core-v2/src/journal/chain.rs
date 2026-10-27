//! The one procedure by which a bound journal is written **and** read.
//!
//! The writer runs it on a copy before accepting a record; the verifier runs it
//! over an export from page 0. The same code both times: invariants of writing
//! and invariants of reading drifted apart once already (security audit of
//! 13.09, finding 13) — here there is nothing for them to drift between.

use crate::crypto::hash::Hash;
use crate::crypto::sign::SignatureSet;
use crate::merkle::{hash_leaf, root};

use super::manifest::{BatchManifest, Split, MANIFEST_FORMAT};
use super::page::{Body, BoundPage, Mode, Party, RecordKind, Zone};
use super::seal::{Counts, Seal, SealRule, TransferKind, TransferRecord};
use super::REPEAT_LIMIT;
use super::{
    BinderError, BATCH_BYTES, BATCH_CONTENT_PAGES, BATCH_PAGES, COUPLING_PAGES, PAGE_BYTES,
    TRANSFER_PAGES, WORK_PAGES,
};

/// The state the procedure carries from record to record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Chain {
    pub(crate) container: Hash,
    /// RFC 6962 leaf hashes of every page so far.
    pub(crate) leaves: Vec<Hash>,
    pub(crate) head: Hash,
    pub(crate) next_seq: u64,
    pub(crate) counts: Counts,
    pub(crate) agent: Party,
    pub(crate) owner: Party,
    /// The rule of two seals in force: the hash of its page, and the rule.
    pub(crate) rule: Option<(Hash, SealRule)>,
    /// The form in force.
    pub(crate) mode: Mode,
    pub(crate) last_offset: u64,
    pub(crate) batch: u64,
    pub(crate) prev_seal: Option<Hash>,
    pub(crate) coupled: [bool; 2],
    /// The repeat rule: the last single-page record of content, and how many
    /// times in a row it was written.
    pub(crate) repeat: Option<(RepeatKey, usize)>,
}

/// What makes two records "the same" for the repeat rule (`[decision]` 11.09):
/// author, kind and content — the content type read as part of the content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RepeatKey {
    author: crate::doc::Uri,
    kind: RecordKind,
    commitment: Hash,
    content_type: Option<crate::doc::Uri>,
}

/// What applying a record produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Applied {
    /// The movable seal for the record, unsigned.
    pub(crate) seal: Seal,
    /// Whether the owner seals this record too: the rule of two seals
    /// (CH-19), a change of form (CH-26, CH-27), an artefact or rights in Pro
    /// (CH-29).
    pub(crate) needs_owner: bool,
    /// For a transfer: who must seal it.
    pub(crate) transfer: Option<TransferParties>,
}

/// Who seals a transfer page, and which page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TransferParties {
    pub(crate) page: u64,
    pub(crate) subject: Hash,
    pub(crate) parties: Vec<Party>,
}

fn leaf(page_hash: &Hash) -> Hash {
    hash_leaf(page_hash.as_bytes())
}

fn page_hash(p: &BoundPage) -> Result<Hash, BinderError> {
    p.hash().map_err(|_| BinderError::Canonicalization)
}

impl Chain {
    /// Page 0.
    pub(crate) fn open(page: &BoundPage) -> Result<(Self, Seal), BinderError> {
        let Body::Opening {
            container,
            mode,
            agent,
            owner,
        } = &page.body
        else {
            return Err(BinderError::Misplaced("page 0 must be the opening"));
        };
        if page.doc_type != BoundPage::TYPE {
            return Err(BinderError::Misplaced("not a bound page"));
        }
        super::check_format(page.v)?;
        if page.seq != 0
            || page.zone != Zone::Opening
            || page.slot != 0
            || page.batch.id != 0
            || page.batch.index != 0
            || page.batch.of != 1
        {
            return Err(BinderError::Misplaced("the opening is page 0, record 0"));
        }
        if &page.prev != container {
            return Err(BinderError::BrokenChain(0));
        }
        if !agent.is_consistent() || !owner.is_consistent() {
            return Err(BinderError::Parties);
        }
        let h = page_hash(page)?;
        let mut chain = Self {
            container: *container,
            leaves: vec![leaf(&h)],
            head: h,
            next_seq: 1,
            counts: Counts::default(),
            agent: agent.clone(),
            owner: owner.clone(),
            rule: None,
            mode: *mode,
            last_offset: page.offset_ms,
            batch: 0,
            prev_seal: None,
            coupled: [false; 2],
            repeat: None,
        };
        let seal = chain.seal(0, page.offset_ms)?;
        chain.prev_seal = Some(seal.hash().map_err(|_| BinderError::Canonicalization)?);
        Ok((chain, seal))
    }

    /// The zone and slot the next page with this body takes, counting the
    /// pages already placed in this record.
    pub(crate) fn place(&self, body: &Body, pending: &Counts) -> Result<(Zone, u64), BinderError> {
        let work = self.counts.work + pending.work;
        let transfer = self.counts.transfer + pending.transfer;
        match body {
            Body::Opening { .. } => Err(BinderError::Misplaced("only page 0 opens")),
            Body::Transfer(t) if t.kind == TransferKind::OwnerChange => {
                if transfer >= TRANSFER_PAGES {
                    return Err(BinderError::Full(Zone::Transfer));
                }
                Ok((Zone::Transfer, transfer + 1))
            }
            Body::Coupling(c) => {
                let slot = c.slot();
                let used = usize::try_from(slot.saturating_sub(1))
                    .ok()
                    .and_then(|i| self.coupled.get(i).copied())
                    .ok_or(BinderError::Misplaced(
                        "a coupling slot that does not exist",
                    ))?;
                if used {
                    return Err(BinderError::CouplingUsed(slot));
                }
                debug_assert!(slot <= COUPLING_PAGES);
                Ok((Zone::Coupling, slot))
            }
            _ => {
                if work >= WORK_PAGES {
                    return Err(BinderError::Full(Zone::Work));
                }
                Ok((Zone::Work, work + 1))
            }
        }
    }

    /// Applies one record: checks it, advances the state, and returns the seal
    /// that goes on it. On error the state is unchanged only if the caller
    /// works on a copy — which both callers do.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn apply(&mut self, pages: &[BoundPage]) -> Result<Applied, BinderError> {
        let first = pages
            .first()
            .ok_or(BinderError::Misplaced("an empty record"))?;
        let n = pages.len();
        // Every "the last page" and "the pages before it" below is this split:
        // no index into `pages` is taken anywhere in this function.
        let (last, before_last) = pages
            .split_last()
            .ok_or(BinderError::Misplaced("an empty record"))?;
        if n > BATCH_PAGES {
            return Err(BinderError::RecordTooLong(n));
        }
        let id = self.batch + 1;
        let offset = first.offset_ms;
        if offset <= self.last_offset {
            return Err(BinderError::OffsetNotGrowing {
                got: offset,
                last: self.last_offset,
            });
        }
        // --- shape of the record --------------------------------------------
        let multi = n > 1;
        if multi {
            if n - 1 > BATCH_CONTENT_PAGES {
                return Err(BinderError::RecordTooLong(n));
            }
            for p in before_last {
                if !matches!(p.body, Body::Content { .. }) {
                    return Err(BinderError::Misplaced(
                        "a record of several pages is content and then its service page",
                    ));
                }
            }
            if !matches!(last.body, Body::Manifest(_)) {
                return Err(BinderError::Misplaced(
                    "the last page of a record of several pages is its service page",
                ));
            }
        } else if matches!(first.body, Body::Manifest(_) | Body::Opening { .. }) {
            return Err(BinderError::Misplaced(
                "a service page stands only after content",
            ));
        }

        // --- every page: its place in the chain -----------------------------
        let mut placed = Counts::default();
        let mut hashes = Vec::with_capacity(n);
        let mut prev = self.head;
        let mut total = 0usize;
        for (i, p) in pages.iter().enumerate() {
            if p.doc_type != BoundPage::TYPE {
                return Err(BinderError::Misplaced("not a bound page"));
            }
            super::check_format(p.v)?;
            let seq = self.next_seq + i as u64;
            if p.seq != seq {
                return Err(BinderError::OutOfOrder {
                    got: p.seq,
                    expected: seq,
                });
            }
            if p.prev != prev {
                return Err(BinderError::BrokenChain(p.seq));
            }
            if p.batch.id != id || p.batch.index as usize != i || p.batch.of as usize != n {
                return Err(BinderError::BatchMark(p.seq));
            }
            if p.offset_ms != offset {
                return Err(BinderError::OneTimeMark(p.seq));
            }
            let (zone, slot) = self.place(&p.body, &placed)?;
            if p.zone != zone || p.slot != slot {
                return Err(BinderError::WrongPlace(p.seq));
            }
            match zone {
                Zone::Work => placed.work += 1,
                Zone::Transfer => placed.transfer += 1,
                Zone::Coupling => placed.coupling += 1,
                Zone::Opening => {}
            }
            let len = p.inline_len();
            if len > PAGE_BYTES {
                return Err(BinderError::PageTooLarge(p.seq));
            }
            total += len;
            let h = page_hash(p)?;
            hashes.push(h);
            prev = h;
        }
        if total > BATCH_BYTES {
            return Err(BinderError::RecordTooLarge(total));
        }
        let first_hash = *hashes
            .first()
            .ok_or(BinderError::Misplaced("an empty record"))?;
        let head = *hashes
            .last()
            .ok_or(BinderError::Misplaced("an empty record"))?;
        let before_last_hashes = hashes.get(..n - 1).unwrap_or(&[]);

        // --- the record's meaning -------------------------------------------
        let mut needs_owner = false;
        let mut transfer: Option<(u64, Hash, TransferRecord)> = None;
        let mut new_rule: Option<Option<(Hash, SealRule)>> = None;
        let mut coupling: Option<u64> = None;
        let mut repeat_key: Option<RepeatKey> = None;
        let mut confirmation = false;
        let mut new_form: Option<Mode> = None;
        let rule_covers =
            |ct: Option<&crate::doc::Uri>| self.rule.as_ref().is_some_and(|(_, r)| r.covers(ct));
        let form = self.mode;

        if multi {
            let Body::Manifest(m) = &last.body else {
                return Err(BinderError::Misplaced("the service page"));
            };
            let (content_type, kind) =
                self.check_manifest(m, before_last, before_last_hashes, id, offset)?;
            needs_owner = rule_covers(content_type.as_ref()) || kind.needs_owner(form);
        } else {
            match &first.body {
                Body::Content {
                    kind,
                    content,
                    content_type,
                } => {
                    needs_owner = rule_covers(content_type.as_ref()) || kind.needs_owner(form);
                    repeat_key = Some(RepeatKey {
                        author: self.agent.id.clone(),
                        kind: *kind,
                        commitment: content.commitment(),
                        content_type: content_type.clone(),
                    });
                }
                Body::Transfer(t) => {
                    self.check_transfer(t)?;
                    transfer = Some((first.seq, first_hash, t.clone()));
                }
                Body::Coupling(c) => coupling = Some(c.slot()),
                Body::Rule(r) => {
                    // Setting a rule and lifting it both take the owner (CH-19).
                    needs_owner = true;
                    if let super::seal::RuleScope::Types(t) = &r.scope {
                        if t.is_empty() {
                            return Err(BinderError::EmptyRule);
                        }
                    }
                    new_rule = Some(match r.scope {
                        super::seal::RuleScope::Lifted => None,
                        _ => Some((first_hash, r.clone())),
                    });
                }
                Body::RepeatConfirmation => confirmation = true,
                Body::Form { to } => {
                    // Either way, the owner's seal (CH-26, CH-27).
                    if *to == form {
                        return Err(BinderError::FormUnchanged(form));
                    }
                    needs_owner = true;
                    new_form = Some(*to);
                }
                Body::Manifest(_) | Body::Opening { .. } => {
                    return Err(BinderError::Misplaced(
                        "a service page stands only after content",
                    ))
                }
            }
        }

        // --- the repeat rule (KS-8 F-6, `[decision]` 11.09) -------------------
        let owed = self
            .repeat
            .as_ref()
            .is_some_and(|(_, run)| *run >= REPEAT_LIMIT);
        if confirmation {
            if !owed {
                return Err(BinderError::NoConfirmationOwed);
            }
            self.repeat = None;
        } else if owed {
            // As in the journal of pages: ten identical records, then the
            // confirmation and nothing else.
            return Err(BinderError::ConfirmationOwed);
        } else {
            self.repeat = match (repeat_key, self.repeat.take()) {
                (Some(k), Some((last, run))) if k == last => Some((k, run + 1)),
                (Some(k), _) => Some((k, 1)),
                (None, _) => None,
            };
        }

        // --- advance --------------------------------------------------------
        for h in &hashes {
            self.leaves.push(leaf(h));
        }
        self.head = head;
        self.next_seq += n as u64;
        self.counts.work += placed.work;
        self.counts.transfer += placed.transfer;
        self.counts.coupling += placed.coupling;
        self.last_offset = offset;
        self.batch = id;
        if let Some(slot) = coupling {
            if let Some(c) = usize::try_from(slot.saturating_sub(1))
                .ok()
                .and_then(|i| self.coupled.get_mut(i))
            {
                *c = true;
            }
        }
        if let Some(r) = new_rule {
            self.rule = r;
        }
        if let Some(to) = new_form {
            self.mode = to;
        }
        let parties = match transfer {
            Some((page, subject, t)) => {
                let mut parties = vec![self.agent.clone(), t.to_agent.clone()];
                if t.kind == TransferKind::OwnerChange {
                    let to_owner = t.to_owner.clone().ok_or(BinderError::Misplaced(
                        "a change of owner names the new owner",
                    ))?;
                    parties.push(self.owner.clone());
                    parties.push(to_owner.clone());
                    self.owner = to_owner;
                }
                // CH-17: the new agent replaces the old one.
                self.agent = t.to_agent;
                Some(TransferParties {
                    page,
                    subject,
                    parties,
                })
            }
            None => None,
        };

        let seal = self.seal(id, offset)?;
        self.prev_seal = Some(seal.hash().map_err(|_| BinderError::Canonicalization)?);
        Ok(Applied {
            seal,
            needs_owner,
            transfer: parties,
        })
    }

    fn check_transfer(&self, t: &TransferRecord) -> Result<(), BinderError> {
        if t.from_agent != self.agent.id {
            return Err(BinderError::Transfer(
                "the handing agent is not the current one",
            ));
        }
        if !t.to_agent.is_consistent() {
            return Err(BinderError::Parties);
        }
        // A hand-off to oneself is not a hand-off. A change of owner may keep
        // the agent: then it is the owner that changes, and the agent signs
        // on both sides.
        if t.kind == TransferKind::Handoff && t.to_agent.id == self.agent.id {
            return Err(BinderError::Transfer(
                "a hand-off to oneself is not a hand-off",
            ));
        }
        if t.to_agent.id == self.agent.id && t.to_agent != self.agent {
            return Err(BinderError::Transfer(
                "the agent kept across a change of owner keeps its keys",
            ));
        }
        match t.kind {
            TransferKind::Handoff => {
                if t.from_owner.is_some() || t.to_owner.is_some() {
                    return Err(BinderError::Transfer(
                        "a hand-off between agents of one owner names no owner",
                    ));
                }
            }
            TransferKind::OwnerChange => {
                if t.from_owner.as_ref() != Some(&self.owner.id) {
                    return Err(BinderError::Transfer(
                        "the handing owner is not the current one",
                    ));
                }
                let to = t.to_owner.as_ref().ok_or(BinderError::Transfer(
                    "a change of owner names the new owner",
                ))?;
                if !to.is_consistent() {
                    return Err(BinderError::Parties);
                }
                if to.id == self.owner.id {
                    return Err(BinderError::Transfer(
                        "the owner does not change: that is a hand-off",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Checks the service page against the pages it describes; returns the
    /// record's content type.
    fn check_manifest(
        &self,
        m: &BatchManifest,
        pages: &[BoundPage],
        hashes: &[Hash],
        id: u64,
        offset: u64,
    ) -> Result<(Option<crate::doc::Uri>, RecordKind), BinderError> {
        let bad = BinderError::Manifest;
        if m.format != MANIFEST_FORMAT {
            return Err(bad("an unknown format"));
        }
        if m.ext.iter().any(|e| e.critical) {
            // No critical extension is defined by this format: whoever set one
            // expects a reader that knows it, and this is not that reader.
            return Err(bad("a critical extension this reader does not know"));
        }
        let first_seq = pages.first().map(|p| p.seq);
        if m.batch != id || Some(m.first) != first_seq || m.pages as usize != pages.len() {
            return Err(bad("the record's number, first page or page count"));
        }
        let leaves: Vec<Hash> = hashes.iter().map(leaf).collect();
        if m.root != root(&leaves) {
            return Err(bad("the tree over the pages"));
        }
        let mut commitments = Vec::with_capacity(pages.len());
        let mut length = 0u64;
        for p in pages {
            let Body::Content {
                kind,
                content,
                content_type,
            } = &p.body
            else {
                return Err(bad("a page of the record that is not content"));
            };
            if content_type != &m.content_type || *kind != m.kind {
                return Err(bad("a page of another content type or kind"));
            }
            commitments.push(content.commitment());
            length += content.inline_len() as u64;
        }
        if m.record != record_hash(&commitments) || m.length != length {
            return Err(bad("the record's hash or length"));
        }
        if m.split != Split::Concat || m.offset_ms != offset {
            return Err(bad("the split rule or the time mark"));
        }
        if m.author != self.agent.id {
            return Err(bad("the author is not the agent"));
        }
        if m.mode != self.mode {
            return Err(bad("the form"));
        }
        if m.prev_seal != self.prev_seal || m.rule != self.rule.as_ref().map(|(h, _)| *h) {
            return Err(bad("the previous seal or the rule in force"));
        }
        Ok((m.content_type.clone(), m.kind))
    }

    /// The movable seal as it stands now, unsigned.
    fn seal(&self, batch: u64, offset: u64) -> Result<Seal, BinderError> {
        Ok(Seal {
            context: crate::doc::Context,
            doc_type: Seal::TYPE.to_owned(),
            v: super::FORMAT_V,
            container: self.container,
            number: self.next_seq - 1,
            batch,
            head: self.head,
            root: root(&self.leaves),
            counts: self.counts,
            agent: self.agent.id.clone(),
            owner: self.owner.id.clone(),
            rule: self.rule.as_ref().map(|(h, _)| *h),
            mode: self.mode,
            prev: self.prev_seal,
            offset_ms: offset,
            signatures: SignatureSet::new(vec![]),
        })
    }
}

/// The hash of a whole record: the commitments of its pieces, in order.
#[must_use]
pub(crate) fn record_hash(commitments: &[Hash]) -> Hash {
    let parts: Vec<&[u8]> = commitments
        .iter()
        .map(|h| h.as_bytes().as_slice())
        .collect();
    let mut fields: Vec<&[u8]> = vec![b"ksg:bound:record:v1"];
    fields.extend(parts);
    Hash::sha256_fields(&fields)
}

/// The leaf hash of a page, as the seal's tree takes it.
pub(crate) fn page_leaf(page: &BoundPage) -> Result<Hash, BinderError> {
    Ok(leaf(&page_hash(page)?))
}
