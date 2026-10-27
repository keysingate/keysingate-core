//! Issuing inside a range. KS-4 §5c.
//!
//! # The role, separated from the release
//!
//! `Issuer` **owns an emission**: it printed the release and its range is the
//! release's range. A delegate owns nothing of the sort — it issues **inside
//! somebody else's release**, within the range it was granted. KS-4 §5c named
//! the split and called it "more than a new document"; this is it.
//!
//! So the machinery that hands out consecutive blocks lives here, over a range
//! it is given rather than one it owns, and [`crate::Issuer`] becomes an
//! emission plus one of these over the whole of it. A delegate runs the same
//! type over its own slice, with the same guarantees and no special case.
//!
//! # What the separation buys, beyond tidiness
//!
//! **Double issuance stays structurally impossible at every level** (KS-4 §5d).
//! The property comes from the cursor: a block always starts where the cursor
//! is, so what has been handed out cannot be handed out again. Because a
//! delegate runs *this* type rather than a reimplementation, it gets that
//! property rather than promising it.
//!
//! And the remaining case is unchanged and still honest: a delegate running
//! **other** code is not a new attack but the old one — a dishonest issuer,
//! §4 — constrained by organization rather than by cryptography. What catches
//! it is the reconciliation of the closing report, which is a layer above.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::history::{AgentHistory, HistoryEntry};
use ksg_core_v2::canonical::doc_hash;
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{
    sign_doc, Ed25519Signer, KeySet, Profile, PublicKey, SignatureSet,
};
use ksg_core_v2::doc::{BlockAllocation, BlockClosure, Class, Range, Serial, Timestamp, Uri};

use crate::error::IssuerError;
use crate::issuer::{PacketTerms, DRAWDOWN_DEN, DRAWDOWN_NUM};

/// The state of one issuing role, for the operator to save.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerSnapshot {
    /// The emission being issued inside — its identifier, not the document. A
    /// delegate does not hold the release.
    pub emission: String,
    /// The range this role may issue within.
    pub range: Range,
    /// The next free serial.
    pub next_serial: u64,
    /// The blocks allocated, by holder, in order of allocation.
    pub allocated: BTreeMap<String, Vec<Range>>,
    /// The closures accepted: block start → closure hash.
    pub closures: BTreeMap<u64, Hash>,
    /// The class of each allocated block: block start → class.
    pub block_class: BTreeMap<u64, Class>,
    /// The hash of each block's allocation: block start → document hash.
    ///
    /// `serde(default)` because the field arrived with KS-1 §13 (CT-31) and a
    /// ledger saved before it is still a ledger. What it loses is the ability
    /// to draw up a history for blocks allocated back then — said plainly by
    /// [`Ledger::history`] rather than papered over with a zero hash.
    #[serde(default)]
    pub allocation_hash: BTreeMap<u64, Hash>,
}

/// Hands out consecutive blocks inside a range.
#[derive(Debug, Clone)]
pub struct Ledger {
    emission: String,
    range: Range,
    next_serial: u64,
    allocated: BTreeMap<String, Vec<Range>>,
    closures: BTreeMap<u64, Hash>,
    block_class: BTreeMap<u64, Class>,
    allocation_hash: BTreeMap<u64, Hash>,
}

impl Ledger {
    /// Opens a ledger over a range.
    ///
    /// # Errors
    ///
    /// [`IssuerError::CorruptSnapshot`] on an empty range — a role that may
    /// issue nothing is not a role, and letting one exist would mean every
    /// allocation had to check for it.
    pub fn open(emission: String, range: Range) -> Result<Self, IssuerError> {
        if range.is_empty() {
            return Err(IssuerError::CorruptSnapshot("the range is empty"));
        }
        Ok(Self {
            emission,
            range,
            next_serial: range.from.0,
            allocated: BTreeMap::new(),
            closures: BTreeMap::new(),
            block_class: BTreeMap::new(),
            allocation_hash: BTreeMap::new(),
        })
    }

    /// The range this role issues within.
    #[must_use]
    pub const fn range(&self) -> Range {
        self.range
    }

    /// The next free serial.
    #[must_use]
    pub const fn next_serial(&self) -> u64 {
        self.next_serial
    }

    /// The blocks allocated to a holder, in order of allocation.
    #[must_use]
    pub fn blocks_of(&self, holder: &Uri) -> &[Range] {
        self.allocated
            .get(holder.as_str())
            .map_or(&[], Vec::as_slice)
    }

    /// Allocates a block to a holder (§7).
    ///
    /// # Errors
    ///
    /// [`IssuerError::RangeExhausted`], [`IssuerError::PrevClosureRequired`],
    /// [`IssuerError::DrawdownTooLow`], [`IssuerError::ClosureForAnotherBlock`],
    /// or a core error while checking the closure.
    pub fn allocate(
        &mut self,
        holder: &Uri,
        prev_closure: Option<&BlockClosure>,
        signer: &Ed25519Signer,
        holder_keys: &KeySet,
        packet: PacketTerms,
    ) -> Result<BlockAllocation, IssuerError> {
        let PacketTerms {
            allocated_at,
            expires_at,
            class,
            block_size,
            // The period travels with the packet's terms; the ledger hands out
            // serials and does not anchor, so it has nothing to do with it.
            anchor_period_ms: _,
        } = packet;
        if block_size == 0 {
            return Err(IssuerError::Core(ksg_core_v2::error::Invalid::Schema(
                "block_size == 0",
            )));
        }
        let previous = self.blocks_of(holder).last().copied();

        // §7 rule 3 and rule 2 — both by way of the previous block's closure.
        let prev_hash = match (previous, prev_closure) {
            (None, _) => None,
            (Some(_), None) => return Err(IssuerError::PrevClosureRequired),
            (Some(prev), Some(closure)) => {
                if closure.block != prev {
                    return Err(IssuerError::ClosureForAnotherBlock);
                }
                // Drawdown is checked BEFORE the closure is accepted: otherwise
                // a failed allocation would leave the block closed, and the
                // second attempt would run into "already closed" instead of its
                // real cause. A failed operation does not change state.
                let used = count(&closure.used_submitted) + count(&closure.used_not_submitted);
                let size = prev.len();
                if used * DRAWDOWN_DEN < size * DRAWDOWN_NUM {
                    return Err(IssuerError::DrawdownTooLow { used, size });
                }
                self.accept_closure(closure, holder_keys)?;
                Some(doc_hash(closure)?)
            }
        };

        let from = self.next_serial;
        let to = from
            .checked_add(block_size - 1)
            .ok_or(IssuerError::RangeExhausted {
                last: from,
                limit: self.range.to.0,
            })?;
        // The bound is THIS role's range. For an issuer it is the release's; for
        // a delegate, the slice it was granted — which is where §5b's nesting
        // stops being a check on a document and becomes a thing that cannot be
        // done.
        if to > self.range.to.0 {
            return Err(IssuerError::RangeExhausted {
                last: from,
                limit: self.range.to.0,
            });
        }

        let block = Range {
            from: Serial(from),
            to: Serial(to),
        };
        let doc = BlockAllocation {
            context: ksg_core_v2::doc::Context,
            doc_type: "BlockAllocation".into(),
            v: ksg_core_v2::version::CURRENT_V,
            emission: self.emission.clone(),
            block,
            class,
            holder: holder.clone(),
            allocated_at,
            expires_at,
            prev_closure: prev_hash,
            signatures: SignatureSet::default(),
        };
        let sig = sign_doc(&doc, signer)?;
        let allocation = BlockAllocation {
            signatures: SignatureSet::new(vec![sig]),
            ..doc
        };

        // The cursor moves only forward, which is what makes double issuance
        // impossible rather than merely detected (KS-4 §5d).
        self.next_serial = to + 1;
        self.block_class.insert(from, class);
        // Kept at the moment of issue, not recomputed later: the document the
        // holder was given is the one the history must name, and a ledger that
        // rebuilt the hash from its own fields would name whatever it thinks
        // it issued (KS-1 §13).
        self.allocation_hash.insert(from, doc_hash(&allocation)?);
        self.allocated
            .entry(holder.as_str().to_string())
            .or_default()
            .push(block);

        Ok(allocation)
    }

    /// Accepts a closing allocation (§12).
    ///
    /// # Errors
    ///
    /// [`IssuerError::AlreadyClosed`] on a repeated close with different
    /// content; a core error on incorrect coverage.
    pub fn accept_closure(
        &mut self,
        closure: &BlockClosure,
        holder_keys: &KeySet,
    ) -> Result<Hash, IssuerError> {
        let key = closure.block.from.0;
        let hash = doc_hash(closure)?;
        if let Some(existing) = self.closures.get(&key) {
            if *existing != hash {
                return Err(IssuerError::AlreadyClosed { from: key });
            }
            return Ok(hash);
        }
        let class = self
            .block_class
            .get(&closure.block.from.0)
            .copied()
            .ok_or(IssuerError::ClosureForAnotherBlock)?;
        closure.validate(class, holder_keys, &Profile::default())?;
        self.closures.insert(key, hash);
        Ok(hash)
    }

    /// The state in full, for the operator to save.
    #[must_use]
    pub fn snapshot(&self) -> LedgerSnapshot {
        LedgerSnapshot {
            emission: self.emission.clone(),
            range: self.range,
            next_serial: self.next_serial,
            allocated: self.allocated.clone(),
            closures: self.closures.clone(),
            block_class: self.block_class.clone(),
            allocation_hash: self.allocation_hash.clone(),
        }
    }

    /// Restores from saved state, holding the three invariants.
    ///
    /// # Errors
    ///
    /// [`IssuerError::CorruptSnapshot`] if the cursor falls outside the range,
    /// if the allocated blocks overlap, or if the cursor is not past the last
    /// of them.
    pub fn restore(s: LedgerSnapshot) -> Result<Self, IssuerError> {
        if s.range.is_empty() {
            return Err(IssuerError::CorruptSnapshot("the range is empty"));
        }
        if s.next_serial < s.range.from.0 || s.next_serial > s.range.to.0 + 1 {
            return Err(IssuerError::CorruptSnapshot(
                "the cursor is outside the range",
            ));
        }
        let mut seen: Vec<Range> = s.allocated.values().flatten().copied().collect();
        seen.sort_by_key(|r| r.from.0);
        for w in seen.windows(2) {
            if w[1].from.0 <= w[0].to.0 {
                return Err(IssuerError::CorruptSnapshot("the allocated blocks overlap"));
            }
        }
        if let Some(last) = seen.last() {
            if last.to.0 >= s.next_serial {
                return Err(IssuerError::CorruptSnapshot(
                    "the cursor is not past the last allocated block",
                ));
            }
            if last.to.0 > s.range.to.0 || seen[0].from.0 < s.range.from.0 {
                return Err(IssuerError::CorruptSnapshot(
                    "an allocated block falls outside the range",
                ));
            }
        }
        Ok(Self {
            emission: s.emission,
            range: s.range,
            next_serial: s.next_serial,
            allocated: s.allocated,
            closures: s.closures,
            block_class: s.block_class,
            allocation_hash: s.allocation_hash,
        })
    }

    /// Draws up the signed list of a holder's blocks (KS-1 §13, CT-31 variant A).
    ///
    /// This is the issuer stating what its own records hold, and the document
    /// says so: it is additional evidence, never required. A container is
    /// verified without it exactly as before — only the claim "the whole
    /// history, across blocks" rests on this signature.
    ///
    /// # Errors
    ///
    /// [`IssuerError::NoBlocks`] if the holder has none;
    /// [`IssuerError::CorruptSnapshot`] if a block's allocation hash is
    /// missing, which happens for blocks issued before this ledger recorded
    /// them — the gap is reported rather than filled with a guess.
    pub fn history(
        &self,
        holder: &Uri,
        agent: &PublicKey,
        issued_at: Timestamp,
        signer: &Ed25519Signer,
    ) -> Result<AgentHistory, IssuerError> {
        let blocks = self.blocks_of(holder);
        if blocks.is_empty() {
            return Err(IssuerError::NoBlocks);
        }
        let mut entries = Vec::with_capacity(blocks.len());
        for b in blocks {
            let allocation =
                *self
                    .allocation_hash
                    .get(&b.from.0)
                    .ok_or(IssuerError::CorruptSnapshot(
                        "a block has no recorded allocation hash",
                    ))?;
            entries.push(HistoryEntry {
                emission: self.emission.clone(),
                block: *b,
                allocation,
            });
        }
        let doc = AgentHistory {
            context: ksg_core_v2::doc::Context,
            doc_type: "AgentHistory".into(),
            v: ksg_core_v2::version::CURRENT_V,
            holder: holder.clone(),
            agent: agent.clone(),
            blocks: entries,
            issued_at,
            signatures: SignatureSet::default(),
        };
        let sig = sign_doc(&doc, signer)?;
        Ok(AgentHistory {
            signatures: SignatureSet::new(vec![sig]),
            ..doc
        })
    }
}

fn count(ranges: &[Range]) -> u64 {
    ranges.iter().map(Range::len).sum()
}
