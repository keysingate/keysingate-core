//! Issuing an emission and keeping the sequence of allocations. Specification §5, §7, §12.

use std::collections::BTreeMap;

use crate::history::AgentHistory;
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{
    sign_doc, Ed25519Signer, KeySet, Profile, PublicKey, SignatureSet,
};
use ksg_core_v2::doc::{BlockAllocation, BlockClosure, Class, Emission, Range, Timestamp, Uri};
use serde::{Deserialize, Serialize};

use crate::error::IssuerError;

/// The fraction of the previous block below which a new one is not allocated (§7 rule 2).
///
/// The threshold is given as a numerator and a denominator rather than a
/// fraction: the comparison `used * 5 >= size * 4` is exact in integers, whereas
/// floating-point division depends on rounding and behaves differently at the
/// boundary for different block sizes. For a block of three serials, "80%" is
/// 2.4, and rounding would decide whether the next block is handed out.
pub(crate) const DRAWDOWN_NUM: u64 = 4;
pub(crate) const DRAWDOWN_DEN: u64 = 5;

/// The emission's terms — what the owner decides, not the protocol.
#[derive(Debug, Clone)]
pub struct Terms {
    /// The emission identifier, of the form `ksg:em:NNNNNN`.
    pub id: String,
    /// The declared range of serials.
    pub range: Range,
    /// The block's lifetime in days.
    pub block_ttl_days: u32,
    /// The issuer's identifier — an opaque URI.
    pub issuer: Uri,
}

/// The terms of one **packet** — a block of serials sold as a unit.
///
/// A separate type rather than four parameters, and the grouping is not
/// cosmetic: the class and the block size stopped being properties of the
/// release when they moved into the allocation, and these four are now exactly
/// what a packet is sold on. What belongs together in the document belongs
/// together in the call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketTerms {
    /// The moment of purchase — the origin of the packet's time (KS-2).
    pub allocated_at: Timestamp,
    /// The end of the packet's declared lifetime.
    pub expires_at: Timestamp,
    /// The class of the containers in this packet, not of the release.
    pub class: Class,
    /// How many serials the packet holds.
    pub block_size: u64,
    /// The aggregation period for this packet's anchors, in milliseconds (Ts-4).
    ///
    /// `None` is one anchor per event — what the code did before aggregation
    /// existed, and what a packet that was never sold a period keeps doing.
    /// `Some(ms)` puts the period's anchors under one root.
    ///
    /// **No default is chosen here.** The period is the trade between the blur
    /// and the precision of the time bound — a day of period buys a day of
    /// blur and costs a day of precision — and that trade is sold, not decided
    /// by the implementation. A default hidden in the code would price it for
    /// the customer silently.
    pub anchor_period_ms: Option<u64>,
}

/// The issuer's state in full.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuerSnapshot {
    /// The signed emission.
    pub emission: Emission,
    /// The next free serial.
    pub next_serial: u64,
    /// The blocks allocated, by holder, in order of allocation.
    pub allocated: BTreeMap<String, Vec<Range>>,
    /// The closures accepted: block start → closure hash.
    pub closures: BTreeMap<u64, Hash>,
    /// The class of each allocated block: block start → class.
    ///
    /// Kept because the class moved from the emission to the packet
    /// (2026-09-11): closing a block needs the class **that block** was issued
    /// under, not a release-wide one.
    #[serde(default)]
    pub block_class: BTreeMap<u64, Class>,
    /// The hash of each block's allocation: block start → document hash
    /// (KS-1 §13). `serde(default)` for the same reason as `block_class`: state
    /// saved before the field existed is still valid state.
    #[serde(default)]
    pub allocation_hash: BTreeMap<u64, Hash>,
}

/// The issuer: keeps the sequence of allocations for one emission.
#[derive(Debug, Clone)]
pub struct Issuer {
    emission: Emission,
    ledger: crate::ledger::Ledger,
}

impl Issuer {
    /// Issues an emission (§5).
    ///
    /// Printing the whole range costs **one** signature: blanks are derived from
    /// the emission deterministically and do not exist as separate documents.
    ///
    /// # Errors
    ///
    /// [`IssuerError::Core`] if the terms fail the §5 check, or if the emission
    /// does not sign.
    pub fn issue(
        terms: &Terms,
        signer: &Ed25519Signer,
        issued_at: Timestamp,
    ) -> Result<Self, IssuerError> {
        let doc = Emission {
            context: ksg_core_v2::doc::Context,
            doc_type: "Emission".into(),
            v: ksg_core_v2::version::CURRENT_V,
            id: terms.id.clone(),
            range: terms.range,
            block_ttl_days: terms.block_ttl_days,
            issuer: terms.issuer.clone(),
            issued_at,
            keys: vec![signer.public()],
            signatures: SignatureSet::default(),
        };
        let sig = sign_doc(&doc, signer)?;
        let emission = Emission {
            signatures: SignatureSet::new(vec![sig]),
            ..doc
        };
        emission.validate(&Profile::default())?;

        let ledger = crate::ledger::Ledger::open(emission.id.clone(), emission.range)?;
        Ok(Self { emission, ledger })
    }

    /// The emission that was issued.
    #[must_use]
    pub fn emission(&self) -> &Emission {
        &self.emission
    }

    /// The next free serial.
    #[must_use]
    pub fn next_serial(&self) -> u64 {
        self.ledger.next_serial()
    }

    /// The blocks allocated to a holder, in order of allocation.
    #[must_use]
    pub fn blocks_of(&self, holder: &Uri) -> &[Range] {
        self.ledger.blocks_of(holder)
    }

    /// The issuing role itself, for an operator that needs it directly.
    #[must_use]
    pub const fn ledger(&self) -> &crate::ledger::Ledger {
        &self.ledger
    }

    /// Allocates a block to a holder (§7).
    ///
    /// `prev_closure` is required from this holder's second block onward and
    /// serves two rules at once: it is the reference of §7 rule 3 and the proof
    /// of drawdown of §7 rule 2. There is no point separating them — the closure
    /// is what drawdown can be computed from reliably; a drawdown report without
    /// a closure would have to be taken on trust.
    ///
    /// The work is [`crate::Ledger::allocate`]'s. An issuer is an emission plus a
    /// ledger over the whole of it, and a delegate is the same ledger over a
    /// slice — which is the point of KS-4 §5c's separation.
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
        self.ledger
            .allocate(holder, prev_closure, signer, holder_keys, packet)
    }

    /// Draws up the signed list of a holder's blocks (KS-1 §13, CT-31).
    ///
    /// # Errors
    ///
    /// [`IssuerError::NoBlocks`] if the holder has none;
    /// [`IssuerError::CorruptSnapshot`] for a block issued before the ledger
    /// recorded allocation hashes.
    pub fn history(
        &self,
        holder: &Uri,
        agent: &PublicKey,
        issued_at: Timestamp,
        signer: &Ed25519Signer,
    ) -> Result<AgentHistory, IssuerError> {
        self.ledger.history(holder, agent, issued_at, signer)
    }

    /// Accepts a closing allocation (§12).
    ///
    /// # Errors
    ///
    /// [`IssuerError::AlreadyClosed`] on a repeated close — an accepted closure
    /// makes the absence of gaps proved, and a second, different one would undo
    /// what is already proved; a core error on incorrect coverage.
    pub fn accept_closure(
        &mut self,
        closure: &BlockClosure,
        holder_keys: &KeySet,
    ) -> Result<Hash, IssuerError> {
        self.ledger.accept_closure(closure, holder_keys)
    }

    /// The state in full, for the operator to save.
    #[must_use]
    pub fn snapshot(&self) -> IssuerSnapshot {
        let l = self.ledger.snapshot();
        IssuerSnapshot {
            emission: self.emission.clone(),
            next_serial: l.next_serial,
            allocated: l.allocated,
            closures: l.closures,
            block_class: l.block_class,
            allocation_hash: l.allocation_hash,
        }
    }

    /// Restores from saved state.
    ///
    /// # Errors
    ///
    /// [`IssuerError::CorruptSnapshot`] if the allocation cursor falls outside
    /// the emission or the allocated blocks overlap: handing out one serial
    /// twice is exactly what makes a blank re-incarnatable.
    pub fn restore(s: IssuerSnapshot) -> Result<Self, IssuerError> {
        s.emission.validate(&Profile::default())?;
        // The three invariants belong to the issuing role and are checked
        // there — by the same code a delegate restores through, so a delegate's
        // saved state is held to exactly the issuer's standard rather than to
        // whatever its own implementation remembered to check.
        let ledger = crate::ledger::Ledger::restore(crate::ledger::LedgerSnapshot {
            emission: s.emission.id.clone(),
            range: s.emission.range,
            next_serial: s.next_serial,
            allocated: s.allocated,
            closures: s.closures,
            block_class: s.block_class,
            allocation_hash: s.allocation_hash,
        })?;
        Ok(Self {
            emission: s.emission,
            ledger,
        })
    }
}
