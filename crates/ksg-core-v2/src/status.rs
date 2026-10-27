//! The container's status and the transitions between statuses. KS-7 §7.
//!
//! # The table is flat, and closed by a default
//!
//! KS-7 §7.2-bis lists one row per transition; §7.2-ter closes everything else:
//!
//! > A "status × event" pair not listed **MUST** yield a refusal. An
//! > implementation **MUST NOT** leave it without a definite outcome.
//!
//! An empty cell is not "nothing happens" — it is a hole one falls into when
//! not expecting it. Here the default is the `_ => Refused` arm of one `match`,
//! and completeness is checked by enumeration in the tests, not by eye.
//!
//! # What is irreversible is the RECORD, not the state
//!
//! KS-7 §7.2-quater. Statuses **accumulate the way keys do**: the section keeps
//! every status ever set, and the current one is the last. Status 31 stays in
//! the history forever and can still be overlaid by 34 — so "irreversible"
//! belongs to the record, and a type that modelled the status as one replaceable
//! value would have no way to say that.
//!
//! Hence [`StatusHistory`] rather than a bare field.
//!
//! # Nothing decides anything inside the container
//!
//! Every transition here is driven by an event presented at a button, or by a
//! deadline running out. There is no rule of the form "the client chooses
//! whether to record the loss": the record of 30 carries its own review
//! deadline, and when it passes without 31 or 32 the container **blocks**. A
//! timer, not good will (KS-7 §7.2-bis, T-B15).

use crate::doc::Class;
use crate::error::Invalid;

/// A container status. KS-8 part J; KS-7 §7.1.
///
/// The numbers are normative and are the reason this is not a plain sequence:
/// 8 and 33 are reserved blanks with no transitions, and the dispute statuses
/// start at 30, leaving the gap deliberately.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(into = "u8", try_from = "u8")]
#[repr(u8)]
pub enum Status {
    /// 0 — the serial exists because the release was printed.
    Printed = 0,
    /// 1 — the packet's layer is on: the serial was sold inside a packet.
    Packeted = 1,
    /// 2 — the buyer's key is on. Issuer's and buyer's keys, still a template.
    BuyerKeyed = 2,
    /// 3 — a sub-agent's key is on: a dealer of the distributor.
    SubAgentKeyed = 3,
    /// 4 — initiated. The container is born: client agent's key and artifact,
    /// laid on at one and the same moment.
    Initiated = 4,
    /// 5 — in work.
    InWork = 5,
    /// 6 — finalized: sealed "with cement", kept but never added to.
    Finalized = 6,
    /// 7 — fully exported in a dispute. The container validates nothing after
    /// it; the records stay provable by their own anchors.
    Exported = 7,
    /// 8 — a reserved blank. No transitions, by decision of 10.09.
    Reserved8 = 8,
    /// 9 — the container was lost: the medium broke. Declared by the client's
    /// last anchored key and published in the chain.
    Lost = 9,
    /// 10 — dead, never activated: the packet's term ran out.
    Expired = 10,
    /// 12 — the journal is **voluntarily opened**.
    ///
    /// `[decision] 11.09` The container stops keeping the pages' secrets: the work —
    /// pages with their dates and times — may be read by anyone who anchors
    /// their own key. Signatures, keys and registrations stay secret.
    ///
    /// Reached only through a declaration by the client and the owner published
    /// in the chain, witnessed by two arbiters. It is **not** the full export:
    /// that is 7 and kills the container. This one leaves it working.
    Opened = 12,
    /// 20 — invalid: initiation was **attempted** after the packet's term.
    /// Differs from 10 in that there it was never attempted at all.
    ActivatedTooLate = 20,
    /// 22 — the client agent's key is lost and the content rots.
    KeyLost = 22,
    /// 30 — under dispute. A claim was handed to the container, anchored in the
    /// chain; the container never learns of it by itself.
    ///
    /// A **working** status (T-21): work goes on under it. What it records is
    /// that something happened to the rights over the artifact — which is why
    /// the container does not fall back to 5 afterwards.
    Disputed = 30,
    /// 31 — disputed and proven. Permanent as a record; may be overlaid by 34.
    /// Rights to the artifact pass to the claimant's ID.
    DisputeProven = 31,
    /// 32 — disputed, not proven.
    ///
    /// A **working** status, as 30 is. The path 5 → 30 → 32 is the record that
    /// the rights were contested and the claim failed; a return to 5 would
    /// erase it, which is why T-21 resolved the way it did.
    DisputeUnproven = 32,
    /// 33 — a reserved blank, as 8 is.
    Reserved33 = 33,
    /// 34 — under appeal against 31.
    Appealed = 34,
    /// 35 — **settled between the two sides**. `[decision] 12.09`
    ///
    /// "Shook hands on it": the claimant and the owner agreed, and the dispute
    /// ends without an arbiter. A **working** status — the container is not
    /// blocked and the work goes on.
    ///
    /// **What was agreed is not published.** The rights may stay, may pass, may
    /// become shared, may be anything the two of them wrote down; `[decision]` it is
    /// their private business. The container records **that** they settled and
    /// the digest of the terms, never the terms — so either of them can later
    /// prove what was agreed, and nobody else learns it from the container.
    Settled = 35,
    /// 21 — **died of prescription**: twelve years blocked with no decision.
    ///
    /// `[inference]` **The number is the executor's** (18.09, `KS-2` §7;
    /// `Reestr_resheniy`: T-38, KS-8 row 21) — the owner said "moves to dead
    /// status" without naming one. 21 is chosen because the twenties are the decade
    /// of deaths off the path (20 too late, 22 the key lost) and 21 is the only
    /// free place in it. One constant to change if the owner names another.
    ///
    /// `[inference]` **Not 22, and not 9.** A status records **why**, and this is a
    /// third reason: the key may be intact and the container may be in hand —
    /// what ran out is the time in which anyone could still decide the dispute.
    Prescribed = 21,
}

impl Status {
    /// Terminal statuses: there is no successor at all (KS-7 §7.2-quater).
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Exported
                | Self::Lost
                | Self::Expired
                | Self::ActivatedTooLate
                | Self::KeyLost
                | Self::Prescribed
        )
    }

    /// Reads back a status from its normative number.
    ///
    /// # Errors
    ///
    /// [`Invalid::Schema`] on a number that names no status — including the
    /// gaps, which are gaps on purpose: 11 and 13 through 19 are not statuses,
    /// and a document carrying one is not a document about a status this
    /// implementation knows.
    pub fn from_number(n: u8) -> Result<Self, Invalid> {
        Self::all()
            .iter()
            .copied()
            .find(|s| s.number() == n)
            .ok_or(Invalid::Schema("no such status"))
    }

    /// A working status: work records are accepted under it.
    ///
    /// **Every dispute status works**: 30, 31, 32 and 34 stand here beside 5 by
    /// the owner's decisions of 11.09. They are not interruptions of the work
    /// but marks on it — that the rights over the artifact were contested, and
    /// how that went.
    ///
    /// 31 included — the case that looks wrong until the reason is stated — and
    /// 34 by the same algorithm: the rights have passed to the claimant, but for the agent to
    /// **stop** there must be an explicit prohibition from that claimant. With
    /// no such declaration the agent may lawfully go on working, by the norms of
    /// its jurisdiction. And once a prohibition is published or served, obeying
    /// it is the responsibility of the client and the owner — **never of the
    /// container**, which knows nothing of jurisdictions and must not pretend
    /// to. See [`Event::FreezeOnOwnerApplication`] for what the owner does have.
    ///
    /// # What makes a container a working one
    ///
    /// `[decision] 11.09` A working container **MUST** carry **record 0 of the
    /// client's key and journal record 0**. That is the whole difference
    /// between 4 and 5: at 4 the client's key is laid on but the zero journal
    /// record is not yet written, so the container is a finished asset — it can
    /// be registered further, sold and resold — and is **not valid for work**.
    ///
    /// The condition is about the container's content, so it cannot be checked
    /// from a status alone: the container checks it — E-OpenJournal, the only
    /// event from 4 to 5, must carry page 0 of the journal
    /// (`ksg-container-v2`, `Container::press`, step 7). Written down here
    /// because the rule is what the refusal of succession from 4 rests on, and
    /// a rule kept only in the reason string of one arm is a rule that gets
    /// lost.
    #[must_use]
    pub const fn is_working(self) -> bool {
        matches!(
            self,
            Self::InWork
                | Self::Opened
                | Self::Disputed
                | Self::DisputeProven
                | Self::DisputeUnproven
                | Self::Appealed
                | Self::Settled
        )
    }

    /// A reserved blank: a place held open, with no transitions in or out.
    #[must_use]
    pub const fn is_reserved(self) -> bool {
        matches!(self, Self::Reserved8 | Self::Reserved33)
    }

    /// The normative number.
    #[must_use]
    pub const fn number(self) -> u8 {
        self as u8
    }

    /// Every status, for the exhaustiveness checks of §7.2 and §14.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Printed,
            Self::Packeted,
            Self::BuyerKeyed,
            Self::SubAgentKeyed,
            Self::Initiated,
            Self::InWork,
            Self::Finalized,
            Self::Exported,
            Self::Reserved8,
            Self::Opened,
            Self::Lost,
            Self::Expired,
            Self::ActivatedTooLate,
            Self::KeyLost,
            Self::Disputed,
            Self::DisputeProven,
            Self::DisputeUnproven,
            Self::Reserved33,
            Self::Appealed,
            Self::Settled,
            Self::Prescribed,
        ]
    }
}

/// An event presented to the container. KS-8 part E, with the deadlines of
/// KS-7 §7.2-bis added.
///
/// Deadlines are events too, and deliberately so: T-23 and T-29 are transitions
/// driven by time running out, and modelling them as anything but an event
/// would put a decision back inside the container.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum Event {
    /// E-1 — the release is printed.
    PrintRelease,
    /// E-2 — the packet's layer goes on.
    ApplyPacket,
    /// E-3 — the buyer's key goes on.
    ApplyBuyerKey,
    /// E-3 — a sub-agent's key goes on.
    ApplySubAgentKey,
    /// E-4 — final initiation, within the packet's term.
    Initiate,
    /// E-4 — initiation attempted **after** the packet's term (T-16).
    InitiateTooLate,
    /// The journal is opened: **record №0** is written.
    ///
    /// Not a work record but the certificate of the journal's start, fixing
    /// what makes this journal unique. Work records begin at **№1**.
    OpenJournal,
    /// E-5 — a work record, №1 and up.
    RecordWork,
    /// E-6 · E-7 · E-8 — artifact, disposition, rights.
    RecordArtifactOrRights,
    /// E-9 — ownership is handed on.
    TransferOwnership,
    /// E-10 — the class is raised.
    RaiseClass,
    /// E-11 — full export, button 3.
    FullExport,
    /// E-13 — finalization, by the issuer's button.
    Finalize,
    /// The journal is opened voluntarily — status **12**.
    ///
    /// Carried by a declaration of the client and the owner published in the
    /// chain, witnessed by two arbiters (`ksg-journal::voluntary`).
    OpenVoluntarily,
    /// E-23 — the issuer freezes the container on the **owner's application**.
    ///
    /// The one lever the owner has when a prohibition on working with the
    /// artifact is served: the issuer's signature together with the owner's
    /// key, in one command, and the container goes to 6. Priced like succession
    /// — ×10, no less than $10 (KS-8 E-14).
    ///
    /// Distinct from E-13, which is the issuer's button alone. Here it takes
    /// two parties, because the owner is asking for something done to a
    /// container that is working and lawful.
    FreezeOnOwnerApplication,
    /// E-14 — succession, when the **owner's** key is lost.
    ///
    /// Not a death: the issuer's final signature freezes this container and a
    /// new one is coupled in front of it, carrying the client's current key and
    /// a new owner key. This container becomes the archive the new one pulls
    /// behind it. The loss that kills is the **client's** key (E-15) or the
    /// medium (E-19); losing the owner's key is a paid transplant.
    Succeed,
    /// E-15 — death declared: the client agent's key is lost.
    DeclareKeyLost,
    /// E-19 — the container is declared lost.
    DeclareContainerLost,
    /// E-19 — a claim of dispute is handed over.
    ServeDispute,
    /// E-20 — decision: proven.
    DisputeProven,
    /// E-21 — decision: not proven.
    DisputeUnproven,
    /// E-22 — an appeal against 31.
    Appeal,
    /// The appeal was won: the status stays 34.
    AppealWon,
    /// The appeal was lost: 31 becomes current again.
    AppealLost,
    /// The review deadline is moved; a new one is written in (T-24).
    ExtendReview,
    /// The review deadline ran out with none of 31, 32, 34 or 35 (T-23, T-29).
    ReviewDeadlinePassed,
    /// The two sides settled — status 35. `[decision] 12.09`
    Settle,
    /// Twelve years passed with the container blocked and no decision. `[decision] 12.09`
    PrescriptionPassed,
    /// The packet's term ran out on a container that was never activated (T-15).
    PacketTermExpired,
}

/// What an event does to a container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The status becomes this one.
    Moves(Status),
    /// The status does not change: the event is recorded and the container
    /// stays where it is.
    Stays,
    /// The container blocks. Only a decision — 31 or 32 — unblocks it (T-25).
    Blocks,
    /// Refused. Either an explicit refusal of §7.2-bis, or the default of
    /// §7.2-ter: a pair not listed has no other outcome.
    Refused(&'static str),
}

/// Whether the container is blocked, and for what.
///
/// Not a status: blocking is not one of the normative numbers, and making it
/// one would have invented a number the owner never assigned. It is a property
/// the record of 30 (or of 34) carries with it until a decision arrives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Blocked {
    /// Not blocked.
    No,
    /// Blocked: a review deadline passed with no decision (T-23, T-29).
    AwaitingDecision,
}

/// The status section: every status ever set, in order.
///
/// A history and not a field, because §7.2-quater says the **record** is what
/// cannot be revoked while the state may be overlaid. The two cannot be told
/// apart by a type that keeps only the latest value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusHistory {
    layers: Vec<Status>,
    blocked: Blocked,
}

impl StatusHistory {
    /// A container at the moment its release was printed.
    #[must_use]
    pub fn new() -> Self {
        Self {
            layers: vec![Status::Printed],
            blocked: Blocked::No,
        }
    }

    /// The current status: the last layer.
    #[must_use]
    pub fn current(&self) -> Status {
        // The history is built with status 0 and never shrinks.
        self.layers.last().copied().unwrap_or(Status::Printed)
    }

    /// Every status ever set, oldest first. A record here is never removed.
    #[must_use]
    pub fn layers(&self) -> &[Status] {
        &self.layers
    }

    /// Whether this status was ever set — the question §7.2-quater makes
    /// meaningful, since 31 stays true of a container that now reads 34.
    #[must_use]
    pub fn ever(&self, status: Status) -> bool {
        self.layers.contains(&status)
    }

    /// Whether the container is blocked.
    #[must_use]
    pub const fn blocked(&self) -> Blocked {
        self.blocked
    }

    /// Applies an event, appending a layer if the status moves.
    ///
    /// # Errors
    ///
    /// [`Invalid::StatusRefused`] when the pair yields a refusal — whether an
    /// explicit one of §7.2-bis or the default of §7.2-ter.
    pub fn apply(&mut self, event: Event) -> Result<Outcome, Invalid> {
        self.apply_for(Class::Heavy, event)
    }

    /// Applies an event for a container of the class given, appending a layer
    /// if the status moves.
    ///
    /// Goal 1, `bare` v2 (owner's decision 08.10): `bare` has no packet (K5)
    /// and its distributor is optional (K6), so it leaves `Printed` straight
    /// to the buyer's key or straight to initiation. Every other class goes
    /// through [`transition`] unchanged, and so does every other pair — which
    /// is why [`StatusHistory::apply`] stays as the Pro default.
    ///
    /// # Errors
    ///
    /// [`Invalid::StatusRefused`] when the pair yields a refusal — whether an
    /// explicit one of §7.2-bis or the default of §7.2-ter.
    pub fn apply_for(&mut self, class: Class, event: Event) -> Result<Outcome, Invalid> {
        let outcome = transition_for(class, self.current(), self.blocked, event);
        match outcome {
            Outcome::Moves(next) => {
                self.layers.push(next);
                // A decision unblocks (T-25); nothing else does.
                if matches!(next, Status::DisputeProven | Status::DisputeUnproven) {
                    self.blocked = Blocked::No;
                }
            }
            Outcome::Blocks => self.blocked = Blocked::AwaitingDecision,
            Outcome::Stays => {}
            Outcome::Refused(why) => return Err(Invalid::StatusRefused(why)),
        }
        Ok(outcome)
    }
}

impl Default for StatusHistory {
    fn default() -> Self {
        Self::new()
    }
}

/// The transition table of KS-7 §7.2-bis, closed by the default of §7.2-ter.
///
/// Every arm carries the row it implements, so a reader can hold the table and
/// the code side by side. The final arm is the closing rule, and it is the only
/// thing standing between this function and an empty cell.
#[must_use]
pub fn transition(from: Status, blocked: Blocked, event: Event) -> Outcome {
    use Event as E;
    use Status as S;

    // A blocked container takes only a decision (T-25), a settlement, or the
    // passage of twelve years. Checked before the table, not inside it: blocking
    // cuts across every row, and spreading it through the arms would mean
    // remembering it in each one.
    //
    // `[decision]` 12.09 added the second and the third. The settlement, because the two
    // sides may still shake hands after the block — the block punishes silence,
    // and they have stopped being silent. The prescription, because it happens
    // **precisely while blocked**: refusing it here would have made the twelve
    // years unreachable, and the container would wait for a decision forever.
    if blocked == Blocked::AwaitingDecision {
        return match event {
            E::DisputeProven => Outcome::Moves(S::DisputeProven),
            E::DisputeUnproven => Outcome::Moves(S::DisputeUnproven),
            E::Settle => Outcome::Moves(S::Settled),
            E::PrescriptionPassed => Outcome::Moves(S::Prescribed),
            _ => Outcome::Refused("the container is blocked; only a decision unblocks it"),
        };
    }

    match (from, event) {
        // T-02 — the packet's layer goes on.
        (S::Printed, E::ApplyPacket) => Outcome::Moves(S::Packeted),
        // T-03 — the buyer's key.
        (S::Packeted, E::ApplyBuyerKey) => Outcome::Moves(S::BuyerKeyed),
        // T-04 — a sub-agent's key.
        (S::BuyerKeyed, E::ApplySubAgentKey) => Outcome::Moves(S::SubAgentKeyed),
        // T-05, T-06 — initiation, from a buyer's or a sub-agent's template.
        (S::BuyerKeyed | S::SubAgentKeyed, E::Initiate) => Outcome::Moves(S::Initiated),
        // T-16 — initiation attempted after the packet's term.
        (S::Packeted | S::BuyerKeyed | S::SubAgentKeyed, E::InitiateTooLate) => {
            Outcome::Moves(S::ActivatedTooLate)
        }
        // T-15 — the term ran out on a container never activated.
        (S::Packeted | S::BuyerKeyed | S::SubAgentKeyed, E::PacketTermExpired) => {
            Outcome::Moves(S::Expired)
        }
        // T-07, restated 11.09 — what moves 4 → 5 is the journal OPENING.
        //
        // Record №0 is not work: it is the certificate that the journal
        // started. Work begins at №1, and by then the container already reads
        // 5. This is also what tells 4 from 5 at all — a working container must
        // carry journal record 0, and at 4 the journal is not open, so the
        // container is a finished asset rather than a working one.
        (S::Initiated, E::OpenJournal) => Outcome::Moves(S::InWork),
        // A work record before the journal is open has no number to take: №1
        // presupposes №0.
        (S::Initiated, E::RecordWork) => {
            Outcome::Refused("the journal is not open: record 0 has not been written")
        }
        // The journal opens once. Its record №0 is what makes it this journal.
        (
            S::InWork
            | S::Finalized
            | S::Opened
            | S::Disputed
            | S::DisputeProven
            | S::DisputeUnproven
            | S::Appealed
            | S::Settled,
            E::OpenJournal,
        ) => Outcome::Refused("the journal is already open"),
        // T-08 — further work records keep it in work.
        (S::InWork, E::RecordWork) => Outcome::Stays,
        // T-09, T-10, T-11 — records that do not change the state.
        (S::InWork, E::RecordArtifactOrRights | E::TransferOwnership | E::RaiseClass) => {
            Outcome::Stays
        }
        // T-12 — finalization.
        (S::InWork | S::Opened, E::Finalize) => Outcome::Moves(S::Finalized),
        // T-B3, settled 11.09 — E-14 succession leaves the OLD container at 6.
        //
        // Derived, not chosen, and the derivation closes: the old container
        //   * stays **valid** — the client's key is untouched, so 9, 22, 10 and
        //     20 are all out, and each would record a false cause besides;
        //   * takes **no more work** — the work goes on in the new container, so
        //     5, 30 and 32 are out;
        //   * must still allow a **full export** on the client's key, which
        //     is what keeps it worth attaching at all.
        //
        // Exactly one status satisfies all three: 6 permits E-11 (T-14) and
        // nothing else non-terminal and non-working does. It agrees with the
        // wording too — E-13 finalizes by the issuer's button, and E-14 is the
        // issuer's "final signature".
        //
        // The link to the successor is NOT recorded here. It lives in the new
        // container, which is coupled in front and points back; giving the old
        // one a status of its own for "has a successor" would invent a number
        // the owner never assigned.
        (
            S::InWork
            | S::Opened
            | S::Disputed
            | S::DisputeProven
            | S::DisputeUnproven
            | S::Appealed
            | S::Settled,
            E::Succeed,
        ) => Outcome::Moves(S::Finalized),
        // T-33, settled 11.09 — succession from an already-frozen container.
        //
        // Allowed, and the old one does not move: it is already at 6. The new
        // container is working and current, and it does NOT start from zero —
        // it continues the work already fixed in this one. Coupling behind an
        // archive is the same act as coupling behind a container that has just
        // been frozen; that the freezing happened earlier changes nothing.
        (S::Finalized, E::Succeed) => Outcome::Stays,
        // T-13, T-14 — full export, from work or from storage.
        //
        // The dispute statuses belong here too, and their absence made the
        // export **unreachable exactly where the specification puts it**:
        // the export mechanism is about the export in a dispute, and
        // the table refused it from 30, 31, 32, 34 and 35 (security audit of
        // 2026-09-13, finding 14). A container under dispute is a working
        // container, and what the dispute changes is **who may press the
        // button**, not whether the operation exists.
        (
            S::InWork
            | S::Opened
            | S::Finalized
            | S::Disputed
            | S::DisputeProven
            | S::DisputeUnproven
            | S::Appealed
            | S::Settled,
            E::FullExport,
        ) => Outcome::Moves(S::Exported),
        // T-17, T-30 — death by a lost client key; finalization forbids
        // additions, and a declaration of death is not an addition.
        (S::Initiated | S::InWork | S::Opened | S::Finalized, E::DeclareKeyLost) => {
            Outcome::Moves(S::KeyLost)
        }
        // T-22 — the container itself is declared lost.
        (S::Initiated | S::InWork | S::Opened | S::Finalized, E::DeclareContainerLost) => {
            Outcome::Moves(S::Lost)
        }
        // T-18 — a dispute is handed over.
        (S::Initiated | S::InWork | S::Opened | S::Finalized, E::ServeDispute) => {
            Outcome::Moves(S::Disputed)
        }
        // T-19, T-20 — the decision.
        (S::Disputed, E::DisputeProven) => Outcome::Moves(S::DisputeProven),
        (S::Disputed, E::DisputeUnproven) => Outcome::Moves(S::DisputeUnproven),
        // T-24 — the review deadline is moved.
        (S::Disputed | S::Appealed, E::ExtendReview) => Outcome::Stays,
        // T-23, T-29 — the deadline passed with no decision. `[decision]` 12.09 added
        // a fourth way out: the two sides settling (35). The block is what the
        // silence costs, and it falls on whoever was silent.
        (S::Disputed | S::Appealed, E::ReviewDeadlinePassed) => Outcome::Blocks,
        // `[decision]` 12.09 — "shook hands on it". Available from either open dispute
        // state, and from neither decided one: a settlement ends a dispute, it
        // does not reopen a decision.
        (S::Disputed | S::Appealed, E::Settle) => Outcome::Moves(S::Settled),
        // `[decision]` 12.09 — twelve years blocked, and the container dies of its own
        // accord. Nobody presses this: the deadline is in the record, and any
        // reader with a calendar can see it has passed.
        (S::Disputed | S::Appealed, E::PrescriptionPassed) => Outcome::Moves(S::Prescribed),
        // T-26 — an appeal against 31.
        (S::DisputeProven, E::Appeal) => Outcome::Moves(S::Appealed),
        // T-27 — the appeal is won: it stays 34.
        (S::Appealed, E::AppealWon) => Outcome::Stays,
        // T-28 — the appeal is lost: 31 becomes current again.
        (S::Appealed, E::AppealLost) => Outcome::Moves(S::DisputeProven),
        // T-21, settled by the owner on 11.09: the status reads **32**, not 5.
        //
        // 30 and 32 are WORKING statuses, and that is the point of them: the
        // path 5 → 30 → 32 records that something happened to the rights over
        // the artifact, and a container that fell back to 5 would erase exactly
        // that — keeping the work and losing what makes it worth anything.
        // T-21-ter, settled 11.09: **31 does not block, and neither does 34** —
        // the owner confirmed 34 follows the same algorithm as 31.
        //
        // Nothing in a dispute stops the work, because stopping is not the
        // container's job: a prohibition on working with the artifact is
        // answered by the client and the owner, outside. What the owner has
        // instead is E-23 below.
        (
            S::Opened
            | S::Disputed
            | S::DisputeProven
            | S::DisputeUnproven
            | S::Appealed
            | S::Settled,
            E::RecordWork | E::RecordArtifactOrRights | E::RaiseClass,
        ) => Outcome::Stays,
        // T-36, `[decision]` 11.09 — the journal is opened voluntarily.
        //
        // From anywhere work is going on, and from 6: a frozen container still
        // has a journal worth reading, and opening it adds nothing to it.
        (
            S::InWork
            | S::Finalized
            | S::Disputed
            | S::DisputeProven
            | S::DisputeUnproven
            | S::Appealed
            | S::Settled,
            E::OpenVoluntarily,
        ) => Outcome::Moves(S::Opened),
        // An open journal opens once. A second opening would change nothing and
        // would put a second record of the same fact in the section.
        (S::Opened, E::OpenVoluntarily) => Outcome::Refused("the journal is already open"),
        // T-35 — the issuer freezes on the owner's application (E-23).
        //
        // Allowed from anywhere work is going on, which is the only place
        // freezing means anything: what is already at 6 is frozen and what is
        // terminal is past freezing.
        (
            S::InWork
            | S::Opened
            | S::Disputed
            | S::DisputeProven
            | S::DisputeUnproven
            | S::Appealed
            | S::Settled,
            E::FreezeOnOwnerApplication,
        ) => Outcome::Moves(S::Finalized),
        // O-07, O-08 withdrawn 10.09: alienating the CONTAINER is allowed under
        // 30, 31 and 34. The dispute is over rights to the artifact, not over
        // the thing.
        (
            S::Opened
            | S::Disputed
            | S::DisputeProven
            | S::DisputeUnproven
            | S::Appealed
            | S::Settled,
            E::TransferOwnership,
        ) => Outcome::Stays,

        // --- explicit refusals of §7.2-bis ---
        // O-01 — after finalization there are never any additions.
        (
            S::Finalized,
            E::RecordWork
            | E::RecordArtifactOrRights
            | E::TransferOwnership
            | E::RaiseClass
            | E::Finalize,
        ) => Outcome::Refused("after finalization the container takes no additions"),
        // O-02 — after a full export the container validates nothing.
        (S::Exported, _) => Outcome::Refused("the container was fully exported"),
        // O-03 — out of the path for good.
        (S::Lost | S::Expired | S::ActivatedTooLate | S::KeyLost, _) => {
            Outcome::Refused("the status is terminal")
        }
        // T-34, settled 11.09 — succession from 4 is refused.
        //
        // Status 4 is not valid FOR WORK. A container at 4 is a finished asset:
        // it can be registered further, sold and resold. It cannot work, and
        // there is therefore no fixed work for a successor to continue.
        //
        // The rule behind it is general and larger than succession
        // (see `is_working`): a working container must carry **record 0 of the
        // client's key and journal record 0**. At 4 the key is on and the zero
        // journal record is not yet written — which is exactly the difference
        // between 4 and 5, and the reason 4 exists as a status of its own.
        (S::Initiated, E::Succeed) => {
            Outcome::Refused("status 4 is not valid for work: there is no fixed work to continue")
        }
        // O-04 — the container is not born yet.
        (S::Printed | S::Packeted | S::BuyerKeyed | S::SubAgentKeyed, E::RecordWork) => {
            Outcome::Refused("the container is not born yet")
        }
        // O-05 — the packet goes on before birth.
        (S::Initiated | S::InWork, E::ApplyPacket) => {
            Outcome::Refused("the packet's layer goes on before birth")
        }
        // O-06 — initiation happens once.
        (S::Initiated | S::InWork, E::Initiate) => Outcome::Refused("initiation happens once"),
        // Reserved blanks have no transitions at all, in or out.
        (S::Reserved8 | S::Reserved33, _) => {
            Outcome::Refused("a reserved status has no transitions")
        }

        // §7.2-ter — the closing rule. Without this arm the table would have
        // empty cells, and an empty cell is a hole one falls into when not
        // expecting it.
        _ => Outcome::Refused("no such transition"),
    }
}

/// The class-aware entry. `bare` has no packet (K5) and its distributor is optional (K6),
/// so it leaves `Printed` straight to the buyer's key or straight to initiation.
/// A full export does not block a `bare` container (`bare` spec §4): where
/// Pro moves to `Exported`, `bare` stays. Every other class, and every other
/// pair, goes through `transition` unchanged.
///
/// Goal 1, `bare` v2 (owner's decision 08.10). [`transition`] itself is not
/// touched: the table-pinning tests keep reading it as the Pro table.
#[must_use]
pub fn transition_for(class: Class, from: Status, blocked: Blocked, event: Event) -> Outcome {
    if class == Class::Bare && blocked == Blocked::No && from == Status::Printed {
        match event {
            Event::ApplyBuyerKey => return Outcome::Moves(Status::BuyerKeyed),
            Event::Initiate => return Outcome::Moves(Status::Initiated),
            _ => {}
        }
    }
    let outcome = transition(from, blocked, event);
    // Goal 1, step G1-4 (`bare` spec §4): the whole-journal export leaves
    // a `bare` container working — Pro's move to `Exported` (status 7) becomes
    // a stay. Anything Pro refuses stays refused: the arm below only rewrites
    // the one move, never a refusal.
    if class == Class::Bare && outcome == Outcome::Moves(Status::Exported) {
        return Outcome::Stays;
    }
    outcome
}

/// The status a verification refusal leaves the container in, where the owner
/// decided on a state rather than a bare refusal.
///
/// Two refusals have such a state, and both are about a container that never
/// legitimately came into being:
///
/// * [`Invalid::ActivationAfterExpiry`] → **20** (T-16), initiation attempted
///   after the packet's term;
/// * [`Invalid::Expired`] → **10** (T-15), the term ran out with no attempt.
///
/// Every other refusal is a refusal and nothing more: returning `None` says
/// that, rather than inventing a status the specification does not name.
///
/// This exists because `error.rs` promised it — "when statuses land in the
/// implementation this maps to status 20". A mapping written in a comment is a
/// mapping nobody can check.
#[must_use]
pub const fn status_after(refusal: &Invalid) -> Option<Status> {
    match refusal {
        Invalid::ActivationAfterExpiry => Some(Status::ActivatedTooLate),
        Invalid::Expired => Some(Status::Expired),
        _ => None,
    }
}

/// Whether a signer should put its signature to this event, reading the status
/// the container currently carries.
///
/// `[decision] 11.09` The current status **MUST** be readable by the **issuer** at the
/// moment it signs, and by the **owner** at the moment it signs: a status that
/// does not match what the signature is for means the party does not sign.
///
/// # Why this exists when `transition` would refuse anyway
///
/// Because refusing afterwards is not the same as not signing. A signature
/// already given is a fact in the world — it can be kept, replayed, or shown to
/// someone who never runs the check. The refusal comes from the verifier, and
/// the verifier is not always the next party to look.
///
/// So the check runs **twice on purpose**: here, before the ink, and again in
/// `transition` when the document is verified. The container's status section
/// is what makes the first of those possible, which is the reason it has to be
/// readable — the one thing inside a sealed container that is read rather than
/// only written to.
#[must_use]
pub fn may_sign(current: Status, blocked: Blocked, event: Event) -> bool {
    !matches!(transition(current, blocked, event), Outcome::Refused(_))
}

/// Whether a signer should put its signature to this event for a container of
/// the class given. Goal 1, `bare` v2: the class-aware twin of [`may_sign`];
/// [`may_sign`] itself stays as the Pro default.
#[must_use]
pub fn may_sign_for(class: Class, current: Status, blocked: Blocked, event: Event) -> bool {
    !matches!(
        transition_for(class, current, blocked, event),
        Outcome::Refused(_)
    )
}

impl From<Status> for u8 {
    fn from(s: Status) -> Self {
        s.number()
    }
}

impl TryFrom<u8> for Status {
    type Error = Invalid;
    fn try_from(n: u8) -> Result<Self, Invalid> {
        Self::from_number(n)
    }
}
