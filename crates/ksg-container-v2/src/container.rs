//! The container as one thing: the parts held together, and the cycle that
//! walks a presented event through every rule. KS-7 §3.3, KS-9.
//!
//! # Why this module exists
//!
//! Before it, every rule in this crate was correct and **called by nothing but
//! its own tests**. A caller could attach the wrong artefact, serve a dispute
//! with no copy of the claim, write work with no order, or move a status
//! without a record — not because a rule was missing, but because nothing
//! stood between the caller and the parts.
//!
//! `[decision] 12.09`, the owner: "all default conditions, triggers, states, changes and starts
//! must go into the spec and the code — directly and transparently". This is that, in
//! code; the spec half is `KS-9`.
//!
//! # The cycle, in the order §3.3 fixes
//!
//! ```text
//! 1. ACCEPT    the event through one of three buttons
//! 2. WRAP      what was submitted — it arrives already wrapped, that is what the type means
//! 3. CHECK     signatures, parties, status
//! 4. TAKE      the shell, without reading
//! 5. RULE      the transition-table row
//! 6. ACT       this operation's checks: artefact · claim · deadline · order · stage · time
//! 7. RECORD    the journal page
//! 8. STATUS    the move with record and anchor
//! 9. ANCHOR    outward
//! ```
//!
//! # All nine or none
//!
//! §3.3 requires steps 5–9 to be atomic: a partly applied event must not stay
//! in the journal. There are no transactions here and there is no need for
//! them — the order does it:
//!
//! | | |
//! |---|---|
//! | **first everything that can refuse** | checks 1–6, and they touch nothing |
//! | **then the single fallible record** | the journal page |
//! | **then what can no longer fail** | the status move, validated in step 5 against the same table it will use |
//!
//! `[inference]` So a refusal leaves the container **byte for byte as it was**, and a
//! success leaves it whole. That is the property the assembly was missing, and
//! it is checked by a test that refuses at each step and compares the state.

use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{KeySet, Profile, PublicKey};
use ksg_core_v2::doc::{Class, ClassPromotion, MemoFormat, Serial, Timestamp, Uri};
use ksg_core_v2::error::Invalid;
use ksg_core_v2::journal::{
    Binder, BinderError, BinderState, Body, BoundExport, BoundPoint, Draft, Mode,
    Outcome as Sealed, Party, RecordKind, Sealing, TransferKind, TransferRecord,
};
use ksg_core_v2::section::{StatusRecord, StatusSection};
use ksg_core_v2::status::{transition_for, Blocked, Event as StatusEvent, Outcome, Status};

use crate::artifact::Attachment;
use crate::command::{Refusal, Refused, Roster};
use crate::dispute::{Filing, Settlement};
use crate::event::{Event, Head, View};
use crate::followup::{Discharge, FollowupError, Raised, Task, Ticket};
use crate::operation::{Operation, Role};
use crate::order::{Order, Work};
use crate::stages::Stage;
use crate::timecheck::{self, Where, BARE_IDLE_AFTER_ISSUE_MS, BARE_IDLE_AFTER_RECORD_MS};

/// The page type of the issuance label's record in a `bare`'s journal
/// (owner's decisions 17.10): the one record an attachment takes between the
/// owner's change and the hand-off.
pub const ISSUE_LABEL_PAGE: &str = "urn:ksg:page:issue-label:v1";

/// How many records a playground's journal holds after its opening
/// (`[decision]` 17.10 "B-2 — A": the playground is for practice; free work
/// without a term is what `bare` is for).
pub const PLAYGROUND_RECORDS: u64 = 100;

/// Why the container would not do it.
///
/// Every variant names **which step of the cycle** refused, because "refused"
/// alone sends the presenter looking in the wrong place.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Stopped {
    /// A party was presented with a key other than the one the container pinned
    /// for it (audit of 2026-09-23, K1).
    #[error("{0} was presented with a key other than the one the container holds for it")]
    ForeignKey(Uri),
    /// The export gate refused (G2).
    #[error("export gate: {0}")]
    Unload(Refusal),
    /// A status change without a command carried a record that is not the
    /// issuer's (audit of 2026-09-23, K2).
    #[error("a status change without a command must be recorded by the issuer")]
    NotTheIssuer,
    /// Steps 1–5: the button, the parties, the status.
    #[error("{0}")]
    Command(#[from] Refused),
    /// Step 6: this operation needs evidence it did not get, or got another's.
    #[error("{op:?} takes {needs}, and that is not what arrived")]
    WrongEvidence {
        /// The operation.
        op: Operation,
        /// What it takes.
        needs: &'static str,
    },
    /// Step 6: the artefact is not this container's.
    #[error("artefact: {0}")]
    Artifact(#[from] crate::artifact::ArtifactError),
    /// Step 6: the dispute's paperwork.
    #[error("dispute: {0}")]
    Dispute(#[from] crate::dispute::DisputeError),
    /// Step 6: the order behind the work.
    #[error("order: {0}")]
    Order(#[from] crate::order::OrderError),
    /// Step 6: the time guard.
    #[error("time: {0}")]
    Time(#[from] crate::timecheck::TimeRefusal),
    /// Step 6: the stage does not admit work.
    #[error("no work at stage {0:?}: a template is not a container")]
    Stage(Stage),
    /// Step 7: the journal of work — the bound journal, pages under a movable
    /// seal (Plan_MVP §9).
    #[error("journal: {0}")]
    Journal(#[from] BinderError),
    /// Step 7: the record waits for the owner's seal (CH-20).
    ///
    /// The one refusal that leaves a trace, and on purpose: the owner's rule
    /// is that the record **waits** and work stands still, not that it is
    /// thrown away. It is kept, nothing else is written, and it goes in when
    /// the same record comes back with the owner's seal.
    #[error("the record waits for the owner's seal")]
    WaitsForOwner,
    /// Step 7: the record is not the one this operation writes.
    #[error("{op:?} writes {expected}")]
    WrongRecord {
        /// The operation.
        op: Operation,
        /// What it writes.
        expected: &'static str,
    },
    /// Step 6: a raise, or a move to Pro, without the issuer (`[decision]`
    /// 12.09: the issuer takes on the obligations of the class).
    #[error("{0:?} to Pro takes the issuer beside the owner")]
    IssuerMissing(Operation),
    /// The operation does not exist in this emission class (Goal 1, `bare` v2:
    /// owner's decision 08.10 — eight operations remain, sixteen are cut).
    #[error("{op:?} does not exist in the {class:?} class")]
    NotInClass {
        /// The operation that was refused.
        op: Operation,
        /// The class that does not carry it.
        class: Class,
    },
    /// Goal 1, `bare` v2 (owner's decision 06.10, `[doc:BARE-V2-SPEC]`
    /// K7): the `bare` container idled past its term — two years from its
    /// initiation with no record of work, one year from its last record —
    /// and is a brick: every button refuses, the export ones included. Not a
    /// status (spec §6, §8): the status and the journal stand as they were.
    #[error("the bare container idled past its term and is bricked since {since_ms}")]
    Bricked {
        /// The time mark from which the container is bricked: the reference
        /// point (initiation, or the last record of work) plus the term.
        since_ms: u64,
    },
    /// A `bare` attached to a leader as its trailer is read-only for good
    /// (owner's decisions 11.10 and 13.10, `[doc:BARE-COUPLING]`):
    /// its journal is closed by the attachment page, and only the exports go
    /// out. Not a status (spec §6): the status and the journal stand as they were.
    #[error("the bare container is attached to a leader and only reads: {op:?} refused")]
    Attached {
        /// The operation refused.
        op: Operation,
    },
    /// A `bare` whose owner changed for an attachment takes the hand-off to
    /// the leader's agent and the coupling page, and no other work (13.10).
    #[error("the bare container is being attached: {needs}")]
    Attaching {
        /// What it takes now.
        needs: &'static str,
    },
    /// A `bare` detached from its leader is burned (owner's decision 13.10):
    /// this copy holds no journal and no keys, and every button refuses.
    #[error("the bare container was detached and burned")]
    Burned,
    /// Step 6: this container does not take that form.
    #[error("form: {0}")]
    Form(&'static str),
    /// A Pro container (the full class) attaches no artefact without the
    /// issuer's seal: the issuer's signature on artefacts is mandatory there
    /// (`[decision]` 22.09, 23.09; CT-47, CT-48).
    #[error("a Pro container has no issuer's seal to sign the artefact with")]
    NoIssuerSeal,
    /// The client's key refused: no half to sign with, or a split that failed.
    #[error("client key: {0}")]
    ClientKey(crate::client_key::ClientKeyError),
    /// The container is not born yet: before initiation (E-4) there is no
    /// client's key and no identifier of its own (CH-5b).
    #[error("the container is not initiated yet: no client's key")]
    Unborn,
    /// Initiation found the container born already, or a birth in the way.
    #[error("birth: {0}")]
    Birth(&'static str),
    /// The container's post-quantum key refused.
    #[error("{0}")]
    PqKey(crate::pq_key::PqKeyError),
    /// A plain-format container was handed an anchor.
    ///
    /// `[decision]` 13.09: the plain form is the playground — it anchors nothing and
    /// is never presented outside. An anchored page in it would be a playground
    /// claiming the chain, which is exactly what the two forms exist to keep
    /// apart.
    #[error("a plain-format container takes no anchors: it is a playground")]
    PlainTakesNoAnchor,
    /// A playground's journal is full: it holds [`PLAYGROUND_RECORDS`]
    /// records after its opening (`[decision]` 17.10 "B-2 — A").
    #[error("a playground holds {PLAYGROUND_RECORDS} records: it is for practice, not for work")]
    PlaygroundFull,
    /// Step 8: the status section.
    #[error("status: {0}")]
    Status(#[from] ksg_core_v2::error::Invalid),
    /// Steps 5–6: an outstanding follow-up holds this operation up.
    #[error("{0}")]
    Followup(#[from] FollowupError),
    /// Step 7: a page was presented for an operation that writes none, or none
    /// for one that must.
    #[error("this operation writes {expected} journal page(s)")]
    WrongPage {
        /// What was expected.
        expected: &'static str,
    },
}

/// What an operation must bring with it — step 6 made explicit.
///
/// `[inference]` An enum rather than a bag of options, so that **the evidence an
/// operation needs is stated in one place and the wrong evidence is a refusal
/// rather than a silently skipped check**. That is the difference between a rule
/// that runs and a rule that exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Evidence {
    /// Nothing beyond the command.
    None,
    /// E-9 in `bare` — the one shape the owner's change has there (owner's
    /// decision 13.10): the leader's owner arrives with the attachment, its
    /// key brought by the command and seated as the arriving party for it.
    NewOwner(PublicKey),
    /// E-9 in `bare` outside an attachment (owner's decision 17.10: the
    /// working transfer — backend to frontend to design — comes back): the
    /// new owner arrives with the command, seated as the arriving party for
    /// it; the agent stays until a hand-off.
    Transfer(PublicKey),
    /// E-10: the class raised, with the document that raises it.
    ///
    /// `[decision] 19.09` (CT-01). The operation existed before the document did, and
    /// for one patch they did not meet: `Container::promote` verified a raise
    /// that the button never handed it. A document that reaches the container
    /// past the cycle is a document nobody checked the status, the roster and
    /// the signatures for.
    ClassRaise(Box<ClassPromotion>),
    /// E-10: the form changed (CH-30) — to Pro with the owner and the issuer,
    /// back to light with the owner alone. The journal takes a page of it.
    Form {
        /// The form after it.
        to: Mode,
    },
    /// E-24: shares of the split key presented and found short (`[decision]` 19.09,
    /// CT-22).
    ///
    /// The declaration's digest, not the declaration: the container records
    /// **that** it was made and when, which is all the window needs. The
    /// shares and their commitments stay outside.
    SharesLost(Hash),
    /// E-4: initiation, with where its moment falls in the packet's window.
    Initiation {
        /// As the caller worked it out — no calendar lives here.
        at: Where,
    },
    /// E-3: whose key is being laid on, and up to which layer level.
    ///
    /// `[decision] 12.09` — part of this operation **moves** to the follow-up worker:
    /// the cycle records that the key was laid on, and the hand-over of the
    /// layer key to that party is a second act between two sides. Naming the
    /// recipient here is what lets the cycle raise it.
    KeyLaid {
        /// The party receiving the layer key.
        to: PublicKey,
        /// Up to which level they are given.
        up_to: crate::layers::Level,
    },
    /// E-6: the artefact and the data about it.
    Artifact(Box<Attachment>),
    /// E-5: a record of work, and the order it was done under, if any.
    Work {
        /// The order, when there is one.
        order: Option<Box<Order>>,
        /// What was done.
        work: Box<Work>,
    },
    /// E-5: the agent hands the container to another agent of the same owner
    /// (CH-16, CH-17) — a working page sealed agent/agent. The new agent's key
    /// was made inside the container ([`Container::stage_handoff`]); the
    /// evidence names nothing the container does not already hold.
    Handoff,
    /// E-7, a disposition about sealing: the rule of two seals set or lifted
    /// (CH-19). Its page takes the owner's seal beside the agent's.
    Rule(ksg_core_v2::journal::SealRule),
    /// The coupling of containers (CH-12): E-14 writes slot 1 into the
    /// trailer ("attached to the leader"), E-5 slot 2 into the leader
    /// ("pulls the trailer"). Goal 1, criterion G1-6: a `bare` trailer has
    /// no E-14 — its slot 1 goes on at E-5, and a `bare` never carries a
    /// slot 2: `bare` is only ever the follower.
    Coupling(ksg_core_v2::journal::CouplingRecord),
    /// 30: the copy of the claim and the term it sets.
    Dispute(Box<Filing>),
    /// 35: the two sides settled.
    Settled(Box<Settlement>),
    /// D-3: by which road the presenters claim the content (E-11).
    ///
    /// Audit of 2026-09-23 (G2): the export gate (`unload_gate`) was written
    /// and called by nothing but its tests, and the export button moved the
    /// status to 7 while no page ever left the container. The road is now
    /// evidence of the export, checked by the gate in step 6.
    Unload(Box<UnloadRoute>),
    /// C-10, step 3 (`[decision]` 10.09): the claim of ownership —
    /// `hash(artifact) + hash(agent ID)` — and the publication of step 1 it
    /// rests on. Without a publication of this container's agent ID in the
    /// chain the claim is refused.
    Claim {
        /// The two hashes recorded in the journal.
        claim: Box<crate::identity::OwnershipClaim>,
        /// Step 1: the agent's ID published in the chain, with its anchor.
        publication: Box<crate::identity::Publication>,
    },
    /// The appointment of a court's expert (`[decision]` 11.09, step 1): the
    /// principals' entry naming the expert's key, written on a page of the
    /// journal of work.
    ExpertNamed(Box<crate::expert::ExpertEntry>),
    /// D-3: the disclosure to a court-appointed expert (G2, 23.09). The
    /// container establishes the expert itself from both sides (`[decision]`
    /// 11.09): the principals' entry, which must be on a page of the journal,
    /// and the expert's own record with its anchor in the chain. A seated
    /// expert is not taken from the presenter (gap of 17.10).
    Disclose {
        /// The principals' entry naming the expert — the journal's side.
        entry: Box<crate::expert::ExpertEntry>,
        /// The expert's own record — the chain's side.
        record: Box<crate::expert::ExpertRecord>,
        /// The anchor of the expert's record in the chain.
        record_anchor: Box<ksg_core_v2::anchor::Attestation>,
        /// The principals' command, in the scope the expert demanded.
        disclosure: Box<crate::expert::ExpertDisclosure>,
    },
    /// D-3: the pointwise export — which page goes out (`[decision]` 11.09).
    Point {
        /// The page's number in the journal.
        number: u64,
    },
    /// D-3: the pointwise export of several pages at once — up to 24, one
    /// export of the twelve (`[decision]` 06.10).
    Points {
        /// The pages' numbers in the journal.
        numbers: Vec<u64>,
    },
    /// The review deadline, at the moment presented.
    Deadline {
        /// The moment, in the container's frame.
        at_ms: u64,
    },
    /// Twelve years, at the moment presented.
    Prescription {
        /// The moment, in the container's frame.
        at_ms: u64,
    },
}

/// The road to the content, owned — what [`crate::unload_gate::Route`]
/// borrows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnloadRoute {
    /// The owner and the client together.
    Principals,
    /// A voluntary opening by four parties, with the anchor of its declaration.
    Voluntary {
        /// The opening.
        opening: Box<crate::voluntary::VoluntaryOpening>,
        /// Its anchor in the chain.
        anchor: ksg_core_v2::anchor::Attestation,
    },
}

/// What an operation writes into the journal of work.
#[derive(Debug, Clone)]
pub enum JournalWrite {
    /// Page 0: the journal opens, in the form the class gives it — Pro for
    /// the full class, light otherwise (CH-21) — under the agent's first seal;
    /// in Pro, the owner's seal and the anchor too (CH-26).
    Open {
        /// The opening's time mark.
        offset_ms: u64,
        /// The seals on page 0.
        sealing: Box<Sealing>,
    },
    /// A record drafted by the container ([`Container::draft_record`] and
    /// its kin), with its seals.
    Record {
        /// The record as the container drafted it.
        draft: Box<Draft>,
        /// The seals and the anchor.
        sealing: Box<Sealing>,
    },
}

impl JournalWrite {
    fn anchored(&self) -> bool {
        match self {
            Self::Open { sealing, .. } | Self::Record { sealing, .. } => sealing.anchor.is_some(),
        }
    }

    /// Puts `anchor` in place of the anchor the write carries — for a reader
    /// that anchors in the network only once a copy of the container has taken
    /// the write with a placeholder.
    pub fn set_anchor(&mut self, anchor: ksg_core_v2::anchor::Attestation) {
        match self {
            Self::Open { sealing, .. } | Self::Record { sealing, .. } => {
                sealing.anchor = Some(anchor);
            }
        }
    }
}

/// What a step-7/8 write consists of, once everything has been checked.
#[derive(Debug, Clone)]
pub struct Writes {
    /// The journal record, for operations that write one.
    pub page: Option<JournalWrite>,
    /// The status record and its anchor, for operations that move the status.
    pub status: Option<(StatusRecord, ksg_core_v2::anchor::Attestation)>,
    /// The event's time mark, for the `bare` idle term (Goal 1, `bare` v2).
    ///
    /// `Some` always: the caller that built the page and the status record
    /// took both from this same clock, and an operation that writes neither
    /// (the pointwise export) still happens at a moment the caller knows.
    /// `None` only from callers written before the term existed — then the
    /// press reads the mark out of the page or the status record instead.
    pub at_ms: Option<u64>,
}

impl Writes {
    /// The event's time mark: what the caller said, else the greatest mark
    /// the writes carry, else nothing (an operation that writes nothing and
    /// whose caller named no moment — the press then falls back to the latest
    /// mark the container holds).
    fn at_ms(&self) -> Option<u64> {
        let mut at = self.at_ms;
        let mut take = |mark: u64| {
            at = Some(at.map_or(mark, |a: u64| a.max(mark)));
        };
        match &self.page {
            Some(JournalWrite::Open { offset_ms, .. }) => take(*offset_ms),
            Some(JournalWrite::Record { draft, .. }) => {
                if let Some(p) = draft.pages().first() {
                    take(p.offset_ms);
                }
            }
            None => {}
        }
        if let Some((record, _)) = &self.status {
            take(record.offset_ms);
        }
        at
    }
}

/// The container, whole.
#[derive(Debug)]
pub struct Container {
    /// The container's identifier from initiation on; before it, the
    /// template's ([`Container::template_id`]) — CH-5b.
    id: Hash,
    release: Release,
    serial: Serial,
    /// The client's key: none until initiation (E-4) gives birth to it.
    agent: Option<PublicKey>,
    /// The form of the anchors in the chain, chosen at birth (`[decision]` 13.09).
    ///
    /// Private and without a setter, on purpose: the decision names
    /// irreversibility as the property, and a field anyone could write would
    /// make it a convention instead.
    memo: MemoFormat,
    /// The raise, if one happened. `[decision] 2026-09-19` (CT-01): the place exists
    /// from birth and is empty until the first raise — a format that gained the
    /// field later would leave every container sold before it without a way up.
    promotion: Option<Class>,
    status: StatusSection,
    journal: Option<Binder>,
    filing: Option<Filing>,
    /// Who served the claim — the key in the claimant's seat at E-19.
    claimant: Option<Uri>,
    /// Who holds the rights to the artefact, when they are not the owner's.
    ///
    /// `KS-7` T-31, `[decision]` 10.09: with record **31** the rights pass to the
    /// claimant's ID, **automatically**, and the container records it. The
    /// container itself stays the owner's — the dispute was about the rights
    /// to the artefact, not about the thing (O-07, O-08 withdrawn 10.09).
    rights_to: Option<Uri>,
    /// The issuer's seal, laid at printing (CT-47). The container signs with
    /// it by itself; the issuer takes no part afterwards.
    seal: Option<crate::seal::IssuerSeal>,
    /// The container's half of the client's working key (`[decision]` 23.09).
    /// No accessor returns it.
    client_half: Option<crate::client_key::ContainerHalf>,
    /// The container's half of the key of the client a `bare` had before its
    /// attachment (owner's decision 13.10, variant A): kept at the hand-off
    /// to the leader's agent for one use only — that client's word on the
    /// detachment. Burned with the copy. No accessor returns it.
    former_half: Option<crate::client_key::ContainerHalf>,
    former_round: Option<crate::client_key::Open>,
    /// The container's own post-quantum key, made at printing: it signs the
    /// stored file outside (CH-5a, CH-5b). No accessor returns the secret.
    pq_key: Option<crate::pq_key::ContainerPqKey>,
    /// The client's key while it is being born (CH-5b): the container's side
    /// between the keygen's messages 2 and 3. Never stored.
    keygen: Option<crate::client_key::ContainerKeygen>,
    /// The client's key born and waiting for the initiation it signs. Never
    /// stored: a birth does not outlive the reader's command.
    birth: Option<Birth>,
    /// The container's side of a signing round opened at the reader.
    round: Option<crate::client_key::Open>,
    /// The new agent's key during a hand-off (CH-16): made inside, used to
    /// sign the hand-off page, integrated when the page goes in. Never stored:
    /// like an open round, it does not outlive the reader's command.
    incoming: Option<Box<crate::client_key::ContainerHalf>>,
    /// The side of a round opened with [`Container::incoming`].
    incoming_round: Option<crate::client_key::Open>,
    /// The full export, once made — handed out once by [`Container::take_export`].
    exported: Option<BoundExport>,
    /// The pages disclosed to an expert, handed out once by
    /// [`Container::take_disclosure`].
    disclosed: Option<Vec<BoundPoint>>,
    /// The page of the last pointwise export, handed out once by
    /// [`Container::take_point`].
    pointed: Option<BoundPoint>,
    /// The pages of the last pointwise export of several pages, handed out
    /// once by [`Container::take_points`].
    pointed_pages: Option<Vec<BoundPoint>>,
    /// The seal's signatures on attached artefacts: the attachment's subject
    /// and the signature over it.
    artifact_seals: Vec<(Hash, ksg_core_v2::crypto::sign::Signature)>,
    roster: Roster,
    pending: Vec<Raised>,
    /// "Who looked" (`crate::view`): attached to the anchors, not to the
    /// journal — they spend none of its pages (§8.1-b).
    views: crate::view::NoticeRing,
    /// Goal 1, `bare` v2: the time mark of the initiation, once it went
    /// through — the idle term's reference while no work was recorded.
    bare_initiated_ms: Option<u64>,
    /// Goal 1, `bare` v2: the time mark of the last record of work, once one
    /// went through — the idle term's reference from then on.
    bare_last_work_ms: Option<u64>,
    /// Detached and burned (13.10): no journal, no keys, no buttons.
    burned: bool,
    /// `bare`: owner's changes that were transfers, not attachments
    /// (17.10) — each wrote a page of the transfer zone, which the
    /// attachment's own page must not be mistaken for.
    bare_transfers: u32,
    /// The owner's read key (X25519) for the issuance label, as the owner
    /// set it (owner's decision 17.10): the container answers with it, and
    /// forgets it when the owner changes.
    owner_read: Option<[u8; 32]>,
    /// The sealed zones (owner's decision 18.10 "A"): the release, the
    /// packet and the chain's six positions, each [`crate::layout::ZONE_BYTES`]
    /// wide — sealed under its level's key once written, noise before.
    /// Empty until the noise is laid ([`Container::lay_zone_noise`]).
    zones: Vec<Vec<u8>>,
    /// Which positions are written: one bit each. The content stays under the
    /// levels' keys; which stage wrote a zone is no secret — the status says
    /// as much.
    zones_written: u128,
}

/// The release layer, zone C-1: what the issuer stamped into the container at
/// status 0 and what never changes afterwards.
///
/// `[decision] 2026-09-19` (CT-27) names its composition: **number, the moment of
/// issuance, the class**. They travel together because they are one layer and
/// because every one of them takes part in what the container is — the id and
/// the moment in its identity (CT-28), the class in what the journal takes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Release {
    /// The release identifier, of the form `ksg:em:NNNNNN`.
    pub id: String,
    /// The moment of issuance. Part of the container's identifier.
    pub issued_at: Timestamp,
    /// The class of the packet this container came from.
    pub class: Class,
}

/// A client's key born for initiation, and what initiation binds it with
/// into the container's identifier (KS-8 E-4: "the client agent's key and
/// the artefact's ID at one and the same moment").
struct Birth {
    half: crate::client_key::ContainerHalf,
    artifact: Uri,
    offset_ms: u64,
}

impl core::fmt::Debug for Birth {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Birth")
            .field("kid", &self.half.public().kid)
            .finish_non_exhaustive()
    }
}

impl Container {
    /// A container as the issuer prints it (E-1): a template of serial
    /// `serial` of `release`, with no client's key yet and no identifier of
    /// its own — those are born at initiation (E-4, CH-5b). Until then the
    /// container is addressed by [`Container::template_id`].
    #[must_use]
    pub fn print(
        release: Release,
        serial: Serial,
        memo: MemoFormat,
        status: StatusSection,
        roster: Roster,
    ) -> Self {
        Self::build(
            ksg_core_v2::section::section_root(&release.id, serial),
            release,
            serial,
            None,
            memo,
            status,
            roster,
        )
    }

    /// What the container is addressed by before initiation, and what the
    /// issuer's word at printing is bound to — on the file, the post-quantum
    /// key and the seal: the root of the release's section for this serial
    /// (`ksg_core_v2::section::section_root`). The same for the whole life
    /// of the container.
    #[must_use]
    pub fn template_id(&self) -> Hash {
        ksg_core_v2::section::section_root(&self.release.id, self.serial)
    }

    /// Whether initiation gave birth to the container: its client's key and
    /// its own identifier exist.
    #[must_use]
    pub const fn born(&self) -> bool {
        self.agent.is_some()
    }

    /// The client's key, once born.
    #[must_use]
    pub const fn agent(&self) -> Option<&PublicKey> {
        self.agent.as_ref()
    }

    fn agent_key(&self) -> Result<&PublicKey, Stopped> {
        self.agent.as_ref().ok_or(Stopped::Unborn)
    }

    /// The container with its post-quantum key laid in — done at printing.
    #[must_use]
    pub fn with_pq_key(mut self, key: crate::pq_key::ContainerPqKey) -> Self {
        self.pq_key = Some(key);
        self
    }

    /// Lays the issuer's seal and the container's post-quantum key at
    /// **initiation**, not at printing (D-4, [doc:CAPSULE-SPEC] §9): the copies
    /// the sale chain keeps from before initiation then carry neither secret.
    ///
    /// Refused (`false`, nothing changes) on a container initiated already,
    /// or one that holds a seal or a post-quantum key already.
    pub fn lay_at_initiation(
        &mut self,
        seal: crate::seal::IssuerSeal,
        pq_key: Option<crate::pq_key::ContainerPqKey>,
    ) -> bool {
        if self.born() || self.seal.is_some() || self.pq_key.is_some() {
            return false;
        }
        self.seal = Some(seal);
        self.pq_key = pq_key;
        true
    }

    /// The container's post-quantum key, public half — what the issuer
    /// vouched for at printing.
    #[must_use]
    pub fn pq_public(&self) -> Option<&PublicKey> {
        self.pq_key
            .as_ref()
            .map(crate::pq_key::ContainerPqKey::public)
    }

    /// The container's own key, signing its file (`crate::store`).
    pub(crate) const fn pq_key(&self) -> Option<&crate::pq_key::ContainerPqKey> {
        self.pq_key.as_ref()
    }

    /// Lays the noise of the sealed zones: `random` is
    /// [`crate::layout::ZONE_POSITIONS`] × [`crate::layout::ZONE_BYTES`]
    /// fresh bytes from a CSPRNG. Once: a container whose noise is laid keeps
    /// it, and what is written replaces it position by position.
    ///
    /// # Errors
    ///
    /// The noise is laid already; randomness of another width.
    pub fn lay_zone_noise(&mut self, random: &[u8]) -> Result<(), Stopped> {
        use crate::layout::{ZONE_BYTES, ZONE_POSITIONS};
        if !self.zones.is_empty() {
            return Err(Stopped::Birth("the zones' noise is laid already"));
        }
        if random.len() != ZONE_POSITIONS * ZONE_BYTES {
            return Err(Stopped::Birth(
                "the zones' noise is not the width asked for",
            ));
        }
        self.zones = random.chunks(ZONE_BYTES).map(<[u8]>::to_vec).collect();
        Ok(())
    }

    /// Whether the zones' noise is laid.
    #[must_use]
    pub fn zones_laid(&self) -> bool {
        !self.zones.is_empty()
    }

    /// Writes a sealed zone (E-1, E-2, E-9; owner's decision 18.10 "A") into
    /// the next free position of `zone` — the chain's positions in order —
    /// and returns the position. The bytes are sealed outside, under the
    /// level's key ([`crate::layout::seal_zone`]); the container takes them
    /// at their width, once per position, and only once the zone is open.
    ///
    /// # Errors
    ///
    /// No noise laid; a zone not written this way; a position past the
    /// zone's; bytes of another width; the zone not open at this status.
    pub fn write_zone(
        &mut self,
        zone: crate::layout::Zone,
        sealed: Vec<u8>,
    ) -> Result<usize, Stopped> {
        use crate::layout::{zone_position, Layout, ZONE_BYTES};
        if self.zones.is_empty() {
            return Err(Stopped::Birth("the zones' noise is not laid"));
        }
        if sealed.len() != ZONE_BYTES {
            return Err(Stopped::Birth("a sealed zone is of another width"));
        }
        if !Layout::may_write(zone, self.status()) {
            return Err(Stopped::Birth("the zone is not open at this status"));
        }
        let mut nth = 0;
        let position = loop {
            let p = zone_position(zone, nth)
                .map_err(|_| Stopped::Birth("the zone has no free position left"))?;
            if self.zones_written & (1 << p) == 0 {
                break p;
            }
            nth += 1;
        };
        self.zones[position] = sealed;
        self.zones_written |= 1 << position;
        Ok(position)
    }

    /// Whether the position holds a written zone.
    #[must_use]
    pub const fn sealed_zone_written(&self, position: usize) -> bool {
        position < crate::layout::ZONE_POSITIONS && self.zones_written & (1 << position) != 0
    }

    /// A sealed zone as it lies: ciphertext under its level's key once
    /// written, noise before — the same width either way. Nothing of it reads
    /// without that key.
    #[must_use]
    pub fn sealed_zone(&self, position: usize) -> Option<&[u8]> {
        self.zones.get(position).map(Vec::as_slice)
    }

    /// What the owner signs to set its read key: the label, this container,
    /// the key.
    #[must_use]
    pub fn owner_read_message(&self, read: &[u8; 32]) -> Vec<u8> {
        let mut m = b"ksg:owner-read-key:v1".to_vec();
        m.extend_from_slice(self.id.as_bytes());
        m.extend_from_slice(read);
        m
    }

    /// The owner sets the read key the issuance label is sealed to (owner's
    /// decision 17.10, conditions 1 and 2): a key of its own, not its signing
    /// key, signed by the owner the container holds.
    ///
    /// # Errors
    ///
    /// No owner; a signature that is not the owner's over
    /// [`Container::owner_read_message`].
    pub fn set_owner_read_key(
        &mut self,
        read: [u8; 32],
        sig: ksg_core_v2::crypto::sign::Signature,
    ) -> Result<(), Stopped> {
        let owner = self
            .roster
            .holder(Role::Owner)
            .cloned()
            .ok_or(Stopped::Birth(
                "the read key is the owner's, and there is no owner",
            ))?;
        if sig.kid != owner.kid {
            return Err(Stopped::Birth("the read key is set by the owner alone"));
        }
        let keys: ksg_core_v2::crypto::sign::KeySet = std::iter::once(owner).collect();
        ksg_core_v2::crypto::sign::SignatureSet::new(vec![sig]).verify(
            &self.owner_read_message(&read),
            &keys,
            &Profile::default(),
        )?;
        self.owner_read = Some(read);
        Ok(())
    }

    /// The container's answer: the owner's read key, the one an issuer seals
    /// the issuance label to (17.10, condition 2). `None` until the owner
    /// sets it, and again after an owner's change.
    #[must_use]
    pub const fn owner_read_key(&self) -> Option<[u8; 32]> {
        self.owner_read
    }

    /// C-12, owner's decision 17.10 "B": the distributor that sold the packet
    /// takes its seat — the one with which, together with the client, it may
    /// declare the container dead when the owner is gone (`DeclareKeyLost`).
    ///
    /// Seated with the packet, before initiation, once. A direct sale by the
    /// issuer seats nobody here, and the issuer's own key is refused: "the
    /// issuer cannot do harm".
    ///
    /// # Errors
    ///
    /// The container is initiated already; a distributor is seated already;
    /// the key is the issuer's, or its `kid` is pinned to another party.
    pub fn seat_distributor(&mut self, key: PublicKey) -> Result<(), Stopped> {
        if self.born() {
            return Err(Stopped::Birth(
                "the distributor is seated with the packet, before initiation",
            ));
        }
        if self.roster.holder(Role::Distributor).is_some() {
            return Err(Stopped::Birth("a distributor is seated already"));
        }
        if self.roster.keys().get(&key.kid).is_some() {
            return Err(Stopped::Birth(
                "the distributor's key is another party's: the issuer does not take this seat",
            ));
        }
        self.roster.add(key, Role::Distributor);
        Ok(())
    }

    /// The birth of the client's key, message 2 (CH-5b): the mobile side sent
    /// its commitment; the container answers with its own and the mobile
    /// side's share. `kid` names the client's key.
    ///
    /// # Errors
    ///
    /// [`Stopped::Birth`] on a container born already or under a `kid` the
    /// roster pins; whatever the keygen refuses.
    pub fn begin_birth<
        R: frost_ed25519::rand_core::RngCore + frost_ed25519::rand_core::CryptoRng,
    >(
        &mut self,
        kid: Uri,
        hello: &crate::client_key::KeygenHello,
        rng: &mut R,
    ) -> Result<crate::client_key::KeygenReply, Stopped> {
        if self.born() {
            return Err(Stopped::Birth("the container is initiated already"));
        }
        if self.roster.keys().get(&kid).is_some() {
            return Err(Stopped::Birth(
                "the roster already pins a key under this kid",
            ));
        }
        let (keygen, reply) = crate::client_key::ContainerKeygen::answer(kid, hello, rng)
            .map_err(Stopped::ClientKey)?;
        self.keygen = Some(keygen);
        self.birth = None;
        Ok(reply)
    }

    /// The birth of the client's key, message 3 (CH-5b): the container keeps
    /// its half, waiting for the initiation (E-4) that binds it with
    /// `artifact` and `offset_ms` into the container's identifier. Returns
    /// the client's key, and the identifier the container will be born with.
    ///
    /// # Errors
    ///
    /// No keygen open; a share that does not match the mobile side's
    /// commitment.
    pub fn finish_birth(
        &mut self,
        fin: &crate::client_key::KeygenFinish,
        artifact: Uri,
        offset_ms: u64,
    ) -> Result<(PublicKey, Hash), Stopped> {
        let keygen = self.keygen.take().ok_or(Stopped::Birth("no keygen open"))?;
        let half = keygen.finish(fin).map_err(Stopped::ClientKey)?;
        let public = half.public().clone();
        let id = ksg_core_v2::doc::derive_container_id(
            &self.release.id,
            &self.release.issued_at,
            self.serial,
            &public,
            &artifact,
            offset_ms,
        );
        self.birth = Some(Birth {
            half,
            artifact,
            offset_ms,
        });
        Ok((public, id))
    }

    /// Drops a birth under way: the key is gone, the container stays a
    /// template.
    pub fn cancel_birth(&mut self) {
        self.keygen = None;
        self.birth = None;
        self.round = None;
    }

    /// Names the key being born, once the group key is known: at initiation
    /// the client's identifier is the `did:key` of that key (G-1), and the
    /// group key exists only when both rounds of the birth are done. Nothing
    /// has been signed under the key yet, so the name is not a change of a
    /// claim, it is the claim.
    ///
    /// # Errors
    ///
    /// [`Stopped::Birth`] when no keygen is open.
    pub fn name_birth(&mut self, kid: Uri) -> Result<(), Stopped> {
        let Some(keygen) = self.keygen.as_mut() else {
            return Err(Stopped::Birth("no keygen open"));
        };
        keygen.set_kid(kid);
        Ok(())
    }

    /// The client's key born for initiation, if any: what the initiation's
    /// command is signed under.
    #[must_use]
    pub fn birth_key(&self) -> Option<&PublicKey> {
        self.birth.as_ref().map(|b| b.half.public())
    }

    /// Initiation went in: the container is born (KS-8 E-4).
    fn be_born(&mut self) {
        if let Some(b) = self.birth.take() {
            let public = b.half.public().clone();
            self.id = ksg_core_v2::doc::derive_container_id(
                &self.release.id,
                &self.release.issued_at,
                self.serial,
                &public,
                &b.artifact,
                b.offset_ms,
            );
            self.agent = Some(public);
            self.client_half = Some(b.half);
            self.round = None;
        }
    }

    /// The half that signs for the client now: the integrated one, or — at
    /// initiation — the one just born.
    fn signing_half(&self) -> Option<&crate::client_key::ContainerHalf> {
        self.client_half
            .as_ref()
            .or_else(|| self.birth.as_ref().map(|b| &b.half))
    }

    /// A container that already exists, assembled from its parts.
    ///
    /// Takes the parts rather than building them, because birth is the issuer's
    /// act and this type is what exists afterwards.
    #[must_use]
    pub fn assemble(
        id: Hash,
        release: Release,
        serial: Serial,
        agent: PublicKey,
        memo: MemoFormat,
        status: StatusSection,
        roster: Roster,
    ) -> Self {
        Self::build(id, release, serial, Some(agent), memo, status, roster)
    }

    fn build(
        id: Hash,
        release: Release,
        serial: Serial,
        agent: Option<PublicKey>,
        memo: MemoFormat,
        status: StatusSection,
        roster: Roster,
    ) -> Self {
        Self {
            id,
            release,
            serial,
            agent,
            memo,
            promotion: None,
            status,
            journal: None,
            filing: None,
            claimant: None,
            rights_to: None,
            seal: None,
            client_half: None,
            former_half: None,
            former_round: None,
            pq_key: None,
            keygen: None,
            birth: None,
            round: None,
            incoming: None,
            incoming_round: None,
            exported: None,
            disclosed: None,
            pointed: None,
            pointed_pages: None,
            artifact_seals: Vec::new(),
            roster,
            pending: Vec::new(),
            views: crate::view::NoticeRing::new(),
            bare_initiated_ms: None,
            bare_last_work_ms: None,
            burned: false,
            bare_transfers: 0,
            owner_read: None,
            zones: Vec::new(),
            zones_written: 0,
        }
    }

    /// Records that somebody looked at one of this container's anchors
    /// (`crate::view`, `[decision]` 13.09 §8.1).
    ///
    /// Not a press: nothing is signed on the container's side, no page of
    /// the journal is spent and no status moves. The notice is true because
    /// the owner-watcher signed the request inside it (CT-15).
    ///
    /// # Errors
    ///
    /// [`crate::view::ViewError::Invalid`] if the notice does not verify,
    /// [`crate::view::ViewError::NotOurs`] if the anchor it names is not one
    /// this container holds, [`crate::view::ViewError::Again`] if this very
    /// request is recorded already.
    pub fn record_view(
        &mut self,
        notice: crate::view::ViewNotice,
        profile: &Profile,
    ) -> Result<(), crate::view::ViewError> {
        self.check_view(&notice, profile)?;
        if self.views.holds(&notice) {
            return Err(crate::view::ViewError::Again);
        }
        self.views.record(notice);
        Ok(())
    }

    /// The notices "who looked" this container keeps.
    #[must_use]
    pub const fn views(&self) -> &crate::view::NoticeRing {
        &self.views
    }

    fn check_view(
        &self,
        notice: &crate::view::ViewNotice,
        profile: &Profile,
    ) -> Result<(), crate::view::ViewError> {
        notice.check(profile)?;
        let want = notice.anchor();
        let seals = self
            .journal
            .iter()
            .flat_map(|j| j.anchors().iter().map(|a| &a.anchor));
        let statuses = self.status.records().iter().map(|(_, a)| a);
        if seals
            .chain(statuses)
            .filter_map(|a| crate::view::proof_ref(&a.proof))
            .any(|r| &r == want)
        {
            Ok(())
        } else {
            Err(crate::view::ViewError::NotOurs)
        }
    }

    /// The full export, handed out **once**: the pages of the journal of work
    /// after E-11 went through the gate. `None` before the export and after
    /// the first take. On a `bare` container every press hands out a fresh
    /// copy and the journal keeps working, so a second export replaces the
    /// first still waiting.
    pub fn take_export(&mut self) -> Option<BoundExport> {
        self.exported.take()
    }

    /// The pages disclosed to an expert, handed out **once**.
    pub fn take_disclosure(&mut self) -> Option<Vec<BoundPoint>> {
        self.disclosed.take()
    }

    /// The page of the last pointwise export, handed out **once**.
    pub fn take_point(&mut self) -> Option<BoundPoint> {
        self.pointed.take()
    }

    /// The pages of the last pointwise export of several pages, handed out
    /// **once**.
    pub fn take_points(&mut self) -> Option<Vec<BoundPoint>> {
        self.pointed_pages.take()
    }

    /// Integrates the container's half of the client's working key — once.
    ///
    /// `[decision]` 23.09: from here on the whole key exists nowhere; the client keeps
    /// only its mobile half, which alone signs nothing. The half must be of the
    /// key this container was born for (its `agent`), and the ML-DSA key it
    /// carries is pinned in the roster as the client's companion key.
    ///
    /// # Errors
    ///
    /// [`ClientKeyError::AlreadyIntegrated`] on a second half;
    /// [`ClientKeyError::OtherKey`] for a half of another key.
    ///
    /// [`ClientKeyError::AlreadyIntegrated`]: crate::client_key::ClientKeyError::AlreadyIntegrated
    /// [`ClientKeyError::OtherKey`]: crate::client_key::ClientKeyError::OtherKey
    pub fn integrate_client_key(
        &mut self,
        half: crate::client_key::ContainerHalf,
    ) -> Result<(), crate::client_key::ClientKeyError> {
        use crate::client_key::ClientKeyError;
        if self.client_half.is_some() {
            return Err(ClientKeyError::AlreadyIntegrated);
        }
        if Some(half.public()) != self.agent.as_ref() {
            return Err(ClientKeyError::OtherKey);
        }
        self.client_half = Some(half);
        Ok(())
    }

    /// The reader, step 2: the client presented its commitment; the container
    /// commits too and answers with the package both halves sign.
    ///
    /// Opening a new round drops any round left open: nonces are used once.
    ///
    /// # Errors
    ///
    /// [`ClientKeyError::NoHalf`] when no half was integrated.
    ///
    /// [`ClientKeyError::NoHalf`]: crate::client_key::ClientKeyError::NoHalf
    pub fn begin_signing<
        R: frost_ed25519::rand_core::RngCore + frost_ed25519::rand_core::CryptoRng,
    >(
        &mut self,
        msg: &[u8],
        client: &crate::client_key::Commitment,
        rng: &mut R,
    ) -> Result<crate::client_key::SigningRound, crate::client_key::ClientKeyError> {
        let half = self
            .signing_half()
            .ok_or(crate::client_key::ClientKeyError::NoHalf)?;
        let (open, round) = half.begin(msg, client, rng);
        self.round = Some(open);
        Ok(round)
    }

    /// The reader, step 4: the client's share arrived. The container adds its
    /// own, aggregates, checks, and adds the ML-DSA signature. The round is
    /// closed whatever the outcome.
    ///
    /// # Errors
    ///
    /// [`ClientKeyError::NoRound`] with no round open; whatever the combining
    /// refuses — a share that is not the client's half does not verify.
    ///
    /// [`ClientKeyError::NoRound`]: crate::client_key::ClientKeyError::NoRound
    pub fn finish_signing<
        R: frost_ed25519::rand_core::RngCore + frost_ed25519::rand_core::CryptoRng,
    >(
        &mut self,
        share: &crate::client_key::MobileShare,
        rng: &mut R,
    ) -> Result<Vec<ksg_core_v2::crypto::sign::Signature>, crate::client_key::ClientKeyError> {
        let open = self
            .round
            .take()
            .ok_or(crate::client_key::ClientKeyError::NoRound)?;
        let half = self
            .signing_half()
            .ok_or(crate::client_key::ClientKeyError::NoHalf)?;
        half.finish(open, share, rng)
    }

    /// A hand-off, step 1 (CH-16, CH-17): the container makes the new agent's
    /// working key **inside** — its half and the ML-DSA key stay here, the
    /// mobile half goes to the new agent. Nothing is integrated yet: the new
    /// agent first seals the hand-off page ([`Container::begin_signing_incoming`]),
    /// and only the page going in makes it the agent.
    ///
    /// `[inference]` Made inside rather than brought: the whole key then exists
    /// only within [`crate::client_key::split`] here, which is where the TEE
    /// will make it; a key brought from outside would have existed whole
    /// outside the container (`[decision]` 23.09).
    ///
    /// # Errors
    ///
    /// No journal or no half of the current agent; a `kid` the roster already
    /// pins; whatever the split refuses.
    pub fn stage_handoff<
        R: frost_ed25519::rand_core::RngCore + frost_ed25519::rand_core::CryptoRng,
    >(
        &mut self,
        kid: Uri,
        rng: &mut R,
    ) -> Result<crate::client_key::MobileHalf, Stopped> {
        let op = Operation::RecordWork;
        self.binder(op)?;
        if self.client_half.is_none() {
            return Err(Stopped::ClientKey(
                crate::client_key::ClientKeyError::NoHalf,
            ));
        }
        if self.roster.keys().get(&kid).is_some() {
            return Err(Stopped::WrongEvidence {
                op,
                needs: "a new agent under a key id the container does not know yet",
            });
        }
        let (inside, mobile) = crate::client_key::split(kid, rng).map_err(Stopped::ClientKey)?;
        self.incoming = Some(Box::new(inside));
        self.incoming_round = None;
        Ok(mobile)
    }

    /// A hand-off with the new agent's key born without a dealer (CH-5b), step
    /// 1 of 2: the new agent's mobile side sent its commitment; the container
    /// answers. Nothing is staged until [`Container::finish_handoff_birth`].
    ///
    /// # Errors
    ///
    /// No journal or no half of the current agent; a `kid` the roster already
    /// pins; whatever the keygen refuses.
    pub fn begin_handoff_birth<
        R: frost_ed25519::rand_core::RngCore + frost_ed25519::rand_core::CryptoRng,
    >(
        &mut self,
        kid: Uri,
        hello: &crate::client_key::KeygenHello,
        rng: &mut R,
    ) -> Result<crate::client_key::KeygenReply, Stopped> {
        let op = Operation::RecordWork;
        self.binder(op)?;
        if self.client_half.is_none() {
            return Err(Stopped::ClientKey(
                crate::client_key::ClientKeyError::NoHalf,
            ));
        }
        if self.roster.keys().get(&kid).is_some() {
            return Err(Stopped::WrongEvidence {
                op,
                needs: "a new agent under a key id the container does not know yet",
            });
        }
        let (keygen, reply) = crate::client_key::ContainerKeygen::answer(kid, hello, rng)
            .map_err(Stopped::ClientKey)?;
        self.keygen = Some(keygen);
        Ok(reply)
    }

    /// Step 2 of 2: the container keeps its half of the new agent's key and
    /// stages the hand-off, as [`Container::stage_handoff`] does.
    ///
    /// # Errors
    ///
    /// No keygen open; a share that does not match the commitment.
    pub fn finish_handoff_birth(
        &mut self,
        fin: &crate::client_key::KeygenFinish,
    ) -> Result<PublicKey, Stopped> {
        if !self.born() {
            return Err(Stopped::Unborn);
        }
        let keygen = self.keygen.take().ok_or(Stopped::Birth("no keygen open"))?;
        let half = keygen.finish(fin).map_err(Stopped::ClientKey)?;
        let public = half.public().clone();
        self.incoming = Some(Box::new(half));
        self.incoming_round = None;
        Ok(public)
    }

    /// The new agent as the hand-off page pins it, while a hand-off is staged.
    #[must_use]
    pub fn incoming_party(&self) -> Option<Party> {
        self.incoming.as_ref().map(|h| Party {
            id: Self::party_of(&h.public().kid),
            keys: vec![h.public().clone()],
        })
    }

    /// Drafts the hand-off page (CH-16): a working page, agent/agent, no owner.
    ///
    /// # Errors
    ///
    /// No journal; no hand-off staged; whatever the page fails.
    pub fn draft_handoff(&self, offset_ms: u64) -> Result<Draft, Stopped> {
        let j = self.binder(Operation::RecordWork)?;
        let to_agent = self.incoming_party().ok_or(Stopped::WrongRecord {
            op: Operation::RecordWork,
            expected: "a hand-off, and no new agent is staged",
        })?;
        Ok(j.draft_transfer(
            TransferRecord {
                kind: TransferKind::Handoff,
                from_agent: j.agent().id.clone(),
                to_agent,
                from_owner: None,
                to_owner: None,
                terms: None,
            },
            offset_ms,
        )?)
    }

    /// As [`Container::begin_signing`], with the new agent's half.
    ///
    /// # Errors
    ///
    /// [`crate::client_key::ClientKeyError::NoHalf`] with no hand-off staged.
    pub fn begin_signing_incoming<
        R: frost_ed25519::rand_core::RngCore + frost_ed25519::rand_core::CryptoRng,
    >(
        &mut self,
        msg: &[u8],
        client: &crate::client_key::Commitment,
        rng: &mut R,
    ) -> Result<crate::client_key::SigningRound, crate::client_key::ClientKeyError> {
        let half = self
            .incoming
            .as_ref()
            .ok_or(crate::client_key::ClientKeyError::NoHalf)?;
        let (open, round) = half.begin(msg, client, rng);
        self.incoming_round = Some(open);
        Ok(round)
    }

    /// As [`Container::finish_signing`], with the new agent's half.
    ///
    /// # Errors
    ///
    /// No round open; whatever the combining refuses.
    pub fn finish_signing_incoming<
        R: frost_ed25519::rand_core::RngCore + frost_ed25519::rand_core::CryptoRng,
    >(
        &mut self,
        share: &crate::client_key::MobileShare,
        rng: &mut R,
    ) -> Result<Vec<ksg_core_v2::crypto::sign::Signature>, crate::client_key::ClientKeyError> {
        let open = self
            .incoming_round
            .take()
            .ok_or(crate::client_key::ClientKeyError::NoRound)?;
        let half = self
            .incoming
            .as_ref()
            .ok_or(crate::client_key::ClientKeyError::NoHalf)?;
        half.finish(open, share, rng)
    }

    /// As [`Container::begin_signing`], with the half of the client a `bare`
    /// had before its attachment — for its signature on the detachment
    /// (13.10, variant A). Signing anything else with it buys nothing: that
    /// key holds the former client's seat only, and only `Detach` asks it.
    ///
    /// # Errors
    ///
    /// [`crate::client_key::ClientKeyError::NoHalf`] with no former client.
    pub fn begin_signing_former<
        R: frost_ed25519::rand_core::RngCore + frost_ed25519::rand_core::CryptoRng,
    >(
        &mut self,
        msg: &[u8],
        client: &crate::client_key::Commitment,
        rng: &mut R,
    ) -> Result<crate::client_key::SigningRound, crate::client_key::ClientKeyError> {
        let half = self
            .former_half
            .as_ref()
            .ok_or(crate::client_key::ClientKeyError::NoHalf)?;
        let (open, round) = half.begin(msg, client, rng);
        self.former_round = Some(open);
        Ok(round)
    }

    /// As [`Container::finish_signing`], with the former client's half.
    ///
    /// # Errors
    ///
    /// No round open; whatever the combining refuses.
    pub fn finish_signing_former<
        R: frost_ed25519::rand_core::RngCore + frost_ed25519::rand_core::CryptoRng,
    >(
        &mut self,
        share: &crate::client_key::MobileShare,
        rng: &mut R,
    ) -> Result<Vec<ksg_core_v2::crypto::sign::Signature>, crate::client_key::ClientKeyError> {
        let open = self
            .former_round
            .take()
            .ok_or(crate::client_key::ClientKeyError::NoRound)?;
        let half = self
            .former_half
            .as_ref()
            .ok_or(crate::client_key::ClientKeyError::NoHalf)?;
        half.finish(open, share, rng)
    }

    /// Drafts the page of the rule of two seals (E-7, CH-19).
    ///
    /// # Errors
    ///
    /// No journal; whatever the page fails.
    pub fn draft_rule(
        &self,
        rule: ksg_core_v2::journal::SealRule,
        offset_ms: u64,
    ) -> Result<Draft, Stopped> {
        Ok(self
            .binder(Operation::AttachArtifactOrRights)?
            .draft_rule(rule, offset_ms)?)
    }

    /// Drafts a page of the coupling (CH-12): slot 1 at E-14, slot 2 at E-5.
    /// Goal 1, criterion G1-6: a `bare` trailer has no E-14 — its slot 1 goes
    /// on as its own work-like page at E-5 (`Container::coupling_op`).
    ///
    /// # Errors
    ///
    /// No journal; a slot written already; whatever the page fails.
    pub fn draft_coupling(
        &self,
        record: ksg_core_v2::journal::CouplingRecord,
        offset_ms: u64,
    ) -> Result<Draft, Stopped> {
        let op = self.coupling_op(&record);
        Ok(self.binder(op)?.draft_coupling(record, offset_ms)?)
    }

    /// Goal 1, criterion G1-6 (`[doc:BARE-V2-SPEC]` §5, §8.3, `[decision]`
    /// 06.10): which operation carries which page of the coupling, in which
    /// class. The leader always records `Pulls` at E-5, `bare` included —
    /// and a `bare` refuses that evidence all the same: **`bare` never
    /// leads** (`check_evidence`). The trailer's `AttachedTo` is E-14 in the
    /// classes that have a succession; in `bare` E-14 is cut, and the page
    /// goes on as E-5: a follower's marker of its leader changes no status,
    /// needs no issuer, and is a page the work button already knows how to
    /// write — the same page, the same slot, without the death of E-14.
    #[must_use]
    fn coupling_op(&self, record: &ksg_core_v2::journal::CouplingRecord) -> Operation {
        use ksg_core_v2::journal::CouplingRecord;
        match record {
            CouplingRecord::Pulls { .. } => Operation::RecordWork,
            CouplingRecord::AttachedTo { .. } => {
                if self.class() == Class::Bare {
                    Operation::RecordWork
                } else {
                    Operation::Succeed
                }
            }
        }
    }

    /// Carries a staged hand-off into a copy of this container — for a reader
    /// that tries a write on a copy before anchoring it (the hand-off is not
    /// stored, so a copy from the bytes has none).
    ///
    /// # Errors
    ///
    /// The half did not copy.
    pub fn carry_staged_handoff(&mut self, from: &Self) -> Result<(), Stopped> {
        if let Some(h) = &from.incoming {
            let st = h.state().map_err(Stopped::ClientKey)?;
            self.incoming = Some(Box::new(
                crate::client_key::ContainerHalf::from_state(&st).map_err(Stopped::ClientKey)?,
            ));
        }
        Ok(())
    }

    /// Drops a staged hand-off: the new key is gone, nothing was written.
    pub fn cancel_handoff(&mut self) {
        self.keygen = None;
        self.incoming = None;
        self.incoming_round = None;
    }

    /// The container with the issuer's seal laid in — done at printing.
    #[must_use]
    pub fn with_seal(mut self, seal: crate::seal::IssuerSeal) -> Self {
        self.seal = Some(seal);
        self
    }

    /// The issuer's seal, if one was laid.
    #[must_use]
    pub const fn seal(&self) -> Option<&crate::seal::IssuerSeal> {
        self.seal.as_ref()
    }

    /// The seal's signatures on attached artefacts.
    #[must_use]
    pub fn artifact_seals(&self) -> &[(Hash, ksg_core_v2::crypto::sign::Signature)] {
        &self.artifact_seals
    }

    /// Who holds the rights to the artefact, if a proven dispute moved them
    /// away from the owner (T-31).
    #[must_use]
    pub const fn rights_to(&self) -> Option<&Uri> {
        self.rights_to.as_ref()
    }

    /// Who holds which role right now — after every sale that has landed.
    #[must_use]
    pub const fn roster(&self) -> &Roster {
        &self.roster
    }

    /// Its identifier.
    #[must_use]
    pub const fn id(&self) -> &Hash {
        &self.id
    }

    /// The form its anchors take. Fixed at birth; there is no way to change it.
    #[must_use]
    pub const fn memo_format(&self) -> MemoFormat {
        self.memo
    }

    /// The class this container works under **now**.
    ///
    /// The packet's class until it was raised, the raised one afterwards. Every
    /// rule that reads a class reads this one, so a raise cannot be honoured in
    /// one place and ignored in another.
    #[must_use]
    pub const fn class(&self) -> Class {
        match self.promotion {
            Some(c) => c,
            None => self.release.class,
        }
    }

    /// Raises the class, on a promotion that verifies (KS-8 E-10, CT-01).
    ///
    /// The document is checked against the class the container holds **now**,
    /// not against the packet's: two raises in a row are two steps, and the
    /// second one has to start where the first ended.
    ///
    /// # Errors
    ///
    /// Whatever [`ClassPromotion::validate`] refuses: another container, a
    /// stale `from`, a raise that does not go upward, or fewer than two
    /// distinct signers.
    /// Prefer pressing E-10 with [`Evidence::ClassRaise`]: the cycle checks the
    /// status, the roster and the signatures on the command before the document
    /// is looked at, and this method checks only the document.
    pub fn promote(
        &mut self,
        doc: &ClassPromotion,
        keys: &KeySet,
        profile: &Profile,
    ) -> Result<(), Invalid> {
        let keys = self.roster.trusted(keys).map_err(|_| {
            Invalid::Schema("a key presented under a known kid is not the one the container holds")
        })?;
        doc.validate(&self.id, self.class(), keys, profile)?;
        self.promotion = Some(doc.to);
        Ok(())
    }

    /// What the status section reads now.
    #[must_use]
    pub fn status(&self) -> Status {
        self.status.current()
    }

    /// Whether a decision is owed.
    #[must_use]
    pub fn blocked(&self) -> Blocked {
        self.status.blocked()
    }

    /// The stage that status reads as.
    #[must_use]
    pub fn stage(&self) -> Option<Stage> {
        Stage::of(self.status())
    }

    /// How many journal pages there are, page 0 included.
    #[must_use]
    pub fn pages(&self) -> usize {
        self.journal.as_ref().map_or(0, |j| {
            usize::try_from(j.number())
                .unwrap_or(usize::MAX)
                .saturating_add(1)
        })
    }

    /// The head of the journal, for an event to claim: the number of the
    /// movable seal and the last page.
    #[must_use]
    pub fn head(&self) -> Option<Head> {
        self.journal.as_ref().map(|j| Head {
            counter: j.number(),
            page: j.head_page(),
        })
    }

    /// The hash of the seal on the journal now — what the next seal links
    /// to, and what an anchor of it attests. `None` before page 0.
    #[must_use]
    pub fn top_seal_hash(&self) -> Option<Hash> {
        self.journal.as_ref().and_then(|j| j.top_seal().hash().ok())
    }

    /// The form the journal is in, once it is open (CH-21).
    #[must_use]
    pub fn form(&self) -> Option<Mode> {
        self.journal.as_ref().map(Binder::mode)
    }

    /// Whether a record waits for the owner's seal (CH-20).
    #[must_use]
    pub fn waiting(&self) -> bool {
        self.journal.as_ref().is_some_and(Binder::waiting)
    }

    /// Whether the container is in Pro: its journal's form once the journal
    /// is open, the form it will open in before that.
    #[must_use]
    pub fn is_pro(&self) -> bool {
        self.form().unwrap_or_else(|| self.opening_form()) == Mode::Pro
    }

    /// How many journal seals carry an anchor. Goal 1, criterion G1-4: a
    /// `bare` journal records none — its work records never touch anchoring.
    #[must_use]
    pub fn journal_anchor_count(&self) -> usize {
        self.journal.as_ref().map_or(0, |j| j.anchors().len())
    }

    /// The form a journal opens in: Pro for the full class, light otherwise
    /// (CH-21: the local form is the light one).
    #[must_use]
    pub fn opening_form(&self) -> Mode {
        if self.class() == Class::Heavy && self.memo == MemoFormat::Controlled {
            Mode::Pro
        } else {
            Mode::Local
        }
    }

    /// The party a key identifier belongs to: `<party>#<fragment>` → `<party>`.
    fn party_of(kid: &Uri) -> Uri {
        kid.as_str()
            .split_once('#')
            .and_then(|(p, _)| Uri::parse(p).ok())
            .unwrap_or_else(|| kid.clone())
    }

    /// The agent as the journal pins it: the client's key, which alone signs
    /// the seal (CH-5a).
    fn agent_party(&self) -> Result<Party, Stopped> {
        let agent = self.agent_key()?;
        Ok(Party {
            id: Self::party_of(&agent.kid),
            keys: vec![agent.clone()],
        })
    }

    /// The party holding a role, as the journal pins it.
    fn party_holding(&self, role: Role) -> Option<Party> {
        let key = self.roster.holder(role)?.clone();
        Some(Party {
            id: Self::party_of(&key.kid),
            keys: vec![key],
        })
    }

    /// The bytes and the hash of the first seal, for signing and anchoring
    /// before E-OpenJournal.
    ///
    /// # Errors
    ///
    /// [`Stopped::WrongRecord`] without an owner; whatever page 0 fails.
    pub fn opening_seal(&self, offset_ms: u64) -> Result<(Vec<u8>, Hash), Stopped> {
        let owner = self
            .party_holding(Role::Owner)
            .ok_or(Stopped::WrongRecord {
                op: Operation::OpenJournal,
                expected: "page 0, and there is no owner to pin",
            })?;
        Ok(Binder::opening_seal(
            self.id,
            self.opening_form(),
            self.agent_party()?,
            owner,
            offset_ms,
        )?)
    }

    fn binder(&self, op: Operation) -> Result<&Binder, Stopped> {
        self.journal.as_ref().ok_or(Stopped::WrongRecord {
            op,
            expected: "a record, and the journal is not open",
        })
    }

    /// Drafts a record of content — work, an artefact, a declaration.
    ///
    /// # Errors
    ///
    /// No journal; whatever the record fails.
    pub fn draft_record(
        &self,
        pieces: Vec<ksg_core_v2::journal::Piece>,
        meta: ksg_core_v2::journal::RecordMeta,
        offset_ms: u64,
    ) -> Result<Draft, Stopped> {
        Ok(self
            .binder(Operation::RecordWork)?
            .draft_record(pieces, meta, offset_ms)?)
    }

    /// Drafts the page of a change of form (E-10, CH-30).
    ///
    /// # Errors
    ///
    /// No journal; the same form; whatever the page fails.
    pub fn draft_form(&self, to: Mode, offset_ms: u64) -> Result<Draft, Stopped> {
        Ok(self
            .binder(Operation::RaiseClass)?
            .draft_form(to, offset_ms)?)
    }

    /// Drafts the page of an owner's change (E-9): the owner changes to the
    /// arriving party, the agent stays (CH-14, CH-15). A sale or a transfer
    /// without one — the terms are optional (13.10); in `bare` the arriving
    /// party is the leader's owner of the attachment.
    ///
    /// # Errors
    ///
    /// No journal, no arriving party; whatever the page fails.
    pub fn draft_owner_change(&self, offset_ms: u64) -> Result<Draft, Stopped> {
        let buyer = self
            .party_holding(Role::Buyer)
            .ok_or(Stopped::WrongRecord {
                op: Operation::TransferOwnership,
                expected: "the owner's change page, and there is no arriving party",
            })?;
        self.draft_owner_change_to(buyer, offset_ms)
    }

    /// As [`Container::draft_owner_change`], to the owner arriving with the
    /// command: in `bare` the leader's owner of an attachment (13.10), whose
    /// key takes the arriving party's seat only when the command is pressed.
    ///
    /// # Errors
    ///
    /// No journal; whatever the page fails.
    pub fn draft_owner_change_to_key(
        &self,
        key: &PublicKey,
        offset_ms: u64,
    ) -> Result<Draft, Stopped> {
        self.draft_owner_change_to(
            Party {
                id: Self::party_of(&key.kid),
                keys: vec![key.clone()],
            },
            offset_ms,
        )
    }

    fn draft_owner_change_to(&self, buyer: Party, offset_ms: u64) -> Result<Draft, Stopped> {
        let j = self.binder(Operation::TransferOwnership)?;
        let record = TransferRecord {
            kind: TransferKind::OwnerChange,
            from_agent: j.agent().id.clone(),
            to_agent: j.agent().clone(),
            from_owner: Some(j.owner().id.clone()),
            to_owner: Some(buyer),
            terms: None,
        };
        Ok(j.draft_transfer(record, offset_ms)?)
    }

    /// Drafts the journal's confirmation of ten identical records (KS-8 F-6).
    ///
    /// # Errors
    ///
    /// No journal; no confirmation owed.
    pub fn draft_confirmation(&self, offset_ms: u64) -> Result<Draft, Stopped> {
        Ok(self
            .binder(Operation::RecordWork)?
            .draft_confirmation(offset_ms)?)
    }

    /// The record that waits for the owner's seal, if one does.
    #[must_use]
    pub fn waiting_draft(&self) -> Option<&Draft> {
        self.journal.as_ref().and_then(Binder::waiting_draft)
    }

    /// The follow-ups this container is waiting on.
    ///
    /// Empty is the answer to "is this container settled": a container with an
    /// outstanding task is mid-step, however finished its status looks.
    #[must_use]
    pub fn pending(&self) -> &[Raised] {
        &self.pending
    }

    /// Hands a worker the right to act on one outstanding task.
    ///
    /// # Errors
    ///
    /// [`FollowupError::NoSuchTask`] for an index that is not outstanding;
    /// [`FollowupError::Stale`] when the container has changed since the task
    /// was raised — the worker would be acting on a container that no longer
    /// exists in that form, and its result would mean nothing.
    pub fn claim(&self, index: usize) -> Result<Ticket, FollowupError> {
        let raised = self
            .pending
            .get(index)
            .ok_or(FollowupError::NoSuchTask(index))?;
        if raised.at_head != self.status.head() {
            return Err(FollowupError::Stale);
        }
        Ok(Ticket {
            index,
            task: raised.task.clone(),
            head: raised.at_head,
        })
    }

    /// Takes a worker's result and closes the task.
    ///
    /// # Errors
    ///
    /// [`FollowupError::Stale`] if the container moved since the ticket was
    /// issued; [`FollowupError::WrongProof`] if the discharge answers another
    /// task; [`FollowupError::NoSuchTask`] if it is no longer outstanding.
    pub fn discharge(&mut self, d: &Discharge) -> Result<(), FollowupError> {
        if d.ticket.head != self.status.head() {
            return Err(FollowupError::Stale);
        }
        let raised = self
            .pending
            .get(d.ticket.index)
            .ok_or(FollowupError::NoSuchTask(d.ticket.index))?;
        if raised.task != d.ticket.task {
            return Err(FollowupError::WrongProof);
        }
        // `[decision]` 12.09 — the control, and a consequence sized to the actual risk.
        // A substantial task is checked; a refused check **counts**, and after
        // MAX_REFUSALS the task shows up as stalled for somebody to look at. It
        // is **not** locked: a worker that finally does the work right is the
        // outcome wanted, and refusing it then would leave the work done, the
        // container unwilling to take it, and what it holds up held up forever.
        if let Err(e) = d.proof.check(&raised.task) {
            let r = &mut self.pending[d.ticket.index];
            r.refused += 1;
            return Err(e);
        }

        self.pending.remove(d.ticket.index);
        Ok(())
    }

    /// The tasks nobody has been able to answer.
    ///
    /// Separate from [`Container::pending`] because they mean different things:
    /// pending is work in flight; stalled is work that has been answered wrongly
    /// [`crate::followup::MAX_REFUSALS`] times and wants a human. **Still answerable** — the flag
    /// is for attention, not a lock.
    #[must_use]
    pub fn stalled(&self) -> Vec<&Raised> {
        self.pending.iter().filter(|r| r.stalled()).collect()
    }

    /// The dispute's paperwork, once one has been served.
    #[must_use]
    pub const fn filing(&self) -> Option<&Filing> {
        self.filing.as_ref()
    }

    /// Goal 1, `bare` v2: the idle term's reference point and term.
    ///
    /// The last record of work where one went through, else the initiation —
    /// and one year past the first, two years past the second. `None` before
    /// initiation went through: with no point to count from there is no term.
    /// Whether this `bare` is being attached: its owner changed for the
    /// attachment (E-9, the only owner's change a `bare` has) and its
    /// coupling page is not in yet.
    #[must_use]
    pub fn bare_attaching(&self) -> bool {
        self.class() == Class::Bare
            && self.journal.as_ref().is_some_and(|j| {
                let c = j.counts();
                // Pages of the transfer zone beyond the transfers are the
                // attachment's owner change (17.10).
                c.transfer > u64::from(self.bare_transfers) && c.coupling == 0
            })
    }

    /// Whether this copy was detached and burned (13.10).
    #[must_use]
    pub const fn burned(&self) -> bool {
        self.burned
    }

    /// Detaching burns this copy: the journal, the client's half, every
    /// export not yet taken and every staged hand-off are dropped, and the
    /// copy answers no button again. What was anchored stays where it is.
    fn burn(&mut self) {
        self.journal = None;
        self.client_half = None;
        self.former_half = None;
        self.former_round = None;
        self.incoming = None;
        self.incoming_round = None;
        self.keygen = None;
        self.round = None;
        self.exported = None;
        self.disclosed = None;
        self.pointed = None;
        self.pointed_pages = None;
        self.burned = true;
    }

    /// Whether this is a `bare` attached to a leader: its coupling page
    /// (slot 1, the only slot a `bare` writes) is in the journal.
    #[must_use]
    pub fn bare_attached(&self) -> bool {
        self.class() == Class::Bare
            && self
                .journal
                .as_ref()
                .is_some_and(|j| j.counts().coupling > 0)
    }

    fn bare_reference(&self) -> Option<(u64, u64)> {
        if let Some(last) = self.bare_last_work_ms {
            Some((last, BARE_IDLE_AFTER_RECORD_MS))
        } else {
            self.bare_initiated_ms
                .map(|initiated| (initiated, BARE_IDLE_AFTER_ISSUE_MS))
        }
    }

    /// The latest time mark the container holds: its `bare` marks and its
    /// last status record. The fallback moment for an operation that writes
    /// nothing and whose caller named none (the pointwise export) — such an
    /// operation happens no earlier than everything the container holds.
    fn latest_mark(&self) -> Option<u64> {
        let mut latest = self.bare_initiated_ms;
        let mut take = |mark: u64| {
            latest = Some(latest.map_or(mark, |m: u64| m.max(mark)));
        };
        if let Some(last) = self.bare_last_work_ms {
            take(last);
        }
        if let Some((record, _)) = self.status.records().last() {
            take(record.offset_ms);
        }
        latest
    }

    /// Goal 1, `bare` v2: after a press went through, moves the idle term's
    /// reference where it belongs. Initiation starts the count; any record of
    /// work restarts it (a hand-off or a coupling slot too: the journal moved,
    /// so the container is plainly not idle). Only on success — a refusal
    /// changes nothing.
    fn note_bare_mark(&mut self, op: Operation, at: Option<u64>) {
        let Some(at) = at else { return };
        match op {
            Operation::Initiate => self.bare_initiated_ms = Some(at),
            Operation::RecordWork => self.bare_last_work_ms = Some(at),
            _ => {}
        }
    }

    /// The whole cycle of §3.3, in order, all nine steps or none.
    ///
    /// # Errors
    ///
    /// [`Stopped`], naming the step that refused. **A refusal changes nothing**:
    /// see the note on ordering in the module docs.
    pub fn press(
        &mut self,
        event: &Event,
        evidence: &Evidence,
        writes: Writes,
        keys: &KeySet,
        profile: &Profile,
    ) -> Result<Outcome, Stopped> {
        if self.class() == Class::Bare && !event.op.in_bare() {
            return Err(Stopped::NotInClass {
                op: event.op,
                class: Class::Bare,
            });
        }
        // Goal 1, `bare` v2: the idle term. Right after the class guard and
        // before everything else — a bricked container refuses every button,
        // the export ones included, and the moment counted is the event's own:
        // what the caller named, else the greatest mark the writes carry.
        // No clock of its own: going backwards is refused further down
        // (the journal for pages), and a mark behind the reference counts as
        // no idle time at all.
        if self.burned {
            return Err(Stopped::Burned);
        }
        // Attached as a trailer: read-only, and no idle term — nothing is
        // written any more, so there is nothing to wait for (13.10). The
        // detachment is the one button left besides the exports.
        if self.bare_attached()
            && !matches!(
                event.op,
                Operation::ExportPoint | Operation::FullExport | Operation::Detach
            )
        {
            return Err(Stopped::Attached { op: event.op });
        }
        if event.op == Operation::Detach && !self.bare_attached() {
            return Err(Stopped::WrongEvidence {
                op: event.op,
                needs: "a bare attached to a leader: only an attached bare detaches",
            });
        }
        // Owner changed for an attachment: the hand-off to the leader's agent
        // and the coupling page, nothing else that writes (13.10).
        if self.bare_attaching() {
            // The issuance label passed on to the leader's owner is a step of
            // the attachment too (owner's decision 17.10 "B"): a record of
            // work whose pages are of the label's type, before the hand-off.
            let label = matches!(
                (event.op, evidence),
                (Operation::RecordWork, Evidence::Work { .. })
            ) && matches!(&writes.page, Some(JournalWrite::Record { draft, .. })
                    if draft.pages().iter().all(|p| matches!(&p.body,
                        ksg_core_v2::journal::Body::Content { content_type: Some(t), .. }
                            if t.as_str() == ISSUE_LABEL_PAGE)
                        || matches!(&p.body, ksg_core_v2::journal::Body::Manifest(m)
                            if m.content_type.as_ref().is_some_and(|t| t.as_str() == ISSUE_LABEL_PAGE))));
            let next = label
                || matches!(
                    (event.op, evidence),
                    (
                        Operation::RecordWork,
                        Evidence::Handoff | Evidence::Coupling(_)
                    ) | (Operation::ExportPoint | Operation::FullExport, _)
                );
            if !next {
                return Err(Stopped::Attaching {
                    needs: "the issuance label, the hand-off to the leader's agent, then the coupling page",
                });
            }
        }
        // E-9 in `light` and Pro to a new owner arriving with the command
        // (owner's decision 18.10 "A", after CH-15's hundred transfers): its
        // key takes the arriving party's seat for this command only, as in
        // `bare`; the seat goes back if the command does not go in. The sale
        // to the buyer laid at E-3 (`Evidence::None`) is unchanged.
        if self.class() != Class::Bare && event.op == Operation::TransferOwnership {
            if let Evidence::Transfer(key) = evidence {
                if self.journal.is_none() {
                    return Err(Stopped::WrongEvidence {
                        op: event.op,
                        needs: "an open journal: a transfer to a new owner is written on its page",
                    });
                }
                let before = self.roster.clone();
                if !self.roster.seat_arriving(key.clone()) {
                    return Err(Stopped::WrongEvidence {
                        op: event.op,
                        needs: "the arriving owner's key under an identifier this container \
                                has not pinned to another key",
                    });
                }
                return match self.press_inner(event, evidence, writes, keys, profile) {
                    Ok(outcome) => {
                        self.owner_read = None;
                        Ok(outcome)
                    }
                    Err(e) => {
                        self.roster = before;
                        Err(e)
                    }
                };
            }
        }
        // E-9 in `bare`: the leader's owner arrives with the command; its key
        // takes the arriving party's seat for this command only, and the seat
        // goes back if the command does not go in.
        if self.class() == Class::Bare && event.op == Operation::TransferOwnership {
            let (Evidence::NewOwner(key) | Evidence::Transfer(key)) = evidence else {
                return Err(Stopped::WrongEvidence {
                    op: event.op,
                    needs: "the arriving owner: the leader's with an attachment, or the new one",
                });
            };
            let transfer = matches!(evidence, Evidence::Transfer(_));
            if transfer && self.journal.is_none() {
                return Err(Stopped::WrongEvidence {
                    op: event.op,
                    needs: "an open journal: a bare's transfer is written on its page",
                });
            }
            if self.bare_attached() || self.bare_attaching() {
                return Err(Stopped::Attaching {
                    needs: "one owner's change per attachment",
                });
            }
            let before = self.roster.clone();
            if !self.roster.seat_arriving(key.clone()) {
                return Err(Stopped::WrongEvidence {
                    op: event.op,
                    needs: "the arriving owner's key under an identifier this container \
                            has not pinned to another key",
                });
            }
            return match self.press_inner(event, evidence, writes, keys, profile) {
                Ok(outcome) => {
                    if transfer {
                        self.bare_transfers = self.bare_transfers.saturating_add(1);
                    }
                    // The read key was the former owner's.
                    self.owner_read = None;
                    Ok(outcome)
                }
                Err(e) => {
                    self.roster = before;
                    Err(e)
                }
            };
        }
        let at = writes.at_ms().or_else(|| self.latest_mark());
        if self.class() == Class::Bare
            && !self.bare_attached()
            && matches!(self.status(), Status::Initiated | Status::InWork)
        {
            if let (Some(at), Some((anchor, term))) = (at, self.bare_reference()) {
                if at.saturating_sub(anchor) > term {
                    return Err(Stopped::Bricked {
                        since_ms: anchor.saturating_add(term),
                    });
                }
            }
        }
        // E-4 on a template: the client's key born for it takes the client's
        // seat for this command, and the command going in gives birth to the
        // container (CH-5b). A refusal leaves the template as it was.
        if event.op != Operation::Initiate || self.born() {
            let outcome = self.press_inner(event, evidence, writes, keys, profile)?;
            if event.op == Operation::TransferOwnership {
                self.owner_read = None;
            }
            self.note_bare_mark(event.op, at);
            if event.op == Operation::Detach {
                self.burn();
            }
            return Ok(outcome);
        }
        let key = self.birth_key().cloned().ok_or(Stopped::Birth(
            "initiation gives birth to the client's key: none was born (`begin_birth`)",
        ))?;
        let before = self.roster.clone();
        self.roster.add(key, Role::Client);
        match self.press_inner(event, evidence, writes, keys, profile) {
            Ok(outcome) => {
                self.be_born();
                self.note_bare_mark(event.op, at);
                Ok(outcome)
            }
            Err(e) => {
                self.roster = before;
                Err(e)
            }
        }
    }

    fn press_inner(
        &mut self,
        event: &Event,
        evidence: &Evidence,
        writes: Writes,
        keys: &KeySet,
        profile: &Profile,
    ) -> Result<Outcome, Stopped> {
        // --- 1-5: the door, the wrapping, the signatures, the status, the rule
        let view = View {
            container: &self.id,
            head: self.head(),
            status: self.status(),
            blocked: self.blocked(),
            roster: &self.roster,
        };
        event.press_for(&view, self.class(), keys, profile)?;
        // From here on every signature — pages, the status record, the order,
        // the promotion — is verified against the keys the container pinned.
        // `event.press` has already refused a presenter whose set disagrees
        // with them (audit of 2026-09-23, K1).
        let pinned = self.roster.keys().clone();
        let keys = &pinned;

        // --- 5-bis: what an unfinished follow-up holds up -------------------
        //
        // Before the operation's own checks, because waiting on a worker is a
        // fact about the container rather than about this command: the answer is
        // "not yet", and a presenter reads that differently from "not like this".
        if let Some(raised) = self.pending.iter().find(|r| r.task.blocks(event.op)) {
            return Err(Stopped::Followup(FollowupError::Blocked {
                op: event.op,
                task: raised.task.clone(),
            }));
        }

        // --- 6: this operation's own checks, none of which touch anything -----
        self.check_evidence(event, evidence, keys, profile)?;

        // --- 5 again, without mutating: what the table will answer in step 8 --
        // Goal 1, `bare` v2: the class-aware table — a `bare` container leaves
        // `Printed` straight to the buyer's key or straight to initiation.
        let moves = event.op.event().map_or(Outcome::Stays, |e| {
            transition_for(self.class(), self.status(), self.blocked(), e)
        });
        if let Outcome::Refused(why) = moves {
            return Err(Stopped::Status(ksg_core_v2::error::Invalid::StatusRefused(
                why,
            )));
        }

        // --- 7: the journal — the ONE fallible write, and it goes first -------
        let journal_open = self.journal.is_some();
        let expects_page = match event.op {
            Operation::OpenJournal
            | Operation::RecordWork
            | Operation::AttachArtifactOrRights
            | Operation::DeclareSharesLost
            | Operation::AppointExpert => true,
            // A sale writes its page once there is a journal to write it in: a
            // container sold before its journal opened has nothing to seal.
            Operation::TransferOwnership => journal_open,
            // E-10 writes the page of a change of form; a raise of the class
            // alone writes nothing.
            Operation::RaiseClass => matches!(evidence, Evidence::Form { .. }),
            // E-14 writes slot 1 of the coupling when the successor is named
            // and there is a journal to write it in (CH-12).
            Operation::Succeed => journal_open && matches!(evidence, Evidence::Coupling(_)),
            _ => false,
        };
        match (&writes.page, expects_page) {
            (Some(_), false) => return Err(Stopped::WrongPage { expected: "no" }),
            (None, true) => return Err(Stopped::WrongPage { expected: "one" }),
            _ => {}
        }
        if let Some(write) = writes.page {
            // The plain form anchors nothing (`[decision]` 13.09, §8.3).
            if self.memo == MemoFormat::Plain && write.anchored() {
                return Err(Stopped::PlainTakesNoAnchor);
            }
            // The playground is for practice: a hundred records after its
            // opening, then it is full (`[decision]` 17.10 "B-2 — A").
            if let (MemoFormat::Plain, JournalWrite::Record { draft, .. }) = (self.memo, &write) {
                if draft
                    .pages()
                    .first()
                    .is_some_and(|p| p.batch.id > PLAYGROUND_RECORDS)
                {
                    return Err(Stopped::PlaygroundFull);
                }
            }
            self.write_journal(event.op, evidence, write, profile)?;
        }

        // --- 7 for D-3: the disclosure to an expert is this operation's one
        // fallible act — checked and spent together inside the journal, and
        // no page or status is written after it (G2).
        // --- 7 for the pointwise export: one page, counted inside the journal
        // against the limit of twelve; nothing is written after it.
        if let (Operation::ExportPoint, Evidence::Point { number }) = (event.op, evidence) {
            let journal = self
                .journal
                .as_mut()
                .ok_or(Stopped::Unload(Refusal::Signature))?;
            self.pointed = Some(journal.export_one(*number)?);
        }
        if let (Operation::ExportPoint, Evidence::Points { numbers }) = (event.op, evidence) {
            let journal = self
                .journal
                .as_mut()
                .ok_or(Stopped::Unload(Refusal::Signature))?;
            self.pointed_pages = Some(journal.export_pages(numbers)?);
        }
        if let (
            Operation::DiscloseToExpert,
            Evidence::Disclose {
                entry,
                record,
                record_anchor,
                disclosure,
            },
        ) = (event.op, evidence)
        {
            let owner = self
                .roster
                .holder(Role::Owner)
                .cloned()
                .ok_or(Stopped::Unload(Refusal::RoleMissing {
                    op: event.op,
                    seat: crate::operation::Seat::Exactly(Role::Owner),
                }))?;
            let agent = self.agent_key()?.clone();
            // Both sides, established here and not taken from the presenter
            // (`[decision]` 11.09): the principals' entry, signed by the
            // client or the owner, and the expert's own anchored record.
            let principals: ksg_core_v2::crypto::sign::KeySet =
                [agent.clone(), owner.clone()].into_iter().collect();
            let expert = crate::expert::establish(
                &self.id,
                entry,
                record,
                record_anchor,
                &principals,
                profile,
            )
            .map_err(|_| Stopped::Unload(Refusal::Signature))?;
            let pieces = crate::expert::entry_pieces(entry)
                .map_err(|_| Stopped::Unload(Refusal::Signature))?;
            let journal = self
                .journal
                .as_mut()
                .ok_or(Stopped::Unload(Refusal::Signature))?;
            if !journal.holds_content(crate::expert::EXPERT_ENTRY_PAGE, &pieces) {
                return Err(Stopped::WrongEvidence {
                    op: event.op,
                    needs: "the expert named on a page of the journal (AppointExpert)",
                });
            }
            let pages =
                crate::expert::disclose(journal, &expert, disclosure, &agent, &owner, profile)?;
            self.disclosed = Some(pages);
        }

        // --- 8: the status — validated above, so it cannot refuse now ---------
        // Goal 1, `bare` v2: the same class-aware route as step 5.
        let outcome = if let Some(e) = event.op.event() {
            let (record, anchor) = match writes.status {
                Some((r, a)) => (Some(r), Some(a)),
                None => (None, None),
            };
            self.status
                .apply_for(self.class(), e, record, anchor, keys, profile)?
        } else {
            Outcome::Stays
        };

        // --- 9: what the caller anchors, and the state that follows -----------
        if let Evidence::Dispute(f) = evidence {
            self.filing = Some((**f).clone());
            self.claimant = event
                .signatures
                .signers()
                .into_iter()
                .find(|k| self.roster.roles_of(k).contains(&Role::Claimant))
                .cloned();
        }
        // CT-47, CT-48: the container seals the artefact itself, with the key
        // the issuer laid in at printing. In Pro this is not optional (step 6
        // refused a Pro container without a seal); elsewhere it is done when
        // a seal is there.
        if let (Evidence::Artifact(a), Some(seal)) = (evidence, &self.seal) {
            let subject = a.subject(&self.id);
            self.artifact_seals.push((subject, seal.seal(&subject)));
        }
        // T-31: record 31 hands the rights to the artefact to the claimant.
        if event.op == Operation::DecideDisputeProven {
            self.rights_to.clone_from(&self.claimant);
        }
        // The raise lands here rather than in step 6, and the difference
        // matters: step 6 refuses, step 9 changes. A class raised by a document
        // that the journal then refused to record would leave the container
        // claiming a regime whose first page never went in.
        if let Evidence::ClassRaise(doc) = evidence {
            self.promote(doc, keys, profile)?;
        }
        // E-11: the content leaves. In Pro the export is once and the
        // journal is spent (G2). In `bare` the export does not block the
        // container (`Bare_v2_spec.md` §4, owner's decision 06.10): the journal
        // stays, keeps taking work and exports, and each press hands out a
        // fresh copy of the whole journal as it stands.
        if event.op == Operation::FullExport {
            if self.class() == Class::Bare {
                if let Some(journal) = self.journal.as_ref() {
                    self.exported = Some(journal.state().export);
                }
            } else if let Some(j) = self.journal.take() {
                self.exported = Some(j.export_final());
            }
        }
        // E-9: the sale moves the seat, not the history (T-6, `KS-7` §9.2).
        // Here rather than in step 6 for the same reason as the raise: the
        // seat moves only once everything the sale writes has gone in.
        if event.op == Operation::TransferOwnership {
            self.roster.transfer_ownership(event.signatures.signers());
        }
        // E-5 hand-off: the page went in, so the new agent **is** the agent
        // (CH-17). Its half replaces the old one — the old agent's half is
        // dropped and its seat goes; its key stays pinned, so what it signed
        // stays checkable (the same rule as a sale's, `Roster::transfer_ownership`).
        if matches!(evidence, Evidence::Handoff) {
            if let Some(half) = self.incoming.take() {
                self.incoming_round = None;
                let old = self.agent_key()?.kid.clone();
                // 13.10: in a `bare` being attached the client it had keeps a
                // seat of its own — its word is needed to detach it later.
                if self.bare_attaching() {
                    self.roster.seat_former_client(&old);
                }
                self.roster.hand_off_client(&old, half.public().clone());
                self.agent = Some(half.public().clone());
                // 13.10, variant A: the half of the client the `bare` had stays
                // inside, for its word on the detachment and nothing else.
                let previous = self.client_half.replace(*half);
                if self.bare_attaching() {
                    self.former_half = previous;
                    self.former_round = None;
                }
                self.round = None;
            }
        }

        // --- 10: what this event sets in motion beyond itself ----------------
        //
        // Raised **after** the write, against the head the write produced: a
        // task bound to the state before it would be stale the moment it was
        // raised.
        if let Some(task) = self.raises(event.op, evidence) {
            self.pending.push(Raised {
                task,
                by: event.op,
                at_head: self.status.head(),
                refused: 0,
            });
        }
        Ok(outcome)
    }

    /// Step 7 itself: the record goes into the bound journal, or waits there
    /// for the owner's seal.
    fn write_journal(
        &mut self,
        op: Operation,
        evidence: &Evidence,
        write: JournalWrite,
        profile: &Profile,
    ) -> Result<(), Stopped> {
        match write {
            JournalWrite::Open { offset_ms, sealing } => {
                if op != Operation::OpenJournal {
                    return Err(Stopped::WrongRecord {
                        op,
                        expected: "a record, not page 0",
                    });
                }
                if self.journal.is_some() {
                    return Err(Stopped::WrongRecord {
                        op,
                        expected: "page 0, and the journal is open already",
                    });
                }
                let owner = self
                    .party_holding(Role::Owner)
                    .ok_or(Stopped::WrongRecord {
                        op,
                        expected: "page 0, and there is no owner to pin",
                    })?;
                let mut journal = Binder::open(
                    self.id,
                    self.opening_form(),
                    self.agent_party()?,
                    owner,
                    offset_ms,
                    &sealing,
                    profile,
                )?;
                journal.set_point_limit(point_limit_of(self.class()))?;
                self.journal = Some(journal);
                Ok(())
            }
            JournalWrite::Record { draft, sealing } => {
                if op == Operation::OpenJournal {
                    return Err(Stopped::WrongRecord {
                        op,
                        expected: "page 0",
                    });
                }
                self.check_record(op, evidence, &draft)?;
                let j = self.journal.as_mut().ok_or(Stopped::WrongRecord {
                    op,
                    expected: "a record, and the journal is not open",
                })?;
                if let Some(waiting) = j.waiting_draft() {
                    // CH-20: the record that waits comes back with the owner's
                    // seal — that record, not another in its place.
                    if *waiting != *draft {
                        return Err(Stopped::WaitsForOwner);
                    }
                    let owner = sealing.owner.clone().ok_or(Stopped::WaitsForOwner)?;
                    j.complete(owner, sealing.anchor.clone(), profile)?;
                    return Ok(());
                }
                match j.seal(*draft, *sealing, profile)? {
                    Sealed::Written(_) => Ok(()),
                    Sealed::Waiting => Err(Stopped::WaitsForOwner),
                }
            }
        }
    }

    /// Whether a drafted record is the one this operation writes.
    fn check_record(
        &self,
        op: Operation,
        evidence: &Evidence,
        draft: &Draft,
    ) -> Result<(), Stopped> {
        let wrong = |expected| Stopped::WrongRecord { op, expected };
        let first = draft.pages().first().ok_or(wrong("a record with pages"))?;
        let kind = match &first.body {
            Body::Content { kind, .. } => Some(*kind),
            _ => None,
        };
        match op {
            Operation::RecordWork => match &first.body {
                Body::Content { .. } if kind == Some(RecordKind::Work) => {
                    if matches!(evidence, Evidence::Handoff) {
                        return Err(wrong("the hand-off page"));
                    }
                    Ok(())
                }
                Body::Coupling(c) if matches!(evidence, Evidence::Coupling(e) if e == c) => {
                    // G1-6: the E-5 coupling page is the leader's slot 2 —
                    // or a `bare` trailer's slot 1, the one shape its cut
                    // E-14 leaves. Any other pairing is not this record.
                    let trailer_marker =
                        matches!(c, ksg_core_v2::journal::CouplingRecord::AttachedTo { .. });
                    if trailer_marker == (self.class() == Class::Bare) {
                        Ok(())
                    } else {
                        Err(wrong("slot 2 of the coupling, or in bare slot 1"))
                    }
                }
                Body::Transfer(t)
                    if t.kind == TransferKind::Handoff
                        && matches!(evidence, Evidence::Handoff)
                        && Some(&t.to_agent) == self.incoming_party().as_ref() =>
                {
                    Ok(())
                }
                // The journal's own confirmation of ten identical records is
                // written by the agent pressing on with work (KS-8 F-6).
                Body::RepeatConfirmation => Ok(()),
                _ => Err(wrong("a record of work")),
            },
            Operation::AttachArtifactOrRights => match (&first.body, evidence) {
                // C-10, step 3: one page, the two hashes and nothing else.
                (_, Evidence::Claim { claim, .. }) => match draft.pages() {
                    [ksg_core_v2::journal::BoundPage {
                        body:
                            Body::Content {
                                content: ksg_core_v2::journal::Piece::Inline(b),
                                content_type: Some(t),
                                ..
                            },
                        ..
                    }] if t.as_str() == crate::identity::OWNERSHIP_CLAIM_PAGE
                        && *b == claim.page_bytes() =>
                    {
                        Ok(())
                    }
                    _ => Err(wrong(
                        "one page of the claim: the artifact's and the ID's hashes",
                    )),
                },
                (Body::Rule(r), Evidence::Rule(asked)) if r == asked => Ok(()),
                (Body::Rule(_), _) | (_, Evidence::Rule(_)) => {
                    Err(wrong("the page of the rule of two seals asked for"))
                }
                _ if kind == Some(RecordKind::ArtifactOrRights) => Ok(()),
                _ => Err(wrong("the artefact, a disposition or rights")),
            },
            // `[decision]` 11.09, step 1: one page naming the expert, carrying
            // the entry or its digest.
            Operation::AppointExpert => match (draft.pages(), evidence) {
                (
                    [ksg_core_v2::journal::BoundPage {
                        body:
                            Body::Content {
                                content,
                                content_type: Some(t),
                                ..
                            },
                        ..
                    }],
                    Evidence::ExpertNamed(entry),
                ) if t.as_str() == crate::expert::EXPERT_ENTRY_PAGE
                    && crate::expert::entry_pieces(entry).is_ok_and(|p| {
                        p.iter().any(|x| x.commitment() == content.commitment())
                    }) =>
                {
                    Ok(())
                }
                _ => Err(wrong(
                    "one page naming the expert, with the entry or its digest",
                )),
            },
            Operation::DeclareSharesLost if kind == Some(RecordKind::SharesDeclaredLost) => Ok(()),
            Operation::DeclareSharesLost => Err(wrong("the declaration of lost shares")),
            Operation::TransferOwnership => match &first.body {
                Body::Transfer(t)
                    if t.kind == TransferKind::OwnerChange
                        && t.to_owner.as_ref().map(|p| &p.keys)
                            == self.party_holding(Role::Buyer).as_ref().map(|p| &p.keys) =>
                {
                    Ok(())
                }
                _ => Err(wrong("the sale page, to the buyer in the roster")),
            },
            Operation::Succeed => match (&first.body, evidence) {
                (
                    Body::Coupling(c @ ksg_core_v2::journal::CouplingRecord::AttachedTo { .. }),
                    Evidence::Coupling(e),
                ) if c == e => Ok(()),
                _ => Err(wrong(
                    "slot 1 of the coupling: the leader this container is attached to",
                )),
            },
            Operation::RaiseClass => match (&first.body, evidence) {
                (Body::Form { to }, Evidence::Form { to: asked }) if to == asked => Ok(()),
                _ => Err(wrong("the page of the change of form asked for")),
            },
            _ => Err(wrong("no record")),
        }
    }

    /// What an operation sets in motion beyond the cycle — KS-9 §10.
    ///
    /// `[inference]` A table rather than a rule scattered through the arms, for the same
    /// reason the transition table is a table: it is read far more often than it
    /// is changed, and a reader must be able to see all of it at once.
    fn raises(&self, op: Operation, evidence: &Evidence) -> Option<Task> {
        match (op, evidence) {
            // E-1, E-2 — the issuer has entered a layer; its fields are its own
            // to write, and the cycle of one event has no issuer in it.
            (Operation::PrintRelease, _) => Some(Task::WriteLayer {
                zone: crate::layout::Zone::Release,
            }),
            (Operation::ApplyPacket, _) => Some(Task::WriteLayer {
                zone: crate::layout::Zone::Packet,
            }),
            // E-3 — `[decision]` 12.09: the second half of laying a key on **moves** out
            // of the base cycle. Recording that it happened is one container's
            // business; handing the layer key over is an exchange between two
            // sides, and it belongs where the other side exists.
            (
                Operation::ApplyBuyerKey | Operation::ApplySubAgentKey,
                Evidence::KeyLaid { to, up_to },
            ) => Some(Task::HandOverLayer {
                to: to.clone(),
                up_to: *up_to,
            }),
            // E-9 in `bare` is the attachment's owner change (13.10): the
            // `bare` is about to be read-only, there is no layer work after it.
            (Operation::TransferOwnership, _) if self.class() == Class::Bare => None,
            // E-9 — ownership moved, so the chain layer no longer describes who
            // holds this container. Rewriting it is the issuer's slot work.
            (Operation::TransferOwnership, _) => Some(Task::WriteLayer {
                zone: crate::layout::Zone::Chain,
            }),
            // E-14 — the successor exists outside this container.
            (Operation::Succeed, _) => Some(Task::CarryId { from: self.id }),
            _ => None,
        }
    }

    /// Step 6 — every rule this crate owns, called for the operation that needs
    /// it. This function is the answer to "who calls these".
    fn check_evidence(
        &self,
        event: &Event,
        evidence: &Evidence,
        keys: &KeySet,
        profile: &Profile,
    ) -> Result<(), Stopped> {
        let op = event.op;
        match (op, evidence) {
            // E-11 — the full export goes through the gate (G2, 23.09).
            (Operation::FullExport, Evidence::Unload(route)) => {
                let signers: Vec<PublicKey> = event
                    .signatures
                    .signers()
                    .into_iter()
                    .filter_map(|k| keys.get(k).cloned())
                    .collect();
                let route = match &**route {
                    UnloadRoute::Principals => crate::unload_gate::Route::Principals,
                    UnloadRoute::Voluntary { opening, anchor } => {
                        crate::unload_gate::Route::Voluntary { opening, anchor }
                    }
                };
                crate::unload_gate::authorize(
                    crate::unload_gate::Subject {
                        container: self.id,
                        memo: self.memo,
                    },
                    op,
                    &route,
                    crate::unload_gate::Presenters {
                        signers: &signers,
                        roster: &self.roster,
                    },
                    profile,
                    0,
                )
                .map_err(|d| Stopped::Unload(d.reason))?;
            }
            // The expert's road: a playground shows nobody anything, and the
            // pages themselves are checked where they are — in the journal.
            // `[decision]` 11.09, step 1: the entry is of this container and
            // signed by a principal — the client or the owner.
            (Operation::AppointExpert, Evidence::ExpertNamed(entry)) => {
                let owner = self.roster.holder(Role::Owner).cloned();
                let principals: ksg_core_v2::crypto::sign::KeySet = self
                    .agent_key()
                    .ok()
                    .cloned()
                    .into_iter()
                    .chain(owner)
                    .collect();
                if entry.container != self.id
                    || ksg_core_v2::canonical::check_envelope(
                        entry.as_ref(),
                        entry.v,
                        &entry.doc_type,
                        &entry.signatures,
                        &principals,
                        profile,
                    )
                    .is_err()
                {
                    return Err(Stopped::WrongEvidence {
                        op,
                        needs: "the expert's entry, of this container, signed by the client or the owner",
                    });
                }
            }
            (Operation::AppointExpert, _) => {
                return Err(Stopped::WrongEvidence {
                    op,
                    needs: "the principals' entry naming the expert",
                })
            }
            (Operation::DiscloseToExpert, Evidence::Disclose { .. }) => {
                if self.memo == MemoFormat::Plain {
                    return Err(Stopped::Unload(Refusal::PlainIsNotPresented));
                }
            }
            // The pointwise export: a plain container presents nothing, as for
            // the expert; the page itself is checked in the journal.
            (Operation::ExportPoint, Evidence::Point { .. } | Evidence::Points { .. }) => {
                if self.memo == MemoFormat::Plain {
                    return Err(Stopped::Unload(Refusal::PlainIsNotPresented));
                }
            }
            (Operation::ExportPoint, _) => {
                return Err(Stopped::WrongEvidence {
                    op,
                    needs: "the number of the page to export",
                })
            }
            (Operation::DiscloseToExpert, _) => {
                return Err(Stopped::WrongEvidence {
                    op,
                    needs: "the appointed expert and the principals' disclosure",
                })
            }
            (Operation::FullExport, _) => {
                return Err(Stopped::WrongEvidence {
                    op,
                    needs: "the road to the content: the principals or a voluntary opening",
                })
            }
            // E-4 — initiation only inside the packet's window (I-2, F-10).
            (Operation::Initiate, Evidence::Initiation { at }) => {
                timecheck::may_initiate(*at)?;
            }
            (Operation::Initiate, _) => {
                return Err(Stopped::WrongEvidence {
                    op,
                    needs: "where its moment falls in the packet's window",
                })
            }

            // E-10 — the raise is checked against the class held now, and the
            // check is the document's own: the container does not get a second,
            // looser opinion of what a valid raise is.
            // E-10 — `[decision]` 12.09: the owner pays for the class and the
            // issuer takes on its obligations, so a raise takes both.
            (Operation::RaiseClass, Evidence::ClassRaise(_)) => {
                self.issuer_signed(event)?;
            }
            // E-10 carries the change of form both ways (CH-30): to Pro with the
            // owner and the issuer, as a raise; back to light with the owner
            // alone (CH-23, CH-27). The owner's seal on the page itself is the
            // journal's to check.
            (Operation::RaiseClass, Evidence::Form { to }) => {
                if *to == Mode::Pro {
                    if self.memo == MemoFormat::Plain {
                        return Err(Stopped::Form(
                            "the plain form is a playground and never goes Pro",
                        ));
                    }
                    if self.class() == Class::Bare {
                        return Err(Stopped::Form(
                            "the base class is never anchored (`[decision]` 10.09)",
                        ));
                    }
                    // CH-22: in Pro every requirement of Pro applies — the
                    // issuer's seal on artefacts among them (CT-48). A
                    // container without the seal would go Pro and then
                    // refuse its first artefact; it is refused here instead.
                    if self.seal.is_none() {
                        return Err(Stopped::NoIssuerSeal);
                    }
                    self.issuer_signed(event)?;
                }
            }
            (Operation::RaiseClass, _) => {
                return Err(Stopped::WrongEvidence {
                    op,
                    needs: "the signed promotion, or the form asked for",
                })
            }

            // E-24 — a declaration of lost shares carries its own digest and
            // nothing else; what it is worth was settled in `ksg-custody`
            // before it arrived.
            (Operation::DeclareSharesLost, Evidence::SharesLost(_)) => {}
            (Operation::DeclareSharesLost, _) => {
                return Err(Stopped::WrongEvidence {
                    op,
                    needs: "the digest of the declaration of lost shares",
                })
            }

            // E-6 — the artefact must be the one this container is (C-3).
            (Operation::AttachArtifactOrRights, Evidence::Artifact(a)) => {
                a.check(
                    &self.id,
                    &self.release.id,
                    &self.release.issued_at,
                    self.serial,
                    self.agent_key()?,
                )?;
                // Pro signs every artefact with the seal (CT-48) — Pro being
                // the journal's form, not only the class it opened in: a light
                // container that went Pro takes on every requirement of Pro
                // (CH-22), and a full one returned to light sheds them (CH-23).
                if self.is_pro() && self.seal.is_none() {
                    return Err(Stopped::NoIssuerSeal);
                }
            }
            // E-7 carries the rule of two seals (CH-19): a disposition about
            // how this container's records are sealed. The owner's seal on the
            // page is the journal's to check — it always takes it.
            // C-10, step 3 without step 1 is refused (`OwnershipClaim::accept`),
            // and the publication must be this container's agent's own act:
            // its key and its signature.
            (Operation::AttachArtifactOrRights, Evidence::Claim { claim, publication }) => {
                let agent = self.agent_key()?.clone();
                let subject = crate::identity::Publication::subject(
                    &publication.container,
                    &publication.open_id,
                    &publication.agent,
                );
                let keys: ksg_core_v2::crypto::sign::KeySet =
                    std::iter::once(agent.clone()).collect();
                let refused = |needs| Stopped::WrongEvidence { op, needs };
                claim
                    .accept(&self.id, publication)
                    .map_err(|_| refused("step 1: this container's agent ID published in the chain, with its anchor, and the claim naming it"))?;
                if publication.agent.key != agent.key
                    || publication
                        .signatures
                        .verify(subject.as_bytes(), &keys, profile)
                        .is_err()
                {
                    return Err(refused("the publication signed by this container's agent"));
                }
            }
            (Operation::AttachArtifactOrRights, Evidence::Rule(_)) => {
                let stage = self.stage().ok_or(Stopped::Stage(Stage::Closed))?;
                if !stage.can_work() {
                    return Err(Stopped::Stage(stage));
                }
            }
            (Operation::AttachArtifactOrRights, _) => {
                return Err(Stopped::WrongEvidence {
                    op,
                    needs: "the artefact and the data about it",
                })
            }

            // E-5 — work happens at a working stage, under an order or openly
            // on the agent's own account (C-7).
            (Operation::RecordWork, Evidence::Work { order, work }) => {
                let stage = self.stage().ok_or(Stopped::Stage(Stage::Closed))?;
                if !stage.can_work() {
                    return Err(Stopped::Stage(stage));
                }
                // The record of work is this container's and the client's own
                // (audit of 2026-09-23, K3: until then neither the work nor
                // the order was verified here, and an order signed by nobody
                // passed as an instruction).
                if work.container != self.id {
                    return Err(Stopped::WrongEvidence {
                        op,
                        needs: "a record of work made in this container",
                    });
                }
                work.validate(&self.roster, keys, profile, self.agent_key()?)?;
                match order {
                    Some(o) => {
                        if o.container != self.id {
                            return Err(Stopped::WrongEvidence {
                                op,
                                needs: "an order addressed to this container",
                            });
                        }
                        o.validate(&self.roster, keys, profile)?;
                        work.under_order(o)?;
                    }
                    None => {
                        // Not a refusal: own initiative is one of the four bases.
                        // What matters is that it SAYS so, and it does.
                        debug_assert!(work.on_own_account());
                    }
                }
            }
            // E-5 carries slot 2 of the coupling (CH-12): the leader records
            // that it pulls the trailer, as a record of its work. A container
            // does not pull itself. Goal 1, criterion G1-6: `bare` never
            // leads — slot 2 is refused in it outright — and a `bare` carries
            // its own marker of the leader (slot 1) on this button, because
            // its E-14 is cut (`Container::coupling_op`).
            (Operation::RecordWork, Evidence::Coupling(c)) => {
                let stage = self.stage().ok_or(Stopped::Stage(Stage::Closed))?;
                if !stage.can_work() {
                    return Err(Stopped::Stage(stage));
                }
                match (self.class(), c) {
                    // 13.10: the coupling page closes an attachment that began
                    // with the owner's change and the hand-off to the
                    // leader's agent — the client the `bare` had holds its own
                    // seat by then.
                    (Class::Bare, ksg_core_v2::journal::CouplingRecord::AttachedTo { leader })
                        if *leader != self.id =>
                    {
                        if !self.bare_attaching()
                            || self.roster.holder(Role::FormerClient).is_none()
                        {
                            return Err(Stopped::Attaching {
                                needs: "the owner's change and the hand-off to the leader's agent come before the coupling page",
                            });
                        }
                    }
                    (Class::Bare, ksg_core_v2::journal::CouplingRecord::Pulls { .. }) => {
                        return Err(Stopped::WrongEvidence {
                            op,
                            needs: "bare is a follower only: it never pulls a trailer",
                        })
                    }
                    (_, ksg_core_v2::journal::CouplingRecord::Pulls { trailer, .. })
                        if *trailer != self.id => {}
                    _ => {
                        return Err(Stopped::WrongEvidence {
                            op,
                            needs: "slot 2 of the coupling: the trailer this container pulls",
                        })
                    }
                }
            }
            // E-5 carries the hand-off to another agent (CH-16): a working page,
            // pressed by the agent handing over; the new agent's seal on the
            // page is the journal's to check.
            (Operation::RecordWork, Evidence::Handoff) => {
                let stage = self.stage().ok_or(Stopped::Stage(Stage::Closed))?;
                if !stage.can_work() {
                    return Err(Stopped::Stage(stage));
                }
                if self.incoming.is_none() {
                    return Err(Stopped::WrongEvidence {
                        op,
                        needs: "a hand-off staged in this container",
                    });
                }
            }
            (Operation::RecordWork, _) => {
                return Err(Stopped::WrongEvidence {
                    op,
                    needs: "a record of work, and the order behind it if there is one",
                })
            }

            // E-3 — the operation must say whose key is being laid on, because
            // the hand-over it raises has to know where to go.
            (Operation::ApplyBuyerKey | Operation::ApplySubAgentKey, Evidence::KeyLaid { .. }) => {}
            (Operation::ApplyBuyerKey | Operation::ApplySubAgentKey, _) => {
                return Err(Stopped::WrongEvidence {
                    op,
                    needs: "whose key is laid on, and up to which level",
                })
            }

            // 30 — no copy of the claim, no dispute (`[decision]` 12.09).
            (Operation::ServeDispute, Evidence::Dispute(f)) => f.validate()?,
            (Operation::ServeDispute, _) => {
                return Err(Stopped::WrongEvidence {
                    op,
                    needs: "the copy of the claim and the term it sets",
                })
            }

            // 35 — the two sides settled.
            (Operation::Settle, Evidence::Settled(_)) => {}
            (Operation::Settle, _) => {
                return Err(Stopped::WrongEvidence {
                    op,
                    needs: "the digest of what was agreed",
                })
            }

            // E-9 in `bare` carries the leader's owner (13.10); a transfer to
            // a new owner arriving with the command, in every class (18.10
            // "A"); otherwise E-9 brings nothing and the buyer is the one laid
            // at E-3.
            (Operation::TransferOwnership, Evidence::NewOwner(_))
                if self.class() == Class::Bare => {}
            (Operation::TransferOwnership, Evidence::Transfer(_)) => {}

            // E-14 may name the successor it couples to (CH-12): slot 1, the
            // leader this container is attached to — never itself.
            (Operation::Succeed, Evidence::Coupling(c)) => match c {
                ksg_core_v2::journal::CouplingRecord::AttachedTo { leader }
                    if *leader != self.id => {}
                _ => {
                    return Err(Stopped::WrongEvidence {
                        op,
                        needs: "slot 1 of the coupling: the leader this container is attached to",
                    })
                }
            },

            // Everything else brings nothing, and bringing something is a
            // refusal rather than a shrug: evidence for an operation that has no
            // use for it means the presenter believes something this container
            // does not.
            (_, Evidence::None) => {}
            _ => {
                return Err(Stopped::WrongEvidence {
                    op,
                    needs: "nothing",
                })
            }
        }
        Ok(())
    }

    /// That the issuer signed the command — for what takes the issuer beside
    /// the owner (E-10 up, `[decision]` 12.09).
    fn issuer_signed(&self, event: &Event) -> Result<(), Stopped> {
        let signed = event.signatures.signers().into_iter().any(|kid| {
            self.roster
                .keys
                .get(kid)
                .is_some_and(|k| self.roster.holds(k, Role::Issuer))
        });
        if signed {
            Ok(())
        } else {
            Err(Stopped::IssuerMissing(event.op))
        }
    }

    /// The trigger of §7.2: the review deadline has passed, so the container
    /// blocks itself.
    ///
    /// `[decision]` 12.09, the owner: "a change is a trigger". Not a command anybody signs: a fact about
    /// the clock, checked against the filing the container already holds.
    ///
    /// # Errors
    ///
    /// [`Stopped::Dispute`] before the deadline, or when no dispute was served.
    pub fn deadline_reached(
        &mut self,
        at_ms: u64,
        record: StatusRecord,
        anchor: ksg_core_v2::anchor::Attestation,
        keys: &KeySet,
        profile: &Profile,
    ) -> Result<Outcome, Stopped> {
        let filing = self
            .filing
            .as_ref()
            .ok_or(crate::dispute::DisputeError::NoClaim)?;
        let event = filing.deadline_passed(at_ms)?;
        let keys = self.issuer_record_keys(&record, keys)?;
        Ok(self
            .status
            .apply(event, Some(record), Some(anchor), &keys, profile)?)
    }

    /// The other trigger: twelve years blocked, and the container dies of
    /// prescription.
    ///
    /// # Errors
    ///
    /// [`Stopped::Dispute`] before twelve years, or with no dispute served.
    pub fn prescribed(
        &mut self,
        at_ms: u64,
        record: StatusRecord,
        anchor: ksg_core_v2::anchor::Attestation,
        keys: &KeySet,
        profile: &Profile,
    ) -> Result<Outcome, Stopped> {
        let filing = self
            .filing
            .as_ref()
            .ok_or(crate::dispute::DisputeError::NoClaim)?;
        let event = filing.prescribed(at_ms)?;
        let keys = self.issuer_record_keys(&record, keys)?;
        Ok(self
            .status
            .apply(event, Some(record), Some(anchor), &keys, profile)?)
    }

    /// How many status records the section holds — the number the next one takes.
    #[must_use]
    pub fn status_records(&self) -> usize {
        self.status.records().len()
    }

    /// Puts a task outstanding directly.
    ///
    /// For the platform, and for tests that need a container waiting on work
    /// without driving the whole road to it. Not a way around the mechanism: the
    /// task is bound to the current head exactly as a raised one is.
    pub fn force_task(&mut self, task: Task) {
        self.pending.push(Raised {
            task,
            by: Operation::PrintRelease,
            at_head: self.status.head(),
            refused: 0,
        });
    }

    /// Swaps the placeholder anchors of the record just written for the
    /// network's: the top seal's, the last status record's, or both.
    ///
    /// For a caller that anchors on a network (audit of 30.09, O-1): it
    /// presses with placeholders — the press is all or nothing — then sends
    /// the memos, then swaps. No copy of the container is pressed to find out
    /// first, so the journal is not replayed a second time per record.
    ///
    /// # Errors
    ///
    /// [`Stopped::Journal`] or [`Stopped::Status`] for an anchor of another
    /// subject, or a seal anchor where the top seal carries none.
    pub fn reanchor_last(
        &mut self,
        seal: Option<ksg_core_v2::anchor::Attestation>,
        status: Option<ksg_core_v2::anchor::Attestation>,
    ) -> Result<(), Stopped> {
        if let Some(a) = seal {
            self.journal
                .as_mut()
                .ok_or(Stopped::Journal(BinderError::NoAnchor))?
                .reanchor_top(a)?;
        }
        if let Some(a) = status {
            self.status.reanchor_last(a).map_err(Stopped::Status)?;
        }
        Ok(())
    }

    /// The status section as it leaves the container: every record with its
    /// anchor, for a third party to check (spec v2 §11, §12).
    ///
    /// Read rather than exported: the section is the one part of a container
    /// that may be read (KS-7 §7.2-octies), so taking it out spends nothing —
    /// unlike the journal's full export, which ends the container.
    #[must_use]
    pub fn status_export(&self) -> ksg_core_v2::section::StatusExport {
        self.status.export()
    }

    /// The head of the status section — what the next record must link to.
    ///
    /// A caller builds the record of step 8 before presenting it, and cannot do
    /// that without knowing where the chain is.
    #[must_use]
    pub fn status_head(&self) -> Hash {
        self.status.head()
    }

    /// Applies a status change directly, without a command.
    ///
    /// For the **issuer's own layers** and for the triggers — the changes that
    /// have no presented event behind them. Everything a party presses goes
    /// through [`Container::press`]; this is the door for what the platform
    /// does to a container rather than what a party asks of it.
    ///
    /// # Errors
    ///
    /// [`Stopped::Status`] when the section refuses — and it refuses before it
    /// moves, so nothing changes.
    pub fn force(
        &mut self,
        event: StatusEvent,
        record: StatusRecord,
        anchor: ksg_core_v2::anchor::Attestation,
        keys: &KeySet,
        profile: &Profile,
    ) -> Result<Outcome, Stopped> {
        let keys = self.issuer_record_keys(&record, keys)?;
        Ok(self
            .status
            .apply(event, Some(record), Some(anchor), &keys, profile)?)
    }

    /// The keys a status change without a command is checked against: the
    /// pinned ones, and only when the record is the issuer's.
    ///
    /// The doors without a command — [`Container::force`] and the two triggers
    /// — are the platform's, and the platform acts as the issuer. Until the
    /// audit of 2026-09-23 (audit of 23.09, K2) they verified the record against whatever key
    /// set the caller brought, so a record signed by anybody moved the status.
    fn issuer_record_keys(&self, record: &StatusRecord, keys: &KeySet) -> Result<KeySet, Stopped> {
        let pinned = self.roster.trusted(keys).map_err(Stopped::ForeignKey)?;
        let signers = record.signatures.signers();
        let by_issuer = !signers.is_empty()
            && signers.iter().all(|kid| {
                pinned
                    .get(kid)
                    .is_some_and(|k| self.roster.holds(k, Role::Issuer))
            });
        if !by_issuer {
            return Err(Stopped::NotTheIssuer);
        }
        Ok(pinned.clone())
    }

    /// The status event this container would record for an operation, for a
    /// caller building the record of step 8 before presenting it.
    #[must_use]
    pub fn would_record(&self, op: Operation) -> Option<StatusEvent> {
        op.event()
    }
}

// ---------------------------------------------------------------------------
// Sealed storage — item P-4 of the MVP plan. The bytes and the cipher are in
// `crate::store`; here is what the container is made of, because only this
// module sees its fields.
// ---------------------------------------------------------------------------

/// Everything a container is, for its own sealed storage. Crate-private: it
/// leaves this crate only encrypted (`crate::store`).
///
/// What is **not** here, on purpose: the open signing round. Its FROST nonces
/// are single-use, and nonces written to disk and used again would give away
/// the container's half of the client's key. A container restored from storage
/// has no open round; the client starts a new one.
#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct ContainerState {
    id: Hash,
    release: Release,
    serial: Serial,
    /// None before initiation (CH-5b).
    agent: Option<PublicKey>,
    memo: MemoFormat,
    promotion: Option<Class>,
    status: Vec<(StatusRecord, ksg_core_v2::anchor::Attestation)>,
    journal: Option<BinderState>,
    filing: Option<Filing>,
    claimant: Option<Uri>,
    rights_to: Option<Uri>,
    seal: Option<crate::seal::SealState>,
    client_half: Option<crate::client_key::HalfState>,
    /// 13.10, variant A: the half of the client a `bare` had before its
    /// attachment. Absent everywhere else.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    former_half: Option<crate::client_key::HalfState>,
    /// Goal 1, `bare` v2 (criterion G1-4): a `bare` container holds no
    /// post-quantum key — the field is absent from the sealed state, not
    /// null (`skip_serializing_if`), so the saved bytes carry no PQ fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pq_key: Option<crate::pq_key::PqKeyState>,
    exported: Option<BoundExport>,
    disclosed: Option<Vec<BoundPoint>>,
    pointed: Option<BoundPoint>,
    #[serde(default)]
    pointed_pages: Option<Vec<BoundPoint>>,
    artifact_seals: Vec<(Hash, ksg_core_v2::crypto::sign::Signature)>,
    roster_seats: Vec<(Uri, Role)>,
    roster_keys: Vec<PublicKey>,
    roster_companions: Vec<(Uri, Uri)>,
    pending: Vec<Raised>,
    #[serde(default)]
    views: Vec<crate::view::ViewNotice>,
    #[serde(default)]
    views_dropped: u64,
    /// Goal 1, `bare` v2: the idle term's marks (`Container::bare_initiated_ms`,
    /// `Container::bare_last_work_ms`). Defaulted so a container sealed before
    /// the term existed still opens.
    #[serde(default)]
    bare_initiated_ms: Option<u64>,
    #[serde(default)]
    bare_last_work_ms: Option<u64>,
    /// Detached and burned (13.10). Defaulted: a container sealed before
    /// the detachment existed was never burned.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    burned: bool,
    /// `bare` transfers that were not attachments (17.10). Defaulted: before
    /// it, a `bare` changed owner only by attaching.
    #[serde(default, skip_serializing_if = "is_zero")]
    bare_transfers: u32,
    /// The owner's read key for the issuance label (17.10). Defaulted: none
    /// was set before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    owner_read: Option<[u8; 32]>,
    /// The sealed zones and which are written (18.10 "A"). Defaulted: a
    /// container saved before them has its noise laid when next opened.
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "zones_b64")]
    zones: Vec<Vec<u8>>,
    #[serde(default)]
    zones_written: u128,
}

/// The sealed zones as base64 strings: as arrays of numbers JSON spends three
/// and a half characters on a byte of noise, and a hundred and six zones would
/// not fit the store (`tests/store.rs`, `a_full_journal_fits_the_store`).
/// Arrays are still read, for a state saved before.
mod zones_b64 {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(zones: &[Vec<u8>], s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(zones.iter().map(|z| STANDARD.encode(z)))
    }

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum One {
        Text(String),
        Bytes(Vec<u8>),
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Vec<u8>>, D::Error> {
        Vec::<One>::deserialize(d)?
            .into_iter()
            .map(|z| match z {
                One::Text(t) => STANDARD.decode(t).map_err(serde::de::Error::custom),
                One::Bytes(b) => Ok(b),
            })
            .collect()
    }
}

impl Container {
    pub(crate) fn to_state(&self) -> Result<ContainerState, crate::store::StoreError> {
        use crate::store::StoreError;
        Ok(ContainerState {
            id: self.id,
            release: self.release.clone(),
            serial: self.serial,
            agent: self.agent.clone(),
            memo: self.memo,
            promotion: self.promotion,
            status: self.status.records().to_vec(),
            journal: self.journal.as_ref().map(Binder::state),
            filing: self.filing.clone(),
            claimant: self.claimant.clone(),
            rights_to: self.rights_to.clone(),
            seal: self.seal.as_ref().map(crate::seal::IssuerSeal::state),
            client_half: self
                .client_half
                .as_ref()
                .map(crate::client_key::ContainerHalf::state)
                .transpose()
                .map_err(|e| StoreError::Encode(e.to_string()))?,
            former_half: self
                .former_half
                .as_ref()
                .map(crate::client_key::ContainerHalf::state)
                .transpose()
                .map_err(|e| StoreError::Encode(e.to_string()))?,
            pq_key: self
                .pq_key
                .as_ref()
                .map(crate::pq_key::ContainerPqKey::state),
            exported: self.exported.clone(),
            disclosed: self.disclosed.clone(),
            pointed: self.pointed.clone(),
            pointed_pages: self.pointed_pages.clone(),
            artifact_seals: self.artifact_seals.clone(),
            roster_seats: self.roster.seats.clone(),
            roster_keys: self.roster.keys.keys().cloned().collect(),
            roster_companions: self.roster.companions.clone(),
            pending: self.pending.clone(),
            views: self.views.as_slice().to_vec(),
            views_dropped: self.views.dropped(),
            bare_initiated_ms: self.bare_initiated_ms,
            bare_last_work_ms: self.bare_last_work_ms,
            burned: self.burned,
            bare_transfers: self.bare_transfers,
            owner_read: self.owner_read,
            zones: self.zones.clone(),
            zones_written: self.zones_written,
        })
    }

    /// Rebuilds a container from its state. The status section and the journal
    /// are **replayed** through the same checks that admitted them — against
    /// the keys the container pinned — so a state that would not have been
    /// written is not restored.
    pub(crate) fn from_state(s: ContainerState) -> Result<Self, crate::store::StoreError> {
        use crate::store::StoreError;
        let roster = Roster {
            seats: s.roster_seats.clone(),
            keys: s.roster_keys.iter().cloned().collect(),
            companions: s.roster_companions.clone(),
        };
        let keys = roster.keys.clone();
        let profile = Profile::default();

        let mut records = s.status.iter().cloned();
        let (first, first_anchor) = records
            .next()
            .ok_or(StoreError::Restore("no status records".into()))?;
        let mut status = StatusSection::start(
            &s.release.id,
            s.serial,
            first,
            first_anchor,
            &keys,
            &profile,
        )
        .map_err(|e| StoreError::Restore(format!("status: {e}")))?;
        // Goal 1, `bare` v2: replayed through the same class-aware route
        // that admitted the records — a `bare` section read as Pro would
        // refuse its own first moves.
        let class = s.promotion.unwrap_or(s.release.class);
        for (record, anchor) in records {
            let event = record.event.ok_or(StoreError::Restore(
                "a status record without its event".into(),
            ))?;
            status
                .apply_for(class, event, Some(record), Some(anchor), &keys, &profile)
                .map_err(|e| StoreError::Restore(format!("status: {e}")))?;
        }

        let journal = match s.journal.clone() {
            Some(j) => {
                let mut b = Binder::restore(j, &profile)
                    .map_err(|e| StoreError::Restore(format!("journal: {e}")))?;
                b.set_point_limit(point_limit_of(class))
                    .map_err(|e| StoreError::Restore(format!("journal: {e}")))?;
                if b.container() != &s.id {
                    return Err(StoreError::Restore(
                        "the journal is rooted in another container".into(),
                    ));
                }
                // The agent the container signs as is the one the journal
                // pins now — after a hand-off, the new one (CH-17).
                if b.agent().keys.first() != s.agent.as_ref() {
                    return Err(StoreError::Restore(
                        "the container's agent is not the journal's".into(),
                    ));
                }
                Some(b)
            }
            None => None,
        };
        let seal = match &s.seal {
            Some(st) => Some(
                crate::seal::IssuerSeal::from_state(st)
                    .ok_or(StoreError::Restore("seal".into()))?,
            ),
            None => None,
        };
        let client_half = match &s.client_half {
            Some(st) => Some(
                crate::client_key::ContainerHalf::from_state(st)
                    .map_err(|e| StoreError::Restore(format!("client half: {e}")))?,
            ),
            None => None,
        };

        let former_half = match &s.former_half {
            Some(st) => Some(
                crate::client_key::ContainerHalf::from_state(st)
                    .map_err(|e| StoreError::Restore(format!("former client's half: {e}")))?,
            ),
            None => None,
        };
        let pq_key = match &s.pq_key {
            Some(st) => Some(
                crate::pq_key::ContainerPqKey::from_state(st)
                    .map_err(|e| StoreError::Restore(e.to_string()))?,
            ),
            None => None,
        };
        // A client's half without a client, or a client without its half
        // once born, would not have been written.
        if client_half
            .as_ref()
            .map(crate::client_key::ContainerHalf::public)
            != s.agent.as_ref()
            && client_half.is_some()
        {
            return Err(StoreError::Restore(
                "the client's half is not of the container's client".into(),
            ));
        }
        let mut this = Self {
            id: s.id,
            release: s.release.clone(),
            serial: s.serial,
            agent: s.agent.clone(),
            memo: s.memo,
            promotion: s.promotion,
            status,
            journal,
            filing: s.filing.clone(),
            claimant: s.claimant.clone(),
            rights_to: s.rights_to.clone(),
            seal,
            client_half,
            former_half,
            former_round: None,
            pq_key,
            keygen: None,
            birth: None,
            round: None,
            incoming: None,
            incoming_round: None,
            exported: s.exported.clone(),
            disclosed: s.disclosed.clone(),
            pointed: s.pointed.clone(),
            pointed_pages: s.pointed_pages.clone(),
            artifact_seals: s.artifact_seals.clone(),
            roster,
            pending: s.pending.clone(),
            views: crate::view::NoticeRing::new(),
            bare_initiated_ms: s.bare_initiated_ms,
            bare_last_work_ms: s.bare_last_work_ms,
            burned: s.burned,
            bare_transfers: s.bare_transfers,
            owner_read: s.owner_read,
            zones: s.zones.clone(),
            zones_written: s.zones_written,
        };
        // 13.10, variant A: the former client's half is kept for the
        // detachment alone, so it is the half of the key that holds the
        // former client's seat — and a burned copy keeps none.
        if let Some(former) = &this.former_half {
            if Some(former.public()) != this.roster.holder(Role::FormerClient) {
                return Err(StoreError::Restore(
                    "the former client's half is not of the key in the former client's seat".into(),
                ));
            }
        }
        if this.burned && (this.journal.is_some() || this.client_half.is_some()) {
            return Err(StoreError::Restore(
                "a burned copy keeps no journal and no client's half".into(),
            ));
        }
        // The notices are checked again, as the records are: a notice that
        // would not have been taken is not restored.
        if s.views.len() > crate::view::NOTICE_RING {
            return Err(StoreError::Restore(
                "more notices than the ring holds".into(),
            ));
        }
        let mut challenges = std::collections::BTreeSet::new();
        for n in &s.views {
            this.check_view(n, &profile)
                .map_err(|e| StoreError::Restore(format!("view notice: {e}")))?;
            if !challenges.insert(n.request.challenge.as_str()) {
                return Err(StoreError::Restore("a view notice recorded twice".into()));
            }
        }
        this.views = crate::view::NoticeRing::from_parts(s.views, s.views_dropped);
        Ok(this)
    }
}

/// Pointwise exports the class allows: `bare` 48 (`[decision]` 11.10), the
/// others 12 (`[decision]` 19.09).
const fn point_limit_of(class: Class) -> u64 {
    match class {
        Class::Bare => ksg_core_v2::journal::BARE_POINT_LIMIT,
        _ => ksg_core_v2::journal::POINT_LIMIT,
    }
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde's `skip_serializing_if` passes a reference
const fn is_zero(n: &u32) -> bool {
    *n == 0
}
