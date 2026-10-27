//! The operations, and where each one arrives. KS-8 part E.

use ksg_core_v2::status::Event;

/// One of the three entry points (KS-8 part D).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Button {
    /// **D-1**, the issuer's: entering data, reading the status, finalization.
    Issuer,
    /// **D-2**, signatures: signing, activating keys, records of work.
    Signatures,
    /// **D-3**, export: the full export in a dispute.
    Export,
}

/// Who a party is, as the container knows them from its own layers.
///
/// `[decision]` 12.09, O-3 — the owner: "exactly whose second key" — is answered by naming the roles
/// per operation rather than counting to two. Counting alone let **any** second
/// party stand in for the one the operation means: two signatures from the
/// client and a sub-agent passed a check written for the client and the owner.
///
/// The roles are only those the model already has. `Buyer` is the one arriving
/// and `Owner` the one in place, so a sale is `Owner + Buyer` and needs no third
/// name for the seller — the seller **is** the owner until the transfer lands.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub enum Role {
    /// The issuer: releases, packets, finalization, the freeze.
    Issuer,
    /// The owner: whoever holds the rights to the container now.
    Owner,
    /// The client agent working inside it.
    Client,
    /// An agent delegated to by the client (KS-4).
    SubAgent,
    /// A party acquiring — a buyer at a sale, an agent whose key is being laid on.
    Buyer,
    /// An orchestrator, where one stands above the client.
    Orchestrator,
    /// An arbiter — seated for a voluntary opening, or deciding a dispute.
    Arbiter,
    /// A claimant contesting the rights (E-17, C-11).
    Claimant,
    /// The distributor that sold the packet, or its agent selling for it
    /// (owner's decision 17.10, C-12 "B"). Seated by the presenting layer
    /// only when the packet came through a distributor: an issuer's direct
    /// sale has no distributor, and the issuer does not take this seat — "the
    /// issuer cannot do harm" stays true.
    Distributor,
    /// The client a `bare` had before it was attached to a leader (owner's
    /// decision 13.10): its seat outlives the hand-off to the leader's agent,
    /// because detaching — burning — the `bare` takes its word too.
    FormerClient,
}

/// One place in a command that a distinct party has to fill.
///
/// Seats, not a count: the difference is the whole of O-3. Two seats are two
/// **distinct** parties, and each says which role may fill it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Seat {
    /// Only this role.
    Exactly(Role),
    /// Either role, whichever is present — for the operations the specification
    /// deliberately leaves to whoever is there: reading the status, declaring a
    /// key lost, naming an expert.
    Either(Role, Role),
}

impl Seat {
    /// Whether a role may fill this seat.
    #[must_use]
    pub const fn admits(self, role: Role) -> bool {
        match self {
            Self::Exactly(r) => r as u8 == role as u8,
            Self::Either(a, b) => a as u8 == role as u8 || b as u8 == role as u8,
        }
    }
}

/// Which keys an operation takes, and from whom (KS-8 D-5, KS-7 §5.3).
///
/// Counted in **parties**, not in signatures, and now named by **role** as well.
/// One party signing twice is a set of two and is not two parties — a lesson this
/// codebase learned in four places, so it is stated once here rather than
/// re-derived at each of them.
///
/// "At the same time" is meant literally throughout: every signature on a single
/// command, checked together. A sequential scheme leaves a window in which the
/// first waits for the rest and can be held or replayed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Keys {
    /// These seats, each filled by a different party of an admitted role.
    Seats(&'static [Seat]),
    /// A set whose composition is decided above the core — the full export.
    Set,
    /// One of these sets of seats, whichever the signers fill — for a rule
    /// with alternatives (C-12, owner's decision 17.10: the owner alone; or
    /// the orchestrator alone; or the distributor with the client).
    AnyOf(&'static [&'static [Seat]]),
}

impl Keys {
    /// How many distinct parties this requires.
    #[must_use]
    pub const fn parties(self) -> usize {
        match self {
            Self::Seats(s) => s.len(),
            // One at the least. The composition is the presenting layer's, and
            // pretending to a number here would be inventing one.
            Self::Set => 1,
            // The smallest alternative: fewer parties never do.
            Self::AnyOf(alts) => {
                let mut min = usize::MAX;
                let mut i = 0;
                while i < alts.len() {
                    if alts[i].len() < min {
                        min = alts[i].len();
                    }
                    i += 1;
                }
                min
            }
        }
    }
}

/// What a container can be asked to do. KS-8 part E.
///
/// # The status is not read here — the port is gone
///
/// `[decision]` 12.09, the owner: "yes, remove the reading — it should not exist at all". E-12 had an
/// operation of its own and no longer does.
///
/// Nothing is lost, which is why the removal is a strengthening rather than a
/// subtraction: §7.3 already requires **every** status change to be anchored, so
/// the current status follows from the chain — publicly, without touching the
/// container at all. A reader gets the status **and its history**, and by the
/// axiom that an entry point is a break-in point, the best port is the absent one.
///
/// Deliberately missing: **E-17** (publishing an encumbrance) and **E-18**
/// (publishing an agent's ID) happen **in the chain** and never reach a
/// container; **E-19** (declaring the container lost) is also published in the
/// chain, and for a plain reason — the container is gone, so there is nothing
/// left to press a button on. **E-16** is a trigger rather than an entry: a
/// status change is a consequence of an operation, not an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Operation {
    /// E-1 — the release is printed and its layer entered.
    PrintRelease,
    /// E-2 — the packet's layer is entered at the sale.
    ApplyPacket,
    /// E-3 — the buyer's key is laid on.
    ApplyBuyerKey,
    /// E-3 — a sub-agent's key is laid on.
    ApplySubAgentKey,
    /// E-4 — final initiation: the client agent's key and the artifact, at one
    /// and the same moment.
    Initiate,
    /// The journal is opened — page 0 (KS-7 §8.1-bis).
    ///
    /// KS-8 part E gives it no number of its own, because before 11.09 the move
    /// to status 5 was thought to be the first record of work. It is an entry
    /// like any other and passes the signatures button.
    OpenJournal,
    /// E-5 — a record of work.
    RecordWork,
    /// E-6 · E-7 · E-8 — the artifact, a disposition, rights and their evidence.
    AttachArtifactOrRights,
    /// E-9 — ownership handed on.
    TransferOwnership,
    /// E-10 — the class raised.
    RaiseClass,
    /// E-11 — the full export. **Kills the container — status 7.**
    FullExport,
    /// The journal is opened voluntarily — **status 12**.
    ///
    /// Four parties on one command: client, owner and two arbiters, carrying the
    /// principals' declaration as published in the chain.
    OpenVoluntarily,
    /// A court-appointed expert is named, in the journal.
    ///
    /// **Either** principal may do it alone: a court order binds each of them
    /// separately, and requiring both would let one stall the appointment.
    AppointExpert,
    /// The disclosure made to an appointed expert — named pages, or everything.
    ///
    /// Both principals, unlike the appointment: handing over the contents is a
    /// disclosure of the container, and every disclosure here takes the pair.
    DiscloseToExpert,
    /// The pointwise export: **one named page** leaves, and the container
    /// lives on. `[decision]` 11.09 (V-4): an export is pointwise or final; the
    /// journal counts pointwise exports and stops at twelve (`[decision]` 19.09).
    /// Who may: the owner, the agent itself, or both — the product description
    /// §15. Added 24.09 (item P-5 of the MVP plan): the journal could export one
    /// page since 11.09, and no operation of the container reached it.
    ExportPoint,
    /// An anchored claim against the rights is handed in — status 30.
    ///
    /// The container does not learn of a dispute; it is **handed** the anchored
    /// statement through a button (T-B6). Delivery is the claimant's own act, and
    /// the claimant has already named themselves in the chain (C-11).
    ServeDispute,
    /// The dispute is decided **for** the claimant — status 31.
    DecideDisputeProven,
    /// The dispute is decided **against** the claimant — status 32.
    DecideDisputeUnproven,
    /// The two sides settle — status 35. `[decision] 12.09`
    ///
    /// The claimant and the owner, and **no arbiter**: a settlement is the
    /// parties' own act, and requiring a third would turn "shook hands on it"
    /// into a small trial.
    Settle,
    /// E-13 — finalization: the content set in cement.
    Finalize,
    /// E-14 — succession when the owner's key is lost.
    Succeed,
    /// E-15 — declaring death when the client's key is lost.
    DeclareKeyLost,
    /// E-23 — the issuer freezes on the owner's application.
    FreezeOnOwnerApplication,
    /// E-24 — shares of the split key are declared lost (`[decision]` 19.09, CT-22).
    ///
    /// Not a death and not a freeze: the container goes on working. What the
    /// operation does is put the declaration into the journal under an anchor,
    /// so that the thirty days have something to be counted from.
    DeclareSharesLost,
    /// Detaching a `bare` from its leader — and with it, burning it (owner's
    /// decisions 13.10): the history became rubbish, not an archive (an
    /// archive simply stays attached). The leader's owner and the client the
    /// `bare` had before the attachment, together. Writes nothing: the
    /// attached `bare` is read-only; what it does is wipe this copy's journal
    /// and keys, after which every button refuses.
    Detach,
}

impl Operation {
    /// The one button this operation arrives at.
    ///
    /// Not "a button it may use": the table of KS-8 part E gives exactly one per
    /// operation, and offering it elsewhere is refused. Three entry points is a
    /// claim about the whole surface, and a claim nobody checks is not one.
    #[must_use]
    pub const fn button(self) -> Button {
        match self {
            Self::PrintRelease
            | Self::ApplyPacket
            | Self::Finalize
            | Self::Succeed
            | Self::FreezeOnOwnerApplication => Button::Issuer,
            Self::ApplyBuyerKey
            | Self::ApplySubAgentKey
            | Self::Initiate
            | Self::OpenJournal
            | Self::RecordWork
            | Self::AttachArtifactOrRights
            | Self::TransferOwnership
            | Self::RaiseClass
            | Self::DeclareKeyLost
            | Self::DeclareSharesLost
            | Self::OpenVoluntarily
            | Self::AppointExpert
            | Self::ServeDispute
            | Self::DecideDisputeProven
            | Self::DecideDisputeUnproven
            | Self::Settle
            | Self::Detach => Button::Signatures,
            Self::FullExport | Self::DiscloseToExpert | Self::ExportPoint => Button::Export,
        }
    }

    /// Which keys it takes, and whose (KS-8 D-5, KS-8 part E, KS-7 §5.3).
    ///
    /// `[decision] 12.09` closes O-3. Every row below comes from the decided table of
    /// KS-8 part E; **`RaiseClass`**, which the table left without parties, was
    /// settled the same day — owner and issuer.
    #[must_use]
    pub const fn keys(self) -> Keys {
        use Role::{
            Arbiter, Buyer, Claimant, Client, Distributor, FormerClient, Issuer, Orchestrator,
            Owner, SubAgent,
        };
        use Seat::{Either, Exactly};
        // E-15, C-12 — `[decision]` 17.10: the owner alone is always enough;
        // when the owner is gone or will not sign, the distributor (or its
        // agent) together with the client, or the orchestrator alone — it
        // stands in for the owner in some arrangements. The container cannot
        // tell "the owner refused" from "the owner was not asked", so the
        // three are alternatives, not a sequence.
        if let Self::DeclareKeyLost = self {
            return Keys::AnyOf(&[
                &[Exactly(Owner)],
                &[Exactly(Orchestrator)],
                &[Exactly(Distributor), Exactly(Client)],
            ]);
        }
        Keys::Seats(match self {
            // The issuer acts alone on its own layers — E-1, E-2, E-13, E-14.
            // Succession is the issuer's final signature, and that is the point
            // of it: the owner's key is the thing that has been lost.
            Self::PrintRelease | Self::ApplyPacket | Self::Finalize | Self::Succeed => {
                &[Exactly(Issuer)]
            }
            // T-B10: delivery is the claimant's key. They have already named
            // themselves in the chain, so there is nobody else it could be.
            Self::ServeDispute => &[Exactly(Claimant)],
            // `[decision]` 12.09 — the two sides of the dispute, and nobody else. The
            // claimant contests the owner's rights, so those two are the ones
            // who can end it between themselves.
            Self::Settle => &[Exactly(Claimant), Exactly(Owner)],
            // O-13, `[decision]` 12.09: **minimum** an arbiter and one side. The optimum
            // — the arbiter and both sides — is in `keys_optimum`, and which of
            // the two was met is reported rather than silently equated.
            Self::DecideDisputeProven | Self::DecideDisputeUnproven => {
                &[Exactly(Arbiter), Either(Client, Owner)]
            }
            // E-3. The key being laid on is the arriving party's, and P-03 made
            // the holder's authorization mandatory beside it: an agent cannot
            // bind itself to somebody else's packet.
            Self::ApplyBuyerKey => &[Exactly(Buyer), Exactly(Owner)],
            // E-3 down the delegation chain: the sub-agent's own key, authorized
            // by the client delegating to it (KS-4).
            Self::ApplySubAgentKey => &[Exactly(SubAgent), Exactly(Client)],
            // E-4. G-1: initiation is possible only with the buyer's keys, and
            // the owner is the party the container is being initiated for.
            Self::Initiate => &[Exactly(Client), Exactly(Owner)],
            // E-5 and page 0 — the routine things the agent does by itself.
            Self::RecordWork | Self::OpenJournal => &[Exactly(Client)],
            // E-6 · E-7 · E-8. The client attaches, the owner consents: this is
            // where what the container is worth changes.
            // CH-29, 30.09: in the light form the owner is not asked; in Pro
            // the owner's seal on the record itself is required, and the
            // journal checks it (`ksg_core_v2::journal`).
            Self::AttachArtifactOrRights => &[Exactly(Client)],
            // E-9 — "of seller and buyer", and the seller is the owner in
            // place until the transfer lands.
            Self::TransferOwnership => &[Exactly(Owner), Exactly(Buyer)],
            // E-10 — `[decision]` 12.09: the owner pays for the class and the issuer
            // takes on its obligations (a heavy class owes anchoring), so
            // neither can be absent.
            // CH-30, 30.09: E-10 also carries the change of form, and back to
            // light it is the owner's alone. The issuer is required where
            // it takes on obligations — a raise, a move to Pro — and the
            // container checks that in step 6.
            Self::RaiseClass => &[Exactly(Owner)],
            // E-15 — answered above, with its alternatives (C-12, 17.10).
            Self::DeclareKeyLost => &[],
            // E-24 — whoever the split key belongs to. `[decision]` 19.09 (CT-22):
            // the owner of that key signs, and the issuer signs instead when
            // the owner's key went with the shares. One seat, two parties who
            // may fill it: a second seat would mean the declaration needs both,
            // and the case it exists for is exactly one of them being gone.
            Self::DeclareSharesLost => &[Either(Issuer, Owner)],
            // E-23 — the issuer's signature at the same time as the owner's key.
            Self::FreezeOnOwnerApplication => &[Exactly(Issuer), Exactly(Owner)],
            // Status 12: four parties on one command. The arbiter seat appears
            // twice, and two seats are two distinct parties — which is exactly
            // the rule that one side seating both arbiters would break.
            Self::OpenVoluntarily => &[
                Exactly(Client),
                Exactly(Owner),
                Exactly(Arbiter),
                Exactly(Arbiter),
            ],
            // Either principal alone: a court order binds each separately, and
            // requiring both would let one of them stall the appointment.
            Self::AppointExpert => &[Either(Client, Owner)],
            // Handing over contents is a disclosure, and every disclosure here
            // takes the pair.
            Self::DiscloseToExpert => &[Exactly(Client), Exactly(Owner)],
            // The product description §15: the owner, the agent, or both.
            Self::ExportPoint => &[Either(Owner, Client)],
            // 13.10: the leader's owner (the `bare`'s owner since the
            // attachment) and the client the `bare` had before it.
            Self::Detach => &[Exactly(Owner), Exactly(FormerClient)],
            // E-11 — the most destructive operation there is: it discloses the
            // whole journal and kills the container (status 7).
            //
            // Until 2026-09-13 this returned `Keys::Set`, a branch where no role
            // is checked at all, so **any** key in the container's set — the
            // issuer's, a buyer's, a sub-agent's, an arbiter's — pressed it
            // alone (security audit, finding 3). "The composition is decided
            // above the core" left the widest default on the narrowest button;
            // above the core nobody set it.
            //
            // The pair below is the floor, not the full procedure: a **forced**
            // export in a dispute takes the arbiter's key from an anchored
            // filing plus the filing party's confirmation
            // (`Mekhanizm_vygruzki_v_spore.md` §4). That is a separate
            // operation, and it belongs with the unload gate, which is not
            // written yet.
            Self::FullExport => &[Exactly(Owner), Exactly(Client)],
        })
    }

    /// The fuller set of parties an operation is **better** performed by.
    ///
    /// `[decision] 12.09` on O-13: for a dispute the **minimum** is an arbiter and one
    /// side; the **optimum** is the arbiter and both sides. Two tiers, so the
    /// rule has to hold both — enforce the minimum, and say which was met.
    ///
    /// Equal to [`Operation::keys`] everywhere else: most operations have one
    /// standard, and pretending otherwise would make every caller ask a question
    /// with only one answer.
    #[must_use]
    pub const fn keys_optimum(self) -> Keys {
        use Role::{Arbiter, Client, Owner};
        use Seat::Exactly;
        match self {
            Self::DecideDisputeProven | Self::DecideDisputeUnproven => {
                Keys::Seats(&[Exactly(Arbiter), Exactly(Client), Exactly(Owner)])
            }
            other => other.keys(),
        }
    }

    /// Whether the operation is anchored (KS-8 part E).
    ///
    /// A disclosure to an expert is the only one that is not, and for a plain
    /// reason: it writes nothing. It is the expert reading, and the expert's own
    /// appointment is already anchored by the record they publish themselves.
    ///
    /// Reading the status used to be the other one. It is **gone** — see the
    /// note on [`Operation`].
    #[must_use]
    pub const fn anchored(self) -> bool {
        !matches!(
            self,
            Self::DiscloseToExpert | Self::ExportPoint | Self::Detach
        )
    }

    /// The status event this operation drives, if any.
    ///
    /// `None` for reading the status, which is the whole point of E-12: a look
    /// that moves nothing.
    #[must_use]
    pub const fn event(self) -> Option<Event> {
        Some(match self {
            // E-24 moves no status: shares going short is not a death and not
            // a freeze, and the container goes on working (`[decision]` 19.09). What
            // it needs is the journal page, so that the thirty days have an
            // anchor to be counted from — and a page is written whether or not
            // a status changes.
            Self::DeclareSharesLost => return None,
            Self::PrintRelease => Event::PrintRelease,
            Self::ApplyPacket => Event::ApplyPacket,
            Self::ApplyBuyerKey => Event::ApplyBuyerKey,
            Self::ApplySubAgentKey => Event::ApplySubAgentKey,
            Self::Initiate => Event::Initiate,
            Self::OpenJournal => Event::OpenJournal,
            Self::RecordWork => Event::RecordWork,
            Self::AttachArtifactOrRights => Event::RecordArtifactOrRights,
            Self::TransferOwnership => Event::TransferOwnership,
            Self::RaiseClass => Event::RaiseClass,
            Self::FullExport => Event::FullExport,
            Self::Finalize => Event::Finalize,
            Self::Succeed => Event::Succeed,
            Self::DeclareKeyLost => Event::DeclareKeyLost,
            Self::FreezeOnOwnerApplication => Event::FreezeOnOwnerApplication,
            Self::OpenVoluntarily => Event::OpenVoluntarily,
            Self::ServeDispute => Event::ServeDispute,
            Self::Settle => Event::Settle,
            Self::DecideDisputeProven => Event::DisputeProven,
            Self::DecideDisputeUnproven => Event::DisputeUnproven,
            // Neither moves the status: naming an expert is a journal entry, and
            // a disclosure to one is a reading. The full export is the operation
            // that ends a container — except a `bare` one, whose export leaves
            // it working (`Bare_v2_spec.md` §4) — and this is deliberately not it.
            Self::AppointExpert | Self::DiscloseToExpert | Self::ExportPoint => return None,
            // No status of its own: the burned copy is not a container any
            // more, and its status section stays as anchored.
            Self::Detach => return None,
        })
    }

    /// Whether the operation exists in the `bare` class (`[doc:BARE-V2-TABLE]` §2,
    /// owner's decision 08.10: `bare` v2). Eight remain; the other sixteen are cut.
    pub const fn in_bare(self) -> bool {
        matches!(
            self,
            Self::PrintRelease
                | Self::ApplyBuyerKey
                | Self::ApplySubAgentKey
                | Self::Initiate
                | Self::OpenJournal
                | Self::RecordWork
                | Self::FullExport
                | Self::ExportPoint
                // 13.10: the owner's change comes back to `bare` in one shape
                // only — the leader's owner, at the attachment — and the
                // detachment is `bare`'s own.
                | Self::TransferOwnership
                | Self::Detach
        )
    }

    /// Every operation, for the exhaustiveness sweeps.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::PrintRelease,
            Self::ApplyPacket,
            Self::ApplyBuyerKey,
            Self::ApplySubAgentKey,
            Self::Initiate,
            Self::OpenJournal,
            Self::RecordWork,
            Self::AttachArtifactOrRights,
            Self::TransferOwnership,
            Self::RaiseClass,
            Self::FullExport,
            Self::Finalize,
            Self::Succeed,
            Self::DeclareKeyLost,
            Self::FreezeOnOwnerApplication,
            Self::OpenVoluntarily,
            Self::AppointExpert,
            Self::DiscloseToExpert,
            Self::ExportPoint,
            Self::ServeDispute,
            Self::DecideDisputeProven,
            Self::DecideDisputeUnproven,
            Self::Settle,
            Self::Detach,
        ]
    }
}
