//! The stages a container passes through. KS-8 A-1, C-1, C-2.
//!
//! # Not a second state machine
//!
//! The statuses already are the machine, and a stage is a **reading** of one:
//! five names over thirty-six numbers, for the places where the difference that
//! matters is coarse. Writing stages as their own transitions would give two
//! machines to keep in agreement, and two machines that must agree eventually
//! do not.
//!
//! So there is exactly one function of substance here — [`Stage::of`] — and every
//! rule below is a question asked of it.
//!
//! # What the stages are for
//!
//! One rule, and it was the reason this module was planned: **a template is not a
//! container.** A reference and a template can be copied, sold and resold; they
//! hold no client's key and no journal, so nothing can be worked in them. The
//! moment of becoming a container is the initiation, and it is not reversible.
//!
//! `[decision] 11.09` put it exactly, about succession, the owner: "status 4 is not
//! valid for work; it is ready for further registration and later sale/resale, but
//! not for work. A working container has one key condition: it must hold 0 records
//! of the client key and a zero journal record." That is [`Stage::Working`], and
//! [`Stage::can_work`] is that sentence made checkable.

use ksg_core_v2::status::Status;

/// Where a container is in its life. KS-8 A-1: one code filled in by stages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Stage {
    /// **Reference** — the issuer's layers and nothing else. Statuses 0–2.
    Reference,
    /// **Template** — sold, keyed, ready to be registered and resold. Statuses
    /// 3–4. Copyable, tradable, **not workable**.
    Template,
    /// **Initiated** — the client agent's key and the artifact are on, the
    /// journal is not open yet. Status 4 is the last template state and this is
    /// what follows it.
    Initiated,
    /// **Working** — record 0 of the client key and page 0 of the journal both
    /// exist. Statuses 5, 12, 30, 31, 32, 34, 35.
    ///
    /// 31 is here on purpose: `[decision]` 11.09 — the rights have moved to the
    /// claimant, and the container still works. A prohibition on working with the
    /// artefact is the claimant's to serve, and the container does not enforce
    /// legal prohibitions.
    Working,
    /// **Closed** — frozen, exported, dead or expired. Statuses 6, 7, 9, 10, 20,
    /// 21, 22.
    Closed,
}

impl Stage {
    /// The stage a status reads as, or `None` for a reserved blank.
    ///
    /// `None` rather than a guess: 8 and 33 are reserved places with no
    /// transitions (`KS-7` T-B18), so they are in no part of a container's life.
    /// Calling them closed would read as a claim that something ended there.
    #[must_use]
    pub const fn of(status: Status) -> Option<Self> {
        Some(match status {
            Status::Printed | Status::Packeted => Self::Reference,
            Status::BuyerKeyed | Status::SubAgentKeyed => Self::Template,
            Status::Initiated => Self::Initiated,
            Status::InWork
            | Status::Opened
            | Status::Disputed
            | Status::DisputeProven
            | Status::DisputeUnproven
            | Status::Appealed
            | Status::Settled => Self::Working,
            Status::Finalized
            | Status::Exported
            | Status::Lost
            | Status::Expired
            | Status::ActivatedTooLate
            | Status::KeyLost
            | Status::Prescribed => Self::Closed,
            Status::Reserved8 | Status::Reserved33 => return None,
        })
    }

    /// Whether work can happen at this stage.
    ///
    /// **Only [`Stage::Working`]**, and the reason is `[decision]` 11.09 quoted in the
    /// module docs: a working container must already hold record 0 of the client
    /// key and page 0 of the journal. A template has neither — it is ready to be
    /// registered and sold on, which is a different thing from being ready to
    /// work.
    #[must_use]
    pub const fn can_work(self) -> bool {
        matches!(self, Self::Working)
    }

    /// Whether the container can still be exported from.
    ///
    /// Closed is not empty: a frozen container (status 6) is a valid archive and
    /// the reason succession works at all — the client key is current, so an
    /// export out of it is possible. What cannot be exported is what no longer
    /// exists: exported, lost, expired, dead.
    #[must_use]
    pub const fn exportable(self) -> bool {
        !matches!(self, Self::Reference | Self::Template)
    }

    /// Whether the thing at this stage can be sold or resold.
    ///
    /// A template can. A working container cannot be sold as a template — its
    /// ownership is handed on instead (E-9), which is a different operation with
    /// different parties.
    #[must_use]
    pub const fn tradable_as_template(self) -> bool {
        matches!(self, Self::Reference | Self::Template)
    }

    /// Every stage, for the sweeps.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Reference,
            Self::Template,
            Self::Initiated,
            Self::Working,
            Self::Closed,
        ]
    }
}
