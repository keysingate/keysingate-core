//! What one event sets in motion beyond itself — the bridge out of the cycle.
//! KS-9 §10.
//!
//! # Why a cycle for one container is not enough
//!
//! Three rules never fitted inside [`crate::container::Container::press`], and
//! not for want of effort: each of them touches **more than this container**.
//!
//! | Rule | Who else it touches |
//! |---|---|
//! | writing a layer's fields | the **issuer**, filling its own slots |
//! | handing over a layer key | a **second party**, receiving it |
//! | carrying an ID to a successor | a **second container** |
//!
//! `[decision]` 12.09, the owner: "add a mechanism that starts another worker to carry out
//! the remaining events, **with logical synchronisation, not just anyhow**".
//!
//! # The synchronisation is the point, not the launching
//!
//! Launching a worker is trivial and worth nothing on its own: a worker that may
//! run at any time against any state is a worker whose result means nothing.
//! What makes this mechanism a mechanism is that every task is **bound to the
//! state that raised it** and **blocks what logically depends on it**:
//!
//! 1. **Raised** by the event that makes it necessary, carrying the section head
//!    at that moment — the container's state, named.
//! 2. **Claimed** by the worker, which gets a [`Ticket`] only while that head is
//!    still current. Anything that changed the container in between invalidates
//!    the claim, because the worker would be acting on a container that no
//!    longer exists in that form.
//! 3. **Discharged** with proof, and again only against the same head.
//! 4. **Until discharged**, the operations that depend on it are **refused** —
//!    named, one by one, in [`Task::blocks`].
//!
//! `[inference]` **Step 4 is the whole of "logical" in "logical synchronisation".** A
//! packet layer not yet written must not be initiated over; a client that has
//! not received its layer key cannot open a journal it could not encrypt to.
//! These are not policies — they are what the next step physically needs.

use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::PublicKey;

use crate::layers::Level;
use crate::layout::Zone;
use crate::operation::Operation;

/// How many refused discharges before a task is **shown** as stalled.
///
/// `[inference]` Three, and the number matters less than what it does: after it the task
/// appears in [`crate::container::Container::stalled`] and somebody has to look
/// at it. It does **not** stop the task from being answered — see the note there.
pub const MAX_REFUSALS: u32 = 3;

/// What went wrong between the cycle and the worker.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FollowupError {
    /// No such task is outstanding.
    #[error("no outstanding task at index {0}")]
    NoSuchTask(usize),
    /// The container moved on since the task was raised or claimed.
    #[error("the container has changed since this task was raised; claim it again")]
    Stale,
    /// The operation waits on a task that has not been discharged.
    ///
    /// The message carries [`Task::remedy`] — who has to do what — because a
    /// client stopped here is usually a new one, before its first line of work
    /// (T-1 of the blocker register: 100% of new clients pass this point).
    #[error("{op:?} waits on {task:?}: {remedy}", remedy = .task.remedy())]
    Blocked {
        /// What was attempted.
        op: Operation,
        /// What it waits for.
        task: Task,
    },
    /// The proof does not answer the task.
    #[error("the proof does not discharge this task")]
    WrongProof,
    /// The check of a substantial task failed.
    #[error("the work does not check out: {why}")]
    CheckFailed {
        /// Which task.
        task: Task,
        /// What did not hold.
        why: &'static str,
    },
}

/// A piece of work the cycle cannot do itself.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Task {
    /// The issuer must write this layer's fields into the layout.
    ///
    /// Raised by the operation that entered the layer; the slots are the
    /// issuer's to fill, and the cycle of one event has no issuer in it.
    WriteLayer {
        /// Which zone of the layout.
        zone: Zone,
    },
    /// The layer key must be handed to the party whose key was just laid on.
    ///
    /// Raised by E-3. Two parties and one exchange — the giving side seals, the
    /// receiving side opens — so it cannot be one party's command.
    HandOverLayer {
        /// Who receives it.
        to: PublicKey,
        /// Up to which level.
        up_to: Level,
    },
    /// The ID must be carried to the successor container.
    ///
    /// Raised by E-14. The successor does not exist inside this container, and a
    /// claim served on this ID must still reach the work that goes on there.
    CarryId {
        /// The container being left behind.
        from: Hash,
    },
}

impl Task {
    /// What has to happen for this task to be discharged, and by whom — in
    /// words a presenter can show to the party that was stopped.
    ///
    /// T-1 of the blocker register, 22.09: a client whose layer key was never
    /// handed over cannot write a line, and before this the refusal said only
    /// `OpenJournal waits on HandOverLayer { .. }` — true, and useless to the
    /// one person who met it. The text names the side that must act, because
    /// the stopped party is usually not it.
    #[must_use]
    pub const fn remedy(&self) -> &'static str {
        match self {
            Self::WriteLayer { .. } => {
                "the issuer has to write this layer's fields; nothing on the client's side moves it"
            }
            Self::HandOverLayer { .. } => {
                "the current holder has to hand the layer key over (seal it to the arriving party \
                 with `hand_over`), and the arriving party has to take delivery (`receive`); \
                 until then there is no key to write a page with. This is the onboarding step \
                 of the first delivery (C-4 of the price list)"
            }
            Self::CarryId { .. } => {
                "the ID has to be carried to the successor container; this container is frozen \
                 and waits on nothing, the task stays open so the succession is not called complete"
            }
        }
    }

    /// Which operations this task holds up until it is discharged.
    ///
    /// `[inference]` **Physical dependence, not policy.** Each row is something the next
    /// operation would need and would not have.
    #[must_use]
    pub fn blocks(&self, op: Operation) -> bool {
        match self {
            // A release layer unwritten: there is no packet to enter into it.
            Self::WriteLayer {
                zone: Zone::Release,
            } => op == Operation::ApplyPacket,
            // A packet layer unwritten: initiating over it would initiate over
            // slots that hold noise.
            Self::WriteLayer { zone: Zone::Packet } => op == Operation::Initiate,
            // Any other zone holds nothing up: the chain and identity layers are
            // written as part of what they belong to.
            Self::WriteLayer { .. } => false,
            // A client without its layer key cannot encrypt a page, so it cannot
            // open a journal, and work is what a journal is for.
            Self::HandOverLayer { .. } => {
                matches!(op, Operation::OpenJournal | Operation::RecordWork)
            }
            // Succession froze this container; nothing here waits on the ID
            // reaching the successor. It stays outstanding so that "the
            // succession is complete" is never said while it is not.
            Self::CarryId { .. } => false,
        }
    }

    /// Whether this task is **substantial**: its result is checked, not merely
    /// recorded.
    ///
    /// `[decision]` 12.09, the owner: "a check can go into the second cycle — checks
    /// of substantial acts, and accordingly the consequences of checks".
    ///
    /// `[inference]` Substantial means **the container can tell whether it was done**,
    /// and something depends on the answer. Handing over a layer key and
    /// carrying an ID are both: the first has a named recipient and a level, the
    /// second has a publication that either validates or does not. Writing a
    /// layer's fields is not — the container cannot read its own slots from
    /// here, and pretending to check it would be a check in name.
    #[must_use]
    pub const fn is_substantial(&self) -> bool {
        matches!(self, Self::HandOverLayer { .. } | Self::CarryId { .. })
    }

    /// A short name, for the spec tables and for messages.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::WriteLayer { .. } => "write the layer's fields",
            Self::HandOverLayer { .. } => "hand over the layer key",
            Self::CarryId { .. } => "carry the ID to the successor",
        }
    }
}

/// A task, together with the state of the container that raised it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Raised {
    /// What to do.
    pub task: Task,
    /// Which operation raised it.
    pub by: Operation,
    /// The head of the status section at that moment — the container, named.
    pub at_head: Hash,
    /// How many discharges of it were refused by the check.
    pub refused: u32,
}

impl Raised {
    /// A task nobody has answered in [`MAX_REFUSALS`] tries.
    ///
    /// # The consequence is visibility, and deliberately nothing else
    ///
    /// `[decision]` 12.09, the owner: "enter adequate risks as consequences, not invented ones".
    ///
    /// `[inference]` **The first version of this locked the task**: after three refusals
    /// even a correct answer was rejected. That guarded against nothing — a
    /// worker that finally does the work right is the outcome wanted — and it
    /// created a failure of its own, in which the work is done, the container
    /// will not take it, and what the task held up stays held up forever.
    ///
    /// The real risk is different and smaller: **a worker retrying and failing
    /// while nobody notices**. Visibility answers it exactly. So a stalled task
    /// is one somebody has to look at, and a correct discharge still closes it.
    #[must_use]
    pub const fn stalled(&self) -> bool {
        self.refused >= MAX_REFUSALS
    }
}

/// A worker's right to act, valid only while the container has not moved.
///
/// Holds the head it was issued against, and both the claim and the discharge
/// compare it. `[inference]` **This is the synchronisation**: a worker cannot be handed
/// a task, have the container change under it, and then report success against
/// a state that no longer exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ticket {
    /// Which outstanding task.
    pub index: usize,
    /// What to do.
    pub task: Task,
    /// The head this ticket is good for.
    pub head: Hash,
}

/// What a worker brings back, in the shape the task calls for.
///
/// `[inference]` A shape per task rather than one digest for all of them, because a
/// digest can only be compared with something and there is nothing to compare it
/// with. What **can** be checked is named here, and what cannot is left out
/// instead of dressed up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Proof {
    /// The layer's fields were written.
    ///
    /// **Checked only for the zone and for not being empty.** The slots are the
    /// issuer's and this container cannot read them from here, so a deeper check
    /// would be a check in name. What the shallow one catches is a real and dull
    /// thing: a worker reporting success having done nothing.
    LayerWritten {
        /// Which zone was filled.
        zone: Zone,
        /// The digest of what went in, for the record.
        digest: Hash,
    },
    /// The layer key was handed over. **Checked**: the recipient and the level
    /// must be the ones the task named.
    HandedOver {
        /// Who received it.
        to: PublicKey,
        /// Up to which level.
        up_to: Level,
        /// The digest of the sealed hand-over.
        sealed: Hash,
    },
    /// The ID was carried to the successor. **Checked**: the carry-over must
    /// validate, and it must start from this container.
    IdCarried {
        /// The container left behind.
        from: Hash,
        /// The container it went to.
        to: Hash,
        /// The digest of the anchored carry-over.
        anchored: Hash,
    },
}

impl Proof {
    /// Whether this answers that task, and answers it truthfully as far as the
    /// container can tell.
    ///
    /// # Errors
    ///
    /// [`FollowupError::WrongProof`] for a proof of another shape;
    /// [`FollowupError::CheckFailed`] when a substantial task's result does not
    /// hold up.
    pub fn check(&self, task: &Task) -> Result<(), FollowupError> {
        match (task, self) {
            (Task::WriteLayer { zone }, Self::LayerWritten { zone: z, digest }) => {
                if z != zone {
                    return Err(FollowupError::CheckFailed {
                        task: task.clone(),
                        why: "another zone was written",
                    });
                }
                if *digest == Hash::sha256(b"") {
                    return Err(FollowupError::CheckFailed {
                        task: task.clone(),
                        why: "nothing was written",
                    });
                }
                Ok(())
            }
            (
                Task::HandOverLayer { to, up_to },
                Self::HandedOver {
                    to: t,
                    up_to: l,
                    sealed,
                },
            ) => {
                if t.kid != to.kid || t.key != to.key {
                    return Err(FollowupError::CheckFailed {
                        task: task.clone(),
                        why: "handed to another party",
                    });
                }
                if l != up_to {
                    return Err(FollowupError::CheckFailed {
                        task: task.clone(),
                        why: "handed a different level",
                    });
                }
                if *sealed == Hash::sha256(b"") {
                    return Err(FollowupError::CheckFailed {
                        task: task.clone(),
                        why: "nothing was sealed",
                    });
                }
                Ok(())
            }
            (
                Task::CarryId { from },
                Self::IdCarried {
                    from: f,
                    to,
                    anchored,
                },
            ) => {
                if f != from {
                    return Err(FollowupError::CheckFailed {
                        task: task.clone(),
                        why: "carried from another container",
                    });
                }
                if to == from {
                    return Err(FollowupError::CheckFailed {
                        task: task.clone(),
                        why: "a container does not succeed itself",
                    });
                }
                if *anchored == Hash::sha256(b"") {
                    return Err(FollowupError::CheckFailed {
                        task: task.clone(),
                        why: "the carry-over is not anchored",
                    });
                }
                Ok(())
            }
            _ => Err(FollowupError::WrongProof),
        }
    }
}

/// What a worker brings back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discharge {
    /// The ticket it answers.
    pub ticket: Ticket,
    /// The work, in the shape the task calls for.
    pub proof: Proof,
}

impl Discharge {
    /// The digest inside the proof, whatever its shape.
    #[must_use]
    pub const fn digest(&self) -> Hash {
        match self.proof {
            Proof::LayerWritten { digest, .. } => digest,
            Proof::HandedOver { sealed, .. } => sealed,
            Proof::IdCarried { anchored, .. } => anchored,
        }
    }

    /// The value a discharge's anchor attests, when the platform anchors it.
    #[must_use]
    pub fn subject(&self) -> Hash {
        Hash::sha256_fields(&[
            b"ksg:followup:discharge:v1",
            self.ticket.head.as_bytes(),
            self.ticket.task.name().as_bytes(),
            self.digest().as_bytes(),
        ])
    }
}
