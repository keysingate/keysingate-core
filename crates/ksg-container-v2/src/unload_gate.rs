//! The unload gate — the only door to the work journal's contents.
//!
//! The gate answers the question CT-31 left open (see
//! `Mekhanizm_vygruzki_v_spore.md`; owner decisions `[decision]` 11.09).
//!
//! # Why a gate, when the checks are already written
//!
//! The parts of the path to the contents exist separately: voluntary
//! opening (`crate::voluntary::VoluntaryOpening`), a court-appointed expert
//! (`crate::expert::establish`, `ExpertDisclosure`), point and final
//! disclosure (`ksg_core_v2::journal::verify_bound_point`, `verify_bound`), operation seats
//! (`Operation::keys`), and the record of a refused attempt.
//!
//! What was missing — **a place where they meet**. Until they meet at one
//! point, the claimant picks which checks to pass and which to skip: call
//! `verify_full` past the operation seats, or press unload past the expert
//! appointment. The gate answers a single question — **whether this set of
//! keys may receive these contents now** — and no other.
//!
//! # Three paths, and no fourth
//!
//! | Path | Who | Proved by |
//! |---|---|---|
//! | **Principals' consent** | owner **and** client | operation seats (E-11) |
//! | **Voluntary opening** | client, owner, and **two arbiters** | `VoluntaryOpening`, where each arbiter is named by three independent parties |
//! | **Court appointment** | expert named by the principals **who also recorded themselves in the chain** | `AppointedExpert` plus `ExpertDisclosure` in the scope the expert set |
//!
//! `[inference]` A court compels people, not the box: on the third path the
//! unloading is done by the **principals themselves**. There is no button here
//! for an outsider holding a court decision, and none will appear.
//!
//! # A refusal is an event too
//!
//! `[decision]` 11.09 on B-6: the attempt is recorded **under anchor**. So a gate
//! refusal carries a ready-made record: silence would mean someone pulled the
//! door and nobody would ever learn of it.

use crate::expert::{AppointedExpert, ExpertDisclosure};
use crate::voluntary::{RefusedAttempt, VoluntaryOpening};
use ksg_core_v2::anchor::Attestation;
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{Profile, PublicKey};
use ksg_core_v2::doc::{MemoFormat, Uri};

use crate::command::{Refusal, Roster};
use crate::operation::{Button, Keys, Operation, Seat};

/// Who presents the unload command: the signers and the role roster.
///
/// Together, not as two arguments: signatures without roles mean nothing, and
/// roles without signatures mean even less — split apart, they allow a call
/// that passes one and forgets the other.
#[derive(Debug, Clone, Copy)]
pub struct Presenters<'a> {
    /// Keys whose signatures the layer above already verified.
    pub signers: &'a [PublicKey],
    /// Who holds which role (O-3).
    pub roster: &'a Roster,
}

/// What the claimant uses to justify the right to the contents.
#[derive(Debug)]
pub enum Route<'a> {
    /// Principals' consent: owner and client together (E-11).
    Principals,
    /// Voluntary opening: four parties, two arbiters, and the statement's
    /// anchor — without a chain record four signatures say only that four
    /// keys agreed, and only to whoever holds the document.
    Voluntary {
        /// The opening itself.
        opening: &'a VoluntaryOpening,
        /// The statement's anchor in the chain.
        anchor: &'a Attestation,
    },
    /// A court-appointed expert, and the principals' permission for them.
    Expert {
        /// The seated expert: named by the principals and recorded in the chain.
        expert: &'a AppointedExpert,
        /// The permission the principals gave — in the scope the expert set.
        disclosure: &'a ExpertDisclosure,
        /// The client's key.
        client: &'a PublicKey,
        /// The owner-holder's key.
        owner: &'a PublicKey,
    },
}

/// What the gate let through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unload {
    /// The container whose contents are handed over.
    pub container: Hash,
    /// How the right was obtained.
    pub how: Granted,
}

/// The path by which the right was obtained — for the report and the work journal record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Granted {
    /// Owner and client together.
    Principals,
    /// Voluntary opening by four parties.
    Voluntary,
    /// Court appointment.
    CourtAppointed,
}

/// The one whose contents are requested: the container and the form it was born in.
///
/// Two unchanging things the gate must know before looking at roles and
/// signatures. Kept together because they travel together, and passing them
/// separately means one day passing one without the other.
#[derive(Debug, Clone, Copy)]
pub struct Subject {
    /// The container's identifier.
    pub container: Hash,
    /// The memo form chosen at birth (`[decision]` 13.09 §8.3).
    pub memo: MemoFormat,
}

/// A gate refusal with the attempt record the layer above must anchor.
#[derive(Debug)]
pub struct Denied {
    /// Why it was refused.
    pub reason: Refusal,
    /// The attempt record — it goes under anchor whatever the outcome.
    pub attempt: RefusedAttempt,
}

/// Lets the contents through or refuses, keeping the attempt record.
///
/// # Errors
///
/// [`Denied`] with the reason and a ready attempt record: wrong operation,
/// seats missing, the presented path not confirmed.
pub fn authorize(
    subject: Subject,
    op: Operation,
    route: &Route<'_>,
    who: Presenters<'_>,
    profile: &Profile,
    offset_ms: u64,
) -> Result<Unload, Box<Denied>> {
    let Subject { container, memo } = subject;
    let container = &container;
    let Presenters { signers, roster } = who;
    let presented: Vec<Uri> = signers.iter().map(|k| k.kid.clone()).collect();
    // The attempt record is built from the same reason as the refusal: two
    // different texts about one event will drift apart, exactly where they
    // will be read — in a dispute.
    let deny = |reason: Refusal| -> Box<Denied> {
        Box::new(Denied {
            attempt: RefusedAttempt::of(
                *container,
                &crate::voluntary::GateError::Opening(leak(&reason)),
                presented.clone(),
                offset_ms,
            ),
            reason,
        })
    };

    // The plain format never leaves (`[decision]` 13.09 §8.3). Checked first:
    // refusing the polygon depends on neither roles nor signatures, and
    // parsing them would answer a question that should never have arisen.
    // The attempt record is still built as usual — trying to carry the polygon
    // outside must stay under anchor all the more.
    if memo == MemoFormat::Plain {
        return Err(deny(Refusal::PlainIsNotPresented));
    }

    // The gate answers for unloading only. Everything else arrives here by
    // mistake, and such a mistake must not pass silently.
    if !matches!(op, Operation::FullExport | Operation::DiscloseToExpert) {
        return Err(deny(Refusal::WrongButton {
            op,
            expected: Button::Export,
            offered: op.button(),
        }));
    }

    match route {
        Route::Principals => {
            // Operation seats — the same check as on the common door: owner and
            // client, each with their own key.
            for seat in seats_of(op) {
                if !seat_filled(*seat, signers, roster) {
                    return Err(deny(Refusal::RoleMissing { op, seat: *seat }));
                }
            }
            Ok(Unload {
                container: *container,
                how: Granted::Principals,
            })
        }
        Route::Voluntary { opening, anchor } => {
            opening
                .validate(container, anchor, profile)
                .map_err(|_| deny(Refusal::Signature))?;
            Ok(Unload {
                container: *container,
                how: Granted::Voluntary,
            })
        }
        Route::Expert {
            expert,
            disclosure,
            client,
            owner,
        } => {
            // The expert is already seated: the container establishes them
            // itself (`expert::establish`, at DiscloseToExpert) from the
            // principals' entry on a page of the journal and the expert's own
            // anchored record — never taken from the presenter (17.10). What is checked
            // here is the permission; the pages are taken from the journal,
            // which checks the scope again against what it holds.
            disclosure
                .check(container, expert, client, owner, profile)
                .map_err(|_| deny(Refusal::Signature))?;
            Ok(Unload {
                container: *container,
                how: Granted::CourtAppointed,
            })
        }
    }
}

/// The seats the unload operation requires.
fn seats_of(op: Operation) -> &'static [Seat] {
    match op.keys() {
        Keys::Seats(s) => s,
        // Past 17.09 the unload keeps its seats; the branch stays so the
        // compiler catches a return to the old behavior.
        Keys::Set | Keys::AnyOf(_) => &[],
    }
}

/// Whether a seat is held by one of the signers.
fn seat_filled(seat: Seat, signers: &[PublicKey], roster: &Roster) -> bool {
    // The key itself, not just its `kid`: someone else's key under a known
    // `kid` holds no seat (audit of 23.09, K1).
    signers.iter().any(|k| match seat {
        Seat::Exactly(role) => roster.holds(k, role),
        Seat::Either(a, b) => roster.holds(k, a) || roster.holds(k, b),
    })
}

/// The one-line refusal reason — for the attempt record.
///
/// `JournalError::Opening` takes `&'static str`, so the text is picked from a
/// closed set: no free-form string from a refusal gets here, and no one can
/// write someone else's text into the work journal through the gate.
const fn leak(reason: &Refusal) -> &'static str {
    match reason {
        Refusal::WrongButton { .. } => "unload gate called for something other than unloading",
        Refusal::RoleMissing { .. } => "operation seat not held",
        Refusal::Signature => "presented path not confirmed",
        Refusal::PlainIsNotPresented => "plain-format container does not leave",
        _ => "unload refused",
    }
}
