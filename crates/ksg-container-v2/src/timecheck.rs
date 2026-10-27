//! The time guard — F-10, the backup that refuses an action on an invalid date.
//!
//! # Why a guard and not a calculation
//!
//! Nothing in this codebase does arithmetic on dates. `Timestamp` is an RFC 3339
//! string whose lexicographic order is its chronological one, and no calendar is
//! parsed anywhere. That is deliberate: a calendar in the middle of a rule is a
//! place where two implementations disagree about a leap second and produce
//! different containers.
//!
//! So the comparisons arrive **already made**. The caller has a clock and a
//! calendar; this module has the rule about what to do with the answers, and
//! refusing is what it does.
//!
//! `[decision]` F-10 calls it a backup script: it does not decide anything on its own,
//! it prevents an action when the date does not hold up. That is the shape here —
//! every function returns a refusal or nothing.
//!
//! # The three things it guards
//!
//! | Guard | Rule | Where the rule comes from |
//! |---|---|---|
//! | the packet's window | initiation only inside it | I-2, and status 20 for too late |
//! | the offset | strictly increasing | F-3, `[decision]` 11.09 |
//! | the order of the two stamps | allocated before it expires | I-2 |

use ksg_core_v2::status::{Event, Status};

/// One day in the container's time marks (milliseconds).
pub const DAY_MS: u64 = 86_400_000;

/// Goal 1, `bare` v2 (owner's decision 06.10, `[doc:BARE-V2-SPEC]` K7):
/// a `bare` container with no record of work bricks this long after its
/// initiation. Two years, as days — the container keeps no calendar.
///
/// Lives here, in `ksg-container-v2` and not in the core: the core's statuses
/// do not change for `bare` (spec §6), the idle term is a container rule.
pub const BARE_IDLE_AFTER_ISSUE_MS: u64 = 730 * DAY_MS;

/// Goal 1, `bare` v2 (owner's decision 06.10 and 07.10, spec K7): a `bare`
/// container with records of work bricks this long after its last record.
/// One year.
pub const BARE_IDLE_AFTER_RECORD_MS: u64 = 365 * DAY_MS;

/// What the guard refuses, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TimeRefusal {
    /// The packet's term had already run out.
    ///
    /// The event to record is [`Event::InitiateTooLate`], which lands the
    /// container on status 20 — not a failure to note and retry, a terminal
    /// state, because a packet that has expired does not come back.
    #[error("the packet's term had run out before this initiation")]
    TooLate,
    /// The packet's term had not started.
    #[error("the packet's term has not begun")]
    TooEarly,
    /// The offset did not increase.
    #[error("the offset must increase; {presented} is not past {last}")]
    OffsetWentBack {
        /// What the page claimed.
        presented: u64,
        /// What the journal already holds.
        last: u64,
    },
    /// The window itself is malformed — it ends before it starts.
    #[error("the packet's window ends before it begins")]
    WindowInverted,
}

/// Where a moment falls relative to a window, as the **caller** worked it out.
///
/// Three answers and nothing else, because three is all the rules below need and
/// a fourth would invite this module to start comparing dates itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Where {
    /// Before the window opened.
    Before,
    /// Inside it.
    Inside,
    /// After it closed.
    After,
}

/// Whether an initiation may happen, given where its moment falls.
///
/// # Errors
///
/// [`TimeRefusal::TooEarly`] or [`TimeRefusal::TooLate`]. The second is the one
/// that matters: it is how a container reaches status 20 rather than 5, and
/// getting it wrong would let an expired packet be worked in.
pub const fn may_initiate(at: Where) -> Result<(), TimeRefusal> {
    match at {
        Where::Inside => Ok(()),
        Where::Before => Err(TimeRefusal::TooEarly),
        Where::After => Err(TimeRefusal::TooLate),
    }
}

/// The status event a refused initiation records.
///
/// A refusal on time is not silence: too late is [`Event::InitiateTooLate`] and
/// the container moves to 20. Too early leaves the container where it was —
/// nothing happened, and nothing is recorded.
#[must_use]
pub const fn event_for(refusal: TimeRefusal) -> Option<Event> {
    match refusal {
        TimeRefusal::TooLate => Some(Event::InitiateTooLate),
        TimeRefusal::TooEarly
        | TimeRefusal::OffsetWentBack { .. }
        | TimeRefusal::WindowInverted => None,
    }
}

/// Whether a packet whose term ran out while it sat unused should expire.
///
/// Separate from [`may_initiate`] because they are different events: this one is
/// the packet dying on its own (status 10), the other is somebody trying to use
/// it after it died (status 20). The statuses were kept distinct on purpose, and
/// the two guards keep the distinction.
#[must_use]
pub const fn expired_unused(at: Where, status: Status) -> Option<Event> {
    match (at, status) {
        (Where::After, Status::Packeted | Status::BuyerKeyed | Status::SubAgentKeyed) => {
            Some(Event::PacketTermExpired)
        }
        _ => None,
    }
}

/// Whether a page's offset may follow the journal's last.
///
/// # Errors
///
/// [`TimeRefusal::OffsetWentBack`] on anything that is not an increase —
/// including equality. `[decision]` 11.09 settled F-3 as a refusal rather than a mark,
/// and equality is the case a "not less than" rule would have let through.
pub const fn may_follow(presented: u64, last: u64) -> Result<(), TimeRefusal> {
    if presented > last {
        Ok(())
    } else {
        Err(TimeRefusal::OffsetWentBack { presented, last })
    }
}

/// Whether a window is a window at all.
///
/// # Errors
///
/// [`TimeRefusal::WindowInverted`] when it ends before it starts. Checked because
/// an inverted window makes every moment `After`, which would read as "every
/// packet has expired" — a wrong answer delivered confidently.
pub const fn window_sane(starts_before_it_ends: bool) -> Result<(), TimeRefusal> {
    if starts_before_it_ends {
        Ok(())
    } else {
        Err(TimeRefusal::WindowInverted)
    }
}
