//! The protocol documents. **Types are part 1, validation part 2.**
//!
//! The primitives common to every document also live here: the opaque
//! identifier [`Uri`], the timestamp [`Timestamp`], the blank serial [`Serial`],
//! and the range [`Range`].

pub mod allocation;
pub mod binding;
pub mod closure;
pub mod container;
pub mod delegation;
pub mod emission;
pub mod key_inclusion;
pub mod promotion;
pub mod ranges;

pub use allocation::BlockAllocation;
pub use binding::AgentBinding;
pub use closure::BlockClosure;
pub use container::{derive_container_id, ContainerInit};
pub use delegation::{
    check_term, resolve, Delegation, GRANT_MAX_MS, GRANT_MS, GRANT_OVERLAP_MS, MAX_DEPTH,
};
pub use emission::{Class, Emission, MemoFormat, MAX_UNUSED_LIFETIME_MS};
pub use key_inclusion::KeyInclusion;
pub use promotion::ClassPromotion;

use serde::{Deserialize, Serialize};

/// An opaque identifier (§4.2).
///
/// The core neither knows nor checks who issued it: `did:key`, `did:web`, WIMSE
/// identifiers, ERC-8004, the Solana Agent Registry, and any future ones are
/// accepted alike. What is checked is **the shape, not the meaning** — declining
/// to pick an identity system is precisely what makes the core compatible with
/// all of them.
///
/// `Deserialize` is written by hand and goes through [`Uri::parse`]. A derived
/// one over a `#[serde(transparent)]` newtype bypasses the constructor, and
/// until 2026-09-18 that is what happened: any string from an untrusted
/// document became a `Uri`, empty ones included (security audit, finding 8).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct Uri(String);

impl<'de> Deserialize<'de> for Uri {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::parse(s).map_err(serde::de::Error::custom)
    }
}

impl Uri {
    /// An identifier from a string.
    ///
    /// # Errors
    ///
    /// [`crate::error::Invalid::Schema`] if the string is empty or contains no
    /// scheme separator. Parsing deliberately goes no further than that.
    pub fn parse(s: impl Into<String>) -> Result<Self, crate::error::Invalid> {
        let s = s.into();
        if s.is_empty() || !s.contains(':') {
            return Err(crate::error::Invalid::Schema("URI: no scheme"));
        }
        Ok(Self(s))
    }

    /// The string representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for Uri {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The `@context` of every document of core v2 (spec v2 §3.3).
pub const CONTEXT: &str = "urn:keysingate:core:v3";

/// The `@context` field: it serializes as [`CONTEXT`] and parses only from it,
/// so a document of core v1 (`urn:keysingate:core:v1`) or of anything else
/// does not become a core v2 document by accident.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Context;

impl Serialize for Context {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(CONTEXT)
    }
}

impl<'de> Deserialize<'de> for Context {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        if s == CONTEXT {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom(
                "@context is not urn:keysingate:core:v3",
            ))
        }
    }
}

/// A moment in time: exactly `YYYY-MM-DDTHH:MM:SS.mmmZ` — UTC, three digits of
/// milliseconds, 24 characters (spec v2 §5).
///
/// # Why one form and nothing else
///
/// Core v1 accepted a fraction of any length, and compared timestamps as
/// strings: `…:00.5Z` sorted **before** `…:00Z` though it is later, so "the
/// earliest anchor" could be the wrong one (audit of 30.09, Ya-5). A single
/// fixed form makes the order of the strings the order of the moments; the
/// calendar is checked in full (days of the month, leap years), and a leap
/// second is refused — a form with 61 seconds has no place in a fixed order.
///
/// A timestamp on its own **proves nothing**: only the bounds — the emission
/// below, a read anchor above — carry weight (spec v2 §5.3, §7).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct Timestamp(String);

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::parse(s).map_err(serde::de::Error::custom)
    }
}

/// The length of the one accepted form.
const TIMESTAMP_LEN: usize = 24;

/// Days since 1970-01-01 of a civil date (proleptic Gregorian).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn days_in_month(y: u32, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        _ => 28,
    }
}

impl Timestamp {
    /// A timestamp from its one accepted form.
    ///
    /// # Errors
    ///
    /// [`crate::error::Invalid::Schema`] for any other form, a date that is
    /// not in the calendar, or a moment before 1970.
    pub fn parse(s: impl Into<String>) -> Result<Self, crate::error::Invalid> {
        let s = s.into();
        Self::millis_of(&s)?;
        Ok(Self(s))
    }

    /// A timestamp from milliseconds since 1970-01-01T00:00:00.000Z.
    ///
    /// # Errors
    ///
    /// [`crate::error::Invalid::Schema`] past the year 9999.
    pub fn from_unix_ms(ms: u64) -> Result<Self, crate::error::Invalid> {
        let bad = crate::error::Invalid::Schema("Timestamp: out of range");
        let days = i64::try_from(ms / 86_400_000).map_err(|_| bad.clone())?;
        let rem = ms % 86_400_000;
        // Civil from days (Howard Hinnant's algorithm).
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = yoe + era * 400 + i64::from(m <= 2);
        if y > 9999 {
            return Err(bad);
        }
        Self::parse(format!(
            "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z",
            rem / 3_600_000,
            (rem % 3_600_000) / 60_000,
            (rem % 60_000) / 1000,
            rem % 1000
        ))
    }

    /// Milliseconds since 1970-01-01T00:00:00.000Z.
    #[must_use]
    pub fn unix_ms(&self) -> u64 {
        // A `Timestamp` exists only once `millis_of` accepted its string.
        Self::millis_of(&self.0).unwrap_or(0)
    }

    fn millis_of(s: &str) -> Result<u64, crate::error::Invalid> {
        let bad = || crate::error::Invalid::Schema("Timestamp: not YYYY-MM-DDTHH:MM:SS.mmmZ");
        let b = s.as_bytes();
        if b.len() != TIMESTAMP_LEN {
            return Err(bad());
        }
        let at = |i: usize| b.get(i).copied().ok_or_else(bad);
        for (i, want) in [
            (4, b'-'),
            (7, b'-'),
            (10, b'T'),
            (13, b':'),
            (16, b':'),
            (19, b'.'),
            (23, b'Z'),
        ] {
            if at(i)? != want {
                return Err(bad());
            }
        }
        let num = |from: usize, len: usize| -> Result<u32, crate::error::Invalid> {
            let mut n: u32 = 0;
            for i in from..from + len {
                let c = at(i)?;
                if !c.is_ascii_digit() {
                    return Err(bad());
                }
                n = n * 10 + u32::from(c - b'0');
            }
            Ok(n)
        };
        let (y, mo, d) = (num(0, 4)?, num(5, 2)?, num(8, 2)?);
        let (h, mi, se, ms) = (num(11, 2)?, num(14, 2)?, num(17, 2)?, num(20, 3)?);
        if y < 1970
            || !(1..=12).contains(&mo)
            || d == 0
            || d > days_in_month(y, mo)
            || h > 23
            || mi > 59
            || se > 59
        {
            return Err(bad());
        }
        let days = days_from_civil(i64::from(y), i64::from(mo), i64::from(d));
        let days = u64::try_from(days).map_err(|_| bad())?;
        Ok(days * 86_400_000
            + u64::from(h) * 3_600_000
            + u64::from(mi) * 60_000
            + u64::from(se) * 1000
            + u64::from(ms))
    }

    /// The string representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for Timestamp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A blank serial.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Serial(pub u64);

impl core::fmt::Display for Serial {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A contiguous range of serials, bounds inclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Range {
    /// The lower bound, inclusive.
    pub from: Serial,
    /// The upper bound, inclusive.
    pub to: Serial,
}

impl Range {
    /// The range contains the serial.
    #[must_use]
    pub const fn contains(&self, s: Serial) -> bool {
        self.from.0 <= s.0 && s.0 <= self.to.0
    }

    /// The number of serials. Returns 0 for an inverted range.
    ///
    /// Saturating: a range of `0..=u64::MAX` counts `u64::MAX` serials rather
    /// than overflowing back to zero. Such a range cannot arise from a document
    /// this crate accepts, but `Range` is public and reachable from untrusted
    /// JSON, and a length that silently became 0 would read as "empty" —
    /// the opposite of what it is (security audit of 2026-09-13, finding 20).
    #[must_use]
    pub const fn len(&self) -> u64 {
        if self.to.0 < self.from.0 {
            0
        } else {
            (self.to.0 - self.from.0).saturating_add(1)
        }
    }

    /// The range is empty (inverted).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
