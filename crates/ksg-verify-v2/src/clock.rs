//! Wall-clock time as the core's [`Timestamp`].
//!
//! Core v1's workspace carried its own calendar arithmetic here. Core v2 has
//! one form of time and its own conversion both ways (spec v2 §5), so this
//! module only reads the clock and hands the milliseconds to the core: two
//! calendars are two chances to disagree about one moment.

use std::time::{SystemTime, UNIX_EPOCH};

use ksg_core_v2::doc::Timestamp;

/// Milliseconds since the Unix epoch. A clock before 1970 reads as 0.
#[must_use]
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// `ms` since the epoch as `YYYY-MM-DDTHH:MM:SS.mmmZ`; the epoch itself past
/// the year 9999, which no clock of this program reads.
#[must_use]
pub fn utc(ms: u64) -> Timestamp {
    Timestamp::from_unix_ms(ms)
        .or_else(|_| Timestamp::from_unix_ms(0))
        .unwrap_or_else(|_| unreachable_epoch())
}

/// A [`Timestamp`] as milliseconds since the epoch.
#[must_use]
pub fn parse_ms(t: &Timestamp) -> Option<u64> {
    Some(t.unix_ms())
}

#[allow(clippy::panic)]
fn unreachable_epoch() -> Timestamp {
    panic!("the epoch is a moment of the one form")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_moments() {
        assert_eq!(utc(0).as_str(), "1970-01-01T00:00:00.000Z");
        assert_eq!(utc(1_790_253_296_789).as_str(), "2026-09-24T12:34:56.789Z");
        assert_eq!(utc(951_782_400_000).as_str(), "2000-02-29T00:00:00.000Z");
        for ms in [0, 951_782_400_000, 1_790_253_296_789, 4_102_444_800_123] {
            assert_eq!(parse_ms(&utc(ms)), Some(ms));
        }
        let t = Timestamp::parse("2026-09-01T00:00:00.000Z").unwrap();
        assert_eq!(parse_ms(&t), Some(1_788_220_800_000));
    }
}
