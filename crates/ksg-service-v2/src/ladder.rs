//! Who may look, and at what price. `[decision]` 19.09 (CT-14), 20.09 (CT-38,
//! CT-37), 22.09 — carried over from `ksg-anchor::registry` of core v1.
//!
//! Path A verifies possession of a key, not the identity behind it: a
//! collector generates one key pair, puts it in a chain and scans without
//! end. Signatures cannot stop that; money and two streams answer it:
//!
//! | Stream | What it shows | What it gets |
//! |---|---|---|
//! | **the curious** | only itself | no limit, a price that climbs look by look, $2 to $80 000 over twenty looks |
//! | **the legal checker** | proof of standing for the issuer and the jurisdiction | the whole chain at once, no ladder — and pays the chain's fees itself |

use serde::{Deserialize, Serialize};

/// The stream a requester belongs to (CT-14).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stream {
    /// Shows only itself. No limit, a climbing price.
    Curious,
    /// Shows proof of standing. No ladder; pays the chain's fees itself.
    LegalChecker,
}

/// The price of each look for the curious, in cents (`[decision]` 20.09,
/// CT-38): one entry per look, from the first.
///
/// | look | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 |
/// |---|---|---|---|---|---|---|---|---|---|---|
/// | $ | 2 | 24 | 80 | 120 | 200 | 900 | 1 600 | 3 200 | 4 800 | 8 000 |
///
/// | look | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 | 19 | 20 |
/// |---|---|---|---|---|---|---|---|---|---|---|
/// | $ | 14 400 | 25 600 | 38 400 | 52 000 | 64 000 | 72 000 | 73 600 | 75 200 | 76 800 | 80 000 |
pub const LADDER_CENTS: [u64; 20] = [
    200, 2_400, 8_000, 12_000, 20_000, 90_000, 160_000, 320_000, 480_000, 800_000, 1_440_000,
    2_560_000, 3_840_000, 5_200_000, 6_400_000, 7_200_000, 7_360_000, 7_520_000, 7_680_000,
    8_000_000,
];

/// The last price of the ladder: what every look past the twentieth costs.
/// Holding rather than climbing keeps the rule the owner's — what the
/// hundredth look costs was never named.
pub const TOP_CENTS: u64 = 8_000_000;

/// What one more look costs, in cents, after `looked` looks in the period.
#[must_use]
pub fn price_of_next_cents(stream: Stream, looked: u64) -> u64 {
    if stream == Stream::LegalChecker {
        // What this stream pays is the chain's own fees, directly.
        return 0;
    }
    usize::try_from(looked)
        .ok()
        .and_then(|i| LADDER_CENTS.get(i))
        .copied()
        .unwrap_or(TOP_CENTS)
}

/// What `looks` looks in one period cost together, in cents.
#[must_use]
pub fn price_of_period_cents(stream: Stream, looks: u64) -> u64 {
    (0..looks).fold(0u64, |acc, i| {
        acc.saturating_add(price_of_next_cents(stream, i))
    })
}

/// How long the mapping of a period's anchors to their containers is kept,
/// in days (`[decision]` 20.09, CT-37; fixed firmly 22.09): three years.
/// Dropping a period on schedule is the host's job —
/// [`crate::desk::Linkage::forget`] is what it calls.
pub const KEY_RETENTION_DAYS: u32 = 3 * 365;
