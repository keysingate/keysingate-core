//! Operations on sets of ranges. Specification §12. **Part 2.**
//!
//! The naive check "the sum of the lengths equals the block size" is WRONG: an
//! overlap in one range is exactly compensated by a gap in another. Coverage and
//! non-overlap are checked **separately**.

use crate::error::{Coverage, Invalid};

use super::{Range, Serial};

/// Merges overlapping and adjacent ranges, with sorting.
///
/// Adjacent ranges are merged deliberately: `[0,9]` and `[10,19]` cover `[0,19]`
/// with no gap, and the coverage check must see that.
#[must_use]
pub fn normalize(ranges: &[Range]) -> Vec<Range> {
    let mut sorted: Vec<Range> = ranges.iter().copied().filter(|r| !r.is_empty()).collect();
    sorted.sort_by_key(|r| (r.from.0, r.to.0));
    let mut merged: Vec<Range> = Vec::with_capacity(sorted.len());
    for r in sorted {
        match merged.last_mut() {
            Some(last) if r.from.0 <= last.to.0.saturating_add(1) => {
                last.to = Serial(last.to.0.max(r.to.0));
            }
            _ => merged.push(r),
        }
    }
    merged
}

/// The first serial occurring twice within a set.
///
/// Checked **before** normalization: `normalize` merges `[0,10]` and `[5,15]`
/// into `[0,15]` and thereby hides the internal overlap. A serial listed twice
/// in one set is as much a defect in the closure as one listed in two.
#[must_use]
pub fn self_overlap(ranges: &[Range]) -> Option<Serial> {
    let mut sorted: Vec<Range> = ranges.iter().copied().filter(|r| !r.is_empty()).collect();
    sorted.sort_by_key(|r| (r.from.0, r.to.0));
    sorted
        .iter()
        .zip(sorted.iter().skip(1))
        .find(|(prev, next)| next.from.0 <= prev.to.0)
        .map(|(_, next)| next.from)
}

/// The first serial falling into both normalized sets.
#[must_use]
pub fn first_overlap(a: &[Range], b: &[Range]) -> Option<Serial> {
    let (mut ai, mut bi) = (a.iter().peekable(), b.iter().peekable());
    while let (Some(x), Some(y)) = (ai.peek(), bi.peek()) {
        if x.to.0 < y.from.0 {
            ai.next();
        } else if y.to.0 < x.from.0 {
            bi.next();
        } else {
            return Some(Serial(x.from.0.max(y.from.0)));
        }
    }
    None
}

/// The first serial of the block not covered by the union of the normalized sets.
#[must_use]
pub fn first_gap(whole: Range, merged: &[Range]) -> Option<Serial> {
    let mut cursor = whole.from.0;
    for r in merged {
        if r.from.0 > cursor {
            return Some(Serial(cursor));
        }
        cursor = cursor.max(r.to.0.saturating_add(1));
        if cursor > whole.to.0 {
            return None;
        }
    }
    (cursor <= whole.to.0).then_some(Serial(cursor))
}

/// The closure's three sets cover the block entirely and are pairwise disjoint (§12).
///
/// # Errors
///
/// [`Invalid::ClosureCoverage`] with [`Coverage::Overlap`] or [`Coverage::Gap`],
/// naming the specific serial: "the closure is wrong" without a serial gives the
/// holder no way to fix it.
pub fn validate_partition(whole: Range, sets: [&[Range]; 3]) -> Result<(), Invalid> {
    if whole.is_empty() {
        return Err(Invalid::Schema("the block being closed is empty"));
    }

    // First, overlaps within each set — normalization hides those.
    for set in sets {
        if let Some(s) = self_overlap(set) {
            return Err(Invalid::ClosureCoverage(Coverage::Overlap { serial: s.0 }));
        }
    }

    let [s0, s1, s2] = sets;
    let normed: [Vec<Range>; 3] = [normalize(s0), normalize(s1), normalize(s2)];
    let [n0, n1, n2] = &normed;

    // Pairwise non-overlap — separately from coverage.
    for (x, y) in [(n0, n1), (n0, n2), (n1, n2)] {
        if let Some(s) = first_overlap(x, y) {
            return Err(Invalid::ClosureCoverage(Coverage::Overlap { serial: s.0 }));
        }
    }

    // Coverage by the union of all three — entirely, with no gap and no overrun.
    let all: Vec<Range> = normed.concat();
    let merged = normalize(&all);
    if let Some(first) = merged.first() {
        if first.from.0 < whole.from.0 || merged.last().is_some_and(|l| l.to.0 > whole.to.0) {
            return Err(Invalid::Schema("the closure runs past the block's bounds"));
        }
    }
    if let Some(s) = first_gap(whole, &merged) {
        return Err(Invalid::ClosureCoverage(Coverage::Gap { serial: s.0 }));
    }
    Ok(())
}

/// The part of `whole` that none of `used` covers.
///
/// `[decision] 11.09` This is what `cancelled` **is**: the packet minus everything
/// used, submitted or not. Two buckets are reported and the third is the
/// difference — so cancellation is not something the holder declares but
/// something that follows from what it declared.
///
/// The difference matters for what can be lied about. A declared `cancelled`
/// makes three numbers that must agree; a derived one makes two, and the third
/// cannot disagree with them. (The partition check in
/// [`validate_partition`] already refused a `cancelled` that was not this
/// difference — computing it means a closure cannot be built wrong in the first
/// place, rather than being caught afterwards.)
///
/// Ranges come back normalized, in ascending order.
#[must_use]
pub fn complement(whole: Range, used: &[&[Range]]) -> Vec<Range> {
    let mut covered: Vec<Range> = Vec::new();
    for set in used {
        covered.extend_from_slice(set);
    }
    let covered = normalize(&covered);

    let mut out = Vec::new();
    let mut next = whole.from.0;
    for r in covered {
        // Only the part of the covered range that falls inside `whole` counts:
        // a range reaching outside it is the partition check's business, not
        // this function's.
        if r.to.0 < whole.from.0 || r.from.0 > whole.to.0 {
            continue;
        }
        if r.from.0 > next {
            out.push(Range {
                from: Serial(next),
                to: Serial(r.from.0 - 1),
            });
        }
        next = next.max(r.to.0.saturating_add(1));
    }
    if next <= whole.to.0 {
        out.push(Range {
            from: Serial(next),
            to: whole.to,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(from: u64, to: u64) -> Range {
        Range {
            from: Serial(from),
            to: Serial(to),
        }
    }

    fn block() -> Range {
        r(4_700_000, 4_700_999)
    }

    #[test]
    fn full_coverage_ok() {
        assert!(validate_partition(
            block(),
            [
                &[r(4_700_000, 4_700_399)],
                &[r(4_700_400, 4_700_599)],
                &[r(4_700_600, 4_700_999)]
            ]
        )
        .is_ok());
    }

    #[test]
    fn gap_names_the_missing_serial() {
        let e = validate_partition(
            block(),
            [
                &[r(4_700_000, 4_700_398)],
                &[r(4_700_400, 4_700_599)],
                &[r(4_700_600, 4_700_999)],
            ],
        )
        .unwrap_err();
        assert_eq!(
            e,
            Invalid::ClosureCoverage(Coverage::Gap { serial: 4_700_399 })
        );
    }

    #[test]
    fn overlap_caught_even_when_lengths_sum_to_block_size() {
        // The length sum equals the block size, yet there is both an overlap
        // and a gap — exactly the case the naive sum check lets through.
        let e = validate_partition(
            block(),
            [
                &[r(4_700_000, 4_700_400)],
                &[r(4_700_400, 4_700_599)],
                &[r(4_700_601, 4_700_999)],
            ],
        )
        .unwrap_err();
        assert!(matches!(
            e,
            Invalid::ClosureCoverage(Coverage::Overlap { .. })
        ));
    }

    #[test]
    fn overlap_inside_one_set_is_not_hidden_by_normalization() {
        // normalize() would merge [0,10] and [5,15] into [0,15] and coverage
        // would resolve. A serial listed twice in one set must be noticed.
        let e = validate_partition(r(0, 15), [&[r(0, 10), r(5, 15)], &[], &[]]).unwrap_err();
        assert_eq!(e, Invalid::ClosureCoverage(Coverage::Overlap { serial: 5 }));
    }

    #[test]
    fn adjacent_ranges_cover_without_gap() {
        assert!(validate_partition(r(0, 19), [&[r(0, 9)], &[r(10, 19)], &[]]).is_ok());
    }

    #[test]
    fn spilling_outside_the_block_is_rejected() {
        assert!(validate_partition(r(10, 20), [&[r(5, 20)], &[], &[]]).is_err());
    }

    #[test]
    fn empty_sets_leave_the_whole_block_uncovered() {
        let e = validate_partition(r(1, 5), [&[], &[], &[]]).unwrap_err();
        assert_eq!(e, Invalid::ClosureCoverage(Coverage::Gap { serial: 1 }));
    }
}
