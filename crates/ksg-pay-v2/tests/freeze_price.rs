//! E-14 and E-23 (KS-8): ten times the container's price, never under $10.

use ksg_pay_v2::{freeze_price_minor, FREEZE_FLOOR_MINOR};

#[test]
fn a_freeze_costs_ten_times_the_container_and_at_least_ten_dollars() {
    assert_eq!(FREEZE_FLOOR_MINOR, 10_000_000, "$10 in USDC minor units");
    // A $0.10 bare: ten times is $1 — the floor holds.
    assert_eq!(freeze_price_minor(100_000), FREEZE_FLOOR_MINOR);
    // A free container still pays the floor.
    assert_eq!(freeze_price_minor(0), FREEZE_FLOOR_MINOR);
    // Exactly $1: ten times is the floor itself.
    assert_eq!(freeze_price_minor(1_000_000), FREEZE_FLOOR_MINOR);
    // A $25 container: $250.
    assert_eq!(freeze_price_minor(25_000_000), 250_000_000);
    // No overflow at the edge.
    assert_eq!(freeze_price_minor(u128::MAX), u128::MAX);
}
