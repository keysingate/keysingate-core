//! Leaks through formatting and comparison — 13.09 audit, findings 2 and 8.
//!
//! `LayerKey` was printed by hand from the start; what was left to the derive
//! was comparison, and it exits at the first difference. The tests pin both forms.

use ksg_container_v2::LayerKey;

#[test]
fn debug_prints_nothing_of_the_key() {
    let k = LayerKey::from_bytes([0x11; 32]);
    assert_eq!(format!("{k:?}"), "LayerKey(..)");

    // And inside the struct that holds it: the derived Debug on the owner
    // is safe exactly because it delegates here.
    let shown = format!("{:?}", vec![k]);
    assert!(!shown.contains("17") && !shown.contains("0x11"), "{shown}");
}

#[test]
fn equality_stays_correct_at_both_ends_of_the_key() {
    let base = LayerKey::from_bytes([0x11; 32]);
    assert_eq!(base, LayerKey::from_bytes([0x11; 32]));

    let mut head = [0x11u8; 32];
    head[0] ^= 0xFF;
    assert_ne!(base, LayerKey::from_bytes(head));

    let mut tail = [0x11u8; 32];
    tail[31] ^= 0xFF;
    assert_ne!(base, LayerKey::from_bytes(tail));
}
