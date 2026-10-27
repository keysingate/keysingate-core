//! Scan keys by period (KS-1 §14.4): derived from the holder's master key,
//! one per label; a key file holds one key or the keys of named periods.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ksg_core_v2::crypto::hash::Hash;
use ksg_verify_v2::solana::{scan_keys_from_text, SealMemo, SealScanKey};

#[test]
fn a_period_key_is_its_periods_alone() {
    let master = SealScanKey::new([7; 32]);
    let aug = master.for_period("2026-08");
    let sep = master.for_period("2026-09");
    assert_eq!(aug, master.for_period("2026-08"), "deterministic");
    assert_ne!(aug, sep);
    assert_ne!(aug, master);
    let (prev, seal) = (Hash::sha256(b"prev"), Hash::sha256(b"seal"));
    assert_ne!(
        SealMemo::of(&aug, &prev, &seal),
        SealMemo::of(&sep, &prev, &seal)
    );
    // No label is a prefix of another's input: lengths are in the derivation.
    assert_ne!(master.for_period("2026-1"), master.for_period("2026-10"));
}

#[test]
fn a_key_file_holds_one_key_or_the_keys_of_periods() {
    let master = SealScanKey::new([9; 32]);
    let one = scan_keys_from_text(&format!("{}\n", master.to_hex().as_str())).unwrap();
    assert_eq!(one, vec![master.clone()]);
    let text = format!(
        r#"{{"periods": {{"2026-08": "{}", "2026-09": "{}"}}}}"#,
        master.for_period("2026-08").to_hex().as_str(),
        master.for_period("2026-09").to_hex().as_str()
    );
    assert_eq!(scan_keys_from_text(&text).unwrap().len(), 2);
    for bad in [
        "",
        "zz",
        r#"{"periods": {}}"#,
        r#"{"keys": []}"#,
        r#"{"periods": {"x": 1}}"#,
    ] {
        assert!(scan_keys_from_text(bad).is_err(), "{bad}");
    }
}
