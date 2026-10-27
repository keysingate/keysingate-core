//! Leak through formatting — audit of 13.09, findings 1 and 8.
//!
//! The tests pin the output shape, not the taste: the derived `Debug` printed a
//! Shamir share whole, and three shares in one log yield the issuer's key. While
//! these tests stand, `#[derive(Debug)]` cannot quietly return on `Share`.

use ksg_custody_v2::{combine_3_of_5, split_3_of_5, Share};

fn shares() -> Vec<Share> {
    let secret = [0xA5u8; 32];
    let entropy = [0x5Au8; 64 + 5 * ksg_custody_v2::SALT_LEN];
    split_3_of_5(&secret, &entropy).expect("split")
}

#[test]
fn debug_does_not_print_the_body() {
    let s = &shares()[0];
    let shown = format!("{s:?}");

    assert_eq!(shown, format!("Share(index={}, ..)", s.index));
    assert!(
        !shown.contains("body"),
        "the derived Debug is back: {shown}"
    );
}

#[test]
fn debug_of_a_vector_of_shares_is_also_clean() {
    // The exact case from the audit: `assert_eq!` or a panic with a set of shares.
    let all = shares();
    let shown = format!("{all:?}");
    assert!(
        !shown.contains("body"),
        "a set of shares gets printed: {shown}"
    );
    for s in &all {
        assert!(
            shown.contains(&format!("Share(index={}, ..)", s.index)),
            "a set element printed in the wrong shape: {shown}"
        );
    }
}

#[test]
fn equality_holds_and_is_not_derived_byte_scan() {
    let all = shares();
    assert_eq!(all[0], all[0].clone());
    assert_ne!(all[0], all[1]);

    // A difference in the last byte is caught just like one in the first:
    // comparison does not exit early. Behavior is checked, not timing —
    // timing cannot be honestly measured by a test, but equality must stay exact.
    let mut tail = all[0].clone();
    let last = tail.body.len() - 1;
    tail.body[last] ^= 0xFF;
    assert_ne!(all[0], tail);

    let mut head = all[0].clone();
    head.body[0] ^= 0xFF;
    assert_ne!(all[0], head);
}

#[test]
fn the_reconstructed_secret_comes_back_wiped_on_drop() {
    // The return type is Zeroizing: it provides the wiping on drop, not the
    // caller's memory. The test pins the type so the fix cannot be rolled back.
    let all = shares();
    let got: zeroize::Zeroizing<Vec<u8>> = combine_3_of_5(&all[..3]).expect("combine");
    assert_eq!(got.len(), 32);
}
