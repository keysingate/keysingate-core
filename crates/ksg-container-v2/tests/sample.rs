//! Signed binding of a selective hash. `[decision]` 22.09, CT-44, CT-45.

use std::io::Cursor;

use ksg_container_v2::seal::{verify_sealed, IssuerSeal};
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{Ed25519Signer, KeySet, Profile};
use ksg_core_v2::doc::Uri;
use ksg_core_v2::journal::Mode;

use ksg_container_v2::sample::{
    choose, price_of_signature_cents, Binding, SampleError, SampleRecord, Step, SAMPLE_MAX_BYTES,
};

fn file(n: usize, salt: u8) -> Cursor<Vec<u8>> {
    Cursor::new((0..n).map(|i| (i as u8).wrapping_mul(31) ^ salt).collect())
}

#[test]
fn the_price_doubles_to_256_and_holds_there() {
    // [decision] 22.09, CT-44: $2, ×2 each, $256 from the 8th, for every one after.
    let dollars: Vec<u64> = (0..12).map(|n| price_of_signature_cents(n) / 100).collect();
    assert_eq!(dollars, [2, 4, 8, 16, 32, 64, 128, 256, 256, 256, 256, 256]);
    assert_eq!(price_of_signature_cents(u64::MAX), 25_600);
}

#[test]
fn the_pieces_never_add_up_to_more_than_256_kb() {
    for count in [1, 3, 7, 64, 1000] {
        let spans = choose(&[9; 32], 12 * 1024 * 1024 * 1024, count).expect("spans");
        let total: u64 = spans.iter().map(|s| u64::from(s.len)).sum();
        assert!(
            total <= SAMPLE_MAX_BYTES,
            "{count} pieces took {total} bytes"
        );
        assert_eq!(spans.len(), count);
    }
}

#[test]
fn every_signing_takes_new_positions() {
    // [decision] 22.09: a new selection at every signature. Keeping old pieces buys
    // nothing.
    let a = choose(&[1; 32], 1 << 30, 3).expect("a");
    let b = choose(&[2; 32], 1 << 30, 3).expect("b");
    assert_ne!(a, b);
}

#[test]
fn pieces_stay_inside_the_file() {
    let size = 5_000;
    for s in choose(&[7; 32], size, 50).expect("spans") {
        assert!(s.offset + u64::from(s.len) <= size);
    }
}

fn binding() -> (Binding, Cursor<Vec<u8>>) {
    let mut stored = file(100_000, 1);
    let mut clean = file(99_000, 1);
    let record = SampleRecord::take(&[3; 32], &mut stored, &mut clean, 3).expect("record");
    assert_ne!(
        record.clean, record.signed,
        "clean and signed are two states"
    );
    (Binding::quote(record, 0), stored)
}

#[test]
fn the_owners_order_price_consent_second_reading_payment_journal() {
    let (mut b, mut stored) = binding();
    assert_eq!(b.step(), Step::Quoted);
    assert_eq!(b.price_cents, 200);
    b.agree().expect("agree");
    b.confirm(&mut stored).expect("the same hash, read again");
    b.pay("tx:0001".into()).expect("pay");
    assert_eq!(b.payment.as_deref(), Some("tx:0001"));
    b.for_journal(Mode::Local).expect("into the journal");
}

#[test]
fn no_step_can_be_skipped() {
    let (mut b, mut stored) = binding();
    assert!(
        b.for_journal(Mode::Local).is_err(),
        "journal before payment"
    );
    assert!(
        b.pay("tx".into()).is_err(),
        "payment before the second reading"
    );
    assert!(
        b.confirm(&mut stored).is_err(),
        "second reading before agreement"
    );
    b.agree().expect("agree");
    assert!(b.agree().is_err(), "agreeing twice");
}

#[test]
fn a_different_file_at_the_second_reading_is_refused() {
    let (mut b, _) = binding();
    b.agree().expect("agree");
    let mut other = file(100_000, 2);
    assert_eq!(b.confirm(&mut other), Err(SampleError::Mismatch));
    assert_eq!(b.step(), Step::Agreed, "nothing moved");
}

#[test]
fn the_signature_covers_the_positions_as_well_as_the_hashes() {
    let (b, _) = binding();
    let mut moved = b.record.clone();
    moved.spans[0].offset += 1;
    assert_ne!(b.record.subject(), moved.subject());
}

fn issuer() -> Ed25519Signer {
    Ed25519Signer::from_seed(
        Uri::parse("did:web:issuer.example#i1").expect("uri"),
        [3; 32],
    )
}

fn paid() -> (Binding, Cursor<Vec<u8>>) {
    let (mut b, mut stored) = binding();
    b.agree().expect("agree");
    b.confirm(&mut stored).expect("reread");
    b.pay("tx:1".into()).expect("pay");
    (b, stored)
}

#[test]
fn in_pro_the_record_goes_in_only_with_the_issuers_seal() {
    // [decision] 23.09, CT-47, CT-48: the container signs with the seal laid at
    // printing; the issuer takes no part.
    let container = Hash::sha256(b"container 000412");
    let seal = IssuerSeal::lay(
        &container,
        Uri::parse("ksg:seal:000412").expect("uri"),
        [8; 32],
        &issuer(),
    );
    let (mut b, _) = paid();
    assert!(b.for_journal(Mode::Pro).is_err(), "unsigned in Pro");
    b.for_journal(Mode::Local)
        .expect("unsigned is allowed outside Pro");
    b.sign(&seal).expect("sealed");
    b.for_journal(Mode::Pro).expect("signed in Pro");

    let keys: KeySet = [issuer().public()].into_iter().collect();
    verify_sealed(
        &container,
        &seal.public(),
        seal.certificate(),
        &keys,
        &b.record.subject(),
        b.issuer_signature.as_ref().expect("signature"),
        &Profile::default(),
    )
    .expect("anyone can check it against the issuer's keys");
}

#[test]
fn a_seal_certifies_nothing_in_another_container() {
    let seal = IssuerSeal::lay(
        &Hash::sha256(b"container A"),
        Uri::parse("ksg:seal:A").expect("uri"),
        [8; 32],
        &issuer(),
    );
    let (mut b, _) = paid();
    b.sign(&seal).expect("sealed");
    let keys: KeySet = [issuer().public()].into_iter().collect();
    assert!(verify_sealed(
        &Hash::sha256(b"container B"),
        &seal.public(),
        seal.certificate(),
        &keys,
        &b.record.subject(),
        b.issuer_signature.as_ref().expect("signature"),
        &Profile::default(),
    )
    .is_err());
}

#[test]
fn the_seal_comes_after_payment() {
    let seal = IssuerSeal::lay(
        &Hash::sha256(b"c"),
        Uri::parse("ksg:seal:c").expect("uri"),
        [8; 32],
        &issuer(),
    );
    let (mut b, _) = binding();
    assert!(b.sign(&seal).is_err());
}
