//! The issuer's behaviour. Specification §5, §7, §12.
//!
//! What is checked is what an act verifier cannot derive: the 80% rule, the
//! requirement for a closure from the second block onward, and the sequence of
//! allocations without overlap.

use ksg_core_v2::crypto::sign::{sign_doc, Ed25519Signer, KeySet, Profile, SignatureSet};
use ksg_core_v2::doc::{BlockClosure, Class, Range, Serial, Timestamp, Uri};
use ksg_issuer_v2::{Issuer, IssuerError, PacketTerms, Terms};

fn uri(s: &str) -> Uri {
    Uri::parse(s).unwrap()
}
fn ts(s: &str) -> Timestamp {
    Timestamp::parse(s).unwrap()
}
fn issuer_key() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:web:issuer.example#k1"), [7u8; 32])
}
fn holder_key() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:key:zHolder#h1"), [42u8; 32])
}
fn holder() -> Uri {
    uri("did:web:holder.example")
}
fn holder_keys() -> KeySet {
    [holder_key().public()].into_iter().collect()
}

fn terms(to: u64) -> Terms {
    Terms {
        id: "ksg:em:000001".into(),
        range: Range {
            from: Serial(1),
            to: Serial(to),
        },
        block_ttl_days: 90,
        issuer: uri("did:web:issuer.example"),
    }
}

/// The issuer plus the packet terms the tests allocate with.
///
/// Since 2026-09-11 the class and the size belong to the **packet**, not to the
/// emission, so they are passed at allocation. The harness carries the defaults
/// a test was set up with, and derefs to the issuer so the rest reads as before.
struct Harness {
    iss: Issuer,
    class: Class,
    size: u64,
}

impl std::ops::Deref for Harness {
    type Target = Issuer;
    fn deref(&self) -> &Issuer {
        &self.iss
    }
}

impl std::ops::DerefMut for Harness {
    fn deref_mut(&mut self) -> &mut Issuer {
        &mut self.iss
    }
}

fn new_issuer(class: Class, block_size: u64, to: u64) -> Harness {
    let iss = Issuer::issue(&terms(to), &issuer_key(), ts("2026-08-27T00:00:00.000Z"))
        .expect("the emission is issued");
    Harness {
        iss,
        class,
        size: block_size,
    }
}

fn allocate(
    h: &mut Harness,
    prev: Option<&BlockClosure>,
) -> Result<ksg_core_v2::doc::BlockAllocation, IssuerError> {
    let (class, size) = (h.class, h.size);
    h.iss.allocate(
        &holder(),
        prev,
        &issuer_key(),
        &holder_keys(),
        PacketTerms {
            allocated_at: ts("2026-08-27T10:00:00.000Z"),
            expires_at: ts("2026-11-25T10:00:00.000Z"),
            class,
            block_size: size,
            anchor_period_ms: None,
        },
    )
}

/// A closure for a block: `used` serials used, the rest cancelled.
fn closure(block: Range, used: u64) -> BlockClosure {
    let mut used_submitted = vec![];
    let mut cancelled = vec![];
    if used > 0 {
        used_submitted.push(Range {
            from: block.from,
            to: Serial(block.from.0 + used - 1),
        });
    }
    if used < block.len() {
        cancelled.push(Range {
            from: Serial(block.from.0 + used),
            to: block.to,
        });
    }
    let mut doc = BlockClosure {
        context: ksg_core_v2::doc::Context,
        doc_type: "BlockClosure".into(),
        v: 3,
        emission: "ksg:em:000001".into(),
        block,
        used_submitted,
        used_not_submitted: vec![],
        cancelled,
        closed_at: ts("2026-08-28T00:00:00.000Z"),
        signatures: SignatureSet::default(),
    };
    doc.signatures = SignatureSet::new(vec![sign_doc(&doc, &holder_key()).unwrap()]);
    doc
}

#[test]
fn the_whole_range_costs_one_signature() {
    // §5: printing the whole range costs one signature. A hundred million
    // blanks are one signed document, not a hundred million documents.
    let iss = new_issuer(Class::Heavy, 1_000, 100_000_000);
    assert_eq!(iss.emission().signatures.len(), 1);
    assert_eq!(iss.emission().range.len(), 100_000_000);
    iss.emission()
        .validate(&Profile::default())
        .expect("the emission is valid");
}

#[test]
fn blocks_are_issued_sequentially_without_overlap() {
    let mut iss = new_issuer(Class::Heavy, 1_000, 10_000);
    let first = allocate(&mut iss, None).unwrap();
    assert_eq!(first.block.from, Serial(1));
    assert_eq!(first.block.to, Serial(1_000));
    assert!(
        first.prev_closure.is_none(),
        "the first block has no reference"
    );

    let second = allocate(&mut iss, Some(&closure(first.block, 1_000))).unwrap();
    assert_eq!(second.block.from, Serial(1_001));
    assert!(
        second.prev_closure.is_some(),
        "from the second block the reference is required"
    );
    assert_eq!(iss.next_serial(), 2_001);
}

#[test]
fn a_second_block_without_a_closure_is_refused() {
    // §7 rule 3. An act verifier cannot derive this — "the second block" is
    // a property of the sequence, not of a document.
    let mut iss = new_issuer(Class::Heavy, 1_000, 10_000);
    let _ = allocate(&mut iss, None).unwrap();
    assert_eq!(
        allocate(&mut iss, None).unwrap_err(),
        IssuerError::PrevClosureRequired
    );
}

#[test]
fn drawdown_below_eighty_percent_blocks_the_next_allocation() {
    // §7 rule 2. A refusal to allocate ahead of need: blocks handed out in
    // advance sit unused until they expire and occupy serials.
    let mut iss = new_issuer(Class::Heavy, 1_000, 10_000);
    let first = allocate(&mut iss, None).unwrap();

    assert_eq!(
        allocate(&mut iss, Some(&closure(first.block, 799))).unwrap_err(),
        IssuerError::DrawdownTooLow {
            used: 799,
            size: 1_000
        }
    );
    // The failed allocation did not change the state: the block is not closed
    // and the cursor is where it was. Otherwise the second attempt would run
    // into "already closed" instead of its real cause.
    assert_eq!(iss.next_serial(), 1_001);
    assert_eq!(iss.blocks_of(&holder()).len(), 1);

    // Exactly 80% is already enough: the boundary is inclusive.
    assert!(allocate(&mut iss, Some(&closure(first.block, 800))).is_ok());
}

#[test]
fn the_threshold_is_exact_at_awkward_block_sizes() {
    // The threshold is computed in integers, not through a fraction: at size 3,
    // "80%" is 2.4, and rounding would decide whether the block is handed out.
    for (size, need) in [(3u64, 3u64), (5, 4), (7, 6), (10, 8), (100_000, 80_000)] {
        let mut iss = new_issuer(Class::Light, size, size * 4);
        let first = allocate(&mut iss, None).unwrap();
        assert!(
            allocate(&mut iss, Some(&closure(first.block, need - 1))).is_err(),
            "size {size}: {} must be too little",
            need - 1
        );
        let mut iss = new_issuer(Class::Light, size, size * 4);
        let first = allocate(&mut iss, None).unwrap();
        assert!(
            allocate(&mut iss, Some(&closure(first.block, need))).is_ok(),
            "size {size}: {need} must suffice"
        );
    }
}

#[test]
fn a_closure_for_another_block_is_refused() {
    let mut iss = new_issuer(Class::Heavy, 1_000, 10_000);
    let first = allocate(&mut iss, None).unwrap();
    let wrong = closure(
        Range {
            from: Serial(5_000),
            to: Serial(5_999),
        },
        1_000,
    );
    assert_eq!(
        allocate(&mut iss, Some(&wrong)).unwrap_err(),
        IssuerError::ClosureForAnotherBlock
    );
    assert_eq!(first.block.from, Serial(1));
}

#[test]
fn a_second_different_closure_for_the_same_block_is_refused() {
    // §12: an accepted closure makes the absence of gaps proved. A second,
    // different one would undo what is already proved.
    let mut iss = new_issuer(Class::Heavy, 1_000, 10_000);
    let first = allocate(&mut iss, None).unwrap();
    let c1 = closure(first.block, 1_000);
    iss.accept_closure(&c1, &holder_keys()).unwrap();

    // Resubmitting the same closure is harmless — idempotence, not a change.
    iss.accept_closure(&c1, &holder_keys()).unwrap();

    let c2 = closure(first.block, 900);
    assert_eq!(
        iss.accept_closure(&c2, &holder_keys()).unwrap_err(),
        IssuerError::AlreadyClosed { from: 1 }
    );
}

#[test]
fn heavy_rejects_a_closure_with_unsubmitted_acts() {
    // §12 for the heavy class: inclusion is mandatory, so "issued but not
    // submitted" does not occur there. The check goes through the core — the
    // issuer does not duplicate it.
    let mut iss = new_issuer(Class::Heavy, 1_000, 10_000);
    let first = allocate(&mut iss, None).unwrap();
    let mut c = closure(first.block, 1_000);
    c.used_submitted = vec![Range {
        from: Serial(1),
        to: Serial(999),
    }];
    c.used_not_submitted = vec![Range {
        from: Serial(1_000),
        to: Serial(1_000),
    }];
    c.cancelled = vec![];
    c.signatures = SignatureSet::new(vec![sign_doc(&c, &holder_key()).unwrap()]);

    assert!(matches!(
        iss.accept_closure(&c, &holder_keys()).unwrap_err(),
        IssuerError::Core(_)
    ));
}

#[test]
fn the_range_runs_out_rather_than_wrapping() {
    let mut iss = new_issuer(Class::Heavy, 1_000, 2_000);
    let first = allocate(&mut iss, None).unwrap();
    let second = allocate(&mut iss, Some(&closure(first.block, 1_000))).unwrap();
    assert_eq!(second.block.to, Serial(2_000));

    let err = allocate(&mut iss, Some(&closure(second.block, 1_000))).unwrap_err();
    assert!(matches!(err, IssuerError::RangeExhausted { .. }));
}

#[test]
fn snapshot_round_trip_and_corruption_checks() {
    let mut iss = new_issuer(Class::Heavy, 1_000, 10_000);
    let first = allocate(&mut iss, None).unwrap();
    let _ = allocate(&mut iss, Some(&closure(first.block, 1_000))).unwrap();

    let snap = iss.snapshot();
    let restored = Issuer::restore(snap.clone()).expect("honest state");
    assert_eq!(restored.next_serial(), iss.next_serial());
    assert_eq!(restored.blocks_of(&holder()).len(), 2);

    // The cursor was rolled back — handing out one serial twice is exactly what
    // makes a blank re-incarnatable.
    let mut rolled_back = snap.clone();
    rolled_back.next_serial = 500;
    assert!(matches!(
        Issuer::restore(rolled_back).unwrap_err(),
        IssuerError::CorruptSnapshot(_)
    ));

    // Overlapping blocks in the state.
    let mut overlapping = snap;
    overlapping
        .allocated
        .get_mut(holder().as_str())
        .unwrap()
        .push(Range {
            from: Serial(500),
            to: Serial(1_499),
        });
    assert!(matches!(
        Issuer::restore(overlapping).unwrap_err(),
        IssuerError::CorruptSnapshot(_)
    ));
}
