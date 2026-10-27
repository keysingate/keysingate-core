//! Issuing inside a range — the role a delegate runs. KS-4 §5c, §5d.

use ksg_core_v2::crypto::sign::{sign_doc, Ed25519Signer, KeySet, SignatureSet};
use ksg_core_v2::doc::{BlockClosure, Class, Range, Serial, Timestamp, Uri};
use ksg_issuer_v2::{IssuerError, Ledger, PacketTerms};

fn uri(s: &str) -> Uri {
    Uri::parse(s).expect("uri")
}
fn ts(s: &str) -> Timestamp {
    Timestamp::parse(s).expect("timestamp")
}
fn distributor() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:web:dist.example#d1"), [92u8; 32])
}
fn holder() -> Uri {
    uri("did:web:holder.example")
}
fn holder_key() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:web:holder.example#h1"), [61u8; 32])
}
fn holder_keys() -> KeySet {
    [holder_key().public()].into_iter().collect()
}
fn r(from: u64, to: u64) -> Range {
    Range {
        from: Serial(from),
        to: Serial(to),
    }
}

/// A delegate's ledger over the slice it was granted.
fn delegated() -> Ledger {
    Ledger::open("ksg:em:000001".into(), r(1000, 1999)).expect("open")
}

fn terms(block_size: u64) -> PacketTerms {
    PacketTerms {
        allocated_at: ts("2026-08-27T10:00:00.000Z"),
        expires_at: ts("2026-11-25T10:00:00.000Z"),
        class: Class::Heavy,
        block_size,
        anchor_period_ms: None,
    }
}

fn give(l: &mut Ledger, size: u64, prev: Option<&BlockClosure>) -> Result<Range, IssuerError> {
    l.allocate(&holder(), prev, &distributor(), &holder_keys(), terms(size))
        .map(|a| a.block)
}

/// A closure for a block, `used` serials used and the rest cancelled.
fn closure(block: Range, used: u64) -> BlockClosure {
    let doc = BlockClosure::draft(
        "ksg:em:000001".into(),
        block,
        if used > 0 {
            vec![Range {
                from: block.from,
                to: Serial(block.from.0 + used - 1),
            }]
        } else {
            vec![]
        },
        vec![],
        ts("2026-11-25T10:00:00.000Z"),
    );
    let sig = sign_doc(&doc, &holder_key()).expect("signature");
    BlockClosure {
        signatures: SignatureSet::new(vec![sig]),
        ..doc
    }
}

// --- the role issues inside its own range, not a release's -------------------

#[test]
fn a_delegate_starts_at_its_range_and_not_at_the_releases() {
    // The separation of §5c in one assertion: this ledger knows nothing of the
    // emission's range and everything about its own.
    let l = delegated();
    assert_eq!(l.range(), r(1000, 1999));
    assert_eq!(l.next_serial(), 1000);
}

#[test]
fn a_delegate_cannot_issue_past_what_it_was_granted() {
    // §5b's nesting, moved from a check on a document to something that cannot
    // be done: the bound is the ledger's own range.
    let mut l = delegated();
    assert_eq!(
        give(&mut l, 1000, None).expect("the whole slice"),
        r(1000, 1999)
    );

    let c = closure(r(1000, 1999), 1000);
    assert_eq!(
        give(&mut l, 1, Some(&c)).unwrap_err(),
        IssuerError::RangeExhausted {
            last: 2000,
            limit: 1999
        }
    );
}

#[test]
fn the_cursor_makes_double_issuance_impossible_rather_than_detectable() {
    // KS-4 §5d. A block always starts where the cursor is, so what was handed
    // out cannot be handed out again — and a delegate gets that property by
    // running this code rather than by promising it.
    let mut l = delegated();
    let first = give(&mut l, 100, None).expect("first");
    assert_eq!(first, r(1000, 1099));

    let c = closure(first, 100);
    let second = give(&mut l, 100, Some(&c)).expect("second");
    assert_eq!(second, r(1100, 1199));
    assert!(second.from.0 > first.to.0, "the ranges cannot overlap");
}

#[test]
fn an_empty_range_is_not_a_role() {
    // A role that may issue nothing would have to be checked for at every
    // allocation; refusing to create one removes the case.
    assert!(matches!(
        Ledger::open("ksg:em:000001".into(), r(500, 499)),
        Err(IssuerError::CorruptSnapshot(_))
    ));
}

// --- saved state is held to the same standard --------------------------------

#[test]
fn a_snapshot_round_trips() {
    let mut l = delegated();
    let block = give(&mut l, 100, None).expect("first");
    let s = l.snapshot();
    let back = Ledger::restore(s).expect("restore");
    assert_eq!(back.range(), r(1000, 1999));
    assert_eq!(back.next_serial(), 1100);
    assert_eq!(back.blocks_of(&holder()), &[block]);
}

#[test]
fn a_cursor_outside_the_range_is_refused() {
    let mut s = delegated().snapshot();
    s.next_serial = 42;
    assert_eq!(
        Ledger::restore(s).unwrap_err(),
        IssuerError::CorruptSnapshot("the cursor is outside the range")
    );
}

#[test]
fn overlapping_blocks_are_refused() {
    let mut s = delegated().snapshot();
    s.allocated.insert(
        holder().as_str().to_string(),
        vec![r(1000, 1099), r(1050, 1149)],
    );
    s.next_serial = 1150;
    assert_eq!(
        Ledger::restore(s).unwrap_err(),
        IssuerError::CorruptSnapshot("the allocated blocks overlap")
    );
}

#[test]
fn a_cursor_behind_the_last_block_is_refused() {
    let mut s = delegated().snapshot();
    s.allocated
        .insert(holder().as_str().to_string(), vec![r(1000, 1099)]);
    s.next_serial = 1050;
    assert_eq!(
        Ledger::restore(s).unwrap_err(),
        IssuerError::CorruptSnapshot("the cursor is not past the last allocated block")
    );
}

#[test]
fn a_block_outside_the_range_is_refused() {
    // The invariant an issuer never needed, because its range was the whole
    // release. A delegate's is not, and a saved state claiming blocks outside it
    // is a delegate that issued beyond its grant.
    let mut s = delegated().snapshot();
    s.allocated
        .insert(holder().as_str().to_string(), vec![r(5000, 5099)]);
    s.next_serial = 5100;
    assert!(matches!(
        Ledger::restore(s),
        Err(IssuerError::CorruptSnapshot(_))
    ));
}

// --- an issuer is this same role over a whole release ------------------------

#[test]
fn an_issuer_runs_the_same_code_a_delegate_does() {
    // The point of §5c: there is no separate implementation for the top level.
    // An issuer is an emission plus one of these over the whole of it.
    use ksg_issuer_v2::{Issuer, Terms};
    let iss = Issuer::issue(
        &Terms {
            id: "ksg:em:000001".into(),
            range: r(1, 100_000_000),
            block_ttl_days: 90,
            issuer: uri("did:web:issuer.example"),
        },
        &distributor(),
        ts("2026-08-27T00:00:00.000Z"),
    )
    .expect("issue");

    assert_eq!(iss.ledger().range(), r(1, 100_000_000));
    assert_eq!(iss.ledger().next_serial(), iss.next_serial());
}
