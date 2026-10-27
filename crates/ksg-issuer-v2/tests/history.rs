//! The issuer's list of an agent's blocks. KS-1 §13, CT-31 variant A.
//!
//! What the list is for: inside a block, completeness is held by consecutive
//! serials; between blocks it is held by nothing, and "the agent's whole
//! history" is what is sold. The tests below hold the list to being a list —
//! and hold the product claim to what the list actually proves.

use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{Ed25519Signer, KeySet, Profile, PublicKey, SignatureSet};
use ksg_core_v2::doc::{BlockClosure, Class, Range, Serial, Timestamp, Uri};
use ksg_core_v2::error::Invalid;
use ksg_issuer_v2::history::{AgentHistory, HistoryEntry};
use ksg_issuer_v2::{IssuerError, Ledger, PacketTerms};

fn uri(s: &str) -> Uri {
    Uri::parse(s).expect("uri")
}
fn ts(s: &str) -> Timestamp {
    Timestamp::parse(s).expect("timestamp")
}
fn issuer_key() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:web:issuer.example#i1"), [7u8; 32])
}
fn issuer_keys() -> KeySet {
    [issuer_key().public()].into_iter().collect()
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
fn agent() -> PublicKey {
    Ed25519Signer::from_seed(uri("did:web:agent.example#a1"), [33u8; 32]).public()
}
fn r(from: u64, to: u64) -> Range {
    Range {
        from: Serial(from),
        to: Serial(to),
    }
}
fn terms(block_size: u64) -> PacketTerms {
    PacketTerms {
        allocated_at: ts("2026-03-01T10:00:00.000Z"),
        expires_at: ts("2026-12-01T10:00:00.000Z"),
        class: Class::Heavy,
        block_size,
        anchor_period_ms: None,
    }
}
fn closure(block: Range, used: u64) -> BlockClosure {
    let doc = BlockClosure::draft(
        "ksg:em:000001".into(),
        block,
        vec![Range {
            from: block.from,
            to: Serial(block.from.0 + used - 1),
        }],
        vec![],
        ts("2026-12-01T10:00:00.000Z"),
    );
    let sig = ksg_core_v2::crypto::sign::sign_doc(&doc, &holder_key()).expect("signature");
    BlockClosure {
        signatures: SignatureSet::new(vec![sig]),
        ..doc
    }
}

/// The auditing firm of the CT-31 example: three blocks of 1 000 over a year.
fn three_blocks() -> Ledger {
    let mut l = Ledger::open("ksg:em:000001".into(), r(1, 100_000)).expect("open");
    let mut prev = None;
    for _ in 0..3 {
        let a = l
            .allocate(
                &holder(),
                prev.as_ref(),
                &issuer_key(),
                &holder_keys(),
                terms(1000),
            )
            .expect("allocate");
        prev = Some(closure(a.block, 1000));
    }
    l
}

fn history(l: &Ledger) -> AgentHistory {
    l.history(
        &holder(),
        &agent(),
        ts("2026-12-15T10:00:00.000Z"),
        &issuer_key(),
    )
    .expect("history")
}

// --- what the list holds -----------------------------------------------------

#[test]
fn three_blocks_of_a_year_become_one_chain() {
    // The gap CT-31 names: from the container, the March and July blocks are
    // invisible. The list is what makes them the same agent's.
    let h = history(&three_blocks());
    assert_eq!(h.blocks.len(), 3);
    assert_eq!(h.blocks[0].block, r(1, 1000));
    assert_eq!(h.blocks[2].block, r(2001, 3000));
    assert_eq!(h.serials(), 3000);
    h.validate(&holder(), &agent(), &issuer_keys(), &Profile::default())
        .expect("a list the issuer signed");
}

#[test]
fn the_entry_names_the_allocation_and_not_only_the_bounds() {
    // A range is two numbers and says nothing about which document handed it
    // out. A verifier holding the allocation must be able to say "this one".
    let mut l = Ledger::open("ksg:em:000001".into(), r(1, 100_000)).expect("open");
    let a = l
        .allocate(&holder(), None, &issuer_key(), &holder_keys(), terms(1000))
        .expect("allocate");
    let h = history(&l);
    let expected = ksg_core_v2::canonical::doc_hash(&a).expect("hash");
    assert!(h.covers(&expected));
    assert!(!h.covers(&Hash::sha256(b"another document")));
}

#[test]
fn a_holder_without_blocks_has_no_history_rather_than_an_empty_one() {
    // An empty list signed by the issuer would be a statement ("this agent
    // worked nowhere") that the issuer is not in a position to make.
    let l = Ledger::open("ksg:em:000001".into(), r(1, 100)).expect("open");
    assert_eq!(
        l.history(
            &holder(),
            &agent(),
            ts("2026-12-15T10:00:00.000Z"),
            &issuer_key()
        )
        .unwrap_err(),
        IssuerError::NoBlocks
    );
}

#[test]
fn a_block_issued_before_hashes_were_recorded_is_reported_not_guessed() {
    // The field arrived with KS-1 §13. A ledger restored from older state can
    // still issue — it just cannot draw up a history for the old blocks, and
    // says so instead of filling the hash with a zero.
    let l = three_blocks();
    let mut s = l.snapshot();
    s.allocation_hash.clear();
    let old = Ledger::restore(s).expect("restore");
    assert_eq!(
        old.history(
            &holder(),
            &agent(),
            ts("2026-12-15T10:00:00.000Z"),
            &issuer_key()
        )
        .unwrap_err(),
        IssuerError::CorruptSnapshot("a block has no recorded allocation hash")
    );
}

// --- what the list refuses to be ---------------------------------------------

#[test]
fn a_repeated_block_is_refused_because_it_lengthens_a_short_history() {
    let mut h = history(&three_blocks());
    let first = h.blocks[0].clone();
    h.blocks.push(first);
    assert_eq!(
        h.validate(&holder(), &agent(), &issuer_keys(), &Profile::default())
            .unwrap_err(),
        Invalid::Schema("AgentHistory repeats a block")
    );
}

#[test]
fn blocks_of_one_emission_running_backwards_are_refused() {
    let mut h = history(&three_blocks());
    h.blocks.swap(0, 2);
    assert_eq!(
        h.validate(&holder(), &agent(), &issuer_keys(), &Profile::default())
            .unwrap_err(),
        Invalid::Schema("AgentHistory blocks of one emission overlap or run backwards")
    );
}

#[test]
fn two_emissions_number_independently_and_are_not_compared() {
    // Serial 5 of one release and serial 5 of another are different scales.
    // Ordering is checked inside an emission, never across.
    let mut h = history(&three_blocks());
    h.blocks.push(HistoryEntry {
        emission: "ksg:em:000002".into(),
        block: r(1, 500),
        allocation: Hash::sha256(b"the other release"),
    });
    // Re-signed, because editing a signed document is exactly what the
    // envelope check catches — the point here is the ordering rule, not that.
    h.signatures = SignatureSet::default();
    let sig = ksg_core_v2::crypto::sign::sign_doc(&h, &issuer_key()).expect("signature");
    let h = AgentHistory {
        signatures: SignatureSet::new(vec![sig]),
        ..h
    };
    h.validate(&holder(), &agent(), &issuer_keys(), &Profile::default())
        .expect("a second release starts its own numbering");
}

#[test]
fn a_list_drawn_up_for_another_agent_does_not_count_for_this_one() {
    // The whole document's worth is "these blocks are THIS agent's".
    let h = history(&three_blocks());
    let other = Ed25519Signer::from_seed(uri("did:web:other.example#o1"), [99u8; 32]).public();
    assert_eq!(
        h.validate(&holder(), &other, &issuer_keys(), &Profile::default())
            .unwrap_err(),
        Invalid::Schema("AgentHistory names another agent")
    );
}

#[test]
fn an_unsigned_list_proves_nothing() {
    // The document rests on the issuer's signature — that is its price, stated
    // in the module note. Without the signature there is nothing left.
    let mut h = history(&three_blocks());
    h.signatures = SignatureSet::default();
    assert!(h
        .validate(&holder(), &agent(), &issuer_keys(), &Profile::default())
        .is_err());
}
