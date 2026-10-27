//! The playground (KS-8, the playground definition): a container in the plain
//! memo format goes the whole road — initiation, a journal — but anchors
//! nothing, goes nowhere outside, and its journal holds a hundred records
//! after the opening (`[decision]` 17.10 "B-2 — A", "B-3 — A").

mod stand;

use ksg_container_v2::container::{Evidence, Stopped, PLAYGROUND_RECORDS};
use ksg_container_v2::layers::Level;
use ksg_container_v2::Operation as Op;
use ksg_container_v2::{Status, Where, Work};
use ksg_core_v2::crypto::sign::SignatureSet;
use ksg_core_v2::doc::{Class, MemoFormat};
use stand::{EventKind, Page, Stand, Who};

fn work(s: &mut Stand, did: &str) -> Result<(), Stopped> {
    let mut w = Work {
        container: *s.c.id(),
        under: None,
        did: did.into(),
        signatures: SignatureSet::default(),
    };
    let subject = w.subject();
    w.signatures = SignatureSet::new(s.client_signs(subject.as_bytes()));
    s.press(
        Op::RecordWork,
        &[Who::Client],
        Evidence::Work {
            order: None,
            work: Box::new(w),
        },
        Page::Of(EventKind::Work),
    )
}

#[test]
fn a_playground_is_initiated_keeps_a_journal_and_holds_a_hundred_records() {
    let mut s = Stand::playground(Class::Light, 7100);
    assert_eq!(s.c.memo_format(), MemoFormat::Plain);
    s.press(Op::ApplyPacket, &[Who::Issuer], Evidence::None, Page::None)
        .expect("packet");
    let buyer = s.parties.buyer.public();
    s.press(
        Op::ApplyBuyerKey,
        &[Who::Buyer, Who::Owner],
        Evidence::KeyLaid {
            to: buyer,
            up_to: Level(2),
        },
        Page::None,
    )
    .expect("buyer key");
    // B-3 — A: the playground reaches initiation (status 4) and opens a journal.
    s.press(
        Op::Initiate,
        &[Who::Client, Who::Owner],
        Evidence::Initiation { at: Where::Inside },
        Page::None,
    )
    .expect("a playground is initiated");
    s.press(
        Op::OpenJournal,
        &[Who::Client],
        Evidence::None,
        Page::Opening,
    )
    .expect("a playground keeps a journal");
    assert_eq!(s.c.status(), Status::InWork);

    // B-2 — A: a hundred records, then the journal is full.
    for i in 1..=PLAYGROUND_RECORDS {
        work(&mut s, &format!("practice {i}")).expect("within the hundred");
    }
    let before = s.c.pages();
    assert!(
        matches!(work(&mut s, "one more"), Err(Stopped::PlaygroundFull)),
        "the hundred and first record is refused"
    );
    assert_eq!(s.c.pages(), before, "and changes nothing");
}
