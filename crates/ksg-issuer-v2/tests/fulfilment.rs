//! The road of an order (`Mekhanizm_oplaty.md` §3): every step in its place,
//! every step out of place refused, and the book unchanged by a refusal.

use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::doc::{Class, Range, Serial, Timestamp, Uri};
use ksg_issuer_v2::{Book, Event, FulfilmentError, Stage};

fn ts(s: &str) -> Timestamp {
    Timestamp::parse(s).expect("ts")
}
fn buyer() -> Uri {
    Uri::parse("did:key:zBuyer").expect("uri")
}
fn placed(size: u64) -> Event {
    Event::Placed {
        buyer: buyer(),
        class: Class::Light,
        size,
        days: 30,
        invoice: "inv-1".into(),
    }
}
fn issued(from: u64, size: u64, until: &str) -> Event {
    Event::Issued {
        packet: Hash::sha256(b"packet"),
        serials: Range {
            from: Serial(from),
            to: Serial(from + size - 1),
        },
        expires_at: ts(until),
    }
}

/// An order walked to delivery: 10 serials, 101..=110, valid through October.
fn delivered(book: &mut Book, id: &str) {
    book.place(id, ts("2026-10-01T09:00:00.000Z"), placed(10))
        .expect("placed");
    book.record(
        id,
        ts("2026-10-01T09:05:00.000Z"),
        Event::Paid {
            payment: "pay-1".into(),
        },
    )
    .expect("paid");
    book.record(
        id,
        ts("2026-10-01T09:06:00.000Z"),
        issued(101, 10, "2026-10-31T00:00:00.000Z"),
    )
    .expect("issued");
    book.record(
        id,
        ts("2026-10-01T09:07:00.000Z"),
        Event::Delivered {
            template: Hash::sha256(b"template"),
        },
    )
    .expect("delivered");
}

#[test]
fn the_whole_road_in_order() {
    let mut book = Book::new();
    delivered(&mut book, "ord-1");
    for s in 101..=108 {
        assert_eq!(
            book.record(
                "ord-1",
                ts("2026-10-02T00:00:00.000Z"),
                Event::Printed { serial: Serial(s) }
            ),
            Ok(Stage::Assembling)
        );
    }
    assert_eq!(
        book.record(
            "ord-1",
            ts("2026-10-20T00:00:00.000Z"),
            Event::Closed {
                closure: Hash::sha256(b"closure"),
                used: 8
            }
        ),
        Ok(Stage::Closed)
    );
    assert_eq!(book.get("ord-1").expect("order").printed().count(), 8);
    // 8 of 10 is 80%: the next packet may be sold.
    assert!(book.may_reorder(&buyer()));
}

#[test]
fn steps_out_of_order_are_refused_and_change_nothing() {
    let mut book = Book::new();
    book.place("ord-1", ts("2026-10-01T09:00:00.000Z"), placed(10))
        .expect("placed");
    let before = book.clone();
    for e in [
        issued(1, 10, "2026-10-31T00:00:00.000Z"),
        Event::Delivered {
            template: Hash::sha256(b"t"),
        },
        Event::Printed { serial: Serial(1) },
        Event::Expired,
    ] {
        assert!(matches!(
            book.record("ord-1", ts("2026-10-01T10:00:00.000Z"), e),
            Err(FulfilmentError::OutOfOrder { .. })
        ));
    }
    assert_eq!(book, before);
}

#[test]
fn one_serial_one_container_and_only_inside_the_packet() {
    let mut book = Book::new();
    delivered(&mut book, "ord-1");
    let at = ts("2026-10-02T00:00:00.000Z");
    book.record(
        "ord-1",
        at.clone(),
        Event::Printed {
            serial: Serial(101),
        },
    )
    .expect("first");
    assert_eq!(
        book.record(
            "ord-1",
            at.clone(),
            Event::Printed {
                serial: Serial(101)
            }
        ),
        Err(FulfilmentError::Serial(Serial(101)))
    );
    assert_eq!(
        book.record(
            "ord-1",
            at,
            Event::Printed {
                serial: Serial(111)
            }
        ),
        Err(FulfilmentError::Serial(Serial(111)))
    );
}

#[test]
fn after_the_term_nothing_is_printed_and_the_packet_expires() {
    let mut book = Book::new();
    delivered(&mut book, "ord-1");
    let late = ts("2026-10-31T00:00:00.000Z");
    assert_eq!(
        book.record(
            "ord-1",
            late.clone(),
            Event::Printed {
                serial: Serial(101)
            }
        ),
        Err(FulfilmentError::PastTerm)
    );
    assert_eq!(book.due_to_expire(&late).count(), 1);
    assert_eq!(
        book.record("ord-1", late.clone(), Event::Expired),
        Ok(Stage::Expired)
    );
    assert_eq!(book.due_to_expire(&late).count(), 0);
    // An expired packet is not accounted for: no next packet.
    assert!(!book.may_reorder(&buyer()));
}

#[test]
fn a_packet_cannot_expire_early() {
    let mut book = Book::new();
    delivered(&mut book, "ord-1");
    assert!(matches!(
        book.record("ord-1", ts("2026-10-10T00:00:00.000Z"), Event::Expired),
        Err(FulfilmentError::Invalid(_))
    ));
}

#[test]
fn only_an_unpaid_order_is_cancelled() {
    let mut book = Book::new();
    book.place("ord-1", ts("2026-10-01T09:00:00.000Z"), placed(10))
        .expect("placed");
    assert_eq!(
        book.record(
            "ord-1",
            ts("2026-10-01T09:01:00.000Z"),
            Event::Cancelled {
                reason: "buyer withdrew".into()
            }
        ),
        Ok(Stage::Cancelled)
    );
    delivered(&mut book, "ord-2");
    assert!(matches!(
        book.record(
            "ord-2",
            ts("2026-10-02T00:00:00.000Z"),
            Event::Cancelled {
                reason: "too late".into()
            }
        ),
        Err(FulfilmentError::OutOfOrder { .. })
    ));
}

#[test]
fn reorder_needs_the_last_packet_closed_and_drawn_to_80_percent() {
    let mut book = Book::new();
    assert!(
        book.may_reorder(&buyer()),
        "a first order is always allowed"
    );
    delivered(&mut book, "ord-1");
    assert!(!book.may_reorder(&buyer()), "an open packet blocks");
    book.record(
        "ord-1",
        ts("2026-10-20T00:00:00.000Z"),
        Event::Closed {
            closure: Hash::sha256(b"c"),
            used: 7,
        },
    )
    .expect("closed");
    assert!(!book.may_reorder(&buyer()), "7 of 10 is below 80%");
}

#[test]
fn the_packet_must_be_the_size_ordered_and_the_closure_must_count_what_was_printed() {
    let mut book = Book::new();
    book.place("ord-1", ts("2026-10-01T09:00:00.000Z"), placed(10))
        .expect("placed");
    book.record(
        "ord-1",
        ts("2026-10-01T09:05:00.000Z"),
        Event::Paid {
            payment: "p".into(),
        },
    )
    .expect("paid");
    assert!(matches!(
        book.record(
            "ord-1",
            ts("2026-10-01T09:06:00.000Z"),
            issued(1, 9, "2026-10-31T00:00:00.000Z")
        ),
        Err(FulfilmentError::Invalid(_))
    ));
    delivered(&mut book, "ord-2");
    book.record(
        "ord-2",
        ts("2026-10-02T00:00:00.000Z"),
        Event::Printed {
            serial: Serial(101),
        },
    )
    .expect("printed");
    book.record(
        "ord-2",
        ts("2026-10-02T00:00:00.000Z"),
        Event::Printed {
            serial: Serial(102),
        },
    )
    .expect("printed");
    assert!(matches!(
        book.record(
            "ord-2",
            ts("2026-10-03T00:00:00.000Z"),
            Event::Closed {
                closure: Hash::sha256(b"c"),
                used: 1
            }
        ),
        Err(FulfilmentError::Invalid(_))
    ));
}

#[test]
fn time_does_not_run_backwards_and_ids_are_unique() {
    let mut book = Book::new();
    book.place("ord-1", ts("2026-10-01T09:00:00.000Z"), placed(10))
        .expect("placed");
    assert!(matches!(
        book.record(
            "ord-1",
            ts("2026-10-01T08:00:00.000Z"),
            Event::Paid {
                payment: "p".into()
            }
        ),
        Err(FulfilmentError::Invalid(_))
    ));
    assert_eq!(
        book.place("ord-1", ts("2026-10-01T09:00:00.000Z"), placed(5)),
        Err(FulfilmentError::Duplicate("ord-1".into()))
    );
    assert!(matches!(
        book.place("ord-2", ts("2026-10-01T09:00:00.000Z"), placed(0)),
        Err(FulfilmentError::Invalid(_))
    ));
}

#[test]
fn the_book_survives_storage() {
    let mut book = Book::new();
    delivered(&mut book, "ord-1");
    let json = serde_json::to_string(&book).expect("json");
    let back: Book = serde_json::from_str(&json).expect("parses");
    assert_eq!(back, book);
    assert_eq!(back.get("ord-1").expect("order").stage(), Stage::Delivered);
    // A field nobody wrote is refused, not ignored.
    let tampered = json.replacen("\"events\"", "\"note\":1,\"events\"", 1);
    assert!(serde_json::from_str::<Book>(&tampered).is_err());
}
