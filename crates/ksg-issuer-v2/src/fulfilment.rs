//! The process around the platform: an order from the moment it is placed to
//! the moment its packet is closed. The skeleton of `Arkhitektura_v2_konteyner`
//! §16 ("ordering, assembly, delivery stages").
//!
//! # The steps, as the owner wrote them
//!
//! `Mekhanizm_oplaty.md` §3, and nothing added:
//!
//! | Step | Stage here | Event |
//! |---|---|---|
//! | 2 — the buyer orders a packet: how many serials, which class; **the invoice is issued here** | [`Stage::Ordered`] | [`Event::Placed`] |
//! | 3 — payment goes through, **the one mandatory payment** | [`Stage::Paid`] | [`Event::Paid`] |
//! | 4 — the issuer issues the `BlockAllocation` | [`Stage::Issued`] | [`Event::Issued`] |
//! | 5 — the buyer receives **the template and the rights**, not containers | [`Stage::Delivered`] | [`Event::Delivered`] |
//! | 6 — initiation: containers are printed from the template, one serial each | [`Stage::Assembling`] | [`Event::Printed`] |
//! | 8 — the packet is closed: every serial accounted for | [`Stage::Closed`] | [`Event::Closed`] |
//! | 9 — the next packet only if the previous one is closed and drawn to 80% | [`Book::may_reorder`] | — |
//!
//! Step 1 (the release) is the issuer's own and has no order; step 7 (work) is
//! the container's and is not seen from here. Two endings are not in the list
//! because the list describes the road and not the ditches: an order nobody
//! paid for is [`Stage::Cancelled`], and a packet whose term ran out before it
//! was closed is [`Stage::Expired`].
//!
//! # Why an event log and not a status field
//!
//! An order is money. "Paid" written over "ordered" loses when, by what
//! payment, and who confirmed it — exactly what a dispute about money asks.
//! So an order keeps its events, oldest first, and its stage is **read from
//! them**: the log is the record, the stage is a view. A stage that could be
//! set directly would be a second record that can disagree with the first.
//!
//! # What is a skeleton here, said plainly
//!
//! The rules of the road are complete and enforced. What is not here yet: who
//! signs each event (today the desk that keeps the book), the payment provider
//! behind [`Event::Paid`] (today a reference typed in — `Plan_MVP` §3.2, the
//! MVP's payment by hand), and the wiring into the desk program (`ksg-cli-v2`
//! `channel.rs`, which still forgets an order the moment it is paid).

use std::collections::BTreeMap;

use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::doc::{Class, Range, Serial, Timestamp, Uri};
use serde::{Deserialize, Serialize};

use crate::issuer::{DRAWDOWN_DEN, DRAWDOWN_NUM};

/// The most events one order may hold: steps 2–5 and 8 are one event each,
/// and every container printed is one more. A packet larger than this is not
/// sold as one order.
pub const MAX_EVENTS: usize = 100_000;

/// Where an order is. Read from its events, never set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Stage {
    /// Placed, invoice issued, not paid.
    Ordered,
    /// Paid, the packet not issued yet.
    Paid,
    /// The packet is issued: serials taken, term running.
    Issued,
    /// The template and the rights are with the buyer.
    Delivered,
    /// At least one container is printed from the template.
    Assembling,
    /// The packet is closed: every serial accounted for.
    Closed,
    /// Cancelled before payment.
    Cancelled,
    /// The packet's term ran out before it was closed.
    Expired,
}

impl Stage {
    /// No event moves an order out of this stage.
    #[must_use]
    pub const fn is_final(self) -> bool {
        matches!(self, Self::Closed | Self::Cancelled | Self::Expired)
    }
}

/// Something that happened to an order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "event", rename_all = "snake_case")]
pub enum Event {
    /// Step 2: the order is placed and the invoice issued.
    Placed {
        /// The buyer's holder URI.
        buyer: Uri,
        /// The packet's class.
        class: Class,
        /// How many serials.
        size: u64,
        /// For how many days after payment the packet is valid.
        days: u64,
        /// The invoice's reference, as the seller's books know it.
        invoice: String,
    },
    /// Step 3: payment received.
    Paid {
        /// The payment's reference, as the provider gives it.
        payment: String,
    },
    /// Step 4: the packet is issued.
    Issued {
        /// The hash of the `BlockAllocation` document.
        packet: Hash,
        /// The serials taken.
        serials: Range,
        /// When the packet's term ends.
        expires_at: Timestamp,
    },
    /// Step 5: the template and the rights are handed to the buyer.
    Delivered {
        /// The hash of the template as handed over.
        template: Hash,
    },
    /// Step 6: one container is printed from the template.
    Printed {
        /// The serial it took.
        serial: Serial,
    },
    /// Step 8: the closure is accepted.
    Closed {
        /// The hash of the `BlockClosure` document.
        closure: Hash,
        /// How many serials were used.
        used: u64,
    },
    /// Cancelled before payment.
    Cancelled {
        /// Why, in a line.
        reason: String,
    },
    /// The packet's term ran out unclosed.
    Expired,
}

/// Why an event was refused. The order is unchanged by a refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FulfilmentError {
    /// No order with this id.
    NoSuchOrder(String),
    /// An order with this id exists already.
    Duplicate(String),
    /// The event does not follow from the stage the order is in.
    OutOfOrder {
        /// Where the order is.
        stage: Stage,
        /// What was attempted.
        event: &'static str,
    },
    /// The event's own content is not acceptable.
    Invalid(&'static str),
    /// The serial was printed already, or lies outside the packet.
    Serial(Serial),
    /// The packet's term has run out.
    PastTerm,
    /// The order has reached [`MAX_EVENTS`].
    Full,
}

impl std::fmt::Display for FulfilmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSuchOrder(id) => write!(f, "no order {id}"),
            Self::Duplicate(id) => write!(f, "order {id} exists already"),
            Self::OutOfOrder { stage, event } => {
                write!(f, "{event} does not follow an order at {stage:?}")
            }
            Self::Invalid(why) => write!(f, "{why}"),
            Self::Serial(s) => write!(f, "serial {} is not printable here", s.0),
            Self::PastTerm => f.write_str("the packet's term has run out"),
            Self::Full => write!(f, "an order holds at most {MAX_EVENTS} events"),
        }
    }
}

impl std::error::Error for FulfilmentError {}

/// One order and everything that happened to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Order {
    /// The order's id at this desk.
    pub id: String,
    /// The events, oldest first, each with its moment.
    pub events: Vec<(Timestamp, Event)>,
}

impl Order {
    /// The stage, read from the events.
    #[must_use]
    pub fn stage(&self) -> Stage {
        let mut stage = Stage::Ordered;
        for (_, e) in &self.events {
            stage = match e {
                Event::Placed { .. } => Stage::Ordered,
                Event::Paid { .. } => Stage::Paid,
                Event::Issued { .. } => Stage::Issued,
                Event::Delivered { .. } => Stage::Delivered,
                Event::Printed { .. } => Stage::Assembling,
                Event::Closed { .. } => Stage::Closed,
                Event::Cancelled { .. } => Stage::Cancelled,
                Event::Expired => Stage::Expired,
            };
        }
        stage
    }

    /// The buyer, the class and the size, from the placing event.
    fn placed(&self) -> Option<(&Uri, Class, u64)> {
        self.events.iter().find_map(|(_, e)| match e {
            Event::Placed {
                buyer, class, size, ..
            } => Some((buyer, *class, *size)),
            _ => None,
        })
    }

    /// The serials and the term, from the issuing event.
    fn issued(&self) -> Option<(Range, &Timestamp)> {
        self.events.iter().find_map(|(_, e)| match e {
            Event::Issued {
                serials,
                expires_at,
                ..
            } => Some((*serials, expires_at)),
            _ => None,
        })
    }

    /// The packet issued for this order and its serials, once issued: what
    /// a closure of it must be about.
    #[must_use]
    pub fn issued_packet(&self) -> Option<(Hash, Range)> {
        self.events.iter().find_map(|(_, e)| match e {
            Event::Issued {
                packet, serials, ..
            } => Some((*packet, *serials)),
            _ => None,
        })
    }

    /// The serials printed so far, in order of printing.
    pub fn printed(&self) -> impl Iterator<Item = Serial> + '_ {
        self.events.iter().filter_map(|(_, e)| match e {
            Event::Printed { serial } => Some(*serial),
            _ => None,
        })
    }

    /// Checks `event` against the order without applying it.
    fn admit(&self, at: &Timestamp, event: &Event) -> Result<(), FulfilmentError> {
        let stage = self.stage();
        let out = |event| Err(FulfilmentError::OutOfOrder { stage, event });
        if self.events.len() >= MAX_EVENTS {
            return Err(FulfilmentError::Full);
        }
        if let Some((last, _)) = self.events.last() {
            if at.unix_ms() < last.unix_ms() {
                return Err(FulfilmentError::Invalid(
                    "an event earlier than the one before it",
                ));
            }
        }
        match event {
            Event::Placed { .. } => out("placed"),
            Event::Paid { payment } => {
                if stage != Stage::Ordered {
                    return out("paid");
                }
                if payment.trim().is_empty() {
                    return Err(FulfilmentError::Invalid("a payment without a reference"));
                }
                Ok(())
            }
            Event::Issued {
                serials,
                expires_at,
                ..
            } => {
                if stage != Stage::Paid {
                    return out("issued");
                }
                let size = self.placed().map_or(0, |(_, _, s)| s);
                if serials.len() != size {
                    return Err(FulfilmentError::Invalid(
                        "the packet's serials do not match the size ordered",
                    ));
                }
                if expires_at.unix_ms() <= at.unix_ms() {
                    return Err(FulfilmentError::Invalid("a packet issued already expired"));
                }
                Ok(())
            }
            Event::Delivered { .. } => {
                if stage != Stage::Issued {
                    return out("delivered");
                }
                self.within_term(at)
            }
            Event::Printed { serial } => {
                if !matches!(stage, Stage::Delivered | Stage::Assembling) {
                    return out("printed");
                }
                self.within_term(at)?;
                let (range, _) = self.issued().ok_or(FulfilmentError::Invalid("no packet"))?;
                // One serial, one container (`[decision]` 19.09).
                if !range.contains(*serial) || self.printed().any(|s| s == *serial) {
                    return Err(FulfilmentError::Serial(*serial));
                }
                Ok(())
            }
            Event::Closed { used, .. } => {
                if !matches!(stage, Stage::Issued | Stage::Delivered | Stage::Assembling) {
                    return out("closed");
                }
                let size = self.placed().map_or(0, |(_, _, s)| s);
                if *used > size {
                    return Err(FulfilmentError::Invalid(
                        "more serials used than the packet has",
                    ));
                }
                if *used < self.printed().count() as u64 {
                    return Err(FulfilmentError::Invalid(
                        "fewer serials used than containers printed",
                    ));
                }
                Ok(())
            }
            Event::Cancelled { reason } => {
                // Money that came in is returned, not cancelled: after payment
                // the order ends in closure or expiry, both of which account
                // for every serial.
                if stage != Stage::Ordered {
                    return out("cancelled");
                }
                if reason.trim().is_empty() {
                    return Err(FulfilmentError::Invalid("a cancellation without a reason"));
                }
                Ok(())
            }
            Event::Expired => {
                if !matches!(stage, Stage::Issued | Stage::Delivered | Stage::Assembling) {
                    return out("expired");
                }
                match self.issued() {
                    Some((_, end)) if at.unix_ms() >= end.unix_ms() => Ok(()),
                    _ => Err(FulfilmentError::Invalid(
                        "the packet's term has not run out",
                    )),
                }
            }
        }
    }

    fn within_term(&self, at: &Timestamp) -> Result<(), FulfilmentError> {
        match self.issued() {
            Some((_, end)) if at.unix_ms() < end.unix_ms() => Ok(()),
            Some(_) => Err(FulfilmentError::PastTerm),
            None => Err(FulfilmentError::Invalid("no packet")),
        }
    }
}

/// The orders of one desk.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Book {
    orders: BTreeMap<String, Order>,
}

impl Book {
    /// An empty book.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// No order was ever placed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.orders.is_empty()
    }

    /// Step 2: places an order. Its id is the caller's (the desk's numbering).
    ///
    /// # Errors
    ///
    /// [`FulfilmentError::Duplicate`], [`FulfilmentError::Invalid`] on an empty
    /// packet, a zero term or an empty invoice reference.
    pub fn place(&mut self, id: &str, at: Timestamp, placed: Event) -> Result<(), FulfilmentError> {
        let Event::Placed {
            size,
            days,
            invoice,
            ..
        } = &placed
        else {
            return Err(FulfilmentError::Invalid("an order begins with its placing"));
        };
        if self.orders.contains_key(id) {
            return Err(FulfilmentError::Duplicate(id.to_owned()));
        }
        if *size == 0 || *days == 0 || invoice.trim().is_empty() || id.trim().is_empty() {
            return Err(FulfilmentError::Invalid(
                "an order needs an id, a size, a term and an invoice",
            ));
        }
        self.orders.insert(
            id.to_owned(),
            Order {
                id: id.to_owned(),
                events: vec![(at, placed)],
            },
        );
        Ok(())
    }

    /// Steps 3–8: records `event` on order `id`, or refuses it and changes
    /// nothing.
    ///
    /// # Errors
    ///
    /// [`FulfilmentError`] naming the rule the event broke.
    pub fn record(
        &mut self,
        id: &str,
        at: Timestamp,
        event: Event,
    ) -> Result<Stage, FulfilmentError> {
        let order = self
            .orders
            .get_mut(id)
            .ok_or_else(|| FulfilmentError::NoSuchOrder(id.to_owned()))?;
        order.admit(&at, &event)?;
        order.events.push((at, event));
        Ok(order.stage())
    }

    /// One order.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Order> {
        self.orders.get(id)
    }

    /// Every order, by id.
    pub fn orders(&self) -> impl Iterator<Item = &Order> {
        self.orders.values()
    }

    /// The orders whose term has run out at `now` without closure — what a
    /// periodic sweep marks [`Event::Expired`].
    pub fn due_to_expire<'a>(&'a self, now: &'a Timestamp) -> impl Iterator<Item = &'a Order> {
        self.orders.values().filter(move |o| {
            !o.stage().is_final()
                && o.issued()
                    .is_some_and(|(_, end)| now.unix_ms() >= end.unix_ms())
        })
    }

    /// Step 9: may `buyer` be sold another packet?
    ///
    /// Only if every earlier packet of theirs is closed, and the last closed
    /// one was drawn to 80% (`DRAWDOWN_NUM / DRAWDOWN_DEN`, the same integer
    /// rule as the ledger). An order still unpaid does not block: it holds no
    /// serials. An expired packet does: its serials are not accounted for.
    #[must_use]
    pub fn may_reorder(&self, buyer: &Uri) -> bool {
        let mut last_closed: Option<(u64, u64, u64)> = None;
        for o in self.orders.values() {
            let Some((b, _, size)) = o.placed() else {
                continue;
            };
            if b != buyer {
                continue;
            }
            match o.stage() {
                Stage::Ordered | Stage::Cancelled => {}
                Stage::Closed => {
                    let (at, used) = o
                        .events
                        .iter()
                        .find_map(|(t, e)| match e {
                            Event::Closed { used, .. } => Some((t.unix_ms(), *used)),
                            _ => None,
                        })
                        .unwrap_or((0, 0));
                    if last_closed.map_or(true, |(t, _, _)| at >= t) {
                        last_closed = Some((at, used, size));
                    }
                }
                _ => return false,
            }
        }
        last_closed.map_or(true, |(_, used, size)| {
            used.saturating_mul(DRAWDOWN_DEN) >= size.saturating_mul(DRAWDOWN_NUM)
        })
    }
}
