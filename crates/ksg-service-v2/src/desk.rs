//! The desk for requests to someone else's anchor. Ts-5, path A; CT-13,
//! CT-14, CT-15, CT-38.
//!
//! `[decision]` 13.09: an owner-watcher who wants to know whose anchor this is
//! presents **its own ID** and signs the request; there is no anonymous look.
//! The desk is the door: it issues a challenge, takes the signed request,
//! checks it by path A, charges the look by its number, and hands the notice
//! to the container that was looked at — never to a journal of ours
//! (`[decision]` 13.09 §8.1).
//!
//! # What the desk keeps, and for how long
//!
//! | What | Why | How long |
//! |---|---|---|
//! | challenges issued and not yet spent | the anti-replay (finding 2): a request is accepted once | [`CHALLENGE_TTL_MS`], then dropped |
//! | which anchor is whose container ([`Linkage`]) | without it there is nobody to notify (CT-13) | by period, [`crate::ladder::KEY_RETENTION_DAYS`], then [`Linkage::forget`] |
//! | looks per owner-watcher per period | the price of the next look (CT-38) | the period |
//! | charges | billing | until the host drains them ([`Desk::drain_charges`]) |
//! | notices waiting for their container ([`Mailbox`]) | delivery | until the holder takes them |
//!
//! Technical logs of the service are the host's (`Resheniya_13.09` §8.1, the
//! correction of 14.09); this crate writes none.
//!
//! # The mapping, and the price of admitting it
//!
//! `[decision]` 19.09 (CT-13): the mapping anchor → container is ours, and the
//! documents say so. In core v2 the anchors are blind (`ksg:bs:v1`): an
//! observer cannot tell whose a memo is, and neither can we from the memo.
//! We know it because **we sent it** (CT-04, [`crate::anchoring`]): the
//! queue records each transaction's container as it lands. That table is a
//! retroactive deanonymization risk for whoever obtains it (audit finding 3);
//! it holds the minimum — transaction, container, period — and a period is
//! droppable.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use ksg_container_v2::view::{AnchorRef, DisclosureRequest, ViewNotice, NOTICE_RING};
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{Profile, PublicKey};
use ksg_core_v2::doc::{Timestamp, Uri};
use ksg_core_v2::error::Invalid;
use ksg_core_v2::status::Status;

use crate::ladder::{price_of_next_cents, Stream};

/// Maps whose keys are not strings, written as lists of pairs: JSON objects
/// take string keys only.
mod pairs {
    use std::collections::BTreeMap;

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<K: Serialize, V: Serialize, S: Serializer>(
        m: &BTreeMap<K, V>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        s.collect_seq(m.iter())
    }

    pub fn deserialize<'de, K, V, D>(d: D) -> Result<BTreeMap<K, V>, D::Error>
    where
        K: Deserialize<'de> + Ord,
        V: Deserialize<'de>,
        D: Deserializer<'de>,
    {
        Ok(Vec::<(K, V)>::deserialize(d)?.into_iter().collect())
    }
}

/// How long an issued challenge stays live, in milliseconds: ten minutes.
pub const CHALLENGE_TTL_MS: u64 = 10 * 60 * 1000;

/// The widest window a request may carry, in milliseconds: fifteen minutes.
/// The challenge is what stops a replay; the window only limits how long a
/// captured request is worth keeping — minutes, not hours.
pub const MAX_WINDOW_MS: u64 = 15 * 60 * 1000;

/// The most challenges outstanding at once. A flood of challenge requests
/// must not grow the desk's memory without end; past this the desk answers
/// [`DeskError::Busy`] until challenges expire or are spent.
pub const MAX_OUTSTANDING: usize = 100_000;

/// Who stands behind an owner-watcher's keys: path A's lookup.
pub trait Registry {
    /// The current status of the container the owner-watcher's keys belong
    /// to, if they are present in a chain at all and the registry's knowledge
    /// of it is current at `now_ms`; `None` — not present, or not known now.
    fn standing(&self, owner: &[PublicKey], now_ms: u64) -> Option<Status>;
}

/// A charge for one look.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Charge {
    /// Who pays: the owner-watcher's identifier.
    pub payer: String,
    /// Which period the look counts in.
    pub period: String,
    /// Which look this is in the period, from one.
    pub look: u64,
    /// The price, in cents.
    pub cents: u64,
}

/// What a request that went through produces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accepted {
    /// What to bill.
    pub charge: Charge,
    /// The container that was looked at.
    pub container: Hash,
    /// The notice, already in the container's [`Mailbox`].
    pub notice: ViewNotice,
}

/// Why a request or a challenge was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeskError {
    /// The request does not verify.
    #[error("the request does not verify: {0}")]
    Invalid(#[from] Invalid),
    /// The window is wider than [`MAX_WINDOW_MS`].
    #[error("the request's window is wider than the desk accepts")]
    WindowTooWide,
    /// The owner-watcher's keys are in no chain (path A).
    #[error("the owner-watcher's keys are not present in any chain")]
    NotInChain,
    /// The challenge was not issued here, expired, or was already used.
    #[error("the challenge was not issued here, has expired, or was already used")]
    Replay,
    /// The anchor asked about is not one we know — or its period was dropped.
    #[error("the anchor is not one this service knows")]
    UnknownAnchor,
    /// Too many challenges outstanding.
    #[error("too many challenges outstanding; try again later")]
    Busy,
    /// The desk's state does not serialize or does not parse.
    #[error("the desk's state could not be written or read")]
    State,
}

/// The challenges a desk has issued and not yet seen spent.
///
/// A replay is two identical documents, and no check of one document tells
/// them apart: what does is memory — issued, not yet used, not expired.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayGuard {
    /// challenge → the moment it dies, ms.
    live: BTreeMap<String, u64>,
}

impl ReplayGuard {
    /// Drops the challenges dead at `now_ms`.
    pub fn purge(&mut self, now_ms: u64) {
        self.live.retain(|_, dies| *dies > now_ms);
    }

    /// Records a challenge as issued, live until `now_ms + CHALLENGE_TTL_MS`.
    ///
    /// # Errors
    ///
    /// [`DeskError::Busy`] past [`MAX_OUTSTANDING`]; [`DeskError::Replay`]
    /// for a value already outstanding — the caller's randomness failed.
    pub fn issue(&mut self, challenge: String, now_ms: u64) -> Result<(), DeskError> {
        self.purge(now_ms);
        if self.live.len() >= MAX_OUTSTANDING {
            return Err(DeskError::Busy);
        }
        if self.live.contains_key(&challenge) {
            return Err(DeskError::Replay);
        }
        self.live
            .insert(challenge, now_ms.saturating_add(CHALLENGE_TTL_MS));
        Ok(())
    }

    /// Spends a challenge: `true` once, for a challenge issued here and live
    /// at `now_ms`; `false` for everything else, which is a refusal either way.
    pub fn spend(&mut self, challenge: &str, now_ms: u64) -> bool {
        matches!(self.live.remove(challenge), Some(dies) if dies > now_ms)
    }

    /// How many challenges are outstanding.
    #[must_use]
    pub fn outstanding(&self) -> usize {
        self.live.len()
    }
}

/// Which anchor is whose container (CT-13), by period.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Linkage {
    #[serde(with = "pairs")]
    anchors: BTreeMap<AnchorRef, (Hash, String)>,
}

impl Linkage {
    /// Records that `anchor` is `container`'s, in `period`.
    pub fn record(&mut self, anchor: AnchorRef, container: Hash, period: impl Into<String>) {
        self.anchors.insert(anchor, (container, period.into()));
    }

    /// Whose container an anchor belongs to, if we can still tell.
    #[must_use]
    pub fn container_of(&self, anchor: &AnchorRef) -> Option<&Hash> {
        self.anchors.get(anchor).map(|(c, _)| c)
    }

    /// Drops a period: after this, its anchors are not ours to tell either.
    /// Returns how many anchors were dropped.
    pub fn forget(&mut self, period: &str) -> usize {
        let before = self.anchors.len();
        self.anchors.retain(|_, (_, p)| p != period);
        before - self.anchors.len()
    }

    /// The periods still readable, oldest first.
    #[must_use]
    pub fn periods(&self) -> Vec<String> {
        let set: BTreeSet<&String> = self.anchors.values().map(|(_, p)| p).collect();
        set.into_iter().cloned().collect()
    }

    /// How many anchors are still readable.
    #[must_use]
    pub fn len(&self) -> usize {
        self.anchors.len()
    }

    /// Whether no anchor is readable.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }
}

/// Notices waiting for their container.
///
/// Bounded per container as the container's own ring is: a holder who does
/// not come for weeks finds the last [`NOTICE_RING`] and the count of the
/// rest, not an unbounded pile.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mailbox {
    #[serde(with = "pairs")]
    boxes: BTreeMap<Hash, (Vec<ViewNotice>, u64)>,
}

impl Mailbox {
    fn put(&mut self, container: Hash, notice: ViewNotice) {
        let (list, dropped) = self.boxes.entry(container).or_default();
        if list.len() >= NOTICE_RING {
            list.remove(0);
            *dropped = dropped.saturating_add(1);
        }
        list.push(notice);
    }

    /// Takes the notices waiting for `container`, oldest first, and how many
    /// were dropped for want of room before the holder came.
    pub fn take(&mut self, container: &Hash) -> (Vec<ViewNotice>, u64) {
        self.boxes.remove(container).unwrap_or_default()
    }

    /// How many notices wait for `container`.
    #[must_use]
    pub fn waiting(&self, container: &Hash) -> usize {
        self.boxes.get(container).map_or(0, |(l, _)| l.len())
    }
}

/// The desk's whole state, for the host to write to disk and read back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Desk {
    audience: Uri,
    guard: ReplayGuard,
    #[serde(with = "pairs")]
    looks: BTreeMap<(String, String), u64>,
    linkage: Linkage,
    mailbox: Mailbox,
    charges: Vec<Charge>,
}

impl Desk {
    /// A desk that answers as `audience` — the requests name it.
    #[must_use]
    pub fn new(audience: Uri) -> Self {
        Self {
            audience,
            guard: ReplayGuard::default(),
            looks: BTreeMap::new(),
            linkage: Linkage::default(),
            mailbox: Mailbox::default(),
            charges: Vec::new(),
        }
    }

    /// Issues a challenge from 32 bytes of the caller's CSPRNG.
    ///
    /// # Errors
    ///
    /// [`DeskError::Busy`] past [`MAX_OUTSTANDING`].
    pub fn challenge(&mut self, random: [u8; 32], now_ms: u64) -> Result<String, DeskError> {
        let c = hex::encode(random);
        self.guard.issue(c.clone(), now_ms)?;
        Ok(c)
    }

    /// Takes a request: checks it by path A, spends its challenge, charges
    /// the look by its number in `period`, and puts the notice in the
    /// mailbox of the container that was looked at.
    ///
    /// The challenge is spent once the request verifies, whatever follows: a
    /// signed request is good for one attempt.
    ///
    /// # Errors
    ///
    /// [`DeskError`]: what refused the request. Nothing is charged and no
    /// notice is made on a refusal.
    pub fn accept(
        &mut self,
        request: &DisclosureRequest,
        registry: &dyn Registry,
        stream: Stream,
        period: &str,
        now: &Timestamp,
        profile: &Profile,
    ) -> Result<Accepted, DeskError> {
        let now_ms = now.unix_ms();
        let status = registry
            .standing(&request.owner, now_ms)
            .ok_or(DeskError::NotInChain)?;
        request.validate(&self.audience, status, Some(now), profile)?;
        let width = request
            .expires_at
            .unix_ms()
            .saturating_sub(request.issued_at.unix_ms());
        if width > MAX_WINDOW_MS {
            return Err(DeskError::WindowTooWide);
        }
        if !self.guard.spend(&request.challenge, now_ms) {
            return Err(DeskError::Replay);
        }
        let container = *self
            .linkage
            .container_of(&request.anchor)
            .ok_or(DeskError::UnknownAnchor)?;
        let payer = request.owner_id().to_owned();
        let key = (payer.clone(), period.to_owned());
        let looked = self.looks.get(&key).copied().unwrap_or(0);
        let charge = Charge {
            payer,
            period: period.to_owned(),
            look: looked.saturating_add(1),
            cents: price_of_next_cents(stream, looked),
        };
        self.looks.insert(key, looked.saturating_add(1));
        self.charges.push(charge.clone());
        let notice = ViewNotice::of(request.clone(), now.clone());
        self.mailbox.put(container, notice.clone());
        Ok(Accepted {
            charge,
            container,
            notice,
        })
    }

    /// Takes the notices waiting for `container` — the holder collecting
    /// them to record in the container (`Container::record_view`).
    pub fn take_notices(&mut self, container: &Hash) -> (Vec<ViewNotice>, u64) {
        self.mailbox.take(container)
    }

    /// The charges since the last drain, for billing.
    pub fn drain_charges(&mut self) -> Vec<Charge> {
        std::mem::take(&mut self.charges)
    }

    /// Ends a billing period: its look counts are dropped, so the next
    /// period's ladder starts from the first look.
    pub fn close_period(&mut self, period: &str) {
        self.looks.retain(|(_, p), _| p != period);
    }

    /// The anchor table, to record into as anchors land.
    pub fn linkage_mut(&mut self) -> &mut Linkage {
        &mut self.linkage
    }

    /// The anchor table.
    #[must_use]
    pub const fn linkage(&self) -> &Linkage {
        &self.linkage
    }

    /// Challenges outstanding.
    #[must_use]
    pub fn outstanding(&self) -> usize {
        self.guard.outstanding()
    }

    /// The desk as JSON, for the host to write to disk.
    ///
    /// # Errors
    ///
    /// [`DeskError::State`] if it does not serialize.
    pub fn to_json(&self) -> Result<String, DeskError> {
        serde_json::to_string(self).map_err(|_| DeskError::State)
    }

    /// The desk read back from disk.
    ///
    /// # Errors
    ///
    /// [`DeskError::State`] if the text is not a desk.
    pub fn from_json(s: &str) -> Result<Self, DeskError> {
        serde_json::from_str(s).map_err(|_| DeskError::State)
    }
}

/// The owner-watchers a registry knows, for tests and small deployments: key
/// id → status of its container.
#[derive(Debug, Clone, Default)]
pub struct StaticRegistry {
    known: BTreeMap<String, Status>,
}

impl StaticRegistry {
    /// Registers an owner-watcher's key as present in a chain, its container
    /// at `status`.
    pub fn insert(&mut self, key: &PublicKey, status: Status) {
        self.known.insert(key.kid.as_str().to_owned(), status);
    }
}

impl Registry for StaticRegistry {
    fn standing(&self, owner: &[PublicKey], _now_ms: u64) -> Option<Status> {
        // Every key the request names must be present, and all of one
        // container: one standing, or none.
        let found: BTreeSet<_> = owner
            .iter()
            .map(|k| self.known.get(k.kid.as_str()).copied())
            .collect::<Option<_>>()?;
        let mut it = found.into_iter();
        let first = it.next()?;
        it.next().is_none().then_some(first)
    }
}
