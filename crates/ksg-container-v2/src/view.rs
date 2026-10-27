//! "Who looked": the named request for an anchor and the notice it leaves in
//! the container it was about. `[decision]` 13.09
//! (`Resheniya_13.09_dostup_k_tsepi.md` §4 path A, §8.1), 19.09 (CT-15, CT-16).
//!
//! Core v1 carried both documents in its core (`ksg-core::doc::{disclosure_request,
//! view_notice}`); core v2 does not (spec v2 §17: "who looked" and the
//! disclosure are the service layer). They are here, next to the container
//! that keeps the notices, and the service that issues them
//! (`ksg-service-v2::desk`) builds on this module.
//!
//! # The request — path A
//!
//! An owner-watcher — the organization asking to look at somebody else's
//! anchor — signs a [`DisclosureRequest`] with its own keys. There is no
//! anonymous look: the request names the owner-watcher always (`[decision]`
//! 13.09). What a valid signature establishes is **possession of the key**,
//! not the organization behind it — path B, a registry of legal entities, was
//! refused.
//!
//! Three leaks of v1's first design stay closed here as they were closed
//! there: a request is bound to **one** challenge the service issued and to
//! the service it is for (replay, audit of 13.09 finding 2); it dies at
//! `expires_at`; and the owner-watcher's container must not be in a terminal
//! status — presence in a key chain is forever, rights are not (finding 6).
//!
//! # The notice — attached to the anchor's signature
//!
//! `[decision]` 13.09 §8.1: the trail is written **into the client's
//! container**, attached to the anchor's signature, and does not spend the
//! journal's pages. `[decision]` 19.09 (CT-15): the notice carries the
//! owner-watcher's own signed request, so nobody on the container's side has
//! to sign it — the party whose signature makes the notice true is the one
//! who was online by construction. And an owner cannot fabricate «competitor
//! X looked at me»: that would take X's signature over a challenge X never saw.
//!
//! In v2 "the anchor's signature" is literal: a request names the anchor by
//! its network and transaction signature ([`AnchorRef`]), and the container
//! takes a notice only for an anchor whose attestation it holds — a seal of
//! its journal or a record of its status section.
//!
//! # The ring
//!
//! Notices are kept in a [`NoticeRing`] of fixed capacity for the **whole
//! container** — not per anchor, as in v1. A per-anchor ring of 64 times a
//! thousand anchors would not fit the 4 MiB the container is padded to; one
//! ring of [`NOTICE_RING`] does, with the full journal, and its size never
//! moves with the attention a container drew: old notices drop for new ones,
//! and how many dropped is counted.
//!
//! What is not closed, and cannot be here: a holder may **suppress** a notice
//! by never recording it. A container's own records are kept by whoever keeps
//! the container.

use serde::{Deserialize, Serialize};

use ksg_core_v2::canonical::{canonical_bytes, check_envelope, Signable};
use ksg_core_v2::crypto::sign::{KeySet, Profile, PublicKey, SignatureSet};
use ksg_core_v2::doc::{Timestamp, Uri};
use ksg_core_v2::error::Invalid;
use ksg_core_v2::status::Status;

/// How many notices one container keeps. Fixed, and that is the point.
///
/// Set from the store's room: the full container of the worst case takes
/// 3.72 MiB of the 4 MiB (`tests/store.rs`, `a_full_journal_fits_the_store`),
/// and 24 notices at [`MAX_NOTICE_BYTES`] take 240 KiB of the 286 KiB left.
pub const NOTICE_RING: usize = 24;

/// The most one notice may take as canonical JSON. A request carries at most
/// two keys and two signatures; with ML-DSA-65 that is about 7.5 KiB. The
/// bound keeps [`NOTICE_RING`] notices inside the store's padding whatever
/// the profile.
pub const MAX_NOTICE_BYTES: usize = 10 * 1024;

/// The most keys an owner-watcher signs a request with: one per algorithm.
pub const MAX_OWNER_KEYS: usize = 2;

/// The width of a challenge: 32 bytes, as 64 lowercase hex digits.
pub const CHALLENGE_HEX_LEN: usize = 64;

/// Which anchor a request is about: the network and the transaction that
/// carries its memo — what an observer of the chain actually sees.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorRef {
    /// The network: `mainnet-beta`, `devnet`, `testnet`.
    pub cluster: String,
    /// The transaction signature, base58.
    pub signature: String,
}

impl AnchorRef {
    fn check(&self) -> Result<(), Invalid> {
        if !matches!(self.cluster.as_str(), "mainnet-beta" | "devnet" | "testnet") {
            return Err(Invalid::Schema("the anchor names an unknown network"));
        }
        // A Solana signature is 64 bytes: 87 or 88 base58 digits, never
        // fewer than 64 even with leading zero bytes.
        let ok_len = (64..=88).contains(&self.signature.len());
        let ok_alphabet = self
            .signature
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() && !matches!(b, b'0' | b'O' | b'I' | b'l'));
        if !(ok_len && ok_alphabet) {
            return Err(Invalid::Schema(
                "the anchor's transaction signature is not base58 of a signature",
            ));
        }
        Ok(())
    }
}

/// A named request to look at an anchor (Ts-5, path A).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisclosureRequest {
    /// Always `"DisclosureRequest"`.
    #[serde(rename = "type")]
    pub doc_type: String,
    /// The major core version.
    pub v: u32,
    /// The keys of the **owner-watcher** — the organization asking to look at
    /// somebody else's anchor; at most one per algorithm. Their presence in
    /// the chain is what path A verifies (the service looks it up).
    pub owner: Vec<PublicKey>,
    /// Which service the request is for. Without it a request drawn up for
    /// one service is valid at another.
    pub audience: Uri,
    /// The anchor being asked about.
    pub anchor: AnchorRef,
    /// The challenge the service issued for this request: 32 bytes, hex.
    /// The whole of the anti-replay — and whether it was issued and is still
    /// unspent is the service's memory, not the document's
    /// (`ksg-service-v2::desk::ReplayGuard`).
    pub challenge: String,
    /// When the request was drawn up — the owner-watcher's clock.
    pub issued_at: Timestamp,
    /// After which the request is dead.
    pub expires_at: Timestamp,
    /// The owner-watcher's signatures.
    pub signatures: SignatureSet,
}

impl Signable for DisclosureRequest {
    const DOC_TYPE: &'static str = "DisclosureRequest";
}

impl DisclosureRequest {
    /// The type field's value.
    pub const TYPE: &'static str = "DisclosureRequest";

    /// The owner-watcher's identifier: the `kid` of its first key, without
    /// the fragment. Always present — a request without an owner does not
    /// verify.
    #[must_use]
    pub fn owner_id(&self) -> &str {
        self.owner
            .first()
            .map_or("", |k| k.kid.as_str().split('#').next().unwrap_or(""))
    }

    /// The owner-watcher's keys as a set.
    #[must_use]
    pub fn owner_keys(&self) -> KeySet {
        self.owner.iter().cloned().collect()
    }

    /// Verifies what the document alone can show: its form, its window, and
    /// that the owner-watcher's own keys signed it — and no other key.
    ///
    /// `now`, when given, must fall inside the window. `None` skips the
    /// window and keeps the rest: a stored request that has expired since is
    /// still the request it was.
    ///
    /// # Errors
    ///
    /// [`Invalid::Schema`] for a malformed request, a window that runs
    /// backwards or that `now` is outside; [`Invalid::Signature`] if the
    /// owner-watcher's keys did not sign it.
    pub fn check_signed(&self, now: Option<&Timestamp>, profile: &Profile) -> Result<(), Invalid> {
        if self.owner.is_empty() || self.owner.len() > MAX_OWNER_KEYS {
            return Err(Invalid::Schema(
                "a request names its owner-watcher with one key per algorithm",
            ));
        }
        let mut algs: Vec<_> = self.owner.iter().map(|k| k.alg).collect();
        algs.sort_by_key(|a| a.to_string());
        algs.dedup();
        if algs.len() != self.owner.len() {
            return Err(Invalid::Schema(
                "a request names its owner-watcher with one key per algorithm",
            ));
        }
        let prefix = self.owner_id();
        if prefix.is_empty()
            || self
                .owner
                .iter()
                .any(|k| k.kid.as_str().split('#').next() != Some(prefix))
        {
            return Err(Invalid::Schema(
                "the owner-watcher's keys belong to one identifier",
            ));
        }
        self.anchor.check()?;
        if self.challenge.len() != CHALLENGE_HEX_LEN
            || !self
                .challenge
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Invalid::Schema(
                "the challenge is not 32 bytes of lowercase hex",
            ));
        }
        // A window that runs backwards is not a window — checked before `now`
        // is consulted, so a malformed request is malformed with or without a
        // clock.
        if self.expires_at <= self.issued_at {
            return Err(Invalid::Schema("the request expires before it is issued"));
        }
        if let Some(now) = now {
            if *now < self.issued_at {
                return Err(Invalid::Schema("the request is dated in the future"));
            }
            if *now > self.expires_at {
                return Err(Invalid::Schema("the request has expired"));
            }
        }
        // Signed by the owner-watcher's keys only: a signature by some other
        // key would pass a bare envelope check over a wider set, and the
        // document exists to name who is looking.
        check_envelope(
            self,
            self.v,
            &self.doc_type,
            &self.signatures,
            &self.owner_keys(),
            profile,
        )
    }

    /// Verifies the request as the service takes it (Ts-5, path A).
    ///
    /// `owner_status` is the current status of the container the
    /// owner-watcher's keys belong to — the service looks it up, since a
    /// requester carrying it would be asserting its own standing.
    ///
    /// # Errors
    ///
    /// As [`DisclosureRequest::check_signed`]; [`Invalid::Schema`] also for a
    /// request addressed to another service, or an owner-watcher whose
    /// container is in a terminal status and exercises no rights (finding 6).
    pub fn validate(
        &self,
        audience: &Uri,
        owner_status: Status,
        now: Option<&Timestamp>,
        profile: &Profile,
    ) -> Result<(), Invalid> {
        if &self.audience != audience {
            return Err(Invalid::Schema(
                "the request is addressed to another service",
            ));
        }
        if owner_status.is_terminal() {
            return Err(Invalid::Schema(
                "the owner-watcher's container is in a terminal status and exercises no rights",
            ));
        }
        self.check_signed(now, profile)
    }
}

/// One recorded view of an anchor (§8.1-g): what was looked at, when, and
/// under whose signature — all inside the request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ViewNotice {
    /// Always `"ViewNotice"`.
    #[serde(rename = "type")]
    pub doc_type: String,
    /// The major core version.
    pub v: u32,
    /// The request as the owner-watcher signed it. **This is the whole
    /// evidence.**
    pub request: DisclosureRequest,
    /// When the service took the request — its clock, not the
    /// owner-watcher's; the two are not the same claim.
    pub seen_at: Timestamp,
}

impl ViewNotice {
    /// The type field's value.
    pub const TYPE: &'static str = "ViewNotice";

    /// A notice of `request`, taken at `seen_at`.
    #[must_use]
    pub fn of(request: DisclosureRequest, seen_at: Timestamp) -> Self {
        Self {
            doc_type: Self::TYPE.into(),
            v: ksg_core_v2::version::CURRENT_V,
            request,
            seen_at,
        }
    }

    /// Verifies the notice as anybody can, years later: its form and size,
    /// the request's signature, and that the view happened inside the
    /// request's window.
    ///
    /// There is no signature of the service to check, deliberately (CT-15).
    ///
    /// # Errors
    ///
    /// [`Invalid::Schema`] for a foreign type or version, an oversized
    /// notice, or a view outside the window; the request's own errors.
    pub fn check(&self, profile: &Profile) -> Result<(), Invalid> {
        ksg_core_v2::version::check(self.v)?;
        if self.doc_type != Self::TYPE || self.request.doc_type != DisclosureRequest::TYPE {
            return Err(Invalid::Schema("not a view notice"));
        }
        let len = canonical_bytes(&NoticeBytes(self))?.len();
        ksg_core_v2::limits::at_most(len, MAX_NOTICE_BYTES, "view notice bytes")?;
        // The view is judged at the moment the service recorded it.
        self.request.check_signed(Some(&self.seen_at), profile)
    }

    /// The owner-watcher's identifier.
    #[must_use]
    pub fn owner_id(&self) -> &str {
        self.request.owner_id()
    }

    /// What was looked at.
    #[must_use]
    pub const fn anchor(&self) -> &AnchorRef {
        &self.request.anchor
    }
}

/// The whole notice, for its canonical size: [`Signable`] would drop nothing
/// here, since the notice has no `signatures` of its own.
#[derive(Serialize)]
struct NoticeBytes<'a>(&'a ViewNotice);

impl Signable for NoticeBytes<'_> {
    const DOC_TYPE: &'static str = "ViewNotice";
}

/// The notices of one container.
///
/// Fixed capacity ([`NOTICE_RING`]); old notices drop for new ones and are
/// counted. Dropping rather than refusing: a full ring that refused would let
/// a flood of views keep the owner from learning about the next real one
/// (finding 9).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoticeRing {
    notices: Vec<ViewNotice>,
    /// How many were dropped to make room.
    dropped: u64,
}

impl NoticeRing {
    /// A container nobody has looked at.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            notices: Vec::new(),
            dropped: 0,
        }
    }

    /// Whether the ring already holds this very request — the same
    /// challenge: one look, recorded once, however often it is delivered.
    #[must_use]
    pub fn holds(&self, notice: &ViewNotice) -> bool {
        self.notices
            .iter()
            .any(|n| n.request.challenge == notice.request.challenge)
    }

    /// Records a view, dropping the oldest notice if the ring is full.
    pub(crate) fn record(&mut self, notice: ViewNotice) {
        if self.notices.len() >= NOTICE_RING {
            self.notices.remove(0);
            self.dropped = self.dropped.saturating_add(1);
        }
        self.notices.push(notice);
    }

    /// The notices kept, oldest first.
    #[must_use]
    pub fn as_slice(&self) -> &[ViewNotice] {
        &self.notices
    }

    /// How many notices were dropped for want of room. Shown rather than
    /// swallowed: "and 400 more" is the truthful reading of a ring that ran
    /// over.
    #[must_use]
    pub const fn dropped(&self) -> u64 {
        self.dropped
    }

    /// How many views in total, kept or dropped.
    #[must_use]
    pub fn seen(&self) -> u64 {
        self.dropped.saturating_add(self.notices.len() as u64)
    }

    /// How many kept views fall inside `[from, to]` — the aggregate form
    /// (CT-16, `[decision]` 19.09): the owner is told «N looks this period»,
    /// not «X looked just now», since the timing is what gives a deal away.
    /// Dropped notices have no date any more; [`NoticeRing::dropped`] says
    /// how many a period may be missing.
    #[must_use]
    pub fn in_period(&self, from: &Timestamp, to: &Timestamp) -> usize {
        self.notices
            .iter()
            .filter(|n| n.seen_at >= *from && n.seen_at <= *to)
            .count()
    }

    pub(crate) fn from_parts(notices: Vec<ViewNotice>, dropped: u64) -> Self {
        Self { notices, dropped }
    }
}

/// Why a container did not take a notice.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ViewError {
    /// The notice does not verify.
    #[error("the notice does not verify: {0}")]
    Invalid(#[from] Invalid),
    /// The anchor it names is not one of this container's.
    #[error("the notice is about an anchor this container does not hold")]
    NotOurs,
    /// This very request is recorded already.
    #[error("this request is recorded already")]
    Again,
}

/// The transaction signature and network of an attestation's proof, when it
/// is a network's proof (canonical JSON with `signature` and `cluster`, as
/// `ksg-verify-v2::solana::AnchorProof` writes it).
pub(crate) fn proof_ref(proof: &[u8]) -> Option<AnchorRef> {
    #[derive(Deserialize)]
    struct P {
        signature: String,
        cluster: String,
    }
    serde_json::from_slice::<P>(proof).ok().map(|p| AnchorRef {
        cluster: p.cluster,
        signature: p.signature,
    })
}
