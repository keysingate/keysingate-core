//! What arrives at a button, as data. KS-7 §4 — O-1, and with it O-4.
//!
//! # The event is data and executes nothing
//!
//! §4.2 is normative: an event **is** data. It is laid down, and a trigger
//! decides. No part of it may be read as code or as an instruction that skips
//! the table of rules. So the payload here is [`Wrapped`] — bytes nothing on
//! this path opens — and the type carries no callback, no closure and no name
//! anything dispatches on.
//!
//! # The composition, and what changed from the proposal
//!
//! KS-7 §4.1 proposed six fields. `[decision] 12.09` settles the composition, with two
//! corrections that came out of building it:
//!
//! | Field | Proposal | Now |
//! |---|---|---|
//! | type | yes | yes — [`Operation`] |
//! | door | yes | yes — [`Button`] |
//! | payload, already wrapped | yes | yes — [`Wrapped`] |
//! | signatures | yes | yes |
//! | keys | yes | **dropped** |
//! | reference to the previous journal entry | yes | **[`Head`]**, and it is a claim rather than a link |
//! | **container** | — | **added** |
//! | **what the signatures cover** | — | **added** |
//!
//! **Keys dropped.** The container knows the keys: they are in the layers it has
//! opened, and each signature names its own. Carrying them in the event would
//! make a second source of truth for the same fact, and two sources of one truth
//! diverge — at which point the question becomes which of them decides.
//!
//! **Container added.** Without it an event is replayable into the neighbour.
//! §3.1 keeps containers from seeing each other's state, which does nothing to
//! stop a command captured at one from being presented at another; naming the
//! container inside the signed bytes does.
//!
//! **What the signatures cover, added.** "Signatures" without the bytes they
//! cover is not a field but a decoration: nothing can be checked against it.
//!
//! # O-4 falls out of O-1, and the answer is "nowhere"
//!
//! O-4 asked **where the client stores the code phrase** — the phrase issued at
//! the initiation of the client's signature, which "binds the command to the
//! moment" so that a captured command cannot be replayed. The difficulty was
//! stated with it: the phrase is **symmetric**, known to both sides.
//!
//! A symmetric secret has to live somewhere on both sides. Inside a container
//! that would be a readable secret, and inside a container there is only writing
//! (KS-8 F-7, and the axiom that an entry point is a break-in point). So the
//! question is not where to put it well. It is whether it needs to exist.
//!
//! **What the phrase was for is done by [`Head`] instead.** The presenter states
//! the head of the journal it saw — the counter and the digest of the last page.
//! A command carrying a stale head is refused, so a captured command is dead the
//! moment anything is written. That is the binding to the moment, and it takes
//! no secret at all: the counter is already monotone by F-3.
//!
//! **And the second factor the phrase looked like is already there, better.**
//! After O-3 every operation that changes what the container is worth takes a
//! second **party**, signing on the same command. That is asymmetric — signatures
//! rather than a shared secret — and a second party cannot be stolen the way a
//! phrase can be copied.
//!
//! So: **the client stores nothing, because there is nothing to store.** The
//! phrase scheme was declared a replaceable layer (KS-7 §5.4, KS-8 I-4), and this
//! replaces it with no layer. If a deployment still wants a symmetric phrase, the
//! one place for it is the client's key store, beside the key and under the same
//! protection — never in the container, and never in two places.

use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{KeySet, Profile, SignatureSet};
use ksg_core_v2::doc::Class;
use ksg_core_v2::status::{Blocked, Status};

use crate::command::{Command, Refusal, Refused, Roster, Strength};
use crate::operation::{Button, Operation};
use crate::pack::{Aead, Compressor, PackError, Packer};

/// Material that has been through step 2 of §3.3 — wrapped before it is checked.
///
/// A newtype rather than bare bytes, because the order is the property: step 2
/// **must** precede step 3, so that the presented material never lies inside in
/// the clear. Making that visible in the type is the honest amount of help a type
/// can give here.
///
/// What it does **not** do is prove that wrapping happened: material arriving
/// over a wire is already wrapped, and [`Wrapped::received`] has to exist. What
/// holds regardless is the half that does not need a cipher — **nothing on this
/// path opens it**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wrapped(Vec<u8>);

impl Wrapped {
    /// Wraps the material — step 2 itself.
    ///
    /// # Errors
    ///
    /// Whatever the packer says: [`PackError::TooLarge`],
    /// [`PackError::ShortNoise`], or the AEAD's.
    pub fn seal<A: Aead, C: Compressor>(
        packer: &Packer<A, C>,
        plain: &[u8],
        noise_bytes: &[u8],
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Self, PackError> {
        packer
            .seal(plain, noise_bytes, key, nonce, aad)
            .map(Wrapped)
    }

    /// Material that arrived already wrapped.
    #[must_use]
    pub const fn received(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The bytes, unread by anything here.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}

/// The head of the journal, as the presenter saw it.
///
/// A **claim**, not a link: the presenter says what it last saw, and the
/// container compares. A link would be a thing the event carries into the
/// journal, and a refused event carries nothing anywhere (§4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Head {
    /// The counter of the last page (F-1).
    pub counter: u64,
    /// The digest of that page.
    pub page: Hash,
}

/// An event presented at a button — the composition of KS-7 §4.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// Which operation. The type of the event.
    pub op: Operation,
    /// Which of the three doors it came through.
    pub button: Button,
    /// Which container it is for. Replay into a neighbour dies here.
    pub container: Hash,
    /// The payload, already wrapped and opened by nothing on this path.
    pub payload: Wrapped,
    /// The signatures.
    pub signatures: SignatureSet,
    /// The bytes those signatures cover.
    pub covered: Vec<u8>,
    /// The journal head the presenter saw, where there is one. `None` before
    /// page 0 exists — a container with no journal has no head to claim.
    pub head: Option<Head>,
}

/// The container as it is at this moment, from the checking side.
///
/// Five values that all answer "what does the container read right now", grouped
/// because they travel together and mean one thing: its identity, its journal
/// head, its status, whether it is blocked, and who holds which role. Passing
/// them one by one made the call a list of arguments nobody could read.
#[derive(Debug, Clone, Copy)]
pub struct View<'a> {
    /// Which container this is.
    pub container: &'a Hash,
    /// The head of its journal, where there is one.
    pub head: Option<Head>,
    /// What its status section reads.
    pub status: Status,
    /// Whether a decision is owed.
    pub blocked: Blocked,
    /// Who holds which role (O-3).
    pub roster: &'a Roster,
}

impl Event {
    /// The bytes the signatures must cover — the event's subject.
    ///
    /// # Why this exists
    ///
    /// Until 2026-09-13 `covered` was whatever the presenting layer chose, and
    /// nothing tied it to the operation. A valid command could therefore be
    /// **replayed with its operation swapped**: the signatures still verified
    /// over the same bytes, while `op`, `button`, `payload` and the container
    /// were read from fields the signer never covered — "record work" pressed
    /// as "full export" (security audit of 2026-09-13, finding 2).
    ///
    /// The subject binds all of it: the operation, the door it came through,
    /// which container, the head the presenter claims to have seen, and a
    /// digest of the payload. Every field goes in length-prefixed, so that no
    /// two different events can produce the same bytes by running one field
    /// into the next.
    ///
    /// The payload enters as a digest, not in the clear: nothing on this path
    /// reads the material (D-4), and hashing it is not reading it.
    #[must_use]
    pub fn subject(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(160);
        let mut field = |bytes: &[u8]| {
            out.extend_from_slice(&u32::try_from(bytes.len()).unwrap_or(u32::MAX).to_be_bytes());
            out.extend_from_slice(bytes);
        };
        field(b"ksg:event:v1");
        field(format!("{:?}", self.op).as_bytes());
        field(format!("{:?}", self.button).as_bytes());
        field(self.container.as_bytes());
        match self.head {
            // A container before page 0 has no head to claim; the two cases
            // must not collide, so the marker differs rather than being absent.
            None => field(b"head:none"),
            Some(h) => {
                field(b"head:some");
                field(&h.counter.to_be_bytes());
                field(h.page.as_bytes());
            }
        }
        field(Hash::sha256(self.payload.bytes()).as_bytes());
        out
    }

    /// The command this event presents.
    ///
    /// The checking of buttons, parties and status lives in [`Command`] and is
    /// not duplicated here: one rule, one place.
    #[must_use]
    pub fn command(&self) -> Command {
        Command {
            op: self.op,
            payload: self.payload.bytes().to_vec(),
            signatures: self.signatures.clone(),
            signed_bytes: self.covered.clone(),
        }
    }

    /// Puts the event through its door.
    ///
    /// Two checks of its own, then the command's. Both of its own are about
    /// **identity and freshness** — that this is the right container and a
    /// current view of it — which is the work the code phrase of O-4 was
    /// supposed to do, done without a secret.
    ///
    /// # Errors
    ///
    /// [`Refused`], carrying the record to anchor as every refusal does:
    /// [`Refusal::WrongContainer`] for an event addressed elsewhere,
    /// [`Refusal::StaleHead`] for a view that is behind, and then whatever the
    /// command answers.
    pub fn press(
        &self,
        view: &View<'_>,
        keys: &KeySet,
        profile: &Profile,
    ) -> Result<Strength, Refused> {
        let command = self.command();
        let refuse = |reason: Refusal| Refused {
            attempt: Box::new(command.record(self.button, view.status, reason.clone())),
            reason,
        };

        if self.container != *view.container {
            return Err(refuse(Refusal::WrongContainer));
        }
        // A stale head is a replayed or held command: something has been written
        // since this one was made. Equality both ways — a head from the future is
        // no better than one from the past, and both mean the presenter is not
        // looking at this container as it is.
        if self.head != view.head {
            return Err(refuse(Refusal::StaleHead));
        }
        // The signatures must cover **this** event, not bytes chosen freely by
        // the presenter. Without this, a signature from one command carries
        // over to another (security audit of 2026-09-13, finding 2).
        if self.covered != self.subject() {
            return Err(refuse(Refusal::UnboundSignature));
        }

        command.press(
            self.button,
            view.status,
            view.blocked,
            view.roster,
            keys,
            profile,
        )
    }

    /// Puts the event through its door for a container of the class given.
    /// Goal 1, `bare` v2 (owner's decision 08.10): the class-aware twin of
    /// [`Event::press`]; [`Event::press`] itself stays as the Pro default.
    ///
    /// # Errors
    ///
    /// [`Refused`], carrying the record to anchor as every refusal does.
    pub fn press_for(
        &self,
        view: &View<'_>,
        class: Class,
        keys: &KeySet,
        profile: &Profile,
    ) -> Result<Strength, Refused> {
        let command = self.command();
        let refuse = |reason: Refusal| Refused {
            attempt: Box::new(command.record(self.button, view.status, reason.clone())),
            reason,
        };

        if self.container != *view.container {
            return Err(refuse(Refusal::WrongContainer));
        }
        // A stale head is a replayed or held command: something has been written
        // since this one was made. Equality both ways — a head from the future is
        // no better than one from the past, and both mean the presenter is not
        // looking at this container as it is.
        if self.head != view.head {
            return Err(refuse(Refusal::StaleHead));
        }
        // The signatures must cover **this** event, not bytes chosen freely by
        // the presenter. Without this, a signature from one command carries
        // over to another (security audit of 2026-09-13, finding 2).
        if self.covered != self.subject() {
            return Err(refuse(Refusal::UnboundSignature));
        }

        command.press_for(
            self.button,
            class,
            view.status,
            view.blocked,
            view.roster,
            keys,
            profile,
        )
    }
}
