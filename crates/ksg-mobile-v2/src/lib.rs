//! # ksg-mobile-v2 — the client's mobile half, as a library for the phone
//!
//! The client's key exists only as two halves (FROST 2-of-2,
//! `ksg_container_v2::client_key`): one inside the container, one with the
//! client. In the MVP the client's half runs as a process,
//! `ksg-remote-panel mobile serve`; in the product it runs on the client's phone. This
//! crate is what both run: everything of the mobile side **except** the
//! screen and the storage of the half, which are the platform's.
//!
//! | Piece | What it does |
//! |---|---|
//! | [`Session`] | one half and the round it has open: commit, then respond once |
//! | [`Consent`] | the holder's yes or no to **what** a round signs, asked before every share |
//! | [`handle_line`] | the wire: one JSON line in, one JSON line out — no process, no socket |
//! | [`Keygen`] | the mobile side's birth: `start` opens it, `finish` closes it — the half waits in between |
//!
//! # Why consent is here and not in the app
//!
//! Before this crate the mobile half answered every round it was sent: a
//! reader that had the half's process could have it sign anything. The half
//! is the client's say in what its agent signs; a half that signs blind is
//! not a say. So every share now passes through [`Consent::approve`] with a
//! description of the message — its digest, its document type — and a
//! refusal ends the round with nothing signed. The app shows the
//! description; a command line asks on the terminal; a test approves in
//! code. Approving everything is a choice a caller makes by name
//! ([`ApproveAll`]), not a default it falls into.
//!
//! # What is not here
//!
//! * The phone app — the screen, the secure storage of the half (Keychain,
//!   Keystore), the transport to the reader. Building it needs a platform
//!   SDK this repository does not carry.
//! * A binding for Swift or Kotlin. The API is small and owns no I/O, so a
//!   binding wraps [`handle_line`] or [`Session`] as they are.

#![forbid(unsafe_code)]

pub mod keygen;

pub use keygen::{Keygen, KeygenError, WaitingHalf};

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use ksg_container_v2::client_key::{
    Commitment, MobileHalf, MobileNonces, MobileShare, SigningRound,
};
use ksg_core_v2::crypto::hash::Hash;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// What a round asks the holder to sign, as the holder is shown it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signing {
    /// SHA-256 of the message, as a multihash: what the holder can compare
    /// with the reader's screen.
    pub digest: String,
    /// The document's `type` when the message is a JSON document that names
    /// one; `None` for other bytes.
    pub doc_type: Option<String>,
    /// The message's length in bytes.
    pub len: usize,
}

impl Signing {
    /// The description of `message`.
    #[must_use]
    pub fn of(message: &[u8]) -> Self {
        let doc_type = serde_json::from_slice::<serde_json::Value>(message)
            .ok()
            .and_then(|v| v.get("type").and_then(|t| t.as_str()).map(str::to_owned));
        Self {
            digest: Hash::sha256(message).to_multihash(),
            doc_type,
            len: message.len(),
        }
    }
}

impl core::fmt::Display for Signing {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} ({} bytes) {}",
            self.doc_type.as_deref().unwrap_or("bytes"),
            self.len,
            self.digest
        )
    }
}

/// The holder's say over each share.
pub trait Consent {
    /// Whether the holder agrees to sign this. Asked once per round, before
    /// the share is made.
    fn approve(&mut self, what: &Signing) -> bool;
}

/// Approves every round. For tests and for a deployment that decided, by
/// name, that its holder approves everything.
#[derive(Debug, Clone, Copy, Default)]
pub struct ApproveAll;

impl Consent for ApproveAll {
    fn approve(&mut self, _what: &Signing) -> bool {
        true
    }
}

/// Why the mobile half did not answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MobileError {
    /// No round open: `respond` before `commit`, or the same round twice.
    NoRound,
    /// The holder said no.
    Refused(Signing),
    /// The round is not one this half can answer.
    Round(String),
    /// A request that is not one.
    Wire(String),
}

impl core::fmt::Display for MobileError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoRound => f.write_str("no round open"),
            Self::Refused(s) => write!(f, "the holder refused to sign {s}"),
            Self::Round(e) => write!(f, "round: {e}"),
            Self::Wire(e) => write!(f, "request: {e}"),
        }
    }
}

impl std::error::Error for MobileError {}

/// One mobile half and the round it has open.
///
/// The nonces of a round live only here, in memory: made by
/// [`Session::commit`], spent by the next [`Session::respond`] — whether it
/// answers or is refused — and never written anywhere. Nonces used twice
/// would give the half away.
pub struct Session<C> {
    half: MobileHalf,
    nonces: Option<MobileNonces>,
    consent: C,
}

impl<C: Consent> Session<C> {
    /// A session over `half`, asking `consent` before every share.
    pub const fn new(half: MobileHalf, consent: C) -> Self {
        Self {
            half,
            nonces: None,
            consent,
        }
    }

    /// The holder's say, to be set before a round is answered — for a
    /// consent given outside the call, as a browser page gives it.
    pub fn consent_mut(&mut self) -> &mut C {
        &mut self.consent
    }

    /// Opens a round: the commitment for the container. A round left open
    /// is dropped: nonces are used once.
    pub fn commit<R: RngCore + CryptoRng>(&mut self, rng: &mut R) -> Commitment {
        let (nonces, commitment) = self.half.commit(rng);
        self.nonces = Some(nonces);
        commitment
    }

    /// The share of the round the container answered with — if the holder
    /// agrees to what it signs.
    ///
    /// # Errors
    ///
    /// [`MobileError::NoRound`] with no round open; [`MobileError::Refused`]
    /// when the holder said no — the round is closed either way;
    /// [`MobileError::Round`] for a round without this half's commitment.
    pub fn respond(&mut self, round: &SigningRound) -> Result<MobileShare, MobileError> {
        let nonces = self.nonces.take().ok_or(MobileError::NoRound)?;
        let what = Signing::of(round.message());
        if !self.consent.approve(&what) {
            return Err(MobileError::Refused(what));
        }
        self.half
            .respond(nonces, round)
            .map_err(|e| MobileError::Round(e.to_string()))
    }
}

/// A birth step the page carries: out to the browser, back with an answer.
///
/// The birth's two crossings use the same request line the signing rounds
/// use — the page holds the birth's secret the way it holds the round's
/// nonces, and nothing of either crosses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BirthOp {
    /// The page opens its birth and answers with this side's commitment.
    Hello,
    /// The page closes its birth with the container's answer and answers
    /// with the container's share (the share waits for the container in the
    /// reader, which names the `did:key` from it).
    Finish,
}

/// What a birth step on the wire is: which of the two crossings a line asks
/// for, or none for the signing rounds.
#[must_use]
pub fn describe_birth(line: &str) -> Option<BirthOp> {
    match serde_json::from_str::<Request>(line).ok()? {
        Request::KeygenStart { .. } => Some(BirthOp::Hello),
        Request::KeygenFinish { .. } => Some(BirthOp::Finish),
        Request::Commit | Request::Respond { .. } => None,
    }
}

/// A request on the wire.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum Request {
    /// Open a round.
    Commit,
    /// Answer a round: the signing package, base64url.
    Respond {
        /// The round as `SigningRound::to_bytes`, base64url.
        round: String,
    },
    /// Open the birth the mobile side will sign the finishing rounds with:
    /// the commitment for the container's `BeginBirth`, base64url.
    KeygenStart {
        /// The client's key name for now — the `did:key` of the group key
        /// replaces it once both sides are done.
        kid: String,
    },
    /// Close the birth with the container's answer: the container's share,
    /// base64url, back for the reader's `FinishBirth`.
    KeygenFinish {
        /// The container's answer (message 2), base64url.
        reply: String,
    },
}

/// An answer on the wire.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Answer {
    /// The commitment or the share, base64url.
    Ok(String),
    /// Why not.
    Err(String),
}

/// One line of the wire in, one line out:
///
/// | Request | Answer |
/// |---|---|
/// | `{"op":"commit"}` | `{"ok":"<commitment>"}` |
/// | `{"op":"respond","round":"<round>"}` | `{"ok":"<share>"}` |
/// | `{"op":"keygen_start","kid":"<kid>"}` | `{"ok":"<hello>"}` |
/// | `{"op":"keygen_finish","reply":"<reply>"}` | `{"ok":"<finish>"}` |
/// | anything it cannot do | `{"err":"<why>"}` |
///
/// What crosses — commitment, round, share — is public by FROST's design.
/// The birth's hello and reply are public the same way; the birth's secret
/// stays on the side that opened it, as the round's nonces do.
///
/// A birth line needs the birth, not a session: it is handled by
/// [`handle_birth_line`] on the platform — the page, or the process — that
/// holds the [`Keygen`]. This handler keeps the signing lines only.
#[must_use]
pub fn handle_line<C: Consent, R: RngCore + CryptoRng>(
    session: &mut Session<C>,
    line: &str,
    rng: &mut R,
) -> String {
    let answer = match serde_json::from_str::<Request>(line) {
        Err(e) => Answer::Err(MobileError::Wire(e.to_string()).to_string()),
        Ok(Request::Commit) => match session.commit(rng).to_bytes() {
            Ok(b) => Answer::Ok(B64.encode(b)),
            Err(e) => Answer::Err(e.to_string()),
        },
        Ok(Request::Respond { round }) => match B64
            .decode(round)
            .map_err(|e| MobileError::Wire(e.to_string()))
            .and_then(|b| {
                SigningRound::from_bytes(&b).map_err(|e| MobileError::Wire(e.to_string()))
            })
            .and_then(|r| session.respond(&r))
        {
            Ok(share) => Answer::Ok(B64.encode(share.to_bytes())),
            Err(e) => Answer::Err(e.to_string()),
        },
        Ok(Request::KeygenStart { .. } | Request::KeygenFinish { .. }) => {
            Answer::Err(MobileError::Wire("a birth line is not for a session".into()).to_string())
        }
    };
    serde_json::to_string(&answer)
        .unwrap_or_else(|_| r#"{"err":"the answer did not encode"}"#.to_owned())
}

/// One birth line in, one answer out, over the birth the platform holds.
///
/// The counterpart of [`handle_line`] for the two birth crossings: the page
/// holds the [`Keygen`] the way it holds the round's nonces — the hello and
/// the reply cross, the secret never does. `birth` is `None` until the first
/// `keygen_start`; a second `finish` answers `NoBirth` — the birth is spent,
/// not repeated.
#[must_use]
pub fn handle_birth_line<R: RngCore + CryptoRng>(
    birth: &mut Option<Keygen>,
    line: &str,
    rng: &mut R,
) -> String {
    let answer = match serde_json::from_str::<Request>(line) {
        Err(e) => Answer::Err(MobileError::Wire(e.to_string()).to_string()),
        Ok(Request::Commit | Request::Respond { .. }) => {
            Answer::Err(MobileError::Wire("a round line is not for a birth".into()).to_string())
        }
        Ok(Request::KeygenStart { kid }) => {
            let kid = match ksg_core_v2::doc::Uri::parse(&kid) {
                Ok(kid) => kid,
                Err(e) => {
                    return json_err(&MobileError::Wire(format!("kid: {e}")));
                }
            };
            match Keygen::start(kid, rng) {
                Ok((opened, hello)) => {
                    *birth = Some(opened);
                    Answer::Ok(B64.encode(hello))
                }
                Err(e) => Answer::Err(MobileError::Wire(e.to_string()).to_string()),
            }
        }
        Ok(Request::KeygenFinish { reply }) => {
            let reply = match B64.decode(reply) {
                Ok(reply) => reply,
                Err(e) => return json_err(&MobileError::Wire(e.to_string())),
            };
            match birth.as_mut() {
                None => Answer::Err(KeygenError::NoBirth.to_string()),
                Some(opened) => match opened.finish(&reply) {
                    Ok(waiting) => Answer::Ok(B64.encode(waiting.finish_bytes())),
                    Err(e) => Answer::Err(e.to_string()),
                },
            }
        }
    };
    serde_json::to_string(&answer)
        .unwrap_or_else(|_| r#"{"err":"the answer did not encode"}"#.to_owned())
}

/// A refused answer line, without a session or a birth to refuse on.
#[must_use]
fn json_err(err: &MobileError) -> String {
    serde_json::to_string(&Answer::Err(err.to_string()))
        .unwrap_or_else(|_| r#"{"err":"the answer did not encode"}"#.to_owned())
}

/// One page of the wire, birth and rounds together: the birth the platform
/// holds, then the half it signs the rounds with. The birth's two crossings
/// go first (the secret stays on the page, the hello and the reply cross);
/// every line after the `finish` is a round line over the half the finish
/// returned.
///
/// A birth line needs the half it has not made yet, and a round line needs
/// the half the birth made: the page answers birth lines through the
/// [`Keygen`] it holds, `keygen_finish` through the [`WaitingHalf`] that
/// closes it, and the rounds after through the session over that half.
pub struct BirthPage {
    birth: Option<Keygen>,
    page: Option<Session<BirthConsent>>,
}

/// The holder's word for the one round being answered on a birth page: the
/// birth's crossings sign nothing and need none; a round asks the holder on
/// the page, as [`Consent`] requires.
#[derive(Debug, Default)]
pub struct BirthConsent(pub Option<bool>);

impl Consent for BirthConsent {
    fn approve(&mut self, _what: &Signing) -> bool {
        self.0.take().unwrap_or(false)
    }
}

impl BirthPage {
    /// An empty page: no birth open, no half held.
    #[must_use]
    pub fn new() -> Self {
        Self {
            birth: None,
            page: None,
        }
    }

    /// Whether the birth still waits for the container's answer.
    #[must_use]
    pub fn is_pending(&self) -> bool {
        self.birth.as_ref().is_some_and(Keygen::is_pending)
    }

    /// Sets the holder's word for the next round line answered. Spent by
    /// the answer, as the page's consent is.
    pub fn set_word(&mut self, approved: bool) {
        if let Some(page) = self.page.as_mut() {
            *page.consent_mut() = BirthConsent(Some(approved));
        }
    }

    /// One line in, one line out: a birth line while the birth is open, a
    /// round line once the finish returned the half. A round line before the
    /// finish is refused — the half does not exist yet. A birth line after
    /// the finish is refused — the birth is spent, not repeated.
    pub fn answer_line<R: RngCore + CryptoRng>(&mut self, line: &str, rng: &mut R) -> String {
        match serde_json::from_str::<Request>(line) {
            Err(_) => json_err(&MobileError::Wire("the request is not one".into())),
            Ok(Request::KeygenStart { .. }) => {
                if self.page.is_some() {
                    return json_err(&MobileError::Wire("the birth is spent".into()));
                }
                handle_birth_line(&mut self.birth, line, rng)
            }
            Ok(Request::KeygenFinish { .. }) => {
                if self.page.is_some() {
                    return json_err(&MobileError::Wire("the birth is spent".into()));
                }
                // The finish's answer carries the share the reader's
                // `FinishBirth` presses with — and the waiting half answers
                // `into_session` on the page's bindings, which move it onto
                // the rounds here through `keep_waiting`.
                let out = handle_birth_line(&mut self.birth, line, rng);
                if serde_json::from_str::<Answer>(&out).is_ok() {
                    self.birth.take();
                }
                out
            }
            Ok(Request::Commit | Request::Respond { .. }) => match self.page.as_mut() {
                Some(page) => handle_line(page, line, rng),
                None => json_err(&MobileError::Wire("the half is not born yet".into())),
            },
        }
    }

    /// Keeps the half a closed birth returned, for the rounds that follow.
    /// The page's bindings call this with the [`WaitingHalf`] their
    /// `keygen_finish` closed the birth with — the birth on this page is
    /// already spent by the `finish` line above, and the share it answered
    /// with crossed to the reader's `FinishBirth`.
    pub fn keep_waiting(&mut self, waiting: WaitingHalf) {
        self.page = Some(waiting.into_session(BirthConsent(None)));
    }
}

impl Default for BirthPage {
    fn default() -> Self {
        Self::new()
    }
}
