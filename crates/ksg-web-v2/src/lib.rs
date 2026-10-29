//! # ksg-web-v2 — the client's mobile half in a browser
//!
//! The owner's word 01.10: the mobile half is not an app — a script the
//! browser runs. This crate is that script's core: `ksg-mobile-v2` compiled
//! to WebAssembly, with the browser's randomness, and the holder's consent
//! given on the page.
//!
//! # The round, step by step
//!
//! | Step | Who | What |
//! |---|---|---|
//! | 1 | reader | `ksg-remote-panel --mobile-web ADDR` holds the round's request and prints the page's address with a one-time token |
//! | 2 | page | asks the reader for the request (`GET /next`) |
//! | 3 | page | [`describe`]: what the round signs — digest, document type, length — shown to the holder |
//! | 4 | holder | yes or no |
//! | 5 | page | [`WebHalf::answer`] with that word, and sends the answer back (`POST /answer`) |
//!
//! A commitment needs no consent: it signs nothing. A share is made only
//! after a yes; a no closes the round with nothing signed.
//!
//! # The birth in the page
//!
//! The half the page signs with starts as a birth: [`keygen::WebBirth`]
//! opens it with the client's key name (`kid`), its hello goes to the
//! reader's `BeginBirth`, the container's answer closes it, and the half
//! signs the rounds that finish the birth while the container lands. The
//! same automaton as the phone's [`Keygen`][ksg_mobile_v2::Keygen] — the
//! birth's secret never leaves the page's memory, and a second `finish`
//! answers `NoBirth`.
//!
//! # What is not here
//!
//! * Secure storage of the half: the page reads the half from a file the
//!   holder picks and keeps it in memory only.
//! * Transport beyond the holder's own machine: the reader listens on the
//!   address it is given, plain HTTP; a phone on another machine needs TLS in
//!   front of it.

#![forbid(unsafe_code)]

pub mod backup;
pub mod keygen;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use ksg_container_v2::client_key::{MobileHalf, SigningRound};
use ksg_mobile_v2::{handle_line, Consent, Request, Session, Signing, WaitingHalf};
use rand_core::{CryptoRng, RngCore};
use wasm_bindgen::prelude::*;

/// The holder's word for the one round being answered: given on the page
/// before [`Web::answer`], spent by it. No word is a no.
#[derive(Debug, Default)]
pub struct Word(Option<bool>);

impl Consent for Word {
    fn approve(&mut self, _what: &Signing) -> bool {
        self.0.take().unwrap_or(false)
    }
}

/// What a request asks the holder to sign: `None` for a commitment (it signs
/// nothing) or for a line that is not a request.
#[must_use]
pub fn describe_request(line: &str) -> Option<Signing> {
    match serde_json::from_str::<Request>(line).ok()? {
        Request::Commit | Request::KeygenStart { .. } | Request::KeygenFinish { .. } => None,
        Request::Respond { round } => {
            let b = B64.decode(round).ok()?;
            let r = SigningRound::from_bytes(&b).ok()?;
            Some(Signing::of(r.message()))
        }
    }
}

/// The half and its open round — the pure core the page's bindings wrap.
pub struct Web {
    session: Session<Word>,
}

impl Web {
    /// The half from its bytes, as `ksg-remote-panel initiate` wrote it.
    ///
    /// # Errors
    ///
    /// The bytes are not a mobile half.
    pub fn from_half(bytes: &[u8]) -> Result<Self, String> {
        let half = MobileHalf::from_bytes(bytes).map_err(|e| format!("mobile half: {e}"))?;
        Ok(Self {
            session: Session::new(half, Word::default()),
        })
    }

    /// The waiting half from a closed birth: the half signs the rounds that
    /// finish the birth while the container lands. A commitment needs no
    /// word; a share asks the holder on the page.
    #[must_use]
    pub fn from_waiting(waiting: WaitingHalf) -> Self {
        Self {
            session: waiting.into_session(Word::default()),
        }
    }

    /// Answers one request line with the holder's word on it.
    pub fn answer<R: RngCore + CryptoRng>(
        &mut self,
        line: &str,
        approved: bool,
        rng: &mut R,
    ) -> String {
        *self.session.consent_mut() = Word(Some(approved));
        let out = handle_line(&mut self.session, line, rng);
        *self.session.consent_mut() = Word(None);
        out
    }
}

/// The half in the page.
#[wasm_bindgen]
pub struct WebHalf(Web);

impl From<Web> for WebHalf {
    fn from(web: Web) -> Self {
        Self(web)
    }
}

#[wasm_bindgen]
impl WebHalf {
    /// Reads the half from the file the holder picked.
    ///
    /// # Errors
    ///
    /// The bytes are not a mobile half.
    #[wasm_bindgen(constructor)]
    pub fn new(half: &[u8]) -> Result<WebHalf, String> {
        Web::from_half(half).map(WebHalf)
    }

    /// Answers the reader's request line; `approved` is the holder's word.
    pub fn answer(&mut self, line: &str, approved: bool) -> String {
        self.0.answer(line, approved, &mut rand_core::OsRng)
    }
}

/// What the request asks to sign, as JSON for the page — `null` when it
/// signs nothing.
#[wasm_bindgen]
#[must_use]
pub fn describe(line: &str) -> Option<String> {
    describe_request(line).and_then(|s| serde_json::to_string(&s).ok())
}
