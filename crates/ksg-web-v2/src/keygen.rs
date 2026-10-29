//! The browser's side of the birth: `start` opens it, `finish` closes it,
//! and the half waits in between.
//!
//! The same automaton as [`Keygen`][ksg_mobile_v2::Keygen] on the phone, over
//! the page's randomness (`crypto.getRandomValues`): the birth's secret never
//! leaves the [`WebBirth`], and [`WebBirth::finish`] spends it — a second
//! `finish` answers `NoBirth` instead of reusing anything. What `finish`
//! returns becomes the [`Web`][super::Web] the page signs the rounds with,
//! through [`Web::from_waiting`][super::Web::from_waiting], while the reader
//! drives the module's `FinishBirth`; the holder stores the half once the
//! container is born (the stored copy is track И17).

use ksg_core_v2::doc::Uri;
use ksg_mobile_v2::Keygen;
use wasm_bindgen::prelude::*;

use super::{Web, WebHalf};

/// The browser's birth between [`start`][WebBirth::start] and
/// [`finish`][WebBirth::finish]: the pure core the page's bindings wrap.
///
/// Made by `start`, spent by `finish`: the secret of message 1 lives only
/// here, in memory, and never crosses anywhere.
pub struct WebBirth {
    birth: Keygen,
}

impl WebBirth {
    /// Opens the birth for the client's key named `kid`: this side's
    /// commitment, as bytes for the container's `BeginBirth`, next to the
    /// birth that waits for the container's answer.
    ///
    /// # Errors
    ///
    /// The `kid` is not one, or the generator refuses.
    pub fn start(kid: &str) -> Result<(Self, Vec<u8>), String> {
        let kid = Uri::parse(kid).map_err(|e| format!("kid: {e}"))?;
        let (birth, hello) =
            Keygen::start(kid, &mut rand_core::OsRng).map_err(|e| e.to_string())?;
        Ok((Self { birth }, hello))
    }

    /// Whether the birth still waits for the container's answer.
    #[must_use]
    pub fn is_pending(&self) -> bool {
        self.birth.is_pending()
    }

    /// Closes the birth with the container's answer and returns the half as
    /// the session it signs the rounds with from now on. A second call
    /// answers `NoBirth` — the birth is spent, not repeated.
    ///
    /// # Errors
    ///
    /// `NoBirth` with no birth open; the container's answer when it is not
    /// one, or its share when it does not match the commitment.
    pub fn finish(&mut self, reply: &[u8]) -> Result<Web, String> {
        let waiting = self.birth.finish(reply).map_err(|e| e.to_string())?;
        Ok(Web::from_waiting(waiting))
    }
}

/// The birth in the page.
#[wasm_bindgen]
pub struct WebBirthJs {
    birth: WebBirth,
    hello: Vec<u8>,
}

#[wasm_bindgen]
impl WebBirthJs {
    /// Opens the birth for the client's key named `kid`.
    ///
    /// # Errors
    ///
    /// The `kid` is not one, or the generator refuses.
    #[wasm_bindgen(constructor)]
    pub fn start(kid: &str) -> Result<WebBirthJs, String> {
        let (birth, hello) = WebBirth::start(kid)?;
        Ok(Self { birth, hello })
    }

    /// This side's commitment, as bytes for the container's `BeginBirth`.
    /// Send it to the reader; it carries no secret.
    #[must_use]
    pub fn hello(&self) -> Vec<u8> {
        self.hello.clone()
    }

    /// Whether the birth still waits for the container's answer.
    #[must_use]
    pub fn is_pending(&self) -> bool {
        self.birth.is_pending()
    }

    /// Closes the birth with the container's answer and returns the half the
    /// page signs the rounds with from now on.
    ///
    /// # Errors
    ///
    /// `NoBirth` with no birth open, or the container's answer when it is
    /// not one.
    pub fn finish(&mut self, reply: &[u8]) -> Result<WebHalf, String> {
        self.birth.finish(reply).map(WebHalf::from)
    }
}
