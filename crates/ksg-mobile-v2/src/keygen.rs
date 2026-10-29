//! The mobile side of the birth: `keygen_start` opens it, `keygen_finish`
//! closes it, and the half waits in between.
//!
//! The birth is three messages (`ksg_container_v2::client_key`): the mobile
//! side's commitment, the container's answer (secret), the container's share
//! (secret). [`Keygen`] holds the mobile side between messages 1 and 3: its
//! secret never leaves it, and a second `finish` answers
//! [`KeygenError::NoBirth`] instead of reusing anything. What
//! [`Keygen::finish`] returns — [`WaitingHalf`] — is the mobile half before
//! the container's birth lands: it already signs the rounds that finish the
//! birth (through [`WaitingHalf::into_session`]) while the reader drives the
//! module's `FinishBirth`, and the reader stores it once the container is born.

use ksg_container_v2::client_key::{KeygenReply, MobileHalf, MobileKeygen};
use ksg_core_v2::crypto::sign::PublicKey;
use ksg_core_v2::doc::Uri;
use rand_core::{CryptoRng, RngCore};

use super::{Consent, Session};

/// Why the mobile birth did not move.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeygenError {
    /// No birth open: `finish` before `start`, or the same birth twice.
    NoBirth,
    /// The generator refused the start.
    Start(String),
    /// The container's answer does not read.
    Reply(String),
    /// The container's share does not match its commitment.
    Finish(String),
}

impl core::fmt::Display for KeygenError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoBirth => f.write_str("no birth open"),
            Self::Start(e) => write!(f, "the birth does not start: {e}"),
            Self::Reply(e) => write!(f, "the birth reply does not read: {e}"),
            Self::Finish(e) => write!(f, "the birth does not finish: {e}"),
        }
    }
}

impl std::error::Error for KeygenError {}

/// The mobile side's birth between `keygen_start` and `keygen_finish`.
///
/// Made by [`Keygen::start`], spent by [`Keygen::finish`]: the secret of
/// message 1 lives only here, in memory, and never crosses anywhere.
pub struct Keygen {
    keygen: Option<MobileKeygen>,
}

impl Keygen {
    /// Opens the birth: this side's commitment, as bytes for the container's
    /// `BeginBirth`. `kid` names the client's key for now — the `did:key` of
    /// the group key replaces it once both sides are done.
    ///
    /// # Errors
    ///
    /// [`KeygenError::Start`] when the generator refuses or the commitment
    /// does not encode.
    pub fn start<R: RngCore + CryptoRng>(
        kid: Uri,
        rng: &mut R,
    ) -> Result<(Self, Vec<u8>), KeygenError> {
        let (keygen, hello) =
            MobileKeygen::start(kid, rng).map_err(|e| KeygenError::Start(e.to_string()))?;
        let hello = hello
            .to_bytes()
            .map_err(|e| KeygenError::Start(e.to_string()))?;
        Ok((Self {
            keygen: Some(keygen),
        }, hello))
    }

    /// Whether the birth still waits for the container's answer.
    #[must_use]
    pub fn is_pending(&self) -> bool {
        self.keygen.is_some()
    }

    /// Closes the birth with the container's answer: keeps the mobile half
    /// and answers with the container's share. A second call answers
    /// [`KeygenError::NoBirth`] — the birth is spent, not repeated.
    ///
    /// # Errors
    ///
    /// [`KeygenError::NoBirth`] with no birth open; [`KeygenError::Reply`]
    /// for an answer that is not one; [`KeygenError::Finish`] when the share
    /// does not match the container's commitment.
    pub fn finish(&mut self, reply: &[u8]) -> Result<WaitingHalf, KeygenError> {
        let keygen = self.keygen.take().ok_or(KeygenError::NoBirth)?;
        let reply =
            KeygenReply::from_bytes(reply).map_err(|e| KeygenError::Reply(e.to_string()))?;
        let (half, group, fin) = keygen
            .finish(&reply)
            .map_err(|e| KeygenError::Finish(e.to_string()))?;
        let fin = fin
            .to_bytes()
            .map_err(|e| KeygenError::Finish(e.to_string()))?
            .to_vec();
        Ok(WaitingHalf { half, group, fin })
    }
}

/// The mobile half after `keygen_finish`, waiting for the container's birth
/// to land: it signs the rounds that finish the birth with, and is stored
/// once the container is born.
pub struct WaitingHalf {
    half: MobileHalf,
    group: PublicKey,
    fin: Vec<u8>,
}

impl WaitingHalf {
    /// The half, to sign the rounds that finish the birth with.
    #[must_use]
    pub fn half(&self) -> &MobileHalf {
        &self.half
    }

    /// The client's public key: what the module's `FinishBirth` names the
    /// `did:key` from.
    #[must_use]
    pub fn group(&self) -> &PublicKey {
        &self.group
    }

    /// The container's share, as bytes for the module's `FinishBirth`.
    /// Secret: the channel must be closed.
    #[must_use]
    pub fn finish_bytes(&self) -> &[u8] {
        &self.fin
    }

    /// The half as the signing session it becomes: the rounds after the
    /// birth are answered through it.
    #[must_use]
    pub fn into_session<C: Consent>(self, consent: C) -> Session<C> {
        Session::new(self.half, consent)
    }

    /// The half, to store once the container is born.
    #[must_use]
    pub fn into_half(self) -> MobileHalf {
        self.half
    }
}
