//! Laying keys on by encrypting the layer, and blinding the previous links.
//! KS-8 K-8, F-7; plan §2.1 `layers.rs`.
//!
//! # The property to produce
//!
//! **F-7: each new layer closes its content from the previous one, and the
//! issuer is the blindest party there is.** Stated the way a test can hold it:
//! the key of level N does not read what level N+1 wrote.
//!
//! And its other half, which matters just as much: a later holder **can** read
//! what earlier ones wrote. Release data is not a secret from the client who
//! bought it; the client's work is a secret from the issuer who printed the
//! blank.
//!
//! # Why the obvious construction is wrong
//!
//! A hash chain of keys is the first thing that comes to mind and it runs the
//! wrong way. Derive `K[n+1] = H(K[n])` and holding an early key yields every
//! later one — the issuer reads everything, which is the exact opposite of F-7.
//! Reverse the derivation and handing the next key on becomes finding a preimage.
//!
//! So the keys are **not derived from one another at all**. Each level's key is
//! its own, and the mechanism is the **hand-over**: when a container passes to
//! the next holder, the current one wraps the keys it holds for that holder, who
//! then makes a fresh key of their own.
//!
//! | | |
//! |---|---|
//! | the new holder receives | every key up to and including the current level |
//! | the new holder makes | its own key, which nobody before it ever sees |
//!
//! The blinding is then not a rule anybody enforces. An earlier holder does not
//! read a later layer because it was never given that key and cannot compute it —
//! and the hand-over is one-directional because it is an act, not a derivation.
//!
//! # Encryption keys are separate from signing keys
//!
//! **A decision the specification did not make, recorded as one.** The parties
//! hold Ed25519 keys, which sign and do not encrypt. Three ways out, and the
//! choice matters:
//!
//! | | |
//! |---|---|
//! | a separate X25519 key per party | **chosen** |
//! | derive X25519 from the Ed25519 secret | rejected: reusing one secret across signing and key agreement is a well-known way to lose both, and the saving is one key per party |
//! | a symmetric secret passed out of band | rejected: it needs a channel the protocol does not have, and every hand-over would need one again |
//!
//! So a party's identity carries two keys — one to sign with, one to be sealed
//! to. Which is also why succession and rotation were worth building first: two
//! keys per party is twice as much to lose.
//!
//! # The key to be sealed to is a hybrid: X25519 and ML-KEM-768
//!
//! K-5 of the blocker register, P-16 of the plan of code changes, 22.09. A
//! container is meant to live for decades, and a hand-over recorded today can
//! be opened by whoever breaks X25519 later — "harvest now, decrypt later".
//! Signatures do not have that problem (a forged signature has to be made
//! *before* it is checked); encryption does, which is why the post-quantum
//! half lands here and not only in `sign.rs`.
//!
//! `[inference]` Decisions made here, each recorded as one:
//!
//! | | chosen | why |
//! |---|---|---|
//! | hybrid or ML-KEM alone | **hybrid**, both always | ML-KEM is young; a flaw in it must not cost more than X25519 already gives. Breaking the wrap takes breaking **both** |
//! | hybrid optional or mandatory | **mandatory**, no classical-only mode | a mode is a downgrade an attacker can ask for; before the first sale there are no old containers to stay compatible with |
//! | combiner | HKDF-SHA256 over `ss_mlkem ‖ ss_x25519`, salt binding the X25519 ephemeral, both recipient keys and the ML-KEM ciphertext | the shape of X-Wing (draft-connolly-cfrg-xwing-kem), expressed with the HKDF this file already uses; binding the ciphertext too costs one hash |
//! | where the randomness comes from | the caller's one 32-byte `ephemeral`, expanded under two labels | as everywhere here: the crates hold no RNG, so the vectors stay reproducible |
//!
//! Cost, named: a published [`SealTo`] grows from 32 bytes to 1 216, and every
//! [`Handover`] carries 1 088 more bytes of ML-KEM ciphertext.

use fips203::ml_kem_768;
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use zeroize::Zeroizing;

use crate::pack::Aead;
use ksg_core_v2::crypto::hash::Hash;

/// Separates a wrapping key from every other derived value in the protocol.
///
/// `v2` since K-5: the key now comes from the hybrid agreement, and a wrap made
/// under the old label must not open under the new derivation by accident.
const WRAP_INFO: &[u8] = b"ksg:layer-wrap:v2";

/// The label the nonce is expanded under (CT-03). Separate from [`WRAP_INFO`]
/// so that the key and the nonce cannot come out of the same expansion.
const NONCE_INFO: &[u8] = b"ksg:layer-nonce:v2";

/// Expands a party's 32-byte seed into its X25519 secret (K-5).
const SEED_X25519: &[u8] = b"ksg:layer-seed:x25519:v1";
/// Expands a party's 32-byte seed into the ML-KEM-768 key-generation seeds.
const SEED_MLKEM: &[u8] = b"ksg:layer-seed:mlkem768:v1";
/// Expands the caller's ephemeral into the X25519 ephemeral secret.
const EPH_X25519: &[u8] = b"ksg:layer-eph:x25519:v1";
/// Expands the caller's ephemeral into the ML-KEM encapsulation randomness.
const EPH_MLKEM: &[u8] = b"ksg:layer-eph:mlkem768:v1";

/// The labels of the classical suite ([`Suite::X25519`], `bare`): its own,
/// so that a wrap made without the post-quantum half never opens under the
/// hybrid derivation, nor the other way round.
const WRAP_INFO_X25519: &[u8] = b"ksg:layer-wrap:x25519:v1";
/// The nonce label of the classical suite; see [`WRAP_INFO_X25519`].
const NONCE_INFO_X25519: &[u8] = b"ksg:layer-nonce:x25519:v1";

/// Which agreement a hand-over is sealed under.
///
/// `[decision]` 07.10 (`Bare_v2_spec` §3): `bare` drops ML-KEM-768 — "for
/// personal needs it is not needed" — and keeps X25519. Every other class
/// stays hybrid (K-5).
///
/// `[inference]` The suite is **not** read from the hand-over. It is the
/// container's class that picks it, on both sides, so a sender cannot ask a
/// Pro or `light` recipient to open a classical wrap: the labels differ and
/// the derivation fails. That keeps the K-5 reason against a classical mode —
/// "a mode is a downgrade an attacker can ask for" — true for the classes the
/// mode is not for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suite {
    /// X25519 and ML-KEM-768, both always (K-5).
    Hybrid,
    /// X25519 alone: `bare` only (`[decision]` 07.10).
    X25519,
}

impl Suite {
    /// The suite a container of `class` seals its hand-overs under.
    #[must_use]
    pub const fn of(class: ksg_core_v2::doc::Class) -> Self {
        match class {
            ksg_core_v2::doc::Class::Bare => Self::X25519,
            _ => Self::Hybrid,
        }
    }
}

/// The length of an ML-KEM-768 encapsulation key, published in [`SealTo`].
pub const MLKEM_EK_LEN: usize = ml_kem_768::EK_LEN;
/// The length of an ML-KEM-768 ciphertext, carried in [`Handover`].
pub const MLKEM_CT_LEN: usize = ml_kem_768::CT_LEN;

/// A layer's key: the secret its content is sealed under.
///
/// `PartialEq` is written by hand below for the same reason `Debug` is: the
/// derived one compares byte by byte with an early exit (audit of 2026-09-13,
/// finding 8). `ZeroizeOnDrop` wipes the key when it goes out of scope, so it
/// does not survive in freed heap (same audit, finding 2).
#[derive(Clone, Eq, zeroize::ZeroizeOnDrop)]
pub struct LayerKey([u8; 32]);

impl LayerKey {
    /// A key from bytes the caller drew from a CSPRNG.
    ///
    /// Taken rather than generated, as everywhere in this codebase: where
    /// randomness comes from is the operator's decision, and **a key from
    /// anything but a cryptographic RNG makes every layer under it readable**.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The bytes, for handing to an AEAD.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// Debug is written by hand so that a layer key never lands in a log through a
// derived formatter. The same reason a password type prints stars.
impl core::fmt::Debug for LayerKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("LayerKey(..)")
    }
}

// Constant-time so that comparing a key with a candidate does not report, in
// timing, how many leading bytes agreed.
impl PartialEq for LayerKey {
    fn eq(&self, other: &Self) -> bool {
        let mut diff = 0u8;
        for (a, b) in self.0.iter().zip(other.0.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }
}

/// One level of the chain, by its position.
///
/// The numbering is the chain of KS-7 §7.2-sexies: 0 is the issuer, then the
/// distributor and the agents, and the client is last. Later reads earlier.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct Level(pub u8);

/// A party's encryption identity — separate from its signing key, deliberately.
///
/// Two public halves since K-5: X25519 and ML-KEM-768. A hand-over is sealed
/// to both at once, and opening it takes both secrets.
#[derive(Clone)]
pub struct SealTo {
    x25519: PublicKey,
    mlkem: [u8; MLKEM_EK_LEN],
}

impl SealTo {
    /// The public halves a hand-over seals to.
    ///
    /// # Errors
    ///
    /// [`LayerError::Malformed`] if `mlkem` is not a valid ML-KEM-768
    /// encapsulation key (FIPS 203 §7.2 input check).
    pub fn new(x25519: PublicKey, mlkem: [u8; MLKEM_EK_LEN]) -> Result<Self, LayerError> {
        ml_kem_768::EncapsKey::try_from_bytes(mlkem).map_err(|_| LayerError::Malformed)?;
        Ok(Self { x25519, mlkem })
    }

    /// The X25519 public half.
    #[must_use]
    pub const fn public(&self) -> &PublicKey {
        &self.x25519
    }

    /// The ML-KEM-768 encapsulation key.
    #[must_use]
    pub const fn mlkem(&self) -> &[u8; MLKEM_EK_LEN] {
        &self.mlkem
    }
}

impl core::fmt::Debug for SealTo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SealTo(..)")
    }
}

/// A party's secret half, for opening what was sealed to it.
///
/// Holds the X25519 secret and the 64-byte ML-KEM seed rather than the
/// 2 400-byte decapsulation key: the seed is what gets wiped on drop, and the
/// key is regenerated from it at the moment of opening.
pub struct OpenWith {
    x25519: StaticSecret,
    mlkem_seed: Zeroizing<[u8; 64]>,
}

impl OpenWith {
    /// From a 32-byte seed the caller drew from a CSPRNG.
    ///
    /// Both secrets are expanded from it under separate labels, so one seed
    /// is all a party has to keep — the shape of X-Wing's key generation.
    #[must_use]
    pub fn from_bytes(seed: [u8; 32]) -> Self {
        let seed = Zeroizing::new(seed);
        let hk = Hkdf::<Sha256>::new(None, seed.as_ref());
        let mut x = Zeroizing::new([0u8; 32]);
        hk.expand(SEED_X25519, x.as_mut())
            .expect("32 bytes is within HKDF-SHA256's output");
        let mut m = Zeroizing::new([0u8; 64]);
        hk.expand(SEED_MLKEM, m.as_mut())
            .expect("64 bytes is within HKDF-SHA256's output");
        Self {
            x25519: StaticSecret::from(*x),
            mlkem_seed: m,
        }
    }

    /// The ML-KEM key pair, regenerated from the seed.
    fn mlkem(&self) -> (ml_kem_768::EncapsKey, ml_kem_768::DecapsKey) {
        let mut d = [0u8; 32];
        let mut z = [0u8; 32];
        d.copy_from_slice(&self.mlkem_seed[..32]);
        z.copy_from_slice(&self.mlkem_seed[32..]);
        ml_kem_768::KG::keygen_from_seed(d, z)
    }

    /// The public halves, to be published as [`SealTo`].
    #[must_use]
    pub fn seal_to(&self) -> SealTo {
        SealTo {
            x25519: PublicKey::from(&self.x25519),
            mlkem: self.mlkem().0.into_bytes(),
        }
    }
}

impl core::fmt::Debug for OpenWith {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OpenWith(..)")
    }
}

/// The keys of every level up to one holder's own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held {
    /// Level and key, lowest first. Contiguous from 0 by construction.
    keys: Vec<(Level, LayerKey)>,
}

impl Held {
    /// The issuer's starting set: its own level and nothing else.
    #[must_use]
    pub fn first(key: LayerKey) -> Self {
        Self {
            keys: vec![(Level(0), key)],
        }
    }

    /// The highest level held — this holder's own.
    ///
    /// # Panics
    ///
    /// Never: a set always holds level 0.
    #[must_use]
    pub fn level(&self) -> Level {
        self.keys.last().expect("never empty").0
    }

    /// The key of a level, if this holder has it.
    ///
    /// `None` is the blinding, and it is the whole point: a holder asking for a
    /// level above its own gets nothing, because nothing was ever given.
    #[must_use]
    pub fn key(&self, level: Level) -> Option<&LayerKey> {
        self.keys.iter().find(|(l, _)| *l == level).map(|(_, k)| k)
    }

    /// Every level held, lowest first.
    #[must_use]
    pub fn levels(&self) -> Vec<Level> {
        self.keys.iter().map(|(l, _)| *l).collect()
    }

    /// Adds this holder's own fresh key after a hand-over.
    fn with_own(mut self, key: LayerKey) -> Self {
        // Saturating: the chain is bounded elsewhere, but the arithmetic must
        // not be the thing that fails (audit finding 20).
        let next = Level(self.level().0.saturating_add(1));
        self.keys.push((next, key));
        self
    }
}

/// What passes to the next holder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handover {
    /// The ephemeral X25519 public half, for the recipient to agree with.
    pub ephemeral: [u8; 32],
    /// The ML-KEM-768 ciphertext (K-5), for the recipient to decapsulate.
    pub kem: Vec<u8>,
    /// The nonce this hand-over was sealed under — **synthetic**, derived from
    /// the agreement together with a digest of what was sealed.
    ///
    /// `[decision] 2026-09-19` (CT-03). It travels rather than being fixed at zero,
    /// and it is not trusted on arrival: a tampered nonce simply fails to open,
    /// because the tag covers the same key agreement.
    pub nonce: [u8; 12],
    /// The wrapped keys.
    pub sealed: Vec<u8>,
    /// The highest level inside.
    pub up_to: Level,
}

/// What can go wrong at a hand-over.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LayerError {
    /// The wrapping or unwrapping failed: a wrong recipient, or tampering.
    #[error("the hand-over did not open: wrong recipient, or tampered with")]
    Sealed,
    /// The wrapped block does not parse as a set of keys.
    #[error("the hand-over does not parse")]
    Malformed,
    /// A hand-over claiming a level that does not follow the one held.
    #[error("a hand-over of level {got:?} does not follow level {held:?}")]
    OutOfOrder {
        /// What arrived.
        got: Level,
        /// What was expected.
        held: Level,
    },
}

/// Hands the container on: wraps what is held for the next holder.
///
/// The current holder's own key goes **with** the set, because the next holder
/// must be able to read this level. What the current holder does not get, and
/// cannot compute, is the next holder's fresh key.
///
/// # Errors
///
/// [`LayerError::Sealed`] if the wrap fails.
pub fn hand_over<A: Aead>(
    aead: &A,
    held: &Held,
    to: &SealTo,
    ephemeral: [u8; 32],
    aad: &[u8],
) -> Result<Handover, LayerError> {
    hand_over_in(Suite::Hybrid, aead, held, to, ephemeral, aad)
}

/// [`hand_over`] under a chosen [`Suite`]: [`Suite::X25519`] leaves the
/// ML-KEM ciphertext empty and binds no ML-KEM value (`bare`, `[decision]`
/// 07.10).
///
/// # Errors
///
/// As [`hand_over`].
pub fn hand_over_in<A: Aead>(
    suite: Suite,
    aead: &A,
    held: &Held,
    to: &SealTo,
    ephemeral: [u8; 32],
    aad: &[u8],
) -> Result<Handover, LayerError> {
    let (x_eph, m_eph) = split_ephemeral(ephemeral);
    let secret = StaticSecret::from(*x_eph);
    let public = PublicKey::from(&secret);
    let shared = secret.diffie_hellman(to.public());
    // X25519 has small-order points: a recipient who publishes one forces the
    // shared secret to all-zero, and with it the wrapping key — the same key for
    // every sender (security audit of 2026-09-13, finding 10b). The check is
    // cheap and the library does not make it for us.
    if !shared.was_contributory() {
        return Err(LayerError::Sealed);
    }
    // The post-quantum half (K-5). The encapsulation key was checked when the
    // `SealTo` was built; checking it again costs nothing and keeps this
    // function honest on its own.
    let (kem_ss, kem) = match suite {
        Suite::Hybrid => {
            let ek = ml_kem_768::EncapsKey::try_from_bytes(to.mlkem)
                .map_err(|_| LayerError::Malformed)?;
            let (ss, ct) = ek.encaps_from_seed(&m_eph);
            (
                Zeroizing::new(ss.into_bytes().to_vec()),
                ct.into_bytes().to_vec(),
            )
        }
        Suite::X25519 => (Zeroizing::new(Vec::new()), Vec::new()),
    };
    let ikm = combine(kem_ss.as_ref(), shared.as_bytes());
    let bind = Binding {
        suite,
        ephemeral: public.as_bytes(),
        recipient: to.public().as_bytes(),
        mlkem_ek: match suite {
            Suite::Hybrid => &to.mlkem,
            Suite::X25519 => &[],
        },
        mlkem_ct: &kem,
    };
    let key = wrap_key(&ikm, &bind);

    // Zeroizing: `plain` is every layer key at once in the clear — the single
    // widest exposure in this file (audit of 2026-09-13, finding 2).
    let mut plain = Zeroizing::new(Vec::with_capacity(held.keys.len() * 33));
    for (level, k) in &held.keys {
        plain.push(level.0);
        plain.extend_from_slice(k.as_bytes());
    }
    // The nonce is synthetic rather than fixed (CT-03): see `wrap_nonce`. The
    // caller is still asked to draw a fresh ephemeral, but a caller who does
    // not now loses far less than everything.
    let nonce = wrap_nonce(&ikm, &bind, &plain);
    let sealed = aead
        .seal(key.as_ref(), &nonce, aad, &plain)
        .map_err(|_| LayerError::Sealed)?;

    Ok(Handover {
        ephemeral: *public.as_bytes(),
        kem,
        nonce,
        sealed,
        up_to: held.level(),
    })
}

/// Takes delivery of a hand-over and adds this holder's own fresh key.
///
/// # Errors
///
/// [`LayerError::Sealed`] if it was not sealed to this holder,
/// [`LayerError::Malformed`] if it does not parse,
/// [`LayerError::OutOfOrder`] if the levels are not contiguous from 0.
pub fn receive<A: Aead>(
    aead: &A,
    handover: &Handover,
    with: &OpenWith,
    own: LayerKey,
    aad: &[u8],
) -> Result<Held, LayerError> {
    receive_in(Suite::Hybrid, aead, handover, with, own, aad)
}

/// [`receive`] under a chosen [`Suite`] — the one the container's class
/// names, never one the hand-over claims.
///
/// # Errors
///
/// As [`receive`]; [`LayerError::Malformed`] also for a classical hand-over
/// that carries an ML-KEM ciphertext.
pub fn receive_in<A: Aead>(
    suite: Suite,
    aead: &A,
    handover: &Handover,
    with: &OpenWith,
    own: LayerKey,
    aad: &[u8],
) -> Result<Held, LayerError> {
    let ephemeral = PublicKey::from(handover.ephemeral);
    let mine = with.seal_to();
    let shared = with.x25519.diffie_hellman(&ephemeral);
    // The same check on the opening side: a sender who put a small-order point
    // in `handover.ephemeral` would otherwise open under an all-zero key.
    if !shared.was_contributory() {
        return Err(LayerError::Sealed);
    }
    // ML-KEM decapsulation does not fail on a wrong ciphertext — it returns a
    // pseudorandom secret (implicit rejection, FIPS 203 §6.3) — so a tampered
    // `kem` surfaces below as an AEAD failure, which is exactly `Sealed`.
    let kem_ss = match suite {
        Suite::Hybrid => {
            let ct: [u8; MLKEM_CT_LEN] = handover
                .kem
                .as_slice()
                .try_into()
                .map_err(|_| LayerError::Malformed)?;
            let ct =
                ml_kem_768::CipherText::try_from_bytes(ct).map_err(|_| LayerError::Malformed)?;
            let (_, dk) = with.mlkem();
            Zeroizing::new(
                dk.try_decaps(&ct)
                    .map_err(|_| LayerError::Sealed)?
                    .into_bytes()
                    .to_vec(),
            )
        }
        Suite::X25519 if handover.kem.is_empty() => Zeroizing::new(Vec::new()),
        Suite::X25519 => return Err(LayerError::Malformed),
    };
    let ikm = combine(kem_ss.as_ref(), shared.as_bytes());
    let bind = Binding {
        suite,
        ephemeral: &handover.ephemeral,
        recipient: mine.public().as_bytes(),
        mlkem_ek: match suite {
            Suite::Hybrid => &mine.mlkem,
            Suite::X25519 => &[],
        },
        mlkem_ct: &handover.kem,
    };
    let key = wrap_key(&ikm, &bind);

    let plain = Zeroizing::new(
        aead.open(key.as_ref(), &handover.nonce, aad, &handover.sealed)
            .map_err(|_| LayerError::Sealed)?,
    );
    if plain.is_empty() || plain.len() % 33 != 0 {
        return Err(LayerError::Malformed);
    }

    let mut keys = Vec::with_capacity(plain.len() / 33);
    for (i, chunk) in plain.chunks_exact(33).enumerate() {
        let level = Level(chunk[0]);
        // Contiguity from 0 is checked rather than assumed: a set with a gap
        // would silently leave a layer unreadable to a holder entitled to it,
        // and the failure would surface much later as "the data is corrupt".
        let expected = Level(u8::try_from(i).map_err(|_| LayerError::Malformed)?);
        if level != expected {
            return Err(LayerError::OutOfOrder {
                got: level,
                held: expected,
            });
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(&chunk[1..]);
        keys.push((level, LayerKey::from_bytes(k)));
    }
    if keys.last().map(|(l, _)| *l) != Some(handover.up_to) {
        return Err(LayerError::OutOfOrder {
            got: handover.up_to,
            held: keys.last().map_or(Level(0), |(l, _)| *l),
        });
    }
    Ok(Held { keys }.with_own(own))
}

/// Splits the caller's one ephemeral into the X25519 secret and the ML-KEM
/// encapsulation randomness, under separate labels (K-5).
fn split_ephemeral(ephemeral: [u8; 32]) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let ephemeral = Zeroizing::new(ephemeral);
    let hk = Hkdf::<Sha256>::new(None, ephemeral.as_ref());
    let mut x = Zeroizing::new([0u8; 32]);
    let mut m = Zeroizing::new([0u8; 32]);
    hk.expand(EPH_X25519, x.as_mut())
        .expect("32 bytes is within HKDF-SHA256's output");
    hk.expand(EPH_MLKEM, m.as_mut())
        .expect("32 bytes is within HKDF-SHA256's output");
    (x, m)
}

/// The input keying material: both shared secrets, ML-KEM first (the order of
/// X-Wing). Breaking the wrap takes recovering **both**.
fn combine(mlkem: &[u8], x25519: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(mlkem.len() + x25519.len()));
    ikm.extend_from_slice(mlkem);
    ikm.extend_from_slice(x25519);
    ikm
}

/// Everything public a wrap is bound to.
struct Binding<'a> {
    suite: Suite,
    ephemeral: &'a [u8],
    recipient: &'a [u8],
    mlkem_ek: &'a [u8],
    mlkem_ct: &'a [u8],
}

/// The wrapping key, derived from the hybrid agreement.
///
/// Every public value goes into the salt so that a wrap cannot be replayed
/// between recipients: the same ephemeral sent to two parties derives two
/// different keys. Since K-5 that includes the recipient's ML-KEM key and the
/// ciphertext, so neither half can be swapped under the other.
fn wrap_key(ikm: &[u8], bind: &Binding<'_>) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    agreement(ikm, bind)
        .expand(
            match bind.suite {
                Suite::Hybrid => WRAP_INFO,
                Suite::X25519 => WRAP_INFO_X25519,
            },
            out.as_mut(),
        )
        .expect("32 bytes is within HKDF-SHA256's output");
    out
}

/// The nonce this hand-over is sealed under — **synthetic**, in the sense of
/// SIV: derived from the agreement *and* from a digest of the plaintext.
///
/// `[decision] 2026-09-19` (CT-03), and the reason it is not derived from the
/// ephemeral alone. The wrapping key is already a function of the ephemeral
/// and the recipient, so a nonce made of the same parts would repeat exactly
/// when the key repeats — the pair would still collide, and deriving it would
/// have bought nothing. Only the plaintext distinguishes two seals under a
/// reused ephemeral, so only the plaintext can separate their nonces.
///
/// What remains when an ephemeral is reused on the same recipient: sealing the
/// **same** keys twice gives the same bytes, which reveals that they are the
/// same and nothing else. Sealing **different** keys gives different nonces,
/// and the catastrophe — two messages under one (key, nonce) — does not happen.
fn wrap_nonce(ikm: &[u8], bind: &Binding<'_>, plain: &[u8]) -> [u8; 12] {
    let digest = Hash::sha256(plain);
    let label = match bind.suite {
        Suite::Hybrid => NONCE_INFO,
        Suite::X25519 => NONCE_INFO_X25519,
    };
    let mut info = Vec::with_capacity(label.len() + 32);
    info.extend_from_slice(label);
    info.extend_from_slice(digest.as_bytes());
    let mut out = [0u8; 12];
    agreement(ikm, bind)
        .expand(&info, &mut out)
        .expect("12 bytes is within HKDF-SHA256's output");
    out
}

/// The extract step both derivations share.
///
/// The salt is length-framed through `Hash::sha256_fields`, so that no two
/// different sets of public values can produce the same salt (the lesson of
/// audit finding 11, applied here from the start).
fn agreement(ikm: &[u8], bind: &Binding<'_>) -> Hkdf<Sha256> {
    let salt = Hash::sha256_fields(&[bind.ephemeral, bind.recipient, bind.mlkem_ek, bind.mlkem_ct]);
    Hkdf::<Sha256>::new(Some(salt.as_bytes()), ikm)
}

#[cfg(test)]
mod hybrid {
    //! K-5, held where the halves can be taken apart: an attacker who has one
    //! of the two secrets — X25519 broken by a quantum computer, or ML-KEM
    //! broken by a flaw nobody has found yet — still does not open the wrap.

    use super::*;
    use crate::ChaCha20Poly1305Aead;

    const AAD: &[u8] = b"container";

    fn sealed_to(victim: &OpenWith) -> Handover {
        let held = Held::first(LayerKey::from_bytes([10; 32]));
        hand_over(
            &ChaCha20Poly1305Aead,
            &held,
            &victim.seal_to(),
            [31; 32],
            AAD,
        )
        .expect("hand over")
    }

    fn with_halves(x_from: &OpenWith, mlkem_from: &OpenWith) -> OpenWith {
        OpenWith {
            x25519: x_from.x25519.clone(),
            mlkem_seed: mlkem_from.mlkem_seed.clone(),
        }
    }

    #[test]
    fn the_victim_opens_with_both_halves() {
        let victim = OpenWith::from_bytes([21; 32]);
        let h = sealed_to(&victim);
        receive(
            &ChaCha20Poly1305Aead,
            &h,
            &victim,
            LayerKey::from_bytes([11; 32]),
            AAD,
        )
        .expect("the rightful recipient opens");
    }

    #[test]
    fn the_x25519_secret_alone_does_not_open() {
        // "Harvest now, decrypt later": X25519 has fallen, ML-KEM has not.
        let victim = OpenWith::from_bytes([21; 32]);
        let h = sealed_to(&victim);
        let attacker = with_halves(&victim, &OpenWith::from_bytes([99; 32]));
        assert_eq!(
            receive(
                &ChaCha20Poly1305Aead,
                &h,
                &attacker,
                LayerKey::from_bytes([11; 32]),
                AAD
            )
            .expect_err("opened with the classical half alone"),
            LayerError::Sealed
        );
    }

    #[test]
    fn the_mlkem_secret_alone_does_not_open() {
        // The other way round: a flaw in ML-KEM costs nothing X25519 still holds.
        let victim = OpenWith::from_bytes([21; 32]);
        let h = sealed_to(&victim);
        let attacker = with_halves(&OpenWith::from_bytes([99; 32]), &victim);
        assert_eq!(
            receive(
                &ChaCha20Poly1305Aead,
                &h,
                &attacker,
                LayerKey::from_bytes([11; 32]),
                AAD
            )
            .expect_err("opened with the post-quantum half alone"),
            LayerError::Sealed
        );
    }

    #[test]
    fn the_two_secrets_of_a_party_are_independent() {
        // One seed, two labels: the X25519 secret is not the seed itself, and
        // the ML-KEM seed does not contain it.
        let p = OpenWith::from_bytes([21; 32]);
        assert_ne!(p.x25519.to_bytes(), [21; 32]);
        assert_ne!(&p.mlkem_seed[..32], &p.x25519.to_bytes()[..]);
    }
}
