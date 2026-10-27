//! The client's working key in two halves. `[decision]` 23.09,
//! `Nekloniruemost_i_klyuchi.md` §3.3-bis; born at the container's initiation
//! (KS-8 E-4, CH-5b — `[doc:CLIENT-KEY-INIT]`).
//!
//! # What the owner decided
//!
//! "A whole working key may exist only until it is applied — until the first
//! signature. Then one part, once inside the container, is integrated into it
//! and becomes non-extractable; the other part stays with the client (the
//! agent). When it needs to sign, it uses its mobile part with the container's
//! reader, at one of the three buttons."
//!
//! # How
//!
//! | Part | Where | What it is |
//! |---|---|---|
//! | the whole key | **nowhere**: born by distributed key generation ([`MobileKeygen`], [`ContainerKeygen`]) | never in one memory |
//! | the container's half | [`ContainerHalf`], laid into the container | a FROST share; no accessor returns it |
//! | the mobile half | [`MobileHalf`], with the client | a FROST share; alone it signs nothing |
//!
//! FROST over Ed25519 (RFC 9591), threshold two of two: a signature comes out
//! only when both halves take part, and what comes out is an **ordinary
//! Ed25519 signature** under an ordinary public key. Nothing that verifies —
//! the core, the vectors, a third party — changes.
//!
//! The post-quantum key is not the client's: it is the container's own
//! (`crate::pq_key`), made at printing, and signs only the container's file.
//!
//! # Birth of the key — three messages
//!
//! 1. the mobile side starts ([`MobileKeygen::start`]) and sends its
//!    commitment ([`KeygenHello`]);
//! 2. the container answers ([`ContainerKeygen::answer`]) with its own
//!    commitment and the mobile side's share ([`KeygenReply`] — **secret**);
//! 3. the mobile side checks it, keeps its half and sends the container's share
//!    ([`MobileKeygen::finish`], [`KeygenFinish`] — **secret**); the container
//!    checks it and keeps its half ([`ContainerKeygen::finish`]).
//!
//! Each side verifies the other's share against its commitment. Messages 2
//! and 3 carry shares: the channel between the two must be closed.
//!
//! A hand-off's new key is born the same way
//! (`Container::begin_handoff_birth`). [`split`] — a dealer that makes the
//! whole key and splits it at once — remains for test stands and
//! `Container::stage_handoff`: `[decision]` 23.09 allows a whole key until its
//! first use.
//!
//! # The round at the reader
//!
//! 1. the client commits ([`MobileHalf::commit`]) and presents the commitment;
//! 2. the container commits too and answers with the signing package
//!    ([`crate::container::Container::begin_signing`]);
//! 3. the client signs its share of that package ([`MobileHalf::respond`]);
//! 4. the container adds its share, aggregates and checks the result against
//!    the client's public key ([`crate::container::Container::finish_signing`]).
//!
//! Randomness is the caller's, as everywhere in this codebase.

use std::collections::BTreeMap;

use frost_ed25519 as frost;
use frost_ed25519::rand_core::{CryptoRng, RngCore};
use ksg_core_v2::crypto::sign::{Alg, PublicKey, Signature};
use ksg_core_v2::doc::Uri;

/// Why the two halves did not produce a signature.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClientKeyError {
    /// The threshold scheme refused (a malformed share or commitment, a share
    /// that does not verify against its half).
    #[error("the two halves did not combine: {0}")]
    Frost(String),
    /// A share arrived with no round open.
    #[error("no signing round is open")]
    NoRound,
    /// The container already holds a half: a key is integrated once.
    #[error("the container already holds the client's half")]
    AlreadyIntegrated,
    /// The half belongs to another key than the one the container was born for.
    #[error("the half is not of the client key this container was born for")]
    OtherKey,
    /// The container holds no half, so it cannot take part.
    #[error("the container holds no half of the client's key")]
    NoHalf,
}

fn frost_err(e: frost::Error) -> ClientKeyError {
    ClientKeyError::Frost(e.to_string())
}

fn b64(bytes: &[u8]) -> String {
    ksg_core_v2::crypto::sign::b64_encode(bytes)
}

/// The container's half of the client's key.
///
/// Neither `Clone` nor readable: no method returns the share. It is handed to
/// the container once and lives there.
pub struct ContainerHalf {
    package: frost::keys::KeyPackage,
    group: frost::keys::PublicKeyPackage,
    public: PublicKey,
}

impl core::fmt::Debug for ContainerHalf {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ContainerHalf")
            .field("kid", &self.public.kid)
            .finish_non_exhaustive()
    }
}

impl ContainerHalf {
    /// The client's public key — the one both halves sign under.
    #[must_use]
    pub const fn public(&self) -> &PublicKey {
        &self.public
    }
}

/// The client's mobile half. Alone it signs nothing.
pub struct MobileHalf {
    package: frost::keys::KeyPackage,
    kid: Uri,
}

impl core::fmt::Debug for MobileHalf {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MobileHalf(kid={})", self.kid)
    }
}

/// The client's nonces for one round. Used once: [`MobileHalf::respond`] takes
/// them by value.
pub struct MobileNonces(frost::round1::SigningNonces);

impl core::fmt::Debug for MobileNonces {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MobileNonces(..)")
    }
}

/// What the client presents at the reader to open a round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commitment(pub(crate) frost::round1::SigningCommitments);

/// What the container answers: the package both halves sign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningRound(pub(crate) frost::SigningPackage);

/// The client's share of a round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MobileShare(pub(crate) frost::round2::SignatureShare);

impl MobileHalf {
    /// Opens a round on the client's side.
    pub fn commit<R: RngCore + CryptoRng>(&self, rng: &mut R) -> (MobileNonces, Commitment) {
        let (nonces, commitments) = frost::round1::commit(self.package.signing_share(), rng);
        (MobileNonces(nonces), Commitment(commitments))
    }

    /// The client's share of the package the container answered with.
    ///
    /// # Errors
    ///
    /// [`ClientKeyError::Frost`] when the package does not carry this half's
    /// commitment.
    pub fn respond(
        &self,
        nonces: MobileNonces,
        round: &SigningRound,
    ) -> Result<MobileShare, ClientKeyError> {
        frost::round2::sign(&round.0, &nonces.0, &self.package)
            .map(MobileShare)
            .map_err(frost_err)
    }
}

/// A dealer's key: made whole and split at once — two halves come out, the
/// whole key does not leave this function. For test stands; a client's key
/// in use is born without a dealer (module docs).
///
/// `kid` names the client's key. Randomness must come from a CSPRNG.
///
/// # Errors
///
/// [`ClientKeyError::Frost`] if the generator refuses — not expected with a
/// working RNG.
pub fn split<R: RngCore + CryptoRng>(
    kid: Uri,
    rng: &mut R,
) -> Result<(ContainerHalf, MobileHalf), ClientKeyError> {
    let (shares, group) =
        frost::keys::generate_with_dealer(2, 2, frost::keys::IdentifierList::Default, &mut *rng)
            .map_err(frost_err)?;
    let mut packages = shares
        .into_values()
        .map(frost::keys::KeyPackage::try_from)
        .collect::<Result<Vec<_>, _>>()
        .map_err(frost_err)?;
    let (Some(mobile), Some(inside)) = (packages.pop(), packages.pop()) else {
        return Err(ClientKeyError::Frost("two shares expected".into()));
    };
    let public = public_of(&kid, &group)?;
    Ok((
        ContainerHalf {
            package: inside,
            group,
            public,
        },
        MobileHalf {
            package: mobile,
            kid,
        },
    ))
}

/// The client's public key as the core names it.
fn public_of(
    kid: &Uri,
    group: &frost::keys::PublicKeyPackage,
) -> Result<PublicKey, ClientKeyError> {
    let vk = group.verifying_key().serialize().map_err(frost_err)?;
    Ok(PublicKey {
        kid: kid.clone(),
        alg: Alg::Ed25519,
        key: b64(&vk),
    })
}

// ---------------------------------------------------------------------------
// The birth of the key: distributed generation, two of two (CH-5b). The whole
// key is never computed: each side ends with its own share and the common
// public key, and checks the other's share against its commitment.
// ---------------------------------------------------------------------------

/// The container's identifier among the two signers; the mobile side's is
/// [`MOBILE_SIGNER`]. The dealer of [`split`] numbers them the same way.
const CONTAINER_SIGNER: u16 = 1;
/// The mobile side's identifier among the two signers.
const MOBILE_SIGNER: u16 = 2;

fn signer(n: u16) -> Result<frost::Identifier, ClientKeyError> {
    frost::Identifier::try_from(n).map_err(frost_err)
}

/// Message 1, mobile → container: the mobile side's commitment. Public.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeygenHello(frost::keys::dkg::round1::Package);

/// Message 2, container → mobile: the container's commitment and the mobile
/// side's share. **Secret** — the channel must be closed.
pub struct KeygenReply {
    commitment: frost::keys::dkg::round1::Package,
    share: frost::keys::dkg::round2::Package,
}

/// Message 3, mobile → container: the container's share. **Secret.**
pub struct KeygenFinish(frost::keys::dkg::round2::Package);

impl core::fmt::Debug for KeygenReply {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("KeygenReply(..)")
    }
}

impl core::fmt::Debug for KeygenFinish {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("KeygenFinish(..)")
    }
}

/// The mobile side between messages 1 and 3. Its secret never leaves it.
pub struct MobileKeygen {
    kid: Uri,
    secret: frost::keys::dkg::round1::SecretPackage,
}

impl core::fmt::Debug for MobileKeygen {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MobileKeygen(kid={})", self.kid)
    }
}

impl MobileKeygen {
    /// Step 1 on the client's side: a fresh secret and its commitment.
    /// `kid` names the client's key.
    ///
    /// # Errors
    ///
    /// [`ClientKeyError::Frost`] if the generator refuses.
    pub fn start<R: RngCore + CryptoRng>(
        kid: Uri,
        rng: &mut R,
    ) -> Result<(Self, KeygenHello), ClientKeyError> {
        let (secret, hello) =
            frost::keys::dkg::part1(signer(MOBILE_SIGNER)?, 2, 2, &mut *rng).map_err(frost_err)?;
        Ok((Self { kid, secret }, KeygenHello(hello)))
    }

    /// Step 3 on the client's side: checks the container's share, keeps its
    /// half and answers with the container's share. Also returns the client's
    /// public key — the client sees which key it now holds half of.
    ///
    /// # Errors
    ///
    /// [`ClientKeyError::Frost`] when the share does not match the
    /// container's commitment.
    pub fn finish(
        self,
        reply: &KeygenReply,
    ) -> Result<(MobileHalf, PublicKey, KeygenFinish), ClientKeyError> {
        let container = signer(CONTAINER_SIGNER)?;
        let r1 = BTreeMap::from([(container, reply.commitment.clone())]);
        let (secret, mut out) = frost::keys::dkg::part2(self.secret, &r1).map_err(frost_err)?;
        let theirs = out
            .remove(&container)
            .ok_or_else(|| ClientKeyError::Frost("no share for the container".into()))?;
        let r2 = BTreeMap::from([(container, reply.share.clone())]);
        let (package, group) = frost::keys::dkg::part3(&secret, &r1, &r2).map_err(frost_err)?;
        let public = public_of(&self.kid, &group)?;
        Ok((
            MobileHalf {
                package,
                kid: self.kid,
            },
            public,
            KeygenFinish(theirs),
        ))
    }
}

/// The container's side between messages 2 and 3.
pub struct ContainerKeygen {
    kid: Uri,
    secret: frost::keys::dkg::round2::SecretPackage,
    hello: BTreeMap<frost::Identifier, frost::keys::dkg::round1::Package>,
}

impl core::fmt::Debug for ContainerKeygen {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ContainerKeygen(kid={})", self.kid)
    }
}

impl ContainerKeygen {
    /// Step 2 inside the container: its own secret, its commitment, and the
    /// mobile side's share of it.
    ///
    /// # Errors
    ///
    /// [`ClientKeyError::Frost`] for a commitment that is not one.
    pub fn answer<R: RngCore + CryptoRng>(
        kid: Uri,
        hello: &KeygenHello,
        rng: &mut R,
    ) -> Result<(Self, KeygenReply), ClientKeyError> {
        let mobile = signer(MOBILE_SIGNER)?;
        let (secret1, commitment) =
            frost::keys::dkg::part1(signer(CONTAINER_SIGNER)?, 2, 2, &mut *rng)
                .map_err(frost_err)?;
        let r1 = BTreeMap::from([(mobile, hello.0.clone())]);
        let (secret, mut out) = frost::keys::dkg::part2(secret1, &r1).map_err(frost_err)?;
        let share = out
            .remove(&mobile)
            .ok_or_else(|| ClientKeyError::Frost("no share for the mobile side".into()))?;
        Ok((
            Self {
                kid,
                secret,
                hello: r1,
            },
            KeygenReply { commitment, share },
        ))
    }

    /// Step 3 inside the container: checks the mobile side's share and keeps
    /// the container's half.
    ///
    /// # Errors
    ///
    /// [`ClientKeyError::Frost`] when the share does not match the mobile
    /// side's commitment.
    pub fn finish(self, fin: &KeygenFinish) -> Result<ContainerHalf, ClientKeyError> {
        let r2 = BTreeMap::from([(signer(MOBILE_SIGNER)?, fin.0.clone())]);
        let (package, group) =
            frost::keys::dkg::part3(&self.secret, &self.hello, &r2).map_err(frost_err)?;
        let public = public_of(&self.kid, &group)?;
        Ok(ContainerHalf {
            package,
            group,
            public,
        })
    }
}

/// Two byte strings, each prefixed with its length (u32, big-endian).
fn two(a: &[u8], b: &[u8]) -> zeroize::Zeroizing<Vec<u8>> {
    let mut out = Vec::with_capacity(8 + a.len() + b.len());
    for part in [a, b] {
        out.extend_from_slice(&u32::try_from(part.len()).unwrap_or(u32::MAX).to_be_bytes());
        out.extend_from_slice(part);
    }
    zeroize::Zeroizing::new(out)
}

fn parts(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let take = |b: &'_ [u8]| -> Option<(usize, usize)> {
        let n = u32::from_be_bytes(b.get(..4)?.try_into().ok()?);
        Some((4, usize::try_from(n).ok()?))
    };
    let (h, n) = take(bytes)?;
    let a = bytes.get(h..h + n)?;
    let rest = bytes.get(h + n..)?;
    let (h2, n2) = take(rest)?;
    let b = rest.get(h2..h2 + n2)?;
    (rest.len() == h2 + n2).then_some((a, b))
}

impl KeygenHello {
    /// As bytes, for the wire.
    ///
    /// # Errors
    ///
    /// [`ClientKeyError::Frost`] if it does not serialize.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ClientKeyError> {
        self.0.serialize().map_err(frost_err)
    }

    /// From the wire.
    ///
    /// # Errors
    ///
    /// [`ClientKeyError::Frost`] for bytes that are not one.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ClientKeyError> {
        frost::keys::dkg::round1::Package::deserialize(bytes)
            .map(Self)
            .map_err(frost_err)
    }
}

impl KeygenReply {
    /// As bytes, for a closed channel. Wiped when dropped.
    ///
    /// # Errors
    ///
    /// [`ClientKeyError::Frost`] if it does not serialize.
    pub fn to_bytes(&self) -> Result<zeroize::Zeroizing<Vec<u8>>, ClientKeyError> {
        let share = zeroize::Zeroizing::new(self.share.serialize().map_err(frost_err)?);
        Ok(two(
            &self.commitment.serialize().map_err(frost_err)?,
            &share,
        ))
    }

    /// From the wire.
    ///
    /// # Errors
    ///
    /// [`ClientKeyError::Frost`] for bytes that are not one.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ClientKeyError> {
        let (c, s) = parts(bytes).ok_or_else(|| ClientKeyError::Frost("not a reply".into()))?;
        Ok(Self {
            commitment: frost::keys::dkg::round1::Package::deserialize(c).map_err(frost_err)?,
            share: frost::keys::dkg::round2::Package::deserialize(s).map_err(frost_err)?,
        })
    }
}

impl KeygenFinish {
    /// As bytes, for a closed channel. Wiped when dropped.
    ///
    /// # Errors
    ///
    /// [`ClientKeyError::Frost`] if it does not serialize.
    pub fn to_bytes(&self) -> Result<zeroize::Zeroizing<Vec<u8>>, ClientKeyError> {
        self.0
            .serialize()
            .map(zeroize::Zeroizing::new)
            .map_err(frost_err)
    }

    /// From the wire.
    ///
    /// # Errors
    ///
    /// [`ClientKeyError::Frost`] for bytes that are not one.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ClientKeyError> {
        frost::keys::dkg::round2::Package::deserialize(bytes)
            .map(Self)
            .map_err(frost_err)
    }
}

/// The container's side of an open round.
pub(crate) struct Open {
    nonces: frost::round1::SigningNonces,
    package: frost::SigningPackage,
}

impl core::fmt::Debug for Open {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Open(..)")
    }
}

impl ContainerHalf {
    /// Step 2: commit and answer with the package.
    pub(crate) fn begin<R: RngCore + CryptoRng>(
        &self,
        msg: &[u8],
        client: &Commitment,
        rng: &mut R,
    ) -> (Open, SigningRound) {
        let (nonces, mine) = frost::round1::commit(self.package.signing_share(), rng);
        let mut all = BTreeMap::new();
        all.insert(*self.package.identifier(), mine);
        // The client's identifier is the other one of the two; the package
        // pairs each commitment with its signer.
        let theirs = self
            .group
            .verifying_shares()
            .keys()
            .find(|id| *id != self.package.identifier())
            .copied()
            .unwrap_or(*self.package.identifier());
        all.insert(theirs, client.0);
        let package = frost::SigningPackage::new(all, msg);
        (
            Open {
                nonces,
                package: package.clone(),
            },
            SigningRound(package),
        )
    }

    /// Step 4: add this half's share, aggregate, check.
    pub(crate) fn finish<R: RngCore + CryptoRng>(
        &self,
        open: Open,
        client: &MobileShare,
        rng: &mut R,
    ) -> Result<Vec<Signature>, ClientKeyError> {
        let mine =
            frost::round2::sign(&open.package, &open.nonces, &self.package).map_err(frost_err)?;
        let theirs = self
            .group
            .verifying_shares()
            .keys()
            .find(|id| *id != self.package.identifier())
            .copied()
            .ok_or_else(|| ClientKeyError::Frost("no second signer".into()))?;
        let mut shares = BTreeMap::new();
        shares.insert(*self.package.identifier(), mine);
        shares.insert(theirs, client.0);
        // `aggregate` verifies every share and the result: a bad client share
        // is refused here, not published.
        let sig = frost::aggregate(&open.package, &shares, &self.group).map_err(frost_err)?;
        let sig_bytes = sig.serialize().map_err(frost_err)?;

        // Ed25519 only: the post-quantum signature is the container's, on its
        // whole file, outside (`crate::store`, `[decision]` 02.10, CH-5a).
        let _ = rng;
        Ok(vec![Signature {
            kid: self.public.kid.clone(),
            alg: Alg::Ed25519,
            value: b64(&sig_bytes),
        }])
    }
}

/// The container's half as bytes — **only** for the container's own sealed
/// storage (item P-4 of the MVP plan), never returned to anyone else: the type
/// is crate-private and leaves this crate only inside a sealed blob.
///
/// FROST 3 serializes its key packages only under a feature this workspace
/// does not enable, so the parts go one by one, each with its own
/// `serialize`. The secret parts are wiped when this value is dropped.
#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct HalfState {
    id: Vec<u8>,
    signing_share: Vec<u8>,
    verifying_share: Vec<u8>,
    verifying_key: Vec<u8>,
    min_signers: u16,
    group: Vec<(Vec<u8>, Vec<u8>)>,
    group_key: Vec<u8>,
    group_min: Option<u16>,
    public: PublicKey,
}

impl HalfState {
    /// Wipes the secret parts: the signing share. What `Drop` does, named so
    /// that it can be checked (`unsafe` is forbidden here, so freed memory
    /// cannot be read back by a test).
    fn wipe(&mut self) {
        use zeroize::Zeroize as _;
        self.signing_share.zeroize();
    }
}

impl Drop for HalfState {
    fn drop(&mut self) {
        self.wipe();
    }
}

impl ContainerHalf {
    /// The half as bytes for sealed storage.
    pub(crate) fn state(&self) -> Result<HalfState, ClientKeyError> {
        let group = self
            .group
            .verifying_shares()
            .iter()
            .map(|(id, share)| Ok((id.serialize(), share.serialize().map_err(frost_err)?)))
            .collect::<Result<Vec<_>, ClientKeyError>>()?;
        Ok(HalfState {
            id: self.package.identifier().serialize(),
            signing_share: self.package.signing_share().serialize(),
            verifying_share: self
                .package
                .verifying_share()
                .serialize()
                .map_err(frost_err)?,
            verifying_key: self
                .package
                .verifying_key()
                .serialize()
                .map_err(frost_err)?,
            min_signers: *self.package.min_signers(),
            group,
            group_key: self.group.verifying_key().serialize().map_err(frost_err)?,
            group_min: self.group.min_signers(),
            public: self.public.clone(),
        })
    }

    /// The half again, from sealed storage.
    pub(crate) fn from_state(s: &HalfState) -> Result<Self, ClientKeyError> {
        let id = frost::Identifier::deserialize(&s.id).map_err(frost_err)?;
        let package = frost::keys::KeyPackage::new(
            id,
            frost::keys::SigningShare::deserialize(&s.signing_share).map_err(frost_err)?,
            frost::keys::VerifyingShare::deserialize(&s.verifying_share).map_err(frost_err)?,
            frost::VerifyingKey::deserialize(&s.verifying_key).map_err(frost_err)?,
            s.min_signers,
        );
        let mut shares = BTreeMap::new();
        for (i, v) in &s.group {
            shares.insert(
                frost::Identifier::deserialize(i).map_err(frost_err)?,
                frost::keys::VerifyingShare::deserialize(v).map_err(frost_err)?,
            );
        }
        let group = frost::keys::PublicKeyPackage::new(
            shares,
            frost::VerifyingKey::deserialize(&s.group_key).map_err(frost_err)?,
            s.group_min,
        );
        Ok(Self {
            package,
            group,
            public: s.public.clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// The round across processes — item P-5 of the MVP plan (`[decision]` 24.09,
// variant A): the mobile half lives in a process of its own, and what passes
// between it and the reader is these three messages as bytes. The nonces never
// leave the mobile process: `MobileNonces` has no serialization, on purpose.
// ---------------------------------------------------------------------------

impl Commitment {
    /// The commitment as bytes, for the wire.
    ///
    /// # Errors
    ///
    /// [`ClientKeyError::Frost`] if it does not serialize.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ClientKeyError> {
        self.0.serialize().map_err(frost_err)
    }

    /// A commitment from the wire.
    ///
    /// # Errors
    ///
    /// [`ClientKeyError::Frost`] for bytes that are not one.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ClientKeyError> {
        frost::round1::SigningCommitments::deserialize(bytes)
            .map(Self)
            .map_err(frost_err)
    }
}

impl SigningRound {
    /// The signing package as bytes, for the wire.
    ///
    /// # Errors
    ///
    /// [`ClientKeyError::Frost`] if it does not serialize.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ClientKeyError> {
        self.0.serialize().map_err(frost_err)
    }

    /// A signing package from the wire.
    ///
    /// # Errors
    ///
    /// [`ClientKeyError::Frost`] for bytes that are not one.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ClientKeyError> {
        frost::SigningPackage::deserialize(bytes)
            .map(Self)
            .map_err(frost_err)
    }

    /// The message this round signs — what the mobile side shows its holder
    /// before answering.
    #[must_use]
    pub fn message(&self) -> &[u8] {
        self.0.message()
    }
}

impl MobileShare {
    /// The share as bytes, for the wire.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.serialize()
    }

    /// A share from the wire.
    ///
    /// # Errors
    ///
    /// [`ClientKeyError::Frost`] for bytes that are not one.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ClientKeyError> {
        frost::round2::SignatureShare::deserialize(bytes)
            .map(Self)
            .map_err(frost_err)
    }
}

/// The tag a declaration of loss starts with (E-19, owner's decisions
/// 15.10): the mobile half signs it alone, with the container's template
/// identifier, the moment and the hash of the client's identifier.
pub const LOST_TAG: &[u8] = b"ksg:lost:v1";

/// The commitment to a mobile half's public share that goes on the chain at
/// initiation: `sha256("ksg:share:v1" ‖ share)`. The share itself stays off
/// the chain until the half declares its container lost.
#[must_use]
pub fn share_commitment(share: &[u8; 32]) -> [u8; 32] {
    use sha2::Digest as _;
    let mut h = sha2::Sha256::new();
    h.update(b"ksg:share:v1");
    h.update(share);
    h.finalize().into()
}

impl MobileHalf {
    /// The client's key this half is half of — its public part.
    ///
    /// # Errors
    ///
    /// [`ClientKeyError::Frost`] if it does not serialize.
    pub fn client_public(&self) -> Result<[u8; 32], ClientKeyError> {
        self.package
            .verifying_key()
            .serialize()
            .map_err(frost_err)?
            .try_into()
            .map_err(|_| ClientKeyError::Frost("a key that is not 32 bytes".into()))
    }

    /// The half's public share: its secret times the base point, compressed.
    /// It identifies the half without revealing anything of the whole key.
    ///
    /// # Errors
    ///
    /// [`ClientKeyError::Frost`] if it does not serialize.
    pub fn share_public(&self) -> Result<[u8; 32], ClientKeyError> {
        self.package
            .verifying_share()
            .serialize()
            .map_err(frost_err)?
            .try_into()
            .map_err(|_| ClientKeyError::Frost("a share that is not 32 bytes".into()))
    }

    /// Signs `msg` with this half **alone**: an ordinary Ed25519 signature
    /// under [`Self::share_public`] — not the client's key, which needs both
    /// halves. Used for one thing only: the declaration that the container
    /// is lost (E-19), when the other half is gone with it.
    ///
    /// # Errors
    ///
    /// [`ClientKeyError::Frost`] if the share does not read.
    pub fn sign_alone<R: RngCore + CryptoRng>(
        &self,
        msg: &[u8],
        rng: &mut R,
    ) -> Result<[u8; 64], ClientKeyError> {
        use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE as B;
        use curve25519_dalek::scalar::Scalar;
        use sha2::Digest as _;
        let bytes = zeroize::Zeroizing::new(self.package.signing_share().serialize());
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| ClientKeyError::Frost("a share that is not 32 bytes".into()))?;
        let x = Option::<Scalar>::from(Scalar::from_canonical_bytes(arr))
            .ok_or_else(|| ClientKeyError::Frost("a share that is not a scalar".into()))?;
        let a = self.share_public()?;
        let mut seed = zeroize::Zeroizing::new([0u8; 32]);
        rng.fill_bytes(seed.as_mut());
        let r = Scalar::from_hash(
            sha2::Sha512::new()
                .chain_update(seed.as_ref())
                .chain_update(msg),
        );
        let big_r = (&r * B).compress().to_bytes();
        let k = Scalar::from_hash(
            sha2::Sha512::new()
                .chain_update(big_r)
                .chain_update(a)
                .chain_update(msg),
        );
        let s = r + k * x;
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&big_r);
        sig[32..].copy_from_slice(s.as_bytes());
        Ok(sig)
    }
}

impl MobileHalf {
    /// The mobile half as bytes — for the client to keep, wherever it keeps
    /// it. It is the client's own half; alone it signs nothing.
    ///
    /// # Errors
    ///
    /// [`ClientKeyError::Frost`] if it does not serialize.
    pub fn to_bytes(&self) -> Result<zeroize::Zeroizing<Vec<u8>>, ClientKeyError> {
        let package = zeroize::Zeroizing::new(self.package.serialize().map_err(frost_err)?);
        let kid = self.kid.as_str().as_bytes();
        let mut out = Vec::with_capacity(4 + kid.len() + package.len());
        out.extend_from_slice(&u32::try_from(kid.len()).unwrap_or(u32::MAX).to_be_bytes());
        out.extend_from_slice(kid);
        out.extend_from_slice(&package);
        Ok(zeroize::Zeroizing::new(out))
    }

    /// The mobile half from its bytes.
    ///
    /// # Errors
    ///
    /// [`ClientKeyError::Frost`] for bytes that are not one.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ClientKeyError> {
        let bad = || ClientKeyError::Frost("not a mobile half".into());
        let len_bytes: [u8; 4] = bytes
            .get(..4)
            .ok_or_else(bad)?
            .try_into()
            .map_err(|_| bad())?;
        let len = usize::try_from(u32::from_be_bytes(len_bytes)).map_err(|_| bad())?;
        let kid = bytes.get(4..4 + len).ok_or_else(bad)?;
        let kid = Uri::parse(core::str::from_utf8(kid).map_err(|_| bad())?).map_err(|_| bad())?;
        let package = frost::keys::KeyPackage::deserialize(bytes.get(4 + len..).ok_or_else(bad)?)
            .map_err(frost_err)?;
        Ok(Self { package, kid })
    }

    /// The client's key identifier this half belongs to.
    #[must_use]
    pub const fn kid(&self) -> &Uri {
        &self.kid
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use sha2::Digest as _;

    /// A deterministic generator for this test only: SHA-256 over a counter.
    struct TestRng(u64);
    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            let mut b = [0u8; 4];
            self.fill_bytes(&mut b);
            u32::from_le_bytes(b)
        }
        fn next_u64(&mut self) -> u64 {
            let mut b = [0u8; 8];
            self.fill_bytes(&mut b);
            u64::from_le_bytes(b)
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(32) {
                self.0 += 1;
                let block = sha2::Sha256::digest(self.0.to_be_bytes());
                chunk.copy_from_slice(&block[..chunk.len()]);
            }
        }
        fn try_fill_bytes(
            &mut self,
            dest: &mut [u8],
        ) -> Result<(), frost_ed25519::rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }
    impl CryptoRng for TestRng {}

    /// The test generator gives one stream whichever way it is drawn from:
    /// the tests that use it are reproducible only if every draw is the same
    /// counter's output.
    #[test]
    fn the_test_generator_gives_one_stream_through_every_draw() {
        let mut bytes = [0u8; 8];
        TestRng(9).fill_bytes(&mut bytes);
        let mut word = [0u8; 4];
        word.copy_from_slice(&bytes[..4]);
        assert_eq!(TestRng(9).next_u32(), u32::from_le_bytes(word));
        assert_eq!(TestRng(9).next_u64(), u64::from_le_bytes(bytes));
        let mut tried = [0u8; 8];
        TestRng(9).try_fill_bytes(&mut tried).expect("never fails");
        assert_eq!(tried, bytes);
    }

    /// One-time secrets (KS-7 §13): wiping leaves no byte of the signing
    /// share, and the share was not empty to begin with.
    #[test]
    fn wiping_the_state_leaves_no_byte_of_the_share() {
        let kid = Uri::parse("did:key:zClient#key-1".to_owned()).expect("uri");
        let mut rng = TestRng(1);
        let (inside, mobile) = split(kid, &mut rng).expect("split");
        let mut st = inside.state().expect("state");
        assert!(st.signing_share.iter().any(|b| *b != 0));
        st.wipe();
        // `zeroize` writes zeros over the bytes, then clears the vector and
        // zeroes its whole capacity: what is left is no share at all, which
        // is stricter than a share of zeros (an `all` over it would hold
        // vacuously and check nothing).
        assert!(st.signing_share.is_empty());

        // The container's side of a round prints nothing of its nonces.
        let (_, commitment) = mobile.commit(&mut rng);
        let (open, _) = inside.begin(b"m", &commitment, &mut rng);
        assert_eq!(format!("{open:?}"), "Open(..)");
    }
}
