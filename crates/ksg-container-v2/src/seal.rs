//! The issuer's seal inside the container. `[decision]` 23.09, CT-47.
//!
//! # What the owner decided
//!
//! "The container puts the issuer's signature; it is inside the container."
//! And from the product description (`Keys_in_Gate_marketing.md` §9): the
//! issuer lays its secrets into the container when it is made, and after that
//! has no way to act on it. So:
//!
//! | When | Who | What |
//! |---|---|---|
//! | at printing | the issuer | lays a **seal key** into the container and **certifies** it: its own key signs "this seal belongs to this container" |
//! | afterwards | the container, by itself | signs with the seal — the issuer takes no part and sees nothing |
//! | at checking | anyone | verifies the certificate against the issuer's keys, then the signature against the seal |
//!
//! A seal is one container's: the certificate names the container's template
//! (`Container::template_id` — the issuer prints before the container's own
//! identifier is born at initiation, CH-5b), so a seal lifted into another
//! container certifies nothing there.
//!
//! `[inference]` What this rests on is the container's own wall (`Keys_in_Gate_marketing.md`
//! §6–§7): no way out for secrets, no outside influence on the automation.

use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{
    Ed25519Signer, KeySet, Profile, PublicKey, Signature, SignatureSet,
};
use ksg_core_v2::doc::Uri;
use ksg_core_v2::error::Invalid;

/// Separates a seal certificate from every other signed value.
const CERT_TAG: &[u8] = b"ksg:issuer-seal:v1";

/// The issuer's seal, laid into one container at printing.
pub struct IssuerSeal {
    signer: Ed25519Signer,
    certificate: Signature,
    /// The seed the seal key was made from, kept for the container's sealed
    /// storage only (item P-4) and wiped on drop. No accessor returns it.
    seed: zeroize::Zeroizing<[u8; 32]>,
}

// Written by hand: a seal key has no business in a log.
impl core::fmt::Debug for IssuerSeal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IssuerSeal")
            .field("kid", &self.signer.public().kid)
            .finish_non_exhaustive()
    }
}

/// What the issuer's certificate covers: this container — by its template
/// identifier, `Container::template_id` — and this seal.
#[must_use]
pub fn certificate_subject(container: &Hash, seal: &PublicKey) -> Hash {
    Hash::sha256_fields(&[
        CERT_TAG,
        container.as_bytes(),
        seal.kid.as_str().as_bytes(),
        seal.key.as_bytes(),
    ])
}

impl IssuerSeal {
    /// Lays a seal at printing: a seal key from the issuer's CSPRNG, certified
    /// by the issuer's own key for this container only.
    #[must_use]
    pub fn lay(container: &Hash, seal_kid: Uri, seed: [u8; 32], issuer: &Ed25519Signer) -> Self {
        let signer = Ed25519Signer::from_seed(seal_kid, seed);
        let subject = certificate_subject(container, &signer.public());
        let certificate = issuer.sign(subject.as_bytes());
        Self {
            signer,
            certificate,
            seed: zeroize::Zeroizing::new(seed),
        }
    }

    /// The seal's public half.
    #[must_use]
    pub fn public(&self) -> PublicKey {
        self.signer.public()
    }

    /// The issuer's certificate for it.
    #[must_use]
    pub const fn certificate(&self) -> &Signature {
        &self.certificate
    }

    /// The seal as bytes, for the container's sealed storage.
    pub(crate) fn state(&self) -> SealState {
        SealState {
            kid: self.signer.public().kid,
            seed: self.seed.to_vec(),
            certificate: self.certificate.clone(),
        }
    }

    /// The seal again, from sealed storage.
    pub(crate) fn from_state(s: &SealState) -> Option<Self> {
        let seed: [u8; 32] = s.seed.as_slice().try_into().ok()?;
        Some(Self {
            signer: Ed25519Signer::from_seed(s.kid.clone(), seed),
            certificate: s.certificate.clone(),
            seed: zeroize::Zeroizing::new(seed),
        })
    }

    /// Signs a digest. Only the container calls this.
    pub(crate) fn seal(&self, subject: &Hash) -> Signature {
        self.signer.sign(subject.as_bytes())
    }
}

/// Checks a sealed signature the way anyone outside can: the certificate
/// against the issuer's keys, then the signature against the seal.
///
/// # Errors
///
/// [`Invalid`] if the issuer did not certify this seal for this container, or
/// the seal did not sign `subject`.
pub fn verify_sealed(
    container: &Hash,
    seal: &PublicKey,
    certificate: &Signature,
    issuer_keys: &KeySet,
    subject: &Hash,
    signature: &Signature,
    profile: &Profile,
) -> Result<(), Invalid> {
    SignatureSet::new(vec![certificate.clone()]).verify(
        certificate_subject(container, seal).as_bytes(),
        issuer_keys,
        profile,
    )?;
    let seal_set: KeySet = [seal.clone()].into_iter().collect();
    SignatureSet::new(vec![signature.clone()]).verify(subject.as_bytes(), &seal_set, profile)
}

/// A seal as bytes — crate-private, for sealed storage only. The seed is wiped
/// when this value is dropped.
#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct SealState {
    kid: Uri,
    seed: Vec<u8>,
    certificate: Signature,
}

impl Drop for SealState {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.seed.zeroize();
    }
}
