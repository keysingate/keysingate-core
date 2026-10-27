//! The container's own post-quantum key (`[decision]` 02.10, CH-5a; CH-5b,
//! `[doc:CLIENT-KEY-INIT]` §2.3).
//!
//! Made inside the container at printing, from the system's randomness; the
//! issuer vouches for it there ([`crate::store::pq_cert_message`]) and it never
//! changes afterwards — a hand-off to another agent moves the client's key,
//! not this one. It signs one thing: the container's whole file, outside
//! (`crate::store`). Not the journal's seal, not the client's work.
//!
//! No accessor returns the secret key; it leaves this crate only inside the
//! container's encrypted storage.

use frost_ed25519::rand_core::{CryptoRng, RngCore};
use ksg_core_v2::crypto::sign::{Alg, PublicKey, Signature};
use ksg_core_v2::doc::Uri;

/// Why the post-quantum key did not come to be, or did not sign.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the container's post-quantum key: {0}")]
pub struct PqKeyError(pub &'static str);

/// The container's ML-DSA-65 key.
pub struct ContainerPqKey {
    sk: fips204::ml_dsa_65::PrivateKey,
    public: PublicKey,
}

// Written by hand: a secret key has no business in a log.
impl core::fmt::Debug for ContainerPqKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ContainerPqKey")
            .field("kid", &self.public.kid)
            .finish_non_exhaustive()
    }
}

impl ContainerPqKey {
    /// A new key, made inside, named `kid`. Randomness must come from a
    /// CSPRNG.
    ///
    /// # Errors
    ///
    /// The generator refused — not expected with a working RNG.
    pub fn generate<R: RngCore + CryptoRng>(kid: Uri, rng: &mut R) -> Result<Self, PqKeyError> {
        use fips204::traits::SerDes as _;
        let (pk, sk) = fips204::ml_dsa_65::try_keygen_with_rng(rng).map_err(PqKeyError)?;
        Ok(Self {
            sk,
            public: PublicKey {
                kid,
                alg: Alg::MlDsa65,
                key: ksg_core_v2::crypto::sign::b64_encode(&pk.into_bytes()),
            },
        })
    }

    /// The public key — what the issuer vouches for and anyone checks the
    /// file with.
    #[must_use]
    pub const fn public(&self) -> &PublicKey {
        &self.public
    }

    /// Signs `msg`. Only the container calls this, over its own file.
    pub(crate) fn sign<R: RngCore + CryptoRng>(
        &self,
        msg: &[u8],
        rng: &mut R,
    ) -> Result<Signature, PqKeyError> {
        use fips204::traits::Signer as _;
        let sig = self
            .sk
            .try_sign_with_rng(rng, msg, &[])
            .map_err(PqKeyError)?;
        Ok(Signature {
            kid: self.public.kid.clone(),
            alg: Alg::MlDsa65,
            value: ksg_core_v2::crypto::sign::b64_encode(&sig),
        })
    }

    /// The key as bytes, for the container's encrypted storage only.
    pub(crate) fn state(&self) -> PqKeyState {
        use fips204::traits::SerDes as _;
        PqKeyState {
            sk: self.sk.clone().into_bytes().to_vec(),
            public: self.public.clone(),
        }
    }

    /// The key again, from encrypted storage.
    pub(crate) fn from_state(s: &PqKeyState) -> Result<Self, PqKeyError> {
        use fips204::traits::SerDes as _;
        let bytes: [u8; fips204::ml_dsa_65::SK_LEN] =
            s.sk.as_slice()
                .try_into()
                .map_err(|_| PqKeyError("stored key has the wrong length"))?;
        let sk = fips204::ml_dsa_65::PrivateKey::try_from_bytes(bytes).map_err(PqKeyError)?;
        Ok(Self {
            sk,
            public: s.public.clone(),
        })
    }
}

/// The key as bytes — crate-private, wiped when dropped.
#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct PqKeyState {
    sk: Vec<u8>,
    public: PublicKey,
}

impl Drop for PqKeyState {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.sk.zeroize();
    }
}
