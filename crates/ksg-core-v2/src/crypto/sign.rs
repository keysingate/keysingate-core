//! Signatures. Specification §4.1. **The array type and the coverage rule are
//! part 1, the cryptographic bodies part 2.**
//!
//! Ed25519 is mandatory, ML-DSA-65 optional. `required_algs` coverage is a
//! logical **AND**. An unknown `alg` is a refusal, not something to ignore.

use std::collections::{BTreeMap, BTreeSet};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature as DalekSig, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::doc::Uri;
use crate::error::{Invalid, SigFail};

/// base64url without padding — the format of `value` and `key` in the specification.
pub(crate) fn b64_decode(s: &str) -> Result<Vec<u8>, ()> {
    URL_SAFE_NO_PAD.decode(s).map_err(|_| ())
}

/// Encoding to base64url without padding.
#[must_use]
pub fn b64_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// A signature algorithm.
///
/// The enumeration is closed: an unknown value becomes [`Invalid::UnknownAlg`]
/// at parse time, not a silently skipped signature. A verifier that passes over
/// an unfamiliar algorithm is affirming a document it did not check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Alg {
    /// Ed25519, RFC 8032. Mandatory in every profile.
    Ed25519,
    /// ML-DSA-65, FIPS 204. Added as a second array element, not as a
    /// replacement. Verification implemented 2026-09-17 over `fips204`;
    /// public key 1952 bytes, signature 3309, both base64url as everywhere.
    #[serde(rename = "ML-DSA-65")]
    MlDsa65,
}

impl core::fmt::Display for Alg {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Ed25519 => "Ed25519",
            Self::MlDsa65 => "ML-DSA-65",
        })
    }
}

/// A public key together with the algorithm it is meant for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicKey {
    /// The key identifier — an opaque URI with a fragment (§4.2).
    pub kid: Uri,
    /// The algorithm the key belongs to.
    pub alg: Alg,
    /// The key material in base64url without padding.
    pub key: String,
}

/// One signature from the array.
///
/// Stored as a separate object rather than a concatenated string: concatenation
/// makes adding a second algorithm a breaking format change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signature {
    /// The key it was signed with.
    pub kid: Uri,
    /// The signature algorithm.
    pub alg: Alg,
    /// The signature value in base64url without padding.
    pub value: String,
}

/// A document's signature array — **multiplicity by construction**.
///
/// The type deliberately offers no `Deref<Target = Vec<_>>` and no
/// single-signature constructor: either one brings back the temptation to treat
/// the array as a field, and a field would have to be replaced when a second
/// algorithm arrives. Replacement invalidates history; addition is monotonic (§15).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SignatureSet(Vec<Signature>);

impl SignatureSet {
    /// A set of the signatures listed.
    #[must_use]
    pub const fn new(signatures: Vec<Signature>) -> Self {
        Self(signatures)
    }

    /// The signatures in the order presented.
    #[must_use]
    pub fn as_slice(&self) -> &[Signature] {
        &self.0
    }

    /// The number of signatures.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// There are no signatures.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The distinct identifiers that signed.
    ///
    /// Not the same as [`len`](Self::len), and the difference is the whole
    /// point of the method: a rule of the form "two signatures" is satisfied by
    /// one party signing twice, which is not two parties. Wherever the protocol
    /// means **two parties**, it counts these.
    #[must_use]
    pub fn signers(&self) -> BTreeSet<&Uri> {
        self.0.iter().map(|s| &s.kid).collect()
    }

    /// Whether `kid` is among the signers.
    #[must_use]
    /// # This is presence, not proof
    ///
    /// It answers "is there an entry with this `kid`", not "did that party
    /// sign". It is sound only **after** [`SignatureSet::verify`] has returned
    /// `Ok` on the same message, because from 2026-09-13 `verify` rejects any
    /// signature that does not match. Calling it on an unverified set proves
    /// nothing.
    pub fn signed_by(&self, kid: &Uri) -> bool {
        self.0.iter().any(|s| &s.kid == kid)
    }

    /// Checks profile coverage.
    ///
    /// Returns `Ok` **only if every** algorithm in `p.required_algs` has a valid
    /// signature under a valid key: a logical AND, not OR.
    ///
    /// # Errors
    ///
    /// - [`Invalid::UnknownAlg`] — a signature of an unrecognized algorithm was
    ///   presented;
    /// - [`Invalid::Signature`] with [`SigFail::MissingRequired`] — a required
    ///   algorithm is not covered;
    /// - [`Invalid::Signature`] with other reasons — a signature was presented
    ///   but failed verification.
    ///
    /// Every signature presented must verify: one that does not is
    /// [`SigFail::Mismatch`] and rejects the document. Coverage is then checked
    /// on top of that — `required_algs` must each have a signature.
    ///
    /// The earlier rule ("an invalid signature merely fails to cover its
    /// algorithm") was removed on 2026-09-13: paired with
    /// [`SignatureSet::signed_by`], which only looks for a `kid`, it let one
    /// party assemble a two-sided authorization alone.
    pub fn verify(&self, msg: &[u8], keys: &KeySet, p: &Profile) -> Result<(), Invalid> {
        let mut covered: BTreeSet<Alg> = BTreeSet::new();
        for s in &self.0 {
            let key = keys.get(&s.kid).ok_or(Invalid::Signature {
                alg: s.alg,
                reason: SigFail::UnknownKey,
            })?;
            // A key issued for a different algorithm is not "the wrong signature"
            // but an inconsistent key set.
            if key.alg != s.alg {
                return Err(Invalid::Signature {
                    alg: s.alg,
                    reason: SigFail::BadKey,
                });
            }
            // A signature that does not match is a **refusal**, not a silent
            // gap in coverage. The earlier reading — "an invalid signature
            // fails to cover its algorithm" — let a party forge two-sided
            // authorization: present `{kid: the other party, value: garbage}`
            // plus one's own valid signature, and `signed_by(other)` was true
            // while `verify` still passed. Security audit of 2026-09-13,
            // finding 1.
            if !verify_one(s, key, msg)? {
                return Err(Invalid::Signature {
                    alg: s.alg,
                    reason: SigFail::Mismatch,
                });
            }
            covered.insert(s.alg);
        }
        for alg in &p.required_algs {
            if !covered.contains(alg) {
                return Err(Invalid::Signature {
                    alg: *alg,
                    reason: SigFail::MissingRequired,
                });
            }
        }
        Ok(())
    }
}

/// The verification profile: what exactly the policy requires of a document.
///
/// The specification keeps policy **outside the core** (§11.3, §17): the core
/// enforces a profile's requirements but does not decide what they should be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    /// The algorithms each of which must have a valid signature (§4.1).
    ///
    /// The default value is `["Ed25519"]`.
    pub required_algs: BTreeSet<Alg>,
    /// How many anchors must be **read** for a subject to have an upper time
    /// bound (spec v2 §7.2). At least one by type: there is no bound on
    /// anybody's word, and "zero anchors" cannot be asked for.
    pub min_anchors: core::num::NonZeroUsize,
    /// The verifier's clock, if it brought one (`[decision]` 19.09, CT-20).
    ///
    /// The core has no clock and does not acquire one here: it is **given** a
    /// moment and compares against it, never reads the system time, and never
    /// subtracts. Time in the profile is the verifier's responsibility — the
    /// owner's decision word for word.
    ///
    /// What it closes (security audit of 2026-09-13, finding 12): a leaked
    /// operational key used to act forever for an offline verifier, because
    /// nothing compared a delegation's `expires_at` with *now* — the whole of
    /// "rotation instead of revocation" (KS-4 §9.4) protected nobody who
    /// checked a year after the leak. With a clock, an expired grant is refused.
    ///
    /// `None` keeps the old behaviour and says so: authenticity is proved, the
    /// currency of the authority is not checked. That is a narrower claim, not
    /// a failure, and a verifier who needs the wider one brings a clock.
    pub now: Option<crate::doc::Timestamp>,
}

impl Profile {
    /// This profile, also requiring an Ed25519 signature: the non-removable
    /// seals of the journal (an owner's seal, a transfer) — spec v2 §10.4.
    ///
    /// The one place the rule is built. Audit of 30.09, O-5: the journal
    /// built it by hand twice, and two copies of a rule drift.
    #[must_use]
    pub fn with_ed25519(&self) -> Self {
        let mut q = self.clone();
        q.required_algs.insert(Alg::Ed25519);
        q
    }

    /// This profile, also requiring Ed25519 **and** ML-DSA-65: the agent's
    /// movable seal (spec v2 §10.4, CH-5). Whatever the caller asked for
    /// stays required; nothing is taken away.
    #[must_use]
    pub fn with_ed25519_and_ml_dsa(&self) -> Self {
        let mut q = self.with_ed25519();
        q.required_algs.insert(Alg::MlDsa65);
        q
    }
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            required_algs: BTreeSet::from([Alg::Ed25519]),
            min_anchors: core::num::NonZeroUsize::MIN,
            now: None,
        }
    }
}

/// The key set presented to the verifier.
///
/// The core does not resolve a `kid` into a key: where a key came from is a
/// question for a layer outside the core (§4.2, §17). Here there is only lookup
/// within an already-presented set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeySet(BTreeMap<Uri, PublicKey>);

impl KeySet {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a key. A repeated `kid` replaces the previous value.
    pub fn insert(&mut self, key: PublicKey) {
        self.0.insert(key.kid.clone(), key);
    }

    /// The key for an identifier.
    #[must_use]
    pub fn get(&self, kid: &Uri) -> Option<&PublicKey> {
        self.0.get(kid)
    }

    /// The number of keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// The set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The keys, in identifier order.
    pub fn keys(&self) -> impl Iterator<Item = &PublicKey> {
        self.0.values()
    }
}

impl FromIterator<PublicKey> for KeySet {
    fn from_iter<I: IntoIterator<Item = PublicKey>>(iter: I) -> Self {
        let mut s = Self::new();
        for k in iter {
            s.insert(k);
        }
        s
    }
}

/// Verifies one signature. Returns `Ok(false)` on an honest mismatch and `Err`
/// on something that is not a signature at all: an unreadable encoding, an
/// unusable key, an unsupported algorithm.
///
/// The distinction matters: a mismatched signature fails to cover its algorithm
/// and is handled by the coverage rule, whereas an unreadable one rejects the
/// document outright.
fn verify_one(sig: &Signature, key: &PublicKey, msg: &[u8]) -> Result<bool, Invalid> {
    match sig.alg {
        Alg::Ed25519 => {
            let key_bytes = b64_decode(&key.key).map_err(|()| Invalid::Signature {
                alg: sig.alg,
                reason: SigFail::BadEncoding,
            })?;
            let key_arr: [u8; 32] = key_bytes.try_into().map_err(|_| Invalid::Signature {
                alg: sig.alg,
                reason: SigFail::BadKey,
            })?;
            let vk = VerifyingKey::from_bytes(&key_arr).map_err(|_| Invalid::Signature {
                alg: sig.alg,
                reason: SigFail::BadKey,
            })?;
            let sig_bytes = b64_decode(&sig.value).map_err(|()| Invalid::Signature {
                alg: sig.alg,
                reason: SigFail::BadEncoding,
            })?;
            let sig_arr: [u8; 64] = sig_bytes.try_into().map_err(|_| Invalid::Signature {
                alg: sig.alg,
                reason: SigFail::BadEncoding,
            })?;
            // `verify_strict`, not `verify`: the permissive form of
            // ed25519-dalek 2.x accepts non-canonical encodings of the point
            // `A` and small-order points, and a signature that verifies under
            // several public keys at once is exactly what a proof must not
            // allow (security audit of 2026-09-13, finding 17).
            Ok(vk
                .verify_strict(msg, &DalekSig::from_bytes(&sig_arr))
                .is_ok())
        }
        // ML-DSA-65 (FIPS 204), the optional second algorithm of the
        // specification. Implemented 2026-09-17: until then the verifier
        // answered "there is nothing to verify it with", which was honest but
        // left a profile of two required algorithms impossible to satisfy.
        //
        // The context string is empty and stays empty: the document's own
        // canonical bytes are the message, and a second, unstated context would
        // be a value two implementations could disagree on.
        Alg::MlDsa65 => {
            use fips204::ml_dsa_65;
            use fips204::traits::{SerDes, Verifier};

            let key_bytes = b64_decode(&key.key).map_err(|()| Invalid::Signature {
                alg: sig.alg,
                reason: SigFail::BadEncoding,
            })?;
            let key_arr: [u8; ml_dsa_65::PK_LEN] =
                key_bytes.try_into().map_err(|_| Invalid::Signature {
                    alg: sig.alg,
                    reason: SigFail::BadKey,
                })?;
            let vk =
                ml_dsa_65::PublicKey::try_from_bytes(key_arr).map_err(|_| Invalid::Signature {
                    alg: sig.alg,
                    reason: SigFail::BadKey,
                })?;
            let sig_bytes = b64_decode(&sig.value).map_err(|()| Invalid::Signature {
                alg: sig.alg,
                reason: SigFail::BadEncoding,
            })?;
            let sig_arr: [u8; ml_dsa_65::SIG_LEN] =
                sig_bytes.try_into().map_err(|_| Invalid::Signature {
                    alg: sig.alg,
                    reason: SigFail::BadEncoding,
                })?;
            Ok(vk.verify(msg, &sig_arr, &[]))
        }
    }
}

/// An Ed25519 signer.
///
/// Needed by the tests and the vector generator: without the ability to produce
/// a signature there is nothing to check the verifying code with. The key is set
/// from a seed rather than from system randomness — the vectors must be
/// reproducible byte for byte.
///
/// `Debug` is written by hand below: what the upstream `SigningKey` prints is
/// not this crate's to promise across versions, and a signing key has no
/// business in a log either way (audit of 2026-09-13, finding 7).
#[derive(Clone)]
pub struct Ed25519Signer {
    kid: Uri,
    key: ed25519_dalek::SigningKey,
}

impl core::fmt::Debug for Ed25519Signer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Ed25519Signer(kid={})", self.kid)
    }
}

impl Ed25519Signer {
    /// A signer from a 32-byte seed.
    #[must_use]
    pub fn from_seed(kid: Uri, seed: [u8; 32]) -> Self {
        Self {
            kid,
            key: ed25519_dalek::SigningKey::from_bytes(&seed),
        }
    }

    /// The public key in a form suitable for a document's `keys` field.
    #[must_use]
    pub fn public(&self) -> PublicKey {
        PublicKey {
            kid: self.kid.clone(),
            alg: Alg::Ed25519,
            key: b64_encode(self.key.verifying_key().as_bytes()),
        }
    }

    /// Signs arbitrary bytes.
    #[must_use]
    pub fn sign(&self, msg: &[u8]) -> Signature {
        use ed25519_dalek::Signer as _;
        Signature {
            kid: self.kid.clone(),
            alg: Alg::Ed25519,
            value: b64_encode(&self.key.sign(msg).to_bytes()),
        }
    }
}

/// Signs a document over its canonical form (§3, §4.1).
///
/// The one correct way to sign: `signatures` is excluded from the signing view,
/// so filling the field in after the call does not break the signature.
///
/// # Errors
///
/// [`Invalid::Canonicalization`] if the document does not canonicalize.
pub fn sign_doc<T: crate::canonical::Signable>(
    doc: &T,
    signer: &Ed25519Signer,
) -> Result<Signature, Invalid> {
    Ok(signer.sign(&crate::canonical::canonical_bytes(doc)?))
}
