//! Encrypted storage: a container as bytes on a disk, signed outside with its
//! own post-quantum key (`[decision]` 02.10, CH-5a; CH-5b). Item P-4 of the
//! MVP plan. ("Seal" in this project is the journal's word, `[decision]` 02.10;
//! a file here is encrypted and signed, not sealed.)
//!
//! # The key is the caller's — and who holds it is the whole question
//!
//! `[decision]` 23.09: for the MVP the container is encrypted under the current
//! holder's **layer key** (`crate::layers`); for the product, under a key
//! bound to a **TEE** (trusted execution environment), so that only the
//! container's own code opens it. The code here takes the key as an argument
//! and does not care which.
//!
//! Inside the bytes are the container's half of the client's key, the
//! container's post-quantum key and the issuer's signing key for artefacts
//! (`crate::seal`). On the test stand the key is the holder's layer key (the
//! stand is for tests only, `[decision]` 25.10); in the product it is bound to
//! a TEE (`[doc:MVP-PLAN]` §3.2).
//!
//! # The bytes
//!
//! `ksg:store:v4` ‖ nonce (12) ‖ ChaCha20-Poly1305 of the padded, compressed
//! state (DEFLATE, bounded on the way back — `crate::pack::Deflate`), with
//! the container's **template** identifier in the associated data — so the
//! bytes of one container do not open as another ‖ the outer signature (JSON)
//! ‖ its length (u32, big-endian). The plaintext is padded to [`STORE_SIZE`]
//! before encryption (`crate::pack`): the file is the same size on the first
//! day and at the thousandth page, and its size says nothing about the work.
//!
//! The template identifier (`Container::template_id`) and not the container's
//! own: that one is born only at initiation (CH-5b), the file exists from
//! printing.
//!
//! # The outer signature
//!
//! From printing on, the container signs its whole file — template
//! identifier, nonce, ciphertext — with its own ML-DSA-65 key
//! (`crate::pq_key`), at every save. A container that holds the key does not
//! open from a file without that signature. The issuer vouched for the key at
//! printing ([`pq_cert_message`]); with it anyone checks the file without the
//! layer key ([`verify_outer`]).
//!
//! # What is not stored
//!
//! The open signing round, and a birth under way. See `ContainerState`.

use frost_ed25519::rand_core::{CryptoRng, RngCore};
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{Alg, KeySet, Profile, PublicKey, Signature, SignatureSet};
use zeroize::Zeroizing;

use crate::container::{Container, ContainerState};
use crate::pack::{ChaCha20Poly1305Aead, Deflate, PackError, Packer};

/// The size every stored container is padded to before encryption.
///
/// Set from the worst case (Plan_MVP §9, CH-12): a journal of `1+1000+100+2`
/// pages, every working page carrying its full 2 KB, every seal anchored with
/// a proof the size of a real Solana one, and twelve pages held for an
/// expert — 3.72 MiB measured with the whole container — and a full ring of
/// "who looked" notices at their bound (`crate::view`), 3.95 MiB in all
/// (test `a_full_journal_fits_the_store`).
pub const STORE_SIZE: usize = 4 * 1024 * 1024;

/// `v4`: the template identifier in the associated data and under the outer
/// signature, by the container's own post-quantum key (CH-5b). `v3` signed
/// with a key of the client's half (CH-5a); `v2` compressed the state before
/// the padding (audit of 30.09, O-2). Bytes of earlier versions are not
/// containers of this one.
const MAGIC: &[u8] = b"ksg:store:v4";

/// Domain of the outer signature: what the container's ML-DSA key signs is
/// this, the template identifier, the nonce and the ciphertext — the whole
/// file but the signature itself.
const OUTER: &[u8] = b"ksg:store:v4:outer";

/// Domain of the issuer's word on a container's post-quantum key, given at
/// printing: "this key is the key of the container of template `template`".
const PQ_CERT: &[u8] = b"ksg:container-pq-key:v2";

/// The most a decompressed state may take: the size of a whole journal
/// export (spec v2 §14) — a state larger than that is not one this program
/// wrote.
pub const MAX_STATE: usize = ksg_core_v2::limits::MAX_EXPORT_BYTES;
const NONCE: usize = 12;

/// Why a container did not go to bytes, or did not come back from them.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    /// The state did not encode.
    #[error("encode: {0}")]
    Encode(String),
    /// The bytes are not a stored container of this version.
    #[error("not a stored container")]
    NotAContainer,
    /// Padding, cipher or size: a wrong key, other bytes, or a state past
    /// [`STORE_SIZE`].
    #[error("cipher: {0}")]
    Pack(#[from] PackError),
    /// The state decrypted but does not rebuild: it would not have been written.
    #[error("restore: {0}")]
    Restore(String),
    /// The outer signature is missing where the container holds its key, or
    /// does not verify: the file is not the one the container wrote.
    #[error("outer signature: {0}")]
    Outer(&'static str),
}

fn outer_message(template: &Hash, nonce: &[u8], sealed: &[u8]) -> Vec<u8> {
    [OUTER, template.as_bytes(), nonce, sealed].concat()
}

/// What the issuer signs at printing to vouch for a container's
/// post-quantum key: the domain, the template identifier and the key.
#[must_use]
pub fn pq_cert_message(template: &Hash, pq_key: &PublicKey) -> Vec<u8> {
    [PQ_CERT, template.as_bytes(), pq_key.key.as_bytes()].concat()
}

/// The outer signature over the file: ML-DSA-65 alone, by `pq_key`.
fn check_outer_sig(
    sig: Signature,
    pq_key: &PublicKey,
    id: &Hash,
    nonce: &[u8],
    sealed: &[u8],
) -> Result<(), StoreError> {
    let mut keys = KeySet::new();
    keys.insert(pq_key.clone());
    let profile = Profile {
        required_algs: [Alg::MlDsa65].into_iter().collect(),
        ..Profile::default()
    };
    SignatureSet::new(vec![sig])
        .verify(&outer_message(id, nonce, sealed), &keys, &profile)
        .map_err(|_| StoreError::Outer("does not verify"))
}

/// A stored file taken apart.
struct FileParts<'a> {
    nonce: &'a [u8],
    sealed: &'a [u8],
    sig: Option<Signature>,
}

/// The parts of a stored file: nonce, ciphertext, outer signature if any.
fn split_file(bytes: &[u8]) -> Result<FileParts<'_>, StoreError> {
    let rest = bytes.strip_prefix(MAGIC).ok_or(StoreError::NotAContainer)?;
    let len_at = rest.len().checked_sub(4).ok_or(StoreError::NotAContainer)?;
    let (body, len) = rest.split_at(len_at);
    let len = u32::from_be_bytes(len.try_into().map_err(|_| StoreError::NotAContainer)?) as usize;
    let sig_at = body
        .len()
        .checked_sub(len)
        .ok_or(StoreError::NotAContainer)?;
    let (body, sig) = body.split_at(sig_at);
    if body.len() < NONCE {
        return Err(StoreError::NotAContainer);
    }
    let (nonce, sealed) = body.split_at(NONCE);
    let sig = if sig.is_empty() {
        None
    } else {
        Some(serde_json::from_slice(sig).map_err(|_| StoreError::Outer("not a signature"))?)
    };
    Ok(FileParts { nonce, sealed, sig })
}

/// Checks a stored container's outer signature against `pq_key` — the
/// container's post-quantum key, as the issuer vouched for it at printing —
/// without the layer key: anyone holding the file can tell it is the one the
/// container wrote. `template` is the container's template identifier
/// (`Container::template_id`).
///
/// # Errors
///
/// [`StoreError::NotAContainer`] for other bytes, [`StoreError::Outer`] for a
/// signature that is missing or does not verify.
pub fn verify_outer(bytes: &[u8], template: &Hash, pq_key: &PublicKey) -> Result<(), StoreError> {
    let FileParts { nonce, sealed, sig } = split_file(bytes)?;
    let sig = sig.ok_or(StoreError::Outer("missing"))?;
    check_outer_sig(sig, pq_key, template, nonce, sealed)
}

/// Checks a stored container's file carries no outer signature — the
/// shape of a `bare` container (Goal 1, criterion G1-4), which holds no
/// post-quantum key and signs nothing outside.
///
/// # Errors
///
/// [`StoreError::NotAContainer`] for other bytes, [`StoreError::Outer`]
/// for a file that carries a signature after all.
pub fn verify_absent_outer(bytes: &[u8]) -> Result<(), StoreError> {
    let FileParts { sig, .. } = split_file(bytes)?;
    if sig.is_some() {
        return Err(StoreError::Outer(
            "a bare container carries no outer signature",
        ));
    }
    Ok(())
}

fn aad(template: &Hash) -> Vec<u8> {
    [MAGIC, template.as_bytes()].concat()
}

fn packer() -> Packer<ChaCha20Poly1305Aead, Deflate> {
    Packer::new(
        ChaCha20Poly1305Aead,
        Deflate { limit: MAX_STATE },
        STORE_SIZE,
    )
}

impl Container {
    /// The container as sealed bytes, under `key`.
    ///
    /// Randomness — the nonce and the padding — is the caller's, as everywhere
    /// in this codebase; it must come from a CSPRNG.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the state does not encode or does not fit.
    pub fn seal_to_bytes<R: RngCore + CryptoRng>(
        &self,
        key: &[u8; 32],
        rng: &mut R,
    ) -> Result<Vec<u8>, StoreError> {
        let state = self.to_state()?;
        let plain = Zeroizing::new(
            serde_json::to_vec(&state).map_err(|e| StoreError::Encode(e.to_string()))?,
        );
        drop(state);

        let p = packer();
        let mut noise = Zeroizing::new(vec![0u8; p.noise_needed(&plain)]);
        rng.fill_bytes(&mut noise);
        let mut nonce = [0u8; NONCE];
        rng.fill_bytes(&mut nonce);

        let template = self.template_id();
        let sealed = p.seal_checked(&plain, &noise, key, &nonce, &aad(&template))?;
        // The outer signature, by the container's own key, laid in at
        // printing. A container assembled without one (test parts) writes
        // an unsigned file and opens only as such.
        let sig = match self.pq_key() {
            None => Vec::new(),
            Some(k) => serde_json::to_vec(
                &k.sign(&outer_message(&template, &nonce, &sealed), rng)
                    .map_err(|e| StoreError::Encode(e.to_string()))?,
            )
            .map_err(|e| StoreError::Encode(e.to_string()))?,
        };
        let sig_len =
            u32::try_from(sig.len()).map_err(|_| StoreError::Encode("signature".into()))?;
        Ok([MAGIC, &nonce, &sealed, &sig, &sig_len.to_be_bytes()].concat())
    }

    /// How many bytes of the [`STORE_SIZE`] the container's state takes now,
    /// before padding: what is left is the room the journal still has.
    ///
    /// # Errors
    ///
    /// [`StoreError::Encode`] if the state does not encode.
    pub fn stored_len(&self) -> Result<usize, StoreError> {
        let state = self.to_state()?;
        let plain = Zeroizing::new(
            serde_json::to_vec(&state).map_err(|e| StoreError::Encode(e.to_string()))?,
        );
        Ok(plain.len())
    }

    /// The bytes the state takes once compressed — what is actually padded to
    /// [`STORE_SIZE`]. Never more than [`Container::stored_len`] by more than
    /// DEFLATE's framing (five bytes per 64 KiB stored block, six of zlib), so
    /// a bound on `stored_len` is a bound on this.
    ///
    /// # Errors
    ///
    /// [`StoreError::Encode`] if the state does not serialize.
    pub fn stored_packed_len(&self) -> Result<usize, StoreError> {
        use crate::pack::Compressor as _;
        let state = self.to_state()?;
        let plain = Zeroizing::new(
            serde_json::to_vec(&state).map_err(|e| StoreError::Encode(e.to_string()))?,
        );
        Ok(Deflate { limit: MAX_STATE }.compress(&plain).len())
    }

    /// A container again, from its encrypted bytes.
    ///
    /// `template` is the template identifier the caller expects
    /// (`Container::template_id`): bytes of another container do not open,
    /// even under the right key.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotAContainer`] for other bytes, [`StoreError::Pack`] for
    /// a wrong key, a wrong `id` or tampering, [`StoreError::Restore`] for a
    /// state that would not have been written.
    pub fn open_sealed(bytes: &[u8], template: &Hash, key: &[u8; 32]) -> Result<Self, StoreError> {
        let FileParts { nonce, sealed, sig } = split_file(bytes)?;
        let plain = Zeroizing::new(packer().open(sealed, key, nonce, &aad(template))?);
        let state: ContainerState =
            serde_json::from_slice(&plain).map_err(|_| StoreError::NotAContainer)?;
        let c = Self::from_state(state)?;
        if &c.template_id() != template {
            return Err(StoreError::Restore(
                "the state is another template's".into(),
            ));
        }
        // A container that holds its key always signs its file: a file
        // without the signature, or with another, was not written by it.
        if let Some(k) = c.pq_key() {
            let sig = sig.ok_or(StoreError::Outer("missing"))?;
            check_outer_sig(sig, k.public(), template, nonce, sealed)?;
        }
        Ok(c)
    }
}
