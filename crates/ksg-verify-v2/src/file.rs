//! A container's file, checked from outside (`[decision]` 02.10, CH-5a;
//! CH-5b): without the layer key, anyone holding the file tells whether it is
//! the one the container wrote.
//!
//! | Check | Against what |
//! |---|---|
//! | the template identifier | recomputed from the release and the serial: `section_root(release, serial)` |
//! | the container's post-quantum key | the issuer's signature on it, given at printing, under the issuer keys the verifier holds |
//! | the file | the outer ML-DSA-65 signature by that key over the template identifier, the nonce and the ciphertext |
//!
//! The layout is `ksg-container-v2::store`'s, version 4, read here
//! independently: a verifier does not run the container's code.

use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{Alg, KeySet, Profile, PublicKey, Signature, SignatureSet};
use ksg_core_v2::doc::Serial;

/// The file's first bytes.
pub const MAGIC: &[u8] = b"ksg:store:v4";
/// Domain of the outer signature.
const OUTER: &[u8] = b"ksg:store:v4:outer";
/// Domain of the issuer's word on the container's post-quantum key.
const PQ_CERT: &[u8] = b"ksg:container-pq-key:v2";
const NONCE: usize = 12;

/// Why a file without an outer key is not accepted (see `verify_file`).
pub const NO_OUTER_KEY: &str = "no outer key in container.json: a bare container's file is not \
provable from outside, and a file of any class with its signature and key stripped looks the same";

/// What the verifier knows about the container's file without opening it —
/// from the holder's `container.json`, every field checked here.
///
/// `pq` / `pq_cert` are absent for `bare` (Goal 1, criterion G1-4: no
/// post-quantum wrapping — the fields are missing, not empty).
#[derive(Debug, Clone)]
pub struct FileClaim {
    /// The release the container was printed in.
    pub release: String,
    /// Its serial.
    pub serial: Serial,
    /// The container's post-quantum key; `None` for `bare`.
    pub pq: Option<PublicKey>,
    /// The issuer's signature on it, given at printing; `None` for `bare`.
    pub pq_cert: Option<Signature>,
}

impl FileClaim {
    /// The claim from a holder's `container.json`.
    ///
    /// # Errors
    ///
    /// A field is missing or is not what it should be.
    pub fn from_meta(json: &[u8]) -> Result<Self, String> {
        let v: serde_json::Value =
            serde_json::from_slice(json).map_err(|e| format!("container.json: {e}"))?;
        let field = |k: &str| v.get(k).cloned().ok_or(format!("container.json: no {k}"));
        Ok(Self {
            release: serde_json::from_value(field("emission")?).map_err(|e| e.to_string())?,
            serial: serde_json::from_value(field("serial")?).map_err(|e| e.to_string())?,
            pq: match v.get("pq") {
                None | Some(serde_json::Value::Null) => None,
                Some(p) => Some(serde_json::from_value(p.clone()).map_err(|e| e.to_string())?),
            },
            pq_cert: match v.get("pq_cert") {
                None | Some(serde_json::Value::Null) => None,
                Some(p) => Some(serde_json::from_value(p.clone()).map_err(|e| e.to_string())?),
            },
        })
    }
}

fn ml_dsa_only() -> Profile {
    Profile {
        required_algs: [Alg::MlDsa65].into_iter().collect(),
        ..Profile::default()
    }
}

/// Checks a container's file against the claim and the issuer's keys.
/// Returns the template identifier the file is bound to.
///
/// # Errors
///
/// What does not hold, named.
pub fn verify_file(bytes: &[u8], claim: &FileClaim, issuer_keys: &KeySet) -> Result<Hash, String> {
    let template = ksg_core_v2::section::section_root(&claim.release, claim.serial);
    // Goal 1, criterion G1-4: a `bare` file carries no outer signature, so
    // from outside there is nothing to check it against. It is never
    // ACCEPTED: which class a file is comes from `container.json`, which the
    // holder writes, and "no key, no signature" is exactly what a Pro or
    // `light` file looks like after someone strips its signature and its
    // key out of the claim. Accepting it would let anyone downgrade any file
    // to "bare" and pass it off as checked.
    let (pq, cert) = match (&claim.pq, &claim.pq_cert) {
        (None, None) => return Err(NO_OUTER_KEY.into()),
        (Some(p), Some(c)) => (p, c),
        _ => return Err("container.json: pq and pq_cert go together".into()),
    };
    if pq.alg != Alg::MlDsa65 {
        return Err("the container's key is not an ML-DSA-65 key".into());
    }
    SignatureSet::new(vec![cert.clone()])
        .verify(
            &[PQ_CERT, template.as_bytes(), pq.key.as_bytes()].concat(),
            issuer_keys,
            &Profile::default().with_ed25519(),
        )
        .map_err(|e| format!("the issuer did not vouch for this key for this container: {e}"))?;

    let rest = bytes
        .strip_prefix(MAGIC)
        .ok_or("not a container file of version 4")?;
    let len_at = rest.len().checked_sub(4).ok_or("truncated")?;
    let (body, len) = rest.split_at(len_at);
    let len = u32::from_be_bytes(len.try_into().map_err(|_| "truncated")?) as usize;
    let sig_at = body.len().checked_sub(len).ok_or("truncated")?;
    let (body, sig) = body.split_at(sig_at);
    if body.len() < NONCE {
        return Err("truncated".into());
    }
    let (nonce, sealed) = body.split_at(NONCE);
    if sig.is_empty() {
        return Err("the file carries no outer signature".into());
    }
    let sig: Signature =
        serde_json::from_slice(sig).map_err(|_| "the outer signature is not one")?;
    let keys: KeySet = [pq.clone()].into_iter().collect();
    SignatureSet::new(vec![sig])
        .verify(
            &[OUTER, template.as_bytes(), nonce, sealed].concat(),
            &keys,
            &ml_dsa_only(),
        )
        .map_err(|e| format!("the outer signature does not hold: {e}"))?;
    Ok(template)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Downgrade: a forged file with no signature and a claim with no key —
    /// what stripping a Pro file down to "bare" gives — must not pass.
    #[test]
    fn a_file_without_an_outer_key_is_never_accepted() {
        let mut forged = MAGIC.to_vec();
        forged.extend_from_slice(&[7u8; 64]);
        forged.extend_from_slice(&0u32.to_be_bytes());
        let claim = FileClaim {
            release: "any".into(),
            serial: Serial(1),
            pq: None,
            pq_cert: None,
        };
        let err = verify_file(&forged, &claim, &KeySet::default()).expect_err("must not pass");
        assert_eq!(err, NO_OUTER_KEY);
    }
}
