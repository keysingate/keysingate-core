//! Padding to a constant size. KS-8 F-4, A-6; plan §2.1 `noise.rs`.
//!
//! # The one property
//!
//! **The size says nothing about the content.** A container with one journal
//! page and one with a thousand are the same number of bytes, and so are a
//! container whose custom slots are empty and one whose hundred are full.
//!
//! Without it the size is a side channel about the work, and by KS-8 F-7 the
//! issuer is meant to be the blindest party there is — an issuer who can weigh a
//! container knows how much was done in it.
//!
//! # Padding is to a FIXED size, not to a bucket
//!
//! That distinction carries the whole security argument for compressing before
//! encrypting. Compress-then-encrypt is a known hazard — CRIME and BREACH — when
//! an attacker can influence part of the plaintext and observe the ciphertext's
//! length. Here the length is a **constant of the layout**, not a function of
//! what compressed how well, so there is nothing to observe.
//!
//! Round the size to buckets and the hazard comes straight back: a bucket
//! boundary is a length signal, just a coarser one.
//!
//! # The noise comes from the caller
//!
//! For the reason it does in `ksg-custody`: where randomness comes from is the
//! operator's decision, and a crate that generates its own hides that decision.
//! **Anything but a cryptographic RNG makes the padding distinguishable**, and
//! then the constant size is preserved while the property it exists for is not.

use crate::pack::PackError;

/// The length prefix's width. Four bytes — a container's content is bounded by
/// its layout and never approaches 4 GiB, and eight would be wasted room that
/// still had to be padded around.
const LEN: usize = 4;

/// Pads `plain` with noise to exactly `size` bytes.
///
/// # Errors
///
/// [`PackError::TooLarge`] if the content plus its length prefix does not fit;
/// [`PackError::ShortNoise`] if too little noise was supplied.
pub fn pad(plain: &[u8], size: usize, noise: &[u8]) -> Result<Vec<u8>, PackError> {
    let needed = plain.len().checked_add(LEN).ok_or(PackError::TooLarge {
        content: plain.len(),
        room: size,
    })?;
    if needed > size {
        return Err(PackError::TooLarge {
            content: plain.len(),
            room: size.saturating_sub(LEN),
        });
    }
    let fill = size - needed;
    if noise.len() < fill {
        return Err(PackError::ShortNoise {
            supplied: noise.len(),
            needed: fill,
        });
    }
    let len = u32::try_from(plain.len()).map_err(|_| PackError::TooLarge {
        content: plain.len(),
        room: size,
    })?;

    let mut out = Vec::with_capacity(size);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(plain);
    out.extend_from_slice(&noise[..fill]);
    debug_assert_eq!(out.len(), size);
    Ok(out)
}

/// How much noise [`pad`] will want for content of this length.
#[must_use]
pub const fn noise_needed(content: usize, size: usize) -> usize {
    size.saturating_sub(content + LEN)
}

/// The content back out of a padded block.
///
/// # Errors
///
/// [`PackError::Malformed`] if the block is shorter than its prefix or claims
/// more content than it holds — which is what a wrong key looks like after the
/// AEAD has already failed, and is kept as a distinct error so the two are not
/// confused in a log.
pub fn unpad(padded: &[u8]) -> Result<&[u8], PackError> {
    if padded.len() < LEN {
        return Err(PackError::Malformed);
    }
    let (prefix, rest) = padded.split_at(LEN);
    let len = u32::from_be_bytes(prefix.try_into().expect("four bytes")) as usize;
    rest.get(..len).ok_or(PackError::Malformed)
}
