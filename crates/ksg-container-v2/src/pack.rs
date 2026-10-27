//! The packing pipeline: **compress → pad with noise to a constant size →
//! encrypt**. Plan §2.1 `pack.rs`.
//!
//! # The order is the security argument
//!
//! Each step is there because of the one after it:
//!
//! | Step | Why here |
//! |---|---|
//! | **compress** | fits more content into a size that is fixed anyway |
//! | **pad to a constant** | the size stops depending on the content — which is also what makes compressing before encrypting safe (see [`crate::noise`]) |
//! | **encrypt** | the content stops being readable |
//!
//! Swap the middle two and the compression ratio leaks through the length.
//! Drop the middle one and CRIME applies. The order is not a preference.
//!
//! # The cipher is behind a trait, and not for testing convenience
//!
//! The same reason `ksg-anchor` puts the network behind a trait rather than a
//! client: a container is opened where it is presented, sometimes years later,
//! and an implementation that can only be opened through one particular library
//! has made its own availability the reader's problem.
//!
//! [`ChaCha20Poly1305Aead`] is supplied as the concrete one. **That is a
//! decision the specification did not make**, and it is recorded as such: the
//! spec gives the order and not the primitive. ChaCha20-Poly1305 was chosen for
//! being constant-time in software without hardware assumptions, which suits a
//! container opened on machines nobody chose in advance. An operator preferring
//! AES-GCM changes the profile, not this pipeline.
//!
//! Compression is behind a trait for a weaker reason: the constant size holds
//! whatever the compressor does, so the choice is an efficiency question
//! rather than a security one. The store uses [`Deflate`]; [`NoCompression`]
//! stays for packing where the room is not tight.

use crate::noise;

/// What can go wrong while packing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PackError {
    /// The content does not fit in the room the layout gives it.
    #[error("{content} bytes of content, {room} bytes of room")]
    TooLarge {
        /// How much there is.
        content: usize,
        /// How much fits.
        room: usize,
    },
    /// Too little noise was supplied for the padding.
    #[error("{supplied} bytes of noise supplied, {needed} needed")]
    ShortNoise {
        /// How much arrived.
        supplied: usize,
        /// How much is needed.
        needed: usize,
    },
    /// The padded block does not parse.
    #[error("the padded block is malformed")]
    Malformed,
    /// The AEAD refused: a wrong key, a wrong nonce, or tampering.
    ///
    /// One error for all three on purpose. Which of them it was is exactly what
    /// an attacker would like told apart, and the AEAD itself does not
    /// distinguish them either.
    #[error("decryption failed")]
    Decryption,
    /// The compressor could not undo its own output.
    #[error("decompression failed")]
    Decompression,
}

/// An authenticated cipher, as the pipeline needs it.
pub trait Aead {
    /// The key width in bytes.
    const KEY: usize;
    /// The nonce width in bytes.
    const NONCE: usize;

    /// Encrypts, authenticating `aad` alongside.
    ///
    /// # Errors
    ///
    /// [`PackError::Decryption`] on a key or nonce of the wrong width.
    fn seal(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        plain: &[u8],
    ) -> Result<Vec<u8>, PackError>;

    /// Decrypts, checking `aad`.
    ///
    /// # Errors
    ///
    /// [`PackError::Decryption`] on a wrong key, a wrong nonce, wrong `aad`, or
    /// tampering.
    fn open(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        sealed: &[u8],
    ) -> Result<Vec<u8>, PackError>;
}

/// A compressor.
pub trait Compressor {
    /// Compresses.
    fn compress(&self, plain: &[u8]) -> Vec<u8>;
    /// Decompresses.
    ///
    /// # Errors
    ///
    /// [`PackError::Decompression`] on input this compressor did not produce.
    fn decompress(&self, packed: &[u8]) -> Result<Vec<u8>, PackError>;
}

/// No compression. The default, because the constant size holds regardless.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoCompression;

impl Compressor for NoCompression {
    fn compress(&self, plain: &[u8]) -> Vec<u8> {
        plain.to_vec()
    }
    fn decompress(&self, packed: &[u8]) -> Result<Vec<u8>, PackError> {
        Ok(packed.to_vec())
    }
}

/// DEFLATE in a zlib frame (RFC 1950/1951), the concrete compressor.
///
/// Audit of 30.09, O-2: the container's state is JSON with page content in
/// base64, a third over its size, and the worst case filled the fixed store to
/// 3.68 MiB of 4 MiB. Compressing before the padding takes that third back and
/// more; the padding keeps the size constant whatever the ratio, so the ratio
/// leaks nothing (see [`crate::noise`]).
///
/// Pure Rust with no unsafe code (`miniz_oxide`), and decompression is bounded:
/// output past `limit` is refused, never allocated — a crafted input cannot
/// make the opener swallow memory.
#[derive(Debug, Clone, Copy)]
pub struct Deflate {
    /// The most the decompressed bytes may take.
    pub limit: usize,
}

impl Compressor for Deflate {
    fn compress(&self, plain: &[u8]) -> Vec<u8> {
        miniz_oxide::deflate::compress_to_vec_zlib(plain, 6)
    }

    fn decompress(&self, packed: &[u8]) -> Result<Vec<u8>, PackError> {
        miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(packed, self.limit)
            .map_err(|_| PackError::Decompression)
    }
}

/// ChaCha20-Poly1305, the concrete cipher.
#[derive(Debug, Clone, Copy, Default)]
pub struct ChaCha20Poly1305Aead;

impl Aead for ChaCha20Poly1305Aead {
    const KEY: usize = 32;
    const NONCE: usize = 12;

    fn seal(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        plain: &[u8],
    ) -> Result<Vec<u8>, PackError> {
        use chacha20poly1305::aead::{Aead as _, KeyInit, Payload};
        use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
        // Lengths are checked here rather than converted fallibly or
        // infallibly. `from_slice` panics on a mismatch, and a panic on a
        // wrong-width key is a worse outcome than a refusal — this is a library
        // opened on machines nobody chose in advance.
        if key.len() != Self::KEY || nonce.len() != Self::NONCE {
            return Err(PackError::Decryption);
        }
        let key = Key::from_slice(key);
        let nonce = Nonce::from_slice(nonce);
        ChaCha20Poly1305::new(key)
            .encrypt(nonce, Payload { msg: plain, aad })
            .map_err(|_| PackError::Decryption)
    }

    fn open(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        sealed: &[u8],
    ) -> Result<Vec<u8>, PackError> {
        use chacha20poly1305::aead::{Aead as _, KeyInit, Payload};
        use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
        if key.len() != Self::KEY || nonce.len() != Self::NONCE {
            return Err(PackError::Decryption);
        }
        let key = Key::from_slice(key);
        let nonce = Nonce::from_slice(nonce);
        ChaCha20Poly1305::new(key)
            .decrypt(nonce, Payload { msg: sealed, aad })
            .map_err(|_| PackError::Decryption)
    }
}

/// The pipeline.
#[derive(Debug, Clone, Copy)]
pub struct Packer<A, C> {
    aead: A,
    compressor: C,
    /// The padded size — a constant of the layout, not of the content.
    size: usize,
}

impl<A: Aead, C: Compressor> Packer<A, C> {
    /// A packer that pads everything to `size`.
    pub const fn new(aead: A, compressor: C, size: usize) -> Self {
        Self {
            aead,
            compressor,
            size,
        }
    }

    /// The padded size before encryption.
    pub const fn size(&self) -> usize {
        self.size
    }

    /// How much noise [`Self::seal`] will want.
    pub fn noise_needed(&self, plain: &[u8]) -> usize {
        noise::noise_needed(self.compressor.compress(plain).len(), self.size)
    }

    /// Compress, pad, encrypt.
    ///
    /// # Errors
    ///
    /// [`PackError::TooLarge`], [`PackError::ShortNoise`], or the AEAD's.
    pub fn seal(
        &self,
        plain: &[u8],
        noise_bytes: &[u8],
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, PackError> {
        let compressed = self.compressor.compress(plain);
        let padded = noise::pad(&compressed, self.size, noise_bytes)?;
        self.aead.seal(key, nonce, aad, &padded)
    }

    /// Compress, pad, encrypt — **and then check its own work**.
    ///
    /// `[decision] 12.09` The packing step is not a rule, it is a **worker**: it runs
    /// the three actions in one fixed order and verifies the result before
    /// handing it over.
    ///
    /// # What the check is for
    ///
    /// A packing that silently produced something unopenable would be found
    /// later — when somebody tried to read it, with the original long gone. The
    /// worker opens what it just sealed and compares. One extra pass over the
    /// data buys the guarantee that **nothing leaves this function that cannot
    /// be opened again**.
    ///
    /// # Errors
    ///
    /// Whatever [`Packer::seal`] says, or [`PackError::Decryption`] if the
    /// round trip does not come back equal — which would mean a fault in the
    /// cipher or the padding rather than bad input.
    pub fn seal_checked(
        &self,
        plain: &[u8],
        noise_bytes: &[u8],
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, PackError> {
        let sealed = self.seal(plain, noise_bytes, key, nonce, aad)?;
        let back = self.open(&sealed, key, nonce, aad)?;
        if back != plain {
            return Err(PackError::Decryption);
        }
        Ok(sealed)
    }

    /// Decrypt, unpad, decompress.
    ///
    /// # Errors
    ///
    /// [`PackError::Decryption`] on a wrong key or tampering,
    /// [`PackError::Malformed`] or [`PackError::Decompression`] after that.
    pub fn open(
        &self,
        sealed: &[u8],
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, PackError> {
        let padded = self.aead.open(key, nonce, aad, sealed)?;
        let compressed = noise::unpad(&padded)?;
        self.compressor.decompress(compressed)
    }
}
