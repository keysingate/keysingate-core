//! A Solana memo transaction, built and signed without an SDK. Item P-6.
//!
//! One legacy transaction, one instruction: the SPL Memo program (v2) with no
//! accounts, the memo as its data, the payer as the only signer. That is the
//! whole of what anchoring a page needs, and writing it out keeps the
//! reference free of a client library whose release cycle is not ours.
//!
//! ```text
//! transaction = shortvec(1) ‖ signature(64) ‖ message
//! message     = header[1, 0, 1] ‖ shortvec(2) ‖ payer(32) ‖ memo_program(32)
//!             ‖ recent_blockhash(32)
//!             ‖ shortvec(1) ‖ program_index(1) ‖ shortvec(0) ‖ shortvec(len) ‖ memo
//! ```
//!
//! The payer's key comes from a file in the Solana CLI's format: a JSON array
//! of 64 numbers, secret seed then public key.

use ed25519_dalek::{Signer as _, SigningKey, Verifier as _, VerifyingKey};
use zeroize::Zeroizing;

/// The SPL Memo program, version 2.
pub const MEMO_PROGRAM: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

/// The longest memo this module builds: the transaction must stay under
/// Solana's 1232-byte packet.
pub const MEMO_MAX: usize = 566;

/// Why a transaction was not built or not read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TxError {
    /// The key file is not 64 numbers whose second half is the first half's
    /// public key.
    #[error("key file: {0}")]
    KeyFile(&'static str),
    /// The memo is empty or too long.
    #[error("memo of {0} bytes")]
    MemoSize(usize),
    /// Bytes that are not a transaction of this shape.
    #[error("transaction: {0}")]
    Malformed(&'static str),
    /// The signature does not verify.
    #[error("the signature does not verify")]
    BadSignature,
}

fn memo_program() -> [u8; 32] {
    let v = bs58::decode(MEMO_PROGRAM)
        .into_vec()
        .expect("a constant base58 key");
    v.try_into().expect("32 bytes")
}

fn shortvec(out: &mut Vec<u8>, mut n: usize) {
    loop {
        let mut b = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(b);
            return;
        }
        b |= 0x80;
        out.push(b);
    }
}

fn read_shortvec(b: &[u8], at: &mut usize) -> Result<usize, TxError> {
    let mut n = 0usize;
    for shift in [0, 7, 14] {
        let byte = *b.get(*at).ok_or(TxError::Malformed("short"))?;
        *at += 1;
        n |= usize::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(n);
        }
    }
    Err(TxError::Malformed("length too long"))
}

/// The payer's key from a Solana CLI key file.
///
/// # Errors
///
/// [`TxError::KeyFile`] when the file is not such a key.
pub fn key_from_file_bytes(bytes: &[u8]) -> Result<SigningKey, TxError> {
    let nums: Zeroizing<Vec<u8>> = Zeroizing::new(
        serde_json::from_slice(bytes).map_err(|_| TxError::KeyFile("not a JSON array of bytes"))?,
    );
    if nums.len() != 64 {
        return Err(TxError::KeyFile("not 64 bytes"));
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&nums[..32]);
    let key = SigningKey::from_bytes(&seed);
    if key.verifying_key().as_bytes()[..] != nums[32..] {
        return Err(TxError::KeyFile(
            "the public half is not of the secret half",
        ));
    }
    Ok(key)
}

/// A key's address: its public key in base58.
#[must_use]
pub fn address(key: &VerifyingKey) -> String {
    bs58::encode(key.as_bytes()).into_string()
}

/// The message both a signer and a reader see.
fn message(payer: &VerifyingKey, blockhash: &[u8; 32], memo: &[u8]) -> Vec<u8> {
    let mut m = vec![1, 0, 1];
    shortvec(&mut m, 2);
    m.extend_from_slice(payer.as_bytes());
    m.extend_from_slice(&memo_program());
    m.extend_from_slice(blockhash);
    shortvec(&mut m, 1);
    m.push(1);
    shortvec(&mut m, 0);
    shortvec(&mut m, memo.len());
    m.extend_from_slice(memo);
    m
}

/// A signed memo transaction and its signature in base58 — the signature is
/// how the network addresses it.
///
/// # Errors
///
/// [`TxError::MemoSize`] for an empty memo or one over [`MEMO_MAX`].
pub fn memo_transaction(
    payer: &SigningKey,
    blockhash: &[u8; 32],
    memo: &[u8],
) -> Result<(Vec<u8>, String), TxError> {
    if memo.is_empty() || memo.len() > MEMO_MAX {
        return Err(TxError::MemoSize(memo.len()));
    }
    let msg = message(&payer.verifying_key(), blockhash, memo);
    let sig = payer.sign(&msg);
    let mut tx = Vec::with_capacity(1 + 64 + msg.len());
    shortvec(&mut tx, 1);
    tx.extend_from_slice(&sig.to_bytes());
    tx.extend_from_slice(&msg);
    Ok((tx, bs58::encode(sig.to_bytes()).into_string()))
}

/// What a memo transaction carries, once read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoTx {
    /// The payer's address.
    pub payer: String,
    /// The recent blockhash, base58.
    pub blockhash: String,
    /// The memo.
    pub memo: Vec<u8>,
    /// The signature, base58.
    pub signature: String,
}

/// Reads back a transaction of exactly the shape [`memo_transaction`] builds,
/// checking its signature.
///
/// # Errors
///
/// [`TxError::Malformed`] for any other shape; [`TxError::BadSignature`].
pub fn read_memo_transaction(tx: &[u8]) -> Result<MemoTx, TxError> {
    let mut at = 0;
    if read_shortvec(tx, &mut at)? != 1 {
        return Err(TxError::Malformed("not one signature"));
    }
    let sig: [u8; 64] = tx
        .get(at..at + 64)
        .ok_or(TxError::Malformed("short"))?
        .try_into()
        .expect("64");
    at += 64;
    let msg = &tx[at..];
    let mut m = 0;
    if msg.get(..3) != Some(&[1, 0, 1]) {
        return Err(TxError::Malformed("header"));
    }
    m += 3;
    if read_shortvec(msg, &mut m)? != 2 {
        return Err(TxError::Malformed("not two accounts"));
    }
    let payer: [u8; 32] = msg
        .get(m..m + 32)
        .ok_or(TxError::Malformed("short"))?
        .try_into()
        .expect("32");
    m += 32;
    if msg.get(m..m + 32) != Some(&memo_program()[..]) {
        return Err(TxError::Malformed("not the memo program"));
    }
    m += 32;
    let blockhash = msg.get(m..m + 32).ok_or(TxError::Malformed("short"))?;
    m += 32;
    if read_shortvec(msg, &mut m)? != 1 || msg.get(m) != Some(&1) {
        return Err(TxError::Malformed("not one memo instruction"));
    }
    m += 1;
    if read_shortvec(msg, &mut m)? != 0 {
        return Err(TxError::Malformed("memo with accounts"));
    }
    let len = read_shortvec(msg, &mut m)?;
    let memo = msg.get(m..m + len).ok_or(TxError::Malformed("short"))?;
    if m + len != msg.len() {
        return Err(TxError::Malformed("trailing bytes"));
    }
    let key = VerifyingKey::from_bytes(&payer).map_err(|_| TxError::Malformed("payer key"))?;
    key.verify(msg, &ed25519_dalek::Signature::from_bytes(&sig))
        .map_err(|_| TxError::BadSignature)?;
    Ok(MemoTx {
        payer: bs58::encode(payer).into_string(),
        blockhash: bs58::encode(blockhash).into_string(),
        memo: memo.to_vec(),
        signature: bs58::encode(sig).into_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn built_and_read_back() {
        let bh = [3u8; 32];
        let memo = "ksg:pg:v1 ".repeat(20); // over 127 bytes: a two-byte length
        let (tx, sig) = memo_transaction(&key(), &bh, memo.as_bytes()).unwrap();
        let r = read_memo_transaction(&tx).unwrap();
        assert_eq!(r.memo, memo.as_bytes());
        assert_eq!(r.signature, sig);
        assert_eq!(r.payer, address(&key().verifying_key()));
        assert_eq!(r.blockhash, bs58::encode(bh).into_string());
        assert!(tx.len() <= 1232);
    }

    #[test]
    fn a_changed_byte_does_not_verify() {
        let (mut tx, _) = memo_transaction(&key(), &[3u8; 32], b"hello").unwrap();
        let last = tx.len() - 1;
        tx[last] ^= 1;
        assert_eq!(read_memo_transaction(&tx), Err(TxError::BadSignature));
    }

    #[test]
    fn memo_bounds() {
        assert!(memo_transaction(&key(), &[0; 32], b"").is_err());
        assert!(memo_transaction(&key(), &[0; 32], &vec![b'a'; MEMO_MAX + 1]).is_err());
        let (tx, _) = memo_transaction(&key(), &[0; 32], &vec![b'a'; MEMO_MAX]).unwrap();
        assert!(tx.len() <= 1232, "{}", tx.len());
    }

    #[test]
    fn the_key_file_of_the_solana_cli() {
        let k = key();
        let mut all = k.to_bytes().to_vec();
        all.extend_from_slice(k.verifying_key().as_bytes());
        let json = serde_json::to_vec(&all).unwrap();
        assert_eq!(key_from_file_bytes(&json).unwrap().to_bytes(), k.to_bytes());
        all[40] ^= 1;
        assert!(key_from_file_bytes(&serde_json::to_vec(&all).unwrap()).is_err());
        assert!(key_from_file_bytes(b"[1,2,3]").is_err());
    }

    #[test]
    fn shortvec_matches_solana() {
        // Values from the Solana short_vec documentation.
        for (n, want) in [
            (0usize, vec![0u8]),
            (0x7f, vec![0x7f]),
            (0x80, vec![0x80, 0x01]),
            (0x3fff, vec![0xff, 0x7f]),
            (0x4000, vec![0x80, 0x80, 0x01]),
        ] {
            let mut v = Vec::new();
            shortvec(&mut v, n);
            assert_eq!(v, want, "{n}");
            let mut at = 0;
            assert_eq!(read_shortvec(&v, &mut at).unwrap(), n);
        }
    }
}
