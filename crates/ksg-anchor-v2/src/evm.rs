//! Writing anchors on an EVM network — Base Sepolia (owner's decisions 14.10:
//! all anchors of `bare` and `light` on Base Sepolia; Pro stays on Solana and
//! may add Base as a second network).
//!
//! What is written is a call of `KsgAnchors.anchor(container, prev, next)`
//! (`core-v2/contracts/KsgAnchors.sol`): the contract keeps the container's
//! last anchor and refuses one that does not continue it. A copy of a
//! container, or a rolled-back file, learns what it is from that refusal.
//!
//! Built by hand, without an SDK, like the Solana memo next door: the EIP-1559
//! transaction (type 2), its RLP, its secp256k1 signature, the ABI of the three
//! functions the contract has. The gas sponsor (a paymaster, ERC-4337) is a
//! separate route and not in this module; here the sender pays its own gas.

use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};

/// A secp256k1 signing key, as the writer holds it.
pub type EvmKey = SigningKey;
use sha3::{Digest, Keccak256};

/// Base Sepolia's chain id.
pub const BASE_SEPOLIA_CHAIN_ID: u64 = 84_532;

/// `KsgAnchors` as built by `scripts/build_contract.sh` (solc 0.8.28), hex.
pub const KSG_ANCHORS_BYTECODE: &str = include_str!("../../../contracts/KsgAnchors.bin");

/// Keccak-256.
#[must_use]
pub fn keccak(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

/// The first four bytes of the signature's hash.
#[must_use]
pub fn selector(signature: &str) -> [u8; 4] {
    let h = keccak(signature.as_bytes());
    [h[0], h[1], h[2], h[3]]
}

/// A 20-byte account address.
pub type Address = [u8; 20];

/// The address of a secp256k1 key: the last 20 bytes of the hash of the
/// uncompressed public key without its prefix byte.
#[must_use]
pub fn address_of(key: &VerifyingKey) -> Address {
    let point = key.to_encoded_point(false);
    let h = keccak(&point.as_bytes()[1..]);
    let mut a = [0u8; 20];
    a.copy_from_slice(&h[12..]);
    a
}

/// Signs a 32-byte digest with an EVM key: `r ‖ s ‖ v`, `v` = 27 or 28 —
/// what [`recover`] reads back to the signer's address. Used where a
/// document names its signer by address (the issuance label of a `bare`,
/// owner's decision 17.10).
///
/// # Errors
///
/// [`EvmError::Sign`] if the signer fails.
pub fn sign_digest(key: &SigningKey, digest: &[u8; 32]) -> Result<[u8; 65], EvmError> {
    let (sig, rec): (Signature, RecoveryId) = key
        .sign_prehash_recoverable(digest)
        .map_err(|_| EvmError::Sign)?;
    let (sig, rec) = match sig.normalize_s() {
        Some(n) => (n, RecoveryId::new(!rec.is_y_odd(), rec.is_x_reduced())),
        None => (sig, rec),
    };
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(&sig.to_bytes());
    out[64] = 27 + u8::from(rec.is_y_odd());
    Ok(out)
}

/// The address that signed `digest` with [`sign_digest`]; `None` for a
/// signature that recovers to no key.
#[must_use]
pub fn recover(digest: &[u8; 32], sig: &[u8; 65]) -> Option<Address> {
    let s = Signature::from_slice(&sig[..64]).ok()?;
    let rec = RecoveryId::from_byte(sig[64].checked_sub(27)?)?;
    let key = VerifyingKey::recover_from_prehash(digest, &s, rec).ok()?;
    Some(address_of(&key))
}

/// What went wrong building or reading a call.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EvmError {
    /// The secret is not a valid secp256k1 scalar.
    #[error("the key is not a valid secp256k1 secret")]
    BadKey,
    /// Signing failed.
    #[error("signing failed")]
    Sign,
    /// A return value of the wrong length.
    #[error("the node returned {0} bytes where 96 were due")]
    BadReturn(usize),
    /// Text that is not hex.
    #[error("not hex: {0}")]
    Hex(String),
}

/// A secp256k1 key from 32 secret bytes.
///
/// # Errors
///
/// [`EvmError::BadKey`] for zero or a value past the group order.
pub fn key_from_secret(secret: &[u8; 32]) -> Result<SigningKey, EvmError> {
    SigningKey::from_bytes(secret.into()).map_err(|_| EvmError::BadKey)
}

// --- RLP -------------------------------------------------------------------

fn rlp_len(prefix_small: u8, len: usize, out: &mut Vec<u8>) {
    if len < 56 {
        out.push(prefix_small + u8::try_from(len).unwrap_or(0));
    } else {
        let be = len.to_be_bytes();
        let skip = be.iter().take_while(|b| **b == 0).count();
        let n = be.len() - skip;
        out.push(prefix_small + 55 + u8::try_from(n).unwrap_or(0));
        out.extend_from_slice(&be[skip..]);
    }
}

/// RLP of a byte string.
#[must_use]
pub fn rlp_bytes(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len() + 9);
    if b.len() == 1 && b[0] < 0x80 {
        out.push(b[0]);
    } else {
        rlp_len(0x80, b.len(), &mut out);
        out.extend_from_slice(b);
    }
    out
}

/// RLP of an unsigned integer: big-endian, no leading zeros, zero as empty.
#[must_use]
pub fn rlp_uint(v: u128) -> Vec<u8> {
    let be = v.to_be_bytes();
    let skip = be.iter().take_while(|b| **b == 0).count();
    rlp_bytes(&be[skip..])
}

/// RLP of a list of already encoded items.
#[must_use]
pub fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let body: Vec<u8> = items.concat();
    let mut out = Vec::with_capacity(body.len() + 9);
    rlp_len(0xc0, body.len(), &mut out);
    out.extend_from_slice(&body);
    out
}

// --- the transaction ---------------------------------------------------------

/// An EIP-1559 (type 2) contract call, value zero, empty access list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    /// The chain.
    pub chain_id: u64,
    /// The sender's nonce.
    pub nonce: u64,
    /// The tip, wei per gas.
    pub max_priority_fee_per_gas: u128,
    /// The fee cap, wei per gas.
    pub max_fee_per_gas: u128,
    /// The gas limit.
    pub gas_limit: u64,
    /// The contract.
    pub to: Address,
    /// The call data.
    pub data: Vec<u8>,
}

impl Call {
    fn fields(&self) -> Vec<Vec<u8>> {
        vec![
            rlp_uint(u128::from(self.chain_id)),
            rlp_uint(u128::from(self.nonce)),
            rlp_uint(self.max_priority_fee_per_gas),
            rlp_uint(self.max_fee_per_gas),
            rlp_uint(u128::from(self.gas_limit)),
            rlp_bytes(&self.to),
            rlp_uint(0),
            rlp_bytes(&self.data),
            rlp_list(&[]),
        ]
    }

    /// The hash the sender signs: `keccak(0x02 ‖ rlp(fields))`.
    #[must_use]
    pub fn signing_hash(&self) -> [u8; 32] {
        let mut b = vec![0x02];
        b.extend_from_slice(&rlp_list(&self.fields()));
        keccak(&b)
    }

    /// The signed transaction, ready for `eth_sendRawTransaction`, and its hash.
    ///
    /// # Errors
    ///
    /// [`EvmError::Sign`] if the signer fails.
    pub fn sign(&self, key: &SigningKey) -> Result<(Vec<u8>, [u8; 32]), EvmError> {
        let (sig, rec): (Signature, RecoveryId) = key
            .sign_prehash_recoverable(&self.signing_hash())
            .map_err(|_| EvmError::Sign)?;
        // Ethereum takes only low-s signatures; k256 signs low-s already, and
        // normalising again is a no-op that keeps the rule visible.
        let (sig, rec) = match sig.normalize_s() {
            Some(n) => (n, RecoveryId::new(!rec.is_y_odd(), rec.is_x_reduced())),
            None => (sig, rec),
        };
        let (r, s) = sig.split_bytes();
        let mut fields = self.fields();
        fields.push(rlp_uint(u128::from(rec.is_y_odd())));
        fields.push(rlp_bytes(strip(&r)));
        fields.push(rlp_bytes(strip(&s)));
        let mut raw = vec![0x02];
        raw.extend_from_slice(&rlp_list(&fields));
        let hash = keccak(&raw);
        Ok((raw, hash))
    }
}

fn strip(b: &[u8]) -> &[u8] {
    let skip = b.iter().take_while(|x| **x == 0).count();
    &b[skip..]
}

// --- the contract's ABI ------------------------------------------------------

/// Call data of `anchor(bytes32 container, bytes32 prev, bytes32 next)`.
#[must_use]
pub fn anchor_data(container: &[u8; 32], prev: &[u8; 32], next: &[u8; 32]) -> Vec<u8> {
    let mut d = selector("anchor(bytes32,bytes32,bytes32)").to_vec();
    d.extend_from_slice(container);
    d.extend_from_slice(prev);
    d.extend_from_slice(next);
    d
}

/// Call data of `handOver(bytes32 container, address to)`.
#[must_use]
pub fn hand_over_data(container: &[u8; 32], to: &Address) -> Vec<u8> {
    let mut d = selector("handOver(bytes32,address)").to_vec();
    d.extend_from_slice(container);
    d.extend_from_slice(&[0u8; 12]);
    d.extend_from_slice(to);
    d
}

/// Call data of `note(bytes32 kind, bytes data)`: a note kept in the log.
#[must_use]
pub fn note_data(kind: &[u8; 32], data: &[u8]) -> Vec<u8> {
    let mut d = selector("note(bytes32,bytes)").to_vec();
    d.extend_from_slice(kind);
    let mut off = [0u8; 32];
    off[31] = 0x40;
    d.extend_from_slice(&off);
    let mut len = [0u8; 32];
    len[24..].copy_from_slice(&(data.len() as u64).to_be_bytes());
    d.extend_from_slice(&len);
    d.extend_from_slice(data);
    d.resize(d.len() + (32 - data.len() % 32) % 32, 0);
    d
}

/// The topic of a note kind: keccak of its tag, e.g. `ksg:ia:v1`.
#[must_use]
pub fn note_kind(tag: &str) -> [u8; 32] {
    keccak(tag.as_bytes())
}

/// Call data of `head(bytes32 container)`.
#[must_use]
pub fn head_data(container: &[u8; 32]) -> Vec<u8> {
    let mut d = selector("head(bytes32)").to_vec();
    d.extend_from_slice(container);
    d
}

/// A container's head as the contract keeps it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Head {
    /// The last anchor; zero before the first.
    pub last: [u8; 32],
    /// Who may write; zero before the first anchor.
    pub writer: Address,
    /// How many anchors the container has.
    pub count: u64,
}

/// Reads the return value of `head`.
///
/// # Errors
///
/// [`EvmError::BadReturn`] if it is not three words.
pub fn decode_head(ret: &[u8]) -> Result<Head, EvmError> {
    if ret.len() != 96 {
        return Err(EvmError::BadReturn(ret.len()));
    }
    let mut last = [0u8; 32];
    last.copy_from_slice(&ret[..32]);
    let mut writer = [0u8; 20];
    writer.copy_from_slice(&ret[44..64]);
    let mut c = [0u8; 8];
    c.copy_from_slice(&ret[88..96]);
    Ok(Head {
        last,
        writer,
        count: u64::from_be_bytes(c),
    })
}

/// Why the contract refused a call, read from its revert data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The anchor was zero.
    ZeroAnchor,
    /// The caller is not the container's writer.
    NotWriter(Address),
    /// `prev` is not the container's last anchor — the caller holds a copy or
    /// a rolled-back file.
    StalePredecessor {
        /// The contract's head.
        head: [u8; 32],
        /// What the caller said came before.
        presented: [u8; 32],
    },
}

/// Reads the contract's revert data; `None` for anything it does not raise.
#[must_use]
pub fn decode_refusal(data: &[u8]) -> Option<Refusal> {
    if data.len() < 4 {
        return None;
    }
    let (sel, args) = data.split_at(4);
    if sel == selector("ZeroAnchor()") {
        return Some(Refusal::ZeroAnchor);
    }
    if sel == selector("NotWriter(address)") && args.len() == 32 {
        let mut a = [0u8; 20];
        a.copy_from_slice(&args[12..]);
        return Some(Refusal::NotWriter(a));
    }
    if sel == selector("StalePredecessor(bytes32,bytes32)") && args.len() == 64 {
        let mut head = [0u8; 32];
        let mut presented = [0u8; 32];
        head.copy_from_slice(&args[..32]);
        presented.copy_from_slice(&args[32..]);
        return Some(Refusal::StalePredecessor { head, presented });
    }
    None
}

/// `0x`-prefixed lowercase hex.
#[must_use]
pub fn hex0x(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

/// Bytes from `0x`-prefixed (or bare) hex.
///
/// # Errors
///
/// [`EvmError::Hex`] for anything else.
pub fn unhex(s: &str) -> Result<Vec<u8>, EvmError> {
    hex::decode(s.trim().trim_start_matches("0x")).map_err(|_| EvmError::Hex(s.to_owned()))
}
