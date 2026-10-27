//! Anchors on Base Sepolia with the gas paid by a sponsor: a UserOperation
//! (ERC-4337, EntryPoint 0.6) from a Coinbase Smart Account whose owner is
//! the writer's `--evm-key` (owner's decisions 14.10 "a network where gas is
//! sponsored", 15.10 "A — the key is ours").
//!
//! What a paymaster sponsors is a UserOperation from a smart account, not the
//! plain EIP-1559 transaction of [`crate::evm::Call`]
//! (`[doc:RESEARCH-PAYMASTER]`, fact 1). So the writer on
//! the contract becomes the smart account's address, and the key signs the
//! UserOperation's hash instead of a transaction.
//!
//! Built by hand, like the rest of this crate. The shapes are those of
//! `viem@2.21.32` (`toCoinbaseSmartAccount`, `getUserOperationHash`), and
//! the test vector in `tests/user_op.rs` was made by that library, not by this
//! code.
//!
//! | Piece | What |
//! |---|---|
//! | the account | `getAddress(owners, 0)` of the factory, `owners = [abi.encode(owner)]` |
//! | its creation | `initCode = factory ‖ createAccount(owners, 0)`, only while it has no code |
//! | the call | `execute(target, 0, data)` |
//! | the hash | `keccak(abi.encode(keccak(pack(op)), entryPoint, chainId))` |
//! | the signature | the owner's raw secp256k1 signature of that hash, `r ‖ s ‖ v` (v = 27, 28), wrapped as `(ownerIndex, signatureData)` |

use k256::ecdsa::{RecoveryId, Signature, SigningKey};
use serde_json::{json, Value};

use crate::evm::{hex0x, keccak, selector, Address, EvmError};

/// EntryPoint 0.6 — the one the Coinbase Smart Account runs on
/// (`viem` `entryPoint06Address`; research fact 2).
pub const ENTRY_POINT_V06: Address = [
    0x5f, 0xf1, 0x37, 0xd4, 0xb0, 0xfd, 0xcd, 0x49, 0xdc, 0xa3, 0x0c, 0x7c, 0xf5, 0x7e, 0x57, 0x8a,
    0x02, 0x6d, 0x27, 0x89,
];

/// The Coinbase Smart Account factory (research fact 2).
pub const CB_FACTORY: Address = [
    0x0b, 0xa5, 0xed, 0x0c, 0x6a, 0xa8, 0xc4, 0x90, 0x38, 0xf8, 0x19, 0xe5, 0x87, 0xe2, 0x63, 0x3c,
    0x4a, 0x9f, 0x42, 0x8a,
];

/// The signature a bundler estimates gas with before the real one exists:
/// the shape and length of a real one (`viem` `getStubSignature`).
pub const STUB_SIGNATURE: [u8; 65] = {
    let mut s = [0u8; 65];
    let mut i = 0;
    while i < 15 {
        s[i] = 0xff;
        i += 1;
    }
    s[15] = 0xf0;
    s[32] = 0x7a;
    let mut j = 33;
    while j < 64 {
        s[j] = 0xaa;
        j += 1;
    }
    s[64] = 0x1c;
    s
};

fn word_u128(v: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&v.to_be_bytes());
    w
}

fn word_addr(a: &Address) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a);
    w
}

/// ABI tail of a `bytes`: its length and its bytes, padded to a word.
fn tail_bytes(b: &[u8]) -> Vec<u8> {
    let mut d = word_u128(b.len() as u128).to_vec();
    d.extend_from_slice(b);
    d.resize(d.len() + (32 - b.len() % 32) % 32, 0);
    d
}

/// The owners of a one-owner account: `[abi.encode(owner)]` as `bytes[]`,
/// followed by `nonce` — the arguments of `createAccount` and `getAddress`.
fn owners_args(owner: &Address, nonce: u128) -> Vec<u8> {
    let mut d = word_u128(0x40).to_vec(); // offset of the array
    d.extend_from_slice(&word_u128(nonce));
    d.extend_from_slice(&word_u128(1)); // one owner
    d.extend_from_slice(&word_u128(0x20)); // offset of its bytes, from the array's body
    d.extend_from_slice(&tail_bytes(&word_addr(owner)));
    d
}

/// Call data of the factory's `getAddress(bytes[] owners, uint256 nonce)`.
#[must_use]
pub fn get_address_data(owner: &Address) -> Vec<u8> {
    let mut d = selector("getAddress(bytes[],uint256)").to_vec();
    d.extend_from_slice(&owners_args(owner, 0));
    d
}

/// `initCode` of an account not yet on the chain: the factory, then
/// `createAccount(bytes[] owners, uint256 nonce)`.
#[must_use]
pub fn init_code(owner: &Address) -> Vec<u8> {
    let mut d = CB_FACTORY.to_vec();
    d.extend_from_slice(&selector("createAccount(bytes[],uint256)"));
    d.extend_from_slice(&owners_args(owner, 0));
    d
}

/// Call data of the account's `execute(address target, uint256 value, bytes data)`.
#[must_use]
pub fn execute_data(target: &Address, data: &[u8]) -> Vec<u8> {
    let mut d = selector("execute(address,uint256,bytes)").to_vec();
    d.extend_from_slice(&word_addr(target));
    d.extend_from_slice(&word_u128(0));
    d.extend_from_slice(&word_u128(0x60));
    d.extend_from_slice(&tail_bytes(data));
    d
}

/// Call data of the EntryPoint's `getNonce(address sender, uint192 key)`, key 0.
#[must_use]
pub fn get_nonce_data(sender: &Address) -> Vec<u8> {
    let mut d = selector("getNonce(address,uint192)").to_vec();
    d.extend_from_slice(&word_addr(sender));
    d.extend_from_slice(&[0u8; 32]);
    d
}

/// Reads the inner call back out of `execute` call data: the mirror of
/// [`execute_data`], for a node that has to carry the call out.
#[must_use]
pub fn decode_execute(d: &[u8]) -> Option<(Address, Vec<u8>)> {
    if d.get(..4)? != selector("execute(address,uint256,bytes)") {
        return None;
    }
    let target: Address = d.get(4 + 12..4 + 32)?.try_into().ok()?;
    let len = usize::try_from(u128::from_be_bytes(
        d.get(4 + 96 + 16..4 + 128)?.try_into().ok()?,
    ))
    .ok()?;
    Some((target, d.get(4 + 128..4 + 128 + len)?.to_vec()))
}

/// The signature as the account reads it: `abi.encode((uint8 ownerIndex,
/// bytes signatureData))`, owner 0.
#[must_use]
pub fn wrap_signature(sig: &[u8]) -> Vec<u8> {
    let mut d = word_u128(0x20).to_vec(); // the tuple is dynamic
    d.extend_from_slice(&word_u128(0)); // ownerIndex
    d.extend_from_slice(&word_u128(0x40)); // offset of signatureData in the tuple
    d.extend_from_slice(&tail_bytes(sig));
    d
}

/// A UserOperation of EntryPoint 0.6.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserOp {
    /// The smart account.
    pub sender: Address,
    /// The EntryPoint's nonce of the account, a 256-bit word.
    pub nonce: [u8; 32],
    /// Factory and creation call while the account has no code; empty after.
    pub init_code: Vec<u8>,
    /// What the account executes.
    pub call_data: Vec<u8>,
    /// Gas of the call.
    pub call_gas_limit: u128,
    /// Gas of the account's and the paymaster's checks.
    pub verification_gas_limit: u128,
    /// Gas the bundler is paid for outside the call.
    pub pre_verification_gas: u128,
    /// As in EIP-1559.
    pub max_fee_per_gas: u128,
    /// As in EIP-1559.
    pub max_priority_fee_per_gas: u128,
    /// The paymaster and its data: who pays the gas.
    pub paymaster_and_data: Vec<u8>,
    /// The wrapped owner's signature.
    pub signature: Vec<u8>,
}

impl UserOp {
    /// The hash the owner signs: `keccak(abi.encode(keccak(pack), entryPoint, chainId))`.
    #[must_use]
    pub fn hash(&self, entry_point: &Address, chain_id: u64) -> [u8; 32] {
        let mut pack = word_addr(&self.sender).to_vec();
        pack.extend_from_slice(&self.nonce);
        pack.extend_from_slice(&keccak(&self.init_code));
        pack.extend_from_slice(&keccak(&self.call_data));
        for v in [
            self.call_gas_limit,
            self.verification_gas_limit,
            self.pre_verification_gas,
            self.max_fee_per_gas,
            self.max_priority_fee_per_gas,
        ] {
            pack.extend_from_slice(&word_u128(v));
        }
        pack.extend_from_slice(&keccak(&self.paymaster_and_data));
        let mut outer = keccak(&pack).to_vec();
        outer.extend_from_slice(&word_addr(entry_point));
        outer.extend_from_slice(&word_u128(u128::from(chain_id)));
        keccak(&outer)
    }

    /// Signs as the account's owner: the raw signature of [`Self::hash`],
    /// `r ‖ s ‖ v`, wrapped.
    ///
    /// # Errors
    ///
    /// [`EvmError::Sign`] if the signer fails.
    pub fn sign(&mut self, key: &SigningKey, chain_id: u64) -> Result<(), EvmError> {
        let h = self.hash(&ENTRY_POINT_V06, chain_id);
        let (sig, rec): (Signature, RecoveryId) = key
            .sign_prehash_recoverable(&h)
            .map_err(|_| EvmError::Sign)?;
        let (sig, rec) = match sig.normalize_s() {
            Some(n) => (n, RecoveryId::new(!rec.is_y_odd(), rec.is_x_reduced())),
            None => (sig, rec),
        };
        let mut raw = sig.to_bytes().to_vec();
        raw.push(27 + u8::from(rec.is_y_odd()));
        self.signature = wrap_signature(&raw);
        Ok(())
    }

    /// The JSON a bundler and a paymaster take (EntryPoint 0.6 field names).
    #[must_use]
    pub fn to_json(&self) -> Value {
        let q = |v: u128| format!("0x{v:x}");
        let nonce = u128::from_be_bytes(self.nonce[16..].try_into().unwrap_or([0; 16]));
        json!({
            "sender": hex0x(&self.sender),
            "nonce": if self.nonce[..16].iter().all(|b| *b == 0) { q(nonce) } else { hex0x(&self.nonce) },
            "initCode": hex0x(&self.init_code),
            "callData": hex0x(&self.call_data),
            "callGasLimit": q(self.call_gas_limit),
            "verificationGasLimit": q(self.verification_gas_limit),
            "preVerificationGas": q(self.pre_verification_gas),
            "maxFeePerGas": q(self.max_fee_per_gas),
            "maxPriorityFeePerGas": q(self.max_priority_fee_per_gas),
            "paymasterAndData": hex0x(&self.paymaster_and_data),
            "signature": hex0x(&self.signature),
        })
    }
}
