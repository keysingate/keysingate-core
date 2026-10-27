//! The [`ChainSender`] on Solana: the adapter the queue was written against.
//!
//! One sender per payer. The holder pays the gas (`[decision]` 19.09,
//! CT-04): the payer's key is the holder's, kept by the service only to sign
//! the fee of the holder's own memos.
//!
//! | Queue asks | Node is asked |
//! |---|---|
//! | send a memo | `getLatestBlockhash` (finalized), then `sendTransaction` with preflight |
//! | where does it stand | `getSignatureStatuses` with history; unknown → `isBlockhashValid`; finalized → `getTransaction` for the slot and block time |
//!
//! A refusal the node states — no funds for the fee — is [`SendError::Refused`];
//! anything else (no answer, rate limit, a node behind) is
//! [`SendError::Transient`]. The queue retries both; the distinction is for
//! the operator.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use ksg_anchor_v2::solana_tx::{address, key_from_file_bytes, memo_transaction};
use ksg_verify_v2::solana::{check_cluster, get_transaction, Rpc};
use serde_json::{json, Value};

/// The value at a JSON pointer, `null` where there is none.
fn at<'a>(v: &'a Value, pointer: &str) -> &'a Value {
    v.pointer(pointer).unwrap_or(&Value::Null)
}

use crate::anchoring::{ChainSender, Landing, SendError, Sent};

/// Sends memos paid by one payer, through one node.
pub struct SolanaSender {
    rpc: Box<dyn Rpc + Send>,
    key: SigningKey,
    cluster: String,
    address: String,
}

impl core::fmt::Debug for SolanaSender {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SolanaSender({} on {})", self.address, self.cluster)
    }
}

/// The node's words for "the payer cannot pay": a refusal, not a hiccup.
fn classify(e: String) -> SendError {
    let l = e.to_ascii_lowercase();
    if [
        "insufficient",
        "prior credit",
        "debit an account",
        "insufficientfunds",
    ]
    .iter()
    .any(|w| l.contains(w))
    {
        SendError::Refused(e)
    } else {
        SendError::Transient(e)
    }
}

impl SolanaSender {
    /// A sender through `rpc`, which must be a node of `cluster` (asked for
    /// its genesis hash), paying with the payer key in `key_file` — the
    /// Solana CLI's format.
    ///
    /// # Errors
    ///
    /// The node is of another cluster or did not answer; the key file is not
    /// a key.
    pub fn new(rpc: Box<dyn Rpc + Send>, cluster: &str, key_file: &[u8]) -> Result<Self, String> {
        check_cluster(rpc.as_ref(), cluster)?;
        let key = key_from_file_bytes(key_file).map_err(|e| format!("payer key: {e}"))?;
        Ok(Self {
            address: address(&key.verifying_key()),
            rpc,
            key,
            cluster: cluster.to_owned(),
        })
    }

    /// The payer's address.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }

    /// The payer's balance in lamports.
    ///
    /// # Errors
    ///
    /// The node did not answer.
    pub fn balance(&self) -> Result<u64, String> {
        let v = self.rpc.call(
            "getBalance",
            json!([self.address, {"commitment": "finalized"}]),
        )?;
        at(&v, "/value")
            .as_u64()
            .ok_or_else(|| "getBalance: no value".into())
    }
}

impl ChainSender for SolanaSender {
    fn cluster(&self) -> &str {
        &self.cluster
    }

    fn payer(&self) -> Option<String> {
        Some(self.address.clone())
    }

    fn send_memo(&mut self, memo: &str) -> Result<Sent, SendError> {
        let bh = self
            .rpc
            .call("getLatestBlockhash", json!([{"commitment": "finalized"}]))
            .map_err(classify)?;
        let blockhash = at(&bh, "/value/blockhash")
            .as_str()
            .ok_or_else(|| SendError::Transient("getLatestBlockhash: no blockhash".into()))?
            .to_owned();
        let bytes: [u8; 32] = bs58::decode(&blockhash)
            .into_vec()
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| SendError::Transient("getLatestBlockhash: not 32 bytes".into()))?;
        let (tx, signature) = memo_transaction(&self.key, &bytes, memo.as_bytes())
            .map_err(|e| SendError::Refused(format!("the memo transaction: {e}")))?;
        let answer = self
            .rpc
            .call(
                "sendTransaction",
                json!([B64.encode(&tx), {"encoding": "base64", "preflightCommitment": "confirmed"}]),
            )
            .map_err(classify)?;
        if answer.as_str() != Some(signature.as_str()) {
            return Err(SendError::Transient(format!(
                "sendTransaction: the node answered {answer}"
            )));
        }
        Ok(Sent {
            signature,
            blockhash,
        })
    }

    fn landing(&mut self, sent: &Sent) -> Result<Landing, SendError> {
        let st = self
            .rpc
            .call(
                "getSignatureStatuses",
                json!([[sent.signature], {"searchTransactionHistory": true}]),
            )
            .map_err(SendError::Transient)?;
        let s = at(&st, "/value/0");
        if s.is_null() {
            let valid = self
                .rpc
                .call(
                    "isBlockhashValid",
                    json!([sent.blockhash, {"commitment": "processed"}]),
                )
                .map_err(SendError::Transient)?;
            return Ok(match at(&valid, "/value").as_bool() {
                Some(false) => Landing::Dropped,
                _ => Landing::Pending,
            });
        }
        if !at(s, "/err").is_null() {
            return Ok(Landing::Failed(at(s, "/err").to_string()));
        }
        if at(s, "/confirmationStatus").as_str() != Some("finalized") {
            return Ok(Landing::Pending);
        }
        Ok(
            match get_transaction(self.rpc.as_ref(), &sent.signature)
                .map_err(SendError::Transient)?
            {
                Some(t) => Landing::Landed {
                    slot: t.slot,
                    block_time: t.block_time,
                },
                None => Landing::Pending,
            },
        )
    }
}
