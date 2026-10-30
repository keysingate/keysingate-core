//! Anchoring `light` on Base Sepolia, and the copy check that comes with it
//! (owner's decisions 14.10: minimal anchors for `light`, all anchors of
//! `bare` and `light` on Base Sepolia).
//!
//! # The schedule — the minimal anchors, not the minimum of the minimum
//!
//! | Anchor | When |
//! |---|---|
//! | Ya-1 | printing: the status record the container is born with |
//! | Ya-2 | initiation: the client's key is on |
//! | before a value | a pointwise export and a transfer of rights go out only on a fresh anchor |
//! | every 10 | after ten records with no anchor the eleventh waits for the network (owner's decision 03.10: ten offline records are allowed) |
//!
//! What is anchored is the hash of the container's newest signed thing — its
//! top seal, else its status head — so an anchor exists only if the parties
//! signed what it commits to. The key on the contract is blind:
//! `sha256(tag ‖ template ‖ salt)`, the salt made at printing and kept in
//! `container.json` (owner's decision 15.10 "B", the blind key: the sponsor's proxy and the
//! chain do not see the template).
//!
//! # The copy check
//!
//! The contract keeps the container's last anchor and refuses an anchor that
//! does not continue it (`core-v2/contracts/KsgAnchors.sol`). A file whose last
//! anchor is behind the head is a copy, or an older file of the same
//! container: everything but the full export is refused (owner's decisions
//! 03.10, 05.10). The check runs when the container opens, if the network
//! answers, and again whenever an anchor is due.
//!
//! # Limits, stated where the code is
//!
//! * Gas: by default the sender pays its own from `--evm-key`. With
//!   `--gas sponsor` at printing (`sponsored` in `container.json`) the
//!   writer is the Coinbase Smart Account owned by `--evm-key`, and anchors
//!   go as UserOperations through the bundler and paymaster at
//!   `KSG_PAYMASTER_URL` (ERC-4337, owner's decisions 14.10, 15.10 "A";
//!   `ksg_anchor_v2::user_op`). The address carries the sponsor's key, so it
//!   is read from the environment and never written down. The route is fixed
//!   at printing: the writer's address differs between the two.
//! * On the stand the EVM key is a stand file like the other stand keys
//!   (`[decision]` 07.10, 25.10: the stand is for tests only).
//! * The mobile half's commitment goes on the chain right after the first
//!   anchor that follows initiation, from the same key: a declaration of loss
//!   is read only against a commitment the container's writer put (E-19).
//! * A transfer of rights (E-9) moves the writer on the contract too: once
//!   the owner's change is in the container, the old key hands the container
//!   over (`handOver`) to the buyer's EVM key, and the buyer's key anchors
//!   from then on. If the network does not answer, the hand-over waits in
//!   `container.json` and goes before the next anchor, from the old key.
//! * Within ten offline records two copies can each write without knowing of
//!   the other; the first to anchor wins, the second learns it is a copy when
//!   it is next due — before any export or transfer.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use ksg_anchor_v2::evm::{
    address_of, anchor_data, decode_refusal, hand_over_data, hex0x, key_from_secret, note_data,
    note_kind, unhex, Address, Call, EvmKey, Refusal,
};
use ksg_anchor_v2::user_op::{self, UserOp};
use ksg_core_v2::crypto::hash::Hash;
use ksg_verify_v2::base::{check_chain, check_not_stale, head, Standing, BASE_SEPOLIA_CHAIN_ID};
use ksg_verify_v2::solana::Rpc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::home::read;

/// Records allowed between two anchors (owner's decision 03.10).
pub const OFFLINE_RECORDS: u32 = 10;

/// Where a `light` container anchors, and what it last anchored.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaseCfg {
    /// The node's JSON-RPC address.
    pub rpc: String,
    /// The `KsgAnchors` contract, `0x…`.
    pub contract: String,
    /// The sender's secp256k1 secret: a file of 64 hex characters.
    pub key: PathBuf,
    /// The last anchor this file put on the chain, hex; none before the first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last: Option<String>,
    /// Records written since the last anchor.
    #[serde(default)]
    pub since: u32,
    /// Anchors this file sent and did not see land, hex: the transaction
    /// went out, its confirmation did not come (a timeout, a node that
    /// stopped answering). Written before sending. If one of them turns out to be
    /// the chain's head, it was this file's own and becomes `last` — not a
    /// sign of a copy ([`BaseCfg::settle`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pending: Vec<String>,
    /// The transaction of the last anchor, for the record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_tx: Option<String>,
    /// The commitment to the client's mobile half, hex, while it waits to go
    /// on the chain with the next anchor (E-19, owner's decisions 15.10).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub share: Option<String>,
    /// The salt of the container's blind anchor key, hex (owner's decision
    /// 15.10 "B", the blind key): the contract and the sponsor's proxy see
    /// `sha256(tag ‖ template ‖ salt)`, never the template.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub salt: Option<String>,
    /// A hand-over owed on the contract after a transfer of rights (E-9):
    /// sent from `key`, then `key` becomes the new owner's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hand_to: Option<HandTo>,
    /// The gas is the sponsor's: the writer is the smart account of `key`,
    /// and anchors go as UserOperations (owner's decision 14.10).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub sponsored: bool,
    /// The chain's block just before this container's first anchor: its
    /// logs are read from here, in spans a limited node still answers
    /// (`ksg_verify_v2::base::logs`; live run 16.10). None before the first
    /// anchor, and in containers anchored before 16.10 — then from block 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_block: Option<u64>,
}

/// Where the sponsor's bundler and paymaster answer: one address, holding
/// the sponsor's client key (`[doc:RESEARCH-PAYMASTER]`,
/// facts 3, 7) — read from the environment, never from a file of the holder's.
pub const PAYMASTER_URL_ENV: &str = "KSG_PAYMASTER_URL";

/// Where the writer's seat on the contract goes after a transfer of rights.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandTo {
    /// The new owner's EVM address, `0x…` — the key's own; on a sponsored
    /// container the seat goes to that key's smart account, worked out when
    /// the hand-over is sent.
    pub to: String,
    /// The new owner's secp256k1 secret: anchors go from it once handed over.
    pub key: PathBuf,
}

impl BaseCfg {
    /// The last anchor as bytes.
    ///
    /// # Errors
    ///
    /// `container.json` holds something that is not 32 bytes of hex.
    pub fn last_bytes(&self) -> Result<Option<[u8; 32]>, String> {
        self.last
            .as_deref()
            .map(|s| {
                unhex(s)
                    .map_err(|e| e.to_string())?
                    .try_into()
                    .map_err(|_| "container.json: base.last is not 32 bytes".to_owned())
            })
            .transpose()
    }
}

impl BaseCfg {
    /// The key the container's anchors go under on the contract.
    ///
    /// # Errors
    ///
    /// `container.json` has no salt (a container set up before 15.10) or a
    /// salt that is not 32 bytes of hex.
    pub fn anchor_key(&self, template: &Hash) -> Result<[u8; 32], String> {
        let salt: [u8; 32] = unhex(self.salt.as_deref().ok_or(
            "container.json: base.salt is missing — the blind anchor key needs it (init again)",
        )?)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "container.json: base.salt is not 32 bytes".to_owned())?;
        Ok(ksg_verify_v2::base::anchor_key(&word(template), &salt))
    }
}

impl BaseCfg {
    /// Takes the chain's head into account: when it is an anchor this file
    /// sent and did not see land ([`BaseCfg::pending`]), the anchor landed
    /// after all and becomes `last`. Returns whether anything changed.
    ///
    /// Every pending anchor continues `last`, so once one of them is the
    /// head none of the others can land any more: all are dropped.
    pub fn settle(&mut self, head: &[u8; 32]) -> bool {
        let h = hex0x(head);
        if self.pending.iter().any(|p| p.eq_ignore_ascii_case(&h)) {
            self.last = Some(h);
            self.last_tx = None;
            self.pending.clear();
            return true;
        }
        false
    }

    /// Notes `next` as sent and not seen land — written before it is sent.
    pub fn sending(&mut self, next: &[u8; 32]) {
        let h = hex0x(next);
        if !self.pending.iter().any(|p| p.eq_ignore_ascii_case(&h)) {
            self.pending.push(h);
        }
    }
}

/// The 32 bytes a hash stands for on the contract.
#[must_use]
pub const fn word(h: &Hash) -> [u8; 32] {
    *h.as_bytes()
}

/// Why an anchor did not land.
#[derive(Debug)]
pub enum AnchorError {
    /// The contract refused it — for a stale predecessor, this file is a copy.
    Refused(Refusal),
    /// The network did not answer or the transaction failed.
    Network(String),
}

/// A connection to the node, with the sender's key.
pub struct BaseLink {
    rpc: Box<dyn Rpc + Send>,
    key: EvmKey,
    /// The writer's address: the key's own, or its smart account when the
    /// gas is sponsored.
    pub from: Address,
    contract: Address,
    wait: Duration,
    /// The bundler and paymaster, when the gas is sponsored.
    sponsor: Option<Box<dyn Rpc + Send>>,
}

/// The address `key` writes from: its own, or — sponsored — its Coinbase
/// Smart Account, as the factory computes it.
///
/// # Errors
///
/// The node does not answer, or answers something that is not an address.
pub fn writer_of(rpc: &dyn Rpc, key: &EvmKey, sponsored: bool) -> Result<Address, String> {
    let owner = address_of(key.verifying_key());
    if !sponsored {
        return Ok(owner);
    }
    let ret = rpc.call(
        "eth_call",
        json!([{"to": hex0x(&user_op::CB_FACTORY), "data": hex0x(&user_op::get_address_data(&owner))}, "latest"]),
    )?;
    let b = unhex(ret.as_str().unwrap_or_default()).map_err(|e| e.to_string())?;
    b.get(12..32)
        .and_then(|a| a.try_into().ok())
        .ok_or_else(|| format!("the account factory answered {ret}"))
}

fn hexnum(v: &Value) -> Result<u128, String> {
    let s = v.as_str().ok_or_else(|| format!("not a number: {v}"))?;
    u128::from_str_radix(s.trim_start_matches("0x"), 16).map_err(|_| format!("not a number: {s}"))
}

/// Reads a secret key file of 64 hex characters.
///
/// # Errors
///
/// The file is missing or is not a key.
pub fn read_key(path: &std::path::Path) -> Result<EvmKey, String> {
    let raw = Zeroizing::new(read(path)?);
    let s = std::str::from_utf8(&raw).map_err(|_| format!("{}: not text", path.display()))?;
    let b = Zeroizing::new(unhex(s).map_err(|_| format!("{}: not hex", path.display()))?);
    let secret: [u8; 32] = b
        .as_slice()
        .try_into()
        .map_err(|_| format!("{}: not 32 bytes", path.display()))?;
    key_from_secret(&secret).map_err(|e| format!("{}: {e}", path.display()))
}

impl BaseLink {
    /// Connects through `rpc` and checks it is Base Sepolia.
    ///
    /// # Errors
    ///
    /// The key is unreadable, the contract address is malformed, the node
    /// does not answer or is another chain.
    pub fn with_rpc(cfg: &BaseCfg, rpc: Box<dyn Rpc + Send>) -> Result<Self, String> {
        Self::with_sponsor(cfg, rpc, None)
    }

    /// As [`Self::with_rpc`], with the sponsor's bundler and paymaster.
    ///
    /// # Errors
    ///
    /// As [`Self::with_rpc`]; a sponsored container without a sponsor.
    pub fn with_sponsor(
        cfg: &BaseCfg,
        rpc: Box<dyn Rpc + Send>,
        sponsor: Option<Box<dyn Rpc + Send>>,
    ) -> Result<Self, String> {
        if cfg.sponsored && sponsor.is_none() {
            return Err(format!(
                "the gas of this container is sponsored: set {PAYMASTER_URL_ENV} to the \
                 sponsor's bundler and paymaster"
            ));
        }
        let key = read_key(&cfg.key)?;
        let contract: Address = unhex(&cfg.contract)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "--contract is not 20 bytes".to_owned())?;
        check_chain(rpc.as_ref(), BASE_SEPOLIA_CHAIN_ID)?;
        let wait = std::env::var("KSG_BASE_WAIT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .map_or(Duration::from_secs(120), Duration::from_secs);
        Ok(Self {
            from: writer_of(rpc.as_ref(), &key, cfg.sponsored)?,
            rpc,
            key,
            contract,
            wait,
            sponsor,
        })
    }

    /// Connects to the node `cfg` names.
    ///
    /// # Errors
    ///
    /// As [`Self::with_rpc`].
    #[cfg(feature = "rpc")]
    pub fn connect(cfg: &BaseCfg) -> Result<Self, String> {
        let sponsor: Option<Box<dyn Rpc + Send>> = if cfg.sponsored {
            let url = std::env::var(PAYMASTER_URL_ENV).map_err(|_| {
                format!(
                    "the gas of this container is sponsored: set {PAYMASTER_URL_ENV} to the \
                     sponsor's bundler and paymaster"
                )
            })?;
            Some(Box::new(ksg_verify_v2::solana::HttpRpc::new(&url)?))
        } else {
            None
        };
        Self::with_sponsor(
            cfg,
            Box::new(ksg_verify_v2::solana::HttpRpc::new(&cfg.rpc)?),
            sponsor,
        )
    }

    /// The address `key` would write from on this link's route.
    ///
    /// # Errors
    ///
    /// As [`writer_of`].
    pub fn writer_for(&self, key: &EvmKey) -> Result<Address, String> {
        writer_of(self.rpc.as_ref(), key, self.sponsor.is_some())
    }

    /// Where the file stands against the chain's head.
    ///
    /// # Errors
    ///
    /// The network does not answer.
    pub fn standing(
        &self,
        container: &[u8; 32],
        mine: Option<&[u8; 32]>,
    ) -> Result<Standing, String> {
        let h = head(self.rpc.as_ref(), &self.contract, container)?;
        Ok(check_not_stale(&h, mine))
    }

    /// The container's head on the chain.
    ///
    /// # Errors
    ///
    /// The network does not answer.
    pub fn head(&self, container: &[u8; 32]) -> Result<ksg_verify_v2::base::Head, String> {
        head(self.rpc.as_ref(), &self.contract, container)
    }

    fn send(&self, data: Vec<u8>) -> Result<String, AnchorError> {
        let net = AnchorError::Network;
        // The node tells first whether the contract would refuse: a refused
        // call is not sent, so it costs nothing and leaves nothing behind.
        let sim = self.rpc.call(
            "eth_call",
            json!([{"from": hex0x(&self.from), "to": hex0x(&self.contract), "data": hex0x(&data)}, "latest"]),
        );
        if let Err(msg) = &sim {
            if let Some(r) = refusal_in(msg) {
                return Err(AnchorError::Refused(r));
            }
            return Err(net(msg.clone()));
        }
        if let Some(sponsor) = &self.sponsor {
            return self.send_sponsored(sponsor.as_ref(), data);
        }
        let nonce = hexnum(
            &self
                .rpc
                .call(
                    "eth_getTransactionCount",
                    json!([hex0x(&self.from), "pending"]),
                )
                .map_err(net)?,
        )
        .map_err(net)?;
        let tip = hexnum(
            &self
                .rpc
                .call("eth_maxPriorityFeePerGas", json!([]))
                .map_err(net)?,
        )
        .map_err(net)?;
        let base = self
            .rpc
            .call("eth_getBlockByNumber", json!(["latest", false]))
            .map_err(net)?;
        let base_fee = base
            .get("baseFeePerGas")
            .map_or(Ok(0), hexnum)
            .map_err(net)?;
        let gas = hexnum(
            &self
                .rpc
                .call(
                    "eth_estimateGas",
                    json!([{"from": hex0x(&self.from), "to": hex0x(&self.contract), "data": hex0x(&data)}]),
                )
                .map_err(net)?,
        )
        .map_err(net)?;
        let call = Call {
            chain_id: BASE_SEPOLIA_CHAIN_ID,
            nonce: u64::try_from(nonce).map_err(|_| net("nonce".into()))?,
            max_priority_fee_per_gas: tip,
            max_fee_per_gas: base_fee * 2 + tip,
            gas_limit: u64::try_from(gas * 6 / 5).map_err(|_| net("gas".into()))?,
            to: self.contract,
            data,
        };
        let (raw, hash) = call.sign(&self.key).map_err(|e| net(e.to_string()))?;
        self.rpc
            .call("eth_sendRawTransaction", json!([hex0x(&raw)]))
            .map_err(net)?;
        let tx = hex0x(&hash);
        let start = Instant::now();
        loop {
            let r = self
                .rpc
                .call("eth_getTransactionReceipt", json!([tx]))
                .map_err(net)?;
            if !r.is_null() {
                if r.get("status").and_then(Value::as_str) == Some("0x1") {
                    return Ok(tx);
                }
                return Err(net(format!("{tx}: the transaction failed on the chain")));
            }
            if start.elapsed() > self.wait {
                return Err(net(format!("{tx}: no receipt after {:?}", self.wait)));
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    /// The sponsored route: a UserOperation of the smart account, its gas
    /// paid by the paymaster (ERC-4337, EntryPoint 0.6; ERC-7677 for the
    /// paymaster's two calls). Returns the transaction that carried it.
    fn send_sponsored(&self, sponsor: &dyn Rpc, data: Vec<u8>) -> Result<String, AnchorError> {
        let net = AnchorError::Network;
        let ep = hex0x(&user_op::ENTRY_POINT_V06);
        let chain = format!("0x{BASE_SEPOLIA_CHAIN_ID:x}");
        let code = self
            .rpc
            .call("eth_getCode", json!([hex0x(&self.from), "latest"]))
            .map_err(net)?;
        let deployed = code.as_str().is_some_and(|c| c.len() > 2);
        let owner = address_of(self.key.verifying_key());
        let nonce_word = unhex(
            self.rpc
                .call(
                    "eth_call",
                    json!([{"to": ep, "data": hex0x(&user_op::get_nonce_data(&self.from))}, "latest"]),
                )
                .map_err(net)?
                .as_str()
                .unwrap_or_default(),
        )
        .map_err(|e| net(e.to_string()))?;
        let nonce: [u8; 32] = nonce_word
            .try_into()
            .map_err(|_| net("the EntryPoint's nonce is not a word".into()))?;
        let tip = hexnum(
            &self
                .rpc
                .call("eth_maxPriorityFeePerGas", json!([]))
                .map_err(net)?,
        )
        .map_err(net)?;
        let base_fee = self
            .rpc
            .call("eth_getBlockByNumber", json!(["latest", false]))
            .map_err(net)?
            .get("baseFeePerGas")
            .map_or(Ok(0), hexnum)
            .map_err(net)?;
        let mut op = UserOp {
            sender: self.from,
            nonce,
            init_code: if deployed {
                Vec::new()
            } else {
                user_op::init_code(&owner)
            },
            call_data: user_op::execute_data(&self.contract, &data),
            call_gas_limit: 0,
            verification_gas_limit: 0,
            pre_verification_gas: 0,
            max_fee_per_gas: base_fee * 2 + tip,
            max_priority_fee_per_gas: tip,
            paymaster_and_data: Vec::new(),
            signature: user_op::wrap_signature(&user_op::STUB_SIGNATURE),
        };
        let pm = |method: &str, op: &UserOp| -> Result<Vec<u8>, AnchorError> {
            let r = sponsor
                .call(method, json!([op.to_json(), ep, chain, {}]))
                .map_err(net)?;
            unhex(r["paymasterAndData"].as_str().unwrap_or_default())
                .map_err(|e| net(format!("{method}: {e}")))
        };
        op.paymaster_and_data = pm("pm_getPaymasterStubData", &op)?;
        let gas = sponsor
            .call("eth_estimateUserOperationGas", json!([op.to_json(), ep]))
            .map_err(net)?;
        op.call_gas_limit = hexnum(&gas["callGasLimit"]).map_err(net)? * 6 / 5;
        op.verification_gas_limit = hexnum(&gas["verificationGasLimit"]).map_err(net)? * 6 / 5;
        op.pre_verification_gas = hexnum(&gas["preVerificationGas"]).map_err(net)?;
        op.paymaster_and_data = pm("pm_getPaymasterData", &op)?;
        op.sign(&self.key, BASE_SEPOLIA_CHAIN_ID)
            .map_err(|e| net(e.to_string()))?;
        let hash = sponsor
            .call("eth_sendUserOperation", json!([op.to_json(), ep]))
            .map_err(net)?;
        let start = Instant::now();
        loop {
            let r = sponsor
                .call("eth_getUserOperationReceipt", json!([hash]))
                .map_err(net)?;
            if !r.is_null() {
                let tx = r["receipt"]["transactionHash"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned();
                if r["success"].as_bool() == Some(true) {
                    return Ok(tx);
                }
                return Err(net(format!("{tx}: the user operation failed on the chain")));
            }
            if start.elapsed() > self.wait {
                return Err(net(format!("{hash}: no receipt after {:?}", self.wait)));
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    /// Puts `next` after `prev` as the container's last anchor.
    ///
    /// # Errors
    ///
    /// [`AnchorError::Refused`] when the contract will not take it,
    /// [`AnchorError::Network`] otherwise.
    pub fn anchor(
        &self,
        container: &[u8; 32],
        prev: &[u8; 32],
        next: &[u8; 32],
    ) -> Result<String, AnchorError> {
        self.send(anchor_data(container, prev, next))
    }

    /// Hands the container's seat of writer to `to` (a transfer of rights).
    ///
    /// # Errors
    ///
    /// As [`Self::anchor`]; [`Refusal::NotWriter`] when this key is not the
    /// writer.
    pub fn hand_over(&self, container: &[u8; 32], to: &Address) -> Result<String, AnchorError> {
        self.send(hand_over_data(container, to))
    }

    /// Puts a note of `tag` on the chain: the issuance anchor of a `bare`.
    ///
    /// # Errors
    ///
    /// As [`Self::anchor`].
    pub fn note(&self, tag: &str, data: &[u8]) -> Result<String, AnchorError> {
        self.send(note_data(&note_kind(tag), data))
    }

    /// The node's latest block.
    ///
    /// # Errors
    ///
    /// The node does not answer.
    pub fn block_number(&self) -> Result<u64, String> {
        hexnum(&self.rpc.call("eth_blockNumber", json!([]))?)
            .and_then(|b| u64::try_from(b).map_err(|_| "eth_blockNumber".to_owned()))
    }

    /// The node, for reads.
    #[must_use]
    pub fn rpc(&self) -> &dyn Rpc {
        self.rpc.as_ref()
    }

    /// The contract.
    #[must_use]
    pub const fn contract(&self) -> &Address {
        &self.contract
    }
}

/// The contract's refusal inside a node's error text, if there is one.
fn refusal_in(msg: &str) -> Option<Refusal> {
    let i = msg.find("0x")?;
    let hexpart: String = msg[i..]
        .chars()
        .skip(2)
        .take_while(char::is_ascii_hexdigit)
        .collect();
    decode_refusal(&unhex(&hexpart).ok()?)
}
