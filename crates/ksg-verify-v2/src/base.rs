//! Reading anchors on Base Sepolia — the `KsgAnchors` contract
//! (`core-v2/contracts/KsgAnchors.sol`, owner's decisions 14.10).
//!
//! Two reads, both free (no transaction, no gas):
//!
//! * [`head`] — a container's last anchor, its writer and its count. A file
//!   whose own last anchor is not the head is a copy or a rolled-back file:
//!   someone continued the chain after it ([`check_not_stale`]).
//! * [`latest_block_time`] — the time of the newest block, for a clock that
//!   the holder's computer cannot set back.
//! * [`export_on_base`] — where an export's seal stands among a `light`
//!   container's anchors: its last one, passed by later ones, or never
//!   anchored. The key is not taken from the holder: the verifier makes it
//!   from the template (the channel's release and serial) and the salt.
//!
//! Through the same [`Rpc`] trait as Solana: an EVM node speaks JSON-RPC too.

use serde_json::{json, Value};

use crate::solana::Rpc;

/// Base Sepolia's chain id.
pub const BASE_SEPOLIA_CHAIN_ID: u64 = 84_532;

/// `head(bytes32)` — the first four bytes of its keccak, fixed here so the
/// verifier needs no hash of its own (checked against the hash in the tests).
pub const HEAD_SELECTOR: [u8; 4] = [0xf3, 0x39, 0xe3, 0xb2];

/// A container's head on the contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Head {
    /// The last anchor; zero before the first.
    pub last: [u8; 32],
    /// Who may write; zero before the first anchor.
    pub writer: [u8; 20],
    /// How many anchors the container has.
    pub count: u64,
}

fn unhex(s: &str) -> Result<Vec<u8>, String> {
    hex::decode(s.trim_start_matches("0x")).map_err(|_| format!("not hex: {s}"))
}

/// Checks the node is on `chain_id` — a reader must not take another chain's
/// state for this one's.
///
/// # Errors
///
/// Transport failure, or a different chain.
pub fn check_chain(rpc: &dyn Rpc, chain_id: u64) -> Result<(), String> {
    let v = rpc.call("eth_chainId", json!([]))?;
    let got = u64::from_str_radix(v.as_str().unwrap_or("").trim_start_matches("0x"), 16)
        .map_err(|_| format!("eth_chainId: {v}"))?;
    if got != chain_id {
        return Err(format!("the node is on chain {got}, not {chain_id}"));
    }
    Ok(())
}

/// The container's head, read with `eth_call` at the latest block.
///
/// # Errors
///
/// Transport failure or a return value that is not three words.
pub fn head(rpc: &dyn Rpc, contract: &[u8; 20], container: &[u8; 32]) -> Result<Head, String> {
    let mut data = HEAD_SELECTOR.to_vec();
    data.extend_from_slice(container);
    let v = rpc.call(
        "eth_call",
        json!([{"to": format!("0x{}", hex::encode(contract)), "data": format!("0x{}", hex::encode(&data))}, "latest"]),
    )?;
    let ret = unhex(v.as_str().unwrap_or(""))?;
    if ret.len() != 96 {
        return Err(format!("head: {} bytes where 96 were due", ret.len()));
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

/// What reading the head says about a file whose last anchor is `mine`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// The file's last anchor is the head: it is the current one.
    Current,
    /// The container has no anchor yet, and neither has the file.
    Unanchored,
    /// The head is past the file's last anchor: another copy anchored after
    /// it, or this file is an older one. Everything but a full export is to
    /// be refused (owner's decisions 03.10 and 05.10).
    Stale {
        /// The head on the chain.
        head: [u8; 32],
    },
}

/// Compares the file's last anchor with the head.
#[must_use]
pub fn check_not_stale(head: &Head, mine: Option<&[u8; 32]>) -> Standing {
    match (mine, head.count) {
        (None, 0) => Standing::Unanchored,
        (Some(m), _) if *m == head.last => Standing::Current,
        _ => Standing::Stale { head: head.last },
    }
}

/// The newest block's time, Unix seconds.
///
/// # Errors
///
/// Transport failure or a block without a timestamp.
pub fn latest_block_time(rpc: &dyn Rpc) -> Result<u64, String> {
    let b: Value = rpc.call("eth_getBlockByNumber", json!(["latest", false]))?;
    let t = b
        .get("timestamp")
        .and_then(Value::as_str)
        .ok_or("the block has no timestamp")?;
    u64::from_str_radix(t.trim_start_matches("0x"), 16).map_err(|_| format!("timestamp: {t}"))
}

/// The topic of `Noted(bytes32,address,bytes)` — fixed, like [`HEAD_SELECTOR`].
pub const NOTED_TOPIC: [u8; 32] = [
    171, 135, 57, 63, 161, 252, 151, 33, 204, 149, 234, 38, 231, 229, 12, 155, 122, 88, 205, 23,
    160, 225, 165, 221, 7, 245, 236, 208, 247, 29, 130, 164,
];

/// A note read back from the contract's log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    /// Who wrote it.
    pub sender: [u8; 20],
    /// What it holds.
    pub data: Vec<u8>,
    /// The block it is in.
    pub block: u64,
}

/// Blocks per `eth_getLogs` question when reading from a known block: a
/// free node answers only short ranges (the live run of 16.10: one refused
/// ten blocks), and a refusal must not read as "nothing there".
/// `KSG_BASE_LOG_SPAN` overrides it.
pub const LOG_SPAN: u64 = 500;

fn log_span() -> u64 {
    std::env::var("KSG_BASE_LOG_SPAN")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|v: &u64| *v > 0)
        .unwrap_or(LOG_SPAN)
}

/// The contract's logs with `topics`, from block `from` to the latest.
///
/// From block 0 — a reader that does not know where the container starts —
/// it is one question, as a node with full logs answers it. From a known
/// block it walks to the latest in spans of [`LOG_SPAN`], so a node that
/// limits the range still answers in full. Any refusal is an error, never
/// an empty answer: a loss or a hand-over must not vanish because a node
/// would not say.
///
/// # Errors
///
/// Transport failure, or a node that refuses a range.
pub fn logs(
    rpc: &dyn Rpc,
    contract: &[u8; 20],
    topics: &[[u8; 32]],
    from: u64,
) -> Result<Vec<Value>, String> {
    let address = format!("0x{}", hex::encode(contract));
    let topics: Vec<String> = topics
        .iter()
        .map(|t| format!("0x{}", hex::encode(t)))
        .collect();
    let ask = |lo: String, hi: String| -> Result<Vec<Value>, String> {
        let got = rpc.call(
            "eth_getLogs",
            json!([{"address": address, "fromBlock": lo, "toBlock": hi, "topics": topics}]),
        )?;
        got.as_array()
            .cloned()
            .ok_or_else(|| "eth_getLogs: not a list".to_owned())
    };
    if from == 0 {
        return ask("0x0".into(), "latest".into());
    }
    let latest = rpc.call("eth_blockNumber", json!([]))?;
    let latest = u64::from_str_radix(
        latest
            .as_str()
            .ok_or("eth_blockNumber: not a number")?
            .trim_start_matches("0x"),
        16,
    )
    .map_err(|_| "eth_blockNumber: not a number")?;
    let span = log_span();
    let mut out = Vec::new();
    let mut lo = from;
    while lo <= latest {
        let hi = lo.saturating_add(span - 1).min(latest);
        out.extend(ask(format!("0x{lo:x}"), format!("0x{hi:x}"))?);
        lo = hi.saturating_add(1);
    }
    Ok(out)
}

/// Every note of `kind` (keccak of its tag) the contract logged since
/// `from_block`.
///
/// # Errors
///
/// Transport failure or a log that does not decode.
pub fn notes(
    rpc: &dyn Rpc,
    contract: &[u8; 20],
    kind: &[u8; 32],
    from_block: u64,
) -> Result<Vec<Note>, String> {
    let logs = logs(rpc, contract, &[NOTED_TOPIC, *kind], from_block)?;
    let mut out = Vec::new();
    for l in &logs {
        let topics = l
            .get("topics")
            .and_then(Value::as_array)
            .ok_or("a log without topics")?;
        let sender_t = unhex(
            topics
                .get(2)
                .and_then(Value::as_str)
                .ok_or("a note without its sender")?,
        )?;
        if sender_t.len() != 32 {
            return Err("a note's sender is not a word".into());
        }
        let mut sender = [0u8; 20];
        sender.copy_from_slice(&sender_t[12..]);
        let data = unhex(
            l.get("data")
                .and_then(Value::as_str)
                .ok_or("a log without data")?,
        )?;
        if data.len() < 64 {
            return Err("a note's data is short".into());
        }
        let len = usize::try_from(u64::from_be_bytes(
            data[56..64].try_into().map_err(|_| "len")?,
        ))
        .map_err(|_| "a note's length")?;
        let body = data
            .get(64..64 + len)
            .ok_or("a note's data is cut")?
            .to_vec();
        let block = l
            .get("blockNumber")
            .and_then(Value::as_str)
            .and_then(|b| u64::from_str_radix(b.trim_start_matches("0x"), 16).ok())
            .unwrap_or(0);
        out.push(Note {
            sender,
            data: body,
            block,
        });
    }
    Ok(out)
}

/// The key a container's anchors go under on the contract: a blind one,
/// `sha256("ksg:base-key:v1" ‖ template ‖ salt)` (owner's decision 15.10 "B", the blind key).
/// Neither the gas sponsor's proxy nor anyone reading the chain links it to
/// the container's template; a copy has the same salt, so the copy check
/// holds.
#[must_use]
pub fn anchor_key(template: &[u8; 32], salt: &[u8; 32]) -> [u8; 32] {
    use sha2::Digest as _;
    let mut h = sha2::Sha256::new();
    h.update(b"ksg:base-key:v1");
    h.update(template);
    h.update(salt);
    h.finalize().into()
}

/// The note tag of a mobile half's commitment, sent at initiation.
pub const SHARE_TAG: &str = "ksg:share:v1";
/// The note tag of a declaration of loss (E-19).
pub const LOST_TAG: &str = "ksg:lost:v1";

/// What the chain says about a container's loss (E-19, owner's decisions
/// 15.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Loss {
    /// No commitment to the client's mobile half is on the chain: nothing can
    /// identify a declaration, and the status stays frozen at its last state.
    NoIdentity,
    /// The half is committed to; no valid declaration of loss.
    NotDeclared,
    /// The mobile half declared the container lost — status 9.
    Declared {
        /// The block of the declaration.
        block: u64,
        /// The moment the client put in it, Unix seconds.
        at: u64,
        /// The hash of the identifier of the client who signed it.
        client: [u8; 32],
    },
}

/// The length of a declaration of loss: `key (32) ‖ share (32) ‖ at (8,
/// big-endian) ‖ client (32) ‖ signature (64)`.
pub const LOST_BODY_LEN: usize = 32 + 32 + 8 + 32 + 64;

/// The note a share commitment carries: `key ‖ commitment`.
#[must_use]
pub fn share_body(template: &[u8; 32], commitment: &[u8; 32]) -> Vec<u8> {
    let mut b = template.to_vec();
    b.extend_from_slice(commitment);
    b
}

/// What the mobile half signs: `"ksg:lost:v1" ‖ key ‖ at ‖ client`, `key`
/// being the container's anchor key ([`anchor_key`]).
#[must_use]
pub fn lost_message(template: &[u8; 32], at: u64, client: &[u8; 32]) -> Vec<u8> {
    let mut m = LOST_TAG.as_bytes().to_vec();
    m.extend_from_slice(template);
    m.extend_from_slice(&at.to_be_bytes());
    m.extend_from_slice(client);
    m
}

/// The hash of the identifier of the client who signs a declaration: the
/// client key's identifier and its public key — the identifier alone is the
/// same for every client on the stand.
#[must_use]
pub fn client_id_hash(kid: &str, client_public: &[u8; 32]) -> [u8; 32] {
    use sha2::Digest as _;
    let mut h = sha2::Sha256::new();
    h.update(b"ksg:client-id:v1");
    h.update(kid.as_bytes());
    h.update(client_public);
    h.finalize().into()
}

/// The note a declaration of loss carries: `key ‖ share ‖ at ‖ client ‖
/// signature`.
#[must_use]
pub fn lost_body(
    template: &[u8; 32],
    share: &[u8; 32],
    at: u64,
    client: &[u8; 32],
    sig: &[u8; 64],
) -> Vec<u8> {
    let mut b = Vec::with_capacity(LOST_BODY_LEN);
    b.extend_from_slice(template);
    b.extend_from_slice(share);
    b.extend_from_slice(&at.to_be_bytes());
    b.extend_from_slice(client);
    b.extend_from_slice(sig);
    b
}

fn sha256_share(share: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;
    let mut h = sha2::Sha256::new();
    h.update(b"ksg:share:v1");
    h.update(share);
    h.finalize().into()
}

/// Reads the container's loss under its anchor key (`key`, see
/// [`anchor_key`]): the share commitment its writer put at initiation, and a declaration whose share matches it and whose signature
/// holds under that share. `kind_of` turns a tag into its topic (keccak);
/// the verifier takes it from the caller and needs no hash of its own.
///
/// # Errors
///
/// Transport failure.
pub fn loss(
    rpc: &dyn Rpc,
    contract: &[u8; 20],
    key: &[u8; 32],
    kind_of: &dyn Fn(&str) -> [u8; 32],
    from_block: u64,
) -> Result<Loss, String> {
    let h = head(rpc, contract, key)?;
    // The commitment counts from the writer, or from any earlier one: a
    // transfer of rights hands the seat over (`HandedOver`), and only the
    // writer of the moment can, so the line of writers is the contract's word.
    let mut writers = earlier_writers(rpc, contract, key, from_block)?;
    writers.push(h.writer);
    let commits: Vec<[u8; 32]> = notes(rpc, contract, &kind_of(SHARE_TAG), from_block)?
        .into_iter()
        .filter(|n| writers.contains(&n.sender) && n.data.len() == 64 && n.data[..32] == key[..])
        .filter_map(|n| n.data[32..].try_into().ok())
        .collect();
    let Some(commit) = commits.first() else {
        return Ok(Loss::NoIdentity);
    };
    for n in notes(rpc, contract, &kind_of(LOST_TAG), from_block)? {
        if n.data.len() != LOST_BODY_LEN || n.data[..32] != key[..] {
            continue;
        }
        let share: [u8; 32] = n.data[32..64].try_into().map_err(|_| "share")?;
        if sha256_share(&share) != *commit {
            continue;
        }
        let at = u64::from_be_bytes(n.data[64..72].try_into().map_err(|_| "at")?);
        let client: [u8; 32] = n.data[72..104].try_into().map_err(|_| "client")?;
        let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&share) else {
            continue;
        };
        let sig = ed25519_dalek::Signature::from_bytes(
            &n.data[104..168].try_into().map_err(|_| "signature")?,
        );
        if vk
            .verify_strict(&lost_message(key, at, &client), &sig)
            .is_ok()
        {
            return Ok(Loss::Declared {
                block: n.block,
                at,
                client,
            });
        }
    }
    Ok(Loss::NotDeclared)
}

/// The topic of `Anchored(bytes32,bytes32,bytes32,uint64,address)` — fixed,
/// like [`HEAD_SELECTOR`].
pub const ANCHORED_TOPIC: [u8; 32] = [
    8, 183, 46, 60, 199, 198, 12, 46, 159, 254, 15, 63, 47, 115, 13, 223, 239, 210, 190, 178, 3,
    116, 198, 224, 59, 209, 170, 1, 118, 47, 224, 139,
];

/// Where a seal stands among a container's anchors on the contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case", tag = "on_base")]
pub enum OnChain {
    /// The seal is the container's last anchor.
    Last {
        /// The block of the anchor.
        block: u64,
    },
    /// The seal was anchored, and the chain went on after it: the container
    /// has a newer state than this export.
    Passed {
        /// The block of the anchor.
        block: u64,
        /// Anchors put after it.
        after: u64,
    },
    /// The seal was never anchored under this key.
    Absent,
}

/// Where `seal` stands among the anchors under `key`.
///
/// # Errors
///
/// Transport failure, or a log that does not decode.
pub fn seal_on_chain(
    rpc: &dyn Rpc,
    contract: &[u8; 20],
    key: &[u8; 32],
    seal: &[u8; 32],
    from_block: u64,
) -> Result<OnChain, String> {
    let logs = logs(rpc, contract, &[ANCHORED_TOPIC, *key], from_block)?;
    let mut found = None;
    for l in &logs {
        let data = unhex(
            l.get("data")
                .and_then(Value::as_str)
                .ok_or("a log without data")?,
        )?;
        // prev, next, count, writer: four words.
        if data.len() != 128 {
            return Err("an anchor's log is not four words".into());
        }
        if data[32..64] == seal[..] {
            let count = u64::from_be_bytes(data[88..96].try_into().map_err(|_| "count")?);
            let block = l
                .get("blockNumber")
                .and_then(Value::as_str)
                .and_then(|b| u64::from_str_radix(b.trim_start_matches("0x"), 16).ok())
                .unwrap_or(0);
            found = Some((block, count));
        }
    }
    let Some((block, count)) = found else {
        return Ok(OnChain::Absent);
    };
    let h = head(rpc, contract, key)?;
    Ok(if h.last == *seal {
        OnChain::Last { block }
    } else {
        OnChain::Passed {
            block,
            after: h.count.saturating_sub(count),
        }
    })
}

/// The seal an export stands on, and whether it is a pointwise export (one
/// page or several) rather than the full one.
///
/// # Errors
///
/// Not an export, or a seal that does not hash.
pub fn export_seal(bytes: &[u8]) -> Result<([u8; 32], bool), String> {
    let v: Value = serde_json::from_slice(bytes).map_err(|e| format!("export: {e}"))?;
    let (seal, point) = match &v {
        Value::Array(points) => (points.first().and_then(|p| p.get("seal")), true),
        Value::Object(o) => (o.get("seal"), o.get("page").is_some()),
        _ => (None, false),
    };
    let seal: ksg_core_v2::journal::Seal =
        serde_json::from_value(seal.ok_or("export: no seal")?.clone())
            .map_err(|e| format!("export: the seal: {e}"))?;
    let h = seal.hash().map_err(|e| format!("export: the seal: {e}"))?;
    Ok((*h.as_bytes(), point))
}

/// Where an export of a `light` container stands on Base Sepolia. The key is
/// the verifier's own: the template from the channel's `release` and
/// `serial` (`ksg_core_v2::section::section_root`), with the container's
/// `salt` ([`anchor_key`]). A pointwise export goes out only on a fresh
/// anchor, so one whose seal is absent is refused: it comes from a copy or an
/// older file (owner's decisions 03.10, 14.10).
///
/// # Errors
///
/// The node does not answer or is not Base Sepolia, the export does not
/// parse — or a pointwise export whose seal was never anchored.
pub fn export_on_base(
    rpc: &dyn Rpc,
    contract: &[u8; 20],
    release: &str,
    serial: u64,
    salt: &[u8; 32],
    export: &[u8],
    from_block: u64,
) -> Result<OnChain, String> {
    check_chain(rpc, BASE_SEPOLIA_CHAIN_ID)?;
    let template = ksg_core_v2::section::section_root(release, ksg_core_v2::doc::Serial(serial));
    let key = anchor_key(template.as_bytes(), salt);
    let (seal, point) = export_seal(export)?;
    let on = seal_on_chain(rpc, contract, &key, &seal, from_block)?;
    if point && on == OnChain::Absent {
        return Err(
            "Base Sepolia: the page's seal was never anchored — a page goes out \
                    only on a fresh anchor, so this one comes from a copy or an older file"
                .into(),
        );
    }
    Ok(on)
}

/// The topic of `HandedOver(bytes32,address,address)` — fixed, like
/// [`HEAD_SELECTOR`].
pub const HANDED_OVER_TOPIC: [u8; 32] = [
    67, 38, 217, 172, 197, 240, 158, 65, 29, 234, 157, 168, 27, 82, 117, 10, 54, 95, 133, 82, 60,
    71, 17, 147, 184, 216, 79, 119, 14, 41, 152, 152,
];

/// Every account that handed the container under `key` over: the writers
/// before the current one, in order.
///
/// # Errors
///
/// Transport failure, or a log that does not decode.
pub fn earlier_writers(
    rpc: &dyn Rpc,
    contract: &[u8; 20],
    key: &[u8; 32],
    from_block: u64,
) -> Result<Vec<[u8; 20]>, String> {
    let logs = logs(rpc, contract, &[HANDED_OVER_TOPIC, *key], from_block)?;
    let mut out = Vec::new();
    for l in &logs {
        let data = unhex(
            l.get("data")
                .and_then(Value::as_str)
                .ok_or("a log without data")?,
        )?;
        if data.len() != 64 {
            return Err("a hand-over's log is not two words".into());
        }
        let mut from = [0u8; 20];
        from.copy_from_slice(&data[12..32]);
        out.push(from);
    }
    Ok(out)
}
