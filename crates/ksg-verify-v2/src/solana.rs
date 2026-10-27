//! Reading anchors from Solana, on core v2: seals of the journal and records
//! of the status section. Item P-6 of the MVP plan; spec v2 §7.3.
//!
//! # The status memo: open
//!
//! A status record is anchored as the memo of an ordinary transaction (the
//! SPL Memo program). The memo is one line:
//!
//! ```text
//! ksg:st:v1 <link> <commit>
//! link   = SHA-256("ksg:st:link:v1"   ‖ prev)         prev = the record's own `prev`
//! commit = SHA-256("ksg:st:commit:v1" ‖ record hash)
//! ```
//!
//! Open on purpose: the status section is the one part of a container that is
//! **read** (KS-7 §7.2-octies — a buyer must see the state of the rights), and
//! its records are public by construction. Two memos with one `link` and
//! different `commit` are two status records after one head: a rewritten
//! history of the container's status, visible to anyone who holds the
//! section ([`find_status_forks`]).
//!
//! # The seal memo: blind
//!
//! A seal of the journal under the movable seal (CH-7) is anchored with a
//! **blind** memo, of fixed length:
//!
//! ```text
//! ksg:bs:v1 <link> <commit>
//! link   = PRF(scan_key, "ksg:bs:link:v1"   ‖ prev seal)    16 bytes, hex
//! commit = PRF(scan_key, "ksg:bs:commit:v1" ‖ seal)         16 bytes, hex
//! ```
//!
//! `[decision] 13.09` (access to the chain, §2): an anonymous
//! observer sees that an anchor exists and nothing else. An open memo, as
//! the status memo above, does not keep that: whoever learns one seal's hash walks the chain
//! memo by memo. Under the blind memo the walk needs the holder's `scan_key`,
//! and the holder decides who gets it — the auditor, with the export. The
//! price is the one `ksg-anchor::blind` names: a fork is visible only to
//! whoever holds the key. The PRF is the one of `ksg-anchor::blind`
//! (HKDF-SHA256, fixed public salt); it is here, in the open crate, because a
//! verifier must be able to recompute it without the proprietary one.
//!
//! What stays visible: the paying account. One payer's history groups its
//! memos — blinding the content does not hide who paid (limit, not gap: the
//! holder pays the gas, `[decision]` 19.09, CT-04).
//!
//! The scan key changes by period ([`SealScanKey::for_period`]): each seal
//! is blinded under the key of its month, derived from the holder's master
//! key. A key handed to an auditor reads its period's seals and no other's;
//! the reader takes a set of keys ([`SolanaReader::with_scan_keys`]) and a key
//! file holds one key or the keys of named periods ([`scan_keys_from_text`]).
//!
//! # What the reader establishes, and what it does not
//!
//! The finalized slot is a consensus quantity; `blockTime` is a stake-weighted
//! **estimate** of wall time, at one-second grain. The reader returns the
//! estimate as the anchoring moment because a seal or a status needs a moment, and says so
//! (`ksg-anchor-v2` writes what this reads).
//!
//! The cluster is the verifier's, not the anchor's, and it is checked against
//! the node itself: a node claiming to be mainnet is asked for its genesis hash.
//!
//! # Forks
//!
//! [`find_status_forks`] and [`find_bound_forks`] look for competing memos
//! among the transactions of the accounts that paid for the export's anchors.
//! A fork paid for by another account is not found this way; see the limits
//! in the module of the writer.

use std::collections::BTreeMap;

use ksg_core_v2::anchor::{Attestation, AttestationVerifier};
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::doc::{Timestamp, Uri};
use ksg_core_v2::error::Invalid;
use ksg_core_v2::journal::{BoundExport, RecordReport};
use ksg_core_v2::section::StatusExport;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// The anchor kind of a status record anchored on Solana with an open memo.
pub const STATUS_KIND: &str = "urn:ksg:anchor:solana:status:v1";

/// The anchor kind of a seal anchored on Solana with a blind memo.
pub const SEAL_KIND: &str = "urn:ksg:anchor:solana:seal:v1";

/// The anchor kind of an agent's ID published on Solana (KS-8 C-10, step 1).
pub const AGENT_ID_KIND: &str = "urn:ksg:anchor:solana:agent-id:v1";

/// The memo prefix of an agent's ID publication: open, by design — the point
/// of publishing is being readable (KS-8 C-10).
pub const AGENT_ID_MEMO_TAG: &str = "ksg:id:v1";

/// The longest open ID a publication memo carries, bytes: the memo must fit
/// one transaction with room to spare.
pub const AGENT_ID_MAX: usize = 200;

/// An agent's ID publication: `ksg:id:v1 <subject> <open id>`, `subject` the
/// hash that binds the ID to one container and one agent key
/// (`ksg_container_v2::identity::Publication::subject`). The container is
/// not in the memo — only in the hash — so two containers of one agent are
/// not linked through it (`[decision]` 12.09).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentIdMemo {
    /// What the publication's anchor attests.
    pub subject: Hash,
    /// The ID, in the open: a URI, so it carries no whitespace.
    pub open_id: String,
}

impl AgentIdMemo {
    /// Parses a memo; `None` for anything else, an ID with whitespace or one
    /// past [`AGENT_ID_MAX`].
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let mut parts = s.split_whitespace();
        if parts.next() != Some(AGENT_ID_MEMO_TAG) {
            return None;
        }
        let subject = Hash::from_multihash(parts.next()?).ok()?;
        let open_id = parts.next()?.to_owned();
        if parts.next().is_some() || open_id.len() > AGENT_ID_MAX {
            return None;
        }
        Some(Self { subject, open_id })
    }
}

impl core::fmt::Display for AgentIdMemo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{AGENT_ID_MEMO_TAG} {} {}",
            self.subject.to_multihash(),
            self.open_id
        )
    }
}

/// The memo prefix of a blind seal anchor.
pub const SEAL_MEMO_TAG: &str = "ksg:bs:v1";

/// The width of a blind value, bytes (as `ksg-anchor::blind`).
pub const SEAL_BLIND_LEN: usize = 16;

/// The salt of the extraction step: fixed and public, the secret is the key.
const SEAL_SALT: &[u8] = b"ksg:bs:v1";

/// The domain of a period key's derivation.
const PERIOD_INFO: &[u8] = b"ksg:bs:period:v1";

/// The scan keys of a file: one key (64 hex digits — a container whose key
/// never changes), or the keys of named periods,
/// `{"periods": {"2026-10": "<hex>", …}}`.
///
/// # Errors
///
/// Neither form, or a key that is not 32 bytes of hex.
pub fn scan_keys_from_text(s: &str) -> Result<Vec<SealScanKey>, String> {
    let t = s.trim();
    if !t.starts_with('{') {
        return SealScanKey::from_hex(t).map(|k| vec![k]);
    }
    let v: Value = serde_json::from_str(t).map_err(|e| format!("scan keys: {e}"))?;
    let periods = v
        .get("periods")
        .and_then(Value::as_object)
        .ok_or("scan keys: no \"periods\"")?;
    if periods.is_empty() {
        return Err("scan keys: no period".into());
    }
    periods
        .values()
        .map(|k| {
            k.as_str()
                .ok_or_else(|| "scan keys: a key is not text".to_owned())
                .and_then(SealScanKey::from_hex)
        })
        .collect()
}

/// The holder's scanning key for the seals of one container: the right to
/// recognize its anchors and to see a fork among them.
///
/// Compares in constant time, prints nothing, is wiped on drop — as
/// `ksg-anchor::blind::ScanKey`.
#[derive(Clone, Eq, zeroize::ZeroizeOnDrop)]
pub struct SealScanKey([u8; 32]);

impl PartialEq for SealScanKey {
    fn eq(&self, other: &Self) -> bool {
        let mut d = 0u8;
        for (a, b) in self.0.iter().zip(other.0.iter()) {
            d |= a ^ b;
        }
        d == 0
    }
}

impl core::fmt::Debug for SealScanKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SealScanKey(…)")
    }
}

impl SealScanKey {
    /// A key from 32 bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The key from its file: 64 hex characters, whitespace around ignored.
    ///
    /// # Errors
    ///
    /// Not 32 bytes of hex.
    pub fn from_hex(s: &str) -> Result<Self, String> {
        let v = zeroize::Zeroizing::new(
            hex::decode(s.trim()).map_err(|_| "scan key: not hex".to_owned())?,
        );
        let b: [u8; 32] = v
            .as_slice()
            .try_into()
            .map_err(|_| "scan key: not 32 bytes".to_owned())?;
        Ok(Self(b))
    }

    /// The key as its file holds it.
    #[must_use]
    pub fn to_hex(&self) -> zeroize::Zeroizing<String> {
        zeroize::Zeroizing::new(hex::encode(self.0))
    }

    fn prf(&self, domain: &[u8], h: &Hash) -> [u8; SEAL_BLIND_LEN] {
        let mut info = Vec::with_capacity(domain.len() + 32);
        info.extend_from_slice(domain);
        info.extend_from_slice(h.as_bytes());
        let mut out = [0u8; SEAL_BLIND_LEN];
        hkdf::Hkdf::<sha2::Sha256>::new(Some(SEAL_SALT), &self.0)
            .expand(&info, &mut out)
            .expect("16 bytes is within HKDF-SHA256's output");
        out
    }

    /// The key of one period, derived from a holder's master key: what the
    /// holder hands an auditor for that period alone. A key given out links
    /// its period's seals forever; it says nothing of another period's
    /// (KS-1 §14.3: rotation closes the future, never the past).
    ///
    /// `period` is a label — the reader uses the calendar month, `YYYY-MM`.
    #[must_use]
    pub fn for_period(&self, period: &str) -> Self {
        let mut info = Vec::with_capacity(PERIOD_INFO.len() + 8 + period.len());
        info.extend_from_slice(PERIOD_INFO);
        info.extend_from_slice(&(period.len() as u64).to_be_bytes());
        info.extend_from_slice(period.as_bytes());
        let mut out = [0u8; 32];
        hkdf::Hkdf::<sha2::Sha256>::new(Some(SEAL_SALT), &self.0)
            .expand(&info, &mut out)
            .expect("32 bytes is within HKDF-SHA256's output");
        Self(out)
    }

    /// The blind `link` of a seal whose predecessor is `prev`.
    #[must_use]
    pub fn link(&self, prev: &Hash) -> [u8; SEAL_BLIND_LEN] {
        self.prf(b"ksg:bs:link:v1", prev)
    }

    /// The blind `commit` of `seal`.
    #[must_use]
    pub fn commit(&self, seal: &Hash) -> [u8; SEAL_BLIND_LEN] {
        self.prf(b"ksg:bs:commit:v1", seal)
    }
}

/// A blind seal memo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealMemo {
    /// See the module note.
    pub link: [u8; SEAL_BLIND_LEN],
    /// See the module note.
    pub commit: [u8; SEAL_BLIND_LEN],
}

impl SealMemo {
    /// The memo of `seal`, whose predecessor is `prev` (the container's
    /// identifier for the first).
    #[must_use]
    pub fn of(key: &SealScanKey, prev: &Hash, seal: &Hash) -> Self {
        Self {
            link: key.link(prev),
            commit: key.commit(seal),
        }
    }

    /// Parses a memo; `None` for anything else, which is normal on a public
    /// chain — and for a memo of another width, which is not ours.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let mut parts = s.split_whitespace();
        if parts.next() != Some(SEAL_MEMO_TAG) {
            return None;
        }
        let f = |p: Option<&str>| -> Option<[u8; SEAL_BLIND_LEN]> {
            hex::decode(p?).ok()?.try_into().ok()
        };
        let link = f(parts.next())?;
        let commit = f(parts.next())?;
        if parts.next().is_some() {
            return None;
        }
        Some(Self { link, commit })
    }
}

impl core::fmt::Display for SealMemo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{SEAL_MEMO_TAG} {} {}",
            hex::encode(self.link),
            hex::encode(self.commit)
        )
    }
}

/// The memo prefix of a status anchor.
pub const STATUS_MEMO_TAG: &str = "ksg:st:v1";

/// The SPL Memo program, version 2.
pub const MEMO_PROGRAM: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

/// Genesis hashes of the public clusters: how a node proves which one it is.
pub const GENESIS: [(&str, &str); 3] = [
    (
        "mainnet-beta",
        "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d",
    ),
    ("devnet", "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG"),
    ("testnet", "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY"),
];

/// A single local node (`solana-test-validator`): a real Solana runtime that
/// nobody else sees. Its genesis is new on every start, so it cannot be
/// pinned; it is accepted only when named, and only if the node is **not**
/// one of the public clusters. An anchor on it proves that the transaction is
/// a valid Solana transaction and nothing more: no third party can see it,
/// and the node's history ends when the node is deleted.
pub const LOCALNET: &str = "localnet";

/// `link` of a status record whose `prev` is `prev`.
#[must_use]
pub fn status_link(prev: &Hash) -> Hash {
    Hash::sha256_parts(&[b"ksg:st:link:v1", prev.as_bytes()])
}

/// `commit` of a status record whose hash is `record`.
#[must_use]
pub fn status_commit(record: &Hash) -> Hash {
    Hash::sha256_parts(&[b"ksg:st:commit:v1", record.as_bytes()])
}

/// A status memo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusMemo {
    /// See the module note.
    pub link: Hash,
    /// See the module note.
    pub commit: Hash,
}

impl StatusMemo {
    /// The memo of a status record with this `prev` and this hash.
    #[must_use]
    pub fn of(prev: &Hash, record: &Hash) -> Self {
        Self {
            link: status_link(prev),
            commit: status_commit(record),
        }
    }

    /// Parses a memo; `None` for anybody else's memo, which is normal on a
    /// public chain.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let mut parts = s.split_whitespace();
        if parts.next() != Some(STATUS_MEMO_TAG) {
            return None;
        }
        let link = Hash::from_multihash(parts.next()?).ok()?;
        let commit = Hash::from_multihash(parts.next()?).ok()?;
        if parts.next().is_some() {
            return None;
        }
        Some(Self { link, commit })
    }
}

impl core::fmt::Display for StatusMemo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{STATUS_MEMO_TAG} {} {}",
            self.link.to_multihash(),
            self.commit.to_multihash()
        )
    }
}

/// Two memos after one head, of different records: a fork of the status
/// history.
#[must_use]
pub fn is_status_fork(a: &StatusMemo, b: &StatusMemo) -> bool {
    a.link == b.link && a.commit != b.commit
}

/// What `Attestation.proof` holds for a Solana anchor — a seal's or a status
/// record's: canonical JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorProof {
    /// The transaction signature, base58.
    pub signature: String,
    /// The slot the transaction landed in.
    pub slot: u64,
    /// The cluster: `mainnet-beta`, `devnet`, `testnet`.
    pub cluster: String,
}

impl AnchorProof {
    /// The proof as the bytes of `Attestation.proof`.
    ///
    /// # Errors
    ///
    /// Never in practice: three plain fields canonicalize.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Invalid> {
        let v = serde_json::to_value(self).map_err(|_| Invalid::Schema("anchor proof"))?;
        ksg_core_v2::canonical::canonicalize(&v)
    }

    /// The proof from `Attestation.proof`.
    ///
    /// # Errors
    ///
    /// The bytes are not an anchor proof.
    pub fn from_bytes(b: &[u8]) -> Result<Self, Invalid> {
        serde_json::from_slice(b).map_err(|_| Invalid::Schema("anchor proof: does not parse"))
    }
}

/// A JSON-RPC endpoint of a Solana node. A trait for the reason the anchoring
/// profile gives: the verifier chooses how it reaches the network.
pub trait Rpc {
    /// Calls `method` with `params`; returns `result`.
    ///
    /// # Errors
    ///
    /// Transport failure or an RPC error object, as text.
    fn call(&self, method: &str, params: Value) -> Result<Value, String>;
}

/// A transaction as the reader needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tx {
    /// The slot.
    pub slot: u64,
    /// The block time estimate, Unix seconds.
    pub block_time: Option<i64>,
    /// Who paid: the first account key.
    pub fee_payer: String,
    /// Every memo of the SPL Memo program in the transaction, as text.
    pub memos: Vec<String>,
}

fn err(s: &'static str) -> Invalid {
    Invalid::Schema(s)
}

/// Fetches a **finalized**, **successful** transaction. `Ok(None)` when the
/// node has none: not yet finalized, forged, or beyond the node's history —
/// three cases the reader cannot tell apart and does not try to.
///
/// # Errors
///
/// Transport, or a response of an unexpected shape.
pub fn get_transaction(rpc: &dyn Rpc, signature: &str) -> Result<Option<Tx>, String> {
    let v = rpc.call(
        "getTransaction",
        json!([signature, {"encoding": "json", "commitment": "finalized", "maxSupportedTransactionVersion": 0}]),
    )?;
    if v.is_null() {
        return Ok(None);
    }
    // A failed transaction still carries its memo in the instruction data;
    // only a successful one says anything.
    if !v["meta"]["err"].is_null() {
        return Ok(None);
    }
    let slot = v["slot"].as_u64().ok_or("getTransaction: no slot")?;
    let block_time = v["blockTime"].as_i64();
    let msg = &v["transaction"]["message"];
    let keys: Vec<&str> = msg["accountKeys"]
        .as_array()
        .ok_or("getTransaction: no account keys")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let fee_payer = (*keys.first().ok_or("getTransaction: no fee payer")?).to_owned();
    let mut memos = Vec::new();
    for ix in msg["instructions"]
        .as_array()
        .map_or(&[][..], Vec::as_slice)
    {
        let idx = ix["programIdIndex"]
            .as_u64()
            .and_then(|i| usize::try_from(i).ok());
        if idx.and_then(|i| keys.get(i)) != Some(&MEMO_PROGRAM) {
            continue;
        }
        let data = ix["data"]
            .as_str()
            .ok_or("getTransaction: no instruction data")?;
        let bytes = bs58::decode(data)
            .into_vec()
            .map_err(|e| format!("instruction data: {e}"))?;
        if let Ok(s) = String::from_utf8(bytes) {
            memos.push(s);
        }
    }
    Ok(Some(Tx {
        slot,
        block_time,
        fee_payer,
        memos,
    }))
}

/// Signatures of an account's transactions, newest first, down to (not
/// including) `until` when given.
///
/// # Errors
///
/// Transport, or a response of an unexpected shape.
pub fn signatures_for(
    rpc: &dyn Rpc,
    address: &str,
    until: Option<&str>,
    limit: u32,
) -> Result<Vec<String>, String> {
    let mut cfg = json!({"limit": limit, "commitment": "finalized"});
    if let Some(u) = until {
        cfg["until"] = json!(u);
    }
    let v = rpc.call("getSignaturesForAddress", json!([address, cfg]))?;
    Ok(v.as_array()
        .ok_or("getSignaturesForAddress: not an array")?
        .iter()
        .filter(|s| s["err"].is_null())
        .filter_map(|s| s["signature"].as_str().map(str::to_owned))
        .collect())
}

/// Asks the node which cluster it is.
///
/// # Errors
///
/// The node answered with another cluster's genesis, or not at all.
pub fn check_cluster(rpc: &dyn Rpc, cluster: &str) -> Result<(), String> {
    if cluster == LOCALNET {
        let got = rpc.call("getGenesisHash", json!([]))?;
        let got = got.as_str().ok_or("getGenesisHash: not a string")?;
        // A public cluster passed off as a local node would carry real
        // anchors under a test label, and the other way round a local node
        // can never pass for a public cluster: the list above pins those.
        return match GENESIS.iter().find(|(_, g)| *g == got) {
            Some((name, _)) => Err(format!("the node is {name}, not a local node")),
            None => Ok(()),
        };
    }
    let expected = GENESIS
        .iter()
        .find(|(c, _)| *c == cluster)
        .map(|(_, g)| *g)
        .ok_or_else(|| format!("unknown cluster {cluster}"))?;
    let got = rpc.call("getGenesisHash", json!([]))?;
    if got.as_str() == Some(expected) {
        Ok(())
    } else {
        Err(format!("the node is not {cluster}: genesis {got}"))
    }
}

/// The reader of Solana anchors on one cluster: what [`crate::Expected`] takes.
pub struct SolanaReader<'a> {
    cluster: String,
    rpc: &'a dyn Rpc,
    scan: Vec<SealScanKey>,
}

impl core::fmt::Debug for SolanaReader<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SolanaReader")
            .field("cluster", &self.cluster)
            .finish_non_exhaustive()
    }
}

impl<'a> SolanaReader<'a> {
    /// A reader of `cluster` through `rpc`, once the node has shown it is that
    /// cluster.
    ///
    /// # Errors
    ///
    /// See [`check_cluster`].
    pub fn connect(rpc: &'a dyn Rpc, cluster: &str) -> Result<Self, String> {
        check_cluster(rpc, cluster)?;
        Ok(Self {
            cluster: cluster.to_owned(),
            rpc,
            scan: Vec::new(),
        })
    }

    /// The same reader, able to recognize blind seal anchors: without the
    /// holder's scan key a seal anchor is noise and is refused.
    #[must_use]
    pub fn with_scan_key(mut self, key: SealScanKey) -> Self {
        self.scan.push(key);
        self
    }

    /// As [`SolanaReader::with_scan_key`], with every key of a set: a
    /// container whose scan key changes by period has one per period.
    #[must_use]
    pub fn with_scan_keys(mut self, keys: impl IntoIterator<Item = SealScanKey>) -> Self {
        self.scan.extend(keys);
        self
    }
}

/// `secs` since the epoch as a [`Timestamp`].
fn utc_secs(secs: i64) -> Result<Timestamp, Invalid> {
    let ms = u64::try_from(secs).map_err(|_| err("block time before 1970"))? * 1000;
    Ok(crate::clock::utc(ms))
}

impl AttestationVerifier for SolanaReader<'_> {
    fn verify(&self, a: &Attestation) -> Result<Timestamp, Invalid> {
        let seal = a.kind.as_str() == SEAL_KIND;
        let agent_id = a.kind.as_str() == AGENT_ID_KIND;
        if !seal && !agent_id && a.kind.as_str() != STATUS_KIND {
            return Err(err("not a Solana anchor of a seal or a status record"));
        }
        if seal && self.scan.is_empty() {
            return Err(err(
                "a blind seal anchor: the holder's scan key is needed to read it",
            ));
        }
        let proof = AnchorProof::from_bytes(&a.proof)?;
        // Checked before the network: a devnet anchor must not even pass as
        // a question to a mainnet reader.
        if proof.cluster != self.cluster {
            return Err(err("the anchor is of another cluster"));
        }
        let tx = get_transaction(self.rpc, &proof.signature)
            .map_err(|_| err("the node did not answer"))?
            .ok_or(err(
                "no finalized successful transaction under this signature",
            ))?;
        if tx.slot != proof.slot {
            return Err(err("the anchor's slot is not the transaction's"));
        }
        let found = if agent_id {
            // KS-8 C-10: the open memo names the very subject.
            tx.memos
                .iter()
                .filter_map(|m| AgentIdMemo::parse(m))
                .any(|m| m.subject == a.subject)
        } else if seal {
            // One key per period: the seal's is whichever commits to it.
            tx.memos
                .iter()
                .filter_map(|m| SealMemo::parse(m))
                .any(|m| self.scan.iter().any(|k| m.commit == k.commit(&a.subject)))
        } else {
            let want = status_commit(&a.subject);
            tx.memos
                .iter()
                .filter_map(|m| StatusMemo::parse(m))
                .any(|m| m.commit == want)
        };
        if !found {
            return Err(err("the transaction's memo is of another subject"));
        }
        utc_secs(tx.block_time.ok_or(err("the node gave no block time"))?)
    }

    fn handles(&self, kind: &Uri) -> bool {
        kind.as_str() == STATUS_KIND || kind.as_str() == SEAL_KIND || kind.as_str() == AGENT_ID_KIND
    }
}

/// A second record after the same head, found in the network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Fork {
    /// The number of the exported record that has a rival: the status
    /// record's number, or the last page of the journal's record.
    pub number: u64,
    /// The transaction that anchored the rival.
    pub signature: String,
}

/// Looks for rivals of the section's status records among the transactions
/// of the accounts that paid for its anchors, at most `limit` per account.
///
/// # Errors
///
/// Transport, or an anchor that is not an anchor proof.
pub fn find_status_forks(rpc: &dyn Rpc, x: &StatusExport, limit: u32) -> Result<Vec<Fork>, String> {
    let mut anchored = Vec::new();
    for (r, a) in &x.records {
        let h = r.hash().map_err(|e| e.to_string())?;
        anchored.push((
            r.number,
            status_link(&r.prev).as_bytes().to_vec(),
            status_commit(&h).as_bytes().to_vec(),
            a,
        ));
    }
    rivals(rpc, &anchored, limit, &|m: &str| {
        StatusMemo::parse(m).map(|m| (m.link.as_bytes().to_vec(), m.commit.as_bytes().to_vec()))
    })
}

/// The same for a journal under the movable seal: a seal is memoed blind
/// (see the module note), `link` over the seal before it — the container's
/// identifier before the first — and `commit` over itself, so a rival is a
/// second seal after the same seal. Only the holder of `scan` can look.
/// `records` are the export's records as [`verify_bound`] gave them.
///
/// [`verify_bound`]: ksg_core_v2::journal::verify_bound
///
/// # Errors
///
/// Transport, or an anchor that is not an anchor proof.
pub fn find_bound_forks(
    rpc: &dyn Rpc,
    x: &BoundExport,
    records: &[RecordReport],
    scan: &[SealScanKey],
    limit: u32,
) -> Result<Vec<Fork>, String> {
    let mut anchored = Vec::new();
    for a in &x.anchors {
        let i = records
            .iter()
            .position(|r| r.batch == a.batch)
            .ok_or("an anchor of no record")?;
        let prev = if i == 0 {
            x.seal.container
        } else {
            records[i - 1].seal
        };
        // Under every key given: a link under the wrong period's key
        // matches no memo of the network, so it finds no rival either.
        for k in scan {
            anchored.push((
                records[i].last,
                k.link(&prev).to_vec(),
                k.commit(&records[i].seal).to_vec(),
                &a.anchor,
            ));
        }
    }
    rivals(rpc, &anchored, limit, &|m: &str| {
        SealMemo::parse(m).map(|m| (m.link.to_vec(), m.commit.to_vec()))
    })
}

/// The memo of a seal whose predecessor is `prev` (or the container's
/// identifier, for the first).
#[must_use]
pub fn seal_memo(scan: &SealScanKey, prev: &Hash, seal: &Hash) -> SealMemo {
    SealMemo::of(scan, prev, seal)
}

type Memo = (Vec<u8>, Vec<u8>);

fn rivals(
    rpc: &dyn Rpc,
    anchored: &[(u64, Vec<u8>, Vec<u8>, &Attestation)],
    limit: u32,
    parse: &dyn Fn(&str) -> Option<Memo>,
) -> Result<Vec<Fork>, String> {
    // link → (number, commit) for every anchor of the export.
    let mut ours: BTreeMap<Vec<u8>, (u64, Vec<u8>)> = BTreeMap::new();
    let mut payers: Vec<String> = Vec::new();
    for (number, l, c, a) in anchored {
        if a.kind.as_str() != STATUS_KIND && a.kind.as_str() != SEAL_KIND {
            continue;
        }
        let proof = AnchorProof::from_bytes(&a.proof).map_err(|e| e.to_string())?;
        ours.insert(l.clone(), (*number, c.clone()));
        if let Some(tx) = get_transaction(rpc, &proof.signature)? {
            if !payers.contains(&tx.fee_payer) {
                payers.push(tx.fee_payer);
            }
        }
    }
    let mut forks = Vec::new();
    for payer in &payers {
        for sig in signatures_for(rpc, payer, None, limit)? {
            let Some(tx) = get_transaction(rpc, &sig)? else {
                continue;
            };
            for (l, c2) in tx.memos.iter().filter_map(|m| parse(m)) {
                if let Some((number, c)) = ours.get(&l) {
                    if *c != c2 {
                        forks.push(Fork {
                            number: *number,
                            signature: sig.clone(),
                        });
                    }
                }
            }
        }
    }
    Ok(forks)
}

/// A node's address as it may be printed: scheme and host only. Providers
/// put the client key in the path (`/v2/<key>`) or the query, so the rest
/// never goes into an error, a log or a report (live run 17.10).
#[must_use]
pub fn redact_url(url: &str) -> String {
    let Some(i) = url.find("://") else {
        return "<node address>".into();
    };
    let rest = &url[i + 3..];
    let host_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let host = rest[..host_end].rsplit('@').next().unwrap_or_default();
    let tail = if host_end < rest.len() { "/…" } else { "" };
    format!("{}{host}{tail}", &url[..i + 3])
}

/// Where a node is: the address itself, or `env:NAME` — read from the
/// environment variable `NAME`, so that an address carrying a key need not
/// be written into a file such as `container.json` (live run 17.10).
///
/// # Errors
///
/// `env:NAME` with `NAME` unset.
pub fn node_address(given: &str) -> Result<String, String> {
    match given.strip_prefix("env:") {
        Some(name) => std::env::var(name)
            .map_err(|_| format!("the node's address: the variable {name} is not set")),
        None => Ok(given.to_owned()),
    }
}

/// A JSON-RPC endpoint over HTTP(S). The proxy comes from `HTTPS_PROXY` for
/// `https` addresses; trusted roots from the system (and `SSL_CERT_FILE`).
/// The address may be `env:NAME` ([`node_address`]); errors name the node
/// by [`redact_url`] only.
#[cfg(feature = "rpc")]
pub struct HttpRpc {
    url: String,
    agent: ureq::Agent,
}

#[cfg(feature = "rpc")]
impl HttpRpc {
    /// An endpoint at `url`.
    ///
    /// # Errors
    ///
    /// The proxy address in the environment does not parse.
    pub fn new(url: &str) -> Result<Self, String> {
        let url = &node_address(url)?;
        let mut b = ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(30));
        if url.starts_with("https://") {
            if let Some(p) = std::env::var("HTTPS_PROXY")
                .ok()
                .or_else(|| std::env::var("https_proxy").ok())
            {
                b = b.proxy(ureq::Proxy::new(p).map_err(|e| format!("proxy: {e}"))?);
            }
        }
        Ok(Self {
            url: url.to_owned(),
            agent: b.build(),
        })
    }
}

#[cfg(feature = "rpc")]
impl HttpRpc {
    fn hide(&self, method: &str, e: &str) -> String {
        format!("{method}: {}", e.replace(&self.url, &redact_url(&self.url)))
    }
}

#[cfg(feature = "rpc")]
impl Rpc for HttpRpc {
    fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let resp: Value = self
            .agent
            .post(&self.url)
            .send_json(body)
            .map_err(|e| self.hide(method, &e.to_string()))?
            .into_json()
            .map_err(|e| self.hide(method, &e.to_string()))?;
        if let Some(e) = resp.get("error") {
            return Err(format!("{method}: {e}"));
        }
        Ok(resp.get("result").cloned().unwrap_or(Value::Null))
    }
}
