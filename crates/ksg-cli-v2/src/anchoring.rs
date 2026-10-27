//! Anchoring seals and status records on Solana, and catching a rolled-back
//! file (audit K5).
//!
//! # What is anchored
//!
//! In Pro every seal of the journal is anchored (CH-7): the memo is the
//! **blind** `ksg:bs:v1 <link> <commit>` (`ksg_verify_v2::solana`, module note)
//! with `link` over the seal before it — the container's identifier before the
//! first — and `commit` over the seal itself, both under the holder's scan key
//! (`scan.key`): an observer without it sees that an anchor exists and nothing
//! else (`[decision]` 13.09). The seal's tree covers every page before it, so one memo fixes
//! them all as they stood (CH-25). The light form anchors nothing (CH-24).
//!
//! Every **status record** is anchored too, in every class (spec v2 §11: a
//! status change is a record **and** its anchor; without a read anchor a
//! status has no time). Its memo is **open** — `ksg:st:v1 <link> <commit>`
//! over the record before it and the record itself (`ksg_verify_v2::solana`,
//! module note) — because the status section is the part of a container that
//! is read (KS-7 §7.2-octies): a buyer must see it, so there is nothing to
//! blind. Record 0 is anchored when the container is printed.
//!
//! # A seal goes to the network only once the container has taken it
//!
//! The anchor is part of the write (`Writes`), so it must exist before the
//! press. An anchor for a seal the container then refuses would sit in the
//! network after the head with nothing behind it — and read, later, as a fork.
//! So the reader first presses a **copy** of the container with a placeholder
//! anchor; only if the copy takes the record does the memo go out, and then
//! the real container is pressed with the real anchor. The same holds for a
//! status record: a memo for a status the container refuses would read as a
//! fork of the status history.
//!
//! # Rollback
//!
//! On opening, the reader asks the network for the payer's transactions newer
//! than the last one this file knows of. A memo among them whose `link` is
//! this file's top seal is a seal put on **after** this file — by a later copy
//! of the container; so is a status memo whose `link` is this file's last
//! status record. The file is an old copy, and writing from it would fork the
//! journal or the status history; the reader refuses to open it.
//!
//! # Limits, stated where the code is
//!
//! * A status memo is open: whoever holds the section walks its anchors, and
//!   so does whoever learns one record's hash — by design, the section is
//!   public (KS-7 §7.2-octies).
//! * One payer account pays for every page; its history groups the
//!   container's anchors for anyone who knows the address — the memos are
//!   blind, the payer is not. The holder pays the gas (`[decision]` 19.09,
//!   CT-04); a payer per container is the holder's choice.
//! * A rollback is caught only if the later copy anchored through the same
//!   payer.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use ksg_anchor_v2::solana_tx::{address, key_from_file_bytes, memo_transaction};
use ksg_core_v2::anchor::Attestation;
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::doc::Uri;
use ksg_verify_v2::solana::{
    check_cluster, get_transaction, signatures_for, status_link, AnchorProof, Rpc, SealMemo,
    SealScanKey, StatusMemo, SEAL_KIND, STATUS_KIND,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use zeroize::Zeroizing;

use crate::home::read;

/// The block time estimate as the anchoring moment; 1970 when the node gave
/// none (which the reader then refuses, as it should).
pub(crate) fn block_time_utc(t: Option<i64>) -> ksg_core_v2::doc::Timestamp {
    ksg_verify_v2::clock::utc(u64::try_from(t.unwrap_or(0)).unwrap_or(0) * 1000)
}

/// What a memo anchors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MemoKind {
    /// A seal of the journal: the blind `ksg:bs:v1`.
    Seal,
    /// A status record: the open `ksg:st:v1`.
    Status,
}

/// The memo of a seal or a status record.
#[must_use]
pub fn memo_of(kind: MemoKind, scan: &SealScanKey, prev: &Hash, subject: &Hash) -> String {
    match kind {
        MemoKind::Seal => SealMemo::of(scan, prev, subject).to_string(),
        MemoKind::Status => StatusMemo::of(prev, subject).to_string(),
    }
}

/// A transaction sent and not yet known to have landed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sent {
    /// Its signature, base58.
    pub signature: String,
    /// The blockhash it was built on: once the node no longer takes it, the
    /// transaction can no longer land.
    pub blockhash: String,
}

/// Where a sent transaction stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Landing {
    /// Finalized: the transaction's signature, its slot and the block time
    /// estimate.
    Landed {
        /// The transaction signature, base58.
        signature: String,
        /// The slot.
        slot: u64,
        /// The block time estimate, Unix seconds.
        block_time: Option<i64>,
    },
    /// Not finalized, and may still be.
    Pending,
    /// Can never land: unknown to the node, its blockhash expired.
    Dropped,
    /// Landed with an error: it wrote no memo.
    Failed(String),
}

/// A memo the container owes the network: its record is in the container
/// under a placeholder anchor, and the network's attestation replaces the
/// placeholder once the memo lands. Kept in `container.json` until then.
///
/// Why it exists: a memo sent whose transaction did not finalize in time
/// used to be forgotten with its record — and when it landed after all, the
/// next record's memo made **two** memos after one head, which a reader of
/// the network reads as a fork. Now the record stays, and the memo is asked
/// about by its signature before it is ever sent again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingAnchor {
    /// Seal or status record.
    pub kind: MemoKind,
    /// What the memo links: the seal or record before, as a multihash.
    pub prev: String,
    /// What it commits to, as a multihash.
    pub subject: String,
    /// The transaction, once sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sent: Option<Sent>,
    /// The scan key's period a seal memo is blinded under — kept so that a
    /// memo sent again is the same memo. Absent for status memos and for a
    /// container whose scan key does not change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub period: Option<String>,
}

/// Where and with what the container anchors its pages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorCfg {
    /// `devnet`, `testnet` or `mainnet-beta`.
    pub cluster: String,
    /// The node's JSON-RPC address.
    pub rpc: String,
    /// The payer's key file (Solana CLI format) — when the reader sends its
    /// memos itself. Absent when they go through the service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payer: Option<PathBuf>,
    /// The service the memos go through (`[decision]` 19.09, CT-04: we
    /// anchor, the holder pays the gas from the payer the service holds for
    /// it). Absent — the reader sends them itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<ServiceRoute>,
    /// The last transaction this container sent: where the rollback check
    /// starts looking.
    #[serde(default)]
    pub last_signature: Option<String>,
    /// Memos owed to the network, oldest first ([`PendingAnchor`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pending: Vec<PendingAnchor>,
    /// Whether the scan key changes every period (the calendar month, UTC):
    /// each seal memo is blinded under the key of its month, derived from
    /// the holder's master key in `scan.key` (`SealScanKey::for_period`).
    /// Containers printed before this have one key for life and keep it.
    #[serde(default)]
    pub rotate_scan: bool,
    /// The periods whose keys blinded at least one seal memo, oldest first:
    /// what `ksg-remote-panel scan-key` hands out.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scan_periods: Vec<String>,
}

impl AnchorCfg {
    /// The key a seal memo of `period` is blinded under.
    #[must_use]
    pub fn seal_key(&self, master: &SealScanKey, period: Option<&str>) -> SealScanKey {
        match period {
            Some(p) if self.rotate_scan => master.for_period(p),
            _ => master.clone(),
        }
    }

    /// Every key a seal of this container may be blinded under now: the
    /// keys of the periods used and of the current one — or the one key.
    #[must_use]
    pub fn seal_keys(&self, master: &SealScanKey, now: &str) -> Vec<SealScanKey> {
        if !self.rotate_scan {
            return vec![master.clone()];
        }
        let mut periods: Vec<&str> = self.scan_periods.iter().map(String::as_str).collect();
        if !periods.contains(&now) {
            periods.push(now);
        }
        periods.into_iter().map(|p| master.for_period(p)).collect()
    }
}

/// The scan key's period of a moment: its calendar month, UTC, `YYYY-MM`.
#[must_use]
pub fn scan_period(ms: u64) -> String {
    let t = ksg_verify_v2::clock::utc(ms);
    t.as_str().get(..7).unwrap_or("0000-00").to_owned()
}

/// The period seals are blinded in now: the current month, or
/// `KSG_SCAN_PERIOD` when it is set to a `YYYY-MM` — for drills and tests of
/// a change of period, which otherwise take a month. It chooses only which
/// of the holder's own keys blinds the holder's own memos.
#[must_use]
pub fn current_scan_period() -> String {
    std::env::var("KSG_SCAN_PERIOD")
        .ok()
        .filter(|p| {
            let b = p.as_bytes();
            b.len() == 7
                && b.get(4) == Some(&b'-')
                && b.iter()
                    .enumerate()
                    .all(|(i, c)| i == 4 || c.is_ascii_digit())
        })
        .unwrap_or_else(|| scan_period(crate::clock::now_ms()))
}

/// The anchoring service a container's memos go through.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceRoute {
    /// The service's address.
    pub url: String,
    /// This holder's name at the service.
    pub holder: String,
}

impl AnchorCfg {
    /// The public RPC of a cluster.
    #[must_use]
    pub fn default_rpc(cluster: &str) -> String {
        if cluster == ksg_verify_v2::solana::LOCALNET {
            // Where `solana-test-validator` listens by default.
            return "http://127.0.0.1:8899".to_owned();
        }
        format!(
            "https://api.{}.solana.com",
            if cluster == "mainnet-beta" {
                "mainnet-beta"
            } else {
                cluster
            }
        )
    }
}

/// Who sends the memos.
enum Via {
    /// The reader itself, with the payer's key.
    Direct(SigningKey),
    /// The anchoring service, asked as this holder, signing with the owner
    /// key, for this container.
    #[cfg(feature = "rpc")]
    Service {
        svc: crate::service::Service,
        holder: String,
        signer: Box<ksg_core_v2::crypto::sign::Ed25519Signer>,
        container: Hash,
    },
}

/// The payer and the node, ready to anchor — directly or through the
/// service.
pub struct Anchorer {
    rpc: Box<dyn Rpc + Send>,
    via: Via,
    cluster: String,
    /// The payer's address: the reader's own, or the one the service pays
    /// from for this holder. The rollback check reads its history.
    pub address: String,
    wait: Duration,
}

/// The job number in a [`Sent`] of the service: `job:N`.
#[cfg(feature = "rpc")]
const JOB: &str = "job:";

fn wait_from_env() -> Duration {
    std::env::var("KSG_ANCHOR_WAIT_S")
        .ok()
        .and_then(|s| s.parse().ok())
        .map_or(Duration::from_secs(120), Duration::from_secs)
}

impl Anchorer {
    /// Checks, at printing, that `cfg` can anchor: the node is of its
    /// cluster and the payer's key reads — or the service answers for that
    /// cluster. Nothing is sent.
    ///
    /// # Errors
    ///
    /// What would make the first anchor fail.
    #[cfg(feature = "rpc")]
    pub fn probe(cfg: &AnchorCfg) -> Result<(), String> {
        let rpc = ksg_verify_v2::solana::HttpRpc::new(&cfg.rpc)?;
        check_cluster(&rpc, &cfg.cluster)?;
        match (&cfg.service, &cfg.payer) {
            (Some(route), None) => {
                let h = crate::service::Service::new(&route.url).get("/v1/health")?;
                if h.get("cluster").and_then(serde_json::Value::as_str)
                    != Some(cfg.cluster.as_str())
                {
                    return Err(format!(
                        "the service at {} anchors on another cluster than {}",
                        route.url, cfg.cluster
                    ));
                }
                Ok(())
            }
            (None, Some(payer)) => {
                let bytes = Zeroizing::new(read(payer)?);
                key_from_file_bytes(&bytes).map_err(|e| format!("{}: {e}", payer.display()))?;
                Ok(())
            }
            _ => Err("anchoring needs a payer key file or a service, one of them".into()),
        }
    }

    /// Connects to the node of `cfg` and checks it is that cluster; then
    /// reads the payer's key, or asks the service, as `holder` signing with
    /// `owner`, which payer it anchors `container`'s memos from.
    ///
    /// # Errors
    ///
    /// The node is another cluster or unreachable; the key file is not a
    /// key; the service refused.
    #[cfg(feature = "rpc")]
    pub fn connect(
        cfg: &AnchorCfg,
        owner: &ksg_core_v2::crypto::sign::Ed25519Signer,
        container: Hash,
    ) -> Result<Self, String> {
        let rpc = ksg_verify_v2::solana::HttpRpc::new(&cfg.rpc)?;
        check_cluster(&rpc, &cfg.cluster)?;
        let (via, address) = match (&cfg.service, &cfg.payer) {
            (Some(route), None) => {
                let svc = crate::service::Service::new(&route.url);
                let me = svc.get_signed("/v1/holder", owner, &route.holder)?;
                if me.get("cluster").and_then(serde_json::Value::as_str)
                    != Some(cfg.cluster.as_str())
                {
                    return Err(format!(
                        "the service at {} anchors on another cluster than {}",
                        route.url, cfg.cluster
                    ));
                }
                let address = me
                    .get("payer")
                    .and_then(serde_json::Value::as_str)
                    .ok_or("the service names no payer for this holder")?
                    .to_owned();
                (
                    Via::Service {
                        svc,
                        holder: route.holder.clone(),
                        signer: Box::new(owner.clone()),
                        container,
                    },
                    address,
                )
            }
            (None, Some(_)) => return Self::with_rpc(Box::new(rpc), cfg),
            _ => return Err("anchoring needs a payer key file or a service, one of them".into()),
        };
        Ok(Self {
            rpc: Box::new(rpc),
            via,
            cluster: cfg.cluster.clone(),
            address,
            wait: wait_from_env(),
        })
    }

    /// The reader sending its memos itself, through a given node.
    ///
    /// # Errors
    ///
    /// The node is another cluster or unreachable; no payer key file, or it
    /// is not a key.
    pub fn with_rpc(rpc: Box<dyn Rpc + Send>, cfg: &AnchorCfg) -> Result<Self, String> {
        check_cluster(rpc.as_ref(), &cfg.cluster)?;
        let payer = cfg
            .payer
            .as_ref()
            .ok_or("sending memos directly needs the payer's key file")?;
        let bytes = Zeroizing::new(read(payer)?);
        let key = key_from_file_bytes(&bytes).map_err(|e| format!("{}: {e}", payer.display()))?;
        Ok(Self {
            address: address(&key.verifying_key()),
            rpc,
            via: Via::Direct(key),
            cluster: cfg.cluster.clone(),
            wait: wait_from_env(),
        })
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
        v["value"]
            .as_u64()
            .ok_or_else(|| "getBalance: no value".into())
    }

    /// Anchors a seal: sends its memo — `link` of `prev`, the seal before it
    /// or the container's identifier, `commit` of `seal` — waits for
    /// finalization, returns the attestation and the transaction's signature.
    ///
    /// # Errors
    ///
    /// The network refused the transaction (no funds, too many requests) or
    /// did not finalize it in time.
    pub fn anchor_seal(
        &self,
        scan: &SealScanKey,
        prev: &Hash,
        seal: &Hash,
    ) -> Result<(Attestation, String), String> {
        self.anchor(
            &memo_of(MemoKind::Seal, scan, prev, seal),
            MemoKind::Seal,
            seal,
        )
    }

    /// Anchors a status record: sends its open memo — `link` of `prev`, the
    /// record before it or the section root, `commit` of `record` — waits
    /// for finalization, returns the attestation and the transaction's
    /// signature.
    ///
    /// # Errors
    ///
    /// As [`Anchorer::anchor_seal`].
    pub fn anchor_status(
        &self,
        prev: &Hash,
        record: &Hash,
    ) -> Result<(Attestation, String), String> {
        let memo = StatusMemo::of(prev, record).to_string();
        self.anchor(&memo, MemoKind::Status, record)
    }

    fn anchor(
        &self,
        memo: &str,
        kind: MemoKind,
        subject: &Hash,
    ) -> Result<(Attestation, String), String> {
        let (sig, slot, block_time) = self.send_memo(kind, subject, memo)?;
        Ok((
            self.attestation(kind, subject, &sig, slot, block_time)?,
            sig,
        ))
    }

    /// The attestation of `subject` by the landed transaction `sig`.
    ///
    /// # Errors
    ///
    /// Never in practice: the proof's three fields canonicalize.
    pub fn attestation(
        &self,
        kind: MemoKind,
        subject: &Hash,
        sig: &str,
        slot: u64,
        block_time: Option<i64>,
    ) -> Result<Attestation, String> {
        let proof = AnchorProof {
            signature: sig.to_owned(),
            slot,
            cluster: self.cluster.clone(),
        };
        Ok(Attestation {
            kind: Uri::parse(match kind {
                MemoKind::Seal => SEAL_KIND,
                MemoKind::Status => STATUS_KIND,
            })
            .map_err(|e| e.to_string())?,
            subject: *subject,
            proof: proof.to_bytes().map_err(|e| e.to_string())?,
            anchored_at: block_time_utc(block_time),
        })
    }

    /// The cluster anchored on.
    #[must_use]
    pub fn cluster(&self) -> &str {
        &self.cluster
    }

    /// Sends `memo` in one transaction and waits for it to finalize: the
    /// signature and the transaction as the node then reports it.
    ///
    /// # Errors
    ///
    /// The network refused the transaction (no funds, too many requests) or
    /// did not finalize it in time.
    pub fn send_memo(
        &self,
        kind: MemoKind,
        subject: &Hash,
        memo: &str,
    ) -> Result<(String, u64, Option<i64>), String> {
        let sent = self.submit(kind, subject, memo)?;
        self.land(&sent)
    }

    /// Waits for a sent memo: its signature, slot and block time once final.
    fn land(&self, sent: &Sent) -> Result<(String, u64, Option<i64>), String> {
        match self.wait(sent)? {
            Landing::Landed {
                signature,
                slot,
                block_time,
            } => Ok((signature, slot, block_time)),
            Landing::Pending => Err(format!(
                "the anchor {} did not finalize in {:?}",
                sent.signature, self.wait
            )),
            Landing::Dropped => Err(format!(
                "the anchor {} was dropped by the network",
                sent.signature
            )),
            Landing::Failed(e) => Err(format!("the anchor transaction failed: {e}")),
        }
    }

    /// Sends `memo` in one transaction **without waiting**: its signature
    /// and the blockhash it was built on — what [`Anchorer::landing`] needs
    /// to tell a slow transaction from a dead one.
    ///
    /// # Errors
    ///
    /// The network refused the transaction: it did not go out.
    pub fn submit(&self, kind: MemoKind, subject: &Hash, memo: &str) -> Result<Sent, String> {
        self.submit_as(&json!(kind), subject, memo)
    }

    /// Publishes an agent's ID (KS-8 C-10, step 1): the open memo
    /// `ksg:id:v1 <subject> <open id>`, waited for until final. Returns the
    /// attestation of `subject` and the transaction's signature.
    ///
    /// Not a [`MemoKind`]: a publication is never pending and never re-sent
    /// with the journal's anchors — it goes once, before anything rests on it.
    ///
    /// # Errors
    ///
    /// As [`Anchorer::anchor_seal`].
    pub fn publish_agent_id(
        &self,
        subject: &Hash,
        open_id: &str,
    ) -> Result<(Attestation, String), String> {
        use ksg_verify_v2::solana::{AgentIdMemo, AGENT_ID_KIND};
        let memo = AgentIdMemo {
            subject: *subject,
            open_id: open_id.to_owned(),
        }
        .to_string();
        let sent = self.submit_as(&json!("agent-id"), subject, &memo)?;
        let (sig, slot, block_time) = self.land(&sent)?;
        let proof = AnchorProof {
            signature: sig.clone(),
            slot,
            cluster: self.cluster.clone(),
        };
        Ok((
            Attestation {
                kind: Uri::parse(AGENT_ID_KIND).map_err(|e| e.to_string())?,
                subject: *subject,
                proof: proof.to_bytes().map_err(|e| e.to_string())?,
                anchored_at: block_time_utc(block_time),
            },
            sig,
        ))
    }

    fn submit_as(
        &self,
        kind: &serde_json::Value,
        subject: &Hash,
        memo: &str,
    ) -> Result<Sent, String> {
        let key = match &self.via {
            Via::Direct(key) => key,
            #[cfg(feature = "rpc")]
            Via::Service {
                svc,
                holder,
                signer,
                container,
            } => {
                let got = svc.post(
                    "/v1/anchor",
                    &json!({
                        "container": container.to_multihash(),
                        "kind": kind,
                        "subject": subject.to_multihash(),
                        "memo": memo,
                    }),
                    Some((signer, holder)),
                )?;
                let job = got
                    .get("job")
                    .and_then(serde_json::Value::as_u64)
                    .ok_or("the service gave no job number")?;
                return Ok(Sent {
                    signature: format!("{JOB}{job}"),
                    blockhash: String::new(),
                });
            }
        };
        let _ = (kind, subject);
        let bh = self
            .rpc
            .call("getLatestBlockhash", json!([{"commitment": "finalized"}]))?;
        let blockhash = bh["value"]["blockhash"]
            .as_str()
            .ok_or("getLatestBlockhash: no blockhash")?
            .to_owned();
        let bytes: [u8; 32] = bs58::decode(&blockhash)
            .into_vec()
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or("getLatestBlockhash: not 32 bytes")?;
        let (tx, sig) =
            memo_transaction(key, &bytes, memo.as_bytes()).map_err(|e| e.to_string())?;
        let sent = self.rpc.call(
            "sendTransaction",
            json!([B64.encode(&tx), {"encoding": "base64", "preflightCommitment": "confirmed"}]),
        )?;
        if sent.as_str() != Some(sig.as_str()) {
            return Err(format!("sendTransaction: the node answered {sent}"));
        }
        Ok(Sent {
            signature: sig,
            blockhash,
        })
    }

    /// Where a sent transaction stands, asked once.
    ///
    /// Unknown to the node **and** built on a blockhash the node no longer
    /// takes — dropped: it can never land, and sending its memo again puts
    /// one memo, not two, in the network. Unknown with a live blockhash —
    /// still pending: it may land yet.
    ///
    /// # Errors
    ///
    /// The node did not answer.
    pub fn landing(&self, sent: &Sent) -> Result<Landing, String> {
        #[cfg(feature = "rpc")]
        if let (
            Via::Service {
                svc,
                holder,
                signer,
                ..
            },
            Some(job),
        ) = (&self.via, sent.signature.strip_prefix(JOB))
        {
            return service_landing(svc, signer, holder, job);
        }
        let st = self.rpc.call(
            "getSignatureStatuses",
            json!([[sent.signature], {"searchTransactionHistory": true}]),
        )?;
        let s = &st["value"][0];
        if s.is_null() {
            let valid = self.rpc.call(
                "isBlockhashValid",
                json!([sent.blockhash, {"commitment": "processed"}]),
            )?;
            return Ok(match valid["value"].as_bool() {
                Some(false) => Landing::Dropped,
                _ => Landing::Pending,
            });
        }
        if !s["err"].is_null() {
            return Ok(Landing::Failed(s["err"].to_string()));
        }
        if s["confirmationStatus"].as_str() == Some("finalized") {
            if let Some(t) = get_transaction(self.rpc.as_ref(), &sent.signature)? {
                return Ok(Landing::Landed {
                    signature: sent.signature.clone(),
                    slot: t.slot,
                    block_time: t.block_time,
                });
            }
        }
        Ok(Landing::Pending)
    }

    /// Asks about a sent transaction until it is no longer pending, or the
    /// wait (`KSG_ANCHOR_WAIT_S`, 120 s by default) runs out —
    /// [`Landing::Pending`] then.
    ///
    /// # Errors
    ///
    /// The node did not answer.
    pub fn wait(&self, sent: &Sent) -> Result<Landing, String> {
        let started = Instant::now();
        loop {
            let l = self.landing(sent)?;
            if l != Landing::Pending || started.elapsed() > self.wait {
                return Ok(l);
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    /// Refuses a file whose top seal or last status record the network shows
    /// a successor of.
    ///
    /// `head` is the hash of the seal on the journal, or the container's
    /// identifier before the journal is opened; `status_head` the hash of the
    /// last status record; `since` the last signature this file knows.
    ///
    /// # Errors
    ///
    /// The file is an old copy, or the node did not answer.
    pub fn check_rollback(
        &self,
        scan: &[SealScanKey],
        head: &Hash,
        status_head: &Hash,
        since: Option<&str>,
    ) -> Result<(), String> {
        // The next seal after `head` is blinded under the key of its own
        // period: any of the keys this container may use.
        let want: Vec<_> = scan.iter().map(|k| k.link(head)).collect();
        let want_status = status_link(status_head);
        for sig in signatures_for(self.rpc.as_ref(), &self.address, since, 100)? {
            let Some(tx) = get_transaction(self.rpc.as_ref(), &sig)? else {
                continue;
            };
            if tx
                .memos
                .iter()
                .filter_map(|m| SealMemo::parse(m))
                .any(|m| want.contains(&m.link))
            {
                return Err(format!(
                    "rolled back: the network holds a seal put on after this file's last seal \
                     (transaction {sig}); this file is an older copy of the container and writing \
                     from it would fork the journal"
                ));
            }
            if tx
                .memos
                .iter()
                .filter_map(|m| StatusMemo::parse(m))
                .any(|m| m.link == want_status)
            {
                return Err(format!(
                    "rolled back: the network holds a status record written after this file's \
                     last one (transaction {sig}); this file is an older copy of the container and \
                     writing from it would fork the status history"
                ));
            }
        }
        Ok(())
    }
}

/// Where a job of the service stands. The service resends a lost memo
/// itself and never twice while one may land (`ksg_service_v2::anchoring`),
/// so the reader sees only "pending" or "landed"; a job the service does not
/// know is "failed", and the reader asks for a new one.
#[cfg(feature = "rpc")]
fn service_landing(
    svc: &crate::service::Service,
    signer: &ksg_core_v2::crypto::sign::Ed25519Signer,
    holder: &str,
    job: &str,
) -> Result<Landing, String> {
    let got = match svc.get_signed(&format!("/v1/anchor/{job}"), signer, holder) {
        Ok(v) => v,
        Err(e) if e.contains("answered 404") => {
            return Ok(Landing::Failed(format!(
                "the service does not know job {job}"
            )))
        }
        Err(e) => return Err(e),
    };
    if got.get("state").and_then(serde_json::Value::as_str) != Some("anchored") {
        return Ok(Landing::Pending);
    }
    let att: Attestation = serde_json::from_value(
        got.get("attestation")
            .cloned()
            .unwrap_or(serde_json::Value::Null),
    )
    .map_err(|e| format!("the service's attestation: {e}"))?;
    let proof = AnchorProof::from_bytes(&att.proof).map_err(|e| e.to_string())?;
    Ok(Landing::Landed {
        signature: proof.signature,
        slot: proof.slot,
        block_time: i64::try_from(att.anchored_at.unix_ms() / 1000).ok(),
    })
}
