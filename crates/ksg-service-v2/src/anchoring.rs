//! The anchoring queue. `[decision]` 19.09, CT-04: we anchor as a mechanism —
//! a scheduler, a queue, uptime — and the holder pays the gas.
//!
//! # What changed from v1, and why
//!
//! Core v1 anchored the **checkpoints of a log**, one per aggregation period.
//! Core v2 has no log (spec v2 §17): every seal of a Pro journal and every
//! status record is anchored by its own memo. So there is nothing to
//! aggregate and nothing to schedule by period; what is left of the service
//! is the part a failing network tests — **a queue that loses nothing and
//! never sends one memo twice**.
//!
//! # Never twice
//!
//! A memo sent, whose transaction did not finalize in time, is the dangerous
//! case. Sending it again blindly puts two memos with one `link` on the
//! chain if the first lands after all — and two memos after one head read
//! as a **fork** (`ksg_verify_v2::solana::find_bound_forks`,
//! `find_status_forks`). So a sent job keeps its transaction's signature, and
//! before anything is sent again the network is asked about that signature:
//!
//! | The network says | The queue does |
//! |---|---|
//! | landed, finalized | builds the attestation; the job is done |
//! | still pending | waits and asks again |
//! | dropped — the blockhash expired with the transaction unseen | sends again: the first can no longer land |
//! | landed with an error | sends again: a failed transaction carries no memo |
//!
//! # What on a failure
//!
//! The job stays, retried with a doubling delay up to one hour; a refusal
//! (no funds for the fee) is retried too, and reported every time — an
//! anchor is not dropped because the payer was empty for an hour. The host
//! writes [`Outbox::to_json`] to disk and reads it back after a restart.

use serde::{Deserialize, Serialize};

use ksg_container_v2::view::AnchorRef;
use ksg_core_v2::anchor::Attestation;
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::doc::Uri;
use ksg_verify_v2::solana::{
    status_commit, AnchorProof, SealMemo, StatusMemo, SEAL_KIND, STATUS_KIND,
};

/// The first retry delay, in milliseconds.
pub const FIRST_RETRY_MS: u64 = 1_000;
/// The longest retry delay, in milliseconds: one hour.
pub const MAX_RETRY_MS: u64 = 60 * 60 * 1_000;
/// The most jobs the queue holds. A container waits on at most two memos
/// per press; this bounds a host that stopped draining, not a busy one.
pub const MAX_JOBS: usize = 100_000;

/// The delay before attempt `attempts + 1`: 1 s, 2 s, 4 s … one hour at most.
#[must_use]
pub fn retry_delay_ms(attempts: u32) -> u64 {
    FIRST_RETRY_MS
        .checked_shl(attempts)
        .filter(|d| *d >= FIRST_RETRY_MS)
        .unwrap_or(MAX_RETRY_MS)
        .min(MAX_RETRY_MS)
}

/// What a memo anchors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    /// A seal of the journal, blind memo `ksg:bs:v1`.
    Seal,
    /// A status record, open memo `ksg:st:v1`.
    Status,
    /// An agent's ID publication, open memo `ksg:id:v1` (KS-8 C-10).
    AgentId,
}

/// Where a sent transaction stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Landing {
    /// Finalized, with its slot and the block time estimate (Unix seconds).
    Landed {
        /// The slot.
        slot: u64,
        /// The block time estimate, when the node gives one.
        block_time: Option<i64>,
    },
    /// Not finalized yet, and may still be.
    Pending,
    /// Can no longer land: its blockhash expired with the transaction unseen.
    Dropped,
    /// Landed with an error: no memo was written.
    Failed(String),
}

/// Why a call to the network failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SendError {
    /// The network did not answer or answered "try again".
    #[error("transient: {0}")]
    Transient(String),
    /// The network refused the transaction — for instance, no funds for the
    /// fee. Retried all the same.
    #[error("refused: {0}")]
    Refused(String),
}

/// The network, as the queue uses it. The one adapter a deployment writes.
pub trait ChainSender {
    /// The cluster the sender writes to: `mainnet-beta`, `devnet`, `testnet`.
    fn cluster(&self) -> &str;

    /// Sends `memo` in one transaction, paid by the holder's payer, **without
    /// waiting**: the transaction's signature and the blockhash it was built
    /// on.
    ///
    /// # Errors
    ///
    /// [`SendError`]: the transaction did not go out.
    fn send_memo(&mut self, memo: &str) -> Result<Sent, SendError>;

    /// Where the transaction `sent` stands. Its blockhash is what tells a
    /// slow transaction from one that can never land.
    ///
    /// # Errors
    ///
    /// [`SendError::Transient`]: the network did not answer.
    fn landing(&mut self, sent: &Sent) -> Result<Landing, SendError>;

    /// The address the memos are paid from, when there is one to name: what
    /// a holder's reader checks its container's history against.
    fn payer(&self) -> Option<String> {
        None
    }
}

/// A transaction sent and not yet known to have landed. Kept with its job,
/// on disk: after a restart the queue still knows what it is waiting for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sent {
    /// The transaction signature, base58.
    pub signature: String,
    /// The blockhash it was built on, base58.
    pub blockhash: String,
}

/// One memo waiting to be anchored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Job {
    /// The queue's number for it.
    pub id: u64,
    /// Whose memo.
    pub container: Hash,
    /// What it anchors.
    pub kind: Kind,
    /// The seal's or the record's hash — the attestation's subject.
    pub subject: Hash,
    /// The memo line.
    pub memo: String,
    /// Sends made so far.
    pub attempts: u32,
    /// Not before this moment, in the host's milliseconds.
    pub next_try_ms: u64,
    /// The transaction last sent and not yet known dead.
    pub sent: Option<Sent>,
    /// The last failure, for the operator.
    pub last_error: Option<String>,
}

/// A memo that landed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anchored {
    /// The job's number.
    pub id: u64,
    /// Whose memo.
    pub container: Hash,
    /// What it anchored.
    pub kind: Kind,
    /// The network's attestation, for the container to take in place of its
    /// placeholder (`Container::reanchor_last`).
    pub attestation: Attestation,
    /// The anchor as an observer names it — for the desk's linkage.
    pub anchor: AnchorRef,
}

/// Why the queue refused a job or failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QueueError {
    /// The memo is not of its kind, or a status memo is of another record.
    #[error("the memo is not a {0} memo of this subject")]
    Memo(&'static str),
    /// The queue is full.
    #[error("the anchoring queue is full")]
    Full,
    /// An attestation could not be built.
    #[error("the attestation could not be built: {0}")]
    Attestation(String),
    /// The queue does not serialize or does not parse.
    #[error("the queue could not be written or read")]
    State,
}

/// What one tick did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Tick {
    /// Memos that landed in this tick.
    pub anchored: Vec<Anchored>,
    /// Memos sent in this tick.
    pub sent: usize,
    /// Calls that failed in this tick; their jobs stay.
    pub failed: usize,
}

/// The queue. Serializable so that it survives a restart.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Outbox {
    next_id: u64,
    jobs: Vec<Job>,
}

impl Outbox {
    /// Queues a memo.
    ///
    /// The memo is checked against its kind; a status memo's `commit` against
    /// the record it names, since that one is open. A seal memo is blind and
    /// can only be checked for its form: the scan key is the holder's.
    ///
    /// # Errors
    ///
    /// [`QueueError::Memo`] for a memo of another kind or record;
    /// [`QueueError::Full`] past [`MAX_JOBS`].
    pub fn push(
        &mut self,
        container: Hash,
        kind: Kind,
        subject: Hash,
        memo: String,
        now_ms: u64,
    ) -> Result<u64, QueueError> {
        match kind {
            Kind::Seal => {
                SealMemo::parse(&memo).ok_or(QueueError::Memo("seal"))?;
            }
            Kind::Status => {
                let m = StatusMemo::parse(&memo).ok_or(QueueError::Memo("status"))?;
                if m.commit != status_commit(&subject) {
                    return Err(QueueError::Memo("status"));
                }
            }
            Kind::AgentId => {
                let m = ksg_verify_v2::solana::AgentIdMemo::parse(&memo)
                    .ok_or(QueueError::Memo("agent-id"))?;
                if m.subject != subject {
                    return Err(QueueError::Memo("agent-id"));
                }
            }
        }
        if self.jobs.len() >= MAX_JOBS {
            return Err(QueueError::Full);
        }
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        self.jobs.push(Job {
            id,
            container,
            kind,
            subject,
            memo,
            attempts: 0,
            next_try_ms: now_ms,
            sent: None,
            last_error: None,
        });
        Ok(id)
    }

    /// What is waiting.
    #[must_use]
    pub fn jobs(&self) -> &[Job] {
        &self.jobs
    }

    /// One pass over the jobs due at `now_ms`: ask about what was sent, send
    /// what was not, and hand back what landed.
    ///
    /// A failing network is not an error: it is counted in [`Tick::failed`]
    /// and retried.
    pub fn tick(&mut self, sender: &mut dyn ChainSender, now_ms: u64) -> Tick {
        let mut tick = Tick::default();
        let mut waiting = Vec::with_capacity(self.jobs.len());
        for mut job in std::mem::take(&mut self.jobs) {
            if job.next_try_ms > now_ms {
                waiting.push(job);
                continue;
            }
            match step(&mut job, sender, now_ms, &mut tick) {
                Some(done) => tick.anchored.push(done),
                None => waiting.push(job),
            }
        }
        self.jobs = waiting;
        tick
    }

    /// The queue as JSON, for the host to write to disk.
    ///
    /// # Errors
    ///
    /// [`QueueError::State`] if it does not serialize.
    pub fn to_json(&self) -> Result<String, QueueError> {
        serde_json::to_string(self).map_err(|_| QueueError::State)
    }

    /// The queue read back from disk.
    ///
    /// # Errors
    ///
    /// [`QueueError::State`] if the text is not a queue.
    pub fn from_json(s: &str) -> Result<Self, QueueError> {
        serde_json::from_str(s).map_err(|_| QueueError::State)
    }
}

fn backoff(job: &mut Job, now_ms: u64, why: String) {
    job.next_try_ms = now_ms.saturating_add(retry_delay_ms(job.attempts));
    job.last_error = Some(why);
}

/// One job's turn: `Some` when it landed.
fn step(
    job: &mut Job,
    sender: &mut dyn ChainSender,
    now_ms: u64,
    tick: &mut Tick,
) -> Option<Anchored> {
    if let Some(sent) = job.sent.clone() {
        let sig = &sent.signature;
        match sender.landing(&sent) {
            Ok(Landing::Landed {
                slot,
                block_time: Some(t),
            }) => match attestation(job, sender.cluster(), sig, slot, t) {
                Ok(done) => return Some(done),
                Err(e) => {
                    tick.failed += 1;
                    backoff(job, now_ms, e.to_string());
                    return None;
                }
            },
            // Landed without a block time yet, or not finalized: ask again.
            Ok(Landing::Landed { .. } | Landing::Pending) => {
                backoff(job, now_ms, format!("{sig}: not finalized yet"));
                return None;
            }
            Ok(Landing::Dropped) => {
                job.sent = None;
                job.last_error = Some(format!("{sig}: dropped by the network"));
            }
            Ok(Landing::Failed(e)) => {
                job.sent = None;
                job.last_error = Some(format!("{sig}: failed: {e}"));
            }
            Err(e) => {
                tick.failed += 1;
                backoff(job, now_ms, e.to_string());
                return None;
            }
        }
    }
    // Nothing in flight: send.
    match sender.send_memo(&job.memo) {
        Ok(sig) => {
            job.sent = Some(sig);
            job.attempts = job.attempts.saturating_add(1);
            tick.sent += 1;
            // Asked about at the next tick: finality takes seconds.
            job.next_try_ms = now_ms.saturating_add(FIRST_RETRY_MS);
        }
        Err(e) => {
            tick.failed += 1;
            backoff(job, now_ms, e.to_string());
            job.attempts = job.attempts.saturating_add(1);
        }
    }
    None
}

fn attestation(
    job: &Job,
    cluster: &str,
    sig: &str,
    slot: u64,
    block_time: i64,
) -> Result<Anchored, QueueError> {
    let proof = AnchorProof {
        signature: sig.to_owned(),
        slot,
        cluster: cluster.to_owned(),
    };
    let kind = match job.kind {
        Kind::Seal => SEAL_KIND,
        Kind::Status => STATUS_KIND,
        Kind::AgentId => ksg_verify_v2::solana::AGENT_ID_KIND,
    };
    let ms = u64::try_from(block_time)
        .ok()
        .and_then(|s| s.checked_mul(1000))
        .ok_or_else(|| QueueError::Attestation("a block time before 1970".into()))?;
    Ok(Anchored {
        id: job.id,
        container: job.container,
        kind: job.kind,
        attestation: Attestation {
            kind: Uri::parse(kind).map_err(|e| QueueError::Attestation(e.to_string()))?,
            subject: job.subject,
            proof: proof
                .to_bytes()
                .map_err(|e| QueueError::Attestation(e.to_string()))?,
            anchored_at: ksg_core_v2::doc::Timestamp::from_unix_ms(ms)
                .map_err(|e| QueueError::Attestation(e.to_string()))?,
        },
        anchor: AnchorRef {
            cluster: cluster.to_owned(),
            signature: sig.to_owned(),
        },
    })
}
