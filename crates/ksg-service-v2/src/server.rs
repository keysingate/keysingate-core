//! The service process: the desk, the registry and the anchoring queues
//! behind one HTTP port. `[decision]` 19.09 (CT-04: we anchor, uptime is
//! what is sold), 13.09 (Ts-5: the door for a named look).
//!
//! # The interface
//!
//! | Method and path | Who | Body → answer |
//! |---|---|---|
//! | `GET /v1/health` | anyone | → `{ok, audience, cluster, holders, watchers, jobs}` |
//! | `POST /v1/challenge` | anyone | → `{challenge}` — for one request, ten minutes |
//! | `POST /v1/watchers` | an owner-watcher | `{channel, statuses}` → `{owner, container, status}` (path A's registration) |
//! | `POST /v1/look` | an owner-watcher | `{request}` → `{charge, container}`; the notice goes to the container's mailbox |
//! | `GET /v1/holder` | a holder, signed | → `{holder, cluster, payer}` — the address its memos are paid from, for its rollback check |
//! | `POST /v1/anchor` | a holder, signed | `{container, kind, subject, memo}` → `{job}` |
//! | `GET /v1/anchor/{job}` | the holder, signed | → `{state, attempts, last_error, attestation, anchor}` |
//! | `POST /v1/notices` | the holder, signed | `{container}` → `{notices, dropped}` |
//! | `POST /v1/bare/orchestrator/challenge` | anyone | `{did_web}` → `{id, code}` — for one proof, ten minutes |
//! | `POST /v1/bare/orchestrator/proof` | the domain's key | `{id, signature}` → `{state, number}` (the code signed by the `did.json` key) |
//!
//! Errors answer `{error}` with a status: 400 malformed, 401 unsigned or a
//! stale or replayed signature, 403 refused by path A, 404 unknown, 409 a
//! spent challenge, 413 too large, 429 busy, 500 the service's own fault.
//!
//! # The holder's signature
//!
//! The anchoring queue spends the holder's payer, and the mailbox holds the
//! holder's notices: both answer only a request the holder signed. Headers:
//!
//! ```text
//! x-ksg-holder:    <holder id from the configuration>
//! x-ksg-time:      <Unix milliseconds>
//! x-ksg-signature: <Ed25519 signature, base64url, over the line below>
//! ksg:service:v1 \n METHOD \n PATH \n TIME \n SHA-256(body) as a multihash
//! ```
//!
//! A signature older or newer than [`AUTH_WINDOW_MS`] is refused, and so is
//! one seen before: a captured request is good for nothing.
//!
//! A holder takes the notices only of a container it has anchored through
//! this service: nobody else can empty its mailbox (a suppressed notice is
//! the one thing the notice ring cannot defend against).
//!
//! # State
//!
//! Every change is written before the answer goes out, by a whole-file
//! replace (`write`, `fsync`, `rename`): a killed process loses no anchor, no
//! charge and no notice it confirmed. The queue's ticker runs once a second.
//!
//! # Deployment
//!
//! The process speaks plain HTTP and limits only what it must to stay up —
//! the body size, the outstanding challenges, the remembered signatures. TLS
//! and the rate of requests per client belong to the reverse proxy in front
//! of it; the process is meant to listen on a local address behind one.
//!
//! # What is logged
//!
//! One line per request to standard error: method, path, status, duration.
//! No bodies, no owner IDs, no keys — the policy of technical logs is still
//! the lawyer's (`Resheniya_13.09` §7 p. 2), so the process writes the least
//! an operator needs.

use std::collections::{BTreeMap, HashMap};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use ed25519_dalek::{Signature as EdSignature, VerifyingKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::json;
use zeroize::Zeroizing;

use ksg_container_v2::view::{AnchorRef, DisclosureRequest, ViewNotice};
use ksg_core_v2::anchor::Attestation;
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{Alg, KeySet, Profile, PublicKey};
use ksg_core_v2::doc::{Timestamp, Uri};
use ksg_core_v2::section::StatusExport;
use ksg_verify_v2::channel::ChannelProof;
use ksg_verify_v2::solana::{Rpc, SolanaReader};

use crate::anchoring::{ChainSender, Kind, Outbox};
use crate::auth::{auth_message, AUTH_WINDOW_MS};
use crate::desk::{Desk, DeskError};
use crate::ladder::{Stream, KEY_RETENTION_DAYS};
use crate::registry::{ChainRegistry, DEFAULT_MAX_AGE_MS};

/// The largest body taken: 2 MiB — a status section of 1 024 records fits.
pub const MAX_BODY: usize = 2 * 1024 * 1024;
/// A single read or write on a client socket waits at most this long; a
/// silent client is dropped instead of holding a request thread.
pub const SOCKET_TIMEOUT_S: u64 = 5;
/// The whole body must arrive within this time, however it trickles in.
pub const BODY_DEADLINE_S: u64 = 10;

/// How long a landed job's answer is kept for its holder: thirty days.
pub const DONE_KEEP_MS: u64 = 30 * 24 * 60 * 60 * 1000;
/// The most landed answers kept per holder.
pub const MAX_DONE: usize = 100_000;
/// The most request signatures remembered against replay.
pub const MAX_SEEN: usize = 200_000;

/// One holder whose memos the service sends.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HolderCfg {
    /// Its name in requests: lowercase letters, digits, `-`.
    pub id: String,
    /// The Ed25519 key its requests are signed with.
    pub key: PublicKey,
    /// Its payer's key file, Solana CLI format: the holder pays the gas.
    pub payer: PathBuf,
}

/// The service's configuration, read from a JSON file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Where to listen, `HOST:PORT`; port 0 picks one.
    pub listen: String,
    /// The service's name in requests (`DisclosureRequest.audience`).
    pub audience: Uri,
    /// The directory of the state files.
    pub state: PathBuf,
    /// `devnet`, `testnet` or `mainnet-beta`.
    pub cluster: String,
    /// The node's JSON-RPC address.
    pub rpc: String,
    /// A JSON list of the keys the service holds as the issuer's.
    pub issuer_keys: PathBuf,
    /// How long a watcher's checked standing holds, seconds; a day by default.
    #[serde(default)]
    pub max_standing_age_s: Option<u64>,
    /// Owner-watchers in the legal checker's stream (CT-14), by key
    /// (base64url): no ladder, they pay the chain's fees themselves.
    #[serde(default)]
    pub legal_checkers: Vec<String>,
    /// The holders.
    pub holders: Vec<HolderCfg>,
    /// Request threads; four by default.
    #[serde(default)]
    pub workers: Option<usize>,
}

/// A landed job, as its holder reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Done {
    /// The attestation, for the container to take.
    pub attestation: Attestation,
    /// The transaction.
    pub anchor: AnchorRef,
    /// When it landed, ms.
    pub landed_ms: u64,
}

/// What is kept on disk for one holder.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HolderState {
    outbox: Outbox,
    done: BTreeMap<u64, Done>,
    /// The containers this holder anchored through us: whose mailboxes it may empty.
    containers: Vec<Hash>,
}

struct Holder {
    key: VerifyingKey,
    state: Mutex<HolderState>,
    sender: Mutex<Box<dyn ChainSender + Send>>,
}

/// The shared service state behind one HTTP port.
///
/// `pub` so integration tests drive the `bare` routes in-process
/// ([`Shared::bare_only`], [`Shared::bare_route`]): no network port, no
/// signer, no database. Contact values (email / `did:web`) are validated and
/// never logged.
pub struct Shared {
    cfg: Config,
    desk: Mutex<Desk>,
    registry: Mutex<ChainRegistry>,
    holders: BTreeMap<String, Holder>,
    seen: Mutex<BTreeMap<String, u64>>,
    rpc: Box<dyn Rpc + Send + Sync>,
    legal: Vec<String>,
    bare: Mutex<BareLedger>,
    /// Pending orchestrator challenges (этап 9: in-memory, ten minutes each).
    orch: Mutex<OrchLedger>,
    /// Request threads now inside an outgoing call (`did.json`, RPC).
    outbound: AtomicUsize,
    /// The most request threads allowed in outgoing calls at once: the rest
    /// stay free for anchoring and status, whatever a remote host does.
    outbound_max: usize,
}

/// One request thread's place in an outgoing call; freed on drop.
struct OutboundSlot<'a>(&'a AtomicUsize);

impl Drop for OutboundSlot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// The share of request threads that may wait on remote hosts: half,
/// at least one.
fn outbound_max(workers: usize) -> usize {
    (workers / 2).max(1)
}

/// Reads a body of at most `MAX_BODY` bytes that must end by `deadline`.
/// Each read is itself bounded by the socket timeout, so a client sending
/// nothing, or a byte at a time, cannot keep the thread past the deadline.
fn read_body(r: &mut dyn std::io::Read, deadline: Instant) -> Result<Vec<u8>, Reply> {
    let mut body = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        if Instant::now() > deadline {
            return Err(err(408, "the body came too slowly"));
        }
        match r.read(&mut buf) {
            Ok(0) => return Ok(body),
            Ok(n) => {
                let Some(got) = buf.get(..n) else {
                    return Err(err(400, "the body did not read"));
                };
                if body.len() + got.len() > MAX_BODY {
                    return Err(err(413, "the body is too large"));
                }
                body.extend_from_slice(got);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Err(err(408, "the body came too slowly"));
            }
            Err(_) => return Err(err(400, "the body did not read")),
        }
    }
}

/// A running service.
pub struct Running {
    /// The address it listens on.
    pub addr: std::net::SocketAddr,
    http: Arc<tiny_http::Server>,
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

impl Running {
    /// Stops taking requests, lets the ticker finish its pass, and returns
    /// once every thread is done. State is on disk already.
    pub fn stop(self) {
        self.stop.store(true, Ordering::SeqCst);
        self.http.unblock();
        for _ in 1..self.threads.len() {
            self.http.unblock();
        }
        for t in self.threads {
            let _ = t.join();
        }
    }

    /// Blocks until the threads end — for the process's main.
    pub fn wait(self) {
        for t in self.threads {
            let _ = t.join();
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn period_of(ms: u64) -> String {
    Timestamp::from_unix_ms(ms).map_or_else(
        |_| "0000-00".into(),
        |t| t.as_str().get(..7).unwrap_or("0000-00").to_owned(),
    )
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A thread that panicked mid-change leaves the state as the last write
    // put it on disk; going on with what is in memory is no worse.
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Writes `bytes` to `path` whole or not at all.
///
/// # Errors
///
/// The file system refused.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::File::create(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
    f.write_all(bytes)
        .and_then(|()| f.sync_all())
        .map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))?;
    if let Some(dir) = path.parent() {
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Option<T>, String> {
    match std::fs::read(path) {
        Ok(b) => serde_json::from_slice(&b)
            .map(Some)
            .map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

impl Shared {
    fn desk_path(&self) -> PathBuf {
        self.cfg.state.join("desk.json")
    }
    fn registry_path(&self) -> PathBuf {
        self.cfg.state.join("registry.json")
    }
    fn holder_path(&self, id: &str) -> PathBuf {
        self.cfg.state.join(format!("holder-{id}.json"))
    }
    fn save_desk(&self, d: &Desk) -> Result<(), String> {
        write_atomic(
            &self.desk_path(),
            d.to_json().map_err(|e| e.to_string())?.as_bytes(),
        )
    }
    fn save_registry(&self, r: &ChainRegistry) -> Result<(), String> {
        write_atomic(
            &self.registry_path(),
            &serde_json::to_vec(r).map_err(|e| e.to_string())?,
        )
    }
    fn save_holder(&self, id: &str, s: &HolderState) -> Result<(), String> {
        write_atomic(
            &self.holder_path(id),
            &serde_json::to_vec(s).map_err(|e| e.to_string())?,
        )
    }
}

/// An answer: a status and a JSON body.
///
/// `pub` so integration tests drive the `bare` routes directly, in-process,
/// without opening a network port.
#[derive(Debug, Clone, PartialEq)]
pub struct Reply(pub u16, pub serde_json::Value);
impl Reply {
    /// The HTTP status code.
    #[must_use]
    pub fn status(&self) -> u16 {
        self.0
    }
    /// The JSON body.
    #[must_use]
    pub fn body(&self) -> &serde_json::Value {
        &self.1
    }
}

fn err(code: u16, msg: impl Into<String>) -> Reply {
    Reply(code, json!({"error": msg.into()}))
}

/// One pending `bare` issuance request (этапы 1+6, in-memory).
///
/// `expect` is the `holder_hmac` of the applicant's contact: the contact
/// value itself is never stored, even in memory. `None` when the HMAC key
/// was unavailable at `start` — the `mail` step then cannot match and
/// refuses with 503.
struct BareEntry {
    code: String,
    expires_ms: u64,
    expect: Option<[u8; 32]>,
    /// Keyed hash of the contact (per-process random key): counts the
    /// pending requests of one contact without keeping the contact itself.
    contact_key: u64,
}

/// The most pending `bare` requests the service keeps at once. Past it a new
/// request is refused with 429 — nobody else's pending request is evicted.
pub const BARE_MAX_PENDING: usize = 10_000;
/// The most pending `bare` requests one contact may hold at once.
pub const BARE_MAX_PER_CONTACT: usize = 3;
/// The most pending orchestrator challenges the service keeps at once.
pub const ORCH_MAX_PENDING: usize = 10_000;
/// The most pending challenges one `did:web` may hold at once.
pub const ORCH_MAX_PER_DOMAIN: usize = 3;
/// The prefix of a ledger refusal that means "full, try later" (HTTP 429).
pub const LEDGER_BUSY: &str = "busy:";

/// How long a `bare` request stays pending: thirty minutes.
pub const BARE_TTL_MS: u64 = 30 * 60 * 1000;

/// How long an orchestrator challenge stays pending: ten minutes.
pub const ORCH_TTL_MS: u64 = 10 * 60 * 1000;

/// The `did.json` address of a bare `did:web:<host>` (no path segments).
pub const DID_JSON_WELL_KNOWN: &str = ".well-known/did.json";

/// Where the applicant sends the six-digit code for manual verification.
const BARE_SEND_TO: &str = "verify@keysingate.com";

/// In-memory ledger of pending `bare` requests (этап 1: no database).
///
/// `issued` stays zero until этап 2 wires a database; the store keeps only
/// pending requests, each for [`BARE_TTL_MS`].
#[derive(Default)]
pub struct BareLedger {
    entries: HashMap<String, BareEntry>,
    keyer: std::collections::hash_map::RandomState,
}
impl BareLedger {
    /// Creates an empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            keyer: std::collections::hash_map::RandomState::new(),
        }
    }

    /// Starts one issuance request: exactly one contact, `email` or `did_web`.
    ///
    /// Returns the request id and the six-digit code, or why the contact is
    /// refused. The contact value itself is never logged nor echoed back.
    /// `hmac_key` is the service HMAC secret; `None` keeps the request
    /// pending but unmatchable (the `mail` step answers 503 until the key
    /// is configured).
    ///
    /// # Errors
    ///
    /// The contact is missing, doubled, malformed — or there is no randomness.
    pub fn start(
        &mut self,
        email: Option<&str>,
        did_web: Option<&str>,
        now: u64,
        hmac_key: Option<&[u8]>,
    ) -> Result<(String, String), String> {
        let ok = match (email, did_web) {
            (Some(e), None) => valid_email(e),
            (None, Some(d)) => valid_did_web(d),
            _ => false,
        };
        if !ok {
            return Err("email or did_web: malformed contact".to_owned());
        }
        let contact: &str = match (email, did_web) {
            (Some(e), None) => e,
            (None, Some(d)) => d,
            _ => return Err("email or did_web: malformed contact".to_owned()),
        };
        // Bounded before any work: the sweep below is O(n) with n at most
        // BARE_MAX_PENDING, and a full ledger refuses instead of evicting.
        self.entries.retain(|_, e| e.expires_ms > now);
        let contact_key = {
            use std::hash::BuildHasher;
            self.keyer.hash_one(contact.to_ascii_lowercase())
        };
        if self.entries.len() >= BARE_MAX_PENDING {
            return Err(format!(
                "{LEDGER_BUSY} too many pending requests; try again later"
            ));
        }
        if self
            .entries
            .values()
            .filter(|e| e.contact_key == contact_key)
            .count()
            >= BARE_MAX_PER_CONTACT
        {
            return Err(format!(
                "{LEDGER_BUSY} this contact already has pending requests; try again later"
            ));
        }
        let mut id_raw = [0u8; 16];
        let mut code_raw = [0u8; 4];
        OsRng
            .try_fill_bytes(&mut id_raw)
            .and_then(|()| OsRng.try_fill_bytes(&mut code_raw))
            .map_err(|_| "no randomness".to_owned())?;
        let id = hex::encode(id_raw);
        let digits = u32::from_le_bytes(code_raw) % 1_000_000;
        let mut code = [b'0'; 6];
        let mut rest = digits;
        let mut i = code.len();
        while i > 0 {
            i -= 1;
            if let Some(slot) = code.get_mut(i) {
                *slot = b'0' + (rest % 10) as u8;
            }
            rest /= 10;
        }
        let code = String::from_utf8_lossy(&code).into_owned();
        let expect = hmac_key.map(|k| crate::bare_db::holder_hmac(k, contact));
        self.entries.insert(
            id.clone(),
            BareEntry {
                expires_ms: now.saturating_add(BARE_TTL_MS),
                code: code.clone(),
                expect,
                contact_key,
            },
        );
        Ok((id, code))
    }

    /// The state of a request id: `"pending"` while it is known and fresh,
    /// `"issued"` once the `mail` step wrote the row.
    pub fn state(&mut self, id: &str, now: u64) -> Option<&'static str> {
        self.entries.retain(|_, e| e.expires_ms > now);
        self.entries.get(id).map(|_| "pending")
    }

    /// Finds a pending request whose expected holder hash and six-digit code
    /// both match, without consuming it: use [`BareLedger::take_by_id`] to
    /// consume only after out-of-band checks (DKIM) succeed, so a forged
    /// message cannot burn someone else's request.
    ///
    /// `holder` is compared in constant time. An expired or unknown id, or a
    /// wrong code or holder, returns `None` without telling which part failed.
    pub fn find_match(&mut self, holder: &[u8; 32], code: &str, now: u64) -> Option<String> {
        self.entries.retain(|_, e| e.expires_ms > now);
        self.entries
            .iter()
            .find(|(_, e)| {
                let Some(expect) = e.expect else { return false };
                constant_eq(&expect, holder) && e.code == code
            })
            .map(|(id, _)| id.clone())
    }

    /// Consumes one pending request by id (one code works once). Returns the
    /// id when it was still pending.
    pub fn take_by_id(&mut self, id: &str) -> Option<String> {
        self.entries.remove(id).map(|_| id.to_owned())
    }

    /// Takes a pending request whose expected holder hash and six-digit code
    /// both match: the request is consumed (one code works once).
    ///
    /// `holder` is compared in constant time. An expired or unknown id, or a
    /// wrong code or holder, returns `None` without telling which part failed.
    pub fn take_match(&mut self, holder: &[u8; 32], code: &str, now: u64) -> Option<String> {
        let id = self.find_match(holder, code, now)?;
        self.take_by_id(&id)
    }

    /// How many certificates were issued (этап 1: always zero, no database).
    #[must_use]
    pub fn issued(&self) -> u64 {
        0
    }
}

/// One pending orchestrator challenge (этап 9, in-memory).
///
/// `did_web` is the domain's full `did:web:...` identifier; `code` is the
/// random challenge to sign. The record itself carries no key material.
struct OrchEntry {
    did_web: String,
    code: String,
    expires_ms: u64,
}

/// In-memory ledger of pending orchestrator challenges (этап 9).
///
/// The store keeps only the challenge each domain must answer, each for
/// [`ORCH_TTL_MS`]: one challenge works once.
#[derive(Default)]
pub struct OrchLedger {
    entries: HashMap<String, OrchEntry>,
}

impl OrchLedger {
    /// Creates an empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Starts one challenge for a `did:web` domain: returns the id and the
    /// random code the domain's `did.json` key must sign.
    ///
    /// # Errors
    ///
    /// The contact is not a well-formed `did:web`, or there is no randomness.
    pub fn start(&mut self, did_web: &str, now: u64) -> Result<(String, String), String> {
        if !valid_did_web(did_web) {
            return Err("did_web: malformed contact".to_owned());
        }
        self.entries.retain(|_, e| e.expires_ms > now);
        if self.entries.len() >= ORCH_MAX_PENDING {
            return Err(format!(
                "{LEDGER_BUSY} too many pending challenges; try again later"
            ));
        }
        if self
            .entries
            .values()
            .filter(|e| e.did_web.eq_ignore_ascii_case(did_web))
            .count()
            >= ORCH_MAX_PER_DOMAIN
        {
            return Err(format!(
                "{LEDGER_BUSY} this domain already has pending challenges; try again later"
            ));
        }
        let mut id_raw = [0u8; 16];
        let mut code_raw = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut id_raw)
            .and_then(|()| OsRng.try_fill_bytes(&mut code_raw))
            .map_err(|_| "no randomness".to_owned())?;
        let id = hex::encode(id_raw);
        let code = hex::encode(code_raw);
        self.entries.insert(
            id.clone(),
            OrchEntry {
                did_web: did_web.to_owned(),
                code: code.clone(),
                expires_ms: now.saturating_add(ORCH_TTL_MS),
            },
        );
        Ok((id, code))
    }

    /// Takes a pending challenge by id: consumed whether or not the proof
    /// verifies (one challenge works once). Returns the `did:web` it was
    /// issued for and the code it carries.
    pub fn take(&mut self, id: &str, now: u64) -> Option<(String, String)> {
        self.entries.retain(|_, e| e.expires_ms > now);
        self.entries
            .remove(id)
            .map(|e| (e.did_web, e.code))
    }
}

/// Compares two hashes without early exit: the timing does not tell how
/// many bytes matched.
fn constant_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    let mut i = 0;
    while i < 32 {
        if let (Some(x), Some(y)) = (a.get(i), b.get(i)) {
            diff |= x ^ y;
        }
        i += 1;
    }
    diff == 0
}

/// A `did:web` contact reads `did:web:<host>[:extra...]`: letters, digits and
/// `-._~%!$&'()*+,;=` per non-empty segment.
fn valid_did_web(s: &str) -> bool {
    const PREFIX: &str = "did:web:";
    let Some(rest) = s.strip_prefix(PREFIX) else {
        return false;
    };
    if rest.is_empty() || rest.len() > 512 {
        return false;
    }
    rest.split(':').all(|seg| {
        !seg.is_empty()
            && seg.len() <= 128
            && seg.bytes().all(|b| {
                b.is_ascii_alphanumeric()
                    || matches!(
                        b,
                        b'-' | b'.'
                            | b'_'
                            | b'~'
                            | b'%'
                            | b'!'
                            | b'$'
                            | b'&'
                            | b'\''
                            | b'('
                            | b')'
                            | b'*'
                            | b'+'
                            | b','
                            | b';'
                            | b'='
                    )
            })
    })
}

/// A plain `local@domain` sanity check: one `@`, a dot in the domain.
fn valid_email(s: &str) -> bool {
    if s.is_empty() || s.len() > 254 || s.contains(' ') {
        return false;
    }
    let mut parts = s.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    !local.is_empty()
        && local.len() <= 64
        && !domain.is_empty()
        && domain.len() <= 253
        && domain.contains('.')
        && local
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b'@')
        && domain
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
}

fn desk_error(e: &DeskError) -> Reply {
    let code = match e {
        DeskError::Invalid(_) | DeskError::WindowTooWide => 400,
        DeskError::NotInChain => 403,
        DeskError::Replay => 409,
        DeskError::UnknownAnchor => 404,
        DeskError::Busy => 429,
        DeskError::State => 500,
    };
    err(code, e.to_string())
}

fn header<'a>(rq: &'a tiny_http::Request, name: &str) -> Option<&'a str> {
    rq.headers()
        .iter()
        .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name))
        .map(|h| h.value.as_str())
}

impl Shared {
    /// The holder a signed request comes from, or why not.
    fn authenticate(
        &self,
        rq: &tiny_http::Request,
        method: &str,
        path: &str,
        body: &[u8],
        now: u64,
    ) -> Result<&str, Reply> {
        let id = header(rq, "x-ksg-holder").ok_or_else(|| err(401, "unsigned request"))?;
        let (id, holder) = self
            .holders
            .get_key_value(id)
            .ok_or_else(|| err(401, "unknown holder"))?;
        let time: u64 = header(rq, "x-ksg-time")
            .and_then(|t| t.parse().ok())
            .ok_or_else(|| err(401, "x-ksg-time: not a number"))?;
        if now.abs_diff(time) > AUTH_WINDOW_MS {
            return Err(err(401, "the signature's time is too far from ours"));
        }
        let sig = header(rq, "x-ksg-signature").ok_or_else(|| err(401, "unsigned request"))?;
        let bytes: [u8; 64] = B64
            .decode(sig)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| err(401, "x-ksg-signature: not a signature"))?;
        holder
            .key
            .verify_strict(
                &auth_message(method, path, time, body),
                &EdSignature::from_bytes(&bytes),
            )
            .map_err(|_| err(401, "the signature does not verify"))?;
        let mut seen = lock(&self.seen);
        seen.retain(|_, dies| *dies > now);
        if seen.contains_key(sig) {
            return Err(err(401, "this signed request was seen before"));
        }
        if seen.len() >= MAX_SEEN {
            return Err(err(429, "too many signed requests; try again later"));
        }
        seen.insert(sig.to_owned(), now.saturating_add(2 * AUTH_WINDOW_MS));
        Ok(id)
    }

    /// A place for an outgoing call, or 503 when half the request threads
    /// already wait on remote hosts.
    fn outbound_slot(&self) -> Result<OutboundSlot<'_>, Reply> {
        if self.outbound.fetch_add(1, Ordering::SeqCst) >= self.outbound_max {
            self.outbound.fetch_sub(1, Ordering::SeqCst);
            return Err(err(503, "busy: too many outgoing calls; try again later"));
        }
        Ok(OutboundSlot(&self.outbound))
    }

    fn handle(&self, rq: &mut tiny_http::Request) -> Reply {
        let method = rq.method().as_str().to_owned();
        let path = rq.url().split('?').next().unwrap_or("").to_owned();
        let deadline = Instant::now() + Duration::from_secs(BODY_DEADLINE_S);
        let body = match read_body(rq.as_reader(), deadline) {
            Ok(b) => b,
            Err(r) => return r,
        };
        let now = now_ms();
        match (method.as_str(), path.as_str()) {
            ("GET", "/v1/health") => self.health(),
            ("POST", "/v1/challenge") => self.challenge(now),
            ("POST", "/v1/watchers") => self.register(&body, now),
            ("POST", "/v1/look") => self.look(&body, now),
            ("GET", "/v1/holder") => match self.authenticate(rq, &method, &path, &body, now) {
                Ok(h) => self.holder(h),
                Err(r) => r,
            },
            ("POST", "/v1/anchor") => match self.authenticate(rq, &method, &path, &body, now) {
                Ok(h) => self.anchor(h, &body, now),
                Err(r) => r,
            },
            ("GET", p) if p.starts_with("/v1/anchor/") => {
                match self.authenticate(rq, &method, &path, &body, now) {
                    Ok(h) => self.job(h, p.trim_start_matches("/v1/anchor/")),
                    Err(r) => r,
                }
            }
            ("POST", "/v1/notices") => match self.authenticate(rq, &method, &path, &body, now) {
                Ok(h) => self.notices(h, &body),
                Err(r) => r,
            },
            ("POST", "/v1/bare/start") => self.bare_start(&body, now),
            ("POST", "/v1/bare/mail") => {
                self.bare_mail(&body, now, header(rq, "authorization"))
            }
            ("POST", "/v1/bare/orchestrator/challenge") => self.orch_challenge(&body, now),
            ("POST", "/v1/bare/orchestrator/proof") => self.orch_proof(&body, now),
            ("GET", p) if p.starts_with("/v1/bare/status/") => {
                self.bare_status(p.trim_start_matches("/v1/bare/status/"), now)
            }
            ("GET", "/v1/bare/count") => self.bare_count(),
            _ => err(404, "no such endpoint"),
        }
    }

    fn health(&self) -> Reply {
        let jobs: usize = self
            .holders
            .values()
            .map(|h| lock(&h.state).outbox.jobs().len())
            .sum();
        Reply(
            200,
            json!({
                "ok": true,
                "audience": self.cfg.audience,
                "cluster": self.cfg.cluster,
                "holders": self.holders.len(),
                "watchers": lock(&self.registry).len(),
                "jobs": jobs,
            }),
        )
    }

    fn challenge(&self, now: u64) -> Reply {
        let mut random = [0u8; 32];
        if OsRng.try_fill_bytes(&mut random).is_err() {
            return err(500, "no randomness");
        }
        let mut desk = lock(&self.desk);
        match desk.challenge(random, now) {
            Ok(c) => match self.save_desk(&desk) {
                Ok(()) => Reply(200, json!({"challenge": c})),
                Err(e) => err(500, e),
            },
            Err(e) => desk_error(&e),
        }
    }

    fn register(&self, body: &[u8], now: u64) -> Reply {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Body {
            channel: ChannelProof,
            statuses: StatusExport,
        }
        let b: Body = match serde_json::from_slice(body) {
            Ok(b) => b,
            Err(e) => return err(400, format!("body: {e}")),
        };
        // The status records' anchors are read from the network the service
        // anchors on.
        let _slot = match self.outbound_slot() {
            Ok(s) => s,
            Err(r) => return r,
        };
        let reader = match SolanaReader::connect(self.rpc.as_ref(), &self.cfg.cluster) {
            Ok(r) => r,
            Err(e) => return err(503, format!("the network: {e}")),
        };
        let mut reg = lock(&self.registry);
        match reg.register(&b.channel, &b.statuses, Some(&reader), now) {
            Ok(s) => match self.save_registry(&reg) {
                Ok(()) => Reply(
                    200,
                    json!({"owner": s.owner.kid, "container": s.container.to_multihash(), "status": s.status.number()}),
                ),
                Err(e) => err(500, e),
            },
            Err(e) => err(403, e.to_string()),
        }
    }

    fn look(&self, body: &[u8], now: u64) -> Reply {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Body {
            request: DisclosureRequest,
        }
        let b: Body = match serde_json::from_slice(body) {
            Ok(b) => b,
            Err(e) => return err(400, format!("body: {e}")),
        };
        let Ok(at) = Timestamp::from_unix_ms(now) else {
            return err(500, "the clock");
        };
        // The stream is ours to decide, never the requester's to claim.
        let stream = if b.request.owner.iter().any(|k| self.legal.contains(&k.key)) {
            Stream::LegalChecker
        } else {
            Stream::Curious
        };
        let reg = lock(&self.registry);
        let mut desk = lock(&self.desk);
        let got = desk.accept(
            &b.request,
            &*reg,
            stream,
            &period_of(now),
            &at,
            &Profile::default(),
        );
        drop(reg);
        // A spent challenge is a change too: written whether or not the look
        // went through.
        if let Err(e) = self.save_desk(&desk) {
            return err(500, e);
        }
        match got {
            Ok(a) => Reply(
                200,
                json!({"charge": a.charge, "container": a.container.to_multihash()}),
            ),
            Err(e) => desk_error(&e),
        }
    }

    fn holder(&self, holder: &str) -> Reply {
        let Some(h) = self.holders.get(holder) else {
            return err(401, "unknown holder");
        };
        let payer = lock(&h.sender).payer();
        Reply(
            200,
            json!({"holder": holder, "cluster": self.cfg.cluster, "payer": payer}),
        )
    }

    fn anchor(&self, holder: &str, body: &[u8], now: u64) -> Reply {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Body {
            container: String,
            kind: Kind,
            subject: String,
            memo: String,
        }
        let b: Body = match serde_json::from_slice(body) {
            Ok(b) => b,
            Err(e) => return err(400, format!("body: {e}")),
        };
        let (Ok(container), Ok(subject)) = (
            Hash::from_multihash(&b.container),
            Hash::from_multihash(&b.subject),
        ) else {
            return err(400, "container and subject are multihashes");
        };
        let Some(h) = self.holders.get(holder) else {
            return err(401, "unknown holder");
        };
        let mut st = lock(&h.state);
        match st.outbox.push(container, b.kind, subject, b.memo, now) {
            Ok(id) => {
                if !st.containers.contains(&container) {
                    st.containers.push(container);
                }
                match self.save_holder(holder, &st) {
                    Ok(()) => Reply(200, json!({"job": id})),
                    Err(e) => err(500, e),
                }
            }
            Err(e) => err(400, e.to_string()),
        }
    }

    fn job(&self, holder: &str, id: &str) -> Reply {
        let Ok(id) = id.parse::<u64>() else {
            return err(400, "a job is a number");
        };
        let Some(h) = self.holders.get(holder) else {
            return err(401, "unknown holder");
        };
        let st = lock(&h.state);
        if let Some(d) = st.done.get(&id) {
            return Reply(
                200,
                json!({"state": "anchored", "attestation": d.attestation, "anchor": d.anchor}),
            );
        }
        match st.outbox.jobs().iter().find(|j| j.id == id) {
            Some(j) => Reply(
                200,
                json!({
                    "state": if j.sent.is_some() { "sent" } else { "queued" },
                    "attempts": j.attempts,
                    "last_error": j.last_error,
                }),
            ),
            None => err(404, "no such job"),
        }
    }

    fn notices(&self, holder: &str, body: &[u8]) -> Reply {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Body {
            container: String,
        }
        let b: Body = match serde_json::from_slice(body) {
            Ok(b) => b,
            Err(e) => return err(400, format!("body: {e}")),
        };
        let Ok(container) = Hash::from_multihash(&b.container) else {
            return err(400, "container is a multihash");
        };
        let Some(h) = self.holders.get(holder) else {
            return err(401, "unknown holder");
        };
        if !lock(&h.state).containers.contains(&container) {
            return err(403, "this holder anchored no such container here");
        }
        let mut desk = lock(&self.desk);
        let (notices, dropped): (Vec<ViewNotice>, u64) = desk.take_notices(&container);
        if let Err(e) = self.save_desk(&desk) {
            return err(500, e);
        }
        Reply(200, json!({"notices": notices, "dropped": dropped}))
    }

    /// Starts one `bare` issuance request (этап 1, in-memory).
    ///
    /// The contact value (email or `did:web`) is validated and never logged.
    fn bare_start(&self, body: &[u8], now: u64) -> Reply {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Body {
            email: Option<String>,
            did_web: Option<String>,
        }
        let b: Body = match serde_json::from_slice(body) {
            Ok(b) => b,
            Err(e) => return err(400, format!("body: {e}")),
        };
        let mut ledger = lock(&self.bare);
        match ledger.start(
            b.email.as_deref(),
            b.did_web.as_deref(),
            now,
            crate::bare_db::load_hmac_key().ok().as_deref().map(|k| k.as_slice()),
        ) {
            Ok((id, code)) => Reply(200, json!({"id": id, "code": code, "send_to": BARE_SEND_TO})),
            Err(e) if e.starts_with(LEDGER_BUSY) => err(429, e),
            Err(e) => err(400, e),
        }
    }

    /// The `mail` intake (этап 6, owner mail only).
    ///
    /// The Email Worker posts the raw message it received on the verify
    /// address plus the pending request id: `{"id", "raw"}` where `raw` is
    /// the full RFC5322 message. The service parses From and the six-digit
    /// code (Subject first, then the text body), checks that exactly one
    /// pending request matches both the holder hash of the From address and
    /// the code, and only then verifies DKIM of the From domain over the raw
    /// message (`mail-auth` against the network DNS). On success it inserts
    /// the issuance row and consumes the request; a consumed code never
    /// works twice. Contact values are validated and never logged.
    fn bare_mail(&self, body: &[u8], now: u64, auth: Option<&str>) -> Reply {
        // The Email Worker proves itself first: without its bearer secret no
        // body is even parsed. The secret lives in a file named by
        // `KSG_BARE_WORKER_SECRET_FILE`; the header is compared in constant
        // time. Contact values are validated and never logged.
        if !worker_secret_ok(auth) {
            return err(401, "worker: unauthorized");
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Body {
            id: String,
            raw: String,
        }
        let b: Body = match serde_json::from_slice(body) {
            Ok(b) => b,
            Err(e) => return err(400, format!("body: {e}")),
        };
        if b.id.is_empty() || b.id.len() > 64 || b.raw.len() > MAX_BODY {
            return err(400, "id or raw: malformed");
        }
        let Some((from, code)) = parse_bare_mail(&b.raw) else {
            return err(400, "from or code: not found");
        };
        if !valid_email(&from) {
            return err(400, "from: malformed contact");
        }
        let key = match crate::bare_db::load_hmac_key() {
            Ok(k) => k,
            Err(_) => return err(503, "hmac key: not configured"),
        };
        let holder = crate::bare_db::holder_hmac(key.as_slice(), &from);
        let matched = {
            let mut ledger = lock(&self.bare);
            ledger.find_match(&holder, &code, now)
        };
        let Some(matched) = matched else {
            return err(404, "no such pending request");
        };
        if matched != b.id {
            return err(404, "no such pending request");
        }
        if !dkim_passes(&b.raw, &from) {
            return err(403, "dkim: no passing signature for from domain");
        }
        {
            let mut ledger = lock(&self.bare);
            if ledger.take_by_id(&matched).is_none() {
                return err(404, "no such pending request");
            }
        }
        match insert_bare_issuance(&from) {
            Ok(number) => Reply(200, json!({"state": "issued", "number": number})),
            Err(e) => e,
        }
    }

    /// Issues one orchestrator challenge (этап 9).
    ///
    /// The caller names the domain's `did:web` identifier; the answer is the
    /// challenge id and the random code the domain's `did.json` key must
    /// sign. Contact values are validated and never logged.
    fn orch_challenge(&self, body: &[u8], now: u64) -> Reply {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Body {
            did_web: String,
        }
        let b: Body = match serde_json::from_slice(body) {
            Ok(b) => b,
            Err(e) => return err(400, format!("body: {e}")),
        };
        if b.did_web.len() > 512 {
            return err(400, "did_web: malformed contact");
        }
        let mut ledger = lock(&self.orch);
        match ledger.start(&b.did_web, now) {
            Ok((id, code)) => Reply(200, json!({"id": id, "code": code})),
            Err(e) if e.starts_with(LEDGER_BUSY) => err(429, e),
            Err(e) => err(400, e),
        }
    }

    /// Checks one orchestrator proof (этап 9).
    ///
    /// The caller answers the challenge id with the code signed by the key
    /// named in the domain's `did.json`: `{"id", "signature"}` where
    /// `signature` is the base64url Ed25519 signature over the challenge code.
    /// On success the service inserts the issuance row against the domain
    /// hash (one free `bare` per domain per release, §migration 001).
    /// The challenge is consumed whether or not the proof verifies. The
    /// worker identity comes from the environment: `KSG_BARE_WORKER_DOMAIN`
    /// must equal the challenge domain, so a stolen worker secret cannot
    /// issue for another domain. Contact values are validated and never
    /// logged.
    fn orch_proof(&self, body: &[u8], now: u64) -> Reply {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Body {
            id: String,
            signature: String,
        }
        let b: Body = match serde_json::from_slice(body) {
            Ok(b) => b,
            Err(e) => return err(400, format!("body: {e}")),
        };
        if b.id.is_empty() || b.id.len() > 64 || b.signature.is_empty() || b.signature.len() > 128 {
            return err(400, "id or signature: malformed");
        }
        let sig: [u8; 64] = match B64.decode(&b.signature).ok().and_then(|v| v.try_into().ok()) {
            Some(s) => s,
            None => return err(400, "signature: not an Ed25519 signature"),
        };
        let Some((did_web, code)) = lock(&self.orch).take(&b.id, now) else {
            return err(404, "no such pending challenge");
        };
        let domain = match crate::bare_db::did_web_domain(&did_web) {
            Some(d) => d.to_owned(),
            None => return err(400, "did_web: malformed contact"),
        };
        let worker = match std::env::var(BARE_WORKER_DOMAIN_ENV) {
            Ok(w) if !w.is_empty() && w.len() <= 253 => w.to_lowercase(),
            _ => return err(503, "worker: not configured"),
        };
        if domain.to_lowercase() != worker {
            return err(403, "worker: not this domain");
        }
        let key = match self.outbound_slot().and_then(|_slot| orch_key(&did_web)) {
            Ok(k) => k,
            Err(e) => return e,
        };
        if key
            .verify_strict(code.as_bytes(), &EdSignature::from_bytes(&sig))
            .is_err()
        {
            return err(403, "proof: bad signature");
        }
        match insert_bare_orch_issuance(&did_web, &domain) {
            Ok(number) => Reply(200, json!({"state": "issued", "number": number})),
            Err(e) => e,
        }
    }
}

/// How the `mail` step reaches Postgres: connection string in
/// `KSG_BARE_DATABASE_URL`, current release id in `KSG_BARE_RELEASE`.
pub const BARE_DATABASE_URL_ENV: &str = "KSG_BARE_DATABASE_URL";
/// The current `bare` release id (row in `releases`).
pub const BARE_RELEASE_ENV: &str = "KSG_BARE_RELEASE";
/// The domain this worker may issue orchestrator `bare` for (этап 9).
///
/// The proof step checks the challenge's domain against this value: a worker
/// configured for one domain cannot spend its secret on another.
pub const BARE_WORKER_DOMAIN_ENV: &str = "KSG_BARE_WORKER_DOMAIN";
/// The file holding the Email Worker bearer secret (этап 17).
///
/// The worker sends `Authorization: Bearer <secret>`; the secret lives in a
/// file named by this variable, never in code. Compared in constant time.
pub const BARE_WORKER_SECRET_FILE_ENV: &str = "KSG_BARE_WORKER_SECRET_FILE";
/// The `HTTP(S)` timeout for fetching the domain's `did.json`, seconds.
pub const BARE_DID_TIMEOUT_S: u64 = 10;

/// Inserts one owner issuance row: smallest free number of the current
/// release against the holder hash of the From address (owner = no domain).
///
/// Contact values never leave this function toward logs; only the outcome
/// code is returned.
///
/// # Errors (as replies)
///
/// 503 when the database or the HMAC key is not configured, 409 when this
/// holder or the release is already spent, 500 on any other database failure.
fn insert_bare_issuance(from: &str) -> Result<i32, Reply> {
    let url = std::env::var(BARE_DATABASE_URL_ENV)
        .map_err(|_| err(503, "database: not configured"))?;
    let release = std::env::var(BARE_RELEASE_ENV).unwrap_or_else(|_| "0".to_owned());
    if release.is_empty() || release.len() > 128 {
        return Err(err(500, "release: misconfigured"));
    }
    let key = crate::bare_db::load_hmac_key().map_err(|_| err(503, "hmac key: not configured"))?;
    let holder = crate::bare_db::holder_hmac(key.as_slice(), from);
    let mut client =
        postgres::Client::connect(&url, postgres::NoTls).map_err(|_| err(503, "database: down"))?;
    let number = crate::bare_db::next_free_number(&mut client, &release).map_err(|e| {
        use crate::bare_db::BareDbError as E;
        match e {
            E::ReleaseFull | E::AlreadyIssued => err(409, "already issued"),
            E::UnknownRelease | E::BadSize => err(500, "release: misconfigured"),
            E::Db(_) => err(500, "database: failed"),
            E::Env | E::KeyFile => err(503, "hmac key: not configured"),
        }
    })?;
    let Some(number) = number else {
        return Err(err(409, "already issued"));
    };
    crate::bare_db::insert_issuance(&mut client, &release, number, &holder, None).map_err(|e| {
        use crate::bare_db::BareDbError as E;
        match e {
            E::AlreadyIssued => err(409, "already issued"),
            E::Db(_) => err(500, "database: failed"),
            E::Env | E::KeyFile => err(503, "hmac key: not configured"),
            E::UnknownRelease | E::BadSize | E::ReleaseFull => {
                err(500, "release: misconfigured")
            }
        }
    })
}

/// Inserts one orchestrator issuance row: the smallest free number of the
/// current release against the holder hash of the `did:web` value and the
/// domain hash of its host (one free `bare` per domain per release).
///
/// Contact values never leave this function toward logs; only the outcome
/// code is returned.
///
/// # Errors (as replies)
///
/// 503 when the database or the HMAC key is not configured, 409 when this
/// holder, this domain, or the release is already spent, 500 on any other
/// database failure.
fn insert_bare_orch_issuance(did_web: &str, domain: &str) -> Result<i32, Reply> {
    let url = std::env::var(BARE_DATABASE_URL_ENV)
        .map_err(|_| err(503, "database: not configured"))?;
    let release = std::env::var(BARE_RELEASE_ENV).unwrap_or_else(|_| "0".to_owned());
    if release.is_empty() || release.len() > 128 {
        return Err(err(500, "release: misconfigured"));
    }
    let key = crate::bare_db::load_hmac_key().map_err(|_| err(503, "hmac key: not configured"))?;
    let holder = crate::bare_db::holder_hmac(key.as_slice(), did_web);
    let dom_hash = crate::bare_db::domain_hmac(key.as_slice(), domain);
    let mut client =
        postgres::Client::connect(&url, postgres::NoTls).map_err(|_| err(503, "database: down"))?;
    let number = crate::bare_db::next_free_number(&mut client, &release).map_err(|e| {
        use crate::bare_db::BareDbError as E;
        match e {
            E::ReleaseFull | E::AlreadyIssued => err(409, "already issued"),
            E::UnknownRelease | E::BadSize => err(500, "release: misconfigured"),
            E::Db(_) => err(500, "database: failed"),
            E::Env | E::KeyFile => err(503, "hmac key: not configured"),
        }
    })?;
    let Some(number) = number else {
        return Err(err(409, "already issued"));
    };
    crate::bare_db::insert_issuance(&mut client, &release, number, &holder, Some(&dom_hash)).map_err(
        |e| {
            use crate::bare_db::BareDbError as E;
            match e {
                E::AlreadyIssued => err(409, "already issued"),
                E::Db(_) => err(500, "database: failed"),
                E::Env | E::KeyFile => err(503, "hmac key: not configured"),
                E::UnknownRelease | E::BadSize | E::ReleaseFull => {
                    err(500, "release: misconfigured")
                }
            }
        },
    )
}

/// The address of a domain's `did.json` (этап 9).
///
/// `did:web:<host>` (no path) reads `https://<host>/.well-known/did.json`;
/// `did:web:<host>:<path...>` reads `https://<host>/<path...>/did.json`.
/// Percent-encoded segments stay encoded: what the domain published under
/// that name is what is read. Returns `None` on a malformed identifier or
/// an over-long URL.
fn did_json_url(did_web: &str) -> Option<String> {
    const PREFIX: &str = "did:web:";
    let rest = did_web.strip_prefix(PREFIX)?;
    if rest.is_empty() || rest.len() > 512 || !valid_did_web(did_web) {
        return None;
    }
    let mut parts = rest.split(':');
    let host = parts.next()?;
    if host.is_empty() || host.len() > 253 {
        return None;
    }
    let mut url = String::from("https://");
    url.push_str(host);
    url.push('/');
    let tail: Vec<&str> = parts.collect();
    if tail.is_empty() {
        url.push_str(DID_JSON_WELL_KNOWN);
    } else {
        for (i, seg) in tail.iter().enumerate() {
            if i > 0 {
                url.push('/');
            }
            url.push_str(seg);
        }
        url.push_str("/did.json");
    }
    if url.len() > 2048 {
        return None;
    }
    Some(url)
}

/// The domain's verification key from its `did.json` (этап 9).
///
/// Fetches the document over HTTPS (`did_json_url`) with a bounded timeout,
/// takes the first `verificationMethod` entry carrying an Ed25519 key in
/// `publicKeyMultibase` (base58btc `z` + 32 bytes, multicodec `0xed 0x01`),
/// and returns it as a [`VerifyingKey`]. Only HTTPS is ever fetched; the
/// HTTP status must be 200 and the body must fit in [`MAX_BODY`].
///
/// # Errors (as replies)
///
/// 503 when the document does not read (network, timeout, status), 500 when
/// it reads but names no usable Ed25519 key.
fn orch_key(did_web: &str) -> Result<VerifyingKey, Reply> {
    let url = did_json_url(did_web).ok_or_else(|| err(400, "did_web: malformed contact"))?;
    let agent: ureq::Agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(BARE_DID_TIMEOUT_S))
        .build();
    let body = agent
        .get(&url)
        .call()
        .map_err(|_| err(503, "did.json: not reachable"))
        .and_then(|resp| {
            if resp.status() != 200 {
                return Err(err(503, "did.json: not reachable"));
            }
            resp.into_string()
                .map_err(|_| err(503, "did.json: not reachable"))
        })?;
    if body.len() > MAX_BODY {
        return Err(err(503, "did.json: too large"));
    }
    did_key(&body).ok_or_else(|| err(500, "did.json: no Ed25519 key"))
}

/// The first Ed25519 key of a `did.json` document.
///
/// Reads `verificationMethod[]`: the first entry whose `publicKeyMultibase`
/// decodes from base58btc `z...` to multicodec `0xed 0x01` + 32 key bytes.
/// Nothing from the document is logged.
fn did_key(body: &str) -> Option<VerifyingKey> {
    let doc: serde_json::Value = serde_json::from_str(body).ok()?;
    let methods = doc.get("verificationMethod")?.as_array()?;
    for m in methods {
        let mb = m.get("publicKeyMultibase")?.as_str()?;
        let raw = mb.strip_prefix('z')?;
        // `bs58 0.5` decodes without a length cap; reject absurd inputs up
        // front (a `z` + 44 chars is the honest shape).
        if raw.len() > 128 {
            continue;
        }
        let decoded = bs58::decode(raw).into_vec().ok()?;
        let bytes: [u8; 34] = decoded.try_into().ok()?;
        if bytes[0] != 0xed || bytes[1] != 0x01 {
            continue;
        }
        let key: [u8; 32] = bytes[2..].try_into().ok()?;
        if let Ok(k) = VerifyingKey::from_bytes(&key) {
            return Some(k);
        }
    }
    None
}

/// Parses a raw RFC5322 message: the From address and the first six-digit
/// code from the Subject, else from the first text body part.
///
/// Returns `None` when the message does not parse, has no usable From
/// address, or names no six ASCII digits in a row. A message with more
/// than one `From` header or more than one address in `From` is also
/// rejected (double-From tricks DKIM checks into validating the wrong
/// identity). The contact value is returned for hashing only — never logged.
fn parse_bare_mail(raw: &str) -> Option<(String, String)> {
    let msg = mail_parser::MessageParser::default().parse(raw.as_bytes())?;
    if msg
        .headers()
        .iter()
        .filter(|h| h.name == mail_parser::HeaderName::From)
        .count()
        != 1
    {
        return None;
    }
    let from = match msg.from()? {
        mail_parser::Address::List(list) => {
            if list.len() != 1 {
                return None;
            }
            list.first()?.address.as_deref()?.trim().to_owned()
        }
        mail_parser::Address::Group(groups) => {
            let total: usize = groups.iter().map(|g| g.addresses.len()).sum();
            if total != 1 {
                return None;
            }
            groups.first()?.addresses.first()?.address.as_deref()?.trim().to_owned()
        }
    };
    if from.is_empty() || from.len() > 254 {
        return None;
    }
    let code = first_six_digits(msg.subject().unwrap_or_default())
        .or_else(|| {
            let mut found = None;
            for i in 0..msg.text_body_count() {
                let part = msg.body_text(i)?;
                if let Some(c) = first_six_digits(&part) {
                    found = Some(c);
                    break;
                }
            }
            found
        })?;
    Some((from, code))
}

/// The first run of exactly six ASCII digits bounded by non-digits.
fn first_six_digits(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut i: usize = 0;
    while i.saturating_add(6) <= bytes.len() {
        let head_ok = i == 0
            || !matches!(bytes.get(i.saturating_sub(1)), Some(b) if b.is_ascii_digit());
        let tail_ok =
            !matches!(bytes.get(i.saturating_add(6)), Some(b) if b.is_ascii_digit());
        let all_digits = bytes
            .get(i..i.saturating_add(6))
            .is_some_and(|w| w.iter().all(|b| b.is_ascii_digit()));
        if all_digits && head_ok && tail_ok {
            return s.get(i..i.saturating_add(6)).map(str::to_owned);
        }
        i += 1;
    }
    None
}

/// Whether the raw message carries a passing DKIM signature whose `d=`
/// domain equals the domain of the From address.
///
/// Verification runs on a throwaway single-threaded runtime in a worker
/// thread: `mail-auth` is async and DNS-backed, the service threads are
/// blocking `tiny_http` workers. Only `Pass` counts; `Neutral` (expired,
/// body-hash mismatch), `Fail`, and DNS errors all refuse. No message
/// content is logged.
fn dkim_passes(raw: &str, from: &str) -> bool {
    let domain = from.rsplit('@').next().unwrap_or_default().to_lowercase();
    if domain.is_empty() || !domain.contains('.') {
        return false;
    }
    let raw = raw.to_owned();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build();
        let Ok(rt) = rt else { return false };
        rt.block_on(async move {
            let authenticator = match mail_auth::MessageAuthenticator::new_cloudflare() {
                Ok(a) => a,
                Err(_) => return false,
            };
            let parsed = match mail_auth::AuthenticatedMessage::parse(raw.as_bytes()) {
                Some(m) => m,
                None => return false,
            };
            authenticator
                .verify_dkim(&parsed)
                .await
                .iter()
                .any(|o| *o.result() == mail_auth::DkimResult::Pass && dkim_domain(o) == domain)
        })
    })
    .join()
    .unwrap_or(false)
}

/// The `d=` domain of a DKIM result's signature, lowercased.
fn dkim_domain(o: &mail_auth::DkimOutput<'_>) -> String {
    o.signature().map(|s| s.d.to_lowercase()).unwrap_or_default()
}

impl Shared {
    /// The state of a `bare` request id: `{"state":"pending"}` or 404.
    fn bare_status(&self, id: &str, now: u64) -> Reply {
        let mut ledger = lock(&self.bare);
        match ledger.state(id, now) {
            Some(state) => Reply(200, json!({"state": state})),
            None => err(404, "no such bare request"),
        }
    }

    /// How many `bare` certificates were issued.
    fn bare_count(&self) -> Reply {
        // TODO(этап 2: БД): count issued certificates from the database once
        // issuance persists past process memory.
        Reply(200, json!({"issued": lock(&self.bare).issued()}))
    }

    /// One pass of every holder's queue; then, once in a while, what ages out.
    fn tick(&self, now: u64) {
        for (id, h) in &self.holders {
            let mut st = lock(&h.state);
            if st.outbox.jobs().iter().all(|j| j.next_try_ms > now) {
                continue;
            }
            let t = {
                let mut sender = lock(&h.sender);
                st.outbox.tick(&mut **sender, now)
            };
            if t.anchored.is_empty() && t.sent == 0 && t.failed == 0 {
                continue;
            }
            if !t.anchored.is_empty() {
                let mut desk = lock(&self.desk);
                for a in &t.anchored {
                    desk.linkage_mut()
                        .record(a.anchor.clone(), a.container, period_of(now));
                }
                if let Err(e) = self.save_desk(&desk) {
                    eprintln!("ksg-service: desk not saved: {e}");
                }
            }
            for a in t.anchored {
                st.done.insert(
                    a.id,
                    Done {
                        attestation: a.attestation,
                        anchor: a.anchor,
                        landed_ms: now,
                    },
                );
            }
            st.done
                .retain(|_, d| now.saturating_sub(d.landed_ms) <= DONE_KEEP_MS);
            while st.done.len() > MAX_DONE {
                let Some(first) = st.done.keys().next().copied() else {
                    break;
                };
                st.done.remove(&first);
            }
            if let Err(e) = self.save_holder(id, &st) {
                eprintln!("ksg-service: holder {id} not saved: {e}");
            }
        }
    }
}

/// Whether the `Authorization: Bearer <secret>` header matches the worker
/// secret from the file named by [`BARE_WORKER_SECRET_FILE_ENV`].
///
/// The comparison runs in constant time over the secret length; an absent
/// header, a non-`Bearer` scheme, an unreadable secret file, or an empty
/// secret all refuse. Nothing secret is logged.
fn worker_secret_ok(auth: Option<&str>) -> bool {
    let given = match auth.and_then(|h| h.strip_prefix("Bearer ")) {
        Some(g) if !g.is_empty() => g.as_bytes(),
        _ => return false,
    };
    let path = match std::env::var(BARE_WORKER_SECRET_FILE_ENV) {
        Ok(p) if !p.is_empty() => p,
        _ => return false,
    };
    let secret: Zeroizing<Vec<u8>> = match std::fs::read(&path) {
        Ok(b) if !b.is_empty() => Zeroizing::new(b),
        _ => return false,
    };
    if given.len() != secret.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in given.iter().zip(secret.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// An [`Rpc`] that answers nothing: `bare_only` never touches the network.
#[derive(Debug, Default)]
struct NoRpc;

impl Rpc for NoRpc {
    fn call(
        &self,
        _method: &str,
        _params: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        Err("no network in bare_only".to_owned())
    }
}

/// A `Shared` handle with no holders, for the `bare` issuance routes.
///
/// Integration tests call [`Shared::bare_route`] through this constructor, so
/// no network port is opened and no signer or database is needed. The `email`
/// / `did:web` contact values are validated and never logged.
impl Shared {
    /// Creates an empty shared state for the `bare` routes (этап 1: no DB).
    ///
    /// # Errors
    ///
    /// The `desk` audience URI does not parse.
    pub fn bare_only(audience: &str) -> Result<Self, String> {
        Ok(Self {
            cfg: Config {
                listen: "127.0.0.1:0".to_owned(),
                audience: Uri::parse(audience).map_err(|e| e.to_string())?,
                state: PathBuf::from("/tmp"),
                cluster: "devnet".to_owned(),
                rpc: "http://127.0.0.1:1".to_owned(),
                issuer_keys: PathBuf::from("/tmp/missing.json"),
                max_standing_age_s: None,
                legal_checkers: Vec::new(),
                holders: Vec::new(),
                workers: Some(1),
            },
            desk: Mutex::new(Desk::new(
                Uri::parse(audience).map_err(|e| e.to_string())?,
            )),
            registry: Mutex::new(ChainRegistry::default()),
            holders: BTreeMap::new(),
            seen: Mutex::new(BTreeMap::new()),
            rpc: Box::new(NoRpc),
            legal: Vec::new(),
            bare: Mutex::new(BareLedger::new()),
            orch: Mutex::new(OrchLedger::new()),
            outbound: AtomicUsize::new(0),
            outbound_max: outbound_max(1),
        })
    }

    /// Drives one `bare` route in-process: `POST /v1/bare/start`,
    /// `GET /v1/bare/status/{id}`, `GET /v1/bare/count`.
    /// `POST /v1/bare/mail` needs the worker bearer secret plus Postgres +
    /// DNS, so it is not on the in-process route: it answers 401 without the
    /// secret, 503 without the database configured.
    ///
    /// Anything else is a 404. Contact values are never logged.
    /// The `auth` argument carries the worker's `Authorization` header for
    /// `/v1/bare/mail` (`None` for the other routes).
    pub fn bare_route(&self, method: &str, path: &str, body: &[u8], now: u64) -> Reply {
        self.bare_route_auth(method, path, body, None, now)
    }

    /// Like [`Shared::bare_route`], with an explicit `Authorization` header
    /// for `/v1/bare/mail`: the Email Worker proves itself with
    /// `Bearer <secret>` (`worker_secret_ok`).
    pub fn bare_route_auth(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        auth: Option<&str>,
        now: u64,
    ) -> Reply {
        match (method, path) {
            ("POST", "/v1/bare/start") => self.bare_start(body, now),
            ("POST", "/v1/bare/mail") => self.bare_mail(body, now, auth),
            ("POST", "/v1/bare/orchestrator/challenge") => self.orch_challenge(body, now),
            ("POST", "/v1/bare/orchestrator/proof") => self.orch_proof(body, now),
            ("GET", p) if p.starts_with("/v1/bare/status/") => {
                self.bare_status(p.trim_start_matches("/v1/bare/status/"), now)
            }
            ("GET", "/v1/bare/count") => self.bare_count(),
            _ => err(404, "no such endpoint"),
        }
    }

    /// What ages out: watchers' standings past their age, and periods of the
    /// anchor table past the retention (CT-37).
    fn expire(&self, now: u64) {
        let mut reg = lock(&self.registry);
        if reg.prune(now) > 0 {
            if let Err(e) = self.save_registry(&reg) {
                eprintln!("ksg-service: registry not saved: {e}");
            }
        }
        drop(reg);
        let keep_ms = u64::from(KEY_RETENTION_DAYS) * 24 * 60 * 60 * 1000;
        let cutoff = period_of(now.saturating_sub(keep_ms));
        let mut desk = lock(&self.desk);
        let old: Vec<String> = desk
            .linkage()
            .periods()
            .into_iter()
            .filter(|p| *p < cutoff)
            .collect();
        if !old.is_empty() {
            for p in &old {
                desk.linkage_mut().forget(p);
            }
            if let Err(e) = self.save_desk(&desk) {
                eprintln!("ksg-service: desk not saved: {e}");
            }
        }
    }
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Starts the service: reads its state, binds its port, starts its threads.
///
/// `senders` is one [`ChainSender`] per configured holder, by id; `rpc` is
/// the node the registry reads status anchors through.
///
/// # Errors
///
/// The configuration is inconsistent, the state does not read, or the port
/// does not bind.
pub fn start(
    cfg: Config,
    mut senders: BTreeMap<String, Box<dyn ChainSender + Send>>,
    rpc: Box<dyn Rpc + Send + Sync>,
) -> Result<Running, String> {
    std::fs::create_dir_all(&cfg.state).map_err(|e| format!("{}: {e}", cfg.state.display()))?;
    let issuer: Vec<PublicKey> = read_json(&cfg.issuer_keys)?
        .ok_or_else(|| format!("{}: missing", cfg.issuer_keys.display()))?;
    let issuer: KeySet = issuer.into_iter().collect();
    let max_age = cfg
        .max_standing_age_s
        .map_or(DEFAULT_MAX_AGE_MS, |s| s.saturating_mul(1000));

    let mut holders = BTreeMap::new();
    for h in &cfg.holders {
        if !valid_id(&h.id) {
            return Err(format!(
                "holder id {:?}: lowercase letters, digits, -",
                h.id
            ));
        }
        if h.key.alg != Alg::Ed25519 {
            return Err(format!("holder {}: the key must be Ed25519", h.id));
        }
        let key: [u8; 32] = B64
            .decode(&h.key.key)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| format!("holder {}: not an Ed25519 key", h.id))?;
        let key = VerifyingKey::from_bytes(&key).map_err(|e| format!("holder {}: {e}", h.id))?;
        let sender = senders
            .remove(&h.id)
            .ok_or_else(|| format!("holder {}: no sender", h.id))?;
        let state: HolderState =
            read_json(&cfg.state.join(format!("holder-{}.json", h.id)))?.unwrap_or_default();
        if holders
            .insert(
                h.id.clone(),
                Holder {
                    key,
                    state: Mutex::new(state),
                    sender: Mutex::new(sender),
                },
            )
            .is_some()
        {
            return Err(format!("holder {} twice", h.id));
        }
    }
    let desk = match std::fs::read_to_string(cfg.state.join("desk.json")) {
        Ok(s) => Desk::from_json(&s).map_err(|e| format!("desk.json: {e}"))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Desk::new(cfg.audience.clone()),
        Err(e) => return Err(format!("desk.json: {e}")),
    };
    let mut registry: ChainRegistry =
        read_json(&cfg.state.join("registry.json"))?.unwrap_or_default();
    registry.configure(issuer, max_age);

    // Every accepted connection gets the socket timeout (patched tiny_http,
    // third_party/tiny_http-0.12.0): a silent peer frees its thread.
    let http = Arc::new(
        tiny_http::Server::http_with_timeout(&cfg.listen, Duration::from_secs(SOCKET_TIMEOUT_S))
            .map_err(|e| format!("{}: {e}", cfg.listen))?,
    );
    let addr = http
        .server_addr()
        .to_ip()
        .ok_or("the server listens on no IP address")?;
    let workers = cfg.workers.unwrap_or(4).clamp(1, 64);
    let shared = Arc::new(Shared {
        legal: cfg.legal_checkers.clone(),
        cfg,
        desk: Mutex::new(desk),
        registry: Mutex::new(registry),
        holders,
        seen: Mutex::new(BTreeMap::new()),
        rpc,
        bare: Mutex::new(BareLedger::new()),
        orch: Mutex::new(OrchLedger::new()),
        outbound: AtomicUsize::new(0),
        outbound_max: outbound_max(workers),
    });
    let stop = Arc::new(AtomicBool::new(false));
    let mut threads = Vec::new();
    for _ in 0..workers {
        let (http, shared, stop) = (http.clone(), shared.clone(), stop.clone());
        threads.push(std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                let Ok(mut rq) = http.recv() else { break };
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                let started = Instant::now();
                let (method, path) = (rq.method().to_string(), rq.url().to_owned());
                let Reply(code, body) = shared.handle(&mut rq);
                eprintln!(
                    "ksg-service: {method} {path} {code} {}ms",
                    started.elapsed().as_millis()
                );
                let mut resp =
                    tiny_http::Response::from_string(body.to_string()).with_status_code(code);
                if let Ok(h) =
                    tiny_http::Header::from_bytes(&b"content-type"[..], &b"application/json"[..])
                {
                    resp.add_header(h);
                }
                let _ = rq.respond(resp);
            }
        }));
    }
    {
        let (shared, stop) = (shared.clone(), stop.clone());
        threads.push(std::thread::spawn(move || {
            let mut last_expire = 0u64;
            while !stop.load(Ordering::SeqCst) {
                let now = now_ms();
                shared.tick(now);
                if now.saturating_sub(last_expire) > 60 * 60 * 1000 {
                    shared.expire(now);
                    last_expire = now;
                }
                std::thread::sleep(Duration::from_millis(1000));
            }
        }));
    }
    Ok(Running {
        addr,
        http,
        stop,
        threads,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn outbound_calls_take_at_most_half_the_threads() {
        assert_eq!(outbound_max(1), 1);
        assert_eq!(outbound_max(4), 2);
        let s = Shared::bare_only("https://svc.example/v1").unwrap();
        let Ok(first) = s.outbound_slot() else {
            panic!("the first call gets a place")
        };
        let second = s.outbound_slot();
        assert_eq!(second.err().map(|r| r.status()), Some(503));
        drop(first);
        assert!(s.outbound_slot().is_ok(), "the place is back after drop");
    }

    #[test]
    fn a_body_past_the_deadline_is_408() {
        let past = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
        let r = read_body(&mut std::io::repeat(b'a'), past).err().unwrap();
        assert_eq!(r.status(), 408);
        let r = read_body(&mut std::io::repeat(b'a'), Instant::now() + Duration::from_secs(60))
            .err()
            .unwrap();
        assert_eq!(r.status(), 413);
        let ok = read_body(&mut &b"{}"[..], Instant::now() + Duration::from_secs(60)).unwrap();
        assert_eq!(ok, b"{}");
    }
}
