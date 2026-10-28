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
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use ed25519_dalek::{Signature as EdSignature, VerifyingKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::json;

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

/// One pending `bare` issuance request (этап 1, in-memory).
#[allow(dead_code)] // `code` is checked by the verify step (этап 2); stored now.
struct BareEntry {
    code: String,
    expires_ms: u64,
}

/// How long a `bare` request stays pending: thirty minutes.
pub const BARE_TTL_MS: u64 = 30 * 60 * 1000;

/// Where the applicant sends the six-digit code for manual verification.
const BARE_SEND_TO: &str = "verify@keysingate.com";

/// In-memory ledger of pending `bare` requests (этап 1: no database).
///
/// `issued` stays zero until этап 2 wires a database; the store keeps only
/// pending requests, each for [`BARE_TTL_MS`].
#[derive(Default)]
pub struct BareLedger {
    entries: HashMap<String, BareEntry>,
}impl BareLedger {
    /// Creates an empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Starts one issuance request: exactly one contact, `email` or `did_web`.
    ///
    /// Returns the request id and the six-digit code, or why the contact is
    /// refused. The contact value itself is never logged nor echoed back.
    ///
    /// # Errors
    ///
    /// The contact is missing, doubled, malformed — or there is no randomness.
    pub fn start(
        &mut self,
        email: Option<&str>,
        did_web: Option<&str>,
        now: u64,
    ) -> Result<(String, String), String> {
        let ok = match (email, did_web) {
            (Some(e), None) => valid_email(e),
            (None, Some(d)) => valid_did_web(d),
            _ => false,
        };
        if !ok {
            return Err("email or did_web: malformed contact".to_owned());
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
            code[i] = b'0' + (rest % 10) as u8;
            rest /= 10;
        }
        let code = String::from_utf8_lossy(&code).into_owned();
        self.entries.retain(|_, e| e.expires_ms > now);
        self.entries.insert(id.clone(), BareEntry {
            expires_ms: now.saturating_add(BARE_TTL_MS),
            code: code.clone(),
        });
        Ok((id, code))
    }

    /// The state of a request id: `"pending"` while it is known and fresh.
    pub fn state(&mut self, id: &str, now: u64) -> Option<&'static str> {
        self.entries.retain(|_, e| e.expires_ms > now);
        self.entries.get(id).map(|_| "pending")
    }

    /// How many certificates were issued (этап 1: always zero, no database).
    #[must_use]
    pub fn issued(&self) -> u64 {
        0
    }
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

    fn handle(&self, rq: &mut tiny_http::Request) -> Reply {
        let method = rq.method().as_str().to_owned();
        let path = rq.url().split('?').next().unwrap_or("").to_owned();
        let mut body = Vec::new();
        if rq
            .as_reader()
            .take(MAX_BODY as u64 + 1)
            .read_to_end(&mut body)
            .is_err()
        {
            return err(400, "the body did not read");
        }
        if body.len() > MAX_BODY {
            return err(413, "the body is too large");
        }
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
        match ledger.start(b.email.as_deref(), b.did_web.as_deref(), now) {
            Ok((id, code)) => Reply(200, json!({"id": id, "code": code, "send_to": BARE_SEND_TO})),
            Err(e) => err(400, e),
        }
    }

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
        })
    }

    /// Drives one `bare` route in-process: `POST /v1/bare/start`,
    /// `GET /v1/bare/status/{id}`, `GET /v1/bare/count`.
    ///
    /// Anything else is a 404. Contact values are never logged.
    pub fn bare_route(&self, method: &str, path: &str, body: &[u8], now: u64) -> Reply {
        match (method, path) {
            ("POST", "/v1/bare/start") => self.bare_start(body, now),
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

    let http =
        Arc::new(tiny_http::Server::http(&cfg.listen).map_err(|e| format!("{}: {e}", cfg.listen))?);
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
