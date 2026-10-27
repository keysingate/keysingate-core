//! # ksg-verify-v2 — the third party's side, on core v2
//!
//! Core v1's `ksg-verify` carried over to `ksg-core-v2`
//! (documents of major version 3). The success metric is the same one the MVP
//! inherits from v0.3 §1.4: a verifier accepts the evidence **without a single
//! request to the issuer or the operator** — an export's bytes in, a verdict
//! out.
//!
//! # What changed against core v1's verifier
//!
//! | Core v1 | Here | Why |
//! |---|---|---|
//! | the journal of entries (`FinalExport`, one `Page`) | gone | core v2 has one work journal: the one under the movable seal (spec v2 §10) |
//! | the transparency log and its checkpoints | gone | no log in core v2 (spec v2 §17) |
//! | every anchor read, the moment thrown away | every anchor read by the core's one rule, and its bound reported per record | audit of 30.09, Ya-1: one model of time |
//! | statuses not exported | a status section export is a form of its own, its anchors read the same way | audit of 30.09, Ya-2 |
//!
//! # What the verifier brings, and why
//!
//! | Input | From where | Why not from the export |
//! |---|---|---|
//! | the export | the party presenting it | — |
//! | the container identifier | the container's initiation document | a journal of another container would pass as this one |
//! | the class | the container's packet | a forgery would declare itself `light` and skip every anchor |
//! | the key set | the keys the verifier accepts for this container | keys shipped with the evidence prove nothing about who holds them |
//! | a reader of the anchoring network | the verifier's own | an anchor's `proof` is opaque until read |
//!
//! # No reader, no time
//!
//! Without a reader a verifier confirms signatures, chain and order of a
//! light journal, and **refuses** anything whose anchors it would have to
//! read — it does not report a weaker result silently.

pub mod base;
pub mod channel;
pub mod clock;
pub mod coupling;
pub mod file;
pub mod issue_anchor;
pub mod solana;
pub mod testkeys;

use ksg_core_v2::anchor::{Attestation, AttestationVerifier};
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{Alg, KeySet, Profile, PublicKey};
use ksg_core_v2::doc::{Class, Timestamp, Uri};
use ksg_core_v2::error::Invalid;
use ksg_core_v2::journal::{
    verify_bound_point, verify_bound_read, Body, BoundExport, BoundPoint, Mode, Party,
};
use ksg_core_v2::section::StatusExport;
use serde::Serialize;

/// Which form the bytes were.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Form {
    /// A [`BoundExport`]: the journal under the movable seal (spec v2 §10).
    Bound,
    /// One [`BoundPoint`]: a page of it under the movable seal.
    BoundPoint,
    /// A [`StatusExport`]: the status section with its anchors (spec v2 §11).
    Statuses,
}

/// The upper time bound of one anchored record, as the reader established it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Bound {
    /// The record's number (journal) or the status record's number.
    pub record: u64,
    /// The earliest moment a read anchor proves; spec v2 §7.2.
    pub not_after: String,
}

/// The verdict, in a form a person and a program can both read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    /// `true` only when every check passed.
    pub accepted: bool,
    /// Which form was checked, when the bytes were recognised.
    pub form: Option<Form>,
    /// Why not, when not accepted.
    pub reason: Option<String>,
    /// Journal: the number of pages; point: 1; statuses: the records.
    pub pages: Option<u64>,
    /// Journal: the movable seal's number; point: the page's; statuses: the
    /// current status.
    pub counter: Option<u64>,
    /// Who sealed: the agent now.
    pub author: Option<String>,
    /// Point: the moment the reader established for the seal's anchor.
    pub anchored_at: Option<String>,
    /// Every anchored record with its bound (spec v2 §7.2).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub bounds: Vec<Bound>,
    /// What this verdict does **not** establish — stated, not implied.
    pub limits: Vec<&'static str>,
    /// The channel the container came through, when one was checked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<channel::ChannelReport>,
    /// Journal: the form it is in now, `local` (light) or `pro`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub journal_form: Option<Mode>,
    /// Journal: runs of pages anchored with no gap. Inside a run the links
    /// between records are confirmed; across a gap they are not (CH-25).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runs: Option<Vec<(u64, u64)>>,
    /// Journal: the agent page 0 pins — the one the channel's initiation
    /// names. `author` is the agent now; they differ after a hand-off.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_agent: Option<String>,
    /// Journal: the pages of hand-offs and changes of owner (CH-14, CH-16),
    /// each sealed by both sides — how the agent got from `first_agent` to
    /// `author` (audit of 30.09, Ya-4).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub transfers: Vec<u64>,
    /// `light` on Base Sepolia: where the export's seal stands among the
    /// container's anchors, when the verifier read it (`--base-rpc`).
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub on_base: Option<base::OnChain>,
    /// Whether the chain was walked (KS-7 §10-bis.3, K-12): only the status
    /// section, read with its anchors, is. Every other verdict is marked
    /// incomplete — it does not say the container is alive, nor that its
    /// rights are not disputed.
    pub complete: bool,
}

impl Report {
    fn rejected(form: Option<Form>, reason: impl Into<String>) -> Self {
        Self {
            accepted: false,
            form,
            reason: Some(reason.into()),
            pages: None,
            counter: None,
            author: None,
            anchored_at: None,
            bounds: Vec::new(),
            limits: Vec::new(),
            channel: None,
            journal_form: None,
            runs: None,
            first_agent: None,
            transfers: Vec::new(),
            on_base: None,
            complete: false,
        }
    }
}

/// A reader that reads nothing: every anchor is unproven with it.
///
/// Explicit rather than a missing argument, so that "verified without
/// reading anchors" can never happen by omission.
#[derive(Debug)]
pub struct NoReader;

impl AttestationVerifier for NoReader {
    fn verify(&self, _a: &Attestation) -> Result<Timestamp, Invalid> {
        Err(Invalid::Schema("no reader for any anchoring network"))
    }
    fn handles(&self, _kind: &Uri) -> bool {
        false
    }
}

/// What the verifier brings.
#[derive(Debug)]
pub struct Expected<'a> {
    /// The container identifier, from the initiation document.
    pub container: Hash,
    /// The class, from the packet.
    pub class: Class,
    /// The accepted keys: the agent's for a journal, the issuer's for the
    /// status section.
    pub keys: KeySet,
    /// Whether the agent's identifier must be the `did:key` of its own key
    /// (Г-1): a key set whose names are stand-ins (`did:key:zAgent`) is then
    /// refused, and a name borrowed from another key with it.
    ///
    /// `false` for the older test vectors and stands, where a `kid` is a name
    /// and not a claim; a verifier that accepts a container's pages sets it.
    pub client_id_from_key: bool,
    /// The reader of the anchoring network.
    pub anchors: &'a dyn AttestationVerifier,
}

/// Verifies bytes that are a journal export, one page of it, or the status
/// section.
///
/// A verdict that did not walk the chain is marked incomplete (KS-7
/// §10-bis.3, K-12): [`Report::complete`] is `false` and a limit says what
/// is not established.
#[must_use]
pub fn verify_bytes(bytes: &[u8], exp: &Expected<'_>) -> Report {
    let mut r = verify_form(bytes, exp);
    if r.accepted {
        r.complete = r.form == Some(Form::Statuses);
        if !r.complete {
            r.limits.push(INCOMPLETE);
        }
    }
    r
}

/// The limit every verdict that did not walk the chain carries (K-12).
pub const INCOMPLETE: &str = "INCOMPLETE: the chain was not walked — this verdict does not say the container is alive, nor that its rights are not disputed (KS-7 §10-bis.3)";

fn verify_form(bytes: &[u8], exp: &Expected<'_>) -> Report {
    // Spec v2 §14: the size before anything is parsed.
    if bytes.len() > ksg_core_v2::limits::MAX_EXPORT_BYTES {
        return Report::rejected(None, "past the limit: export size");
    }
    // Under the movable seal ML-DSA-65 is not a choice of the verifier: every
    // agent's seal carries it (CH-5), and the owner's and the transfers'
    // seals are Ed25519 by design — the binder checks each by its own rule.
    let profile = Profile::default();
    let value = serde_json::from_slice::<serde_json::Value>(bytes).ok();
    let doc_type = value
        .as_ref()
        .and_then(|v| v.get("type").and_then(|t| t.as_str()).map(str::to_owned));
    match doc_type.as_deref() {
        Some(BoundExport::TYPE) => match serde_json::from_slice::<BoundExport>(bytes) {
            Ok(x) => bound(&x, exp, &profile),
            Err(e) => Report::rejected(Some(Form::Bound), e.to_string()),
        },
        Some(StatusExport::TYPE) => match serde_json::from_slice::<StatusExport>(bytes) {
            Ok(x) => statuses(&x, exp, &profile),
            Err(e) => Report::rejected(Some(Form::Statuses), e.to_string()),
        },
        _ if value.as_ref().is_some_and(|v| v.get("seal").is_some()) => {
            match serde_json::from_slice::<BoundPoint>(bytes) {
                Ok(p) => bound_point(&p, exp, &profile),
                Err(e) => Report::rejected(Some(Form::BoundPoint), e.to_string()),
            }
        }
        _ => Report::rejected(
            None,
            "neither a journal export, a page under the seal, nor the status section",
        ),
    }
}

/// The form a class opens its journal in: the full class in Pro, every other
/// in the light form (spec v2 §9).
fn opening_form(class: Class) -> Mode {
    if class == Class::Heavy {
        Mode::Pro
    } else {
        Mode::Local
    }
}

/// An anchor of a kind the verifier's reader does not read is a refusal here:
/// the export claims a bound, and a bound nobody read is not one.
fn read_anchor(a: &Attestation, exp: &Expected<'_>) -> Result<Timestamp, String> {
    if !exp.anchors.handles(&a.kind) {
        return Err(format!("no reader for the anchor kind {}", a.kind.as_str()));
    }
    exp.anchors
        .verify(a)
        .map_err(|e| format!("the anchor does not hold: {e}"))
}

fn bound(x: &BoundExport, exp: &Expected<'_>, profile: &Profile) -> Report {
    let no = |r: String| Report::rejected(Some(Form::Bound), r);
    if x.seal.container != exp.container {
        return no("the journal is of another container".into());
    }
    // The first agent is the one the verifier knows: its keys are pinned in
    // page 0, and they must be keys the verifier accepts.
    let Some(Body::Opening { agent, mode, .. }) = x.pages.first().map(|p| &p.body) else {
        return no("no page 0".into());
    };
    if let Some(k) = agent.keys.iter().find(|k| exp.keys.get(&k.kid) != Some(*k)) {
        return no(format!(
            "page 0 pins a key the verifier does not accept: {}",
            k.kid.as_str()
        ));
    }
    if let Err(e) = named_by_its_key(agent, exp) {
        return no(e);
    }
    if *mode != opening_form(exp.class) {
        return no(format!(
            "a {:?} container opens its journal {:?}, not {mode:?}",
            exp.class,
            opening_form(exp.class)
        ));
    }
    if exp.class == Class::Bare && !x.anchors.is_empty() {
        return no("the base class is never anchored".into());
    }
    // Every anchor must be of a kind the reader reads: the core skips a kind
    // nobody reads (§7.2 item 3), and a verifier that let that pass would
    // accept a Pro journal whose anchors nobody looked at.
    for a in &x.anchors {
        if !exp.anchors.handles(&a.anchor.kind) {
            return no(format!(
                "record {}: no reader for the anchor kind {}",
                a.batch,
                a.anchor.kind.as_str()
            ));
        }
    }
    let (r, bounds) = match verify_bound_read(x, profile, Some(exp.anchors)) {
        Ok(v) => v,
        Err(e) => return no(e.to_string()),
    };
    let bounds: Vec<Bound> = bounds
        .into_iter()
        .filter_map(|b| {
            b.not_after.map(|t| Bound {
                record: b.batch,
                not_after: t.as_str().to_owned(),
            })
        })
        .collect();
    Report {
        accepted: true,
        form: Some(Form::Bound),
        reason: None,
        pages: Some(x.pages.len() as u64),
        counter: Some(r.number),
        author: Some(r.agent.id.as_str().to_owned()),
        anchored_at: None,
        bounds,
        limits: vec![
            "who holds the keys is not established here",
            "whether the container is still in force (not deleted since) is a question about current state",
            "page content is shown as exported; a digest proves only that content of that shape existed",
            "pages outside the runs are not anchored: their state is fixed by the seal, and they have no force (CH-25)",
        ],
        channel: None,
        journal_form: Some(r.mode),
        runs: Some(r.runs),
        first_agent: Some(agent.id.as_str().to_owned()),
        transfers: r.transfers,
        on_base: None,
            complete: false,
    }
}

/// Г-1: the agent that signs the pages is named by the `did:key` of the key it
/// signs under — the group key of its two halves, computed from the key
/// itself, so that no registry and no trusted party is needed to tell one
/// client agent from another.
///
/// A name that is not that string is refused: a `kid` is a name, and anyone
/// can generate a key and call it `did:key:zClient`. Only a key the party
/// holds and the verifier accepts makes the name a claim.
///
/// Skipped when the verifier does not ask for it ([`Expected::client_id_from_key`]),
/// for the older vectors whose names are stand-ins.
fn named_by_its_key(party: &Party, exp: &Expected<'_>) -> Result<(), String> {
    if !exp.client_id_from_key {
        return Ok(());
    }
    let mut ed25519 = 0usize;
    for k in &party.keys {
        if k.alg != Alg::Ed25519 {
            continue;
        }
        ed25519 += 1;
        if !ksg_core_v2::crypto::did_key::names(&party.id, k) {
            let did = ksg_core_v2::crypto::did_key::of_public(k)
                .map_err(|e| format!("the agent's key has no did:key: {e}"))?;
            return Err(format!(
                "the pages are authored by {}, but the key it signs under is {did} (Г-1)",
                party.id.as_str()
            ));
        }
    }
    if ed25519 == 0 {
        return Err(format!(
            "{}: no Ed25519 key to name the agent by (Г-1)",
            party.id.as_str()
        ));
    }
    Ok(())
}

/// The agent as the verifier knows it: its accepted keys, all of one party.
fn agent_of(keys: &KeySet) -> Result<Party, String> {    let first = keys.keys().next().ok_or("keys: the set is empty")?;
    let id = first.kid.as_str().split('#').next().unwrap_or_default();
    let party = Party {
        id: Uri::parse(id).map_err(|e| format!("keys: {e}"))?,
        keys: keys.keys().cloned().collect(),
    };
    if !party.is_consistent() {
        return Err("keys: not all of one agent".into());
    }
    Ok(party)
}

fn bound_point(p: &BoundPoint, exp: &Expected<'_>, profile: &Profile) -> Report {
    let no = |r: String| Report::rejected(Some(Form::BoundPoint), r);
    let agent = match agent_of(&exp.keys) {
        Ok(a) => a,
        Err(e) => return no(e),
    };
    if let Err(e) = named_by_its_key(&agent, exp) {
        return no(e);
    }
    if let Err(e) = verify_bound_point(p, &exp.container, &agent, profile) {
        return no(e.to_string());
    }
    let anchored_at = match &p.anchor {
        None => None,
        Some(a) => {
            // The same one rule as for a whole journal (spec v2 §7.2).
            let subject = match p.seal.hash() {
                Ok(h) => h,
                Err(e) => return no(e.to_string()),
            };
            if let Err(e) = read_anchor(a, exp) {
                return no(e);
            }
            match ksg_core_v2::anchor::upper_bound(
                core::slice::from_ref(a),
                &subject,
                profile,
                Some(exp.anchors),
            ) {
                Ok(Some(t)) => Some(t.as_str().to_owned()),
                Ok(None) => return no("the seal's anchor gives no bound".into()),
                Err(e) => return no(e.to_string()),
            }
        }
    };
    Report {
        accepted: true,
        form: Some(Form::BoundPoint),
        reason: None,
        pages: Some(1),
        counter: Some(p.page.seq),
        author: Some(agent.id.as_str().to_owned()),
        anchored_at,
        bounds: Vec::new(),
        limits: vec![
            "the page is under the movable seal of this container; what came before it is shown only by the whole export",
            "the anchor, if any, is of the movable seal; whether the page's own record was anchored is shown only by the whole export (CH-25)",
            "who holds the keys is not established here",
        ],
        channel: None,
        journal_form: Some(p.seal.mode),
        runs: None,
        first_agent: None,
        transfers: Vec::new(),
        on_base: None,
            complete: false,
    }
}

fn statuses(x: &StatusExport, exp: &Expected<'_>, profile: &Profile) -> Report {
    let no = |r: String| Report::rejected(Some(Form::Statuses), r);
    for (r, a) in &x.records {
        if !exp.anchors.handles(&a.kind) {
            return no(format!(
                "status record {}: no reader for the anchor kind {}",
                r.number,
                a.kind.as_str()
            ));
        }
    }
    let report = match ksg_core_v2::section::verify_status_export(
        x,
        &exp.keys,
        profile,
        Some(exp.anchors),
    ) {
        Ok(r) => r,
        Err(e) => return no(e.to_string()),
    };
    let mut bounds = Vec::new();
    for (n, t) in report.times.iter().enumerate() {
        match t {
            Some(t) => bounds.push(Bound {
                record: n as u64,
                not_after: t.as_str().to_owned(),
            }),
            None => return no(format!("status record {n}: its anchor gives no bound")),
        }
    }
    Report {
        accepted: true,
        form: Some(Form::Statuses),
        reason: None,
        pages: Some(x.records.len() as u64),
        counter: Some(u64::from(report.current.number())),
        author: None,
        anchored_at: None,
        bounds,
        limits: vec![
            "that this is the latest status needs the network: a later record may exist after the export",
            "who holds the issuer's keys is not established here",
        ],
        channel: None,
        journal_form: None,
        runs: None,
        first_agent: None,
        transfers: Vec::new(),
        on_base: None,
            complete: false,
    }
}

/// Reads a key set from JSON: an array of `{"kid", "alg", "key"}` objects.
///
/// # Errors
///
/// A message when the bytes are not such an array.
pub fn keys_from_json(bytes: &[u8]) -> Result<KeySet, String> {
    let keys: Vec<PublicKey> = serde_json::from_slice(bytes).map_err(|e| format!("keys: {e}"))?;
    if keys.is_empty() {
        return Err("keys: the set is empty".into());
    }
    Ok(keys.into_iter().collect())
}
