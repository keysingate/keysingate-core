//! Path A's lookup, from the chain itself: [`ChainRegistry`].
//!
//! `[decision]` 13.09 (§4, path A): a disclosure counts when the request is
//! signed by an owner key **already present in a chain**. The desk asks a
//! [`Registry`] two things about the keys that signed: are they in a chain,
//! and what is the status of the container they belong to (finding 6: a key
//! in a chain is forever, rights are not).
//!
//! # Where the answer comes from
//!
//! From the owner-watcher's own documents, checked here, not from its word:
//!
//! | It presents | Checked by | What it establishes |
//! |---|---|---|
//! | its container's channel bundle (`ChannelProof`) | `ksg_verify_v2::channel::verify_channel` against the issuer's keys the service holds | the release, the grants, the packet, the binding and the initiation are the issuer's chain — and the packet's **holder key** is in it |
//! | its container's status section (`StatusExport`) | `ksg_core_v2::section::verify_status_export`, anchors read when a reader is given | the container's current status, signed by the issuer |
//!
//! The owner-watcher is the packet's holder: the key the seller pinned in
//! the packet is the one organization the chain names as having bought it.
//!
//! # What it cannot establish, and the bound on it
//!
//! A status section shows the status **as of its last record**. A watcher
//! whose container moved on — exported, its key lost — could present an
//! older section. The registry does not trust a standing forever: an entry
//! is good for `max_age_ms` after it was checked, then the watcher presents
//! its section again. Reading the chain for a later record would close it
//! fully, but status memos are found through the payer's account, which the
//! section does not name.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use ksg_core_v2::anchor::AttestationVerifier;
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{Alg, KeySet, Profile, PublicKey};
use ksg_core_v2::section::{verify_status_export, StatusExport};
use ksg_core_v2::status::Status;
use ksg_verify_v2::channel::{holder_key, verify_channel, ChannelProof};

use crate::desk::Registry;

/// How long a checked standing holds by default: one day.
pub const DEFAULT_MAX_AGE_MS: u64 = 24 * 60 * 60 * 1000;

/// The most owner-watchers the registry keeps.
pub const MAX_ENTRIES: usize = 1_000_000;

/// One owner-watcher's standing, as last checked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Standing {
    /// The owner-watcher's key: the packet's holder key.
    pub owner: PublicKey,
    /// Its container.
    pub container: Hash,
    /// Its container's status when checked.
    pub status: Status,
    /// When checked, in the service's milliseconds.
    pub checked_ms: u64,
}

/// Why a registration was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegistryError {
    /// The channel bundle does not verify against the issuer's keys.
    #[error("channel: {0}")]
    Channel(String),
    /// The status section does not verify, or is of another container.
    #[error("status section: {0}")]
    Statuses(String),
    /// The registry is full.
    #[error("the registry is full")]
    Full,
}

/// The registry. Its entries serialize; the issuer's keys do not — they are
/// the service's configuration, given at start.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainRegistry {
    #[serde(skip)]
    issuer_keys: KeySet,
    max_age_ms: u64,
    /// key material (Ed25519, base64url) → standing.
    entries: BTreeMap<String, Standing>,
}

impl ChainRegistry {
    /// An empty registry trusting `issuer_keys` as the issuer's.
    #[must_use]
    pub fn new(issuer_keys: KeySet, max_age_ms: u64) -> Self {
        Self {
            issuer_keys,
            max_age_ms,
            entries: BTreeMap::new(),
        }
    }

    /// Gives a registry read back from disk the issuer's keys and the age
    /// limit of the running configuration.
    pub fn configure(&mut self, issuer_keys: KeySet, max_age_ms: u64) {
        self.issuer_keys = issuer_keys;
        self.max_age_ms = max_age_ms;
    }

    /// Checks an owner-watcher's documents and records its standing.
    ///
    /// `reader` reads the status records' anchors; without one the status is
    /// taken from the issuer's signatures alone.
    ///
    /// # Errors
    ///
    /// [`RegistryError`]: what did not verify.
    pub fn register(
        &mut self,
        channel: &ChannelProof,
        statuses: &StatusExport,
        reader: Option<&dyn AttestationVerifier>,
        now_ms: u64,
    ) -> Result<Standing, RegistryError> {
        let container = channel.init.container;
        let client: KeySet = [channel.init.agent.clone()].into_iter().collect();
        verify_channel(channel, &container, &self.issuer_keys, &client)
            .map_err(RegistryError::Channel)?;
        if statuses.emission != channel.init.emission || statuses.serial != channel.init.serial {
            return Err(RegistryError::Statuses(
                "of another container than the channel's".into(),
            ));
        }
        let report = verify_status_export(statuses, &self.issuer_keys, &Profile::default(), reader)
            .map_err(|e| RegistryError::Statuses(e.to_string()))?;
        let pinned = holder_key(channel.packet.holder.as_str())
            .ok_or_else(|| RegistryError::Channel("the packet names no holder key".into()))?;
        let owner = channel
            .holder_keys
            .iter()
            .find(|k| k.alg == Alg::Ed25519 && k.key == pinned)
            .cloned()
            .ok_or_else(|| RegistryError::Channel("the holder's key is not presented".into()))?;
        if self.entries.len() >= MAX_ENTRIES && !self.entries.contains_key(&owner.key) {
            return Err(RegistryError::Full);
        }
        let standing = Standing {
            owner: owner.clone(),
            container,
            status: report.current,
            checked_ms: now_ms,
        };
        self.entries.insert(owner.key, standing.clone());
        Ok(standing)
    }

    /// Drops the standings older than the age limit at `now_ms`; how many.
    pub fn prune(&mut self, now_ms: u64) -> usize {
        let before = self.entries.len();
        let age = self.max_age_ms;
        self.entries
            .retain(|_, s| now_ms.saturating_sub(s.checked_ms) <= age);
        before - self.entries.len()
    }

    /// How many owner-watchers are registered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether none is.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Registry for ChainRegistry {
    fn standing(&self, owner: &[PublicKey], now_ms: u64) -> Option<Status> {
        // Every key that signed must be the registered holder key itself —
        // matched by key material, never by `kid`, which anyone may write.
        let mut found: Option<&Standing> = None;
        for k in owner {
            let s = self.entries.get(&k.key)?;
            if k.alg != s.owner.alg || now_ms.saturating_sub(s.checked_ms) > self.max_age_ms {
                return None;
            }
            match found {
                Some(f) if f.container != s.container => return None,
                _ => found = Some(s),
            }
        }
        found.map(|s| s.status)
    }
}
