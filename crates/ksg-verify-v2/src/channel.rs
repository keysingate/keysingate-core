//! The channel a container came through. Item P-8 of the MVP plan.
//!
//! A container is not printed out of nothing: the issuer declared a release,
//! granted a range of it to a distributor (who may grant part of that to its
//! own agents, four levels at most), a packet of serials was sold from that
//! range to a holder, an agent was bound to the packet, and the container was
//! initiated on one serial of it. Every step is a signed document of the
//! frozen core; this module walks them in order and ties the last one to the
//! container identifier the verifier holds.
//!
//! | Step | Document | Signed by | Checked here |
//! |---|---|---|---|
//! | release | `Emission` | the issuer | its keys are among the keys the verifier trusts as the issuer's |
//! | grants | `Delegation` × 0…5 | the grantor | `resolve`: nesting, depth ≤ 4, term, parent hashes |
//! | packet | `BlockAllocation` | the last grantee (or the issuer) | signed by the keys the chain grants; the block inside the granted range |
//! | binding | `AgentBinding` | the agent and the packet's holder | the agent is bound to exactly this block, by the key the packet was sold to; one binding per packet, every container of it initiated under the same one |
//! | initiation | `ContainerInit` | the container's client key and one more party | the serial is in the block; the identifier is derived from it; initiated within the packet's lifetime, lengthened +10% per channel level |
//!
//! # Whose packet it is (KS-5)
//!
//! The core names the holder by an opaque URI. The seller writes the buyer's
//! public key into that URI — [`holder_uri`], `urn:ksg:holder:ed25519:<key>` —
//! and signs it with the packet, so the key is pinned by the seller's
//! signature, not by whoever presents the bundle. Of the keys the bundle
//! carries, only the one whose material is the pinned key counts. A copy of
//! someone else's sale does not help: binding the packet takes the pinned
//! key's signature, and only the buyer holds its secret.
//!
//! # The closing statement (audit of 30.09, Ya-7)
//!
//! When the packet is closed, the holder signs a `BlockClosure`: which serials
//! were used and submitted, which used and not submitted, which cancelled.
//! A bundle may carry it. Then the verifier checks it is of this packet,
//! signed by the holder the packet pins, partitions the packet exactly, and
//! does **not** cancel this container's serial — a container on a cancelled
//! serial is a container its own holder disowned. Without one, the report
//! says that the packet's completeness is not established.
//!
//! # What it does not establish
//!
//! One bundle proves one serial was used once *in this bundle*; that nobody
//! else bound the same block is `check_binding_uniqueness`'s question, which
//! needs the other bindings.

use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{Alg, KeySet, Profile, PublicKey};
use ksg_core_v2::doc::{
    resolve, AgentBinding, BlockAllocation, BlockClosure, Class, ContainerInit, Delegation,
    Emission,
};
use serde::{Deserialize, Serialize};

/// The `type` of a channel bundle.
pub const CHANNEL_TYPE: &str = "ChannelProof";

/// How a packet's holder names its key: this prefix, then the Ed25519 public
/// key in base64url, as `PublicKey::key` carries it.
pub const HOLDER_PREFIX: &str = "urn:ksg:holder:ed25519:";

/// The holder URI a packet is sold to, for the buyer's `key`.
///
/// # Errors
///
/// A key that is not Ed25519: the holder signs the binding with an Ed25519 key.
pub fn holder_uri(key: &PublicKey) -> Result<String, String> {
    if key.alg != Alg::Ed25519 {
        return Err("the holder's key must be Ed25519".into());
    }
    Ok(format!("{HOLDER_PREFIX}{}", key.key))
}

/// The key material a holder URI pins, if it is one.
#[must_use]
pub fn holder_key(holder: &str) -> Option<&str> {
    holder.strip_prefix(HOLDER_PREFIX).filter(|k| {
        !k.is_empty()
            && k.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    })
}

/// Every document from the release to the container, in one file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelProof {
    /// Always [`CHANNEL_TYPE`].
    #[serde(rename = "type")]
    pub doc_type: String,
    /// The release.
    pub emission: Emission,
    /// The grants, outermost first; empty when the issuer sold the packet itself.
    pub chain: Vec<Delegation>,
    /// The packet.
    pub packet: BlockAllocation,
    /// The packet holder's keys as presented; only the one the packet pins
    /// counts (see the module note).
    pub holder_keys: Vec<PublicKey>,
    /// The agent bound to the packet.
    pub binding: AgentBinding,
    /// The initiation of the container.
    pub init: ContainerInit,
    /// The packet's closing statement, once the holder has signed one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closure: Option<BlockClosure>,
}

/// What a channel check established.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChannelReport {
    /// The release.
    pub release: String,
    /// The container's serial.
    pub serial: u64,
    /// The packet's class — what the container's export must be checked as.
    pub class: Class,
    /// Who holds the packet.
    pub holder: String,
    /// The grantees, outermost first: the distributor, then its agents.
    pub channel: Vec<String>,
    /// The client key the container was initiated with.
    pub agent: String,
    /// A test release: signed with public test keys, of no force
    /// ([`crate::testkeys`]).
    pub test: bool,
    /// The packet's closing statement was presented and holds: the packet is
    /// accounted for serial by serial, and this container's serial is among
    /// the used ones.
    pub closed: bool,
}

/// Walks the channel and ties it to `container`.
///
/// `issuer_keys` are the verifier's own: the keys it trusts as the issuer's.
/// `client_keys` are the keys it checks the pages with; the agent the
/// container was initiated for must be among them, or the pages and the
/// channel would be about two different clients.
///
/// # Errors
///
/// The first step that does not hold, in words.
pub fn verify_channel(
    p: &ChannelProof,
    container: &Hash,
    issuer_keys: &KeySet,
    client_keys: &KeySet,
) -> Result<ChannelReport, String> {
    let profile = Profile::default();
    if p.doc_type != CHANNEL_TYPE {
        return Err("not a channel bundle".into());
    }
    // The release: signed by its own keys, and those are the issuer's.
    p.emission
        .validate(&profile)
        .map_err(|e| format!("release: {e}"))?;
    if p.emission
        .keys
        .iter()
        .any(|k| issuer_keys.get(&k.kid) != Some(k))
    {
        return Err("release: signed by keys the verifier does not hold as the issuer's".into());
    }
    let emission_keys: KeySet = p.emission.keys.iter().cloned().collect();

    // The grants, and the keys they hand down.
    let (granted, range) = resolve(&p.emission, &p.chain, &emission_keys, &profile)
        .map_err(|e| format!("channel: {e}"))?;

    // The packet: signed by those keys, inside that range. `is_first_block`
    // is taken as true: whether the holder had a packet before, and closed
    // it, is the grantor's ledger, not something one bundle can show.
    p.packet
        .validate(&p.emission, true, None, &granted, &profile)
        .map_err(|e| format!("packet: {e}"))?;
    if p.packet.block.from < range.from || p.packet.block.to > range.to {
        return Err("packet: outside the range the channel granted".into());
    }

    // The agent, bound to the packet by itself and the holder — the holder
    // the seller signed into the packet, not whoever presents the bundle.
    let pinned = holder_key(p.packet.holder.as_str())
        .ok_or("packet: the holder names no key, so nobody can be shown to hold it")?;
    let holder_keys: KeySet = p
        .holder_keys
        .iter()
        .filter(|k| k.alg == Alg::Ed25519 && k.key == pinned)
        .cloned()
        .collect();
    if holder_keys.is_empty() {
        return Err("binding: not by the key the packet was sold to".into());
    }
    p.binding
        .validate(&p.packet, &holder_keys, &profile)
        .map_err(|e| format!("binding: {e}"))?;

    // The initiation, within the packet's lifetime lengthened per level.
    let depth = u8::try_from(p.chain.len()).map_err(|_| "channel: too long")?;
    let mut init_keys = holder_keys.clone();
    init_keys.insert(p.binding.agent.clone());
    for k in client_keys.keys() {
        init_keys.insert(k.clone());
    }
    p.init
        .validate(&p.emission, &p.binding, depth, &init_keys, &profile)
        .map_err(|e| format!("initiation: {e}"))?;
    // `ContainerInit::validate` compares emission and block with the binding
    // it is given, not the hash it carries; the hash is what ties this
    // initiation to this binding and no other.
    let bh = ksg_core_v2::canonical::doc_hash(&p.binding).map_err(|e| format!("binding: {e}"))?;
    if p.init.binding != bh {
        return Err("initiation: names another binding".into());
    }
    if client_keys.get(&p.init.agent.kid) != Some(&p.init.agent) {
        return Err("initiation: the agent is not the key the pages are checked with".into());
    }
    if p.init.container != *container {
        return Err("initiation: of another container".into());
    }
    if let Some(c) = &p.closure {
        check_closure(c, &p.packet, &holder_keys, p.init.serial, &profile)?;
    }

    Ok(ChannelReport {
        release: p.emission.id.clone(),
        serial: p.init.serial.0,
        class: p.packet.class,
        holder: p.packet.holder.as_str().to_owned(),
        channel: p
            .chain
            .iter()
            .map(|d| d.delegate.as_str().to_owned())
            .collect(),
        agent: p.init.agent.kid.as_str().to_owned(),
        test: crate::testkeys::is_test_release(&p.emission),
        closed: p.closure.is_some(),
    })
}

/// The closing statement against the packet it closes (audit of 30.09, Ya-7).
fn check_closure(
    c: &BlockClosure,
    packet: &BlockAllocation,
    holder_keys: &KeySet,
    serial: ksg_core_v2::doc::Serial,
    profile: &Profile,
) -> Result<(), String> {
    if c.emission != packet.emission || c.block != packet.block {
        return Err("closure: of another packet".into());
    }
    c.validate(packet.class, holder_keys, profile)
        .map_err(|e| format!("closure: {e}"))?;
    if c.cancelled.iter().any(|r| r.contains(serial)) {
        return Err(format!(
            "closure: the holder cancelled serial {serial}, the one this container was initiated on"
        ));
    }
    Ok(())
}
