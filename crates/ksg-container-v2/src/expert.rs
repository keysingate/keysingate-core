//! A court-appointed expert, and the compulsory disclosure. `[decision]` 11.09.
//!
//! This is path B-2, the one the voluntary mechanism did not cover: a technical
//! expert-arbiter **appointed by a court**, or the case sent out for independent
//! examination.
//!
//! # The sequence
//!
//! | | Who | What |
//! |---|---|---|
//! | 1 | the client and/or the owner | enter the appointed expert's key **in the journal** |
//! | 2 | the expert | makes their own record **in the chain**: the parameters and their public key |
//! | 3 | the client **and** the owner | perform the disclosure **for that expert** — partial or full |
//!
//! # The property worth naming: the court compels the people, not the box
//!
//! Step 3 is still done **by the principals**. There is no route by which a
//! court order, or anyone holding one, extracts anything from a container by
//! itself — the container has no such button, and this does not add one.
//!
//! That is not a loophole. A container that could be opened by a sufficiently
//! official-looking demand is a container whose contents are available to
//! whoever can forge one, and the whole difficulty of §3 was that the container
//! cannot tell a real court from a convincing one. So it does not try. Refusal
//! to comply stays a matter between the principals and the court, where it
//! already was, and the container stops being the place to attack.
//!
//! # Why the expert's own chain record matters
//!
//! The key entered in the journal is what the **principals** say the expert's
//! key is. The record in the chain is what the **expert** says. Both are needed
//! and neither substitutes for the other:
//!
//! * without the journal entry, anyone with a chain record could present
//!   themselves as the appointed expert;
//! * without the chain record, the principals alone decide who the expert was,
//!   and could name a key they control — which is exactly the objection the
//!   voluntary mechanism answered with two arbiters.
//!
//! It is the same shape as identification by agreement, with the parties being
//! the principals on one side and the expert on the other.

use serde::{Deserialize, Serialize};

use ksg_core_v2::anchor::Attestation;
use ksg_core_v2::canonical::{check_envelope, doc_hash, Signable};
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{KeySet, Profile, PublicKey, SignatureSet};
use ksg_core_v2::doc::Uri;

use ksg_core_v2::journal::BoundPage;

use crate::voluntary::GateError;

/// The content type of the journal page that names the appointed expert:
/// it carries the [`ExpertEntry`]'s digest, or the entry itself.
pub const EXPERT_ENTRY_PAGE: &str = "urn:ksg:page:expert-entry:v1";

/// What a journal page naming `entry` may carry: its digest, or the entry in
/// its canonical bytes.
///
/// # Errors
///
/// [`GateError::Canonicalization`] if the entry does not canonicalise.
pub fn entry_pieces(entry: &ExpertEntry) -> Result<[ksg_core_v2::journal::Piece; 2], GateError> {
    use ksg_core_v2::journal::Piece;
    Ok([
        Piece::Digest(doc_hash(entry).map_err(|_| GateError::Canonicalization)?),
        Piece::Inline(
            ksg_core_v2::canonical::canonical_bytes(entry)
                .map_err(|_| GateError::Canonicalization)?,
        ),
    ])
}

/// Step 1 — the principals name the appointed expert, in the journal.
///
/// Written by the client and/or the owner. "And/or" is the owner's wording and
/// it is kept: either principal may name the expert, since a court order binds
/// each of them separately and waiting for the other would let one of them stall
/// the appointment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpertEntry {
    /// Always [`ksg_core_v2::doc::CONTEXT`] (spec v2 §3.3).
    #[serde(rename = "@context")]
    pub context: ksg_core_v2::doc::Context,
    /// Always `"ExpertEntry"`.
    #[serde(rename = "type")]
    pub doc_type: String,
    /// The major core version.
    pub v: u32,
    /// The container under examination.
    pub container: Hash,
    /// The appointed expert's key, as the principals give it.
    pub expert: PublicKey,
    /// What appointed them — a case number, an order, an instruction. Opaque to
    /// the container, which is not in a position to read a court's paperwork.
    pub appointment: String,
    /// The client's or the owner's signature.
    pub signatures: SignatureSet,
}

impl Signable for ExpertEntry {
    const DOC_TYPE: &'static str = "ExpertEntry";
}

/// Step 2 — the expert's own record, published in the chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpertRecord {
    /// Always [`ksg_core_v2::doc::CONTEXT`] (spec v2 §3.3).
    #[serde(rename = "@context")]
    pub context: ksg_core_v2::doc::Context,
    /// Always `"ExpertRecord"`.
    #[serde(rename = "type")]
    pub doc_type: String,
    /// The major core version.
    pub v: u32,
    /// The container under examination.
    pub container: Hash,
    /// The expert's public key, as the expert gives it.
    pub expert: PublicKey,
    /// The parameters of the examination, as the expert states them.
    pub parameters: String,
    /// **How much the expert requires** — the path of the compulsory disclosure.
    ///
    /// `[decision]` 12.09, the owner: "The path for a forced unload is set by logic, by the arbiter
    /// or the expert." So it is stated **here**, in the record the expert signs
    /// and the chain carries, and not in the command the principals sign.
    ///
    /// The reason it belongs on this side: a party under examination choosing
    /// how much of itself is examined is not an examination. Leaving the scope
    /// with the principals would let them answer a demand for everything with
    /// three named pages, and the expert would have no way to say that this was
    /// not what was asked — a court reading the result would think it saw all it
    /// ordered.
    ///
    /// It is public and dated for the same reason the demand is answerable for:
    /// an expert cannot afterwards enlarge what they required, and the
    /// principals cannot afterwards shrink it.
    pub demanded: Scope,
    /// The expert's signature.
    pub signatures: SignatureSet,
}

impl Signable for ExpertRecord {
    const DOC_TYPE: &'static str = "ExpertRecord";
}

/// An expert established by both sides: named in the journal, self-declared in
/// the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppointedExpert {
    /// The expert's key, agreed by both routes.
    pub key: PublicKey,
    /// Who named them among the principals.
    pub named_by: Uri,
    /// What the expert says the examination is about.
    pub parameters: String,
    /// What the expert requires — set by the expert, executed by the
    /// principals. See [`ExpertRecord::demanded`].
    pub demanded: Scope,
}

/// Establishes the expert from the two records.
///
/// # Errors
///
/// [`GateError::Opening`] naming which part did not hold;
/// [`GateError::Signature`] if a signature does not verify.
pub fn establish(
    container: &Hash,
    entry: &ExpertEntry,
    record: &ExpertRecord,
    record_anchor: &Attestation,
    principals: &KeySet,
    profile: &Profile,
) -> Result<AppointedExpert, GateError> {
    if entry.container != *container || record.container != *container {
        return Err(GateError::Opening(
            "the appointment is of another container",
        ));
    }

    // What the principals say. Verified against the principals' keys: the entry
    // is only worth anything if one of them made it.
    check_envelope(
        entry,
        entry.v,
        &entry.doc_type,
        &entry.signatures,
        principals,
        profile,
    )
    .map_err(|_| GateError::Signature)?;
    let named_by = entry
        .signatures
        .as_slice()
        .first()
        .map(|s| s.kid.clone())
        .ok_or(GateError::Opening("the journal entry is not signed"))?;

    // What the expert says. Verified against the key the record itself carries —
    // self-attesting, like a binding: anyone may generate a key, and what this
    // establishes is that whoever published the record holds it.
    let mut own = KeySet::new();
    own.insert(record.expert.clone());
    check_envelope(
        record,
        record.v,
        &record.doc_type,
        &record.signatures,
        &own,
        profile,
    )
    .map_err(|_| GateError::Signature)?;

    // The chain must carry the expert's record, or "the expert declared
    // themselves" is a claim on paper rather than a public fact.
    let h = doc_hash(record).map_err(|_| GateError::Canonicalization)?;
    record_anchor
        .covers(&h)
        .map_err(|_| GateError::Opening("the anchor is of another expert record"))?;

    // The two sides must name the same key. This is the whole identification,
    // and disagreement is a failure rather than something to resolve.
    if entry.expert.key != record.expert.key {
        return Err(GateError::Opening(
            "the journal and the chain name different experts",
        ));
    }

    Ok(AppointedExpert {
        key: record.expert.clone(),
        named_by,
        parameters: record.parameters.clone(),
        demanded: record.demanded.clone(),
    })
}

/// Step 3 — the disclosure the principals perform for the expert.
///
/// **Both** of them, unlike the appointment: naming an expert is answering a
/// court, and either principal may be ordered to do it alone, but handing over
/// the contents is a disclosure of the container and takes the pair, as every
/// disclosure here does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpertDisclosure {
    /// Always [`ksg_core_v2::doc::CONTEXT`] (spec v2 §3.3).
    #[serde(rename = "@context")]
    pub context: ksg_core_v2::doc::Context,
    /// Always `"ExpertDisclosure"`.
    #[serde(rename = "type")]
    pub doc_type: String,
    /// The major core version.
    pub v: u32,
    /// The container under examination.
    pub container: Hash,
    /// The expert this is for.
    pub expert: PublicKey,
    /// Which pages, or all of them — and it must be **what the expert
    /// demanded**. The principals perform the disclosure; they do not size it.
    pub scope: Scope,
    /// The client's and the owner's signatures.
    pub signatures: SignatureSet,
}

impl Signable for ExpertDisclosure {
    const DOC_TYPE: &'static str = "ExpertDisclosure";
}

/// How much goes to the expert.
///
/// There is no third option, and that is a decision rather than an omission:
/// `[decision]` of 10.09 — "a disclosure cannot be made of a chunk; either a particular
/// event is shown, or everything". A **partial** disclosure is therefore a set
/// of **named** pages, not a range and not a filter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// The named pages, and nothing around them.
    Pages(Vec<u64>),
    /// Everything. **Kills the container** — status 7.
    Everything,
}

impl ExpertDisclosure {
    /// Verifies the command and returns what the expert is to receive.
    ///
    /// Takes the pages rather than the journal, because a full disclosure spends
    /// the journal and that is the caller's act, not this function's.
    ///
    /// # Errors
    ///
    /// [`GateError::Opening`] if it is of another container or another
    /// expert, or if both principals did not sign;
    /// [`GateError::NoSuchPage`] for a page that is not there;
    /// [`GateError::Signature`] if a signature does not verify.
    pub fn authorize<'a>(
        &self,
        container: &Hash,
        expert: &AppointedExpert,
        pages: &'a [BoundPage],
        client: &PublicKey,
        owner: &PublicKey,
        profile: &Profile,
    ) -> Result<Vec<&'a BoundPage>, GateError> {
        self.check(container, expert, client, owner, profile)?;
        match &self.scope {
            Scope::Everything => Ok(pages.iter().collect()),
            Scope::Pages(wanted) => wanted
                .iter()
                .map(|n| {
                    pages
                        .iter()
                        .find(|p| p.seq == *n)
                        .ok_or(GateError::NoSuchPage(*n))
                })
                .collect(),
        }
    }

    /// Verifies the command alone: this container, this expert, both
    /// principals signed, the scope the expert demanded. What is disclosed is
    /// the caller's to take — from the journal of pages or the bound one.
    ///
    /// # Errors
    ///
    /// As [`ExpertDisclosure::authorize`], less the page lookup.
    pub fn check(
        &self,
        container: &Hash,
        expert: &AppointedExpert,
        client: &PublicKey,
        owner: &PublicKey,
        profile: &Profile,
    ) -> Result<(), GateError> {
        if self.container != *container {
            return Err(GateError::Opening("the disclosure is of another container"));
        }
        if self.expert.key != expert.key.key {
            return Err(GateError::Opening(
                "the disclosure is for a different expert",
            ));
        }
        if client.kid == owner.kid {
            return Err(GateError::Opening("the client and the owner are one party"));
        }
        for k in [client, owner] {
            if !self.signatures.signed_by(&k.kid) {
                return Err(GateError::Opening(
                    "a disclosure to an expert takes both principals",
                ));
            }
        }
        let mut keys = KeySet::new();
        keys.insert(client.clone());
        keys.insert(owner.clone());
        check_envelope(
            self,
            self.v,
            &self.doc_type,
            &self.signatures,
            &keys,
            profile,
        )
        .map_err(|_| GateError::Signature)?;

        // `[decision]` 12.09: the path is set by the arbiter or the expert. The
        // principals execute it, so a command narrower — or wider — than the
        // anchored demand is not the disclosure that was ordered.
        if self.scope != expert.demanded {
            return Err(GateError::Opening(
                "the disclosure is not of the scope the expert demanded",
            ));
        }
        Ok(())
    }
}

/// Hands the expert the pages the principals signed for, each with its proof
/// under the movable seal.
///
/// Was `Binder::disclose_to_expert` in core v1's workspace. The expert's
/// documents are not core in v2 (spec v2 §17), so the disclosure lives here and
/// takes pages out through the core's door for the expert,
/// [`ksg_core_v2::journal::Binder::expert_pages`]: up to 24 pages per
/// disclosure, **outside** the twelve pointwise exports — `[decision]` 19.09
/// (CT-21) "the 13th goes through the export to the expert", confirmed 06.10.
///
/// # Errors
///
/// [`ksg_core_v2::journal::BinderError::Export`] for a command that does not hold or a scope of
/// everything (that goes by the full export, E-11);
/// [`ksg_core_v2::journal::BinderError::PageCount`] for no page, more than 24 or one twice;
/// [`ksg_core_v2::journal::BinderError::NoSuchPage`] for a page that is not there.
pub fn disclose(
    journal: &mut ksg_core_v2::journal::Binder,
    expert: &AppointedExpert,
    disclosure: &ExpertDisclosure,
    client: &PublicKey,
    owner: &PublicKey,
    profile: &Profile,
) -> Result<Vec<ksg_core_v2::journal::BoundPoint>, ksg_core_v2::journal::BinderError> {
    use ksg_core_v2::journal::BinderError;
    let container = *journal.container();
    disclosure
        .check(&container, expert, client, owner, profile)
        .map_err(|_| BinderError::Export("the expert's disclosure does not hold"))?;
    let Scope::Pages(wanted) = &disclosure.scope else {
        return Err(BinderError::Export(
            "everything goes by the full export (E-11), not by a disclosure",
        ));
    };
    journal.expert_pages(wanted)
}
