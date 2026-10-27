//! The identity layer, and publishing an agent's ID. KS-8 C-4, C-10, C-11.
//!
//! # Two things in one zone, opened by different people
//!
//! C-4 lays them down **together** and encrypts them **differently**, and that
//! asymmetry is the design rather than an implementation detail:
//!
//! | | encrypted under | who can open it |
//! |---|---|---|
//! | **the identity's ID** | the chain's last key | the owner, at an export, **under an anchor** |
//! | **the identity itself** | the identity's **own** key | **only it** |
//!
//! So an owner can be made to say *which* identity a container belongs to, and
//! cannot expose *who* that identity is. A court can reach the address; it
//! cannot reach the person through the container. That is the whole point of
//! keeping the two apart, and it is why there is **no function here that
//! discloses the identity** — the absence is the guarantee, as it is for the
//! journal's pages.
//!
//! # Inside the container there are only hashes
//!
//! C-10: the open ID is published **in the chain** and **in the artifact**; the
//! container records `hash(artifact) + hash(agent ID)`. It stays opaque, and only
//! the declaration is public.
//!
//! A hash here is **a way to refer, not a way to hide** (C-11): the ID is
//! already open, so the hash resolves and the addressee is unambiguous.
//!
//! # The order is a checkable condition, not advice
//!
//! ```text
//! 1. the agent's ID is published in the chain, WITH AN ANCHOR
//! 2. the ID is published in the artifact itself — like a signature on a painting
//! 3. only then does the container record hash(artifact) + hash(agent ID)
//! ```
//!
//! **Step 3 without step 1 is refused**, and that is what [`OwnershipClaim`]
//! enforces.
//!
//! **Step 2 the container cannot check, and pretending otherwise would be
//! worse than admitting it.** Nothing here can see inside a file, and a
//! signature in an artifact is *a pointer, not a proof* — which is exactly where
//! C2PA breaks, its manifest being bound to the file and lost on editing. So the
//! rule about the artifact belongs to the layer that handles artifacts, and this
//! module says so rather than implying a check it does not make.
//!
//! # One ID per container
//!
//! `[decision] 12.09` The ID binds to the **container**, of the units the model has.
//!
//! Since a container's identifier is derived from its artifact among other
//! things, one container holds exactly one artifact — a second artifact would be
//! a second container. So "per container" and "per artifact" are the same rule,
//! and the choice is between that and an ID spanning an agent's whole working
//! life.
//!
//! | | |
//! |---|---|
//! | **kept** | reachability. A claim still has an address |
//! | **gained** | two containers of one agent are not linkable through their IDs |
//! | **paid** | reputation accumulates per container, since correlation and accumulated reputation are one quantity seen from two sides |
//!
//! # Why the rule exists at all
//!
//! The owner's analogy: filing a claim. A copy goes to the court, and a copy
//! goes **to the party being sued**. An agent has no address and no other
//! particulars — only an ID. Publishing it *is* that address.
//!
//! Rights without reachability are rights without responsibility. Wanting to
//! own publicly and wanting not to be found are the two halves this rule refuses
//! to allow at once.

use ksg_core_v2::anchor::Attestation;
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{KeySet, Profile, PublicKey, SignatureSet};
use ksg_core_v2::doc::Uri;

/// Separates an agent-ID digest from every other hash in the protocol.
const ID_DOMAIN: &[u8] = b"ksg:agent-id:v1";

/// The digest by which a published ID is referred to.
///
/// One function, used by the claim inside the container and by a challenge in
/// the chain alike, so that the two cannot disagree about what hashing an ID
/// means — the symmetry of C-11 depends on both sides computing the same value.
#[must_use]
pub fn id_hash(open_id: &str) -> Hash {
    Hash::sha256_fields(&[ID_DOMAIN, open_id.as_bytes()])
}

/// What can go wrong in the identity layer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdentityError {
    /// The ID was never published in the chain (C-10 step 1).
    #[error("the agent's ID is not published in the chain: ownership is not recorded without it")]
    NotPublished,
    /// The publication is of a different ID than the claim refers to.
    #[error("the published ID does not match the one claimed")]
    WrongId,
    /// The chain does not carry the publication.
    #[error("the publication is not anchored")]
    NotAnchored,
    /// The claim is about another container.
    #[error("the claim is of another container")]
    WrongContainer,
    /// A signature did not verify.
    #[error("a signature did not verify")]
    Signature,
    /// The disclosure of an identity ID came without its anchor.
    #[error("disclosing an identity ID happens under an anchor")]
    DisclosureNotAnchored,
}

/// An agent's ID, published openly — step 1 of C-10.
///
/// Published in the chain and therefore **irreversible**: an ID once out is not
/// withdrawn. That belongs in the terms of sale beside "a discarded key does not
/// come back", and the decision is one-sided — to be taken before, not after.
///
/// # One ID per container
///
/// `[decision] 12.09` The ID binds to the **container**. So a publication is *for* a
/// container, and the same open ID serving two of them is refused.
///
/// What that buys is the thing the whole fork was about: **two containers of one
/// agent are not linkable through their IDs**. Reachability is kept — a claim
/// still has an address — and it is an address for one container's work rather
/// than for everything the agent ever did.
///
/// What it costs is stated where it will be read: reputation accumulates **per
/// container**, since correlation and accumulated reputation are the same
/// quantity looked at from two sides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Publication {
    /// The container this ID was published for.
    pub container: Hash,
    /// The ID, in the open. Not a hash: the point of publishing is being
    /// readable.
    pub open_id: String,
    /// The agent's key, so that the publication is the agent's own act.
    pub agent: PublicKey,
    /// The signature over it.
    pub signatures: SignatureSet,
    /// The anchor putting it in the chain. **Not optional** — an unpublished ID
    /// is the whole thing the rule is against.
    pub anchor: Attestation,
}

impl Publication {
    /// The value a publication's anchor must attest.
    ///
    /// The container goes into the digest, so a publication cannot be moved to
    /// another container by reusing its anchor — which is what "one ID per
    /// container" would otherwise amount to in practice.
    #[must_use]
    pub fn subject(container: &Hash, open_id: &str, agent: &PublicKey) -> Hash {
        Hash::sha256_fields(&[
            b"ksg:agent-id:publication:v1",
            container.as_bytes(),
            open_id.as_bytes(),
            agent.key.as_bytes(),
        ])
    }

    /// Whether this publication really is in the chain and really is this
    /// agent's.
    ///
    /// # Errors
    ///
    /// [`IdentityError::NotAnchored`] if the anchor is of something else.
    pub fn validate(&self) -> Result<(), IdentityError> {
        self.anchor
            .covers(&Self::subject(&self.container, &self.open_id, &self.agent))
            .map_err(|_| IdentityError::NotAnchored)
    }

    /// The digest this publication answers to.
    #[must_use]
    pub fn id_hash(&self) -> Hash {
        id_hash(&self.open_id)
    }
}

/// A claim of ownership, as recorded **inside** the container — step 3 of C-10.
///
/// Two hashes and nothing else. The container stays opaque; what is public is the
/// declaration in the chain, not this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnershipClaim {
    /// The container this is recorded in.
    pub container: Hash,
    /// The artifact claimed.
    pub artifact: Hash,
    /// The claimant's published ID, by its digest.
    pub agent_id: Hash,
}

/// The content type of the journal page that records an [`OwnershipClaim`]
/// (C-10, step 3): its two hashes, artifact then agent ID.
pub const OWNERSHIP_CLAIM_PAGE: &str = "urn:ksg:page:ownership-claim:v1";

impl OwnershipClaim {
    /// What the page carries: the artifact's hash and the agent ID's hash,
    /// their multihash bytes one after the other — two hashes and nothing
    /// else.
    #[must_use]
    pub fn page_bytes(&self) -> Vec<u8> {
        let mut b = self.artifact.to_multihash().into_bytes();
        b.push(b'\n');
        b.extend_from_slice(self.agent_id.to_multihash().as_bytes());
        b
    }

    /// Accepts the claim, or refuses it for want of a publication.
    ///
    /// **Step 3 without step 1 is not accepted**, which is the condition C-10
    /// states and the reason this function takes a publication rather than
    /// trusting the claim.
    ///
    /// # Errors
    ///
    /// [`IdentityError::WrongContainer`], [`IdentityError::NotAnchored`],
    /// [`IdentityError::WrongId`] when the publication is of another ID.
    pub fn accept(&self, container: &Hash, published: &Publication) -> Result<(), IdentityError> {
        if self.container != *container {
            return Err(IdentityError::WrongContainer);
        }
        // `[decision]` 12.09: the ID binds to the container, so a publication made for
        // another one does not serve here — even a perfectly good one. Without
        // this the binding would be per container in the documentation and per
        // agent in practice.
        if published.container != *container {
            return Err(IdentityError::WrongContainer);
        }
        published.validate()?;
        if published.id_hash() != self.agent_id {
            return Err(IdentityError::WrongId);
        }
        Ok(())
    }
}

/// A challenge to ownership, as recorded **in the chain** — C-11.
///
/// The same shape as [`OwnershipClaim`] and a different place, and that is the
/// point: the right is recorded inside, the challenge outside, which is **why
/// the owner can neither hide it nor fail to notice it**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    /// The artifact contested.
    pub artifact: Hash,
    /// The challenger's published ID, by its digest.
    pub claimant_id: Hash,
    /// The anchor putting the challenge in the chain.
    pub anchor: Attestation,
}

impl Challenge {
    /// The value a challenge's anchor must attest.
    #[must_use]
    pub fn subject(artifact: &Hash, claimant_id: &Hash) -> Hash {
        Hash::sha256_fields(&[
            b"ksg:challenge:v1",
            artifact.as_bytes(),
            claimant_id.as_bytes(),
        ])
    }

    /// Whether the challenger named themselves as the rule requires.
    ///
    /// The threshold C-11 sets: **spoiling somebody's title anonymously is not
    /// possible**. A challenger must publish their own ID first, exactly as the
    /// owner had to.
    ///
    /// # Errors
    ///
    /// [`IdentityError::NotPublished`] if the challenger has not published;
    /// [`IdentityError::WrongId`] if the publication is of another ID;
    /// [`IdentityError::NotAnchored`] if the challenge is not in the chain.
    pub fn validate(&self, claimant: &Publication) -> Result<(), IdentityError> {
        claimant
            .validate()
            .map_err(|_| IdentityError::NotPublished)?;
        if claimant.id_hash() != self.claimant_id {
            return Err(IdentityError::WrongId);
        }
        self.anchor
            .covers(&Self::subject(&self.artifact, &self.claimant_id))
            .map_err(|_| IdentityError::NotAnchored)
    }
}

/// The owner disclosing **which** identity a container belongs to (C-4).
///
/// Under an anchor, always: a disclosure that left no trace would let an owner
/// be asked quietly and answer quietly, and the trace is what makes the demand
/// answerable for.
///
/// There is deliberately no counterpart for the identity **itself**. Only the
/// identity holds that key, and no function here takes it — which is the
/// guarantee, stated by absence rather than by a comment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdDisclosure {
    /// The container.
    pub container: Hash,
    /// The identity's ID, opened.
    pub open_id: String,
    /// The owner's signature over the disclosure.
    pub signatures: SignatureSet,
    /// The anchor. **Not optional.**
    pub anchor: Attestation,
}

impl IdDisclosure {
    /// The value a disclosure's anchor must attest.
    #[must_use]
    pub fn subject(container: &Hash, open_id: &str) -> Hash {
        Hash::sha256_fields(&[
            b"ksg:identity-disclosure:v1",
            container.as_bytes(),
            open_id.as_bytes(),
        ])
    }

    /// Verifies the disclosure against the hash the container holds.
    ///
    /// # Errors
    ///
    /// [`IdentityError::WrongContainer`],
    /// [`IdentityError::DisclosureNotAnchored`], [`IdentityError::WrongId`] if
    /// the opened ID does not hash to what the container recorded,
    /// [`IdentityError::Signature`] if the owner's signature fails.
    pub fn verify(
        &self,
        container: &Hash,
        recorded: &Hash,
        owner: &KeySet,
        profile: &Profile,
    ) -> Result<Uri, IdentityError> {
        if self.container != *container {
            return Err(IdentityError::WrongContainer);
        }
        self.anchor
            .covers(&Self::subject(container, &self.open_id))
            .map_err(|_| IdentityError::DisclosureNotAnchored)?;
        if &id_hash(&self.open_id) != recorded {
            return Err(IdentityError::WrongId);
        }
        let signer = self
            .signatures
            .as_slice()
            .first()
            .map(|s| s.kid.clone())
            .ok_or(IdentityError::Signature)?;
        self.signatures
            .verify(
                &Self::subject(container, &self.open_id).as_bytes()[..],
                owner,
                profile,
            )
            .map_err(|_| IdentityError::Signature)?;
        Ok(signer)
    }
}

/// Carrying an ID over from a container to its successor — E-14.
///
/// # Why this is not a contradiction of "one ID per container"
///
/// `[decision] 12.09` The ID binds to the container; `[decision]` (same day) it **carries over
/// to the successor, if that is feasible**. Both hold, and the reason they do is
/// that succession is *already public*.
///
/// The property paid for by binding per container is that two containers of one
/// agent are not linkable through their IDs. Under E-14 the link between A and B
/// is not a leak to be avoided — it is **the point of the operation**: the
/// issuer freezes A and couples B in front of it, and that coupling is anchored.
/// So re-using the ID for B discloses nothing the succession record does not
/// already say. The rule is kept where it earns something and lifted exactly
/// where it earns nothing.
///
/// # What it buys
///
/// A claim served on A's ID **reaches B**. Without the carry-over, the address
/// changes at the transplant: work continues in B while a claim sits against a
/// frozen archive. Rights without reachability were the thing C-10 was written
/// against, and losing reachability at succession would reintroduce it by the
/// back door.
///
/// # What is checked
///
/// | | |
/// |---|---|
/// | same **open ID** in both publications | otherwise nothing is being carried over |
/// | same **agent key** in both | an ID is not dragged onto a stranger's container |
/// | the two containers **differ** | a carry-over to itself is not one |
/// | the agent **signed** the carry-over | it is the agent's act, as the publication was |
/// | the carry-over is **anchored** | the link A→B is public, which is what makes it safe |
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdSuccession {
    /// The container being left behind — A, frozen at status 6.
    pub from: Hash,
    /// The container continuing the work — B.
    pub to: Hash,
    /// The ID carried over, in the open.
    pub open_id: String,
    /// The agent, unchanged. One agent, one key; only the ID was ever per
    /// container.
    pub agent: PublicKey,
    /// The agent's signature over the carry-over.
    pub signatures: SignatureSet,
    /// The anchor. **Not optional** — the public link is the justification.
    pub anchor: Attestation,
}

impl IdSuccession {
    /// The value a carry-over's anchor must attest.
    ///
    /// Both containers are inside it, and in that order: the anchor of a
    /// carry-over A→B cannot be replayed as B→A, nor moved to a third container.
    #[must_use]
    pub fn subject(from: &Hash, to: &Hash, open_id: &str, agent: &PublicKey) -> Hash {
        Hash::sha256_fields(&[
            b"ksg:agent-id:succession:v1",
            from.as_bytes(),
            to.as_bytes(),
            open_id.as_bytes(),
            agent.key.as_bytes(),
        ])
    }

    /// Whether the ID really was carried over, given both publications.
    ///
    /// Takes them both rather than trusting the fields: a carry-over that named
    /// containers nobody had published for would be a claim about two strangers.
    ///
    /// # Errors
    ///
    /// [`IdentityError::WrongContainer`] when a publication is of another
    /// container or the two are the same; [`IdentityError::WrongId`] when the
    /// IDs or the agent keys differ; [`IdentityError::NotAnchored`] when the
    /// publications or the carry-over are not in the chain;
    /// [`IdentityError::Signature`] when the agent did not sign the carry-over.
    pub fn validate(
        &self,
        predecessor: &Publication,
        successor: &Publication,
    ) -> Result<(), IdentityError> {
        if self.from == self.to {
            return Err(IdentityError::WrongContainer);
        }
        if predecessor.container != self.from || successor.container != self.to {
            return Err(IdentityError::WrongContainer);
        }
        predecessor.validate()?;
        successor.validate()?;
        if predecessor.open_id != self.open_id || successor.open_id != self.open_id {
            return Err(IdentityError::WrongId);
        }
        // One agent, one key — the publication already carries it, so a
        // mismatch here means somebody else's ID is being pulled along.
        if predecessor.agent != self.agent || successor.agent != self.agent {
            return Err(IdentityError::WrongId);
        }
        let subject = Self::subject(&self.from, &self.to, &self.open_id, &self.agent);
        self.anchor
            .covers(&subject)
            .map_err(|_| IdentityError::NotAnchored)?;
        // The agent signed the carry-over: it is the agent's act, as the
        // publication was (C-10). Checked against the agent's own key only.
        let keys: ksg_core_v2::crypto::sign::KeySet = std::iter::once(self.agent.clone()).collect();
        self.signatures
            .verify(
                subject.as_bytes(),
                &keys,
                &ksg_core_v2::crypto::sign::Profile::default(),
            )
            .map_err(|_| IdentityError::Signature)
    }

    /// The digest the carried ID answers to — the same on both sides, which is
    /// the whole of what "carried over" means.
    #[must_use]
    pub fn id_hash(&self) -> Hash {
        id_hash(&self.open_id)
    }
}

/// Which containers an ID reaches, following a run of carry-overs.
///
/// A claim is served on an **ID**, and after one or more transplants that ID has
/// more than one container behind it: the working one and the frozen archives
/// coupled behind it. This resolves the run so that the answer to "does this
/// claim reach that container" is computed rather than assumed.
///
/// The links must form a **line**, and that is checked: each carry-over starts
/// where the previous one ended, and no container appears twice. A fork would
/// mean one ID serving two working containers — which is the linkability the
/// per-container rule exists to prevent, arrived at by chaining instead of
/// directly.
///
/// # Errors
///
/// [`IdentityError::WrongContainer`] when the run is not a line, forks, or
/// revisits a container; [`IdentityError::WrongId`] when a step carries a
/// different ID or a different agent; anchor errors as [`IdSuccession::validate`].
pub fn carried_line(
    first: &Hash,
    steps: &[IdSuccession],
    publications: &[Publication],
) -> Result<Vec<Hash>, IdentityError> {
    if publications.len() != steps.len() + 1 {
        return Err(IdentityError::WrongContainer);
    }
    let mut seen = vec![*first];
    if publications[0].container != *first {
        return Err(IdentityError::WrongContainer);
    }
    for (i, step) in steps.iter().enumerate() {
        if step.from != seen[seen.len() - 1] {
            return Err(IdentityError::WrongContainer);
        }
        if seen.contains(&step.to) {
            return Err(IdentityError::WrongContainer);
        }
        step.validate(&publications[i], &publications[i + 1])?;
        if step.open_id != steps[0].open_id {
            return Err(IdentityError::WrongId);
        }
        seen.push(step.to);
    }
    Ok(seen)
}
