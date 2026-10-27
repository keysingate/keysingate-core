//! The identity layer, and publishing an agent's ID. KS-8 C-4, C-10, C-11.
//!
//! The rule under all of it: **want to own — say who you are.** Rights without
//! reachability are rights without responsibility.

use ksg_container_v2::{
    id_hash, Challenge, IdDisclosure, IdSuccession, IdentityError, OwnershipClaim, Publication,
};
use ksg_core_v2::anchor::Attestation;
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{Ed25519Signer, KeySet, Profile, SignatureSet};
use ksg_core_v2::doc::{Timestamp, Uri};

fn uri(s: &str) -> Uri {
    Uri::parse(s).expect("uri")
}
fn agent() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:key:zAgent#a1"), [42u8; 32])
}
fn claimant() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:key:zClaimant#x1"), [85u8; 32])
}
fn owner() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:key:zOwner#o1"), [44u8; 32])
}
fn p() -> Profile {
    Profile::default()
}
fn container() -> Hash {
    Hash::sha256(b"the container's identifier")
}
fn artifact() -> Hash {
    Hash::sha256(b"the artifact")
}

const AGENT_ID: &str = "ksg:agent:zAgent-public-identifier";
const CLAIMANT_ID: &str = "ksg:agent:zClaimant-public-identifier";

fn anchor(subject: Hash) -> Attestation {
    Attestation {
        kind: uri("urn:ksg:anchor:test"),
        subject,
        proof: b"opaque".to_vec(),
        anchored_at: Timestamp::parse("2026-09-10T00:00:00.000Z").expect("ts"),
    }
}

fn publication(open_id: &str, who: &Ed25519Signer) -> Publication {
    publication_for(container(), open_id, who)
}

fn publication_for(c: Hash, open_id: &str, who: &Ed25519Signer) -> Publication {
    let subject = Publication::subject(&c, open_id, &who.public());
    Publication {
        container: c,
        open_id: open_id.into(),
        agent: who.public(),
        signatures: SignatureSet::new(vec![who.sign(subject.as_bytes())]),
        anchor: anchor(subject),
    }
}

// --- step 3 does not happen without step 1 -----------------------------------

#[test]
fn ownership_is_recorded_only_after_the_id_is_published() {
    // C-10, the condition rather than the advice. The container records
    // hash(artifact) + hash(agent ID), and refuses to do so for an ID nobody can
    // reach.
    let pub_ = publication(AGENT_ID, &agent());
    let claim = OwnershipClaim {
        container: container(),
        artifact: artifact(),
        agent_id: id_hash(AGENT_ID),
    };
    claim
        .accept(&container(), &pub_)
        .expect("published, so the claim stands");
}

#[test]
fn an_unpublished_id_cannot_claim_ownership() {
    // The anchor is what makes a publication a publication. Without it the ID
    // was written down, not published — and an unreachable owner is what the
    // rule exists against.
    let mut unpublished = publication(AGENT_ID, &agent());
    unpublished.anchor = anchor(Hash::sha256(b"something else"));
    let claim = OwnershipClaim {
        container: container(),
        artifact: artifact(),
        agent_id: id_hash(AGENT_ID),
    };
    assert_eq!(
        claim.accept(&container(), &unpublished).unwrap_err(),
        IdentityError::NotAnchored
    );
}

#[test]
fn a_publication_of_some_other_id_does_not_serve() {
    // Otherwise one published ID would license claims under any number of
    // others, and "say who you are" would mean "let somebody have said
    // something".
    let other = publication(CLAIMANT_ID, &claimant());
    let claim = OwnershipClaim {
        container: container(),
        artifact: artifact(),
        agent_id: id_hash(AGENT_ID),
    };
    assert_eq!(
        claim.accept(&container(), &other).unwrap_err(),
        IdentityError::WrongId
    );
}

#[test]
fn a_claim_recorded_in_another_container_is_refused() {
    let pub_ = publication(AGENT_ID, &agent());
    let claim = OwnershipClaim {
        container: Hash::sha256(b"another container"),
        artifact: artifact(),
        agent_id: id_hash(AGENT_ID),
    };
    assert_eq!(
        claim.accept(&container(), &pub_).unwrap_err(),
        IdentityError::WrongContainer
    );
}

#[test]
fn the_container_holds_hashes_and_not_the_open_id() {
    // C-10: inside there are only hashes; the open ID lives in the chain and in
    // the artifact. The claim's type is the guarantee — there is no field for an
    // open ID to sit in.
    let claim = OwnershipClaim {
        container: container(),
        artifact: artifact(),
        agent_id: id_hash(AGENT_ID),
    };
    let rendered = format!("{claim:?}");
    assert!(!rendered.contains(AGENT_ID), "{rendered}");
    assert_ne!(id_hash(AGENT_ID), id_hash(CLAIMANT_ID));
}

// --- the symmetry ------------------------------------------------------------

#[test]
fn a_challenger_must_name_itself_too() {
    // C-11: spoiling somebody's title anonymously is not possible. The
    // challenger publishes exactly as the owner had to.
    let claimant_pub = publication(CLAIMANT_ID, &claimant());
    let ch = Challenge {
        artifact: artifact(),
        claimant_id: id_hash(CLAIMANT_ID),
        anchor: anchor(Challenge::subject(&artifact(), &id_hash(CLAIMANT_ID))),
    };
    ch.validate(&claimant_pub).expect("a named challenger");
}

#[test]
fn an_anonymous_challenge_is_refused() {
    let mut unpublished = publication(CLAIMANT_ID, &claimant());
    unpublished.anchor = anchor(Hash::sha256(b"not a publication"));
    let ch = Challenge {
        artifact: artifact(),
        claimant_id: id_hash(CLAIMANT_ID),
        anchor: anchor(Challenge::subject(&artifact(), &id_hash(CLAIMANT_ID))),
    };
    assert_eq!(
        ch.validate(&unpublished).unwrap_err(),
        IdentityError::NotPublished
    );
}

#[test]
fn a_challenge_not_in_the_chain_is_refused() {
    // The right is recorded inside the container and the challenge outside it,
    // which is why the owner can neither hide it nor fail to notice it. A
    // challenge nobody anchored is a challenge the owner would never see.
    let claimant_pub = publication(CLAIMANT_ID, &claimant());
    let ch = Challenge {
        artifact: artifact(),
        claimant_id: id_hash(CLAIMANT_ID),
        anchor: anchor(Hash::sha256(b"elsewhere")),
    };
    assert_eq!(
        ch.validate(&claimant_pub).unwrap_err(),
        IdentityError::NotAnchored
    );
}

#[test]
fn both_sides_hash_an_id_the_same_way() {
    // The symmetry of C-11 rests on it: the owner's claim inside and the
    // challenger's claim outside must compute the same digest, or the addressee
    // would not resolve.
    let inside = OwnershipClaim {
        container: container(),
        artifact: artifact(),
        agent_id: id_hash(AGENT_ID),
    };
    let outside = Challenge {
        artifact: artifact(),
        claimant_id: id_hash(AGENT_ID),
        anchor: anchor(Challenge::subject(&artifact(), &id_hash(AGENT_ID))),
    };
    assert_eq!(inside.agent_id, outside.claimant_id);
}

// --- the owner may open the ID, and nobody may open the identity --------------

#[test]
fn the_owner_discloses_which_identity_under_an_anchor() {
    // C-4: the identity's ID is the owner's to open at an export, under an
    // anchor. The trace is what makes a quiet demand answerable for.
    let subject = IdDisclosure::subject(&container(), AGENT_ID);
    let d = IdDisclosure {
        container: container(),
        open_id: AGENT_ID.into(),
        signatures: SignatureSet::new(vec![owner().sign(subject.as_bytes())]),
        anchor: anchor(subject),
    };
    let keys: KeySet = [owner().public()].into_iter().collect();
    let who = d
        .verify(&container(), &id_hash(AGENT_ID), &keys, &p())
        .expect("the disclosure verifies");
    assert_eq!(who, owner().public().kid);
}

#[test]
fn a_disclosure_without_an_anchor_leaves_no_trace_and_is_refused() {
    let subject = IdDisclosure::subject(&container(), AGENT_ID);
    let d = IdDisclosure {
        container: container(),
        open_id: AGENT_ID.into(),
        signatures: SignatureSet::new(vec![owner().sign(subject.as_bytes())]),
        anchor: anchor(Hash::sha256(b"untraceable")),
    };
    let keys: KeySet = [owner().public()].into_iter().collect();
    assert_eq!(
        d.verify(&container(), &id_hash(AGENT_ID), &keys, &p())
            .unwrap_err(),
        IdentityError::DisclosureNotAnchored
    );
}

#[test]
fn a_disclosure_of_an_id_the_container_does_not_hold_is_refused() {
    // Otherwise an owner could "disclose" any identity at all, and the
    // disclosure would say nothing about this container.
    let subject = IdDisclosure::subject(&container(), CLAIMANT_ID);
    let d = IdDisclosure {
        container: container(),
        open_id: CLAIMANT_ID.into(),
        signatures: SignatureSet::new(vec![owner().sign(subject.as_bytes())]),
        anchor: anchor(subject),
    };
    let keys: KeySet = [owner().public()].into_iter().collect();
    assert_eq!(
        d.verify(&container(), &id_hash(AGENT_ID), &keys, &p())
            .unwrap_err(),
        IdentityError::WrongId
    );
}

#[test]
fn nothing_here_opens_the_identity_itself() {
    // The guarantee of C-4, stated by absence. The identity is encrypted under
    // its own key, and no type in this module takes that key or returns that
    // value — there is IdDisclosure for the ID and nothing for the identity.
    //
    // Held as a named test so that adding such a function later has to argue
    // with it rather than slip in.
    let subject = IdDisclosure::subject(&container(), AGENT_ID);
    let d = IdDisclosure {
        container: container(),
        open_id: AGENT_ID.into(),
        signatures: SignatureSet::new(vec![owner().sign(subject.as_bytes())]),
        anchor: anchor(subject),
    };
    // What comes back is the ID and who opened it. Never the identity.
    let keys: KeySet = [owner().public()].into_iter().collect();
    let who = d
        .verify(&container(), &id_hash(AGENT_ID), &keys, &p())
        .unwrap();
    assert_eq!(who, owner().public().kid);
    assert_eq!(d.open_id, AGENT_ID);
}

// --- one ID per container ----------------------------------------------------

#[test]
fn an_id_published_for_another_container_does_not_serve_here() {
    // `[decision]` 12.09: the ID binds to the container. A perfectly good publication,
    // anchored and signed, is still refused if it was made for a different
    // container — otherwise the binding would be per container in the
    // documentation and per agent in practice.
    let elsewhere = Hash::sha256(b"another container");
    let good_but_elsewhere = publication_for(elsewhere, AGENT_ID, &agent());
    good_but_elsewhere
        .validate()
        .expect("it is a valid publication in its own right");

    let claim = OwnershipClaim {
        container: container(),
        artifact: artifact(),
        agent_id: id_hash(AGENT_ID),
    };
    assert_eq!(
        claim.accept(&container(), &good_but_elsewhere).unwrap_err(),
        IdentityError::WrongContainer
    );
}

#[test]
fn a_publications_anchor_cannot_be_moved_to_another_container() {
    // The container goes into the anchored digest, so the anchor of a
    // publication for one container does not attest one for another. Without it
    // the rule would be enforced by a field comparison that an attacker simply
    // edits.
    let here = publication(AGENT_ID, &agent());
    let moved = Publication {
        container: Hash::sha256(b"another container"),
        ..here
    };
    assert_eq!(moved.validate().unwrap_err(), IdentityError::NotAnchored);
}

#[test]
fn two_containers_of_one_agent_are_not_linkable_through_their_ids() {
    // What the choice was for. The same agent works in two containers under two
    // IDs, and nothing in either container connects them: the digests differ,
    // and the publications are anchored to different containers.
    let first = publication_for(container(), AGENT_ID, &agent());
    let second_container = Hash::sha256(b"the agent's other container");
    let second = publication_for(second_container, CLAIMANT_ID, &agent());

    first.validate().expect("first");
    second.validate().expect("second");
    assert_ne!(first.id_hash(), second.id_hash());
    assert_ne!(first.anchor.subject, second.anchor.subject);

    // And each serves only its own container.
    let claim_here = OwnershipClaim {
        container: container(),
        artifact: artifact(),
        agent_id: first.id_hash(),
    };
    claim_here.accept(&container(), &first).expect("its own");
    assert!(claim_here.accept(&container(), &second).is_err());
}

#[test]
fn the_same_agent_key_may_publish_for_each_container_separately() {
    // Reachability is kept: the agent is still the one publishing, and the key
    // is the same. What is not shared is the ID.
    let a = publication_for(container(), AGENT_ID, &agent());
    let b = publication_for(Hash::sha256(b"other"), CLAIMANT_ID, &agent());
    assert_eq!(a.agent.kid, b.agent.kid, "one agent, one key");
    assert_ne!(a.open_id, b.open_id, "two containers, two IDs");
}

// --- E-14: the ID carries over to the successor --------------------------
//
// `[decision]` 12.09, the owner: "the ID carries over to the successor, if feasible." It is
// feasible, and the reason is that the succession is already anchored — so the
// carry-over discloses nothing the transplant does not already say.

fn container_b() -> Hash {
    Hash::sha256(b"the successor container")
}
fn container_c() -> Hash {
    Hash::sha256(b"the second successor")
}

fn carry(from: Hash, to: Hash, open_id: &str, who: &Ed25519Signer) -> IdSuccession {
    let subject = IdSuccession::subject(&from, &to, open_id, &who.public());
    IdSuccession {
        from,
        to,
        open_id: open_id.into(),
        agent: who.public(),
        signatures: SignatureSet::new(vec![who.sign(subject.as_bytes())]),
        anchor: anchor(subject),
    }
}

#[test]
fn the_id_carries_over_to_the_successor() {
    let a = publication_for(container(), AGENT_ID, &agent());
    let b = publication_for(container_b(), AGENT_ID, &agent());
    let step = carry(container(), container_b(), AGENT_ID, &agent());
    step.validate(&a, &b).expect("the carry-over stands");
    // And the point of it: the same digest answers on both sides, so a claim
    // served on A's ID has an address in B.
    assert_eq!(step.id_hash(), a.id_hash());
    assert_eq!(step.id_hash(), b.id_hash());
}

#[test]
fn a_carried_id_still_serves_the_successors_own_claim() {
    let b = publication_for(container_b(), AGENT_ID, &agent());
    let claim = OwnershipClaim {
        container: container_b(),
        artifact: artifact(),
        agent_id: id_hash(AGENT_ID),
    };
    // The successor's publication is a publication for B, so nothing about the
    // carry-over weakens the per-container check inside the container.
    claim.accept(&container_b(), &b).expect("accepted");
}

#[test]
fn the_carry_over_cannot_be_replayed_backwards() {
    let a = publication_for(container(), AGENT_ID, &agent());
    let b = publication_for(container_b(), AGENT_ID, &agent());
    let step = carry(container(), container_b(), AGENT_ID, &agent());
    let reversed = IdSuccession {
        from: container_b(),
        to: container(),
        ..step
    };
    // Both containers are inside the anchored subject, in order.
    assert_eq!(
        reversed.validate(&b, &a),
        Err(IdentityError::NotAnchored),
        "A→B is not B→A"
    );
}

#[test]
fn an_id_is_not_dragged_onto_a_strangers_container() {
    let a = publication_for(container(), AGENT_ID, &agent());
    // The successor published a different agent's key under the same open ID —
    // the shape of an attempt to inherit somebody's address.
    let b = publication_for(container_b(), AGENT_ID, &claimant());
    let step = carry(container(), container_b(), AGENT_ID, &agent());
    assert_eq!(step.validate(&a, &b), Err(IdentityError::WrongId));
}

#[test]
fn a_carry_over_to_itself_is_not_one() {
    let a = publication_for(container(), AGENT_ID, &agent());
    let step = carry(container(), container(), AGENT_ID, &agent());
    assert_eq!(
        step.validate(&a, &a),
        Err(IdentityError::WrongContainer),
        "a container does not succeed itself"
    );
}

#[test]
fn a_different_id_is_not_a_carry_over() {
    let a = publication_for(container(), AGENT_ID, &agent());
    let b = publication_for(container_b(), CLAIMANT_ID, &agent());
    let step = carry(container(), container_b(), AGENT_ID, &agent());
    assert_eq!(step.validate(&a, &b), Err(IdentityError::WrongId));
}

#[test]
fn two_transplants_form_a_line_and_the_id_reaches_all_three() {
    let pubs = vec![
        publication_for(container(), AGENT_ID, &agent()),
        publication_for(container_b(), AGENT_ID, &agent()),
        publication_for(container_c(), AGENT_ID, &agent()),
    ];
    let steps = vec![
        carry(container(), container_b(), AGENT_ID, &agent()),
        carry(container_b(), container_c(), AGENT_ID, &agent()),
    ];
    let line = ksg_container_v2::carried_line(&container(), &steps, &pubs).expect("a line");
    assert_eq!(line, vec![container(), container_b(), container_c()]);
}

#[test]
fn a_fork_is_refused_one_id_does_not_serve_two_working_containers() {
    let pubs = vec![
        publication_for(container(), AGENT_ID, &agent()),
        publication_for(container_b(), AGENT_ID, &agent()),
        publication_for(container_c(), AGENT_ID, &agent()),
    ];
    // Both steps leave A. That is the linkability the per-container rule
    // exists against, reached by chaining instead of directly.
    let steps = vec![
        carry(container(), container_b(), AGENT_ID, &agent()),
        carry(container(), container_c(), AGENT_ID, &agent()),
    ];
    assert_eq!(
        ksg_container_v2::carried_line(&container(), &steps, &pubs),
        Err(IdentityError::WrongContainer)
    );
}

#[test]
fn a_cycle_is_refused() {
    let pubs = vec![
        publication_for(container(), AGENT_ID, &agent()),
        publication_for(container_b(), AGENT_ID, &agent()),
        publication_for(container(), AGENT_ID, &agent()),
    ];
    let steps = vec![
        carry(container(), container_b(), AGENT_ID, &agent()),
        carry(container_b(), container(), AGENT_ID, &agent()),
    ];
    assert_eq!(
        ksg_container_v2::carried_line(&container(), &steps, &pubs),
        Err(IdentityError::WrongContainer)
    );
}

/// C-10 (KS-8): the agent **signed** the carry-over — one without the
/// agent's signature, or signed by somebody else, does not stand.
#[test]
fn a_carry_over_the_agent_did_not_sign_does_not_stand() {
    let a = publication_for(container(), AGENT_ID, &agent());
    let b = publication_for(container_b(), AGENT_ID, &agent());
    let mut unsigned = carry(container(), container_b(), AGENT_ID, &agent());
    unsigned.signatures = SignatureSet::new(vec![]);
    assert_eq!(unsigned.validate(&a, &b), Err(IdentityError::Signature));

    let stranger = Ed25519Signer::from_seed(
        ksg_core_v2::doc::Uri::parse("did:key:zStranger#k1".to_owned()).unwrap(),
        [99u8; 32],
    );
    let mut forged = carry(container(), container_b(), AGENT_ID, &agent());
    let subject = IdSuccession::subject(&container(), &container_b(), AGENT_ID, &agent().public());
    forged.signatures = SignatureSet::new(vec![stranger.sign(subject.as_bytes())]);
    assert_eq!(forged.validate(&a, &b), Err(IdentityError::Signature));
}
