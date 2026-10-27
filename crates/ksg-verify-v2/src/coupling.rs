//! The coupling of two containers, checked from outside (owner's decisions
//! 11.10 and 13.10).
//!
//! A coupling is two pages in two journals: the trailer's slot 1 names its
//! leader, the leader's slot 2 names the trailer and the trailer's last seal.
//! Each page alone is one side's word. With both exports in hand a verifier
//! confirms the pair: each names the other, the seal the leader carries is
//! the trailer's own last seal, and the leader is Pro — its seals are
//! anchored, which is what anchors the trailer's last seal as well.
//!
//! With only the leader's export the coupling is claimed, not confirmed: any
//! Pro may write a slot 2 naming somebody else's container.

use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::Profile;
use ksg_core_v2::journal::{verify_bound, Body, BoundExport, CouplingRecord, Mode};

/// What the pair of exports shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pair {
    /// Both sides name each other, the seal matches, the leader is Pro.
    Confirmed {
        /// The trailer.
        trailer: Hash,
        /// The leader.
        leader: Hash,
    },
    /// The pair does not hold; the reason names the first thing that failed.
    Refused(String),
}

fn slot1(x: &BoundExport) -> Option<Hash> {
    x.pages.iter().find_map(|p| match &p.body {
        Body::Coupling(CouplingRecord::AttachedTo { leader }) => Some(*leader),
        _ => None,
    })
}

fn slot2(x: &BoundExport) -> Option<(Hash, Hash)> {
    x.pages.iter().find_map(|p| match &p.body {
        Body::Coupling(CouplingRecord::Pulls {
            trailer,
            trailer_seal,
        }) => Some((*trailer, *trailer_seal)),
        _ => None,
    })
}

/// Checks a coupling from the two whole-journal exports.
#[must_use]
pub fn verify_pair(trailer: &BoundExport, leader: &BoundExport, profile: &Profile) -> Pair {
    let refused = |why: &str| Pair::Refused(why.to_owned());
    if let Err(e) = verify_bound(trailer, profile) {
        return Pair::Refused(format!("the trailer's export does not verify: {e}"));
    }
    if let Err(e) = verify_bound(leader, profile) {
        return Pair::Refused(format!("the leader's export does not verify: {e}"));
    }
    let t_id = trailer.seal.container;
    let l_id = leader.seal.container;
    let Some(named_leader) = slot1(trailer) else {
        return refused("the trailer has no coupling page: it names no leader");
    };
    if named_leader != l_id {
        return refused("the trailer names another leader");
    }
    let Some((named_trailer, carried_seal)) = slot2(leader) else {
        return refused("the leader has no coupling page: it pulls no trailer");
    };
    if named_trailer != t_id {
        return refused("the leader pulls another trailer");
    }
    // The trailer writes nothing after its coupling page (13.10), so the
    // seal the leader carries is the trailer's last seal, and nothing else.
    let Ok(last) = trailer.seal.hash() else {
        return refused("the trailer's last seal cannot be hashed");
    };
    if carried_seal != last {
        return refused("the leader carries a seal that is not the trailer's last");
    }
    if leader.seal.mode != Mode::Pro {
        return refused("the leader is not Pro: a trailer is attached to Pro only");
    }
    Pair::Confirmed {
        trailer: t_id,
        leader: l_id,
    }
}
