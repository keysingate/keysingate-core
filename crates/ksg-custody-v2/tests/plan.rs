//! Where the shares lie. §2.4 — the two rules that decide whether five places
//! are five.

use ksg_core_v2::crypto::hash::Hash;
use ksg_custody_v2::plan::{Keeping, Place, Plan, MAX_PER_JURISDICTION};
use ksg_custody_v2::CustodyError;

fn place(keeping: Keeping, j: &str, op: &str) -> Place {
    Place {
        keeping,
        jurisdiction: j.into(),
        operator: op.into(),
    }
}

/// The plan of §2.4 as the owner settled it on 12.09.
fn as_decided() -> Plan {
    Plan {
        places: vec![
            place(Keeping::Offline, "UA", ""),
            place(Keeping::Offline, "PL", ""),
            place(Keeping::Depositary, "UA", ""),
            place(Keeping::Cloud, "DE", "provider-x"),
            place(Keeping::Cloud, "CH", "provider-y"),
        ],
        threshold: 3,
        procedure: Hash::sha256(b"the written recovery procedure"),
    }
}

#[test]
fn the_plan_as_decided_stands() {
    as_decided().validate().expect("five independent places");
    assert!(!as_decided().any_country_could_take_it());
}

#[test]
fn three_shares_in_one_country_is_a_country_that_holds_the_key() {
    // The rule that came out of choosing a Ukrainian notary: with a threshold of
    // three, one country holding three holds everything.
    let mut p = as_decided();
    p.places[1].jurisdiction = "UA".into();
    assert_eq!(
        p.validate().unwrap_err(),
        CustodyError::Plan("too many shares in one jurisdiction")
    );
    assert!(p.any_country_could_take_it());
    assert_eq!(p.exposure("UA"), 3);
}

#[test]
fn two_in_one_country_is_the_limit_and_it_is_allowed() {
    // Ukraine holds the notary and one offline site, and that is the quota.
    assert_eq!(as_decided().exposure("UA"), MAX_PER_JURISDICTION);
    as_decided()
        .validate()
        .expect("two is the limit, not a fault");
}

#[test]
fn two_clouds_at_one_operator_are_one_cloud() {
    // the owner: "otherwise 4 and 5 fall together" — a revoked account, a sanction or one order
    // takes both at once, and the set stands on four places while claiming five.
    let mut p = as_decided();
    p.places[4].operator = "provider-x".into();
    assert_eq!(
        p.validate().unwrap_err(),
        CustodyError::Plan("two shares with one cloud operator: that is one share")
    );
}

#[test]
fn a_cloud_with_no_operator_named_cannot_be_judged() {
    let mut p = as_decided();
    p.places[3].operator = String::new();
    assert_eq!(
        p.validate().unwrap_err(),
        CustodyError::Plan("a cloud place with no operator named")
    );
}

#[test]
fn all_of_one_kind_falls_to_one_kind_of_event() {
    // Five clouds fall to one technical event; five notaries to one legal
    // process. The mix is the point of the mix.
    let p = Plan {
        places: (0..5)
            .map(|i| place(Keeping::Cloud, &format!("J{i}"), &format!("op{i}")))
            .collect(),
        threshold: 3,
        procedure: Hash::sha256(b"procedure"),
    };
    assert_eq!(
        p.validate().unwrap_err(),
        CustodyError::Plan("every share kept the same way: one kind of event takes them all")
    );
}

#[test]
fn a_set_with_no_written_procedure_is_five_envelopes_and_a_guess() {
    let mut p = as_decided();
    p.procedure = Hash::sha256(b"");
    assert_eq!(
        p.validate().unwrap_err(),
        CustodyError::Plan("no recovery procedure: five envelopes and a guess")
    );
}

#[test]
fn fewer_places_than_the_threshold_cannot_be_recovered_at_all() {
    let mut p = as_decided();
    p.places.truncate(2);
    assert_eq!(
        p.validate().unwrap_err(),
        CustodyError::Plan(
            "fewer places than the threshold: the secret cannot be recovered at all"
        )
    );
}

#[test]
fn the_chain_gets_a_digest_and_the_topology_stays_private() {
    // Anchoring the places themselves would publish which country to subpoena
    // and which provider to press. The digest proves only that the plan has not
    // been quietly rewritten, which is the property actually needed.
    let p = as_decided();
    let printed = format!("{:?}", p.digest());
    for leak in ["UA", "provider-x", "Depositary"] {
        assert!(!printed.contains(leak), "the digest leaks {leak}");
    }
    // And it does change when the plan does — a plan editable after the fact is
    // not a plan.
    let mut moved = as_decided();
    moved.places[3].operator = "provider-z".into();
    assert_ne!(p.digest(), moved.digest());
}
