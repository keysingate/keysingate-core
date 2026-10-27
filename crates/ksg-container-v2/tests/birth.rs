//! The birth of the client's key and of the container at initiation (KS-8
//! E-4, CH-5b — `[doc:CLIENT-KEY-INIT]`): printed
//! as a template, the container gets its client's key — born in two halves,
//! never whole — and its own identifier only when E-4 goes in.

mod stand;

use ksg_container_v2::client_key::{ContainerKeygen, KeygenFinish, MobileKeygen};
use ksg_container_v2::container::Evidence;
use ksg_container_v2::layers::Level;
use ksg_container_v2::{Container, Operation as Op, Role, Status, Stopped, Where};
use ksg_core_v2::crypto::sign::{KeySet, Profile, SignatureSet};
use ksg_core_v2::doc::{derive_container_id, Class};
use stand::{uri, Page, Stand, StandRng, Who};

const KEY: [u8; 32] = [7u8; 32];

fn to_buyer_keyed(s: &mut Stand) {
    s.press(Op::ApplyPacket, &[Who::Issuer], Evidence::None, Page::None)
        .expect("packet");
    let buyer = s.parties.buyer.public();
    s.press(
        Op::ApplyBuyerKey,
        &[Who::Buyer, Who::Owner],
        Evidence::KeyLaid {
            to: buyer,
            up_to: Level(2),
        },
        Page::None,
    )
    .expect("buyer's key");
}

/// E-4 with no key born: only the owner can sign — the client has nothing
/// to sign with yet.
fn initiate_unborn(s: &mut Stand) -> Result<(), Stopped> {
    s.press(
        Op::Initiate,
        &[Who::Owner],
        Evidence::Initiation { at: Where::Inside },
        Page::None,
    )
}

fn initiate(s: &mut Stand) -> Result<(), Stopped> {
    s.press(
        Op::Initiate,
        &[Who::Client, Who::Owner],
        Evidence::Initiation { at: Where::Inside },
        Page::None,
    )
}

#[test]
fn the_key_is_born_in_two_halves_and_signs_as_one_ed25519_key() {
    let mut rng = StandRng(1);
    let (keygen, hello) = MobileKeygen::start(uri("did:key:zA#a1"), &mut rng).expect("start");
    let (inside, reply) =
        ContainerKeygen::answer(uri("did:key:zA#a1"), &hello, &mut rng).expect("answer");
    let (mobile, public, fin) = keygen.finish(&reply).expect("mobile");
    let half = inside.finish(&fin).expect("container");
    assert_eq!(half.public(), &public);

    let _ = (mobile, half);

    // On a container: born at E-4, the two halves sign together, and what
    // comes out is an ordinary Ed25519 signature under the client's key.
    let mut s = Stand::printed(Class::Heavy, 2);
    to_buyer_keyed(&mut s);
    s.give_birth();
    initiate(&mut s).expect("born");
    let sigs = s.client_signs(b"hello");
    let keys: KeySet = [s.client.clone()].into_iter().collect();
    SignatureSet::new(sigs)
        .verify(b"hello", &keys, &Profile::default().with_ed25519())
        .expect("one Ed25519 signature");
}

#[test]
fn a_share_that_is_not_the_committed_one_is_refused_by_either_side() {
    let mut rng = StandRng(3);
    let (keygen, hello) = MobileKeygen::start(uri("did:key:zA#a1"), &mut rng).expect("start");
    let (inside, reply) =
        ContainerKeygen::answer(uri("did:key:zA#a1"), &hello, &mut rng).expect("answer");
    // Another birth's message 3 does not finish this one.
    let (keygen2, hello2) = MobileKeygen::start(uri("did:key:zA#a1"), &mut rng).expect("start");
    let (_, reply2) =
        ContainerKeygen::answer(uri("did:key:zA#a1"), &hello2, &mut rng).expect("answer");
    let (_, _, fin2) = keygen2.finish(&reply2).expect("mobile");
    assert!(inside.finish(&fin2).is_err());
    // A byte of the container's share changed: the mobile side refuses it.
    let mut bytes = reply.to_bytes().expect("bytes").to_vec();
    let at = bytes.len() - 5;
    bytes[at] ^= 1;
    // Refused as bytes already, or by the mobile side.
    if let Ok(bad) = ksg_container_v2::client_key::KeygenReply::from_bytes(&bytes) {
        assert!(keygen.finish(&bad).is_err());
    }
    // And the wire forms refuse what they are not.
    assert!(KeygenFinish::from_bytes(b"nothing").is_err());
}

#[test]
fn a_printed_container_is_a_template_until_initiation_gives_birth_to_it() {
    let mut s = Stand::printed(Class::Heavy, 4);
    let template = s.c.template_id();
    assert!(!s.c.born());
    assert_eq!(s.c.id(), &template);
    assert!(s.c.roster().holder(Role::Client).is_none());
    to_buyer_keyed(&mut s);

    // E-4 without a key born for it: refused, nothing moves.
    assert!(matches!(initiate_unborn(&mut s), Err(Stopped::Birth(_))));
    assert_eq!(s.c.status(), Status::BuyerKeyed);

    let id = s.give_birth();
    initiate(&mut s).expect("initiation gives birth");
    assert!(s.c.born());
    assert_eq!(s.c.id(), &id);
    assert_eq!(s.c.template_id(), template);
    assert_eq!(s.c.agent(), Some(&s.client));
    assert_eq!(s.c.roster().holder(Role::Client), Some(&s.client));
    assert_eq!(
        id,
        derive_container_id(
            stand::EMISSION,
            &stand::ts("2026-09-01T00:00:00.000Z"),
            stand::SERIAL,
            &s.client,
            &uri(stand::ARTIFACT),
            stand::OFFSET,
        ),
        "the identifier is the core's: the client's key and the artefact, at once"
    );

    // The journal opens on the born container, and the file goes on.
    s.press(
        Op::OpenJournal,
        &[Who::Client],
        Evidence::None,
        Page::Opening,
    )
    .expect("journal");
    let bytes = s.c.seal_to_bytes(&KEY, &mut s.rng).expect("stored");
    let back = Container::open_sealed(&bytes, &template, &KEY).expect("opens");
    assert_eq!(back.id(), &id);
    assert!(back.born());
}

#[test]
fn an_initiation_that_does_not_go_in_leaves_the_template_as_it_was() {
    let mut s = Stand::printed(Class::Heavy, 5);
    to_buyer_keyed(&mut s);
    s.give_birth();
    // The owner did not sign: refused, and the born key holds no seat.
    let err = s
        .press(
            Op::Initiate,
            &[Who::Client],
            Evidence::Initiation { at: Where::Inside },
            Page::None,
        )
        .expect_err("E-4 takes the client and the owner");
    assert!(!matches!(err, Stopped::Birth(_)), "{err:?}");
    assert!(!s.c.born());
    assert!(s.c.roster().holder(Role::Client).is_none());
    assert_eq!(s.c.id(), &s.c.template_id());
    // A birth does not outlive the reader's command: a stored template has
    // none, and initiation needs a new one.
    let bytes = s.c.seal_to_bytes(&KEY, &mut s.rng).expect("stored");
    s.c = Container::open_sealed(&bytes, &s.c.template_id(), &KEY).expect("opens");
    assert!(s.c.birth_key().is_none());
    assert!(matches!(initiate_unborn(&mut s), Err(Stopped::Birth(_))));
    s.give_birth();
    initiate(&mut s).expect("a new birth goes in");
}

#[test]
fn a_born_container_is_born_once() {
    let mut s = Stand::printed(Class::Light, 6);
    to_buyer_keyed(&mut s);
    s.give_birth();
    initiate(&mut s).expect("born");
    let mut rng = StandRng(7);
    let (_, hello) = MobileKeygen::start(uri("did:key:zB#b1"), &mut rng).expect("start");
    assert!(matches!(
        s.c.begin_birth(uri("did:key:zB#b1"), &hello, &mut rng),
        Err(Stopped::Birth(_))
    ));
}

#[test]
fn before_initiation_the_template_has_no_client_to_open_a_journal_for() {
    let mut s = Stand::printed(Class::Heavy, 8);
    to_buyer_keyed(&mut s);
    assert!(matches!(s.c.opening_seal(1), Err(Stopped::Unborn)));
}
