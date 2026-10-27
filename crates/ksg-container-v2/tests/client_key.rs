//! The client's working key in two halves — `[decision]` 23.09.
//!
//! One half is integrated into the container and never leaves; the mobile half
//! stays with the client and alone signs nothing. The ML-DSA key lives only in
//! the container; since `[decision]` 02.10 (CH-5a) it signs the container's
//! file outside, not what the client signs inside.

use frost_ed25519::rand_core::{CryptoRng, Error as RngError, RngCore};
use ksg_container_v2::client_key::{split, ClientKeyError};
use ksg_container_v2::container::{Container, Release};
use ksg_container_v2::{Button, Command, Operation, Refusal, Role, Roster};
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{sign_doc, Alg, Ed25519Signer, KeySet, Profile, SignatureSet};
use ksg_core_v2::doc::{Class, MemoFormat, Serial, Timestamp, Uri};
use ksg_core_v2::section::{StatusRecord, StatusSection};
use ksg_core_v2::status::{Blocked, Status};
use sha2::{Digest, Sha256};

/// A deterministic CSPRNG for tests only: SHA-256 over a counter.
struct TestRng(u64);

impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(32) {
            self.0 += 1;
            let block = Sha256::digest(self.0.to_be_bytes());
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl CryptoRng for TestRng {}

fn uri(s: &str) -> Uri {
    Uri::parse(s).expect("uri")
}
fn p() -> Profile {
    Profile::default()
}
fn both_algs() -> Profile {
    Profile {
        required_algs: [Alg::Ed25519, Alg::MlDsa65].into_iter().collect(),
        ..Profile::default()
    }
}
fn ed25519() -> Profile {
    Profile {
        required_algs: [Alg::Ed25519].into_iter().collect(),
        ..Profile::default()
    }
}
fn issuer() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:key:zIssuer#i1"), [11u8; 32])
}
fn owner() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:key:zOwner#o1"), [44u8; 32])
}
fn client_kid() -> Uri {
    uri("did:key:zAgent#a1")
}

const EMISSION: &str = "ksg:em:000001";
const SERIAL: Serial = Serial(7);

fn section() -> StatusSection {
    let root = ksg_core_v2::section::section_root(EMISSION, SERIAL);
    let mut r = StatusRecord {
        context: ksg_core_v2::doc::Context,
        doc_type: "StatusRecord".into(),
        v: 3,
        number: 0,
        status: Status::Printed,
        event: None,
        offset_ms: 0,
        prev: root,
        signatures: SignatureSet::default(),
    };
    r.signatures = SignatureSet::new(vec![sign_doc(&r, &issuer()).expect("sig")]);
    let a = ksg_core_v2::anchor::Attestation {
        kind: uri("urn:ksg:anchor:test"),
        subject: r.hash().expect("hash"),
        proof: b"opaque".to_vec(),
        anchored_at: Timestamp::parse("2026-09-12T00:00:00.000Z").expect("ts"),
    };
    let keys: KeySet = [issuer().public()].into_iter().collect();
    StatusSection::start(EMISSION, SERIAL, r, a, &keys, &p()).expect("section")
}

/// A container born for the client key the halves make.
fn container_for(client: ksg_core_v2::crypto::sign::PublicKey) -> Container {
    Container::assemble(
        Hash::sha256(b"container"),
        Release {
            id: EMISSION.into(),
            issued_at: Timestamp::parse("2026-09-01T00:00:00.000Z").expect("ts"),
            class: Class::Heavy,
        },
        SERIAL,
        client.clone(),
        MemoFormat::Controlled,
        section(),
        Roster::of([
            (issuer().public(), Role::Issuer),
            (owner().public(), Role::Owner),
            (client, Role::Client),
        ]),
    )
}

/// The whole round at the reader, as the client and the container play it.
fn sign_at_reader(
    c: &mut Container,
    mobile: &ksg_container_v2::client_key::MobileHalf,
    msg: &[u8],
    rng: &mut TestRng,
) -> Result<Vec<ksg_core_v2::crypto::sign::Signature>, ClientKeyError> {
    let (nonces, commitment) = mobile.commit(rng);
    let round = c.begin_signing(msg, &commitment, rng)?;
    let share = mobile.respond(nonces, &round)?;
    c.finish_signing(&share, rng)
}

#[test]
fn both_halves_together_give_an_ordinary_ed25519_signature_and_no_ml_dsa() {
    let mut rng = TestRng(1);
    let (inside, mobile) = split(client_kid(), &mut rng).expect("split");
    let mut c = container_for(inside.public().clone());
    c.integrate_client_key(inside).expect("integrated");

    let msg = b"the event's subject";
    let sigs = sign_at_reader(&mut c, &mobile, msg, &mut rng).expect("signed");
    let set = SignatureSet::new(sigs);

    // The core's own verifier, against the keys the container pinned.
    set.verify(msg, c.roster().keys(), &ed25519())
        .expect("verifies as an ordinary signature");
    // CH-5a: no ML-DSA on what the client signs — it signs the file outside.
    assert_eq!(set.len(), 1);
    assert!(set.verify(msg, c.roster().keys(), &both_algs()).is_err());
    // And the signature does not carry over to other bytes.
    assert!(set
        .verify(b"something else", c.roster().keys(), &p())
        .is_err());
}

#[test]
fn the_client_alone_is_one_party() {
    let mut rng = TestRng(2);
    let (inside, mobile) = split(client_kid(), &mut rng).expect("split");
    let mut c = container_for(inside.public().clone());
    c.integrate_client_key(inside).expect("integrated");

    let body = b"attach";
    let sigs = sign_at_reader(&mut c, &mobile, body, &mut rng).expect("signed");
    // Initiation takes the client AND the owner (E-4): the client alone
    // leaves the owner's seat empty. (Until CH-29 the
    // example was attaching an artefact, which no longer seats the owner.)
    let cmd = Command {
        op: Operation::Initiate,
        payload: Vec::new(),
        signatures: SignatureSet::new(sigs.clone()),
        signed_bytes: body.to_vec(),
    };
    let got = cmd.press(
        Button::Signatures,
        Status::BuyerKeyed,
        Blocked::No,
        c.roster(),
        c.roster().keys(),
        &p(),
    );
    assert!(
        matches!(
            got,
            Err(ref r) if matches!(r.reason, Refusal::NotEnoughSignatures { .. } | Refusal::OneParty(_))
        ),
        "{got:?}"
    );

    // With the owner it goes through.
    let mut with_owner = sigs;
    with_owner.push(owner().sign(body));
    let cmd = Command {
        signatures: SignatureSet::new(with_owner),
        ..cmd
    };
    cmd.press(
        Button::Signatures,
        Status::BuyerKeyed,
        Blocked::No,
        c.roster(),
        c.roster().keys(),
        &ed25519(),
    )
    .expect("client and owner");
}

#[test]
fn a_mobile_half_of_another_key_does_not_sign_with_this_container() {
    let mut rng = TestRng(3);
    let (inside, _mine) = split(client_kid(), &mut rng).expect("split");
    let (_, stranger) = split(client_kid(), &mut rng).expect("another split");
    let mut c = container_for(inside.public().clone());
    c.integrate_client_key(inside).expect("integrated");

    let got = sign_at_reader(&mut c, &stranger, b"msg", &mut rng);
    assert!(matches!(got, Err(ClientKeyError::Frost(_))), "{got:?}");
}

#[test]
fn a_half_is_integrated_once_and_only_into_its_own_container() {
    let mut rng = TestRng(4);
    let (inside, _) = split(client_kid(), &mut rng).expect("split");
    let (other, _) = split(client_kid(), &mut rng).expect("split");
    let (again, _) = split(client_kid(), &mut rng).expect("split");

    let mut c = container_for(inside.public().clone());
    assert_eq!(c.integrate_client_key(other), Err(ClientKeyError::OtherKey));
    c.integrate_client_key(inside).expect("its own half");
    assert_eq!(
        c.integrate_client_key(again),
        Err(ClientKeyError::AlreadyIntegrated)
    );
}

#[test]
fn no_round_no_signature_and_a_round_is_used_once() {
    let mut rng = TestRng(5);
    let (inside, mobile) = split(client_kid(), &mut rng).expect("split");
    let mut c = container_for(inside.public().clone());

    // Before integration the container has nothing to sign with.
    let (_, commitment) = mobile.commit(&mut rng);
    assert_eq!(
        c.begin_signing(b"m", &commitment, &mut rng).err(),
        Some(ClientKeyError::NoHalf)
    );
    c.integrate_client_key(inside).expect("integrated");

    let (nonces, commitment) = mobile.commit(&mut rng);
    let round = c.begin_signing(b"m", &commitment, &mut rng).expect("round");
    let share = mobile.respond(nonces, &round).expect("share");
    c.finish_signing(&share, &mut rng).expect("signed");
    assert_eq!(
        c.finish_signing(&share, &mut rng),
        Err(ClientKeyError::NoRound),
        "the same share does not sign twice"
    );
}

#[test]
fn a_round_between_two_processes_goes_through_bytes_only() {
    // Item P-5 of the MVP plan (`[decision]` 24.09, variant A): the mobile half
    // lives in a process of its own. Everything that crosses — the half as the
    // client keeps it, the commitment, the round, the share — crosses as bytes.
    use ksg_container_v2::client_key::{Commitment, MobileHalf, MobileShare, SigningRound};
    let mut rng = TestRng(6);
    let (inside, mobile) = split(client_kid(), &mut rng).expect("split");
    let mut c = container_for(inside.public().clone());
    c.integrate_client_key(inside).expect("integrated");

    // The client's own file, read back in another process.
    let file = mobile.to_bytes().expect("mobile half bytes");
    let mobile = MobileHalf::from_bytes(&file).expect("mobile half back");
    assert_eq!(mobile.kid(), &client_kid());

    let msg = b"a page, signed across a pipe";
    let (nonces, commitment) = mobile.commit(&mut rng);
    let commitment = Commitment::from_bytes(&commitment.to_bytes().unwrap()).unwrap();
    let round = c.begin_signing(msg, &commitment, &mut rng).expect("round");
    let round = SigningRound::from_bytes(&round.to_bytes().unwrap()).unwrap();
    assert_eq!(round.message(), msg, "the mobile side sees what it signs");
    let share = mobile.respond(nonces, &round).expect("share");
    let share = MobileShare::from_bytes(&share.to_bytes()).unwrap();
    let sigs = c.finish_signing(&share, &mut rng).expect("signed");

    SignatureSet::new(sigs)
        .verify(msg, c.roster().keys(), &ed25519())
        .expect("an ordinary signature, as in one process");
    assert!(MobileHalf::from_bytes(b"garbage").is_err());
    assert!(Commitment::from_bytes(b"garbage").is_err());
}

/// E-19 (owner's decisions 15.10): the mobile half alone signs the loss of
/// its container, under its own public share — an ordinary Ed25519 signature
/// any verifier checks; the share is committed to by a hash at initiation.
#[test]
fn the_mobile_half_alone_signs_the_loss_under_its_share() {
    use ksg_container_v2::client_key::{share_commitment, split, LOST_TAG};
    let mut rng = TestRng(41);
    let kid = ksg_core_v2::doc::Uri::parse("did:key:zClientLoss").unwrap();
    let (_container, mobile) = split(kid, &mut rng).unwrap();
    let share = mobile.share_public().unwrap();
    let mut msg = LOST_TAG.to_vec();
    msg.extend_from_slice(&[7u8; 32]);
    let sig = mobile.sign_alone(&msg, &mut rng).unwrap();

    let vk = ed25519_dalek::VerifyingKey::from_bytes(&share).unwrap();
    let s = ed25519_dalek::Signature::from_bytes(&sig);
    assert!(vk.verify_strict(&msg, &s).is_ok());
    // Another container's template: the same signature does not hold.
    let mut other = LOST_TAG.to_vec();
    other.extend_from_slice(&[8u8; 32]);
    assert!(vk.verify_strict(&other, &s).is_err());
    // The commitment pins this share and no other.
    assert_ne!(share_commitment(&share), share_commitment(&[0u8; 32]));
    assert_eq!(share_commitment(&share), share_commitment(&share));
}

/// The debug print of every piece of the client's key names it and shows
/// nothing secret (mutation run of FROST, 16.10: these prints were read by no
/// test — and the dangerous change is the opposite one, a print of the key).
#[test]
fn debug_prints_name_the_piece_and_hide_the_secret() {
    use ksg_container_v2::client_key::{ContainerKeygen, MobileKeygen};
    let mut rng = TestRng(41);
    let (inside, mobile) = split(client_kid(), &mut rng).expect("split");
    let shown = format!("{mobile:?}");
    assert_eq!(shown, format!("MobileHalf(kid={})", client_kid().as_str()));
    let shown = format!("{inside:?}");
    assert!(shown.starts_with("ContainerHalf"), "{shown}");
    assert!(shown.contains(client_kid().as_str()), "{shown}");

    let (nonces, _) = mobile.commit(&mut rng);
    assert_eq!(format!("{nonces:?}"), "MobileNonces(..)");

    let (keygen, hello) = MobileKeygen::start(client_kid(), &mut rng).expect("start");
    assert_eq!(
        format!("{keygen:?}"),
        format!("MobileKeygen(kid={})", client_kid().as_str())
    );
    let (inner, reply) = ContainerKeygen::answer(client_kid(), &hello, &mut rng).expect("answer");
    assert_eq!(
        format!("{inner:?}"),
        format!("ContainerKeygen(kid={})", client_kid().as_str())
    );
    assert_eq!(format!("{reply:?}"), "KeygenReply(..)");
    let (_, _, fin) = keygen.finish(&reply).expect("finish");
    assert_eq!(format!("{fin:?}"), "KeygenFinish(..)");
}

/// `MobileHalf::client_public` is the client's key the half belongs to — what
/// a declaration of loss names the client by (E-19).
#[test]
fn the_half_names_the_client_key_it_belongs_to() {
    use ksg_container_v2::client_key::{ContainerKeygen, MobileKeygen};
    let mut rng = TestRng(42);
    let (keygen, hello) = MobileKeygen::start(client_kid(), &mut rng).expect("start");
    let (inner, reply) = ContainerKeygen::answer(client_kid(), &hello, &mut rng).expect("answer");
    let (half, public, fin) = keygen.finish(&reply).expect("finish");
    let container_half = inner.finish(&fin).expect("container half");
    assert_eq!(container_half.public(), &public);
    let bytes = half.client_public().expect("public");
    assert_eq!(ksg_core_v2::crypto::sign::b64_encode(&bytes), public.key);
    let (_, other) = split(client_kid(), &mut rng).expect("another key");
    assert_ne!(other.client_public().expect("public"), bytes);
}
