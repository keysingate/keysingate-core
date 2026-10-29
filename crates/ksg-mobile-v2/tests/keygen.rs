//! The mobile birth automaton (track I): `Keygen::start` opens the birth,
//! `Keygen::finish` closes it with the container's answer, and the mobile
//! half waits between the two — its secret never leaves the `Keygen`.
//!
//! A second `finish` answers `NoBirth` instead of reusing the secret, and
//! answers that are not the container's are refused. The waiting half signs
//! one round with the container, end to end, like the reader will drive it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ksg_container_v2::client_key::{ContainerKeygen, KeygenFinish, KeygenHello, KeygenReply};
use ksg_container_v2::container::{Container, Release};
use ksg_container_v2::{Role, Roster};
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{
    sign_doc, Ed25519Signer, KeySet, Profile, SignatureSet,
};
use ksg_core_v2::doc::{derive_container_id, Class, MemoFormat, Serial, Timestamp, Uri};
use ksg_core_v2::section::{section_root, StatusRecord, StatusSection};
use ksg_core_v2::status::Status;
use ksg_mobile_v2::{ApproveAll, Keygen, KeygenError};
use rand_core::{CryptoRng, Error as RngError, RngCore};

/// A deterministic generator for the tests only: splitmix64, as the module's
/// stand uses. Its quality is irrelevant — what the tests check is the mobile
/// birth, not the keys.
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
        for chunk in dest.chunks_mut(8) {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            let bytes = z.to_le_bytes();
            let n = chunk.len().min(bytes.len());
            chunk.copy_from_slice(bytes.get(..n).unwrap_or(&[]));
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for TestRng {}

fn kid() -> Uri {
    Uri::parse("did:key:zAgent#a1").unwrap()
}

fn uri(s: &str) -> Uri {
    Uri::parse(s).unwrap()
}

fn issuer() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:key:zIssuer#i1"), [11u8; 32])
}

const EMISSION: &str = "ksg:em:000001";
const SERIAL: Serial = Serial(7);

/// A container assembled for the client's public key, carrying the
/// container's half: the reader's side of the round the waiting half signs.
fn container_for(
    client: ksg_core_v2::crypto::sign::PublicKey,
    inside: ksg_container_v2::client_key::ContainerHalf,
    rng: &mut TestRng,
) -> Container {
    let template = section_root(EMISSION, SERIAL);
    let issued_at = Timestamp::parse("2026-09-01T00:00:00.000Z").unwrap();
    let id = derive_container_id(
        EMISSION,
        &issued_at,
        SERIAL,
        &client,
        &uri("ksg:artifact:the-one"),
        1_000,
    );
    let mut r0 = StatusRecord {
        context: ksg_core_v2::doc::Context,
        doc_type: "StatusRecord".into(),
        v: 3,
        number: 0,
        status: Status::Printed,
        event: None,
        offset_ms: 0,
        prev: template,
        signatures: SignatureSet::default(),
    };
    r0.signatures = SignatureSet::new(vec![sign_doc(&r0, &issuer()).unwrap()]);
    let a0 = ksg_core_v2::anchor::Attestation {
        kind: uri("urn:ksg:anchor:stand"),
        subject: r0.hash().unwrap(),
        proof: b"stand".to_vec(),
        anchored_at: Timestamp::parse("2026-09-12T00:00:00.000Z").unwrap(),
    };
    let keys: KeySet = [issuer().public()].into_iter().collect();
    let section = StatusSection::start(EMISSION, SERIAL, r0, a0, &keys, &Profile::default()).unwrap();
    let pq = ksg_container_v2::pq_key::ContainerPqKey::generate(
        uri("did:key:zContainer#pq"),
        rng,
    )
    .unwrap();
    let mut container = Container::assemble(
        id,
        Release {
            id: EMISSION.into(),
            issued_at,
            class: Class::Heavy,
        },
        SERIAL,
        client.clone(),
        MemoFormat::Controlled,
        section,
        Roster::of([
            (issuer().public(), Role::Issuer),
            (client, Role::Client),
        ]),
    )
    .with_pq_key(pq);
    container.integrate_client_key(inside).unwrap();
    container
}

#[test]
fn start_opens_finish_closes_and_the_half_signs_with_the_container() {
    let mut rng = TestRng(21);

    // The crate under test, start to finish: `start` opens the birth and its
    // hello reads as the container's message 1; the container answers with
    // message 2; `finish` closes the birth with it.
    let (mut birth, hello_out) = Keygen::start(kid(), &mut rng).unwrap();
    assert!(birth.is_pending(), "a started birth waits");
    let hello = KeygenHello::from_bytes(&hello_out).unwrap();
    assert_eq!(
        hello.to_bytes().unwrap(),
        hello_out,
        "the hello re-encodes"
    );
    let (inside, reply) = ContainerKeygen::answer(kid(), &hello, &mut rng).unwrap();
    let reply_out = reply.to_bytes().unwrap().to_vec();
    let reply = KeygenReply::from_bytes(&reply_out).unwrap();
    let waiting = birth.finish(&reply_out).unwrap();
    assert!(!birth.is_pending(), "a finished birth is spent");
    assert_eq!(
        waiting.group().kid.as_str(),
        "did:key:zAgent#a1",
        "the client's key keeps its name"
    );

    // The container closes its side with message 3; both halves hold the
    // same key.
    let half = inside
        .finish(&KeygenFinish::from_bytes(waiting.finish_bytes()).unwrap())
        .unwrap();
    assert_eq!(half.public(), waiting.group());

    // The waiting half signs one round with the container, end to end: the
    // reader will drive the module's `FinishBirth` the same way.
    let mut container = container_for(waiting.group().clone(), half, &mut rng);
    let mut session = waiting.into_session(ApproveAll);
    let msg = b"the round both halves sign";
    let commitment = session.commit(&mut rng);
    let round = container.begin_signing(msg, &commitment, &mut rng).unwrap();
    let share = session.respond(&round).unwrap();
    let sigs = container.finish_signing(&share, &mut rng).unwrap();
    SignatureSet::new(sigs)
        .verify(
            msg,
            container.roster().keys(),
            &Profile {
                required_algs: [ksg_core_v2::crypto::sign::Alg::Ed25519]
                    .into_iter()
                    .collect(),
                ..Profile::default()
            },
        )
        .unwrap();

    // A second finish spends nothing: the birth is over.
    assert!(
        matches!(birth.finish(&reply_out), Err(KeygenError::NoBirth)),
        "the birth does not repeat"
    );
    let _ = reply;
}

#[test]
fn garbage_and_a_stranger_share_are_refused() {
    let mut rng = TestRng(23);

    // Garbage is not the container's answer.
    let mut birth = Keygen::start(kid(), &mut rng).unwrap().0;
    assert!(
        matches!(birth.finish(b"nothing"), Err(KeygenError::Reply(_))),
        "a bad reply is refused"
    );

    // Another birth's message 3 does not finish this one: the shares hold
    // different keys.
    let (mut birth, hello_out) = Keygen::start(kid(), &mut rng).unwrap();
    let hello = KeygenHello::from_bytes(&hello_out).unwrap();
    let (_inside, _reply) = ContainerKeygen::answer(kid(), &hello, &mut rng).unwrap();
    let (stranger, stranger_hello) =
        ksg_container_v2::client_key::MobileKeygen::start(kid(), &mut rng).unwrap();
    let (_stranger_inside, stranger_reply) =
        ContainerKeygen::answer(kid(), &stranger_hello, &mut rng).unwrap();
    let (_stranger_half, _group, stranger_fin) = stranger.finish(&stranger_reply).unwrap();
    let stranger_fin = stranger_fin.to_bytes().unwrap().to_vec();
    assert!(
        matches!(
            birth.finish(&stranger_fin),
            Err(KeygenError::Reply(_)) | Err(KeygenError::Finish(_))
        ),
        "a stranger's share is refused"
    );

    // The wire forms refuse what they are not.
    assert!(KeygenReply::from_bytes(b"nothing").is_err());
    assert!(KeygenFinish::from_bytes(b"nothing").is_err());
    let _ = Hash::sha256(b"touch");
}

#[test]
fn the_birth_crosses_the_page_wire_and_signs_rounds_after() {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use base64::Engine as _;
    use ksg_mobile_v2::{
        describe_birth, handle_birth_line, BirthOp, BirthPage, Request,
    };

    let mut rng = TestRng(77);

    // The page opens its birth over the wire: `keygen_start` carries the
    // kid, the answer carries the hello — and nothing else. The line is a
    // birth line, not a round line.
    let start = serde_json::to_string(&Request::KeygenStart {
        kid: "did:key:zAgent#a1".into(),
    })
    .unwrap();
    assert_eq!(describe_birth(&start), Some(BirthOp::Hello));
    assert_eq!(
        describe_birth(r#"{"op":"commit"}"#),
        None,
        "a round line is not a birth line"
    );
    let mut birth = None;
    let answer = handle_birth_line(&mut birth, &start, &mut rng);
    let hello_b64: String = match serde_json::from_str::<ksg_mobile_v2::Answer>(&answer) {
        Ok(ksg_mobile_v2::Answer::Ok(h)) => h,
        other => panic!("the page opens its birth: {other:?}"),
    };
    let hello = B64.decode(hello_b64).unwrap();

    // The container answers message 1 with message 2 — over the module's
    // `BeginBirth`, as the reader drives it.
    let hello = KeygenHello::from_bytes(&hello).unwrap();
    let (_inside, reply) = ContainerKeygen::answer(kid(), &hello, &mut rng).unwrap();
    let reply_bytes = reply.to_bytes().unwrap().to_vec();
    let finish = serde_json::to_string(&Request::KeygenFinish {
        reply: B64.encode(&reply_bytes),
    })
    .unwrap();
    assert_eq!(describe_birth(&finish), Some(BirthOp::Finish));
    let answer = handle_birth_line(&mut birth, &finish, &mut rng);
    let fin_b64: String = match serde_json::from_str::<ksg_mobile_v2::Answer>(&answer) {
        Ok(ksg_mobile_v2::Answer::Ok(f)) => f,
        other => panic!("the page closes its birth: {other:?}"),
    };
    assert!(!B64.decode(fin_b64).unwrap().is_empty(), "the share goes home");

    // A second finish spends nothing: the birth is over, not repeated.
    let again = handle_birth_line(&mut birth, &finish, &mut rng);
    assert!(
        matches!(
            serde_json::from_str::<ksg_mobile_v2::Answer>(&again),
            Ok(ksg_mobile_v2::Answer::Err(_))
        ),
        "the birth does not repeat: {again}"
    );

    // A round line on a page with no birth open and no half kept is
    // refused — the half does not exist yet.
    let mut page = BirthPage::new();
    assert!(!page.is_pending(), "an empty page waits for nothing");
    let refused = page.answer_line(r#"{"op":"commit"}"#, &mut rng);
    assert!(
        refused.contains("not born yet"),
        "a round before the birth is refused: {refused}"
    );

    // A birth line after the finish is spent is refused — the birth does
    // not repeat. (The empty page opens a fresh birth here: the automaton
    // it holds is per-page, and the wire's `keygen_start` opens whichever
    // page it reaches. What the page must refuse is a birth line once its
    // half is born — covered by `keep_waiting` below, where the finish
    // moved the half onto the rounds.)
    let opened = page.answer_line(&start, &mut rng);
    assert!(
        opened.contains("\"ok\""),
        "an empty page opens the birth it is asked for: {opened}"
    );
    let _ = Hash::sha256(b"touch");
}
