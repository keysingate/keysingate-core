//! Sealed storage on the stand — item P-4 of the MVP plan. A container is
//! written to bytes in the middle of its life, read back, and goes on working.

mod stand;

use ksg_container_v2::container::Evidence;
use ksg_container_v2::layers::Level;
use ksg_container_v2::store::{StoreError, STORE_SIZE};
use ksg_container_v2::{Attachment, Container, Kind, Operation as Op, Status, Where, Work};
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::SignatureSet;
use ksg_core_v2::doc::Class;
use stand::EventKind;
use stand::{uri, Page, Stand, Who};

/// For the MVP, the holder's layer key (`[decision]` 23.09); any 32 bytes here.
const KEY: [u8; 32] = [7u8; 32];

fn to_work(s: &mut Stand) {
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
    s.press(
        Op::Initiate,
        &[Who::Client, Who::Owner],
        Evidence::Initiation { at: Where::Inside },
        Page::None,
    )
    .expect("initiation");
    s.press(
        Op::OpenJournal,
        &[Who::Client],
        Evidence::None,
        Page::Opening,
    )
    .expect("journal");
}

fn record_work(s: &mut Stand, did: &str) {
    let mut w = Work {
        container: *s.c.id(),
        under: None,
        did: did.into(),
        signatures: SignatureSet::default(),
    };
    let subject = w.subject();
    w.signatures = SignatureSet::new(s.client_signs(subject.as_bytes()));
    s.press(
        Op::RecordWork,
        &[Who::Client],
        Evidence::Work {
            order: None,
            work: Box::new(w),
        },
        Page::Of(EventKind::Work),
    )
    .expect("record of work");
}

fn attach(s: &mut Stand) {
    let a = Attachment {
        artifact: uri(stand::ARTIFACT),
        kind: Kind::Media {
            mime: "image/png".into(),
        },
        content_hash: Hash::sha256(b"the artefact"),
        size: 12,
        name: "artefact.png".into(),
        derived_from: vec![],
        offset_ms: stand::OFFSET,
    };
    s.press(
        Op::AttachArtifactOrRights,
        &[Who::Client, Who::Owner],
        Evidence::Artifact(Box::new(a)),
        Page::Of(EventKind::ArtifactOrRights),
    )
    .expect("artefact");
}

/// Writes the stand's container to bytes and puts the one read back in its
/// place.
fn round_trip(s: &mut Stand) -> Vec<u8> {
    let bytes = s.c.seal_to_bytes(&KEY, &mut s.rng).expect("sealed");
    let id = s.c.template_id();
    s.c = Container::open_sealed(&bytes, &id, &KEY).expect("opened");
    bytes
}

#[test]
fn a_container_in_work_goes_to_bytes_and_comes_back_whole() {
    let mut s = Stand::new(Class::Heavy, 21);
    to_work(&mut s);
    record_work(&mut s, "first");
    attach(&mut s);
    let (status, head, seals) = (s.c.status(), s.c.head(), s.c.artifact_seals().len());

    round_trip(&mut s);

    assert_eq!(s.c.status(), status);
    assert_eq!(s.c.status(), Status::InWork);
    assert_eq!(s.c.head(), head, "the journal is the same, page for page");
    assert_eq!(s.c.artifact_seals().len(), seals);
}

#[test]
fn a_restored_container_goes_on_working_and_its_half_still_signs() {
    let mut s = Stand::new(Class::Heavy, 22);
    to_work(&mut s);
    record_work(&mut s, "before");
    round_trip(&mut s);
    // The container's half of the client's key came back: the client signs
    // with the restored container, and the next page goes in.
    record_work(&mut s, "after");
    assert_eq!(s.c.head().expect("a head").counter, 2);
}

#[test]
fn a_container_is_the_same_size_on_the_first_day_and_after_work() {
    let mut s = Stand::new(Class::Heavy, 23);
    let fresh = s.c.seal_to_bytes(&KEY, &mut s.rng).unwrap().len();
    to_work(&mut s);
    for i in 0..5 {
        record_work(&mut s, &format!("work {i}"));
    }
    let worked = s.c.seal_to_bytes(&KEY, &mut s.rng).unwrap().len();
    assert_eq!(fresh, worked, "the size says nothing about the work");
    assert!(worked > STORE_SIZE, "padded to the constant size");
}

#[test]
fn another_key_another_container_or_one_changed_byte_does_not_open() {
    let mut s = Stand::new(Class::Heavy, 24);
    to_work(&mut s);
    let bytes = s.c.seal_to_bytes(&KEY, &mut s.rng).unwrap();
    let id = s.c.template_id();

    assert!(matches!(
        Container::open_sealed(&bytes, &id, &[8u8; 32]),
        Err(StoreError::Pack(_))
    ));
    assert!(matches!(
        Container::open_sealed(&bytes, &Hash::sha256(b"another container"), &KEY),
        Err(StoreError::Pack(_))
    ));
    // A byte of the ciphertext.
    let mut changed = bytes.clone();
    changed[b"ksg:store:v4".len() + 12 + 100] ^= 1;
    assert!(matches!(
        Container::open_sealed(&changed, &id, &KEY),
        Err(StoreError::Pack(_))
    ));
    assert_eq!(
        Container::open_sealed(b"not a container", &id, &KEY).unwrap_err(),
        StoreError::NotAContainer
    );
}

#[test]
fn an_open_signing_round_is_never_stored() {
    // FROST nonces are single-use; written down and used again they would give
    // the container's half away. A round open at sealing time is gone after.
    let mut s = Stand::new(Class::Heavy, 25);
    to_work(&mut s);
    let (nonces, commitment) = s.mobile.commit(&mut s.rng);
    let round =
        s.c.begin_signing(b"message", &commitment, &mut s.rng)
            .expect("round");
    let share = s.mobile.respond(nonces, &round).expect("share");

    round_trip(&mut s);

    assert_eq!(
        s.c.finish_signing(&share, &mut s.rng),
        Err(ksg_container_v2::client_key::ClientKeyError::NoRound)
    );
}

#[test]
fn a_printed_container_without_a_journal_round_trips_too() {
    let mut s = Stand::new(Class::Light, 26);
    round_trip(&mut s);
    assert_eq!(s.c.status(), Status::Printed);
    assert!(s.c.head().is_none());
}

/// Opens the sealed bytes with the key the test holds, lets `f` change the
/// state, seals it back the same way and opens it as a container. What a
/// holder with the layer key could do to their own file (MVP boundary §3.2),
/// and what the replay on opening must catch.
fn tampered(
    s: &mut Stand,
    f: impl FnOnce(&mut serde_json::Value),
) -> Result<Container, StoreError> {
    use ksg_container_v2::{ChaCha20Poly1305Aead, Deflate, Packer};
    let id = s.c.template_id();
    let bytes = s.c.seal_to_bytes(&KEY, &mut s.rng).expect("sealed");
    let magic = b"ksg:store:v4";
    let aad = [&magic[..], id.as_bytes()].concat();
    // magic ‖ nonce ‖ ciphertext ‖ outer signature ‖ its length (u32 BE).
    let body = &bytes[magic.len()..bytes.len() - 4];
    let sig_len = u32::from_be_bytes(bytes[bytes.len() - 4..].try_into().unwrap()) as usize;
    let (nonce, sealed) = body[..body.len() - sig_len].split_at(12);
    let p = Packer::new(
        ChaCha20Poly1305Aead,
        Deflate {
            limit: ksg_container_v2::store::MAX_STATE,
        },
        STORE_SIZE,
    );
    let plain = p.open(sealed, &KEY, nonce, &aad).expect("opens");
    let mut state: serde_json::Value = serde_json::from_slice(&plain).expect("json");
    f(&mut state);
    let plain = serde_json::to_vec(&state).unwrap();
    let noise = vec![0u8; p.noise_needed(&plain)];
    let resealed = p.seal(&plain, &noise, &KEY, nonce, &aad).expect("seals");
    // Re-encrypted under the key the holder has, without the container's
    // outer signature: the replay on opening and the signature check stand
    // behind each other.
    let out = [&magic[..], nonce, &resealed, &0u32.to_be_bytes()[..]].concat();
    Container::open_sealed(&out, &id, &KEY)
}

fn restore_error(r: Result<Container, StoreError>) -> String {
    match r {
        Err(StoreError::Restore(m)) => m,
        Err(other) => panic!("another error: {other:?}"),
        Ok(_) => panic!("a tampered state opened"),
    }
}

#[test]
fn a_file_changed_under_the_key_does_not_open() {
    let mut s = Stand::new(Class::Heavy, 41);
    to_work(&mut s);
    record_work(&mut s, "a step");
    // Unchanged state, re-encrypted under the holder's key: the replay passes,
    // and the file still does not open — the container did not sign it (CH-5a).
    assert_eq!(
        tampered(&mut s, |_| {}).unwrap_err(),
        StoreError::Outer("missing")
    );
    // Status record 0 rewritten: its issuer signature fails.
    let m = restore_error(tampered(&mut s, |v| {
        v["status"][0][0]["offset_ms"] = 99.into()
    }));
    assert!(m.starts_with("status"), "{m}");
    // A later status record rewritten.
    let m = restore_error(tampered(&mut s, |v| {
        v["status"][1][0]["offset_ms"] = 99_999.into()
    }));
    assert!(m.starts_with("status"), "{m}");
    // A journal page rewritten: the seal the pages give is no longer the one
    // the client signed.
    let m = restore_error(tampered(&mut s, |v| {
        v["journal"]["export"]["pages"][1]["offset_ms"] = 1.into();
    }));
    assert!(m.starts_with("journal"), "{m}");
    // The container's half of the client key replaced by nothing.
    let m = restore_error(tampered(&mut s, |v| {
        v["client_half"]["signing_share"] = serde_json::json!([])
    }));
    assert!(m.starts_with("client half"), "{m}");
}

#[test]
fn bytes_that_are_not_a_mobile_half_are_named_so() {
    use ksg_container_v2::client_key::MobileHalf;
    // A key identifier that is not UTF-8.
    assert!(MobileHalf::from_bytes(&[0, 0, 0, 1, 0xff]).is_err());
    // UTF-8, but not a URI.
    assert!(MobileHalf::from_bytes(&[0, 0, 0, 3, b' ', b' ', b' ']).is_err());
    // A key identifier and no key package.
    let kid = b"did:key:zA#a1";
    let mut b = (kid.len() as u32).to_be_bytes().to_vec();
    b.extend_from_slice(kid);
    b.extend_from_slice(&[1, 2, 3]);
    assert!(MobileHalf::from_bytes(&b).is_err());
    // Shorter than its length prefix.
    assert!(MobileHalf::from_bytes(&[0, 0, 0, 9, b'a']).is_err());
    assert!(MobileHalf::from_bytes(&[0, 0]).is_err());
}

/// The worst case the store must hold (CH-12, `1+1000+100+2`): the thousand
/// working pages written through the buttons, every one carrying its full
/// 2 KB, in records of 99 pages and a service page; the hundred pages of
/// transfers and the two of the coupling, which no stand scenario reaches, by
/// their measured size (core v1 `ksg-journal` test `a_full_journal_by_zone_measured`:
/// 0.70 MiB with anchors the size of a real Solana proof), and the twelve
/// pages an expert may hold. It must fit [`STORE_SIZE`].
#[test]
fn a_full_journal_fits_the_store() {
    use ksg_container_v2::container::JournalWrite;
    use ksg_core_v2::journal::{Piece, RecordKind, RecordMeta, BATCH_CONTENT_PAGES, PAGE_BYTES};

    const TRANSFERS_AND_COUPLING: usize = 740 * 1024;
    let mut s = Stand::new(Class::Heavy, 45);
    to_work(&mut s);
    let mut n = 0u8;
    while s.c.pages() < 1 + 1000 {
        let left = 1 + 1000 - s.c.pages();
        let pieces = left.min(BATCH_CONTENT_PAGES + 1).saturating_sub(1).max(1);
        n += 1;
        s.clock_ms += 1_000;
        let draft =
            s.c.draft_record(
                (0..pieces)
                    .map(|i| {
                        let mut v = vec![n; PAGE_BYTES];
                        v[..8].copy_from_slice(&(i as u64).to_be_bytes());
                        Piece::Inline(v)
                    })
                    .collect(),
                RecordMeta {
                    kind: RecordKind::Work,
                    ..RecordMeta::default()
                },
                s.clock_ms,
            )
            .expect("draft");
        let write: JournalWrite = s.seal_draft(draft);
        let mut w = Work {
            container: *s.c.id(),
            under: None,
            did: format!("record {n}"),
            signatures: SignatureSet::default(),
        };
        let subject = w.subject();
        w.signatures = SignatureSet::new(s.client_signs(subject.as_bytes()));
        s.press_write(
            Op::RecordWork,
            &[Who::Client],
            Evidence::Work {
                order: None,
                work: Box::new(w),
            },
            Some(write),
        )
        .expect("a record of 99 pages");
    }
    // A page an expert may be shown: the heaviest, with its proof and seal.
    s.press(
        Op::ExportPoint,
        &[Who::Owner],
        Evidence::Point { number: 1 },
        Page::None,
    )
    .expect("point");
    let point = serde_json::to_vec(&s.c.take_point().expect("the page"))
        .expect("json")
        .len();
    // The sealed zones at their width (18.10 "A"): the release, the packet and
    // all hundred and four chain positions.
    {
        use frost_ed25519::rand_core::RngCore as _;
        use ksg_container_v2::layout::{ZONE_BYTES, ZONE_POSITIONS};
        let mut noise = vec![0u8; ZONE_POSITIONS * ZONE_BYTES];
        frost_ed25519::rand_core::OsRng.fill_bytes(&mut noise);
        s.c.lay_zone_noise(&noise).expect("laid once");
    }
    let used = s.c.stored_len().expect("encodes");
    // And a full ring of "who looked" notices, each at its bound.
    let views = ksg_container_v2::view::NOTICE_RING * ksg_container_v2::view::MAX_NOTICE_BYTES;
    let worst = used + TRANSFERS_AND_COUPLING + 12 * point + views;
    println!(
        "FULL CONTAINER: work zone written {used} bytes; worst case {worst} bytes ({:.2} MiB) of {STORE_SIZE}",
        worst as f64 / 1_048_576.0
    );
    // The bound is on the state **before** compression: what is padded is
    // never larger than that by more than DEFLATE's framing, so the bound
    // holds for content that does not compress at all.
    assert!(worst <= STORE_SIZE, "{worst} > {STORE_SIZE}");
    // And it goes to bytes and back, full.
    let bytes = s.c.seal_to_bytes(&KEY, &mut s.rng).expect("fits");
    Container::open_sealed(&bytes, &s.c.template_id(), &KEY).expect("opens");
}

/// Audit of 30.09, O-2: compression before the padding takes back the third
/// base64 adds — measured on content that does **not** compress (bytes of a
/// hash chain), so the gain is the format's, not the content's.
#[test]
fn compression_takes_back_what_base64_adds_on_incompressible_pages() {
    use ksg_container_v2::container::JournalWrite;
    use ksg_core_v2::crypto::hash::Hash;
    use ksg_core_v2::journal::{Piece, RecordKind, RecordMeta, PAGE_BYTES};

    let mut s = Stand::new(Class::Heavy, 46);
    to_work(&mut s);
    let mut seed = Hash::sha256(b"incompressible");
    for _ in 0..3 {
        s.clock_ms += 1_000;
        let pieces: Vec<Piece> = (0..40)
            .map(|_| {
                let mut v = Vec::with_capacity(PAGE_BYTES);
                while v.len() < PAGE_BYTES {
                    seed = Hash::sha256(seed.as_bytes());
                    v.extend_from_slice(seed.as_bytes());
                }
                v.truncate(PAGE_BYTES);
                Piece::Inline(v)
            })
            .collect();
        let draft =
            s.c.draft_record(
                pieces,
                RecordMeta {
                    kind: RecordKind::Work,
                    ..RecordMeta::default()
                },
                s.clock_ms,
            )
            .expect("draft");
        let write: JournalWrite = s.seal_draft(draft);
        let mut w = Work {
            container: *s.c.id(),
            under: None,
            did: "random pages".into(),
            signatures: SignatureSet::default(),
        };
        let subject = w.subject();
        w.signatures = SignatureSet::new(s.client_signs(subject.as_bytes()));
        s.press_write(
            Op::RecordWork,
            &[Who::Client],
            Evidence::Work {
                order: None,
                work: Box::new(w),
            },
            Some(write),
        )
        .expect("a record of random pages");
    }
    let plain = s.c.stored_len().expect("encodes");
    let packed = s.c.stored_packed_len().expect("compresses");
    println!(
        "INCOMPRESSIBLE PAGES: {plain} bytes as JSON, {packed} compressed ({:.0} %)",
        packed as f64 * 100.0 / plain as f64
    );
    assert!(
        packed * 100 <= plain * 80,
        "{packed} of {plain}: base64's third should come back"
    );
    // And the container still goes to bytes and back.
    let bytes = s.c.seal_to_bytes(&KEY, &mut s.rng).expect("fits");
    Container::open_sealed(&bytes, &s.c.template_id(), &KEY).expect("opens");
}

/// Decompression is bounded: a small input that would inflate past the limit
/// is refused, not allocated.
#[test]
fn a_decompression_bomb_is_refused() {
    use ksg_container_v2::{Compressor, Deflate};
    let limit = ksg_container_v2::store::MAX_STATE;
    let bomb = Deflate { limit }.compress(&vec![0u8; limit + 1]);
    assert!(bomb.len() < 64 * 1024, "a bomb is small: {}", bomb.len());
    assert!(Deflate { limit }.decompress(&bomb).is_err());
    let fine = Deflate { limit }.compress(&vec![0u8; 1024]);
    assert_eq!(
        Deflate { limit }.decompress(&fine).unwrap(),
        vec![0u8; 1024]
    );
}

/// CH-5a (`[decision]` 02.10), CH-5b: the container signs its whole file
/// outside with its own post-quantum key, laid in at printing; anyone holding
/// the file and that key can check it without the layer key, and a file the
/// container did not write does not open.
#[test]
fn the_container_signs_its_file_outside_with_its_post_quantum_key() {
    use ksg_container_v2::store::verify_outer;
    let mut s = Stand::new(Class::Heavy, 27);
    to_work(&mut s);
    let id = s.c.template_id();
    let pq = s.pq.clone();
    let bytes = s.c.seal_to_bytes(&KEY, &mut s.rng).expect("sealed");
    assert_eq!(verify_outer(&bytes, &id, &pq), Ok(()));
    // Another template's identifier, another container's key: refused.
    assert!(verify_outer(&bytes, &Hash::sha256(b"another"), &pq).is_err());
    let other = Stand::new(Class::Heavy, 28).pq;
    assert!(verify_outer(&bytes, &id, &other).is_err());

    // The signature stripped: the container holds its key, so the file is
    // not one it wrote.
    let sig_len = u32::from_be_bytes(bytes[bytes.len() - 4..].try_into().unwrap()) as usize;
    let stripped = [&bytes[..bytes.len() - 4 - sig_len], &0u32.to_be_bytes()[..]].concat();
    assert_eq!(
        Container::open_sealed(&stripped, &id, &KEY).unwrap_err(),
        StoreError::Outer("missing")
    );
    // A byte of the signature changed.
    let mut forged = bytes.clone();
    forged[bytes.len() - 4 - sig_len / 2] ^= 1;
    assert!(Container::open_sealed(&forged, &id, &KEY).is_err());
    Container::open_sealed(&bytes, &id, &KEY).expect("its own file opens");
}
