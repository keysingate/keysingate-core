//! Packing and layers. KS-8 F-4, F-7, K-8; plan §2.1 and §2.2.

use ksg_container_v2::layers::{
    hand_over, receive, Held, LayerError, LayerKey, Level, OpenWith, SealTo, MLKEM_CT_LEN,
    MLKEM_EK_LEN,
};
use ksg_container_v2::noise;
use ksg_container_v2::{ChaCha20Poly1305Aead, NoCompression, PackError, Packer};

const SIZE: usize = 4096;
const AAD: &[u8] = b"the container's identifier";

fn packer() -> Packer<ChaCha20Poly1305Aead, NoCompression> {
    Packer::new(ChaCha20Poly1305Aead, NoCompression, SIZE)
}

/// Test noise. NOT a substitute for a CSPRNG — see the module docs. Here it only
/// has to be fixed so a failure reproduces.
fn noise_bytes(len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut x: u8 = 0x5a;
    for _ in 0..len {
        x = x.wrapping_mul(31).wrapping_add(17);
        out.push(x);
    }
    out
}

fn key(b: u8) -> [u8; 32] {
    [b; 32]
}

// --- the size says nothing ---------------------------------------------------

#[test]
fn the_ciphertext_is_the_same_length_whatever_is_inside() {
    // KS-8 F-4 and the reason for it: by F-7 the issuer is the blindest party
    // there is, and an issuer who can weigh a container knows how much was done
    // in it.
    let p = packer();
    let mut lengths = std::collections::BTreeSet::new();
    for content in [
        vec![],
        b"one page".to_vec(),
        vec![7u8; 1000],
        vec![0u8; SIZE - 4],
    ] {
        let sealed = p
            .seal(&content, &noise_bytes(SIZE), &key(1), &[0u8; 12], AAD)
            .expect("seal");
        lengths.insert(sealed.len());
    }
    assert_eq!(lengths.len(), 1, "the length varied with the content");
}

#[test]
fn content_that_does_not_fit_is_refused_rather_than_truncated() {
    // Silently dropping the tail would produce a container that opens and is
    // wrong, which is worse than one that refuses to close.
    let p = packer();
    let err = p
        .seal(
            &vec![0u8; SIZE],
            &noise_bytes(SIZE),
            &key(1),
            &[0u8; 12],
            AAD,
        )
        .unwrap_err();
    assert!(matches!(err, PackError::TooLarge { .. }), "{err}");
}

#[test]
fn too_little_noise_is_refused_rather_than_stretched() {
    // Stretching short noise is the failure that looks like success: the
    // container closes, the size is right, and the padding is predictable.
    let p = packer();
    let content = b"work".to_vec();
    let needed = p.noise_needed(&content);
    let err = p
        .seal(&content, &noise_bytes(needed - 1), &key(1), &[0u8; 12], AAD)
        .unwrap_err();
    assert_eq!(
        err,
        PackError::ShortNoise {
            supplied: needed - 1,
            needed
        }
    );
}

#[test]
fn padding_is_to_a_fixed_size_and_not_to_a_bucket() {
    // The distinction carries the whole argument for compressing before
    // encrypting: a bucket boundary is a length signal, just a coarser one.
    for content_len in [0usize, 1, 2, 3, 100, 1000] {
        let padded = noise::pad(&vec![1u8; content_len], SIZE, &noise_bytes(SIZE)).expect("pad");
        assert_eq!(
            padded.len(),
            SIZE,
            "content of {content_len} changed the size"
        );
    }
}

// --- the round trip ----------------------------------------------------------

#[test]
fn what_was_sealed_comes_back() {
    let p = packer();
    for content in [vec![], b"a page of work".to_vec(), vec![9u8; 2000]] {
        let sealed = p
            .seal(&content, &noise_bytes(SIZE), &key(3), &[1u8; 12], AAD)
            .expect("seal");
        assert_eq!(
            p.open(&sealed, &key(3), &[1u8; 12], AAD).expect("open"),
            content
        );
    }
}

#[test]
fn a_wrong_key_a_wrong_nonce_and_tampering_are_one_answer() {
    // Which of the three it was is exactly what an attacker would like told
    // apart, and the AEAD does not distinguish them either.
    let p = packer();
    let sealed = p
        .seal(b"work", &noise_bytes(SIZE), &key(3), &[1u8; 12], AAD)
        .expect("seal");

    assert_eq!(
        p.open(&sealed, &key(4), &[1u8; 12], AAD).unwrap_err(),
        PackError::Decryption
    );
    assert_eq!(
        p.open(&sealed, &key(3), &[2u8; 12], AAD).unwrap_err(),
        PackError::Decryption
    );
    let mut bad = sealed.clone();
    bad[10] ^= 1;
    assert_eq!(
        p.open(&bad, &key(3), &[1u8; 12], AAD).unwrap_err(),
        PackError::Decryption
    );
}

#[test]
fn the_container_identifier_is_authenticated_alongside() {
    // A sealed layer lifted into another container does not open there. Without
    // the aad it would, and a container could be assembled out of somebody
    // else's parts.
    let p = packer();
    let sealed = p
        .seal(b"work", &noise_bytes(SIZE), &key(3), &[1u8; 12], AAD)
        .expect("seal");
    assert_eq!(
        p.open(&sealed, &key(3), &[1u8; 12], b"another container")
            .unwrap_err(),
        PackError::Decryption
    );
}

// --- F-7: the key of level N does not read level N+1 -------------------------

fn aead() -> ChaCha20Poly1305Aead {
    ChaCha20Poly1305Aead
}

/// A chain: issuer → distributor → agent → client, each handing on.
fn chain() -> Vec<Held> {
    let issuer = Held::first(LayerKey::from_bytes(key(10)));
    let mut out = vec![issuer.clone()];

    let parties = [
        (OpenWith::from_bytes(key(21)), key(11), key(31)),
        (OpenWith::from_bytes(key(22)), key(12), key(32)),
        (OpenWith::from_bytes(key(23)), key(13), key(33)),
    ];
    let mut held = issuer;
    for (secret, own, ephemeral) in parties {
        let h = hand_over(&aead(), &held, &secret.seal_to(), ephemeral, AAD).expect("hand over");
        held = receive(&aead(), &h, &secret, LayerKey::from_bytes(own), AAD).expect("receive");
        out.push(held.clone());
    }
    out
}

#[test]
fn a_later_holder_reads_every_earlier_layer() {
    // The half of F-7 that is easy to forget: release data is not a secret from
    // the client who bought the blank.
    let c = chain();
    let client = c.last().expect("the client");
    assert_eq!(client.level(), Level(3));
    for l in 0..=3u8 {
        assert!(
            client.key(Level(l)).is_some(),
            "the client cannot read level {l}"
        );
    }
}

#[test]
fn the_key_of_level_n_does_not_read_level_n_plus_one() {
    // F-7 itself, and the test the plan asked for by name. Not enforced by a
    // rule — the key was never handed over and cannot be computed, because the
    // levels are not derived from one another.
    let c = chain();
    for (n, held) in c.iter().enumerate() {
        let own = u8::try_from(n).expect("four levels");
        assert_eq!(held.level(), Level(own));
        assert!(
            held.key(Level(own)).is_some(),
            "level {own} lost its own key"
        );
        for above in own + 1..=4 {
            assert!(
                held.key(Level(above)).is_none(),
                "level {own} could read level {above}"
            );
        }
    }
}

#[test]
fn the_issuer_is_the_blindest_party() {
    // F-7 in its own words. The issuer holds one key and reads one layer — the
    // one it wrote.
    let c = chain();
    let issuer = c.first().expect("the issuer");
    assert_eq!(issuer.levels(), vec![Level(0)]);
}

#[test]
fn a_layer_key_never_reaches_a_log() {
    // Written by hand for the reason a password type prints stars: a derived
    // formatter would put the key in every debug line that touches a container.
    let k = LayerKey::from_bytes(key(7));
    assert_eq!(format!("{k:?}"), "LayerKey(..)");
    let s = OpenWith::from_bytes(key(8));
    assert_eq!(format!("{s:?}"), "OpenWith(..)");
    assert_eq!(format!("{:?}", s.seal_to()), "SealTo(..)");
}

// --- the hand-over itself ----------------------------------------------------

#[test]
fn a_hand_over_opens_only_for_the_party_it_was_sealed_to() {
    let held = Held::first(LayerKey::from_bytes(key(10)));
    let intended = OpenWith::from_bytes(key(21));
    let stranger = OpenWith::from_bytes(key(99));

    let h = hand_over(&aead(), &held, &intended.seal_to(), key(31), AAD).expect("hand over");
    assert!(receive(&aead(), &h, &stranger, LayerKey::from_bytes(key(11)), AAD).is_err());
    receive(&aead(), &h, &intended, LayerKey::from_bytes(key(11)), AAD)
        .expect("the intended party");
}

#[test]
fn a_hand_over_does_not_open_in_another_container() {
    // The aad again, at the level where it matters most: keys lifted between
    // containers would let one be reassembled from another's parts.
    let held = Held::first(LayerKey::from_bytes(key(10)));
    let to = OpenWith::from_bytes(key(21));
    let h = hand_over(&aead(), &held, &to.seal_to(), key(31), AAD).expect("hand over");
    assert!(receive(
        &aead(),
        &h,
        &to,
        LayerKey::from_bytes(key(11)),
        b"another container"
    )
    .is_err());
}

#[test]
fn a_tampered_hand_over_is_refused() {
    let held = Held::first(LayerKey::from_bytes(key(10)));
    let to = OpenWith::from_bytes(key(21));
    let mut h = hand_over(&aead(), &held, &to.seal_to(), key(31), AAD).expect("hand over");
    h.sealed[0] ^= 1;
    assert!(receive(&aead(), &h, &to, LayerKey::from_bytes(key(11)), AAD).is_err());
}

#[test]
fn the_ephemeral_half_cannot_be_reused_between_recipients() {
    // Both public halves go into the derivation, so one ephemeral sent to two
    // parties derives two different wrapping keys. Without that a hand-over
    // could be replayed at a second recipient.
    let held = Held::first(LayerKey::from_bytes(key(10)));
    let first = OpenWith::from_bytes(key(21));
    let second = OpenWith::from_bytes(key(22));

    let h = hand_over(&aead(), &held, &first.seal_to(), key(31), AAD).expect("hand over");
    assert!(
        receive(&aead(), &h, &second, LayerKey::from_bytes(key(12)), AAD).is_err(),
        "a hand-over replayed at another recipient opened"
    );
}

#[test]
fn each_hand_over_adds_exactly_one_level() {
    let c = chain();
    for (n, held) in c.iter().enumerate() {
        assert_eq!(held.levels().len(), n + 1);
    }
}

// --- the nonce, after CT-03 --------------------------------------------------

#[test]
fn reusing_an_ephemeral_no_longer_repeats_the_nonce() {
    // The finding this closes (audit of 2026-09-13, 10a): the nonce was fixed
    // at zero, so a caller who reused an ephemeral on the same recipient
    // encrypted two different messages under one (key, nonce) — which in
    // ChaCha20-Poly1305 gives away the plaintexts and the authenticator.
    //
    // The fix is a synthetic nonce, and the test is the reason it had to be
    // synthetic rather than merely derived: the key is already a function of
    // the ephemeral and the recipient, so anything derived from those alone
    // would repeat exactly when the key repeats.
    let to = OpenWith::from_bytes(key(21));
    let same_ephemeral = key(31);

    let one = Held::first(LayerKey::from_bytes(key(10)));
    let other = Held::first(LayerKey::from_bytes(key(11)));

    let a = hand_over(&aead(), &one, &to.seal_to(), same_ephemeral, AAD).expect("first");
    let b = hand_over(&aead(), &other, &to.seal_to(), same_ephemeral, AAD).expect("second");

    assert_eq!(a.ephemeral, b.ephemeral, "the ephemeral really was reused");
    assert_ne!(
        a.nonce, b.nonce,
        "different contents under a reused ephemeral must not share a nonce"
    );
    // And both still open, because the nonce travels with the hand-over.
    receive(&aead(), &a, &to, LayerKey::from_bytes(key(40)), AAD).expect("the first opens");
    receive(&aead(), &b, &to, LayerKey::from_bytes(key(41)), AAD).expect("the second opens");
}

#[test]
fn the_same_content_under_the_same_ephemeral_is_the_same_bytes() {
    // What is left after the fix, stated so that nobody reads more into it
    // than it gives: sealing identical keys twice to the same recipient with
    // the same ephemeral is deterministic. That reveals the two are equal and
    // nothing about what they are.
    let to = OpenWith::from_bytes(key(21));
    let held = Held::first(LayerKey::from_bytes(key(10)));
    let a = hand_over(&aead(), &held, &to.seal_to(), key(31), AAD).expect("first");
    let b = hand_over(&aead(), &held, &to.seal_to(), key(31), AAD).expect("second");
    assert_eq!(a.nonce, b.nonce);
    assert_eq!(a.sealed, b.sealed);
}

#[test]
fn a_tampered_nonce_does_not_open() {
    // The nonce travels in the clear, so the test that matters is what happens
    // when it is changed on the way: the tag is computed under the agreement,
    // so a changed nonce fails to authenticate rather than decrypting to
    // something else.
    let to = OpenWith::from_bytes(key(21));
    let held = Held::first(LayerKey::from_bytes(key(10)));
    let mut h = hand_over(&aead(), &held, &to.seal_to(), key(31), AAD).expect("hand over");
    h.nonce[0] ^= 1;
    receive(&aead(), &h, &to, LayerKey::from_bytes(key(40)), AAD)
        .expect_err("a changed nonce does not open");
}

// --- K-5: the wrap is a hybrid of X25519 and ML-KEM-768 -----------------------

#[test]
fn the_seal_to_key_carries_both_halves_and_the_hand_over_both_ciphertexts() {
    // The cost of K-5, held by a test so that it cannot grow unnoticed.
    let to = OpenWith::from_bytes(key(21));
    let s = to.seal_to();
    assert_eq!(s.mlkem().len(), MLKEM_EK_LEN);
    assert_eq!(MLKEM_EK_LEN, 1184, "ML-KEM-768 encapsulation key");
    let held = Held::first(LayerKey::from_bytes(key(10)));
    let h = hand_over(&aead(), &held, &s, key(31), AAD).expect("hand over");
    assert_eq!(h.kem.len(), MLKEM_CT_LEN);
    assert_eq!(MLKEM_CT_LEN, 1088, "ML-KEM-768 ciphertext");
}

#[test]
fn a_tampered_mlkem_ciphertext_is_refused() {
    // ML-KEM does not fail on a wrong ciphertext — implicit rejection gives a
    // pseudorandom secret instead — so the refusal has to come from the
    // wrapping key no longer matching. It does.
    let held = Held::first(LayerKey::from_bytes(key(10)));
    let to = OpenWith::from_bytes(key(21));
    let mut h = hand_over(&aead(), &held, &to.seal_to(), key(31), AAD).expect("hand over");
    h.kem[100] ^= 1;
    assert_eq!(
        receive(&aead(), &h, &to, LayerKey::from_bytes(key(11)), AAD).expect_err("opened"),
        LayerError::Sealed
    );
}

#[test]
fn an_mlkem_ciphertext_of_the_wrong_length_does_not_parse() {
    let held = Held::first(LayerKey::from_bytes(key(10)));
    let to = OpenWith::from_bytes(key(21));
    let mut h = hand_over(&aead(), &held, &to.seal_to(), key(31), AAD).expect("hand over");
    h.kem.pop();
    assert_eq!(
        receive(&aead(), &h, &to, LayerKey::from_bytes(key(11)), AAD).expect_err("opened"),
        LayerError::Malformed
    );
}

#[test]
fn the_mlkem_half_cannot_be_swapped_between_hand_overs() {
    // Two hand-overs to the same recipient under different ephemerals: taking
    // the ML-KEM ciphertext of one into the other breaks the wrap, because the
    // ciphertext is bound into the derivation, not merely decapsulated.
    let held = Held::first(LayerKey::from_bytes(key(10)));
    let to = OpenWith::from_bytes(key(21));
    let a = hand_over(&aead(), &held, &to.seal_to(), key(31), AAD).expect("first");
    let b = hand_over(&aead(), &held, &to.seal_to(), key(32), AAD).expect("second");
    let mut mixed = a.clone();
    mixed.kem = b.kem;
    assert!(receive(&aead(), &mixed, &to, LayerKey::from_bytes(key(11)), AAD).is_err());
}

#[test]
fn a_malformed_mlkem_key_is_refused_before_anything_is_sealed_to_it() {
    // FIPS 203 §7.2: every coefficient must be below q. All-ones bytes are
    // not, so this is not a key and nothing may be sealed to it.
    let x = *OpenWith::from_bytes(key(21)).seal_to().public();
    assert_eq!(
        SealTo::new(x, [0xFF; MLKEM_EK_LEN]).expect_err("accepted"),
        LayerError::Malformed
    );
    // A real one round-trips through the constructor.
    let real = OpenWith::from_bytes(key(21)).seal_to();
    SealTo::new(*real.public(), *real.mlkem()).expect("a valid key");
}

#[test]
fn the_hybrid_wrap_is_reproducible_from_its_inputs() {
    // The crates hold no RNG; the vectors depend on this.
    let held = Held::first(LayerKey::from_bytes(key(10)));
    let to = OpenWith::from_bytes(key(21));
    let a = hand_over(&aead(), &held, &to.seal_to(), key(31), AAD).expect("first");
    let b = hand_over(&aead(), &held, &to.seal_to(), key(31), AAD).expect("second");
    assert_eq!(a, b);
}

// --- `bare` seals without ML-KEM-768 (`[decision]` 07.10) -------------------

mod classical {
    use super::{key, AAD};
    use ksg_container_v2::layers::{
        hand_over_in, receive_in, Held, LayerError, LayerKey, Level, OpenWith, Suite,
    };
    use ksg_container_v2::ChaCha20Poly1305Aead as Aead;
    use ksg_core_v2::doc::Class;

    fn sealed(suite: Suite, to: &OpenWith) -> ksg_container_v2::layers::Handover {
        let held = Held::first(LayerKey::from_bytes(key(10)));
        hand_over_in(suite, &Aead, &held, &to.seal_to(), key(31), AAD).expect("hand over")
    }

    #[test]
    fn bare_alone_is_classical() {
        assert_eq!(Suite::of(Class::Bare), Suite::X25519);
        assert_eq!(Suite::of(Class::Light), Suite::Hybrid);
        assert_eq!(Suite::of(Class::Heavy), Suite::Hybrid);
    }

    #[test]
    fn a_classical_hand_over_carries_no_ml_kem_and_opens() {
        let to = OpenWith::from_bytes(key(21));
        let h = sealed(Suite::X25519, &to);
        assert!(h.kem.is_empty(), "no ML-KEM ciphertext in bare");
        let got = receive_in(
            Suite::X25519,
            &Aead,
            &h,
            &to,
            LayerKey::from_bytes(key(11)),
            AAD,
        )
        .expect("the recipient opens");
        assert_eq!(got.levels(), vec![Level(0), Level(1)]);
        assert_eq!(got.key(Level(0)), Some(&LayerKey::from_bytes(key(10))));
        // A stranger does not.
        assert_eq!(
            receive_in(
                Suite::X25519,
                &Aead,
                &h,
                &OpenWith::from_bytes(key(99)),
                LayerKey::from_bytes(key(11)),
                AAD
            ),
            Err(LayerError::Sealed)
        );
    }

    #[test]
    fn the_suites_do_not_open_each_other() {
        // The class picks the suite on both sides: a classical wrap is not
        // a hybrid one with the ML-KEM half left out, and the other way round.
        let to = OpenWith::from_bytes(key(21));
        let own = || LayerKey::from_bytes(key(11));
        let classical = sealed(Suite::X25519, &to);
        assert!(receive_in(Suite::Hybrid, &Aead, &classical, &to, own(), AAD).is_err());
        let hybrid = sealed(Suite::Hybrid, &to);
        assert_eq!(
            receive_in(Suite::X25519, &Aead, &hybrid, &to, own(), AAD),
            Err(LayerError::Malformed),
            "an ML-KEM ciphertext in a classical hand-over"
        );
        // And a classical one stripped of its labels' difference: the
        // hybrid wrap with its ciphertext removed does not open as classical.
        let mut stripped = hybrid;
        stripped.kem.clear();
        assert_eq!(
            receive_in(Suite::X25519, &Aead, &stripped, &to, own(), AAD),
            Err(LayerError::Sealed)
        );
    }
}
