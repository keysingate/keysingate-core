//! The capsule's criteria K1 and K2 (plan v8, `[doc:HACKATHON-PLAN]`;
//! `[doc:CAPSULE-SPEC]` §3, §10 item 2). Green 26.10; the noise
//! test runs in release (`-- --ignored`).

use ksg_container_v2::capsule::{
    assemble, open, slot_start, MapRole, Part, PartKind, BLOCKS, CAPSULE_SIZE,
};
use ksg_container_v2::layers::OpenWith;

/// A deterministic stream for tests: SHA-256 in counter mode. Tests only.
fn stream(seed: u64) -> impl FnMut(&mut [u8]) {
    use sha2::{Digest, Sha256};
    let mut counter = 0u64;
    move |out: &mut [u8]| {
        for chunk in out.chunks_mut(32) {
            let h = Sha256::new()
                .chain_update(seed.to_be_bytes())
                .chain_update(counter.to_be_bytes())
                .finalize();
            chunk.copy_from_slice(&h[..chunk.len()]);
            counter += 1;
        }
    }
}

fn map(seed: u8) -> OpenWith {
    OpenWith::from_bytes([seed; 32])
}

fn parts(pages: usize) -> Vec<Part> {
    vec![
        Part { kind: PartKind::Code, bytes: vec![0x61; 760 * 1024] },
        Part { kind: PartKind::State, bytes: vec![0x70; 4 * 1024 * 1024 * pages.min(1) / 2] },
        Part { kind: PartKind::ClientSecrets, bytes: vec![0x63; 96] },
        Part { kind: PartKind::OwnerSecrets, bytes: vec![0x6f; 64] },
        Part { kind: PartKind::SharedSecrets, bytes: vec![0x73; 4032] },
    ]
}

fn two_maps() -> (OpenWith, OpenWith, Vec<(MapRole, ksg_container_v2::layers::SealTo)>) {
    let (c, o) = (map(1), map(2));
    let maps = vec![(MapRole::Client, c.seal_to()), (MapRole::Owner, o.seal_to())];
    (c, o, maps)
}

/// NIST SP 800-22 §2.1 (frequency) and §2.3 (runs), P-values at α = 0.01.
fn nist_frequency_and_runs(bytes: &[u8]) -> (f64, f64) {
    let n = (bytes.len() * 8) as f64;
    let ones: u64 = bytes.iter().map(|b| u64::from(b.count_ones())).sum();
    let s = 2.0 * ones as f64 - n;
    let p_freq = erfc(s.abs() / n.sqrt() / std::f64::consts::SQRT_2);
    let pi = ones as f64 / n;
    let mut runs = 1u64;
    let bit = |i: usize| (bytes[i / 8] >> (7 - i % 8)) & 1;
    for i in 1..bytes.len() * 8 {
        if bit(i) != bit(i - 1) {
            runs += 1;
        }
    }
    let num = (runs as f64 - 2.0 * n * pi * (1.0 - pi)).abs();
    let den = 2.0 * (2.0 * n).sqrt() * pi * (1.0 - pi);
    (p_freq, erfc(num / den))
}

/// erfc by Abramowitz–Stegun 7.1.26 — enough for a P-value threshold.
fn erfc(x: f64) -> f64 {
    let t = 1.0 / (1.0 + 0.327_591_1 * x);
    let y = t * (0.254_829_592
        + t * (-0.284_496_736 + t * (1.421_413_741 + t * (-1.453_152_027 + t * 1.061_405_429))));
    y * (-x * x).exp()
}

#[test]
fn k1_a_capsule_is_always_the_same_size() {
    let (_, _, maps) = two_maps();
    let small = assemble(&parts(0), &maps, &mut stream(1)).expect("assembles");
    let full = assemble(&parts(1), &maps, &mut stream(2)).expect("assembles");
    assert_eq!(small.len(), CAPSULE_SIZE);
    assert_eq!(full.len(), CAPSULE_SIZE);
}

#[test]
#[ignore = "slow unoptimized: cargo test --release -p ksg-container-v2 --test capsule -- --ignored"]
fn k1_a_capsule_passes_frequency_and_runs_tests() {
    let (_, _, maps) = two_maps();
    // NIST SP 800-22 §4.2.1: at α = 0.01 about 1% of truly random sequences
    // fail each test, so the criterion is the proportion that pass —
    // for 100 sequences at least 0.99 − 3·√(0.99·0.01/100) ≈ 0.960.
    let (mut freq_ok, mut runs_ok) = (0, 0);
    for seed in 0..100 {
        let cap = assemble(&parts(1), &maps, &mut stream(seed)).expect("assembles");
        let (f, r) = nist_frequency_and_runs(&cap);
        freq_ok += usize::from(f >= 0.01);
        runs_ok += usize::from(r >= 0.01);
    }
    assert!(freq_ok >= 96, "frequency: {freq_ok}/100 passed");
    assert!(runs_ok >= 96, "runs: {runs_ok}/100 passed");
}

#[test]
fn k2_each_map_opens_its_own_parts_only() {
    let (c, o, maps) = two_maps();
    let cap = assemble(&parts(0), &maps, &mut stream(3)).expect("assembles");
    let (role, got) = open(&cap, &c).expect("the client's map opens");
    assert_eq!(role, MapRole::Client);
    assert!(got.iter().any(|p| p.kind == PartKind::ClientSecrets));
    assert!(got.iter().all(|p| p.kind != PartKind::OwnerSecrets));
    let (role, got) = open(&cap, &o).expect("the owner's map opens");
    assert_eq!(role, MapRole::Owner);
    assert!(got.iter().all(|p| p.kind != PartKind::ClientSecrets));
    assert!(open(&cap, &map(9)).is_err(), "a stranger's map opens nothing");
}

#[test]
fn k2_colliding_slots_both_open() {
    // Find two maps whose slots start in the same block.
    let first = map(1);
    let start = slot_start(&first.seal_to());
    let second = (1u32..200_000)
        .map(|i| {
            let mut seed = [0u8; 32];
            seed[..4].copy_from_slice(&i.to_be_bytes());
            seed[31] = 0xA5;
            OpenWith::from_bytes(seed)
        })
        .find(|m| slot_start(&m.seal_to()) == start)
        .expect("a colliding map within 200 000 tries (1 in 1 536 each)");
    let maps = vec![(MapRole::Client, first.seal_to()), (MapRole::Owner, second.seal_to())];
    let cap = assemble(&parts(0), &maps, &mut stream(4)).expect("assembles");
    assert!(open(&cap, &first).is_ok());
    assert!(open(&cap, &second).is_ok());
    assert!(start < BLOCKS);
}

#[test]
fn k2_reassembly_by_one_party_keeps_the_other_partys_slot() {
    let (c, o, maps) = two_maps();
    let cap = assemble(&parts(0), &maps, &mut stream(5)).expect("assembles");
    let (_, mut got) = open(&cap, &c).expect("the client opens");
    // The client writes; it re-seals the owner's slot to the owner's public half.
    if let Some(s) = got.iter_mut().find(|p| p.kind == PartKind::State) {
        s.bytes.push(1);
    }
    let again = assemble(&got, &maps, &mut stream(6)).expect("re-assembles");
    assert!(open(&again, &o).is_ok(), "the owner's map opens the new capsule");
    let same = cap.chunks(4096).zip(again.chunks(4096)).filter(|(a, b)| a == b).count();
    assert_eq!(same, 0, "no block survives a re-assembly");
}

#[test]
fn a_tampered_capsule_does_not_open() {
    let (c, _, maps) = two_maps();
    let mut cap = assemble(&parts(0), &maps, &mut stream(7)).expect("assembles");
    for b in cap.iter_mut().step_by(4096) {
        *b ^= 1;
    }
    assert!(open(&cap, &c).is_err());
}
