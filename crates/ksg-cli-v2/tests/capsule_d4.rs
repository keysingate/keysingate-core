//! Criterion K3 (plan v8): Д-4 — before initiation the container holds neither
//! the issuer's seal seed nor its post-quantum key, so the copies the sale
//! chain keeps carry no secret (`[doc:CAPSULE-SPEC]` §9,
//! owner's decision 25.10 "(а)"). Green 27.10.

use ksg_container_v2::Container;
use ksg_core_v2::crypto::hash::Hash;
use std::process::Command;

#[test]
fn k3_a_printed_container_carries_no_seal_and_no_pq_key() {
    let dir = std::env::temp_dir().join(format!("ksg-d4-{}", std::process::id()));
    let home = dir.join("h");
    let ok = Command::new(env!("CARGO_BIN_EXE_ksg-remote-panel"))
        .args(["--home", home.to_str().unwrap(), "init", "--class", "heavy"])
        .status()
        .unwrap()
        .success();
    assert!(ok, "init");
    let meta: serde_json::Value =
        serde_json::from_slice(&std::fs::read(home.join("container.json")).unwrap()).unwrap();
    let template = Hash::from_multihash(meta["template"].as_str().unwrap()).unwrap();
    let key: [u8; 32] = std::fs::read(home.join("layer.key")).unwrap().try_into().unwrap();
    let bytes = std::fs::read(home.join("container.ksg")).unwrap();
    let c = Container::open_sealed(&bytes, &template, &key).unwrap();
    assert!(c.seal().is_none(), "the seal is born at initiation, not at printing");
    assert!(c.pq_public().is_none(), "the post-quantum key is born at initiation");
    std::fs::remove_dir_all(&dir).unwrap();
}
