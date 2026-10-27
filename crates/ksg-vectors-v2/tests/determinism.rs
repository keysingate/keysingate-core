//! The files on disk are what the generator produces now, byte for byte
//! (spec v2 §16 item 5). A change to the core that moves a vector shows up
//! here, not silently in a third party's implementation.

use std::path::Path;

#[test]
fn the_vectors_on_disk_are_reproduced_byte_for_byte() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(ksg_vectors_v2::VECTORS_DIR);
    for (name, value) in ksg_vectors_v2::generate() {
        let on_disk = std::fs::read_to_string(dir.join(name))
            .unwrap_or_else(|e| panic!("{name}: {e}; run `cargo run -p ksg-vectors-v2`"));
        assert_eq!(
            on_disk,
            ksg_vectors_v2::render(&value),
            "{name} differs from what the generator produces; run `cargo run -p ksg-vectors-v2` and review the diff"
        );
    }
}

#[test]
fn two_runs_give_the_same_bytes() {
    let a: Vec<String> = ksg_vectors_v2::generate()
        .iter()
        .map(|(_, v)| ksg_vectors_v2::render(v))
        .collect();
    let b: Vec<String> = ksg_vectors_v2::generate()
        .iter()
        .map(|(_, v)| ksg_vectors_v2::render(v))
        .collect();
    assert_eq!(a, b);
}
