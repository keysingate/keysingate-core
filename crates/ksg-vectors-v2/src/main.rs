//! Writes the vectors of core v2 to `core-v2/vectors/`. Spec v2 §16 item 5.

use std::fs;
use std::path::Path;

fn main() -> std::io::Result<()> {
    let out = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(ksg_vectors_v2::VECTORS_DIR);
    fs::create_dir_all(&out)?;
    let sets = ksg_vectors_v2::generate();
    for (name, value) in &sets {
        fs::write(out.join(name), ksg_vectors_v2::render(value))?;
    }
    eprintln!(
        "ksg-vectors-v2: {} sets written to {}",
        sets.len(),
        out.display()
    );
    Ok(())
}
