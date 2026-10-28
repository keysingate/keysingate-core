//! Seal an issuance anchor and open it back (G1-5d step 4 demo).
//!
//! ```sh
//! cargo run -p ksg-verify-v2 --example issue_anchor
//! ```
//! stdout: one `ksg:ia:v1 …` line, then `open+matches: true`.

use ksg_verify_v2::issue_anchor::{self, BareCheckKey, DocKind};

fn main() {
    let key = BareCheckKey::new([7; 32]).for_period("2026");
    let scope = issue_anchor::scope("bare-2026-10", "2.0.0");
    let docs = [(DocKind::Email, "alice@example.com")];
    let memo = issue_anchor::seal(&key, "2026", &scope, &docs, [9; 32]).expect("seal");
    println!("{memo}");
    let opened = issue_anchor::open(&key, &memo).expect("open");
    let ok = opened.matches(&key, &scope, &docs).expect("matches");
    println!("open+matches: {ok}");
    assert!(ok, "the anchor must open and match its document");
}
