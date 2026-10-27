//! The page's core without a page: a commitment needs no word, a request
//! that is not one is answered with an error, and the half reads back.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
use ksg_container_v2::client_key::split;
use ksg_web_v2::{describe_request, Web};

fn half() -> Vec<u8> {
    let kid = ksg_core_v2::doc::Uri::parse("urn:ksg:test:client").unwrap();
    let (_inside, half) = split(kid, &mut rand_core::OsRng).unwrap();
    half.to_bytes().unwrap().to_vec()
}

#[test]
fn a_commitment_signs_nothing_and_needs_no_word() {
    let line = r#"{"op":"commit"}"#;
    assert!(describe_request(line).is_none());
    let mut web = Web::from_half(&half()).unwrap();
    // Even without the holder's yes the commitment goes: it signs nothing.
    assert!(web
        .answer(line, false, &mut rand_core::OsRng)
        .starts_with(r#"{"ok":"#));
}

#[test]
fn what_is_not_a_request_or_a_half_is_refused() {
    assert!(describe_request("not json").is_none());
    let mut web = Web::from_half(&half()).unwrap();
    let a = web.answer(
        r#"{"op":"respond","round":"AAAA"}"#,
        true,
        &mut rand_core::OsRng,
    );
    assert!(a.starts_with(r#"{"err":"#), "{a}");
    assert!(Web::from_half(b"no half").is_err());
}
