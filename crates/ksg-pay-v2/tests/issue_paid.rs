//! Goal 2, criterion G2-8: the whole road of a paid `bare` on the stand —
//! the issuance anchor says "already had one", the issuer asks for payment,
//! a payment is accepted once, and only then the `bare` is handed over.

use std::collections::BTreeSet;

use base64::Engine as _;
use ksg_pay_v2::{before_handover, Address, Handover, Price, Refused, Till};
use ksg_verify_v2::issue_anchor::{self, BareCheckKey, DocKind};

// The independent EIP-3009 vector of the unit tests (eth-account 0.13.4).
const ISSUER: &str = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C";
const PAYMENT: &str = r#"{"x402Version":1,"scheme":"exact","network":"base-sepolia","payload":{"signature":"0x2a895ae6947395e7203111cc46aae30fb17b34185d92e5dc3af39b1f0047a97a0c6e8b4874c9e32469ab305eae18a3e23895f84a878ed4d905652f33f43878421c","authorization":{"from":"0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A","to":"0x209693Bc6afc0C5328bA36FaF03C514EF312287C","value":"100000","validAfter":"1760000000","validBefore":"1760000600","nonce":"0xabababababababababababababababababababababababababababababababab"}}}"#;
const NOW: u64 = 1_760_000_100;

#[test]
fn a_repeat_bare_is_handed_over_only_after_one_accepted_payment() {
    let key = BareCheckKey::new([7; 32]).for_period("2026");
    let scope = issue_anchor::scope("bare-2026-10", "2.0.0");
    let anna = [(DocKind::Email, "alice@example.com")];
    let till = Till::base_sepolia(Address::parse(ISSUER).unwrap());
    let price = Price {
        minor: 100_000, // $0.10
        resource: "https://issuer.example/bare/issue".into(),
        description: "a repeated bare".into(),
    };
    let mut taken = BTreeSet::new();
    let pay = base64::engine::general_purpose::STANDARD.encode(PAYMENT);

    // First time: no anchor matches — free, no payment asked.
    let anchors: Vec<String> = Vec::new();
    let had = |anchors: &[String]| {
        anchors.iter().any(|m| {
            issue_anchor::open(&key, m)
                .and_then(|a| a.matches(&key, &scope, &anna))
                .unwrap_or(false)
        })
    };
    assert_eq!(
        before_handover(&till, &price, had(&anchors), None, NOW, &mut taken),
        Ok(Handover::Free)
    );
    let anchors = vec![issue_anchor::seal(&key, "2026", &scope, &anna, [1; 32]).unwrap()];

    // Second time: the anchor matches — 402 until paid.
    let r = before_handover(&till, &price, had(&anchors), None, NOW, &mut taken);
    let Err(Ok(body)) = r else {
        panic!("expected a 402 body, got {r:?}")
    };
    assert_eq!(body["accepts"][0]["maxAmountRequired"], "100000");

    // Paid: handed over, once.
    let r = before_handover(&till, &price, had(&anchors), Some(&pay), NOW, &mut taken);
    assert!(matches!(r, Ok(Handover::Paid(_))), "{r:?}");
    assert_eq!(
        before_handover(&till, &price, had(&anchors), Some(&pay), NOW, &mut taken),
        Err(Err(Refused::Replayed))
    );
}
