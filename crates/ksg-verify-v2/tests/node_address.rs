//! A node's address carries the provider's key in its path or query: it
//! never goes into an error, and it may live in the environment instead of a
//! file (the agent's live run of 17.10).

#![cfg(feature = "rpc")]
#![allow(clippy::unwrap_used)]

use ksg_verify_v2::solana::{node_address, redact_url, HttpRpc, Rpc};

#[test]
fn an_address_is_printed_as_its_host_only() {
    assert_eq!(
        redact_url("https://base-sepolia.g.alchemy.com/v2/SECRETKEY"),
        "https://base-sepolia.g.alchemy.com/…"
    );
    assert_eq!(
        redact_url("https://go.getblock.io/SECRET?x=1"),
        "https://go.getblock.io/…"
    );
    assert_eq!(
        redact_url("https://user:pw@node.example"),
        "https://node.example"
    );
    assert_eq!(redact_url("http://127.0.0.1:8545"), "http://127.0.0.1:8545");
    assert_eq!(redact_url("not a url"), "<node address>");
}

#[test]
fn a_failing_node_does_not_print_its_key() {
    // Port 1: nothing listens, the call fails with the transport's error.
    let rpc = HttpRpc::new("http://127.0.0.1:1/v2/SECRETKEY").unwrap();
    let e = rpc.call("eth_chainId", serde_json::json!([])).unwrap_err();
    assert!(!e.contains("SECRETKEY"), "{e}");
    // The node is still named — by its host.
    assert!(e.contains("http://127.0.0.1:1/…"), "{e}");
}

#[test]
fn an_address_may_come_from_the_environment() {
    std::env::set_var("KSG_TEST_NODE_ADDRESS", "http://127.0.0.1:1/v2/ENVKEY");
    assert_eq!(
        node_address("env:KSG_TEST_NODE_ADDRESS").unwrap(),
        "http://127.0.0.1:1/v2/ENVKEY"
    );
    assert!(node_address("env:KSG_TEST_NODE_ADDRESS_UNSET")
        .unwrap_err()
        .contains("KSG_TEST_NODE_ADDRESS_UNSET"));
    let rpc = HttpRpc::new("env:KSG_TEST_NODE_ADDRESS").unwrap();
    let e = rpc.call("eth_chainId", serde_json::json!([])).unwrap_err();
    assert!(!e.contains("ENVKEY"), "{e}");
}
