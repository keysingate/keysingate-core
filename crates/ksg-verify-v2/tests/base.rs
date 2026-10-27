//! Base Sepolia reads against a node that answers from a script.

use ksg_verify_v2::base::{check_chain, latest_block_time, BASE_SEPOLIA_CHAIN_ID};
use ksg_verify_v2::solana::Rpc;
use serde_json::{json, Value};

struct Node(Value);
impl Rpc for Node {
    fn call(&self, method: &str, _params: Value) -> Result<Value, String> {
        self.0
            .get(method)
            .cloned()
            .ok_or_else(|| format!("{method}: not scripted"))
    }
}

#[test]
fn the_chain_is_checked_and_the_block_time_read() {
    let base = Node(
        json!({"eth_chainId": "0x14a34", "eth_getBlockByNumber": {"timestamp": "0x6728a0c0"}}),
    );
    assert!(check_chain(&base, BASE_SEPOLIA_CHAIN_ID).is_ok());
    assert_eq!(latest_block_time(&base).unwrap(), 0x6728_a0c0);

    let mainnet = Node(json!({"eth_chainId": "0x2105"}));
    let e = check_chain(&mainnet, BASE_SEPOLIA_CHAIN_ID).unwrap_err();
    assert!(e.contains("8453"), "{e}");

    let no_time = Node(json!({"eth_getBlockByNumber": {"number": "0x1"}}));
    assert!(latest_block_time(&no_time).is_err());
}
