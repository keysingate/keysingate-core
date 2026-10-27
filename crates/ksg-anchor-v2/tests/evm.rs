//! The Base Sepolia anchor: the transaction against an independent signer, and
//! the contract's rules run in an EVM inside the test.

use ksg_anchor_v2::evm::{
    address_of, anchor_data, decode_head, decode_refusal, hand_over_data, head_data, hex0x,
    key_from_secret, unhex, Call, Refusal, BASE_SEPOLIA_CHAIN_ID, KSG_ANCHORS_BYTECODE,
};
use revm::db::{CacheDB, EmptyDB};
use revm::primitives::{Address, Bytes, ExecutionResult, Output, TxKind, U256};
use revm::Evm;

/// The vector: eth-account 0.13.4 (Python), an implementation independent of
/// this crate, signing the same call with the same key.
#[test]
fn the_anchor_transaction_matches_an_independent_signer() {
    let secret: [u8; 32] =
        unhex("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")
            .unwrap()
            .try_into()
            .unwrap();
    let key = key_from_secret(&secret).unwrap();
    assert_eq!(
        hex0x(&address_of(key.verifying_key())),
        "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23"
    );
    let container: [u8; 32] = core::array::from_fn(|i| u8::try_from(i).unwrap());
    let call = Call {
        chain_id: BASE_SEPOLIA_CHAIN_ID,
        nonce: 7,
        max_priority_fee_per_gas: 1_000_000,
        max_fee_per_gas: 2_000_000_000,
        gas_limit: 120_000,
        to: [0x11; 20],
        data: anchor_data(&container, &[0; 32], &[0xab; 32]),
    };
    let (raw, hash) = call.sign(&key).unwrap();
    assert_eq!(
        hex::encode(&raw),
        "02f8d283014a3407830f424084773594008301d4c094111111111111111111111111111111111111111180b8646ed37a1d000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0000000000000000000000000000000000000000000000000000000000000000ababababababababababababababababababababababababababababababababc001a07c4721aff60efbcf7542d964f37732d99101aaecf886e0f7e5431b7233227fa4a020570e8024ec017ca9bf7393e78929f1aa98087a0a265793c5021e26de4fcb1f"
    );
    assert_eq!(
        hex::encode(hash),
        "6603d40c10c377efbdea64066f35589264626b9ede6497008f2ff57dfbeb7c33"
    );
}

struct Chain {
    db: CacheDB<EmptyDB>,
    contract: Address,
}

enum Res {
    Ok(Vec<u8>),
    Refused(Vec<u8>),
}

impl Chain {
    fn new() -> Self {
        let mut db = CacheDB::new(EmptyDB::default());
        let code = unhex(KSG_ANCHORS_BYTECODE).unwrap();
        let r = Evm::builder()
            .with_db(&mut db)
            .modify_tx_env(|tx| {
                tx.caller = Address::repeat_byte(0xee);
                tx.transact_to = TxKind::Create;
                tx.data = Bytes::from(code);
                tx.gas_limit = 5_000_000;
                tx.gas_price = U256::ZERO;
            })
            .build()
            .transact_commit()
            .unwrap();
        let contract = match r {
            ExecutionResult::Success {
                output: Output::Create(_, Some(a)),
                ..
            } => a,
            other => panic!("deploy failed: {other:?}"),
        };
        Self { db, contract }
    }

    fn call(&mut self, from: u8, data: Vec<u8>) -> Res {
        let contract = self.contract;
        let r = Evm::builder()
            .with_db(&mut self.db)
            .modify_tx_env(|tx| {
                tx.caller = Address::repeat_byte(from);
                tx.transact_to = TxKind::Call(contract);
                tx.data = Bytes::from(data);
                tx.gas_limit = 1_000_000;
                tx.gas_price = U256::ZERO;
            })
            .build()
            .transact_commit()
            .unwrap();
        match r {
            ExecutionResult::Success { output, .. } => Res::Ok(output.into_data().to_vec()),
            ExecutionResult::Revert { output, .. } => Res::Refused(output.to_vec()),
            ExecutionResult::Halt { reason, .. } => panic!("halt: {reason:?}"),
        }
    }

    fn anchor(&mut self, from: u8, c: [u8; 32], prev: [u8; 32], next: [u8; 32]) -> Option<Refusal> {
        match self.call(from, anchor_data(&c, &prev, &next)) {
            Res::Ok(_) => None,
            Res::Refused(d) => Some(decode_refusal(&d).expect("a refusal the contract raises")),
        }
    }

    fn head(&mut self, c: [u8; 32]) -> ksg_anchor_v2::evm::Head {
        match self.call(0x01, head_data(&c)) {
            Res::Ok(d) => decode_head(&d).unwrap(),
            Res::Refused(d) => panic!("head refused: {d:?}"),
        }
    }
}

const A: u8 = 0xa1;
const B: u8 = 0xb2;

#[test]
fn the_contract_keeps_the_head_and_refuses_a_copy() {
    let mut ch = Chain::new();
    let c = [7u8; 32];
    let (j1, j2, j3) = ([1u8; 32], [2u8; 32], [3u8; 32]);

    // Before the first anchor the head is empty.
    let h = ch.head(c);
    assert_eq!((h.last, h.writer, h.count), ([0; 32], [0; 20], 0));

    // The first anchor continues nothing; its sender becomes the writer.
    assert_eq!(ch.anchor(A, c, [0; 32], j1), None);
    let h = ch.head(c);
    assert_eq!((h.last, h.writer, h.count), (j1, [A; 20], 1));

    // A first anchor that claims a predecessor is refused.
    let other = [8u8; 32];
    assert!(matches!(
        ch.anchor(A, other, j1, j2),
        Some(Refusal::StalePredecessor { head, .. }) if head == [0; 32]
    ));

    // Two copies hold the same last anchor j1. The first to anchor moves the
    // head; the second is refused and learns it is a copy.
    assert_eq!(ch.anchor(A, c, j1, j2), None);
    assert_eq!(
        ch.anchor(A, c, j1, j3),
        Some(Refusal::StalePredecessor {
            head: j2,
            presented: j1
        })
    );
    assert_eq!(ch.head(c).last, j2, "the refused anchor changed nothing");

    // A stranger cannot push the head forward, even continuing it.
    assert_eq!(ch.anchor(B, c, j2, j3), Some(Refusal::NotWriter([A; 20])));

    // A zero anchor is refused.
    assert_eq!(ch.anchor(A, c, j2, [0; 32]), Some(Refusal::ZeroAnchor));

    // The writer hands over (a transfer of rights); the old writer is out.
    assert!(matches!(
        ch.call(A, hand_over_data(&c, &[B; 20])),
        Res::Ok(_)
    ));
    assert_eq!(ch.anchor(A, c, j2, j3), Some(Refusal::NotWriter([B; 20])));
    assert_eq!(ch.anchor(B, c, j2, j3), None);
    let h = ch.head(c);
    assert_eq!((h.last, h.writer, h.count), (j3, [B; 20], 3));

    // Only the writer hands over.
    assert!(matches!(
        ch.call(A, hand_over_data(&c, &[A; 20])),
        Res::Refused(_)
    ));
}

/// The verifier's read (`ksg_verify_v2::base`) over JSON-RPC, answered by the
/// same EVM: the selector it fixes is the contract's, the head it decodes is
/// the one written, and a file left behind reads as stale.
#[test]
fn the_verifier_reads_the_head_the_writer_left() {
    use ksg_verify_v2::base::{check_not_stale, head, Standing, HEAD_SELECTOR};
    use ksg_verify_v2::solana::Rpc;
    use std::cell::RefCell;

    assert_eq!(HEAD_SELECTOR, ksg_anchor_v2::evm::selector("head(bytes32)"));

    struct Node(RefCell<Chain>);
    impl Rpc for Node {
        fn call(
            &self,
            method: &str,
            params: serde_json::Value,
        ) -> Result<serde_json::Value, String> {
            assert_eq!(method, "eth_call");
            let data = unhex(params[0]["data"].as_str().unwrap()).unwrap();
            match self.0.borrow_mut().call(0x01, data) {
                Res::Ok(d) => Ok(serde_json::Value::String(hex0x(&d))),
                Res::Refused(_) => Err("reverted".into()),
            }
        }
    }
    let mut ch = Chain::new();
    let contract: [u8; 20] = ch.contract.into_array();
    let c = [9u8; 32];
    assert_eq!(ch.anchor(A, c, [0; 32], [1; 32]), None);
    assert_eq!(ch.anchor(A, c, [1; 32], [2; 32]), None);
    let node = Node(RefCell::new(ch));
    let h = head(&node, &contract, &c).unwrap();
    assert_eq!((h.last, h.writer, h.count), ([2; 32], [A; 20], 2));
    assert_eq!(check_not_stale(&h, Some(&[2; 32])), Standing::Current);
    assert_eq!(
        check_not_stale(&h, Some(&[1; 32])),
        Standing::Stale { head: [2; 32] }
    );
    let empty = head(&node, &contract, &[5; 32]).unwrap();
    assert_eq!(check_not_stale(&empty, None), Standing::Unanchored);
}

/// The verifier's topic for `Anchored` is the contract's event (the export
/// check reads it, `ksg_verify_v2::base::seal_on_chain`).
#[test]
fn the_verifier_reads_the_contracts_anchored_event() {
    assert_eq!(
        ksg_verify_v2::base::ANCHORED_TOPIC,
        ksg_anchor_v2::evm::note_kind("Anchored(bytes32,bytes32,bytes32,uint64,address)")
    );
    assert_eq!(
        ksg_verify_v2::base::NOTED_TOPIC,
        ksg_anchor_v2::evm::note_kind("Noted(bytes32,address,bytes)")
    );
    assert_eq!(
        ksg_verify_v2::base::HANDED_OVER_TOPIC,
        ksg_anchor_v2::evm::note_kind("HandedOver(bytes32,address,address)")
    );
}
