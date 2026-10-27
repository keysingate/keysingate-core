//! The UserOperation of the sponsored route (`src/user_op.rs`) against a
//! vector made by `viem@2.21.32` — `toCoinbaseSmartAccount`,
//! `getUserOperationHash` (EntryPoint 0.6), the owner's `sign` — not by this
//! crate: key `0x11…11`, sender `0x22…22`, target `0x33…33`, inner call
//! `0xdeadbeef`, nonce 5, chain 84532.

#![allow(clippy::unwrap_used)]

use ksg_anchor_v2::evm::{address_of, key_from_secret, unhex};
use ksg_anchor_v2::user_op::{
    decode_execute, execute_data, get_address_data, init_code, wrap_signature, UserOp,
    ENTRY_POINT_V06, STUB_SIGNATURE,
};

const OWNER: &str = "0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A";
const CALL_DATA: &str = "0xb61d27f60000000000000000000000003333333333333333333333333333333333333333000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000004deadbeef00000000000000000000000000000000000000000000000000000000";
const INIT_CODE: &str = "0x0ba5ed0c6aa8c49038f819e587e2633c4a9f428a3ffba36f0000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002000000000000000000000000019E7E376E7C213B7E7e7e46cc70A5dD086DAff2A";
const GET_ADDRESS: &str = "0x250b1b410000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002000000000000000000000000019E7E376E7C213B7E7e7e46cc70A5dD086DAff2A";
const HASH: &str = "0xa12237cde1d3dd44599b2d77d2954a84a6112d7b918b429ea3ef29d0086ebc41";
const SIGNATURE: &str = "0x00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000418baf784ca31ee7d4022c062b202b45e0a29d03e6598e2d5beda79e0b801f24e46e7b118fdd10293dd57cb92e262d38f7c041fe6613c37872a4f3991d5a2e64f41b00000000000000000000000000000000000000000000000000000000000000";
const STUB: &str = "0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000041fffffffffffffffffffffffffffffff0000000000000000000000000000000007aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1c00000000000000000000000000000000000000000000000000000000000000";

fn op() -> UserOp {
    let owner: [u8; 20] = unhex(OWNER).unwrap().try_into().unwrap();
    let mut nonce = [0u8; 32];
    nonce[31] = 5;
    let mut pm = vec![0x44; 20];
    pm.extend_from_slice(&[0xab, 0xcd]);
    UserOp {
        sender: [0x22; 20],
        nonce,
        init_code: init_code(&owner),
        call_data: execute_data(&[0x33; 20], &[0xde, 0xad, 0xbe, 0xef]),
        call_gas_limit: 100_000,
        verification_gas_limit: 200_000,
        pre_verification_gas: 50_000,
        max_fee_per_gas: 3_000_000,
        max_priority_fee_per_gas: 1_000_000,
        paymaster_and_data: pm,
        signature: Vec::new(),
    }
}

#[test]
fn the_pieces_are_the_ones_viem_makes() {
    let key = key_from_secret(&[0x11; 32]).unwrap();
    let owner = address_of(key.verifying_key());
    assert_eq!(owner.to_vec(), unhex(OWNER).unwrap());
    assert_eq!(
        execute_data(&[0x33; 20], &[0xde, 0xad, 0xbe, 0xef]),
        unhex(CALL_DATA).unwrap()
    );
    assert_eq!(init_code(&owner), unhex(INIT_CODE).unwrap());
    assert_eq!(get_address_data(&owner), unhex(GET_ADDRESS).unwrap());
    assert_eq!(wrap_signature(&STUB_SIGNATURE), unhex(STUB).unwrap());
    assert_eq!(
        decode_execute(&unhex(CALL_DATA).unwrap()),
        Some(([0x33; 20], vec![0xde, 0xad, 0xbe, 0xef]))
    );
}

#[test]
fn the_hash_and_the_signature_are_the_ones_viem_makes() {
    let mut op = op();
    assert_eq!(
        op.hash(&ENTRY_POINT_V06, 84_532).to_vec(),
        unhex(HASH).unwrap()
    );
    // Another chain or another EntryPoint is another hash.
    assert_ne!(
        op.hash(&ENTRY_POINT_V06, 8_453).to_vec(),
        unhex(HASH).unwrap()
    );
    assert_ne!(op.hash(&[0; 20], 84_532).to_vec(), unhex(HASH).unwrap());
    op.sign(&key_from_secret(&[0x11; 32]).unwrap(), 84_532)
        .unwrap();
    assert_eq!(op.signature, unhex(SIGNATURE).unwrap());
}
