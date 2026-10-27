//! A devnet in a thread: a JSON-RPC server over plain HTTP on 127.0.0.1 that
//! keeps a ledger of memo transactions.
//!
//! It answers the methods the reader and the verifier call, and it is strict
//! where the real one is: a transaction must verify (`read_memo_transaction`
//! checks the Ed25519 signature over the message), must name a blockhash it
//! handed out, and must be paid for.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ksg_anchor_v2::solana_tx::read_memo_transaction;
use ksg_verify_v2::solana::{GENESIS, MEMO_PROGRAM};
use serde_json::{json, Value};

pub const FEE: u64 = 5_000;

#[derive(Clone, Debug)]
pub struct Tx {
    pub signature: String,
    pub slot: u64,
    pub payer: String,
    pub memo: Vec<u8>,
}

#[derive(Default)]
pub struct Ledger {
    pub balances: BTreeMap<String, u64>,
    /// Oldest first.
    pub txs: Vec<Tx>,
    pub slot: u64,
    /// Take transactions but do not finalize them: they wait in `held`.
    pub hold: bool,
    pub held: Vec<Tx>,
    /// Bumped by `expire`: the blockhash handed out changes, and the old one
    /// is no longer valid.
    pub epoch: u8,
}

impl Ledger {
    /// A transaction the node takes without asking: a rival from another
    /// copy, planted by a test.
    pub fn plant(&mut self, payer: &str, memo: &str) -> String {
        self.slot += 1;
        let signature = format!("PLANTED{}", self.slot);
        self.txs.push(Tx {
            signature: signature.clone(),
            slot: self.slot,
            payer: payer.into(),
            memo: memo.as_bytes().to_vec(),
        });
        signature
    }

    fn blockhash(&self) -> String {
        bs58::encode([9u8.wrapping_add(self.epoch); 32]).into_string()
    }

    /// The held transactions land, in order.
    pub fn release(&mut self) {
        self.hold = false;
        for mut t in std::mem::take(&mut self.held) {
            self.slot += 1;
            t.slot = self.slot;
            self.txs.push(t);
        }
    }

    /// The held transactions are lost and their blockhash expires: they can
    /// never land.
    pub fn drop_held(&mut self) {
        self.hold = false;
        self.held.clear();
        self.epoch = self.epoch.wrapping_add(1);
    }

    fn call(&mut self, method: &str, p: &Value) -> Result<Value, String> {
        match method {
            "getGenesisHash" => Ok(json!(GENESIS[1].1)),
            "getLatestBlockhash" => Ok(json!({"context": {"slot": self.slot},
                "value": {"blockhash": self.blockhash(), "lastValidBlockHeight": self.slot + 150}})),
            "getBalance" => {
                let who = p[0].as_str().unwrap_or_default();
                Ok(
                    json!({"context": {"slot": self.slot}, "value": self.balances.get(who).copied().unwrap_or(0)}),
                )
            }
            "sendTransaction" => {
                let bytes = B64
                    .decode(p[0].as_str().ok_or("no transaction")?)
                    .map_err(|e| e.to_string())?;
                let tx = read_memo_transaction(&bytes)
                    .map_err(|e| format!("failed to deserialize: {e}"))?;
                if tx.blockhash != self.blockhash() {
                    return Err("Blockhash not found".into());
                }
                let bal = self.balances.entry(tx.payer.clone()).or_default();
                if *bal < FEE {
                    return Err(
                        "Attempt to debit an account but found no record of a prior credit.".into(),
                    );
                }
                *bal -= FEE;
                let t = Tx {
                    signature: tx.signature.clone(),
                    slot: 0,
                    payer: tx.payer,
                    memo: tx.memo,
                };
                if self.hold {
                    self.held.push(t);
                } else {
                    self.slot += 1;
                    self.txs.push(Tx {
                        slot: self.slot,
                        ..t
                    });
                }
                Ok(json!(tx.signature))
            }
            "getSignatureStatuses" => {
                let sig = p[0][0].as_str().unwrap_or_default();
                Ok(json!({"context": {"slot": self.slot}, "value": [self
                    .txs
                    .iter()
                    .find(|t| t.signature == sig)
                    .map(|t| json!({"slot": t.slot, "confirmations": null, "err": null, "confirmationStatus": "finalized"}))]}))
            }
            "isBlockhashValid" => {
                let bh = p[0].as_str().unwrap_or_default();
                Ok(json!({"context": {"slot": self.slot}, "value": bh == self.blockhash()}))
            }
            "getTransaction" => {
                let sig = p[0].as_str().unwrap_or_default();
                Ok(self.txs.iter().find(|t| t.signature == sig).map_or(Value::Null, |t| {
                    json!({
                        "slot": t.slot,
                        "blockTime": 1_790_000_000 + t.slot,
                        "meta": {"err": null},
                        "transaction": {"message": {
                            "accountKeys": [t.payer, MEMO_PROGRAM],
                            "instructions": [{"programIdIndex": 1, "accounts": [], "data": bs58::encode(&t.memo).into_string()}]
                        }}
                    })
                }))
            }
            "getSignaturesForAddress" => {
                let who = p[0].as_str().unwrap_or_default();
                let until = p[1]["until"].as_str();
                let limit = p[1]["limit"].as_u64().unwrap_or(1000) as usize;
                let mut out = Vec::new();
                for t in self.txs.iter().rev().filter(|t| t.payer == who) {
                    if Some(t.signature.as_str()) == until {
                        break;
                    }
                    out.push(json!({"signature": t.signature, "slot": t.slot, "err": null}));
                    if out.len() == limit {
                        break;
                    }
                }
                Ok(json!(out))
            }
            m => Err(format!("Method not found: {m}")),
        }
    }
}

pub struct MockDevnet {
    pub url: String,
    pub ledger: Arc<Mutex<Ledger>>,
}

fn serve(stream: TcpStream, ledger: Arc<Mutex<Ledger>>) {
    let mut r = BufReader::new(stream.try_clone().expect("clone"));
    let mut w = stream;
    loop {
        let mut len = None;
        let mut line = String::new();
        loop {
            line.clear();
            if r.read_line(&mut line).unwrap_or(0) == 0 {
                return;
            }
            if line == "\r\n" {
                break;
            }
            let l = line.to_ascii_lowercase();
            if let Some(v) = l.strip_prefix("content-length:") {
                len = v.trim().parse::<usize>().ok();
            }
        }
        let mut body = vec![0u8; len.unwrap_or(0)];
        if r.read_exact(&mut body).is_err() {
            return;
        }
        let req: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        let method = req["method"].as_str().unwrap_or_default().to_owned();
        let answer = match ledger.lock().unwrap().call(&method, &req["params"]) {
            Ok(v) => json!({"jsonrpc": "2.0", "id": req["id"], "result": v}),
            Err(e) => {
                json!({"jsonrpc": "2.0", "id": req["id"], "error": {"code": -32002, "message": e}})
            }
        };
        let out = serde_json::to_vec(&answer).unwrap();
        let head = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
            out.len()
        );
        if w.write_all(head.as_bytes())
            .and_then(|()| w.write_all(&out))
            .is_err()
        {
            return;
        }
    }
}

impl MockDevnet {
    pub fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = format!("http://{}", listener.local_addr().unwrap());
        let ledger = Arc::new(Mutex::new(Ledger::default()));
        let l = ledger.clone();
        std::thread::spawn(move || {
            for s in listener.incoming().flatten() {
                let l = l.clone();
                std::thread::spawn(move || serve(s, l));
            }
        });
        Self { url, ledger }
    }

    pub fn fund(&self, address: &str, lamports: u64) {
        *self
            .ledger
            .lock()
            .unwrap()
            .balances
            .entry(address.into())
            .or_default() += lamports;
    }
}
