//! `ksg-service --config FILE` — the service process (`ksg_service_v2::server`).
//!
//! Builds one Solana sender per holder from its payer key file, reads the
//! state directory, listens, and prints `listening on ADDR` once it does.
//! Every change is on disk before it is answered, so the process is stopped
//! by killing it.

use std::collections::BTreeMap;
use std::path::Path;

use ksg_service_v2::anchoring::ChainSender;
use ksg_service_v2::server::{start, Config};
use ksg_service_v2::solana::SolanaSender;
use ksg_verify_v2::solana::HttpRpc;
use zeroize::Zeroizing;

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let path = match args.as_slice() {
        [flag, path] if flag == "--config" => path,
        _ => return Err("usage: ksg-service --config FILE".into()),
    };
    let cfg: Config = serde_json::from_slice(
        &std::fs::read(Path::new(path)).map_err(|e| format!("{path}: {e}"))?,
    )
    .map_err(|e| format!("{path}: {e}"))?;
    let mut senders: BTreeMap<String, Box<dyn ChainSender + Send>> = BTreeMap::new();
    for h in &cfg.holders {
        let key = Zeroizing::new(
            std::fs::read(&h.payer).map_err(|e| format!("{}: {e}", h.payer.display()))?,
        );
        let s = SolanaSender::new(Box::new(HttpRpc::new(&cfg.rpc)?), &cfg.cluster, &key)
            .map_err(|e| format!("holder {}: {e}", h.id))?;
        eprintln!("ksg-service: holder {} pays from {}", h.id, s.address());
        senders.insert(h.id.clone(), Box::new(s));
    }
    let rpc = Box::new(HttpRpc::new(&cfg.rpc)?);
    let running = start(cfg, senders, rpc)?;
    println!("listening on {}", running.addr);
    running.wait();
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("ksg-service: {e}");
        std::process::exit(1);
    }
}
