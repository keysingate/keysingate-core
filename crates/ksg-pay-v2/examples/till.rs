//! The issuer's till from the command line (stand, Base Sepolia, no real money).
//!
//!   till required <payTo> <minor> <resource>          # prints the 402 body
//!   till accept   <payTo> <minor> <resource> < header # ACCEPTED / REFUSED
//!
//! Used by `scripts/e2e_ksg_x402.sh` against μ Gate's `ksg-smoke`.
use std::collections::BTreeSet;
use std::io::Read;

use ksg_pay_v2::{accept, payment_required, Address, Price, Till};

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let (Some(cmd), Some(pay_to), Some(minor), Some(resource)) =
        (a.first(), a.get(1), a.get(2), a.get(3))
    else {
        eprintln!("usage: till required|accept <payTo> <minor> <resource>");
        std::process::exit(2)
    };
    let till = Till::base_sepolia(Address::parse(pay_to).expect("payTo"));
    let price = Price {
        minor: minor.parse().expect("minor"),
        resource: resource.clone(),
        description: "a repeated bare".into(),
    };
    match cmd.as_str() {
        "required" => println!("{}", payment_required(&till, &price)),
        "accept" => {
            let mut h = String::new();
            std::io::stdin().read_to_string(&mut h).expect("stdin");
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_secs();
            match accept(&till, &price, &h, now, &mut BTreeSet::new()) {
                Ok(p) => println!(
                    "ACCEPTED from {} value {}",
                    p.authorization.from, p.authorization.value
                ),
                Err(e) => {
                    println!("REFUSED {e:?}");
                    std::process::exit(1)
                }
            }
        }
        _ => std::process::exit(2),
    }
}
