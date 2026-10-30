//! `ksg-remote-panel` — the reader on a command line, on core v2. Item P-5 of the MVP
//! plan; core v1's program is `ksg`, on core v1.
//!
//! ```text
//! ksg-remote-panel --home DIR init --class heavy|light|bare
//!                     [--emission ksg:em:test:NNNNNN] [--serial N] [--artifact URI]
//!                     [--anchor solana:devnet --payer KEYFILE [--rpc URL]]
//! ksg-remote-panel --home DIR [--mobile FILE] COMMAND
//!   packet | buyer-key | open-journal | finalize | status
//!   initiate                  (E-4: the client's key is born; its mobile half
//!                              is written to --mobile FILE, which must not exist)
//!   work --did TEXT
//!   attach --type URI --file F [--mime TYPE] [--keep journal|outside]   (17.10: the file whole in the journal, or its digest)
//!   form --to pro|light        (E-10: the owner; to Pro, the issuer too)
//!   handoff --name URI --new-mobile F   (E-5: to another agent of the same owner)
//!   rule --scope all|lift|URI,URI    (E-7: the rule of two seals; the owner seals)
//!   succeed --leader MULTIHASH          (E-14: the issuer; slot 1 of the coupling)
//!   pull --trailer MULTIHASH --trailer-seal MULTIHASH (E-5: slot 2)
//!   attach-to --leader-home DIR --agent URI --new-mobile F
//!                                       (bare, 13.10: E-9 to the leader's owner,
//!                                        hand-off to the leader's agent, slot 1)
//!   detach --former-mobile F            (bare, 13.10: the owner and the former
//!                                        client; burns the copy)
//!   export-page --number N[,N...] --by owner|client --out F
//!   export-final --out F
//!   keys --out F
//!   close-packet --used FROM-TO[,…] [--not-submitted FROM-TO[,…]]
//!                             (the holder's closing statement, into channel.json)
//!   export-statuses --out F   (the status section with its anchors, spec v2 §11)
//!   issuer-keys --out F       (the key the status records are signed with)
//!   scan-key --out F          (the holder's key to its blind anchors, for an auditor)
//! ksg-remote-panel mobile serve --half FILE
//!
//! the channel (P-8), each party at its own desk directory:
//! ksg-remote-panel issuer init --desk DIR --release ksg:em:test:NNNNNN --range FROM-TO
//! ksg-remote-panel issuer|distributor grant --desk DIR --to URI --keys FILE --size N --out FILE
//! ksg-remote-panel --home DIR holder          (the buyer: the URI to sell the packet to)
//! ksg-remote-panel issuer|distributor order --desk DIR --to HOLDER --class C --size N
//! ksg-remote-panel issuer|distributor confirm-payment --desk DIR --order ID --out FILE
//! ksg-remote-panel issuer|distributor cancel --desk DIR --order ID --reason TEXT
//! ksg-remote-panel issuer|distributor orders|expire --desk DIR
//! ksg-remote-panel issuer|distributor close --desk DIR --order ID --channel FILE
//! ksg-remote-panel distributor init   --desk DIR --name URI
//! ksg-remote-panel distributor accept --desk DIR --grant FILE --emission FILE
//! ksg-remote-panel --home DIR init --sale FILE --issuer-desk DIR [--serial N]
//! ksg-remote-panel issuer template --desk DIR --sale FILE --out FILE   (the packet's template)
//! ksg-remote-panel --home DIR init --template FILE [--serial N]
//! ksg-remote-panel --home DIR channel --out FILE
//! ```
//!
//! `init` prints a template: no client's key yet (CH-5b). `initiate` gives
//! birth to it — the container's half inside, the mobile half to
//! `--mobile FILE`, never whole — and to the container's identifier.
//!
//! Commands the client signs after that (`open-journal`, `work`, `attach`,
//! `form` — every seal is the client's — `export-page --by client`,
//! `export-final`) need `--mobile FILE`: the program
//! starts `ksg-remote-panel mobile serve` on it as a child process and signs through it.
//!
//! Exit code: 0 done, 1 refused or failed, 2 usage error.

use std::collections::BTreeMap;
use std::io::{self, BufReader};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ksg_cli_v2::anchoring::AnchorCfg;
use ksg_cli_v2::channel::{
    accept, cancel, close, confirm_payment, desk_init, expire, grant, issue_template, issuer_init,
    order, orders, parse_range, Sale, Template,
};
use ksg_cli_v2::home::{read, write_atomic};
use ksg_cli_v2::mobile::{serve, ChildMobile, Mobile, NoMobile, TtyConsent};
use ksg_cli_v2::{init, ChannelInit, InitOptions, PrintSource, Reader, Who};
use ksg_container_v2::client_key::MobileHalf;
use ksg_core_v2::doc::{Class, Uri};
use ksg_core_v2::journal::Mode;
use ksg_mobile_v2::ApproveAll;
use zeroize::Zeroizing;

const USAGE: &str = "KSG Remote Panel: presses the buttons of a KeysInGate container from outside; the container is never opened.
usage:
  ksg-remote-panel --home DIR init --class heavy|light|bare [--emission ksg:em:test:NNNNNN] [--serial N] [--artifact URI]
                                [--anchor solana:devnet|testnet|mainnet-beta|localnet (--payer KEYFILE | --service URL --holder ID) [--rpc URL]]
                                [--base-rpc URL --base-contract 0x.. --evm-key FILE [--gas self|sponsor]]
  ksg-remote-panel --home DIR packet --seat FILE   (the distributor that sold the packet takes its seat, C-12)
  ksg-remote-panel --home DIR [--mobile FILE] packet|buyer-key|open-journal|finalize|status
  ksg-remote-panel --home DIR --mobile NEW-FILE initiate   (the client's key is born; its half goes to NEW-FILE)
  ksg-remote-panel --home DIR --mobile-web ADDR [--web-root DIR] COMMAND  (the half in a browser page, ksg-web-v2)
  ksg-remote-panel --home DIR --mobile FILE work --did TEXT
  ksg-remote-panel --home DIR --mobile FILE attach --type URI --file F [--mime TYPE] [--keep journal|outside]
  ksg-remote-panel --home DIR --mobile FILE form --to pro|light
  ksg-remote-panel --home DIR [--mobile FILE] declare-dead [--distributor-desk DIR]   (C-12: the owner, or the distributor with the client)
  ksg-remote-panel --home DIR --mobile FILE publish-id --id URI   (Pro: the agent's ID in the chain, KS-8 C-10 step 1)
  ksg-remote-panel --home DIR --mobile FILE handoff --name URI --new-mobile F
  ksg-remote-panel --home DIR --mobile FILE rule --scope all|lift|URI,URI
  ksg-remote-panel --home DIR --mobile FILE succeed --leader MULTIHASH
  ksg-remote-panel --home DIR --mobile FILE pull --trailer MULTIHASH --trailer-seal MULTIHASH
  ksg-remote-panel --home DIR --mobile FILE attach-to --leader-home DIR --agent URI --new-mobile F
  ksg-remote-panel --home DIR detach --former-mobile F
  ksg-remote-panel --home DIR --mobile FILE owner-change [--evm-key FILE]   (light, Pro: to the buyer laid at E-3)
  ksg-remote-panel --home DIR --mobile FILE owner-change --new-owner-home DIR [--evm-key FILE]   (light, Pro: to a new owner, up to 104 times, 18.10)
  ksg-remote-panel --home DIR --mobile FILE owner-change --new-owner-home DIR [--base-rpc URL --base-contract ADDR --evm-key FILE --from-block N (required with the network)]   (bare: the transfer; with the network the issuance label passes on, 17.10)
  ksg-remote-panel --home DIR --mobile FILE claim --artifact-file FILE   (KS-8 C-10 step 3: hash(artifact) + hash(agent ID), after publish-id)
  ksg-remote-panel --home DIR owner-read-key --out FILE   (the owner's read key of the issuance label, for its company)
  ksg-remote-panel --home DIR label-key --out FILE   (the container's answer: owner and read key, for the issuer)
  ksg-remote-panel --home DIR [--mobile FILE] export-page --number N[,N...] --by owner|client --out F
  ksg-remote-panel --home DIR --mobile FILE export-final --out F
  ksg-remote-panel --home DIR keys --out F
  ksg-remote-panel --home DIR export-statuses --out F
  ksg-remote-panel --home DIR issuer-keys --out F
  ksg-remote-panel --home DIR scan-key --out F
  ksg-remote-panel --home DIR channel --out F
  ksg-remote-panel --home DIR close-packet --used FROM-TO[,...] [--not-submitted FROM-TO[,...]]
  ksg-remote-panel --home DIR holder
  ksg-remote-panel --home DIR delete --template ID   (a bare only: the owner deletes it with everything in it)
  ksg-remote-panel --home DIR record-views --from FILE
  ksg-remote-panel --home DIR views [--since TIME --until TIME]
  ksg-remote-panel --home DIR service-register --service URL
  ksg-remote-panel --home DIR service-look --service URL --anchor CLUSTER:SIGNATURE
  ksg-remote-panel --home DIR service-views --service URL --holder ID
  ksg-remote-panel --home DIR init --sale FILE --issuer-desk DIR [--serial N] [--artifact URI] [--anchor ...]
  ksg-remote-panel --home DIR init --template FILE [--serial N] [--artifact URI] [--anchor ...]
  ksg-remote-panel issuer template --desk DIR --sale FILE --out FILE
  ksg-remote-panel issuer init --desk DIR --release ksg:em:test:NNNNNN --range FROM-TO [--ttl-days N]
  ksg-remote-panel issuer|distributor grant --desk DIR --to URI --keys FILE --size N [--days 90] --out FILE
  ksg-remote-panel issuer|distributor order --desk DIR --to HOLDER --class heavy|light|bare --size N [--days 365]
  ksg-remote-panel issuer|distributor confirm-payment --desk DIR --order ID --out FILE
  ksg-remote-panel issuer|distributor cancel --desk DIR --order ID --reason TEXT
  ksg-remote-panel issuer|distributor orders|expire --desk DIR
  ksg-remote-panel issuer|distributor close --desk DIR --order ID --channel FILE
  ksg-remote-panel distributor init --desk DIR --name URI
  ksg-remote-panel distributor accept --desk DIR --grant FILE --emission FILE
  ksg-remote-panel distributor seat --desk DIR --sale FILE --out FILE   (the seller's seat in the packet's containers, C-12)
  ksg-remote-panel mobile serve --half FILE [--confirm]
  ksg-remote-panel declare-lost --half FILE [--anchor-key 0x..] --base-rpc URL --base-contract 0x.. --evm-key FILE [--gas self|sponsor] [--from-block N]
  ksg-remote-panel lost-status --anchor-key 0x.. | --half FILE  --base-rpc URL --base-contract 0x.. [--from-block N]";

enum Failure {
    Usage(String),
    Failed(String),
}

fn usage(s: impl Into<String>) -> Failure {
    Failure::Usage(s.into())
}

impl From<String> for Failure {
    fn from(s: String) -> Self {
        Self::Failed(s)
    }
}

/// `--name value` pairs after the command; a flag given twice is a usage error.
fn flags(rest: &[String]) -> Result<BTreeMap<String, String>, Failure> {
    let mut out = BTreeMap::new();
    let mut it = rest.iter();
    while let Some(k) = it.next() {
        let Some(name) = k.strip_prefix("--") else {
            return Err(usage(format!("unexpected argument: {k}")));
        };
        let v = it
            .next()
            .ok_or_else(|| usage(format!("--{name} needs a value")))?;
        if out.insert(name.to_owned(), v.clone()).is_some() {
            return Err(usage(format!("--{name} given twice")));
        }
    }
    Ok(out)
}

fn need<'a>(f: &'a BTreeMap<String, String>, name: &str) -> Result<&'a str, Failure> {
    f.get(name)
        .map(String::as_str)
        .ok_or_else(|| usage(format!("--{name} is required")))
}

fn only(f: &BTreeMap<String, String>, allowed: &[&str]) -> Result<(), Failure> {
    match f.keys().find(|k| !allowed.contains(&k.as_str())) {
        Some(k) => Err(usage(format!("unknown flag --{k}"))),
        None => Ok(()),
    }
}

fn parse_uri(s: &str, what: &str) -> Result<Uri, Failure> {
    Uri::parse(s).map_err(|e| usage(format!("{what}: {e}")))
}

fn parse_class(s: &str) -> Result<Class, Failure> {
    serde_json::from_value(serde_json::Value::String(s.to_owned()))
        .map_err(|_| usage("--class must be heavy, light or bare"))
}

fn run(args: &[String]) -> Result<(), Failure> {
    // `ksg mobile serve --half FILE`
    if args.first().map(String::as_str) == Some("mobile") {
        if args.get(1).map(String::as_str) != Some("serve") {
            return Err(usage("mobile: only `serve`"));
        }
        let confirm = args.iter().any(|a| a == "--confirm");
        let rest: Vec<String> = args[2..]
            .iter()
            .filter(|a| *a != "--confirm")
            .cloned()
            .collect();
        let f = flags(&rest)?;
        only(&f, &["half"])?;
        let bytes = Zeroizing::new(read(Path::new(need(&f, "half")?))?);
        let half = MobileHalf::from_bytes(&bytes).map_err(|e| format!("mobile half: {e}"))?;
        let stdin = io::stdin();
        let (input, output) = (BufReader::new(stdin.lock()), io::stdout().lock());
        return if confirm {
            serve(half, TtyConsent, input, output)
        } else {
            serve(half, ApproveAll, input, output)
        }
        .map_err(Failure::Failed);
    }

    // `ksg issuer …` and `ksg distributor …`: the desks of the channel.
    if let Some(role @ ("issuer" | "distributor")) = args.first().map(String::as_str) {
        return desk_command(role, &args[1..]);
    }
    // `ksg issue-anchor put|check …`: the issuance anchor of a `bare` on Base
    // Sepolia (owner's decisions 06.10 and 14.10). No container: the issuers'
    // program writes and reads it, outside any container.
    if args.first().map(String::as_str) == Some("issue-anchor") {
        return issue_anchor_command(&args[1..]);
    }
    // `ksg declare-lost` / `ksg lost-status` (E-19, owner's decisions 15.10):
    // the container is gone, so no `--home` — the mobile half and the chain.
    if let Some(cmd @ ("declare-lost" | "lost-status")) = args.first().map(String::as_str) {
        return lost_command(cmd, &args[1..]);
    }
    // Core v2 has no transparency log (spec v2 §17): `ksg log` of core v1's
    // program has no counterpart here, and says so rather than "unknown".
    if args.first().map(String::as_str) == Some("log") {
        return Err(usage(
            "there is no transparency log on core v2: use core v1's `ksg log`",
        ));
    }

    // Global flags, then the command, then its flags.
    let mut home: Option<PathBuf> = None;
    let mut mobile: Option<PathBuf> = None;
    let mut mobile_web: Option<String> = None;
    let mut web_root: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() && args[i].starts_with("--") {
        let v = args
            .get(i + 1)
            .ok_or_else(|| usage(format!("{} needs a value", args[i])))?;
        match args[i].as_str() {
            "--home" => home = Some(v.into()),
            "--mobile" => mobile = Some(v.into()),
            "--mobile-web" => mobile_web = Some(v.clone()),
            "--web-root" => web_root = Some(v.into()),
            other => return Err(usage(format!("unknown flag {other}"))),
        }
        i += 2;
    }
    let home = home.ok_or_else(|| usage("--home is required"))?;
    let cmd = args.get(i).ok_or_else(|| usage("no command"))?.as_str();
    let f = flags(&args[i + 1..])?;

    if cmd == "delete" {
        only(&f, &["template"])?;
        let gone = ksg_cli_v2::reader::delete_bare(&home, need(&f, "template")?)?;
        println!("deleted    {} files", gone.len());
        println!("copies     a copy elsewhere is another file: not touched");
        return Ok(());
    }
    if cmd == "holder" {
        only(&f, &[])?;
        println!("{}", ksg_cli_v2::reader::holder(&home)?);
        return Ok(());
    }
    if cmd == "init" {
        only(
            &f,
            &[
                "class",
                "emission",
                "serial",
                "artifact",
                "anchor",
                "payer",
                "service",
                "holder",
                "rpc",
                "sale",
                "issuer-desk",
                "template",
                "base-rpc",
                "base-contract",
                "evm-key",
                "gas",
            ],
        )?;
        let source = match (f.get("sale"), f.get("issuer-desk"), f.get("template")) {
            (None, None, None) => None,
            (Some(sale), Some(desk), None) => {
                let sale: Sale = serde_json::from_slice(&read(Path::new(sale))?)
                    .map_err(|e| format!("--sale: {e}"))?;
                Some((sale, PrintSource::Desk(PathBuf::from(desk))))
            }
            (None, None, Some(t)) => {
                let sale = Template::open(Path::new(t))?.sale.clone();
                Some((sale, PrintSource::Template(PathBuf::from(t))))
            }
            (_, _, Some(_)) => {
                return Err(usage(
                    "--template prints on its own: no --sale, no --issuer-desk",
                ))
            }
            _ => return Err(usage("--sale and --issuer-desk go together")),
        };
        let from_template = matches!(source, Some((_, PrintSource::Template(_))));
        let channel = match source {
            None => None,
            Some((sale, source)) => {
                if let Some(c) = f.get("class") {
                    if parse_class(c)? != sale.packet.class {
                        return Err(usage("--class differs from the packet's class"));
                    }
                }
                if f.contains_key("emission") {
                    return Err(usage("--emission comes from the sale"));
                }
                Some(ChannelInit {
                    source,
                    serial: f
                        .get("serial")
                        .map(|s| s.parse().map_err(|_| usage("--serial must be a number")))
                        .transpose()?,
                    sale,
                })
            }
        };
        let anchor = anchor_flags(&f)?;
        let opts = InitOptions {
            class: match (&channel, f.get("class")) {
                (Some(ch), _) => ch.sale.packet.class,
                (None, _) => parse_class(need(&f, "class")?)?,
            },
            emission: f
                .get("emission")
                .cloned()
                .unwrap_or_else(|| "ksg:em:test:000001".into()),
            serial: f.get("serial").map_or(Ok(1), |s| {
                s.parse().map_err(|_| usage("--serial must be a number"))
            })?,
            artifact: parse_uri(
                f.get("artifact").map_or("ksg:artifact:mvp", String::as_str),
                "--artifact",
            )?,
            anchor,
            channel,
            base: base_flags(&f)?,
        };
        // `light` anchors on Base Sepolia; Pro keeps its anchors on Solana and
        // takes Base as its second network for E-19 only (owner's decision
        // 16.10 "A"); `bare` is never anchored.
        if opts.base.is_some() && opts.class == Class::Bare {
            return Err(usage(
                "--base-rpc: a bare is never anchored; light anchors on Base Sepolia, \
                 Pro keeps its anchors on Solana and uses Base for E-19 only",
            ));
        }
        if mobile.is_some() {
            return Err(usage(
                "init prints no client's key: it is born at `--mobile FILE initiate`",
            ));
        }
        let meta = init(&home, &opts)?;
        println!("template   {}", meta.template);
        println!("serial     {}", meta.serial.0);
        if meta.base.is_some() && meta.class == Class::Light {
            // Ya-1: the container is born on the chain with its first status
            // record. Printing is online; with no network there is no print.
            // (Pro's anchors are Solana's: Base takes Pro only at initiation,
            // for E-19.)
            let mut r = Reader::open(&home, Box::new(NoMobile))?;
            r.base_anchor()?;
            println!(
                "anchored   Base Sepolia, tx {}",
                r.meta
                    .base
                    .as_ref()
                    .and_then(|b| b.last_tx.clone())
                    .unwrap_or_default()
            );
        }
        if from_template {
            // A container of a template carries what the template does: the
            // packet's layer and the buyer's key (statuses 1 and 2).
            // Bare v2 (Goal 1, owner's decision 08.10) has no packet layer:
            // ApplyPacket does not exist in that class, so only the buyer's
            // key is laid — the status is still BuyerKeyed (2), the numbers
            // are normative and no step is renumbered.
            let mut r = Reader::open(&home, Box::new(NoMobile))?;
            if opts.class != Class::Bare {
                r.packet()?;
            }
            r.buyer_key()?;
            if opts.class == Class::Bare {
                println!("status     2 (buyer's key on; initiate next)");
            } else {
                println!("status     2 (issuer's and buyer's keys on; initiate next)");
            }
        }
        return Ok(());
    }

    if cmd == "close-packet" {
        // No container is opened: the statement is the holder's, over the
        // packet, and goes into the channel bundle beside the container.
        only(&f, &["used", "not-submitted"])?;
        let ranges = |k: &str| -> Result<Vec<_>, Failure> {
            f.get(k).map_or(Ok(Vec::new()), |v| {
                v.split(',')
                    .map(|r| parse_range(r).map_err(usage))
                    .collect()
            })
        };
        let c = ksg_cli_v2::reader::close_packet(&home, ranges("used")?, ranges("not-submitted")?)?;
        println!(
            "closed     {}-{}: {} cancelled range(s), laid into channel.json",
            c.block.from,
            c.block.to,
            c.cancelled.len()
        );
        return Ok(());
    }

    if cmd == "scan-key" {
        // No container is opened: the key is the holder's file, and handing
        // it out is the holder's decision (`[decision]` 13.09).
        only(&f, &["out", "period"])?;
        let h = ksg_cli_v2::home::Home(home.clone());
        let k = ksg_cli_v2::reader::read_scan_key(&h)?;
        let meta: ksg_cli_v2::home::Meta = serde_json::from_slice(&read(&h.meta())?)
            .map_err(|x| format!("container.json: {x}"))?;
        let out = match meta.anchor.as_ref().filter(|c| c.rotate_scan) {
            // One key for life: the key itself.
            None => {
                if f.contains_key("period") {
                    return Err(usage("--period: this container's scan key does not change"));
                }
                zeroize::Zeroizing::new(k.to_hex().to_string())
            }
            // The keys of the periods asked for — one, or every one used.
            Some(cfg) => {
                let periods: Vec<&String> = match f.get("period") {
                    Some(p) if cfg.scan_periods.contains(p) => vec![p],
                    Some(p) => return Err(format!("no seal was anchored in period {p}").into()),
                    None => cfg.scan_periods.iter().collect(),
                };
                let mut m = serde_json::Map::new();
                for p in periods {
                    m.insert(
                        p.clone(),
                        serde_json::Value::String(k.for_period(p).to_hex().to_string()),
                    );
                }
                zeroize::Zeroizing::new(serde_json::json!({"periods": m}).to_string())
            }
        };
        write_atomic(Path::new(need(&f, "out")?), out.as_bytes(), true)?;
        return Ok(());
    }

    if cmd == "initiate" {
        // The mobile half does not exist yet: initiation gives birth to it.
        only(&f, &[])?;
        let out = mobile.ok_or_else(|| usage("initiate needs --mobile FILE for the half born"))?;
        let mut r = Reader::open(&home, Box::new(NoMobile))?;
        r.initiate(&out)?;
        println!("container  {}", r.meta.id);
        println!("mobile     {}", out.display());
        // E-19: the half alone declares a loss under the container's blind
        // anchor key — kept beside the half, since the container may be gone.
        if let Some(b) = &r.meta.base {
            let t = ksg_core_v2::crypto::hash::Hash::from_multihash(&r.meta.template)
                .map_err(|e| format!("container.json: template: {e}"))?;
            let key = ksg_anchor_v2::evm::hex0x(&b.anchor_key(&t)?);
            let side = PathBuf::from(format!("{}.anchor", out.display()));
            write_atomic(&side, key.as_bytes(), true)?;
            println!("anchor key {key} ({})", side.display());
        }
        return Ok(());
    }

    let mobile: Box<dyn Mobile> = match (&mobile, mobile_web) {
        (Some(_), Some(_)) => {
            return Err(usage("--mobile and --mobile-web: one or the other"));
        }
        (Some(half), None) => {
            let me = std::env::current_exe().map_err(|e| format!("own path: {e}"))?;
            Box::new(ChildMobile::spawn(&me, half)?)
        }
        // The half in a browser page (ksg-web-v2): the address goes to the
        // holder on the error stream, the output stays the command's.
        (None, Some(addr)) => {
            let web = ksg_cli_v2::web_mobile::WebMobile::listen(&addr, web_root)?;
            eprintln!("mobile half: open {}", web.url);
            Box::new(web)
        }
        (None, None) => Box::new(NoMobile),
    };
    let mut r = Reader::open(&home, mobile)?;

    match cmd {
        "packet" if f.contains_key("seat") => {
            only(&f, &["seat"])?;
            let seat: ksg_cli_v2::channel::DistributorSeat =
                serde_json::from_slice(&read(Path::new(need(&f, "seat")?))?)
                    .map_err(|e| format!("--seat: {e}"))?;
            r.packet_seating(Some(&seat))?;
            println!(
                "seated     {} — the distributor that sold the packet",
                seat.distributor.as_str()
            );
        }
        "packet" | "buyer-key" | "open-journal" | "finalize" | "status" => {
            only(&f, &[])?;
            match cmd {
                "packet" => r.packet()?,
                "buyer-key" => r.buyer_key()?,
                "open-journal" => r.open_journal()?,
                "finalize" => r.finalize()?,
                _ => {}
            }
        }
        "work" => {
            only(&f, &["did"])?;
            r.work(need(&f, "did")?)?;
        }
        "attach" => {
            only(&f, &["type", "file", "mime", "keep"])?;
            let ty = parse_uri(need(&f, "type")?, "--type")?;
            let path = Path::new(need(&f, "file")?);
            let bytes = read(path)?;
            let name = path
                .file_name()
                .map_or_else(|| "file".into(), |n| n.to_string_lossy().into_owned());
            let mime = f
                .get("mime")
                .map_or("application/octet-stream", String::as_str);
            let whole = match f.get("keep").map_or("outside", String::as_str) {
                "journal" => true,
                "outside" => false,
                _ => return Err(usage("--keep must be journal or outside")),
            };
            r.attach(ty, &bytes, &name, mime, whole)?;
        }
        "export-page" => {
            only(&f, &["number", "by", "out"])?;
            let by = match need(&f, "by")? {
                "owner" => Who::Owner,
                "client" => Who::Client,
                _ => return Err(usage("--by must be owner or client")),
            };
            // One number gives one page as before; a comma list gives up to 24
            // pages in one pointwise export (`[decision]` 06.10).
            let raw = need(&f, "number")?;
            let bytes = if raw.contains(',') {
                let numbers = raw
                    .split(',')
                    .map(|n| n.trim().parse())
                    .collect::<Result<Vec<u64>, _>>()
                    .map_err(|_| usage("--number must be a number or a comma list"))?;
                let pages = r.export_pages(&numbers, by)?;
                serde_json::to_vec_pretty(&pages).map_err(|e| e.to_string())?
            } else {
                let number = raw
                    .parse()
                    .map_err(|_| usage("--number must be a number or a comma list"))?;
                let page = r.export_page(number, by)?;
                serde_json::to_vec_pretty(&page).map_err(|e| e.to_string())?
            };
            write_atomic(Path::new(need(&f, "out")?), &bytes, false)?;
            base_beside(&r, need(&f, "out")?)?;
        }
        "export-final" => {
            only(&f, &["out"])?;
            let export = r.export_final()?;
            let bytes = serde_json::to_vec_pretty(&export).map_err(|e| e.to_string())?;
            write_atomic(Path::new(need(&f, "out")?), &bytes, false)?;
            base_beside(&r, need(&f, "out")?)?;
        }
        "form" => {
            only(&f, &["to"])?;
            let to = match need(&f, "to")? {
                "pro" => Mode::Pro,
                "light" => Mode::Local,
                _ => return Err(usage("--to must be pro or light")),
            };
            r.form(to)?;
        }
        "rule" => {
            only(&f, &["scope"])?;
            use ksg_core_v2::journal::{RuleScope, SealRule};
            let scope = match need(&f, "scope")? {
                "all" => RuleScope::All,
                "lift" => RuleScope::Lifted,
                t => RuleScope::Types(
                    t.split(',')
                        .map(|x| parse_uri(x, "--scope"))
                        .collect::<Result<_, _>>()?,
                ),
            };
            r.rule(SealRule { scope })?;
        }
        "succeed" => {
            only(&f, &["leader"])?;
            let leader = ksg_core_v2::crypto::hash::Hash::from_multihash(need(&f, "leader")?)
                .map_err(|_| usage("--leader must be a container identifier"))?;
            r.succeed_to(leader)?;
        }
        "pull" => {
            only(&f, &["trailer", "trailer-seal"])?;
            let h = |k: &str| {
                ksg_core_v2::crypto::hash::Hash::from_multihash(need(&f, k)?)
                    .map_err(|_| usage("a multihash is expected"))
            };
            r.pull(h("trailer")?, h("trailer-seal")?)?;
        }
        "attach-to" => {
            only(
                &f,
                &[
                    "leader-home",
                    "agent",
                    "new-mobile",
                    "base-rpc",
                    "base-contract",
                    "evm-key",
                    "from-block",
                ],
            )?;
            let agent = parse_uri(need(&f, "agent")?, "--agent")?;
            let out = f.get("new-mobile").map(PathBuf::from);
            // With the network, the issuance label passes on to the leader's
            // owner as a step of the attachment (17.10 "B").
            let net = match f.get("base-rpc") {
                Some(rpc) => Some(ksg_cli_v2::reader::LabelNet {
                    rpc: rpc.clone(),
                    contract: need(&f, "base-contract")?.to_owned(),
                    key: PathBuf::from(need(&f, "evm-key")?),
                    from_block: need_from_block(&f)?,
                }),
                None => None,
            };
            r.attach_to(
                Path::new(need(&f, "leader-home")?),
                &agent,
                out.as_deref(),
                net.as_ref(),
            )?;
            println!("attached   {}", r.meta.id);
            if let Some(out) = out.filter(|p| p.exists()) {
                println!("mobile     {}", out.display());
            }
        }
        "detach" => {
            only(&f, &["former-mobile"])?;
            let me = std::env::current_exe().map_err(|e| format!("own path: {e}"))?;
            let former = ChildMobile::spawn(&me, Path::new(need(&f, "former-mobile")?))?;
            r.detach(Box::new(former))?;
            println!("detached   {} — the copy is burned", r.meta.id);
        }
        "declare-dead" => {
            only(&f, &["distributor-desk"])?;
            let d = f
                .get("distributor-desk")
                .map(|p| ksg_cli_v2::channel::distributor_signer(Path::new(p)))
                .transpose()?;
            let by = if d.is_some() {
                "the distributor with the client"
            } else {
                "the owner"
            };
            r.declare_dead(d)?;
            println!("dead       declared by {by}: the container does not work any more");
        }
        // A `light` or Pro to a new owner (owner's decision 18.10 "A"): the
        // EVM key is the new owner's, for the writer's seat on Base Sepolia.
        "owner-change" if f.contains_key("new-owner-home") && r.meta.class != Class::Bare => {
            only(&f, &["new-owner-home", "evm-key"])?;
            let kid = r.transfer_to(
                Path::new(need(&f, "new-owner-home")?),
                f.get("evm-key").map(Path::new),
            )?;
            println!("owner      {kid}");
        }
        "owner-change" if f.contains_key("new-owner-home") => {
            only(
                &f,
                &[
                    "new-owner-home",
                    "base-rpc",
                    "base-contract",
                    "evm-key",
                    "from-block",
                ],
            )?;
            // With the network, the issuance label passes on with the owner
            // (17.10): read there, its duplicate written there and in the
            // journal.
            let net = match f.get("base-rpc") {
                Some(rpc) => Some(ksg_cli_v2::reader::LabelNet {
                    rpc: rpc.clone(),
                    contract: need(&f, "base-contract")?.to_owned(),
                    key: PathBuf::from(need(&f, "evm-key")?),
                    from_block: need_from_block(&f)?,
                }),
                None => None,
            };
            let kid = r.bare_transfer(Path::new(need(&f, "new-owner-home")?), net.as_ref())?;
            println!("owner      {kid}");
            if net.is_some() {
                println!("label      passed on: the journal and the network");
            }
        }
        "owner-read-key" => {
            // The owner's read key for the people of its company (17.10,
            // condition 1): it opens issuance labels and signs nothing.
            only(&f, &["out"])?;
            let secret = r.owner_read_secret()?;
            write_atomic(
                Path::new(need(&f, "out")?),
                hex::encode(*secret).as_bytes(),
                true,
            )?;
            println!(
                "read key   {}",
                hex::encode(ksg_cli_v2::issue_label::read_public(&secret))
            );
        }
        "label-key" => {
            // The container's answer an issuer seals the label to (17.10,
            // condition 2).
            only(&f, &["out"])?;
            let answer = r.label_answer()?;
            let bytes = serde_json::to_vec_pretty(&answer).map_err(|e| e.to_string())?;
            write_atomic(Path::new(need(&f, "out")?), &bytes, false)?;
            println!("read key   {}", answer["read"].as_str().unwrap_or(""));
        }
        "owner-change" => {
            only(&f, &["evm-key"])?;
            match r.owner_change(f.get("evm-key").map(Path::new))? {
                Some(tx) => println!("handed     Base Sepolia, tx {tx}"),
                None if r.meta.base.as_ref().is_some_and(|b| b.hand_to.is_some()) => {
                    println!("handed     waits for Base Sepolia: goes before the next anchor");
                }
                None => {}
            }
            println!("owner      {}", r.buyer().kid.as_str());
        }
        // KS-8 C-10, step 3: hash(artifact) + hash(agent ID), after
        // `publish-id` (step 1).
        "claim" => {
            only(&f, &["artifact-file"])?;
            let bytes = read(Path::new(need(&f, "artifact-file")?))?;
            let artifact = ksg_core_v2::crypto::hash::Hash::sha256(&bytes);
            r.claim_ownership(artifact)?;
            println!("claimed    {}", artifact.to_multihash());
        }
        "publish-id" => {
            only(&f, &["id"])?;
            let (anchor, tx) = r.publish_id(need(&f, "id")?)?;
            println!("published  {}", need(&f, "id")?);
            println!("subject    {}", anchor.subject.to_multihash());
            match tx {
                Some(tx) => println!("anchored   Solana, tx {tx}"),
                None => println!("anchored   local (the stand: no network)"),
            }
        }
        "handoff" => {
            only(&f, &["name", "new-mobile"])?;
            let name = parse_uri(need(&f, "name")?, "--name")?;
            let out = PathBuf::from(need(&f, "new-mobile")?);
            r.handoff(&name, &out)?;
            println!("agent      {}", name.as_str());
            println!("mobile     {}", out.display());
        }
        "keys" => {
            only(&f, &["out"])?;
            write_atomic(Path::new(need(&f, "out")?), &r.client_keys_json()?, false)?;
        }
        "record-views" => {
            only(&f, &["from"])?;
            let notices: Vec<ksg_container_v2::view::ViewNotice> =
                serde_json::from_slice(&read(Path::new(need(&f, "from")?))?).map_err(|x| {
                    format!(
                        "{}: not a list of view notices: {x}",
                        need(&f, "from").unwrap_or_default()
                    )
                })?;
            let (taken, refused) = r.record_views(notices)?;
            println!("recorded   {taken}");
            for why in refused {
                println!("refused    {why}");
            }
        }
        "views" => {
            only(&f, &["since", "until"])?;
            match (f.get("since"), f.get("until")) {
                (Some(a), Some(b)) => {
                    let ts = |x: &str| {
                        ksg_core_v2::doc::Timestamp::parse(x)
                            .map_err(|_| usage("--since/--until: YYYY-MM-DDTHH:MM:SS.mmmZ"))
                    };
                    println!("looks      {}", r.views_in(&ts(a)?, &ts(b)?));
                }
                (None, None) => {
                    for line in r.view_lines() {
                        println!("{line}");
                    }
                }
                _ => return Err(usage("views: --since and --until go together")),
            }
        }
        #[cfg(feature = "rpc")]
        "service-register" => {
            only(&f, &["service"])?;
            let svc = ksg_cli_v2::service::Service::new(need(&f, "service")?);
            let a = r.service_register(&svc)?;
            println!("registered {}", a);
        }
        #[cfg(feature = "rpc")]
        "service-look" => {
            only(&f, &["service", "anchor"])?;
            let svc = ksg_cli_v2::service::Service::new(need(&f, "service")?);
            let (cluster, signature) = need(&f, "anchor")?
                .split_once(':')
                .ok_or_else(|| usage("--anchor CLUSTER:SIGNATURE"))?;
            let a = r.service_look(
                &svc,
                ksg_container_v2::view::AnchorRef {
                    cluster: cluster.to_owned(),
                    signature: signature.to_owned(),
                },
            )?;
            println!("looked     {a}");
        }
        #[cfg(feature = "rpc")]
        "service-views" => {
            only(&f, &["service", "holder"])?;
            let svc = ksg_cli_v2::service::Service::new(need(&f, "service")?);
            let (taken, refused, dropped) = r.service_views(&svc, need(&f, "holder")?)?;
            println!("recorded   {taken}");
            if dropped > 0 {
                println!("dropped    {dropped} at the service, for want of room");
            }
            for why in refused {
                println!("refused    {why}");
            }
        }
        "export-statuses" => {
            only(&f, &["out"])?;
            write_atomic(Path::new(need(&f, "out")?), &r.status_export_json()?, false)?;
        }
        "issuer-keys" => {
            only(&f, &["out"])?;
            write_atomic(Path::new(need(&f, "out")?), &r.issuer_keys_json()?, false)?;
        }
        "channel" => {
            only(&f, &["out"])?;
            let proof = read(&home.join("channel.json")).map_err(|_| {
                "no channel.json: the container was not printed on a packet, or is not initiated yet (the channel's documents are made at initiation)".to_string()
            })?;
            write_atomic(Path::new(need(&f, "out")?), &proof, false)?;
        }
        other => return Err(usage(format!("unknown command {other}"))),
    }
    for line in r.status_lines() {
        println!("{line}");
    }
    Ok(())
}

fn desk_command(role: &str, args: &[String]) -> Result<(), Failure> {
    let sub = args
        .first()
        .ok_or_else(|| usage(format!("{role}: which command?")))?
        .as_str();
    let f = flags(&args[1..])?;
    let desk = PathBuf::from(need(&f, "desk")?);
    let days = |default: u64| -> Result<u64, Failure> {
        f.get("days").map_or(Ok(default), |d| {
            d.parse().map_err(|_| usage("--days must be a number"))
        })
    };
    let size = || -> Result<u64, Failure> {
        need(&f, "size")?
            .parse()
            .map_err(|_| usage("--size must be a number"))
    };
    match (role, sub) {
        ("issuer", "init") => {
            only(&f, &["desk", "release", "range", "ttl-days"])?;
            let release = need(&f, "release")?;
            ksg_cli_v2::testkeys::check_release(release).map_err(usage)?;
            let range = parse_range(need(&f, "range")?).map_err(usage)?;
            let ttl = f.get("ttl-days").map_or(Ok(365), |d| {
                d.parse().map_err(|_| usage("--ttl-days must be a number"))
            })?;
            let em = issuer_init(&desk, release, range, ttl)?;
            println!(
                "release    {} serials {}-{}",
                em.id, em.range.from.0, em.range.to.0
            );
            println!("keys       {}", desk.join("issuer-keys.json").display());
        }
        ("distributor", "init") => {
            only(&f, &["desk", "name"])?;
            let k = desk_init(&desk, need(&f, "name")?)?;
            println!("desk       {}", k.kid.as_str());
            println!("keys       {}", desk.join("keys.json").display());
        }
        // C-12, 17.10: the distributor's module — its seat in the containers
        // of a packet it sold, signed at its desk, handed to the holder.
        ("distributor", "seat") => {
            only(&f, &["desk", "sale", "out"])?;
            let sale: Sale = serde_json::from_slice(&read(Path::new(need(&f, "sale")?))?)
                .map_err(|e| format!("--sale: {e}"))?;
            let seat = ksg_cli_v2::channel::seat_statement(&desk, &sale)?;
            write_atomic(
                Path::new(need(&f, "out")?),
                &serde_json::to_vec_pretty(&seat).map_err(|e| e.to_string())?,
                false,
            )?;
            println!(
                "seat       {} for {}",
                seat.key.kid.as_str(),
                seat.holder.as_str()
            );
        }
        ("distributor", "accept") => {
            only(&f, &["desk", "grant", "emission"])?;
            let chain = serde_json::from_slice(&read(Path::new(need(&f, "grant")?))?)
                .map_err(|e| format!("--grant: {e}"))?;
            let em = serde_json::from_slice(&read(Path::new(need(&f, "emission")?))?)
                .map_err(|e| format!("--emission: {e}"))?;
            let r = accept(&desk, em, chain)?;
            println!("granted    serials {}-{}", r.from.0, r.to.0);
        }
        (_, "grant") => {
            only(&f, &["desk", "to", "keys", "size", "days", "out"])?;
            let keys = serde_json::from_slice(&read(Path::new(need(&f, "keys")?))?)
                .map_err(|e| format!("--keys: {e}"))?;
            let chain = grant(&desk, need(&f, "to")?, keys, size()?, days(90)?)?;
            let leaf = chain.last().expect("one link at least");
            write_atomic(
                Path::new(need(&f, "out")?),
                &serde_json::to_vec_pretty(&chain).map_err(|e| e.to_string())?,
                false,
            )?;
            println!(
                "granted    serials {}-{} to {} (level {})",
                leaf.range.from.0,
                leaf.range.to.0,
                leaf.delegate.as_str(),
                leaf.depth
            );
        }
        ("issuer", "template") => {
            only(&f, &["desk", "sale", "out"])?;
            let sale: Sale = serde_json::from_slice(&read(Path::new(need(&f, "sale")?))?)
                .map_err(|e| format!("--sale: {e}"))?;
            let t = issue_template(&desk, sale, Path::new(need(&f, "out")?))?;
            let b = t.sale.packet.block;
            println!(
                "template   serials {}-{} ({:?}) for {}, {} to print",
                b.from.0,
                b.to.0,
                t.sale.packet.class,
                t.sale.packet.holder.as_str(),
                t.left()
            );
        }
        (_, "order") => {
            only(&f, &["desk", "to", "class", "size", "days"])?;
            let o = order(
                &desk,
                need(&f, "to")?,
                parse_class(need(&f, "class")?)?,
                size()?,
                days(365)?,
            )?;
            println!(
                "order      {} — {} {:?} serials for {}, awaiting payment",
                o.id, o.size, o.class, o.to
            );
        }
        (_, "confirm-payment") => {
            only(&f, &["desk", "order", "out"])?;
            let sale = confirm_payment(&desk, need(&f, "order")?)?;
            write_atomic(
                Path::new(need(&f, "out")?),
                &serde_json::to_vec_pretty(&sale).map_err(|e| e.to_string())?,
                false,
            )?;
            println!(
                "packet     serials {}-{} ({:?}) to {}",
                sale.packet.block.from.0,
                sale.packet.block.to.0,
                sale.packet.class,
                sale.packet.holder.as_str()
            );
        }
        (_, "cancel") => {
            only(&f, &["desk", "order", "reason"])?;
            let id = need(&f, "order")?;
            cancel(&desk, id, need(&f, "reason")?)?;
            println!("order      {id} cancelled");
        }
        (_, "close") => {
            only(&f, &["desk", "order", "channel"])?;
            let id = need(&f, "order")?;
            let proof: ksg_verify_v2::channel::ChannelProof =
                serde_json::from_slice(&read(Path::new(need(&f, "channel")?))?)
                    .map_err(|e| format!("--channel: {e}"))?;
            let (hash, used) = close(&desk, id, &proof)?;
            println!("closed     {id}: {used} serial(s) used, closure {hash}");
        }
        (_, "orders") => {
            only(&f, &["desk"])?;
            for (id, stage) in orders(&desk)? {
                println!("{id:<10} {stage:?}");
            }
        }
        (_, "expire") => {
            only(&f, &["desk"])?;
            let gone = expire(&desk)?;
            if gone.is_empty() {
                println!("expired    none");
            }
            for id in gone {
                println!("expired    {id}");
            }
        }
        _ => return Err(usage(format!("unknown command: {role} {sub}"))),
    }
    Ok(())
}

/// The holder the anchor counts (owner's decision 27.10): the owner's e-mail
/// or the orchestrator's `did:web`, never a document. `email:<address>`,
/// `did-web:<did:web:…>`.
fn parse_docs(s: &str) -> Result<Vec<(ksg_verify_v2::issue_anchor::DocKind, String)>, Failure> {
    use ksg_verify_v2::issue_anchor::DocKind;
    s.split(',')
        .map(|d| {
            let (k, n) = d
                .split_once(':')
                .ok_or_else(|| usage("--docs is email:<address>[,did-web:<did:web:…>]"))?;
            let n = n.trim();
            let kind = match k {
                "email" => DocKind::Email,
                "did-web" => {
                    if !n.starts_with("did:web:") {
                        return Err(usage(format!(
                            "--docs: did-web must carry its prefix, did:web:… (got {n:?})"
                        )));
                    }
                    DocKind::DidWeb
                }
                other => {
                    return Err(usage(format!(
                        "--docs: unknown kind {other} (email, did-web)"
                    )))
                }
            };
            if n.is_empty() {
                return Err(usage("--docs: empty holder"));
            }
            Ok((kind, n.to_owned()))
        })
        .collect()
}

/// `issue-anchor label`: whoever holds the owner's read key reads the
/// issuance label of its `bare` from the network (17.10).
fn issue_label_command(f: &BTreeMap<String, String>) -> Result<(), Failure> {
    only(f, &["read-key", "base-rpc", "base-contract", "from-block"])?;
    let secret: Zeroizing<[u8; 32]> = Zeroizing::new(
        hex::decode(
            std::str::from_utf8(&Zeroizing::new(read(Path::new(need(f, "read-key")?))?))
                .map_err(|_| "--read-key: not text".to_owned())?
                .trim(),
        )
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| "--read-key: not 32 bytes of hex".to_owned())?,
    );
    let net = ksg_cli_v2::reader::LabelNet {
        rpc: need(f, "base-rpc")?.to_owned(),
        contract: need(f, "base-contract")?.to_owned(),
        key: PathBuf::new(),
        from_block: need_from_block(f)?,
    };
    match ksg_cli_v2::reader::label_on_chain(&net, &secret)? {
        None => println!("label      none opens with this read key"),
        Some((l, block)) => {
            println!("owner      {}", l.current_owner().kid.as_str());
            println!(
                "issued     to {}, by {}, at {}",
                l.owner.kid.as_str(),
                l.issuer,
                ksg_cli_v2::clock::utc(l.issued_ms).as_str()
            );
            println!("passes     {}", l.passes.len());
            println!("block      {block}");
        }
    }
    Ok(())
}

/// `issue-anchor put`: the issuer puts the anchor of a `bare` handed over
/// against `--docs` (the holder: an e-mail or a `did:web`). `issue-anchor
/// check`: the next issuer asks whether this holder already had a `bare` of
/// this release and version — `refused` if any anchor matches (the beta
/// repeats neither free nor for payment, owner's decision 27.10), `free` if
/// none does.
fn issue_anchor_command(args: &[String]) -> Result<(), Failure> {
    use ksg_verify_v2::issue_anchor::{open, period_of, scope, seal, BareCheckKey, ANCHOR_TAG};
    let sub = args.first().map_or("", String::as_str);
    let f = flags(args.get(1..).unwrap_or(&[]))?;
    if sub == "label" {
        return issue_label_command(&f);
    }
    let key = BareCheckKey::from_hex(
        std::str::from_utf8(&Zeroizing::new(read(Path::new(need(&f, "check-key")?))?))
            .map_err(|_| "--check-key: not text".to_owned())?,
    )?;
    let docs = parse_docs(need(&f, "docs")?)?;
    let docs_ref: Vec<_> = docs.iter().map(|(k, n)| (*k, n.as_str())).collect();
    let sc = scope(need(&f, "release")?, need(&f, "version")?);
    let contract: [u8; 20] = ksg_anchor_v2::evm::unhex(need(&f, "base-contract")?)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| usage("--base-contract is not 20 bytes"))?;
    match sub {
        "put" => {
            only(
                &f,
                &[
                    "check-key",
                    "docs",
                    "release",
                    "version",
                    "year",
                    "base-rpc",
                    "base-contract",
                    "evm-key",
                    "gas",
                    "label-for",
                ],
            )?;
            let year = f.get("year").cloned().unwrap_or_else(|| {
                ksg_cli_v2::clock::utc(ksg_cli_v2::clock::now_ms()).as_str()[..4].to_owned()
            });
            let mut seed = [0u8; 32];
            rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut seed);
            let memo = seal(&key.for_period(&year), &year, &sc, &docs_ref, seed)?;
            let link =
                ksg_cli_v2::base_anchor::BaseLink::connect(&ksg_cli_v2::base_anchor::BaseCfg {
                    rpc: need(&f, "base-rpc")?.to_owned(),
                    contract: need(&f, "base-contract")?.to_owned(),
                    key: PathBuf::from(need(&f, "evm-key")?),
                    last: None,
                    since: 0,
                    last_tx: None,
                    pending: Vec::new(),
                    share: None,
                    salt: None,
                    hand_to: None,
                    sponsored: gas_flag(&f)?,
                    from_block: None,
                })?;
            let tx = link
                .note(ANCHOR_TAG, memo.as_bytes())
                .map_err(|e| match e {
                    ksg_cli_v2::base_anchor::AnchorError::Refused(r) => format!("refused: {r:?}"),
                    ksg_cli_v2::base_anchor::AnchorError::Network(x) => x,
                })?;
            println!("anchored   issuance, year {year}, tx {tx}");
            // The issuance label (17.10): whose, when, by whom — sealed to the
            // read key the container answered with (`ksg-remote-panel label-key`).
            if let Some(path) = f.get("label-for") {
                let answer: serde_json::Value = serde_json::from_slice(&read(Path::new(path))?)
                    .map_err(|e| format!("--label-for: {e}"))?;
                let owner: ksg_core_v2::crypto::sign::PublicKey =
                    serde_json::from_value(answer["owner"].clone())
                        .map_err(|e| format!("--label-for: owner: {e}"))?;
                let read_key: [u8; 32] = hex::decode(answer["read"].as_str().unwrap_or(""))
                    .ok()
                    .and_then(|v| v.try_into().ok())
                    .ok_or_else(|| "--label-for: read is not 32 bytes of hex".to_owned())?;
                let evm = ksg_cli_v2::base_anchor::read_key(Path::new(need(&f, "evm-key")?))?;
                let label = ksg_cli_v2::issue_label::Label::issue(
                    owner,
                    ksg_cli_v2::clock::now_ms(),
                    &evm,
                )?;
                let mut random = [0u8; 56];
                rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut random);
                let sealed = ksg_cli_v2::issue_label::seal(&label, &read_key, &random)?;
                let tx = link
                    .note(ksg_cli_v2::issue_label::LABEL_TAG, sealed.as_bytes())
                    .map_err(|e| match e {
                        ksg_cli_v2::base_anchor::AnchorError::Refused(r) => {
                            format!("refused: {r:?}")
                        }
                        ksg_cli_v2::base_anchor::AnchorError::Network(x) => x,
                    })?;
                println!("labelled   sealed to the owner's read key, tx {tx}");
            }
        }
        "check" => {
            only(
                &f,
                &[
                    "check-key",
                    "docs",
                    "release",
                    "version",
                    "base-rpc",
                    "base-contract",
                    "from-block",
                ],
            )?;
            let rpc = ksg_verify_v2::solana::HttpRpc::new(need(&f, "base-rpc")?)?;
            ksg_verify_v2::base::check_chain(&rpc, ksg_verify_v2::base::BASE_SEPOLIA_CHAIN_ID)?;
            let notes = ksg_verify_v2::base::notes(
                &rpc,
                &contract,
                &ksg_anchor_v2::evm::note_kind(ANCHOR_TAG),
                from_block_flag(&f)?,
            )?;
            let mut seen = 0usize;
            for n in &notes {
                let Ok(memo) = std::str::from_utf8(&n.data) else {
                    continue;
                };
                let Some(year) = period_of(memo) else {
                    continue;
                };
                let Ok(a) = open(&key.for_period(year), memo) else {
                    continue;
                };
                seen += 1;
                if a.matches(&key.for_period(year), &sc, &docs_ref)? {
                    println!(
                        "refused    a bare of this release and version was already issued to \
                         this holder (beta: no repeat, no payment)"
                    );
                    // The issuance label as the chain keeps it (`Bare_v2_spec`
                    // §5, K9): who issued and when; read with the issuer's key.
                    println!(
                        "issued     block {}, by {}",
                        n.block,
                        ksg_anchor_v2::evm::hex0x(&n.sender)
                    );
                    return Ok(());
                }
            }
            println!("free       no anchor matches ({seen} read)");
        }
        _ => return Err(usage("issue-anchor: put or check")),
    }
    Ok(())
}

/// `declare-lost`: the client's mobile half, alone, declares its container
/// lost on Base Sepolia — the half's public share, the moment, the hash of
/// the client's identifier, signed by the half. `lost-status`: what the chain
/// says. If the chain holds no commitment to the half, nothing can identify a
/// declaration, and the status stays frozen at its last state (E-19).
fn lost_command(cmd: &str, args: &[String]) -> Result<(), Failure> {
    use ksg_verify_v2::base::{
        client_id_hash, loss, lost_body, lost_message, Loss, BASE_SEPOLIA_CHAIN_ID, LOST_TAG,
    };
    let f = flags(args)?;
    // The container's blind anchor key (owner's decision 15.10 "B", the blind key): given,
    // or read from beside the half, where `initiate` left it.
    let key_hex = match (f.get("anchor-key"), f.get("half")) {
        (Some(k), _) => k.clone(),
        (None, Some(h)) => {
            String::from_utf8(ksg_cli_v2::home::read(Path::new(&format!("{h}.anchor")))?)
                .map_err(|_| "the anchor key file is not text".to_owned())?
        }
        (None, None) => {
            return Err(usage(
                "--anchor-key 0x.. (or --half FILE beside its .anchor)",
            ))
        }
    };
    let key: [u8; 32] = ksg_anchor_v2::evm::unhex(key_hex.trim())
        .map_err(|e| usage(format!("--anchor-key: {e}")))?
        .try_into()
        .map_err(|_| usage("--anchor-key is not 32 bytes"))?;
    let contract: [u8; 20] = ksg_anchor_v2::evm::unhex(need(&f, "base-contract")?)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| usage("--base-contract is not 20 bytes"))?;
    let rpc = ksg_verify_v2::solana::HttpRpc::new(need(&f, "base-rpc")?)?;
    ksg_verify_v2::base::check_chain(&rpc, BASE_SEPOLIA_CHAIN_ID)?;
    let kind = |t: &str| ksg_anchor_v2::evm::note_kind(t);
    let from = from_block_flag(&f)?;
    let state = loss(&rpc, &contract, &key, &kind, from)?;
    if cmd == "lost-status" {
        only(
            &f,
            &[
                "anchor-key",
                "half",
                "base-rpc",
                "base-contract",
                "from-block",
            ],
        )?;
        match state {
            Loss::NoIdentity => println!(
                "frozen     no commitment to the client's half on the chain: the status stays at its last state"
            ),
            Loss::NotDeclared => println!("in use     not declared lost"),
            Loss::Declared { block, at, client } => println!(
                "lost       declared at {} (block {block}), client {}",
                ksg_cli_v2::clock::utc(at.saturating_mul(1000)).as_str(),
                ksg_anchor_v2::evm::hex0x(&client)
            ),
        }
        return Ok(());
    }
    only(
        &f,
        &[
            "half",
            "anchor-key",
            "base-rpc",
            "base-contract",
            "evm-key",
            "gas",
            "from-block",
        ],
    )?;
    match state {
        Loss::NoIdentity => {
            return Err(Failure::Failed(
                "the chain holds no commitment to the client's half: nothing can identify a \
                 declaration, and the status stays frozen at its last state"
                    .into(),
            ))
        }
        Loss::Declared { .. } => {
            println!("lost       declared already");
            return Ok(());
        }
        Loss::NotDeclared => {}
    }
    let bytes = zeroize::Zeroizing::new(ksg_cli_v2::home::read(Path::new(need(&f, "half")?))?);
    let half = MobileHalf::from_bytes(&bytes).map_err(|e| format!("mobile half: {e}"))?;
    let share = half.share_public().map_err(|e| e.to_string())?;
    let client = client_id_hash(
        half.kid().as_str(),
        &half.client_public().map_err(|e| e.to_string())?,
    );
    let at = ksg_cli_v2::clock::now_ms() / 1000;
    let sig = half
        .sign_alone(&lost_message(&key, at, &client), &mut rand_core::OsRng)
        .map_err(|e| e.to_string())?;
    let link = ksg_cli_v2::base_anchor::BaseLink::connect(&ksg_cli_v2::base_anchor::BaseCfg {
        rpc: need(&f, "base-rpc")?.to_owned(),
        contract: need(&f, "base-contract")?.to_owned(),
        key: PathBuf::from(need(&f, "evm-key")?),
        last: None,
        since: 0,
        last_tx: None,
        pending: Vec::new(),
        share: None,
        salt: None,
        hand_to: None,
        sponsored: gas_flag(&f)?,
        from_block: None,
    })?;
    let tx = link
        .note(LOST_TAG, &lost_body(&key, &share, at, &client, &sig))
        .map_err(|e| match e {
            ksg_cli_v2::base_anchor::AnchorError::Refused(r) => format!("refused: {r:?}"),
            ksg_cli_v2::base_anchor::AnchorError::Network(x) => x,
        })?;
    if !matches!(
        loss(&rpc, &contract, &key, &kind, from)?,
        Loss::Declared { .. }
    ) {
        return Err(Failure::Failed(format!(
            "{tx}: on the chain, but the declaration does not hold against the commitment — \
             this half is not the container's"
        )));
    }
    println!("lost       declared, tx {tx}");
    Ok(())
}

/// Beside an export of a `light` container on Base Sepolia, `<out>.base.json`:
/// the contract and the salt of the blind anchor key. The verifier makes the
/// key from them and the template the channel proves (`ksg-verify-v2
/// --base-rpc URL --base FILE`); the salt alone names nothing.
fn base_beside(r: &Reader, out: &str) -> Result<(), String> {
    let Some(b) = r
        .meta
        .base
        .as_ref()
        .filter(|_| r.meta.class == Class::Light)
    else {
        return Ok(());
    };
    let Some(salt) = &b.salt else {
        return Ok(());
    };
    let json = serde_json::to_vec_pretty(&serde_json::json!({
        "contract": b.contract,
        "salt": salt,
        "from_block": b.from_block,
    }))
    .map_err(|e| e.to_string())?;
    let path = format!("{out}.base.json");
    write_atomic(Path::new(&path), &json, false)?;
    println!("base       {path}");
    Ok(())
}

fn base_flags(
    f: &BTreeMap<String, String>,
) -> Result<Option<ksg_cli_v2::base_anchor::BaseCfg>, Failure> {
    match (f.get("base-rpc"), f.get("base-contract"), f.get("evm-key")) {
        (None, None, None) if f.contains_key("gas") => {
            Err(usage("--gas sponsor goes with --base-rpc"))
        }
        (None, None, None) => Ok(None),
        (Some(rpc), Some(contract), Some(key)) => Ok(Some(ksg_cli_v2::base_anchor::BaseCfg {
            rpc: rpc.clone(),
            contract: contract.clone(),
            key: PathBuf::from(key),
            last: None,
            since: 0,
            last_tx: None,
            pending: Vec::new(),
            share: None,
            // The blind anchor key's salt (owner's decision 15.10 "B", the blind key).
            salt: Some(ksg_anchor_v2::evm::hex0x(&{
                let mut b = [0u8; 32];
                rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut b);
                b
            })),
            hand_to: None,
            sponsored: gas_flag(f)?,
            from_block: None,
        })),
        _ => Err(usage(
            "--base-rpc, --base-contract and --evm-key go together",
        )),
    }
}

/// `--from-block N`: the block the chain's logs are read from, in spans a
/// limited node still answers (`ksg_verify_v2::base::logs`); without it,
/// from block 0 in one question, as before.
/// `--from-block N`, required where the issuance label is read from the
/// network (owner's decision 18.10): without it the reading would start at
/// block 0 — tens of thousands of questions on Base Sepolia.
fn need_from_block(f: &BTreeMap<String, String>) -> Result<u64, Failure> {
    if !f.contains_key("from-block") {
        return Err(usage(
            "--from-block N is required with the network: the block the issuance \
             label was written at or before (reading from block 0 is not done)",
        ));
    }
    from_block_flag(f)
}

fn from_block_flag(f: &BTreeMap<String, String>) -> Result<u64, Failure> {
    f.get("from-block").map_or(Ok(0), |v| {
        v.parse()
            .map_err(|_| usage("--from-block must be a block number"))
    })
}

/// `--gas self|sponsor`: who pays the gas on Base Sepolia — the writer's key
/// (the default), or the sponsor through a smart account (owner's decision
/// 14.10; the sponsor's address from `KSG_PAYMASTER_URL`).
fn gas_flag(f: &BTreeMap<String, String>) -> Result<bool, Failure> {
    match f.get("gas").map(String::as_str) {
        None | Some("self") => Ok(false),
        Some("sponsor") if f.contains_key("base-rpc") => Ok(true),
        Some("sponsor") => Err(usage("--gas sponsor goes with --base-rpc")),
        Some(_) => Err(usage("--gas must be self or sponsor")),
    }
}

fn anchor_flags(f: &BTreeMap<String, String>) -> Result<Option<AnchorCfg>, Failure> {
    match f.get("anchor") {
        None => {
            if ["payer", "rpc", "service", "holder"]
                .iter()
                .any(|k| f.contains_key(*k))
            {
                return Err(usage(
                    "--payer, --service, --holder and --rpc go with --anchor",
                ));
            }
            Ok(None)
        }
        Some(a) => {
            let cluster = a
                .strip_prefix("solana:")
                .ok_or_else(|| usage("--anchor must be solana:CLUSTER"))?;
            Ok(Some(AnchorCfg {
                cluster: cluster.to_owned(),
                rpc: f
                    .get("rpc")
                    .cloned()
                    .unwrap_or_else(|| AnchorCfg::default_rpc(cluster)),
                payer: f.get("payer").map(PathBuf::from),
                service: match (f.get("service"), f.get("holder")) {
                    (Some(url), Some(holder)) if !f.contains_key("payer") => {
                        Some(ksg_cli_v2::anchoring::ServiceRoute {
                            url: url.clone(),
                            holder: holder.clone(),
                        })
                    }
                    (None, None) if f.contains_key("payer") => None,
                    _ => {
                        return Err(usage(
                            "--anchor takes --payer KEYFILE, or --service URL --holder ID",
                        ))
                    }
                },
                last_signature: None,
                pending: Vec::new(),
                // Printed from now on: a scan key per month (KS-1 §14.4, D-8).
                rotate_scan: true,
                scan_periods: Vec::new(),
            }))
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(Failure::Usage(m)) => {
            eprintln!("{m}\n{USAGE}");
            ExitCode::from(2)
        }
        Err(Failure::Failed(m)) => {
            eprintln!("{m}");
            ExitCode::FAILURE
        }
    }
}
