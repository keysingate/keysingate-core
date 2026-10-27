//! `ksg-verify-v2` — a third party checks a journal export, a page of it or
//! the status section on its own machine, on core v2.
//!
//! ```text
//! ksg-verify-v2 --export FILE --container MULTIHASH --class heavy|light|bare
//!            --keys FILE [--json]
//!            [--rpc URL --cluster devnet|testnet|mainnet-beta|localnet [--forks]]
//!            [--scan-key FILE]
//!            [--channel FILE --issuer-keys FILE [--test]]
//! ksg-verify-v2 --file container.ksg --meta container.json --issuer-keys FILE
//! ```
//!
//! `--file` checks a container's file without opening it (CH-5a, CH-5b): the
//! issuer vouched at printing for the container's post-quantum key, and that
//! key signed this file (`ksg_verify_v2::file`).
//!
//! A release of the prototype is a test release: signed with public test keys
//! (`ksg_verify_v2::testkeys`), of no force. `--channel` refuses it unless
//! `--test` is given, and then the report says it is a test.
//!
//! `--channel` walks the documents from the release to the container — grants,
//! packet, binding, initiation — against the issuer keys the verifier holds
//! (`ksg_verify_v2::channel`). The class is then the packet's; `--class` may be
//! left out, and if given must agree.
//!
//! Without `--rpc` no anchor is read, and anything that needs one is refused.
//! With it, anchors are read from the node, which must prove it is the
//! cluster named by `--cluster` — the verifier's choice, not the export's.
//! `--forks` also looks for rival records after the same head (audit K5) among
//! the transactions of the accounts that paid for the export's anchors; a
//! rival refuses the export.
//!
//! Seals of a journal under the movable seal are anchored with a **blind** memo
//! (`ksg_verify_v2::solana`, module note): reading them needs the holder's scan
//! key, `--scan-key FILE` (`ksg-remote-panel scan-key --out FILE` gives it). Without it a
//! seal anchor is refused — the holder decides who may walk the series.
//!
//! The status section (`ksg-remote-panel export-statuses`) is checked the same way:
//! `--keys` then names the issuer's keys, and every status record's anchor
//! is read; without `--rpc` a status has no time and the section is refused.
//!
//! `--base-rpc URL --base FILE` (with `--channel`; FILE is the `<export>.base.json`
//! `ksg-remote-panel` writes beside a `light` export: the contract and the salt)
//! reads where a `light` export's seal stands among the container's anchors
//! on Base Sepolia (`ksg_verify_v2::base::export_on_base`): the key is made
//! from the release and serial the channel proves and the container's salt,
//! not taken from the holder. A page whose seal was never anchored is
//! refused; a full export whose seal is not anchored is accepted and says so.
//!
//! Exit code: 0 accepted, 1 rejected, 2 usage error.

use std::process::ExitCode;

use ksg_core_v2::anchor::AttestationVerifier;
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::Profile;
use ksg_core_v2::doc::Class;
use ksg_verify_v2::channel::{verify_channel, ChannelProof};
use ksg_verify_v2::{keys_from_json, verify_bytes, Expected, NoReader};

const USAGE: &str = "usage: ksg-verify-v2 --export FILE --container MULTIHASH \
--class heavy|light|bare --keys FILE [--json] \
[--rpc URL --cluster devnet|testnet|mainnet-beta|localnet [--forks]] [--scan-key FILE] \
[--channel FILE --issuer-keys FILE [--test] [--base-rpc URL --base FILE]]
       ksg-verify-v2 --file FILE --meta FILE --issuer-keys FILE
       ksg-verify-v2 --pair TRAILER_EXPORT LEADER_EXPORT";

struct Args {
    export: String,
    container: String,
    class: Option<String>,
    keys: String,
    channel: Option<String>,
    issuer_keys: Option<String>,
    json: bool,
    rpc: Option<String>,
    cluster: Option<String>,
    forks: bool,
    test: bool,
    scan_key: Option<String>,
    base_rpc: Option<String>,
    base: Option<String>,
}

fn parse(mut it: impl Iterator<Item = String>) -> Result<Args, String> {
    let (mut export, mut container, mut class, mut keys) = (None, None, None, None);
    let (mut json, mut forks, mut test) = (false, false, false);
    let (mut rpc, mut cluster) = (None, None);
    let (mut channel, mut issuer_keys) = (None, None);
    let mut scan_key = None;
    let (mut base_rpc, mut base) = (None, None);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--export" => export = it.next(),
            "--container" => container = it.next(),
            "--class" => class = it.next(),
            "--keys" => keys = it.next(),
            "--json" => json = true,
            "--rpc" => rpc = it.next(),
            "--cluster" => cluster = it.next(),
            "--forks" => forks = true,
            "--channel" => channel = it.next(),
            "--issuer-keys" => issuer_keys = it.next(),
            "--test" => test = true,
            "--scan-key" => scan_key = it.next(),
            "--base-rpc" => base_rpc = it.next(),
            "--base" => base = it.next(),
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    if rpc.is_some() != cluster.is_some() {
        return Err("--rpc and --cluster go together".into());
    }
    if scan_key.is_some() && rpc.is_none() {
        return Err("--scan-key needs --rpc: it reads anchors".into());
    }
    if channel.is_some() != issuer_keys.is_some() {
        return Err("--channel and --issuer-keys go together".into());
    }
    if class.is_none() && channel.is_none() {
        return Err("--class is required (or --channel, which names it)".into());
    }
    if forks && rpc.is_none() {
        return Err("--forks needs --rpc".into());
    }
    if base_rpc.is_some() != base.is_some() {
        return Err("--base-rpc and --base go together".into());
    }
    if base_rpc.is_some() && channel.is_none() {
        return Err(
            "--base-rpc needs --channel: the key is made from the release and serial it proves"
                .into(),
        );
    }
    if test && channel.is_none() {
        return Err("--test goes with --channel: the release is read from it".into());
    }
    Ok(Args {
        export: export.ok_or("--export is required")?,
        container: container.ok_or("--container is required")?,
        class,
        channel,
        issuer_keys,
        keys: keys.ok_or("--keys is required")?,
        json,
        rpc,
        cluster,
        forks,
        test,
        scan_key,
        base_rpc,
        base,
    })
}

/// `--file F --meta F --issuer-keys F`: the container's file, from outside.
fn file_mode(args: &[String]) -> ExitCode {
    let mut it = args.iter();
    let (mut file, mut meta, mut ik) = (None, None, None);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--file" => file = it.next(),
            "--meta" => meta = it.next(),
            "--issuer-keys" => ik = it.next(),
            other => {
                eprintln!("unknown argument {other:?}\n{USAGE}");
                return ExitCode::from(2);
            }
        }
    }
    let (Some(file), Some(meta), Some(ik)) = (file, meta, ik) else {
        eprintln!("--file needs --meta and --issuer-keys\n{USAGE}");
        return ExitCode::from(2);
    };
    let read = |p: &str| std::fs::read(p).map_err(|e| format!("{p}: {e}"));
    let setup = (|| -> Result<_, String> {
        let claim = ksg_verify_v2::file::FileClaim::from_meta(&read(meta)?)?;
        let keys = keys_from_json(&read(ik)?)?;
        Ok((read(file)?, claim, keys))
    })();
    let (bytes, claim, keys) = match setup {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{e}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match ksg_verify_v2::file::verify_file(&bytes, &claim, &keys) {
        Ok(t) => {
            println!(
                "ACCEPTED: the file is the one the container wrote (template {}); \
                 its key is the one the issuer vouched for at printing",
                t.to_multihash()
            );
            ExitCode::SUCCESS
        }
        Err(e) if claim.pq.is_none() => {
            println!("NOT VERIFIABLE: {e}");
            ExitCode::from(3)
        }
        Err(e) => {
            println!("REJECTED: {e}");
            ExitCode::from(1)
        }
    }
}

/// `--pair TRAILER LEADER`: the coupling of two containers, from both
/// whole-journal exports (owner's decision 13.10).
fn pair_mode(args: &[String]) -> ExitCode {
    let [flag, trailer, leader] = args else {
        eprintln!("--pair takes two exports: the trailer's and the leader's\n{USAGE}");
        return ExitCode::from(2);
    };
    debug_assert_eq!(flag, "--pair");
    let read = |p: &str| -> Result<ksg_core_v2::journal::BoundExport, String> {
        let bytes = std::fs::read(p).map_err(|e| format!("{p}: {e}"))?;
        serde_json::from_slice(&bytes).map_err(|e| format!("{p}: {e}"))
    };
    let (t, l) = match (read(trailer), read(leader)) {
        (Ok(t), Ok(l)) => (t, l),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("{e}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match ksg_verify_v2::coupling::verify_pair(&t, &l, &Profile::default()) {
        ksg_verify_v2::coupling::Pair::Confirmed { trailer, leader } => {
            println!(
                "ACCEPTED: {} is attached to {}; the leader is Pro and carries the trailer's last seal",
                trailer.to_multihash(),
                leader.to_multihash()
            );
            ExitCode::SUCCESS
        }
        ksg_verify_v2::coupling::Pair::Refused(why) => {
            println!("REJECTED: {why}");
            ExitCode::from(1)
        }
    }
}

fn main() -> ExitCode {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if raw.iter().any(|a| a == "--file") {
        return file_mode(&raw);
    }
    if raw.first().is_some_and(|a| a == "--pair") {
        return pair_mode(&raw);
    }
    let args = match parse(raw.into_iter()) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let setup = (|| -> Result<(Vec<u8>, Hash, Option<Class>, _, _), String> {
        let bytes = std::fs::read(&args.export).map_err(|e| format!("{}: {e}", args.export))?;
        let container =
            Hash::from_multihash(&args.container).map_err(|e| format!("--container: {e}"))?;
        let class = match &args.class {
            None => None,
            Some(c) => Some(
                serde_json::from_value::<Class>(serde_json::Value::String(c.clone()))
                    .map_err(|_| format!("--class: {c:?} is not heavy, light or bare"))?,
            ),
        };
        let keys =
            keys_from_json(&std::fs::read(&args.keys).map_err(|e| format!("{}: {e}", args.keys))?)?;
        let channel = match (&args.channel, &args.issuer_keys) {
            (Some(c), Some(k)) => {
                let proof: ChannelProof =
                    serde_json::from_slice(&std::fs::read(c).map_err(|e| format!("{c}: {e}"))?)
                        .map_err(|e| format!("--channel: {e}"))?;
                let ik = keys_from_json(&std::fs::read(k).map_err(|e| format!("{k}: {e}"))?)?;
                Some((proof, ik))
            }
            _ => None,
        };
        Ok((bytes, container, class, keys, channel))
    })();
    let (bytes, container, class, keys, channel) = match setup {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{e}\n{USAGE}");
            return ExitCode::from(2);
        }
    };

    // The channel first: it names the class the export is checked as.
    let channel_report = match &channel {
        None => None,
        Some((proof, issuer_keys)) => match verify_channel(proof, &container, issuer_keys, &keys) {
            Ok(r) if r.test && !args.test => {
                println!(
                    "REJECTED: channel: a test release ({}): signed with public test keys, \
                     of no force; --test checks it as a test",
                    r.release
                );
                return ExitCode::from(1);
            }
            Ok(r) => Some(r),
            Err(e) => {
                println!("REJECTED: channel: {e}");
                return ExitCode::from(1);
            }
        },
    };
    let class = match (class, &channel_report) {
        (Some(c), Some(r)) if c != r.class => {
            println!("REJECTED: --class {c:?} but the packet is {:?}", r.class);
            return ExitCode::from(1);
        }
        (Some(c), _) => c,
        (None, Some(r)) => r.class,
        (None, None) => unreachable!("parse requires one of them"),
    };

    #[cfg(feature = "rpc")]
    let node = match &args.rpc {
        None => None,
        Some(url) => match ksg_verify_v2::solana::HttpRpc::new(url) {
            Ok(n) => Some(n),
            Err(e) => {
                eprintln!("--rpc: {e}");
                return ExitCode::from(2);
            }
        },
    };
    #[cfg(not(feature = "rpc"))]
    if args.rpc.is_some() || args.forks {
        eprintln!("built without the `rpc` feature");
        return ExitCode::from(2);
    }
    #[cfg(feature = "rpc")]
    let scan = match &args.scan_key {
        None => None,
        Some(f) => match std::fs::read_to_string(f)
            .map_err(|e| format!("{f}: {e}"))
            .and_then(|s| ksg_verify_v2::solana::scan_keys_from_text(&s))
        {
            Ok(k) => Some(k),
            Err(e) => {
                eprintln!("--scan-key: {e}");
                return ExitCode::from(2);
            }
        },
    };
    #[cfg(feature = "rpc")]
    let reader = match (&node, &args.cluster) {
        (Some(n), Some(c)) => match ksg_verify_v2::solana::SolanaReader::connect(n, c) {
            Ok(r) => Some(
                scan.iter()
                    .flatten()
                    .fold(r, |r, k| r.with_scan_key(k.clone())),
            ),
            Err(e) => {
                println!("REJECTED: {e}");
                return ExitCode::from(1);
            }
        },
        _ => None,
    };
    #[cfg(not(feature = "rpc"))]
    let reader: Option<NoReader> = None;
    let anchors: &dyn AttestationVerifier = match &reader {
        Some(r) => r,
        None => &NoReader,
    };

    let mut report = verify_bytes(
        &bytes,
        &Expected {
            container,
            class,
            keys,
            // The product's rule (Г-1): an agent is named by the `did:key` of
            // the key it signs under.
            client_id_from_key: true,
            anchors,
        },
    );
    if report.accepted && args.cluster.as_deref() == Some(ksg_verify_v2::solana::LOCALNET) {
        report.limits.push(
            "anchored on a local node: only that machine saw these anchors, they prove nothing to anyone else",
        );
    } else if report.accepted && args.cluster.as_deref().is_some_and(|c| c != "mainnet-beta") {
        report.limits.push(
            "anchored on a test cluster: writing there is free and its history is not kept for long",
        );
    }
    #[cfg(feature = "rpc")]
    if report.accepted && args.forks {
        match check_forks(
            &bytes,
            node.as_ref().expect("--forks needs --rpc"),
            scan.as_deref(),
        ) {
            Ok(None) => report.limits.push(
                "forks were looked for only among the transactions of the accounts that paid for these anchors",
            ),
            Ok(Some(why)) | Err(why) => {
                report.accepted = false;
                report.reason = Some(why);
            }
        }
    }

    // `light` on Base Sepolia: where the export's seal stands among the
    // container's anchors, under the key the verifier makes itself.
    #[cfg(feature = "rpc")]
    if report.accepted {
        if let (Some(url), Some(file), Some(r)) = (&args.base_rpc, &args.base, &channel_report) {
            match on_base(url, file, r, &bytes) {
                Ok(on) => report.on_base = Some(on),
                Err(why) => {
                    report.accepted = false;
                    report.reason = Some(why);
                }
            }
        }
    }
    #[cfg(not(feature = "rpc"))]
    if args.base_rpc.is_some() {
        eprintln!("built without the `rpc` feature");
        return ExitCode::from(2);
    }

    if report.accepted {
        match channel_report {
            Some(r) => {
                if r.test {
                    report.limits.push(
                        "TEST RELEASE: signed with public test keys; it has no force as evidence",
                    );
                }
                report.limits.push(
                    "that this block was bound only once is not checked: that needs the network",
                );
                if !r.closed {
                    report.limits.push(
                        "the packet's completeness is not established: the bundle carries no closing statement",
                    );
                }
                report.channel = Some(r);
            }
            None => report.limits.push(
                "the release is not checked without --channel: a test container is not recognised",
            ),
        }
    }

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".into())
        );
    } else if report.accepted {
        println!("ACCEPTED ({:?})", report.form.expect("set when accepted"));
        if let Some(n) = report.pages {
            println!("  pages:       {n}");
        }
        if let Some(c) = report.counter {
            println!("  last number: {c}");
        }
        if let Some(a) = &report.author {
            println!("  author:      {a}");
        }
        if let Some(a) = report
            .first_agent
            .as_ref()
            .filter(|a| Some(*a) != report.author.as_ref())
        {
            println!(
                "  first agent: {a} (handed on at pages {:?})",
                report.transfers
            );
        }
        if let Some(t) = &report.anchored_at {
            println!("  anchored by: {t} (as the reader established)");
        }
        if let Some(f) = &report.journal_form {
            println!("  form:        {f:?}");
        }
        match report.on_base {
            Some(ksg_verify_v2::base::OnChain::Last { block }) => {
                println!("  Base:        the container's last anchor (block {block})");
            }
            Some(ksg_verify_v2::base::OnChain::Passed { block, after }) => println!(
                "  Base:        anchored (block {block}); the container went on: {after} anchors after it"
            ),
            Some(ksg_verify_v2::base::OnChain::Absent) => println!(
                "  Base:        the seal is not anchored — up to ten records go without the network, or a copy's full export"
            ),
            None => {}
        }
        for b in &report.bounds {
            println!(
                "  record {}:   no later than {} (as the reader established)",
                b.record, b.not_after
            );
        }
        if let Some(runs) = &report.runs {
            let runs: Vec<String> = runs.iter().map(|(a, b)| format!("{a}..={b}")).collect();
            println!(
                "  anchored:    {}",
                if runs.is_empty() {
                    "none".to_owned()
                } else {
                    runs.join(", ")
                }
            );
        }
        if let Some(c) = &report.channel {
            println!(
                "  release:     {} serial {} ({:?})",
                c.release, c.serial, c.class
            );
            println!("  packet to:   {}", c.holder);
            if c.channel.is_empty() {
                println!("  sold by:     the issuer");
            } else {
                println!("  channel:     {}", c.channel.join(" -> "));
            }
        }
        for l in &report.limits {
            println!("  not established: {l}");
        }
    } else {
        println!(
            "REJECTED: {}",
            report.reason.as_deref().unwrap_or("unknown reason")
        );
    }
    if report.accepted {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

/// `Ok(None)` when no rival record is found; `Ok(Some(why))` when one is.
#[cfg(feature = "rpc")]
fn check_forks(
    bytes: &[u8],
    rpc: &ksg_verify_v2::solana::HttpRpc,
    scan: Option<&[ksg_verify_v2::solana::SealScanKey]>,
) -> Result<Option<String>, String> {
    use ksg_core_v2::journal::{verify_bound, BoundExport};
    use ksg_core_v2::section::StatusExport;
    let forks = if let Ok(x) = serde_json::from_slice::<BoundExport>(bytes) {
        // Already checked: the records are what the verdict stood on.
        let r = verify_bound(&x, &ksg_core_v2::crypto::sign::Profile::default())
            .map_err(|e| e.to_string())?;
        let scan = scan.ok_or("forks among blind seal anchors: the holder's scan key is needed")?;
        ksg_verify_v2::solana::find_bound_forks(rpc, &x, &r.records, scan, 1000)?
    } else if let Ok(x) = serde_json::from_slice::<StatusExport>(bytes) {
        ksg_verify_v2::solana::find_status_forks(rpc, &x, 1000)?
    } else {
        return Err("--forks reads a journal export or the status section".into());
    };
    Ok(forks.first().map(|f| {
        format!(
            "fork: another record after the same head as record {} was anchored (transaction {})",
            f.number, f.signature
        )
    }))
}

/// Reads where the export's seal stands on Base Sepolia (`--base-rpc`).
#[cfg(feature = "rpc")]
fn on_base(
    url: &str,
    file: &str,
    channel: &ksg_verify_v2::channel::ChannelReport,
    export: &[u8],
) -> Result<ksg_verify_v2::base::OnChain, String> {
    let v: serde_json::Value =
        serde_json::from_slice(&std::fs::read(file).map_err(|e| format!("{file}: {e}"))?)
            .map_err(|e| format!("{file}: {e}"))?;
    let field = |k: &str| {
        v.get(k)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("{file}: no {k}"))
    };
    let (contract, salt) = (field("contract")?, field("salt")?);
    let word = |s: &str, what: &str| -> Result<Vec<u8>, String> {
        hex::decode(s.trim_start_matches("0x")).map_err(|_| format!("{what}: not hex"))
    };
    let contract: [u8; 20] = word(contract, "contract")?
        .try_into()
        .map_err(|_| "contract: not 20 bytes".to_owned())?;
    let salt: [u8; 32] = word(salt, "salt")?
        .try_into()
        .map_err(|_| "salt: not 32 bytes".to_owned())?;
    // Where the container's anchors start, when the holder's program wrote
    // it: logs are then read from there in spans.
    let from = v
        .get("from_block")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let rpc = ksg_verify_v2::solana::HttpRpc::new(url)?;
    ksg_verify_v2::base::export_on_base(
        &rpc,
        &contract,
        &channel.release,
        channel.serial,
        &salt,
        export,
        from,
    )
}
