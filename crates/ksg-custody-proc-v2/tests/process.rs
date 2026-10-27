//! The program end to end: the process is shut before it reads, shares go out
//! and come back, and every way of handing it the wrong thing is a refusal.
//!
//! Most runs pass `--no-mlock`: a test machine's locked-memory limit is not
//! this crate's to raise. The one test that asks for the lock accepts either
//! outcome the program allows — locked, or exit 3 naming the remedy — and
//! nothing in between.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_ksg-custody");

fn run(args: &[&str]) -> Output {
    Command::new(BIN).args(args).output().expect("runs")
}

fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("ksg-custody-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).expect("dir");
    d
}

fn s(p: &Path) -> &str {
    p.to_str().expect("utf-8 path")
}

/// Splits a 32-byte key into `d/sh`, returns the key.
fn split(d: &Path) -> Vec<u8> {
    let key: Vec<u8> = (0u8..32).map(|i| i.wrapping_mul(97) ^ 0x3c).collect();
    fs::write(d.join("key"), &key).expect("key");
    let o = run(&[
        "split",
        "--secret",
        s(&d.join("key")),
        "--out",
        s(&d.join("sh")),
        "--no-mlock",
    ]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    key
}

#[test]
fn the_process_is_shut_before_it_reads() {
    let o = run(&["state", "--no-mlock"]);
    assert!(o.status.success());
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(out.contains("no_core=1"), "{out}");
    #[cfg(target_os = "linux")]
    assert!(out.contains("not_dumpable=1"), "{out}");
}

#[test]
fn asking_for_the_lock_gives_the_lock_or_a_named_refusal() {
    let o = run(&["state"]);
    let out = String::from_utf8_lossy(&o.stdout);
    let err = String::from_utf8_lossy(&o.stderr);
    match o.status.code() {
        Some(0) => assert!(out.contains("locked=1"), "{out}"),
        Some(3) => assert!(
            err.contains("mlockall failed") && err.contains("ulimit -l"),
            "{err}"
        ),
        other => panic!("exit {other:?}: {err}"),
    }
}

#[test]
fn any_three_shares_give_the_key_back() {
    let d = dir("roundtrip");
    let key = split(&d);
    for (i, pick) in [[1, 2, 3], [1, 3, 5], [2, 4, 5], [3, 4, 5]]
        .iter()
        .enumerate()
    {
        let out = d.join(format!("back-{i}"));
        let files: Vec<PathBuf> = pick
            .iter()
            .map(|n| d.join("sh").join(format!("share-{n}.txt")))
            .collect();
        let mut args = vec!["combine", "--set", "", "--out", s(&out), "--no-mlock"];
        let set = d.join("sh/set.txt");
        args[2] = s(&set);
        args.extend(files.iter().map(|f| s(f)));
        let o = run(&args);
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        assert_eq!(fs::read(&out).expect("secret"), key);
    }
}

#[cfg(unix)]
#[test]
fn shares_and_the_secret_are_written_for_their_owner_only() {
    use std::os::unix::fs::PermissionsExt as _;
    let d = dir("modes");
    split(&d);
    for n in 1..=5 {
        let m = fs::metadata(d.join(format!("sh/share-{n}.txt")))
            .expect("share")
            .permissions()
            .mode();
        assert_eq!(m & 0o777, 0o600, "share {n}");
    }
    let m = fs::metadata(d.join("sh"))
        .expect("dir")
        .permissions()
        .mode();
    assert_eq!(m & 0o077, 0, "the share directory is the owner's");
}

#[test]
fn two_shares_are_refused() {
    let d = dir("two");
    split(&d);
    let o = run(&[
        "combine",
        "--set",
        s(&d.join("sh/set.txt")),
        "--out",
        s(&d.join("back")),
        "--no-mlock",
        s(&d.join("sh/share-1.txt")),
        s(&d.join("sh/share-2.txt")),
    ]);
    assert_eq!(o.status.code(), Some(1));
    assert!(!d.join("back").exists());
}

#[test]
fn a_changed_share_is_named_and_nothing_is_written() {
    let d = dir("tampered");
    split(&d);
    let p = d.join("sh/share-2.txt");
    let mut text = fs::read_to_string(&p).expect("share");
    // Flip the last hex digit of the body.
    let last = text.trim_end().len() - 1;
    let flipped = if &text[last..=last] == "0" { "1" } else { "0" };
    text.replace_range(last..=last, flipped);
    fs::write(&p, text).expect("write");

    let o = run(&[
        "check",
        "--set",
        s(&d.join("sh/set.txt")),
        "--no-mlock",
        s(&d.join("sh/share-1.txt")),
        s(&p),
    ]);
    assert_eq!(o.status.code(), Some(1));
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(
        out.contains("share 1: ok") && out.contains("share 2: share 2 does not match"),
        "{out}"
    );

    let o = run(&[
        "combine",
        "--set",
        s(&d.join("sh/set.txt")),
        "--out",
        s(&d.join("back")),
        "--no-mlock",
        s(&d.join("sh/share-1.txt")),
        s(&p),
        s(&d.join("sh/share-3.txt")),
    ]);
    assert_eq!(o.status.code(), Some(1));
    assert!(!d.join("back").exists());
}

#[test]
fn an_edited_set_is_refused_by_its_root() {
    let d = dir("set");
    split(&d);
    let p = d.join("sh/set.txt");
    let text = fs::read_to_string(&p).expect("set");
    // Replace commitment 5 with commitment 4: the root no longer matches.
    let lines: Vec<&str> = text.lines().collect();
    let c4 = lines[6].trim_start_matches("commitment 4 ");
    let edited = text.replace(lines[7], &format!("commitment 5 {c4}"));
    fs::write(&p, edited).expect("write");
    let o = run(&[
        "check",
        "--set",
        s(&p),
        "--no-mlock",
        s(&d.join("sh/share-1.txt")),
    ]);
    assert_eq!(o.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&o.stderr).contains("root does not match"));
}

#[test]
fn nothing_is_overwritten() {
    let d = dir("overwrite");
    split(&d);
    // A second split into the same directory.
    let o = run(&[
        "split",
        "--secret",
        s(&d.join("key")),
        "--out",
        s(&d.join("sh")),
        "--no-mlock",
    ]);
    assert_eq!(o.status.code(), Some(1));
    // A combine onto an existing file.
    fs::write(d.join("back"), b"keep me").expect("write");
    let o = run(&[
        "combine",
        "--set",
        s(&d.join("sh/set.txt")),
        "--out",
        s(&d.join("back")),
        "--no-mlock",
        s(&d.join("sh/share-1.txt")),
        s(&d.join("sh/share-2.txt")),
        s(&d.join("sh/share-3.txt")),
    ]);
    assert_eq!(o.status.code(), Some(1));
    assert_eq!(fs::read(d.join("back")).expect("kept"), b"keep me");
}

#[test]
fn a_share_never_reaches_the_error_text() {
    let d = dir("errors");
    split(&d);
    let share = fs::read_to_string(d.join("sh/share-1.txt")).expect("share");
    let body = share
        .trim_end()
        .rsplit(' ')
        .next()
        .expect("body")
        .to_owned();
    // A share with a broken tag: the refusal names the file, never the bytes.
    let p = d.join("broken.txt");
    fs::write(
        &p,
        share.replace("ksg-custody-share v2", "ksg-custody-share v9"),
    )
    .expect("w");
    let o = run(&[
        "check",
        "--set",
        s(&d.join("sh/set.txt")),
        "--no-mlock",
        s(&p),
    ]);
    assert_eq!(o.status.code(), Some(1));
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(!all.contains(&body), "{all}");
}

#[test]
fn usage_errors_exit_two() {
    assert_eq!(run(&[]).status.code(), Some(2));
    assert_eq!(run(&["split", "--no-mlock"]).status.code(), Some(2));
    assert_eq!(run(&["frobnicate", "--no-mlock"]).status.code(), Some(2));
    assert_eq!(run(&["state", "--bogus"]).status.code(), Some(2));
}
