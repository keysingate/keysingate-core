//! The mobile half in a browser page (`ksg-web-v2`): the reader holds the
//! round's requests over HTTP, a thread plays the page — fetches, shows what
//! it signs, answers with the holder's word.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use ksg_web_v2::{describe_request, Web};

const KSG: &str = env!("CARGO_BIN_EXE_ksg-remote-panel");

struct Dir(PathBuf);

impl Dir {
    fn new(name: &str) -> Self {
        let d = std::env::temp_dir().join(format!("ksg-web-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Self(d)
    }
    fn p(&self, name: &str) -> String {
        self.0.join(name).to_string_lossy().into_owned()
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn ok(args: &[&str]) -> String {
    let out = Command::new(KSG).args(args).output().unwrap();
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// One HTTP exchange; the status and the body — `None` once the reader is
/// gone.
fn http(host: &str, method: &str, path: &str, body: &str) -> Option<(u16, String)> {
    let mut s = TcpStream::connect(host).ok()?;
    write!(
        s,
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .ok()?;
    let mut out = String::new();
    s.read_to_string(&mut out).ok()?;
    let status = out.get(9..12)?.parse().ok()?;
    let body = out.split_once("\r\n\r\n").map_or("", |(_, b)| b).to_owned();
    Some((status, body))
}

/// The page: answers every request it finds until the reader exits, with the
/// holder's `word` on what a round signs. Returns the documents it was shown.
fn page(url: &str, half: &[u8], word: bool, done: impl Fn() -> bool) -> Vec<String> {
    let rest = url.trim_start_matches("http://");
    let (host, q) = rest.split_once("/?").unwrap();
    let mut web = Web::from_half(half).unwrap();
    let mut shown = Vec::new();
    // Without the token the page reads nothing.
    assert_eq!(http(host, "GET", "/next", "").map(|r| r.0), Some(403));
    let start = Instant::now();
    while !done() && start.elapsed() < Duration::from_secs(60) {
        let Some((status, line)) = http(host, "GET", &format!("/next?{q}"), "") else {
            break;
        };
        if status != 200 {
            std::thread::sleep(Duration::from_millis(20));
            continue;
        }
        if let Some(what) = describe_request(&line) {
            shown.push(what.doc_type.unwrap_or_default());
        }
        let answer = web.answer(&line, word, &mut rand_core::OsRng);
        let _ = http(host, "POST", &format!("/answer?{q}"), &answer);
    }
    shown
}

fn initiated(d: &Dir) -> (String, String) {
    let (home, half) = (d.p("home"), d.p("m.half"));
    ok(&["--home", &home, "init", "--class", "heavy"]);
    ok(&["--home", &home, "packet"]);
    ok(&["--home", &home, "buyer-key"]);
    ok(&["--home", &home, "--mobile", &half, "initiate"]);
    (home, half)
}

fn run_with_page(home: &str, half: &str, word: bool, cmd: &[&str]) -> (bool, String, Vec<String>) {
    let mut args = vec!["--home", home, "--mobile-web", "127.0.0.1:0"];
    args.extend_from_slice(cmd);
    let mut child = Command::new(KSG)
        .args(&args)
        .env("KSG_MOBILE_WAIT_SECS", "30")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut err = BufReader::new(child.stderr.take().unwrap());
    let mut first = String::new();
    err.read_line(&mut first).unwrap();
    let url = first
        .trim()
        .strip_prefix("mobile half: open ")
        .unwrap_or_else(|| panic!("no address: {first}"))
        .to_owned();
    let bytes = std::fs::read(half).unwrap();
    let finished = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let f = std::sync::Arc::clone(&finished);
    let browser = std::thread::spawn(move || {
        page(&url, &bytes, word, || {
            f.load(std::sync::atomic::Ordering::SeqCst)
        })
    });
    let status = child.wait().unwrap();
    finished.store(true, std::sync::atomic::Ordering::SeqCst);
    let mut rest = String::new();
    err.read_to_string(&mut rest).unwrap();
    (status.success(), rest, browser.join().unwrap())
}

#[test]
fn the_half_in_a_browser_page_signs_what_the_holder_saw() {
    let d = Dir::new("yes");
    let (home, half) = initiated(&d);
    let (ok_, err, shown) = run_with_page(&home, &half, true, &["open-journal"]);
    assert!(ok_, "{err}");
    assert!(!shown.is_empty(), "the holder was shown what is signed");
    let (ok_, err, _) = run_with_page(&home, &half, true, &["work", "--did", "from the browser"]);
    assert!(ok_, "{err}");
}

#[test]
fn the_holder_says_no_and_nothing_is_written() {
    let d = Dir::new("no");
    let (home, half) = initiated(&d);
    let before = std::fs::read(d.0.join("home").join("container.ksg")).unwrap();
    let (ok_, err, shown) = run_with_page(&home, &half, false, &["open-journal"]);
    assert!(!ok_);
    assert!(err.contains("refused"), "{err}");
    assert!(!shown.is_empty());
    let after = std::fs::read(d.0.join("home").join("container.ksg")).unwrap();
    assert_eq!(before, after, "a refused round writes nothing");
}
