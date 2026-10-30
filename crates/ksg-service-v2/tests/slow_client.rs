//! A slow or silent client does not hold a request thread: the socket
//! timeout and the body deadline free it, and the service keeps answering.
//! One request thread, real port.

#![allow(clippy::unwrap_used, clippy::expect_used)]


use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use ksg_core_v2::doc::Uri;
use ksg_service_v2::server::{start, Config, Running, BODY_DEADLINE_S, SOCKET_TIMEOUT_S};
use ksg_verify_v2::solana::Rpc;

struct NoRpc;
impl Rpc for NoRpc {
    fn call(&self, _m: &str, _p: serde_json::Value) -> Result<serde_json::Value, String> {
        Err("no network".to_owned())
    }
}

fn serve(name: &str) -> (Running, PathBuf) {
    let d = std::env::temp_dir().join(format!("ksg-slow-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("issuer-keys.json"), "[]").unwrap();
    let cfg = Config {
        listen: "127.0.0.1:0".into(),
        audience: Uri::parse("https://desk.example/v1").unwrap(),
        state: d.join("state"),
        cluster: "devnet".into(),
        rpc: "http://127.0.0.1:1".into(),
        issuer_keys: d.join("issuer-keys.json"),
        max_standing_age_s: None,
        legal_checkers: Vec::new(),
        holders: Vec::new(),
        workers: Some(1),
    };
    (start(cfg, Default::default(), Box::new(NoRpc)).unwrap(), d)
}

/// `GET /v1/health` on a fresh connection; the status line.
fn health(addr: std::net::SocketAddr) -> String {
    let mut c = TcpStream::connect(addr).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
    c.write_all(b"GET /v1/health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut out = String::new();
    let _ = c.read_to_string(&mut out);
    out.lines().next().unwrap_or("").to_owned()
}

/// Headers promising a body, then the body never comes. Over 1 KiB, so
/// `tiny_http` hands it to a request thread unread.
fn stall(addr: std::net::SocketAddr) -> TcpStream {
    let mut c = TcpStream::connect(addr).unwrap();
    c.write_all(
        b"POST /v1/look HTTP/1.1\r\nHost: x\r\nContent-Length: 100000\r\n\r\n{\"req",
    )
    .unwrap();
    c
}

#[test]
fn a_silent_body_does_not_stop_the_service() {
    let (svc, d) = serve("silent");
    let _held = stall(svc.addr);
    std::thread::sleep(Duration::from_millis(200));
    let t = Instant::now();
    let line = health(svc.addr);
    assert!(line.contains(" 200"), "health: {line:?}");
    assert!(
        // One timed-out read of the body, one of the bounded drain.
        t.elapsed() < Duration::from_secs(2 * SOCKET_TIMEOUT_S + 3),
        "freed by the socket timeout, took {:?}",
        t.elapsed()
    );
    svc.stop();
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn a_trickling_body_is_cut_at_the_deadline() {
    let (svc, d) = serve("trickle");
    let addr = svc.addr;
    let trickle = std::thread::spawn(move || {
        let mut c = stall(addr);
        // One byte a second: each read succeeds, only the deadline stops it.
        for _ in 0..(BODY_DEADLINE_S + 10) {
            std::thread::sleep(Duration::from_secs(1));
            if c.write_all(b"x").is_err() {
                return;
            }
        }
    });
    std::thread::sleep(Duration::from_millis(500));
    let t = Instant::now();
    let line = health(addr);
    assert!(line.contains(" 200"), "health: {line:?}");
    assert!(
        // The deadline, then the drain: at most 2 s plus one read.
        t.elapsed() < Duration::from_secs(BODY_DEADLINE_S + SOCKET_TIMEOUT_S + 5),
        "freed by the body deadline, took {:?}",
        t.elapsed()
    );
    svc.stop();
    let _ = trickle.join();
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn a_huge_content_length_does_not_abort_the_process() {
    let (svc, d) = serve("huge");
    // Over MAX_BODY sent, near usize::MAX declared: the unread remainder is
    // dropped, which upstream tiny_http allocated in one piece and aborted.
    let mut c = TcpStream::connect(svc.addr).unwrap();
    c.write_all(
        b"POST /v1/look HTTP/1.1\r\nHost: x\r\nContent-Length: 9223372036854775000\r\n\r\n",
    )
    .unwrap();
    let chunk = vec![b'a'; 1 << 20];
    for _ in 0..3 {
        if c.write_all(&chunk).is_err() {
            break;
        }
    }
    c.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let mut out = String::new();
    let _ = c.read_to_string(&mut out);
    assert!(out.starts_with("HTTP/1.1 413"), "reply: {:?}", out.lines().next());
    let line = health(svc.addr);
    assert!(line.contains(" 200"), "still up: {line:?}");
    svc.stop();
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn the_server_still_accepts_after_an_idle_spell() {
    // The timeout is per connection, not on the listener: an idle listener
    // must not time out its accept loop.
    let (svc, d) = serve("idle");
    std::thread::sleep(Duration::from_secs(SOCKET_TIMEOUT_S + 2));
    let line = health(svc.addr);
    assert!(line.contains(" 200"), "after idle: {line:?}");
    svc.stop();
    let _ = std::fs::remove_dir_all(d);
}
