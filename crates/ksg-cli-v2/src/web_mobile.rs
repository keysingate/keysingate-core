//! The mobile half in a browser: the reader holds each request of a signing
//! round and the page fetches it over HTTP (`ksg-web-v2`, the owner's word
//! 01.10: not an app — a script the browser runs).
//!
//! | Page asks | Reader answers |
//! |---|---|
//! | `GET /next?t=TOKEN` | `200` and the request line, or `204` when none is waiting |
//! | `POST /answer?t=TOKEN` with the answer line | `200` |
//! | `GET /…` other paths | the page's files from `--web-root`, if given |
//!
//! The token is random, made per run and printed with the page's address: a
//! page without it neither reads the rounds nor answers them. What crosses —
//! commitment, round, share — is public by FROST's design; the nonces stay in
//! the page. The reader listens on the address it is given, plain HTTP: on the
//! holder's own machine (`127.0.0.1`); beyond it, TLS in front.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use ksg_container_v2::client_key::{Commitment, MobileShare, SigningRound};
use ksg_mobile_v2::{Answer, Request};
use rand_core::{OsRng, RngCore};

use crate::mobile::Mobile;

#[derive(Default)]
struct Slot {
    request: Option<String>,
    answer: Option<String>,
}

type Shared = Arc<(Mutex<Slot>, Condvar)>;

/// The mobile half in a browser page, reached over HTTP.
pub struct WebMobile {
    slot: Shared,
    wait: Duration,
    /// The page's address, with the token.
    pub url: String,
}

impl WebMobile {
    /// Listens on `addr` (`127.0.0.1:0` picks a free port) and serves the
    /// page's files from `root`, if given.
    ///
    /// # Errors
    ///
    /// The address is taken or is not one.
    pub fn listen(addr: &str, root: Option<PathBuf>) -> Result<Self, String> {
        let listener = TcpListener::bind(addr).map_err(|e| format!("--mobile-web {addr}: {e}"))?;
        let local = listener.local_addr().map_err(|e| e.to_string())?;
        let mut t = [0u8; 16];
        OsRng.fill_bytes(&mut t);
        let token = B64.encode(t);
        let slot: Shared = Arc::default();
        let shared = Arc::clone(&slot);
        let tok = token.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let _ = serve(stream, &shared, &tok, root.as_deref());
            }
        });
        let wait = std::env::var("KSG_MOBILE_WAIT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .map_or(Duration::from_secs(300), Duration::from_secs);
        Ok(Self {
            slot,
            wait,
            url: format!("http://{local}/?t={token}"),
        })
    }

    fn call(&mut self, req: &Request) -> Result<Vec<u8>, String> {
        let line = serde_json::to_string(req).map_err(|e| e.to_string())?;
        let (lock, cv) = &*self.slot;
        let mut s = lock.lock().map_err(|_| "the page's slot is poisoned")?;
        s.request = Some(line);
        s.answer = None;
        let start = Instant::now();
        let answer = loop {
            if let Some(a) = s.answer.take() {
                break a;
            }
            let left = self
                .wait
                .checked_sub(start.elapsed())
                .ok_or_else(|| format!("the browser did not answer within {:?}", self.wait))?;
            s = cv
                .wait_timeout(s, left)
                .map_err(|_| "the page's slot is poisoned")?
                .0;
        };
        s.request = None;
        match serde_json::from_str::<Answer>(&answer) {
            Ok(Answer::Ok(b)) => B64.decode(b).map_err(|e| e.to_string()),
            Ok(Answer::Err(e)) => Err(format!("mobile half: {e}")),
            Err(_) => Err("the browser's answer is not one".into()),
        }
    }
}

impl Mobile for WebMobile {
    fn commit(&mut self) -> Result<Commitment, String> {
        let b = self.call(&Request::Commit)?;
        Commitment::from_bytes(&b).map_err(|e| e.to_string())
    }

    fn respond(&mut self, round: &SigningRound) -> Result<MobileShare, String> {
        let round = B64.encode(round.to_bytes().map_err(|e| e.to_string())?);
        let b = self.call(&Request::Respond { round })?;
        MobileShare::from_bytes(&b).map_err(|e| e.to_string())
    }
}

fn reply(mut s: &TcpStream, status: &str, kind: &str, body: &[u8]) -> std::io::Result<()> {
    write!(
        s,
        "HTTP/1.1 {status}\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    s.write_all(body)?;
    s.flush()
}

fn serve(
    stream: TcpStream,
    slot: &Shared,
    token: &str,
    root: Option<&Path>,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut r = BufReader::new(&stream);
    let mut first = String::new();
    r.read_line(&mut first)?;
    let mut len = 0usize;
    loop {
        let mut h = String::new();
        if r.read_line(&mut h)? == 0 || h == "\r\n" || h == "\n" {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            if k.eq_ignore_ascii_case("content-length") {
                len = v.trim().parse().unwrap_or(0);
            }
        }
    }
    if len > 64 * 1024 {
        return reply(&stream, "413 Payload Too Large", "text/plain", b"too large");
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    let mut parts = first.split_whitespace();
    let (method, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let authorized = query.split('&').any(|kv| kv == format!("t={token}"));
    let (lock, cv) = &**slot;
    match (method, path) {
        ("GET", "/next") | ("POST", "/answer") if !authorized => {
            reply(&stream, "403 Forbidden", "text/plain", b"no token")
        }
        // A request is shown until it is answered, not until the reader takes
        // the answer: shown again in between, the page would answer it twice —
        // a second commitment over the first one's nonces, or a commitment
        // landing as the share of the next round (`web.rs`, 18.10).
        ("GET", "/next") => {
            let req = lock
                .lock()
                .ok()
                .and_then(|s| s.answer.is_none().then(|| s.request.clone()).flatten());
            match req {
                Some(line) => reply(&stream, "200 OK", "application/json", line.as_bytes()),
                None => reply(&stream, "204 No Content", "text/plain", b""),
            }
        }
        ("POST", "/answer") => {
            if let Ok(mut s) = lock.lock() {
                // The first answer to a request is the one; a late second
                // one is dropped.
                if s.request.is_some() && s.answer.is_none() {
                    s.answer = Some(String::from_utf8_lossy(&body).trim().to_owned());
                    cv.notify_all();
                }
            }
            reply(&stream, "200 OK", "text/plain", b"")
        }
        ("GET", p) => match root.and_then(|r| file_in(r, p)) {
            Some((bytes, kind)) => reply(&stream, "200 OK", kind, &bytes),
            None => reply(&stream, "404 Not Found", "text/plain", b"not found"),
        },
        _ => reply(&stream, "405 Method Not Allowed", "text/plain", b""),
    }
}

/// A file of the page under `root` — never outside it.
fn file_in(root: &Path, path: &str) -> Option<(Vec<u8>, &'static str)> {
    let rel = Path::new(path.trim_start_matches('/'));
    if rel.components().any(|c| !matches!(c, Component::Normal(_))) {
        return None;
    }
    let p = if path == "/" {
        root.join("index.html")
    } else {
        root.join(rel)
    };
    let kind = match p.extension().and_then(|e| e.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "text/javascript",
        Some("wasm") => "application/wasm",
        _ => "application/octet-stream",
    };
    std::fs::read(p).ok().map(|b| (b, kind))
}
