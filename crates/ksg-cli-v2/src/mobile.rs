//! The client's mobile half, and the wire between it and the reader.
//!
//! In the product the mobile half lives on the client's phone; in the MVP it
//! lives in a separate process, `ksg-remote-panel mobile serve --half FILE`, which is the
//! only thing that reads the half's file. The reader and that process talk in
//! JSON lines over its standard input and output:
//!
//! | Reader sends | Mobile answers |
//! |---|---|
//! | `{"op":"commit"}` | `{"ok":"<commitment, base64url>"}` |
//! | `{"op":"respond","round":"<signing round, base64url>"}` | `{"ok":"<share, base64url>"}` |
//! | anything it cannot do | `{"err":"<why>"}` |
//!
//! **The one-time nonces never cross the wire**: they are made by `commit` and
//! spent by the next `respond` inside the mobile process, and dropped when it
//! exits. What crosses — commitment, round, share — is public by FROST's design
//! (`ksg-container::client_key`).
//!
//! The session and the wire are `ksg-mobile-v2`'s — the same library the
//! phone runs. Every share passes the holder's consent first: `--confirm`
//! asks on the terminal and refuses with no terminal; without it the process
//! approves every round, which is the MVP's boundary stated by name (one
//! person plays every party, `[decision]` 23.09), not a default of the
//! library.

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use ksg_container_v2::client_key::{Commitment, MobileHalf, MobileShare, SigningRound};
use ksg_mobile_v2::{handle_line, Answer, ApproveAll, Consent, Request, Session, Signing};
use rand_core::OsRng;

/// The client's side of a signing round, wherever it runs.
pub trait Mobile {
    /// Opens a round: the commitment to send to the container.
    ///
    /// # Errors
    ///
    /// Why the mobile half could not commit.
    fn commit(&mut self) -> Result<Commitment, String>;

    /// The client's share of the round the container answered with.
    ///
    /// # Errors
    ///
    /// No round open, or a round without this half's commitment.
    fn respond(&mut self, round: &SigningRound) -> Result<MobileShare, String>;
}

/// No mobile half: for commands the client does not sign.
#[derive(Debug)]
pub struct NoMobile;

impl Mobile for NoMobile {
    fn commit(&mut self) -> Result<Commitment, String> {
        Err("this command needs the client's signature: pass --mobile FILE".into())
    }
    fn respond(&mut self, _round: &SigningRound) -> Result<MobileShare, String> {
        Err("no mobile half".into())
    }
}

/// The mobile half in this process, approving every round: the half the
/// reader itself plays in the MVP (a new agent's half during a hand-off),
/// where one person plays every party (`[decision]` 23.09).
pub struct LocalMobile(Session<ApproveAll>);

impl LocalMobile {
    /// The half, with no round open.
    #[must_use]
    pub const fn new(half: MobileHalf) -> Self {
        Self(Session::new(half, ApproveAll))
    }
}

impl Mobile for LocalMobile {
    fn commit(&mut self) -> Result<Commitment, String> {
        Ok(self.0.commit(&mut OsRng))
    }

    fn respond(&mut self, round: &SigningRound) -> Result<MobileShare, String> {
        self.0.respond(round).map_err(|e| e.to_string())
    }
}

/// Asks the holder on the terminal before every share: `--confirm`.
///
/// The question goes to `/dev/tty`, not to standard output, which is the
/// wire to the reader.
#[derive(Debug, Default)]
pub struct TtyConsent;

impl Consent for TtyConsent {
    fn approve(&mut self, what: &Signing) -> bool {
        let Ok(mut tty) = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
        else {
            // No terminal, nobody to ask: no.
            return false;
        };
        if write!(tty, "mobile half: sign {what}? [y/N] ")
            .and_then(|()| tty.flush())
            .is_err()
        {
            return false;
        }
        let mut answer = String::new();
        BufReader::new(tty).read_line(&mut answer).is_ok()
            && matches!(answer.trim(), "y" | "Y" | "yes")
    }
}

/// Serves `half` over JSON lines until the input ends, asking `consent`
/// before every share.
///
/// # Errors
///
/// Only when the output cannot be written; a request it cannot do is answered
/// with `{"err": …}` and serving goes on.
pub fn serve<C: Consent>(
    half: MobileHalf,
    consent: C,
    input: impl BufRead,
    mut output: impl Write,
) -> Result<(), String> {
    let mut session = Session::new(half, consent);
    for line in input.lines() {
        let line = line.map_err(|e| e.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        let mut out = handle_line(&mut session, &line, &mut OsRng);
        out.push('\n');
        output
            .write_all(out.as_bytes())
            .map_err(|e| e.to_string())?;
        output.flush().map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// The mobile half in a child process: `PROGRAM mobile serve --half FILE`.
pub struct ChildMobile {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
}

impl ChildMobile {
    /// Starts the mobile process.
    ///
    /// # Errors
    ///
    /// The program did not start.
    pub fn spawn(program: &Path, half: &Path) -> Result<Self, String> {
        let mut child = Command::new(program)
            .args(["mobile", "serve", "--half"])
            .arg(half)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("mobile process: {e}"))?;
        let stdin = child.stdin.take().ok_or("mobile process: no stdin")?;
        let stdout = BufReader::new(child.stdout.take().ok_or("mobile process: no stdout")?);
        Ok(Self {
            child,
            stdin: Some(stdin),
            stdout,
        })
    }

    fn call(&mut self, req: &Request) -> Result<Vec<u8>, String> {
        let mut line = serde_json::to_string(req).map_err(|e| e.to_string())?;
        line.push('\n');
        let stdin = self.stdin.as_mut().ok_or("mobile process closed")?;
        stdin
            .write_all(line.as_bytes())
            .and_then(|()| stdin.flush())
            .map_err(|e| format!("mobile process: {e}"))?;
        let mut answer = String::new();
        self.stdout
            .read_line(&mut answer)
            .map_err(|e| format!("mobile process: {e}"))?;
        match serde_json::from_str::<Answer>(&answer) {
            Ok(Answer::Ok(b)) => B64.decode(b).map_err(|e| e.to_string()),
            Ok(Answer::Err(e)) => Err(format!("mobile half: {e}")),
            Err(_) => Err("mobile process: no answer".into()),
        }
    }
}

impl Mobile for ChildMobile {
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

impl Drop for ChildMobile {
    fn drop(&mut self) {
        // Closing its input ends the mobile process, and its nonces with it.
        drop(self.stdin.take());
        let _ = self.child.wait();
    }
}
