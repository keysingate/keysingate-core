//! How shares and sets lie on disk.
//!
//! Plain lines, written and read by hand rather than through a serializer: a
//! share is key material, and every buffer it passes through here is a
//! [`Zeroizing`] one this module owns. A serializer would make copies it does
//! not wipe.
//!
//! ```text
//! ksg-custody-share v2 <index> <salt: 64 hex> <body: hex>
//! ```
//!
//! ```text
//! ksg-custody-set v2
//! threshold <k>
//! root <64 hex>
//! commitment <index> <64 hex>      one line per share, in order
//! ```
//!
//! The set is public — commitments and their root, the root being what goes on
//! the chain. Reading it back recomputes the root and refuses a file whose
//! stated root does not match: an edited commitment would otherwise pass for
//! the set.

use ksg_custody_v2::{Commitment, CustodySet, Share, SALT_LEN};
use zeroize::Zeroizing;

const SHARE_TAG: &str = "ksg-custody-share v2";
const SET_TAG: &str = "ksg-custody-set v2";

/// Why a file was not read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Malformed(pub &'static str);

impl std::fmt::Display for Malformed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

/// One share as one line, in a buffer wiped on drop.
#[must_use]
pub fn write_share(s: &Share) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(
        SHARE_TAG.len() + 8 + 2 * (SALT_LEN + s.body.len()),
    ));
    out.push_str(SHARE_TAG);
    out.push(' ');
    out.push_str(&s.index.to_string());
    out.push(' ');
    push_hex(&mut out, &s.salt);
    out.push(' ');
    push_hex(&mut out, &s.body);
    out.push('\n');
    out
}

/// Hex into a buffer that is already wiped on drop — `hex::encode` would
/// return a fresh `String` that is not.
fn push_hex(out: &mut String, bytes: &[u8]) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for &b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
}

/// Reads one share.
///
/// # Errors
///
/// [`Malformed`] naming what is wrong. The text of the file is never echoed.
pub fn read_share(text: &[u8]) -> Result<Share, Malformed> {
    let text = std::str::from_utf8(text).map_err(|_| Malformed("a share is not text"))?;
    let line = text.trim_end_matches('\n');
    if line.contains('\n') {
        return Err(Malformed("a share file holds one line"));
    }
    let rest = line
        .strip_prefix(SHARE_TAG)
        .and_then(|r| r.strip_prefix(' '))
        .ok_or(Malformed("not a ksg-custody-share v2 line"))?;
    let mut parts = rest.split(' ');
    let (Some(index), Some(salt), Some(body), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Malformed("a share line has index, salt and body"));
    };
    let index: u8 = index.parse().map_err(|_| Malformed("bad share index"))?;
    if index == 0 {
        return Err(Malformed("share index 0 is the secret's position"));
    }
    let mut s = [0u8; SALT_LEN];
    hex::decode_to_slice(salt, &mut s).map_err(|_| Malformed("bad salt"))?;
    if body.is_empty() || body.len() % 2 != 0 {
        return Err(Malformed("bad body"));
    }
    let mut b = Zeroizing::new(vec![0u8; body.len() / 2]);
    hex::decode_to_slice(body, &mut b[..]).map_err(|_| Malformed("bad body"))?;
    let share = Share {
        index,
        salt: s,
        body: std::mem::take(&mut *b),
    };
    zeroize::Zeroize::zeroize(&mut s);
    Ok(share)
}

/// The set as text.
#[must_use]
pub fn write_set(set: &CustodySet) -> String {
    let mut out = format!(
        "{SET_TAG}\nthreshold {}\nroot {}\n",
        set.threshold(),
        hex::encode(set.root().as_bytes())
    );
    for (i, c) in set.commitments().iter().enumerate() {
        out.push_str(&format!("commitment {} {c}\n", i + 1));
    }
    out
}

/// Reads a set and checks its root.
///
/// # Errors
///
/// [`Malformed`] naming what is wrong, including a root that does not match
/// the commitments.
pub fn read_set(text: &str) -> Result<CustodySet, Malformed> {
    let mut lines = text.lines();
    if lines.next() != Some(SET_TAG) {
        return Err(Malformed("not a ksg-custody-set v2 file"));
    }
    let threshold: u8 = lines
        .next()
        .and_then(|l| l.strip_prefix("threshold "))
        .and_then(|n| n.parse().ok())
        .ok_or(Malformed("no threshold line"))?;
    let root = lines
        .next()
        .and_then(|l| l.strip_prefix("root "))
        .ok_or(Malformed("no root line"))?;
    let mut commitments = Vec::new();
    for (i, l) in lines.enumerate() {
        let rest = l
            .strip_prefix("commitment ")
            .ok_or(Malformed("a line that is not a commitment"))?;
        let (n, h) = rest
            .split_once(' ')
            .ok_or(Malformed("a commitment line has index and digest"))?;
        if n.parse::<usize>().ok() != Some(i + 1) {
            return Err(Malformed("commitments out of order"));
        }
        let mut d = [0u8; 32];
        hex::decode_to_slice(h, &mut d).map_err(|_| Malformed("bad commitment"))?;
        commitments.push(Commitment::from_bytes(d));
    }
    let set = CustodySet::from_commitments(commitments, threshold)
        .map_err(|_| Malformed("the commitments do not make a scheme"))?;
    if hex::encode(set.root().as_bytes()) != root {
        return Err(Malformed("the root does not match the commitments"));
    }
    Ok(set)
}
