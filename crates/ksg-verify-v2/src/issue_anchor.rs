//! The issuance anchor of a `bare` v2 container (`[decision]` 06.10).
//!
//! Put once, by the issuer, when a `bare` is handed over. It answers one
//! question for the next issuer: "has this person already had a free `bare`
//! of this release and software version?" — a match on any checked holder
//! makes the next one paid.
//!
//! The anchor counts the holder, not the documents (decision 27.10): the
//! owner's e-mail or the orchestrator's `did:web`, never a passport, an
//! identity card or a tax number.
//!
//! | Part | How |
//! |---|---|
//! | content | a fixed table of [`SLOTS`] holder tags; an absent holder is a stub |
//! | mask | which slots are holders and which are stubs — inside the table |
//! | protection | the whole table is encrypted (XChaCha20-Poly1305) |
//! | key | `bare check key`, a partner key held by the issuers, one per year |
//! | in the clear | the tag and the year only — the year picks the key |
//!
//! A holder tag is a keyed PRF (HKDF-SHA256) of the holder's kind and its
//! normalized value, never a plain hash: an e-mail has few enough values to be
//! found from a plain hash by trying them all. A stub is random and looks the
//! same. The table has the same size whatever it holds.
//!
//! The container never holds this key and never reads anchors: they are
//! written and read by the issuers' program, outside the container.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ksg_core_v2::crypto::hash::Hash;

/// The anchor's tag on the chain.
pub const ANCHOR_TAG: &str = "ksg:ia:v1";
/// Document slots in every table.
pub const SLOTS: usize = 8;
const TAG_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const TABLE_LEN: usize = 1 + 1 + 32 + SLOTS * TAG_LEN;
const SALT: &[u8] = b"ksg:ia:salt:v1";

/// Kinds of holder, one per slot. The slot of a kind never changes: the next
/// issuer compares slot to slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DocKind {
    /// The owner's e-mail address.
    Email = 0,
    /// The orchestrator's `did:web` identifier.
    DidWeb = 1,
}

impl DocKind {
    /// A holder value as compared: trimmed and lower case. An e-mail is taken
    /// as it stands; a `did:web` must carry its `did:web:` prefix.
    ///
    /// # Errors
    ///
    /// The value is empty, or a `did:web` without its prefix.
    pub fn normalize(self, value: &str) -> Result<String, String> {
        let v = value.trim().to_lowercase();
        if v.is_empty() {
            return Err("holder: empty value".into());
        }
        match self {
            Self::Email => Ok(v),
            Self::DidWeb if v.starts_with("did:web:") => Ok(v),
            Self::DidWeb => Err("holder: did:web must start with \"did:web:\"".into()),
        }
    }
}

/// `bare check key`: the issuers' partner key. The emitter holds the master;
/// each issuer gets the key of each year ([`BareCheckKey::for_period`]).
/// A key given out reads its year forever and no other (rotation closes the
/// future, never the past — as `SealScanKey`).
///
/// Compares in constant time, prints nothing, is wiped on drop.
#[derive(Clone, Eq, zeroize::ZeroizeOnDrop)]
pub struct BareCheckKey([u8; 32]);

impl PartialEq for BareCheckKey {
    fn eq(&self, other: &Self) -> bool {
        ct_eq(&self.0, &other.0)
    }
}

impl core::fmt::Debug for BareCheckKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("BareCheckKey(…)")
    }
}

impl BareCheckKey {
    /// A key from 32 bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The key from its file: 64 hex characters, whitespace around ignored.
    ///
    /// # Errors
    ///
    /// Not 32 bytes of hex.
    pub fn from_hex(s: &str) -> Result<Self, String> {
        let v = zeroize::Zeroizing::new(
            hex::decode(s.trim()).map_err(|_| "bare check key: not hex".to_owned())?,
        );
        let b: [u8; 32] = v
            .as_slice()
            .try_into()
            .map_err(|_| "bare check key: not 32 bytes".to_owned())?;
        Ok(Self(b))
    }

    /// The key as its file holds it.
    #[must_use]
    pub fn to_hex(&self) -> zeroize::Zeroizing<String> {
        zeroize::Zeroizing::new(hex::encode(self.0))
    }

    /// The key of one year, from the master: `period` is `YYYY`.
    #[must_use]
    pub fn for_period(&self, period: &str) -> Self {
        Self(self.expand(b"ksg:ia:period:v1", &[period.as_bytes()]))
    }

    /// The tag of one holder under this year's key: an e-mail trimmed and
    /// lower case, or a lower-case `did:web` with its prefix.
    ///
    /// # Errors
    ///
    /// The value is empty, or a `did:web` without its prefix.
    pub fn doc_tag(&self, kind: DocKind, value: &str) -> Result<[u8; TAG_LEN], String> {
        let v = kind.normalize(value)?;
        let hash_key = self.expand(b"ksg:ia:doc-key:v1", &[]);
        Ok(Self(hash_key).expand(b"ksg:ia:doc:v1", &[&[kind as u8], v.as_bytes()]))
    }

    fn enc_key(&self) -> zeroize::Zeroizing<[u8; 32]> {
        zeroize::Zeroizing::new(self.expand(b"ksg:ia:enc:v1", &[]))
    }

    fn expand(&self, domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
        let mut info = Vec::with_capacity(64);
        info.extend_from_slice(domain);
        for p in parts {
            info.extend_from_slice(&(p.len() as u64).to_be_bytes());
            info.extend_from_slice(p);
        }
        let mut out = [0u8; 32];
        hkdf::Hkdf::<sha2::Sha256>::new(Some(SALT), &self.0)
            .expand(&info, &mut out)
            .expect("32 bytes is within HKDF-SHA256's output");
        out
    }
}

/// What a free `bare` is counted against: one release, one software version.
#[must_use]
pub fn scope(release: &str, version: &str) -> Hash {
    Hash::sha256_fields(&[b"ksg:ia:scope:v1", release.as_bytes(), version.as_bytes()])
}

/// An opened anchor.
#[derive(Clone, PartialEq, Eq)]
pub struct IssueAnchor {
    /// Bit `i` set: slot `i` is a holder; clear: a stub.
    pub mask: u8,
    /// [`scope`] of the `bare` issued.
    pub scope: Hash,
    slots: [[u8; TAG_LEN]; SLOTS],
}

impl core::fmt::Debug for IssueAnchor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IssueAnchor")
            .field("mask", &format_args!("{:08b}", self.mask))
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

impl IssueAnchor {
    /// Whether this anchor counts against a holder showing `holders` for a
    /// `bare` of `scope`: the same scope and a match on any checked slot.
    /// Every slot is compared, whatever the outcome.
    ///
    /// # Errors
    ///
    /// A holder value is empty or not a `did:web`.
    pub fn matches(
        &self,
        key: &BareCheckKey,
        scope: &Hash,
        holders: &[(DocKind, &str)],
    ) -> Result<bool, String> {
        let mut hit = 0u8;
        for (kind, value) in holders {
            let t = key.doc_tag(*kind, value)?;
            let i = *kind as usize;
            let checked = (self.mask >> i) & 1;
            hit |= checked & u8::from(ct_eq(&t, &self.slots[i]));
        }
        Ok(hit == 1 && ct_eq(scope.as_bytes(), self.scope.as_bytes()))
    }
}

/// The anchor for a `bare` of `scope` handed over against `holders`, under the
/// year `period`'s key. `seed` — 32 fresh random bytes from the caller, new
/// for every anchor: it gives the stubs and the nonce.
///
/// # Errors
///
/// No holder, a holder value is empty or not a `did:web`, or a kind given
/// twice.
pub fn seal(
    key: &BareCheckKey,
    period: &str,
    scope: &Hash,
    holders: &[(DocKind, &str)],
    seed: [u8; 32],
) -> Result<String, String> {
    check_period(period)?;
    if holders.is_empty() {
        return Err("issuance anchor: no holder".into());
    }
    let seed = BareCheckKey(seed);
    let mut mask = 0u8;
    let mut slots = [[0u8; TAG_LEN]; SLOTS];
    for (i, s) in slots.iter_mut().enumerate() {
        *s = seed.expand(b"ksg:ia:stub:v1", &[&[i as u8]]);
    }
    for (kind, value) in holders {
        let i = *kind as usize;
        if mask & (1 << i) != 0 {
            return Err(format!("issuance anchor: {kind:?} given twice"));
        }
        mask |= 1 << i;
        slots[i] = key.doc_tag(*kind, value)?;
    }
    let mut table = zeroize::Zeroizing::new(Vec::with_capacity(TABLE_LEN));
    table.push(1);
    table.push(mask);
    table.extend_from_slice(scope.as_bytes());
    for s in &slots {
        table.extend_from_slice(s);
    }
    let nonce_full = seed.expand(b"ksg:ia:nonce:v1", &[]);
    let nonce = XNonce::from_slice(&nonce_full[..NONCE_LEN]);
    let ct = XChaCha20Poly1305::new(key.enc_key().as_ref().into())
        .encrypt(
            nonce,
            Payload {
                msg: &table,
                aad: &aad(period),
            },
        )
        .map_err(|_| "issuance anchor: encryption failed".to_owned())?;
    let mut body = nonce.to_vec();
    body.extend_from_slice(&ct);
    Ok(format!("{ANCHOR_TAG} {period} {}", hex::encode(body)))
}

/// The year of an anchor, to pick its key; `None` if it is not one.
#[must_use]
pub fn period_of(memo: &str) -> Option<&str> {
    let mut p = memo.split_whitespace();
    (p.next() == Some(ANCHOR_TAG)).then(|| p.next()).flatten()
}

/// Opens an anchor with its year's key.
///
/// # Errors
///
/// Not an anchor, another year's key, or the anchor was changed.
pub fn open(key: &BareCheckKey, memo: &str) -> Result<IssueAnchor, String> {
    let mut p = memo.split_whitespace();
    if p.next() != Some(ANCHOR_TAG) {
        return Err("not an issuance anchor".into());
    }
    let period = p.next().ok_or("issuance anchor: no year")?;
    check_period(period)?;
    let body = hex::decode(p.next().ok_or("issuance anchor: no body")?)
        .map_err(|_| "issuance anchor: body is not hex")?;
    if p.next().is_some() || body.len() != NONCE_LEN + TABLE_LEN + 16 {
        return Err("issuance anchor: wrong size".into());
    }
    let (nonce, ct) = body.split_at(NONCE_LEN);
    let table = zeroize::Zeroizing::new(
        XChaCha20Poly1305::new(key.enc_key().as_ref().into())
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ct,
                    aad: &aad(period),
                },
            )
            .map_err(|_| {
                "issuance anchor: does not open with this key (another year, or changed)"
            })?,
    );
    if table[0] != 1 {
        return Err("issuance anchor: unknown table version".into());
    }
    let mut scope = [0u8; 32];
    scope.copy_from_slice(&table[2..34]);
    let mut slots = [[0u8; TAG_LEN]; SLOTS];
    for (i, s) in slots.iter_mut().enumerate() {
        s.copy_from_slice(&table[34 + i * TAG_LEN..34 + (i + 1) * TAG_LEN]);
    }
    Ok(IssueAnchor {
        mask: table[1],
        scope: Hash::from_bytes(scope),
        slots,
    })
}

fn aad(period: &str) -> Vec<u8> {
    [ANCHOR_TAG.as_bytes(), b" ", period.as_bytes()].concat()
}

fn check_period(period: &str) -> Result<(), String> {
    if period.len() == 4 && period.bytes().all(|b| b.is_ascii_digit()) {
        Ok(())
    } else {
        Err(format!("issuance anchor: year {period:?} is not YYYY"))
    }
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b) {
        d |= x ^ y;
    }
    d == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn master() -> BareCheckKey {
        BareCheckKey::new([7; 32])
    }

    fn y2026() -> BareCheckKey {
        master().for_period("2026")
    }

    fn sc() -> Hash {
        scope("bare-2026-10", "2.0.0")
    }

    const ANNA: &[(DocKind, &str)] = &[
        (DocKind::Email, "Anna.Petrova@Example.COM"),
        (DocKind::DidWeb, "did:web:example.org:anna"),
    ];

    #[test]
    fn a_second_free_bare_is_caught_by_any_one_holder() {
        let m = seal(&y2026(), "2026", &sc(), ANNA, [1; 32]).unwrap();
        let a = open(&y2026(), &m).unwrap();
        // the same e-mail in another case and with spaces around it
        assert!(a
            .matches(
                &y2026(),
                &sc(),
                &[(DocKind::Email, " anna.petrova@EXAMPLE.com ")]
            )
            .unwrap());
        // the same did:web in another case
        assert!(a
            .matches(
                &y2026(),
                &sc(),
                &[(DocKind::DidWeb, "DID:WEB:Example.ORG:Anna")]
            )
            .unwrap());
    }

    #[test]
    fn another_holder_another_scope_or_another_kind_is_free() {
        let a = open(
            &y2026(),
            &seal(&y2026(), "2026", &sc(), ANNA, [1; 32]).unwrap(),
        )
        .unwrap();
        assert!(!a
            .matches(&y2026(), &sc(), &[(DocKind::Email, "boris@example.com")])
            .unwrap());
        assert!(!a
            .matches(&y2026(), &scope("bare-2026-10", "2.1.0"), ANNA)
            .unwrap());
        // the same value shown as another kind of holder
        assert!(!a
            .matches(
                &y2026(),
                &sc(),
                &[(DocKind::DidWeb, "did:web:anna.petrova@example.com")]
            )
            .unwrap());
    }

    #[test]
    fn did_web_without_its_prefix_is_refused() {
        assert!(DocKind::DidWeb.normalize("example.org:anna").is_err());
        assert!(y2026()
            .doc_tag(DocKind::DidWeb, "example.org:anna")
            .is_err());
        assert!(seal(
            &y2026(),
            "2026",
            &sc(),
            &[(DocKind::DidWeb, "anna@example.com")],
            [1; 32]
        )
        .is_err());
    }

    #[test]
    fn a_stub_never_matches() {
        let a = open(
            &y2026(),
            &seal(&y2026(), "2026", &sc(), &ANNA[..1], [1; 32]).unwrap(),
        )
        .unwrap();
        assert_eq!(a.mask, 0b0000_0001);
        assert!(!a
            .matches(
                &y2026(),
                &sc(),
                &[(DocKind::DidWeb, "did:web:example.org:anna")]
            )
            .unwrap());
    }

    #[test]
    fn every_anchor_has_one_size_and_shows_only_its_year() {
        let one = seal(&y2026(), "2026", &sc(), &ANNA[..1], [1; 32]).unwrap();
        let two = seal(&y2026(), "2026", &sc(), ANNA, [2; 32]).unwrap();
        assert_eq!(one.len(), two.len());
        assert_eq!(period_of(&one), Some("2026"));
        assert!(!one.to_lowercase().contains("petrova"));
        assert!(!one.contains(&hex::encode(
            y2026()
                .doc_tag(DocKind::Email, "anna.petrova@example.com")
                .unwrap()
        )));
        assert!(one.len() < 1024, "fits a chain record: {}", one.len());
    }

    #[test]
    fn the_same_holder_twice_gives_unlinkable_anchors() {
        let a = seal(&y2026(), "2026", &sc(), ANNA, [1; 32]).unwrap();
        let b = seal(&y2026(), "2026", &sc(), ANNA, [2; 32]).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn another_year_key_does_not_open_and_a_change_is_refused() {
        let m = seal(&y2026(), "2026", &sc(), ANNA, [1; 32]).unwrap();
        assert!(open(&master().for_period("2027"), &m).is_err());
        assert!(open(&master(), &m).is_err());
        let relabelled = m.replacen(" 2026 ", " 2027 ", 1);
        assert!(open(&y2026(), &relabelled).is_err());
        let mut flipped = m.clone().into_bytes();
        let last = flipped.len() - 1;
        flipped[last] = if flipped[last] == b'0' { b'1' } else { b'0' };
        assert!(open(&y2026(), &String::from_utf8(flipped).unwrap()).is_err());
    }

    #[test]
    fn bad_input_is_refused() {
        assert!(seal(&y2026(), "26", &sc(), ANNA, [1; 32]).is_err());
        assert!(seal(&y2026(), "2026", &sc(), &[], [1; 32]).is_err());
        assert!(seal(&y2026(), "2026", &sc(), &[(DocKind::Email, "   ")], [1; 32]).is_err());
        let twice = [
            (DocKind::Email, "a@example.com"),
            (DocKind::Email, "b@example.com"),
        ];
        assert!(seal(&y2026(), "2026", &sc(), &twice, [1; 32]).is_err());
        assert!(open(&y2026(), "ksg:bs 00 00").is_err());
    }

    #[test]
    fn the_key_prints_nothing() {
        assert_eq!(format!("{:?}", y2026()), "BareCheckKey(…)");
        assert_ne!(master(), y2026());
        assert_eq!(BareCheckKey::from_hex(&y2026().to_hex()).unwrap(), y2026());
    }
}
