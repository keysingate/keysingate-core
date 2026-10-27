//! The issuance anchor of a `bare` v2 container (`[decision]` 06.10).
//!
//! Put once, by the issuer, when a `bare` is handed over. It answers one
//! question for the next issuer: "has this person already had a free `bare`
//! of this release and software version?" — a match on any checked document
//! makes the next one paid.
//!
//! | Part | How |
//! |---|---|
//! | content | a fixed table of [`SLOTS`] document tags; a missing document is a stub |
//! | mask | which slots are documents and which are stubs — inside the table |
//! | protection | the whole table is encrypted (XChaCha20-Poly1305) |
//! | key | `bare check key`, a partner key held by the issuers, one per year |
//! | in the clear | the tag and the year only — the year picks the key |
//!
//! A document tag is a keyed PRF (HKDF-SHA256) of the document's kind and its
//! normalized number, never a plain hash: a passport number has few enough
//! values to be found from a plain hash by trying them all. A stub is random
//! and looks the same. The table has the same size whatever it holds.
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

/// Kinds of document, one per slot. The slot of a kind never changes: the
/// next issuer compares slot to slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DocKind {
    /// Passport.
    Passport = 0,
    /// National identity card.
    IdCard = 1,
    /// Driving licence.
    DrivingLicence = 2,
    /// Tax number.
    TaxNumber = 3,
    /// Residence permit.
    ResidencePermit = 4,
    /// Social insurance number.
    SocialInsurance = 5,
    /// Reserved.
    Other1 = 6,
    /// Reserved.
    Other2 = 7,
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

    /// The tag of one document under this year's key.
    ///
    /// # Errors
    ///
    /// The number holds no letter or digit.
    pub fn doc_tag(&self, kind: DocKind, number: &str) -> Result<[u8; TAG_LEN], String> {
        let n = normalize(number);
        if n.is_empty() {
            return Err("document number: no letter or digit".into());
        }
        let hash_key = self.expand(b"ksg:ia:doc-key:v1", &[]);
        Ok(Self(hash_key).expand(b"ksg:ia:doc:v1", &[&[kind as u8], n.as_bytes()]))
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

/// A document number as compared: letters and digits only, upper case.
/// "AB 123-456" and "ab123456" are one number.
#[must_use]
pub fn normalize(number: &str) -> String {
    number
        .chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(char::to_uppercase)
        .collect()
}

/// An opened anchor.
#[derive(Clone, PartialEq, Eq)]
pub struct IssueAnchor {
    /// Bit `i` set: slot `i` is a document; clear: a stub.
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
    /// Whether this anchor counts against a person showing `docs` for a
    /// `bare` of `scope`: the same scope and a match on any checked slot.
    /// Every slot is compared, whatever the outcome.
    ///
    /// # Errors
    ///
    /// A document number is empty.
    pub fn matches(
        &self,
        key: &BareCheckKey,
        scope: &Hash,
        docs: &[(DocKind, &str)],
    ) -> Result<bool, String> {
        let mut hit = 0u8;
        for (kind, number) in docs {
            let t = key.doc_tag(*kind, number)?;
            let i = *kind as usize;
            let checked = (self.mask >> i) & 1;
            hit |= checked & u8::from(ct_eq(&t, &self.slots[i]));
        }
        Ok(hit == 1 && ct_eq(scope.as_bytes(), self.scope.as_bytes()))
    }
}

/// The anchor for a `bare` of `scope` handed over against `docs`, under the
/// year `period`'s key. `seed` — 32 fresh random bytes from the caller, new
/// for every anchor: it gives the stubs and the nonce.
///
/// # Errors
///
/// No document, a document number is empty, or a kind given twice.
pub fn seal(
    key: &BareCheckKey,
    period: &str,
    scope: &Hash,
    docs: &[(DocKind, &str)],
    seed: [u8; 32],
) -> Result<String, String> {
    check_period(period)?;
    if docs.is_empty() {
        return Err("issuance anchor: no document".into());
    }
    let seed = BareCheckKey(seed);
    let mut mask = 0u8;
    let mut slots = [[0u8; TAG_LEN]; SLOTS];
    for (i, s) in slots.iter_mut().enumerate() {
        *s = seed.expand(b"ksg:ia:stub:v1", &[&[i as u8]]);
    }
    for (kind, number) in docs {
        let i = *kind as usize;
        if mask & (1 << i) != 0 {
            return Err(format!("issuance anchor: {kind:?} given twice"));
        }
        mask |= 1 << i;
        slots[i] = key.doc_tag(*kind, number)?;
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
        (DocKind::Passport, "AB 123456"),
        (DocKind::TaxNumber, "1234567890"),
    ];

    #[test]
    fn a_second_free_bare_is_caught_by_any_one_document() {
        let m = seal(&y2026(), "2026", &sc(), ANNA, [1; 32]).unwrap();
        let a = open(&y2026(), &m).unwrap();
        assert!(a
            .matches(&y2026(), &sc(), &[(DocKind::TaxNumber, "12345 67890")])
            .unwrap());
        assert!(a
            .matches(&y2026(), &sc(), &[(DocKind::Passport, "ab-123456")])
            .unwrap());
    }

    #[test]
    fn another_person_another_scope_or_another_kind_is_free() {
        let a = open(
            &y2026(),
            &seal(&y2026(), "2026", &sc(), ANNA, [1; 32]).unwrap(),
        )
        .unwrap();
        assert!(!a
            .matches(&y2026(), &sc(), &[(DocKind::Passport, "XY999999")])
            .unwrap());
        assert!(!a
            .matches(&y2026(), &scope("bare-2026-10", "2.1.0"), ANNA)
            .unwrap());
        // the same number shown as another kind of document
        assert!(!a
            .matches(&y2026(), &sc(), &[(DocKind::IdCard, "AB123456")])
            .unwrap());
    }

    #[test]
    fn a_stub_never_matches() {
        let a = open(
            &y2026(),
            &seal(&y2026(), "2026", &sc(), ANNA, [1; 32]).unwrap(),
        )
        .unwrap();
        assert_eq!(a.mask, 0b0000_1001);
        for k in [DocKind::IdCard, DocKind::DrivingLicence, DocKind::Other2] {
            assert!(!a.matches(&y2026(), &sc(), &[(k, "AB123456")]).unwrap());
        }
    }

    #[test]
    fn every_anchor_has_one_size_and_shows_only_its_year() {
        let one = seal(&y2026(), "2026", &sc(), &ANNA[..1], [1; 32]).unwrap();
        let two = seal(&y2026(), "2026", &sc(), ANNA, [2; 32]).unwrap();
        assert_eq!(one.len(), two.len());
        assert_eq!(period_of(&one), Some("2026"));
        assert!(!one.to_uppercase().contains("AB123456"));
        assert!(!one.contains(&hex::encode(
            y2026().doc_tag(DocKind::Passport, "AB123456").unwrap()
        )));
        assert!(one.len() < 1024, "fits a chain record: {}", one.len());
    }

    #[test]
    fn the_same_person_twice_gives_unlinkable_anchors() {
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
        assert!(seal(
            &y2026(),
            "2026",
            &sc(),
            &[(DocKind::Passport, " - ")],
            [1; 32]
        )
        .is_err());
        let twice = [(DocKind::Passport, "A1"), (DocKind::Passport, "B2")];
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
