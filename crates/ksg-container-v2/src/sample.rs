//! Signed binding of a selective hash — a paid service. `[decision]` 22.09, CT-44, CT-45.
//!
//! # What the owner described
//!
//! A separate, optional service, at the wish of the client or the owner: a hash
//! of **randomly chosen pieces** of the artefact the client keeps, signed, and
//! recorded in the journal of work.
//!
//! The owner's example, word for word in structure: an artefact of 12 GB; three
//! positions — at 3.12 GB take 100 characters, at 7.64 GB take 60, at 9.73 GB
//! take 12; put them together and hash them; add the hash of the **whole**
//! artefact in its clean state, without the signature, and the hash of it
//! **with** the signature; that whole record goes into the journal.
//!
//! | Rule | Where |
//! |---|---|
//! | positions are **new at every signing** | [`SampleRecord::take`] draws them from a fresh seed |
//! | together the pieces are **at most 256 KB** | [`SAMPLE_MAX_BYTES`] |
//! | the client **cannot know** the positions — they stay inside the record, and the record goes into the journal of work, which is closed | the record is page content; nothing here prints the spans |
//! | before payment, the same hash is **read a second time** | [`Binding::confirm`] |
//! | order: price → consent → second reading → payment → journal | [`Binding`] refuses any other order |
//! | 1st signature $2, each next ×2, **$256 from the 8th on, for every one after** | [`price_of_signature_cents`] |
//! | the issuer sees nothing; the automation runs inside, without it | the file is read locally; nothing here sends anything anywhere |
//! | gas is paid by the container / issuer — **only** in this service | the service's payer, not this crate: no network here |
//! | the record is a **new page** of the journal of work, **anchored by default**; in the deferred class it may go unanchored, **and then without the issuer's signature** (`[decision]` 22.09) | page kind `HashBinding`; the journal's class rule |
//! | a plain-format container takes no anchors (`[decision]` 13.09) | so the service does not exist there — the container refuses the anchored page |
//!
//! # What it proves, and what it does not
//!
//! `[inference]` A client who throws the file away and keeps only earlier pieces gains
//! nothing: the next signing picks new positions. And in an audit, a dispute or
//! a court the full artefact has to be presented anyway — the owner's point: "they
//! won't throw it away". Keeping the file is the client's side of the boundary
//! (`Prilozhenie` §2.10); this service lets a client show that it did.
//!
//! # Who signs
//!
//! `[decision]` 23.09 (CT-47): **the container**, with the issuer's seal laid into it
//! at printing (`crate::seal`). The issuer takes no part and sees nothing.
//! In Pro — the full class — the record goes into the journal only signed
//! (CT-48); in the deferred class it may go without an anchor, and then
//! without the signature (`[decision]` 22.09).

use std::io::{Read, Seek, SeekFrom};

use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use ksg_core_v2::crypto::hash::Hash;

/// The most the chosen pieces may add up to, in bytes (`[decision]` 22.09: "up to 256 KB").
pub const SAMPLE_MAX_BYTES: u64 = 256 * 1024;

/// The price of the first signature, in cents.
pub const FIRST_SIGNATURE_CENTS: u64 = 200;

/// Where the price stops climbing, in cents: $256, reached at the 8th signature
/// and held for every one after it (`[decision]` 22.09, CT-44).
pub const SIGNATURE_CAP_CENTS: u64 = 25_600;

/// Separates the position stream from every other derived value.
const SPANS_INFO: &[u8] = b"ksg:sample-spans:v1";

/// What one more signature costs, in cents, after `signed_before` of them in
/// this container: $2, $4, $8 … $256, then $256 for every one after.
#[must_use]
pub fn price_of_signature_cents(signed_before: u64) -> u64 {
    if signed_before >= 7 {
        return SIGNATURE_CAP_CENTS;
    }
    FIRST_SIGNATURE_CENTS << signed_before
}

/// One chosen piece: where it starts and how long it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    /// The byte offset from the start of the file.
    pub offset: u64,
    /// How many bytes from there.
    pub len: u32,
}

/// What can go wrong.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SampleError {
    /// Nothing to choose from, or no pieces asked for.
    #[error("an empty artefact, or no pieces asked for")]
    Nothing,
    /// The file could not be read where a piece lies.
    #[error("the artefact could not be read at a chosen position")]
    Unreadable,
    /// The second reading did not give the same hash: the file presented is
    /// not the one first read.
    #[error("the second reading does not match the first")]
    Mismatch,
    /// A step of the service out of its order.
    #[error("{0}")]
    OutOfOrder(&'static str),
}

/// Chooses `count` pieces of a file of `size` bytes, from `seed`.
///
/// The seed comes from the caller's CSPRNG, as every secret does in these
/// crates; a new seed at every signing is what makes the positions new. The
/// pieces together never exceed [`SAMPLE_MAX_BYTES`].
///
/// # Errors
///
/// [`SampleError::Nothing`] for an empty file or zero pieces.
pub fn choose(seed: &[u8; 32], size: u64, count: usize) -> Result<Vec<Span>, SampleError> {
    if size == 0 || count == 0 {
        return Err(SampleError::Nothing);
    }
    let count_u64 = u64::try_from(count).map_err(|_| SampleError::Nothing)?;
    let per_piece = (SAMPLE_MAX_BYTES / count_u64).clamp(1, size);
    // One expansion per piece, the piece's number in the label: HKDF-SHA256
    // gives at most 8 160 bytes per call, which a thousand pieces would pass.
    let hk = Hkdf::<Sha256>::new(None, seed);
    let mut spans = Vec::with_capacity(count);
    for i in 0..count_u64 {
        let mut info = Vec::with_capacity(SPANS_INFO.len() + 8);
        info.extend_from_slice(SPANS_INFO);
        info.extend_from_slice(&i.to_be_bytes());
        let mut chunk = [0u8; 16];
        hk.expand(&info, &mut chunk)
            .map_err(|_| SampleError::Nothing)?;
        let a = u64::from_be_bytes(chunk[..8].try_into().expect("8 bytes"));
        let b = u64::from_be_bytes(chunk[8..].try_into().expect("8 bytes"));
        let len = 1 + b % per_piece;
        let offset = a % (size - len + 1);
        spans.push(Span {
            offset,
            len: u32::try_from(len).map_err(|_| SampleError::Nothing)?,
        });
    }
    Ok(spans)
}

/// The hash of the chosen pieces, read from `file`.
///
/// Each piece goes in with its offset and length, so the same bytes at a
/// different place do not give the same hash.
///
/// # Errors
///
/// [`SampleError::Unreadable`] when a piece lies outside the file or cannot be
/// read.
pub fn digest<R: Read + Seek>(file: &mut R, spans: &[Span]) -> Result<Hash, SampleError> {
    let mut parts: Vec<Vec<u8>> = vec![b"ksg:sample:v1".to_vec()];
    for s in spans {
        file.seek(SeekFrom::Start(s.offset))
            .map_err(|_| SampleError::Unreadable)?;
        let mut buf = vec![0u8; s.len as usize];
        file.read_exact(&mut buf)
            .map_err(|_| SampleError::Unreadable)?;
        parts.push(s.offset.to_be_bytes().to_vec());
        parts.push(buf);
    }
    let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    Ok(Hash::sha256_fields(&refs))
}

/// The hash of a whole file, read in chunks so a 12 GB artefact is never held
/// in memory at once.
///
/// # Errors
///
/// [`SampleError::Unreadable`] when the file cannot be read.
pub fn whole<R: Read + Seek>(file: &mut R) -> Result<Hash, SampleError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| SampleError::Unreadable)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = file.read(&mut buf).map_err(|_| SampleError::Unreadable)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(Hash::from_bytes(h.finalize().into()))
}

/// The record that goes into the journal of work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SampleRecord {
    /// The chosen pieces. Inside the record, and so inside the closed journal.
    pub spans: Vec<Span>,
    /// The hash of the pieces.
    pub sample: Hash,
    /// The hash of the whole artefact in its clean state, without the signature.
    pub clean: Hash,
    /// The hash of the whole artefact with the signature.
    pub signed: Hash,
}

impl SampleRecord {
    /// Chooses new positions and reads them from the stored artefact.
    ///
    /// `stored` is the artefact the client keeps — the pieces are read from it;
    /// `clean` is the artefact without the signature. Both are read whole for
    /// their hashes.
    ///
    /// # Errors
    ///
    /// [`SampleError`] when there is nothing to read or a piece cannot be read.
    pub fn take<A: Read + Seek, B: Read + Seek>(
        seed: &[u8; 32],
        stored: &mut A,
        clean: &mut B,
        count: usize,
    ) -> Result<Self, SampleError> {
        let size = stored
            .seek(SeekFrom::End(0))
            .map_err(|_| SampleError::Unreadable)?;
        let spans = choose(seed, size, count)?;
        let sample = digest(stored, &spans)?;
        Ok(Self {
            sample,
            clean: whole(clean)?,
            signed: whole(stored)?,
            spans,
        })
    }

    /// The record as page content for the journal of work, under the page
    /// kind `HashBinding`: the same framed fields the signature covers, so what
    /// is exported is what was signed.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for f in self.fields() {
            out.extend_from_slice(&u32::try_from(f.len()).unwrap_or(u32::MAX).to_be_bytes());
            out.extend_from_slice(&f);
        }
        out
    }

    fn fields(&self) -> Vec<Vec<u8>> {
        let mut parts: Vec<Vec<u8>> = vec![
            b"ksg:sample-record:v1".to_vec(),
            self.sample.as_bytes().to_vec(),
            self.clean.as_bytes().to_vec(),
            self.signed.as_bytes().to_vec(),
            (self.spans.len() as u64).to_be_bytes().to_vec(),
        ];
        for s in &self.spans {
            parts.push(s.offset.to_be_bytes().to_vec());
            parts.push(s.len.to_be_bytes().to_vec());
        }
        parts
    }

    /// What the signature covers: the three hashes and the positions.
    #[must_use]
    pub fn subject(&self) -> Hash {
        let parts = self.fields();
        let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        Hash::sha256_fields(&refs)
    }
}

/// Where a binding stands. The owner's order, and no other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// The price has been shown.
    Quoted,
    /// The client agreed to it.
    Agreed,
    /// The same hash was read a second time, and matched.
    Confirmed,
    /// Paid; the payment is on record.
    Paid,
    /// Signed by the container with the issuer's seal.
    Signed,
}

/// One paid signing, from the price to the payment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    /// The record being bound.
    pub record: SampleRecord,
    /// What this signing costs, in cents.
    pub price_cents: u64,
    /// The field that receives the payment: a reference to it — a transaction
    /// or an invoice — opaque here.
    pub payment: Option<String>,
    /// The issuer's seal over [`SampleRecord::subject`], put by the container.
    pub issuer_signature: Option<ksg_core_v2::crypto::sign::Signature>,
    step: Step,
}

impl Binding {
    /// Shows the price for the next signature in this container.
    #[must_use]
    pub fn quote(record: SampleRecord, signed_before: u64) -> Self {
        Self {
            record,
            price_cents: price_of_signature_cents(signed_before),
            payment: None,
            issuer_signature: None,
            step: Step::Quoted,
        }
    }

    /// Where the binding stands.
    #[must_use]
    pub const fn step(&self) -> Step {
        self.step
    }

    /// The client agrees to the price.
    ///
    /// # Errors
    ///
    /// [`SampleError::OutOfOrder`] unless the price was just shown.
    pub fn agree(&mut self) -> Result<(), SampleError> {
        self.advance(
            Step::Quoted,
            Step::Agreed,
            "agreement comes after the price",
        )
    }

    /// Reads the same pieces a second time and compares.
    ///
    /// # Errors
    ///
    /// [`SampleError::OutOfOrder`] before agreement; [`SampleError::Mismatch`]
    /// when the file presented now is not the one read first.
    pub fn confirm<R: Read + Seek>(&mut self, stored: &mut R) -> Result<(), SampleError> {
        if self.step != Step::Agreed {
            return Err(SampleError::OutOfOrder(
                "the second reading comes after agreement",
            ));
        }
        if digest(stored, &self.record.spans)? != self.record.sample {
            return Err(SampleError::Mismatch);
        }
        self.step = Step::Confirmed;
        Ok(())
    }

    /// Records the payment.
    ///
    /// # Errors
    ///
    /// [`SampleError::OutOfOrder`] before the second reading matched.
    pub fn pay(&mut self, payment: String) -> Result<(), SampleError> {
        self.advance(
            Step::Confirmed,
            Step::Paid,
            "payment comes after the second reading",
        )?;
        self.payment = Some(payment);
        Ok(())
    }

    /// The container signs the paid record with the issuer's seal (CT-47).
    ///
    /// # Errors
    ///
    /// [`SampleError::OutOfOrder`] before payment.
    pub fn sign(&mut self, seal: &crate::seal::IssuerSeal) -> Result<(), SampleError> {
        self.advance(Step::Paid, Step::Signed, "the seal comes after payment")?;
        self.issuer_signature = Some(seal.seal(&self.record.subject()));
        Ok(())
    }

    /// The record, ready for the journal of work.
    ///
    /// In the Pro form of the journal only signed (CT-48; CH-22: a light
    /// container that went Pro takes on Pro's requirements); in the light
    /// form once paid, signed or not. `form` is the journal's form now —
    /// `Container::form`.
    ///
    /// # Errors
    ///
    /// [`SampleError::OutOfOrder`] before payment, or unsigned in Pro.
    pub fn for_journal(
        &self,
        form: ksg_core_v2::journal::Mode,
    ) -> Result<&SampleRecord, SampleError> {
        match (self.step, form) {
            (Step::Signed, _) => Ok(&self.record),
            (Step::Paid, ksg_core_v2::journal::Mode::Pro) => Err(SampleError::OutOfOrder(
                "in Pro the record goes into the journal only with the issuer's seal",
            )),
            (Step::Paid, _) => Ok(&self.record),
            _ => Err(SampleError::OutOfOrder(
                "the journal takes the record after payment",
            )),
        }
    }

    fn advance(&mut self, from: Step, to: Step, why: &'static str) -> Result<(), SampleError> {
        if self.step != from {
            return Err(SampleError::OutOfOrder(why));
        }
        self.step = to;
        Ok(())
    }
}
