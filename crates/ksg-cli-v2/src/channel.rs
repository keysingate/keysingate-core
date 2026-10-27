//! The channel: the issuer, its distributors and their agents, each at its own
//! desk. Item P-8 of the MVP plan.
//!
//! A **desk** is a directory holding one party's key and what it was granted:
//!
//! | Party | Gets | Gives |
//! |---|---|---|
//! | issuer | — | the release (`Emission`); grants of ranges (`Delegation`, depth 0); packets |
//! | distributor | a grant from the issuer | grants to its agents (depth 1…4); packets |
//! | agent of a distributor | a grant from the distributor | the same, one level down |
//!
//! A packet is sold as a **sale** file: the release, the chain of grants and
//! the `BlockAllocation`. The enterprise that bought it prints containers on
//! its serials (`ksg init --sale`), and each container keeps the whole chain
//! as a `ChannelProof` a verifier checks without asking anyone
//! (`ksg-verify --channel`).
//!
//! # Numbers are handed out once
//!
//! Serials are the thing sold — as policy blank numbers are in agency sales of
//! insurance — so a desk never gives out a serial twice. Both a grant and a
//! packet are taken from the desk's ledger cursor (`ksg-issuer::Ledger`),
//! which only moves forward; a grant is recorded there as a block of the
//! delegate's. A desk cannot grant or sell what it was not granted: its
//! ledger spans only its own range.
//!
//! # The MVP boundary
//!
//! Every desk is a directory with a seed in it (`desk.json`, mode 0600). In the
//! product the issuer's root key is offline and the operational key is itself a
//! grant (`ksg-core::doc::delegation`); here one key per desk.

use std::path::{Path, PathBuf};

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{
    sign_doc, Ed25519Signer, KeySet, Profile, PublicKey, SignatureSet,
};
use ksg_core_v2::doc::{
    resolve, BlockAllocation, BlockClosure, Class, Delegation, Emission, Range, Serial, Timestamp,
    Uri,
};
use ksg_issuer_v2::{Book, Event, Issuer, Ledger, LedgerSnapshot, PacketTerms, Stage, Terms};
use ksg_verify_v2::channel::ChannelProof;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::clock::{now_ms, utc};
use crate::home::{read, write_atomic, Home, Lock};

const DAY_MS: u64 = 86_400_000;

/// One party's desk, as stored.
#[derive(Serialize, Deserialize)]
pub struct Desk {
    /// `issuer` or `distributor`.
    pub role: String,
    /// Who the party is.
    pub name: Uri,
    /// Its key identifier.
    pub kid: Uri,
    /// Its seed, base64url. Secret.
    pub seed: String,
    /// The release, once issued or accepted.
    pub emission: Option<Emission>,
    /// The grants down to this desk, outermost first; empty for the issuer.
    pub chain: Vec<Delegation>,
    /// The serials this desk may still hand out.
    pub ledger: Option<LedgerSnapshot>,
    /// The serials the issuer has printed a container on: one serial, one
    /// container. Absent in desks written before it existed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub printed: Vec<u64>,
    /// Packets the issuer issued a template of: their serials are printed
    /// from the template, not at the desk.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub templated: Vec<Range>,
    /// Packets ordered and not paid for yet.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub orders: Vec<Order>,
    /// The number of the last order taken, so numbers are not reused.
    #[serde(default)]
    pub last_order: u64,
    /// Every order with what happened to it — placed, paid, issued, handed
    /// over, cancelled, expired (`ksg_issuer_v2::fulfilment`). `orders` above
    /// is the list of open orders; this is the record, and it is never
    /// shortened. Absent in desks written before it existed.
    #[serde(default, skip_serializing_if = "Book::is_empty")]
    pub book: Book,
    /// The holders' closing statements this desk accepted, as signed. The
    /// ledger keeps only their hashes, but the next packet to the same holder
    /// must carry the statement itself (§7 rule 3). Absent in desks written
    /// before it existed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub closures: Vec<BlockClosure>,
}

impl Drop for Desk {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.seed.zeroize();
    }
}

/// A packet as sold: everything the buyer needs to print on it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sale {
    /// Always `"Sale"`.
    #[serde(rename = "type")]
    pub doc_type: String,
    /// The release.
    pub emission: Emission,
    /// The grants from the issuer to the seller.
    pub chain: Vec<Delegation>,
    /// The packet.
    pub packet: BlockAllocation,
}

fn e(x: impl std::fmt::Display) -> String {
    x.to_string()
}

fn uri(s: &str) -> Result<Uri, String> {
    Uri::parse(s).map_err(|x| format!("{s}: {x}"))
}

/// The distributor's seat in a container (C-12, owner's decisions 17.10
/// "B" and "give the distributor a module to add its key"): the distributor
/// that sold a packet says, under its desk key, which key takes its seat in
/// the containers of that packet. The holder hands it to `packet --seat`; the
/// container takes it only after [`check_seat`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DistributorSeat {
    /// Always `"DistributorSeat"`.
    #[serde(rename = "type")]
    pub doc_type: String,
    /// The release.
    pub emission: String,
    /// The packet it is for: the multihash of its document.
    pub packet: String,
    /// Who bought the packet.
    pub holder: Uri,
    /// The distributor (or its agent) that sold it — the last grant's delegate.
    pub distributor: Uri,
    /// The key that takes the seat: one of the last grant's keys.
    pub key: PublicKey,
    /// That key's signature over [`DistributorSeat::message`].
    pub signature: ksg_core_v2::crypto::sign::Signature,
}

/// The type of a [`DistributorSeat`].
pub const SEAT_TYPE: &str = "DistributorSeat";

impl DistributorSeat {
    /// The bytes the seat key signs: every field but the signature, framed.
    #[must_use]
    pub fn message(
        emission: &str,
        packet: &str,
        holder: &Uri,
        distributor: &Uri,
        key: &PublicKey,
    ) -> Vec<u8> {
        Hash::sha256_fields(&[
            b"ksg:distributor-seat:v1",
            emission.as_bytes(),
            packet.as_bytes(),
            holder.as_str().as_bytes(),
            distributor.as_str().as_bytes(),
            key.kid.as_str().as_bytes(),
            key.key.as_bytes(),
        ])
        .as_bytes()
        .to_vec()
    }
}

/// The distributor's module: the seat document for the packet of `sale`,
/// signed at the desk in `dir` — which must be the desk that sold it.
///
/// # Errors
///
/// Not a distributor's desk; a direct sale (no grant); the desk's key is not
/// the last grant's — another seller sold this packet.
pub fn seat_statement(dir: &Path, sale: &Sale) -> Result<DistributorSeat, String> {
    let desk = Desk::open(dir)?;
    if desk.role != "distributor" {
        return Err(format!("{}: not a distributor's desk", dir.display()));
    }
    let signer = desk.signer()?;
    let key = signer.public();
    let grant = sale
        .chain
        .last()
        .ok_or("the issuer sold this packet directly: there is no distributor's seat")?;
    if !grant.keys.iter().any(|k| k == &key) {
        return Err(format!(
            "{}: this desk did not sell this packet (it is {}'s)",
            dir.display(),
            grant.delegate.as_str()
        ));
    }
    let packet = ksg_core_v2::canonical::doc_hash(&sale.packet)
        .map_err(e)?
        .to_multihash();
    let msg = DistributorSeat::message(
        &sale.emission.id,
        &packet,
        &sale.packet.holder,
        &grant.delegate,
        &key,
    );
    Ok(DistributorSeat {
        doc_type: SEAT_TYPE.into(),
        emission: sale.emission.id.clone(),
        packet,
        holder: sale.packet.holder.clone(),
        distributor: grant.delegate.clone(),
        signature: signer.sign(&msg),
        key,
    })
}

/// Checks a seat document against the sale it claims, and returns the key
/// that takes the seat. The sale itself is checked again here (`check_sale`:
/// the grants down from the release's keys, the packet signed by the last of
/// them), and the release's keys must include `issuer` — the issuer of the
/// container at hand, not whatever keys the sale file carries.
///
/// # Errors
///
/// Any link that does not hold, named.
pub fn check_seat(
    seat: &DistributorSeat,
    sale: &Sale,
    issuer: &PublicKey,
) -> Result<PublicKey, String> {
    if seat.doc_type != SEAT_TYPE {
        return Err("the seat: not a DistributorSeat".into());
    }
    check_sale(sale)?;
    if !sale.emission.keys.iter().any(|k| k == issuer) {
        return Err("the seat: the sale is not of this container's issuer".into());
    }
    let grant = sale
        .chain
        .last()
        .ok_or("the seat: the issuer sold this packet directly — there is no distributor")?;
    if seat.emission != sale.emission.id {
        return Err("the seat: another release".into());
    }
    let packet = ksg_core_v2::canonical::doc_hash(&sale.packet)
        .map_err(e)?
        .to_multihash();
    if seat.packet != packet || seat.holder != sale.packet.holder {
        return Err("the seat: another packet or another holder".into());
    }
    if seat.distributor != grant.delegate || !grant.keys.iter().any(|k| k == &seat.key) {
        return Err(
            "the seat: the key is not the seller's — the last grant does not name it".into(),
        );
    }
    let msg = DistributorSeat::message(
        &seat.emission,
        &seat.packet,
        &seat.holder,
        &seat.distributor,
        &seat.key,
    );
    let keys: KeySet = std::iter::once(seat.key.clone()).collect();
    SignatureSet::new(vec![seat.signature.clone()])
        .verify(&msg, &keys, &Profile::default().with_ed25519())
        .map_err(|x| format!("the seat: the distributor's signature: {x}"))?;
    Ok(seat.key.clone())
}

/// The signer of the distributor's desk in `dir`: its key, for the
/// declaration of a dead container with the client (C-12, 17.10).
///
/// # Errors
///
/// No desk there, a desk that is not a distributor's, or a bad seed.
pub fn distributor_signer(dir: &Path) -> Result<Ed25519Signer, String> {
    let desk = Desk::open(dir)?;
    if desk.role != "distributor" {
        return Err(format!("{}: not a distributor's desk", dir.display()));
    }
    desk.signer()
}

fn desk_path(dir: &Path) -> PathBuf {
    dir.join("desk.json")
}

fn now() -> Timestamp {
    utc(now_ms())
}

fn later(days: u64) -> Result<Timestamp, String> {
    let ms = days
        .checked_mul(DAY_MS)
        .and_then(|d| d.checked_add(now_ms()));
    ms.map(utc).ok_or_else(|| "--days: too long".into())
}

impl Desk {
    fn open(dir: &Path) -> Result<Self, String> {
        serde_json::from_slice(&Zeroizing::new(read(&desk_path(dir))?))
            .map_err(|x| format!("desk.json: {x}"))
    }

    fn save(&self, dir: &Path) -> Result<(), String> {
        let bytes = Zeroizing::new(serde_json::to_vec_pretty(self).map_err(e)?);
        write_atomic(&desk_path(dir), &bytes, true)
    }

    fn signer(&self) -> Result<Ed25519Signer, String> {
        let v = Zeroizing::new(B64.decode(&self.seed).map_err(|_| "desk.json: seed")?);
        let seed: [u8; 32] = v.as_slice().try_into().map_err(|_| "desk.json: seed")?;
        Ok(Ed25519Signer::from_seed(self.kid.clone(), seed))
    }

    /// The seed, for printing containers at the issuer's desk.
    pub(crate) fn seed(&self) -> Result<Zeroizing<[u8; 32]>, String> {
        let v = Zeroizing::new(B64.decode(&self.seed).map_err(|_| "desk.json: seed")?);
        let mut out = Zeroizing::new([0u8; 32]);
        if v.len() != 32 {
            return Err("desk.json: seed".into());
        }
        out.copy_from_slice(&v);
        Ok(out)
    }

    fn fresh(dir: &Path, role: &str, name: Uri, kid: Uri) -> Result<Self, String> {
        std::fs::create_dir_all(dir).map_err(|x| format!("{}: {x}", dir.display()))?;
        if desk_path(dir).exists() {
            return Err(format!("{} already holds a desk", dir.display()));
        }
        // Test keys only (`crate::testkeys`): the issuer's is the release-wide
        // one, a distributor's is named after it.
        let s = match role {
            "issuer" => crate::testkeys::secret(crate::testkeys::ISSUER),
            _ => crate::testkeys::secret(&format!("distributor:{}", name.as_str())),
        };
        Ok(Self {
            role: role.into(),
            name,
            kid,
            seed: B64.encode(*s),
            emission: None,
            chain: Vec::new(),
            ledger: None,
            printed: Vec::new(),
            templated: Vec::new(),
            orders: Vec::new(),
            last_order: 0,
            book: Book::new(),
            closures: Vec::new(),
        })
    }

    fn emission(&self) -> Result<&Emission, String> {
        self.emission
            .as_ref()
            .ok_or_else(|| "this desk has no release yet: accept a grant first".into())
    }

    /// The closing statement of `holder`'s last block, if the desk took one.
    /// `None` for a first packet — and for a block not closed yet, which the
    /// ledger then refuses as it must.
    fn last_closure(&self, ledger: &Ledger, holder: &Uri) -> Option<&BlockClosure> {
        let last = ledger.blocks_of(holder).last()?;
        self.closures.iter().find(|c| c.block == *last)
    }

    fn ledger(&self) -> Result<Ledger, String> {
        let s = self
            .ledger
            .clone()
            .ok_or("this desk has nothing to hand out")?;
        Ledger::restore(s).map_err(e)
    }
}

fn write_json(path: &Path, v: &impl Serialize) -> Result<(), String> {
    write_atomic(path, &serde_json::to_vec_pretty(v).map_err(e)?, false)
}

/// Opens the issuer's desk and issues the release. Writes `emission.json` and
/// `issuer-keys.json` (what verifiers are given as the issuer's keys).
///
/// # Errors
///
/// The directory already holds a desk, or the terms do not pass the core's
/// check of a release.
pub fn issuer_init(
    dir: &Path,
    release: &str,
    range: Range,
    ttl_days: u32,
) -> Result<Emission, String> {
    let mut desk = Desk::fresh(
        dir,
        "issuer",
        uri(crate::home::kid::ISSUER_PARTY)?,
        uri(crate::home::kid::ISSUER)?,
    )?;
    let signer = desk.signer()?;
    let issuer = Issuer::issue(
        &Terms {
            id: release.into(),
            range,
            block_ttl_days: ttl_days,
            issuer: desk.name.clone(),
        },
        &signer,
        now(),
    )
    .map_err(e)?;
    let emission = issuer.emission().clone();
    desk.emission = Some(emission.clone());
    desk.ledger = Some(issuer.ledger().snapshot());
    desk.save(dir)?;
    write_json(&dir.join("emission.json"), &emission)?;
    write_json(&dir.join("issuer-keys.json"), &emission.keys)?;
    Ok(emission)
}

/// Opens a distributor's (or an agent's) desk. Writes `keys.json`, which the
/// grantor needs to name the keys in the grant.
///
/// # Errors
///
/// The directory already holds a desk.
pub fn desk_init(dir: &Path, name: &str) -> Result<PublicKey, String> {
    let name = uri(name)?;
    let kid = uri(&format!("{}#k1", name.as_str()))?;
    let desk = Desk::fresh(dir, "distributor", name, kid)?;
    let public = desk.signer()?.public();
    desk.save(dir)?;
    write_json(&dir.join("keys.json"), &[&public])?;
    Ok(public)
}

/// Grants the next `size` serials of this desk to `to`, for `days`: returns
/// the whole chain the grantee accepts.
///
/// # Errors
///
/// No serials left, a term outside 90…180 days is refused by the core, or the
/// chain would pass four levels below the issuer.
pub fn grant(
    dir: &Path,
    to: &str,
    keys: Vec<PublicKey>,
    size: u64,
    days: u64,
) -> Result<Vec<Delegation>, String> {
    let mut desk = Desk::open(dir)?;
    let emission = desk.emission()?.clone();
    let signer = desk.signer()?;
    let to = uri(to)?;

    // The range comes off this desk's ledger, as a packet would: recorded as
    // a block of the delegate's, so the desk can never hand it out again.
    let mut ledger = desk.ledger()?;
    let reserved = ledger
        .allocate(
            &to,
            None,
            &signer,
            &KeySet::new(),
            PacketTerms {
                allocated_at: now(),
                expires_at: later(days)?,
                class: Class::Bare,
                block_size: size,
                anchor_period_ms: None,
            },
        )
        .map_err(e)?;

    let parent = desk.chain.last();
    // A grant cannot outlive the one it comes from (the core refuses it): a
    // sub-grant ends when its parent does, if that is sooner.
    let start = now_ms();
    let mut end = days
        .checked_mul(DAY_MS)
        .and_then(|d| d.checked_add(start))
        .ok_or("--days: too long")?;
    if let Some(p) = parent {
        let parent_end =
            crate::clock::parse_ms(&p.expires_at).ok_or("the parent grant's end does not read")?;
        end = end.min(parent_end);
    }
    if end <= start {
        return Err("the grant this desk holds has run out".into());
    }
    let doc = Delegation {
        context: ksg_core_v2::doc::Context,
        doc_type: "Delegation".into(),
        v: ksg_core_v2::version::CURRENT_V,
        emission: emission.id.clone(),
        range: reserved.block,
        delegate: to,
        keys,
        parent: parent
            .map(ksg_core_v2::canonical::doc_hash)
            .transpose()
            .map_err(e)?,
        depth: parent.map_or(0, |p| p.depth.saturating_add(1)),
        delegated_at: utc(start),
        term_ms: end - start,
        expires_at: utc(end),
        signatures: SignatureSet::default(),
    };
    let sig = sign_doc(&doc, &signer).map_err(e)?;
    let doc = Delegation {
        signatures: SignatureSet::new(vec![sig]),
        ..doc
    };
    let mut chain = desk.chain.clone();
    chain.push(doc);
    let emission_keys: KeySet = emission.keys.iter().cloned().collect();
    resolve(&emission, &chain, &emission_keys, &Profile::default())
        .map_err(|x| format!("the grant: {x}"))?;

    desk.ledger = Some(ledger.snapshot());
    desk.save(dir)?;
    Ok(chain)
}

/// Takes a grant: the desk's release and range from now on.
///
/// # Errors
///
/// The chain does not verify against the release, or does not grant this
/// desk's key.
pub fn accept(dir: &Path, emission: Emission, chain: Vec<Delegation>) -> Result<Range, String> {
    let mut desk = Desk::open(dir)?;
    if desk.emission.is_some() {
        return Err("this desk already holds a grant".into());
    }
    emission
        .validate(&Profile::default())
        .map_err(|x| format!("release: {x}"))?;
    let emission_keys: KeySet = emission.keys.iter().cloned().collect();
    let (granted, range) = resolve(&emission, &chain, &emission_keys, &Profile::default())
        .map_err(|x| format!("the grant: {x}"))?;
    let me = desk.signer()?.public();
    if granted.get(&me.kid) != Some(&me) {
        return Err("the grant is for other keys than this desk's".into());
    }
    let ledger = Ledger::open(emission.id.clone(), range).map_err(e)?;
    desk.emission = Some(emission);
    desk.chain = chain;
    desk.ledger = Some(ledger.snapshot());
    desk.save(dir)?;
    Ok(range)
}

/// A packet ordered and not paid for yet: no serials are taken for it.
///
/// Payment is the one point money passes through the channel
/// (`Mekhanizm_oplaty.md` §2–3): the seller issues the packet only once
/// payment is confirmed, and the moment of confirmation is the packet's
/// origin — paid serials become the packet's (`[decision]` 19.09).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Order {
    /// The order's number at this desk, `ord-N`.
    pub id: String,
    /// The buyer's holder URI.
    pub to: String,
    /// The packet's class.
    pub class: Class,
    /// How many serials.
    pub size: u64,
    /// For how many days after payment the packet is valid.
    pub days: u64,
    /// When it was ordered.
    pub ordered_at: Timestamp,
}

fn packet_terms(class: Class, size: u64, days: u64) -> Result<PacketTerms, String> {
    Ok(PacketTerms {
        allocated_at: now(),
        expires_at: later(days)?,
        class,
        block_size: size,
        anchor_period_ms: None,
    })
}

/// Takes an order for a packet of `size` serials of `class` for `to`, valid
/// for `days` after payment. No serial is taken: that happens at
/// [`confirm_payment`]. `to` is the buyer's holder URI: its key is what binds
/// the packet later (KS-5).
///
/// # Errors
///
/// `to` names no key, the desk is busy, or the packet could not be issued as
/// ordered (no serials left, a size the class is not sold in) — checked now
/// so that an order that can never be served is not taken.
pub fn order(dir: &Path, to: &str, class: Class, size: u64, days: u64) -> Result<Order, String> {
    if ksg_verify_v2::channel::holder_key(to).is_none() {
        return Err(format!(
            "--to must be the buyer's holder URI ({}…, from `ksg --home DIR holder`)",
            ksg_verify_v2::channel::HOLDER_PREFIX
        ));
    }
    let _lock = Lock::take(&Home(dir.to_path_buf()))?;
    let mut desk = Desk::open(dir)?;
    // A dry run on a copy of the ledger: nothing is taken, nothing is saved.
    let holder = uri(to)?;
    let mut ledger = desk.ledger()?;
    let prev = desk.last_closure(&ledger, &holder).cloned();
    ledger
        .allocate(
            &holder,
            prev.as_ref(),
            &desk.signer()?,
            &KeySet::new(),
            packet_terms(class, size, days)?,
        )
        .map_err(e)?;
    let next = desk
        .orders
        .iter()
        .filter_map(|o| o.id.strip_prefix("ord-")?.parse::<u64>().ok())
        .chain(std::iter::once(desk.last_order))
        .max()
        .unwrap_or(0)
        + 1;
    let o = Order {
        id: format!("ord-{next}"),
        to: to.to_owned(),
        class,
        size,
        days,
        ordered_at: now(),
    };
    desk.last_order = next;
    // Step 2 of `Mekhanizm_oplaty.md` §3: the order is placed and the invoice
    // issued. In the MVP the invoice is the order itself, so its reference is
    // the order's number.
    desk.book
        .place(
            &o.id,
            o.ordered_at.clone(),
            Event::Placed {
                buyer: uri(to)?,
                class,
                size,
                days,
                invoice: o.id.clone(),
            },
        )
        .map_err(|x| x.to_string())?;
    desk.orders.push(o.clone());
    desk.save(dir)?;
    Ok(o)
}

/// Confirms payment of order `id` by hand (the MVP's form of payment,
/// `Plan_MVP_2026-09-23.md` §3.2) and issues the packet: its serials are
/// taken now, and now is its origin.
///
/// # Errors
///
/// No such order, the desk is busy, or the packet could not be issued; the
/// order then stays open.
pub fn confirm_payment(dir: &Path, id: &str) -> Result<Sale, String> {
    let _lock = Lock::take(&Home(dir.to_path_buf()))?;
    let mut desk = Desk::open(dir)?;
    let at_index = desk
        .orders
        .iter()
        .position(|o| o.id == id)
        .ok_or_else(|| format!("no open order {id} at {}", dir.display()))?;
    let o = desk.orders[at_index].clone();
    let emission = desk.emission()?.clone();
    let signer = desk.signer()?;
    let mut ledger = desk.ledger()?;
    let holder = uri(&o.to)?;
    let prev = desk.last_closure(&ledger, &holder).cloned();
    let packet = ledger
        .allocate(
            &holder,
            prev.as_ref(),
            &signer,
            &KeySet::new(),
            packet_terms(o.class, o.size, o.days)?,
        )
        .map_err(e)?;
    // The document must pass what a buyer and a verifier will check.
    let emission_keys: KeySet = emission.keys.iter().cloned().collect();
    let (granted, _) =
        resolve(&emission, &desk.chain, &emission_keys, &Profile::default()).map_err(e)?;
    packet
        .validate(&emission, true, None, &granted, &Profile::default())
        .map_err(|x| format!("the packet: {x}"))?;
    let sale = Sale {
        doc_type: "Sale".into(),
        emission,
        chain: desk.chain.clone(),
        packet,
    };
    // Steps 3–5: paid by hand (the MVP's payment), the packet issued, and the
    // sale — the packet with its release and grants — handed to the buyer, all
    // in this one act. Recorded before the desk is saved, so the ledger and the
    // book cannot disagree about whether this packet exists.
    let at = now();
    let packet_hash = ksg_core_v2::canonical::doc_hash(&sale.packet).map_err(e)?;
    let sale_bytes = serde_json::to_vec(&sale).map_err(|x| x.to_string())?;
    for event in [
        Event::Paid {
            payment: format!("manual:{id}"),
        },
        Event::Issued {
            packet: packet_hash,
            serials: sale.packet.block,
            expires_at: sale.packet.expires_at.clone(),
        },
        Event::Delivered {
            template: ksg_core_v2::crypto::hash::Hash::sha256(&sale_bytes),
        },
    ] {
        desk.book
            .record(id, at.clone(), event)
            .map_err(|x| format!("order {id}: {x}"))?;
    }
    desk.ledger = Some(ledger.snapshot());
    desk.orders.remove(at_index);
    desk.save(dir)?;
    Ok(sale)
}

/// Cancels an order that is not paid for yet, with a reason. A paid order is
/// not cancelled: its serials are taken and end in closure or expiry.
///
/// # Errors
///
/// No such open order, the desk is busy, or the reason is empty.
pub fn cancel(dir: &Path, id: &str, reason: &str) -> Result<(), String> {
    let _lock = Lock::take(&Home(dir.to_path_buf()))?;
    let mut desk = Desk::open(dir)?;
    let at = desk
        .orders
        .iter()
        .position(|o| o.id == id)
        .ok_or_else(|| format!("no open order {id} at {}", dir.display()))?;
    desk.book
        .record(
            id,
            now(),
            Event::Cancelled {
                reason: reason.to_owned(),
            },
        )
        .map_err(|x| format!("order {id}: {x}"))?;
    desk.orders.remove(at);
    desk.save(dir)
}

/// Every order of the desk with its stage, oldest number first.
///
/// # Errors
///
/// The desk cannot be read.
pub fn orders(dir: &Path) -> Result<Vec<(String, Stage)>, String> {
    let desk = Desk::open(dir)?;
    let mut out: Vec<(String, Stage)> = desk
        .book
        .orders()
        .map(|o| (o.id.clone(), o.stage()))
        .collect();
    out.sort_by_key(|(id, _)| {
        id.strip_prefix("ord-")
            .and_then(|n| n.parse::<u64>().ok())
            .unwrap_or(u64::MAX)
    });
    Ok(out)
}

/// Marks every packet whose term has run out without closure as expired, and
/// returns their order numbers. Meant to run periodically; running it twice
/// changes nothing the second time.
///
/// # Errors
///
/// The desk is busy or cannot be read.
pub fn expire(dir: &Path) -> Result<Vec<String>, String> {
    let _lock = Lock::take(&Home(dir.to_path_buf()))?;
    let mut desk = Desk::open(dir)?;
    let at = now();
    let due: Vec<String> = desk.book.due_to_expire(&at).map(|o| o.id.clone()).collect();
    for id in &due {
        desk.book
            .record(id, at.clone(), Event::Expired)
            .map_err(|x| format!("order {id}: {x}"))?;
    }
    if !due.is_empty() {
        desk.save(dir)?;
    }
    Ok(due)
}

/// Accepts the holder's closure of the packet sold under order `id` — step 8
/// of `Mekhanizm_oplaty.md` §3: every serial accounted for, the packet closed.
///
/// The closure comes in the channel bundle the holder lays it into
/// (`ksg-remote-panel --home DIR close-packet`, then `channel --out FILE`). The bundle
/// must be of this order's packet, and only the key the packet was sold to
/// may sign the closure. Accepting the same closure twice changes nothing;
/// a different one for a closed packet is refused.
///
/// Returns the closure's hash and how many serials were used.
///
/// # Errors
///
/// No such order or no packet issued for it, a bundle of another packet or
/// without a closure, a closure not signed by the packet's holder or not
/// covering the packet, the order already ended, or the desk is busy.
pub fn close(dir: &Path, id: &str, proof: &ChannelProof) -> Result<(Hash, u64), String> {
    let _lock = Lock::take(&Home(dir.to_path_buf()))?;
    let mut desk = Desk::open(dir)?;
    let (packet, serials) = desk
        .book
        .get(id)
        .ok_or_else(|| format!("no order {id} at {}", dir.display()))?
        .issued_packet()
        .ok_or_else(|| format!("order {id}: no packet was issued for it"))?;
    if ksg_core_v2::canonical::doc_hash(&proof.packet).map_err(e)? != packet {
        return Err(format!(
            "the bundle is of another packet than order {id}'s ({}-{})",
            serials.from.0, serials.to.0
        ));
    }
    let closure = proof
        .closure
        .as_ref()
        .ok_or("the bundle has no closure: the holder runs `close-packet` first")?;
    // The key the seller signed into the packet, not whoever presents the
    // bundle — the same rule the channel check applies.
    let pinned = ksg_verify_v2::channel::holder_key(proof.packet.holder.as_str())
        .ok_or("the packet's holder names no key")?;
    let keys: KeySet = proof
        .holder_keys
        .iter()
        .filter(|k| k.alg == ksg_core_v2::crypto::sign::Alg::Ed25519 && k.key == pinned)
        .cloned()
        .collect();
    if keys.is_empty() {
        return Err("the bundle has not the key the packet was sold to".into());
    }
    let used = closure
        .used_submitted
        .iter()
        .chain(&closure.used_not_submitted)
        .map(Range::len)
        .sum::<u64>();
    let recorded = desk.book.get(id).and_then(|o| {
        o.events.iter().find_map(|(_, ev)| match ev {
            Event::Closed { closure, .. } => Some(*closure),
            _ => None,
        })
    });
    if let Some(h) = recorded {
        if h != ksg_core_v2::canonical::doc_hash(closure).map_err(e)? {
            return Err(format!("order {id} is closed by another closure"));
        }
        // A desk written before closures were kept takes the statement now,
        // so its holder can buy the next packet.
        if !desk.closures.contains(closure) {
            desk.closures.push(closure.clone());
            desk.save(dir)?;
        }
        return Ok((h, used));
    }
    let mut ledger = desk.ledger()?;
    let hash = ledger.accept_closure(closure, &keys).map_err(e)?;
    // Recorded before the desk is saved, as at payment: the ledger and the
    // book agree on whether this packet is closed.
    desk.book
        .record(
            id,
            now(),
            Event::Closed {
                closure: hash,
                used,
            },
        )
        .map_err(|x| format!("order {id}: {x}"))?;
    desk.ledger = Some(ledger.snapshot());
    desk.closures.push(closure.clone());
    desk.save(dir)?;
    Ok((hash, used))
}

/// A packet template: what the issuer hands the buyer instead of containers.
///
/// `[decision]` 19.09: a packet is a template with a quota — the issuer's key,
/// the buyer's key and a quota of serials; containers are made from it, as
/// many as there are clients, each on one serial of the quota
/// (`Moment_pokupki_i_ispolzovaniya.md` §1–3). The issuer issues it once per
/// packet (`ksg issuer template`); after that no container of the packet
/// needs the issuer's desk.
///
/// It carries the issuer's printing seed, as every container's parties file
/// does in the MVP: printing is the issuer's act, and the issuer lays its
/// secrets in at creation. It is a secret file (`0600`), and the prototype
/// signs only with public test keys (`crate::testkeys`). The template keeps
/// its own count of the serials printed from it: one serial, one container.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Template {
    /// Always `"Template"`.
    #[serde(rename = "type")]
    pub doc_type: String,
    /// The template format's version.
    pub v: u32,
    /// The packet as sold: the release, the grants, the packet.
    pub sale: Sale,
    /// The issuer's printing seed, base64url. Secret.
    pub issuer_seed: String,
    /// The serials of the quota a container was printed on.
    #[serde(default)]
    pub printed: Vec<u64>,
}

impl Drop for Template {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.issuer_seed.zeroize();
    }
}

impl Template {
    /// Reads a template file.
    ///
    /// # Errors
    ///
    /// Not readable, or not a template.
    pub fn open(path: &Path) -> Result<Self, String> {
        let t: Self = serde_json::from_slice(&Zeroizing::new(read(path)?))
            .map_err(|x| format!("{}: {x}", path.display()))?;
        if t.doc_type != "Template" || t.v != 1 {
            return Err(format!("{}: not a packet template", path.display()));
        }
        Ok(t)
    }

    fn save(&self, path: &Path) -> Result<(), String> {
        let bytes = Zeroizing::new(serde_json::to_vec_pretty(self).map_err(e)?);
        write_atomic(path, &bytes, true)
    }

    /// The serials of the quota no container was printed on yet.
    #[must_use]
    pub fn left(&self) -> u64 {
        let b = self.sale.packet.block;
        (b.to.0 - b.from.0 + 1).saturating_sub(self.printed.len() as u64)
    }

    /// The earliest serial of the quota not printed yet: initiation goes from
    /// the early serials of the quota (`Moment_pokupki_i_ispolzovaniya.md` §2).
    #[must_use]
    pub fn next_serial(&self) -> Option<u64> {
        let b = self.sale.packet.block;
        (b.from.0..=b.to.0).find(|s| !self.printed.contains(s))
    }
}

fn template_lock(path: &Path) -> Result<Lock, String> {
    let mut l = path.as_os_str().to_owned();
    l.push(".lock");
    Lock::at(PathBuf::from(l), path)
}

/// The issuer issues the template of the packet in `sale`, into `out`.
///
/// The packet's serials are reserved at the desk for the template: the desk
/// will not print them itself, so a serial goes out once whichever way it is
/// printed.
///
/// # Errors
///
/// Not the issuer's desk, a sale of another release or that does not check,
/// a packet already templated, or a serial of it already printed.
pub fn issue_template(dir: &Path, sale: Sale, out: &Path) -> Result<Template, String> {
    check_sale(&sale)?;
    let _lock = Lock::take(&Home(dir.to_path_buf()))?;
    let mut desk = Desk::open(dir)?;
    if desk.role != "issuer" {
        return Err(format!("{} is not the issuer's desk", dir.display()));
    }
    let emission = desk.emission()?;
    if emission.id != sale.emission.id || emission.keys != sale.emission.keys {
        return Err(format!(
            "{} did not issue release {}",
            dir.display(),
            sale.emission.id
        ));
    }
    let block = sale.packet.block;
    if desk
        .templated
        .iter()
        .any(|r| r.from.0 <= block.to.0 && block.from.0 <= r.to.0)
    {
        return Err("a template of this packet was issued already".into());
    }
    if desk
        .printed
        .iter()
        .any(|s| block.from.0 <= *s && *s <= block.to.0)
    {
        return Err("a serial of this packet was printed at the desk already".into());
    }
    let t = Template {
        doc_type: "Template".into(),
        v: 1,
        sale,
        issuer_seed: desk.seed.clone(),
        printed: Vec::new(),
    };
    if out.exists() {
        return Err(format!("{} exists", out.display()));
    }
    t.save(out)?;
    desk.templated.push(block);
    desk.save(dir)?;
    Ok(t)
}

enum Target {
    Desk(PathBuf),
    Template(PathBuf),
}

/// A print in progress: the desk or the template is locked, the serial is
/// known not to have been printed, and the issuer's seed is at hand.
///
/// Printing is the issuer's act (status record 0 is signed by the issuer's
/// key), and one serial makes one container. The desk remembers every serial
/// it printed, and a template every serial printed from it;
/// [`Printing::commit`] records this one.
pub struct Printing {
    target: Target,
    serial: u64,
    seed: Zeroizing<[u8; 32]>,
    _lock: Lock,
}

impl std::fmt::Debug for Printing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let at = match &self.target {
            Target::Desk(p) | Target::Template(p) => p,
        };
        f.debug_struct("Printing")
            .field("at", at)
            .field("serial", &self.serial)
            .finish_non_exhaustive()
    }
}

fn already(serial: u64, emission: &str) -> String {
    format!("serial {serial} of {emission} is printed already: one serial, one container")
}

/// Opens a print of `serial` of release `emission` at the issuer's desk `dir`.
///
/// # Errors
///
/// Not the issuer's desk, another print holds the desk, the desk issued
/// another release, the serial was printed already, or it belongs to a packet
/// the desk issued a template of.
pub fn begin_print(dir: &Path, emission: &str, serial: u64) -> Result<Printing, String> {
    let lock = Lock::take(&Home(dir.to_path_buf()))?;
    let desk = Desk::open(dir)?;
    if desk.role != "issuer" {
        return Err(format!("{} is not the issuer's desk", dir.display()));
    }
    if desk.emission()?.id != emission {
        return Err(format!(
            "{} did not issue release {emission}",
            dir.display()
        ));
    }
    if desk.printed.contains(&serial) {
        return Err(already(serial, emission));
    }
    if desk
        .templated
        .iter()
        .any(|r| r.from.0 <= serial && serial <= r.to.0)
    {
        return Err(format!(
            "serial {serial} belongs to a packet printed from its template"
        ));
    }
    Ok(Printing {
        target: Target::Desk(dir.to_path_buf()),
        serial,
        seed: desk.seed()?,
        _lock: lock,
    })
}

/// Opens a print of `serial` from the template at `path`.
///
/// # Errors
///
/// Another print holds the template, the serial is outside the quota or was
/// printed from it already.
pub fn begin_template_print(path: &Path, serial: u64) -> Result<Printing, String> {
    let lock = template_lock(path)?;
    let t = Template::open(path)?;
    let emission = &t.sale.emission.id;
    if !t.sale.packet.covers(Serial(serial)) {
        return Err(format!(
            "serial {serial} is not in the template's quota {}-{}",
            t.sale.packet.block.from.0, t.sale.packet.block.to.0
        ));
    }
    if t.printed.contains(&serial) {
        return Err(already(serial, emission));
    }
    let v = Zeroizing::new(
        B64.decode(&t.issuer_seed)
            .map_err(|_| "the template's issuer seed")?,
    );
    let seed: [u8; 32] = v
        .as_slice()
        .try_into()
        .map_err(|_| "the template's issuer seed")?;
    Ok(Printing {
        target: Target::Template(path.to_path_buf()),
        serial,
        seed: Zeroizing::new(seed),
        _lock: lock,
    })
}

impl Printing {
    /// The issuer's seed.
    #[must_use]
    pub fn seed(&self) -> &Zeroizing<[u8; 32]> {
        &self.seed
    }

    /// Records the serial as printed and releases the desk or the template.
    ///
    /// Called before the container's files are written: a failure after it
    /// leaves the serial spent and no container, never two containers.
    ///
    /// # Errors
    ///
    /// The desk or the template does not read or write.
    pub fn commit(self) -> Result<(), String> {
        match &self.target {
            Target::Desk(dir) => {
                let mut desk = Desk::open(dir)?;
                if desk.printed.contains(&self.serial) {
                    return Err(format!("serial {} is printed already", self.serial));
                }
                desk.printed.push(self.serial);
                desk.save(dir)
            }
            Target::Template(path) => {
                let mut t = Template::open(path)?;
                if t.printed.contains(&self.serial) {
                    return Err(format!("serial {} is printed already", self.serial));
                }
                t.printed.push(self.serial);
                t.save(path)
            }
        }
    }
}

/// Checks a sale as the buyer: the chain from the release to the packet.
///
/// # Errors
///
/// The first document that does not hold.
pub fn check_sale(sale: &Sale) -> Result<(), String> {
    let p = Profile::default();
    sale.emission
        .validate(&p)
        .map_err(|x| format!("release: {x}"))?;
    let keys: KeySet = sale.emission.keys.iter().cloned().collect();
    let (granted, range) =
        resolve(&sale.emission, &sale.chain, &keys, &p).map_err(|x| format!("the grants: {x}"))?;
    sale.packet
        .validate(&sale.emission, true, None, &granted, &p)
        .map_err(|x| format!("the packet: {x}"))?;
    if sale.packet.block.from < range.from || sale.packet.block.to > range.to {
        return Err("the packet: outside the range the grants give".into());
    }
    Ok(())
}

/// Parses `FROM-TO` as a range of serials.
///
/// # Errors
///
/// Not two numbers with a dash.
pub fn parse_range(s: &str) -> Result<Range, String> {
    let (a, b) = s.split_once('-').ok_or("a range is FROM-TO")?;
    let n = |x: &str| {
        x.trim()
            .parse::<u64>()
            .map(Serial)
            .map_err(|_| "a range is FROM-TO".to_string())
    };
    Ok(Range {
        from: n(a)?,
        to: n(b)?,
    })
}
