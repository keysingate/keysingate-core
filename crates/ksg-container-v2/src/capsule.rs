//! The capsule: the sealed form of a container. `[doc:CAPSULE-SPEC]`
//! §3, §10 item 2, §11 (owner's decisions 25.10: "a file of noise, the layout
//! known only to the map"; variant B — a client's map and an owner's map; one
//! secret file per party).
//!
//! # The one property
//!
//! **Outside, the capsule is noise.** A fixed number of fixed-size blocks; no
//! magic, no lengths, no version in clear. Each part — the container's code,
//! its state, its secrets — is `nonce ‖ AEAD` under a data key of its own,
//! placed in blocks chosen by a permutation whose seed only a map's slot holds.
//!
//! # Maps and slots
//!
//! A map is a party's key pair — the same X25519 + ML-KEM-768 hybrid a layer
//! hand-over is sealed to (`crate::layers::SealTo`, `OpenWith`). A slot is
//! sealed to the map's **public** half, so whoever re-assembles the capsule
//! re-seals the other party's slot without its secret. The slot's block is
//! derived from the public half; a collision moves the later map one block on.
//!
//! # What is not hidden
//!
//! A slot's first 32 bytes are an X25519 public key, which is not uniform (its
//! top bit is clear): one block in 1 536 carries a one-bit bias. Elligator
//! encoding would remove it; the frequency and runs tests do not see it.

use crate::layers::{OpenWith, SealTo};

/// One block, bytes.
pub const BLOCK: usize = 4 * 1024;

/// Blocks in a capsule: 6 MiB (`Spec_kapsula` §11, K-2).
pub const BLOCKS: usize = 1536;

/// A capsule's size, bytes — the same for every capsule.
pub const CAPSULE_SIZE: usize = BLOCK * BLOCKS;

/// What a part of the capsule holds (`Spec_kapsula` §3, §10 item 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PartKind {
    /// The container's code (the WASM module).
    Code,
    /// The container's state: the journal and the rest, compressed.
    State,
    /// Secrets of the client's map only: the container's half of the client's key,
    /// the issuer's seal seed.
    ClientSecrets,
    /// Secrets of the owner's map only: the former client's half (`bare`).
    OwnerSecrets,
    /// Secrets both maps open: the container's post-quantum key.
    SharedSecrets,
}

/// Which map a slot belongs to, in the fixed order of slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MapRole {
    /// Before initiation: the current holder's layer.
    Holder,
    /// The client's map.
    Client,
    /// The owner's map.
    Owner,
}

impl MapRole {
    /// The parts this map's slot opens.
    #[must_use]
    pub const fn opens(self) -> &'static [PartKind] {
        use PartKind::{ClientSecrets, Code, OwnerSecrets, SharedSecrets, State};
        match self {
            Self::Holder => &[Code, State, ClientSecrets, OwnerSecrets, SharedSecrets],
            Self::Client => &[Code, State, ClientSecrets, SharedSecrets],
            Self::Owner => &[Code, State, OwnerSecrets, SharedSecrets],
        }
    }
}

/// A part in clear, before assembly or after opening.
#[derive(Clone, PartialEq, Eq)]
pub struct Part {
    /// What it is.
    pub kind: PartKind,
    /// Its bytes.
    pub bytes: Vec<u8>,
}

impl core::fmt::Debug for Part {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Part")
            .field("kind", &self.kind)
            .field("len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

/// Why a capsule did not assemble or open.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CapsuleError {
    /// The parts do not fit the capsule's blocks.
    #[error("the parts do not fit the capsule: {need} blocks needed, {room} free")]
    TooLarge {
        /// Blocks the parts need.
        need: usize,
        /// Blocks free after the slots.
        room: usize,
    },
    /// No slot of this map opened: not this capsule, or not this map.
    #[error("no slot of this map opens in this capsule")]
    NoSlot,
    /// A part failed its AEAD check: tampered, or a wrong key.
    #[error("a part of the capsule does not open")]
    Tampered,
    /// Bytes of another size are not a capsule.
    #[error("not a capsule: {0} bytes")]
    WrongSize(usize),
}

/// Most maps a capsule carries: the holder's before initiation, or the
/// client's and the owner's after. Bounds the reader's probing.
pub const MAX_MAPS: usize = 3;

/// The `SharedSecrets` part: what both maps must read to carry the capsule on.
///
/// Public because the reader seals the first capsule (`init`) before any
/// session opens it, and the module reads it back (`Spec_kapsula` §10 item 3).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Shared {
    /// Version of this layout.
    pub v: u32,
    /// The key the container's state is sealed under, base64url (32 bytes).
    pub state_key: String,
    /// The container's template identifier, as a multihash.
    pub template: String,
    /// The artefact the container was initiated on.
    pub artifact: String,
    /// The client's key identifier, for the birth (E-4).
    pub client: String,
    /// The wall clock of the issuance, milliseconds since the Unix epoch:
    /// the offsets in the journal run from it.
    pub issued_ms: u64,
    /// The greatest offset already used: offsets grow strictly, even when the
    /// wall clock does not.
    pub clock_ms: u64,
    /// Every map the capsule seals to, in slot order (§10 item 2).
    pub maps: Vec<MapPub>,
}

/// One map's public halves, enough to re-seal its slot.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MapPub {
    /// `holder`, `client` or `owner`.
    pub role: String,
    /// The X25519 public half, base64url (32 bytes).
    pub x25519: String,
    /// The ML-KEM-768 encapsulation key, base64url.
    pub mlkem: String,
}

/// Seals a container's state into a capsule: the shared secrets part, the
/// code, the state, and the parts the map does not rewrite.
///
/// This is the one place a capsule is built — the reader's `init` (no session
/// yet), and a session's close (`Spec_kapsula` §10 item 3, §4).
///
/// # Errors
///
/// [`CapsuleError::TooLarge`], [`CapsuleError::NoSlot`], or a sealing failure.
#[allow(clippy::too_many_arguments)]
pub fn seal_into_capsule(
    state: &[u8],
    state_key: &[u8; 32],
    template: &str,
    artifact: &str,
    client: &str,
    issued_ms: u64,
    clock_ms: u64,
    code: &[u8],
    parts: &[Part],
    maps: &[(MapRole, SealTo)],
    random: &mut dyn FnMut(&mut [u8]),
) -> Result<Vec<u8>, CapsuleError> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use base64::Engine as _;
    let shared = Shared {
        v: 1,
        state_key: B64.encode(state_key),
        template: template.to_string(),
        artifact: artifact.to_string(),
        client: client.to_string(),
        issued_ms,
        clock_ms,
        maps: maps
            .iter()
            .map(|(role, map)| MapPub {
                role: role_name(*role).to_string(),
                x25519: B64.encode(map.public().as_bytes()),
                mlkem: B64.encode(map.mlkem()),
            })
            .collect(),
    };
    let shared = serde_json::to_vec(&shared).map_err(|_| CapsuleError::Tampered)?;
    let mut all = parts.to_vec();
    all.push(Part {
        kind: PartKind::Code,
        bytes: code.to_vec(),
    });
    all.push(Part {
        kind: PartKind::State,
        bytes: state.to_vec(),
    });
    all.push(Part {
        kind: PartKind::SharedSecrets,
        bytes: shared,
    });
    assemble(&all, maps, random)
}

/// A map's role, as [`Shared`] spells it.
#[must_use]
pub const fn role_name(role: MapRole) -> &'static str {
    match role {
        MapRole::Holder => "holder",
        MapRole::Client => "client",
        MapRole::Owner => "owner",
    }
}

const SLOT_INFO: &[u8] = b"ksg:capsule:slot:v1";
const SLOT_AAD: &[u8] = b"ksg:capsule:slot-payload:v1";
const PART_AAD: &[u8] = b"ksg:capsule:part:v1";
const PERM_INFO: &[u8] = b"ksg:capsule:perm:v1";
const KINDS: [PartKind; 5] = [
    PartKind::Code,
    PartKind::State,
    PartKind::ClientSecrets,
    PartKind::OwnerSecrets,
    PartKind::SharedSecrets,
];
/// A hand-over as it lies in a slot: ephemeral ‖ ML-KEM ciphertext ‖ nonce ‖
/// one wrapped key (level byte + 32 + tag 16).
const HANDOVER_LEN: usize = 32 + crate::layers::MLKEM_CT_LEN + 12 + 33 + 16;
const NONCE: usize = 12;
const TAG: usize = 16;

impl PartKind {
    const fn index(self) -> usize {
        match self {
            Self::Code => 0,
            Self::State => 1,
            Self::ClientSecrets => 2,
            Self::OwnerSecrets => 3,
            Self::SharedSecrets => 4,
        }
    }
}

impl MapRole {
    const fn byte(self) -> u8 {
        match self {
            Self::Holder => 0,
            Self::Client => 1,
            Self::Owner => 2,
        }
    }
    const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Holder),
            1 => Some(Self::Client),
            2 => Some(Self::Owner),
            _ => None,
        }
    }
    fn may_open(self, kind: PartKind) -> bool {
        self.opens().contains(&kind)
    }
}

fn hkdf(ikm: &[u8], info: &[u8], out: &mut [u8]) {
    hkdf::Hkdf::<sha2::Sha256>::new(None, ikm)
        .expand(info, out)
        .expect("short outputs are within HKDF-SHA256's range");
}

/// The block a map's slot starts from: derived from the map's public half
/// (`Spec_kapsula` §10 item 2.2). A collision with an earlier map moves on.
#[must_use]
pub fn slot_start(map: &SealTo) -> usize {
    let mut ikm = Vec::with_capacity(32 + crate::layers::MLKEM_EK_LEN);
    ikm.extend_from_slice(map.public().as_bytes());
    ikm.extend_from_slice(map.mlkem());
    let mut out = [0u8; 8];
    hkdf(&ikm, SLOT_INFO, &mut out);
    (u64::from_be_bytes(out) % BLOCKS as u64) as usize
}

/// The blocks a part takes: its sealed length rounded up to blocks.
const fn blocks_for(len: usize) -> usize {
    (len + NONCE + TAG).div_ceil(BLOCK)
}

/// The order the free blocks are used in: a Fisher–Yates shuffle driven by
/// HKDF of the slot's seed. Same seed, same order — on every side.
fn permutation(seed: &[u8; 32], taken: &[usize]) -> Vec<usize> {
    let mut free: Vec<usize> = (0..BLOCKS).filter(|b| !taken.contains(b)).collect();
    let mut stream = vec![0u8; free.len() * 8];
    for (i, chunk) in stream.chunks_mut(32 * 8).enumerate() {
        let mut info = PERM_INFO.to_vec();
        info.extend_from_slice(&(i as u64).to_be_bytes());
        hkdf(seed, &info, chunk);
    }
    for i in (1..free.len()).rev() {
        let r = u64::from_be_bytes(stream[i * 8..i * 8 + 8].try_into().expect("8 bytes"));
        let j = (r % (i as u64 + 1)) as usize;
        free.swap(i, j);
    }
    free
}

/// Where each part lies: blocks in permutation order, parts in kind order.
fn layout(seed: &[u8; 32], taken: &[usize], lens: &[u32; 5]) -> Result<[Vec<usize>; 5], CapsuleError> {
    let order = permutation(seed, taken);
    let need: usize = lens.iter().map(|l| blocks_for(*l as usize)).sum();
    if need > order.len() {
        return Err(CapsuleError::TooLarge { need, room: order.len() });
    }
    let mut at = 0;
    let mut out: [Vec<usize>; 5] = Default::default();
    for (i, l) in lens.iter().enumerate() {
        let n = blocks_for(*l as usize);
        out[i] = order[at..at + n].to_vec();
        at += n;
    }
    Ok(out)
}

fn write_scattered(capsule: &mut [u8], blocks: &[usize], bytes: &[u8]) {
    for (chunk, b) in bytes.chunks(BLOCK).zip(blocks) {
        capsule[b * BLOCK..b * BLOCK + chunk.len()].copy_from_slice(chunk);
    }
}

fn read_scattered(capsule: &[u8], blocks: &[usize], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    for b in blocks {
        let take = (len - out.len()).min(BLOCK);
        out.extend_from_slice(&capsule[b * BLOCK..b * BLOCK + take]);
    }
    out
}

/// What a slot carries, in clear inside its AEAD.
struct Payload {
    role: MapRole,
    seed: [u8; 32],
    lens: [u32; 5],
    /// Every slot's block: the layout is built around all of them, and the
    /// opening map cannot compute the others' (it lacks their public halves).
    taken: Vec<usize>,
    keys: Vec<(PartKind, zeroize::Zeroizing<[u8; 32]>)>,
}

impl Payload {
    fn to_bytes(&self) -> zeroize::Zeroizing<Vec<u8>> {
        let mut v = zeroize::Zeroizing::new(Vec::with_capacity(1 + 32 + 20 + 1 + 33 * 5));
        v.push(self.role.byte());
        v.extend_from_slice(&self.seed);
        for l in self.lens {
            v.extend_from_slice(&l.to_be_bytes());
        }
        v.push(u8::try_from(self.taken.len()).expect("three maps at most"));
        for b in &self.taken {
            v.extend_from_slice(&u16::try_from(*b).expect("blocks fit u16").to_be_bytes());
        }
        v.push(u8::try_from(self.keys.len()).expect("five kinds at most"));
        for (k, key) in &self.keys {
            v.push(u8::try_from(k.index()).expect("five kinds"));
            v.extend_from_slice(key.as_ref());
        }
        v
    }

    fn from_bytes(v: &[u8]) -> Option<Self> {
        let role = MapRole::from_byte(*v.first()?)?;
        let seed: [u8; 32] = v.get(1..33)?.try_into().ok()?;
        let mut lens = [0u32; 5];
        for (i, l) in lens.iter_mut().enumerate() {
            *l = u32::from_be_bytes(v.get(33 + i * 4..37 + i * 4)?.try_into().ok()?);
        }
        let slots = usize::from(*v.get(53)?);
        if slots == 0 || slots > MAX_MAPS {
            return None;
        }
        let mut taken = Vec::with_capacity(slots);
        for i in 0..slots {
            let b = usize::from(u16::from_be_bytes(v.get(54 + i * 2..56 + i * 2)?.try_into().ok()?));
            if b >= BLOCKS {
                return None;
            }
            taken.push(b);
        }
        let base = 54 + slots * 2;
        let n = usize::from(*v.get(base)?);
        let mut keys = Vec::with_capacity(n);
        for i in 0..n {
            let at = base + 1 + i * 33;
            let kind = *KINDS.get(usize::from(*v.get(at)?))?;
            let key: [u8; 32] = v.get(at + 1..at + 33)?.try_into().ok()?;
            keys.push((kind, zeroize::Zeroizing::new(key)));
        }
        Some(Self { role, seed, lens, taken, keys })
    }
}

fn seal_slot(
    payload: &Payload,
    to: &SealTo,
    random: &mut dyn FnMut(&mut [u8]),
) -> Result<Vec<u8>, CapsuleError> {
    use crate::layers::{hand_over, Held, LayerKey};
    use crate::pack::{Aead as _, ChaCha20Poly1305Aead};
    let mut slot_key = zeroize::Zeroizing::new([0u8; 32]);
    random(slot_key.as_mut());
    let mut eph = [0u8; 32];
    random(&mut eph);
    let h = hand_over(
        &ChaCha20Poly1305Aead,
        &Held::first(LayerKey::from_bytes(*slot_key)),
        to,
        eph,
        SLOT_AAD,
    )
    .map_err(|_| CapsuleError::Tampered)?;
    let mut nonce = [0u8; NONCE];
    random(&mut nonce);
    let sealed = ChaCha20Poly1305Aead
        .seal(slot_key.as_ref(), &nonce, SLOT_AAD, &payload.to_bytes())
        .map_err(|_| CapsuleError::Tampered)?;
    let mut out = Vec::with_capacity(BLOCK);
    out.extend_from_slice(&h.ephemeral);
    out.extend_from_slice(&h.kem);
    out.extend_from_slice(&h.nonce);
    out.extend_from_slice(&h.sealed);
    debug_assert_eq!(out.len(), HANDOVER_LEN);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&u16::try_from(sealed.len()).expect("a slot fits a block").to_be_bytes());
    out.extend_from_slice(&sealed);
    if out.len() > BLOCK {
        return Err(CapsuleError::TooLarge { need: 2, room: 1 });
    }
    Ok(out)
}

fn open_slot(block: &[u8], with: &OpenWith) -> Option<Payload> {
    use crate::layers::{receive, Handover, LayerKey, Level};
    use crate::pack::{Aead as _, ChaCha20Poly1305Aead};
    let k = crate::layers::MLKEM_CT_LEN;
    let h = Handover {
        ephemeral: block.get(0..32)?.try_into().ok()?,
        kem: block.get(32..32 + k)?.to_vec(),
        nonce: block.get(32 + k..44 + k)?.try_into().ok()?,
        sealed: block.get(44 + k..HANDOVER_LEN)?.to_vec(),
        up_to: Level(0),
    };
    let held = receive(&ChaCha20Poly1305Aead, &h, with, LayerKey::from_bytes([0; 32]), SLOT_AAD).ok()?;
    let slot_key = held.key(Level(0))?;
    let nonce = block.get(HANDOVER_LEN..HANDOVER_LEN + NONCE)?;
    let len_at = HANDOVER_LEN + NONCE;
    let len = usize::from(u16::from_be_bytes(block.get(len_at..len_at + 2)?.try_into().ok()?));
    let sealed = block.get(len_at + 2..len_at + 2 + len)?;
    let plain = zeroize::Zeroizing::new(
        ChaCha20Poly1305Aead
            .open(slot_key.as_bytes(), nonce, SLOT_AAD, sealed)
            .ok()?,
    );
    Payload::from_bytes(&plain)
}

/// The blocks the slots take, in map order, collisions moved on.
fn slot_blocks(maps: &[&SealTo]) -> Vec<usize> {
    let mut taken = Vec::with_capacity(maps.len());
    for m in maps {
        let mut b = slot_start(m);
        while taken.contains(&b) {
            b = (b + 1) % BLOCKS;
        }
        taken.push(b);
    }
    taken
}

/// Assembles a capsule from parts, sealing one slot to each map.
///
/// `random` supplies every random byte (nonces, data keys, the permutation
/// seed, the noise): the caller's CSPRNG, as everywhere in this crate.
///
/// # Errors
///
/// [`CapsuleError::TooLarge`]; [`CapsuleError::Tampered`] if sealing fails.
pub fn assemble(
    parts: &[Part],
    maps: &[(MapRole, SealTo)],
    random: &mut dyn FnMut(&mut [u8]),
) -> Result<Vec<u8>, CapsuleError> {
    use crate::pack::{Aead as _, ChaCha20Poly1305Aead};
    if maps.is_empty() || maps.len() > MAX_MAPS {
        return Err(CapsuleError::NoSlot);
    }
    let mut capsule = vec![0u8; CAPSULE_SIZE];
    random(&mut capsule);
    let mut lens = [0u32; 5];
    let mut plain: [&[u8]; 5] = [&[]; 5];
    for p in parts {
        let i = p.kind.index();
        lens[i] = u32::try_from(p.bytes.len()).map_err(|_| CapsuleError::TooLarge { need: BLOCKS + 1, room: BLOCKS })?;
        plain[i] = &p.bytes;
    }
    let taken = slot_blocks(&maps.iter().map(|(_, m)| m).collect::<Vec<_>>());
    let mut seed = [0u8; 32];
    random(&mut seed);
    let where_ = layout(&seed, &taken, &lens)?;
    let mut keys: Vec<zeroize::Zeroizing<[u8; 32]>> = Vec::with_capacity(5);
    for i in 0..5 {
        let mut key = zeroize::Zeroizing::new([0u8; 32]);
        random(key.as_mut());
        let mut nonce = [0u8; NONCE];
        random(&mut nonce);
        let mut aad = PART_AAD.to_vec();
        aad.push(u8::try_from(i).expect("five kinds"));
        let sealed = ChaCha20Poly1305Aead
            .seal(key.as_ref(), &nonce, &aad, plain[i])
            .map_err(|_| CapsuleError::Tampered)?;
        let mut bytes = nonce.to_vec();
        bytes.extend_from_slice(&sealed);
        write_scattered(&mut capsule, &where_[i], &bytes);
        keys.push(key);
    }
    for ((role, map), block) in maps.iter().zip(&taken) {
        let payload = Payload {
            role: *role,
            seed,
            lens,
            taken: taken.clone(),
            keys: KINDS
                .iter()
                .filter(|k| role.may_open(**k))
                .map(|k| (*k, keys[k.index()].clone()))
                .collect(),
        };
        let slot = seal_slot(&payload, map, random)?;
        capsule[block * BLOCK..block * BLOCK + slot.len()].copy_from_slice(&slot);
    }
    Ok(capsule)
}

/// Opens the parts a map is entitled to.
///
/// # Errors
///
/// [`CapsuleError::WrongSize`], [`CapsuleError::NoSlot`],
/// [`CapsuleError::Tampered`].
pub fn open(capsule: &[u8], map: &OpenWith) -> Result<(MapRole, Vec<Part>), CapsuleError> {
    use crate::pack::{Aead as _, ChaCha20Poly1305Aead};
    if capsule.len() != CAPSULE_SIZE {
        return Err(CapsuleError::WrongSize(capsule.len()));
    }
    let start = slot_start(&map.seal_to());
    let payload = (0..MAX_MAPS)
        .map(|i| (start + i) % BLOCKS)
        .find_map(|b| open_slot(&capsule[b * BLOCK..(b + 1) * BLOCK], map))
        .ok_or(CapsuleError::NoSlot)?;
    let lens = payload.lens;
    let where_ = layout(&payload.seed, &payload.taken, &lens)?;
    let mut parts = Vec::with_capacity(payload.keys.len());
    for (kind, key) in &payload.keys {
        let i = kind.index();
        let len = lens[i] as usize + NONCE + TAG;
        let bytes = read_scattered(capsule, &where_[i], len);
        let mut aad = PART_AAD.to_vec();
        aad.push(u8::try_from(i).expect("five kinds"));
        let plain = ChaCha20Poly1305Aead
            .open(key.as_ref(), &bytes[..NONCE], &aad, &bytes[NONCE..])
            .map_err(|_| CapsuleError::Tampered)?;
        parts.push(Part { kind: *kind, bytes: plain });
    }
    Ok((payload.role, parts))
}
