//! The layout of a container's fields. KS-8 part C, A-6, F-4.
//!
//! # What a layout is for
//!
//! Not for finding a field — a container is not read (KS-7 §8.1-ter). It is for
//! the one property that has to hold whatever is inside: **the size does not
//! say how full it is**.
//!
//! Every zone below has a **fixed** capacity, occupied from birth, under noise
//! until written (A-6: "the journal exists from birth under noise"; C-5: "a
//! hundred slots, noise until filled"). A container one page into its journal
//! and a container at its thousandth are the same size, and that is what stops
//! the size from being a side channel about the work.
//!
//! # The half this module does and the half it does not
//!
//! What is here is **structural**: capacities are constant, a slot occupies its
//! width whether written or not, and nothing in the API reports emptiness.
//!
//! What is **not** here is the cryptographic half — compress, pad to a constant
//! size, encrypt (plan §2.1 `pack.rs`, `noise.rs`, `layers.rs`). The
//! specification gives that order and not the detail, and noise that only looks
//! like noise is worse than none: it would make the property appear held while
//! an observer told written slots from unwritten ones at a glance. So the shape
//! is fixed here and the filling is left honestly undone.
//!
//! # Stages, and why a field cannot be written early
//!
//! Each zone is filled at a stage of the container's life (KS-8 C-1 … C-5), and
//! a field written out of order is refused rather than accepted-and-overwritten.
//! Not tidiness: the release layer is what the issuer signs, and a container
//! whose release layer could be filled later is a container whose earliest layer
//! is not evidence of anything.

use ksg_core_v2::status::Status;

/// A zone of the container, filled at one stage and fixed in size.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum Zone {
    /// **C-1**, the release layer: release id, position, the release's date and
    /// time, the class, the issuer's key. Filled by the issuer at status 0.
    Release,
    /// **C-2**, the packet layer: packet id and number, the moment of purchase,
    /// the buyer's opaque id, size, class, quota, the buyer's key over the
    /// issuer's. The same in every container of a packet.
    Packet,
    /// **C-3**, the chain positions: the ids of distributor, owner and agents as
    /// the container is handed on, then the client agent's id and the artifact's
    /// at initiation.
    Chain,
    /// **C-4**, the identity layer. Laid down together, encrypted differently:
    /// the identity id under the chain's last key, the identity itself under its
    /// own — which is why only it can open that one.
    Identity,
    /// **C-5**, the custom slots: a hundred places, noise until filled.
    Custom,
    /// **A-6**, the journal: a thousand pages, existing from birth under noise.
    Journal,
    /// The status section (KS-7 §7.3) — the one zone that is read as well as
    /// written.
    Status,
    /// The key section (KS-1): keys accumulate, none is ever replaced.
    Keys,
}

/// A hundred custom places (KS-8 C-5).
pub const CUSTOM_SLOTS: usize = 100;

/// A thousand journal pages (KS-8 A-6).
pub const JOURNAL_PAGES: usize = 1000;

impl Zone {
    /// How many slots the zone holds. Fixed, and occupied from birth.
    #[must_use]
    pub const fn slots(self) -> usize {
        match self {
            // The release layer's five fields (C-1) and the packet layer's
            // seven (C-2) are counted, not guessed: a zone whose width depended
            // on what was written would be the side channel this exists against.
            Self::Release => 5,
            Self::Packet => 7,
            // Four intermediary levels plus the client agent and the artifact
            // (KS-7 §7.2-sexies gives the depth; C-3 gives the last two).
            Self::Chain => 6,
            // The identity id and the identity (C-4).
            Self::Identity => 2,
            Self::Custom => CUSTOM_SLOTS,
            Self::Journal => JOURNAL_PAGES,
            // Statuses accumulate; the section is sized for the whole numbered
            // space so that a container cannot run out of room to record what
            // happened to it.
            Self::Status => 36,
            // A key chain of five parties plus the client's own (KS-1, and the
            // channel depth again).
            Self::Keys => 6,
        }
    }

    /// The earliest status at which the zone may be written.
    ///
    /// A field offered before it is refused. The release layer is what the
    /// issuer signs; a container whose release layer could be filled later is a
    /// container whose earliest layer proves nothing.
    #[must_use]
    pub const fn opens_at(self) -> Status {
        match self {
            Self::Release | Self::Status => Status::Printed,
            Self::Packet => Status::Packeted,
            // The chain's positions start with the buyer's key and go on being
            // added to as the container is handed along.
            Self::Chain | Self::Keys => Status::BuyerKeyed,
            // Identity and the custom slots belong to a container that exists.
            Self::Identity | Self::Custom => Status::Initiated,
            // The journal's space exists from birth; its first page is written
            // when the journal opens, which is what makes the container working.
            Self::Journal => Status::Initiated,
        }
    }

    /// Every zone, for the sweeps.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Release,
            Self::Packet,
            Self::Chain,
            Self::Identity,
            Self::Custom,
            Self::Journal,
            Self::Status,
            Self::Keys,
        ]
    }
}

/// The container's shape: every zone, at its fixed width.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout;

impl Layout {
    /// Total slots, across every zone. **A constant**, and that is the point.
    #[must_use]
    pub fn slots() -> usize {
        Zone::all().iter().map(|z| z.slots()).sum()
    }

    /// Whether a zone may be written at this status.
    ///
    /// The check is one-sided on purpose: it says when a zone **opens**, never
    /// when it closes. Closing is finalization's business (E-13), and it closes
    /// the container rather than a zone — a rule per zone would be a second
    /// place for "no more additions" to live, and two places for one rule
    /// disagree.
    #[must_use]
    pub fn may_write(zone: Zone, at: Status) -> bool {
        if at.is_terminal() || at == Status::Finalized {
            return false;
        }
        at.number() >= zone.opens_at().number()
    }
}

/// What a slot holds.
///
/// The two states are distinguishable **here**, inside an implementation that
/// already has the container open. They must not be distinguishable to an
/// observer of the stored bytes, and making that true is the packing layer's
/// job — see the module documentation for why it is not faked here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Slot {
    /// Never written. Reads as noise from outside.
    Noise,
    /// Written once.
    Filled(Vec<u8>),
}

impl Slot {
    /// Writes into a slot.
    ///
    /// # Errors
    ///
    /// [`LayoutError::AlreadyWritten`] — a slot is written once. A container
    /// whose fields could be rewritten would make every layer under it a claim
    /// about the present rather than a record of the past.
    pub fn write(&mut self, bytes: Vec<u8>) -> Result<(), LayoutError> {
        match self {
            Self::Noise => {
                *self = Self::Filled(bytes);
                Ok(())
            }
            Self::Filled(_) => Err(LayoutError::AlreadyWritten),
        }
    }
}

/// What can go wrong when writing a field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LayoutError {
    /// The slot already holds something.
    #[error("the slot is written; a field is written once")]
    AlreadyWritten,
    /// The zone is not open at this status.
    #[error("{zone:?} does not open before status {opens_at}")]
    TooEarly {
        /// The zone offered.
        zone: Zone,
        /// When it opens.
        opens_at: u8,
    },
    /// The container takes no more additions.
    #[error("the container takes no additions at status {0}")]
    Closed(u8),
    /// There is no such slot in the zone.
    #[error("{zone:?} has {slots} slots and slot {asked} was asked for")]
    NoSuchSlot {
        /// The zone offered.
        zone: Zone,
        /// How many it has.
        slots: usize,
        /// Which was asked for.
        asked: usize,
    },
}

/// A container's fields, laid out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fields {
    zones: Vec<(Zone, Vec<Slot>)>,
}

impl Default for Fields {
    fn default() -> Self {
        Self::new()
    }
}

impl Fields {
    /// A fresh container: every slot present, every slot noise.
    #[must_use]
    pub fn new() -> Self {
        Self {
            zones: Zone::all()
                .iter()
                .map(|z| (*z, vec![Slot::Noise; z.slots()]))
                .collect(),
        }
    }

    /// Writes a field.
    ///
    /// # Errors
    ///
    /// [`LayoutError`] naming which rule refused.
    pub fn write(
        &mut self,
        zone: Zone,
        slot: usize,
        at: Status,
        bytes: Vec<u8>,
    ) -> Result<(), LayoutError> {
        if at.is_terminal() || at == Status::Finalized {
            return Err(LayoutError::Closed(at.number()));
        }
        if !Layout::may_write(zone, at) {
            return Err(LayoutError::TooEarly {
                zone,
                opens_at: zone.opens_at().number(),
            });
        }
        let slots = zone.slots();
        let cell = self
            .zone_mut(zone)
            .get_mut(slot)
            .ok_or(LayoutError::NoSuchSlot {
                zone,
                slots,
                asked: slot,
            })?;
        cell.write(bytes)
    }

    /// How many slots there are in total. **Does not change as fields are
    /// written** — the whole reason this type is shaped this way.
    #[must_use]
    pub fn slots(&self) -> usize {
        self.zones.iter().map(|(_, s)| s.len()).sum()
    }

    fn zone_mut(&mut self, zone: Zone) -> &mut Vec<Slot> {
        &mut self
            .zones
            .iter_mut()
            .find(|(z, _)| *z == zone)
            .expect("every zone is present from birth")
            .1
    }
}

// ---------------------------------------------------------------------------
// The layers written zone by zone (owner's decision 18.10 "A").
// ---------------------------------------------------------------------------

/// The width of a sealed zone in bytes: nonce, ciphertext and tag together.
/// Constant whatever the fields hold, and the same for a zone never written —
/// then it is noise of this width.
///
/// 640: the packet's fields take 417 bytes (a sale through the channel), and
/// a hundred and six zones of 640 fit the store with the journal full
/// (`tests/store.rs`, `a_full_journal_fits_the_store`); of 1024 they do not.
pub const ZONE_BYTES: usize = 640;

/// The zones written under their own level's key (E-1, E-2, E-9): the
/// release layer, the packet layer and the chain's positions.
pub const SEALED_ZONES: [Zone; 3] = [Zone::Release, Zone::Packet, Zone::Chain];

/// Positions of the chain zone (owner's decision 18.10: a hundred, after CH-15's
/// hundred pages of sales and transfers, and four more): every change of owner
/// of a Pro or `light` container writes one.
pub const CHAIN_POSITIONS: usize = 104;

/// Positions of the sealed zones in a container: the release, the packet,
/// then the chain's.
pub const ZONE_POSITIONS: usize = 2 + CHAIN_POSITIONS;

const NONCE: usize = 12;
const TAG: usize = 16;
/// What the fields may take inside a sealed zone: its width less the nonce,
/// the tag and the two bytes of the fields' length.
pub const ZONE_ROOM: usize = ZONE_BYTES - NONCE - TAG - 2;

/// The position of the `nth` write of `zone` (the chain's are counted).
///
/// # Errors
///
/// [`LayoutError::NoSuchSlot`] for a zone not written this way, or a chain
/// position past [`CHAIN_POSITIONS`].
pub const fn zone_position(zone: Zone, nth: usize) -> Result<usize, LayoutError> {
    match zone {
        Zone::Release if nth == 0 => Ok(0),
        Zone::Packet if nth == 0 => Ok(1),
        Zone::Chain if nth < CHAIN_POSITIONS => Ok(2 + nth),
        _ => Err(LayoutError::NoSuchSlot {
            zone,
            slots: zone.slots(),
            asked: nth,
        }),
    }
}

fn zone_aad(container: &[u8], position: usize) -> Vec<u8> {
    let mut a = b"ksg:zone:v1".to_vec();
    a.extend_from_slice(container);
    a.extend_from_slice(&(position as u32).to_be_bytes());
    a
}

/// What went wrong sealing or opening a zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ZoneError {
    /// The fields do not fit the zone.
    #[error("the fields take {0} bytes and a zone holds {ZONE_ROOM}")]
    TooLarge(usize),
    /// The randomness given is not the width asked for.
    #[error("the randomness is not the width asked for")]
    Randomness,
    /// Not this zone's key, not this zone, or tampered.
    #[error("the zone does not open with this key")]
    Sealed,
}

/// Seals a zone's fields under its level's key: `nonce ‖ ciphertext ‖ tag`,
/// exactly [`ZONE_BYTES`] long. The fields are padded inside the encryption
/// with `random`'s bytes, so the width says nothing about their length.
/// `random` is [`ZONE_BYTES`] fresh bytes from a CSPRNG: the nonce and the
/// padding.
///
/// # Errors
///
/// [`ZoneError::TooLarge`], [`ZoneError::Randomness`].
pub fn seal_zone(
    key: &crate::layers::LayerKey,
    container: &[u8],
    position: usize,
    fields: &[u8],
    random: &[u8],
) -> Result<Vec<u8>, ZoneError> {
    use crate::pack::Aead as _;
    if fields.len() > ZONE_ROOM {
        return Err(ZoneError::TooLarge(fields.len()));
    }
    if random.len() != ZONE_BYTES {
        return Err(ZoneError::Randomness);
    }
    let nonce = &random[..NONCE];
    let mut plain = zeroize::Zeroizing::new(Vec::with_capacity(ZONE_BYTES - NONCE - TAG));
    plain.extend_from_slice(&(fields.len() as u16).to_be_bytes());
    plain.extend_from_slice(fields);
    plain.extend_from_slice(&random[NONCE..NONCE + (ZONE_ROOM - fields.len())]);
    let ct = crate::pack::ChaCha20Poly1305Aead
        .seal(
            key.as_bytes(),
            nonce,
            &zone_aad(container, position),
            &plain,
        )
        .map_err(|_| ZoneError::Sealed)?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ct);
    debug_assert_eq!(out.len(), ZONE_BYTES);
    Ok(out)
}

/// Opens a sealed zone with its level's key.
///
/// # Errors
///
/// [`ZoneError::Sealed`]: another key (a lower level's among them), another
/// zone or container, noise, or tampering.
pub fn open_zone(
    key: &crate::layers::LayerKey,
    container: &[u8],
    position: usize,
    sealed: &[u8],
) -> Result<Vec<u8>, ZoneError> {
    use crate::pack::Aead as _;
    if sealed.len() != ZONE_BYTES {
        return Err(ZoneError::Sealed);
    }
    let plain = zeroize::Zeroizing::new(
        crate::pack::ChaCha20Poly1305Aead
            .open(
                key.as_bytes(),
                &sealed[..NONCE],
                &zone_aad(container, position),
                &sealed[NONCE..],
            )
            .map_err(|_| ZoneError::Sealed)?,
    );
    let len = usize::from(u16::from_be_bytes([plain[0], plain[1]]));
    plain
        .get(2..2 + len)
        .map(<[u8]>::to_vec)
        .ok_or(ZoneError::Sealed)
}
