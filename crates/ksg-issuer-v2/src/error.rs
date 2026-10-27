//! Issuer errors.
//!
//! Kept separate from [`ksg_core_v2::error::Invalid`] for the same reason as the
//! log's errors: `Invalid` means "the document breaks a protocol rule", whereas
//! these mean "a block cannot be allocated right now". A holder who got "invalid
//! document" instead of "the previous block is 40% drawn down" would be fixing
//! the wrong thing.

/// The issuer's refusal to allocate a block or accept a closure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssuerError {
    /// The emission's range is exhausted.
    RangeExhausted {
        /// The last serial allocated.
        last: u64,
        /// The emission's upper bound.
        limit: u64,
    },
    /// The previous block is drawn down by less than 80% (§7 rule 2).
    ///
    /// Not a holder's error but a refusal to allocate ahead of need: blocks
    /// handed out in advance sit unused until they expire and occupy serials for
    /// which the absence of gaps can then never be proved.
    DrawdownTooLow {
        /// How many serials were used.
        used: u64,
        /// The block size.
        size: u64,
    },
    /// From the second block onward the previous block's closing allocation is
    /// required (§7 rule 3).
    PrevClosureRequired,
    /// A closure for a different block was presented.
    ClosureForAnotherBlock,
    /// A closure for this block was already accepted: closing it a second time
    /// would change what has been proved.
    AlreadyClosed {
        /// The block's start.
        from: u64,
    },
    /// The holder has no blocks, so there is no history to draw up (KS-1 §13).
    NoBlocks,
    /// The state is inconsistent with itself.
    CorruptSnapshot(&'static str),
    /// A core error while working with a document.
    Core(ksg_core_v2::error::Invalid),
}

impl core::fmt::Display for IssuerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::RangeExhausted { last, limit } => {
                write!(
                    f,
                    "range exhausted: allocated up to {last} against the limit {limit}"
                )
            }
            Self::DrawdownTooLow { used, size } => {
                write!(
                    f,
                    "the previous block is drawn down {used} of {size}, at least 80% is required"
                )
            }
            Self::PrevClosureRequired => {
                write!(
                    f,
                    "from the second block onward the previous block's closure is required"
                )
            }
            Self::ClosureForAnotherBlock => write!(f, "the closure belongs to a different block"),
            Self::NoBlocks => write!(f, "the holder has no blocks"),
            Self::AlreadyClosed { from } => {
                write!(f, "the block starting at {from} is already closed")
            }
            Self::CorruptSnapshot(m) => write!(f, "corrupt state: {m}"),
            Self::Core(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for IssuerError {}

impl From<ksg_core_v2::error::Invalid> for IssuerError {
    fn from(e: ksg_core_v2::error::Invalid) -> Self {
        Self::Core(e)
    }
}
