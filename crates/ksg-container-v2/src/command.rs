//! What arrives at a button, and what happens to it. KS-8 D-4, D-5, F-9.

use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{KeySet, Profile, PublicKey, SignatureSet};
use ksg_core_v2::doc::{Class, Uri};
use ksg_core_v2::status::{may_sign, may_sign_for, Blocked, Status};

use crate::operation::{Button, Keys, Operation, Role, Seat};

/// Why a command did not go through.
///
/// **A refusal is an ordinary outcome, not an error** (KS-8 F-9). The container
/// is entitled not to accept; that is what it is for. Hence a named reason
/// rather than a generic failure — the presenter is meant to read it and come
/// back with something else.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// The operation was offered at a button it does not arrive at.
    #[error("{op:?} arrives at {expected:?}, not at {offered:?}")]
    WrongButton {
        /// What was offered.
        op: Operation,
        /// Where it belongs.
        expected: Button,
        /// Where it was offered.
        offered: Button,
    },
    /// Fewer distinct parties than the operation takes.
    #[error("{op:?} takes {needed:?} and {presented} signature(s) arrived")]
    NotEnoughSignatures {
        /// What was offered.
        op: Operation,
        /// What it takes.
        needed: Keys,
        /// How many arrived.
        presented: usize,
    },
    /// The signed bytes are not this event's subject — the signatures cover
    /// something else, so they say nothing about this command.
    #[error("the signatures do not cover this event")]
    UnboundSignature,
    /// A plain-format container was asked to give its contents outside.
    ///
    /// `[decision]` 13.09 §8.3: the plain form is the playground — it anchors nothing
    /// and is **never presented outside**. Refusing the unload is the second
    /// half of that rule; refusing the anchor was the first. Without both, a
    /// playground could still be shown as evidence, and the whole point of two
    /// forms is that it cannot.
    #[error("a plain-format container is a playground: its contents do not go outside")]
    PlainIsNotPresented,
    /// Signatures arrived, but from too few parties (KS-8 D-5).
    #[error("{0} signed more than once; the signatures must come from that many parties")]
    OneParty(Uri),
    /// A seat the operation requires went unfilled — O-3.
    #[error("{op:?} wants {seat:?} and no such party signed")]
    RoleMissing {
        /// What was offered.
        op: Operation,
        /// The seat nobody filled.
        seat: Seat,
    },
    /// Somebody signed whom the container does not know a role for.
    #[error("{0} signed, and the container knows no role for that key")]
    NoRole(Uri),
    /// A party was presented with a key other than the one the container pinned
    /// for it — a substitution under a known `kid` (audit of 2026-09-23, K1).
    #[error("{0} was presented with a key other than the one the container holds for it")]
    ForeignKey(Uri),
    /// A signature did not verify, or an algorithm was left uncovered.
    #[error("a signature did not verify")]
    Signature,
    /// The container's status does not admit this operation.
    #[error("{op:?} is not admitted at status {status}")]
    WrongStatus {
        /// What was offered.
        op: Operation,
        /// What the container reads.
        status: u8,
    },
    /// The event is addressed to another container.
    #[error("this event is for another container")]
    WrongContainer,
    /// The presenter's view of the journal is not the current one.
    #[error("the journal head presented is not the current one; the command is stale")]
    StaleHead,
    /// The container is blocked and only a decision unblocks it.
    #[error("the container is blocked; only a decision unblocks it")]
    Blocked,
}

/// The record of a refused attempt — O-2, by way of B-6.
///
/// `[decision] 11.09` on B-6: an attempt is **recorded under an anchor**. The reasoning
/// was one sentence and it decides O-2 too — *silence means the door was rattled
/// and you will never learn of it.*
///
/// # What it does and does not carry
///
/// | | |
/// |---|---|
/// | **carries** | what was asked, where, by whom, at what status, and why it was refused |
/// | **does not carry** | the payload. Only the digest of the signed bytes, so an attempt proves what was presented without disclosing it |
///
/// A refused attempt **changes nothing** — §4.3 is explicit that neither the
/// state nor the journal moves. This is not a journal page and not a status
/// record; it is a thing to anchor, and anchoring is the platform's job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attempt {
    /// What was asked for.
    pub op: Operation,
    /// Which button it was offered at — not the one it belongs to, the one used.
    pub button: Button,
    /// The status the container read at the time.
    pub at_status: u8,
    /// Who signed, in order. **Names, not signatures**: the point is that the
    /// door was rattled and by whom.
    pub signers: Vec<Uri>,
    /// The digest of what was signed. Never the payload.
    pub signed: Hash,
    /// Why it was refused.
    pub reason: Refusal,
}

impl Attempt {
    /// The value an attempt's anchor must attest.
    #[must_use]
    pub fn subject(&self) -> Hash {
        let mut parts: Vec<Vec<u8>> = vec![
            b"ksg:attempt:v1".to_vec(),
            format!("{:?}", self.op).into_bytes(),
            format!("{:?}", self.button).into_bytes(),
            vec![self.at_status],
            self.signed.as_bytes().to_vec(),
            format!("{:?}", self.reason).into_bytes(),
        ];
        for s in &self.signers {
            parts.push(s.as_str().as_bytes().to_vec());
        }
        let refs: Vec<&[u8]> = parts.iter().map(std::vec::Vec::as_slice).collect();
        Hash::sha256_fields(&refs)
    }
}

/// A refusal together with the record of it.
///
/// The two arrive **as one value**, and that is deliberate: B-6 requires the
/// attempt to be recorded, and a caller that received only a reason could quietly
/// not record anything. Here there is no way to hold a refusal without also
/// holding the thing to anchor.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{reason}")]
pub struct Refused {
    /// Why.
    pub reason: Refusal,
    /// What to anchor.
    ///
    /// Boxed: a refusal is an ordinary outcome and travels in every `Result` on
    /// this path, so the success case should not carry the weight of the record.
    /// The one allocation happens only when something is actually refused.
    pub attempt: Box<Attempt>,
}

/// How well a command was staffed — O-13.
///
/// Some operations have two tiers: a minimum that is enforced and an optimum that
/// is better. Deciding a dispute is the one that has them today — an arbiter and
/// one side at the least, the arbiter and both sides at best.
///
/// **Reported rather than equated.** A decision taken with one side absent is
/// weaker than one both sides stood at, and that difference should travel with
/// the decision instead of disappearing into "it passed". The platform anchors it
/// beside the status change, so a later reader sees which it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strength {
    /// The minimum the rule requires.
    Minimum,
    /// Everyone the operation would rather have.
    Full,
}

/// A command presented at a button.
///
/// # The payload is opaque, and that is D-4
///
/// KS-8 D-4 fixes the order **accept → WRAP → check → take**, so that the
/// material never lies inside in the clear for a second. The wrapping itself is
/// [`crate::event::Wrapped::seal`] over the packing layer (`crate::pack`); what
/// the reader passes today is [`crate::event::Wrapped::received`] with the
/// material carried beside the event as `Evidence`. Wrapping that material is
/// left for the TEE: in the MVP the wrapping key would sit with the same holder
/// who holds the storage key, and would protect nothing
/// (`[doc:EXECUTOR-DECISIONS]`, executor decision 6).
///
/// What this path can hold, it holds: `payload` is bytes, and **nothing on this
/// path parses them**. A path that never reads the material cannot check it
/// early by accident, which is the half of D-4 that does not need a cipher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    /// What is being asked for.
    pub op: Operation,
    /// The material, unread by anything here.
    pub payload: Vec<u8>,
    /// The signatures over the command.
    pub signatures: SignatureSet,
    /// The bytes the signatures cover.
    ///
    /// Supplied by the caller rather than derived here — but no longer chosen
    /// freely: [`crate::Event::press`] refuses unless these bytes are exactly
    /// [`crate::Event::subject`], which binds the operation, the button, the
    /// container, the claimed head and a digest of the payload. A command
    /// reaching [`Command::press`] directly is checked by its caller; the
    /// container's own door does the binding (security audit of 2026-09-13,
    /// finding 2).
    pub signed_bytes: Vec<u8>,
}

impl Command {
    /// Puts the command through the button.
    ///
    /// The checks run in the order a presenter wants the answer in: the button
    /// first, because it is the cheapest to fix and the axiom worth stating
    /// loudest; then the signatures; then the status.
    ///
    /// Status comes **last** deliberately. It is the only check that depends on
    /// the container's history, so failing it means "not now" rather than "not
    /// like this", and a presenter reads those differently.
    ///
    /// # Errors
    ///
    /// A [`Refusal`], which is an ordinary outcome (KS-8 F-9).
    pub fn press(
        &self,
        button: Button,
        status: Status,
        blocked: Blocked,
        roster: &Roster,
        keys: &KeySet,
        profile: &Profile,
    ) -> Result<Strength, Refused> {
        self.press_inner(button, status, blocked, roster, keys, profile)
            .map_err(|reason| Refused {
                attempt: Box::new(self.record(button, status, reason.clone())),
                reason,
            })?;
        Ok(self.strength(roster))
    }

    /// Puts the command through the button for a container of the class
    /// given. Goal 1, `bare` v2 (owner's decision 08.10): the class-aware
    /// twin of [`Command::press`]; [`Command::press`] itself stays as the Pro
    /// default.
    ///
    /// # Errors
    ///
    /// A [`Refusal`], which is an ordinary outcome (KS-8 F-9).
    #[allow(clippy::too_many_arguments)] // the twin keeps `press`'s shape plus the class
    pub fn press_for(
        &self,
        button: Button,
        class: Class,
        status: Status,
        blocked: Blocked,
        roster: &Roster,
        keys: &KeySet,
        profile: &Profile,
    ) -> Result<Strength, Refused> {
        self.press_inner_for(button, class, status, blocked, roster, keys, profile)
            .map_err(|reason| Refused {
                attempt: Box::new(self.record(button, status, reason.clone())),
                reason,
            })?;
        Ok(self.strength(roster))
    }

    /// Whether the optimum set of parties signed, or only the minimum.
    ///
    /// Asked **after** the command is accepted, never as a condition of it: the
    /// minimum is the rule, and the optimum is a fact about this particular
    /// command worth carrying forward.
    #[must_use]
    pub fn strength(&self, roster: &Roster) -> Strength {
        let best = match self.op.keys_optimum() {
            Keys::Seats(best) => best,
            // An alternative is whole or it is not accepted: whichever one
            // the signers filled is the full set.
            Keys::Set | Keys::AnyOf(_) => return Strength::Full,
        };
        let signers: std::collections::BTreeSet<&Uri> = self
            .signatures
            .signers()
            .into_iter()
            .map(|k| roster.principal(k))
            .collect();
        let mut who: Vec<(&Uri, Role)> = Vec::with_capacity(signers.len());
        for kid in &signers {
            if let Some(role) = roster.role_of(kid) {
                who.push((kid, role));
            }
        }
        let mut taken = vec![false; who.len()];
        if who.len() >= best.len() && seat_all(best, &who, &mut taken) {
            Strength::Full
        } else {
            Strength::Minimum
        }
    }

    /// The record this command leaves if it is refused.
    ///
    /// Public because a platform may want to anchor an attempt it refused
    /// earlier, for its own reasons — but it is never the only way to get one:
    /// [`Command::press`] hands it over with every refusal.
    #[must_use]
    pub fn record(&self, button: Button, status: Status, reason: Refusal) -> Attempt {
        Attempt {
            op: self.op,
            button,
            at_status: status.number(),
            signers: self
                .signatures
                .as_slice()
                .iter()
                .map(|s| s.kid.clone())
                .collect(),
            signed: Hash::sha256(&self.signed_bytes),
            reason,
        }
    }

    fn press_inner(
        &self,
        button: Button,
        status: Status,
        blocked: Blocked,
        roster: &Roster,
        keys: &KeySet,
        profile: &Profile,
    ) -> Result<(), Refusal> {
        let expected = self.op.button();
        if button != expected {
            return Err(Refusal::WrongButton {
                op: self.op,
                expected,
                offered: button,
            });
        }

        self.check_signatures(roster, keys, profile)?;

        // §7.3-bis — the status is read before the ink. Read from the CHAIN:
        // `[decision]` 12.09 removed the read port, so the value arrives as an argument
        // like elapsed time does, and this module never reaches into a container
        // for it.
        let Some(event) = self.op.event() else {
            return Ok(());
        };
        if !may_sign(status, blocked, event) {
            return Err(if blocked == Blocked::AwaitingDecision {
                Refusal::Blocked
            } else {
                Refusal::WrongStatus {
                    op: self.op,
                    status: status.number(),
                }
            });
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)] // the twin keeps `press_inner`'s shape plus the class
    fn press_inner_for(
        &self,
        button: Button,
        class: Class,
        status: Status,
        blocked: Blocked,
        roster: &Roster,
        keys: &KeySet,
        profile: &Profile,
    ) -> Result<(), Refusal> {
        let expected = self.op.button();
        if button != expected {
            return Err(Refusal::WrongButton {
                op: self.op,
                expected,
                offered: button,
            });
        }

        self.check_signatures(roster, keys, profile)?;

        // §7.3-bis — the status is read before the ink, through the
        // class-aware table (Goal 1, `bare` v2).
        let Some(event) = self.op.event() else {
            return Ok(());
        };
        if !may_sign_for(class, status, blocked, event) {
            return Err(if blocked == Blocked::AwaitingDecision {
                Refusal::Blocked
            } else {
                Refusal::WrongStatus {
                    op: self.op,
                    status: status.number(),
                }
            });
        }
        Ok(())
    }

    /// KS-8 D-5 and O-3: how many keys, from how many parties, and **whose**.
    fn check_signatures(
        &self,
        roster: &Roster,
        keys: &KeySet,
        profile: &Profile,
    ) -> Result<(), Refusal> {
        // Parties, not keys: a companion key counts as the party it signs for.
        let signers: std::collections::BTreeSet<&Uri> = self
            .signatures
            .signers()
            .into_iter()
            .map(|k| roster.principal(k))
            .collect();
        let needed = self.op.keys();

        match needed {
            // Counted by DISTINCT signers, never by length. One party signing
            // twice is a set of two and is not two parties — count length and
            // the rule is satisfiable by exactly the party it constrains.
            Keys::Seats(seats) => {
                if signers.len() < seats.len() {
                    // Name the more useful of the two failures: signatures that
                    // arrived but from too few parties is a different mistake
                    // from signatures missing, and "not enough signatures" when
                    // enough arrived would send the presenter looking in the
                    // wrong place.
                    if self.signatures.len() >= seats.len() {
                        let who = signers
                            .into_iter()
                            .next()
                            .cloned()
                            .expect("a non-empty set has a signer");
                        return Err(Refusal::OneParty(who));
                    }
                    return Err(Refusal::NotEnoughSignatures {
                        op: self.op,
                        needed,
                        presented: self.signatures.len(),
                    });
                }
                self.fill_seats(seats, &signers, roster)?;
            }
            Keys::AnyOf(alts) => {
                if self.signatures.is_empty() {
                    return Err(Refusal::NotEnoughSignatures {
                        op: self.op,
                        needed,
                        presented: 0,
                    });
                }
                // The first alternative the distinct signers fill, each by a
                // different party (O-3 as for `Seats`). None filled — the
                // smallest alternative's missing seat is named.
                let filled = alts.iter().any(|seats| {
                    signers.len() >= seats.len() && self.fill_seats(seats, &signers, roster).is_ok()
                });
                if !filled {
                    let smallest = alts.iter().min_by_key(|s| s.len()).copied().unwrap_or(&[]);
                    return Err(match self.fill_seats(smallest, &signers, roster) {
                        Err(e) => e,
                        Ok(()) => Refusal::NotEnoughSignatures {
                            op: self.op,
                            needed,
                            presented: self.signatures.len(),
                        },
                    });
                }
            }
            Keys::Set => {
                if self.signatures.is_empty() {
                    return Err(Refusal::NotEnoughSignatures {
                        op: self.op,
                        needed,
                        presented: 0,
                    });
                }
            }
        }

        // Against the keys the container pinned, never the presenter's: the
        // presenter's set is only compared, and a substitution is named.
        let trusted = roster.trusted(keys).map_err(Refusal::ForeignKey)?;
        self.signatures
            .verify(&self.signed_bytes, trusted, profile)
            .map_err(|_| Refusal::Signature)
    }

    /// Seats every place with a different party of an admitted role — O-3.
    ///
    /// # Why this is a matching rather than a loop
    ///
    /// A greedy pass fails on a real case: given the seats `[Either(Client,
    /// Owner), Exactly(Owner)]` and signatures from the client and the owner, a
    /// loop that hands the owner to the first seat finds nothing for the second
    /// and refuses a command that is in fact good. With at most four seats the
    /// exhaustive search costs nothing and is right, so it is what runs.
    fn fill_seats(
        &self,
        seats: &[Seat],
        signers: &std::collections::BTreeSet<&Uri>,
        roster: &Roster,
    ) -> Result<(), Refusal> {
        // Every signer must have a role. An extra key that verifies but answers
        // to nobody is exactly what should not pass quietly: the operation says
        // who acts, and a party outside that list is not one of them.
        let mut who: Vec<(&Uri, Role)> = Vec::with_capacity(signers.len());
        for kid in signers {
            let role = roster
                .role_of(kid)
                .ok_or_else(|| Refusal::NoRole((*kid).clone()))?;
            who.push((kid, role));
        }

        let mut taken = vec![false; who.len()];
        if seat_all(seats, &who, &mut taken) {
            return Ok(());
        }
        // Report the seat with no candidate at all, which is the one a presenter
        // can act on. If every seat has candidates and the seating still fails,
        // the first seat is named: something has to be, and guessing which of a
        // tangle to blame would be worse than being consistent.
        let seat = seats
            .iter()
            .find(|s| !who.iter().any(|(_, r)| s.admits(*r)))
            .copied()
            .unwrap_or(seats[0]);
        Err(Refusal::RoleMissing { op: self.op, seat })
    }
}

/// Who holds which role, as the container knows it from its own layers — and
/// **with which key**.
///
/// Supplied by the caller for the same reason `signed_bytes` is: the container
/// checks the rule, and knowing which key belongs to the owner is the presenting
/// layer's job — it reads that from the layers it has opened. Passing it in keeps
/// this module a checker rather than a directory.
///
/// # Why the key is pinned and not only its identifier
///
/// Until the audit of 2026-09-23 the roster held `kid → role` and nothing else,
/// and signatures were verified against a key set **the presenter** handed in
/// with the command. A `kid` is a name, not a key: anybody could present a
/// command signed with their own key under the issuer's `kid`, bring a key set
/// that maps that `kid` to their own key, and the container seated them as the
/// issuer (finding audit of 23.09, K1 of `[doc:AUDIT-2309]`). The roster now pins
/// the public key the role belongs to, and verification uses the pinned keys
/// (§9 and §16 of the product description: the container interacts only with
/// keys that pass its own check).
///
/// The pinned set only grows: a sale moves the owner's *seat*, but the seller's
/// key stays pinned so that what the seller signed while owner stays checkable.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Roster {
    pub(crate) seats: Vec<(Uri, Role)>,
    pub(crate) keys: KeySet,
    /// Keys that sign **for** a party rather than as one: `kid` of the
    /// companion → `kid` of the party. The ML-DSA key the container holds for
    /// the client (`[decision]` 23.09) is one; a party that signs in two algorithms is
    /// still one party, and counting its two `kid`s as two would let it fill
    /// two seats alone.
    pub(crate) companions: Vec<(Uri, Uri)>,
}

impl Roster {
    /// An empty roster.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a key as holding a role.
    ///
    /// One key **may** hold more than one role — a client that is also the owner
    /// of its own container is ordinary. It still fills one seat, because seats
    /// are seated by distinct **parties**: the same key cannot be both signatures
    /// of a two-party command, which is the rule O-3 exists to make checkable.
    ///
    /// **The first key pinned under a `kid` stays.** A second, different key
    /// under the same `kid` gets the role recorded but never its key pinned, so
    /// nothing it signs verifies: a clash fails closed rather than handing the
    /// seat to whichever key came last.
    pub fn add(&mut self, key: PublicKey, role: Role) -> &mut Self {
        if self.keys.get(&key.kid).is_none() {
            self.keys.insert(key.clone());
        }
        self.seats.push((key.kid, role));
        self
    }

    /// Builds a roster from pairs.
    #[must_use]
    pub fn of(pairs: impl IntoIterator<Item = (PublicKey, Role)>) -> Self {
        let mut r = Self::new();
        for (key, role) in pairs {
            r.add(key, role);
        }
        r
    }

    /// Pins a key that signs for `party` and is not a party of its own.
    ///
    /// Same first-pin-stays rule as [`Roster::add`].
    pub fn add_companion(&mut self, key: PublicKey, party: &Uri) -> &mut Self {
        if self.keys.get(&key.kid).is_none() {
            self.keys.insert(key.clone());
        }
        self.companions.push((key.kid, party.clone()));
        self
    }

    /// The party a `kid` signs for: itself, or the party it is a companion of.
    #[must_use]
    pub fn principal<'a>(&'a self, kid: &'a Uri) -> &'a Uri {
        self.companions
            .iter()
            .find(|(c, _)| c == kid)
            .map_or(kid, |(_, p)| p)
    }

    /// The keys the container knows its parties by — what every signature
    /// presented to it is verified against.
    #[must_use]
    pub const fn keys(&self) -> &KeySet {
        &self.keys
    }

    /// The pinned keys, once the presenter's view of them has been checked.
    ///
    /// The presenter's set is not trusted for anything: it is only compared.
    /// A key under a pinned `kid` that differs from the pinned one is a
    /// substitution and is named; keys under `kid`s the roster does not pin
    /// are ignored, because the container verifies nothing against them.
    ///
    /// # Errors
    ///
    /// The `kid` presented with a key other than the pinned one.
    pub fn trusted(&self, presented: &KeySet) -> Result<&KeySet, Uri> {
        for key in presented.keys() {
            if let Some(pinned) = self.keys.get(&key.kid) {
                if pinned != key {
                    return Err(key.kid.clone());
                }
            }
        }
        Ok(&self.keys)
    }

    /// The pinned key of the party that holds `role` now — the first one.
    #[must_use]
    pub fn holder(&self, role: Role) -> Option<&PublicKey> {
        self.seats
            .iter()
            .find(|(_, r)| *r == role)
            .and_then(|(kid, _)| self.keys.get(kid))
    }

    /// Whether this exact key — not merely its `kid` — holds the role.
    #[must_use]
    pub fn holds(&self, key: &PublicKey, role: Role) -> bool {
        self.keys.get(&key.kid) == Some(key) && self.roles_of(&key.kid).contains(&role)
    }

    /// E-9 in `bare` (13.10): the leader's owner arriving with the command
    /// takes the arriving party's seat — the only one, so the sale page names
    /// exactly it.
    ///
    /// Refused (`false`, nothing changed) when the key's identifier is pinned
    /// to another key: the first pin stays ([`Roster::add`]), so the seat
    /// would go to a key the arriving owner does not hold.
    #[must_use]
    pub fn seat_arriving(&mut self, key: PublicKey) -> bool {
        if self.keys.get(&key.kid).is_some_and(|pinned| *pinned != key) {
            return false;
        }
        self.seats.retain(|(_, r)| *r != Role::Buyer);
        self.add(key, Role::Buyer);
        true
    }

    /// The client a `bare` had before its attachment keeps a seat of its own
    /// (13.10): its key stays pinned and its word is asked to detach.
    pub fn seat_former_client(&mut self, kid: &Uri) {
        if !self
            .seats
            .iter()
            .any(|(k, r)| k == kid && *r == Role::FormerClient)
        {
            self.seats.push((kid.clone(), Role::FormerClient));
        }
    }

    /// A hand-off has landed (CH-16, CH-17): the new agent takes the
    /// client's seat, the old one leaves it. The old key stays pinned — what
    /// it signed while agent stays checkable — but it is nobody now.
    pub fn hand_off_client(&mut self, old: &Uri, new: PublicKey) {
        self.seats
            .retain(|(k, r)| !(k == old && *r == Role::Client));
        self.add(new, Role::Client);
    }

    /// A sale has landed: the buyer becomes the owner and the seller stops
    /// being one (E-9, `KS-7` §9.2, `KS-8` I-7; T-6 of the blocker register).
    ///
    /// **The set of keys is for checking the past; the right to act belongs to
    /// the last one.** Signatures the seller made while owner stay valid
    /// forever — they are checked against the key set, which this does not
    /// touch. What goes is the seller's *seat*: after this, a command the
    /// seller signs as owner is refused with [`Refusal::NoRole`], because the
    /// container no longer knows that key as anybody.
    ///
    /// Before 22.09 nothing here changed at a sale, and a sold container kept
    /// answering to the seller's key for as long as it lived.
    ///
    /// The buyer is whichever of `signers` holds the buyer's role. Returns
    /// whether ownership moved — `false` when no signer was a buyer, which the
    /// seating of the command rules out and which therefore changes nothing.
    pub fn transfer_ownership<'a>(&mut self, signers: impl IntoIterator<Item = &'a Uri>) -> bool {
        let buyers: Vec<Uri> = signers
            .into_iter()
            .filter(|k| self.roles_of(k).contains(&Role::Buyer))
            .cloned()
            .collect();
        if buyers.is_empty() {
            return false;
        }
        self.seats.retain(|(_, r)| *r != Role::Owner);
        for (kid, role) in &mut self.seats {
            if *role == Role::Buyer && buyers.contains(kid) {
                *role = Role::Owner;
            }
        }
        true
    }

    /// The first role recorded for a key, if any.
    #[must_use]
    pub fn role_of(&self, kid: &Uri) -> Option<Role> {
        self.seats.iter().find(|(k, _)| k == kid).map(|(_, r)| *r)
    }

    /// Every role recorded for a key.
    #[must_use]
    pub fn roles_of(&self, kid: &Uri) -> Vec<Role> {
        self.seats
            .iter()
            .filter(|(k, _)| k == kid)
            .map(|(_, r)| *r)
            .collect()
    }
}

/// Exhaustive seating: seat by seat, trying every unused party.
fn seat_all(seats: &[Seat], who: &[(&Uri, Role)], taken: &mut [bool]) -> bool {
    let Some((seat, rest)) = seats.split_first() else {
        return true;
    };
    for (i, (_, role)) in who.iter().enumerate() {
        if taken[i] || !seat.admits(*role) {
            continue;
        }
        taken[i] = true;
        if seat_all(rest, who, taken) {
            return true;
        }
        taken[i] = false;
    }
    false
}
