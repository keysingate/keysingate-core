//! The test stand: one container, every party, and the reader.
//!
//! Every scenario on the stand goes through [`Container::press`] — the three
//! buttons — and nothing else: no status is forced, no rule is called
//! directly. The client signs **only** through the two halves of its working
//! key (`[decision]` 23.09): the mobile half with the stand, the other half inside the
//! container. What the stand checks is therefore the container as a whole,
//! not its parts.
//!
//! [`Stand::pressed`] collects every operation that went through. The e2e
//! suite asserts that, across its scenarios, **every** operation of the three
//! buttons went through at least once.

#![allow(dead_code)]

use std::collections::BTreeSet;

use frost_ed25519::rand_core::{CryptoRng, Error as RngError, RngCore};
use ksg_container_v2::client_key::{split, MobileHalf};
use ksg_container_v2::container::{Container, Evidence, JournalWrite, Release, Stopped, Writes};
use ksg_container_v2::followup::{Discharge, Proof, Task};
use ksg_container_v2::seal::IssuerSeal;
use ksg_container_v2::{Event, Operation, Role, Roster, Wrapped};
use ksg_core_v2::anchor::Attestation;
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{
    sign_doc, Alg, Ed25519Signer, KeySet, Profile, PublicKey, SignatureSet,
};
use ksg_core_v2::doc::{derive_container_id, Class, MemoFormat, Serial, Timestamp, Uri};
use ksg_core_v2::journal::{Draft, Mode, Piece, RecordKind, RecordMeta, Sealing};
use ksg_core_v2::section::{StatusRecord, StatusSection};
use ksg_core_v2::status::{transition_for, Event as StatusEvent, Outcome, Status};
use sha2::{Digest, Sha256};

pub const EMISSION: &str = "ksg:em:000001";
pub const SERIAL: Serial = Serial(7);
pub const ARTIFACT: &str = "ksg:artifact:the-one";
pub const OFFSET: u64 = 1_000;
pub const DAY: u64 = 86_400_000;

/// A deterministic CSPRNG for the stand only: SHA-256 over a counter.
pub struct StandRng(pub u64);

impl RngCore for StandRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(32) {
            self.0 += 1;
            let block = Sha256::digest(self.0.to_be_bytes());
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl CryptoRng for StandRng {}

pub fn uri(s: &str) -> Uri {
    Uri::parse(s).expect("uri")
}
pub fn ts(s: &str) -> Timestamp {
    Timestamp::parse(s).expect("ts")
}
pub fn p() -> Profile {
    Profile::default()
}

/// Every party on the stand except the client, whose key exists only as two
/// halves.
pub struct Parties {
    pub issuer: Ed25519Signer,
    pub owner: Ed25519Signer,
    pub buyer: Ed25519Signer,
    pub subagent: Ed25519Signer,
    pub orchestrator: Ed25519Signer,
    pub arbiter_a: Ed25519Signer,
    pub arbiter_b: Ed25519Signer,
    pub claimant: Ed25519Signer,
    /// The distributor that sold the packet (C-12, 17.10): not seated at
    /// printing — it takes its seat itself, `Container::seat_distributor`.
    pub distributor: Ed25519Signer,
}

impl Parties {
    fn new() -> Self {
        let s = |kid: &str, seed: u8| Ed25519Signer::from_seed(uri(kid), [seed; 32]);
        Self {
            issuer: s("did:key:zIssuer#i1", 11),
            owner: s("did:key:zOwner#o1", 44),
            buyer: s("did:key:zBuyer#b1", 12),
            subagent: s("did:key:zSub#s1", 13),
            orchestrator: s("did:key:zOrch#r1", 14),
            arbiter_a: s("did:key:zArbA#j1", 70),
            arbiter_b: s("did:key:zArbB#j1", 71),
            claimant: s("did:key:zClaim#k1", 15),
            distributor: s("did:key:zDist#d1", 72),
        }
    }
}

/// Who signs a command on the stand.
#[derive(Clone, Copy, Debug)]
pub enum Who {
    /// The client — through the reader, both halves.
    Client,
    Issuer,
    Owner,
    Buyer,
    SubAgent,
    Orchestrator,
    ArbiterA,
    ArbiterB,
    Claimant,
    /// The client a `bare` had before its attachment (13.10): its mobile
    /// half with the stand, its other half kept inside for the detachment.
    FormerClient,
    /// The distributor that sold the packet (C-12, 17.10).
    Distributor,
}

/// What a stand page records. The stand's own list since core v2: the work
/// journal of core v1 (`ksg_journal::EventKind`) is gone, and the bound
/// journal's `RecordKind` has no repeat confirmation — that one is a page the
/// journal writes, not a kind of record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    Work,
    ArtifactOrRights,
    RepeatConfirmation,
    SharesDeclaredLost,
    HashBinding,
}

/// Whether the operation writes a journal page, and which.
#[derive(Clone, Copy, Debug)]
pub enum Page {
    None,
    Opening,
    Of(EventKind),
    /// The page of a change of form (E-10, CH-30).
    Form(Mode),
}

pub struct Stand {
    pub c: Container,
    pub mobile: MobileHalf,
    /// The former client's mobile half, once a `bare` is handed to the
    /// leader's agent during its attachment (13.10).
    pub former_mobile: Option<MobileHalf>,
    pub rng: StandRng,
    pub parties: Parties,
    pub client: PublicKey,
    /// The container's own post-quantum key: it signs the stored file (CH-5a, CH-5b).
    /// For `Bare` (criterion G1-4) this is a placeholder that was never
    /// generated and is never attached — `Container::pq_public()` is `None`.
    #[allow(dead_code)]
    pub pq: PublicKey,
    /// A stand-in for the anchorer (the network or the service queue):
    /// every anchor attached below counts as one call to it. Goal 1,
    /// criterion G1-4 pins this at zero for `bare` work records.
    pub anchor_calls: usize,
    /// The journal's clock: offsets must strictly increase.
    pub clock_ms: u64,
    /// Every operation that went through on this stand.
    pub pressed: BTreeSet<String>,
}

pub fn client_kid() -> Uri {
    uri("did:key:zAgent#a1")
}
pub fn client_author() -> Uri {
    uri("did:key:zAgent")
}

fn anchor(subject: Hash) -> Attestation {
    Attestation {
        kind: uri("urn:ksg:anchor:stand"),
        subject,
        proof: b"stand".to_vec(),
        anchored_at: ts("2026-09-12T00:00:00.000Z"),
    }
}

impl Stand {
    /// A container at printing, of the class given, with the client's key
    /// already in two halves and the container's half integrated.
    pub fn new(class: Class, seed: u64) -> Self {
        Self::build(class, seed, true, true)
    }

    /// As [`Stand::new`], in the plain memo format: a playground (KS-8,
    /// the playground definition).
    #[allow(dead_code)]
    pub fn playground(class: Class, seed: u64) -> Self {
        Self::build_as(class, seed, true, true, MemoFormat::Plain)
    }

    /// A container as the issuer prints it (CH-5b): no client's key, no
    /// identifier of its own — both are born at initiation, [`Stand::give_birth`].
    /// Until then `mobile` and `client` are placeholders of nobody's.
    #[allow(dead_code)]
    pub fn printed(class: Class, seed: u64) -> Self {
        Self::build(class, seed, true, false)
    }

    /// The birth of the client's key (CH-5b): the three messages between the
    /// mobile side and the container, each through its bytes. After it the
    /// stand's mobile half is the new one; initiation still has to go in.
    #[allow(dead_code)]
    pub fn give_birth(&mut self) -> Hash {
        use ksg_container_v2::client_key::{KeygenFinish, KeygenHello, KeygenReply, MobileKeygen};
        let (keygen, hello) = MobileKeygen::start(client_kid(), &mut self.rng).expect("start");
        let hello = KeygenHello::from_bytes(&hello.to_bytes().expect("bytes")).expect("hello");
        let reply = self
            .c
            .begin_birth(client_kid(), &hello, &mut self.rng)
            .expect("the container answers");
        let reply = KeygenReply::from_bytes(&reply.to_bytes().expect("bytes")).expect("reply");
        let (mobile, public, fin) = keygen
            .finish(&reply)
            .expect("the mobile side keeps its half");
        let fin = KeygenFinish::from_bytes(&fin.to_bytes().expect("bytes")).expect("finish");
        let (inside, id) = self
            .c
            .finish_birth(&fin, uri(ARTIFACT), OFFSET)
            .expect("the container keeps its half");
        assert_eq!(inside, public, "both sides hold halves of one key");
        self.mobile = mobile;
        self.client = public;
        id
    }

    /// The same container, printed **without** the issuer's seal.
    #[allow(dead_code)]
    pub fn unsealed(class: Class, seed: u64) -> Self {
        Self::build(class, seed, false, true)
    }

    fn build(class: Class, seed: u64, sealed: bool, born: bool) -> Self {
        Self::build_as(class, seed, sealed, born, MemoFormat::Controlled)
    }

    fn build_as(class: Class, seed: u64, sealed: bool, born: bool, memo: MemoFormat) -> Self {
        let parties = Parties::new();
        let mut rng = StandRng(seed);
        let (inside, mobile) = split(client_kid(), &mut rng).expect("split");
        let client = inside.public().clone();
        // Goal 1, criterion G1-4: a `bare` printing creates no
        // post-quantum key and stores none — the layer is not set. The
        // `pq` slot keeps a placeholder that is never attached and never
        // signs (no secret is generated for it).
        let (pq_key, pq) = if class == Class::Bare {
            (
                None,
                PublicKey {
                    kid: uri("did:key:zContainer#pq"),
                    alg: Alg::MlDsa65,
                    key: String::new(),
                },
            )
        } else {
            let k = ksg_container_v2::pq_key::ContainerPqKey::generate(
                uri("did:key:zContainer#pq"),
                &mut rng,
            )
            .expect("pq key");
            let p = k.public().clone();
            (Some(k), p)
        };

        let issued_at = ts("2026-09-01T00:00:00.000Z");
        let id = derive_container_id(
            EMISSION,
            &issued_at,
            SERIAL,
            &client,
            &uri(ARTIFACT),
            OFFSET,
        );

        let root = ksg_core_v2::section::section_root(EMISSION, SERIAL);
        let mut r0 = StatusRecord {
            context: ksg_core_v2::doc::Context,
            doc_type: "StatusRecord".into(),
            v: 3,
            number: 0,
            status: Status::Printed,
            event: None,
            offset_ms: 0,
            prev: root,
            signatures: SignatureSet::default(),
        };
        r0.signatures = SignatureSet::new(vec![sign_doc(&r0, &parties.issuer).expect("sig")]);
        let a0 = anchor(r0.hash().expect("hash"));
        let issuer_keys: KeySet = [parties.issuer.public()].into_iter().collect();
        let section =
            StatusSection::start(EMISSION, SERIAL, r0, a0, &issuer_keys, &p()).expect("section");

        let mut roster = Roster::of([
            (parties.issuer.public(), Role::Issuer),
            (parties.owner.public(), Role::Owner),
            (parties.buyer.public(), Role::Buyer),
            (parties.subagent.public(), Role::SubAgent),
            (parties.orchestrator.public(), Role::Orchestrator),
            (parties.arbiter_a.public(), Role::Arbiter),
            (parties.arbiter_b.public(), Role::Arbiter),
            (parties.claimant.public(), Role::Claimant),
        ]);
        if born {
            roster.add(client.clone(), Role::Client);
        }

        // The issuer's word at printing is bound to the template (CH-5b).
        let seal = IssuerSeal::lay(&root, uri("did:key:zSeal#s1"), [90u8; 32], &parties.issuer);
        let release = Release {
            id: EMISSION.into(),
            issued_at,
            class,
        };
        let c = if born {
            Container::assemble(id, release, SERIAL, client.clone(), memo, section, roster)
        } else {
            Container::print(release, SERIAL, memo, section, roster)
        };
        let c = match pq_key {
            Some(k) => c.with_pq_key(k),
            None => c,
        };
        let mut c = if sealed { c.with_seal(seal) } else { c };
        if born {
            c.integrate_client_key(inside)
                .expect("the container's half");
        }

        Self {
            c,
            mobile,
            former_mobile: None,
            rng,
            parties,
            client,
            pq,
            anchor_calls: 0,
            clock_ms: OFFSET,
            pressed: BTreeSet::new(),
        }
    }

    fn signer(&self, who: Who) -> Option<&Ed25519Signer> {
        let p = &self.parties;
        Some(match who {
            Who::Client | Who::FormerClient => return None,
            Who::Issuer => &p.issuer,
            Who::Owner => &p.owner,
            Who::Buyer => &p.buyer,
            Who::SubAgent => &p.subagent,
            Who::Orchestrator => &p.orchestrator,
            Who::ArbiterA => &p.arbiter_a,
            Who::ArbiterB => &p.arbiter_b,
            Who::Claimant => &p.claimant,
            Who::Distributor => &p.distributor,
        })
    }

    /// The client signs at the reader: its mobile half, the container's half.
    pub fn client_signs(&mut self, msg: &[u8]) -> Vec<ksg_core_v2::crypto::sign::Signature> {
        let (nonces, commitment) = self.mobile.commit(&mut self.rng);
        let round = self
            .c
            .begin_signing(msg, &commitment, &mut self.rng)
            .expect("the container opens a round");
        let share = self
            .mobile
            .respond(nonces, &round)
            .expect("the mobile half");
        self.c
            .finish_signing(&share, &mut self.rng)
            .expect("both halves")
    }

    /// The former client signs: its mobile half and the half the container
    /// kept for it (13.10, variant A).
    pub fn former_signs(&mut self, msg: &[u8]) -> Vec<ksg_core_v2::crypto::sign::Signature> {
        let m = self.former_mobile.as_ref().expect("a former client");
        let (nonces, commitment) = m.commit(&mut self.rng);
        let round = self
            .c
            .begin_signing_former(msg, &commitment, &mut self.rng)
            .expect("the container opens a round");
        let share = self
            .former_mobile
            .as_ref()
            .expect("a former client")
            .respond(nonces, &round)
            .expect("the mobile half");
        self.c
            .finish_signing_former(&share, &mut self.rng)
            .expect("both halves")
    }

    fn sign_all(&mut self, msg: &[u8], who: &[Who]) -> SignatureSet {
        let mut sigs = Vec::new();
        for w in who {
            if matches!(w, Who::FormerClient) {
                sigs.extend(self.former_signs(msg));
                continue;
            }
            match self.signer(*w) {
                Some(s) => sigs.push(s.sign(msg)),
                None => sigs.extend(self.client_signs(msg)),
            }
        }
        SignatureSet::new(sigs)
    }

    fn tick(&mut self) -> u64 {
        self.clock_ms += 1_000;
        self.clock_ms
    }

    /// Moves the stand's clock forward by `ms` — the idle-term tests jump
    /// days at once instead of pressing thousands of times.
    pub fn advance(&mut self, ms: u64) {
        self.clock_ms = self.clock_ms.saturating_add(ms);
    }

    /// Seals a drafted record the way the parties would: the client's seal
    /// (Ed25519 + ML-DSA), the owner's where the journal asks for it, and the
    /// anchor in Pro — made only once the owner has sealed (CH-26).
    pub fn seal_draft(&mut self, draft: Draft) -> JournalWrite {
        let bytes = draft.seal_bytes().expect("bytes");
        let mut sealing = Sealing {
            seal: SignatureSet::new(self.client_signs(&bytes)),
            ..Sealing::default()
        };
        if draft.needs_owner() {
            sealing.owner = Some(SignatureSet::new(vec![self.parties.owner.sign(&bytes)]));
        }
        if let Some(tb) = draft.transfer_bytes().expect("bytes") {
            let mut sigs = self.client_signs(&tb);
            sigs.push(self.parties.owner.sign(&tb));
            sigs.push(self.parties.buyer.sign(&tb));
            sealing.transfer = Some(SignatureSet::new(sigs));
        }
        // Goal 1, criterion G1-4: a `bare` work record anchors nothing —
        // the placeholder is Pro-only, and `bare` opens local anyway.
        // Every anchor attached counts as one call to the anchorer.
        if draft.is_pro() && self.c.class() != Class::Bare {
            sealing.anchor = Some(anchor(draft.seal_hash().expect("hash")));
            self.anchor_calls += 1;
        }
        JournalWrite::Record {
            draft: Box::new(draft),
            sealing: Box::new(sealing),
        }
    }

    pub fn page(&mut self, op: Operation, page: Page) -> Option<JournalWrite> {
        let offset_ms = self.tick();
        let kind = match page {
            Page::None => {
                // A sale writes its page once the journal is open (CH-14).
                if op == Operation::TransferOwnership && self.c.head().is_some() {
                    let d = self
                        .c
                        .draft_owner_change(offset_ms)
                        .expect("owner's change page");
                    return Some(self.seal_draft(d));
                }
                return None;
            }
            Page::Opening => {
                let (bytes, hash) = self.c.opening_seal(offset_ms).expect("page 0");
                // G1-4: `bare` never anchors — its opening form is local anyway.
                let pro = self.c.opening_form() == Mode::Pro && self.c.class() != Class::Bare;
                if pro {
                    self.anchor_calls += 1;
                }
                let sealing = Sealing {
                    seal: SignatureSet::new(self.client_signs(&bytes)),
                    owner: pro.then(|| SignatureSet::new(vec![self.parties.owner.sign(&bytes)])),
                    anchor: pro.then(|| anchor(hash)),
                    ..Sealing::default()
                };
                return Some(JournalWrite::Open {
                    offset_ms,
                    sealing: Box::new(sealing),
                });
            }
            Page::Form(to) => {
                let d = self.c.draft_form(to, offset_ms).expect("form page");
                return Some(self.seal_draft(d));
            }
            Page::Of(EventKind::RepeatConfirmation) => {
                let d = self.c.draft_confirmation(offset_ms).expect("confirmation");
                return Some(self.seal_draft(d));
            }
            Page::Of(EventKind::ArtifactOrRights) => RecordKind::ArtifactOrRights,
            Page::Of(EventKind::SharesDeclaredLost) => RecordKind::SharesDeclaredLost,
            Page::Of(EventKind::HashBinding) => RecordKind::HashBinding,
            Page::Of(_) => RecordKind::Work,
        };
        let d = self
            .c
            .draft_record(
                vec![Piece::Digest(Hash::sha256(&offset_ms.to_be_bytes()))],
                RecordMeta {
                    kind,
                    ..RecordMeta::default()
                },
                offset_ms,
            )
            .expect("draft");
        Some(self.seal_draft(d))
    }

    fn status_record(&mut self, op: Operation) -> Option<(StatusRecord, Attestation)> {
        let ev = op.event()?;
        // Goal 1, `bare` v2: the harness predicts through the same
        // class-aware route the container presses through.
        let Outcome::Moves(next) =
            transition_for(self.c.class(), self.c.status(), self.c.blocked(), ev)
        else {
            return None;
        };
        let mut r = StatusRecord {
            context: ksg_core_v2::doc::Context,
            doc_type: "StatusRecord".into(),
            v: 3,
            number: self.c.status_records() as u64,
            status: next,
            event: Some(ev),
            offset_ms: self.tick(),
            prev: self.c.status_head(),
            signatures: SignatureSet::default(),
        };
        r.signatures = SignatureSet::new(vec![sign_doc(&r, &self.parties.issuer).expect("sig")]);
        let a = anchor(r.hash().expect("hash"));
        Some((r, a))
    }

    /// A status record for a trigger — a change nobody presses (deadline,
    /// prescription): signed by the issuer, anchored, linked to the head.
    pub fn trigger_record(&mut self, ev: StatusEvent) -> (StatusRecord, Attestation) {
        let next = match transition_for(self.c.class(), self.c.status(), self.c.blocked(), ev) {
            Outcome::Moves(n) => n,
            _ => self.c.status(),
        };
        let mut r = StatusRecord {
            context: ksg_core_v2::doc::Context,
            doc_type: "StatusRecord".into(),
            v: 3,
            number: self.c.status_records() as u64,
            status: next,
            event: Some(ev),
            offset_ms: self.tick(),
            prev: self.c.status_head(),
            signatures: SignatureSet::default(),
        };
        r.signatures = SignatureSet::new(vec![sign_doc(&r, &self.parties.issuer).expect("sig")]);
        let a = anchor(r.hash().expect("hash"));
        (r, a)
    }

    /// Presses the button of `op`, signed by `who`, with `evidence`, writing
    /// the page `page` — and then lets the follow-up worker do its part.
    pub fn press(
        &mut self,
        op: Operation,
        who: &[Who],
        evidence: Evidence,
        page: Page,
    ) -> Result<(), Stopped> {
        let head = self.c.head();
        let mut e = Event {
            op,
            button: op.button(),
            container: *self.c.id(),
            payload: Wrapped::received(b"wrapped at the reader".to_vec()),
            signatures: SignatureSet::default(),
            covered: Vec::new(),
            head,
        };
        e.covered = e.subject();
        let covered = e.covered.clone();
        e.signatures = self.sign_all(&covered, who);

        let page = self.page(op, page);
        self.press_signed(e, evidence, page)
    }

    /// Presses the button of `op` with a journal write made by hand — for a
    /// scenario that seals a record differently from the stand's parties.
    pub fn press_write(
        &mut self,
        op: Operation,
        who: &[Who],
        evidence: Evidence,
        page: Option<JournalWrite>,
    ) -> Result<(), Stopped> {
        let head = self.c.head();
        let mut e = Event {
            op,
            button: op.button(),
            container: *self.c.id(),
            payload: Wrapped::received(b"wrapped at the reader".to_vec()),
            signatures: SignatureSet::default(),
            covered: Vec::new(),
            head,
        };
        e.covered = e.subject();
        let covered = e.covered.clone();
        e.signatures = self.sign_all(&covered, who);
        self.press_signed(e, evidence, page)
    }

    fn press_signed(
        &mut self,
        e: Event,
        evidence: Evidence,
        page: Option<JournalWrite>,
    ) -> Result<(), Stopped> {
        let op = e.op;
        let status = self.status_record(op);
        let keys = self.c.roster().keys().clone();
        // The event's moment: the clock after the page and the status record
        // took their marks from it — no earlier than either.
        let at_ms = Some(self.clock_ms);
        self.c.press(
            &e,
            &evidence,
            Writes {
                page,
                status,
                at_ms,
            },
            &keys,
            &p(),
        )?;
        self.pressed.insert(format!("{op:?}"));
        self.work_off();
        Ok(())
    }

    /// The follow-up worker: discharges what it can prove.
    pub fn work_off(&mut self) {
        while let Some(i) =
            self.c.pending().iter().position(|r| {
                matches!(r.task, Task::WriteLayer { .. } | Task::HandOverLayer { .. })
            })
        {
            let ticket = self.c.claim(i).expect("claimable");
            let proof = match &ticket.task {
                Task::WriteLayer { zone } => Proof::LayerWritten {
                    zone: *zone,
                    digest: Hash::sha256(b"fields written by the issuer"),
                },
                Task::HandOverLayer { to, up_to } => Proof::HandedOver {
                    to: to.clone(),
                    up_to: *up_to,
                    sealed: Hash::sha256(b"sealed hand-over"),
                },
                Task::CarryId { .. } => unreachable!("filtered above"),
            };
            self.c
                .discharge(&Discharge { ticket, proof })
                .expect("the worker's proof");
        }
    }
}
