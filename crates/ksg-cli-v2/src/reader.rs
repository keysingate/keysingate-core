//! The reader: the stand's orchestration, with the container on a disk.
//!
//! Every command goes through [`Container::press`] — the three buttons — and
//! nothing else, as on the stand. After a press that went through, the
//! container is sealed back to disk; after one that was refused, nothing is
//! written, so a refusal leaves the file exactly as it was.

use std::path::Path;

use ksg_container_v2::container::{
    Container, Evidence, JournalWrite, Release, UnloadRoute, Writes,
};
use ksg_container_v2::followup::{Discharge, Proof, Task};
use ksg_container_v2::capsule::{self as capsule, MapRole};
use ksg_container_v2::layers::{Level, OpenWith};
use ksg_container_v2::seal::IssuerSeal;
use ksg_container_v2::{Attachment, Event, Kind, Operation, Role, Roster, Where, Work, Wrapped};
use ksg_core_v2::anchor::Attestation;
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{
    sign_doc, Ed25519Signer, KeySet, Profile, PublicKey, Signature, SignatureSet,
};
use ksg_core_v2::doc::{Class, MemoFormat, Serial, Uri};
use ksg_core_v2::journal::{
    BoundExport, BoundPoint, Draft, Mode, Piece, RecordKind, RecordMeta, Sealing,
};
use ksg_core_v2::section::{section_root, StatusRecord, StatusSection};
use ksg_core_v2::status::{transition_for, Outcome, Status};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::anchoring::{memo_of, AnchorCfg, Anchorer, Landing, MemoKind, PendingAnchor};

/// Why paying what the container owes the network stopped.
enum Settle {
    /// No memo of this round went out: undoing the record is safe.
    NothingSent(String),
    /// A memo went out: the record stays, with its memo owed.
    Owed(String),
}
use crate::channel::{begin_print, begin_template_print, check_sale, Sale};
use crate::clock::{now_ms, utc};
use crate::home::{kid, read, write_atomic, Home, Lock, Meta, Parties, Seeds};
use crate::mobile::LocalMobile;
use crate::mobile::Mobile;
use crate::LOCAL_ANCHOR;
use ksg_core_v2::doc::{AgentBinding, ContainerInit};
use ksg_verify_v2::channel::{holder_uri, verify_channel, ChannelProof, CHANNEL_TYPE};
use ksg_verify_v2::solana::SealScanKey;

/// Who signs a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Who {
    /// The issuer.
    Issuer,
    /// The owner.
    Owner,
    /// The buyer.
    Buyer,
    /// The client — through both halves: the mobile process and the container.
    Client,
    /// The owner arriving with an owner's change: in `bare`, the leader's
    /// owner of an attachment (E-9, 13.10).
    Arriving,
    /// The client a `bare` had before its attachment — through its mobile
    /// half and the half the container kept for the detachment (13.10, A).
    FormerClient,
    /// The distributor that sold the packet, with its desk's key (C-12, 17.10).
    Distributor,
}

/// Whether a command writes a journal record, and which.
#[derive(Debug, Clone)]
pub enum PageSpec {
    /// No record.
    None,
    /// Page 0, the opening.
    Opening,
    /// A record of this kind, with this content.
    Of {
        /// What the record is: work, or an artefact, a disposition, rights.
        kind: RecordKind,
        /// The content, or its digest.
        content: Piece,
        /// What the record is, as a URI (a licence, a policy, …), if given.
        content_type: Option<Uri>,
    },
    /// A record of several content pages and its service page: a file kept
    /// whole in the journal, cut into pages (`[decision]` 17.10).
    Record {
        /// The pages' content, in order.
        pieces: Vec<Piece>,
        /// What the service page says about them.
        meta: RecordMeta,
    },
    /// The page of a change of form (CH-26, CH-27, CH-30).
    Form(Mode),
    /// The hand-off page (CH-16): sealed by the new agent, the transfer
    /// signed by both.
    Handoff,
    /// The page of the rule of two seals (CH-19).
    Rule(ksg_core_v2::journal::SealRule),
    /// A page of the coupling (CH-12).
    Coupling(ksg_core_v2::journal::CouplingRecord),
    /// The page of an owner's change (E-9): to the arriving owner.
    OwnerChange,
}

/// A journal write, sealed, with what its anchor's memo links.
struct Prepared {
    write: JournalWrite,
    /// The seal the write puts on.
    seal: Hash,
    /// The seal before it, or the container's identifier.
    prev: Hash,
}

/// What `init` needs.
#[derive(Debug)]
pub struct InitOptions {
    /// The class of the release.
    pub class: Class,
    /// The release identifier, `ksg:em:NNNNNN`.
    pub emission: String,
    /// The serial within the release.
    pub serial: u64,
    /// The artefact the container is bound to.
    pub artifact: Uri,
    /// Where pages are anchored; `None` — the local placeholder.
    pub anchor: Option<AnchorCfg>,
    /// Printing on a packet bought through the channel; `None` — a container
    /// of its own release, as before P-8. With it, the release, the class
    /// and the serial come from the packet and `emission`, `class` and
    /// `serial` above are ignored.
    pub channel: Option<ChannelInit>,
    /// Where a `light` container anchors on Base Sepolia (owner's decisions
    /// 14.10); `None` — not there.
    pub base: Option<crate::base_anchor::BaseCfg>,
}

/// A container printed on a packet: the sale, the issuer's seed (the issuer
/// prints — `[doc:PRODUCT-DESCRIPTION]`: the issuer is the creator of
/// the container, the channel distributes numbers), and which serial.
pub struct ChannelInit {
    /// The packet as sold.
    pub sale: Sale,
    /// Who prints: the issuer's desk, or the packet's template.
    pub source: PrintSource,
    /// The serial; `None` — the packet's first.
    pub serial: Option<u64>,
}

/// Where a container of a packet is printed from.
#[derive(Debug, Clone)]
pub enum PrintSource {
    /// The issuer's desk: its seed signs the print, and it remembers the
    /// serials printed.
    Desk(std::path::PathBuf),
    /// The packet's template (`crate::channel::Template`): issued once by the
    /// issuer, it prints the quota's serials and remembers them.
    Template(std::path::PathBuf),
}

impl std::fmt::Debug for ChannelInit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChannelInit")
            .field("packet", &self.sale.packet.block)
            .field("serial", &self.serial)
            .finish_non_exhaustive()
    }
}

fn uri(s: &str) -> Uri {
    Uri::parse(s).expect("a constant URI")
}

fn local_anchor(subject: Hash) -> Attestation {
    Attestation {
        kind: uri(LOCAL_ANCHOR),
        subject,
        proof: b"local".to_vec(),
        anchored_at: utc(now_ms()),
    }
}

fn e(x: impl std::fmt::Display) -> String {
    x.to_string()
}

/// Prints a container (E-1): a template with the container's own
/// post-quantum key and the issuer's word on it, written to the home
/// directory. No client's key and no identifier of its own yet — both are
/// born at initiation, [`Reader::initiate`] (KS-8 E-4, CH-5b). Nothing is
/// pressed yet.
///
/// # Errors
///
/// The home directory already holds a container, or a file did not write.
pub fn init(home: &Path, opts: &InitOptions) -> Result<Meta, String> {
    let home = Home(home.to_path_buf());
    std::fs::create_dir_all(&home.0).map_err(|x| format!("{}: {x}", home.0.display()))?;
    if home.container().exists() {
        return Err(format!("{} already holds a container", home.0.display()));
    }
    // What the container is printed as: its own release, or a packet's.
    let (emission_id, class, serial, issued_at, artifact_offset_ms) = match &opts.channel {
        None => {
            crate::testkeys::check_release(&opts.emission)?;
            (
                opts.emission.clone(),
                opts.class,
                Serial(opts.serial),
                utc(now_ms()),
                1,
            )
        }
        Some(ch) => {
            check_sale(&ch.sale)?;
            let packet = &ch.sale.packet;
            let serial = Serial(match (ch.serial, &ch.source) {
                (Some(s), _) => s,
                (None, PrintSource::Desk(_)) => packet.block.from.0,
                (None, PrintSource::Template(t)) => crate::channel::Template::open(t)?
                    .next_serial()
                    .ok_or("the template's quota is used up")?,
            });
            if !packet.covers(serial) {
                return Err(format!(
                    "serial {} is not in the packet {:?}",
                    serial.0, packet.block
                ));
            }
            // The identifier is derived from the release's moment (as
            // `ContainerInit` checks it) and the offset from the packet's origin.
            let origin = crate::clock::parse_ms(packet.origin())
                .ok_or("the packet's allocated_at does not read")?;
            let offset = now_ms().saturating_sub(origin).max(1);
            (
                ch.sale.emission.id.clone(),
                packet.class,
                serial,
                ch.sale.emission.issued_at.clone(),
                offset,
            )
        }
    };
    if let Some(cfg) = &opts.anchor {
        if class == Class::Bare {
            return Err("the base class is never anchored: --anchor is for heavy and light".into());
        }
        // Fail at printing, not at the first page: the node, the cluster, the
        // key or the service.
        probe(cfg)?;
    }

    // The issuer's desk, locked for the print; a serial printed before is refused.
    let printing = match &opts.channel {
        None => None,
        Some(ch) => Some(match &ch.source {
            PrintSource::Desk(d) => begin_print(d, &emission_id, serial.0)?,
            PrintSource::Template(t) => begin_template_print(t, serial.0)?,
        }),
    };
    // The parties `holder` already made, so the packet was sold to this owner.
    let label = crate::testkeys::home_label(&home.0)?;
    let mut seeds = if home.parties().exists() {
        read_seeds(&home)?
    } else {
        Parties::test(&label)
    };
    if let Some(p) = &printing {
        use base64::Engine as _;
        seeds.issuer = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(**p.seed());
    }
    let parties = Parties::from_seeds(&seeds)?;
    if let Some(ch) = &opts.channel {
        if !ch.sale.emission.keys.contains(&parties.issuer.public()) {
            return Err("the print's issuer is not the issuer of this packet's release".into());
        }
        // KS-5: a packet is bound by the key it was sold to, and only its
        // buyer holds that key's secret.
        if ch.sale.packet.holder.as_str() != holder_uri(&parties.owner.public())? {
            return Err(format!(
                "the packet was sold to {}, not to this home's owner (`ksg --home DIR holder`)",
                ch.sale.packet.holder.as_str()
            ));
        }
    }
    // The storage key and the scanning key are test keys of this container
    // (`crate::testkeys`): its home, release and serial. The client's key is
    // not made here: it is born at initiation (CH-5b).
    let this = format!("{label}:{emission_id}:{}", serial.0);
    // Until initiation the container is its template (CH-5b).
    let template = section_root(&emission_id, serial);
    // Goal 1, criterion G1-4: a `bare` printing sets no post-quantum
    // layer — no key is generated, none is stored, the issuer vouches
    // for nothing. Pro and `light` keep the key, as before.
    // Д-4 ([doc:CAPSULE-SPEC] §9): the seal and the post-quantum key are laid
    // at initiation (`Reader::initiate`), so the copies the sale chain keeps
    // from before it carry neither secret.
    let pq: Option<PublicKey> = None;
    let issued_ms = now_ms();

    // Status 0, signed by the issuer: printing is the issuer's act.
    let mut r0 = StatusRecord {
        context: ksg_core_v2::doc::Context,
        doc_type: "StatusRecord".into(),
        v: 3,
        number: 0,
        status: Status::Printed,
        event: None,
        offset_ms: 0,
        prev: section_root(&emission_id, serial),
        signatures: SignatureSet::default(),
    };
    r0.signatures = SignatureSet::new(vec![sign_doc(&r0, &parties.issuer).map_err(e)?]);
    let r0_hash = r0.hash().map_err(e)?;
    let issuer_keys: KeySet = [parties.issuer.public()].into_iter().collect();
    // Checked with the placeholder first: no memo for a record 0 the section
    // would refuse (see `crate::anchoring`).
    StatusSection::start(
        &emission_id,
        serial,
        r0.clone(),
        local_anchor(r0_hash),
        &issuer_keys,
        &Profile::default(),
    )
    .map_err(e)?;
    // Spec v2 §11: a status change is a record and its anchor — record 0
    // included. Anchored in the network when the container is printed with
    // `--anchor`; the placeholder otherwise, and then no status has a time.
    let mut anchor_cfg = opts.anchor.clone();
    let a0 = match &mut anchor_cfg {
        None => local_anchor(r0_hash),
        Some(cfg) => {
            let (att, sig) =
                connect(cfg, &parties.owner, template)?.anchor_status(&r0.prev, &r0_hash)?;
            cfg.last_signature = Some(sig);
            att
        }
    };
    let section = StatusSection::start(
        &emission_id,
        serial,
        r0,
        a0,
        &issuer_keys,
        &Profile::default(),
    )
    .map_err(e)?;

    let roster = Roster::of([
        (parties.issuer.public(), Role::Issuer),
        (parties.owner.public(), Role::Owner),
        (parties.buyer.public(), Role::Buyer),
    ]);
    let mut c = Container::print(
        Release {
            id: emission_id.clone(),
            issued_at: issued_at.clone(),
            class,
        },
        serial,
        MemoFormat::Controlled,
        section,
        roster,
    );
    // The sealed zones are noise until written (owner's decision 18.10 "A");
    // the release zone is the issuer's at printing (E-1, C-1).
    lay_noise(&mut c)?;
    let template_ms = template.to_multihash();
    seal_into(
        &mut c,
        ksg_container_v2::Zone::Release,
        &zone_fields(
            ksg_container_v2::Zone::Release,
            emission_id.as_str(),
            &template_ms,
            &serial.0.to_be_bytes(),
        ),
        &template_ms,
    )?;

    // The issuer vouches, at printing, for the key that signs the
    // container's file outside (`[decision]` 02.10, CH-5a, CH-5b) —
    // except for `bare`, which has no such key (G1-4).
    let pq_cert = pq.as_ref().map(|p| {
        parties
            .issuer
            .sign(&ksg_container_v2::store::pq_cert_message(&template, p))
    });
    let meta = Meta {
        id: template.to_multihash(),
        template: template.to_multihash(),
        class,
        emission: emission_id.clone(),
        issued_at,
        issued_ms,
        serial,
        artifact: opts.artifact.clone(),
        artifact_offset_ms,
        clock_ms: artifact_offset_ms,
        pq_cert,
        client: None,
        pq,
        anchor: anchor_cfg,
        base: opts.base.clone(),
    };

    // The serial is spent before anything is written: a failure below leaves
    // no container on it, never two.
    if let Some(p) = printing {
        p.commit()?;
    }
    // On a packet: the sale, for initiation to bind the agent and the
    // container with (`Reader::initiate`).
    if let Some(ch) = &opts.channel {
        write_atomic(
            &home.sale(),
            &serde_json::to_vec_pretty(&ch.sale).map_err(e)?,
            false,
        )?;
    }
    let key = crate::testkeys::secret(&format!("layer:{this}"));
    write_atomic(&home.layer_key(), &*key, true)?;
    // The holder's scanning key: whoever gets it can recognize this
    // container's anchors in the network (blind seal memo, `[decision]` 13.09).
    let scan = SealScanKey::new(*crate::testkeys::secret(&format!("scan:{this}")));
    write_atomic(&home.scan_key(), scan.to_hex().as_bytes(), true)?;
    let seeds_json = Zeroizing::new(serde_json::to_vec(&seeds).map_err(e)?);
    write_atomic(&home.parties(), &seeds_json, true)?;
    write_atomic(
        &home.meta(),
        &serde_json::to_vec_pretty(&meta).map_err(e)?,
        false,
    )?;
    write_atomic(
        &home.container(),
        &c.seal_to_bytes(&key, &mut OsRng).map_err(e)?,
        false,
    )?;
    Ok(meta)
}

/// Seals a printed container into a capsule — the reader's `init`
/// (`Spec_kapsula` §3, §10 п. 3): the code part (the module's WASM bytes), the
/// state sealed under the holder's layer key, and one map — before initiation
/// the holder's key plays the map's role (§4).
///
/// # Errors
///
/// A file is missing, the state does not open under the layer key, or the
/// capsule does not assemble.
pub fn home_to_capsule(home: &Path, code: &[u8]) -> Result<Vec<u8>, String> {
    let home = Home(home.to_path_buf());
    let meta: Meta = serde_json::from_slice(&read(&home.meta())?)
        .map_err(|x| format!("container.json: {x}"))?;
    let raw = Zeroizing::new(read(&home.layer_key())?);
    let key: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| "layer.key: not 32 bytes")?;
    let template = Hash::from_multihash(&meta.template).map_err(e)?;
    let state = read(&home.container())?;
    // The state must open before it goes in: a capsule no session can read is
    // worse than a refusal at printing.
    let container = Container::open_sealed(&state, &template, &key).map_err(e)?;
    if container.template_id() != template {
        return Err("container.json: the template is not the container's".into());
    }
    let map = OpenWith::from_bytes(key).seal_to();
    // Before initiation there is no client's key, so no `did:key` to name it
    // with (Г-1); after it, the name is the one the birth gave.
    let client = meta
        .client
        .as_ref()
        .map_or_else(|| uri(kid::UNBORN), |k| k.kid.clone());
    let mut rng = OsRng;
    let mut fill = |out: &mut [u8]| rng.fill_bytes(out);
    capsule::seal_into_capsule(
        &state,
        &key,
        &meta.template,
        meta.artifact.as_str(),
        client.as_str(),
        meta.issued_ms,
        meta.clock_ms,
        code,
        &[],
        &[(MapRole::Holder, map)],
        &mut fill,
    )
    .map_err(|x| format!("the capsule does not assemble: {x}"))
}

/// The two core documents a verifier walks the channel with, made at
/// initiation (CH-5b): the packet bound to the buyer's key, and the container
/// initiated on its serial — signed by the client's key just born (both
/// halves) and the owner. `client_signs` is the client at the reader.
/// The client at the reader: signs bytes through both halves.
type ClientSigns<'a> = dyn FnMut(&[u8]) -> Result<Vec<Signature>, String> + 'a;

/// What initiation binds into the container: the serial, the client's key
/// just born, the artefact and its moment, and the identifier they make.
struct Birth<'a> {
    serial: Serial,
    agent: PublicKey,
    artifact: &'a Uri,
    offset_ms: u64,
    container: Hash,
}

fn channel_documents(
    client_signs: &mut ClientSigns<'_>,
    parties: &Parties,
    sale: &Sale,
    birth: Birth<'_>,
) -> Result<ChannelProof, String> {
    let Birth {
        serial,
        agent,
        artifact,
        offset_ms,
        container,
    } = birth;
    let packet = &sale.packet;
    // One binding per packet ("the packet is pinned to this key",
    // `Moment_pokupki_i_ispolzovaniya.md` §3): the packet is bound to the
    // buyer's key, signed by it and by the holder, at the moment the packet
    // was paid for. Nothing in it depends on the container, and Ed25519
    // signatures are deterministic, so every container of the packet carries
    // the same document — the same hash, never a rival.
    let mut binding = AgentBinding {
        context: ksg_core_v2::doc::Context,
        doc_type: "AgentBinding".into(),
        v: ksg_core_v2::version::CURRENT_V,
        emission: packet.emission.clone(),
        block: packet.block,
        agent: parties.buyer.public(),
        bound_at: packet.allocated_at.clone(),
        signatures: SignatureSet::default(),
    };
    binding.signatures = SignatureSet::new(vec![
        sign_doc(&binding, &parties.buyer).map_err(e)?,
        sign_doc(&binding, &parties.owner).map_err(e)?,
    ]);
    let mut init = ContainerInit {
        context: ksg_core_v2::doc::Context,
        doc_type: "ContainerInit".into(),
        v: ksg_core_v2::version::CURRENT_V,
        emission: packet.emission.clone(),
        serial,
        binding: ksg_core_v2::canonical::doc_hash(&binding).map_err(e)?,
        agent,
        artifact: artifact.clone(),
        offset_ms,
        container,
        signatures: SignatureSet::default(),
    };
    let msg = ksg_core_v2::canonical::canonical_bytes(&init).map_err(e)?;
    let client = client_signs(&msg)?
        .into_iter()
        .find(|x| x.kid == init.agent.kid)
        .ok_or("no Ed25519 signature from the client")?;
    init.signatures = SignatureSet::new(vec![client, sign_doc(&init, &parties.owner).map_err(e)?]);
    let proof = ChannelProof {
        doc_type: CHANNEL_TYPE.into(),
        emission: sale.emission.clone(),
        chain: sale.chain.clone(),
        packet: packet.clone(),
        holder_keys: vec![parties.owner.public()],
        binding,
        init,
        closure: None,
    };
    // What a verifier will check, checked before anything is written.
    let client_keys: KeySet = [proof.init.agent.clone()].into_iter().collect();
    let issuer_keys: KeySet = proof.emission.keys.iter().cloned().collect();
    verify_channel(&proof, &container, &issuer_keys, &client_keys)?;
    Ok(proof)
}

fn read_seeds(home: &Home) -> Result<Seeds, String> {
    serde_json::from_slice(&Zeroizing::new(read(&home.parties())?))
        .map_err(|x| format!("parties.json: {x}"))
}

/// The holder closes the packet: signs the closing statement — which serials
/// were used and submitted, which used and not submitted; the rest is
/// cancelled — and lays it into this container's channel bundle, so a
/// verifier sees the packet accounted for (audit of 30.09, Ya-7).
///
/// Checked before it is written, as a verifier will check it: a statement
/// that cancels this container's own serial is refused.
///
/// # Errors
///
/// No channel bundle in `home`, ranges that do not partition the packet, a
/// statement already laid, or one the verifier would refuse.
pub fn close_packet(
    home: &Path,
    used: Vec<ksg_core_v2::doc::Range>,
    not_submitted: Vec<ksg_core_v2::doc::Range>,
) -> Result<ksg_core_v2::doc::BlockClosure, String> {
    let home = Home(home.to_path_buf());
    let _lock = Lock::take(&home)?;
    let mut proof: ChannelProof = serde_json::from_slice(
        &read(&home.channel())
            .map_err(|_| "no channel.json: the container was not printed on a packet, or is not initiated yet (the channel's documents are made at initiation)")?,
    )
    .map_err(|x| format!("channel.json: {x}"))?;
    if proof.closure.is_some() {
        return Err("the packet is already closed in this bundle".into());
    }
    let parties = Parties::from_seeds(&read_seeds(&home)?)?;
    let mut c = ksg_core_v2::doc::BlockClosure::draft(
        proof.packet.emission.clone(),
        proof.packet.block,
        used,
        not_submitted,
        utc(now_ms()),
    );
    c.signatures = SignatureSet::new(vec![sign_doc(&c, &parties.owner).map_err(e)?]);
    proof.closure = Some(c.clone());
    let client_keys: KeySet = [proof.init.agent.clone()].into_iter().collect();
    let issuer_keys: KeySet = proof.emission.keys.iter().cloned().collect();
    verify_channel(&proof, &proof.init.container, &issuer_keys, &client_keys)?;
    write_atomic(
        &home.channel(),
        &serde_json::to_vec_pretty(&proof).map_err(e)?,
        false,
    )?;
    Ok(c)
}

/// K4 (`Bare_v2_spec`, `[decision]` 06.10): the owner deletes a `bare` with
/// everything in it — the container, its keys, the parties' seeds, the
/// reader's files. `template` is the owner's confirmation: the container's
/// own template, as `init` printed it. Returns what was removed.
///
/// Only a `bare`: `light` and Pro keep a journal other parties rely on, and
/// K4 is a criterion of `bare` alone. The class is the one sealed inside the
/// container, not the one `container.json` names. The secret files are
/// overwritten with zeros before they go — `[inference]` best effort: a
/// journaling file system or an SSD may keep the old blocks, which is the
/// stand's lot (keys outside are the stand's, `[decision]` 07.10). A copy
/// elsewhere is another file and is not touched (K3: copying is allowed).
///
/// # Errors
///
/// The container does not open; not a `bare`; `template` is not its own.
pub fn delete_bare(home: &Path, template: &str) -> Result<Vec<std::path::PathBuf>, String> {
    let r = Reader::open(home, Box::new(crate::mobile::NoMobile))?;
    if r.c.class() != Class::Bare {
        return Err(
            "delete: only a bare is deleted by its owner (K4); light and Pro \
                    keep their journal"
                .into(),
        );
    }
    if r.meta.template != template {
        return Err("delete: --template is not this container's — nothing deleted".into());
    }
    let h = &r.home;
    let secret = [h.layer_key(), h.scan_key(), h.parties()];
    let open = [
        h.container(),
        h.meta(),
        h.sale(),
        h.channel(),
        h.handovers(),
    ];
    let mut gone = Vec::new();
    for p in secret.iter().chain(open.iter()) {
        let Ok(len) = std::fs::metadata(p).map(|m| m.len()) else {
            continue;
        };
        if secret.contains(p) {
            let zeros = vec![0u8; usize::try_from(len).unwrap_or(0)];
            std::fs::write(p, &zeros).map_err(|x| format!("{}: {x}", p.display()))?;
        }
        std::fs::remove_file(p).map_err(|x| format!("{}: {x}", p.display()))?;
        gone.push(p.clone());
    }
    // The lock goes last, with the reader.
    drop(r);
    Ok(gone)
}

/// The holder URI a packet is sold to for this home's owner: the owner's
/// public key, which the seller signs into the packet (KS-5). Makes the
/// parties' seeds on first call; the container printed later keeps them.
///
/// # Errors
///
/// The home directory or its seeds file does not read or write.
pub fn holder(home: &Path) -> Result<String, String> {
    let home = Home(home.to_path_buf());
    if !home.parties().exists() {
        std::fs::create_dir_all(&home.0).map_err(|x| format!("{}: {x}", home.0.display()))?;
        let seeds = Parties::test(&crate::testkeys::home_label(&home.0)?);
        let json = Zeroizing::new(serde_json::to_vec(&seeds).map_err(e)?);
        write_atomic(&home.parties(), &json, true)?;
    }
    let parties = Parties::from_seeds(&read_seeds(&home)?)?;
    holder_uri(&parties.owner.public())
}

/// The leader of an attachment, from its home (13.10): its identifier, and
/// its owner's seed under an identifier of its own in this container — the
/// owner arriving with the command. A `bare` is never a leader.
///
/// # Errors
///
/// The home does not read; the leader is `bare`.
fn leader_of(leader_home: &Path) -> Result<(Hash, Seeds), String> {
    let home = Home(leader_home.to_path_buf());
    let meta: Meta = serde_json::from_slice(&read(&home.meta())?)
        .map_err(|x| format!("the leader's container.json: {x}"))?;
    if meta.class == Class::Bare {
        return Err(
            "attach-to: the leader is bare — a trailer is attached to Pro only (13.10)".into(),
        );
    }
    let id = Hash::from_multihash(&meta.id)
        .map_err(|x| format!("the leader's container.json: id: {x}"))?;
    let theirs = read_seeds(&home)?;
    let seeds = Seeds {
        issuer: theirs.issuer.clone(),
        owner: theirs.owner.clone(),
        buyer: theirs.buyer.clone(),
        seal: theirs.seal.clone(),
        owner_kid: Some(format!("did:key:zKsgOwnerOf-{}#k1", meta.id)),
    };
    Ok((id, seeds))
}

/// The owner of another stand home, as the arriving owner of a `bare`'s
/// transfer (17.10): its seed under an identifier of that home's own, as
/// the leader's owner arrives at an attachment.
fn owner_of(home: &Path) -> Result<Seeds, String> {
    let other = Home(home.to_path_buf());
    // A stand home: its container.json must be there.
    let _: Meta = serde_json::from_slice(&read(&other.meta())?)
        .map_err(|x| format!("the new owner's container.json: {x}"))?;
    let theirs = read_seeds(&other)?;
    // Named by its own key, not by the home's container: `bare` templates of
    // one release share one identifier until they are born (K5).
    let public = Parties::from_seeds(&theirs)?.owner.public();
    let tag: String = Hash::sha256(public.key.as_bytes()).as_bytes()[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok(Seeds {
        issuer: theirs.issuer.clone(),
        owner: theirs.owner.clone(),
        buyer: theirs.buyer.clone(),
        seal: theirs.seal.clone(),
        owner_kid: Some(format!("did:key:zKsgOwner-{tag}#k1")),
    })
}

/// Where the issuance label of a `bare` lives on the network (17.10): read
/// from `from_block`, its duplicate written with `key`.
pub struct LabelNet {
    /// The node.
    pub rpc: String,
    /// The contract, `0x…`.
    pub contract: String,
    /// The EVM key that pays for the duplicate's note.
    pub key: std::path::PathBuf,
    /// The block to read from.
    pub from_block: u64,
}

impl LabelNet {
    fn link(&self) -> Result<crate::base_anchor::BaseLink, String> {
        crate::base_anchor::BaseLink::connect(&crate::base_anchor::BaseCfg {
            rpc: self.rpc.clone(),
            contract: self.contract.clone(),
            key: self.key.clone(),
            last: None,
            since: 0,
            last_tx: None,
            pending: Vec::new(),
            share: None,
            salt: None,
            hand_to: None,
            sponsored: false,
            from_block: None,
        })
    }
}

/// The latest issuance label on the contract that `read` opens, and its
/// block. The first one (no passes yet) must have been written by the
/// issuer it names.
///
/// # Errors
///
/// The network does not answer.
pub fn label_on_chain(
    net: &LabelNet,
    read: &[u8; 32],
) -> Result<Option<(crate::issue_label::Label, u64)>, String> {
    let rpc = ksg_verify_v2::solana::HttpRpc::new(&net.rpc)?;
    let contract: [u8; 20] = ksg_anchor_v2::evm::unhex(&net.contract)
        .map_err(|x| x.to_string())?
        .try_into()
        .map_err(|_| "the contract is not 20 bytes".to_owned())?;
    let notes = ksg_verify_v2::base::notes(
        &rpc,
        &contract,
        &ksg_anchor_v2::evm::note_kind(crate::issue_label::LABEL_TAG),
        net.from_block,
    )?;
    let mut found = None;
    for n in notes {
        let Ok(memo) = std::str::from_utf8(&n.data) else {
            continue;
        };
        let Ok(l) = crate::issue_label::open(memo, read) else {
            continue;
        };
        if l.passes.is_empty()
            && !ksg_anchor_v2::evm::hex0x(&n.sender).eq_ignore_ascii_case(&l.issuer)
        {
            continue;
        }
        found = Some((l, n.block));
    }
    Ok(found)
}

/// A zone's fields: the zone's name, the emission, the template and what
/// the zone holds, each with its length.
fn zone_fields(
    zone: ksg_container_v2::Zone,
    emission: &str,
    template: &str,
    content: &[u8],
) -> Vec<u8> {
    let mut f = Vec::new();
    for part in [
        format!("{zone:?}").as_bytes(),
        emission.as_bytes(),
        template.as_bytes(),
        content,
    ] {
        f.extend_from_slice(&(part.len() as u16).to_be_bytes());
        f.extend_from_slice(part);
    }
    f
}

/// The key of the level that writes a zone's position: the release — level
/// 0, the packet — 1, the chain's positions — 2 on. On the stand the levels'
/// keys are the test keys of public labels, as in the hand-over of layer keys
/// (`[decision]` 07.10: keys outside are the stand's).
#[must_use]
pub fn zone_key_of(template: &str, position: usize) -> ksg_container_v2::layers::LayerKey {
    ksg_container_v2::layers::LayerKey::from_bytes(*crate::testkeys::secret(&format!(
        "layer-level:{}:{template}",
        position.min(7)
    )))
}

/// Seals `fields` for the next free position of `zone` under its level's
/// key, bound to the template, and writes it. Returns the sealed bytes'
/// digest.
fn seal_into(
    c: &mut Container,
    zone: ksg_container_v2::Zone,
    fields: &[u8],
    template: &str,
) -> Result<Hash, String> {
    use ksg_container_v2::layout::{seal_zone, zone_position, ZONE_BYTES};
    use rand_core::RngCore as _;
    let binding = Hash::from_multihash(template).map_err(|x| x.to_string())?;
    let mut nth = 0;
    let position = loop {
        let p = zone_position(zone, nth).map_err(e)?;
        if c.sealed_zone_written(p) {
            nth += 1;
            continue;
        }
        break p;
    };
    let mut random = Zeroizing::new(vec![0u8; ZONE_BYTES]);
    OsRng.fill_bytes(&mut random);
    let sealed = seal_zone(
        &zone_key_of(template, position),
        binding.as_bytes(),
        position,
        fields,
        &random,
    )
    .map_err(e)?;
    let digest = Hash::sha256(&sealed);
    c.write_zone(zone, sealed).map_err(e)?;
    Ok(digest)
}

/// Lays the noise of the sealed zones from the OS's CSPRNG (18.10 "A").
fn lay_noise(c: &mut Container) -> Result<(), String> {
    use ksg_container_v2::layout::{ZONE_BYTES, ZONE_POSITIONS};
    use rand_core::RngCore as _;
    let mut random = Zeroizing::new(vec![0u8; ZONE_POSITIONS * ZONE_BYTES]);
    OsRng.fill_bytes(&mut random);
    c.lay_zone_noise(&random).map_err(e)
}

/// A container opened from its home directory, ready to press.
pub struct Reader {
    home: Home,
    key: Zeroizing<[u8; 32]>,
    parties: Parties,
    /// What the reader knows about the container.
    pub meta: Meta,
    /// The container.
    pub c: Container,
    mobile: Box<dyn Mobile>,
    /// The new agent's mobile half during a hand-off.
    incoming: Option<LocalMobile>,
    /// The arriving owner during an owner's change (E-9).
    arriving: Option<Ed25519Signer>,
    /// The former client's mobile half during a detachment.
    former: Option<Box<dyn Mobile>>,
    /// The distributor's desk key while it signs a declaration (C-12).
    distributor: Option<Ed25519Signer>,
    anchorer: Option<(Anchorer, SealScanKey)>,
    /// The node on Base Sepolia, when it answered at opening.
    base: Option<crate::base_anchor::BaseLink>,
    /// The chain's head is past this file: a copy or an older file. Only the
    /// full export goes (owner's decisions 03.10, 05.10).
    pub copy: bool,
    _lock: Lock,
}

#[cfg(feature = "rpc")]
fn connect(cfg: &AnchorCfg, owner: &Ed25519Signer, container: Hash) -> Result<Anchorer, String> {
    Anchorer::connect(cfg, owner, container)
}

#[cfg(not(feature = "rpc"))]
fn connect(_cfg: &AnchorCfg, _owner: &Ed25519Signer, _container: Hash) -> Result<Anchorer, String> {
    Err("built without the `rpc` feature: no way to reach a node".into())
}

#[cfg(feature = "rpc")]
fn connect_base(cfg: &crate::base_anchor::BaseCfg) -> Result<crate::base_anchor::BaseLink, String> {
    crate::base_anchor::BaseLink::connect(cfg)
}

#[cfg(not(feature = "rpc"))]
fn connect_base(
    _cfg: &crate::base_anchor::BaseCfg,
) -> Result<crate::base_anchor::BaseLink, String> {
    Err("built without the `rpc` feature: no way to reach a node".into())
}

#[cfg(feature = "rpc")]
fn probe(cfg: &AnchorCfg) -> Result<(), String> {
    Anchorer::probe(cfg)
}

#[cfg(not(feature = "rpc"))]
fn probe(_cfg: &AnchorCfg) -> Result<(), String> {
    Err("built without the `rpc` feature: no way to reach a node".into())
}

/// The holder's scanning key from `scan.key`.
///
/// # Errors
///
/// The file is missing or is not a key.
pub fn read_scan_key(home: &Home) -> Result<SealScanKey, String> {
    let raw = Zeroizing::new(read(&home.scan_key())?);
    let s = std::str::from_utf8(&raw).map_err(|_| "scan.key: not text")?;
    SealScanKey::from_hex(s)
}

impl Prepared {
    fn anchored(&self) -> bool {
        match &self.write {
            JournalWrite::Open { sealing, .. } | JournalWrite::Record { sealing, .. } => {
                sealing.anchor.is_some()
            }
        }
    }
}

/// The outer word on the file before it is opened (`[decision]` 02.10,
/// CH-5a, CH-5b): the issuer vouched at printing for the container's
/// post-quantum key, and that key signed this file. A file signed by any
/// other key — a container passed off as this one — is refused without the
/// layer key.
fn check_outer(
    meta: &Meta,
    issuer: &PublicKey,
    template: &Hash,
    bytes: &[u8],
) -> Result<(), String> {
    // Goal 1, criterion G1-4: a `bare` container has no post-quantum
    // key — nothing to vouch for, nothing signed outside. The file
    // must then carry no outer signature; anything else is refused.
    if meta.class == Class::Bare {
        if meta.pq.is_some() || meta.pq_cert.is_some() {
            return Err("container.json: a bare container carries no post-quantum key".into());
        }
        return ksg_container_v2::store::verify_absent_outer(bytes).map_err(e);
    }
    // Д-4: before initiation a container holds no post-quantum key, so its
    // file carries no outer signature — exactly as `bare` (anything else is refused).
    if meta.client.is_none() && meta.pq.is_none() && meta.pq_cert.is_none() {
        return ksg_container_v2::store::verify_absent_outer(bytes).map_err(e);
    }
    let Some(cert) = &meta.pq_cert else {
        return Err("container.json: no issuer's word on the container's key (pq_cert)".into());
    };
    let Some(pq) = &meta.pq else {
        return Err("container.json: no container key (pq)".into());
    };
    let mut keys = KeySet::new();
    keys.insert(issuer.clone());
    SignatureSet::new(vec![cert.clone()])
        .verify(
            &ksg_container_v2::store::pq_cert_message(template, pq),
            &keys,
            &Profile::default().with_ed25519(),
        )
        .map_err(|x| format!("container.json: the issuer's word on the key: {x}"))?;
    ksg_container_v2::store::verify_outer(bytes, template, pq).map_err(e)?;
    Ok(())
}

impl Reader {
    /// Opens the container in `home`, with `mobile` as the client's half.
    ///
    /// # Errors
    ///
    /// A file is missing, or the sealed bytes do not open under the layer key.
    pub fn open(home: &Path, mobile: Box<dyn Mobile>) -> Result<Self, String> {
        let home = Home(home.to_path_buf());
        let lock = Lock::take(&home)?;
        let mut meta: Meta = serde_json::from_slice(&read(&home.meta())?)
            .map_err(|x| format!("container.json: {x}"))?;
        let raw = Zeroizing::new(read(&home.layer_key())?);
        let key: [u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| "layer.key: not 32 bytes")?;
        let key = Zeroizing::new(key);
        let parties = Parties::from_seeds(&read_seeds(&home)?)?;
        let template = Hash::from_multihash(&meta.template)
            .map_err(|x| format!("container.json: template: {x}"))?;
        let bytes = read(&home.container())?;
        check_outer(&meta, &parties.issuer.public(), &template, &bytes)?;
        let c = Container::open_sealed(&bytes, &template, &key).map_err(e)?;
        // `check_outer` skipped the outer signature because container.json
        // says `bare` — a file the holder writes. The class sealed inside the
        // container is the one that counts: a Pro or `light` file stripped of
        // its signature and relabelled `bare` stops here.
        if meta.class == Class::Bare && c.class() != Class::Bare {
            return Err("container.json says bare, the container is not: its outer \
                        signature is missing"
                .into());
        }
        if c.id().to_multihash() != meta.id {
            return Err("container.json: the identifier is not the container's".into());
        }
        let id = *c.id();
        let anchorer = match &meta.anchor {
            None => None,
            Some(cfg) => {
                // The service knows the container by its template: the one
                // identifier it has from printing to the end (CH-5b).
                let a = connect(cfg, &parties.owner, c.template_id())?;
                let scan = read_scan_key(&home)?;
                // K5: an older copy of the container does not open.
                let head = c.top_seal_hash().unwrap_or(id);
                a.check_rollback(
                    &cfg.seal_keys(&scan, &crate::anchoring::current_scan_period()),
                    &head,
                    &c.status_head(),
                    cfg.last_signature.as_deref(),
                )?;
                Some((a, scan))
            }
        };
        // Base Sepolia (`light`): the copy check at opening, if the node
        // answers. A node that does not answer is the ten offline records'
        // business, not a refusal here.
        let mut copy = false;
        // An anchor this file sent and did not see land may be the head now:
        // then it is this file's own, not another copy's (settled below).
        let mut settled = false;
        let base = match meta.base.clone() {
            // `light` anchors here; Pro reads only E-19 here (16.10 "A").
            Some(mut cfg) if matches!(meta.class, Class::Light | Class::Heavy) => {
                match connect_base(&cfg) {
                    Ok(link) => {
                        let t = cfg.anchor_key(&c.template_id())?;
                        let kind = |tag: &str| ksg_anchor_v2::evm::note_kind(tag);
                        let read = ksg_verify_v2::base::loss(
                            link.rpc(),
                            link.contract(),
                            &t,
                            &kind,
                            cfg.from_block.unwrap_or(0),
                        )
                        .and_then(|l| Ok((l, link.head(&t)?)))
                        .and_then(|(l, h)| {
                            if cfg.settle(&h.last) {
                                settled = true;
                                meta.base = Some(cfg.clone());
                            }
                            let mine = cfg.last_bytes()?;
                            Ok((l, ksg_verify_v2::base::check_not_stale(&h, mine.as_ref())))
                        });
                        match read {
                            // E-19: a container its client's half declared lost
                            // is not opened (status 9).
                            Ok((ksg_verify_v2::base::Loss::Declared { block, .. }, _)) => {
                                return Err(format!(
                                    "the client declared this container lost (Base Sepolia, \
                                 block {block}): it does not open"
                                ));
                            }
                            // The copy check is `light`'s: Pro's head is on Solana.
                            Ok((_, ksg_verify_v2::base::Standing::Stale { .. }))
                                if meta.class == Class::Light =>
                            {
                                copy = true;
                                Some(link)
                            }
                            Ok(_) => Some(link),
                            // The node stopped answering half-way: as offline as
                            // one that does not answer at all.
                            Err(_) => None,
                        }
                    }
                    Err(_) => None,
                }
            }
            _ => None,
        };
        // Only the record of what landed changes: the container is untouched.
        if settled {
            write_atomic(
                &home.meta(),
                &serde_json::to_vec_pretty(&meta).map_err(e)?,
                false,
            )?;
        }
        Ok(Self {
            home,
            key,
            parties,
            meta,
            c,
            mobile,
            incoming: None,
            arriving: None,
            former: None,
            distributor: None,
            anchorer,
            base,
            copy,
            _lock: lock,
        })
    }

    fn save(&self) -> Result<(), String> {
        let bytes = self.c.seal_to_bytes(&self.key, &mut OsRng).map_err(e)?;
        // What the container is now — after initiation, born (CH-5b).
        let mut meta = self.meta.clone();
        meta.id = self.c.id().to_multihash();
        // The client's key born at initiation: the first agent's, kept after
        // a hand-off — what its pages from page 0 are checked against.
        if meta.client.is_none() {
            meta.client = self.c.agent().cloned();
        }
        write_atomic(&self.home.container(), &bytes, false)?;
        write_atomic(
            &self.home.meta(),
            &serde_json::to_vec_pretty(&meta).map_err(e)?,
            false,
        )
    }

    fn signer(&self, who: Who) -> Option<&Ed25519Signer> {
        match who {
            Who::Issuer => Some(&self.parties.issuer),
            Who::Owner => Some(&self.parties.owner),
            Who::Buyer => Some(&self.parties.buyer),
            Who::Arriving => self.arriving.as_ref(),
            Who::Distributor => self.distributor.as_ref(),
            Who::Client | Who::FormerClient => None,
        }
    }

    /// The buyer's key.
    #[must_use]
    pub fn buyer(&self) -> PublicKey {
        self.parties.buyer.public()
    }

    /// The client signs: its mobile half in the other process, the
    /// container's half here.
    ///
    /// # Errors
    ///
    /// Either half refused.
    pub fn client_signs(&mut self, msg: &[u8]) -> Result<Vec<Signature>, String> {
        let commitment = self.mobile.commit()?;
        let round = self
            .c
            .begin_signing(msg, &commitment, &mut OsRng)
            .map_err(e)?;
        let share = self.mobile.respond(&round)?;
        self.c.finish_signing(&share, &mut OsRng).map_err(e)
    }

    /// The new agent signs during a hand-off: its mobile half, the half of
    /// its key the container made and holds.
    fn incoming_signs(&mut self, msg: &[u8]) -> Result<Vec<Signature>, String> {
        let m = self.incoming.as_mut().ok_or("no hand-off staged")?;
        let commitment = m.commit()?;
        let round = self
            .c
            .begin_signing_incoming(msg, &commitment, &mut OsRng)
            .map_err(e)?;
        let share = m.respond(&round)?;
        self.c
            .finish_signing_incoming(&share, &mut OsRng)
            .map_err(e)
    }

    /// The hand-off page's seals (CH-3, CH-16, CH-17): the movable seal is
    /// the new agent's alone; the transfer seal takes both agents' Ed25519.
    fn seal_handoff(&mut self, draft: Draft) -> Result<Prepared, String> {
        let bytes = draft.seal_bytes().map_err(e)?;
        let seal = draft.seal_hash().map_err(e)?;
        let prev = draft.seal().prev.unwrap_or(*self.c.id());
        let tb = draft
            .transfer_bytes()
            .map_err(e)?
            .ok_or("the hand-off page carries no transfer")?;
        let ed = |v: Vec<Signature>| -> Vec<Signature> {
            v.into_iter()
                .filter(|x| x.alg == ksg_core_v2::crypto::sign::Alg::Ed25519)
                .collect()
        };
        let mut transfer = ed(self.client_signs(&tb)?);
        transfer.extend(ed(self.incoming_signs(&tb)?));
        let mut sealing = Sealing {
            seal: SignatureSet::new(self.incoming_signs(&bytes)?),
            transfer: Some(SignatureSet::new(transfer)),
            ..Sealing::default()
        };
        if draft.is_pro() && self.c.class() != Class::Bare {
            sealing.anchor = Some(local_anchor(seal));
        }
        Ok(Prepared {
            write: JournalWrite::Record {
                draft: Box::new(draft),
                sealing: Box::new(sealing),
            },
            seal,
            prev,
        })
    }

    /// The agent hands the container to another agent of the same owner
    /// (CH-16, CH-17): the container makes the new agent's key inside, the
    /// new agent's mobile half goes to `out`, and from the hand-off page on
    /// only the new agent seals. `name` names the new agent.
    ///
    /// The half is written **before** the page goes in — without it the
    /// container could never sign again — and removed if the page does not.
    ///
    /// # Errors
    ///
    /// See [`Reader::press`]; the file could not be written.
    pub fn handoff(&mut self, name: &Uri, out: &Path) -> Result<(), String> {
        self.handoff_keeping(name, out).map(drop)
    }

    /// As [`Reader::handoff`], handing back the new agent's mobile half for
    /// what this process presses next.
    fn handoff_keeping(&mut self, name: &Uri, out: &Path) -> Result<LocalMobile, String> {
        let kid = Uri::parse(format!("{}#key-1", name.as_str())).map_err(e)?;
        // The new agent's key is born without a dealer (CH-5b): its mobile
        // side here, the container's half inside.
        let (keygen, hello) =
            ksg_container_v2::client_key::MobileKeygen::start(kid.clone(), &mut OsRng)
                .map_err(e)?;
        let reply = self
            .c
            .begin_handoff_birth(kid, &hello, &mut OsRng)
            .map_err(e)?;
        let (half, public, fin) = keygen.finish(&reply).map_err(e)?;
        if self.c.finish_handoff_birth(&fin).map_err(e)? != public {
            self.c.cancel_handoff();
            return Err("the two sides of the birth hold halves of different keys".into());
        }
        let bytes = half.to_bytes().map_err(e)?;
        if let Err(x) = write_atomic(out, &bytes, true) {
            self.c.cancel_handoff();
            return Err(x);
        }
        self.incoming = Some(LocalMobile::new(half));
        let r = self.press(
            Operation::RecordWork,
            &[Who::Client],
            Evidence::Handoff,
            PageSpec::Handoff,
        );
        let incoming = self.incoming.take();
        if let Err(x) = r {
            self.c.cancel_handoff();
            let _ = std::fs::remove_file(out);
            return Err(x);
        }
        incoming.ok_or_else(|| "the hand-off lost the new agent's half".into())
    }

    /// The attachment of a `bare` as a trailer (13.10), the whole order:
    ///
    /// 1. the owner's change (E-9): the leader's owner arrives with the
    ///    command and signs beside this container's owner; from then on it is
    ///    this container's owner, and `parties.json` holds its key;
    /// 2. the hand-off to the leader's agent: its key is born inside, its
    ///    mobile half goes to `new_mobile`; the client's half this `bare` had
    ///    stays inside for the detachment, and its mobile half stays where it
    ///    is — the file given with `--mobile`;
    /// 3. slot 1 of the coupling, sealed by the leader's agent.
    ///
    /// A step that went in is not repeated: a run stopped half-way goes on
    /// from where it stopped (step 3 then needs the new agent's half as the
    /// `--mobile`).
    ///
    /// # Errors
    ///
    /// Not a `bare`, attached already, a `bare` leader, the leader's home
    /// unreadable; see [`Reader::press`].
    pub fn attach_to(
        &mut self,
        leader_home: &Path,
        agent: &Uri,
        new_mobile: Option<&Path>,
        label: Option<&LabelNet>,
    ) -> Result<(), String> {
        if self.c.class() != Class::Bare {
            return Err("attach-to: only a bare attaches as a trailer (13.10); \
                        a Pro or light container is succeeded with `succeed`"
                .into());
        }
        if self.c.burned() {
            return Err("attach-to: this copy was detached and burned".into());
        }
        if self.c.bare_attached() {
            return Err("attach-to: this bare is attached already".into());
        }
        let (leader, owner_seeds) = leader_of(leader_home)?;
        if leader == *self.c.id() {
            return Err("attach-to: a container is not its own leader".into());
        }
        let owner = Parties::from_seeds(&owner_seeds)?.owner;
        // 1. The owner's change, once — and with the network, the issuance
        // label read by the former owner before its seat changes (17.10 "B").
        let mut moving = None;
        if !self.c.bare_attaching() {
            if let Some(net) = label {
                let former = Parties::from_seeds(&read_seeds(&self.home)?)?.owner;
                let (l, _) = label_on_chain(net, &*self.owner_read_secret()?)?
                    .ok_or("attach-to: no issuance label of this owner on the network")?;
                if l.current_owner().key != former.public().key {
                    return Err("attach-to: the label found is not this owner's".into());
                }
                moving = Some((l, former));
            }
            let key = owner.public();
            self.arriving = Some(owner);
            let r = self.press(
                Operation::TransferOwnership,
                &[Who::Owner, Who::Arriving],
                Evidence::NewOwner(key),
                PageSpec::OwnerChange,
            );
            self.arriving = None;
            r?;
        }
        self.adopt_owner(&owner_seeds)?;
        if self.c.owner_read_key().is_none() {
            self.publish_owner_read_key()?;
        }
        // 1-b. The label passed on to the leader's owner: in the journal and
        // on the network, before the hand-off (17.10 "B").
        if let (Some((l, former)), Some(net)) = (moving, label) {
            let read = self
                .c
                .owner_read_key()
                .ok_or("attach-to: the leader's owner has no read key")?;
            let next = l.pass_to(&former, self.parties.owner.public(), now_ms())?;
            self.write_label(&next, &read, Some(net))?;
        }
        // 2. The hand-off to the leader's agent, once.
        if self.c.roster().holder(Role::FormerClient).is_none() {
            let out =
                new_mobile.ok_or("attach-to: --new-mobile FILE for the leader's agent's half")?;
            let incoming = self.handoff_keeping(agent, out)?;
            self.mobile = Box::new(incoming);
        }
        // 3. Slot 1 of the coupling: the last page this `bare` writes.
        let c = ksg_core_v2::journal::CouplingRecord::AttachedTo { leader };
        self.press(
            Operation::RecordWork,
            &[Who::Client],
            Evidence::Coupling(c.clone()),
            PageSpec::Coupling(c),
        )
    }

    /// After the owner's change of an attachment, `parties.json` holds the
    /// owner the container holds: the leader's (13.10). Nothing to do when it
    /// does already; refused when the container's owner is somebody else's.
    fn adopt_owner(&mut self, leader_owner: &Seeds) -> Result<(), String> {
        let theirs = Parties::from_seeds(leader_owner)?.owner;
        let held = self.c.roster().holder(Role::Owner).cloned();
        if held.as_ref() != Some(&theirs.public()) {
            return Err(
                "attach-to: this container's owner is not the leader's owner — \
                        it was changed for another leader"
                    .into(),
            );
        }
        if self.parties.owner.public() == theirs.public() {
            return Ok(());
        }
        let mut seeds = read_seeds(&self.home)?;
        seeds.owner.clone_from(&leader_owner.owner);
        seeds.owner_kid.clone_from(&leader_owner.owner_kid);
        let json = Zeroizing::new(serde_json::to_vec_pretty(&seeds).map_err(e)?);
        write_atomic(&self.home.parties(), &json, true)?;
        self.parties.owner = theirs;
        Ok(())
    }

    /// The detachment of an attached `bare` (13.10): the owner — the
    /// leader's, since the attachment — and the client it had before it sign;
    /// the copy is burned. `former` is that client's mobile half.
    ///
    /// # Errors
    ///
    /// Not an attached `bare`; see [`Reader::press`].
    pub fn detach(&mut self, former: Box<dyn Mobile>) -> Result<(), String> {
        self.former = Some(former);
        let r = self.press(
            Operation::Detach,
            &[Who::Owner, Who::FormerClient],
            Evidence::None,
            PageSpec::None,
        );
        self.former = None;
        r
    }

    /// Sets or lifts the rule of two seals (E-7, CH-19): the agent presses,
    /// the owner seals the page beside the agent.
    ///
    /// # Errors
    ///
    /// See [`Reader::press`].
    pub fn rule(&mut self, rule: ksg_core_v2::journal::SealRule) -> Result<(), String> {
        self.press(
            Operation::AttachArtifactOrRights,
            &[Who::Client],
            Evidence::Rule(rule.clone()),
            PageSpec::Rule(rule),
        )
    }

    /// Succession (E-14, the issuer) with slot 1 of the coupling: this
    /// container is attached to `leader`, its successor (CH-12).
    ///
    /// # Errors
    ///
    /// See [`Reader::press`].
    pub fn succeed_to(&mut self, leader: Hash) -> Result<(), String> {
        let c = ksg_core_v2::journal::CouplingRecord::AttachedTo { leader };
        self.press(
            Operation::Succeed,
            &[Who::Issuer],
            Evidence::Coupling(c.clone()),
            PageSpec::Coupling(c),
        )
    }

    /// Slot 2 of the coupling (E-5, CH-12): this container pulls `trailer`,
    /// whose last seal is `trailer_seal`.
    ///
    /// # Errors
    ///
    /// See [`Reader::press`].
    pub fn pull(&mut self, trailer: Hash, trailer_seal: Hash) -> Result<(), String> {
        let c = ksg_core_v2::journal::CouplingRecord::Pulls {
            trailer,
            trailer_seal,
        };
        self.press(
            Operation::RecordWork,
            &[Who::Client],
            Evidence::Coupling(c.clone()),
            PageSpec::Coupling(c),
        )
    }

    fn sign_all(&mut self, msg: &[u8], who: &[Who]) -> Result<SignatureSet, String> {
        let mut sigs = Vec::new();
        for w in who {
            match w {
                Who::Client => sigs.extend(self.client_signs(msg)?),
                Who::FormerClient => sigs.extend(self.former_signs(msg)?),
                _ => sigs.push(
                    self.signer(*w)
                        .ok_or("no signer of this party for this command")?
                        .sign(msg),
                ),
            }
        }
        Ok(SignatureSet::new(sigs))
    }

    /// The former client signs the detachment: its mobile half in the other
    /// process, the half the container kept for it here (13.10, variant A).
    fn former_signs(&mut self, msg: &[u8]) -> Result<Vec<Signature>, String> {
        let m = self
            .former
            .as_mut()
            .ok_or("no former client's half for this command")?;
        let commitment = m.commit()?;
        let round = self
            .c
            .begin_signing_former(msg, &commitment, &mut OsRng)
            .map_err(e)?;
        let share = m.respond(&round)?;
        self.c.finish_signing_former(&share, &mut OsRng).map_err(e)
    }

    // Offsets are milliseconds since issuance and grow strictly, even when
    // the wall clock does not.
    fn tick(&mut self) -> u64 {
        let elapsed = now_ms().saturating_sub(self.meta.issued_ms);
        self.meta.clock_ms = elapsed.max(self.meta.clock_ms + 1);
        self.meta.clock_ms
    }

    fn page(&mut self, spec: PageSpec) -> Result<Option<Prepared>, String> {
        let offset_ms = self.tick();
        let draft = match spec {
            PageSpec::None => return Ok(None),
            PageSpec::Opening => {
                let (bytes, seal) = self.c.opening_seal(offset_ms).map_err(e)?;
                // Pro opens with the owner's seal and the anchor (CH-26); the
                // light form with the agent's seal alone. `bare` never
                // anchors (G1-4) — its opening form is local anyway.
                let pro = self.c.opening_form() == Mode::Pro && self.c.class() != Class::Bare;
                let sealing = Sealing {
                    seal: SignatureSet::new(self.client_signs(&bytes)?),
                    owner: pro.then(|| SignatureSet::new(vec![self.parties.owner.sign(&bytes)])),
                    anchor: pro.then(|| local_anchor(seal)),
                    ..Sealing::default()
                };
                return Ok(Some(Prepared {
                    write: JournalWrite::Open {
                        offset_ms,
                        sealing: Box::new(sealing),
                    },
                    seal,
                    prev: *self.c.id(),
                }));
            }
            PageSpec::Of {
                kind,
                content,
                content_type,
            } => self.c.draft_record(
                vec![content],
                RecordMeta {
                    kind,
                    content_type,
                    ..RecordMeta::default()
                },
                offset_ms,
            ),
            PageSpec::Record { pieces, meta } => self.c.draft_record(pieces, meta, offset_ms),
            PageSpec::Form(to) => self.c.draft_form(to, offset_ms),
            PageSpec::Rule(r) => self.c.draft_rule(r, offset_ms),
            PageSpec::Coupling(c) => self.c.draft_coupling(c, offset_ms),
            PageSpec::OwnerChange => match &self.arriving {
                Some(a) => self.c.draft_owner_change_to_key(&a.public(), offset_ms),
                None => self.c.draft_owner_change(offset_ms),
            },
            PageSpec::Handoff => {
                let draft = self.c.draft_handoff(offset_ms).map_err(e)?;
                return self.seal_handoff(draft).map(Some);
            }
        }
        .map_err(e)?;
        self.seal_draft(draft).map(Some)
    }

    /// Seals a drafted record the way its parties do: the client's seal
    /// through both halves; the owner's where the journal asks for it (CH-29);
    /// both sides of a transfer; the local placeholder anchor in Pro, which
    /// `press_inner` swaps for a network anchor.
    fn seal_draft(&mut self, draft: Draft) -> Result<Prepared, String> {
        let bytes = draft.seal_bytes().map_err(e)?;
        let seal = draft.seal_hash().map_err(e)?;
        let prev = draft.seal().prev.unwrap_or(*self.c.id());
        let mut sealing = Sealing {
            seal: SignatureSet::new(self.client_signs(&bytes)?),
            ..Sealing::default()
        };
        if draft.needs_owner() {
            sealing.owner = Some(SignatureSet::new(vec![self.parties.owner.sign(&bytes)]));
        }
        if let Some(tb) = draft.transfer_bytes().map_err(e)? {
            let mut sigs = self.client_signs(&tb)?;
            sigs.push(self.parties.owner.sign(&tb));
            // The arriving side: the owner arriving with the command when
            // there is one (E-9 of an attachment), else the buyer.
            sigs.push(
                self.arriving
                    .as_ref()
                    .unwrap_or(&self.parties.buyer)
                    .sign(&tb),
            );
            sealing.transfer = Some(SignatureSet::new(sigs));
        }
        if draft.is_pro() {
            sealing.anchor = Some(local_anchor(seal));
        }
        Ok(Prepared {
            write: JournalWrite::Record {
                draft: Box::new(draft),
                sealing: Box::new(sealing),
            },
            seal,
            prev,
        })
    }

    fn status_record(
        &mut self,
        op: Operation,
    ) -> Result<Option<(StatusRecord, Attestation)>, String> {
        let Some(ev) = op.event() else {
            return Ok(None);
        };
        // Goal 1, `bare` v2: the record is built through the same
        // class-aware route the container presses through.
        let Outcome::Moves(next) =
            transition_for(self.c.class(), self.c.status(), self.c.blocked(), ev)
        else {
            return Ok(None);
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
        r.signatures = SignatureSet::new(vec![sign_doc(&r, &self.parties.issuer).map_err(e)?]);
        let a = local_anchor(r.hash().map_err(e)?);
        Ok(Some((r, a)))
    }

    /// Presses the button of `op`, signed by `who`, with `evidence`, writing
    /// `page`; lets the follow-up worker do its part; seals the container back
    /// to disk.
    ///
    /// # Errors
    ///
    /// The container refused (nothing is written), or signing or saving failed.
    pub fn press(
        &mut self,
        op: Operation,
        who: &[Who],
        evidence: Evidence,
        page: PageSpec,
    ) -> Result<(), String> {
        // A copy, or an older file, does only the full export.
        if self.copy && op != Operation::FullExport {
            return Err(
                "this file is a copy, or an older file, of the container: the chain \
                        continued after it (Base Sepolia). Only the full export is allowed"
                    .into(),
            );
        }
        // `light` on Base Sepolia: a value goes out only on a fresh anchor; a
        // record past the ten offline ones waits for the network.
        let on_base = self.meta.class == Class::Light && self.meta.base.is_some();
        let writes = !matches!(page, PageSpec::None);
        if on_base {
            let due = matches!(op, Operation::ExportPoint | Operation::TransferOwnership)
                || (writes
                    && self.meta.base.as_ref().map_or(0, |b| b.since)
                        >= crate::base_anchor::OFFLINE_RECORDS);
            if due {
                self.base_anchor()?;
            }
        }
        // What an earlier command left owed is paid before anything new is
        // written: a record goes on top only of records the network holds.
        if self.owes_anchor() {
            self.settle().map_err(|x| match x {
                Settle::NothingSent(x) | Settle::Owed(x) => x,
            })?;
        }
        let clock = self.meta.clock_ms;
        let result = self.press_inner(op, who, &evidence, page);
        if result.is_err() {
            // A refusal writes nothing, the clock included.
            self.meta.clock_ms = clock;
            return result;
        }
        if on_base {
            if let Some(b) = &mut self.meta.base {
                if writes {
                    b.since += 1;
                }
            }
        }
        self.save()?;
        // E-19 for Pro (owner's decision 16.10 "A"): Base Sepolia carries the
        // commitment to the mobile half and nothing else of Pro — one anchor
        // makes this key the writer, the note follows. Best effort: while the
        // commitment waits, every press tries again; Pro's own anchors are
        // Solana's and do not wait for Base.
        if self.meta.class == Class::Heavy
            && self.meta.base.as_ref().is_some_and(|b| b.share.is_some())
            && self.c.born()
        {
            let _ = self.base_anchor();
        }
        // Ya-2: the client's key is on — anchored at once if the network is
        // there; if not, the next record waits for it.
        if on_base && op == Operation::Initiate && self.base_anchor().is_err() {
            if let Some(b) = &mut self.meta.base {
                b.since = crate::base_anchor::OFFLINE_RECORDS;
            }
            self.save()?;
        }
        Ok(())
    }

    /// Anchors the container's newest signed thing on Base Sepolia — its top
    /// seal, else its status head — after the last anchor this file put
    /// there. Saved at once: the chain has moved, and the file must know.
    ///
    /// # Errors
    ///
    /// The network does not answer (the action that needed the anchor waits
    /// for it), or the contract refuses: then this file is a copy, or an
    /// older file, and is marked so.
    pub fn base_anchor(&mut self) -> Result<(), String> {
        use crate::base_anchor::{word, AnchorError};
        let Some(cfg) = self.meta.base.clone() else {
            return Err("this container does not anchor on Base Sepolia".into());
        };
        if self.base.is_none() {
            self.base =
                Some(connect_base(&cfg).map_err(|x| {
                    format!("an anchor is due and Base Sepolia does not answer: {x}")
                })?);
        }
        // E-19 before anything is written on the chain (live run 16.10): a
        // node that answers but will not give the logs opens the container
        // as offline, and the anchor must not then go out over a declared
        // loss. Not read is not written — the same as no network, within
        // the ten offline records.
        // Where this container's logs start: just before its first anchor.
        // Only then — a container anchored earlier keeps reading from 0.
        // Before the first anchor nothing of it is on the chain, so the
        // loss is read from here too, not from block 0 (a node limited to a
        // range would refuse that, and printing would stop).
        let first_block = if cfg.last.is_none() && cfg.from_block.is_none() {
            let link = self.base.as_ref().ok_or("no link")?;
            Some(
                link.block_number()
                    .map_err(|x| format!("an anchor is due and Base Sepolia does not answer: {x}"))?
                    .saturating_sub(1),
            )
        } else {
            None
        };
        {
            let link = self.base.as_ref().ok_or("no link")?;
            let key = cfg.anchor_key(&self.c.template_id())?;
            let kind = |tag: &str| ksg_anchor_v2::evm::note_kind(tag);
            match ksg_verify_v2::base::loss(
                link.rpc(),
                link.contract(),
                &key,
                &kind,
                cfg.from_block.or(first_block).unwrap_or(0),
            ) {
                Ok(ksg_verify_v2::base::Loss::Declared { block, .. }) => {
                    return Err(format!(
                        "the client declared this container lost (Base Sepolia, block \
                         {block}): nothing more goes on the chain"
                    ))
                }
                Ok(_) => {}
                Err(x) => {
                    return Err(format!(
                        "an anchor is due and Base Sepolia did not answer the loss check: {x}"
                    ))
                }
            }
        }
        // A hand-over owed from a transfer of rights goes first: until it
        // lands, the new owner's key is not the writer.
        self.base_hand_over()?;
        let cfg = self.meta.base.clone().ok_or("no base")?;
        // A hand-over changes the key: the link is made again from it.
        if self.base.is_none() {
            self.base =
                Some(connect_base(&cfg).map_err(|x| {
                    format!("an anchor is due and Base Sepolia does not answer: {x}")
                })?);
        }
        let key = cfg.anchor_key(&self.c.template_id())?;
        let next = word(
            &self
                .c
                .top_seal_hash()
                .unwrap_or_else(|| self.c.status_head()),
        );
        // An anchor sent earlier whose confirmation never came may have landed
        // since: then it is `last`, and the new one continues it.
        self.base_settle(&key)?;
        let cfg = self.meta.base.clone().ok_or("no base")?;
        let prev = cfg.last_bytes()?.unwrap_or([0; 32]);
        if cfg.last_bytes()? == Some(next) {
            return Ok(());
        }
        // Written before sending: if the confirmation does not come, the file
        // still knows the head may be its own.
        if let Some(b) = &mut self.meta.base {
            b.sending(&next);
        }
        self.save()?;
        let link = self.base.as_ref().ok_or("no link")?;
        match link.anchor(&key, &prev, &next) {
            Ok(tx) => {
                if let Some(b) = &mut self.meta.base {
                    b.last = Some(ksg_anchor_v2::evm::hex0x(&next));
                    b.pending.clear();
                    b.since = 0;
                    b.last_tx = Some(tx);
                    if first_block.is_some() {
                        b.from_block = first_block;
                    }
                }
                self.save()?;
                self.base_share();
                Ok(())
            }
            Err(AnchorError::Refused(r)) => {
                if matches!(r, ksg_anchor_v2::evm::Refusal::StalePredecessor { .. }) {
                    // The head moved past `last`: one of this file's own
                    // unconfirmed anchors landed meanwhile, or this is a copy.
                    if self.base_settle(&key)? {
                        return self.base_anchor();
                    }
                    self.copy = true;
                }
                Err(format!(
                    "Base Sepolia refused the anchor ({r:?}): this file is a copy, or an older \
                     file, of the container. Only the full export is allowed"
                ))
            }
            Err(AnchorError::Network(x)) => Err(format!(
                "an anchor is due and Base Sepolia did not take it: {x}"
            )),
        }
    }

    /// Reads the head and, when it is one of this file's own anchors sent
    /// without a confirmation, records it as `last` ([`BaseCfg::settle`]).
    /// Returns whether it did.
    ///
    /// # Errors
    ///
    /// The node does not answer, or the file does not save.
    fn base_settle(&mut self, key: &[u8; 32]) -> Result<bool, String> {
        let pending = self
            .meta
            .base
            .as_ref()
            .is_some_and(|b| !b.pending.is_empty());
        if !pending {
            return Ok(false);
        }
        let link = self.base.as_ref().ok_or("no link")?;
        let h = link
            .head(key)
            .map_err(|x| format!("an anchor is due and Base Sepolia does not answer: {x}"))?;
        let changed = self.meta.base.as_mut().is_some_and(|b| b.settle(&h.last));
        if changed {
            self.save()?;
        }
        Ok(changed)
    }

    /// KS-8 C-10, step 1 (E-18, `[decision]` 10.09): the agent publishes its
    /// ID in the chain, with an anchor. The publication is the agent's own
    /// act — the client's key signs it, through both halves — and it is
    /// **for this container**: the container goes into the anchored hash
    /// (`identity::Publication::subject`, `[decision]` 12.09), so its anchor
    /// cannot be reused for another. The memo carries the ID in the open and
    /// the hash, never the container (`ksg_verify_v2::solana::AgentIdMemo`).
    ///
    /// Pro only for now: Pro anchors on Solana and the memo goes there. On a
    /// stand without a network (`--anchor` not given) the anchor is the
    /// stand's local one, as for every other record there.
    ///
    /// **Irreversible**: once out, an ID is not withdrawn, and one container
    /// publishes one. The publication is kept in `agent-id.json` beside the
    /// container. Steps 2 (the ID in the artifact) and 3 (the claim inside
    /// the container) are not this function's.
    ///
    /// # Errors
    ///
    /// Not Pro; not initiated; the ID is not a URI or is too long; published
    /// already; the client did not sign; the network did not take it.
    pub fn publish_id(&mut self, open_id: &str) -> Result<(Attestation, Option<String>), String> {
        use ksg_container_v2::identity::Publication;
        if self.c.class() != Class::Heavy {
            return Err(
                "publish-id: an agent's ID is published for a Pro container (KS-8 C-10)".into(),
            );
        }
        let Some(agent) = self.meta.client.clone() else {
            return Err(
                "publish-id: the client's key is born at initiation — initiate first".into(),
            );
        };
        Uri::parse(open_id.to_owned())
            .map_err(|x| format!("publish-id: --id is not a URI: {x}"))?;
        if open_id.len() > ksg_verify_v2::solana::AGENT_ID_MAX {
            return Err(format!(
                "publish-id: --id is longer than {} bytes",
                ksg_verify_v2::solana::AGENT_ID_MAX
            ));
        }
        let path = self.home.agent_id();
        if path.exists() {
            return Err(
                "publish-id: this container's agent ID is published already — \
                        a published ID is not withdrawn, and a container has one"
                    .into(),
            );
        }
        let container = *self.c.id();
        let subject = Publication::subject(&container, open_id, &agent);
        let signatures = SignatureSet::new(
            self.client_signs(subject.as_bytes())?
                .into_iter()
                .filter(|x| x.kid == agent.kid)
                .collect(),
        );
        let keys: KeySet = std::iter::once(agent.clone()).collect();
        signatures
            .verify(
                subject.as_bytes(),
                &keys,
                &Profile::default().with_ed25519(),
            )
            .map_err(|x| format!("publish-id: the agent's signature: {x}"))?;
        let (anchor, tx) = match &self.anchorer {
            Some((a, _)) => {
                let (att, sig) = a.publish_agent_id(&subject, open_id)?;
                (att, Some(sig))
            }
            None => (local_anchor(subject), None),
        };
        let p = Publication {
            container,
            open_id: open_id.to_owned(),
            agent,
            signatures,
            anchor,
        };
        p.validate().map_err(e)?;
        let doc = serde_json::json!({
            "container": p.container.to_multihash(),
            "open_id": p.open_id,
            "agent": p.agent,
            "signatures": p.signatures,
            "anchor": p.anchor,
            "tx": tx,
        });
        write_atomic(&path, &serde_json::to_vec_pretty(&doc).map_err(e)?, false)?;
        Ok((p.anchor, tx))
    }

    /// KS-8 C-10, step 3 (`[decision]` 10.09): the claim of ownership —
    /// `hash(artifact) + hash(agent ID)` — recorded in the journal on one
    /// page, after step 1: the publication kept in `agent-id.json` goes with
    /// it, and the container refuses the claim without it or with another
    /// ID. Step 2 (the ID in the artifact itself) the container cannot check
    /// (`identity.rs`). The client and the owner sign, as for an artefact.
    ///
    /// # Errors
    ///
    /// No publication (`publish-id` first); an unreadable one; see
    /// [`Reader::press`].
    pub fn claim_ownership(&mut self, artifact: Hash) -> Result<(), String> {
        use ksg_container_v2::identity::{
            id_hash, OwnershipClaim, Publication, OWNERSHIP_CLAIM_PAGE,
        };
        let raw = read(&self.home.agent_id()).map_err(|_| {
            "claim: step 1 first — the agent's ID published in the chain (`publish-id`)".to_owned()
        })?;
        let doc: serde_json::Value = serde_json::from_slice(&raw).map_err(e)?;
        let field = |k: &str| {
            doc.get(k)
                .cloned()
                .ok_or_else(|| format!("claim: agent-id.json has no {k}"))
        };
        let publication = Publication {
            container: Hash::from_multihash(
                field("container")?
                    .as_str()
                    .ok_or("claim: agent-id.json: container")?,
            )
            .map_err(e)?,
            open_id: field("open_id")?
                .as_str()
                .ok_or("claim: agent-id.json: open_id")?
                .to_owned(),
            agent: serde_json::from_value(field("agent")?).map_err(e)?,
            signatures: serde_json::from_value(field("signatures")?).map_err(e)?,
            anchor: serde_json::from_value(field("anchor")?).map_err(e)?,
        };
        let claim = OwnershipClaim {
            container: *self.c.id(),
            artifact,
            agent_id: id_hash(&publication.open_id),
        };
        let page = PageSpec::Of {
            kind: RecordKind::ArtifactOrRights,
            content: Piece::Inline(claim.page_bytes()),
            content_type: Some(Uri::parse(OWNERSHIP_CLAIM_PAGE.to_owned()).map_err(e)?),
        };
        self.press(
            Operation::AttachArtifactOrRights,
            &[Who::Client, Who::Owner],
            Evidence::Claim {
                claim: Box::new(claim),
                publication: Box::new(publication),
            },
            page,
        )
    }

    /// The owner's change (E-9): the owner and the buyer laid at E-3 sign,
    /// and the buyer becomes the owner — in the container, in `parties.json`
    /// and, for `light` on Base Sepolia, on the contract: the old owner's key
    /// hands the seat of writer over to the buyer's (`evm_key`), which
    /// anchors from then on (gap 15.10). The transfer goes out on a fresh
    /// anchor, as any value does.
    ///
    /// Returns the hand-over's transaction; `None` when there is nothing to
    /// hand over, or the network did not take it — then it waits in
    /// `container.json` and goes before the next anchor.
    ///
    /// # Errors
    ///
    /// A `bare` (its owner's change is the attachment, `attach-to`); `light`
    /// on Base Sepolia without `evm_key`, or `evm_key` where nothing anchors
    /// on Base Sepolia; an unreadable key; see [`Reader::press`].
    pub fn owner_change(&mut self, evm_key: Option<&Path>) -> Result<Option<String>, String> {
        if self.c.class() == Class::Bare {
            return Err(
                "owner-change: a bare's new owner comes with --new-owner-home DIR \
                        (its transfer, 17.10) or with `attach-to`"
                    .into(),
            );
        }
        let hand_to = self.hand_to_of(evm_key)?;
        // A sale writes its page once there is a journal to write it in.
        let page = if self.c.top_seal_hash().is_some() {
            PageSpec::OwnerChange
        } else {
            PageSpec::None
        };
        self.press(
            Operation::TransferOwnership,
            &[Who::Owner, Who::Buyer],
            Evidence::None,
            page,
        )?;
        // The buyer sits in the owner's seat: `parties.json` follows.
        let mut seeds = read_seeds(&self.home)?;
        seeds.owner.clone_from(&seeds.buyer);
        seeds.owner_kid = Some(self.parties.buyer.public().kid.as_str().to_owned());
        let json = Zeroizing::new(serde_json::to_vec_pretty(&seeds).map_err(e)?);
        write_atomic(&self.home.parties(), &json, true)?;
        self.parties.owner = Parties::from_seeds(&seeds)?.owner;
        let Some(hand_to) = hand_to else {
            return Ok(None);
        };
        if let Some(b) = &mut self.meta.base {
            b.hand_to = Some(hand_to);
        }
        self.save()?;
        Ok(self.base_hand_over().ok().flatten())
    }

    /// Where the container anchors on Base Sepolia, the new owner's EVM key
    /// that takes the writer's seat at an owner's change (15.10); refused
    /// where it does not, and required where it does.
    fn hand_to_of(
        &self,
        evm_key: Option<&Path>,
    ) -> Result<Option<crate::base_anchor::HandTo>, String> {
        let on_base =
            matches!(self.meta.class, Class::Light | Class::Heavy) && self.meta.base.is_some();
        match (on_base, evm_key) {
            (true, Some(k)) => Ok(Some(crate::base_anchor::HandTo {
                to: ksg_anchor_v2::evm::hex0x(&ksg_anchor_v2::evm::address_of(
                    crate::base_anchor::read_key(k)?.verifying_key(),
                )),
                key: k.to_path_buf(),
            })),
            (true, None) => Err("owner-change: this container anchors on Base Sepolia — \
                                 --evm-key FILE, the new owner's key, takes the writer's seat"
                .into()),
            (false, Some(_)) => Err("owner-change: --evm-key only where the container anchors \
                                     on Base Sepolia"
                .into()),
            (false, None) => Ok(None),
        }
    }

    /// The transfer of a `light` or Pro to a new owner (E-9, owner's decision
    /// 18.10 "A", after CH-15's hundred transfers): the owner and the arriving
    /// owner — the owner of `new_owner_home` — sign, the page goes into the
    /// transfer zone, the chain layer writes its next position, and the
    /// arriving owner takes the owner's seat in the container and in
    /// `parties.json`; on Base Sepolia the writer's seat on the contract goes
    /// to `evm_key`, as at the sale to the buyer laid at E-3. As many times as
    /// there are chain positions. Returns the new owner's key identifier.
    ///
    /// # Errors
    ///
    /// A `bare` (its transfer is [`Reader::bare_transfer`]); the same home;
    /// no open journal; the EVM key as in [`Reader::owner_change`]; see
    /// [`Reader::press`].
    pub fn transfer_to(
        &mut self,
        new_owner_home: &Path,
        evm_key: Option<&Path>,
    ) -> Result<String, String> {
        if self.c.class() == Class::Bare {
            return Err("owner-change: a bare's transfer goes through bare_transfer".into());
        }
        if new_owner_home.canonicalize().ok() == self.home.0.canonicalize().ok() {
            return Err("owner-change: the new owner's home is this container's".into());
        }
        let hand_to = self.hand_to_of(evm_key)?;
        let seeds = owner_of(new_owner_home)?;
        let arriving = Parties::from_seeds(&seeds)?.owner;
        let key = arriving.public();
        let kid = key.kid.as_str().to_owned();
        self.arriving = Some(arriving);
        let r = self.press(
            Operation::TransferOwnership,
            &[Who::Owner, Who::Arriving],
            Evidence::Transfer(key),
            PageSpec::OwnerChange,
        );
        self.arriving = None;
        r?;
        let mut mine = read_seeds(&self.home)?;
        mine.owner.clone_from(&seeds.owner);
        mine.owner_kid.clone_from(&seeds.owner_kid);
        let json = Zeroizing::new(serde_json::to_vec_pretty(&mine).map_err(e)?);
        write_atomic(&self.home.parties(), &json, true)?;
        self.parties.owner = Parties::from_seeds(&seeds)?.owner;
        if let Some(h) = hand_to {
            if let Some(b) = &mut self.meta.base {
                b.hand_to = Some(h);
            }
            self.save()?;
            let _ = self.base_hand_over();
        }
        Ok(kid)
    }

    /// The transfer of a `bare` (E-9, owner's decision 17.10): the owner and
    /// the arriving owner — the owner of `new_owner_home` — sign, the page
    /// goes into the transfer zone, and the arriving owner takes the owner's
    /// seat in the container and in `parties.json`. The agent stays; a new
    /// agent comes with `handoff`. Returns the new owner's key identifier.
    ///
    /// # Errors
    ///
    /// Not a `bare`; the same home; no open journal, an attached `bare`;
    /// see [`Reader::press`].
    pub fn bare_transfer(
        &mut self,
        new_owner_home: &Path,
        label: Option<&LabelNet>,
    ) -> Result<String, String> {
        if self.c.class() != Class::Bare {
            return Err(
                "owner-change --new-owner-home: a light's or Pro's transfer \
                        goes through transfer_to"
                    .into(),
            );
        }
        if new_owner_home.canonicalize().ok() == self.home.0.canonicalize().ok() {
            return Err("owner-change: the new owner's home is this container's".into());
        }
        let seeds = owner_of(new_owner_home)?;
        let arriving = Parties::from_seeds(&seeds)?.owner;
        let key = arriving.public();
        let kid = key.kid.as_str().to_owned();
        // The label as the former owner reads it, before the seat changes.
        let former = Parties::from_seeds(&read_seeds(&self.home)?)?.owner;
        let moving = match label {
            Some(net) => {
                let (l, _) = label_on_chain(net, &*self.owner_read_secret()?)?
                    .ok_or("owner-change: no issuance label of this owner on the network")?;
                if l.current_owner().key != former.public().key {
                    return Err("owner-change: the label found is not this owner's".into());
                }
                Some(l)
            }
            None => None,
        };
        self.arriving = Some(arriving);
        let r = self.press(
            Operation::TransferOwnership,
            &[Who::Owner, Who::Arriving],
            Evidence::Transfer(key),
            PageSpec::OwnerChange,
        );
        self.arriving = None;
        r?;
        let mut mine = read_seeds(&self.home)?;
        mine.owner.clone_from(&seeds.owner);
        mine.owner_kid.clone_from(&seeds.owner_kid);
        let json = Zeroizing::new(serde_json::to_vec_pretty(&mine).map_err(e)?);
        write_atomic(&self.home.parties(), &json, true)?;
        self.parties.owner = Parties::from_seeds(&seeds)?.owner;
        let read = self.publish_owner_read_key()?;
        if let (Some(l), Some(net)) = (moving, label) {
            let next = l.pass_to(&former, self.parties.owner.public(), now_ms())?;
            self.write_label(&next, &read, Some(net))?;
        }
        Ok(kid)
    }

    /// The owner's read key (X25519), expanded from the owner's seed under a
    /// label of its own (17.10, condition 1): it opens issuance labels and
    /// signs nothing.
    ///
    /// # Errors
    ///
    /// An unreadable `parties.json`.
    pub fn owner_read_secret(&self) -> Result<Zeroizing<[u8; 32]>, String> {
        let seeds = read_seeds(&self.home)?;
        Ok(crate::issue_label::read_secret(&*crate::home::owner_seed(
            &seeds,
        )?))
    }

    /// The owner sets its read key in the container, signed with its own key
    /// (17.10, condition 2: the issuer takes it from the container's answer).
    /// Returns the public half.
    ///
    /// # Errors
    ///
    /// The container refuses it; the container does not save.
    pub fn publish_owner_read_key(&mut self) -> Result<[u8; 32], String> {
        let public = crate::issue_label::read_public(&*self.owner_read_secret()?);
        let sig = self.parties.owner.sign(&self.c.owner_read_message(&public));
        self.c.set_owner_read_key(public, sig).map_err(e)?;
        self.save()?;
        Ok(public)
    }

    /// The container's answer for an issuer: whose it is and the key the
    /// label is sealed to.
    ///
    /// # Errors
    ///
    /// No owner, or no read key set.
    pub fn label_answer(&self) -> Result<serde_json::Value, String> {
        let owner = self
            .c
            .roster()
            .holder(Role::Owner)
            .cloned()
            .ok_or("the container holds no owner")?;
        let read = self
            .c
            .owner_read_key()
            .ok_or("the owner has not set a read key")?;
        Ok(serde_json::json!({
            "owner": owner,
            "read": hex::encode(read),
        }))
    }

    /// The label's duplicate: sealed to `read`, a record in the journal and,
    /// with `net`, a note on the contract.
    fn write_label(
        &mut self,
        label: &crate::issue_label::Label,
        read: &[u8; 32],
        net: Option<&LabelNet>,
    ) -> Result<(), String> {
        use ksg_core_v2::journal::PAGE_BYTES;
        let mut random = [0u8; 56];
        rand_core::RngCore::fill_bytes(&mut OsRng, &mut random);
        let sealed = crate::issue_label::seal(label, read, &random)?;
        let mut w = Work {
            container: *self.c.id(),
            under: None,
            did: format!(
                "issuance label passed to {}",
                label.current_owner().kid.as_str()
            ),
            signatures: SignatureSet::default(),
        };
        let subject = w.subject();
        w.signatures = SignatureSet::new(self.client_signs(subject.as_bytes())?);
        self.press(
            Operation::RecordWork,
            &[Who::Client],
            Evidence::Work {
                order: None,
                work: Box::new(w),
            },
            PageSpec::Record {
                pieces: sealed
                    .as_bytes()
                    .chunks(PAGE_BYTES)
                    .map(|c| Piece::Inline(c.to_vec()))
                    .collect(),
                meta: RecordMeta {
                    kind: RecordKind::Work,
                    content_type: Some(uri(crate::issue_label::LABEL_PAGE)),
                    media: Some("text/plain".into()),
                    ..RecordMeta::default()
                },
            },
        )?;
        if let Some(net) = net {
            net.link()?
                .note(crate::issue_label::LABEL_TAG, sealed.as_bytes())
                .map_err(|x| match x {
                    crate::base_anchor::AnchorError::Refused(r) => format!("refused: {r:?}"),
                    crate::base_anchor::AnchorError::Network(x) => x,
                })?;
        }
        Ok(())
    }

    /// Sends the hand-over a transfer of rights left owed, from the old
    /// owner's key; once it lands, the new owner's key is the one anchors go
    /// from. `None` when nothing is owed.
    ///
    /// # Errors
    ///
    /// The network did not take it (it stays owed), or the contract refused
    /// it for a writer other than either key.
    fn base_hand_over(&mut self) -> Result<Option<String>, String> {
        use crate::base_anchor::AnchorError;
        let Some(cfg) = self.meta.base.clone() else {
            return Ok(None);
        };
        let Some(hand_to) = cfg.hand_to.clone() else {
            return Ok(None);
        };
        let to: ksg_anchor_v2::evm::Address = ksg_anchor_v2::evm::unhex(&hand_to.to)
            .map_err(|x| x.to_string())?
            .try_into()
            .map_err(|_| "container.json: base.hand_to.to is not 20 bytes".to_owned())?;
        if self.base.is_none() {
            self.base = Some(connect_base(&cfg).map_err(|x| {
                format!("a hand-over is owed and Base Sepolia does not answer: {x}")
            })?);
        }
        let link = self.base.as_ref().ok_or("no link")?;
        // The seat goes to the address the new owner's key writes from: the
        // key's own, or its smart account when the gas is sponsored.
        let to = if cfg.sponsored {
            link.writer_for(&crate::base_anchor::read_key(&hand_to.key)?)?
        } else {
            to
        };
        let key = cfg.anchor_key(&self.c.template_id())?;
        let tx = match link.hand_over(&key, &to) {
            Ok(tx) => tx,
            // Sent before, and the file did not learn of it: the seat is the
            // new owner's already.
            Err(AnchorError::Refused(ksg_anchor_v2::evm::Refusal::NotWriter(w))) if w == to => {
                String::from("already on the chain")
            }
            // Nothing was anchored under this key yet: there is no seat to
            // hand over, and the new owner's key takes it at its first anchor.
            Err(AnchorError::Refused(ksg_anchor_v2::evm::Refusal::NotWriter(w)))
                if w == [0u8; 20] =>
            {
                String::from("no writer yet")
            }
            Err(AnchorError::Refused(r)) => {
                return Err(format!("Base Sepolia refused the hand-over ({r:?})"))
            }
            Err(AnchorError::Network(x)) => {
                return Err(format!(
                    "a hand-over is owed and Base Sepolia did not take it: {x}"
                ))
            }
        };
        if let Some(b) = &mut self.meta.base {
            b.key = hand_to.key;
            b.hand_to = None;
        }
        // The link holds the old key: the next one is made with the new.
        self.base = None;
        self.save()?;
        Ok(Some(tx))
    }

    /// Puts the waiting commitment to the client's mobile half on the chain
    /// (E-19). If the network does not take it, it waits for the next anchor.
    fn base_share(&mut self) {
        let Some(link) = self.base.as_ref() else {
            return;
        };
        let Some(commit) = self
            .meta
            .base
            .as_ref()
            .and_then(|b| b.share.as_deref())
            .and_then(|h| ksg_anchor_v2::evm::unhex(h).ok())
            .and_then(|v| <[u8; 32]>::try_from(v).ok())
        else {
            return;
        };
        let Some(Ok(key)) = self
            .meta
            .base
            .as_ref()
            .map(|b| b.anchor_key(&self.c.template_id()))
        else {
            return;
        };
        let body = ksg_verify_v2::base::share_body(&key, &commit);
        if link.note(ksg_verify_v2::base::SHARE_TAG, &body).is_ok() {
            if let Some(b) = &mut self.meta.base {
                b.share = None;
            }
            let _ = self.save();
        }
    }

    fn press_inner(
        &mut self,
        op: Operation,
        who: &[Who],
        evidence: &Evidence,
        page: PageSpec,
    ) -> Result<(), String> {
        let head = self.c.head();
        let mut ev = Event {
            op,
            button: op.button(),
            container: *self.c.id(),
            payload: Wrapped::received(b"wrapped at the reader".to_vec()),
            signatures: SignatureSet::default(),
            covered: Vec::new(),
            head,
        };
        ev.covered = ev.subject();
        let covered = ev.covered.clone();
        ev.signatures = self.sign_all(&covered, who)?;
        let page = self.page(page)?;
        let status = self.status_record(op)?;
        let keys = self.c.roster().keys().clone();
        let refused = |x: ksg_container_v2::Stopped| format!("refused: {x}");

        // What goes to the network, decided before the press: the seal of a
        // Pro record and the status record, when this container anchors.
        // Goal 1, criterion G1-4: a `bare` work record anchors nothing —
        // neither the network nor the service queue is touched for it.
        let bare_work = self.c.class() == Class::Bare && op == Operation::RecordWork;
        let seal_out = page
            .as_ref()
            .filter(|p| !bare_work && p.anchored())
            .map(|p| (p.prev, p.seal));
        let status_out = if bare_work {
            None
        } else {
            status
                .as_ref()
                .map(|(r, _)| r.hash().map(|h| (r.prev, h)))
                .transpose()
                .map_err(e)?
        };
        let writes = Writes {
            page: page.map(|p| p.write),
            status,
            // The event's moment for the `bare` idle term: the clock after the
            // page and the status record took their marks from it.
            at_ms: Some(self.meta.clock_ms),
        };
        // The press first, with placeholder anchors: it is all or nothing, so
        // a refusal here spends no memo and changes nothing (audit of 30.09,
        // O-1 — this used to be a press of a whole copy of the container).
        self.c
            .press(&ev, evidence, writes, &keys, &Profile::default())
            .map_err(refused)?;
        if self.anchorer.is_none() || (seal_out.is_none() && status_out.is_none()) {
            return self.work_off();
        }
        // Then the memos, then the network's anchors in place of the
        // placeholders. What is owed is written down first; until a memo has
        // gone out, a failure puts the container back as the disk holds it
        // and nothing is saved. Once one has gone out, the record stays —
        // with the memo owed (`PendingAnchor`) — so that a memo landing late
        // is taken, never sent again into a fork.
        // A seal is blinded under the key of the month it is pressed in.
        let period = crate::anchoring::current_scan_period();
        let owed: Vec<PendingAnchor> = seal_out
            .map(|(prev, seal)| (MemoKind::Seal, prev, seal))
            .into_iter()
            .chain(status_out.map(|(prev, rec)| (MemoKind::Status, prev, rec)))
            .map(|(kind, prev, subject)| PendingAnchor {
                kind,
                prev: prev.to_multihash(),
                subject: subject.to_multihash(),
                sent: None,
                period: (kind == MemoKind::Seal).then(|| period.clone()),
            })
            .collect();
        if let Some(cfg) = &mut self.meta.anchor {
            if cfg.rotate_scan && seal_out.is_some() && !cfg.scan_periods.contains(&period) {
                cfg.scan_periods.push(period.clone());
            }
            cfg.pending = owed;
        }
        match self.settle() {
            Ok(()) => self.work_off(),
            Err(Settle::NothingSent(x)) => {
                self.c = Container::open_sealed(
                    &read(&self.home.container())?,
                    &self.c.template_id(),
                    &self.key,
                )
                .map_err(e)?;
                self.meta = serde_json::from_slice(&read(&self.home.meta())?)
                    .map_err(|x| format!("container.json: {x}"))?;
                Err(x)
            }
            Err(Settle::Owed(x)) => Err(x),
        }
    }

    /// Pays what the container owes the network: for each memo owed, oldest
    /// first, asks about the transaction already sent — or sends it — and
    /// takes the network's attestation in place of the placeholder.
    ///
    /// After every memo that goes out, the container and its memo are on
    /// disk before the wait: a crash or a timeout leaves a record that
    /// knows its transaction.
    fn settle(&mut self) -> Result<(), Settle> {
        let mut sent_any = false;
        loop {
            let Some((anchorer, scan)) = &self.anchorer else {
                return Ok(());
            };
            let Some(owed) = self
                .meta
                .anchor
                .as_ref()
                .and_then(|c| c.pending.first().cloned())
            else {
                return Ok(());
            };
            let fail = |x: String, sent_any: bool| {
                if sent_any {
                    Settle::Owed(format!(
                        "{x} — the record is kept with its memo owed; the next command \
                         asks the network again"
                    ))
                } else {
                    Settle::NothingSent(x)
                }
            };
            let prev = Hash::from_multihash(&owed.prev).map_err(|x| Settle::Owed(e(x)))?;
            let subject = Hash::from_multihash(&owed.subject).map_err(|x| Settle::Owed(e(x)))?;
            let landed = match &owed.sent {
                Some(sent) => match anchorer.wait(sent).map_err(|x| fail(x, true))? {
                    Landing::Landed {
                        signature,
                        slot,
                        block_time,
                    } => Some((signature, slot, block_time)),
                    Landing::Pending => {
                        return Err(fail(
                            format!("the anchor {} is not final yet", sent.signature),
                            true,
                        ))
                    }
                    // It can no longer land: sent again below, and the
                    // network holds one memo, not two.
                    Landing::Dropped | Landing::Failed(_) => None,
                },
                None => None,
            };
            let (sig, slot, block_time) = match landed {
                Some(l) => l,
                None => {
                    let key = self.meta.anchor.as_ref().map_or_else(
                        || scan.clone(),
                        |c| c.seal_key(scan, owed.period.as_deref()),
                    );
                    let memo = memo_of(owed.kind, &key, &prev, &subject);
                    let sent = anchorer
                        .submit(owed.kind, &subject, &memo)
                        .map_err(|x| fail(x, sent_any || owed.sent.is_some()))?;
                    sent_any = true;
                    if let Some(cfg) = &mut self.meta.anchor {
                        // A job of the service is not a transaction: the
                        // rollback check starts from the real one, once known.
                        if cfg.service.is_none() {
                            cfg.last_signature = Some(sent.signature.clone());
                        }
                        if let Some(p) = cfg.pending.first_mut() {
                            p.sent = Some(sent.clone());
                        }
                    }
                    self.save().map_err(|x| fail(x, true))?;
                    match anchorer.wait(&sent).map_err(|x| fail(x, true))? {
                        Landing::Landed {
                            signature,
                            slot,
                            block_time,
                        } => (signature, slot, block_time),
                        Landing::Pending => {
                            return Err(fail(
                                format!("the anchor {} is not final yet", sent.signature),
                                true,
                            ))
                        }
                        Landing::Dropped => {
                            return Err(fail(
                                format!("the anchor {} was dropped by the network", sent.signature),
                                true,
                            ))
                        }
                        Landing::Failed(x) => {
                            return Err(fail(format!("the anchor transaction failed: {x}"), true))
                        }
                    }
                }
            };
            let att = anchorer
                .attestation(owed.kind, &subject, &sig, slot, block_time)
                .map_err(|x| fail(x, true))?;
            let swapped = match owed.kind {
                MemoKind::Seal => self.c.reanchor_last(Some(att), None),
                MemoKind::Status => self.c.reanchor_last(None, Some(att)),
            };
            swapped.map_err(|x| fail(e(x), true))?;
            if let Some(cfg) = &mut self.meta.anchor {
                cfg.pending.remove(0);
                cfg.last_signature = Some(sig.clone());
            }
            self.save().map_err(|x| fail(x, true))?;
        }
    }

    /// Records the notices "who looked" the desk handed out for this
    /// container (`ksg_container_v2::view`, `[decision]` 13.09 §8.1): how
    /// many were taken, and why each other one was not. A notice recorded
    /// already is skipped quietly — the desk may hand one out twice.
    ///
    /// Not a press: nothing is signed and no page is spent.
    ///
    /// # Errors
    ///
    /// The container does not save.
    pub fn record_views(
        &mut self,
        notices: Vec<ksg_container_v2::view::ViewNotice>,
    ) -> Result<(usize, Vec<String>), String> {
        let mut taken = 0;
        let mut refused = Vec::new();
        for n in notices {
            let what = format!("{} at {}", n.owner_id(), n.seen_at.as_str());
            match self.c.record_view(n, &Profile::default()) {
                Ok(()) => taken += 1,
                Err(ksg_container_v2::view::ViewError::Again) => {}
                Err(x) => refused.push(format!("{what}: {x}")),
            }
        }
        if taken > 0 {
            self.save()?;
        }
        Ok((taken, refused))
    }

    /// The notices kept, one line each, and the count of dropped ones.
    #[must_use]
    pub fn view_lines(&self) -> Vec<String> {
        let v = self.c.views();
        let mut out: Vec<String> = v
            .as_slice()
            .iter()
            .map(|n| {
                format!(
                    "view       {} {} looked at {}:{}",
                    n.seen_at.as_str(),
                    n.owner_id(),
                    n.anchor().cluster,
                    n.anchor().signature
                )
            })
            .collect();
        if v.dropped() > 0 {
            out.push(format!("dropped    {} older views", v.dropped()));
        }
        out
    }

    /// How many kept views fall in `[since, until]` — the aggregate form
    /// (CT-16).
    #[must_use]
    pub fn views_in(
        &self,
        since: &ksg_core_v2::doc::Timestamp,
        until: &ksg_core_v2::doc::Timestamp,
    ) -> usize {
        self.c.views().in_period(since, until)
    }

    /// Path A's registration at the service: this container's channel
    /// bundle and status section, so that its owner key may look at
    /// somebody else's anchor. The service's answer.
    ///
    /// # Errors
    ///
    /// No channel bundle (the container was not printed on a packet), a memo
    /// owed, or the service refused.
    #[cfg(feature = "rpc")]
    pub fn service_register(
        &self,
        svc: &crate::service::Service,
    ) -> Result<serde_json::Value, String> {
        let channel: serde_json::Value = serde_json::from_slice(
            &read(&self.home.channel())
                .map_err(|_| "no channel.json: the container was not printed on a packet, or is not initiated yet (the channel's documents are made at initiation)")?,
        )
        .map_err(|x| format!("channel.json: {x}"))?;
        let statuses: serde_json::Value =
            serde_json::from_slice(&self.status_export_json()?).map_err(e)?;
        svc.post(
            "/v1/watchers",
            &serde_json::json!({"channel": channel, "statuses": statuses}),
            None,
        )
    }

    /// Asks the service whose `anchor` is, as the owner-watcher this home's
    /// owner key is: a challenge, then the request signed with that key
    /// (`[decision]` 13.09, path A). The service's answer: the charge and
    /// the container.
    ///
    /// # Errors
    ///
    /// The service refused or did not answer.
    #[cfg(feature = "rpc")]
    pub fn service_look(
        &self,
        svc: &crate::service::Service,
        anchor: ksg_container_v2::view::AnchorRef,
    ) -> Result<serde_json::Value, String> {
        use ksg_container_v2::view::DisclosureRequest;
        let audience = svc
            .get("/v1/health")?
            .get("audience")
            .and_then(serde_json::Value::as_str)
            .map(uri)
            .ok_or("the service names no audience")?;
        let challenge = svc
            .post("/v1/challenge", &serde_json::json!({}), None)?
            .get("challenge")
            .and_then(serde_json::Value::as_str)
            .ok_or("the service gave no challenge")?
            .to_owned();
        let now = now_ms();
        let mut rq = DisclosureRequest {
            doc_type: DisclosureRequest::TYPE.into(),
            v: ksg_core_v2::version::CURRENT_V,
            owner: vec![self.parties.owner.public()],
            audience,
            anchor,
            challenge,
            issued_at: utc(now),
            expires_at: utc(now + 5 * 60 * 1000),
            signatures: SignatureSet::default(),
        };
        rq.signatures = SignatureSet::new(vec![sign_doc(&rq, &self.parties.owner).map_err(e)?]);
        svc.post("/v1/look", &serde_json::json!({"request": rq}), None)
    }

    /// Takes the notices "who looked" the service holds for this container,
    /// signed as `holder`, and records them: how many were recorded, why each
    /// other was not, and how many the service dropped for want of room.
    ///
    /// # Errors
    ///
    /// The service refused or did not answer; the container does not save.
    #[cfg(feature = "rpc")]
    pub fn service_views(
        &mut self,
        svc: &crate::service::Service,
        holder: &str,
    ) -> Result<(usize, Vec<String>, u64), String> {
        let got = svc.post(
            "/v1/notices",
            &serde_json::json!({"container": self.meta.template}),
            Some((&self.parties.owner, holder)),
        )?;
        let notices: Vec<ksg_container_v2::view::ViewNotice> = serde_json::from_value(
            got.get("notices")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        )
        .map_err(|x| format!("the service's notices: {x}"))?;
        let dropped = got
            .get("dropped")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let (taken, refused) = self.record_views(notices)?;
        Ok((taken, refused, dropped))
    }

    /// Whether the container owes the network a memo.
    #[must_use]
    pub fn owes_anchor(&self) -> bool {
        self.meta
            .anchor
            .as_ref()
            .is_some_and(|c| !c.pending.is_empty())
    }

    /// The follow-up worker: discharges the layer tasks it can prove.
    fn work_off(&mut self) -> Result<(), String> {
        while let Some(i) =
            self.c.pending().iter().position(|r| {
                matches!(r.task, Task::WriteLayer { .. } | Task::HandOverLayer { .. })
            })
        {
            let ticket = self.c.claim(i).map_err(e)?;
            let proof = match &ticket.task {
                Task::WriteLayer { zone } => Proof::LayerWritten {
                    zone: *zone,
                    digest: self.write_layer(*zone)?,
                },
                Task::HandOverLayer { to, up_to } => Proof::HandedOver {
                    to: to.clone(),
                    up_to: *up_to,
                    sealed: self.hand_layer_over(to, *up_to)?,
                },
                Task::CarryId { .. } => unreachable!("filtered above"),
            };
            self.c.discharge(&Discharge { ticket, proof }).map_err(e)?;
        }
        Ok(())
    }

    /// The fields the issuer writes into `zone` (E-1, E-2, E-9): the release
    /// (emission, serial, template), the sale of the packet, the owner the
    /// chain layer now names.
    fn layer_fields(&self, zone: ksg_container_v2::Zone) -> Vec<u8> {
        use ksg_container_v2::Zone;
        let content: Vec<u8> = match zone {
            // C-2: the packet's own fields, and the digest of the whole
            // signed sale they come from — the sale with its chain of grants
            // does not fit a zone, and need not: the digest binds it.
            Zone::Packet => match read(&self.home.sale()) {
                Ok(raw) => {
                    let sale = Hash::sha256(&raw).to_multihash();
                    let fields = match serde_json::from_slice::<crate::channel::Sale>(&raw) {
                        Ok(s) => serde_json::json!({
                            "emission": s.packet.emission,
                            "block": s.packet.block,
                            "class": s.packet.class,
                            "holder": s.packet.holder,
                            "allocated_at": s.packet.allocated_at,
                            "expires_at": s.packet.expires_at,
                            "sale": sale,
                        }),
                        // Not a sale this program reads: the digest alone.
                        Err(_) => serde_json::json!({ "sale": sale }),
                    };
                    serde_json::to_vec(&fields).unwrap_or_default()
                }
                Err(_) => Vec::new(),
            },
            Zone::Chain => self.parties.owner.public().key.into_bytes(),
            _ => self.meta.serial.0.to_be_bytes().to_vec(),
        };
        zone_fields(zone, &self.meta.emission, &self.meta.template, &content)
    }

    /// The key of the level that writes `position` ([`zone_key_of`]).
    #[must_use]
    pub fn zone_key(&self, position: usize) -> ksg_container_v2::layers::LayerKey {
        zone_key_of(&self.meta.template, position)
    }

    /// Writes `zone` (owner's decision 18.10 "A"): its fields sealed under the
    /// writing level's key, padded to the zone's width with fresh noise, into
    /// the next free position. Returns the digest of the sealed zone, which
    /// the proof carries.
    fn write_layer(&mut self, zone: ksg_container_v2::Zone) -> Result<Hash, String> {
        if !self.c.zones_laid() {
            lay_noise(&mut self.c)?;
        }
        let fields = self.layer_fields(zone);
        let template = self.meta.template.clone();
        seal_into(&mut self.c, zone, &fields, &template)
    }

    /// E-3, the act the cycle moved out (`[decision]` 12.09): the layer keys
    /// up to `up_to` are sealed to the party `to` with the real hand-over of
    /// `ksg-container-v2::layers` — X25519 alone for `bare` (`[decision]`
    /// 07.10), hybrid with ML-KEM-768 otherwise — the recipient takes
    /// delivery and makes its own key, and the sealed hand-over goes to
    /// `handovers.json` beside the container. Returns the digest the proof
    /// carries.
    ///
    /// On the stand (`[decision]` 07.10: keys outside are the stand's) the
    /// stand plays every party: the upstream levels and the recipient's
    /// opening key are the test keys of public labels (`testkeys`), so the
    /// chain is recomputable and nothing in it passes for real.
    fn hand_layer_over(&self, to: &PublicKey, up_to: Level) -> Result<Hash, String> {
        use ksg_container_v2::layers::{hand_over_in, receive_in, Held, LayerKey, OpenWith, Suite};
        use ksg_container_v2::ChaCha20Poly1305Aead as Aead;
        use rand_core::RngCore as _;
        let suite = Suite::of(self.c.class());
        let template = &self.meta.template;
        let level_key = |l: u8| {
            LayerKey::from_bytes(*crate::testkeys::secret(&format!(
                "layer-level:{l}:{template}"
            )))
        };
        let open = |who: &str| {
            OpenWith::from_bytes(*crate::testkeys::secret(&format!("open:{who}:{template}")))
        };
        let fresh = || {
            let mut b = Zeroizing::new([0u8; 32]);
            OsRng.fill_bytes(b.as_mut());
            *b
        };
        let aad = |who: &str| {
            Hash::sha256_fields(&[
                b"ksg:layer-hand-over:v1",
                self.c.id().as_bytes(),
                who.as_bytes(),
            ])
        };
        // The upstream chain, level by level, each holder handing on to the
        // next — the same act as below, so the set the recipient gets is one
        // a real chain would hold.
        let mut held = Held::first(level_key(0));
        for l in 1..=up_to.0 {
            let who = format!("level:{l}");
            let h = hand_over_in(
                suite,
                &Aead,
                &held,
                &open(&who).seal_to(),
                fresh(),
                aad(&who).as_bytes(),
            )
            .map_err(e)?;
            held = receive_in(
                suite,
                &Aead,
                &h,
                &open(&who),
                level_key(l),
                aad(&who).as_bytes(),
            )
            .map_err(e)?;
        }
        let who = to.kid.as_str().to_owned();
        let sent = hand_over_in(
            suite,
            &Aead,
            &held,
            &open(&who).seal_to(),
            fresh(),
            aad(&who).as_bytes(),
        )
        .map_err(e)?;
        // The recipient takes delivery: a hand-over it cannot open is not
        // a hand-over, and the task is not discharged on one.
        let got = receive_in(
            suite,
            &Aead,
            &sent,
            &open(&who),
            LayerKey::from_bytes(fresh()),
            aad(&who).as_bytes(),
        )
        .map_err(|x| format!("the hand-over to {who} does not open: {x}"))?;
        if got.level().0 != up_to.0.saturating_add(1) {
            return Err(format!(
                "the hand-over to {who} gave level {:?}",
                got.level()
            ));
        }
        let b64 = |b: &[u8]| {
            use base64::Engine as _;
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
        };
        let entry = serde_json::json!({
            "to": who,
            "up_to": sent.up_to.0,
            "suite": format!("{suite:?}"),
            "ephemeral": b64(&sent.ephemeral),
            "kem": b64(&sent.kem),
            "nonce": b64(&sent.nonce),
            "sealed": b64(&sent.sealed),
        });
        let path = self.home.handovers();
        let mut all: Vec<serde_json::Value> = match std::fs::read(&path) {
            Ok(b) => serde_json::from_slice(&b).map_err(|x| format!("handovers.json: {x}"))?,
            Err(_) => Vec::new(),
        };
        all.push(entry);
        write_atomic(&path, &serde_json::to_vec_pretty(&all).map_err(e)?, false)?;
        Ok(Hash::sha256_fields(&[
            b"ksg:layer-hand-over:v1",
            &sent.ephemeral,
            &sent.kem,
            &sent.nonce,
            &sent.sealed,
        ]))
    }

    // --- the insurance scenario, one method per command ---------------------

    /// The issuer applies the packet.
    ///
    /// # Errors
    ///
    /// See [`Reader::press`].
    pub fn packet(&mut self) -> Result<(), String> {
        self.packet_seating(None)
    }

    /// The issuer applies the packet and, when the distributor that sold it
    /// gave its seat document, seats it (C-12, owner's decisions 17.10: "B"
    /// and "give the distributor a module to add its key"). The document is
    /// checked against the sale this container was printed from and against
    /// this container's issuer (`channel::check_seat`) before anything moves.
    /// Without a document nobody is seated: a seat is the distributor's own
    /// act, not something read off the sale.
    ///
    /// # Errors
    ///
    /// A seat document on a container printed without a sale; a document that
    /// does not check; see [`Reader::press`].
    pub fn packet_seating(
        &mut self,
        seat: Option<&crate::channel::DistributorSeat>,
    ) -> Result<(), String> {
        if let Some(seat) = seat {
            let bytes = read(&self.home.sale()).map_err(|_| {
                "packet --seat: this container was not printed from a sale — there is no \
                 distributor to seat"
                    .to_owned()
            })?;
            let sale: Sale =
                serde_json::from_slice(&bytes).map_err(|x| format!("sale.json: {x}"))?;
            let key = crate::channel::check_seat(seat, &sale, &self.parties.issuer.public())?;
            self.c.seat_distributor(key).map_err(e)?;
        }
        self.press(
            Operation::ApplyPacket,
            &[Who::Issuer],
            Evidence::None,
            PageSpec::None,
        )
    }

    /// E-15, C-12 (owner's decision 17.10): the container is declared dead in
    /// the client's stead — by the owner alone, or by the distributor that
    /// sold the packet together with the client (`distributor` — its desk's
    /// key). The orchestrator's path exists in the container; the stand has
    /// no orchestrator. Dead is final: nothing opens after it.
    ///
    /// # Errors
    ///
    /// No distributor seated (a direct sale) for the distributor's path; the
    /// status does not admit it; see [`Reader::press`].
    pub fn declare_dead(&mut self, distributor: Option<Ed25519Signer>) -> Result<(), String> {
        let who: &[Who] = match distributor {
            None => &[Who::Owner],
            Some(d) => {
                if self.c.roster().holder(Role::Distributor).is_none() {
                    return Err(
                        "declare-dead: no distributor is seated in this container — \
                                the packet was sold directly by the issuer"
                            .into(),
                    );
                }
                self.distributor = Some(d);
                &[Who::Distributor, Who::Client]
            }
        };
        let r = self.press(
            Operation::DeclareKeyLost,
            who,
            Evidence::None,
            PageSpec::None,
        );
        self.distributor = None;
        r
    }

    /// The buyer's key is laid, up to level 2, with the owner's consent.
    ///
    /// # Errors
    ///
    /// See [`Reader::press`].
    pub fn buyer_key(&mut self) -> Result<(), String> {
        let to = self.buyer();
        self.press(
            Operation::ApplyBuyerKey,
            &[Who::Buyer, Who::Owner],
            Evidence::KeyLaid {
                to,
                up_to: Level(2),
            },
            PageSpec::None,
        )
    }

    /// Initiation of the container (E-4, CH-5b): the client's key is born —
    /// the container's half inside, the mobile half to `mobile_out`, never
    /// whole — and with it and the artefact the container's identifier; the
    /// client (both halves) and the owner sign the initiation, and the
    /// container is born. On a packet, the channel's documents are made here.
    ///
    /// In the MVP the mobile side runs in this process and its half goes to a
    /// file; in the product it is the client's device (`[decision]` pending,
    /// V-MP), over a closed channel.
    ///
    /// The half is written **before** the initiation goes in — without it the
    /// container could never sign — and removed if it does not.
    ///
    /// # Errors
    ///
    /// Initiated already; `mobile_out` exists; see [`Reader::press`].
    pub fn initiate(&mut self, mobile_out: &Path) -> Result<(), String> {
        use ksg_container_v2::client_key::MobileKeygen;
        if self.c.born() {
            return Err("the container is initiated already".into());
        }
        if mobile_out.exists() {
            return Err(format!(
                "{} exists: a mobile half is never overwritten",
                mobile_out.display()
            ));
        }
        // The artefact's moment: from the packet's origin, now (KS-8 E-4).
        let sale: Option<Sale> = match read(&self.home.sale()) {
            Ok(b) => Some(serde_json::from_slice(&b).map_err(|x| format!("sale.json: {x}"))?),
            Err(_) => None,
        };
        let offset_ms = match &sale {
            None => self.meta.artifact_offset_ms,
            Some(s) => {
                let origin = crate::clock::parse_ms(s.packet.origin())
                    .ok_or("the packet's allocated_at does not read")?;
                now_ms().saturating_sub(origin).max(1)
            }
        };
        let artifact = self.meta.artifact.clone();

        // The three messages of the birth. The key has no name yet: it is
        // born by the first two, and only then can it be called by its own
        // `did:key` (Г-1) — see below.
        let (keygen, hello) = MobileKeygen::start(uri(kid::UNBORN), &mut OsRng).map_err(e)?;
        let reply = self
            .c
            .begin_birth(uri(kid::UNBORN), &hello, &mut OsRng)
            .map_err(e)?;
        let (mut mobile, mut public, fin) = keygen.finish(&reply).map_err(e)?;
        // Г-1: the client agent's identifier is the `did:key` of the group key
        // its two halves sign under — unique without a registry, and the name
        // a verifier computes from the same key. Nothing is signed yet, so the
        // birth's documents and every page after them carry the computed name.
        let named = ksg_core_v2::crypto::did_key::kid(&public)
            .map_err(|x| format!("the client's did:key: {x}"))?;
        mobile.set_kid(named.clone());
        public.kid = named.clone();
        if let Err(x) = self.c.name_birth(named) {
            self.c.cancel_birth();
            return Err(e(x));
        }
        // E-19: the commitment to the mobile half goes on the chain with the
        // anchor of initiation, so that the half alone can declare a loss.
        let share =
            ksg_container_v2::client_key::share_commitment(&mobile.share_public().map_err(e)?);
        let (born, id) = self
            .c
            .finish_birth(&fin, artifact.clone(), offset_ms)
            .map_err(e)?;
        if born != public {
            self.c.cancel_birth();
            return Err("the two sides of the birth hold halves of different keys".into());
        }
        if let Err(x) = write_atomic(mobile_out, &mobile.to_bytes().map_err(e)?, true) {
            self.c.cancel_birth();
            return Err(x);
        }
        let undo = |r: &mut Self, x: String| -> String {
            r.c.cancel_birth();
            let _ = std::fs::remove_file(mobile_out);
            x
        };
        self.mobile = Box::new(LocalMobile::new(mobile));

        let proof = match &sale {
            None => None,
            Some(sale) => {
                let parties = Parties::from_seeds(&read_seeds(&self.home)?)?;
                let serial = self.meta.serial;
                let mut signs = |m: &[u8]| self.client_signs(m);
                match channel_documents(
                    &mut signs,
                    &parties,
                    sale,
                    Birth {
                        serial,
                        agent: public.clone(),
                        artifact: &artifact,
                        offset_ms,
                        container: id,
                    },
                ) {
                    Ok(p) => Some(p),
                    Err(x) => return Err(undo(self, x)),
                }
            }
        };
        // Д-4: the seal and the post-quantum key are born now, not at printing.
        // The issuer's word on them is on the template, as before (on the stand
        // the issuer's key is at hand; in the product it is the initiation page).
        let template = self.c.template_id();
        let seal = IssuerSeal::lay(&template, uri(kid::SEAL), *self.parties.seal, &self.parties.issuer);
        let pq_key = if self.c.class() == Class::Bare {
            None
        } else {
            match ksg_container_v2::pq_key::ContainerPqKey::generate(uri(kid::CONTAINER_PQ), &mut OsRng) {
                Ok(k) => Some(k),
                Err(x) => return Err(undo(self, e(x))),
            }
        };
        let pq_public = pq_key.as_ref().map(|k| k.public().clone());
        if !self.c.lay_at_initiation(seal, pq_key) {
            return Err(undo(self, "the seal or the post-quantum key is laid already".into()));
        }
        let pq_cert = pq_public.as_ref().map(|p| {
            self.parties
                .issuer
                .sign(&ksg_container_v2::store::pq_cert_message(&template, p))
        });
        let (pq_before, cert_before) = (self.meta.pq.clone(), self.meta.pq_cert.clone());
        self.meta.pq = pq_public;
        self.meta.pq_cert = pq_cert;
        let offset_before = self.meta.artifact_offset_ms;
        self.meta.artifact_offset_ms = offset_ms;
        if let Some(b) = &mut self.meta.base {
            b.share = Some(ksg_anchor_v2::evm::hex0x(&share));
        }
        if let Err(x) = self.press(
            Operation::Initiate,
            &[Who::Client, Who::Owner],
            Evidence::Initiation { at: Where::Inside },
            PageSpec::None,
        ) {
            if !self.c.born() {
                self.meta.artifact_offset_ms = offset_before;
                self.meta.pq = pq_before;
                self.meta.pq_cert = cert_before;
                if let Some(b) = &mut self.meta.base {
                    b.share = None;
                }
                return Err(undo(self, x));
            }
            // Born, with the status memo owed: the half stays.
            return Err(x);
        }
        if let Some(p) = &proof {
            write_atomic(
                &self.home.channel(),
                &serde_json::to_vec_pretty(p).map_err(e)?,
                false,
            )?;
        }
        // `bare`: the owner's read key for the issuance label (17.10).
        if self.c.class() == Class::Bare {
            self.publish_owner_read_key()?;
        }
        Ok(())
    }

    /// The client opens the journal: page 0.
    ///
    /// # Errors
    ///
    /// See [`Reader::press`].
    pub fn open_journal(&mut self) -> Result<(), String> {
        self.press(
            Operation::OpenJournal,
            &[Who::Client],
            Evidence::None,
            PageSpec::Opening,
        )
    }

    /// A record of work on the client's own account; `did` becomes the page.
    ///
    /// # Errors
    ///
    /// See [`Reader::press`].
    pub fn work(&mut self, did: &str) -> Result<(), String> {
        let mut w = Work {
            container: *self.c.id(),
            under: None,
            did: did.into(),
            signatures: SignatureSet::default(),
        };
        let subject = w.subject();
        w.signatures = SignatureSet::new(self.client_signs(subject.as_bytes())?);
        self.press(
            Operation::RecordWork,
            &[Who::Client],
            Evidence::Work {
                order: None,
                work: Box::new(w),
            },
            PageSpec::Of {
                kind: RecordKind::Work,
                content: Piece::Inline(did.as_bytes().to_vec()),
                content_type: None,
            },
        )
    }

    /// A document goes into the journal under a page type (a policy, a
    /// licence, a right, an artefact of the work). Kept outside, its digest
    /// is the page and the file stays with the client; kept whole
    /// (`whole`, `[decision]` 17.10 "kept in the journal whole or outside the
    /// container"), the file itself is the record, cut into pages of
    /// [`PAGE_BYTES`](ksg_core_v2::journal::PAGE_BYTES), its media type on
    /// the service page. Either way the attachment names its hash, so any
    /// copy is checked against the record.
    ///
    /// # Errors
    ///
    /// A file kept whole that does not fit one record; see [`Reader::press`].
    pub fn attach(
        &mut self,
        page_type: Uri,
        bytes: &[u8],
        name: &str,
        mime: &str,
        whole: bool,
    ) -> Result<(), String> {
        use ksg_core_v2::journal::{BATCH_CONTENT_PAGES, PAGE_BYTES};
        let digest = Hash::sha256(bytes);
        let a = Attachment {
            artifact: self.meta.artifact.clone(),
            kind: Kind::Media { mime: mime.into() },
            content_hash: digest,
            size: bytes.len() as u64,
            name: name.into(),
            derived_from: vec![],
            offset_ms: self.meta.artifact_offset_ms,
        };
        let spec = if whole {
            if bytes.is_empty() || bytes.len() > BATCH_CONTENT_PAGES * PAGE_BYTES {
                return Err(format!(
                    "attach: a file kept in the journal is 1 to {} bytes; keep this one outside",
                    BATCH_CONTENT_PAGES * PAGE_BYTES
                ));
            }
            PageSpec::Record {
                pieces: bytes
                    .chunks(PAGE_BYTES)
                    .map(|c| Piece::Inline(c.to_vec()))
                    .collect(),
                meta: RecordMeta {
                    kind: RecordKind::ArtifactOrRights,
                    content_type: Some(page_type),
                    media: Some(mime.into()),
                    ..RecordMeta::default()
                },
            }
        } else {
            PageSpec::Of {
                kind: RecordKind::ArtifactOrRights,
                content: Piece::Digest(digest),
                content_type: Some(page_type),
            }
        };
        self.press(
            Operation::AttachArtifactOrRights,
            &[Who::Client, Who::Owner],
            Evidence::Artifact(Box::new(a)),
            spec,
        )
    }

    /// The owner changes the journal's form (E-10, CH-30): to Pro with the
    /// issuer, as a raise — from then on every seal is anchored; back to the
    /// light form alone — what was paid for Pro is not returned (CH-23).
    ///
    /// # Errors
    ///
    /// See [`Reader::press`].
    pub fn form(&mut self, to: Mode) -> Result<(), String> {
        let who: &[Who] = match to {
            Mode::Pro => &[Who::Owner, Who::Issuer],
            Mode::Local => &[Who::Owner],
        };
        self.press(
            Operation::RaiseClass,
            who,
            Evidence::Form { to },
            PageSpec::Form(to),
        )
    }

    /// One page leaves; the container lives on. `by` is the owner or the
    /// client.
    ///
    /// # Errors
    ///
    /// See [`Reader::press`].
    pub fn export_page(&mut self, number: u64, by: Who) -> Result<BoundPoint, String> {
        self.press(
            Operation::ExportPoint,
            &[by],
            Evidence::Point { number },
            PageSpec::None,
        )?;
        self.c
            .take_point()
            .ok_or_else(|| "no page handed out".into())
    }

    /// Up to 24 pages leave at once — one pointwise export of the twelve
    /// (`[decision]` 06.10); the container lives on. `by` is the owner or the
    /// client.
    ///
    /// # Errors
    ///
    /// See [`Reader::press`].
    pub fn export_pages(&mut self, numbers: &[u64], by: Who) -> Result<Vec<BoundPoint>, String> {
        self.press(
            Operation::ExportPoint,
            &[by],
            Evidence::Points {
                numbers: numbers.to_vec(),
            },
            PageSpec::None,
        )?;
        self.c
            .take_points()
            .ok_or_else(|| "no pages handed out".into())
    }

    /// The issuer finalizes.
    ///
    /// # Errors
    ///
    /// See [`Reader::press`].
    pub fn finalize(&mut self) -> Result<(), String> {
        self.press(
            Operation::Finalize,
            &[Who::Issuer],
            Evidence::None,
            PageSpec::None,
        )
    }

    /// The owner and the client export everything; the container dies.
    ///
    /// # Errors
    ///
    /// See [`Reader::press`].
    pub fn export_final(&mut self) -> Result<BoundExport, String> {
        self.press(
            Operation::FullExport,
            &[Who::Owner, Who::Client],
            Evidence::Unload(Box::new(UnloadRoute::Principals)),
            PageSpec::None,
        )?;
        self.c
            .take_export()
            .ok_or_else(|| "no export handed out".into())
    }

    /// The keys a verifier checks the client's pages with, as `ksg-verify`
    /// reads them.
    ///
    /// # Errors
    ///
    /// Never in practice: public keys serialize.
    pub fn client_keys_json(&self) -> Result<Vec<u8>, String> {
        let client = self
            .meta
            .client
            .as_ref()
            .ok_or("the container is not initiated: no client's key yet")?;
        serde_json::to_vec_pretty(&[client]).map_err(e)
    }

    /// The status section with every record's anchor, as JSON — what a third
    /// party checks the container's status with (spec v2 §11, §12).
    ///
    /// # Errors
    ///
    /// Does not serialize.
    pub fn status_export_json(&self) -> Result<Vec<u8>, String> {
        if self.owes_anchor() {
            return Err(
                "a memo is owed to the network: the last record carries a placeholder; \
                 run any command that writes, or wait and try again"
                    .into(),
            );
        }
        serde_json::to_vec_pretty(&self.c.status_export()).map_err(e)
    }

    /// The issuer's public key, as a key set: what signed the status records.
    ///
    /// # Errors
    ///
    /// Does not serialize.
    pub fn issuer_keys_json(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec_pretty(&[self.parties.issuer.public()]).map_err(e)
    }

    /// The container's state, one line per fact.
    #[must_use]
    pub fn status_lines(&self) -> Vec<String> {
        vec![
            format!("container  {}", self.meta.id),
            format!("class      {:?}", self.meta.class),
            format!("status     {:?}", self.c.status()),
            format!("pages      {}", self.c.pages()),
            format!(
                "top seal   {}",
                self.c
                    .top_seal_hash()
                    .map_or_else(|| "none".into(), |h| h.to_multihash())
            ),
            format!(
                "form       {}",
                match self.c.form() {
                    None => "journal not open",
                    Some(Mode::Local) => "light (no anchors)",
                    Some(Mode::Pro) => "Pro (every seal anchored)",
                }
            ),
            format!("pending    {}", self.c.pending().len()),
            match (&self.meta.anchor, &self.anchorer) {
                (Some(cfg), Some((a, _))) => format!(
                    "anchor     solana:{} payer {} balance {}",
                    cfg.cluster,
                    a.address,
                    a.balance()
                        .map_or_else(|x| format!("? ({x})"), |b| format!("{b} lamports"))
                ),
                _ => "anchor     local placeholder".into(),
            },
            format!(
                "owed       {}",
                self.meta.anchor.as_ref().map_or(0, |c| c.pending.len())
            ),
            format!("viewed     {}", self.c.views().seen()),
            // 13.10: where a `bare` stands with its attachment.
            format!(
                "coupling   {}",
                if self.c.burned() {
                    "detached, the copy burned"
                } else if self.c.bare_attached() {
                    "attached as a trailer: read-only"
                } else if self.c.bare_attaching() {
                    "being attached: the hand-off, then the coupling page"
                } else {
                    "none"
                }
            ),
        ]
    }
}
