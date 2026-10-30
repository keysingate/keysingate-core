//! The home directory: the container on a disk, and what the MVP keeps next
//! to it.
//!
//! | File | What | Secret |
//! |---|---|---|
//! | `container.ksg` | the container, sealed (`ksg-container::store`) | no — sealed |
//! | `layer.key` | the key it is sealed under: the holder's layer key (`[decision]` 23.09) | **yes** |
//! | `parties.json` | seeds of the issuer, the owner, the buyer and the issuer's seal | **yes** |
//! | `container.json` | what the reader needs to know without opening the container | no |
//! | `sale.json` | on a packet: the sale, from printing to initiation | no |
//! | `agent-id.json` | the agent's ID as published, with its anchor (KS-8 C-10) | no — public |
//! | `handovers.json` | the sealed hand-overs of layer keys (E-3) | no — sealed to their recipients |
//!
//! Secrets are written with mode `0600` and never printed.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use ksg_core_v2::crypto::sign::{Ed25519Signer, PublicKey};
use ksg_core_v2::doc::{Class, Serial, Timestamp, Uri};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Where the files of one container are.
#[derive(Debug, Clone)]
pub struct Home(pub PathBuf);

impl Home {
    /// `container.ksg`.
    #[must_use]
    pub fn container(&self) -> PathBuf {
        self.0.join("container.ksg")
    }
    /// `layer.key`.
    #[must_use]
    pub fn layer_key(&self) -> PathBuf {
        self.0.join("layer.key")
    }
    /// `scan.key`: the holder's scanning key for the blind seal anchors, hex.
    #[must_use]
    pub fn scan_key(&self) -> PathBuf {
        self.0.join("scan.key")
    }
    /// `parties.json`.
    #[must_use]
    pub fn parties(&self) -> PathBuf {
        self.0.join("parties.json")
    }
    /// `container.json`.
    #[must_use]
    pub fn meta(&self) -> PathBuf {
        self.0.join("container.json")
    }
    /// `sale.json`: the packet as sold, kept from printing to initiation.
    #[must_use]
    pub fn sale(&self) -> PathBuf {
        self.0.join("sale.json")
    }
    /// `handovers.json`: the sealed hand-overs of layer keys (E-3), in order.
    /// Sealed to their recipients — not a secret.
    #[must_use]
    pub fn handovers(&self) -> PathBuf {
        self.0.join("handovers.json")
    }
    /// `agent-id.json`: the agent's ID as published for this container
    /// (KS-8 C-10, step 1). Public by design.
    #[must_use]
    pub fn agent_id(&self) -> PathBuf {
        self.0.join("agent-id.json")
    }
    /// `channel.json`: the documents from the release to this container.
    #[must_use]
    pub fn channel(&self) -> PathBuf {
        self.0.join("channel.json")
    }
    /// `lock`: present while a reader has the container open.
    #[must_use]
    pub fn lock(&self) -> PathBuf {
        self.0.join("lock")
    }
}

/// One reader at a time per home directory.
///
/// Two readers on one container would each seal their own next state and the
/// later write would erase the earlier — two journals from one head, which is
/// the fork of audit K5 made by accident. The lock is a file created with
/// `create_new`, removed when the reader closes. A reader that crashed leaves
/// it behind; removing it by hand is the owner's call, not the program's.
#[derive(Debug)]
pub struct Lock(PathBuf);

impl Lock {
    /// Takes the lock of `home`.
    ///
    /// # Errors
    ///
    /// Another reader holds it, or the file system refused.
    pub fn take(home: &Home) -> Result<Self, String> {
        Self::at(home.lock(), &home.0)
    }

    /// Takes the lock file `path`, guarding `what` (named in the refusal).
    ///
    /// # Errors
    ///
    /// Another process holds it, or the file system refused.
    pub fn at(path: PathBuf, what: &Path) -> Result<Self, String> {
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(_) => Ok(Self(path)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(format!(
                "{} is open by another reader (remove {} if none is running)",
                what.display(),
                path.display()
            )),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// What the reader knows about its container without opening it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Meta {
    /// The container identifier, as a multihash — before initiation, the
    /// template's (CH-5b).
    pub id: String,
    /// The template identifier, as a multihash: what the file and the
    /// issuer's word at printing are bound to, for the container's whole life.
    pub template: String,
    /// The class of the release.
    pub class: Class,
    /// The release identifier.
    pub emission: String,
    /// The moment of issuance.
    pub issued_at: Timestamp,
    /// The same moment, in milliseconds since the epoch.
    pub issued_ms: u64,
    /// The serial.
    pub serial: Serial,
    /// The artefact the container is bound to.
    pub artifact: Uri,
    /// The artefact's offset, part of the identifier.
    pub artifact_offset_ms: u64,
    /// The last offset written: offsets grow strictly.
    pub clock_ms: u64,
    /// The client's key: none until initiation (CH-5b).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<PublicKey>,
    /// The container's own post-quantum key: it signs the stored file
    /// outside (CH-5a, CH-5b). Absent for `Bare` (criterion G1-4: no
    /// post-quantum wrapping — the field is missing, not empty).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pq: Option<PublicKey>,
    /// The issuer's signature, given at printing, that `pq` is this
    /// container's key (`ksg_container_v2::store::pq_cert_message`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pq_cert: Option<ksg_core_v2::crypto::sign::Signature>,
    /// Where pages are anchored; absent — the local placeholder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<crate::anchoring::AnchorCfg>,
    /// Where a `light` container anchors on Base Sepolia (owner's decisions
    /// 14.10); absent — not anchored there.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<crate::base_anchor::BaseCfg>,
}

/// Seeds of the parties the MVP plays itself.
#[derive(Serialize, Deserialize)]
pub struct Seeds {
    /// The issuer.
    pub issuer: String,
    /// The owner.
    pub owner: String,
    /// The buyer.
    pub buyer: String,
    /// The issuer's seal.
    pub seal: String,
    /// The owner's key identifier when it is not the printed owner's: after
    /// an owner's change of an attachment (E-9 in `bare`, 13.10) the owner is
    /// the leader's, under an identifier of its own — the container pins the
    /// first key it sees under an identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_kid: Option<String>,
}

impl Drop for Seeds {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.issuer.zeroize();
        self.owner.zeroize();
        self.buyer.zeroize();
        self.seal.zeroize();
    }
}

/// The parties' signers, rebuilt from their seeds.
pub struct Parties {
    /// The issuer.
    pub issuer: Ed25519Signer,
    /// The owner.
    pub owner: Ed25519Signer,
    /// The buyer.
    pub buyer: Ed25519Signer,
    /// The issuer's seal seed.
    pub seal: Zeroizing<[u8; 32]>,
}

fn uri(s: &str) -> Uri {
    Uri::parse(s).expect("a constant URI")
}

/// Key identifiers of the MVP's parties.
pub mod kid {
    /// The issuer.
    pub const ISSUER: &str = "did:key:zKsgIssuer#k1";
    /// The issuer as a party (what a release names as its issuer).
    pub const ISSUER_PARTY: &str = "did:key:zKsgIssuer";
    /// The owner.
    pub const OWNER: &str = "did:key:zKsgOwner#k1";
    /// The buyer.
    pub const BUYER: &str = "did:key:zKsgBuyer#k1";
    /// The issuer's seal.
    pub const SEAL: &str = "did:key:zKsgSeal#k1";
    /// The name a client's key carries until it is born (G-1).
    ///
    /// A birth names its key by the `did:key` of the group key, and that key
    /// exists only when the birth is done — before it there is nothing to
    /// compute a name from. So a key in the making, and a capsule sealed
    /// before initiation, carry this instead. It is never signed: the first
    /// signature under the key is made after the name is given.
    pub const UNBORN: &str = "urn:ksg:client:unborn#keygen";
    /// The container's own post-quantum key (CH-5b).
    pub const CONTAINER_PQ: &str = "did:key:zKsgContainer#pq";
}

/// The owner's seed, for keys expanded from it under labels of their own
/// (the owner's read key of the issuance label, 17.10).
///
/// # Errors
///
/// A seed that is not 32 bytes of base64url.
pub fn owner_seed(s: &Seeds) -> Result<Zeroizing<[u8; 32]>, String> {
    seed(&s.owner)
}

fn seed(s: &str) -> Result<Zeroizing<[u8; 32]>, String> {
    let v = Zeroizing::new(
        B64.decode(s)
            .map_err(|_| "parties.json: a seed is not base64url")?,
    );
    let mut out = Zeroizing::new([0u8; 32]);
    if v.len() != 32 {
        return Err("parties.json: a seed is not 32 bytes".into());
    }
    out.copy_from_slice(&v);
    Ok(out)
}

impl Parties {
    /// The test seeds of the parties of home `label` (`crate::testkeys`):
    /// the issuer's and the seal's are the release-wide test keys, the owner's
    /// and the buyer's are named after the home.
    #[must_use]
    pub fn test(label: &str) -> Seeds {
        use crate::testkeys::{seed, ISSUER, SEAL};
        let one = |l: &str| B64.encode(seed(l));
        Seeds {
            issuer: one(ISSUER),
            owner: one(&format!("owner:{label}")),
            buyer: one(&format!("buyer:{label}")),
            seal: one(SEAL),
            owner_kid: None,
        }
    }

    /// The signers from their seeds.
    ///
    /// # Errors
    ///
    /// A seed that is not 32 bytes of base64url.
    pub fn from_seeds(s: &Seeds) -> Result<Self, String> {
        let signer = |kid: &str, v: &str| seed(v).map(|b| Ed25519Signer::from_seed(uri(kid), *b));
        Ok(Self {
            issuer: signer(kid::ISSUER, &s.issuer)?,
            owner: match &s.owner_kid {
                None => signer(kid::OWNER, &s.owner)?,
                Some(k) => {
                    let k = Uri::parse(k.clone())
                        .map_err(|_| "parties.json: the owner's key identifier is not a URI")?;
                    Ed25519Signer::from_seed(k, *seed(&s.owner)?)
                }
            },
            buyer: signer(kid::BUYER, &s.buyer)?,
            seal: seed(&s.seal)?,
        })
    }
}

/// Writes `bytes` to `path` through a temporary file and a rename, so that a
/// crash leaves the old file or the new one, never half of one. Mode `0600`
/// when `secret`.
///
/// # Errors
///
/// The file system refused.
pub fn write_atomic(path: &Path, bytes: &[u8], secret: bool) -> Result<(), String> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = secret;
    let mut f = opts
        .open(&tmp)
        .map_err(|e| format!("{}: {e}", tmp.display()))?;
    f.write_all(bytes)
        .and_then(|()| f.sync_all())
        .map_err(|e| format!("{}: {e}", tmp.display()))?;
    fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
}

/// Reads a file, naming it in the error.
///
/// # Errors
///
/// The file does not read.
pub fn read(path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|e| format!("{}: {e}", path.display()))
}
