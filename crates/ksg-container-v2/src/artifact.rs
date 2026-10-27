//! Attaching the artefact, and the one check that makes it the right one.
//! KS-8 E-6, C-3, C-10.
//!
//! # The container *is* its artefact, and that can be verified
//!
//! A container's identifier is **derived** (C-3): emission, serial, the agent's
//! key, **the artefact** and the offset go into one digest. Two consequences,
//! and the second one is this module:
//!
//! 1. one container holds exactly one artefact — a second artefact would be a
//!    second container;
//! 2. **the artefact attached can be checked against the identifier itself.**
//!
//! So attaching is not a matter of trust. Recompute the identifier from the
//! attachment and compare: a different artefact gives a different identifier, and
//! the mismatch is arithmetic rather than opinion.
//!
//! `[inference]` This is the strongest check in the layer around the container, and it
//! costs one hash. It is worth naming why it exists at all: without it, "one
//! container, one artefact" would be a sentence in a specification, and the
//! substitution of an artefact after the fact would be invisible.
//!
//! # What is attached besides the artefact
//!
//! `[decision]` E-6, the owner: "attaching the artefact **and data about it**". The data are
//! descriptive and the container does not read them, so they are held as stated
//! and hashed into what the parties sign. Two of them are singled out because a
//! reader needs them to make sense of the rest:
//!
//! | Field | Why it is its own field |
//! |---|---|
//! | `kind` | what kind of thing this is — media, a task, a process, or a kind the product adds later (`[decision]` 22.09, CT-43) |
//! | `content_hash`, `size`, `name` | **all three required** (`[decision]` 19.09 CT-28 item 4, the name made required `[decision]` 22.09 CT-43): the hash is what proves the bytes, the size is the cheap first check, the name is for the people who read the record |
//! | `derived_from` | what it was made out of. An agent's output is usually somebody's input, and provenance that is not recorded at attachment cannot be reconstructed later |

use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::PublicKey;
use ksg_core_v2::doc::{derive_container_id, Serial, Timestamp, Uri};

/// What can go wrong when attaching.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ArtifactError {
    /// The attached artefact is not the one this container is.
    #[error("this artefact does not derive this container's identifier")]
    NotThisContainer,
    /// A description with nothing in it: no media type, no task description,
    /// no named kind.
    #[error("an artefact is attached with its kind stated")]
    NoMedia,
    /// The name is required (`[decision]` 22.09, CT-43).
    #[error("an artefact is attached with its name")]
    NoName,
    /// An empty artefact: nothing to hash, nothing to keep.
    #[error("an artefact of zero bytes is not an artefact")]
    Empty,
    /// A process says what role it is carried out in.
    #[error("a process states its role")]
    NoRole,
    /// A process that ends before it starts.
    #[error("a process cannot end before it starts")]
    EndsBeforeStart,
}

/// Who a source came from — `[decision]` 22.09 names orchestrator, owner and
/// administrator, "and so on", so the list stays open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceFrom {
    /// Another agent directing this one.
    Orchestrator,
    /// The agent's owner.
    Owner,
    /// An administrator.
    Administrator,
    /// Anybody the three do not cover, named in words.
    Other(String),
}

impl SourceFrom {
    fn label(&self) -> &str {
        match self {
            Self::Orchestrator => "orchestrator",
            Self::Owner => "owner",
            Self::Administrator => "administrator",
            Self::Other(s) => s,
        }
    }
}

/// One source of a task or a process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    /// Who it came from.
    pub from: SourceFrom,
    /// Their identifier, where they have one.
    pub by: Option<Uri>,
    /// What they gave, by reference.
    pub reference: Option<Uri>,
}

/// A task: what was asked, by whom, with what (`[decision]` 22.09, CT-43).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskArtifact {
    /// What the task is.
    pub description: String,
    /// Where it came from, and from whom.
    pub sources: Vec<Source>,
    /// References, content and context, by reference.
    pub references: Vec<Uri>,
}

/// How a process ends.
///
/// `[decision]` 22.09 (CT-46): a **watch** is a form with a start and an end,
/// date and time, and a mark of whether it is one-off or repeats. The next
/// start follows its own schedule, and that is not ours: the cycle, the
/// schedule and deviations from it are not recorded — only this start-stop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum End {
    /// On a date.
    At(Timestamp),
    /// Without an end.
    Indefinite,
    /// A watch: ends at `until`; `repeats` says whether this start-stop is
    /// one-off or one of a recurring series.
    Watch {
        /// The end of this watch, date and time.
        until: Timestamp,
        /// One-off (`false`) or recurring (`true`).
        repeats: bool,
    },
}

/// A process: **always** with a start or an entry, and an end (`[decision]` 22.09).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Process {
    /// When it started, or when this agent entered it.
    pub start: Timestamp,
    /// How it ends.
    pub end: End,
    /// The role the agent carries it out in.
    pub role: String,
    /// Where it came from.
    pub sources: Vec<Source>,
    /// The rules it runs under, by reference.
    pub rules: Vec<Uri>,
}

/// What kind of thing the artefact is (`[decision]` 22.09, CT-43).
///
/// Open by design: "other kinds that will develop with the product". A new
/// kind is a new arm; [`Kind::Other`] carries one before it has its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    /// A file, by its IANA media type (`image/png`, `application/pdf`).
    Media {
        /// The media type.
        mime: String,
    },
    /// A task.
    Task(TaskArtifact),
    /// A process.
    Process(Process),
    /// A kind the product has not given its own arm yet.
    Other {
        /// What kind, as a URI.
        kind: Uri,
        /// What it is, in words.
        description: String,
    },
}

/// The artefact and the data about it. KS-8 E-6, C-6.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attachment {
    /// The artefact, as the identifier's derivation names it.
    pub artifact: Uri,
    /// What kind of thing it is.
    pub kind: Kind,
    /// The hash of its content. For a task or a process, of its description in
    /// canonical form.
    ///
    /// **Not** part of the container's identifier: the identity is the
    /// container, release, serial and moment (`[decision]` 19.09, CT-28 item 3), and a
    /// file re-saved by its keeper would otherwise take the container with it.
    pub content_hash: Hash,
    /// Its size in bytes.
    pub size: u64,
    /// Its name. Required.
    pub name: String,
    /// What it was made from, if anything — by their artefact URIs.
    pub derived_from: Vec<Uri>,
    /// The offset at which the container was initiated, which is one of the
    /// inputs to its identifier.
    pub offset_ms: u64,
}

impl Attachment {
    /// Whether this attachment is the artefact this container is.
    ///
    /// Recomputes the identifier from the parts and compares. A different
    /// artefact, a different agent key, a different serial, a different release
    /// time or a different offset all give a different identifier, so one
    /// comparison covers all five.
    ///
    /// # Errors
    ///
    /// [`ArtifactError`] for an attachment whose data is incomplete — no kind,
    /// no name, no bytes, a process without a role or ending before it starts;
    /// [`ArtifactError::NotThisContainer`] when the derivation does not come out
    /// at this container's identifier.
    pub fn check(
        &self,
        container: &Hash,
        emission: &str,
        issued_at: &Timestamp,
        serial: Serial,
        agent: &PublicKey,
    ) -> Result<(), ArtifactError> {
        match &self.kind {
            Kind::Media { mime } if mime.trim().is_empty() => {
                return Err(ArtifactError::NoMedia);
            }
            Kind::Task(t) if t.description.trim().is_empty() => {
                return Err(ArtifactError::NoMedia);
            }
            Kind::Other { description, .. } if description.trim().is_empty() => {
                return Err(ArtifactError::NoMedia);
            }
            Kind::Process(p) => {
                if p.role.trim().is_empty() {
                    return Err(ArtifactError::NoRole);
                }
                if let End::At(end) | End::Watch { until: end, .. } = &p.end {
                    if end.as_str() < p.start.as_str() {
                        return Err(ArtifactError::EndsBeforeStart);
                    }
                }
            }
            _ => {}
        }
        if self.name.trim().is_empty() {
            return Err(ArtifactError::NoName);
        }
        if self.size == 0 {
            return Err(ArtifactError::Empty);
        }
        let derived = derive_container_id(
            emission,
            issued_at,
            serial,
            agent,
            &self.artifact,
            self.offset_ms,
        );
        if &derived != container {
            return Err(ArtifactError::NotThisContainer);
        }
        Ok(())
    }

    /// The digest the parties sign when attaching.
    ///
    /// Covers every field: provenance that is signed cannot be edited
    /// afterwards, and provenance that is not signed is a note rather than a
    /// record. Lists are prefixed with their length, so that no two different
    /// attachments frame into the same fields.
    #[must_use]
    pub fn subject(&self, container: &Hash) -> Hash {
        let mut parts: Vec<Vec<u8>> = vec![
            b"ksg:artifact-attach:v2".to_vec(),
            container.as_bytes().to_vec(),
            self.artifact.as_str().as_bytes().to_vec(),
            self.content_hash.as_bytes().to_vec(),
            self.size.to_be_bytes().to_vec(),
            self.name.as_bytes().to_vec(),
            self.offset_ms.to_be_bytes().to_vec(),
        ];
        kind_fields(&self.kind, &mut parts);
        list(&mut parts, self.derived_from.iter().map(Uri::as_str));
        let refs: Vec<&[u8]> = parts.iter().map(std::vec::Vec::as_slice).collect();
        Hash::sha256_fields(&refs)
    }
}

fn list<'a>(parts: &mut Vec<Vec<u8>>, items: impl ExactSizeIterator<Item = &'a str>) {
    parts.push((items.len() as u64).to_be_bytes().to_vec());
    for s in items {
        parts.push(s.as_bytes().to_vec());
    }
}

fn sources(parts: &mut Vec<Vec<u8>>, sources: &[Source]) {
    parts.push((sources.len() as u64).to_be_bytes().to_vec());
    for s in sources {
        parts.push(s.from.label().as_bytes().to_vec());
        parts.push(
            s.by.as_ref()
                .map_or(b"-".to_vec(), |u| u.as_str().as_bytes().to_vec()),
        );
        parts.push(
            s.reference
                .as_ref()
                .map_or(b"-".to_vec(), |u| u.as_str().as_bytes().to_vec()),
        );
    }
}

fn kind_fields(kind: &Kind, parts: &mut Vec<Vec<u8>>) {
    match kind {
        Kind::Media { mime } => {
            parts.push(b"media".to_vec());
            parts.push(mime.as_bytes().to_vec());
        }
        Kind::Task(t) => {
            parts.push(b"task".to_vec());
            parts.push(t.description.as_bytes().to_vec());
            sources(parts, &t.sources);
            list(parts, t.references.iter().map(Uri::as_str));
        }
        Kind::Process(p) => {
            parts.push(b"process".to_vec());
            parts.push(p.start.as_str().as_bytes().to_vec());
            match &p.end {
                End::At(e) => parts.push(e.as_str().as_bytes().to_vec()),
                End::Indefinite => parts.push(b"indefinite".to_vec()),
                End::Watch { until, repeats } => {
                    parts.push(b"watch".to_vec());
                    parts.push(until.as_str().as_bytes().to_vec());
                    parts.push(if *repeats {
                        b"repeats".to_vec()
                    } else {
                        b"once".to_vec()
                    });
                }
            }
            parts.push(p.role.as_bytes().to_vec());
            sources(parts, &p.sources);
            list(parts, p.rules.iter().map(Uri::as_str));
        }
        Kind::Other { kind, description } => {
            parts.push(b"other".to_vec());
            parts.push(kind.as_str().as_bytes().to_vec());
            parts.push(description.as_bytes().to_vec());
        }
    }
}
