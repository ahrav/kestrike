//! The choice schema: the one contract every nondeterministic
//! decision of the simulation harness goes through.
//!
//! A decision names its identity: the schema, a domain, an actor, the
//! actor's incarnation, a preregistered site and the site's occurrence
//! within that incarnation. The identity's canonical bytes and the run's
//! root seed SplitMix64 through SHA-256, so a decision's value depends only
//! on the root, its namespace and how many decisions the site made before
//! it. A decision draws an index among canonical candidates, a bounded
//! integer or a byte fill, and the chooser records it as fixed-width tagged
//! records before the caller applies its effect. Replay reads those records
//! back and refuses short input, a different candidate set and an index
//! outside the candidates, each by its own error before the decision's
//! effect, and `finish` refuses trailing input. The persistence domain and
//! the crash kind stay refused unless the chooser runs under the
//! [`Admission`] of a recovery profile.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use crate::storage::seeded::SplitMix64;

/// The schema version every identity carries.
pub(crate) const SCHEMA: u16 = 1;

/// Bytes of every record.
pub(crate) const RECORD_LEN: usize = 32;

/// Bytes of a candidate descriptor.
pub(crate) const CANDIDATE_LEN: usize = 16;

/// Entropy bytes one record carries.
const ENTROPY_PER_RECORD: usize = RECORD_LEN - 2;

/// The domain separator hashed ahead of the root and the identity.
const DERIVATION: &[u8; 16] = b"image-cache cv1\0";

/// Who a decision belongs to. `Persistence` is reserved for the
/// persistence and crash domain: a chooser decides at its sites only under
/// an [`Admission`], and an admitted chooser checks each crash candidate
/// against the admitted cut table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub(crate) enum Domain {
    Workload = 1,
    Disk = 2,
    Link = 3,
    Clock = 4,
    Entropy = 5,
    Put = 6,
    Persistence = 7,
    Chaos = 8,
}

impl Domain {
    pub(crate) fn from_code(code: u8) -> Option<Self> {
        [
            Self::Workload,
            Self::Disk,
            Self::Link,
            Self::Clock,
            Self::Entropy,
            Self::Put,
            Self::Persistence,
            Self::Chaos,
        ]
        .into_iter()
        .find(|domain| *domain as u8 == code)
    }

    fn reserved(self) -> bool {
        self == Self::Persistence
    }
}

/// The kinds of recorded events. `Crash` is reserved with the persistence
/// domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub(crate) enum EventKind {
    Action = 1,
    Delivery = 2,
    Completion = 3,
    Release = 4,
    Advance = 5,
    Crash = 6,
}

impl EventKind {
    /// The kind, or `HarnessDefect` for the reserved crash kind outside an
    /// admission.
    pub(crate) fn admit(self, admission: Option<&Admission>) -> Result<Self, ChoiceError> {
        match (self, admission) {
            (Self::Crash, None) => Err(ChoiceError::HarnessDefect(Defect::ReservedEvent)),
            (kind, _) => Ok(kind),
        }
    }
}

/// Bytes of the cut-table hash prefix a crash candidate carries.
pub(crate) const TABLE_PREFIX: usize = CANDIDATE_LEN - 6;

/// What a parsed recovery record admits: the persistence domain, and crash
/// candidates naming one of `cuts` entries of the cut table whose SHA-256
/// starts with `table`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Admission {
    pub(crate) cuts: u32,
    pub(crate) table: [u8; TABLE_PREFIX],
}

impl Admission {
    /// The crash candidate for cut `index`: the persistence domain byte, the
    /// crash kind byte, the index big-endian and the table prefix, or `None`
    /// past the table's end.
    pub(crate) fn candidate(&self, index: u32) -> Option<Candidate> {
        if index >= self.cuts {
            return None;
        }
        let mut bytes = [0; CANDIDATE_LEN];
        bytes[0] = Domain::Persistence as u8;
        bytes[1] = EventKind::Crash as u8;
        bytes[2..6].copy_from_slice(&index.to_be_bytes());
        bytes[6..].copy_from_slice(&self.table);
        Some(Candidate(bytes))
    }

    /// The cut index `candidate` names under this admission, or `None` for
    /// a candidate of another kind, table or index past the table's end.
    pub(crate) fn cut(&self, candidate: &Candidate) -> Option<u32> {
        let index = u32::from_be_bytes(candidate.0[2..6].try_into().expect("four bytes"));
        (self.candidate(index) == Some(*candidate)).then_some(index)
    }
}

/// A decision site: one place in the harness topology where an actor
/// decides. Sites are registered before the first decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Site {
    pub(crate) domain: Domain,
    pub(crate) actor: u16,
    pub(crate) site: u16,
}

impl Site {
    /// The site as one integer, distinct for distinct sites: the domain in
    /// bits 32 and up, the actor in bits 16 to 31 and the site number in the
    /// low 16 bits.
    const fn key(self) -> u64 {
        (self.domain as u64) << 32 | (self.actor as u64) << 16 | self.site as u64
    }
}

/// The full identity of one decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Identity {
    pub(crate) site: Site,
    pub(crate) incarnation: u32,
    pub(crate) occurrence: u32,
}

/// Bytes of an identity's canonical encoding.
pub(crate) const IDENTITY_LEN: usize = 15;

/// Offset of the domain byte in an identity's canonical encoding.
const DOMAIN_AT: usize = 2;

impl Identity {
    /// Schema, domain, actor, incarnation, site and occurrence, little-endian
    /// at fixed offsets.
    pub(crate) fn canonical(&self) -> [u8; IDENTITY_LEN] {
        let mut out = [0; IDENTITY_LEN];
        out[0..2].copy_from_slice(&SCHEMA.to_le_bytes());
        out[DOMAIN_AT] = self.site.domain as u8;
        out[3..5].copy_from_slice(&self.site.actor.to_le_bytes());
        out[5..9].copy_from_slice(&self.incarnation.to_le_bytes());
        out[9..11].copy_from_slice(&self.site.site.to_le_bytes());
        out[11..15].copy_from_slice(&self.occurrence.to_le_bytes());
        out
    }

    /// The first eight bytes, little-endian, of SHA-256 over the derivation
    /// separator, the root and the canonical identity.
    pub(crate) fn seed(&self, root: u64) -> u64 {
        let mut hash = Sha256::new();
        hash.update(DERIVATION);
        hash.update(root.to_le_bytes());
        hash.update(self.canonical());
        let digest = hash.finalize();
        u64::from_le_bytes(digest[..8].try_into().expect("eight bytes"))
    }
}

/// A canonical candidate descriptor: fixed-width bytes that name what a
/// candidate is. Every byte is a process-stable, nonsecret value, so tapes
/// and bundles replay byte for byte across processes: a field value, the
/// simulated time `PutAction::Defer` holds, or a crash candidate's cut
/// table hash prefix, under which an admission makes a candidate naming
/// another table or an index past its end [`Defect::Table`]. Candidates
/// compare by their bytes, the total order a decision's set must follow.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Candidate(pub(crate) [u8; CANDIDATE_LEN]);

/// The PUT actions an upload decision chooses among, as canonical
/// descriptors: the PUT domain byte and a tag, then key, attempt and an
/// action argument big-endian, so descriptors sort by those fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PutAction {
    /// The client invokes PUT and sends BEGIN.
    Begin {
        key: u32,
        attempt: u16,
    },
    /// The owner prepares the attempt's fill.
    Prepare {
        key: u32,
        attempt: u16,
    },
    /// The supplier hands fragment `fragment` to the client.
    Supply {
        key: u32,
        attempt: u16,
        fragment: u32,
    },
    /// The supplier defers its next fragment until `ready_us`.
    Defer {
        key: u32,
        attempt: u16,
        ready_us: u32,
    },
    Cancel {
        key: u32,
        attempt: u16,
    },
    Abandon {
        key: u32,
        attempt: u16,
    },
    /// The attempt's outcome reaches the client.
    Outcome {
        key: u32,
        attempt: u16,
    },
    /// The client retries the attempt in the same session.
    Retry {
        key: u32,
        attempt: u16,
    },
}

impl PutAction {
    pub(crate) fn candidate(self) -> Candidate {
        let (tag, key, attempt, argument) = match self {
            Self::Begin { key, attempt } => (1, key, attempt, 0),
            Self::Prepare { key, attempt } => (2, key, attempt, 0),
            Self::Supply {
                key,
                attempt,
                fragment,
            } => (3, key, attempt, fragment),
            Self::Defer {
                key,
                attempt,
                ready_us,
            } => (4, key, attempt, ready_us),
            Self::Cancel { key, attempt } => (5, key, attempt, 0),
            Self::Abandon { key, attempt } => (6, key, attempt, 0),
            Self::Outcome { key, attempt } => (7, key, attempt, 0),
            Self::Retry { key, attempt } => (8, key, attempt, 0),
        };
        let mut bytes = [0; CANDIDATE_LEN];
        bytes[0] = Domain::Put as u8;
        bytes[1] = tag;
        bytes[2..6].copy_from_slice(&key.to_be_bytes());
        bytes[6..8].copy_from_slice(&attempt.to_be_bytes());
        bytes[8..12].copy_from_slice(&argument.to_be_bytes());
        Candidate(bytes)
    }

    /// The action `candidate` describes, or `None` for a candidate outside
    /// the PUT domain or with an unknown tag.
    pub(crate) fn from_candidate(candidate: &Candidate) -> Option<Self> {
        let bytes = &candidate.0;
        if bytes[0] != Domain::Put as u8 {
            return None;
        }
        let key = u32::from_be_bytes(bytes[2..6].try_into().expect("four bytes"));
        let attempt = u16::from_be_bytes(bytes[6..8].try_into().expect("two bytes"));
        let argument = u32::from_be_bytes(bytes[8..12].try_into().expect("four bytes"));
        Some(match bytes[1] {
            1 => Self::Begin { key, attempt },
            2 => Self::Prepare { key, attempt },
            3 => Self::Supply {
                key,
                attempt,
                fragment: argument,
            },
            4 => Self::Defer {
                key,
                attempt,
                ready_us: argument,
            },
            5 => Self::Cancel { key, attempt },
            6 => Self::Abandon { key, attempt },
            7 => Self::Outcome { key, attempt },
            8 => Self::Retry { key, attempt },
            _ => return None,
        })
    }
}

/// A harness bug, as opposed to a property of the system under test.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Defect {
    /// A decision at a site the topology never registered.
    Unregistered(Site),
    /// A decision in the reserved persistence and crash domain without an
    /// admission.
    ReservedDomain,
    /// An event of the reserved crash kind without an admission.
    ReservedEvent,
    /// Under an admission, a crash candidate, one whose first two bytes are
    /// the persistence domain and the crash kind, that names another cut
    /// table or an index past the admitted table's end.
    Table,
    /// Candidates out of their total order, or repeated.
    Unordered,
    /// An index among no candidates, or a bound of zero.
    Empty,
    /// A site's occurrence counter reached `u32::MAX` in one incarnation;
    /// counting a further decision would overflow it and wrap to an
    /// identity already used.
    Occurrences(Site),
    /// More candidates, or a longer fill, than a record's 32-bit size names.
    Oversized,
    /// A decision for an incarnation other than the actor's current one.
    Incarnation { actor: u16, incarnation: u32 },
    /// A decision at this site found its chooser already borrowed.
    #[cfg(test)]
    Borrowed(Site),
}

/// Why a decision or a replay failed. Every decision failure precedes that
/// decision's effect; `Trailing` comes from `finish`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ChoiceError {
    HarnessDefect(Defect),
    /// The replayed input ended inside or before a record the decision needs.
    Short,
    /// The replayed record names another decision or departs from the
    /// recorded layout: another identity or kind, a fill length, a bound, a
    /// tag other than a candidate's, or nonzero padding. A changed candidate
    /// count or candidate record reports `Candidates`.
    Identity,
    /// The replayed candidate set differs from the decision's, such as
    /// crash candidates of another cut table.
    Candidates,
    /// The replayed selection lies outside the candidates or the bound.
    Index {
        index: u64,
        len: u64,
    },
    /// Input remains after the last decision.
    Trailing {
        bytes: usize,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum Tag {
    Identity = 1,
    Candidate = 2,
    Selection = 3,
    Entropy = 4,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum Kind {
    Index = 1,
    Bounded = 2,
    Bytes = 3,
}

type Record = [u8; RECORD_LEN];

/// A record's bytes after its tag.
type Payload = [u8; RECORD_LEN - 1];

/// Appends a record of `tag` to `tape` and returns the record's payload,
/// the `RECORD_LEN - 1` bytes after its tag, for the caller to fill in
/// place. Bytes the caller leaves unwritten stay zero, the padding
/// [`Reader::next`] requires on replay.
fn append(tape: &mut Vec<u8>, tag: Tag) -> &mut [u8] {
    let start = tape.len();
    tape.resize(start + RECORD_LEN, 0);
    tape[start] = tag as u8;
    &mut tape[start + 1..]
}

/// The chooser's record of decisions: the tape it writes from its source,
/// or the tape it replays with the offset of the next record.
#[derive(Debug)]
enum Mode {
    Record { source: Source, tape: Vec<u8> },
    Replay { tape: Vec<u8>, at: usize },
}

/// Where a recording chooser's values come from.
#[derive(Debug)]
enum Source {
    /// Each decision's own stream, derived from the root and its identity.
    Root(u64),
    /// Bytes read in order from an input, with the offset of the next one:
    /// a decision below a bound takes the fewest little-endian bytes that
    /// hold the bound less one, at least one, modulo the bound, and a fill
    /// takes its length in bytes.
    Feed { input: Vec<u8>, at: usize },
}

impl Source {
    /// The value below `bound` for the decision `identity`, or `Short` when
    /// a feed holds too few bytes; a refused draw consumes nothing.
    fn below(&mut self, identity: Identity, bound: u64) -> Result<u64, ChoiceError> {
        match self {
            Self::Root(root) => Ok(SplitMix64::new(identity.seed(*root)).below(bound)),
            Self::Feed { input, at } => {
                let width = fed_width(bound);
                let bytes = input.get(*at..*at + width).ok_or(ChoiceError::Short)?;
                let mut word = [0; 8];
                word[..width].copy_from_slice(bytes);
                *at += width;
                Ok(u64::from_le_bytes(word) % bound)
            }
        }
    }

    /// Fills `out` for the decision `identity`, or `Short` when a feed holds
    /// too few bytes; a refused fill consumes nothing.
    fn fill(&mut self, identity: Identity, out: &mut [u8]) -> Result<(), ChoiceError> {
        match self {
            Self::Root(root) => {
                let mut stream = SplitMix64::new(identity.seed(*root));
                for word in out.chunks_mut(8) {
                    word.copy_from_slice(&stream.next_u64().to_le_bytes()[..word.len()]);
                }
            }
            Self::Feed { input, at } => {
                let bytes = input.get(*at..*at + out.len()).ok_or(ChoiceError::Short)?;
                out.copy_from_slice(bytes);
                *at += out.len();
            }
        }
        Ok(())
    }
}

fn fed_width(bound: u64) -> usize {
    let bits = 64 - (bound - 1).leading_zeros();
    (bits.div_ceil(8) as usize).max(1)
}

/// One recorded decision as a fed chooser reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Draw {
    /// An index's or bounded value's selection, little-endian in
    /// `fed_width(bound)` bytes, or a fill's bytes.
    pub(crate) bytes: Vec<u8>,
    pub(crate) fill: bool,
}

/// The decisions `tape` records, in record order, read with the replay
/// reader's layout and padding checks. `None` for a tape that ends inside
/// a decision, holds a record out of place, with nonzero padding or of an
/// unknown kind, a fill split otherwise than into 30-byte pieces with any
/// remainder last, a bounded identity with a nonzero size, an index bound
/// other than its candidate count or a selection outside its bound.
pub(crate) fn draws(tape: &[u8]) -> Option<Vec<Draw>> {
    let mut reader = Reader { tape, at: 0 };
    let mut out = Vec::new();
    while reader.at < tape.len() {
        let identity = reader.next(Tag::Identity, IDENTITY_PAYLOAD).ok()?;
        let size = u32::from_le_bytes(
            identity[IDENTITY_LEN + 1..IDENTITY_PAYLOAD]
                .try_into()
                .ok()?,
        ) as usize;
        let kind = identity[IDENTITY_LEN];
        if kind == Kind::Bytes as u8 {
            let mut bytes = Vec::new();
            while bytes.len() < size {
                let width = (size - bytes.len()).min(ENTROPY_PER_RECORD);
                let piece = reader.next(Tag::Entropy, 1 + width).ok()?;
                (usize::from(piece[0]) == width).then_some(())?;
                bytes.extend_from_slice(&piece[1..1 + width]);
            }
            out.push(Draw { bytes, fill: true });
            continue;
        }
        let candidates = match kind {
            kind if kind == Kind::Index as u8 => size,
            kind if kind == Kind::Bounded as u8 && size == 0 => 0,
            _ => return None,
        };
        for _ in 0..candidates {
            reader.next(Tag::Candidate, CANDIDATE_LEN).ok()?;
        }
        let selection = reader.next(Tag::Selection, 16).ok()?;
        let word =
            |at: usize| u64::from_le_bytes(selection[at..at + 8].try_into().expect("eight bytes"));
        let (value, bound) = (word(0), word(8));
        let index = kind == Kind::Index as u8;
        (value < bound && (!index || bound == size as u64)).then_some(())?;
        let bytes = value.to_le_bytes()[..fed_width(bound)].to_vec();
        out.push(Draw { bytes, fill: false });
    }
    Some(out)
}

/// `bounded_decisions` returns each bounded decision's site and selected
/// value in tape order, or `None` for a tape [`draws`] refuses or whose
/// bounded identity record names a domain code [`Domain::from_code`]
/// rejects.
#[cfg(test)]
pub(crate) fn bounded_decisions(tape: &[u8]) -> Option<Vec<(Site, u64)>> {
    draws(tape)?;
    let (records, _) = tape.as_chunks::<RECORD_LEN>();
    let mut out = Vec::new();
    for (at, record) in records.iter().enumerate() {
        let payload = &record[1..];
        if record[0] != Tag::Identity as u8 || payload[IDENTITY_LEN] != Kind::Bounded as u8 {
            continue;
        }
        // The actor and site offsets of `Identity::canonical`'s layout.
        const ACTOR_AT: usize = 3;
        const SITE_AT: usize = 9;
        let half = |at: usize| u16::from_le_bytes([payload[at], payload[at + 1]]);
        let site = Site {
            domain: Domain::from_code(payload[DOMAIN_AT])?,
            actor: half(ACTOR_AT),
            site: half(SITE_AT),
        };
        // `draws` accepted the tape, so a bounded decision's selection
        // record follows its identity record.
        let selection = &records[at + 1][1..];
        let value = u64::from_le_bytes(selection[..8].try_into().expect("eight bytes"));
        out.push((site, value));
    }
    Some(out)
}

/// A registered site with its actor's latest incarnation (`None` until the
/// actor launches) and the decisions the site made in that incarnation.
/// [`Chooser::launch`] sets both for each of the actor's sites, and a
/// decision is refused unless it names that incarnation, so one counter per
/// site holds every occurrence a decision can take.
#[derive(Clone, Copy, Debug)]
struct Registered {
    /// The site's [`Site::key`].
    key: u64,
    site: Site,
    incarnation: Option<u32>,
    occurrences: u32,
}

/// The capacity a recording chooser's tape starts with: 32 records, room
/// for 16 bounded decisions of two records each before the tape reallocates.
const TAPE_START: usize = 32 * RECORD_LEN;

/// Makes and records every decision of one run.
#[derive(Debug)]
pub(crate) struct Chooser {
    /// Every registered site once, in order of first registration, with its
    /// incarnation and occurrence count.
    sites: Vec<Registered>,
    /// Each registered site's position in `sites` plus one, by key, with
    /// zero marking an empty entry: an open-addressed table of a power-of-two
    /// length at least twice the site count, so at most half full, probed
    /// linearly with wraparound from a key's [`slot`].
    index: Vec<usize>,
    /// `64 - log2(index.len())`, the shift that makes [`slot`] land inside
    /// `index`.
    shift: u32,
    /// Each actor's latest incarnation.
    incarnations: BTreeMap<u16, u32>,
    decisions: u64,
    /// The index the next `index` decision selects instead of deriving one.
    forced: Option<usize>,
    /// What a recovery record admits; `None` under a live profile.
    admission: Option<Admission>,
    mode: Mode,
}

impl Chooser {
    /// A chooser that derives decisions from `root` at the registered
    /// `sites` and records them.
    pub(crate) fn record(root: u64, sites: &[Site]) -> Self {
        Self::new(
            sites,
            Mode::Record {
                source: Source::Root(root),
                tape: Vec::with_capacity(TAPE_START),
            },
        )
    }

    /// A chooser that reads every value from `input` in decision order, as
    /// [`Source::Feed`] lays it out, and records it; a decision past the
    /// input's end is refused as [`ChoiceError::Short`] before its effect,
    /// and input left after the last decision is ignored.
    pub(crate) fn fed(sites: &[Site], input: Vec<u8>) -> Self {
        Self::new(
            sites,
            Mode::Record {
                source: Source::Feed { input, at: 0 },
                tape: Vec::with_capacity(TAPE_START),
            },
        )
    }

    /// A chooser that replays the decisions `tape` recorded, reading every
    /// value from the tape.
    pub(crate) fn replay(sites: &[Site], tape: Vec<u8>) -> Self {
        Self::new(sites, Mode::Replay { tape, at: 0 })
    }

    /// A chooser in `mode` with every distinct site of `sites` registered
    /// and no actor launched.
    fn new(sites: &[Site], mode: Mode) -> Self {
        // Twice the site count, rounded up to a power of two, keeps `index`
        // at most half full; at least two entries keep the shift below 64.
        let len = (2 * sites.len()).next_power_of_two().max(2);
        let mut chooser = Self {
            sites: Vec::with_capacity(sites.len()),
            index: vec![0; len],
            shift: 64 - len.trailing_zeros(),
            incarnations: BTreeMap::new(),
            decisions: 0,
            forced: None,
            admission: None,
            mode,
        };
        for &site in sites {
            // A repeated site probes to its first registration and registers
            // once.
            if let Err(empty) = chooser.probe(site.key()) {
                chooser.sites.push(Registered {
                    key: site.key(),
                    site,
                    incarnation: None,
                    occurrences: 0,
                });
                chooser.index[empty] = chooser.sites.len();
            }
        }
        chooser
    }

    /// The chooser under `admission`, a recovery record's, before its first
    /// decision: it decides in the persistence domain and draws crash
    /// candidates of the admitted cut table.
    pub(crate) fn admitting(mut self, admission: Admission) -> Self {
        assert_eq!(self.decisions, 0, "admission precedes every decision");
        self.admission = Some(admission);
        self
    }

    /// The admission the chooser runs under, which [`EventKind::admit`]
    /// takes; `None` under a live profile.
    pub(crate) fn admission(&self) -> Option<&Admission> {
        self.admission.as_ref()
    }

    /// Starts `actor`'s next incarnation, the first being 0, and returns
    /// it; each of `actor`'s registered sites restarts at occurrence 0 in
    /// it, and decisions for its earlier incarnations are refused.
    pub(crate) fn launch(&mut self, actor: u16) -> u32 {
        let next = self
            .incarnations
            .get(&actor)
            .map_or(0, |incarnation| incarnation + 1);
        self.incarnations.insert(actor, next);
        for registered in &mut self.sites {
            if registered.site.actor == actor {
                registered.incarnation = Some(next);
                registered.occurrences = 0;
            }
        }
        next
    }

    #[cfg(test)]
    pub(crate) fn incarnation(&self, actor: u16) -> Option<u32> {
        self.incarnations.get(&actor).copied()
    }

    /// Draws every later decision from `root` and records it after the
    /// decisions [`recorded`](Self::recorded) holds, the read part of a
    /// replayed tape included.
    /// Incarnations and occurrence counters carry on, so a later decision
    /// keeps the identity it would have had and only its value changes. An
    /// index forced before the divergence is dropped.
    pub(crate) fn diverge(&mut self, root: u64) {
        self.forced = None;
        let tape = self.recorded().to_vec();
        self.mode = Mode::Record {
            source: Source::Root(root),
            tape,
        };
    }

    /// Makes the next [`index`](Self::index) decision a recording chooser
    /// makes select `index`, recorded as a derived one would be, so a
    /// replay of the tape reproduces it; a replaying chooser reads its
    /// tape. A forced index outside that decision's candidates is refused
    /// as [`ChoiceError::Index`] before any effect.
    pub(crate) fn force(&mut self, index: usize) {
        self.forced = Some(index);
    }

    /// Decisions made so far, byte fills included.
    pub(crate) fn decisions(&self) -> u64 {
        self.decisions
    }

    #[cfg(test)]
    pub(crate) fn displaced(&self) -> usize {
        self.index
            .iter()
            .enumerate()
            .filter(|&(at, &entry)| {
                entry
                    .checked_sub(1)
                    .is_some_and(|position| slot(self.sites[position].key, self.shift) != at)
            })
            .count()
    }

    /// Drops a recording chooser's tape so far: its hook has streamed it.
    /// Decisions keep deriving from the root and each site's occurrence, so
    /// the run's values are unchanged; [`finish`](Self::finish) returns only
    /// what was recorded since. A replaying chooser keeps its tape. Returns
    /// whether the tape was dropped.
    pub(crate) fn release(&mut self) -> bool {
        match &mut self.mode {
            Mode::Record { tape, .. } => {
                tape.clear();
                true
            }
            Mode::Replay { .. } => false,
        }
    }

    /// Sets `site`'s occurrence counter in its current incarnation to
    /// `occurrence`, as a boundary control that reaches the counter's end
    /// without running every decision before it; a site that is not
    /// registered is unchanged.
    #[cfg(test)]
    pub(crate) fn skip_to(&mut self, site: Site, occurrence: u32) {
        if let Ok(position) = self.probe(site.key()) {
            self.sites[position].occurrences = occurrence;
        }
    }

    /// The tape's records so far: every record a recording chooser wrote
    /// since its last [`release`](Self::release), its whole tape when it
    /// released none, or every record a replaying chooser replayed.
    pub(crate) fn recorded(&self) -> &[u8] {
        match &self.mode {
            Mode::Record { tape, .. } => tape,
            Mode::Replay { tape, at } => &tape[..*at],
        }
    }

    /// An index into `candidates`, which must follow their total order.
    pub(crate) fn index(
        &mut self,
        site: Site,
        incarnation: u32,
        candidates: &[Candidate],
    ) -> Result<usize, ChoiceError> {
        if candidates.is_empty() {
            return Err(ChoiceError::HarnessDefect(Defect::Empty));
        }
        if candidates.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(ChoiceError::HarnessDefect(Defect::Unordered));
        }
        if let Some(admission) = &self.admission {
            let crash = [Domain::Persistence as u8, EventKind::Crash as u8];
            let drifted = candidates
                .iter()
                .filter(|candidate| candidate.0[..2] == crash)
                .any(|candidate| admission.cut(candidate).is_none());
            if drifted {
                return Err(ChoiceError::HarnessDefect(Defect::Table));
            }
        }
        let count = size(candidates.len())?;
        let (identity, position) = self.identity(site, incarnation)?;
        let len = u64::from(count);
        let index = match &mut self.mode {
            Mode::Record { source, tape } => {
                let index = match self.forced.take() {
                    Some(forced) if (forced as u64) < len => forced as u64,
                    Some(forced) => {
                        return Err(ChoiceError::Index {
                            index: forced as u64,
                            len,
                        });
                    }
                    None => source.below(identity, len)?,
                };
                push(tape, identity, Kind::Index, count);
                for candidate in candidates {
                    append(tape, Tag::Candidate)[..CANDIDATE_LEN].copy_from_slice(&candidate.0);
                }
                selection(tape, index, len);
                index
            }
            Mode::Replay { tape, at } => {
                replay(tape, at, identity, (Kind::Index, count), |reader| {
                    for candidate in candidates {
                        let payload = reader.next(Tag::Candidate, CANDIDATE_LEN)?;
                        if payload[..CANDIDATE_LEN] != candidate.0 {
                            return Err(ChoiceError::Candidates);
                        }
                    }
                    reader.selection(len)
                })?
            }
        };
        self.commit(position);
        Ok(index as usize)
    }

    /// A value below `bound`.
    pub(crate) fn bounded(
        &mut self,
        site: Site,
        incarnation: u32,
        bound: u64,
    ) -> Result<u64, ChoiceError> {
        if bound == 0 {
            return Err(ChoiceError::HarnessDefect(Defect::Empty));
        }
        let (identity, position) = self.identity(site, incarnation)?;
        let value = match &mut self.mode {
            Mode::Record { source, tape } => {
                let value = source.below(identity, bound)?;
                push(tape, identity, Kind::Bounded, 0);
                selection(tape, value, bound);
                value
            }
            Mode::Replay { tape, at } => {
                replay(tape, at, identity, (Kind::Bounded, 0), |reader| {
                    reader.selection(bound)
                })?
            }
        };
        self.commit(position);
        Ok(value)
    }

    /// Fills `out` as one decision: the bytes come from the decision's
    /// stream and are recorded as entropy records that replay verbatim.
    pub(crate) fn bytes(
        &mut self,
        site: Site,
        incarnation: u32,
        out: &mut [u8],
    ) -> Result<(), ChoiceError> {
        let len = size(out.len())?;
        let (identity, position) = self.identity(site, incarnation)?;
        match &mut self.mode {
            Mode::Record { source, tape } => {
                source.fill(identity, out)?;
                push(tape, identity, Kind::Bytes, len);
                for piece in out.chunks(ENTROPY_PER_RECORD) {
                    let payload = append(tape, Tag::Entropy);
                    payload[0] = piece.len() as u8;
                    payload[1..1 + piece.len()].copy_from_slice(piece);
                }
            }
            Mode::Replay { tape, at } => {
                let pieces = replay(tape, at, identity, (Kind::Bytes, len), |reader| {
                    let start = reader.at;
                    for piece in out.chunks(ENTROPY_PER_RECORD) {
                        let payload = reader.next(Tag::Entropy, 1 + piece.len())?;
                        if usize::from(payload[0]) != piece.len() {
                            return Err(ChoiceError::Identity);
                        }
                    }
                    Ok(start)
                })?;
                for (record, piece) in out.chunks_mut(ENTROPY_PER_RECORD).enumerate() {
                    let start = pieces + record * RECORD_LEN + 2;
                    piece.copy_from_slice(&tape[start..start + piece.len()]);
                }
            }
        }
        self.commit(position);
        Ok(())
    }

    /// The tape: a recording chooser's records since its last
    /// [`release`](Self::release), every decision when it released none,
    /// and a replaying chooser's whole tape; replay fails on input left
    /// after the last decision.
    pub(crate) fn finish(self) -> Result<Vec<u8>, ChoiceError> {
        match self.mode {
            Mode::Record { tape, .. } => Ok(tape),
            Mode::Replay { tape, at } if at < tape.len() => Err(ChoiceError::Trailing {
                bytes: tape.len() - at,
            }),
            Mode::Replay { tape, .. } => Ok(tape),
        }
    }

    /// The identity of `site`'s next decision in `incarnation` and the
    /// site's position in `sites`.
    ///
    /// # Errors
    ///
    /// A [`ChoiceError::HarnessDefect`] naming:
    /// - [`Defect::ReservedDomain`] if `site` is in the persistence domain
    ///   and the chooser runs under no admission.
    /// - [`Defect::Unregistered`] if `site` is outside the registry.
    /// - [`Defect::Incarnation`] unless `incarnation` is the latest one
    ///   [`launch`](Self::launch) returned for `site`'s actor.
    /// - [`Defect::Occurrences`] if `site`'s occurrence counter in the
    ///   current incarnation equals `u32::MAX`.
    #[inline(always)]
    fn identity(&self, site: Site, incarnation: u32) -> Result<(Identity, usize), ChoiceError> {
        if site.domain.reserved() && self.admission.is_none() {
            return Err(ChoiceError::HarnessDefect(Defect::ReservedDomain));
        }
        let Ok(position) = self.probe(site.key()) else {
            return Err(ChoiceError::HarnessDefect(Defect::Unregistered(site)));
        };
        let registered = self.sites[position];
        if registered.incarnation != Some(incarnation) {
            return Err(ChoiceError::HarnessDefect(Defect::Incarnation {
                actor: site.actor,
                incarnation,
            }));
        }
        if registered.occurrences == u32::MAX {
            return Err(ChoiceError::HarnessDefect(Defect::Occurrences(site)));
        }
        let identity = Identity {
            site,
            incarnation,
            occurrence: registered.occurrences,
        };
        Ok((identity, position))
    }

    /// Probes `index` for `key`: `Ok` with the registered site's position in
    /// `sites`, or `Err` with the empty entry where the key would go. The
    /// table is at most half full, so every probe reaches one or the other.
    #[inline(always)]
    fn probe(&self, key: u64) -> Result<usize, usize> {
        let mask = self.index.len() - 1;
        let mut at = slot(key, self.shift);
        loop {
            let Some(position) = self.index[at].checked_sub(1) else {
                return Err(at);
            };
            if self.sites[position].key == key {
                return Ok(position);
            }
            at = (at + 1) & mask;
        }
    }

    /// Steps the site at `position` in `sites` and counts the decision;
    /// replayed decisions step their sites as recorded ones do.
    fn commit(&mut self, position: usize) {
        self.sites[position].occurrences += 1;
        self.decisions += 1;
    }
}

/// The entry a probe for `key` starts at in a table of `1 << (64 - shift)`
/// entries: the top `64 - shift` bits of the 64-bit wrapping product of
/// `key` and `0x9e37_79b9_7f4a_7c15`, 2^64 divided by the golden ratio and
/// rounded down (Knuth's Fibonacci hashing), which spreads keys that differ
/// only in their low bits, such as one actor's adjacent site numbers,
/// across the table.
fn slot(key: u64, shift: u32) -> usize {
    (key.wrapping_mul(0x9e37_79b9_7f4a_7c15) >> shift) as usize
}

/// Bytes of an identity record's payload: the identity, the kind and the
/// size.
const IDENTITY_PAYLOAD: usize = IDENTITY_LEN + 5;

/// An identity record's payload: the canonical identity, the decision's
/// kind and its size, the candidate count of an index or the length of a
/// byte fill; zero for a bounded value, whose bound the selection record
/// carries.
fn identity_payload(identity: Identity, kind: Kind, size: u32) -> [u8; IDENTITY_PAYLOAD] {
    let mut payload = [0; IDENTITY_PAYLOAD];
    payload[..IDENTITY_LEN].copy_from_slice(&identity.canonical());
    payload[IDENTITY_LEN] = kind as u8;
    payload[IDENTITY_LEN + 1..].copy_from_slice(&size.to_le_bytes());
    payload
}

/// Appends the identity record of `identity`'s decision of `kind` and
/// `size` to `tape`.
fn push(tape: &mut Vec<u8>, identity: Identity, kind: Kind, size: u32) {
    append(tape, Tag::Identity)[..IDENTITY_PAYLOAD]
        .copy_from_slice(&identity_payload(identity, kind, size));
}

/// A tape record's contribution to a decision count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Opens {
    Decision,
    Reserved,
    Nothing,
}

pub(crate) fn opens(record: &Record) -> Opens {
    if record[0] != Tag::Identity as u8 {
        return Opens::Nothing;
    }
    if Domain::from_code(record[1 + DOMAIN_AT]).is_some_and(Domain::reserved) {
        Opens::Reserved
    } else {
        Opens::Decision
    }
}

/// Appends a selection record to `tape`: the selected value and the bound
/// it lies below, the candidate count of an index.
fn selection(tape: &mut Vec<u8>, value: u64, bound: u64) {
    let payload = append(tape, Tag::Selection);
    payload[..8].copy_from_slice(&value.to_le_bytes());
    payload[8..16].copy_from_slice(&bound.to_le_bytes());
}

/// `len` as a record's 32-bit size.
fn size(len: usize) -> Result<u32, ChoiceError> {
    u32::try_from(len).map_err(|_| ChoiceError::HarnessDefect(Defect::Oversized))
}

/// Replays one decision from `tape` at `at`: checks its identity record
/// against `identity`, `kind` and the decision's size, runs `body` over the
/// rest of its records, and moves `at` past them only when all validated.
fn replay<T>(
    tape: &[u8],
    at: &mut usize,
    identity: Identity,
    (kind, size): (Kind, u32),
    body: impl FnOnce(&mut Reader<'_>) -> Result<T, ChoiceError>,
) -> Result<T, ChoiceError> {
    let mut reader = Reader { tape, at: *at };
    let payload = reader.next(Tag::Identity, IDENTITY_PAYLOAD)?;
    let expected = identity_payload(identity, kind, size);
    if payload[..=IDENTITY_LEN] != expected[..=IDENTITY_LEN] {
        return Err(ChoiceError::Identity);
    }
    if payload[IDENTITY_LEN + 1..IDENTITY_PAYLOAD] != expected[IDENTITY_LEN + 1..] {
        return Err(match kind {
            Kind::Index => ChoiceError::Candidates,
            _ => ChoiceError::Identity,
        });
    }
    let value = body(&mut reader)?;
    *at = reader.at;
    Ok(value)
}

/// Reads records from a replayed tape without moving the chooser's offset
/// until the whole decision validated.
struct Reader<'t> {
    tape: &'t [u8],
    at: usize,
}

impl Reader<'_> {
    /// The payload of the next record, which must carry `tag` and a payload
    /// of `width` bytes followed by zeros, as the recorder writes it.
    fn next(&mut self, tag: Tag, width: usize) -> Result<Payload, ChoiceError> {
        let record: Record = self
            .tape
            .get(self.at..self.at + RECORD_LEN)
            .ok_or(ChoiceError::Short)?
            .try_into()
            .expect("a record's bytes");
        if record[0] != tag as u8 {
            return Err(match tag {
                Tag::Candidate => ChoiceError::Candidates,
                _ => ChoiceError::Identity,
            });
        }
        if record[1 + width..].iter().any(|&byte| byte != 0) {
            return Err(ChoiceError::Identity);
        }
        self.at += RECORD_LEN;
        Ok(record[1..].try_into().expect("a payload's bytes"))
    }

    /// The selection record's value, recorded under `bound`, which it must
    /// lie below.
    fn selection(&mut self, bound: u64) -> Result<u64, ChoiceError> {
        let payload = self.next(Tag::Selection, 16)?;
        let word =
            |at: usize| u64::from_le_bytes(payload[at..at + 8].try_into().expect("eight bytes"));
        let (index, recorded) = (word(0), word(8));
        if recorded != bound {
            return Err(ChoiceError::Identity);
        }
        if index >= bound {
            return Err(ChoiceError::Index { index, len: bound });
        }
        Ok(index)
    }
}
