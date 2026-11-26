//! Ordered decoded-message rules for the simulated link. A rule pairs a
//! selector with an effect; a chain runs every rule in order over one
//! pending decision per message, later rules overriding what earlier ones
//! set, and the link applies the decision only after the last rule. Taps
//! capture the pending decision at chosen positions in the order messages
//! arrive; the tap after the last rule sees the committed decision.
//!
//! Selectors read the end a message travels toward and its decoded header:
//! kind, request, PUT serial or GET allocation, session epoch, fragment
//! range and acknowledgement holes. A packed datagram, 2 to
//! [`MAX_PACKED_GETS`] whole frames whose kind bytes say GET, is read by its
//! first GET frame ([`frame_of`]): selectors, captures, the link's resend key
//! and corruption see that frame, so a rule that selects by request misses a
//! GET packed behind another. Containment judges that frame toward the owner,
//! which handles a packed datagram frame by frame, and the whole datagram
//! toward a client, which parses each datagram as one frame. Every field a rule sets, a later rule
//! can set back. A rule's window keeps per-rule state, skipping its first matches
//! and acting on a bounded number after them. Chains, taps and captures are
//! bounded by a manifest: a chain over its bound is refused, and captures
//! past their bound stop with the overflow recorded, keeping every capture
//! taken.
//!
//! Corruption classes each name the receiver layer that rejects them:
//! header corruption the frame codec, tag corruption authentication, a GET
//! body the body crc, a PUT body authentication (its tag covers the body),
//! and truncation the datagram layer. Each class acts on a packed datagram's
//! first frame as on a lone GET datagram of that frame's bytes. The unsupported class names no layer:
//! it is a containment control, excluded from witnesses.

use crate::storage::Crc32c;

use super::auth::KeyRing;
use super::datagram::{HEADER_LEN, MAX_PACKED_GETS, PeerId};
use super::frame::{AUTHENTICATED_LEN, Direction, FrameError, Header, KIND_AT, Kind, parse};

/// The bytes the rules read as `bytes`'s frame: the first frame of a packed datagram, 2 to [`MAX_PACKED_GETS`] whole
/// 192-byte frames whose kind bytes say GET, and otherwise every byte.
pub(crate) fn frame_of(bytes: &[u8]) -> &[u8] {
    let (frames, rest) = bytes.as_chunks::<HEADER_LEN>();
    let packed = rest.is_empty()
        && (2..=MAX_PACKED_GETS).contains(&frames.len())
        && frames.iter().all(|frame| frame[KIND_AT] == Kind::Get as u8);
    if packed { &bytes[..HEADER_LEN] } else { bytes }
}

/// Every frame of `bytes`: each 192-byte frame of a packed datagram, as [`frame_of`] recognizes one, and otherwise
/// every byte as one frame. Test readers that count what a client sent read a datagram through it.
pub(crate) fn frames_of(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    // `frame_of` gives 192 bytes for a packed datagram and every byte otherwise; `chunks` needs a nonzero width, and
    // an empty datagram yields no frame at any width.
    bytes.chunks(frame_of(bytes).len().max(1))
}

/// One message as the rules see it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Message {
    pub(crate) link: u16,
    /// The end the message travels toward.
    pub(crate) toward: usize,
    /// The message's position among every message the link carried.
    pub(crate) ordinal: u64,
    /// The decoded header, when the frame the rules read ([`frame_of`]) parses.
    pub(crate) header: Option<Header>,
}

impl Message {
    pub(crate) fn decode(link: u16, toward: usize, ordinal: u64, bytes: &[u8]) -> Self {
        let header = parse(Crc32c::detect(), frame_of(bytes), false)
            .ok()
            .map(|frame| frame.header());
        Self {
            link,
            toward,
            ordinal,
            header,
        }
    }

    fn kind(&self) -> Option<Kind> {
        self.header.map(|header| header.kind)
    }
}

/// Which messages a rule selects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Selector {
    Any,
    Kind(Kind),
    /// Messages toward this end.
    Toward(usize),
    Request(u64),
    /// A PUT attempt by its fill serial, or a GET by its allocation.
    Serial(u64),
    /// A session by its epoch.
    Session(u64),
    /// Fragment indexes in `first..=last`, or an ACK's receipt base there.
    Fragments {
        first: u32,
        last: u32,
    },
    /// ACKs whose receipt mask names a fragment held past a hole.
    Holes,
    /// Every listed selector.
    All(Vec<Selector>),
}

impl Selector {
    fn matches(&self, message: &Message) -> bool {
        let header = message.header.as_ref();
        match self {
            Self::Any => true,
            Self::Kind(kind) => message.kind() == Some(*kind),
            Self::Toward(side) => message.toward == *side,
            Self::Request(request) => header.is_some_and(|h| h.request == *request),
            Self::Serial(serial) => header.is_some_and(|h| h.allocation == *serial),
            Self::Session(epoch) => header.is_some_and(|h| h.epoch == *epoch),
            Self::Fragments { first, last } => {
                header.is_some_and(|h| (*first..=*last).contains(&h.index))
            }
            Self::Holes => {
                header.is_some_and(|h| matches!(h.kind, Kind::Ack | Kind::PutAck) && h.offset != 0)
            }
            Self::All(selectors) => selectors.iter().all(|selector| selector.matches(message)),
        }
    }
}

/// How a rule changes the pending decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Effect {
    /// Clears any drop an earlier rule or fault set.
    Deliver,
    Drop,
    /// Drops as a partition of the selected traffic.
    Isolate,
    /// Delivers this many link turns late.
    Delay(u64),
    /// Delivers ahead of every message queued before it.
    Reorder,
    /// Delivers a second copy.
    Duplicate,
    /// Delivers one copy, clearing any duplication.
    NoDuplicate,
    /// Delivers in queue order, clearing any reordering.
    InOrder,
    /// Delivers without delay.
    Prompt,
    Corrupt(Corruption),
    /// Delivers the bytes as sent, clearing any corruption.
    Clean,
    Truncate,
    /// Delivers whole, clearing any truncation.
    Whole,
}

/// Why a decision drops its message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Dropped {
    /// The direction's loss fault.
    Fault,
    /// The rule at this position.
    Rule(usize),
    /// The isolating rule at this position.
    Isolated(usize),
    /// A datagram of the burst an earlier loss drew.
    Burst,
    /// The direction's resend loss.
    Resend,
}

/// One message's pending decision. It arrives with the duplicate draw and
/// any loss, burst or resend drop set. `delay`, `reorder` and `truncate`
/// left `None` fall to the link's later draws, and the link corrupts only
/// when a rule sets `corrupt`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Decision {
    pub(crate) drop: Option<Dropped>,
    pub(crate) duplicate: bool,
    pub(crate) delay: Option<u64>,
    pub(crate) reorder: Option<bool>,
    pub(crate) truncate: Option<bool>,
    pub(crate) corrupt: Option<Corruption>,
}

impl Effect {
    fn apply(self, decision: &mut Decision, at: usize) {
        match self {
            Self::Deliver => decision.drop = None,
            Self::Drop => decision.drop = Some(Dropped::Rule(at)),
            Self::Isolate => decision.drop = Some(Dropped::Isolated(at)),
            Self::Delay(turns) => decision.delay = Some(turns),
            Self::Reorder => decision.reorder = Some(true),
            Self::Duplicate => decision.duplicate = true,
            Self::NoDuplicate => decision.duplicate = false,
            Self::InOrder => decision.reorder = Some(false),
            Self::Prompt => decision.delay = Some(0),
            Self::Corrupt(class) => decision.corrupt = Some(class),
            Self::Clean => decision.corrupt = None,
            Self::Truncate => decision.truncate = Some(true),
            Self::Whole => decision.truncate = Some(false),
        }
    }
}

/// A selector, a window over its matches and an effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Rule {
    selector: Selector,
    skip: u32,
    take: u32,
    effect: Effect,
    /// Messages the selector matched so far.
    matched: u32,
}

impl Rule {
    /// A rule acting on every message `selector` matches.
    pub(crate) fn new(selector: Selector, effect: Effect) -> Self {
        Self {
            selector,
            skip: 0,
            take: u32::MAX,
            effect,
            matched: 0,
        }
    }

    /// The rule acting only on its matches after the first `skip`, for at
    /// most `take` of them.
    pub(crate) fn window(self, skip: u32, take: u32) -> Self {
        Self { skip, take, ..self }
    }

    /// Whether the rule acts on `message`, counting the match.
    fn acts(&mut self, message: &Message) -> bool {
        if !self.selector.matches(message) {
            return false;
        }
        let seen = self.matched;
        self.matched = self.matched.saturating_add(1);
        seen >= self.skip && seen - self.skip < self.take
    }
}

/// The bounds a run's link fixtures stay within.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Manifest {
    pub(crate) rules: usize,
    pub(crate) taps: usize,
    pub(crate) captures: usize,
    pub(crate) records: usize,
}

pub(crate) const MANIFEST: Manifest = Manifest {
    rules: 32,
    taps: 8,
    captures: 4_096,
    records: 65_536,
};

/// A manifest or link-limit bound an operation would pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Bound {
    Rules,
    Taps,
    Captures,
    Records,
    /// Link entries per direction.
    Entries,
    /// Copied bytes in flight per direction.
    CopyBytes,
    /// Retained transmit references per link.
    TxSlots,
    /// Damaged copies the link keeps for the containment check.
    Damaged,
}

/// One tap's view of one message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Capture {
    /// Rules that ran before the view: the last tap, at the chain's length,
    /// sees the committed decision.
    pub(crate) tap: usize,
    pub(crate) link: u16,
    pub(crate) toward: usize,
    pub(crate) ordinal: u64,
    pub(crate) kind: Option<Kind>,
    pub(crate) index: Option<u32>,
    /// The header's grant: a PUT READY's or ACK's cumulative grant.
    pub(crate) grant: Option<u32>,
    pub(crate) decision: Decision,
}

/// An ordered rule chain with its taps and captures.
#[derive(Debug, Clone, Default)]
pub(crate) struct Chain {
    rules: Vec<Rule>,
    taps: Vec<usize>,
    captures: Vec<Capture>,
    limit: usize,
    overflow: bool,
}

impl Chain {
    /// A chain of `rules` tapped after each count of rules in `taps`.
    ///
    /// # Errors
    ///
    /// The manifest bound `rules` or `taps` passes, or a tap past the last
    /// rule.
    pub(crate) fn new(
        rules: Vec<Rule>,
        taps: &[usize],
        manifest: &Manifest,
    ) -> Result<Self, Bound> {
        if rules.len() > manifest.rules {
            return Err(Bound::Rules);
        }
        if taps.len() > manifest.taps || taps.iter().any(|&tap| tap > rules.len()) {
            return Err(Bound::Taps);
        }
        Ok(Self {
            rules,
            taps: taps.to_vec(),
            captures: Vec::new(),
            limit: manifest.captures,
            overflow: false,
        })
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.rules.is_empty() && self.taps.is_empty()
    }

    /// Runs every rule in order over `base`, then returns the committed
    /// decision.
    pub(crate) fn decide(&mut self, message: &Message, base: Decision) -> Decision {
        let mut pending = base;
        self.tap(0, message, pending);
        for at in 0..self.rules.len() {
            if self.rules[at].acts(message) {
                self.rules[at].effect.apply(&mut pending, at);
            }
            self.tap(at + 1, message, pending);
        }
        pending
    }

    fn tap(&mut self, position: usize, message: &Message, decision: Decision) {
        if !self.taps.contains(&position) {
            return;
        }
        if self.captures.len() == self.limit {
            self.overflow = true;
            return;
        }
        self.captures.push(Capture {
            tap: position,
            link: message.link,
            toward: message.toward,
            ordinal: message.ordinal,
            kind: message.kind(),
            index: message.header.map(|header| header.index),
            grant: message.header.map(|header| header.grant),
            decision,
        });
    }

    /// Every capture, in the order the taps saw them.
    pub(crate) fn captures(&self) -> &[Capture] {
        &self.captures
    }

    /// The bound a refused capture would have passed, if any.
    pub(crate) fn overflow(&self) -> Option<Bound> {
        self.overflow.then_some(Bound::Captures)
    }
}

/// A corruption the link applies to the delivered copy alone; the sender's
/// memory keeps its bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Corruption {
    /// A byte the header crc covers.
    Header,
    /// A byte of the tag.
    Tag,
    /// A body byte of a GET DATA frame, which the tag covers through the frame's body digest.
    GetBody,
    /// A body byte of a PUT kind, which the tag covers.
    PutBody,
    /// The last byte of the frame the rules read, which the harness attributes to no layer.
    Unsupported,
}

/// A receiver layer that rejects a datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Layer {
    /// The receive meta's truncation flag.
    Datagram,
    /// The frame codec, through the header crc.
    Frame,
    Auth,
    /// The body crc.
    Body,
}

impl Corruption {
    /// The layer that rejects this class, or `None` for the containment
    /// control.
    pub(crate) fn layer(self) -> Option<Layer> {
        match self {
            Self::Header => Some(Layer::Frame),
            Self::Tag | Self::GetBody | Self::PutBody => Some(Layer::Auth),
            Self::Unsupported => None,
        }
    }

    /// Flips this class's byte of `bytes` and returns whether it lay inside
    /// `bytes`.
    pub(crate) fn apply(self, bytes: &mut [u8]) -> bool {
        let at = match self {
            Self::Header => AUTHENTICATED_LEN - 1,
            Self::Tag => AUTHENTICATED_LEN,
            Self::GetBody | Self::PutBody => HEADER_LEN,
            Self::Unsupported => bytes.len().saturating_sub(1),
        };
        let Some(byte) = bytes.get_mut(at) else {
            return false;
        };
        *byte ^= 0x5a;
        true
    }
}

/// What a receiver needs to judge a copy delivered toward an end: the key
/// ring, the peer the frame names, the owner endpoint and the frame's
/// direction.
pub(crate) type Receiver<'k> = (&'k KeyRing, PeerId, u32, Direction);

/// The first receiver layer that rejects `bytes` arriving at `receiver`,
/// checked in the receivers' order, or `None` when every layer accepts them.
/// Toward the owner the layers judge the frame the rules read, a packed
/// datagram's first frame; toward a client they judge the whole datagram.
fn rejecting_layer(
    bytes: &[u8],
    truncated: bool,
    (ring, peer, endpoint, direction): Receiver<'_>,
) -> Option<Layer> {
    let crc = Crc32c::detect();
    let judged = match direction {
        Direction::ClientToOwner => frame_of(bytes),
        Direction::OwnerToClient => bytes,
    };
    let frame = match parse(crc, judged, truncated) {
        Ok(frame) => frame,
        Err(FrameError::Truncated) => return Some(Layer::Datagram),
        Err(_) => return Some(Layer::Frame),
    };
    if ring
        .authenticate(&frame, peer, endpoint, direction)
        .is_err()
    {
        return Some(Layer::Auth);
    }
    if frame.check_body(crc).is_err() {
        return Some(Layer::Body);
    }
    None
}

/// Containment over `damaged`: every copy whose class names a layer, and
/// every truncated copy, is rejected by that layer. Returns the count
/// checked; containment controls are skipped and left uncounted. A packed
/// copy toward the owner counts once, for its first frame.
///
/// # Errors
///
/// The first copy another layer rejected or every layer accepted: its
/// class and the layer that rejected it, if any.
pub(crate) fn contain<'k>(
    damaged: &[super::link::Damaged],
    receiver: impl Fn(usize) -> Receiver<'k>,
) -> Result<usize, (Option<Corruption>, Option<Layer>)> {
    let mut checked = 0;
    for copy in damaged {
        let named = if copy.truncated {
            Some(Layer::Datagram)
        } else {
            copy.corruption.and_then(Corruption::layer)
        };
        let Some(named) = named else {
            continue;
        };
        let found = rejecting_layer(&copy.bytes, copy.truncated, receiver(copy.toward));
        if found != Some(named) {
            return Err((copy.corruption, found));
        }
        checked += 1;
    }
    Ok(checked)
}
