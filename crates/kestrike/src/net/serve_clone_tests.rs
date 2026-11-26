//! Clone fidelity of the GET transfer core, the ground a finite search over
//! its states stands on. A copy of a core and its namespace keeps every
//! future-relevant field, so the copy and its original evolve to equal
//! canonical forms under identical inputs, and each copy owns its device
//! holds. [`Seen`] prunes search states by exact canonical equality and
//! re-expands a state reached with a greater allowance.

use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasher, RandomState};

use crate::records::Records;
use crate::storage::seeded::SplitMix64;
use crate::storage::{EngineBudget, SourceRange};

use super::datagram::PeerId;
use super::frame::{Header, Kind, Status};
use super::pace::Shaper;
use super::requests::{RequestId, RequestTable};
use super::serve::{Chunk, GetOutcome, Manifest, ReadEnd, Retained, ServeConfig};
use super::serve_tests::{CONFIG, Core, Tx, ack, get, session, shaped_core};
use super::served::{Request, Requests};
use super::session::Admitted;

/// Peers, wire slots per peer and request-table slots of the searched core.
pub(super) const PEERS: u16 = 2;
pub(super) const WIRE_SLOTS: u16 = 2;
pub(super) const TABLE_SLOTS: u32 = 2;
pub(super) const LANES: usize = PEERS as usize * WIRE_SLOTS as usize;
/// The staged batch the core is built with.
pub(super) const BATCH: u32 = 8;
/// One fragment per chunk, two chunks per object.
pub(super) const CHUNK: u64 = 8192;
pub(super) const MANIFEST: Manifest = Manifest {
    allocation: 7,
    metadata_len: 0,
    body_len: 2 * CHUNK as u32,
};

/// A test chunk whose device hold lives in the chunk, so a copy of a core
/// copies the hold with it: a hold belongs to exactly one core. The third
/// field is the object offset the chunk is delivered for; its bytes equal
/// the content there unless a control changes them.
#[derive(Clone)]
pub(super) struct Owned(pub(super) Box<[u8]>, pub(super) Cell<bool>, pub(super) u64);

/// The chunk's hold and its bytes, the bytes as their object range when they
/// equal the object's content there, so equal chunks print equal and any
/// other bytes print in full.
impl std::fmt::Debug for Owned {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut chunk = f.debug_struct("Owned");
        let range = self.2..self.2 + self.0.len() as u64;
        if *self.0 == *content(range.clone()) {
            chunk.field("content", &range);
        } else {
            chunk.field("bytes", &self.0);
        }
        chunk.field("held", &self.1.get()).finish()
    }
}

/// The object's bytes over `range`: each 256-byte block XORs one
/// permutation with its block index, so no two blocks of an object match
/// and a fragment carrying another fragment's bytes differs.
pub(super) fn content(range: std::ops::Range<u64>) -> Vec<u8> {
    range
        .map(|at| ((at.wrapping_mul(7) + 3) ^ (at >> 8)) as u8)
        .collect()
}

impl AsRef<[u8]> for Owned {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Chunk for Owned {
    fn device_held(&self) -> bool {
        self.1.get()
    }

    fn crc(
        &self,
        crc: crate::storage::Crc32c,
        _runs: &mut crate::storage::ZeroRuns,
        _window_crcs: &[u32],
        range: std::ops::Range<usize>,
    ) -> u32 {
        crc.checksum(&self.0[range])
    }
}

impl Retained<'_> for Owned {
    fn source(&self, _range: std::ops::Range<usize>) -> Option<SourceRange<'_, 'static>> {
        None
    }
}

/// Holds of the chunks the core retains: setting one models the device
/// taking or returning that chunk's buffer.
pub(super) trait Hold {
    fn hold(&self) -> &Cell<bool>;
}

impl Hold for Owned {
    fn hold(&self) -> &Cell<bool> {
        &self.1
    }
}

impl Hold for Tx {
    fn hold(&self) -> &Cell<bool> {
        &self.1
    }
}

/// One wire identity's live GET as the driver tracks it.
#[derive(Clone, Copy, Debug)]
pub(super) struct Live {
    pub(super) id: RequestId,
    pub(super) request: Header,
    /// Chunks delivered.
    pub(super) delivered: u8,
    /// Whether the read holds a command for the next chunk.
    pub(super) commanded: bool,
    pub(super) read_ended: bool,
    /// One past the highest DATA fragment sent.
    pub(super) sent: u32,
    /// The receipt the client's last valid ACK reported: one past the
    /// highest fragment it acknowledged.
    pub(super) acked: u32,
    /// The client's cumulative grant: the GET's, raised by a valid ACK.
    pub(super) grant: u32,
}

/// The driver's view and observers: the clock, each lane's next generation
/// and live GET, the frames sent so far, the last poll's frames, and the
/// byte and device-hold facts the search monitors check.
#[derive(Clone, Debug, Default)]
pub(super) struct World {
    pub(super) now_us: u64,
    pub(super) generations: [u64; LANES],
    pub(super) live: [Option<Live>; LANES],
    pub(super) frames: u64,
    pub(super) last_poll: Vec<(PeerId, Kind, u64, u32)>,
    /// DATA frames whose offset or bytes differ from the object's content at
    /// their fragment.
    pub(super) wrong_bytes: u32,
    /// `skipped` counts DATA frames whose fragment index exceeds their
    /// request's first unsent index.
    pub(super) skipped: u32,
    /// Chunks of each lane's GET the device holds, as the device knows it.
    pub(super) holds: [u8; LANES],
    /// GETs released while the device still held one of their chunks.
    pub(super) released_held: u32,
    /// `vanished` counts GETs that left the core before they ended.
    pub(super) vanished: u32,
    /// The terminal of every live or released GET that reached one, ordered
    /// by `(peer, request)`.
    pub(super) settled: Vec<Settled>,
    /// Whether each lane's GET sent COMPLETE while the device held one of
    /// its chunks.
    pub(super) completed_held: [bool; LANES],
    /// Frames and releases that break each terminal rule.
    pub(super) broken: Broken,
    /// Which frames the sender takes.
    pub(super) sender: Sender,
    /// The core defect the driver plants, for the terminal controls.
    pub(super) plant: Plant,
}

/// Counts of frames and releases that break each terminal rule.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Broken {
    /// COMPLETE frames sent before the read ended and the client's ACK
    /// reported every fragment received.
    pub(super) early: u32,
    /// ERROR frames sent as the first terminal of a GET whose read ended
    /// and whose client reported every fragment received.
    pub(super) errored: u32,
    /// First terminal frames whose manifest or key differ from the GET's
    /// request and bound object.
    pub(super) mismatched: u32,
    /// Terminal frames sent for a GET the core holds unended.
    pub(super) unended: u32,
    /// Terminal frames of another logical result than their GET's
    /// terminal, or that exceed the replays the core queued.
    pub(super) repeated: u32,
    /// DATA frames sent after their GET's terminal.
    pub(super) data_after: u32,
    /// GETs released with no terminal.
    pub(super) unterminated: u32,
}

impl Broken {
    /// Whether any terminal rule broke.
    pub(super) fn any(self) -> bool {
        self != Self::default()
    }
}

/// A core defect the driver plants for a terminal control.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum Plant {
    #[default]
    None,
    /// The core stages COMPLETE ahead of every DATA frame.
    EarlyComplete,
    /// The core stages every terminal frame twice.
    DoubleTerminal,
    /// The core releases every ended GET at a drain, its held chunks
    /// included.
    HeldRelease,
    /// The core ends each GET at its COMPLETE, and the COMPLETE frame stays
    /// inside the core.
    SilentComplete,
    ErrorForComplete,
    /// The core's COMPLETE frames carry another allocation than the bound
    /// object's.
    WrongManifest,
    /// The core sends a replay whose manifest differs from the settled
    /// terminal's manifest.
    ConflictingReplay,
    /// The core answers an owed replay of a settled GET with a DATA frame
    /// in place of the replayed terminal.
    DataAfterTerminal,
    /// After every poll that leaves no frame the shaper refused, the next
    /// poll stages replies first, so replies that fill a batch keep a ready
    /// request from staging.
    RepliesFirst,
}

/// A terminal frame's logical result: its kind, an ERROR's status, a
/// COMPLETE's manifest, and the GET's key. The replay rule holds a terminal
/// answering an owed replay to the result the GET settled with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Logical {
    pub(super) kind: Kind,
    pub(super) status: u16,
    pub(super) allocation: u64,
    pub(super) metadata_len: u32,
    pub(super) body_len: u32,
    pub(super) key: [u8; 32],
}

impl Logical {
    fn of(header: &Header) -> Self {
        Self {
            kind: header.kind,
            status: header.status,
            allocation: header.allocation,
            metadata_len: header.metadata_len,
            body_len: header.body_len,
            key: header.key,
        }
    }

    /// The logical result a terminal of `kind` and `status` carries for the
    /// GET `request`: the bound object's manifest under COMPLETE, and the
    /// request's key.
    fn of_get(kind: Kind, status: u16, request: &Header) -> Self {
        let manifest = match kind {
            Kind::Complete => MANIFEST,
            _ => Manifest {
                allocation: 0,
                metadata_len: 0,
                body_len: 0,
            },
        };
        Self {
            kind,
            status,
            allocation: manifest.allocation,
            metadata_len: manifest.metadata_len,
            body_len: manifest.body_len,
            key: request.key,
        }
    }

    /// The result the terminal monitor records when a CANCEL ends the GET
    /// `request`.
    fn cancelled(request: &Header) -> Self {
        Self::of_get(Kind::Error, Status::Cancelled as u16, request)
    }
}

/// One GET's logical terminal. It outlives the GET's release because the
/// core can send queued replies after the release, and the terminal rules
/// check those replies against this record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Settled {
    pub(super) peer: PeerId,
    pub(super) request: u64,
    /// The first COMPLETE or ERROR frame sent for the GET, or, for a GET
    /// its client's CANCEL ended, the cancelled ERROR the core caches and
    /// replays to a duplicate.
    pub(super) terminal: Logical,
    /// Replays the core queued and kept for the GET after its terminal,
    /// each of which a further terminal frame answers.
    pub(super) owed: u8,
}

impl World {
    fn settled_at(&self, peer: PeerId, request: u64) -> Result<usize, usize> {
        self.settled
            .binary_search_by_key(&(peer, request), |settled| (settled.peer, settled.request))
    }

    pub(super) fn terminal(&self, lane: usize) -> Option<Kind> {
        let live = self.live[lane]?;
        let at = self.settled_at(peer(lane), live.request.request).ok()?;
        Some(self.settled[at].terminal.kind)
    }

    fn settle(&mut self, peer: PeerId, request: u64, terminal: Logical) {
        if let Err(at) = self.settled_at(peer, request) {
            let settled = Settled {
                peer,
                request,
                terminal,
                owed: 0,
            };
            self.settled.insert(at, settled);
        }
    }

    pub(super) fn owe(&mut self, peer: PeerId, request: u64, queued: u8) {
        if let Ok(at) = self.settled_at(peer, request) {
            let owed = &mut self.settled[at].owed;
            *owed = owed.saturating_add(queued);
        }
    }
}

/// `live` is `None` for frames from GETs released by the drain or refused
/// at admission with a queued ERROR. Its boolean is whether the core
/// considers the GET ended.
fn terminal(
    world: &mut World,
    (peer, request, terminal): (PeerId, u64, Logical),
    live: Option<(usize, Live, bool)>,
) {
    let complete = terminal.kind == Kind::Complete;
    let first = world.settled_at(peer, request).is_err();
    if let Some((lane, live, ended)) = live {
        let ready = live.read_ended && live.acked >= MANIFEST.count();
        world.broken.early += u32::from(complete && !ready);
        world.broken.errored += u32::from(!complete && ready && first);
        let expected = Logical::of_get(terminal.kind, terminal.status, &live.request);
        world.broken.mismatched += u32::from(first && terminal != expected);
        world.broken.unended += u32::from(!ended);
        world.completed_held[lane] |= complete && world.holds[lane] > 0;
    }
    match world.settled_at(peer, request) {
        Ok(at) => {
            let settled = &mut world.settled[at];
            let repeated = settled.terminal != terminal || settled.owed == 0;
            settled.owed = settled.owed.saturating_sub(1);
            world.broken.repeated += u32::from(repeated);
        }
        Err(_) if live.is_some() => world.settle(peer, request, terminal),
        Err(_) => {}
    }
}

/// The replays the core has counted and the replies a full reply ring
/// dropped. One input queues at most one reply, so the change of each
/// across an input tells whether the input's replay was queued and kept.
fn replays<C: Chunk>(core: &Core<C>) -> (u64, u64) {
    let report = core.report();
    (report.replays, report.dropped_replies)
}

/// Counts the replays the core queued and kept since [`replays`] read
/// `before` as ones `lane`'s live GET owes, once the GET has its terminal.
fn owe<C: Chunk>(world: &mut World, core: &Core<C>, lane: usize, before: (u64, u64)) {
    let (counted, dropped) = replays(core);
    let kept = (counted - before.0).saturating_sub(dropped - before.1);
    let queued = u8::try_from(kept).unwrap_or(u8::MAX);
    let request = world.live[lane].expect("a live GET").request.request;
    world.owe(peer(lane), request, queued);
}

/// The frames a poll's sender takes, for the staging controls.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum Sender {
    /// Every frame the poll stages, up to a prefix poll's count.
    #[default]
    Takes,
    /// No DATA frame: the poll stops at the first one.
    RefusesData,
    /// DATA only of fragments sent before.
    ResendsOnly,
}

/// Search budgets left: fault actions (stale ACK, CANCEL) and finite time
/// advances.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Budgets {
    pub(super) faults: u8,
    pub(super) advances: u8,
}

/// One search state: the core with its namespace, the driver's view and the
/// budgets left.
#[derive(Clone)]
pub(super) struct Node<C> {
    pub(super) core: Core<C>,
    pub(super) world: World,
    pub(super) budgets: Budgets,
}

pub(super) fn node<C: Chunk>(batch: u32) -> Node<C> {
    node_with(CONFIG, batch)
}

/// [`node`] under `config`.
pub(super) fn node_with<C: Chunk>(config: ServeConfig, batch: u32) -> Node<C> {
    let table = RequestTable::<Request<C>>::new(TABLE_SLOTS, PEERS, TABLE_SLOTS);
    let core = Core::new(
        config,
        table,
        PEERS,
        batch,
        0,
        4,
        &mut EngineBudget::new(1 << 20),
    )
    .expect("a core");
    Node {
        core,
        world: World::default(),
        budgets: Budgets {
            faults: 2,
            advances: 4,
        },
    }
}

/// The state's exact canonical form: every field of the core and its
/// namespace, the driver's view and observers, and the budgets left.
pub(super) fn canonical<C: std::fmt::Debug>(node: &Node<C>) -> String {
    format!(
        "{:?}\n{:?}\n{:?}\n{:?}",
        node.core.serve, node.core.requests, node.world, node.budgets
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Action {
    Get(usize),
    Duplicate(usize),
    /// A valid ACK from the lane's client reporting receipt `base`,
    /// cumulative grant `grant` and receipt mask `mask`, whose bit `k` names
    /// fragment `base + 1 + k` as held; a nonzero mask names a hole, which
    /// stands for a lost frame and spends a fault.
    Ack(usize, u32, u32, u64),
    StaleAck(usize),
    Cancel(usize),
    Chunk(usize),
    ReadEnd(usize),
    Poll,
    /// The sender accepts the first `n` staged frames, with `n` below the
    /// staged count.
    Prefix(usize),
    Advance,
    /// The device returns the lane's GET's `n`th retained chunk, counted
    /// among the chunks the core retains for it in payload order.
    Return(usize, usize),
    Drain,
}

/// The grant a lane's GET opens with: both fragments on the first peer's
/// lanes, one on the second's, so grant waits occur.
pub(super) fn grant(lane: usize) -> u32 {
    if lane < WIRE_SLOTS as usize { 2 } else { 1 }
}

fn peer(lane: usize) -> PeerId {
    PeerId((lane / WIRE_SLOTS as usize) as u16)
}

pub(super) fn admitted(lane: usize) -> Admitted {
    Admitted {
        peer: peer(lane),
        ..session(2)
    }
}

/// `holds` yields each device-held chunk's hold flag and its index among
/// all chunks the core retains for `id`.
pub(super) fn holds<C: Hold>(
    requests: &Requests<C>,
    id: RequestId,
) -> impl Iterator<Item = (usize, &Cell<bool>)> {
    requests
        .get_chunks(id)
        .map(Hold::hold)
        .enumerate()
        .filter(|(_, hold)| hold.get())
}

/// Every action the state admits, in a fixed order.
pub(super) fn enabled<C>(node: &Node<C>) -> Vec<Action>
where
    C: Clone + Chunk + Hold + for<'a> Retained<'a>,
{
    let staged = node
        .core
        .clone()
        .poll(node.world.now_us, 64, |frames| frames.count());
    let mut actions = vec![Action::Poll];
    actions.extend((0..staged).map(Action::Prefix));
    actions.push(Action::Drain);
    if node.budgets.advances > 0 {
        actions.push(Action::Advance);
    }
    for (lane, live) in node.world.live.iter().enumerate() {
        let Some(live) = live else {
            actions.push(Action::Get(lane));
            continue;
        };
        actions.push(Action::Duplicate(lane));
        let full = MANIFEST.count();
        for base in live.acked..=live.sent.min(full) {
            let above = live.sent.min(full).saturating_sub(base + 1);
            let masks = if node.budgets.faults > 0 {
                1u64 << above
            } else {
                1
            };
            for grant in live.grant..=full {
                actions.extend((0..masks).map(|mask| Action::Ack(lane, base, grant, mask)));
            }
        }
        if node.budgets.faults > 0 {
            actions.extend([Action::StaleAck(lane), Action::Cancel(lane)]);
        }
        if live.delivered < 2 {
            actions.push(Action::Chunk(lane));
        } else if !live.read_ended {
            actions.push(Action::ReadEnd(lane));
        }
        actions.extend(holds(&node.core.requests, live.id).map(|(at, _)| Action::Return(lane, at)));
    }
    actions
}

pub(super) fn apply<C: Chunk + Hold + for<'a> Retained<'a>>(
    node: &mut Node<C>,
    action: Action,
    chunk: impl FnOnce(u64) -> C,
) {
    let now = node.world.now_us;
    let world = &mut node.world;
    let core = &mut node.core;
    match action {
        Action::Get(lane) => {
            let slot = (lane % WIRE_SLOTS as usize) as u16;
            let request = get(slot, world.generations[lane], grant(lane));
            match core.get(admitted(lane), &request, now) {
                GetOutcome::Read { id, .. } => {
                    core.read_started(id);
                    world.generations[lane] += 1;
                    world.live[lane] = Some(Live {
                        id,
                        request,
                        delivered: 0,
                        commanded: true,
                        read_ended: false,
                        sent: 0,
                        acked: 0,
                        grant: request.grant,
                    });
                }
                // A refusal settles the identity on both sides: the client ends
                // the GET at the refusal, so its next GET takes the next
                // generation.
                GetOutcome::Refused(_) => world.generations[lane] += 1,
                GetOutcome::Duplicate | GetOutcome::Replayed | GetOutcome::Dropped => {}
            }
        }
        Action::Duplicate(lane) => {
            let live = world.live[lane].expect("a live GET");
            let replays = replays(core);
            core.get(admitted(lane), &live.request, now);
            owe(world, core, lane, replays);
        }
        Action::Ack(lane, base, grant, mask) => {
            node.budgets.faults -= u8::from(mask != 0);
            let replays = replays(core);
            let live = world.live[lane].as_mut().expect("a live GET");
            live.acked = base;
            live.grant = grant;
            let header = Header {
                offset: mask,
                ..ack(&live.request, &MANIFEST, base, grant)
            };
            core.ack(admitted(lane), &header, now);
            owe(world, core, lane, replays);
        }
        Action::StaleAck(lane) => {
            node.budgets.faults -= 1;
            let replays = replays(core);
            let live = world.live[lane].expect("a live GET");
            let header = ack(&live.request, &MANIFEST, 0, 0);
            core.ack(admitted(lane), &header, now);
            owe(world, core, lane, replays);
        }
        Action::Cancel(lane) => {
            node.budgets.faults -= 1;
            let live = world.live[lane].expect("a live GET");
            let cancel = Header {
                kind: Kind::Cancel,
                status: Status::Cancelled as u16,
                metadata_len: 0,
                body_len: 0,
                grant: 0,
                remaining_ms: 0,
                ..live.request
            };
            core.cancel(admitted(lane), &cancel, now);
            let (peer, request) = (peer(lane), live.request.request);
            if core.requests.get_is_ended(live.id) {
                world.settle(peer, request, Logical::cancelled(&live.request));
            }
            // A cancel clears the GET's queued replies.
            if let Ok(at) = world.settled_at(peer, request) {
                world.settled[at].owed = 0;
            }
        }
        Action::Chunk(lane) => {
            let live = world.live[lane].as_mut().expect("a live GET");
            if !live.commanded && core.wants_grant(live.id) {
                core.granted(live.id);
                live.commanded = true;
            }
            if live.commanded {
                let start = u64::from(live.delivered) * CHUNK;
                let chunk = chunk(start);
                let device = chunk.hold().get();
                if core.chunk(live.id, MANIFEST, start..start + CHUNK, chunk, &[], now) {
                    world.holds[lane] += u8::from(device);
                }
                live.delivered += 1;
                live.commanded = false;
            }
        }
        Action::ReadEnd(lane) => {
            let live = world.live[lane].as_mut().expect("a live GET");
            core.read_done(live.id, ReadEnd::Complete(MANIFEST), now);
            live.read_ended = true;
        }
        Action::Poll | Action::Prefix(_) => {
            let take = match action {
                Action::Prefix(n) => n,
                _ => usize::MAX,
            };
            world.last_poll.clear();
            let sender = world.sender;
            let sent: Vec<(PeerId, u64, u32)> = if sender == Sender::ResendsOnly {
                (0..LANES)
                    .filter_map(|lane| {
                        let live = world.live[lane]?;
                        Some((admitted(lane).peer, live.request.request, live.sent))
                    })
                    .collect()
            } else {
                Vec::new()
            };
            let refused = move |out: &super::serve::Out<'_, '_>| {
                let header = out.header;
                let resent = || {
                    sent.iter().any(|&(peer, request, sent)| {
                        peer == out.peer && request == header.request && header.index < sent
                    })
                };
                header.kind == Kind::Data
                    && match sender {
                        Sender::Takes => false,
                        Sender::RefusesData => true,
                        Sender::ResendsOnly => !resent(),
                    }
            };
            let plant = world.plant;
            let mut terminals = Vec::new();
            core.poll(now, 64, |frames| {
                frames
                    .take(take)
                    .take_while(|out| !refused(out))
                    .inspect(|out| {
                        world.frames += 1;
                        let header = out.header;
                        let kind = header.kind;
                        let lane = (0..LANES).find(|&lane| {
                            world.live[lane].is_some_and(|live| {
                                peer(lane) == out.peer && live.request.request == header.request
                            })
                        });
                        let settled = world.settled_at(out.peer, header.request).is_ok();
                        let frames: &[Kind] = match (plant, kind) {
                            (Plant::EarlyComplete, Kind::Data) => &[Kind::Complete, Kind::Data],
                            (Plant::DataAfterTerminal, Kind::Complete) if settled => &[Kind::Data],
                            (Plant::DoubleTerminal, Kind::Complete) => &[Kind::Complete; 2],
                            (Plant::DoubleTerminal, Kind::Error) => &[Kind::Error; 2],
                            (Plant::ErrorForComplete, Kind::Complete) => &[Kind::Error],
                            (Plant::SilentComplete, Kind::Complete) => &[],
                            _ => std::slice::from_ref(&kind),
                        };
                        for &frame in frames {
                            world
                                .last_poll
                                .push((out.peer, frame, header.request, header.index));
                            let at = (out.peer, header.request);
                            match frame {
                                Kind::Complete | Kind::Error => {
                                    let mut terminal = Logical {
                                        kind: frame,
                                        ..Logical::of(&header)
                                    };
                                    let replay = world.settled_at(at.0, at.1).is_ok();
                                    if plant == Plant::ConflictingReplay && replay {
                                        terminal.allocation ^= 1;
                                    }
                                    if plant == Plant::WrongManifest && frame == Kind::Complete {
                                        terminal.allocation ^= 1;
                                    }
                                    terminals.push((at, terminal, lane));
                                }
                                Kind::Data => {
                                    let after = world.settled_at(at.0, at.1).is_ok()
                                        || terminals.iter().any(|&(of, ..)| of == at);
                                    world.broken.data_after += u32::from(after);
                                }
                                _ => {}
                            }
                        }
                        if kind != Kind::Data {
                            return;
                        }
                        let bytes = [out.payload[0].bytes(), out.payload[1].bytes()].concat();
                        let start = u64::from(header.index) * CHUNK;
                        let range = start..(start + CHUNK).min(MANIFEST.total());
                        let exact = header.offset == start && bytes == content(range);
                        world.wrong_bytes += u32::from(!exact);
                        let lane = world.live.iter_mut().enumerate().find_map(|(lane, live)| {
                            live.as_mut().filter(|live| {
                                peer(lane) == out.peer && live.request.request == header.request
                            })
                        });
                        if let Some(live) = lane {
                            world.skipped += u32::from(header.index > live.sent);
                            live.sent = live.sent.max(header.index + 1);
                        }
                    })
                    .count()
            });
            for ((peer, request), logical, lane) in terminals {
                let live = lane.map(|lane| {
                    let live = world.live[lane].expect("a terminal's GET is live");
                    (lane, live, core.requests.get_is_ended(live.id))
                });
                terminal(world, (peer, request, logical), live);
            }
            if plant == Plant::RepliesFirst && core.serve.egress_need() == 0 {
                core.serve.stage_replies_first();
            }
        }
        Action::Advance => {
            node.budgets.advances -= 1;
            world.now_us += CONFIG.retry_us;
            core.tick(world.now_us);
        }
        Action::Return(lane, at) => {
            let id = world.live[lane].expect("a live GET").id;
            if let Some((_, hold)) = holds(&core.requests, id).find(|&(held, _)| held == at) {
                hold.set(false);
                world.holds[lane] -= 1;
            }
            core.reap();
        }
        Action::Drain => {
            let ended: Vec<bool> = world
                .live
                .iter()
                .map(|live| {
                    live.is_none_or(|live| {
                        core.requests().get(live.id).is_some()
                            && core.requests.get_is_ended(live.id)
                    })
                })
                .collect();
            if world.plant == Plant::HeldRelease {
                for (lane, live) in world.live.iter().enumerate() {
                    if let Some(live) = live.filter(|_| ended[lane]) {
                        let slot = (lane % WIRE_SLOTS as usize) as u16;
                        core.requests.release(live.id, peer(lane), slot);
                    }
                }
            }
            core.release_drained(|_| true);
            for (lane, &ended) in ended.iter().enumerate() {
                let released = world.live[lane]
                    .filter(|live| core.requests().get(live.id).is_none())
                    .map(|live| live.request.request);
                if let Some(request) = released {
                    world.live[lane] = None;
                    world.released_held += u32::from(world.holds[lane] > 0);
                    world.vanished += u32::from(!ended);
                    let settled = world.settled_at(peer(lane), request).is_ok();
                    world.broken.unterminated += u32::from(!settled);
                    world.completed_held[lane] = false;
                    world.holds[lane] = 0;
                }
            }
        }
    }
}

/// The device-held chunk of the object's content from `start`.
pub(super) fn owned(start: u64) -> Owned {
    Owned(content(start..start + CHUNK).into(), Cell::new(true), start)
}

/// Runs `script` from a fresh state.
pub(super) fn scripted(script: &[Action]) -> Node<Owned> {
    let mut state = node(BATCH);
    for &action in script {
        apply(&mut state, action, owned);
    }
    state
}

/// Two GETs from two peers, each holding a device-held chunk, with frames
/// sent and an ACK applied.
const BUSY: [Action; 6] = [
    Action::Get(0),
    Action::Chunk(0),
    Action::Poll,
    Action::Ack(0, 1, 2, 0),
    Action::Get(2),
    Action::Chunk(2),
];

/// Two peers may reuse one wire request ID, so a DATA frame belongs to the
/// lane of its peer; otherwise a valid ACK would acknowledge fragments its
/// peer was never sent, or none of those it was.
#[test]
fn a_lane_counts_only_its_own_peers_data() {
    let state = scripted(&[
        Action::Get(0),
        Action::Chunk(0),
        Action::Get(2),
        Action::Chunk(2),
        Action::Poll,
    ]);
    let wire = |lane: usize| state.world.live[lane].expect("a live GET").request.request;
    assert_eq!(wire(0), wire(2), "both lanes use one wire ID");
    for lane in [0, 2] {
        let peer = peer(lane);
        let received = state
            .world
            .last_poll
            .iter()
            .filter(|&&(to, kind, request, _)| {
                to == peer && kind == Kind::Data && request == wire(lane)
            })
            .map(|&(.., index)| index + 1)
            .max();
        let sent = state.world.live[lane].expect("a live GET").sent;
        assert_eq!(Some(sent), received, "lane {lane}");
    }
}

/// Under identical sequences sampled from the whole alphabet, a copy taken
/// at a sampled step equals its original in canonical form, and the two
/// stay equal, every last poll included, at every later step; each of the
/// twelve actions changes some state while a copy exists, and both copies
/// keep their indexes.
#[test]
fn a_copy_and_its_original_evolve_equal_under_identical_inputs() {
    let mut occurred = HashSet::new();
    for seed in 0..64 {
        let mut rng = SplitMix64::new(seed);
        let mut original = node::<Owned>(BATCH);
        let copy_at = rng.below(30);
        let mut copy = None;
        for step in 0..60 {
            if step == copy_at {
                let copied = original.clone();
                assert_eq!(canonical(&copied), canonical(&original), "seed {seed}");
                copy = Some(copied);
            }
            let actions = enabled(&original);
            let action = actions[rng.below(actions.len() as u64) as usize];
            let before = copy.is_some().then(|| canonical(&original));
            apply(&mut original, action, owned);
            if before.is_some_and(|before| canonical(&original) != before) {
                occurred.insert(std::mem::discriminant(&action));
            }
            original.core.check_indexes();
            if let Some(copy) = &mut copy {
                apply(copy, action, owned);
                copy.core.check_indexes();
                assert_eq!(
                    canonical(copy),
                    canonical(&original),
                    "seed {seed} step {step} {action:?}"
                );
            }
        }
    }
    assert_eq!(occurred.len(), 12, "every action changed a copied state");
}

/// A copy of a shaped core whose shaper refused a frame keeps the refused
/// request's turn and the bytes it waits for: the copy and its original
/// stage the same frames as the bucket refills.
#[test]
fn a_copy_of_a_shaped_core_keeps_the_refused_turn() {
    let mut original = shaped_core(16);
    let at = Shaper::CONTROL_US;
    original.poll(at, 64, |frames| frames.count());
    let mut copy = original.clone();
    let form = |core: &Core<Box<[u8]>>| format!("{:?}\n{:?}", core.serve, core.requests);
    assert_ne!(copy.serve.egress_need(), 0, "the shaper refused");
    for step in 1..=40 {
        let now = at + step * 100;
        let sent = original.poll(now, 64, |frames| frames.count());
        assert_eq!(copy.poll(now, 64, |frames| frames.count()), sent, "{now}");
        assert_eq!(form(&copy), form(&original), "{now}");
    }
}

/// A copy keeps its staged batch's capacity: copied before its first poll,
/// the batch is empty, and the copy's poll still stages what the
/// original's stages.
#[test]
fn an_empty_staged_batch_keeps_its_positive_size_in_a_copy() {
    let mut original = scripted(&[Action::Get(0), Action::Chunk(0)]);
    let mut copy = original.clone();
    let sent = original.core.poll(0, 64, |frames| frames.count());
    assert!(sent > 0);
    assert_eq!(copy.core.poll(0, 64, |frames| frames.count()), sent);
}

/// A copy serves GETs, chunks, ACKs, polls, ticks, reaps and releases
/// without allocating: the reap drops a returned chunk and the release frees
/// an ended request's slot onto the copied free list.
#[test]
fn a_copy_serves_without_allocating() {
    let mut original = scripted(&BUSY);
    apply(&mut original, Action::Cancel(2), owned);
    let mut copy = original.clone();
    let (live, ended) = (
        copy.world.live[0].expect("a live GET"),
        copy.world.live[2].expect("a live GET"),
    );
    let chunk = owned(0);
    let allocations = crate::instrument::allocations();
    let core = &mut copy.core;
    holds(&core.requests, ended.id)
        .next()
        .expect("a held chunk")
        .1
        .set(false);
    assert_eq!(core.reap(), 1, "the returned chunk ends its hold");
    assert_eq!(core.release_drained(|_| true), 1, "the ended GET leaves");
    let request = get(1, 0, 2);
    let GetOutcome::Read { id, .. } = core.get(admitted(1), &request, 0) else {
        panic!("a new request");
    };
    core.read_started(id);
    core.chunk(id, MANIFEST, 0..CHUNK, chunk, &[], 0);
    core.poll(0, 64, |frames| frames.count());
    core.ack(admitted(0), &ack(&live.request, &MANIFEST, 1, 2), 0);
    core.tick(CONFIG.retry_us);
    core.poll(CONFIG.retry_us, 64, |frames| frames.count());
    assert_eq!(crate::instrument::allocations(), allocations);
}

/// Whether `action` on a copy of `base` leaves `base`'s canonical form as
/// it was.
fn sibling_unaffected<C>(base: &Node<C>, action: Action, chunk: impl FnOnce(u64) -> C) -> bool
where
    C: Clone + std::fmt::Debug + Chunk + Hold + for<'a> Retained<'a>,
{
    let before = canonical(base);
    let mut sibling = base.clone();
    apply(&mut sibling, action, chunk);
    assert_ne!(canonical(&sibling), before, "{action:?} changed nothing");
    canonical(base) == before
}

/// A return, release, hold, receipt, poll, tick, cancel or duplicate on one
/// of two copies changes nothing of the other, and each such action changes
/// the copy it runs on.
#[test]
fn sibling_copies_are_independent() {
    let busy = scripted(&BUSY);
    let mut cancelled = busy.clone();
    apply(&mut cancelled, Action::Cancel(2), owned);
    apply(&mut cancelled, Action::Return(2, 0), owned);
    let mut polled = busy.clone();
    apply(&mut polled, Action::Poll, owned);
    for (base, action) in [
        (&busy, Action::Return(0, 0)),
        (&cancelled, Action::Drain),
        (&busy, Action::Chunk(0)),
        (&polled, Action::Ack(2, 1, 2, 0)),
        (&busy, Action::Poll),
        (&busy, Action::Advance),
        (&busy, Action::Cancel(2)),
        (&busy, Action::Duplicate(2)),
    ] {
        assert!(
            sibling_unaffected(base, action, owned),
            "{action:?} reached the sibling"
        );
    }
}

/// Control: a chunk whose hold flag a copy shares by reference lets a
/// return on one copy reach its sibling, which the independence check
/// catches, and the sibling's reap drops a chunk its own device never
/// returned.
#[test]
fn a_shared_hold_flag_breaks_sibling_independence() {
    let shared = |start| {
        Tx(
            content(start..start + CHUNK).into(),
            std::rc::Rc::new(Cell::new(true)),
        )
    };
    let mut base = node::<Tx>(BATCH);
    apply(&mut base, Action::Get(0), shared);
    apply(&mut base, Action::Chunk(0), shared);
    apply(&mut base, Action::Poll, shared);
    apply(&mut base, Action::Ack(0, 1, 2, 0), shared);
    assert!(
        !sibling_unaffected(&base, Action::Return(0, 0), shared),
        "the return reached the sibling"
    );
    assert_eq!(
        base.core.reap(),
        1,
        "the sibling reaps a chunk it still holds"
    );
}

/// Equal states have equal canonical forms, and states that differ in an
/// observer, a budget, a core counter, a retained chunk's hold in the
/// namespace, the staged batch or a free list's order differ; a copied
/// record array keeps its free list's capacity.
#[test]
fn canonical_forms_equate_equal_states_and_separate_every_difference() {
    let busy = scripted(&BUSY);
    assert_eq!(canonical(&busy), canonical(&scripted(&BUSY)));
    assert_eq!(canonical(&busy), canonical(&busy.clone()));
    let mut observed = busy.clone();
    observed.world.frames += 1;
    let mut budgeted = busy.clone();
    budgeted.budgets.advances -= 1;
    let mut stale = busy.clone();
    let live = stale.world.live[0].expect("a live GET");
    stale
        .core
        .ack(admitted(0), &ack(&live.request, &MANIFEST, 0, 0), 0);
    assert_eq!(stale.core.report().stale_acks, 1);
    let returned = busy.clone();
    let id = returned.world.live[0].expect("a live GET").id;
    holds(&returned.core.requests, id)
        .next()
        .expect("a held chunk")
        .1
        .set(false);
    for other in [observed, budgeted, stale, returned] {
        assert_ne!(canonical(&other), canonical(&busy));
    }
    assert_ne!(
        canonical(&node::<Owned>(BATCH)),
        canonical(&node::<Owned>(BATCH * 2))
    );
    let records = |frees: &[u32]| {
        let mut records = Records::<u8>::new(3);
        for value in 0..3 {
            records.insert(value).expect("a free slot");
        }
        for &slot in frees {
            records.remove(slot);
        }
        let copy = records.clone();
        assert_eq!(format!("{copy:?}"), format!("{records:?}"));
        assert!(format!("{copy:?}").contains("free_capacity: 3"));
        format!("{copy:?}")
    };
    assert_ne!(records(&[0, 1]), records(&[1, 0]), "free-list order");
}

/// The search's record of visited states: buckets by digest, each holding
/// the exact canonical forms in it and the greatest allowance each was
/// reached with.
pub(super) struct Seen<H> {
    digest: H,
    buckets: HashMap<u64, Vec<(String, u32)>>,
}

impl<H: Fn(&str) -> u64> Seen<H> {
    pub(super) fn new(digest: H) -> Self {
        Self {
            digest,
            buckets: HashMap::new(),
        }
    }

    /// Distinct states visited.
    pub(super) fn len(&self) -> usize {
        self.buckets.values().map(Vec::len).sum()
    }

    /// Bytes of the canonical forms stored.
    pub(super) fn bytes(&self) -> usize {
        self.buckets
            .values()
            .flatten()
            .map(|(form, _)| form.len())
            .sum()
    }

    /// Distinct states in the fullest bucket.
    pub(super) fn largest_bucket(&self) -> usize {
        self.buckets.values().map(Vec::len).max().unwrap_or(0)
    }

    /// `allowance` counts the steps remaining when the state is reached.
    pub(super) fn visit(&mut self, canonical: String, allowance: u32) -> Visit {
        let bucket = self.buckets.entry((self.digest)(&canonical)).or_default();
        match bucket.iter_mut().find(|(seen, _)| *seen == canonical) {
            Some((_, seen)) if *seen >= allowance => Visit::Pruned,
            Some((_, seen)) => {
                *seen = allowance;
                Visit::Widened
            }
            None => {
                bucket.push((canonical, allowance));
                Visit::Stored
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Visit {
    Stored,
    /// The state re-expands; its allowance becomes the pruning threshold
    /// for equal canonical states.
    Widened,
    Pruned,
}

impl Visit {
    pub(super) fn expands(self) -> bool {
        self != Self::Pruned
    }
}

pub(super) fn digest(canonical: &str) -> u64 {
    thread_local! {
        static STATE: RandomState = RandomState::new();
    }
    STATE.with(|state| state.hash_one(canonical))
}

/// An equal state reached with no more allowance prunes; one reached with a
/// greater allowance re-expands, and its allowance then prunes equal states
/// reached with no more.
#[test]
fn a_greater_allowance_re_expands_a_pruned_state() {
    let mut seen = Seen::new(digest);
    let state = canonical(&scripted(&BUSY));
    assert_eq!(seen.visit(state.clone(), 3), Visit::Stored);
    assert_eq!(seen.visit(state.clone(), 3), Visit::Pruned);
    assert_eq!(seen.visit(state.clone(), 2), Visit::Pruned);
    assert_eq!(seen.visit(state.clone(), 5), Visit::Widened);
    assert_eq!(seen.visit(state, 4), Visit::Pruned);
    assert_eq!(seen.len(), 1, "a widening keeps the one stored form");
    assert!(Visit::Stored.expands() && Visit::Widened.expands());
    assert!(!Visit::Pruned.expands());
}

/// Collision control: under a digest that sends every state to one bucket,
/// distinct states still expand, because pruning compares canonical forms
/// exactly.
#[test]
fn colliding_digests_never_merge_distinct_states() {
    let busy = canonical(&scripted(&BUSY));
    let one_get = canonical(&scripted(&[Action::Get(0)]));
    assert_ne!(busy, one_get);
    let mut seen = Seen::new(|_: &str| 0);
    assert_eq!(seen.visit(busy.clone(), 3), Visit::Stored);
    assert_eq!(seen.visit(one_get.clone(), 3), Visit::Stored);
    assert_eq!(seen.buckets[&0].len(), 2);
}
