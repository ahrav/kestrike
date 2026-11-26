//! Finite exhaustive search over the GET transfer core's pure alphabet: GET
//! and duplicate GET, valid and stale ACK, CANCEL, chunk and read end, poll
//! and TX prefix, finite time advance, device return and drain release.
//! From one declared bound, a depth-first search expands every enabled
//! action of every state above the depth bound, prunes a state whose exact
//! canonical form was reached with at least its allowance, and checks at
//! every reached state the byte, custody, per-request staging and terminal
//! obligations. A search starts at its bound's root: the fresh core, or a
//! seeded root the driver reaches by replaying a scripted prefix from the
//! fresh core, so every seeded root is a state the core reached. A seeded
//! bound names the `sometimes` witnesses its search must observe. Only a
//! search that exhausts its bound and observes every witness it names
//! earns credit; a watchdog stop is incomplete.

use std::cell::Cell;
use std::collections::HashSet;
use std::mem::{Discriminant, discriminant};
use std::ops::Range;

use crate::net::PeerId;
use crate::storage::{Crc32c, SourceRange, ZeroRuns};

use super::frame::Kind;
use super::pace::Shaper;
use super::requests::RequestId;
use super::serve::{Chunk, GetOutcome, Retained, ServeConfig};
use super::serve_clone_tests::{
    Action, BATCH, Broken, Budgets, CHUNK, Hold, LANES, MANIFEST, Node, Owned, Plant, Seen, Sender,
    TABLE_SLOTS, Visit, WIRE_SLOTS, World, admitted, apply, canonical, content, digest, enabled,
    grant, holds, node, node_with, owned, scripted,
};
use super::serve_tests::{CONFIG, get};

/// The chunk types a search runs over.
trait Searched: Clone + std::fmt::Debug + Chunk + Hold + for<'a> Retained<'a> {}

impl<C: Clone + std::fmt::Debug + Chunk + Hold + for<'a> Retained<'a>> Searched for C {}

/// Polls a request whose premises hold may wait before it stages its
/// fragment: one. Under the premises the shaper refuses nothing and the
/// peer's pacer covers a whole batch, so only the batch's room can defer
/// the fragment; within the declared bounds one batch holds every frame
/// staged ahead of it. A bound with more traffic per poll than a batch
/// needs a larger bound.
const POLL_BOUND: usize = 1;

/// The batch of [`PRESSED`], which two refusals fill.
const PRESSED_BATCH: u32 = 2;

/// The frames a due GET stages up to and including its due DATA frame:
/// its START, a resend of every fragment below the due one, which a
/// duplicate GET requeues, and the due frame. With two-chunk content one
/// fragment lies below it: three.
const DUE_FRAMES: usize = 3;

/// Polls a request whose premises hold may wait before it stages its
/// fragment while the other peer queues refusals before every poll, at a
/// batch of [`PRESSED_BATCH`]. Replies stage first unless the previous
/// poll left requests waiting, and replies that fill the batch while a
/// request is ready leave requests waiting, so with the shaper unshaped the
/// core alternates: at worst one poll the refusals fill, then one
/// requests-first poll. A requests-first poll visits the cursor's request
/// for up to [`DATA_BURST`](super::serve::DATA_BURST) frames; the batch
/// cuts that visit and leaves the cursor on the other request, and a
/// request out of frames yields the batch's rest to the other in the same
/// poll, so every requests-first poll stages [`PRESSED_BATCH`] frames while
/// the two requests hold that many. Each GET holds at most [`DUE_FRAMES`]
/// frames, the two together `TABLE_SLOTS * DUE_FRAMES`, so the due frame
/// stages within `ceil(2 * 3 / 2)` = 3 requests-first polls, each after a
/// poll the refusals fill: 6. The premises give the peer's pacer [`BATCH`]
/// = 8 tokens, and three requests-first polls stage at most six of its
/// frames, so the pacer never binds.
const PRESSED_BOUND: usize =
    2 * (TABLE_SLOTS as usize * DUE_FRAMES).div_ceil(PRESSED_BATCH as usize);

/// How the staging monitor's lookahead runs a due request's polls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Staging {
    /// [`POLL_BOUND`] polls with no other input; a missed fragment breaks
    /// [`Obligation::Staging`].
    Quiet,
    /// [`PRESSED_BOUND`] polls, before each of which the other peer queues
    /// every refusal it can draw; a missed fragment breaks
    /// [`Obligation::Starved`].
    Pressed,
}

impl Staging {
    fn polls(self) -> usize {
        match self {
            Self::Quiet => POLL_BOUND,
            Self::Pressed => PRESSED_BOUND,
        }
    }
}

/// One declared search bound: its root, depth in actions, fault actions
/// and finite time advances, the transitions the watchdog allows before it
/// stops the search, the witnesses it must observe, the core's batch and
/// the staging monitor's lookahead. The core is otherwise fixed: two
/// peers, two request slots, two wire slots per peer and two-chunk
/// content.
#[derive(Clone, Copy, Debug)]
struct Bounds {
    name: &'static str,
    root: Root,
    depth: u32,
    faults: u8,
    advances: u8,
    watchdog: u64,
    witnesses: &'static [&'static str],
    batch: u32,
    staging: Staging,
}

/// The state a search starts from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Root {
    /// A fresh core.
    Fresh,
    /// Lane 0's GET sent every DATA frame and its read ended, with its
    /// client's final ACK outstanding.
    PrefinalAck,
    /// Lane 0's GET sent COMPLETE while the device holds its chunks.
    CompletedHeld,
}

impl Root {
    /// The actions that reach the root from a fresh core.
    fn prefix(self) -> &'static [Action] {
        const PREFINAL_ACK: [Action; 5] = [
            Action::Get(0),
            Action::Chunk(0),
            Action::Chunk(0),
            Action::ReadEnd(0),
            Action::Poll,
        ];
        const COMPLETED_HELD: [Action; 7] = [
            Action::Get(0),
            Action::Chunk(0),
            Action::Chunk(0),
            Action::ReadEnd(0),
            Action::Poll,
            Action::Ack(0, 2, 2, 0),
            Action::Poll,
        ];
        match self {
            Self::Fresh => &[],
            Self::PrefinalAck => &PREFINAL_ACK,
            Self::CompletedHeld => &COMPLETED_HELD,
        }
    }

    /// Whether `node` stands in the root's named state.
    fn holds<C>(self, node: &Node<C>) -> bool {
        let Some(live) = node.world.live[0] else {
            return self == Self::Fresh && node.world.live.iter().all(Option::is_none);
        };
        let ended = node.core.requests.get_is_ended(live.id);
        let every_fragment = live.sent == MANIFEST.count() && live.read_ended;
        match self {
            Self::Fresh => false,
            Self::PrefinalAck => every_fragment && live.acked < MANIFEST.count() && !ended,
            Self::CompletedHeld => {
                every_fragment
                    && ended
                    && node.world.terminal(0) == Some(Kind::Complete)
                    && node.world.completed_held[0]
                    && node.world.holds[0] > 0
            }
        }
    }
}

/// The seeded GET's client reported every fragment received with its read
/// ended, and a poll answered with COMPLETE, from a state the byte and
/// terminal rules accept. From the completed-held root that COMPLETE is the
/// replay of the GET's cached terminal, the same logical result.
const COMPLETE_WITNESS: &str = "ef-09-prefinal-ack-complete";

/// A drain released the seeded GET, which sent COMPLETE while the device
/// held one of its chunks, once the device returned them: the logical
/// completion with a retained chunk followed by the device return.
const RELEASE_WITNESS: &str = "ef-09-completed-held-release";

/// The witnesses a seeded bound must observe.
const SEEDED_WITNESSES: &[&str] = &[COMPLETE_WITNESS, RELEASE_WITNESS];

/// The bound the pull-request lane runs: about 5 s for this module in a
/// debug build.
const SHALLOW: Bounds = Bounds {
    name: "serve-search-shallow",
    root: Root::Fresh,
    depth: 5,
    faults: 1,
    advances: 1,
    watchdog: 1_000_000,
    witnesses: &[],
    batch: BATCH,
    staging: Staging::Quiet,
};

/// The nightly bound: the specification's two faults and four time
/// advances at depth 6, with about 0.75 GB of stored forms. Distinct states
/// grow about sixfold per level.
const NIGHTLY: Bounds = Bounds {
    name: "serve-search-nightly",
    root: Root::Fresh,
    depth: 6,
    faults: 2,
    advances: 4,
    watchdog: 10_000_000,
    witnesses: &[],
    batch: BATCH,
    staging: Staging::Quiet,
};

/// The nightly bound from the pre-final-ACK root, where COMPLETE takes the
/// final ACK and a poll, and the release of the completed GET two device
/// returns and a drain more.
const PREFINAL_ACK: Bounds = Bounds {
    name: "serve-search-prefinal-ack",
    root: Root::PrefinalAck,
    ..SEEDED
};

/// The nightly bound from the completed-held root, where the release takes
/// two device returns and a drain, and a replayed COMPLETE an ACK and a
/// poll.
const COMPLETED_HELD: Bounds = Bounds {
    name: "serve-search-completed-held",
    root: Root::CompletedHeld,
    ..SEEDED
};

/// The seeded bounds' shared depth, budgets and watchdog: the nightly
/// bound's two faults and four time advances at depth 5, where the
/// pre-final-ACK search stores about 0.5 GB of canonical forms.
const SEEDED: Bounds = Bounds {
    name: "serve-search-seeded",
    root: Root::Fresh,
    depth: 5,
    faults: 2,
    advances: 4,
    watchdog: 10_000_000,
    witnesses: SEEDED_WITNESSES,
    batch: BATCH,
    staging: Staging::Quiet,
};

/// The reply-pressure bound: a batch of two, which two refusals fill, at
/// depth 7 with no fault and no time advance, under the pressed lookahead.
/// Depth 6 is the shallowest that applies a poll replies fill while a
/// request is due: two GETs fill the table, two more draw refusals, a chunk
/// makes the first due and the poll stages the refusals. Depth 7 is the
/// shallowest whose lookahead needs all of [`PRESSED_BOUND`]: a duplicate
/// of a GET that sent its first fragment requeues its START and that
/// fragment ahead of the due one. The search stores about 0.8 GB of
/// canonical forms.
const PRESSED: Bounds = Bounds {
    name: "serve-search-pressed",
    root: Root::Fresh,
    depth: 7,
    faults: 0,
    advances: 0,
    watchdog: 10_000_000,
    witnesses: &[],
    batch: PRESSED_BATCH,
    staging: Staging::Pressed,
};

/// The obligation a monitor found broken at a state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Obligation {
    /// A DATA frame carried bytes other than the content's (O-BYTES).
    Bytes,
    /// The core dropped a chunk the device held (O-CUSTODY).
    Custody,
    /// A terminal broke its rules: a terminal frame while the request is
    /// pending, a COMPLETE before every fragment was acknowledged, an ERROR
    /// as the first terminal of a GET whose client acknowledged every
    /// fragment with its read ended, a first terminal whose manifest or key
    /// differ from the GET's request and bound object, a second or
    /// conflicting terminal, DATA after a terminal, a release of a GET with
    /// no terminal, or a release while the device held one of the GET's
    /// chunks.
    Terminal,
    /// A request failed to stage a chunk while `staging_due` held, skipped
    /// a fragment, or left the core before the request ended; the
    /// per-request staging monitor reports these.
    Staging,
    /// Under the pressed lookahead, the GET on `lane` failed to stage its
    /// due fragment within [`PRESSED_BOUND`] polls.
    Starved { lane: usize },
}

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// Every state within the bound was checked, every state above the
    /// depth bound was expanded, and every monitor held.
    Exhaustive,
    /// The watchdog stopped the search before it exhausted the bound.
    Incomplete,
    /// A monitor failed at the state the path reaches.
    Violation {
        obligation: Obligation,
        path: Vec<Action>,
    },
}

/// Totals of one search: distinct action kinds applied, distinct states
/// stored, transitions applied, the most states waiting on the stack, the
/// bytes of stored canonical forms and the deepest checked state.
#[derive(Debug, Default)]
struct Totals {
    alphabet: usize,
    states: usize,
    transitions: u64,
    high_water: usize,
    memory: usize,
    depth: u32,
}

/// One search's bound, verdict and totals, the distinct states in its
/// fullest digest bucket, the witnesses its bound names and those it
/// observed, and the states it stored that a poll reached whose batch
/// replies filled while a request was due.
#[derive(Debug)]
struct Report {
    bound: &'static str,
    verdict: Verdict,
    totals: Totals,
    largest_bucket: usize,
    required: &'static [&'static str],
    witnessed: Vec<&'static str>,
    activations: u64,
}

impl Report {
    /// The line a seeded search prints and its lane row matches: the
    /// bound, verdict and totals, then the witnesses observed.
    fn line(&self) -> String {
        format!(
            "{}: {:?} {:?} witnesses: {}",
            self.bound,
            self.verdict,
            self.totals,
            self.witnessed.join(" ")
        )
    }
}

/// Whether a search's report earns credit: only an exhaustive one that
/// observed every witness its bound names does; a missing report, a
/// watchdog stop, a violation and a missing witness earn none.
fn credited(report: Option<&Report>) -> bool {
    report.is_some_and(|report| {
        report.verdict == Verdict::Exhaustive
            && report.required.iter().all(|w| report.witnessed.contains(w))
    })
}

/// The first obligation `node` breaks, if any.
fn monitor<C>(node: &Node<C>, chunk: fn(u64) -> C, staging: Staging) -> Option<Obligation>
where
    C: Searched,
{
    let world = &node.world;
    if world.wrong_bytes > 0 {
        return Some(Obligation::Bytes);
    }
    let requests = &node.core.requests;
    let custody = world.live.iter().enumerate().all(|(lane, live)| {
        live.is_none_or(|live| {
            let held = requests.get_chunks(live.id).filter(|c| c.hold().get());
            held.count() == usize::from(world.holds[lane])
        })
    });
    if !custody {
        return Some(Obligation::Custody);
    }
    if world.skipped > 0 || world.vanished > 0 {
        return Some(Obligation::Staging);
    }
    let starved =
        (0..LANES).find(|&lane| staging_due(node, lane) && !stages(node, lane, chunk, staging));
    if let Some(lane) = starved {
        return Some(match staging {
            Staging::Quiet => Obligation::Staging,
            Staging::Pressed => Obligation::Starved { lane },
        });
    }
    (world.broken.any() || world.released_held > 0).then_some(Obligation::Terminal)
}

/// The staging monitor's premises for `lane`'s GET: it is live and not
/// ended; a delivered fragment is unsent and inside the client's grant;
/// its peer's pacer holds a token for every frame of a batch, so no reply,
/// START or other request's frame staged ahead of it on that peer exhausts
/// them; and the shaper is unshaped with no refused frame waiting. ACK,
/// grant, chunk, refill and device waits fall outside these premises. The
/// core commands no read beyond the client's grant, so under this driver a
/// delivered fragment lies inside it. The searched configuration's pacer
/// and shaper never bind within the declared bounds, so the premise test
/// is what checks those two premises.
fn staging_due<C>(node: &Node<C>, lane: usize) -> bool {
    let Some(live) = node.world.live[lane] else {
        return false;
    };
    let serve = &node.core.serve;
    !node.core.requests.get_is_ended(live.id)
        && live.sent < u32::from(live.delivered)
        && live.sent < live.grant
        && serve.paced(admitted(lane).peer, node.world.now_us, BATCH)
        && serve.report().shaped_bytes_per_s == Shaper::UNSHAPED
        && serve.egress_need() == 0
}

/// Whether `lane`'s GET stages its first unsent fragment as DATA within
/// `staging`'s polls of a copy of `node`.
fn stages<C>(node: &Node<C>, lane: usize, chunk: fn(u64) -> C, staging: Staging) -> bool
where
    C: Searched,
{
    staged_at(node, lane, chunk, staging, staging.polls()).is_some()
}

/// The poll, counted from one, at which `lane`'s GET first stages its
/// first unsent fragment as DATA within `polls` polls of a copy of `node`.
/// Under [`Staging::Pressed`] the other peer queues every refusal it can
/// draw before each poll; under [`Staging::Quiet`] nothing else happens.
fn staged_at<C>(
    node: &Node<C>,
    lane: usize,
    chunk: fn(u64) -> C,
    staging: Staging,
    polls: usize,
) -> Option<usize>
where
    C: Searched,
{
    let live = node.world.live[lane].expect("a live GET");
    let peer = admitted(lane).peer;
    let mut copy = node.clone();
    (1..=polls).find(|_| {
        if staging == Staging::Pressed {
            press(&mut copy, peer, chunk);
        }
        apply(&mut copy, Action::Poll, chunk);
        copy.world
            .last_poll
            .iter()
            .any(|&(to, kind, request, index)| {
                to == peer
                    && kind == Kind::Data
                    && request == live.request.request
                    && index == live.sent
            })
    })
}

/// Queues on `node` every refusal a peer other than `peer` can draw: while
/// every table slot holds a GET, a GET on each of that peer's free lanes,
/// which the full table refuses with an ERROR queued in the peer's reply
/// ring.
fn press<C: Searched>(node: &mut Node<C>, peer: PeerId, chunk: fn(u64) -> C) {
    let held = node.world.live.iter().flatten().count();
    if held < TABLE_SLOTS as usize {
        return;
    }
    for lane in (0..LANES).filter(|&lane| admitted(lane).peer != peer) {
        if node.world.live[lane].is_none() {
            apply(node, Action::Get(lane), chunk);
            assert!(
                node.world.live[lane].is_none(),
                "the full table refuses lane {lane}"
            );
        }
    }
}

/// Whether the poll from `parent` to `child` staged a whole batch of
/// `batch` frames, none of them a live GET's, while a GET in `parent` was
/// due: replies filled the batch while a request was ready.
fn saturated<C>(parent: &Node<C>, child: &Node<C>, batch: u32) -> bool {
    let live = |peer: PeerId, request: u64| {
        (0..LANES).any(|lane| {
            parent.world.live[lane]
                .is_some_and(|live| admitted(lane).peer == peer && live.request.request == request)
        })
    };
    let polled = &child.world.last_poll;
    polled.len() == batch as usize
        && polled
            .iter()
            .all(|&(peer, _, request, _)| !live(peer, request))
        && (0..LANES).any(|lane| staging_due(parent, lane))
}

/// `bounds`' root under its budgets, with chunks from `chunk`: the fresh
/// core with the root's prefix replayed through the driver, then `sender`
/// and `plant` installed.
///
/// # Panics
///
/// When the prefix leaves the core outside the root's named state.
fn root<C: Searched>(bounds: Bounds, chunk: fn(u64) -> C, sender: Sender, plant: Plant) -> Node<C> {
    let mut start = node::<C>(bounds.batch);
    start.budgets = Budgets {
        faults: bounds.faults,
        advances: bounds.advances,
    };
    for &action in bounds.root.prefix() {
        apply(&mut start, action, chunk);
    }
    assert!(
        bounds.root.holds(&start),
        "{:?} root: {:?}",
        bounds.root,
        start.world
    );
    start.world.sender = sender;
    start.world.plant = plant;
    start
}

/// Searches `bounds` from its root under `sender` and `plant`, with chunks
/// from `chunk` and visited states bucketed by their digest.
fn run<C: Searched>(bounds: Bounds, chunk: fn(u64) -> C, sender: Sender, plant: Plant) -> Report {
    search(bounds, root(bounds, chunk, sender, plant), chunk, digest)
}

/// Searches every state `bounds` admits from `start`, whose chunks come
/// from `chunk`, given each chunk's object offset, with visited states
/// bucketed by `bucket`.
fn search<C: Searched>(
    bounds: Bounds,
    start: Node<C>,
    chunk: fn(u64) -> C,
    bucket: fn(&str) -> u64,
) -> Report {
    let seed = start.world.live[0]
        .filter(|_| bounds.root != Root::Fresh)
        .map(|live| live.id);
    let mut witnessed: Vec<&'static str> = Vec::new();
    let mut seen = Seen::new(bucket);
    let mut totals = Totals::default();
    let mut activations = 0;
    let mut kinds: HashSet<Discriminant<Action>> = HashSet::new();
    seen.visit(canonical(&start), bounds.depth);
    let mut stack = vec![(start, Vec::new())];
    let report = |verdict,
                  mut totals: Totals,
                  kinds: &HashSet<_>,
                  seen: &Seen<fn(&str) -> u64>,
                  witnessed: &[&'static str],
                  activations: u64| {
        totals.alphabet = kinds.len();
        totals.states = seen.len();
        totals.memory = seen.bytes();
        let mut witnessed = witnessed.to_vec();
        witnessed.sort_unstable();
        Report {
            bound: bounds.name,
            verdict,
            totals,
            largest_bucket: seen.largest_bucket(),
            required: bounds.witnesses,
            witnessed,
            activations,
        }
    };
    while let Some((state, path)) = stack.pop() {
        let depth = path.len() as u32;
        totals.depth = totals.depth.max(depth);
        if let Some(obligation) = monitor(&state, chunk, bounds.staging) {
            let verdict = Verdict::Violation { obligation, path };
            return report(verdict, totals, &kinds, &seen, &witnessed, activations);
        }
        if depth == bounds.depth {
            continue;
        }
        for action in enabled(&state) {
            if totals.transitions == bounds.watchdog {
                return report(
                    Verdict::Incomplete,
                    totals,
                    &kinds,
                    &seen,
                    &witnessed,
                    activations,
                );
            }
            let mut child = state.clone();
            apply(&mut child, action, chunk);
            totals.transitions += 1;
            kinds.insert(discriminant(&action));
            let saturating = action == Action::Poll && saturated(&state, &child, bounds.batch);
            if let Some(seed) = seed {
                witness(seed, (&state, &child), action, &mut witnessed);
            }
            let visit = seen.visit(canonical(&child), bounds.depth - depth - 1);
            activations += u64::from(saturating && visit == Visit::Stored);
            if visit.expands() {
                let mut path = path.clone();
                path.push(action);
                stack.push((child, path));
                totals.high_water = totals.high_water.max(stack.len());
            }
        }
    }
    report(
        Verdict::Exhaustive,
        totals,
        &kinds,
        &seen,
        &witnessed,
        activations,
    )
}

/// Records into `witnessed` the witnesses the step from `parent` to
/// `child` under `action` shows for the seeded GET `seed`, lane 0's at the
/// root, when `child` breaks no byte or terminal rule: a poll that sends
/// COMPLETE for it once its client reported every fragment received with
/// its read ended witnesses [`COMPLETE_WITNESS`], and a drain that releases
/// it after it sent COMPLETE while the device held one of its chunks
/// witnesses [`RELEASE_WITNESS`].
fn witness<C>(
    seed: RequestId,
    (parent, child): (&Node<C>, &Node<C>),
    action: Action,
    witnessed: &mut Vec<&'static str>,
) {
    let world = &child.world;
    if world.wrong_bytes > 0 || world.broken.any() || world.released_held > 0 {
        return;
    }
    let seeded = |node: &Node<C>| node.world.live[0].filter(|live| live.id == seed);
    let completed = matches!(action, Action::Poll | Action::Prefix(_))
        && seeded(child).is_some_and(|live| {
            live.read_ended
                && live.acked == MANIFEST.count()
                && world.last_poll.iter().any(|&(peer, kind, request, _)| {
                    kind == Kind::Complete
                        && peer == admitted(0).peer
                        && request == live.request.request
                })
        });
    let released = action == Action::Drain
        && parent.world.completed_held[0]
        && seeded(parent).is_some()
        && world.live[0].is_none();
    for (seen, name) in [(completed, COMPLETE_WITNESS), (released, RELEASE_WITNESS)] {
        if seen && !witnessed.contains(&name) {
            witnessed.push(name);
        }
    }
}

/// A chunk whose bytes differ from the content in one place.
fn corrupt(start: u64) -> Owned {
    let mut chunk = owned(start);
    chunk.0[100] ^= 0x01;
    chunk
}

/// A chunk carrying the other chunk's bytes, as a fragment taken from the
/// wrong offset would.
fn swapped(start: u64) -> Owned {
    let other = CHUNK - start;
    Owned(content(other..other + CHUNK).into(), Cell::new(true), start)
}

/// A chunk that reports no device reference while the device holds it,
/// letting the core drop it early.
#[derive(Clone, Debug)]
struct Unheld(Owned);

impl AsRef<[u8]> for Unheld {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Chunk for Unheld {
    fn device_held(&self) -> bool {
        false
    }

    fn crc(
        &self,
        crc: Crc32c,
        runs: &mut ZeroRuns,
        window_crcs: &[u32],
        range: Range<usize>,
    ) -> u32 {
        self.0.crc(crc, runs, window_crcs, range)
    }
}

impl<'a> Retained<'a> for Unheld {
    fn source(&self, _range: Range<usize>) -> Option<SourceRange<'_, 'a>> {
        None
    }
}

impl Hold for Unheld {
    fn hold(&self) -> &Cell<bool> {
        self.0.hold()
    }
}

fn unheld(start: u64) -> Unheld {
    Unheld(owned(start))
}

/// The shallow bound exhausts with every monitor active: each of the
/// twelve action kinds is applied, the report prints its totals, and it
/// earns credit.
#[test]
fn the_shallow_search_exhausts_its_bound() {
    let report = run(SHALLOW, owned, Sender::Takes, Plant::None);
    eprintln!("{}: {:?} {:?}", report.bound, report.verdict, report.totals);
    assert_eq!(report.verdict, Verdict::Exhaustive, "{report:?}");
    assert_eq!(report.totals.alphabet, 12, "{report:?}");
    assert_eq!(report.totals.depth, SHALLOW.depth, "{report:?}");
    let totals = &report.totals;
    assert_eq!(
        (totals.states, totals.transitions, totals.high_water),
        SHALLOW_TOTALS,
        "{report:?}"
    );
    assert!(credited(Some(&report)));
}

/// The shallow search's distinct states, transitions and stack high water;
/// the search is deterministic, so these totals pin the reachable state
/// space, and a change to the alphabet, the driver or the pruning that
/// alters that space fails this test.
const SHALLOW_TOTALS: (usize, u64, usize) = (15_914, 34_745, 56);

/// The nightly search's distinct states, transitions and stack high water.
const NIGHTLY_TOTALS: (usize, u64, usize) = (135_549, 314_557, 69);

/// Collision control at search scale: bucketing states by the length of
/// their canonical form, which sends distinct states to one bucket, reaches
/// exactly the states and transitions the full digest does.
#[test]
fn colliding_buckets_reach_the_same_states() {
    let bounds = Bounds {
        depth: 4,
        ..SHALLOW
    };
    let full = run(bounds, owned, Sender::Takes, Plant::None);
    let coarse = search(
        bounds,
        root(bounds, owned, Sender::Takes, Plant::None),
        owned,
        |form| form.len() as u64,
    );
    assert_eq!(coarse.verdict, Verdict::Exhaustive);
    assert_eq!(
        (coarse.totals.states, coarse.totals.transitions),
        (full.totals.states, full.totals.transitions)
    );
    assert!(coarse.largest_bucket > 1, "{coarse:?}");
}

/// Controls: a chunk with one wrong byte, and a chunk carrying the other
/// chunk's bytes, each fail the byte monitor.
#[test]
fn a_wrong_byte_fails_the_byte_monitor() {
    for chunk in [corrupt as fn(u64) -> Owned, swapped] {
        let report = run(SHALLOW, chunk, Sender::Takes, Plant::None);
        assert!(
            matches!(
                report.verdict,
                Verdict::Violation {
                    obligation: Obligation::Bytes,
                    ..
                }
            ),
            "{report:?}"
        );
        assert!(!credited(Some(&report)));
    }
}

/// Control: a chunk released while the device holds it fails the custody
/// monitor.
#[test]
fn an_early_release_fails_the_custody_monitor() {
    let report = run(SHALLOW, unheld, Sender::Takes, Plant::None);
    assert!(
        matches!(
            report.verdict,
            Verdict::Violation {
                obligation: Obligation::Custody,
                ..
            }
        ),
        "{report:?}"
    );
    assert!(!credited(Some(&report)));
}

/// Control: a sender that takes no DATA frame leaves a request with every
/// premise funded unstaged, which the staging monitor names.
#[test]
fn a_request_that_never_stages_fails_the_staging_monitor() {
    let report = run(SHALLOW, owned, Sender::RefusesData, Plant::None);
    let Verdict::Violation { obligation, path } = report.verdict else {
        panic!("{report:?}");
    };
    assert_eq!(obligation, Obligation::Staging);
    assert!(
        path.iter().any(|action| matches!(action, Action::Chunk(_))),
        "a delivered fragment waits: {path:?}"
    );
}

/// The staging monitor's premises exclude legitimate waits: a request
/// waiting for its chunk, for receipt of everything it sent, for a grant,
/// for a pacing refill, under a shaped shaper or ended by a CANCEL is not
/// due, while one holding an unsent delivered fragment is.
#[test]
fn the_staging_monitor_fires_only_under_its_premises() {
    let waiting_for_chunk = scripted(&[Action::Get(0)]);
    assert!(!staging_due(&waiting_for_chunk, 0));
    let due = scripted(&[Action::Get(0), Action::Chunk(0)]);
    assert!(staging_due(&due, 0));
    assert!(stages(&due, 0, owned, Staging::Quiet));
    let sent = scripted(&[Action::Get(0), Action::Chunk(0), Action::Poll]);
    assert!(!staging_due(&sent, 0), "it waits for receipt");
    let cancelled = scripted(&[Action::Get(0), Action::Chunk(0), Action::Cancel(0)]);
    assert!(!staging_due(&cancelled, 0), "it ended");
    let script = [
        Action::Get(2),
        Action::Chunk(2),
        Action::Poll,
        Action::Ack(2, 1, 2, 0),
        Action::Chunk(2),
    ];
    let narrow = scripted(&script[..3]);
    let live = narrow.world.live[2].expect("a live GET");
    assert_eq!((live.delivered, live.sent, live.grant), (1, 1, 1));
    assert!(
        !staging_due(&narrow, 2),
        "it sent everything delivered, and a grant of one commands no second chunk"
    );
    let widened = scripted(&script);
    assert!(staging_due(&widened, 2), "the ACK widened the grant");
    assert!(stages(&widened, 2, owned, Staging::Quiet));
    let narrow_pacer = ServeConfig {
        rate_per_sec: 1_000,
        burst: 1,
        ..CONFIG
    };
    let mut starved = node_with::<Owned>(narrow_pacer, BATCH);
    for action in [Action::Get(0), Action::Chunk(0)] {
        apply(&mut starved, action, owned);
    }
    assert!(
        !staging_due(&starved, 0),
        "one token pays for the unacknowledged START, not the fragment too"
    );
    assert!(!stages(&starved, 0, owned, Staging::Quiet));
    let batch_pacer = ServeConfig {
        burst: u64::from(BATCH),
        ..CONFIG
    };
    let mut paced = node_with::<Owned>(batch_pacer, BATCH);
    for action in [
        Action::Get(0),
        Action::Chunk(0),
        Action::Poll,
        Action::Chunk(0),
    ] {
        apply(&mut paced, action, owned);
    }
    assert!(
        !staging_due(&paced, 0),
        "START and fragment 0 spent two of the batch's tokens"
    );
    apply(&mut paced, Action::Advance, owned);
    assert!(
        staging_due(&paced, 0),
        "the refill filled the batch's tokens again"
    );
    assert!(stages(&paced, 0, owned, Staging::Quiet));
    let mut shaped = scripted(&[Action::Get(0), Action::Chunk(0)]);
    shaped.core.control(0, Some(0));
    shaped.core.control(Shaper::CONTROL_US, Some(1));
    assert!(
        !staging_due(&shaped, 0),
        "a shaped shaper is outside the premises"
    );
}

/// Control: a sender that takes DATA only of fragments sent before leaves
/// the first unsent fragment unstaged while a resend of fragment 0 stages,
/// and the staging monitor, which asks for that fragment, names it.
#[test]
fn a_resend_in_place_of_the_due_fragment_fails_the_staging_monitor() {
    let mut state = scripted(&[Action::Get(0), Action::Chunk(0), Action::Poll]);
    state.world.sender = Sender::ResendsOnly;
    for action in [Action::Advance, Action::Chunk(0)] {
        apply(&mut state, action, owned);
    }
    assert!(staging_due(&state, 0), "{:?}", state.world.live[0]);
    let mut probe = state.clone();
    apply(&mut probe, Action::Poll, owned);
    assert!(
        probe
            .world
            .last_poll
            .iter()
            .any(|&(_, kind, _, index)| kind == Kind::Data && index == 0),
        "fragment 0 resends: {:?}",
        probe.world.last_poll
    );
    assert!(!stages(&state, 0, owned, Staging::Quiet));
    assert_eq!(
        monitor(&state, owned, Staging::Quiet),
        Some(Obligation::Staging)
    );
}

/// A watchdog stop is incomplete and earns no credit, and neither does a
/// missing report.
#[test]
fn a_watchdog_stop_or_a_missing_report_earns_no_credit() {
    let bounds = Bounds {
        watchdog: 10,
        ..SHALLOW
    };
    let report = run(bounds, owned, Sender::Takes, Plant::None);
    assert_eq!(report.verdict, Verdict::Incomplete);
    assert_eq!(report.totals.transitions, 10);
    assert!(!credited(Some(&report)));
    assert!(!credited(None));
}

/// The nightly bound. It is ignored in the pull-request lane and registered
/// as a search-bound row; it earns credit only from a lane that runs it with
/// `--ignored`.
#[test]
#[ignore = "nightly search bound; run with --ignored"]
fn the_nightly_search_exhausts_its_bound() {
    let report = run(NIGHTLY, owned, Sender::Takes, Plant::None);
    eprintln!("{}: {:?} {:?}", report.bound, report.verdict, report.totals);
    assert_eq!(report.totals.alphabet, 12, "{report:?}");
    assert_eq!(report.totals.depth, NIGHTLY.depth, "{report:?}");
    let totals = &report.totals;
    assert_eq!(
        (totals.states, totals.transitions, totals.high_water),
        NIGHTLY_TOTALS,
        "{report:?}"
    );
    assert_eq!(report.verdict, Verdict::Exhaustive, "{report:?}");
    assert!(credited(Some(&report)));
}

/// Control: a DATA frame of a fragment past its request's first unsent
/// one, as a core that skips a fragment would stage, fails the staging
/// monitor although its offset and bytes are the content's. The driver's
/// count of sent fragments is set back after fragment 0 goes out, so the
/// fragment the core stages next, fragment 1, arrives ahead of the fragment
/// the driver holds as first unsent.
#[test]
fn a_fragment_sent_ahead_of_the_first_unsent_fails_the_staging_monitor() {
    let mut state = scripted(&[
        Action::Get(0),
        Action::Chunk(0),
        Action::Poll,
        Action::Chunk(0),
    ]);
    let live = state.world.live[0].as_mut().expect("a live GET");
    assert_eq!((live.sent, live.delivered), (1, 2));
    live.sent = 0;
    apply(&mut state, Action::Poll, owned);
    assert!(
        state
            .world
            .last_poll
            .iter()
            .any(|&(_, kind, _, index)| kind == Kind::Data && index == 1),
        "fragment 1 goes out: {:?}",
        state.world.last_poll
    );
    assert_eq!(state.world.wrong_bytes, 0, "its offset and bytes are right");
    assert_eq!(
        monitor(&state, owned, Staging::Quiet),
        Some(Obligation::Staging)
    );
}

/// The device's return order matters to the search: with fragment 0 sent
/// and acknowledged, returning chunk 0 lets the reap drop it, while
/// returning chunk 1 keeps both chunks retained with chunk 0 still held, so
/// each held chunk needs its own enabled return.
#[test]
fn each_held_chunk_offers_its_own_return() {
    let both_held = scripted(&[
        Action::Get(0),
        Action::Chunk(0),
        Action::Poll,
        Action::Ack(0, 1, 2, 0),
        Action::Chunk(0),
    ]);
    let returns: Vec<Action> = enabled(&both_held)
        .into_iter()
        .filter(|action| matches!(action, Action::Return(..)))
        .collect();
    assert_eq!(returns, [Action::Return(0, 0), Action::Return(0, 1)]);
    let id = both_held.world.live[0].expect("a live GET").id;
    let retained = |node: &Node<Owned>| {
        node.core
            .requests
            .get_chunks(id)
            .map(|chunk| chunk.hold().get())
            .collect::<Vec<bool>>()
    };
    let mut first = both_held.clone();
    apply(&mut first, Action::Return(0, 0), owned);
    assert_eq!(retained(&first), [true], "the passed chunk 0 left the core");
    let mut second = both_held.clone();
    apply(&mut second, Action::Return(0, 1), owned);
    assert_eq!(retained(&second), [true, false], "chunk 0 stays held");
    assert_eq!(
        (first.world.holds[0], second.world.holds[0]),
        (1, 1),
        "each return ends one hold"
    );
    assert_ne!(canonical(&first), canonical(&second));
}

/// A poll's sender may stop after any number of staged frames, and each
/// stopping point settles a different set of requests, so the alphabet
/// offers one TX prefix per count below the frames the poll can stage.
#[test]
fn every_sendable_prefix_is_enabled() {
    let two_ready = scripted(&[
        Action::Get(0),
        Action::Chunk(0),
        Action::Get(1),
        Action::Chunk(1),
    ]);
    let staged = two_ready
        .core
        .clone()
        .poll(two_ready.world.now_us, 64, |frames| frames.count());
    assert!(staged > 2, "both GETs stage START and DATA: {staged}");
    let actions = enabled(&two_ready);
    let prefixes: Vec<usize> = actions
        .iter()
        .filter_map(|action| match action {
            Action::Prefix(n) => Some(*n),
            _ => None,
        })
        .collect();
    assert_eq!(prefixes, (0..staged).collect::<Vec<usize>>());
    let mut forms = HashSet::new();
    for n in 0..staged {
        let mut child = two_ready.clone();
        apply(&mut child, Action::Prefix(n), owned);
        assert!(
            forms.insert(canonical(&child)),
            "prefix {n} repeats a state"
        );
    }
}

/// Control: a GET that leaves the core before it ended, as a core that
/// releases an active request would let happen, fails the staging monitor
/// even with no chunk held, since the request's staging obligation ends
/// only with the request.
#[test]
fn a_live_request_released_before_its_end_fails_the_staging_monitor() {
    let mut state = scripted(&[Action::Get(0), Action::Chunk(0), Action::Return(0, 0)]);
    let live = state.world.live[0].expect("a live GET");
    assert!(!state.core.is_ended(live.id));
    assert_eq!(state.world.holds[0], 0, "the device returned its chunk");
    let slot = live.request.request as u16;
    assert!(state.core.requests.release(live.id, admitted(0).peer, slot));
    apply(&mut state, Action::Drain, owned);
    assert!(
        state.world.live[0].is_none(),
        "the driver saw the GET leave"
    );
    assert_eq!(
        monitor(&state, owned, Staging::Quiet),
        Some(Obligation::Staging)
    );
}

/// A valid ACK reports a receipt and a cumulative grant independently, so
/// the alphabet offers every receipt from the last one reported through the
/// fragments sent, paired with every grant from the current one through the
/// manifest's count; a receipt without a wider grant releases a passed
/// chunk while the next fragment stays uncommanded.
#[test]
fn valid_acks_vary_receipt_and_grant_independently() {
    let sent_one = scripted(&[Action::Get(2), Action::Chunk(2), Action::Poll]);
    let live = sent_one.world.live[2].expect("a live GET");
    assert_eq!((live.sent, live.grant), (1, 1));
    let acks: Vec<Action> = enabled(&sent_one)
        .into_iter()
        .filter(|action| matches!(action, Action::Ack(..)))
        .collect();
    assert_eq!(
        acks,
        [
            Action::Ack(2, 0, 1, 0),
            Action::Ack(2, 0, 2, 0),
            Action::Ack(2, 1, 1, 0),
            Action::Ack(2, 1, 2, 0),
        ]
    );
    let mut received = sent_one.clone();
    apply(&mut received, Action::Ack(2, 1, 1, 0), owned);
    assert_eq!(received.core.report().stale_acks, 0, "the core accepted it");
    assert!(
        !received.core.wants_grant(live.id),
        "the client granted one fragment and received it, so the read stays uncommanded"
    );
    assert!(!staging_due(&received, 2));
    let mut widened = sent_one.clone();
    apply(&mut widened, Action::Ack(2, 1, 2, 0), owned);
    assert!(
        widened.core.wants_grant(live.id),
        "a wider grant commands the next read"
    );
    assert_ne!(canonical(&received), canonical(&widened));
}

/// A valid ACK may report fragments held above its receipt, which names the
/// fragments between as holes; the alphabet offers every mask over the sent
/// fragments above the receipt, and a mask that names a hole spends a fault,
/// since the hole stands for a lost frame.
#[test]
fn a_selective_receipt_names_a_hole_and_spends_a_fault() {
    let both_sent = scripted(&[
        Action::Advance,
        Action::Get(0),
        Action::Chunk(0),
        Action::Chunk(0),
        Action::Poll,
    ]);
    let live = both_sent.world.live[0].expect("a live GET");
    assert_eq!((live.sent, live.grant), (2, 2));
    let acks: Vec<Action> = enabled(&both_sent)
        .into_iter()
        .filter(|action| matches!(action, Action::Ack(..)))
        .collect();
    assert_eq!(
        acks,
        [
            Action::Ack(0, 0, 2, 0),
            Action::Ack(0, 0, 2, 1),
            Action::Ack(0, 1, 2, 0),
            Action::Ack(0, 2, 2, 0),
        ]
    );
    let mut holed = both_sent.clone();
    apply(&mut holed, Action::Ack(0, 0, 2, 1), owned);
    assert_eq!(holed.core.report().stale_acks, 0, "the core accepted it");
    assert_eq!(holed.budgets.faults, both_sent.budgets.faults - 1);
    apply(&mut holed, Action::Poll, owned);
    assert!(
        holed
            .world
            .last_poll
            .iter()
            .any(|&(_, kind, _, index)| kind == Kind::Data && index == 0),
        "fragment 0 resends as the hole: {:?}",
        holed.world.last_poll
    );
    assert_eq!(holed.core.report().hole_resends, 1);
    let mut spent = both_sent.clone();
    spent.budgets.faults = 0;
    assert!(
        !enabled(&spent).contains(&Action::Ack(0, 0, 2, 1)),
        "a spent fault budget offers no hole"
    );
}

/// One all-approving drain completes the alphabet: a drain that approves
/// only some of the ended GETs reaches the state that ending those GETs,
/// draining and then ending the rest reaches, and a drain that approves
/// none changes nothing.
#[test]
fn a_partial_drain_reaches_a_state_ordered_drains_reach() {
    let both_ended = scripted(&[
        Action::Get(0),
        Action::Chunk(0),
        Action::Return(0, 0),
        Action::Get(2),
        Action::Cancel(0),
        Action::Cancel(2),
    ]);
    let first = both_ended.world.live[0].expect("a live GET").id;
    let mut partial = both_ended.clone();
    partial.core.release_drained(|id| id == first);
    partial.world.live[0] = None;
    let ordered = scripted(&[
        Action::Get(0),
        Action::Chunk(0),
        Action::Return(0, 0),
        Action::Get(2),
        Action::Cancel(0),
        Action::Drain,
        Action::Cancel(2),
    ]);
    assert_eq!(canonical(&partial), canonical(&ordered));
    let mut none = both_ended.clone();
    none.core.release_drained(|_| false);
    assert_eq!(canonical(&none), canonical(&both_ended));
}

/// A duplicate of a released GET replays the cached terminal that a
/// duplicate of the same GET replays once it ended and before it drained,
/// and the drain commutes with the replay, so the live GET's duplicate
/// reaches every post-release replay state.
#[test]
fn a_duplicate_before_the_drain_reaches_the_post_release_replay_state() {
    let released = scripted(&[Action::Get(0), Action::Cancel(0), Action::Drain]);
    let request = scripted(&[Action::Get(0)]).world.live[0]
        .expect("a live GET")
        .request;
    let mut replayed_after = released.clone();
    replayed_after
        .core
        .get(admitted(0), &request, replayed_after.world.now_us);
    let before = released.core.report();
    let after = replayed_after.core.report();
    assert_eq!(
        (after.replays, after.requests),
        (before.replays + 1, before.requests),
        "the core answers from its cached terminal and admits no new request"
    );
    // The released GET retains its terminal, so it owes the replay.
    replayed_after
        .world
        .owe(admitted(0).peer, request.request, 1);
    let mut replayed_before = scripted(&[
        Action::Get(0),
        Action::Cancel(0),
        Action::Duplicate(0),
        Action::Drain,
    ]);
    apply(&mut replayed_before, Action::Poll, owned);
    apply(&mut replayed_after, Action::Poll, owned);
    assert_eq!(canonical(&replayed_before), canonical(&replayed_after));
}

/// The pre-final-ACK search's distinct states, transitions and stack high
/// water.
const PREFINAL_ACK_TOTALS: (usize, u64, usize) = (74_174, 180_783, 87);

/// The completed-held search's distinct states, transitions and stack high
/// water.
const COMPLETED_HELD_TOTALS: (usize, u64, usize) = (32_630, 80_121, 72);

/// Runs seeded bound `bounds` unplanted and checks it exhausts at its depth
/// with `pinned` totals, observes every witness it names and earns credit.
fn seeded(bounds: Bounds, pinned: (usize, u64, usize)) {
    let report = run(bounds, owned, Sender::Takes, Plant::None);
    eprintln!("{}", report.line());
    assert_eq!(report.verdict, Verdict::Exhaustive, "{report:?}");
    assert_eq!(report.totals.alphabet, 12, "{report:?}");
    assert_eq!(report.totals.depth, bounds.depth, "{report:?}");
    let totals = &report.totals;
    assert_eq!(
        (totals.states, totals.transitions, totals.high_water),
        pinned,
        "{report:?}"
    );
    assert_eq!(
        report.witnessed,
        [RELEASE_WITNESS, COMPLETE_WITNESS],
        "{report:?}"
    );
    assert!(credited(Some(&report)));
}

/// The nightly seeded bound from the pre-final-ACK root: the final ACK and
/// a poll send COMPLETE while the device holds both chunks, and the device
/// returns and a drain release the GET.
#[test]
#[ignore = "nightly search bound; run with --ignored"]
fn the_prefinal_ack_search_exhausts_its_bound() {
    seeded(PREFINAL_ACK, PREFINAL_ACK_TOTALS);
}

/// The nightly seeded bound from the completed-held root: the device
/// returns and a drain release the completed GET, and an ACK and a poll
/// replay its COMPLETE.
#[test]
#[ignore = "nightly search bound; run with --ignored"]
fn the_completed_held_search_exhausts_its_bound() {
    seeded(COMPLETED_HELD, COMPLETED_HELD_TOTALS);
}

/// Each seeded root is the state its name declares, reached from a fresh
/// core by its prefix through the driver.
#[test]
fn the_seeded_roots_stand_in_their_named_states() {
    let prefinal = root(PREFINAL_ACK, owned, Sender::Takes, Plant::None);
    let live = prefinal.world.live[0].expect("a live GET");
    assert_eq!((live.sent, live.acked, live.read_ended), (2, 0, true));
    assert_eq!(prefinal.world.terminal(0), None);
    let held = root(COMPLETED_HELD, owned, Sender::Takes, Plant::None);
    assert_eq!(held.world.terminal(0), Some(Kind::Complete));
    assert_eq!(held.world.holds[0], 2, "the device holds both chunks");
    assert!(!Root::PrefinalAck.holds(&held) && !Root::CompletedHeld.holds(&prefinal));
}

/// A seeded bound short enough for the fast tier: depth 3 from the
/// pre-final-ACK root, which reaches COMPLETE and, under each terminal
/// plant, the frame or release the plant breaks.
const CONTROL: Bounds = Bounds {
    name: "serve-search-terminal-control",
    depth: 3,
    ..PREFINAL_ACK
};

/// Controls: a core that stages COMPLETE ahead of each DATA frame, one
/// that stages every terminal frame twice, one that releases an ended GET
/// while the device holds its chunks, one that sends ERROR in place of
/// COMPLETE, and one whose COMPLETE carries another allocation each fail
/// the terminal monitor with a path that, replayed, breaks that plant's
/// own rule, while the same bound unplanted exhausts and sends COMPLETE.
#[test]
fn a_premature_complete_a_duplicate_terminal_a_held_release_a_wrong_kind_and_a_wrong_manifest_fail_the_terminal_monitor()
 {
    let clean = run(CONTROL, owned, Sender::Takes, Plant::None);
    assert_eq!(clean.verdict, Verdict::Exhaustive, "{clean:?}");
    assert_eq!(clean.witnessed, [COMPLETE_WITNESS], "{clean:?}");
    assert!(
        !credited(Some(&clean)),
        "a missing release witness earns no credit"
    );
    let early = |world: &World| world.broken.early > 0 && world.broken.data_after > 0;
    let repeated = |world: &World| world.broken.repeated > 0;
    let held = |world: &World| world.released_held > 0;
    let errored = |world: &World| world.broken.errored > 0;
    let mismatched = |world: &World| world.broken.mismatched > 0;
    for (plant, rule) in [
        (Plant::EarlyComplete, &early as &dyn Fn(&World) -> bool),
        (Plant::DoubleTerminal, &repeated),
        (Plant::HeldRelease, &held),
        (Plant::ErrorForComplete, &errored),
        (Plant::WrongManifest, &mismatched),
    ] {
        let report = run(CONTROL, owned, Sender::Takes, plant);
        let Verdict::Violation { obligation, path } = &report.verdict else {
            panic!("{plant:?}: {report:?}");
        };
        assert_eq!(*obligation, Obligation::Terminal, "{plant:?}: {path:?}");
        let mut state = root(CONTROL, owned, Sender::Takes, plant);
        for &action in path {
            apply(&mut state, action, owned);
        }
        assert!(
            rule(&state.world),
            "{plant:?} breaks its own rule: {:?}",
            state.world
        );
        assert!(!credited(Some(&report)));
    }
}

/// The terminal monitor permits one replay queued by the final ACK before
/// the drain releases the GET. The terminal monitor rejects a second replay
/// after the GET is released, and a replay whose manifest differs from the
/// settled COMPLETE's.
#[test]
fn a_duplicate_terminal_after_its_get_released_fails_the_terminal_monitor() {
    for (plant, repeated, completes_sent) in [
        (Plant::None, false, 1),
        (Plant::DoubleTerminal, true, 2),
        (Plant::ConflictingReplay, true, 1),
    ] {
        let mut state = root(COMPLETED_HELD, owned, Sender::Takes, plant);
        let id = state.world.live[0].expect("the seeded GET").id;
        let mut path = Vec::new();
        loop {
            let Some(at) = holds(&state.core.requests, id).next().map(|(at, _)| at) else {
                break;
            };
            path.push(Action::Return(0, at));
            apply(&mut state, Action::Return(0, at), owned);
        }
        for action in [Action::Ack(0, 2, 2, 0), Action::Drain, Action::Poll] {
            assert!(enabled(&state).contains(&action), "{action:?}");
            path.push(action);
            apply(&mut state, action, owned);
        }
        assert!(path.len() <= COMPLETED_HELD.depth as usize, "{path:?}");
        assert!(state.world.live[0].is_none(), "the drain released the GET");
        let completes = state.world.last_poll.iter();
        let completes = completes.filter(|&&(_, kind, ..)| kind == Kind::Complete);
        assert_eq!(completes.count(), completes_sent, "{plant:?}");
        assert_eq!(state.world.broken.repeated > 0, repeated, "{plant:?}");
        assert_eq!(
            monitor(&state, owned, Staging::Quiet),
            repeated.then_some(Obligation::Terminal),
            "{plant:?}: {:?}",
            state.world
        );
    }
}

/// A GET refused `RequestPressure` while both table slots are held settles
/// its request id: after the drain frees the slots, the same id is answered
/// with the refusal again and admits no read, so the queued refusal ERROR
/// is never sent for a live GET. The next generation on the slot admits.
#[test]
fn a_refused_get_is_not_admitted_on_a_retry_under_the_same_request_id() {
    let mut state = root(PREFINAL_ACK, owned, Sender::Takes, Plant::None);
    for action in [
        Action::Get(3),
        Action::Cancel(3),
        Action::Get(2),
        Action::Drain,
    ] {
        assert!(enabled(&state).contains(&action), "{action:?}");
        apply(&mut state, action, owned);
    }
    let slot = (2 % WIRE_SLOTS as usize) as u16;
    let refused = get(slot, 0, grant(2));
    let again = state.core.get(admitted(2), &refused, state.world.now_us);
    assert!(matches!(again, GetOutcome::Replayed), "{again:?}");
    assert!(state.world.live[2].is_none());
    apply(&mut state, Action::Get(2), owned);
    assert_eq!(
        state.world.live[2].map(|live| live.request.request),
        Some(get(slot, 1, grant(2)).request),
        "the retry takes the next generation"
    );
    apply(&mut state, Action::Poll, owned);
    assert_eq!(state.world.broken.unended, 0, "{:?}", state.world);
    assert_eq!(monitor(&state, owned, Staging::Quiet), None);
}

/// Controls for the unended and unterminated rules. A core that stages a
/// COMPLETE ahead of a live GET's DATA sends a terminal for a GET it has not
/// ended. A core that ends a GET at its COMPLETE and sends no frame for it
/// releases the GET with no terminal.
#[test]
fn an_unended_terminal_and_an_unterminated_release_fail_the_terminal_monitor() {
    let mut state = root(SHALLOW, owned, Sender::Takes, Plant::EarlyComplete);
    for action in [Action::Get(0), Action::Chunk(0), Action::Poll] {
        assert!(enabled(&state).contains(&action), "{action:?}");
        apply(&mut state, action, owned);
    }
    assert!(state.world.broken.unended > 0, "{:?}", state.world);
    assert_eq!(
        monitor(&state, owned, Staging::Quiet),
        Some(Obligation::Terminal)
    );

    let mut state = root(PREFINAL_ACK, owned, Sender::Takes, Plant::SilentComplete);
    let id = state.world.live[0].expect("the seeded GET").id;
    for action in [Action::Ack(0, 2, 2, 0), Action::Poll] {
        assert!(enabled(&state).contains(&action), "{action:?}");
        apply(&mut state, action, owned);
    }
    assert!(
        state.core.requests.get_is_ended(id),
        "the COMPLETE ended the GET"
    );
    assert!(
        state.world.last_poll.is_empty(),
        "{:?}",
        state.world.last_poll
    );
    loop {
        let Some(at) = holds(&state.core.requests, id).next().map(|(at, _)| at) else {
            break;
        };
        apply(&mut state, Action::Return(0, at), owned);
    }
    apply(&mut state, Action::Drain, owned);
    assert!(state.world.live[0].is_none(), "the drain released the GET");
    assert_eq!(state.world.vanished, 0, "{:?}", state.world);
    assert!(state.world.broken.unterminated > 0, "{:?}", state.world);
    assert_eq!(
        monitor(&state, owned, Staging::Quiet),
        Some(Obligation::Terminal)
    );
}

#[test]
fn a_kept_replay_after_dropped_refusals_is_owed() {
    let mut state = root(PREFINAL_ACK, owned, Sender::Takes, Plant::None);
    apply(&mut state, Action::Get(3), owned);
    for _ in 0..=CONFIG.replies {
        apply(&mut state, Action::Get(2), owned);
    }
    assert_eq!(state.core.report().dropped_replies, 1);
    for action in [
        Action::Cancel(3),
        Action::Poll,
        Action::Duplicate(3),
        Action::Poll,
    ] {
        assert!(enabled(&state).contains(&action), "{action:?}");
        apply(&mut state, action, owned);
    }
    assert_eq!(state.core.report().replays, 1);
    assert_eq!(
        state.world.last_poll.len(),
        1,
        "{:?}",
        state.world.last_poll
    );
    assert_eq!(state.world.broken, Broken::default(), "{:?}", state.world);
}

#[test]
fn data_after_a_terminal_settled_by_an_earlier_poll_fails_the_terminal_monitor() {
    let mut state = root(
        COMPLETED_HELD,
        owned,
        Sender::Takes,
        Plant::DataAfterTerminal,
    );
    assert_eq!(state.world.terminal(0), Some(Kind::Complete));
    for action in [Action::Duplicate(0), Action::Poll] {
        assert!(enabled(&state).contains(&action), "{action:?}");
        apply(&mut state, action, owned);
    }
    let kinds: Vec<Kind> = state
        .world
        .last_poll
        .iter()
        .map(|&(_, kind, ..)| kind)
        .collect();
    assert_eq!(kinds, [Kind::Data], "{:?}", state.world.last_poll);
    assert_eq!(state.world.broken.repeated, 0, "{:?}", state.world);
    assert!(state.world.broken.data_after > 0, "{:?}", state.world);
    assert_eq!(
        monitor(&state, owned, Staging::Quiet),
        Some(Obligation::Terminal)
    );
}

/// A seeded search that ends before its GET's final ACK reaches a poll
/// exhausts without a COMPLETE, reports the witnesses missing and earns no
/// credit.
#[test]
fn a_seeded_search_without_its_witnesses_earns_no_credit() {
    let short = Bounds {
        depth: 1,
        ..PREFINAL_ACK
    };
    let report = run(short, owned, Sender::Takes, Plant::None);
    assert_eq!(report.verdict, Verdict::Exhaustive);
    assert!(report.witnessed.is_empty(), "{report:?}");
    assert!(report.line().ends_with("witnesses: "), "{}", report.line());
    assert!(!credited(Some(&report)));
}

/// The pressed search's distinct states, transitions and stack high water.
const PRESSED_TOTALS: (usize, u64, usize) = (123_737, 343_388, 60);

/// The states the pressed search stores that a poll reached whose batch
/// replies filled while a request was due.
const PRESSED_ACTIVATIONS: u64 = 1000;
const _: () = assert!(PRESSED_ACTIVATIONS > 0, "a vacuous monitor earns nothing");

/// Runs [`PRESSED`] under `plant` and returns its report; a lookahead that
/// starves a due GET panics naming its lane, the length of the path to the
/// state and the path.
fn pressed(plant: Plant) -> Report {
    let report = run(PRESSED, owned, Sender::Takes, plant);
    if let Verdict::Violation {
        obligation: Obligation::Starved { lane },
        path,
    } = &report.verdict
    {
        let actions = path.len();
        panic!("lane {lane} starved under reply pressure after {actions} actions: {path:?}");
    }
    report
}

/// The reply-pressure bound exhausts with every monitor holding, a due
/// GET staging within [`PRESSED_BOUND`] polls while the other peer queues
/// refusals before each one, and stores states that a poll reached whose
/// batch replies filled while a request was due; the test prints that
/// count after the totals.
#[test]
#[ignore = "nightly search bound; run with --ignored"]
fn the_pressed_search_exhausts_its_bound() {
    let report = pressed(Plant::None);
    eprintln!(
        "{}: {:?} {:?} activations: {}",
        report.bound, report.verdict, report.totals, report.activations
    );
    assert_eq!(report.verdict, Verdict::Exhaustive, "{report:?}");
    assert_eq!(report.totals.alphabet, 9, "{report:?}");
    assert_eq!(report.totals.depth, PRESSED.depth, "{report:?}");
    let totals = &report.totals;
    assert_eq!(
        (totals.states, totals.transitions, totals.high_water),
        PRESSED_TOTALS,
        "{report:?}"
    );
    assert_eq!(report.activations, PRESSED_ACTIVATIONS, "{report:?}");
    assert!(credited(Some(&report)));
}

/// Control: a core that stages replies first at every poll the shaper
/// leaves unrefused, so a poll the refusals fill gives requests no turn,
/// starves a due GET under reply pressure.
#[test]
#[ignore = "nightly search bound; run with --ignored"]
#[should_panic(expected = "lane 3 starved under reply pressure after 7 actions")]
fn negative_control_replies_first_after_a_poll_replies_fill_starves_a_due_get() {
    pressed(Plant::RepliesFirst);
}

/// The pressed lookahead's worst case meets its bound at its last poll: a
/// duplicate of lane 1's GET after it sent its first fragment requeues its
/// START and that fragment, lane 0's fresh GET is ready beside it, and the
/// other peer's two refusals fill every replies-first poll, so lane 1's
/// second fragment stages at poll [`PRESSED_BOUND`], and the first poll is
/// one the refusals fill while both GETs are due. With replies staged
/// first at every poll neither GET stages, and the monitor names lane 0,
/// the first due lane it checks. A poll without refusals fills no batch
/// with replies.
#[test]
fn a_duplicated_get_under_reply_pressure_stages_its_due_fragment_at_the_bound() {
    let script = [
        Action::Get(1),
        Action::Chunk(1),
        Action::Chunk(1),
        Action::Get(0),
        Action::Poll,
        Action::Duplicate(1),
        Action::Chunk(0),
    ];
    let state = |plant| {
        let mut state = root(PRESSED, owned, Sender::Takes, plant);
        for action in script {
            apply(&mut state, action, owned);
        }
        state
    };
    assert_eq!(DUE_FRAMES as u32, MANIFEST.count() + 1);
    let fixed = state(Plant::None);
    assert!(staging_due(&fixed, 0) && staging_due(&fixed, 1));
    let mut pressed = fixed.clone();
    press(&mut pressed, admitted(1).peer, owned);
    let mut filled = pressed.clone();
    apply(&mut filled, Action::Poll, owned);
    assert!(
        saturated(&pressed, &filled, PRESSED_BATCH),
        "{:?}",
        filled.world.last_poll
    );
    let mut quiet = fixed.clone();
    apply(&mut quiet, Action::Poll, owned);
    assert!(
        !saturated(&fixed, &quiet, PRESSED_BATCH),
        "{:?}",
        quiet.world.last_poll
    );
    assert_eq!(fixed.world.live[1].map(|live| live.sent), Some(1));
    let at = staged_at(&fixed, 1, owned, Staging::Pressed, 4 * PRESSED_BOUND);
    assert_eq!(at, Some(PRESSED_BOUND));
    assert_eq!(monitor(&fixed, owned, Staging::Pressed), None);
    let planted = state(Plant::RepliesFirst);
    let at = staged_at(&planted, 1, owned, Staging::Pressed, 4 * PRESSED_BOUND);
    assert_eq!(at, None);
    assert_eq!(
        monitor(&planted, owned, Staging::Pressed),
        Some(Obligation::Starved { lane: 0 })
    );
}
