//! The test-owned turn controller. Each turn selects one canonical event
//! among the world's runnable set as a recorded choice and applies it as
//! one bounded production action on one actor; world time starts where the
//! world's actors stand and advances only when nothing is runnable, to the
//! earliest due event, never back and never past an event that falls due on
//! the way.
//!
//! The world owns its actors and reports what is runnable and when the next
//! event falls due; the controller owns the clock, the choice, the turn
//! record and the limits, and tells the world each time the clock moves. A
//! run ends `Halted` when its hook asks it to stop, polled at the top of
//! each step ahead of the goal and the limits, and `Done` when the world
//! reaches its goal, checked before every limit; the hook's `end` still
//! runs. A defect the world records before the first clock move or after a
//! turn ends the run `Defect` first. Every limit (total turns, turns at one
//! time, steps without progress) and a world with nothing runnable and
//! nothing due end it `Inconclusive` naming the limit; a step is a turn or
//! a clock move that leaves nothing runnable. A chooser refusal, or a due
//! time that does not move the clock, ends it `Defect`. Progress is the
//! world's semantic count of observable results, such as new outcomes or
//! delivered bytes.

use std::cell::RefCell;

use super::action::Profile;
use super::choice::{Candidate, ChoiceError, Chooser, Site};
use super::entropy::DrawRefusal;
use super::recovery::{Record, embed};
use super::trace::{Event, TURN_OBSERVATION};

/// What the controller drives: actors, their runnable events and their
/// clocks.
pub(crate) trait World {
    /// The world's configuration as canonical bytes, recorded with the
    /// profile before the first turn.
    fn config(&self) -> Vec<u8>;

    /// The `recovery-cut-v1` record a recovery profile's world runs under,
    /// recorded after the profile record; a live world has none.
    fn recovery(&self) -> Option<Record> {
        None
    }

    /// The time the world's actors stand at before the first turn: the
    /// controller's clock starts there, so no actor sees time move back
    /// across the handoff.
    fn start(&self) -> u64;

    /// Moves passive state, such as link clocks, to `now`. The controller
    /// calls it once at the start time and once each time the clock moves.
    fn advance(&mut self, now: u64);

    /// The events runnable at `now`, as canonical candidates in their total
    /// order.
    fn runnable(&self, now: u64) -> Vec<Candidate>;

    /// The earliest time after `now` an event falls due, or `None` when only
    /// another event can make one runnable.
    fn next_due(&self, now: u64) -> Option<u64>;

    /// Applies `event` at `now` as one bounded action and returns its
    /// outcome, recorded with the turn. Any choice the action draws, such as
    /// a rekey's boot nonce or a link fault, comes from the run's chooser,
    /// which the controller releases before the action runs, so it lands on
    /// the run's tape.
    fn apply(&mut self, event: Candidate, now: u64) -> u64;

    /// What the world saw the last applied action collect, which the turn
    /// record carries beside its outcome, and forgets it: the controller
    /// takes it once after each [`apply`](Self::apply), so no turn carries
    /// another turn's observation. All zero when the action collected
    /// nothing; a world that observes nothing keeps the default.
    fn observation(&mut self) -> [u8; TURN_OBSERVATION] {
        [0; TURN_OBSERVATION]
    }

    /// The semantic progress count: it grows only with new observable
    /// results.
    fn progress(&self) -> u64;

    /// Whether the run reached its goal.
    fn done(&self) -> bool;

    /// The refusal the world recorded for a decision or entropy draw it made
    /// itself. The runner checks before the first turn and after each turn,
    /// and `Some` ends the run as [`End::Defect`].
    fn defect(&self) -> Option<Defect> {
        None
    }

    /// Appends to `out` the events the world produced since the last call,
    /// such as executed actions, audited link outcomes and its first
    /// failure. The controller calls it after each clock move and each turn,
    /// between actions.
    fn emit(&mut self, _out: &mut Vec<Event>) {}
}

/// What a run streams as it goes. The controller calls `enter` before each
/// clock move's world update and each turn's selection, `leave` once that
/// action returns, and the other methods only between actions.
pub(crate) trait Hook {
    /// The run's record and the choices recorded before the first turn.
    fn begin(&mut self, _record: &[u8], _choices: &[u8]) {}

    fn enter(&mut self) {}

    fn leave(&mut self) {}

    /// The clock moved to `now`: the choices recorded since the last call,
    /// and what the world emitted.
    fn clock(&mut self, _choices: &[u8], _now: u64, _events: &[Event]) {}

    /// A turn applied: the choices recorded since the last call, the turn,
    /// and what the world emitted.
    fn turn(&mut self, _choices: &[u8], _turn: &Turn, _events: &[Event]) {}

    /// A stopped boundary: the controller calls it after each `clock`,
    /// before the next turn's selection, with the run's chooser free to
    /// borrow.
    fn stopped(&mut self, _chooser: &RefCell<Chooser>) {}

    /// A turn's selection is next among `runnable`, with the run's chooser
    /// free to borrow; nothing ran since the last turn or stopped boundary.
    fn select(&mut self, _runnable: &[Candidate], _chooser: &RefCell<Chooser>) {}

    /// The run ended: the choices recorded since the last call.
    fn end(&mut self, _choices: &[u8]) {}

    /// Whether the run's report keeps every turn and its chooser keeps its
    /// whole tape. A hook that streams the run elsewhere answers `false`:
    /// the report then counts turns without keeping them, and a recording
    /// chooser releases each choice once the hook has seen it, so a
    /// recorded run of any length holds a bounded record. A replaying
    /// chooser keeps the tape it replays.
    fn retains(&self) -> bool {
        true
    }

    /// Whether the run must stop, polled at the top of every controller
    /// step after the first clock move, ahead of the goal and the limits:
    /// `true` ends the run [`End::Halted`], and the hook's `end` still runs.
    fn halted(&self) -> bool {
        false
    }
}

/// A run that streams nothing.
impl Hook for () {}

/// The controller's limits, each at least one, each ending a run
/// `Inconclusive` once it is reached: turns in all, turns at one time, or
/// steps since progress last grew, where a step is a turn or a clock move
/// that leaves nothing runnable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Limits {
    pub(crate) total: u64,
    pub(crate) same_time: u64,
    pub(crate) no_progress: u64,
}

impl Limits {
    /// Total, same-time and no-progress limits, little-endian.
    fn record(&self) -> [u8; 24] {
        let mut out = [0; 24];
        out[..8].copy_from_slice(&self.total.to_le_bytes());
        out[8..16].copy_from_slice(&self.same_time.to_le_bytes());
        out[16..].copy_from_slice(&self.no_progress.to_le_bytes());
        out
    }
}

/// The limit that stopped a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Limit {
    Total,
    SameTime,
    NoProgress,
    /// Nothing was runnable and nothing was due.
    Quiescent,
}

/// A run stopped by a harness bug rather than a property of the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Defect {
    /// The chooser refused a decision.
    Choice(ChoiceError),
    /// The chooser refused an entropy draw the world made.
    Entropy(DrawRefusal),
    /// The world named a due time at or before the current time while
    /// nothing was runnable.
    Due { now: u64, due: u64 },
}

impl Defect {
    /// The chooser's error behind a refused decision or entropy draw.
    pub(crate) fn choice(self) -> Option<ChoiceError> {
        match self {
            Self::Choice(error) | Self::Entropy(DrawRefusal { error, .. }) => Some(error),
            Self::Due { .. } => None,
        }
    }
}

/// How a run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum End {
    /// The world reached its goal.
    Done,
    /// A limit stopped the run first.
    Inconclusive(Limit),
    Defect(Defect),
    /// [`Hook::halted`] answered `true` at the top of the controller loop.
    Halted,
}

/// One applied turn: the time, the selected event, its outcome and the
/// world's [`observation`](World::observation) of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Turn {
    pub(crate) now: u64,
    pub(crate) event: Candidate,
    pub(crate) outcome: u64,
    pub(crate) observation: [u8; TURN_OBSERVATION],
}

/// A run's record. Checked work, the world's progress, the wall time the
/// turns took on the running thread, and virtual and skipped time are
/// separate fields; time never counts as work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Report {
    /// The profile's record, then a recovery world's `recovery-cut-v1`
    /// record prefixed by its `u32` little-endian length, then the world's
    /// configuration prefixed by its `u32` little-endian length, then the
    /// limits, all taken before the first turn.
    pub(crate) record: Vec<u8>,
    /// Every applied turn, kept when the hook [`retains`](Hook::retains).
    pub(crate) turns: Vec<Turn>,
    /// Turns applied, kept or not.
    pub(crate) turn_count: u64,
    pub(crate) end: End,
    pub(crate) progress: u64,
    /// Wall time spent applying turns.
    pub(crate) wall: std::time::Duration,
    /// World time at the end.
    pub(crate) virtual_us: u64,
    /// World time advanced while nothing was runnable.
    pub(crate) skipped_us: u64,
}

/// The record a run under `profile` over a world configured as `config`,
/// under `recovery`'s record when it has one, and bounded by `limits` takes
/// before its first turn.
pub(crate) fn record(
    profile: &Profile,
    recovery: Option<&Record>,
    config: &[u8],
    limits: Limits,
) -> Vec<u8> {
    let mut out = embed(profile.record(), recovery);
    out.extend((config.len() as u32).to_le_bytes());
    out.extend(config);
    out.extend(limits.record());
    out
}

/// Runs `world` under `profile` from the world's start time, selecting each
/// turn's event at `site` in `incarnation` of `chooser`, which the world's
/// actions share.
pub(crate) fn run(
    world: &mut impl World,
    profile: &Profile,
    chooser: &RefCell<Chooser>,
    choice: (Site, u32),
    limits: Limits,
) -> Report {
    run_hooked(world, profile, chooser, choice, limits, &mut ())
}

/// [`run`], streaming the run into `hook` between actions.
pub(crate) fn run_hooked(
    world: &mut impl World,
    profile: &Profile,
    chooser: &RefCell<Chooser>,
    (site, incarnation): (Site, u32),
    limits: Limits,
    hook: &mut impl Hook,
) -> Report {
    assert!(
        limits.total > 0 && limits.same_time > 0 && limits.no_progress > 0,
        "every limit is at least one turn: {limits:?}"
    );
    let record = record(profile, world.recovery().as_ref(), &world.config(), limits);
    let (mut now, mut skipped) = (world.start(), 0u64);
    let (mut same_time, mut idle) = (0u64, 0u64);
    // Whether the clock moved since the last applied turn.
    let mut moved = false;
    let mut turns = Vec::new();
    let mut turn_count = 0u64;
    let retains = hook.retains();
    let mut progress = world.progress();
    let mut wall = std::time::Duration::ZERO;
    let mut events = Vec::new();
    let mut seen = chooser.borrow().recorded().len();
    hook.begin(&record, &chooser.borrow().recorded()[..seen]);
    let end = 'run: {
        if let Some(defect) = world.defect() {
            break 'run End::Defect(defect);
        }
        hook_clock(world, (now, chooser, &mut seen), hook, &mut events);
        loop {
            if hook.halted() {
                break End::Halted;
            }
            if world.done() {
                break End::Done;
            }
            if turn_count == limits.total {
                break End::Inconclusive(Limit::Total);
            }
            if idle == limits.no_progress {
                break End::Inconclusive(Limit::NoProgress);
            }
            let runnable = world.runnable(now);
            if runnable.is_empty() {
                // A clock advance that leaves the world unfinished with no
                // runnable events consumes the no-progress budget before the
                // next advance.
                if moved {
                    idle += 1;
                    if idle == limits.no_progress {
                        break End::Inconclusive(Limit::NoProgress);
                    }
                }
                match world.next_due(now) {
                    Some(due) if due > now => {
                        skipped += due - now;
                        now = due;
                        same_time = 0;
                        moved = true;
                        hook_clock(world, (now, chooser, &mut seen), hook, &mut events);
                        continue;
                    }
                    Some(due) => break End::Defect(Defect::Due { now, due }),
                    None => break End::Inconclusive(Limit::Quiescent),
                }
            }
            moved = false;
            if same_time == limits.same_time {
                break End::Inconclusive(Limit::SameTime);
            }
            hook.select(&runnable, chooser);
            hook.enter();
            let selected = chooser.borrow_mut().index(site, incarnation, &runnable);
            let index = match selected {
                Ok(index) => index,
                Err(error) => {
                    hook.leave();
                    break End::Defect(Defect::Choice(error));
                }
            };
            let event = runnable[index];
            #[expect(
                clippy::disallowed_methods,
                reason = "the turn wall-time diagnostic stays outside decisions and the bundle digest"
            )]
            let started = std::time::Instant::now();
            let outcome = world.apply(event, now);
            wall += started.elapsed();
            hook.leave();
            let turn = Turn {
                now,
                event,
                outcome,
                observation: world.observation(),
            };
            turn_count += 1;
            if retains {
                turns.push(turn);
            }
            world.emit(&mut events);
            let tape = chooser.borrow();
            hook.turn(&tape.recorded()[seen..], &turn, &events);
            seen = tape.recorded().len();
            drop(tape);
            if !retains && chooser.borrow_mut().release() {
                seen = 0;
            }
            events.clear();
            if let Some(defect) = world.defect() {
                break End::Defect(defect);
            }
            same_time += 1;
            let reached = world.progress();
            if reached > progress {
                progress = reached;
                idle = 0;
            } else {
                idle += 1;
            }
        }
    };
    hook.end(&chooser.borrow().recorded()[seen..]);
    Report {
        record,
        turns,
        turn_count,
        end,
        progress: world.progress(),
        wall,
        virtual_us: now,
        skipped_us: skipped,
    }
}

/// Moves `world`'s clock to `now` as one action, then streams the choices
/// recorded since `seen`, the move and what the world emitted into `hook`,
/// then reports the stopped boundary to `hook`.
fn hook_clock(
    world: &mut impl World,
    (now, chooser, seen): (u64, &RefCell<Chooser>, &mut usize),
    hook: &mut impl Hook,
    events: &mut Vec<Event>,
) {
    hook.enter();
    world.advance(now);
    hook.leave();
    world.emit(events);
    let tape = chooser.borrow();
    hook.clock(&tape.recorded()[*seen..], now, events);
    *seen = tape.recorded().len();
    drop(tape);
    if !hook.retains() && chooser.borrow_mut().release() {
        *seen = 0;
    }
    events.clear();
    hook.stopped(chooser);
}
