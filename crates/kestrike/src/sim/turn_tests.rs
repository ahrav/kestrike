//! Controller tests over a scripted world of independent actors, each with
//! its own due times and a count of the turns it took: time advances only
//! when nothing is runnable, to the earliest due time, never past a due
//! actor; equal-time events run in orders the root selects; a stalled actor
//! leaves its peers advancing; every limit ends the run `Inconclusive`; and a
//! due time that does not move the clock ends it `Defect`.
//!
//! Rate scenarios pair a fast actor of period `P`, whose turns count as no
//! progress, with a slow actor whose one action at deadline `D` is the goal.
//! Limits stay step counts, and a clock move adds no step here because each
//! move lands on a due event that then runs. With `k` the events runnable
//! at `D`, a scenario sized `no_progress >= ceil(D / P) + k`,
//! `same_time >= k` and `total >= ceil(D / P) + k` ends `Done` at `D`; an
//! undersized one ends `Inconclusive` naming the limit with the
//! deadline pending; an actor re-armed at `now` ends at the same-time limit;
//! and aggregate progress that rises every turn reaches the total limit
//! while the per-actor counts name the starved actor.
//!
//! Against that rule, the mixed world in `net::world_tests` runs under
//! `total = 20_000`, `same_time = 400` and `no_progress = 5_000`. Its wake
//! sources: the owner every 1 ms (`MAINTAIN_REST_US`) while maintenance
//! rests, or at `now` after a maintenance call that was tried with more work
//! or refused; the disk service every 1 ms; link arrivals and returns every
//! 100 µs only while a datagram or a return is queued; a 5 ms deferral; the
//! 200 ms request deadline; a local object that lives to the next whole
//! second; a waiting history step's wake time; and each client's timers
//! while a request is in flight, GET and ACK retries 3 ms apart doubling up
//! to three times, a gap ACK 500 µs after a gap appears and 1 ms after the
//! last, upload retries 3 ms apart, bootstrap retries 5 ms apart, a refused
//! send's retry, and a client due at `now` while it has a frame to send.
//! - An idle world, with no request in flight, wakes twice per millisecond:
//!   2 000 non-progress turns within the expiry, below `no_progress`, so
//!   the rule holds there.
//! - A request in flight adds the client timers. Each timer re-arms at least
//!   500 µs after it fires, so `t` armed timers add at most `400 t` turns to
//!   the owner's and the service's 400 within the request deadline, and the
//!   rule holds while the two clients arm at most eleven timers between
//!   them; a client due at `now` repeats like the owner's re-arm, a count
//!   this derivation leaves unbounded.
//! - With traffic queued for the whole window, links add 2 000 instants within
//!   the request deadline and 10 000 within the expiry, each instant one or
//!   more turns. `no_progress` holds for either deadline only while queued
//!   traffic makes progress within 5 000 steps, and `total` holds for the
//!   expiry only while its 10 000 link instants and 2 000 owner and service
//!   turns average under 1.8 turns per link instant; the request deadline's
//!   2 400 instants in all leave room for about two turns per instant under
//!   `no_progress` and eight under `total`.
//! - The owner's re-arm at `now` repeats while maintenance keeps reporting
//!   more work or a refusal, a count the world does not bound, so
//!   `same_time = 400` is not derived; a run that spins past it ends
//!   `Inconclusive(SameTime)` rather than hiding the spin.

use std::cell::RefCell;

use super::action::{ActionKind, Profile};
use super::choice::{CANDIDATE_LEN, Candidate, ChoiceError, Chooser, Domain, Site};
use super::trace::Event;
use super::turn::{Defect, End, Hook, Limit, Limits, Turn, World, record, run, run_hooked};

const SITE: Site = Site {
    domain: Domain::Workload,
    actor: 0,
    site: 1,
};

const LIMITS: Limits = Limits {
    total: 1_000,
    same_time: 50,
    no_progress: 200,
};

fn profile(root: u64) -> Profile {
    Profile {
        name: "scripted",
        declared: vec![ActionKind::Get],
        root,
    }
}

/// Actors each due every `period` microseconds, taking `goal` turns to
/// finish; a stalled actor is never runnable.
struct Scripted {
    period: Vec<u64>,
    due: Vec<u64>,
    taken: Vec<u64>,
    goal: u64,
    stalled: Option<usize>,
    /// Every turn's time and actor, in order.
    log: Vec<(u64, usize)>,
    /// Whether progress counts turns; an idle world's turns count nothing.
    counts: bool,
    /// Whether the world can finish.
    finishes: bool,
    /// Every time the controller moved the clock to.
    advanced: Vec<u64>,
    /// A due time to report however far the clock is.
    stuck_due: Option<u64>,
    /// Below this clock bound, `next_due` reports the next microsecond as a
    /// clock-only step.
    phantom_until: Option<u64>,
    /// A refused draw to report once this many turns ran.
    defect_after: Option<usize>,
}

impl Scripted {
    fn new(period: &[u64], goal: u64) -> Self {
        Self {
            period: period.to_vec(),
            due: vec![0; period.len()],
            taken: vec![0; period.len()],
            goal,
            stalled: None,
            log: Vec::new(),
            counts: true,
            finishes: true,
            advanced: Vec::new(),
            stuck_due: None,
            phantom_until: None,
            defect_after: None,
        }
    }

    fn candidate(actor: usize) -> Candidate {
        let mut bytes = [0; CANDIDATE_LEN];
        bytes[0] = Domain::Workload as u8;
        bytes[1] = actor as u8;
        Candidate(bytes)
    }

    fn live(&self, actor: usize) -> bool {
        self.stalled != Some(actor) && self.taken[actor] < self.goal
    }
}

impl World for Scripted {
    fn config(&self) -> Vec<u8> {
        self.period
            .iter()
            .flat_map(|period| period.to_le_bytes())
            .collect()
    }

    fn start(&self) -> u64 {
        0
    }

    fn advance(&mut self, now: u64) {
        self.advanced.push(now);
    }

    fn runnable(&self, now: u64) -> Vec<Candidate> {
        (0..self.due.len())
            .filter(|&actor| self.live(actor) && self.due[actor] <= now)
            .map(Self::candidate)
            .collect()
    }

    fn next_due(&self, now: u64) -> Option<u64> {
        if self.stuck_due.is_some() {
            return self.stuck_due;
        }
        if let Some(until) = self.phantom_until {
            return (now < until).then_some(now + 1);
        }
        (0..self.due.len())
            .filter(|&actor| self.live(actor) && self.due[actor] > now)
            .map(|actor| self.due[actor])
            .min()
    }

    fn apply(&mut self, event: Candidate, now: u64) -> u64 {
        let actor = usize::from(event.0[1]);
        assert!(self.due[actor] <= now, "an actor ran before it was due");
        self.taken[actor] += 1;
        self.due[actor] = now + self.period[actor];
        self.log.push((now, actor));
        self.taken[actor]
    }

    fn progress(&self) -> u64 {
        if self.counts {
            self.taken.iter().sum()
        } else {
            0
        }
    }

    fn done(&self) -> bool {
        self.finishes
            && (0..self.due.len()).all(|actor| self.stalled == Some(actor) || !self.live(actor))
    }

    fn defect(&self) -> Option<Defect> {
        let after = self.defect_after?;
        (self.log.len() >= after).then_some(Defect::Choice(ChoiceError::Short))
    }
}

fn chooser(root: u64) -> (RefCell<Chooser>, u32) {
    let mut chooser = Chooser::record(root, &[SITE]);
    let incarnation = chooser.launch(SITE.actor);
    (RefCell::new(chooser), incarnation)
}

fn ran(world: &mut Scripted, root: u64, limits: Limits) -> End {
    let (chooser, incarnation) = chooser(root);
    run(world, &profile(root), &chooser, (SITE, incarnation), limits).end
}

/// Time advances only when nothing is runnable, to the earliest due
/// actor, so every due time of every actor is a turn's time, and the world
/// hears each move once; the skipped time is recorded apart from the turns,
/// and the profile, configuration and limits before them.
#[test]
fn time_advances_to_the_earliest_due_event_only_when_nothing_runs() {
    let mut world = Scripted::new(&[300, 700, 1_000], 4);
    let (chooser, incarnation) = chooser(7);
    let report = run(
        &mut world,
        &profile(7),
        &chooser,
        (SITE, incarnation),
        LIMITS,
    );
    assert_eq!(report.end, End::Done);
    assert_eq!(
        report.record,
        record(&profile(7), None, &world.config(), LIMITS)
    );
    let mut moves = world.log.iter().map(|&(at, _)| at).collect::<Vec<_>>();
    moves.dedup();
    assert_eq!(world.advanced, moves, "one move per distinct turn time");
    let times: Vec<u64> = report.turns.iter().map(|turn| turn.now).collect();
    assert!(times.windows(2).all(|pair| pair[0] <= pair[1]), "{times:?}");
    for (actor, period) in [(0usize, 300u64), (1, 700), (2, 1_000)] {
        let at: Vec<u64> = world
            .log
            .iter()
            .filter(|&&(_, who)| who == actor)
            .map(|&(at, _)| at)
            .collect();
        assert_eq!(
            at,
            (0..4).map(|k| k * period).collect::<Vec<_>>(),
            "actor {actor}"
        );
    }
    assert_eq!(report.virtual_us, 3_000);
    assert!(report.skipped_us > 0 && report.skipped_us <= report.virtual_us);
    assert_eq!(report.progress, 12);
}

/// Events runnable at one time run in the order the root selects: some
/// roots order the three time-zero turns differently, and one root replays
/// its order from its tape.
#[test]
fn equal_time_events_run_in_distinct_selected_orders() {
    let order = |root: u64| {
        let mut world = Scripted::new(&[500, 500, 500], 1);
        let (chooser, incarnation) = chooser(root);
        run(
            &mut world,
            &profile(root),
            &chooser,
            (SITE, incarnation),
            LIMITS,
        );
        let order: Vec<usize> = world.log.iter().map(|&(_, actor)| actor).collect();
        (order, chooser.into_inner().finish().unwrap())
    };
    let orders: Vec<Vec<usize>> = (1..=8).map(|root| order(root).0).collect();
    assert!(orders.iter().any(|o| *o != orders[0]), "{orders:?}");
    let (recorded, tape) = order(3);
    let mut world = Scripted::new(&[500, 500, 500], 1);
    let mut replay = Chooser::replay(&[SITE], tape);
    let incarnation = replay.launch(SITE.actor);
    let replay = RefCell::new(replay);
    run(
        &mut world,
        &profile(3),
        &replay,
        (SITE, incarnation),
        LIMITS,
    );
    let replayed: Vec<usize> = world.log.iter().map(|&(_, actor)| actor).collect();
    assert_eq!(replayed, recorded);
    replay.into_inner().finish().unwrap();
}

/// A stalled actor leaves its peers advancing to their goals.
#[test]
fn a_stalled_actor_leaves_its_peers_advancing() {
    let mut world = Scripted::new(&[100, 100], 5);
    world.stalled = Some(1);
    assert_eq!(ran(&mut world, 9, LIMITS), End::Done);
    assert_eq!(world.taken, [5, 0]);
}

/// Total, same-time and no-progress limits, and a world with nothing
/// runnable and nothing due, each end the run `Inconclusive` by name, never
/// `Done`; turns that make no semantic progress are not progress, and a due
/// time that does not move the clock is a defect.
#[test]
fn every_limit_ends_the_run_inconclusive() {
    let mut long = Scripted::new(&[10], 100);
    assert_eq!(
        ran(&mut long, 11, Limits { total: 5, ..LIMITS }),
        End::Inconclusive(Limit::Total)
    );
    let mut busy = Scripted::new(&[0], 100);
    assert_eq!(
        ran(
            &mut busy,
            11,
            Limits {
                same_time: 3,
                ..LIMITS
            }
        ),
        End::Inconclusive(Limit::SameTime)
    );
    let mut idle = Scripted::new(&[10], 100);
    idle.counts = false;
    assert_eq!(
        ran(
            &mut idle,
            11,
            Limits {
                no_progress: 4,
                ..LIMITS
            }
        ),
        End::Inconclusive(Limit::NoProgress)
    );
    let mut dead = Scripted::new(&[10, 10], 3);
    dead.stalled = Some(0);
    dead.finishes = false;
    assert_eq!(
        ran(&mut dead, 11, LIMITS),
        End::Inconclusive(Limit::Quiescent)
    );
    let mut stuck = Scripted::new(&[10, 10], 3);
    stuck.stalled = Some(0);
    stuck.finishes = false;
    stuck.stuck_due = Some(0);
    assert_eq!(
        ran(&mut stuck, 11, LIMITS),
        End::Defect(Defect::Due { now: 0, due: 0 }),
        "a due time that does not move the clock is a world defect"
    );
}

/// Clock moves that leave nothing runnable count toward the no-progress
/// limit, so a world whose due times never make an event runnable ends
/// `Inconclusive` once that limit is spent.
#[test]
fn clock_only_moves_end_at_the_no_progress_limit() {
    let mut phantom = Scripted::new(&[10], 1);
    phantom.stalled = Some(0);
    phantom.finishes = false;
    phantom.phantom_until = Some(1_000_000);
    let limits = Limits {
        no_progress: 4,
        ..LIMITS
    };
    assert_eq!(
        ran(&mut phantom, 11, limits),
        End::Inconclusive(Limit::NoProgress)
    );
    assert_eq!(phantom.advanced, [0, 1, 2, 3, 4]);
}

/// Completion takes precedence over the no-progress limit: a goal reached
/// on a turn that adds no progress ends the run `Done`.
#[test]
fn a_goal_reached_on_the_last_idle_turn_is_done() {
    let mut last = Scripted::new(&[10], 1);
    last.counts = false;
    let limits = Limits {
        no_progress: 1,
        ..LIMITS
    };
    assert_eq!(ran(&mut last, 11, limits), End::Done);
    assert_eq!(last.taken, [1]);
}

/// A draw an action makes and the chooser refuses ends the run as a choice
/// defect after the turn that drew it, keeping every turn so far.
#[test]
fn a_refused_draw_inside_a_turn_ends_the_run_a_defect() {
    let mut world = Scripted::new(&[10, 10], 100);
    world.defect_after = Some(3);
    let (chooser, incarnation) = chooser(5);
    let report = run(
        &mut world,
        &profile(5),
        &chooser,
        (SITE, incarnation),
        LIMITS,
    );
    assert_eq!(report.end, End::Defect(Defect::Choice(ChoiceError::Short)));
    assert_eq!(report.turns.len(), 3);
}

/// A hook that logs its calls and the choices it was handed.
#[derive(Default)]
struct Spy {
    calls: Vec<&'static str>,
    inside: bool,
    choices: Vec<u8>,
    /// A call other than `leave` arrived while an action ran.
    intruded: bool,
}

impl Spy {
    fn call(&mut self, name: &'static str) {
        self.intruded |= self.inside;
        self.calls.push(name);
    }
}

impl Hook for Spy {
    fn begin(&mut self, _record: &[u8], choices: &[u8]) {
        self.call("begin");
        self.choices.extend_from_slice(choices);
    }

    fn enter(&mut self) {
        self.call("enter");
        self.inside = true;
    }

    fn leave(&mut self) {
        self.inside = false;
        self.calls.push("leave");
    }

    fn clock(&mut self, choices: &[u8], _now: u64, _events: &[Event]) {
        self.call("clock");
        self.choices.extend_from_slice(choices);
    }

    fn turn(&mut self, choices: &[u8], _turn: &Turn, _events: &[Event]) {
        self.call("turn");
        self.choices.extend_from_slice(choices);
    }

    fn end(&mut self, choices: &[u8]) {
        self.call("end");
        self.choices.extend_from_slice(choices);
    }
}

/// The controller brackets each clock move's world update and each turn's
/// selection and action between `enter` and `leave`, on the refused-choice
/// path too, calls every other hook only between actions, and hands the
/// hook every recorded choice once, in tape order.
#[test]
fn the_hook_streams_between_actions_and_sees_every_choice_once() {
    let mut world = Scripted::new(&[300, 700], 3);
    let (chooser, incarnation) = chooser(9);
    let mut spy = Spy::default();
    let report = run_hooked(
        &mut world,
        &profile(9),
        &chooser,
        (SITE, incarnation),
        LIMITS,
        &mut spy,
    );
    assert_eq!(report.end, End::Done);
    assert!(!spy.intruded && !spy.inside);
    assert_eq!(spy.choices, chooser.borrow().recorded());
    assert_eq!(spy.calls.first(), Some(&"begin"));
    assert_eq!(spy.calls.last(), Some(&"end"));
    for pair in spy.calls.windows(2) {
        if pair[0] == "enter" {
            assert_eq!(pair[1], "leave");
        }
        if matches!(pair[1], "clock" | "turn") {
            assert_eq!(pair[0], "leave", "{:?}", spy.calls);
        }
    }
    let count = |name| spy.calls.iter().filter(|&&call| call == name).count();
    assert_eq!(count("turn"), report.turns.len());
    assert_eq!(count("clock"), world.advanced.len());
    assert_eq!(
        count("enter"),
        count("turn") + count("clock"),
        "every action is entered"
    );
    assert_eq!(count("leave"), count("enter"));
    let unregistered = RefCell::new(Chooser::record(9, &[]));
    let mut world = Scripted::new(&[300], 1);
    let mut spy = Spy::default();
    let report = run_hooked(
        &mut world,
        &profile(9),
        &unregistered,
        (SITE, 0),
        LIMITS,
        &mut spy,
    );
    assert!(matches!(report.end, End::Defect(Defect::Choice(_))));
    assert!(!spy.inside && !spy.intruded);
    assert_eq!(spy.calls[spy.calls.len() - 3..], ["enter", "leave", "end"]);
}

/// A spy that halts the run once it has seen `after` turns.
struct Halting {
    spy: Spy,
    after: usize,
}

impl Hook for Halting {
    fn enter(&mut self) {
        self.spy.enter();
    }

    fn leave(&mut self) {
        self.spy.leave();
    }

    fn turn(&mut self, choices: &[u8], turn: &Turn, events: &[Event]) {
        self.spy.turn(choices, turn, events);
    }

    fn end(&mut self, choices: &[u8]) {
        self.spy.end(choices);
    }

    fn halted(&self) -> bool {
        self.spy
            .calls
            .iter()
            .filter(|&&call| call == "turn")
            .count()
            >= self.after
    }
}

/// A hook that halts after `after` turns ends the run `Halted` before the
/// next turn, with exactly those turns applied, and still sees `end`.
#[test]
fn a_halted_hook_ends_the_run_before_the_next_turn() {
    for after in [0, 2] {
        let mut world = Scripted::new(&[300, 700], 3);
        let (chooser, incarnation) = chooser(9);
        let mut halting = Halting {
            spy: Spy::default(),
            after,
        };
        let report = run_hooked(
            &mut world,
            &profile(9),
            &chooser,
            (SITE, incarnation),
            LIMITS,
            &mut halting,
        );
        assert_eq!(report.end, End::Halted, "after {after}");
        assert_eq!(report.turns.len(), after);
        let calls = &halting.spy.calls;
        assert_eq!(calls.last(), Some(&"end"));
        assert_eq!(calls.iter().filter(|&&call| call == "turn").count(), after);
    }
}

/// A hook that streams the run without retaining it, noting at each turn
/// and clock move how many choices the chooser holds beside how many it
/// should hold: those handed over then, after the first clock move also
/// those `begin` handed over, which the controller releases with the
/// first clock move's.
struct Streamed<'c> {
    chooser: &'c RefCell<Chooser>,
    choices: Vec<u8>,
    held: Vec<(usize, usize)>,
    /// Choices `begin` handed over that no release dropped yet.
    owed: usize,
}

impl Streamed<'_> {
    fn note(&mut self, choices: &[u8]) {
        self.held.push((
            self.chooser.borrow().recorded().len(),
            self.owed + choices.len(),
        ));
        self.owed = 0;
        self.choices.extend_from_slice(choices);
    }
}

impl Hook for Streamed<'_> {
    fn begin(&mut self, _record: &[u8], choices: &[u8]) {
        self.owed = choices.len();
        self.choices.extend_from_slice(choices);
    }

    fn clock(&mut self, choices: &[u8], _now: u64, _events: &[Event]) {
        self.note(choices);
    }

    fn turn(&mut self, choices: &[u8], _turn: &Turn, _events: &[Event]) {
        self.note(choices);
    }

    fn end(&mut self, choices: &[u8]) {
        self.choices.extend_from_slice(choices);
    }

    fn retains(&self) -> bool {
        false
    }
}

/// A chooser of `root` that recorded one decision before its run, so the
/// run's `begin` callback hands that choice over.
fn decided_chooser(root: u64) -> (RefCell<Chooser>, u32) {
    let (chooser, incarnation) = chooser(root);
    let candidates = [Candidate([0; CANDIDATE_LEN]), Candidate([1; CANDIDATE_LEN])];
    chooser
        .borrow_mut()
        .index(SITE, incarnation, &candidates)
        .unwrap();
    assert!(!chooser.borrow().recorded().is_empty());
    (chooser, incarnation)
}

/// A run whose hook does not retain it streams the same choices as a
/// retained run, keeps no turns but counts them, and its recording
/// chooser holds at each turn and clock move only the choices handed over
/// then and those not yet released, so every earlier choice was released:
/// the choice recorded before the run is gone by the first turn.
#[test]
fn a_streaming_hook_releases_every_choice_it_saw() {
    let mut world = Scripted::new(&[300, 700], 3);
    let (retained, incarnation) = decided_chooser(9);
    let mut spy = Spy::default();
    let kept = run_hooked(
        &mut world,
        &profile(9),
        &retained,
        (SITE, incarnation),
        LIMITS,
        &mut spy,
    );
    let mut world = Scripted::new(&[300, 700], 3);
    let (released, incarnation) = decided_chooser(9);
    let mut streamed = Streamed {
        chooser: &released,
        choices: Vec::new(),
        held: Vec::new(),
        owed: 0,
    };
    let report = run_hooked(
        &mut world,
        &profile(9),
        &released,
        (SITE, incarnation),
        LIMITS,
        &mut streamed,
    );
    assert_eq!(report.end, kept.end);
    assert_eq!(streamed.choices, spy.choices);
    assert!(report.turns.is_empty());
    assert_eq!(report.turn_count, kept.turns.len() as u64);
    assert!(
        streamed.held.iter().any(|&(_, handed)| handed > 0),
        "{:?}",
        streamed.held
    );
    for &(held, handed) in &streamed.held {
        assert_eq!(held, handed, "{:?}", streamed.held);
    }
}

/// A world of one fast actor and one slow actor: the fast actor wakes every `period` microseconds, zero to re-arm at `now`, and its turns count as progress only when `fast_counts`; the slow actor's one action falls due at `deadline` and is the world's goal and its only progress otherwise.
struct Paced {
    period: u64,
    deadline: u64,
    fast_due: u64,
    fast_counts: bool,
    /// Turns each actor took that counted as its progress: fast, slow.
    progress: [u64; 2],
    fast_turns: u64,
    fired: bool,
}

const FAST: usize = 0;
const SLOW: usize = 1;

impl Paced {
    fn new(period: u64, deadline: u64, fast_counts: bool) -> Self {
        Self {
            period,
            deadline,
            fast_due: 0,
            fast_counts,
            progress: [0; 2],
            fast_turns: 0,
            fired: false,
        }
    }

    /// The slow actor's deadline while it has not fired.
    fn pending(&self) -> Option<u64> {
        (!self.fired).then_some(self.deadline)
    }

    /// The actors whose progress stayed at zero.
    fn starved(&self) -> Vec<usize> {
        (0..2).filter(|&actor| self.progress[actor] == 0).collect()
    }
}

impl World for Paced {
    fn config(&self) -> Vec<u8> {
        [self.period, self.deadline, u64::from(self.fast_counts)]
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect()
    }

    fn start(&self) -> u64 {
        0
    }

    fn advance(&mut self, _now: u64) {}

    fn runnable(&self, now: u64) -> Vec<Candidate> {
        let mut runnable = vec![];
        if self.fast_due <= now {
            runnable.push(Scripted::candidate(FAST));
        }
        if !self.fired && self.deadline <= now {
            runnable.push(Scripted::candidate(SLOW));
        }
        runnable
    }

    fn next_due(&self, now: u64) -> Option<u64> {
        [Some(self.fast_due), self.pending()]
            .into_iter()
            .flatten()
            .filter(|&due| due > now)
            .min()
    }

    fn apply(&mut self, event: Candidate, now: u64) -> u64 {
        if usize::from(event.0[1]) == FAST {
            self.fast_turns += 1;
            self.progress[FAST] += u64::from(self.fast_counts);
            self.fast_due = now + self.period;
        } else {
            assert!(self.deadline <= now, "the deadline fired early");
            self.fired = true;
            self.progress[SLOW] += 1;
        }
        self.fast_turns
    }

    fn progress(&self) -> u64 {
        self.progress.iter().sum()
    }

    fn done(&self) -> bool {
        self.fired
    }
}

/// What one scenario's run reported and its world held at the end: the
/// end, the turn count, virtual and skipped time, the world's `next_due` at
/// the end time, the pending deadline, each actor's progress, the fast
/// actor's turns and the actors whose progress stayed at zero.
#[derive(Debug)]
struct Witness {
    end: End,
    turns: usize,
    virtual_us: u64,
    skipped_us: u64,
    next_due: Option<u64>,
    pending: Option<u64>,
    progress: [u64; 2],
    fast_turns: u64,
    starved: Vec<usize>,
}

/// Runs `world` under `limits` at `root`, checks that the run's record ends
/// with the limits and that replaying the recorded tape reproduces the
/// record, every turn, the end and both times, and returns the witness.
fn paced(world: impl Fn() -> Paced, root: u64, limits: Limits) -> Witness {
    let mut recorded = world();
    let (chooser, incarnation) = chooser(root);
    let report = run(
        &mut recorded,
        &profile(root),
        &chooser,
        (SITE, incarnation),
        limits,
    );
    let tape = chooser.into_inner().finish().unwrap();
    let limit_bytes: Vec<u8> = [limits.total, limits.same_time, limits.no_progress]
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect();
    assert!(
        report.record.ends_with(&limit_bytes),
        "the limits are part of the run's identity"
    );
    let mut replayed = world();
    let mut replay = Chooser::replay(&[SITE], tape);
    let incarnation = replay.launch(SITE.actor);
    let replay = RefCell::new(replay);
    let again = run(
        &mut replayed,
        &profile(root),
        &replay,
        (SITE, incarnation),
        limits,
    );
    assert_eq!(
        (
            &again.record,
            &again.turns,
            again.end,
            again.virtual_us,
            again.skipped_us
        ),
        (
            &report.record,
            &report.turns,
            report.end,
            report.virtual_us,
            report.skipped_us
        ),
        "the tape replays the run"
    );
    replay.into_inner().finish().unwrap();
    Witness {
        end: report.end,
        turns: report.turns.len(),
        virtual_us: report.virtual_us,
        skipped_us: report.skipped_us,
        next_due: recorded.next_due(report.virtual_us),
        pending: recorded.pending(),
        progress: recorded.progress,
        fast_turns: recorded.fast_turns,
        starved: recorded.starved(),
    }
}

/// Roots the scenarios that share an instant run at, so both orders at `D` occur.
const ROOTS: [u64; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

/// The slow deadline `D` of the rate scenarios, and two fast periods: `P`
/// does not divide `D`, so the deadline is the only event runnable at `D`,
/// and `P_DIVIDING` does, so both actors are runnable at `D`.
const DEADLINE: u64 = 10_000;
const PERIOD: u64 = 300;
const P_DIVIDING: u64 = 250;

/// Limits sized from the rate ratio under the step semantics for a fast
/// period `period`. The fast actor takes `ceil(D / P)` non-progress turns
/// before `D`, no clock move counts as a step because each lands on a due
/// event that then runs,
/// and `k` events are runnable at `D`, two when `P` divides `D` and one
/// otherwise, so up to `k - 1` fast turns at `D` precede the deadline.
/// Hence `no_progress = ceil(D / P) + k`, one above the non-progress turns
/// before the deadline turn; `same_time = k`, the turns runnable at one
/// instant, a limit [`run`] checks before each turn and so admits; and
/// `total = ceil(D / P) + k`, every turn of the run, which ends `Done`
/// before the total limit is checked.
fn sized(period: u64) -> Limits {
    let before = DEADLINE.div_ceil(period);
    let at_deadline = 1 + u64::from(DEADLINE.is_multiple_of(period));
    Limits {
        total: before + at_deadline,
        same_time: at_deadline,
        no_progress: before + at_deadline,
    }
}

/// The run ends `Done` at `virtual_us == D`, every
/// microsecond of it skipped while nothing ran, with the slow actor's
/// deadline action its only progress; a failure names the end, the pending
/// deadline and the witness.
fn ends_done_at_the_deadline(witness: &Witness) {
    assert!(
        witness.end == End::Done
            && (witness.virtual_us, witness.skipped_us) == (DEADLINE, DEADLINE)
            && witness.progress == [0, 1],
        "ended {:?} with the deadline {:?} pending: {witness:?}",
        witness.end,
        witness.pending
    );
}

/// Limits sized from the rate ratio end the run `Done` at the deadline,
/// with the fast actor's turns before it, whether the deadline is alone at
/// `D` or shares it with a fast turn, at several roots.
#[test]
fn sized_limits_let_a_slow_deadline_fire_beside_a_fast_idle_actor() {
    for period in [PERIOD, P_DIVIDING] {
        let before = DEADLINE.div_ceil(period);
        let mut fast_turns = Vec::new();
        for root in ROOTS {
            let witness = paced(|| Paced::new(period, DEADLINE, false), root, sized(period));
            ends_done_at_the_deadline(&witness);
            assert_eq!(witness.turns as u64, witness.fast_turns + 1, "{witness:?}");
            assert_eq!(witness.pending, None);
            fast_turns.push(witness.fast_turns);
        }
        fast_turns.sort_unstable();
        fast_turns.dedup();
        // With both actors runnable at D, some roots run the fast turn first, the case the `k` term sizes.
        let orders: Vec<u64> = (before..before + sized(period).same_time).collect();
        assert_eq!(fast_turns, orders, "period {period}");
    }
}

/// The sized `no_progress` is the smallest that lets the deadline fire on
/// every schedule. For a period that does not divide `D`, one less ends the
/// run `Inconclusive(NoProgress)` on the last fast turn before `D`, with the
/// deadline next due; for one that divides `D`, one less ends it on the fast
/// turn at `D` at a root that runs the fast actor first there.
#[test]
fn one_below_the_sized_no_progress_limit_ends_on_the_last_fast_turn() {
    let dividing = Limits {
        no_progress: sized(P_DIVIDING).no_progress - 1,
        ..sized(P_DIVIDING)
    };
    let fast_first = ROOTS
        .map(|root| paced(|| Paced::new(P_DIVIDING, DEADLINE, false), root, dividing))
        .into_iter()
        .find(|witness| witness.end != End::Done)
        .expect("a root runs the fast actor first at D");
    assert_eq!(fast_first.end, End::Inconclusive(Limit::NoProgress));
    assert_eq!(
        (
            fast_first.turns as u64,
            fast_first.virtual_us,
            fast_first.pending
        ),
        (dividing.no_progress, DEADLINE, Some(DEADLINE)),
        "{fast_first:?}"
    );
    let limits = Limits {
        no_progress: sized(PERIOD).no_progress - 1,
        ..sized(PERIOD)
    };
    let witness = paced(|| Paced::new(PERIOD, DEADLINE, false), 3, limits);
    let last = (DEADLINE.div_ceil(PERIOD) - 1) * PERIOD;
    assert_eq!(witness.end, End::Inconclusive(Limit::NoProgress));
    assert_eq!(
        (witness.turns as u64, witness.virtual_us, witness.next_due),
        (limits.no_progress, last, Some(DEADLINE)),
        "{witness:?}"
    );
}

/// For a period that divides `D`, `same_time` one below the sized value
/// ends the run `Inconclusive(SameTime)` on the fast turn at `D` at a root
/// that runs the fast actor first there, the deadline still pending at
/// `now`.
#[test]
fn one_below_the_sized_same_time_limit_ends_on_the_fast_turn_at_the_deadline() {
    let limits = Limits {
        same_time: sized(P_DIVIDING).same_time - 1,
        ..sized(P_DIVIDING)
    };
    let fast_first = ROOTS
        .map(|root| paced(|| Paced::new(P_DIVIDING, DEADLINE, false), root, limits))
        .into_iter()
        .find(|witness| witness.end != End::Done)
        .expect("a root runs the fast actor first at D");
    assert_eq!(fast_first.end, End::Inconclusive(Limit::SameTime));
    assert_eq!(
        (
            fast_first.turns as u64,
            fast_first.virtual_us,
            fast_first.pending,
            fast_first.progress
        ),
        (
            DEADLINE.div_ceil(P_DIVIDING) + limits.same_time,
            DEADLINE,
            Some(DEADLINE),
            [0, 0]
        ),
        "{fast_first:?}"
    );
    assert_eq!(sized(PERIOD).same_time, 1);
}

/// The negative control: `no_progress = D / P / 2` ends the run
/// `Inconclusive(NoProgress)` after that many fast turns, the deadline
/// still pending, and fails [`ends_done_at_the_deadline`].
#[test]
#[should_panic(expected = "ended Inconclusive(NoProgress) with the deadline Some(10000) pending")]
fn negative_control_undersized_limits_end_inconclusive_with_the_deadline_pending() {
    let limits = Limits {
        no_progress: DEADLINE / PERIOD / 2,
        ..sized(PERIOD)
    };
    let witness = paced(|| Paced::new(PERIOD, DEADLINE, false), 3, limits);
    let last = (limits.no_progress - 1) * PERIOD;
    assert_eq!(witness.end, End::Inconclusive(Limit::NoProgress));
    assert_eq!(
        (witness.turns as u64, witness.virtual_us, witness.skipped_us),
        (limits.no_progress, last, last),
        "{witness:?}"
    );
    assert_eq!(witness.next_due, Some(last + PERIOD));
    assert_eq!(
        (witness.pending, witness.progress),
        (Some(DEADLINE), [0, 0])
    );
    ends_done_at_the_deadline(&witness);
}

/// A fast actor re-armed at `now` forever keeps the clock at zero, and
/// the controller names the spin `Inconclusive(SameTime)` with the deadline
/// never fired. The same-time limit binds because it is the smallest:
/// `no_progress` and `total` each sit one above it.
#[test]
fn an_actor_re_armed_at_now_forever_ends_inconclusive_at_the_same_time_limit() {
    let same_time = LIMITS.same_time;
    let limits = Limits {
        total: same_time + 1,
        same_time,
        no_progress: same_time + 1,
    };
    let witness = paced(|| Paced::new(0, DEADLINE, false), 5, limits);
    assert_eq!(
        witness.end,
        End::Inconclusive(Limit::SameTime),
        "{witness:?}"
    );
    assert_eq!((witness.virtual_us, witness.skipped_us), (0, 0));
    assert_eq!(witness.turns as u64, same_time);
    assert_eq!(
        (witness.pending, witness.progress[SLOW]),
        (Some(DEADLINE), 0)
    );
    assert_eq!(witness.next_due, Some(DEADLINE));
}

/// A fast actor whose every turn counts as progress, re-armed at `now`,
/// keeps the aggregate rising, so `no_progress` never binds, and with
/// `same_time` one above `total` the run reaches `Total`; only the
/// per-actor counts name the starved slow actor.
#[test]
fn aggregate_progress_rising_every_turn_hides_a_starved_actor_until_total() {
    let total = LIMITS.same_time;
    let limits = Limits {
        total,
        same_time: total + 1,
        no_progress: 1,
    };
    let witness = paced(|| Paced::new(0, DEADLINE, true), 7, limits);
    assert_eq!(witness.end, End::Inconclusive(Limit::Total), "{witness:?}");
    assert_eq!(witness.progress, [total, 0]);
    assert_eq!(witness.turns as u64, total);
    assert_eq!(
        (
            witness.virtual_us,
            witness.skipped_us,
            witness.next_due,
            witness.pending
        ),
        (0, 0, Some(DEADLINE), Some(DEADLINE))
    );
    assert_eq!(
        witness.starved,
        [SLOW],
        "the per-actor counts name the starved actor"
    );
}
