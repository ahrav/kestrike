//! Composed rounds through the turn controller. A fixture that turns
//! several actors at one time, such as a link advance, a client poll, a
//! disk tick and an owner poll, names each as one action of a round, and
//! the controller selects every action as one recorded turn.
//!
//! The thread's schedule decides which actions are runnable at each turn.
//! `Legacy`, the default, offers only the next action in the order the
//! fixture listed, so a round repeats the fixture's fixed order exactly and
//! every assertion written against that order still holds. `Generated`
//! first runs the round's link advances in their listed order, as the
//! controller moves passive state before a turn, then offers every action
//! the round has not run, and a chooser seeded from the schedule's root
//! and the round's ordinal picks among them. Ordinals restart at each
//! [`with_schedule`], so one root repeats one test body's orders. Every
//! action runs exactly once per round under either schedule.

use std::cell::{Cell, RefCell};

use super::action::Profile;
use super::choice::{CANDIDATE_LEN, Candidate, Domain, Site};
use super::turn::{End, Limits, World, run};

/// The order a thread's rounds run their actions in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Schedule {
    /// The fixture's listed order.
    Legacy,
    /// Orders a chooser recorded from `root` picks, one per round.
    Generated { root: u64 },
}

thread_local! {
    static SCHEDULE: Cell<Schedule> = const { Cell::new(Schedule::Legacy) };
    static ROUNDS: Cell<u64> = const { Cell::new(0) };
    static CHOICES: Cell<u64> = const { Cell::new(0) };
}

/// Runs `body` with this thread's rounds under `schedule`, numbering them
/// from zero with an empty ordering-choice count, and restores the previous
/// schedule and counts after it returns or unwinds. Under test the thread's
/// fixture sessions restart, so `body` sees the sessions a standalone run sees.
pub(crate) fn with_schedule<R>(schedule: Schedule, body: impl FnOnce() -> R) -> R {
    struct Restore(Schedule, u64, u64);
    impl Drop for Restore {
        fn drop(&mut self) {
            SCHEDULE.with(|cell| cell.set(self.0));
            ROUNDS.with(|cell| cell.set(self.1));
            CHOICES.with(|cell| cell.set(self.2));
        }
    }
    let _restore = Restore(
        SCHEDULE.with(|cell| cell.replace(schedule)),
        ROUNDS.with(|cell| cell.replace(0)),
        CHOICES.with(|cell| cell.replace(0)),
    );
    #[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
    let _sessions = crate::storage::restart_sessions();
    body()
}

/// Runs `body` under this thread's current schedule with its round
/// ordinals restarted, so two runs a test compares take the same orders.
/// The rounds `body` runs still count toward [`rounds`] after it returns.
pub(crate) fn afresh<R>(body: impl FnOnce() -> R) -> R {
    struct Keep(u64);
    impl Drop for Keep {
        fn drop(&mut self) {
            ROUNDS.with(|cell| cell.set(self.0 + cell.get()));
        }
    }
    let _keep = Keep(ROUNDS.with(|cell| cell.replace(0)));
    body()
}

/// Whether this thread's rounds run in the fixture's listed order, so an
/// assertion on exact poll, tick or report counts holds.
pub(crate) fn legacy() -> bool {
    SCHEDULE.with(Cell::get) == Schedule::Legacy
}

/// How many rounds this thread ran under its innermost [`with_schedule`],
/// counting those run inside [`afresh`].
pub(crate) fn rounds() -> u64 {
    ROUNDS.with(Cell::get)
}

/// The turns a generated order may take to reach the outcome the listed
/// order reaches.
const GENERATED_TURNS: usize = 8;

fn repeat(mut turn: impl FnMut() -> bool) {
    for _ in 0..GENERATED_TURNS {
        if turn() {
            return;
        }
    }
}

/// Runs `turn` once under the legacy schedule. Under a generated schedule a
/// round may run its actions in another order, so `turn` runs until it
/// returns `true`, at most [`GENERATED_TURNS`] times; the caller then
/// asserts the outcome.
pub(crate) fn turn_until(mut turn: impl FnMut() -> bool) {
    if legacy() {
        turn();
    } else {
        repeat(turn);
    }
}

/// Returns at once under the legacy schedule. Under a generated schedule
/// `turn` runs until it returns `true`, at most [`GENERATED_TURNS`] times.
pub(crate) fn catch_up(turn: impl FnMut() -> bool) {
    if !legacy() {
        repeat(turn);
    }
}

/// Who an action turns. The kind and index name the action's candidate,
/// so two actions of one round name distinct actors or distinct steps of
/// one actor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Actor {
    /// A simulated link's clock advance.
    Link(u16),
    /// A client endpoint's poll.
    Client(u16),
    /// A simulated disk's tick.
    Disk(u16),
    /// An owner endpoint's poll.
    Owner(u16),
    /// A storage volume's poll.
    Volume(u16),
    /// A scripted owner double's turn.
    Double(u16),
    /// A test-side step the round orders with the actors, such as injecting
    /// a frame or bridging a mock port.
    Harness(u16),
}

impl Actor {
    fn code(self) -> (u8, u16) {
        match self {
            Self::Link(index) => (1, index),
            Self::Client(index) => (2, index),
            Self::Disk(index) => (3, index),
            Self::Owner(index) => (4, index),
            Self::Volume(index) => (5, index),
            Self::Double(index) => (6, index),
            Self::Harness(index) => (7, index),
        }
    }
}

/// One action of a round: its actor and the bounded production call that
/// turns it.
pub(crate) struct Act<'a> {
    actor: Actor,
    run: &'a mut dyn FnMut(),
}

impl<'a> Act<'a> {
    pub(crate) fn new(actor: Actor, run: &'a mut dyn FnMut()) -> Self {
        Self { actor, run }
    }
}

/// Appends one action per closure of `runs` to `acts`, the `i`th as
/// `actor(i)`, in `runs`' order.
pub(crate) fn push_each<'a, F: FnMut()>(
    acts: &mut Vec<Act<'a>>,
    actor: fn(u16) -> Actor,
    runs: &'a mut [F],
) {
    for (i, run) in runs.iter_mut().enumerate() {
        let index = u16::try_from(i).expect("a round names at most u16::MAX actors of a kind");
        acts.push(Act::new(actor(index), run));
    }
}

/// The round's decision site: the workload domain's actor zero.
const SITE: Site = Site {
    domain: Domain::Workload,
    actor: 0,
    site: 0,
};

/// One round's actions, each run once in the order the controller selects.
struct Round<'r, 'a> {
    acts: &'r mut [Act<'a>],
    ran: Vec<bool>,
    legacy: bool,
}

impl Round<'_, '_> {
    /// The candidate naming action `at`: its actor's kind and index and its
    /// position in the round, so one actor's steps stay distinct.
    fn candidate(&self, at: usize) -> Candidate {
        let (kind, index) = self.acts[at].actor.code();
        let mut bytes = [0; CANDIDATE_LEN];
        bytes[0] = kind;
        bytes[1..3].copy_from_slice(&index.to_le_bytes());
        bytes[3..5].copy_from_slice(&(at as u16).to_le_bytes());
        Candidate(bytes)
    }
}

impl World for Round<'_, '_> {
    fn config(&self) -> Vec<u8> {
        (0..self.acts.len())
            .flat_map(|at| self.candidate(at).0)
            .collect()
    }

    fn start(&self) -> u64 {
        0
    }

    fn advance(&mut self, _now: u64) {}

    fn runnable(&self, _now: u64) -> Vec<Candidate> {
        let unran = (0..self.acts.len()).filter(|&at| !self.ran[at]);
        // A link advance moves the link's clock to the round's time, so a
        // generated order runs the round's advances first, in their listed
        // order, as the controller moves passive state before a turn.
        let link = |at: &usize| matches!(self.acts[*at].actor, Actor::Link(_));
        let first = if self.legacy {
            unran.clone().next()
        } else {
            unran.clone().find(link)
        };
        if let Some(at) = first {
            return vec![self.candidate(at)];
        }
        let mut open: Vec<Candidate> = unran.map(|at| self.candidate(at)).collect();
        open.sort_unstable();
        open
    }

    fn next_due(&self, _now: u64) -> Option<u64> {
        None
    }

    fn apply(&mut self, event: Candidate, _now: u64) -> u64 {
        let at = usize::from(u16::from_le_bytes([event.0[3], event.0[4]]));
        self.ran[at] = true;
        (self.acts[at].run)();
        at as u64
    }

    fn progress(&self) -> u64 {
        self.ran.iter().filter(|&&ran| ran).count() as u64
    }

    fn done(&self) -> bool {
        self.ran.iter().all(|&ran| ran)
    }
}

/// Runs `acts` as one round: the controller selects each action as one
/// turn, under this thread's schedule.
///
/// # Panics
///
/// When the controller ends the round before every action ran, which only
/// a harness defect can cause.
pub(crate) fn round(acts: &mut [Act<'_>]) {
    if acts.is_empty() {
        return;
    }
    let ordinal = ROUNDS.with(|cell| cell.replace(cell.get() + 1));
    let (legacy, root) = match SCHEDULE.with(Cell::get) {
        Schedule::Legacy => (true, 0),
        Schedule::Generated { root } => (false, root ^ ordinal.rotate_left(32)),
    };
    // A generated order runs the link advances first, then offers every
    // other action at once, so the round chooses an order exactly when two
    // or more of its actions are not link advances.
    let unforced = |act: &&Act<'_>| !matches!(act.actor, Actor::Link(_));
    if !legacy && acts.iter().filter(unforced).nth(1).is_some() {
        CHOICES.with(|cell| cell.set(cell.get() + 1));
    }
    let len = acts.len() as u64;
    let mut world = Round {
        ran: vec![false; acts.len()],
        acts,
        legacy,
    };
    let profile = Profile {
        name: "round",
        declared: Vec::new(),
        root,
    };
    let mut recorder = profile.recorder(&[SITE]);
    let incarnation = recorder.launch(SITE.actor);
    let chooser = RefCell::new(recorder);
    let limits = Limits {
        total: len,
        same_time: len,
        no_progress: len + 1,
    };
    let report = run(&mut world, &profile, &chooser, (SITE, incarnation), limits);
    assert_eq!(report.end, End::Done, "a round runs every action once");
}

/// The roots a module's generated corpus runs under.
pub(crate) const ROOTS: [u64; 4] = [11, 23, 37, 41];

/// Runs test body `body`, named `name`, with this thread's rounds under the
/// generated schedule from `root`, naming both on stderr when it fails.
///
/// # Panics
///
/// When `body` panics or its rounds offer zero ordering choices.
pub(crate) fn generated(root: u64, name: &str, body: fn()) {
    let ran = std::panic::catch_unwind(|| {
        with_schedule(Schedule::Generated { root }, || {
            body();
            assert!(
                CHOICES.with(Cell::get) > 0,
                "{name} runs at least one round that chooses its order"
            );
        });
    });
    if let Err(panic) = ran {
        eprintln!(
            "{name} failed under the generated schedule from root {root}; rerun it as \
             with_schedule(Schedule::Generated {{ root: {root} }}, {name})"
        );
        std::panic::resume_unwind(panic);
    }
}

/// Declares test `$name`, which reruns each listed test of the module under
/// every root in [`ROOTS`]. A listed test keeps its outcome, custody and
/// byte assertions under every root; an assertion on exact poll, tick or
/// report counts runs only under the legacy schedule, behind [`legacy`].
macro_rules! generated_corpus {
    ($name:ident: $($test:ident),+ $(,)?) => {
        #[test]
        fn $name() {
            for root in $crate::sim::round::ROOTS {
                $($crate::sim::round::generated(root, stringify!($test), $test);)+
            }
        }
    };
}

pub(crate) use generated_corpus;
