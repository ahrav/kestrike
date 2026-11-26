//! Branching a recorded bundle at a verified milestone into forked
//! children, and judging what each child reports.
//!
//! A branch replays a bundle strictly from its tape. At every stopped
//! boundary it judges the milestone over the turns and events recorded up
//! to and including that boundary, so the predicate never reads an earlier
//! boundary's state and draws nothing. At the first boundary where the
//! predicate holds, the recorder writes its pending records to the sink and
//! the fork is admitted only at that stopped boundary of the one-threaded
//! worker. The prefix is then fixed: its semantic record count, its SHA-256
//! and the decisions made.
//!
//! The parent forks each suffix's children and goes on replaying, so its
//! bundle must still reproduce the original. The worker's branch form
//! forks one to [`MAX_SIBLINGS`] identical siblings of each suffix, one by
//! default. Each child re-baselines its allocation counters, switches its
//! chooser to the suffix's root with every decision identity and
//! occurrence counter continuing from the prefix, runs to its terminal,
//! writes its bundle and sends one framed report. A child whose run panics
//! reports the teardown audits its unwind ran and exits nonzero.
//!
//! The parent credits a child only from a success frame at exit 0 read to
//! end of file. A credited child must report the parent's prefix, keep only
//! its standard streams and report open, start its counted window at zero,
//! run its one teardown audit (a recovery or cluster child runs none),
//! write a bundle that loads to its reported digest and whose leading
//! semantic records hash to the prefix, and run to a bundle that counts
//! under [`ledger::counts`](crate::sim::ledger::counts). Its suffix is
//! judged from the upload state at the fork boundary, or from the state
//! before any upload when the boundary recorded none: an upload's
//! device-held sources may fall only after an uploader poll or a transmit
//! release on the uploader's link or, on links that release at delivery,
//! only after the owner's poll; its result may be decided only after an
//! outcome collection and never changes once decided; and its attempt may
//! advance only to the next one, once no source is held, through an
//! invocation of the first upload or of one after a publication, or a
//! retry of a decided, unpublished upload.
//! Siblings of one suffix must agree on digest, decisions and terminal. A
//! child whose host failed or killed it, whose bundle the parent cannot
//! read or load, or whose run ended in an infrastructure class, makes the
//! branch incomplete evidence rather than a judged result.
//! Without a fork, the same branch replays the prefix and diverges in
//! process, which is how library tests branch.

use std::cell::RefCell;
use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::sim::action::ActionKind;
use crate::sim::choice::{Chooser, Domain, EventKind};
use crate::sim::fork::{self, Boundary, Classified, Report, Spawned, Verdict};
use crate::sim::ledger::{armed, counts};
use crate::sim::trace::{
    Infrastructure, Outcome, PAYLOAD, RECORD, Recorder, Terminal, is_semantic, load,
};
use crate::sim::turn::Turn;

use super::super::observe::teardowns;
use super::CLIENT_POLL;
use super::bundle::{ACT, Stops, UPLOAD, UploadState, admit, run_stopping};
use super::replay::recorded;

/// The most suffixes the worker's branch form accepts.
pub(crate) const MAX_SUFFIXES: u32 = 16;

/// The most identical siblings per suffix the worker's branch form accepts.
/// Siblings of one suffix run the same tape, so any disagreement among them
/// is a problem.
pub(crate) const MAX_SIBLINGS: u32 = 4;

/// A predicate over a branch's facts at a stopped boundary: a fixed
/// milestone, or an instance of a milestone family carrying its parameter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Milestone {
    /// `pending-put`: an upload granted by the owner whose result is
    /// undecided while a device holds at least one of its source slots.
    PendingPut,
    /// `recovery-reached`: a recovery run's planned cut was reached and its
    /// Crash turn has not yet activated it.
    RecoveryReached,
    /// `turn-N`: at least N turns completed. The initial boundary precedes
    /// every turn, so `turn-0` holds there.
    Turn(u64),
    /// `script-N`: the scripted history's step N, counted from zero,
    /// returned an outcome other than `STAY`. A step that returns `STAY`
    /// runs again and has not completed; named witness marks play no part.
    Script(u32),
}

/// The milestones `--capabilities` lists: the fixed names, then the
/// family patterns, whose `N` stands for a canonical unsigned decimal.
pub(crate) const MILESTONES: [&str; 4] = ["pending-put", "recovery-reached", "turn-N", "script-N"];

impl Milestone {
    /// The milestone `name` names: a fixed name, `turn-N` with `N` a
    /// `u64`, or `script-N` with `N` a `u32`, each `N` in canonical
    /// decimal: ASCII digits with no sign, space or leading zero, `0`
    /// itself excepted, within the type's range.
    pub(crate) fn parse(name: &str) -> Option<Self> {
        fn canonical<T: std::str::FromStr + ToString>(digits: &str) -> Option<T> {
            let value: T = digits.parse().ok()?;
            (value.to_string() == digits).then_some(value)
        }
        match name {
            "pending-put" => Some(Self::PendingPut),
            "recovery-reached" => Some(Self::RecoveryReached),
            _ => match name.split_once('-')? {
                ("turn", digits) => canonical(digits).map(Self::Turn),
                ("script", digits) => canonical(digits).map(Self::Script),
                _ => None,
            },
        }
    }

    /// Whether the milestone holds over `facts`.
    pub(crate) fn holds(self, facts: &Facts) -> bool {
        match self {
            Self::PendingPut => facts.pending(),
            Self::RecoveryReached => facts.armed,
            Self::Turn(turns) => facts.turns >= turns,
            Self::Script(step) => facts.steps.is_some_and(|steps| steps > u64::from(step)),
        }
    }
}

/// The `witness:` line for milestone `name` over `facts`, the facts at
/// the boundary where a branch or exploration forked: whether the
/// milestone's predicate holds over them, which is `false` for a name no
/// milestone carries, then the boundary, the upload state (`none` when the
/// records so far hold none) and whether a planned recovery cut stands
/// reached and not yet activated.
pub(crate) fn witness(name: &str, facts: &Facts) -> String {
    let holds = Milestone::parse(name).is_some_and(|milestone| milestone.holds(facts));
    let upload = facts.upload.map_or_else(
        || "none".to_owned(),
        |state| {
            format!(
                "attempt:{},grant:{},held:{},outcome:{}",
                state.attempt, state.grant, state.held, state.outcome
            )
        },
    );
    format!(
        "witness: {name} holds={holds} boundary={} upload={upload} armed={}\n",
        facts.boundary, facts.armed
    )
}

/// The `milestone:` line for milestone `name` where a run `reached` it,
/// then its [`witness`] line: the two lines `--branch` and `--explore`
/// print alike.
pub(crate) fn milestone_lines(name: &str, reached: &Reached) -> String {
    format!(
        "milestone: {name} boundary={} semantic={} decisions={} prefix={}\n{}",
        reached.facts.boundary,
        reached.semantic,
        reached.decisions,
        hex(&reached.prefix),
        witness(name, &reached.facts),
    )
}

/// What the records so far say: the stopped boundaries passed, the
/// upload's latest state, whether a planned cut stands reached, and the
/// turns and scripted steps completed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Facts {
    /// Stopped boundaries reached, the current one included.
    pub(crate) boundary: u64,
    pub(crate) upload: Option<UploadState>,
    pub(crate) armed: bool,
    /// Turns applied.
    pub(crate) turns: u64,
    /// One past the index of the last SCRIPT step completed in a mixed
    /// run, the one world whose SCRIPT event runs a history's step, and
    /// zero before the first; `None` in any other world. Steps complete in
    /// index order, so step N has completed once this exceeds N.
    pub(crate) steps: Option<u64>,
    /// Whether the mixed run's links return a transmit's device references
    /// at delivery, in the owner's receive, rather than after a delay or a
    /// withheld release; `false` in any other world.
    pub(crate) at_delivery: bool,
}

impl Facts {
    /// The facts before a run's first record: none, with a step count of
    /// zero in a mixed run, under links that release at delivery or not.
    pub(super) fn starting(mixed: bool, at_delivery: bool) -> Self {
        Self {
            steps: mixed.then_some(0),
            at_delivery,
            ..Self::default()
        }
    }

    /// Takes the facts `events` carry: the latest upload state and whether
    /// a planned cut stands reached.
    pub(super) fn events(&mut self, events: &[crate::sim::trace::Event]) {
        if let Some(state) = events.iter().rev().find_map(UploadState::of) {
            self.upload = Some(state);
        }
        if let Some(armed) = armed(events) {
            self.armed = armed;
        }
    }

    /// Counts `turn`, and records the scripted step it completed, if any,
    /// by the step index its SCRIPT event carries. It reads the turn's
    /// candidate and outcome alone, so it draws nothing.
    pub(super) fn turned(&mut self, turn: &Turn) {
        self.turns += 1;
        if let Some(steps) = &mut self.steps
            && let Some(step) = super::completed_step(&turn.event, turn.outcome)
        {
            *steps = u64::from(step) + 1;
        }
    }

    /// Whether the run is a mixed one, whose one observer audits its end.
    pub(crate) fn mixed(&self) -> bool {
        self.steps.is_some()
    }

    /// Whether the upload is pending: granted by the owner, its result
    /// undecided, and a device holding at least one of its source slots.
    fn pending(&self) -> bool {
        self.upload.is_some_and(|state| {
            state.attempt > 0 && state.grant > 0 && state.held > 0 && state.outcome == 0
        })
    }
}

/// Where a run reached its milestone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Reached {
    pub(crate) facts: Facts,
    /// Semantic records of the prefix.
    pub(crate) semantic: u64,
    /// The SHA-256 of the prefix's semantic records.
    pub(crate) prefix: [u8; 32],
    pub(crate) decisions: u64,
}

/// What a forked child does besides its honest run, for the checks that
/// the parent credits only honest children.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ChildPlant {
    None,
    /// Panics at the child's first stopped boundary after the fork.
    Panic,
    /// Sleeps forever at the child's first stopped boundary after the fork.
    Hang,
}

/// What a branch does at its milestone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// Records where the milestone is, and nothing more.
    Probe,
    /// Diverges in process to this suffix.
    Diverge(u32),
    /// Forks `siblings` children per suffix, each bounded by `wait` from the
    /// first fork.
    Fork {
        suffixes: u32,
        siblings: u32,
        plant: ChildPlant,
        wait: Duration,
    },
}

/// A forked child's state inside its own process.
#[derive(Debug)]
struct Forked {
    suffix: u32,
    sibling: u32,
    plant: ChildPlant,
    report: Report,
    /// The child's own reading of its recorder's prefix after the fork.
    prefix: (u64, [u8; 32]),
    /// Teardown audits this thread had run when the child began.
    teardowns: u64,
    /// The child's open descriptors right after the fork, or why the host
    /// refused to list them.
    descriptors: Result<Vec<i32>, String>,
    /// The allocation count the child inherited, before its re-baseline.
    inherited: usize,
    /// The allocation count right after the re-baseline.
    baseline: usize,
}

/// The branch's state across the stopped boundaries of one run.
#[derive(Debug)]
struct Branch<'b> {
    milestone: Milestone,
    mode: Mode,
    root: u64,
    /// The bundle under replay, whose prefix the replay's has to equal at
    /// the milestone before any child is forked.
    original: &'b [u8],
    facts: Facts,
    reached: Option<Reached>,
    refused: Option<fork::Refusal>,
    /// The replay's records stopped matching the bundle's before any
    /// boundary held the milestone.
    diverged: bool,
    /// Children the parent forked: suffix, sibling and process.
    children: Vec<(u32, u32, fork::Child)>,
    /// The children's deadline, which `fork` sets on entry.
    deadline: Option<Instant>,
    /// Set in a forked child only.
    forked: Option<Forked>,
}

impl<'b> Branch<'b> {
    fn new(milestone: Milestone, mode: Mode, root: u64, original: &'b [u8], facts: Facts) -> Self {
        Self {
            milestone,
            mode,
            root,
            original,
            facts,
            reached: None,
            refused: None,
            diverged: false,
            children: Vec::new(),
            deadline: None,
            forked: None,
        }
    }

    /// Forks `siblings` children for each suffix; a child returns at once
    /// with its chooser switched to its suffix. A failed fork records a
    /// `Host` refusal and forks no more; the children already forked stay
    /// to be collected.
    fn fork<W: Write>(
        &mut self,
        (suffixes, siblings, plant, wait): (u32, u32, ChildPlant, Duration),
        recorder: &Recorder<W>,
        chooser: &RefCell<Chooser>,
    ) {
        #[expect(
            clippy::disallowed_methods,
            reason = "the child watchdog reads host time outside simulation decisions"
        )]
        let deadline = Instant::now() + wait;
        self.deadline = Some(deadline);
        for suffix in 0..suffixes {
            for sibling in 0..siblings {
                // SAFETY: the child forgets the reports of its earlier
                // siblings below, holds no other inherited descriptor owner,
                // and ends through `fork::exit` in `finish_child`, whose
                // panics `branch` catches into `fork::exit` as well.
                match unsafe { fork::spawn(deadline) } {
                    Ok(Spawned::Parent(child)) => self.children.push((suffix, sibling, child)),
                    Ok(Spawned::Child(report)) => {
                        std::mem::forget(std::mem::take(&mut self.children));
                        let inherited = crate::instrument::allocations();
                        crate::instrument::rebaseline();
                        let baseline = crate::instrument::allocations();
                        let descriptors = fork::descriptors();
                        chooser.borrow_mut().diverge(suffix_root(self.root, suffix));
                        self.forked = Some(Forked {
                            suffix,
                            sibling,
                            plant,
                            report,
                            prefix: recorder.prefix(),
                            teardowns: teardowns(),
                            descriptors,
                            inherited,
                            baseline,
                        });
                        return;
                    }
                    Err(error) => {
                        self.refused = Some(fork::Refusal::Host(error));
                        return;
                    }
                }
            }
        }
    }

    /// Where the run reached its milestone, or why the branch is refused.
    /// `reproduced` is whether the replay reproduced the bundle: a run that
    /// stopped reproducing it before any boundary held the milestone
    /// diverged, which says nothing about the bundle's own run.
    fn outcome(&self, reproduced: bool) -> Result<Reached, Unbranched> {
        outcome(self.reached, &self.refused, reproduced && !self.diverged)
    }
}

impl<W: Write> Stops<W> for &mut Branch<'_> {
    fn events(&mut self, events: &[crate::sim::trace::Event]) {
        self.facts.events(events);
    }

    fn turn(&mut self, turn: &Turn) {
        self.facts.turned(turn);
    }

    fn stopped(&mut self, recorder: &mut Recorder<W>, chooser: &RefCell<Chooser>) {
        self.facts.boundary += 1;
        if let Some(forked) = &self.forked {
            match forked.plant {
                ChildPlant::Panic => panic!("a planted panic in a forked child"),
                ChildPlant::Hang => loop {
                    #[expect(
                        clippy::disallowed_methods,
                        reason = "the watchdog fixture parks a forked child outside the simulated schedule"
                    )]
                    std::thread::sleep(Duration::from_secs(1));
                },
                ChildPlant::None => return,
            }
        }
        if self.reached.is_some() || self.refused.is_some() || self.diverged {
            return;
        }
        let holds = self.milestone.holds(&self.facts);
        if !holds {
            return;
        }
        recorder.flush();
        // The milestone's facts came from the replay's own records; the
        // children continue the bundle only if those records are the
        // bundle's.
        let (semantic, prefix) = recorder.prefix();
        if prefix_digest(self.original, semantic) != Some(prefix) {
            self.diverged = true;
            return;
        }
        // An in-process branch stays in its one process, so any thread
        // count admits it.
        if let Mode::Fork { .. } = self.mode {
            let boundary = Boundary {
                stopped: true,
                holds,
                flushed: recorder.flushed(),
            };
            if let Err(refusal) = fork::eligible(boundary) {
                self.refused = Some(refusal);
                return;
            }
        }
        self.reached = Some(Reached {
            facts: self.facts,
            semantic,
            prefix,
            decisions: chooser.borrow().decisions(),
        });
        match self.mode {
            Mode::Probe => {}
            Mode::Diverge(suffix) => chooser.borrow_mut().diverge(suffix_root(self.root, suffix)),
            Mode::Fork {
                suffixes,
                siblings,
                plant,
                wait,
            } => self.fork((suffixes, siblings, plant, wait), recorder, chooser),
        }
    }
}

/// The root suffix `suffix` of a run from `root` derives its decisions
/// from after the prefix.
pub(crate) fn suffix_root(root: u64, suffix: u32) -> u64 {
    let digest = Sha256::new()
        .chain_update(b"image-cache suffix v1")
        .chain_update(root.to_le_bytes())
        .chain_update(suffix.to_le_bytes())
        .finalize();
    u64::from_le_bytes(digest[..8].try_into().expect("eight bytes"))
}

/// Why a bundle cannot be branched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Unbranched {
    /// The bundle does not load or name a run, its recovery record is
    /// refused before the first turn, the milestone is unknown, or the
    /// suffix count is zero.
    Input(String),
    /// The run never reached a stopped boundary where the milestone holds,
    /// or the fork there was refused.
    Milestone(fork::Refusal),
    /// The prefix replay stopped reproducing the bundle before any boundary
    /// where the milestone holds, either by never reaching one or by
    /// reaching one over records the bundle does not hold, so the bundle's
    /// own run is unjudged.
    Diverged,
}

/// A branch's run: the replay's bundle and whether it reproduced the
/// original, or the unwind of a panic in it.
pub(super) type Ran = std::thread::Result<(Vec<u8>, bool)>;

/// A strict replay of `original` that `state` watches, made from the
/// named milestone, the recorded manifest and the facts before the run's
/// first record: the state and the run.
///
/// # Errors
///
/// `Input` when the bundle does not load or name a run, its recovery
/// record does not parse, a live profile's Config embeds one, or the
/// record differs from the one this executable derives for the bundle's
/// profile, or no milestone goes by `name`.
pub(super) fn replayed<S>(
    original: &[u8],
    name: &str,
    state: impl FnOnce(Milestone, &crate::sim::manifest::Manifest, Facts) -> S,
) -> Result<(S, Ran), Unbranched>
where
    for<'s> &'s mut S: Stops<Vec<u8>>,
{
    let (loaded, manifest) =
        recorded(original).map_err(|refused| Unbranched::Input(format!("{refused:?}")))?;
    let admitted = admit(&manifest).map_err(|refusal| Unbranched::Input(format!("{refusal:?}")))?;
    let milestone = Milestone::parse(name)
        .ok_or_else(|| Unbranched::Input(format!("no milestone is named {name}")))?;
    let mut state = state(
        milestone,
        &manifest,
        Facts::starting(admitted.live(), admitted.at_delivery()),
    );
    let chooser = admitted
        .replayer(&loaded)
        .map_err(|refused| Unbranched::Input(format!("{refused:?}")))?;
    let ran = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let (closed, _, finished, _) = run_stopping(admitted, Vec::new(), chooser, &mut state);
        let same = finished.is_ok()
            && closed.digest == loaded.digest
            && closed.work.decisions == loaded.decisions
            && closed.terminal == loaded.terminal;
        (closed.sink, same)
    }));
    Ok((state, ran))
}

/// A replay of `original` that branches with `mode`: the branch's state and
/// its run.
fn branched<'b>(
    original: &'b [u8],
    name: &str,
    mode: Mode,
) -> Result<(Branch<'b>, Ran), Unbranched> {
    replayed(original, name, |milestone, manifest, facts| {
        Branch::new(milestone, mode, manifest.root, original, facts)
    })
}

/// Where a run reached its milestone, or why a branch is refused there:
/// the refusal recorded, else the predicate that never held. `reproduced`
/// is whether the replay reproduced the bundle through the milestone: a run
/// that stopped reproducing it before any boundary held the milestone
/// diverged, which says nothing about the bundle's own run.
pub(super) fn outcome(
    reached: Option<Reached>,
    refused: &Option<fork::Refusal>,
    reproduced: bool,
) -> Result<Reached, Unbranched> {
    match (reached, refused) {
        (Some(reached), None) => Ok(reached),
        (None, None) if !reproduced => Err(Unbranched::Diverged),
        (_, refused) => Err(Unbranched::Milestone(
            refused.clone().unwrap_or(fork::Refusal::Predicate),
        )),
    }
}

/// Replays `original` to milestone `name` and diverges there in process
/// to `suffix`, when given: where the milestone stands and the bundle the
/// run recorded.
///
/// # Errors
///
/// As [`Unbranched`].
pub(crate) fn diverged(
    original: &[u8],
    name: &str,
    suffix: Option<u32>,
) -> Result<(Reached, Vec<u8>), Unbranched> {
    let mode = suffix.map_or(Mode::Probe, Mode::Diverge);
    let (branch, ran) = branched(original, name, mode)?;
    let (bytes, reproduced) = ran.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    Ok((branch.outcome(reproduced)?, bytes))
}

/// What a credited child reported.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ChildReport {
    pub(crate) prefix: [u8; 32],
    pub(crate) semantic: u64,
    pub(crate) digest: [u8; 32],
    pub(crate) decisions: u64,
    pub(crate) terminal: String,
    pub(crate) bundle: String,
    pub(crate) descriptors: Vec<i32>,
    pub(crate) inherited: usize,
    pub(crate) baseline: usize,
    pub(crate) teardowns: u64,
}

/// A report's fields, in the order the child writes them.
const FIELDS: [&str; 10] = [
    "prefix",
    "semantic",
    "digest",
    "decisions",
    "terminal",
    "bundle",
    "descriptors",
    "inherited",
    "baseline",
    "teardowns",
];

pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(super) fn unhex(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }
    let mut out = [0; 32];
    for (at, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(2 * at..2 * at + 2)?, 16).ok()?;
    }
    Some(out)
}

impl ChildReport {
    fn text(&self) -> String {
        let values = [
            hex(&self.prefix),
            self.semantic.to_string(),
            hex(&self.digest),
            self.decisions.to_string(),
            self.terminal.clone(),
            self.bundle.clone(),
            format!("{:?}", self.descriptors),
            self.inherited.to_string(),
            self.baseline.to_string(),
            self.teardowns.to_string(),
        ];
        FIELDS
            .iter()
            .zip(values)
            .map(|(field, value)| format!("{field}: {value}\n"))
            .collect()
    }

    /// The report `payload` spells, `None` unless it holds exactly the
    /// fields of [`FIELDS`] in order and each parses.
    fn parse(payload: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(payload).ok()?;
        let values: Vec<&str> = text
            .lines()
            .zip(FIELDS)
            .map(|(line, field)| line.strip_prefix(field)?.strip_prefix(": "))
            .collect::<Option<_>>()?;
        if values.len() != FIELDS.len() || text.lines().count() != FIELDS.len() {
            return None;
        }
        let listed = values[6].strip_prefix('[')?.strip_suffix(']')?;
        let descriptors = if listed.is_empty() {
            Vec::new()
        } else {
            listed
                .split(", ")
                .map(str::parse)
                .collect::<Result<_, _>>()
                .ok()?
        };
        Some(Self {
            prefix: unhex(values[0])?,
            semantic: values[1].parse().ok()?,
            digest: unhex(values[2])?,
            decisions: values[3].parse().ok()?,
            terminal: values[4].to_owned(),
            bundle: values[5].to_owned(),
            descriptors,
            inherited: values[7].parse().ok()?,
            baseline: values[8].parse().ok()?,
            teardowns: values[9].parse().ok()?,
        })
    }
}

/// A terminal as the worker prints it.
pub(crate) fn terminal_text(terminal: Terminal) -> String {
    match terminal {
        Terminal::Complete {
            outcome,
            fired,
            required,
        } => {
            let outcome = match outcome {
                Outcome::Pass => "pass",
                Outcome::Violation => "violation",
                Outcome::Inconclusive => "inconclusive",
                Outcome::Unsuccessful => "unsuccessful",
            };
            format!("complete {outcome} fired={fired:02x} required={required:02x}")
        }
        Terminal::Infrastructure(class) => {
            let class = match class {
                Infrastructure::Sink => "sink",
                Infrastructure::Cap => "cap",
                Infrastructure::Truncated => "truncated",
                Infrastructure::Defect => "defect",
            };
            format!("infrastructure {class}")
        }
    }
}

/// The problem a credited child gets when the parent's host cannot read
/// its bundle, which [`Branched::incomplete`] reads as incomplete evidence
/// for its suffix.
pub(super) const UNREAD: &str = "its bundle cannot be read";

/// The problem a credited child gets when the bundle the parent read fails
/// to load, so the bytes on disk differ from the ones the child loaded
/// before it reported; [`Branched::incomplete`] reads it as incomplete
/// evidence for its suffix.
pub(super) const UNLOADED: &str = "its bundle does not load";

/// The problem a credited child gets when its loaded bundle ends in an
/// infrastructure class, which [`Branched::incomplete`] reads as incomplete
/// evidence for its suffix whatever terminal the report claimed.
pub(super) const UNFINISHED: &str = "its run left incomplete evidence";

/// Ends a forked child: writes its bundle into `dir` and sends its report,
/// or, when its run panicked, sends the teardown audits the unwind ran. A
/// panic while it reports ends it with exit code 101 as well; a descriptor
/// list or a bundle the host refused ends it with [`fork::HOST_FAILED`].
fn finish_child(forked: Forked, ran: Ran, dir: &Path) -> ! {
    let Forked {
        suffix,
        sibling,
        mut report,
        prefix: (semantic, prefix),
        teardowns: before,
        descriptors,
        inherited,
        baseline,
        ..
    } = forked;
    let torn = teardowns() - before;
    let Ok((bytes, _)) = ran else {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let said = format!("panicked\nteardowns: {torn}\n");
            report.send(Verdict::Failure, said.as_bytes())
        }));
        fork::exit(101);
    };
    let code = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let descriptors = match descriptors {
            Ok(descriptors) => descriptors,
            Err(error) => {
                let reason = format!("descriptors: {error}\n");
                report.send(Verdict::Failure, reason.as_bytes());
                return fork::HOST_FAILED;
            }
        };
        let name = format!("suffix-{suffix}-{sibling}.bundle");
        let written = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.join(&name))
            .and_then(|mut file| file.write_all(&bytes).and_then(|()| file.flush()));
        match (written, load(&bytes, u64::MAX)) {
            (Ok(()), Ok(loaded)) => {
                let child = ChildReport {
                    prefix,
                    semantic,
                    digest: loaded.digest,
                    decisions: loaded.decisions,
                    terminal: terminal_text(loaded.terminal),
                    bundle: name,
                    descriptors,
                    inherited,
                    baseline,
                    teardowns: torn,
                };
                if report.send(Verdict::Success, child.text().as_bytes()) {
                    0
                } else {
                    101
                }
            }
            (written, loaded) => {
                let unwritten = written.is_err();
                let reason = format!("unwritten: {:?} {:?}\n", written.err(), loaded.err());
                report.send(Verdict::Failure, reason.as_bytes());
                if unwritten { fork::HOST_FAILED } else { 101 }
            }
        }
    }));
    fork::exit(code.unwrap_or(101));
}

/// One child as its parent judged it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Judged {
    pub(crate) suffix: u32,
    pub(crate) sibling: u32,
    pub(crate) class: Classified,
    /// The report a credited child sent.
    pub(crate) report: Option<ChildReport>,
    /// Every check the child failed; a credited child with none passes.
    pub(crate) problems: Vec<String>,
}

/// A branched bundle: its milestone, whether the parent's replay still
/// reproduced the original, and every child.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Branched {
    pub(crate) reached: Reached,
    pub(crate) parent: bool,
    pub(crate) children: Vec<Judged>,
}

impl Branched {
    /// Whether a child's suffix has no evidence either way: the parent lost
    /// its pipe or reap, the child could not set up its report, list its
    /// descriptors or write its bundle, something outside the branch killed
    /// it, the parent could not read or load that bundle, or the loaded
    /// bundle ended in an infrastructure class, the terminal the run form
    /// also reports as incomplete. `SIGKILL` is the outside kill: the
    /// branch's own kills end as `Watchdog` or `Lost` and the child's timer
    /// raises `SIGALRM`, so a `SIGKILL` death is the host's, such as the
    /// kernel's memory killer. The judge records the parent-side cases as
    /// problems, so the classification reads the bundle, never the report's
    /// claimed terminal.
    pub(crate) fn incomplete(&self) -> bool {
        self.children.iter().any(|child| {
            let host_failed = matches!(
                child.class,
                Classified::Lost(_)
                    | Classified::Silent(fork::SETUP_FAILED)
                    | Classified::Signaled(libc::SIGKILL)
                    | Classified::Failed {
                        code: fork::HOST_FAILED,
                        ..
                    }
            );
            host_failed
                || child.problems.iter().any(|problem| {
                    [UNREAD, UNLOADED, UNFINISHED]
                        .iter()
                        .any(|prefix| problem.starts_with(prefix))
                })
        })
    }

    /// Every failed check: each child's, then siblings that disagree and a
    /// parent that no longer reproduces. Children come suffix by suffix, as
    /// [`branch`] forks them.
    pub(crate) fn problems(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .children
            .iter()
            .flat_map(|child| {
                child.problems.iter().map(|problem| {
                    format!(
                        "suffix {} sibling {}: {problem}",
                        child.suffix, child.sibling
                    )
                })
            })
            .collect();
        for siblings in self.children.chunk_by(|a, b| a.suffix == b.suffix) {
            // A sibling without a report already names its own failure, so
            // only the reports present are compared.
            let outcomes: Vec<_> = siblings
                .iter()
                .filter_map(|child| child.report.as_ref())
                .map(|report| (report.digest, report.decisions, report.terminal.as_str()))
                .collect();
            if outcomes.windows(2).any(|pair| pair[0] != pair[1]) {
                out.push(format!(
                    "the siblings of suffix {} disagree",
                    siblings[0].suffix
                ));
            }
        }
        if !self.parent {
            out.push("the parent's replay no longer reproduces the bundle".into());
        }
        out
    }
}

/// The SHA-256 over the first `semantic` semantic records of `bytes`, or
/// `None` when it holds fewer.
pub(super) fn prefix_digest(bytes: &[u8], semantic: u64) -> Option<[u8; 32]> {
    let mut digest = Sha256::new();
    let mut taken = 0;
    for record in bytes.as_chunks::<RECORD>().0 {
        if taken == semantic {
            break;
        }
        if is_semantic(record[0]) {
            digest.update(record);
            taken += 1;
        }
    }
    (taken == semantic).then(|| digest.finalize().into())
}

// The bundle tags the custody check reads, as the trace module's record
// tags number them.
const TURN: u8 = 4;
const CLOCK: u8 = 5;
const EVENT: u8 = 6;

/// Whether a turn's event can return the uploader's device-held sources.
/// On links that release `at_delivery` it is the owner's poll, whose
/// receive delivers the datagrams. Otherwise it is the uploader's poll,
/// whose transport reclaim returns the references the link made
/// returnable, or a transmit release on the uploader's link, link 0. An
/// upload action stages or retires an upload and leaves every device
/// reference in place.
fn returns_sources(event: &[u8], at_delivery: bool) -> bool {
    let workload = event[0] == Domain::Workload as u8;
    if at_delivery {
        return workload && event[1] == super::OWNER_POLL;
    }
    let uploader_poll = workload && event[1] == CLIENT_POLL && event[2] == 0;
    let release =
        event[0] == Domain::Link as u8 && event[1] == EventKind::Release as u8 && event[2] == 0;
    uploader_poll || release
}

/// The custody faults of a child's suffix, the records of `bytes` past the
/// prefix's `semantic` records, judged from `start`, the upload state at
/// the fork boundary, or from the state before any upload when the
/// boundary recorded none, on links that release `at_delivery` or not:
/// device custody that falls with no event that returns sources in the
/// turn that recorded the fall, a result decided with no outcome
/// collection in that turn, and an attempt that changes other than to the
/// next one, begun in that turn by an invocation of the first upload or
/// of one after a published upload, or by a retry of a decided,
/// unpublished upload. A new attempt starts undecided.
pub(crate) fn custody(
    bytes: &[u8],
    semantic: u64,
    start: Option<UploadState>,
    at_delivery: bool,
) -> Vec<String> {
    let mut out = Vec::new();
    let published = UploadState::code(super::super::upload::UploadOutcome::Published);
    let (mut last, mut taken) = (start.unwrap_or_default(), 0);
    let (mut returned, mut collected) = (false, false);
    let (mut invoked, mut retried) = (false, false);
    let failed = |out: &mut Vec<String>, last: &UploadState, state: &UploadState| {
        out.push(format!(
            "attempt {} became {} with no retry or invocation its prior state allows",
            last.attempt, state.attempt
        ));
    };
    for record in bytes.as_chunks::<RECORD>().0 {
        if !is_semantic(record[0]) {
            continue;
        }
        taken += 1;
        if taken <= semantic {
            continue;
        }
        match (record[0], record[1]) {
            // Evidence lasts for the turn that supplied it: the world emits
            // the upload's state in that turn's event batch.
            (TURN, _) => {
                returned = returns_sources(&record[12..28], at_delivery);
                (collected, invoked, retried) = (false, false, false);
            }
            (CLOCK, _) => (returned, collected, invoked, retried) = (false, false, false, false),
            (EVENT, ACT) => {
                let outcome = u64::from_le_bytes(record[5..13].try_into().expect("an outcome"));
                let took = outcome != super::REFUSED;
                let (invoke, retry) = (
                    took && record[4] == ActionKind::PutInvoke as u8,
                    took && record[4] == ActionKind::Retry as u8,
                );
                // A collection before a new attempt begins is the old one's.
                collected = !(invoke || retry) && collected
                    || took && record[4] == ActionKind::PutOutcome as u8;
                (invoked, retried) = (invoked || invoke, retried || retry);
            }
            (EVENT, UPLOAD) => {
                let payload: [u8; PAYLOAD] = record[4..].try_into().expect("a payload");
                let Some(state) = UploadState::of(&crate::sim::trace::Event {
                    kind: UPLOAD,
                    payload,
                }) else {
                    continue;
                };
                // A taken start, a changed attempt or attempt zero, which
                // names no upload, needs the next attempt begun by an action
                // the prior state allows, once the device returned every
                // source the prior attempt held.
                let changed = state.attempt != last.attempt;
                let begun = last.attempt.checked_add(1) == Some(state.attempt)
                    && last.held == 0
                    && (invoked && (last.attempt == 0 || last.outcome == published)
                        || retried && last.outcome != 0 && last.outcome != published);
                if (changed || invoked || retried || state.attempt == 0) && !begun {
                    failed(&mut out, &last, &state);
                }
                if !changed && last.outcome != 0 && state.outcome != last.outcome {
                    out.push(format!(
                        "the upload's result changed from {} to {}",
                        last.outcome, state.outcome
                    ));
                }
                if state.held < last.held && !returned {
                    out.push(format!(
                        "device custody fell from {} to {} with nothing returning sources",
                        last.held, state.held
                    ));
                }
                let undecided = last.outcome == 0 || changed;
                if undecided && state.outcome != 0 && !collected {
                    out.push("the upload's result was decided with no outcome collection".into());
                }
                last = state;
                (returned, collected, invoked, retried) = (false, false, false, false);
            }
            _ => {}
        }
    }
    out
}

/// Judges one collected child against the branch's milestone, reading its
/// bundle from `dir`.
fn judge_child(
    suffix: u32,
    sibling: u32,
    class: Classified,
    reached: Reached,
    dir: &Path,
) -> Judged {
    let report = match &class {
        Classified::Success(payload) => ChildReport::parse(payload),
        _ => None,
    };
    let problems = match (&class, &report) {
        (Classified::Silent(fork::SETUP_FAILED), _) => {
            vec![
                "it could not set up its report, its descriptors or its parent-death signal".into(),
            ]
        }
        (Classified::Success(_), None) => vec!["its report does not parse".into()],
        (Classified::Success(_), Some(child)) => {
            report_problems(child, (suffix, sibling), reached, dir)
        }
        _ => vec![format!("{class:?} earns no credit")],
    };
    Judged {
        suffix,
        sibling,
        class,
        report,
        problems,
    }
}

/// The checks a credited child's report and bundle fail. The bundle judged
/// is the one named for `suffix` and `sibling`, as [`finish_child`] writes
/// it, whatever the report names. A bundle closed by an infrastructure
/// class is incomplete evidence for its suffix, as the run form treats the
/// same terminal, so it fails one; so does a complete bundle ending in a
/// violation, an inconclusive or unsuccessful run, or a pass with a required
/// obligation unfired.
fn report_problems(
    child: &ChildReport,
    (suffix, sibling): (u32, u32),
    reached: Reached,
    dir: &Path,
) -> Vec<String> {
    let mut problems = Vec::new();
    if (child.prefix, child.semantic) != (reached.prefix, reached.semantic) {
        problems.push("its prefix differs from the parent's".into());
    }
    let name = format!("suffix-{suffix}-{sibling}.bundle");
    if child.bundle != name {
        problems.push(format!("it reported bundle {} for {name}", child.bundle));
    }
    if child.descriptors != [0, 1, 2, fork::REPORT_FD] {
        problems.push(format!("it held descriptors {:?}", child.descriptors));
    }
    if child.inherited == 0 || child.baseline != 0 {
        problems.push(format!(
            "it inherited {} allocations and its counted window began at {}",
            child.inherited, child.baseline
        ));
    }
    let bytes = match std::fs::read(dir.join(&name)) {
        Ok(bytes) => bytes,
        Err(error) => {
            problems.push(format!("{UNREAD}: {error}"));
            return problems;
        }
    };
    // The mixed run's one observer drops at its end and audits the final
    // boundary, witnesses and oracle; a suffix that never ran that audit is
    // unjudged. A recovery run judges through its ledger and a cluster run
    // through its cells' final checks, and neither runs an observer. The
    // parent's admitted world decides which run the child continues.
    let loaded = load(&bytes, u64::MAX);
    if loaded.is_ok() && child.teardowns != u64::from(reached.facts.mixed()) {
        problems.push(format!("it ran {} teardown audits", child.teardowns));
    }
    match loaded {
        Ok(loaded) if (loaded.digest, loaded.decisions) == (child.digest, child.decisions) => {
            if terminal_text(loaded.terminal) != child.terminal {
                problems.push(format!(
                    "its bundle ends in {} and its report says {}",
                    terminal_text(loaded.terminal),
                    child.terminal
                ));
            }
            match loaded.terminal {
                Terminal::Infrastructure(_) => problems.push(format!(
                    "{UNFINISHED}: its bundle ends in {}",
                    terminal_text(loaded.terminal)
                )),
                terminal if !counts(&loaded) => problems.push(format!(
                    "its run ended in {}, which counts as no pass",
                    terminal_text(terminal)
                )),
                _ => {}
            }
        }
        Ok(loaded) => problems.push(format!(
            "its bundle loads as digest {} with {} decisions, against its report",
            hex(&loaded.digest),
            loaded.decisions
        )),
        Err(error) => problems.push(format!("{UNLOADED}: {error:?}")),
    }
    if prefix_digest(&bytes, reached.semantic) != Some(reached.prefix) {
        problems.push("its bundle does not start with the prefix".into());
    }
    let at_delivery = reached.facts.at_delivery;
    problems.extend(custody(
        &bytes,
        reached.semantic,
        reached.facts.upload,
        at_delivery,
    ));
    problems
}

/// Branches `original` at milestone `name` into `siblings` forked children
/// for each of `suffixes` suffixes, every child planted with `plant`, and
/// judges each child within `wait` of the first fork; each child writes
/// its bundle into `dir`. The parent kills and reaps every child before a
/// panic in its own run propagates, and collects every child before it
/// returns a refusal.
///
/// # Errors
///
/// As [`Unbranched`], for a refusal before the fork, a failed fork, a
/// milestone the run never reached, or a prefix replay that diverged before
/// reaching it.
pub(crate) fn branch(
    original: &[u8],
    name: &str,
    (suffixes, siblings): (u32, u32),
    dir: &Path,
    plant: ChildPlant,
    wait: Duration,
) -> Result<Branched, Unbranched> {
    if suffixes == 0 || siblings == 0 {
        return Err(Unbranched::Input(
            "a branch needs at least one suffix and one child of each".into(),
        ));
    }
    let mode = Mode::Fork {
        suffixes,
        siblings,
        plant,
        wait,
    };
    let (mut branch, ran) = branched(original, name, mode)?;
    if let Some(forked) = branch.forked.take() {
        finish_child(forked, ran, dir);
    }
    #[expect(
        clippy::disallowed_methods,
        reason = "the child watchdog reads host time outside simulation decisions"
    )]
    let deadline = branch.deadline.unwrap_or_else(Instant::now);
    let children = std::mem::take(&mut branch.children);
    let ran = match ran {
        Ok(ran) => ran,
        Err(panic) => {
            for (_, _, child) in children {
                #[expect(
                    clippy::disallowed_methods,
                    reason = "panic cleanup reaps the child against an immediate host deadline"
                )]
                fork::collect(child, Instant::now());
            }
            std::panic::resume_unwind(panic);
        }
    };
    // Every child is collected at once and reaped before any is judged,
    // so neither a sibling nor reading bundles spends a child's watchdog
    // time.
    let (named, processes): (Vec<_>, Vec<_>) = children
        .into_iter()
        .map(|(suffix, sibling, child)| ((suffix, sibling), child))
        .unzip();
    let collected: Vec<_> = named
        .into_iter()
        .zip(fork::collect_all(processes, deadline))
        .map(|((suffix, sibling), (class, _))| (suffix, sibling, class))
        .collect();
    let reached = branch.outcome(ran.1)?;
    let children = collected
        .into_iter()
        .map(|(suffix, sibling, class)| judge_child(suffix, sibling, class, reached, dir))
        .collect();
    Ok(Branched {
        reached,
        parent: ran.1,
        children,
    })
}

#[cfg(test)]
pub(crate) mod tests;
