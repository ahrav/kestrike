//! The recovery world: the two-key workload's local fills over one shared
//! media handle, with every planned process-death cut applied as a
//! recorded Crash turn, the owner's death and relaunch through the
//! lifecycle as recorded turns, and a recovered lookup checked by the
//! oracle under the campaign's hypothesis.
//!
//! The world walks its planned cuts in table order, one incarnation each.
//! Each incarnation runs the workload from its first operation; after every
//! operation the world stops, so each cut's boundary is a stopped boundary.
//! At the planned cut's boundary the world emits `Reached` and holds the
//! target there, offering the Crash turn and a Hold turn that keeps it
//! pinned; the Crash turn draws the cut at the owner's persistence site,
//! the effect choice, before the owner dies. The Crash turn then applies
//! the cut: it takes the writes the device's capture shows accepted and not
//! delivered, checks them against the children the descriptor declares at
//! the cut's boundary, snapshots their submitted bytes and the media under
//! them, and realizes each child's prescribed landing on the dead queue by
//! executing the held writes in acceptance order, a whole landing as it
//! stands, none as a dropped command and a sector prefix as a torn write.
//! A process-death cut then drains the dead queue, and a controller-reset
//! cut resets it, dropping what stays queued. The media under each write is
//! read back and compared ([`measure`]), and the activation records the
//! measured landing, the class whose path ran and the drain beside the plan
//! for credit to compare. The bundle is then released, a Relaunch
//! turn starts the next incarnation cold
//! with its links under the manifest's link bounds and records the cut's
//! Restart row, and a Lookup turn reads every workload
//! key, each answer judged by the oracle as a recovered lookup after that
//! Restart: a hit or Missing is judged, an oracle violation fails the
//! check under the oracle's rule, and an answer the oracle cannot judge
//! leaves the check without a verdict. A cut whose relaunch would pass the
//! manifest's restart bound is skipped, which leaves the run inconclusive;
//! a lifecycle step that refuses ends it unsuccessful by name.
//!
//! While an incarnation lives, the conservation rule judges its storage's
//! tables after every turn and clock move, so it runs after every operation
//! and each Relaunch turn, on the new incarnation's tables, which each cold
//! relaunch starts fresh. A fault sets the run's failed rule to the rule's
//! text, which the run carries to its bundle as a violation of the
//! `Restart` obligation when it settles; an unreadable table ends the run
//! unsuccessful by the snapshot's reason. While no incarnation lives, from
//! a Crash turn to the next Relaunch, the rule is skipped.
//!
//! At each Crash snapshot, the write check compares writes accepted since scene
//! install, including delivered writes, with a prefix of the boundary's child
//! ranges in order. Capture overflow fails the check. The held-write match
//! requires the writes the capture shows as outstanding to match every child
//! range in order.

use std::cell::RefCell;
use std::rc::Rc;

use crate::oracle::{Hypothesis, KeyId, Label, Obligation, Outcome as Judged, Script, check};
use crate::sim::action::Profile;
use crate::sim::choice::{Admission, CANDIDATE_LEN, Candidate, ChoiceError, Chooser, Domain, Site};
use crate::sim::cut::{Boundary, Child, Class, Cut};
use crate::sim::ledger::{Activation, Checked, Entry, Evidence, event};
use crate::sim::recovery::{Record, Recovery};
use crate::sim::trace::Event;
use crate::sim::turn::{Hook, Limits, Report, World, run_hooked};
use crate::storage::device::sim::{Capture, Fault};
use crate::storage::owner_fixture::{CHUNK_LEN, QuiesceMode, SimControl, TestPlatform, reserve};
use crate::storage::{RecordConfig, WorkBudget, WritableFill};

use super::super::fetch::Outcome;
use super::super::link::LinkLimits;
use super::super::observe::{Lenses, Tables, tables};
use super::super::owner_tests::{key, payload};
use super::super::put_tests::Scene;
use super::super::restart::{Disposition, Fresh, Lifecycle, Manifest, Run, restart_scene_with};

/// The turn controller's site.
pub(crate) const TURN: Site = Site {
    domain: Domain::Workload,
    actor: 0,
    site: 1,
};

/// The owner's persistence site, where a Crash turn draws its cut.
pub(crate) const CRASH: Site = Site {
    domain: Domain::Persistence,
    actor: 1,
    site: 1,
};

/// The recovery world's decision sites.
pub(crate) fn sites() -> [Site; 2] {
    [TURN, CRASH]
}

mod measure;

use measure::{BLOCK, Held};

/// The key name each workload operation fills, of which the profile's
/// workload takes the first ones.
const KEYS: [u8; 2] = [10, 11];

/// The campaign's hypothesis: a process death followed by a cold relaunch,
/// whose recovered lookups claim nothing survived.
pub(crate) const HYPOTHESIS: Hypothesis = Hypothesis("process-death-cold-relaunch");

/// An answer that returns bytes before failing counts as a hit because
/// those bytes prefix a version served by the relaunched owner.
pub(crate) fn recovered_answer(outcome: Option<Outcome>, bytes: &[u8]) -> Option<Judged> {
    match outcome {
        Some(Outcome::Complete) => Some(Judged::Hit),
        Some(Outcome::Incomplete(_)) if !bytes.is_empty() => Some(Judged::Hit),
        Some(Outcome::Missing) if bytes.is_empty() => Some(Judged::Missing),
        _ => None,
    }
}

/// Manifest bounds for the recovery lifecycle, incarnation links, and turn
/// controller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Bounds {
    pub(crate) lifecycle: Manifest,
    pub(crate) link: LinkLimits,
    pub(crate) turns: Limits,
}

/// What the world does next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// The workload runs; `next` operations ran in this incarnation and
    /// the clock has moved since the last one when `stopped`.
    Work { next: usize, stopped: bool },
    /// The owner died at the cut; the next turn relaunches.
    Dead,
    /// The relaunched owner answers; the next turn looks every workload key
    /// up.
    Recovered,
    /// Every planned cut ran or was skipped, or [`Recovering::break_with`]
    /// ended the run.
    Finished,
}

/// The turn events the world offers, as canonical candidates: the workload
/// domain byte, a tag, and the operation's index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Turn {
    Fill(u8),
    Crash,
    /// The target stays pinned at its edge for one more turn.
    Hold,
    Relaunch,
    Lookup,
}

impl Turn {
    fn candidate(self) -> Candidate {
        let (tag, operation) = match self {
            Self::Fill(operation) => (1, operation),
            Self::Crash => (2, 0),
            Self::Relaunch => (3, 0),
            Self::Lookup => (4, 0),
            Self::Hold => (5, 0),
        };
        let mut bytes = [0; CANDIDATE_LEN];
        bytes[0] = Domain::Workload as u8;
        bytes[1] = tag;
        bytes[2] = operation;
        Candidate(bytes)
    }

    fn of(candidate: &Candidate) -> Option<Self> {
        let bytes = candidate.0;
        match (bytes[0] == Domain::Workload as u8, bytes[1]) {
            (true, 1) => Some(Self::Fill(bytes[2])),
            (true, 2) => Some(Self::Crash),
            (true, 3) => Some(Self::Relaunch),
            (true, 4) => Some(Self::Lookup),
            (true, 5) => Some(Self::Hold),
            _ => None,
        }
    }
}

/// What a run of the recovery world leaves: the controller's report, the
/// chooser to finish, the rule of the first failed check, the oracle's or
/// the conservation rule's, why
/// the first check without a verdict reached none, whether a check passed
/// the Restart obligation, whether a cut was skipped at the restart bound,
/// and the lifecycle step that refused or the conservation snapshot's
/// reason for reading nothing, when either ended the run. The write check keeps its diagnostics in memory.
pub(crate) struct Ran {
    /// The table index and reason for the first cut with an undeclared write or incomplete capture.
    pub(crate) write_gap: Option<(u32, measure::WriteGap)>,
    /// Cut index and inspected-write count for each write check with a complete capture.
    pub(crate) compared_writes: Vec<(u32, usize)>,
    pub(crate) report: Report,
    pub(crate) draws: Rc<RefCell<Chooser>>,
    pub(crate) failed: Option<&'static str>,
    pub(crate) inconclusive: Option<&'static str>,
    pub(crate) restarted: bool,
    pub(crate) skipped: bool,
    pub(crate) broken: Option<&'static str>,
    /// An owner incarnation still lived when the run ended.
    pub(crate) alive: bool,
    /// The leaked-unit plant reserved a unit.
    pub(crate) leaked: bool,
    /// Snapshots the conservation rule judged.
    pub(crate) conserved: u64,
}

struct Recovering<'r, 's, 'm> {
    first_ordinal: u64,
    write_gap: Option<(u32, measure::WriteGap)>,
    compared_writes: Vec<(u32, usize)>,
    scene: Option<Scene<'s, 'm>>,
    life: &'r mut Lifecycle<'s, 'm>,
    fresh: &'r mut Vec<Fresh<'s, 'm>>,
    fills: Vec<WritableFill<'s, 'm, TestPlatform>>,
    draws: Rc<RefCell<Chooser>>,
    admission: Admission,
    recovery: Recovery,
    table: Vec<Cut>,
    /// The planned cuts in table order, and how many the run took up.
    plan: Vec<u32>,
    at: usize,
    phase: Phase,
    /// The owner actor's incarnation at the persistence site.
    owner: u32,
    /// The lifecycle's restart bound.
    restarts: usize,
    link: LinkLimits,
    log: Vec<Event>,
    progress: u64,
    failed: Option<&'static str>,
    inconclusive: Option<&'static str>,
    restarted: bool,
    skipped: bool,
    broken: Option<&'static str>,
    /// The oracle rows of the cut under check: its Restart, once the
    /// relaunch recorded it, then its recovered lookups.
    rows: Option<Script>,
    /// The workload's keys and the bytes each fill writes.
    keys: &'static [u8],
    object: usize,
    plant: Plant,
    defect: Option<ChoiceError>,
    /// The conservation rule's reusable buffers.
    lenses: Lenses,
    /// The leaked-unit plant reserved a unit.
    leaked: bool,
}

impl<'s, 'm> Recovering<'_, 's, 'm> {
    /// The write check starts at the ordinal recorded here. The attach's
    /// RESET writes precede the bootstrap rebase; session opens and the initial
    /// fixture publication precede scene install.
    fn install(&mut self, scene: Scene<'s, 'm>) {
        for net in &scene.nets {
            net.borrow_mut().set_limits(self.link);
        }
        self.first_ordinal = scene.control.capture().accepted;
        self.scene = Some(scene);
    }

    /// The cut the run works toward.
    fn target(&self) -> Option<(u32, &Cut)> {
        let index = *self.plan.get(self.at)?;
        Some((index, &self.table[index as usize]))
    }

    /// The operation count at which the target's boundary stands.
    fn position(cut: &Cut) -> usize {
        cut.operation as usize + usize::from(cut.boundary == Boundary::After)
    }

    fn at_boundary(&self) -> bool {
        match (self.phase, self.target()) {
            (Phase::Work { next, stopped }, Some((_, cut))) => {
                stopped && next == Self::position(cut)
            }
            _ => false,
        }
    }

    /// Skips every remaining planned cut once a relaunch after its death
    /// would pass the restart bound.
    fn skip_past_bound(&mut self) {
        if (self.life.incarnation() as usize) < self.restarts {
            return;
        }
        while let Some((index, _)) = self.target() {
            self.log.push(event(index, &Entry::Skipped));
            self.skipped = true;
            self.at += 1;
        }
        self.phase = Phase::Finished;
    }

    fn fill(&mut self, operation: u8) -> u64 {
        if operation == 1 && self.plant == Plant::Unfilled {
            return 0;
        }
        let name = self.keys[usize::from(operation)];
        let scene = self.scene.as_mut().expect("a living scene");
        // Each incarnation seeds its fill from its own index, so its bytes
        // stay distinct from an earlier incarnation's write under the same
        // range; the measurement marks any block they share ambiguous.
        let seed = u64::from(name) | u64::from(self.life.incarnation()) << 8;
        let object = payload(self.object, seed);
        let Ok(mut fill) = reserve(scene.storage, &key(name), 0, object.len()) else {
            return 0;
        };
        let io = &mut WorkBudget::with_io(0, usize::MAX, usize::MAX);
        let mut taken = 0;
        while taken < object.len() {
            match scene.owner.receive_fill(&mut fill, &object[taken..], io) {
                Ok(0) | Err(_) => break,
                Ok(more) => taken += more,
            }
        }
        self.fills.push(fill);
        taken as u64
    }

    /// The Crash turn: draws the cut at the owner's persistence site, then
    /// checks accepted writes, kills the owner, applies the cut's landing to the held writes,
    /// drains the dead queue, measures the landing on the media and
    /// releases the bundle.
    fn crash(&mut self) -> u64 {
        let Some((index, cut)) = self.target() else {
            return 0;
        };
        let cut = cut.clone();
        let candidate = self.admission.candidate(index).expect("a planned cut");
        let drawn = self
            .draws
            .borrow_mut()
            .index(CRASH, self.owner, &[candidate]);
        if let Err(error) = drawn {
            self.defect = Some(error);
            return 0;
        }
        let scene = self.scene.take().expect("a living scene");
        let queue = scene.control.outstanding() as u16;
        let held = self.fills.len() as u16;
        let descriptor = self.recovery.descriptor();
        let point = descriptor
            .points
            .iter()
            .find(|point| point.identity() == (cut.operation, cut.site, cut.occurrence))
            .expect("each table cut belongs to a descriptor point");
        let mut children = point.children(cut.boundary).to_vec();
        if self.plant == Plant::Unmatched {
            for child in &mut children {
                child.lba = child.lba.wrapping_sub(1);
            }
        }
        let capture = scene.control.capture();
        let (inspected, gap) = measure::write_gap(&capture, self.first_ordinal, &children);
        if gap != Some(measure::WriteGap::Overflow) {
            self.compared_writes.push((index, inspected));
        }
        if let Some(gap) = gap {
            self.write_gap.get_or_insert((index, gap));
        }
        let writes = self.held(&scene.control, &capture, &children);
        if let (Some(writes), Plant::Indistinct) = (&writes, self.plant) {
            for write in writes {
                scene
                    .control
                    .write_device(write.start as usize, &write.before);
            }
        }
        if let Err((_, scene)) = self.life.die(scene) {
            self.scene = Some(*scene);
            return self.break_with("the lifecycle refused the owner's death");
        }
        let dead = self.life.dead().len() - 1;
        let control = self.life.dead()[dead].control().clone();
        for (write, &word) in writes.iter().flatten().zip(&cut.mask) {
            self.land(&control, write, word);
        }
        // A reset drops every command still queued; process death leaves
        // the controller live, so the drain posts every executed write.
        let reset = (cut.class == Class::ControllerReset) != (self.plant == Plant::Swapped);
        let (mode, class, frees) = if reset {
            (
                QuiesceMode::Reset,
                Class::ControllerReset,
                Disposition::Reset,
            )
        } else {
            (
                QuiesceMode::AllReturned,
                Class::ProcessDeath,
                Disposition::AllReturned,
            )
        };
        let disposed = self.life.dead_mut(dead).dispose(mode);
        let drained = disposed == Ok(frees) && control.pending() == 0;
        let (landing, evidence) = match &writes {
            Some(writes) => measure::observe(&control, writes),
            None => (Vec::new(), Evidence::Unmatched),
        };
        self.fills.clear();
        self.log.push(event(
            index,
            &Entry::Activated(Activation {
                landing,
                drained,
                held,
                class,
                queue,
                evidence,
            }),
        ));
        if disposed != Ok(frees) || self.life.release(dead).is_err() {
            return self.break_with("the dead queue did not drain and free its slot");
        }
        self.phase = Phase::Dead;
        u64::from(queue)
    }

    /// The writes `control`'s capture shows accepted and not delivered, in
    /// acceptance order, with the bytes each carries and the media under
    /// it, when each is still queued and their device ranges are the
    /// children the descriptor declares at the cut boundary; `None`
    /// otherwise. Under [`Plant::Indistinct`] each write's media before
    /// death is its submitted bytes.
    fn held(
        &self,
        control: &SimControl,
        capture: &Capture,
        children: &[Child],
    ) -> Option<Vec<Held>> {
        measure::matching_outstanding(&capture.events, children)?
            .into_iter()
            .map(|(token, device)| {
                let start = device.start();
                let submitted = control.submitted(token)?;
                let before = if self.plant == Plant::Indistinct {
                    submitted.clone()
                } else {
                    control.device(start as usize, device.byte_len() as usize)
                };
                Some(Held {
                    token,
                    start,
                    submitted,
                    before,
                })
            })
            .collect()
    }

    /// Realizes landing `word` on held `write` by executing it now, so the
    /// held writes execute in acceptance order: whole as it stands, none as
    /// a dropped command and a sector prefix as a torn write. Under
    /// [`Plant::Whole`] every write executes whole. A fault the device
    /// refuses leaves the write to execute whole, which the measurement
    /// then shows.
    fn land(&self, control: &SimControl, write: &Held, word: u64) {
        // A matched write spans 1 to 64 blocks, as its descriptor child does.
        let whole = u64::MAX >> (64 - write.submitted.len() / BLOCK);
        let fault = match word {
            _ if self.plant == Plant::Whole => None,
            word if word == whole => None,
            0 => Some(Fault::DropCommand),
            word => Some(Fault::TornWrite {
                sectors: word.trailing_ones(),
            }),
        };
        if let Some(fault) = fault {
            let _ = control.try_fault(write.token, fault);
        }
        control.execute(write.token);
        if self.plant == Plant::Stuck {
            let _ = control.try_hold(write.token);
        }
    }

    /// The Relaunch turn: starts the next incarnation cold over the shared
    /// media and launches the owner's next chooser incarnation with it.
    fn relaunch(&mut self, now: u64) -> u64 {
        if self.fresh.is_empty() {
            return self.break_with("no incarnation's resources remain for the relaunch");
        }
        let fresh = self.fresh.remove(0);
        match self.life.relaunch(fresh, now / 100) {
            Ok(scene) => self.install(scene),
            Err(_) => return self.break_with("the lifecycle refused the relaunch"),
        }
        let scene = self.scene.as_ref().expect("the relaunched scene");
        match self.plant {
            Plant::LeakedUnit => {
                self.leaked |= crate::storage::owner_fixture::leak_unit(scene.storage);
            }
            Plant::PoisonedPool => crate::storage::owner_fixture::poison_pool(scene.storage),
            _ => {}
        }
        self.owner = self.draws.borrow_mut().launch(CRASH.actor);
        debug_assert_eq!(
            self.owner,
            self.life.incarnation(),
            "one incarnation identity"
        );
        let (index, cut) = self.target().expect("a planned cut");
        let mut rows = Script::new();
        rows.restart(HYPOTHESIS, KeyId(self.keys[cut.operation as usize]));
        self.rows = Some(rows);
        self.log.push(event(index, &Entry::Recovered));
        self.phase = Phase::Recovered;
        1
    }

    /// Ends the run at a lifecycle step that refused, or at a conservation
    /// snapshot that could not read the tables: the run is unsuccessful by
    /// `rule`.
    fn break_with(&mut self, rule: &'static str) -> u64 {
        self.broken.get_or_insert(rule);
        self.phase = Phase::Finished;
        0
    }

    /// The Lookup turn: reads every workload key from the relaunched owner
    /// and judges each answer as a recovered lookup after the restart; the
    /// turn's outcome is the hits it saw.
    fn lookup(&mut self) -> u64 {
        let (index, _) = self.target().expect("a planned cut");
        let mut rows = self.rows.take().expect("the relaunch recorded its Restart");
        let mut hits = 0;
        let mut answered = true;
        for &name in self.keys {
            let scene = self.scene.as_mut().expect("a living scene");
            let (outcome, bytes) = scene.read(1, name, 0);
            let outcome = if self.plant == Plant::Revived {
                Some(Outcome::Complete)
            } else {
                outcome
            };
            let judged = recovered_answer(outcome, &bytes).map(|judged| {
                let label = (judged == Judged::Hit).then_some(Label(u64::from(name)));
                (judged, label)
            });
            match judged {
                Some((judged, label)) => {
                    hits += u64::from(judged == Judged::Hit);
                    rows.recovered_lookup(HYPOTHESIS, KeyId(name), judged, label);
                }
                None => answered = false,
            }
        }
        let verdict = check(&rows.finish());
        let passed = answered && verdict.satisfies(&[Obligation::Restart]);
        self.restarted |= passed;
        if !passed {
            match verdict.violated() {
                Some((_, rule)) => {
                    self.failed.get_or_insert(rule);
                }
                None => {
                    self.inconclusive.get_or_insert(if answered {
                        "the recovery check reached no verdict"
                    } else {
                        "the relaunched owner answered a recovered lookup with neither a hit nor Missing"
                    });
                }
            }
        }
        let checked = if passed { Checked::Pass } else { Checked::Fail };
        self.log.push(event(index, &Entry::Checked(checked)));
        self.at += 1;
        self.progress += 1;
        self.phase = if self.target().is_some() {
            Phase::Work {
                next: 0,
                stopped: false,
            }
        } else {
            Phase::Finished
        };
        if self.phase != Phase::Finished {
            self.skip_past_bound();
        }
        hits
    }
}

impl World for Recovering<'_, '_, '_> {
    fn config(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend((self.plan.len() as u32).to_le_bytes());
        for index in &self.plan {
            out.extend(index.to_le_bytes());
        }
        out
    }

    fn recovery(&self) -> Option<Record> {
        Some(self.recovery.record())
    }

    fn start(&self) -> u64 {
        0
    }

    fn advance(&mut self, _now: u64) {
        if let Phase::Work { next, .. } = self.phase {
            self.phase = Phase::Work {
                next,
                stopped: true,
            };
        }
        if self.at_boundary() {
            let (index, _) = self.target().expect("a planned cut");
            let queue = self
                .scene
                .as_ref()
                .map_or(0, |scene| scene.control.outstanding() as u16);
            self.log.push(event(index, &Entry::Reached { queue }));
        }
    }

    fn runnable(&self, _now: u64) -> Vec<Candidate> {
        match self.phase {
            Phase::Work { stopped: false, .. } | Phase::Finished => Vec::new(),
            Phase::Work { .. } if self.at_boundary() => {
                vec![Turn::Crash.candidate(), Turn::Hold.candidate()]
            }
            Phase::Work { next, .. } => vec![Turn::Fill(next as u8).candidate()],
            Phase::Dead => vec![Turn::Relaunch.candidate()],
            Phase::Recovered => vec![Turn::Lookup.candidate()],
        }
    }

    fn next_due(&self, now: u64) -> Option<u64> {
        matches!(self.phase, Phase::Work { stopped: false, .. }).then_some(now + 100)
    }

    fn apply(&mut self, event: Candidate, now: u64) -> u64 {
        match Turn::of(&event) {
            Some(Turn::Fill(operation)) => {
                let written = self.fill(operation);
                if let Phase::Work { next, .. } = self.phase {
                    self.phase = Phase::Work {
                        next: next + 1,
                        stopped: false,
                    };
                }
                written
            }
            Some(Turn::Crash) => self.crash(),
            Some(Turn::Hold) => 0,
            Some(Turn::Relaunch) => self.relaunch(now),
            Some(Turn::Lookup) => self.lookup(),
            None => 0,
        }
    }

    fn progress(&self) -> u64 {
        self.progress
    }

    fn done(&self) -> bool {
        self.phase == Phase::Finished
    }

    fn defect(&self) -> Option<crate::sim::turn::Defect> {
        self.defect.map(crate::sim::turn::Defect::Choice)
    }

    /// Judges the living incarnation's tables, then appends the ledger
    /// events the world produced since the last call.
    fn emit(&mut self, out: &mut Vec<Event>) {
        if let Some(scene) = &self.scene {
            match tables(scene.storage, &mut self.lenses) {
                Tables::Conserved => {}
                Tables::Violated(rule) => {
                    self.failed.get_or_insert(rule);
                }
                Tables::Unreadable(reason) => {
                    self.break_with(reason);
                }
            }
        }
        out.append(&mut self.log);
    }
}

/// Whether a run's recorded `turns` hold at least one Relaunch and the turn
/// after each Relaunch is a Lookup. Only the Lookup is runnable once the
/// owner is rebuilt, and the clock stays put while a turn is runnable, so
/// the rebuilt owner's lookup lands one turn after its relaunch, at the
/// relaunch's time, inside [`EPISODE_TURNS`](super::EPISODE_TURNS) and
/// [`EPISODE_US`](super::EPISODE_US).
pub(super) fn lookups_follow_relaunches(turns: &[[u8; CANDIDATE_LEN]]) -> bool {
    let turn = |at: usize| turns.get(at).and_then(|bytes| Turn::of(&Candidate(*bytes)));
    let relaunches: Vec<usize> = (0..turns.len())
        .filter(|&at| turn(at) == Some(Turn::Relaunch))
        .collect();
    !relaunches.is_empty()
        && relaunches
            .into_iter()
            .all(|at| turn(at + 1) == Some(Turn::Lookup))
}

/// Runs `recovery`'s planned cuts under `bounds`: the lifecycle bounds,
/// the link bounds on every incarnation's links, and the turn limits.
pub(crate) fn run(
    chooser: Chooser,
    profile: &Profile,
    recovery: Recovery,
    bounds: Bounds,
    hook: &mut impl Hook,
) -> Ran {
    run_planted(chooser, profile, recovery, bounds, Plant::None, hook)
}

/// A defect a control plants in the recovery world.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Plant {
    None,
    /// Every recovered lookup is judged a hit.
    Revived,
    /// Every held write lands whole, whatever its cut prescribes.
    Whole,
    /// Every held write's range already holds its submitted bytes before
    /// death.
    Indistinct,
    /// The write check and held-write match expect each child one block earlier. The device
    /// still receives and reports the workload's original ranges.
    Unmatched,
    /// Operation 1 reaches its boundary with zero fill submissions.
    Unfilled,
    /// Every cut is disposed of under the other class's path: a reset for
    /// process death and a drain for a controller reset.
    Swapped,
    /// Every held write still pending after it executes stays held, so a
    /// drain leaves the dead queue nonempty at each cut that lands any of
    /// it.
    Stuck,
    /// Each Relaunch turn reserves one payload unit from the new
    /// incarnation's extent allocator and records it in no slot, which the
    /// conservation rule judges at the end of that turn.
    LeakedUnit,
    /// Each Relaunch turn poisons the new incarnation's pool gate, as a
    /// holder that panicked would, so the conservation snapshot is
    /// unreadable at the end of that turn.
    PoisonedPool,
}

fn object(blocks: u8) -> usize {
    let record = RecordConfig {
        chunk_len: CHUNK_LEN,
    }
    .validate()
    .expect("the fixture's record format validates");
    let payload = record
        .payload_of(u64::from(blocks) * BLOCK as u64)
        .expect("a payload fills the profile's record to its last byte");
    payload as usize
}

/// [`run`], with `plant` in the world.
pub(super) fn run_planted(
    chooser: Chooser,
    profile: &Profile,
    recovery: Recovery,
    bounds: Bounds,
    plant: Plant,
    hook: &mut impl Hook,
) -> Ran {
    let draws = Rc::new(RefCell::new(chooser));
    let mut ran = None;
    let lifecycle = bounds.lifecycle;
    restart_scene_with(
        lifecycle,
        lifecycle.restarts.min(recovery.table().len()) + 1,
        |Run {
             scene,
             mut life,
             mut fresh,
             ..
         }| {
            let turn = draws.borrow_mut().launch(TURN.actor);
            let owner = draws.borrow_mut().launch(CRASH.actor);
            let admission = recovery.admission();
            let table = recovery.table();
            let plan: Vec<u32> = (0..table.len() as u32).collect();
            let mut world = Recovering {
                first_ordinal: 0,
                compared_writes: Vec::new(),
                write_gap: None,
                scene: None,
                life: &mut life,
                fresh: &mut fresh,
                fills: Vec::new(),
                draws: Rc::clone(&draws),
                admission,
                recovery,
                table,
                plan,
                at: 0,
                phase: Phase::Work {
                    next: 0,
                    stopped: false,
                },
                owner,
                restarts: lifecycle.restarts,
                link: bounds.link,
                log: Vec::new(),
                progress: 0,
                failed: None,
                inconclusive: None,
                restarted: false,
                skipped: false,
                broken: None,
                rows: None,
                keys: &KEYS[..recovery.workload().0],
                object: object(recovery.workload().1),
                plant,
                defect: None,
                lenses: Lenses::default(),
                leaked: false,
            };
            world.install(scene);
            for index in world.plan.clone() {
                world.log.push(event(index, &Entry::Planned));
            }
            world.skip_past_bound();
            let report = run_hooked(
                &mut world,
                profile,
                &draws,
                (TURN, turn),
                bounds.turns,
                hook,
            );
            ran = Some(Ran {
                write_gap: world.write_gap,
                compared_writes: std::mem::take(&mut world.compared_writes),
                report,
                draws: Rc::clone(&draws),
                failed: world.failed,
                inconclusive: world.inconclusive,
                restarted: world.restarted,
                skipped: world.skipped,
                broken: world.broken,
                alive: world.scene.is_some(),
                leaked: world.leaked,
                conserved: world.lenses.judgments(),
            });
            drop(world);
        },
    );
    ran.expect("the recovery scene ran")
}

#[cfg(test)]
mod tests;
