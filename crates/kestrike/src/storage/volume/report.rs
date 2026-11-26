//! The recovery report: what one attach's recovery did, phase by phase, in the caller's tick time, with the readiness transitions it took.
//!
//! REPORT-BOUNDED: the report stores counts, byte totals, tick times and typed states in fixed-size fields in the volume.

use super::super::device::Disk;
use super::super::os::Platform;
use super::super::readiness::{State, Word};
use super::attach::Volume;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecoveryPhase {
    /// From the attach's first tick until the readiness word leaves `Detached` and `Loading`.
    Initialization,
    /// The owner's adoption of helper terminals; operations are the terminals adopted.
    Adoption,
    /// From `begin_replay` until `Live`; operations are the replay calls that advanced readiness, rows the admitted bindings.
    Replay,
    /// The first read that ended `Complete` at `Live`.
    FirstSafeHit,
    /// `Live` over restored bindings, the earliest a restored hit can serve; rows are the restored bindings, unweighted by demand.
    RetainedReadiness,
    /// The first payload write submitted at `Live`, the earliest a fill can land.
    FillReadiness,
}

/// The number of [`RecoveryPhase`]s.
pub const RECOVERY_PHASES: usize = RecoveryPhase::FillReadiness as usize + 1;

pub const RECOVERY_TRANSITIONS: usize = State::ALL_STATES.len();

/// One phase's span and counts; `start` and `end` are the tick times `poll_storage` was given, and a replay step between ticks carries the last tick's time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct PhaseReport {
    pub start: Option<u64>,
    pub end: Option<u64>,
    pub operations: u64,
    pub rows: u64,
}

/// One readiness transition a tick observed, at that tick's time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Transition {
    pub from: State,
    pub to: State,
    pub at: u64,
}

/// `RecoveryReport` is one attach's recovery report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct RecoveryReport {
    /// Indexed by [`RecoveryPhase`].
    pub phases: [PhaseReport; RECOVERY_PHASES],
    pub transitions: [Option<Transition>; RECOVERY_TRANSITIONS],
    /// The helpers' peak live jobs, held bytes and decoded-byte charge.
    pub peak_jobs: u32,
    pub peak_input_bytes: u64,
    pub peak_output_bytes: u64,
    /// The units the warm bootstrap's allocator holds restored.
    pub held_units: u64,
    /// The most recovery I/O bytes charged in one report window of the owner's share, at most its part plus its
    /// bucket's capacity, and the windows that refused at least one charge, one the bucket could not hold when it
    /// was offered. A report window opens at the first charge offered at least one interval after the window before
    /// it opened.
    pub io_peak_bytes: u64,
    pub io_saturated_windows: u64,
    /// The warm bootstrap's loss record.
    pub warm: WarmReport,
}

/// Loss accounting for a warm bootstrap's slot and its suffix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct WarmReport {
    /// Slot units that failed their identity, crc or content check; the entries with a row on them are lost.
    pub failed_units: u32,
    /// Slot units the device could not read.
    pub unread_units: u32,
    /// The first damage of the slot, which outranks the rest.
    pub first_damage: Option<super::super::recovery::checkpoint::UnitDamage>,
    /// Suffixes whose first hole is damage, and suffixes whose first hole ends their unflushed tail.
    pub suffix_damage: u32,
    pub suffix_tails: u32,
    /// Whole suffix inserts behind their suffix's first hole, and the replay's unread markers: the LSNs whose read
    /// failed, the region end of each suffix recorded longer than its region, and the first LSN a replay that refused
    /// its limits leaves unread.
    pub suffix_dropped: u64,
    pub suffix_unread: u64,
    /// The slot's entries a suffix entry superseded, and those withheld for a session the reader does not admit.
    pub slot_superseded: u64,
    pub slot_withheld: u64,
    /// Entries the conversion omitted: a portable pair whose deadline lies at or below the earliest bound of the load's
    /// reading, less one second on a stepped scale, a covered `(key, version)`, or a version-0 entry whose key the
    /// coverage touches. Every other unrestorable entry refuses the attempt.
    pub omitted: u64,
    /// Entries installed at the commit. An entry whose pair the load's reading or sample alone judges expired counts
    /// here: it installs as a member that reads expired and holds its units.
    pub installed: u64,
}

impl RecoveryReport {
    /// `phase` is `phase`'s span and counts.
    pub fn phase(&self, phase: RecoveryPhase) -> PhaseReport {
        self.phases[phase as usize]
    }

    /// `time_in` is the tick time the volume spent in `state` through `now`, summed over its stays; a stay ends at `now` when `now` falls inside it, and a stay entered after `now` adds nothing.
    pub fn time_in(&self, state: State, now: u64) -> u64 {
        let seen = || self.transitions.iter().flatten();
        let leaves = seen().skip(1).map(|transition| transition.at).chain([now]);
        seen()
            .zip(leaves)
            .filter(|(entered, _)| entered.to == state)
            .map(|(entered, left)| left.min(now).saturating_sub(entered.at))
            .sum()
    }
}

/// `Milestone` tracks the first safe hit or the first fill at `Live` until an observation records it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Milestone {
    /// `Idle` applies before `Live`, after `Live` ends, or after an observation records the event.
    #[default]
    Idle,
    /// An observation recorded `Live`, and the event is still to come.
    Awaited,
    /// The event happened while the readiness word held `Live`; the next observation records it.
    Due,
}

impl Milestone {
    #[cold]
    #[inline(never)]
    fn arrive(&mut self, word: &Word) {
        *self = if word.holds(State::Live) {
            Self::Due
        } else {
            Self::Idle
        };
    }
}

/// `Recorder` is the volume's report as it grows, with the hooks' state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Recorder {
    report: RecoveryReport,
    /// The time of the tick running now.
    now: u64,
    /// Whether a tick ran.
    ticked: bool,
    /// Whether the initialization start was stamped at a tick's time, which gives the recovery times their origin.
    timed: bool,
    /// The readiness the last observation recorded.
    state: Option<State>,
    first_safe_hit: Milestone,
    fill_readiness: Milestone,
    /// Whether a warm bootstrap recorded its load's account.
    warm_loaded: bool,
    /// Whether that load reached its deciding result, its commit or an ending `Unloadable`, `Collided` or
    /// `MetadataFailed`, after which its account stays fixed for the attach.
    warm_decided: bool,
}

impl Recorder {
    pub(super) fn tick_at(&mut self, now: u64) {
        self.now = now;
        self.ticked = true;
    }

    /// The time of the tick running now.
    pub(super) fn now(&self) -> u64 {
        self.now
    }

    /// `count` opens `phase` at the current tick if it is not open, extends its end there, and adds the counts.
    pub(super) fn count(&mut self, phase: RecoveryPhase, (operations, rows): (u64, u64)) {
        let now = self.now;
        let entry = &mut self.report.phases[phase as usize];
        entry.start.get_or_insert(now);
        entry.end = Some(now);
        entry.operations += operations;
        entry.rows += rows;
    }

    pub(super) fn record_peaks(&mut self, (jobs, input, output): (u32, usize, usize)) {
        let report = &mut self.report;
        report.peak_jobs = report.peak_jobs.max(jobs);
        report.peak_input_bytes = report.peak_input_bytes.max(input as u64);
        report.peak_output_bytes = report.peak_output_bytes.max(output as u64);
    }

    pub(super) fn record_held_units(&mut self, units: u64) {
        self.report.held_units = units;
    }

    /// Records `load`'s damage and suffix report as the warm bootstrap's loss record.
    pub(super) fn warm_load(&mut self, load: &super::super::recovery::checkpoint::SlotLoad) {
        self.warm_loaded = true;
        let warm = &mut self.report.warm;
        if let Some(damage) = &load.damage {
            warm.failed_units = damage.failed.len() as u32;
            warm.unread_units = damage.unread.len() as u32;
            warm.first_damage = Some(damage.first);
        }
        warm.suffix_damage = load.suffix.damage.len() as u32;
        warm.suffix_tails = load.suffix.tails.len() as u32;
        warm.suffix_dropped = load.suffix.dropped.len() as u64;
        warm.suffix_unread = load.suffix.unread.len() as u64;
        warm.slot_superseded = load.slot_superseded;
        warm.slot_withheld = load.slot_withheld;
    }

    pub(super) fn warm_converted(&mut self, omitted: u64) {
        self.report.warm.omitted = omitted;
    }

    /// A commit decides the warm load even when it installs zero entries.
    pub(super) fn warm_installed(&mut self, installed: u64) {
        self.report.warm.installed = installed;
        self.warm_decided = true;
    }

    /// Records an ending `Unloadable`, `Collided` or `MetadataFailed` outcome as the deciding result of a load that
    /// recorded its account.
    pub(super) fn warm_refused(&mut self) {
        self.warm_decided |= self.warm_loaded;
    }

    pub(super) fn report(&self) -> RecoveryReport {
        self.report
    }

    /// `current` holds when `word` still holds the last state observed.
    #[inline]
    pub(super) fn current(&self, word: &Word) -> bool {
        self.state.is_some_and(|state| word.holds(state))
    }

    /// `settled` holds exactly when an observation would leave the recorder as it is, so the tick skips it.
    #[inline]
    pub(super) fn settled(&self, word: &Word) -> bool {
        self.first_safe_hit != Milestone::Due
            && self.fill_readiness != Milestone::Due
            && self.current(word)
    }

    /// Call `completed_read` after a read ends `Complete`. The first completion while `word` holds `Live` after `observe` recorded `Live` marks the first safe hit.
    #[inline]
    pub(super) fn completed_read(&mut self, word: &Word) {
        if self.first_safe_hit == Milestone::Awaited {
            self.first_safe_hit.arrive(word);
        }
    }

    /// Call `submitted_write` after a payload write is submitted. The first submission while `word` holds `Live` after `observe` recorded `Live` marks the first fill.
    #[inline]
    pub(super) fn submitted_write(&mut self, word: &Word) {
        if self.fill_readiness == Milestone::Awaited {
            self.fill_readiness.arrive(word);
        }
    }

    /// `observe` records due milestones before readiness transitions, preserving event order when a withdrawal occurs between observations.
    pub(super) fn observe(&mut self, state: State, restored: u64) {
        let at = self.now;
        let phases = &mut self.report.phases;
        let start = &mut phases[RecoveryPhase::Initialization as usize].start;
        if start.is_none() {
            self.timed = self.ticked;
        }
        start.get_or_insert(at);
        if !state.initializing() {
            phases[RecoveryPhase::Initialization as usize]
                .end
                .get_or_insert(at);
        }
        if self.first_safe_hit == Milestone::Due {
            self.first_safe_hit = Milestone::Idle;
            self.count(RecoveryPhase::FirstSafeHit, (1, 0));
        }
        if self.fill_readiness == Milestone::Due {
            self.fill_readiness = Milestone::Idle;
            self.count(RecoveryPhase::FillReadiness, (1, 0));
        }
        if self.state == Some(state) {
            return;
        }
        if self.state == Some(State::Replaying) {
            self.count(RecoveryPhase::Replay, (0, 0));
        }
        let transition = Transition {
            from: self.state.unwrap_or(state),
            to: state,
            at,
        };
        let slot = self
            .report
            .transitions
            .iter_mut()
            .find(|slot| slot.is_none());
        debug_assert!(
            slot.is_some(),
            "the readiness table enters each state at most once"
        );
        if let Some(slot) = slot {
            *slot = Some(transition);
        }
        let milestone = if state == State::Live {
            if restored > 0 {
                self.count(RecoveryPhase::RetainedReadiness, (1, restored));
            }
            Milestone::Awaited
        } else {
            Milestone::Idle
        };
        (self.first_safe_hit, self.fill_readiness) = (milestone, milestone);
        self.state = Some(state);
    }
}

impl<'s, 'a, P: Platform, D: Disk> Volume<'s, 'a, P, D> {
    /// `recovery_report` is this attach's recovery report so far.
    pub fn recovery_report(&self) -> RecoveryReport {
        RecoveryReport {
            io_peak_bytes: self.recovery_io.peak(),
            io_saturated_windows: self.recovery_io.saturated(),
            ..self.recovery.report()
        }
    }

    /// Whether the recovery I/O share's report window open at `now`, a tick of the poll clock, refused a charge. The
    /// reading lasts until that window is one interval old, whether or not the share's bucket drained since.
    pub(crate) fn recovery_io_full(&self, now: u64) -> bool {
        self.recovery_io.full(now)
    }

    /// The most bytes one window of the recovery I/O share can charge, its part plus its bucket capacity.
    pub(crate) fn recovery_io_limit(&self) -> u64 {
        self.recovery_io.limit()
    }

    /// The most recovery I/O bytes one window charged so far and the windows that refused a charge, the values
    /// [`Self::recovery_report`] writes into `io_peak_bytes` and `io_saturated_windows`. The peak is the share's own
    /// window count: a refunded recovery read or checkpoint-unit charge leaves it, and a suffix block's charge stays
    /// in it for each time the log handed the block out.
    pub(crate) fn recovery_io_peak(&self) -> (u64, u64) {
        (self.recovery_io.peak(), self.recovery_io.saturated())
    }

    /// The recorder's report of this attach where it lies: [`Self::recovery_report`] without the recovery I/O
    /// share's two figures, which read 0 here.
    pub(crate) fn recovery_record(&self) -> &RecoveryReport {
        &self.recovery.report
    }

    /// Whether the attach's recovery times have an origin: its initialization start was stamped at a tick's time.
    /// Before the first tick the recorder's clock reads 0 by default, so a close before any tick stamps the start at
    /// a time no tick gave, and the attach's times stay without an origin after later polls.
    pub(crate) fn recovery_timed(&self) -> bool {
        self.recovery.timed
    }

    /// Whether the attach's warm load reached its deciding result with its account recorded: the commit, or an ending
    /// `Unloadable`, `Collided` or `MetadataFailed` after the stage recorded the decoded load's account. A load refused
    /// before the stage (the slot reader's `Limits` or `Memory` refusal) records no account, and a load awaiting its
    /// commit, or stopped there by a withdrawal, reads false.
    pub(crate) fn warm_decided(&self) -> bool {
        self.recovery.warm_decided
    }

    /// Offers the share a charge its bucket never holds at `now`, so the window open at `now` refuses, for the tests
    /// that read a saturated share through the owner's report entry.
    #[cfg(test)]
    pub(crate) fn refuse_recovery_io(&mut self, now: u64) {
        let fits = self
            .recovery_io
            .admit(now, u64::MAX, super::super::recovery::IoClass::Bulk);
        assert!(!fits, "no bucket holds u64::MAX bytes");
    }

    /// The volume's recovery I/O share and the current tick, for the tests that drive the suffix log's writes, which
    /// charge it before they issue.
    #[cfg(test)]
    pub(crate) fn recovery_io(&mut self) -> (&mut super::super::recovery::IoShare, u64) {
        (&mut self.recovery_io, self.recovery.now())
    }

    /// `observe_recovery` records due milestones even when readiness is unchanged, and a readiness transition since the previous observation.
    #[inline]
    pub(super) fn observe_recovery(&mut self) {
        let word = &self.storage.readiness;
        if !self.recovery.settled(word) {
            self.observe_change();
        }
    }

    /// `observe_transition` runs at each tick's start and checks for a readiness transition only, so a transition between ticks is recorded before the tick's reads complete.
    #[inline]
    pub(super) fn observe_transition(&mut self) {
        let word = &self.storage.readiness;
        if !self.recovery.current(word) {
            self.observe_change();
        }
    }

    #[cold]
    #[inline(never)]
    fn observe_change(&mut self) {
        self.recovery
            .observe(self.readiness(), self.restored_rows());
    }
}
