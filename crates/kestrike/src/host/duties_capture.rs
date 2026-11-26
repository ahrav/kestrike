//! The capture pass of a serving tenure: one walk of the membership at a cut, the stage's slot reservation, the
//! cut's whole encode on the recovery helpers, one checkpoint-unit command at a time to write and read back every
//! unit, then the Publish on the store lane. A turn makes at most one transition of the pass and stages at most one
//! unit command.
//!
//! Invariants:
//!
//! - PossNamedCoversStore: the owner thread reserves the stage's slot in the duties' one [`PossiblyNamed`] before it
//!   dispatches the encode, and the encode carries that reservation and the cut alone, so the set stays on the
//!   owner thread while the helpers encode and a suffix step may take it to the lane meanwhile. The Publish moves
//!   the set to the lane and holds the duties' one shard-record slot while it runs. A reservation, a refused
//!   stage's release and a unit command read the set on the owner thread: the pass waits in its dispatch, its
//!   encode's adoption and its unit commands while a suffix step holds the set, and a unit command fails the
//!   single-holder check while any other job holds it.
//! - STORE-OFF-POLL: the encode runs on a helper thread and the Publish on the lane thread. The walk, the unit
//!   commands and the proof run on the owner thread, and the lane thread runs the pass's one store request.
//! - `ReservedBeforeWrite`, `VerifiedBeforePublish`: every unit write goes to the stage's reserved slot under the
//!   pass's live counter, and the Publish is submitted once every unit read back equal, with the proof and the
//!   capture epoch the owner thread read directly before the submit.
//! - `QuarantineUntilBarrier`: a pass that ends unpublished after a unit write abandons its stage, which quarantines
//!   the slot; a Publish whose outcome is unknown leaves its slot possibly named until a later success settles it.
//! - Kept unit buffers: the tenure keeps the unit buffers of its last stage between passes, and the next encode
//!   writes its units into them before it allocates; that encode writes every byte of each unit it stages
//!   ([`StagedCheckpoint::encode`]). Each walk turn and each encode checks the kept buffers with the cut's copy and
//!   the units against the capture budget. The tenure gives them to the volume's helpers to free once it withdraws
//!   or its open stops, once the policy refuses every later start, and when a walk needs their bytes; the encode
//!   frees those past the units its stage needs when they number more than twice those units or the budget cannot
//!   hold them with its stage.
//!   A walk waits for the helpers to finish freeing released buffers before it reserves a chunk against the
//!   released bytes.
//! - The epoch the owner thread reads before the submit is the one [`checkpoint::publish`] requires its caller to
//!   read at the call. A pass starts only once the open reached `Opened`, which follows `Live`; a storage attaches
//!   once, and its attach, every restored install and its load commit run before `Live`. So no replacement of the
//!   membership runs between that read and the settlement of the Publish's write, including a write whose outcome
//!   is unknown until a later own exact-version success.
//!
//! [`checkpoint::publish`]: crate::storage::checkpoint::publish

use super::super::exit::{Exit, Rerun};
use super::super::lane::{Job, Publish};
use super::{Duties, Open, Set, Unsettled, closed_to_writes};
use crate::failover::planned::Published;
use crate::failover::records::{ShardRecord, UNIT_ENTRIES};
use crate::failover::report::{Captures, Gauge, Pressure};
use crate::net::{Datagrams, Owner};
use crate::storage::checkpoint::{
    self, Checkpoint, Cut, PER_UNIT, PossiblyNamed, ReserveRefusal, StageRefusal, StagedCheckpoint,
    Units, WriteRefused,
};
use crate::storage::store::{Read, Store, WatermarkLog};
use crate::storage::{
    CaptureError, CapturePolicy, Disk, Encode, Encoded, EngineBudget, Leftovers, Panicked,
    Platform, Readiness, UnitDone, UnitRefused,
};

/// The failed or unequal commands of one unit that a pass stages again; one more ends the pass abandoned. The count
/// starts again at each unit that read back equal, so isolated transient faults across a large stage do not add up,
/// and a unit that keeps failing ends the pass.
const UNIT_RETRIES: u32 = 3;

/// A tenure's capture policy and pass, the budget the walk's copy of a cut and each encode's input and units are
/// checked against, and the counts [`Duties::captures`] reports.
pub(super) struct Capture {
    pub(super) policy: CapturePolicy,
    pub(super) budget: EngineBudget,
    pub(super) pass: Pass,
    /// The earliest turn time of the next start: one view period after a refused start or after a pass that ended
    /// unpublished while it served a due publication, and `u64::MAX` once a poisoned capture mutex, a closed storage
    /// or a halted tenure refuses every later start.
    pub(super) start_at: u64,
    pub(super) refused: u64,
    pub(super) abandoned: u64,
    #[cfg(test)]
    pub(super) published: u64,
    /// The last Publish's refusal.
    #[cfg(test)]
    pub(super) refusal: Option<WriteRefused>,
    /// This turn's adoption of a Publish completion moved the pass.
    landed: bool,
    /// A suffix step reported a due publication that no Publish has settled since.
    pub(super) publish_due: bool,
    /// The running pass started while a publication was due, so it serves that publication.
    pub(super) serving_due: bool,
    /// The last walk's copy, emptied: the next walk fills the chunks it reserved under the budget.
    pub(super) spare: Cut,
    /// The unit buffers of the last stage and the kept buffers it did not take, which the next encode writes before
    /// it allocates. They count against the budget, [`PER_UNIT`] bytes each, in every check while the tenure holds
    /// them; the tenure frees them once it withdraws or its open stops, once the policy refuses every later start,
    /// when its walk needs their bytes, and when a walk turn ends the pass abandoned.
    pub(super) kept: Units,
    /// The volume's capture pool is discarding kept unit buffers. They remain allocated until
    /// [`Owner::discarded`] reads `true`, so the walk waits for that before reserving a chunk against those bytes.
    yielding: bool,
    /// The thread that ran the last encode.
    #[cfg(test)]
    pub(super) encoded_on: Option<String>,
}

/// One capture pass, from its start to the end [`finish_capture`](crate::storage::Storage::finish_capture) records.
#[derive(Debug)]
pub(super) enum Pass {
    Idle,
    /// The walk visits [`UNIT_ENTRIES`] slots a turn into `cut`.
    Walking {
        counter: u32,
        cut: Cut,
    },
    /// `cut` holds the walk and the side list until the encode's dispatch; `input` is the bytes the cut holds
    /// outside the side list's charge.
    Walked {
        counter: u32,
        cut: Cut,
        input: usize,
    },
    /// The encode runs on the recovery helpers over the slot the set reserved for it.
    Encoding {
        counter: u32,
    },
    Writing {
        counter: u32,
        staged: StagedCheckpoint,
        unit: Unit,
        retries: u32,
    },
    /// Every unit read back equal; the proof and the Publish's submit wait for an idle lane, the set on the owner
    /// thread, and a last view that read this tenure's shard record.
    Proving {
        counter: u32,
        staged: StagedCheckpoint,
    },
    /// The Publish holds the set and the stage on the lane.
    Publishing {
        counter: u32,
    },
    /// The pass ended; `finish_capture` waits for the capture mutex.
    Finishing {
        counter: u32,
    },
}

/// A unit command to stage (`Write`, `Read`) or one staged whose result is still to come (`Written`, `Reading`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Unit {
    Write(u32),
    Written(u32),
    Read(u32),
    Reading(u32),
}

#[cfg(test)]
thread_local! {
    /// The Publish carries the owner thread's epoch minus one, standing for an epoch read before a load commit.
    pub(super) static STALE_EPOCH: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// [`Duties::capturing`] admits a storage with a sequence arena.
    pub(super) static ADMIT_ARENA: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Why [`Duties::capturing`] refuses a capture policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureRefusal {
    /// The lane's storage carries a sequence arena, so a fill may place an object of two or more extents. The
    /// single-extent warm loader rejects a checkpoint containing a multi-extent entry or a suffix recording its INSERT.
    /// Omitting a multi-extent entry's INSERT from the suffix can cause recovery to restore the key's superseded
    /// version from an earlier checkpoint. A load that omits a live multi-extent entry because this installer restores
    /// one extent makes recovery depend on installer capabilities, so a later installer that restores multi-extent
    /// entries, run over an older checkpoint, could restore an entry whose units a later fill reused.
    /// [`Duties::capturing`] returns `SequenceArena` at the start of the tenure, before the tenure serves.
    SequenceArena,
    /// The capture budget falls below [`Cut::turn_reserve`] for an empty copy. That reserve covers the first chunk
    /// and chunk list needed to copy one member. Below it, every walk that visits a member abandons its pass.
    Budget,
}

/// Duties whose capture policy [`Duties::capturing`] refused, returned with no policy, and the cause.
pub struct Uncaptured<'l, S, L, P: Platform> {
    pub duties: Duties<'l, S, L, P>,
    pub cause: CaptureRefusal,
}

impl<S, L, P: Platform> std::fmt::Debug for Uncaptured<'_, S, L, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Uncaptured")
            .field("cause", &self.cause)
            .finish_non_exhaustive()
    }
}

impl<'l, S: Store, L: WatermarkLog, P: Platform> Duties<'l, S, L, P> {
    /// Runs the tenure's capture passes under `policy`; the walk's copy of a cut and each encode's input and units
    /// are checked against `budget`. The first call sets the policy and the budget for the tenure; a later call
    /// returns the duties unchanged, so a pass in flight, its stage and the counts stay as they are.
    ///
    /// The caller passes a policy from [`CapturePolicy::new`] with no pass started and no changed bytes fed, built
    /// at a turn time of the owner's turn clock: the duties give the policy each turn's `now`, in microseconds,
    /// times 1,000. `budget` is the capture's own headroom, held apart from the policy's side-list charge, which
    /// [`CapturePolicy::new`] took from the engine budget; the checks charge copies of it, so each pass reuses it.
    /// The tenure keeps the chunks of its last walk's copy and the unit buffers of its last stage between passes,
    /// inside that headroom, so the next walk and the next encode write into memory they already hold; the first
    /// pass of a tenure reserves them.
    ///
    /// Under such a policy a pass becomes due on the time ceiling: the duties feed no changed bytes to the byte
    /// trigger, and pass `planned_restart` and `fill_stopped` as `false`. The paced interval spaces the pass's unit
    /// writes; the walk takes the side list before the first write, so the fast interval does not apply.
    ///
    /// # Errors
    ///
    /// [`CaptureRefusal::SequenceArena`] when the lane's storage carries a sequence arena, checked at the first
    /// call: the duties come back with no policy, and the caller ends the tenure before it serves. So a tenure that
    /// publishes checkpoints caches no object past one extent's payload: its FILLs of such an object refuse
    /// `Layout(MultipleExtents)`. `capturing` returns [`CaptureRefusal::Budget`] if the initial reservation for
    /// the walk's copy exceeds `budget`.
    pub fn capturing(
        mut self,
        policy: CapturePolicy,
        budget: EngineBudget,
    ) -> Result<Self, Box<Uncaptured<'l, S, L, P>>> {
        #[cfg(test)]
        let admit_arena = ADMIT_ARENA.with(std::cell::Cell::get);
        #[cfg(not(test))]
        let admit_arena = false;
        let mut scratch = budget;
        let refusal = match self.capture {
            Some(_) => None,
            None if self.lane.storage().has_sequence_arena() && !admit_arena => {
                Some(CaptureRefusal::SequenceArena)
            }
            None if scratch.charge(Cut::new().turn_reserve()).is_err() => {
                Some(CaptureRefusal::Budget)
            }
            None => None,
        };
        if let Some(cause) = refusal {
            return Err(Box::new(Uncaptured {
                duties: self,
                cause,
            }));
        }
        self.capture.get_or_insert(Capture {
            policy,
            budget,
            pass: Pass::Idle,
            start_at: 0,
            refused: 0,
            abandoned: 0,
            #[cfg(test)]
            published: 0,
            #[cfg(test)]
            refusal: None,
            landed: false,
            publish_due: false,
            serving_due: false,
            spare: Cut::new(),
            kept: Vec::new(),
            yielding: false,
            #[cfg(test)]
            encoded_on: None,
        });
        Ok(self)
    }

    /// The tenure's capture counts, each `Some` under a capture policy. `refused` counts refused starts, at most
    /// one a view period while a refusal lasts, and refused encode dispatches and stages. `abandoned` counts passes
    /// that ended unpublished after their start: a walk or a unit command that failed, a refused proof, and a
    /// refused Publish, including one whose store error leaves its outcome unknown and which may have committed.
    pub fn captures(&self) -> Captures {
        let counts = self.capture.as_ref();
        Captures {
            refused: counts.map(|capture| capture.refused),
            abandoned: counts.map(|capture| capture.abandoned),
        }
    }

    /// [`Pressure::unresolved`] over the possibly-named set as it last returned to the owner thread.
    pub fn quarantine(&self) -> Gauge {
        self.quarantine
    }

    #[inline(never)]
    pub(super) fn capture<'a, D: Disk, T: Datagrams<'a>>(
        &mut self,
        owner: &mut Owner<'_, 'a, '_, P, D, T>,
        now: u64,
    ) -> Option<Exit> {
        let capture = self.capture.as_mut()?;
        if std::mem::take(&mut capture.landed) {
            return None;
        }
        if matches!(capture.pass, Pass::Idle) {
            // The idle pass stays in place: a turn with no start due moves no pass state.
            let started = self.start(owner, now);
            if !matches!(started, Pass::Idle) {
                self.counts().pass = started;
            }
            return None;
        }
        let pass = std::mem::replace(&mut capture.pass, Pass::Idle);
        let next = match pass {
            Pass::Idle => unreachable!("the idle pass returned above"),
            Pass::Walking { counter, cut } => self.walk(owner, counter, cut),
            Pass::Walked {
                counter,
                cut,
                input,
            } => self.dispatch(owner, counter, (cut, input)),
            // A refused stage's reservation ends over the set, so the terminal waits while a step holds the set.
            Pass::Encoding { counter } if !self.set_here() => Pass::Encoding { counter },
            Pass::Encoding { counter } => match owner.take_encoded() {
                None => Pass::Encoding { counter },
                Some(Err(Panicked)) => {
                    // The reservation dropped with the job; the caller drops the duties at this exit.
                    self.counts().pass = Pass::Finishing { counter };
                    return Some(Exit::Rerun(Rerun::Unwound));
                }
                Some(Ok(encoded)) => self.encoded(counter, encoded),
            },
            Pass::Writing {
                counter,
                staged,
                unit,
                retries,
            } => self.unit(owner, (counter, staged), (unit, retries), now),
            Pass::Proving { counter, staged } => self.prove(owner, counter, staged),
            Pass::Publishing { counter } => Pass::Publishing { counter },
            Pass::Finishing { counter } => self.finish(owner, counter, now),
        };
        self.counts().pass = next;
        None
    }

    fn counts(&mut self) -> &mut Capture {
        self.capture
            .as_mut()
            .expect("a pass runs under a capture policy")
    }

    /// Starts a pass when the policy is due, the tenure open reached `Opened`, the last view read this tenure's
    /// shard record, and the set is on the owner thread. A refused start waits one view period. A halted tenure
    /// refuses every later start from the first turn on which one is due.
    fn start<'a, D: Disk, T: Datagrams<'a>>(
        &mut self,
        owner: &mut Owner<'_, 'a, '_, P, D, T>,
        now: u64,
    ) -> Pass {
        let planned = self.roll_asks_start();
        // Most turns end here: no start is due until the policy's triggers, a due publication or the roll say so.
        if !planned {
            let capture = self.counts();
            let triggered = capture.publish_due || (capture.policy).due(nanos(now), false, false);
            if now < capture.start_at || !triggered {
                return Pass::Idle;
            }
        }
        if self.halted(owner) {
            self.counts().start_at = u64::MAX;
            self.release(owner);
        }
        if self.counts().start_at == u64::MAX {
            self.planned_pass(None, Published::Refused);
            return Pass::Idle;
        }
        if self.roll_active() && !planned {
            return Pass::Idle;
        }
        let (planned_restart, fill_stopped) = (planned, planned);
        let ready = self.open == Open::Opened
            && self.viewed_tenure
            && self.read.is_some()
            && self.settling.is_none()
            && owner.readiness() == Readiness::Live
            && self.set_here();
        let capture = self.counts();
        let serving_due = capture.publish_due;
        if ready && serving_due && now >= capture.start_at {
            // A due publication counts as the byte trigger for this start, which clears it.
            capture.policy.changed_bytes(u64::MAX);
        }
        let due = now >= capture.start_at
            && (capture.policy).due(nanos(now), planned_restart, fill_stopped);
        let Set::Here(possible) = &self.possible else {
            return Pass::Idle;
        };
        if !ready || !due {
            return Pass::Idle;
        }
        let free = possible.free_slot().is_some();
        let view_us = self.periods.view_us;
        if self.open_again
            && let Some(read) = &self.read
        {
            let start = checkpoint::suffix_start(read.value());
            if owner.storage().with_suffix(|log| log.place(start)).is_err() {
                return Pass::Idle;
            }
        }
        let capture = self.counts();
        let started = (owner.storage()).try_start_capture(
            &mut capture.policy,
            nanos(now),
            planned_restart,
            fill_stopped,
            free,
        );
        match started {
            Ok(Some(started)) => {
                capture.serving_due = serving_due;
                let cut = std::mem::take(&mut capture.spare);
                self.roll_pass(started.counter);
                Pass::Walking {
                    counter: started.counter,
                    cut,
                }
            }
            Ok(None) | Err(CaptureError::Unavailable) => Pass::Idle,
            // A poisoned capture mutex and a closed storage refuse every later start.
            Err(CaptureError::Poisoned | CaptureError::Closed) => {
                capture.start_at = u64::MAX;
                self.release(owner);
                self.planned_pass(None, Published::Refused);
                Pass::Idle
            }
            Err(refusal) => {
                capture.refused += 1;
                capture.start_at = now.saturating_add(view_us);
                let slot = refusal == CaptureError::NoFreeCheckpointSlot;
                self.bound_refused(None, slot);
                Pass::Idle
            }
        }
    }

    /// Reports a refused start or stage to the roll. `bound`, a start with no free checkpoint slot or a stage refused
    /// for placement, sets [`Duties::roll_due`] and leaves the roll unpublished.
    fn bound_refused(&mut self, counter: Option<u32>, bound: bool) {
        self.roll_due |= bound;
        self.roll_unpublished |= bound;
        self.planned_pass(
            counter,
            match bound {
                true => Published::NoSlot,
                false => Published::Refused,
            },
        );
    }

    /// Runs one [`walk_turn`] under the budget with the kept unit buffers charged and moves the pass by its outcome;
    /// a copy the budget or the allocator refuses, and a pass the storage ended, end the pass abandoned, and the
    /// tenure keeps the copy's chunks. The tenure frees the kept buffers before a turn whose reservations the budget
    /// holds with the copy only without them ([`turn_budget`]), and once a walk turn ends the pass abandoned.
    ///
    /// While the volume's capture pool is discarding buffers the tenure released, the walk waits in place. The copy
    /// reserves a chunk against the released bytes only after the discard completes.
    fn walk<'a, D: Disk, T: Datagrams<'a>>(
        &mut self,
        owner: &mut Owner<'_, 'a, '_, P, D, T>,
        counter: u32,
        cut: Cut,
    ) -> Pass {
        let capture = self.counts();
        if capture.yielding {
            if !owner.discarded() {
                return Pass::Walking { counter, cut };
            }
            capture.yielding = false;
        }
        let budget = capture.budget;
        let held = match turn_budget(budget, capture.kept.len() * PER_UNIT, &cut) {
            Some(held) => held,
            None => {
                self.release(owner);
                if self.counts().yielding {
                    return Pass::Walking { counter, cut };
                }
                budget
            }
        };
        match walk_turn(owner.storage(), held, counter, cut) {
            Walked::More(cut) => Pass::Walking { counter, cut },
            Walked::Done(cut, input) => Pass::Walked {
                counter,
                cut,
                input,
            },
            Walked::Abandoned(cut) => {
                self.release(owner);
                self.retire(owner, cut);
                self.abandon(counter)
            }
        }
    }

    /// Reserves the stage's slot in the set, on the owner thread, and moves the reservation and the cut to the
    /// recovery helpers for the encode; the set stays here. The dispatch waits while a shard-record job holds the
    /// set. A set that refuses the reservation and a volume that refuses the encode refuse the stage, and the
    /// policy's next trigger starts the next pass.
    fn dispatch<'a, D: Disk, T: Datagrams<'a>>(
        &mut self,
        owner: &mut Owner<'_, 'a, '_, P, D, T>,
        counter: u32,
        (cut, input): (Cut, usize),
    ) -> Pass {
        let checkpoint = Checkpoint {
            shard: owner.tenure().shard(),
            session: owner.tenure().get(),
            capture: counter,
        };
        let Set::Here(possible) = &mut self.possible else {
            return Pass::Walked {
                counter,
                cut,
                input,
            };
        };
        let reservation = match possible.reserve_stage(checkpoint, &cut) {
            Ok(reservation) => reservation,
            Err(refusal) => {
                self.retire(owner, cut);
                return self.stage_refused(counter, StageRefusal::Reserve(refusal));
            }
        };
        let capture = self.counts();
        let encode = Encode {
            reservation,
            cut,
            input,
            budget: capture.budget,
            kept: std::mem::take(&mut capture.kept),
        };
        match owner.encode(encode) {
            Ok(()) => Pass::Encoding { counter },
            Err(encode) => {
                let Encode {
                    reservation,
                    cut,
                    kept,
                    ..
                } = *encode;
                self.counts().kept = kept;
                self.here_mut().release(reservation);
                self.retire(owner, cut);
                self.counts().refused += 1;
                self.planned_pass(Some(counter), Published::Refused);
                Pass::Finishing { counter }
            }
        }
    }

    /// Adopts the encode's terminal, with the set on the owner thread: the stage starts its unit commands, or the
    /// set releases the refused stage's reservation and the pass ends. The tenure keeps the emptied cut's chunks and
    /// the kept unit buffers the stage did not take.
    pub(super) fn encoded(&mut self, counter: u32, encoded: Encoded) -> Pass {
        #[cfg(test)]
        {
            self.counts().encoded_on = encoded.thread;
        }
        let capture = self.counts();
        (capture.spare, capture.kept) = (encoded.cut, encoded.kept);
        match encoded.staged {
            Ok(staged) => Pass::Writing {
                counter,
                staged,
                unit: Unit::Write(0),
                retries: 0,
            },
            Err((refusal, reservation)) => {
                self.here_mut().release(reservation);
                self.stage_refused(counter, refusal)
            }
        }
    }

    /// Ends a pass whose stage was refused: a refused stage counts and reaches the roll, and one refused for
    /// placement sets [`Duties::roll_due`] and leaves the roll unpublished.
    pub(super) fn stage_refused(&mut self, counter: u32, refusal: StageRefusal) -> Pass {
        let placement = matches!(refusal, StageRefusal::Reserve(ReserveRefusal::Placement(_)));
        self.counts().refused += 1;
        self.bound_refused(Some(counter), placement);
        Pass::Finishing { counter }
    }

    /// Stages or adopts one unit command: a write the policy paces, then its read-back. A busy journal cell, an
    /// unavailable buffer, a command the volume does not admit now and a busy capture mutex keep the command for a
    /// later turn. A failed command and a unit that read back unequal are staged again, at most [`UNIT_RETRIES`]
    /// times a unit; past that, and on any other refusal, the pass ends abandoned. Units go in order, so every unit
    /// below the one read back is verified and the read-back checks that unit's flag alone.
    pub(super) fn unit<'a, D: Disk, T: Datagrams<'a>>(
        &mut self,
        owner: &mut Owner<'_, 'a, '_, P, D, T>,
        (counter, mut staged): (u32, StagedCheckpoint),
        (unit, mut retries): (Unit, u32),
        now: u64,
    ) -> Pass {
        if self.stepping {
            // A suffix step or a certify holds the set on the lane. Staging a unit command and ending the stage over
            // the set wait for its return; the volume keeps a unit command's result until the pass takes it.
            return Pass::Writing {
                counter,
                staged,
                unit,
                retries,
            };
        }
        let storage = owner.storage();
        let mut again = |retry: Unit| {
            (retries < UNIT_RETRIES).then(|| {
                retries += 1;
                retry
            })
        };
        let kept = |refused: UnitRefused| match refused {
            UnitRefused::Busy | UnitRefused::Buffer | UnitRefused::Unadmitted => Some(unit),
            UnitRefused::Unreserved | UnitRefused::Range => None,
        };
        let units = staged.units().len() as u32;
        // A halted pass ends at a unit with no command outstanding, so the volume keeps the custody of one it issued.
        if matches!(unit, Unit::Write(_) | Unit::Read(_)) && self.halted(owner) {
            self.end_stage(staged);
            self.release(owner);
            return self.abandon(counter);
        }
        let next = match unit {
            Unit::Write(at) => {
                // The walk took the side list, and no removal saves into it after that.
                if self.counts().policy.unit_due(nanos(now), 0) {
                    let possible = self.here();
                    let written = storage.submit_capture_unit(counter, || {
                        owner.stage_unit_write(possible, &mut staged, at)
                    });
                    match written {
                        Ok(Ok(())) => {
                            let _ = self.counts().policy.submitted(nanos(now));
                            Some(Unit::Written(at))
                        }
                        Ok(Err(refused)) => kept(refused),
                        Err(CaptureError::Unavailable) => Some(unit),
                        Err(_) => None,
                    }
                } else {
                    Some(unit)
                }
            }
            Unit::Read(at) => match owner.stage_unit_read(self.here(), (staged.slot(), at)) {
                Ok(()) => Some(Unit::Reading(at)),
                Err(refused) => kept(refused),
            },
            Unit::Written(at) => match owner.take_unit_for(&mut staged) {
                None => Some(unit),
                Some(UnitDone::Failed { .. }) => again(Unit::Write(at)),
                Some(UnitDone::Written { .. }) => Some(Unit::Read(at)),
                Some(UnitDone::Read { .. }) => {
                    unreachable!("the journal cell holds one unit command: the staged write")
                }
            },
            Unit::Reading(at) => match owner.take_unit_for(&mut staged) {
                None => Some(unit),
                Some(UnitDone::Failed { .. }) => again(Unit::Read(at)),
                Some(UnitDone::Written { .. }) => {
                    unreachable!("the journal cell holds one unit command: the staged read-back")
                }
                Some(UnitDone::Read { .. }) if !staged.unit_verified(at) => again(Unit::Write(at)),
                Some(UnitDone::Read { .. }) if at + 1 == units => {
                    return Pass::Proving { counter, staged };
                }
                Some(UnitDone::Read { .. }) => {
                    retries = 0;
                    Some(Unit::Write(at + 1))
                }
            },
        };
        match next {
            Some(unit) => Pass::Writing {
                counter,
                staged,
                unit,
                retries,
            },
            None => {
                self.end_stage(staged);
                self.abandon(counter)
            }
        }
    }

    /// Mints the pass's proof, reads the capture epoch after it, and submits the Publish over the duties' read. A
    /// pass whose last view failed to read this tenure's shard record, or whose lane holds a job, waits here with
    /// its stage: the Publish goes to an idle lane, as the open's writes and the page jobs do, so a view that falls
    /// due waits behind at most one lane job (POLL-WITHIN-WINDOW).
    fn prove<'a, D: Disk, T: Datagrams<'a>>(
        &mut self,
        owner: &mut Owner<'_, 'a, '_, P, D, T>,
        counter: u32,
        mut staged: StagedCheckpoint,
    ) -> Pass {
        if !self.writing && matches!(self.possible, Set::Here(_)) && self.halted(owner) {
            self.end_stage(staged);
            self.release(owner);
            return self.abandon(counter);
        }
        let here = self.lane.outstanding() == 0
            && self.viewed_tenure
            && matches!(self.possible, Set::Here(_));
        let read = match &self.read {
            Some(read) if here && !self.roll_sealed() => read.clone(),
            _ => return Pass::Proving { counter, staged },
        };
        let storage = owner.storage();
        let tenure = (owner.tenure().shard(), owner.tenure().get());
        let cut = match storage.cut_intact(tenure, counter) {
            Ok(cut) => cut,
            Err(CaptureError::Unavailable) => return Pass::Proving { counter, staged },
            Err(_) => {
                self.end_stage(staged);
                return self.abandon(counter);
            }
        };
        // The module header states why this read satisfies the caller duty of `checkpoint::publish`.
        let epoch = storage.capture_epoch();
        #[cfg(test)]
        let epoch = match STALE_EPOCH.with(std::cell::Cell::get) {
            true => crate::storage::checkpoint::CaptureEpoch(epoch.0.wrapping_sub(1)),
            false => epoch,
        };
        // Every unit read back equal, so the Publish needs no unit bytes, and the tenure keeps the buffers.
        self.keep(staged.take_units());
        let publish = Publish {
            possible: self.take_set(),
            read,
            own: owner.tenure().target(),
            cut,
            epoch,
            staged,
        };
        match self.lane.submit(Job::Publish(Box::new(publish))) {
            Ok(()) => {
                self.writing = true;
                Pass::Publishing { counter }
            }
            Err(job) => {
                let Job::Publish(publish) = *job else {
                    unreachable!("the lane returns the job it refused")
                };
                self.returned(publish.possible);
                Pass::Proving {
                    counter,
                    staged: publish.staged,
                }
            }
        }
    }

    /// Adopts a Publish's completion as the turn's one transition, to `Finishing`. A store error may follow a request that
    /// committed, so the next view's read of this tenure replaces the duties' read, and after a first Publish over a
    /// record that named no checkpoint the open runs again from the view: a Confirm settles the set and the suffix
    /// opens when the Publish committed. A first Publish refused before any request leaves the suffix required and
    /// closed, so the tenure's FILLs and removals refuse until the next pass publishes. A tenure whose open settled
    /// with the log closed runs its open again after this Publish: from `Opening` when the Publish returns
    /// `Ok(read)`, and from the view after a store error, as after a first Publish; a Publish refused before any
    /// request keeps the log closed until a later Publish.
    pub(super) fn published(
        &mut self,
        mut possible: PossiblyNamed,
        staged: StagedCheckpoint,
        published: Result<Read<ShardRecord>, WriteRefused>,
    ) {
        self.writing = false;
        let submitted = staged.named();
        let slot = staged.slot();
        staged.abandon(&mut possible);
        self.returned(possible);
        let prior = (self.read.as_ref()).map(|read| read.value().checkpoint);
        let first = prior.is_some_and(|prior| prior.is_none());
        let capture = self.counts();
        let Pass::Publishing { counter } = capture.pass else {
            unreachable!(
                "PossNamedCoversStore: a Publish completes only the pass that submitted it"
            )
        };
        (capture.pass, capture.landed) = (Pass::Finishing { counter }, true);
        #[cfg(test)]
        {
            capture.refusal = published.as_ref().err().copied();
            capture.published += u64::from(published.is_ok());
        }
        let result = match &published {
            Ok(read) => Published::Acknowledged(*read.value()),
            Err(WriteRefused::Store(_)) => Published::Store,
            Err(_) => Published::Refused,
        };
        let open_again = std::mem::take(&mut self.open_again);
        let capture = self.counts();
        match published {
            Ok(read) => {
                capture.publish_due = false;
                self.read = Some(read);
                self.unsettled = None;
                if first || open_again {
                    self.reopen(Open::Opening);
                }
            }
            Err(refusal) => {
                capture.abandoned += 1;
                if matches!(refusal, WriteRefused::Store(_)) {
                    self.read = None;
                    if let Some(prior) = prior {
                        let unsettled = self.unsettled.get_or_insert(Unsettled {
                            prior,
                            submitted: Vec::new(),
                        });
                        unsettled.submitted.push(submitted);
                    }
                    if first || open_again {
                        self.reopen(Open::Viewing);
                    } else {
                        self.settling = Some(slot);
                    }
                } else {
                    self.open_again = open_again;
                }
            }
        }
        self.planned_pass(Some(counter), result);
    }

    fn halted<'a, D: Disk, T: Datagrams<'a>>(&self, owner: &Owner<'_, 'a, '_, P, D, T>) -> bool {
        self.open == Open::Stopped || closed_to_writes(owner)
    }

    /// Ends the pass, retrying while the capture mutex is busy. A pass the storage already ended ends in the policy.
    /// A pass that started while a publication was due and ended with it still due, its Publish refused or never
    /// submitted, holds the next start one view period, as a refused start does; a publication that came due while
    /// another pass ran starts the next pass on the next turn.
    fn finish<'a, D: Disk, T: Datagrams<'a>>(
        &mut self,
        owner: &Owner<'_, 'a, '_, P, D, T>,
        counter: u32,
        now: u64,
    ) -> Pass {
        let view_us = self.periods.view_us;
        let capture = self.counts();
        match owner.storage().finish_capture(&mut capture.policy, counter) {
            Ok(()) => {}
            Err(CaptureError::Unavailable) => return Pass::Finishing { counter },
            Err(_) => capture.policy.finished(),
        }
        if std::mem::take(&mut capture.serving_due) && capture.publish_due {
            capture.start_at = capture.start_at.max(now.saturating_add(view_us));
        }
        Pass::Idle
    }

    fn abandon(&mut self, counter: u32) -> Pass {
        self.planned_pass(Some(counter), Published::Refused);
        self.counts().abandoned += 1;
        Pass::Finishing { counter }
    }

    /// Takes the set back from a job and refreshes the quarantine gauge.
    pub(super) fn returned(&mut self, possible: PossiblyNamed) {
        self.quarantine = Pressure::unresolved(&possible);
        self.possible = Set::Here(possible);
    }

    fn here_mut(&mut self) -> &mut PossiblyNamed {
        match &mut self.possible {
            Set::Here(possible) => possible,
            Set::Unbuilt | Set::Away => {
                panic!("PossNamedCoversStore: a reservation ends over the set on the owner thread")
            }
        }
    }

    pub(super) fn here(&self) -> &PossiblyNamed {
        match &self.possible {
            Set::Here(possible) => possible,
            Set::Unbuilt | Set::Away => {
                panic!("PossNamedCoversStore: a unit command reads the set on the owner thread")
            }
        }
    }

    /// Ends `staged` over the set, which quarantines its slot once a unit write exposed it, refreshes the gauge, and
    /// keeps the stage's unit buffers for the next encode.
    fn end_stage(&mut self, mut staged: StagedCheckpoint) {
        let units = staged.take_units();
        let mut possible = self.take_set();
        staged.abandon(&mut possible);
        self.returned(possible);
        self.keep(units);
    }

    /// Keeps `units`, an ended stage's buffers, with the kept buffers the stage did not take.
    fn keep(&mut self, mut units: Units) {
        let capture = self.counts();
        units.append(&mut capture.kept);
        capture.kept = units;
    }

    /// Gives the kept unit buffers to the volume's helpers to free; the budget no longer counts them.
    fn release<'a, D: Disk, T: Datagrams<'a>>(&mut self, owner: &mut Owner<'_, 'a, '_, P, D, T>) {
        let units = std::mem::take(&mut self.counts().kept);
        let accepted = owner.discard(Leftovers {
            saved: Vec::new(),
            units,
        });
        self.counts().yielding |= accepted;
    }

    /// Frees the kept unit buffers of a tenure whose open stopped or whose owner's authority withdrew or closed. The
    /// duties call it on each turn that adopts a view's completion, so a halted tenure with no pass running frees
    /// them at its next view.
    pub(super) fn release_halted<'a, D: Disk, T: Datagrams<'a>>(
        &mut self,
        owner: &mut Owner<'_, 'a, '_, P, D, T>,
    ) {
        let kept = (self.capture.as_ref()).is_some_and(|capture| !capture.kept.is_empty());
        if kept && self.halted(owner) {
            self.release(owner);
        }
    }

    /// Empties the copy of a pass that ends before its encode and keeps its chunks for the next walk; the volume's
    /// helpers free its side list.
    fn retire<'a, D: Disk, T: Datagrams<'a>>(
        &mut self,
        owner: &mut Owner<'_, 'a, '_, P, D, T>,
        mut cut: Cut,
    ) {
        let saved = cut.recycle();
        self.counts().spare = cut;
        owner.discard(Leftovers {
            saved,
            units: Vec::new(),
        });
    }
}

/// What one walk turn leaves of the cut's copy: the copy with slots still to visit, the whole cut with the bytes
/// it holds outside the side list's charge, or the copy to empty for a pass that ends abandoned.
pub(super) enum Walked {
    More(Cut),
    Done(Cut, usize),
    Abandoned(Cut),
}

/// The budget a walk turn of `cut` runs under while the tenure keeps `kept` bytes of unit buffers: the capture
/// `budget` with those bytes charged, or `None` when `budget` holds the copy and the turn's reservations
/// ([`Cut::turn_reserve`]) only without them, so the kept buffers yield their bytes.
pub(super) fn turn_budget(budget: EngineBudget, kept: usize, cut: &Cut) -> Option<EngineBudget> {
    let mut held = budget;
    let room = (cut.bytes().saturating_add(cut.turn_reserve())).saturating_add(kept);
    let mut scratch = budget;
    (kept == 0 || scratch.charge(room).is_ok()).then(|| {
        held.charge(kept)
            .expect("the budget holds the kept bytes with the turn's room");
        held
    })
}

/// Visits one batch of slots, then, once the cursor passed the last slot, takes the side list. The copy packs each
/// member into word chunks of a fixed size, so a turn's copy moves no member of an earlier turn, and it reserves a
/// chunk only when the budget holds the copy with it: a copy the budget or the allocator cannot hold ends the pass
/// abandoned. The side list's entries move into the cut under the policy's own charge. The encode later checks the
/// copy and its units together and refuses the stage when they do not fit.
pub(super) fn walk_turn<P: Platform>(
    storage: &crate::storage::Storage<P>,
    budget: EngineBudget,
    counter: u32,
    mut cut: Cut,
) -> Walked {
    let mut copied = true;
    let visited = storage.capture_visit(counter, UNIT_ENTRIES as usize, |entry| {
        copied = copied && cut.push(entry, &budget).is_ok();
    });
    if !copied {
        return Walked::Abandoned(cut);
    }
    let saved = visited.and_then(|walked| match walked {
        0 => storage.capture_saved(counter).map(Some),
        _ => Ok(None),
    });
    match saved {
        Ok(Some(saved)) => {
            cut.save(saved);
            let input = cut.bytes();
            Walked::Done(cut, input)
        }
        Ok(None) | Err(CaptureError::Unavailable) => Walked::More(cut),
        Err(_) => Walked::Abandoned(cut),
    }
}

/// The capture policy's nanoseconds for the duties' turn time `now` in microseconds.
pub(super) fn nanos(now: u64) -> u64 {
    now.saturating_mul(1_000)
}
