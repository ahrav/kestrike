//! The production-volume soak: one owner-thread tool that drives the
//! canonical fill, read, invalidate, release and pressure workload against
//! one [`Volume`], checks every byte it reads against content it generates
//! itself, and keeps every unfinished operation in a bounded ledger.
//!
//! The workload draws each decision through the simulation's choice
//! contract, one recording chooser per window, so a seed fixes the inputs
//! while completions and timing are observed. A window ends once
//! `cut_every` operations settled or [`STEPS_PER_WINDOW`] steps ran, so a
//! device that settles nothing bounds the tape a window records; its cut
//! writes the identities still unresolved, which carry into the next
//! window, and the digest of the window's decision tape. Admission keeps the ledger within its capacity,
//! and each checkpoint requires the storage's lease credits equal to the
//! leases the ledger holds. A ledger at capacity refuses the next operation
//! as inconclusive, drops nothing and cuts the window.
//!
//! The receipt is JSON lines under the shared artifact envelope, section
//! `soak`: one line per cut and one final lifecycle line, each carrying
//! cumulative Cancelled, Stalled and Missing violation counts. The lifecycle
//! line's `session` is the session the volume opened under, zero for a
//! bootstrap that never opened, and its `tenure_session` is the session the
//! run's serving authority holds, taken from the soak store before attach. [`Soak::close`]
//! cuts the window in progress, releases every held lease, polls terminals and overdue reads,
//! requests cancellation of every live read, then closes the
//! volume until it quiesces within its patience; a stop the volume does not
//! prove leaves the receipt counting the commands the table still owns.
//!
//! The soak stands in for the invalidation feed: it gives a feed position only to an
//! invalidation that returned `Ok` and advances coverage to it.

mod bound;
mod monitor;

use monitor::{Publication, Read};
#[cfg(test)]
mod bound_tests;
#[cfg(test)]
mod full_ledger_tests;
#[cfg(test)]
mod monitor_tests;
mod receipt;
mod store;
#[cfg(all(test, target_os = "linux"))]
mod writer_tests;

pub use bound::{BoundConfig, SMOKE_BOUND, soak_bound};
pub use receipt::open_receipt;
pub use store::STORE_DIR;
#[cfg(test)]
pub(crate) use store::{recorded_tenure_authority, tenure_authority};

use std::io::Write;
use std::num::NonZeroU8;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::sim::action::ActionKind as Action;
use crate::sim::choice::{Candidate, Chooser, Domain, Site};
use crate::storage::{
    BeginError, Decision, Disk, ExtentLease, FillPublishError, FillReserveError, InvalidateError,
    LookupError, MaintainError, MaintainReport, MetadataOutcome, Platform, QuiesceProgress,
    ReadEvent, ReadOp, ReadRefusal, ReadStatus, ReceiveError, Refusal, RefusalReason, Registration,
    RemovedMember, Storage, SubmitRefusal, Volume, WorkBudget, WritableFill,
};

/// The actions the soak draws among, in code order, the order the chooser's candidates require.
const WORKLOAD: [Action; 6] = [
    Action::Fill,
    Action::Acquire,
    Action::Read,
    Action::Release,
    Action::Invalidate,
    Action::Pressure,
];

fn candidate(action: Action) -> Candidate {
    let mut bytes = [0u8; 16];
    bytes[0] = action as u8;
    Candidate(bytes)
}

const ACTOR: u16 = 1;
const fn site(site: u16) -> Site {
    Site {
        domain: Domain::Workload,
        actor: ACTOR,
        site,
    }
}
const ACTION: Site = site(1);
const KEY: Site = site(2);
const LENGTH: Site = site(3);
const TRIES: usize = 4;
/// Steps a window holds at most; each step records up to three decisions.
pub const STEPS_PER_WINDOW: u32 = 4096;

#[derive(Debug, Clone, Copy)]
pub struct SoakConfig {
    pub seed: u64,
    /// Keys the workload spans, each `key(n)` for `n` below it.
    pub keys: NonZeroU8,
    /// The largest body a fill draws; every fill carries no metadata.
    pub body_cap: usize,
    /// Ledger capacity: held leases, live reads and the open fill at once.
    pub capacity: usize,
    /// Leases the soak holds at most, below `capacity`.
    pub pressure: usize,
    /// Settled operations per window.
    pub cut_every: u32,
    /// How long each read's verdict, one fill's writes, the close's read
    /// drain, its quiesce, or the controller's disable may each take. Read
    /// deadlines use microseconds since the run began.
    pub patience: Duration,
}

/// The workload the tool and the hardware smoke run.
pub const SMOKE: SoakConfig = SoakConfig {
    seed: 1,
    keys: NonZeroU8::new(32).unwrap(),
    body_cap: 200_000,
    capacity: 12,
    pressure: 4,
    cut_every: 64,
    patience: Duration::from_secs(30),
};

pub fn key(n: u8) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[..8].copy_from_slice(b"soak-key");
    key[31] = n;
    key
}

/// Generation `generation` of key `n`, `len` bytes: a function of the three only.
pub fn content(n: u8, generation: u32, len: usize) -> Vec<u8> {
    let mut state = (u64::from(n) << 32 | u64::from(generation)) ^ 0x9E37_79B9_7F4A_7C15;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect()
}

/// Why a soak failed; the first failure ends it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoakFailure {
    /// A complete read of key `key` returned bytes other than its generation's content.
    Bytes { key: u8, generation: u32 },
    /// A Cancelled terminal; the soak authorizes one through its own
    /// accepted `cancel_read` request on that exact read.
    Cancelled { run: u64, id: u64, op: ReadOp },
    /// A live read whose deadline sweep recorded an overdue verdict.
    /// `deadline` is microseconds since the run began.
    Stalled {
        run: u64,
        id: u64,
        op: ReadOp,
        deadline: u64,
    },
    /// A missing publication whose residency obligation still holds.
    Missing { key: u8, generation: u32 },
    /// A read of a published key ended neither complete nor cancelled.
    Read { key: u8, status: ReadStatus },
    /// The volume refused a read of a published key with `refusal`;
    /// exhausted read operations, exhausted response buffers, a full command
    /// table and a full device queue are the refusals the soak absorbs.
    Refused { key: u8, refusal: ReadRefusal },
    /// The storage refused to begin a fill of key `key` with `error`. A
    /// key's attempt in progress and full fill slots are the refusals the
    /// soak retries later; the soak's one thread holds no gate between its
    /// calls, so a contended gate is a poisoned one.
    Begin { key: u8, error: BeginError },
    /// A fill's admission, reservation, receive or publication was refused,
    /// its write failed, or it did not finish within the patience. A full
    /// volume, a full table or pool, the lease limit and a full index are
    /// the refusals the soak retries later.
    Fill { key: u8 },
    /// A lookup of a published key failed with `error`. The lease and retain
    /// limits are refusals a later step retries. A Missing lookup is judged
    /// against the publication's residency obligation.
    Lookup { key: u8, error: LookupError },
    /// An invalidation of a published key failed with `error`; an unpaid
    /// budget is the refusal a later step retries.
    Invalidate { key: u8, error: InvalidateError },
    /// A coverage advance to the last assigned feed position refused with `error` while the storage was open.
    Coverage {
        error: crate::storage::CoverageError,
    },
    /// The storage's lease credits disagreed with the leases the ledger holds
    /// and the credit its live fill holds.
    Credits {
        leases: usize,
        reported: Option<usize>,
    },
    /// A read ended that the ledger did not hold.
    Untracked,
    /// The ledger was full; the run proves nothing past that point.
    Inconclusive,
    /// The volume's bootstrap refused, its format failed, or a metadata write failed for good, with this outcome.
    Metadata { outcome: MetadataOutcome },
    /// The volume reached `Readiness::Withheld` while storage admission remained open, ending the soak.
    Withheld,
    /// The serving authority never reached `Serving`, so the volume admitted no fill or read and the run proves
    /// nothing; it replaces a failure [`follows_from_not_serving`](Self::follows_from_not_serving) names and leaves
    /// every other failure.
    NeverServing,
    /// Maintenance found its root gate poisoned, an inner gate busy or
    /// poisoned, a table malformed or a commit contended `contended` times,
    /// or its expiry sweep drew no clock sample. The soak's one thread holds
    /// no gate while it maintains, so the count is poisoned or malformed
    /// state. Maintenance's other refusals pass without failing the run.
    Maintenance {
        contended: usize,
        clock_unavailable: bool,
    },
    /// A SIGTERM ended the run before its duration; the run proves nothing
    /// past that point.
    Interrupted,
    /// The receipt could not be written.
    Receipt,
}

impl SoakFailure {
    /// Whether a volume that never reached `Serving` explains this failure: it admits no fill and no read, so a fill
    /// refused by the volume, a refused or incomplete read, or a lookup or invalidation that finds no published key
    /// follow from it. A storage-level begin refusal, bytes that differ, a Cancelled terminal, a stalled read, a
    /// missing publication, or a coverage, ledger, bootstrap, withdrawal, maintenance, interrupt or receipt failure
    /// stands on its own: each of the three monitor failures names a read or a publication the volume admitted.
    pub fn follows_from_not_serving(&self) -> bool {
        match self {
            Self::Fill { .. }
            | Self::Read { .. }
            | Self::Refused { .. }
            | Self::Lookup { .. }
            | Self::Invalidate { .. } => true,
            Self::Bytes { .. }
            | Self::Cancelled { .. }
            | Self::Stalled { .. }
            | Self::Missing { .. }
            | Self::Begin { .. }
            | Self::Coverage { .. }
            | Self::Credits { .. }
            | Self::Untracked
            | Self::Inconclusive
            | Self::Metadata { .. }
            | Self::Withheld
            | Self::NeverServing
            | Self::Maintenance { .. }
            | Self::Interrupted
            | Self::Receipt => false,
        }
    }

    /// The operator step a failure needs before another run on the same volume can pass.
    pub fn remedy(&self) -> Option<&'static str> {
        match self {
            Self::Metadata {
                outcome: MetadataOutcome::FormatMismatch,
            } => Some(
                "the volume's root slots record another metadata layout or format. Zeroing both root slots, the volume's first two metadata blocks, discards its recovery state and every object its payload holds, so zero them only for a volume whose contents may go, while kestrike-bind --release has returned it to its kernel driver, and only under the soak store that last attached the volume: the next run formats it under that store's next session, which is above every session its leftover payload records carry. A volume this store did not last attach is replaced, and its replacement takes a new state directory",
            ),
            Self::Metadata {
                outcome: MetadataOutcome::StaleSession,
            } => Some(
                "a valid root slot holds a session at or above the one this run took from the soak store in the state directory's soak-store directory. That store must stay with the volume for the volume's whole life: restore the store that last attached this volume. A volume whose roots a binary wrote with medium-derived generations, or whose store is lost, is replaced, and its replacement takes a new state directory; zeroing the root slots leaves its payload records under sessions a new store would issue again",
            ),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inconclusive {
    /// The ledger was full; the soak admitted nothing further.
    Ledger,
}

struct Filling<'s, 'a, P: Platform> {
    id: u64,
    fill: WritableFill<'s, 'a, P>,
    key: u8,
    generation: u32,
    taken: usize,
    bytes: Vec<u8>,
    begun: Instant,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Witnesses {
    /// A read the volume refused because every read operation was live.
    pub queue_full: bool,
    /// A read still live across a cut.
    pub held_read: bool,
    /// Maintenance evicted to keep the volume's headroom, or a fill's reservation met a full volume, full object slots or a full index.
    pub near_capacity: bool,
    /// A fill and its exact read after a pressure's leases released.
    pub healed: bool,
    /// The serving authority reached `Serving` at some poll.
    pub served: bool,
}

/// How a soak's close ended.
pub enum Closed<'s, 'a, P: Platform, D: Disk> {
    /// The volume quiesced with every obligation settled.
    Drained(Volume<'s, 'a, P, D>),
    /// The volume's stop stayed unproven; it keeps the custody the receipt names.
    Retained(Volume<'s, 'a, P, D>),
}

pub struct Ended<'s, 'a, P: Platform, D: Disk, W> {
    pub closed: Closed<'s, 'a, P, D>,
    pub failure: Option<SoakFailure>,
    pub receipt: W,
}

/// One soak over one storage and its volume.
pub struct Soak<'s, 'a, P: Platform, D: Disk, W: Write> {
    storage: &'s Storage<P>,
    volume: Volume<'s, 'a, P, D>,
    reader: Registration<'s, P>,
    config: SoakConfig,
    receipt: W,
    started: Instant,
    chooser: Chooser,
    window: u64,
    settled: u32,
    /// Steps since the last cut.
    stepped: u32,
    /// Each key's expected content and publication allocation, with its
    /// residency obligation. With `fingerprints`, the allocation names the
    /// exact publication.
    published: Vec<Option<Publication>>,
    /// Each key's index fingerprint, derived once in `Soak::new`, or `0` when
    /// [`Storage::route`] returns `None` (an unindexed or drained storage,
    /// or one with every shard disabled). The soak's shared borrow of the
    /// storage keeps its keyed hash state fixed, so one derivation serves
    /// every publication of the key.
    fingerprints: Vec<u64>,
    next_generation: u32,
    next_id: u64,
    /// The ledger: every held lease and live read, each with its identity,
    /// and the open fill in `filling`.
    leases: Vec<(u64, ExtentLease<'s, P>)>,
    pub(crate) reads: Vec<Read>,
    filling: Option<Filling<'s, 'a, P>>,
    witnesses: Witnesses,
    pressured: bool,
    aborted_fill: bool,
    heal: Option<u64>,
    refused: u64,
    /// The feed position of the last invalidation that returned `Ok`: positions go only to those, in order, so every lower one returned `Ok` and the soak advances coverage to each as it is assigned.
    feed: u64,
    failure: Option<SoakFailure>,
    cancelled: u64,
    stalled: u64,
    missing: u64,
    #[cfg(test)]
    clock: Option<u64>,
    #[cfg(test)]
    observe_cancel: Option<fn(&Read)>,
    events: Vec<ReadEvent<'a>>,
    /// The simulated device each poll ticks.
    #[cfg(test)]
    pub(crate) device: Option<crate::storage::owner_fixture::SimControl>,
    /// The work budget an invalidation gets in place of the soak's own, so a test can exhaust it.
    #[cfg(test)]
    pub(crate) invalidation_budget: Option<usize>,
}

/// Window `window`'s recording chooser, its one actor launched.
fn window_chooser(seed: u64, window: u64) -> Chooser {
    let mut chooser = Chooser::record(seed ^ window, &[ACTION, KEY, LENGTH]);
    chooser.launch(ACTOR);
    chooser
}

fn budget() -> WorkBudget {
    WorkBudget::new(1 << 16)
}

impl<'s, 'a, P: Platform, D: Disk, W: Write> Soak<'s, 'a, P, D, W> {
    pub fn new(
        storage: &'s Storage<P>,
        volume: Volume<'s, 'a, P, D>,
        reader: Registration<'s, P>,
        config: SoakConfig,
        receipt: W,
    ) -> Self {
        Self {
            storage,
            volume,
            reader,
            config,
            receipt,
            started: Instant::now(),
            chooser: window_chooser(config.seed, 0),
            window: 0,
            settled: 0,
            stepped: 0,
            published: (0..config.keys.get()).map(|_| None).collect(),
            fingerprints: (0..config.keys.get())
                .map(|n| {
                    storage
                        .route(&key(n))
                        .map_or(0, |route| route.fingerprint())
                })
                .collect(),
            next_generation: 0,
            next_id: 0,
            leases: Vec::with_capacity(config.capacity),
            reads: Vec::with_capacity(config.capacity),
            witnesses: Witnesses::default(),
            pressured: false,
            aborted_fill: false,
            heal: None,
            filling: None,
            refused: 0,
            feed: 0,
            failure: None,
            cancelled: 0,
            stalled: 0,
            missing: 0,
            #[cfg(test)]
            clock: None,
            #[cfg(test)]
            observe_cancel: None,
            events: Vec::with_capacity(8),
            #[cfg(test)]
            device: None,
            #[cfg(test)]
            invalidation_budget: None,
        }
    }

    pub fn failure(&self) -> Option<SoakFailure> {
        self.failure
    }

    pub fn witnesses(&self) -> Witnesses {
        self.witnesses
    }

    pub fn windows(&self) -> u64 {
        self.window
    }

    /// The last assigned feed position.
    #[cfg(test)]
    pub(crate) fn feed(&self) -> u64 {
        self.feed
    }

    /// Whether key `n` holds a published generation.
    #[cfg(test)]
    pub(crate) fn is_published(&self, n: u8) -> bool {
        self.published[usize::from(n)].is_some()
    }

    /// Ledger entries now, each a held lease, a live read or the open fill.
    pub fn unsettled(&self) -> usize {
        self.leases.len() + self.reads.len() + usize::from(self.filling.is_some())
    }

    pub fn unresolved(&self) -> Vec<u64> {
        let leases = self.leases.iter().map(|&(id, _)| id);
        let reads = self.reads.iter().map(|read| read.id);
        leases
            .chain(reads)
            .chain(self.filling.as_ref().map(|filling| filling.id))
            .collect()
    }

    /// Changes what the soak expects of key `n`, so its next complete read mismatches.
    #[cfg(test)]
    pub(crate) fn misremember(&mut self, n: u8, generation: u32, len: usize) {
        if let Some(expected) = &mut self.published[usize::from(n)] {
            expected.generation += generation;
            expected.len += len;
        }
    }

    fn fail(&mut self, failure: SoakFailure) {
        self.failure.get_or_insert(failure);
    }

    /// Records that a SIGTERM ended the run, so the run fails as
    /// [`SoakFailure::Interrupted`] and its receipt says so.
    pub fn interrupt(&mut self) {
        self.fail(SoakFailure::Interrupted);
    }

    fn room(&self) -> Result<(), Inconclusive> {
        if self.unsettled() >= self.config.capacity {
            return Err(Inconclusive::Ledger);
        }
        Ok(())
    }

    fn admit(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }

    fn choose(&mut self, site: Site, bound: u64) -> u64 {
        self.chooser.bounded(site, 0, bound).unwrap_or(0)
    }

    /// Draws and runs one action, then polls the volume; at `cut_every`
    /// settled operations or [`STEPS_PER_WINDOW`] steps, checks the ledger
    /// and cuts the window.
    ///
    /// # Errors
    ///
    /// `Inconclusive` when the ledger refused the action; the soak then
    /// fails as [`SoakFailure::Inconclusive`], since it proves nothing past
    /// that point.
    pub fn step(&mut self) -> Result<(), Inconclusive> {
        let action = self
            .chooser
            .index(ACTION, 0, &WORKLOAD.map(candidate))
            .map_or(Action::Read, |at| WORKLOAD[at]);
        let n = self.choose(KEY, u64::from(self.config.keys.get())) as u8;
        let outcome = match action {
            Action::Fill => self.fill(n),
            Action::Read => self.read(n),
            Action::Acquire => self.acquire(n),
            Action::Release => self.release(1),
            Action::Invalidate => self.invalidate(n),
            _ => self.pressure(n),
        };
        self.poll();
        self.stepped += 1;
        if outcome.is_err() {
            self.refused += 1;
            self.fail(SoakFailure::Inconclusive);
        }
        if self.settled >= self.config.cut_every
            || self.stepped >= STEPS_PER_WINDOW
            || outcome.is_err()
        {
            self.checkpoint();
        }
        outcome
    }

    pub(crate) fn fill(&mut self, n: u8) -> Result<(), Inconclusive> {
        if self.published[usize::from(n)].is_some() || self.filling.is_some() {
            return Ok(());
        }
        self.room()?;
        let len = 1 + self.choose(LENGTH, self.config.body_cap as u64) as usize;
        let generation = self.next_generation;
        self.next_generation += 1;
        let attempt = match self.storage.begin_fill(
            &key(n),
            crate::storage::CacheVersion(0),
            TRIES,
            &mut budget(),
        ) {
            Ok(attempt) => attempt,
            Err(BeginError::InProgress | BeginError::FillSlotsFull) => {
                return Ok(());
            }
            Err(error) => {
                self.fail(SoakFailure::Begin { key: n, error });
                return Ok(());
            }
        };
        let Decision::Admit(admitted) = self.storage.decide_admission(Some(0), Some(len)) else {
            self.fail(SoakFailure::Fill { key: n });
            return Ok(());
        };
        let fill = match attempt.reserve_storage(admitted, Some(0), Some(len), TRIES, &mut budget())
        {
            Ok(fill) => fill,
            Err(
                FillReserveError::ObjectSlotsFull
                | FillReserveError::PayloadFull
                | FillReserveError::CleanReserve
                | FillReserveError::IndexFull,
            ) => {
                self.witnesses.near_capacity = true;
                return Ok(());
            }
            Err(
                FillReserveError::RetiredPressure
                | FillReserveError::LeaseLimit
                | FillReserveError::Bootstrapping,
            ) => return Ok(()),
            Err(_) => {
                self.fail(SoakFailure::Fill { key: n });
                return Ok(());
            }
        };
        self.filling = Some(Filling {
            id: self.admit(),
            fill,
            key: n,
            generation,
            taken: 0,
            bytes: content(n, generation, len),
            begun: Instant::now(),
        });
        Ok(())
    }

    /// Streams the open fill's bytes and publishes it once its writes completed.
    fn advance(&mut self) {
        let Some(mut filling) = self.filling.take() else {
            return;
        };
        let progress = filling.fill.progress(&self.volume);
        if progress.failed || filling.begun.elapsed() > self.config.patience {
            self.fail(SoakFailure::Fill { key: filling.key });
            filling.fill.abort();
            self.settled += 1;
            return;
        }
        if !progress.is_ready() {
            if progress.submitted_units < progress.len_units {
                match filling.fill.receive(
                    &mut self.volume,
                    &filling.bytes[filling.taken..],
                    &mut WorkBudget::with_io(0, usize::MAX, usize::MAX),
                ) {
                    Ok(count) => filling.taken += count,
                    Err(
                        ReceiveError::PoolExhausted
                        | ReceiveError::TableFull
                        | ReceiveError::Bootstrapping
                        | ReceiveError::Budget(_),
                    ) => {}
                    Err(_) => {
                        self.fail(SoakFailure::Fill { key: filling.key });
                        filling.fill.abort();
                        self.settled += 1;
                        return;
                    }
                }
            }
            self.filling = Some(filling);
            return;
        }
        let (n, len) = (filling.key, filling.bytes.len());
        match filling
            .fill
            .publish(&mut self.volume, u64::MAX, TRIES, &mut budget())
        {
            Ok(lease) => {
                self.published[usize::from(n)] = Some(Publication {
                    generation: filling.generation,
                    len,
                    allocation: lease.id(),
                    resident: true,
                });
                drop(lease);
                if self.pressured && self.unsettled() == 0 {
                    self.pressured = false;
                    self.settled += 1;
                    if self.read(n).is_ok() {
                        self.heal = self.reads.last().map(|read| read.id);
                    }
                    return;
                }
            }
            Err(FillPublishError::IndexFull) => {}
            Err(_) => self.fail(SoakFailure::Fill { key: n }),
        }
        self.settled += 1;
    }

    fn lookup(&mut self, n: u8) -> Option<ExtentLease<'s, P>> {
        match self.reader.lookup(&key(n), TRIES, &mut budget()) {
            Ok(lease) => Some(lease),
            Err(LookupError::Missing) => {
                if let Some(Publication {
                    generation,
                    resident: true,
                    ..
                }) = &self.published[usize::from(n)]
                {
                    let generation = *generation;
                    self.missing += 1;
                    self.fail(SoakFailure::Missing { key: n, generation });
                }
                self.published[usize::from(n)] = None;
                None
            }
            Err(LookupError::LeaseLimit | LookupError::RetainLimit) => None,
            Err(error) => {
                self.fail(SoakFailure::Lookup { key: n, error });
                None
            }
        }
    }

    fn acquire(&mut self, n: u8) -> Result<(), Inconclusive> {
        if self.published[usize::from(n)].is_none() || self.leases.len() >= self.config.pressure {
            return Ok(());
        }
        self.room()?;
        if let Some(lease) = self.lookup(n) {
            let id = self.admit();
            self.leases.push((id, lease));
        }
        Ok(())
    }

    fn read(&mut self, n: u8) -> Result<(), Inconclusive> {
        let Some(Publication {
            generation, len, ..
        }) = &self.published[usize::from(n)]
        else {
            return Ok(());
        };
        let (generation, len) = (*generation, *len);
        self.room()?;
        let Some(lease) = self.lookup(n) else {
            return Ok(());
        };
        match self.volume.read(lease, u64::MAX) {
            Ok(op) => {
                let id = self.admit();
                let admitted_at = self.now();
                let patience = u64::try_from(self.config.patience.as_micros()).unwrap_or(u64::MAX);
                self.reads.push(Read {
                    id,
                    run: self.volume.session(),
                    op,
                    admitted_at,
                    deadline: admitted_at.saturating_add(patience),
                    cancellation: None,
                    stalled: false,
                    key: n,
                    generation,
                    len,
                    bytes: Vec::with_capacity(len),
                });
            }
            Err(refused) => match refused.refusal {
                ReadRefusal::OpsExhausted => self.witnesses.queue_full = true,
                ReadRefusal::PoolExhausted => {}
                ReadRefusal::Submit(
                    Refusal::TableFull { .. }
                    | Refusal::Device(SubmitRefusal {
                        reason: RefusalReason::QueueFull,
                        ..
                    }),
                ) => {}
                refusal => self.fail(SoakFailure::Refused { key: n, refusal }),
            },
        }
        Ok(())
    }

    /// Releases the `count` oldest held leases.
    fn release(&mut self, count: usize) -> Result<(), Inconclusive> {
        let count = count.min(self.leases.len());
        self.leases.drain(..count);
        self.settled += count as u32;
        Ok(())
    }

    pub(crate) fn invalidate(&mut self, n: u8) -> Result<(), Inconclusive> {
        if self.published[usize::from(n)].is_none() {
            return Ok(());
        }
        #[cfg(test)]
        let mut budget = self
            .invalidation_budget
            .map_or_else(budget, WorkBudget::new);
        #[cfg(not(test))]
        let mut budget = budget();
        match self.storage.invalidate(&key(n), TRIES, &mut budget) {
            Ok(_) => {
                self.published[usize::from(n)] = None;
                self.settled += 1;
                self.assign();
            }
            Err(InvalidateError::BudgetExhausted) => {}
            Err(error) => self.fail(SoakFailure::Invalidate { key: n, error }),
        }
        Ok(())
    }

    /// An open storage over a present device refuses `Closed` only once its epoch count is exhausted, which fails the run.
    fn assign(&mut self) {
        self.feed += 1;
        match self.storage.advance_coverage(self.feed) {
            Ok(_) => {}
            Err(crate::storage::CoverageError::Closed)
                if self.storage.is_closed() || self.volume.is_lost() => {}
            Err(error) => self.fail(SoakFailure::Coverage { error }),
        }
    }

    /// Tops the held leases up to `pressure` with key `n`, issues reads until
    /// the ledger, the volume's read operations or 64 new ledger identities,
    /// the acquired leases included, stop them, then releases the leases; the
    /// next fill into an empty ledger heals.
    pub(crate) fn pressure(&mut self, n: u8) -> Result<(), Inconclusive> {
        let before = self.next_id;
        for _ in 0..self.config.pressure {
            self.acquire(n)?;
        }
        while self.room().is_ok() && self.next_id - before < 64 {
            let issued = self.next_id;
            self.read(n)?;
            if self.next_id == issued {
                break;
            }
        }
        self.release(self.leases.len())?;
        self.pressured |= self.next_id != before;
        Ok(())
    }

    /// The soak volume's metadata outcome.
    #[cfg(test)]
    pub(crate) fn metadata_outcome(&self) -> MetadataOutcome {
        self.volume.metadata_outcome()
    }

    fn check_metadata(&mut self) {
        if self.volume.readiness() == crate::storage::Readiness::Withheld
            && !self.storage.is_closed()
            && !self.volume.is_lost()
        {
            self.fail(SoakFailure::Withheld);
            return;
        }
        let outcome = match self.volume.metadata_outcome() {
            MetadataOutcome::Unformatted => self.volume.format().err(),
            // The soak subscribes to its storage's own feed from its first position once the RESET path's load completes.
            MetadataOutcome::Open
                if self.volume.readiness() == crate::storage::Readiness::Loaded =>
            {
                let feed = self.volume.storage().feed_contract();
                let _ = self.volume.begin_replay(feed, 0);
                None
            }
            MetadataOutcome::Bootstrapping | MetadataOutcome::Open => None,
            outcome => Some(outcome),
        };
        if let Some(outcome) = outcome {
            self.fail(SoakFailure::Metadata { outcome });
        }
    }

    pub fn poll(&mut self) {
        #[cfg(test)]
        if let Some(device) = &self.device {
            device.tick(64);
        }
        let mut report = MaintainReport::default();
        match self.storage.maintain_into(&mut budget(), &mut report) {
            Ok(None) => {
                self.witnesses.near_capacity |= report.evicted > 0;
                // `removed` holds this call's removals in its first
                // `evicted + expired` entries, so a call with both counts
                // zero skips the residency scan.
                if report.evicted + report.expired > 0 {
                    for removed in report.removed.into_iter().flatten() {
                        self.removed(removed);
                    }
                }
                if report.contended > 0 || report.clock_unavailable {
                    self.fail(SoakFailure::Maintenance {
                        contended: report.contended,
                        clock_unavailable: report.clock_unavailable,
                    });
                }
            }
            Err(MaintainError::Poisoned) => self.fail(SoakFailure::Maintenance {
                contended: 1,
                clock_unavailable: false,
            }),
            Ok(Some(_)) | Err(_) => {}
        }
        self.advance();
        let now = self.now();
        let mut events = std::mem::take(&mut self.events);
        self.volume.poll_storage(now, &mut events);
        self.witnesses.served |=
            self.volume.authority_state() == crate::failover::serving::State::Serving;
        for event in events.drain(..) {
            match event {
                ReadEvent::Chunk { op, chunk, .. } => {
                    if let Some(read) = self.reads.iter_mut().find(|read| read.op == op) {
                        read.bytes.extend_from_slice(chunk.bytes());
                    }
                    drop(chunk);
                    let _ = self.volume.grant_read(op);
                }
                ReadEvent::Done { op, status, .. } => self.done(op, status),
            }
        }
        self.events = events;
        self.check_metadata();
        // Terminals retire obligations before the same boundary sweeps deadlines.
        self.overdue(now);
    }

    fn now(&self) -> u64 {
        #[cfg(test)]
        if let Some(now) = self.clock {
            return now;
        }
        u64::try_from(self.started.elapsed().as_micros()).unwrap_or(u64::MAX)
    }

    /// Ends the residency obligation of each publication whose key's
    /// fingerprint and allocation both equal `removed`'s. The scan compares
    /// `fingerprints` first and reads a key's publication only on a
    /// fingerprint match.
    fn removed(&mut self, removed: RemovedMember) {
        for (fingerprint, publication) in self.fingerprints.iter().zip(&mut self.published) {
            if *fingerprint == removed.fingerprint
                && let Some(publication) = publication
                && publication.allocation == removed.allocation
            {
                publication.resident = false;
            }
        }
    }

    fn overdue(&mut self, now: u64) {
        for read in &mut self.reads {
            debug_assert!(read.deadline >= read.admitted_at);
            if now >= read.deadline && !read.stalled {
                read.stalled = true;
                self.stalled += 1;
                self.failure.get_or_insert(SoakFailure::Stalled {
                    run: read.run,
                    id: read.id,
                    op: read.op,
                    deadline: read.deadline,
                });
            }
        }
    }

    fn cancel(&mut self, at: usize) {
        let read = &mut self.reads[at];
        #[cfg(test)]
        if let Some(observe) = self.observe_cancel {
            observe(read);
        }
        read.cancellation = Some(self.volume.cancel_read(read.op));
    }

    fn done(&mut self, op: ReadOp, status: ReadStatus) {
        let Some(at) = self.reads.iter().position(|read| read.op == op) else {
            self.fail(SoakFailure::Untracked);
            return;
        };
        if status == ReadStatus::Cancelled && self.reads[at].cancellation != Some(Ok(())) {
            let read = &self.reads[at];
            let failure = SoakFailure::Cancelled {
                run: read.run,
                id: read.id,
                op,
            };
            self.cancelled += 1;
            self.fail(failure);
        }
        let read = self.reads.swap_remove(at);
        let (key, generation) = (read.key, read.generation);
        match status {
            ReadStatus::Complete if read.bytes == content(key, generation, read.len) => {
                if self.heal == Some(read.id) {
                    self.witnesses.healed = true;
                }
            }
            ReadStatus::Complete => self.fail(SoakFailure::Bytes { key, generation }),
            ReadStatus::Cancelled => {}
            status => self.fail(SoakFailure::Read { key, status }),
        }
        self.settled += 1;
    }

    /// Checks the ledger against the storage's own counts and cuts the window.
    pub fn checkpoint(&mut self) {
        if !self.reads.is_empty() {
            self.witnesses.held_read = true;
        }
        // A live fill holds two `Shared` credits, the publisher's and its
        // terminal read right's, until it ends; its first lease takes the
        // publisher's, and with no follower joined the other returns.
        let leases =
            self.leases.len() + crate::storage::FILL_CREDITS * usize::from(self.filling.is_some());
        let reported = self.storage.lease_report().map(|report| report.reserved);
        if reported != Some(leases) {
            self.fail(SoakFailure::Credits { leases, reported });
        }
        let chooser = std::mem::replace(
            &mut self.chooser,
            window_chooser(self.config.seed, self.window + 1),
        );
        let tape = Sha256::digest(chooser.recorded());
        let unresolved: Vec<String> = self.unresolved().iter().map(u64::to_string).collect();
        let line = format!(
            "{{\"envelope\": {{\"version\": 1, \"section\": \"soak\"}}, \"soak\": {{\"cut\": {}, \"settled\": {}, \"unresolved\": [{}], \"capacity\": {}, \"leases\": {}, \"credits_reported\": {}, \"tape_sha256\": \"{}\", \"cancelled\": {}, \"stalled\": {}, \"missing\": {}}}}}",
            self.window,
            self.settled,
            unresolved.join(", "),
            self.config.capacity,
            leases,
            reported.map_or_else(|| "null".to_owned(), |reported| reported.to_string()),
            tape.iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            self.cancelled,
            self.stalled,
            self.missing,
        );
        if writeln!(self.receipt, "{line}").is_err() {
            self.fail(SoakFailure::Receipt);
        }
        self.window += 1;
        self.settled = 0;
        self.stepped = 0;
    }

    /// Cuts the window the steps since the last cut make, releases every
    /// held lease and polls terminals and overdue reads, then requests
    /// cancellation of every live read and drains them, then closes the
    /// volume until it quiesces within a fresh `patience` window, and writes
    /// the final lifecycle line, which names the remaining logical records
    /// and physical commands.
    pub fn close(mut self) -> Ended<'s, 'a, P, D, W> {
        if self.stepped > 0 {
            self.checkpoint();
        }
        let _ = self.release(self.leases.len());
        if let Some(filling) = self.filling.take() {
            filling.fill.abort();
            self.aborted_fill = true;
        }
        self.poll();
        for at in 0..self.reads.len() {
            self.cancel(at);
        }
        let begun = Instant::now();
        while !self.reads.is_empty() && begun.elapsed() < self.config.patience {
            self.poll();
        }
        let begun = Instant::now();
        let quiesced = loop {
            if matches!(self.volume.close(), QuiesceProgress::Quiesced(_)) {
                break true;
            }
            if begun.elapsed() > self.config.patience {
                break false;
            }
            self.poll();
        };
        if !self.witnesses.served
            && self
                .failure
                .as_ref()
                .is_none_or(SoakFailure::follows_from_not_serving)
        {
            self.failure = Some(SoakFailure::NeverServing);
        }
        let drained = quiesced && self.unsettled() == 0;
        let lifecycle = if drained { "drained" } else { "retained" };
        let table = self.volume.table_report();
        let clock = self.volume.report().clock;
        let line = format!(
            "{{\"envelope\": {{\"version\": 1, \"section\": \"soak\"}}, \"soak\": {{\"lifecycle\": \"{lifecycle}\", \"session\": {}, \"tenure_session\": {}, \"windows\": {}, \"refused\": {}, \"aborted_fill\": {}, \"unsettled\": {}, \"reads\": {}, \"commands_pending\": {}, \"commands_abandoned\": {}, \"clock_trust\": \"{:?}\", \"absent_expiry\": {}, \"failure\": \"{:?}\", \"witnesses\": \"{:?}\", \"cancelled\": {}, \"stalled\": {}, \"missing\": {}}}}}",
            self.volume.session(),
            self.volume.tenure_session(),
            self.window,
            self.refused,
            self.aborted_fill,
            self.unsettled(),
            self.reads.len(),
            table.pending,
            table.abandoned,
            clock.trust,
            clock.absent.total(),
            self.failure,
            self.witnesses,
            self.cancelled,
            self.stalled,
            self.missing,
        );
        if writeln!(self.receipt, "{line}")
            .and_then(|()| self.receipt.flush())
            .is_err()
        {
            self.fail(SoakFailure::Receipt);
        }
        Ended {
            closed: if drained {
                Closed::Drained(self.volume)
            } else {
                Closed::Retained(self.volume)
            },
            failure: self.failure,
            receipt: self.receipt,
        }
    }
}
