//! Chaos points: named places inside production functions where a test
//! build asks one seeded yes-or-no question, and a yes makes the function
//! return a legal rare outcome, such as a lock attempt that finds its lock
//! busy on one thread.
//!
//! [`chaos!`] is the only way production code asks. Outside test builds it
//! expands to the literal `false`, so the asking function compiles to what
//! it is with no point, and this module holds the macro alone. In a test
//! build the macro calls `fire`, which answers `false` until a run arms
//! the points on its thread.
//!
//! A run arms the points for its turn loop and runs each production action
//! its turns select inside `acting`. An armed point is one bounded decision
//! per reach inside an action, made by the run's chooser at the point's own
//! site in the [`Domain::Chaos`] domain for the armed actor's current
//! incarnation, with the point's odds as the bound. The point fires exactly
//! when the decision selects 0. A reach outside every action, such as a
//! harness check between turns, decides nothing. Each decision lands on the
//! run's tape, so a bundle of an armed run replays its fires, and `census`
//! counts each point's reaches and fires from a tape alone. A refused
//! decision, or a chooser the harness holds borrowed, fires nothing; the
//! first such refusal latches until the run disarms, which returns it, and
//! the run ends as a harness defect.
//!
//! `CATALOG` holds one row per point: its append-only code, its name, the
//! function and file that ask it, the fired outcome, the documentation
//! text in that file that permits the outcome, and its odds. A guard test
//! keeps the catalog and the [`chaos!`] calls equal, and an integration
//! test reads the crate's non-test binaries for `MARK`, a string only the
//! catalog holds.
//!
//! [`Domain::Chaos`]: crate::sim::choice::Domain::Chaos

/// Whether the chaos point `$point`, a variant of the catalog's `Point`,
/// fires at this reach: in a test build, one seeded decision inside a
/// production action while a run has armed the points on this thread and
/// `false` otherwise; outside test builds, the literal `false`.
#[cfg(test)]
macro_rules! chaos {
    ($point:ident) => {
        $crate::sim::chaos::fire($crate::sim::chaos::Point::$point)
    };
}

/// Whether the chaos point `$point` fires at this reach: outside test
/// builds, the literal `false`.
#[cfg(not(test))]
macro_rules! chaos {
    ($point:ident) => {
        false
    };
}

pub(crate) use chaos;

#[cfg(test)]
use std::cell::{Cell, RefCell};
#[cfg(test)]
use std::marker::PhantomData;
#[cfg(test)]
use std::rc::Rc;

#[cfg(test)]
use crate::sim::choice::{ChoiceError, Chooser, Defect, Domain, Site, bounded_decisions};

/// A chaos point. Its discriminant is its append-only catalog code, the
/// site number its decisions take.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub(crate) enum Point {
    /// `Gate::try_lock` finds the gate busy after its read saw the word
    /// open.
    GateBusy = 1,
    /// `Pool::capture_membership_lock` finds the capture mutex busy.
    CaptureBusy = 2,
    /// `update_after` loses the exchange it was about to make, and every
    /// exchange the rest of its budget would pay for, to another writer.
    ExchangeLost = 3,
}

#[cfg(test)]
impl Point {
    /// Every point, in code order.
    pub(crate) const ALL: [Self; 3] = [Self::GateBusy, Self::CaptureBusy, Self::ExchangeLost];

    /// The point's position in [`Self::ALL`] and in `CATALOG`.
    pub(crate) fn at(self) -> usize {
        usize::from(self as u16) - 1
    }

    /// The point's catalog row.
    pub(crate) fn row(self) -> &'static Row {
        &CATALOG[self.at()]
    }

    /// The site the point's decisions take for `actor`.
    pub(crate) fn site(self, actor: u16) -> Site {
        Site {
            domain: Domain::Chaos,
            actor,
            site: self as u16,
        }
    }
}

/// One catalog row: what a point is, where it asks, what it returns when it
/// fires, the text that permits that outcome there and its odds.
/// `attempt` identifies the operation at the chaos point, and `cause`
/// identifies the production event behind that outcome. [`DECLINED`] holds
/// a row for every nonblocking attempt outside the catalog. The attempt
/// guard checks that `CATALOG` and `DECLINED` together cover exactly the
/// nonblocking attempts of the crate's non-test source.
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct Row {
    pub(crate) point: Point,
    pub(crate) name: &'static str,
    /// The function that asks the point: `Type::method` for a method of an
    /// inherent `impl` block, the bare name for a free function.
    pub(crate) function: &'static str,
    /// The file that holds the function, relative to the crate's `src`.
    pub(crate) file: &'static str,
    /// The kind of the attempt the function itself makes at the point, if
    /// any. The attempt guard credits the row with the function's calls of
    /// that kind.
    pub(crate) attempt: Option<Attempt>,
    /// What the function returns when the point fires.
    pub(crate) outcome: &'static str,
    /// The documentation text in `file` that permits `outcome`, with any
    /// comment line breaks joined by one space.
    pub(crate) permits: &'static str,
    /// The production event that produces `outcome` with no point firing.
    pub(crate) cause: &'static str,
    /// The bound of each decision: one in `odds` reaches fires.
    pub(crate) odds: u64,
}

/// Every chaos point's row, in code order.
#[cfg(test)]
pub(crate) const CATALOG: [Row; 3] = [
    Row {
        point: Point::GateBusy,
        name: "gate-busy",
        function: "Gate::try_lock",
        file: "storage/gate.rs",
        attempt: None,
        outcome: "`Contended`, with the word left open",
        permits: "`Contended` if held elsewhere",
        cause: "a second holder of the gate word: a pool report holding the \
                gate it took through `Gate::lock`, or a concurrent publication, \
                removal, maintenance or close try of the same gate",
        odds: 4,
    },
    Row {
        point: Point::CaptureBusy,
        name: "capture-busy",
        function: "Pool::capture_membership_lock",
        file: "storage/capture.rs",
        attempt: Some(Attempt::TryLock),
        outcome: "`GateError::Contended`, with the mutex untouched",
        permits: "`GateError::Contended` if another holder has the mutex",
        cause: "a second holder of the capture mutex: a checkpoint writer \
                inside `capture_visit`, which tries the pool gate while it \
                holds the mutex",
        odds: 4,
    },
    Row {
        point: Point::ExchangeLost,
        name: "exchange-lost",
        function: "update_after",
        file: "storage/lease.rs",
        attempt: None,
        outcome: "`IncrementError::Contended`, with the word untouched and the rest \
                  of the budget paid for exchanges counted as lost",
        permits: "a budget that runs out while either count is nonzero is `Contended`",
        cause: "other writers of the same word winning every exchange the budget \
                pays for: readers on other threads reserving and returning engine \
                credits, or retaining and releasing rights on the same slot. On a \
                credit word this takes an engine lease limit of 2 or more: at a \
                limit of 1 one lost exchange shows the word full, and with budget \
                for another attempt production returns `LeaseLimit` with one \
                failed exchange",
        odds: 4,
    },
];

/// A kind of nonblocking attempt, named by the method its call names.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Attempt {
    /// A lock or gate attempt.
    TryLock,
    /// An atomic compare-exchange.
    CompareExchange,
    /// An atomic compare-exchange that may also fail spuriously.
    CompareExchangeWeak,
    /// A channel poll.
    TryRecv,
}

#[cfg(test)]
impl Attempt {
    pub(crate) const ALL: [Self; 4] = [
        Self::TryLock,
        Self::CompareExchange,
        Self::CompareExchangeWeak,
        Self::TryRecv,
    ];

    /// The method name a call of this kind names.
    pub(crate) fn method(self) -> &'static str {
        match self {
            Self::TryLock => "try_lock",
            Self::CompareExchange => "compare_exchange",
            Self::CompareExchangeWeak => "compare_exchange_weak",
            Self::TryRecv => "try_recv",
        }
    }
}

/// What the survey decided for a candidate.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Disposition {
    /// No chaos point stands at the attempt, for the reason given.
    Declined(&'static str),
    /// The attempt meets the four admission conditions: production
    /// produces its outcome with no disk, network or clock fault driving
    /// it, its file's documentation permits the outcome, a swept profile
    /// enters the function, and no cataloged point in a function it calls
    /// already produces the outcome. The named point's catalog row stands
    /// in the row's file.
    Admitted(Point),
}

/// The nonblocking attempts of one kind in one production function that
/// no catalog row names.
#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct Candidate {
    /// The attempt guard uses these function names: `name` for a free
    /// function, `Type::name` for a method of an inherent `impl` block and
    /// `Type::name (trait impl)` for a method of a trait `impl` block, with
    /// `Type` the last path segment of the implemented type, or the
    /// metavariable's name without `$` when a macro writes the block.
    pub(crate) function: &'static str,
    /// The file that holds the function, relative to the crate's `src`.
    pub(crate) file: &'static str,
    pub(crate) kind: Attempt,
    /// What the function does when an attempt fails.
    pub(crate) outcome: &'static str,
    pub(crate) disposition: Disposition,
}

/// The most rows of [`DECLINED`] that are admitted.
#[cfg(test)]
pub(crate) const ADMITTED_MAX: usize = 3;

/// The function calls a function that a catalog row names, whose point
/// already produces the outcome.
#[cfg(test)]
const CALLS_CATALOGED: &str = "calls a cataloged attempt";

#[cfg(test)]
const NO_PROFILE: &str = "no profile enters the function: no run of roots 1 to 300 of each of \
                          `upload`, `contended`, `cluster-swarm` and `cluster-pressure` \
                          entered it, by an instrumented worker's function coverage";

/// The exchange runs under the pool gate on a free slot's word, which no
/// other thread writes, so a failure is corruption.
#[cfg(test)]
const UNDER_GATE: &str = "under the pool gate no other thread writes the word, so a failure \
                          is corruption, which panics";

#[cfg(test)]
const RETRIES: &str = "the failure branch retries and returns no outcome";

/// Every candidate of the crate's non-test source, declined with its
/// reason or admitted for a chaos point; a guard keeps the rows and the
/// attempts equal. At most [`ADMITTED_MAX`] rows are admitted. The rows
/// name functions whose source names a listed kind: each makes the attempt
/// itself, except `attempts`, which runs its caller's closure under the
/// name `try_lock`. `update_after` reaches one only through the lease word's
/// `exchange_weak`, so the rows name those impls. `update_after` returns
/// `IncrementError::Contended` when its budget ends after a failed exchange,
/// the outcome of the `exchange-lost` point.
#[cfg(test)]
pub(crate) const DECLINED: [Candidate; 40] = [
    Candidate {
        function: "TableImage::try_lock",
        file: "storage/tables.rs",
        kind: Attempt::TryLock,
        outcome: "`GateError::Contended` or `Poisoned`",
        disposition: Disposition::Declined(CALLS_CATALOGED),
    },
    Candidate {
        function: "Pool::try_lock",
        file: "storage/owner.rs",
        kind: Attempt::TryLock,
        outcome: "`GateError::Contended` or `Poisoned`, counted as a failed try",
        disposition: Disposition::Declined(CALLS_CATALOGED),
    },
    Candidate {
        function: "Pool::try_lock_quiet",
        file: "storage/owner.rs",
        kind: Attempt::TryLock,
        outcome: "`GateError::Contended` or `Poisoned`, uncounted",
        disposition: Disposition::Declined(CALLS_CATALOGED),
    },
    Candidate {
        function: "RootGate::try_lock",
        file: "storage/gate.rs",
        kind: Attempt::TryLock,
        outcome: "`GateError::Contended` or `Poisoned`",
        disposition: Disposition::Declined(CALLS_CATALOGED),
    },
    Candidate {
        function: "Storage::reserve_layout",
        file: "storage/reserve.rs",
        kind: Attempt::TryLock,
        outcome: "`ReserveError::Gate`",
        disposition: Disposition::Declined(CALLS_CATALOGED),
    },
    Candidate {
        function: "Storage::return_allocation",
        file: "storage/release.rs",
        kind: Attempt::TryLock,
        outcome: "`ReturnOutcome::PendingContended` or `PendingPoisoned`",
        disposition: Disposition::Declined(CALLS_CATALOGED),
    },
    Candidate {
        function: "try_maintenance_gate",
        file: "storage/release.rs",
        kind: Attempt::TryLock,
        outcome: "`ServiceError::Gate`, noted for the observer",
        disposition: Disposition::Declined(CALLS_CATALOGED),
    },
    Candidate {
        function: "try_gate",
        file: "storage/release.rs",
        kind: Attempt::TryLock,
        outcome: "`ServiceError::Gate`, noted for the observer",
        disposition: Disposition::Declined(CALLS_CATALOGED),
    },
    Candidate {
        function: "publish_from",
        file: "storage/publish.rs",
        kind: Attempt::TryLock,
        outcome: "`PublishError::Contended`, or `Corrupt` for a poisoned gate",
        disposition: Disposition::Declined(CALLS_CATALOGED),
    },
    Candidate {
        function: "take_gate",
        file: "storage/publish.rs",
        kind: Attempt::TryLock,
        outcome: "`Refusal::Contended` after its busy tries, `Poisoned` at once, or \
                  `BudgetExhausted` when the budget cannot pay a try",
        disposition: Disposition::Declined(CALLS_CATALOGED),
    },
    Candidate {
        function: "attempts",
        file: "storage/publish.rs",
        kind: Attempt::TryLock,
        outcome: "`Refusal::Contended` once `tries` tries found the lock busy, `Poisoned` \
                  at once, or `BudgetExhausted` when the budget cannot pay a try",
        disposition: Disposition::Declined(
            "runs the closure its caller passes as `try_lock`: the gate try of `take_gate`, \
             and `Pool::capture_membership_lock` and `Pool::try_lock_quiet` for a fill's \
             publication; each is a cataloged attempt or calls one",
        ),
    },
    Candidate {
        function: "Storage::maintain_open",
        file: "storage/maintain.rs",
        kind: Attempt::TryLock,
        outcome: "`MaintainError::Contended` or `Poisoned`",
        disposition: Disposition::Declined(CALLS_CATALOGED),
    },
    Candidate {
        function: "Storage::inspect_fills",
        file: "storage/finalize.rs",
        kind: Attempt::TryLock,
        outcome: "`FinalizeError::ShardGateHeld` or `ShardPoisoned`",
        disposition: Disposition::Declined(CALLS_CATALOGED),
    },
    Candidate {
        function: "try_pool",
        file: "storage/evict.rs",
        kind: Attempt::TryLock,
        outcome: "`GateError::Contended` or `Poisoned`, noted for the observer",
        disposition: Disposition::Declined(CALLS_CATALOGED),
    },
    Candidate {
        function: "Storage::close_service",
        file: "storage/closing.rs",
        kind: Attempt::TryLock,
        outcome: "`CloseError::Contended` or `Poisoned`",
        disposition: Disposition::Declined(CALLS_CATALOGED),
    },
    Candidate {
        function: "Storage::read_run",
        file: "storage/closing.rs",
        kind: Attempt::TryLock,
        outcome: "`RunError::Contended` or `Poisoned`",
        disposition: Disposition::Declined(CALLS_CATALOGED),
    },
    Candidate {
        function: "ExtentReservation::bind",
        file: "storage/allocation.rs",
        kind: Attempt::TryLock,
        outcome: "`CompleteError::Gate`",
        disposition: Disposition::Declined(CALLS_CATALOGED),
    },
    Candidate {
        function: "Storage::promise",
        file: "storage/builder.rs",
        kind: Attempt::TryLock,
        outcome: "`PromiseError::Reserve(ReserveError::Gate)` for a busy or poisoned gate",
        disposition: Disposition::Declined(CALLS_CATALOGED),
    },
    Candidate {
        function: "Builder::place",
        file: "storage/builder.rs",
        kind: Attempt::TryLock,
        outcome: "`PromiseError::Reserve(ReserveError::Gate)` for a busy or poisoned gate",
        disposition: Disposition::Declined(CALLS_CATALOGED),
    },
    Candidate {
        function: "Pool::capture_lock",
        file: "storage/capture.rs",
        kind: Attempt::TryLock,
        outcome: "`GateError::Contended`, or `Poisoned`",
        disposition: Disposition::Declined(
            "no profile enters the function: no run of roots 1 to 300 of each of \
             `upload`, `contended`, `cluster-swarm` and `cluster-pressure`, of the \
             `recovery-16k`, `recovery-512` and `recovery-torn` profiles at 1 and 20 \
             `restarts`, or of `cluster-broad` or `cluster-long` entered it",
        ),
    },
    Candidate {
        function: "lock_file",
        file: "bind/lock.rs",
        kind: Attempt::TryLock,
        outcome: "`WouldBlock` while another process holds the file lock",
        disposition: Disposition::Declined(NO_PROFILE),
    },
    Candidate {
        function: "try_hold",
        file: "host/link.rs",
        kind: Attempt::TryLock,
        outcome: "`None` while another thread holds the mutex; the guard of a poisoned mutex",
        disposition: Disposition::Declined(
            "no profile enters the function: by the callers in the source, only the unit \
             tests of `host` build a `Link` or call `Duties::linked`, and no profile's \
             plan runs them",
        ),
    },
    Candidate {
        function: "Gate::attempt",
        file: "storage/gate.rs",
        kind: Attempt::CompareExchange,
        outcome: "`GateError::Contended`, or `Poisoned` for a poisoned word",
        disposition: Disposition::Declined(
            "gate-busy fires in this function before the exchange, through `Gate::try_lock`; \
                 `Gate::lock` retries",
        ),
    },
    Candidate {
        function: "atomic::compare_exchange (trait impl)",
        file: "storage/gate.rs",
        kind: Attempt::CompareExchange,
        outcome: "the atomic's `Err` with the value it holds",
        disposition: Disposition::Declined(
            "forwards to the atomic; `Gate::attempt` holds the outcome",
        ),
    },
    Candidate {
        function: "install",
        file: "storage/word.rs",
        kind: Attempt::CompareExchange,
        outcome: "retries on the value it saw; `false` for a counted, other or \
                  malformed word",
        disposition: Disposition::Declined(RETRIES),
    },
    Candidate {
        function: "Lane::install",
        file: "storage/tables/lanes.rs",
        kind: Attempt::CompareExchange,
        outcome: "panics: the free slot's word changed",
        disposition: Disposition::Declined(UNDER_GATE),
    },
    Candidate {
        function: "install_filling",
        file: "storage/reserve.rs",
        kind: Attempt::CompareExchange,
        outcome: "panics: the free slot's word changed",
        disposition: Disposition::Declined(UNDER_GATE),
    },
    Candidate {
        function: "release_anchor",
        file: "storage/release.rs",
        kind: Attempt::CompareExchange,
        outcome: "retries on the value it saw; panics for a word without its counted \
                  anchor",
        disposition: Disposition::Declined(RETRIES),
    },
    Candidate {
        function: "park_marked",
        file: "storage/release.rs",
        kind: Attempt::CompareExchange,
        outcome: "retries on the value it saw; `false` once that value names another \
                  incarnation or sets a reserved bit",
        disposition: Disposition::Declined(RETRIES),
    },
    Candidate {
        function: "Word::set_authority",
        file: "storage/readiness.rs",
        kind: Attempt::CompareExchange,
        outcome: "retries on the value it saw until the word holds the publication",
        disposition: Disposition::Declined(RETRIES),
    },
    Candidate {
        function: "Word::apply",
        file: "storage/readiness.rs",
        kind: Attempt::CompareExchange,
        outcome: "judges the event again against the value it saw; `ReadinessError` \
                  for a refused one",
        disposition: Disposition::Declined(RETRIES),
    },
    Candidate {
        function: "word::compare_exchange (trait impl)",
        file: "storage/coverage/epochs.rs",
        kind: Attempt::CompareExchange,
        outcome: "the atomic's `Err` with the value it holds",
        disposition: Disposition::Declined("forwards to the atomic; `register` holds the outcome"),
    },
    Candidate {
        function: "register",
        file: "storage/coverage/epochs.rs",
        kind: Attempt::CompareExchange,
        outcome: "retries on the value it saw; `None` once admission closes",
        disposition: Disposition::Declined(RETRIES),
    },
    Candidate {
        function: "Storage::issue_cache",
        file: "storage/cache.rs",
        kind: Attempt::CompareExchange,
        outcome: "`CacheError::AlreadyIssued`",
        disposition: Disposition::Declined(
            "the documentation permits `AlreadyIssued` only once the issuance bit is claimed, \
                 and a fire on an unclaimed bit refuses the storage's one issuance",
        ),
    },
    Candidate {
        function: "atomic::compare_exchange (trait impl)",
        file: "storage/fill.rs",
        kind: Attempt::CompareExchange,
        outcome: "the atomic's `Err` with the value it holds",
        disposition: Disposition::Declined("forwards to the atomic; `depart` holds the outcome"),
    },
    Candidate {
        function: "depart",
        file: "storage/fill.rs",
        kind: Attempt::CompareExchange,
        outcome: "retries once on a revoked word; `false` for a word that carries \
                  another serial or already carries `DEPARTED`",
        disposition: Disposition::Declined(RETRIES),
    },
    // exchange-lost stands at the credit words' exchanges in
    // `update_after`, the loop that makes them and returns their outcome.
    // The lifetime word's copy of the loop carries the point too, and runs
    // only after `retain_right`'s inline first exchange is lost.
    Candidate {
        function: "AtomicUsize::exchange_weak (trait impl)",
        file: "storage/lease.rs",
        kind: Attempt::CompareExchangeWeak,
        outcome: "the atomic's `Err`; `update_after` retries, and returns \
                  `IncrementError::Contended` once its budget ends after a failed \
                  exchange",
        disposition: Disposition::Admitted(Point::ExchangeLost),
    },
    Candidate {
        function: "AtomicU64::exchange_weak (trait impl)",
        file: "storage/lease.rs",
        kind: Attempt::CompareExchangeWeak,
        outcome: "the atomic's `Err`; `update_after` retries, and returns \
                  `IncrementError::Contended` once its budget ends after a failed \
                  exchange",
        disposition: Disposition::Declined(
            "`retain_right` makes the lifetime word's first exchange inline, ahead of \
             `update_after` and its point, and no sampled swept run lost that \
             exchange: 0 of 500 roots each of `upload`, `faulted` and `contended` \
             lost it",
        ),
    },
    Candidate {
        function: "Lane::landed",
        file: "host/lane.rs",
        kind: Attempt::TryRecv,
        outcome: "`None` while the channel is empty; `Done::Panicked`, for the oldest \
                  outstanding kind, once it is empty and the lane thread has ended",
        disposition: Disposition::Declined(
            "the simulation worker sets `INLINE_RECOVERY` on its thread, so a lane it \
             starts there runs inline and `landed` reads the inline queue; no run of \
             roots 1 to 300 of the four swept profiles entered the function",
        ),
    },
    Candidate {
        function: "Helpers::next",
        file: "storage/volume/helpers.rs",
        kind: Attempt::TryRecv,
        outcome: "`None` for an empty channel and for one whose helpers have all exited",
        disposition: Disposition::Declined(
            "the simulation worker sets `INLINE_RECOVERY` on its thread, so a pool it \
             starts there starts no helper, drops its channel's one sender and takes \
             its terminals from the inline queue, and the receive finds the channel \
             disconnected; no run of roots 1 to 300 of the four swept profiles entered \
             the function",
        ),
    },
];

/// A string only the catalog holds. A test build links it through `fire`,
/// the function every `chaos!` call reaches, and through [`arm`], so a
/// binary that compiled either holds its bytes; a binary built without
/// `cfg(test)` compiles neither and holds no copy. The literal is spelled
/// in two pieces, so a copy of this file that a test embeds holds no whole
/// mark.
#[cfg(test)]
const MARK: &str = concat!("kestrike chaos ", "point catalog");

/// Each point's odds as `CATALOG` sets them, in code order.
#[cfg(test)]
fn odds() -> [u64; Point::ALL.len()] {
    Point::ALL.map(|point| point.row().odds)
}

/// The least engine lease limit at which a run arms `exchange-lost`. A
/// credit word under a limit of 1 holds 0 or 1, so after one lost exchange
/// the next attempt returns `LeaseLimit`; from a limit of 2 other writers
/// can win each exchange in turn.
#[cfg(test)]
pub(crate) const EXCHANGE_LOST_LEASE_LIMIT: usize = 2;

/// The returned odds follow [`Point::ALL`] order and match `CATALOG`,
/// except that zero odds disarm `exchange-lost` when `lease_limit` is
/// below [`EXCHANGE_LOST_LEASE_LIMIT`].
#[cfg(test)]
pub(crate) fn odds_within(lease_limit: usize) -> [u64; Point::ALL.len()] {
    let mut odds = odds();
    if lease_limit < EXCHANGE_LOST_LEASE_LIMIT {
        odds[Point::ExchangeLost.at()] = 0;
    }
    odds
}

/// The sites the points' decisions take for `actor`, in code order, for a
/// chooser of an armed run to register.
#[cfg(test)]
pub(crate) fn sites(actor: u16) -> Vec<Site> {
    Point::ALL.iter().map(|point| point.site(actor)).collect()
}

/// What an armed thread decides with.
#[cfg(test)]
struct Armed {
    chooser: Rc<RefCell<Chooser>>,
    actor: u16,
    incarnation: u32,
    /// Each point's bound, in code order; 0 leaves that point unarmed.
    odds: [u64; Point::ALL.len()],
    /// The first refused decision since arming.
    refusal: Option<ChoiceError>,
}

#[cfg(test)]
thread_local! {
    /// Whether the points are armed and not silenced on this thread: set
    /// only while `ARMED` holds a run's state, so a reach of an unarmed
    /// point reads two cells and touches no other state.
    static LIVE: Cell<bool> = const { Cell::new(false) };
    /// Whether this thread runs a production action inside [`acting`].
    static ACTING: Cell<bool> = const { Cell::new(false) };
    static ARMED: RefCell<Option<Armed>> = const { RefCell::new(None) };
}

/// Arms the points on this thread for one run: each reach of a point with
/// nonzero `odds` inside [`acting`] decides through `chooser` at its site
/// for `actor` in `incarnation`, until the returned guard drops or
/// [`silence`] runs.
///
/// # Panics
///
/// If the points are already armed on this thread.
#[cfg(test)]
pub(crate) fn arm(
    chooser: &Rc<RefCell<Chooser>>,
    (actor, incarnation): (u16, u32),
    odds: [u64; Point::ALL.len()],
) -> Arming {
    std::hint::black_box(MARK);
    ARMED.with_borrow_mut(|armed| {
        assert!(armed.is_none(), "the chaos points are armed once per run");
        *armed = Some(Armed {
            chooser: Rc::clone(chooser),
            actor,
            incarnation,
            odds,
            refusal: None,
        });
    });
    LIVE.set(true);
    Arming(PhantomData)
}

/// Proof that the points are armed on this thread. Dropping it, by
/// [`disarm`](Self::disarm) or by unwinding, disarms them and releases
/// the armed chooser.
///
/// The thread that called `arm` owns the armed state; guard ownership and
/// shared access stay on that thread.
#[cfg(test)]
#[must_use = "dropping the guard disarms the points"]
pub(crate) struct Arming(PhantomData<*const ()>);

/// If [`Arming`] implements `Send`, two `AmbiguousIfSend` implementations
/// apply and the lookup becomes ambiguous.
#[cfg(test)]
const _: () = {
    trait AmbiguousIfSend<A> {
        fn item() {}
    }
    impl<T: ?Sized> AmbiguousIfSend<()> for T {}
    impl<T: ?Sized + Send> AmbiguousIfSend<u8> for T {}
    let _ = <Arming as AmbiguousIfSend<_>>::item;
};

#[cfg(test)]
impl Arming {
    /// Disarms the points and returns the first refusal latched while they
    /// were armed.
    pub(crate) fn disarm(self) -> Option<ChoiceError> {
        let refusal = ARMED.with_borrow(|armed| {
            armed
                .as_ref()
                .expect("an `Arming` guard exists only while `ARMED` holds its run's state")
                .refusal
        });
        drop(self);
        refusal
    }
}

#[cfg(test)]
impl Drop for Arming {
    fn drop(&mut self) {
        LIVE.set(false);
        ARMED.take();
    }
}

/// Runs `action`, a production action a run's turn selected, with the
/// armed points deciding at their reaches inside it. A reach outside every
/// action, such as a harness check that reads the storage between turns,
/// decides nothing, so the points refuse only what production code asked.
#[cfg(test)]
pub(crate) fn acting<T>(action: impl FnOnce() -> T) -> T {
    struct Restore(bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            ACTING.set(self.0);
        }
    }
    let _restore = Restore(ACTING.replace(true));
    action()
}

/// Stops the armed points from firing, keeping a latched refusal for
/// [`refusal`] and [`Arming::disarm`]: a run whose goal holds runs its
/// remaining turns with no point deciding.
#[cfg(test)]
pub(crate) fn silence() {
    LIVE.set(false);
}

/// The refusal latched since the points were armed on this thread.
#[cfg(test)]
pub(crate) fn refusal() -> Option<ChoiceError> {
    ARMED.with_borrow(|armed| armed.as_ref()?.refusal)
}

/// The bounds the points are armed with on this thread, in [`Point::ALL`]
/// order, or `None` while they are unarmed.
#[cfg(test)]
pub(crate) fn armed_odds() -> Option<[u64; Point::ALL.len()]> {
    ARMED.with_borrow(|armed| Some(armed.as_ref()?.odds))
}

/// Whether `point` fires at this reach: `false` with no decision unless
/// the reach is inside [`acting`], the points are armed and not silenced
/// on this thread, and `point` has odds;
/// otherwise one bounded decision at `point`'s site, which fires on 0. A
/// refused decision, or a chooser already borrowed, latches its refusal
/// and fires nothing, as does every reach after it.
#[cfg(test)]
pub(crate) fn fire(point: Point) -> bool {
    std::hint::black_box(MARK);
    if !(ACTING.get() && LIVE.get()) {
        return false;
    }
    ARMED.with_borrow_mut(|armed| {
        let armed = armed
            .as_mut()
            .expect("`LIVE` is set only while `ARMED` holds a run's state");
        let odds = armed.odds[point.at()];
        if odds == 0 || armed.refusal.is_some() {
            return false;
        }
        let site = point.site(armed.actor);
        let decided = match armed.chooser.try_borrow_mut() {
            Ok(mut chooser) => chooser.bounded(site, armed.incarnation, odds),
            Err(_) => Err(ChoiceError::HarnessDefect(Defect::Borrowed(site))),
        };
        decided
            .inspect_err(|error| armed.refusal = Some(*error))
            .is_ok_and(|value| value == 0)
    })
}

/// One point's decisions on a tape.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Census {
    /// Bounded decisions at the point's site.
    pub(crate) reached: u64,
    /// Those that selected 0.
    pub(crate) fired: u64,
}

/// Each point's census over `tape`, in code order: the bounded decisions in
/// the chaos domain at the point's site, for any actor, and those that
/// selected 0. `None` for a tape the choice reader refuses.
#[cfg(test)]
pub(crate) fn census(tape: &[u8]) -> Option<[Census; Point::ALL.len()]> {
    let mut out = [Census::default(); Point::ALL.len()];
    for (site, value) in bounded_decisions(tape)? {
        let Some(point) = Point::ALL
            .into_iter()
            .find(|point| site.domain == Domain::Chaos && site.site == *point as u16)
        else {
            continue;
        };
        let counts = &mut out[point.at()];
        counts.reached += 1;
        counts.fired += u64::from(value == 0);
    }
    Some(out)
}

#[cfg(test)]
#[path = "chaos_tests.rs"]
pub(super) mod tests;
