//! The owner thread's per-turn duties for one serving tenure. [`Duties::turn`] adopts at most one store-lane
//! completion per turn, and the owner serves GETs while lane jobs are outstanding.
//!
//! The tenure open starts when the owner's readiness is `Live`. It runs a [`Job::View`], builds a [`PossiblyNamed`]
//! over the view's layout and named checkpoint, confirms the shard record by the tenure's own exact-version write
//! ([`Job::Confirm`]), and opens the tenure's suffix ([`Job::Open`]) over the predecessor ends the warm load
//! certified. A warm tenure publishes a FILL only after its log opens. The open stops before the set is built when
//! the view's volume record holds a layout the volume does not admit: another layout than a warm load read under,
//! or one over another metadata prefix. A later view whose layout differs from the one the set was built under also
//! stops it.
//!
//! After a Publish whose outcome is unknown, the duties adopt a view's shard record as the next base only when it
//! names the checkpoint that Publish's base named or the one it submitted; any other checkpoint stops the open, so
//! no Confirm, suffix open or pass runs over a pointer the tenure did not write.
//!
//! Each Publish with an unknown outcome adds its submitted checkpoint to the checkpoints a view may name, until an
//! acknowledged own write, such as the settling Confirm below, settles the set. While the opened tenure holds a read, a newer view stops the open if its checkpoint differs from both the read's
//! checkpoint and every submitted checkpoint.
//!
//! Under a capture policy ([`Duties::capturing`]) the tenure then runs capture passes: a pass walks the membership,
//! reserves its stage's slot, encodes its cut on the recovery helpers and publishes a checkpoint through a
//! [`Job::Publish`]. A first Publish over a record that named no checkpoint moves the open from `Opened` back to
//! `Opening`, so the suffix opens, and after a store error back to `Viewing`, so the open runs again from the next
//! view.
//! A pass submits its Publish only to an idle lane, so the Publish is the lane's one outstanding job.
//!
//! After an unanswered or refused View or write, the tenure retries from the next periodic View using the same
//! [`PossiblyNamed`]. If the record names a checkpoint and the log stays closed, the
//! tenure retries Open with the returned read at least `view_us` after submission. A busy capture mutex can keep
//! the log closed. [`Open::Stopped`] ends job submission for the open. A completion that shows the lane's client
//! withdrawn ends the tenure with [`Rerun::Withdrawn`]: the client issues no further request, so the next
//! incarnation opens one from the durable watermark.
//!
//! The record view runs once per view period: the duties snapshot the last Report the authority evaluated and the
//! last listing, then submit a [`Job::View`]. Its completion feeds [`Owner::observe_shard_view`], refreshes the
//! freshness clock or marks a failed read, using the view's send time on the serving clock for either outcome, and
//! runs [`Owner::owner_poll`] over the snapshot, the reads and that send time. A view whose volume read fails polls
//! with the standby binding of the last volume record, the peers the instance lookup bound and the instances that
//! record's attach and ended entries bound, when READ-ORDER admits it, and a view record that does not decode ends
//! the tenure with [`Rerun::Withdrawn`]. A [`Job::Listing`] reads the attachment listing once per listing period.
//!
//! A view read that shows a later tenure, another active volume or a retired own volume withdraws the owner as
//! deposed, and a shard read below the tenure's `(g, E)` withdraws it as a regression; the serving loop ends the
//! tenure on either.
//!
//! The duties keep what the status reports beside the owner's state: the listing result of the last poll, read with
//! [`poll::owner_listing`] over the reads the poll judged, and the store client's monitors the lane handed back with
//! the last adopted completion. A view that polls with no standby binding READ-ORDER admits judges the listing
//! without the records a binding could admit; when it leaves a listed record out, its result reads unavailable
//! unless the check found a foreign or duplicate record. The store counts are the tenure's: the duties take the lane's tally as the baseline
//! when the tenure open starts and report each later copy's gain over it.
//!
//! The reclaim step follows each poll that read the volume record ([`Owner::owner_reclaim`]): on a `Continue`
//! verdict the serving authority past its fencing boundary submits at most one ended-key preempt and returns the
//! ended pairs to drop. The duties keep each pair of a host the same View's shard record names owner or standby, and
//! every pair when that shard read failed ([`droppable`]). While no drop job is outstanding, the duties submit one
//! [`Job::Drop`] of the pairs left, an exact-version replace of the viewed volume record, after the turn's other
//! submissions. After a failed version
//! condition, an unknown outcome or a refused submit, the next poll uses a fresh read to determine which pairs to
//! drop; a store error that withdraws the client ends the incarnation with [`Rerun::Withdrawn`].
//!
//! The coverage duty writes held INVALIDATEs' pages through [`Job::Page`] and submits each page job only to an idle
//! lane, so a page job is the lane's one outstanding job: a due view, listing or shard-record write waits until the
//! page completion is adopted. That turn submits a due view and defers the next page job to a later turn. On an idle
//! lane, a turn that adopted no page completion submits the saved follow-up request of the write in
//! flight while [`Owner::cover_continues`] holds, and drops the request otherwise. With no follow-up saved, the turn
//! calls [`Owner::cover_begin`] to write the next held page in ascending order, wrapping to the lowest held page
//! when none lies above the last page written. A request
//! the lane refuses waits for a later turn. Each page completion goes to [`Owner::cover_end`], which acknowledges
//! the write's entries only on its acknowledged commit; an unresolved write with no value of the page from the
//! store, an unknown outcome or an unavailable re-read, holds every page job for one view period. A coverage
//! withdrawal ends the incarnation with the exit the authority names, which is [`Exit::Deposed`] for a page fence
//! of a later activated session, or with [`Rerun::Withdrawn`] while the authority still serves; an authority
//! already withdrawn that names no exit keeps its post-withdrawal poll.
//!
//! Once the open reached `Opened` over a record that names a checkpoint, a [`Job::Step`] runs one suffix store step: it
//! certifies the durable prefix and extends the reserved end, and the log admits records only up to the ends the store
//! committed. A submitted step sets the next one due one step period later. A due step waits for an idle lane, so it
//! is the lane's one outstanding job from its submit to its adoption, and while the duties hold no read; the periods
//! it waits through count toward that one due step. A capture pass's encode leaves the set on the owner thread, so
//! steps go out while it runs. After a Publish over a record that already named a checkpoint ends with a store error, a [`Job::Confirm`] over
//! the next view's read settles the set before the next capture start. A due handoff, a capture start with no free
//! checkpoint slot, a stage refused for placement and, for duties with no capture policy, a due publication set
//! [`Duties::roll_due`]. Duties built through [`Duties::rolling`] then roll the tenure once a record read names a
//! standby: stop fills, publish a capture unless a capture start with no free checkpoint slot or a stage refused for
//! placement set `roll_due`, stop mutations, seal and certify the suffix with a [`Job::Certify`], withdraw for
//! `Cause::Planned` and end with [`Rerun::Planned`]. Either placement condition suppresses the roll's Publish for the
//! rest of the tenure. Until a roll starts, the tenure keeps serving hits and its log refuses mutations at the bound.
//!
//! Duties built through [`Duties::requesting`] take each authenticated planned request the inbox delivers into the
//! same machine: a transfer drains, publishes, certifies, withdraws and transfers the shard to the named standby
//! through a [`Job::Transfer`], and a requested restart ends with [`Rerun::Planned`] as the roll does.
//!
//! Steps and a roll's certifies stop when the owner closes to writes. If a step's or a certify's store error withdraws
//! the store client, the incarnation ends on the turn that adopts the error, as it does for a Confirm or an Open.
//!
//! Invariants:
//!
//! - STORE-OFF-POLL: every store request of the tenure runs as a lane job, the pair drop and the transfer included.
//! - EndOrder: a pair leaves the volume record only by a drop job over the record a poll read after a Report that
//!   omitted the pair's key. An earlier poll observed the end mark before that Report's submission.
//! - NAMED-PAIR-KEPT: a drop job carries no pair of a host that the shard record its View read names owner or
//!   standby, and a View whose shard read failed submits no drop. A takeover CAS that a standby prepared before the
//!   reconciler ended its attach can commit after the end; the successor's pair then stays recorded for the next
//!   takeover's Predecessor check. The guard and the takeover's shard-first step-1 read close the order in which the
//!   end, the drop and a designation of that host fall between the takeover's two step-1 reads only while the
//!   owner's View reads the volume record before the shard record.
//! - SERIAL-ISSUE, PossNamedCoversStore: one shard-record job (Confirm, Open, Step, Publish or Certify) is outstanding
//!   at a time, and it takes the one [`PossiblyNamed`] the duties hold; the transfer, the one shard-record job of a
//!   withdrawn owner, follows the acknowledged certify and carries no set; a second such job while the set is away
//!   fails the single-holder check. A capture encode takes a slot reservation the owner thread made in the set and
//!   leaves the set with the duties.
//! - READ-ORDER: a poll judges a Report and a listing that the duties took before they submitted the view whose
//!   volume record and shard record it reads. A binding of standbys is as old as the view whose volume record
//!   produced it, so a view whose volume read fails judges the whole listing against the last binding only when the
//!   duties adopted that listing before they submitted the view that produced the binding. Against a later listing
//!   it judges only the listed records that no binding admits, the own instance, a record that is no instance ID
//!   and a record listed twice: a standby that enrolled and attached after the last volume record read is outside
//!   that binding, and the device reservation fences its writes while the volume reads fail. A sequence stamp on
//!   each adopted listing and each submitted view records the order.
//! - POLL-WITHIN-WINDOW: the serving authority defers an unrecorded registrant for one serving window from the
//!   submission of the first Report that lists it, and the poll of a view whose volume record enrolls the pair ends
//!   the deferral. [`Periods::new`] admits only periods under which that poll completes inside the window. The
//!   Report can be submitted its deadline before the registration. The first view that reads the enrollment is due
//!   one view period after the submission of the last view that missed it. A listing or two store calls delay it:
//!   a shard-record or page job outstanding when it falls due holds its submission until that job's call ends, and
//!   a [`Job::Drop`] queued behind the open's job of the same turn can start before the duties submit the view,
//!   which then waits for the drop's call as well; or a listing that runs then holds its reads for the listing
//!   deadline. It then makes two store calls. A view is submitted while no shard-record or page job is outstanding,
//!   and the lane runs it ahead of every queued job, so from its submission it takes one running listing or drop
//!   and two store calls at most, which the `Deadlines` refusal keeps inside the view period. A standby registers
//!   only after its takeover write on the shard record commits, and each write of a [`Job::Confirm`], a
//!   [`Job::Open`] or a [`Job::Step`] conditions on that record's version, so after the takeover write such a job
//!   ends at its next request, within two store calls, which the view period covers. Each of the three is submitted
//!   to an idle lane, where only a drop joins it, so one submitted after the takeover write holds a due view for
//!   its one store call and that drop's. The bound holds while each Report certifies within its deadline, each
//!   store call returns within the store deadline, and the lane thread and the owner thread run.
//! - ACK-ON-COMMIT: [`Duties::acknowledged`] and every INVALIDATED the duty queues name only entries carried by a
//!   page write whose acknowledged commit the turn adopted.
//! - ROLE-BOUND: a poll's `Deposed` ends the incarnation with [`Exit::Deposed`], or with [`Rerun::Withdrawn`] when
//!   the owner withdrew on the view's shard read as a regression, and its `Retire` parks it with [`Exit::Retire`],
//!   each with no write; a `Withdraw` keeps the view running, and under a recorded holder of
//!   another host while the shard read names this tenure it ends the incarnation with [`Rerun::RecordedHolder`].

use std::num::NonZeroU64;

use super::exit::{Exit, Rerun};
use super::gate::HostGate;
use super::inputs;
use super::lane::{Done, Job, Lane, Plane};
use crate::failover::attachments::{InstanceId, Mismatch, Peer};
use crate::failover::bounds::Bounds;
use crate::failover::evidence::{NotSole, Pair, ReservationType};
use crate::failover::flip::volume_state;
use crate::failover::poll::{self, Holder, Verdict};
use crate::failover::reconcile::{LISTING_HOLD_US, StandbyGate};
use crate::failover::records::{
    Host, Layout, NamedCheckpoint, ShardRecord, VolumeRecord, VolumeState,
};
use crate::failover::report::{Enumeration, Gauge};
use crate::failover::retire::{Target, Trigger};
use crate::failover::serving::{Cause, Event, ReportTrigger, State};
use crate::failover::withhold::W_US;
use crate::net::{Datagrams, Owner};
use crate::storage::checkpoint::{
    PossiblyNamed, SuffixBounds, SuffixDue, WriteRefused, required_history,
};
use crate::storage::page_coverage::{Cover, Entry as CoverageEntry, PageRequest};
use crate::storage::store::{Read, Store, StoreError, Tally, WatermarkLog};
use crate::storage::{Disk, Platform, PolledReport, Readiness};

/// `Viewing`, `Confirming` and `Opening` each cover both an outstanding job and the wait before its retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Open {
    /// The open waits for the owner's readiness to reach `Live`.
    Due,
    /// The tenure uses the volume and shard reads from the first successful View to build its [`PossiblyNamed`].
    Viewing,
    /// The tenure writes the viewed shard record back at its exact version.
    Confirming,
    /// The tenure certifies the predecessor ends, reserves its own suffix and opens the log.
    Opening,
    /// When the record names a checkpoint, `Opened` means the log is open, except after the suffix reservation
    /// refused `Chain`. A record that names none, or that refusal, leaves the log closed until the tenure's next
    /// Publish moves the open back to `Opening`.
    Opened,
    /// The open ends here because the owner's session names another shard, the suffix bounds or the view's layout
    /// admit no log, the first View's layout differs from the warm read's layout, a later View's layout differs
    /// from the set's layout or its checkpoint from the tenure's, the view shows another tenure or another active
    /// volume, the client withdrew, the chain admits no suffix of the tenure, or the owner withdrew.
    Stopped,
}

/// The tenure's one [`PossiblyNamed`]: `Unbuilt` before the first View, `Here` while the duties hold it, `Away`
/// while a lane job carries it.
enum Set {
    Unbuilt,
    Here(PossiblyNamed),
    Away,
}

/// The shard record may name the prior checkpoint or a submitted checkpoint while a Publish's outcome is unknown.
struct Unsettled {
    /// The checkpoint the base of the first such Publish named.
    prior: Option<NamedCheckpoint>,
    /// The checkpoint each such Publish submitted.
    submitted: Vec<NamedCheckpoint>,
}

impl Unsettled {
    fn submitted(&self, named: Option<NamedCheckpoint>) -> bool {
        named.is_some_and(|named| self.submitted.contains(&named))
    }
}

/// `Judged` classifies the view's shard record for the opened tenure relative to the read the duties hold.
enum Judged {
    /// The record's version is at or below the held read's, or a Publish is outstanding and the record may reflect
    /// that Publish's commit.
    Stale,
    /// The record's version is above the held read's, and the record names the held read's checkpoint or one an
    /// unsettled Publish submitted.
    Base,
    /// The record's version is above the held read's, and the record names any other checkpoint.
    Foreign,
}

/// The longest view period, half the availability withhold's `W_US`.
pub const VIEW_US: u64 = W_US / 2;

/// The assumed attachment-listing period.
pub const LISTING_US: u64 = 60_000_000;

/// The longest host-side listing deadline.
pub const LISTING_DEADLINE_US: u64 = 1_000_000;

// The zone loop admits a detach settle time only above its floor, and `Periods::new` keeps the span a poll holds a
// listing below `LISTING_HOLD_US`. A settle time covers every admitted span while the two constants are equal.
const _: () =
    assert!(crate::failover::zone_loop::config::DETACH_SETTLE_FLOOR_US == LISTING_HOLD_US);

/// The periods and deadlines of a tenure's record view and attachment listing that POLL-WITHIN-WINDOW admits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Periods {
    view_us: u64,
    listing_us: u64,
    store_deadline_us: u64,
    listing_deadline_us: u64,
    step_us: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeriodRefusal {
    View,
    Listing,
    ListingDeadline,
    Deadlines,
    Window,
}

impl Periods {
    /// `store_deadline_us` bounds one store call of the lane: one [`Client`](crate::storage::store::Client) call
    /// with its one store request and the watermark-log write that follows a raised mark. `listing_deadline_us`
    /// bounds one [`ControlPlane::attachments`](crate::failover::attachments::ControlPlane::attachments) call. The
    /// refusals keep POLL-WITHIN-WINDOW, and the upper bound on the listing period keeps the span a poll holds a
    /// listing below [`LISTING_HOLD_US`]: a poll's volume read follows the request of the listing it judges by at
    /// most the listing deadline, the listing period, the one running job ahead of the submitted view and the view's
    /// volume read, while each call meets its deadline and the lane thread and the owner thread run.
    ///
    /// # Errors
    ///
    /// [`PeriodRefusal::View`] for a view period of zero or above [`VIEW_US`], [`PeriodRefusal::ListingDeadline`]
    /// for a listing deadline of zero or above [`LISTING_DEADLINE_US`], [`PeriodRefusal::Listing`] when
    /// `listing_us < view_us`, [`PeriodRefusal::Deadlines`] when `store_deadline_us == 0` or the two store calls of
    /// a view and the longer of the listing deadline and the store deadline sum to the view period or more,
    /// [`PeriodRefusal::Listing`] when the listing period, the listing deadline, the longer of the listing deadline
    /// and the store deadline, and one store call sum to [`LISTING_HOLD_US`] or more, and [`PeriodRefusal::Window`]
    /// when `bounds.report_deadline()`, the view period, the longer of the listing deadline and two store calls,
    /// and the two store calls of a view sum to `bounds.window()` or more.
    pub fn new(
        bounds: &Bounds,
        view_us: u64,
        listing_us: u64,
        (store_deadline_us, listing_deadline_us): (u64, u64),
    ) -> Result<Self, PeriodRefusal> {
        if view_us == 0 || view_us > VIEW_US {
            return Err(PeriodRefusal::View);
        }
        if listing_us < view_us {
            return Err(PeriodRefusal::Listing);
        }
        if listing_deadline_us == 0 || listing_deadline_us > LISTING_DEADLINE_US {
            return Err(PeriodRefusal::ListingDeadline);
        }
        let reads_us = store_deadline_us.saturating_mul(2);
        // One running listing or drop is ahead of a submitted view.
        let behind_us = listing_deadline_us.max(store_deadline_us);
        if store_deadline_us == 0 || reads_us.saturating_add(behind_us) >= view_us {
            return Err(PeriodRefusal::Deadlines);
        }
        let held_us = listing_us
            .saturating_add(listing_deadline_us)
            .saturating_add(behind_us)
            .saturating_add(store_deadline_us);
        if held_us >= LISTING_HOLD_US {
            return Err(PeriodRefusal::Listing);
        }
        // A listing, or the open's store call and the drop queued behind it, is ahead of a due view.
        let ahead_us = listing_deadline_us.max(reads_us);
        let poll_us = (bounds.report_deadline())
            .saturating_add(view_us)
            .saturating_add(ahead_us)
            .saturating_add(reads_us);
        if poll_us >= bounds.window() {
            return Err(PeriodRefusal::Window);
        }
        Ok(Self {
            view_us,
            listing_us,
            store_deadline_us,
            listing_deadline_us,
            step_us: view_us,
        })
    }

    /// Submitting a suffix step makes the next step due `step_us` microseconds later. [`Periods::new`] sets the step
    /// period to the view period; `with_step` accepts any nonzero `step_us`.
    pub fn with_step(self, step_us: NonZeroU64) -> Self {
        Self {
            step_us: step_us.get(),
            ..self
        }
    }

    /// The deadline of one store call of the lane. The store class's request deadline and its watermark-log write
    /// stay within it.
    pub fn store_deadline_us(&self) -> u64 {
        self.store_deadline_us
    }

    /// The deadline the control-plane class enforces on one listing call.
    pub fn listing_deadline_us(&self) -> u64 {
        self.listing_deadline_us
    }
}

/// The identity a tenure's polls judge by. `holder` names the own volume and the own instance; each poll takes
/// the holder's host from the owner of the tenure's target, so the `host` given here is unread. `instance` returns
/// `Some` only for the verified instance of a standby host the caller expects on this volume, and `None` for every
/// other host, as [`inputs::peers`] requires: the poll admits the listed instance of each host it binds.
pub struct Records<'l> {
    pub holder: Holder,
    pub instance: &'l dyn Fn(Host) -> Option<InstanceId>,
}

/// A value and the duties' sequence stamp at the event that produced it.
type Stamped<T> = (T, u64);

/// The Report and the listing a view's poll judges, both taken when the duties submit the view, and the view's
/// stamp. The listing carries the stamp of its adoption.
type Snapshot = (
    Result<PolledReport, NotSole>,
    Option<Stamped<Vec<String>>>,
    u64,
);

type Viewed<R> = Result<Read<R>, StoreError>;

pub struct Duties<'l, S, L, P: Platform> {
    /// The gate of the owner's reclaim step, [`Owner::owner_reclaim`], and of the planned transfer, which only test
    /// builds construct. A transfer job carries it while it runs.
    standby: Option<StandbyGate>,
    lane: Lane<'l, S, L, P>,
    records: Records<'l>,
    plane: Option<Plane>,
    bounds: SuffixBounds,
    periods: Periods,
    open: Open,
    possible: Set,
    ends: Vec<(u64, u64)>,
    read: Option<Read<ShardRecord>>,
    writing: bool,
    open_at: u64,
    viewing: Option<Snapshot>,
    view_at: u64,
    /// The views the duties submitted this tenure; the completed view is number `views`, since one is outstanding at
    /// a time.
    pub(super) views: u64,
    /// The standby binding of the last volume record, stamped with the view that read the record: the peers the
    /// instance lookup bound, then each instance an attach or ended entry of another host bound, with its host. A
    /// view without the volume record judges its listing against this set, which is the set the record admitted.
    peers: Option<Stamped<Vec<Peer>>>,
    listing_at: u64,
    /// The last listing with its adoption time and stamp.
    listed: Option<(Vec<String>, u64, u64)>,
    /// The sequence stamp, advanced at each listing adoption and each view submission.
    stamp: u64,
    /// A listing call completed.
    listing_returned: bool,
    /// The outstanding view's snapshot holds no listing, and a listing call completed before it.
    unlisted: bool,
    /// The listing result of the last poll, unavailable when the poll left a listed record unjudged and found no
    /// foreign or duplicate record.
    enumeration: Enumeration,
    /// The lane's tally when the tenure open started.
    baseline: Option<Tally>,
    unobserved: u64,
    paging: bool,
    dropping: bool,
    /// The volume read and the ended pairs the reclaim step of the View this turn adopted returned.
    reclaimed: Option<(Read<VolumeRecord>, Vec<Pair>)>,
    page_next: Option<PageRequest>,
    page_after: Option<u16>,
    page_at: u64,
    acknowledged: Vec<CoverageEntry>,
    capture: Option<capture::Capture>,
    /// The last view read a shard record that names this tenure.
    viewed_tenure: bool,
    /// The layout the set was built under.
    layout: Option<Layout>,
    /// `unsettled` holds the checkpoints of Publishes with an unknown outcome until an acknowledged own write
    /// settles the set.
    unsettled: Option<Unsettled>,
    quarantine: Gauge,
    step_at: u64,
    /// A suffix step holds the set on the lane.
    stepping: bool,
    /// The signals of the last suffix step that sampled them, `None` until one did and after a step whose one try of
    /// the capture mutex failed.
    due: Option<SuffixDue>,
    /// The refusal of the last step adopted, `None` once a step committed.
    #[cfg(test)]
    step_refusal: Option<WriteRefused>,
    roll_due: bool,
    /// A suffix step sampled the signals.
    sampled: bool,
    linking: Option<status::Linking<'l>>,
    /// The `(g, owner, E)` of the last shard record the tenure read.
    target: Option<Target>,
    request: Option<super::link::Request>,
    /// The requests one inbox drain delivered, in delivery order, for duties built through [`Duties::requesting`];
    /// the inbox holds at most [`super::link::INBOX`] messages, the capacity reserved at construction.
    delivered: Vec<super::link::Request>,
    /// The slot of a Publish over a record that already named a checkpoint, ended with a store error: a Confirm
    /// settles the set before the next capture start.
    settling: Option<u32>,
    /// `roll_unpublished` stays set for the rest of the tenure once a capture start with no free checkpoint slot or
    /// a stage refused for placement sets `roll_due`; the roll then skips its Publish.
    roll_unpublished: bool,
    /// Boxed, so the turn of a running roll moves a pointer when it takes the roll out of the duties and returns it.
    rolling: Option<Box<roll::Roll>>,
    /// The open settled with the log closed; the next committed Publish runs the open again.
    open_again: bool,
}

impl<'l, S: Store, L: WatermarkLog, P: Platform> Duties<'l, S, L, P> {
    /// `lane` uses the owner process's client and storage. `plane` lists the own volume's attachments; with `None`
    /// every poll carries no listing.
    ///
    /// # Panics
    ///
    /// When `lane` holds an outstanding job: every completion the duties adopt is of a job they submitted.
    pub fn new(
        (_gate, standby): (&HostGate, StandbyGate),
        lane: Lane<'l, S, L, P>,
        records: Records<'l>,
        plane: Option<Plane>,
        bounds: SuffixBounds,
        periods: Periods,
    ) -> Self {
        assert_eq!(lane.outstanding(), 0, "the duties start over an idle lane");
        Self {
            standby: Some(standby),
            lane,
            records,
            plane,
            bounds,
            periods,
            open: Open::Due,
            possible: Set::Unbuilt,
            ends: Vec::new(),
            read: None,
            writing: false,
            open_at: 0,
            viewing: None,
            view_at: 0,
            views: 0,
            peers: None,
            listing_at: 0,
            listed: None,
            stamp: 0,
            listing_returned: false,
            unlisted: false,
            enumeration: Enumeration::Unavailable,
            baseline: None,
            unobserved: 0,
            paging: false,
            dropping: false,
            reclaimed: None,
            page_next: None,
            page_after: None,
            page_at: 0,
            acknowledged: Vec::new(),
            capture: None,
            viewed_tenure: false,
            layout: None,
            unsettled: None,
            quarantine: Gauge::Unavailable,
            step_at: 0,
            stepping: false,
            due: None,
            #[cfg(test)]
            step_refusal: None,
            roll_due: false,
            sampled: false,
            settling: None,
            linking: None,
            target: None,
            request: None,
            delivered: Vec::with_capacity(super::link::INBOX),
            roll_unpublished: false,
            rolling: None,
            open_again: false,
        }
    }

    /// After `owner` polls at `now`, the turn drains the link inbox, admits the planned requests it delivered to
    /// duties built through [`Duties::requesting`], and adopts at most one lane completion; adopting a View runs the
    /// owner poll and the reclaim step. While a withdrawn tenure's transfer waits for its outcome the turn submits no
    /// view and no listing. The turn then submits, in order: the view when due and no view, shard-record or page job
    /// is outstanding; the open's next job when the lane is idle and the owner admits the job; the listing when due
    /// and no view, shard-record, page or drop job is outstanding; the drop of the pairs the adopted View's reclaim
    /// step returned when no drop job is outstanding; and a page job when the lane is idle and the turn adopted no
    /// page completion. The planned exit's step runs last, and it can withdraw the authority, close the owner and
    /// submit the transfer job in that turn. It publishes the owner's status last; a turn that returns an exit, or
    /// that leaves the owner in a state for which [`super::serve::ended`] names one, publishes it whatever the status
    /// period.
    ///
    /// The turn returns [`Exit::Rerun`] with [`Rerun::Unwound`] if the adopted completion is [`Done::Panicked`], with
    /// [`Rerun::Withdrawn`] if it shows the client withdrawn, in any state of the open, the exit of an adopted view's
    /// poll, the exit of a coverage step that failed, the exit of a capture pass that ends the tenure, the exit of a
    /// planned exit ([`Rerun::Planned`], [`Exit::Stopped`] after an acknowledged transfer, [`Exit::Deposed`] when the
    /// view after a refused or unknown transfer shows a later tenure, or the exit [`super::serve::ended`] names when an
    /// earlier cause withdrew the tenure), and `None` otherwise. A panicked job
    /// loses any set it carried.
    ///
    /// Each step runs behind a test of conditions it needs, so a turn with no completion to adopt, an open that
    /// ended with no settling Confirm pending, no view, listing or suffix step due, no coverage work and no capture
    /// policy calls none of them.
    ///
    /// # Panics
    ///
    /// When a shard-record job would take the set while another carries it (PossNamedCoversStore), or the lane
    /// refuses a submit while no job is outstanding.
    pub fn turn<'a, D: Disk, T: Datagrams<'a>>(
        &mut self,
        owner: &mut Owner<'_, 'a, '_, P, D, T>,
        now: u64,
    ) -> Option<Exit> {
        self.inbound(owner, now);
        self.intake(owner, now);
        self.acknowledged.clear();
        self.reclaimed = None;
        let mut paged = false;
        if let Some(done) = self.lane.poll() {
            paged = matches!(done, Done::Page { .. });
            if let Some(exit) = self.adopt(owner, done, now) {
                self.publish(owner, now, true);
                return Some(exit);
            }
        }
        if !matches!(self.open, Open::Opened | Open::Stopped) {
            self.advance(owner);
        }
        // A queued View runs ahead of every other job, so no elective read is submitted while the withdrawn owner's
        // transfer waits on the lane; the reread a refused or unknown outcome asks for is submitted as usual.
        let transferring = self.transfer_waits(owner);
        if now >= self.view_at && self.viewing.is_none() && !transferring {
            self.view(owner, now);
        }
        if matches!(self.open, Open::Confirming | Open::Opening) || self.settling.is_some() {
            self.write(owner, now);
        }
        if now >= self.listing_at && self.plane.is_some() && !transferring {
            self.list(now);
        }
        if let Some((read, pairs)) = self.reclaimed.take() {
            self.drop_pairs(owner, read, pairs);
        }
        // With no follow-up request saved, no page to move on from and nothing waiting at the owner, the coverage
        // step would start no write and change nothing.
        let covers = self.page_next.is_some() || self.page_after.is_some() || owner.cover_waits();
        if !paged
            && covers
            && !self.paging
            && now >= self.page_at
            && let Some(exit) = self.cover(owner, now)
        {
            self.publish(owner, now, true);
            return Some(exit);
        }
        // The pass takes the set before the step on a turn both need it, so a step period at or below a lane round
        // trip still leaves the pass its turns. A pass that ends the tenure ends the turn.
        if self.capture.is_some()
            && let Some(exit) = self.capture(owner, now)
        {
            self.publish(owner, now, true);
            return Some(exit);
        }
        if self.open == Open::Opened && now >= self.step_at && !self.roll_sealed() {
            self.step(owner, now);
        }
        let exit = self.roll(owner, now);
        self.publish(owner, now, exit.is_some());
        exit
    }

    /// Starts the open once the owner is `Live`, and stops an open under way once the owner closed to writes.
    #[inline(never)]
    fn advance<'a, D: Disk, T: Datagrams<'a>>(&mut self, owner: &Owner<'_, 'a, '_, P, D, T>) {
        if self.open == Open::Due && owner.readiness() == Readiness::Live {
            let own = std::ptr::eq(self.lane.storage(), owner.storage());
            let bounds = self.bounds.limits.bounded() && self.bounds.step > 0;
            self.open = match own && bounds {
                true => Open::Viewing,
                false => Open::Stopped,
            };
            self.baseline = Some(self.lane.tally());
        }
        if matches!(self.open, Open::Viewing | Open::Confirming | Open::Opening)
            && closed_to_writes(owner)
        {
            self.open = Open::Stopped;
        }
    }

    #[inline(never)]
    fn cover<'a, D: Disk, T: Datagrams<'a>>(
        &mut self,
        owner: &mut Owner<'_, 'a, '_, P, D, T>,
        now: u64,
    ) -> Option<Exit> {
        if self.lane.outstanding() > 0 || now < self.page_at {
            return None;
        }
        let request = match self.page_next.take() {
            Some(request) => owner.cover_continues().then_some(request),
            None => match owner.cover_begin(self.page_after, now) {
                Ok(request) => request,
                Err(_) => return withdrawn(owner),
            },
        };
        let Some(request) = request else {
            self.page_after = None;
            return None;
        };
        self.page_after = Some(request.page());
        match self.lane.submit(Job::Page { request }) {
            Ok(()) => self.paging = true,
            Err(job) => {
                if let Job::Page { request } = *job {
                    self.page_next = Some(request);
                }
            }
        }
        None
    }

    #[inline(never)]
    fn view<'a, D: Disk, T: Datagrams<'a>>(
        &mut self,
        owner: &Owner<'_, 'a, '_, P, D, T>,
        now: u64,
    ) {
        if self.viewing.is_some() || self.writing || self.paging || now < self.view_at {
            return;
        }
        let listed = (self.listed.as_ref())
            .filter(|(_, at, _)| now.saturating_sub(*at) <= self.periods.listing_us)
            .map(|(listed, _, stamp)| (listed.clone(), *stamp));
        let unlisted = listed.is_none() && self.listing_returned;
        let stamp = self.stamp + 1;
        let snapshot = (owner.poll_report(), listed, stamp);
        let job = Job::View {
            volume: self.records.holder.volume,
            shard: owner.tenure().shard(),
            sent_at: owner.serving_sample(),
        };
        if self.lane.submit(job).is_ok() {
            self.stamp = stamp;
            (self.viewing, self.unlisted) = (Some(snapshot), unlisted);
            self.view_at = now.saturating_add(self.periods.view_us);
            self.views += 1;
        }
    }

    #[inline(never)]
    fn list(&mut self, now: u64) {
        if self.viewing.is_some()
            || self.writing
            || self.paging
            || self.dropping
            || now < self.listing_at
        {
            return;
        }
        let Some(plane) = self.plane.take() else {
            return;
        };
        let job = Job::Listing {
            plane,
            volume: self.records.holder.volume,
            sent_at: now,
        };
        match self.lane.submit(job) {
            Ok(()) => self.listing_at = now.saturating_add(self.periods.listing_us),
            Err(job) => {
                if let Job::Listing { plane, .. } = *job {
                    self.plane = Some(plane);
                }
            }
        }
    }

    #[inline(never)]
    fn adopt<'a, D: Disk, T: Datagrams<'a>>(
        &mut self,
        owner: &mut Owner<'_, 'a, '_, P, D, T>,
        done: Done,
        now: u64,
    ) -> Option<Exit> {
        match done {
            Done::View {
                sent_at,
                volume,
                shard,
            } => {
                let exit = self.viewed(owner, (sent_at, volume, shard), now);
                self.release_halted(owner);
                return exit;
            }
            Done::Confirm {
                possible,
                confirmed,
            } => {
                let ended = write_withdrew(owner, &confirmed, now);
                if self.open == Open::Opened {
                    self.resettled(possible, confirmed);
                } else {
                    self.returned(possible);
                    self.settle(confirmed.map(|read| (read, false)), Open::Opening, now);
                }
                if ended {
                    return Some(Exit::Rerun(Rerun::Withdrawn));
                }
            }
            Done::Open { possible, opened } => {
                self.returned(possible);
                let ended = write_withdrew(owner, &opened, now);
                self.settle(opened, Open::Opened, now);
                if ended {
                    return Some(Exit::Rerun(Rerun::Withdrawn));
                }
            }
            Done::Step {
                possible,
                stepped,
                due,
            } => {
                let ended = write_withdrew(owner, &stepped, now);
                self.stepped(possible, stepped, due);
                if ended {
                    return Some(Exit::Rerun(Rerun::Withdrawn));
                }
            }
            Done::Publish {
                possible,
                staged,
                published,
            } => {
                let ended = matches!(&published, Err(WriteRefused::Store(error))
                    if client_withdrawn(owner, [error], now));
                self.published(possible, staged, published);
                if ended {
                    self.open = Open::Stopped;
                    return Some(Exit::Rerun(Rerun::Withdrawn));
                }
            }
            Done::Certify {
                possible,
                end,
                certified,
            } => {
                let ended = write_withdrew(owner, &certified, now);
                let storage = owner.storage();
                self.roll_certified(possible, end, certified, |end| {
                    let _ = storage.with_suffix(|log| log.certified(end));
                });
                if ended {
                    return Some(Exit::Rerun(Rerun::Withdrawn));
                }
            }
            Done::Listing {
                plane,
                listed,
                sent_at,
            } => {
                self.plane = Some(plane);
                self.listing_returned = true;
                self.stamp += 1;
                self.listed = listed
                    .ok()
                    .filter(|_| now.saturating_sub(sent_at) <= self.periods.listing_deadline_us)
                    .map(|listed| (listed, now, self.stamp));
            }
            Done::Transfer { gate, transferred } => {
                self.standby = Some(gate);
                return self.transfer_done(owner, transferred, now);
            }
            Done::Drop { dropped } => {
                self.dropping = false;
                let error = dropped.as_ref().and_then(|dropped| dropped.as_ref().err());
                if client_withdrawn(owner, error, now) {
                    self.open = Open::Stopped;
                    return Some(Exit::Rerun(Rerun::Withdrawn));
                }
            }
            Done::Page { reply } => {
                self.paging = false;
                match owner.cover_end(reply, &mut self.acknowledged, now) {
                    Ok(Cover::Next(request)) => self.page_next = Some(request),
                    Ok(Cover::Unresolved) => {
                        self.page_at = now.saturating_add(self.periods.view_us);
                    }
                    Ok(Cover::Rebased | Cover::Done) => {}
                    Err(_) => return withdrawn(owner),
                }
            }
            #[cfg(test)]
            Done::Held => {}
            #[cfg(test)]
            Done::Marked => {}
            Done::Panicked => {
                self.open = Open::Stopped;
                return Some(Exit::Rerun(Rerun::Unwound));
            }
        }
        None
    }

    fn viewed<'a, D: Disk, T: Datagrams<'a>>(
        &mut self,
        owner: &mut Owner<'_, 'a, '_, P, D, T>,
        (sent_at, volume, shard): (u64, Viewed<VolumeRecord>, Viewed<ShardRecord>),
        now: u64,
    ) -> Option<Exit> {
        let snapshot = self.viewing.take();
        #[cfg(test)]
        let snapshot = snapshot.map(|(polled, listed, stamp)| match tests::planted() {
            true => (owner.poll_report(), listed, stamp),
            false => (polled, listed, stamp),
        });
        let errors = [volume.as_ref().err(), shard.as_ref().err()];
        let undecoded = (errors.into_iter().flatten()).any(|e| matches!(e, StoreError::Codec(_)));
        let ended = client_withdrawn(owner, errors.into_iter().flatten(), now) || undecoded;
        self.view_at = self.view_at.max(now.saturating_add(1));
        let (volume, shard) = (volume.ok(), shard.ok());
        if let Some(read) = &shard {
            self.target = Some(Target::of(read.value()));
        }
        let target = owner.tenure().target();
        let holder = Holder {
            host: target.owner,
            ..self.records.holder
        };
        owner.observe_shard_view(holder.volume, shard.as_ref(), volume.as_ref(), None, now);
        let names = shard
            .as_ref()
            .is_some_and(|read| Target::of(read.value()) == target);
        self.viewed_tenure = names;
        if let Some(roll) = self.rolling.as_mut() {
            roll.viewed = shard.as_ref().filter(|_| names).map(|read| *read.value());
            roll.volume_read = volume.is_some();
            // An incomplete view preserves the previous value of `roll.standby_enrolled`.
            if let (Some(volume), Some(shard)) = (volume.as_ref(), shard.as_ref()) {
                let (volume, shard) = (volume.value(), shard.value());
                roll.standby_enrolled = volume.volume == shard.active
                    && (shard.standby).is_some_and(|standby| volume.enrolled(standby).is_some());
            }
            roll.seen = shard.as_ref().map(|read| (*read.value(), self.views));
        }
        match &shard {
            Some(_) if names => {
                owner.authority_event(Event::Refresh { at: sent_at }, now);
            }
            Some(_) => {}
            None if !ended => {
                owner.authority_event(Event::ReadFailed { sent_at }, now);
            }
            None => {}
        }
        let mut pairs = Vec::new();
        if let Some((polled, listed, stamp)) = snapshot {
            // A view that read its volume record judges with the peers its lookup binds, since the record's entries
            // admit the instances they bind. The binding it leaves for a view without the record holds both.
            let lookup = volume.as_ref().and_then(|read| {
                let record = read.value();
                let peers = inputs::peers(&holder, record, self.records.instance)?;
                let entries = (record.bound_beside(holder.host))
                    .map(|(host, &instance)| Peer { host, instance });
                self.peers = Some((peers.iter().copied().chain(entries).collect(), stamp));
                Some(peers)
            });
            // READ-ORDER: the binding admits a listing the duties adopted before they submitted the view that
            // produced the binding. A view that read its volume record produced its binding itself, and its
            // snapshot's listing is older than its submission.
            let bound = (self.peers.as_ref()).filter(|(_, bound)| {
                listed.as_ref().is_none_or(|(_, adopted)| adopted < bound) || unbounded()
            });
            let total = listed.as_ref().map_or(0, |(listed, _)| listed.len());
            let listed = listed.map(|(listed, _)| match bound {
                Some(_) => listed,
                None => unbindable(&holder, listed),
            });
            // Without a binding READ-ORDER admits, the check runs without the records a binding could admit.
            let unjudged = listed.as_ref().is_some_and(|kept| kept.len() < total);
            let peers = match (&lookup, bound) {
                (_, None) => &[][..],
                (Some(lookup), Some(_)) => lookup,
                (None, Some((binding, _))) => binding,
            };
            let reads = inputs::reads(
                shard.as_ref().map(Read::value),
                volume.as_ref().map(Read::value),
                listed.as_deref(),
                peers,
            );
            let report = polled.as_ref().map(PolledReport::report);
            let report = report.as_ref().map_err(|refusal| **refusal);
            let verdict = owner.owner_poll(&holder, report, &reads, sent_at, now);
            if let (Some(read), Some(gate)) = (&volume, &self.standby) {
                let reclaimed = owner.owner_reclaim(gate, &holder, &verdict, report, read.value());
                pairs = droppable(shard.as_ref().map(Read::value), read.value(), reclaimed);
            }
            self.enumeration = match poll::owner_listing(&holder, &reads) {
                // A foreign or duplicate record retires whatever the unjudged records hold; a clean result and a
                // missing own record each also claim that no record lies outside the admitted set.
                Some(checked) if unjudged && !checked.as_ref().is_err_and(Mismatch::retires) => {
                    Enumeration::Unavailable
                }
                Some(checked) => Enumeration::from(&checked),
                None if self.unlisted => Enumeration::Unlisted,
                None => Enumeration::Unavailable,
            };
            if let Some(exit) = self.act(owner, verdict, (names, &polled), now) {
                self.open = Open::Stopped;
                return Some(exit);
            }
        }
        if ended {
            self.open = Open::Stopped;
            return Some(Exit::Rerun(Rerun::Withdrawn));
        }
        let relaid = (volume.as_ref())
            .zip(self.layout)
            .is_some_and(|(volume, layout)| volume.value().layout != layout);
        // A relaid volume stops the open; its arms below then skip, and the reclaim step's drop still goes out.
        if relaid {
            self.open = Open::Stopped;
        }
        match (&volume, shard) {
            (Some(volume), Some(shard)) if self.open == Open::Viewing => {
                self.begin(owner, (volume.value(), shard));
            }
            // After a store error the next view of the tenure that reconciles becomes the base. A newer read naming
            // the base's checkpoint, such as one after a spare designation, or the checkpoint of an unsettled
            // Publish, becomes the base of the next Publish. Neither settles anything in the set.
            (_, Some(shard)) if self.open == Open::Opened && names => {
                let judged = (self.read.as_ref()).map(|held| self.judge(held, &shard));
                match judged {
                    None if self.reconciles(&shard) => self.read = Some(shard),
                    None | Some(Judged::Foreign) => self.open = Open::Stopped,
                    Some(Judged::Base) => self.read = Some(shard),
                    Some(Judged::Stale) => {}
                }
            }
            _ => {}
        }
        if let Some(read) = volume.filter(|_| !pairs.is_empty()) {
            self.reclaimed = Some((read, pairs));
        }
        None
    }

    /// Any read reconciles when all Publishes are settled. Otherwise, `shard` must name the first unsettled
    /// Publish's base checkpoint or a checkpoint submitted by an unsettled Publish.
    fn reconciles(&self, shard: &Read<ShardRecord>) -> bool {
        let named = shard.value().checkpoint;
        (self.unsettled.as_ref())
            .is_none_or(|unsettled| named == unsettled.prior || unsettled.submitted(named))
    }

    fn judge(&self, held: &Read<ShardRecord>, shard: &Read<ShardRecord>) -> Judged {
        let publishing = (self.capture.as_ref())
            .is_some_and(|capture| matches!(capture.pass, capture::Pass::Publishing { .. }));
        if publishing || shard.version() <= held.version() {
            return Judged::Stale;
        }
        let named = shard.value().checkpoint;
        let submitted =
            (self.unsettled.as_ref()).is_some_and(|unsettled| unsettled.submitted(named));
        match named == held.value().checkpoint || submitted {
            true => Judged::Base,
            false => Judged::Foreign,
        }
    }

    /// Moves the open to `next` unless it stopped.
    fn reopen(&mut self, next: Open) {
        if self.open != Open::Stopped {
            self.open = next;
        }
    }

    /// The duties build the set once, from the first View that returns both reads. The Confirm writes back the
    /// viewed value, so the committed record names the slot the set holds, as [`PossiblyNamed::new`] requires, and
    /// the first reservation follows that Confirm. A View after a failed write keeps the set, so an own write of
    /// unknown outcome stays possibly named until an own success settles it.
    ///
    /// The suffix log maps each LSN to a prefix unit by the set's layout. The first View of a warm tenure must show
    /// the layout of the warm read, and each later View must show the set's layout. A layout mismatch can direct a
    /// suffix write to a unit holding the loaded checkpoint or a predecessor suffix block.
    fn begin<'a, D: Disk, T: Datagrams<'a>>(
        &mut self,
        owner: &mut Owner<'_, 'a, '_, P, D, T>,
        (volume, shard): (&VolumeRecord, Read<ShardRecord>),
    ) {
        let record = shard.value();
        let layout = volume.layout;
        let own = self.records.holder.volume;
        let names = volume.volume == own
            && record.shard == owner.tenure().shard()
            && record.active == own
            && volume_state(record, volume) == Ok(VolumeState::Active);
        let (_, region) = required_history(record, &layout);
        let admits = layout.check_floor().is_ok() && self.bounds.step <= region;
        let manifest = record.checkpoint.is_some() || record.ancestry.as_slice().is_empty();
        let bound = match &self.possible {
            Set::Here(possible) => *possible.layout() == layout,
            Set::Unbuilt => (owner.warm_layout()).is_none_or(|loaded| loaded == layout),
            Set::Away => true,
        };
        let unbuilt = matches!(self.possible, Set::Unbuilt);
        let attached = !unbuilt || owner.admits_layout(&layout);
        let reconciled = unbuilt || self.reconciles(&shard);
        if !(names && admits && manifest && bound && attached && reconciled) {
            self.open = Open::Stopped;
            return;
        }
        if unbuilt {
            self.layout = Some(layout);
            self.ends = owner.certified().unwrap_or_default();
            let session = owner.tenure().get();
            let named = record.checkpoint;
            let tenure = (owner.tenure().shard(), session);
            self.possible = Set::Here(PossiblyNamed::new(tenure, layout, named));
        }
        self.read = Some(shard);
        self.open = Open::Confirming;
    }

    /// EndOrder, STORE-OFF-POLL: submits the drop of `pairs` from `read`, the volume record the poll judged, as one
    /// [`Job::Drop`] that carries the tenure's session, while no drop job is outstanding. The turn calls it after the open's
    /// next job and the listing, so the lane runs a Confirm or Open submitted in the same turn ahead of the drop. A
    /// later poll uses a fresh read to determine which pairs still qualify for a drop.
    fn drop_pairs<'a, D: Disk, T: Datagrams<'a>>(
        &mut self,
        owner: &Owner<'_, 'a, '_, P, D, T>,
        read: Read<VolumeRecord>,
        pairs: Vec<Pair>,
    ) {
        if pairs.is_empty() || self.dropping {
            return;
        }
        let job = Job::Drop {
            read,
            pairs,
            session: owner.tenure().get(),
        };
        self.dropping = self.lane.submit(job).is_ok();
    }

    fn act<'a, D: Disk, T: Datagrams<'a>>(
        &mut self,
        owner: &mut Owner<'_, 'a, '_, P, D, T>,
        verdict: Verdict,
        (names, polled): (bool, &Result<PolledReport, NotSole>),
        now: u64,
    ) -> Option<Exit> {
        match verdict {
            Verdict::Continue => {}
            Verdict::Unobserved => self.unobserved += 1,
            Verdict::Deposed => {
                // A shard read below the tenure's `(g, E)` names no later tenure: the owner withdrew on it as a
                // regression, and the incarnation reruns.
                if owner.authority_withdrawal() == Some(Cause::Regression) && !owner.has_successor()
                {
                    return Some(Exit::Rerun(Rerun::Withdrawn));
                }
                owner.authority_event(Event::Withdraw(Cause::Flipped), now);
                return Some(Exit::Deposed);
            }
            Verdict::Retire(retirement) => {
                owner.authority_event(Event::Withdraw(cause(retirement.trigger())), now);
                return Some(Exit::Retire(retirement.target));
            }
            Verdict::Withdraw => {
                if owner.authority_state() != State::Withdrawn {
                    let held = (polled.as_ref()).is_ok_and(|polled| {
                        let report = polled.report();
                        report.rtype != ReservationType::None
                            && report.entries.iter().any(|entry| entry.holder)
                    });
                    let cause = if held {
                        Cause::RecordedHolder
                    } else {
                        Cause::Unheld
                    };
                    owner.authority_event(Event::Withdraw(cause), now);
                }
            }
        }
        let holder = matches!(owner.authority_state(), State::Withdrawn | State::Closed)
            && owner.authority_report().withdrawal == Some(Cause::RecordedHolder);
        (holder && names).then_some(Exit::Rerun(Rerun::RecordedHolder))
    }

    fn settle(
        &mut self,
        written: Result<(Read<ShardRecord>, bool), WriteRefused>,
        next: Open,
        now: u64,
    ) {
        self.writing = false;
        if !matches!(self.open, Open::Confirming | Open::Opening) {
            return;
        }
        match written {
            Ok((read, opened)) => {
                self.target = Some(Target::of(read.value()));
                let named = read.value().checkpoint.is_some();
                self.read = Some(read);
                self.unsettled = None;
                if next == Open::Opened && !opened && named {
                    self.open_at = now.saturating_add(self.periods.view_us);
                } else {
                    self.reopen(next);
                }
            }
            Err(WriteRefused::Chain) if next == Open::Opened && self.reopens() => {
                // The reservation refused `Chain`: the record's required history fills the delta region, or its chain
                // is at its cap. The open settles with the log closed, a due Publish raises the floor, and the open
                // runs again after that Publish.
                (self.open, self.read, self.open_again) = (Open::Opened, None, true);
                if let Some(capture) = self.capture.as_mut() {
                    capture.publish_due = true;
                }
            }
            Err(
                WriteRefused::Tenure
                | WriteRefused::Chain
                | WriteRefused::Store(
                    StoreError::Successor(_)
                    | StoreError::Codec(_)
                    | StoreError::Regression(_)
                    | StoreError::Namespace
                    | StoreError::Log
                    | StoreError::Withdrawn,
                ),
            ) => self.open = Open::Stopped,
            Err(_) => self.reopen(Open::Viewing),
        }
    }

    /// Whether a refused suffix reservation settles the open with the log closed: duties with a capture policy, whose
    /// Publish can raise the floor.
    fn reopens(&self) -> bool {
        #[cfg(test)]
        if roll_tests::stopped_open() {
            return false;
        }
        self.capture.is_some()
    }

    #[inline(never)]
    fn write<'a, D: Disk, T: Datagrams<'a>>(
        &mut self,
        owner: &Owner<'_, 'a, '_, P, D, T>,
        now: u64,
    ) {
        let settling = self.open == Open::Opened && self.settling.is_some() && self.read.is_some();
        if !(matches!(self.open, Open::Confirming | Open::Opening) || settling)
            || !matches!(self.possible, Set::Here(_))
            || self.lane.outstanding() > 0
            || now < self.open_at
            || owner.lost()
            || owner.poisoned()
            || owner.authority_report().state == State::Withdrawn
        {
            return;
        }
        let own = owner.tenure().target();
        let job = match self.open {
            Open::Confirming => {
                let read = self
                    .read
                    .take()
                    .expect("a confirm follows the view it read");
                Job::Confirm {
                    possible: self.take_set(),
                    read,
                    own,
                }
            }
            Open::Opening => {
                let read = self
                    .read
                    .take()
                    .expect("an open follows its confirmed read");
                let ends = uncertified_ends(&self.ends, read.value());
                Job::Open {
                    possible: self.take_set(),
                    read,
                    own,
                    ends,
                    bounds: self.bounds,
                }
            }
            Open::Opened if settling => Job::Confirm {
                possible: self.take_set(),
                read: self
                    .read
                    .take()
                    .expect("the settling Confirm follows the view it read"),
                own,
            },
            Open::Due | Open::Viewing | Open::Opened | Open::Stopped => return,
        };
        self.writing = true;
        self.lane
            .submit(job)
            .expect("the duties hold one shard-record job outstanding");
    }

    /// Submits the step period's suffix step once the open finished, when the duties' read names a checkpoint and the
    /// lane is idle, so the step is the lane's one outstanding job and the set is on the owner thread. A capture
    /// pass's encode leaves the set here, so a step goes out while the helpers encode.
    /// Steps end once the owner is closed to writes ([`closed_to_writes`]); a withdrawn owner keeps polling its views.
    #[inline(never)]
    fn step<'a, D: Disk, T: Datagrams<'a>>(
        &mut self,
        owner: &Owner<'_, 'a, '_, P, D, T>,
        now: u64,
    ) {
        if self.open != Open::Opened || self.lane.outstanding() > 0 || now < self.step_at {
            return;
        }
        let named = self
            .read
            .as_ref()
            .filter(|read| read.value().checkpoint.is_some());
        let Some(read) = named.filter(|_| !closed_to_writes(owner)).cloned() else {
            return;
        };
        let job = Job::Step {
            possible: self.take_set(),
            read,
            own: owner.tenure().target(),
            bounds: self.bounds,
        };
        (self.writing, self.stepping) = (true, true);
        self.step_at = now.saturating_add(self.periods.step_us);
        self.lane
            .submit(job)
            .expect("the duties hold one shard-record job outstanding");
    }

    /// Adopts a step's completion. A store error may follow a request that committed, so the next view's read of
    /// this tenure replaces the duties' read; a tenure mismatch stops the duties' shard-record writes, as it stops the
    /// open. A due publication holds a capture start due until a Publish commits; duties with no capture policy
    /// cannot publish, so for them, as for a due handoff, it sets [`Duties::roll_due`].
    fn stepped(
        &mut self,
        possible: PossiblyNamed,
        stepped: Result<Read<ShardRecord>, WriteRefused>,
        due: Option<SuffixDue>,
    ) {
        (self.writing, self.stepping) = (false, false);
        self.returned(possible);
        #[cfg(test)]
        {
            self.step_refusal = stepped.as_ref().err().copied();
        }
        match stepped {
            Ok(read) => {
                self.target = Some(Target::of(read.value()));
                self.read = Some(read);
            }
            Err(WriteRefused::Store(_)) => self.read = None,
            Err(WriteRefused::Tenure) => self.open = Open::Stopped,
            Err(_) => {}
        }
        #[cfg(test)]
        let due = due.or_else(|| step_tests::default_signal().then(SuffixDue::default));
        self.due = due;
        let Some(due) = due else {
            return;
        };
        self.sampled = true;
        self.roll_due |= due.handoff || (due.publication && self.capture.is_none());
        if let Some(capture) = self.capture.as_mut() {
            capture.publish_due |= due.publication;
        }
    }

    /// Adopts the settling Confirm of an opened tenure. A committed Confirm settles the set to the read's checkpoint.
    /// When that checkpoint is in the lost Publish's slot, the Publish committed and fulfilled the publication it
    /// served; the monotonic `abandoned` count of [`Duties::captures`] still includes the pass. Otherwise the
    /// publication stays due, and the next step samples the settled floor again. A store error drops the read, and
    /// the next view confirms its read of this tenure again; a tenure mismatch stops the duties' shard-record
    /// writes.
    fn resettled(
        &mut self,
        possible: PossiblyNamed,
        confirmed: Result<Read<ShardRecord>, WriteRefused>,
    ) {
        self.writing = false;
        self.returned(possible);
        match confirmed {
            Ok(read) => {
                let slot = read.value().checkpoint.map(|named| named.slot);
                if let Some(capture) = self.capture.as_mut()
                    && slot.is_some()
                    && slot == self.settling
                {
                    capture.publish_due = false;
                    #[cfg(test)]
                    {
                        capture.published += 1;
                        capture.refusal = None;
                    }
                }
                (self.read, self.settling, self.unsettled) = (Some(read), None, None);
            }
            Err(WriteRefused::Tenure) => self.open = Open::Stopped,
            Err(_) => self.read = None,
        }
    }

    /// Whether the set is on the owner thread: no shard-record job or encode holds it.
    pub(super) fn set_here(&self) -> bool {
        matches!(self.possible, Set::Here(_))
    }

    fn take_set(&mut self) -> PossiblyNamed {
        match std::mem::replace(&mut self.possible, Set::Away) {
            Set::Here(possible) => possible,
            Set::Unbuilt | Set::Away => {
                panic!("PossNamedCoversStore: one shard-record job holds the possibly-named set")
            }
        }
    }

    /// A latched request to roll to a new tenure, set by a due handoff, a capture start refused with no free
    /// checkpoint slot, a stage refused for placement, or, for duties with no capture policy, a due publication. The
    /// tenure keeps serving hits; the log refuses a mutation only at its own bound. The roll that clears it starts a
    /// new tenure.
    pub fn roll_due(&self) -> bool {
        self.roll_due
    }

    /// The signals of the last suffix step, `None` until a step sampled them and for a step that sampled none.
    pub fn suffix_due(&self) -> Option<SuffixDue> {
        self.due
    }

    pub fn open(&self) -> Open {
        self.open
    }

    pub fn unobserved(&self) -> u64 {
        self.unobserved
    }

    /// The entries acknowledged by the page completion this turn adopted, once each; empty after a turn that
    /// adopted none. The next turn replaces them, so a caller reads them after each turn.
    pub fn acknowledged(&self) -> &[CoverageEntry] {
        &self.acknowledged
    }

    /// Ends the lane as [`Lane::end`] does and returns the client: the job the lane thread runs completes, the
    /// queued jobs drop unrun, and an unadopted completion drops. A store write of the running job can commit after
    /// the owner's teardown when the caller ends the duties after `serve` returns.
    ///
    /// # Panics
    ///
    /// When the lane thread panicked outside its job containment.
    pub fn end(self) -> crate::storage::store::Client<S, L> {
        self.lane.end()
    }
}

/// The exit of a tenure whose coverage step failed: the exit the owner's authority names ([`super::serve::ended`]).
/// A newer page fence has withdrawn the authority by then, which names [`Exit::Deposed`] when the fence is an
/// activated session and [`Rerun::Withdrawn`] otherwise. With none named, an authority already withdrawn keeps its
/// post-withdrawal poll and no exit follows, since [`Owner::cover_open`] refuses every later page write. A serving
/// authority ends the incarnation with [`Rerun::Withdrawn`]: a latched cause closes coverage writes and FILL for
/// the incarnation, and an unpaired reply, which the duty's one outstanding page job never produces, leaves the
/// owner's write in flight with no reply to end it, so the next incarnation judges the records again.
fn withdrawn<'a, P: Platform, D: Disk, T: Datagrams<'a>>(
    owner: &Owner<'_, 'a, '_, P, D, T>,
) -> Option<Exit> {
    super::serve::ended(owner).or_else(|| {
        (owner.authority_report().state != State::Withdrawn)
            .then_some(Exit::Rerun(Rerun::Withdrawn))
    })
}

fn closed_to_writes<'a, P: Platform, D: Disk, T: Datagrams<'a>>(
    owner: &Owner<'_, 'a, '_, P, D, T>,
) -> bool {
    matches!(owner.authority_state(), State::Withdrawn | State::Closed)
        || owner.readiness() != Readiness::Live
        || owner.lost()
        || owner.poisoned()
}

fn uncertified_ends(ends: &[(u64, u64)], record: &ShardRecord) -> Vec<(u64, u64)> {
    let chain = record.ancestry.as_slice();
    (ends.iter().copied())
        .filter(|&(session, end)| {
            (chain.iter()).any(|suffix| suffix.session == session && suffix.certified < end)
        })
        .collect()
}

/// Whether the store error that refused a shard-record job's write withdrew the store client, as
/// [`client_withdrawn`] judges it.
fn write_withdrew<'a, R, P: Platform, D: Disk, T: Datagrams<'a>>(
    owner: &mut Owner<'_, 'a, '_, P, D, T>,
    written: &Result<R, WriteRefused>,
    now: u64,
) -> bool {
    matches!(written, Err(WriteRefused::Store(error)) if client_withdrawn(owner, [error], now))
}

/// Whether `errors` show the lane's client withdrawn: a regression, a record of another namespace, a failed
/// watermark record, or a call on a client one of those withdrew. A regression also withdraws the tenure with
/// `Cause::Regression`.
fn client_withdrawn<'a, 'e, P: Platform, D: Disk, T: Datagrams<'a>>(
    owner: &mut Owner<'_, 'a, '_, P, D, T>,
    errors: impl IntoIterator<Item = &'e StoreError>,
    now: u64,
) -> bool {
    let mut withdrawn = false;
    for error in errors {
        if matches!(error, StoreError::Regression(_)) {
            owner.authority_event(Event::Withdraw(Cause::Regression), now);
        }
        withdrawn |= matches!(
            error,
            StoreError::Regression(_)
                | StoreError::Namespace
                | StoreError::Log
                | StoreError::Withdrawn
        );
    }
    withdrawn
}

/// Whether a test planted the control that admits the last binding for every listing; false outside tests.
#[cfg(not(test))]
fn unbounded() -> bool {
    false
}

#[cfg(test)]
use tests::unbounded;

/// The records of `listed` that no standby binding admits: the own instance, a record that is no instance ID, and
/// every record listed more than once, since a binding admits each standby once.
fn unbindable(holder: &Holder, listed: Vec<String>) -> Vec<String> {
    let kept = |record: &String| {
        record == holder.instance.as_str()
            || InstanceId::new(record).is_none()
            || listed.iter().filter(|other| *other == record).count() > 1
    };
    listed
        .iter()
        .filter(|record| kept(record))
        .cloned()
        .collect()
}

/// NAMED-PAIR-KEPT: the pairs of `pairs` the owner drops from `volume`, given `shard`, the shard record read by
/// the same View, or `None` when that read failed. A failed read keeps every pair, and a read keeps each pair that
/// `volume` records for the host it names owner or standby. Such a host may hold a takeover CAS prepared before
/// its end, and that CAS's successor passes the next takeover's Predecessor check only while its pair stays
/// recorded. A later View drops the pair once the shard record names neither role for its host.
pub(crate) fn droppable(
    shard: Option<&ShardRecord>,
    volume: &VolumeRecord,
    mut pairs: Vec<Pair>,
) -> Vec<Pair> {
    #[cfg(test)]
    if reclaim_tests::unguarded() {
        return pairs;
    }
    let Some(shard) = shard else {
        return Vec::new();
    };
    let named = |host: Host| host == shard.owner || shard.standby == Some(host);
    pairs.retain(|pair| {
        !(volume.pairs.iter()).any(|recorded| recorded.pair == *pair && named(recorded.host))
    });
    pairs
}

fn cause(trigger: &Trigger) -> Cause {
    match trigger {
        Trigger::Attachment(_) | Trigger::Events => Cause::Attachment,
        Trigger::Report(refusal) => {
            ReportTrigger::new(*refusal).map_or(Cause::RestartCheck, Cause::Report)
        }
        Trigger::Modification => Cause::Modification,
        Trigger::VolumeState | Trigger::Layout(_) => Cause::RestartCheck,
        Trigger::Activation => Cause::ActivationRecord,
    }
}

#[path = "duties_capture.rs"]
mod capture;
pub use capture::{CaptureRefusal, Uncaptured};
#[path = "duties_status.rs"]
mod status;
pub use status::{Linked, STATUS_US};
#[cfg(test)]
#[path = "duties_capture_tests.rs"]
pub(crate) mod capture_tests;
#[cfg(test)]
#[path = "duties_cover_tests.rs"]
pub(super) mod cover_tests;
#[cfg(test)]
#[path = "duties_lapse_tests.rs"]
mod lapse_tests;
#[cfg(test)]
#[path = "duties_observed_tests.rs"]
mod observed_tests;
#[cfg(test)]
#[path = "duties_reclaim_tests.rs"]
mod reclaim_tests;
#[path = "duties_roll.rs"]
mod roll;
#[cfg(test)]
#[path = "duties_roll_tests.rs"]
pub(crate) mod roll_tests;
#[cfg(test)]
#[path = "duties_status_tests.rs"]
mod status_tests;
#[cfg(test)]
#[path = "duties_step_tests.rs"]
pub(crate) mod step_tests;
#[cfg(test)]
#[path = "duties_tests.rs"]
pub(crate) mod tests;
#[cfg(test)]
#[path = "duties_transfer_tests.rs"]
pub(crate) mod transfer_tests;
#[cfg(test)]
#[path = "duties_view_tests.rs"]
pub(super) mod view_tests;
