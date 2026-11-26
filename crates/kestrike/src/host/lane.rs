//! After recovery, the lane thread holds the owner process's store [`Client`] and runs the serving tenure's store
//! requests and its attachment listing as [`Job`]s. The owner thread submits jobs and adopts each [`Done`] by
//! polling.
//!
//! Invariants:
//!
//! - STORE-OFF-POLL: on a threaded lane, every store request of a serving tenure runs in `ran` on the lane thread.
//!   [`Lane::submit`] and [`Lane::poll`] wait for no store request: `submit` takes the queue lock, which the lane
//!   thread holds only to pick a job, and `poll` reads the count of completions the thread sent and, when one
//!   landed or the thread ended, the completion channel once. The inline lane of test builds runs each job inside
//!   `submit`, on the submitting thread.
//! - ONE-ISSUER: one thread holds the client and runs one job at a time, to its end. A request of unknown outcome may
//!   still commit after the next request issues (SERIAL-ISSUE of `storage::store::client`).
//! - BOUNDED: at most [`DEPTH`] jobs are outstanding, from their submit to the adoption of their completion, and at
//!   most one of each kind; a submit past either bound, or to a lane whose thread ended, returns its job unrun.
//! - VIEW-FIRST: a queued [`Job::View`] runs before every other queued job; the others run in submission order. A
//!   View submitted while a job runs waits for that job to end.
//! - SET-BY-VALUE: a job that writes the shard record moves the tenure's [`PossiblyNamed`] to the lane thread, and its
//!   completion moves the set back, so one thread holds the set at a time. [`Job::Transfer`] writes the shard record
//!   without the set: the withdrawn owner submits it after the acknowledged certify returned the set. The caller holds
//!   one set per tenure (PossNamedCoversStore of [`checkpoint`]). A [`Done::Panicked`] completion, or a close with the
//!   job outstanding, loses the set, and the caller ends the tenure.
//! - CONTAINED: a job unwind that reaches `ran` completes as [`Done::Panicked`], and the thread keeps the client; a
//!   panic raised while another unwinds aborts the process. When the lane thread ended outside that containment,
//!   `poll` delivers the completions it sent, then one `Done::Panicked` for each outstanding job with none.
//! - JOINED: on a threaded lane, [`Lane::end`] and `Drop` close the queue, drop the jobs the thread has not taken, and
//!   join the thread once the job it runs ends. An inline lane already ran every accepted job, and its close drops
//!   the completions nobody adopted.
//! - MONITORS-HANDED-BACK: after each job `ran` runs, a contained panic included, the lane thread copies the
//!   client's [`Monitors`] into the completion it sends, so [`Lane::monitors`] is the copy taken after the last
//!   adopted job that carried one; a [`Done::Panicked`] that `poll` delivers for an ended thread keeps the earlier
//!   copy. The owner thread reads it with no lock and no syscall beyond the poll's channel receive.

use std::collections::VecDeque;
use std::mem::Discriminant;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, TryRecvError};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::thread::{Scope, ScopedJoinHandle};

use super::gate::HostGate;
use crate::failover::attachments::{ControlPlane, Unlisted};
use crate::failover::evidence::Pair;
use crate::failover::reconcile::StandbyGate;
use crate::failover::records::{Host, ShardRecord, VolumeId, VolumeRecord};
use crate::failover::retire::Target;
use crate::net::ownership::Shard;
use crate::storage::checkpoint::{
    self, CaptureEpoch, CutIntact, PossiblyNamed, StagedCheckpoint, SuffixBounds, SuffixDue,
    WriteRefused,
};
use crate::storage::page_coverage::{PageReply, PageRequest};
use crate::storage::store::{
    Alarm, Client, Key, Outgoing, Read, Store, StoreError, Tally, Transferred, WatermarkLog,
};
use crate::storage::{CpuSet, Platform, Storage, contain};

/// The most jobs outstanding at once.
pub const DEPTH: usize = 4;

/// A store job the lane thread runs. Each variant is one kind; the lane holds at most one job of each kind.
#[derive(Debug)]
pub enum Job {
    /// Reads the volume record `volume`, then the shard record of `shard` (READ-ORDER). `sent_at` is a time the
    /// submitter takes on its own clock before the submit, which [`Done::View`] returns unchanged. A View can wait in
    /// the queue and behind the job running at its submit, so the shard read is sent at or after `sent_at` and before
    /// the completion's adoption: `sent_at` is a lower bound on the send time, and the adoption time an upper bound.
    View {
        volume: VolumeId,
        shard: Shard,
        sent_at: u64,
    },
    /// Confirms the tenure's set over `read` with an own shard-record write ([`checkpoint::confirm`]).
    Confirm {
        possible: PossiblyNamed,
        read: Read<ShardRecord>,
        own: Target,
    },
    /// Opens the tenure's suffix over `read` ([`checkpoint::open_suffix`]), first certifying each `(session, certified
    /// end)` of `ends`, the predecessor suffix ends the warm load established. The lane passes `ends` on unchecked.
    Open {
        possible: PossiblyNamed,
        read: Read<ShardRecord>,
        own: Target,
        ends: Vec<(u64, u64)>,
        bounds: SuffixBounds,
    },
    /// Lists the attachments of `volume` through `plane`; `sent_at` is the owner's turn time at the submit.
    Listing {
        plane: Plane,
        volume: VolumeId,
        sent_at: u64,
    },
    Page {
        request: PageRequest,
    },
    /// Runs one store step of the tenure's open suffix over `read`, which shows `own`, under `bounds`.
    Step {
        possible: PossiblyNamed,
        read: Read<ShardRecord>,
        own: Target,
        bounds: SuffixBounds,
    },
    /// Publishes `staged` over `read`, which shows `own`, under the proof `cut` and the capture epoch `epoch` the owner
    /// thread read directly before the submit. The tenure knows `read`'s checkpoint when its set holds that slot.
    Publish(Box<Publish>),
    /// Certifies the suffix of `session` to `end` over `read`, which shows `own`, or confirms `read` when it records
    /// no suffix of `session`.
    Certify {
        possible: PossiblyNamed,
        read: Read<ShardRecord>,
        own: Target,
        session: u64,
        end: u64,
    },
    /// The withdrawn owner's planned transfer ([`Client::transfer`]) of `read`, the record its certify committed, to
    /// `target` for the tenure `outgoing` names. The job carries the standby gate and its completion returns it.
    ///
    /// ENDED-GRANTS-NOTHING: the job reads the volume record of `read`'s active volume after the shard read whose
    /// version the write conditions on, and issues the write only when that record enrolls a pair for `target`'s live
    /// attach. A target whose entry reads ended, gone or unenrolled refuses `Stale(Target)`, and a failed read returns
    /// its error, each with no write. The volume read and the shard write are two requests: an attach end that commits
    /// between them is the outcome the target's own restart checks read.
    Transfer {
        gate: StandbyGate,
        read: Read<ShardRecord>,
        outgoing: Outgoing,
        target: Host,
    },
    /// The owner's pair drop: an exact-version replace of `read`, the volume record a [`Job::View`] returned, with
    /// [`VolumeRecord::dropped`] of `pairs` for `session`, which keeps the record's fence (EndOrder). The caller
    /// passes the pairs that [`Owner::owner_reclaim`](crate::net::Owner::owner_reclaim) returned for the poll that
    /// judged `read`, less each pair of a host the View's shard record names owner or standby (NAMED-PAIR-KEPT in
    /// `host::duties`). The job returns a client refusal, a lost version condition or an unknown outcome unchanged,
    /// and the owner rereads the record on its next poll.
    Drop {
        read: Read<VolumeRecord>,
        pairs: Vec<Pair>,
        session: u64,
    },
    /// Sends on `started` from the lane thread, then waits until `release` receives or hangs up.
    #[cfg(test)]
    Hold {
        started: mpsc::Sender<()>,
        release: mpsc::Receiver<()>,
    },
    /// Completes at once.
    #[cfg(test)]
    Mark,
}

/// A job's completion, which [`Lane::poll`] adopts once. A shard-record job's completion returns the set it carried.
#[derive(Debug)]
pub enum Done {
    /// The two reads' results and the job's `sent_at`. The lane issues the shard read whatever the volume read
    /// returned; both use one client, so a client withdrawn before the View refuses both with no request.
    View {
        sent_at: u64,
        volume: Result<Read<VolumeRecord>, StoreError>,
        shard: Result<Read<ShardRecord>, StoreError>,
    },
    /// The set and [`checkpoint::confirm`]'s result.
    Confirm {
        possible: PossiblyNamed,
        confirmed: Result<Read<ShardRecord>, WriteRefused>,
    },
    /// The set and [`checkpoint::open_suffix`]'s result: the last committed read, or the supplied read when the call
    /// wrote nothing, and whether this call opened the suffix log. `false` follows a record that names no checkpoint,
    /// an unsettled floor, a busy or poisoned capture mutex, closed storage, invalid bounds, or a log already open or
    /// used. An Open over the returned read and set with no `ends` reuses a committed reservation with no store
    /// request. An error can follow writes that committed.
    Open {
        possible: PossiblyNamed,
        opened: Result<(Read<ShardRecord>, bool), WriteRefused>,
    },
    Listing {
        plane: Plane,
        listed: Result<Vec<String>, Unlisted>,
        sent_at: u64,
    },
    Page {
        reply: PageReply,
    },
    /// The step's set, its last committed read or first refusal, and the signals the log raised before its writes,
    /// `None` when the step's one try of the capture mutex failed and it sampled none.
    Step {
        possible: PossiblyNamed,
        stepped: Result<Read<ShardRecord>, WriteRefused>,
        due: Option<SuffixDue>,
    },
    /// The Publish's set and stage, and the committed read or the refusal.
    Publish {
        possible: PossiblyNamed,
        staged: StagedCheckpoint,
        published: Result<Read<ShardRecord>, WriteRefused>,
    },
    Certify {
        possible: PossiblyNamed,
        end: u64,
        certified: Result<Read<ShardRecord>, WriteRefused>,
    },
    /// The gate the job carried and [`Client::transfer`]'s result, or the enrollment read's refusal with no write:
    /// `Stale(Target)` for a target the volume record leaves unenrolled and the read's error for a failed read.
    Transfer {
        gate: StandbyGate,
        transferred: Result<Transferred, StoreError>,
    },
    /// The replace's result; `None` when [`VolumeRecord::dropped`] admitted no record and the job issued no request.
    Drop {
        dropped: Option<Result<Read<VolumeRecord>, StoreError>>,
    },
    #[cfg(test)]
    Held,
    #[cfg(test)]
    Marked,
    /// A shard-record write the job began has an unknown outcome and may commit, and the job's set is lost, so the
    /// caller ends the tenure on `Panicked`. When the lane thread ended, a `Panicked` job may never have run. A refused
    /// submit returns the unrun job to the caller.
    Panicked,
}

/// Runs `job` over `client` and `storage` on the calling thread: the lane thread, or the submitting thread of an
/// inline test lane.
fn ran<S: Store, L: WatermarkLog, P: Platform>(
    job: Job,
    client: &mut Client<S, L>,
    storage: &Storage<P>,
) -> Done {
    let run = || match job {
        Job::View {
            volume,
            shard,
            sent_at,
        } => {
            let volume = client.read::<VolumeRecord>(Key::Volume(volume));
            let shard = client.read::<ShardRecord>(Key::Shard(shard));
            Done::View {
                sent_at,
                volume,
                shard,
            }
        }
        Job::Confirm {
            mut possible,
            read,
            own,
        } => {
            let confirmed = checkpoint::confirm(client, &mut possible, &read, own);
            Done::Confirm {
                possible,
                confirmed,
            }
        }
        Job::Open {
            mut possible,
            read,
            own,
            ends,
            bounds,
        } => {
            let opened = checkpoint::open_suffix(
                client,
                &mut possible,
                (read, own),
                (storage, &ends),
                bounds,
            );
            Done::Open { possible, opened }
        }
        Job::Listing {
            mut plane,
            volume,
            sent_at,
        } => {
            let listed = plane.0.attachments(&volume);
            Done::Listing {
                plane,
                listed,
                sent_at,
            }
        }
        Job::Page { request } => Done::Page {
            reply: request.run(client),
        },
        Job::Step {
            mut possible,
            read,
            own,
            bounds,
        } => {
            let (stepped, due) =
                checkpoint::suffix_step(client, &mut possible, (read, own), storage, bounds);
            Done::Step {
                possible,
                stepped,
                due,
            }
        }
        Job::Publish(publish) => {
            let Publish {
                mut possible,
                read,
                own,
                cut,
                epoch,
                mut staged,
            } = *publish;
            // The tenure knows the checkpoints its set holds: a read naming a slot outside it is refused `Known`.
            let known = (read.value().checkpoint).filter(|named| possible.contains(named.slot));
            let published = checkpoint::publish(
                client,
                &mut possible,
                &read,
                (own, known),
                (&cut, epoch),
                &mut staged,
            );
            Done::Publish {
                possible,
                staged,
                published,
            }
        }
        Job::Certify {
            mut possible,
            read,
            own,
            session,
            end,
        } => {
            let ancestry = read.value().ancestry;
            let own_suffix = (ancestry.as_slice().iter()).any(|suffix| suffix.session == session);
            // A tenure whose log never opened records no suffix of its own: its own exact-version write over the
            // record settles the set and proves the record still holds the tenure.
            let certified = match own_suffix {
                true => checkpoint::certify(client, &mut possible, (&read, own), (session, end)),
                false => checkpoint::confirm(client, &mut possible, &read, own),
            };
            Done::Certify {
                possible,
                end,
                certified,
            }
        }
        Job::Transfer {
            gate,
            read,
            outgoing,
            target,
        } => {
            #[cfg(test)]
            let skips = crate::host::duties::transfer_tests::planted_enrollment_unread();
            #[cfg(not(test))]
            let skips = false;
            let enrolled = match skips {
                true => Ok(()),
                false => (client.read::<VolumeRecord>(Key::Volume(read.value().active))).and_then(
                    |read| {
                        (read.value().enrolled(target).is_some())
                            .then_some(())
                            .ok_or(StoreError::Stale(crate::failover::retire::Stale::Target))
                    },
                ),
            };
            let transferred =
                enrolled.and_then(|()| client.transfer(&gate, &read, &outgoing, target));
            Done::Transfer { gate, transferred }
        }
        Job::Drop {
            read,
            pairs,
            session,
        } => Done::Drop {
            dropped: (read.value().dropped(&pairs, session))
                .map(|next| client.replace(&read, next)),
        },
        #[cfg(test)]
        Job::Hold { started, release } => {
            let _ = started.send(());
            let _ = release.recv();
            Done::Held
        }
        #[cfg(test)]
        Job::Mark => Done::Marked,
    };
    contain(run).unwrap_or(Done::Panicked)
}

/// A [`Job::Publish`]'s inputs: every value [`checkpoint::publish`] takes, moved to the lane thread.
#[derive(Debug)]
pub struct Publish {
    pub possible: PossiblyNamed,
    pub read: Read<ShardRecord>,
    pub own: Target,
    pub cut: CutIntact,
    pub epoch: CaptureEpoch,
    pub staged: StagedCheckpoint,
}

/// [`Job::Listing`] calls [`ControlPlane::attachments`] for its volume. The call blocks the lane thread, delaying a
/// queued [`Job::View`] and [`Lane::end`], so the class enforces the listing deadline of the tenure's periods,
/// `host::duties::Periods::listing_deadline_us`.
pub struct Plane(pub Box<dyn ControlPlane + Send>);

impl std::fmt::Debug for Plane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Plane")
    }
}

/// The store client's tally since `Client::open` and its alarm, copied on the lane thread after a job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Monitors {
    pub outcomes: Tally,
    pub alarm: Alarm,
}

impl Monitors {
    fn of<S: Store, L: WatermarkLog>(client: &Client<S, L>) -> Self {
        Self {
            outcomes: client.outcomes(),
            alarm: client.alarm(),
        }
    }
}

type Kind = Discriminant<Job>;

/// A completion as the lane hands it back: its job's kind, the completion and the monitors after the job.
type Handed = (Kind, Done, Monitors);

struct Queue {
    jobs: VecDeque<Job>,
    ended: bool,
}

impl Queue {
    /// The queued [`Job::View`], else the oldest job.
    fn take(&mut self) -> Option<Job> {
        let view = (self.jobs.iter()).position(|job| matches!(job, Job::View { .. }));
        self.jobs.remove(view.unwrap_or(0))
    }
}

/// The bit of [`Waiting::landed`] that the lane thread sets when its body ends.
const GONE: u64 = 1 << 63;

struct Waiting {
    queue: Mutex<Queue>,
    ready: Condvar,
    /// The count of completions the lane thread sent, which it raises after each send, with [`GONE`] set once its
    /// body ended. A poll that reads the count it already adopted returns without reading the channel.
    landed: AtomicU64,
}

impl Waiting {
    fn new() -> Self {
        let queue = Queue {
            jobs: VecDeque::with_capacity(DEPTH),
            ended: false,
        };
        Self {
            queue: Mutex::new(queue),
            ready: Condvar::new(),
            landed: AtomicU64::new(0),
        }
    }

    fn queue(&self) -> std::sync::MutexGuard<'_, Queue> {
        self.queue.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The next job the queue picks, waiting while it is empty and open; `None` once the lane ended.
    fn next(&self) -> Option<Job> {
        let mut queue = self.queue();
        while queue.jobs.is_empty() && !queue.ended {
            queue = (self.ready.wait(queue)).unwrap_or_else(PoisonError::into_inner);
        }
        queue.take()
    }

    /// Closes the queue and returns the jobs the thread has not taken, for the caller to drop outside the lock.
    fn close(&self) -> VecDeque<Job> {
        let unrun = {
            let mut queue = self.queue();
            queue.ended = true;
            std::mem::take(&mut queue.jobs)
        };
        self.ready.notify_all();
        unrun
    }

    fn end(&self) {
        drop(self.close());
    }
}

/// Runs when the lane thread's body returns or unwinds. It closes the queue before it publishes [`GONE`], so any
/// submit after a poll observed `GONE` finds the queue closed and returns its job unrun. It publishes `GONE` before
/// it drops the unrun jobs, so a job destructor that unwinds leaves `GONE` set.
struct Closed<'a>(&'a Waiting);

impl Drop for Closed<'_> {
    fn drop(&mut self) {
        let unrun = self.0.close();
        self.0.landed.fetch_or(GONE, Ordering::Release);
        drop(unrun);
    }
}

enum Mode<'scope, S, L, P: Platform> {
    Thread {
        waiting: Arc<Waiting>,
        done: mpsc::Receiver<Handed>,
        /// The count of completions the owner took from `done`.
        adopted: u64,
        handle: Option<ScopedJoinHandle<'scope, Client<S, L>>>,
        storage: &'scope Storage<P>,
    },
    #[cfg(test)]
    Inline(Box<Inline<'scope, S, L, P>>),
}

/// An inline lane runs `ran` at the submit, on the submitting thread. While `holding` is set the completion waits
/// in `held` until the test releases it; otherwise it lands at once.
#[cfg(test)]
pub(crate) struct Inline<'scope, S, L, P: Platform> {
    client: Option<Client<S, L>>,
    storage: &'scope Storage<P>,
    held: VecDeque<Handed>,
    released: VecDeque<Handed>,
    holding: bool,
}

/// One owner process's store lane. [`Lane::end`] returns the client to the caller.
pub struct Lane<'scope, S, L, P: Platform> {
    mode: Mode<'scope, S, L, P>,
    /// The kind of each job submitted and not yet adopted.
    outstanding: Vec<Kind>,
    /// The client's tally at the lane's start.
    started: Tally,
    /// The monitors the last adopted completion carried.
    monitors: Option<Monitors>,
}

impl<'scope, S, L, P> Lane<'scope, S, L, P>
where
    S: Store + Send + 'scope,
    L: WatermarkLog + Send + 'scope,
    P: Platform,
{
    /// Starts the lane thread in `scope` over `client` and `storage`, placed on `cpus`, the recovery helpers' CPU set.
    /// Under `INLINE_RECOVERY`, a test build returns an inline lane that runs each job on the submitting thread.
    ///
    /// # Errors
    ///
    /// If the thread's start or its placement on `cpus` fails, `start` drops `client` and returns the error.
    pub fn start<'env>(
        _gate: &HostGate,
        scope: &'scope Scope<'scope, 'env>,
        mut client: Client<S, L>,
        storage: &'scope Storage<P>,
        cpus: CpuSet,
    ) -> std::io::Result<Self> {
        #[cfg(test)]
        if crate::storage::INLINE_RECOVERY.with(std::cell::Cell::get) {
            return Ok(Self::inline(client, storage));
        }
        let started = client.outcomes();
        let waiting = Arc::new(Waiting::new());
        // At most `DEPTH` completions wait for adoption (BOUNDED), so a send never waits.
        let (sender, done) = mpsc::sync_channel(DEPTH);
        let (placed, placement) = mpsc::sync_channel(1);
        let queue = Arc::clone(&waiting);
        let builder = std::thread::Builder::new().name("store-lane".to_owned());
        #[expect(
            clippy::disallowed_methods,
            reason = "the simulation worker sets INLINE_RECOVERY to run store-lane jobs on its own thread"
        )]
        let handle = builder.spawn_scoped(scope, move || {
            let _closed = Closed(&queue);
            // The sender drops before `_closed` marks the thread gone, so a poll that reads the mark finds the
            // channel disconnected once it is empty.
            let sender = sender;
            let applied = cpus.apply_current();
            let placed_on_cpus = applied.is_ok();
            let _ = placed.send(applied);
            if placed_on_cpus {
                while let Some(job) = queue.next() {
                    let kind = std::mem::discriminant(&job);
                    let done = ran(job, &mut client, storage);
                    if sender.send((kind, done, Monitors::of(&client))).is_err() {
                        break;
                    }
                    queue.landed.fetch_add(1, Ordering::Release);
                }
            }
            client
        })?;
        let applied = (placement.recv())
            .unwrap_or_else(|_| Err(std::io::Error::other("the lane ended before its placement")));
        if let Err(error) = applied {
            let _ = handle.join();
            return Err(error);
        }
        Ok(Self {
            mode: Mode::Thread {
                waiting,
                done,
                adopted: 0,
                handle: Some(handle),
                storage,
            },
            outstanding: Vec::with_capacity(DEPTH),
            started,
            monitors: None,
        })
    }
}

impl<'scope, S: Store, L: WatermarkLog, P: Platform> Lane<'scope, S, L, P> {
    #[cfg(test)]
    pub(crate) fn inline(client: Client<S, L>, storage: &'scope Storage<P>) -> Self {
        Self {
            started: client.outcomes(),
            monitors: None,
            mode: Mode::Inline(Box::new(Inline {
                client: Some(client),
                storage,
                held: VecDeque::new(),
                released: VecDeque::new(),
                holding: false,
            })),
            outstanding: Vec::with_capacity(DEPTH),
        }
    }

    /// Queues `job`.
    ///
    /// # Errors
    ///
    /// `job`, unrun, when [`DEPTH`] jobs are outstanding, a job of its kind is, or the lane thread ended.
    pub fn submit(&mut self, job: Job) -> Result<(), Box<Job>> {
        let kind = std::mem::discriminant(&job);
        if self.outstanding.len() == DEPTH || self.outstanding.contains(&kind) {
            return Err(Box::new(job));
        }
        match &mut self.mode {
            Mode::Thread { waiting, .. } => {
                let mut queue = waiting.queue();
                if queue.ended {
                    return Err(Box::new(job));
                }
                queue.jobs.push_back(job);
                drop(queue);
                waiting.ready.notify_one();
            }
            #[cfg(test)]
            Mode::Inline(inline) => {
                let client = inline
                    .client
                    .as_mut()
                    .expect("a live lane holds its client");
                let done = ran(job, client, inline.storage);
                let done = (kind, done, Monitors::of(client));
                if inline.holding {
                    inline.held.push_back(done);
                } else {
                    inline.released.push_back(done);
                }
            }
        }
        self.outstanding.push(kind);
        Ok(())
    }

    /// Adopts the oldest completion that landed, if one did, and frees its kind's place under BOUNDED. A lane with no
    /// job outstanding returns `None` without reading its channel, as does a threaded lane whose thread runs on and
    /// sent no completion since the last one adopted. Once the lane thread ended, `poll` delivers the completions it
    /// sent, then one [`Done::Panicked`] for each outstanding job with none.
    #[inline(always)]
    pub fn poll(&mut self) -> Option<Done> {
        let oldest = *self.outstanding.first()?;
        if let Mode::Thread {
            waiting, adopted, ..
        } = &self.mode
            && waiting.landed.load(Ordering::Acquire) == *adopted
        {
            return None;
        }
        self.landed(oldest)
    }

    /// The part of [`Lane::poll`] that reads the completions, with `oldest` the oldest outstanding kind.
    #[inline(never)]
    fn landed(&mut self, oldest: Kind) -> Option<Done> {
        let (kind, done, monitors) = match &mut self.mode {
            Mode::Thread { done, adopted, .. } => match done.try_recv() {
                Ok((kind, done, monitors)) => {
                    *adopted += 1;
                    (kind, done, Some(monitors))
                }
                Err(TryRecvError::Empty) => return None,
                Err(TryRecvError::Disconnected) => (oldest, Done::Panicked, None),
            },
            #[cfg(test)]
            Mode::Inline(inline) => {
                let (kind, done, monitors) = inline.released.pop_front()?;
                (kind, done, Some(monitors))
            }
        };
        self.outstanding.retain(|outstanding| *outstanding != kind);
        self.monitors = monitors.or(self.monitors);
        Some(done)
    }

    pub fn outstanding(&self) -> usize {
        self.outstanding.len()
    }

    /// The client's monitors as the lane thread copied them after the job of the last completion [`Lane::poll`]
    /// returned that carried them, `None` before the first.
    pub fn monitors(&self) -> Option<Monitors> {
        self.monitors
    }

    /// The client's tally as of [`Lane::monitors`], or at the lane's start before a completion was adopted.
    pub fn tally(&self) -> Tally {
        self.monitors
            .map_or(self.started, |monitors| monitors.outcomes)
    }

    /// The storage the lane's jobs run over.
    pub(crate) fn storage(&self) -> &'scope Storage<P> {
        match &self.mode {
            Mode::Thread { storage, .. } => storage,
            #[cfg(test)]
            Mode::Inline(inline) => inline.storage,
        }
    }

    /// Closes the queue, drops the jobs the thread has not taken, joins the thread once the job it runs ends, and
    /// returns the client. Every job still outstanding loses its completion and its set, and a shard-record write the
    /// thread took may have committed, so a caller that closes with a job outstanding ends the tenure.
    ///
    /// # Panics
    ///
    /// When the lane thread panicked outside the containment of `ran`.
    pub fn end(mut self) -> Client<S, L> {
        match &mut self.mode {
            Mode::Thread {
                waiting, handle, ..
            } => {
                waiting.end();
                let handle = handle.take().expect("a live lane holds its thread");
                handle
                    .join()
                    .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
            }
            #[cfg(test)]
            Mode::Inline(inline) => inline.client.take().expect("a live lane holds its client"),
        }
    }

    #[cfg(test)]
    pub(crate) fn inline_mut(&mut self) -> &mut Inline<'scope, S, L, P> {
        match &mut self.mode {
            Mode::Inline(inline) => inline,
            Mode::Thread { .. } => panic!("a threaded lane"),
        }
    }

    /// The next completion through [`Lane::poll`]. A threaded lane with a job outstanding retries until 60 s have
    /// passed; an idle lane and an inline lane return the first poll's result.
    #[cfg(test)]
    pub(crate) fn wait(&mut self) -> Option<Done> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        loop {
            let done = self.poll();
            let inline = matches!(self.mode, Mode::Inline(_));
            if done.is_some() || inline || self.outstanding.is_empty() {
                return done;
            }
            if std::time::Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
}

#[cfg(test)]
impl<S, L, P: Platform> Inline<'_, S, L, P> {
    /// Holds every later completion until [`Inline::release`] lands it.
    pub(crate) fn hold(&mut self) {
        self.holding = true;
    }

    /// Lands the oldest held completion and reports whether one was held.
    pub(crate) fn release(&mut self) -> bool {
        let Some(done) = self.held.pop_front() else {
            return false;
        };
        self.released.push_back(done);
        true
    }

    pub(crate) fn held(&self) -> usize {
        self.held.len()
    }

    /// Lands every held completion and lands later ones at once.
    pub(crate) fn release_all(&mut self) {
        self.holding = false;
        while self.release() {}
    }
}

impl<S, L, P: Platform> Drop for Lane<'_, S, L, P> {
    /// Closes the queue, drops the jobs the thread has not taken, and joins the thread, which returns the client to be
    /// dropped here. Every job still outstanding loses its completion and its set, as at [`Lane::end`].
    fn drop(&mut self) {
        match &mut self.mode {
            Mode::Thread {
                waiting, handle, ..
            } => {
                waiting.end();
                if let Some(handle) = handle.take() {
                    let _ = handle.join();
                }
            }
            #[cfg(test)]
            Mode::Inline(_) => {}
        }
    }
}

#[cfg(test)]
#[path = "lane_tests.rs"]
pub(super) mod tests;
