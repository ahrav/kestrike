//! The recovery helpers: the jobs one warm attempt or a serving tenure's capture runs off the owner thread, and the bounded pool of threads that runs them.
//!
//! A job owns everything it reads: the read buffer and the immutable context and patch a slot decode's jobs share, a conversion piece's chunks, the chunks, places and pairs a free job drops, an encode's slot reservation and cut, or the side list and units a discard drops.
//! A destination job moves its guard into its terminal output. A job holds no storage, volume or gate reference, so its execution is the pure callable [`ran`], which the helper threads and a test pool's inline dispatch both call.
//!
//! Invariants owned by this module:
//!
//! - BOUNDED: the live jobs, the bytes they hold and the decoded bytes they may return stay within the [`RecoveryLimits`] the attach charged to the engine budget; a job's charge is reserved before its dispatch, for a slot window before its read is submitted, and released once: when its terminal reaches the owner, when the owner releases a reservation it will not dispatch, or when a cancel releases every reservation still undispatched. A helper frees the bitmaps and key words a sealed destination job is done with after it sends that job's terminal; the reader's estimate counts those buffers. A named slot's window job holds the read buffer it took under a decode's charge, a destination job holds its guard under an input charge of the decode's `guard_bytes`, which counts the guard's bitmaps, and the replay job holds the suffix blocks, so an owner may give it a destination job's charge. The whole entries a destination job carries and the suffix blocks the replay job carries count in the reader's `SlotDecode::bytes` and replay estimate, which the reader only checks against the engine budget's headroom; the owner holds a charge of that size from the reader's construction until the reader, its jobs and their terminals are freed, a cancelled attempt's included, the pool's threads ended, and the load `finish` returns is installed or dropped. The replay job allocates its report, patch and routed chunks within that replay estimate without a fallible reservation; a slot load needs limits that hold one window's charge and `input_bytes` of at least one guard, and smaller limits admit no slot job; a caller that starts slot loads refuses limits whose `input_bytes` is below the decode's `guard_bytes`. The guard's bitmaps count in both this charge and the reader's `SlotDecode::bytes` estimate. The pool queues every job at its dispatch, and the next idle helper thread takes it. A warm conversion job holds one piece of a destination's chunks of a finished slot load, whose bytes the reader charged, and a warm free job holds a committed or refused piece's consumed chunks and places and a committed load's destination pairs, each under an empty charge; a warm-staged load's chunks stay under the reader's charge until the volume and its helper pool drop. A capture's encode job holds its slot reservation, the walk's copy of the cut, the tenure's kept unit buffers and the encoded units under an empty charge of these bounds; the encode checks the copy's bytes outside the side list's charge, the units and the kept buffers together against the capture's engine budget, and a pool a capture started runs that tenure's encodes, one at a time, and the frees of what its ended passes hold, each under an empty charge.
//! - Dropping a cancelled pool waits while its threads finish the jobs queued before the cancel: a slot job, a suffix replay or a destination seal included, runs to its end, and so do a warm conversion, which walks its piece, and a warm free job that a commit or a refused conversion queued.
//! - ADOPT-ONCE: the owner adopts a terminal only under the tag of the attempt that dispatched it; a terminal of an earlier attempt releases its charge and publishes nothing.
//! - CONTAINED: a panicking job ends as a typed [`Panicked`] terminal, and dropping the pool waits for every thread it started. A slot job runs by value, so a panic drops the destination guard or suffix blocks it moved; an encode's panic drops the reservation and the cut it moved.
//! - PLACED: [`Helpers::start`] applies [`RecoveryLimits::cpus`] to every thread it starts and fails when the kernel refuses the set. The warm bootstrap's scoped workers apply the same set at their start and keep the owner's affinity when the kernel refuses it, which changes speed only.

#[cfg(all(test, loom))]
use loom::{
    sync::{Arc, Mutex, mpsc},
    thread,
};
use std::panic::{AssertUnwindSafe, catch_unwind};
#[cfg(not(all(test, loom)))]
use std::{
    sync::{Arc, Mutex, mpsc},
    thread,
};

use super::super::recovery::checkpoint::{self as slot, Done, Work};

/// Bounds on one recovery helper pool, a warm attempt's or a serving tenure's encode pool, and on the volume's recovery
/// I/O, each validated positive at attach.
///
/// The job and byte bounds also cap the named-slot reader's read depth: a slot read is submitted only once its window's charge fits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryLimits {
    /// Helper threads use an explicit CPU set because they otherwise inherit a pinned owner's single-CPU affinity.
    pub cpus: super::CpuSet,
    /// Threads one attempt starts; at most `jobs`, since each thread runs one live job at a time.
    pub helpers: u32,
    /// Live jobs, reserved, running or awaiting adoption.
    pub jobs: u32,
    /// Bytes the live jobs' charges hold; at least one metadata block, a validity floor that sizes no cold-attach
    /// job. An encode job holds an empty charge: the capture's engine budget checks its bytes.
    pub input_bytes: usize,
    /// Output charge the live jobs hold, 24 bytes per read byte, the helpers' output factor; at least one metadata
    /// block's charge.
    pub output_bytes: usize,
    /// Terminals one tick receives, adopted or stale, counted across every poll of that tick.
    pub adopt: u32,
    /// The host's recovery I/O share, of which this volume's owner drains `bytes / owners` per interval, in ticks of the
    /// `now` its polls read ([`HostShare`](super::super::recovery::HostShare)); that part holds at least the largest
    /// recovery read plus one suffix block.
    pub io: super::super::recovery::HostShare,
}

/// Whether the planted defect that admits a reservation past the pool's bounds is set; false outside tests.
fn over_reserve() -> bool {
    #[cfg(test)]
    return OVER_RESERVE.with(std::cell::Cell::get);
    #[cfg(not(test))]
    false
}

#[cfg(test)]
thread_local! {
    /// A planted defect: a reservation ignores the job and byte bounds.
    pub(super) static OVER_RESERVE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Output bytes a slot-window job's charge reserves for each byte it reads ([`Charge::decode`]). The reader budgets the
/// window's decoded rows separately in `SlotDecode::bytes`, so this factor sizes no decode: it caps how many window
/// reservations `output_bytes` admits at once, and with the metadata block's length it sets the attach's validity floor.
pub(crate) const OUTPUT_PER_BYTE: usize = 24;

/// `Tag` names the attempt a job belongs to: the owner's attempt ordinal, which a cancel advances past every terminal
/// still to come.
pub(super) type Tag = u64;

/// One job: a job of a named slot's decode, a warm conversion, a free of a committed warm load's or a refused
/// conversion's output, a serving tenure's whole-cut encode, or a free of what an ended capture pass holds.
#[derive(Debug)]
pub(super) enum Job {
    /// A job of a named slot's decode: a window, a destination or the suffix replay.
    Slot(Work),
    /// One conversion piece of a warm load, a run of one destination's chunks, into its restored entries' places.
    Restore(Box<super::warm::Convert>),
    /// A committed warm load's, or a refused piece's, consumed chunks and places, with a committed load's destination
    /// pairs, freed off the owner thread.
    Free(Vec<super::warm::Converted>, Vec<super::warm::Pairs>),
    /// A capture pass's whole-cut encode into the slot its reservation holds, under the volume's crc mechanism.
    Encode(Box<super::checkpoint::Encode>, super::super::record::Crc32c),
    /// What a capture pass that ended holds to free: its cut's side list or the unit buffers its tenure kept.
    Discard(Box<super::checkpoint::Leftovers>),
    /// A job that panics, for the containment tests.
    #[cfg(test)]
    Panic,
}

/// A job's output.
#[derive(Debug)]
pub(super) enum Output {
    Slot(Done),
    Restored(super::warm::Converted),
    Freed,
    Encoded(Box<super::checkpoint::Encoded>),
}

/// `Panicked` is [`contain`]'s error for a run that unwound, and the terminal of a job whose execution panicked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Panicked;

/// `Charge` is a job's share of the bounds: the copied bytes it holds and the decoded bytes it may return.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) struct Charge {
    pub(super) input: usize,
    pub(super) output: usize,
}

impl Charge {
    /// The charge of a decode over `bytes` read bytes.
    pub(super) fn decode(bytes: usize) -> Self {
        Self {
            input: bytes,
            output: bytes.saturating_mul(OUTPUT_PER_BYTE),
        }
    }
}

/// A job's terminal as the owner receives it.
pub(super) type Terminal = (Tag, Charge, Result<Output, Panicked>);

#[cfg(test)]
thread_local! {
    /// When `INLINE` is true, pools this thread starts run jobs inline at dispatch, and store lanes this thread starts
    /// through `host::Lane::start` run each job inline at its submit.
    pub(crate) static INLINE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Pools this thread starts run each job inline at dispatch and hold its terminal until a test releases it.
    pub(crate) static PARK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Decodes this thread dispatches panic.
    pub(super) static PANIC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Encodes run on this thread panic.
    pub(crate) static ENCODE_PANIC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Pools this thread starts wait for a running job's terminal at each poll, so a test's tick count does not depend on thread timing.
    pub(super) static WAIT: std::cell::Cell<bool> = const { std::cell::Cell::new(true) };
}

/// Terminals a parked pool ran, and those a test released in the order the owner receives them.
#[cfg(test)]
pub(super) type Parked = (Vec<Terminal>, std::collections::VecDeque<Terminal>);

/// If `run` unwinds, `contain` returns `Err(Panicked)` even if the caught payload's destructor panics. `contain`
/// forgets the second panic's payload to skip its destructor. If a panic escapes a destructor during unwinding, the
/// process aborts.
pub(crate) fn contain<T>(run: impl FnOnce() -> T) -> Result<T, Panicked> {
    catch_unwind(AssertUnwindSafe(run)).map_err(|payload| {
        if let Err(again) = catch_unwind(AssertUnwindSafe(|| drop(payload))) {
            std::mem::forget(again);
        }
        Panicked
    })
}

/// What a helper frees after it sent a job's terminal: the buffers a slot job is done with.
type Spent = Vec<Vec<u64>>;

/// `ran` runs on the caller's thread and reads only data owned by `job`.
fn ran(job: Job) -> (Result<Output, Panicked>, Spent) {
    match job {
        Job::Slot(work) => {
            let mut spent = Vec::new();
            let output = contain(|| {
                let mut done = slot::run(work);
                spent = done.spent();
                Output::Slot(done)
            });
            (output, spent)
        }
        Job::Restore(job) => (
            contain(|| Output::Restored(super::warm::convert(*job))),
            Spent::default(),
        ),
        Job::Free(converted, pairs) => (
            contain(|| {
                drop((converted, pairs));
                Output::Freed
            }),
            Spent::default(),
        ),
        Job::Encode(encode, crc) => (
            contain(|| {
                #[cfg(test)]
                assert!(
                    !ENCODE_PANIC.with(std::cell::Cell::get),
                    "a planted encode panic"
                );
                Output::Encoded(Box::new(encode.run(crc)))
            }),
            Spent::default(),
        ),
        Job::Discard(leftovers) => (
            contain(|| {
                drop(leftovers);
                Output::Freed
            }),
            Spent::default(),
        ),
        #[cfg(test)]
        Job::Panic => (
            contain(|| panic!("a planted helper panic")),
            Spent::default(),
        ),
    }
}

/// `Helpers` is one attempt's pool: `limits.helpers` threads taking jobs from one queue and returning each terminal to the owner.
#[derive(Debug)]
pub(super) struct Helpers {
    limits: RecoveryLimits,
    /// The attempt whose terminals the owner adopts; a cancel advances it past every terminal still to come.
    tag: Tag,
    /// The job queue, `None` once the pool is cancelled; a queued `None` asks one thread to end once the jobs queued before it ran.
    jobs: Option<mpsc::Sender<Option<(Tag, Charge, Job)>>>,
    done: mpsc::Receiver<Terminal>,
    threads: Vec<thread::JoinHandle<()>>,
    /// The charges the live jobs hold.
    held: Charge,
    /// Reservations not yet dispatched, which a cancel releases.
    reserved: (u32, Charge),
    /// Dispatched jobs whose terminal the owner has not received.
    running: u32,
    /// The most live jobs and the largest held charges any reservation reached since the pool started.
    peak: (u32, Charge),
    /// Terminals an inline test pool ran at dispatch, in dispatch order.
    #[cfg(test)]
    landed: std::collections::VecDeque<Terminal>,
    #[cfg(test)]
    inline: bool,
    #[cfg(test)]
    parked: Option<Parked>,
    #[cfg(all(test, not(loom)))]
    wait: bool,
}

impl Helpers {
    /// `start` starts `limits.helpers` threads for the attempt `tag`; a test pool started under `INLINE` runs the same jobs at dispatch without helper threads.
    ///
    /// # Errors
    ///
    /// The first error from starting a thread or placing it on `limits.cpus`.
    pub(super) fn start(limits: RecoveryLimits, tag: Tag) -> std::io::Result<Self> {
        let (jobs, queue) = mpsc::channel::<Option<(Tag, Charge, Job)>>();
        let (sender, done) = mpsc::channel();
        let queue = Arc::new(Mutex::new(queue));
        let mut pool = Self {
            limits,
            tag,
            jobs: Some(jobs),
            done,
            threads: Vec::with_capacity(limits.helpers as usize),
            held: Charge::default(),
            reserved: (0, Charge::default()),
            running: 0,
            peak: (0, Charge::default()),
            #[cfg(test)]
            landed: std::collections::VecDeque::new(),
            #[cfg(test)]
            inline: crate::storage::INLINE_RECOVERY.with(std::cell::Cell::get),
            #[cfg(test)]
            parked: PARK.with(std::cell::Cell::get).then(Parked::default),
            #[cfg(all(test, not(loom)))]
            wait: WAIT.with(std::cell::Cell::get),
        };
        #[cfg(test)]
        if pool.inline {
            return Ok(pool);
        }
        for index in 0..limits.helpers {
            let (queue, sender) = (Arc::clone(&queue), sender.clone());
            let builder = thread::Builder::new().name(format!("recovery-{index}"));
            #[cfg_attr(
                not(all(test, loom)),
                expect(
                    clippy::disallowed_methods,
                    reason = "the simulation worker sets INLINE_RECOVERY to run recovery jobs on its own thread"
                )
            )]
            let handle = builder.spawn(move || {
                loop {
                    // The guard ends with the statement, so one job never blocks the queue.
                    let received = queue.lock().map(|queue| queue.recv());
                    let Ok(Ok(Some((tag, charge, job)))) = received else {
                        return;
                    };
                    let (output, spent) = ran(job);
                    if sender.send((tag, charge, output)).is_err() {
                        return;
                    }
                    drop(spent);
                }
            })?;
            // The helper inherits its creator's affinity mask until CPU placement succeeds.
            #[cfg(not(all(test, loom)))]
            let placed = {
                use std::os::unix::thread::JoinHandleExt;
                // SAFETY: `handle` is this pool's unjoined handle, and the new helper cannot exit yet: its queue stays
                // connected and no job or termination has been sent.
                unsafe { limits.cpus.apply(handle.as_pthread_t()) }
            };
            // A CPU placement error drops the pool with the helper's handle included.
            pool.threads.push(handle);
            #[cfg(not(all(test, loom)))]
            placed?;
        }
        Ok(pool)
    }

    /// Whether a dispatched job's terminal has yet to reach the owner.
    pub(super) fn busy(&self) -> bool {
        self.running > 0
    }

    /// Whether the pool still takes jobs; a cancel ends that for the attempt.
    pub(super) fn accepting(&self) -> bool {
        self.jobs.is_some()
    }

    /// Whether the pool takes jobs and holds none, reserved or running, so every terminal to come is of a job dispatched
    /// from here on.
    pub(super) fn idle(&self) -> bool {
        self.accepting() && self.live() == 0
    }

    /// Live jobs: those reserved and not yet dispatched, and those running.
    fn live(&self) -> u32 {
        self.reserved.0 + self.running
    }

    /// The jobs the job bound still admits.
    pub(super) fn room(&self) -> u32 {
        self.limits.jobs.saturating_sub(self.live())
    }

    /// `reserve` takes `charge` for one more job when the bounds hold it; a refusal leaves every charge as it was.
    pub(super) fn reserve(&mut self, charge: Charge) -> bool {
        let input = self.held.input.saturating_add(charge.input);
        let output = self.held.output.saturating_add(charge.output);
        let bounded = self.live() < self.limits.jobs
            && input <= self.limits.input_bytes
            && output <= self.limits.output_bytes;
        let fits = (bounded || over_reserve()) && self.jobs.is_some();
        if fits {
            self.held = Charge { input, output };
            self.reserved.0 += 1;
            self.reserved.1.input += charge.input;
            self.reserved.1.output += charge.output;
            let (jobs, held) = &mut self.peak;
            *jobs = (*jobs).max(self.reserved.0 + self.running);
            held.input = held.input.max(input);
            held.output = held.output.max(output);
        }
        fits
    }

    /// `dispatch` queues `job` under a charge [`reserve`](Self::reserve) took and reports whether the pool took it; a cancelled pool drops the job, its charge already released by the cancel.
    pub(super) fn dispatch(&mut self, charge: Charge, job: Job) -> bool {
        if self.jobs.is_none() {
            return false;
        }
        self.reserved.0 -= 1;
        self.reserved.1.input -= charge.input;
        self.reserved.1.output -= charge.output;
        #[cfg(test)]
        if self.inline || self.parked.is_some() {
            let terminal = (self.tag, charge, self::ran(job).0);
            if let Some((ran, _)) = self.parked.as_mut() {
                ran.push(terminal);
            } else {
                self.landed.push_back(terminal);
            }
            self.running += 1;
            return true;
        }
        self.running += 1;
        // The threads hold the queue's receiver until the pool is cancelled, so the send lands; a send that finds every
        // thread ended releases the job's charge, since its terminal never comes.
        let sent = (self.jobs.as_ref()).map(|jobs| jobs.send(Some((self.tag, charge, job))));
        if let Some(Err(_)) = sent {
            self.running -= 1;
            self.release(charge);
        }
        true
    }

    /// `unreserve` releases a reservation whose job will not be dispatched.
    pub(super) fn unreserve(&mut self, charge: Charge) {
        if self.jobs.is_none() {
            return;
        }
        self.reserved.0 -= 1;
        self.reserved.1.input -= charge.input;
        self.reserved.1.output -= charge.output;
        self.release(charge);
    }

    /// `cancel` reserves nothing more for the attempt, releases every reservation not yet dispatched, and makes every terminal still to come stale; the threads end once the queue drains.
    pub(super) fn cancel(&mut self) {
        if self.jobs.is_none() {
            return;
        }
        self.end_queue();
        self.tag = self.tag.wrapping_add(1);
        let (_, charge) = std::mem::take(&mut self.reserved);
        self.held.input -= charge.input;
        self.held.output -= charge.output;
    }

    /// Queues one end for each thread behind every queued job and reserves nothing more.
    fn end_queue(&mut self) {
        if let Some(jobs) = self.jobs.take() {
            for _ in 0..self.threads.len() {
                let _ = jobs.send(None);
            }
        }
    }

    /// `poll` returns the next terminal of the current attempt while `adopt`, the terminals this tick's earlier polls received, stays below the adoption bound; it releases every terminal's charge and waits for none.
    pub(super) fn poll(&mut self, adopt: &mut u32) -> Option<Result<Output, Panicked>> {
        while *adopt < self.limits.adopt {
            let (tag, charge, output) = self.next()?;
            *adopt += 1;
            self.running -= 1;
            self.release(charge);
            if tag == self.tag {
                return Some(output);
            }
        }
        None
    }

    /// The next terminal, if one arrived; a test pool started under [`WAIT`] waits for one while a job runs.
    fn next(&mut self) -> Option<Terminal> {
        #[cfg(test)]
        if let Some((_, released)) = self.parked.as_mut() {
            return released.pop_front();
        }
        #[cfg(test)]
        if let Some(terminal) = self.landed.pop_front() {
            return Some(terminal);
        }
        #[cfg(all(test, not(loom)))]
        if self.wait && self.running > 0 {
            return (self.done)
                .recv_timeout(std::time::Duration::from_secs(60))
                .ok();
        }
        self.done.try_recv().ok()
    }

    fn release(&mut self, charge: Charge) {
        self.held.input -= charge.input;
        self.held.output -= charge.output;
    }

    /// A parked pool's terminals.
    #[cfg(test)]
    pub(super) fn parked(&mut self) -> Option<&mut Parked> {
        self.parked.as_mut()
    }

    /// The live jobs and the charges they hold.
    #[cfg(test)]
    pub(super) fn held(&self) -> (u32, Charge) {
        (self.live(), self.held)
    }

    /// The most live jobs and the largest held charges any reservation reached since the pool started.
    pub(super) fn peak(&self) -> (u32, Charge) {
        self.peak
    }

    /// Whether every thread of the pool has ended.
    #[cfg(all(test, not(loom)))]
    pub(super) fn ended(&self) -> bool {
        self.threads.iter().all(thread::JoinHandle::is_finished)
    }

    #[cfg(all(test, not(loom)))]
    pub(super) fn thread_cpus(&self) -> Vec<super::CpuSet> {
        use std::os::unix::thread::JoinHandleExt;
        assert!(
            self.accepting(),
            "a cancelled pool's helpers may have exited"
        );
        (self.threads.iter())
            .map(|thread| {
                // SAFETY: `thread` is this pool's unjoined handle and the pool accepts, as asserted above, so its helpers
                // wait on its connected queue and have not exited; `&self` keeps a cancel out for the whole call.
                unsafe { super::CpuSet::of(thread.as_pthread_t()) }
                    .expect("a live helper reports its mask")
            })
            .collect()
    }
}

impl Drop for Helpers {
    /// Ends the queue and waits for every thread, so no job outlives the pool; the terminals still in flight release their charges with it.
    fn drop(&mut self) {
        self.end_queue();
        for handle in self.threads.drain(..) {
            let _ = handle.join();
        }
    }
}
