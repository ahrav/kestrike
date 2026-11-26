//! Completion staging for the SPDK driver: one preallocated record per
//! accepted command and a FIFO of terminals, filled only by native callbacks.
//!
//! - A record holds an accepted command's token until its terminal is
//!   delivered or a proven stop supersedes it, so a new submit never
//!   overwrites a pending terminal.
//! - The FIFO holds one entry per accepted command at most, so any burst of
//!   callbacks, including failure and abort fanout past the native polling
//!   limit, fits without loss.
//! - A staged terminal is deliverable only after the driver certifies it: a
//!   terminal staged during a completion poll that returned success on a
//!   healthy controller. A terminal staged during a failing poll, a submit,
//!   admin processing, or teardown may be a software abort with the device
//!   still able to reach the buffer, so it stays held until a proven stop
//!   discards it.
//! - Callbacks write only into this state, never allocate, and never panic.
//! - The state and the callback contexts live in allocations [`Slots`] owns
//!   through raw pointers, so moving the driver never invalidates a pointer
//!   native code holds. They are freed only by [`Slots::free`].

use std::cell::UnsafeCell;
use std::ffi::c_void;
use std::ptr::NonNull;

use spdk_sys as sys;

use super::super::status::{Classification, ControllerEvent, DeviceStatus};
use super::certify::{self, Record};

/// The staging state. Native callbacks reach it through the pointers in the
/// per-record contexts while the driver is inside a native call, so the
/// driver reaches it only between native calls and through [`Slots::staging`].
pub(crate) struct Staging {
    records: Box<[Record]>,
    fifo: Box<[u32]>,
    head: usize,
    len: usize,
    certified: usize,
    free: Vec<u32>,
    /// Completions for records that were not accepted, and completions with no
    /// completion entry, which a correct native layer never produces.
    pub(crate) strays: u64,
    /// Timeout reports and the last `(qpair, command ID)` reported.
    pub(crate) timeouts: u64,
    pub(crate) last_timeout: Option<(usize, u16)>,
    /// `event` retains the first controller event reported by a staged status.
    pub(crate) event: Option<ControllerEvent>,
}

/// One record's callback argument: the staging cell and the record index.
/// A callback names its command by record index alone, so it stages into whichever command holds the record when it runs.
/// The driver trusts the finality of SPDK v25.05.1 that [`Native`](super::native::Native)'s contract states: an accepted command gets exactly one callback and none after it, so its record is reusable once its terminal is delivered.
pub(crate) struct Context {
    staging: *const UnsafeCell<Staging>,
    index: u32,
}

/// The owner of the staging cell and the contexts. Dropping it leaks both,
/// so a pointer native code still holds never dangles; only [`free`](Self::free) releases them.
pub(crate) struct Slots {
    cell: NonNull<UnsafeCell<Staging>>,
    contexts: NonNull<[Context]>,
}

impl Slots {
    /// Staging for `depth` accepted commands, with each record's stable callback context.
    pub(crate) fn new(depth: u32) -> Self {
        let staging = Staging {
            records: vec![Record::Free; depth as usize].into_boxed_slice(),
            fifo: vec![0; depth as usize].into_boxed_slice(),
            head: 0,
            len: 0,
            certified: 0,
            free: (0..depth).rev().collect(),
            strays: 0,
            timeouts: 0,
            last_timeout: None,
            event: None,
        };
        let cell = NonNull::from(Box::leak(Box::new(UnsafeCell::new(staging))));
        let contexts: Box<[Context]> = (0..depth)
            .map(|index| Context {
                staging: cell.as_ptr(),
                index,
            })
            .collect();
        Self {
            cell,
            contexts: NonNull::from(Box::leak(contexts)),
        }
    }

    /// The staging state.
    ///
    /// # Safety
    ///
    /// No native call that can run a callback is in progress, and no other
    /// reference from this method is live.
    pub(crate) unsafe fn staging(&mut self) -> &mut Staging {
        // SAFETY: the caller's contract; the cell lives until `free`.
        unsafe { &mut *self.cell.as_ref().get() }
    }

    /// The completion callback argument for record `index`.
    pub(crate) fn context(&self, index: u32) -> *mut c_void {
        // SAFETY: `index` is below the depth `new` built, and the contexts live until `free`.
        unsafe {
            (&raw const (*self.contexts.as_ptr())[index as usize])
                .cast_mut()
                .cast()
        }
    }

    /// The timeout callback argument.
    pub(crate) fn timeout_arg(&self) -> *mut c_void {
        self.cell.as_ptr().cast()
    }

    /// Frees the state and contexts.
    ///
    /// # Safety
    ///
    /// Native code holds no pointer from [`context`](Self::context) or
    /// [`timeout_arg`](Self::timeout_arg) and will run no callback with one.
    pub(crate) unsafe fn free(self) {
        // SAFETY: both allocations came from `Box::leak` in `new` and nothing else reaches them.
        unsafe {
            drop(Box::from_raw(self.contexts.as_ptr()));
            drop(Box::from_raw(self.cell.as_ptr()));
        }
    }
}

impl Staging {
    pub(crate) fn accepted(&self) -> usize {
        self.records.len() - self.free.len()
    }

    /// Takes a free record for `token`, or `None` when every record is accepted.
    pub(crate) fn accept(&mut self, token: u64) -> Option<u32> {
        let index = self.free.pop()?;
        debug_assert!(
            certify::takes(self.records[index as usize]),
            "a free-list record holds no command"
        );
        self.records[index as usize] = Record::Accepted { token };
        Some(index)
    }

    /// Returns a record whose submission the native layer refused.
    pub(crate) fn refuse(&mut self, index: u32) {
        self.records[index as usize] = Record::Free;
        self.free.push(index);
    }

    /// Stages a terminal for `index`; called from the completion callback.
    fn stage(&mut self, index: u32, status: u16) {
        let Some(record) = self.records.get_mut(index as usize) else {
            self.strays += 1;
            return;
        };
        let Some(staged) = certify::stage(*record, status) else {
            self.strays += 1;
            return;
        };
        *record = staged;
        if DeviceStatus::Nvme(status).classify(0) != Classification::Success {
            self.note_event(status);
        }
        let mut slot = self.head + self.len;
        if slot >= self.fifo.len() {
            slot -= self.fifo.len();
        }
        self.fifo[slot] = index;
        self.len += 1;
    }

    #[cold]
    #[inline(never)]
    fn note_event(&mut self, status: u16) {
        self.event = self
            .event
            .or(ControllerEvent::of_status(DeviceStatus::Nvme(status)));
    }

    /// Terminals staged and not yet delivered.
    pub(crate) fn staged(&self) -> usize {
        self.len
    }

    /// Certified terminals awaiting delivery.
    pub(crate) fn certified(&self) -> usize {
        self.certified
    }

    /// Makes every staged terminal deliverable.
    pub(crate) fn certify(&mut self) {
        self.certified = self.len;
    }

    /// Delivers at most `limit` certified terminals, oldest first, freeing their records.
    #[inline(always)]
    pub(crate) fn deliver(&mut self, limit: usize, mut push: impl FnMut(u64, u16)) -> usize {
        let count = certify::deliverable(limit, self.certified);
        for _ in 0..count {
            let index = self.fifo[self.head];
            self.head = (self.head + 1) % self.fifo.len();
            self.len -= 1;
            self.certified -= 1;
            if let Some((token, status)) = certify::terminal(self.records[index as usize]) {
                push(token, status);
            }
            self.records[index as usize] = Record::Free;
            self.free.push(index);
        }
        count
    }

    /// Forgets every staged terminal and accepted record after a proven stop.
    pub(crate) fn discard(&mut self) {
        self.records.fill(Record::Free);
        self.free.clear();
        self.free.extend((0..self.records.len() as u32).rev());
        (self.head, self.len, self.certified) = (0, 0, 0);
    }
}

/// The NVMe completion callback: copies the complete 16-bit status into the record's staging.
/// SPDK runs each accepted command's callback once, on the driver's thread, inside a native call the driver makes; only a completion poll's terminals can certify, and a poll may run callbacks and still return a negative result, so certification follows the poll's return.
///
/// # Safety
///
/// `arg` is a [`Slots::context`] whose slots are alive, and `cpl` is null or
/// a valid completion; the driver is inside the native call that runs this
/// callback and holds no reference into the staging.
pub(crate) unsafe extern "C" fn complete(arg: *mut c_void, cpl: *const sys::spdk_nvme_cpl) {
    // SAFETY: the caller's contract.
    unsafe {
        let Some(context) = arg.cast::<Context>().as_ref() else {
            return;
        };
        let staging = &mut *(*context.staging).get();
        // A missing completion cannot prove the command's end, so the record stays accepted.
        let Some(cpl) = cpl.as_ref() else {
            staging.strays += 1;
            return;
        };
        staging.stage(context.index, cpl.__bindgen_anon_1.status_raw);
    }
}

/// The controller timeout callback: records the report and nothing else.
///
/// # Safety
///
/// `arg` is a [`Slots::timeout_arg`] whose slots are alive, under the same contract as [`complete`].
pub(crate) unsafe extern "C" fn timed_out(
    arg: *mut c_void,
    _ctrlr: *mut sys::spdk_nvme_ctrlr,
    qpair: *mut sys::spdk_nvme_qpair,
    cid: u16,
) {
    // SAFETY: the caller's contract.
    unsafe {
        let Some(cell) = arg.cast::<UnsafeCell<Staging>>().cast_const().as_ref() else {
            return;
        };
        let staging = &mut *cell.get();
        staging.timeouts = staging.timeouts.wrapping_add(1);
        staging.last_timeout = Some((qpair.addr(), cid));
    }
}
