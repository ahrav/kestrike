//! Driver tests over per-thread scripted [`Native`] calls: submits queue
//! their callbacks, and a completion poll runs them with a success status.
//! The fixture records submit arguments and callback origins, including the
//! enclosing native call and the submission each callback belongs to.

use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::ffi::c_void;
use std::ptr::NonNull;
use std::time::Duration;

use spdk_sys as sys;

use super::super::disk::{CommandToken, CompletionSink, Disk, DmaRange, QuiesceStatus};
use super::super::geometry::DeviceRange;
use super::super::status::DeviceStatus;
use super::disk::{CanaryError, SpdkDisk, attached};
use super::limits::{Limits, NamespaceFacts};
use super::native::Native;
use super::statistics::StatisticsFailure;
use super::statistics_tests;
use crate::failover::identity::Key;
use crate::native::{Environment, Unregistered, registration_tests};
use crate::storage::device::disk::RefusalReason;
use crate::storage::{
    CommandTable, EngineBudget, PoolKind, QuiesceProgress, Quiesced, ReservationCommand,
    ReservationLimits, Terminal,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Call {
    ConnectOptions,
    Connect,
    Register,
    Report,
    Acquire,
    ControllerData,
    Pci,
    Namespace,
    NamespaceData,
    NamespaceFacts,
    AllocQpair,
    RegisterTimeout,
    Submit,
    Poll,
    Failed,
    Disconnect,
    Admin,
    Registers,
    Free,
    Detach,
    LogPage,
    GetFeature,
}

/// One I/O-queue submit as the driver called it: the operation, the namespace, qpair and host pointer it passed, the sector address and count, the callback and its argument, and the result the script answered. A reservation command logs as a non-write with a zero sector range.
#[derive(Debug, Clone, Copy)]
pub(super) struct Submitted {
    pub(super) write: bool,
    pub(super) ns: usize,
    pub(super) qpair: usize,
    pub(super) payload: usize,
    pub(super) lba: u64,
    pub(super) count: u32,
    callback: sys::spdk_nvme_cmd_cb,
    pub(super) arg: *mut c_void,
    pub(super) rc: i32,
}

/// One callback the fixture ran: the native call it ran inside, by position in the call log and by kind, the submission it belongs to, fixed when the fixture queued or replayed it and read independently of the driver's staging record, and its raw status, or `None` for a null completion. A log-page callback's submission is `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Origin {
    pub(super) call: usize,
    pub(super) inside: Call,
    pub(super) submission: Option<usize>,
    pub(super) status: Option<u16>,
}

/// What a native call answered: a result code, a failure-flag read or a register read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Answer {
    Rc(i32),
    Failed(bool),
    Registers(u32, u32),
}

#[derive(Default)]
pub(super) struct Script {
    calls: Vec<Call>,
    /// The handle address each native call named, by position in the call log; zero for a call that names none.
    pub(super) handles: Vec<usize>,
    pub(super) answers: Vec<(usize, Answer)>,
    /// Every I/O-queue submit, accepted or refused, in call order: reads, writes and reservation commands. A reservation command logs as a non-write with a zero sector range.
    pub(super) submits: Vec<Submitted>,
    /// Every callback the fixture ran, in run order.
    pub(super) origins: Vec<Origin>,
    /// Results for the next I/O-queue submits; an empty queue answers 0.
    pub(super) submit_rc: VecDeque<i32>,
    /// When set, an accepted I/O-queue submit runs its own callback with the next scripted status before it answers, and an accepted Get Features submit does the same with its scripted status.
    pub(super) submit_inline: bool,
    /// When set, a refused I/O-queue submit runs its own callback with the next scripted status before it answers its nonzero result.
    pub(super) refused_inline: bool,
    /// Queued callbacks, oldest first, the next I/O-queue submit runs with success status before it answers.
    pub(super) submit_runs_io: usize,
    /// When set, a refused submit queues its callback as an accepted one does: an invalid-contract control, since a nonzero result ends SPDK's access to the command.
    pub(super) queue_refused: bool,
    /// Callbacks of earlier submissions, each with its status or `None` for a null completion, the next completion poll runs before its own.
    pub(super) replay: VecDeque<(usize, Option<u16>)>,
    /// Accepted submissions awaiting a completion poll, oldest first: the callbacks SPDK still owes.
    pub(super) queued: VecDeque<usize>,
    /// Each reservation command as the driver called it: the call, its two action words, the payload length and the first 16 payload bytes.
    pub(super) reservation_calls: Vec<(Call, u32, u32, u32, [u8; 16])>,
    /// The bytes an accepted reservation Report's callback finds in its payload, zero-padded to the payload length.
    pub(super) report_bytes: Vec<u8>,
    /// Accepted reservation Reports awaiting their callback: the submission, its payload and the bytes the callback finds there.
    reports: Vec<(usize, *mut c_void, Vec<u8>)>,
    /// Results for the next detaches; an empty queue answers 0.
    pub(super) detach: VecDeque<i32>,
    /// The next detach runs the callback before taking its result.
    pub(super) detaching: Option<Box<dyn FnOnce()>>,
    /// Raw NVMe status words for the next completions; an empty queue answers success.
    pub(super) status: VecDeque<u16>,
    /// Accepted log-page commands awaiting an admin poll: callback, argument and payload.
    admin: VecDeque<(sys::spdk_nvme_cmd_cb, *mut c_void, *mut c_void)>,
    /// The page an admin poll copies into each completed log-page command's payload.
    page: Option<Box<[u8; 4096]>>,
    /// Results for the next log-page submits; an empty queue answers 0.
    log_page_rc: VecDeque<i32>,
    /// Raw NVMe status words for the next log-page completions; an empty queue answers success.
    admin_status: VecDeque<u16>,
    /// Results for the next admin polls in place of the completed count.
    pub(super) admin_rc: VecDeque<i32>,
    /// Queued I/O callbacks, oldest first, each admin poll runs with success status; the count persists across polls until a test resets it.
    pub(super) admin_runs_io: usize,
    /// Queued I/O callbacks, oldest first, the next log-page submit runs with success status before it answers.
    pub(super) log_page_runs_io: usize,
    /// Results for the next completion polls in place of the completed count, each with whether the poll runs its callbacks first; an empty queue runs them and answers the count.
    pub(super) poll: VecDeque<(i32, bool)>,
    /// When set, completion polls that run callbacks model abort fanout beyond the native polling limit: the callback of every queued command the device has finished runs, each past the limit with an abort status.
    pub(super) fanout: bool,
    /// Commands the device has finished by each of the next completion polls that run callbacks, oldest first; an empty queue finishes every queued command.
    pub(super) finished: VecDeque<usize>,
    /// Answers for the next failure-flag reads; an empty queue answers false.
    pub(super) failed: VecDeque<bool>,
    /// Results for the next disconnects; an empty queue answers 0.
    pub(super) disconnect: VecDeque<i32>,
    /// CC and CSTS words for the next register reads; an empty queue reads a disabled controller.
    pub(super) registers: VecDeque<(u32, u32)>,
    /// The controller Identify data attach reads; `None` answers a null pointer.
    pub(super) controller: Option<Box<sys::spdk_nvme_ctrlr_data>>,
    /// The namespace Identify data attach reads; `None` answers a null pointer.
    pub(super) namespace_data: Option<Box<sys::spdk_nvme_ns_data>>,
    /// The PCI vendor and device IDs attach reads.
    pub(super) pci: Option<(u16, u16)>,
    /// The namespace accessors' answers attach reads.
    pub(super) facts: Option<NamespaceFacts>,
    /// Whether the qpair allocation fails.
    pub(super) no_qpair: bool,
    /// Whether the namespace lookup answers a null pointer.
    pub(super) no_namespace: bool,
    /// The host identifier each Get Features completion writes into its payload.
    pub(super) feature_host_id: [u8; 16],
    /// The raw status word of each Get Features completion.
    pub(super) feature_status: u16,
    /// The Get Features submit result.
    pub(super) feature_rc: i32,
    /// Whether admin polls hold accepted Get Features commands; a successful detach completes them with an abort
    /// status.
    pub(super) feature_held: bool,
    /// Accepted Get Features commands awaiting an admin poll: callback, argument and payload.
    pub(super) features: VecDeque<(sys::spdk_nvme_cmd_cb, *mut c_void, *mut c_void)>,
    /// When set, the script models a medium whose sectors are the size of the namespace facts the attach read, the
    /// size the attached driver counts its transfers in: a write the script will accept copies its `count` sectors of
    /// payload into `media`, and a read it will accept fills each sector of its range from `media`, or with zeros for
    /// a sector `media` lacks, both before the submit runs any callback.
    pub(super) medium: bool,
    /// The modeled medium's written sectors, by LBA, each one sector long; a sector it lacks reads as zeros.
    pub(super) media: BTreeMap<u64, Vec<u8>>,
    /// The sector size of the namespace facts the last attach read.
    attached_sector: Option<usize>,
    /// The extended host identifier and transport address of the last connect.
    pub(super) connected: Option<([u8; 16], String)>,
}

thread_local! {
    pub(super) static SCRIPT: RefCell<Script> = RefCell::default();
}

/// Logs `call` with the address of the controller, namespace or qpair handle it named.
fn record(call: Call, handle: usize) {
    SCRIPT.with_borrow_mut(|script| {
        script.calls.push(call);
        script.handles.push(handle);
    });
}

/// Logs `answer` for the call recorded last and returns it.
fn answered<T>(value: T, answer: Answer) -> T {
    SCRIPT.with_borrow_mut(|script| {
        let call = script.calls.len() - 1;
        script.answers.push((call, answer));
    });
    value
}

pub(super) fn calls() -> Vec<Call> {
    SCRIPT.with_borrow(|script| script.calls.clone())
}

/// Runs `submission`'s callback inside the native call recorded last, logging its origin first. A reservation Report's first callback finds its scripted bytes in its payload.
fn run_io(submission: usize, status: Option<u16>) {
    let (callback, arg, report) = SCRIPT.with_borrow_mut(|script| {
        let call = script.calls.len() - 1;
        script.origins.push(Origin {
            call,
            inside: script.calls[call],
            submission: Some(submission),
            status,
        });
        let submitted = script.submits[submission];
        let report = script
            .reports
            .iter()
            .position(|&(reported, ..)| reported == submission)
            .map(|at| script.reports.swap_remove(at));
        (submitted.callback, submitted.arg, report)
    });
    if let Some((_, payload, bytes)) = report {
        // SAFETY: the driver keeps an accepted Report's destination, which holds `bytes.len()` bytes, exclusive until this first callback.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), payload.cast(), bytes.len()) };
    }
    let mut cpl = sys::spdk_nvme_cpl::default();
    cpl.__bindgen_anon_1.status_raw = status.unwrap_or(0);
    let cpl = status.map_or(std::ptr::null(), |_| &raw const cpl);
    if let Some(callback) = callback {
        // SAFETY: `arg` is the driver's context for a command it submitted, and its slots stay alive while the driver lives.
        unsafe { callback(arg, cpl) };
    }
}

/// Runs an admin command's callback inside the native call recorded last, logging its origin first.
fn run_admin(callback: sys::spdk_nvme_cmd_cb, arg: *mut c_void, status: u16) {
    SCRIPT.with_borrow_mut(|script| {
        let call = script.calls.len() - 1;
        script.origins.push(Origin {
            call,
            inside: script.calls[call],
            submission: None,
            status: Some(status),
        });
    });
    let mut cpl = sys::spdk_nvme_cpl::default();
    cpl.__bindgen_anon_1.status_raw = status;
    if let Some(callback) = callback {
        // SAFETY: `arg` is the driver's context for an admin command it holds outstanding.
        unsafe { callback(arg, &cpl) };
    }
}

/// The modeled medium's sector size when the script models one and will accept the next I/O-queue submit: the size
/// the attach read from the namespace facts, which the driver counts its transfers in.
///
/// # Panics
///
/// When the script models a medium for a driver whose attach read no namespace facts.
fn modeled(script: &Script) -> Option<usize> {
    if !script.medium || script.submit_rc.front().is_some_and(|&rc| rc != 0) {
        return None;
    }
    Some(
        script
            .attached_sector
            .expect("a modeled medium takes its sector size from the attach's namespace facts"),
    )
}

/// Logs an I/O-queue submit, runs the reentrant callbacks the script asks for, and answers the scripted result. An accepted submission joins the queue, or under `submit_inline` runs its own callback first. A refused submission runs its own callback first under `refused_inline`. `report` holds the bytes an accepted reservation Report's callback finds in `payload`.
fn submit(
    write: bool,
    (ns, qpair, payload): (
        *mut sys::spdk_nvme_ns,
        *mut sys::spdk_nvme_qpair,
        *mut c_void,
    ),
    (lba, count): (u64, u32),
    (callback, arg): (sys::spdk_nvme_cmd_cb, *mut c_void),
    report: Option<Vec<u8>>,
) -> i32 {
    record(Call::Submit, qpair.addr());
    let (index, rc, reentry) = SCRIPT.with_borrow_mut(|script| {
        let rc = script.submit_rc.pop_front().unwrap_or(0);
        script.submits.push(Submitted {
            write,
            ns: ns.addr(),
            qpair: qpair.addr(),
            payload: payload.addr(),
            lba,
            count,
            callback,
            arg,
            rc,
        });
        let index = script.submits.len() - 1;
        if let Some(bytes) = report.filter(|_| rc == 0) {
            script.reports.push((index, payload, bytes));
        }
        let reentry = std::mem::take(&mut script.submit_runs_io).min(script.queued.len());
        let reentry: Vec<usize> = script.queued.drain(..reentry).collect();
        (index, rc, reentry)
    });
    for submission in reentry {
        run_io(submission, Some(0));
    }
    let inline = SCRIPT.with_borrow_mut(|script| {
        let own = if rc == 0 {
            script.submit_inline
        } else {
            script.refused_inline
        };
        if own {
            return Some(script.status.pop_front().unwrap_or(0));
        }
        if rc == 0 || script.queue_refused {
            script.queued.push_back(index);
        }
        None
    });
    if let Some(raw) = inline {
        run_io(index, Some(raw));
    }
    answered(rc, Answer::Rc(rc))
}

/// The raw NVMe status word with generic status type, aborted by request, and do-not-retry set.
pub(super) const ABORTED_BY_REQUEST: u16 = 0x8000 | (0x0007 << 1);

pub(crate) struct Scripted;

// SAFETY: accepted submits queue their callback; completion polls, admin
// polls, submits, qpair frees and detaches run queued or replayed callbacks
// with the scripted status on the calling thread. A replayed callback, or a
// refused submit's callback queued under `queue_refused`, breaches SPDK's
// one-final-callback finality on purpose; it stays memory-safe because each
// context and the staging it points into live until the driver detaches and
// drops. Under `refused_inline` a refused submit runs its own callback inside
// the submit, before its nonzero result ends the native layer's access to
// the callback argument; the context the driver passed is live through that
// call. Read and write payloads are recorded as opaque addresses unless
// `Script::medium` models a medium: then a write the script accepts reads
// its `count` sectors of payload, and a read it accepts fills each sector of
// its range from the medium or with zeros, both inside the submit and sized by
// the sector size of the namespace facts the attach read, the size the driver
// counts transfers in. A
// reservation Register or Acquire payload is read for 16 bytes inside its
// submit, and a Report payload is written once, inside the command's first
// callback. Admin log-page payloads remain allocated for a 4,096-byte page,
// and Get Features payloads for 16 bytes, until their callback or proven
// stop, and the fixture writes only those bytes. Register reads
// answer the scripted words or a disabled controller, the Identify reads
// return null or a pointer into the script's boxed fixture, which stays in
// place until a test replaces it outside a native call, and no method
// dereferences a controller, namespace or qpair.
unsafe impl Native for Scripted {
    unsafe fn connect_options(opts: &mut sys::spdk_nvme_ctrlr_opts, exhid: [u8; 16]) {
        record(Call::ConnectOptions, 0);
        opts.extended_host_id = exhid;
    }

    /// Records the options' extended host identifier and the transport address, and connects whenever the script
    /// holds controller Identify data, to a controller handle no method dereferences.
    unsafe fn connect(
        trid: &sys::spdk_nvme_transport_id,
        opts: &sys::spdk_nvme_ctrlr_opts,
    ) -> *mut sys::spdk_nvme_ctrlr {
        record(Call::Connect, 0);
        let address: String = trid
            .traddr
            .iter()
            .take_while(|&&byte| byte != 0)
            .map(|&byte| char::from(byte.to_ne_bytes()[0]))
            .collect();
        SCRIPT.with_borrow_mut(|script| script.connected = Some((opts.extended_host_id, address)));
        if SCRIPT.with_borrow(|script| script.controller.is_some()) {
            NonNull::dangling().as_ptr()
        } else {
            std::ptr::null_mut()
        }
    }

    unsafe fn reservation_register(
        ns: *mut sys::spdk_nvme_ns,
        qpair: *mut sys::spdk_nvme_qpair,
        payload: *mut sys::spdk_nvme_reservation_register_data,
        action: u32,
        cptpl: u32,
        callback: sys::spdk_nvme_cmd_cb,
        arg: *mut c_void,
    ) -> i32 {
        record(Call::Register, qpair.addr());
        // SAFETY: the driver supplied 16 readable payload bytes for this call.
        let bytes = unsafe { payload.cast::<[u8; 16]>().read() };
        SCRIPT.with_borrow_mut(|s| {
            s.reservation_calls
                .push((Call::Register, action, cptpl, 16, bytes))
        });
        submit(
            false,
            (ns, qpair, payload.cast()),
            (0, 0),
            (callback, arg),
            None,
        )
    }

    unsafe fn reservation_report(
        ns: *mut sys::spdk_nvme_ns,
        qpair: *mut sys::spdk_nvme_qpair,
        payload: *mut c_void,
        len: u32,
        callback: sys::spdk_nvme_cmd_cb,
        arg: *mut c_void,
    ) -> i32 {
        record(Call::Report, qpair.addr());
        let bytes = SCRIPT.with_borrow_mut(|s| {
            s.reservation_calls.push((Call::Report, 0, 0, len, [0; 16]));
            assert!(s.report_bytes.len() <= len as usize);
            let mut bytes = s.report_bytes.clone();
            bytes.resize(len as usize, 0);
            bytes
        });
        submit(
            false,
            (ns, qpair, payload),
            (0, 0),
            (callback, arg),
            Some(bytes),
        )
    }

    unsafe fn reservation_acquire(
        ns: *mut sys::spdk_nvme_ns,
        qpair: *mut sys::spdk_nvme_qpair,
        payload: *mut sys::spdk_nvme_reservation_acquire_data,
        action: u32,
        rtype: u32,
        callback: sys::spdk_nvme_cmd_cb,
        arg: *mut c_void,
    ) -> i32 {
        record(Call::Acquire, qpair.addr());
        // SAFETY: the driver supplied 16 readable payload bytes for this call.
        let bytes = unsafe { payload.cast::<[u8; 16]>().read() };
        SCRIPT.with_borrow_mut(|s| {
            s.reservation_calls
                .push((Call::Acquire, action, rtype, 16, bytes))
        });
        submit(
            false,
            (ns, qpair, payload.cast()),
            (0, 0),
            (callback, arg),
            None,
        )
    }

    unsafe fn controller_data(
        ctrlr: *mut sys::spdk_nvme_ctrlr,
    ) -> *const sys::spdk_nvme_ctrlr_data {
        record(Call::ControllerData, ctrlr.addr());
        SCRIPT.with_borrow(|script| {
            script
                .controller
                .as_deref()
                .map_or(std::ptr::null(), std::ptr::from_ref)
        })
    }

    unsafe fn pci_ids(ctrlr: *mut sys::spdk_nvme_ctrlr) -> Option<(u16, u16)> {
        record(Call::Pci, ctrlr.addr());
        SCRIPT.with_borrow(|script| script.pci)
    }

    unsafe fn namespace(ctrlr: *mut sys::spdk_nvme_ctrlr, _: u32) -> *mut sys::spdk_nvme_ns {
        record(Call::Namespace, ctrlr.addr());
        if SCRIPT.with_borrow(|script| script.no_namespace) {
            std::ptr::null_mut()
        } else {
            NonNull::dangling().as_ptr()
        }
    }

    unsafe fn namespace_data(ns: *mut sys::spdk_nvme_ns) -> *const sys::spdk_nvme_ns_data {
        record(Call::NamespaceData, ns.addr());
        SCRIPT.with_borrow(|script| {
            script
                .namespace_data
                .as_deref()
                .map_or(std::ptr::null(), std::ptr::from_ref)
        })
    }

    unsafe fn namespace_facts(
        ctrlr: *mut sys::spdk_nvme_ctrlr,
        _: *mut sys::spdk_nvme_ns,
        opts: &mut sys::spdk_nvme_io_qpair_opts,
    ) -> NamespaceFacts {
        record(Call::NamespaceFacts, ctrlr.addr());
        let facts = SCRIPT.with_borrow_mut(|script| {
            let facts = script.facts.expect("scripted namespace facts");
            script.attached_sector = Some(usize::try_from(facts.sector_size).unwrap());
            facts
        });
        opts.io_queue_size = facts.max_queue_size;
        facts
    }

    unsafe fn alloc_io_qpair(
        ctrlr: *mut sys::spdk_nvme_ctrlr,
        _: &sys::spdk_nvme_io_qpair_opts,
    ) -> *mut sys::spdk_nvme_qpair {
        record(Call::AllocQpair, ctrlr.addr());
        if SCRIPT.with_borrow(|script| script.no_qpair) {
            std::ptr::null_mut()
        } else {
            NonNull::dangling().as_ptr()
        }
    }

    unsafe fn register_timeout(
        ctrlr: *mut sys::spdk_nvme_ctrlr,
        _: u64,
        _: u64,
        _: sys::spdk_nvme_timeout_cb,
        _: *mut c_void,
    ) {
        record(Call::RegisterTimeout, ctrlr.addr());
    }

    unsafe fn read(
        ns: *mut sys::spdk_nvme_ns,
        qpair: *mut sys::spdk_nvme_qpair,
        payload: *mut c_void,
        lba: u64,
        count: u32,
        callback: sys::spdk_nvme_cmd_cb,
        arg: *mut c_void,
    ) -> i32 {
        SCRIPT.with_borrow(|script| {
            if let Some(sector) = modeled(script) {
                let zeros = vec![0; sector];
                for at in 0..u64::from(count) {
                    let bytes = script.media.get(&(lba + at)).unwrap_or(&zeros);
                    assert_eq!(bytes.len(), sector, "a modeled sector holds one sector");
                    let offset = usize::try_from(at).unwrap() * sector;
                    // SAFETY: the driver supplied `count` sectors of writable payload for this read, and
                    // `offset + sector` lies within them; `bytes` holds `sector` bytes.
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            bytes.as_ptr(),
                            payload.cast::<u8>().add(offset),
                            sector,
                        )
                    };
                }
            }
        });
        submit(
            false,
            (ns, qpair, payload),
            (lba, count),
            (callback, arg),
            None,
        )
    }

    unsafe fn write(
        ns: *mut sys::spdk_nvme_ns,
        qpair: *mut sys::spdk_nvme_qpair,
        payload: *mut c_void,
        lba: u64,
        count: u32,
        callback: sys::spdk_nvme_cmd_cb,
        arg: *mut c_void,
    ) -> i32 {
        SCRIPT.with_borrow_mut(|script| {
            if let Some(sector) = modeled(script) {
                for at in 0..u64::from(count) {
                    let offset = usize::try_from(at).unwrap() * sector;
                    let mut bytes = vec![0; sector];
                    // SAFETY: the driver supplied `count` sectors of readable payload for this write, and
                    // `offset + sector` lies within them.
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            payload.cast::<u8>().add(offset),
                            bytes.as_mut_ptr(),
                            sector,
                        )
                    };
                    script.media.insert(lba + at, bytes);
                }
            }
        });
        submit(
            true,
            (ns, qpair, payload),
            (lba, count),
            (callback, arg),
            None,
        )
    }

    unsafe fn process_completions(qpair: *mut sys::spdk_nvme_qpair, limit: u32) -> i32 {
        record(Call::Poll, qpair.addr());
        let replay: Vec<_> = SCRIPT.with_borrow_mut(|script| script.replay.drain(..).collect());
        for (submission, status) in replay {
            run_io(submission, status);
        }
        let (scripted, ready): (Option<i32>, Vec<usize>) = SCRIPT.with_borrow_mut(|script| {
            let (rc, runs) = script
                .poll
                .pop_front()
                .map_or((None, true), |(rc, runs)| (Some(rc), runs));
            let count = if runs {
                let finished = script.finished.pop_front().unwrap_or(usize::MAX);
                let reaped = if script.fanout {
                    usize::MAX
                } else {
                    limit as usize
                };
                script.queued.len().min(reaped).min(finished)
            } else {
                0
            };
            (rc, script.queued.drain(..count).collect())
        });
        let reaped = ready.len().min(limit as usize);
        for (position, &submission) in ready.iter().enumerate() {
            let raw = if position < reaped {
                SCRIPT.with_borrow_mut(|script| script.status.pop_front().unwrap_or(0))
            } else {
                ABORTED_BY_REQUEST
            };
            run_io(submission, Some(raw));
        }
        let rc = scripted.unwrap_or(reaped as i32);
        answered(rc, Answer::Rc(rc))
    }

    unsafe fn is_failed(ctrlr: *mut sys::spdk_nvme_ctrlr) -> bool {
        record(Call::Failed, ctrlr.addr());
        let failed = SCRIPT.with_borrow_mut(|script| script.failed.pop_front().unwrap_or(false));
        answered(failed, Answer::Failed(failed))
    }

    unsafe fn disconnect(ctrlr: *mut sys::spdk_nvme_ctrlr) -> i32 {
        record(Call::Disconnect, ctrlr.addr());
        let rc = SCRIPT.with_borrow_mut(|script| script.disconnect.pop_front().unwrap_or(0));
        answered(rc, Answer::Rc(rc))
    }

    unsafe fn process_admin_completions(ctrlr: *mut sys::spdk_nvme_ctrlr) -> i32 {
        record(Call::Admin, ctrlr.addr());
        let (io, rc): (Vec<usize>, _) = SCRIPT.with_borrow_mut(|script| {
            let count = script.admin_runs_io.min(script.queued.len());
            (
                script.queued.drain(..count).collect(),
                script.admin_rc.pop_front(),
            )
        });
        for submission in io {
            run_io(submission, Some(0));
        }
        let features: Vec<_> = SCRIPT.with_borrow_mut(|script| {
            if script.feature_held {
                Vec::new()
            } else {
                script.features.drain(..).collect()
            }
        });
        for (callback, arg, payload) in features {
            let (host_id, raw) =
                SCRIPT.with_borrow(|script| (script.feature_host_id, script.feature_status));
            // SAFETY: the driver keeps the Get Features request, whose payload holds 16 bytes, allocated until this
            // callback.
            unsafe { payload.cast::<[u8; 16]>().write(host_id) };
            run_admin(callback, arg, raw);
        }
        let ready: Vec<_> = SCRIPT.with_borrow_mut(|script| script.admin.drain(..).collect());
        for &(callback, arg, payload) in &ready {
            let (page, raw) = SCRIPT.with_borrow_mut(|script| {
                (
                    script.page.as_deref().copied(),
                    script.admin_status.pop_front().unwrap_or(0),
                )
            });
            if let Some(page) = page {
                // SAFETY: the driver submitted `payload` with room for one 4,096-byte page.
                unsafe { payload.cast::<[u8; 4096]>().write(page) };
            }
            run_admin(callback, arg, raw);
        }
        let rc = rc.unwrap_or(ready.len() as i32);
        answered(rc, Answer::Rc(rc))
    }

    unsafe fn registers(ctrlr: *mut sys::spdk_nvme_ctrlr) -> (u32, u32) {
        record(Call::Registers, ctrlr.addr());
        let (cc, csts) =
            SCRIPT.with_borrow_mut(|script| script.registers.pop_front().unwrap_or((0, 0)));
        answered((cc, csts), Answer::Registers(cc, csts))
    }

    /// Completes every queued command with an abort status, however many there are.
    unsafe fn free_io_qpair(qpair: *mut sys::spdk_nvme_qpair) -> i32 {
        record(Call::Free, qpair.addr());
        let aborted: Vec<usize> =
            SCRIPT.with_borrow_mut(|script| script.queued.drain(..).collect());
        for submission in aborted {
            run_io(submission, Some(ABORTED_BY_REQUEST));
        }
        answered(0, Answer::Rc(0))
    }

    /// A detach that succeeds completes every command still queued, on the I/O queue or the admin queue, with an abort status.
    unsafe fn detach(ctrlr: *mut sys::spdk_nvme_ctrlr) -> i32 {
        record(Call::Detach, ctrlr.addr());
        if let Some(detaching) = SCRIPT.with_borrow_mut(|script| script.detaching.take()) {
            detaching();
        }
        let rc = SCRIPT.with_borrow_mut(|script| script.detach.pop_front().unwrap_or(0));
        if rc == 0 {
            let (io, admin): (Vec<usize>, Vec<_>) = SCRIPT.with_borrow_mut(|script| {
                (
                    script.queued.drain(..).collect(),
                    script
                        .features
                        .drain(..)
                        .chain(script.admin.drain(..))
                        .collect(),
                )
            });
            for submission in io {
                run_io(submission, Some(ABORTED_BY_REQUEST));
            }
            for (callback, arg, _) in admin {
                run_admin(callback, arg, ABORTED_BY_REQUEST);
            }
        }
        answered(rc, Answer::Rc(rc))
    }

    unsafe fn get_feature(
        ctrlr: *mut sys::spdk_nvme_ctrlr,
        feature: u8,
        cdw11: u32,
        payload: *mut c_void,
        len: u32,
        callback: sys::spdk_nvme_cmd_cb,
        arg: *mut c_void,
    ) -> i32 {
        assert_eq!(
            (feature, cdw11, len),
            (0x81, 1, 16),
            "Get Features Host Identifier, EXHID"
        );
        record(Call::GetFeature, ctrlr.addr());
        let (rc, inline, host_id, raw) = SCRIPT.with_borrow_mut(|script| {
            let rc = script.feature_rc;
            if rc == 0 && !script.submit_inline {
                script.features.push_back((callback, arg, payload));
            }
            (
                rc,
                script.submit_inline,
                script.feature_host_id,
                script.feature_status,
            )
        });
        if rc == 0 && inline {
            // SAFETY: the driver keeps the Get Features request, whose payload holds 16 bytes, allocated through the submit.
            unsafe { payload.cast::<[u8; 16]>().write(host_id) };
            run_admin(callback, arg, raw);
        }
        answered(rc, Answer::Rc(rc))
    }

    unsafe fn get_log_page(
        ctrlr: *mut sys::spdk_nvme_ctrlr,
        _: u8,
        _: u32,
        payload: *mut c_void,
        _: u32,
        callback: sys::spdk_nvme_cmd_cb,
        arg: *mut c_void,
    ) -> i32 {
        record(Call::LogPage, ctrlr.addr());
        let io: Vec<usize> = SCRIPT.with_borrow_mut(|script| {
            let count = std::mem::take(&mut script.log_page_runs_io).min(script.queued.len());
            script.queued.drain(..count).collect()
        });
        for submission in io {
            run_io(submission, Some(0));
        }
        let rc = SCRIPT.with_borrow_mut(|script| {
            let rc = script.log_page_rc.pop_front().unwrap_or(0);
            if rc == 0 {
                script.admin.push_back((callback, arg, payload));
            }
            rc
        });
        answered(rc, Answer::Rc(rc))
    }
}

pub(super) fn limits(depth: u32) -> Limits {
    facts().limits(depth).unwrap()
}

/// A 1 GiB namespace of 512-byte sectors with a 128 KiB transfer limit.
pub(super) fn facts() -> NamespaceFacts {
    NamespaceFacts {
        active: true,
        sector_size: 512,
        sectors: 1 << 21,
        metadata_size: 0,
        protection_type: 0,
        max_transfer: 128 << 10,
        boundary: 0,
        max_queue_size: 256,
    }
}

/// SPDK services a namespace-change event inside an admin poll with
/// Identify commands it spins on until they complete, so a pick that polled
/// the admin queue could hold the owner thread for as long as the device
/// takes to answer.
#[test]
fn picks_poll_only_the_io_qpair() {
    let mut disk = SpdkDisk::<Scripted>::scripted("scripted:picks", limits(8));
    disk.statistics().request();
    let mut page = [0u8; 4096];
    let memory = DmaRange::new(NonNull::from(&mut page).cast(), 0, 4096);
    disk.mark_verified(memory);
    let device = DeviceRange::new(0, 4096).unwrap();
    let mut out = Vec::with_capacity(1);
    for round in 0..4 {
        std::thread::sleep(Duration::from_millis(2));
        for pick in 0..64 {
            let token = CommandToken::from_raw(round * 64 + pick);
            // SAFETY: the scripted native layer never touches `memory`.
            unsafe { disk.submit_read(token, device, memory) }.unwrap();
            out.clear();
            disk.pick_completions(&mut CompletionSink::new(&mut out, 1));
            assert_eq!(out.len(), 1);
            assert_eq!(out[0].token, token);
        }
    }
    let calls = calls();
    assert!(
        calls
            .iter()
            .all(|call| matches!(call, Call::Submit | Call::Poll | Call::Failed)),
        "{calls:?}"
    );
}

#[test]
fn a_statistics_request_submits_one_log_page_command_and_publishes_its_reading() {
    let mut disk = SpdkDisk::<Scripted>::scripted("scripted:statistics", limits(2));
    let expected = statistics_tests::page(3, &[(0, 512, 9)]);
    SCRIPT.with_borrow_mut(|script| script.page = Some(Box::new(expected)));
    let handle = disk.statistics();
    handle.request();
    disk.service();
    assert_eq!(
        calls(),
        [Call::LogPage, Call::Failed],
        "the submit reads the failure flag as a call outside a poll"
    );
    assert_eq!(handle.latest(), None);
    disk.service();
    let reading = handle.latest().expect("published");
    assert_eq!(reading.sequence, 1);
    assert_eq!(
        reading.outcome,
        Ok(super::statistics::parse(&expected).unwrap())
    );
    disk.service();
    let calls = calls();
    assert_eq!(calls.iter().filter(|&&call| call == Call::Admin).count(), 1);
    assert_eq!(
        calls.iter().filter(|&&call| call == Call::LogPage).count(),
        1
    );
}

#[test]
fn a_request_during_an_outstanding_command_gets_the_next_command() {
    let mut disk = SpdkDisk::<Scripted>::scripted("scripted:statistics-again", limits(2));
    let handle = disk.statistics();
    handle.request();
    disk.service();
    handle.request();
    disk.service();
    assert_eq!(handle.latest().map(|reading| reading.sequence), Some(1));
    disk.service();
    disk.service();
    assert_eq!(handle.latest().map(|reading| reading.sequence), Some(2));
    disk.service();
    let log_pages = calls()
        .iter()
        .filter(|&&call| call == Call::LogPage)
        .count();
    assert_eq!(log_pages, 2);
}

#[test]
fn a_request_from_another_thread_is_served_by_the_owner_thread() {
    let mut disk = SpdkDisk::<Scripted>::scripted("scripted:statistics-thread", limits(2));
    let handle = disk.statistics();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    std::thread::scope(|scope| {
        scope.spawn(|| handle.request());
        while handle.latest().is_none() {
            assert!(std::time::Instant::now() < deadline, "request not served");
            disk.service();
        }
    });
    let reading = handle.latest().unwrap();
    assert_eq!(reading.sequence, 1);
}

/// A log-page submit SPDK refuses, and a command that completes with an
/// error status, each publish their failure and leave the driver serving.
#[test]
fn a_refused_or_failed_log_page_command_publishes_its_failure() {
    let mut disk = SpdkDisk::<Scripted>::scripted("scripted:statistics-fail", limits(2));
    let handle = disk.statistics();
    SCRIPT.with_borrow_mut(|script| script.log_page_rc.push_back(-libc::ENOMEM));
    handle.request();
    disk.service();
    assert_eq!(
        handle.latest().map(|reading| reading.outcome),
        Some(Err(StatisticsFailure::Refused(-libc::ENOMEM)))
    );
    let invalid_field = 0x0002u16 << 1;
    SCRIPT.with_borrow_mut(|script| script.admin_status.push_back(invalid_field));
    handle.request();
    disk.service();
    disk.service();
    let reading = handle.latest().unwrap();
    assert_eq!(
        (reading.sequence, reading.outcome),
        (2, Err(StatisticsFailure::Status(invalid_field)))
    );
    let mut page = [0u8; 4096];
    let memory = DmaRange::new(NonNull::from(&mut page).cast(), 0, 4096);
    disk.mark_verified(memory);
    let device = DeviceRange::new(0, 4096).unwrap();
    // SAFETY: the scripted native layer never touches `memory`.
    unsafe { disk.submit_read(CommandToken::from_raw(0), device, memory) }.unwrap();
}

#[test]
fn a_terminal_staged_during_the_statistics_admin_poll_turns_the_driver_gone() {
    let mut disk = SpdkDisk::<Scripted>::scripted("scripted:statistics-stray", limits(2));
    let mut page = [0u8; 4096];
    let memory = DmaRange::new(NonNull::from(&mut page).cast(), 0, 4096);
    disk.mark_verified(memory);
    let device = DeviceRange::new(0, 4096).unwrap();
    // SAFETY: the scripted native layer never touches `memory`.
    unsafe { disk.submit_read(CommandToken::from_raw(0), device, memory) }.unwrap();
    disk.statistics().request();
    disk.service();
    SCRIPT.with_borrow_mut(|script| script.admin_runs_io = usize::MAX);
    disk.service();
    assert_eq!(
        disk.statistics().latest().map(|reading| reading.outcome),
        Some(Err(StatisticsFailure::DeviceGone(None)))
    );
    let mut out = Vec::with_capacity(1);
    disk.pick_completions(&mut CompletionSink::new(&mut out, 1));
    assert!(out.is_empty(), "{out:?}");
    // SAFETY: the scripted native layer never touches `memory`.
    let refusal =
        unsafe { disk.submit_read(CommandToken::from_raw(1), device, memory) }.unwrap_err();
    assert_eq!(
        (refusal.reason, refusal.code),
        (RefusalReason::DeviceGone, None)
    );
}

/// An I/O terminal staged inside the log-page submit, or a controller that fails during it, turns the driver gone: the statistics request answers `DeviceGone`, a later pick runs no poll that could certify the staged terminal although a read still awaits one, later submits refuse, and both reads stay accepted until the disable proof. An accepted log-page command stays allocated until its callback runs during the disable; a refused one is freed. The cases cross a stray I/O terminal and a failed controller with an accepted and a refused log-page submit.
#[test]
fn a_terminal_staged_during_the_statistics_submit_turns_the_driver_gone() {
    for (stray, failed, log_page_rc) in [
        (true, false, 0),
        (true, false, -libc::ENOMEM),
        (false, true, 0),
        (false, true, -libc::ENOMEM),
    ] {
        SCRIPT.with_borrow_mut(|script| *script = Script::default());
        let address = format!("scripted:statistics-submit-{stray}-{failed}-{log_page_rc}");
        let mut disk = SpdkDisk::<Scripted>::scripted(&address, limits(2));
        let mut page = [0u8; 4096];
        let memory = DmaRange::new(NonNull::from(&mut page).cast(), 0, 4096);
        disk.mark_verified(memory);
        let device = DeviceRange::new(0, 4096).unwrap();
        for token in 0..2 {
            // SAFETY: the scripted native layer never touches `memory`.
            unsafe { disk.submit_read(CommandToken::from_raw(token), device, memory) }.unwrap();
        }
        SCRIPT.with_borrow_mut(|script| {
            script.log_page_runs_io = usize::from(stray);
            script.failed.push_back(failed);
            script.log_page_rc.push_back(log_page_rc);
        });
        let handle = disk.statistics();
        handle.request();
        disk.service();
        let case = (stray, failed, log_page_rc);
        assert_eq!(
            handle.latest().map(|reading| reading.outcome),
            Some(Err(StatisticsFailure::DeviceGone(None))),
            "{case:?}"
        );
        let witness = disk.witness();
        assert_eq!(
            (witness.accepted, witness.staged),
            (2, usize::from(stray)),
            "{case:?}"
        );
        let polls = calls().iter().filter(|&&call| call == Call::Poll).count();
        let mut out = Vec::with_capacity(2);
        disk.pick_completions(&mut CompletionSink::new(&mut out, 2));
        assert!(out.is_empty(), "{case:?}: {out:?}");
        assert_eq!(
            calls().iter().filter(|&&call| call == Call::Poll).count(),
            polls,
            "{case:?}: a gone driver polls nothing"
        );
        // SAFETY: the scripted native layer never touches `memory`.
        let refusal =
            unsafe { disk.submit_read(CommandToken::from_raw(2), device, memory) }.unwrap_err();
        assert_eq!(
            (refusal.reason, refusal.code),
            (RefusalReason::DeviceGone, None),
            "{case:?}"
        );
        handle.request();
        disk.service();
        assert_eq!(
            handle
                .latest()
                .map(|reading| (reading.sequence, reading.outcome)),
            Some((2, Err(StatisticsFailure::DeviceGone(None)))),
            "{case:?}: a gone driver submits no further log-page command"
        );
        assert_eq!(
            calls()
                .iter()
                .filter(|&&call| call == Call::LogPage)
                .count(),
            1,
            "{case:?}"
        );
        assert_eq!(
            SCRIPT.with_borrow(|script| script.admin.len()),
            usize::from(log_page_rc == 0),
            "{case:?}: SPDK holds only an accepted log-page command"
        );
        assert_eq!(disk.quiesce(), QuiesceStatus::Pending, "{case:?}");
        assert_eq!(disk.quiesce(), QuiesceStatus::Stopped, "{case:?}");
        assert!(
            SCRIPT.with_borrow(|script| script.admin.is_empty()),
            "{case:?}: the disable ran the abandoned command's callback into its live request"
        );
        assert!(disk.detach(&Unregistered::scripted()), "{case:?}");
    }
}

#[test]
fn a_failed_statistics_admin_poll_turns_the_driver_gone_with_its_code() {
    let mut disk = SpdkDisk::<Scripted>::scripted("scripted:statistics-admin", limits(2));
    let handle = disk.statistics();
    handle.request();
    disk.service();
    SCRIPT.with_borrow_mut(|script| script.admin_rc.push_back(-libc::ENXIO));
    disk.service();
    assert_eq!(
        handle.latest().map(|reading| reading.outcome),
        Some(Err(StatisticsFailure::DeviceGone(Some(libc::ENXIO))))
    );
    let mut page = [0u8; 4096];
    let memory = DmaRange::new(NonNull::from(&mut page).cast(), 0, 4096);
    disk.mark_verified(memory);
    let device = DeviceRange::new(0, 4096).unwrap();
    // SAFETY: the scripted native layer never touches `memory`.
    let refusal =
        unsafe { disk.submit_read(CommandToken::from_raw(0), device, memory) }.unwrap_err();
    assert_eq!(
        (refusal.reason, refusal.code),
        (RefusalReason::DeviceGone, Some(libc::ENXIO))
    );
}

/// A stopping driver's answer lets a control thread polling `latest` observe the next sequence.
#[test]
fn a_stopping_driver_answers_the_requests_it_cannot_serve() {
    let mut disk = SpdkDisk::<Scripted>::scripted("scripted:statistics-stop", limits(2));
    let handle = disk.statistics();
    handle.request();
    disk.service();
    assert_eq!(disk.quiesce(), QuiesceStatus::Pending);
    disk.service();
    let first = handle
        .latest()
        .expect("the outstanding command is answered");
    assert_eq!(first.outcome, Err(StatisticsFailure::DeviceGone(None)));
    disk.service();
    assert_eq!(handle.latest(), Some(first));
    handle.request();
    disk.service();
    let second = handle.latest().expect("a later request is answered");
    assert_eq!(
        (second.sequence, second.outcome),
        (first.sequence + 1, Err(StatisticsFailure::DeviceGone(None)))
    );
    assert_eq!(disk.quiesce(), QuiesceStatus::Stopped);
    assert!(disk.detach(&Unregistered::scripted()));
}

#[test]
fn a_stopped_table_leaves_no_statistics_request_unanswered() {
    let arena = registration_tests::new_arena();
    let mut disk = SpdkDisk::<Scripted>::scripted("scripted:statistics-table", limits(2));
    let buffer = arena.acquire(PoolKind::ReceiveWrite).unwrap();
    disk.mark_verified(buffer.range(4096).unwrap());
    let handle = disk.statistics();
    let mut table = CommandTable::new(disk, &arena, 1, &mut EngineBudget::new(usize::MAX)).unwrap();
    let token = table
        .submit_read(buffer, DeviceRange::new(0, 4096).unwrap())
        .unwrap();
    handle.request();
    table.service_disk();
    handle.request();
    let mut none = Vec::new();
    assert_eq!(
        table.quiesce(&mut none),
        QuiesceProgress::Draining { outstanding: 1 }
    );
    assert_eq!(
        table.quiesce(&mut none),
        QuiesceProgress::Delivering { remaining: 1 }
    );
    let stopped = calls().len();
    table.service_disk();
    let first = handle
        .latest()
        .expect("the stop answers the outstanding command");
    assert_eq!(
        (first.sequence, first.outcome),
        (1, Err(StatisticsFailure::DeviceGone(None)))
    );
    handle.request();
    table.service_disk();
    let second = handle
        .latest()
        .expect("a request after the stop is answered");
    assert_eq!(
        (second.sequence, second.outcome),
        (2, Err(StatisticsFailure::DeviceGone(None)))
    );
    let mut out = Vec::with_capacity(1);
    assert_eq!(
        table.quiesce(&mut out),
        QuiesceProgress::Quiesced(Quiesced::DeviceStopped)
    );
    assert!(matches!(out.pop(), Some(Terminal::Quiesced { token: t, .. }) if t == token));
    assert_eq!(
        calls().len(),
        stopped,
        "the native call log ends at the stop"
    );
    drop((none, out, table));
    assert!(arena.release().is_ok());
}

/// `spdk_nvme_detach` returns `-ENOMEM` and leaves the controller attached
/// when it cannot allocate its teardown context. The controller still holds
/// the staging's timeout argument, so the driver stays stopped with its
/// address reserved, and a later detach can succeed.
#[test]
fn a_refused_detach_keeps_the_driver_stopped_and_its_address_reserved() {
    let address = "scripted:detach";
    let mut disk = SpdkDisk::<Scripted>::scripted(address, limits(2));
    assert_eq!(disk.quiesce(), QuiesceStatus::Pending);
    assert_eq!(disk.quiesce(), QuiesceStatus::Stopped);
    SCRIPT.with_borrow_mut(|script| script.detach.push_back(-libc::ENOMEM));
    assert!(!disk.detach(&Unregistered::scripted()));
    assert!(attached().contains(address));
    assert!(disk.detach(&Unregistered::scripted()));
    assert!(!attached().contains(address));
    let detaches = calls().iter().filter(|&&call| call == Call::Detach).count();
    assert_eq!(detaches, 2);
}

/// A canary that completes with a failing NVMe status proves nothing about the
/// device's range isolation, so the driver serves nothing after it.
#[test]
fn a_failed_canary_status_turns_the_driver_gone() {
    let (env, arena) = (Environment::detached(), registration_tests::new_arena());
    let mut registration = registration_tests::ready(&env, &arena);
    let mut disk =
        SpdkDisk::<Scripted>::scripted_leased("scripted:canary", limits(2), &mut registration);
    let buffer = arena.acquire(PoolKind::ReceiveWrite).unwrap();
    let internal_error = 0x0006u16 << 1;
    SCRIPT.with_borrow_mut(|script| script.status.push_back(internal_error));
    let failed = disk
        .canary(&registration, buffer, Duration::from_secs(1))
        .unwrap_err();
    assert_eq!(
        failed,
        CanaryError::Status(DeviceStatus::Nvme(internal_error))
    );
    let mut page = [0u8; 4096];
    let memory = DmaRange::new(NonNull::from(&mut page).cast(), 0, 4096);
    let device = DeviceRange::new(0, 4096).unwrap();
    // SAFETY: the scripted native layer never touches `memory`.
    let refusal =
        unsafe { disk.submit_read(CommandToken::from_raw(0), device, memory) }.unwrap_err();
    assert_eq!(refusal.reason, RefusalReason::DeviceGone);
}

/// Attach leases the device before the registration maps and verifies, so
/// a driver without an attach authority serves commands only once its
/// registered arena is verified, here by a canary that certified the
/// device's range isolation, and then only over memory inside that arena.
#[test]
fn commands_are_refused_until_the_canary_passes() {
    let (env, arena) = (Environment::detached(), registration_tests::new_arena());
    let mut registration = registration_tests::ready(&env, &arena);
    let mut disk =
        SpdkDisk::<Scripted>::scripted_leased("scripted:unverified", limits(2), &mut registration);
    let mut page = [0u8; 4096];
    let memory = DmaRange::new(NonNull::from(&mut page).cast(), 0, 4096);
    let device = DeviceRange::new(0, 4096).unwrap();
    // SAFETY: the scripted native layer never touches `memory`.
    let refusal =
        unsafe { disk.submit_read(CommandToken::from_raw(0), device, memory) }.unwrap_err();
    assert_eq!(refusal.reason, RefusalReason::NotVerified);
    let buffer = arena.acquire(PoolKind::ReceiveWrite).unwrap();
    let buffer = disk
        .canary(&registration, buffer, Duration::from_secs(1))
        .unwrap();
    // SAFETY: as above.
    let refusal =
        unsafe { disk.submit_read(CommandToken::from_raw(1), device, memory) }.unwrap_err();
    assert_eq!(refusal.reason, RefusalReason::InvalidRange);
    let inside = buffer.range(4096).unwrap();
    // SAFETY: as above.
    unsafe { disk.submit_read(CommandToken::from_raw(2), device, inside) }.unwrap();
}

/// The unregistration proof names its registration, so a stopped driver
/// detaches only after the registration that leased its device was undone.
#[test]
fn detach_requires_the_proof_of_the_leasing_registration() {
    let (env, arena_a, arena_b) = (
        Environment::detached(),
        registration_tests::new_arena(),
        registration_tests::new_arena(),
    );
    let mut a = registration_tests::ready(&env, &arena_a);
    let b = registration_tests::ready(&env, &arena_b);
    let mut disk = SpdkDisk::<Scripted>::scripted_leased("scripted:proof", limits(2), &mut a);
    assert_eq!(disk.quiesce(), QuiesceStatus::Pending);
    assert_eq!(disk.quiesce(), QuiesceStatus::Stopped);
    a.device_stopped(disk.stop_proof().unwrap()).unwrap();
    let other = registration_tests::undone(b);
    assert!(
        !disk.detach(&other),
        "another registration's proof does not detach"
    );
    assert!(attached().contains("scripted:proof"));
    assert!(disk.detach(&registration_tests::undone(a)));
    assert!(!attached().contains("scripted:proof"));
}

/// The canary binds the device to one arena, so it accepts only the
/// registration that leased the device.
#[test]
fn the_canary_refuses_a_registration_that_did_not_lease_the_device() {
    let (env, arena_a, arena_b) = (
        Environment::detached(),
        registration_tests::new_arena(),
        registration_tests::new_arena(),
    );
    let mut a = registration_tests::ready(&env, &arena_a);
    let b = registration_tests::ready(&env, &arena_b);
    let mut disk = SpdkDisk::<Scripted>::scripted_leased("scripted:other", limits(2), &mut a);
    let buffer = arena_b.acquire(PoolKind::ReceiveWrite).unwrap();
    let failed = disk.canary(&b, buffer, Duration::from_secs(1)).unwrap_err();
    assert_eq!(failed, CanaryError::NotReady);
    let buffer = arena_a.acquire(PoolKind::ReceiveWrite).unwrap();
    disk.canary(&a, buffer, Duration::from_secs(1)).unwrap();
}

/// The canary's own submission is selected inside the driver, so a caller's
/// token value never reaches the canary path.
#[test]
fn the_canary_token_value_grants_no_bypass() {
    let mut disk = SpdkDisk::<Scripted>::scripted("scripted:token", limits(2));
    let mut page = [0u8; 4096];
    let memory = DmaRange::new(NonNull::from(&mut page).cast(), 0, 4096);
    let device = DeviceRange::new(0, 4096).unwrap();
    // SAFETY: the scripted native layer never touches `memory`.
    let refusal =
        unsafe { disk.submit_read(CommandToken::from_raw(u64::MAX), device, memory) }.unwrap_err();
    assert_eq!(refusal.reason, RefusalReason::NotVerified);
}

#[test]
fn a_submit_admits_only_whole_sector_lengths_inside_the_limits() {
    SCRIPT.take();
    let limits = NamespaceFacts {
        sector_size: 4096,
        sectors: 1 << 18,
        ..facts()
    }
    .limits(2)
    .unwrap();
    assert_eq!((limits.sector_size, limits.sector_shift), (4096, 12));
    let mut disk = SpdkDisk::<Scripted>::scripted("scripted:sectors", limits);
    let mut page = [0u8; 3 * 4096];
    let backing = NonNull::from(&mut page).cast::<u8>();
    let memory = |len: u32| DmaRange::new(backing, 0, len);
    disk.mark_verified(memory(4096));
    let refused = [
        (DeviceRange::new(0, 512).unwrap(), memory(512)),
        (DeviceRange::new(0, 1536).unwrap(), memory(1536)),
        (DeviceRange::new(0, 4096 + 512).unwrap(), memory(4096 + 512)),
        (
            DeviceRange::new(0, limits.transfer + 4096).unwrap(),
            memory(limits.transfer + 4096),
        ),
        (
            DeviceRange::new(limits.capacity - 4096, 8192).unwrap(),
            memory(8192),
        ),
        (DeviceRange::new(0, 4096).unwrap(), memory(8192)),
    ];
    for (n, (device, memory)) in refused.into_iter().enumerate() {
        // SAFETY: the scripted native layer never touches `memory`.
        let refusal = unsafe { disk.submit_read(CommandToken::from_raw(n as u64), device, memory) }
            .unwrap_err();
        assert_eq!(
            (refusal.reason, refusal.code),
            (RefusalReason::InvalidRange, None),
            "{device:?}"
        );
    }
    assert!(calls().is_empty(), "a refused range makes no native call");
    let mut out = Vec::with_capacity(1);
    for (n, len) in [4096, 8192, 3 * 4096].into_iter().enumerate() {
        let token = CommandToken::from_raw(100 + n as u64);
        let device = DeviceRange::new(limits.capacity - u64::from(len), len).unwrap();
        // SAFETY: as above.
        unsafe { disk.submit_read(token, device, memory(len)) }.unwrap();
        out.clear();
        disk.pick_completions(&mut CompletionSink::new(&mut out, 1));
        assert_eq!(out.len(), 1, "{len} bytes reach the device");
        assert_eq!(out[0].token, token);
    }
    let mut fine =
        SpdkDisk::<Scripted>::scripted("scripted:sectors-512", super::disk_tests::limits(2));
    fine.mark_verified(memory(4096));
    for (n, len) in [512, 1536].into_iter().enumerate() {
        let token = CommandToken::from_raw(200 + n as u64);
        let device = DeviceRange::new(0, len).unwrap();
        // SAFETY: as above.
        unsafe { fine.submit_read(token, device, memory(len)) }.unwrap();
        out.clear();
        fine.pick_completions(&mut CompletionSink::new(&mut out, 1));
        assert_eq!(out.len(), 1, "{len} bytes reach a 512-byte-sector device");
        assert_eq!(out[0].token, token);
    }
}

#[test]
fn a_gone_driver_refuses_device_gone_before_the_range_checks() {
    SCRIPT.take();
    let limits = limits(2);
    let mut disk = SpdkDisk::<Scripted>::scripted("scripted:gone-first", limits);
    let mut page = [0u8; 4096];
    let memory = DmaRange::new(NonNull::from(&mut page).cast(), 0, 4096);
    disk.mark_verified(memory);
    let device = DeviceRange::new(0, 4096).unwrap();
    SCRIPT.with_borrow_mut(|script| script.submit_rc.push_back(-libc::ENXIO));
    // SAFETY: the scripted native layer never touches `memory`.
    let refusal =
        unsafe { disk.submit_read(CommandToken::from_raw(0), device, memory) }.unwrap_err();
    assert_eq!(
        (refusal.reason, refusal.code),
        (RefusalReason::DeviceGone, Some(libc::ENXIO))
    );
    let over = DeviceRange::new(0, limits.transfer + 4096).unwrap();
    // SAFETY: as above.
    let refusal = unsafe {
        disk.submit_read(
            CommandToken::from_raw(1),
            over,
            DmaRange::new(NonNull::from(&mut page).cast(), 0, limits.transfer + 4096),
        )
    }
    .unwrap_err();
    assert_eq!(
        (refusal.reason, refusal.code),
        (RefusalReason::DeviceGone, Some(libc::ENXIO))
    );
    assert_eq!(
        calls().iter().filter(|&&call| call == Call::Submit).count(),
        1,
        "the gone driver makes no further native call"
    );
}

/// The scripted driver's zeroed Identify pages decode a block size exponent
/// of zero, so the persistence profile's derivation refuses them as
/// malformed before any atomics check.
#[test]
fn the_scripted_driver_s_zeroed_identify_refuses_the_profile_as_malformed() {
    let disk = SpdkDisk::<Scripted>::scripted("scripted:profile", limits(2));
    let raw = disk.attach_facts().unwrap().identify.raw();
    assert!(
        raw.controller()
            .iter()
            .chain(raw.namespace())
            .all(|&byte| byte == 0),
        "the scripted pages are zeroed"
    );
    assert_eq!(
        super::super::PersistenceProfile::derive(disk.attach_facts().unwrap()),
        Err(super::super::DeriveRefusal::Ineligible(
            super::super::ProfileRefusal::Malformed(super::super::IdentifyMalformed::SectorSize(0))
        ))
    );
}

/// Submits one read through `disk`, picks its completion, and returns the refusal of the next submit, if any.
fn read_then_submit(disk: &mut SpdkDisk<'_, Scripted>) -> Option<RefusalReason> {
    submit_one(disk, 0).unwrap();
    let mut out = Vec::with_capacity(1);
    disk.pick_completions(&mut CompletionSink::new(&mut out, 1));
    submit_one(disk, 1).err().map(|refusal| refusal.reason)
}

fn submit_one(
    disk: &mut SpdkDisk<'_, Scripted>,
    token: u64,
) -> Result<(), crate::storage::device::SubmitRefusal> {
    let mut page = [0u8; 4096];
    let memory = DmaRange::new(NonNull::from(&mut page).cast(), 0, 4096);
    disk.mark_verified(memory);
    let device = DeviceRange::new(0, 4096).unwrap();
    // SAFETY: the scripted native layer never touches `memory`.
    unsafe { disk.submit_read(CommandToken::from_raw(token), device, memory) }
}

/// Returns the CC.EN mask first and the CSTS.RDY mask second.
pub(super) fn ready_masks() -> (u32, u32) {
    // SAFETY: the mask accessors take no argument and read no memory.
    unsafe {
        (
            sys::spdk_sys_nvme_cc_en_mask(),
            sys::spdk_sys_nvme_csts_rdy_mask(),
        )
    }
}

/// A completion with an abort or queue-deletion status, and a failed completion poll, each record their
/// mid-tenure controller event and turn the driver gone, so the incarnation submits nothing after it; a success
/// records none and the next submit is accepted.
#[test]
fn a_mid_tenure_controller_event_ends_submission() {
    use crate::storage::ControllerEvent;
    let generic = |code: u16| code << 1;
    for (name, status, failed, event) in [
        ("success", Some(0), false, None),
        (
            "abort requested",
            Some(generic(0x07)),
            false,
            Some(ControllerEvent::Abort),
        ),
        (
            "sq deletion",
            Some(generic(0x08)),
            false,
            Some(ControllerEvent::QueueDelete),
        ),
        (
            "failed controller",
            None,
            true,
            Some(ControllerEvent::Reset),
        ),
    ] {
        SCRIPT.take();
        let mut disk = SpdkDisk::<Scripted>::scripted(&format!("scripted:event-{name}"), limits(2));
        SCRIPT.with_borrow_mut(|script| {
            script.status.extend(status);
            if failed {
                script.poll.push_back((-6, false));
            }
        });
        let refused = read_then_submit(&mut disk);
        assert_eq!(disk.controller_event(), event, "{name}");
        assert_eq!(
            refused,
            event.map(|_| RefusalReason::DeviceGone),
            "{name}: submission after the event"
        );
    }
}

/// The ready observation reads CC.EN and CSTS.RDY set; a disabled controller, or one whose register read failed and reads all ones, is not ready.
#[test]
fn ready_requires_an_enabled_ready_controller() {
    let (en, rdy) = ready_masks();
    for (registers, ready) in [
        ((en, rdy), true),
        ((en, 0), false),
        ((0, rdy), false),
        ((u32::MAX, rdy), false),
        ((en, u32::MAX), false),
        ((u32::MAX, u32::MAX), false),
    ] {
        SCRIPT.take();
        let disk =
            SpdkDisk::<Scripted>::scripted(&format!("scripted:ready-{registers:?}"), limits(2));
        SCRIPT.with_borrow_mut(|script| script.registers.push_back(registers));
        assert_eq!(disk.ready(), ready, "{registers:?}");
    }
}

#[test]
fn every_controller_event_site_records_the_first_event_and_ends_submission() {
    use crate::storage::ControllerEvent;
    type Drive = fn(&mut SpdkDisk<'_, Scripted>);
    let rows: [(&str, Drive, ControllerEvent, Option<i32>); 11] = [
        (
            "log-page submit refused as gone",
            |disk| {
                SCRIPT.with_borrow_mut(|script| script.log_page_rc.push_back(-libc::ENXIO));
                disk.statistics().request();
                disk.service();
            },
            ControllerEvent::Reset,
            Some(libc::ENXIO),
        ),
        (
            "abort staged by a failing poll",
            |disk| {
                SCRIPT.with_borrow_mut(|script| {
                    script.status.push_back(0x07 << 1);
                    script.poll.push_back((-libc::ENXIO, true));
                });
                submit_one(disk, 0).unwrap();
                let mut out = Vec::with_capacity(1);
                disk.pick_completions(&mut CompletionSink::new(&mut out, 1));
            },
            ControllerEvent::Abort,
            Some(libc::ENXIO),
        ),
        (
            "sq deletion then abort within one poll",
            |disk| {
                SCRIPT.with_borrow_mut(|script| script.status.extend([0x08 << 1, 0x07 << 1]));
                submit_one(disk, 0).unwrap();
                submit_one(disk, 1).unwrap();
                let mut out = Vec::with_capacity(2);
                disk.pick_completions(&mut CompletionSink::new(&mut out, 2));
                assert_eq!(out.len(), 2, "the sink takes both terminals");
            },
            ControllerEvent::QueueDelete,
            None,
        ),
        (
            "terminal staged inside a submit",
            |disk| {
                SCRIPT.with_borrow_mut(|script| script.submit_inline = true);
                let _ = submit_one(disk, 0);
            },
            ControllerEvent::Reset,
            None,
        ),
        (
            "abort-requested terminal staged inside a submit",
            |disk| {
                SCRIPT.with_borrow_mut(|script| {
                    script.submit_inline = true;
                    script.status.push_back(0x07 << 1);
                });
                let _ = submit_one(disk, 0);
            },
            ControllerEvent::Abort,
            None,
        ),
        (
            "failure flag after an accepted submit",
            |disk| {
                SCRIPT.with_borrow_mut(|script| script.failed.push_back(true));
                let _ = submit_one(disk, 0);
            },
            ControllerEvent::Reset,
            None,
        ),
        (
            "abort-requested terminals staged beyond the sink's room",
            |disk| {
                SCRIPT.with_borrow_mut(|script| {
                    script.fanout = true;
                    script.status.extend([0, 0x07 << 1, 0x08 << 1]);
                });
                for token in 0..3 {
                    submit_one(disk, token).unwrap();
                }
                let mut out = Vec::with_capacity(1);
                disk.pick_completions(&mut CompletionSink::new(&mut out, 1));
                assert_eq!(out.len(), 1, "the sink takes one terminal");
            },
            ControllerEvent::Abort,
            None,
        ),
        (
            "failure flag after a submit that SPDK refuses as gone",
            |disk| {
                SCRIPT.with_borrow_mut(|script| {
                    script.failed.push_back(true);
                    script.submit_rc.push_back(-libc::ENXIO);
                });
                assert!(submit_one(disk, 0).is_err());
            },
            ControllerEvent::Reset,
            Some(libc::ENXIO),
        ),
        (
            "submit refused as gone",
            |disk| {
                SCRIPT.with_borrow_mut(|script| script.submit_rc.push_back(-libc::ENXIO));
                assert!(submit_one(disk, 0).is_err());
            },
            ControllerEvent::Reset,
            Some(libc::ENXIO),
        ),
        (
            "failed admin poll",
            |disk| {
                disk.statistics().request();
                disk.service();
                SCRIPT.with_borrow_mut(|script| script.admin_rc.push_back(-libc::ENXIO));
                disk.service();
            },
            ControllerEvent::Reset,
            Some(libc::ENXIO),
        ),
        (
            "aborted log-page command",
            |disk| {
                SCRIPT.with_borrow_mut(|script| script.admin_status.push_back(0x07 << 1));
                disk.statistics().request();
                disk.service();
                disk.service();
            },
            ControllerEvent::Abort,
            None,
        ),
    ];
    let ready = ready_masks();
    for (name, drive, event, code) in rows {
        SCRIPT.take();
        let mut disk = SpdkDisk::<Scripted>::scripted(&format!("scripted:site-{name}"), limits(4));
        drive(&mut disk);
        assert_eq!(disk.controller_event(), Some(event), "{name}");
        let refusal = submit_one(&mut disk, 9).unwrap_err();
        assert_eq!(
            (refusal.reason, refusal.code),
            (RefusalReason::DeviceGone, code),
            "{name}: submission after the event"
        );
        SCRIPT.with_borrow_mut(|script| script.registers.push_back(ready));
        assert!(!disk.ready(), "{name}: a gone driver is not ready");
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Read,
    Write,
    Register,
}

/// A Register of a key no authority constrains.
fn register() -> ReservationCommand {
    ReservationCommand::Register {
        new: Key::decode((2 << 32) | 2).unwrap(),
    }
}

/// Submits one command of `kind` and returns its refusal's reason and code.
fn submit_kind(
    disk: &mut SpdkDisk<'_, Scripted>,
    kind: Kind,
    token: u64,
    page: &mut [u8; 4096],
) -> Result<(), (RefusalReason, Option<i32>)> {
    let token = CommandToken::from_raw(token);
    let device = DeviceRange::new(0, 4096).unwrap();
    let len = if kind == Kind::Register { 16 } else { 4096 };
    let memory = DmaRange::new(NonNull::from(page).cast(), 0, len);
    // SAFETY: the scripted native layer never touches `memory` after the submit returns, and `page` outlives the
    // driver's use of it within this call.
    unsafe {
        match kind {
            Kind::Read => disk.submit_read(token, device, memory),
            Kind::Write => disk.submit_write(token, device, memory),
            Kind::Register => disk.submit_reservation(token, register(), memory),
        }
    }
    .map_err(|refusal| (refusal.reason, refusal.code))
}

fn count(call: Call) -> usize {
    calls().iter().filter(|&&made| made == call).count()
}

#[test]
fn a_terminal_staged_inside_a_refused_submit_is_held_until_the_proven_stop() {
    use crate::storage::ControllerEvent;

    for kind in [Kind::Read, Kind::Write, Kind::Register] {
        for (rc, reason) in [
            (-libc::EINVAL, RefusalReason::InvalidRange),
            (-libc::ENOMEM, RefusalReason::QueueFull),
        ] {
            let case = (kind, rc);
            SCRIPT.take();
            let mut disk = SpdkDisk::<Scripted>::scripted(
                &format!("scripted:inline-refused-{kind:?}-{rc}"),
                limits(1),
            );
            disk.set_reservation_limits(ReservationLimits::new(3, 2, 10, 20).unwrap());
            let mut page = [0u8; 4096];
            register().encode(&mut page[..16]);
            disk.mark_verified(DmaRange::new(NonNull::from(&mut page).cast(), 0, 4096));
            let submit_call = if kind == Kind::Register {
                Call::Register
            } else {
                Call::Submit
            };

            SCRIPT.with_borrow_mut(|script| {
                script.submit_rc.push_back(rc);
                script.refused_inline = true;
            });
            assert_eq!(
                submit_kind(&mut disk, kind, 0, &mut page),
                Err((reason, Some(-rc))),
                "{case:?}: the native refusal passes through"
            );
            assert_eq!(count(submit_call), 1, "{case:?}");
            let ran = SCRIPT.with_borrow(|script| script.origins.clone());
            assert_eq!(ran.len(), 1, "{case:?}: one callback ran");
            assert_eq!(
                (ran[0].inside, ran[0].submission, ran[0].status),
                (Call::Submit, Some(0), Some(0)),
                "{case:?}: the refused command's callback ran inside its submit with a success status"
            );
            assert_eq!(
                disk.witness().staged,
                1,
                "{case:?}: the callback staged its terminal inside the refused submit"
            );
            assert_eq!(
                disk.controller_event(),
                Some(ControllerEvent::Reset),
                "{case:?}: a terminal staged during a submit ends the incarnation"
            );
            let accepted = disk.witness().accepted;

            for token in 1..3 {
                assert_eq!(
                    submit_kind(&mut disk, kind, token, &mut page),
                    Err((RefusalReason::DeviceGone, None)),
                    "{case:?}: submit {token} after the refused one"
                );
            }
            assert_eq!(
                count(submit_call),
                1,
                "{case:?}: a gone driver hands the native layer no further command"
            );
            assert_eq!(
                disk.witness().accepted,
                accepted,
                "{case:?}: the accepted count stays as the refused submit left it"
            );

            // The staged terminal is never certified: a pick polls nothing and delivers nothing.
            let mut out = Vec::with_capacity(2);
            disk.pick_completions(&mut CompletionSink::new(&mut out, 2));
            assert!(out.is_empty(), "{case:?}: {out:?}");
            assert_eq!(count(Call::Poll), 0, "{case:?}");
            assert_eq!(disk.witness().staged, 1, "{case:?}: held after the pick");

            // The first quiesce call starts the disable and proves nothing, so the terminal stays held.
            assert_eq!(disk.quiesce(), QuiesceStatus::Pending, "{case:?}");
            disk.pick_completions(&mut CompletionSink::new(&mut out, 2));
            assert!(out.is_empty(), "{case:?}: {out:?}");
            let witness = disk.witness();
            assert_eq!(
                (witness.staged, witness.stop.map(|stop| stop.proven)),
                (1, None),
                "{case:?}: held until the registers prove the stop"
            );
            assert_eq!(count(Call::Free), 0, "{case:?}");

            // The register proof discards the staging once.
            assert_eq!(disk.quiesce(), QuiesceStatus::Stopped, "{case:?}");
            let witness = disk.witness();
            assert_eq!(
                (
                    witness.accepted,
                    witness.staged,
                    witness.stop.map(|stop| stop.proven)
                ),
                (0, 0, Some(true)),
                "{case:?}: the proven stop leaves no record accepted or staged"
            );
            assert_eq!(disk.quiesce(), QuiesceStatus::Stopped, "{case:?}");
            assert_eq!(
                count(Call::Free),
                1,
                "{case:?}: one qpair free, one discard"
            );
            disk.pick_completions(&mut CompletionSink::new(&mut out, 2));
            assert!(out.is_empty(), "{case:?}: {out:?}");
            assert_eq!(
                submit_kind(&mut disk, kind, 3, &mut page),
                Err((RefusalReason::DeviceGone, None)),
                "{case:?}: a stopped driver accepts nothing"
            );
            assert_eq!(count(Call::Poll), 0, "{case:?}");
        }
    }
}
