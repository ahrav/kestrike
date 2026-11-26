//! The SPDK driver's argument, refusal, callback-origin, stop and finality
//! records, judged through the Scripted fixture's logs: each submit's
//! arguments and result, and each callback with the native call it ran
//! inside and the submission it belongs to. The
//! fixture fixes a callback's submission when it queues or replays it, so
//! the origin log names the submission a callback came from independently of
//! the staging record it reaches.
//!
//! Every case has a stable name and a deadline it declares before it runs;
//! a case that misses its deadline is missing evidence and fails. The
//! inventory [`REQUIRED`] is frozen here, and
//! [`every_required_spdk_case_is_witnessed`] runs every declared case and
//! checks that each required case is among those witnessed.

use std::ptr::NonNull;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::Duration;

use super::super::super::ledger::EngineBudget;
use super::super::super::test_platform::TestPlatform;
use super::super::disk::{
    CommandToken, Completion, CompletionSink, Disk, DmaRange, QuiesceStatus, RefusalReason,
    SubmitRefusal,
};
use super::super::geometry::DeviceRange;
use super::super::status::DeviceStatus;
use super::super::{
    BufferArena, CommandTable, PoolKind, QuiesceProgress, Quiesced, Refusal, Rejected, Terminal,
    slot_of,
};
use super::certify::disable_proven;
use super::disk::{SCRIPTED_CTRLR, SCRIPTED_NS, SCRIPTED_QPAIR, SpdkDisk};
use super::disk_tests::{
    ABORTED_BY_REQUEST, Answer, Call, Origin, SCRIPT, Script, Scripted, calls, facts, limits,
};
use super::limits::{Limits, NamespaceFacts};
use super::outstanding_tests::arena;
use super::staging::{self, Slots};
use super::stop_tests::unproven_registers;
use crate::native::Unregistered;

/// Each case's deadline. Every case finishes within 50 ms in an
/// unoptimized build on a development host; ten seconds is a margin of two
/// hundred for a loaded workspace runner.
const DEADLINE: Duration = Duration::from_secs(10);

const LEN: u32 = 4096;
const READ: PoolKind = PoolKind::ReadResponse;
const WRITE: PoolKind = PoolKind::ReceiveWrite;

/// One declared case: its stable name, its deadline, and its run, which
/// panics when a check fails.
struct Case {
    name: &'static str,
    deadline: Duration,
    run: fn(),
}

/// The frozen inventory of the driver's fault situations.
const REQUIRED: [&str; 25] = [
    "arguments/byte-range",
    "arguments/preflight-refusal",
    "refusal/enomem",
    "refusal/enxio",
    "refusal/einval",
    "refusal/efault",
    "refusal/controller-failure",
    "refusal/queued-refused-invalid-contract",
    "origin/ordinary-submit",
    "origin/admin-poll",
    "origin/failed-poll",
    "origin/failed-health",
    "origin/certified-drain-while-gone",
    "stop/disconnect-started",
    "stop/disconnect-busy",
    "stop/disconnect-refused",
    "stop/one-slot-sink",
    "stop/device-held-prefix",
    "stop/sparse-slots",
    "finality/staged-duplicate",
    "finality/null-completion",
    "finality/duplicate-after-delivery",
    "finality/post-reuse-assumption-violation",
    "finality/queued-refused-after-reuse-invalid-contract",
    "finality/null-argument",
];

const CASES: [Case; 25] = [
    case("arguments/byte-range", arguments_byte_range),
    case("arguments/preflight-refusal", arguments_preflight_refusal),
    case("refusal/enomem", || refusal(libc::ENOMEM)),
    case("refusal/enxio", || refusal(libc::ENXIO)),
    case("refusal/einval", || refusal(libc::EINVAL)),
    case("refusal/efault", || refusal(libc::EFAULT)),
    case("refusal/controller-failure", refusal_controller_failure),
    case(
        "refusal/queued-refused-invalid-contract",
        refusal_queued_invalid_contract,
    ),
    case("origin/ordinary-submit", || origin(Outside::Submit)),
    case("origin/admin-poll", || origin(Outside::AdminPoll)),
    case("origin/failed-poll", || origin(Outside::FailedPoll)),
    case("origin/failed-health", || {
        origin(Outside::Health { failed: true })
    }),
    case(
        "origin/certified-drain-while-gone",
        origin_certified_drain_while_gone,
    ),
    case("stop/disconnect-started", || stop_case(0, 2, Mix::Withheld)),
    case("stop/disconnect-busy", || {
        stop_case(-libc::EBUSY, 2, Mix::Withheld)
    }),
    case("stop/disconnect-refused", || {
        stop_case(-libc::EIO, 3, Mix::Withheld)
    }),
    case("stop/one-slot-sink", || stop_case(0, 1, Mix::Withheld)),
    case("stop/device-held-prefix", || {
        stop_case(0, 4, Mix::DeviceHeld)
    }),
    case("stop/sparse-slots", || stop_case(0, 2, Mix::Sparse)),
    case("finality/staged-duplicate", finality_staged_duplicate),
    case("finality/null-completion", finality_null_completion),
    case(
        "finality/duplicate-after-delivery",
        finality_duplicate_after_delivery,
    ),
    case(
        "finality/post-reuse-assumption-violation",
        finality_post_reuse_assumption_violation,
    ),
    case(
        "finality/queued-refused-after-reuse-invalid-contract",
        finality_queued_refused_after_reuse,
    ),
    case("finality/null-argument", finality_null_argument),
];

const fn case(name: &'static str, run: fn()) -> Case {
    Case {
        name,
        deadline: DEADLINE,
        run,
    }
}

/// Runs `case` on its own thread, with that thread's own script, and returns
/// once it passes within its deadline. A failed check fails with that
/// check's panic; a run past the deadline fails as missing evidence.
fn witness(case: &Case) {
    let (done, finished) = mpsc::channel();
    let run = case.run;
    let worker = thread::spawn(move || {
        run();
        let _ = done.send(());
    });
    match finished.recv_timeout(case.deadline) {
        Ok(()) => worker.join().unwrap(),
        Err(RecvTimeoutError::Disconnected) => {
            std::panic::resume_unwind(worker.join().unwrap_err())
        }
        Err(RecvTimeoutError::Timeout) => panic!(
            "{} gave no witness within {:?}: missing evidence",
            case.name, case.deadline
        ),
    }
}

fn run_case(name: &str) {
    let case = CASES
        .iter()
        .find(|case| case.name == name)
        .unwrap_or_else(|| panic!("{name} is a declared case"));
    witness(case);
}

#[test]
fn the_spdk_case_inventory_is_frozen() {
    let names: Vec<&str> = CASES.iter().map(|case| case.name).collect();
    assert_eq!(names, REQUIRED);
    for (at, name) in names.iter().enumerate() {
        assert!(!names[..at].contains(name), "{name} is declared once");
    }
}

#[test]
fn every_required_spdk_case_is_witnessed() {
    let mut witnessed = Vec::new();
    for case in &CASES {
        witness(case);
        witnessed.push(case.name);
    }
    for required in REQUIRED {
        assert!(
            witnessed.contains(&required),
            "{required} is required but no case witnessed it"
        );
    }
}

/// A scripted address unique across every case run in this process, so a
/// case run twice at once attaches two drivers.
fn address(name: &str) -> String {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    format!(
        "scripted:records-{name}-{}",
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

fn script<T>(f: impl FnOnce(&mut Script) -> T) -> T {
    SCRIPT.with_borrow_mut(f)
}

/// The answer the native call at position `call` gave.
fn answer(call: usize) -> Answer {
    script(|s| {
        s.answers
            .iter()
            .find(|(at, _)| *at == call)
            .map(|&(_, answer)| answer)
    })
    .unwrap_or_else(|| panic!("call {call} answered"))
}

fn origins() -> Vec<Origin> {
    script(|s| s.origins.clone())
}

fn origins_of(submission: usize) -> Vec<Origin> {
    origins()
        .into_iter()
        .filter(|origin| origin.submission == Some(submission))
        .collect()
}

/// Checks the ordinary terminal delivered for `submission` by a pick that
/// returned with `returned` native calls logged: the submission's callback
/// ran once, inside a completion poll that answered nonnegative, and the
/// next native call after that poll read the failure flag as healthy before
/// the pick returned.
fn assert_poll_certified(submission: usize, returned: usize) {
    let ran = origins_of(submission);
    assert_eq!(ran.len(), 1, "submission {submission}: {ran:?}");
    let origin = ran[0];
    assert_eq!(origin.inside, Call::Poll, "submission {submission}");
    assert!(
        matches!(answer(origin.call), Answer::Rc(rc) if rc >= 0),
        "submission {submission}: the origin poll answered nonnegative"
    );
    let health = origin.call + 1;
    assert!(health < returned, "submission {submission}");
    assert_eq!(calls()[health], Call::Failed, "submission {submission}");
    assert_eq!(
        answer(health),
        Answer::Failed(false),
        "submission {submission}: the origin poll observed a healthy controller"
    );
}

/// A scripted driver over a heap page range it treats as registered; a
/// submission's token is its index in the fixture's submit log.
struct Rig {
    disk: SpdkDisk<'static, Scripted>,
    base: NonNull<u8>,
    _page: Box<[u8]>,
}

impl Rig {
    fn new(name: &str, limits: Limits, bytes: usize) -> Self {
        script(|s| *s = Script::default());
        let mut page = vec![0u8; bytes].into_boxed_slice();
        let base = NonNull::new(page.as_mut_ptr()).unwrap();
        let mut disk = SpdkDisk::<Scripted>::scripted(&address(name), limits);
        disk.mark_verified(DmaRange::new(base, 0, LEN));
        Self {
            disk,
            base,
            _page: page,
        }
    }

    fn memory(&self, offset: usize, len: u32) -> DmaRange {
        // SAFETY: every offset a case passes lies within the page.
        DmaRange::new(unsafe { self.base.add(offset) }, offset, len)
    }

    /// Submits `len` bytes at device byte `start` from `offset` bytes into the page.
    fn submit_at(
        &mut self,
        write: bool,
        start: u64,
        memory: DmaRange,
    ) -> Result<usize, SubmitRefusal> {
        let submission = script(|s| s.submits.len());
        let token = CommandToken::from_raw(submission as u64);
        let device = DeviceRange::new(start, memory.byte_len()).unwrap();
        // SAFETY: the scripted native layer treats the memory as an opaque address.
        unsafe {
            if write {
                self.disk.submit_write(token, device, memory)
            } else {
                self.disk.submit_read(token, device, memory)
            }
        }
        .map(|()| submission)
    }

    fn read(&mut self, block: u64) -> usize {
        let memory = self.memory(0, LEN);
        self.submit_at(false, block * u64::from(LEN), memory)
            .unwrap()
    }

    /// One pick with room for `room` terminals: the delivered submissions and
    /// statuses, and the native calls logged when the pick returned.
    fn pick(&mut self, room: usize) -> (Vec<(usize, u16)>, usize) {
        let mut out: Vec<Completion> = Vec::with_capacity(room);
        self.disk
            .pick_completions(&mut CompletionSink::new(&mut out, room));
        let delivered = out
            .iter()
            .map(|completion| {
                let DeviceStatus::Nvme(status) = completion.status else {
                    panic!("{completion:?}")
                };
                (completion.token.raw() as usize, status)
            })
            .collect();
        (delivered, calls().len())
    }

    fn assert_gone(&mut self) {
        let memory = self.memory(0, LEN);
        let refusal = self.submit_at(false, 0, memory).unwrap_err();
        assert_eq!(refusal.reason, RefusalReason::DeviceGone);
    }

    /// A proven stop with valid registers on the first read: afterwards every
    /// record is free and the staging FIFO is empty.
    fn stop(&mut self) {
        assert!(matches!(
            self.disk.quiesce(),
            QuiesceStatus::Pending | QuiesceStatus::Failed(_)
        ));
        assert_eq!(self.disk.quiesce(), QuiesceStatus::Stopped);
        let witness = self.disk.witness();
        assert_eq!(
            (witness.accepted, witness.staged, witness.certified),
            (0, 0, 0)
        );
        assert!(self.disk.detach(&Unregistered::scripted()));
    }
}

/// Every read and write reaches the native layer with the requested
/// operation, the attached namespace and qpair, the exact host pointer, and
/// `lba = start / sector` and `count = len / sector`; the products of the
/// logged values, taken in `u128`, give back the requested byte interval,
/// which ends within the capacity. Each power-of-two sector size from 1 byte
/// to 4 KiB, every size that divides 4 KiB, is
/// crossed with nonzero device and memory offsets, the smallest transfer,
/// the transfer limit and a range ending at the capacity, and each command's
/// terminal reaches its own token.
fn arguments_byte_range() {
    for sector in (0..=12).map(|shift| 1u32 << shift) {
        let namespace = NamespaceFacts {
            sector_size: sector,
            sectors: (1u64 << 30) / u64::from(sector),
            ..facts()
        };
        let limits = namespace.limits(8).unwrap();
        let (capacity, transfer) = (limits.capacity, limits.transfer);
        assert_eq!(
            (capacity, transfer),
            (1 << 30, 128 << 10),
            "sector {sector}"
        );
        // The smallest transfer a device range carries: one sector, at least 512 bytes.
        let small = sector.max(512);
        let mut rig = Rig::new(
            "arguments",
            limits,
            2 * transfer as usize + 4 * LEN as usize,
        );
        // Each ledger row: (write, device start byte, length in bytes, memory offset into the page).
        let ledger: [(bool, u64, u32, usize); 7] = [
            (false, 7 * u64::from(LEN), small, LEN as usize),
            (true, 9 * u64::from(LEN), 3 * LEN, 2 * LEN as usize),
            (false, 0, transfer, 0),
            (
                false,
                capacity - u64::from(transfer),
                transfer,
                LEN as usize,
            ),
            (
                true,
                capacity - u64::from(transfer),
                transfer,
                3 * LEN as usize,
            ),
            (true, capacity - u64::from(LEN), LEN, transfer as usize),
            (false, capacity - u64::from(LEN), small, 5 * LEN as usize),
        ];
        for (write, start, len, offset) in ledger {
            let case = (sector, write, start, len, offset);
            let memory = rig.memory(offset, len);
            let submission = rig.submit_at(write, start, memory).unwrap();
            let logged = script(|s| s.submits[submission]);
            assert_eq!(logged.write, write, "{case:?}");
            assert_eq!(
                (logged.ns, logged.qpair),
                (SCRIPTED_NS, SCRIPTED_QPAIR),
                "{case:?}"
            );
            assert_eq!(logged.payload, memory.addr().as_ptr().addr(), "{case:?}");
            assert_eq!(
                logged.payload,
                rig.base.as_ptr().addr() + offset,
                "{case:?}"
            );
            assert_eq!(logged.lba, start / u64::from(sector), "{case:?}");
            assert_eq!(
                u64::from(logged.count),
                u64::from(len) / u64::from(sector),
                "{case:?}"
            );
            let wide = u128::from(sector);
            assert_eq!(u128::from(logged.lba) * wide, u128::from(start), "{case:?}");
            assert_eq!(u128::from(logged.count) * wide, u128::from(len), "{case:?}");
            assert!(
                (u128::from(logged.lba) + u128::from(logged.count)) * wide <= u128::from(capacity),
                "{case:?}"
            );
            assert!(!logged.arg.is_null(), "{case:?}");
            assert_eq!(rig.pick(1).0, [(submission, 0)], "{case:?}");
        }
        rig.stop();
    }
}

/// A submit the driver refuses before SPDK sees it, for a range past the
/// capacity or the transfer limit, a length off the sector size, memory of
/// another length or outside the registered arena, an unverified driver, or
/// a full queue, returns before any native call, so the call and submit logs
/// stay unchanged.
fn arguments_preflight_refusal() {
    let namespace = NamespaceFacts {
        sector_size: 4096,
        sectors: (1u64 << 30) / 4096,
        ..facts()
    };
    let limits = namespace.limits(1).unwrap();
    let (capacity, transfer) = (limits.capacity, limits.transfer);
    let mut rig = Rig::new(
        "preflight",
        limits,
        2 * transfer as usize + 2 * LEN as usize,
    );
    let foreign = DmaRange::new(rig.memory(LEN as usize, LEN).addr(), 0, LEN);
    let invalid = [
        (0, rig.memory(0, transfer + LEN)),
        (capacity, rig.memory(0, LEN)),
        (capacity - u64::from(LEN), rig.memory(0, 2 * LEN)),
        (0, rig.memory(0, 512)),
        (0, foreign),
    ];
    for (start, memory) in invalid {
        let before = calls().len();
        let refusal = rig.submit_at(false, start, memory).unwrap_err();
        assert_eq!(
            refusal,
            SubmitRefusal {
                reason: RefusalReason::InvalidRange,
                code: None
            },
            "{start} {memory:?}"
        );
        assert_eq!(
            calls().len(),
            before,
            "a preflight refusal makes no native call"
        );
    }
    let before = calls().len();
    let mismatched = rig.memory(0, LEN);
    let device = DeviceRange::new(0, 2 * LEN).unwrap();
    // SAFETY: the scripted native layer treats the memory as an opaque address.
    let refusal = unsafe {
        rig.disk
            .submit_read(CommandToken::from_raw(9), device, mismatched)
    }
    .unwrap_err();
    assert_eq!(refusal.reason, RefusalReason::InvalidRange);
    assert_eq!(calls().len(), before);
    rig.read(0);
    let before = calls().len();
    let memory = rig.memory(0, LEN);
    let refusal = rig.submit_at(true, u64::from(LEN), memory).unwrap_err();
    assert_eq!(
        (refusal.reason, refusal.code),
        (RefusalReason::QueueFull, None)
    );
    assert_eq!(calls().len(), before, "a full queue refuses before SPDK");
    let mut unverified = SpdkDisk::<Scripted>::scripted(&address("unverified"), limits);
    let before = calls().len();
    // SAFETY: as above.
    let refusal = unsafe {
        unverified.submit_read(
            CommandToken::from_raw(0),
            DeviceRange::new(0, LEN).unwrap(),
            memory,
        )
    }
    .unwrap_err();
    assert_eq!(refusal.reason, RefusalReason::NotVerified);
    assert_eq!(calls().len(), before);
    assert_eq!(
        script(|s| s.submits.len()),
        1,
        "only the one accepted read reached SPDK"
    );
}

/// A table of `depth` slots over a scripted driver of the same depth whose registration covers the arena.
fn table<'a>(
    arena: &'a BufferArena<TestPlatform>,
    name: &str,
    depth: u16,
) -> CommandTable<'a, SpdkDisk<'a, Scripted>> {
    script(|s| *s = Script::default());
    let mut disk = SpdkDisk::<Scripted>::scripted(&address(name), limits(u32::from(depth)));
    let probe = arena.acquire(READ).unwrap();
    disk.mark_verified(probe.range(LEN).unwrap());
    drop(probe);
    CommandTable::new(disk, arena, depth, &mut EngineBudget::new(usize::MAX))
        .map_err(|(error, _)| error)
        .unwrap()
}

fn submit<'a>(
    table: &mut CommandTable<'a, SpdkDisk<'a, Scripted>>,
    buffer: super::super::Buffer<'a>,
    write: bool,
    block: u64,
) -> Result<CommandToken, Rejected<'a>> {
    let range = DeviceRange::new(block * u64::from(LEN), LEN).unwrap();
    if write {
        table.submit_write(buffer, range)
    } else {
        table.submit_read(buffer, range)
    }
}

/// The custody census: table pending records, each pool's application and
/// storage counts, the driver's accepted, staged and certified records, and
/// the callbacks the fixture still owes.
fn census(
    table: &mut CommandTable<'_, SpdkDisk<'_, Scripted>>,
    arena: &BufferArena<TestPlatform>,
) -> [usize; 8] {
    let witness = table.driver_witness();
    let (read, write) = (arena.report(READ), arena.report(WRITE));
    [
        table.report().pending as usize,
        read.application as usize,
        read.storage as usize,
        write.application as usize,
        write.storage as usize,
        witness.accepted,
        witness.staged + witness.certified,
        script(|s| s.queued.len()),
    ]
}

fn token_of(terminal: &Terminal<'_>) -> CommandToken {
    match terminal {
        Terminal::Read { token, .. }
        | Terminal::Written { token, .. }
        | Terminal::Failed { token, .. }
        | Terminal::Quiesced { token, .. }
        | Terminal::Abandoned { token, .. }
        | Terminal::Reservation { token, .. } => *token,
    }
}

/// A native refusal with `errno`, of a read and of a write, alone and after
/// an accepted command: the table returns the same buffer
/// application-owned with the driver's classification and code, the census
/// is unchanged, the staging slot is free, and the fixture's queue of owed
/// callbacks holds the accepted commands alone.
/// After a nonfatal refusal the same buffer's retry is accepted and both
/// commands deliver once each, each through its own callback; after
/// `-ENXIO` the table refuses before the driver and a proven stop quiesces
/// the earlier command.
fn refusal(errno: i32) {
    refusal_with(errno, false);
}

/// [`refusal`] with the scripted driver running each refused command's own callback inside its submit when
/// `refused_inline` is set.
fn refusal_with(errno: i32, refused_inline: bool) {
    let reason = match errno {
        libc::ENOMEM => RefusalReason::QueueFull,
        libc::ENXIO => RefusalReason::DeviceGone,
        _ => RefusalReason::InvalidRange,
    };
    for write in [false, true] {
        for prior in [false, true] {
            let case = (errno, write, prior);
            let arena = arena();
            let mut table = table(&arena, "refusal", 4);
            let earlier =
                prior.then(|| submit(&mut table, arena.acquire(READ).unwrap(), false, 0).unwrap());
            let buffer = arena.acquire(if write { WRITE } else { READ }).unwrap();
            let identity = (buffer.kind(), buffer.offset());
            let before = census(&mut table, &arena);
            script(|s| {
                s.submit_rc.push_back(-errno);
                s.refused_inline = refused_inline;
            });
            let Rejected {
                buffer: returned,
                refusal: why,
            } = submit(&mut table, buffer, write, 1).unwrap_err();
            assert_eq!(
                why,
                Refusal::Device(SubmitRefusal {
                    reason,
                    code: Some(errno)
                }),
                "{case:?}"
            );
            assert_eq!(
                (returned.kind(), returned.offset()),
                identity,
                "{case:?}: the same buffer comes back"
            );
            assert_eq!(
                census(&mut table, &arena),
                before,
                "{case:?}: a native refusal leaves the census as it was before the submit"
            );
            let refused = script(|s| s.submits.len() - 1);
            assert_eq!(script(|s| s.submits[refused].rc), -errno, "{case:?}");
            assert!(origins_of(refused).is_empty(), "{case:?}");
            let mut out = Vec::with_capacity(2);
            if reason == RefusalReason::DeviceGone {
                let calls_before = calls().len();
                let again = submit(&mut table, returned, write, 1).unwrap_err();
                assert_eq!(again.refusal, Refusal::DeviceLost, "{case:?}");
                assert_eq!(
                    calls().len(),
                    calls_before,
                    "{case:?}: refused before the driver"
                );
                // Direct submission exercises the driver's latched refusal independently of the table's admission check.
                if !prior {
                    let disk = table
                        .disk_mut()
                        .expect("a lost table with nothing outstanding lends its driver");
                    let memory = again.buffer.range(LEN).unwrap();
                    let device = DeviceRange::new(u64::from(LEN), LEN).unwrap();
                    let token = CommandToken::from_raw(9);
                    // SAFETY: a gone driver refuses before SPDK sees the memory, which stays application-owned.
                    let direct = unsafe {
                        if write {
                            disk.submit_write(token, device, memory)
                        } else {
                            disk.submit_read(token, device, memory)
                        }
                    };
                    assert_eq!(
                        direct,
                        Err(SubmitRefusal {
                            reason: RefusalReason::DeviceGone,
                            code: Some(errno)
                        }),
                        "{case:?}: the driver itself latched gone"
                    );
                    assert_eq!(
                        calls().len(),
                        calls_before,
                        "{case:?}: the gone driver refused before SPDK"
                    );
                }
                drop(again);
                let mut progress = table.quiesce(&mut out);
                while !matches!(progress, QuiesceProgress::Quiesced(_)) {
                    progress = table.quiesce(&mut out);
                }
                if let Some(earlier) = earlier {
                    // On a gone driver the earlier read's one callback runs inside the proven stop's qpair free, and the table quiesces the read from its own record.
                    assert_eq!(
                        progress,
                        QuiesceProgress::Quiesced(Quiesced::DeviceStopped),
                        "{case:?}"
                    );
                    assert!(
                        matches!(
                            out.as_slice(),
                            [Terminal::Quiesced { token, .. }] if *token == earlier
                        ),
                        "{case:?}: {out:?}"
                    );
                    let ran: Vec<Call> = origins_of(0).iter().map(|origin| origin.inside).collect();
                    assert_eq!(ran, [Call::Free], "{case:?}");
                } else {
                    assert_eq!(
                        progress,
                        QuiesceProgress::Quiesced(Quiesced::AllReturned),
                        "{case:?}"
                    );
                    assert!(out.is_empty(), "{case:?}: {out:?}");
                }
            } else {
                let retry = submit(&mut table, returned, write, 1).unwrap();
                table.poll(&mut out);
                let mut delivered: Vec<_> = out.iter().map(token_of).collect();
                delivered.sort_unstable_by_key(|token| token.raw());
                let mut expected: Vec<_> = earlier.into_iter().chain([retry]).collect();
                expected.sort_unstable_by_key(|token| token.raw());
                assert_eq!(delivered, expected, "{case:?}");
                let retried = script(|s| s.submits.len() - 1);
                assert_eq!(origins_of(retried).len(), 1, "{case:?}");
                if prior {
                    assert_eq!(
                        origins_of(0).len(),
                        1,
                        "{case:?}: the earlier command's own callback"
                    );
                }
            }
            drop((out, table));
            assert!(arena.release().is_ok(), "{case:?}");
        }
    }
}

/// A nonfatal native refusal still returns its buffer while a controller
/// that reads failed during the submit turns the driver gone: the next
/// submit refuses `DeviceGone`.
fn refusal_controller_failure() {
    let arena = arena();
    let mut table = table(&arena, "refusal-failed", 4);
    let buffer = arena.acquire(READ).unwrap();
    let identity = (buffer.kind(), buffer.offset());
    let before = census(&mut table, &arena);
    script(|s| {
        s.submit_rc.push_back(-libc::ENOMEM);
        s.failed.push_back(true);
    });
    let Rejected {
        buffer: returned,
        refusal: why,
    } = submit(&mut table, buffer, false, 0).unwrap_err();
    assert_eq!(
        why,
        Refusal::Device(SubmitRefusal {
            reason: RefusalReason::QueueFull,
            code: Some(libc::ENOMEM)
        })
    );
    assert_eq!((returned.kind(), returned.offset()), identity);
    assert_eq!(census(&mut table, &arena), before);
    let again = submit(&mut table, returned, false, 0).unwrap_err();
    assert_eq!(
        again.refusal,
        Refusal::Device(SubmitRefusal {
            reason: RefusalReason::DeviceGone,
            code: None
        }),
        "the failure latched the driver gone"
    );
    drop((again, table));
    assert!(arena.release().is_ok());
}

/// Invalid-contract control: the fixture queues a refused command's callback
/// although a nonzero result ends SPDK's access. With the record still free
/// when the callback runs, it counts a stray, and the pick delivers the
/// accepted command alone.
fn refusal_queued_invalid_contract() {
    let mut rig = Rig::new("queued-refused", limits(2), 2 * LEN as usize);
    let b = rig.read(0);
    script(|s| {
        s.queue_refused = true;
        s.submit_rc.push_back(-libc::ENOMEM);
    });
    let memory = rig.memory(0, LEN);
    let refused = script(|s| s.submits.len());
    let refusal = rig.submit_at(false, u64::from(LEN), memory).unwrap_err();
    assert_eq!(refusal.reason, RefusalReason::QueueFull);
    script(|s| s.queue_refused = false);
    assert_eq!(rig.pick(2).0, [(b, 0)], "invalid-contract control");
    assert_eq!(
        origins_of(refused).len(),
        1,
        "invalid-contract control: the refused callback ran"
    );
    let witness = rig.disk.witness();
    assert_eq!(
        (witness.accepted, witness.staged, witness.strays),
        (0, 0, 1)
    );
    rig.stop();
}

/// The native call that stages command A: a call outside a healthy completion poll, or under `Health { failed: false }`
/// a healthy poll, the planted origin of a negative control.
#[derive(Debug, Clone, Copy)]
enum Outside {
    Submit,
    AdminPoll,
    FailedPoll,
    /// A successful completion poll after which the controller's failure flag reads `failed`.
    Health {
        failed: bool,
    },
}

/// Accepts A and B; a native call outside a healthy poll stages A while B
/// stays outstanding. The origin log names that call for A; A stays staged
/// and uncertified, the driver is gone, and a later pick delivers an empty
/// batch. A proven stop quiesces both, and B's one callback runs inside the
/// free. The log-page submit origin is the statistics regression in
/// `disk_tests`, which the same origin log records.
fn origin(outside: Outside) {
    let mut rig = Rig::new("origin", limits(4), 2 * LEN as usize);
    let (a, b) = (rig.read(0), rig.read(1));
    let handle = rig.disk.statistics();
    let inside = match outside {
        Outside::Submit => {
            script(|s| s.submit_runs_io = 1);
            rig.read(2);
            Call::Submit
        }
        Outside::AdminPoll => {
            handle.request();
            rig.disk.service();
            script(|s| s.admin_runs_io = 1);
            rig.disk.service();
            script(|s| s.admin_runs_io = 0);
            Call::Admin
        }
        Outside::FailedPoll => {
            script(|s| {
                s.finished.push_back(1);
                s.poll.push_back((-libc::EIO, true));
            });
            assert!(rig.pick(4).0.is_empty());
            Call::Poll
        }
        Outside::Health { failed } => {
            script(|s| {
                s.finished.push_back(1);
                s.failed.push_back(failed);
            });
            let picked = rig.pick(4).0;
            assert!(
                picked.is_empty(),
                "{outside:?}: a poll on a failed controller certifies no terminal it staged: {picked:?}"
            );
            Call::Poll
        }
    };
    let ran = origins_of(a);
    assert_eq!(ran.len(), 1, "{outside:?}");
    assert_eq!(ran[0].inside, inside, "{outside:?}");
    assert!(origins_of(b).is_empty(), "{outside:?}: B stays outstanding");
    let witness = rig.disk.witness();
    assert_eq!((witness.staged, witness.certified), (1, 0), "{outside:?}");
    script(|s| s.finished.push_back(usize::MAX));
    assert!(
        rig.pick(4).0.is_empty(),
        "{outside:?}: a gone driver delivers neither A nor B through a later poll"
    );
    rig.assert_gone();
    rig.stop();
    let freed = origins_of(b);
    assert_eq!(freed.len(), 1, "{outside:?}");
    assert_eq!(freed[0].inside, Call::Free, "{outside:?}");
}

/// Terminals a healthy poll certified that waited for room in the sink
/// deliver after the driver turned gone, each from its own healthy poll.
fn origin_certified_drain_while_gone() {
    let mut rig = Rig::new("drain-gone", limits(4), 2 * LEN as usize);
    let (a, b) = (rig.read(0), rig.read(1));
    script(|s| s.fanout = true);
    let (first, returned) = rig.pick(1);
    assert_eq!(first, [(a, 0)]);
    assert_poll_certified(a, returned);
    script(|s| s.fanout = false);
    assert_eq!(rig.disk.witness().certified, 1);
    script(|s| s.submit_rc.push_back(-libc::ENXIO));
    let memory = rig.memory(0, LEN);
    assert_eq!(
        rig.submit_at(false, 0, memory).unwrap_err().reason,
        RefusalReason::DeviceGone
    );
    let (drained, returned) = rig.pick(2);
    assert_eq!(drained, [(b, ABORTED_BY_REQUEST)]);
    assert_poll_certified(b, returned);
    rig.stop();
}

/// Which commands a stop case leaves outside the device at the disable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mix {
    /// Slot 0 delivers and slot 1 waits certified, aborted past the poll's limit, while slots 2 to 5 stay on the device. The abort is a controller event, so the driver refuses every later submit.
    Withheld,
    /// Slots 0 and 1 deliver, leaving the four pending records in slots 2 to 5.
    Sparse,
    /// All six commands stay on the device in slots 0 to 5.
    DeviceHeld,
}

/// Submits one command per block, writes on even blocks and reads on odd ones, recording each token.
fn submit_blocks<'a>(
    table: &mut CommandTable<'a, SpdkDisk<'a, Scripted>>,
    arena: &'a BufferArena<TestPlatform>,
    tokens: &mut Vec<CommandToken>,
    blocks: std::ops::Range<u64>,
) {
    for block in blocks {
        let pool = if block % 2 == 0 { WRITE } else { READ };
        tokens.push(submit(table, arena.acquire(pool).unwrap(), pool == WRITE, block).unwrap());
    }
}

/// Six commands, reads and writes, through a table of depth 8 whose output
/// holds `room` terminals, with `mix` deciding which deliver before the
/// stop. The disable starts with `disconnect`, four register reads fail to
/// prove it, and the fifth proves it. The one qpair free follows the
/// proving read on the same qpair and aborts every device command, more
/// than the room; the stop delivers the `M` remaining commands as quiesced
/// in exactly `ceil(M / room)` calls from the proving call, wherever their
/// slots lie, and each command reaches the table exactly once.
fn stop_case(disconnect: i32, room: usize, mix: Mix) {
    let arena = arena();
    let mut table = table(&arena, "stop", 8);
    // The ledger holds every terminal the table delivered, ordinary or quiesced, in delivery order.
    let mut ledger = Vec::new();
    let mut tokens = Vec::new();
    match mix {
        Mix::Withheld => {
            submit_blocks(&mut table, &arena, &mut tokens, 0..6);
            script(|s| {
                s.fanout = true;
                s.finished.push_back(2);
            });
            let mut one = Vec::with_capacity(1);
            assert_eq!(table.poll(&mut one).delivered, 1);
            ledger.append(&mut one);
            script(|s| s.fanout = false);
        }
        Mix::Sparse => {
            submit_blocks(&mut table, &arena, &mut tokens, 0..6);
            script(|s| s.finished.push_back(2));
            let mut two = Vec::with_capacity(2);
            assert_eq!(table.poll(&mut two).delivered, 2);
            ledger.append(&mut two);
        }
        Mix::DeviceHeld => submit_blocks(&mut table, &arena, &mut tokens, 0..6),
    }
    script(|s| {
        s.poll.push_back((0, false));
        s.disconnect.push_back(disconnect);
        s.registers.extend(unproven_registers());
    });
    let mut out = Vec::with_capacity(room);
    let mut outstanding = 0;
    let proving = loop {
        let progress = table.quiesce(&mut out);
        ledger.append(&mut out);
        match progress {
            QuiesceProgress::Draining { outstanding: left }
            | QuiesceProgress::Unproven {
                outstanding: left, ..
            } => {
                assert!(!calls().contains(&Call::Free), "no free before the proof");
                outstanding = left;
            }
            other => break other,
        }
    };
    let mut drains = 1;
    let mut progress = proving;
    while progress != QuiesceProgress::Quiesced(Quiesced::DeviceStopped) {
        assert!(
            matches!(progress, QuiesceProgress::Delivering { .. }),
            "{progress:?}"
        );
        progress = table.quiesce(&mut out);
        ledger.append(&mut out);
        drains += 1;
    }
    let delivered: Vec<CommandToken> = ledger
        .iter()
        .filter(|terminal| !matches!(terminal, Terminal::Quiesced { .. }))
        .map(token_of)
        .collect();
    assert_eq!(
        delivered.len(),
        if mix == Mix::DeviceHeld { 0 } else { 2 },
        "{mix:?}: the commands delivered before the stop"
    );
    let remaining = 6 - delivered.len();
    assert_eq!(
        outstanding as usize, remaining,
        "{mix:?}: every remaining command stays outstanding until the register proof"
    );
    if mix == Mix::Sparse {
        let highest = tokens
            .iter()
            .filter(|token| !delivered.contains(token))
            .map(|&token| slot_of(token))
            .max();
        assert_eq!(highest, Some(5), "the pending records sit in slots 2 to 5");
    }
    assert_eq!(
        drains,
        remaining.div_ceil(room),
        "{mix:?}: the stop drains M commands in ceil(M / room) calls"
    );
    let log = calls();
    let handles = script(|s| s.handles.clone());
    let frees: Vec<usize> = (0..log.len()).filter(|&at| log[at] == Call::Free).collect();
    assert_eq!(frees.len(), 1);
    assert_eq!(
        handles[frees[0]], SCRIPTED_QPAIR,
        "the free names the driver's qpair"
    );
    let reads: Vec<usize> = (0..frees[0])
        .filter(|&at| log[at] == Call::Registers)
        .collect();
    assert!(
        reads.iter().all(|&at| handles[at] == SCRIPTED_CTRLR),
        "every register read names the driver's controller"
    );
    // SAFETY: the mask accessors read native constants.
    let (en, rdy) = unsafe {
        (
            spdk_sys::spdk_sys_nvme_cc_en_mask(),
            spdk_sys::spdk_sys_nvme_csts_rdy_mask(),
        )
    };
    let proven: Vec<bool> = reads
        .iter()
        .map(|&at| match answer(at) {
            Answer::Registers(cc, csts) => disable_proven(cc, csts, en, rdy),
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(
        proven,
        [false, false, false, false, true],
        "invalid reads, then the proof"
    );
    assert_eq!(
        *reads.last().unwrap() + 1,
        frees[0],
        "the free follows the proving read"
    );
    let aborted: Vec<Origin> = origins()
        .into_iter()
        .filter(|origin| origin.inside == Call::Free)
        .collect();
    assert_eq!(
        aborted.len(),
        remaining,
        "the free aborts every device command"
    );
    assert!(aborted.len() > room);
    assert!(
        aborted
            .iter()
            .all(|origin| origin.status == Some(ABORTED_BY_REQUEST))
    );
    let mut seen: Vec<CommandToken> = ledger.iter().map(token_of).collect();
    seen.sort_unstable_by_key(|token| token.raw());
    tokens.sort_unstable_by_key(|token| token.raw());
    assert_eq!(seen, tokens, "one terminal per command");
    let witness = table.driver_witness();
    assert_eq!(
        (witness.accepted, witness.staged, witness.certified),
        (0, 0, 0)
    );
    drop((ledger, out, table));
    assert!(arena.release().is_ok());
}

/// A second callback for a staged command, in the same poll, counts a
/// stray: the record keeps its first status and delivers once.
fn finality_staged_duplicate() {
    let mut rig = Rig::new("staged-duplicate", limits(2), 2 * LEN as usize);
    let a = rig.read(0);
    script(|s| s.replay.push_back((a, Some(0x0002))));
    assert_eq!(rig.pick(1).0, [(a, 0x0002)]);
    assert_eq!(origins_of(a).len(), 2);
    assert_eq!(rig.disk.witness().strays, 1);
    rig.stop();
}

/// A null completion counts a stray and keeps the record accepted; the
/// command's own completion then delivers it.
fn finality_null_completion() {
    let mut rig = Rig::new("null-completion", limits(2), 2 * LEN as usize);
    let a = rig.read(0);
    script(|s| {
        s.replay.push_back((a, None));
        s.poll.push_back((0, false));
    });
    assert!(rig.pick(1).0.is_empty());
    let witness = rig.disk.witness();
    assert_eq!(
        (witness.accepted, witness.staged, witness.strays),
        (1, 0, 1)
    );
    assert_eq!(rig.pick(1).0, [(a, 0)]);
    rig.stop();
}

/// A callback for a delivered command whose record is still free counts a
/// stray and leaves every other command as it was.
fn finality_duplicate_after_delivery() {
    let mut rig = Rig::new("after-delivery", limits(2), 2 * LEN as usize);
    let (a, b) = (rig.read(0), rig.read(1));
    script(|s| s.finished.push_back(1));
    assert_eq!(rig.pick(1).0, [(a, 0)]);
    assert_eq!(rig.disk.witness().accepted, 1);
    script(|s| {
        s.replay.push_back((a, Some(0x0004)));
        s.poll.push_back((0, false));
    });
    assert!(rig.pick(1).0.is_empty());
    let witness = rig.disk.witness();
    assert_eq!(
        (witness.accepted, witness.staged, witness.strays),
        (1, 0, 1)
    );
    assert_eq!(rig.pick(1).0, [(b, 0)]);
    rig.stop();
}

/// Assumption-violation containment control. SPDK v25.05.1 runs one final
/// callback per accepted command, and the driver trusts it. This case breaks
/// that finality on purpose: A completes and delivers, B reuses A's record,
/// and the fixture invokes A's saved callback inside a healthy poll while B
/// is pending. The origin log names submission A, fixed when the fixture
/// saved the callback; the driver, which names a command by record alone,
/// delivers B's token with A's status, and B's own later callback is a
/// stray. The outcome is labeled an assumption violation: it shows the limit
/// of trusted finality, and the guarantee ends at that limit. Per-submission
/// callback isolation stays a proposed, unimplemented property.
fn finality_post_reuse_assumption_violation() {
    let mut rig = Rig::new("post-reuse", limits(1), 2 * LEN as usize);
    let a = rig.read(0);
    assert_eq!(rig.pick(1).0, [(a, 0)]);
    let b = rig.read(1);
    let stale = 0x0002;
    script(|s| {
        s.replay.push_back((a, Some(stale)));
        s.poll.push_back((0, false));
    });
    let (delivered, _) = rig.pick(1);
    let last = *origins().last().unwrap();
    assert_eq!(
        (last.submission, last.inside, last.status),
        (Some(a), Call::Poll, Some(stale)),
        "assumption violation: the origin log names A independently of the slot"
    );
    assert_eq!(
        delivered,
        [(b, stale)],
        "assumption violation: a callback after A's terminal stages B's reused record"
    );
    assert!(rig.pick(1).0.is_empty());
    rig.stop();
    assert_eq!(
        origins_of(b)
            .iter()
            .map(|origin| origin.inside)
            .collect::<Vec<_>>(),
        [Call::Free]
    );
    assert_eq!(
        rig.disk.witness().strays,
        1,
        "B's own callback finds a free record"
    );
}

/// Invalid-contract control: a refused submit whose callback the fixture
/// queues anyway, followed by a retry that reuses the freed record. The
/// refused callback runs first and stages the retry's record, so the retry
/// delivers once with the refused callback's origin, and its own callback
/// is a stray: the contract that a nonzero result ends SPDK's access is what
/// keeps a refusal inert.
fn finality_queued_refused_after_reuse() {
    let mut rig = Rig::new("refused-reuse", limits(1), 2 * LEN as usize);
    script(|s| {
        s.queue_refused = true;
        s.submit_rc.push_back(-libc::ENOMEM);
        s.status.push_back(0x0006);
    });
    let memory = rig.memory(0, LEN);
    let refused = script(|s| s.submits.len());
    assert!(rig.submit_at(false, 0, memory).is_err());
    script(|s| s.queue_refused = false);
    let retry = rig.read(1);
    script(|s| s.fanout = true);
    let (delivered, _) = rig.pick(1);
    assert_eq!(
        delivered,
        [(retry, 0x0006)],
        "invalid-contract control: the refused callback stages the retry"
    );
    assert_eq!(origins_of(refused)[0].inside, Call::Poll);
    assert_eq!(rig.disk.witness().strays, 1);
    rig.stop();
}

/// A completion callback with a null argument leaves the staging unchanged.
fn finality_null_argument() {
    let mut slots = Slots::new(2);
    // SAFETY: the reference ends before the callback below runs.
    unsafe { slots.staging() }.accept(3).unwrap();
    let cpl = spdk_sys::spdk_nvme_cpl::default();
    // SAFETY: the callback returns at once on a null argument, and `cpl` is a valid completion.
    unsafe { staging::complete(std::ptr::null_mut(), &cpl) };
    // SAFETY: as above.
    let state = unsafe { slots.staging() };
    assert_eq!((state.accepted(), state.staged(), state.strays), (1, 0, 0));
    // SAFETY: the slots' pointers live only in this test, which has finished with them.
    unsafe { slots.free() };
}

#[test]
fn every_read_and_write_carries_its_exact_byte_range_to_spdk() {
    run_case("arguments/byte-range");
}

#[test]
fn a_preflight_refusal_reaches_no_native_call() {
    run_case("arguments/preflight-refusal");
}

#[test]
fn an_enomem_refusal_returns_the_buffer_and_permits_a_retry() {
    run_case("refusal/enomem");
}

/// The planted callback: the scripted driver runs the refused read's own callback inside its refused submit, so the
/// refused command's staging record stays in the census, counted as staged where a submit that kept its refused
/// record would count it as accepted, and the census check rejects it.
#[test]
#[should_panic(expected = "a native refusal leaves the census as it was before the submit")]
fn negative_control_a_callback_inside_the_refused_submit_leaves_a_staged_record() {
    witness(&case("refusal/enomem-inline-control", || {
        refusal_with(libc::ENOMEM, true)
    }));
}

#[test]
fn an_enxio_refusal_returns_the_buffer_and_latches_the_driver_gone() {
    run_case("refusal/enxio");
}

#[test]
fn an_einval_refusal_returns_the_buffer_and_permits_a_retry() {
    run_case("refusal/einval");
}

#[test]
fn an_efault_refusal_returns_the_buffer_and_permits_a_retry() {
    run_case("refusal/efault");
}

#[test]
fn a_controller_failure_during_a_refused_submit_still_latches_gone() {
    run_case("refusal/controller-failure");
}

#[test]
fn a_queued_refused_command_is_an_invalid_contract_control() {
    run_case("refusal/queued-refused-invalid-contract");
}

#[test]
fn a_terminal_staged_inside_an_ordinary_submit_is_never_certified() {
    run_case("origin/ordinary-submit");
}

#[test]
fn a_terminal_staged_inside_an_admin_poll_is_never_certified() {
    run_case("origin/admin-poll");
}

#[test]
fn a_terminal_staged_inside_a_failed_poll_is_never_certified() {
    run_case("origin/failed-poll");
}

#[test]
fn a_terminal_staged_inside_a_poll_on_a_failed_controller_is_never_certified() {
    run_case("origin/failed-health");
}

/// The planted healthy read: the controller's failure flag reads clear after the poll that runs A's callback, so that
/// poll certifies A, as one that ignored a failed controller would, and its pick delivers A where the check expects
/// nothing.
#[test]
#[should_panic(expected = "a poll on a failed controller certifies no terminal it staged")]
fn negative_control_a_healthy_read_after_the_poll_certifies_its_terminal() {
    witness(&case("origin/healthy-read-control", || {
        origin(Outside::Health { failed: false })
    }));
}

#[test]
fn certified_terminals_drain_after_the_driver_turns_gone() {
    run_case("origin/certified-drain-while-gone");
}

#[test]
fn a_started_disable_frees_after_its_proof_and_drains_every_abort() {
    run_case("stop/disconnect-started");
}

#[test]
fn a_busy_disable_frees_after_its_proof_and_drains_every_abort() {
    run_case("stop/disconnect-busy");
}

#[test]
fn a_refused_disable_frees_after_its_proof_and_drains_every_abort() {
    run_case("stop/disconnect-refused");
}

#[test]
fn a_one_slot_sink_drains_the_aborts_one_per_call() {
    run_case("stop/one-slot-sink");
}

#[test]
fn device_held_commands_drain_in_ceil_m_over_room_calls() {
    run_case("stop/device-held-prefix");
}

#[test]
fn pending_records_in_sparse_slots_drain_in_ceil_m_over_room_calls() {
    run_case("stop/sparse-slots");
}

#[test]
fn a_duplicate_callback_for_a_staged_command_is_a_stray() {
    run_case("finality/staged-duplicate");
}

#[test]
fn a_null_completion_keeps_the_record_accepted() {
    run_case("finality/null-completion");
}

#[test]
fn a_callback_after_delivery_before_reuse_is_a_stray() {
    run_case("finality/duplicate-after-delivery");
}

#[test]
fn a_callback_after_reuse_is_an_assumption_violation_control() {
    run_case("finality/post-reuse-assumption-violation");
}

#[test]
fn a_queued_refused_command_after_reuse_is_an_invalid_contract_control() {
    run_case("finality/queued-refused-after-reuse-invalid-contract");
}

#[test]
fn a_null_callback_argument_is_inert() {
    run_case("finality/null-argument");
}
