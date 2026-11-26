//! The environment and registration on the prerequisite host: hugepages
//! reserved, root, and VFIO loaded in no-IOMMU mode on an allowlisted host.
//! An IOMMU-mode container mapping needs an attached VFIO device, so the
//! storage and transport drivers' hardware tests cover that posture. Run as root, for example
//! `sudo target/debug/deps/kestrike-<hash> --ignored native::env_tests`.
//! The log capture tests run independently of environment initialization.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use super::{
    ArenaRegistration, DeviceStopped, DmaMode, DmaPolicy, EnvConfig, EnvError, Environment,
    MempoolError, PacketMempool, Supervisor, Watchdog,
};
use crate::storage::{
    BufferArena, BufferConfig, EngineBudget, HugepageSize, LinuxPlatform, NodeMask, PoolKind,
    PoolSpec, Released,
};

struct Unreachable;

impl Supervisor for Unreachable {
    fn contain(&self) {
        panic!("teardown stalled");
    }
}

/// Eighteen 2 MiB backing pages, packet kinds included.
const POOLS: [PoolSpec; 5] = [
    PoolSpec {
        kind: PoolKind::ReadResponse,
        count: 1024,
        buffer_len: 16 << 10,
    },
    PoolSpec {
        kind: PoolKind::ReceiveWrite,
        count: 7,
        buffer_len: 2 << 20,
    },
    PoolSpec {
        kind: PoolKind::Maintenance,
        count: 256,
        buffer_len: 4 << 10,
    },
    PoolSpec {
        kind: PoolKind::PacketReceive,
        count: 192,
        buffer_len: 16 << 10,
    },
    PoolSpec {
        kind: PoolKind::PacketHeader,
        count: 256,
        buffer_len: 4 << 10,
    },
];

#[test]
#[ignore = "needs root, reserved 2 MiB hugepages and a supported VFIO posture"]
fn the_environment_registers_and_verifies_a_hugepage_arena_then_finishes_in_order() {
    // SAFETY: reads this thread's CPU.
    let core = u32::try_from(unsafe { libc::sched_getcpu() }).unwrap();
    let config = EnvConfig {
        core,
        hugepage_dir: Path::new("/dev/hugepages"),
        allowed: &[],
    };
    let env = Environment::initialize(&config).unwrap();
    assert_eq!(
        Environment::initialize(&config).unwrap_err(),
        EnvError::AlreadyInitialized
    );

    let buffers = BufferConfig {
        hugepage: HugepageSize::TwoMiB,
        nodes: NodeMask::from_nodes(&[0]).unwrap(),
        pools: &POOLS,
    };
    let buffers = buffers.validate().unwrap();
    let mut budget = EngineBudget::unlimited();
    let arena = BufferArena::initialize(&buffers, LinuxPlatform, &mut budget).unwrap();
    let arena_charge =
        buffers.backing_len() + crate::storage::device::Pools::metadata_bytes(&buffers);
    assert_eq!(budget.used(), arena_charge);
    let mut registration = ArenaRegistration::register(
        &env,
        &arena,
        DmaPolicy {
            allow_no_iommu: true,
        },
    )
    .unwrap();
    registration.map().unwrap();
    let report = registration.verify().unwrap();
    eprintln!("startup report: {report:?}");
    let witness = super::registration_tests::dma_witness(&report)
        .unwrap_or_else(|short| panic!("the registration earned no address witness: {short}"));
    let (base, extent) = registration.range();
    if report.mode == DmaMode::NoIommu {
        // Each registered IOVA is the page's physical address, which DPDK's own translation must give.
        for page in 0..extent / report.page_size {
            let va = base + page * report.page_size;
            // SAFETY: `rte_mem_virt2phy` reads this process's page map for `va` without dereferencing it, and `va` lies inside the live arena backing.
            let native = unsafe { spdk_sys::rte_mem_virt2phy(va as *const std::ffi::c_void) };
            assert_eq!(registration.iova(va, 1), Some(native), "page {page}");
        }
    }
    let first = registration
        .iova(base, 1)
        .expect("the first page translates");
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let capabilities = status
        .lines()
        .find(|line| line.starts_with("CapEff:"))
        .unwrap_or("CapEff: unread");
    let namespace = std::fs::read_link("/proc/self/ns/user")
        .map_or_else(|_| "unread".into(), |path| path.display().to_string());
    eprintln!(
        "observe: dma-witness {witness}; mapping base {base:#x} iova {first:#x} extent {extent}; {capabilities}; user namespace {namespace}"
    );
    assert!(registration.is_ready());
    assert_eq!(report.verified_pages, report.extent / report.page_size);
    assert_eq!(report.mappings, u32::from(report.mode == DmaMode::Iommu));

    for stopped in mempools(&arena, &mut registration, &mut budget) {
        registration.device_stopped(stopped).unwrap();
    }

    let watchdog = Watchdog::arm(Duration::from_secs(30), Arc::new(Unreachable)).unwrap();
    registration.unregister(&watchdog).unwrap();
    env.finish(&watchdog).unwrap();
    assert_eq!(
        Environment::initialize(&config).unwrap_err(),
        EnvError::AlreadyInitialized,
        "a finished process stays latched as initialized"
    );
    assert_eq!(arena.release().unwrap(), Released::Complete);
}

/// The packet mempools over the registered arena: each charges exactly the
/// heap bytes it allocates, a construction that fails inside DPDK frees
/// them and charges nothing, each ops name resolves when its pool is created,
/// every pool has a per-core cache of zero and single-producer, single-consumer flags, population
/// leaves every buffer free with each object at its buffer's mbuf offset and registered IOVA, a
/// served kind refuses arena acquire and post and a second pool, a native bulk allocation larger
/// than the pool fails with the arena unchanged, native frees return every posting, another
/// device's stop proof releases nothing, and release leaves every receive buffer free and the
/// header kind claimable again, while a pool dropped without release serves nothing.
/// Returns the stop proofs of the devices it leased.
fn mempools(
    arena: &BufferArena<LinuxPlatform>,
    registration: &mut ArenaRegistration<'_>,
    budget: &mut EngineBudget,
) -> [DeviceStopped; 3] {
    let (nic, other, later) = (
        registration.device_attached(),
        registration.device_attached(),
        registration.device_attached(),
    );
    let registration = &*registration;
    // The endpoint's memory charges its request table to the composition's
    // budget and holds the receive view the receive pool borrows.
    let start = budget.used();
    let endpoint = crate::net::EndpointConfig {
        peers: 1,
        request_slots: 8,
        peer_requests: 8,
        receive_reserve: 8,
        batch: 8,
    }
    .validate::<u64>(arena.config())
    .unwrap();
    let memory = endpoint.initialize(arena, budget).unwrap();
    let view = &memory.receive;
    let (receive, charged, allocated) = crate::instrument::charged(budget, |budget| {
        PacketMempool::receive(view, registration, &nic, c"ks-test-rx", budget)
    });
    let receive = receive.unwrap();
    let state = PacketMempool::ARENA_CHARGE;
    assert_eq!((charged, allocated), (state, state), "the boxed ops state");
    assert_eq!(
        PacketMempool::receive(
            view,
            registration,
            &nic,
            c"ks-test-rx2",
            &mut EngineBudget::unlimited()
        )
        .err(),
        Some(MempoolError::Kind),
        "one receive pool serves the kind"
    );
    assert!(
        arena.acquire(PoolKind::PacketReceive).is_err()
            && arena.post(PoolKind::PacketReceive).is_err()
    );
    assert!(
        view.post().is_err() && view.acquire(crate::net::PacketUse::Control).is_err(),
        "the pool alone hands out its buffers"
    );
    let (header, charged, allocated) = crate::instrument::charged(budget, |budget| {
        PacketMempool::header(arena, registration, &nic, c"ks-test-hdr", budget)
    });
    let header = header.unwrap();
    assert_eq!((charged, allocated), (state, state), "the boxed ops state");
    assert_eq!(
        PacketMempool::header(
            arena,
            registration,
            &nic,
            c"ks-test-hdr2",
            &mut EngineBudget::unlimited()
        )
        .err(),
        Some(MempoolError::Kind),
        "one header pool holds the kind"
    );
    assert!(arena.acquire(PoolKind::PacketHeader).is_err());
    let (payload, charged, allocated) = crate::instrument::charged(budget, |budget| {
        PacketMempool::payload(arena, registration, &nic, c"ks-test-pay", 64, budget)
    });
    let payload = payload.unwrap();
    assert_eq!(charged, allocated, "the charge is the bytes allocated");
    assert_eq!(Some(charged), PacketMempool::payload_charge(64));
    assert_eq!(
        budget.used() - start,
        endpoint.charge() + 2 * PacketMempool::ARENA_CHARGE + charged,
        "the composition charges each part once, descriptor memory in the payload pool alone"
    );
    // A second pool of one name fails inside DPDK after its state and
    // descriptors were allocated; it frees them and charges nothing.
    let (used, freed, bytes) = (
        budget.used(),
        crate::instrument::deallocated_bytes(),
        crate::instrument::allocated_bytes(),
    );
    assert!(matches!(
        PacketMempool::payload(arena, registration, &nic, c"ks-test-pay", 64, budget),
        Err(MempoolError::Native(_))
    ));
    assert_eq!(budget.used(), used, "a failed construction charges nothing");
    assert_eq!(
        crate::instrument::deallocated_bytes() - freed,
        crate::instrument::allocated_bytes() - bytes,
        "and frees what it allocated"
    );
    for pool in [&receive, &header, &payload] {
        let (flags, cache) = pool.native_shape();
        let spsc = spdk_sys::RTE_MEMPOOL_F_SP_PUT | spdk_sys::RTE_MEMPOOL_F_SC_GET;
        assert_eq!((flags & spsc, cache), (spsc, 0));
        assert!(pool.armed());
    }
    assert_eq!(
        arena.report(PoolKind::PacketReceive).free,
        192,
        "population posted nothing"
    );
    let mut mbufs = [std::ptr::null_mut(); 193];
    // SAFETY: `mbufs` has room for every requested mbuf.
    let refused = unsafe {
        spdk_sys::spdk_sys_rte_pktmbuf_alloc_bulk(receive.as_ptr(), mbufs.as_mut_ptr(), 193)
    };
    assert_eq!(refused, -libc::ENOBUFS);
    assert_eq!(receive.report().refused, 1);
    assert_eq!(
        arena.report(PoolKind::PacketReceive).posted,
        0,
        "a short bulk allocation posts nothing"
    );
    // SAFETY: as above.
    let rc = unsafe {
        spdk_sys::spdk_sys_rte_pktmbuf_alloc_bulk(receive.as_ptr(), mbufs.as_mut_ptr(), 4)
    };
    assert_eq!(rc, 0);
    assert_eq!(arena.report(PoolKind::PacketReceive).posted, 4);
    for mbuf in &mbufs[..4] {
        // SAFETY: each mbuf came from the allocation above and is freed once, unwritten.
        unsafe { spdk_sys::spdk_sys_rte_pktmbuf_free(*mbuf) };
    }
    assert_eq!(
        arena.report(PoolKind::PacketReceive).free,
        192,
        "native frees reach the ops"
    );
    assert_eq!(receive.report().returned, 4);
    let (receive, other) = receive.release(other.stopped()).unwrap_err();
    assert!(
        receive.armed() && arena.post(PoolKind::PacketReceive).is_err(),
        "another device's stop proof leaves the pool serving"
    );
    let stopped = released(payload, released(header, released(receive, nic.stopped())));
    let report = arena.report(PoolKind::PacketReceive);
    assert_eq!(
        (report.posted, report.free),
        (0, 192),
        "the native free's drain posted nothing"
    );
    let dropped = PacketMempool::payload(
        arena,
        registration,
        &later,
        c"ks-test-pay2",
        4,
        &mut EngineBudget::unlimited(),
    )
    .unwrap();
    // A header pool named as a live pool fails inside DPDK after its claims
    // and its state; it ends both claims, frees the state and charges
    // nothing, so the next header pool claims the kind again.
    let (used, freed, bytes) = (
        budget.used(),
        crate::instrument::deallocated_bytes(),
        crate::instrument::allocated_bytes(),
    );
    assert!(matches!(
        PacketMempool::header(arena, registration, &later, c"ks-test-pay2", budget),
        Err(MempoolError::Native(_))
    ));
    assert_eq!(budget.used(), used, "a failed construction charges nothing");
    assert_eq!(
        crate::instrument::deallocated_bytes() - freed,
        crate::instrument::allocated_bytes() - bytes,
        "and frees what it allocated"
    );
    // An exact budget holds the next header pool, which claims the kind again.
    let mut exact = EngineBudget::new(PacketMempool::ARENA_CHARGE);
    let again =
        PacketMempool::header(arena, registration, &later, c"ks-test-hdr3", &mut exact).unwrap();
    assert_eq!(exact.used(), PacketMempool::ARENA_CHARGE);
    let later = released(again, later.stopped());
    let native = dropped.as_ptr();
    drop(dropped);
    let mut one = [std::ptr::null_mut(); 1];
    // SAFETY: the dropped pool stays allocated; its ops answer from a detached state.
    let rc = unsafe { spdk_sys::spdk_sys_rte_pktmbuf_alloc_bulk(native, one.as_mut_ptr(), 1) };
    assert_eq!(
        rc,
        -libc::ENOBUFS,
        "a pool dropped without release serves nothing"
    );
    drop(memory);
    [stopped, other, later]
}

/// Releases `pool` with the stop proof of the device it serves and returns the proof.
fn released(pool: PacketMempool<'_>, stopped: DeviceStopped) -> DeviceStopped {
    pool.release(stopped)
        .ok()
        .expect("the serving device's stop proof releases its pool")
}

/// Capture returns its closure's result and exactly what was written to DPDK's log stream meanwhile, then points the log back at standard error, on unwind as well; a later capture holds only its own writes.
#[test]
fn capture_collects_the_log_and_restores_it() {
    use spdk_sys as sys;
    let (out, log) = super::env::capture(|| {
        // SAFETY: the log stream is the capture's open memory stream.
        unsafe { libc::fputs(c"probe line\n".as_ptr(), sys::rte_log_get_stream().cast()) };
        7
    });
    assert_eq!((out, log.as_str()), (7, "probe line\n"));
    // SAFETY: reads DPDK's current log stream and the C library's standard error.
    let restored = || unsafe { sys::rte_log_get_stream().cast::<libc::FILE>() == stderr() };
    assert!(restored());
    let unwound = std::panic::catch_unwind(|| super::env::capture(|| panic!("inside capture")));
    assert!(unwound.is_err());
    assert!(restored());
    let ((), again) = super::env::capture(|| {
        // SAFETY: the log stream is the capture's open memory stream.
        unsafe { libc::fputs(c"next\n".as_ptr(), sys::rte_log_get_stream().cast()) };
    });
    assert_eq!(again, "next\n", "each capture holds only its own writes");
}

/// The C library's standard error stream.
unsafe fn stderr() -> *mut libc::FILE {
    unsafe extern "C" {
        static mut stderr: *mut libc::FILE;
    }
    // SAFETY: the C library initializes `stderr` before main.
    unsafe { stderr }
}

/// The capture lifetime test's ID, which it runs in a fresh child so its
/// late writer reaches no other test's capture.
const SPANS: &str = "native::env_tests::a_saved_capture_stream_outlives_restore_and_later_captures";

/// A writer that saved the capture stream writes across the first
/// capture's flush and copy, its restore, a later capture and an unwound
/// one, after a large write inside the first capture moved the stream's
/// buffer. The stream and its cell stay alive throughout: under address
/// sanitizer, each capture's instrumented read of the cell and copy of the
/// buffer is checked. Exact bytes are asserted for the first capture's own
/// writes, which precede the late writer. The late write witnessed inside
/// the second capture's window lands in that capture, other late lines
/// land in any capture or none, and every line a capture holds besides its
/// own is a whole late line.
#[test]
fn a_saved_capture_stream_outlives_restore_and_later_captures() {
    crate::exact_child::run(
        SPANS,
        std::time::Duration::from_secs(120),
        saved_stream_spans_captures,
    );
}

fn saved_stream_spans_captures() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use spdk_sys as sys;
    let own = "own line\n";
    let large = format!("{}\n", "x".repeat(64 * 1024));
    let large_line = std::ffi::CString::new(large.clone()).unwrap();
    let (stop, written) = (AtomicBool::new(false), AtomicUsize::new(0));
    // Waits for two more completed late writes, the second of which began
    // after this call: at most one write is in flight when it starts.
    let late_write = || {
        let from = written.load(Ordering::Acquire);
        while written.load(Ordering::Acquire) < from + 2 {
            std::thread::yield_now();
        }
    };
    let assert_only_late_besides = |log: &str, own_lines: &[&str]| {
        let mut own_lines = own_lines.to_vec();
        for line in log.lines() {
            if let Some(at) = own_lines.iter().position(|own| *own == line) {
                own_lines.remove(at);
            } else {
                assert_eq!(line, "late", "a capture held a torn or foreign line");
            }
        }
        assert!(
            own_lines.is_empty(),
            "a capture lost its own lines: {own_lines:?}"
        );
    };
    let before = super::env::capture_buffer().expect("the capture stream opened");
    assert!(!before.is_null(), "the stream published its first buffer");
    /// Stops the late writer when the scope ends, an assertion's unwind
    /// included, so the scope's join returns.
    struct Stop<'a>(&'a AtomicBool);
    impl Drop for Stop<'_> {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }
    std::thread::scope(|scope| {
        let _stop = Stop(&stop);
        let ((), first) = super::env::capture(|| {
            // SAFETY: the log stream is the capture's open memory stream.
            let stream = unsafe { sys::rte_log_get_stream() } as usize;
            // SAFETY: as above.
            unsafe {
                libc::fputs(c"own line\n".as_ptr(), stream as *mut libc::FILE);
                libc::fputs(large_line.as_ptr(), stream as *mut libc::FILE);
            }
            let (stop, written) = (&stop, &written);
            scope.spawn(move || {
                // The saved stream: DPDK's log stream as this capture set it.
                let stream = stream as *mut libc::FILE;
                while !stop.load(Ordering::Acquire) {
                    // SAFETY: the capture stream stays open for the process, so a saved writer may write after a restore.
                    unsafe { libc::fputs(c"late\n".as_ptr(), stream) };
                    written.fetch_add(1, Ordering::AcqRel);
                    std::thread::yield_now();
                }
            });
        });
        assert!(
            first.starts_with(&format!("{own}{large}")),
            "the first capture opens with its own writes"
        );
        assert_only_late_besides(&first[own.len() + large.len()..], &[]);
        // SAFETY: reads DPDK's current log stream and the C library's standard error.
        let restored = || unsafe { sys::rte_log_get_stream().cast::<libc::FILE>() == stderr() };
        assert!(restored(), "the first capture restored the log");
        // A late write that began after the restore.
        late_write();
        // glibc's memory stream grows into a new allocation, so the large
        // write left the first buffer.
        assert_ne!(
            super::env::capture_buffer().unwrap(),
            before,
            "the large write moved the stream's buffer"
        );
        let ((), second) = super::env::capture(|| {
            // SAFETY: the log stream is the capture's open memory stream.
            unsafe { libc::fputs(c"second\n".as_ptr(), sys::rte_log_get_stream().cast()) };
            // A late write inside the second capture's window.
            late_write();
        });
        assert_only_late_besides(&second, &["second"]);
        // The late write witnessed inside the window completed under the
        // stream's lock before the flush, so the capture holds it.
        assert!(
            second.lines().any(|line| line == "late"),
            "the second capture missed its witnessed late write"
        );
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            super::env::capture(|| {
                // A late write inside the unwound capture's window.
                late_write();
                panic!("inside capture")
            })
        }));
        assert!(
            unwound.is_err() && restored(),
            "the unwound capture restored the log"
        );
        late_write();
    });
}

/// Control: a capture after its cell was released reads freed memory,
/// which address sanitizer reports at the capture's read of the cell and
/// aborts on. The test runs that capture in a fresh child and requires the
/// report's access stack, up to the line locating the address in its chunk,
/// to name `capture`.
#[cfg(kestrike_asan)]
#[test]
fn a_released_capture_cell_is_reported_as_a_use_after_free() {
    use spdk_sys as sys;

    use crate::exact_child::{ExactChild, Outcome};
    const ID: &str = "native::env_tests::a_released_capture_cell_is_reported_as_a_use_after_free";
    if crate::exact_child::is_child(ID) {
        let _ = super::env::capture(|| ());
        // SAFETY: deliberately violated: the cell is freed while the stream still names it.
        unsafe { super::env::release_capture_cell() };
        let ((), log) = super::env::capture(|| {
            // SAFETY: the log stream is the capture's open memory stream.
            unsafe {
                libc::fputs(
                    c"after release\n".as_ptr(),
                    sys::rte_log_get_stream().cast(),
                )
            };
        });
        eprintln!("escaped the sanitizer with {} bytes", log.len());
        return;
    }
    let outcome = ExactChild::spawn(ID, &[])
        .unwrap()
        .finish(std::time::Instant::now() + std::time::Duration::from_secs(120));
    let (Outcome::Failed { stderr, .. } | Outcome::Crashed { stderr, .. }) = outcome else {
        panic!("the child ran past the release: {outcome:?}");
    };
    let stderr = stderr.join("\n");
    assert!(
        stderr.contains("AddressSanitizer") && stderr.contains("heap-use-after-free"),
        "the report names a heap use after free:\n{stderr}"
    );
    let access = stderr
        .split_once(" of size ")
        .and_then(|(_, rest)| rest.split_once(" is located "))
        .map(|(access, _)| access)
        .unwrap_or_else(|| panic!("the report holds an access stack:\n{stderr}"));
    assert!(
        access
            .match_indices("env::capture")
            .any(|(at, name)| !access[at + name.len()..].starts_with('d')),
        "the access stack names capture:\n{stderr}"
    );
    assert!(
        !stderr.contains("escaped the sanitizer"),
        "the copy was reported before its bytes were used"
    );
}
