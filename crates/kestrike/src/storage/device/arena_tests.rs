//! Tests verify arena bring-up, rollback, and release through the recording
//! platform's call log. Heap-backed tests run the production sequence over
//! zeroed, hugepage-aligned heap memory; the ignored native tests need a host
//! with reserved hugepages and run only with `--ignored hugepage`.

use super::super::init::{InitError, InitPhase};
use super::super::ledger::{EngineBudget, EngineBudgetExceeded};
use super::super::mapping::{Region, RetainedMapping};
use super::super::os::{HugepageSize, LinuxPlatform, OsCode, Platform};
use super::super::placement::{NodeMask, PlacementError};
use super::super::test_platform::{Call, Fail, Log, Op, TestPlatform};
use super::{ArenaFailure, BufferArena, BufferConfig, PoolKind, PoolSpec, Released};

const MIB: usize = 1 << 20;
const TWO_MIB: usize = 2 * MIB;
const BASE_PAGE: usize = 4096;

/// 1 MiB + 1 MiB + 4 KiB of buffers: two 2 MiB backing pages, the second
/// holding one buffer unit and a tail of 2 MiB less 4 KiB.
const POOLS: [PoolSpec; 3] = [
    PoolSpec {
        kind: PoolKind::ReadResponse,
        count: 256,
        buffer_len: 4096,
    },
    PoolSpec {
        kind: PoolKind::ReceiveWrite,
        count: 1,
        buffer_len: 1 << 20,
    },
    PoolSpec {
        kind: PoolKind::Maintenance,
        count: 1,
        buffer_len: 4096,
    },
];
const BACKING: usize = 2 * TWO_MIB;
/// Pool metadata for the fixture's 258 buffers: a 16-byte record and a 4-byte free-stack entry each.
const METADATA: usize = 258 * 20;
/// Everything initialization charges for the fixture.
const CHARGE: usize = BACKING + METADATA;

fn node_mask(nodes: &[usize]) -> NodeMask {
    NodeMask::from_nodes(nodes).unwrap()
}

fn config(nodes: NodeMask) -> BufferConfig<'static> {
    BufferConfig {
        hugepage: HugepageSize::TwoMiB,
        nodes,
        pools: &POOLS,
    }
}

fn heap() -> (TestPlatform, Log) {
    let platform = TestPlatform::heap(BASE_PAGE);
    let log = platform.log();
    (platform, log)
}

/// A budget that already carries an unrelated charge, so a test can tell a
/// written budget from a replaced one.
fn budget(headroom: usize) -> EngineBudget {
    let mut budget = EngineBudget::new(1000 + headroom);
    budget.charge(1000).unwrap();
    budget
}

fn call(op: Op, base: usize, len: usize) -> Call {
    Call { op, base, len }
}

/// The complete successful bring-up of a `backing`-byte arena at `base` on a
/// platform whose base page is `base_page` bytes.
fn bring_up_log(base: usize, backing: usize, base_page: usize) -> Vec<Call> {
    let mut calls = vec![
        call(Op::PageSize, 0, 0),
        call(Op::Topology, 0, 0),
        call(Op::MapHuge(HugepageSize::TwoMiB), base, backing),
        call(Op::Bind, base, backing),
        call(Op::Protect, base, backing),
    ];
    for page in 0..backing / TWO_MIB {
        let start = base + page * TWO_MIB;
        calls.extend([
            call(Op::Populate, start, TWO_MIB),
            call(Op::Residency, start, base_page),
            call(Op::CheckBound, start, TWO_MIB),
        ]);
    }
    calls
}

fn mapped_base(log: &Log) -> usize {
    let mapped = log.mapped();
    assert_eq!(mapped.len(), 1, "{:?}", log.all());
    mapped[0].0
}

#[test]
fn heap_initialization_logs_the_hugepage_sequence_and_charges_the_backing() {
    for base_page in [BASE_PAGE, 64 * 1024] {
        let platform = TestPlatform::heap(base_page);
        let log = platform.log();
        let validated = config(node_mask(&[0])).validate().unwrap();
        let mut budget = budget(CHARGE);
        let arena = BufferArena::initialize(&validated, platform, &mut budget).unwrap();
        let base = mapped_base(&log);
        assert_eq!(
            log.all(),
            bring_up_log(base, BACKING, base_page),
            "base page {base_page}"
        );
        assert!(log.calls(Op::AdviseHuge).is_empty());
        assert!(log.calls(Op::AdviseNormal).is_empty());
        assert_eq!(budget.used(), 1000 + CHARGE);
        assert_eq!(budget.limit(), 1000 + CHARGE);
        assert_eq!(validated.charge(), CHARGE, "the charge query");

        let placement = arena.placement();
        assert_eq!(placement.nodes, node_mask(&[0]));
        assert_eq!(placement.pages_verified, 2);
        let backing = arena.backing();
        assert_eq!(backing.base().as_ptr().addr(), base);
        assert_eq!(backing.extent(), BACKING);
        assert_eq!(backing.hugepage(), HugepageSize::TwoMiB);
        assert_eq!(arena.config(), &validated);

        assert_eq!(arena.release().unwrap(), Released::Complete);
        assert_eq!(log.ranges(Op::Unmap), [(base, BACKING)]);
        assert_eq!(
            log.all().len(),
            bring_up_log(base, BACKING, base_page).len() + 1
        );
    }
}

/// Every byte of the backing reads as zero after bring-up, and a pattern
/// written at the first and last byte of each backing page reads back.
#[test]
fn heap_backing_is_zeroed_and_writable_end_to_end() {
    let (platform, _log) = heap();
    let validated = config(node_mask(&[0])).validate().unwrap();
    let arena =
        BufferArena::initialize(&validated, platform, &mut EngineBudget::new(CHARGE)).unwrap();
    let base = arena.backing().base();
    // SAFETY: the arena owns the populated, writable backing and no other
    // path touches it during this test; the slice ends before the writes.
    unsafe {
        let bytes = std::slice::from_raw_parts(base.as_ptr(), BACKING);
        assert!(bytes.iter().all(|byte| *byte == 0));
        for page in 0..BACKING / TWO_MIB {
            for offset in [page * TWO_MIB, (page + 1) * TWO_MIB - 1] {
                base.add(offset).write(0xA5);
                assert_eq!(base.add(offset).read(), 0xA5);
            }
        }
    }
    assert_eq!(arena.release().unwrap(), Released::Complete);
}

#[test]
fn refusals_before_mapping_touch_neither_the_kernel_nor_the_budget() {
    let validated = |nodes: &[usize]| config(node_mask(nodes)).validate().unwrap();
    let cases = [
        (
            validated(&[0, 4]),
            CHARGE,
            InitError::Placement(PlacementError::NodeDoesNotExist {
                region: Region::Buffers,
                node: 4,
            }),
        ),
        (
            validated(&[3]),
            CHARGE,
            InitError::Placement(PlacementError::NodeWithoutMemory {
                region: Region::Buffers,
                node: 3,
            }),
        ),
        (
            validated(&[0, 2, 3]),
            CHARGE,
            InitError::Placement(PlacementError::NodeNotAllowed {
                region: Region::Buffers,
                node: 2,
            }),
        ),
        (
            validated(&[0]),
            BACKING - 1,
            InitError::Envelope(EngineBudgetExceeded {
                limit: 1000 + BACKING - 1,
                used: 1000,
                requested: BACKING,
            }),
        ),
        (
            validated(&[0]),
            CHARGE - 1,
            InitError::Envelope(EngineBudgetExceeded {
                limit: 1000 + CHARGE - 1,
                used: 1000 + BACKING,
                requested: METADATA,
            }),
        ),
    ];
    for (validated, headroom, expected) in cases {
        let (platform, log) = heap();
        let mut budget = budget(headroom);
        let before = budget;
        let failure = BufferArena::initialize(&validated, platform, &mut budget).unwrap_err();
        assert_eq!(
            failure,
            ArenaFailure {
                error: expected,
                retained: None
            }
        );
        assert_eq!(budget, before);
        assert_eq!(
            log.all(),
            [call(Op::PageSize, 0, 0), call(Op::Topology, 0, 0)]
        );
    }

    for (op, expected) in [
        (Op::PageSize, InitError::PageSizeUnavailable(OsCode(7))),
        (Op::Topology, InitError::TopologyUnavailable(OsCode(7))),
    ] {
        let (platform, log) = heap();
        platform.fail_at(Fail {
            op,
            ordinal: 1,
            code: OsCode(7),
            region: None,
        });
        let mut budget = budget(CHARGE);
        let before = budget;
        let failure = BufferArena::initialize(&validated(&[0]), platform, &mut budget).unwrap_err();
        assert_eq!(failure.error, expected);
        assert_eq!(failure.retained, None);
        assert_eq!(budget, before);
        assert!(log.mapped().is_empty());
        assert_eq!(log.all().last().unwrap().op, op);
    }
}

/// A failure injected at every kernel call of bring-up, in both backing
/// pages: the mapping is released once at its base and full extent right
/// after the failing call, nothing else runs, and the budget is untouched.
/// A failed map releases nothing.
#[test]
fn a_failure_at_every_phase_releases_the_mapping_once() {
    let cases = [
        (Op::MapHuge(HugepageSize::TwoMiB), 1, InitPhase::Map),
        (Op::Bind, 1, InitPhase::Placement),
        (Op::Protect, 1, InitPhase::Protect),
        (Op::Populate, 1, InitPhase::Populate),
        (Op::Residency, 1, InitPhase::VerifyPopulation),
        (Op::CheckBound, 1, InitPhase::VerifyPlacement),
        (Op::Populate, 2, InitPhase::Populate),
        (Op::Residency, 2, InitPhase::VerifyPopulation),
        (Op::CheckBound, 2, InitPhase::VerifyPlacement),
    ];
    for (op, ordinal, phase) in cases {
        let (platform, log) = heap();
        platform.fail_at(Fail {
            op,
            ordinal,
            code: OsCode(90),
            region: None,
        });
        let validated = config(node_mask(&[0])).validate().unwrap();
        let mut budget = budget(CHARGE);
        let before = budget;
        let failure = BufferArena::initialize(&validated, platform, &mut budget).unwrap_err();
        assert_eq!(
            failure,
            ArenaFailure {
                error: InitError::Os {
                    phase,
                    region: Region::Buffers,
                    code: OsCode(90),
                },
                retained: None,
            },
            "{op:?} #{ordinal}"
        );
        assert_eq!(budget, before);
        let all = log.all();
        let failed_at = all
            .iter()
            .enumerate()
            .filter(|(_, c)| c.op == op)
            .nth(ordinal - 1)
            .unwrap()
            .0;
        if phase == InitPhase::Map {
            assert_eq!(all.len(), failed_at + 1);
            assert!(log.mapped().is_empty());
        } else {
            let base = mapped_base(&log);
            assert_eq!(
                all[..failed_at + 1],
                bring_up_log(base, BACKING, BASE_PAGE)[..failed_at + 1]
            );
            assert_eq!(all[failed_at + 1..], [call(Op::Unmap, base, BACKING)]);
        }
    }
}

/// Defects found by verification name the backing page, counted from the
/// base, and end bring-up at that page: its failing call, then one release,
/// with the caller's budget untouched.
#[test]
fn verification_defects_name_the_backing_page_and_roll_back() {
    enum Defect {
        Unpopulated,
        WrongNode,
        StatusError,
    }
    for page in 0..2 {
        for defect in [Defect::Unpopulated, Defect::WrongNode, Defect::StatusError] {
            let (platform, log) = heap();
            let mut answers = vec![0, 0];
            let mut resident = vec![1, 1];
            let expected = match defect {
                Defect::Unpopulated => {
                    resident[page] = 0;
                    InitError::Unpopulated {
                        region: Region::Buffers,
                        page,
                    }
                }
                Defect::WrongNode => {
                    answers[page] = 1;
                    InitError::WrongNode {
                        region: Region::Buffers,
                        page,
                        node: 1,
                    }
                }
                Defect::StatusError => {
                    answers[page] = -5;
                    InitError::PageStatusError {
                        region: Region::Buffers,
                        page,
                        code: OsCode(5),
                    }
                }
            };
            platform.fake_residency(resident);
            platform.fake_page_nodes(answers);
            let validated = config(node_mask(&[0])).validate().unwrap();
            let mut budget = budget(CHARGE);
            let before = budget;
            let failure = BufferArena::initialize(&validated, platform, &mut budget).unwrap_err();
            assert_eq!(failure.error, expected);
            assert_eq!(failure.retained, None);
            assert_eq!(budget, before);
            let base = mapped_base(&log);
            let start = base + page * TWO_MIB;
            let mut calls = bring_up_log(base, BACKING, BASE_PAGE);
            // The page's populate and residency calls, then its bound check
            // and one node query in its own unit when placement is at fault.
            calls.truncate(5 + 3 * page + 2);
            if !matches!(defect, Defect::Unpopulated) {
                calls.push(call(Op::CheckBound, start, TWO_MIB));
                calls.push(call(Op::PageNode, start, TWO_MIB));
            }
            calls.push(call(Op::Unmap, base, BACKING));
            assert_eq!(log.all(), calls, "page {page}");
        }
    }
}

/// A refused range check makes one node query per backing page it covers,
/// not one per base page; clean answers let bring-up continue.
#[test]
fn a_refused_range_check_queries_once_per_backing_page() {
    let (platform, log) = heap();
    platform.fail_at(Fail {
        op: Op::CheckBound,
        ordinal: 1,
        code: OsCode(libc::EIO),
        region: None,
    });
    let validated = config(node_mask(&[0])).validate().unwrap();
    let arena =
        BufferArena::initialize(&validated, platform, &mut EngineBudget::new(CHARGE)).unwrap();
    let base = mapped_base(&log);
    assert_eq!(log.calls(Op::PageNode), [call(Op::PageNode, base, TWO_MIB)]);
    assert_eq!(arena.placement().pages_verified, 2);
    assert_eq!(arena.release().unwrap(), Released::Complete);
}

/// Bind and every bound check receive exactly the validated mask, and every
/// residency query receives exactly one status byte.
#[test]
fn every_check_uses_the_bound_mask_and_one_status_byte() {
    let (platform, log) = heap();
    platform.fake_page_nodes(vec![1, 1]);
    let validated = config(node_mask(&[1])).validate().unwrap();
    let arena =
        BufferArena::initialize(&validated, platform, &mut EngineBudget::new(CHARGE)).unwrap();
    assert_eq!(
        log.masks(),
        [
            (Op::Bind, node_mask(&[1])),
            (Op::CheckBound, node_mask(&[1])),
            (Op::CheckBound, node_mask(&[1])),
        ]
    );
    assert_eq!(log.status_lens(), [1, 1]);
    assert_eq!(arena.placement().nodes, node_mask(&[1]));
    assert_eq!(arena.release().unwrap(), Released::Complete);
}

#[test]
fn a_misaligned_base_fails_after_mapping_and_releases_once() {
    let (platform, log) = heap();
    platform.misalign_hugepages();
    let validated = config(node_mask(&[0])).validate().unwrap();
    let mut budget = budget(CHARGE);
    let before = budget;
    let failure = BufferArena::initialize(&validated, platform, &mut budget).unwrap_err();
    let base = mapped_base(&log);
    assert_eq!(base % TWO_MIB, BASE_PAGE);
    assert_eq!(
        failure,
        ArenaFailure {
            error: InitError::MisalignedBase {
                region: Region::Buffers,
                base,
                align: TWO_MIB,
            },
            retained: None,
        }
    );
    assert_eq!(budget, before);
    let calls: Vec<Op> = log.all().iter().map(|c| c.op).collect();
    assert_eq!(
        calls,
        [
            Op::PageSize,
            Op::Topology,
            Op::MapHuge(HugepageSize::TwoMiB),
            Op::Unmap
        ]
    );
    assert_eq!(log.ranges(Op::Unmap), [(base, BACKING)]);
}

/// A rollback the kernel refuses is reported with the region, base, length
/// and code it saw, is never retried, and leaves the backing charged to the
/// caller.
#[test]
fn a_refused_rollback_is_retained_and_charged() {
    let (platform, log) = heap();
    for (op, code) in [(Op::Populate, OsCode(90)), (Op::Unmap, OsCode(91))] {
        platform.fail_at(Fail {
            op,
            ordinal: 1,
            code,
            region: None,
        });
    }
    let validated = config(node_mask(&[0])).validate().unwrap();
    let mut budget = budget(CHARGE);
    let failure = BufferArena::initialize(&validated, platform, &mut budget).unwrap_err();
    let base = mapped_base(&log);
    assert_eq!(
        failure,
        ArenaFailure {
            error: InitError::Os {
                phase: InitPhase::Populate,
                region: Region::Buffers,
                code: OsCode(90),
            },
            retained: Some(RetainedMapping {
                region: Region::Buffers,
                base,
                len: BACKING,
                code: OsCode(91),
            }),
        }
    );
    assert_eq!(budget.used(), 1000 + BACKING);
    assert_eq!(log.ranges(Op::Unmap), [(base, BACKING)]);
    assert!(log.calls(Op::Residency).is_empty());
}

#[test]
fn a_refused_release_is_reported_retained() {
    let (platform, log) = heap();
    platform.fail_at(Fail {
        op: Op::Unmap,
        ordinal: 1,
        code: OsCode(92),
        region: None,
    });
    let validated = config(node_mask(&[0])).validate().unwrap();
    let mut budget = budget(CHARGE);
    let arena = BufferArena::initialize(&validated, platform, &mut budget).unwrap();
    let base = mapped_base(&log);
    assert_eq!(
        arena.release().unwrap(),
        Released::Retained(RetainedMapping {
            region: Region::Buffers,
            base,
            len: BACKING,
            code: OsCode(92),
        })
    );
    assert_eq!(log.ranges(Op::Unmap), [(base, BACKING)]);
    assert_eq!(budget.used(), 1000 + CHARGE);
}

#[test]
fn release_refuses_while_a_device_mempool_serves_a_kind() {
    let (platform, log) = heap();
    let validated = config(node_mask(&[0])).validate().unwrap();
    let arena = BufferArena::initialize(&validated, platform, &mut budget(CHARGE)).unwrap();
    assert!(arena.pools().pool(PoolKind::Maintenance).claim_served());
    let blocked = arena.release().unwrap_err();
    assert_eq!(
        blocked.served,
        [
            (PoolKind::ReadResponse, false),
            (PoolKind::ReceiveWrite, false),
            (PoolKind::Maintenance, true),
            (PoolKind::PacketReceive, false),
            (PoolKind::PacketHeader, false),
            (PoolKind::Reservation, false)
        ]
    );
    assert!(blocked.held.iter().all(|(_, count)| *count == 0));
    assert!(log.calls(Op::Unmap).is_empty(), "nothing was unmapped");
    let arena = blocked.arena;
    arena.pools().pool(PoolKind::Maintenance).end_served();
    assert_eq!(arena.release().unwrap(), Released::Complete);
}

#[test]
fn dropping_an_unreleased_arena_unmaps_nothing() {
    let (platform, log) = heap();
    let validated = config(node_mask(&[0])).validate().unwrap();
    let arena =
        BufferArena::initialize(&validated, platform, &mut EngineBudget::new(CHARGE)).unwrap();
    drop(arena);
    assert!(log.calls(Op::Unmap).is_empty());
}

/// A 1 GiB configuration maps with its own size and refuses typed; the heap
/// backing never allocates a gigabyte for it.
#[test]
fn a_one_gib_arena_requests_its_page_size_and_refuses_typed() {
    let (platform, log) = heap();
    let one_gib = Op::MapHuge(HugepageSize::OneGiB);
    platform.fail_at(Fail {
        op: one_gib,
        ordinal: 1,
        code: OsCode(libc::EINVAL),
        region: None,
    });
    let validated = BufferConfig {
        hugepage: HugepageSize::OneGiB,
        ..config(node_mask(&[0]))
    }
    .validate()
    .unwrap();
    let mut budget = budget((1 << 30) + METADATA);
    let failure = BufferArena::initialize(&validated, platform, &mut budget).unwrap_err();
    assert_eq!(
        failure.error,
        InitError::Os {
            phase: InitPhase::Map,
            region: Region::Buffers,
            code: OsCode(libc::EINVAL),
        }
    );
    assert_eq!(log.calls(one_gib), [call(one_gib, 0, 1 << 30)]);
    assert!(log.calls(Op::Unmap).is_empty());
    assert_eq!(budget.used(), 1000);
}

/// Host facts for the 2 MiB hugepage pool, read from sysfs and printed so
/// every native run records the host it had.
#[derive(Debug)]
struct HugepageHost {
    kernel: String,
    total: usize,
    free: usize,
    overcommit: usize,
    free_by_node: Vec<(usize, usize)>,
    /// Whether the kernel supports 1 GiB hugepages at all, and if so the
    /// size of its persistent pool.
    one_gib_pool: Option<usize>,
}

const ONE_GIB_POOL: &str = "/sys/kernel/mm/hugepages/hugepages-1048576kB";

/// Native tests share the host's hugepage pools, so one test's reservation
/// would change another's preconditions; each holds this for its whole run.
static NATIVE: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn read_count(path: &str) -> Option<usize> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// Takes the native-test lock, then samples the host.
fn hugepage_host() -> (std::sync::MutexGuard<'static, ()>, HugepageHost) {
    let guard = NATIVE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let pool = "/sys/kernel/mm/hugepages/hugepages-2048kB";
    let allowed = LinuxPlatform.topology().unwrap().allowed;
    let free_by_node = allowed
        .nodes()
        .map(|node| {
            let path = format!(
                "/sys/devices/system/node/node{node}/hugepages/hugepages-2048kB/free_hugepages"
            );
            (node, read_count(&path).unwrap_or(0))
        })
        .collect();
    // SAFETY: `uname` fills the struct it is given and reads nothing else.
    let kernel = unsafe {
        let mut name: libc::utsname = std::mem::zeroed();
        assert_eq!(libc::uname(&mut name), 0);
        std::ffi::CStr::from_ptr(name.release.as_ptr())
            .to_string_lossy()
            .into_owned()
    };
    let host = HugepageHost {
        kernel,
        total: read_count(&format!("{pool}/nr_hugepages")).unwrap_or(0),
        free: read_count(&format!("{pool}/free_hugepages")).unwrap_or(0),
        overcommit: read_count(&format!("{pool}/nr_overcommit_hugepages")).unwrap_or(0),
        free_by_node,
        one_gib_pool: std::fs::exists(ONE_GIB_POOL)
            .unwrap()
            .then(|| read_count(&format!("{ONE_GIB_POOL}/nr_hugepages")).unwrap()),
    };
    eprintln!(
        "hugepage host: kernel {}, nr_hugepages {}, free {}, nr_overcommit_hugepages {}, free by node {:?}, 1 GiB pool {:?}",
        host.kernel, host.total, host.free, host.overcommit, host.free_by_node, host.one_gib_pool
    );
    (guard, host)
}

/// Fails, loudly, on a host that cannot exercise the claim, so an unmet
/// precondition is never reported as a pass.
fn require(met: bool, what: &str, host: &HugepageHost) {
    assert!(
        met,
        "hugepage host precondition unmet: {what}; host {host:?}"
    );
}

/// Metadata charged for [`native_pools`] over `pages` backing pages: 512 buffers per page, 20 bytes each.
fn native_metadata(pages: usize) -> usize {
    pages * 512 * 20
}

/// Three pools that fill exactly `pages` 2 MiB backing pages.
fn native_pools(pages: usize) -> [PoolSpec; 3] {
    let unit = |kind| PoolSpec {
        kind,
        count: 1,
        buffer_len: 4096,
    };
    [
        PoolSpec {
            count: u32::try_from(pages * 512 - 2).unwrap(),
            ..unit(PoolKind::ReadResponse)
        },
        unit(PoolKind::ReceiveWrite),
        unit(PoolKind::Maintenance),
    ]
}

fn native_config(nodes: NodeMask, pools: &[PoolSpec]) -> BufferConfig<'_> {
    BufferConfig {
        hugepage: HugepageSize::TwoMiB,
        nodes,
        pools,
    }
}

#[test]
#[ignore = "needs reserved 2 MiB hugepages"]
fn native_hugepage_arena_initializes_reports_placement_and_releases() {
    let (_native, host) = hugepage_host();
    require(host.overcommit == 0, "nr_overcommit_hugepages = 0", &host);
    let node = host.free_by_node.iter().find(|(_, free)| *free >= 2);
    require(
        node.is_some(),
        "an allowed node with 2 free hugepages",
        &host,
    );
    let node = node.unwrap().0;
    let pools = native_pools(2);
    let validated = native_config(node_mask(&[node]), &pools)
        .validate()
        .unwrap();
    let base_page = LinuxPlatform.page_size().unwrap();
    let platform = TestPlatform::linux();
    let log = platform.log();
    let mut budget = EngineBudget::new(usize::MAX);
    let arena = BufferArena::initialize(&validated, platform, &mut budget).unwrap();
    let base = mapped_base(&log);
    assert_eq!(base % TWO_MIB, 0);
    assert_eq!(log.all(), bring_up_log(base, 2 * TWO_MIB, base_page));
    assert_eq!(budget.used(), 2 * TWO_MIB + native_metadata(2));
    let placement = arena.placement();
    assert_eq!(placement.nodes, node_mask(&[node]));
    assert_eq!(placement.pages_verified, 2);
    // Independent residency witness: every base page of the backing is
    // resident, read through a call the arena never makes.
    let mut status = vec![0u8; 2 * TWO_MIB / base_page];
    // SAFETY: the arena owns the live backing; `status` holds one byte per
    // base page of it.
    let result = unsafe {
        libc::mincore(
            arena.backing().base().as_ptr().cast(),
            2 * TWO_MIB,
            status.as_mut_ptr(),
        )
    };
    assert_eq!(result, 0);
    assert!(status.iter().all(|byte| byte & 1 == 1));
    assert_eq!(arena.release().unwrap(), Released::Complete);
    assert_eq!(log.ranges(Op::Unmap), [(base, 2 * TWO_MIB)]);
}

#[test]
#[ignore = "reads the host's 2 MiB hugepage pool"]
fn native_hugepage_request_beyond_the_free_pool_fails_at_map() {
    let (_native, host) = hugepage_host();
    require(host.overcommit == 0, "nr_overcommit_hugepages = 0", &host);
    let node = host.free_by_node[0].0;
    let pools = native_pools(host.free + 1);
    let validated = native_config(node_mask(&[node]), &pools)
        .validate()
        .unwrap();
    let platform = TestPlatform::linux();
    let log = platform.log();
    let failure = BufferArena::initialize(&validated, platform, &mut EngineBudget::new(usize::MAX))
        .unwrap_err();
    assert_eq!(
        failure.error,
        InitError::Os {
            phase: InitPhase::Map,
            region: Region::Buffers,
            code: OsCode(libc::ENOMEM),
        }
    );
    assert!(log.calls(Op::Unmap).is_empty());
}

#[test]
#[ignore = "needs a host with no 1 GiB hugepage pool"]
fn native_hugepage_unconfigured_size_fails_at_map() {
    let (_native, host) = hugepage_host();
    // A kernel without 1 GiB support refuses the size itself; one that
    // supports it with an empty pool has no page to reserve.
    let expected = match host.one_gib_pool {
        None => libc::EINVAL,
        Some(pool) => {
            require(pool == 0, "an empty 1 GiB pool", &host);
            libc::ENOMEM
        }
    };
    let node = host.free_by_node[0].0;
    let pools = native_pools(1);
    let validated = BufferConfig {
        hugepage: HugepageSize::OneGiB,
        ..native_config(node_mask(&[node]), &pools)
    }
    .validate()
    .unwrap();
    let platform = TestPlatform::linux();
    let log = platform.log();
    let failure = BufferArena::initialize(&validated, platform, &mut EngineBudget::new(usize::MAX))
        .unwrap_err();
    assert_eq!(
        failure.error,
        InitError::Os {
            phase: InitPhase::Map,
            region: Region::Buffers,
            code: OsCode(expected),
        }
    );
    assert!(log.calls(Op::Unmap).is_empty());
}

/// Hugepages free on another node let the map succeed, but a mask naming a
/// node with none free fails population with a typed error, not a signal.
#[test]
#[ignore = "needs free 2 MiB hugepages on one allowed node and none on another"]
fn native_hugepage_node_shortage_fails_at_populate() {
    let (_native, host) = hugepage_host();
    require(host.overcommit == 0, "nr_overcommit_hugepages = 0", &host);
    let empty = host.free_by_node.iter().find(|(_, free)| *free == 0);
    let stocked = host.free_by_node.iter().any(|(_, free)| *free >= 1);
    require(
        empty.is_some() && stocked,
        "one allowed node with free hugepages and one with none",
        &host,
    );
    let node = empty.unwrap().0;
    let has_memory = LinuxPlatform.topology().unwrap().has_memory;
    require(
        has_memory.contains(node),
        "the empty node has memory",
        &host,
    );
    let pools = native_pools(1);
    let validated = native_config(node_mask(&[node]), &pools)
        .validate()
        .unwrap();
    let platform = TestPlatform::linux();
    let log = platform.log();
    let failure = BufferArena::initialize(&validated, platform, &mut EngineBudget::new(usize::MAX))
        .unwrap_err();
    assert!(
        matches!(
            failure.error,
            InitError::Os {
                phase: InitPhase::Populate,
                region: Region::Buffers,
                ..
            }
        ),
        "{failure:?}"
    );
    assert_eq!(failure.retained, None);
    assert_eq!(log.ranges(Op::Unmap).len(), 1);
}
