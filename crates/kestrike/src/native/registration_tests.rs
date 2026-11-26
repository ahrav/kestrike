//! Step order, fault handling and custody of the arena registration guard,
//! over a recording [`DmaPort`] with injectable faults and a heap-backed
//! arena.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::dma::{DmaMode, DmaPolicy, DmaPort, DmaReport, IovaMode};
use super::env::{Environment, Unfinished};
use super::registration::{
    ArenaRegistration, CHECK_CHUNK, DeviceLease, RegistrationError, RegistrationStep, Unregistered,
};
use super::watchdog::{Supervisor, Watchdog};
use crate::storage::device::Pools;
use crate::storage::test_platform::TestPlatform;
use crate::storage::{
    BufferArena, BufferConfig, EngineBudget, HugepageSize, NodeMask, PoolKind, PoolSpec, Released,
};

const PAGE: usize = 2 << 20;
const PAGES: usize = 3;
/// 2 MiB + 2 MiB + 4 KiB of buffers: three 2 MiB backing pages.
const POOLS: [PoolSpec; 3] = [
    PoolSpec {
        kind: PoolKind::ReadResponse,
        count: 512,
        buffer_len: 4096,
    },
    PoolSpec {
        kind: PoolKind::ReceiveWrite,
        count: 1,
        buffer_len: 2 << 20,
    },
    PoolSpec {
        kind: PoolKind::Maintenance,
        count: 1,
        buffer_len: 4096,
    },
];

pub(crate) fn new_arena() -> BufferArena<TestPlatform> {
    let config = BufferConfig {
        hugepage: HugepageSize::TwoMiB,
        nodes: NodeMask::from_nodes(&[0]).unwrap(),
        pools: &POOLS,
    };
    let validated = config.validate().unwrap();
    let mut budget = EngineBudget::new(1 << 30);
    budget.charge(4096).unwrap();
    let previous = budget.used();
    let arena = BufferArena::initialize(&validated, TestPlatform::heap(4096), &mut budget).unwrap();
    let admitted = PAGES * PAGE + Pools::metadata_bytes(&validated);
    assert!(previous <= budget.used() && budget.used() <= budget.limit());
    assert_eq!(budget.used(), previous + admitted);
    arena
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Call {
    ExtmemRegister { pages: usize },
    ExtmemUnregister,
    SpdkRegister,
    SpdkUnregister,
    Map,
    Unmap,
}

/// One container call: the address, the IOVA and the length the registration passed.
type Range = (usize, u64, usize);

/// The fake's environment and faults; a fault names the call that fails and its code.
struct State {
    iova: IovaMode,
    /// `None` reports an IOMMU class that cannot be read.
    guest_iommu: Option<bool>,
    no_iommu: Option<bool>,
    free_lists: u32,
    memlock: u64,
    /// Physical address offset per page in no-IOMMU mode; `None` reports no address.
    physical: Option<u64>,
    /// Reports the backing pages' physical addresses in reverse order, so neighboring pages differ in their offset.
    reversed: bool,
    fail: Vec<(Call, i32)>,
    /// Pages whose SPDK translation is short and whose DPDK translation is wrong.
    short_page: Option<usize>,
    wrong_page: Option<usize>,
    /// A page whose SPDK translation names the wrong IOVA.
    spdk_wrong_page: Option<usize>,
    /// A page DPDK reports no IOVA for.
    dpdk_missing_page: Option<usize>,
    /// Blocks the named call until the gate opens.
    stall: Option<(Call, Receiver<()>)>,
    calls: Vec<Call>,
    /// The registered external memory: base and per-page IOVAs.
    extmem: Option<(usize, Vec<u64>)>,
    /// The address and length of the registered external memory.
    registered: Option<(usize, usize)>,
    /// The container map calls and the container unmap calls, each in call order.
    maps: Vec<Range>,
    unmaps: Vec<Range>,
    spdk: bool,
}

#[derive(Clone)]
pub(super) struct Fake(Rc<RefCell<State>>);

impl Fake {
    pub(super) fn iommu() -> Self {
        Self(Rc::new(RefCell::new(State {
            iova: IovaMode::Va,
            guest_iommu: Some(true),
            no_iommu: Some(false),
            free_lists: 1,
            memlock: u64::MAX,
            physical: None,
            reversed: false,
            fail: Vec::new(),
            short_page: None,
            wrong_page: None,
            spdk_wrong_page: None,
            dpdk_missing_page: None,
            stall: None,
            calls: Vec::new(),
            extmem: None,
            registered: None,
            maps: Vec::new(),
            unmaps: Vec::new(),
            spdk: false,
        })))
    }

    fn no_iommu() -> Self {
        let fake = Self::iommu();
        {
            let mut s = fake.0.borrow_mut();
            (s.iova, s.guest_iommu, s.no_iommu, s.physical) = (
                IovaMode::Pa,
                Some(false),
                Some(true),
                Some(64 * PAGE as u64),
            );
        }
        fake
    }

    fn fail(&self, call: Call, code: i32) -> &Self {
        self.0.borrow_mut().fail.push((call, code));
        self
    }

    fn calls(&self) -> Vec<Call> {
        self.0.borrow().calls.clone()
    }

    /// Sets whether DPDK mistranslates the first page; while it does, a verify or a recheck of the registration fails.
    pub(super) fn mistranslate(&self, wrong: bool) {
        self.0.borrow_mut().wrong_page = wrong.then_some(0);
    }

    fn run(&self, call: Call) -> Result<(), i32> {
        let stall = {
            let mut s = self.0.borrow_mut();
            s.calls.push(call);
            match s.stall.take() {
                Some((stalled, gate)) if stalled == call => Some(gate),
                other => {
                    s.stall = other;
                    None
                }
            }
        };
        if let Some(gate) = stall {
            gate.recv().unwrap();
        }
        let s = self.0.borrow();
        s.fail
            .iter()
            .find(|(failing, _)| *failing == call)
            .map_or(Ok(()), |&(_, code)| Err(code))
    }
}

impl DmaPort for Fake {
    fn iova_mode(&self) -> IovaMode {
        self.0.borrow().iova
    }
    fn guest_iommu(&self) -> Option<bool> {
        self.0.borrow().guest_iommu
    }
    fn vfio_no_iommu(&self) -> Option<bool> {
        self.0.borrow().no_iommu
    }
    fn free_memseg_lists(&self) -> u32 {
        self.0.borrow().free_lists
    }
    fn memlock_limit(&self) -> u64 {
        self.0.borrow().memlock
    }
    fn physical_addresses(&self, va: usize, page: usize, pages: usize) -> Result<Vec<u64>, usize> {
        let (offset, reversed) = {
            let s = self.0.borrow();
            (s.physical.ok_or(0usize)?, s.reversed)
        };
        Ok((0..pages)
            .map(|index| if reversed { pages - 1 - index } else { index })
            .map(|index| offset + (va + index * page) as u64)
            .collect())
    }
    unsafe fn extmem_register(
        &mut self,
        va: usize,
        len: usize,
        iovas: &[u64],
        page: usize,
    ) -> Result<(), i32> {
        assert_eq!(page, PAGE);
        let result = self.run(Call::ExtmemRegister { pages: iovas.len() });
        if result.is_ok() {
            let mut s = self.0.borrow_mut();
            s.extmem = Some((va, iovas.to_vec()));
            s.registered = Some((va, len));
        }
        result
    }
    fn extmem_unregister(&mut self, _: usize, _: usize) -> Result<(), i32> {
        assert!(
            !self.0.borrow().spdk,
            "SPDK must unregister while the external memory exists"
        );
        let result = self.run(Call::ExtmemUnregister);
        if result.is_ok() {
            let mut s = self.0.borrow_mut();
            s.extmem = None;
            s.registered = None;
        }
        result
    }
    unsafe fn spdk_register(&mut self, _: usize, _: usize) -> Result<(), i32> {
        assert!(
            self.0.borrow().extmem.is_some(),
            "SPDK registers over existing external memory"
        );
        // SPDK records the region even when a later map callback fails, but
        // not when it refuses a busy or malformed range.
        let result = self.run(Call::SpdkRegister);
        self.0.borrow_mut().spdk = !matches!(result, Err(libc::EBUSY));
        result
    }
    fn spdk_unregister(&mut self, _: usize, _: usize) -> Result<(), i32> {
        assert!(
            self.0.borrow().extmem.is_some(),
            "SPDK unregisters while the external memory exists"
        );
        let result = self.run(Call::SpdkUnregister);
        if result.is_ok() {
            self.0.borrow_mut().spdk = false;
        }
        result
    }
    unsafe fn container_map(&mut self, va: usize, iova: u64, len: usize) -> Result<(), i32> {
        assert_eq!(va as u64, iova, "IOMMU mode maps IOVA = VA");
        self.0.borrow_mut().maps.push((va, iova, len));
        self.run(Call::Map)
    }
    fn container_unmap(&mut self, va: usize, iova: u64, len: usize) -> Result<(), i32> {
        self.0.borrow_mut().unmaps.push((va, iova, len));
        self.run(Call::Unmap)
    }
    /// SPDK's translation from `va` and its contiguous length, capped at
    /// `len`, once SPDK recorded the region: a page translates over its
    /// whole length, the short page stops 4 KiB before its end, and the next
    /// page continues the length when its translation follows this one's by
    /// a page.
    fn spdk_translate(&self, va: usize, len: usize) -> Option<(u64, usize)> {
        let s = self.0.borrow();
        if !s.spdk {
            return None;
        }
        let translation = |index: usize| {
            let (base, iovas) = s.extmem.as_ref()?;
            let iova = *iovas.get(index)?;
            let wrong = s.spdk_wrong_page == Some(index);
            Some((
                base + index * PAGE,
                iova + if wrong { PAGE as u64 } else { 0 },
            ))
        };
        let (first, _) = self.lookup(&s, va)?;
        let (start, iova) = translation(first)?;
        let mut index = first;
        let mut size = start + PAGE - va;
        loop {
            if s.short_page == Some(index) {
                size -= 4096;
                break;
            }
            let continues = translation(index + 1).is_some_and(|(_, next)| {
                Some(next) == translation(index).map(|(_, at)| at + PAGE as u64)
            });
            if size >= len || !continues {
                break;
            }
            index += 1;
            size += PAGE;
        }
        Some((iova + (va - start) as u64, size.min(len)))
    }
    fn dpdk_translations(&self, va: usize, page: usize, out: &mut [Option<u64>]) {
        let s = self.0.borrow();
        for (at, slot) in out.iter_mut().enumerate() {
            *slot = self
                .lookup(&s, va + at * page)
                .filter(|&(index, _)| s.dpdk_missing_page != Some(index))
                .map(|(index, iova)| {
                    if s.wrong_page == Some(index) {
                        iova + PAGE as u64
                    } else {
                        iova
                    }
                });
        }
    }
}

impl Fake {
    fn lookup(&self, s: &State, va: usize) -> Option<(usize, u64)> {
        let (base, iovas) = s.extmem.as_ref()?;
        let index = (va - base) / PAGE;
        iovas.get(index).map(|&iova| (index, iova))
    }
}

const IOMMU: DmaPolicy = DmaPolicy {
    allow_no_iommu: false,
};
const ALLOWLISTED: DmaPolicy = DmaPolicy {
    allow_no_iommu: true,
};

pub(super) fn register<'a>(
    env: &'a Environment,
    arena: &'a BufferArena<TestPlatform>,
    fake: &Fake,
    policy: DmaPolicy,
) -> Result<ArenaRegistration<'a>, RegistrationError> {
    ArenaRegistration::register_with(
        env,
        arena.hold_registration(),
        policy,
        Box::new(fake.clone()),
    )
}

/// A registration of `arena` that mapped and verified over an IOMMU fake, ready for commands.
pub(crate) fn ready<'a>(
    env: &'a Environment,
    arena: &'a BufferArena<TestPlatform>,
) -> ArenaRegistration<'a> {
    let mut registration = register(env, arena, &Fake::iommu(), IOMMU).unwrap();
    registration.map().unwrap();
    registration.verify().unwrap();
    registration
}

/// [`ready`], with a switch that makes DPDK mistranslate the first page from
/// then on, so the registration's next recheck fails.
pub(crate) fn ready_until_stale<'a>(
    env: &'a Environment,
    arena: &'a BufferArena<TestPlatform>,
) -> (ArenaRegistration<'a>, impl Fn()) {
    let fake = Fake::iommu();
    let mut registration = register(env, arena, &fake, IOMMU).unwrap();
    registration.map().unwrap();
    registration.verify().unwrap();
    (registration, move || {
        fake.0.borrow_mut().wrong_page = Some(0);
    })
}

/// A registration of `arena` over an IOMMU fake, registered and unmapped.
pub(crate) fn registered<'a>(
    env: &'a Environment,
    arena: &'a BufferArena<TestPlatform>,
) -> ArenaRegistration<'a> {
    register(env, arena, &Fake::iommu(), IOMMU).unwrap()
}

/// A registration of `arena` over an IOMMU fake whose DPDK translation of
/// the first page is wrong, so its [`verify`](ArenaRegistration::verify)
/// fails; it is registered and unmapped.
pub(crate) fn mistranslated<'a>(
    env: &'a Environment,
    arena: &'a BufferArena<TestPlatform>,
) -> ArenaRegistration<'a> {
    let fake = Fake::iommu();
    fake.0.borrow_mut().wrong_page = Some(0);
    register(env, arena, &fake, IOMMU).unwrap()
}

/// Undoes `registration` under a generous watchdog.
pub(crate) fn undone(registration: ArenaRegistration<'_>) -> Unregistered<'_> {
    registration.unregister(&watchdog()).unwrap()
}

/// The arena's release outcome: `Ok` when it unmapped, else the outstanding registration holds.
fn release(arena: BufferArena<TestPlatform>) -> Result<Released, u32> {
    arena.release().map_err(|blocked| blocked.registrations)
}

/// Counts containment requests and opens a stall gate on the first.
pub(crate) struct Recorder(Mutex<u32>, Mutex<Option<Sender<()>>>);

impl Recorder {
    pub(crate) fn new() -> Self {
        Self(Mutex::default(), Mutex::default())
    }

    pub(crate) fn requests(&self) -> u32 {
        *self.0.lock().unwrap()
    }
}

impl Supervisor for Recorder {
    fn contain(&self) {
        *self.0.lock().unwrap() += 1;
        if let Some(gate) = self.1.lock().unwrap().take() {
            gate.send(()).unwrap();
        }
    }
}

/// The address-translation witness a verified registration's report earns:
/// every backing page verified, every byte translated in whole pages, and
/// the mode's mapping proof, the container mapping in IOMMU mode or a
/// present physical address for every page in no-IOMMU mode. After a passing
/// [`verify`], `translated_bytes` equals `extent` and `physical_pages`
/// equals `extent / page_size` in no-IOMMU mode and zero in IOMMU mode.
///
/// [`verify`]: super::ArenaRegistration::verify
pub(crate) fn dma_witness(report: &DmaReport) -> Result<String, String> {
    let pages = report.extent / report.page_size.max(1);
    if pages == 0 || report.verified_pages != pages {
        return Err(format!(
            "{} of {pages} pages verified",
            report.verified_pages
        ));
    }
    if report.translated_bytes != report.extent {
        return Err(format!(
            "{} of {} bytes translated",
            report.translated_bytes, report.extent
        ));
    }
    let (mappings, physical) = match report.mode {
        DmaMode::Iommu => (1, 0),
        DmaMode::NoIommu => (0, pages),
    };
    if report.mappings != mappings {
        return Err(format!("{} container mappings", report.mappings));
    }
    if report.physical_pages != physical {
        return Err(format!(
            "{} of {pages} physical addresses",
            report.physical_pages
        ));
    }
    Ok(format!(
        "{:?} iova {:?} registered pages {pages} of {} bytes translated {} bytes physical queries {} mappings {}",
        report.mode,
        report.iova_mode,
        report.page_size,
        report.translated_bytes,
        report.physical_pages,
        report.mappings
    ))
}

/// A verified registration earns the address witness in each mode, and each
/// shortfall the witness names leaves it uncredited: a page that failed to
/// verify, a short translation, a missing IOMMU mapping, a missing physical
/// address and a zero count.
#[test]
fn only_a_complete_verified_registration_earns_the_address_witness() {
    for (fake, policy) in [(Fake::iommu(), IOMMU), (Fake::no_iommu(), ALLOWLISTED)] {
        let (env, arena) = (Environment::detached(), new_arena());
        let mut registration = register(&env, &arena, &fake, policy).unwrap();
        registration.map().unwrap();
        let report = registration.verify().unwrap();
        let witness = dma_witness(&report).unwrap();
        assert!(
            witness.contains(&format!("registered pages {PAGES} ")),
            "{witness}"
        );
        let physical = if report.mode == DmaMode::NoIommu {
            PAGES
        } else {
            0
        };
        assert_eq!(
            (report.physical_pages, report.translated_bytes),
            (physical, PAGES * PAGE)
        );
        let refusals: [(DmaReport, String); 4] = [
            (
                DmaReport {
                    verified_pages: PAGES - 1,
                    ..report
                },
                format!("{} of {PAGES} pages verified", PAGES - 1),
            ),
            (
                DmaReport {
                    translated_bytes: PAGES * PAGE - 1,
                    ..report
                },
                "bytes translated".into(),
            ),
            (
                DmaReport {
                    verified_pages: 0,
                    translated_bytes: 0,
                    ..report
                },
                format!("0 of {PAGES} pages verified"),
            ),
            if report.mode == DmaMode::Iommu {
                (
                    DmaReport {
                        mappings: 0,
                        ..report
                    },
                    "0 container mappings".into(),
                )
            } else {
                (
                    DmaReport {
                        physical_pages: PAGES - 1,
                        ..report
                    },
                    format!("{} of {PAGES} physical addresses", PAGES - 1),
                )
            },
        ];
        for (short, reason) in refusals {
            assert!(
                dma_witness(&short).is_err_and(|refused| refused.contains(&reason)),
                "{short:?}"
            );
        }
        registration.unregister(&watchdog()).unwrap();
    }
    // A failed verify after a passing one resets both counts, so its report earns nothing.
    let (env, arena) = (Environment::detached(), new_arena());
    let fake = Fake::iommu();
    let mut registration = register(&env, &arena, &fake, IOMMU).unwrap();
    registration.map().unwrap();
    assert_eq!(
        registration.verify().unwrap().translated_bytes,
        PAGES * PAGE
    );
    fake.0.borrow_mut().short_page = Some(2);
    assert!(registration.verify().is_err());
    let report = registration.report();
    assert_eq!((report.verified_pages, report.translated_bytes), (0, 0));
    assert!(
        dma_witness(&report).is_err_and(|refused| refused.contains("pages verified")),
        "{report:?}"
    );
}

pub(super) fn watchdog() -> Watchdog {
    Watchdog::arm(Duration::from_secs(60), Arc::new(Recorder::new())).unwrap()
}

const FULL: [Call; 6] = [
    Call::ExtmemRegister { pages: PAGES },
    Call::SpdkRegister,
    Call::Map,
    Call::SpdkUnregister,
    Call::Unmap,
    Call::ExtmemUnregister,
];

#[test]
fn a_full_lifecycle_registers_maps_once_verifies_and_undoes_in_order() {
    let (env, arena) = (Environment::detached(), new_arena());
    let fake = Fake::iommu();
    let mut registration = register(&env, &arena, &fake, IOMMU).unwrap();
    assert!(
        !registration.is_ready(),
        "no DMA before the mapping and translations verify"
    );
    registration.map().unwrap();
    assert!(!registration.is_ready());
    assert_eq!(
        registration.map().unwrap_err().step,
        RegistrationStep::Map,
        "each range maps once"
    );
    let report = registration.verify().unwrap();
    assert!(registration.is_ready());
    assert_eq!(
        (report.mode, report.mappings, report.verified_pages),
        (DmaMode::Iommu, 1, PAGES)
    );
    assert_eq!(
        (
            report.extent,
            report.page_size,
            report.iova_mode,
            report.guest_iommu
        ),
        (PAGES * PAGE, PAGE, IovaMode::Va, true)
    );
    let lease = registration.device_attached();
    registration.device_stopped(lease.stopped()).unwrap();
    registration.unregister(&watchdog()).unwrap();
    assert_eq!(fake.calls(), FULL);
    assert_eq!(release(arena), Ok(Released::Complete));
}

#[test]
fn no_iommu_mode_registers_physical_addresses_and_maps_nothing() {
    let (env, arena) = (Environment::detached(), new_arena());
    let fake = Fake::no_iommu();
    let mut registration = register(&env, &arena, &fake, ALLOWLISTED).unwrap();
    registration.map().unwrap();
    let report = registration.verify().unwrap();
    assert_eq!(
        (report.mode, report.mappings, report.vfio_no_iommu),
        (DmaMode::NoIommu, 0, Some(true))
    );
    let base = arena.backing().base().as_ptr().addr() as u64;
    let iovas = fake.0.borrow().extmem.clone().unwrap().1;
    assert_eq!(
        iovas,
        (0..PAGES as u64)
            .map(|p| 64 * PAGE as u64 + base + p * PAGE as u64)
            .collect::<Vec<_>>()
    );
    registration.unregister(&watchdog()).unwrap();
    assert!(
        !fake
            .calls()
            .iter()
            .any(|c| matches!(c, Call::Map | Call::Unmap))
    );
    assert_eq!(release(arena), Ok(Released::Complete));
}

#[test]
fn unsupported_postures_and_exhausted_capacity_refuse_before_any_registration() {
    type Case = (fn(&mut State), DmaPolicy, RegistrationStep);
    let cases: [Case; 6] = [
        (
            |s| s.guest_iommu = Some(false),
            IOMMU,
            RegistrationStep::Mode,
        ),
        (|s| s.no_iommu = Some(true), IOMMU, RegistrationStep::Mode),
        (
            |s| (s.iova, s.guest_iommu, s.no_iommu) = (IovaMode::Pa, Some(false), Some(true)),
            IOMMU,
            RegistrationStep::Mode,
        ),
        (
            |s| s.iova = IovaMode::Undecided,
            ALLOWLISTED,
            RegistrationStep::Mode,
        ),
        (|s| s.free_lists = 0, IOMMU, RegistrationStep::Capacity),
        (
            |s| s.memlock = (PAGES * PAGE) as u64 - 1,
            IOMMU,
            RegistrationStep::Capacity,
        ),
    ];
    for (edit, policy, step) in cases {
        let (env, arena) = (Environment::detached(), new_arena());
        let fake = Fake::iommu();
        edit(&mut fake.0.borrow_mut());
        let refused = register(&env, &arena, &fake, policy).unwrap_err();
        assert_eq!((refused.step, refused.retained), (step, false));
        assert!(fake.calls().is_empty());
        assert_eq!(release(arena), Ok(Released::Complete));
    }
}

/// The posture is observed, never inferred: an IOMMU class that cannot be
/// read is no observation of a host without a guest IOMMU, so it refuses
/// each posture the same environment enters once the class is read, before
/// any native registration.
#[test]
fn an_unreadable_iommu_class_refuses_both_postures_before_any_registration() {
    type Case = (fn() -> Fake, DmaPolicy, DmaMode);
    let cases: [Case; 2] = [
        (Fake::iommu, IOMMU, DmaMode::Iommu),
        (Fake::no_iommu, ALLOWLISTED, DmaMode::NoIommu),
    ];
    for (fake, policy, mode) in cases {
        let (env, arena) = (Environment::detached(), new_arena());
        let fake = fake();
        let observed = fake.0.borrow().guest_iommu;
        let registration = register(&env, &arena, &fake, policy).unwrap();
        assert_eq!(registration.report().mode, mode, "{observed:?} is admitted");
        registration.unregister(&watchdog()).unwrap();
        assert_eq!(release(arena), Ok(Released::Complete));

        let (env, arena) = (Environment::detached(), new_arena());
        let before = fake.calls().len();
        fake.0.borrow_mut().guest_iommu = None;
        let refused = register(&env, &arena, &fake, policy).unwrap_err();
        assert_eq!(
            (refused.step, refused.retained),
            (RegistrationStep::Mode, false),
            "{mode:?} with an unreadable class"
        );
        assert_eq!(fake.calls().len(), before, "no native call was made");
        assert_eq!(release(arena), Ok(Released::Complete));
    }
}

#[test]
fn a_page_without_an_aligned_physical_address_refuses_before_registration() {
    for physical in [None, Some(4096)] {
        let (env, arena) = (Environment::detached(), new_arena());
        let fake = Fake::no_iommu();
        fake.0.borrow_mut().physical = physical;
        let refused = register(&env, &arena, &fake, ALLOWLISTED).unwrap_err();
        assert_eq!(
            (refused.step, refused.page),
            (RegistrationStep::Address, Some(0))
        );
        assert!(fake.calls().is_empty());
        assert_eq!(release(arena), Ok(Released::Complete));
    }
}

#[test]
fn a_failed_registration_step_rolls_back_or_retains_the_arena() {
    let (env, arena) = (Environment::detached(), new_arena());
    let fake = Fake::iommu();
    fake.fail(Call::ExtmemRegister { pages: PAGES }, 28);
    let refused = register(&env, &arena, &fake, IOMMU).unwrap_err();
    assert_eq!(
        (refused.step, refused.code, refused.retained),
        (RegistrationStep::ExtmemRegister, Some(28), false)
    );
    assert_eq!(release(arena), Ok(Released::Complete));

    // A failed SPDK registration may be partial; explicit cleanup makes the arena releasable again.
    let (env, arena) = (Environment::detached(), new_arena());
    let fake = Fake::iommu();
    fake.fail(Call::SpdkRegister, 12);
    let refused = register(&env, &arena, &fake, IOMMU).unwrap_err();
    assert_eq!(
        (refused.step, refused.retained),
        (RegistrationStep::SpdkRegister, false)
    );
    assert_eq!(
        fake.calls(),
        [
            FULL[0],
            Call::SpdkRegister,
            Call::SpdkUnregister,
            Call::ExtmemUnregister
        ]
    );
    assert_eq!(release(arena), Ok(Released::Complete));

    for (cleanup, code) in [
        (Call::SpdkUnregister, 16),
        (Call::SpdkUnregister, libc::EINVAL),
        (Call::ExtmemUnregister, 16),
    ] {
        let (env, arena) = (Environment::detached(), new_arena());
        let fake = Fake::iommu();
        fake.fail(Call::SpdkRegister, 12).fail(cleanup, code);
        let refused = register(&env, &arena, &fake, IOMMU).unwrap_err();
        assert_eq!(
            (refused.step, refused.retained),
            (RegistrationStep::SpdkRegister, true),
            "cleanup {cleanup:?} failing with {code}"
        );
        assert_eq!(
            release(arena),
            Err(1),
            "a failed cleanup after {cleanup:?} with {code} keeps the arena held"
        );
    }
}

#[test]
fn a_failed_map_leaves_dma_disabled_even_with_valid_software_translations() {
    let (env, arena) = (Environment::detached(), new_arena());
    let fake = Fake::iommu();
    fake.fail(Call::Map, 22);
    let mut registration = register(&env, &arena, &fake, IOMMU).unwrap();
    assert_eq!(registration.map().unwrap_err().code, Some(22));
    let base = arena.backing().base().as_ptr().addr();
    assert!(
        DmaPort::spdk_translate(&fake, base, PAGE).is_some(),
        "SPDK still translates the arena"
    );
    assert_eq!(
        registration.verify().unwrap_err().step,
        RegistrationStep::Verify
    );
    assert!(!registration.is_ready());
    registration.unregister(&watchdog()).unwrap();
    assert_eq!(
        fake.calls(),
        [
            FULL[0],
            FULL[1],
            Call::Map,
            Call::SpdkUnregister,
            Call::ExtmemUnregister
        ],
        "nothing to unmap"
    );
    assert_eq!(release(arena), Ok(Released::Complete));
}

/// Verification names the first faulted page whether the IOVAs form one run
/// SPDK answers for at once, in IOMMU mode or for ascending physical pages,
/// or one run per page, for descending physical pages; a DPDK fault before an
/// SPDK fault is the one named, and so is an SPDK fault before a DPDK fault.
#[test]
fn a_short_or_mismatched_translation_fails_verification_at_its_page() {
    type Fault = (fn(&mut State), usize);
    let faults: [Fault; 6] = [
        (|s| s.short_page = Some(2), 2),
        (|s| s.short_page = Some(0), 0),
        (|s| s.wrong_page = Some(1), 1),
        (|s| s.spdk_wrong_page = Some(0), 0),
        (
            |s| (s.dpdk_missing_page, s.spdk_wrong_page) = (Some(1), Some(2)),
            1,
        ),
        (
            |s| (s.spdk_wrong_page, s.wrong_page) = (Some(1), Some(2)),
            1,
        ),
    ];
    // (no-IOMMU mode, descending physical pages)
    let layouts = [(false, false), (true, false), (true, true)];
    for (fault, page) in faults {
        for (no_iommu, reversed) in layouts {
            let (env, arena) = (Environment::detached(), new_arena());
            let (fake, policy) = if no_iommu {
                (Fake::no_iommu(), ALLOWLISTED)
            } else {
                (Fake::iommu(), IOMMU)
            };
            fake.0.borrow_mut().reversed = reversed;
            fault(&mut fake.0.borrow_mut());
            let mut registration = register(&env, &arena, &fake, policy).unwrap();
            registration.map().unwrap();
            let failed = registration.verify().unwrap_err();
            assert_eq!(
                (failed.step, failed.page),
                (RegistrationStep::Verify, Some(page)),
                "no-IOMMU {no_iommu} reversed {reversed}"
            );
            assert!(!registration.is_ready());
            assert_eq!(registration.report().verified_pages, 0);
        }
    }
}

/// A recheck that finds a changed translation revokes readiness: later pools, ports and IOVA lookups refuse until the arena is re-registered.
#[test]
fn a_failed_recheck_revokes_readiness() {
    let (env, arena) = (Environment::detached(), new_arena());
    let fake = Fake::iommu();
    let mut registration = register(&env, &arena, &fake, IOMMU).unwrap();
    registration.map().unwrap();
    registration.verify().unwrap();
    let (base, _) = registration.range();
    assert!(registration.recheck().is_ok());
    assert!(registration.iova(base, 64).is_some());
    fake.0.borrow_mut().wrong_page = Some(1);
    let failed = registration.recheck().unwrap_err();
    assert_eq!(
        (failed.step, failed.page),
        (RegistrationStep::Verify, Some(1))
    );
    assert!(
        !registration.is_ready(),
        "a failed recheck revokes readiness"
    );
    assert_eq!(registration.iova(base, 64), None);
    assert_eq!(
        registration.recheck().unwrap_err().page,
        None,
        "an unverified registration refuses the recheck itself"
    );
}

fn wide_arena(pages: usize) -> BufferArena<TestPlatform> {
    let pools = [PoolSpec {
        kind: PoolKind::ReceiveWrite,
        count: u32::try_from(pages).unwrap(),
        buffer_len: PAGE as u32,
    }];
    let config = BufferConfig {
        hugepage: HugepageSize::TwoMiB,
        nodes: NodeMask::from_nodes(&[0]).unwrap(),
        pools: &pools,
    };
    let validated = config.validate().unwrap();
    let mut budget = EngineBudget::new(1 << 30);
    BufferArena::initialize(&validated, TestPlatform::heap(4096), &mut budget).unwrap()
}

#[test]
fn the_dpdk_check_reaches_the_second_chunk() {
    let pages = CHECK_CHUNK + 1;
    let (env, arena) = (Environment::detached(), wide_arena(pages));
    let fake = Fake::iommu();
    fake.0.borrow_mut().dpdk_missing_page = Some(CHECK_CHUNK);
    let mut registration = register(&env, &arena, &fake, IOMMU).unwrap();
    registration.map().unwrap();
    let failed = registration.verify().unwrap_err();
    assert_eq!(
        (failed.step, failed.page),
        (RegistrationStep::Verify, Some(CHECK_CHUNK))
    );
    assert_eq!(registration.report().verified_pages, 0);
    fake.0.borrow_mut().dpdk_missing_page = None;
    let report = registration.verify().unwrap();
    assert_eq!(
        (report.verified_pages, report.translated_bytes),
        (pages, pages * PAGE)
    );
    registration.unregister(&watchdog()).unwrap();
    assert_eq!(release(arena), Ok(Released::Complete));
}

/// What a registration, and a device lease of it when one is held, answer at one moment.
#[derive(Debug, PartialEq)]
struct Answers {
    ready: bool,
    /// The lease's reading of the registration's readiness.
    lease_ready: Option<bool>,
    /// The IOVA of the arena's first 64 bytes.
    iova: Option<u64>,
    /// The offsets of four buffers of 64 bytes from the arena's base.
    offsets: Box<[Option<u64>]>,
    verified_pages: usize,
    translated_bytes: usize,
}

impl Answers {
    fn read(registration: &ArenaRegistration<'_>, lease: Option<&DeviceLease>) -> Self {
        let (base, _) = registration.range();
        let report = registration.report();
        Self {
            ready: registration.is_ready(),
            lease_ready: lease.map(DeviceLease::ready),
            iova: registration.iova(base, 64),
            offsets: registration.offsets(base, 64, 4),
            verified_pages: report.verified_pages,
            translated_bytes: report.translated_bytes,
        }
    }

    /// Whether the registration and any lease are ready, every lookup answers, and the report counts verified
    /// pages and translated bytes.
    fn granted(&self) -> bool {
        self.ready
            && self.lease_ready != Some(false)
            && self.iova.is_some()
            && self.offsets.len() == 4
            && self.offsets.iter().all(Option::is_some)
            && self.verified_pages > 0
            && self.translated_bytes > 0
    }
}

/// A repeated `verify()` that finds a missing or short SPDK translation, a missing DPDK translation, or a wrong SPDK or DPDK translation, revokes readiness: IOVA lookups return `None` until a later `verify()` succeeds.
/// Each failed verify names its page with no error number and nothing retained, and revokes readiness, the IOVA
/// and offset lookups, and the report's verified pages and translated bytes; the next passing verify grants each
/// of them again as the first one did. The last row holds a device lease across a wrong DPDK translation of the
/// first page: the lease reports the same readiness, and it returns before the registration undoes.
#[test]
fn a_failed_repeat_verify_revokes_readiness() {
    type Fault = (fn(&mut State, bool), usize, bool);
    // Each row is a fault, the page it fails at, and whether a device holds a lease across the verifies.
    let faults: [Fault; 6] = [
        (|s, on| s.spdk = !on, 0, false),
        (|s, on| s.dpdk_missing_page = on.then_some(1), 1, false),
        (|s, on| s.short_page = on.then_some(2), 2, false),
        (|s, on| s.wrong_page = on.then_some(1), 1, false),
        (|s, on| s.spdk_wrong_page = on.then_some(2), 2, false),
        (|s, on| s.wrong_page = on.then_some(0), 0, true),
    ];
    for (fault, page, leased) in faults {
        let (env, arena) = (Environment::detached(), new_arena());
        let fake = Fake::iommu();
        let mut registration = register(&env, &arena, &fake, IOMMU).unwrap();
        registration.map().unwrap();
        let pages = registration.verify().unwrap().verified_pages;
        let lease = leased.then(|| registration.device_attached());
        let granted = Answers::read(&registration, lease.as_ref());
        assert!(granted.granted(), "the first verify grants: {granted:?}");
        let (base, _) = registration.range();
        let lookups = [base, base + page * PAGE];
        assert!(
            lookups
                .iter()
                .all(|&va| registration.iova(va, 64).is_some())
        );
        fault(&mut fake.0.borrow_mut(), true);
        let failed = registration.verify().unwrap_err();
        assert_eq!(
            (failed.step, failed.page),
            (RegistrationStep::Verify, Some(page))
        );
        assert_eq!(
            failed,
            RegistrationError {
                step: RegistrationStep::Verify,
                code: None,
                page: Some(page),
                retained: false,
            }
        );
        assert!(
            !registration.is_ready(),
            "a failed verify at page {page} revokes readiness"
        );
        assert_eq!(registration.report().verified_pages, 0);
        assert!(
            lookups
                .iter()
                .all(|&va| registration.iova(va, 64).is_none()),
            "valid-range lookups refuse after the failed verify at page {page}"
        );
        assert_eq!(
            Answers::read(&registration, lease.as_ref()),
            Answers {
                ready: false,
                lease_ready: leased.then_some(false),
                iova: None,
                offsets: [None; 4].into(),
                verified_pages: 0,
                translated_bytes: 0,
            },
            "the failed verify at page {page} revokes every answer"
        );
        fault(&mut fake.0.borrow_mut(), false);
        assert_eq!(registration.verify().unwrap().verified_pages, pages);
        assert!(registration.is_ready());
        assert!(
            lookups
                .iter()
                .all(|&va| registration.iova(va, 64).is_some())
        );
        assert_eq!(
            Answers::read(&registration, lease.as_ref()),
            granted,
            "the passing verify grants again what the first one granted"
        );
        if let Some(lease) = lease {
            registration.device_stopped(lease.stopped()).unwrap();
        }
        registration.unregister(&watchdog()).unwrap();
        assert_eq!(release(arena), Ok(Released::Complete));
    }
}

/// Three passing verifies of one mapped registration with a device lease held: the second and the third keep
/// every answer the first one granted, so a revocation comes from a failed verify alone.
#[test]
fn a_repeated_passing_verify_keeps_readiness_and_the_reports_counts() {
    let (env, arena) = (Environment::detached(), new_arena());
    let mut registration = register(&env, &arena, &Fake::iommu(), IOMMU).unwrap();
    registration.map().unwrap();
    registration.verify().unwrap();
    let lease = registration.device_attached();
    let granted = Answers::read(&registration, Some(&lease));
    assert!(granted.granted(), "the first verify grants: {granted:?}");
    for repeat in ["second", "third"] {
        assert!(registration.verify().is_ok(), "the {repeat} verify passes");
        assert_eq!(
            Answers::read(&registration, Some(&lease)),
            granted,
            "the {repeat} verify keeps every answer"
        );
    }
    registration.device_stopped(lease.stopped()).unwrap();
    registration.unregister(&watchdog()).unwrap();
    assert_eq!(release(arena), Ok(Released::Complete));
}

/// `offsets` matches `iova` over each whole buffer, with distinct offsets on neighboring pages, for page-aligned runs, unaligned runs whose buffers cross a page boundary, buffers below the arena or past its end, a zero length, and an unverified registration.
#[test]
fn buffer_offsets_match_each_whole_buffers_iova() {
    let (env, arena) = (Environment::detached(), new_arena());
    let fake = Fake::no_iommu();
    fake.0.borrow_mut().reversed = true;
    let mut registration = register(&env, &arena, &fake, ALLOWLISTED).unwrap();
    registration.map().unwrap();
    registration.verify().unwrap();
    let (base, extent) = registration.range();
    let each = |registration: &ArenaRegistration<'_>, span: usize, len: usize, count: usize| {
        (0..count)
            .map(|index| {
                let addr = span + index * len;
                registration
                    .iova(addr, len)
                    .map(|iova| iova.wrapping_sub(addr as u64))
            })
            .collect::<Box<[_]>>()
    };
    let whole = registration.offsets(base, 4096, PAGES * PAGE / 4096);
    assert_ne!(
        whole[0],
        whole[PAGE / 4096],
        "neighboring pages have their own offsets"
    );
    let cases = [
        (base, 4096, PAGES * PAGE / 4096),
        (base + 1000, 4096, 2 * PAGE / 4096 + 4),
        (base + 3 * 4096, 3 * 4096, PAGES * PAGE / (3 * 4096) + 2),
        (base - 8192, 4096, 8),
        (base, PAGE, PAGES + 2),
        (base + PAGE / 2, PAGE, PAGES),
        (base + extent - 4096, 8192, 2),
        (base, 0, 4),
        (base, 4096, 0),
    ];
    for (span, len, count) in cases {
        assert_eq!(
            registration.offsets(span, len, count),
            each(&registration, span, len, count),
            "{count} buffers of {len} bytes at base + {}",
            span.wrapping_sub(base) as isize
        );
    }
    fake.0.borrow_mut().wrong_page = Some(1);
    registration.recheck().unwrap_err();
    assert!(
        registration
            .offsets(base, 4096, 8)
            .iter()
            .all(Option::is_none),
        "an unverified registration translates nothing"
    );
}

#[test]
fn an_unproven_device_stop_keeps_the_registration_and_backing_held() {
    let (env, arena) = (Environment::detached(), new_arena());
    let fake = Fake::iommu();
    let mut registration = register(&env, &arena, &fake, IOMMU).unwrap();
    registration.map().unwrap();
    registration.verify().unwrap();
    let stopped = registration.device_attached();
    let _live = registration.device_attached();
    registration.device_stopped(stopped.stopped()).unwrap();
    let retained = registration.unregister(&watchdog()).unwrap_err();
    assert_eq!(
        (retained.error.step, retained.error.retained),
        (RegistrationStep::DeviceStop, true)
    );
    assert_eq!(
        fake.calls(),
        FULL[..3],
        "nothing undone while one device may still reach the arena"
    );
    drop(retained);
    assert_eq!(release(arena), Err(1));
}

#[test]
fn a_stop_proof_from_another_registration_retires_no_device() {
    let env = Environment::detached();
    let (arena_a, arena_b) = (new_arena(), new_arena());
    let (fake_a, fake_b) = (Fake::iommu(), Fake::iommu());
    let mut a = register(&env, &arena_a, &fake_a, IOMMU).unwrap();
    let mut b = register(&env, &arena_b, &fake_b, IOMMU).unwrap();
    a.map().unwrap();
    let _live = a.device_attached();
    let lease_b = b.device_attached();
    let refused = a.device_stopped(lease_b.stopped()).unwrap_err();
    assert_eq!(
        (refused.step, refused.retained),
        (RegistrationStep::DeviceStop, false)
    );
    let retained = a.unregister(&watchdog()).unwrap_err();
    assert_eq!(
        (retained.error.step, retained.error.retained),
        (RegistrationStep::DeviceStop, true),
        "another registration's proof must not retire this registration's device"
    );
    assert_eq!(fake_a.calls(), FULL[..3]);
}

#[test]
fn a_failed_unmap_retains_the_registration_and_the_arena() {
    let (env, arena) = (Environment::detached(), new_arena());
    let fake = Fake::iommu();
    fake.fail(Call::Unmap, 5);
    let mut registration = register(&env, &arena, &fake, IOMMU).unwrap();
    registration.map().unwrap();
    let retained = registration.unregister(&watchdog()).unwrap_err();
    assert_eq!(
        (retained.error.step, retained.error.code),
        (RegistrationStep::Unmap, Some(5))
    );
    assert_eq!(
        retained.report().mappings,
        1,
        "the mapping is still reported in place"
    );
    assert_eq!(
        fake.calls(),
        [
            FULL[0],
            FULL[1],
            Call::Map,
            Call::SpdkUnregister,
            Call::Unmap
        ]
    );
    drop(retained);
    assert_eq!(release(arena), Err(1));
}

#[test]
fn a_dropped_guard_keeps_the_arena_unreleasable() {
    let (env, arena) = (Environment::detached(), new_arena());
    let fake = Fake::iommu();
    drop(register(&env, &arena, &fake, IOMMU).unwrap());
    assert_eq!(release(arena), Err(1));
}

#[test]
fn watchdog_expiry_requests_containment_and_retains_mapped_custody() {
    let (env, arena) = (Environment::detached(), new_arena());
    let fake = Fake::iommu();
    let (open, gate) = mpsc::channel();
    fake.0.borrow_mut().stall = Some((Call::SpdkUnregister, gate));
    let mut registration = register(&env, &arena, &fake, IOMMU).unwrap();
    registration.map().unwrap();
    registration.verify().unwrap();
    let supervisor = Arc::new(Recorder(Mutex::default(), Mutex::new(Some(open))));
    let watchdog = Watchdog::arm(Duration::from_millis(20), supervisor.clone()).unwrap();
    // The stalled unregister returns only once the supervisor was asked to contain.
    let retained = registration.unregister(&watchdog).unwrap_err();
    assert_eq!(supervisor.requests(), 1);
    assert_eq!(retained.error.step, RegistrationStep::Watchdog);
    assert_eq!(retained.report().mappings, 1, "no step after expiry ran");
    assert_eq!(
        fake.calls(),
        [FULL[0], FULL[1], Call::Map, Call::SpdkUnregister]
    );
    drop(retained);
    assert_eq!(release(arena), Err(1));
}

/// The posture truth table: VA with a guest IOMMU and VFIO's IOMMU mode, or,
/// on an allowlisted host, PA with no guest IOMMU and VFIO's no-IOMMU mode.
#[test]
fn posture_selection_admits_exactly_the_two_supported_combinations() {
    for iova in [IovaMode::Va, IovaMode::Pa, IovaMode::Undecided] {
        for guest_iommu in [false, true] {
            for no_iommu in [None, Some(false), Some(true)] {
                for policy in [IOMMU, ALLOWLISTED] {
                    let expected = match (iova, guest_iommu, no_iommu, policy.allow_no_iommu) {
                        (IovaMode::Va, true, Some(false), _) => Some(DmaMode::Iommu),
                        (IovaMode::Pa, false, Some(true), true) => Some(DmaMode::NoIommu),
                        _ => None,
                    };
                    assert_eq!(
                        DmaMode::select(iova, guest_iommu, no_iommu, policy),
                        expected,
                        "{iova:?} {guest_iommu} {no_iommu:?} {policy:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn a_failed_undo_step_names_the_step_and_keeps_the_arena_held() {
    for (call, done) in [(Call::SpdkUnregister, 3), (Call::ExtmemUnregister, 5)] {
        let (env, arena) = (Environment::detached(), new_arena());
        let fake = Fake::iommu();
        fake.fail(call, 16);
        let mut registration = register(&env, &arena, &fake, IOMMU).unwrap();
        registration.map().unwrap();
        let retained = registration.unregister(&watchdog()).unwrap_err();
        assert_eq!(
            (
                retained.error.step,
                retained.error.code,
                retained.error.retained
            ),
            (
                if call == Call::SpdkUnregister {
                    RegistrationStep::SpdkUnregister
                } else {
                    RegistrationStep::ExtmemUnregister
                },
                Some(16),
                true
            )
        );
        assert_eq!(fake.calls(), FULL[..=done]);
        drop(retained);
        assert_eq!(release(arena), Err(1));
    }
}

/// The environment refuses to finish while a registration's native state may exist, including after a retained failure.
#[test]
fn the_environment_cannot_finish_while_registration_state_may_exist() {
    let (env, arena) = (Environment::detached(), new_arena());
    let fake = Fake::iommu();
    fake.fail(Call::SpdkRegister, 12)
        .fail(Call::ExtmemUnregister, 16);
    assert!(register(&env, &arena, &fake, IOMMU).unwrap_err().retained);
    let Err(Unfinished::Registered(_still_up, 1)) = env.finish(&watchdog()) else {
        panic!("a live registration refuses the finish");
    };

    // A refused SPDK registration that recorded nothing undoes only the external memory and counts nothing.
    let other = Environment::detached();
    let arena = new_arena();
    let fake = Fake::iommu();
    fake.fail(Call::SpdkRegister, libc::EBUSY);
    assert!(!register(&other, &arena, &fake, IOMMU).unwrap_err().retained);
    assert_eq!(
        fake.calls(),
        [FULL[0], Call::SpdkRegister, Call::ExtmemUnregister]
    );
    assert_eq!(release(arena), Ok(Released::Complete));

    assert!(matches!(
        other.finish(&expired_watchdog()),
        Err(Unfinished::Expired(_))
    ));
}

/// A native failure that recorded no error number reports no code rather than a zero.
#[test]
fn a_failure_without_an_error_number_reports_no_code() {
    let (env, arena) = (Environment::detached(), new_arena());
    let fake = Fake::iommu();
    fake.fail(Call::Map, 0);
    let mut registration = register(&env, &arena, &fake, IOMMU).unwrap();
    let failed = registration.map().unwrap_err();
    assert_eq!((failed.step, failed.code), (RegistrationStep::Map, None));
}

/// A device-facing address comes from the explicit per-page IOVAs only after every page verified, and only for a range inside one backing page of the arena.
#[test]
fn iovas_translate_ranges_inside_one_verified_page() {
    let (env, arena) = (Environment::detached(), new_arena());
    let fake = Fake::no_iommu();
    let mut registration = register(&env, &arena, &fake, ALLOWLISTED).unwrap();
    let base = arena.backing().base().as_ptr().addr();
    assert_eq!(
        registration.iova(base, 64),
        None,
        "no address before verification"
    );
    registration.map().unwrap();
    registration.verify().unwrap();
    let iovas = fake.0.borrow().extmem.clone().unwrap().1;
    assert_eq!(
        registration.iova(base + PAGE + 10, 100),
        Some(iovas[1] + 10)
    );
    assert_eq!(
        registration.iova(base + PAGE - 8, 16),
        None,
        "a range crossing a page"
    );
    assert_eq!(
        registration.iova(base + PAGES * PAGE, 1),
        None,
        "past the arena"
    );
    assert_eq!(registration.iova(base - 1, 1), None, "before the arena");
    assert_eq!(registration.iova(base, 0), None, "an empty range");
    let lease = registration.device_attached();
    registration.device_stopped(lease.stopped()).unwrap();
    registration.unregister(&watchdog()).unwrap();
    assert_eq!(release(arena), Ok(Released::Complete));
}

/// A packet mempool needs a registration that verified every page, a device that registration leased, and its kind with every buffer free: construction refuses before any native call otherwise, ending the view it claimed.
#[test]
#[cfg_attr(
    miri,
    ignore = "the packet layout comes from a native size computation"
)]
fn packet_mempools_refuse_unverified_registrations_and_held_kinds() {
    use super::{MempoolError, PacketMempool};
    let pools = [
        PoolSpec {
            kind: PoolKind::PacketHeader,
            count: 4,
            buffer_len: 4096,
        },
        PoolSpec {
            kind: PoolKind::ReadResponse,
            count: 4,
            buffer_len: 4096,
        },
    ];
    let config = BufferConfig {
        hugepage: HugepageSize::TwoMiB,
        nodes: NodeMask::from_nodes(&[0]).unwrap(),
        pools: &pools,
    };
    let arena = BufferArena::initialize(
        &config.validate().unwrap(),
        TestPlatform::heap(4096),
        &mut EngineBudget::new(1 << 30),
    )
    .unwrap();
    let env = Environment::detached();
    let fake = Fake::no_iommu();
    let mut registration = register(&env, &arena, &fake, ALLOWLISTED).unwrap();
    let lease = registration.device_attached();
    assert_eq!(
        PacketMempool::header(
            &arena,
            &registration,
            &lease,
            c"t",
            &mut EngineBudget::unlimited()
        )
        .err(),
        Some(MempoolError::Unverified)
    );
    registration.map().unwrap();
    registration.verify().unwrap();
    let (elsewhere, elsewhere_fake) = (new_arena(), Fake::iommu());
    let mut foreign = register(&env, &elsewhere, &elsewhere_fake, IOMMU).unwrap();
    let foreign_lease = foreign.device_attached();
    assert_eq!(
        PacketMempool::header(
            &arena,
            &registration,
            &foreign_lease,
            c"t",
            &mut EngineBudget::unlimited()
        )
        .err(),
        Some(MempoolError::Device),
        "another registration's device"
    );
    foreign.device_stopped(foreign_lease.stopped()).unwrap();
    let held = arena.acquire(PoolKind::PacketHeader).unwrap();
    assert_eq!(
        PacketMempool::header(
            &arena,
            &registration,
            &lease,
            c"t",
            &mut EngineBudget::unlimited()
        )
        .err(),
        Some(MempoolError::Kind),
        "a held buffer"
    );
    drop(held);
    assert!(
        arena.acquire(PoolKind::PacketHeader).is_ok(),
        "a refused construction ends its view"
    );
    registration.device_stopped(lease.stopped()).unwrap();
    registration.unregister(&watchdog()).unwrap();
}

/// Each lease names its own device, and its stop proof names the same device, so two leases of one registration give proofs that tell their devices apart.
#[test]
fn stop_proofs_name_the_device_whose_lease_made_them() {
    let (env, arena) = (Environment::detached(), new_arena());
    let fake = Fake::iommu();
    let mut registration = register(&env, &arena, &fake, IOMMU).unwrap();
    let (first, second) = (
        registration.device_attached(),
        registration.device_attached(),
    );
    let (one, two) = (first.device(), second.device());
    assert_ne!(one, two, "each lease names its own device");
    let (first, second) = (first.stopped(), second.stopped());
    assert_eq!((first.device(), second.device()), (one, two));
    registration.device_stopped(first).unwrap();
    registration.device_stopped(second).unwrap();
}

/// A packet mempool frees itself only for the stop proof of the device it was built for: another device's proof, even one of the same registration, comes back with the pool, which stays armed while its kind stays served.
#[test]
#[cfg_attr(
    miri,
    ignore = "the packet layout comes from a native size computation"
)]
fn a_packet_mempool_refuses_another_devices_stop_proof() {
    let env = Environment::detached();
    let arena = super::mock::arena();
    let fake = Fake::iommu();
    let mut registration = register(&env, arena, &fake, IOMMU).unwrap();
    let nic = registration.device_attached();
    let other = registration.device_attached();
    let pool = super::mock::mempool(arena, PoolKind::PacketReceive, nic.device());
    let (pool, stopped) = pool.release(other.stopped()).unwrap_err();
    assert!(pool.armed(), "a refused release leaves the pool serving");
    assert!(
        arena.post(PoolKind::PacketReceive).is_err(),
        "the kind stays served"
    );
    registration.device_stopped(stopped).unwrap();
    drop(pool);
    registration.device_stopped(nic.stopped()).unwrap();
}

/// `release` returns the pool and its own device's stop proof while a receive buffer stays posted or a payload descriptor stays out. The pool stays armed, so the returns still end those postings.
#[test]
#[cfg_attr(
    miri,
    ignore = "the packet layout comes from a native size computation"
)]
fn a_packet_mempool_refuses_release_while_an_object_is_out() {
    use super::mempool::{PacketMempool, Role, entries};
    let env = Environment::detached();
    let arena = super::mock::arena();
    let fake = Fake::iommu();
    let mut registration = register(&env, arena, &fake, IOMMU).unwrap();
    let nic = registration.device_attached();
    let receive = super::mock::mempool(arena, PoolKind::PacketReceive, nic.device());
    let payload = super::mock::payload_pool(arena, 4);
    let payload = PacketMempool::mocked(payload.mp, payload.state, nic.device());
    let mut stopped = nic.stopped();
    for (pool, role) in [(receive, Role::Receive), (payload, Role::Payload)] {
        let (enqueue, dequeue) = entries(role);
        let mut out = [std::ptr::null_mut(); 2];
        // SAFETY: `out` holds two slots and the pool is a mock pool of its role's ops.
        assert_eq!(unsafe { dequeue(pool.as_ptr(), out.as_mut_ptr(), 2) }, 0);
        let (pool, proof) = pool.release(stopped).expect_err("two objects are out");
        stopped = proof;
        assert!(pool.armed(), "a refused release leaves the pool serving");
        // SAFETY: both objects came from the dequeue above and no device saw them.
        assert_eq!(unsafe { enqueue(pool.as_ptr(), out.as_ptr(), 2) }, 0);
        assert_eq!(
            pool.report(),
            super::mempool::OpsReport {
                returned: 2,
                stray: 0,
                refused: 0
            },
            "the returns still reach the state"
        );
        drop(pool);
    }
    assert_eq!(arena.report(PoolKind::PacketReceive).posted, 0);
    registration.device_stopped(stopped).unwrap();
}

/// Each packet mempool constructor charges its retained heap state before
/// it claims the kind, allocates or creates the native pool: a budget one byte short
/// refuses with the budget unchanged, nothing allocated and the kind still
/// free for a view; zero payload descriptors refuse first; and the payload
/// charge covers the padded descriptor stride, the descriptor stack and the
/// out flags.
#[test]
#[cfg_attr(
    miri,
    ignore = "the packet layout comes from a native size computation"
)]
fn packet_mempools_charge_before_any_claim_or_allocation() {
    use super::PacketMempool;
    use super::mempool::{MempoolError, OpsState};
    use crate::storage::device::{PRIVATE, object_overhead};
    let (env, arena) = (Environment::detached(), super::mock::arena());
    let registration = ready(&env, arena);
    let mut leases = registration;
    let lease = leases.device_attached();
    let registration = &leases;
    let state = size_of::<OpsState>();
    assert_eq!(PacketMempool::ARENA_CHARGE, state);
    let (header, trailer) = object_overhead();
    let stride = (header + size_of::<spdk_sys::rte_mbuf>() + PRIVATE + trailer).next_power_of_two();
    let backing = stride * 64;
    assert_eq!(
        PacketMempool::payload_charge(64),
        Some(state + 64 * 4 + 64 + backing),
        "the descriptor stack, the out flags and the padded descriptors"
    );
    assert_eq!(PacketMempool::payload_charge(0), None, "no descriptors");

    let refuses = |build: &dyn Fn(&mut EngineBudget) -> Result<(), MempoolError>,
                   limit: usize,
                   expected: fn(&MempoolError) -> bool| {
        let mut budget = EngineBudget::new(limit);
        let allocations = crate::instrument::allocations();
        let refused = build(&mut budget).expect_err("refused");
        assert!(expected(&refused), "{refused:?}");
        assert_eq!(
            crate::instrument::allocations(),
            allocations,
            "nothing allocated"
        );
        assert_eq!(budget, EngineBudget::new(limit), "the budget is unchanged");
    };
    let short = |e: &MempoolError| matches!(e, MempoolError::Budget(_));
    refuses(
        &|budget| PacketMempool::header(arena, registration, &lease, c"t", budget).map(drop),
        state - 1,
        short,
    );
    let view = crate::net::PacketPool::new(arena, PoolKind::PacketReceive, 2).unwrap();
    refuses(
        &|budget| PacketMempool::receive(&view, registration, &lease, c"t", budget).map(drop),
        state - 1,
        short,
    );
    refuses(
        &|budget| PacketMempool::payload(arena, registration, &lease, c"t", 64, budget).map(drop),
        state + 64 * 5 + backing - 1,
        short,
    );
    refuses(
        &|budget| PacketMempool::payload(arena, registration, &lease, c"t", 0, budget).map(drop),
        usize::MAX,
        |e| *e == MempoolError::Count,
    );
    assert!(
        arena.acquire(PoolKind::PacketHeader).is_ok(),
        "a refused header pool claims no view"
    );
    let served = arena.pools().pool(PoolKind::PacketReceive);
    assert!(
        served.claim_served(),
        "a refused receive pool claims no service"
    );
    served.end_served();
    drop(view);
    leases.device_stopped(lease.stopped()).unwrap();
}

/// Where an undo stops: an outstanding lease under a live or an expired
/// watchdog, the watchdog expiring before the first undo call or during
/// one, or one undo call failing. `Returned` and `ReturnedExpired` lease a
/// device and return its stop proof before the undo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cut {
    Leased,
    LeasedExpired,
    Returned,
    ReturnedExpired,
    ExpiredBeforeUndo,
    ExpiredDuring(Call),
    Fails(Call),
    None,
}

/// What one undo left: its error step and code, the mappings its retained
/// report names or zero on success, the
/// calls the fake saw, the registrations the environment still counts and
/// the arena's release outcome.
#[derive(Debug, PartialEq, Eq)]
struct Undo {
    step: Option<RegistrationStep>,
    code: Option<i32>,
    mappings: u32,
    calls: Vec<Call>,
    counted: u32,
    released: Result<(), u32>,
}

fn expired_watchdog() -> Watchdog {
    let expired = Watchdog::arm(Duration::ZERO, Arc::new(Recorder::new())).unwrap();
    while !expired.expired() {
        std::thread::yield_now();
    }
    expired
}

/// Registers, maps and verifies a fresh arena in `mode`, cuts its undo at
/// `cut`, and reports what the undo left. A stalled call waits for the
/// watchdog's containment request, which follows its expiry, so the
/// expiry lands during that call.
fn undo_at(mode: DmaMode, cut: Cut) -> Undo {
    let (env, arena) = (Environment::detached(), new_arena());
    let (fake, policy) = match mode {
        DmaMode::Iommu => (Fake::iommu(), IOMMU),
        DmaMode::NoIommu => (Fake::no_iommu(), ALLOWLISTED),
    };
    let mut registration = register(&env, &arena, &fake, policy).unwrap();
    registration.map().unwrap();
    registration.verify().unwrap();
    let lease = match cut {
        Cut::Leased | Cut::LeasedExpired => Some(registration.device_attached()),
        Cut::Returned | Cut::ReturnedExpired => {
            let lease = registration.device_attached();
            registration.device_stopped(lease.stopped()).unwrap();
            None
        }
        _ => None,
    };
    let watchdog = match cut {
        Cut::ExpiredBeforeUndo | Cut::LeasedExpired | Cut::ReturnedExpired => expired_watchdog(),
        Cut::ExpiredDuring(call) => {
            let (open, gate) = mpsc::channel();
            fake.0.borrow_mut().stall = Some((call, gate));
            let supervisor = Arc::new(Recorder(Mutex::default(), Mutex::new(Some(open))));
            Watchdog::arm(Duration::from_millis(20), supervisor).unwrap()
        }
        Cut::Fails(call) => {
            fake.fail(call, 16);
            watchdog()
        }
        Cut::Leased | Cut::Returned | Cut::None => watchdog(),
    };
    let (step, code, mappings) = match registration.unregister(&watchdog) {
        Ok(_) => (None, None, 0),
        Err(retained) => {
            assert!(retained.error.retained, "{cut:?}");
            let error = retained.error;
            (Some(error.step), error.code, retained.report().mappings)
        }
    };
    drop(watchdog);
    // The count and the arena's hold belong to the registration, so they outlast the lease value.
    drop(lease);
    // `finish` refuses on a live registration before it reads the watchdog,
    // so an expired one tells the count apart without running a finalizer.
    let counted = match env.finish(&expired_watchdog()) {
        Err(Unfinished::Registered(_, count)) => count,
        Err(Unfinished::Expired(_)) => 0,
        other => panic!("{cut:?}: {other:?}"),
    };
    Undo {
        step,
        code,
        mappings,
        calls: fake.calls(),
        counted,
        released: release(arena).map(drop),
    }
}

/// Every cut short of a complete undo, in both DMA modes, leaves the
/// registration retained, the environment counting it and the arena held,
/// with the mappings the native steps left: a failed unmap keeps one, a
/// completed unmap leaves zero though the registration stays retained, and
/// no-IOMMU mode reports zero mappings and undoes through the SPDK and
/// external-memory unregisters alone. A device not proven stopped refuses
/// before any undo call, under an expired watchdog too, and an expiry
/// after the external memory's unregister still retains. Only the complete
/// undo clears the count and releases the arena.
#[test]
fn only_a_complete_undo_releases_and_every_cut_retains_the_hold_and_count() {
    use Call::{ExtmemUnregister as Extmem, Map, SpdkUnregister as Spdk, Unmap};
    use DmaMode::{Iommu, NoIommu};
    use RegistrationStep as Step;
    type Row = (DmaMode, Cut, Option<RegistrationStep>, u32, &'static [Call]);
    let rows: [Row; 22] = [
        (Iommu, Cut::Leased, Some(Step::DeviceStop), 1, &[]),
        (Iommu, Cut::LeasedExpired, Some(Step::DeviceStop), 1, &[]),
        (Iommu, Cut::ReturnedExpired, Some(Step::Watchdog), 1, &[]),
        (Iommu, Cut::Returned, None, 0, &[Spdk, Unmap, Extmem]),
        (Iommu, Cut::ExpiredBeforeUndo, Some(Step::Watchdog), 1, &[]),
        (
            Iommu,
            Cut::Fails(Spdk),
            Some(Step::SpdkUnregister),
            1,
            &[Spdk],
        ),
        (
            Iommu,
            Cut::ExpiredDuring(Spdk),
            Some(Step::Watchdog),
            1,
            &[Spdk],
        ),
        (
            Iommu,
            Cut::Fails(Unmap),
            Some(Step::Unmap),
            1,
            &[Spdk, Unmap],
        ),
        (
            Iommu,
            Cut::ExpiredDuring(Unmap),
            Some(Step::Watchdog),
            0,
            &[Spdk, Unmap],
        ),
        (
            Iommu,
            Cut::Fails(Extmem),
            Some(Step::ExtmemUnregister),
            0,
            &[Spdk, Unmap, Extmem],
        ),
        (
            Iommu,
            Cut::ExpiredDuring(Extmem),
            Some(Step::Watchdog),
            0,
            &[Spdk, Unmap, Extmem],
        ),
        (Iommu, Cut::None, None, 0, &[Spdk, Unmap, Extmem]),
        (NoIommu, Cut::Leased, Some(Step::DeviceStop), 0, &[]),
        (NoIommu, Cut::LeasedExpired, Some(Step::DeviceStop), 0, &[]),
        (NoIommu, Cut::ReturnedExpired, Some(Step::Watchdog), 0, &[]),
        (NoIommu, Cut::Returned, None, 0, &[Spdk, Extmem]),
        (
            NoIommu,
            Cut::ExpiredBeforeUndo,
            Some(Step::Watchdog),
            0,
            &[],
        ),
        (
            NoIommu,
            Cut::Fails(Spdk),
            Some(Step::SpdkUnregister),
            0,
            &[Spdk],
        ),
        (
            NoIommu,
            Cut::ExpiredDuring(Spdk),
            Some(Step::Watchdog),
            0,
            &[Spdk],
        ),
        (
            NoIommu,
            Cut::Fails(Extmem),
            Some(Step::ExtmemUnregister),
            0,
            &[Spdk, Extmem],
        ),
        (
            NoIommu,
            Cut::ExpiredDuring(Extmem),
            Some(Step::Watchdog),
            0,
            &[Spdk, Extmem],
        ),
        (NoIommu, Cut::None, None, 0, &[Spdk, Extmem]),
    ];
    for (mode, cut, step, mappings, undo) in rows {
        let setup: &[Call] = match mode {
            Iommu => &[FULL[0], FULL[1], Map],
            NoIommu => &[FULL[0], FULL[1]],
        };
        let complete = step.is_none();
        let expected = Undo {
            step,
            code: matches!(cut, Cut::Fails(_)).then_some(16),
            mappings,
            calls: [setup, undo].concat(),
            counted: u32::from(!complete),
            released: if complete { Ok(()) } else { Err(1) },
        };
        assert_eq!(undo_at(mode, cut), expected, "{mode:?} {cut:?}");
    }
}

/// Registers an arena of `pages` backing pages in IOMMU mode, maps it, and checks the one container mapping the fake recorded against the arena's own base and extent, then that a second map leaves the record unchanged and the undo removes the same range.
fn mapping_covers(pages: usize) {
    let (env, arena) = (Environment::detached(), wide_arena(pages));
    let hold = arena.hold_registration();
    let (base, extent) = {
        let backing = hold.backing();
        (backing.base().as_ptr().addr(), backing.extent())
    };
    assert_eq!(extent, pages * PAGE, "the arena has {pages} backing pages");

    let fake = Fake::iommu();
    let mut registration =
        ArenaRegistration::register_with(&env, hold, IOMMU, Box::new(fake.clone())).unwrap();
    assert_eq!(registration.report().mode, DmaMode::Iommu);
    assert_eq!(
        fake.0.borrow().registered,
        Some((base, extent)),
        "the registered extent is the arena"
    );
    assert!(fake.0.borrow().maps.is_empty(), "no mapping before map");

    registration.map().unwrap();
    let maps = fake.0.borrow().maps.clone();
    assert_eq!(maps.len(), 1, "one container mapping: {maps:x?}");
    let (va, iova, len) = maps[0];
    assert_eq!(va, base, "the mapping starts at the arena's base");
    assert_eq!(
        len, extent,
        "the mapping's length is the arena's whole extent of {pages} pages"
    );
    assert_eq!(va + len, base + pages * PAGE, "the last page is mapped");
    assert_eq!(iova, base as u64, "the IOVA is the virtual address");
    assert_eq!(registration.report().mappings, 1);

    assert!(
        registration.map().is_err(),
        "a second map is refused and maps nothing"
    );
    assert_eq!(fake.0.borrow().maps, [(base, base as u64, extent)]);

    registration.unregister(&watchdog()).unwrap();
    assert_eq!(
        fake.0.borrow().unmaps,
        [(base, base as u64, extent)],
        "undo removes the same range"
    );
}

/// The mapping of an arena of one backing page is that page: a mapping one page short would be empty.
#[test]
fn one_container_mapping_covers_an_arena_of_one_backing_page() {
    mapping_covers(1);
}

/// The mapping of an arena of three backing pages starts at the arena's base and reaches the end of its third page, so no buffer of the arena lies outside the one IOMMU mapping.
#[test]
fn one_container_mapping_covers_an_arena_of_three_backing_pages() {
    mapping_covers(3);
}
