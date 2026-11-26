//! Scripted native steps and a local latch drive environment initialization
//! through its production coordinator.

use std::ffi::{CStr, OsStr};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use spdk_sys as sys;

use super::{EnvConfig, EnvError, EnvSteps, Environment, Finalizer, PciAddress};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    PreInit,
    Init,
    Timers,
    Core,
    Finalize(Finalizer),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Options {
    name: String,
    core_mask: String,
    main_core: i32,
    shm_id: i32,
    hugedir: String,
    env_context: String,
    no_pci: bool,
    allowed: Vec<(u32, u8, u8, u8)>,
}

struct Script {
    latch: Arc<AtomicBool>,
    pre_init: Result<(), i32>,
    init: i32,
    timers: i32,
    core: u32,
    steps: Vec<Step>,
    options: Option<Options>,
}

impl Script {
    fn healthy(core: u32) -> Self {
        Self {
            latch: Arc::new(AtomicBool::new(false)),
            pre_init: Ok(()),
            init: 0,
            timers: 0,
            core,
            steps: Vec::new(),
            options: None,
        }
    }

    fn step(&mut self, step: Step) {
        self.steps.push(step);
    }
}

/// # Safety
///
/// The caller must ensure `ptr` points to a NUL-terminated string that lives
/// for the call.
unsafe fn text(ptr: *const libc::c_char) -> String {
    // SAFETY: the caller guarantees that `ptr` points to a NUL-terminated
    // string valid for this call.
    unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned()
}

impl EnvSteps for Script {
    fn latch(&self) -> &AtomicBool {
        &self.latch
    }

    fn pre_init(&mut self) -> Result<(), i32> {
        self.step(Step::PreInit);
        self.pre_init
    }

    unsafe fn init(&mut self, opts: &sys::spdk_env_opts) -> (i32, String) {
        self.step(Step::Init);
        let allowed = if opts.pci_allowed.is_null() {
            Vec::new()
        } else {
            // SAFETY: the caller's contract: `pci_allowed` points at
            // `num_pci_addr` addresses that outlive this call.
            unsafe { std::slice::from_raw_parts(opts.pci_allowed, opts.num_pci_addr) }
                .iter()
                .map(|a| (a.domain, a.bus, a.dev, a.func))
                .collect()
        };
        // SAFETY: the caller's contract: each string field points at a
        // NUL-terminated string that outlives this call.
        let options = unsafe {
            Options {
                name: text(opts.name),
                core_mask: text(opts.core_mask),
                main_core: opts.main_core,
                shm_id: opts.shm_id,
                hugedir: text(opts.hugedir),
                env_context: text(opts.env_context.cast_const().cast()),
                no_pci: opts.no_pci,
                allowed,
            }
        };
        self.options = Some(options);
        (self.init, "probe report\n".into())
    }

    unsafe fn init_timers(&mut self) -> i32 {
        self.step(Step::Timers);
        self.timers
    }

    fn core(&mut self) -> u32 {
        self.step(Step::Core);
        self.core
    }

    unsafe fn finalize(&mut self, finalizer: Finalizer) {
        self.step(Step::Finalize(finalizer));
    }
}

const CORE: u32 = 3;
const ALLOWED: [PciAddress; 2] = [
    PciAddress {
        domain: 0,
        bus: 0x1f,
        device: 0,
        function: 0,
    },
    PciAddress {
        domain: 1,
        bus: 6,
        device: 2,
        function: 1,
    },
];

fn config(allowed: &[PciAddress]) -> EnvConfig<'_> {
    EnvConfig {
        core: CORE,
        hugepage_dir: Path::new("/dev/hugepages"),
        allowed,
    }
}

#[derive(Debug, Clone)]
struct Observed {
    result: Result<(), EnvError>,
    steps: Vec<Step>,
    options: Option<Options>,
    latched: bool,
}

fn attempt(config: &EnvConfig<'_>, latch: &Arc<AtomicBool>, script: &mut Script) -> Observed {
    script.latch = Arc::clone(latch);
    let result = Environment::initialize_with(config, script).map(|env| {
        assert_eq!(env.probe_log(), "probe report\n");
    });
    Observed {
        result,
        steps: std::mem::take(&mut script.steps),
        options: script.options.take(),
        latched: latch.load(Ordering::Acquire),
    }
}

struct Case {
    name: &'static str,
    script: Script,
    result: Result<(), EnvError>,
    steps: &'static [Step],
}

const THROUGH_CORE: &[Step] = &[Step::PreInit, Step::Init, Step::Timers, Step::Core];

fn cases() -> Vec<Case> {
    let with = |change: fn(&mut Script)| {
        let mut script = Script::healthy(CORE);
        change(&mut script);
        script
    };
    vec![
        Case {
            name: "pre-init failure",
            script: with(|s| s.pre_init = Err(-libc::EEXIST)),
            result: Err(EnvError::PreInit(-libc::EEXIST)),
            steps: &[Step::PreInit],
        },
        Case {
            name: "environment init failure",
            script: with(|s| s.init = -libc::ENODEV),
            result: Err(EnvError::Init(-libc::ENODEV)),
            steps: &[Step::PreInit, Step::Init],
        },
        Case {
            name: "timer failure",
            script: with(|s| s.timers = -libc::ENOMEM),
            result: Err(EnvError::Timers(-libc::ENOMEM)),
            steps: &[
                Step::PreInit,
                Step::Init,
                Step::Timers,
                Step::Finalize(Finalizer::Environment),
            ],
        },
        Case {
            name: "timers already initialized",
            script: with(|s| s.timers = -libc::EALREADY),
            result: Ok(()),
            steps: THROUGH_CORE,
        },
        Case {
            name: "wrong core",
            script: with(|s| s.core = CORE + 1),
            result: Err(EnvError::Core {
                expected: CORE,
                found: CORE + 1,
            }),
            steps: &[
                Step::PreInit,
                Step::Init,
                Step::Timers,
                Step::Core,
                Step::Finalize(Finalizer::Timers),
                Step::Finalize(Finalizer::Environment),
            ],
        },
        Case {
            name: "success",
            script: Script::healthy(CORE),
            result: Ok(()),
            steps: THROUGH_CORE,
        },
    ]
}

#[derive(Debug, PartialEq, Eq)]
enum Mismatch {
    Result(Result<(), EnvError>),
    Steps(Vec<Step>),
    LatchClear,
    Options(Box<Option<Options>>),
}

fn judge(case: &Case, observed: &Observed, allowed: &[PciAddress]) -> Result<(), Mismatch> {
    if observed.result != case.result {
        return Err(Mismatch::Result(observed.result));
    }
    if observed.steps != case.steps {
        return Err(Mismatch::Steps(observed.steps.clone()));
    }
    if !observed.latched {
        return Err(Mismatch::LatchClear);
    }
    let expected = case.steps.contains(&Step::Init).then(|| options(allowed));
    if observed.options != expected {
        return Err(Mismatch::Options(Box::new(observed.options.clone())));
    }
    Ok(())
}

/// A valid attempt after a latched outcome refuses, calls no step and
/// leaves the latch set.
fn judge_retry(observed: &Observed) -> Result<(), Mismatch> {
    if observed.result != Err(EnvError::AlreadyInitialized) {
        return Err(Mismatch::Result(observed.result));
    }
    if !observed.steps.is_empty() {
        return Err(Mismatch::Steps(observed.steps.clone()));
    }
    if !observed.latched {
        return Err(Mismatch::LatchClear);
    }
    Ok(())
}

fn options(allowed: &[PciAddress]) -> Options {
    Options {
        name: "kestrike".into(),
        core_mask: format!("[{CORE}]"),
        main_core: i32::try_from(CORE).unwrap(),
        shm_id: -1,
        hugedir: "/dev/hugepages".into(),
        env_context: "--log-level=pmd.net.ena.driver:info".into(),
        no_pci: allowed.is_empty(),
        allowed: allowed
            .iter()
            .map(|a| (a.domain, a.bus, a.device, a.function))
            .collect(),
    }
}

#[test]
fn every_initialization_branch_latches_once_and_finalizes_in_reverse() {
    for allowed in [&[][..], &ALLOWED[..]] {
        let config = config(allowed);
        for mut case in cases() {
            let latch = Arc::new(AtomicBool::new(false));
            let observed = attempt(&config, &latch, &mut case.script);
            assert_eq!(judge(&case, &observed, allowed), Ok(()), "{}", case.name);
            let again = attempt(&config, &latch, &mut Script::healthy(CORE));
            assert_eq!(judge_retry(&again), Ok(()), "{}", case.name);
        }
    }
}

/// Entrants that race on one latch elect one winner: exactly one runs the
/// native steps, and every other refuses `AlreadyInitialized` before any
/// step, whichever thread's swap lands first.
#[test]
fn concurrent_entrants_elect_one_native_initializer() {
    const ENTRANTS: usize = 8;
    let config = config(&[]);
    let latch = Arc::new(AtomicBool::new(false));
    let start = std::sync::Barrier::new(ENTRANTS);
    let observed: Vec<Observed> = std::thread::scope(|scope| {
        let entrants: Vec<_> = (0..ENTRANTS)
            .map(|_| {
                scope.spawn(|| {
                    let mut script = Script::healthy(CORE);
                    start.wait();
                    attempt(&config, &latch, &mut script)
                })
            })
            .collect();
        entrants
            .into_iter()
            .map(|entrant| entrant.join().unwrap())
            .collect()
    });
    let (winners, refused): (Vec<_>, Vec<_>) = observed
        .iter()
        .partition(|observed| observed.result.is_ok());
    assert_eq!(winners.len(), 1, "one entrant wins the latch");
    assert_eq!(winners[0].steps, THROUGH_CORE);
    for observed in refused {
        assert_eq!(judge_retry(observed), Ok(()));
    }
}

#[test]
fn an_invalid_configuration_calls_no_step_and_leaves_the_latch_clear() {
    let nul = OsStr::from_bytes(b"/dev/huge\0pages");
    let not_utf8 = OsStr::from_bytes(b"/dev/huge\xffpages");
    let invalid = [
        EnvConfig {
            hugepage_dir: Path::new(nul),
            ..config(&[])
        },
        EnvConfig {
            hugepage_dir: Path::new(not_utf8),
            ..config(&[])
        },
        EnvConfig {
            core: sys::RTE_MAX_LCORE,
            ..config(&[])
        },
    ];
    let latch = Arc::new(AtomicBool::new(false));
    let mut script = Script::healthy(CORE);
    for config in &invalid {
        let observed = attempt(config, &latch, &mut script);
        assert_eq!(observed.result, Err(EnvError::Config), "{config:?}");
        assert!(observed.steps.is_empty(), "{config:?}");
        assert!(!observed.latched, "{config:?}");
        assert_eq!(
            Environment::initialize(config).err(),
            Some(EnvError::Config),
            "{config:?}: the public entry refuses the same configuration"
        );
    }
    let valid = attempt(&config(&[]), &latch, &mut script);
    assert_eq!(valid.result, Ok(()));
    assert_eq!(valid.steps, THROUGH_CORE);
    for config in &invalid {
        let observed = attempt(config, &latch, &mut script);
        assert_eq!(observed.result, Err(EnvError::Config), "{config:?}");
        assert!(observed.steps.is_empty(), "{config:?}");
        assert!(observed.latched, "{config:?}");
    }
}

#[test]
fn the_judges_reject_a_reset_latch_a_skipped_finalizer_and_a_reversed_order() {
    let mut cases = cases();
    let wrong_core = cases
        .iter_mut()
        .find(|case| case.name == "wrong core")
        .unwrap();
    let latch = Arc::new(AtomicBool::new(false));
    let observed = attempt(&config(&[]), &latch, &mut wrong_core.script);
    let wrong_core = &*wrong_core;
    assert_eq!(judge(wrong_core, &observed, &[]), Ok(()));
    let cleared = Observed {
        latched: false,
        ..observed.clone()
    };
    assert_eq!(judge(wrong_core, &cleared, &[]), Err(Mismatch::LatchClear));
    let again = attempt(&config(&[]), &latch, &mut Script::healthy(CORE));
    assert_eq!(judge_retry(&again), Ok(()));
    let rerun = Observed {
        result: Ok(()),
        steps: THROUGH_CORE.to_vec(),
        options: Some(options(&[])),
        latched: true,
    };
    assert_eq!(judge_retry(&rerun), Err(Mismatch::Result(Ok(()))));
    let mut skipped = observed.clone();
    skipped.steps.pop();
    assert!(
        matches!(judge(wrong_core, &skipped, &[]), Err(Mismatch::Steps(_))),
        "a skipped environment finalizer"
    );
    let mut reversed = observed;
    reversed.steps[4..].reverse();
    assert!(
        matches!(judge(wrong_core, &reversed, &[]), Err(Mismatch::Steps(_))),
        "the environment finalized before the timers"
    );
}
