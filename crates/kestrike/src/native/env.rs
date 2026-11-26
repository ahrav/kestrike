//! The process's one SPDK and DPDK environment.
//!
//! [`Environment::initialize`] runs the pre-init hooks, then SPDK's
//! environment init (which initializes DPDK's EAL), then DPDK's timer
//! subsystem, and checks that the calling thread runs as the configured
//! core. The native log of initialization, which carries each device
//! driver's probe report, is captured and kept, then written to standard
//! error. [`Environment::finish`] refuses while a registration made through
//! the environment is live, then finalizes the timers and the environment
//! under the caller's watchdog. A refusal returns the live environment; a
//! watchdog expiry after the timer finalizer returns a [`Contained`] value
//! whose one operation is drop. The first `initialize` past configuration
//! checks latches the process, so every later `initialize` that passes
//! configuration checks returns `AlreadyInitialized`, whatever the earlier
//! outcome.

use std::cell::Cell;
use std::ffi::CString;
use std::marker::PhantomData;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use spdk_sys as sys;

use super::watchdog::Watchdog;

/// Runs before SPDK's environment init, in order. Mempool ops register here,
/// before any pool exists, because a pool resolves its ops by name when it is
/// created and cannot change them afterward.
const PRE_INIT: &[fn() -> Result<(), i32>] = &[super::mempool::register];

/// A PCI address, `domain:bus:device.function`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciAddress {
    pub domain: u32,
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

/// What the environment may use. `allowed` lists the only PCI devices the
/// process may attach; with none, PCI is disabled. DPDK's native
/// allocations draw from the hugepages under `hugepage_dir`, the host's pool
/// that every owner process shares; a process's native use grows until that
/// pool is exhausted.
#[derive(Debug, Clone)]
pub struct EnvConfig<'a> {
    /// The core of the thread that initializes and owns the environment.
    pub core: u32,
    pub hugepage_dir: &'a Path,
    pub allowed: &'a [PciAddress],
}

/// A refused or failed initialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvError {
    /// The process already initialized an environment, live, failed or finished.
    AlreadyInitialized,
    /// The hugepage directory is invalid UTF-8 or contains a NUL byte, or
    /// `core` is at least `RTE_MAX_LCORE`.
    Config,
    /// A pre-init hook failed with this code; SPDK's environment init never ran.
    PreInit(i32),
    /// SPDK's environment init failed with this code.
    Init(i32),
    /// The timer subsystem failed with this code; the environment was finalized.
    Timers(i32),
    /// The calling thread is not the configured core; the timers and the
    /// environment were finalized.
    Core { expected: u32, found: u32 },
}

/// A finish that stopped short of finalizing the environment, or whose
/// watchdog had expired when the environment finalizer returned. A refusal
/// returns the environment live and unchanged, and a later finish with no
/// live registration, under an unexpired watchdog, completes it.
#[derive(Debug)]
pub enum Unfinished {
    /// Refused before either finalizer: this many registrations made through
    /// the environment are still live.
    Registered(Environment, u32),
    /// Refused before either finalizer: the watchdog had expired.
    Expired(Environment),
    /// The watchdog expired after finish finalized the timer subsystem; see
    /// [`Contained`].
    Contained(Contained),
}

/// The outcome of a finish that finalized the timer subsystem and then found
/// its watchdog expired. Found before the environment finalizer, the expiry
/// leaves the rest of the native environment initialized; found once that
/// finalizer returned, it leaves the environment finalized. The native state
/// stays as it is for the supervisor's containment and for the rest of the
/// process's life. This value marks that state; its only operation is drop,
/// which runs no finalizer and leaves the native state as it is. It is a
/// distinct type with no methods and no conversion to [`Environment`], so
/// every environment operation rejects it.
///
/// The type system rejects registration, finish and conversion back to an
/// environment:
///
/// ```compile_fail,E0308
/// # use kestrike::native::*;
/// # use kestrike::storage::*;
/// # fn f(contained: Contained, arena: &BufferArena<LinuxPlatform>, policy: DmaPolicy) {
/// let _ = ArenaRegistration::register(&contained, arena, policy);
/// # }
/// ```
///
/// ```compile_fail,E0599
/// # use kestrike::native::*;
/// # fn f(contained: Contained, watchdog: &Watchdog) {
/// let _ = contained.finish(watchdog);
/// # }
/// ```
///
/// ```compile_fail,E0308
/// # use kestrike::native::*;
/// # fn f(contained: Contained) -> Environment {
/// Environment::from(contained)
/// # }
/// ```
///
/// Stable rustdoc checks that each example fails to compile;
/// `cargo +nightly test --doc` also matches each error code against its
/// stated cause.
#[derive(Debug)]
#[must_use = "a contained finish leaves the native state as it is for the supervisor"]
pub struct Contained {
    _owner_thread: PhantomData<*mut ()>,
}

// A contained value's drop runs no code, so it runs no finalizer.
const _: () = assert!(!std::mem::needs_drop::<Contained>());

/// The native finalizers finish runs, in this order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Finalizer {
    /// `rte_timer_subsystem_finalize`.
    Timers,
    /// `spdk_env_fini`.
    Environment,
}

/// The process's initialization latch. Only [`Native`] lends it, so only
/// [`Environment::initialize`] writes it, once its configuration checks
/// pass, and it stays set for the life of the process, so after any finish
/// outcome a later `initialize` with a valid configuration returns
/// `AlreadyInitialized`.
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// The native steps of initialization, in the order
/// [`Environment::initialize_with`] calls them, and the finalizers that
/// [`Environment::finish`] also runs. [`Native`] binds the process's SPDK
/// and DPDK calls; a test binds a script, so every branch of the one
/// coordinator runs without native environment state. The coordinator
/// fills the options' defaults itself through `spdk_env_opts_init`, which
/// writes only the structure it receives.
trait EnvSteps {
    /// The latch these steps initialize under. The coordinator sets it
    /// before the first step, and a latch already set refuses the attempt.
    fn latch(&self) -> &AtomicBool;
    /// Runs the pre-init hooks in order and returns the first failure.
    fn pre_init(&mut self) -> Result<(), i32>;
    /// Runs SPDK's environment init with `opts` and returns its result
    /// with the native log it wrote.
    ///
    /// # Safety
    ///
    /// Every string and array `opts` points to is valid and outlives the
    /// call, and the swap that set [`latch`](Self::latch) admitted this
    /// init.
    unsafe fn init(&mut self, opts: &sys::spdk_env_opts) -> (i32, String);
    /// Runs DPDK's timer subsystem init and returns its result.
    ///
    /// # Safety
    ///
    /// [`init`](Self::init) returned 0 on this thread.
    unsafe fn init_timers(&mut self) -> i32;
    /// The calling thread's lcore identity.
    fn core(&mut self) -> u32;
    /// Runs one finalizer.
    ///
    /// # Safety
    ///
    /// No DPDK timer or memory user is live. [`Finalizer::Timers`] runs
    /// only after [`init_timers`](Self::init_timers) returned 0 or
    /// `-EALREADY`; [`Finalizer::Environment`] runs only after
    /// [`init`](Self::init) returned 0 and the timers are finalized or
    /// failed to initialize.
    unsafe fn finalize(&mut self, finalizer: Finalizer);
}

/// The process's SPDK and DPDK calls under the process latch. Only this
/// module names the type, and its two call sites are
/// [`Environment::initialize`] and [`Environment::finish`]; each places
/// every step where its native call's safety requires.
struct Native;

impl EnvSteps for Native {
    fn latch(&self) -> &AtomicBool {
        &INITIALIZED
    }

    fn pre_init(&mut self) -> Result<(), i32> {
        PRE_INIT.iter().try_for_each(|hook| hook())
    }

    unsafe fn init(&mut self, opts: &sys::spdk_env_opts) -> (i32, String) {
        // SAFETY: the caller's contract.
        let (rc, probe_log) = capture(|| unsafe { sys::spdk_env_init(opts) });
        echo(&probe_log);
        (rc, probe_log)
    }

    unsafe fn init_timers(&mut self) -> i32 {
        // SAFETY: the caller's contract.
        unsafe { sys::rte_timer_subsystem_init() }
    }

    fn core(&mut self) -> u32 {
        // SAFETY: reads this thread's lcore identity.
        unsafe { sys::spdk_sys_rte_lcore_id() }
    }

    unsafe fn finalize(&mut self, finalizer: Finalizer) {
        match finalizer {
            // SAFETY: the caller's contract.
            Finalizer::Timers => unsafe { sys::rte_timer_subsystem_finalize() },
            // SAFETY: the caller's contract.
            Finalizer::Environment => unsafe { sys::spdk_env_fini() },
        }
    }
}

/// Maps the timer init result, counting `-EALREADY` as ready: another
/// component of the process initialized the timer subsystem first.
fn timers_ready(rc: i32) -> Result<(), i32> {
    if rc == 0 || rc == -libc::EALREADY {
        Ok(())
    } else {
        Err(rc)
    }
}

/// Extra native arguments: the ENA driver logs its transmit placement policy and LLQ entry size at this level.
const PROBE_LOG_LEVEL: &std::ffi::CStr = c"--log-level=pmd.net.ena.driver:info";

unsafe extern "C" {
    fn flockfile(stream: *mut libc::FILE);
    fn funlockfile(stream: *mut libc::FILE);
}

/// Points DPDK's log back at standard error when dropped, unwinding included.
struct RestoreLog;

impl Drop for RestoreLog {
    fn drop(&mut self) {
        // SAFETY: a null stream selects standard error.
        unsafe { sys::rte_openlog_stream(std::ptr::null_mut()) };
    }
}

/// The process's one memory stream for captured DPDK logs, and the cell
/// holding its buffer and length, both allocated for the process: a thread
/// that read DPDK's log stream before a restore may still write to it,
/// under the stream's lock.
struct Captured {
    stream: *mut libc::FILE,
    cell: *mut (*mut libc::c_char, libc::size_t),
}

// SAFETY: the stream is used only under its own lock, and the cell only by the stream and under that lock.
unsafe impl Send for Captured {}
// SAFETY: as for `Send`.
unsafe impl Sync for Captured {}

/// Opens the capture stream on first use; `None` when `open_memstream` fails.
fn captured() -> Option<&'static Captured> {
    static STREAM: std::sync::OnceLock<Option<Captured>> = std::sync::OnceLock::new();
    STREAM
        .get_or_init(|| {
            let cell = Box::into_raw(Box::new((std::ptr::null_mut(), 0)));
            // SAFETY: the leaked cell outlives the stream, which is never closed.
            let stream = unsafe { libc::open_memstream(&raw mut (*cell).0, &raw mut (*cell).1) };
            (!stream.is_null()).then_some(Captured { stream, cell })
        })
        .as_ref()
}

impl Captured {
    /// Runs `read` with the stream's buffer and length after a flush, all
    /// under the stream's lock, so no writer moves the buffer meanwhile.
    fn flushed<R>(&self, read: impl FnOnce(*mut libc::c_char, libc::size_t) -> R) -> R {
        // SAFETY: the stream is open for the process; holding its lock, the flush updates the cell to the bytes written since the rewind.
        unsafe {
            flockfile(self.stream);
            libc::fflush(self.stream);
            let (buf, len) = *self.cell;
            let read = read(buf, len);
            funlockfile(self.stream);
            read
        }
    }
}

/// The capture stream's buffer after a flush under its lock: where the
/// stream's bytes live now. `None` when the stream failed to open.
#[cfg(test)]
pub(crate) fn capture_buffer() -> Option<*const libc::c_char> {
    Some(captured()?.flushed(|buf, _| buf.cast_const()))
}

/// Frees the capture cell while the stream still names it, so the next
/// capture's read of the cell is a use after free that address sanitizer
/// reports.
///
/// # Safety
///
/// Every later use of the capture stream in this process is undefined.
/// Call it only in a child process that ends at the sanitizer's report.
#[cfg(all(test, kestrike_asan))]
pub(crate) unsafe fn release_capture_cell() {
    if let Some(captured) = captured() {
        // SAFETY: the cell came from `Box::into_raw` in `captured`; the caller accepts its dangling uses.
        drop(unsafe { Box::from_raw(captured.cell) });
    }
}

/// Runs `f` with DPDK's log written to memory, and returns its result and
/// the log written meanwhile, by any thread. Captures run one at a time,
/// each rewinding the one process-wide stream, so its buffer stays as large
/// as the largest capture. When the stream failed to open, `f` runs with
/// DPDK's log unchanged and the returned log is empty.
pub(crate) fn capture<T>(f: impl FnOnce() -> T) -> (T, String) {
    static ONE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let Some(captured) = captured() else {
        return (f(), String::new());
    };
    // One capture at a time owns the stream and DPDK's log.
    let _one = ONE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let stream = captured.stream;
    // SAFETY: the stream is open for the process; the lock orders the rewind before DPDK writes.
    unsafe {
        flockfile(stream);
        libc::rewind(stream);
        funlockfile(stream);
        sys::rte_openlog_stream(stream.cast());
    }
    let restore = RestoreLog;
    let out = f();
    drop(restore);
    let log = captured.flushed(|buf, len| {
        if buf.is_null() {
            String::new()
        } else {
            // SAFETY: the flush left `len` bytes at `buf`, and the stream's lock keeps every writer from moving them during the copy.
            String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(buf.cast::<u8>(), len) })
                .into_owned()
        }
    });
    (out, log)
}

/// Writes a captured native `log` to standard error. The caller keeps the
/// log and acts on the native call's result, so a standard error that
/// cannot be written loses only this copy: the write's error is dropped
/// where `eprint!` would panic and unwind out of the native step.
pub(crate) fn echo(log: &str) {
    use std::io::Write;
    let _ = std::io::stderr().write_all(log.as_bytes());
}

/// The initialized environment, owned by the thread that initialized it.
#[derive(Debug)]
pub struct Environment {
    /// Registrations made through the environment whose native state may still exist.
    registrations: Cell<u32>,
    probe_log: String,
    _owner_thread: PhantomData<*mut ()>,
}

impl Environment {
    /// Initializes the process's environment on the calling thread.
    ///
    /// # Errors
    ///
    /// [`EnvError`] naming the step that refused or failed:
    ///
    /// - `Config` and `AlreadyInitialized` return before any native step.
    /// - `PreInit` returns before SPDK's environment init.
    /// - `Timers` returns after the environment is finalized.
    /// - `Core` returns after the timers and then the environment are
    ///   finalized.
    pub fn initialize(config: &EnvConfig<'_>) -> Result<Self, EnvError> {
        Self::initialize_with(config, &mut Native)
    }

    /// [`initialize`](Self::initialize) with the native steps supplied,
    /// including the latch they lend. It validates `config` first, so a
    /// refused configuration leaves `steps.latch()` clear and calls no step.
    /// It then sets that latch, and a latch already set refuses with
    /// `AlreadyInitialized` before any step.
    /// The steps run in order: pre-init, environment init, timer init, core
    /// identity. A timer failure finalizes the environment, and a wrong
    /// core finalizes the timers and then the environment.
    fn initialize_with(
        config: &EnvConfig<'_>,
        steps: &mut impl EnvSteps,
    ) -> Result<Self, EnvError> {
        let dir = config
            .hugepage_dir
            .to_str()
            .and_then(|dir| CString::new(dir).ok())
            .ok_or(EnvError::Config)?;
        if config.core >= sys::RTE_MAX_LCORE {
            return Err(EnvError::Config);
        }
        let core_mask = CString::new(format!("[{}]", config.core)).map_err(|_| EnvError::Config)?;
        let main_core = i32::try_from(config.core).map_err(|_| EnvError::Config)?;
        if steps.latch().swap(true, Ordering::AcqRel) {
            return Err(EnvError::AlreadyInitialized);
        }
        steps.pre_init().map_err(EnvError::PreInit)?;
        let mut allowed: Vec<sys::spdk_pci_addr> = config
            .allowed
            .iter()
            .map(|a| sys::spdk_pci_addr {
                domain: a.domain,
                bus: a.bus,
                dev: a.device,
                func: a.function,
            })
            .collect();
        let mut opts = sys::spdk_env_opts {
            opts_size: size_of::<sys::spdk_env_opts>(),
            ..Default::default()
        };
        // SAFETY: `opts` is a sized options structure.
        unsafe { sys::spdk_env_opts_init(&mut opts) };
        opts.name = c"kestrike".as_ptr();
        opts.core_mask = core_mask.as_ptr();
        opts.main_core = main_core;
        opts.shm_id = -1;
        opts.hugedir = dir.as_ptr();
        opts.env_context = PROBE_LOG_LEVEL.as_ptr().cast_mut().cast();
        opts.no_pci = allowed.is_empty();
        opts.num_pci_addr = allowed.len();
        opts.pci_allowed = if allowed.is_empty() {
            std::ptr::null_mut()
        } else {
            allowed.as_mut_ptr()
        };
        // SAFETY: `dir`, `core_mask`, `allowed` and the two constants
        // `opts` points to live to the end of this function, and the swap
        // above set the steps' latch.
        let (rc, probe_log) = unsafe { steps.init(&opts) };
        if rc != 0 {
            return Err(EnvError::Init(rc));
        }
        // SAFETY: `init` returned 0 on this thread; nothing has used the
        // environment yet, so no timer or memory user is live when a timer
        // failure finalizes it.
        if let Err(rc) = timers_ready(unsafe { steps.init_timers() }) {
            unsafe { steps.finalize(Finalizer::Environment) };
            return Err(EnvError::Timers(rc));
        }
        let found = steps.core();
        if found != config.core {
            // SAFETY: the timer init returned 0 or -EALREADY and nothing
            // has used the environment yet, so no timer or memory user is
            // live; the environment finalizes after the timers.
            unsafe {
                steps.finalize(Finalizer::Timers);
                steps.finalize(Finalizer::Environment);
            }
            return Err(EnvError::Core {
                expected: config.core,
                found,
            });
        }
        Ok(Self {
            registrations: Cell::new(0),
            probe_log,
            _owner_thread: PhantomData,
        })
    }

    /// The native log initialization wrote, including each probed driver's report.
    pub fn probe_log(&self) -> &str {
        &self.probe_log
    }

    /// An environment for unit tests of registration bookkeeping; it makes no native call.
    #[cfg(test)]
    pub(crate) fn detached() -> Self {
        Self {
            registrations: Cell::new(0),
            probe_log: String::new(),
            _owner_thread: PhantomData,
        }
    }

    /// Counts a registration that must end before [`finish`](Self::finish).
    ///
    /// # Panics
    ///
    /// If the count exceeds `u32::MAX`.
    pub(crate) fn registered(&self) {
        let count = self.registrations.get().checked_add(1);
        self.registrations.set(
            count.unwrap_or_else(|| {
                unreachable!("registrations are bounded by the process's arenas")
            }),
        );
    }

    /// Retires one registration whose undo succeeded.
    pub(crate) fn unregistered(&self) {
        self.registrations
            .set(self.registrations.get().saturating_sub(1));
    }

    /// Finalizes the timer subsystem and then the environment, each only
    /// while `watchdog` has not expired. The process stays latched as
    /// initialized after every outcome, so a later
    /// [`initialize`](Self::initialize) with a valid configuration returns
    /// `AlreadyInitialized`.
    ///
    /// # Errors
    ///
    /// - [`Unfinished::Registered`] while a registration made through the
    ///   environment is live; no finalizer ran.
    /// - [`Unfinished::Expired`] when the watchdog expired before the timer
    ///   finalizer; no finalizer ran.
    /// - [`Unfinished::Contained`] when the watchdog expired after the timer
    ///   finalizer: found before the environment finalizer, only the timer
    ///   finalizer ran; found once the environment finalizer returned, both
    ///   ran.
    pub fn finish(self, watchdog: &Watchdog) -> Result<(), Unfinished> {
        self.finish_with(
            || watchdog.expired(),
            // SAFETY: `finish_with` runs a finalizer only after it saw zero
            // live registrations, and every device stops before its
            // registration ends and detaches only against the undo's proof,
            // which borrows the environment this call consumes, so no DPDK
            // timer or memory user is live;
            // it asks for `Timers` before `Environment`, and `initialize`
            // returns an environment only after both inits returned ready.
            |finalizer| unsafe { Native.finalize(finalizer) },
        )
    }

    /// [`finish`](Self::finish) with the watchdog and the native calls
    /// supplied: `expired` is asked before each finalizer and again after
    /// the last, and `finalize` receives [`Finalizer::Timers`] then
    /// [`Finalizer::Environment`].
    pub(crate) fn finish_with(
        self,
        expired: impl Fn() -> bool,
        mut finalize: impl FnMut(Finalizer),
    ) -> Result<(), Unfinished> {
        let live = self.registrations.get();
        if live > 0 {
            return Err(Unfinished::Registered(self, live));
        }
        if expired() {
            return Err(Unfinished::Expired(self));
        }
        finalize(Finalizer::Timers);
        if expired() {
            return Err(Unfinished::Contained(Contained {
                _owner_thread: PhantomData,
            }));
        }
        finalize(Finalizer::Environment);
        // `Ok` lets the caller go on to its later teardown steps, which an
        // expiry skips, so a finish whose watchdog had expired by the time
        // the environment finalizer returned ends contained.
        if expired() {
            return Err(Unfinished::Contained(Contained {
                _owner_thread: PhantomData,
            }));
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "env_init_tests.rs"]
mod init_tests;

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    #[test]
    fn timers_initialized_by_another_driver_count_as_ready() {
        assert_eq!(timers_ready(0), Ok(()));
        assert_eq!(timers_ready(-libc::EALREADY), Ok(()));
        assert_eq!(timers_ready(-libc::ENOMEM), Err(-libc::ENOMEM));
    }

    #[derive(Debug, Clone, Copy)]
    enum Expiry {
        Never,
        BeforeFinish,
        During(Finalizer),
    }

    /// Setting expiry inside the finalizer callback lets the tests verify
    /// that each watchdog check runs after the finalizer it follows.
    fn finish(env: Environment, expiry: Expiry) -> (Result<(), Unfinished>, Vec<Finalizer>) {
        let expired = Cell::new(matches!(expiry, Expiry::BeforeFinish));
        let calls = RefCell::new(Vec::new());
        let outcome = env.finish_with(
            || expired.get(),
            |finalizer| {
                calls.borrow_mut().push(finalizer);
                if matches!(expiry, Expiry::During(during) if during == finalizer) {
                    expired.set(true);
                }
            },
        );
        (outcome, calls.into_inner())
    }

    /// A live registration refuses before either finalizer, ahead of an
    /// expired watchdog too: the environment comes back with its count kept.
    #[test]
    fn a_live_registration_refuses_before_either_finalizer() {
        for (expiry, live) in [
            (Expiry::Never, 1),
            (Expiry::BeforeFinish, 1),
            (Expiry::Never, 2),
            (Expiry::BeforeFinish, 2),
        ] {
            let env = Environment::detached();
            for _ in 0..live {
                env.registered();
            }
            let (outcome, calls) = finish(env, expiry);
            let Err(Unfinished::Registered(env, count)) = outcome else {
                panic!("refused live: {outcome:?}");
            };
            assert_eq!(count, live, "{expiry:?}");
            assert!(calls.is_empty(), "no finalizer ran");
            assert_eq!(env.registrations.get(), live, "the count is kept");
            let (again, calls) = finish(env, expiry);
            assert!(
                matches!(again, Err(Unfinished::Registered(_, count)) if count == live),
                "{expiry:?}: a second finish refuses with the same count: {again:?}"
            );
            assert!(calls.is_empty(), "no finalizer ran");
        }
    }

    #[test]
    fn a_finish_under_a_running_watchdog_finalizes_timers_then_the_environment() {
        let (outcome, calls) = finish(Environment::detached(), Expiry::Never);
        assert!(outcome.is_ok(), "{outcome:?}");
        assert_eq!(calls, [Finalizer::Timers, Finalizer::Environment]);
    }

    /// A watchdog expired before the first finalizer returns the live
    /// environment, which a later finish under a running watchdog completes:
    /// timers, then the environment, each once.
    #[test]
    fn an_expiry_before_the_finalizers_returns_the_live_environment() {
        let (outcome, calls) = finish(Environment::detached(), Expiry::BeforeFinish);
        let Err(Unfinished::Expired(env)) = outcome else {
            panic!("refused live: {outcome:?}");
        };
        assert!(calls.is_empty(), "no finalizer ran");
        let (outcome, calls) = finish(env, Expiry::Never);
        assert!(outcome.is_ok());
        assert_eq!(calls, [Finalizer::Timers, Finalizer::Environment]);
    }

    /// A watchdog that expires once the timers are finalized ends the
    /// finish contained, with `Timers` the only finalizer run.
    #[test]
    fn an_expiry_after_the_timers_ends_contained() {
        let (outcome, calls) = finish(Environment::detached(), Expiry::During(Finalizer::Timers));
        let Err(Unfinished::Contained(_)) = outcome else {
            panic!("contained: {outcome:?}");
        };
        assert_eq!(calls, [Finalizer::Timers]);
    }

    /// A watchdog that expires while the environment finalizer runs has
    /// expired after the timers were finalized, so the finish ends contained,
    /// with both finalizers run.
    #[test]
    fn an_expiry_inside_the_environment_finalizer_ends_contained() {
        let (outcome, calls) = finish(
            Environment::detached(),
            Expiry::During(Finalizer::Environment),
        );
        assert_eq!(calls, [Finalizer::Timers, Finalizer::Environment]);
        assert!(
            matches!(outcome, Err(Unfinished::Contained(_))),
            "a watchdog expired after the timer finalizer leaves only Contained: {outcome:?}"
        );
    }
}
