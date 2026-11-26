//! Standalone GenMC package for the repository's checker route: a case runs
//! as `main` under `genmc -rc11` with `genmc-std` standing in for `std`.
//! The qualification cases qualify the route; the credit, cutoff and grace
//! kernels run the production `credit`, `grace` and `word` modules, and the
//! terminal kernel the production `index::sequence` module, and the join
//! kernel the production `fill` and `row` modules, included by path.
//!
//! The route uses these `genmc-std` shims and nothing else: `thread::spawn_f`
//! to start a thread, `JoinHandle::join` to wait for it, and the
//! `__VERIFIER_assert_fail` symbol `check!` calls. Atomics and fences are
//! the real `std` items `genmc-std` re-exports; the integer operations come
//! from `core`.

mod check;
#[cfg(kernel = "credit")]
mod credit_kernel;
#[cfg(kernel = "cutoff")]
mod cutoff_kernel;
#[cfg(kernel = "grace")]
mod grace_kernel;
#[cfg(kernel = "join")]
mod join;
#[cfg(kernel = "join")]
mod join_kernel;
#[cfg(kernel = "qualification")]
mod qualification;
#[cfg(kernel = "terminal")]
#[path = "../../../../../crates/kestrike/src/index/sequence.rs"]
mod sequence;
#[cfg(any(kernel = "credit", kernel = "cutoff", kernel = "grace"))]
mod storage;
#[cfg(kernel = "terminal")]
mod terminal_kernel;

fn main() {
    #[cfg(kernel = "qualification")]
    qualification::run();
    #[cfg(kernel = "credit")]
    credit_kernel::run();
    #[cfg(kernel = "cutoff")]
    cutoff_kernel::run();
    #[cfg(kernel = "grace")]
    grace_kernel::run();
    #[cfg(kernel = "terminal")]
    terminal_kernel::run();
    #[cfg(kernel = "join")]
    join_kernel::run();
}
