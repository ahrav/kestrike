//! The production modules under test, included by path, and the stand-ins
//! for the two sibling modules `grace.rs` imports.
//!
//! Shims: `config` holds the one constant `grace.rs` takes from the
//! production `config` module, `ERA_TERMINAL`, with the production value
//! (`scripts/test-judge-genmc.py` compares the two, and the declaration
//! lists `config.rs` as transcribed so a receipt binds it); `probe` is a no-op in place of
//! the production instrumentation, whose notes record counts in tests and
//! do nothing in production builds.

pub(crate) mod config {
    pub(crate) const ERA_TERMINAL: u64 = 1 << 63;
}

pub(crate) mod probe {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Primitive {
        Load,
        Store,
        Cas,
        Rmw,
    }

    #[inline(always)]
    pub(crate) fn note(_primitive: Primitive) {}
}

#[path = "../../../../../crates/kestrike/src/storage/credit.rs"]
pub(crate) mod credit;
#[cfg(kernel = "credit")]
#[path = "../../../../../crates/kestrike/src/storage/credit_steps.rs"]
pub(crate) mod credit_steps;
#[path = "../../../../../crates/kestrike/src/storage/grace.rs"]
pub(crate) mod grace;
#[path = "../../../../../crates/kestrike/src/storage/word.rs"]
pub(crate) mod word;
