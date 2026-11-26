//! Test-only rule controls. A rule control disables one checker rule for the
//! duration of one closure on the calling thread and shows that the change
//! flips at least one golden's verdict. Every judgment outside [`without`]
//! runs with every rule in force, so the checker keeps one strictness and one
//! search.

use std::cell::Cell;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    /// Operations linearize by tenure tag; disabled, every operation lands
    /// in the initial tenure.
    TenureOrder,
    /// An interval covers absent versions; disabled, it covers only versions
    /// published at its linearization point.
    AbsentCoverage,
    /// Each client's accepted tags respect its high-water.
    HighWater,
    /// Every explicit tenure tag names a logged activation.
    TagReconciliation,
    /// A hit after a recorded removal of its label in the same tenure fails
    /// unless a recorded restore of that label follows the removal.
    EvidenceClass,
}

thread_local! {
    static DISABLED: Cell<Option<Rule>> = const { Cell::new(None) };
}

pub(crate) fn holds(rule: Rule) -> bool {
    DISABLED.with(|disabled| disabled.get() != Some(rule))
}

/// Restores the previous setting when dropped, on return or unwind.
struct Restore(Option<Rule>);

impl Drop for Restore {
    fn drop(&mut self) {
        DISABLED.with(|disabled| disabled.set(self.0));
    }
}

/// Runs `judge` with `rule` disabled on this thread, then restores the
/// previous setting, also when `judge` panics.
pub(crate) fn without<T>(rule: Rule, judge: impl FnOnce() -> T) -> T {
    let _restore = Restore(DISABLED.with(|disabled| disabled.replace(Some(rule))));
    judge()
}
