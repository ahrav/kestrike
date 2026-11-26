//! Cache hints: write prefetches for a burst of stores that must be visible
//! before a release, and read or write prefetches for a line whose miss would
//! otherwise sit on the critical path, such as a bucket a derivation has
//! just located or the records a retirement is about to touch.
//!
//! A run of full-line stores that miss the local cache can switch the core
//! into a write-streaming path that completes each line at the shared cache
//! instead of allocating it locally. A release that follows the run, such as
//! freeing a gate, then waits for every one of those far completions, one
//! shared-cache round trip each. Requesting the lines for writing first turns
//! the same stores into local hits and the release into a local drain.
//!
//! A prefetch is a hint: it reads and writes nothing the program can observe
//! and never faults, whatever the address, so a target without one (or an
//! interpreter such as Miri) gets a no-op with identical behavior.

/// Bytes covered by one hint. A core with wider lines takes two hints per
/// line, which is harmless.
pub(crate) const LINE: usize = 64;

/// Whether an atomic read-modify-write waits for the software prefetches
/// issued before it. On AMD Zen 4 a locked instruction does; a Neoverse V1
/// issues the exchange at once. Where it waits, a hint between two gate
/// exchanges moves its line's miss onto the second exchange, which costs
/// more than it hides for a line that would otherwise miss once, at its
/// use: a path that hints there for such lines hints only where this is
/// false. Hints for lines that would each miss behind a later locked
/// instruction, one wait apiece, pay off either way: the exchange waits
/// once for all of them. So do the record header hints before a lookup's
/// reservation, before a retirement's or a return's pool gate and ahead of
/// the service pass's next return: each hinted line is read under or right
/// after the exchange, so the wait replaces a miss in series.
///
/// Every x86_64 core is taken to wait as Zen 4 does, and every core of
/// another architecture to issue at once as Neoverse V1 does.
pub(crate) const RMW_WAITS_FOR_HINTS: bool = cfg!(target_arch = "x86_64");

#[cfg(test)]
thread_local! {
    /// [`hint`] calls on this thread, counted on every target, including
    /// those where the hint itself is a no-op.
    pub(crate) static WRITE_HINTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };

    /// [`hint_read`] calls made on this thread.
    pub(crate) static READ_HINTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Hints that the line at `address` is about to be stored to. The address is
/// only an address: never dereferenced, so any value is fine.
#[inline]
pub(crate) fn hint(address: *const u8) {
    #[cfg(test)]
    WRITE_HINTS.with(|count| count.set(count.get() + 1));
    write_hint(address);
}

#[cfg(all(target_arch = "aarch64", not(miri)))]
#[inline(always)]
fn write_hint(address: *const u8) {
    // SAFETY: `prfm` is a hint with no architectural memory effect and cannot
    // fault; the operand is only an address and is never dereferenced.
    unsafe {
        core::arch::asm!(
            "prfm pstl1keep, [{0}]",
            in(reg) address,
            options(nostack, preserves_flags, readonly)
        )
    };
}

#[cfg(all(target_arch = "x86_64", not(miri)))]
#[inline(always)]
fn write_hint(address: *const u8) {
    // SAFETY: `prefetchw` is a hint with no architectural memory effect and
    // cannot fault; the operand is only an address and is never dereferenced.
    unsafe {
        core::arch::asm!(
            "prefetchw [{0}]",
            in(reg) address,
            options(nostack, preserves_flags, readonly)
        )
    };
}

/// Hints that the line at `address` is about to be loaded. A read hint asks
/// for a shared copy, so readers on other cores keep theirs; the write hint
/// would take the line from them.
#[cfg(all(target_arch = "aarch64", not(miri)))]
#[inline]
pub(crate) fn hint_read(address: *const u8) {
    #[cfg(test)]
    READ_HINTS.with(|count| count.set(count.get() + 1));
    // SAFETY: as for `hint`.
    unsafe {
        core::arch::asm!(
            "prfm pldl1keep, [{0}]",
            in(reg) address,
            options(nostack, preserves_flags, readonly)
        )
    };
}

/// Hints that the line at `address` is about to be loaded.
#[cfg(all(target_arch = "x86_64", not(miri)))]
#[inline]
pub(crate) fn hint_read(address: *const u8) {
    #[cfg(test)]
    READ_HINTS.with(|count| count.set(count.get() + 1));
    // SAFETY: as for `hint`.
    unsafe {
        core::arch::asm!(
            "prefetcht0 [{0}]",
            in(reg) address,
            options(nostack, preserves_flags, readonly)
        )
    };
}

/// Interpreters and other targets have no hint to issue.
#[cfg(any(miri, not(any(target_arch = "aarch64", target_arch = "x86_64"))))]
#[inline(always)]
fn write_hint(_address: *const u8) {}

/// Interpreters and other targets have no hint to issue.
#[cfg(any(miri, not(any(target_arch = "aarch64", target_arch = "x86_64"))))]
#[inline]
pub(crate) fn hint_read(_address: *const u8) {
    #[cfg(test)]
    READ_HINTS.with(|count| count.set(count.get() + 1));
}

#[cfg(test)]
mod tests {
    use super::{LINE, hint_read};

    /// A read hint reads nothing and cannot fault, so any address is safe to
    /// hint: hints at the null address and in the kernel half both return.
    #[test]
    fn read_hints_never_fault() {
        hint_read(std::ptr::null());
        hint_read(std::ptr::without_provenance(usize::MAX - LINE + 1));
    }
}
