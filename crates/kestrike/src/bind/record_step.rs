//! The filesystem steps of a mappings record's write and removal, each a
//! point at which a test may script an outcome. Outside tests, each step
//! invokes its filesystem call directly.
//!
//! A scripted outcome governs one occurrence of its step on the calling
//! thread: an errno fails the step before the call takes effect, a short
//! count at [`RecordStep::Write`] passes only that prefix of the buffer to
//! the file, and `Pass` makes the call unchanged.

use std::io::{self, Write};

/// One filesystem call of [`Mappings::write`](super::Mappings::write) or
/// [`Mappings::discard`](super::Mappings::discard). The write unlinks a
/// stale temporary file, best effort, creates the temporary file
/// exclusively, writes it, syncs it, renames it onto the record's path, and
/// opens and syncs the directory holding that path. The removal unlinks the
/// record, then opens and syncs its directory.
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub(crate) enum RecordStep {
    TemporaryUnlink,
    Create,
    Write,
    FileSync,
    Rename,
    DirectoryOpen,
    DirectorySync,
    Unlink,
}

/// An outcome a test scripts for one occurrence of a step.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scripted {
    /// The step fails with this errno before its call takes effect.
    Errno(i32),
    /// A `write` passes the first `min(count, len)` bytes of its buffer to
    /// the file and returns the file's result. Scripting it at another step
    /// panics.
    Short(usize),
    /// The step makes its call, so a later outcome for the same step applies
    /// to a later occurrence.
    Pass,
}

/// The scripted outcomes, each consumed by the next occurrence of its step,
/// and every step reached with the outcome it took: `None` when no outcome
/// was scripted for that occurrence.
#[cfg(test)]
pub(crate) struct Script {
    pub(crate) outcomes: Vec<(RecordStep, Scripted)>,
    pub(crate) reached: Vec<(RecordStep, Option<Scripted>)>,
    /// Runs as each step is reached, before its outcome, so a test reads the
    /// record's path as an independent reader would at that moment. It only
    /// reads: a record write or removal inside it reaches a step while the
    /// script is borrowed and panics.
    pub(crate) observe: Box<dyn FnMut(RecordStep)>,
}

#[cfg(test)]
thread_local! {
    pub(crate) static SCRIPT: std::cell::RefCell<Option<Script>> =
        const { std::cell::RefCell::new(None) };
}

/// Records that `at` was reached on this thread and returns the outcome
/// scripted for this occurrence, if any.
#[cfg(test)]
fn scripted(at: RecordStep) -> Option<Scripted> {
    SCRIPT.with(|script| {
        let mut script = script.borrow_mut();
        let script = script.as_mut()?;
        (script.observe)(at);
        let outcome = script
            .outcomes
            .iter()
            .position(|(step, _)| *step == at)
            .map(|index| script.outcomes.remove(index).1);
        script.reached.push((at, outcome));
        outcome
    })
}

/// Runs `call` for step `at`, or returns the errno a test scripted for it;
/// a short outcome scripted at `at` panics.
#[inline(always)]
pub(super) fn step<T>(_at: RecordStep, call: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    #[cfg(test)]
    match scripted(_at) {
        Some(Scripted::Errno(errno)) => return Err(io::Error::from_raw_os_error(errno)),
        Some(Scripted::Short(_)) => panic!("a short outcome is scripted at {_at:?}"),
        Some(Scripted::Pass) | None => {}
    }
    call()
}

/// The part of `buf` step `at` passes to its call: all of it, or the prefix
/// a test scripted; or the errno a test scripted for it.
#[inline(always)]
fn prefix(_at: RecordStep, buf: &[u8]) -> io::Result<&[u8]> {
    #[cfg(test)]
    match scripted(_at) {
        Some(Scripted::Errno(errno)) => return Err(io::Error::from_raw_os_error(errno)),
        Some(Scripted::Short(count)) => return Ok(&buf[..count.min(buf.len())]),
        Some(Scripted::Pass) | None => {}
    }
    Ok(buf)
}

/// Wraps the staging file so each `write` passes through [`prefix`].
pub(super) struct StepWriter<W>(pub(super) W);

impl<W: Write> Write for StepWriter<W> {
    #[inline(always)]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let buf = prefix(RecordStep::Write, buf)?;
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}
