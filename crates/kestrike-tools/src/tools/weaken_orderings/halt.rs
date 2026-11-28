//! The ends of a command other than its report: a refusal with its exit code, a handled signal, or a
//! failed step that the run has no refusal for.

use std::io::{self, Write};

use crate::process::Interrupted;
use crate::text::Text;

#[derive(Debug)]
pub(super) enum Halt {
    /// A refusal: `weaken-orderings: REASON` on standard error and the exit `code`.
    Stop { code: u8, reason: Text },
    /// A handled signal: `weaken-orderings: signal NUMBER` on standard error, then the end by SIGINT.
    Interrupted(i32),
    /// A failed step: `weaken-orderings: MESSAGE` on standard error and exit 1.
    Failed(String),
}

impl Halt {
    pub(super) fn stop(code: u8, reason: impl Into<Text>) -> Self {
        Self::Stop {
            code,
            reason: reason.into(),
        }
    }

    pub(super) fn failed(message: impl std::fmt::Display) -> Self {
        Self::Failed(message.to_string())
    }

    pub(super) fn is_interrupt(&self) -> bool {
        matches!(self, Self::Interrupted(_))
    }

    /// `end` writes the halt's line to `err` and returns the exit code; an interrupted run ends itself by
    /// SIGINT first and returns 130 only where that signal leaves it running.
    pub(super) fn end(&self, err: &mut impl Write) -> u8 {
        let (line, code) = match self {
            Self::Stop { code, reason } => (reason.to_string(), *code),
            Self::Interrupted(signal) => (format!("signal {signal}"), 130),
            Self::Failed(message) => (message.clone(), 1),
        };
        let _ = writeln!(err, "weaken-orderings: {line}");
        let _ = err.flush();
        if self.is_interrupt() {
            end_by_sigint();
        }
        code
    }
}

impl From<Interrupted> for Halt {
    fn from(Interrupted(signal): Interrupted) -> Self {
        Self::Interrupted(signal)
    }
}

impl From<io::Error> for Halt {
    fn from(error: io::Error) -> Self {
        Self::failed(error)
    }
}

/// `end_by_sigint` gives SIGINT its default action, unblocks it in the calling thread and sends it to
/// this process, which then ends by that signal.
fn end_by_sigint() {
    // SAFETY: `signal`, `sigemptyset`, `sigaddset`, `pthread_sigmask` and `kill` take plain values and a
    // local signal set that outlives the calls; `sigemptyset` initializes the set before it is read.
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_DFL);
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGINT);
        libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
        libc::kill(libc::getpid(), libc::SIGINT);
    }
}
