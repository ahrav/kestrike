//! The ways a step of a command ends early, and the text of an unforeseen failure.

use std::any::Any;
use std::io;
use std::path::Path;

use crate::host_stop::{FailedCall, Interrupted, Unwritten};
use crate::plants::files::strerror;
use crate::text::Text;

/// The cause that takes a run onto the abort path: `reach`, `guardrail`, `deadline` or
/// `stop-not-shown`, with the guardrail text it names and its detail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Aborted {
    cause: &'static str,
    guardrail: Option<Text>,
    detail: Text,
}

impl Aborted {
    pub(crate) fn new(cause: &'static str, guardrail: Option<Text>, detail: Text) -> Self {
        Self {
            cause,
            guardrail,
            detail,
        }
    }

    pub fn cause(&self) -> &'static str {
        self.cause
    }

    pub fn guardrail(&self) -> Option<&Text> {
        self.guardrail.as_ref()
    }

    pub fn detail(&self) -> &Text {
        &self.detail
    }
}

/// An unforeseen failure of a step. [`Fault::text`] names its class: `Refusal` for a mark's value
/// or bytes a check refused and for the lock's refusal, `Unwritten` for a mark's write that failed
/// after its link, the class Python gives a system error's number, `RuntimeError` for a step asked
/// for before the state it reads, and `panic` for a panic.
#[derive(Debug)]
pub enum Fault {
    Refusal(Text),
    Unwritten(Text),
    Os { code: Option<i32>, text: String },
    Order(String),
    Panic(String),
}

impl Fault {
    pub(crate) fn os(error: &io::Error) -> Self {
        Self::Os {
            code: error.raw_os_error(),
            text: strerror(error),
        }
    }

    /// The fault of a mark's write at `path`: a failed step is its system error, a write that took
    /// no byte is the system error `EIO` with the write's sentence, and a failure after the link is
    /// the sentence of what stands.
    pub(crate) fn unwritten(unwritten: &Unwritten, path: &Path) -> Self {
        match unwritten {
            Unwritten::Failed { error, .. } => Self::os(error),
            Unwritten::Stalled => Self::Os {
                code: Some(libc::EIO),
                text: unwritten.sentence(path).to_string(),
            },
            _ => Self::Unwritten(unwritten.sentence(path)),
        }
    }

    pub(crate) fn panic(payload: &(dyn Any + Send)) -> Self {
        let message = payload
            .downcast_ref::<&str>()
            .map(|text| (*text).to_owned())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "a panic with no message".to_owned());
        Self::Panic(message)
    }

    /// `<class>: <message>`; a system error reads `<class>: [Errno N] <the system's text>`.
    pub fn text(&self) -> Text {
        let mut text = Text::new();
        match self {
            Self::Refusal(message) => {
                text.push_str("Refusal: ");
                text.push_text(message);
            }
            Self::Unwritten(message) => {
                text.push_str("Unwritten: ");
                text.push_text(message);
            }
            Self::Os {
                code: Some(code),
                text: message,
            } => text.push_str(&format!(
                "{}: [Errno {code}] {message}",
                os_error_class(*code)
            )),
            Self::Os {
                code: None,
                text: message,
            } => text.push_str(&format!("OSError: {message}")),
            Self::Order(message) => text.push_str(&format!("RuntimeError: {message}")),
            Self::Panic(message) => text.push_str(&format!("panic: {message}")),
        }
        text
    }
}

/// The class name Python 3 gives an `OSError` of the error number `code`: the subclass its fixed
/// table maps the number to, else `OSError`.
fn os_error_class(code: i32) -> &'static str {
    match code {
        libc::EAGAIN | libc::EALREADY | libc::EINPROGRESS => "BlockingIOError",
        libc::ECHILD => "ChildProcessError",
        libc::EPIPE | libc::ESHUTDOWN => "BrokenPipeError",
        libc::ECONNABORTED => "ConnectionAbortedError",
        libc::ECONNREFUSED => "ConnectionRefusedError",
        libc::ECONNRESET => "ConnectionResetError",
        libc::EEXIST => "FileExistsError",
        libc::ENOENT => "FileNotFoundError",
        libc::EISDIR => "IsADirectoryError",
        libc::ENOTDIR => "NotADirectoryError",
        libc::EINTR => "InterruptedError",
        libc::EACCES | libc::EPERM => "PermissionError",
        libc::ESRCH => "ProcessLookupError",
        libc::ETIMEDOUT => "TimeoutError",
        _ => "OSError",
    }
}

/// How a step ends early: a refusal, with whether `injection/` may stand after it; a cause of the
/// abort path; a signal the record raised; a failed call; or an unforeseen failure.
#[derive(Debug)]
pub enum Halt {
    Refused { sentence: Text, may_stand: bool },
    Aborted(Aborted),
    Interrupted(Interrupted),
    Failed(FailedCall),
    Fault(Fault),
}

impl Halt {
    pub(crate) fn refused(sentence: Text) -> Self {
        Self::Refused {
            sentence,
            may_stand: false,
        }
    }

    pub(crate) fn aborted(cause: &'static str, guardrail: Option<Text>, detail: Text) -> Self {
        Self::Aborted(Aborted::new(cause, guardrail, detail))
    }
}

impl From<Interrupted> for Halt {
    fn from(raised: Interrupted) -> Self {
        Self::Interrupted(raised)
    }
}

impl From<Fault> for Halt {
    fn from(fault: Fault) -> Self {
        Self::Fault(fault)
    }
}

impl From<crate::gameday::Refusal> for Halt {
    fn from(refusal: crate::gameday::Refusal) -> Self {
        Self::refused(refusal.message().clone())
    }
}
