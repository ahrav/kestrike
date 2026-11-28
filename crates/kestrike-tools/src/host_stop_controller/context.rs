//! Each case supplies a command's clocks, calls, files, streams and environment through [`Context`].

use std::ffi::OsString;
use std::io::Write;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use crate::host_stop::{Files, Number, Record, Seam};
use crate::json::Value;
use crate::text::Text;

/// A command and its arguments, as the tool's argument reading gives them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    /// `run --operator F --package F --evidence DIR`. `evidence` keeps its bytes, since an empty
    /// path is refused by name.
    Run {
        operator: PathBuf,
        package: PathBuf,
        evidence: OsString,
    },
    Restore {
        operator: PathBuf,
        evidence: OsString,
        reviewed: Option<PathBuf>,
    },
}

/// The system a command runs on. `env` is the environment read at the tool's start, under which
/// every call runs; `catalog` names the game-day catalog; `top` is the tree whose Rust files bound
/// the package's lists; `file_limit` bounds every file read and `mark_limit` every mark's bytes. The
/// record borrows a [`Delivered`](crate::host_stop::Delivered) that lives to the process's end, as
/// the one the signal handlers store into does.
pub struct Context<'a, S: Seam, F: Files> {
    pub seam: &'a mut S,
    pub files: &'a F,
    pub record: &'a mut Record<'static>,
    pub env: &'a [(OsString, OsString)],
    pub out: &'a mut dyn Write,
    pub err: &'a mut dyn Write,
    pub catalog: &'a Path,
    pub top: &'a Path,
    pub file_limit: u64,
    pub mark_limit: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stream {
    Out,
    Err,
}

impl<S: Seam, F: Files> Context<'_, S, F> {
    /// Writes `line` and a newline in UTF-8, each lone surrogate as `\udXXX`, and flushes. A write
    /// or a flush that fails changes no outcome, so its error is dropped.
    pub(crate) fn say(&mut self, stream: Stream, line: &Text) {
        let out: &mut dyn Write = match stream {
            Stream::Out => &mut *self.out,
            Stream::Err => &mut *self.err,
        };
        let shown = format!("{line}\n");
        let _ = out.write_all(shown.as_bytes()).and_then(|()| out.flush());
    }
}

/// `path` in the form Python's `pathlib` writes it: empty and `.` components dropped, `..` kept, a
/// leading `//` kept, three or more leading slashes as one, and an empty relative path as `.`.
pub(crate) fn pure(path: &[u8]) -> PathBuf {
    let slashes = if path.starts_with(b"//") && !path.starts_with(b"///") {
        2
    } else {
        usize::from(path.starts_with(b"/"))
    };
    let names: Vec<&[u8]> = path
        .split(|&byte| byte == b'/')
        .filter(|name| !name.is_empty() && *name != b".")
        .collect();
    let mut pure = vec![b'/'; slashes];
    pure.extend_from_slice(&names.join(&b'/'));
    if pure.is_empty() {
        pure.push(b'.');
    }
    PathBuf::from(OsString::from_vec(pure))
}

/// `name` in `directory`, in [`pure`] form.
pub(crate) fn beside(directory: &Path, name: &str) -> PathBuf {
    let mut joined = directory.as_os_str().as_bytes().to_vec();
    joined.push(b'/');
    joined.extend_from_slice(name.as_bytes());
    pure(&joined)
}

/// `number` as a float: an integer's nearest double, ties to even, as Python converts an integer
/// in a sum with a float.
pub(crate) fn seconds(number: Number) -> f64 {
    match number.value() {
        Value::Float(float) => float,
        Value::Integer(integer) => integer
            .to_string()
            .parse()
            .expect("an integer's digits parse as a float"),
        other => unreachable!("a number's value is a number, not {other:?}"),
    }
}

/// Python's `repr` of a list of texts, in the given order.
pub(crate) fn list_repr<'a>(items: impl IntoIterator<Item = &'a Text>) -> String {
    let shown: Vec<String> = items.into_iter().map(Text::repr).collect();
    format!("[{}]", shown.join(", "))
}
