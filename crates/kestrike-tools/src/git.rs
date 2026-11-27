//! These functions pass argument vectors to Git and read its output. Every function takes the environment
//! its Git child starts in as an [`Environ`] value, built by [`caller_environ`] or [`push_environ`]; both set
//! `GIT_NO_REPLACE_OBJECTS=1`, so Git reads each object as the repository stores it and no `refs/replace`
//! entry stands in for one, and nothing here changes the process's own environment.
//! [`REPOSITORY_VARIABLES`] names the variables that redirect Git to another repository.

use std::ffi::OsStr;
use std::fmt;
use std::io::{self, Write};
use std::process::{Child, Command, Output, Stdio};

use crate::environ::{Environ, remove, set};
use crate::text::{Text, escaped, strip_str};

/// The variables that point Git at another repository, work tree, index or object store than the one the
/// working directory names, in the order a refusal lists them.
pub const REPOSITORY_VARIABLES: [&str; 5] = [
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_COMMON_DIR",
    "GIT_OBJECT_DIRECTORY",
];

/// The variables that set Git's pathspec mode: each makes Git read a pathspec's magic, such as `:(top)`,
/// otherwise than its manual's default, and Git refuses the literal mode beside any other.
pub const PATHSPEC_MODES: [&str; 4] = [
    "GIT_LITERAL_PATHSPECS",
    "GIT_GLOB_PATHSPECS",
    "GIT_NOGLOB_PATHSPECS",
    "GIT_ICASE_PATHSPECS",
];

const PATHSPEC_AND_DIFF_VARIABLES: [&str; 3] =
    ["GIT_ICASE_PATHSPECS", "GIT_GLOB_PATHSPECS", "GIT_DIFF_OPTS"];

/// A Git command that did not give its output. `Display` writes the line a tool prints after its own name.
#[derive(Debug)]
pub enum GitError {
    /// `Start` wraps an error from `Command::output` or `Command::spawn`, including a failure to launch Git:
    /// `git: ` and the system's error.
    Start(io::Error),
    /// A batch read returns this error if a batch write fails with an error other than a closed pipe, the
    /// writer thread fails to start, or reading the child's output or status fails:
    /// `git cat-file --batch: ` and the system's error.
    Io(io::Error),
    /// Git exited with a failure: the command as `git <arguments>`, `: ` and Git's standard error with white
    /// space stripped at both ends and each byte sequence that is not UTF-8 replaced by U+FFFD.
    Failed(String),
    /// Git's output is not UTF-8: the decoder's message, after the command or the request's name where the
    /// function names one.
    NotUtf8(String),
    /// `Truncated` identifies the request for an incomplete or malformed reply of `git cat-file --batch`, or
    /// one that answers an object id with another. It also reports trailing bytes after the final reply,
    /// with the number of answers read.
    Truncated(String),
    /// A batch read returns `Name` for a name that contains a line feed or NUL, and [`blob_texts`] also for
    /// one that ends in a carriage return. Git reads a line feed in a batch name as a request separator,
    /// reads a name up to a NUL, and strips a final carriage return.
    Name(String),
}

impl fmt::Display for GitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Start(error) => write!(f, "git: {error}"),
            Self::Io(error) => write!(f, "git cat-file --batch: {error}"),
            Self::Failed(text) | Self::NotUtf8(text) | Self::Truncated(text) | Self::Name(text) => {
                f.write_str(text)
            }
        }
    }
}

impl std::error::Error for GitError {}

/// `caller_environ` is this process's environment with `GIT_NO_REPLACE_OBJECTS=1` set.
pub fn caller_environ() -> Environ {
    let mut environ: Environ = std::env::vars_os().collect();
    set(&mut environ, "GIT_NO_REPLACE_OBJECTS", "1".into());
    environ
}

/// `push_environ` is [`caller_environ`] without the [`PATHSPEC_MODES`] variables, so a child reads each
/// pathspec with its magic whatever pathspec mode the caller set.
pub fn push_environ() -> Environ {
    without_pathspec_modes(caller_environ())
}

/// `without_pathspec_modes` is `environ` without the [`PATHSPEC_MODES`] variables, the others kept in order.
pub(crate) fn without_pathspec_modes(mut environ: Environ) -> Environ {
    for name in PATHSPEC_MODES {
        remove(&mut environ, name);
    }
    environ
}

/// `command` prepares `program`, Git or a check the hook runs, to start with exactly the variables of
/// `environ`.
pub fn command(environ: &Environ, program: impl AsRef<OsStr>) -> Command {
    let mut command = Command::new(program);
    command
        .env_clear()
        .envs(environ.iter().map(|(name, value)| (name, value)));
    command
}

/// `git` returns the standard output of `git args` in `environ`. Git that does not start is
/// [`GitError::Start`], a failed command is [`GitError::Failed`], and its [`GitError::NotUtf8`] holds the
/// decoder's message verbatim.
pub fn git<S: AsRef<OsStr>>(environ: &Environ, args: &[S]) -> Result<String, GitError> {
    let output = captured(command(environ, "git").args(args), args)?;
    String::from_utf8(output).map_err(|error| GitError::NotUtf8(error.utf8_error().to_string()))
}

/// `git_text` returns the standard output of `git args` in `environ` without `GIT_ICASE_PATHSPECS`,
/// `GIT_GLOB_PATHSPECS` and `GIT_DIFF_OPTS`. Git that does not start is [`GitError::Start`], a failed command
/// is [`GitError::Failed`], and output that is not UTF-8 is [`GitError::NotUtf8`] after the command.
pub fn git_text<S: AsRef<OsStr>>(environ: &Environ, args: &[S]) -> Result<String, GitError> {
    let mut git = command(environ, "git");
    git.args(args);
    for name in PATHSPEC_AND_DIFF_VARIABLES {
        git.env_remove(name);
    }
    let output = captured(&mut git, args)?;
    String::from_utf8(output)
        .map_err(|error| GitError::NotUtf8(format!("{}: {}", label(args), error.utf8_error())))
}

/// `output` returns the exit status and both streams of `git args` in `environ`, whatever the status. Git
/// that does not start is [`GitError::Start`].
pub fn output<S: AsRef<OsStr>>(environ: &Environ, args: &[S]) -> Result<Output, GitError> {
    command(environ, "git")
        .args(args)
        .output()
        .map_err(GitError::Start)
}

/// `merge_base` returns the output of `git merge-base one other` in `environ` with white space stripped at
/// both ends, and `None` when Git exits 1 with no output, as it does for two commits that share no history.
/// Git that does not start is [`GitError::Start`], any other failed exit is [`GitError::Failed`], and output
/// that is not UTF-8 is [`GitError::NotUtf8`].
pub fn merge_base<S: AsRef<OsStr>>(
    environ: &Environ,
    one: S,
    other: S,
) -> Result<Option<String>, GitError> {
    let args = [OsStr::new("merge-base"), one.as_ref(), other.as_ref()];
    let output = output(environ, &args)?;
    if output.status.code() == Some(1) && output.stdout.is_empty() {
        return Ok(None);
    }
    if !output.status.success() {
        return Err(failed(&args, &output.stderr));
    }
    let found = String::from_utf8(output.stdout)
        .map_err(|error| GitError::NotUtf8(error.utf8_error().to_string()))?;
    Ok(Some(strip_str(&found).to_owned()))
}

/// `blob_texts` returns the text of each `<rev>:<path>` name of `specs` in order, read by one
/// `git cat-file --batch` in `environ`: a blob's bytes, and an empty text for a name Git reports missing and
/// for an object other than a blob. A name that holds a line feed or a NUL, or that ends in a carriage
/// return, is [`GitError::Name`] before Git starts. Git that does not start is [`GitError::Start`], a failed
/// write or read is [`GitError::Io`], a failed exit is [`GitError::Failed`], a reply that leaves the batch
/// framing is [`GitError::Truncated`], and a blob that is not UTF-8 is [`GitError::NotUtf8`] after its name.
pub fn blob_texts(environ: &Environ, specs: &[String]) -> Result<Vec<String>, GitError> {
    let data = batch(environ, specs, true)?;
    batch_texts(&data, specs)
}

/// `blob_bytes` returns the bytes of each object `names` names, in order, read by one
/// `git cat-file --batch` in `environ`: `Some` with a blob's bytes, and `None` for a name Git reports
/// missing and for an object other than a blob. Git reads a name without its final carriage return, so a
/// name that ends in one reads the object of that shorter name. A name that holds a line feed or a NUL is
/// [`GitError::Name`] before Git starts. Git that does not start is [`GitError::Start`], a failed write or
/// read is [`GitError::Io`], a failed exit is [`GitError::Failed`], and a reply that leaves the batch
/// framing, or that answers an object id with another, is [`GitError::Truncated`].
pub fn blob_bytes(environ: &Environ, names: &[String]) -> Result<Vec<Option<Vec<u8>>>, GitError> {
    let data = batch(environ, names, false)?;
    let bodies = replies(&data, names, |_, kind, body| {
        Ok((kind == b"blob").then(|| body.to_vec()))
    })?;
    Ok(bodies.into_iter().map(Option::flatten).collect())
}

/// `misnamed` is the refusal of a batch name Git would read as another name.
fn misnamed(name: &str, misread: &str) -> GitError {
    GitError::Name(format!(
        "git cat-file --batch: the name {} {misread}",
        Text::from(name).repr()
    ))
}

/// `batch` writes each of `names` and a line feed to one `git cat-file --batch` in `environ` and returns its
/// standard output. The first name that holds a line feed or a NUL, or with `final_return` set ends in a
/// carriage return, is refused before Git starts.
fn batch(environ: &Environ, names: &[String], final_return: bool) -> Result<Vec<u8>, GitError> {
    for name in names {
        let misread = if name.contains('\n') {
            "holds a line feed"
        } else if name.contains('\0') {
            "holds a NUL"
        } else if final_return && name.ends_with('\r') {
            "ends in a carriage return"
        } else {
            continue;
        };
        return Err(misnamed(name, misread));
    }
    let input: String = names.iter().map(|name| format!("{name}\n")).collect();
    let child = command(environ, "git")
        .args(["cat-file", "--batch"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(GitError::Start)?;
    let output = fed(child, input.as_bytes()).map_err(GitError::Io)?;
    if !output.status.success() {
        return Err(failed(&["cat-file", "--batch"], &output.stderr));
    }
    Ok(output.stdout)
}

/// `fed` writes `input` to the standard input of `child`, which was spawned with all three streams piped,
/// from a thread of its own while it collects both output streams, and waits for the child. A child that
/// closes its input before reading all of it ends the write without an error.
///
/// # Errors
///
/// The writer thread cannot start, the write fails otherwise, or the wait fails.
pub(crate) fn fed(mut child: Child, input: &[u8]) -> io::Result<Output> {
    let mut stdin = child
        .stdin
        .take()
        .expect("the child's standard input is piped");
    std::thread::scope(|scope| {
        let writer =
            std::thread::Builder::new().spawn_scoped(scope, move || match stdin.write_all(input) {
                Err(error) if error.kind() != io::ErrorKind::BrokenPipe => Err(error),
                _ => Ok(()),
            });
        let output = child.wait_with_output();
        let written = writer.and_then(|handle| handle.join().expect("the writer thread returns"));
        written.and(output)
    })
}

/// `batch_texts` reads the reply of [`blob_texts`] for `specs`: a blob's text, and an empty text for a missing
/// name and for an object other than a blob.
pub(crate) fn batch_texts(data: &[u8], specs: &[String]) -> Result<Vec<String>, GitError> {
    replies(data, specs, |spec, kind, body| {
        if kind != b"blob" {
            return Ok(String::new());
        }
        std::str::from_utf8(body)
            .map(str::to_owned)
            .map_err(|error| GitError::NotUtf8(format!("{spec}: {error}")))
    })
    .map(|texts| texts.into_iter().map(Option::unwrap_or_default).collect())
}

/// `replies` reads one reply for each name of `names`, in order: `<id> <type> <size>`, a line feed, `size`
/// bytes and a line feed, which `found` turns into a value, or `<name> missing` and a line feed, `None`, where
/// the name is the one Git read, without its final carriage return. A name that is a full object id must be
/// answered with that id. Bytes after the last reply are refused.
pub(crate) fn replies<T>(
    data: &[u8],
    names: &[String],
    mut found: impl FnMut(&str, &[u8], &[u8]) -> Result<T, GitError>,
) -> Result<Vec<Option<T>>, GitError> {
    let mut values = Vec::with_capacity(names.len());
    let mut rest = data;
    for name in names {
        let ends = || {
            GitError::Truncated(format!(
                "git cat-file --batch: the reply ends before its answer for {}",
                escaped(name)
            ))
        };
        let other = || {
            GitError::Truncated(format!(
                "git cat-file --batch: the answer for {} has another form",
                escaped(name)
            ))
        };
        let at = rest
            .iter()
            .position(|&byte| byte == b'\n')
            .ok_or_else(ends)?;
        let (header, after) = (&rest[..at], &rest[at + 1..]);
        let read = name.strip_suffix('\r').unwrap_or(name);
        if header == format!("{read} missing").as_bytes() {
            values.push(None);
            rest = after;
            continue;
        }
        let fields: Vec<&[u8]> = header.split(|&byte| byte == b' ').collect();
        let [id, kind, size] = fields.as_slice() else {
            return Err(other());
        };
        if id.is_empty()
            || kind.is_empty()
            || size.is_empty()
            || !size.iter().all(u8::is_ascii_digit)
            || (is_object_id(name) && *id != name.as_bytes())
        {
            return Err(other());
        }
        let size = std::str::from_utf8(size)
            .expect("ASCII digits are UTF-8")
            .parse::<usize>()
            .map_err(|_| ends())?;
        match after.get(size) {
            Some(b'\n') => {}
            Some(_) => return Err(other()),
            None => return Err(ends()),
        }
        let body = &after[..size];
        rest = &after[size + 1..];
        values.push(Some(found(name, kind, body)?));
    }
    if !rest.is_empty() {
        return Err(GitError::Truncated(format!(
            "git cat-file --batch: the reply goes on after its {} answers",
            names.len()
        )));
    }
    Ok(values)
}

/// `is_object_id` holds for a name of 40 or 64 lowercase hexadecimal digits, the full form of a SHA-1 or a
/// SHA-256 object id.
fn is_object_id(name: &str) -> bool {
    matches!(name.len(), 40 | 64)
        && name
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn captured<S: AsRef<OsStr>>(command: &mut Command, args: &[S]) -> Result<Vec<u8>, GitError> {
    let Output {
        status,
        stdout,
        stderr,
    } = command.output().map_err(GitError::Start)?;
    if status.success() {
        Ok(stdout)
    } else {
        Err(failed(args, &stderr))
    }
}

fn failed<S: AsRef<OsStr>>(args: &[S], stderr: &[u8]) -> GitError {
    GitError::Failed(format!(
        "{}: {}",
        label(args),
        strip_str(&String::from_utf8_lossy(stderr))
    ))
}

pub(crate) fn label<S: AsRef<OsStr>>(args: &[S]) -> String {
    let mut line = String::from("git");
    for arg in args {
        line.push(' ');
        line.push_str(&Text::from_os(arg.as_ref()).to_string());
    }
    line
}

#[cfg(test)]
#[path = "git_tests.rs"]
mod tests;
