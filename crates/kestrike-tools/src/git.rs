//! These functions pass argument vectors to Git and read its standard output as strict UTF-8. Every Git
//! child of this module starts from `command`, which sets `GIT_NO_REPLACE_OBJECTS=1`, so Git reads each
//! object as the repository stores it and no `refs/replace` entry stands in for one.

use std::ffi::OsStr;
use std::fmt;
use std::io::{self, Write};
use std::process::{Command, Output, Stdio};

use crate::text::{Text, escaped, strip_str};

const PATHSPEC_AND_DIFF_VARIABLES: [&str; 3] =
    ["GIT_ICASE_PATHSPECS", "GIT_GLOB_PATHSPECS", "GIT_DIFF_OPTS"];

/// A Git command that did not give its output. `Display` writes the line a tool prints after its own name.
#[derive(Debug)]
pub enum GitError {
    /// `Start` wraps an error from `Command::output` or `Command::spawn`, including a failure to launch Git:
    /// `git: ` and the system's error.
    Start(io::Error),
    /// `blob_texts` returns this error if a batch write fails with an error other than a closed pipe, the
    /// writer thread fails to start, or reading the child's output or status fails:
    /// `git cat-file --batch: ` and the system's error.
    Io(io::Error),
    /// Git exited with a failure: the command as `git <arguments>`, `: ` and Git's standard error with white
    /// space stripped at both ends and each byte sequence that is not UTF-8 replaced by U+FFFD.
    Failed(String),
    /// Git's output is not UTF-8: the decoder's message, after the command or the request's name where the
    /// function names one.
    NotUtf8(String),
    /// `Truncated` identifies the request for an incomplete or malformed reply of `git cat-file --batch`. It
    /// also reports trailing bytes after the final reply, with the number of answers read.
    Truncated(String),
    /// `blob_texts` returns `Name` for a batch name that contains a line feed or NUL or ends in a carriage
    /// return. Git reads a line feed in a batch name as a request separator, reads a name up to a NUL, and
    /// strips a final carriage return.
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

/// `command` is `git` in the caller's environment with `GIT_NO_REPLACE_OBJECTS=1` added.
fn command() -> Command {
    let mut command = Command::new("git");
    command.env("GIT_NO_REPLACE_OBJECTS", "1");
    command
}

/// `git` returns the standard output of `git args` in the caller's environment; `git` sets
/// `GIT_NO_REPLACE_OBJECTS=1` in the child's environment. Git that does not start is [`GitError::Start`], a
/// failed command is [`GitError::Failed`], and its [`GitError::NotUtf8`] holds the decoder's message verbatim.
pub fn git<S: AsRef<OsStr>>(args: &[S]) -> Result<String, GitError> {
    let output = captured(command().args(args), args)?;
    String::from_utf8(output).map_err(|error| GitError::NotUtf8(error.utf8_error().to_string()))
}

/// `git_text` returns the standard output of `git args`. It removes `GIT_ICASE_PATHSPECS`,
/// `GIT_GLOB_PATHSPECS` and `GIT_DIFF_OPTS` from the child's environment and sets `GIT_NO_REPLACE_OBJECTS=1`.
/// Git that does not start is [`GitError::Start`], a failed command is [`GitError::Failed`], and output that
/// is not UTF-8 is [`GitError::NotUtf8`] after the command.
pub fn git_text<S: AsRef<OsStr>>(args: &[S]) -> Result<String, GitError> {
    let mut git = command();
    git.args(args);
    for name in PATHSPEC_AND_DIFF_VARIABLES {
        git.env_remove(name);
    }
    let output = captured(&mut git, args)?;
    String::from_utf8(output)
        .map_err(|error| GitError::NotUtf8(format!("{}: {}", label(args), error.utf8_error())))
}

/// `merge_base` returns the output of `git merge-base one other` with white space stripped at both ends, and
/// `None` when Git exits 1 with no output, as it does for two commits that share no history. It removes
/// nothing from the caller's environment. Git that does not start is [`GitError::Start`], any other failed
/// exit is [`GitError::Failed`], and output that is not UTF-8 is [`GitError::NotUtf8`].
pub fn merge_base(one: &str, other: &str) -> Result<Option<String>, GitError> {
    let args = ["merge-base", one, other];
    let output = command().args(args).output().map_err(GitError::Start)?;
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
/// `git cat-file --batch`: a blob's bytes, and an empty text for a name Git reports missing and for an object
/// other than a blob. `blob_texts` inherits the caller's environment and sets `GIT_NO_REPLACE_OBJECTS=1`. A
/// name that holds a line feed or a NUL, or that ends in a carriage return, is [`GitError::Name`] before Git
/// starts. Git that does not start is [`GitError::Start`], a failed write or
/// read is [`GitError::Io`], a failed exit is [`GitError::Failed`], a reply that leaves the batch
/// framing is [`GitError::Truncated`], and a blob that is not UTF-8 is [`GitError::NotUtf8`] after its name.
pub fn blob_texts(specs: &[String]) -> Result<Vec<String>, GitError> {
    for spec in specs {
        let misread = if spec.contains('\n') {
            "holds a line feed"
        } else if spec.contains('\0') {
            "holds a NUL"
        } else if spec.ends_with('\r') {
            "ends in a carriage return"
        } else {
            continue;
        };
        return Err(GitError::Name(format!(
            "git cat-file --batch: the name {} {misread}",
            Text::from(spec.as_str()).repr()
        )));
    }
    let input: String = specs.iter().map(|spec| format!("{spec}\n")).collect();
    let mut child = command()
        .args(["cat-file", "--batch"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(GitError::Start)?;
    let mut stdin = child
        .stdin
        .take()
        .expect("the child's standard input is piped");
    let output = std::thread::scope(|scope| {
        let writer = std::thread::Builder::new().spawn_scoped(scope, move || {
            match stdin.write_all(input.as_bytes()) {
                Err(error) if error.kind() != io::ErrorKind::BrokenPipe => Err(error),
                _ => Ok(()),
            }
        });
        let output = child.wait_with_output();
        let written = writer.and_then(|handle| handle.join().expect("the writer thread returns"));
        written.and(output)
    })
    .map_err(GitError::Io)?;
    if !output.status.success() {
        return Err(failed(&["cat-file", "--batch"], &output.stderr));
    }
    batch_texts(&output.stdout, specs)
}

/// `batch_texts` reads one reply for each name of `specs`, in order: `<id> <type> <size>`, a line feed, `size`
/// bytes and a line feed, or `<name> missing` and a line feed for that name. Bytes after the last reply are
/// refused.
pub(crate) fn batch_texts(data: &[u8], specs: &[String]) -> Result<Vec<String>, GitError> {
    let mut texts = Vec::with_capacity(specs.len());
    let mut rest = data;
    for spec in specs {
        let ends = || {
            GitError::Truncated(format!(
                "git cat-file --batch: the reply ends before its answer for {}",
                escaped(spec)
            ))
        };
        let other = || {
            GitError::Truncated(format!(
                "git cat-file --batch: the answer for {} has another form",
                escaped(spec)
            ))
        };
        let at = rest
            .iter()
            .position(|&byte| byte == b'\n')
            .ok_or_else(ends)?;
        let (header, after) = (&rest[..at], &rest[at + 1..]);
        if header == format!("{spec} missing").as_bytes() {
            texts.push(String::new());
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
        if *kind == b"blob" {
            let text = std::str::from_utf8(body)
                .map_err(|error| GitError::NotUtf8(format!("{spec}: {error}")))?;
            texts.push(text.to_owned());
        } else {
            texts.push(String::new());
        }
    }
    if !rest.is_empty() {
        return Err(GitError::Truncated(format!(
            "git cat-file --batch: the reply goes on after its {} answers",
            specs.len()
        )));
    }
    Ok(texts)
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
