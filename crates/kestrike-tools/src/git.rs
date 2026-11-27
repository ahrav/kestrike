//! These functions pass argument vectors to Git and read its standard output as strict UTF-8.

use std::ffi::OsStr;
use std::fmt;
use std::io::{self, Write};
use std::process::{Command, Output, Stdio};

use crate::text::{Text, strip_str};

const PATHSPEC_AND_DIFF_VARIABLES: [&str; 3] =
    ["GIT_ICASE_PATHSPECS", "GIT_GLOB_PATHSPECS", "GIT_DIFF_OPTS"];

#[derive(Debug)]
pub enum GitError {
    Start(io::Error),
    Io(io::Error),
    Failed(String),
    NotUtf8(String),
    Truncated(String),
}

impl fmt::Display for GitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Start(error) => write!(f, "git: {error}"),
            Self::Io(error) => write!(f, "git cat-file --batch: {error}"),
            Self::Failed(text) | Self::NotUtf8(text) | Self::Truncated(text) => f.write_str(text),
        }
    }
}

impl std::error::Error for GitError {}

/// `git` returns the standard output of `git args` in the caller's environment. Its [`GitError::NotUtf8`]
/// holds the decoder's message verbatim.
pub fn git<S: AsRef<OsStr>>(args: &[S]) -> Result<String, GitError> {
    let output = captured(Command::new("git").args(args), args)?;
    String::from_utf8(output).map_err(|error| GitError::NotUtf8(error.utf8_error().to_string()))
}

pub fn git_text<S: AsRef<OsStr>>(args: &[S]) -> Result<String, GitError> {
    let mut command = Command::new("git");
    command.args(args);
    for name in PATHSPEC_AND_DIFF_VARIABLES {
        command.env_remove(name);
    }
    let output = captured(&mut command, args)?;
    String::from_utf8(output)
        .map_err(|error| GitError::NotUtf8(format!("{}: {}", label(args), error.utf8_error())))
}

pub fn merge_base(one: &str, other: &str) -> Result<Option<String>, GitError> {
    let args = ["merge-base", one, other];
    let output = Command::new("git")
        .args(args)
        .output()
        .map_err(GitError::Start)?;
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

pub fn blob_texts(specs: &[String]) -> Result<Vec<String>, GitError> {
    let input: String = specs.iter().map(|spec| format!("{spec}\n")).collect();
    let mut child = Command::new("git")
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
        let writer = scope.spawn(move || match stdin.write_all(input.as_bytes()) {
            Err(error) if error.kind() != io::ErrorKind::BrokenPipe => Err(error),
            _ => Ok(()),
        });
        let output = child.wait_with_output();
        let written = writer.join().expect("the writer thread returns");
        written.and(output)
    })
    .map_err(GitError::Io)?;
    if !output.status.success() {
        return Err(failed(&["cat-file", "--batch"], &output.stderr));
    }
    batch_texts(&output.stdout, specs)
}

pub(crate) fn batch_texts(data: &[u8], specs: &[String]) -> Result<Vec<String>, GitError> {
    let mut texts = Vec::with_capacity(specs.len());
    let mut at = 0;
    for spec in specs {
        let end = data
            .get(at..)
            .and_then(|rest| rest.iter().position(|&byte| byte == b'\n'))
            .map(|offset| at + offset)
            .ok_or_else(|| {
                GitError::Truncated(format!(
                    "git cat-file --batch: the reply ends before its answer for {spec}"
                ))
            })?;
        let header: Vec<&[u8]> = data[at..end]
            .split(|&byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c))
            .filter(|word| !word.is_empty())
            .collect();
        at = end + 1;
        let (kind, size) = match header.as_slice() {
            [_, kind, size] if size.iter().all(u8::is_ascii_digit) => (*kind, *size),
            _ => {
                texts.push(String::new());
                continue;
            }
        };
        let size = std::str::from_utf8(size)
            .expect("ASCII digits are UTF-8")
            .parse::<usize>()
            .unwrap_or(usize::MAX);
        let body = &data[at.min(data.len())..at.saturating_add(size).min(data.len())];
        if kind == b"blob" {
            let text = std::str::from_utf8(body)
                .map_err(|error| GitError::NotUtf8(format!("{spec}: {error}")))?;
            texts.push(text.to_owned());
        } else {
            texts.push(String::new());
        }
        at = at.saturating_add(size).saturating_add(1);
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
