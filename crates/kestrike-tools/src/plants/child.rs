//! The children a plant run starts beside Git: a command with its output in two new log files, and the
//! question to the head's staged helper.
//!
//! The run resolves each child's name through the supplied `PATH`, passes the supplied environment
//! unchanged, and restores the default action for each handled signal in the child. A logged command
//! inherits standard input. The run reads the signal record before it starts a logged command and while
//! it waits for one. If the signal record changes during startup, the run acts on the signal once it
//! holds the child's handle. The run waits for the helper to finish before reading the signal record.
//! When the signal record changes while a logged command is running, the run uses the child's handle to
//! send SIGTERM to that child alone and waits indefinitely for the child to exit.

use std::ffi::{CStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::os::fd::FromRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use super::ending::{Halt, Stopped};
use super::files::strerror;
use super::verdict::NoVerdict;
use crate::environ::Environ;
use crate::json::Value;
use crate::process::{Interrupt, child_defaults, exit_code, exited_within, handled_set};
use crate::text::{Text, newlines, text};

/// The program the run starts for the head's helper and for the question to it.
pub(crate) const PYTHON: &str = "python3";

/// The question to the staged helper, given its path and, for a rerun, the exit; standard input holds
/// the helper's source as read once at the proof's setup, framed by its length in decimal and a line
/// feed, then a rerun's last line. It runs that source as the helper's module, checks that its
/// `reported` is callable, and prints as JSON the texts of the verdicts of exits 0 and 1, or whether
/// `reported` counts the exit beside the line. The helper's writes to descriptor 1 go to standard error, leaving standard output for the JSON
/// answer alone.
const QUESTION: &str = "import importlib.util, json, os, sys
answer_out = os.dup(1)
os.dup2(2, 1)
size, _, given = sys.stdin.buffer.read().partition(b'\\n')
source, line = given[:int(size)], given[int(size):]
spec = importlib.util.spec_from_loader('staged_reproduce_test', loader=None, origin=sys.argv[1])
module = importlib.util.module_from_spec(spec)
module.__file__ = sys.argv[1]
exec(compile(source, sys.argv[1], 'exec'), module.__dict__)
if not callable(module.reported):
    raise TypeError('its `reported` is not callable')
if len(sys.argv) == 2:
    answer = [str(module.RESULTS[code]) for code in (0, 1)]
else:
    answer = bool(module.reported(int(sys.argv[2]), line.decode()))
os.write(answer_out, (json.dumps(answer) + '\\n').encode())
";

/// When `session` is true, the child starts the program as a new session leader.
fn defaults(command: &mut Command, session: bool) {
    let handled = handled_set();
    // SAFETY: `pre_exec` runs the hook in the forked child, so every call in the hook, including the
    // error path, must be async-signal-safe. The closure owns its initialized `handled` set.
    unsafe {
        command.pre_exec(move || {
            if session && libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            child_defaults(&handled)
        });
    }
}

/// `terminate` sends SIGTERM to the child, which is held unreaped, and waits for it with no limit.
///
/// # Errors
///
/// The signal cannot be sent, which leaves the child unwaited, or the wait fails.
fn terminate(child: &mut Child) -> Result<(), Halt> {
    let pid = libc::pid_t::try_from(child.id()).expect("a process id fits pid_t");
    let failed =
        |error: io::Error| Halt::Failed(text!("a child cannot be stopped: ", strerror(&error)));
    // SAFETY: `kill` takes two integers and touches no memory of the caller.
    if unsafe { libc::kill(pid, libc::SIGTERM) } != 0 {
        return Err(failed(io::Error::last_os_error()));
    }
    child.wait().map(drop).map_err(failed)
}

/// A command the run starts with its output in two log files.
pub struct Logged<'a> {
    /// The logs' path without `.out` and `.err`.
    pub log: &'a Path,
    pub argv: &'a [OsString],
    /// The command's name in a reason.
    pub what: &'a str,
    pub cwd: Option<&'a Path>,
    pub env: &'a Environ,
    /// Whether the child leads a session of its own, so a signal to the run's process group reaches it
    /// through the run alone.
    pub session: bool,
    /// The work directory, from which a reason names the logs.
    pub work: &'a Path,
}

fn suffixed(log: &Path, suffix: &str) -> PathBuf {
    let mut name = log.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

fn did_not_run(what: &str, error: &io::Error) -> Stopped {
    Stopped::NoVerdict(NoVerdict::plain(text!(
        "`",
        what,
        "` did not run: ",
        strerror(error)
    )))
}

/// `logged` runs the command with its standard output in `LOG.out` and its error output in `LOG.err`.
/// It creates each log exclusively and returns the child's exit code or the negated terminating signal
/// number, with the child's standard output as UTF-8 text, `\r\n` and `\r` read as `\n`.
///
/// # Errors
///
/// `logged` returns `Stopped::NoVerdict` for an empty `argv` before it creates either log, and when log
/// creation, child startup, waiting for the child, or UTF-8 decoding of standard output fails. A wait
/// that fails leaves the child as it stands, since its state is unknown. `logged` checks for a recorded
/// signal before spawning the child and returns early if it finds one. If the wait detects a signal,
/// `logged` sends SIGTERM and waits for the child to exit.
pub fn logged(started: &Logged<'_>, interrupt: &Interrupt) -> Result<(i32, String), Stopped> {
    let what = started.what;
    let Some((program, args)) = started.argv.split_first() else {
        let error = io::Error::new(io::ErrorKind::InvalidInput, "the command names no program");
        return Err(did_not_run(what, &error));
    };
    let create = |suffix| {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(suffixed(started.log, suffix))
    };
    let mut out = create(".out").map_err(|error| did_not_run(what, &error))?;
    let err = create(".err").map_err(|error| did_not_run(what, &error))?;
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .envs(started.env.iter().cloned())
        .stdin(Stdio::inherit())
        .stdout(out.try_clone().map_err(|error| did_not_run(what, &error))?)
        .stderr(err);
    if let Some(cwd) = started.cwd {
        command.current_dir(cwd);
    }
    defaults(&mut command, started.session);
    interrupt.check()?;
    let mut child = command.spawn().map_err(|error| did_not_run(what, &error))?;
    let status = match exited_within(&mut child, Duration::MAX, Some(interrupt)) {
        Ok(Some(status)) => status,
        Ok(None) => {
            terminate(&mut child)?;
            interrupt.check()?;
            unreachable!("a wait ends early only on a recorded signal");
        }
        Err(error) => return Err(did_not_run(what, &error)),
    };
    let code = exit_code(status);
    let mut bytes = Vec::new();
    out.rewind()
        .and_then(|()| out.read_to_end(&mut bytes))
        .map_err(|error| did_not_run(what, &error))?;
    match String::from_utf8(bytes) {
        Ok(read) => Ok((code, newlines(read))),
        Err(error) => {
            let log = started
                .log
                .strip_prefix(started.work)
                .unwrap_or(started.log);
            Err(Stopped::NoVerdict(NoVerdict::plain(text!(
                "`",
                what,
                "` exited ",
                code,
                " and printed no UTF-8 text (",
                error.utf8_error().to_string(),
                "); its output is in ",
                log,
                ".out"
            ))))
        }
    }
}

fn memory_file(name: &CStr) -> io::Result<File> {
    // SAFETY: `name` is a NUL-terminated string that outlives the call.
    let descriptor = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `descriptor` is a new open descriptor that this call alone owns.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

/// The question's three streams are in-memory files, so the wait ends at the child's exit even while a
/// descendant holds a stream open.
///
/// # Errors
///
/// Setup, spawn, wait and output-read errors carry the prefix `` `python3` did not run: ``. When the
/// child gives no accepted answer, `asked` returns the last line of stripped stderr, or the message
/// `` `python3` exited {exit} with no answer `` if stripped stderr is empty.
fn asked<T>(
    env: &Environ,
    helper: &Path,
    source: &[u8],
    code: Option<i32>,
    input: &[u8],
    shape: impl FnOnce(Value) -> Option<T>,
) -> Result<T, Text> {
    let failed = |error: io::Error| text!("`python3` did not run: ", strerror(&error));
    let mut stdin = memory_file(c"question-in").map_err(failed)?;
    stdin
        .write_all(format!("{}\n", source.len()).as_bytes())
        .and_then(|()| stdin.write_all(source))
        .and_then(|()| stdin.write_all(input))
        .and_then(|()| stdin.rewind())
        .map_err(failed)?;
    let mut stdout = memory_file(c"question-out").map_err(failed)?;
    let mut stderr = memory_file(c"question-err").map_err(failed)?;
    let mut command = Command::new(PYTHON);
    command
        .args(["-B", "-c", QUESTION])
        .arg(helper)
        .env_clear()
        .envs(env.iter().cloned())
        .stdin(stdin)
        .stdout(stdout.try_clone().map_err(failed)?)
        .stderr(stderr.try_clone().map_err(failed)?);
    if let Some(code) = code {
        command.arg(code.to_string());
    }
    defaults(&mut command, false);
    let status = command
        .spawn()
        .and_then(|mut child| child.wait())
        .map_err(failed)?;
    let read = |file: &mut File| {
        let mut bytes = Vec::new();
        file.rewind()
            .and_then(|()| file.read_to_end(&mut bytes))
            .map(|_| bytes)
    };
    let printed = read(&mut stdout).map_err(failed)?;
    let errors = read(&mut stderr).map_err(failed)?;
    let exit = exit_code(status);
    let answer = match crate::json::parse_unique(String::from_utf8_lossy(&printed).trim()) {
        Ok(value) if exit == 0 => shape(value),
        _ => None,
    };
    answer.ok_or_else(|| {
        let errors = Text::from(String::from_utf8_lossy(&errors).into_owned());
        match errors.strip().splitlines().last() {
            Some(last) => last.clone(),
            None => text!("`python3` exited ", exit, " with no answer"),
        }
    })
}

/// `verdict_texts` returns the helper's verdict texts in exit-code order: 0, then 1.
///
/// # Errors
///
/// As [`asked`].
pub(crate) fn verdict_texts(
    env: &Environ,
    helper: &Path,
    source: &[u8],
) -> Result<[Text; 2], Text> {
    asked(env, helper, source, None, &[], |value| match value {
        Value::Array(items) => match <[Value; 2]>::try_from(items) {
            Ok([Value::String(zero), Value::String(one)]) => Some([zero, one]),
            _ => None,
        },
        _ => None,
    })
}

/// `counts` returns the Boolean answer for exit `code` and last line `line`.
///
/// # Errors
///
/// As [`asked`].
pub(crate) fn counts(
    env: &Environ,
    helper: &Path,
    source: &[u8],
    code: i32,
    line: &Text,
) -> Result<bool, Text> {
    asked(
        env,
        helper,
        source,
        Some(code),
        line.as_bytes(),
        |value| match value {
            Value::Bool(counted) => Some(counted),
            _ => None,
        },
    )
}

#[cfg(test)]
#[path = "child_tests.rs"]
mod tests;
