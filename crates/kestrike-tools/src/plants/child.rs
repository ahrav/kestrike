//! The children a plant run starts beside Git: a command with its output in two new log files, and the
//! question to the head's staged helper.
//!
//! The run resolves each child's name through the supplied `PATH` and passes the supplied environment
//! unchanged. In each child it resets SIGINT, SIGTERM and SIGHUP from a handler to their default action,
//! keeping one that is ignored, unblocks the three, and sets SIGXFSZ to its default action. A logged
//! command inherits standard input. The run reads the signal record before it starts a logged command
//! and while it waits for one. If the signal record changes during startup, the run acts on the signal
//! once it holds the child's handle. The question to the helper runs whole: the run reads the signal
//! record just before it starts the question and after the question ends, and not while it waits.
//! When the signal record changes while a logged command is running, the run uses the child's handle to
//! send SIGTERM to that child alone and waits indefinitely for the child to exit.

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use super::ending::{Halt, Stopped};
use super::files::strerror;
use super::verdict::NoVerdict;
use crate::environ::Environ;
use crate::json::Value;
use crate::process::{
    Interrupt, child_defaults, exit_code, exited_within, file_size_signal_default, handled_set,
};
use crate::text::{Text, newlines, text};

/// The program the run starts for the head's helper and for the question to it.
pub(crate) const PYTHON: &str = "python3";

/// The question to the staged helper, given its path and, for a rerun, the exit; standard input holds
/// the helper's source as read once at the proof's setup, framed by its length in decimal and a line
/// feed, then a rerun's last line. It runs that source as the helper's module, checks that its
/// `reported` is callable, and prints as JSON the texts of the verdicts of exits 0 and 1, or whether
/// `reported` counts the exit beside the line. The helper's writes to descriptor 1 and its prints go
/// to standard error in the order it makes them, leaving standard output for the JSON answer alone.
const QUESTION: &str = "import importlib.util, json, os, sys
answer_out = os.dup(1)
os.dup2(2, 1)
sys.stdout = sys.stderr
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

/// `defaults` makes the child reset each handled signal that has a handler to its default action,
/// unblock the three and set SIGXFSZ to its default action, whatever `session` is; when `session` is
/// true, the child also starts the program as a new session leader.
fn defaults(command: &mut Command, session: bool) {
    let handled = handled_set();
    // SAFETY: the hook runs in the forked child before `exec` and calls only `setsid`, then
    // `child_defaults` and `file_size_signal_default`, whose contracts state that they call only
    // async-signal-safe functions (`sigaction`, `sigprocmask` and `signal`); the error path reads
    // `errno` alone. The closure owns its initialized `handled` set.
    unsafe {
        command.pre_exec(move || {
            if session && libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            child_defaults(&handled)?;
            file_size_signal_default()
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
/// SIGTERM goes to the child by its process id, which is sound only while `logged` holds the child
/// unreaped and is its one waiter: no other code of the process waits for any child, and SIGCHLD is
/// not ignored.
///
/// # Errors
///
/// `Stopped::NoVerdict`: an empty `argv`, before either log is created; a log that cannot be created;
/// a child that cannot be started or waited for; standard output that is no UTF-8. A wait that fails
/// leaves the child as it stands, since its state is unknown.
///
/// `Stopped::Halt`: `Halt::Interrupted` for a signal recorded at the check just before the spawn, when
/// both logs exist and no child has started, or for one recorded while the child runs, once SIGTERM
/// has gone to the child and the child has exited; `Halt::Failed` when that SIGTERM cannot be sent or
/// the wait after it fails.
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

/// `unnamed` opens a new file with no name in the directory `dir`, readable and writable by this
/// process alone; it goes when its last descriptor closes.
fn unnamed(dir: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_TMPFILE)
        .open(dir)
}

/// `sampled` reads `file` from its start up to the length it has when `sampled` is called, by
/// positioned reads that leave the file offset, which a descendant may share, as it stands.
fn sampled(file: &File) -> io::Result<Vec<u8>> {
    let len = usize::try_from(file.metadata()?.len())
        .map_err(|_| io::Error::from_raw_os_error(libc::EFBIG))?;
    let mut bytes = vec![0; len];
    let mut read = 0;
    while read < len {
        match file.read_at(&mut bytes[read..], read as u64) {
            Ok(0) => break,
            Ok(count) => read += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    bytes.truncate(read);
    Ok(bytes)
}

/// `asked` starts the question to the `staged` helper in a `python3 -B` child and returns its answer
/// once the child has exited. The question's three streams are files with no name in the staged
/// directory, so the wait
/// ends at the child's exit even while a descendant holds a stream open. Each output stream is read
/// from its start up to its length after the child's exit; standard error is read only when the child
/// gives no accepted answer. An answer is accepted when the child exits 0 and its standard output is
/// UTF-8 text that holds one JSON value of the shape `shape` takes. A signal recorded in `interrupt`
/// just before the spawn starts no child.
///
/// # Errors
///
/// Setup, spawn, wait and output-read errors carry the prefix `` `python3` did not run: ``; a signal
/// recorded before the spawn gives `` `python3` did not start: a signal was recorded ``. When the child
/// gives no accepted answer, `asked` returns the last line of stripped stderr, or the message
/// `` `python3` exited {exit} with no answer `` if stripped stderr is empty.
fn asked<T>(
    staged: &Staged<'_>,
    code: Option<i32>,
    input: &[u8],
    interrupt: &Interrupt,
    shape: impl FnOnce(Value) -> Option<T>,
) -> Result<T, Text> {
    let Staged {
        env,
        dir,
        helper,
        source,
    } = *staged;
    let failed = |error: io::Error| text!("`python3` did not run: ", strerror(&error));
    let framed = format!("{}\n", source.len());
    let mut stdin = unnamed(dir).map_err(failed)?;
    crate::fixtures::fits(framed.len() + source.len() + input.len())
        .and_then(|()| stdin.write_all(framed.as_bytes()))
        .and_then(|()| stdin.write_all(source))
        .and_then(|()| stdin.write_all(input))
        .and_then(|()| stdin.rewind())
        .map_err(failed)?;
    let stdout = unnamed(dir).map_err(failed)?;
    let stderr = unnamed(dir).map_err(failed)?;
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
    if interrupt.check().is_err() {
        return Err(Text::from("`python3` did not start: a signal was recorded"));
    }
    let status = command
        .spawn()
        .and_then(|mut child| child.wait())
        .map_err(failed)?;
    let exit = exit_code(status);
    let printed = sampled(&stdout).map_err(failed)?;
    let answer =
        match std::str::from_utf8(&printed).map(|read| crate::json::parse_unique(read.trim())) {
            Ok(Ok(value)) if exit == 0 => shape(value),
            _ => None,
        };
    if let Some(answer) = answer {
        return Ok(answer);
    }
    let errors = sampled(&stderr).map_err(failed)?;
    let errors = Text::from(String::from_utf8_lossy(&errors).into_owned());
    match errors.strip().splitlines().last() {
        Some(last) => Err(last.clone()),
        None => Err(text!("`python3` exited ", exit, " with no answer")),
    }
}

/// The staged helper the question loads: its path, its source as read once, and the directory that
/// holds the question's streams.
pub(crate) struct Staged<'a> {
    pub env: &'a Environ,
    pub dir: &'a Path,
    pub helper: &'a Path,
    pub source: &'a [u8],
}

/// `verdict_texts` returns the helper's verdict texts in exit-code order: 0, then 1.
///
/// # Errors
///
/// As [`asked`].
pub(crate) fn verdict_texts(staged: &Staged<'_>, interrupt: &Interrupt) -> Result<[Text; 2], Text> {
    asked(staged, None, &[], interrupt, |value| match value {
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
    staged: &Staged<'_>,
    code: i32,
    line: &Text,
    interrupt: &Interrupt,
) -> Result<bool, Text> {
    asked(
        staged,
        Some(code),
        line.as_bytes(),
        interrupt,
        |value| match value {
            Value::Bool(counted) => Some(counted),
            _ => None,
        },
    )
}

#[cfg(test)]
#[path = "child_tests.rs"]
mod tests;
