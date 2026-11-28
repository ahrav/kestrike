//! The children a plant run starts beside Git: a command with its output in two new log files, and the
//! question to the head's staged helper; and the endings of a step and of a run.
//!
//! A child is started by name, found through the `PATH` of the environment it is given, with that
//! environment as its whole environment, standard input inherited and each handled signal back at its
//! default action. The run reads the signal record before it starts a logged command and while it waits
//! for one; a signal recorded during the start is acted on once the child's handle is held. The question
//! to the helper runs whole, and the run reads the record after it. A child that runs
//! when a signal is recorded gets SIGTERM, by its handle and alone, and the run waits for it with no
//! limit before it ends.

use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{self, Read, Seek};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use super::files::strerror;
use super::git::CallError;
use super::verdict::NoVerdict;
use crate::environ::Environ;
use crate::process::{Interrupt, Interrupted, SIGNALS, exit_code, exited_within};
use crate::text::{Text, newlines, text};

/// Why a run ends before its score: a recorded signal, or a failure outside a plant, exit 4.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Halt {
    Interrupted(i32),
    Failed(Text),
}

impl Halt {
    /// `code` is the tool's exit: 128 plus the signal, or 4 for a failure or a signal number whose exit
    /// is no byte.
    pub fn code(&self) -> u8 {
        match self {
            Self::Interrupted(signal) => signal
                .checked_add(128)
                .and_then(|code| u8::try_from(code).ok())
                .unwrap_or(4),
            Self::Failed(_) => 4,
        }
    }
}

impl From<Interrupted> for Halt {
    fn from(Interrupted(signal): Interrupted) -> Self {
        Self::Interrupted(signal)
    }
}

/// A checked Git step that exited nonzero: its subcommand, its exit code and its error output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitFailed {
    pub step: Text,
    pub code: i32,
    pub stderr: Text,
}

impl GitFailed {
    /// `shown` is `` `git STEP` exited CODE ``.
    pub(crate) fn shown(&self) -> Text {
        text!("`git ", self.step, "` exited ", self.code)
    }
}

/// How one plant's step ended without its value: the plant's no verdict, a checked Git step that
/// failed, or the end of the run.
#[derive(Debug)]
pub enum Step {
    NoVerdict(NoVerdict),
    Git(GitFailed),
    Halt(Halt),
}

impl From<NoVerdict> for Step {
    fn from(ending: NoVerdict) -> Self {
        Self::NoVerdict(ending)
    }
}

impl From<Halt> for Step {
    fn from(halt: Halt) -> Self {
        Self::Halt(halt)
    }
}

impl From<Interrupted> for Step {
    fn from(interrupted: Interrupted) -> Self {
        Self::Halt(interrupted.into())
    }
}

/// A Git call that started and printed no UTF-8 text, or that could not start or be waited for, is the
/// plant's no verdict, `the run failed: ` and the call's text.
impl From<CallError> for Step {
    fn from(error: CallError) -> Self {
        match error {
            CallError::Failed { step, code, stderr } => Self::Git(GitFailed { step, code, stderr }),
            CallError::Interrupted(interrupted) => interrupted.into(),
            other => Self::NoVerdict(NoVerdict::failed(other.to_string())),
        }
    }
}

/// The program the run starts for the head's helper and for the question to it.
pub(crate) const PYTHON: &str = "python3";

/// The question to the staged helper, given its path and, for a rerun, the exit and the last line on
/// standard input. It loads the helper as a module, checks that its `reported` is callable, and prints
/// as JSON the texts of the verdicts of exits 0 and 1, or whether `reported` counts the exit beside the
/// line. What the helper prints while it loads or answers goes to standard error, so standard output
/// holds the answer alone.
const QUESTION: &str = "import contextlib, importlib.util, json, sys
with contextlib.redirect_stdout(sys.stderr):
    spec = importlib.util.spec_from_file_location('staged_reproduce_test', sys.argv[1])
    if spec is None or spec.loader is None:
        raise ImportError(sys.argv[1] + ' has no loader')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not callable(module.reported):
        raise TypeError('its `reported` is not callable')
    if len(sys.argv) == 2:
        answer = [str(module.RESULTS[code]) for code in (0, 1)]
    else:
        answer = bool(module.reported(int(sys.argv[2]), sys.stdin.buffer.read().decode()))
print(json.dumps(answer))
";

/// `defaults` makes the child of `command` set each handled signal that has a handler back to its
/// default action before it runs the program, and with `session` lead a session of its own.
fn defaults(command: &mut Command, session: bool) {
    // SAFETY: the hook runs in the forked child before `exec` and calls only `setsid` and `sigaction`,
    // which are async-signal-safe; it writes only `current`, a local all-zero `sigaction` (a valid value)
    // that each `sigaction` call overwrites.
    unsafe {
        command.pre_exec(move || {
            if session && libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            for signal in SIGNALS {
                let mut current: libc::sigaction = std::mem::zeroed();
                if libc::sigaction(signal, std::ptr::null(), &mut current) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if current.sa_sigaction != libc::SIG_IGN && current.sa_sigaction != libc::SIG_DFL {
                    current.sa_sigaction = libc::SIG_DFL;
                    if libc::sigaction(signal, &current, std::ptr::null_mut()) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
            }
            Ok(())
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

fn did_not_run(what: &str, error: &io::Error) -> Step {
    Step::NoVerdict(NoVerdict::plain(text!(
        "`",
        what,
        "` did not run: ",
        strerror(error)
    )))
}

/// `logged` runs the command with its standard output in `LOG.out` and its error output in `LOG.err`,
/// each created new, and returns its exit, or the negated number of the signal that ended it, and its
/// standard output as UTF-8 text with `\r\n` and `\r` read as `\n`.
///
/// # Errors
///
/// A log that cannot be created, a child that cannot start or be waited for, or an output that is no
/// UTF-8 text is the plant's no verdict; a wait that fails leaves the child as it stands, since its state
/// is unknown. A signal recorded before the start ends the run with no child started, and one recorded
/// while the child runs ends the run once the child has ended after SIGTERM.
pub fn logged(started: &Logged<'_>, interrupt: &Interrupt) -> Result<(i32, String), Step> {
    let what = started.what;
    let create = |suffix| {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(suffixed(started.log, suffix))
    };
    let mut out = create(".out").map_err(|error| did_not_run(what, &error))?;
    let err = create(".err").map_err(|error| did_not_run(what, &error))?;
    let (program, args) = started
        .argv
        .split_first()
        .expect("a logged command names its program");
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
            Err(Step::NoVerdict(NoVerdict::plain(text!(
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

/// What the staged helper answers: the texts of its verdicts of exits 0 and 1, or whether it counts a
/// rerun's exit beside its last line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Answer {
    Results([Text; 2]),
    Counted(bool),
}

/// `ask` starts `python3 -B -c QUESTION HELPER [EXIT]` in `env`, writes `line` to its standard input
/// for a rerun's question, and reads its answer. A signal recorded while it runs acts after it.
///
/// # Errors
///
/// The tool's words for an answer that did not come: the last line of the child's error output, its
/// exit, or the start that failed.
pub(crate) fn ask(
    env: &Environ,
    helper: &Path,
    rerun: Option<(i32, &Text)>,
) -> Result<Answer, Text> {
    let mut command = Command::new(PYTHON);
    command
        .args(["-B", "-c", QUESTION])
        .arg(helper)
        .env_clear()
        .envs(env.iter().cloned())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some((code, _)) = rerun {
        command.arg(code.to_string());
    }
    defaults(&mut command, false);
    let child = command
        .spawn()
        .map_err(|error| text!("`python3` did not run: ", strerror(&error)))?;
    let line = rerun.map_or(&[][..], |(_, line)| line.as_bytes());
    let output = crate::git::fed(child, line)
        .map_err(|error| text!("`python3` did not run: ", strerror(&error)))?;
    let code = exit_code(output.status);
    let printed = String::from_utf8_lossy(&output.stdout);
    let answer = match crate::json::parse_unique(printed.trim()) {
        Ok(crate::json::Value::Array(items)) if rerun.is_none() && code == 0 => match &items[..] {
            [
                crate::json::Value::String(zero),
                crate::json::Value::String(one),
            ] => Some(Answer::Results([zero.clone(), one.clone()])),
            _ => None,
        },
        Ok(crate::json::Value::Bool(counted)) if rerun.is_some() && code == 0 => {
            Some(Answer::Counted(counted))
        }
        _ => None,
    };
    answer.ok_or_else(|| {
        let errors = Text::from(String::from_utf8_lossy(&output.stderr).into_owned());
        match errors.strip().splitlines().last() {
            Some(last) => last.clone(),
            None => text!("`python3` exited ", code, " with no answer"),
        }
    })
}

#[cfg(test)]
#[path = "child_tests.rs"]
mod tests;
