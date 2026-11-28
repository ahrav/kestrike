//! The tool's entry: the checks, the run with its signal handlers, the cleanup and the score.
//!
//! The run reads `GIT_NO_REPLACE_OBJECTS=1` into the environment of every child and changes no variable
//! of its own process. It installs the handlers of SIGINT, SIGTERM and SIGHUP once its work directory
//! stands; a signal recorded before the score's write ends the run, after its cleanup, with 128 plus
//! the signal and no score, and one recorded once the write has begun changes nothing.

use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{FromRawFd, RawFd};
use std::path::Path;

use crate::plants::{
    Halt, Inputs, Outcome, Run, UNANNOUNCED, conclude, prepare, publish, said, score,
};
use crate::process::{INTERRUPT, install_handlers};
use crate::text::text;

/// A standard stream written through a duplicate of its descriptor, so a write the descriptor refuses
/// returns its error, `EBADF` of a stream opened read-only or closed included.
struct Stream(Result<File, i32>);

impl Stream {
    fn of(descriptor: RawFd) -> Self {
        // SAFETY: `fcntl` with `F_DUPFD_CLOEXEC` takes a descriptor and an integer minimum and touches
        // no memory; a closed `descriptor` gives -1.
        let copy = unsafe { libc::fcntl(descriptor, libc::F_DUPFD_CLOEXEC, 3) };
        if copy < 0 {
            return Self(Err(io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EBADF)));
        }
        // SAFETY: `copy` is a new open descriptor that this stream alone owns.
        Self(Ok(unsafe { File::from_raw_fd(copy) }))
    }
}

impl Write for Stream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match &mut self.0 {
            Ok(file) => file.write(bytes),
            Err(code) => Err(io::Error::from_raw_os_error(*code)),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.0 {
            Ok(file) => file.flush(),
            Err(code) => Err(io::Error::from_raw_os_error(*code)),
        }
    }
}

/// `run` runs the plants the checks select, from the invoking directory's checkout.
pub fn run(_top: &Path, args: &[OsString]) -> u8 {
    let env = std::env::vars_os().collect();
    let (mut out, mut err) = (
        Stream::of(libc::STDOUT_FILENO),
        Stream::of(libc::STDERR_FILENO),
    );
    if let Err(error) = crate::process::ignore_file_size_signal() {
        let _ = said(
            &mut err,
            &text!("plant-runner: SIGXFSZ: ", error.to_string()),
        );
        return 4;
    }
    let inputs = match prepare(args, env, std::env::current_dir()) {
        Outcome::Run(inputs) => inputs,
        Outcome::Help(text) => {
            return match out.write_all(text.as_bytes()).and_then(|()| out.flush()) {
                Ok(()) => 0,
                Err(_) => UNANNOUNCED,
            };
        }
        Outcome::Usage { code, text } => {
            let _ = err.write_all(text.as_bytes());
            return code;
        }
        Outcome::Rejected(reason) => {
            let _ = said(&mut err, &text!("plant-runner rejected: ", reason));
            return 2;
        }
        Outcome::Failed(reason) => {
            let _ = said(&mut err, &text!("plant-runner: ", reason));
            return 4;
        }
    };
    if said(&mut err, &text!("work: ", inputs.work())).is_err() {
        return 4;
    }
    match started(&inputs) {
        Ok(run) => finished(&inputs, run, &mut out, &mut err),
        Err(halt) => failed(&halt, &mut err),
    }
}

fn failed(halt: &Halt, err: &mut impl Write) -> u8 {
    if let Halt::Failed(reason) = halt {
        let _ = said(err, &text!("plant-runner: ", reason));
    }
    halt.code()
}

/// `started` reads the head's date and installs the handlers.
fn started(inputs: &Inputs) -> Result<Run<'_>, Halt> {
    let run = Run::new(inputs, &INTERRUPT)?;
    install_handlers()
        .map_err(|error| Halt::Failed(text!("the signal handlers: ", error.to_string())))?;
    Ok(run)
}

/// `cleanup` removes the run's worktrees and the proof's target directory, naming on `err` each one that
/// remains, and returns whether a worktree remains.
fn cleanup(inputs: &Inputs, run: &Run<'_>, err: &mut impl Write) -> Result<bool, Halt> {
    let remained = run.remove_trees()?;
    let mut written = Ok(());
    for (tree, unlisted) in &remained {
        let line = match unlisted {
            None => text!(
                "plant-runner left the worktree ",
                tree,
                "; remove it with `git worktree remove --force --force`"
            ),
            Some(code) => text!(
                "plant-runner cannot tell whether the worktree ",
                tree,
                " remains: `git worktree list` exited ",
                *code,
                "; remove it with `git worktree remove --force --force` if it does"
            ),
        };
        written = written.and(said(err, &line));
    }
    let target = inputs.work().join("proof").join("target");
    crate::plants::remove(&target);
    if target.exists() {
        written = written.and(said(
            err,
            &text!("plant-runner left the proof's target directory ", target),
        ));
    }
    written.map_err(|error| {
        Halt::Failed(text!(
            "a cleanup line cannot be written: ",
            crate::plants::files::strerror(&error)
        ))
    })?;
    Ok(!remained.is_empty())
}

/// `finished` runs the store, cleans up, and writes and prints the score.
fn finished(inputs: &Inputs, mut run: Run<'_>, out: &mut impl Write, err: &mut impl Write) -> u8 {
    let stored = run.run_store(err);
    let cleaned = cleanup(inputs, &run, err);
    if let Some(signal) = INTERRUPT.recorded() {
        return Halt::Interrupted(signal).code();
    }
    let (entries, remained) = match (stored, cleaned) {
        (Err(halt), _) | (Ok(_), Err(halt)) => return failed(&halt, err),
        (Ok(entries), Ok(remained)) => (entries, remained),
    };
    if remained {
        return 4;
    }
    let written = score::score(inputs.head(), &entries, run.settings());
    let bytes = score::bytes(&written);
    if let Some(signal) = INTERRUPT.recorded() {
        return Halt::Interrupted(signal).code();
    }
    conclude(
        inputs.head(),
        &inputs.score(),
        &entries,
        &bytes,
        publish,
        out,
        err,
    )
}
