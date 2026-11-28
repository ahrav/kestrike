//! The tool's entry: the checks, the run with its signal handlers, the cleanup and the score.
//!
//! The run reads `GIT_NO_REPLACE_OBJECTS=1` into the environment of every child and changes no variable
//! of its own process. It installs the handlers of SIGINT, SIGTERM and SIGHUP once its work directory
//! stands; a signal recorded before the score's write ends the run, after its cleanup, with 128 plus
//! the signal and no score, and one recorded once the write has begun changes nothing.

use std::ffi::OsString;
use std::io::{self, Write};
use std::path::Path;

use crate::plants::{Halt, Inputs, Outcome, Run, conclude, prepare, publish, score};
use crate::process::{INTERRUPT, install_handlers};
use crate::text::{Text, text};

fn say(out: &mut impl Write, line: &Text) {
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

/// `run` runs the plants the checks select, from the invoking directory's checkout.
pub fn run(_top: &Path, args: &[OsString]) -> u8 {
    let env = std::env::vars_os().collect();
    let (mut out, mut err) = (io::stdout().lock(), io::stderr().lock());
    let inputs = match prepare(args, env, std::env::current_dir()) {
        Outcome::Run(inputs) => inputs,
        Outcome::Help(text) => {
            let _ = out.write_all(text.as_bytes());
            return 0;
        }
        Outcome::Usage { code, text } => {
            let _ = err.write_all(text.as_bytes());
            return code;
        }
        Outcome::Rejected(reason) => {
            say(&mut err, &text!("plant-runner rejected: ", reason));
            return 2;
        }
        Outcome::Failed(reason) => {
            say(&mut err, &text!("plant-runner: ", reason));
            return 4;
        }
    };
    say(&mut err, &text!("work: ", inputs.work()));
    match started(&inputs) {
        Ok(run) => finished(&inputs, run, &mut out, &mut err),
        Err(halt) => failed(&halt, &mut err),
    }
}

fn failed(halt: &Halt, err: &mut impl Write) -> u8 {
    if let Halt::Failed(reason) = halt {
        say(err, &text!("plant-runner: ", reason));
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
/// remains, and returns whether one does. It reads no signal record.
fn cleanup(inputs: &Inputs, run: &Run<'_>, err: &mut impl Write) -> Result<bool, Halt> {
    let remained = run.remove_trees()?;
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
        say(err, &line);
    }
    let target = inputs.work().join("proof").join("target");
    crate::plants::remove(&target);
    if target.exists() {
        say(
            err,
            &text!("plant-runner left the proof's target directory ", target),
        );
    }
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
