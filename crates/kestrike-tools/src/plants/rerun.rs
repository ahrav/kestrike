//! A proof rerun judged from values: whether the proof's worktree still holds the run's `Cargo.lock`, the
//! helper's exit code and output, and the verdict of the head's staged helper, which the caller asks for
//! the exit and the last line alone.

use std::path::Path;

use super::verdict::{Kind, NoVerdict};
use super::words::words;
use crate::text::Text;

/// One finished rerun of a proof: the test id, where its log and its run's output stand (each from the
/// work directory), whether the tree still holds the run's `Cargo.lock`, and the helper's exit code and
/// standard output.
#[derive(Clone, Copy, Debug)]
pub struct Rerun<'a> {
    proof: &'a Text,
    log: &'a Path,
    kept: &'a Path,
    holds_lock: bool,
    code: i32,
    out: &'a str,
}

impl<'a> Rerun<'a> {
    pub fn new(
        proof: &'a Text,
        log: &'a Path,
        kept: &'a Path,
        holds_lock: bool,
        code: i32,
        out: &'a str,
    ) -> Self {
        Self {
            proof,
            log,
            kept,
            holds_lock,
            code,
            out,
        }
    }
}

/// What the head's staged helper says of a rerun's exit and last line: whether it counts them as a
/// reported result, and the verdict it prints for that exit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HelperVerdict {
    counted: bool,
    expected: Text,
}

impl HelperVerdict {
    pub fn new(counted: bool, expected: Text) -> Self {
        Self { counted, expected }
    }
}

/// `judge_rerun` returns the rerun's exit, 0 or 1, once its tree holds the run's `Cargo.lock` and the
/// helper counts its last line beside that exit. `ask` is given the exit and the last line of the output
/// with Python's whitespace stripped, or the empty text, and is called for an exit of 0 or 1 alone.
///
/// # Errors
///
/// In this order: a tree without the run's lockfile ([`Kind::Relocked`]); exit 3 ([`Kind::Unbuilt`]);
/// another exit than 0 or 1; the error `ask` returns; and a verdict the helper does not count.
pub fn judge_rerun(
    rerun: &Rerun<'_>,
    ask: impl FnOnce(i32, &Text) -> Result<HelperVerdict, NoVerdict>,
) -> Result<u8, NoVerdict> {
    let (proof, code) = (rerun.proof, rerun.code);
    let log = Text::from_os(rerun.log.as_os_str());
    let kept = Text::from_os(rerun.kept.as_os_str());
    if !rerun.holds_lock {
        return Err(NoVerdict::of(
            Kind::Relocked,
            words!(
                "the rerun of the proof ",
                proof,
                " left the proof's worktree without the run's Cargo.lock; its output is in ",
                log,
                ".out"
            ),
        ));
    }
    if code == 3 {
        return Err(NoVerdict::of(
            Kind::Unbuilt,
            words!(
                "the rerun of the proof ",
                proof,
                " exited 3; its verdict is in ",
                log,
                ".out and its build output under ",
                kept
            ),
        ));
    }
    let exit = match code {
        0 => 0,
        1 => 1,
        _ => {
            return Err(NoVerdict::plain(words!(
                "the rerun of the proof ",
                proof,
                " exited ",
                code,
                "; its verdict is in ",
                log,
                ".out, its error output in ",
                log,
                ".err and its run's output under ",
                kept
            )));
        }
    };
    let lines = Text::from(rerun.out).strip().splitlines();
    let verdict = ask(code, lines.last().unwrap_or(&Text::new()))?;
    if !verdict.counted {
        return Err(NoVerdict::plain(words!(
            "the rerun of the proof ",
            proof,
            " exited ",
            code,
            " without the verdict `",
            verdict.expected,
            "`; its output is in ",
            log,
            ".out"
        )));
    }
    Ok(exit)
}
