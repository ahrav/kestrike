//! A command's class: how it ended, and the class a parsed bundle summary
//! earns.

use crate::exit::Sim;
use crate::protocol::{Summary, Terminal};

/// A command's end: its class, and why.
#[derive(Debug)]
pub(super) struct Stop(pub(super) Sim, pub(super) String);

pub(super) fn rejected(reason: impl Into<String>) -> Stop {
    Stop(Sim::Rejected, reason.into())
}

pub(super) fn incomplete(reason: impl Into<String>) -> Stop {
    Stop(Sim::Incomplete, reason.into())
}

/// The run form's exit code for incomplete evidence, which a run that
/// panicked is.
pub(crate) const INCOMPLETE: i32 = 3;

/// The class `summary` earns alone and the run form's exit code that
/// agrees with it: 0 for a counting bundle, 1 for another complete one, 3
/// for an incomplete one. `None` for a summary that counts without a
/// decision, which earns no class.
fn earned(summary: &Summary) -> Option<(Sim, i32)> {
    if summary.counts {
        summary
            .decisions
            .is_some_and(|count| count > 0)
            .then_some((Sim::Counts, 0))
    } else if matches!(summary.terminal, Terminal::Complete { .. }) {
        Some((Sim::Complete, 1))
    } else {
        Some((Sim::Incomplete, INCOMPLETE))
    }
}

/// Whether `summary` earns a class and the run form's exit code `exit` is
/// the one that agrees with it.
pub(crate) fn agrees(summary: &Summary, exit: i32) -> bool {
    earned(summary).is_some_and(|(_, agreed)| agreed == exit)
}

/// The class a parsed bundle summary earns, and why. `exit`, the run
/// form's exit code, must agree with the class.
pub(super) fn credit(summary: &Summary, exit: Option<i32>) -> Stop {
    let terminal = summary.terminal;
    let decisions = summary
        .decisions
        .map_or_else(|| "unrecorded".to_owned(), |count| count.to_string());
    let described = format!(
        "{terminal}, digest {}, {decisions} decisions",
        summary.digest
    );
    let Some((class, agreed)) = earned(summary) else {
        return incomplete(format!(
            "the worker counts a bundle without a decision: {described}"
        ));
    };
    match exit {
        Some(exit) if exit != agreed => incomplete(format!(
            "the worker exited {exit}, and its summary earns {}: {described}",
            class.name()
        )),
        _ => Stop(class, format!("{}: {described}", class.name())),
    }
}
