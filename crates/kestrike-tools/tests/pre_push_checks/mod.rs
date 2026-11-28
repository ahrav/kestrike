//! The cases of the pre-push hook's library and tool: the seven cases of the hook's self-test that call its
//! functions alone, rows that each assert one value of a ref line's plan, a guard sentence, a Git read or
//! the scan's entry, each named by the hook case whose input it reuses, and the hook's cases that start the
//! tool `pre-push-checks` over the self-test's repository.

mod cancelled;
mod chaos_checks;
mod exits;
mod functions;
mod guard;
mod guarded;
mod lines;
pub(crate) mod push;
mod reads;
mod ref_lines;
mod repository;
mod scanned;
mod selected;
mod selection;
