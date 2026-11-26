//! A point check of buffer custody at the device boundary: at the instant of a call, each command the simulated device holds names its own buffer, and that buffer is in storage custody.
//!
//! [`check`] reads the device's held list, [`SimControl::held`], against the arena's own record of each buffer, its obligation set, at the host offset each held command names.
//! It judges two rules, the device fact first:
//!
//! - Rule D ([`Rule::Distinct`]): the held commands' host offsets are pairwise distinct.
//! - Rule S ([`Rule::Storage`]): each held command's host offset is the start of one arena buffer whose obligation set is storage, or storage plus detached once its caller cancelled.
//!
//! Both rules judge the start offset a command names; a command table submits each buffer's range from that buffer's start and within its length.
//!
//! The check applies where a command table owns the simulated device; a buffer a test submits at the device trait stays application-owned.
//! A pass holds at the instant of the call and covers no interval between calls.
//! The check reads storage identity, the host offset, and leaves the buffer's incarnation and the table's record of the token unread: a buffer that left storage custody and came back to it in another record, named by one held command, reads as a pass.

use super::custody::{DETACHED, STORAGE};
use super::sim::{HeldCommand, SimControl};
use super::{BufferArena, CommandToken, PoolKind};
use crate::storage::os::Platform;

/// The rule a held command breaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    /// Two held commands name one buffer.
    Distinct,
    /// A held command's buffer left storage custody.
    Storage,
}

impl Rule {
    /// The assertion message a failure under the rule carries.
    pub(crate) fn text(self) -> &'static str {
        match self {
            Self::Distinct => "two device-held commands name one buffer",
            Self::Storage => "the device holds a command whose buffer left storage custody",
        }
    }
}

/// A held command that breaks a rule: the rule, the held entry, and, for rule S, the pool kind whose buffer starts at the entry's host offset with the obligation set found there; both are `None` under rule D, and under rule S when no buffer starts there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Breach {
    pub rule: Rule,
    pub entry: HeldCommand,
    pub kind: Option<PoolKind>,
    pub set: Option<u8>,
}

/// Judges every command `control`'s device holds against `arena`'s obligation sets: rule D over all held entries, then rule S for each.
/// Returns the number of entries judged, which each caller compares with the count it expects.
/// The call only reads, so the device's records, events, capture and generator stay as they were.
///
/// # Errors
///
/// The first [`Breach`]: under rule D the later of two entries with one host offset, under rule S the first entry in acceptance order whose offset starts no buffer or starts one whose set is neither storage nor storage plus detached.
pub(crate) fn check<P: Platform>(
    control: &SimControl,
    arena: &BufferArena<P>,
) -> Result<usize, Breach> {
    judge(&control.held(), arena)
}

/// [`check`] over one snapshot of the held list.
/// Only the pool kinds the arena configures are read: an absent kind's buffer length is zero, and `Pools::obligations` divides a host offset of 0 by it.
pub(super) fn judge<P: Platform>(
    held: &[HeldCommand],
    arena: &BufferArena<P>,
) -> Result<usize, Breach> {
    for (at, entry) in held.iter().enumerate() {
        if held[..at].iter().any(|earlier| earlier.host == entry.host) {
            return Err(Breach {
                rule: Rule::Distinct,
                entry: *entry,
                kind: None,
                set: None,
            });
        }
    }
    for entry in held {
        let found = PoolKind::ALL
            .into_iter()
            .filter(|kind| arena.config().pool(*kind).count > 0)
            .find_map(|kind| {
                arena
                    .pools()
                    .obligations(kind, entry.host)
                    .map(|set| (kind, set))
            });
        match found {
            Some((_, set)) if set == STORAGE || set == STORAGE | DETACHED => {}
            _ => {
                return Err(Breach {
                    rule: Rule::Storage,
                    entry: *entry,
                    kind: found.map(|(kind, _)| kind),
                    set: found.map(|(_, set)| set),
                });
            }
        }
    }
    Ok(held.len())
}

/// The count [`check`] returns for `control`'s device over `arena`, with the tokens of the held list beside it, for a caller that asserts both.
///
/// # Panics
///
/// On a [`Breach`], with the breach and its rule's text.
pub(crate) fn judged<P: Platform>(
    control: &SimControl,
    arena: &BufferArena<P>,
) -> (usize, Vec<CommandToken>) {
    let held = control.held();
    let count =
        judge(&held, arena).unwrap_or_else(|breach| panic!("{}: {breach:?}", breach.rule.text()));
    (count, held.iter().map(|entry| entry.token).collect())
}
