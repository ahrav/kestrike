//! [`ALLOWED`] records the rule texts a sweep may leave uncaught, each
//! with its reason, and [`unlisted`] names the uncaught texts outside it.
//!
//! A row of [`ALLOWED`] holds a scope of the worker's rule catalog, a rule
//! text of that scope or `None` for every text of the scope, and the
//! reason the sweep may leave the text uncaught. [`firsts`] reads each
//! text under the first scope the catalog lists it in, and [`unlisted`]
//! checks [`ALLOWED`] for that scope only.

use std::collections::{BTreeMap, BTreeSet};

use crate::protocol::Scope;

/// A scope, the text it allows uncaught or `None` for the whole scope, and
/// the reason.
type Row = (Scope, Option<&'static str>, &'static str);

const CONSERVATION: &str = "the conservation rule's one swept control, `leaked`, \
                            catches its free-run text, and no swept control plants \
                            the wrong table this text names";

pub(in crate::campaign) const ALLOWED: &[Row] = &[
    (
        Scope::Boundary,
        Some("a slot word is malformed"),
        CONSERVATION,
    ),
    (
        Scope::Boundary,
        Some("a held extent overlaps another or lies outside the volume"),
        CONSERVATION,
    ),
    (
        Scope::Boundary,
        Some("a ledger term differs from the slot words or the free units"),
        CONSERVATION,
    ),
    (
        Scope::Boundary,
        Some("a resident slot has no binding"),
        CONSERVATION,
    ),
    (
        Scope::History,
        Some("an owner turn sampled a tick other than its projection"),
        "the check compares two values the test harness writes: the tick the \
         world arms on the storage clock for a turn that takes a sample, and \
         the test platform's last sample after that turn, which the platform \
         takes from the armed tick or, after a relaunch, from the tick the \
         harness arms on the new storage; the cache reads the clock and \
         writes neither value",
    ),
    (
        Scope::History,
        Some("the held sample began at or past the deadline"),
        "the check compares two values the test harness writes: the world time \
         of an always-runnable step, which the turn controller runs before it \
         moves the clock, and the deadline the script set at least one second \
         past that time in the step before; the cache writes neither value",
    ),
    (
        Scope::Oracle,
        None,
        "the oracle judges recorded rows, which only the `recovery-` profiles, \
         a few scripted histories and the tests that record rows hold; a \
         sweep's other runs record no rows",
    ),
];

/// `firsts` yields each distinct text of `catalog` once, in catalog order,
/// paired with the first scope that lists it.
pub(in crate::campaign) fn firsts(
    catalog: &[(String, String)],
) -> impl Iterator<Item = (&str, &str)> {
    let mut seen = BTreeSet::new();
    catalog
        .iter()
        .filter(move |(_, text)| seen.insert(text.as_str()))
        .map(|(scope, text)| (scope.as_str(), text.as_str()))
}

/// `unlisted` keeps each distinct text of `catalog` for which
/// `caught(text)` and the [`ALLOWED`] check of its first scope both return
/// false, grouped by that scope in catalog order. The map holds only
/// scopes with such a text.
pub(in crate::campaign) fn unlisted(
    catalog: &[(String, String)],
    caught: impl Fn(&str) -> bool,
) -> BTreeMap<&str, Vec<&str>> {
    let allowed = |scope: &str, text: &str| {
        ALLOWED.iter().any(|&(row, listed, _)| {
            row.name() == scope && listed.is_none_or(|listed| listed == text)
        })
    };
    let mut unlisted: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (scope, text) in firsts(catalog) {
        if !caught(text) && !allowed(scope, text) {
            unlisted.entry(scope).or_default().push(text);
        }
    }
    unlisted
}

#[cfg(test)]
#[path = "uncaught_tests.rs"]
mod tests;
