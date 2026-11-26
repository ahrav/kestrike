//! The worker's capability catalog: every profile name admission accepts,
//! with its class.
//!
//! [`listed`] gates [`named`](super::bundle::named), so a name outside the
//! catalog names no profile. [`listing`] prints the catalog, the manifest
//! key forms [`Manifest::parse`](crate::sim::manifest::Manifest::parse)
//! checks, the two recorder constraints, each profile's admission bounds,
//! each history's expected ending and, for a history that composes more
//! than the fixed topology, its owner and client counts, the failure each
//! history that expects no pass declares, the `settled-`
//! family's shared bounds
//! and word rules, the branch bounds and each cluster profile's ranges,
//! workload and fault dimensions and minima. Every listed profile has an
//! executable scenario, so each lists as `support=implemented`. Each also
//! lists as `campaign=unqualified`: the catalog is a fixed declaration,
//! makes no campaign-qualification claim and derives nothing from a run;
//! bundle summaries report each run.

use crate::sim::manifest::{Form, KEYS, VERSION, form};
use crate::sim::trace::{CHUNK, FIELD_CHUNKS, OPEN_ROOM, PUSH_ROOM, RECORD};

use super::branch::{MAX_SIBLINGS, MAX_SUFFIXES, MILESTONES};
use super::bundle::{HELD, TOPOLOGY, composed_by, held_by};
use super::histories::Expect;

/// The capability listing's format version, which also names the forms a
/// worker has: a worker of version 3 or later prints its rule catalog for
/// `--rules`, and version 4 or later prints `fails` declarations. At `summary: 1`, `capabilities: 5` requires
/// `windows` beside a recovery summary's stage census.
pub(crate) const CAPABILITIES: u32 = 5;

/// The summary format version the worker prints for an inspected bundle.
pub(crate) const SUMMARY: u32 = 1;

/// What a profile's run is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Class {
    /// A healthy scenario expected to pass.
    Live,
    /// A deliberately faulty control expected to fail its named check or,
    /// for a planted panic, to end as incomplete evidence.
    Control,
    /// A live scenario under a recovery profile's cut table.
    Recovery,
    /// A composed custody, incident or cohort history.
    History,
}

impl Class {
    fn name(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Control => "control",
            Self::Recovery => "recovery",
            Self::History => "history",
        }
    }
}

/// One fixed profile name and its class.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Entry {
    pub(crate) name: &'static str,
    pub(crate) class: Class,
}

const fn entry(name: &'static str, class: Class) -> Entry {
    Entry { name, class }
}

/// Every fixed profile name admission accepts, beside the `settled-`
/// family and the composed histories.
pub(crate) const FIXED: [Entry; 68] = [
    entry("upload", Class::Live),
    entry("recovery-16k", Class::Recovery),
    entry("recovery-512", Class::Recovery),
    entry("recovery-torn", Class::Recovery),
    entry("corrupted", Class::Control),
    entry("planted", Class::Control),
    entry("panicking", Class::Control),
    entry("asserting", Class::Control),
    entry("acked", Class::Control),
    entry("misread", Class::Control),
    entry("staged-hit", Class::Control),
    entry("leaked", Class::Control),
    entry("uncounted", Class::Control),
    entry("faulted", Class::Live),
    entry("faulted-corrupted", Class::Control),
    entry("contended", Class::Live),
    entry("contended-acked", Class::Control),
    entry("boundary-tiny", Class::Live),
    entry("boundary-tiny-corrupted", Class::Control),
    entry("boundary-collision", Class::Live),
    entry("boundary-collision-corrupted", Class::Control),
    entry("boundary-fragmentation", Class::Live),
    entry("boundary-fragmentation-corrupted", Class::Control),
    entry("boundary-mixed-size", Class::Live),
    entry("boundary-mixed-size-corrupted", Class::Control),
    entry("boundary-real-counter", Class::Live),
    entry("boundary-real-counter-corrupted", Class::Control),
    entry("long", Class::Live),
    entry("long-planted", Class::Control),
    entry("rekey", Class::Live),
    entry("rekey-stalled", Class::Control),
    entry("replacing", Class::Live),
    entry("replacing-corrupted", Class::Control),
    entry("failing", Class::Live),
    entry("failing-corrupted", Class::Control),
    entry("failing-hit", Class::Control),
    entry("failing-exposed", Class::Control),
    entry("local", Class::Live),
    entry("local-corrupted", Class::Control),
    entry("control", Class::Live),
    entry("control-corrupted", Class::Control),
    entry("deferring", Class::Live),
    entry("deferring-corrupted", Class::Control),
    entry("uncertain", Class::Live),
    entry("uncertain-corrupted", Class::Control),
    entry("uncertain-published", Class::Control),
    entry("settled", Class::Live),
    entry("settled-corrupted", Class::Control),
    entry("cluster-broad", Class::Live),
    entry("cluster-pressure", Class::Live),
    entry("cluster-swarm", Class::Live),
    entry("cluster-swarm-wrong-owner", Class::Control),
    entry("cluster-swarm-stale-read", Class::Control),
    entry("cluster-swarm-late-stale", Class::Control),
    entry("cluster-swarm-leak", Class::Control),
    entry("cluster-swarm-corrupt", Class::Control),
    entry("cluster-swarm-misread", Class::Control),
    entry("cluster-swarm-unremoved", Class::Control),
    entry("cluster-wrong-owner", Class::Control),
    entry("cluster-stale-read", Class::Control),
    entry("cluster-long", Class::Live),
    entry("cluster-late-stale", Class::Control),
    entry("cluster-late-leak", Class::Control),
    entry("cluster-late-corrupt", Class::Control),
    entry("cluster-version-end", Class::Control),
    entry("cluster-order-1", Class::Control),
    entry("cluster-order-2", Class::Control),
    entry("cluster-order-3", Class::Control),
];

/// The words a `settled-` name joins after `settled`, each named at most
/// once and applied left to right to the settled scenario's inputs as
/// `settled` defines; `planted` makes the name a control.
pub(crate) const SETTLED: [&str; 9] = [
    "batched",
    "scaled",
    "cramped",
    "twice",
    "hasty",
    "eager",
    "faulted",
    "planted",
    "invalidating",
];

/// The class of the profile `name` names, or `None` for a name admission
/// refuses.
pub(crate) fn class(name: &str) -> Option<Class> {
    if let Some(entry) = FIXED.iter().find(|entry| entry.name == name) {
        return Some(entry.class);
    }
    if super::histories::every().any(|history| history.name == name) {
        return Some(Class::History);
    }
    // The words are checked as the split yields them, so a name of any
    // length uses fixed memory and refuses at its first unknown or repeated
    // word.
    let (mut seen, mut planted) = ([false; SETTLED.len()], false);
    for word in name.strip_prefix("settled-")?.split('-') {
        let at = SETTLED.iter().position(|known| *known == word)?;
        if std::mem::replace(&mut seen[at], true) {
            return None;
        }
        planted |= word == "planted";
    }
    Some(if planted { Class::Control } else { Class::Live })
}

/// Whether admission accepts the profile name `name`.
pub(crate) fn listed(name: &str) -> bool {
    class(name).is_some()
}

/// The capability listing, one `key: value` line per fact.
pub(crate) fn listing() -> String {
    let mut out =
        format!("capabilities: {CAPABILITIES}\nsummary: {SUMMARY}\nmanifest: {VERSION}\n");
    for key in KEYS {
        let shape = match form(key) {
            Form::Version => format!("version={VERSION}"),
            Form::Text => "text".to_owned(),
            Form::Digest => "sha256".to_owned(),
            Form::Count { max } => format!("count min=1 max={max}"),
        };
        out.push_str(&format!("key: {key} {shape}\n"));
    }
    out.push_str(&format!(
        "constraint: min(records, bytes/{RECORD}) >= ring+{OPEN_ROOM} (+1 when every=1)\n"
    ));
    out.push_str(&format!(
        "constraint: min(records, bytes/{RECORD}) >= c + c/every + ring+{PUSH_ROOM}, c = ceil(canonical bytes/{CHUNK}) <= {FIELD_CHUNKS}\n"
    ));
    out.push_str(&format!("held: {}\n", HELD.join(",")));
    let held = |name: &str| {
        // Every count parses at 1 or more, so a held bound of 0 lists as the
        // least count a manifest can declare.
        held_by(name)
            .expect("every listed profile names a scenario")
            .iter()
            .map(|(key, least)| format!("{key}={}", (*least).max(1)))
            .collect::<Vec<_>>()
            .join(",")
    };
    for entry in &FIXED {
        out.push_str(&format!(
            "profile: {} class={} support=implemented campaign=unqualified held={}\n",
            entry.name,
            entry.class.name(),
            held(entry.name)
        ));
    }
    for history in super::histories::every() {
        let expected = match history.expect {
            Expect::Pass => "pass",
            Expect::Violation(..) => "violation",
            Expect::Unsuccessful(_) => "unsuccessful",
        };
        let composed = composed_by(history.name).expect("every history names a scenario");
        let topology = if composed == TOPOLOGY {
            String::new()
        } else {
            format!(" owners={} clients={}", composed.0, composed.1)
        };
        out.push_str(&format!(
            "profile: {} class={} expected={expected} support=implemented campaign=unqualified held={}{topology}\n",
            history.name,
            Class::History.name(),
            held(history.name)
        ));
        // The obligation prints as the code a violation's failure
        // identity holds for it.
        match history.expect {
            Expect::Pass => {}
            Expect::Violation(obligation, rule) => {
                let code = super::bundle::obligation_code(obligation);
                out.push_str(&format!(
                    "fails: {} violation {code} {rule}\n",
                    history.name
                ));
            }
            Expect::Unsuccessful(witness) => {
                out.push_str(&format!("fails: {} unsuccessful {witness}\n", history.name));
            }
        }
    }
    out.push_str(&format!(
        "family: settled-WORDS words={} each=at-most-once applied=left-to-right class=live,control-when-planted support=implemented campaign=unqualified held={}\n",
        SETTLED.join(","),
        held("settled")
    ));
    for milestone in MILESTONES {
        out.push_str(&format!("milestone: {milestone}\n"));
    }
    out.push_str(&format!(
        "branch: suffixes=1..{MAX_SUFFIXES} siblings=1..{MAX_SIBLINGS}\n"
    ));
    out.push_str(&format!(
        "topology: owners={} clients={} configurable=no; cluster profiles draw theirs\n",
        TOPOLOGY.0, TOPOLOGY.1
    ));
    for shape in &super::cluster::PROFILES {
        out.push_str(&shape.listing());
    }
    out
}

#[cfg(test)]
mod tests;
