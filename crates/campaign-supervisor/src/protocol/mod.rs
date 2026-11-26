//! The simulation worker's text protocol: one parser for each of these
//! stdout forms of the worker, the capability listing, the rule catalog, a
//! bundle summary and the run form's panic line, the branch and
//! exploration output, the session output, the session replay verdict,
//! and bundle replay and reduction results.
//!
//! Worker output is faulty but not malicious: it can be truncated, carry a
//! line twice, drop one, or drift from this grammar when the worker
//! changes. Each parser therefore takes every fact its form prints exactly
//! as often as the form prints it, parses each value into its semantic
//! type, and refuses output that is torn, repeats or lacks a required
//! line, holds a key the form never prints, holds a value outside its form
//! or holds lines that disagree. A refused output yields no value, so no
//! credit or record derives from it. Text values (a cause, an unsuccessful
//! rule, a failure identity, a panic's location and payload) keep the bytes
//! the worker printed.
//!
//! A parsed output counts only as the complete output of a worker that
//! exited with the status its form documents: output cut at a line
//! boundary can drop a trailing optional line, or trailing lines of a
//! list such as the listing's clusters, and still parse.
//!
//! The listing's `summary` version selects the base grammar for bundle
//! summaries and run output. At `summary: 1`, a recovery census includes
//! `stages` and `limits`. Capability version 5 is the first that also
//! requires `windows`. The capability version governs the listing,
//! branch, exploration and session output, replay and reduction verdicts,
//! and stored session index and end lines.
//!
//! Retained archives pin their workers. A new wire form needs a distinct
//! version so the parser can still select the form each archived worker emits.
//!
//! The worker crate's protocol contract case, built under
//! `cfg(protocol_contract)`, feeds the worker's own output through these
//! parsers, so a change to either side that breaks the grammar fails that
//! case. The supervisor depends on no worker code; the worker crate takes
//! this crate as a dev-dependency under that cfg alone, so a worker built
//! without the cfg links none of it. An archive build must keep the cfg
//! out of the build flags it inherits for its worker to link none of it.

mod error;
mod fork;
mod listing;
mod pairs;
mod rules;
mod session;
mod session_index;
mod summary;
mod terminal;
mod triage;
#[cfg(test)]
mod triage_tests;

#[cfg(test)]
mod fixture;
#[cfg(test)]
mod fork_tests;
#[cfg(test)]
mod listing_tests;
#[cfg(test)]
mod rules_tests;
#[cfg(test)]
mod session_tests;
#[cfg(test)]
mod summary_tests;

pub use self::error::Error;
pub use self::fork::{
    Branch, Child, ChildClass, Explore, LABEL, Leaf, Limits, Milestone, Node, Upload, Witness,
};
pub use self::listing::{
    CAPABILITIES, Class, DECLARED_FAILURES, Declared, Expected, Fails, Family, Fixed, Form, Key,
    Listing, Profile, RULE_CATALOG,
};
pub use self::rules::{RULES, Rule, Rules, Scope};
pub use self::session::{Candidate, Divergence, End, Session, SessionReplay};
pub use self::session_index::{SessionEnd, SessionEnding, WindowLine};
pub use self::summary::{
    COVERAGE, Cluster, Drawn, FailureIdentity, Ledger, Recovery, Run, SUMMARY, Stages, Summary,
    Topology,
};
pub use self::terminal::{Infrastructure, Outcome, STOPS, Terminal};
pub use self::triage::{ReduceResult, ReplayResult};

pub(crate) use fork::{child_check, missing_child_evidence};
