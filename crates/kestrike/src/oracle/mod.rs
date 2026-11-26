//! A test-only history oracle: plain-data history rows, the eight
//! obligations they are judged against, and verdicts that satisfy a gate
//! only as `Pass` with every declared obligation activated.
//! `preservation` judges a passing history's retained sets for the stronger
//! claim that every member was served or lies on a damaged unit.
//! `ownership` judges one volume's ownership steps, which are separate from the
//! history rows, and returns a pass or a `Restart` violation or a malformed
//! verdict; its verdicts pass through no ledger and activate no obligation.
//!
//! Expected values come from the oracle's own keys, labels, byte copies and
//! counts. The module imports only the standard library and its own
//! submodules, which `guard_tests` enforces.

mod action;
mod attempt;
mod attempts;
mod bounds;
mod candidates;
mod checker;
mod clients;
mod command;
mod content;
mod continuation;
mod coverage;
mod custody;
mod delivery;
mod domain;
mod evidence;
mod history;
mod ids;
mod key_model;
mod ledger;
mod memo_hash;
mod obligation;
mod outcome;
pub(crate) mod ownership;
mod preservation;
mod recorder;
mod retention;
mod row;
mod rules;
mod script;
mod search;
mod tenure;
mod verdict;

mod continuation_tests;
mod corrupted_tests;
mod custody_tests;
mod delivery_tests;
mod domain_tests;
mod enumeration_tests;
mod golden;
pub(crate) mod guard_tests;
mod history_tests;
mod obligation_tests;
mod ownership_tests;
mod qualified_tests;
mod reach_guard_tests;
mod recovery_tests;
mod tenure_golden;
mod vocabulary_tests;

pub(crate) use self::action::ActionKind;
pub(crate) use self::attempt::{PutOutcome, Serial};
pub(crate) use self::bounds::{MAX_KEYS, SearchBudget};
pub(crate) use self::checker::{check, check_clients, check_within};
pub(crate) use self::clients::Acceptance;
pub(crate) use self::command::{BoundaryEvent, CommandEvidence, census};
pub(crate) use self::content::Geometry;
pub(crate) use self::continuation::{Continuation, Entry, LIMITS, Limits, Pending};
pub(crate) use self::custody::{Checkpoint, Custodian};
pub(crate) use self::evidence::{Decision, DurableFact, Hypothesis};
pub(crate) use self::golden::BOUNDARY as QUALIFIED_BOUNDARY;
pub(crate) use self::history::History;
pub(crate) use self::ids::{
    ClientId, ClockSample, CutId, Episode, Incarnation, KeyId, Label, OpId, Ordinal, Owner,
    ResourceKind, Tenure, WideOp,
};
pub(crate) use self::obligation::{EvidenceLabel, OBLIGATIONS, Obligation};
pub(crate) use self::outcome::{Failure, NoInformation, Outcome, VisibilityCause};
pub(crate) use self::preservation::{NEVER_SERVED, Preserved, preserved};
pub(crate) use self::recorder::Recorder;
pub(crate) use self::row::{ReportKind, ReportState, Row};
pub(crate) use self::script::Script;
pub(crate) use self::verdict::{Inconclusive, Verdict, Violation};
