//! A plant's entry in the score: its record's identity, the steps' values and its result with the reason,
//! as a JSON object whose members stand in the order the steps first set them.
//!
//! An entry starts with `id`, `row`, `fix`, `files` and `proof` from the plant's record, then `campaign`,
//! `profiles`, `proof_exits`, `commit`, `tree`, `archive`, `counts`, `runs`, `controls`, `histories`,
//! `keys` and `head_failures`, each `null` or empty until a step sets it. A result adds `result` and
//! `reason`; a catch adds `suspect`, and a finished miss adds `miss_cause`.

use std::fmt;
use std::path::Path;

use super::record::Plant;
use super::verdict::NoVerdict;
use crate::json::{Integer, Object, Value};
use crate::text::{Text, text};

/// The five results of a plant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Caught,
    Missed,
    NoVerdict,
    DoesNotApply,
    NotLive,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Caught => "caught",
            Self::Missed => "missed",
            Self::NoVerdict => "no verdict",
            Self::DoesNotApply => "does not apply",
            Self::NotLive => "not live",
        }
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A plant's entry: the score's members for it, its result once a step sets one, and its record's miss
/// cause.
#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    members: Object,
    verdict: Option<Verdict>,
    campaign: Text,
    profiles: Vec<Text>,
    miss_cause: Value,
}

fn string(value: &Text) -> Value {
    Value::String(value.clone())
}

impl Entry {
    /// `new` is the entry of `plant` before any step.
    pub fn new(plant: &Plant) -> Self {
        let mut members = Object::new();
        for name in ["id", "row", "fix", "files", "proof"] {
            let value = plant
                .record()
                .get(name)
                .unwrap_or_else(|| panic!("a checked record holds {name}"));
            members.insert(name, value.clone());
        }
        let campaign = text!("plant-", plant.id());
        let profiles: Vec<Text> = plant.expected().into_iter().cloned().collect();
        members.insert("campaign", Value::String(campaign.clone()));
        members.insert(
            "profiles",
            Value::Array(profiles.iter().map(string).collect()),
        );
        for name in ["proof_exits", "commit", "tree", "archive", "counts"] {
            members.insert(name, Value::Null);
        }
        members.insert("runs", Value::Object(Object::new()));
        members.insert("controls", Value::Null);
        members.insert("histories", Value::Null);
        members.insert("keys", Value::Object(Object::new()));
        members.insert("head_failures", Value::Array(Vec::new()));
        let miss_cause = plant
            .miss_cause()
            .map_or(Value::Null, |cause| Value::Object(cause.clone()));
        Self {
            members,
            verdict: None,
            campaign,
            profiles,
            miss_cause,
        }
    }

    /// The plant's result, `None` until a step sets one.
    pub fn verdict(&self) -> Option<Verdict> {
        self.verdict
    }

    pub fn id(&self) -> &Text {
        self.text("id").expect("an entry holds its id")
    }

    /// The reason of the result, `None` until a step sets one.
    pub fn reason(&self) -> Option<&Text> {
        self.text("reason")
    }

    /// The entry's members, in the order the steps first set them.
    pub fn members(&self) -> &Object {
        &self.members
    }

    fn text(&self, name: &str) -> Option<&Text> {
        match self.members.get(name) {
            Some(Value::String(text)) => Some(text),
            _ => None,
        }
    }

    /// The campaign name, `plant-<id>`.
    pub(super) fn campaign(&self) -> &Text {
        &self.campaign
    }

    /// The expected profiles, in the record's order, each once.
    pub(super) fn profiles(&self) -> &[Text] {
        &self.profiles
    }

    pub(super) fn set(&mut self, name: &str, value: Value) {
        self.members.insert(name, value);
    }

    pub(super) fn push_head_failure(&mut self, failure: Object) {
        match self.members.get_mut("head_failures") {
            Some(Value::Array(failures)) => failures.push(Value::Object(failure)),
            _ => panic!("an entry holds its head failures"),
        }
    }

    /// `settle` sets the result and its reason.
    pub(super) fn settle(&mut self, verdict: Verdict, reason: Text) {
        self.verdict = Some(verdict);
        self.members
            .insert("result", Value::String(Text::from(verdict.as_str())));
        self.members.insert("reason", Value::String(reason));
    }

    pub fn set_commit(&mut self, commit: &Text) {
        self.set("commit", string(commit));
    }

    pub fn set_tree(&mut self, tree: &Text) {
        self.set("tree", string(tree));
    }

    /// `set_archive` records the build digest of the planted tree's archive.
    pub fn set_archive(&mut self, build: &Text) {
        self.set("archive", string(build));
    }

    /// `does_not_apply` is the result of a patch Git refuses, with Git's reason.
    pub fn does_not_apply(&mut self, reason: Text) {
        self.settle(Verdict::DoesNotApply, reason);
    }

    /// `no_verdict` is the result of a step that ended without one.
    pub fn no_verdict(&mut self, ending: &NoVerdict) {
        self.settle(Verdict::NoVerdict, ending.reason().clone());
    }

    /// `prove` records the proof's exits on the head and on the plant; any pair but 0 and 1 is `not live`.
    pub fn prove(&mut self, head: u8, planted: u8) {
        let mut exits = Object::new();
        exits.insert("head", Value::Integer(Integer::from(u64::from(head))));
        exits.insert("plant", Value::Integer(Integer::from(u64::from(planted))));
        self.set("proof_exits", Value::Object(exits));
        if (head, planted) != (0, 1) {
            let reason = format!(
                "its proof exits {head} on the head and {planted} on the plant, where a live plant's \
                 proof exits 0 and 1"
            );
            self.settle(Verdict::NotLive, Text::from(reason));
        }
    }

    /// `unswept` is the miss of a plant with no expected profile, once its archive builds.
    pub fn unswept(&mut self) {
        self.settle(
            Verdict::Missed,
            Text::from("no expected profile; no sweep ran"),
        );
    }

    /// `finish` adds the record's miss cause to a miss and writes `<work>` in place of each occurrence of
    /// the work directory `work` in the reason, since the score is a tracked file. A run finishes each
    /// entry once, after its last step, and before it scores the entries.
    pub fn finish(&mut self, work: &Path) {
        if self.verdict == Some(Verdict::Missed) {
            self.members.insert("miss_cause", self.miss_cause.clone());
        }
        if let Some(reason) = self.reason() {
            let replaced = reason.replace(&text!(work), &Text::from("<work>"));
            self.members.insert("reason", Value::String(replaced));
        }
    }
}
