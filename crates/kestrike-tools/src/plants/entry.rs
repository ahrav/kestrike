//! A plant's entry in the score: its record's identity, the steps' values and its result with the reason,
//! as a JSON object whose members stand in the order the steps first set them.
//!
//! An entry starts with `id`, `row`, `fix`, `files` and `proof` from the plant's record, then `campaign`,
//! `profiles`, `proof_exits`, `commit`, `tree`, `archive`, `counts`, `runs`, `controls`, `histories`,
//! `keys` and `head_failures`, each `null` or empty until a step sets it. A result adds `result` and
//! `reason`; a catch adds `suspect`, and a finished miss adds `miss_cause`.

use std::path::Path;

use super::output::Pins;
use super::record::Plant;
use super::verdict::{NoVerdict, Verdict};
use crate::json::{Integer, Object, Value};
use crate::text::{Text, text};

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

    /// `archived` records the planted tree's archive build digest, and settles a plant with no expected
    /// profile as missed. It returns whether the plant goes on to its sweeps.
    #[must_use]
    pub fn archived(&mut self, pins: &Pins) -> bool {
        self.set("archive", string(pins.build()));
        if self.profiles.is_empty() {
            self.settle(
                Verdict::Missed,
                Text::from("no expected profile; no sweep ran"),
            );
        }
        !self.profiles.is_empty()
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

    /// `finish` returns `None` until a step sets the result. It adds the record's miss cause to a miss and
    /// replaces each occurrence of `work` in the reason with `<work>`.
    pub fn finish(mut self, work: &Path) -> Option<Finished> {
        let verdict = self.verdict?;
        if verdict == Verdict::Missed {
            self.members.insert("miss_cause", self.miss_cause.clone());
        }
        let reason = match self.members.get("reason") {
            Some(Value::String(reason)) => reason.replace(&text!(work), &Text::from("<work>")),
            _ => panic!("a settled entry holds its reason"),
        };
        self.members.insert("reason", Value::String(reason.clone()));
        let Some(Value::String(id)) = self.members.get("id") else {
            panic!("an entry holds its id");
        };
        Some(Finished {
            id: id.clone(),
            reason,
            verdict,
            members: self.members,
        })
    }
}

/// [`Entry::finish`] returns `Finished` only after a step sets the plant's verdict.
#[derive(Clone, Debug, PartialEq)]
pub struct Finished {
    id: Text,
    reason: Text,
    verdict: Verdict,
    members: Object,
}

impl Finished {
    pub fn id(&self) -> &Text {
        &self.id
    }

    pub fn verdict(&self) -> Verdict {
        self.verdict
    }

    pub fn reason(&self) -> &Text {
        &self.reason
    }

    pub fn members(&self) -> &Object {
        &self.members
    }
}
