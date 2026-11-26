//! Coverage rows retain frozen dimensions, bound witnesses and null unmeasured operands.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::{Value, json};

use crate::protocol::{COVERAGE, Summary};
use crate::record::{Digest, Text};

pub(super) const UNAVAILABLE: &[&str] = &["incarnations", "retained_depth"];

pub(super) fn supports_credit(class: Option<&Text>) -> bool {
    matches!(class.map(Text::as_str), Some("live" | "history"))
}

pub(super) const WORK: &[&str] = &[
    "decisions",
    "turns",
    "progress",
    "boundaries_checked",
    "operations",
    "witnesses",
    "faults_delivered",
    "owners",
    "clients",
    "incarnations",
    "retained_depth",
];
#[cfg(test)]
pub(super) const TOTALS: &[&str] = &[
    "cpu_us",
    "wall_us",
    "memory_bytes",
    "pids",
    "virtual_us",
    "skipped_us",
];

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(super) struct Declaration {
    pub build: Digest,
    pub class: Option<Text>,
    pub counts: Option<BTreeMap<Text, u64>>,
    pub generator: Option<Text>,
    pub minima: Option<Text>,
    pub profile: Text,
    pub support: String,
    pub declared: bool,
    pub unsupported_dimensions: BTreeSet<String>,
}

pub(super) struct Coverage {
    pub declaration: Declaration,
    pub jobs: Vec<String>,
    pub ran: bool,
    pub credited: Vec<String>,
    pub attempts: BTreeMap<String, u64>,
    pub measured: BTreeMap<String, Vec<Option<u64>>>,
    pub minima: BTreeMap<String, u64>,
    pub qualified: bool,
    pub qualification: String,
}

impl Coverage {
    pub fn new(declaration: Declaration) -> Result<Self, super::Error> {
        let mut measured = WORK
            .iter()
            .map(|key| ((*key).into(), Vec::new()))
            .collect::<BTreeMap<_, _>>();
        measured.extend(
            declaration
                .unsupported_dimensions
                .iter()
                .map(|dimension| (dimension.clone(), Vec::new())),
        );
        let minima = declaration
            .minima
            .as_ref()
            .map(super::super::minima::parse)
            .transpose()?
            .unwrap_or_default()
            .into_iter()
            .map(|(key, count)| (key.as_str().to_owned(), count))
            .collect();
        if declaration.minima.is_some() {
            measured.extend(
                COVERAGE
                    .iter()
                    .map(|key| (format!("reached.{key}"), Vec::new())),
            );
        }
        Ok(Self {
            declaration,
            jobs: Vec::new(),
            ran: false,
            credited: Vec::new(),
            attempts: BTreeMap::new(),
            measured,
            minima,
            qualified: false,
            qualification: "calibrated capacity for these frozen counts is missing".into(),
        })
    }

    pub fn credit(&mut self, job: String, attempt: u64, summary: Option<&Summary>) {
        self.attempts.insert(job.clone(), attempt);
        self.credited.push(job);
        for (key, operands) in &mut self.measured {
            operands.push(summary.and_then(|summary| metric(summary, key)));
        }
    }

    pub fn row(self) -> Result<Value, super::Error> {
        let supported = self.declaration.support == "implemented"
            && supports_credit(self.declaration.class.as_ref());
        let state = if !self.declaration.declared {
            "inconclusive"
        } else if !supported {
            "unsupported"
        } else if !self.credited.is_empty() {
            "credited"
        } else if !self.ran {
            "unrun"
        } else {
            "inconclusive"
        };
        let dimensions: BTreeMap<_, _> = self
            .measured
            .iter()
            .map(|(key, operands)| {
                let witness = operands.iter().any(|value| {
                    value.is_some_and(|value| {
                        if key == "faults_delivered" { value >= self.minima.get("faults").copied().unwrap_or(1) }
                        else if let Some(dimension) = key.strip_prefix("reached.") {
                            value >= self.minima.get(dimension).copied().unwrap_or(1)
                        } else {
                            value > 0
                        }
                    })
                });
                let dimension_state = if self.declaration.unsupported_dimensions.contains(key) || UNAVAILABLE.contains(&key.as_str()) || self.declaration.class.as_ref().is_some_and(|class| class.as_str() == "history") && matches!(key.as_str(), "operations" | "witnesses") {
                    "unsupported"
                } else if state == "credited" && !witness {
                    "inconclusive"
                } else {
                    state
                };
                let mut measurement = if matches!(key.as_str(), "owners" | "clients") {
                    let value = (!operands.is_empty() && operands.iter().all(Option::is_some))
                        .then(|| operands.iter().flatten().copied().max()).flatten();
                    json!({"aggregation": "maximum", "value": value,
                        "measurement": if value.is_some() { "measured" } else { "unmeasured" },
                        "reason": if value.is_none() { Some("an operand is absent") } else { None },
                        "sources": self.credited.iter().zip(operands).filter(|(_, operand)| value.is_some() && **operand == value).map(|(job, _)| job).collect::<Vec<_>>()})
                } else { total(key, operands)? };
                if key == "faults_delivered" {
                    let required = self.minima.get("faults").copied().unwrap_or(1);
                    let credited = operands.iter().filter_map(|value| match value { None => Some(None), Some(value) if *value >= required => Some(Some(*value)), Some(_) => None }).collect::<Vec<_>>();
                    let mut credited_total = total(key, &credited)?;
                    if credited.is_empty() { credited_total["reason"] = json!("no credited fault attempts"); }
                    measurement["credited_total"] = credited_total;
                    measurement["shortfalls"] = json!(self.credited.iter().zip(operands).filter_map(|(job, value)| value.filter(|value| *value < required).map(|delivered| json!({"job": job, "attempt": self.attempts[job], "requested": required, "delivered": delivered}))).collect::<Vec<_>>());
                }
                if operands.is_empty() { measurement["reason"] = json!("no credited attempts"); }
                Ok((
                    key,
                    json!({"state": dimension_state, "reason": if dimension_state == "unsupported" {
                        if UNAVAILABLE.contains(&key.as_str()) { Some("worker summary declares this metric unavailable") }
                        else if self.declaration.class.as_ref().is_some_and(|class| class.as_str() == "history") && matches!(key.as_str(), "operations" | "witnesses") { Some("history summaries declare this metric unavailable") }
                        else if self.declaration.unsupported_dimensions.contains(key) { Some("capability declaration excludes this dimension") }
                        else { Some("profile coverage requires an implemented live or history declaration") }
                    } else if !self.declaration.declared { Some("capability declaration is unavailable") } else if dimension_state == "inconclusive" { Some("a selected attempt must meet the dimension witness minimum") } else { None }, "required": key.strip_prefix("reached.").and_then(|key| self.minima.get(key)),
                        "witness": {"scope": "one selected attempt", "minimum": if key == "faults_delivered" { self.minima.get("faults").copied().unwrap_or(1) } else { key.strip_prefix("reached.").and_then(|dimension| self.minima.get(dimension)).copied().unwrap_or(1) }, "maximum": operands.iter().flatten().max()},
                        "measurement": measurement}),
                ))
            })
            .collect::<Result<_, super::Error>>()?;
        Ok(
            json!({"declaration": self.declaration, "state": state, "jobs": self.jobs,
            "credited": self.credited, "qualified": self.qualified,
            "qualification": self.qualification, "dimensions": dimensions}),
        )
    }
}

pub(super) fn total(name: &str, operands: &[Option<u64>]) -> Result<Value, super::Error> {
    let value = if operands.is_empty() || operands.iter().any(Option::is_none) {
        None
    } else {
        Some(
            operands
                .iter()
                .try_fold(0u64, |sum, value| {
                    sum.checked_add(value.expect("operand is measured"))
                })
                .ok_or_else(|| {
                    super::Error::Held(format!(
                        "total {name} overflows u64 across {} operands",
                        operands.len()
                    ))
                })?,
        )
    };
    Ok(
        json!({"value": value, "measurement": if value.is_some() { "measured" } else { "unmeasured" }, "reason": if operands.is_empty() { Some("no published attempts") } else if value.is_none() { Some("an operand is absent") } else { None }}),
    )
}

pub(super) fn metric(summary: &Summary, key: &str) -> Option<u64> {
    Some(match key {
        "decisions" => summary.decisions?,
        "turns" => summary.turns?,
        "progress" => summary.progress?,
        "boundaries_checked" => summary.boundaries_checked?,
        "operations" => summary.operations?,
        "witnesses" => summary.witnesses?,
        "faults_delivered" => summary.faults_delivered?,
        "owners" => summary.owners?,
        "clients" => summary.clients?,
        "virtual_us" => summary.virtual_us?,
        "skipped_us" => summary.skipped_us?,
        _ => {
            let key = key.strip_prefix("reached.")?;
            let index = COVERAGE.iter().position(|name| *name == key)?;
            u64::from(summary.cluster.as_ref()?.drawn.as_ref()?.coverage[index])
        }
    })
}
