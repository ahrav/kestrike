//! The readers of the tool's listing and outcome file, and the judgment of a run from them.
//!
//! A mutant is caught only when the baseline passed and the outcome file records it caught; on any other
//! baseline every listed mutant is not-run. A name in the outcome file is a JSON string, and two names
//! are one name when their code points are equal.

use crate::json::{self, Object, Value};
use crate::python;
use crate::text::Text;

/// A listed mutant's outcome in the report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Outcome {
    Caught,
    Missed,
    Timeout,
    Unviable,
    NotRun,
}

impl Outcome {
    pub(super) const ALL: [Self; 5] = [
        Self::Caught,
        Self::Missed,
        Self::Timeout,
        Self::Unviable,
        Self::NotRun,
    ];

    pub(super) fn word(self) -> &'static str {
        match self {
            Self::Caught => "caught",
            Self::Missed => "missed",
            Self::Timeout => "timeout",
            Self::Unviable => "unviable",
            Self::NotRun => "not-run",
        }
    }

    /// `viable` holds for the outcomes of a judged mutant that compiled.
    fn viable(self) -> bool {
        matches!(self, Self::Caught | Self::Missed | Self::Timeout)
    }
}

/// The tool's per-mutant summaries; a summary outside this table judges nothing.
const VERDICTS: [(&str, Outcome); 4] = [
    ("CaughtMutant", Outcome::Caught),
    ("MissedMutant", Outcome::Missed),
    ("Timeout", Outcome::Timeout),
    ("Unviable", Outcome::Unviable),
];
const ROUND_DIGITS: usize = 3;

/// One mutant of the listing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Listed {
    name: Text,
    file: Text,
}

/// `read_listing` returns the mutants of the listing, each with its name and file, in order; a text of
/// whitespace alone is an empty listing.
///
/// # Errors
///
/// The text is no JSON document, or no array of objects whose `name` and `file` are strings, or a name
/// repeats.
pub(super) fn read_listing(text: &str) -> Result<Vec<Listed>, String> {
    if Text::from(text).strip().is_empty() {
        return Ok(Vec::new());
    }
    let refused = || "expected an array of mutants, each with a string name and file".to_owned();
    let Value::Array(rows) = json::parse(text).map_err(|error| error.to_string())? else {
        return Err(refused());
    };
    let mut listed: Vec<Listed> = Vec::with_capacity(rows.len());
    for row in &rows {
        let Value::Object(row) = row else {
            return Err(refused());
        };
        let (Some(Value::String(name)), Some(Value::String(file))) =
            (row.get("name"), row.get("file"))
        else {
            return Err(refused());
        };
        listed.push(Listed {
            name: name.clone(),
            file: file.clone(),
        });
    }
    let mut names: Vec<&Text> = listed.iter().map(|mutant| &mutant.name).collect();
    names.sort();
    if names.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("a mutant name repeats".to_owned());
    }
    Ok(listed)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Baseline {
    Passed,
    Failed,
}

impl Baseline {
    fn word(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
        }
    }
}

/// The outcome file as the run reads it: the baseline, and each judged mutant's name, verdict and phase
/// seconds in the file's order.
#[derive(Clone, Debug, PartialEq)]
pub struct Outcomes {
    baseline: Option<Baseline>,
    pub(super) judged: Vec<(Text, Outcome, Object)>,
}

impl Outcomes {
    pub(super) fn empty() -> Self {
        Self {
            baseline: None,
            judged: Vec::new(),
        }
    }

    /// `failed` keeps the judged mutants and makes the baseline failed.
    pub(super) fn failed(mut self) -> Self {
        self.baseline = Some(Baseline::Failed);
        self
    }
}

/// `seconds` returns a phase time rounded to three places: an integer by its digits and a float as
/// [`python::round`] rounds it. It returns `None` for a time that is no number, a `true` or `false`, a
/// negative number, a float that is not finite, or an integer whose nearest double is not finite.
fn seconds(value: &Value) -> Option<Value> {
    match value {
        Value::Integer(integer) => {
            let nearest: f64 = integer.to_string().parse().ok()?;
            (nearest.is_finite() && nearest >= 0.0).then(|| value.clone())
        }
        Value::Float(float) if float.is_finite() && *float >= 0.0 => {
            python::round(value, ROUND_DIGITS)
        }
        _ => None,
    }
}

fn text_of(value: &Value) -> Option<&Text> {
    match value {
        Value::String(text) => Some(text),
        _ => None,
    }
}

/// `phases` maps each phase's lowercased name to its seconds; of two equal names the later time stands
/// at the first one's place.
fn phases(results: &Value) -> Option<Object> {
    let Value::Array(results) = results else {
        return None;
    };
    let mut phases = Object::new();
    for phase in results {
        let Value::Object(phase) = phase else {
            return None;
        };
        let name = lowercase(text_of(phase.get("phase")?)?);
        phases.insert(name, seconds(phase.get("duration")?)?);
    }
    Some(phases)
}

/// `lowercase` lowercases each run of scalar values as [`str::to_lowercase`] does and keeps each
/// surrogate.
fn lowercase(text: &Text) -> Text {
    let mut lowered = Text::new();
    let mut run = String::new();
    for code in text.code_points() {
        match char::from_u32(code) {
            Some(scalar) => run.push(scalar),
            None => {
                lowered.push_str(&run.to_lowercase());
                run.clear();
                lowered
                    .push_code_point(code)
                    .expect("a code point of a text is at most U+10FFFF");
            }
        }
    }
    lowered.push_str(&run.to_lowercase());
    lowered
}

/// `read_outcomes` returns the baseline verdict and each judged mutant's verdict and phase seconds of the
/// tool's outcome file. A mutant whose summary is no verdict is seen but not judged.
///
/// It returns `None` for bytes that are no UTF-8, no JSON document, or no object whose `outcomes` is an
/// array; for a record that is no object with a `scenario`, a `summary` and a `phase_results` array of
/// objects, each with a string `phase` and a `duration` [`seconds`] reads; for a mutant record without
/// `{"Mutant": {"name": NAME}}` where `NAME` is a string, or with an array or object as its summary; and
/// for a repeated baseline or name.
pub fn read_outcomes(bytes: &[u8]) -> Option<Outcomes> {
    let document = json::parse(std::str::from_utf8(bytes).ok()?).ok()?;
    let Value::Object(document) = document else {
        return None;
    };
    let mut read = Outcomes::empty();
    let Value::Array(records) = document.get("outcomes")? else {
        return None;
    };
    let mut seen: Vec<&Text> = Vec::new();
    for record in records {
        let Value::Object(record) = record else {
            return None;
        };
        let (scenario, summary) = (record.get("scenario")?, record.get("summary")?);
        let phases = phases(record.get("phase_results")?)?;
        if matches!(scenario, Value::String(text) if *text == "Baseline") {
            if read.baseline.is_some() {
                return None;
            }
            let passed = matches!(summary, Value::String(text) if *text == "Success");
            read.baseline = Some(if passed {
                Baseline::Passed
            } else {
                Baseline::Failed
            });
            continue;
        }
        let Value::Object(scenario) = scenario else {
            return None;
        };
        let Value::Object(mutant) = scenario.get("Mutant")? else {
            return None;
        };
        let Value::String(name) = mutant.get("name")? else {
            return None;
        };
        if seen.contains(&name) {
            return None;
        }
        seen.push(name);
        if matches!(summary, Value::Array(_) | Value::Object(_)) {
            return None;
        }
        let verdict = VERDICTS
            .iter()
            .find(|(summary_word, _)| text_of(summary).is_some_and(|text| text == summary_word))
            .map(|&(_, verdict)| verdict);
        if let Some(verdict) = verdict {
            read.judged.push((name.clone(), verdict, phases));
        }
    }
    Some(read)
}

/// One listed mutant's entry of the report.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct Entry {
    listed: Listed,
    outcome: Outcome,
    phases: Object,
}

impl Entry {
    pub(super) fn name(&self) -> &Text {
        &self.listed.name
    }

    pub(super) fn is_missed(&self) -> bool {
        self.outcome == Outcome::Missed
    }
}

/// The report fields that the listing and the outcome file decide.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct Judgment {
    pub(super) mutants: Vec<Entry>,
    /// The count of each outcome, in the order of [`Outcome::ALL`].
    pub(super) counts: [usize; 5],
    pub(super) flagged: Vec<Text>,
    pub(super) baseline: Option<Baseline>,
    pub(super) reason: Option<Text>,
}

/// `judge` returns the per-mutant entries, counts, flagged files, baseline and reason of `listed` against
/// `outcomes`, `None` for an unreadable outcome file. The first reason that applies stands: the given
/// one, an unreadable outcome file, a baseline that failed or is absent, then a judged set other than the
/// listed set. Only a passed baseline gives a listed mutant an outcome other than not-run.
pub(super) fn judge(
    listed: &[Listed],
    outcomes: Option<&Outcomes>,
    reason: Option<Text>,
) -> Judgment {
    let empty = Outcomes::empty();
    let read = outcomes.unwrap_or(&empty);
    let is_listed = |name: &Text| listed.iter().any(|m| m.name == *name);
    let judged_name = |name: &Text| read.judged.iter().find(|(judged, _, _)| judged == name);
    let mut reason = reason;
    if reason.is_none() && !listed.is_empty() {
        reason = match (outcomes, read.baseline) {
            (None, _) => Some(Text::from("the tool wrote no readable outcome file")),
            (Some(_), Some(Baseline::Failed)) => Some(Text::from("the baseline failed")),
            (Some(_), None) => Some(Text::from("the outcome file holds no baseline")),
            (Some(_), Some(Baseline::Passed)) => {
                let unjudged = listed
                    .iter()
                    .filter(|m| judged_name(&m.name).is_none())
                    .count();
                let unlisted = read
                    .judged
                    .iter()
                    .filter(|(name, _, _)| !is_listed(name))
                    .count();
                (unjudged > 0 || unlisted > 0).then(|| {
                    Text::from(format!(
                        "{unjudged} listed mutants have no outcome and {unlisted} judged mutants were not listed"
                    ))
                })
            }
        };
    }
    let passed = read.baseline == Some(Baseline::Passed);
    let mutants: Vec<Entry> = listed
        .iter()
        .map(|mutant| {
            let credited = judged_name(&mutant.name).filter(|_| passed);
            let (outcome, phases) = credited
                .map_or((Outcome::NotRun, Object::new()), |(_, verdict, phases)| {
                    (*verdict, phases.clone())
                });
            Entry {
                listed: mutant.clone(),
                outcome,
                phases,
            }
        })
        .collect();
    let mut counts = [0; 5];
    for entry in &mutants {
        counts[entry.outcome as usize] += 1;
    }
    let flagged = flagged(&mutants);
    Judgment {
        mutants,
        counts,
        flagged,
        baseline: read.baseline,
        reason,
    }
}

/// `flagged` returns, sorted, each file with one or more viable mutants, all of them missed.
fn flagged(mutants: &[Entry]) -> Vec<Text> {
    let mut files: Vec<&Text> = mutants.iter().map(|entry| &entry.listed.file).collect();
    files.sort();
    files.dedup();
    files
        .into_iter()
        .filter(|&file| {
            let mut viable = mutants
                .iter()
                .filter(|entry| entry.listed.file == *file && entry.outcome.viable())
                .peekable();
            viable.peek().is_some() && viable.all(Entry::is_missed)
        })
        .cloned()
        .collect()
}

impl Judgment {
    pub(super) fn complete(&self) -> bool {
        self.reason.is_none()
    }

    pub(super) fn listed(&self) -> usize {
        self.mutants.len()
    }

    pub(super) fn count(&self, outcome: Outcome) -> usize {
        self.counts[outcome as usize]
    }

    /// `fields` writes the judgment's report fields into `report`.
    pub(super) fn fields(&self, report: &mut Object) {
        let mutants = self.mutants.iter().map(|entry| {
            let mut object = Object::new();
            object.insert("name", Value::String(entry.listed.name.clone()));
            object.insert("file", Value::String(entry.listed.file.clone()));
            object.insert("outcome", Value::String(Text::from(entry.outcome.word())));
            object.insert("phase_seconds", Value::Object(entry.phases.clone()));
            Value::Object(object)
        });
        report.insert("mutants", Value::Array(mutants.collect()));
        let mut counts = Object::new();
        counts.insert("listed", Value::Integer(self.listed().into()));
        for outcome in Outcome::ALL {
            counts.insert(outcome.word(), Value::Integer(self.count(outcome).into()));
        }
        report.insert("counts", Value::Object(counts));
        let flagged = self.flagged.iter().cloned().map(Value::String).collect();
        report.insert("flagged", Value::Array(flagged));
        let baseline = self.baseline.map_or(Value::Null, |baseline| {
            Value::String(baseline.word().into())
        });
        report.insert("baseline", baseline);
        report.insert("complete", Value::Bool(self.complete()));
        report.insert(
            "reason",
            self.reason.clone().map_or(Value::Null, Value::String),
        );
    }
}
