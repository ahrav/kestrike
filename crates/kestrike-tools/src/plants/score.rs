//! The score of a run: the head commit, the sentence `K of N plants at commit HEAD`, a tally of the
//! results in the order they first occur, the plants that are not live, the run's settings and each
//! plant's entry; its bytes as the store holds them, the lines the run prints and its exit code.
//!
//! `N` counts the caught and the missed plants. The bytes are [`json::indented_in_order`] and one final
//! newline.

use super::entry::{Entry, Verdict};
use crate::json::{self, Integer, Object, Value};
use crate::text::{Text, text};

/// `sentence` is `K of N plants at commit HEAD`.
fn sentence(head: &str, entries: &[Entry]) -> Text {
    let count = |wanted: &[Verdict]| {
        entries
            .iter()
            .filter(|entry| {
                entry
                    .verdict()
                    .is_some_and(|verdict| wanted.contains(&verdict))
            })
            .count()
    };
    let (caught, counted) = (
        count(&[Verdict::Caught]),
        count(&[Verdict::Caught, Verdict::Missed]),
    );
    text!(caught, " of ", counted, " plants at commit ", head)
}

/// `score` is the score of `entries`, each settled, at commit `head`, with the run's `settings`.
pub fn score(head: &str, entries: &[Entry], settings: Object) -> Object {
    let mut results = Object::new();
    for entry in entries {
        let verdict = entry
            .verdict()
            .expect("a scored entry holds its result")
            .as_str();
        let tally = match results.get(verdict) {
            Some(Value::Integer(tally)) => tally
                .checked_add(&Integer::from(1u64))
                .expect("a tally of entries fits an integer"),
            _ => Integer::from(1u64),
        };
        results.insert(verdict, Value::Integer(tally));
    }
    let not_live = entries
        .iter()
        .filter(|entry| entry.verdict() == Some(Verdict::NotLive))
        .map(|entry| Value::String(entry.id().clone()))
        .collect();
    let mut score = Object::new();
    score.insert("commit", Value::String(Text::from(head)));
    score.insert("sentence", Value::String(sentence(head, entries)));
    score.insert("results", Value::Object(results));
    score.insert("not_live", Value::Array(not_live));
    score.insert("settings", Value::Object(settings));
    let plants = entries
        .iter()
        .map(|entry| Value::Object(entry.members().clone()))
        .collect();
    score.insert("plants", Value::Array(plants));
    score
}

/// `bytes` is the score as the store holds it.
pub fn bytes(score: &Object) -> String {
    let mut written = json::indented_in_order(&Value::Object(score.clone()));
    written.push('\n');
    written
}

/// `lines` are the lines a run prints once its score stands: the sentence, then `ID: RESULT (REASON)` for
/// each entry.
pub fn lines(head: &str, entries: &[Entry]) -> Vec<Text> {
    let mut lines = vec![sentence(head, entries)];
    for entry in entries {
        lines.push(result_line(entry));
    }
    lines
}

/// `result_line` is `ID: RESULT (REASON)` of a settled entry.
pub fn result_line(entry: &Entry) -> Text {
    let verdict = entry.verdict().expect("a settled entry holds its result");
    let reason = entry.reason().expect("a settled entry holds its reason");
    text!(entry.id(), ": ", verdict.as_str(), " (", reason, ")")
}

/// `exit_code` is 1 when a miss lacks its cause, else 3 when a plant has no verdict, does not apply or is
/// not live, else 0.
pub fn exit_code(entries: &[Entry]) -> u8 {
    let uncaused = entries.iter().any(|entry| {
        entry.verdict() == Some(Verdict::Missed)
            && matches!(entry.members().get("miss_cause"), None | Some(Value::Null))
    });
    let unjudged = entries.iter().any(|entry| {
        matches!(
            entry.verdict(),
            Some(Verdict::NoVerdict | Verdict::DoesNotApply | Verdict::NotLive)
        )
    });
    if uncaused {
        1
    } else if unjudged {
        3
    } else {
        0
    }
}
