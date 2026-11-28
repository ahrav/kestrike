//! The score of a run: the head commit, the sentence `K of N plants at commit HEAD`, a tally of the
//! results in the order they first occur, the plants that are not live, the run's settings and each
//! plant's entry; its bytes as the store holds them, the lines the run prints and its exit code.
//!
//! `N` counts the caught and the missed plants. The bytes are [`json::indented_in_order`] and one final
//! newline.

use super::entry::Finished;
use super::verdict::Verdict;
use crate::json::{self, Integer, Object, Value};
use crate::text::{Text, text};

/// `sentence` is `K of N plants at commit HEAD`.
fn sentence(head: &str, entries: &[Finished]) -> Text {
    let count = |wanted: &[Verdict]| {
        entries
            .iter()
            .filter(|entry| wanted.contains(&entry.verdict()))
            .count()
    };
    let (caught, counted) = (
        count(&[Verdict::Caught]),
        count(&[Verdict::Caught, Verdict::Missed]),
    );
    text!(caught, " of ", counted, " plants at commit ", head)
}

/// `score` is the score of `entries` at commit `head`, with the run's `settings`.
pub fn score(head: &str, entries: &[Finished], settings: Object) -> Object {
    let mut tallies: Vec<(&str, usize)> = Vec::new();
    for entry in entries {
        let verdict = entry.verdict().as_str();
        match tallies.iter_mut().find(|(name, _)| *name == verdict) {
            Some((_, tally)) => *tally += 1,
            None => tallies.push((verdict, 1)),
        }
    }
    let mut results = Object::new();
    for (verdict, tally) in tallies {
        results.insert(verdict, Value::Integer(Integer::from(tally)));
    }
    let not_live = entries
        .iter()
        .filter(|entry| entry.verdict() == Verdict::NotLive)
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
pub fn lines(head: &str, entries: &[Finished]) -> Vec<Text> {
    let mut lines = vec![sentence(head, entries)];
    for entry in entries {
        lines.push(result_line(entry));
    }
    lines
}

/// `result_line` is `ID: RESULT (REASON)` of an entry.
pub fn result_line(entry: &Finished) -> Text {
    text!(
        entry.id(),
        ": ",
        entry.verdict().as_str(),
        " (",
        entry.reason(),
        ")"
    )
}

/// `exit_code` is 1 when a miss lacks its cause, else 3 when a plant has no verdict, does not apply or is
/// not live, else 0.
pub fn exit_code(entries: &[Finished]) -> u8 {
    let uncaused = entries.iter().any(|entry| {
        entry.verdict() == Verdict::Missed
            && matches!(entry.members().get("miss_cause"), None | Some(Value::Null))
    });
    let unjudged = entries.iter().any(|entry| {
        matches!(
            entry.verdict(),
            Verdict::NoVerdict | Verdict::DoesNotApply | Verdict::NotLive
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
