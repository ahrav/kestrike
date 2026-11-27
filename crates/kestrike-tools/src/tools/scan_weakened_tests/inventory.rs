//! An inventory scalar's path joins its keys with `.`; a list item that holds a string `id` takes `[id]`, any
//! other item `[position]`. `flatten` rejects empty keys, and keys and string `id`s that match `ALIASING`.
//! It also rejects all-digit string `id`s because `[id]` could denote a list position.

use std::collections::{HashMap, HashSet};

use crate::git::blob_texts;
use crate::json::{self, Value};
use crate::text::{Text, escaped};

use super::digits::{integer, is_digits};
use super::finding::short;
use super::hunks::paired;
use super::patterns::{ALIASING, INVENTORY_TEXT_BUDGET, text_of};
use super::tree::files;
use super::{Change, Class, Failure, Shown};

pub const INVENTORY: &str = "scripts/test-inventory.json";
const BUDGETS: [&str; 3] = ["seeds", "seconds", "executions"];
const TEXTS: [&str; 2] = ["bound", "member"];
const TIMEOUTS: [&str; 2] = ["deadline_seconds", "member_drain_seconds"];

#[derive(Default)]
struct Document<'v> {
    leaves: Vec<(Text, &'v Value)>,
    index: HashMap<Text, usize>,
    owners: HashSet<Text>,
}

impl<'v> Document<'v> {
    fn get(&self, path: &Text) -> Option<&'v Value> {
        self.index.get(path).map(|&at| self.leaves[at].1)
    }

    fn flatten(&mut self, node: &'v Value, path: &Text) -> Result<(), Failure> {
        match node {
            Value::Object(object) => {
                self.owners.insert(path.clone());
                for (key, value) in object.iter() {
                    if key.is_empty() || ALIASING.is_match(key.as_bytes()) {
                        let under = if path.is_empty() {
                            "the root".to_owned()
                        } else if key.is_empty() {
                            escaped(&path.to_string())
                        } else {
                            path.to_string()
                        };
                        return Err(Failure::Refused(format!(
                            "{INVENTORY}: the key {} under {under} could name another path",
                            key.repr()
                        )));
                    }
                    let mut child = path.clone();
                    if !path.is_empty() {
                        child.push_str(".");
                    }
                    child.push_text(key);
                    self.flatten(value, &child)?;
                }
            }
            Value::Array(items) => {
                for (position, value) in items.iter().enumerate() {
                    let id = match value {
                        Value::Object(object) => match object.get("id") {
                            Some(Value::String(id)) => Some(id),
                            _ => None,
                        },
                        _ => None,
                    };
                    if let Some(id) = id
                        && (ALIASING.is_match(id.as_bytes()) || is_digits(id.code_points()))
                    {
                        return Err(Failure::Refused(format!(
                            "{INVENTORY}: the id {} under {path} could name another path",
                            id.repr()
                        )));
                    }
                    let mut child = path.clone();
                    child.push_str("[");
                    match id {
                        Some(id) => child.push_text(id),
                        None => child.push_str(&position.to_string()),
                    }
                    child.push_str("]");
                    self.flatten(value, &child)?;
                }
            }
            _ if self.index.contains_key(path) => {
                return Err(Failure::Refused(format!(
                    "{INVENTORY}: two values share the path {path}"
                )));
            }
            _ => {
                self.index.insert(path.clone(), self.leaves.len());
                self.leaves.push((path.clone(), node));
            }
        }
        Ok(())
    }
}

fn parsed(text: &str) -> Result<Option<Value>, Failure> {
    if text.is_empty() {
        return Ok(None);
    }
    json::parse(text)
        .map(Some)
        .map_err(|error| Failure::Refused(format!("{INVENTORY}: {error}")))
}

fn count(value: Option<&Value>) -> Option<&json::Integer> {
    match value {
        Some(Value::Integer(integer)) => Some(integer),
        _ => None,
    }
}

/// `inventory_changes` returns each inventory budget that fell or went absent and each timeout that rose. A
/// budget counts as absent when its owner remains but loses the budget field, or when a string field in
/// `TEXTS` loses the count or disappears from an owner that remains. An integer budget or timeout whose new
/// value is a scalar of another type, and a `TEXTS` field whose new value is a scalar other than a text, is
/// refused.
pub fn inventory_changes(old_text: &str, new_text: &str) -> Result<Vec<Change>, Failure> {
    let old_value = parsed(old_text)?;
    let mut old = Document::default();
    if let Some(value) = &old_value {
        old.flatten(value, &Text::new())?;
    }
    let new_value = parsed(new_text)?;
    let mut new = Document::default();
    if let Some(value) = &new_value {
        new.flatten(value, &Text::new())?;
    }
    let mut found = Vec::new();
    for (path, before) in &old.leaves {
        let (owner, field) = path.rpartition(b'.');
        let after = new.get(path);
        let dropped = !new.index.contains_key(path) && new.owners.contains(&owner);
        let field = field.to_str().unwrap_or_default();
        let (budget, timeout) = (BUDGETS.contains(&field), TIMEOUTS.contains(&field));
        let (earlier, later) = (count(Some(before)), count(after));
        let after_text = match after {
            Some(Value::String(text)) => Some(text),
            _ => None,
        };
        let name = path.to_string();
        if let Some(later) = after
            && match before {
                Value::Integer(_) => (budget || timeout) && !matches!(later, Value::Integer(_)),
                Value::String(_) => TEXTS.contains(&field) && !matches!(later, Value::String(_)),
                _ => false,
            }
        {
            return Err(Failure::Refused(format!(
                "{INVENTORY}: the value at {} changes from {} to {}",
                escaped(&name),
                kind(before),
                kind(later)
            )));
        }
        let shown = |integer: &json::Integer| Shown::Count(integer.clone());
        if budget
            && let Some(earlier) = earlier
            && dropped
        {
            found.push(Change::new(
                Class::BudgetLowered,
                name,
                shown(earlier),
                Shown::absent(),
            ));
        } else if budget
            && let (Some(earlier), Some(later)) = (earlier, later)
            && later < earlier
        {
            found.push(Change::new(
                Class::BudgetLowered,
                name,
                shown(earlier),
                shown(later),
            ));
        } else if timeout
            && let (Some(earlier), Some(later)) = (earlier, later)
            && later > earlier
        {
            found.push(Change::new(
                Class::TimeoutRaised,
                name,
                shown(earlier),
                shown(later),
            ));
        } else if TEXTS.contains(&field)
            && let Value::String(before) = before
            && (after_text.is_some() || dropped)
        {
            let empty = Text::new();
            found.extend(text_changes(&name, before, after_text.unwrap_or(&empty))?);
        }
    }
    Ok(found)
}

fn kind(value: &Value) -> &'static str {
    match value {
        Value::Object(_) => "an object",
        Value::Array(_) => "a list",
        Value::String(_) => "a text",
        Value::Integer(_) => "an integer",
        Value::Float(_) => "a float",
        Value::Bool(_) => "a boolean",
        Value::Null => "null",
    }
}

fn text_changes(name: &str, before: &Text, after: &Text) -> Result<Vec<Change>, Failure> {
    let counts = |text: &'_ Text| {
        INVENTORY_TEXT_BUDGET
            .captures(text.as_bytes())
            .map(|found| {
                let word = text_of(found.name("name").expect("the pattern captures a name"));
                let value = text_of(found.name("value").expect("the pattern captures a value"));
                (word.to_owned(), (word.to_owned(), value.to_owned()))
            })
            .collect::<Vec<_>>()
    };
    let (pairs, unpaired) = paired(counts(before), counts(after));
    let label = |word: &str| format!("{name} {}", word.trim_end_matches(':'));
    let mut found = Vec::new();
    for ((word, earlier), (_, later)) in pairs {
        let later = integer(&later)?;
        let earlier = integer(&earlier)?;
        if later < earlier {
            let (old, new) = (Shown::Count(earlier), Shown::Count(later));
            found.push(Change::new(Class::BudgetLowered, label(&word), old, new));
        }
    }
    for (word, (_, earlier)) in unpaired {
        let earlier = integer(&earlier)?;
        let old = Shown::Count(earlier);
        found.push(Change::new(
            Class::BudgetLowered,
            label(&word),
            old,
            Shown::absent(),
        ));
    }
    Ok(found)
}

/// `inventory_text` returns the inventory's text at `rev`, and an empty text where `rev` holds no entry at its
/// path. An entry that is no file, and a file that is empty or unreadable, is refused.
pub fn inventory_text(rev: &str) -> Result<String, Failure> {
    if files(rev, &[INVENTORY])?.is_empty() {
        return Ok(String::new());
    }
    let short = short(rev);
    let text = blob_texts(&[format!("{rev}:{INVENTORY}")])?.remove(0);
    if text.is_empty() {
        return Err(Failure::Refused(format!(
            "{INVENTORY} at {short} is empty or unreadable"
        )));
    }
    Ok(text)
}
