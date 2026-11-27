//! An inventory scalar's path joins its keys with `.`; a list item that holds a string `id` takes `[id]`, any
//! other item `[position]`. `flatten` rejects keys and string `id`s that match `ALIASING`. It also rejects
//! all-digit string `id`s because `[id]` could denote a list position.

use std::collections::{HashMap, HashSet};

use crate::git::{blob_texts, git_text};
use crate::json::{self, Value};
use crate::text::Text;

use super::digits::{integer, is_digits};
use super::hunks::{paired, text_of};
use super::patterns::{ALIASING, INVENTORY_TEXT_BUDGET};
use super::{Failure, Shown};

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
                    if ALIASING.is_match(key.as_bytes()) {
                        let under = if path.is_empty() {
                            "the root".to_owned()
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

/// An inventory finding: its class, its name and its old and new values.
pub type Change = (&'static str, String, Shown, Shown);

/// `inventory_changes` returns each inventory budget that fell or went absent and each timeout that rose. A
/// budget counts as absent when its owner remains but loses the budget field, or when a string field in
/// `TEXTS` loses the count or disappears from an owner that remains.
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
        let (earlier, later) = (count(Some(before)), count(after));
        let name = path.to_string();
        let shown = |integer: &json::Integer| Shown::Count(integer.clone());
        if let (true, Some(earlier), true) = (BUDGETS.contains(&field), earlier, dropped) {
            found.push(("budget-lowered", name, shown(earlier), Shown::absent()));
        } else if let (true, Some(earlier), Some(later)) =
            (BUDGETS.contains(&field), earlier, later)
            && later < earlier
        {
            found.push(("budget-lowered", name, shown(earlier), shown(later)));
        } else if let (true, Some(earlier), Some(later)) =
            (TIMEOUTS.contains(&field), earlier, later)
            && later > earlier
        {
            found.push(("timeout-raised", name, shown(earlier), shown(later)));
        } else if let (true, Value::String(before)) = (TEXTS.contains(&field), before)
            && (matches!(after, Some(Value::String(_))) || dropped)
        {
            let empty = Text::new();
            let after = match after {
                Some(Value::String(after)) => after,
                _ => &empty,
            };
            found.extend(text_changes(&name, before, after)?);
        }
    }
    Ok(found)
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
            found.push((
                "budget-lowered",
                label(&word),
                Shown::Count(earlier),
                Shown::Count(later),
            ));
        }
    }
    for (word, (_, earlier)) in unpaired {
        let earlier = integer(&earlier)?;
        found.push((
            "budget-lowered",
            label(&word),
            Shown::Count(earlier),
            Shown::absent(),
        ));
    }
    Ok(found)
}

pub fn inventory_text(rev: &str) -> Result<String, Failure> {
    let entry = git_text(&["ls-tree", "-z", "--full-tree", rev, "--", INVENTORY])?;
    if entry.is_empty() {
        return Ok(String::new());
    }
    let short = &rev[..rev.len().min(12)];
    let mode = entry
        .split(|c: char| crate::text::is_space(u32::from(c)))
        .find(|word| !word.is_empty());
    if !matches!(mode, Some("100644" | "100755")) {
        return Err(Failure::Refused(format!(
            "{INVENTORY} at {short} is not a file"
        )));
    }
    let text = blob_texts(&[format!("{rev}:{INVENTORY}")])?.remove(0);
    if text.is_empty() {
        return Err(Failure::Refused(format!(
            "{INVENTORY} at {short} is empty or unreadable"
        )));
    }
    Ok(text)
}
