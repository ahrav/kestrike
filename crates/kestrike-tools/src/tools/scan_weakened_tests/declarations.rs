//! `declarations` finds matches in the [`code`] view and reads the attribute text from the original source.
//!
//! A fn's name is `scope::name`: the scopes are the names of its enclosing inline modules and a `{}` for each
//! other enclosing brace block. The name drops an `r#` prefix. A fn receives an ignore attribute if its
//! header match is the first to end after the attribute.

use std::collections::{HashMap, HashSet};

use regex::bytes::NoExpand;

use crate::rust_text::{FUNCTION, IGNORE, code};
use crate::text::words;

use super::patterns::{REASON, SCOPE, text_of};

/// Each entry groups one fn name's declarations in file order, with one attribute list per declaration.
pub type Declarations = Vec<(String, Vec<Vec<String>>)>;

pub fn declarations(text: &str) -> Declarations {
    let view = code(text);
    let mut scopes = SCOPE.captures(view.as_bytes());
    let mut scope = scopes.next();
    let mut stack: Vec<String> = Vec::new();
    let mut path = String::new();
    let mut functions: Vec<(usize, String, Vec<String>)> = Vec::new();
    for header in FUNCTION.find_iter(&view) {
        while let Some(open) = scope
            .as_ref()
            .filter(|open| open.get(0).expect("group 0 is the match").end() <= header.start())
        {
            let whole = open.get(0).expect("group 0 is the match");
            if whole.as_bytes() != b"}" {
                stack.push(open.name("module").map_or("{}", text_of).to_owned());
            } else {
                stack.pop();
            }
            path = stack.join("::");
            scope = scopes.next();
        }
        let last = words(header.as_str())
            .last()
            .expect("a fn header holds its name");
        let name = last.strip_prefix("r#").unwrap_or(last);
        let name = if path.is_empty() {
            name.to_owned()
        } else {
            format!("{path}::{name}")
        };
        functions.push((header.end(), name, Vec::new()));
    }
    for attribute in IGNORE.find_iter(&view) {
        let index = functions.partition_point(|(end, _, _)| *end <= attribute.end());
        if let Some((_, _, attributes)) = functions.get_mut(index) {
            let written: Vec<&str> = words(&text[attribute.start()..attribute.end()]).collect();
            attributes.push(written.join(" "));
        }
    }
    let mut found: Declarations = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    for (_, name, attributes) in functions {
        let at = *index.entry(name.clone()).or_insert_with(|| {
            found.push((name, Vec::new()));
            found.len() - 1
        });
        found[at].1.push(attributes);
    }
    found
}

pub fn plain(attributes: &[String]) -> usize {
    attributes
        .iter()
        .filter(|attribute| attribute.starts_with("#[ignore"))
        .count()
}

/// `conditions` returns the attribute texts with each `ignore = ".."` reason replaced by `ignore` and every
/// white-space code point removed.
pub fn conditions(attributes: &[String]) -> HashSet<String> {
    attributes
        .iter()
        .map(|attribute| {
            let bare = REASON
                .regex()
                .replace_all(attribute.as_bytes(), NoExpand(b"ignore"));
            let bare = String::from_utf8_lossy(&bare);
            words(&bare).collect()
        })
        .collect()
}
