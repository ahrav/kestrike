//! The tool's build model for `cfg`, `cfg_attr` and test attributes: a
//! non-test build of the crate, which treats every option of [`FALSE`] as
//! false and every other option as unknown.
//!
//! Invariant: `gated` returns true only when the attributes exclude the item
//! from every such build. An unknown predicate leaves the item eligible for
//! inclusion; another attribute can still exclude it.

use proc_macro2::{Delimiter, TokenStream, TokenTree};
use syn::{Attribute, Meta, Path};

/// The configuration options the build model treats as false.
pub const FALSE: [&str; 7] = [
    "test",
    "kani",
    "loom",
    "fuzzing",
    "protocol_contract",
    "verus_keep_ghost",
    "miri",
];

/// True when one of `attributes` excludes its item: a `cfg` whose predicate
/// is false, a `cfg_attr` whose predicate is true and that applies such an
/// attribute, or a test attribute such as `#[test]` or `#[tokio::test]`.
pub fn gated(attributes: &[Attribute]) -> bool {
    attributes.iter().any(|attribute| match &attribute.meta {
        Meta::Path(path) => gates(&names(path), None),
        Meta::List(list) => gates(&names(&list.path), Some(&list.tokens)),
        Meta::NameValue(_) => false,
    })
}

fn names(path: &Path) -> Vec<String> {
    path.segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect()
}

fn gates(names: &[String], arguments: Option<&TokenStream>) -> bool {
    match (names, arguments) {
        ([name], Some(predicate)) if name == "cfg" => evaluate(&trees(predicate)) == Some(false),
        ([name], Some(arguments)) if name == "cfg_attr" => applies_gate(arguments),
        ([.., name], _) => name == "test",
        _ => false,
    }
}

/// True when a `cfg_attr` of `attributes` can set `path`: its predicate is
/// true or unknown in the build model and it applies `path`, directly or
/// through a nested `cfg_attr`.
pub fn sets_path(attributes: &[Attribute]) -> bool {
    attributes.iter().any(|attribute| match &attribute.meta {
        Meta::List(list) => names(&list.path) == ["cfg_attr"] && can_set_path(&list.tokens),
        _ => false,
    })
}

fn can_set_path(arguments: &TokenStream) -> bool {
    let mut parts = split(&trees(arguments)).into_iter();
    let Some(predicate) = parts.next() else {
        return false;
    };
    evaluate(&predicate) != Some(false)
        && parts.any(|attribute| match attribute.as_slice() {
            [TokenTree::Ident(name), ..] if name == "path" => true,
            [TokenTree::Ident(name), TokenTree::Group(group)] if name == "cfg_attr" => {
                can_set_path(&group.stream())
            }
            _ => false,
        })
}

fn applies_gate(arguments: &TokenStream) -> bool {
    let mut parts = split(&trees(arguments)).into_iter();
    let Some(predicate) = parts.next() else {
        return false;
    };
    evaluate(&predicate) == Some(true)
        && parts.any(|attribute| {
            let names: Vec<String> = attribute
                .iter()
                .filter_map(|tree| match tree {
                    TokenTree::Ident(ident) => Some(ident.to_string()),
                    _ => None,
                })
                .collect();
            let arguments = attribute.iter().find_map(|tree| match tree {
                TokenTree::Group(group) => Some(group.stream()),
                _ => None,
            });
            gates(&names, arguments.as_ref())
        })
}

fn evaluate(predicate: &[TokenTree]) -> Option<bool> {
    match predicate {
        [TokenTree::Ident(name)] => match name.to_string().as_str() {
            "false" => Some(false),
            "true" => Some(true),
            name if FALSE.contains(&name) => Some(false),
            _ => None,
        },
        [TokenTree::Ident(name), TokenTree::Group(group)]
            if group.delimiter() == Delimiter::Parenthesis =>
        {
            let values: Vec<Option<bool>> = split(&trees(&group.stream()))
                .iter()
                .map(|argument| evaluate(argument))
                .collect();
            match name.to_string().as_str() {
                "all" if values.contains(&Some(false)) => Some(false),
                "all" if values.iter().all(|value| *value == Some(true)) => Some(true),
                "any" if values.contains(&Some(true)) => Some(true),
                "any" if values.iter().all(|value| *value == Some(false)) => Some(false),
                "not" => match values.as_slice() {
                    [value] => value.map(|value| !value),
                    _ => None,
                },
                _ => None,
            }
        }
        _ => None,
    }
}

fn trees(stream: &TokenStream) -> Vec<TokenTree> {
    stream.clone().into_iter().collect()
}

fn split(trees: &[TokenTree]) -> Vec<Vec<TokenTree>> {
    trees
        .split(|tree| matches!(tree, TokenTree::Punct(punct) if punct.as_char() == ','))
        .filter(|part| !part.is_empty())
        .map(<[TokenTree]>::to_vec)
        .collect()
}
