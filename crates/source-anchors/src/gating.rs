//! Decides whether an item's attributes remove it from every build without
//! `test`.
//!
//! Invariant: an item reads as gated only when no build without `test` holds
//! it, whatever the other configuration options are. A `cfg` predicate is
//! evaluated with `test` false and every other option unknown, so a predicate
//! that an unknown option could satisfy leaves its item in production.
//! Two occurrences of one option are read apart, so `all(unix, not(unix))` is
//! unknown and its item stays in production.

use proc_macro2::{Delimiter, TokenStream, TokenTree};
use syn::{Attribute, Meta, Path};

/// Whether one of `attributes` removes its item from every build without
/// `test`: a `cfg` whose predicate is false there, a `cfg_attr` whose
/// predicate is true there and that applies such an attribute, or a test
/// attribute such as `#[test]` or `#[tokio::test]`.
pub(crate) fn gated(attributes: &[Attribute]) -> bool {
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

/// Whether the attribute with path `names` and `arguments` gates its item.
fn gates(names: &[String], arguments: Option<&TokenStream>) -> bool {
    match (names, arguments) {
        ([name], Some(predicate)) if name == "cfg" => evaluate(&trees(predicate)) == Some(false),
        ([name], Some(arguments)) if name == "cfg_attr" => applies_gate(arguments),
        ([.., name], _) => name == "test",
        _ => false,
    }
}

/// Whether a `cfg_attr(predicate, attributes...)` applies a gating attribute
/// in every build without `test`: its predicate is true there and one of its
/// attributes gates.
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

/// A `cfg` predicate's value in a build without `test`, or `None` when it
/// depends on another option.
fn evaluate(predicate: &[TokenTree]) -> Option<bool> {
    match predicate {
        [TokenTree::Ident(name)] => match name.to_string().as_str() {
            "test" | "false" => Some(false),
            "true" => Some(true),
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

/// `trees` split at its top-level commas, without an empty trailing part.
fn split(trees: &[TokenTree]) -> Vec<Vec<TokenTree>> {
    trees
        .split(|tree| matches!(tree, TokenTree::Punct(punct) if punct.as_char() == ','))
        .filter(|part| !part.is_empty())
        .map(<[TokenTree]>::to_vec)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::gated;

    fn item_gated(attributes: &str) -> bool {
        let item: syn::ItemFn = syn::parse_str(&format!("{attributes} fn item() {{}}"))
            .expect("the attributes and a function parse");
        gated(&item.attrs)
    }

    #[test]
    fn a_predicate_false_without_test_gates_its_item() {
        for attributes in [
            "#[cfg(test)]",
            "#[cfg(all(test, loom))]",
            "#[cfg(all(unix, test))]",
            "#[cfg(all(feature = \"sim\", not(loom), test))]",
            "#[cfg(all(all(test)))]",
            "#[cfg(any(test))]",
            "#[cfg(not(not(test)))]",
            "#[cfg(any(test, all(test, unix)))]",
            "#[cfg(any())]",
            "#[cfg(false)]",
            "#[cfg(\n    all(\n        test,\n        target_os = \"linux\"\n    )\n)]",
            "#[allow(dead_code)] #[cfg(test)]",
        ] {
            assert!(
                item_gated(attributes),
                "{attributes} leaves its item in production"
            );
        }
    }

    #[test]
    fn a_predicate_another_option_can_satisfy_leaves_its_item_in_production() {
        for attributes in [
            "",
            "#[cfg(not(test))]",
            "#[cfg(any(test, kani))]",
            "#[cfg(all(any(unix, test), feature = \"x\"))]",
            "#[cfg(unix)]",
            "#[cfg(all(unix, not(unix)))]",
            "#[cfg(all())]",
            "#[cfg(true)]",
            "#[cfg_attr(test, allow(dead_code))]",
            "#[cfg_attr(test, cfg(test))]",
            "#[cfg_attr(unix, inline)]",
            "#[cfg_attr(unix, cfg(test))]",
            "#[cfg_attr(unix, inline, cfg(any(test)))]",
            "#[cfg_attr(unix, cfg_attr(all(), cfg(test)))]",
            "#[doc = \"cfg(test)\"]",
            "#[allow(clippy::test_attr_in_doctest)]",
        ] {
            assert!(!item_gated(attributes), "{attributes} gates its item");
        }
    }

    #[test]
    fn a_test_attribute_and_a_cfg_attr_that_always_applies_a_gate_gate_their_item() {
        for attributes in [
            "#[test]",
            "#[tokio::test]",
            "#[tokio::test(flavor = \"current_thread\")]",
            "#[cfg_attr(all(), cfg(test))]",
            "#[cfg_attr(all(), inline, cfg(any(test)))]",
            "#[cfg_attr(true, cfg_attr(all(), cfg(test)))]",
            "#[cfg_attr(not(test), test)]",
        ] {
            assert!(
                item_gated(attributes),
                "{attributes} leaves its item in production"
            );
        }
    }
}
