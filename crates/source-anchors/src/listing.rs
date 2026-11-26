//! Lists a parsed file's declarations by its syntax tree.
//!
//! Invariant: every listed line names a declaration the parser found at an
//! item, field or variant position. Text inside a comment, a literal, a macro
//! invocation or definition, or a function body is never listed, and a
//! declaration is `production` only when neither it nor an enclosing item is
//! [gated](crate::gating). A `value` line directly follows the `const` line
//! it belongs to and carries the `const` line's build and text.

use std::fmt;

use syn::{Attribute, Expr, Field, ForeignItem, Ident, ImplItem, Item, TraitItem, Visibility};

use crate::gating::gated;
use crate::value::integer_arithmetic;

/// One declaration of a source file, displayed as `<build>\t<kind>\t<text>`.
pub(crate) struct Declaration {
    production: bool,
    kind: &'static str,
    text: String,
}

impl fmt::Display for Declaration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let build = if self.production {
            "production"
        } else {
            "gated"
        };
        write!(f, "{build}\t{}\t{}", self.kind, self.text)
    }
}

/// The declarations of `source` in source order, or the parser's error.
pub(crate) fn declarations(source: &str) -> syn::Result<Vec<Declaration>> {
    let file = syn::parse_file(source)?;
    let mut listing = Listing(Vec::new());
    listing.items(&file.items, !gated(&file.attrs), true);
    Ok(listing.0)
}

struct Listing(Vec<Declaration>);

impl Listing {
    /// Lists `items`; `production` is false inside a gated item or file, and
    /// `top` is true for the file's own items, outside every inline module.
    fn items(&mut self, items: &[Item], production: bool, top: bool) {
        for item in items {
            match item {
                Item::Const(item) => {
                    self.constant(
                        production,
                        &item.attrs,
                        &item.vis,
                        &item.ident,
                        Some(&item.expr),
                    );
                }
                Item::Static(item) => {
                    self.item(production, &item.attrs, &item.vis, "static", &item.ident);
                }
                Item::Type(item) => {
                    self.item(production, &item.attrs, &item.vis, "type", &item.ident);
                }
                Item::TraitAlias(item) => {
                    self.item(production, &item.attrs, &item.vis, "trait", &item.ident);
                }
                Item::Fn(item) => {
                    self.item(production, &item.attrs, &item.vis, "fn", &item.sig.ident);
                }
                Item::Struct(item) => {
                    let inner =
                        self.item(production, &item.attrs, &item.vis, "struct", &item.ident);
                    self.fields(&item.fields, inner);
                }
                Item::Union(item) => {
                    let inner = self.item(production, &item.attrs, &item.vis, "union", &item.ident);
                    self.fields(&item.fields.named, inner);
                }
                Item::Enum(item) => {
                    let inner = self.item(production, &item.attrs, &item.vis, "enum", &item.ident);
                    for variant in &item.variants {
                        self.push(
                            inner && !gated(&variant.attrs),
                            "variant",
                            variant.ident.to_string(),
                        );
                    }
                }
                Item::Mod(item) => {
                    let inner = self.item(production, &item.attrs, &item.vis, "mod", &item.ident);
                    match &item.content {
                        Some((_, items)) => self.items(items, inner, false),
                        None if top => {
                            if let Some(line) = self.0.last_mut() {
                                line.kind = "module";
                            }
                        }
                        None => {}
                    }
                }
                Item::Trait(item) => {
                    let inner = self.item(production, &item.attrs, &item.vis, "trait", &item.ident);
                    for member in &item.items {
                        let none = Visibility::Inherited;
                        match member {
                            TraitItem::Const(member) => {
                                let default = member.default.as_ref().map(|(_, value)| value);
                                self.constant(inner, &member.attrs, &none, &member.ident, default);
                            }
                            TraitItem::Fn(member) => {
                                self.item(inner, &member.attrs, &none, "fn", &member.sig.ident);
                            }
                            TraitItem::Type(member) => {
                                self.item(inner, &member.attrs, &none, "type", &member.ident);
                            }
                            _ => {}
                        }
                    }
                }
                Item::Impl(item) => {
                    let inner = production && !gated(&item.attrs);
                    for member in &item.items {
                        match member {
                            ImplItem::Const(member) => {
                                self.constant(
                                    inner,
                                    &member.attrs,
                                    &member.vis,
                                    &member.ident,
                                    Some(&member.expr),
                                );
                            }
                            ImplItem::Fn(member) => {
                                self.item(
                                    inner,
                                    &member.attrs,
                                    &member.vis,
                                    "fn",
                                    &member.sig.ident,
                                );
                            }
                            ImplItem::Type(member) => {
                                self.item(inner, &member.attrs, &member.vis, "type", &member.ident);
                            }
                            _ => {}
                        }
                    }
                }
                Item::ForeignMod(item) => {
                    let inner = production && !gated(&item.attrs);
                    for member in &item.items {
                        match member {
                            ForeignItem::Fn(member) => {
                                self.item(
                                    inner,
                                    &member.attrs,
                                    &member.vis,
                                    "fn",
                                    &member.sig.ident,
                                );
                            }
                            ForeignItem::Static(member) => {
                                self.item(
                                    inner,
                                    &member.attrs,
                                    &member.vis,
                                    "static",
                                    &member.ident,
                                );
                            }
                            ForeignItem::Type(member) => {
                                self.item(inner, &member.attrs, &member.vis, "type", &member.ident);
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
    }

    /// Lists one item and returns whether its members are in production.
    fn item(
        &mut self,
        production: bool,
        attributes: &[Attribute],
        visibility: &Visibility,
        keyword: &str,
        name: &Ident,
    ) -> bool {
        let production = production && !gated(attributes);
        let text = match scope(visibility) {
            Some(scope) => format!("{scope} {keyword} {name}"),
            None => format!("{keyword} {name}"),
        };
        self.push(production, "item", text);
        production
    }

    /// The `value` line takes the `const` line's build, so a gated constant's
    /// value stays gated. A trait constant that declares only a type passes
    /// `None` as its `initializer`.
    fn constant(
        &mut self,
        production: bool,
        attributes: &[Attribute],
        visibility: &Visibility,
        name: &Ident,
        initializer: Option<&Expr>,
    ) {
        let production = self.item(production, attributes, visibility, "const", name);
        let value = initializer.and_then(integer_arithmetic);
        if let (Some(value), Some(declaration)) = (value, self.0.last()) {
            let text = format!("{} = {value}", declaration.text);
            self.push(production, "value", text);
        }
    }

    fn fields<'a>(&mut self, fields: impl IntoIterator<Item = &'a Field>, production: bool) {
        for field in fields {
            if let Some(name) = &field.ident {
                let text = match scope(&field.vis) {
                    Some(scope) => format!("{scope} {name}"),
                    None => name.to_string(),
                };
                self.push(production && !gated(&field.attrs), "field", text);
            }
        }
    }

    fn push(&mut self, production: bool, kind: &'static str, text: String) {
        self.0.push(Declaration {
            production,
            kind,
            text,
        });
    }
}

/// `pub`, `pub(crate)`, `pub(super)`, `pub(in a::b)`, or `None` for a private
/// declaration.
fn scope(visibility: &Visibility) -> Option<String> {
    match visibility {
        Visibility::Public(_) => Some("pub".to_owned()),
        Visibility::Restricted(restricted) => {
            let path: Vec<String> = restricted
                .path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect();
            let within = if restricted.in_token.is_some() {
                "in "
            } else {
                ""
            };
            Some(format!("pub({within}{})", path.join("::")))
        }
        Visibility::Inherited => None,
    }
}

#[cfg(test)]
mod tests {
    use super::declarations;

    fn lines(source: &str) -> Vec<String> {
        declarations(source)
            .expect("the source parses")
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    #[test]
    fn items_fields_variants_and_members_are_listed_with_their_visibility() {
        let source = r#"
            pub struct Report { pub held_units: u64, pub(crate) members: u32, private: u8 }
            pub struct Pair(pub u8, u8);
            pub enum Milestone { FirstSafeHit, Fill { tick: u64 }, Sized(u8) = 3 }
            const NAMESPACE: u8 = 0;
            pub(super) fn retained_set<'r>(x: &'r u8) -> &'r u8 { x }
            pub(in crate::storage) static FLAG: u8 = 0;
            impl Report { pub fn real(&self) -> u8 { 0 } const LIMIT: u8 = 1; }
            pub trait Judge { fn decide(&self); type Verdict; }
            unsafe extern "C" { pub fn external(); }
            pub mod inner { pub type Alias = u8; mod nested_elsewhere; }
            mod elsewhere;
        "#;
        assert_eq!(
            lines(source),
            [
                "production\titem\tpub struct Report",
                "production\tfield\tpub held_units",
                "production\tfield\tpub(crate) members",
                "production\tfield\tprivate",
                "production\titem\tpub struct Pair",
                "production\titem\tpub enum Milestone",
                "production\tvariant\tFirstSafeHit",
                "production\tvariant\tFill",
                "production\tvariant\tSized",
                "production\titem\tconst NAMESPACE",
                "production\tvalue\tconst NAMESPACE = 0",
                "production\titem\tpub(super) fn retained_set",
                "production\titem\tpub(in crate::storage) static FLAG",
                "production\titem\tpub fn real",
                "production\titem\tconst LIMIT",
                "production\tvalue\tconst LIMIT = 1",
                "production\titem\tpub trait Judge",
                "production\titem\tfn decide",
                "production\titem\ttype Verdict",
                "production\titem\tpub fn external",
                "production\titem\tpub mod inner",
                "production\titem\tpub type Alias",
                "production\titem\tmod nested_elsewhere",
                "production\tmodule\tmod elsewhere",
            ]
        );
    }

    #[test]
    fn text_in_comments_literals_macros_and_function_bodies_is_not_listed() {
        let source = r##"
            /*
            pub fn commented() {}
            /* pub fn nested_comment() {} */
            */
            // pub fn line_comment() {}
            pub const DOC: &str = "
            pub fn in_string() {}
            ";
            pub const RAW: &str = r#"
            pub fn in_raw_string() {}
            "#;
            pub const QUOTES: [char; 2] = ['\x41', '"'];
            pub const AFTER: &str = "]; pub fn after_quotes() {} ";
            macro_rules! unused { () => { pub fn in_macro_definition() {} }; }
            unused_elsewhere! { pub fn in_macro_invocation() {} }
            pub fn outer() { pub fn in_function_body() {} }
            pub enum E<const N: usize = { Some(3usize).unwrap() }> {
                A = core::mem::size_of::<Box<dyn core::ops::Add<u8, Output = u8>>>() as isize,
            }
            pub fn real() {}
        "##;
        assert_eq!(
            lines(source),
            [
                "production\titem\tpub const DOC",
                "production\titem\tpub const RAW",
                "production\titem\tpub const QUOTES",
                "production\titem\tpub const AFTER",
                "production\titem\tpub fn outer",
                "production\titem\tpub enum E",
                "production\tvariant\tA",
                "production\titem\tpub fn real",
            ]
        );
    }

    #[test]
    fn a_gate_covers_its_item_and_everything_inside_it() {
        let source = r#"
            #[cfg(test)]
            mod tests {
                macro_rules! m { ($($x:tt)*) => { $($x)* } }
                const S: &str = "
}
";
                pub fn in_test_module() {}
                pub struct Fixture { pub field: u8 }
                pub enum Case { One }
            }
            #[cfg(all(
                test,
                target_os = "linux",
            ))]
            #[allow(
                dead_code,
            )]
            impl Report { pub fn only_in_tests(&self) {} }
            pub struct Kept {
                #[cfg(test)]
                pub scratch: u64,
                pub held: u64,
            }
            pub enum Kind { #[cfg(test)] Probe, Real }
            #[test]
            pub fn a_test() {}
            #[cfg(not(test))]
            pub fn production_only() {}
            pub fn real() {}
        "#;
        assert_eq!(
            lines(source),
            [
                "gated\titem\tmod tests",
                "gated\titem\tconst S",
                "gated\titem\tpub fn in_test_module",
                "gated\titem\tpub struct Fixture",
                "gated\tfield\tpub field",
                "gated\titem\tpub enum Case",
                "gated\tvariant\tOne",
                "gated\titem\tpub fn only_in_tests",
                "production\titem\tpub struct Kept",
                "gated\tfield\tpub scratch",
                "production\tfield\tpub held",
                "production\titem\tpub enum Kind",
                "gated\tvariant\tProbe",
                "production\tvariant\tReal",
                "gated\titem\tpub fn a_test",
                "production\titem\tpub fn production_only",
                "production\titem\tpub fn real",
            ]
        );
    }

    #[test]
    fn an_inner_attribute_gates_its_whole_scope() {
        assert_eq!(
            lines("#![cfg(test)]\npub fn ghost() {}\n"),
            ["gated\titem\tpub fn ghost"]
        );
        assert_eq!(
            lines("pub mod m {\n    #![cfg(test)]\n    pub fn ghost() {}\n}\npub fn real() {}\n"),
            [
                "gated\titem\tpub mod m",
                "gated\titem\tpub fn ghost",
                "production\titem\tpub fn real",
            ]
        );
    }

    #[test]
    fn an_integer_constant_lists_its_value_under_its_own_build_and_declaration() {
        let source = r#"
            pub const IO_UNIT: usize = 4_096;
            pub(crate) const UNIT_ENTRIES: u64 = ((crate::storage::IO_UNIT - OVERHEAD) / 96) as u64;
            pub const NOTE: &str = "const IO_UNIT: usize = 512;";
            pub const PAIR: [u8; 2] = [1, 2];
            #[cfg(test)]
            mod probe { pub const IO_UNIT: usize = 512; }
            impl Report { pub const LIMIT: u8 = 1 << 3; }
            pub trait Judge { const ROUNDS: u8 = 2; const DEPTH: u8; }
        "#;
        assert_eq!(
            lines(source),
            [
                "production\titem\tpub const IO_UNIT",
                "production\tvalue\tpub const IO_UNIT = 4096",
                "production\titem\tpub(crate) const UNIT_ENTRIES",
                "production\tvalue\tpub(crate) const UNIT_ENTRIES = u64(((crate::storage::IO_UNIT - OVERHEAD) / 96))",
                "production\titem\tpub const NOTE",
                "production\titem\tpub const PAIR",
                "gated\titem\tmod probe",
                "gated\titem\tpub const IO_UNIT",
                "gated\tvalue\tpub const IO_UNIT = 512",
                "production\titem\tpub const LIMIT",
                "production\tvalue\tpub const LIMIT = (1 << 3)",
                "production\titem\tpub trait Judge",
                "production\titem\tconst ROUNDS",
                "production\tvalue\tconst ROUNDS = 2",
                "production\titem\tconst DEPTH",
            ]
        );
    }

    #[test]
    fn a_source_that_does_not_parse_lists_nothing() {
        assert!(declarations("pub fn broken( {").is_err());
    }
}
