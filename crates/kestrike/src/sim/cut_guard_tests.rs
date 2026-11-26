//! Every source file under `src/sim/cut` imports only the standard
//! library, `sha2` and the core's own modules. The guard also flags each
//! closure bound, function pointer, trait object, trait declaration and
//! generic function or impl, the forms through which a caller could pass
//! root selection or exclusion policy into the core.

use std::path::Path;

use crate::oracle::guard_tests::{
    EXTERNAL_CRATES, FORBIDDEN_TOKENS, KEYWORDS, UNTERMINATED, attribute_names_path, depth,
    sources, tokens, use_tree_violations,
};

/// The external crate the core hashes with.
const HASHER: &str = "sha2";

/// The core's path below the crate root, as tokens.
const HOME: [&str; 3] = ["sim", "::", "cut"];

/// The roots a `use` tree in a file below `mod.rs` may start from.
const CHILD_ROOTS: [&str; 5] = ["std", "core", "alloc", HASHER, "super"];

/// The roots a `use` tree in `mod.rs` may start from; its submodules are
/// named through `self`.
const MOD_ROOTS: [&str; 5] = ["std", "core", "alloc", HASHER, "self"];

/// Tokens that would let a caller pass behavior into the core.
const HOOKS: [&str; 5] = ["Fn", "FnMut", "FnOnce", "dyn", "trait"];

/// The guard's findings in `file`, a path relative to `src/sim/cut`: a
/// `crate::` path outside `crate::sim::cut`, a `use` tree whose root is
/// outside `MOD_ROOTS` in `mod.rs` or `CHILD_ROOTS` elsewhere, a `super`
/// or `crate` nested past a `use` root, an external crate or absolute
/// path other than `std`, `core`, `alloc` and `sha2`, a `super` chain
/// above the core, a file-inclusion or `macro_rules` token, an `extern
/// crate` item, a `path` attribute, an unterminated string, each hook
/// token or function-pointer type, and each generic function or impl,
/// including a function with an `impl Trait` parameter.
fn violations(file: &str, source: &str) -> Vec<String> {
    let tokens = tokens(source);
    let depth = depth(file);
    let roots: &[&str] = if depth == 0 { &MOD_ROOTS } else { &CHILD_ROOTS };
    let at = |i: usize| tokens.get(i).copied().unwrap_or("");
    let mut found = Vec::new();
    if tokens.contains(&UNTERMINATED) {
        found.push(format!("{file}: {UNTERMINATED}"));
    }
    let mut run = 0;
    for i in 0..tokens.len() {
        let (token, next, previous) = (at(i), at(i + 1), at(i.wrapping_sub(1)));
        if token == "crate" && next == "::" && !tokens[i + 2..].starts_with(&HOME) {
            found.push(format!("{file}: crate path `crate::{}`", at(i + 2)));
        }
        if next == "::" && token != HASHER && EXTERNAL_CRATES.contains(&token) {
            found.push(format!("{file}: external crate `{token}`"));
        }
        if token == "::" && !matches!(next, "std" | "core" | "alloc" | HASHER) {
            let continues = i > 0
                && !KEYWORDS.contains(&previous)
                && (previous == ">" || previous.chars().all(|c| c.is_alphanumeric() || c == '_'));
            if !continues {
                found.push(format!("{file}: absolute path `::{next}`"));
            }
        }
        if (token == "extern" && next == "crate") || FORBIDDEN_TOKENS.contains(&token) {
            found.push(format!("{file}: `{token}`"));
        }
        if token == "#" && attribute_names_path(&tokens[i + 1..]) {
            found.push(format!("{file}: `path` attribute"));
        }
        // `item` holds when `impl` opens an impl block at item position.
        // `returned` holds when `impl` follows `->`, tokenized as `-` then
        // `>`: a return-position type the defining function chooses. Every
        // other `impl Trait`, including one nested inside a return type, is
        // flagged.
        let item = matches!(previous, "" | "}" | ";" | "]" | "{" | "unsafe");
        let returned = previous == ">" && at(i.wrapping_sub(2)) == "-";
        let generic = (token == "fn" && at(i + 2) == "<")
            || (token == "impl" && (next == "<" || !(item || returned)));
        if HOOKS.contains(&token) || (token == "fn" && next == "(") || generic {
            found.push(format!("{file}: hook `{token}`"));
        }
        if token == "super" {
            run += 1;
            if run > depth {
                found.push(format!("{file}: path above the cut core"));
            }
        } else if token != "::" {
            run = 0;
        }
        if token == "use" {
            use_tree_violations(file, &tokens[i + 1..], roots, &HOME, &mut found);
        }
    }
    found
}

#[test]
fn cut_core_sources_import_only_std_sha2_and_the_core() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/sim/cut");
    let mut files = Vec::new();
    sources(&dir, &dir, &mut files);
    let mut names: Vec<&str> = files.iter().map(|(name, _)| name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        ["descriptor.rs", "enumerate.rs", "identity.rs", "mod.rs"]
    );
    let found: Vec<String> = files
        .iter()
        .flat_map(|(name, source)| violations(name, source))
        .collect();
    assert!(found.is_empty(), "{found:#?}");
}

#[test]
fn the_guard_flags_protocol_imports_and_policy_hooks() {
    let krate = "crate::";
    let flagged = [
        (
            "enumerate.rs",
            format!("use {krate}storage::journal::Root;"),
        ),
        ("enumerate.rs", format!("use {krate}sim::trace::Field;")),
        (
            "enumerate.rs",
            format!("let r = {krate}net::restart::relaunch();"),
        ),
        (
            "enumerate.rs",
            "use super::super::choice::Chooser;".to_string(),
        ),
        ("mod.rs", "use super::choice::Chooser;".to_string()),
        (
            "enumerate.rs",
            "use super::{identity::Cut, super::choice::Chooser};".to_string(),
        ),
        (
            "enumerate.rs",
            "use super::{identity::Cut, super::{choice::Chooser, super::{storage::journal::Root}}};"
                .to_string(),
        ),
        ("mod.rs", "mod identity;\npub(crate) use identity::Cut;".to_string()),
        ("enumerate.rs", "use libc as l;".to_string()),
        ("enumerate.rs", "use libc::c_int;".to_string()),
        ("enumerate.rs", "let p = ::spdk_sys::probe();".to_string()),
        ("enumerate.rs", "use ::journal::Root;".to_string()),
        ("enumerate.rs", "let s = \"unterminated;".to_string()),
        (
            "enumerate.rs",
            "pub(crate) fn plan(select: impl Fn(&Cut) -> bool) {}".to_string(),
        ),
        (
            "enumerate.rs",
            "pub(crate) fn plan(policy: &dyn Exclusion) {}".to_string(),
        ),
        ("enumerate.rs", "pub(crate) trait Root {}".to_string()),
        ("enumerate.rs", "type Hook = fn(&Cut) -> bool;".to_string()),
        (
            "enumerate.rs",
            "pub(crate) fn plan<R: Ord>(root: R) {}".to_string(),
        ),
        (
            "enumerate.rs",
            "pub(crate) fn plan(root: impl Ord) {}".to_string(),
        ),
        (
            "enumerate.rs",
            "pub(crate) fn plan(cuts: &mut impl Iterator<Item = Cut>) {}".to_string(),
        ),
        (
            "enumerate.rs",
            "pub(crate) fn plan(cuts: Vec<impl Ord>) {}".to_string(),
        ),
        ("identity.rs", "impl<T: Ord> From<T> for Cut {}".to_string()),
        ("enumerate.rs", "include!(\"../trace.rs\");".to_string()),
        (
            "enumerate.rs",
            "#[path = \"../trace.rs\"] mod t;".to_string(),
        ),
        ("enumerate.rs", "extern crate self as c;".to_string()),
        ("enumerate.rs", "macro_rules! m { () => {} }".to_string()),
    ];
    for (file, source) in &flagged {
        assert!(!violations(file, source).is_empty(), "{file}: {source}");
    }
    let admitted = [
        (
            "enumerate.rs",
            "use std::collections::BTreeSet;".to_string(),
        ),
        ("identity.rs", "use sha2::{Digest, Sha256};".to_string()),
        ("enumerate.rs", "use super::identity::Cut;".to_string()),
        (
            "mod.rs",
            "mod identity;\npub(crate) use self::identity::Cut;".to_string(),
        ),
        ("enumerate.rs", format!("use {krate}sim::cut::Cut;")),
        (
            "enumerate.rs",
            "pub(crate) fn enumerate(d: &Descriptor) -> Vec<Cut> { Vec::new() }".to_string(),
        ),
        (
            "enumerate.rs",
            "fn masks(child: Child) -> impl Iterator<Item = u64> { [0].into_iter() }".to_string(),
        ),
        (
            "identity.rs",
            "#[derive(Clone)]\npub(crate) struct S;\nimpl S {}\nimpl Copy for S {}".to_string(),
        ),
        ("enumerate.rs", "let s = \"crate::storage\";".to_string()),
        (
            "enumerate.rs",
            "// use crate::storage::Root;\nuse std::fmt;".to_string(),
        ),
        ("enumerate.rs", "let v = Vec::<u8>::new();".to_string()),
    ];
    for (file, source) in &admitted {
        assert!(violations(file, source).is_empty(), "{file}: {source}");
    }
}
