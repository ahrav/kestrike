//! The import guard keeps every oracle source file on the standard library
//! and the oracle's own submodules.

use std::fs;
use std::path::Path;

/// The crate roots this crate's `Cargo.toml` dependencies bind;
/// `external_crates_list_every_manifest_dependency` holds the list equal
/// to the manifest's dependency keys.
pub(crate) const EXTERNAL_CRATES: [&str; 13] = [
    "libc",
    "memchr",
    "polyval",
    "sha2",
    "spdk_sys",
    "subtle",
    "loom",
    "libfuzzer_sys",
    "itf",
    "quint_connect",
    "serde",
    "serde_json",
    "campaign_supervisor",
];
const CHILD_ROOTS: [&str; 4] = ["std", "core", "alloc", "super"];
const MOD_ROOTS: [&str; 4] = ["std", "core", "alloc", "self"];
const ORACLE_ROOT: &str = "oracle";
pub(crate) const UNTERMINATED: &str = "<unterminated string>";
pub(crate) const KEYWORDS: [&str; 22] = [
    "as", "break", "const", "dyn", "else", "for", "if", "impl", "in", "let", "match", "move",
    "mut", "pub", "ref", "return", "static", "type", "unsafe", "use", "where", "while",
];
pub(crate) const FORBIDDEN_TOKENS: [&str; 4] =
    ["macro_rules", "include", "include_str", "include_bytes"];

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Splits `source` into identifier, `::` and single-character tokens,
/// dropping whitespace and comments. Each closed string literal becomes
/// `""` and each char literal `''`, so text inside a literal yields no
/// token; an unclosed string becomes `UNTERMINATED`. Raw identifiers
/// lose their `r#` prefix.
pub(crate) fn tokens(source: &str) -> Vec<&str> {
    let (mut offsets, chars): (Vec<usize>, Vec<char>) = source.char_indices().unzip();
    offsets.push(source.len());
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        if c.is_whitespace() {
            i += 1;
        } else if c == '/' && next == Some('/') {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
        } else if c == '/' && next == Some('*') {
            let mut level = 0;
            while i < chars.len() {
                if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
                    level += 1;
                    i += 2;
                } else if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
                    level -= 1;
                    i += 2;
                    if level == 0 {
                        break;
                    }
                } else {
                    i += 1;
                }
            }
        } else if c == '"' {
            i += 1;
            while i < chars.len() && chars[i] != '"' {
                i += if chars[i] == '\\' { 2 } else { 1 };
            }
            out.push(if i < chars.len() {
                "\"\""
            } else {
                UNTERMINATED
            });
            i += 1;
        } else if c == '\'' {
            let close = if next == Some('\\') {
                (i + 3..chars.len()).find(|&j| chars[j] == '\'')
            } else if chars.get(i + 2) == Some(&'\'') {
                Some(i + 2)
            } else {
                None
            };
            match close {
                Some(end) => {
                    i = end + 1;
                    out.push("''");
                }
                None => {
                    i += 1;
                    out.push("'");
                }
            }
        } else if is_ident(c) {
            let start = i;
            while i < chars.len() && is_ident(chars[i]) {
                i += 1;
            }
            let word = &source[offsets[start]..offsets[i]];
            let raw = matches!(word, "r" | "br" | "cr");
            let hashes = chars[i..].iter().take_while(|&&h| h == '#').count();
            let quoted = chars.get(i + hashes) == Some(&'"');
            if word == "r" && hashes == 1 && chars.get(i + 1).is_some_and(|&n| is_ident(n)) {
                i += 1;
                let start = i;
                while i < chars.len() && is_ident(chars[i]) {
                    i += 1;
                }
                out.push(&source[offsets[start]..offsets[i]]);
            } else if raw && quoted {
                i += hashes + 1;
                let mut closed = false;
                while i < chars.len() {
                    let closing = chars[i] == '"'
                        && chars[i + 1..]
                            .iter()
                            .take(hashes)
                            .filter(|&&h| h == '#')
                            .count()
                            == hashes;
                    i += 1;
                    if closing {
                        i += hashes;
                        closed = true;
                        break;
                    }
                }
                out.push(if closed { "\"\"" } else { UNTERMINATED });
            } else {
                out.push(word);
            }
        } else if c == ':' && next == Some(':') {
            out.push("::");
            i += 2;
        } else {
            out.push(&source[offsets[i]..offsets[i + 1]]);
            i += 1;
        }
    }
    out
}

/// Whether the attribute starting at `rest`, the tokens after a `#`,
/// contains a `path` token inside its outermost brackets.
pub(crate) fn attribute_names_path(rest: &[&str]) -> bool {
    let mut level = 0;
    for &token in rest.iter().skip_while(|&&t| t == "!") {
        match token {
            "[" => level += 1,
            "]" => {
                level -= 1;
                if level == 0 {
                    return false;
                }
            }
            "path" if level > 0 => return true,
            _ if level == 0 => return false,
            _ => {}
        }
    }
    false
}

/// How many `super` segments lead from `file`, a `/`-separated path
/// relative to the guarded root, back to that root's module: one per
/// directory, plus one unless the file is a `mod.rs`.
pub(crate) fn depth(file: &str) -> usize {
    let parts: Vec<&str> = file.split('/').collect();
    let dirs = parts.len() - 1;
    dirs + usize::from(parts.last() != Some(&"mod.rs"))
}

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
        let (token, next, after) = (at(i), at(i + 1), at(i + 2));
        if token == "crate" && next == "::" && after != ORACLE_ROOT {
            found.push(format!("{file}: crate path `crate::{after}`"));
        }
        if (token == "extern" && next == "crate") || FORBIDDEN_TOKENS.contains(&token) {
            found.push(format!("{file}: `{token}`"));
        }
        if token == "#" && attribute_names_path(&tokens[i + 1..]) {
            found.push(format!("{file}: `path` attribute"));
        }
        if token == "::" && !matches!(next, "std" | "core" | "alloc") {
            let previous = at(i.wrapping_sub(1));
            let continues = i > 0
                && !KEYWORDS.contains(&previous)
                && (previous == ">" || previous.chars().all(is_ident));
            if !continues {
                found.push(format!("{file}: absolute path `::{next}`"));
            }
        }
        if next == "::" && EXTERNAL_CRATES.contains(&token) {
            found.push(format!("{file}: external crate `{token}`"));
        }
        if token == "super" {
            run += 1;
            if run > depth {
                found.push(format!("{file}: path above the oracle"));
            }
        } else if token != "::" {
            run = 0;
        }
        if token == "use" {
            use_tree_violations(file, &tokens[i + 1..], roots, &[ORACLE_ROOT], &mut found);
        }
    }
    found
}

/// A root starts the statement or a branch of a brace group that itself sits
/// at a root position; a group after `::` holds suffixes of the path before
/// it. Each root must be one of `roots` or be `crate` followed by `::` and
/// the `home` tokens, the guarded module's path below the crate root. Past a
/// root, `super` is valid only in that root's leading `self`/`super` chain,
/// and a suffix group rejects both `super` and `crate`.
pub(crate) fn use_tree_violations(
    file: &str,
    after_use: &[&str],
    roots: &[&str],
    home: &[&str],
    found: &mut Vec<String>,
) {
    let end = after_use
        .iter()
        .position(|&t| t == ";")
        .unwrap_or(after_use.len());
    let statement = &after_use[..end];
    let mut groups: Vec<bool> = Vec::new();
    let mut at_root = true;
    let mut chain = false;
    for (j, &token) in statement.iter().enumerate() {
        match token {
            "{" => {
                groups.push(at_root);
                chain = false;
            }
            "," => {
                at_root = groups.last() == Some(&true);
                chain = false;
            }
            "}" => {
                groups.pop();
                at_root = false;
                chain = false;
            }
            _ if at_root => {
                let into_home = token == "crate"
                    && statement.get(j + 1) == Some(&"::")
                    && statement
                        .get(j + 2..)
                        .is_some_and(|rest| rest.starts_with(home));
                if !roots.contains(&token) && !into_home {
                    found.push(format!("{file}: use root `{token}`"));
                }
                at_root = false;
                chain = matches!(token, "self" | "super");
            }
            "::" => {}
            "super" if chain => {}
            "super" | "crate" => {
                found.push(format!(
                    "{file}: nested path in `use {}`",
                    statement.join("")
                ));
                chain = false;
            }
            _ => chain = false,
        }
    }
}

/// Appends every `.rs` file under `dir`, recursively, to `found` as its
/// path relative to `root` and its text.
///
/// # Panics
///
/// - If a directory or file under `dir` cannot be read.
/// - If a file path lies outside `root`.
pub(crate) fn sources(root: &Path, dir: &Path, found: &mut Vec<(String, String)>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            sources(root, &path, found);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            let name = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            found.push((name, fs::read_to_string(&path).unwrap()));
        }
    }
}

/// Cargo binds each dependency key as a crate root, replacing `-` with `_`,
/// even when `package` names a different source package.
fn manifest_crates(manifest: &str) -> Vec<String> {
    let mut found: Vec<String> = manifest_dependencies(manifest)
        .into_iter()
        .map(|(_, key)| key.replace('-', "_"))
        .collect();
    found.sort();
    found
}

/// `manifest_dependencies` returns `(kind, key)` pairs in file order: one
/// for each key line under a dependency table header and one for each
/// dotted `[<kind>.<key>]` header. A dependency table header is a header
/// whose text ends in `dependencies`, target-specific tables included.
/// The kind is the header's `.`-separated segment that ends in
/// `dependencies`, such as `dev-dependencies`, with `_` read as `-`. For a
/// key line, the key is the text before `=` with whitespace and then `"`
/// trimmed from its ends, up to its first `.`. For a dotted header, the key
/// is the text after the last `dependencies.`. Lines starting with `#` are
/// skipped.
pub(crate) fn manifest_dependencies(manifest: &str) -> Vec<(String, String)> {
    let mut found = Vec::new();
    let mut kind = None;
    for line in manifest.lines().map(str::trim) {
        if let Some(header) = line.strip_prefix('[') {
            let header = header.split(']').next().unwrap_or("");
            kind = header.strip_suffix("dependencies").map(table_kind);
            if let Some((table, name)) = header.rsplit_once("dependencies.") {
                found.push((table_kind(table), name.to_owned()));
            }
        } else if let Some(kind) = &kind
            && !line.starts_with('#')
            && let Some((key, _)) = line.split_once('=')
        {
            let key = key.trim().trim_matches('"');
            let name = key.split('.').next().unwrap_or(key);
            found.push((kind.clone(), name.to_owned()));
        }
    }
    found
}

/// `prefix` is the header text before `dependencies`. Its last
/// `.`-separated segment supplies the kind's prefix, with `_` read as `-`.
fn table_kind(prefix: &str) -> String {
    let segment = prefix.rsplit('.').next().unwrap_or("");
    format!("{}dependencies", segment.replace('_', "-"))
}

#[test]
fn oracle_sources_import_only_std_and_oracle_submodules() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/oracle");
    let mut files = Vec::new();
    sources(&dir, &dir, &mut files);
    for expected in ["mod.rs", "row.rs", "history.rs", "guard_tests.rs"] {
        assert!(
            files.iter().any(|(name, _)| name == expected),
            "{expected} missing"
        );
    }
    let found: Vec<String> = files
        .iter()
        .flat_map(|(name, source)| violations(name, source))
        .collect();
    assert!(found.is_empty(), "{found:#?}");
}

#[test]
fn external_crates_list_every_manifest_dependency() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let manifest = fs::read_to_string(path).unwrap();
    let mut expected = EXTERNAL_CRATES.map(str::to_string).to_vec();
    expected.sort();
    assert_eq!(manifest_crates(&manifest), expected);
}

/// The supervisor's parser is a dependency of the worker crate only in
/// the `cfg(protocol_contract)` dev-dependency table, so a build without
/// that cfg links none of it; `external_crates_list_every_manifest_dependency`
/// refuses a second declaration.
#[test]
fn the_parser_is_a_dependency_only_under_the_contract_cfg() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let manifest = fs::read_to_string(path).unwrap();
    assert_eq!(contract_table(&manifest), ["campaign_supervisor"]);
    // A commented header names no table.
    let commented =
        "# [target.'cfg(protocol_contract)'.dev-dependencies]\n[dev-dependencies]\nplain = \"1\"\n";
    assert!(contract_table(commented).is_empty());
}

/// The crates the `cfg(protocol_contract)` dev-dependency table of
/// `manifest` names: the lines after its header line up to the next table
/// header.
fn contract_table(manifest: &str) -> Vec<String> {
    let header = "[target.'cfg(protocol_contract)'.dev-dependencies]";
    let mut lines = manifest.lines().skip_while(|line| line.trim() != header);
    let Some(first) = lines.next() else {
        return Vec::new();
    };
    let table: Vec<&str> = lines
        .take_while(|line| !line.trim_start().starts_with('['))
        .collect();
    manifest_crates(&format!("{first}\n{}", table.join("\n")))
}

#[test]
fn manifest_crates_reads_every_dependency_table_form() {
    let manifest = r#"
[package]
name = "not-a-dependency"

[dependencies]
plain = "1"
dashed-name = { version = "1" }
renamed = { package = "original", version = "1" }
inherited.workspace = true
# commented = "1"

[dev-dependencies]
dev-only = "1"

[build-dependencies]
build_only = "1"

[target.'cfg(all(target_os = "linux", target_pointer_width = "64"))'.dependencies]
linux-only = "1"

[target.'cfg(loom)'.dev-dependencies] # model checking
model = "1"

[dependencies.table-form]
version = "1"

[features]
extra = ["dep:plain"]
"#;
    assert_eq!(
        manifest_crates(manifest),
        [
            "build_only",
            "dashed_name",
            "dev_only",
            "inherited",
            "linux_only",
            "model",
            "plain",
            "renamed",
            "table_form",
        ]
    );
}

#[test]
fn the_guard_flags_production_and_external_imports() {
    let krate = "crate::";
    let flagged = [
        ("row.rs", format!("use {krate}storage::record::crc32c;")),
        ("row.rs", format!("use {krate}index::{{Key, Identity}};")),
        (
            "row.rs",
            "use super::super::storage::ledger::EngineBudget;".to_string(),
        ),
        ("mod.rs", "use super::net::frame::parse;".to_string()),
        (
            "row.rs",
            format!("let crc = {krate}storage::record::checksum(bytes);"),
        ),
        ("row.rs", "use sha2::Sha256;".to_string()),
        ("row.rs", "use libfuzzer_sys::fuzz_target;".to_string()),
        (
            "row.rs",
            "let mac = subtle::ConstantTimeEq::ct_eq(a, b);".to_string(),
        ),
        (
            "row.rs",
            "include!(\"../storage/allocation.rs\");".to_string(),
        ),
        (
            "row.rs",
            "use super::{super::storage::Storage};".to_string(),
        ),
        (
            "row.rs",
            "use super::{self as o, super::index::Key};".to_string(),
        ),
        (
            "row.rs",
            "fn f() { use proptest::prelude::any; }".to_string(),
        ),
        ("row.rs", "pub use foo::Bar;".to_string()),
        ("row.rs", "#[cfg(x)] use foo::Bar;".to_string()),
        ("row.rs", format!("use {krate}oracle_extra::Table;")),
        (
            "row.rs",
            format!("let s = r#\"a\"b\"#; use {krate}storage::Storage;"),
        ),
        (
            "row.rs",
            format!("/* \" */ use {krate}storage::Secret; /* \" */"),
        ),
        (
            "row.rs",
            format!("let q = '\\\"'; let v = {krate}storage::Secret::X; let p = '\"';"),
        ),
        ("row.rs", "let v = crate ::storage::Secret::X;".to_string()),
        ("row.rs", "extern  crate self as ic;".to_string()),
        ("row.rs", "include !(\"../storage/mod.rs\");".to_string()),
        (
            "row.rs",
            "# [path = \"../storage/mod.rs\"] mod s;".to_string(),
        ),
        ("row.rs", "use{tokio::x};".to_string()),
        ("row.rs", "let v = ::sha2::Sha256::new();".to_string()),
        ("row.rs", "::sha2::Sha256::new();".to_string()),
        (
            "row.rs",
            "let r#x = 1; let y = r#x + crate::storage::SECRET;".to_string(),
        ),
        ("row.rs", "let s = r#\"open; crate::storage::X".to_string()),
        (
            "row.rs",
            "macro_rules! p { ($a:tt) => { $a::storage::SECRET } } p!(crate);".to_string(),
        ),
        (
            "row.rs",
            "use core::include as inc; super::inc!(\"../storage/mod.rs\");".to_string(),
        ),
        (
            "row.rs",
            "#[cfg_attr(all(), path = \"../storage/mod.rs\")] mod loaded;".to_string(),
        ),
        (
            "row.rs",
            "#![path = \"../storage\"] mod loaded;".to_string(),
        ),
        ("row.rs", "let s = \"unterminated;".to_string()),
        (
            "row.rs",
            "impl ::subtle::ConstantTimeEq for Row {}".to_string(),
        ),
        (
            "row.rs",
            "for _ in ::memchr::memchr_iter(1, b) {}".to_string(),
        ),
        ("row.rs", "if ::libc::getpid() > 0 {}".to_string()),
        (
            "row.rs",
            "let d: &dyn ::subtle::ConstantTimeEq = x;".to_string(),
        ),
        (
            "row.rs",
            "#[cfg_attr(all(), rustfmt::skip[x], path = \"../storage/mod.rs\")] mod loaded;"
                .to_string(),
        ),
        (
            "checker/search.rs",
            "use super::super::super::storage::Storage;".to_string(),
        ),
        (
            "row.rs",
            "use {std::mem, sha2 as hash}; let h = hash::Sha256::default();".to_string(),
        ),
        (
            "row.rs",
            "use {std::fmt, {core::mem, tokio as t}};".to_string(),
        ),
        (
            "row.rs",
            "use crate as oracle; let s = oracle::storage::Secret;".to_string(),
        ),
    ];
    for (file, source) in &flagged {
        assert!(!violations(file, source).is_empty(), "{file}: {source}");
    }
    let admitted = [
        (
            "row.rs",
            "use std::collections::HashSet;\nuse super::ids::KeyId;".to_string(),
        ),
        ("mod.rs", "mod row;\nuse self::row::Row;".to_string()),
        ("row.rs", format!("use {krate}oracle::row::Row;")),
        ("row.rs", "// use sha2::Sha256;\nuse std::fmt;".to_string()),
        (
            "row.rs",
            "let text = \"use sha2::Sha256; crate::index\";".to_string(),
        ),
        (
            "row.rs",
            "let hashed = my_sha2::digest(b);\nuse core::mem;".to_string(),
        ),
        (
            "checker/search.rs",
            "use super::super::row::Row;".to_string(),
        ),
        ("checker/mod.rs", "use super::row::Row;".to_string()),
        ("row.rs", "let reuse = 1; let user = reuse;".to_string()),
        (
            "row.rs",
            "use std::path::Path; #[derive(Debug)] struct S; let r#type = 1;".to_string(),
        ),
        (
            "row.rs",
            "let s = r#\"use sha2::X\"#; use super::row::Row;".to_string(),
        ),
        (
            "row.rs",
            "let c = '\"'; let l: &'static str = \"crate::index\";".to_string(),
        ),
        (
            "row.rs",
            "pub(crate) struct S; let v = Vec::<u8>::new();".to_string(),
        ),
        (
            "row.rs",
            "/* use sha2::X; /* nested */ crate::index */ use std::fmt;".to_string(),
        ),
        ("row.rs", "use {std::fmt, super::row::Row};".to_string()),
        (
            "row.rs",
            format!("use {{{krate}oracle::row::Row, std::fmt}};"),
        ),
        (
            "row.rs",
            "use std::{fmt, collections::{HashMap, HashSet}};".to_string(),
        ),
    ];
    for (file, source) in &admitted {
        assert!(violations(file, source).is_empty(), "{file}: {source}");
    }
}
