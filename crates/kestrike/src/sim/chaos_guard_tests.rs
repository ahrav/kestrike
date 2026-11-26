//! The source guard over the chaos catalog. Every `chaos!` call names a
//! catalog row; each row has exactly one call, in the file and function
//! the row names; that file holds the row's permitting text, compared in
//! the raw source with comment line breaks joined; and no source outside
//! the chaos module names the module's fire function by path or imports
//! the module by glob. The two reversed copies of the catalog's mark, which
//! the binary scans search with, reverse to the mark.
//!
//! The attempt guard reads the crate's non-test source, the files a build
//! without `test` compiles less the items such a build leaves out, for
//! nonblocking attempts: mentions of `try_lock`, `compare_exchange`,
//! `compare_exchange_weak` and `try_recv`, whether a call, a path or name
//! passed as a value, or a name handed to a macro. Each function that
//! holds one is named by a catalog row or by a row of the declined table,
//! each row of that table names a function that holds an attempt of its
//! kind and states the outcome, a declined row states its reason, and at
//! most the table's bound of rows are admitted for a point. Each rule of
//! both guards has a fixture that fails it alone.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;
use std::path::Path;

use super::chaos::{ADMITTED_MAX, Attempt, CATALOG, Candidate, DECLINED, Disposition, Point, Row};
use crate::clients_closed_tests::string_fields;
use crate::oracle::guard_tests::{UNTERMINATED, attribute_names_path, sources, tokens};

/// The chaos module's file, exempt from the import rules because it
/// defines the macro and the fire function.
const HOME: &str = "sim/chaos.rs";

/// The functions of [`HOME`] that must each reference the catalog's mark.
const MARKED: [&str; 2] = ["arm", "fire"];

const RENAMED: &str = "renames `chaos`";

struct Function<'a> {
    /// The type of the item-level `impl` block that holds the function,
    /// or `""` for a function outside every such block.
    owner: &'a str,
    via_trait: bool,
    name: &'a str,
    /// The byte offset of the `fn` keyword in the source.
    offset: usize,
    /// The token position of the `fn` keyword.
    start: usize,
    /// The token positions of the body's opening and closing braces.
    body: Range<usize>,
}

impl Function<'_> {
    fn qualified(&self) -> String {
        match (self.owner, self.via_trait) {
            ("", _) => self.name.to_owned(),
            (owner, false) => format!("{owner}::{}", self.name),
            (owner, true) => format!("{owner}::{} (trait impl)", self.name),
        }
    }
}

fn starts_a_name(token: &str) -> bool {
    token.starts_with(|c: char| c.is_alphabetic() || c == '_')
}

/// The type an item-level `impl` at `tokens[at]` implements for: the last
/// path segment ahead of the type's generic arguments, after `for` when
/// the block implements a trait.
fn implemented<'a>(tokens: &[&'a str], at: usize) -> (&'a str, bool) {
    let mut i = at + 1;
    if tokens.get(i) == Some(&"<") {
        let mut level = 0;
        while let Some(&token) = tokens.get(i) {
            match token {
                "<" => level += 1,
                ">" if tokens[i - 1] != "-" => level -= 1,
                _ => {}
            }
            i += 1;
            if level == 0 {
                break;
            }
        }
    }
    let header: Vec<&str> = tokens[i.min(tokens.len())..]
        .iter()
        .copied()
        .take_while(|&token| token != "{" && token != "where")
        .collect();
    let for_at = header.iter().rposition(|&token| token == "for");
    let named = for_at.map_or(&header[..], |at| &header[at + 1..]);
    let owner = named
        .iter()
        .copied()
        .take_while(|&token| token != "<")
        .filter(|token| starts_a_name(token))
        .last()
        .unwrap_or("");
    (owner, for_at.is_some())
}

/// Every function of `source` that has a body. An `impl` opens a block
/// only at item level, after a closed item, an attribute or an opening
/// brace. `impl Trait` in a signature preserves the enclosing owner.
fn functions<'a>(source: &'a str, tokens: &[&'a str]) -> Vec<Function<'a>> {
    enum Open<'a> {
        Impl(&'a str, bool),
        Function(usize),
        Other,
    }
    let mut out: Vec<Function<'a>> = Vec::new();
    let mut open: Vec<Open<'a>> = Vec::new();
    // `pending` tracks the `impl` or `fn` header and its parenthesis and
    // bracket depth until the body opens or a depth-zero `;` ends the
    // declaration.
    let mut pending: Option<(Open<'a>, usize)> = None;
    for (i, &token) in tokens.iter().enumerate() {
        let before = if i == 0 { "" } else { tokens[i - 1] };
        match token {
            "impl" if matches!(before, "" | "}" | ";" | "]" | "{" | "unsafe") => {
                let (owner, via_trait) = implemented(tokens, i);
                pending = Some((Open::Impl(owner, via_trait), 0));
            }
            "fn" => {
                let name = tokens.get(i + 1).copied().unwrap_or("");
                if starts_a_name(name) {
                    let (owner, via_trait) = match open.last() {
                        Some(&Open::Impl(owner, via_trait)) => (owner, via_trait),
                        _ => ("", false),
                    };
                    // An identifier token is a slice of `source`.
                    let offset = token.as_ptr() as usize - source.as_ptr() as usize;
                    out.push(Function {
                        owner,
                        via_trait,
                        name,
                        offset,
                        start: i,
                        body: 0..0,
                    });
                    pending = Some((Open::Function(out.len() - 1), 0));
                }
            }
            "(" | "[" => {
                if let Some((_, nested)) = &mut pending {
                    *nested += 1;
                }
            }
            ")" | "]" => {
                if let Some((_, nested)) = &mut pending {
                    *nested = nested.saturating_sub(1);
                }
            }
            ";" if matches!(pending, Some((_, 0))) => {
                if let Some((Open::Function(_), _)) = pending.take() {
                    out.pop();
                }
            }
            "{" => {
                let opened = match pending {
                    Some((_, nested)) if nested > 0 => Open::Other,
                    _ => pending.take().map_or(Open::Other, |(opened, _)| opened),
                };
                if let Open::Function(at) = opened {
                    out[at].body = i..i;
                }
                open.push(opened);
            }
            "}" => {
                if let Some(Open::Function(at)) = open.pop() {
                    out[at].body.end = i;
                }
            }
            _ => {}
        }
    }
    out
}

/// The innermost function whose signature or body holds token `at`, so a
/// call inside a closure belongs to the function that holds the closure
/// and a parameter's name to the function that declares it.
fn enclosing<'f, 'a>(functions: &'f [Function<'a>], at: usize) -> Option<&'f Function<'a>> {
    functions
        .iter()
        .filter(|function| (function.start..function.body.end).contains(&at))
        .max_by_key(|function| function.body.start)
}

/// `documented` joins the documentation lines for the `fn` at `offset`
/// with a single space. Intervening attribute lines keep the comment
/// attached to the function.
fn documented(source: &str, offset: usize) -> String {
    let line_start = source[..offset].rfind('\n').map_or(0, |at| at + 1);
    let lines: Vec<&str> = source[..line_start].lines().map(str::trim).collect();
    let mut above: Vec<&str> = Vec::new();
    let mut at = lines.len();
    while at > 0 {
        let line = lines[at - 1];
        let outer_doc = line
            .strip_prefix("///")
            .filter(|text| !text.starts_with('/'));
        if let Some(text) = outer_doc {
            above.push(text.trim());
            at -= 1;
        } else if line.starts_with("//") || line.starts_with("#[") {
            at -= 1;
        } else if let Some(start) = attribute_start(&lines[..at]) {
            at = start;
        } else {
            break;
        }
    }
    above.reverse();
    above.join(" ")
}

fn attribute_start(lines: &[&str]) -> Option<usize> {
    let start = lines.iter().rposition(|line| line.starts_with("#["))?;
    let balance = |text: &[&str], open: char, close: char| {
        let count = |wanted: char| {
            text.iter()
                .map(|line| line.matches(wanted).count())
                .sum::<usize>()
        };
        count(open) as isize - count(close) as isize
    };
    let spans = balance(&lines[start..=start], '[', ']') > 0
        && balance(&lines[start..], '[', ']') == 0
        && balance(&lines[start..], '(', ')') == 0
        && lines.last().is_some_and(|line| line.ends_with(']'));
    spans.then_some(start)
}

/// The finding for the tokens after the `chaos ::` at `at`: the fire
/// function named by path or anywhere in an import group, a glob import of
/// the module, or the module renamed through `self as`.
fn imported(tokens: &[&str], at: usize) -> Option<&'static str> {
    const FIRE: &str = "names `chaos::fire` by path";
    const GLOB: &str = "imports `chaos` by glob";
    match tokens.get(at + 2).copied().unwrap_or("") {
        "fire" => Some(FIRE),
        "*" => Some(GLOB),
        "{" => {
            let mut rooted: Vec<bool> = Vec::new();
            for (i, &token) in tokens.iter().enumerate().skip(at + 2) {
                let leaf = matches!(tokens[i - 1], "{" | ",");
                let in_chaos = rooted.last() == Some(&true);
                match token {
                    "{" => rooted.push(rooted.is_empty() || (in_chaos && leaf)),
                    "}" => {
                        rooted.pop();
                        if rooted.is_empty() {
                            break;
                        }
                    }
                    "fire" => return Some(FIRE),
                    "*" if in_chaos && leaf => return Some(GLOB),
                    "self" if in_chaos && tokens.get(i + 1) == Some(&"as") => {
                        return Some(RENAMED);
                    }
                    _ => {}
                }
            }
            None
        }
        _ => None,
    }
}

/// Whether the token at `at` lies in a `use` item: scanning back from `at`,
/// a `use` keyword comes before any `;`. A `use` followed by `<` is a
/// `use<..>` capture bound, and the scan passes over it.
fn in_use(tokens: &[&str], at: usize) -> bool {
    for before in (0..at).rev() {
        match tokens[before] {
            ";" => return false,
            "use" if tokens.get(before + 1) != Some(&"<") => return true,
            _ => {}
        }
    }
    false
}

/// The guard's findings over `files`, paths relative to the crate's `src`
/// with their contents.
fn violations(files: &[(String, String)]) -> Vec<String> {
    let mut found = Vec::new();
    let mut calls: Vec<(Point, String)> = Vec::new();
    for (file, source) in files {
        let tokens = tokens(source);
        if tokens.contains(&UNTERMINATED) {
            found.push(format!("{file}: {UNTERMINATED}"));
        }
        let functions = functions(source, &tokens);
        let at = |i: usize| tokens.get(i).copied().unwrap_or("");
        for i in (0..tokens.len()).filter(|&i| at(i) == "chaos") {
            if at(i + 1) == "!" && matches!(at(i + 2), "(" | "[" | "{") {
                let named = at(i + 3);
                match Point::ALL
                    .into_iter()
                    .find(|point| format!("{point:?}") == named)
                {
                    Some(point) => {
                        let function = enclosing(&functions, i)
                            .map(Function::qualified)
                            .unwrap_or_default();
                        calls.push((point, format!("{file} {function}")));
                    }
                    None => found.push(format!("{file}: `chaos!({named})` names no catalog row")),
                }
            }
            if file == HOME {
                continue;
            }
            let finding = match at(i + 1) {
                "::" => imported(&tokens, i),
                "as" if in_use(&tokens, i) => Some(RENAMED),
                _ => None,
            };
            if let Some(finding) = finding {
                found.push(format!("{file}: {finding}"));
            }
        }
        if file == HOME {
            found.extend(home_violations(&tokens, &functions));
        }
    }
    if !files.iter().any(|(file, _)| file == HOME) {
        found.push(format!("{HOME} is missing"));
    }
    for row in &CATALOG {
        let sites: Vec<&str> = calls
            .iter()
            .filter(|(point, _)| *point == row.point)
            .map(|(_, site)| site.as_str())
            .collect();
        let expected = format!("{} {}", row.file, row.function);
        if sites != [expected.as_str()] {
            found.push(format!(
                "{}: calls in {sites:?}, one in {expected} expected",
                row.name
            ));
        }
        let docs: Vec<String> = files
            .iter()
            .find(|(file, _)| file == row.file)
            .map(|(_, source)| {
                functions(source, &tokens(source))
                    .iter()
                    .filter(|function| function.qualified() == row.function)
                    .map(|function| documented(source, function.offset))
                    .collect()
            })
            .unwrap_or_default();
        if docs.len() > 1 {
            found.push(format!(
                "{}: {} defines {} {} times",
                row.name,
                row.file,
                row.function,
                docs.len()
            ));
        }
        if !docs.iter().any(|doc| doc.contains(row.permits)) {
            found.push(format!(
                "{}: the documentation of {} in {} lacks the permitting text `{}`",
                row.name, row.function, row.file, row.permits
            ));
        }
    }
    found
}

/// The findings over the chaos module's own tokens: the macro a non-test
/// build compiles expands to the one token `false`, and each function of
/// [`MARKED`] holds `black_box(MARK)`.
fn home_violations(tokens: &[&str], functions: &[Function<'_>]) -> Vec<String> {
    let mut found = Vec::new();
    let head = [
        "cfg",
        "(",
        "not",
        "(",
        "test",
        ")",
        ")",
        "]",
        "macro_rules",
        "!",
        "chaos",
        "{",
    ];
    let arm = [
        "(", "$", "point", ":", "ident", ")", "=", ">", "{", "false", "}", ";", "}",
    ];
    let expands_to_false = tokens
        .windows(head.len())
        .position(|window| window == head)
        .is_some_and(|at| tokens[at + head.len()..].starts_with(&arm));
    if !expands_to_false {
        found.push(format!(
            "{HOME}: the non-test `chaos!` expands to other than `false`"
        ));
    }
    let reference = ["black_box", "(", "MARK", ")"];
    for name in MARKED {
        let marked = functions
            .iter()
            .filter(|function| function.owner.is_empty() && function.name == name)
            .any(|function| {
                tokens[function.body.clone()]
                    .windows(reference.len())
                    .any(|window| window == reference)
            });
        if !marked {
            found.push(format!("{HOME}: `{name}` holds no `black_box(MARK)`"));
        }
    }
    found
}

/// Whether the `cfg` predicate `predicate`, the tokens inside `cfg(..)`,
/// is false in every build without `test`: `test` itself, an `all` with
/// such an argument, or an `any` whose every argument is one, `any()`
/// included.
fn excludes_non_test(predicate: &[&str]) -> bool {
    match predicate {
        ["test"] => true,
        ["all", "(", inner @ .., ")"] => arguments(inner).into_iter().any(excludes_non_test),
        ["any", "(", inner @ .., ")"] => arguments(inner).into_iter().all(excludes_non_test),
        _ => false,
    }
}

/// `tokens` split at its commas outside parentheses, with empty pieces
/// dropped.
fn arguments<'t, 'a>(tokens: &'t [&'a str]) -> Vec<&'t [&'a str]> {
    let (mut out, mut level, mut start) = (Vec::new(), 0_usize, 0);
    for (i, &token) in tokens.iter().enumerate() {
        match token {
            "(" => level += 1,
            ")" => level = level.saturating_sub(1),
            "," if level == 0 => {
                out.push(&tokens[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&tokens[start..]);
    out.retain(|piece| !piece.is_empty());
    out
}

/// The position of the bracket that closes the one at `tokens[open]`,
/// counting parentheses, brackets and braces alike.
fn closing(tokens: &[&str], open: usize) -> usize {
    let mut level = 0_usize;
    for (i, &token) in tokens.iter().enumerate().skip(open) {
        match token {
            "(" | "[" | "{" => level += 1,
            ")" | "]" | "}" if level <= 1 => return i,
            ")" | "]" | "}" => level -= 1,
            _ => {}
        }
    }
    tokens.len()
}

/// The end, exclusive, of the item, statement, field, argument or
/// parameter that starts at `tokens[from]`, where `tokens` are slices of
/// `source`: after its first `;` outside brackets, its first `,` outside
/// brackets and generic arguments, or its first braced block outside
/// brackets together with any `else` blocks that follow it; or before the
/// `)`, `]`, `}` or `>` that closes the list or block holding it. A `<`
/// opens a generic argument list when it stands against a name or `::`,
/// as rustfmt writes one; rustfmt writes a comparison or shift between
/// spaces. A `>` immediately following the `>` that closed the range's
/// last open generic argument list closes the list holding the range. A
/// match arm's `=>` ends the lists its guard opened, and its
/// value opens none. The flag is set for a range that reaches its block's
/// end past an open `<`, which can hide the fields or arms after it. A
/// `where` clause with two bounds, or a turbofish of two arguments in an
/// arm's value, ends the range early, which reads test code as compiled;
/// a test-only last parameter of a closure ends it after the closure's
/// body.
fn item_end(source: &str, tokens: &[&str], from: usize) -> (usize, bool) {
    // Only `<` and `>` tokens are asked, and each is a slice of `source`.
    let before = |token: &str| {
        let at = token.as_ptr() as usize - source.as_ptr() as usize;
        source[..at].chars().next_back().unwrap_or(' ')
    };
    let (mut level, mut angle, mut arm) = (0_usize, 0_usize, false);
    // The position of the `>` that closed the range's last open generic
    // argument list.
    let mut shut = None;
    let mut i = from;
    while let Some(&token) = tokens.get(i) {
        let previous = tokens[i - 1];
        match token {
            "{" if level == 0 => {
                i = closing(tokens, i) + 1;
                if tokens.get(i) != Some(&"else") {
                    return (i, false);
                }
            }
            "(" | "[" | "{" => level += 1,
            ")" | "]" | "}" if level == 0 => return (i, angle > 0),
            ")" | "]" | "}" => level -= 1,
            ";" if level == 0 => return (i + 1, false),
            "," if level == 0 && angle == 0 => return (i + 1, false),
            "<" if level == 0 && !arm => {
                let glued = before(token);
                if glued.is_alphanumeric() || matches!(glued, '_' | ':') {
                    angle += 1;
                }
            }
            ">" if level == 0 && previous == "=" => (angle, arm) = (0, true),
            ">" if level == 0 && previous == "-" => {}
            ">" if level == 0 && angle > 0 => {
                angle -= 1;
                if angle == 0 {
                    shut = Some(i);
                }
            }
            ">" if level == 0 => {
                let glued = before(token);
                let closes = glued == '>' && shut == Some(i - 1);
                if closes || (!glued.is_whitespace() && !matches!(glued, '<' | '>')) {
                    return (i, false);
                }
            }
            _ => {}
        }
        i += 1;
    }
    (tokens.len(), angle > 0)
}

/// The token ranges of `tokens`, slices of `source`, that a build without
/// `test` leaves out: each item or statement under an outer `cfg`
/// attribute whose predicate [`excludes_non_test`], from its first
/// attribute to its end; and the count of those ranges that [`item_end`]
/// flags.
fn test_only(source: &str, tokens: &[&str]) -> (Vec<Range<usize>>, usize) {
    let attribute = |i: usize| tokens.get(i) == Some(&"#") && tokens.get(i + 1) == Some(&"[");
    let (mut out, mut open) = (Vec::new(), 0);
    let mut i = 0;
    while i < tokens.len() {
        if !attribute(i) {
            i += 1;
            continue;
        }
        let start = i;
        let mut excluded = false;
        while attribute(i) {
            // At least `i + 2`: the closing bracket, or the token count for
            // an attribute the file leaves unclosed.
            let close = closing(tokens, i + 1);
            if let ["cfg", "(", predicate @ .., ")"] = &tokens[i + 2..close] {
                excluded |= excludes_non_test(predicate);
            }
            i = close + 1;
        }
        if excluded {
            let (end, unclosed) = item_end(source, tokens, i);
            open += usize::from(unclosed);
            i = end;
            out.push(start..i);
        }
    }
    (out, open)
}

/// The text of the string literal that follows `token`, a slice of
/// `source`, when no other token stands between them but `=`, `!` and
/// `(`.
fn literal_after<'a>(source: &'a str, token: &str) -> Option<&'a str> {
    let after = token.as_ptr() as usize - source.as_ptr() as usize + token.len();
    let rest = source[after..].trim_start_matches(|c: char| c.is_whitespace() || "=!(".contains(c));
    let text = rest.strip_prefix('"')?;
    text.find('"').map(|end| &text[..end])
}

/// What the attributes of a `mod` declaration say of its file.
#[derive(Debug, PartialEq)]
enum ModulePath<'a> {
    /// No attribute names `path`.
    Default,
    /// A `path = "..."` attribute names this file.
    Literal(&'a str),
    /// An attribute names `path` in a form the walk leaves unread: a raw
    /// or computed value, or a `cfg_attr`.
    Unread,
}

/// The `path` attribute among the attributes of the `mod` at
/// `tokens[at]`, read past its visibility, `pub(in a::b)` included.
fn path_attribute<'a>(source: &'a str, tokens: &[&'a str], at: usize) -> ModulePath<'a> {
    // The opening bracket matched by the closer at `tokens[close]`.
    let opening = |close: usize, open: &str, shut: &str| {
        let mut level = 0_usize;
        (0..=close).rev().find(|&j| {
            if tokens[j] == shut {
                level += 1;
            } else if tokens[j] == open {
                level -= 1;
            }
            level == 0
        })
    };
    let mut i = at;
    if i > 0 && tokens[i - 1] == ")" {
        if let Some(open) = opening(i - 1, "(", ")")
            && open > 0
            && tokens[open - 1] == "pub"
        {
            i = open - 1;
        }
    } else if i > 0 && tokens[i - 1] == "pub" {
        i -= 1;
    }
    let mut found = ModulePath::Default;
    while i > 1 && tokens[i - 1] == "]" {
        let Some(open) = opening(i - 1, "[", "]").filter(|&open| open > 0) else {
            break;
        };
        if tokens[open - 1] != "#" {
            break;
        }
        if attribute_names_path(&tokens[open..i]) {
            let plain = tokens[open + 1..i] == ["path", "=", "\"\"", "]"];
            found = plain
                .then(|| literal_after(source, tokens[open + 1]))
                .flatten()
                .map_or(ModulePath::Unread, ModulePath::Literal);
        }
        i = open - 1;
    }
    found
}

/// `relative` resolved against `dir`, both `/`-separated paths relative
/// to the crate's `src`, with `.` and `..` segments applied; `None` for an
/// absolute path or one whose `..` leaves `src`.
fn resolved(dir: &str, relative: &str) -> Option<String> {
    if relative.starts_with('/') {
        return None;
    }
    let mut parts: Vec<&str> = dir.split('/').filter(|part| !part.is_empty()).collect();
    for part in relative.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            part => parts.push(part),
        }
    }
    Some(parts.join("/"))
}

/// The directory `name` inside `dir`, both relative to the crate's `src`.
fn child(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_owned()
    } else {
        format!("{dir}/{name}")
    }
}

fn parent(file: &str) -> &str {
    file.rsplit_once('/').map_or("", |(dir, _)| dir)
}

/// One file of the crate's non-test source and the token ranges of it
/// that a build without `test` leaves out.
struct Compiled<'a> {
    file: &'a str,
    source: &'a str,
    tokens: Vec<&'a str>,
    skipped: Vec<Range<usize>>,
}

/// A declaration's label, the directory that the file it names owns and
/// the files it can name, in order; or the finding for a declaration the
/// walk cannot resolve.
type Declaration = Result<(String, String, Vec<String>), String>;

/// The module declarations and `include!` calls of `unit` outside its
/// skipped ranges, in file order, with `owned` the directory the file
/// owns. A `path` attribute resolves against the file's directory at its
/// top level, and against the owned directory below the enclosing inline
/// modules inside one. Any other declaration resolves to `NAME.rs` or
/// `NAME/mod.rs` in the owned directory below the enclosing inline modules.
/// An `include!` names a file relative to the file's directory, and the
/// included file owns its own directory.
fn declarations(unit: &Compiled<'_>, owned: &str) -> Vec<Declaration> {
    let (file, tokens) = (unit.file, &unit.tokens);
    let mut out = Vec::new();
    let mut inline: Vec<(&str, usize)> = Vec::new();
    let mut depth = 0_usize;
    // `test_only` returns disjoint ranges in ascending order.
    let mut skipped = unit.skipped.iter().peekable();
    let mut i = 0;
    while i < tokens.len() {
        if let Some(range) = skipped.next_if(|range| range.start == i) {
            i = range.end;
            continue;
        }
        let below = || {
            inline
                .iter()
                .fold(owned.to_owned(), |dir, (name, _)| child(&dir, name))
        };
        let (next, after) = (tokens.get(i + 1).copied(), tokens.get(i + 2).copied());
        match (tokens[i], next, after) {
            ("mod", Some(name), Some(";")) => {
                let label = format!("module `{name}`");
                out.push(match path_attribute(unit.source, tokens, i) {
                    ModulePath::Default => {
                        let dir = child(&below(), name);
                        let candidates = vec![format!("{dir}.rs"), format!("{dir}/mod.rs")];
                        Ok((label, dir, candidates))
                    }
                    ModulePath::Literal(path) => {
                        let base = if inline.is_empty() {
                            parent(file).to_owned()
                        } else {
                            below()
                        };
                        match resolved(&base, path) {
                            Some(target) => Ok((label, parent(&target).to_owned(), vec![target])),
                            None => Err(format!("{file}: {label} names a path outside `src`")),
                        }
                    }
                    ModulePath::Unread => Err(format!(
                        "{file}: {label} names a `path` the walk does not read"
                    )),
                });
            }
            ("mod", Some(name), Some("{")) => {
                if path_attribute(unit.source, tokens, i) != ModulePath::Default {
                    out.push(Err(format!(
                        "{file}: inline module `{name}` names a `path` the walk does not read"
                    )));
                }
                inline.push((name, depth));
            }
            ("include", Some("!"), _) => {
                let included = literal_after(unit.source, tokens[i]).unwrap_or("");
                out.push(match resolved(parent(file), included) {
                    Some(target) => Ok((
                        "`include!`".to_owned(),
                        parent(&target).to_owned(),
                        vec![target],
                    )),
                    None => Err(format!("{file}: `include!` names a path outside `src`")),
                });
            }
            ("{", _, _) => depth += 1,
            ("}", _, _) => {
                depth = depth.saturating_sub(1);
                if inline.last().is_some_and(|&(_, at)| at == depth) {
                    inline.pop();
                }
            }
            _ => {}
        }
        i += 1;
    }
    out
}

/// The number of `path` assignments under a `[lib]` or `[[bin]]` header of
/// `manifest`. A header or key matches after its whitespace and quotes are
/// removed, so the count includes each `path` that `string_fields` reads
/// and each one written in another form: a literal or multi-line string,
/// a quoted key, or a header with whitespace or quotes.
fn target_paths(manifest: &str) -> usize {
    let spelled = |text: &str| -> String {
        text.chars()
            .filter(|c| !c.is_whitespace() && !matches!(c, '"' | '\''))
            .collect()
    };
    let mut inside = false;
    let mut count = 0;
    for line in manifest.lines().map(str::trim) {
        if line.starts_with('[') {
            let header = spelled(line.split('#').next().unwrap_or(""));
            inside = header == "[lib]" || header == "[[bin]]";
        } else if inside
            && line
                .split_once('=')
                .is_some_and(|(key, _)| spelled(key) == "path")
        {
            count += 1;
        }
    }
    count
}

/// The root files of the crate's targets in `sources`: the `[lib]` table's
/// `path` or `lib.rs`, `main.rs`, each `bin/NAME.rs` and `bin/NAME/main.rs`,
/// and each `[[bin]]` table's `path` in `manifest`, the crate's
/// `Cargo.toml`; a finding for each target path outside `sources`; and a
/// finding for the assignments [`target_paths`] counts beyond those
/// `string_fields` reads.
fn roots<'a>(sources: &BTreeMap<&'a str, &str>, manifest: &str) -> (Vec<&'a str>, Vec<String>) {
    let mut out: Vec<&str> = sources
        .keys()
        .copied()
        .filter(|file| {
            *file == "main.rs"
                || file.strip_prefix("bin/").is_some_and(|rest| {
                    !rest.contains('/')
                        || rest
                            .split_once('/')
                            .is_some_and(|(_, file)| file == "main.rs")
                })
        })
        .collect();
    let library = string_fields(manifest, "[lib]", "path");
    let binaries = string_fields(manifest, "[[bin]]", "path");
    let mut found = Vec::new();
    let unread = target_paths(manifest) - library.len() - binaries.len();
    if unread > 0 {
        found.push(format!(
            "Cargo.toml: {unread} target paths in a form the walk does not read"
        ));
    }
    let mut named = library;
    if named.is_empty() && sources.contains_key("lib.rs") {
        named.push("src/lib.rs");
    }
    named.extend(binaries);
    for path in named {
        let file = path.trim_start_matches("./").strip_prefix("src/");
        match file.and_then(|file| sources.get_key_value(file)) {
            Some((&file, _)) => out.push(file),
            None => found.push(format!(
                "Cargo.toml: target path {path}, which the walk does not read"
            )),
        }
    }
    (out, found)
}

/// The files of `files` that a build without `test` compiles, walked from
/// the roots that `manifest`, the crate's `Cargo.toml`, gives
/// ([`roots`]), and the walk's findings: a name two files share, a target
/// path outside `files`, a declaration that resolves to no file or that
/// the walk does not read, and a file whose skipped ranges reach their
/// block's end past an open `<`.
///
/// The walk follows each declaration outside the skipped ranges as Cargo
/// does ([`declarations`]), once for each pair of a file and the directory
/// it owns, so a file reached as two modules resolves the children of
/// each. `clients_closed_tests::binary_sources` walks the same
/// declarations for the binaries and refuses `path` and `include!`.
fn compiled<'a>(files: &'a [(String, String)], manifest: &str) -> (Vec<Compiled<'a>>, Vec<String>) {
    let mut sources: BTreeMap<&str, &str> = BTreeMap::new();
    let mut found = Vec::new();
    for (file, source) in files {
        if sources.insert(file, source).is_some() {
            found.push(format!("{file}: two sources share the name"));
        }
    }
    let (roots, refused) = roots(&sources, manifest);
    found.extend(refused);
    let mut pending: Vec<(&str, String)> = roots
        .into_iter()
        .map(|file| (file, parent(file).to_owned()))
        .collect();
    let mut units: BTreeMap<&str, Compiled<'a>> = BTreeMap::new();
    let mut walked = BTreeSet::new();
    while let Some((file, owned)) = pending.pop() {
        if !walked.insert((file, owned.clone())) {
            continue;
        }
        let unit = units.entry(file).or_insert_with(|| {
            let source = sources[file];
            let tokens = tokens(source);
            let (skipped, open) = test_only(source, &tokens);
            if open > 0 {
                found.push(format!(
                    "{file}: {open} skipped ranges reach their block's end past an open `<`"
                ));
            }
            Compiled {
                file,
                source,
                tokens,
                skipped,
            }
        });
        for declared in declarations(unit, &owned) {
            let finding = match declared {
                Ok((label, owns, candidates)) => match candidates
                    .iter()
                    .find_map(|target| sources.get_key_value(target.as_str()))
                {
                    Some((&target, _)) => {
                        pending.push((target, owns));
                        continue;
                    }
                    None => format!("{file}: {label} resolves to no file"),
                },
                Err(finding) => finding,
            };
            if !found.contains(&finding) {
                found.push(finding);
            }
        }
    }
    (units.into_values().collect(), found)
}

/// The findings over the nonblocking attempts of `files`, the crate's
/// source, with `manifest` its `Cargo.toml`: the walk's ([`compiled`]); a
/// call of an [`Attempt`] kind in a function that neither a row of
/// `catalog` with that kind nor a row of `declined` names; a row of either
/// whose function holds no call of its kind; a row of `declined` whose
/// file defines its function twice, that repeats another's attempt, or
/// that names a cataloged attempt; a row with an empty outcome; a declined
/// row with an empty reason; an admitted row whose point has no row of
/// `catalog` in its file, or that names the point of an earlier admitted
/// row; and more than [`ADMITTED_MAX`] admitted rows.
/// A call is any mention of a kind's method name: a method or path call,
/// a path or a bare name passed as a value, a closure called by that name,
/// or a name a macro receives and may write a call from. Three mentions
/// stand apart: the name a `fn` item declares, a name inside a `use`
/// item, and a path segment ahead of a `::` that opens a longer path
/// (a `::<` turbofish belongs to a call).
fn attempt_violations(
    files: &[(String, String)],
    manifest: &str,
    catalog: &[Row],
    declined: &[Candidate],
) -> Vec<String> {
    let (compiled, mut found) = compiled(files, manifest);
    let mut held: Vec<(&str, String, Attempt)> = Vec::new();
    let mut defined: Vec<(&str, String)> = Vec::new();
    for file in &compiled {
        let skipped = |i: usize| file.skipped.iter().any(|range| range.contains(&i));
        let functions = functions(file.source, &file.tokens);
        defined.extend(
            functions
                .iter()
                .filter(|function| !skipped(function.body.start))
                .map(|function| (file.file, function.qualified())),
        );
        let at = |i: usize| file.tokens.get(i).copied().unwrap_or("");
        for i in 1..file.tokens.len() {
            let Some(kind) = Attempt::ALL.into_iter().find(|kind| kind.method() == at(i)) else {
                continue;
            };
            let declared = at(i - 1) == "fn";
            let segment = at(i + 1) == "::" && at(i + 2) != "<";
            if declared || segment || skipped(i) || in_use(&file.tokens, i) {
                continue;
            }
            let Some(function) = enclosing(&functions, i).map(Function::qualified) else {
                let finding = format!(
                    "{}: `{}` stands outside every function, where no row names it",
                    file.file,
                    kind.method()
                );
                if !found.contains(&finding) {
                    found.push(finding);
                }
                continue;
            };
            if !held.contains(&(file.file, function.clone(), kind)) {
                held.push((file.file, function, kind));
            }
        }
    }
    let holds = |file: &str, function: &str, kind: Attempt| {
        held.iter()
            .any(|(at, name, made)| (*at, name.as_str(), *made) == (file, function, kind))
    };
    for (file, function, kind) in &held {
        let cataloged = catalog.iter().any(|row| {
            (row.file, row.function, row.attempt) == (*file, function.as_str(), Some(*kind))
        });
        let listed = declined
            .iter()
            .any(|row| (row.file, row.function, row.kind) == (*file, function.as_str(), *kind));
        if !cataloged && !listed {
            found.push(format!(
                "{file} {function}: `{}` is named by neither the catalog nor the declined table",
                kind.method()
            ));
        }
    }
    for row in catalog {
        if let Some(kind) = row.attempt
            && !holds(row.file, row.function, kind)
        {
            found.push(format!(
                "{} {}: the catalog row names a `{}` call the function does not hold",
                row.file,
                row.function,
                kind.method()
            ));
        }
    }
    for (at, row) in declined.iter().enumerate() {
        let key = (row.file, row.function, row.kind);
        if !holds(row.file, row.function, row.kind) {
            found.push(format!(
                "{} {}: the row names a `{}` call the function does not hold",
                row.file,
                row.function,
                row.kind.method()
            ));
        }
        let definitions = defined
            .iter()
            .filter(|(file, name)| (*file, name.as_str()) == (row.file, row.function))
            .count();
        if definitions > 1 {
            found.push(format!(
                "{} {}: the file defines the function {definitions} times",
                row.file, row.function
            ));
        }
        if declined[..at]
            .iter()
            .any(|other| (other.file, other.function, other.kind) == key)
        {
            found.push(format!(
                "{} {}: a second row names its `{}`",
                row.file,
                row.function,
                row.kind.method()
            ));
        }
        if catalog
            .iter()
            .any(|other| (other.file, other.function, other.attempt) == (key.0, key.1, Some(key.2)))
        {
            found.push(format!(
                "{} {}: a declined row names the catalog's `{}`",
                row.file,
                row.function,
                row.kind.method()
            ));
        }
        if row.outcome.trim().is_empty() {
            found.push(format!(
                "{} {}: a row with an empty outcome",
                row.file, row.function
            ));
        }
        if matches!(row.disposition, Disposition::Declined(reason) if reason.trim().is_empty()) {
            found.push(format!(
                "{} {}: a declined row with an empty reason",
                row.file, row.function
            ));
        }
        if let Disposition::Admitted(point) = row.disposition {
            if !catalog
                .iter()
                .any(|other| (other.point, other.file) == (point, row.file))
            {
                found.push(format!(
                    "{} {}: an admitted row whose point {point:?} has no catalog row in the file",
                    row.file, row.function
                ));
            }
            if declined[..at]
                .iter()
                .any(|other| other.disposition == row.disposition)
            {
                found.push(format!(
                    "{} {}: a second admitted row names {point:?}",
                    row.file, row.function
                ));
            }
        }
    }
    let admitted = declined
        .iter()
        .filter(|row| matches!(row.disposition, Disposition::Admitted(_)))
        .count();
    if admitted > ADMITTED_MAX {
        found.push(format!("{admitted} rows admitted, at most {ADMITTED_MAX}"));
    }
    found
}

fn crate_sources() -> Vec<(String, String)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    sources(&dir, &dir, &mut files);
    files
}

/// `files` with `file`'s contents replaced through `edit`, which must
/// change them, so a fixture whose anchor text is gone fails here.
fn edited(
    mut files: Vec<(String, String)>,
    file: &str,
    edit: impl FnOnce(&str) -> String,
) -> Vec<(String, String)> {
    let entry = files
        .iter_mut()
        .find(|(name, _)| name == file)
        .expect("a crate source");
    let changed = edit(&entry.1);
    assert_ne!(changed, entry.1, "the fixture edits {file}");
    entry.1 = changed;
    files
}

fn added(mut files: Vec<(String, String)>, file: &str, source: &str) -> Vec<(String, String)> {
    files.push((file.to_owned(), source.to_owned()));
    files
}

/// `source` with its first `from` after the first `after` replaced by `to`.
fn replaced_after(source: &str, after: &str, from: &str, to: &str) -> String {
    let (head, tail) = source.split_at(source.find(after).expect("the fixture's anchor"));
    format!("{head}{}", tail.replacen(from, to, 1))
}

#[test]
fn the_catalog_and_the_call_sites_agree() {
    let found = violations(&crate_sources());
    assert!(found.is_empty(), "{found:#?}");
}

/// Each fixture breaks one rule over the chaos module's file and the
/// files the catalog names, and the guard reports that rule's finding
/// alone. The whole-crate scan is `the_catalog_and_the_call_sites_agree`.
#[test]
fn each_fixture_fails_its_own_rule() {
    const GATE: &str = "storage/gate.rs";
    const CAPTURE: &str = "storage/capture.rs";
    const GATE_CALL: &str = "crate::sim::chaos::chaos!(GateBusy)";
    let files: Vec<(String, String)> = crate_sources()
        .into_iter()
        .filter(|(file, _)| file == HOME || CATALOG.iter().any(|row| row.file == file))
        .collect();
    assert_eq!(violations(&files), [""; 0]);
    let unknown = added(
        files.clone(),
        "storage/fixture.rs",
        "fn f() -> bool { crate::sim::chaos::chaos!(SlotBusy) }",
    );
    assert_eq!(
        violations(&unknown),
        ["storage/fixture.rs: `chaos!(SlotBusy)` names no catalog row"]
    );
    for call in [
        "crate::sim::chaos::chaos!(GateBusy)",
        "crate::sim::chaos::chaos![GateBusy]",
        "crate::sim::chaos::chaos!{GateBusy}",
    ] {
        let twice = added(
            files.clone(),
            "storage/gate_fixture.rs",
            &format!("fn f() -> bool {{ {call} }}"),
        );
        assert_eq!(
            violations(&twice),
            [
                r#"gate-busy: calls in ["storage/gate.rs Gate::try_lock", "storage/gate_fixture.rs f"], one in storage/gate.rs Gate::try_lock expected"#
            ],
            "{call}"
        );
    }
    let moved = added(
        edited(files.clone(), CAPTURE, |source| {
            source.replace("crate::sim::chaos::chaos!(CaptureBusy)", "false")
        }),
        "storage/publish_fixture.rs",
        "fn f() -> bool { crate::sim::chaos::chaos!(CaptureBusy) }",
    );
    assert_eq!(
        violations(&moved),
        [
            r#"capture-busy: calls in ["storage/publish_fixture.rs f"], one in storage/capture.rs Pool::capture_membership_lock expected"#
        ]
    );
    let elsewhere = edited(files.clone(), GATE, |source| {
        source
            .replace(
                "fn attempt(&self",
                &format!("fn is_held(&self) -> bool {{ {GATE_CALL} }}\n    fn attempt(&self"),
            )
            .replace(&format!("{GATE_CALL})"), "false)")
    });
    assert_eq!(
        violations(&elsewhere),
        [
            r#"gate-busy: calls in ["storage/gate.rs Gate::is_held"], one in storage/gate.rs Gate::try_lock expected"#
        ]
    );
    // `RootGate::try_lock` shares the method name and the file.
    let sibling = edited(files.clone(), GATE, |source| {
        source.replace(&format!("{GATE_CALL})"), "false)").replace(
            "let mut guard = self.0.try_lock()?;",
            &format!("let _ = {GATE_CALL};\n        let mut guard = self.0.try_lock()?;"),
        )
    });
    assert_eq!(
        violations(&sibling),
        [
            r#"gate-busy: calls in ["storage/gate.rs RootGate::try_lock"], one in storage/gate.rs Gate::try_lock expected"#
        ]
    );
    let through_trait = edited(files.clone(), GATE, |source| {
        format!(
            "{}\ntrait Probe {{ fn try_lock(&self) -> bool; }}\n\
             impl<W: GateWord> Probe for Gate<W> {{\n    fn try_lock(&self) -> bool {{ {GATE_CALL} }}\n}}\n",
            source.replace(&format!("{GATE_CALL})"), "false)")
        )
    });
    assert_eq!(
        violations(&through_trait),
        [
            r#"gate-busy: calls in ["storage/gate.rs Gate::try_lock (trait impl)"], one in storage/gate.rs Gate::try_lock expected"#
        ]
    );
    let nested = edited(files.clone(), GATE, |source| {
        format!(
            "{}\nmod inner {{\n    struct Gate;\n    impl Gate {{\n        \
             fn try_lock(&self) -> bool {{ {GATE_CALL} }}\n    }}\n}}\n",
            source.replace(&format!("{GATE_CALL})"), "false)")
        )
    });
    assert_eq!(
        violations(&nested),
        ["gate-busy: storage/gate.rs defines Gate::try_lock 2 times"]
    );
    let removed = edited(files.clone(), GATE, |source| {
        source.replace(GATE_CALL, "false")
    });
    assert_eq!(
        violations(&removed),
        ["gate-busy: calls in [], one in storage/gate.rs Gate::try_lock expected"]
    );
    // Each rewording changes the asking method's own copy of the text and
    // preserves the matching text in a sibling method's documentation.
    let unpermitted = edited(files.clone(), CAPTURE, |source| {
        assert!(source.matches("if another holder has the mutex").count() > 1);
        replaced_after(
            source,
            "One nonblocking try at the `capture` mutex for a membership change",
            "if another holder has the mutex",
            "if the mutex is busy",
        )
    });
    assert_eq!(
        violations(&unpermitted),
        [
            "capture-busy: the documentation of Pool::capture_membership_lock in \
             storage/capture.rs lacks the permitting text \
             ``GateError::Contended` if another holder has the mutex`"
        ]
    );
    let unpermitted = edited(files.clone(), GATE, |source| {
        assert!(source.matches("`Contended` if held elsewhere").count() > 1);
        source.replacen("`Contended` if held elsewhere", "`Contended` if busy", 1)
    });
    assert_eq!(
        violations(&unpermitted),
        [
            "gate-busy: the documentation of Gate::try_lock in storage/gate.rs \
             lacks the permitting text ``Contended` if held elsewhere`"
        ]
    );
    for (row, file) in [(&CATALOG[0], GATE), (&CATALOG[1], CAPTURE)] {
        let demoted = edited(files.clone(), file, |source| {
            let asking = functions(source, &tokens(source))
                .into_iter()
                .find(|function| function.qualified() == row.function)
                .expect("the row's method");
            let text = source[..asking.offset]
                .rfind(row.permits)
                .expect("the permitting text on one line");
            let line = source[..text].rfind("///").expect("a doc line");
            format!("{}//{}", &source[..line], &source[line + 3..])
        });
        assert_eq!(
            violations(&demoted),
            [format!(
                "{}: the documentation of {} in {} lacks the permitting text `{}`",
                row.name, row.function, row.file, row.permits
            )]
        );
    }
    let lost = Point::ExchangeLost.row();
    let unpermitted = edited(files.clone(), lost.file, |source| {
        source.replacen(
            "either count is nonzero is `Contended`",
            "either count is nonzero refuses",
            1,
        )
    });
    assert_eq!(
        violations(&unpermitted),
        [format!(
            "{}: the documentation of {} in {} lacks the permitting text `{}`",
            lost.name, lost.function, lost.file, lost.permits
        )]
    );
    for (named, finding) in [
        (
            "fn f() -> bool { crate::sim::chaos::fire(crate::sim::chaos::Point::GateBusy) }",
            "names `chaos::fire` by path",
        ),
        (
            "use crate::sim::chaos::{Point, fire};",
            "names `chaos::fire` by path",
        ),
        (
            "use crate::sim::chaos::{Point::{GateBusy}, fire};",
            "names `chaos::fire` by path",
        ),
        ("use crate::sim::chaos::*;", "imports `chaos` by glob"),
        (
            "use crate::sim::chaos::{Point::{GateBusy}, *};",
            "imports `chaos` by glob",
        ),
        ("use crate::sim::chaos as points;", "renames `chaos`"),
        (
            "use crate::sim::{chaos::{self as points}};",
            "renames `chaos`",
        ),
        ("use crate::sim::chaos::chaos as ask;", "renames `chaos`"),
        ("use crate::sim::chaos::{{*}};", "imports `chaos` by glob"),
        (
            "use crate::sim::chaos::{Census, {Point, *}};",
            "imports `chaos` by glob",
        ),
        ("use crate::sim::{other, chaos as c};", "renames `chaos`"),
    ] {
        let fired = added(files.clone(), "net/fixture.rs", named);
        assert_eq!(
            violations(&fired),
            [format!("net/fixture.rs: {finding}")],
            "{named}"
        );
    }
    for clean in [
        "fn f(p: P) -> u8 { g(1, p.chaos as u8) }",
        "use crate::sim::chaos::{Point::{self as P}};",
        "use crate::sim::chaos::{Point::{*}};",
    ] {
        let allowed = added(files.clone(), "net/fixture.rs", clean);
        assert_eq!(violations(&allowed), [""; 0], "{clean}");
    }
    let homeless: Vec<(String, String)> = files
        .iter()
        .filter(|(file, _)| file != HOME)
        .cloned()
        .collect();
    assert_eq!(violations(&homeless), ["sim/chaos.rs is missing"]);
    let unclosed = added(files.clone(), "net/fixture.rs", "fn f() { \"abc }");
    assert_eq!(
        violations(&unclosed),
        ["net/fixture.rs: <unterminated string>"]
    );
    let truthy = edited(files.clone(), HOME, |source| {
        replaced_after(source, "#[cfg(not(test))]\nmacro_rules!", "false", "true")
    });
    assert_eq!(
        violations(&truthy),
        ["sim/chaos.rs: the non-test `chaos!` expands to other than `false`"]
    );
    for name in MARKED {
        let unmarked = edited(files.clone(), HOME, |source| {
            replaced_after(
                source,
                &format!("pub(crate) fn {name}("),
                "std::hint::black_box(MARK);",
                "",
            )
        });
        assert_eq!(
            violations(&unmarked),
            [format!("sim/chaos.rs: `{name}` holds no `black_box(MARK)`")]
        );
    }
}

/// A single space separates text from consecutive comment lines.
#[test]
fn comment_line_breaks_join_before_the_permitting_text_is_compared() {
    let permits = CATALOG[1].permits;
    let wrapped = "/// `GateError::Contended` if another\n    /// holder has the mutex.\n    \
                   #[inline]\n    pub(super) fn f() {}\n";
    let offset = wrapped.find("fn f").unwrap();
    assert!(documented(wrapped, offset).contains(permits));
    let other = format!("{wrapped}\n/// Another\n/// function.\nfn g() {{}}\n");
    assert_eq!(
        documented(&other, other.find("fn g").unwrap()),
        "Another function."
    );
    let spanning = "/// First.\n// An ordinary comment.\n//// Four slashes.\n/// Second.\n\
                    #[expect(\n    clippy::x,\n    reason = \"y\"\n)]\nfn h() {}\n";
    assert_eq!(
        documented(spanning, spanning.find("fn h").unwrap()),
        "First. Second."
    );
    let parted = "/// Of the constant.\nconst A: [u8; 1] = [0];\nfn i() {}\n";
    assert_eq!(documented(parted, parted.find("fn i").unwrap()), "");
}

#[test]
fn a_function_is_named_behind_its_impl_type() {
    let source = "impl<W: GateWord> Gate<W> {\n    fn attempt(&self, refuse: impl FnOnce() -> bool) \
                  -> u8 { let f = || 1; f() }\n    fn declared(&self);\n}\n\
                  impl<W: GateWord> Drop for GateGuard<'_, W> { fn drop(&mut self) {} }\n\
                  fn free() -> impl Iterator<Item = u8> { fn inner() {} [1].into_iter() }\n\
                  fn sized(a: [u8; { 1 }]) -> u8 { let g = 2; g }\n";
    let tokens = tokens(source);
    let functions = functions(source, &tokens);
    let names: Vec<String> = functions.iter().map(Function::qualified).collect();
    assert_eq!(
        names,
        [
            "Gate::attempt",
            "GateGuard::drop (trait impl)",
            "free",
            "inner",
            "sized"
        ]
    );
    let local = tokens.iter().position(|&token| token == "g").unwrap();
    assert_eq!(
        enclosing(&functions, local).map(Function::qualified),
        Some("sized".to_owned())
    );
    let closure = tokens.iter().position(|&token| token == "f").unwrap();
    assert_eq!(
        enclosing(&functions, closure).map(Function::qualified),
        Some("Gate::attempt".to_owned())
    );
    assert!(source[functions[0].offset..].starts_with("fn attempt"));
}

/// Reversing the scan needle in `tests/soak_cli.rs` yields the catalog's
/// mark, and the scan's test holds its code once, from the needle's
/// reversal through the census of the binaries to the loop that refuses
/// one holding the catalog's mark or the control mark. A copy of the scan with one step commented out,
/// a forward needle, a loop over part of the list or a binary skipped
/// fails this guard. This reads the code's shape; the scan's own run reads
/// the binaries.
#[test]
fn the_scans_search_for_the_mark() {
    let scan =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/soak_cli.rs"))
            .unwrap();
    let prefix = "const REVERSED_MARK: &str = \"";
    assert_eq!(scan.matches(prefix).count(), 1);
    let start = scan.find(prefix).expect("the scan's needle") + prefix.len();
    let text = &scan[start..start + scan[start..].find('"').unwrap()];
    assert_eq!(text, super::chaos::tests::REVERSED_MARK);
    assert!(searches_for_the_mark(&scan));
    let refusal = "            assert!(\n                memchr::memmem::find(&bytes, needle.as_bytes()).is_none(),\n";
    let control = "            assert!(\n                memchr::memmem::find(&bytes, control.as_bytes()).is_none(),\n";
    let census = "        assert_eq!(\n            sources, names,\n";
    let manifest = "            !declares_bin(&manifest)\n";
    let list = "        let scanned = [\n";
    let each = "        for binary in scanned {\n";
    for (step, line) in [
        ("the refusal", refusal),
        ("the control refusal", control),
        ("the census", census),
        ("the manifest check", manifest),
    ] {
        assert_eq!(scan.matches(line).count(), 1, "{step}");
        let indent = &line[..line.len() - line.trim_start().len()];
        let commented = scan.replace(line, &format!("{indent}// {}", line.trim_start()));
        assert!(!searches_for_the_mark(&commented), "a scan without {step}");
    }
    for (change, from, to) in [
        (
            "a forward needle",
            "REVERSED_MARK.chars().rev()",
            "REVERSED_MARK.chars()",
        ),
        (
            "a loop over part of the list",
            each,
            "        let scanned = &scanned[1..];\n        for binary in scanned {\n",
        ),
        (
            "a binary skipped",
            each,
            "        for binary in scanned.into_iter().skip(1) {\n",
        ),
        (
            "a census of another list",
            list,
            "        let scanned = [env!(\"CARGO_BIN_EXE_kestrike-bind\")];\n        let listed = [\n",
        ),
    ] {
        assert_eq!(scan.matches(from).count(), 1, "{change}");
        assert!(!searches_for_the_mark(&scan.replace(from, to)), "{change}");
    }
}

/// Whether the code tokens of `scan` hold the scan's test once, whole: the
/// reversals of the needle and the control needle and their checks, the
/// three binaries, their census against the sources under `src/bin` and
/// the manifest, and the loop that reads each binary whole and refuses it
/// when it holds the catalog's mark or the control mark.
fn searches_for_the_mark(scan: &str) -> bool {
    let code = tokens(scan).concat();
    let reversed = "#[test]fnno_binary_holds_a_chaos_point(){\
                    letneedle:String=REVERSED_MARK.chars().rev().collect();\
                    letcontrol:String=REVERSED_CONTROL_MARK.chars().rev().collect();\
                    assert!(needle.starts_with(\"\")&&needle.ends_with(\"\"),\"\");\
                    assert!(control.starts_with(\"\")&&control.ends_with(\"\"),\"\");";
    let census = "letscanned=[env!(\"\"),env!(\"\"),env!(\"\"),];\
                  letnames:Vec<String>=scanned.iter().map(|binary|name_of(Path::new(binary))).collect();\
                  letsources=bin_sources(Path::new(concat!(env!(\"\"),\"\"))).unwrap();\
                  letmanifest=fs::read_to_string(concat!(env!(\"\"),\"\")).unwrap();\
                  assert!(!declares_bin(&manifest)&&!Path::new(concat!(env!(\"\"),\"\")).exists(),\"\");\
                  assert_eq!(sources,names,\"\");";
    let body = "forbinaryinscanned{letbytes=artifact(Path::new(binary)).unwrap();\
                assert!(memchr::memmem::find(&bytes,needle.as_bytes()).is_none(),\"\");\
                assert!(memchr::memmem::find(&bytes,control.as_bytes()).is_none(),\"\");}";
    let whole = [reversed, census, body, "}"].concat();
    code.matches(&whole).count() == 1 && code.matches(body).count() == 1
}

/// The survey admits one row, the credit words' exchange, for the
/// `exchange-lost` point; every other row is declined.
#[test]
fn the_declined_table_admits_the_credit_exchange_alone() {
    let admitted: Vec<_> = DECLINED
        .iter()
        .filter_map(|row| match row.disposition {
            Disposition::Admitted(point) => Some((row.function, row.file, row.kind, point)),
            Disposition::Declined(_) => None,
        })
        .collect();
    assert_eq!(
        admitted,
        [(
            "AtomicUsize::exchange_weak (trait impl)",
            "storage/lease.rs",
            Attempt::CompareExchangeWeak,
            Point::ExchangeLost
        )]
    );
}

#[test]
fn every_attempt_is_cataloged_or_declined() {
    let manifest =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")).unwrap();
    let found = attempt_violations(&crate_sources(), &manifest, &CATALOG, &DECLINED);
    assert!(found.is_empty(), "{found:#?}");
}

/// The gate file of the attempt guard's small crate: one cataloged
/// function and one declined one.
const ATTEMPT_GATE: &str = "impl<W> Gate<W> {
    fn try_lock(&self) -> u8 { self.0.try_lock() }
    fn attempt(&self) -> bool { self.0.compare_exchange(0, 1, A, B).is_ok() }
}
";

/// A small crate: `lib.rs`, `storage/mod.rs` declaring `gate` and then
/// `declared`, [`ATTEMPT_GATE`], and the `extra` files.
fn attempt_crate(declared: &str, extra: &[(&str, &str)]) -> Vec<(String, String)> {
    let files = vec![
        ("lib.rs".to_owned(), "pub mod storage;\n".to_owned()),
        (
            "storage/mod.rs".to_owned(),
            format!("mod gate;\n{declared}\n"),
        ),
        ("storage/gate.rs".to_owned(), ATTEMPT_GATE.to_owned()),
    ];
    extra
        .iter()
        .fold(files, |files, (file, source)| added(files, file, source))
}

/// Each fixture breaks one rule of the attempt guard over a small crate,
/// and the guard reports that rule's finding alone. A call under a `cfg`
/// that no build without `test` compiles, or in a file only such a
/// declaration reaches, lies outside the guarded source, and the skipped
/// range ends where its item, statement, arm, field, argument or parameter
/// ends; a target root and a declaration resolve as Cargo resolves them.
#[test]
fn each_attempt_fixture_fails_its_own_rule() {
    const PROBE: &str = "fn probe(word: &W) -> bool { word.compare_exchange(0, 1, A, B).is_ok() }";
    const UNNAMED: &str =
        "probe: `compare_exchange` is named by neither the catalog nor the declined table";
    const TRY_LOCK: &str =
        "probe: `try_lock` is named by neither the catalog nor the declined table";
    let unnamed = |file: &str| format!("{file} {UNNAMED}");
    let catalog = [Row {
        function: "Gate::try_lock",
        file: "storage/gate.rs",
        attempt: Some(Attempt::TryLock),
        ..CATALOG[0]
    }];
    let rows = [Candidate {
        function: "Gate::attempt",
        file: "storage/gate.rs",
        kind: Attempt::CompareExchange,
        outcome: "`Contended`",
        disposition: Disposition::Declined("retries"),
    }];
    let small = || attempt_crate("", &[]);
    let guarded = |files: &[(String, String)]| attempt_violations(files, "", &catalog, &rows);
    let inline = |declared: &str| guarded(&attempt_crate(declared, &[]));
    let built = |manifest: &str, files: &[(String, String)]| {
        attempt_violations(files, manifest, &catalog, &rows)
    };
    assert_eq!(guarded(&small()), [""; 0]);
    let unlisted_gate = "storage/gate.rs Gate::try_lock: `try_lock` is named by neither the \
                         catalog nor the declined table";
    assert_eq!(
        attempt_violations(&small(), "", &[], &rows),
        [unlisted_gate]
    );
    let kindless = [Row {
        attempt: None,
        ..catalog[0]
    }];
    assert_eq!(
        attempt_violations(&small(), "", &kindless, &rows),
        [unlisted_gate]
    );
    let stale = [
        Row { ..catalog[0] },
        Row {
            function: "Gate::open",
            ..catalog[0]
        },
    ];
    assert_eq!(
        attempt_violations(&small(), "", &stale, &rows),
        [
            "storage/gate.rs Gate::open: the catalog row names a `try_lock` call the function \
          does not hold"
        ]
    );
    let probed = |declared: &str| attempt_crate(declared, &[("storage/probe.rs", PROBE)]);
    assert_eq!(
        guarded(&probed("mod probe;")),
        [unnamed("storage/probe.rs")]
    );
    for skipped in [
        "#[cfg(test)]",
        "#[cfg(all(loom, test))]",
        "#[cfg(any())]",
        "#[cfg(test)]\n#[cfg(unix)]",
    ] {
        assert_eq!(guarded(&probed(&format!("{skipped}\nmod probe;"))), [""; 0]);
        assert_eq!(inline(&format!("{skipped}\n{PROBE}")), [""; 0], "{skipped}");
    }
    for compiled in ["#[cfg(any(test, loom))]", "#[cfg(not(test))]"] {
        let found = inline(&format!("{compiled}\n{PROBE}"));
        assert_eq!(found, [unnamed("storage/mod.rs")], "{compiled}");
    }
    // A production call after each skipped form stays guarded.
    let call = "word.compare_exchange(0, 1, A, B).is_ok()";
    for after in [
        format!("#[cfg(test)]\nfn t(x: &X) -> u8 {{ x.try_lock() }}\n{PROBE}"),
        format!("#[cfg(test)]\nfn t(x: [X; 2]) -> u8 {{ x[0].try_lock() }}\n{PROBE}"),
        format!(
            "fn probe(word: &W) -> bool {{\n    #[cfg(test)]\n    if a < b {{ x.try_lock() }} \
             else {{ y.try_lock() }}\n    {call}\n}}"
        ),
        format!(
            "fn probe(word: &W) -> bool {{\n    #[cfg(test)]\n    let _ = x.try_lock();\n    \
             {call}\n}}"
        ),
        format!(
            "fn probe(word: &W, n: u8) -> bool {{\n    match n {{\n        #[cfg(test)]\n        \
             k if k < 3 => x.try_lock(),\n        _ => {call},\n    }}\n}}"
        ),
        format!(
            "fn probe(word: &W) -> S {{\n    S {{\n        #[cfg(test)]\n        a: Foo::<A, \
             B>::new(x.try_lock()),\n        b: {call},\n    }}\n}}"
        ),
        format!("fn probe(word: &W, #[cfg(test)] n: u8) -> bool {{ {call} }}"),
        format!("fn probe(word: &W) -> bool {{ [true, #[cfg(test)] false][0] && {call} }}"),
        format!("fn probe<A, #[cfg(test)] B>(word: &W) -> bool {{ {call} }}"),
        // The bound of a skipped last generic parameter and the parameter
        // list end in adjacent `>` tokens: the guard skips the parameter
        // alone and reads the function's body.
        format!("fn probe<#[cfg(test)] B: AsRef<str>>(word: &W) -> bool {{ {call} }}"),
        format!("fn probe<A, #[cfg(test)] B: Into<Vec<u8>>>(word: &W) -> bool {{ {call} }}"),
    ] {
        assert_eq!(inline(&after), [unnamed("storage/mod.rs")], "{after}");
    }
    // A comparison or shift in a skipped field ends the field at its comma.
    for (skipped, later) in [
        ("a: n < 3", "c: n > 1"),
        ("a: n < 3", "c: T { d: 0 }"),
        ("a: n << 3", "c: n >> 1"),
        // A shift after a closed generic argument list stays an operator.
        ("a: n as Wide<u8> >> y.try_lock()", "c: n > 1"),
    ] {
        let fields = format!(
            "fn probe(word: &W, n: u8) -> S {{\n    S {{\n        #[cfg(test)]\n        \
             {skipped},\n        b: {call},\n        {later},\n    }}\n}}"
        );
        assert_eq!(inline(&fields), [unnamed("storage/mod.rs")], "{fields}");
    }
    for skipped in ["0 => n < 3", "0 => n<3", "k if k<3 => x.try_lock()"] {
        let arm = format!(
            "fn probe(word: &W, n: u8) -> bool {{\n    match n {{\n        #[cfg(test)]\n        \
             {skipped},\n        _ => {call},\n    }}\n}}"
        );
        assert_eq!(inline(&arm), [unnamed("storage/mod.rs")], "{arm}");
    }
    let swallowing = format!(
        "fn probe(word: &W, n: u8) -> S {{\n    S {{\n        #[cfg(test)]\n        \
         a: n<3,\n        b: {call},\n    }}\n}}"
    );
    assert_eq!(
        inline(&swallowing),
        ["storage/mod.rs: 1 skipped ranges reach their block's end past an open `<`"]
    );
    for unclosed in ["#[", "#[cfg(test)]\nfn t() {"] {
        assert_eq!(inline(unclosed), [""; 0], "{unclosed}");
    }
    for (declared, file) in [
        (
            "#[path = \"other.rs\"]\npub(crate) mod probe;",
            "storage/other.rs",
        ),
        (
            "#[path = \"other.rs\"]\npub(in crate::storage) mod probe;",
            "storage/other.rs",
        ),
        ("#[path = \"other.rs\"]\npub mod probe;", "storage/other.rs"),
        (
            "#[path = \"other.rs\"]\n#[allow(dead_code)]\nmod probe;",
            "storage/other.rs",
        ),
        ("#[path = \"../other.rs\"] mod probe;", "other.rs"),
        ("mod probe;", "storage/probe/mod.rs"),
        ("mod inner {\n    mod probe;\n}", "storage/inner/probe.rs"),
        // Closing `f`'s body keeps `inner` as the module that holds `probe`.
        (
            "mod inner {\n    fn f() {}\n    mod probe;\n}",
            "storage/inner/probe.rs",
        ),
        (
            "mod inner {\n    #[path = \"x.rs\"]\n    mod probe;\n}",
            "storage/inner/x.rs",
        ),
        ("include!(\"other.rs\");", "storage/other.rs"),
    ] {
        // A redirected declaration's default file stands beside its target.
        let default = if declared.contains("path") {
            "storage/probe.rs"
        } else {
            "storage/unused.rs"
        };
        let files = attempt_crate(declared, &[(file, PROBE), (default, "")]);
        assert_eq!(guarded(&files), [unnamed(file)], "{declared}");
    }
    for (declared, finding) in [
        (
            "#[cfg_attr(not(test), path = \"other.rs\")]\nmod probe;",
            "module `probe` names a `path` the walk does not read",
        ),
        (
            "#[path = r\"other.rs\"]\nmod probe;",
            "module `probe` names a `path` the walk does not read",
        ),
        (
            "#[path = \"x\"]\nmod inner {}",
            "inline module `inner` names a `path` the walk does not read",
        ),
        (
            "#[path = \"../../src/other.rs\"]\nmod probe;",
            "module `probe` names a path outside `src`",
        ),
        (
            "#[path = \"/src/other.rs\"]\nmod probe;",
            "module `probe` names a path outside `src`",
        ),
        (
            "include!(\"../../src/other.rs\");",
            "`include!` names a path outside `src`",
        ),
    ] {
        let files = attempt_crate(
            declared,
            &[
                ("storage/probe.rs", ""),
                ("storage/other.rs", PROBE),
                ("other.rs", PROBE),
                ("src/other.rs", PROBE),
            ],
        );
        assert_eq!(
            guarded(&files),
            [format!("storage/mod.rs: {finding}")],
            "{declared}"
        );
    }
    let nested = edited(
        attempt_crate("", &[("storage/gate/probe.rs", PROBE)]),
        "storage/gate.rs",
        |source| format!("{source}mod probe;\n"),
    );
    assert_eq!(guarded(&nested), [unnamed("storage/gate/probe.rs")]);
    // A `path` attribute resolves against the directory of the file that
    // declares it, which for `storage/gate.rs` is `storage`.
    let beside = edited(
        attempt_crate("", &[("storage/x.rs", PROBE), ("storage/gate/x.rs", "")]),
        "storage/gate.rs",
        |source| format!("{source}#[path = \"x.rs\"]\nmod probe;\n"),
    );
    assert_eq!(guarded(&beside), [unnamed("storage/x.rs")]);
    // A skipped last field ends before the brace that closes its literal,
    // so the inline module around it closes where it does.
    let last = attempt_crate(
        "mod inner {\n    fn f() -> S { S { a: 1, #[cfg(test)] b: 2 } }\n}\nmod probe;",
        &[("storage/probe.rs", PROBE)],
    );
    assert_eq!(guarded(&last), [unnamed("storage/probe.rs")]);
    let included = edited(
        attempt_crate(
            "",
            &[
                ("storage/inc.rs", "mod probe;\n"),
                ("storage/probe.rs", PROBE),
                ("storage/gate/probe.rs", PROBE),
            ],
        ),
        "storage/gate.rs",
        |source| format!("{source}include!(\"inc.rs\");\n"),
    );
    assert_eq!(guarded(&included), [unnamed("storage/probe.rs")]);
    for declared in [
        "mod probe;\n#[path = \"probe.rs\"]\nmod alias;",
        "#[path = \"probe.rs\"]\nmod alias;\nmod probe;",
    ] {
        let files = attempt_crate(
            declared,
            &[
                ("storage/probe.rs", "mod child;\n"),
                ("storage/probe/child.rs", PROBE),
                ("storage/child.rs", PROBE),
            ],
        );
        let mut found = guarded(&files);
        found.sort();
        assert_eq!(
            found,
            [
                unnamed("storage/child.rs"),
                unnamed("storage/probe/child.rs")
            ],
            "{declared}"
        );
    }
    assert_eq!(
        inline("mod absent;"),
        ["storage/mod.rs: module `absent` resolves to no file"]
    );
    for include in [
        "include!(\"absent.rs\");",
        "include!(concat!(\"a\", \".rs\"));",
    ] {
        assert_eq!(
            inline(include),
            ["storage/mod.rs: `include!` resolves to no file"],
            "{include}"
        );
    }
    assert_eq!(
        guarded(&added(small(), "storage/gate.rs", ATTEMPT_GATE)),
        ["storage/gate.rs: two sources share the name"]
    );
    for (call, kind) in [
        ("[m].iter().map(Mutex::try_lock).count()", "try_lock"),
        ("rx.try_recv::<u8>().is_ok()", "try_recv"),
        ("f(Mutex::try_lock, 1)", "try_lock"),
        ("[Mutex::try_lock].len() > 0", "try_lock"),
        ("S { f: Mutex::try_lock }.ok()", "try_lock"),
        ("(Mutex::try_lock as fn(&M) -> R)(m).is_ok()", "try_lock"),
        ("Mutex::try_lock(m).is_ok()", "try_lock"),
        (
            "m.compare_exchange_weak(0, 1, A, B).is_ok()",
            "compare_exchange_weak",
        ),
        // A macro may write a call from a method name it receives.
        ("poll!(m, try_lock)", "try_lock"),
        ("poll!(try_recv => rx)", "try_recv"),
        // A closure called by a listed name.
        ("{ let try_lock = || m.lock(); try_lock() }", "try_lock"),
    ] {
        assert_eq!(
            inline(&format!("fn probe(m: &M, rx: &R) -> bool {{ {call} }}")),
            [format!(
                "storage/mod.rs probe: `{kind}` is named by neither the catalog nor the \
                 declined table"
            )],
            "{call}"
        );
    }
    // A parameter named for a kind belongs to the function that declares it.
    for (call, kind) in [
        (
            "fn probe(mut try_lock: impl FnMut() -> bool) -> bool { m.lock() }",
            "try_lock",
        ),
        (
            "fn probe<F: Fn() -> bool>(try_recv: F) -> bool { rx.recv() }",
            "try_recv",
        ),
    ] {
        assert_eq!(
            inline(call),
            [format!(
                "storage/mod.rs probe: `{kind}` is named by neither the catalog nor the \
                 declined table"
            )],
            "{call}"
        );
    }
    assert_eq!(
        inline("fn probe(m: &M) { let f = Mutex::try_lock; }"),
        [format!("storage/mod.rs {TRY_LOCK}")]
    );
    // A call after a `use` item and one after a `use<..>` capture bound.
    for after_use in [
        "use a::b;\nfn probe(m: &M) -> bool { m.try_lock().is_ok() }",
        "fn probe<'a>(m: &'a M) -> impl Sized + use<'a> { m.try_lock() }",
    ] {
        assert_eq!(
            inline(after_use),
            [format!("storage/mod.rs {TRY_LOCK}")],
            "{after_use}"
        );
    }
    for unlisted in [
        "use a::{b::try_lock, c};",
        "use a::try_lock as b;",
        "use crate::try_recv::Reply;",
        "fn probe() { crate::try_lock::metrics(); }",
        "trait Probe { fn try_lock(&self) -> u8; }",
    ] {
        assert_eq!(inline(unlisted), [""; 0], "{unlisted}");
    }
    // A row names its function in its own file: the same functions in a
    // second file are named by neither table.
    let twin = attempt_crate("mod twin;", &[("storage/twin.rs", ATTEMPT_GATE)]);
    assert_eq!(
        guarded(&twin),
        [
            "storage/twin.rs Gate::try_lock: `try_lock` is named by neither the catalog nor the \
          declined table",
            "storage/twin.rs Gate::attempt: `compare_exchange` is named by neither the catalog \
          nor the declined table"
        ]
    );
    // A call in a nested function belongs to the nested function.
    let nested_fn = edited(small(), "storage/gate.rs", |source| {
        source.replace(
            "{ self.0.compare_exchange(0, 1, A, B).is_ok() }",
            "{ fn inner(rx: &R) -> bool { rx.try_recv().is_ok() } \
             self.0.compare_exchange(0, 1, A, B).is_ok() }",
        )
    });
    assert_eq!(
        guarded(&nested_fn),
        [
            "storage/gate.rs inner: `try_recv` is named by neither the catalog nor the declined \
          table"
        ]
    );
    let second_kind = edited(small(), "storage/gate.rs", |source| {
        source.replace(".is_ok() }", ".is_ok() && rx.try_recv().is_ok() }")
    });
    assert_eq!(
        guarded(&second_kind),
        [
            "storage/gate.rs Gate::attempt: `try_recv` is named by neither the catalog nor the \
          declined table"
        ]
    );
    let cataloged_second = edited(small(), "storage/gate.rs", |source| {
        source.replace(
            "{ self.0.try_lock() }",
            "{ rx.try_recv(); self.0.try_lock() }",
        )
    });
    assert_eq!(
        guarded(&cataloged_second),
        [
            "storage/gate.rs Gate::try_lock: `try_recv` is named by neither the catalog nor the \
          declined table"
        ]
    );
    // Target roots.
    for root in ["main.rs", "bin/tool.rs", "bin/tool/main.rs"] {
        assert_eq!(
            guarded(&added(small(), root, PROBE)),
            [unnamed(root)],
            "{root}"
        );
    }
    assert_eq!(
        guarded(&added(small(), "bin/tool/fixtures/main.rs", PROBE)),
        [""; 0]
    );
    let tool = added(small(), "tools/tool.rs", PROBE);
    assert_eq!(
        built(
            "[[bin]]\nname = \"tool\"\npath = \"src/tools/tool.rs\"\n",
            &tool
        ),
        [unnamed("tools/tool.rs")]
    );
    assert_eq!(
        built(
            "[[bin]]\nname = \"tool\"\npath = \"./tools/tool.rs\"\n",
            &tool
        ),
        ["Cargo.toml: target path ./tools/tool.rs, which the walk does not read"]
    );
    // The redirected library root leaves the gate file unreached, so the
    // fixture's tables are empty.
    assert_eq!(
        attempt_violations(
            &added(small(), "other.rs", PROBE),
            "[lib]\npath = \"src/other.rs\"\n",
            &[],
            &[]
        ),
        [unnamed("other.rs")]
    );
    for manifest in [
        "[lib]\npath = 'src/other.rs'\n",
        "[[bin]]\nname = \"tool\"\npath = 'src/other.rs'\n",
        "[ lib ]\npath = \"src/other.rs\"\n",
        "[\"lib\"]\npath = \"src/other.rs\"\n",
        "[lib]\n\"path\" = \"src/other.rs\"\n",
    ] {
        assert_eq!(
            built(manifest, &added(small(), "other.rs", PROBE)),
            ["Cargo.toml: 1 target paths in a form the walk does not read"],
            "{manifest}"
        );
    }
    assert_eq!(
        built(
            "[[test]]\nname = \"sim_worker\"\npath = \"src/worker.rs\"\n",
            &added(small(), "worker.rs", PROBE)
        ),
        [""; 0]
    );
    let outside = attempt_crate(
        "fn poll(x: &X) -> u8 { include!(\"poll.rs\") }",
        &[("storage/poll.rs", "x.try_lock()")],
    );
    let stands = "storage/poll.rs: `try_lock` stands outside every function, where no row names it";
    assert_eq!(guarded(&outside), [stands]);
    let nameless = Candidate {
        function: "",
        file: "storage/poll.rs",
        kind: Attempt::TryLock,
        ..rows[0]
    };
    assert_eq!(
        attempt_violations(&outside, "", &catalog, &[rows[0], nameless]),
        [
            stands,
            "storage/poll.rs : the row names a `try_lock` call the function does not hold"
        ]
    );
    let with = |row: Candidate| attempt_violations(&small(), "", &catalog, &[row]);
    let beside = |row: Candidate| attempt_violations(&small(), "", &catalog, &[rows[0], row]);
    assert_eq!(
        beside(Candidate {
            function: "Gate::open",
            ..rows[0]
        }),
        [
            "storage/gate.rs Gate::open: the row names a `compare_exchange` call the function \
          does not hold"
        ]
    );
    assert_eq!(
        beside(Candidate {
            kind: Attempt::TryLock,
            ..rows[0]
        }),
        [
            "storage/gate.rs Gate::attempt: the row names a `try_lock` call the function does \
          not hold"
        ]
    );
    assert_eq!(
        beside(Candidate {
            file: "storage/other.rs",
            ..rows[0]
        }),
        [
            "storage/other.rs Gate::attempt: the row names a `compare_exchange` call the \
          function does not hold"
        ]
    );
    for second in [
        rows[0],
        Candidate {
            disposition: Disposition::Admitted(Point::GateBusy),
            ..rows[0]
        },
    ] {
        assert_eq!(
            beside(second),
            ["storage/gate.rs Gate::attempt: a second row names its `compare_exchange`"]
        );
    }
    assert_eq!(
        beside(Candidate {
            function: "Gate::try_lock",
            kind: Attempt::TryLock,
            ..rows[0]
        }),
        ["storage/gate.rs Gate::try_lock: a declined row names the catalog's `try_lock`"]
    );
    let namesake = edited(small(), "storage/gate.rs", |source| {
        format!(
            "{source}mod inner {{\n    impl<W> Gate<W> {{\n        fn attempt(&self) -> bool \
             {{ self.0.compare_exchange(0, 1, A, B).is_ok() }}\n    }}\n}}\n"
        )
    });
    assert_eq!(
        guarded(&namesake),
        ["storage/gate.rs Gate::attempt: the file defines the function 2 times"]
    );
    let test_namesake = edited(small(), "storage/gate.rs", |source| {
        format!(
            "{source}#[cfg(test)]\nmod tests {{\n    impl<W> Gate<W> {{\n        \
             fn attempt(&self) -> bool {{ true }}\n    }}\n}}\n"
        )
    });
    assert_eq!(guarded(&test_namesake), [""; 0]);
    let twice = edited(small(), "storage/gate.rs", |source| {
        source.replace(
            ".is_ok() }",
            ".is_ok() && self.0.compare_exchange(1, 0, A, B).is_ok() }",
        )
    });
    assert_eq!(guarded(&twice), [""; 0]);
    assert_eq!(
        with(Candidate {
            outcome: " ",
            ..rows[0]
        }),
        ["storage/gate.rs Gate::attempt: a row with an empty outcome"]
    );
    assert_eq!(
        with(Candidate {
            disposition: Disposition::Declined(" "),
            ..rows[0]
        }),
        ["storage/gate.rs Gate::attempt: a declined row with an empty reason"]
    );
    // Four functions of one file, each with its own row; three admitted
    // rows pass, and a fourth is refused.
    let many = attempt_crate(
        "mod many;",
        &[(
            "storage/many.rs",
            "fn a(w: &W) -> bool { w.compare_exchange(0, 1, A, B).is_ok() }\n\
             fn b(w: &W) -> bool { w.compare_exchange(0, 1, A, B).is_ok() }\n\
             fn c(w: &W) -> bool { w.compare_exchange(0, 1, A, B).is_ok() }\n\
             fn d(w: &W) -> bool { w.compare_exchange(0, 1, A, B).is_ok() }\n",
        )],
    );
    let admitted = |function: &'static str, point: Option<Point>| Candidate {
        function,
        file: "storage/many.rs",
        disposition: point.map_or(rows[0].disposition, Disposition::Admitted),
        ..rows[0]
    };
    let three = [
        rows[0],
        admitted("a", Some(Point::GateBusy)),
        admitted("b", Some(Point::CaptureBusy)),
        admitted("c", Some(Point::ExchangeLost)),
        admitted("d", None),
    ];
    // Each admitted row's point has its catalog row in the row's file.
    let at = |point: Point, function: &'static str| Row {
        point,
        function,
        file: "storage/many.rs",
        attempt: None,
        ..CATALOG[0]
    };
    let pointed = [
        Row { ..catalog[0] },
        at(Point::GateBusy, "a"),
        at(Point::CaptureBusy, "b"),
        at(Point::ExchangeLost, "c"),
    ];
    assert_eq!(attempt_violations(&many, "", &pointed, &three), [""; 0]);
    let alone = |point: Point| {
        [
            three[0],
            admitted("a", Some(point)),
            admitted("b", None),
            admitted("c", None),
            three[4],
        ]
    };
    assert_eq!(
        attempt_violations(&many, "", &catalog, &alone(Point::GateBusy)),
        ["storage/many.rs a: an admitted row whose point GateBusy has no catalog row in the file"]
    );
    let gate_only = [Row { ..catalog[0] }, at(Point::GateBusy, "a")];
    assert_eq!(
        attempt_violations(&many, "", &gate_only, &alone(Point::GateBusy)),
        [""; 0]
    );
    assert_eq!(
        attempt_violations(&many, "", &gate_only, &alone(Point::CaptureBusy)),
        [
            "storage/many.rs a: an admitted row whose point CaptureBusy has no catalog row in the file"
        ]
    );
    let twice = [
        three[0],
        three[1],
        admitted("b", Some(Point::GateBusy)),
        admitted("c", None),
        three[4],
    ];
    assert_eq!(
        attempt_violations(&many, "", &pointed, &twice),
        ["storage/many.rs b: a second admitted row names GateBusy"]
    );
    // Three points admit at most three rows, so a fourth names a point
    // again.
    let four = [
        three[0],
        three[1],
        three[2],
        three[3],
        admitted("d", Some(Point::GateBusy)),
    ];
    assert_eq!(
        attempt_violations(&many, "", &pointed, &four),
        [
            "storage/many.rs d: a second admitted row names GateBusy",
            "4 rows admitted, at most 3"
        ]
    );
}
