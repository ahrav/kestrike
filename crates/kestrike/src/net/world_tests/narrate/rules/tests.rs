//! The rule catalog against the crate's sources: every violation a check
//! can raise names a cataloged text, every cataloged text is one a check
//! raises, and the scan fails closed on a sink whose rule it cannot
//! resolve and on each spelling `scan` names that would hide a sink.
//! Lookup selects a text by its full hash, then checks the recorded
//! length and prefix.

use std::collections::BTreeSet;
use std::path::Path;

use sha2::{Digest, Sha256};

use super::{
    CLUSTER, CLUSTER_SHARED, HISTORY_SHARED, ORACLE, WORLD, listing, resolve, scoped, texts,
};

/// A source file: its path under `src/` and its text, with its test items
/// blanked, as [`blank_tests`] and [`blank_unnamed`] do.
struct Source {
    path: String,
    text: String,
}

/// How a rule a scanned site forwards reaches it, for a site whose rule is
/// neither written there nor a parameter of its helper.
enum Forward {
    /// The site re-raises a rule another scanned producer raised, or one a
    /// history or reduction catalog declares from them.
    Raised,
    /// The rule is one the named function of the same file returns: every
    /// text and constant written in its body.
    Returns(&'static str),
}

/// Every forwarding site: its file, enclosing function and argument.
const FORWARDS: [(&str, &str, &str, Forward); 14] = [
    (
        "net/world_tests/histories/restarts.rs",
        "judge_recovered",
        "rule",
        Forward::Raised,
    ),
    (
        "net/world_tests/histories/warm_loads.rs",
        "judged",
        "rule",
        Forward::Raised,
    ),
    (
        "net/world_tests/histories/silent_owners.rs",
        "judge_result",
        "rule",
        Forward::Raised,
    ),
    (
        "net/world_tests/histories/incidents/unknowns.rs",
        "u3_judge",
        "rule",
        Forward::Raised,
    ),
    (
        "net/world_tests/histories/incidents.rs",
        "judge_record",
        "rule",
        Forward::Raised,
    ),
    (
        "net/world_tests/bundle.rs",
        "judge_recovery",
        "rule",
        Forward::Raised,
    ),
    (
        "net/world_tests/histories.rs",
        "failure",
        "rule",
        Forward::Raised,
    ),
    (
        "net/world_tests/histories.rs",
        "ends_as_declared",
        "rule",
        Forward::Raised,
    ),
    (
        "net/world_tests/histories.rs",
        "misread_failed",
        "rule",
        Forward::Raised,
    ),
    (
        "net/world_tests/replay.rs",
        "conditions",
        "rule",
        Forward::Raised,
    ),
    ("net/world_tests/schedule.rs", "of", "rule", Forward::Raised),
    (
        "net/world_tests/cluster.rs",
        "collected",
        "rule",
        Forward::Returns("binding_rule"),
    ),
    (
        "net/world_tests/cluster.rs",
        "check",
        "rule",
        Forward::Returns("binding_rule"),
    ),
    (
        "net/world_tests/cluster.rs",
        "take_acknowledgments",
        "rule",
        Forward::Returns("binding_rule"),
    ),
];

/// Every crate source file outside `tests.rs` files and `tests/`
/// directories, with its comments, its test items and the items only they
/// name blanked, read once per process: a file named `*_tests.rs` can hold
/// harness code a recorded world runs.
fn sources() -> &'static [Source] {
    static SOURCES: std::sync::LazyLock<Vec<Source>> = std::sync::LazyLock::new(read_sources);
    &SOURCES
}

fn read_sources() -> Vec<Source> {
    fn walk(dir: &Path, root: &Path, out: &mut Vec<Source>) {
        let mut paths: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        paths.sort();
        for path in paths {
            if path.is_dir() {
                walk(&path, root, out);
                continue;
            }
            let rel = path
                .strip_prefix(root)
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned();
            let test = rel.ends_with("/tests.rs") || rel.contains("/tests/");
            if rel.ends_with(".rs") && !test {
                let text = blank_comments(&std::fs::read_to_string(&path).unwrap());
                let text = blank_tests(&text);
                out.push(Source { path: rel, text });
            }
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut out = Vec::new();
    walk(&root, &root, &mut out);
    blank_unnamed(&mut out);
    out
}

/// `range` of `bytes` replaced by spaces, newlines kept.
fn blank(bytes: &mut [u8], range: std::ops::RangeInclusive<usize>) {
    for byte in &mut bytes[range] {
        if *byte != b'\n' {
            *byte = b' ';
        }
    }
}

/// `text` with its line comments blanked, its literals kept.
fn blank_comments(text: &str) -> String {
    let mut bytes = text.as_bytes().to_vec();
    let mut at = 0;
    while at < text.len() {
        let end = skip(text.as_bytes(), at);
        if text.as_bytes()[at] == b'/' && end > at {
            blank(&mut bytes, at..=end);
        }
        at = end + 1;
    }
    String::from_utf8(bytes).unwrap()
}

/// `text` with every function a `#[test]` alone on its line marks blanked,
/// at any indentation, inside inline modules included. The rest of an
/// inline `#[cfg(test)]` module stays, so a helper a recorded world calls
/// there is scanned like any other. The function's body opens at the first
/// `{` after the `#[test]` that lies outside a literal, so a brace in the
/// string of a later attribute opens none.
fn blank_tests(text: &str) -> String {
    let mut bytes = text.as_bytes().to_vec();
    for (at, _) in text.match_indices("#[test]") {
        let line = text[..at].rfind('\n').map_or(0, |start| start + 1);
        if !text[line..at].trim().is_empty() {
            continue;
        }
        let mut open = at;
        while text.as_bytes()[open] != b'{' {
            open = skip(text.as_bytes(), open) + 1;
        }
        blank(&mut bytes, at..=close(text, open));
    }
    String::from_utf8(bytes).unwrap()
}

/// Each source path's module, as a `/`-separated path with a trailing
/// `/`: empty for the crate root, `src/mod.rs` included; a `#[path]` file
/// under the module its declaration names; else the file's own path, a
/// `mod.rs` file its directory's.
fn modules(sources: &[Source]) -> std::collections::HashMap<String, String> {
    let mut declared = std::collections::HashMap::new();
    for source in sources {
        let dir = source.path.rsplit_once('/').map_or("", |(dir, _)| dir);
        for (at, attribute) in source.text.match_indices("#[path = \"") {
            let rest = &source.text[at + attribute.len()..];
            let (Some(end), Some(item)) = (rest.find('"'), rest.find("mod ")) else {
                continue;
            };
            let target = match dir {
                "" => rest[..end].to_owned(),
                dir => format!("{dir}/{}", &rest[..end]),
            };
            let name: String = rest[item + 4..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            declared.insert(target, (source.path.clone(), name));
        }
    }
    fn of(path: &str, declared: &std::collections::HashMap<String, (String, String)>) -> String {
        if matches!(path, "lib.rs" | "main.rs" | "mod.rs") {
            return String::new();
        }
        if let Some((parent, name)) = declared.get(path) {
            return format!("{}{name}/", of(parent, declared));
        }
        let module = path
            .strip_suffix("/mod.rs")
            .unwrap_or(path.trim_end_matches(".rs"));
        format!("{module}/")
    }
    let paths = sources.iter().map(|source| &source.path);
    paths
        .map(|path| (path.clone(), of(path, &declared)))
        .collect()
}

/// Each private `fn`, `static` or `const` item `text` declares at its top
/// level or inside an inline `mod` block: its name and byte range. Items
/// inside `impl`, `trait` and function bodies are left out, so a trait
/// method a caller reaches through its trait stays.
fn items(text: &str) -> Vec<(String, std::ops::RangeInclusive<usize>)> {
    let bytes = text.as_bytes();
    let (mut out, mut blocks, mut start, mut at) = (Vec::new(), vec![true], 0, 0);
    while at < bytes.len() {
        at = skip(bytes, at);
        match bytes[at] {
            b'{' => {
                let module = text[start..at].split_whitespace().any(|word| word == "mod");
                blocks.push(module && blocks.last() == Some(&true));
                start = at + 1;
            }
            b'}' => {
                blocks.pop();
                start = at + 1;
            }
            b';' => start = at + 1,
            _ if blocks.last() == Some(&true) && (at == 0 || bytes[at - 1] == b'\n') => {
                let line = text[at..].trim_start_matches([' ', '\t']);
                let item = text.len() - line.len();
                let kind = ["fn ", "static ", "const "]
                    .into_iter()
                    .find(|kind| line.starts_with(kind));
                if let Some(kind) = kind {
                    let name: String = line[kind.len()..]
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                        .collect();
                    let end = if kind == "fn " {
                        close(text, item + line.find('{').unwrap())
                    } else {
                        item + item_end_at(text, item, b';')
                    };
                    out.push((name, item..=end));
                }
            }
            _ => {}
        }
        at += 1;
    }
    out
}

/// `sources` with every private item, as [`items`] finds them, that the
/// code of its module and the module's descendants, the only code a
/// private item is visible to, names only at its definition blanked,
/// repeatedly, so a fixture only blanked tests use, and the helpers only
/// it uses, leave the scan. A name that code repeats, in a literal
/// included, keeps its item.
fn blank_unnamed(sources: &mut [Source]) {
    type Uses = std::collections::HashMap<String, usize>;
    let modules = modules(sources);
    let modules: Vec<&String> = sources
        .iter()
        .map(|source| &modules[&source.path])
        .collect();
    let within: Vec<Vec<usize>> = modules
        .iter()
        .map(|module| {
            let inside = |other: &usize| modules[*other].starts_with(module.as_str());
            (0..modules.len()).filter(inside).collect()
        })
        .collect();
    let words = |source: &Source| {
        let mut uses = Uses::new();
        let words = source
            .text
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_');
        for word in words.filter(|word| !word.is_empty()) {
            *uses.entry(word.to_owned()).or_default() += 1;
        }
        uses
    };
    let mut uses: Vec<Uses> = sources.iter().map(words).collect();
    loop {
        let mut touched = BTreeSet::new();
        for index in 0..sources.len() {
            let named = |name: &str| {
                let count = |other: &usize| uses[*other].get(name).copied().unwrap_or(0);
                within[index].iter().map(count).sum::<usize>()
            };
            let unnamed: Vec<_> = items(&sources[index].text)
                .into_iter()
                .filter(|(name, _)| named(name) == 1)
                .collect();
            if unnamed.is_empty() {
                continue;
            }
            let mut bytes = std::mem::take(&mut sources[index].text).into_bytes();
            for (_, range) in unnamed {
                blank(&mut bytes, range);
            }
            sources[index].text = String::from_utf8(bytes).unwrap();
            touched.insert(index);
        }
        if touched.is_empty() {
            return;
        }
        for index in touched {
            uses[index] = words(&sources[index]);
        }
    }
}

/// The end of the string, character literal, lifetime or line comment that
/// starts at `at` in `text`, or `at` itself for any other byte.
fn skip(text: &[u8], at: usize) -> usize {
    match text[at] {
        b'"' => {
            let mut end = at + 1;
            while text[end] != b'"' {
                end += if text[end] == b'\\' { 2 } else { 1 };
            }
            end
        }
        b'\'' if text.get(at + 1) == Some(&b'\\') => {
            at + 2 + text[at + 2..].iter().position(|&b| b == b'\'').unwrap()
        }
        b'\'' if text.get(at + 2) == Some(&b'\'') => at + 2,
        b'/' if text.get(at + 1) == Some(&b'/') => {
            at + text[at..]
                .iter()
                .position(|&b| b == b'\n')
                .unwrap_or(text.len() - at - 1)
        }
        _ => at,
    }
}

/// The offset of the bracket that closes the one at `open`.
fn close(text: &str, open: usize) -> usize {
    let bytes = text.as_bytes();
    let (mut depth, mut at) = (0, open);
    loop {
        at = skip(bytes, at);
        match bytes[at] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                depth -= 1;
                if depth == 0 {
                    return at;
                }
            }
            _ => {}
        }
        at += 1;
    }
}

/// `text` split at its top-level commas, each part trimmed; with `angles`,
/// a comma inside `<..>` is not top level.
fn split(text: &str, angles: bool) -> Vec<&str> {
    let bytes = text.as_bytes();
    let (mut parts, mut start, mut depth, mut at) = (Vec::new(), 0, 0i32, 0);
    while at < bytes.len() {
        at = skip(bytes, at);
        match bytes[at] {
            b'(' | b'[' | b'{' => depth += 1,
            b'<' if angles => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b'>' if angles && bytes[at - 1] != b'-' => depth -= 1,
            b',' if depth == 0 => {
                parts.push(text[start..at].trim());
                start = at + 1;
            }
            _ => {}
        }
        at += 1;
    }
    parts.push(text[start..].trim());
    parts.retain(|part| !part.is_empty());
    parts
}

/// The text of the string literal `literal`.
fn unescape(literal: &str) -> String {
    let mut out = String::new();
    let mut rest = &literal[1..literal.len() - 1];
    while let Some(at) = rest.find('\\') {
        out.push_str(&rest[..at]);
        let next = rest[at + 1..].chars().next().unwrap();
        rest = &rest[at + 1 + next.len_utf8()..];
        match next {
            '\n' => rest = rest.trim_start(),
            'n' => out.push('\n'),
            other => out.push(other),
        }
    }
    out.push_str(rest);
    out
}

/// Whether `word` is a constant's name.
fn constant(word: &str) -> bool {
    word.len() > 1
        && word
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

/// Whether `word` is a lowercase identifier.
fn identifier(word: &str) -> bool {
    !word.is_empty()
        && word
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// The scan: the texts it resolved, its helpers, and each site it could
/// not resolve.
#[derive(Default)]
struct Scan {
    rules: BTreeSet<String>,
    /// Each helper's module group, name, parameter index and whether it is
    /// a method.
    helpers: BTreeSet<(String, String, usize, bool)>,
    /// The [`FORWARDS`] entries a site used.
    forwarded: BTreeSet<usize>,
    /// Each source path's module, as [`modules`] names it.
    modules: std::collections::HashMap<String, String>,
    failures: Vec<String>,
}

impl Scan {
    /// The string constant `name` names from `path`: the one `path`
    /// declares, else the only one any source declares.
    fn constant(&mut self, sources: &[Source], path: &str, name: &str, site: &str) {
        let declared = format!("const {name}: &");
        let mut found = Vec::new();
        for source in sources {
            let mut from = 0;
            while let Some(at) = source.text[from..].find(&declared) {
                let at = from + at;
                from = at + 1;
                let value = source.text[at..].split_once('=').unwrap().1.trim_start();
                if value.starts_with('"') {
                    let end = skip(value.as_bytes(), 0);
                    found.push((source.path == path, unescape(&value[..=end])));
                }
            }
        }
        let own: Vec<_> = found.iter().filter(|(own, _)| *own).collect();
        match (own.as_slice(), found.as_slice()) {
            ([(_, text)], _) | ([], [(_, text)]) => {
                self.rules.insert(text.clone());
            }
            ([], []) => self
                .failures
                .push(format!("{site}: no string constant {name}")),
            _ => self
                .failures
                .push(format!("{site}: {name} names two constants")),
        }
    }

    /// Resolves `arg`, the rule a sink at `pos` in `source` raises.
    fn argument(&mut self, sources: &[Source], source: &Source, pos: usize, arg: &str) {
        let line = source.text[..pos].matches('\n').count() + 1;
        let site = format!("{}:{line}: {arg:?}", source.path);
        let arg = arg.trim();
        if arg.starts_with('"') && skip(arg.as_bytes(), 0) == arg.len() - 1 {
            self.rules.insert(unescape(arg));
            return;
        }
        if constant(arg) {
            return self.constant(sources, &source.path, arg, &site);
        }
        if let Some(condition) = arg.strip_prefix("if ") {
            return self.branches(sources, source, pos, condition, &site);
        }
        if !identifier(arg) {
            return self
                .failures
                .push(format!("{site}: unsupported expression"));
        }
        let text = &source.text;
        let group = self.modules[&source.path].clone();
        let Some((name, params, method, at, body)) = enclosing(text, pos) else {
            return self
                .failures
                .push(format!("{site}: outside every function"));
        };
        if let Some((bound, init, index)) = binding(text, body, pos, arg) {
            return self.bound(sources, source, bound, (init, index), &site);
        }
        if let Some((name, params)) = closure(text, body, pos)
            && let Some(index) = params.iter().position(|param| param == arg)
        {
            self.helpers.insert((group, name, index, false));
            return;
        }
        if let Some(index) = params.iter().position(|param| param == arg) {
            let line = text[..at].rsplit('\n').next().unwrap();
            if line.trim_start().starts_with("pub") {
                let reason = "a visible helper, whose callers outside its module go unscanned";
                return self.failures.push(format!("{site}: {name} is {reason}"));
            }
            self.helpers.insert((group, name, index, method));
            return;
        }
        let forward = FORWARDS.iter().position(|(path, function, ident, _)| {
            *path == source.path && *function == name && *ident == arg
        });
        if let Some(at) = forward {
            self.forwarded.insert(at);
        }
        match forward.map(|at| &FORWARDS[at].3) {
            Some(Forward::Raised) => {}
            Some(Forward::Returns(function)) => {
                let Some((open, body)) = body_of(&source.text, function) else {
                    return self
                        .failures
                        .push(format!("{site}: no function {function}"));
                };
                self.returned(sources, source, open, body, &site);
            }
            None => self.failures.push(format!("{site}: unresolved in {name}")),
        }
    }

    /// Resolves each rule the forwarded function `body`, at `open` in
    /// `source`, returns: the argument of each `Some(..)` and
    /// `then_some(..)` in it, each through [`Scan::argument`]. A body that
    /// returns none fails.
    fn returned(
        &mut self,
        sources: &[Source],
        source: &Source,
        open: usize,
        body: &str,
        site: &str,
    ) {
        let mut any = false;
        for wrapper in ["Some(", "then_some("] {
            for (at, _) in body.match_indices(wrapper) {
                let before = body.as_bytes()[..at].last().copied().unwrap_or(b' ');
                if wrapper == "Some(" && (before.is_ascii_alphanumeric() || before == b'_') {
                    continue;
                }
                let paren = at + wrapper.len() - 1;
                let value = &body[paren + 1..close(body, paren)];
                self.argument(sources, source, open + paren, value);
                any = true;
            }
        }
        if !any {
            self.failures
                .push(format!("{site}: the forwarded function returns no rule"));
        }
    }

    /// Resolves the rule a `let` at `at` binds: its `if` initializer as an
    /// argument, and each arm of its `match` initializer, the component
    /// `index` of each arm's tuple when the pattern is a tuple, skipping
    /// arms that leave the function or loop. Every other form fails.
    fn bound(
        &mut self,
        sources: &[Source],
        source: &Source,
        at: usize,
        (init, index): (&str, Option<usize>),
        site: &str,
    ) {
        if init.starts_with("if ") && index.is_none() {
            return self.argument(sources, source, at, init);
        }
        let Some(arms) = init.strip_prefix("match ").and_then(|_| arms(init)) else {
            return self.failures.push(format!("{site}: unsupported binding"));
        };
        for arm in arms {
            let word: String = arm
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '!')
                .collect();
            let diverges = ["return", "continue", "break", "panic!", "unreachable!"];
            if diverges.contains(&word.as_str()) {
                continue;
            }
            let value = match index {
                None => Some(arm),
                Some(index) => arm
                    .strip_prefix('(')
                    .and_then(|tuple| tuple.strip_suffix(')'))
                    .and_then(|tuple| split(tuple, false).get(index).copied()),
            };
            match value {
                Some(value) => self.argument(sources, source, at, value),
                None => self
                    .failures
                    .push(format!("{site}: an arm {arm:?} binds no rule")),
            }
        }
    }

    /// Resolves each branch of `if CONDITION { A } else { B }`, an
    /// argument text after its `if`.
    fn branches(
        &mut self,
        sources: &[Source],
        source: &Source,
        pos: usize,
        text: &str,
        site: &str,
    ) {
        let Some(open) = text.find('{') else {
            return self
                .failures
                .push(format!("{site}: unsupported expression"));
        };
        let end = close(text, open);
        self.argument(sources, source, pos, &text[open + 1..end]);
        let rest = text[end + 1..].trim_start();
        match rest.strip_prefix("else") {
            Some(other) => {
                let other = other.trim();
                let other = other
                    .strip_prefix('{')
                    .and_then(|inner| inner.strip_suffix('}'))
                    .unwrap_or(other);
                self.argument(sources, source, pos, other);
            }
            None => self.failures.push(format!("{site}: an if without else")),
        }
    }
}

/// Whether `text` from `from` to `to` stays inside the block open at
/// `from`: no bracket closes below it.
fn in_scope(text: &str, from: usize, to: usize) -> bool {
    let bytes = text.as_bytes();
    let (mut depth, mut at) = (0i32, from);
    while at < to {
        at = skip(bytes, at);
        match bytes[at] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            _ => {}
        }
        if depth < 0 {
            return false;
        }
        at += 1;
    }
    true
}

/// The name and parameter names of the innermost closure bound by
/// `let NAME = |..|` after `body` whose body holds `pos` in `text`.
fn closure(text: &str, body: usize, pos: usize) -> Option<(String, Vec<String>)> {
    let mut end = pos;
    while let Some(at) = text[body..end].rfind("= |") {
        let at = body + at;
        end = at;
        let name = text[..at].trim_end().rsplit(' ').next()?.to_owned();
        let bar = at + 3 + text[at + 3..].find('|')?;
        let rest = text[bar + 1..].trim_start();
        let start = text.len() - rest.len();
        let close = match rest.find('{') {
            Some(open) if rest.starts_with('{') || rest.starts_with("->") => {
                close(text, start + open)
            }
            _ => start + item_end_at(rest, 0, b';'),
        };
        if close < pos || !in_scope(text, at, pos) {
            continue;
        }
        let names = text[at + 3..bar]
            .split(',')
            .map(|param| param.split(':').next().unwrap().trim().to_owned())
            .collect();
        return Some((name, names));
    }
    None
}

/// The innermost function definition whose body holds `pos` in `text`:
/// its name, parameter names, whether it takes `self`, the offset of its
/// `fn` and that of its body's opening brace.
fn enclosing(text: &str, pos: usize) -> Option<(String, Vec<String>, bool, usize, usize)> {
    let bytes = text.as_bytes();
    let mut end = pos;
    while let Some(at) = text[..end].rfind("fn ") {
        end = at;
        let line = &text[text[..at].rfind('\n').map_or(0, |at| at + 1)..at];
        if at > 0 && (bytes[at - 1].is_ascii_alphanumeric() || bytes[at - 1] == b'_')
            || line.contains("//")
        {
            continue;
        }
        let rest = &text[at + 3..];
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        let Some(open) = rest.find('(').map(|open| at + 3 + open) else {
            continue;
        };
        let params = close(text, open);
        let Some(body) = text[params..].find(['{', ';']).map(|body| params + body) else {
            continue;
        };
        if bytes[body] == b';' || close(text, body) < pos {
            continue;
        }
        let mut names: Vec<String> = split(&text[open + 1..params], true)
            .into_iter()
            .map(|param| {
                let name = param.split(':').next().unwrap().trim();
                name.trim_start_matches("mut ").to_owned()
            })
            .collect();
        let method = names.first().is_some_and(|first| first.ends_with("self"));
        if method {
            names.remove(0);
        }
        return Some((name, names, method, at, body));
    }
    None
}

/// The nearest `let` after `body` and before `pos` in `text` that binds
/// `name`, alone or in a tuple, in a block still open at `pos`: its
/// offset, its initializer and the name's index in a tuple pattern.
fn binding<'s>(
    text: &'s str,
    body: usize,
    pos: usize,
    name: &str,
) -> Option<(usize, &'s str, Option<usize>)> {
    let mut from = pos;
    while let Some(at) = text[body..from].rfind("let ") {
        let at = body + at;
        from = at;
        let (pattern, _) = text[at + 4..pos].split_once(" = ")?;
        let index = match pattern.strip_prefix('(').and_then(|p| p.strip_suffix(')')) {
            Some(tuple) => split(tuple, false).iter().position(|part| *part == name),
            None => (pattern == name).then_some(0),
        };
        let Some(index) = index else {
            continue;
        };
        if !in_scope(text, at, pos) {
            continue;
        }
        let start = at + 4 + pattern.len() + 3;
        let init = &text[start..start + item_end_at(text, start, b';')];
        let tuple = pattern.starts_with('(');
        return Some((at, init, tuple.then_some(index)));
    }
    None
}

/// The result expression of each arm of the `match` expression `text`,
/// a block's tail for an arm whose result is a block; `None` when an arm
/// has no `=>`.
fn arms(text: &str) -> Option<Vec<&str>> {
    let open = text.find('{')?;
    let inner = &text[open + 1..close(text, open)];
    let bytes = inner.as_bytes();
    let (mut out, mut at) = (Vec::new(), 0);
    while !inner[at..].trim().is_empty() {
        let arrow = at + arrow(&inner[at..])?;
        let rest = inner[arrow + 2..].trim_start();
        let start = inner.len() - rest.len();
        let end = if rest.starts_with('{') {
            let end = close(inner, start);
            let block = inner[start + 1..end].trim();
            let tail = split_statements(block).pop().unwrap_or_default();
            out.push(tail);
            end + 1
        } else {
            let end = start + item_end_at(inner, start, b',');
            out.push(inner[start..end].trim());
            end + 1
        };
        at = end.min(bytes.len());
        if inner[at..].starts_with(',') {
            at += 1;
        }
    }
    Some(out)
}

/// The offset of the first `=>` outside every bracket and literal in
/// `text`.
fn arrow(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let (mut depth, mut at) = (0i32, 0);
    while at + 1 < bytes.len() {
        at = skip(bytes, at);
        match bytes[at] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b'=' if depth == 0 && bytes.get(at + 1) == Some(&b'>') => return Some(at),
            _ => {}
        }
        at += 1;
    }
    None
}

/// The offset, from `from`, of the first `stop` byte outside every bracket
/// and literal in `text`, or of its end.
fn item_end_at(text: &str, from: usize, stop: u8) -> usize {
    let bytes = text.as_bytes();
    let (mut depth, mut at) = (0i32, from);
    while at < bytes.len() {
        at = skip(bytes, at);
        match bytes[at] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            byte if byte == stop && depth == 0 => return at - from,
            _ => {}
        }
        at += 1;
    }
    bytes.len() - from
}

/// The statements of the block body `text`, split at its top-level `;`,
/// each trimmed, its tail expression last.
fn split_statements(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < text.len() {
        let end = at + item_end_at(text, at, b';');
        let part = text[at..end].trim();
        if !part.is_empty() {
            out.push(part);
        }
        at = end + 1;
    }
    out
}

/// The offset and body of the function `name` in `text`.
fn body_of<'s>(text: &'s str, name: &str) -> Option<(usize, &'s str)> {
    let at = text.find(&format!("fn {name}("))?;
    let open = at + text[at..].find('{')?;
    Some((open, &text[open..=close(text, open)]))
}

/// Whether the parenthesis closing at `end` ends a pattern: a match arm,
/// an alternative or a `let` pattern, rather than an expression.
fn pattern(text: &str, end: usize) -> bool {
    let rest = text[end + 1..].trim_start_matches([')', ' ', '\n']);
    let alternative = rest.starts_with('|') && !rest.starts_with("||");
    rest.starts_with("=>") || alternative || rest.starts_with("= ")
}

/// The offset of the first non-whitespace byte at or after `at` in
/// `text`.
fn past_space(text: &str, at: usize) -> usize {
    at + text[at..].len() - text[at..].trim_start().len()
}

/// Scans `sources` for the violations they can raise. A sink is
/// `Failure::Violation(..)` or a `Violation { .. }` literal, whitespace
/// before the bracket allowed. The scan fails on a `Failure::Violation` it
/// does not see called, a `use` that imports `Failure`'s variants or renames
/// `Failure`, a `type` alias of it, and a helper passed as a value or called
/// by path. It reads no macro expansion and no other alias of the type.
fn scan(sources: &[Source]) -> Scan {
    let mut scan = Scan {
        modules: modules(sources),
        ..Scan::default()
    };
    for source in sources {
        let text = &source.text;
        let line = |at: usize| text[..at].matches('\n').count() + 1;
        let edge =
            |byte: Option<&u8>| byte.is_none_or(|b| !b.is_ascii_alphanumeric() && *b != b'_');
        let bounded = |at: usize| edge(text.as_bytes().get(at.wrapping_sub(1)));
        for spelling in ["Failure::{", "Failure::*", "Failure as ", "= Failure;"] {
            for (at, _) in text.match_indices(spelling).filter(|(at, _)| bounded(*at)) {
                let site = format!("{}:{}", source.path, line(at));
                scan.failures
                    .push(format!("{site}: imports or renames Failure's variants"));
            }
        }
        for (at, word) in text.match_indices("Failure::Violation") {
            if !bounded(at) || !edge(text.as_bytes().get(at + word.len())) {
                continue;
            }
            let open = past_space(text, at + word.len());
            if text.as_bytes().get(open) != Some(&b'(') {
                let site = format!("{}:{}", source.path, line(at));
                scan.failures
                    .push(format!("{site}: Failure::Violation not called"));
                continue;
            }
            let end = close(text, open);
            let args = split(&text[open + 1..end], false);
            if pattern(text, end) {
                continue;
            }
            match args.get(1).filter(|_| args.len() == 2) {
                Some(rule) => scan.argument(sources, source, open, rule),
                None => {
                    let site = format!("{}:{}", source.path, line(at));
                    scan.failures
                        .push(format!("{site}: a violation without two arguments"));
                }
            }
        }
        for (at, word) in text.match_indices("Violation") {
            let open = past_space(text, at + word.len());
            if !edge(text.as_bytes().get(at.wrapping_sub(1)))
                || !edge(text.as_bytes().get(at + word.len()))
                || text.as_bytes().get(open) != Some(&b'{')
            {
                continue;
            }
            let named = ["struct ", "enum "]
                .iter()
                .any(|item| text[..at].ends_with(item));
            let end = close(text, open);
            if named || pattern(text, end) {
                continue;
            }
            for field in split(&text[open + 1..end], false) {
                match field.split_once(':') {
                    _ if field == "rule" => scan.argument(sources, source, open, "rule"),
                    Some(("rule", value)) => scan.argument(sources, source, open, value),
                    _ => {}
                }
            }
        }
    }
    let mut done = BTreeSet::new();
    while let Some(helper) = scan.helpers.difference(&done).next().cloned() {
        done.insert(helper.clone());
        let (group, name, index, method) = helper;
        let members = sources
            .iter()
            .filter(|source| scan.modules[&source.path].starts_with(group.as_str()));
        let members: Vec<_> = members.collect();
        for source in members {
            let text = &source.text;
            let bytes = text.as_bytes();
            let edge =
                |byte: Option<&u8>| byte.is_none_or(|b| !b.is_ascii_alphanumeric() && *b != b'_');
            for (at, _) in text.match_indices(name.as_str()) {
                if !edge(bytes.get(at.wrapping_sub(1))) || !edge(bytes.get(at + name.len())) {
                    continue;
                }
                let before = text[..at].trim_end();
                let open = past_space(text, at + name.len());
                let called = bytes.get(open) == Some(&b'(');
                let site = format!("{}:{}", source.path, text[..at].matches('\n').count() + 1);
                if text[..at].ends_with("fn ") || called && before.ends_with('.') != method {
                    continue;
                }
                if !called || method && before.ends_with("::") {
                    let valued = ["(", ",", "&", "::", "= "]
                        .iter()
                        .any(|end| before.ends_with(end.trim()));
                    if valued || method {
                        scan.failures
                            .push(format!("{site}: {name} used other than as a call"));
                    }
                    continue;
                }
                let args = split(&text[open + 1..close(text, open)], false);
                match args.get(index) {
                    Some(arg) => scan.argument(sources, source, open, arg),
                    None => scan
                        .failures
                        .push(format!("{site}: {name} without its rule")),
                }
            }
        }
    }
    scan
}

/// Every difference between `rules` and `catalog`, each side named.
fn differences(rules: &BTreeSet<String>, catalog: &BTreeSet<String>) -> Vec<String> {
    let mut out: Vec<String> = rules
        .difference(catalog)
        .map(|rule| format!("raised but not cataloged: {rule:?}"))
        .collect();
    out.extend(
        catalog
            .difference(rules)
            .map(|rule| format!("cataloged but never raised: {rule:?}")),
    );
    out
}

/// Every violation a non-test source can raise resolves to texts, and
/// those texts are exactly the catalog's, and every forwarding entry
/// names a site. The scan reaches every producer
/// family: the observer's, the oracle's, the mixed world's and histories'
/// and the cluster checker's, each through its own helper, so a scan that
/// finds nothing cannot pass.
#[test]
fn every_violation_rule_producer_is_cataloged() {
    let scan = scan(sources());
    assert!(scan.failures.is_empty(), "{:#?}", scan.failures);
    assert_eq!(
        scan.forwarded.len(),
        FORWARDS.len(),
        "a forwarding entry names no site"
    );
    let catalog: BTreeSet<String> = texts().map(str::to_owned).collect();
    assert_eq!(catalog.len(), texts().count(), "a text is cataloged twice");
    let found = differences(&scan.rules, &catalog);
    assert!(found.is_empty(), "{found:#?}");
    for (group, name) in [
        ("net/world_tests/histories/", "fail"),
        ("net/world_tests/cluster/", "violation"),
        ("net/world_tests/cluster/", "foreign"),
        ("oracle/custody/", "fail"),
        ("oracle/clients/", "fail"),
    ] {
        assert!(
            scan.helpers
                .iter()
                .any(|helper| helper.0 == group && helper.1 == name),
            "no helper {name} in {group}: {:?}",
            scan.helpers
        );
    }
    for rule in [
        "a bound slot's record fails its header or chunk checks",
        "a lost fragment's source was released before its receipt",
        "unrelated work stalled or read bytes outside the visible versions",
        "a PUT frame naming a GET changed more than its counter",
        "an owner binds a version it reported as not published",
        "host loss replaced a retained cut with a cold start",
        "no legal order of the key's operations",
        "an upload collected as published without its result",
    ] {
        assert!(scan.rules.contains(rule), "{rule}");
    }
}

/// A source that raises a rule the catalog lacks, a catalog that lacks a
/// raised rule, and a catalog that holds a rule no source raises, each
/// fail the comparison and name the rule.
#[test]
fn an_omitted_rule_fails_the_catalog() {
    let added = Source {
        path: "net/world_tests/added.rs".into(),
        text: "fn added(first: &FirstFailure) {\n    first.record(Failure::Violation(\
            Obligation::Bytes, \"a rule no catalog holds\"));\n}\n"
            .into(),
    };
    let scan = scan(&[added]);
    assert!(scan.failures.is_empty(), "{:?}", scan.failures);
    let catalog: BTreeSet<String> = texts().map(str::to_owned).collect();
    let found = differences(&scan.rules, &catalog);
    assert!(
        found
            .iter()
            .any(|line| line == "raised but not cataloged: \"a rule no catalog holds\""),
        "{found:?}"
    );
    let full = self::scan(sources()).rules;
    let omitted = "a lost fragment's source was released before its receipt";
    let mut short = catalog.clone();
    assert!(short.remove(omitted));
    assert_eq!(
        differences(&full, &short),
        [format!("raised but not cataloged: {omitted:?}")]
    );
    let mut extra = catalog.clone();
    extra.insert("a rule no producer raises".to_owned());
    assert_eq!(
        differences(&full, &extra),
        ["cataloged but never raised: \"a rule no producer raises\"".to_owned()]
    );
}

/// A rule raised through an expression the scan cannot resolve to texts,
/// a helper's argument among them, a local not bound to a `match` or
/// `if`, a forwarding site no table entry names, and a helper visible
/// outside its module, whose callers the scan does not search, each fail
/// the scan; so do an `else` branch or a `match` arm of a bound rule that
/// is no text, a parameter an unrelated closure shares a name with, a
/// `match` binding in an earlier function, a constructor spelled with
/// space before its bracket around an unresolved rule, a constructor used
/// as a value, an import of `Failure`'s variants or a rename of `Failure`,
/// a local bound to an unsupported expression that shadows a parameter, an
/// arm whose call merely begins with `return`, a sink followed by `||`
/// whose arguments do not split in two, a commented field above a rule
/// that is no text, and a helper passed as a value.
#[test]
fn an_unsupported_rule_expression_fails_the_catalog() {
    for (text, expected) in [
        (
            "fn f(first: &FirstFailure, at: u32) {\n    first.record(Failure::Violation(\
                Obligation::Bytes, rules()[at]));\n}\n",
            "unsupported expression",
        ),
        (
            "fn f(first: &FirstFailure) {\n    let rule = pick();\n    first.record(\
                Failure::Violation(Obligation::Bytes, rule));\n}\n",
            "unsupported binding",
        ),
        (
            "fn raise(first: &FirstFailure, rule: &'static str) {\n    first.record(\
                Failure::Violation(Obligation::Bytes, rule));\n}\nfn g(first: &FirstFailure) {\n    \
                raise(first, NOT_A_CONSTANT);\n}\n",
            "no string constant NOT_A_CONSTANT",
        ),
        (
            "fn raise(first: &FirstFailure, rule: &'static str) {\n    first.record(\
                Failure::Violation(Obligation::Bytes, rule));\n}\nfn g(first: &FirstFailure) {\n    \
                raise(first, &format!(\"x\"));\n}\n",
            "unsupported expression",
        ),
        (
            "pub(super) fn raise(first: &FirstFailure, rule: &'static str) {\n    first.record(\
                Failure::Violation(Obligation::Bytes, rule));\n}\n",
            "unscanned",
        ),
        (
            "fn judge() -> Violation {\n    Violation {\n        op,\n        rule: if a { \"x\" },\n    }\n}\n",
            "an if without else",
        ),
        (
            "fn f(first: &FirstFailure) {\n    let rule = if a { \"x\" } else { pick() };\n    \
                first.record(Failure::Violation(Obligation::Bytes, rule));\n}\n",
            "unsupported expression",
        ),
        (
            "fn f(first: &FirstFailure) {\n    let rule = match a {\n        1 => \"x\",\n        \
                _ => pick(),\n    };\n    first.record(Failure::Violation(Obligation::Bytes, \
                rule));\n}\n",
            "unsupported expression",
        ),
        (
            "pub fn f(first: &FirstFailure, rule: &'static str) {\n    let g = |rule| rule;\n    \
                first.record(Failure::Violation(Obligation::Bytes, rule));\n}\n",
            "unscanned",
        ),
        (
            "fn e() {\n    let rule = match a {\n        _ => \"x\",\n    };\n}\nfn f(first: \
                &FirstFailure) {\n    first.record(Failure::Violation(Obligation::Bytes, rule));\n}\n",
            "unresolved in f",
        ),
        (
            "use Failure::*;\nfn f() {}\n",
            "imports or renames Failure's variants",
        ),
        (
            "fn f(first: &FirstFailure) {\n    first.record(Some(\"x\").map(|rule| Failure::Violation \
                (Obligation::Bytes, pick())));\n}\n",
            "unsupported expression",
        ),
        (
            "fn f() -> Vec<Failure> {\n    rules().map(Failure::Violation).collect()\n}\n",
            "Failure::Violation not called",
        ),
        (
            "fn f(first: &FirstFailure, rule: &'static str) {\n    let rule = pick();\n    \
                first.record(Failure::Violation(Obligation::Bytes, rule));\n}\n",
            "unsupported binding",
        ),
        (
            "fn f(first: &FirstFailure) {\n    let rule = match a {\n        1 => return_rule(),\n        \
                _ => \"x\",\n    };\n    first.record(Failure::Violation(Obligation::Bytes, rule));\n}\n",
            "unsupported expression",
        ),
        (
            "fn f(first: &FirstFailure) -> bool {\n    matches!(Failure::Violation(Obligation::Bytes)) \
                || first.ok()\n}\n",
            "a violation without two arguments",
        ),
        (
            "fn judge() -> Violation {\n    Violation {\n        op,\n        // the rule\n        \
                rule: pick(),\n    }\n}\n",
            "unsupported expression",
        ),
        (
            "fn raise(first: &FirstFailure, rule: &'static str) {\n    first.record(\
                Failure::Violation(Obligation::Bytes, rule));\n}\nfn g() {\n    \
                let all = [\"x\"].map(raise);\n}\n",
            "raise used other than as a call",
        ),
        (
            "use super::Failure as F;\nfn f() {}\n",
            "imports or renames Failure's variants",
        ),
    ] {
        let source = Source {
            path: "net/world_tests/added.rs".into(),
            text: blank_comments(text),
        };
        let scan = scan(&[source]);
        assert!(
            scan.failures
                .iter()
                .any(|failure| failure.ends_with(expected)),
            "{text}: {:?}",
            scan.failures
        );
    }
}

/// The scan reads files named like test files, so harness code a recorded
/// world runs there stays in it, with each `#[test]` function, inline test
/// module and private item only those tests name blanked: a test-only
/// fixture raises no rule and keeps no catalog entry alive, and a helper a
/// runtime item calls stays. A helper defined in a `mod.rs` file is
/// searched for callers in its child modules.
#[test]
fn test_items_leave_the_scan_and_harness_code_stays() {
    let full = sources();
    let put = full.iter().find(|source| source.path == "net/put_tests.rs");
    assert!(put.is_some_and(|put| put.text.contains("fn scene_drawn")));
    let mut added = vec![Source {
        path: "net/added_tests.rs".into(),
        text: blank_tests(
            "//! A test file.\nstatic FIXTURE: Failure = Failure::Violation(Obligation::Bytes, \"a test-only rule\");\n\
            fn checked() -> Failure {\n    FIXTURE\n}\n#[test]\nfn uses() {\n    checked();\n}\n\
            fn harness(first: &FirstFailure) {\n    first.record(Failure::Violation(\
            Obligation::Bytes, \"a harness rule\"));\n}\npub(crate) fn run() {\n    harness();\n}\n\
            #[cfg(test)]\nmod inner {\n    fn t() { Failure::Violation(Obligation::Bytes, \"inner\"); }\n}\n",
        ),
    }];
    blank_unnamed(&mut added);
    let scanned = self::scan(&added);
    assert!(scanned.failures.is_empty(), "{:?}", scanned.failures);
    assert_eq!(scanned.rules, BTreeSet::from(["a harness rule".to_owned()]));
    let parent = Source {
        path: "net/world_tests/family/mod.rs".into(),
        text: "fn raise(first: &FirstFailure, rule: &'static str) {\n    first.record(\
            Failure::Violation(Obligation::Bytes, rule));\n}\n"
            .into(),
    };
    let child = Source {
        path: "net/world_tests/family/child.rs".into(),
        text: "fn g(first: &FirstFailure) {\n    super::raise(first, \"a child's rule\");\n}\n"
            .into(),
    };
    let scanned = self::scan(&[parent, child]);
    assert!(scanned.failures.is_empty(), "{:?}", scanned.failures);
    assert!(
        scanned.rules.contains("a child's rule"),
        "{:?}",
        scanned.rules
    );
}

/// A test function's body opens at the first brace outside a literal, so a
/// brace inside the string of an attribute between `#[test]` and the
/// function is no body: the blanking ends at the function's own close and
/// the item after it stays.
#[test]
fn a_brace_in_a_test_attributes_string_opens_no_body() {
    let text = "#[test]\n#[should_panic(expected = \"a list: [Item { field\")]\n\
        fn t() {\n    plant();\n}\nfn harness() {\n    \"kept\";\n}\n";
    let blanked = blank_tests(text);
    let kept = text.find("fn harness").unwrap();
    assert_eq!(&blanked[kept..], &text[kept..]);
    assert!(blanked[..kept].trim().is_empty(), "{blanked}");
}

/// A file a `#[path]` attribute declares is its declarer's child module,
/// so a helper there is searched for callers in it; an inline test module
/// keeps its helpers a runtime item calls and drops its indented tests.
#[test]
fn path_children_and_inline_test_modules_are_scanned() {
    let declarer = Source {
        path: "net/owner.rs".into(),
        text: "fn raise(first: &FirstFailure, rule: &'static str) {\n    first.record(\
            Failure::Violation(Obligation::Bytes, rule));\n}\n#[path = \"owner_extra.rs\"]\nmod extra;\n"
            .into(),
    };
    let declared = Source {
        path: "net/owner_extra.rs".into(),
        text:
            "fn g(first: &FirstFailure) {\n    super::raise(first, \"a path child's rule\");\n}\n"
                .into(),
    };
    let scanned = scan(&[declarer, declared]);
    assert!(scanned.failures.is_empty(), "{:?}", scanned.failures);
    assert!(
        scanned.rules.contains("a path child's rule"),
        "{:?}",
        scanned.rules
    );
    let mut nested = vec![Source {
        path: "net/nested_tests.rs".into(),
        text: blank_tests(
            "//! A test file.\n#[cfg(test)]\npub(crate) mod inner {\n    fn helper(first: &FirstFailure) {\n        \
            first.record(Failure::Violation(Obligation::Bytes, \"a module helper's rule\"));\n    }\n    \
            pub(crate) fn run() {\n        helper();\n    }\n    #[test]\n    fn t() {\n        \
            Failure::Violation(Obligation::Bytes, \"an indented test's rule\");\n    }\n}\n",
        ),
    }];
    blank_unnamed(&mut nested);
    let scanned = scan(&nested);
    assert_eq!(
        scanned.rules,
        BTreeSet::from(["a module helper's rule".to_owned()])
    );
}

/// A forwarded function's rules are each value it returns in `Some(..)`
/// or `then_some(..)`; a returned helper call fails the scan, and so does
/// a forwarded function that returns no such value.
#[test]
fn forwarded_rules_resolve_each_returned_value() {
    let forwarding = |body: &str| Source {
        path: "net/world_tests/cluster.rs".into(),
        text: format!(
            "fn binding_rule(&self) -> Option<&'static str> {{\n{body}\n}}\nfn check(&self, first: \
            &FirstFailure) {{\n    let rule = match self.binding_rule() {{\n        Some(rule) => rule,\n        \
            None => return,\n    }};\n    first.record(Failure::Violation(Obligation::Bytes, rule));\n}}\n"
        ),
    };
    let scanned = scan(&[forwarding(
        "    if a { return Some(\"x\"); }\n    b.then_some(\"y\")",
    )]);
    assert!(
        scanned.rules.contains("x") && scanned.rules.contains("y"),
        "{:?}",
        scanned.rules
    );
    let scanned = scan(&[forwarding(
        "    if a { return Some(\"x\"); }\n    Some(pick())",
    )]);
    let failed = |scanned: &Scan, end: &str| scanned.failures.iter().any(|f| f.ends_with(end));
    assert!(
        failed(&scanned, "unsupported expression"),
        "{:?}",
        scanned.failures
    );
    let scanned = scan(&[forwarding("    None")]);
    assert!(
        failed(&scanned, "the forwarded function returns no rule"),
        "{:?}",
        scanned.failures
    );
}

/// A cataloged rule resolves from its full hash, a short and a long rule
/// alike, and a longer rule that shares a cataloged rule's first 41 bytes
/// resolves to nothing: no prefix selects a text. The failure view's tests
/// judge length, prefix, variant and obligation against the resolved text.
#[test]
fn rules_resolve_by_their_full_hash_alone() {
    let hash = |rule: &str| Sha256::digest(rule.as_bytes()).to_vec();
    let long = "unrelated work stalled or read bytes outside the visible versions";
    for rule in ["an unexpected binding", long] {
        assert_eq!(resolve(&hash(rule)), Some(rule));
    }
    assert_eq!(resolve(&hash(&format!("{long} and more"))), None);
    assert_eq!(resolve(&hash(&long[..41])), None);
}

/// The world scope holds exactly the cataloged texts the single-owner
/// world's source writes outside its tests. `HISTORY_SHARED` contains
/// exactly the oracle texts that originate in a history source's own
/// check, and every `HISTORY_SHARED` text is scoped `history` then
/// `oracle`. The two restart verdicts, the publication verdict and the
/// abandonment verdict are scoped `oracle` alone, and the verdict the
/// handout step takes from the world's read check is scoped `world` then
/// `oracle`.
/// The cluster texts a history shares are exactly the cluster's texts a
/// history source writes, each scoped `cluster` then `history`.
/// The cluster scope's texts are exactly the cataloged texts the cluster
/// checker's sources write.
/// Every cataloged text has a scope, a text has two scopes only as the
/// world's or a history's and then the oracle's, or as the cluster's and
/// then a history's, and the catalog form prints its version and one line
/// for each scoped text.
#[test]
fn every_rule_has_a_scope_and_the_world_scope_holds_what_its_source_writes() {
    let world = sources()
        .iter()
        .find(|source| source.path == "net/world_tests.rs")
        .expect("the single-owner world's source");
    let written: BTreeSet<&str> = texts()
        .filter(|text| world.text.contains(&format!("{text:?}")))
        .collect();
    assert_eq!(written, WORLD.iter().copied().collect());
    // `HISTORY_SHARED` lists the oracle texts raised by history steps' own
    // checks. Each history in `forwarded` and `misread` declares the
    // verdict its step records from another producer: `restarts.rs` and
    // `warm_loads.rs` the oracle's restart verdicts, `silent_owners.rs` its
    // publication verdict, `incidents/unknowns.rs` its abandonment verdict,
    // and `histories.rs` the verdict from the world's read check.
    let forwarded = [
        "a recovered candidate was found without admission",
        "a retained entry outside every damage set was lost on host loss",
        "an attempt that did not publish published",
        "an abandonment of an attempt that was not Unknown",
    ];
    let misread = "a refused read exposed bytes";
    let histories: BTreeSet<&str> = ORACLE
        .iter()
        .copied()
        .filter(|text| {
            sources().iter().any(|source| {
                source.path.starts_with("net/world_tests/histories")
                    && source.text.contains(&format!("{text:?}"))
            })
        })
        .collect();
    assert!(forwarded.iter().all(|text| histories.contains(text)));
    assert!(histories.contains(misread));
    let shared: BTreeSet<&str> = HISTORY_SHARED.iter().copied().collect();
    assert_eq!(shared.len(), HISTORY_SHARED.len());
    assert_eq!(
        shared,
        histories
            .into_iter()
            .filter(|text| !forwarded.contains(text) && *text != misread)
            .collect()
    );
    let scopes: Vec<(&str, &str)> = scoped().collect();
    let scopes_of = |text: &str| -> Vec<&str> {
        scopes
            .iter()
            .filter(|(_, scoped)| *scoped == text)
            .map(|(scope, _)| *scope)
            .collect()
    };
    for text in HISTORY_SHARED {
        assert_eq!(scopes_of(text), ["history", "oracle"], "{text}");
    }
    // A cluster text a history source writes has two producers, the cluster
    // checker and that history's step, and is scoped `cluster` then
    // `history`.
    let clustered: Vec<&str> = CLUSTER
        .iter()
        .copied()
        .filter(|text| {
            sources().iter().any(|source| {
                source.path.starts_with("net/world_tests/histories")
                    && source.text.contains(&format!("{text:?}"))
            })
        })
        .collect();
    assert_eq!(clustered, CLUSTER_SHARED);
    for text in clustered {
        assert_eq!(scopes_of(text), ["cluster", "history"], "{text}");
    }
    // The cataloged texts the cluster checker's sources write are exactly
    // the cluster scope's.
    let cluster_written: BTreeSet<&str> = texts()
        .filter(|text| {
            sources().iter().any(|source| {
                (source.path == "net/world_tests/cluster.rs"
                    || source.path.starts_with("net/world_tests/cluster/"))
                    && source.text.contains(&format!("{text:?}"))
            })
        })
        .collect();
    assert_eq!(cluster_written, CLUSTER.iter().copied().collect());
    for text in forwarded {
        assert_eq!(scopes_of(text), ["oracle"], "{text}");
    }
    assert_eq!(scopes_of(misread), ["world", "oracle"]);
    for text in texts() {
        let found: Vec<&str> = scopes
            .iter()
            .filter(|(_, scoped)| *scoped == text)
            .map(|(scope, _)| *scope)
            .collect();
        assert!(
            matches!(
                found[..],
                [_] | ["world", "oracle"] | ["history", "oracle"] | ["cluster", "history"]
            ),
            "{text}: {found:?}"
        );
    }
    assert!(
        scopes
            .iter()
            .all(|(_, text)| texts().any(|known| known == *text))
    );
    let distinct: BTreeSet<&(&str, &str)> = scopes.iter().collect();
    assert_eq!(distinct.len(), scopes.len());
    for scope in ["boundary", "world", "cluster", "history", "oracle"] {
        assert!(scopes.iter().any(|(found, _)| *found == scope), "{scope}");
    }
    let printed = listing();
    let mut lines = printed.lines();
    assert_eq!(lines.next(), Some("rules: 1"));
    let rules: Vec<String> = scopes
        .iter()
        .map(|(scope, text)| format!("rule: {scope} {text}"))
        .collect();
    assert_eq!(lines.collect::<Vec<_>>(), rules);
    assert!(printed.ends_with('\n'));
}
