//! The reach guard checks each family's `verification/reach/<family>.json`
//! register against the listed enums returned by `scan`: every listed variant has a
//! row, every row names a listed variant, every listed enum has rows, every
//! `unreached` row names a reason row of its class, and the header's live
//! count equals the number of `unplaced` rows. Every register committed
//! under `verification/reach/` belongs to a family the guard checks. Each
//! reason row an `unreached` row names carries a listed `kind` and a
//! nonempty `missing`, every reason row carries the id and keys the tool
//! writes, and an `unreached` row names every reason row. Its
//! module walk, option list and name rule follow the tool under
//! `verification/reach/tool/`, and it reads the register with `std`.
//! The guard checks that its `FAMILIES` matches the tool's `FAMILIES` under
//! `verification/reach/tool/`.
//! `fits` checks each row for the fields the tool's reader requires for
//! that row's state, and `run_fits` and `totals_fits` check the header's
//! `run` and `totals` lines for the tool's keys and types. The reader takes
//! the JSON values the tool's reader takes in each field.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use super::guard_tests::{KEYWORDS, tokens};

const FAMILIES: [&str; 3] = ["storage", "net", "failover"];

const ENDINGS: [&str; 6] = [
    "Error",
    "Refusal",
    "Refused",
    "Rejection",
    "Reason",
    "Failure",
];

const FALSE: [&str; 7] = [
    "test",
    "kani",
    "loom",
    "fuzzing",
    "protocol_contract",
    "verus_keep_ghost",
    "miri",
];

const KEYS: [&str; 8] = [
    "enum", "variant", "sites", "state", "count", "measured", "reason", "cause",
];

const STATES: [&str; 4] = ["reached", "unreached", "unplaced", "unmeasured"];

const REASON_KEYS: [&str; 6] = ["id", "measured", "functions", "kind", "missing", "sentence"];

/// The keys of `REASON_KEYS` that the tool's `Reason` requires on read and
/// writes whatever their value; it leaves each other key out when empty.
const REQUIRED_REASON_KEYS: [&str; 3] = ["id", "measured", "sentence"];

const MEASURED: [&str; 3] = ["file-not-run", "function-not-entered", "not-constructed"];

const KINDS: [&str; 5] = [
    "step",
    "fault",
    "configuration",
    "environment",
    "unconstructible",
];

const CAUSES: [&str; 3] = ["no-site", "no-region", "unplaceable"];

/// The keys of the header's `run` line, in the order the tool writes them;
/// every key but `tool` is required.
const RUN_KEYS: [&str; 10] = [
    "commit",
    "toolchain",
    "flags",
    "build",
    "worker",
    "profiles",
    "roots",
    "counts",
    "no_pass",
    "tool",
];

/// The keys of the header's `totals` line, each required, in the order the
/// tool writes them.
const TOTALS_KEYS: [&str; 7] = [
    "rows",
    "reached",
    "unreached",
    "unplaced",
    "file-not-run",
    "function-not-entered",
    "not-constructed",
];

/// The nesting the register's rows and header use: a row object holds
/// `sites`, an array of three-string arrays.
const DEPTH: usize = 4;

type Read<'a> = dyn Fn(&str) -> Result<Option<String>, String> + 'a;

fn sync(family: &str) -> String {
    format!(
        "run `cargo run --locked --release --manifest-path verification/reach/tool/Cargo.toml -- sync {family}` \
         and commit verification/reach/{family}.json"
    )
}

/// The index past the group that opens at `tokens[open]`.
fn closing(tokens: &[&str], open: usize) -> usize {
    let mut depth = 0usize;
    for (i, token) in tokens.iter().enumerate().skip(open) {
        match *token {
            "(" | "[" | "{" => depth += 1,
            ")" | "]" | "}" => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
    }
    tokens.len()
}

fn arguments<'a, 'b>(tokens: &'b [&'a str]) -> Vec<&'b [&'a str]> {
    let mut parts = Vec::new();
    let (mut start, mut i) = (0, 0);
    while i < tokens.len() {
        match tokens[i] {
            "(" | "[" | "{" => i = closing(tokens, i),
            "," => {
                parts.push(&tokens[start..i]);
                i += 1;
                start = i;
            }
            _ => i += 1,
        }
    }
    if start < tokens.len() {
        parts.push(&tokens[start..]);
    }
    parts
}

/// `variant_parts` splits an enum body at its top-level commas and keeps
/// the generic arguments of a turbofish in a discriminant whole.
fn variant_parts<'a, 'b>(tokens: &'b [&'a str]) -> Vec<&'b [&'a str]> {
    let mut parts = Vec::new();
    let (mut start, mut i, mut angle) = (0, 0, 0usize);
    while i < tokens.len() {
        match tokens[i] {
            "(" | "[" | "{" => {
                i = closing(tokens, i);
                continue;
            }
            "<" if angle > 0 || (i > 0 && tokens[i - 1] == "::") => angle += 1,
            ">" if angle > 0 && tokens[i - 1] != "-" => angle -= 1,
            "," if angle == 0 => {
                parts.push(&tokens[start..i]);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    if start < tokens.len() {
        parts.push(&tokens[start..]);
    }
    parts
}

fn evaluate(predicate: &[&str]) -> Option<bool> {
    match predicate {
        ["true"] => Some(true),
        ["false"] => Some(false),
        [name] if FALSE.contains(name) => Some(false),
        [name, "(", inner @ .., ")"] => {
            let values: Vec<Option<bool>> = arguments(inner).into_iter().map(evaluate).collect();
            match *name {
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

/// True when the attribute body `attribute`, the tokens between `#[` and
/// `]`, excludes its item.
fn gates(attribute: &[&str]) -> bool {
    match attribute {
        ["cfg", "(", predicate @ .., ")"] => evaluate(predicate) == Some(false),
        ["cfg_attr", "(", inner @ .., ")"] => {
            let parts = arguments(inner);
            parts.split_first().is_some_and(|(predicate, applied)| {
                evaluate(predicate) == Some(true) && applied.iter().any(|part| gates(part))
            })
        }
        _ => {
            attribute
                .split(|token| *token == "(")
                .next()
                .and_then(<[&str]>::last)
                == Some(&"test")
        }
    }
}

/// True when the attribute body is a `cfg_attr` whose predicate the build
/// model leaves true or unknown and that applies `path`, directly or
/// through a nested `cfg_attr`.
fn sets_path(attribute: &[&str]) -> bool {
    let ["cfg_attr", "(", inner @ .., ")"] = attribute else {
        return false;
    };
    let parts = arguments(inner);
    parts.split_first().is_some_and(|(predicate, applied)| {
        evaluate(predicate) != Some(false)
            && applied
                .iter()
                .any(|part| part.first() == Some(&"path") || sets_path(part))
    })
}

/// True when `token` is an identifier that is no keyword: the token
/// before the `!` of a macro call. A `!` after any other token negates.
fn names(token: &str) -> bool {
    !KEYWORDS.contains(&token) && token.chars().all(|c| c.is_alphanumeric() || c == '_')
}

/// True when `rest`, the tokens after an attribute, start a field: an
/// optional visibility, then a name before `:` or `,`.
fn fielded(rest: &[&str]) -> bool {
    let rest = match rest {
        ["pub", "(", ..] => &rest[closing(rest, 1)..],
        ["pub", rest @ ..] => rest,
        rest => rest,
    };
    matches!(rest, [name, ":" | ",", ..] if names(name))
}

struct Listed {
    path: String,
    file: String,
    variants: Vec<String>,
}

fn join(directory: &str, name: &str) -> String {
    if directory.is_empty() {
        name.to_owned()
    } else {
        format!("{directory}/{name}")
    }
}

fn resolve_path(directory: &str, target: &str) -> Option<String> {
    if target.starts_with('/') || target.starts_with('\\') || target.contains(':') {
        return None;
    }
    let mut parts: Vec<&str> = directory
        .split('/')
        .filter(|part| !part.is_empty())
        .collect();
    for part in target.split('/') {
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

/// The plain string literal after `= ` that follows `token`, a slice of
/// `text` such as the `path` of `#[path = "..."]`.
fn literal_after(text: &str, token: &str) -> Option<String> {
    let offset = token.as_ptr().addr().checked_sub(text.as_ptr().addr())?;
    let rest = text.get(offset + token.len()..)?.trim_start();
    let rest = rest.strip_prefix('=')?.trim_start().strip_prefix('"')?;
    let end = rest.find(['"', '\\'])?;
    (rest.as_bytes()[end] == b'"').then(|| rest[..end].to_owned())
}

struct Base<'a> {
    directory: &'a str,
    children: String,
    inline: bool,
}

struct Scan<'a> {
    read: &'a Read<'a>,
    family: &'a str,
    found: Vec<Listed>,
    problems: Vec<String>,
    active: Vec<String>,
    walked: BTreeSet<String>,
}

impl Scan<'_> {
    fn walk(&mut self, rel: &str, text: &str, module: &[String]) {
        if self.active.iter().any(|file| file == rel) {
            self.problems.push(format!(
                "{rel}: a `#[path]` declaration re-enters this file"
            ));
            return;
        }
        if !self.walked.insert(rel.to_owned()) {
            return;
        }
        let tokens = tokens(text);
        let directory = rel.rsplit_once('/').map_or("", |(directory, _)| directory);
        let stem = rel
            .rsplit('/')
            .next()
            .unwrap_or(rel)
            .trim_end_matches(".rs");
        let children = if stem == "mod" {
            directory.to_owned()
        } else {
            join(directory, stem)
        };
        let base = Base {
            directory,
            children,
            inline: false,
        };
        self.active.push(rel.to_owned());
        self.items(&tokens, text, rel, &base, module);
        self.active.pop();
    }

    /// `rel` names the source file and `text` its contents; `module` names
    /// the Rust module holding `tokens`. Inline modules share their
    /// parent's `rel`. A pending attribute ends at the first `;` or brace
    /// group after it, and at the comma that ends its match arm or field.
    fn items(&mut self, tokens: &[&str], text: &str, rel: &str, base: &Base, module: &[String]) {
        let mut attributes: Vec<&[&str]> = Vec::new();
        // `arm` holds from the `=>` of a match arm, or from the attribute
        // of a field, to the comma that ends the arm or the field, where
        // its attributes end. `turbofish` counts the open `::<` lists,
        // whose commas end neither; the walk steps over the parameters of
        // a closure that is the arm's body or the field's value.
        let (mut arm, mut turbofish) = (false, 0usize);
        let mut i = 0;
        while i < tokens.len() {
            let gated = || attributes.iter().any(|attribute| gates(attribute));
            let next = tokens.get(i + 1).copied();
            match tokens[i] {
                "=" if next == Some(">") => {
                    arm = true;
                    i += 2;
                }
                "<" if turbofish > 0 || (i > 0 && tokens[i - 1] == "::") => {
                    turbofish += 1;
                    i += 1;
                }
                ">" if turbofish > 0 && tokens[i - 1] != "-" => {
                    turbofish -= 1;
                    i += 1;
                }
                "|" if arm && i > 0 && matches!(tokens[i - 1], ":" | ">" | "move") => {
                    i = (i + 1..tokens.len())
                        .find(|&k| tokens[k] == "|")
                        .map_or(tokens.len(), |k| k + 1);
                }
                "," if arm && turbofish == 0 => {
                    attributes.clear();
                    arm = false;
                    i += 1;
                }
                "#" if next == Some("[") => {
                    let end = closing(tokens, i + 1);
                    attributes.push(&tokens[i + 2..end - 1]);
                    arm |= fielded(&tokens[end..]);
                    i = end;
                }
                "#" if next == Some("!") && tokens.get(i + 2) == Some(&"[") => {
                    let end = closing(tokens, i + 2);
                    if gates(&tokens[i + 3..end - 1]) {
                        return;
                    }
                    i = end;
                }
                "macro_rules" if next == Some("!") => {
                    i = (i + 2..tokens.len())
                        .find(|&k| matches!(tokens[k], "{" | "(" | "["))
                        .map_or(tokens.len(), |k| closing(tokens, k));
                    attributes.clear();
                }
                "(" | "[" => {
                    let end = closing(tokens, i);
                    if !gated() {
                        self.items(&tokens[i + 1..end - 1], text, rel, base, module);
                    }
                    i = end;
                }
                "!" if matches!(next, Some("{" | "(" | "[")) && i > 0 && names(tokens[i - 1]) => {
                    i = closing(tokens, i + 1);
                    attributes.clear();
                }
                "mod" => {
                    let (gated, name) = (gated(), next.unwrap_or_default());
                    let mut path = module.to_vec();
                    path.push(name.to_owned());
                    let child = join(&base.children, name);
                    if tokens.get(i + 2) == Some(&"{") {
                        let end = closing(tokens, i + 2);
                        if !gated {
                            let inner = Base {
                                directory: base.directory,
                                children: child,
                                inline: true,
                            };
                            self.items(&tokens[i + 3..end - 1], text, rel, &inner, &path);
                        }
                        i = end;
                    } else {
                        if !gated {
                            self.declared(text, rel, base, &child, &path, &attributes);
                        }
                        i += 2;
                    }
                    attributes.clear();
                }
                "enum" => {
                    let gated = gated();
                    let name = next.unwrap_or_default();
                    let mut open = i + 2;
                    while open < tokens.len() && tokens[open] != "{" {
                        open = if tokens[open] == "(" {
                            closing(tokens, open)
                        } else {
                            open + 1
                        };
                    }
                    let end = closing(tokens, open);
                    let family = rel.starts_with(&format!("{}/", self.family));
                    if !gated && family && ENDINGS.iter().any(|ending| name.ends_with(ending)) {
                        let mut path = module.to_vec();
                        path.push(name.to_owned());
                        self.found.push(Listed {
                            path: path.join("::"),
                            file: rel.to_owned(),
                            variants: variants(&tokens[(open + 1).min(end)..end.saturating_sub(1)]),
                        });
                    }
                    attributes.clear();
                    i = end;
                }
                "{" => {
                    let end = closing(tokens, i);
                    if !gated() {
                        self.items(&tokens[i + 1..end - 1], text, rel, base, module);
                    }
                    attributes.clear();
                    i = end;
                }
                ";" => {
                    attributes.clear();
                    i += 1;
                }
                _ => i += 1,
            }
        }
    }

    fn declared(
        &mut self,
        text: &str,
        rel: &str,
        base: &Base,
        child: &str,
        path: &[String],
        attributes: &[&[&str]],
    ) {
        let name = path.join("::");
        if attributes.iter().any(|attribute| sets_path(attribute)) {
            self.problems.push(format!(
                "{rel}: `mod {name}` takes its file from a `cfg_attr` the build model cannot rule out"
            ));
            return;
        }
        let target = attributes
            .iter()
            .find(|attribute| attribute.first() == Some(&"path"));
        let candidates = match target {
            Some(_) if base.inline => {
                self.problems.push(format!(
                    "{rel}: `mod {name}` names its file by `#[path]` inside an inline module"
                ));
                return;
            }
            Some(attribute) => {
                let file = literal_after(text, attribute[0])
                    .and_then(|target| resolve_path(base.directory, &target));
                let Some(file) = file else {
                    self.problems.push(format!(
                        "{rel}: `mod {name}` names a `#[path]` outside the source root or in a form the guard reads no further"
                    ));
                    return;
                };
                vec![file]
            }
            None => vec![format!("{child}.rs"), join(child, "mod.rs")],
        };
        let mut found = Vec::new();
        for candidate in candidates {
            match (self.read)(&candidate) {
                Ok(Some(text)) => found.push((candidate, text)),
                Ok(None) => {}
                Err(error) => {
                    self.problems.push(error);
                    return;
                }
            }
        }
        match found.as_slice() {
            [(file, text)] => self.walk(file, text, path),
            [] => self
                .problems
                .push(format!("{rel}: no file for `mod {name}`")),
            _ => self
                .problems
                .push(format!("{rel}: two files for `mod {name}`")),
        }
    }
}

fn variants(body: &[&str]) -> Vec<String> {
    let mut found = Vec::new();
    for part in variant_parts(body) {
        let (mut k, mut gated) = (0, false);
        while part.get(k) == Some(&"#") && part.get(k + 1) == Some(&"[") {
            let end = closing(part, k + 1);
            gated |= gates(&part[k + 2..end - 1]);
            k = end;
        }
        if let Some(name) = part.get(k)
            && !gated
            && !found.iter().any(|known| known == name)
        {
            found.push((*name).to_owned());
        }
    }
    found
}

/// A JSON value the tool writes: a string, a number without sign,
/// fraction, exponent or leading zero, an array or an object. The reader
/// refuses `null`, `true`, `false` and every other number, as the tool's
/// reader refuses them in each field of the register.
#[derive(Debug, PartialEq)]
enum Value {
    Text(String),
    Number(u64),
    Array(Vec<Value>),
    Object(Vec<(String, Value)>),
}

struct Reader<'a> {
    chars: std::iter::Peekable<std::str::Chars<'a>>,
    depth: usize,
}

impl Reader<'_> {
    fn eat(&mut self, expected: char) -> Option<()> {
        (self.chars.next()? == expected).then_some(())
    }

    fn hex(&mut self) -> Option<u32> {
        let mut unit = 0;
        for _ in 0..4 {
            unit = unit * 16 + self.chars.next()?.to_digit(16)?;
        }
        Some(unit)
    }

    fn text(&mut self) -> Option<String> {
        self.eat('"')?;
        let mut out = String::new();
        loop {
            match self.chars.next()? {
                '"' => return Some(out),
                '\\' => out.push(match self.chars.next()? {
                    '"' => '"',
                    '\\' => '\\',
                    '/' => '/',
                    'b' => '\u{8}',
                    'f' => '\u{c}',
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    'u' => match self.hex()? {
                        high @ 0xD800..=0xDBFF => {
                            self.eat('\\')?;
                            self.eat('u')?;
                            let low = self.hex().filter(|low| (0xDC00..=0xDFFF).contains(low))?;
                            char::from_u32(0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00))?
                        }
                        unit => char::from_u32(unit)?,
                    },
                    _ => return None,
                }),
                c if c < ' ' => return None,
                c => out.push(c),
            }
        }
    }

    fn nested<T>(&mut self, body: impl FnOnce(&mut Self) -> Option<T>) -> Option<T> {
        if self.depth == DEPTH {
            return None;
        }
        self.depth += 1;
        let out = body(self);
        self.depth -= 1;
        out
    }

    fn value(&mut self) -> Option<Value> {
        match *self.chars.peek()? {
            '"' => self.text().map(Value::Text),
            '0'..='9' => {
                let mut digits = String::new();
                while let Some(&c) = self.chars.peek().filter(|c| c.is_ascii_digit()) {
                    digits.push(c);
                    self.chars.next();
                }
                if digits.len() > 1 && digits.starts_with('0') {
                    return None;
                }
                digits.parse().ok().map(Value::Number)
            }
            '[' => self.nested(|reader| {
                reader.chars.next();
                let mut items = Vec::new();
                if reader.chars.peek() == Some(&']') {
                    reader.chars.next();
                    return Some(Value::Array(items));
                }
                loop {
                    items.push(reader.value()?);
                    match reader.chars.next()? {
                        ',' => {}
                        ']' => return Some(Value::Array(items)),
                        _ => return None,
                    }
                }
            }),
            '{' => self.nested(|reader| reader.object().map(Value::Object)),
            _ => None,
        }
    }

    fn object(&mut self) -> Option<Vec<(String, Value)>> {
        self.eat('{')?;
        let mut fields = Vec::new();
        if self.chars.peek() == Some(&'}') {
            self.chars.next();
            return Some(fields);
        }
        loop {
            let key = self.text()?;
            self.eat(':')?;
            fields.push((key, self.value()?));
            match self.chars.next()? {
                ',' => {}
                '}' => return Some(fields),
                _ => return None,
            }
        }
    }
}

/// `object` returns fields only when exactly one object fills `body`.
fn object(body: &str) -> Option<Vec<(String, Value)>> {
    let mut reader = Reader {
        chars: body.chars().peekable(),
        depth: 0,
    };
    let fields = reader.object()?;
    reader.chars.next().is_none().then_some(fields)
}

fn field<'a>(fields: &'a [(String, Value)], key: &str) -> Option<&'a Value> {
    fields
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value)
}

fn string<'a>(fields: &'a [(String, Value)], key: &str) -> Option<&'a str> {
    match field(fields, key)? {
        Value::Text(text) => Some(text),
        _ => None,
    }
}

/// `ordered` returns the indices of `fields` keys in `known` when those
/// keys appear in the order of `known`.
fn ordered(fields: &[(String, Value)], known: &[&str]) -> Option<Vec<usize>> {
    let positions: Vec<usize> = fields
        .iter()
        .map(|(key, _)| known.iter().position(|name| name == key))
        .collect::<Option<_>>()?;
    positions
        .windows(2)
        .all(|pair| pair[0] < pair[1])
        .then_some(positions)
}

fn texts(value: &Value, length: usize) -> bool {
    matches!(value, Value::Array(items)
        if items.len() == length && items.iter().all(|item| matches!(item, Value::Text(_))))
}

fn table(value: &Value, length: usize) -> bool {
    matches!(value, Value::Array(items) if items.iter().all(|item| texts(item, length)))
}

struct Row {
    line: usize,
    enum_path: String,
    variant: String,
    state: String,
    fields: Vec<(String, Value)>,
}

#[derive(Default)]
struct Register {
    commit: Option<String>,
    live: Option<u64>,
    reasons: BTreeMap<String, Reason>,
    rows: Vec<Row>,
    problems: Vec<String>,
}

struct Reason {
    line: usize,
    fields: Vec<(String, Value)>,
}

fn row(line: usize, fields: Vec<(String, Value)>) -> Option<Row> {
    let positions = ordered(&fields, &KEYS)?;
    if positions.get(..4) != Some(&[0, 1, 2, 3]) || !table(field(&fields, "sites")?, 3) {
        return None;
    }
    let typed = fields
        .iter()
        .skip(4)
        .all(|(key, value)| match key.as_str() {
            "count" => matches!(value, Value::Number(_)),
            _ => matches!(value, Value::Text(_)),
        });
    let state = string(&fields, "state").filter(|state| STATES.contains(state))?;
    if !typed {
        return None;
    }
    Some(Row {
        line,
        enum_path: string(&fields, "enum")?.to_owned(),
        variant: string(&fields, "variant")?.to_owned(),
        state: state.to_owned(),
        fields,
    })
}

fn reason(line: usize, fields: Vec<(String, Value)>) -> Option<(String, Reason)> {
    ordered(&fields, &REASON_KEYS)?;
    let complete = REQUIRED_REASON_KEYS
        .iter()
        .all(|required| field(&fields, required).is_some());
    let typed = fields.iter().all(|(key, value)| match key.as_str() {
        "functions" => table(value, 2),
        _ => matches!(value, Value::Text(_)),
    });
    let classed = string(&fields, "measured").is_some_and(|measured| MEASURED.contains(&measured));
    if !complete || !typed || !classed {
        return None;
    }
    Some((string(&fields, "id")?.to_owned(), Reason { line, fields }))
}

/// `run_fits` holds the `run` line to the tool's `Run`: the keys of
/// [`RUN_KEYS`] in order, `tool` optional, `profiles` and `no_pass` arrays
/// of strings, `counts` an object of strings, and strings elsewhere.
fn run_fits(fields: &[(String, Value)]) -> bool {
    let keys: Vec<&str> = fields.iter().map(|(key, _)| key.as_str()).collect();
    (keys == RUN_KEYS || keys == RUN_KEYS[..RUN_KEYS.len() - 1])
        && fields
            .iter()
            .all(|(key, value)| match (key.as_str(), value) {
                ("profiles" | "no_pass", Value::Array(items)) => {
                    items.iter().all(|item| matches!(item, Value::Text(_)))
                }
                ("counts", Value::Object(counts)) => counts
                    .iter()
                    .all(|(_, count)| matches!(count, Value::Text(_))),
                ("profiles" | "no_pass" | "counts", _) => false,
                (_, value) => matches!(value, Value::Text(_)),
            })
}

/// `totals_fits` holds the `totals` line to every key of [`TOTALS_KEYS`],
/// in order, each a number.
fn totals_fits(fields: &[(String, Value)]) -> bool {
    fields.len() == TOTALS_KEYS.len()
        && fields
            .iter()
            .zip(TOTALS_KEYS)
            .all(|((key, value), known)| key == known && matches!(value, Value::Number(_)))
}

/// `fits` holds a row to the field set of its state: a `reached` row a
/// positive count, an `unreached` row a count of zero and a known class,
/// an `unplaced` row a known cause, and an `unmeasured` row none.
/// `violations` holds an `unreached` row's reason to a reason row of its
/// class.
fn fits(row: &Row) -> bool {
    let has = |key: &str| field(&row.fields, key).is_some();
    let within = |key: &str, known: &[&str]| {
        string(&row.fields, key).is_some_and(|value| known.contains(&value))
    };
    let count = match field(&row.fields, "count") {
        Some(Value::Number(count)) => Some(*count),
        _ => None,
    };
    match row.state.as_str() {
        "reached" => {
            count.is_some_and(|count| count > 0)
                && !has("measured")
                && !has("reason")
                && !has("cause")
        }
        "unreached" => count == Some(0) && within("measured", &MEASURED) && !has("cause"),
        "unplaced" => {
            !has("count") && !has("measured") && !has("reason") && within("cause", &CAUSES)
        }
        _ => !has("count") && !has("measured") && !has("reason") && !has("cause"),
    }
}

/// `entries` reads the lines of one array of the register from `start` up
/// to the line `end`, each but the last ending in a comma, and returns the
/// 1-based line number and the object text of each, with the index of the
/// line `end`.
fn entries<'a>(
    lines: &[&'a str],
    start: usize,
    end: &str,
    problems: &mut Vec<String>,
) -> (Vec<(usize, &'a str)>, usize) {
    let Some(close) = (start..lines.len()).find(|&index| lines[index] == end) else {
        problems.push(format!(
            "line {}: an array with no closing `{end}` line",
            start + 1
        ));
        return (Vec::new(), lines.len());
    };
    let mut found = Vec::new();
    for (index, line) in lines.iter().enumerate().take(close).skip(start) {
        let last = index + 1 == close;
        match line.strip_suffix(',') {
            Some(body) if !last => found.push((index + 1, body)),
            None if last => found.push((index + 1, *line)),
            _ => problems.push(format!("line {}: a separator out of place", index + 1)),
        }
    }
    (found, close)
}

fn register(text: &str) -> Register {
    let mut register = Register::default();
    let lines: Vec<&str> = text.lines().collect();
    let line = |index: usize| lines.get(index).copied().unwrap_or_default();
    let mut problems = Vec::new();
    let mut header = |index: usize, prefix: &str| {
        let fields = line(index)
            .strip_prefix(prefix)
            .and_then(|body| body.strip_suffix(','))
            .and_then(object);
        if fields.is_none() {
            problems.push(format!(
                "line {}: the header's {} line is unreadable",
                index + 1,
                prefix.trim_end_matches(": ")
            ));
        }
        fields
    };
    let run = header(1, "\"run\": ").filter(|fields| run_fits(fields));
    let totals = header(2, "\"totals\": ");
    let live = header(3, "\"live\": ");
    if run.is_none() {
        problems.push("line 2: the header's run line differs from the tool's run".to_owned());
    }
    if totals.is_some_and(|fields| !totals_fits(&fields)) {
        problems.push("line 3: the header's totals line differs from the tool's totals".to_owned());
    }
    register.commit = run.and_then(|fields| string(&fields, "commit").map(str::to_owned));
    register.live = live.and_then(|fields| match fields.as_slice() {
        [(key, Value::Number(count))] if key == "unplaced" => Some(*count),
        _ => None,
    });
    if line(0) != "{" {
        problems.push("line 1: the register opens with a line other than `{`".to_owned());
    }
    if line(4) != "\"reasons\": [" {
        problems.push(
            "line 5: the reasons array opens with a line other than `\"reasons\": [`".to_owned(),
        );
    }
    let (reasons, close) = entries(&lines, 5, "],", &mut problems);
    for (number, body) in reasons {
        match object(body).and_then(|fields| reason(number, fields)) {
            Some((id, reason)) => {
                let measured = string(&reason.fields, "measured").unwrap_or_default();
                if !id
                    .strip_prefix(measured)
                    .is_some_and(|key| key.starts_with(':'))
                {
                    problems.push(format!(
                        "line {number}: the id of the reason row {id} opens with other than \
                         `{measured}:`"
                    ));
                }
                for (key, value) in &reason.fields {
                    let empty = match value {
                        Value::Text(text) => text.is_empty(),
                        Value::Array(items) => items.is_empty(),
                        _ => false,
                    };
                    if empty && !REQUIRED_REASON_KEYS.contains(&key.as_str()) {
                        problems.push(format!(
                            "line {number}: the reason row {id} holds an empty {key}, which \
                             the tool leaves out"
                        ));
                    }
                }
                if let Some(first) = register.reasons.get(&id) {
                    problems.push(format!(
                        "line {number}: a second reason row for {id}, first at line {}",
                        first.line
                    ));
                } else {
                    register.reasons.insert(id, reason);
                }
            }
            None => problems.push(format!("line {number}: an unreadable reason row")),
        }
    }
    if line(close + 1) != "\"rows\": [" {
        problems.push(format!(
            "line {}: the rows array opens with a line other than `\"rows\": [`",
            close + 2
        ));
    }
    let (rows, close) = entries(&lines, close + 2, "]", &mut problems);
    for (number, body) in rows {
        match object(body).and_then(|fields| row(number, fields)) {
            Some(row) => register.rows.push(row),
            None => problems.push(format!("line {number}: an unreadable row")),
        }
    }
    if line(close + 1) != "}" || lines.len() != close + 2 {
        problems.push(format!(
            "line {}: the register ends with a line other than a closing `}}`",
            close + 2
        ));
    }
    if register.commit.is_none() {
        problems.push("the header names no run commit".to_owned());
    }
    if register.live.is_none() {
        problems.push("the header holds no live unplaced count".to_owned());
    }
    register.problems = problems;
    register
}

fn scan(read: &Read, family: &str) -> (Vec<Listed>, Vec<String>) {
    let mut scan = Scan {
        read,
        family,
        found: Vec::new(),
        problems: Vec::new(),
        active: Vec::new(),
        walked: BTreeSet::new(),
    };
    match read("mod.rs") {
        Ok(Some(text)) => scan.walk("mod.rs", &text, &[]),
        Ok(None) => scan.problems.push("mod.rs: absent".to_owned()),
        Err(error) => scan.problems.push(error),
    }
    (scan.found, scan.problems)
}

/// `violations` returns scan problems, register problems, and findings from
/// checking the register `text` against the listed enums of `family`.
fn violations(read: &Read, family: &str, text: &str) -> Vec<String> {
    let (listed, mut found) = scan(read, family);
    let register = register(text);
    found.extend(register.problems.iter().cloned());
    let mut rows: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for row in &register.rows {
        if !rows.entry(&row.enum_path).or_default().insert(&row.variant) {
            found.push(format!(
                "line {}: a second row for {}::{}",
                row.line, row.enum_path, row.variant
            ));
        }
    }
    let mut paths: BTreeMap<&str, &str> = BTreeMap::new();
    let mut declared: BTreeSet<(&str, &str)> = BTreeSet::new();
    for listed in &listed {
        if let Some(first) = paths.insert(&listed.path, &listed.file) {
            found.push(format!(
                "{} is declared twice ({first}, {}); rename one enum or keep one declaration",
                listed.path, listed.file
            ));
        }
        declared.extend(
            listed
                .variants
                .iter()
                .map(|variant| (listed.path.as_str(), variant.as_str())),
        );
        let Some(variants) = rows.get(listed.path.as_str()) else {
            if listed.variants.is_empty() {
                found.push(format!(
                    "{} ({}) is a listed enum with no variant the register can hold; \
                     give it a variant or a name outside the list",
                    listed.path, listed.file
                ));
            } else {
                found.push(format!(
                    "{} ({}) is a listed enum with no rows: {}",
                    listed.path,
                    listed.file,
                    sync(family)
                ));
            }
            continue;
        };
        for variant in &listed.variants {
            if !variants.contains(variant.as_str()) {
                found.push(format!(
                    "{}::{variant} has no row: {}",
                    listed.path,
                    sync(family)
                ));
            }
        }
    }
    let mut cited: BTreeMap<&str, &Reason> = BTreeMap::new();
    for row in &register.rows {
        let line = row.line;
        if !declared.contains(&(row.enum_path.as_str(), row.variant.as_str())) {
            found.push(format!(
                "line {line}: the row {}::{} names no listed variant: {}",
                row.enum_path,
                row.variant,
                sync(family)
            ));
        }
        let reason = string(&row.fields, "reason");
        let measured = string(&row.fields, "measured");
        if row.state == "unreached"
            && let Some((id, named)) = reason.and_then(|id| register.reasons.get_key_value(id))
        {
            cited.insert(id, named);
        }
        match row.state.as_str() {
            "unmeasured"
                if field(&row.fields, "count").is_some()
                    || field(&row.fields, "reason").is_some() =>
            {
                found.push(format!(
                    "line {line}: the unmeasured row {}::{} carries a count or a reason",
                    row.enum_path, row.variant
                ))
            }
            state if !fits(row) => found.push(format!(
                "line {line}: the {state} row {}::{} carries fields that differ from the set of its state",
                row.enum_path, row.variant
            )),
            "unreached"
                if !reason.is_some_and(|id| {
                    let class = register
                        .reasons
                        .get(id)
                        .and_then(|named| string(&named.fields, "measured"));
                    class == measured
                }) =>
            {
                found.push(format!(
                    "line {line}: the unreached row {}::{} names no reason row of its class",
                    row.enum_path, row.variant
                ))
            }
            _ => {}
        }
    }
    for (id, Reason { line, .. }) in &register.reasons {
        if !cited.contains_key(id.as_str()) {
            found.push(format!(
                "line {line}: no unreached row names the reason row {id}; delete the reason row"
            ));
        }
    }
    let mut keys: BTreeMap<&str, (&str, Option<&str>, Option<&str>)> = BTreeMap::new();
    for (id, Reason { line, fields }) in cited {
        let (kind, missing) = (string(fields, "kind"), string(fields, "missing"));
        if !kind.is_some_and(|kind| KINDS.contains(&kind)) {
            found.push(format!(
                "line {line}: the reason row {id} lacks a kind, one of {}",
                KINDS.join(", ")
            ));
        }
        if !missing.is_some_and(|missing| !missing.trim().is_empty()) {
            found.push(format!(
                "line {line}: the reason row {id} lacks a nonempty missing sentence"
            ));
        }
        let key = id.split_once(':').map_or(id, |(_, key)| key);
        match keys.get(key) {
            Some(&(first, first_kind, first_missing)) => {
                if (first_kind, first_missing) != (kind, missing) {
                    found.push(format!(
                        "line {line}: the reason row {id} differs in kind or missing from \
                         {first}, which shares its key"
                    ));
                }
            }
            None => {
                keys.insert(key, (id, kind, missing));
            }
        }
    }
    let unplaced = register
        .rows
        .iter()
        .filter(|row| row.state == "unplaced")
        .count() as u64;
    if let Some(live) = register.live
        && live != unplaced
    {
        found.push(format!(
            "the register holds {unplaced} unplaced rows and its header's live count is {live}"
        ));
    }
    found
}

fn crate_file(rel: &str) -> Result<Option<String>, String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(rel);
    match std::fs::read_to_string(&path) {
        Ok(text) => Ok(Some(text)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("{rel}: {error}")),
    }
}

fn repository_file(rel: &str) -> String {
    repository_text(rel).unwrap_or_else(|error| panic!("{error}"))
}

fn repository_text(rel: &str) -> Result<String, String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel);
    std::fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))
}

#[test]
fn the_register_matches_the_source() {
    let mut failed = Vec::new();
    for family in FAMILIES {
        let text = match repository_text(&format!("verification/reach/{family}.json")) {
            Ok(text) => text,
            Err(error) => {
                failed.push(error);
                continue;
            }
        };
        let found = violations(&crate_file, family, &text);
        if !found.is_empty() {
            failed.push(format!(
                "verification/reach/{family}.json:\n{}",
                found.join("\n")
            ));
        }
        println!("{}", unmeasured_line(family, &register(&text)));
    }
    assert!(failed.is_empty(), "{}", failed.join("\n"));
}

/// The registers under `verification/reach/` are exactly the families the
/// guard checks, and the tool takes each of those families.
#[test]
fn every_committed_register_is_a_family_the_guard_checks() {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../verification/reach");
    let mut registers = Vec::new();
    for entry in std::fs::read_dir(&directory).expect("the register directory") {
        let path = entry.expect("a directory entry").path();
        if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            let family = path.file_stem().and_then(|stem| stem.to_str());
            registers.push(family.expect("a family name").to_owned());
        }
    }
    registers.sort();
    let mut families = FAMILIES.to_vec();
    families.sort_unstable();
    assert_eq!(registers, families);
    let source = repository_file("verification/reach/tool/src/source.rs");
    let taken = constant(&source, "FAMILIES");
    for family in FAMILIES {
        assert!(taken.iter().any(|name| name == family), "{family}");
    }
}

/// The line the guard prints for `family`: the number of its `unmeasured`
/// rows and the commit of the named run.
fn unmeasured_line(family: &str, register: &Register) -> String {
    let unmeasured = register
        .rows
        .iter()
        .filter(|row| row.state == "unmeasured")
        .count();
    format!(
        "verification/reach/{family}.json: {unmeasured} unmeasured rows since the named run at {}",
        register.commit.as_deref().unwrap_or_default()
    )
}

/// The string values of the one top-level `pub const NAME: [&str; N]`
/// array in `source`.
fn constant(source: &str, name: &str) -> Vec<String> {
    let declaration = format!("\npub const {name}: ");
    let starts: Vec<usize> = source
        .match_indices(&declaration)
        .map(|(at, _)| at)
        .collect();
    let [start] = starts.as_slice() else {
        panic!("`pub const {name}` occurs {} times", starts.len());
    };
    let body = &source[*start..];
    let open = body.find("= [").expect("an array");
    let close = body.find("];").expect("its end");
    body[open..close]
        .split('"')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect()
}

#[test]
fn the_guard_and_the_tool_hold_one_option_list_name_rule_and_family_list() {
    let cfg = repository_file("verification/reach/tool/src/cfg.rs");
    assert_eq!(constant(&cfg, "FALSE"), FALSE);
    let source = repository_file("verification/reach/tool/src/source.rs");
    assert_eq!(constant(&source, "ENDINGS"), ENDINGS);
    assert_eq!(constant(&source, "FAMILIES"), FAMILIES);
    let moved = "//! pub const ENDINGS: [&str; 1] = [\"Old\"];\npub const ENDINGS: [&str; 2] = [\n    \"Error\",\n    \"Refusal\",\n];\n";
    assert_eq!(
        constant(&format!("\n{moved}"), "ENDINGS"),
        ["Error", "Refusal"]
    );
}

#[test]
fn the_guard_and_the_tool_hold_one_list_of_classes_and_one_of_causes() {
    let register = repository_file("verification/reach/tool/src/register.rs");
    assert_eq!(constant(&register, "MEASURED"), MEASURED);
    assert_eq!(constant(&register, "CAUSES"), CAUSES);
}

#[test]
fn the_guard_prints_the_sync_command_the_guide_gives() {
    assert_eq!(
        sync("storage"),
        "run `cargo run --locked --release --manifest-path verification/reach/tool/Cargo.toml -- sync storage` \
         and commit verification/reach/storage.json"
    );
    let guide = repository_file("docs/agents/simulation.md");
    assert!(guide.contains(
        "\ncargo run --locked --release --manifest-path verification/reach/tool/Cargo.toml -- sync storage\n"
    ));
}

/// `struct_fields` pairs each public field name of `pub struct {name}` with
/// whether an attribute precedes it that defaults the field on read and
/// leaves it out of the render when empty, in declaration order.
fn struct_fields(source: &str, name: &str) -> Vec<(String, bool)> {
    let start = source
        .find(&format!("pub struct {name} {{"))
        .unwrap_or_else(|| panic!("`pub struct {name}` in the tool"));
    let body = &source[start..];
    let body = &body[..body.find("\n}").expect("its end")];
    let mut defaulted = false;
    let mut found = Vec::new();
    for line in body.lines().skip(1).map(str::trim) {
        if line.starts_with("#[serde(default, skip_serializing_if = ")
            && line.contains("::is_empty")
        {
            defaulted = true;
        } else if let Some((field, _)) = line
            .strip_prefix("pub ")
            .and_then(|line| line.split_once(':'))
        {
            found.push((field.to_owned(), defaulted));
            defaulted = false;
        }
    }
    found
}

#[test]
fn the_guard_reads_reason_keys_in_the_order_and_with_the_defaults_of_the_tool() {
    let register = repository_file("verification/reach/tool/src/register.rs");
    let reason = struct_fields(&register, "Reason");
    let names: Vec<&str> = reason.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names, REASON_KEYS);
    let required: Vec<&str> = reason
        .iter()
        .filter(|(_, defaulted)| !defaulted)
        .map(|(name, _)| name.as_str())
        .collect();
    assert_eq!(required, REQUIRED_REASON_KEYS);
}

const DISK: &str = "\
pub enum DiskError {
    Full,
    Gone(u8),
    Torn { at: u8 },
    #[cfg(test)]
    Planted,
}
// enum CommentError { A }
const NOTE: &str = \"enum StringError { A }\";
#[cfg(test)]
mod tests {
    enum TestError { A }
}
#[cfg(kani)]
enum ProofError { A }
pub enum DiskState { Idle }
";

const REGISTER: &str = r#"{
"run": {"commit":"0123abc","toolchain":"rustc","flags":"","build":"","worker":"","profiles":[],"roots":"1-50","counts":{},"no_pass":[],"tool":""},
"totals": {"rows":3,"reached":1,"unreached":1,"unplaced":1,"file-not-run":0,"function-not-entered":0,"not-constructed":1},
"live": {"unplaced":1},
"reasons": [
{"id":"not-constructed:storage::disk::DiskError","measured":"not-constructed","kind":"fault","missing":"No profile tears a write.","sentence":""}
],
"rows": [
{"enum":"storage::disk::DiskError","variant":"Full","sites":[["storage/disk.rs","f","path"]],"state":"reached","count":3},
{"enum":"storage::disk::DiskError","variant":"Gone","sites":[],"state":"unplaced","cause":"no-site"},
{"enum":"storage::disk::DiskError","variant":"Torn","sites":[["storage/disk.rs","g","struct"]],"state":"unreached","count":0,"measured":"not-constructed","reason":"not-constructed:storage::disk::DiskError"}
]
}
"#;

const TORN: &str = r#""variant":"Torn""#;

const SYNC: &str = "run `cargo run --locked --release --manifest-path verification/reach/tool/Cargo.toml -- sync storage` \
                    and commit verification/reach/storage.json";

fn tree(entries: &[(&str, &str)], register: &str) -> Vec<String> {
    let mut files = BTreeMap::from([
        (
            "mod.rs",
            "pub mod storage;\nmod sim;\n#[cfg(test)]\nmod tests;\n",
        ),
        ("sim.rs", "pub enum SimError { Lost }\n"),
        (
            "storage/mod.rs",
            "pub mod disk;\n#[cfg(any(test, kani))]\nmod proofs;\n",
        ),
        ("storage/disk.rs", DISK),
    ]);
    files.extend(entries.iter().copied());
    violations(
        &|rel: &str| Ok(files.get(rel).map(|text| (*text).to_owned())),
        "storage",
        register,
    )
}

fn fixture(disk: &str, register: &str) -> Vec<String> {
    tree(&[("storage/disk.rs", disk)], register)
}

fn with_row(row: &str) -> String {
    REGISTER.replace("\n]\n}", &format!(",\n{row}\n]\n}}"))
}

fn one(found: Vec<String>, rule: &str) {
    assert_eq!(found.len(), 1, "{found:#?}");
    assert!(found[0].contains(rule), "{found:#?}");
}

/// The finding for the reason row `id` at `line` that no `unreached` row
/// names.
fn unnamed(line: usize, id: &str) -> String {
    format!("line {line}: no unreached row names the reason row {id}; delete the reason row")
}

#[test]
fn the_fixture_admits_comments_strings_and_gated_items() {
    assert_eq!(fixture(DISK, REGISTER), Vec::<String>::new());
    let unlisted = format!(
        "{DISK}pub enum ErrorKind {{ A }}\npub enum ReasonCode {{ A }}\n#[test]\nfn planted() {{ enum LocalError {{ A }} }}\nimpl DiskError {{\n    #[cfg(test)]\n    fn probe() {{ enum ProbeError {{ A }} }}\n}}\n"
    );
    assert_eq!(fixture(&unlisted, REGISTER), Vec::<String>::new());
}

#[test]
fn an_enum_in_an_inline_module_takes_the_module_in_its_path() {
    let disk = format!("{DISK}pub mod inner {{\n    pub enum InnerRefusal {{ Busy }}\n}}\n");
    one(
        fixture(&disk, REGISTER),
        "storage::disk::inner::InnerRefusal (storage/disk.rs) is a listed enum with no rows",
    );
    let register = with_row(
        r#"{"enum":"storage::disk::inner::InnerRefusal","variant":"Busy","sites":[],"state":"unmeasured"}"#,
    );
    assert_eq!(fixture(&disk, &register), Vec::<String>::new());
    // `mod r#gen` declares the module `gen`, so the row's enum path holds `gen`.
    let raw = format!("{DISK}pub mod r#gen {{\n    pub enum InnerRefusal {{ Busy }}\n}}\n");
    one(
        fixture(&raw, REGISTER),
        "storage::disk::gen::InnerRefusal (storage/disk.rs) is a listed enum with no rows",
    );
    let register = with_row(
        r#"{"enum":"storage::disk::gen::InnerRefusal","variant":"Busy","sites":[],"state":"unmeasured"}"#,
    );
    assert_eq!(fixture(&raw, &register), Vec::<String>::new());
}

/// Each line of the tool's `gating-cases.txt` is `gated` or `kept` and an
/// attribute. The tool's tests read the same file, so the guard and the
/// tool judge one list of attributes.
#[test]
fn each_gating_case_is_listed_exactly_when_it_is_kept() {
    let cases = repository_file("verification/reach/tool/gating-cases.txt");
    let mut disk = String::from(DISK);
    let mut kept = Vec::new();
    let mut gated = 0;
    for (index, line) in cases.lines().enumerate() {
        let (verdict, attribute) = line.split_once(' ').expect("a verdict and an attribute");
        disk.push_str(&format!("{attribute}\npub enum Case{index}Error {{ A }}\n"));
        match verdict {
            "kept" => kept.push(format!(
                "storage::disk::Case{index}Error (storage/disk.rs) is a listed enum with no rows: {SYNC}"
            )),
            "gated" => gated += 1,
            other => panic!("{other}: a verdict is `gated` or `kept`"),
        }
    }
    assert!(gated > 0 && !kept.is_empty());
    assert_eq!(fixture(&disk, REGISTER), kept);
}

#[test]
fn a_variant_without_a_row_fails_and_names_the_sync_command() {
    let disk = DISK.replace(
        "    Torn { at: u8 },\n",
        "    Torn { at: u8 },\n    Lost,\n",
    );
    let found = fixture(&disk, REGISTER);
    one(found.clone(), "storage::disk::DiskError::Lost has no row");
    assert!(found[0].ends_with(SYNC), "{found:#?}");
}

#[test]
fn a_row_without_a_variant_fails_and_names_the_sync_command() {
    let register = with_row(
        r#"{"enum":"storage::disk::DiskError","variant":"Missing","sites":[],"state":"unreached","count":0,"measured":"not-constructed","reason":"not-constructed:storage::disk::DiskError"}"#,
    );
    let found = fixture(DISK, &register);
    one(
        found.clone(),
        "the row storage::disk::DiskError::Missing names no listed variant",
    );
    assert!(found[0].ends_with(SYNC), "{found:#?}");
}

#[test]
fn a_listed_enum_without_rows_fails_and_one_with_no_variant_names_no_sync() {
    let disk = format!("{DISK}pub(crate) enum WriteRefusal {{ Busy }}\n");
    let found = fixture(&disk, REGISTER);
    one(
        found.clone(),
        "storage::disk::WriteRefusal (storage/disk.rs) is a listed enum with no rows",
    );
    assert!(found[0].ends_with(SYNC), "{found:#?}");
    for body in ["{}", "{ #[cfg(test)] Planted }"] {
        let found = fixture(&format!("{DISK}pub enum EmptyError {body}\n"), REGISTER);
        one(
            found.clone(),
            "is a listed enum with no variant the register can hold",
        );
        assert!(!found[0].contains("sync"), "{found:#?}");
    }
}

#[test]
fn an_unreached_row_that_names_no_reason_row_fails() {
    let register = REGISTER.replace(
        r#""reason":"not-constructed:storage::disk::DiskError""#,
        r#""reason":"not-constructed:elsewhere""#,
    );
    let lone = [
        "line 11: the unreached row storage::disk::DiskError::Torn names no reason row of its class"
            .to_owned(),
        unnamed(6, "not-constructed:storage::disk::DiskError"),
    ];
    assert_eq!(fixture(DISK, &register), lone);
    let register = REGISTER.replace(
        r#","reason":"not-constructed:storage::disk::DiskError""#,
        "",
    );
    assert_eq!(fixture(DISK, &register), lone);
}

#[test]
fn a_count_of_unplaced_rows_that_differs_from_the_live_count_fails() {
    for (live, message) in [
        (
            "2",
            "the register holds 1 unplaced rows and its header's live count is 2",
        ),
        (
            "0",
            "the register holds 1 unplaced rows and its header's live count is 0",
        ),
    ] {
        let register = REGISTER.replace(
            r#""live": {"unplaced":1}"#,
            &format!(r#""live": {{"unplaced":{live}}}"#),
        );
        one(fixture(DISK, &register), message);
    }
    let register = REGISTER.replace(r#""live": {"unplaced":1}"#, r#""live": {"unplaced":"1"}"#);
    one(
        fixture(DISK, &register),
        "the header holds no live unplaced count",
    );
}

#[test]
fn an_unmeasured_row_passes_and_one_with_a_count_or_a_reason_fails() {
    let disk = DISK.replace(
        "    Torn { at: u8 },\n",
        "    Torn { at: u8 },\n    Lost,\n",
    );
    let row = r#"{"enum":"storage::disk::DiskError","variant":"Lost","sites":[["storage/disk.rs","h","path"]],"state":"unmeasured""#;
    assert_eq!(
        fixture(&disk, &with_row(&format!("{row}}}"))),
        Vec::<String>::new()
    );
    assert_eq!(
        unmeasured_line("storage", &register(&with_row(&format!("{row}}}")))),
        "verification/reach/storage.json: 1 unmeasured rows since the named run at 0123abc"
    );
    assert_eq!(
        unmeasured_line("storage", &register(REGISTER)),
        "verification/reach/storage.json: 0 unmeasured rows since the named run at 0123abc"
    );
    for carried in [
        r#","count":0}"#,
        r#","reason":"not-constructed:storage::disk::DiskError"}"#,
    ] {
        one(
            fixture(&disk, &with_row(&format!("{row}{carried}"))),
            "the unmeasured row storage::disk::DiskError::Lost carries a count or a reason",
        );
    }
    for carried in [r#","reason":7}"#, r#","reason":null}"#] {
        let found = fixture(&disk, &with_row(&format!("{row}{carried}")));
        assert!(!found.is_empty(), "{carried}");
    }
}

#[test]
fn a_row_whose_fields_differ_from_the_set_of_its_state_fails() {
    let disk = DISK.replace(
        "    Torn { at: u8 },\n",
        "    Torn { at: u8 },\n    Lost,\n",
    );
    let register = with_row(
        r#"{"enum":"storage::disk::DiskError","variant":"Lost","sites":[],"state":"unmeasured"}"#,
    );
    assert_eq!(fixture(&disk, &register), Vec::<String>::new());
    let reason = r#""reason":"not-constructed:storage::disk::DiskError""#;
    for (from, to, row) in [
        (
            r#""state":"reached","count":3"#.to_owned(),
            r#""state":"reached""#.to_owned(),
            "reached row storage::disk::DiskError::Full",
        ),
        (
            r#""state":"reached","count":3"#.to_owned(),
            r#""state":"reached","count":3,"measured":"not-constructed""#.to_owned(),
            "reached row storage::disk::DiskError::Full",
        ),
        (
            r#""state":"reached","count":3"#.to_owned(),
            format!(r#""state":"reached","count":3,{reason}"#),
            "reached row storage::disk::DiskError::Full",
        ),
        (
            r#""state":"reached","count":3"#.to_owned(),
            r#""state":"reached","count":3,"cause":"no-site""#.to_owned(),
            "reached row storage::disk::DiskError::Full",
        ),
        (
            r#""state":"unreached","count":0,"#.to_owned(),
            r#""state":"unreached","#.to_owned(),
            "unreached row storage::disk::DiskError::Torn",
        ),
        (
            r#""count":0,"measured":"not-constructed","#.to_owned(),
            r#""count":0,"#.to_owned(),
            "unreached row storage::disk::DiskError::Torn",
        ),
        (
            r#""count":0,"measured":"not-constructed","#.to_owned(),
            r#""count":0,"measured":"never","#.to_owned(),
            "unreached row storage::disk::DiskError::Torn",
        ),
        (
            format!("{reason}}}"),
            format!(r#"{reason},"cause":"no-site"}}"#),
            "unreached row storage::disk::DiskError::Torn",
        ),
        (
            r#""state":"unplaced","cause":"no-site""#.to_owned(),
            r#""state":"unplaced""#.to_owned(),
            "unplaced row storage::disk::DiskError::Gone",
        ),
        (
            r#""state":"unplaced","cause":"no-site""#.to_owned(),
            r#""state":"unplaced","cause":"elsewhere""#.to_owned(),
            "unplaced row storage::disk::DiskError::Gone",
        ),
        (
            r#""state":"unplaced","cause":"no-site""#.to_owned(),
            r#""state":"unplaced","count":0,"cause":"no-site""#.to_owned(),
            "unplaced row storage::disk::DiskError::Gone",
        ),
        (
            r#""state":"unplaced","cause":"no-site""#.to_owned(),
            r#""state":"unplaced","measured":"not-constructed","cause":"no-site""#.to_owned(),
            "unplaced row storage::disk::DiskError::Gone",
        ),
        (
            r#""state":"unplaced","cause":"no-site""#.to_owned(),
            format!(r#""state":"unplaced",{reason},"cause":"no-site""#),
            "unplaced row storage::disk::DiskError::Gone",
        ),
        (
            r#""state":"unmeasured""#.to_owned(),
            r#""state":"unmeasured","measured":"not-constructed""#.to_owned(),
            "unmeasured row storage::disk::DiskError::Lost",
        ),
        (
            r#""state":"unmeasured""#.to_owned(),
            r#""state":"unmeasured","cause":"no-site""#.to_owned(),
            "unmeasured row storage::disk::DiskError::Lost",
        ),
    ] {
        let broken = register.replace(&from, &to);
        assert_ne!(broken, register, "{from}");
        one(
            fixture(&disk, &broken),
            &format!("the {row} carries fields that differ from the set of its state"),
        );
    }
}

#[test]
fn a_macro_body_is_skipped_and_a_second_row_fails() {
    for skipped in [
        "some_macro! {\n    pub enum ProbeError { A }\n}\n",
        "macro_rules! probe {\n    () => { pub enum ProbeError { A } };\n}\n",
        "macro_rules! probe (\n    () => { mod hidden; }\n);\n",
    ] {
        assert_eq!(
            fixture(&format!("{DISK}{skipped}"), REGISTER),
            Vec::<String>::new()
        );
    }
    let never = format!("{DISK}fn stop() -> ! {{ enum StopError {{ Halt }} loop {{}} }}\n");
    one(
        fixture(&never, REGISTER),
        "storage::disk::StopError (storage/disk.rs) is a listed enum with no rows",
    );
    let register = with_row(
        r#"{"enum":"storage::disk::DiskError","variant":"Full","sites":[],"state":"reached","count":1}"#,
    );
    one(
        fixture(DISK, &register),
        "a second row for storage::disk::DiskError::Full",
    );
}

#[test]
fn a_row_the_guard_cannot_read_fails() {
    let full = r#"{"enum":"storage::disk::DiskError","variant":"Full","sites":[["storage/disk.rs","f","path"]],"state":"reached","count":3},"#;
    for unreadable in [
        REGISTER.replace(TORN, r#""variant":"Torn","extra":1"#),
        REGISTER.replace(r#""state":"reached""#, r#""state":"seen""#),
        REGISTER.replace(r#""sites":[],"#, r#""sites":[,"#),
        REGISTER.replace(r#""sites":[],"#, r#""sites":7,"#),
        REGISTER.replace(r#""sites":[],"#, r#""sites":[["storage/disk.rs","f"]],"#),
        REGISTER.replace(r#""count":3"#, r#""count":"3""#),
        REGISTER.replace(
            r#""sites":[],"state":"unplaced""#,
            r#""state":"unplaced","sites":[]"#,
        ),
        REGISTER.replace(
            r#""count":0,"measured":"not-constructed""#,
            r#""measured":"not-constructed","count":0"#,
        ),
        REGISTER.replace(
            r#""sites":[],"#,
            &format!(r#""sites":{}{},"#, "[".repeat(9), "]".repeat(9)),
        ),
    ] {
        assert_ne!(unreadable, REGISTER);
        let found = fixture(DISK, &unreadable);
        assert!(
            found
                .iter()
                .any(|finding| finding.contains("an unreadable row")),
            "{found:#?}"
        );
    }
    for (broken, problem) in [
        (
            REGISTER.replace(full, full.trim_end_matches(',')),
            "a separator out of place",
        ),
        (
            REGISTER.trim_end().trim_end_matches('}').to_owned(),
            "closing `}`",
        ),
        (
            REGISTER.replace("\"live\"", "\"run\""),
            "the header's \"live\" line is unreadable",
        ),
        (REGISTER.replace("\n]\n}", "\n]\n}\nextra"), "closing `}`"),
        (
            REGISTER.replace(r#","sentence":"""#, ""),
            "an unreadable reason row",
        ),
        (
            REGISTER.replace(r#""kind":"fault""#, r#""kind":7"#),
            "an unreadable reason row",
        ),
        (
            REGISTER.replace(
                r#""missing":"No profile tears a write.""#,
                r#""missing":7"#,
            ),
            "an unreadable reason row",
        ),
        (
            REGISTER.replace(
                r#""measured":"not-constructed","kind""#,
                r#""measured":"never","kind""#,
            ),
            "an unreadable reason row",
        ),
        (
            REGISTER.replacen("{\n", "[\n", 1),
            "the register opens with a line other than `{`",
        ),
        (
            REGISTER.replace("\"reasons\": [", "\"reason\": ["),
            "the reasons array opens with a line other than",
        ),
        (
            REGISTER.replace("\"rows\": [", "\"row\": ["),
            "the rows array opens with a line other than",
        ),
        (
            REGISTER.replace("\n],\n", "\n"),
            "an array with no closing `],` line",
        ),
        (
            REGISTER.replace(
                "\n],\n",
                "\n{\"id\":\"not-constructed:storage::disk::DiskError\",\"measured\":\"not-constructed\",\"sentence\":\"\"}\n],\n",
            )
            .replace("\"sentence\":\"\"}\n{", "\"sentence\":\"\"},\n{"),
            "a second reason row for not-constructed:storage::disk::DiskError, first at line 6",
        ),
        (
            REGISTER.replace(r#""commit":"0123abc","#, ""),
            "the header names no run commit",
        ),
        (
            REGISTER.replace(r#"{"unplaced":1}"#, r#"{"count":1}"#),
            "the header holds no live unplaced count",
        ),
    ] {
        assert_ne!(broken, REGISTER);
        let found = fixture(DISK, &broken);
        assert!(
            found.iter().any(|finding| finding.contains(problem)),
            "{problem}: {found:#?}"
        );
    }
}

#[test]
fn the_reader_decodes_json_escapes_as_the_tool_writes_them() {
    let register = REGISTER
        .replace(
            r#""sentence":"""#,
            "\"sentence\":\"a \\\"quoted\\\" \\\\ \\ud83d\\ude00 \\u00e9\\n\\t\"",
        )
        .replace(r#""variant":"Full""#, r#""variant":"\u0046ull""#);
    assert_eq!(fixture(DISK, &register), Vec::<String>::new());
    for broken in [r#"\ud83d"#, r#"\ude00"#, r#"\u00g1"#, r#"\q"#] {
        let register = REGISTER.replace(r#""sentence":"""#, &format!(r#""sentence":"{broken}""#));
        let found = fixture(DISK, &register);
        assert!(
            found
                .iter()
                .any(|finding| finding.contains("an unreadable reason row")),
            "{broken}"
        );
    }
}

/// A call argument, a parenthesized expression, an array element, an
/// array length and a negated group each hold a block whose items the walk
/// lists. A group under a gating attribute stays out, a parameter's
/// attribute stays inside its parameter list, and the attribute of a match
/// arm or of a field ends at the comma that ends the arm or the field, past
/// the parameters of a closure that is the arm's body or the field's value.
#[test]
fn an_enum_declared_inside_an_expression_group_is_listed() {
    for (holder, name) in [
        (
            "fn hold() { consume({ enum CallError { Lost } }); }\n",
            "CallError",
        ),
        (
            "fn hold() { let _ = ({ enum ParenError { Lost } }); }\n",
            "ParenError",
        ),
        (
            "fn hold() { let _ = [{ enum ArrayError { Lost } 0u8 }]; }\n",
            "ArrayError",
        ),
        (
            "fn hold(_: [u8; { enum LengthError { Lost } 1 }]) {}\n",
            "LengthError",
        ),
        (
            "fn hold(#[cfg(test)] _probe: u8) { enum BodyError { Lost } }\n",
            "BodyError",
        ),
        (
            "fn hold() { if !({ enum NotError { Lost } true }) {} }\n",
            "NotError",
        ),
        (
            "fn hold(x: u8) -> u8 { match x { #[cfg(test)] 0 => 1, _ => consume({ enum LateError { Lost } }) } }\n",
            "LateError",
        ),
        (
            "fn hold(x: u8) -> u8 { match x { #[cfg(test)] 0 => pick::<u8, u8>({ enum EarlyError { Lost } }), _ => consume({ enum LastError { Lost } }) } }\n",
            "LastError",
        ),
        (
            "fn hold() -> S { S { #[cfg(test)] a: consume({ enum GoneError { Lost } }), b: consume({ enum FieldError { Lost } }) } }\n",
            "FieldError",
        ),
        (
            "fn hold(a: u8) -> S { S { #[cfg(test)] a, b: consume({ enum ShortError { Lost } }) } }\n",
            "ShortError",
        ),
        (
            "struct S { #[cfg(test)] pub(crate) a: u8, b: [u8; { enum DeclaredError { Lost } 1 }] }\n",
            "DeclaredError",
        ),
    ] {
        one(
            fixture(&format!("{DISK}{holder}"), REGISTER),
            &format!("storage::disk::{name} (storage/disk.rs) is a listed enum with no rows"),
        );
    }
    for gated in [
        "fn hold() {\n    #[cfg(test)]\n    consume({ enum ProbeError { Lost } });\n}\n",
        "fn hold() -> S { S { #[cfg(test)] a: |x: u8, y: u8| { enum ClosureError { Lost } x }, b: 0 } }\n",
        "fn hold(x: u8) { match x { #[cfg(test)] 0 => move |a: u8, b: u8| { enum MovedError { Lost } a }, _ => drop } }\n",
    ] {
        assert_eq!(
            fixture(&format!("{DISK}{gated}"), REGISTER),
            Vec::<String>::new(),
            "{gated}"
        );
    }
}

#[test]
fn the_walk_follows_every_module_edge_the_tool_follows() {
    let extra = "#[path = \"storage/extra.rs\"]\nmod extra;\npub mod storage;\nmod sim;\n";
    one(
        tree(
            &[
                ("mod.rs", extra),
                ("storage/extra.rs", "pub enum ExtraError { Busy }\n"),
            ],
            REGISTER,
        ),
        "extra::ExtraError (storage/extra.rs) is a listed enum with no rows",
    );
    let renamed = "#[path = \"disk_impl.rs\"]\npub mod disk;\n";
    assert_eq!(
        tree(
            &[("storage/mod.rs", renamed), ("storage/disk_impl.rs", DISK)],
            REGISTER
        ),
        Vec::<String>::new()
    );
    let gated = "pub mod disk;\n#[cfg_attr(test, path = \"other.rs\")]\nmod probe;\n";
    let found = tree(
        &[
            ("storage/mod.rs", gated),
            (
                "storage/probe.rs",
                "#![cfg(test)]\npub enum ProbeError { A }\n",
            ),
        ],
        REGISTER,
    );
    assert_eq!(found, Vec::<String>::new());
    let inline =
        "pub mod disk;\nmod inner {\n    #![cfg(test)]\n    pub enum InnerError { A }\n}\n";
    assert_eq!(
        tree(&[("storage/mod.rs", inline)], REGISTER),
        Vec::<String>::new()
    );
    for (declaration, problem) in [
        (
            "#[cfg_attr(unix, path = \"other.rs\")]\npub mod disk;\n",
            "cfg_attr",
        ),
        (
            "#[path = \"../../x.rs\"]\npub mod disk;\n",
            "outside the source root",
        ),
        (
            "#[path = \"mod.rs\"]\npub mod disk;\n",
            "re-enters this file",
        ),
        (
            "mod outer {\n    #[path = \"x.rs\"]\n    mod disk;\n}\n",
            "inside an inline module",
        ),
    ] {
        let found = tree(&[("storage/mod.rs", declaration)], REGISTER);
        assert!(
            found.iter().any(|finding| finding.contains(problem)),
            "{problem}: {found:#?}"
        );
    }
}

#[test]
fn an_unreadable_module_file_or_two_layouts_fail() {
    let files = BTreeMap::from([
        ("mod.rs", "pub mod storage;\n"),
        ("storage/mod.rs", "pub mod disk;\n"),
        ("storage/disk.rs", DISK),
        ("storage/disk/mod.rs", "pub enum OtherError { A }\n"),
    ]);
    let found = violations(
        &|rel: &str| match rel {
            "storage/disk.rs" => Err(format!("{rel}: permission denied")),
            _ => Ok(files.get(rel).map(|text| (*text).to_owned())),
        },
        "storage",
        REGISTER,
    );
    assert!(
        found
            .iter()
            .any(|finding| finding.contains("permission denied")),
        "{found:#?}"
    );
    let found = violations(
        &|rel: &str| Ok(files.get(rel).map(|text| (*text).to_owned())),
        "storage",
        REGISTER,
    );
    assert!(
        found
            .iter()
            .any(|finding| finding.contains("two files for `mod storage::disk`")),
        "{found:#?}"
    );
}

#[test]
fn a_turbofish_discriminant_and_a_repeated_path_are_read_as_the_tool_reads_them() {
    let disk = DISK.replace("    Full,\n", "    Full = tag::<u8, Vec<u16>>(),\n");
    assert_eq!(fixture(&disk, REGISTER), Vec::<String>::new());
    let twice = format!(
        "{DISK}fn a() {{ enum LocalError {{ A }} }}\nfn b() {{ enum LocalError {{ A }} }}\n"
    );
    let found = fixture(&twice, REGISTER);
    assert!(
        found
            .iter()
            .any(|finding| finding.contains("storage::disk::LocalError is declared twice")),
        "{found:#?}"
    );
}

const WRITTEN: &str = r#""kind":"fault","missing":"No profile tears a write.","#;

#[test]
fn a_cited_reason_row_without_a_kind_or_a_missing_sentence_fails() {
    let reason = "line 6: the reason row not-constructed:storage::disk::DiskError lacks";
    for (unwritten, lacks) in [
        (r#""missing":"No profile tears a write.","#, "a kind"),
        (
            r#""kind":"verdict","missing":"No profile tears a write.","#,
            "a kind",
        ),
        (r#""kind":"fault","#, "a nonempty missing sentence"),
        (
            r#""kind":"fault","missing":" ","#,
            "a nonempty missing sentence",
        ),
        (
            r#""kind":"fault","missing":"\r","#,
            "a nonempty missing sentence",
        ),
        (
            r#""kind":"fault","missing":"\f","#,
            "a nonempty missing sentence",
        ),
        (
            r#""kind":"\fault","missing":"No profile tears a write.","#,
            "a kind",
        ),
    ] {
        let found = fixture(DISK, &REGISTER.replace(WRITTEN, unwritten));
        assert_eq!(found.len(), 1, "{unwritten}: {found:#?}");
        one(found, &format!("{reason} {lacks}"));
    }
    let uncited = REGISTER.replace(WRITTEN, "").replace(
        r#""state":"unreached","count":0,"measured":"not-constructed","reason":"not-constructed:storage::disk::DiskError""#,
        r#""state":"reached","count":1"#,
    );
    assert!(!uncited.contains(r#""kind""#), "{uncited}");
    assert_eq!(
        fixture(DISK, &uncited),
        [unnamed(6, "not-constructed:storage::disk::DiskError")]
    );
    one(
        fixture(
            DISK,
            &uncited.replace(r#""sentence":"""#, r#""kind":1,"sentence":"""#),
        ),
        "line 6: an unreadable reason row",
    );
    let disk = DISK.replace(
        "    Torn { at: u8 },\n",
        "    Torn { at: u8 },\n    Lost,\n",
    );
    let second = with_row(
        r#"{"enum":"storage::disk::DiskError","variant":"Lost","sites":[["storage/disk.rs","h","path"]],"state":"unreached","count":0,"measured":"file-not-run","reason":"file-not-run:storage/disk.rs"}"#,
    )
    .replace(
        "\n],\n\"rows\"",
        ",\n{\"id\":\"file-not-run:storage/disk.rs\",\"measured\":\"file-not-run\",\"sentence\":\"\"}\n],\n\"rows\"",
    );
    let found = fixture(&disk, &second);
    assert_eq!(found.len(), 2, "{found:#?}");
    assert!(
        found.iter().all(|finding| finding
            .starts_with("line 7: the reason row file-not-run:storage/disk.rs lacks")),
        "{found:#?}"
    );
}

/// A reason row stays while an `unreached` row names it. `sync` and
/// `measure` keep every earlier reason row, so one whose last row left it
/// fails here until it is deleted.
#[test]
fn a_reason_row_that_no_unreached_row_names_fails() {
    let added = REGISTER.replace(
        "\n],\n\"rows\"",
        ",\n{\"id\":\"file-not-run:storage/other.rs\",\"measured\":\"file-not-run\",\"kind\":\"step\",\"missing\":\"No profile runs the file.\",\"sentence\":\"\"}\n],\n\"rows\"",
    );
    assert_eq!(
        fixture(DISK, &added),
        [unnamed(7, "file-not-run:storage/other.rs")]
    );
    let torn = r#""state":"unreached","count":0,"measured":"not-constructed","reason":"not-constructed:storage::disk::DiskError""#;
    assert!(REGISTER.contains(torn), "{REGISTER}");
    let own = unnamed(6, "not-constructed:storage::disk::DiskError");
    assert_eq!(
        fixture(
            DISK,
            &REGISTER.replace(torn, r#""state":"reached","count":1"#)
        ),
        [own.as_str()]
    );
    let unmeasured = REGISTER.replace(
        torn,
        r#""state":"unmeasured","reason":"not-constructed:storage::disk::DiskError""#,
    );
    assert_eq!(
        fixture(DISK, &unmeasured),
        [
            "line 11: the unmeasured row storage::disk::DiskError::Torn carries a count or a reason"
                .to_owned(),
            own.clone(),
        ]
    );
}

#[test]
fn a_row_that_names_a_reason_row_of_another_measured_value_fails() {
    let another =
        "the unreached row storage::disk::DiskError::Torn names no reason row of its class";
    let id = "not-constructed:storage::disk::DiskError";
    let entered = "function-not-entered:storage::disk::DiskError";
    one(
        fixture(
            DISK,
            &REGISTER.replace(id, entered).replace(
                r#""measured":"not-constructed","kind""#,
                r#""measured":"function-not-entered","kind""#,
            ),
        ),
        another,
    );
    one(
        fixture(
            DISK,
            &REGISTER.replace(
                r#""measured":"not-constructed","reason""#,
                r#""measured":"file-not-run","reason""#,
            ),
        ),
        another,
    );
}

#[test]
fn a_reason_row_of_an_unlisted_measured_value_fails_cited_or_not() {
    let uncited = |measured: &str| {
        REGISTER.replace(
            "\n],\n\"rows\"",
            &format!(
                ",\n{{\"id\":\"file-not-run:storage/other.rs\",\"measured\":\"{measured}\",\"sentence\":\"\"}}\n],\n\"rows\""
            ),
        )
    };
    assert_eq!(
        fixture(DISK, &uncited("file-not-run")),
        [unnamed(7, "file-not-run:storage/other.rs")]
    );
    one(
        fixture(DISK, &uncited("seen")),
        "line 7: an unreadable reason row",
    );
    let cited = REGISTER.replace(
        r#""measured":"not-constructed","kind""#,
        r#""measured":"seen","kind""#,
    );
    assert_eq!(
        fixture(DISK, &cited),
        [
            "line 6: an unreadable reason row",
            "line 11: the unreached row storage::disk::DiskError::Torn names no reason row of its class",
        ]
    );
}

#[test]
fn a_reason_row_whose_id_opens_with_another_measured_value_fails_cited_or_not() {
    let uncited = |id: &str| {
        REGISTER.replace(
            "\n],\n\"rows\"",
            &format!(
                ",\n{{\"id\":\"{id}\",\"measured\":\"file-not-run\",\"sentence\":\"\"}}\n],\n\"rows\""
            ),
        )
    };
    assert_eq!(
        fixture(DISK, &uncited("file-not-run:storage/other.rs")),
        [unnamed(7, "file-not-run:storage/other.rs")]
    );
    for id in [
        "not-constructed:storage/other.rs",
        "file-not-run",
        "file-not-runs:storage/other.rs",
        "storage/other.rs",
    ] {
        assert_eq!(
            fixture(DISK, &uncited(id)),
            [
                format!(
                    "line 7: the id of the reason row {id} opens with other than `file-not-run:`"
                ),
                unnamed(7, id),
            ]
        );
    }
    let cited = REGISTER.replace(
        "not-constructed:storage::disk::DiskError",
        "file-not-run:storage::disk::DiskError",
    );
    one(
        fixture(DISK, &cited),
        "line 6: the id of the reason row file-not-run:storage::disk::DiskError opens with \
         other than `not-constructed:`",
    );
}

#[test]
fn a_reason_row_that_holds_an_empty_optional_key_fails_cited_or_not() {
    let uncited = |optional: &str| {
        REGISTER.replace(
            "\n],\n\"rows\"",
            &format!(
                ",\n{{\"id\":\"file-not-run:storage/other.rs\",\"measured\":\"file-not-run\",{optional}\"sentence\":\"\"}}\n],\n\"rows\""
            ),
        )
    };
    let other = unnamed(7, "file-not-run:storage/other.rs");
    assert_eq!(fixture(DISK, &uncited("")), [other.as_str()]);
    for (optional, key) in [
        (r#""functions":[],"#, "functions"),
        (r#""kind":"","#, "kind"),
        (r#""missing":"","#, "missing"),
    ] {
        assert_eq!(
            fixture(DISK, &uncited(optional)),
            [
                format!(
                    "line 7: the reason row file-not-run:storage/other.rs holds an empty {key}, \
                     which the tool leaves out"
                ),
                other.clone(),
            ]
        );
    }
    one(
        fixture(
            DISK,
            &REGISTER.replace(
                r#""measured":"not-constructed","kind""#,
                r#""measured":"not-constructed","functions":[],"kind""#,
            ),
        ),
        "line 6: the reason row not-constructed:storage::disk::DiskError holds an empty \
         functions, which the tool leaves out",
    );
}

#[test]
fn cited_reason_rows_that_share_a_key_and_differ_in_kind_or_missing_fail() {
    let disk = DISK.replace(
        "    Torn { at: u8 },\n",
        "    Torn { at: u8 },\n    Lost,\n",
    );
    let copy = |kind: &str, missing: &str| {
        with_row(
            r#"{"enum":"storage::disk::DiskError","variant":"Lost","sites":[["storage/disk.rs","h","path"]],"state":"unreached","count":0,"measured":"function-not-entered","reason":"function-not-entered:storage::disk::DiskError"}"#,
        )
        .replace(
            "\n],\n\"rows\"",
            &format!(
                ",\n{{\"id\":\"function-not-entered:storage::disk::DiskError\",\"measured\":\"function-not-entered\",\"kind\":\"{kind}\",\"missing\":\"{missing}\",\"sentence\":\"\"}}\n],\n\"rows\""
            ),
        )
    };
    assert_eq!(
        fixture(&disk, &copy("fault", "No profile tears a write.")),
        Vec::<String>::new()
    );
    for (kind, missing) in [
        ("fault", "No profile loses a disk."),
        ("step", "No profile tears a write."),
    ] {
        one(
            fixture(&disk, &copy(kind, missing)),
            "line 6: the reason row not-constructed:storage::disk::DiskError differs in kind or \
             missing from function-not-entered:storage::disk::DiskError, which shares its key",
        );
    }
}

#[test]
fn a_register_off_the_layout_the_tool_writes_fails() {
    let row = r#"{"id":"not-constructed:storage::disk::DiskError","measured":"not-constructed","kind":"fault","missing":"No profile tears a write.","sentence":""}"#;
    let other = r#"{"id":"file-not-run:storage/other.rs","measured":"file-not-run","sentence":""}"#;
    for (departed, problem) in [
        (
            REGISTER.replace(row, &format!("{row},")),
            "line 6: a separator out of place",
        ),
        (
            REGISTER.replace(row, &format!("{row}\n{other}")),
            "line 6: a separator out of place",
        ),
        (
            REGISTER.replace(
                "],\n\"rows\"",
                &format!("],\n\"reasons\": [\n{other}\n],\n\"rows\""),
            ),
            "line 8: the rows array opens with a line other than `\"rows\": [`",
        ),
        (
            REGISTER.replace("\n]\n}\n", "\n]\n"),
            "line 13: the register ends with a line other than a closing `}`",
        ),
        (
            REGISTER.replace("\"not-constructed\":1},\n", "\"not-constructed\":1}\n"),
            "line 3: the header's \"totals\" line is unreadable",
        ),
    ] {
        assert_ne!(departed, REGISTER);
        let found = fixture(DISK, &departed);
        assert!(
            found.iter().any(|finding| finding == problem),
            "{problem}: {found:#?}"
        );
    }
}

#[test]
fn a_reason_row_off_the_tools_keys_types_or_escapes_or_a_second_one_for_an_id_fails() {
    let row = r#"{"id":"not-constructed:storage::disk::DiskError","measured":"not-constructed","kind":"fault","missing":"No profile tears a write.","sentence":""}"#;
    assert!(REGISTER.contains(row));
    for unreadable in [
        row.replace(r#""sentence":"""#, r#""sentence":"","note":1"#),
        row.replace(r#""sentence":"""#, r#""sentence":"","kind":"fault""#)
            .replace(r#""kind":"fault","missing""#, r#""missing""#),
        row.replace(r#""kind":"fault","#, r#""kind":"fault","kind":"fault","#),
        row.replace(r#""measured":"not-constructed","#, ""),
        row.replace(r#","sentence":"""#, ""),
        row.replace(r#""sentence":"""#, r#""sentence":null"#),
        row.replace(r#""kind":"fault""#, r#""kind":1"#),
        row.replace(
            r#""measured":"not-constructed","#,
            r#""measured":"not-constructed","functions":[["storage/disk.rs"]],"#,
        ),
        row.replace("No profile", r"\q profile"),
        row.replace("No profile", "No\tprofile"),
    ] {
        let found = fixture(DISK, &REGISTER.replace(row, &unreadable));
        assert!(
            found.len() == 2 && found[0] == "line 6: an unreadable reason row",
            "{unreadable}: {found:#?}"
        );
    }
    let listed = row.replace(
        r#""measured":"not-constructed","#,
        r#""measured":"not-constructed","functions":[["storage/disk.rs","g"]],"#,
    );
    assert_eq!(
        fixture(DISK, &REGISTER.replace(row, &listed)),
        Vec::<String>::new()
    );
    one(
        fixture(DISK, &REGISTER.replace(row, &format!("{row},\n{row}"))),
        "line 7: a second reason row for not-constructed:storage::disk::DiskError, first at line 6",
    );
}

#[test]
fn a_value_the_tool_reader_refuses_fails_the_guard() {
    let unplaced = r#""state":"unplaced","cause":"no-site""#;
    for unreadable in [
        REGISTER.replace(r#""count":3"#, r#""count":03"#),
        REGISTER.replace(unplaced, r#""state":"unplaced","cause":null"#),
        REGISTER.replace(
            unplaced,
            r#""state":"unplaced","cause":"no-site","count":true"#,
        ),
        REGISTER.replace(r#""count":3"#, r#""count":{"n":3}"#),
    ] {
        assert_ne!(unreadable, REGISTER);
        let found = fixture(DISK, &unreadable);
        assert!(
            found
                .iter()
                .any(|finding| finding.contains("an unreadable row")),
            "{found:#?}"
        );
    }
    for (broken, problem) in [
        (
            REGISTER.replace(r#"{"unplaced":1}"#, r#"{"unplaced":01}"#),
            "the header's \"live\" line is unreadable",
        ),
        (
            REGISTER.replace(r#""rows":3,"#, r#""rows":true,"#),
            "the header's \"totals\" line is unreadable",
        ),
        (
            REGISTER.replace(r#""rows":3,"#, ""),
            "the header's totals line differs from the tool's totals",
        ),
        (
            REGISTER.replace(r#""rows":3,"#, r#""rows":"3","#),
            "the header's totals line differs from the tool's totals",
        ),
        (
            REGISTER.replace(r#""counts":{}"#, r#""counts":{"p":null}"#),
            "the header's \"run\" line is unreadable",
        ),
        (
            REGISTER.replace(r#""counts":{}"#, r#""counts":{"p":3}"#),
            "the header's run line differs from the tool's run",
        ),
        (
            REGISTER.replace(r#""roots":"1-50""#, r#""roots":{}"#),
            "the header's run line differs from the tool's run",
        ),
        (
            REGISTER.replace(r#","toolchain":"rustc""#, ""),
            "the header's run line differs from the tool's run",
        ),
    ] {
        assert_ne!(broken, REGISTER);
        let found = fixture(DISK, &broken);
        assert!(
            found.iter().any(|finding| finding.contains(problem)),
            "{problem}: {found:#?}"
        );
    }
    let untooled = REGISTER.replace(r#","tool":"""#, "");
    assert_ne!(untooled, REGISTER);
    assert_eq!(fixture(DISK, &untooled), Vec::<String>::new());
}

#[test]
fn a_count_outside_its_state_or_a_reason_of_another_class_fails() {
    for (from, to, rule) in [
        (
            r#""state":"reached","count":3"#,
            r#""state":"reached","count":0"#,
            "reached row storage::disk::DiskError::Full carries fields",
        ),
        (
            r#""count":0,"measured":"not-constructed""#,
            r#""count":2,"measured":"not-constructed""#,
            "unreached row storage::disk::DiskError::Torn carries fields",
        ),
        (
            r#""count":0,"measured":"not-constructed""#,
            r#""count":0,"measured":"file-not-run""#,
            "the unreached row storage::disk::DiskError::Torn names no reason row of its class",
        ),
    ] {
        let broken = REGISTER.replace(from, to);
        assert_ne!(broken, REGISTER, "{from}");
        one(fixture(DISK, &broken), rule);
    }
}

#[test]
fn the_guard_and_the_tool_hold_one_list_of_states() {
    let register = repository_file("verification/reach/tool/src/register.rs");
    assert_eq!(constant(&register, "STATES"), STATES);
}

#[test]
fn the_reader_reads_arrays_and_objects_nested_to_its_depth_and_no_further() {
    let arrays = |depth: usize| format!(r#"{{"a":{}1{}}}"#, "[".repeat(depth), "]".repeat(depth));
    let objects = |depth: usize| {
        format!(
            r#"{{"a":{}{{}}{}}}"#,
            r#"{"b":"#.repeat(depth - 1),
            "}".repeat(depth - 1)
        )
    };
    for nested in [arrays, objects] {
        assert!(object(&nested(DEPTH)).is_some(), "{}", nested(DEPTH));
        assert!(
            object(&nested(DEPTH + 1)).is_none(),
            "{}",
            nested(DEPTH + 1)
        );
    }
}
