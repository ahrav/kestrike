//! What the catalog's check knows of files before it reads a row: the kernel package's texts and the
//! defects of their includes, the files each module declaration of the crate loads, the standing of each
//! file the package includes from the crate, a loom test's model source and its message literals, the
//! `check!` messages of a kernel text, and the tests and bindings a row may cite.
//!
//! A loom test is named by its whole module path. Its model source is the one module file that path
//! reaches from `crates/kestrike/src/mod.rs`: each module the path names is loaded by a declaration
//! the reading of a parent's module declarations finds in its parent, a `#[path]` one or a bare `mod name;`, and the last file reached
//! declares the remaining module inline. A module that its parent declares more than once, inline or
//! by two files, has none.
//!
//! An included file stands as production when a chain of live declarations from a crate root (`mod.rs`,
//! `lib.rs` or `main.rs` of the crate's source directory) loads it, and as excluded when every chain
//! that loads it passes a test-only item. A bare `mod name;` loads `name.rs` or `name/mod.rs` from the
//! directory its module file's declarations load from: the crate's source directory for a root, `D` for
//! `D/mod.rs` and for the sibling `D.rs`, and its own directory for a file a path attribute loads. A
//! `#[path = "..."]` on a `mod` item loads that path from the module file's own directory, and inside
//! inline `mod` blocks both load from the declaring directory extended by the blocks' names. A path
//! attribute counts in a root, in a module file whose bare declarations load from the included file's
//! directory, and nowhere else. Among a macro's tokens a path attribute or a `mod` keyword loads
//! nothing and is refused.
//!
//! Repository paths are texts relative to the checkout's top. A path joins with `/`, drops empty and
//! `.` components and keeps `..`, and a root of exactly two slashes stays; a path attribute's target is
//! also normalized lexically, each `..` dropping the component before it. Paths sort component by
//! component, and the include defects by their file's path as text. A refusal is the catalog check's
//! `scope file` refusal with its sentence, in the order the rules meet it; the classification gives each
//! distinct sentence once. Offsets are byte offsets of the source, which its scanned texts share, and
//! each window before a bracket spans 40 code points of the source. A word edge of a pattern stands
//! where [`is_word`] holds on one side only, a letter, a number or `_` of any script.
//!
//! Each function trusts the directories its caller names, the kernel package, the checkout root and
//! the crate tree, and reads every link in them as it stands.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;

use super::sites::{MACRO, call_end, line_of, opener};
use crate::classes::{SPACE, WORD, bounded_iter, captures_bounded, compiled, is_word};
use crate::genmc::{INCLUDED, is_file, no_nul, package_sources, read_text, under_target, walk};
use crate::json::{Text, Value};
use crate::paths::{normalize, resolve};
use crate::production_text::blanked;
use crate::rust_text::{Lexeme, back, blank, code, lexemes};
use crate::text::is_space;

/// The crate whose module tree holds the model sources and the included production files.
const CRATE: &str = "crates/kestrike/src";

/// The name of every refusal this module gives.
const SCOPE_FILE: &str = "scope file";

/// A reader of repository paths: the text at a path relative to the checkout's top, or the error of
/// reading it, [`io::ErrorKind::NotFound`] for a file that does not exist.
pub type Reader<'r> = &'r dyn Fn(&str) -> io::Result<String>;

/// One refusal of the catalog's check, a `scope file` refusal with its sentence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    message: String,
}

impl Refusal {
    fn scope(message: String) -> Self {
        Self { message }
    }

    /// The refusal's name in the check's report.
    pub fn name(&self) -> &'static str {
        SCOPE_FILE
    }

    /// The refusal's sentence.
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// The root of `path`: `//` when exactly two slashes lead it, `/` for one or three or more, else none.
fn root(path: &str) -> &'static str {
    if path.starts_with("//") && !path.starts_with("///") {
        "//"
    } else if path.starts_with('/') {
        "/"
    } else {
        ""
    }
}

/// The root of a repository path's text and its other components, with empty and `.` components
/// dropped.
fn parts(path: &str) -> (&str, Vec<&str>) {
    let root = root(path);
    let names = path
        .split('/')
        .filter(|name| !name.is_empty() && *name != ".")
        .collect();
    (root, names)
}

fn assembled(root: &str, names: &[&str]) -> String {
    if names.is_empty() && root.is_empty() {
        ".".to_owned()
    } else {
        format!("{root}{}", names.join("/"))
    }
}

/// The text of `path` with empty and `.` components dropped, `..` kept.
fn pure(path: &str) -> String {
    let (root, names) = parts(path);
    assembled(root, &names)
}

/// `name` joined to `base`; an absolute `name` replaces `base`.
fn joined(base: &str, name: &str) -> String {
    if name.starts_with('/') {
        return pure(name);
    }
    let (root, mut names) = parts(base);
    names.extend(parts(name).1);
    assembled(root, &names)
}

fn parent(path: &str) -> String {
    let (root, mut names) = parts(path);
    names.pop();
    assembled(root, &names)
}

fn name(path: &str) -> &str {
    parts(path).1.last().copied().unwrap_or("")
}

/// The suffix of `path`'s name: from its last `.`, unless that `.` leads or ends the name.
fn name_suffix(path: &str) -> &str {
    let name = name(path);
    match name.rfind('.') {
        Some(at) if at > 0 && at < name.len() - 1 => &name[at..],
        _ => "",
    }
}

fn stem(path: &str) -> &str {
    let name = name(path);
    &name[..name.len() - name_suffix(path).len()]
}

/// `path` with the suffix of its name replaced by `suffix`.
///
/// # Errors
///
/// `with_suffix` refuses a path with an empty name, such as `.`.
fn with_suffix(path: &str, suffix: &str) -> io::Result<String> {
    if name(path).is_empty() {
        return Err(io::Error::other(format!("{path} has an empty name")));
    }
    Ok(joined(&parent(path), &format!("{}{suffix}", stem(path))))
}

/// The lexical normal form of `path`: each `..` drops the component before it, and a `..` that leads
/// an absolute path is dropped.
fn normpath(path: &str) -> String {
    String::from_utf8(normalize(path.as_bytes())).expect("a UTF-8 path normalizes to UTF-8")
}

/// Whether the name of `path` ends in `.rs`.
fn named_rs(path: &Path) -> bool {
    path.file_name()
        .is_some_and(|name| name.as_encoded_bytes().ends_with(b".rs"))
}

/// The text of `path`.
///
/// # Errors
///
/// `text_of` refuses a path that is no UTF-8.
fn text_of(path: &Path) -> io::Result<String> {
    path.to_str().map(str::to_owned).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is no UTF-8 path", path.display()),
        )
    })
}

/// The start of a path attribute, `#[path` or `#![path`, or of `#[cfg_attr(` whose `path =` [`path_attributes`]
/// looks for in code.
static ATTRIBUTE_HEAD: LazyLock<Regex> = LazyLock::new(|| {
    compiled(&format!(
        r"\A#{SPACE}*!?{SPACE}*\[{SPACE}*(?:path|cfg_attr{SPACE}*\()"
    ))
});

static ASSIGNED: LazyLock<Regex> = LazyLock::new(|| compiled(&format!(r"\A{SPACE}*=")));

/// A `#[path = "..."]` attribute on a `mod` item declared by a file, other outer attributes and a
/// visibility between them: group `path` holds the path, `mod` the keyword and `name` the module.
static DECLARED: LazyLock<Regex> = LazyLock::new(|| {
    compiled(&format!(
        r#"#{SPACE}*\[{SPACE}*path{SPACE}*={SPACE}*"(?P<path>[^"]*)"{SPACE}*\]{SPACE}*(?:#{SPACE}*\[[^\]]*\]{SPACE}*)*(?:pub(?:\([^)]*\))?{SPACE}+)?(?P<mod>mod){SPACE}+(?:r#)?(?P<name>{WORD}+){SPACE}*;"#
    ))
});

static INLINE: LazyLock<Regex> =
    LazyLock::new(|| compiled(&format!(r"mod{SPACE}+(?:r#)?({WORD}+){SPACE}*\{{")));

static BARE: LazyLock<Regex> =
    LazyLock::new(|| compiled(&format!(r"mod{SPACE}+(?:r#)?({WORD}+){SPACE}*;")));

static INCLUDE: LazyLock<Regex> = LazyLock::new(|| compiled("include"));

/// An assertion, a panic or an `expect` named at the end of a window before its bracket.
static DIAGNOSTIC: LazyLock<Regex> = LazyLock::new(|| {
    compiled(&format!(
        r"(?:(?:assert|assert_eq|assert_ne|debug_assert|debug_assert_eq|debug_assert_ne|panic|unreachable)!|\.{SPACE}*expect){SPACE}*\z"
    ))
});

static CHECK: LazyLock<Regex> = LazyLock::new(|| compiled(&format!(r"check{SPACE}*!{SPACE}*\z")));

static LAST_ARGUMENT: LazyLock<Regex> =
    LazyLock::new(|| compiled(&format!(r"\A{SPACE}*,?{SPACE}*\)")));

/// The code points of the source in each window before a bracket.
const WINDOW: usize = 40;

/// The `(start, end)` of each path attribute of `text` in order, each search resuming at the end of the
/// last: `#[path` or `#![path` with no word character after `path`, or `#[cfg_attr(` with a `path` that
/// no word character precedes, then white space and `=`, before the first `]`. A `cfg_attr` match ends
/// at the `=` after the last such `path`.
fn path_attributes(text: &str) -> Vec<(usize, usize)> {
    let mut found = Vec::new();
    let mut at = 0;
    while let Some(offset) = text[at..].find('#') {
        let start = at + offset;
        let Some(head) = ATTRIBUTE_HEAD.find(&text[start..]) else {
            at = start + 1;
            continue;
        };
        let head_end = start + head.end();
        let end = if head.as_str().ends_with("path") {
            let after = text[head_end..].chars().next();
            (!after.is_some_and(is_word)).then_some(head_end)
        } else {
            cfg_path(text, head_end)
        };
        match end {
            Some(end) => {
                found.push((start, end));
                at = end;
            }
            None => at = start + 1,
        }
    }
    found
}

/// The end of the `=` after the last `path` between `from` and the first `]` after it that no word
/// character precedes and white space and `=` follow.
fn cfg_path(text: &str, from: usize) -> Option<usize> {
    let close = text[from..]
        .find(']')
        .map_or(text.len(), |offset| from + offset);
    let region = &text[from..close];
    region
        .match_indices("path")
        .filter(|&(offset, _)| {
            !text[..from + offset]
                .chars()
                .next_back()
                .is_some_and(is_word)
        })
        .filter_map(|(offset, _)| {
            let after = from + offset + "path".len();
            ASSIGNED
                .find(&text[after..])
                .map(|assigned| after + assigned.end())
        })
        .last()
}

/// The offset of the first `mod` keyword of `text` that neither `#` nor a word character precedes and no
/// word character follows.
fn mod_keyword(text: &str) -> Option<usize> {
    text.match_indices("mod")
        .map(|(offset, _)| offset)
        .find(|&offset| {
            let before = text[..offset].chars().next_back();
            let after = text[offset + 3..].chars().next();
            !before.is_some_and(|c| c == '#' || is_word(c)) && !after.is_some_and(is_word)
        })
}

/// What the module declarations of one module file load.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Loads {
    bare: BTreeSet<String>,
    attributed: BTreeMap<String, BTreeSet<String>>,
    refusals: Vec<Refusal>,
}

impl Loads {
    /// Whether a path attribute loads `path`, when `attribute`, or else a bare declaration.
    fn holds(&self, path: &str, attribute: bool) -> bool {
        if attribute {
            self.attributed.contains_key(path)
        } else {
            self.bare.contains(path)
        }
    }
}

/// What the module declarations of the module file `module`, whose text is `source` and whose bare
/// declarations load from the directory `child`, load: when `live`, the declarations outside test-only
/// items, else every declaration outside comments and literals. `bare` holds `name.rs` and `name/mod.rs`
/// of each bare `mod name;`; `attributed` holds each file a path attribute loads with the names it is
/// declared under, a name inside inline modules prefixed by theirs and
/// `::`; `refusals` holds a declaration among a macro's tokens, a path attribute that holds an escape,
/// and a path attribute the reading cannot pair with a declaration.
///
/// Among a macro's tokens a path attribute or a `mod` keyword is refused and loads nothing: a
/// definition's body declares only where it is invoked, and an invocation may drop its tokens or turn
/// them into a declaration. A macro found among the tokens of an earlier one has no tokens of its own.
fn loads(module: &str, child: &str, source: &str, live: bool) -> Loads {
    let (text, scanned) = if live {
        blanked(source)
    } else {
        (source.to_owned(), code(source))
    };
    let (text, scanned) = (text.as_str(), scanned.as_str());
    let mut found = Loads::default();
    let mut view = scanned.to_owned();
    for head in bounded_iter(&MACRO, scanned) {
        let whole = head.get_match();
        let end = call_end(&view, whole.end() - 1);
        let tokens = &view[whole.end()..end];
        if mod_keyword(tokens).is_some() || !path_attributes(tokens).is_empty() {
            found.refusals.push(Refusal::scope(format!(
                "{module}:{}: a module declaration inside a macro's tokens, which the scope rule \
                 cannot read",
                line_of(&view, whole.start())
            )));
        }
        let hidden = blank(tokens);
        view.replace_range(whole.end()..end, &hidden);
    }
    let inline: Vec<(String, usize, usize)> = bounded_iter(&INLINE, &view)
        .map(|block| {
            let open = block.get_match().end() - 1;
            let name = block
                .get(1)
                .expect("INLINE has group 1")
                .as_str()
                .to_owned();
            (name, open, call_end(&view, open))
        })
        .collect();
    let enclosing = |offset: usize| -> Vec<&str> {
        inline
            .iter()
            .filter(|&&(_, low, high)| low < offset && offset < high)
            .map(|(name, _, _)| name.as_str())
            .collect()
    };
    let mut marked = BTreeSet::new();
    for declared in DECLARED.captures_iter(text) {
        let start = declared.get_match().start();
        if view.as_bytes()[start] != b'#' {
            continue;
        }
        marked.insert(declared.name("mod").expect("DECLARED has mod").start());
        let inside = enclosing(start);
        let target = declared.name("path").expect("DECLARED has path").as_str();
        if target.contains('\\') {
            found.refusals.push(Refusal::scope(format!(
                "{module}:{}: the path attribute holds an escape the scope rule cannot read",
                line_of(text, start)
            )));
            continue;
        }
        let base = if inside.is_empty() {
            parent(module)
        } else {
            joined(child, &inside.join("/"))
        };
        let target = normpath(&joined(&base, target));
        let mut names = inside.clone();
        names.push(declared.name("name").expect("DECLARED has name").as_str());
        let name = names.join("::");
        found.attributed.entry(target).or_default().insert(name);
    }
    if path_attributes(&view).len() != marked.len() {
        found.refusals.push(Refusal::scope(format!(
            "{module} holds a path attribute the scope rule cannot read"
        )));
    }
    for declaration in bounded_iter(&BARE, &view) {
        let start = declaration.get_match().start();
        if marked.contains(&start) {
            continue;
        }
        let name = declaration.get(1).expect("BARE has group 1").as_str();
        let home = joined(child, &enclosing(start).join("/"));
        found.bare.insert(joined(&home, &format!("{name}.rs")));
        found.bare.insert(joined(&home, &format!("{name}/mod.rs")));
    }
    found
}

/// (the repository path, the text) of the model source of loom test `test`, read down from the crate's
/// `mod.rs` through `read`: each module the path names is loaded by a declaration the reading of module declarations finds in its
/// parent with comments and literals passed over, and the last file reached declares the remaining
/// module inline. `None` when a declaration or the file it loads is missing, or when a parent declares
/// one module more than once, inline or by two files, which only a `cfg` this lookup does not evaluate
/// tells apart. A read error of any kind counts as a missing file, so `name/mod.rs` stands for a
/// `name.rs` that cannot be read.
pub fn module_file(test: &str, read: Reader<'_>) -> Option<(String, String)> {
    let mut names: Vec<&str> = test.split("::").collect();
    names.pop();
    let mut names = names.as_slice();
    let mut home = CRATE.to_owned();
    let mut path = joined(&home, "mod.rs");
    let mut text = read(&path).ok();
    while let (Some(current), Some((&first, rest))) = (&text, names.split_first()) {
        let scanned = code(current);
        let declared = loads(&path, &home, current, false);
        let paths: Vec<&str> = declared
            .attributed
            .iter()
            .filter(|(_, names)| names.contains(first))
            .map(|(target, _)| target.as_str())
            .collect();
        let inline = opens_inline(&scanned, first);
        let bare = declared
            .bare
            .contains(&joined(&home, &format!("{first}.rs")));
        if paths.len() + usize::from(bare) + usize::from(inline) != 1 {
            return None;
        }
        if inline {
            break;
        }
        let files: Vec<String> = if paths.is_empty() {
            vec![
                joined(&home, &format!("{first}.rs")),
                joined(&home, &format!("{first}/mod.rs")),
            ]
        } else {
            paths.iter().map(|target| pure(target)).collect()
        };
        let chosen = files
            .iter()
            .find(|file| read(file).ok().is_some())
            .unwrap_or(&files[0])
            .clone();
        home = if !paths.is_empty() || name(&chosen) == "mod.rs" {
            parent(&chosen)
        } else {
            with_suffix(&chosen, "").expect("a declared module file has a name")
        };
        text = read(&chosen).ok();
        path = chosen;
        names = rest;
    }
    text.map(|text| (path, text))
}

/// Whether `scanned` opens an inline module named `name`: `mod` with no word character before it, white
/// space, an optional `r#`, `name` as written, optional white space and `{`. The white space after `mod`
/// may end inside `name` when `name` opens with white space.
fn opens_inline(scanned: &str, name: &str) -> bool {
    scanned.match_indices("mod").any(|(at, _)| {
        if scanned[..at].chars().next_back().is_some_and(is_word) {
            return false;
        }
        let rest = &scanned[at + 3..];
        let spaces: Vec<usize> = rest
            .char_indices()
            .take_while(|&(_, c)| is_space(u32::from(c)))
            .map(|(offset, c)| offset + c.len_utf8())
            .collect();
        spaces.iter().any(|&after| {
            let tail = &rest[after..];
            [tail.strip_prefix("r#"), Some(tail)]
                .into_iter()
                .flatten()
                .filter_map(|tail| tail.strip_prefix(name))
                .any(|tail| {
                    tail.trim_start_matches(|c: char| is_space(u32::from(c)))
                        .starts_with('{')
                })
        })
    })
}

/// The text of the model source [`module_file`] finds for loom test `test`.
pub fn module_source(test: &str, read: Reader<'_>) -> Option<String> {
    module_file(test, read).map(|(_, text)| text)
}

/// The contents of the string literals of `text` passed to an assertion, a panic or an `expect`.
pub fn diagnostics(text: &str) -> Vec<String> {
    diagnostic_sites(text)
        .into_iter()
        .map(|(content, _)| content)
        .collect()
}

/// (content, line) of each string literal of `text` whose innermost open bracket follows, within 40
/// code points, the name of an assertion macro, `panic!`, `unreachable!` or an `expect` method; the
/// line is that of the macro or method name, where a panic it raises reports its location.
pub fn diagnostic_sites(text: &str) -> Vec<(String, usize)> {
    let view = code(text);
    let mut found = Vec::new();
    for (kind, start, end) in lexemes(text) {
        if kind != Lexeme::String {
            continue;
        }
        let Some(index) = opener(&view, start) else {
            continue;
        };
        let window = back(text, index, WINDOW);
        let Some(named) = captures_bounded(&DIAGNOSTIC, &view[window..index], 0) else {
            continue;
        };
        let name = named.get_match().as_str();
        let leading = name.len() - name.trim_start_matches(['.', ' ', '\t', '\n']).len();
        let macro_at = window + named.get_match().start() + leading;
        let lexeme = &text[start..end];
        let open = lexeme.find('"').expect("a string lexeme holds a quote");
        let close = lexeme.rfind('"').expect("a string lexeme holds a quote");
        found.push((
            lexeme[open + 1..close.max(open + 1)].to_owned(),
            line_of(text, macro_at),
        ));
    }
    found
}

/// (path, line) of the one assertion, panic or `expect` in the model source of loom test `test` whose
/// message literal holds `failure`, or `None` when no model source or other than one such literal
/// stands there.
pub fn loom_site(test: &str, failure: &str, read: Reader<'_>) -> Option<(String, usize)> {
    let (path, text) = module_file(test, read)?;
    let lines: Vec<usize> = diagnostic_sites(&text)
        .into_iter()
        .filter(|(content, _)| content.contains(failure))
        .map(|(_, line)| line)
        .collect();
    match lines.as_slice() {
        [line] => Some((path, *line)),
        _ => None,
    }
}

/// The contents of the `c"..."` literals of `text` that are the last argument of a `check!` call, its
/// message: the `c` stands right before the quote with no word character before it, the literal's
/// innermost open bracket follows `check!` within 40 code points, and only white space and one comma
/// stand between the literal and the call's `)`.
pub fn c_literals(text: &str) -> Vec<String> {
    let view = code(text);
    let mut found = Vec::new();
    for (kind, start, end) in lexemes(text) {
        let prefixed = kind == Lexeme::String
            && text.as_bytes()[start] == b'"'
            && start > 0
            && text.as_bytes()[start - 1] == b'c'
            && !text[..start - 1].chars().next_back().is_some_and(is_word);
        if !prefixed {
            continue;
        }
        let Some(index) = opener(&view, start) else {
            continue;
        };
        let window = back(text, index, WINDOW);
        if captures_bounded(&CHECK, &view[window..index], 0).is_some()
            && LAST_ARGUMENT.is_match(&view[end..])
        {
            found.push(text[start + 1..end - 1].to_owned());
        }
    }
    found
}

/// The text of each Rust source of the kernel package at `package`, keyed by its path relative to
/// `package`: each regular file, or link to one, under it named `*.rs`, with build state under a
/// `target` component aside. A directory named like a source is passed over, as is a link that loops.
///
/// # Errors
///
/// `kernel_texts` returns an error of [`walk`] or [`is_file`], the error of reading a source, of kind
/// [`io::ErrorKind::InvalidData`] for one that is no UTF-8, and an error of that kind for a path that
/// is no UTF-8.
pub fn kernel_texts(package: &Path) -> io::Result<BTreeMap<String, String>> {
    let mut texts = BTreeMap::new();
    for path in walk(package)? {
        if !named_rs(&path) || !is_file(&path)? || under_target(&path, package) {
            continue;
        }
        let relative = path.strip_prefix(package).unwrap_or(&path);
        texts.insert(text_of(relative)?, read_text(&path)?);
    }
    Ok(texts)
}

/// The `scope file` refusals of what makes the `#[path]` includes of each kernel source in `kernels`
/// differ from what [`INCLUDED`] reads, the sources in the order of their paths as text, each named as
/// `<package name>/<path>`: the name `include` in its code, a path attribute in its code that the
/// scanner misses, a scanner match outside its code, an include path that holds a backslash, and an
/// include that resolves inside `package` to no source of `kernels`.
///
/// # Errors
///
/// `include_defects` returns the error of [`resolve`] for `package` or for an include path, which
/// refuses one whose lookup meets a link loop.
pub fn include_defects(
    package: &Path,
    kernels: &BTreeMap<String, String>,
) -> io::Result<Vec<Refusal>> {
    let mut defects = Vec::new();
    let package_name = match package.components().next_back() {
        Some(Component::Normal(name)) => name.to_string_lossy().into_owned(),
        Some(Component::ParentDir) => "..".to_owned(),
        _ => String::new(),
    };
    for (path, text) in kernels {
        let view = code(text);
        let live: BTreeSet<usize> = path_attributes(&view)
            .into_iter()
            .map(|(start, _)| start)
            .collect();
        let mut read = BTreeMap::new();
        for found in INCLUDED.captures_iter(text) {
            let whole = found.get_match();
            let hash = whole.start() + whole.as_str().find('#').expect("INCLUDED holds `#`");
            read.insert(hash, found.get(1).expect("INCLUDED has group 1").as_str());
        }
        let place = |offset: usize| format!("{package_name}/{path}:{}", line_of(text, offset));
        for found in bounded_iter(&INCLUDE, &view) {
            defects.push(Refusal::scope(format!(
                "{}: an include! macro, whose source the scope rule does not read",
                place(found.get_match().start())
            )));
        }
        for offset in live.iter().filter(|offset| !read.contains_key(offset)) {
            defects.push(Refusal::scope(format!(
                "{}: a path attribute the include scanner misses",
                place(*offset)
            )));
        }
        for offset in read.keys().filter(|offset| !live.contains(offset)) {
            defects.push(Refusal::scope(format!(
                "{}: the include scanner reads a path attribute outside live code",
                place(*offset)
            )));
        }
        let source_dir = package.join(path);
        let source_dir = source_dir.parent().unwrap_or(package);
        for (&offset, &target) in &read {
            let resolved = resolve(&source_dir.join(no_nul(target)?))?;
            let repr = Text::from(target).repr();
            if target.contains('\\') {
                defects.push(Refusal::scope(format!(
                    "{}: the include path {repr} holds an escape",
                    place(offset)
                )));
                continue;
            }
            let home = resolve(package)?;
            if let Ok(relative) = resolved.strip_prefix(&home)
                && !relative
                    .to_str()
                    .is_some_and(|relative| kernels.contains_key(&pure(relative)))
            {
                defects.push(Refusal::scope(format!(
                    "{}: the include {repr} is no Rust source of the package the scan reads",
                    place(offset)
                )));
            }
        }
    }
    Ok(defects)
}

/// The crate sources under the tree `tree`, relative to it and in component order, whose text holds a
/// path attribute; a source that cannot be read holds none.
///
/// # Errors
///
/// `path_holders` returns an error of [`walk`] or [`is_file`], and an error of kind
/// [`io::ErrorKind::InvalidData`] for a path that is no UTF-8.
fn path_holders(tree: &Path) -> io::Result<Vec<String>> {
    let mut sources: Vec<PathBuf> = walk(&tree.join(CRATE))?
        .into_iter()
        .filter(|path| named_rs(path))
        .collect();
    sources.sort();
    let mut holders = Vec::new();
    for path in sources {
        if is_file(&path)? && !path_attributes(&read_text(&path).unwrap_or_default()).is_empty() {
            holders.push(text_of(path.strip_prefix(tree).unwrap_or(&path))?);
        }
    }
    Ok(holders)
}

/// The longest chain of module files, each declared by the next, that the classification follows.
pub const CHAIN: usize = 400;

/// The standing a declaration gives an included file, in rank order: a file with several standings
/// takes the first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Standing {
    Production,
    /// Declared by a path attribute of a file whose place in the crate the rules do not read.
    Elsewhere,
    Excluded,
    /// A module file that would declare it cannot be read.
    Unreadable,
}

/// The standings a bare declaration and a path attribute give a file, in that order.
type Standings = [Option<Standing>; 2];

/// The first of `left` and `right` in rank order, or `None` when both are.
fn first(left: Option<Standing>, right: Option<Standing>) -> Option<Standing> {
    left.into_iter().chain(right).min()
}

/// The file names the path attributes of `text` declare.
fn declared_names(text: &str) -> impl Iterator<Item = String> + '_ {
    DECLARED
        .captures_iter(text)
        .map(|declared| name(declared.name("path").expect("DECLARED has path").as_str()).to_owned())
}

/// The text a module file holds for the classification.
#[derive(Clone)]
enum Source {
    Text(String),
    Absent,
    Failed(String),
}

/// The production and excluded files the kernel package includes from outside itself, and the
/// refusals of their classification.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Scope {
    included: Vec<String>,
    excluded: Vec<String>,
    refusals: Vec<Refusal>,
}

impl Scope {
    /// The included files that stand as production, relative to the checkout, in the order of the
    /// package's sources.
    pub fn included(&self) -> &[String] {
        &self.included
    }

    /// The included files that every chain of declarations loads through a test-only item.
    pub fn excluded(&self) -> &[String] {
        &self.excluded
    }

    /// The refusals: an include outside the repository, a file declared only by a path attribute
    /// elsewhere, one no module file declares, a module file that cannot be read, and the declaration
    /// refusals of the reading of module declarations, each distinct sentence once.
    pub fn refusals(&self) -> &[Refusal] {
        &self.refusals
    }
}

/// The state of one classification: the texts read, the readings made and the standings found.
struct Classifier<'r> {
    read: Reader<'r>,
    roots: [String; 3],
    texts: BTreeMap<String, Source>,
    parsed: BTreeMap<(String, String, bool), Loads>,
    places: BTreeMap<String, Standings>,
    holders: Vec<String>,
    pathed: BTreeSet<String>,
    scope: Scope,
    /// The module files whose standings are being found, one inside the next.
    depth: usize,
}

impl Classifier<'_> {
    fn once(&mut self, message: String) {
        if !self
            .scope
            .refusals
            .iter()
            .any(|refusal| refusal.message == message)
        {
            self.scope.refusals.push(Refusal::scope(message));
        }
    }

    /// The text of `module` through the reader, read once.
    fn source(&mut self, module: &str) -> Source {
        if !self.texts.contains_key(module) {
            let source = match (self.read)(module) {
                Ok(text) => Source::Text(text),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Source::Absent,
                Err(error) => Source::Failed(error.to_string()),
            };
            self.texts.insert(module.to_owned(), source);
        }
        self.texts[module].clone()
    }

    /// `loads` of `module`, its bare declarations loading from `child`: of its live declarations, or
    /// of all of them with comments and literals passed over. The module's text has been read.
    fn parse(&mut self, module: &str, child: &str, live: bool) -> &Loads {
        let key = (module.to_owned(), child.to_owned(), live);
        if !self.parsed.contains_key(&key) {
            let Some(Source::Text(text)) = self.texts.get(module) else {
                unreachable!("a module file is parsed after its text is read");
            };
            let found = loads(module, child, text, live);
            for refusal in found.refusals.clone() {
                self.once(refusal.message);
            }
            self.parsed.insert(key.clone(), found);
        }
        &self.parsed[&key]
    }

    /// The standing a bare declaration gives crate source `file` and the standing a path attribute
    /// gives it. A file whose standing is being found has none.
    fn place(&mut self, file: &str) -> io::Result<Standings> {
        if let Some(&found) = self.places.get(file) {
            return Ok(found);
        }
        if self.depth == CHAIN {
            return Err(io::Error::other(format!(
                "module files chain more than {CHAIN} deep at {file}"
            )));
        }
        self.places.insert(file.to_owned(), [None, None]);
        self.depth += 1;
        let found = if self.roots.iter().any(|root| root == file) {
            Ok([Some(Standing::Production); 2])
        } else {
            self.declared(file).map(|(standings, _)| standings)
        };
        self.depth -= 1;
        let found = found?;
        self.places.insert(file.to_owned(), found);
        Ok(found)
    }

    /// The module files whose bare declarations load from `directory`, the directory of `file`: its
    /// `mod.rs` and sibling `D.rs` (the roots for the crate's source directory), then in component order
    /// each file of the directory that a path attribute of a path holder or of those module files names.
    fn searched(&mut self, file: &str, directory: &str) -> io::Result<Vec<String>> {
        let named: Vec<String> =
            if directory != CRATE && !directory.starts_with(&format!("{CRATE}/")) {
                Vec::new()
            } else if directory == CRATE {
                self.roots.to_vec()
            } else {
                vec![joined(directory, "mod.rs"), with_suffix(directory, ".rs")?]
            };
        let mut names = self.pathed.clone();
        for module in &named {
            if let Source::Text(text) = self.source(module) {
                names.extend(declared_names(&text));
            }
        }
        let mut others: Vec<String> = names
            .iter()
            .filter(|name| *name != "mod.rs")
            .map(|name| joined(directory, name))
            .filter(|module| module != file && !named.contains(module))
            .collect();
        others.sort_by(|left, right| parts(left).cmp(&parts(right)));
        Ok(named.into_iter().chain(others).collect())
    }

    /// The standings of [`Classifier::place`] for `file`, and the module files whose bare declarations
    /// load from its directory, which a refusal names as searched.
    fn declared(&mut self, file: &str) -> io::Result<(Standings, Vec<String>)> {
        let directory = if name(file) == "mod.rs" {
            parent(&parent(file))
        } else {
            parent(file)
        };
        let modules = self.searched(file, &directory)?;
        let extra: Vec<String> = self
            .roots
            .iter()
            .chain(&self.holders)
            .filter(|module| !modules.contains(module))
            .cloned()
            .collect();
        let file_name = name(file).to_owned();
        let mut found: Standings = [None, None];
        for module in modules.iter().chain(&extra) {
            let home = modules.contains(module);
            let source = self.source(module);
            if let (Source::Failed(error), true) = (&source, home) {
                self.once(format!(
                    "{module} cannot be read to classify {file}: {error}"
                ));
                found[0] = first(found[0], Some(Standing::Unreadable));
            }
            let is_root = self.roots.contains(module);
            let Source::Text(text) = source else {
                continue;
            };
            if !(home || is_root || text.contains(&file_name)) {
                continue;
            }
            let child = if home {
                directory.clone()
            } else if matches!(name(module), "mod.rs" | "lib.rs" | "main.rs") {
                parent(module)
            } else {
                joined(&parent(module), stem(module))
            };
            let anywhere = self.parse(module, &child, false);
            let loaded = [anywhere.holds(file, false), anywhere.holds(file, true)];
            for attribute in [false, true] {
                if !loaded[usize::from(attribute)] {
                    continue;
                }
                let standing = if !home && !is_root {
                    Some(Standing::Elsewhere)
                } else if attribute || is_root || name(module) == "mod.rs" {
                    let [bare, attributed] = self.place(module)?;
                    first(bare, attributed)
                } else {
                    let sibling = *module == with_suffix(&directory, ".rs")?;
                    self.place(module)?[usize::from(!sibling)]
                };
                let tested = standing == Some(Standing::Production)
                    && !self.parse(module, &child, true).holds(file, attribute);
                let state = if tested {
                    Some(Standing::Excluded)
                } else {
                    standing
                };
                let slot = &mut found[usize::from(attribute)];
                *slot = first(*slot, state);
            }
        }
        Ok((found, modules))
    }
}

/// The files outside the kernel package at `package` that it includes by `#[path]`, as [`package_sources`]
/// lists them, classified by the declarations that load each one, relative to the checkout `root`.
///
/// The package is walked on disk under `root`. The path holders are the crate sources under `tree`
/// whose text holds a path attribute; each holder and each module file is read through `read`. A source
/// of the package that resolves inside it is passed over, one outside `root` is refused, and each other
/// is production, excluded, refused as declared only by a path attribute elsewhere, refused as declared
/// by no module file. A module file of its directory that cannot be read is refused by name, and the
/// file takes the standing its other declarations give it, in neither list when they give none. A crate
/// source that cannot be read from `tree`, or a holder `read` fails on, holds no path attribute.
///
/// # Errors
///
/// `scope_files` returns an error of [`package_sources`], of the walk of the crate's sources, of [`resolve`] for a
/// source, the package or `root`, an error of kind [`io::ErrorKind::InvalidData`] for a path that is no
/// UTF-8, and an error for an included file at the top of the checkout whose standing depends on a
/// sibling named after the top's own empty name.
pub fn scope_files(
    package: &Path,
    root: &Path,
    read: Reader<'_>,
    tree: &Path,
) -> io::Result<Scope> {
    let mut classifier = Classifier {
        read,
        roots: ["mod.rs", "lib.rs", "main.rs"].map(|name| joined(CRATE, name)),
        texts: BTreeMap::new(),
        parsed: BTreeMap::new(),
        places: BTreeMap::new(),
        holders: Vec::new(),
        pathed: BTreeSet::new(),
        scope: Scope::default(),
        depth: 0,
    };
    for holder in path_holders(tree)? {
        if let Source::Text(text) = classifier.source(&holder) {
            classifier.pathed.extend(declared_names(&text));
            classifier.holders.push(holder);
        }
    }
    for path in package_sources(package)? {
        let resolved = resolve(&path)?;
        if resolved.starts_with(resolve(package)?) {
            continue;
        }
        let Ok(relative) = resolved.strip_prefix(resolve(root)?) else {
            classifier.once(format!(
                "the kernel package includes {}, outside the repository",
                path.display()
            ));
            continue;
        };
        let relative = pure(&text_of(relative)?);
        let ([bare, attributed], searched) = classifier.declared(&relative)?;
        match first(bare, attributed) {
            Some(Standing::Production) => classifier.scope.included.push(relative),
            Some(Standing::Elsewhere) => classifier.once(format!(
                "{relative} is declared only by a path attribute outside its module files and the \
                 crate root, in a file whose place in the crate the scope rule does not read"
            )),
            Some(Standing::Excluded) => classifier.scope.excluded.push(relative),
            Some(Standing::Unreadable) => {}
            None => {
                let listed: Vec<String> = searched
                    .iter()
                    .map(|module| Text::from(module.as_str()).repr())
                    .collect();
                classifier.once(format!(
                    "the kernel package includes {relative} and no module file declares it through \
                     declarations that reach the crate root; searched [{}] and the crate's path \
                     attributes",
                    listed.join(", ")
                ));
            }
        }
    }
    Ok(classifier.scope)
}

/// Why [`references`] read no references.
#[derive(Debug)]
pub enum ReferenceError {
    /// A declaration lacks a member the references are read from, or holds one of another shape.
    Shape(String),
    /// The kernel package's texts cannot be read, as [`kernel_texts`] returns it.
    Kernel(io::Error),
}

impl std::fmt::Display for ReferenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Shape(reason) => f.write_str(reason),
            Self::Kernel(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for ReferenceError {}

fn shape(reason: String) -> ReferenceError {
    ReferenceError::Shape(reason)
}

/// One member of an iteration over a JSON value: an element of an array, a key of an object, or one
/// code point of a string.
enum Member<'v> {
    Value(&'v Value),
    Text(Text),
}

fn members<'v>(value: &'v Value, what: &str) -> Result<Vec<Member<'v>>, ReferenceError> {
    match value {
        Value::Array(items) => Ok(items.iter().map(Member::Value).collect()),
        Value::Object(object) => Ok(object
            .iter()
            .map(|(key, _)| Member::Text(key.clone()))
            .collect()),
        Value::String(text) => Ok(text
            .code_points()
            .map(|code| {
                Member::Text(Text::from_code_points([code]).expect("a code point of a text"))
            })
            .collect()),
        _ => Err(shape(format!("{what} is no array"))),
    }
}

/// The member `key` of `member`, which must be an object that holds it.
fn subscript<'v>(member: &Member<'v>, key: &str, what: &str) -> Result<&'v Value, ReferenceError> {
    lookup(member, key, what)?.ok_or_else(|| shape(format!("{what} has no member {key}")))
}

/// The member `key` of `member` when it is an object, `None` when the object lacks it.
fn lookup<'v>(
    member: &Member<'v>,
    key: &str,
    what: &str,
) -> Result<Option<&'v Value>, ReferenceError> {
    match member {
        Member::Value(Value::Object(object)) => Ok(object.get(key)),
        _ => Err(shape(format!("{what} is no object"))),
    }
}

/// The text a set of names keeps of `member`: a string or a key; a number, a boolean or null names no
/// test. An array or an object cannot stand in a set.
fn name_of(member: &Member<'_>, what: &str) -> Result<Option<Text>, ReferenceError> {
    match member {
        Member::Text(text) | Member::Value(Value::String(text)) => Ok(Some(text.clone())),
        Member::Value(Value::Array(_) | Value::Object(_)) => {
            Err(shape(format!("{what} is an array or an object")))
        }
        Member::Value(_) => Ok(None),
    }
}

/// The members of an object, by name and value.
fn items<'v>(value: &'v Value, what: &str) -> Result<Vec<(&'v Text, &'v Value)>, ReferenceError> {
    match value {
        Value::Object(object) => Ok(object.iter().map(|(key, value)| (key, value)).collect()),
        _ => Err(shape(format!("{what} is no object"))),
    }
}

/// The tests a disposition entry may name and the twins a row may cite, each by lane, the bindings of
/// the GenMC declaration by id, and the kernel package's texts.
#[derive(Debug)]
pub struct References {
    positive: [BTreeSet<Text>; 2],
    twins: [BTreeSet<Text>; 3],
    bindings: BTreeMap<Text, Value>,
    kernels: BTreeMap<String, String>,
}

impl References {
    /// The positive tests of `lane` (`loom` or `genmc`): for `loom` each test a loom record lists under
    /// `tests` and no loom record lists under `controls`, for `genmc` each case declared `positive`.
    pub fn positive(&self, lane: &str) -> Option<&BTreeSet<Text>> {
        match lane {
            "loom" => Some(&self.positive[0]),
            "genmc" => Some(&self.positive[1]),
            _ => None,
        }
    }

    /// The twins of `lane`: a loom control of a loom record, a GenMC case declared `violation`, and an
    /// RC11 litmus test whose outcome is `Sometimes`.
    pub fn twins(&self, lane: &str) -> Option<&BTreeSet<Text>> {
        match lane {
            "loom" => Some(&self.twins[0]),
            "genmc" => Some(&self.twins[1]),
            "rc11" => Some(&self.twins[2]),
            _ => None,
        }
    }

    /// The last binding entry whose id is the string `id`.
    pub fn binding(&self, id: &Text) -> Option<&Value> {
        self.bindings.get(id)
    }

    /// The kernel package's texts, as [`kernel_texts`] returns them.
    pub fn kernels(&self) -> &BTreeMap<String, String> {
        &self.kernels
    }
}

/// The references of the GenMC declaration `declared`, the litmus list `litmus` and the obligation
/// records `records`, with the kernel package `declared` names read under the checkout `root`.
///
/// # Errors
///
/// `references` returns [`ReferenceError::Shape`] for a declaration whose members are absent or of
/// another shape than the references are read from, and [`ReferenceError::Kernel`] for the error of
/// [`kernel_texts`].
pub fn references(
    declared: &Value,
    litmus: &Value,
    records: &Value,
    root: &Path,
) -> Result<References, ReferenceError> {
    let records = subscript(&Member::Value(records), "records", "the obligation records")?;
    let mut loom = Vec::new();
    for record in members(records, "the obligation records' records")? {
        let job = lookup(&record, "job", "an obligation record")?;
        if job.is_some_and(|job| matches!(job, Value::String(text) if *text == "loom")) {
            loom.push(record);
        }
    }
    let mut controls = BTreeSet::new();
    for record in &loom {
        let Some(listed) = lookup(record, "controls", "a loom record")? else {
            continue;
        };
        for control in members(listed, "a loom record's controls")? {
            let test = subscript(&control, "test", "a loom control")?;
            controls.extend(name_of(&Member::Value(test), "a loom control's test")?);
        }
    }
    let mut tested = BTreeSet::new();
    for record in &loom {
        let tests = subscript(record, "tests", "a loom record")?;
        for test in members(tests, "a loom record's tests")? {
            tested.extend(name_of(&test, "a loom record's test")?);
        }
    }
    let declared_member = Member::Value(declared);
    let cases = items(
        subscript(&declared_member, "cases", "the GenMC declaration")?,
        "the GenMC declaration's cases",
    )?;
    let expecting = |expect: &str| -> Result<BTreeSet<Text>, ReferenceError> {
        let mut found = BTreeSet::new();
        for &(name, case) in &cases {
            let value = subscript(&Member::Value(case), "expect", "a GenMC case")?;
            if matches!(value, Value::String(text) if *text == expect) {
                found.insert(name.clone());
            }
        }
        Ok(found)
    };
    let positive = [&tested - &controls, expecting("positive")?];
    let violations = expecting("violation")?;
    let mut sometimes = BTreeSet::new();
    let litmus_tests = subscript(&Member::Value(litmus), "tests", "the litmus list")?;
    for (name, test) in items(litmus_tests, "the litmus list's tests")? {
        let outcome = subscript(&Member::Value(test), "outcome", "a litmus test")?;
        if matches!(outcome, Value::String(text) if *text == "Sometimes") {
            sometimes.insert(name.clone());
        }
    }
    let mut bindings = BTreeMap::new();
    let listed = subscript(&declared_member, "bindings", "the GenMC declaration")?;
    for entry in members(listed, "the GenMC declaration's bindings")? {
        let id = subscript(&entry, "id", "a binding")?;
        if matches!(id, Value::Array(_) | Value::Object(_)) {
            return Err(shape("a binding's id is an array or an object".to_owned()));
        }
        let Member::Value(value) = entry else {
            unreachable!("an entry with an id is an object");
        };
        if let Value::String(id) = id {
            bindings.insert(id.clone(), value.clone());
        }
    }
    let package = match subscript(&declared_member, "package", "the GenMC declaration")? {
        Value::String(text) => text.to_os(),
        _ => {
            return Err(shape(
                "the GenMC declaration's package is no string".to_owned(),
            ));
        }
    };
    let kernels = match package {
        Some(package) => kernel_texts(&root.join(package)).map_err(ReferenceError::Kernel)?,
        None => BTreeMap::new(),
    };
    Ok(References {
        positive,
        twins: [controls, violations, sometimes],
        bindings,
        kernels,
    })
}

#[cfg(test)]
#[path = "sources_tests.rs"]
mod tests;
