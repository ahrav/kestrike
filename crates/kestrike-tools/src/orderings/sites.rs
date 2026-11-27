//! The site reading of a scoped file: its production text, its scanned text, its sites in order, and the
//! defects that hide a site from the reading, each as a sentence.
//!
//! A site is one `Ordering` stronger than `Relaxed`, or one fence call, in the production text that
//! [`analyzed`] gives, matched outside comments and literals. A fence call is a call of a path, a leading
//! `::` included, whose last segment holds `fence`, declarations and definitions aside; it spans from the
//! first character of its path to the end of the call and a `;` directly after it. A hook of [`HOOKS`]
//! mentioned as `S::NAME` is no site while the file holds at least one definition of it with a body and
//! every such body is empty. An ordering passed directly to a fence call belongs to the fence; an ordering
//! nested deeper in the fence's arguments is a site of its own.
//!
//! The op of an ordering comes from the atomic method, called as `receiver.method(...)`, whose argument it
//! is. A compare-exchange's success ordering is an `rmw` and its failure ordering a `load`, and
//! `fetch_update`'s set and fetch orderings are an `rmw` and a `load`, each read by argument position
//! while no earlier argument holds `<` or `>` outside brackets. The op of a strength constant, a
//! `const NAME: Ordering` item, comes from each `S::NAME` mention in the file's scanned text: the mentions
//! must all sit in atomic calls of one op. A constant with no such mention takes its op from [`EXTERNAL`],
//! keyed by the file and the constant's name, and any other constant with no mention is unread.
//!
//! The production text spells each ordering variant as part of an `Ordering::` path and names each fence
//! path only in a path call whose callee the reading delimits whole, a macro fragment, or a forwarder
//! invocation `name!(<type>, std::sync::atomic::fence);`. Each `$fence` call sits in the body of a
//! `macro_rules!` that is one arm `($name:ty, $fence:path) => {..}`, whose production invocations, at
//! least one, all pass `std::sync::atomic::fence`, lie among no other macro's tokens and follow the
//! definition with only blank text between. Each departure from these rules is a defect, as is each
//! test-only element whose end the production text's rules read more than one way.
//!
//! Offsets are byte offsets of the source, which the production and scanned texts share. Each window
//! spans a count of code points of the source: 200 before and after a fence name, 200 before a method.
//! Each pattern compiles with Python's classes; [`captures_bounded`] checks Python's `\b` at a match's word
//! edges, and `fence_path` also matches the fence path before a final newline, as Python's `$` does.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;

use crate::classes::{SPACE, WORD, bounded_iter, captures_bounded, compiled, is_word};
use crate::production_text::{analyzed, closing};
use crate::rust_text::{ahead, back};
use crate::text::strip_str;

/// The hooks a strength type defines, which a file mentions as `S::NAME`.
pub const HOOKS: [&str; 5] = [
    "fence_park",
    "fence_clear",
    "fence_pin",
    "fence_retire",
    "fence_certify",
];

/// The op of a strength constant whose consumer lies outside its file, keyed by the defining file and the
/// constant's name: `RELOAD` of `storage/credit.rs` reaches `record_credits` in `storage/lease.rs` as
/// `S::RELOAD`, and both of its `credit::credits` calls load with it.
pub const EXTERNAL: &[Pin] = &[("crates/kestrike/src/storage/credit.rs", "RELOAD", Op::Load)];

/// A strength constant's op pinned by hand: the defining file, the constant's name and the op.
pub type Pin = (&'static str, &'static str, Op);

/// An `Ordering` variant stronger than `Relaxed`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Strength {
    SeqCst,
    AcqRel,
    Acquire,
    Release,
}

impl Strength {
    pub fn name(self) -> &'static str {
        match self {
            Self::SeqCst => "SeqCst",
            Self::AcqRel => "AcqRel",
            Self::Acquire => "Acquire",
            Self::Release => "Release",
        }
    }

    fn of(name: &str) -> Self {
        match name {
            "SeqCst" => Self::SeqCst,
            "AcqRel" => Self::AcqRel,
            "Acquire" => Self::Acquire,
            "Release" => Self::Release,
            _ => unreachable!("ORDERING's group names one of the four variants, not {name}"),
        }
    }
}

/// The operation an ordering orders, or `Unread` where the reading reads none.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Op {
    Load,
    Store,
    Rmw,
    Unread,
}

impl Op {
    pub fn name(self) -> &'static str {
        match self {
            Self::Load => "load",
            Self::Store => "store",
            Self::Rmw => "rmw",
            Self::Unread => "unread",
        }
    }
}

/// What a site is: an ordering with the op it orders, or a fence call with the offset of its opening
/// bracket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Ordering { strength: Strength, op: Op },
    Fence { open: usize },
}

/// One site: for an ordering, the span of its `Ordering::Variant` path; for a fence call, the span from
/// its path to the end of the call and a `;` directly after it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Site {
    start: usize,
    end: usize,
    kind: Kind,
}

impl Site {
    pub fn start(&self) -> usize {
        self.start
    }

    pub fn end(&self) -> usize {
        self.end
    }

    pub fn kind(&self) -> Kind {
        self.kind
    }

    /// The op's name as the catalog spells it: `fence` for a fence call.
    pub fn op_name(&self) -> &'static str {
        match self.kind {
            Kind::Ordering { op, .. } => op.name(),
            Kind::Fence { .. } => "fence",
        }
    }
}

/// The reading of one scoped file. Each defect names the file and, where the defect has one place, its
/// line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reading {
    production: String,
    scanned: String,
    sites: Vec<Site>,
    defects: Vec<String>,
}

impl Reading {
    pub fn production(&self) -> &str {
        &self.production
    }

    pub fn scanned(&self) -> &str {
        &self.scanned
    }

    /// The sites in the order of their starts.
    pub fn sites(&self) -> &[Site] {
        &self.sites
    }

    pub fn defects(&self) -> &[String] {
        &self.defects
    }
}

static ORDERING: LazyLock<Regex> = LazyLock::new(|| {
    compiled(&format!(
        r"Ordering{SPACE}*::{SPACE}*(SeqCst|AcqRel|Acquire|Release)"
    ))
});

static SPELLING: LazyLock<Regex> =
    LazyLock::new(|| compiled(&format!(r"Ordering{SPACE}*(?:::{SPACE}*\*|as)")));

static VARIANT: LazyLock<Regex> = LazyLock::new(|| compiled("(?:SeqCst|AcqRel|Acquire|Release)"));

static FENCE: LazyLock<Regex> = LazyLock::new(|| compiled(&format!(r"\$?{WORD}*fence{WORD}*")));

/// The path before a fence name, at the end of a window. [`fence_path`] also tries the window without a
/// final newline.
static FENCE_PATH: LazyLock<Regex> = LazyLock::new(|| {
    compiled(&format!(
        r"(?:::{SPACE}*)?(?:(?:<(?:[^<>]|<[^<>]*>)*>|{WORD}+){SPACE}*::{SPACE}*)*\$?{WORD}*\z"
    ))
});

static FORWARDER: LazyLock<Regex> = LazyLock::new(|| {
    compiled(&format!(
        r"({WORD}+){SPACE}*!{SPACE}*\({SPACE}*[\p{{L}}\p{{N}}_:<>]+{SPACE}*,{SPACE}*std{SPACE}*::{SPACE}*sync{SPACE}*::{SPACE}*atomic{SPACE}*::{SPACE}*\z"
    ))
});

static ARM: LazyLock<Regex> = LazyLock::new(|| {
    compiled(&format!(
        r"\A{SPACE}*\({SPACE}*\${WORD}+{SPACE}*:{SPACE}*ty{SPACE}*,{SPACE}*\$fence{SPACE}*:{SPACE}*path{SPACE}*\){SPACE}*=>{SPACE}*\{{"
    ))
});

static MACRO: LazyLock<Regex> = LazyLock::new(|| {
    compiled(&format!(
        r"(?:macro_rules{SPACE}*!{SPACE}*(?:r#)?{WORD}+|{WORD}+{SPACE}*!){SPACE}*[(\[{{]"
    ))
});

static CONSTANT: LazyLock<Regex> = LazyLock::new(|| {
    compiled(&format!(
        r"const{SPACE}+({WORD}+){SPACE}*:{SPACE}*Ordering{SPACE}*={SPACE}*\z"
    ))
});

static MACRO_RULES: LazyLock<Regex> =
    LazyLock::new(|| compiled(&format!(r"macro_rules!{SPACE}*(?:r#)?({WORD}+){SPACE}*\{{")));

static METHOD: LazyLock<Regex> = LazyLock::new(|| {
    compiled(&format!(
        r"\.{SPACE}*({WORD}+){SPACE}*(?:::<[^>]*>)?{SPACE}*\z"
    ))
});

static DEFINED: LazyLock<Regex> = LazyLock::new(|| compiled(&format!(r"fn{SPACE}+\z")));
static STRENGTH_PATH: LazyLock<Regex> =
    LazyLock::new(|| compiled(&format!(r"S{SPACE}*::{SPACE}*\z")));
static METHOD_DOT: LazyLock<Regex> = LazyLock::new(|| compiled(&format!(r"\.{SPACE}*\z")));
static TYPED: LazyLock<Regex> = LazyLock::new(|| compiled(&format!(r"\A{SPACE}*:")));
static CALL: LazyLock<Regex> = LazyLock::new(|| compiled(&format!(r"\A{SPACE}*\(")));
static PASSED: LazyLock<Regex> = LazyLock::new(|| compiled(&format!(r"\A{SPACE}*\){SPACE}*;")));
static ARM_TAIL: LazyLock<Regex> = LazyLock::new(|| compiled(&format!(r"\A{SPACE}*;?{SPACE}*\z")));

/// The scanned text of a file and the source whose code points measure its windows.
#[derive(Clone, Copy)]
struct View<'t> {
    source: &'t str,
    scanned: &'t str,
}

/// The 1-based line of `offset` in `text`; `offset` is at most `text.len()`.
pub fn line_of(text: &str, offset: usize) -> usize {
    text.as_bytes()[..offset]
        .iter()
        .filter(|&&byte| byte == b'\n')
        .count()
        + 1
}

/// The offset past the bracket that closes the one at `start`, or the end of `text`.
fn call_end(text: &str, start: usize) -> usize {
    let mut depth = 0_isize;
    for (index, c) in text[start..].char_indices() {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            _ => {}
        }
        if depth == 0 {
            return start + index + c.len_utf8();
        }
    }
    text.len()
}

/// The offset of the innermost bracket open at `offset`.
fn opener(scanned: &str, offset: usize) -> Option<usize> {
    let mut depth = 0_usize;
    for (index, &byte) in scanned.as_bytes()[..offset].iter().enumerate().rev() {
        match byte {
            b')' | b']' | b'}' => depth += 1,
            b'(' | b'[' | b'{' if depth == 0 => return Some(index),
            b'(' | b'[' | b'{' => depth -= 1,
            _ => {}
        }
    }
    None
}

/// The offset of the `{` that opens the body of an item whose header continues at `index`, or `None` when
/// a `;` outside brackets ends it as a declaration.
fn body_open(text: &str, index: usize) -> Option<usize> {
    let mut depth = 0_isize;
    for (position, &byte) in text.as_bytes().iter().enumerate().skip(index) {
        match byte {
            b'(' | b'[' => depth += 1,
            b')' | b']' => depth -= 1,
            b'{' if depth == 0 => return Some(position),
            b';' if depth == 0 => return None,
            _ => {}
        }
    }
    None
}

/// `text[start..end]`, or the empty text when `start` lies past `end`.
fn between(text: &str, start: usize, end: usize) -> &str {
    text.get(start..end).unwrap_or("")
}

/// The source's text of `start..end` with each character the scanned text blanks as one space.
fn spelled(view: View<'_>, start: usize, end: usize) -> String {
    view.source[start..end]
        .char_indices()
        .map(|(offset, c)| {
            let at = start + offset;
            if view.scanned[at..].starts_with(c) {
                c
            } else {
                ' '
            }
        })
        .collect()
}

/// The op of the call argument at `offset`, read from the atomic method whose argument it is.
fn call_op(view: View<'_>, offset: usize) -> Op {
    let scanned = view.scanned;
    let Some(index) = opener(scanned, offset).filter(|&index| scanned.as_bytes()[index] == b'(')
    else {
        return Op::Unread;
    };
    let (mut depth, mut commas, mut generic) = (0_isize, 0_usize, false);
    for byte in scanned[index + 1..offset].bytes() {
        match byte {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            _ if depth == 0 => {
                commas += usize::from(byte == b',');
                generic |= matches!(byte, b'<' | b'>');
            }
            _ => {}
        }
    }
    let window = &scanned[back(view.source, index, 200)..index];
    let name = METHOD
        .captures(window)
        .and_then(|found| found.get(1))
        .map_or("", |name| name.as_str());
    match (name, generic, commas) {
        ("load", ..) => Op::Load,
        ("store", ..) => Op::Store,
        ("swap", ..) => Op::Rmw,
        _ if name.starts_with("fetch_") && name != "fetch_update" => Op::Rmw,
        (_, true, _) => Op::Unread,
        ("compare_exchange" | "compare_exchange_weak", _, 2) | ("fetch_update", _, 0) => Op::Rmw,
        ("compare_exchange" | "compare_exchange_weak", _, 3) | ("fetch_update", _, 1) => Op::Load,
        _ => Op::Unread,
    }
}

/// The hooks of [`HOOKS`] that `scanned` defines with at least one body, each body empty.
fn empty_hooks(scanned: &str) -> Vec<&'static str> {
    let last = back(scanned, scanned.len(), 1);
    HOOKS
        .into_iter()
        .filter(|name| {
            let definition = compiled(&format!(r"fn{SPACE}+{name}"));
            let bodies: Vec<&str> = bounded_iter(&definition, scanned)
                .filter_map(|found| {
                    let brace = body_open(scanned, found.get_match().end())?;
                    let close = closing(scanned, brace).map_or(last, |end| end - 1);
                    Some(between(scanned, brace + 1, close))
                })
                .collect();
            !bodies.is_empty() && bodies.iter().all(|body| strip_str(body).is_empty())
        })
        .collect()
}

/// The span of the fence path at the end of `before`, as Python's `search` finds it with a `$` that
/// matches at the end and before a final newline: the leftmost start, and at one start the match that
/// runs to the end. A path's white space runs over line breaks, so a word that ends the line above a
/// rooted path `::std::...` starts the path. A path that ends before a final newline is counted back from
/// the fence name by its length: a callee `<W>::x` on the line above `fence(` gives a site that starts at
/// `W>` and a prefix that ends with `<`.
fn fence_path(before: &str) -> (usize, usize) {
    let span = |found: regex::Match<'_>| (found.start(), found.end());
    let full = FENCE_PATH
        .find(before)
        .map_or((before.len(), before.len()), span);
    let short = before
        .strip_suffix('\n')
        .and_then(|rest| FENCE_PATH.find(rest))
        .map(span);
    match short {
        Some(short) if short.0 < full.0 => short,
        _ => full,
    }
}

/// Whether Python's `\w$` finds a match in `text`: its last character, or the one before a final newline,
/// is a word character. A qualified call `<W>::f()` at the start of a line, after a line that ends in a
/// word, therefore has a callee the matcher cannot delimit.
fn ends_in_word(text: &str) -> bool {
    let mut last = text.chars().rev();
    match last.next() {
        Some('\n') => last.next().is_some_and(is_word),
        found => found.is_some_and(is_word),
    }
}

/// The fence calls of a scanned text, each fence name the reading counts outside a delimited path call,
/// and the macro each forwarder invocation that passes `std::sync::atomic::fence` invokes.
struct Fences {
    found: Vec<Site>,
    stray: Vec<(usize, &'static str)>,
    forwards: Vec<String>,
}

fn fence_calls(view: View<'_>) -> Fences {
    let View { source, scanned } = view;
    let mut fences = Fences {
        found: Vec::new(),
        stray: Vec::new(),
        forwards: Vec::new(),
    };
    let empty = empty_hooks(scanned);
    for found in bounded_iter(&FENCE, scanned) {
        let name = found.get_match();
        let (start, end) = (name.start(), name.end());
        let window = back(source, start, 200);
        let before = &scanned[window..start];
        let after = &scanned[end..ahead(source, end, 200)];
        if captures_bounded(&DEFINED, before, 0).is_some()
            || (name.as_str().starts_with('$') && TYPED.is_match(after))
        {
            continue;
        }
        if empty.contains(&name.as_str()) && captures_bounded(&STRENGTH_PATH, before, 0).is_some() {
            continue;
        }
        let Some(call) = CALL.find(after) else {
            let forwarder = captures_bounded(&FORWARDER, before, 0);
            match forwarder {
                Some(forwarder) if name.as_str() == "fence" && PASSED.is_match(after) => {
                    let macro_name = forwarder.get(1).expect("FORWARDER has group 1");
                    fences.forwards.push(macro_name.as_str().to_owned());
                }
                _ => fences
                    .stray
                    .push((start, "a fence path named outside a call")),
            }
            continue;
        };
        let (path_start, path_end) = fence_path(before);
        let path_points = source[window + path_start..window + path_end]
            .chars()
            .count();
        let site_start = back(source, start, path_points);
        let prefix = &scanned[window..site_start];
        if METHOD_DOT.is_match(prefix) {
            fences.stray.push((start, "a fence called as a method"));
            continue;
        }
        if matches!(prefix.chars().next_back(), Some('$' | '>' | ':')) || ends_in_word(prefix) {
            fences
                .stray
                .push((start, "a fence callee the matcher cannot delimit"));
            continue;
        }
        let open = end + call.end() - 1;
        let close = call_end(scanned, open);
        let semicolon = usize::from(scanned.as_bytes().get(close) == Some(&b';'));
        fences.found.push(Site {
            start: site_start,
            end: close + semicolon,
            kind: Kind::Fence { open },
        });
    }
    fences
}

/// The defects of the tie between each `$fence` call, the `macro_rules!` whose body holds it, and that
/// macro's production invocations: each passes `std::sync::atomic::fence`, none lies among another macro's
/// tokens, the body is one arm `($name:ty, $fence:path) => {..}`, and the invocations follow the definition
/// with blank text alone between.
fn forwarder_defects(scanned: &str, fences: &Fences) -> Vec<String> {
    let spans: Vec<(String, usize, usize)> = bounded_iter(&MACRO_RULES, scanned)
        .map(|found| {
            let open = found.get_match().end() - 1;
            let name = found.get(1).expect("MACRO_RULES has group 1").as_str();
            (
                name.to_owned(),
                open,
                closing(scanned, open).unwrap_or(scanned.len()),
            )
        })
        .collect();
    let (mut owners, mut defects) = (BTreeSet::new(), Vec::new());
    for site in &fences.found {
        if scanned.as_bytes()[site.start] != b'$' {
            continue;
        }
        match spans
            .iter()
            .find(|&&(_, low, high)| low < site.start && site.start < high)
        {
            Some(owner) => {
                owners.insert(owner.clone());
            }
            None => defects.push(format!(
                "line {}: a $fence call lies in no macro_rules! body",
                line_of(scanned, site.start)
            )),
        }
    }
    let owned: BTreeSet<&str> = owners.iter().map(|(name, _, _)| name.as_str()).collect();
    let passed: BTreeSet<&str> = fences.forwards.iter().map(String::as_str).collect();
    for name in passed.difference(&owned) {
        defects.push(format!(
            "{name}! receives std::sync::atomic::fence and holds no $fence call"
        ));
    }
    let groups: Vec<(usize, usize)> = bounded_iter(&MACRO, scanned)
        .map(|found| {
            let open = found.get_match().end() - 1;
            (open, call_end(scanned, open))
        })
        .collect();
    for (name, low, high) in &owners {
        let invocation = compiled(&format!(r"{}{SPACE}*!{SPACE}*[(\[{{]", regex::escape(name)));
        let invoked: Vec<(usize, usize)> = bounded_iter(&invocation, scanned)
            .map(|found| {
                let whole = found.get_match();
                (whole.start(), whole.end() - 1)
            })
            .collect();
        if invoked.iter().any(|&(offset, _)| {
            groups
                .iter()
                .any(|&(first, last)| first < offset && offset < last)
        }) {
            defects.push(format!(
                "{name}! is invoked among another macro's tokens, which the matcher cannot expand"
            ));
        }
        let passing = fences
            .forwards
            .iter()
            .filter(|&forward| forward == name)
            .count();
        if invoked.is_empty() || passing != invoked.len() {
            defects.push(format!(
                "{name}! holds a $fence call, and {passing} of its {} production invocations pass \
                 std::sync::atomic::fence",
                invoked.len()
            ));
        }
        let mut cursor = ARM.find(&scanned[low + 1..]).and_then(|arm| {
            let arm_open = low + 1 + arm.end() - 1;
            let after_arm = closing(scanned, arm_open).unwrap_or(*low);
            let tail = between(scanned, after_arm, back(scanned, *high, 1));
            ARM_TAIL.is_match(tail).then_some(*high)
        });
        for &(offset, open) in &invoked {
            if let Some(at) = cursor {
                let end = call_end(scanned, open);
                cursor = (offset >= at && strip_str(&scanned[at..offset]).is_empty())
                    .then(|| end + usize::from(scanned.as_bytes().get(end) == Some(&b';')));
            }
        }
        if cursor.is_none() {
            defects.push(format!(
                "{name}! is not one arm ($name:ty, $fence:path) => {{..}} that its production \
                 invocations directly follow"
            ));
        }
    }
    defects
}

/// Each site of the view in order of start, given its fence calls and the pins of the file at `path`.
fn ordered_sites(view: View<'_>, fences: &[Site], path: &str, pins: &[Pin]) -> Vec<Site> {
    let scanned = view.scanned;
    let mut found = fences.to_vec();
    for ordering in bounded_iter(&ORDERING, scanned) {
        let whole = ordering.get_match();
        let start = whole.start();
        let owned = fences.iter().any(|fence| {
            fence.start <= start
                && start < fence.end
                && matches!(fence.kind, Kind::Fence { open } if opener(scanned, start) == Some(open))
        });
        if owned {
            continue;
        }
        let line = scanned[..start]
            .rfind('\n')
            .map_or(0, |newline| newline + 1);
        let op = match captures_bounded(&CONSTANT, &scanned[line..start], 0) {
            Some(constant) => {
                let name = constant.get(1).expect("CONSTANT has group 1").as_str();
                let mention = compiled(&format!(r"S{SPACE}*::{SPACE}*{}", regex::escape(name)));
                let ops: BTreeSet<Op> = bounded_iter(&mention, scanned)
                    .map(|found| call_op(view, found.get_match().start()))
                    .collect();
                match ops.len() {
                    0 => pins
                        .iter()
                        .find(|&&(file, constant, _)| file == path && constant == name)
                        .map_or(Op::Unread, |&(_, _, op)| op),
                    1 => ops.into_iter().next().expect("one op"),
                    _ => Op::Unread,
                }
            }
            None => call_op(view, start),
        };
        let strength = Strength::of(ordering.get(1).expect("ORDERING has group 1").as_str());
        found.push(Site {
            start,
            end: whole.end(),
            kind: Kind::Ordering { strength, op },
        });
    }
    found.sort_by_key(|site| site.start);
    found
}

/// The sites of `scanned` read alone: its own fence calls, and no strength constant whose consumer lies
/// outside it. Its windows count code points of `scanned`.
pub fn sites(scanned: &str) -> Vec<Site> {
    let view = View {
        source: scanned,
        scanned,
    };
    ordered_sites(view, &fence_calls(view).found, "", &[])
}

/// The reading of the scoped file at `path`, the path relative to the checkout's top, whose text is
/// `text`. A strength constant with no `S::NAME` mention takes its op from the pin in `pins` for `path`
/// and its name; the catalog's check passes [`EXTERNAL`].
pub fn read(path: &str, text: &str, pins: &[Pin]) -> Reading {
    let analysis = analyzed(text);
    let view = View {
        source: text,
        scanned: analysis.scanned(),
    };
    let scanned = view.scanned;
    let mut defects: Vec<String> = bounded_iter(&SPELLING, scanned)
        .map(|found| {
            let whole = found.get_match();
            format!(
                "{path}:{}: {} hides the sites it names from the matcher",
                line_of(text, whole.start()),
                spelled(view, whole.start(), whole.end())
            )
        })
        .collect();
    let named: BTreeSet<usize> = bounded_iter(&ORDERING, scanned)
        .map(|found| found.get(1).expect("ORDERING has group 1").start())
        .collect();
    for found in bounded_iter(&VARIANT, scanned) {
        let whole = found.get_match();
        if !named.contains(&whole.start()) {
            defects.push(format!(
                "{path}:{}: {} outside an Ordering:: path hides its site from the matcher",
                line_of(text, whole.start()),
                whole.as_str()
            ));
        }
    }
    defects.extend(analysis.cut().iter().map(|&offset| {
        format!(
            "{path}:{}: a test-only element whose end the matcher reads more than one way; \
             parenthesize its `<`, `>` or `|`, or move it into a test-only block or module",
            line_of(text, offset)
        )
    }));
    let fences = fence_calls(view);
    defects.extend(fences.stray.iter().map(|&(offset, why)| {
        format!(
            "{path}:{}: {why} hides the sites it names from the matcher",
            line_of(text, offset)
        )
    }));
    defects.extend(
        forwarder_defects(scanned, &fences)
            .into_iter()
            .map(|defect| format!("{path}: {defect}")),
    );
    let sites = ordered_sites(view, &fences.found, path, pins);
    Reading {
        production: analysis.production().to_owned(),
        scanned: scanned.to_owned(),
        sites,
        defects,
    }
}

#[cfg(test)]
#[path = "sites_tests.rs"]
mod tests;
