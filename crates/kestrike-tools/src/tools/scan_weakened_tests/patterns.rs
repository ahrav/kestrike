//! A pattern with a trailing lookahead stores it as a separate expression anchored at the candidate's end.

use std::sync::LazyLock;

use regex::bytes::{Captures, Regex};

use crate::rust_text::{SPACE, WORD};

const NUMBER: &str = r"(?P<value>\d[\d_]*)";
const INTEGER_TYPE: &str = r"[iu](?:8|16|32|64|128|size)";

fn trivia() -> String {
    format!(r"(?:{SPACE}|/\*.*?\*/)*")
}

pub struct Pattern {
    regex: Regex,
    ahead: Option<Regex>,
}

impl Pattern {
    fn new(pattern: &str, ahead: Option<&str>) -> Self {
        let compile = |pattern: &str| {
            Regex::new(pattern)
                .unwrap_or_else(|error| panic!("the pattern {pattern} compiles: {error}"))
        };
        Self {
            regex: compile(pattern),
            ahead: ahead.map(|ahead| compile(&format!(r"\A(?:{ahead})"))),
        }
    }

    pub fn regex(&self) -> &Regex {
        &self.regex
    }

    /// `captures` yields matches in order. When a candidate fails its lookahead, `captures` resumes one code
    /// point after the candidate's start to keep overlapping candidates eligible.
    pub fn captures<'h>(&'h self, haystack: &'h [u8]) -> impl Iterator<Item = Captures<'h>> + 'h {
        let mut at = 0;
        std::iter::from_fn(move || {
            loop {
                let found = self.regex.captures_at(haystack, at)?;
                let whole = found.get(0).expect("group 0 is the match");
                if self.ahead_holds(haystack, whole.end()) {
                    at = whole.end().max(whole.start() + 1);
                    return Some(found);
                }
                at = whole.start() + code_point_length(&haystack[whole.start()..]);
            }
        })
    }

    pub fn is_match(&self, haystack: &[u8]) -> bool {
        self.captures(haystack).next().is_some()
    }

    fn ahead_holds(&self, haystack: &[u8], end: usize) -> bool {
        self.ahead
            .as_ref()
            .is_none_or(|ahead| ahead.is_match(&haystack[end..]))
    }
}

fn code_point_length(bytes: &[u8]) -> usize {
    match bytes.first() {
        Some(0xc0..0xe0) => 2,
        Some(0xe0..0xf0) => 3,
        Some(0xf0..) => 4,
        _ => 1,
    }
}

pub static PREEMPTION_BOUND: LazyLock<Pattern> = LazyLock::new(|| {
    let trivia = trivia();
    Pattern::new(
        &format!(r"\b(?P<name>preemption_bound){SPACE}*={SPACE}*Some\({SPACE}*{NUMBER}{trivia}\)"),
        None,
    )
});

pub static MAX_BRANCHES: LazyLock<Pattern> = LazyLock::new(|| {
    Pattern::new(
        &format!(r"\b(?P<name>max_branches){SPACE}*={SPACE}*{NUMBER}"),
        Some(&format!("{}[;,]", trivia())),
    )
});

pub static CONST_BUDGET: LazyLock<Pattern> = LazyLock::new(|| {
    Pattern::new(
        &(format!(
            r"\bconst{SPACE}+(?P<name>{WORD}*(?:SEEDS|ROOTS|PREEMPTION_BOUND)){SPACE}*:{SPACE}*"
        ) + &format!(
            r"(?:{INTEGER_TYPE}{SPACE}*={SPACE}*|\[{SPACE}*{INTEGER_TYPE}{SPACE}*;{SPACE}*){NUMBER}"
        )),
        Some(&format!(r"{}[;\]]", trivia())),
    )
});

pub static CONSTANT: LazyLock<Pattern> = LazyLock::new(|| {
    Pattern::new(
        &(format!(r"\bconst{SPACE}+(?P<name>{WORD}+){SPACE}*:")
            + &format!(r"(?P<typed>{SPACE}*{INTEGER_TYPE}{SPACE}*={SPACE}*{NUMBER})?")),
        None,
    )
});

/// `CONSTANT_END` matches the terminator of `CONSTANT`'s optional `typed` group: trivia followed by `;`.
pub static CONSTANT_END: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!(r"\A(?:{};)", trivia())).expect("the pattern compiles"));

pub static NAMED_BOUND: LazyLock<Pattern> = LazyLock::new(|| {
    Pattern::new(
        &format!(
            r"(?P<site>\bpreemption_bound{SPACE}*={SPACE}*Some\({SPACE}*)(?P<name>[A-Za-z_]{WORD}*)"
        ),
        Some(&format!(r"{SPACE}*\)")),
    )
});

pub static REASON: LazyLock<Pattern> = LazyLock::new(|| {
    Pattern::new(
        &format!(r#"\bignore{SPACE}*={SPACE}*"(?:\\.|[^"\\])*""#),
        None,
    )
});

pub static TIMEOUT_MINUTES: LazyLock<Pattern> = LazyLock::new(|| {
    Pattern::new(
        &format!(r"\b(?P<name>timeout-minutes):{SPACE}*{NUMBER}"),
        None,
    )
});

pub static DEADLINE: LazyLock<Pattern> =
    LazyLock::new(|| Pattern::new(&format!(r"\b(?P<name>deadline){SPACE}+{NUMBER}m\b"), None));

pub static TIMEOUT: LazyLock<Pattern> = LazyLock::new(|| {
    Pattern::new(
        &format!(r"\b(?P<name>timeout)\b.*?{SPACE}{NUMBER}m\b"),
        None,
    )
});

pub static INVENTORY_TEXT_BUDGET: LazyLock<Pattern> = LazyLock::new(|| {
    Pattern::new(
        r"\b(?P<name>depth:|actions|cycles) (?P<value>\d+)",
        Some(&format!(r"[{}:,;$)]|\z", &SPACE[1..SPACE.len() - 1])),
    )
});

pub static ASSERT: LazyLock<Pattern> =
    LazyLock::new(|| Pattern::new(&format!(r"\bassert{WORD}*!"), None));

pub static DIGITS: LazyLock<Pattern> = LazyLock::new(|| Pattern::new(r"\d[\d_]*", None));

pub static HUNK: LazyLock<Pattern> =
    LazyLock::new(|| Pattern::new(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@", None));

pub static ALIASING: LazyLock<Pattern> = LazyLock::new(|| Pattern::new(r"[.\[\]]", None));

pub static SCOPE: LazyLock<Pattern> = LazyLock::new(|| {
    Pattern::new(
        &format!(r"\bmod{SPACE}+(?:r#)?(?P<module>{WORD}+){SPACE}*\{{|[{{}}]"),
        None,
    )
});

pub fn rust_budgets() -> [&'static Pattern; 3] {
    [&PREEMPTION_BOUND, &MAX_BRANCHES, &CONST_BUDGET]
}

pub fn timeouts() -> [&'static Pattern; 3] {
    [&TIMEOUT_MINUTES, &DEADLINE, &TIMEOUT]
}
