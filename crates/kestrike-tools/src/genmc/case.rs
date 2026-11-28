//! The case judge reads one GenMC run's text and exit against its case declaration: a positive case
//! needs one clean verification with complete executions, a violation case one `ERROR` event at the
//! line of a declared `check!` of its kernel file and the run's own error graph.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;

use super::refusal::{
    Code, Error, Refusal, lines, listed, lookup, member, open_file, openable, read_json,
    read_strict, replaced, single, string, strings, tool_failure,
};
use crate::classes::{SPACE, compiled};
use crate::json::{Integer, Text, Value};
use crate::python::{decimal, equal, repr, str_of};

const EXPECTED: &str = "verification/genmc/expected.json";

const NONSPACE: &str = r"[^\s\x1c-\x1f]";

static ABORTS: LazyLock<Regex> = LazyLock::new(|| {
    compiled(
        "(?i)does not support intrinsic|Constant unimplemented|LLVM ERROR|Assertion `|Aborted\
         |Segmentation fault|terminate called|internal error|unsupported",
    )
});

static ERROR_EVENT: LazyLock<Regex> =
    LazyLock::new(|| compiled(&format!(r"^\((\d+), (\d+)\): ERROR ({NONSPACE}+):(\d+)$")));

static GRAPH_EVENT: LazyLock<Regex> =
    LazyLock::new(|| compiled(&format!(r#"(?m)^{SPACE}*"\((\d+), (\d+)\)" \[label="#)));

static GRAPH_ERROR: LazyLock<Regex> = LazyLock::new(|| {
    compiled(&format!(
        r#"(?m)^{SPACE}*"\((\d+), (\d+)\)" \[label=<ERROR <FONT COLOR="gray"> ({NONSPACE}+):(\d+)</FONT>>"#
    ))
});

static TEXT_EVENT: LazyLock<Regex> =
    LazyLock::new(|| compiled(&format!(r"(?m)^{SPACE}*\((\d+), (\d+)\): ")));

static COMPILATION: LazyLock<Regex> =
    LazyLock::new(|| compiled(r"^\*\*\* Compilation complete\.$"));
static TRANSFORMATION: LazyLock<Regex> =
    LazyLock::new(|| compiled(r"^\*\*\* Transformation complete\.$"));
static EXECUTIONS: LazyLock<Regex> =
    LazyLock::new(|| compiled(r"^Number of complete executions explored: (\d+)$"));
static COMPLETE: LazyLock<Regex> = LazyLock::new(|| compiled(r"^\*\*\* Verification complete\.$"));
static NO_ERRORS: LazyLock<Regex> = LazyLock::new(|| compiled(r"^No errors were detected\.$"));
static SAFETY: LazyLock<Regex> = LazyLock::new(|| compiled(r"^Error: Safety violation!$"));
static UNSUCCESSFUL: LazyLock<Regex> =
    LazyLock::new(|| compiled(r"^\*\*\* Verification unsuccesful\.$"));

fn refused(code: Code, reason: String) -> Error {
    Error::Refusal(Refusal::new(code, reason))
}

fn quoted(text: &str) -> String {
    Text::from(text).repr()
}

fn tuple(items: &[&str]) -> String {
    let items: Vec<String> = items.iter().map(|item| quoted(item)).collect();
    format!("({})", items.join(", "))
}

/// The line of the `check!` invocation that carries `message` in the kernel file `declared` names. The
/// package is read from the declaration file under `root`. Lines are numbered as `str.splitlines`
/// splits them, and the message is found as the text `c"<message>"` anywhere on a line, a comment
/// included; the invocation is the nearest line at or above it that holds `check!(`.
///
/// # Errors
///
/// `check_line` returns a tool failure when the message stands on other than one line or no line at or
/// above it holds `check!(`, [`Error::Value`] for a kernel path that holds a NUL byte or bytes that are
/// no UTF-8, and [`Error::Os`] for a failed read.
pub fn check_line(root: &Path, declared: &Value, message: &Value) -> Result<usize, Error> {
    let expected = read_json(&root.join(EXPECTED))?;
    let package = string(member(&expected, "package")?, "the declared package")?;
    let file = member(declared, "file")?;
    let path: PathBuf = root
        .join(package)
        .join(string(file, "the declared kernel file")?)
        .components()
        .collect();
    let source = lines(&read_strict(openable(&path)?)?);
    let needle = str_of(message)
        .to_str()
        .map(|message| format!("c\"{message}\""));
    let lines: Vec<usize> = source
        .iter()
        .enumerate()
        .filter(|(_, text)| needle.as_ref().is_some_and(|needle| text.contains(needle)))
        .map(|(index, _)| index + 1)
        .collect();
    if lines.len() != 1 {
        return Err(tool_failure(format!(
            "the check {} appears {} times in {}",
            crate::python::repr(message),
            lines.len(),
            str_of(file)
        )));
    }
    (1..=lines[0])
        .rev()
        .find(|&number| source[number - 1].contains("check!("))
        .ok_or_else(|| {
            tool_failure(format!(
                "the message {} sits in no check! invocation",
                crate::python::repr(message)
            ))
        })
}

fn events(pattern: &Regex, text: &str, skipped: [&str; 2]) -> BTreeSet<(String, String)> {
    pattern
        .captures_iter(text)
        .filter(|found| {
            let rest = &text[found.get_match().end()..];
            !skipped.iter().any(|label| rest.starts_with(label))
        })
        .map(|found| (found[1].to_owned(), found[2].to_owned()))
        .collect()
}

/// Checks that the graph file at `graph` is the run's own: it is a nonempty regular file, its one
/// `ERROR` node is `event` at `at`, and its events are the events `text` prints after its violation
/// line.
///
/// # Errors
///
/// `check_graph` returns a tool failure for a graph that differs, and [`Error::Os`] for a failed read.
pub fn check_graph(
    name: &str,
    text: &str,
    graph: &Path,
    event: (&str, &str),
    at: (&str, &Integer),
) -> Result<(), Error> {
    let file = match open_file(graph).map_err(Error::Os)? {
        Some(file) if file.metadata().map_err(Error::Os)?.len() > 0 => file,
        _ => return Err(tool_failure(format!("{name} left no error graph"))),
    };
    let dot = replaced(file).map_err(Error::Os)?;
    let errors: Vec<[String; 4]> = GRAPH_ERROR
        .captures_iter(&dot)
        .map(|found| [1, 2, 3, 4].map(|group| found[group].to_owned()))
        .collect();
    let line = at.1.to_string();
    let reported = [event.0, event.1, at.0, line.as_str()];
    if errors.len() != 1 || errors[0] != reported {
        let marked: Vec<String> = errors
            .iter()
            .map(|error| tuple(&error.each_ref().map(String::as_str)))
            .collect();
        return Err(tool_failure(format!(
            "{name}'s graph marks errors [{}], the run reported {} at {}:{}",
            marked.join(", "),
            tuple(&[event.0, event.1]),
            at.0,
            at.1
        )));
    }
    // The dumped graph draws a thread's end for some threads only and a blocked join never, so both
    // event sets leave them out.
    let after = text
        .split_once("Error: Safety violation!")
        .map_or("", |(_, after)| after);
    if events(&GRAPH_EVENT, &dot, ["<THREAD_END", "<BLOCK"])
        != events(&TEXT_EVENT, after, ["THREAD_END", "BLOCK"])
    {
        return Err(tool_failure(format!(
            "{name}'s graph holds other events than the run reported"
        )));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Judged {
    at: Option<String>,
    executions: Integer,
}

impl Judged {
    pub fn result(&self) -> &'static str {
        if self.at.is_some() {
            "violation"
        } else {
            "positive"
        }
    }

    pub fn at(&self) -> Option<&str> {
        self.at.as_deref()
    }

    pub fn executions(&self) -> &Integer {
        &self.executions
    }
}

fn integer(digits: &str) -> Result<Integer, Error> {
    decimal(digits).map_err(Error::Value)
}

fn sorted_texts(value: &Value, what: &str) -> Result<Vec<Text>, Error> {
    let mut texts = Vec::new();
    for item in listed(value, what)? {
        let Value::String(text) = item else {
            return Err(Error::Type(format!("{what} is no string")));
        };
        texts.push(text.clone());
    }
    texts.sort();
    Ok(texts)
}

/// The result of one complete case run whose text, exit and graph match `declared`, a case's
/// declaration. A declaration whose `expect` is `positive` is judged as positive and any other as a
/// violation. `intrinsics` is the sorted list of the intrinsics the bitcode calls.
///
/// # Errors
///
/// `judge_case` returns a refusal for a run that does not match, and the errors of [`check_line`] and
/// [`check_graph`]; [`Error::Key`] or [`Error::Type`] for a declaration without a member it reads, and
/// [`Error::Value`] for a count or line of more than [`crate::json::MAX_INTEGER_DIGITS`] digits.
pub fn judge_case(
    root: &Path,
    name: &str,
    declared: &Value,
    text: &str,
    exit_code: &Integer,
    graph: &Path,
    intrinsics: &[String],
) -> Result<Judged, Error> {
    if super::refusal::INTERRUPTED
        .iter()
        .any(|&code| *exit_code == Integer::from(code))
    {
        return Err(Error::Refusal(Refusal::with_completion(
            Code::Incomplete,
            format!("{name} was interrupted (exit {exit_code})"),
            "timeout",
        )));
    }
    if let Some(wanted) = lookup(declared, "intrinsics")? {
        let wanted = sorted_texts(wanted, "the declared intrinsics")?;
        let same = intrinsics.len() == wanted.len()
            && intrinsics
                .iter()
                .zip(&wanted)
                .all(|(called, wanted)| wanted.to_str() == Some(called.as_str()));
        if !same {
            let wanted = Value::Array(wanted.into_iter().map(Value::String).collect());
            return Err(tool_failure(format!(
                "{name}'s bitcode calls {}, declared {}",
                repr(&strings(intrinsics)),
                repr(&wanted)
            )));
        }
    }
    let lines: Vec<String> = lines(text)
        .iter()
        .map(|line| Text::from(line.as_str()).strip().to_string())
        .filter(|line| !line.is_empty())
        .collect();
    if let Some(abort) = lines.iter().find(|line| ABORTS.is_match(line)) {
        return Err(tool_failure(format!("{name} aborted: {}", quoted(abort))));
    }
    single(&lines, &COMPILATION, name, "compilation")?;
    single(&lines, &TRANSFORMATION, name, "transformation")?;
    let executions = integer(&single(&lines, &EXECUTIONS, name, "execution count")?[1])?;
    let errors: Vec<_> = lines
        .iter()
        .filter_map(|line| ERROR_EVENT.captures(line))
        .collect();
    if equal(
        member(declared, "expect")?,
        &Value::String("positive".into()),
    ) {
        positive(name, exit_code, &lines, !errors.is_empty(), executions)
    } else {
        violation(
            root, name, declared, text, exit_code, graph, &lines, &errors, executions,
        )
    }
}

/// The rules of a case declared positive, after the rules every case shares.
fn positive(
    name: &str,
    exit_code: &Integer,
    lines: &[String],
    errors: bool,
    executions: Integer,
) -> Result<Judged, Error> {
    let zero = Integer::from(0_u64);
    if *exit_code != zero {
        let code = if *exit_code == Integer::from(42_u64) {
            Code::Mismatch
        } else {
            Code::ToolFailure
        };
        return Err(refused(
            code,
            format!("{name} exited {exit_code}, declared positive"),
        ));
    }
    single(lines, &COMPLETE, name, "Verification complete")?;
    single(lines, &NO_ERRORS, name, "No errors")?;
    if errors || lines.iter().any(|line| line.starts_with("Error:")) {
        return Err(tool_failure(format!(
            "{name} reports an error beside exit 0"
        )));
    }
    if executions == zero {
        return Err(refused(
            Code::Mismatch,
            format!("{name} explored no complete execution"),
        ));
    }
    if let Some(blocked) = lines
        .iter()
        .find(|line| line.starts_with("Number of blocked executions seen:"))
    {
        return Err(refused(
            Code::Mismatch,
            format!("{name} pruned executions: {}", quoted(blocked)),
        ));
    }
    Ok(Judged {
        at: None,
        executions,
    })
}

/// The rules of a case declared a violation, after the rules every case shares.
#[expect(
    clippy::too_many_arguments,
    reason = "each argument is one input the violation rules read"
)]
fn violation(
    root: &Path,
    name: &str,
    declared: &Value,
    text: &str,
    exit_code: &Integer,
    graph: &Path,
    lines: &[String],
    errors: &[regex::Captures<'_>],
    executions: Integer,
) -> Result<Judged, Error> {
    let zero = Integer::from(0_u64);
    let violation = Integer::from(42_u64);
    if *exit_code != violation {
        let code = if *exit_code == zero {
            Code::Mismatch
        } else {
            Code::ToolFailure
        };
        return Err(refused(
            code,
            format!("{name} exited {exit_code}, declared a violation"),
        ));
    }
    single(lines, &SAFETY, name, "Safety violation")?;
    single(lines, &UNSUCCESSFUL, name, "Verification unsuccesful")?;
    for (pattern, what) in [
        (&*COMPLETE, "Verification complete"),
        (&*NO_ERRORS, "No errors"),
    ] {
        let successes = lines.iter().filter(|line| pattern.is_match(line)).count();
        if successes > 0 {
            return Err(tool_failure(format!(
                "{name} prints {successes} {what} lines beside a violation"
            )));
        }
    }
    if errors.len() != 1 {
        return Err(tool_failure(format!(
            "{name} reports {} ERROR events",
            errors.len()
        )));
    }
    let found = &errors[0];
    let event = (&found[1], &found[2]);
    let file = &found[3];
    let line = integer(&found[4])?;
    let checks = member(declared, "checks")?;
    let checks = listed(checks, "the declared checks")?;
    let mut wanted = Vec::new();
    for message in checks {
        let kernel = string(member(declared, "file")?, "the declared kernel file")?;
        wanted.push((
            crate::paths::name(kernel).to_owned(),
            check_line(root, declared, message)?,
        ));
    }
    if !wanted
        .iter()
        .any(|(kernel, at)| kernel == file && line == Integer::from(*at))
    {
        let accepted: Vec<String> = wanted
            .iter()
            .map(|(kernel, at)| format!("{kernel}:{at}"))
            .collect();
        return Err(refused(
            Code::Mismatch,
            format!(
                "{name} failed at {file}:{line}, declared {}",
                accepted.join(", ")
            ),
        ));
    }
    check_graph(name, text, graph, event, (file, &line))?;
    Ok(Judged {
        at: Some(format!("{file}:{line}")),
        executions,
    })
}

#[cfg(test)]
#[path = "case_tests.rs"]
pub(crate) mod tests;
