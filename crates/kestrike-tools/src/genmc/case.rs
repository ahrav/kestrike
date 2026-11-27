//! The case judge checks the graph and the `check!` lines in the declared kernel file.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

use super::refusal::{
    Code, Error, Refusal, lookup, member, read_json, read_replaced, read_strict, single, string,
};
use crate::classes::{SPACE, compiled};
use crate::genmc::is_file;
use crate::json::{Integer, Text, Value};
use crate::python::{decimal, equal, members, str_of};

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

fn tool_failure(reason: String) -> Error {
    refused(Code::ToolFailure, reason)
}

fn quoted(text: &str) -> String {
    Text::from(text).repr()
}

fn tuple(items: &[&str]) -> String {
    let items: Vec<String> = items.iter().map(|item| quoted(item)).collect();
    format!("({})", items.join(", "))
}

fn name_of(path: &str) -> &str {
    path.split('/')
        .rfind(|part| !part.is_empty() && *part != ".")
        .unwrap_or("")
}

fn lines_of(text: &str) -> Vec<String> {
    Text::from(text)
        .splitlines()
        .iter()
        .map(|line| line.to_string())
        .collect()
}

pub fn check_line(root: &Path, declared: &Value, message: &Value) -> Result<usize, Error> {
    let expected = read_json(&root.join(EXPECTED))?;
    let package = string(member(&expected, "package")?, "the declared package")?;
    let file = member(declared, "file")?;
    let path = root
        .join(package)
        .join(string(file, "the declared kernel file")?);
    let source = lines_of(&read_strict(&path)?);
    let needle = format!("c\"{}\"", str_of(message));
    let lines: Vec<usize> = source
        .iter()
        .enumerate()
        .filter(|(_, text)| text.contains(&needle))
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

pub fn check_graph(
    name: &str,
    text: &str,
    graph: &Path,
    event: (&str, &str),
    at: (&str, &Integer),
) -> Result<(), Error> {
    if !is_file(graph).map_err(Error::Os)? || fs::metadata(graph).map_err(Error::Os)?.len() == 0 {
        return Err(tool_failure(format!("{name} left no error graph")));
    }
    let dot = read_replaced(graph).map_err(Error::Os)?;
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

fn sorted_texts(value: &Value, what: &str) -> Result<Vec<String>, Error> {
    let listed = members(value).ok_or_else(|| Error::Type(format!("{what} is not iterable")))?;
    let mut texts = Vec::new();
    for item in &listed {
        texts.push(string(item, what)?.to_owned());
    }
    texts.sort();
    Ok(texts)
}

fn texts_repr(texts: &[String]) -> String {
    let items: Vec<String> = texts.iter().map(|text| quoted(text)).collect();
    format!("[{}]", items.join(", "))
}

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
        return Err(Error::Refusal(Refusal::completed(
            Code::Incomplete,
            format!("{name} was interrupted (exit {exit_code})"),
            "timeout",
        )));
    }
    if let Some(wanted) = lookup(declared, "intrinsics")? {
        let wanted = sorted_texts(wanted, "the declared intrinsics")?;
        if intrinsics != wanted.as_slice() {
            return Err(tool_failure(format!(
                "{name}'s bitcode calls {}, declared {}",
                texts_repr(intrinsics),
                texts_repr(&wanted)
            )));
        }
    }
    let lines: Vec<String> = lines_of(text)
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
    let zero = Integer::from(0_u64);
    let violation = Integer::from(42_u64);
    if equal(
        member(declared, "expect")?,
        &Value::String("positive".into()),
    ) {
        if *exit_code != zero {
            let code = if *exit_code == violation {
                Code::Mismatch
            } else {
                Code::ToolFailure
            };
            return Err(refused(
                code,
                format!("{name} exited {exit_code}, declared positive"),
            ));
        }
        single(&lines, &COMPLETE, name, "Verification complete")?;
        single(&lines, &NO_ERRORS, name, "No errors")?;
        if !errors.is_empty() || lines.iter().any(|line| line.starts_with("Error:")) {
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
        return Ok(Judged {
            at: None,
            executions,
        });
    }
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
    single(&lines, &SAFETY, name, "Safety violation")?;
    single(&lines, &UNSUCCESSFUL, name, "Verification unsuccesful")?;
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
    let checks = members(checks)
        .ok_or_else(|| Error::Type("the declared checks are not iterable".into()))?;
    let mut wanted = Vec::new();
    for message in &checks {
        let kernel = string(member(declared, "file")?, "the declared kernel file")?;
        wanted.push((
            name_of(kernel).to_owned(),
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
