//! [`loom_result`] judges a loom test's output and [`genmc_result`] a GenMC case's evidence directory,
//! each as killed, survived or no verdict with a reason. The caller vouches for the evidence directory
//! and the checkout root it names. [`genmc_result`] treats files under both as trusted input.

use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

use crate::classes::{SPACE, compiled};
use crate::genmc::case::judge_case;
use crate::genmc::evidence::{check_command, check_config};
use crate::genmc::is_file;
use crate::genmc::read_text;
use crate::genmc::refusal::{
    Error, lines, member, open_file, parse_json, read_replaced, read_strict, replaced, strict,
};
use crate::json::{Integer, Object, Text, Value};
use crate::python::{ascii_digits, decimal, int, str_of};

static LOOM_PASS: LazyLock<Regex> =
    LazyLock::new(|| compiled(r"(?m)^test result: ok\. 1 passed; 0 failed; 0 ignored;"));
static LOOM_FAIL: LazyLock<Regex> =
    LazyLock::new(|| compiled(r"(?m)^test result: FAILED\. 0 passed; 1 failed; 0 ignored;"));
static LOOM_IGNORED: LazyLock<Regex> =
    LazyLock::new(|| compiled(r"(?m)^test result: ok\. 0 passed; 0 failed; 1 ignored;"));
static LOOM_ABSENT: LazyLock<Regex> =
    LazyLock::new(|| compiled(r"(?m)^test result: ok\. 0 passed; 0 failed; 0 ignored;"));
static LOOM_RUNNING: LazyLock<Regex> = LazyLock::new(|| compiled(r"(?m)^running \d+ tests?$"));
static PANIC: LazyLock<Regex> = LazyLock::new(|| {
    compiled(r"(?m)^thread '[^']*'(?: \(\d+\))? panicked at ([^\n]*?):(\d+):\d+:\n(.*)$")
});

/// The Cargo status line of a build that compiled the `kestrike` crate, the evidence that a plant took
/// effect in a loom run.
pub static LOOM_REBUILT: LazyLock<Regex> =
    LazyLock::new(|| compiled(&format!(r"(?m)^{SPACE}*Compiling kestrike v")));
static GENMC_REBUILT: LazyLock<Regex> = LazyLock::new(|| {
    compiled(&format!(
        r"(?m)^{SPACE}*(?:Checking|Compiling) genmc-kernels v"
    ))
});

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Killed,
    Survived,
    NoVerdict,
}

impl Verdict {
    pub fn name(self) -> &'static str {
        match self {
            Self::Killed => "killed",
            Self::Survived => "survived",
            Self::NoVerdict => "no verdict",
        }
    }
}

fn no_verdict(reason: &str) -> (Verdict, String) {
    (Verdict::NoVerdict, reason.to_owned())
}

/// The verdict of one loom test from its output `text`, whose `\r\n` and lone `\r` the caller has
/// read as `\n`. `code` is `None` when the run reaches its deadline. `rebuilt` is true for an unplanted
/// run, and for a planted one once any test output of its plant matched [`LOOM_REBUILT`]. A panic kills
/// the test only where it reports `site`, the file and line of the assertion that holds `failure`, and
/// the first line of its message holds `failure`. `Survived` holds for one test that passed under the
/// bounds its model sets: the caller clears each `LOOM_*` variable and refuses a `LOOM_*` entry in
/// Cargo's `[env]` before the run, and this function sees neither.
///
/// # Errors
///
/// `loom_result` returns [`Error::Value`] when such a panic reports a line of more than
/// [`MAX_INTEGER_DIGITS`](crate::json::MAX_INTEGER_DIGITS) digits.
pub fn loom_result(
    text: &str,
    code: Option<i32>,
    failure: &str,
    rebuilt: bool,
    site: Option<(&str, usize)>,
) -> Result<(Verdict, String), Error> {
    let Some(code) = code else {
        return Ok(no_verdict("timeout"));
    };
    if !rebuilt {
        return Ok(no_verdict("no evidence that kestrike rebuilt"));
    }
    if code == 0 && LOOM_PASS.is_match(text) {
        return Ok((Verdict::Survived, "one executed test passed".to_owned()));
    }
    if code != 0 && LOOM_FAIL.is_match(text) {
        if let Some((path, line)) = site.filter(|_| !failure.is_empty()) {
            for panic in PANIC.captures_iter(text) {
                if !panic[3].contains(failure) {
                    continue;
                }
                let at = decimal(&panic[2]).map_err(Error::Value)?;
                if &panic[1] == path && at == Integer::from(line) {
                    return Ok((
                        Verdict::Killed,
                        format!(
                            "failed with {} at {path}:{line}",
                            Text::from(failure).repr()
                        ),
                    ));
                }
            }
        }
        return Ok(no_verdict(
            "failed with another text or at another assertion",
        ));
    }
    if LOOM_IGNORED.is_match(text) {
        return Ok(no_verdict("the test is ignored"));
    }
    if LOOM_ABSENT.is_match(text) {
        return Ok(no_verdict("the test is absent: no test matched its name"));
    }
    if !LOOM_RUNNING.is_match(text) {
        return Ok(no_verdict("a build failure"));
    }
    Ok(no_verdict(
        "the test crashed: its run ended without a summary",
    ))
}

/// The exit the lane recorded for `case` in `genmc-<case>.exit`, read as `int` reads a string, or `None`
/// for a file that does not read or holds no integer.
pub fn case_exit(evidence: &Path, case: &str) -> Option<Integer> {
    let text = read_text(&evidence.join(format!("genmc-{case}.exit"))).ok()?;
    let digits = ascii_digits(&text);
    int(&Value::String(Text::from(digits.as_str()).strip())).ok()
}

/// The lane's `identity.json`, with the fields [`check_command`] reads checked for their JSON type.
///
/// # Errors
///
/// `identity_record` returns [`Error::Value`] for a record of another shape, bytes that are no UTF-8 or
/// JSON the reader refuses, [`Error::Runtime`] for nesting past [`crate::json::MAX_DEPTH`], and
/// [`Error::Os`] for a failed read.
pub fn identity_record(evidence: &Path) -> Result<Value, Error> {
    let record = parse_json(&read_strict(&evidence.join("identity.json"))?)?;
    let text = |value: Option<&Value>| matches!(value, Some(Value::String(_)));
    fn object(value: Option<&Value>) -> Option<&Object> {
        match value {
            Some(Value::Object(object)) => Some(object),
            _ => None,
        }
    }
    let shaped = match &record {
        Value::Object(record) => {
            object(record.get("binary")).is_some_and(|binary| text(binary.get("path")))
                && object(record.get("rustc"))
                    .is_some_and(|rustc| text(rustc.get("name")) && text(rustc.get("toolchain")))
        }
        _ => false,
    };
    if !shaped {
        return Err(Error::Value(
            "the identity record lacks a binary path or a rustc name and toolchain".to_owned(),
        ));
    }
    Ok(record)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    verdict: Verdict,
    reason: String,
    executions: Option<Integer>,
}

impl Outcome {
    fn none(reason: String) -> Self {
        Self {
            verdict: Verdict::NoVerdict,
            reason,
            executions: None,
        }
    }

    pub fn verdict(&self) -> Verdict {
        self.verdict
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }

    pub fn executions(&self) -> Option<&Integer> {
        self.executions.as_ref()
    }
}

fn checked_command(
    root: &Path,
    declared: &Value,
    case: &str,
    evidence: &Path,
) -> Result<(), Error> {
    check_config(evidence)?;
    let mut env = Object::new();
    let env_text = read_strict(&evidence.join(format!("genmc-{case}.env")))?;
    for line in lines(&env_text) {
        if let Some((name, value)) = line.split_once('=') {
            env.insert(name, Value::String(value.into()));
        }
    }
    let record = identity_record(evidence)?;
    let argv = lines(&read_strict(&evidence.join(format!("genmc-{case}.argv")))?);
    check_command(root, case, declared, &record, &argv, &env, evidence)
}

/// The verdict of one GenMC case, `case` of the declaration `declared`, from the files its lane left in
/// `evidence`. The caller selects a case declared `positive`: the first attempt judges the case's own
/// declaration, and its acceptance is `Survived`. `kill` is the failure text and the kernel file of the
/// case family; with both nonempty, a second attempt judges the case as a violation at the `check!` of
/// that file that carries the failure, and its acceptance is `Killed`. `code` is
/// [`case_exit`] of the same directory and case; this function checks that the exit file is present and
/// judges with `code`. A lane that passed its own deadline is the caller's to refuse before this call.
///
/// # Errors
///
/// A refusal, an OS error, a value error or a missing member of the configuration and command check,
/// and a refusal or an OS error of each attempt, become a no-verdict reason. `genmc_result` returns
/// every other error: a link loop at the graph path, nesting past [`crate::json::MAX_DEPTH`] in the
/// identity record, a type error of the declaration, and a failed read or bytes that are no UTF-8 in
/// the intrinsics file.
pub fn genmc_result(
    root: &Path,
    declared: &Value,
    case: &str,
    kill: Option<(&str, &str)>,
    evidence: &Path,
    planted: bool,
    code: Option<&Integer>,
) -> Result<Outcome, Error> {
    for kind in ["txt", "exit", "argv", "env"] {
        if !is_file(&evidence.join(format!("genmc-{case}.{kind}"))).map_err(Error::Os)? {
            return Ok(Outcome::none("the lane left no output".to_owned()));
        }
    }
    if !is_file(&evidence.join("identity.json")).map_err(Error::Os)? {
        return Ok(Outcome::none("the lane left no output".to_owned()));
    }
    match checked_command(root, declared, case, evidence) {
        Ok(()) => {}
        Err(error @ (Error::Refusal(_) | Error::Os(_) | Error::Value(_) | Error::Key(_))) => {
            return Ok(Outcome::none(format!(
                "the lane's build or command is not the declared one: {error}"
            )));
        }
        Err(error) => return Err(error),
    }
    let check_log = evidence.join(format!("check-{case}.txt"));
    let rebuilt = |check_log: &Path| -> Result<bool, Error> {
        Ok(match open_file(check_log).map_err(Error::Os)? {
            Some(file) => GENMC_REBUILT.is_match(&replaced(file).map_err(Error::Os)?),
            None => false,
        })
    };
    if planted && !rebuilt(&check_log)? {
        return Ok(Outcome::none(
            "no evidence that the kernel rebuilt".to_owned(),
        ));
    }
    let Some(code) = code else {
        return Ok(Outcome::none("no exit code".to_owned()));
    };
    let text = read_replaced(&evidence.join(format!("genmc-{case}.txt"))).map_err(Error::Os)?;
    let called = evidence.join(format!("genmc-{case}.intrinsics"));
    let mut intrinsics: Vec<String> = if let Some(file) = open_file(&called).map_err(Error::Os)? {
        let text = strict(file)?;
        Text::from(text.as_str())
            .split()
            .iter()
            .map(ToString::to_string)
            .collect()
    } else {
        Vec::new()
    };
    intrinsics.sort();
    intrinsics.dedup();
    let graph = evidence.join(format!("genmc-{case}.dot"));
    let own = member(member(declared, "cases")?, case)?;
    let mut attempts = vec![(Verdict::Survived, own.clone())];
    if let Some((failure, kernel)) =
        kill.filter(|(failure, kernel)| !failure.is_empty() && !kernel.is_empty())
    {
        let Value::Object(own) = own else {
            return Err(Error::Type("a case declaration is no object".to_owned()));
        };
        let mut killing = own.clone();
        killing.insert("expect", Value::String("violation".into()));
        killing.insert("file", Value::String(kernel.into()));
        killing.insert("checks", Value::Array(vec![Value::String(failure.into())]));
        attempts.push((Verdict::Killed, Value::Object(killing)));
    }
    let mut reasons = Vec::new();
    for (verdict, declaration) in &attempts {
        match judge_case(root, case, declaration, &text, code, &graph, &intrinsics) {
            Ok(judged) => {
                return Ok(Outcome {
                    verdict: *verdict,
                    reason: format!(
                        "judge_case accepts the {} declaration",
                        str_of(member(declaration, "expect")?)
                    ),
                    executions: Some(judged.executions().clone()),
                });
            }
            Err(error @ (Error::Refusal(_) | Error::Os(_))) => reasons.push(error.to_string()),
            Err(error) => return Err(error),
        }
    }
    Ok(Outcome::none(reasons.join("; ")))
}

#[cfg(test)]
#[path = "verdicts_tests.rs"]
pub(crate) mod tests;
