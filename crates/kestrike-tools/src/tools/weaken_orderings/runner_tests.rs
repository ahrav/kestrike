use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::super::execute::Launch;
use super::super::halt::Halt;
use super::{Runner, Runs};
use crate::genmc::case::tests::POSITIVE;
use crate::json::{self, Text, Value};
use crate::orderings::check::GENMC;
use crate::orderings::sources::kernel_texts;
use crate::paths::tests::Scratch;
use crate::process::Interrupt;

fn top() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the checkout resolves")
}

/// The lane call's stand-in: it leaves one case's output and exit in the lane's evidence directory and
/// reports the deadline, no exit code.
fn expired(
    _: &Launch<'_>,
    _: &[OsString],
    _: &Path,
    env: Option<&[(OsString, OsString)]>,
    _: Duration,
    output: &Path,
) -> Result<(Option<i32>, f64), Halt> {
    std::fs::write(output, "").expect("the lane's output writes");
    let evidence = env
        .and_then(|env| env.iter().find(|(name, _)| name == "EVIDENCE"))
        .map(|(_, value)| PathBuf::from(value))
        .expect("the lane is given its evidence directory");
    std::fs::write(evidence.join("genmc-join-production.txt"), POSITIVE).expect("written");
    std::fs::write(evidence.join("genmc-join-production.exit"), "0\n").expect("written");
    Ok((None, 1.0))
}

/// A lane call past its deadline gives every case of the call no verdict, whatever a case's own output
/// and exit, and each result keeps the exit the lane recorded for its case.
#[test]
fn a_genmc_lane_past_its_deadline_gives_no_verdict_for_every_case() {
    let scratch = Scratch::new("weaken-lane-deadline");
    let top = top();
    let declared =
        json::parse(&std::fs::read_to_string(top.join(GENMC)).expect("reads")).expect("parses");
    let Value::Object(object) = &declared else {
        panic!("the declaration is an object");
    };
    let Some(Value::String(package)) = object.get("package") else {
        panic!("the declaration names its package");
    };
    let kernels = kernel_texts(&top.join(package.to_string())).expect("the kernels read");
    let interrupt = Interrupt::new();
    let launch = Launch::new(&interrupt);
    let pins = [
        ("STABLE", "1.99.0"),
        ("NIGHTLY", "nightly-2026-07-27"),
        ("LOOM", "0.7.2"),
    ]
    .map(|(name, value)| (name.to_owned(), value.to_owned()))
    .into();
    let evidence = scratch.0.join("evidence");
    std::fs::create_dir(&evidence).expect("made");
    let mut runner = Runner {
        work: scratch.0.clone(),
        copy: top,
        evidence,
        revision: "0".repeat(40),
        pins,
        environ: Vec::new(),
        launch: &launch,
        execute: expired,
        serial: 0,
        rebuilt: None,
        declared,
        kernels,
        reads: std::cell::RefCell::new(BTreeMap::new()),
    };
    let cases = [
        Text::from("join-production"),
        Text::from("credit-seq-empty"),
    ];
    let mut runs: Runs = BTreeMap::new();
    let results = runner
        .genmc(&cases, "", Some(&Text::from("row00")), &mut runs)
        .expect("the lane is judged");
    let field = |result: &Value, key: &str| match result {
        Value::Object(result) => result.get(key).cloned().expect("a member"),
        _ => panic!("a result is an object"),
    };
    for result in &results {
        assert_eq!(field(result, "lane_exit"), Value::Null);
        assert_eq!(
            field(result, "result"),
            Value::String(Text::from("no verdict"))
        );
        assert_eq!(
            field(result, "reason"),
            Value::String(Text::from("the lane passed its deadline"))
        );
    }
    assert_eq!(results.len(), 2);
    assert_eq!(
        field(&results[0], "exit"),
        json::parse("0").expect("parses")
    );
}
