//! A plant's entry for each of the five results, the score of a run, its bytes, its lines and the exit
//! code; the stored `verification/plants/score.json` is read and written back byte for byte.

use std::fs;
use std::path::Path;

use kestrike_tools::json::{self, Value};
use kestrike_tools::plants::score::{bytes, exit_code, lines, result_line, score};
use kestrike_tools::plants::{Entry, Finished, NoVerdict, Options, Outcome, Plant};
use kestrike_tools::text::Text;

use super::judgment::{alpha, judged_row, pins, shown};
use super::repository::{Repository, members, record};

/// The miss cause of the plants of `unprofiled(CAUSE)`.
const CAUSE: &str = r#"{"cause": "workload", "evidence": "no profile drives it"}"#;

fn plants(repository: &Repository) -> Vec<Plant> {
    let Outcome::Run(inputs) = repository.prepare(&repository.call(&[])) else {
        panic!("the fixture's checks pass");
    };
    inputs.plants().to_vec()
}

/// `unprofiled` is a fixture whose plants expect no profile, each with the miss cause `cause`.
fn unprofiled(cause: &str) -> Repository {
    let repository = Repository::new();
    for (id, file) in [("alpha", "src/lib.rs"), ("beta", "src/util.rs")] {
        let mut fields = members(id, file);
        for (name, value) in &mut fields {
            if name == "miss_cause" {
                *value = cause.to_owned();
            }
            if name == "expected" {
                *value = "[]".to_owned();
            }
        }
        repository.write(
            &format!("verification/plants/{id}/plant.json"),
            record(&fields),
        );
    }
    repository.commit();
    repository
}

/// Each result leaves its members in the order the steps first set them: `suspect` for a catch alone,
/// `miss_cause` for a miss alone, and the work directory written as `<work>` in the reason.
#[test]
fn each_result_leaves_its_members_in_order() {
    let rows: &[(&str, &str)] = &[
        (
            r#"does not apply"#,
            r#"{"id":"alpha","row":7,"fix":{"pull_request":12,"commit":"0123abc"},"files":["src/lib.rs"],"proof":"tests::the_proof","campaign":"plant-alpha","profiles":["smoke","crash-loop"],"proof_exits":null,"commit":null,"tree":null,"archive":null,"counts":null,"runs":{},"controls":null,"histories":null,"keys":{},"head_failures":[],"result":"does not apply","reason":"error: patch failed: src/lib.rs:1"}"#,
        ),
        (
            r#"prove 1 1"#,
            r#"{"id":"alpha","row":7,"fix":{"pull_request":12,"commit":"0123abc"},"files":["src/lib.rs"],"proof":"tests::the_proof","campaign":"plant-alpha","profiles":["smoke","crash-loop"],"proof_exits":{"head":1,"plant":1},"commit":null,"tree":null,"archive":null,"counts":null,"runs":{},"controls":null,"histories":null,"keys":{},"head_failures":[],"result":"not live","reason":"its proof exits 1 on the head and 1 on the plant, where a live plant's proof exits 0 and 1"}"#,
        ),
        (
            r#"prove 0 0"#,
            r#"{"id":"alpha","row":7,"fix":{"pull_request":12,"commit":"0123abc"},"files":["src/lib.rs"],"proof":"tests::the_proof","campaign":"plant-alpha","profiles":["smoke","crash-loop"],"proof_exits":{"head":0,"plant":0},"commit":null,"tree":null,"archive":null,"counts":null,"runs":{},"controls":null,"histories":null,"keys":{},"head_failures":[],"result":"not live","reason":"its proof exits 0 on the head and 0 on the plant, where a live plant's proof exits 0 and 1"}"#,
        ),
        (
            r#"prove 1 0"#,
            r#"{"id":"alpha","row":7,"fix":{"pull_request":12,"commit":"0123abc"},"files":["src/lib.rs"],"proof":"tests::the_proof","campaign":"plant-alpha","profiles":["smoke","crash-loop"],"proof_exits":{"head":1,"plant":0},"commit":null,"tree":null,"archive":null,"counts":null,"runs":{},"controls":null,"histories":null,"keys":{},"head_failures":[],"result":"not live","reason":"its proof exits 1 on the head and 0 on the plant, where a live plant's proof exits 0 and 1"}"#,
        ),
        (
            r#"prove 0 1"#,
            r#"{"id":"alpha","row":7,"fix":{"pull_request":12,"commit":"0123abc"},"files":["src/lib.rs"],"proof":"tests::the_proof","campaign":"plant-alpha","profiles":["smoke","crash-loop"],"proof_exits":{"head":0,"plant":1},"commit":null,"tree":null,"archive":null,"counts":null,"runs":{},"controls":null,"histories":null,"keys":{},"head_failures":[],"result":"no verdict","reason":"`git apply` exited 1 in <work>/plants/alpha/tree"}"#,
        ),
        (
            r#"unswept"#,
            r#"{"id":"alpha","row":7,"fix":{"pull_request":12,"commit":"0123abc"},"files":["src/lib.rs"],"proof":"tests::the_proof","campaign":"plant-alpha","profiles":[],"proof_exits":null,"commit":"c","tree":"t","archive":"a","counts":null,"runs":{},"controls":null,"histories":null,"keys":{},"head_failures":[],"result":"missed","reason":"no expected profile; no sweep ran","miss_cause":{"cause":"workload","evidence":"no profile drives it"}}"#,
        ),
        (
            r#"unswept without a cause"#,
            r#"{"id":"alpha","row":7,"fix":{"pull_request":12,"commit":"0123abc"},"files":["src/lib.rs"],"proof":"tests::the_proof","campaign":"plant-alpha","profiles":[],"proof_exits":null,"commit":"c","tree":"t","archive":"a","counts":null,"runs":{},"controls":null,"histories":null,"keys":{},"head_failures":[],"result":"missed","reason":"no expected profile; no sweep ran","miss_cause":null}"#,
        ),
    ];
    let (plain, caused, uncaused) = (Repository::new(), unprofiled(CAUSE), unprofiled("null"));
    let alpha = plants(&plain).remove(0);
    let (with_cause, without_cause) = (plants(&caused).remove(0), plants(&uncaused).remove(0));
    let work = Path::new("/work/of/the/run");
    for (name, expected) in rows {
        let mut entry = Entry::new(match *name {
            "unswept" => &with_cause,
            "unswept without a cause" => &without_cause,
            _ => &alpha,
        });
        match *name {
            "does not apply" => {
                entry.does_not_apply(Text::from("error: patch failed: src/lib.rs:1"))
            }
            "unswept" | "unswept without a cause" => {
                entry.set_commit(&Text::from("c"));
                entry.set_tree(&Text::from("t"));
                assert!(!entry.archived(&pins("a")), "{name} has no sweep");
            }
            proved => {
                let exits: Vec<u8> = proved[6..]
                    .split(' ')
                    .map(|exit| exit.parse().expect("an exit"))
                    .collect();
                entry.prove(exits[0], exits[1]);
                if entry.verdict().is_none() {
                    let reason = "`git apply` exited 1 in /work/of/the/run/plants/alpha/tree";
                    entry.no_verdict(&NoVerdict::plain(reason));
                }
            }
        }
        let entry = entry.finish(work).expect("a result");
        assert_eq!(shown(&entry), *expected, "{name}");
    }
}

/// A plant that expects a profile goes on from its archive to its sweeps without a result, and an entry
/// without a result, a live proof's included, finishes as `None`.
#[test]
fn an_entry_finishes_once_a_step_sets_its_result() {
    let repository = Repository::new();
    let alpha = plants(&repository).remove(0);
    let mut entry = Entry::new(&alpha);
    assert!(entry.archived(&pins("a")));
    assert_eq!(entry.verdict(), None);
    assert_eq!(entry.finish(Path::new("/w")), None);
    let mut proved = Entry::new(&alpha);
    proved.prove(0, 1);
    assert_eq!(proved.finish(Path::new("/w")), None);
}

/// `settled` is a finished entry of `plant` with the result `result`, the way a run's steps set it: a
/// catch through the judgment, a miss of a plant without a sweep, a proof that exits 1 twice, and any
/// other result with the reason `the reason of NUMBER`.
fn settled(result: &str, number: usize, plant: &(Plant, Options), work: &Path) -> Finished {
    if result == "caught" {
        let entry = judged_row(
            "a_confirmed_suspect_whose_seed_passes_on_the_head_is_caught",
            plant,
            work,
        );
        fs::remove_dir_all(work).expect("removed");
        return entry;
    }
    let mut entry = Entry::new(&plant.0);
    let reason = Text::from(format!("the reason of {number}"));
    match result {
        "not live" => entry.prove(1, 1),
        "missed" => assert!(!entry.archived(&pins("a"))),
        "does not apply" => entry.does_not_apply(reason),
        "no verdict" => entry.no_verdict(&NoVerdict::plain(reason)),
        other => panic!("no result {other}"),
    }
    entry.finish(work).expect("a result")
}

/// The score tallies results in the order they first occur, counts the caught and the missed plants,
/// lists the plants that are not live, and exits 1 for a miss without its cause, else 3 for a plant
/// without a verdict, else 0.
#[test]
fn a_score_tallies_its_results_and_gives_the_exit_code() {
    type ScoreRow = (
        &'static [(&'static str, bool)],
        &'static str,
        &'static [&'static str],
        u8,
        Option<&'static str>,
    );
    let rows: &[ScoreRow] = &[
        (
            &[],
            r#"{"commit":"c0ffee","sentence":"0 of 0 plants at commit c0ffee","results":{},"not_live":[],"settings":{"workers":28,"runs":300,"seconds":60,"rounds":10,"base_archive":null,"campaign_sha256":"0000000000000000000000000000000000000000000000000000000000000000","plants":["b","a"]},"plants":[]}"#,
            &[r#"0 of 0 plants at commit c0ffee"#],
            0,
            Some(
                "{\n  \"commit\": \"c0ffee\",\n  \"sentence\": \"0 of 0 plants at commit c0ffee\",\n  \"results\": {},\n  \"not_live\": [],\n  \"settings\": {\n    \"workers\": 28,\n    \"runs\": 300,\n    \"seconds\": 60,\n    \"rounds\": 10,\n    \"base_archive\": null,\n    \"campaign_sha256\": \"0000000000000000000000000000000000000000000000000000000000000000\",\n    \"plants\": [\n      \"b\",\n      \"a\"\n    ]\n  },\n  \"plants\": []\n}\n",
            ),
        ),
        (
            &[
                (r#"no verdict"#, false),
                (r#"caught"#, false),
                (r#"not live"#, false),
                (r#"caught"#, false),
                (r#"missed"#, true),
                (r#"does not apply"#, false),
                (r#"not live"#, false),
            ],
            r#"{"commit":"c0ffee","sentence":"2 of 3 plants at commit c0ffee","results":{"no verdict":1,"caught":2,"not live":2,"missed":1,"does not apply":1},"not_live":["alpha","alpha"],"settings":{"workers":28,"runs":300,"seconds":60,"rounds":10,"base_archive":null,"campaign_sha256":"0000000000000000000000000000000000000000000000000000000000000000","plants":["b","a"]},"plants":["alpha","beta","alpha","beta","alpha","beta","alpha"]}"#,
            &[
                r#"2 of 3 plants at commit c0ffee"#,
                r#"alpha: no verdict (the reason of 0)"#,
                r#"beta: caught (violation: a in run 1 of smoke)"#,
                r#"alpha: not live (its proof exits 1 on the head and 1 on the plant, where a live plant's proof exits 0 and 1)"#,
                r#"beta: caught (violation: a in run 1 of smoke)"#,
                r#"alpha: missed (no expected profile; no sweep ran)"#,
                r#"beta: does not apply (the reason of 5)"#,
                r#"alpha: not live (its proof exits 1 on the head and 1 on the plant, where a live plant's proof exits 0 and 1)"#,
            ],
            3,
            None,
        ),
        (
            &[(r#"missed"#, false), (r#"caught"#, false)],
            r#"{"commit":"c0ffee","sentence":"1 of 2 plants at commit c0ffee","results":{"missed":1,"caught":1},"not_live":[],"settings":{"workers":28,"runs":300,"seconds":60,"rounds":10,"base_archive":null,"campaign_sha256":"0000000000000000000000000000000000000000000000000000000000000000","plants":["b","a"]},"plants":["alpha","beta"]}"#,
            &[
                r#"1 of 2 plants at commit c0ffee"#,
                r#"alpha: missed (no expected profile; no sweep ran)"#,
                r#"beta: caught (violation: a in run 1 of smoke)"#,
            ],
            1,
            None,
        ),
        (
            &[(r#"missed"#, true), (r#"no verdict"#, false)],
            r#"{"commit":"c0ffee","sentence":"0 of 1 plants at commit c0ffee","results":{"missed":1,"no verdict":1},"not_live":[],"settings":{"workers":28,"runs":300,"seconds":60,"rounds":10,"base_archive":null,"campaign_sha256":"0000000000000000000000000000000000000000000000000000000000000000","plants":["b","a"]},"plants":["alpha","beta"]}"#,
            &[
                r#"0 of 1 plants at commit c0ffee"#,
                r#"alpha: missed (no expected profile; no sweep ran)"#,
                r#"beta: no verdict (the reason of 1)"#,
            ],
            3,
            None,
        ),
        (
            &[(r#"missed"#, true), (r#"caught"#, false)],
            r#"{"commit":"c0ffee","sentence":"1 of 2 plants at commit c0ffee","results":{"missed":1,"caught":1},"not_live":[],"settings":{"workers":28,"runs":300,"seconds":60,"rounds":10,"base_archive":null,"campaign_sha256":"0000000000000000000000000000000000000000000000000000000000000000","plants":["b","a"]},"plants":["alpha","beta"]}"#,
            &[
                r#"1 of 2 plants at commit c0ffee"#,
                r#"alpha: missed (no expected profile; no sweep ran)"#,
                r#"beta: caught (violation: a in run 1 of smoke)"#,
            ],
            0,
            None,
        ),
        (
            &[(r#"not live"#, false)],
            r#"{"commit":"c0ffee","sentence":"0 of 0 plants at commit c0ffee","results":{"not live":1},"not_live":["alpha"],"settings":{"workers":28,"runs":300,"seconds":60,"rounds":10,"base_archive":null,"campaign_sha256":"0000000000000000000000000000000000000000000000000000000000000000","plants":["b","a"]},"plants":["alpha"]}"#,
            &[
                r#"0 of 0 plants at commit c0ffee"#,
                r#"alpha: not live (its proof exits 1 on the head and 1 on the plant, where a live plant's proof exits 0 and 1)"#,
            ],
            3,
            Some(
                "{\n  \"commit\": \"c0ffee\",\n  \"sentence\": \"0 of 0 plants at commit c0ffee\",\n  \"results\": {\n    \"not live\": 1\n  },\n  \"not_live\": [\n    \"alpha\"\n  ],\n  \"settings\": {\n    \"workers\": 28,\n    \"runs\": 300,\n    \"seconds\": 60,\n    \"rounds\": 10,\n    \"base_archive\": null,\n    \"campaign_sha256\": \"0000000000000000000000000000000000000000000000000000000000000000\",\n    \"plants\": [\n      \"b\",\n      \"a\"\n    ]\n  },\n  \"plants\": [\n    {\n      \"id\": \"alpha\",\n      \"row\": 7,\n      \"fix\": {\n        \"pull_request\": 12,\n        \"commit\": \"0123abc\"\n      },\n      \"files\": [\n        \"src/lib.rs\"\n      ],\n      \"proof\": \"tests::the_proof\",\n      \"campaign\": \"plant-alpha\",\n      \"profiles\": [\n        \"smoke\",\n        \"crash-loop\"\n      ],\n      \"proof_exits\": {\n        \"head\": 1,\n        \"plant\": 1\n      },\n      \"commit\": null,\n      \"tree\": null,\n      \"archive\": null,\n      \"counts\": null,\n      \"runs\": {},\n      \"controls\": null,\n      \"histories\": null,\n      \"keys\": {},\n      \"head_failures\": [],\n      \"result\": \"not live\",\n      \"reason\": \"its proof exits 1 on the head and 1 on the plant, where a live plant's proof exits 0 and 1\"\n    }\n  ]\n}\n",
            ),
        ),
        (
            &[(r#"does not apply"#, false), (r#"missed"#, false)],
            r#"{"commit":"c0ffee","sentence":"0 of 1 plants at commit c0ffee","results":{"does not apply":1,"missed":1},"not_live":[],"settings":{"workers":28,"runs":300,"seconds":60,"rounds":10,"base_archive":null,"campaign_sha256":"0000000000000000000000000000000000000000000000000000000000000000","plants":["b","a"]},"plants":["alpha","beta"]}"#,
            &[
                r#"0 of 1 plants at commit c0ffee"#,
                r#"alpha: does not apply (the reason of 0)"#,
                r#"beta: missed (no expected profile; no sweep ran)"#,
            ],
            1,
            None,
        ),
        (
            &[(r#"does not apply"#, false)],
            r#"{"commit":"c0ffee","sentence":"0 of 0 plants at commit c0ffee","results":{"does not apply":1},"not_live":[],"settings":{"workers":28,"runs":300,"seconds":60,"rounds":10,"base_archive":null,"campaign_sha256":"0000000000000000000000000000000000000000000000000000000000000000","plants":["b","a"]},"plants":["alpha"]}"#,
            &[
                r#"0 of 0 plants at commit c0ffee"#,
                r#"alpha: does not apply (the reason of 0)"#,
            ],
            3,
            None,
        ),
    ];
    let repository = Repository::new();
    let (with_causes, without_causes) = (unprofiled(CAUSE), unprofiled("null"));
    let options = alpha(&repository).1;
    let plain = plants(&repository);
    let (caused, uncaused) = (plants(&with_causes), plants(&without_causes));
    let json::Value::Object(settings) = json::parse(
        r#"{"workers": 28, "runs": 300, "seconds": 60, "rounds": 10, "base_archive": null,
            "campaign_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
            "plants": ["b", "a"]}"#,
    )
    .expect("JSON") else {
        panic!("an object");
    };
    let scratch = &repository.scratch;
    for &(results, expected, printed, code, written) in rows {
        let entries: Vec<Finished> = results
            .iter()
            .enumerate()
            .map(|(number, &(result, with_cause))| {
                let plant = match (result, with_cause) {
                    ("missed", true) => &caused[number % 2],
                    ("missed", false) => &uncaused[number % 2],
                    _ => &plain[number % 2],
                };
                let work = scratch.join(format!("work-{number}"));
                settled(result, number, &(plant.clone(), options.clone()), &work)
            })
            .collect();
        let scored = score("c0ffee", &entries, settings.clone());
        let members: Vec<Value> = entries
            .iter()
            .map(|entry| Value::Object(entry.members().clone()))
            .collect();
        assert_eq!(
            scored.get("plants"),
            Some(&Value::Array(members)),
            "{results:?}"
        );
        let mut ids = scored.clone();
        let listed: Vec<Value> = entries
            .iter()
            .map(|entry| Value::String(entry.id().clone()))
            .collect();
        ids.insert("plants", Value::Array(listed));
        assert_eq!(json::text(&Value::Object(ids)), expected, "{results:?}");
        let said: Vec<String> = lines("c0ffee", &entries)
            .iter()
            .map(Text::to_string)
            .collect();
        assert_eq!(said, printed, "{results:?}");
        assert_eq!(exit_code(&entries), code, "{results:?}");
        if let Some(written) = written {
            assert_eq!(bytes(&scored), written, "{results:?}");
        }
    }
}

/// The stored score reads back and writes the same bytes: two spaces of indent, members in document
/// order, ASCII escapes and one final newline.
#[test]
fn the_stored_score_is_written_back_byte_for_byte() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../verification/plants/score.json");
    let stored = fs::read_to_string(&path).expect("the stored score reads");
    let json::Value::Object(read) = json::parse_unique(&stored).expect("the stored score is JSON")
    else {
        panic!("the stored score is an object");
    };
    assert_eq!(bytes(&read), stored);
}

/// A non-finite float, a non-ASCII code point and a lone surrogate take the forms Python's
/// `json.dumps(value, indent=2)` gives them.
#[test]
fn a_score_writes_every_value_python_writes() {
    let json::Value::Object(read) =
        json::parse(r#"{"a": [NaN, -Infinity, 1e16, 0.1], "é": "\ud800\u2028", "b": {}}"#)
            .expect("JSON")
    else {
        panic!("an object");
    };
    let expected = "{\n  \"a\": [\n    NaN,\n    -Infinity,\n    1e+16,\n    0.1\n  ],\n  \"\\u00e9\": \
                    \"\\ud800\\u2028\",\n  \"b\": {}\n}\n";
    assert_eq!(bytes(&read), expected);
}

/// A reason with a line break stays one value in the score and spans two lines of the result line.
#[test]
fn a_reason_with_a_line_break_spans_its_result_line() {
    let repository = Repository::new();
    let alpha = plants(&repository).remove(0);
    let work = Path::new("/work/of/the/run");
    let mut entry = Entry::new(&alpha);
    entry.no_verdict(&NoVerdict::plain(
        "`campaign confirm` exited 2: one\ntwo in /work/of/the/run",
    ));
    let entry = entry.finish(work).expect("a result");
    assert_eq!(
        entry.reason().to_string(),
        "`campaign confirm` exited 2: one\ntwo in <work>"
    );
    assert_eq!(
        result_line(&entry).to_string(),
        "alpha: no verdict (`campaign confirm` exited 2: one\ntwo in <work>)"
    );
}
