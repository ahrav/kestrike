//! Tests of the sweeps, the status and suspect list they leave, and the verdict keys at the root.

use kestrike_tools::json::{self, Value};
use kestrike_tools::python::hexdigest;

use super::fixture::{CAUSE, Done, Fixture, PLANTS, shown, text_of};

/// `same` asserts that `value` is the JSON document `expected`, members in any order.
pub fn same(value: Option<&Value>, expected: &str, what: &str) {
    let want = json::parse(expected).unwrap_or_else(|error| panic!("{expected}: {error:?}"));
    let found = value.unwrap_or_else(|| panic!("{what}: no value"));
    assert_eq!(
        json::indented(found).expect("a finite value"),
        json::indented(&want).expect("a finite value"),
        "{what}"
    );
}

/// `digest` is the stand-in's build digest of `mode`.
pub fn digest(mode: &str) -> String {
    hexdigest(mode.as_bytes())
}

pub fn exited(done: &Done, code: i32) {
    assert_eq!(done.code, code, "{}", done.stderr);
}

#[test]
fn each_result_stands_in_the_score_with_its_reason() {
    let mut fx = Fixture::new();
    let names: Vec<&str> = PLANTS
        .iter()
        .map(|(name, _)| *name)
        .filter(|name| *name != "p-nocause")
        .collect();
    let done = fx.run(&names, &[]);
    exited(&done, 3);
    let (written, plants) = fx.results();
    assert_eq!(text_of(written.get("commit").expect("a commit")), fx.head);
    let sentence = format!("1 of 3 plants at commit {}", fx.head);
    assert_eq!(
        text_of(written.get("sentence").expect("a sentence")),
        sentence
    );
    same(
        written.get("results"),
        r#"{"caught": 1, "missed": 2, "no verdict": 6, "does not apply": 1}"#,
        "results",
    );
    assert!(done.stdout.contains(&sentence), "{}", done.stdout);
    let lines: Vec<&str> = done.stdout.lines().collect();
    for line in [
        "p-catch: caught (violation: a rule in run 7 of b)",
        "p-alarm: no verdict (the root holds alarm)",
        "p-miss: missed (each expected profile reached 300 runs and the root holds no suspect)",
    ] {
        assert!(lines.contains(&line), "{line:?} in {}", done.stdout);
    }
    assert_eq!(
        text_of(plants["p-stale"].get("result").expect("a result")),
        "does not apply"
    );
    for (name, reason) in [
        ("p-nobuild", "the planted tree does not build"),
        ("p-alarm", "the root holds alarm"),
        (
            "p-headfail",
            "does not pass on the unpatched head: incomplete",
        ),
        (
            "p-refuse",
            "made no finding of violation: a rule in run 7 of a",
        ),
        ("p-other", "the root holds suspects in a (1)"),
        ("p-short", "a stayed below 300 runs after 3 sweeps"),
    ] {
        fx.verdict(name, "no verdict", reason);
    }
    same(plants["p-alarm"].get("keys"), r#"{"alarm": 1}"#, "keys");
    let Some(Value::Object(settings)) = written.get("settings") else {
        panic!("the score holds its settings");
    };
    assert_eq!(
        text_of(settings.get("base_archive").expect("a base archive")),
        digest("base")
    );
    let listed: Vec<String> = names.iter().map(|name| format!("\"{name}\"")).collect();
    same(
        settings.get("plants"),
        &format!("[{}]", listed.join(", ")),
        "plants",
    );
    let campaign = std::fs::read(&fx.stand_in).expect("the stand-in reads");
    assert_eq!(
        text_of(settings.get("campaign_sha256").expect("a digest")),
        hexdigest(&campaign)
    );
}

#[test]
fn the_sweep_repeats_until_every_profile_reaches_the_floor() {
    let mut fx = Fixture::new();
    fx.run(&["p-miss", "p-slow"], &[]);
    let sweeps = fx.calls(&["sweep"]);
    let option = |call: &Vec<String>, name: &str| {
        let at = call
            .iter()
            .position(|arg| arg == name)
            .expect("the option stands");
        call[at + 1].clone()
    };
    let names: Vec<String> = sweeps
        .iter()
        .map(|call| option(call, "--campaign"))
        .collect();
    assert_eq!(
        names,
        [
            "plant-p-miss",
            "plant-p-miss",
            "plant-p-slow",
            "plant-p-slow",
            "plant-p-slow"
        ]
    );
    for call in &sweeps {
        assert_eq!(option(call, "--workers"), "2");
    }
    let place = fx.work.join("plants").join("p-miss");
    let shown_path = |name: &str| place.join(name).display().to_string();
    assert_eq!(
        sweeps[0],
        [
            "sweep".to_owned(),
            "--root".to_owned(),
            shown_path("root"),
            "--archive".to_owned(),
            shown_path("archive"),
            "--campaign".to_owned(),
            "plant-p-miss".to_owned(),
            "--profiles".to_owned(),
            "a".to_owned(),
            "--workers".to_owned(),
            "2".to_owned(),
            "--for".to_owned(),
            "1".to_owned(),
        ]
    );
    let (_, plants) = fx.results();
    same(plants["p-miss"].get("miss_cause"), CAUSE, "miss_cause");
    let Some(Value::Object(runs)) = plants["p-slow"].get("runs") else {
        panic!("p-slow holds its runs");
    };
    let Some(Value::Object(slow)) = runs.get("slow") else {
        panic!("p-slow holds the runs of slow");
    };
    assert_eq!(shown(slow.get("next")), "300");
    fx.verdict(
        "p-slow",
        "missed",
        "each expected profile reached 300 runs and the root holds no suspect",
    );
    assert!(fx.calls(&["confirm"]).is_empty());
    for name in ["p-miss", "p-slow"] {
        let env = fx
            .work
            .join("plants")
            .join(name)
            .join("archive")
            .join("env");
        let text = std::fs::read_to_string(&env).expect("the archive's environment reads");
        let Ok(Value::Object(seen)) = json::parse(&text) else {
            panic!("{text}");
        };
        same(
            seen.get("proof"),
            r#"{"target": false, "tree": false}"#,
            name,
        );
    }
    assert_eq!(fx.proof_modes(), ["base", "pass", "pass"]);
}

#[test]
fn a_floor_reached_exactly_ends_the_sweeps() {
    let mut fx = Fixture::new();
    fx.run_in(&["p-miss"], &["--runs", "400"], &[], None);
    fx.verdict("p-miss", "missed", "each expected profile reached 400 runs");
    assert_eq!(fx.calls(&["sweep"]).len(), 2);
    let (written, _) = fx.results();
    let Some(Value::Object(settings)) = written.get("settings") else {
        panic!("the score holds its settings");
    };
    for (name, value) in [
        ("workers", "2"),
        ("runs", "400"),
        ("seconds", "1"),
        ("rounds", "3"),
    ] {
        assert_eq!(shown(settings.get(name)), value, "{name}");
    }
}

#[test]
fn a_profile_one_run_below_the_floor_is_swept_again() {
    let mut fx = Fixture::new();
    fx.run_in(&["p-miss"], &["--runs", "401"], &[], None);
    fx.verdict("p-miss", "missed", "each expected profile reached 401 runs");
    assert_eq!(fx.calls(&["sweep"]).len(), 3);
}

#[test]
fn a_floor_out_of_reach_in_the_rounds_leaves_no_verdict() {
    let mut fx = Fixture::new();
    fx.run_in(&["p-miss"], &["--runs", "601"], &[], None);
    fx.verdict(
        "p-miss",
        "no verdict",
        "a stayed below 601 runs after 3 sweeps",
    );
    assert_eq!(fx.calls(&["sweep"]).len(), 3);
}

#[test]
fn a_plant_with_no_expected_profile_is_missed_without_a_sweep() {
    let mut fx = Fixture::new();
    let done = fx.run(&["p-noprofile"], &[]);
    exited(&done, 0);
    let heads: Vec<Vec<String>> = fx
        .calls(&[])
        .into_iter()
        .map(|call| call[..2].to_vec())
        .collect();
    assert_eq!(heads, [["sim", "archive"]]);
    let (written, plants) = fx.results();
    let plant = &plants["p-noprofile"];
    assert_eq!(text_of(plant.get("result").expect("a result")), "missed");
    assert_eq!(
        text_of(plant.get("archive").expect("an archive")),
        digest("pass")
    );
    assert_eq!(
        text_of(written.get("sentence").expect("a sentence")),
        format!("0 of 1 plants at commit {}", fx.head)
    );
}

#[test]
fn each_malformed_or_contradictory_record_leaves_no_verdict() {
    let cases = [
        (
            "p-otherlock",
            "keeps no regular Cargo.lock equal to the run's",
        ),
        ("p-nolock", "keeps no regular Cargo.lock equal to the run's"),
        ("p-loneline", "`suspects.jsonl` lists 1 suspects"),
        ("p-disorder", "gives a counts out of order"),
        ("p-othercampaign", "names campaign 'another' and counts {}"),
        (
            "p-exitone",
            "the last sweep exited 1 and the root holds no verdict key",
        ),
        ("p-rootsuspect", "counts 1 suspects at the root"),
        ("p-statusfail", "`campaign sweep-status` exited 2"),
        ("p-booltotal", "counts False suspects at the root"),
        ("p-floattotal", "counts 0.0 suspects at the root"),
        ("p-confirmfail", "`campaign confirm` exited 2"),
        ("p-norun", "a has no run counted"),
        (
            "p-overrun",
            "gives a counts out of order: pass 150, runs 201, next 200",
        ),
        (
            "p-othercounts",
            "names campaign 'plant-p-othercounts' and counts {'nodes': 5}",
        ),
        (
            "p-badbytes",
            "`campaign sweep-status` exited 0 and printed no UTF-8 text",
        ),
        ("p-historynocount", "gives h-history no suspect count"),
    ];
    let mut fx = Fixture::new();
    let names: Vec<&str> = cases.iter().map(|(name, _)| *name).collect();
    let done = fx.run(&names, &[]);
    exited(&done, 3);
    for (name, reason) in cases {
        fx.verdict(name, "no verdict", reason);
    }
    let exitone = fx
        .calls(&["sweep"])
        .into_iter()
        .filter(|call| call.iter().any(|arg| arg == "plant-p-exitone"))
        .count();
    assert_eq!(exitone, 1);
}

#[test]
fn a_status_without_a_profile_s_suspect_count_leaves_no_verdict() {
    let mut fx = Fixture::new();
    fx.run(&["p-nocount"], &[]);
    fx.verdict(
        "p-nocount",
        "no verdict",
        "gives a no count of next, runs, pass, suspects",
    );
}

#[test]
fn a_status_without_a_profile_s_suspect_keys_gives_no_catch() {
    let mut fx = Fixture::new();
    let done = fx.run(&["p-nokeys", "p-oddkeys"], &[]);
    exited(&done, 3);
    for name in ["p-nokeys", "p-oddkeys"] {
        fx.verdict(
            name,
            "no verdict",
            "`campaign sweep-status` gives a no count of its suspects by key",
        );
    }
    assert!(fx.calls(&["sim", "run"]).is_empty());
}

#[test]
fn a_count_by_key_that_does_not_account_for_a_profile_s_suspects_gives_no_catch() {
    let mut fx = Fixture::new();
    let done = fx.run(&["p-emptykeys", "p-shortkeys", "p-lowkey"], &[]);
    exited(&done, 3);
    fx.verdict(
        "p-emptykeys",
        "no verdict",
        "`campaign sweep-status` counts 1 suspects of a and 0 by key",
    );
    fx.verdict(
        "p-shortkeys",
        "no verdict",
        "`campaign sweep-status` counts 2 suspects of a and 1 by key",
    );
    fx.verdict(
        "p-lowkey",
        "no verdict",
        "`suspects.jsonl` lists 2 suspects of a under `violation: a rule` and `campaign sweep-status` \
         counts 1",
    );
    assert!(fx.calls(&["sim", "run"]).is_empty());
}

#[test]
fn a_differing_replay_the_sweep_counted_and_did_not_list_gives_no_catch() {
    let mut fx = Fixture::new();
    let done = fx.run(
        &[
            "p-replayunlisted",
            "p-otherunlisted",
            "p-replaylisted",
            "p-manyviolations",
        ],
        &[],
    );
    exited(&done, 3);
    fx.verdict(
        "p-replayunlisted",
        "no verdict",
        "`campaign sweep-status` counts 9 suspects of a under `replay differs: a rule` and \
         `suspects.jsonl` lists 8",
    );
    fx.verdict(
        "p-otherunlisted",
        "no verdict",
        "`campaign sweep-status` counts 1 suspects of a under `other` and `suspects.jsonl` lists 0",
    );
    for name in ["p-replaylisted", "p-manyviolations"] {
        let caught = fx.verdict(name, "caught", "violation: a rule in run 7 of a");
        assert_eq!(suspect(&caught, "run"), "7", "{name}");
    }
    assert_eq!(fx.calls(&["sim", "run"]).len(), 2);
}

/// `suspect` is the JSON text of the member `name` of the entry's suspect.
pub fn suspect(entry: &json::Object, name: &str) -> String {
    let Some(Value::Object(suspect)) = entry.get("suspect") else {
        panic!("the entry names its suspect");
    };
    shown(suspect.get(name))
}

#[test]
fn a_profile_that_may_hide_a_differing_replay_leaves_another_profile_s_suspect_to_catch() {
    let mut fx = Fixture::new();
    let done = fx.run(&["p-replayelsewhere"], &[]);
    exited(&done, 0);
    let caught = fx.verdict(
        "p-replayelsewhere",
        "caught",
        "violation: a rule in run 8 of b",
    );
    assert_eq!(
        (suspect(&caught, "profile"), suspect(&caught, "run")),
        ("\"b\"".to_owned(), "8".to_owned())
    );
    assert_eq!(fx.calls(&["sim", "run"]).len(), 1);
}

#[test]
fn a_suspect_whose_replay_differs_gives_no_catch_and_leaves_another_seed_to_catch() {
    let mut fx = Fixture::new();
    let done = fx.run(&["p-replaydiffers", "p-replayonly"], &[]);
    exited(&done, 3);
    let caught = fx.verdict(
        "p-replaydiffers",
        "caught",
        "violation: a rule in run 8 of a",
    );
    assert_eq!(suspect(&caught, "run"), "8");
    fx.verdict(
        "p-replayonly",
        "no verdict",
        "the sweep's replay of violation: a rule in run 7 of a differs",
    );
    assert_eq!(fx.calls(&["sim", "run"]).len(), 1);
}

#[test]
fn each_verdict_key_leaves_no_verdict_and_names_itself() {
    let mut fx = Fixture::new();
    let done = fx.run(&["p-nopass", "p-unreached", "p-nowindow"], &[]);
    exited(&done, 3);
    let nopass = fx.verdict("p-nopass", "no verdict", "the root holds no_pass");
    same(nopass.get("keys"), r#"{"no_pass": ["a"]}"#, "no_pass");
    let unreached = fx.verdict("p-unreached", "no verdict", "the root holds unreached");
    same(
        unreached.get("keys"),
        r#"{"unreached": {"a": ["a required event"]}}"#,
        "unreached",
    );
    let window = fx.verdict("p-nowindow", "no verdict", "the root holds no_window");
    same(
        window.get("keys"),
        r#"{"no_window": {"a": ["a planned window"]}}"#,
        "no_window",
    );
}

#[test]
fn a_confirmed_catch_outranks_a_verdict_key() {
    let mut fx = Fixture::new();
    fx.run(&["p-catchalarm"], &[]);
    fx.verdict("p-catchalarm", "caught", "violation: a rule in run 7 of a");
    assert_eq!(fx.calls(&["sweep"]).len(), 1);
}

#[test]
fn a_malformed_suspect_list_leaves_no_verdict() {
    let mut fx = Fixture::new();
    fx.run(&["p-badline", "p-dirlog"], &[]);
    fx.verdict(
        "p-badline",
        "no verdict",
        "suspects.jsonl line 1 is no suspect",
    );
    fx.verdict(
        "p-dirlog",
        "no verdict",
        "suspects.jsonl is no regular file",
    );
    assert!(fx.calls(&["confirm"]).is_empty());
}

#[test]
fn a_suspect_record_a_kill_cut_short_is_not_read() {
    let mut fx = Fixture::new();
    fx.run(&["p-cutline"], &[]);
    fx.verdict(
        "p-cutline",
        "missed",
        "each expected profile reached 300 runs",
    );
}

#[test]
fn a_suspect_line_with_a_line_separator_is_one_record() {
    let mut fx = Fixture::new();
    fx.run(&["p-wide"], &[]);
    fx.verdict("p-wide", "caught", "violation: a rule in run 7 of a");
}

#[test]
fn a_suspect_outside_the_expected_profiles_leaves_no_verdict() {
    let mut fx = Fixture::new();
    fx.run(&["p-history"], &[]);
    fx.verdict(
        "p-history",
        "no verdict",
        "the root holds suspects in h-history (1)",
    );
    assert!(fx.calls(&["confirm"]).is_empty());
}

#[test]
fn a_failed_step_leaves_no_verdict_with_its_cause() {
    let mut fx = Fixture::new();
    let done = fx.run(&["p-nomanifest", "p-damaged"], &[]);
    exited(&done, 3);
    let failed = fx.verdict(
        "p-nomanifest",
        "no verdict",
        "the seed check of violation: a rule in run 7 of a did not run: \
         <work>/plants/p-nomanifest/root/manifests/a.manifest: No such file or directory (os error 2)",
    );
    let reason = text_of(failed.get("reason").expect("a reason"));
    assert!(
        !reason.contains(&fx.scratch.display().to_string()),
        "{reason}"
    );
    fx.verdict("p-damaged", "no verdict", "`campaign sweep` exited 4");
}

#[test]
fn an_archive_refused_for_another_cause_than_its_build_names_the_exit() {
    let mut fx = Fixture::new();
    fx.run(&["p-refusedarchive"], &[]);
    let plant = fx.verdict(
        "p-refusedarchive",
        "no verdict",
        "`campaign sim archive` of the planted tree exited 2",
    );
    let reason = text_of(plant.get("reason").expect("a reason"));
    assert!(!reason.contains("does not build"), "{reason}");
}

#[test]
fn an_unpatched_head_that_does_not_build_leaves_no_verdict() {
    let mut fx = Fixture::new();
    let done = fx.run(&["p-catch", "p-headfail"], &[("STANDIN_BASE_FAIL", "1")]);
    exited(&done, 3);
    fx.verdict("p-catch", "no verdict", "the unpatched head does not build");
    fx.verdict(
        "p-headfail",
        "no verdict",
        "the unpatched head does not build",
    );
    assert_eq!(fx.calls(&["sim", "archive"]).len(), 3);
}
