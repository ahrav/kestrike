//! The run's refusals before any test: the work directory, the checkout's changes against `HEAD`, the
//! copy's catalog, GenMC declaration and Cargo configuration, and a planted file with line endings a text
//! restore changes.

use std::fs;
use std::os::unix::fs::symlink;

use kestrike_tools::genmc::package_sources;
use kestrike_tools::genmc::read_source;
use kestrike_tools::json::{self, Value};
use kestrike_tools::orderings::check::{GENMC, check};
use kestrike_tools::orderings::sites::EXTERNAL;

use super::fixture::*;

#[test]
fn a_work_directory_inside_the_checkout_or_unusable_is_refused() {
    let fixture = Fixture::new("refused-work");
    fixture.commit();
    let before = status(&fixture.repo);
    symlink(&fixture.repo, fixture.base.join("link")).expect("linked");
    let inside = [
        fixture.repo.join("work"),
        format!("{}/elsewhere/../repo/work", fixture.base.display()).into(),
        fixture.base.join("link/work"),
    ];
    for work in inside {
        let ran = fixture.run_with(
            &[RUN_FENCE],
            Opts {
                work: Some(work.clone()),
                ..Opts::default()
            },
        );
        assert_eq!(ran.code(), Some(2), "{}: {}", work.display(), ran.stderr);
        assert!(
            ran.stderr.contains("lies inside the checkout"),
            "{}",
            ran.stderr
        );
    }
    assert_eq!(status(&fixture.repo), before);
    let full = fixture.base.join("full");
    fs::create_dir(&full).expect("made");
    fs::write(full.join("x"), "x").expect("written");
    let plain = fixture.base.join("plain");
    fs::write(&plain, "x").expect("written");
    let refused = [
        (full.clone(), "is not empty".to_owned()),
        (
            plain.clone(),
            format!("the work directory {} cannot be listed", plain.display()),
        ),
        (
            plain.join("sub"),
            format!(
                "the work directory {} cannot hold the copy",
                plain.join("sub").display()
            ),
        ),
    ];
    for (work, wanted) in refused {
        let ran = fixture.run_with(
            &[RUN_FENCE],
            Opts {
                work: Some(work.clone()),
                ..Opts::default()
            },
        );
        assert_eq!(ran.code(), Some(2), "{}: {}", work.display(), ran.stderr);
        assert!(ran.stderr.contains(&wanted), "{}", ran.stderr);
        assert_eq!(ran.stderr.lines().count(), 1, "{}", ran.stderr);
        assert!(ran.report.is_none());
        assert_eq!(fixture.stub_calls(), Vec::<Value>::new());
    }
    assert!(!fixture.repo.join("work").exists());
}

#[test]
fn a_run_whose_judging_scripts_differ_from_head_is_refused() {
    let fixture = Fixture::new("differ");
    fixture.commit();
    let tracked = [
        "scripts/judge-genmc.py",
        "scripts/judge-rc11.py",
        "crates/kestrike-tools/src/lib.rs",
        "Cargo.toml",
        ".cargo/config.toml",
        "scripts/tool.sh",
        ".github/workflows/agent-checks.yml",
    ];
    for (index, name) in tracked.iter().enumerate() {
        let path = fixture.repo.join(name);
        let original = fs::read(&path).expect("reads");
        let mut changed = original.clone();
        changed.push(b'\n');
        fs::write(&path, changed).expect("written");
        let ran = fixture.run_with(
            &[RUN_FENCE],
            Opts {
                work: Some(fixture.work(&format!("dirty-{index}"))),
                ..Opts::default()
            },
        );
        fs::write(&path, original).expect("written");
        assert_eq!(ran.code(), Some(2), "{name}: {}", ran.stderr);
        assert!(
            ran.stderr.contains("differ from HEAD"),
            "{name}: {}",
            ran.stderr
        );
        assert!(ran.report.is_none());
        assert_eq!(fixture.lines(".log"), Vec::<String>::new());
    }
    let stray = fixture.repo.join("crates/kestrike-tools/src/stray.rs");
    fs::write(&stray, "").expect("written");
    let ran = fixture.run_with(
        &[RUN_FENCE],
        Opts {
            work: Some(fixture.work("untracked")),
            ..Opts::default()
        },
    );
    fs::remove_file(&stray).expect("removed");
    assert_eq!(ran.code(), Some(2), "{}", ran.stderr);
    assert!(ran.stderr.contains("differ from HEAD"), "{}", ran.stderr);
    assert!(ran.report.is_none());
    let classifier = fixture.repo.join("scripts/classify-atomics.py");
    let original = fs::read(&classifier).expect("reads");
    let mut changed = original.clone();
    changed.push(b'\n');
    fs::write(&classifier, changed).expect("written");
    let ran = fixture.run_with(
        &[RUN_FENCE],
        Opts {
            work: Some(fixture.work("classifier")),
            ..Opts::default()
        },
    );
    fs::write(&classifier, original).expect("written");
    assert_eq!(ran.code(), Some(0), "{}", ran.stderr);
}

#[test]
fn a_refused_catalog_or_declaration_stops_the_run() {
    let fixture = Fixture::new("refused-catalog");
    fixture.commit_with(|catalog| {
        row(catalog, "grace-visit").insert(
            "replace",
            text("const VISIT: Ordering = Ordering::Relaxed;"),
        );
    });
    let ran = fixture.run_rows(&["grace-visit"]);
    assert_eq!(ran.code(), Some(2), "{}", ran.stderr);
    assert!(
        ran.stderr.contains("check refuses the copy's catalog"),
        "{}",
        ran.stderr
    );
    let declaration = fixture.repo.join(GENMC);
    let mut declared = read_json(&declaration);
    let Value::Object(object) = &mut declared else {
        panic!("the declaration is an object");
    };
    object.insert("package", Value::Null);
    fs::write(&declaration, json::line(&declared)).expect("written");
    fixture.commit();
    let ran = fixture.run_with(
        &[RUN_FENCE],
        Opts {
            work: Some(fixture.work("package")),
            ..Opts::default()
        },
    );
    assert_eq!(ran.code(), Some(2), "{}", ran.stderr);
    assert!(
        ran.stderr.contains("check refuses the copy's catalog"),
        "{}",
        ran.stderr
    );
    assert_eq!(ran.stderr.lines().count(), 2, "{}", ran.stderr);
}

#[test]
fn a_stray_source_in_the_invoking_checkout_leaves_the_copy_s_check_alone() {
    let fixture = Fixture::new("stray");
    fixture.commit();
    fs::write(
        fixture.repo.join("crates/kestrike/src/stray.rs"),
        "#[path = concat!(\"storage/\", \"fill.rs\")] mod fill;\n",
    )
    .expect("written");
    let read = |path: &str| read_source(&fixture.repo, path);
    let (report, code) = check(
        &read,
        &fixture.repo,
        &fixture.repo,
        EXTERNAL,
        &package_sources,
    );
    assert_eq!(code, 1, "{report:?}");
    let messages: Vec<String> = items(get(&report, "refusals"))
        .iter()
        .map(|entry| string(get(entry, "message")))
        .collect();
    assert!(
        messages.contains(
            &"crates/kestrike/src/stray.rs holds a path attribute the scope rule cannot read"
                .to_owned()
        ),
        "{messages:?}"
    );
    let ran = fixture.run_rows(&[RUN_FENCE]);
    assert_eq!(ran.code(), Some(0), "{}", ran.stderr);
}

#[test]
fn a_shaping_cargo_configuration_or_another_loom_stops_the_run() {
    let fixture = Fixture::new("shaping");
    fixture.commit();
    let elsewhere = fixture.base.join("elsewhere").display().to_string();
    let target = format!("{{\"build\": {{\"target-dir\": \"{elsewhere}\"}}}}");
    let build = format!("{{\"build\": {{\"build-dir\": \"{elsewhere}\"}}}}");
    let refusals: [(&str, Vec<Setting>, &str); 7] = [
        (
            RUN_FENCE,
            env(&[(
                "STUB_CONFIG",
                "{\"env\": {\"LOOM_MAX_PREEMPTIONS\": \"1\"}}",
            )]),
            "env.LOOM_MAX_PREEMPTIONS",
        ),
        (
            RUN_FENCE,
            env(&[("STUB_CONFIG", &target)]),
            "build.target-dir",
        ),
        (
            RUN_FENCE,
            env(&[("STUB_CONFIG", &build)]),
            "build.build-dir",
        ),
        (
            JOIN_ROW,
            env(&[("STUB_CONFIG_KERNELS", &target)]),
            "build.target-dir",
        ),
        (
            RUN_FENCE,
            env(&[
                ("STUB_CONFIG_EXIT", "101"),
                ("STUB_CONFIG_ERR", "error: unknown -Z flag"),
            ]),
            "exited 101: error: unknown -Z flag",
        ),
        (
            RUN_FENCE,
            env(&[("STUB_LOOM", "loom v0.7.3")]),
            "the copy resolves loom v0.7.3",
        ),
        (
            RUN_FENCE,
            env(&[("STUB_TREE_EXIT", "101")]),
            "the copy resolves loom unresolved",
        ),
    ];
    for (index, (id, ambient, wanted)) in refusals.into_iter().enumerate() {
        let ran = fixture.run_with(
            &[id],
            Opts {
                work: Some(fixture.work(&format!("config-{index}"))),
                env: ambient,
                ..Opts::default()
            },
        );
        assert_eq!(ran.code(), Some(2), "{wanted}: {}", ran.stderr);
        assert!(ran.stderr.contains(wanted), "{wanted}: {}", ran.stderr);
        assert!(ran.report.is_none());
        assert_eq!(fixture.lines(".log"), Vec::<String>::new());
        assert_eq!(fixture.lines(".lane"), Vec::<String>::new());
    }
    let ran = fixture.run_with(
        &[JOIN_ROW],
        Opts {
            work: Some(fixture.work("genmc-only")),
            env: env(&[
                ("STUB_LOOM", "loom v0.7.3"),
                ("STUB_CONFIG", "{\"env\": {\"LOOM_X\": \"1\"}}"),
            ]),
            ..Opts::default()
        },
    );
    assert_eq!(ran.code(), Some(0), "{}", ran.stderr);
    assert_eq!(
        string(get(get(ran.report(), "pins"), "loom resolved")),
        "v0.7.3"
    );
    let ran = fixture.run_with(
        &[RUN_FENCE],
        Opts {
            work: Some(fixture.work("loom-only")),
            env: env(&[(
                "STUB_CONFIG_KERNELS",
                "{\"build\": {\"target-dir\": \"/x\"}}",
            )]),
            ..Opts::default()
        },
    );
    assert_eq!(ran.code(), Some(0), "{}", ran.stderr);
    for call in fixture.stub_calls() {
        assert!(!string(get(&call, "cwd")).ends_with("kernels"), "{call:?}");
    }
}

fn binding<'d>(declared: &'d mut Value, id: &str) -> &'d mut kestrike_tools::json::Object {
    let Value::Object(declared) = declared else {
        panic!("the declaration is an object");
    };
    let Some(Value::Array(bindings)) = declared.get_mut("bindings") else {
        panic!("the declaration lists bindings");
    };
    bindings
        .iter_mut()
        .find_map(|entry| match entry {
            Value::Object(entry) if entry.get("id") == Some(&text(id)) => Some(entry),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no binding {id}"))
}

fn case<'d>(declared: &'d mut Value, name: &str) -> &'d mut kestrike_tools::json::Object {
    let Value::Object(declared) = declared else {
        panic!("the declaration is an object");
    };
    let Some(Value::Object(cases)) = declared.get_mut("cases") else {
        panic!("the declaration holds cases");
    };
    match cases.get_mut(name) {
        Some(Value::Object(case)) => case,
        _ => panic!("no case {name}"),
    }
}

#[test]
fn a_genmc_declaration_the_copys_judge_refuses_stops_a_run_that_selects_a_case() {
    let fixture = Fixture::new("declaration");
    let declaration = fixture.repo.join(GENMC);
    let committed = read_json(&declaration);
    type Change = fn(&mut Value);
    let changes: [(&str, Change, &str); 2] = [
        (
            "drifted",
            |declared| {
                binding(declared, "claim-load").insert("orderings", texts(&["Acquire"]));
            },
            "correspondence drift: claim-load",
        ),
        (
            "disagreeing",
            |declared| {
                case(declared, "credit-seq-empty").insert("litmus", texts(&["L0-no-fences"]));
            },
            "credit-seq-empty is declared positive",
        ),
    ];
    for (name, change, wanted) in changes {
        let mut planted = committed.clone();
        change(&mut planted);
        fs::write(&declaration, json::line(&planted)).expect("written");
        fixture.commit();
        let ran = fixture.run_with(
            &[CREDIT_ROW],
            Opts {
                work: Some(fixture.work(name)),
                ..Opts::default()
            },
        );
        assert_eq!(ran.code(), Some(2), "{name}: {}", ran.stderr);
        assert!(ran.stderr.contains(wanted), "{name}: {}", ran.stderr);
        assert_eq!(ran.stderr.lines().count(), 2, "{}", ran.stderr);
        assert!(ran.report.is_none());
        assert_eq!(fixture.lines(".lane"), Vec::<String>::new());
    }
    let ran = fixture.run_with(
        &[RUN_FENCE],
        Opts {
            work: Some(fixture.work("loom-only")),
            ..Opts::default()
        },
    );
    assert_eq!(ran.code(), Some(0), "{}", ran.stderr);
    assert_eq!(results(ran.report(), RUN_FENCE), ["survived"; 2]);
}

#[test]
fn a_planted_file_a_text_restore_cannot_reproduce_is_refused() {
    let fixture = Fixture::new("line-endings");
    let files = super::standins::scoped_files(&fixture.repo);
    let credit = fixture.repo.join(&files[0]);
    let bytes = fs::read_to_string(&credit)
        .expect("reads")
        .replace('\n', "\r\n");
    fs::write(&credit, bytes).expect("written");
    fixture.commit();
    let ran = fixture.run_rows(&[CREDIT_ROW]);
    assert_eq!(ran.code(), Some(2), "{}", ran.stderr);
    let wanted = format!("the scoped files ['{}'] hold line endings", files[0]);
    assert!(ran.stderr.contains(&wanted), "{}", ran.stderr);
    assert!(ran.report.is_none());
    assert_eq!(fixture.lines(".lane"), Vec::<String>::new());
}
