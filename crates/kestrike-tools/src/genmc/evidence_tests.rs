use std::fs;
use std::path::Path;

use super::{check_command, check_config};
use crate::genmc::case::tests::{declaration, root};
use crate::genmc::refusal::Error;
use crate::json::{Object, Value, parse};
use crate::paths::tests::Scratch;

const LSE_CONFIG: &str = "{\"target\":{\"cfg(target_arch = \\\"aarch64\\\")\":{\"rustdocflags\":[\"-C\",\
\"target-feature=+lse\"],\"rustflags\":[\"-C\",\"target-feature=+lse\"]}}}\n";

fn configured(bytes: Option<&[u8]>) -> Result<(), String> {
    let scratch = Scratch::new("check-config");
    if let Some(bytes) = bytes {
        fs::write(scratch.0.join("cargo-config.json"), bytes).expect("the configuration writes");
    }
    check_config(&scratch.0).map_err(|error| match error {
        Error::Refusal(refusal) => refusal.reason().to_owned(),
        other => panic!("a refusal, not {other:?}"),
    })
}

fn refused(text: &str) -> String {
    configured(Some(text.as_bytes())).expect_err("the configuration is refused")
}

#[test]
fn a_recorded_configuration_admits_the_lse_table_alone() {
    assert_eq!(configured(Some(LSE_CONFIG.as_bytes())), Ok(()));
    let reordered = r#"{"target": {"cfg(target_arch = \"aarch64\")": {"rustflags": ["-C", "target-feature=+lse"], "rustdocflags": ["-C", "target-feature=+lse"]}}, "build": {"jobs": 2}}"#;
    assert_eq!(configured(Some(reordered.as_bytes())), Ok(()));
    #[rustfmt::skip]
    let rows = [
        (r#"{"profile": {}, "source": {}}"#, "the cargo configuration sets profile, source"),
        (r#"{"target": {"x": {}}}"#, "the cargo configuration sets target"),
        (r#"{"build": {"jobs": 4, "target-dir": "x", "rustc": "r"}}"#, "the cargo configuration sets build.rustc, build.target-dir"),
        (r#"{"env": {"RUSTFLAGS": "x", "OTHER": "y", "CARGO_HOME": "z", "CASE": "c"}}"#,
         "the cargo configuration sets env.CARGO_HOME, env.CASE, env.RUSTFLAGS"),
        ("[1]", "the recorded cargo configuration is not a table"),
        (r#"{"build": [1]}"#, "malformed evidence: the recorded cargo configuration's build is not a table"),
        (r#"{"env": "x"}"#, "malformed evidence: the recorded cargo configuration's env is not a table"),
    ];
    for (text, reason) in rows {
        assert_eq!(refused(text), reason, "{text}");
    }
    let linker = LSE_CONFIG.replace(
        "\"rustdocflags\"",
        "\"linker\":\"/usr/bin/ld\",\"rustdocflags\"",
    );
    assert_eq!(refused(&linker), "the cargo configuration sets target");
}

#[test]
fn a_configuration_that_is_missing_or_unreadable_is_a_tool_failure() {
    assert_eq!(
        configured(None),
        Err("the lane left no recorded cargo configuration".to_owned())
    );
    let unreadable = "the recorded cargo configuration is unreadable: ";
    assert!(refused("{").starts_with(unreadable));
    let bytes = configured(Some(b"\xff")).expect_err("the configuration is refused");
    assert!(bytes.starts_with(unreadable), "{bytes}");
    let deep = format!("{}{}", "[".repeat(5000), "]".repeat(5000));
    assert!(refused(&deep).starts_with("malformed evidence: "));
}

struct Command {
    argv: Vec<String>,
    env: Object,
}

fn command(evidence: &Path) -> Command {
    let manifest = root().join("verification/genmc/packages/run-join-production/Cargo.toml");
    let argv = vec![
        "/genmc/build/bin/genmc".to_owned(),
        "-rc11".to_owned(),
        "--disable-estimation".to_owned(),
        format!(
            "--dump-error-graph={}",
            evidence.join("genmc-join-production.dot").display()
        ),
        manifest.display().to_string(),
    ];
    let mut env = Object::new();
    for (name, value) in [
        ("CASE", "join-production"),
        ("RUSTUP_TOOLCHAIN", "nightly-2026-07-27"),
        ("RUSTC", "/toolchain/bin/rustc"),
        ("RUSTC_WRAPPER", ""),
        ("RUSTC_WORKSPACE_WRAPPER", ""),
    ] {
        env.insert(name, Value::String(value.into()));
    }
    Command { argv, env }
}

fn commanded(evidence: &Path, command: &Command) -> Result<(), String> {
    let record = parse(
        r#"{"binary": {"path": "/genmc/build/bin/genmc"}, "rustc": {"name": "nightly-2026-07-27", "toolchain": "/toolchain"}}"#,
    )
    .expect("JSON");
    check_command(
        &root(),
        "join-production",
        &declaration(),
        &record,
        &command.argv,
        &command.env,
        evidence,
    )
    .map_err(|error| match error {
        Error::Refusal(refusal) => refusal
            .reason()
            .replace(&evidence.display().to_string(), "<EV>"),
        other => panic!("a refusal, not {other:?}"),
    })
}

#[test]
fn a_command_is_the_identified_genmc_with_the_cases_own_graph_and_manifest() {
    let scratch = Scratch::new("check-command");
    let evidence = &scratch.0;
    let good = command(evidence);
    assert_eq!(commanded(evidence, &good), Ok(()));
    let manifest = root().join("verification/genmc/packages/run-join-production/Cargo.toml");
    let wanted = format!(
        "not genmc -rc11 --disable-estimation --dump-error-graph=<EV>/genmc-join-production.dot {}",
        manifest.display()
    );
    let other = root().join("verification/genmc/packages/run-other/Cargo.toml");
    let changes: [(usize, String); 4] = [
        (0, "/other/genmc".to_owned()),
        (2, "--estimation".to_owned()),
        (3, "--dump-error-graph=/elsewhere.dot".to_owned()),
        (4, other.display().to_string()),
    ];
    for (at, argument) in changes {
        let mut changed = command(evidence);
        changed.argv[at] = argument;
        let shown: Vec<String> = changed
            .argv
            .iter()
            .map(|item| {
                format!(
                    "'{}'",
                    item.replace(&evidence.display().to_string(), "<EV>")
                )
            })
            .collect();
        assert_eq!(
            commanded(evidence, &changed),
            Err(format!(
                "join-production ran [{}], {wanted}",
                shown.join(", ")
            )),
            "{at}"
        );
    }
    let mut wrapped = command(evidence);
    wrapped
        .env
        .insert("RUSTC_WRAPPER", Value::String("sccache".into()));
    assert_eq!(
        commanded(evidence, &wrapped),
        Err(
            "join-production ran with {'CASE': 'join-production', 'RUSTUP_TOOLCHAIN': \
'nightly-2026-07-27', 'RUSTC': '/toolchain/bin/rustc', 'RUSTC_WRAPPER': 'sccache', \
'RUSTC_WORKSPACE_WRAPPER': ''}, not {'CASE': 'join-production', 'RUSTUP_TOOLCHAIN': \
'nightly-2026-07-27', 'RUSTC': '/toolchain/bin/rustc', 'RUSTC_WRAPPER': '', \
'RUSTC_WORKSPACE_WRAPPER': ''}"
                .to_owned()
        )
    );
    let mut extra = command(evidence);
    extra.env.insert("EXTRA", Value::String("1".into()));
    assert!(commanded(evidence, &extra).is_err());
    let mut reordered = command(evidence);
    let mut entries: Vec<_> = reordered.env.iter().cloned().collect();
    entries.reverse();
    reordered.env = Object::new();
    for (name, value) in entries {
        reordered.env.insert(name, value);
    }
    assert_eq!(commanded(evidence, &reordered), Ok(()));
    let short = Command {
        argv: vec!["x".to_owned()],
        env: good.env.clone(),
    };
    assert_eq!(
        commanded(evidence, &short),
        Err(format!("join-production ran ['x'], {wanted}"))
    );
}

#[test]
fn every_shaping_table_and_build_key_is_named_in_order() {
    let all = r#"{"source": {}, "patch": {}, "unstable": {}, "target": {}, "profile": {}, "build": {"rustdocflags": 1, "rustflags": 1, "build-dir": 1, "target-dir": 1, "target": 1, "rustc-workspace-wrapper": 1, "rustc-wrapper": 1, "rustc": 1, "jobs": 1}}"#;
    assert_eq!(
        refused(all),
        "the cargo configuration sets profile, target, unstable, patch, source, build.rustc, \
         build.rustc-wrapper, build.rustc-workspace-wrapper, build.target, build.target-dir, \
         build.build-dir, build.rustflags, build.rustdocflags"
    );
    for table in ["profile", "target", "unstable", "patch", "source"] {
        let text = format!(r#"{{"{table}": {{}}}}"#);
        assert_eq!(
            refused(&text),
            format!("the cargo configuration sets {table}")
        );
    }
    for key in [
        "rustc",
        "rustc-wrapper",
        "rustc-workspace-wrapper",
        "target",
        "target-dir",
        "build-dir",
        "rustflags",
        "rustdocflags",
    ] {
        let text = format!(r#"{{"build": {{"{key}": "x"}}}}"#);
        assert_eq!(
            refused(&text),
            format!("the cargo configuration sets build.{key}")
        );
    }
}

#[test]
fn a_command_path_counts_by_its_resolved_form() {
    let scratch = Scratch::new("check-command-spelling");
    let evidence = &scratch.0;
    let mut spelled = command(evidence);
    spelled.argv[3] = format!(
        "--dump-error-graph={}/./genmc-join-production.dot",
        evidence.display()
    );
    spelled.argv[4] = root()
        .join("verification/genmc/packages/kernels/../run-join-production/Cargo.toml")
        .display()
        .to_string();
    assert_eq!(commanded(evidence, &spelled), Ok(()));
    let mut bare = command(evidence);
    bare.argv[3] = evidence
        .join("genmc-join-production.dot")
        .display()
        .to_string();
    assert!(commanded(evidence, &bare).is_err());
}

#[test]
fn a_graph_path_that_loops_is_a_runtime_error() {
    let scratch = Scratch::new("check-command-loop");
    let evidence = &scratch.0;
    let graph = evidence.join("genmc-join-production.dot");
    std::os::unix::fs::symlink(&graph, &graph).expect("the link is made");
    let record = parse(
        r#"{"binary": {"path": "/genmc/build/bin/genmc"}, "rustc": {"name": "n", "toolchain": "/t"}}"#,
    )
    .expect("JSON");
    let good = command(evidence);
    let result = check_command(
        &root(),
        "join-production",
        &declaration(),
        &record,
        &good.argv,
        &good.env,
        evidence,
    );
    assert!(matches!(result, Err(Error::Runtime(_))), "{result:?}");
}
