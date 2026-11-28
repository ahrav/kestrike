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
    let manifest = root().join("verification/genmc/packages/run-join-production/Cargo.toml");
    let shown: Vec<String> = bare
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
        commanded(evidence, &bare),
        Err(format!(
            "join-production ran [{}], not genmc -rc11 --disable-estimation \
             --dump-error-graph=<EV>/genmc-join-production.dot {}",
            shown.join(", "),
            manifest.display()
        ))
    );
}

#[test]
fn a_refused_command_names_the_manifest_in_its_normal_form() {
    let scratch = Scratch::new("check-command-manifest");
    let evidence = &scratch.0;
    let Value::Object(mut declared) = declaration() else {
        panic!("the declaration is an object");
    };
    declared.insert(
        "package",
        Value::String("./verification//genmc/packages/kernels".into()),
    );
    let record = parse(r#"{"binary": {"path": "/g"}, "rustc": {"name": "n", "toolchain": "/t"}}"#)
        .expect("JSON");
    let result = check_command(
        &root(),
        "join-production",
        &Value::Object(declared),
        &record,
        &["x".to_owned()],
        &Object::new(),
        evidence,
    );
    let Err(Error::Refusal(refusal)) = result else {
        panic!("a refusal, not {result:?}");
    };
    let manifest = root().join("verification/genmc/packages/run-join-production/Cargo.toml");
    assert_eq!(
        refusal
            .reason()
            .replace(&evidence.display().to_string(), "<EV>"),
        format!(
            "join-production ran ['x'], not genmc -rc11 --disable-estimation \
             --dump-error-graph=<EV>/genmc-join-production.dot {}",
            manifest.display()
        )
    );
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

/// The admitted `target` table admits no other shaping entry beside it, and the same value under
/// another table is that table's entry.
#[test]
fn the_admitted_target_table_admits_nothing_beside_it() {
    let target = r#"{"cfg(target_arch = \"aarch64\")": {"rustflags": ["-C", "target-feature=+lse"], "rustdocflags": ["-C", "target-feature=+lse"]}}"#;
    for (beside, reason) in [
        (r#""profile": {}"#, "the cargo configuration sets profile"),
        (
            r#""build": {"rustflags": []}"#,
            "the cargo configuration sets build.rustflags",
        ),
        (
            r#""env": {"RUSTFLAGS": "x"}"#,
            "the cargo configuration sets env.RUSTFLAGS",
        ),
    ] {
        let text = format!(r#"{{"target": {target}, {beside}}}"#);
        assert_eq!(refused(&text), reason, "{beside}");
    }
    assert_eq!(
        refused(&format!(r#"{{"unstable": {target}}}"#)),
        "the cargo configuration sets unstable"
    );
}

/// The manifest is built on the resolved root, so a root named through a link admits the case's own
/// command; a package with a `//` root keeps it, so its manifest is no `/` path the command resolves.
#[test]
fn the_manifest_stands_under_the_resolved_root_with_the_packages_own_root() {
    let scratch = Scratch::new("check-command-root");
    let evidence = &scratch.0;
    let link = evidence.join("checkout");
    std::os::unix::fs::symlink(root(), &link).expect("the link is made");
    let record = parse(
        r#"{"binary": {"path": "/genmc/build/bin/genmc"}, "rustc": {"name": "nightly-2026-07-27", "toolchain": "/toolchain"}}"#,
    )
    .expect("JSON");
    let good = command(evidence);
    let check = |root: &Path, declared: &Value, argv: &[String]| {
        check_command(
            root,
            "join-production",
            declared,
            &record,
            argv,
            &good.env,
            evidence,
        )
    };
    assert!(check(&link, &declaration(), &good.argv).is_ok());
    let rooted = |package: &str| {
        let Value::Object(mut declared) = declaration() else {
            panic!("the declaration is an object");
        };
        declared.insert("package", Value::String(package.into()));
        Value::Object(declared)
    };
    let mut one = good.argv.clone();
    one[4] = "/kernels/run-join-production/Cargo.toml".to_owned();
    assert!(check(&root(), &rooted("/kernels/pkg"), &one).is_ok());
    let mut two = good.argv.clone();
    two[4] = "//kernels/run-join-production/Cargo.toml".to_owned();
    match check(&root(), &rooted("//kernels/pkg"), &two) {
        Err(Error::Refusal(refusal)) => assert!(
            refusal
                .reason()
                .ends_with(" //kernels/run-join-production/Cargo.toml"),
            "{}",
            refusal.reason()
        ),
        other => panic!("a refusal, not {other:?}"),
    }
}

/// A recorded path with a NUL byte is a value error, and a toolchain with a lone surrogate pins a
/// RUSTC that holds the surrogate, which a recorded `\ud800` spelled in ASCII is not.
#[test]
fn a_command_compares_the_values_it_was_given() {
    let scratch = Scratch::new("check-command-values");
    let evidence = &scratch.0;
    let record = |toolchain: &str| {
        parse(&format!(
            r#"{{"binary": {{"path": "/genmc/build/bin/genmc"}}, "rustc": {{"name": "nightly-2026-07-27", "toolchain": "{toolchain}"}}}}"#
        ))
        .expect("JSON")
    };
    let check = |record: &Value, command: &Command| {
        check_command(
            &root(),
            "join-production",
            &declaration(),
            record,
            &command.argv,
            &command.env,
            evidence,
        )
    };
    for at in [3, 4] {
        let mut nul = command(evidence);
        nul.argv[at] = nul.argv[at].replacen("/genmc", "/bad\0/../genmc", 1);
        assert!(nul.argv[at].contains('\0'), "{at}");
        match check(&record("/toolchain"), &nul) {
            Err(Error::Value(reason)) => assert_eq!(reason, "embedded null byte"),
            other => panic!("a value error, not {other:?}"),
        }
    }
    let mut ascii = command(evidence);
    ascii
        .env
        .insert("RUSTC", Value::String("\\ud800/bin/rustc".into()));
    match check(&record("\\ud800"), &ascii) {
        Err(Error::Refusal(refusal)) => assert_eq!(
            refusal.reason(),
            "join-production ran with {'CASE': 'join-production', 'RUSTUP_TOOLCHAIN': \
'nightly-2026-07-27', 'RUSTC': '\\\\ud800/bin/rustc', 'RUSTC_WRAPPER': '', 'RUSTC_WORKSPACE_WRAPPER': ''}, \
not {'CASE': 'join-production', 'RUSTUP_TOOLCHAIN': 'nightly-2026-07-27', 'RUSTC': '\\ud800/bin/rustc', \
'RUSTC_WRAPPER': '', 'RUSTC_WORKSPACE_WRAPPER': ''}"
        ),
        other => panic!("a refusal, not {other:?}"),
    }
}
