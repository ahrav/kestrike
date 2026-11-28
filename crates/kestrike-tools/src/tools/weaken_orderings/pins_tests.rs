use std::ffi::OsString;

use super::{shaping, workflow_pins};
use crate::paths::tests::Scratch;

/// A pin reads bare, double-quoted or single-quoted with a comment after it, a later line of a name takes
/// its value, only the `env` block before `jobs:` counts, so a pin after it neither sets nor supplies one,
/// and a missing, empty or unmatched-quote pin of STABLE, NIGHTLY or LOOM refuses with
/// exit 2 and names it.
#[test]
fn workflow_pins_read_quoted_and_commented_values_and_need_the_toolchain_pins() {
    use super::super::halt::Halt;
    let scratch = Scratch::new("weaken-pins");
    let workflow = scratch.0.join(".github/workflows/agent-checks.yml");
    std::fs::create_dir_all(workflow.parent().expect("a parent")).expect("made");
    std::fs::write(
        &workflow,
        "env:\n  STABLE: \"1.99.0\" # pinned\n  NIGHTLY: nightly-2026-07-27\n  LOOM: '0.6.0'\n  LOOM: '0.7.2' # quoted\n\njobs:\n  x: {}\n  STABLE: 9.9.9\n",
    )
    .expect("written");
    let pins = workflow_pins(&scratch.0).expect("the pins read");
    let expected: Vec<(String, String)> = [
        ("STABLE", "1.99.0"),
        ("NIGHTLY", "nightly-2026-07-27"),
        ("LOOM", "0.7.2"),
    ]
    .iter()
    .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
    .collect();
    assert_eq!(pins, expected);
    for (text, missing) in [
        (
            "env:\n  NIGHTLY: nightly-2026-07-27\n  LOOM: \"0.7.2\"\n\njobs:\n",
            "STABLE",
        ),
        (
            "env:\n  NIGHTLY: nightly-2026-07-27\n  LOOM: \"0.7.2\"\n\njobs:\n  STABLE: \"1.99.0\"\n",
            "STABLE",
        ),
        (
            "env:\n  STABLE: \"\"\n  NIGHTLY: n\n  LOOM: \"0.7.2\"\n\njobs:\n",
            "STABLE",
        ),
        (
            "env:\n  STABLE: 1.99.0\n  NIGHTLY: n\n  LOOM: '0.7.2\n\njobs:\n",
            "LOOM",
        ),
    ] {
        std::fs::write(&workflow, text).expect("written");
        match workflow_pins(&scratch.0) {
            Err(Halt::Stop { code, reason }) => {
                assert_eq!(code, 2, "{text:?}");
                assert!(
                    reason
                        .to_string()
                        .contains(&format!("names no {missing} pin")),
                    "{reason}"
                );
            }
            other => panic!("{text:?}: {other:?}"),
        }
    }
}

/// The shaping names leave the loom lane's environment, and `CARGO_BUILD_JOBS` and other names stay.
#[test]
fn the_loom_lane_clears_each_shaping_name() {
    for (name, cleared) in [
        ("RUSTC", true),
        ("RUSTC_WRAPPER", true),
        ("RUSTFLAGS", true),
        ("CARGO_ENCODED_RUSTDOCFLAGS", true),
        ("CARGO_BUILD_TARGET", true),
        ("CARGO_BUILD_JOBS", false),
        ("CARGO_BUILD_", false),
        ("CARGO_TARGET_DIR", true),
        ("CARGO_PROFILE_DEV_OPT_LEVEL", true),
        ("LOOM_MAX_PREEMPTIONS", true),
        ("LOOM_\n", false),
        ("RUSTC\n", true),
        ("RUSTCX", false),
        ("PATH", false),
    ] {
        assert_eq!(shaping(&OsString::from(name)), cleared, "{name:?}");
    }
}

/// The lane's environment holds one value of each name it sets, the run's own, whatever the inherited
/// environment repeats.
#[test]
fn the_lane_environment_sets_each_name_once() {
    let environ: Vec<(OsString, OsString)> =
        [("STABLE", "0.0.1"), ("PATH", "/bin"), ("STABLE", "0.0.2")]
            .iter()
            .map(|(name, value)| (OsString::from(name), OsString::from(value)))
            .collect();
    let pins = vec![("STABLE".to_owned(), "1.99.0".to_owned())];
    let env = super::lane_env(&environ, std::path::Path::new("/w"), &pins);
    let stable: Vec<&OsString> = env
        .iter()
        .filter(|(name, _)| name == "STABLE")
        .map(|(_, value)| value)
        .collect();
    assert_eq!(stable, [&OsString::from("1.99.0")]);
}
