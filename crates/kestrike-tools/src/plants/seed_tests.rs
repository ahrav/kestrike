//! The seed check's manifest: the sweep's manifest of the suspect's profile, read as text with `\r\n` and
//! `\r` read as `\n`, hashed with the suspect's seed as its root, and pinned to the base archive.

use std::fs;

use super::manifest;

use crate::json::Value;
use crate::paths::tests::Scratch;
use crate::plants::output::archive_pins;
use crate::plants::suspects::Suspect;
use crate::text::Text;

fn write(path: &std::path::Path, bytes: &[u8]) {
    fs::create_dir_all(path.parent().expect("a parent")).expect("made");
    fs::write(path, bytes).expect("written");
}

const ROWS: &[(&[u8], &str, &str)] = &[
    (
        b"root = 0\nprofile = smoke\n",
        "70edc0e078a3eb51a5b3013e8df15929e5702b02da48985a0eab8eab1b531232",
        "root = 42\nprofile = smoke\n",
    ),
    (
        b"root\r\nbuild = a = b\rx = 1",
        "40023fa5c2e61f493b5753382a2f311cb6e0a5fae93621199360c9e3a0a7671f",
        "root = 42\nbuild = B\nx = 1\n",
    ),
    (
        b"root = 0\n\n",
        "3a1da508be429e2a3da724c695113b33d3d5c40b30546218c92a362790c1f275",
        "root = 42\n\n",
    ),
    (
        b"",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "",
    ),
    (
        b"\n",
        "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b",
        "\n",
    ),
    (
        b"build = x\nroot = 1\nroot = 2\n",
        "6600cc70ecf385935c120474cb7eb63c67d0d60d263fe46bddb12a65e615d38f",
        "build = B\nroot = 42\nroot = 42\n",
    ),
];

/// `suspect` is a suspect of `smoke` with the seed 42, read as `suspects.jsonl` holds one.
fn suspect() -> Suspect {
    let line = r#"{"profile": "smoke", "run": 3, "seed": 42, "class": "violation", "key": "violation: a"}"#;
    Suspect::from_line(line.as_bytes()).expect("a suspect")
}

/// A manifest whose seeded text hashes to the confirmed digest is pinned with the root and the four
/// pins; any other digest, a digest that is no text and a missing digest run nothing.
#[test]
fn a_manifest_runs_only_the_job_confirm_ran() {
    let scratch = Scratch::new("seed");
    let suspect = suspect();
    let root = scratch.0.join("root");
    let printed = r#"{"build": "B", "executable": "E", "platform": "P", "toolchain": "T"}"#;
    let pins = archive_pins(
        0,
        printed,
        "the unpatched head",
        "base/archive.err".as_ref(),
    )
    .expect("pins");
    let differs = Text::from("its manifest differs from the job `confirm` ran");
    for &(bytes, digest, pinned) in ROWS {
        write(&root.join("manifests/smoke.manifest"), bytes);
        let digest = Value::String(Text::from(digest));
        let read = manifest(&root, &suspect, Some(&digest)).expect("the digest matches");
        assert_eq!(read.pinned(&pins), Text::from(pinned), "{bytes:?}");
        let other = Value::String(Text::from("0".repeat(64)));
        assert_eq!(
            manifest(&root, &suspect, Some(&other)),
            Err(differs.clone())
        );
        assert_eq!(
            manifest(&root, &suspect, Some(&Value::Null)),
            Err(differs.clone())
        );
        assert_eq!(manifest(&root, &suspect, None), Err(differs.clone()));
    }
}

/// A manifest that is no UTF-8 text keeps the check from running, with the path and the reader's text.
#[test]
fn a_manifest_that_is_no_text_keeps_the_check_from_running() {
    let scratch = Scratch::new("seed");
    let suspect = suspect();
    let root = scratch.0.join("root");
    let path = root.join("manifests/smoke.manifest");
    write(&path, b"root = \xff\n");
    let failed = manifest(&root, &suspect, None).expect_err("no text");
    let reason = format!("{}: stream did not contain valid UTF-8", path.display());
    assert_eq!(failed, Text::from(reason.as_str()));
}

/// A profile that holds a surrogate names no file, so its check runs nothing.
#[test]
fn a_profile_that_names_no_file_runs_nothing() {
    let line = r#"{"profile": "\ud800", "run": 3, "seed": 42, "class": "violation", "key": "k"}"#;
    let suspect = Suspect::from_line(line.as_bytes()).expect("a suspect");
    let scratch = Scratch::new("seed-name");
    let refused = manifest(&scratch.0, &suspect, None).expect_err("no file name");
    assert_eq!(refused, Text::from("'\\ud800' names no manifest file"));
}
