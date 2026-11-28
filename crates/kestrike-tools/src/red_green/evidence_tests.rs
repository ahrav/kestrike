use std::fs::{self, DirBuilder};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use super::{Evidence, Readings, evidence};
use crate::paths::tests::Scratch;
use crate::red_green::reasons::tests::{leg, options};
use crate::red_green::reasons::{NO_EVIDENCE, base_reason, head_reason};
use crate::text::Text;

const TEST: &str = "storage::device::table_tests::a_poll_reports_each_completion_once";
const EXPECT: &str = "a poll counts that completion as delivered";

fn mkfifo(path: &Path) {
    let made = std::process::Command::new("mkfifo").arg(path).status();
    assert!(made.expect("mkfifo starts").success(), "the FIFO is made");
}

fn receipt(scratch: &Scratch) -> PathBuf {
    let receipt = scratch.0.join("receipts/local-1-1");
    fs::create_dir_all(&receipt).expect("the receipt is made");
    for name in [
        "local-1-1-1-base",
        "local-1-1-1-head.2",
        "local-1-1-1-base.3",
        "local-1-1-1-base.4",
        "local-1-1-1-base.\u{663}",
        "local-1-1-2-base",
        "local-1-1-1-base.x",
        "local-1-1-1-base.",
    ] {
        DirBuilder::new()
            .mode(0o700)
            .create(receipt.join(name))
            .expect("the leg is made");
        fs::write(receipt.join(name).join("attempt-1.stdout"), EXPECT).expect("written");
    }
    for name in [
        "local-1-1-1-base",
        "local-1-1-1-head.2",
        "local-1-1-1-base.\u{663}",
        "local-1-1-2-base",
        "local-1-1-1-base.x",
        "local-1-1-1-base.",
    ] {
        fs::write(receipt.join(name).join("artifact.json"), "{}\n").expect("written");
    }
    fs::create_dir(receipt.join("local-1-1-1-base.3/artifact.json")).expect("made");
    fs::write(receipt.join("local-1-1-1-head.2/attempt-1.stderr"), "").expect("written");
    fs::create_dir(receipt.join("local-1-1-1-base.5")).expect("made");
    fs::write(receipt.join("local-1-1-1-base.5/artifact.json"), "{}\n").expect("written");
    mkfifo(&receipt.join("local-1-1-1-base.5/attempt-1.stdout"));
    fs::create_dir(receipt.join("local-1-1-1-base.5/attempt-1.stderr")).expect("made");
    let outside = scratch.0.join("outside/local-1-1-1-base");
    fs::create_dir_all(&outside).expect("made");
    fs::write(outside.join("artifact.json"), "{}\n").expect("written");
    fs::create_dir(receipt.join("local-1-1-1-base.6")).expect("made");
    symlink(
        outside.join("artifact.json"),
        receipt.join("local-1-1-1-base.6/artifact.json"),
    )
    .expect("linked");
    symlink(receipt.join("local-1-1-1-base"), scratch.0.join("via")).expect("linked");
    fs::create_dir(receipt.join("local-1-1-1-base.7")).expect("made");
    symlink(
        "artifact.json",
        receipt.join("local-1-1-1-base.7/artifact.json"),
    )
    .expect("linked");
    fs::create_dir(receipt.join("local-1-1-1-base.8")).expect("made");
    fs::write(receipt.join("local-1-1-1-base.8/artifact.json"), "{}\n").expect("written");
    let locked = receipt.join("local-1-1-1-base.8/attempt-1.stderr");
    fs::write(&locked, "").expect("written");
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).expect("locked");
    receipt
}

fn read(artifact: PathBuf, streams: &[&'static str]) -> Evidence {
    let outputs = streams
        .iter()
        .map(|stream| {
            let data = if *stream == "stdout" {
                EXPECT.as_bytes().to_vec()
            } else {
                Vec::new()
            };
            (*stream, data)
        })
        .collect();
    Evidence::Read(Readings {
        artifact,
        data: b"{}\n".to_vec(),
        outputs,
    })
}

enum Expected {
    Absent,
    Unreadable(PathBuf),
    Read(&'static str, &'static [&'static str]),
}

/// A leg's evidence counts only as `artifact.json` directly in its own directory of this run's receipt,
/// read through links. Only regular attempt output files contribute to a leg's readings.
#[test]
fn a_leg_counts_only_its_own_readable_artifact_and_a_reported_verdict() {
    let scratch = Scratch::new("red-green-evidence");
    let receipt = receipt(&scratch);
    let at = |name: &str| receipt.join(name).join("artifact.json");
    let mut rows: Vec<(&str, &str, Option<PathBuf>, &str, Expected)> = vec![
        (
            "its own artifact",
            "base",
            Some(at("local-1-1-1-base")),
            "1",
            Expected::Read("local-1-1-1-base", &["stdout"]),
        ),
        (
            "a suffixed directory",
            "head",
            Some(at("local-1-1-1-head.2")),
            "1",
            Expected::Read("local-1-1-1-head.2", &["stdout", "stderr"]),
        ),
        (
            "another leg's artifact",
            "head",
            Some(at("local-1-1-1-base")),
            "1",
            Expected::Absent,
        ),
        (
            "an attempt output for the artifact",
            "base",
            Some(receipt.join("local-1-1-1-base/attempt-1.stdout")),
            "1",
            Expected::Absent,
        ),
        (
            "a directory outside the receipt",
            "base",
            Some(scratch.0.join("outside/local-1-1-1-base/artifact.json")),
            "1",
            Expected::Absent,
        ),
        (
            "an artifact that is a directory",
            "base",
            Some(at("local-1-1-1-base.3")),
            "1",
            Expected::Unreadable(at("local-1-1-1-base.3")),
        ),
        (
            "an artifact that is absent",
            "base",
            Some(at("local-1-1-1-base.4")),
            "1",
            Expected::Unreadable(at("local-1-1-1-base.4")),
        ),
        (
            "a suffix of other decimal digits",
            "base",
            Some(at("local-1-1-1-base.\u{663}")),
            "1",
            Expected::Read("local-1-1-1-base.\u{663}", &["stdout"]),
        ),
        (
            "a suffix that is no number",
            "base",
            Some(at("local-1-1-1-base.x")),
            "1",
            Expected::Absent,
        ),
        (
            "another attempt's directory",
            "base",
            Some(at("local-1-1-2-base")),
            "1",
            Expected::Absent,
        ),
        (
            "this attempt's directory",
            "base",
            Some(at("local-1-1-2-base")),
            "2",
            Expected::Read("local-1-1-2-base", &["stdout"]),
        ),
        (
            "a link to its own directory",
            "base",
            Some(scratch.0.join("via/artifact.json")),
            "1",
            Expected::Read("local-1-1-1-base", &["stdout"]),
        ),
        (
            "a path through ..",
            "base",
            Some(receipt.join("local-1-1-1-base/../local-1-1-1-base/artifact.json")),
            "1",
            Expected::Read("local-1-1-1-base", &["stdout"]),
        ),
        (
            "outputs that are a FIFO and a directory",
            "base",
            Some(at("local-1-1-1-base.5")),
            "1",
            Expected::Read("local-1-1-1-base.5", &[]),
        ),
        (
            "an artifact that links out of the receipt",
            "base",
            Some(at("local-1-1-1-base.6")),
            "1",
            Expected::Absent,
        ),
        (
            "an artifact that links to itself",
            "base",
            Some(at("local-1-1-1-base.7")),
            "1",
            Expected::Unreadable(at("local-1-1-1-base.7")),
        ),
        (
            "an empty suffix",
            "base",
            Some(at("local-1-1-1-base.")),
            "1",
            Expected::Absent,
        ),
        ("no announcement", "base", None, "1", Expected::Absent),
    ];
    let locked = receipt.join("local-1-1-1-base.8/attempt-1.stderr");
    if fs::File::open(&locked).is_err() {
        rows.push((
            "an attempt output that cannot be read",
            "base",
            Some(at("local-1-1-1-base.8")),
            "1",
            Expected::Unreadable(locked.clone()),
        ));
    } else {
        eprintln!(
            "a mode 000 file opens for this user, so the unreadable attempt output row is not run"
        );
    }
    for (name, leg, announced, attempt, expected) in rows {
        let announced = announced.map(|path| Text::from_os(path.as_os_str()));
        let found = evidence(&receipt, &Text::from(attempt), leg, announced.as_ref())
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        match expected {
            Expected::Absent => assert_eq!(found, Evidence::Absent, "{name}"),
            Expected::Unreadable(path) => {
                let Evidence::Unreadable(error) = &found else {
                    panic!("{name}: {found:?}");
                };
                let named = Text::from_os(path.as_os_str());
                let opening = crate::text::text!(named, ": ");
                assert!(error.starts_with(&opening), "{name}: {error:?}");
            }
            Expected::Read(directory, streams) => {
                assert_eq!(found, read(at(directory), streams), "{name}");
            }
        }
    }
    let artifact = at("local-1-1-1-base");
    let options = options(TEST, EXPECT);
    for code in [0, 6] {
        let found = base_reason(&mut leg(code, "", Evidence::Absent), &options);
        let expected = format!("the runner did not complete the base leg: exit {code}, verdict ''");
        assert_eq!(found, Some(Text::from(expected)));
    }
    let unreported = head_reason(&leg(1, "", read(artifact.clone(), &["stdout", "stderr"])));
    assert_eq!(
        unreported,
        Some(Text::from("the head leg did not pass: exit 1, verdict ''"))
    );
    let (red, green) = (
        "reproduced: reproduced on attempt 1",
        "not reproduced in 1 attempts",
    );
    for streams in [&["stdout"][..], &["stderr"], &["stdout", "stderr"]] {
        let complete = streams.len() == 2;
        let base = base_reason(&mut leg(1, red, read(artifact.clone(), streams)), &options);
        let refused = Text::from(format!("the base leg failed but {NO_EVIDENCE}: {red}"));
        assert_eq!(base, (!complete).then_some(refused), "{streams:?}");
        let head = head_reason(&leg(0, green, read(artifact.clone(), streams)));
        let refused = Text::from(format!("the head leg passed but {NO_EVIDENCE}: {green}"));
        assert_eq!(head, (!complete).then_some(refused), "{streams:?}");
    }
}
