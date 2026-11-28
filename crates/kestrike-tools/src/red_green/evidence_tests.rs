use std::fs::{self, DirBuilder, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt, symlink};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use super::{Evidence, Readings, evidence};
use crate::paths::DEPTH;
use crate::paths::tests::Scratch;
use crate::red_green::reasons::tests::{leg, options};
use crate::red_green::reasons::{NO_EVIDENCE, base_reason, head_reason};
use crate::text::{Text, text};

const TEST: &str = "storage::device::table_tests::a_poll_reports_each_completion_once";
const EXPECT: &str = "a poll counts that completion as delivered";

pub(crate) fn mkfifo(path: &Path) {
    let made = std::process::Command::new("mkfifo").arg(path).status();
    assert!(made.expect("mkfifo starts").success(), "the FIFO is made");
}

/// The value of `F_SETSIG` in Linux's `fcntl.h`.
const F_SETSIG: libc::c_int = 10;

/// A write lease this process holds on a file, released by a thread of its own once a lease break begins
/// or after 30 seconds.
pub(crate) struct Lease(JoinHandle<bool>);

impl Lease {
    /// `None` where the kernel or the filesystem refuses the lease. The break is signaled with `SIGURG`,
    /// whose default action ignores it.
    pub(crate) fn take(path: &Path) -> Option<Self> {
        let file = fs::File::open(path).expect("the leased file opens");
        let descriptor = file.as_raw_fd();
        // SAFETY: `descriptor` stays open across both calls because `file` lives past them, and each
        // command takes an integer argument.
        let taken = unsafe {
            libc::fcntl(descriptor, F_SETSIG, libc::SIGURG) == 0
                && libc::fcntl(descriptor, libc::F_SETLEASE, libc::F_WRLCK) == 0
        };
        if !taken {
            return None;
        }
        Some(Self(std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(30);
            while Instant::now() < deadline {
                // SAFETY: `file` is owned by this thread and open for each call.
                let held = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETLEASE) };
                if held != libc::F_WRLCK {
                    // SAFETY: as above.
                    let released =
                        unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETLEASE, libc::F_UNLCK) };
                    return released == 0;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            false
        })))
    }

    /// Whether a lease break began and the lease was released.
    pub(crate) fn broken(self) -> bool {
        self.0.join().expect("the lease thread ends")
    }
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
        "local-1-1-1-head.2/local-1-1-1-base",
        "local-1-1-1-base2",
        "local-9-9-1-base",
        "local-1-1-1-base.10",
        "local-1-1-1-base.11",
        "local-1-1-1-base.13",
    ] {
        DirBuilder::new()
            .mode(0o700)
            .create(receipt.join(name))
            .expect("the leg is made");
        fs::write(receipt.join(name).join("attempt-1.stdout"), EXPECT).expect("written");
        if !name.ends_with(".3") && !name.ends_with(".4") {
            fs::write(receipt.join(name).join("artifact.json"), "{}\n").expect("written");
        }
    }
    fs::create_dir(receipt.join("local-1-1-1-base.9")).expect("made");
    fs::write(
        receipt.join("local-1-1-1-base.9/attempt-1.stdout"),
        "other\n",
    )
    .expect("written");
    symlink(
        "../local-1-1-1-base/artifact.json",
        receipt.join("local-1-1-1-base.9/artifact.json"),
    )
    .expect("linked");
    symlink(
        "../local-1-1-1-head.2/attempt-1.stderr",
        receipt.join("local-1-1-1-base.10/attempt-1.stderr"),
    )
    .expect("linked");
    symlink(
        "attempt-1.stderr",
        receipt.join("local-1-1-1-base.11/attempt-1.stderr"),
    )
    .expect("linked");
    symlink("loop", receipt.join("loop")).expect("linked");
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
    let socket = scratch.0.join("s");
    UnixListener::bind(&socket).expect("the socket is bound");
    fs::rename(
        &socket,
        receipt.join("local-1-1-1-base.13/attempt-1.stderr"),
    )
    .expect("moved");
    let elsewhere = scratch.0.join("elsewhere");
    fs::create_dir(&elsewhere).expect("made");
    fs::write(elsewhere.join("artifact.json"), ELSEWHERE[0]).expect("written");
    fs::write(elsewhere.join("attempt-1.stdout"), ELSEWHERE[1]).expect("written");
    fs::write(elsewhere.join("attempt-1.stderr"), ELSEWHERE[2]).expect("written");
    symlink(&elsewhere, receipt.join("local-1-1-1-base.16")).expect("linked");
    receipt
}

/// The artifact and the two attempt outputs of a directory outside the receipt.
const ELSEWHERE: [&str; 3] = [
    "{\"elsewhere\": 1}\n",
    "elsewhere stdout\n",
    "elsewhere stderr\n",
];

fn read(artifact: PathBuf, streams: &[&str]) -> Evidence {
    let output = |stream: &str| {
        let data = if stream == "stdout" { EXPECT } else { "" };
        streams.contains(&stream).then(|| data.as_bytes().to_vec())
    };
    Evidence::Read(Readings {
        artifact,
        data: b"{}\n".to_vec(),
        outputs: [output("stdout"), output("stderr")],
    })
}

enum Expected {
    Absent,
    Unreadable(PathBuf),
    Read(&'static str, &'static [&'static str]),
}

/// A leg's evidence counts only as `artifact.json` directly in its own directory of this run's receipt,
/// read through links. Only regular attempt output files contribute to a leg's readings, each read at
/// the target of a link. An announcement that holds a NUL, or a surrogate that encodes to no byte, names
/// no artifact.
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
        (
            "an own-named directory below another leg's",
            "base",
            Some(at("local-1-1-1-head.2/local-1-1-1-base")),
            "1",
            Expected::Absent,
        ),
        (
            "digits without a dot",
            "base",
            Some(at("local-1-1-1-base2")),
            "1",
            Expected::Absent,
        ),
        (
            "another run's name",
            "base",
            Some(at("local-9-9-1-base")),
            "1",
            Expected::Absent,
        ),
        (
            "an artifact that links to another directory of the leg",
            "base",
            Some(at("local-1-1-1-base.9")),
            "1",
            Expected::Read("local-1-1-1-base", &["stdout"]),
        ),
        (
            "an attempt output that links to a regular file",
            "base",
            Some(at("local-1-1-1-base.10")),
            "1",
            Expected::Read("local-1-1-1-base.10", &["stdout", "stderr"]),
        ),
        (
            "an attempt output that links to itself",
            "base",
            Some(at("local-1-1-1-base.11")),
            "1",
            Expected::Read("local-1-1-1-base.11", &["stdout"]),
        ),
        (
            "a looping link before ..",
            "base",
            Some(receipt.join("loop/../local-1-1-1-base/artifact.json")),
            "1",
            Expected::Read("local-1-1-1-base", &["stdout"]),
        ),
        (
            "a looping link before a repeated separator",
            "base",
            Some(receipt.join("loop//../local-1-1-1-base/artifact.json")),
            "1",
            Expected::Absent,
        ),
        (
            "a looping link before a root of two slashes",
            "base",
            Some(PathBuf::from(format!(
                "{}/loop//{}/local-1-1-1-base/artifact.json",
                receipt.display(),
                receipt.display()
            ))),
            "1",
            Expected::Absent,
        ),
        (
            "an attempt output that is a socket",
            "base",
            Some(at("local-1-1-1-base.13")),
            "1",
            Expected::Read("local-1-1-1-base.13", &["stdout"]),
        ),
        (
            "a leg-named link to a directory outside the receipt",
            "base",
            Some(at("local-1-1-1-base.16")),
            "1",
            Expected::Absent,
        ),
        (
            "a NUL behind a looping link",
            "base",
            Some(receipt.join("loop/../x\0/../local-1-1-1-base/artifact.json")),
            "1",
            Expected::Absent,
        ),
        (
            "a NUL in a component that .. removes",
            "base",
            Some(receipt.join("x\0/../local-1-1-1-base/artifact.json")),
            "1",
            Expected::Absent,
        ),
        (
            "a NUL in a kept component",
            "base",
            Some(receipt.join("local-1-1-1-base/artifact.json\0")),
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
                let opening = text!(named, ": ");
                assert!(error.starts_with(&opening), "{name}: {error:?}");
            }
            Expected::Read(directory, streams) => {
                assert_eq!(found, read(at(directory), streams), "{name}");
            }
        }
    }
    let clean = Text::from_os(receipt.as_os_str());
    let through = |before: &str, component: u32| {
        let component = Text::from_code_points([component]).expect("a code point");
        text!(
            &clean,
            before,
            component,
            "/../local-1-1-1-base/artifact.json"
        )
    };
    for (name, announced, expected) in [
        (
            "a component that .. removes",
            through("/", u32::from('x')),
            read(at("local-1-1-1-base"), &["stdout"]),
        ),
        (
            "a surrogate that encodes to no byte",
            through("/", 0xd800),
            Evidence::Absent,
        ),
        (
            "a surrogate that encodes to no byte behind a looping link",
            through("/loop/../", 0xd800),
            Evidence::Absent,
        ),
    ] {
        let found = evidence(&receipt, &Text::from("1"), "base", Some(&announced));
        assert_eq!(found.expect("the path resolves"), expected, "{name}");
    }
    let behind = receipt.join("loop/../local-1-1-1-base.16/artifact.json");
    let found = evidence(
        &receipt,
        &Text::from("1"),
        "base",
        Some(&Text::from_os(behind.as_os_str())),
    );
    let [data, stdout, stderr] = ELSEWHERE.map(|bytes| bytes.as_bytes().to_vec());
    let elsewhere = Evidence::Read(Readings {
        artifact: at("local-1-1-1-base.16"),
        data,
        outputs: [Some(stdout), Some(stderr)],
    });
    assert_eq!(
        found.expect("the path resolves"),
        elsewhere,
        "a leg-named link behind a looping link"
    );
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

/// An `artifact.json` that is a FIFO is read as its writer wrote it; with no writer the read waits for
/// one.
#[test]
fn an_artifact_that_is_a_fifo_reads_what_its_writer_wrote() {
    let scratch = Scratch::new("red-green-evidence");
    let receipt = scratch.0.join("local-1-1");
    let leg = receipt.join("local-1-1-1-base");
    fs::create_dir_all(&leg).expect("the leg is made");
    fs::write(leg.join("attempt-1.stdout"), EXPECT).expect("written");
    let artifact = leg.join("artifact.json");
    mkfifo(&artifact);
    let writer = {
        let artifact = artifact.clone();
        std::thread::spawn(move || fs::write(artifact, "{}\n"))
    };
    let announced = Text::from_os(artifact.as_os_str());
    let found = evidence(&receipt, &Text::from("1"), "base", Some(&announced));
    let release = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&artifact)
        .expect("the FIFO opens for reading without a wait");
    let written = writer.join().expect("the writer ends");
    drop(release);
    assert_eq!(
        found.expect("the path resolves"),
        read(artifact, &["stdout"])
    );
    written.expect("the FIFO takes the bytes");
}

/// An attempt output that links to a file outside the leg's directory is read at its target, and the base
/// leg's search finds the expected text in the target's bytes.
#[test]
fn an_attempt_output_that_links_outside_the_leg_is_read_at_its_target() {
    for (index, stream) in ["stdout", "stderr"].into_iter().enumerate() {
        let scratch = Scratch::new("red-green-evidence");
        let receipt = scratch.0.join("local-1-1");
        let leg_directory = receipt.join("local-1-1-1-base");
        fs::create_dir_all(&leg_directory).expect("the leg is made");
        fs::write(leg_directory.join("artifact.json"), "{}\n").expect("written");
        let target = scratch.0.join("target");
        fs::write(&target, format!("linked {EXPECT}\n")).expect("written");
        let peer = ["stderr", "stdout"][index];
        fs::write(leg_directory.join(format!("attempt-1.{peer}")), "peer\n").expect("written");
        symlink(&target, leg_directory.join(format!("attempt-1.{stream}"))).expect("linked");
        let artifact = leg_directory.join("artifact.json");
        let announced = Text::from_os(artifact.as_os_str());
        let found = evidence(&receipt, &Text::from("1"), "base", Some(&announced))
            .expect("the path resolves");
        let mut outputs = [Some(b"peer\n".to_vec()), Some(b"peer\n".to_vec())];
        outputs[index] = Some(format!("linked {EXPECT}\n").into_bytes());
        let expected = Evidence::Read(Readings {
            artifact,
            data: b"{}\n".to_vec(),
            outputs,
        });
        assert_eq!(found, expected, "{stream}");
        let mut judged = leg(1, "reproduced: on attempt 1", found);
        let reason = base_reason(&mut judged, &options(TEST, EXPECT));
        assert_eq!(reason, None, "{stream}");
        assert_eq!(judged.expect_streams, Some(vec![stream]), "{stream}");
    }
}

/// An attempt output under another process's write lease is read once the lease breaks.
#[test]
fn an_attempt_output_under_a_write_lease_is_read_once_the_lease_breaks() {
    let scratch = Scratch::new("red-green-evidence");
    let receipt = scratch.0.join("local-1-1");
    let leg_directory = receipt.join("local-1-1-1-base");
    fs::create_dir_all(&leg_directory).expect("the leg is made");
    fs::write(leg_directory.join("artifact.json"), "{}\n").expect("written");
    fs::write(leg_directory.join("attempt-1.stdout"), EXPECT).expect("written");
    fs::write(leg_directory.join("attempt-1.stderr"), "").expect("written");
    let Some(lease) = Lease::take(&leg_directory.join("attempt-1.stdout")) else {
        eprintln!("the filesystem refuses a write lease, so the property is not exercised");
        return;
    };
    let artifact = leg_directory.join("artifact.json");
    let announced = Text::from_os(artifact.as_os_str());
    let found = evidence(&receipt, &Text::from("1"), "base", Some(&announced));
    assert!(lease.broken(), "the read opens the leased output");
    assert_eq!(
        found.expect("the path resolves"),
        read(artifact, &["stdout", "stderr"])
    );
}

/// An announcement through links nested past `DEPTH` is an error, where a chain of `DEPTH` links resolves.
#[test]
fn an_announcement_through_links_nested_past_the_depth_is_an_error() {
    let scratch = Scratch::new("red-green-evidence");
    let receipt = scratch.0.join("local-1-1");
    fs::create_dir_all(receipt.join(format!("l{}", DEPTH + 1))).expect("made");
    for at in 0..=DEPTH {
        symlink(format!("l{}", at + 1), receipt.join(format!("l{at}"))).expect("linked");
    }
    let announce = |link: &str| Text::from_os(receipt.join(link).join("artifact.json").as_os_str());
    let within = evidence(&receipt, &Text::from("1"), "base", Some(&announce("l1")));
    assert_eq!(
        within.expect("a chain of DEPTH links resolves"),
        Evidence::Absent
    );
    let error = evidence(&receipt, &Text::from("1"), "base", Some(&announce("l0")))
        .expect_err("a chain past DEPTH is refused");
    assert!(
        error
            .to_string()
            .starts_with(&format!("links nest more than {DEPTH} deep at ")),
        "{error}"
    );
}
