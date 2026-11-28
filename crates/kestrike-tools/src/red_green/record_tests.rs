use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use super::{Leg, Record, record};
use crate::red_green::evidence::{Evidence, Readings};
use crate::red_green::options::{DEFAULT_WATCHDOG, Options};
use crate::red_green::reasons::NO_EVIDENCE;
use crate::red_green::reasons::tests::options;
use crate::text::Text;

const PROVEN: &str = r#"{
  "base": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "cargo_target_dir": "/t/red-green/build",
  "carried": [
    {
      "blob": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "path": "t.rs"
    },
    {
      "blob": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "path": "caf\u00e9.rs"
    }
  ],
  "command": "bash scripts/tool.sh red-green --package=p --target=lib --test=storage::device::table_tests::a_poll_reports_each_completion_once '--expect=a poll counts that completion as delivered' --carry=t.rs --base=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb --head=cccccccccccccccccccccccccccccccccccccccc --watchdog=30.0 --release --artifacts=/r",
  "expect": "a poll counts that completion as delivered",
  "head": "cccccccccccccccccccccccccccccccccccccccc",
  "legs": {
    "base": {
      "artifact": "/r/local-1-1/local-1-1-1-base/artifact.json",
      "attempt_sha256": {
        "stderr": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "stdout": "860ebd846fe743c125dc562151f7e0ec10392d082826092fd05bd8724a358a3b"
      },
      "exit": 1,
      "expect_streams": [
        "stdout"
      ],
      "seconds": 12.346,
      "sha256": "ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356",
      "verdict": "reproduced: on attempt 1"
    },
    "head": {
      "artifact": "/r/local-1-1/local-1-1-1-head/artifact.json",
      "attempt_sha256": {
        "stderr": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "stdout": "dc51b8c96c2d745df3bd5590d990230a482fd247123599548e0632fdbf97fc22"
      },
      "exit": 0,
      "seconds": 0.001,
      "sha256": "ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356",
      "verdict": "not reproduced in 1 attempts"
    }
  },
  "package": "p",
  "release": true,
  "result": "proven",
  "scripts": {
    "reproduce-test.py": "1111111111111111111111111111111111111111111111111111111111111111",
    "select-tests.py": "2222222222222222222222222222222222222222222222222222222222222222"
  },
  "target": "lib",
  "test": "storage::device::table_tests::a_poll_reports_each_completion_once",
  "tool": {
    "executable": "3333333333333333333333333333333333333333333333333333333333333333"
  },
  "watchdog_seconds": 30.0
}
"#;

const WITHOUT_THE_TEXT: &str = r#"{
  "base": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "cargo_target_dir": "/t/red-green/build",
  "carried": [
    {
      "blob": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "path": "t.rs"
    },
    {
      "blob": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "path": "caf\u00e9.rs"
    }
  ],
  "command": "bash scripts/tool.sh red-green --package=p --target=lib --test=storage::device::table_tests::a_poll_reports_each_completion_once '--expect=a poll counts that completion as delivered' --carry=t.rs --base=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb --head=cccccccccccccccccccccccccccccccccccccccc --watchdog=30.0 --release --artifacts=/r",
  "expect": "a poll counts that completion as delivered",
  "head": "cccccccccccccccccccccccccccccccccccccccc",
  "legs": {
    "base": {
      "artifact": "/r/local-1-1/local-1-1-1-base/artifact.json",
      "attempt_sha256": {
        "stderr": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "stdout": "73cb3858a687a8494ca3323053016282f3dad39d42cf62ca4e79dda2aac7d9ac"
      },
      "exit": 1,
      "expect_streams": [],
      "seconds": 3.0,
      "sha256": "ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356",
      "verdict": "reproduced: on attempt 1"
    }
  },
  "package": "p",
  "release": true,
  "result": "refused: the test failed on the base without the expected text",
  "scripts": {
    "reproduce-test.py": "1111111111111111111111111111111111111111111111111111111111111111",
    "select-tests.py": "2222222222222222222222222222222222222222222222222222222222222222"
  },
  "target": "lib",
  "test": "storage::device::table_tests::a_poll_reports_each_completion_once",
  "tool": {
    "executable": null
  },
  "watchdog_seconds": 30.0
}
"#;

const REFUSED_AT_THE_BASE: &str = r#"{
  "base": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "cargo_target_dir": "/t/red-green/build",
  "carried": [
    {
      "blob": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "path": "t.rs"
    },
    {
      "blob": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "path": "caf\u00e9.rs"
    }
  ],
  "command": "bash scripts/tool.sh red-green --package=p --target=lib --test=storage::device::table_tests::a_poll_reports_each_completion_once '--expect=a poll counts that completion as delivered' --carry=t.rs --base=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb --head=cccccccccccccccccccccccccccccccccccccccc --watchdog=30.0 --artifacts=/r",
  "expect": "a poll counts that completion as delivered",
  "head": "cccccccccccccccccccccccccccccccccccccccc",
  "legs": {
    "base": {
      "artifact": null,
      "attempt_sha256": {},
      "evidence_error": "an error",
      "exit": 1,
      "seconds": 2.062,
      "sha256": null,
      "verdict": "reproduced"
    }
  },
  "package": "p",
  "release": false,
  "result": "refused: the base leg failed but x",
  "scripts": {
    "reproduce-test.py": "1111111111111111111111111111111111111111111111111111111111111111",
    "select-tests.py": "2222222222222222222222222222222222222222222222222222222222222222"
  },
  "target": "lib",
  "test": "storage::device::table_tests::a_poll_reports_each_completion_once",
  "tool": {
    "executable": "3333333333333333333333333333333333333333333333333333333333333333"
  },
  "watchdog_seconds": 30.0
}
"#;

const SIGNAL_DEATH: &str = r#"{
  "base": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "cargo_target_dir": "/t/red-green/build",
  "carried": [
    {
      "blob": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "path": "t.rs"
    },
    {
      "blob": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "path": "caf\u00e9.rs"
    }
  ],
  "command": "bash scripts/tool.sh red-green --package=p --target=lib --test=storage::device::table_tests::a_poll_reports_each_completion_once '--expect=a poll counts that completion as delivered' --carry=t.rs --base=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb --head=cccccccccccccccccccccccccccccccccccccccc --watchdog=30.0 --artifacts=/r",
  "expect": "a poll counts that completion as delivered",
  "head": "cccccccccccccccccccccccccccccccccccccccc",
  "legs": {
    "base": {
      "artifact": null,
      "attempt_sha256": {},
      "exit": -9,
      "seconds": 1.5,
      "sha256": null,
      "verdict": ""
    }
  },
  "package": "p",
  "release": false,
  "result": "refused: exit -9",
  "scripts": {
    "reproduce-test.py": "1111111111111111111111111111111111111111111111111111111111111111",
    "select-tests.py": "2222222222222222222222222222222222222222222222222222222222222222"
  },
  "target": "lib",
  "test": "storage::device::table_tests::a_poll_reports_each_completion_once",
  "tool": {
    "executable": "3333333333333333333333333333333333333333333333333333333333333333"
  },
  "watchdog_seconds": 30.0
}
"#;

const NO_LEG: &str = r#"{
  "base": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "cargo_target_dir": "/t/red-green/build",
  "carried": [
    {
      "blob": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "path": "t.rs"
    },
    {
      "blob": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "path": "caf\u00e9.rs"
    }
  ],
  "command": "bash scripts/tool.sh red-green --package=p --target=lib --test=storage::device::table_tests::a_poll_reports_each_completion_once '--expect=a poll counts that completion as delivered' --carry=t.rs --base=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb --head=cccccccccccccccccccccccccccccccccccccccc --watchdog=30.0 --artifacts=/r",
  "expect": "a poll counts that completion as delivered",
  "head": "cccccccccccccccccccccccccccccccccccccccc",
  "legs": {},
  "package": "p",
  "release": false,
  "result": "refused: the base leg's tree differs",
  "scripts": {
    "reproduce-test.py": "1111111111111111111111111111111111111111111111111111111111111111",
    "select-tests.py": "2222222222222222222222222222222222222222222222222222222222222222"
  },
  "target": "lib",
  "test": "storage::device::table_tests::a_poll_reports_each_completion_once",
  "tool": {
    "executable": "3333333333333333333333333333333333333333333333333333333333333333"
  },
  "watchdog_seconds": 30.0
}
"#;

const PARTIAL: &str = r#"{
  "base": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "cargo_target_dir": "/t/red-green/build",
  "carried": [
    {
      "blob": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "path": "t.rs"
    },
    {
      "blob": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "path": "caf\u00e9.rs"
    }
  ],
  "command": "bash scripts/tool.sh red-green --package=p --target=lib --test=storage::device::table_tests::a_poll_reports_each_completion_once '--expect=a poll counts that completion as delivered' --carry=t.rs --base=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb --head=cccccccccccccccccccccccccccccccccccccccc --watchdog=30.0 --artifacts=/r",
  "expect": "a poll counts that completion as delivered",
  "head": "cccccccccccccccccccccccccccccccccccccccc",
  "legs": {
    "base": {
      "artifact": "/r/local-1-1/local-1-1-1-base.\udcff/artifact.json",
      "attempt_sha256": {
        "stdout": "95aebb28195b8d737effe0df18d71d39c8d8ba6569286fd3930fbc9f9767181e"
      },
      "exit": 1,
      "seconds": 4.0,
      "sha256": "ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356",
      "verdict": "reproduced: on attempt 1"
    }
  },
  "package": "p",
  "release": false,
  "result": "refused: the base leg failed but left no readable artifact.json or attempt output of its own in the receipt: reproduced: on attempt 1",
  "scripts": {
    "reproduce-test.py": "1111111111111111111111111111111111111111111111111111111111111111",
    "select-tests.py": "2222222222222222222222222222222222222222222222222222222222222222"
  },
  "target": "lib",
  "test": "storage::device::table_tests::a_poll_reports_each_completion_once",
  "tool": {
    "executable": "3333333333333333333333333333333333333333333333333333333333333333"
  },
  "watchdog_seconds": 30.0
}
"#;

const TEST: &str = "storage::device::table_tests::a_poll_reports_each_completion_once";
const EXPECT: &str = "a poll counts that completion as delivered";
const COMMAND: &str = "bash scripts/tool.sh red-green --package=p --target=lib \
    --test=storage::device::table_tests::a_poll_reports_each_completion_once \
    '--expect=a poll counts that completion as delivered' --carry=t.rs \
    --base=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb --head=cccccccccccccccccccccccccccccccccccccccc \
    --watchdog=30.0 --artifacts=/r";

fn leg(exit: i32, verdict: &str, seconds: f64, evidence: Evidence) -> Leg {
    Leg {
        exit,
        verdict: Text::from(verdict),
        seconds,
        evidence,
        expect_streams: None,
    }
}

/// Seconds round to three places, half to even on the binary value: 0.0005 lies above the half and
/// 2.0625 on it. The proven run and the run refused without the expected text are release runs, the
/// others debug runs. The head leg enters with `expect_streams` set and its entry holds no such member.
#[test]
fn record_writes_each_state_of_the_receipt() {
    let options = Options {
        watchdog: 30.0,
        artifacts: Some(Text::from("r")),
        ..options(TEST, EXPECT)
    };
    assert_ne!(options.watchdog, DEFAULT_WATCHDOG);
    let released = Options {
        release: true,
        ..options.clone()
    };
    let released_command = Text::from(COMMAND.replace(" --artifacts", " --release --artifacts"));
    let (base, head, command) = (
        Text::from("b".repeat(40)),
        Text::from("c".repeat(40)),
        Text::from(COMMAND),
    );
    let carried = [
        (Text::from("t.rs"), Text::from("a".repeat(40))),
        (Text::from("caf\u{e9}.rs"), Text::from("b".repeat(40))),
    ];
    let scripts = [
        ("reproduce-test.py", "1".repeat(64)),
        ("select-tests.py", "2".repeat(64)),
    ];
    let executable = "3".repeat(64);
    let read = Evidence::Read(Readings {
        artifact: PathBuf::from("/r/local-1-1/local-1-1-1-base/artifact.json"),
        data: b"{}\n".to_vec(),
        outputs: [Some(EXPECT.as_bytes().to_vec()), Some(Vec::new())],
    });
    let red = Leg {
        expect_streams: Some(vec!["stdout"]),
        ..leg(1, "reproduced: on attempt 1", 12.34567, read)
    };
    let green = Leg {
        expect_streams: Some(vec!["stdout"]),
        ..leg(
            0,
            "not reproduced in 1 attempts",
            0.0005,
            Evidence::Read(Readings {
                artifact: PathBuf::from("/r/local-1-1/local-1-1-1-head/artifact.json"),
                data: b"{}\n".to_vec(),
                outputs: [Some(b"ok\n".to_vec()), Some(Vec::new())],
            }),
        )
    };
    let textless = Leg {
        expect_streams: Some(vec![]),
        ..leg(
            1,
            "reproduced: on attempt 1",
            3.0,
            Evidence::Read(Readings {
                artifact: PathBuf::from("/r/local-1-1/local-1-1-1-base/artifact.json"),
                data: b"{}\n".to_vec(),
                outputs: [Some(b"x\n".to_vec()), Some(Vec::new())],
            }),
        )
    };
    let unreadable = leg(
        1,
        "reproduced",
        2.0625,
        Evidence::Unreadable(Text::from("an error")),
    );
    let signal = leg(-9, "", 1.5, Evidence::Absent);
    let partial = leg(
        1,
        "reproduced: on attempt 1",
        4.0,
        Evidence::Read(Readings {
            artifact: PathBuf::from(OsStr::from_bytes(
                b"/r/local-1-1/local-1-1-1-base.\xff/artifact.json",
            )),
            data: b"{}\n".to_vec(),
            outputs: [Some(b"partial\n".to_vec()), None],
        }),
    );
    let no_evidence = format!("the base leg failed but {NO_EVIDENCE}: reproduced: on attempt 1");
    type Row<'a> = (&'a str, Vec<(&'a str, Leg)>, Option<&'a str>, bool, &'a str);
    let rows: [Row; 6] = [
        (
            "proven",
            vec![("base", red), ("head", green)],
            None,
            true,
            PROVEN,
        ),
        (
            "refused without the expected text",
            vec![("base", textless)],
            Some("the test failed on the base without the expected text"),
            true,
            WITHOUT_THE_TEXT,
        ),
        (
            "refused at the base",
            vec![("base", unreadable)],
            Some("the base leg failed but x"),
            false,
            REFUSED_AT_THE_BASE,
        ),
        (
            "refused with standard output alone",
            vec![("base", partial)],
            Some(&no_evidence),
            false,
            PARTIAL,
        ),
        (
            "refused by a signal death",
            vec![("base", signal)],
            Some("exit -9"),
            false,
            SIGNAL_DEATH,
        ),
        (
            "no leg",
            vec![],
            Some("the base leg's tree differs"),
            false,
            NO_LEG,
        ),
    ];
    for (name, legs, reason, release, expected) in rows {
        let reason = reason.map(Text::from);
        let written = record(&Record {
            options: if release { &released } else { &options },
            base: &base,
            head: &head,
            carried: &carried,
            cargo_target_dir: Path::new("/t/red-green/build"),
            scripts: &scripts,
            executable: (name != "refused without the expected text")
                .then_some(executable.as_str()),
            legs: &legs,
            reason: reason.as_ref(),
            command: if release { &released_command } else { &command },
        });
        assert_eq!(written.as_deref(), Ok(expected), "{name}");
    }
}

#[test]
fn a_non_finite_seconds_is_refused() {
    let options = options(TEST, EXPECT);
    let empty = Text::new();
    let legs = [("base", leg(1, "", f64::NAN, Evidence::Absent))];
    let written = record(&Record {
        options: &options,
        base: &empty,
        head: &empty,
        carried: &[],
        cargo_target_dir: Path::new("/t"),
        scripts: &[],
        executable: None,
        legs: &legs,
        reason: None,
        command: &empty,
    });
    assert!(written.is_err());
}
