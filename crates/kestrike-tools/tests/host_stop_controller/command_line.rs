//! The tool's command line through the built binary: the words after `error:` and the exit code of
//! each argument vector. A vector the reader takes reaches the command, which here refuses the
//! missing operator file `a`.

use std::process::{Command, Stdio};

use crate::host_stop_support::{Scratch, tree};

const BINARY: &str = env!("CARGO_BIN_EXE_kestrike-tools");
const MISSING: &str = "host-stop-controller: refused: the operator file cannot be read: No such \
                       file or directory; nothing written";
const CHOICE: &str = "(choose from 'run', 'restore', 'seal')";

/// The rows: the arguments, the exit code, and the last line of standard error after `error: `, or
/// the whole last line where it holds no `error: `; `None` for help, which writes standard output.
fn rows() -> Vec<(&'static [&'static str], u8, Option<String>)> {
    let error = |text: &str| Some(text.to_owned());
    let missing = Some(MISSING.to_owned());
    vec![
        (
            &[],
            2,
            error("the following arguments are required: command"),
        ),
        (
            &["x"],
            2,
            error(&format!("argument command: invalid choice: 'x' {CHOICE}")),
        ),
        (
            &["--"],
            2,
            error("the following arguments are required: command"),
        ),
        (
            &["--", "run"],
            2,
            error("the following arguments are required: --operator, --package, --evidence"),
        ),
        (
            &[
                "--",
                "run",
                "--operator",
                "a",
                "--package",
                "b",
                "--evidence",
                "c",
            ],
            2,
            missing.clone(),
        ),
        (
            &["--", "-x", "run"],
            2,
            error(&format!("argument command: invalid choice: '-x' {CHOICE}")),
        ),
        (
            &["--", "--"],
            2,
            error(&format!("argument command: invalid choice: '--' {CHOICE}")),
        ),
        (
            &[
                "--bogus",
                "--",
                "run",
                "--operator",
                "a",
                "--package",
                "b",
                "--evidence",
                "c",
            ],
            2,
            error("unrecognized arguments: --bogus"),
        ),
        (
            &["ru"],
            2,
            error(&format!("argument command: invalid choice: 'ru' {CHOICE}")),
        ),
        (
            &["-1"],
            2,
            error(&format!("argument command: invalid choice: '-1' {CHOICE}")),
        ),
        (
            &["-x y"],
            2,
            error(&format!(
                "argument command: invalid choice: '-x y' {CHOICE}"
            )),
        ),
        (
            &["--operator", "x"],
            2,
            error(&format!("argument command: invalid choice: 'x' {CHOICE}")),
        ),
        (&["-h"], 0, None),
        (&["--he"], 0, None),
        (&["-hh"], 0, None),
        (&["-h", "run", "x"], 0, None),
        (&["run", "--bogus", "-h"], 0, None),
        (
            &["-hx"],
            2,
            error("argument -h/--help: ignored explicit argument 'x'"),
        ),
        (
            &["--help=x"],
            2,
            error("argument -h/--help: ignored explicit argument 'x'"),
        ),
        (
            &["--=x", "run"],
            2,
            error("argument -h/--help: ignored explicit argument 'x'"),
        ),
        (
            &["run", "-h=x"],
            2,
            error("argument -h/--help: ignored explicit argument 'x'"),
        ),
        (
            &["run"],
            2,
            error("the following arguments are required: --operator, --package, --evidence"),
        ),
        (
            &["restore"],
            2,
            error("the following arguments are required: --operator, --evidence"),
        ),
        (
            &["seal", "--evidence", "b"],
            2,
            error("the following arguments are required: --operator"),
        ),
        (
            &["-x", "run"],
            2,
            error("the following arguments are required: --operator, --package, --evidence"),
        ),
        (
            &["run", "--operator"],
            2,
            error("argument --operator: expected one argument"),
        ),
        (
            &["run", "--operator", "-h"],
            2,
            error("argument --operator: expected one argument"),
        ),
        (
            &["run", "--operator", "--", "x"],
            2,
            error("argument --operator: expected one argument"),
        ),
        (
            &[
                "restore",
                "--operator",
                "a",
                "--evidence",
                "b",
                "--reviewed",
            ],
            2,
            error("argument --reviewed: expected one argument"),
        ),
        (
            &["run", "--=x"],
            2,
            error("ambiguous option: --=x could match --help, --operator, --package, --evidence"),
        ),
        (
            &[
                "--bogus",
                "run",
                "--operator",
                "a",
                "--package",
                "b",
                "--evidence",
                "c",
                "--zz",
                "y",
            ],
            2,
            error("unrecognized arguments: --bogus --zz y"),
        ),
        (
            &[
                "run",
                "--operator",
                "a",
                "--package",
                "b",
                "--evidence",
                "c",
                "--",
                "x",
            ],
            2,
            error("unrecognized arguments: -- x"),
        ),
        (
            &[
                "seal",
                "--operator",
                "a",
                "--evidence",
                "b",
                "--reviewed",
                "c",
            ],
            2,
            error("unrecognized arguments: --reviewed c"),
        ),
        (
            &["run", "--op", "a", "--pa", "b", "--ev", "c"],
            2,
            missing.clone(),
        ),
        (
            &["run", "--operator=a", "--pack=b", "--e", "c"],
            2,
            missing.clone(),
        ),
        (
            &[
                "run",
                "--operator",
                "z",
                "--operator",
                "a",
                "--package",
                "b",
                "--evidence",
                "c",
            ],
            2,
            missing.clone(),
        ),
        (
            &["restore", "--re", "x", "--operator", "a", "--evidence", "b"],
            2,
            missing.clone(),
        ),
        (&["seal", "--operator=a", "--evidence="], 2, missing),
        (
            &["seal", "--operator", "-٣", "--evidence", "e"],
            2,
            error("argument --operator: expected one argument"),
        ),
        (
            &[
                "run",
                "--package",
                "-٣",
                "--operator",
                "a",
                "--evidence",
                "e",
            ],
            2,
            error("argument --package: expected one argument"),
        ),
        (
            &["-hx=y"],
            2,
            error("argument -h/--help: ignored explicit argument 'x=y'"),
        ),
        (
            &["-hx=1", "-h"],
            2,
            error("argument -h/--help: ignored explicit argument 'x=1'"),
        ),
        (
            &["-hh=x"],
            2,
            error("argument -h/--help: ignored explicit argument '=x'"),
        ),
        (
            &[
                "-hx=y",
                "run",
                "--operator",
                "a",
                "--package",
                "b",
                "--evidence",
                "c",
            ],
            2,
            error("argument -h/--help: ignored explicit argument 'x=y'"),
        ),
    ]
}

/// Each row's exit code and last line of standard error; help writes the controller's contract to
/// standard output and nothing to standard error. The scratch directory holds an operator file `z`
/// of `{}`, so the row that names `z` before `a` shows that the last `--operator` stands.
#[test]
fn each_argument_vector_reads_as_the_controllers_parser_read_it() {
    super::started::apart(
        module_path!(),
        "each_argument_vector_reads_as_the_controllers_parser_read_it",
        || {
            let scratch = Scratch::new("command-line");
            scratch.write("z", b"{}\n");
            for (args, code, last) in rows() {
                let ran = Command::new(BINARY)
                    .arg(tree())
                    .arg("host-stop-controller")
                    .args(args)
                    .current_dir(&scratch.0)
                    .env_clear()
                    .env("PATH", &scratch.0)
                    .stdin(Stdio::null())
                    .output()
                    .expect("the binary runs");
                assert_eq!(ran.status.code(), Some(i32::from(code)), "{args:?} {ran:?}");
                let (stdout, stderr) = (
                    String::from_utf8(ran.stdout).expect("UTF-8"),
                    String::from_utf8(ran.stderr).expect("UTF-8"),
                );
                match last {
                    None => {
                        assert_eq!(
                            stdout,
                            kestrike_tools::tools::host_stop_controller::HELP,
                            "{args:?}"
                        );
                        assert_eq!(stderr, "", "{args:?}");
                    }
                    Some(last) => {
                        let line = stderr.lines().last().unwrap_or("");
                        let words = line.split_once("error: ").map_or(line, |(_, words)| words);
                        assert_eq!(words, last, "{args:?}");
                        assert_eq!(stdout, "", "{args:?}");
                    }
                }
            }
        },
    );
}

/// Help that standard output refuses exits 120 with one line on standard error that names the
/// stream and the error; the same start with a pipe as standard output exits 0 with the help.
#[test]
fn help_that_standard_output_refuses_exits_120_and_names_the_stream() {
    super::started::apart(
        module_path!(),
        "help_that_standard_output_refuses_exits_120_and_names_the_stream",
        || {
            let scratch = Scratch::new("help-refused");
            let start = |stdout: Stdio| {
                Command::new(BINARY)
                    .arg(tree())
                    .args(["host-stop-controller", "-h"])
                    .current_dir(&scratch.0)
                    .env_clear()
                    .env("PATH", &scratch.0)
                    .stdin(Stdio::null())
                    .stdout(stdout)
                    .stderr(Stdio::piped())
                    .output()
                    .expect("the binary runs")
            };
            let full = std::fs::File::options()
                .write(true)
                .open("/dev/full")
                .expect("/dev/full opens for writing");
            let refused = start(Stdio::from(full));
            assert_eq!(refused.status.code(), Some(120), "{refused:?}");
            assert_eq!(
                String::from_utf8(refused.stderr).expect("UTF-8"),
                "host-stop-controller: standard output: No space left on device (os error 28)\n"
            );
            let taken = start(Stdio::piped());
            assert_eq!(taken.status.code(), Some(0), "{taken:?}");
            assert_eq!(
                String::from_utf8(taken.stdout).expect("UTF-8"),
                kestrike_tools::tools::host_stop_controller::HELP
            );
            assert_eq!(taken.stderr, b"");
        },
    );
}

/// A refusal of the arguments whose line standard error refuses exits 120; the same start with a
/// pipe as standard error exits 2 with the refusal's line.
#[test]
fn a_refusal_of_the_arguments_that_standard_error_refuses_exits_120() {
    super::started::apart(
        module_path!(),
        "a_refusal_of_the_arguments_that_standard_error_refuses_exits_120",
        || {
            let scratch = Scratch::new("refusal-refused");
            let start = |stderr: Stdio| {
                Command::new(BINARY)
                    .arg(tree())
                    .args(["host-stop-controller", "bogus"])
                    .current_dir(&scratch.0)
                    .env_clear()
                    .env("PATH", &scratch.0)
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(stderr)
                    .output()
                    .expect("the binary runs")
            };
            let full = std::fs::File::options()
                .write(true)
                .open("/dev/full")
                .expect("/dev/full opens for writing");
            let refused = start(Stdio::from(full));
            assert_eq!(refused.status.code(), Some(120), "{refused:?}");
            assert_eq!(refused.stdout, b"");
            let taken = start(Stdio::piped());
            assert_eq!(taken.status.code(), Some(2), "{taken:?}");
            let line = String::from_utf8(taken.stderr).expect("UTF-8");
            assert!(line.contains("invalid choice: 'bogus'"), "{line}");
            assert_eq!(taken.stdout, b"");
        },
    );
}

/// An argument that is no UTF-8 shows in the invalid choice and among the leftover arguments as
/// `repr` writes a lone surrogate, `'\\udcff'`.
#[test]
fn an_argument_of_no_utf_8_form_shows_as_its_surrogate_escape() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    super::started::apart(
        module_path!(),
        "an_argument_of_no_utf_8_form_shows_as_its_surrogate_escape",
        || {
            let byte = OsString::from_vec(vec![0xff]);
            let leftover: Vec<OsString> = [
                "run",
                "--operator",
                "a",
                "--package",
                "b",
                "--evidence",
                "c",
            ]
            .iter()
            .map(OsString::from)
            .chain([byte.clone()])
            .collect();
            for (args, last) in [
                (
                    vec![byte],
                    format!("argument command: invalid choice: '\\udcff' {CHOICE}"),
                ),
                (leftover, "unrecognized arguments: \\udcff".to_owned()),
            ] {
                let ran = Command::new(BINARY)
                    .arg(tree())
                    .arg("host-stop-controller")
                    .args(&args)
                    .env_clear()
                    .stdin(Stdio::null())
                    .output()
                    .expect("the binary runs");
                assert_eq!(ran.status.code(), Some(2), "{ran:?}");
                let stderr = String::from_utf8(ran.stderr).expect("UTF-8");
                let line = stderr.lines().last().unwrap_or("");
                assert_eq!(
                    line.split_once("error: ").map(|(_, w)| w),
                    Some(last.as_str())
                );
            }
        },
    );
}

/// The reader puts each value in its field of the command: the last of a repeated option, a value
/// given by a prefix or after `=`, and `--reviewed` of `restore` where it is given and `None` where
/// it is not. A value `--` given after `=`, by a whole name or a prefix, is the path `--`, and a
/// later occurrence of the option replaces it.
#[test]
fn each_value_lands_in_its_field_of_the_command() {
    use std::ffi::OsString;
    use std::path::PathBuf;

    use kestrike_tools::args::Parsed;
    use kestrike_tools::host_stop_controller::Command as Read;
    use kestrike_tools::tools::host_stop_controller::read;

    let args = |words: &[&str]| -> Vec<OsString> { words.iter().map(OsString::from).collect() };
    let rows = [
        (
            args(&[
                "run",
                "--op",
                "o1",
                "--operator=o",
                "--evidence",
                "e",
                "--pa",
                "p",
            ]),
            Read::Run {
                operator: PathBuf::from("o"),
                package: PathBuf::from("p"),
                evidence: OsString::from("e"),
            },
        ),
        (
            args(&["restore", "--re", "r", "--evidence=e", "--operator", "o"]),
            Read::Restore {
                operator: PathBuf::from("o"),
                evidence: OsString::from("e"),
                reviewed: Some(PathBuf::from("r")),
            },
        ),
        (
            args(&["restore", "--evidence", "e", "--operator", "o"]),
            Read::Restore {
                operator: PathBuf::from("o"),
                evidence: OsString::from("e"),
                reviewed: None,
            },
        ),
        (
            args(&["seal", "--ev", "e", "--o", "o"]),
            Read::Seal {
                operator: PathBuf::from("o"),
                evidence: OsString::from("e"),
            },
        ),
        (
            args(&["run", "--operator=--", "--package=--", "--e=--"]),
            Read::Run {
                operator: PathBuf::from("--"),
                package: PathBuf::from("--"),
                evidence: OsString::from("--"),
            },
        ),
        (
            args(&["restore", "--operator=--", "--evidence=--", "--reviewed=--"]),
            Read::Restore {
                operator: PathBuf::from("--"),
                evidence: OsString::from("--"),
                reviewed: Some(PathBuf::from("--")),
            },
        ),
        (
            args(&[
                "seal",
                "--operator=--",
                "--operator",
                "a",
                "--evidence",
                "e",
            ]),
            Read::Seal {
                operator: PathBuf::from("a"),
                evidence: OsString::from("e"),
            },
        ),
    ];
    for (given, expected) in rows {
        assert_eq!(read(&given), Parsed::Run(expected), "{given:?}");
    }
}
