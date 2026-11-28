//! Each case runs `scripts/ci-scan-weakened-tests.sh` in a scratch tree with a `scripts/tool.sh` stand-in to
//! check CI-visible output and exit status.

use std::fs::{self, DirBuilder};
use std::io::Write;
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

const WRAPPER: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../scripts/ci-scan-weakened-tests.sh"
);

struct Tree {
    root: PathBuf,
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

impl Tree {
    fn new(name: &str) -> Self {
        let scratch = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
        fs::create_dir_all(&scratch).expect("the scratch root is made");
        let root = (0..1000)
            .map(|at| {
                scratch.join(format!(
                    "kestrike-ci-scan-{name}-{}-{at}",
                    std::process::id()
                ))
            })
            .find(|root| match DirBuilder::new().mode(0o700).create(root) {
                Ok(()) => true,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
                Err(error) => panic!("{}: {error}", root.display()),
            })
            .expect("a new scratch directory is made");
        fs::create_dir(root.join("scripts")).expect("the scratch tree is made");
        fs::create_dir(root.join("draws")).expect("the stand-in directory is made");
        Self { root }
    }

    fn launcher(&self, text: Option<&str>) {
        let path = self.root.join("scripts/tool.sh");
        match text {
            Some(text) => fs::write(path, text).expect("the stand-in is written"),
            None => {
                let _ = fs::remove_file(path);
            }
        }
    }

    /// `execve` refuses a file that any process holds open for writing with `ETXTBSY`, and another test
    /// thread's child inherits the open writer at `fork` even when `FD_CLOEXEC` is set.
    fn draw(&self, text: &str) {
        let mut writer = Command::new("sh")
            .args(["-c", r#"cat > "$1" && chmod 755 "$1""#, "sh"])
            .arg(self.root.join("draws/od"))
            .stdin(Stdio::piped())
            .spawn()
            .expect("the stand-in's writer starts");
        writer
            .stdin
            .take()
            .expect("the writer's standard input is a pipe")
            .write_all(text.as_bytes())
            .expect("the stand-in's text reaches the writer");
        let status = writer.wait().expect("the stand-in's writer is reaped");
        assert!(status.success(), "the stand-in draw is written: {status}");
    }

    fn environment(&self) -> Option<Vec<u8>> {
        match fs::read(self.root.join("environment")) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => panic!("the capture reads: {error}"),
        }
    }

    fn run(&self, env: &[(&str, &str)]) -> Output {
        let _ = fs::remove_file(self.root.join("environment"));
        Command::new("bash")
            .arg(WRAPPER)
            .args(["--base", "HEAD^1"])
            .current_dir(&self.root)
            .env("STAND_IN_ENVIRONMENT", self.root.join("environment"))
            .env("LC_ALL", "C")
            .envs(env.iter().copied())
            .output()
            .expect("bash starts")
    }
}

fn framed(printed: &str) -> (String, String) {
    let (stop, rest) = printed
        .split_once('\n')
        .expect("the wrapper prints a stop line");
    let token = stop
        .strip_prefix("::stop-commands::")
        .expect("the first line stops command processing");
    assert!(
        token.len() == 32 && token.bytes().all(|b| b.is_ascii_hexdigit()),
        "{token}"
    );
    let middle = rest
        .strip_suffix(&format!("::{token}::\n"))
        .expect("the last line resumes command processing with the same token");
    assert!(!middle.contains(token), "{middle}");
    (token.to_owned(), middle.to_owned())
}

const RECORDS: &str = "env > \"$STAND_IN_ENVIRONMENT\"\nprintf 'arguments: %s\\n' \"$*\"\n";

/// The wrapper prints the stop line first and the resume line with the same token last, with the launcher's
/// lines of both streams between them in the order written, and exits with the launcher's status. One
/// launcher writes `##[error]` to stdout and `##[warning]` to stderr, then exits with status 1; the others
/// exit 0, 2 and 127, and one is absent. No variable of the launcher's environment holds the token, a `token`
/// variable exported to the wrapper included, and each run draws a new token.
#[test]
fn the_wrapper_stops_workflow_commands_around_the_scan_and_keeps_its_status() {
    let tree = Tree::new("status");
    let legacy = format!(
        "{RECORDS}printf '##[error]a report line\\n'\nprintf '##[warning]a hint line\\n' >&2\nexit 1\n"
    );
    let quiet = format!("{RECORDS}exit 0\n");
    let refused = format!("{RECORDS}printf 'scan-weakened-tests: a refusal\\n' >&2\nexit 2\n");
    let failed = "printf 'tool.sh: the build of kestrike-tools failed\\n' >&2\nexit 127\n";
    let arguments = "arguments: scan-weakened-tests --base HEAD^1\n";
    let mut tokens = Vec::new();
    for (launcher, code, expected, env) in [
        (
            Some(legacy.as_str()),
            1,
            format!("{arguments}##[error]a report line\n##[warning]a hint line\n"),
            &[("token", "inherited")][..],
        ),
        (
            Some(quiet.as_str()),
            0,
            arguments.to_owned(),
            &[("SHELLOPTS", "allexport")][..],
        ),
        (
            Some(refused.as_str()),
            2,
            format!("{arguments}scan-weakened-tests: a refusal\n"),
            &[][..],
        ),
        (
            Some(failed),
            127,
            "tool.sh: the build of kestrike-tools failed\n".to_owned(),
            &[][..],
        ),
        (None, 127, String::new(), &[][..]),
    ] {
        tree.launcher(launcher);
        let output = tree.run(env);
        assert_eq!(output.status.code(), Some(code), "{launcher:?} {env:?}");
        assert!(
            output.stderr.is_empty(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let printed = String::from_utf8(output.stdout).expect("the wrapper writes UTF-8");
        let (token, middle) = framed(&printed);
        if launcher.is_some() {
            assert_eq!(middle, expected);
        } else {
            assert!(middle.ends_with("No such file or directory\n"), "{middle}");
        }
        if launcher.is_some_and(|text| text.starts_with(RECORDS)) {
            let environment = tree.environment().expect("the stand-in ran");
            assert!(
                !environment
                    .windows(token.len())
                    .any(|window| window == token.as_bytes()),
                "the launcher's environment holds the token"
            );
            assert!(
                !environment
                    .split(|&byte| byte == b'\n')
                    .any(|line| line.starts_with(b"token=")),
                "a token variable reached the launcher"
            );
        }
        tokens.push(token);
    }
    let mut distinct = tokens.clone();
    distinct.sort();
    distinct.dedup();
    assert_eq!(distinct.len(), tokens.len(), "{tokens:?}");
}

const MALFORMED: &str =
    "ci-scan-weakened-tests.sh: the random source gave no token of 32 hex digits\n";

#[test]
fn a_failed_or_malformed_draw_stops_the_wrapper_before_the_scan() {
    let tree = Tree::new("draw");
    tree.launcher(Some(&format!("{RECORDS}exit 0\n")));
    let path = format!("./draws:{}", std::env::var("PATH").expect("PATH is set"));
    let marker = tree.root.join("draw");
    let marker_path = marker.to_str().expect("the scratch path is UTF-8");
    for (row, (draw, code, complaint)) in [
        ("exit 1\n", 1, ""),
        ("printf '%032d\\n' 0\nexit 3\n", 3, ""),
        ("printf 'abc\\n'\n", 1, MALFORMED),
        ("printf '%032d\\n' 0 | tr 0 g\n", 1, MALFORMED),
    ]
    .into_iter()
    .enumerate()
    {
        tree.draw(&format!("printf '{row}' > \"$STAND_IN_DRAW\"\n{draw}"));
        let _ = fs::remove_file(&marker);
        let output = tree.run(&[("PATH", &path), ("STAND_IN_DRAW", marker_path)]);
        assert_eq!(
            fs::read_to_string(&marker).ok(),
            Some(row.to_string()),
            "{draw}: the row's draw did not run"
        );
        assert_eq!(output.status.code(), Some(code), "{draw}");
        assert_eq!(String::from_utf8_lossy(&output.stderr), complaint, "{draw}");
        assert!(output.stdout.is_empty(), "{draw}");
        assert_eq!(tree.environment(), None, "{draw}: the launcher ran");
    }
}
