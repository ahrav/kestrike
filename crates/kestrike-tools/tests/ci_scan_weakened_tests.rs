//! Each case runs `scripts/ci-scan-weakened-tests.sh` in a scratch tree with a `scripts/tool.sh` stand-in to
//! check CI-visible output and exit status.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

const WRAPPER: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../scripts/ci-scan-weakened-tests.sh"
);

static TREES: AtomicUsize = AtomicUsize::new(0);

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
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "kestrike-ci-scan-{name}-{}-{}",
            std::process::id(),
            TREES.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("scripts")).expect("the scratch tree is made");
        fs::create_dir_all(root.join("draws")).expect("the stand-in directory is made");
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

    fn environment(&self) -> Option<String> {
        fs::read_to_string(self.root.join("environment")).ok()
    }

    fn run(&self, env: &[(&str, &str)]) -> Output {
        let _ = fs::remove_file(self.root.join("environment"));
        Command::new("bash")
            .arg(WRAPPER)
            .args(["--base", "HEAD^1"])
            .current_dir(&self.root)
            .env("STAND_IN_ENVIRONMENT", self.root.join("environment"))
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
        (Some(quiet.as_str()), 0, arguments.to_owned(), &[][..]),
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
        assert_eq!(output.status.code(), Some(code), "{launcher:?}");
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
                environment
                    .lines()
                    .all(|line| line.split_once('=').is_none_or(|(_, value)| value != token)),
                "a variable of the launcher holds the token"
            );
            assert!(
                !environment.lines().any(|line| line.starts_with("token=")),
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

/// The wrapper requires a draw of exactly 32 ASCII hexadecimal digits. If the draw fails or yields a
/// malformed token, the wrapper exits with a nonzero status before printing the stop line or running the
/// launcher.
#[test]
fn a_failed_or_malformed_draw_stops_the_wrapper_before_the_scan() {
    let tree = Tree::new("draw");
    tree.launcher(Some(&format!("{RECORDS}exit 0\n")));
    let path = format!(
        "{}:{}",
        tree.root.join("draws").display(),
        std::env::var("PATH").expect("PATH is set")
    );
    for draw in [
        "exit 1\n",
        "printf 'abc\\n'\n",
        "printf '%032d\\n' 0 | tr 0 g\n",
    ] {
        let od = tree.root.join("draws/od");
        fs::write(&od, draw).expect("the stand-in draw is written");
        fs::set_permissions(&od, fs::Permissions::from_mode(0o755)).expect("the draw runs");
        let output = tree.run(&[("PATH", &path)]);
        assert_ne!(output.status.code(), Some(0), "{draw}");
        assert!(output.stdout.is_empty(), "{draw}");
        assert_eq!(tree.environment(), None, "{draw}: the launcher ran");
    }
}
