use std::ffi::OsString;
use std::fs::{self, DirBuilder};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const TOOL: &str = env!("CARGO_BIN_EXE_kestrike-tools");
const INVENTORY: &str = "scripts/test-inventory.json";
const KEY: &str = "ignore-existing:src/a_tests.rs";
const MIRI_IGNORE: &str = concat!("#[cfg_attr(miri, ", "ignore)]");

fn test_fn(name: &str) -> String {
    format!("#[test]\nfn {name}() {{\n    assert!(true);\n}}\n")
}

#[derive(Clone, Debug)]
enum J {
    O(Vec<(String, J)>),
    A(Vec<J>),
    S(String),
    N(i64),
    B(bool),
}

fn quoted(text: &str) -> String {
    let mut out = String::from("\"");
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            ' '..='~' => out.push(c),
            _ => out.push_str(&format!("\\u{:04x}", u32::from(c))),
        }
    }
    out.push('"');
    out
}

impl J {
    fn dump(&self, indent: Option<usize>) -> String {
        let (open, close, items): (char, char, Vec<String>) = match self {
            J::O(members) => {
                let items = members.iter().map(|(key, value)| {
                    format!(
                        "{}: {}",
                        quoted(key),
                        value.dump(indent.map(|depth| depth + 1))
                    )
                });
                ('{', '}', items.collect())
            }
            J::A(items) => {
                let items = items
                    .iter()
                    .map(|item| item.dump(indent.map(|depth| depth + 1)));
                ('[', ']', items.collect())
            }
            J::S(text) => return quoted(text),
            J::N(number) => return number.to_string(),
            J::B(flag) => return flag.to_string(),
        };
        match indent {
            _ if items.is_empty() => format!("{open}{close}"),
            None => format!("{open}{}{close}", items.join(", ")),
            Some(depth) => {
                let inner = "  ".repeat(depth + 1);
                let body = items.join(&format!(",\n{inner}"));
                format!("{open}\n{inner}{body}\n{}{close}", "  ".repeat(depth))
            }
        }
    }

    fn with(&self, key: &str, value: J) -> J {
        let J::O(members) = self else {
            panic!("a row is an object");
        };
        let mut members = members.clone();
        match members.iter_mut().find(|(name, _)| name == key) {
            Some((_, slot)) => *slot = value,
            None => members.push((key.to_owned(), value)),
        }
        J::O(members)
    }

    fn without(&self, key: &str) -> J {
        let J::O(members) = self else {
            panic!("a row is an object");
        };
        J::O(
            members
                .iter()
                .filter(|(name, _)| name != key)
                .cloned()
                .collect(),
        )
    }
}

fn s(text: &str) -> J {
    J::S(text.to_owned())
}

fn object(members: &[(&str, J)]) -> J {
    J::O(
        members
            .iter()
            .map(|(key, value)| ((*key).to_owned(), value.clone()))
            .collect(),
    )
}

fn rows() -> [J; 3] {
    [
        object(&[
            ("id", s("a")),
            ("seeds", J::N(12)),
            ("bound", s("^a: depth: 6 actions 40$")),
        ]),
        object(&[("id", s("b")), ("seeds", J::N(4))]),
        object(&[
            ("id", s("f")),
            ("seconds", J::N(10)),
            ("executions", J::N(3)),
            ("member", s("^f: cycles 9$")),
            ("deadline_seconds", J::N(30)),
        ]),
    ]
}

fn document(rows: &[J], drain: i64) -> J {
    object(&[
        ("miri_sweep", object(&[("seeds", J::N(64))])),
        ("qemu", object(&[("member_drain_seconds", J::N(drain))])),
        (
            "qualified",
            object(&[("lane", object(&[("rows", J::A(rows.to_vec()))]))]),
        ),
    ])
}

fn inventory(rows: &[J]) -> String {
    document(rows, 10).dump(Some(0)) + "\n"
}

struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
    bytes: Vec<u8>,
}

impl From<Output> for Run {
    fn from(output: Output) -> Self {
        Self {
            code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            bytes: output.stdout,
        }
    }
}

impl Run {
    fn outcome(&self) -> (Option<i32>, &str) {
        (self.code, &self.stdout)
    }

    fn lines(&self) -> Vec<&str> {
        self.stdout.lines().collect()
    }
}

fn one_line(text: &str) -> bool {
    text.strip_suffix('\n')
        .is_some_and(|line| !line.contains(['\n', '\r']))
}

fn assert_blocks(run: &Run, line: &str) {
    assert_eq!(run.code, Some(1), "{}{}", run.stdout, run.stderr);
    assert!(
        run.stdout.contains(&format!("blocks {line}\n")),
        "{}",
        run.stdout
    );
}

struct Repo {
    temp: PathBuf,
    repo: PathBuf,
    env: Vec<(OsString, OsString)>,
    base: String,
}

impl Drop for Repo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.temp);
    }
}

impl Repo {
    fn new(name: &str) -> Self {
        let root = Path::new(env!("CARGO_TARGET_TMPDIR"));
        fs::create_dir_all(root).expect("the scratch root is made");
        let temp = (0..1000)
            .map(|at| root.join(format!("kestrike-scan-{name}-{}-{at}", std::process::id())))
            .find(|temp| DirBuilder::new().mode(0o700).create(temp).is_ok())
            .expect("a new scratch directory is made");
        let repo = temp.join("repo");
        fs::create_dir(&repo).expect("the repository directory is made");
        let mut env: Vec<(OsString, OsString)> = std::env::vars_os()
            .filter(|(key, _)| {
                let key = key.to_string_lossy();
                !key.starts_with("GIT_") && !key.starts_with("GITHUB_")
            })
            .collect();
        let global = temp.join("global");
        for (key, value) in [
            ("GIT_CONFIG_NOSYSTEM", OsString::from("1")),
            ("GIT_CONFIG_GLOBAL", global.into_os_string()),
            ("GIT_CEILING_DIRECTORIES", temp.clone().into_os_string()),
            ("GIT_AUTHOR_NAME", OsString::from("t")),
            ("GIT_AUTHOR_EMAIL", OsString::from("t@example.com")),
            ("GIT_COMMITTER_NAME", OsString::from("t")),
            ("GIT_COMMITTER_EMAIL", OsString::from("t@example.com")),
        ] {
            env.push((OsString::from(key), value));
        }
        let mut repo = Self {
            temp,
            repo,
            env,
            base: String::new(),
        };
        repo.git(&["init", "-q", "-b", "main"]);
        let ignored = format!("#[ignore = \"slow\"]\n{}", test_fn("old_name"));
        let tests = test_fn("first") + &test_fn("second");
        repo.base = repo.commit(
            &[
                ("src/a_tests.rs", &tests),
                ("src/model.rs", MODEL),
                ("src/ignored_tests.rs", &ignored),
                ("src/gone_tests.rs", &test_fn("gone")),
                (INVENTORY, &inventory(&rows())),
                (
                    ".github/workflows/agent-checks.yml",
                    "    timeout-minutes: 15\n    run: exec timeout --kill-after=30s 5m make\n",
                ),
                (
                    "scripts/rust-lane.sh",
                    "  step check deadline 25m cargo check\n",
                ),
            ],
            "change",
            &[],
        );
        repo
    }

    fn command(&self, program: &str) -> Command {
        let mut command = Command::new(program);
        command
            .env_clear()
            .envs(self.env.iter().cloned())
            .current_dir(&self.repo);
        command
    }

    fn git(&self, args: &[&str]) -> String {
        let output = self.command("git").args(args).output().expect("git starts");
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .expect("git writes UTF-8")
            .trim()
            .to_owned()
    }

    fn write(&self, name: &str, content: &[u8]) {
        let path = self.repo.join(name);
        fs::create_dir_all(path.parent().expect("a file has a parent"))
            .expect("the parent is made");
        fs::write(path, content).expect("the file is written");
    }

    fn commit(&self, files: &[(&str, &str)], message: &str, deleted: &[&str]) -> String {
        for (name, content) in files {
            self.write(name, content.as_bytes());
            self.git(&["add", "--", name]);
        }
        for name in deleted {
            self.git(&["rm", "-q", "--", name]);
        }
        self.git(&[
            "commit",
            "-q",
            "--allow-empty",
            "--cleanup=verbatim",
            "-m",
            message,
        ]);
        self.git(&["rev-parse", "HEAD"])
    }

    fn change(&self, files: &[(&str, &str)]) -> String {
        self.commit(files, "change", &[])
    }

    fn edit(&self, path: &str, old: &str, new: &str) -> String {
        let text = fs::read_to_string(self.repo.join(path)).expect("the file reads");
        text.replace(old, new)
    }

    fn reset(&self, rev: &str) {
        self.git(&["reset", "-q", "--hard", rev]);
    }

    fn tool(&self, args: &[&str], env: &[(&str, &str)], cwd: Option<&Path>) -> Command {
        let mut command = self.command(TOOL);
        command
            .args([".", "scan-weakened-tests"])
            .args(args)
            .envs(env.iter().copied())
            .current_dir(cwd.unwrap_or(&self.repo));
        command
    }

    fn scan_with(&self, args: &[&str], env: &[(&str, &str)], cwd: Option<&Path>) -> Run {
        Run::from(self.tool(args, env, cwd).output().expect("the tool starts"))
    }

    fn scan(&self, args: &[&str]) -> Run {
        self.scan_with(args, &[], None)
    }

    fn scan_env(&self, args: &[&str], env: &[(&str, &str)]) -> Run {
        self.scan_with(args, env, None)
    }

    fn scan_head(&self, head: &str) -> Run {
        self.scan(&["--base", &self.base, "--head", head])
    }

    fn scan_parent(&self, head: &str) -> Run {
        self.scan(&["--base", &format!("{head}^"), "--head", head])
    }

    fn ignore_second(&self, message: &str) -> String {
        let text = self.edit(
            "src/a_tests.rs",
            "#[test]\nfn second",
            "#[test]\n#[ignore]\nfn second",
        );
        self.commit(&[("src/a_tests.rs", &text)], message, &[])
    }

    fn link(&self, path: &str, target: &str, message: &str) -> String {
        let mut child = self
            .command("git")
            .args(["hash-object", "-w", "--stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("git starts");
        use std::io::Write;
        child
            .stdin
            .take()
            .expect("the input is piped")
            .write_all(target.as_bytes())
            .expect("the target is written");
        let output = child.wait_with_output().expect("git exits");
        let object = String::from_utf8(output.stdout).expect("an object name is UTF-8");
        self.git(&[
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("120000,{},{path}", object.trim()),
        ]);
        if !message.is_empty() {
            self.git(&["commit", "-q", "-m", message]);
        }
        self.git(&["rev-parse", "HEAD"])
    }
}

const MODEL: &str = "    builder.preemption_bound = Some(3);\n    builder.max_branches = 10_000;\n\
                     const SEEDS: u64 = 48;\nconst ROOTS: [u64; 3] = [1, 2, 3];\n\
                     const MOD_ROOTS: [&str; 4] = [\"a\", \"b\", \"c\", \"d\"];\n\
                     const CASE_SEEDS: usize = 9;\nconst S19_ROOTS: [u32; 3] = [\n\
                     const PREEMPTION_BOUND: usize = 9;\n\
                     \x20   builder.preemption_bound = Some(PREEMPTION_BOUND);\n";

#[test]
fn an_existing_test_that_gains_an_ignore_blocks() {
    let repo = Repo::new("gains");
    for attribute in ["#[ignore = \"slow\"]", MIRI_IGNORE] {
        let text = repo.edit(
            "src/a_tests.rs",
            "#[test]\nfn second",
            &format!("#[test]\n{attribute}\nfn second"),
        );
        let head = repo.change(&[("src/a_tests.rs", &text)]);
        assert_blocks(
            &repo.scan_head(&head),
            &format!("{KEY} second: not ignored -> {attribute}"),
        );
        repo.reset(&repo.base);
    }
}

#[test]
fn a_lowered_inventory_budget_blocks_by_row_id_while_rows_reorder() {
    let repo = Repo::new("reorder-blocks");
    let [a, b, f] = rows();
    let head = repo.change(&[(INVENTORY, &inventory(&[b.with("seeds", J::N(3)), f, a]))]);
    let run = repo.scan_head(&head);
    assert_blocks(
        &run,
        &format!("budget-lowered:{INVENTORY} qualified.lane.rows[b].seeds: 4 -> 3"),
    );
    assert_eq!(run.stdout.matches('\n').count(), 1, "{}", run.stdout);
}

#[test]
fn a_reorder_with_no_value_change_is_no_finding() {
    let repo = Repo::new("reorder");
    let [a, b, f] = rows();
    let head = repo.change(&[(INVENTORY, &inventory(&[f, b, a]))]);
    let run = repo.scan_head(&head);
    assert_eq!(run.outcome(), (Some(0), ""), "{}", run.stderr);
}

#[test]
fn a_lowered_count_in_a_bound_text_or_the_miri_sweep_blocks() {
    let repo = Repo::new("bound-text");
    let [a, b, f] = rows();
    let cases = [
        (
            inventory(&[
                a.with("bound", s("^a: depth: 5 actions 40$")),
                b.clone(),
                f.clone(),
            ]),
            "qualified.lane.rows[a].bound depth: 6 -> 5",
        ),
        (
            inventory(&[
                a.with("bound", s("^a: depth: 6 actions 39$")),
                b.clone(),
                f.clone(),
            ]),
            "qualified.lane.rows[a].bound actions: 40 -> 39",
        ),
        (
            inventory(&[a.clone(), b.clone(), f.with("member", s("^f: cycles 8$"))]),
            "qualified.lane.rows[f].member cycles: 9 -> 8",
        ),
        (
            inventory(&[a.clone(), b.clone(), f.with("seconds", J::N(9))]),
            "qualified.lane.rows[f].seconds: 10 -> 9",
        ),
        (
            inventory(&[a.clone(), b.clone(), f.with("executions", J::N(2))]),
            "qualified.lane.rows[f].executions: 3 -> 2",
        ),
        (
            inventory(&[a.without("seeds"), b.clone(), f.clone()]),
            "qualified.lane.rows[a].seeds: 12 -> absent",
        ),
        (
            inventory(&rows()).replace("\"seeds\": 64", "\"seeds\": 32"),
            "miri_sweep.seeds: 64 -> 32",
        ),
    ];
    for (text, line) in cases {
        let head = repo.change(&[(INVENTORY, &text)]);
        assert_blocks(
            &repo.scan_head(&head),
            &format!("budget-lowered:{INVENTORY} {line}"),
        );
        repo.reset(&repo.base);
    }
}

#[test]
fn each_lowered_rust_budget_blocks() {
    let repo = Repo::new("rust-budgets");
    let cases = [
        ("Some(3)", "Some(2)", "preemption_bound at line 1: 3 -> 2"),
        ("10_000;", "9_999;", "max_branches at line 2: 10000 -> 9999"),
        (
            "SEEDS: u64 = 48",
            "SEEDS: u64 = 47",
            "SEEDS at line 3: 48 -> 47",
        ),
        (
            "[u64; 3] = [1, 2, 3]",
            "[u64; 2] = [1, 2]",
            "ROOTS at line 4: 3 -> 2",
        ),
        (
            "CASE_SEEDS: usize = 9",
            "CASE_SEEDS: usize = 8",
            "CASE_SEEDS at line 6: 9 -> 8",
        ),
        (
            "[u32; 3] = [\n",
            "[u32; 2] = [\n",
            "S19_ROOTS at line 7: 3 -> 2",
        ),
        (
            "PREEMPTION_BOUND: usize = 9",
            "PREEMPTION_BOUND: usize = 8",
            "PREEMPTION_BOUND at line 8: 9 -> 8",
        ),
        (
            "Some(PREEMPTION_BOUND)",
            "Some(8)",
            "preemption_bound at line 9: 9 -> 8",
        ),
        (
            "Some(3);\n",
            "Some(LOW);\nconst LOW: usize = 1;\n",
            "preemption_bound at line 1: 3 -> 1",
        ),
        (
            "const PREEMPTION_BOUND: usize = 9;\n    builder.preemption_bound = Some(PREEMPTION_BOUND);",
            "    builder.preemption_bound = Some(8);",
            "preemption_bound at line 8: 9 -> 8",
        ),
    ];
    for (old, new, line) in cases {
        let head = repo.change(&[("src/model.rs", &repo.edit("src/model.rs", old, new))]);
        assert_blocks(
            &repo.scan_head(&head),
            &format!("budget-lowered:src/model.rs {line}"),
        );
        repo.reset(&repo.base);
    }
}

#[test]
fn a_raised_budget_a_new_row_and_a_shortened_string_array_pass() {
    let repo = Repo::new("raised");
    let [a, b, f] = rows();
    let flagged = object(&[("id", s("d")), ("seeds", J::B(true))]);
    let flag = repo.change(&[(INVENTORY, &inventory(&[a.clone(), b, f.clone(), flagged]))]);
    let model = repo.edit("src/model.rs", "Some(3)", "Some(4)").replace(
        "[&str; 4] = [\"a\", \"b\", \"c\", \"d\"]",
        "[&str; 3] = [\"a\", \"b\", \"c\"]",
    );
    let rows = [
        a.with("seeds", J::N(13))
            .with("bound", s("^a: depth: 7 actions 40$")),
        f.with("deadline_seconds", J::N(20)),
        object(&[("id", s("c")), ("seeds", J::N(1))]),
        object(&[("id", s("d"))]),
    ];
    let tests = repo.edit(
        "src/a_tests.rs",
        "assert!(true);\n}\n#[test]\nfn second",
        "assert_eq!(1, 1);\n}\n#[test]\nfn second",
    );
    let head = repo.change(&[
        ("src/model.rs", &model),
        (INVENTORY, &inventory(&rows)),
        ("src/a_tests.rs", &tests),
    ]);
    let run = repo.scan(&["--base", &flag, "--head", &head]);
    assert_eq!(run.outcome(), (Some(0), ""), "{}", run.stderr);
}

#[test]
fn lines_with_one_pairing_text_pair_in_order() {
    let repo = Repo::new("pair-order");
    let [a, b, f] = rows();
    repo.change(&[
        (
            "src/model.rs",
            "    a.preemption_bound = Some(1);\n    b.preemption_bound = Some(3);\n    b.preemption_bound = Some(5);\n",
        ),
        (INVENTORY, &inventory(&[a.with("bound", s("^a: depth: 3 depth: 5$")), b.clone(), f.clone()])),
    ]);
    let head = repo.change(&[
        (
            "src/model.rs",
            "    b.preemption_bound = Some(4);\n    b.preemption_bound = Some(4);\n",
        ),
        (
            INVENTORY,
            &inventory(&[a.with("bound", s("^a: depth: 6 depth: 4$")), b, f]),
        ),
    ]);
    let run = repo.scan_parent(&head);
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    assert_eq!(
        run.stdout,
        format!(
            "blocks budget-lowered:src/model.rs preemption_bound at line 2: 5 -> 4\n\
             blocks budget-lowered:{INVENTORY} qualified.lane.rows[a].bound depth: 5 -> 4\n"
        )
    );
}

#[test]
fn hunks_pair_only_within_themselves() {
    let repo = Repo::new("hunks");
    repo.change(&[(
        "src/model.rs",
        "    b.max_branches = 1;\nx\n    b.max_branches = 3;\n",
    )]);
    let head = repo.change(&[("src/model.rs", "x\n    b.max_branches = 2;\n")]);
    repo.git(&["config", "diff.interHunkContext", "1"]);
    let parent = format!("{head}^");
    let run = repo.scan_env(
        &["--base", &parent, "--head", &head],
        &[("GIT_DIFF_OPTS", "--unified=3")],
    );
    assert_blocks(
        &run,
        "budget-lowered:src/model.rs max_branches at line 2: 3 -> 2",
    );
}

#[test]
fn a_path_with_glob_characters_reads_its_own_hunks() {
    let repo = Repo::new("glob");
    repo.change(&[
        ("src/[ab].rs", "    b.max_branches = 10;\n"),
        ("src/a.rs", "    b.max_branches = 10;\n"),
        ("src/A.rs", "    b.max_branches = 10;\n"),
    ]);
    let head = repo.change(&[
        ("src/a.rs", "    b.max_branches = 9;\n"),
        ("src/[ab].rs", "    b.max_branches = 10;\n// x\n"),
        ("src/A.rs", "    b.max_branches = 10;\n// x\n"),
    ]);
    let parent = format!("{head}^");
    let run = repo.scan_env(
        &["--base", &parent, "--head", &head],
        &[("GIT_ICASE_PATHSPECS", "1")],
    );
    assert_eq!(
        run.stdout,
        "blocks budget-lowered:src/a.rs max_branches at line 1: 10 -> 9\n"
    );
}

#[test]
fn a_renamed_ignored_test_reports_as_new() {
    let repo = Repo::new("renamed");
    let head = repo.change(&[(
        "src/ignored_tests.rs",
        &repo.edit("src/ignored_tests.rs", "old_name", "new_name"),
    )]);
    let run = repo.scan_head(&head);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert_eq!(
        run.stdout,
        "reports ignore-new:src/ignored_tests.rs new_name: absent -> #[ignore = \"slow\"]\n"
    );
}

#[test]
fn each_report_class_prints_its_line_and_passes() {
    let repo = Repo::new("report-classes");
    let new_tests = format!("#[ignore]\n{}", test_fn("arrives"));
    let tests = repo.edit(
        "src/a_tests.rs",
        "    assert!(true);\n}\n#[test]\nfn second",
        "}\n#[test]\nfn second",
    );
    let head = repo.commit(
        &[
            (
                ".github/workflows/agent-checks.yml",
                "    timeout-minutes: 20\n",
            ),
            (
                "scripts/rust-lane.sh",
                "  step check deadline 30m cargo check\n",
            ),
            (INVENTORY, &(document(&rows(), 11).dump(Some(0)) + "\n")),
            ("src/new_tests.rs", &new_tests),
            ("src/a_tests.rs", &tests),
        ],
        "change",
        &["src/gone_tests.rs"],
    );
    let run = repo.scan_head(&head);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert_eq!(
        run.lines(),
        [
            "reports assertions-removed:src/a_tests.rs assert lines: 1 removed -> 0 added",
            "reports assertions-removed:src/gone_tests.rs assert lines: 1 removed -> 0 added",
            "reports ignore-new:src/new_tests.rs arrives: absent -> #[ignore]",
            "reports timeout-raised:.github/workflows/agent-checks.yml timeout-minutes at line 1: 15 -> 20",
            "reports timeout-raised:scripts/rust-lane.sh deadline at line 1: 25 -> 30",
            &format!("reports timeout-raised:{INVENTORY} qemu.member_drain_seconds: 10 -> 11"),
        ]
    );
}

#[test]
fn only_the_exact_key_with_a_reason_in_the_range_acknowledges() {
    let repo = Repo::new("exact-key");
    let outside = repo.commit(&[], &format!("Weakens-Test: {KEY}: an earlier reason"), &[]);
    let cases = [
        (
            format!("subject\n\nWeakens-Test: {KEY}: needs a cgroup scope"),
            0,
        ),
        (format!("subject\n\nWeakens-Test: {KEY}: "), 1),
        (format!("subject\n\nWeakens-Test: {KEY}:    \t"), 1),
        (
            format!("subject\n\nWeakens-Test: {KEY}x: needs a cgroup scope"),
            1,
        ),
        (
            "subject\n\nWeakens-Test: budget-lowered:src/a_tests.rs: needs a cgroup scope"
                .to_owned(),
            1,
        ),
        (
            "subject\n\nWeakens-Test: ignore-existing:src: needs a cgroup scope".to_owned(),
            1,
        ),
        (
            format!("subject\n\n> Weakens-Test: {KEY}: quoted from another commit"),
            1,
        ),
        ("subject".to_owned(), 1),
    ];
    for (message, code) in cases {
        let head = repo.ignore_second(&message);
        let run = repo.scan(&["--base", &outside, "--head", &head]);
        assert_eq!(
            run.code,
            Some(code),
            "{message}: {}{}",
            run.stdout,
            run.stderr
        );
        if code == 1 {
            assert!(
                run.stderr
                    .contains(&format!("Weakens-Test: {KEY}: <reason>")),
                "{}",
                run.stderr
            );
        } else {
            assert_eq!(
                run.stdout,
                format!(
                    "acknowledged {KEY} second: not ignored -> #[ignore] (Weakens-Test: needs a cgroup scope)\n"
                )
            );
        }
        repo.reset(&outside);
    }
}

#[test]
fn one_line_acknowledges_every_finding_of_its_class_in_its_file() {
    let repo = Repo::new("one-line");
    repo.commit(
        &[(
            "src/a_tests.rs",
            "#[test]\n#[ignore]\nfn first() {}\n#[test]\n#[ignore]\nfn second() {}\n",
        )],
        &format!("ignore both\n\nWeakens-Test: {KEY}: both need root"),
        &[],
    );
    let head = repo.change(&[("src/model.rs", "// unrelated\n")]);
    let run = repo.scan_head(&head);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    for name in ["first", "second"] {
        let line = format!(
            "acknowledged {KEY} {name}: not ignored -> #[ignore] (Weakens-Test: both need root)\n"
        );
        assert!(run.stdout.contains(&line), "{}", run.stdout);
    }
}

#[test]
fn an_unreadable_base_exits_two_and_an_empty_range_prints_nothing() {
    let repo = Repo::new("unreadable-base");
    assert_eq!(repo.scan(&["--base", &"f".repeat(40)]).code, Some(2));
    assert_eq!(repo.scan(&["--base", "no-such-ref"]).code, Some(2));
    let empty = repo.scan(&["--base", &repo.base]);
    assert_eq!(
        (empty.code, empty.stdout.as_str(), empty.stderr.as_str()),
        (Some(0), "", "")
    );
    let raised = repo.change(&[(
        "src/model.rs",
        &repo.edit("src/model.rs", "Some(3)", "Some(4)"),
    )]);
    let behind = repo.scan(&["--base", &raised, "--head", &repo.base]);
    assert_eq!(
        (behind.code, behind.stdout.as_str(), behind.stderr.as_str()),
        (Some(0), "", "")
    );
}

#[test]
fn a_budget_line_after_a_form_feed_or_a_carriage_return_is_read() {
    let repo = Repo::new("form-feed");
    for separator in ["\x0c", "\r"] {
        repo.write(
            "src/model.rs",
            format!("x{separator}const SEEDS: u64 = 48;\n").as_bytes(),
        );
        repo.git(&["commit", "-q", "-am", "budget"]);
        repo.write(
            "src/model.rs",
            format!("x{separator}const SEEDS: u64 = 2;\n").as_bytes(),
        );
        repo.git(&["commit", "-q", "-am", "lowered"]);
        assert_blocks(
            &repo.scan(&["--base", "HEAD^"]),
            "budget-lowered:src/model.rs SEEDS at line 1: 48 -> 2",
        );
    }
}

#[test]
fn a_rust_path_holding_a_newline_exits_two() {
    let repo = Repo::new("newline-path");
    repo.ignore_second("change");
    repo.change(&[("src/a\nb.rs", "fn x() {}\n")]);
    let run = repo.scan(&["--base", &repo.base]);
    assert_eq!(run.code, Some(2), "{}{}", run.stdout, run.stderr);
    assert_eq!(
        run.stderr,
        "scan-weakened-tests: a changed Rust path holds a newline, which the blob reader cannot name\n"
    );
}

#[test]
fn text_that_is_not_utf8_exits_two() {
    let repo = Repo::new("not-utf8");
    repo.ignore_second("change");
    repo.write("src/model.rs", b"// \xff\n");
    repo.git(&["commit", "-q", "-am", "binary byte"]);
    let run = repo.scan(&["--base", &repo.base]);
    assert_eq!(run.code, Some(2));
    assert!(run.stderr.contains("src/model.rs"), "{}", run.stderr);
}

#[test]
fn a_byte_that_is_not_utf8_outside_the_diff_exits_two() {
    let repo = Repo::new("outside-diff");
    repo.change(&[("src/b.rs", "x\n")]);
    repo.write("src/b.rs", b"x\n// \xff\n");
    repo.git(&["commit", "-q", "-am", "unchanged byte"]);
    let rust = repo.git(&["rev-parse", "HEAD"]);
    repo.write("src/b.rs", b"y\n// \xff\n");
    repo.git(&["commit", "-q", "-am", "edit beside the byte"]);
    let run = repo.scan(&["--base", &rust, "--head", "HEAD"]);
    assert_eq!(run.code, Some(2), "{}{}", run.stdout, run.stderr);
    assert!(
        run.stderr.starts_with("scan-weakened-tests: ") && run.stderr.contains("src/b.rs"),
        "{}",
        run.stderr
    );
    let [a, b, f] = rows();
    let text = inventory(&[a.with("note", s("cafe")), b, f]);
    repo.change(&[(INVENTORY, &text)]);
    let before = repo.git(&["rev-parse", "HEAD"]);
    let (head, tail) = text
        .replace("\"seeds\": 12", "\"seeds\": 11")
        .split_once("\"cafe\"")
        .map(|(head, tail)| (head.to_owned(), tail.to_owned()))
        .expect("the note is written");
    repo.write(
        INVENTORY,
        &[head.as_bytes(), b"\"caf\xe9\"", tail.as_bytes()].concat(),
    );
    repo.git(&["commit", "-q", "-am", "latin-1 note"]);
    let run = repo.scan(&["--base", &before, "--head", "HEAD"]);
    assert_eq!(run.code, Some(2), "{}{}", run.stdout, run.stderr);
    assert!(run.stderr.contains(INVENTORY), "{}", run.stderr);
}

#[test]
fn a_scan_from_a_subdirectory_reports_the_line_patterns() {
    let repo = Repo::new("subdirectory");
    let head = repo.change(&[(
        "src/model.rs",
        &repo.edit("src/model.rs", "Some(3)", "Some(2)"),
    )]);
    repo.git(&["config", "diff.relative", "true"]);
    let root = repo.scan_head(&head);
    let scripts = repo.repo.join("scripts");
    let nested = repo.scan_with(
        &["--base", &repo.base],
        &[("GIT_LITERAL_PATHSPECS", "1")],
        Some(&scripts),
    );
    assert!(
        root.stdout
            .contains("blocks budget-lowered:src/model.rs preemption_bound at line 1: 3 -> 2\n")
    );
    assert_eq!(nested.outcome(), root.outcome());
}

#[test]
fn the_report_reads_commits_only_and_leaves_the_checkout_as_it_was() {
    let repo = Repo::new("checkout");
    repo.change(&[
        (
            "src/model.rs",
            &repo.edit("src/model.rs", "Some(3)", "Some(2)"),
        ),
        (
            ".github/workflows/agent-checks.yml",
            "    timeout-minutes: 20\n",
        ),
    ]);
    let head = repo.ignore_second("change");
    let clean = repo.scan_head(&head);
    repo.write("src/a_tests.rs", test_fn("first").as_bytes());
    repo.write("src/model.rs", b"    builder.preemption_bound = Some(1);\n");
    repo.git(&["add", "src/model.rs"]);
    repo.write(".gitattributes", b"*.rs -diff\n*.yml diff=rewrite\n");
    repo.git(&["config", "diff.rewrite.textconv", "sed s/timeout/hidden/"]);
    let state = || {
        [
            repo.git(&["status", "--porcelain"]),
            repo.git(&["diff", "--cached"]),
            repo.git(&["worktree", "list", "--porcelain"]),
            fs::read_to_string(repo.repo.join("src/a_tests.rs")).expect("the file reads"),
        ]
    };
    let before = state();
    let changed = repo.scan(&["--base", &repo.base]);
    let after = state();
    assert_eq!(clean.code, Some(1));
    assert!(
        clean
            .stdout
            .contains("blocks budget-lowered:src/model.rs preemption_bound at line 1: 3 -> 2\n")
    );
    assert!(clean.stdout.contains(
        "reports timeout-raised:.github/workflows/agent-checks.yml timeout-minutes at line 1: 15 -> 20\n"
    ));
    assert_eq!(changed.outcome(), clean.outcome());
    assert_eq!(after, before);
}

#[test]
fn the_report_is_appended_to_the_step_summary() {
    let repo = Repo::new("summary");
    repo.ignore_second("change");
    let summary = repo.temp.join("summary.md");
    fs::write(&summary, "earlier step\n").expect("the summary is written");
    let path = summary.to_str().expect("the path is UTF-8");
    let run = repo.scan_env(&["--base", &repo.base], &[("GITHUB_STEP_SUMMARY", path)]);
    let line = format!("blocks {KEY} second: not ignored -> #[ignore]\n");
    assert_eq!(run.outcome(), (Some(1), line.as_str()), "{}", run.stderr);
    let text = fs::read_to_string(&summary).expect("the summary reads");
    assert!(text.starts_with("earlier step\n"), "{text}");
    assert_eq!(text.matches(&line).count(), 1, "{text}");
}

#[test]
fn a_budget_written_as_an_expression_or_a_hex_literal_is_no_finding() {
    let repo = Repo::new("expression");
    let model = repo
        .edit("src/model.rs", "SEEDS: u64 = 48", "SEEDS: u64 = 0x40")
        .replace("max_branches = 10_000;", "max_branches = 5_000 * 4;");
    let head = repo.change(&[("src/model.rs", &model)]);
    let run = repo.scan_head(&head);
    assert_eq!(run.outcome(), (Some(0), ""), "{}", run.stderr);
}

#[test]
fn equal_paired_values_are_no_finding() {
    let repo = Repo::new("equal");
    let head = repo.change(&[
        (
            "src/model.rs",
            &repo.edit(
                "src/model.rs",
                "[u64; 3] = [1, 2, 3]",
                "[u64; 3] = [1, 2, 4]",
            ),
        ),
        (
            ".github/workflows/agent-checks.yml",
            "    timeout-minutes: 15 # fifteen\n    run: exec timeout --kill-after=30s 5m make\n",
        ),
    ]);
    let run = repo.scan_head(&head);
    assert_eq!(run.outcome(), (Some(0), ""), "{}", run.stderr);
}

#[test]
fn the_diff_algorithm_setting_leaves_the_pairing_as_it_was() {
    let repo = Repo::new("algorithm");
    repo.change(&[(
        "src/model.rs",
        "fn f() {\n}\n\nfn f() {\n{\nx();\n b.max_branches = 10;\nfn f() {\n",
    )]);
    let head = repo.change(&[(
        "src/model.rs",
        "fn f() {\n}\n\nfn f() {\n{\nfn f() {\nx();\n b.max_branches = 9;\nfn f() {\n{\n",
    )]);
    repo.git(&["config", "diff.algorithm", "histogram"]);
    assert_blocks(
        &repo.scan_parent(&head),
        "budget-lowered:src/model.rs max_branches at line 8: 10 -> 9",
    );
}

#[test]
fn a_command_timeout_and_a_row_deadline_that_rise_report() {
    let repo = Repo::new("timeouts");
    let [a, b, f] = rows();
    let head = repo.change(&[
        (
            ".github/workflows/agent-checks.yml",
            "    timeout-minutes: 14\n    run: exec timeout --kill-after=30s 7m make\n",
        ),
        (
            INVENTORY,
            &inventory(&[a, b, f.with("deadline_seconds", J::N(31))]),
        ),
    ]);
    let run = repo.scan_head(&head);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert_eq!(
        run.stdout.lines().collect::<Vec<_>>(),
        [
            "reports timeout-raised:.github/workflows/agent-checks.yml timeout at line 2: 5 -> 7",
            &format!(
                "reports timeout-raised:{INVENTORY} qualified.lane.rows[f].deadline_seconds: 30 -> 31"
            ),
        ]
    );
}

#[test]
fn a_count_or_a_field_that_leaves_an_object_that_remains_blocks() {
    let repo = Repo::new("leaves-object");
    let [a, b, f] = rows();
    let cases = [
        (
            inventory(&[
                a.with("bound", s("^a: depth: \\d+ actions 40$")),
                b.clone(),
                f.clone(),
            ]),
            "qualified.lane.rows[a].bound depth: 6 -> absent",
        ),
        (
            inventory(&[a.clone(), b.clone(), f.with("member", s("^f:$"))]),
            "qualified.lane.rows[f].member cycles: 9 -> absent",
        ),
        (
            inventory(&[a.clone(), b.clone(), f.without("member")]),
            "qualified.lane.rows[f].member cycles: 9 -> absent",
        ),
        (
            inventory(&rows()).replace("\"seeds\": 64", "\"options\": {\"x\": 1}"),
            "miri_sweep.seeds: 64 -> absent",
        ),
        (
            inventory(&rows()).replace("{\n    \"seeds\": 64\n  }", "{}"),
            "miri_sweep.seeds: 64 -> absent",
        ),
    ];
    for (text, line) in cases {
        let head = repo.change(&[(INVENTORY, &text)]);
        assert_blocks(
            &repo.scan_head(&head),
            &format!("budget-lowered:{INVENTORY} {line}"),
        );
        repo.reset(&repo.base);
    }
}

#[test]
fn a_removed_object_and_a_reworded_text_with_every_count_are_no_finding() {
    let repo = Repo::new("reworded");
    let [a, b, f] = rows();
    let rows = [a.with("bound", s("^a(x): depth: 6 actions 40$")), b, f];
    let J::O(members) = document(&rows, 10) else {
        panic!("the document is an object");
    };
    let kept = J::O(
        members
            .into_iter()
            .filter(|(key, _)| key != "miri_sweep")
            .collect(),
    );
    let head = repo.change(&[(INVENTORY, &kept.dump(None))]);
    let run = repo.scan_head(&head);
    assert_eq!(run.outcome(), (Some(0), ""), "{}", run.stderr);
}

#[test]
fn a_root_level_budget_that_falls_or_goes_absent_blocks() {
    let repo = Repo::new("root-level");
    repo.change(&[(INVENTORY, "{\"baseline\": \"x\", \"seeds\": 12}")]);
    for (text, line) in [
        ("{\"baseline\": \"x\", \"seeds\": 11}", "seeds: 12 -> 11"),
        ("{\"baseline\": \"x\"}", "seeds: 12 -> absent"),
    ] {
        let head = repo.change(&[(INVENTORY, text)]);
        assert_blocks(
            &repo.scan_parent(&head),
            &format!("budget-lowered:{INVENTORY} {line}"),
        );
        repo.reset("HEAD^");
    }
}

/// The files of a commit, the paths it deletes, and the words its refusal holds.
type Refusal = (Vec<(String, String)>, Vec<&'static str>, &'static str);

#[test]
fn an_inventory_that_cannot_be_compared_exits_two() {
    let repo = Repo::new("cannot-compare");
    let ignored = repo.edit(
        "src/a_tests.rs",
        "#[test]\nfn second",
        "#[test]\n#[ignore]\nfn second",
    );
    let [a, b, f] = rows();
    let J::O(mut decoy) = document(&[b.with("seeds", J::N(3)), a.clone(), f.clone()], 10) else {
        panic!("the document is an object");
    };
    decoy.push(("qualified.lane.rows[b].seeds".to_owned(), J::N(4)));
    let deep = "[".repeat(5000) + &"]".repeat(5000);
    let more = |row: J| inventory(&[a.clone(), b.clone(), f.clone(), row]);
    let cases: Vec<Refusal> = vec![
        (
            vec![(INVENTORY.to_owned(), J::O(decoy).dump(None))],
            vec![],
            "the key 'qualified.lane.rows[b].seeds' under the root",
        ),
        (
            vec![(INVENTORY.to_owned(), more(b.with("seeds", J::N(3))))],
            vec![],
            "share the path qualified.lane.rows[b].id",
        ),
        (
            vec![(
                INVENTORY.to_owned(),
                more(object(&[("id", s("1")), ("seeds", J::N(2))])),
            )],
            vec![],
            "the id '1'",
        ),
        (
            vec![(
                INVENTORY.to_owned(),
                more(object(&[("id", s("x.y")), ("seeds", J::N(2))])),
            )],
            vec![],
            "the id 'x.y'",
        ),
        (
            vec![(INVENTORY.to_owned(), r#"{"": {"seeds": 4}}"#.to_owned())],
            vec![],
            "the key '' under the root could name another path",
        ),
        (
            vec![(
                INVENTORY.to_owned(),
                r#"{"a": {"": {"seeds": 4}}}"#.to_owned(),
            )],
            vec![],
            "the key '' under a could name another path",
        ),
        (
            vec![(
                INVENTORY.to_owned(),
                r#"{"a\r::error::b": {"": {"seeds": 4}}}"#.to_owned(),
            )],
            vec![],
            "the key '' under a\\r::error::b could name another path\n",
        ),
        (
            vec![(
                INVENTORY.to_owned(),
                r#"{"a\r::error::b": {"x.y": 4}}"#.to_owned(),
            )],
            vec![],
            "the key 'x.y' under a\\r::error::b could name another path\n",
        ),
        (
            vec![(
                INVENTORY.to_owned(),
                r#"{"a\r::error::b": [{"id": "x.y"}]}"#.to_owned(),
            )],
            vec![],
            "the id 'x.y' under a\\r::error::b could name another path\n",
        ),
        (
            vec![(
                INVENTORY.to_owned(),
                r#"{"a\r::error::b": [{"id": "x"}, {"id": "x"}]}"#.to_owned(),
            )],
            vec![],
            "two values share the path a\\r::error::b[x].id\n",
        ),
        (vec![(INVENTORY.to_owned(), deep)], vec![], INVENTORY),
        (
            vec![(INVENTORY.to_owned(), String::new())],
            vec![],
            "is empty",
        ),
        (
            vec![(INVENTORY.to_owned(), "not json".to_owned())],
            vec![],
            INVENTORY,
        ),
        (
            vec![
                (INVENTORY.to_owned(), "not json".to_owned()),
                ("src/a_tests.rs".to_owned(), ignored.clone()),
            ],
            vec![],
            INVENTORY,
        ),
        (
            vec![(format!("{INVENTORY}/x"), "{}".to_owned())],
            vec![INVENTORY],
            "is not a file",
        ),
    ];
    for (files, deleted, message) in cases {
        for name in &deleted {
            repo.git(&["rm", "-q", "--", name]);
        }
        let files: Vec<(&str, &str)> = files
            .iter()
            .map(|(name, text)| (name.as_str(), text.as_str()))
            .collect();
        let head = repo.change(&files);
        let run = repo.scan_head(&head);
        assert_eq!(run.outcome(), (Some(2), ""), "{message}: {}", run.stderr);
        assert!(run.stderr.contains(message), "{}", run.stderr);
        assert!(
            run.stderr.starts_with("scan-weakened-tests: "),
            "{}",
            run.stderr
        );
        assert!(one_line(&run.stderr), "{}", run.stderr);
        repo.reset(&repo.base);
    }
}

#[test]
fn an_inventory_entry_whose_object_is_missing_exits_two() {
    let repo = Repo::new("missing-object");
    repo.git(&["read-tree", &repo.base]);
    repo.git(&[
        "update-index",
        "--cacheinfo",
        &format!("100644,{},{INVENTORY}", "1".repeat(40)),
    ]);
    let tree = repo.git(&["write-tree", "--missing-ok"]);
    let head = repo.git(&["commit-tree", &tree, "-p", &repo.base, "-m", "missing"]);
    let run = repo.scan_head(&head);
    assert_eq!(run.code, Some(2), "{}{}", run.stdout, run.stderr);
    let expected = format!(
        "scan-weakened-tests: {INVENTORY} at {} is empty or unreadable\n",
        &head[..12]
    );
    assert_eq!(run.stderr, expected);
}

#[test]
fn a_deleted_inventory_is_no_finding() {
    let repo = Repo::new("deleted-inventory");
    let head = repo.commit(&[], "change", &[INVENTORY]);
    let run = repo.scan_head(&head);
    assert_eq!(run.outcome(), (Some(0), ""), "{}", run.stderr);
}

#[test]
fn a_test_in_a_sibling_module_is_matched_by_its_module() {
    let repo = Repo::new("sibling-module");
    let helper = "fn helper() {\n    let _ = 1;\n}\n";
    let same = test_fn("same");
    let first = format!("mod a {{\n{helper}#[ignore = \"slow\"]\n{same}}}\nmod b {{\n{helper}");
    repo.change(&[("src/mods_tests.rs", &format!("{first}{same}}}\n"))]);
    let head = repo.change(&[(
        "src/mods_tests.rs",
        &format!("{first}#[ignore]\n{same}}}\n"),
    )]);
    let run = repo.scan_parent(&head);
    assert_eq!(
        run.outcome(),
        (
            Some(1),
            "blocks ignore-existing:src/mods_tests.rs b::same: not ignored -> #[ignore]\n"
        ),
        "{}",
        run.stderr
    );
    let reordered = repo.change(&[(
        "src/mods_tests.rs",
        &format!("mod b {{\n#[ignore]\n{same}}}\nmod a {{\n#[ignore = \"slow\"]\n{same}}}\n"),
    )]);
    let run = repo.scan(&["--base", &head, "--head", &reordered]);
    assert_eq!(run.outcome(), (Some(0), ""), "{}", run.stderr);
    let moved = repo.change(&[(
        "src/mods_tests.rs",
        &format!("mod c {{\n#[ignore]\n{same}}}\n"),
    )]);
    let run = repo.scan(&["--base", &reordered, "--head", &moved]);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert!(
        run.stdout
            .contains("reports ignore-new:src/mods_tests.rs c::same: absent -> #[ignore]\n")
    );
    assert!(!run.stdout.contains("ignore-existing"), "{}", run.stdout);
}

#[test]
fn a_conditional_ignore_widened_to_a_plain_one_blocks() {
    let repo = Repo::new("widened");
    let miri = MIRI_IGNORE;
    let text = repo.edit(
        "src/a_tests.rs",
        "#[test]\nfn second",
        &format!("#[test]\n{miri}\nfn second"),
    );
    repo.change(&[("src/a_tests.rs", &text)]);
    for (attributes, line) in [
        ("#[ignore]".to_owned(), format!("{miri} -> #[ignore]")),
        (
            format!("{miri}\n#[ignore]"),
            format!("{miri} -> {miri}; #[ignore]"),
        ),
        (
            format!("#[ignore]\n{miri}"),
            format!("{miri} -> #[ignore]; {miri}"),
        ),
    ] {
        let head = repo.change(&[(
            "src/a_tests.rs",
            &repo.edit("src/a_tests.rs", miri, &attributes),
        )]);
        assert_blocks(&repo.scan_parent(&head), &format!("{KEY} second: {line}"));
        repo.reset("HEAD^");
    }
    let reason = repo.change(&[(
        "src/a_tests.rs",
        &repo.edit(
            "src/a_tests.rs",
            miri,
            concat!("#[cfg_attr(miri, ", "ignore = \"slow\")]"),
        ),
    )]);
    let run = repo.scan_parent(&reason);
    assert_eq!(run.outcome(), (Some(0), ""), "{}", run.stderr);
    let narrowed = repo.change(&[(
        "src/ignored_tests.rs",
        &repo.edit("src/ignored_tests.rs", "#[ignore = \"slow\"]", miri),
    )]);
    assert_eq!(repo.scan_parent(&narrowed).code, Some(0));
}

#[test]
fn an_ignore_inside_a_literal_or_a_comment_names_no_test() {
    let repo = Repo::new("literal-decoy");
    let cases = [
        ("const NOTE: &str = \"#[ignore]\";\n", "#[ignore]"),
        ("// #[ignore]\n", "#[ignore]"),
        ("/* outer /* inner */ #[ignore] */\n", "#[ignore]"),
        (
            "const C: [char; 2] = ['\\u{0}', '\"'];\nconst D: bool = matches!('a', '\\x00'|'\"');\n",
            "#[ignore]",
        ),
        ("", "#[ignore] // this fn hangs on CI"),
        ("", "#[ignore]\n// fn hangs on CI"),
        ("", "#[ignore]\n/* fn hangs */"),
    ];
    for (decoy, attribute) in cases {
        let planted = repo.change(&[(
            "src/a_tests.rs",
            &repo.edit(
                "src/a_tests.rs",
                "#[test]\nfn second() {\n",
                &format!("{decoy}#[test]\nfn second() {{\n    assert_eq!(\"x\", \"x\");\n"),
            ),
        )]);
        let control = repo.scan_parent(&planted);
        assert_eq!(
            control.outcome(),
            (Some(0), ""),
            "{decoy}: {}",
            control.stderr
        );
        let head = repo.change(&[(
            "src/a_tests.rs",
            &repo.edit(
                "src/a_tests.rs",
                "#[test]\nfn second",
                &format!("#[test]\n{attribute}\nfn second"),
            ),
        )]);
        let run = repo.scan(&["--base", &planted, "--head", &head]);
        assert_eq!(
            run.outcome(),
            (
                Some(1),
                format!("blocks {KEY} second: not ignored -> #[ignore]\n").as_str()
            ),
            "{decoy}: {}",
            run.stderr
        );
        repo.reset(&repo.base);
    }
}

#[test]
fn many_ignores_with_no_fn_after_them_are_no_finding() {
    let repo = Repo::new("many-ignores");
    let text = repo.edit("src/a_tests.rs", "", "") + &"#[ignore]\n".repeat(3000);
    let head = repo.change(&[("src/a_tests.rs", &text)]);
    let mut child = repo
        .tool(&["--base", &repo.base, "--head", &head], &[], None)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the tool starts");
    let started = Instant::now();
    while child
        .try_wait()
        .expect("the child's status reads")
        .is_none()
    {
        if started.elapsed() > Duration::from_secs(60) {
            child.kill().expect("the child is killed");
            child.wait().expect("the killed child is reaped");
            panic!("the scan ran past 60 seconds");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let run = Run::from(child.wait_with_output().expect("the output reads"));
    assert_eq!(run.outcome(), (Some(0), ""), "{}", run.stderr);
}

#[test]
fn a_non_ascii_path_reads_under_a_non_utf8_locale() {
    let repo = Repo::new("locale-path");
    let path = "src/caf\u{e9}_tests.rs";
    repo.change(&[(
        path,
        &format!("const SEEDS: u64 = 12;\n{}", test_fn("second")),
    )]);
    let head = repo.change(&[(
        path,
        "const SEEDS: u64 = 11;\n#[test]\n#[ignore]\nfn second() {\n    assert!(true);\n}\n",
    )]);
    let installed = Command::new("locale")
        .arg("-a")
        .output()
        .map(|output| output.stdout)
        .unwrap_or_default();
    let installed = String::from_utf8_lossy(&installed);
    let mut locales = vec!["C"];
    locales.extend(
        ["en_US.iso88591", "en_US.ISO-8859-1"]
            .into_iter()
            .filter(|name| installed.split_whitespace().any(|found| found == *name))
            .take(1),
    );
    let parent = format!("{head}^");
    for locale in locales {
        let run = repo.scan_env(&["--base", &parent, "--head", &head], &[("LC_ALL", locale)]);
        assert_eq!(run.code, Some(1), "{locale}: {}", run.stderr);
        assert_eq!(
            run.lines(),
            [
                format!("blocks ignore-existing:{path} second: not ignored -> #[ignore]"),
                format!("blocks budget-lowered:{path} SEEDS at line 1: 12 -> 11"),
            ]
        );
    }
}

#[test]
fn the_longest_key_owns_an_acknowledgement_line() {
    let repo = Repo::new("longest-key");
    for path in ["src/a.rs", "src/a.rs: b.rs"] {
        repo.change(&[(path, &test_fn("first"))]);
    }
    let start = repo.git(&["rev-parse", "HEAD"]);
    let (long_key, short_key) = ("ignore-existing:src/a.rs: b.rs", "ignore-existing:src/a.rs");
    for (message, code) in [
        (format!("x\n\nWeakens-Test: {long_key}: needs root"), 1),
        (format!("x\n\nWeakens-Test: {long_key}:  "), 1),
        (
            format!("x\n\nWeakens-Test: {long_key}: needs root\nWeakens-Test: {short_key}: also"),
            0,
        ),
    ] {
        let ignored = "#[test]\n#[ignore]\nfn first() {}\n";
        let head = repo.commit(
            &[("src/a.rs", ignored), ("src/a.rs: b.rs", ignored)],
            &message,
            &[],
        );
        let run = repo.scan(&["--base", &start, "--head", &head]);
        assert_eq!(
            run.code,
            Some(code),
            "{message}: {}{}",
            run.stdout,
            run.stderr
        );
        if code == 1 {
            let line = format!("blocks {short_key} first: not ignored -> #[ignore]\n");
            assert!(run.stdout.contains(&line), "{}", run.stdout);
        }
        repo.reset(&start);
    }
}

#[test]
fn an_acknowledgement_after_a_line_separator_other_than_lf_is_no_line() {
    let repo = Repo::new("separator");
    for (separator, code) in [("\x0c", 1), ("\r", 1), ("\u{2028}", 1), ("\r\n", 0)] {
        let head = repo.ignore_second(&format!(
            "subject\n\nprose{separator}Weakens-Test: {KEY}: needs root\n"
        ));
        let run = repo.scan_head(&head);
        let verdict = if code == 0 { "acknowledged" } else { "blocks" };
        let first = run
            .stdout
            .split(" (")
            .next()
            .expect("a split yields a first part");
        let expected = format!(
            "{verdict} {KEY} second: not ignored -> #[ignore]{}",
            if code == 1 { "\n" } else { "" }
        );
        assert_eq!(
            (run.code, first),
            (Some(code), expected.as_str()),
            "{separator:?}: {}",
            run.stderr
        );
        repo.reset(&repo.base);
    }
}

#[test]
fn one_acknowledged_key_leaves_another_blocking() {
    let repo = Repo::new("one-key");
    let budget = format!("budget-lowered:{INVENTORY}");
    let [a, b, f] = rows();
    repo.commit(
        &[(INVENTORY, &inventory(&[a.with("seeds", J::N(11)), b, f]))],
        &format!("lower\n\nWeakens-Test: {budget}: the row moved to a nightly lane"),
        &[],
    );
    let head = repo.ignore_second("ignore");
    let run = repo.scan_head(&head);
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    assert_eq!(
        run.lines(),
        [
            format!("blocks {KEY} second: not ignored -> #[ignore]"),
            format!(
                "acknowledged {budget} qualified.lane.rows[a].seeds: 12 -> 11 (Weakens-Test: the row moved to a nightly lane)"
            ),
        ]
    );
    let range = format!("{}..{}", &repo.base[..12], &head[..12]);
    assert_eq!(
        run.stderr,
        format!(
            "scan-weakened-tests: {KEY} blocks; acknowledge it with a commit-message line in {range}: \
             Weakens-Test: {KEY}: <reason>\n"
        )
    );
}

#[test]
fn the_head_argument_bounds_the_findings_and_the_acknowledgements() {
    let repo = Repo::new("head-bounds");
    let tip = repo.ignore_second("ignore");
    repo.commit(
        &[],
        &format!("later\n\nWeakens-Test: {KEY}: written after the scanned head"),
        &[],
    );
    assert_eq!(repo.scan(&["--base", &repo.base]).code, Some(0));
    assert_blocks(
        &repo.scan_head(&tip),
        &format!("{KEY} second: not ignored -> #[ignore]"),
    );
}

#[test]
fn a_range_with_no_blocking_finding_reads_no_commit_message() {
    let repo = Repo::new("no-log");
    let trace = repo.temp.join("trace");
    let head = repo.change(&[(
        ".github/workflows/agent-checks.yml",
        "    timeout-minutes: 20\n    run: exec timeout --kill-after=30s 5m make\n",
    )]);
    let path = trace.to_str().expect("the path is UTF-8");
    let run = repo.scan_env(
        &["--base", &repo.base, "--head", &head],
        &[("GIT_TRACE", path)],
    );
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert!(run.stdout.contains("timeout-raised"), "{}", run.stdout);
    let traced = fs::read_to_string(&trace).expect("the trace reads");
    assert!(traced.contains("git diff"), "{traced}");
    assert!(!traced.contains("git log"), "{traced}");
}

#[test]
fn an_unreadable_head_or_an_unwritable_summary_exits_two() {
    let repo = Repo::new("unreadable-head");
    let run = repo.scan(&["--base", &repo.base, "--head", "no-such-ref"]);
    assert_eq!(run.code, Some(2));
    let rest = run
        .stderr
        .strip_prefix("scan-weakened-tests: git rev-parse ")
        .expect("the command is named");
    let (_, message) = rest
        .split_once(": ")
        .expect("the message follows the command");
    assert!(
        message.starts_with(|c: char| !c.is_whitespace()),
        "{}",
        run.stderr
    );
    repo.ignore_second("change");
    let directory = repo.temp.to_str().expect("the path is UTF-8");
    let run = repo.scan_env(
        &["--base", &repo.base],
        &[("GITHUB_STEP_SUMMARY", directory)],
    );
    assert_eq!(run.code, Some(2), "{}", run.stderr);
    assert!(
        run.stderr
            .starts_with("scan-weakened-tests: step summary: "),
        "{}",
        run.stderr
    );
    assert!(one_line(&run.stderr), "{}", run.stderr);
}

#[test]
fn a_sibling_that_cannot_load_or_a_missing_git_exits_two() {
    let repo = Repo::new("missing-git");
    assert_eq!(repo.scan(&["--base", &repo.base]).code, Some(0));
    let empty = repo.temp.join("empty");
    fs::create_dir_all(&empty).expect("the directory is made");
    let path = empty.to_str().expect("the path is UTF-8");
    let missing = repo.scan_env(&["--base", &repo.base], &[("PATH", path)]);
    assert_eq!(missing.code, Some(2), "{}", missing.stderr);
    assert!(
        missing.stderr.starts_with("scan-weakened-tests: "),
        "{}",
        missing.stderr
    );
}

#[test]
fn a_comment_before_a_budget_terminator_keeps_the_budget() {
    let repo = Repo::new("comment-terminator");
    repo.change(&[(
        "src/model.rs",
        "    b.max_branches = 10 /* cap */;\n    b.preemption_bound = Some(3 /* x */);\n",
    )]);
    let head = repo.change(&[(
        "src/model.rs",
        "    b.max_branches = 9 /* cap */;\n    b.preemption_bound = Some(2 /* x */);\n",
    )]);
    let run = repo.scan_parent(&head);
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    assert_eq!(
        run.lines(),
        [
            "blocks budget-lowered:src/model.rs preemption_bound at line 2: 3 -> 2",
            "blocks budget-lowered:src/model.rs max_branches at line 1: 10 -> 9",
        ]
    );
}

#[test]
fn a_count_that_stops_being_a_literal_reads_as_absent() {
    let repo = Repo::new("stops-literal");
    let [a, b, f] = rows();
    for (bound, line) in [
        ("^a: depth: 6 actions 40?$", "actions: 40 -> absent"),
        ("^a: depth: 5[0-9] actions 40$", "depth: 6 -> absent"),
    ] {
        let head = repo.change(&[(
            INVENTORY,
            &inventory(&[a.with("bound", s(bound)), b.clone(), f.clone()]),
        )]);
        let run = repo.scan_head(&head);
        let expected =
            format!("blocks budget-lowered:{INVENTORY} qualified.lane.rows[a].bound {line}\n");
        assert_eq!(
            run.outcome(),
            (Some(1), expected.as_str()),
            "{}",
            run.stderr
        );
        repo.reset(&repo.base);
    }
}

#[test]
fn raw_identifiers_name_their_fns_and_modules() {
    let repo = Repo::new("raw-identifiers");
    repo.change(&[(
        "src/raw_tests.rs",
        "#[test]\n#[ignore]\nfn r#type() {}\n#[test]\nfn r#match() {}\nmod r#kind {\n    fn helper() {}\n}\n",
    )]);
    let head = repo.change(&[(
        "src/raw_tests.rs",
        "#[test]\nfn r#type() {}\n#[test]\n#[ignore]\nfn r#match() {}\n\
         mod r#kind {\n    fn helper() {}\n    #[ignore]\n    fn other() {}\n}\n",
    )]);
    let run = repo.scan_parent(&head);
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    assert_eq!(
        run.lines(),
        [
            "blocks ignore-existing:src/raw_tests.rs match: not ignored -> #[ignore]",
            "reports ignore-new:src/raw_tests.rs kind::other: absent -> #[ignore]",
        ]
    );
}

#[test]
fn a_new_test_named_like_a_method_or_a_nested_fn_is_new() {
    let repo = Repo::new("method-name");
    let harness =
        "struct H;\nimpl H {\n    fn drains(&self) {}\n}\nfn outer() {\n    fn inner() {}\n}\n";
    repo.change(&[("src/harness_tests.rs", harness)]);
    let head = repo.change(&[(
        "src/harness_tests.rs",
        &format!(
            "{harness}#[test]\n#[ignore]\nfn drains() {{}}\n#[test]\n#[ignore]\nfn inner() {{}}\n"
        ),
    )]);
    let run = repo.scan_parent(&head);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert_eq!(
        run.lines(),
        [
            "reports ignore-new:src/harness_tests.rs drains: absent -> #[ignore]",
            "reports ignore-new:src/harness_tests.rs inner: absent -> #[ignore]",
        ]
    );
}

#[test]
fn a_plainly_ignored_test_that_gains_another_ignore_is_no_finding() {
    let repo = Repo::new("plain-gains");
    let text = repo.edit(
        "src/a_tests.rs",
        "#[test]\nfn second",
        "#[test]\n#[ignore]\nfn second",
    );
    repo.change(&[("src/a_tests.rs", &text)]);
    for added in [MIRI_IGNORE, "#[ignore = \"slow\"]"] {
        let text = repo.edit(
            "src/a_tests.rs",
            "#[ignore]\n",
            &format!("#[ignore]\n{added}\n"),
        );
        let head = repo.change(&[("src/a_tests.rs", &text)]);
        let run = repo.scan_parent(&head);
        assert_eq!(run.outcome(), (Some(0), ""), "{added}: {}", run.stderr);
        repo.reset("HEAD^");
    }
}

#[test]
fn a_runnable_twin_of_an_ignored_test_that_gains_an_ignore_blocks() {
    let repo = Repo::new("twin");
    let twins = |attribute: &str| {
        format!(
            "#[cfg(miri)]\n#[test]\n#[ignore]\nfn twin() {{}}\n#[cfg(not(miri))]\n#[test]\n{attribute}fn twin() {{}}\n"
        )
    };
    repo.change(&[("src/twin_tests.rs", &twins(""))]);
    let head = repo.change(&[("src/twin_tests.rs", &twins("#[cfg_attr(loom, ignore)]\n"))]);
    assert_blocks(
        &repo.scan_parent(&head),
        "ignore-existing:src/twin_tests.rs twin: not ignored -> #[cfg_attr(loom, ignore)]",
    );
}

#[test]
fn a_second_conditional_ignore_blocks() {
    let repo = Repo::new("second-conditional");
    let miri = MIRI_IGNORE;
    let text = repo.edit(
        "src/a_tests.rs",
        "#[test]\nfn second",
        &format!("#[test]\n{miri}\nfn second"),
    );
    repo.change(&[("src/a_tests.rs", &text)]);
    let text = repo.edit(
        "src/a_tests.rs",
        miri,
        &format!("{miri}\n#[cfg_attr(loom, ignore)]"),
    );
    let head = repo.change(&[("src/a_tests.rs", &text)]);
    assert_blocks(
        &repo.scan_parent(&head),
        &format!("{KEY} second: {miri} -> {miri}; #[cfg_attr(loom, ignore)]"),
    );
}

#[test]
fn a_conditional_ignore_whose_condition_changes_blocks() {
    let repo = Repo::new("condition-changes");
    let miri = concat!("#[cfg_attr(miri, ", "ignore = \"weak\")]");
    let text = repo.edit(
        "src/a_tests.rs",
        "#[test]\nfn second",
        &format!("#[test]\n{miri}\nfn second"),
    );
    repo.change(&[("src/a_tests.rs", &text)]);
    for predicate in ["not(miri)", "any(miri, unix)", "all(miri, unix)"] {
        let changed = miri.replace("(miri,", &format!("({predicate},"));
        let head = repo.change(&[(
            "src/a_tests.rs",
            &repo.edit("src/a_tests.rs", miri, &changed),
        )]);
        assert_blocks(
            &repo.scan_parent(&head),
            &format!("{KEY} second: {miri} -> {changed}"),
        );
        repo.reset("HEAD^");
    }
}

#[test]
fn conditional_ignores_that_keep_their_conditions_are_no_finding() {
    let repo = Repo::new("keep-conditions");
    let (miri, loom) = (
        concat!("#[cfg_attr(miri, ", "ignore = \"weak\")]"),
        "#[cfg_attr(loom, ignore)]",
    );
    let text = repo.edit(
        "src/a_tests.rs",
        "#[test]\nfn second",
        &format!("#[test]\n{miri}\n{loom}\nfn second"),
    );
    repo.change(&[("src/a_tests.rs", &text)]);
    let cases = [
        format!(
            "{}\n{loom}",
            concat!(
                "#[cfg_attr(miri, ",
                "ignore = \"a \\\"quoted\\\" ] reason\")]"
            )
        ),
        format!("{MIRI_IGNORE}\n{loom}"),
        format!(
            "#[cfg_attr(\n    miri,\n    ignore = \"a reason long enough to wrap the attribute\"\n)]\n{loom}"
        ),
        format!("{loom}\n{miri}"),
        miri.to_owned(),
    ];
    for attributes in cases {
        let text = repo.edit("src/a_tests.rs", &format!("{miri}\n{loom}"), &attributes);
        let head = repo.change(&[("src/a_tests.rs", &text)]);
        let run = repo.scan_parent(&head);
        assert_eq!(run.outcome(), (Some(0), ""), "{attributes}: {}", run.stderr);
        repo.reset("HEAD^");
    }
}

#[test]
fn a_named_bound_that_does_not_fall_or_has_no_one_value_is_no_finding() {
    let repo = Repo::new("named-bound");
    let site = |value: &str| format!("    builder.preemption_bound = Some({value});\n");
    for (old, new) in [
        ("Some(PREEMPTION_BOUND)", "Some(9)"),
        ("Some(PREEMPTION_BOUND)", "Some(10)"),
        ("Some(3)", "Some(PREEMPTION_BOUND)"),
        ("Some(3)", "Some(bound)"),
        (
            "PREEMPTION_BOUND: usize = 9;\n    builder.preemption_bound = Some(PREEMPTION_BOUND)",
            "PREEMPTION_BOUND: usize = 12;\n    builder.preemption_bound = Some(10)",
        ),
    ] {
        let head = repo.change(&[("src/model.rs", &repo.edit("src/model.rs", old, new))]);
        let run = repo.scan_head(&head);
        assert_eq!(
            run.outcome(),
            (Some(0), ""),
            "{old} -> {new}: {}",
            run.stderr
        );
        repo.reset(&repo.base);
    }
    for declarations in [
        "const LOW: usize = 9;\nmod m {\n    const LOW: usize = 5;\n}\n",
        "const LOW: usize = 3 * 3;\n",
        "const LOW: usize = 9;\nconst LOW: usize = 3 * 3;\n",
        "// const LOW: usize = 9;\n",
    ] {
        repo.change(&[("src/named.rs", &format!("{declarations}{}", site("LOW")))]);
        let head = repo.change(&[("src/named.rs", &format!("{declarations}{}", site("1")))]);
        let run = repo.scan_parent(&head);
        assert_eq!(
            run.outcome(),
            (Some(0), ""),
            "{declarations}: {}",
            run.stderr
        );
    }
}

#[test]
fn an_inventory_that_is_a_link_exits_two() {
    let repo = Repo::new("inventory-link");
    let link = repo.link(INVENTORY, "{}", "link");
    let restored = repo.change(&[(INVENTORY, &inventory(&rows()))]);
    for (base, head) in [
        (repo.base.as_str(), link.as_str()),
        (link.as_str(), restored.as_str()),
    ] {
        let run = repo.scan(&["--base", base, "--head", head]);
        assert_eq!(run.code, Some(2), "{base}: {}{}", run.stdout, run.stderr);
        let expected = format!(
            "scan-weakened-tests: {INVENTORY} at {} is not a file\n",
            &link[..12]
        );
        assert_eq!(run.stderr, expected);
    }
}

#[test]
fn an_inventory_scan_ignores_the_pathspec_environment() {
    let repo = Repo::new("pathspec-environment");
    let [a, b, f] = rows();
    let head = repo.change(&[(INVENTORY, &inventory(&[b.with("seeds", J::N(3)), a, f]))]);
    let source = repo.repo.join("src");
    for name in ["GIT_ICASE_PATHSPECS", "GIT_GLOB_PATHSPECS"] {
        let run = repo.scan_with(
            &["--base", &repo.base, "--head", &head],
            &[(name, "1")],
            Some(&source),
        );
        let expected =
            format!("blocks budget-lowered:{INVENTORY} qualified.lane.rows[b].seeds: 4 -> 3\n");
        assert_eq!(
            run.outcome(),
            (Some(1), expected.as_str()),
            "{name}: {}",
            run.stderr
        );
    }
}

/// A carriage return in a path is written `\r` in the report line, the step summary and the hint line, so
/// the `::error::` after it starts no line that a runner reads as a workflow command. A backslash in the
/// path stays as it is.
#[test]
fn a_carriage_return_in_a_path_is_written_escaped() {
    let repo = Repo::new("carriage-return");
    let path = "src/a\r::error::b\\c.rs";
    repo.change(&[(path, "const SEEDS: u64 = 12;\n")]);
    let head = repo.change(&[(path, "const SEEDS: u64 = 11;\n")]);
    let summary = repo.temp.join("summary.md");
    let summary_path = summary.to_str().expect("the path is UTF-8");
    let base = format!("{head}^");
    let run = repo.scan_env(
        &["--base", &base, "--head", &head],
        &[("GITHUB_STEP_SUMMARY", summary_path)],
    );
    let key = "budget-lowered:src/a\\r::error::b\\c.rs";
    let line = format!("blocks {key} SEEDS at line 1: 12 -> 11\n");
    assert_eq!(
        (run.code, run.bytes.as_slice()),
        (Some(1), line.as_bytes()),
        "{}",
        run.stderr
    );
    let parent = repo.git(&["rev-parse", &base]);
    let range = format!("{}..{}", &parent[..12], &head[..12]);
    assert_eq!(
        run.stderr,
        format!(
            "scan-weakened-tests: {key} blocks; acknowledge it with a commit-message line in {range}: \
             Weakens-Test: {key}: <reason>\n"
        )
    );
    let text = fs::read_to_string(&summary).expect("the summary reads");
    assert_eq!(
        text,
        format!("Weakened-test scan of {range}:\n\n```text\n{line}```\n")
    );
}

/// A line feed, U+007F, U+0085 and U+00A0 in an inventory key are each written as `repr` writes them.
#[test]
fn a_control_character_in_an_inventory_key_is_written_escaped() {
    let repo = Repo::new("key-line-feed");
    let key = r#"x\n\u007f\u0085\u00a0::error::y"#;
    let base = repo.change(&[(INVENTORY, &format!(r#"{{"{key}": {{"seeds": 2}}}}"#))]);
    let head = repo.change(&[(INVENTORY, &format!(r#"{{"{key}": {{"seeds": 1}}}}"#))]);
    let run = repo.scan(&["--base", &base, "--head", &head]);
    let line =
        format!("blocks budget-lowered:{INVENTORY} x\\n\\x7f\\x85\\xa0::error::y.seeds: 2 -> 1\n");
    assert_eq!(run.outcome(), (Some(1), line.as_str()), "{}", run.stderr);
}

#[test]
fn a_report_the_output_encoding_cannot_spell_prints_escaped() {
    let repo = Repo::new("encoding");
    let summary = repo.temp.join("summary.md");
    fs::write(&summary, "earlier step\n").expect("the summary is written");
    let path = summary.to_str().expect("the path is UTF-8");
    let head = repo.change(&[(
        "src/\u{65e5}_tests.rs",
        &format!("#[ignore]\n{}", test_fn("arrives")),
    )]);
    let run = repo.scan_with(
        &["--base", &repo.base, "--head", &head],
        &[("LC_ALL", "C"), ("GITHUB_STEP_SUMMARY", path)],
        None,
    );
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    let line = "reports ignore-new:src/\u{65e5}_tests.rs arrives: absent -> #[ignore]\n";
    assert_eq!(run.bytes, line.as_bytes());
    let text = fs::read_to_string(&summary).expect("the summary reads");
    assert!(text.contains(line), "{text}");
    assert!(text.starts_with("earlier step\n"), "{text}");
    repo.reset(&repo.base);
    let surrogate = "{\"qualified\": {\"lane\": {\"rows\": [{\"id\": \"s\\ud800\", \"deadline_seconds\": 5}]}}}";
    repo.change(&[(INVENTORY, surrogate)]);
    let raised = repo.change(&[(INVENTORY, &surrogate.replace("5}", "6}"))]);
    let parent = format!("{raised}^");
    let run = repo.scan_env(
        &["--base", &parent, "--head", &raised],
        &[("GITHUB_STEP_SUMMARY", path)],
    );
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    let line = format!(
        "reports timeout-raised:{INVENTORY} qualified.lane.rows[s\\ud800].deadline_seconds: 5 -> 6\n"
    );
    assert_eq!(run.stdout, line);
    let text = fs::read_to_string(&summary).expect("the summary reads");
    assert!(text.ends_with(&format!("```text\n{line}```\n")), "{text}");
}

#[test]
fn an_acknowledgement_reads_as_utf8_whatever_the_log_encoding() {
    let repo = Repo::new("log-encoding");
    let head = repo.ignore_second(&format!(
        "ignore\n\nWeakens-Test: {KEY}: caf\u{e9} needs root"
    ));
    repo.git(&["config", "i18n.logOutputEncoding", "ISO-8859-1"]);
    let run = repo.scan_head(&head);
    let expected = format!(
        "acknowledged {KEY} second: not ignored -> #[ignore] (Weakens-Test: caf\u{e9} needs root)\n"
    );
    assert_eq!(
        run.outcome(),
        (Some(0), expected.as_str()),
        "{}",
        run.stderr
    );
}

#[test]
fn the_diff_heuristic_setting_leaves_the_pairing_as_it_was() {
    let repo = Repo::new("heuristic");
    let base = format!(
        "Z0\n x();\nb\nb\n{}{{\n b.max_branches = 10;\nfn f() {{\n x();\nZ1\n",
        " b.max_branches = 9;\n y();\n".repeat(3)
    );
    repo.change(&[("src/model.rs", &base)]);
    let head = format!(
        " }}\n x();\nb\nb\nb\n{} x();\nfn f() {{\n\n",
        " b.max_branches = 9;\n y();\n".repeat(4)
    );
    let head = repo.change(&[("src/model.rs", &head)]);
    repo.git(&["config", "diff.indentHeuristic", "false"]);
    assert_blocks(
        &repo.scan_parent(&head),
        "budget-lowered:src/model.rs max_branches at line 12: 10 -> 9",
    );
}

#[test]
fn a_base_past_the_fork_point_charges_the_head_with_its_own_commits_only() {
    let repo = Repo::new("past-fork");
    let branch = repo.change(&[("src/lib.rs", "fn f() {}\n")]);
    repo.reset(&repo.base);
    let [a, b, f] = rows();
    let ahead = repo.commit(
        &[
            (
                "src/model.rs",
                &repo.edit("src/model.rs", "SEEDS: u64 = 48", "SEEDS: u64 = 96"),
            ),
            ("src/ignored_tests.rs", &test_fn("old_name")),
            (
                INVENTORY,
                &inventory(&[a.with("seeds", J::N(24)), b.with("seconds", J::N(5)), f]),
            ),
        ],
        &format!("strengthen\n\nWeakens-Test: {KEY}: written on the base side"),
        &[],
    );
    let run = repo.scan(&["--base", &ahead, "--head", &branch]);
    assert_eq!(
        (run.code, run.stdout.as_str(), run.stderr.as_str()),
        (Some(0), "", "")
    );
    repo.reset(&branch);
    let weakened = repo.ignore_second("ignore");
    let run = repo.scan(&["--base", &ahead, "--head", &weakened]);
    let expected = format!("blocks {KEY} second: not ignored -> #[ignore]\n");
    assert_eq!(
        run.outcome(),
        (Some(1), expected.as_str()),
        "{}",
        run.stderr
    );
    let range = format!(
        "in {}..{}: Weakens-Test: {KEY}: <reason>",
        &repo.base[..12],
        &weakened[..12]
    );
    assert!(run.stderr.contains(&range), "{}", run.stderr);
}

#[test]
fn a_base_that_shares_no_history_with_the_head_exits_two() {
    let repo = Repo::new("no-history");
    let unrelated = repo.git(&[
        "commit-tree",
        &format!("{}^{{tree}}", repo.base),
        "-m",
        "unrelated root",
    ]);
    let head = repo.ignore_second("ignore");
    let run = repo.scan(&["--base", &unrelated, "--head", &head]);
    assert_eq!(run.outcome(), (Some(2), ""), "{}", run.stderr);
    let expected = format!(
        "scan-weakened-tests: {} and {} share no history\n",
        &unrelated[..12],
        &head[..12]
    );
    assert_eq!(run.stderr, expected);
}

#[test]
fn ci_scans_a_pull_request_from_the_first_parent_of_its_test_merge() {
    let workflow =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows/agent-checks.yml");
    let workflow = fs::read_to_string(workflow).expect("the workflow reads");
    assert_eq!(
        workflow.matches("scan-weakened-tests").count(),
        1,
        "one step runs the scan"
    );
    assert!(workflow.contains(SCAN_STEP), "{SCAN_STEP}");
    let wrapper =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/ci-scan-weakened-tests.sh");
    let wrapper = fs::read_to_string(wrapper).expect("the wrapper reads");
    assert!(
        wrapper.contains("\nbash scripts/tool.sh scan-weakened-tests \"$@\" 2>&1 || status=$?\n")
    );
    let repo = Repo::new("first-parent");
    let key = format!("budget-lowered:{INVENTORY}");
    let [a, b, f] = rows();
    let pull = repo.change(&[(
        INVENTORY,
        &inventory(&[a.clone(), b.with("seeds", J::N(3)), f.clone()]),
    )]);
    repo.reset(&repo.base);
    repo.commit(
        &[(INVENTORY, &inventory(&[a.with("seeds", J::N(11)), b, f]))],
        &format!("lower a\n\nWeakens-Test: {key}: row a is slow on the runner"),
        &[],
    );
    repo.git(&["merge", "-q", "--no-ff", "-m", "test merge", &pull]);
    assert_eq!(repo.scan(&["--base", &repo.base]).code, Some(0));
    let run = repo.scan(&["--base", "HEAD^1"]);
    let expected = format!("blocks {key} qualified.lane.rows[b].seeds: 4 -> 3\n");
    assert_eq!(
        run.outcome(),
        (Some(1), expected.as_str()),
        "{}",
        run.stderr
    );
}

#[test]
fn changed_rust_files_share_one_diff_process_per_batch() {
    let repo = Repo::new("batches");
    let names: Vec<String> = (0..300)
        .map(|index| format!("src/many/f{index:03}.rs"))
        .collect();
    for name in &names {
        repo.write(name, b"    b.max_branches = 10;\n");
    }
    repo.git(&["add", "-A"]);
    repo.git(&["commit", "-q", "-m", "many files"]);
    for name in &names {
        repo.write(name, b"    b.max_branches = 10;\n// x\n");
    }
    repo.write(&names[299], b"    b.max_branches = 9;\n");
    repo.git(&["commit", "-q", "-am", "change each file"]);
    let trace = repo.temp.join("trace");
    let path = trace.to_str().expect("the path is UTF-8");
    let run = repo.scan_env(&["--base", "HEAD^"], &[("GIT_TRACE", path)]);
    let expected = format!(
        "blocks budget-lowered:{} max_branches at line 1: 10 -> 9\n",
        names[299]
    );
    assert_eq!(
        run.outcome(),
        (Some(1), expected.as_str()),
        "{}",
        run.stderr
    );
    let traced = fs::read_to_string(&trace).expect("the trace reads");
    assert_eq!(
        traced.matches("-U0").count(),
        2,
        "300 changed files read in two diffs"
    );
}

/// A path that Git quotes in its `diff --git` header makes the batch's headers differ from the expected ones,
/// so each path of the batch is read in a diff of its own, and each later file keeps its own hunks.
#[test]
fn a_path_that_git_quotes_leaves_each_later_file_its_own_hunks() {
    let repo = Repo::new("quoted-path");
    repo.change(&[
        ("src/a\"q.rs", "    b.max_branches = 10;\n"),
        ("src/b.rs", "    b.max_branches = 10;\n"),
    ]);
    let head = repo.change(&[
        ("src/a\"q.rs", "    b.max_branches = 8;\n"),
        ("src/b.rs", "    b.max_branches = 9;\n"),
    ]);
    let run = repo.scan_parent(&head);
    let expected = "blocks budget-lowered:src/a\"q.rs max_branches at line 1: 10 -> 8\n\
                    blocks budget-lowered:src/b.rs max_branches at line 1: 10 -> 9\n";
    assert_eq!(run.outcome(), (Some(1), expected), "{}", run.stderr);
}

#[test]
fn a_changed_path_name_that_is_not_utf8_exits_two() {
    let repo = Repo::new("path-not-utf8");
    let name = std::ffi::OsStr::from_bytes(b"src/caf\xff.rs");
    fs::write(repo.repo.join(name), "x\n").expect("the file is written");
    repo.git(&["add", "-A"]);
    repo.git(&["commit", "-q", "-m", "a path that is not UTF-8"]);
    let run = repo.scan(&["--base", "HEAD^"]);
    assert_eq!(run.outcome(), (Some(2), ""), "{}", run.stderr);
    assert_eq!(
        run.stderr,
        "scan-weakened-tests: invalid utf-8 sequence of 1 bytes from index 7\n"
    );
}

#[test]
fn a_workflow_diff_that_is_not_utf8_exits_two_and_names_its_command() {
    let repo = Repo::new("workflow-not-utf8");
    repo.write(
        ".github/workflows/agent-checks.yml",
        b"    timeout-minutes: 16 \xff\n",
    );
    repo.git(&["commit", "-q", "-am", "a workflow byte that is not UTF-8"]);
    let run = repo.scan(&["--base", "HEAD^"]);
    assert_eq!(run.outcome(), (Some(2), ""), "{}", run.stderr);
    assert!(
        run.stderr.starts_with(
            "scan-weakened-tests: git --no-literal-pathspecs -c core.quotePath=false diff "
        ),
        "{}",
        run.stderr
    );
    assert!(
        run.stderr.contains(":(top,literal).github/workflows/agent-checks.yml: invalid utf-8 sequence of 1 bytes from index "),
        "{}",
        run.stderr
    );
}

#[test]
fn two_blocking_keys_print_their_hints_in_the_order_they_first_block() {
    let repo = Repo::new("two-keys");
    let [a, b, f] = rows();
    let tests = repo.edit(
        "src/a_tests.rs",
        "#[test]\nfn second",
        "#[test]\n#[ignore]\nfn second",
    );
    let head = repo.change(&[
        ("src/a_tests.rs", &tests),
        (INVENTORY, &inventory(&[a.with("seeds", J::N(11)), b, f])),
    ]);
    let run = repo.scan_head(&head);
    let budget = format!("budget-lowered:{INVENTORY}");
    let range = format!("{}..{}", &repo.base[..12], &head[..12]);
    let hint = |key: &str| {
        format!(
            "scan-weakened-tests: {key} blocks; acknowledge it with a commit-message line in {range}: Weakens-Test: {key}: <reason>\n"
        )
    };
    assert_eq!(run.code, Some(1));
    assert_eq!(
        run.stdout,
        format!(
            "blocks {KEY} second: not ignored -> #[ignore]\nblocks {budget} qualified.lane.rows[a].seeds: 12 -> 11\n"
        )
    );
    assert_eq!(run.stderr, hint(KEY) + &hint(&budget));
}

#[test]
fn the_arguments_read_as_the_option_table_states() {
    let repo = Repo::new("arguments");
    let help = repo.scan(&["--help"]);
    assert_eq!(help.code, Some(0));
    assert!(
        help.stdout
            .starts_with("usage: scan-weakened-tests [-h] --base BASE [--head HEAD]\n\n"),
        "{}",
        help.stdout
    );
    let usage =
        "usage: scan-weakened-tests [-h] --base BASE [--head HEAD]\nscan-weakened-tests: error: ";
    let missing = repo.scan(&[]);
    assert_eq!(missing.code, Some(2));
    assert_eq!(
        missing.stderr,
        format!("{usage}the following arguments are required: --base\n")
    );
    let ambiguous = repo.scan(&["--he", "HEAD"]);
    assert_eq!(ambiguous.code, Some(2));
    assert_eq!(
        ambiguous.stderr,
        format!("{usage}ambiguous option: --he could match --help, --head\n")
    );
    let head = repo.ignore_second("ignore");
    let abbreviated = repo.scan(&["--bas", &repo.base, "--hea", &head]);
    assert_eq!(
        abbreviated.outcome(),
        (
            Some(1),
            format!("blocks {KEY} second: not ignored -> #[ignore]\n").as_str()
        )
    );
    let dashes = repo.scan(&["--base=--"]);
    assert_eq!(dashes.code, Some(2));
    assert!(
        dashes.stderr.starts_with(
            "scan-weakened-tests: git rev-parse --verify --end-of-options --^{commit}: fatal: "
        ),
        "{}",
        dashes.stderr
    );
}

#[test]
fn a_full_standard_output_exits_120_before_the_summary_and_the_hints() {
    let repo = Repo::new("full-output");
    repo.ignore_second("ignore");
    let summary = repo.temp.join("summary.md");
    let full = fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .expect("/dev/full opens");
    let path = summary.to_str().expect("the path is UTF-8");
    let run = Run::from(
        repo.tool(
            &["--base", &repo.base],
            &[("GITHUB_STEP_SUMMARY", path)],
            None,
        )
        .stdout(full)
        .output()
        .expect("the tool starts"),
    );
    assert_eq!(run.code, Some(120), "{}", run.stderr);
    assert!(!summary.exists());
    assert_eq!(
        run.stderr,
        "scan-weakened-tests: standard output: No space left on device (os error 28)\n"
    );
}

/// `/dev/null` opened for reading alone refuses each write with `EBADF`.
#[test]
fn a_read_only_standard_stream_exits_120_before_the_summary_and_the_hints() {
    let read_only = || fs::File::open("/dev/null").expect("/dev/null opens");
    let refused = "scan-weakened-tests: standard output: Bad file descriptor (os error 9)\n";
    let repo = Repo::new("read-only");
    repo.ignore_second("ignore");
    let summary = repo.temp.join("summary.md");
    let path = summary.to_str().expect("the path is UTF-8");
    let report = Run::from(
        repo.tool(
            &["--base", &repo.base],
            &[("GITHUB_STEP_SUMMARY", path)],
            None,
        )
        .stdout(read_only())
        .output()
        .expect("the tool starts"),
    );
    assert_eq!(report.code, Some(120), "{}", report.stderr);
    assert!(!summary.exists());
    assert_eq!(report.stderr, refused);
    let refusal = repo
        .tool(&[], &[], None)
        .stderr(read_only())
        .status()
        .expect("the tool starts");
    assert_eq!(refusal.code(), Some(120));
    let help = Run::from(
        repo.tool(&["--help"], &[], None)
            .stdout(read_only())
            .output()
            .expect("the tool starts"),
    );
    assert_eq!((help.code, help.stderr.as_str()), (Some(120), refused));
}

/// Git stops repository discovery below the scratch directory.
#[test]
fn a_scratch_tree_without_its_git_directory_reaches_no_enclosing_repository() {
    let repo = Repo::new("ceiling");
    let outer = repo
        .command("git")
        .args(["init", "-q"])
        .current_dir(&repo.temp)
        .status()
        .expect("git starts");
    assert!(outer.success());
    fs::remove_dir_all(repo.repo.join(".git")).expect("the case's .git is removed");
    let found = repo
        .command("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .expect("git starts");
    assert!(
        !found.status.success(),
        "{}",
        String::from_utf8_lossy(&found.stdout)
    );
    assert!(found.stdout.is_empty());
}

#[test]
fn an_empty_summary_variable_or_an_empty_report_writes_no_summary() {
    let repo = Repo::new("no-summary");
    let summary = repo.temp.join("summary.md");
    let path = summary.to_str().expect("the path is UTF-8");
    let quiet = repo.change(&[("src/model.rs", "// unrelated\n")]);
    let run = repo.scan_env(
        &["--base", &repo.base, "--head", &quiet],
        &[("GITHUB_STEP_SUMMARY", path)],
    );
    assert_eq!(run.outcome(), (Some(0), ""));
    assert!(!summary.exists());
    repo.ignore_second("ignore");
    let run = repo.scan_env(&["--base", &repo.base], &[("GITHUB_STEP_SUMMARY", "")]);
    assert_eq!(run.code, Some(1));
    assert!(!run.stderr.contains("step summary"), "{}", run.stderr);
    assert!(one_line(&run.stderr), "{}", run.stderr);
}

#[test]
fn counts_past_u64_negative_counts_and_decimal_digits_outside_ascii_compare_by_value() {
    let repo = Repo::new("values");
    repo.change(&[
        (
            INVENTORY,
            "{\"seeds\": -1, \"seconds\": 123456789012345678901}",
        ),
        (
            "src/model.rs",
            "    b.max_branches = \u{661}\u{660};\n    b.max_branches\x1c=\x1c9;\n",
        ),
    ]);
    let head = repo.change(&[
        (
            INVENTORY,
            "{\"seeds\": -2, \"seconds\": 123456789012345678900}",
        ),
        (
            "src/model.rs",
            "    b.max_branches = \u{669};\n    b.max_branches\x1c=\x1c8;\n",
        ),
    ]);
    let run = repo.scan_parent(&head);
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    assert_eq!(
        run.lines(),
        [
            "blocks budget-lowered:src/model.rs max_branches at line 1: 10 -> 9",
            "blocks budget-lowered:src/model.rs max_branches at line 2: 9 -> 8",
            &format!("blocks budget-lowered:{INVENTORY} seeds: -1 -> -2"),
            &format!(
                "blocks budget-lowered:{INVENTORY} seconds: 123456789012345678901 -> 123456789012345678900"
            ),
        ]
    );
}

#[test]
fn a_budget_of_more_than_4300_digits_exits_two() {
    let repo = Repo::new("digit-limit");
    repo.change(&[(
        "src/model.rs",
        &format!("    b.max_branches = {};\n", "1".repeat(4301)),
    )]);
    let head = repo.change(&[(
        "src/model.rs",
        &format!("    b.max_branches = {};\n", "2".repeat(4301)),
    )]);
    let run = repo.scan_parent(&head);
    assert_eq!(run.outcome(), (Some(2), ""), "{}", run.stderr);
    assert_eq!(
        run.stderr,
        "scan-weakened-tests: a run of 4301 digits passes the limit of 4300 for integer conversion\n"
    );
}

#[test]
fn a_summary_path_with_a_trailing_separator_names_its_file() {
    let repo = Repo::new("summary-separator");
    repo.ignore_second("ignore");
    let path = format!("{}//summary.md/", repo.temp.display());
    let run = repo.scan_env(&["--base", &repo.base], &[("GITHUB_STEP_SUMMARY", &path)]);
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    let text = fs::read_to_string(repo.temp.join("summary.md")).expect("the summary reads");
    assert!(
        text.contains(&format!("blocks {KEY} second: not ignored -> #[ignore]\n")),
        "{text}"
    );
}

/// A change under a directory that stands at the inventory's path at the base runs the inventory check, which
/// refuses the directory as no file.
#[test]
fn a_change_under_an_inventory_directory_exits_two() {
    let repo = Repo::new("inventory-directory");
    let inner = format!("{INVENTORY}/x");
    repo.git(&["rm", "-q", "--", INVENTORY]);
    let base = repo.change(&[(&inner, "{}")]);
    let head = repo.change(&[(&inner, r#"{"seeds": 1}"#)]);
    let run = repo.scan(&["--base", &base, "--head", &head]);
    assert_eq!(run.outcome(), (Some(2), ""), "{}", run.stderr);
    let expected = format!(
        "scan-weakened-tests: {INVENTORY} at {} is not a file\n",
        &base[..12]
    );
    assert_eq!(run.stderr, expected);
}

/// A changed Rust path or timeout file whose entry at the base or the head is neither mode 100644 nor 100755
/// is refused, naming that commit: a link whose target holds an ignored test stands where the scan would read
/// the link's target path as Rust text. A path that begins with a colon is read as itself, and a carriage
/// return in the refused path is written `\r`.
#[test]
fn a_diffed_path_that_is_no_file_at_either_commit_exits_two() {
    let repo = Repo::new("not-a-file");
    let tests = test_fn("first") + &test_fn("second");
    let file = repo.change(&[("tests/t.rs", &tests)]);
    let ignored = tests.replace("#[test]\nfn second", "#[test]\n#[ignore]\nfn second");
    repo.write("tests/ignored.txt", ignored.as_bytes());
    repo.git(&["add", "tests/ignored.txt"]);
    let link = repo.link("tests/t.rs", "ignored.txt", "link");
    repo.reset(&link);
    fs::remove_file(repo.repo.join("tests/t.rs")).expect("the link is removed");
    let restored = repo.change(&[("tests/t.rs", &tests)]);
    repo.reset(&repo.base);
    let lane = repo.link("scripts/rust-lane.sh", "x", "lane link");
    repo.reset(&repo.base);
    let colon = repo.link(":t\r.rs", "ignored.txt", "colon link");
    for (base, head, named, path) in [
        (&file, &link, &link, "tests/t.rs"),
        (&link, &restored, &link, "tests/t.rs"),
        (&repo.base, &lane, &lane, "scripts/rust-lane.sh"),
        (&repo.base, &colon, &colon, ":t\\r.rs"),
    ] {
        let run = repo.scan(&["--base", base, "--head", head]);
        assert_eq!(run.outcome(), (Some(2), ""), "{path}: {}", run.stderr);
        let expected = format!(
            "scan-weakened-tests: {path} at {} is not a file\n",
            &named[..12]
        );
        assert_eq!(run.stderr, expected);
    }
}

/// Git reads no replacement object: a replace ref that maps the head's tree to the base's leaves the scan
/// reading the head's own tree, where an existing test gains an ignore, which the blob reader finds, and a
/// budget falls, which the zero-context diff finds.
#[test]
fn a_replace_ref_leaves_the_heads_own_tree_scanned() {
    let repo = Repo::new("replace-ref");
    repo.ignore_second("ignore");
    let lowered = repo.edit("src/model.rs", "SEEDS: u64 = 48", "SEEDS: u64 = 47");
    let head = repo.change(&[("src/model.rs", &lowered)]);
    let tree = |rev: &str| repo.git(&["rev-parse", &format!("{rev}^{{tree}}")]);
    repo.git(&["replace", &tree(&head), &tree(&repo.base)]);
    assert_eq!(repo.git(&["diff", "--name-only", &repo.base, &head]), "");
    let run = repo.scan_head(&head);
    let expected = format!(
        "blocks {KEY} second: not ignored -> #[ignore]\n\
         blocks budget-lowered:src/model.rs SEEDS at line 3: 48 -> 47\n"
    );
    assert_eq!(
        run.outcome(),
        (Some(1), expected.as_str()),
        "{}",
        run.stderr
    );
}

/// A gitlink added at a Rust path is refused whatever the submodule setting of the repository says: the scan
/// lists the changed paths with every submodule shown.
#[test]
fn a_gitlink_that_the_submodule_setting_hides_exits_two() {
    let repo = Repo::new("hidden-gitlink");
    let link = format!("160000,{},tests/t.rs", repo.base);
    repo.git(&["update-index", "--add", "--cacheinfo", &link]);
    repo.git(&["commit", "-q", "-m", "gitlink"]);
    let head = repo.git(&["rev-parse", "HEAD"]);
    repo.git(&["config", "diff.ignoreSubmodules", "all"]);
    assert_eq!(repo.git(&["diff", "--name-only", &repo.base, &head]), "");
    let run = repo.scan_head(&head);
    assert_eq!(run.outcome(), (Some(2), ""), "{}", run.stderr);
    assert_eq!(
        run.stderr,
        format!(
            "scan-weakened-tests: tests/t.rs at {} is not a file\n",
            &head[..12]
        )
    );
}

/// A timeout file of mode 100755 at both commits is a file, and its raised deadline reports.
#[test]
fn an_executable_timeout_file_is_read_as_a_file() {
    use std::os::unix::fs::PermissionsExt;
    let repo = Repo::new("executable-lane");
    let lane = "scripts/rust-lane.sh";
    fs::set_permissions(repo.repo.join(lane), fs::Permissions::from_mode(0o755))
        .expect("the mode is set");
    repo.git(&["add", "--", lane]);
    repo.git(&["commit", "-q", "-m", "executable"]);
    let base = repo.git(&["rev-parse", "HEAD"]);
    let head = repo.change(&[(lane, "  step check deadline 30m cargo check\n")]);
    for rev in [&base, &head] {
        let entry = repo.git(&["ls-tree", rev, "--", lane]);
        assert!(entry.starts_with("100755 "), "{entry}");
    }
    let run = repo.scan(&["--base", &base, "--head", &head]);
    let expected = format!("reports timeout-raised:{lane} deadline at line 1: 25 -> 30\n");
    assert_eq!(
        run.outcome(),
        (Some(0), expected.as_str()),
        "{}",
        run.stderr
    );
}

/// A changed Rust path that becomes a link in the second batch of the mode check is refused.
#[test]
fn a_link_in_a_later_batch_of_the_mode_check_exits_two() {
    let repo = Repo::new("batch-link");
    let names: Vec<String> = (0..300)
        .map(|index| format!("src/many/f{index:03}.rs"))
        .collect();
    for name in &names {
        repo.write(name, b"fn f() {}\n");
    }
    repo.git(&["add", "-A"]);
    repo.git(&["commit", "-q", "-m", "many files"]);
    let base = repo.git(&["rev-parse", "HEAD"]);
    for name in &names[..299] {
        repo.write(name, b"fn f() {}\n// x\n");
    }
    repo.git(&["add", "-A"]);
    fs::remove_file(repo.repo.join(&names[299])).expect("the file is removed");
    let head = repo.link(&names[299], "f000.rs", "link the last file");
    let run = repo.scan(&["--base", &base, "--head", &head]);
    assert_eq!(run.outcome(), (Some(2), ""), "{}", run.stderr);
    assert_eq!(
        run.stderr,
        format!(
            "scan-weakened-tests: {} at {} is not a file\n",
            names[299],
            &head[..12]
        )
    );
}

/// A key whose path holds a carriage return is written `\r` in the report and the hint; a commit line that
/// carries the carriage return itself acknowledges it, and the line with the written spelling does not.
#[test]
fn a_carriage_return_in_a_path_is_acknowledged_by_the_raw_character() {
    let repo = Repo::new("raw-acknowledgement");
    let path = "src/a\rb.rs";
    let base = repo.change(&[(path, "const SEEDS: u64 = 12;\n")]);
    let shown = "Lower it\n\nWeakens-Test: budget-lowered:src/a\\rb.rs: written spelling\n";
    let head = repo.commit(&[(path, "const SEEDS: u64 = 11;\n")], shown, &[]);
    let line = "budget-lowered:src/a\\rb.rs SEEDS at line 1: 12 -> 11";
    let run = repo.scan(&["--base", &base, "--head", &head]);
    let expected = format!("blocks {line}\n");
    assert_eq!(
        run.outcome(),
        (Some(1), expected.as_str()),
        "{}",
        run.stderr
    );
    let raw = format!("Acknowledge it\n\nWeakens-Test: budget-lowered:{path}: raw character\n");
    let acknowledged = repo.commit(&[], &raw, &[]);
    let run = repo.scan(&["--base", &base, "--head", &acknowledged]);
    let expected = format!("acknowledged {line} (Weakens-Test: raw character)\n");
    assert_eq!(
        run.outcome(),
        (Some(0), expected.as_str()),
        "{}",
        run.stderr
    );
}

const CASES: &str = "crates/kestrike-tools/tests";

/// A case of the tools crate that stands at the base and whose id is absent at the head blocks, keyed by the
/// base entry's path: a deleted case file, whose removed assertion still reports, a deleted case directory, a case renamed to another id, which is
/// the absence of its old id, and a directory whose `mod.rs` becomes `main.rs` beside the root `tools.rs`.
#[test]
fn a_removed_case_of_the_tools_crate_blocks() {
    let repo = Repo::new("case-removed");
    let base = repo.change(&[
        (&format!("{CASES}/tools.rs"), "mod one;\n"),
        (&format!("{CASES}/one.rs"), &test_fn("one")),
        (&format!("{CASES}/two/mod.rs"), "mod helper;\n"),
        (&format!("{CASES}/two/helper.rs"), "fn two() {}\n"),
        (&format!("{CASES}/three.rs"), "fn three() {}\n"),
    ]);
    let block = |path: &str, id: &str| {
        format!("blocks case-removed:{CASES}/{path} case {id}: present -> absent\n")
    };
    let path = |name: &str| format!("{CASES}/{name}");
    for (files, deleted, expected) in [
        (
            vec![],
            vec![path("one.rs")],
            format!(
                "reports assertions-removed:{CASES}/one.rs assert lines: 1 removed -> 0 added\n{}",
                block("one.rs", "one")
            ),
        ),
        (
            vec![],
            vec![path("two/mod.rs"), path("two/helper.rs")],
            block("two", "two"),
        ),
        (
            vec![(path("four.rs"), "fn three() {}\n")],
            vec![path("three.rs")],
            block("three.rs", "three"),
        ),
        (
            vec![(path("two/main.rs"), "mod helper;\n")],
            vec![path("two/mod.rs")],
            block("two", "two"),
        ),
    ] {
        let files: Vec<(&str, &str)> = files
            .iter()
            .map(|(name, text)| (name.as_str(), *text))
            .collect();
        let deleted: Vec<&str> = deleted.iter().map(String::as_str).collect();
        let head = repo.commit(&files, "change", &deleted);
        let run = repo.scan(&["--base", &base, "--head", &head]);
        assert_eq!(
            run.outcome(),
            (Some(1), expected.as_str()),
            "{}",
            run.stderr
        );
        repo.reset(&base);
    }
}

/// A case whose id stays at the head under another shape is present: a file that becomes a directory with
/// `mod.rs`, and a directory whose root `main.rs`, at a base without `tools.rs`, becomes `mod.rs` at a head
/// with it. A deletion below the top level of the case directory, of a name that starts with a dot, of a test
/// file of another crate, and of `tools.rs` is no case.
#[test]
fn a_case_that_keeps_its_id_or_a_deletion_outside_the_cases_is_no_finding() {
    let repo = Repo::new("case-kept");
    let path = |name: &str| format!("{CASES}/{name}");
    let base = repo.change(&[
        (&path("one.rs"), "fn one() {}\n"),
        (&path("two/main.rs"), "fn two() {}\n"),
        (&path("three/mod.rs"), "mod helper;\n"),
        (&path("three/helper.rs"), "fn three() {}\n"),
        (&path(".hidden.rs"), "fn hidden() {}\n"),
        ("crates/other/tests/four.rs", "fn four() {}\n"),
    ]);
    let head = repo.commit(
        &[
            (&path("tools.rs"), "mod one;\n"),
            (&path("one/mod.rs"), "fn one() {}\n"),
            (&path("two/mod.rs"), "fn two() {}\n"),
        ],
        "change",
        &[
            &path("one.rs"),
            &path("two/main.rs"),
            &path("three/helper.rs"),
            &path(".hidden.rs"),
            "crates/other/tests/four.rs",
        ],
    );
    let later = repo.commit(&[], "change", &[&path("tools.rs")]);
    for (from, to) in [(&base, &head), (&head, &later)] {
        let run = repo.scan(&["--base", from, "--head", to]);
        assert_eq!(run.outcome(), (Some(0), ""), "{}", run.stderr);
    }
}

/// A commit line `Weakens-Test: case-removed:<base entry path>: <reason>` in the range acknowledges the removal.
#[test]
fn an_acknowledged_case_removal_passes() {
    let repo = Repo::new("case-acknowledged");
    let path = format!("{CASES}/one.rs");
    let base = repo.change(&[(&path, "fn one() {}\n")]);
    let message = format!("Drop the case\n\nWeakens-Test: case-removed:{path}: merged into two\n");
    let head = repo.commit(&[], &message, &[&path]);
    let run = repo.scan(&["--base", &base, "--head", &head]);
    let expected = format!(
        "acknowledged case-removed:{path} case one: present -> absent (Weakens-Test: merged into two)\n"
    );
    assert_eq!(
        run.outcome(),
        (Some(0), expected.as_str()),
        "{}",
        run.stderr
    );
}

/// A Rust path that is a file at one commit and a tree at the other is refused whatever the tree holds: a
/// changed `.rs` file under the tree, listed in the same batch, leaves the tree's own record in place.
#[test]
fn a_rust_path_that_becomes_a_tree_exits_two_whatever_it_holds() {
    let repo = Repo::new("becomes-tree");
    for inner in ["x.rs", "x.txt"] {
        let file = repo.change(&[("src/foo.rs", "fn f() {}\n")]);
        repo.git(&["rm", "-q", "--", "src/foo.rs"]);
        let tree = repo.change(&[(&format!("src/foo.rs/{inner}"), "fn g() {}\n")]);
        repo.git(&["rm", "-q", "-r", "--", "src/foo.rs"]);
        let restored = repo.change(&[("src/foo.rs", "fn f() {}\n")]);
        for (base, head) in [(&file, &tree), (&tree, &restored)] {
            let run = repo.scan(&["--base", base, "--head", head]);
            assert_eq!(run.outcome(), (Some(2), ""), "{inner}: {}", run.stderr);
            assert_eq!(
                run.stderr,
                format!(
                    "scan-weakened-tests: src/foo.rs at {} is not a file\n",
                    &tree[..12]
                )
            );
        }
        repo.reset(&repo.base);
    }
}

/// A carriage return in an acknowledgement's reason is written `\r` in the acknowledged line on standard
/// output and in the step summary.
#[test]
fn a_carriage_return_in_an_acknowledgement_is_written_escaped() {
    let repo = Repo::new("reason-carriage-return");
    let head = repo.ignore_second(&format!(
        "Ignore it\n\nWeakens-Test: {KEY}: x\r::error::y\n"
    ));
    let summary = repo.temp.join("summary.md");
    let path = summary.to_str().expect("the path is UTF-8");
    let run = repo.scan_env(
        &["--base", &repo.base, "--head", &head],
        &[("GITHUB_STEP_SUMMARY", path)],
    );
    let line = format!(
        "acknowledged {KEY} second: not ignored -> #[ignore] (Weakens-Test: x\\r::error::y)\n"
    );
    assert_eq!(run.outcome(), (Some(0), line.as_str()), "{}", run.stderr);
    let text = fs::read_to_string(&summary).expect("the summary reads");
    assert!(text.contains(&line), "{text}");
}

/// A directory whose root is `main.rs` is a case at a commit whose test directory holds no regular
/// `tools.rs`, at the base and at the head alike; where the head holds `tools.rs`, its roots are `<id>.rs`
/// and `<id>/mod.rs` alone. A directory with both roots is one case.
#[test]
fn a_main_rs_root_is_a_case_at_a_commit_without_tools_rs() {
    let repo = Repo::new("case-main-root");
    let path = |name: &str| format!("{CASES}/{name}");
    let base = repo.change(&[
        (&path("two/main.rs"), "fn two() {}\n"),
        (&path("three/main.rs"), "fn three() {}\n"),
        (&path("three/mod.rs"), "fn three() {}\n"),
        (&path("one.rs"), "fn one() {}\n"),
    ]);
    let kept = repo.change(&[(&path("one.rs"), "fn one() { }\n")]);
    let harness = repo.change(&[(&path("tools.rs"), "mod one;\n")]);
    let block =
        |id: &str| format!("blocks case-removed:{CASES}/{id} case {id}: present -> absent\n");
    let run = repo.scan(&["--base", &base, "--head", &kept]);
    assert_eq!(run.outcome(), (Some(0), ""), "{}", run.stderr);
    let run = repo.scan(&["--base", &kept, "--head", &harness]);
    let expected = block("two");
    assert_eq!(
        run.outcome(),
        (Some(1), expected.as_str()),
        "{}",
        run.stderr
    );
    repo.reset(&base);
    let gone = repo.commit(
        &[],
        "change",
        &[&path("three/main.rs"), &path("three/mod.rs")],
    );
    let run = repo.scan(&["--base", &base, "--head", &gone]);
    let expected = block("three");
    assert_eq!(
        run.outcome(),
        (Some(1), expected.as_str()),
        "{}",
        run.stderr
    );
}

/// The step that runs the scan, from its name line to its `run` line: the step's own `env` sets the scan's
/// base, and its one `run` line starts the wrapper that guards the runner's command processing.
const SCAN_STEP: &str = "      - name: Weakened-test scan\n        env:\n          SCAN_BASE: ${{ \
                         github.event_name == 'pull_request' && 'HEAD^1' || github.event.before || \
                         'origin/main' }}\n        run: bash scripts/ci-scan-weakened-tests.sh --base \
                         \"$SCAN_BASE\"\n";

/// A path that holds the runner's legacy command text `##[error]` keeps its bytes in the report line: the
/// CI step's wrapper stops command processing around the scan, and an acknowledgement repeats the key as the
/// report spells it.
#[test]
fn a_legacy_command_text_in_a_path_keeps_its_bytes() {
    let repo = Repo::new("legacy-command");
    let head = repo.change(&[(
        "src/##[error]a_tests.rs",
        &format!("#[ignore]\n{}", test_fn("arrives")),
    )]);
    let run = repo.scan_head(&head);
    assert_eq!(
        run.outcome(),
        (
            Some(0),
            "reports ignore-new:src/##[error]a_tests.rs arrives: absent -> #[ignore]\n"
        ),
        "{}",
        run.stderr
    );
}

impl Repo {
    fn gitlink(&self, path: &str, message: &str) -> String {
        let entry = format!("160000,{},{path}", self.base);
        self.git(&["update-index", "--add", "--cacheinfo", &entry]);
        self.commit(&[], message, &[])
    }

    fn refused(&self, base: &str, head: &str, line: &str) {
        let run = self.scan(&["--base", base, "--head", head]);
        assert_eq!(run.outcome(), (Some(2), ""), "{line}: {}", run.stderr);
        assert_eq!(run.stderr, format!("scan-weakened-tests: {line}\n"));
    }
}

/// A fixed input or a changed Rust path with no entry at a commit, under a directory that is a link or a
/// submodule there, is refused as lying under that entry, at the base and at the head. The fixed inputs are
/// checked when the diff names none of them: the inventory under a link at both ends, the workflow file under
/// a link at the head alone, and the lane script that is a link at both ends while its target changes. An ancestor that is a regular file leaves the path absent, which
/// reads as a deleted or an added file.
#[test]
fn a_path_under_a_link_or_a_submodule_at_either_commit_exits_two() {
    let repo = Repo::new("linked-ancestor");
    let [a, b, f] = rows();
    let lane = fs::read_to_string(repo.repo.join("scripts/rust-lane.sh")).expect("the lane reads");
    let lowered = |seeds| inventory(&[a.clone(), b.with("seeds", J::N(seeds)), f.clone()]);
    let short = |commit: &str| commit[..12].to_owned();
    repo.git(&["rm", "-r", "-q", "scripts"]);
    repo.commit(
        &[
            ("moved/test-inventory.json", &lowered(3)),
            ("moved/rust-lane.sh", &lane),
        ],
        "move",
        &[],
    );
    let linked = repo.link("scripts", "moved", "link the scripts");
    let restore = |message: &str| {
        repo.git(&["rm", "-q", "--cached", "scripts"]);
        let _ = fs::remove_file(repo.repo.join("scripts"));
        repo.commit(
            &[
                (INVENTORY, &inventory(&rows())),
                ("scripts/rust-lane.sh", &lane),
            ],
            message,
            &[],
        )
    };
    let restored = restore("restore the scripts");
    repo.reset(&linked);
    let relowered = repo.change(&[("moved/test-inventory.json", &lowered(2))]);
    repo.reset(&repo.base);
    repo.git(&["rm", "-r", "-q", "scripts"]);
    let submodule = repo.gitlink("scripts", "a submodule at scripts");
    let unlinked = restore("restore the scripts beside the submodule");
    repo.reset(&repo.base);
    repo.git(&["rm", "-r", "-q", "scripts"]);
    let file = repo.change(&[("scripts", "a file\n")]);
    let after_file = restore("restore the scripts beside the file");
    repo.reset(&repo.base);
    let tests = test_fn("first") + &test_fn("second");
    let rust = repo.change(&[("tests/t.rs", &tests)]);
    repo.git(&["rm", "-r", "-q", "tests"]);
    let ignored = tests.replace("#[test]\nfn second", "#[test]\n#[ignore]\nfn second");
    repo.commit(&[("moved_tests/t.rs", &ignored)], "move the tests", &[]);
    let rust_linked = repo.link("tests", "moved_tests", "link the tests");
    repo.reset(&repo.base);
    let workflow = ".github/workflows/agent-checks.yml";
    let flow = fs::read_to_string(repo.repo.join(workflow)).expect("the workflow reads");
    let unflowed = repo.commit(&[], "drop the workflow", &[workflow]);
    repo.change(&[("elsewhere/agent-checks.yml", &flow.replace("15", "20"))]);
    let flow_linked = repo.link(".github/workflows", "../elsewhere", "link the workflows");
    repo.reset(&repo.base);
    let lane_path = "scripts/rust-lane.sh";
    repo.git(&["rm", "-q", lane_path]);
    repo.change(&[("scripts/lane.txt", &lane)]);
    let lane_linked = repo.link(lane_path, "lane.txt", "link the lane");
    let lane_raised = repo.change(&[("scripts/lane.txt", &lane.replace("25m", "40m"))]);
    let under = |path: &str, commit: &str, ancestor: &str, kind: &str| {
        format!(
            "{path} at {} lies under {ancestor}, which is {kind}",
            short(commit)
        )
    };
    for (base, head, line) in [
        (
            &repo.base,
            &linked,
            under(lane_path, &linked, "scripts", "a link"),
        ),
        (
            &linked,
            &restored,
            under(lane_path, &linked, "scripts", "a link"),
        ),
        (
            &linked,
            &relowered,
            under(INVENTORY, &linked, "scripts", "a link"),
        ),
        (
            &repo.base,
            &submodule,
            under(lane_path, &submodule, "scripts", "a submodule"),
        ),
        (
            &submodule,
            &unlinked,
            under(lane_path, &submodule, "scripts", "a submodule"),
        ),
        (
            &rust,
            &rust_linked,
            under("tests/t.rs", &rust_linked, "tests", "a link"),
        ),
        (
            &unflowed,
            &flow_linked,
            under(workflow, &flow_linked, ".github/workflows", "a link"),
        ),
        (
            &lane_linked,
            &lane_raised,
            format!("{lane_path} at {} is not a file", short(&lane_linked)),
        ),
    ] {
        repo.refused(base, head, &line);
    }
    for (base, head) in [(&repo.base, &file), (&file, &after_file)] {
        let run = repo.scan(&["--base", base, "--head", head]);
        assert_eq!(run.outcome(), (Some(0), ""), "{}", run.stderr);
        assert_eq!(run.stderr, "");
    }
}

/// The tools crate's test directory is refused at a commit where it is a link or a submodule, or lies under
/// one, whatever paths the range changes: the cases a checkout reads stand behind that entry.
#[test]
fn a_case_directory_under_a_link_or_a_submodule_exits_two() {
    let repo = Repo::new("linked-cases");
    let short = |commit: &str| commit[..12].to_owned();
    repo.change(&[
        ("other/tests/tools.rs", "mod one;\n"),
        ("other/tests/one.rs", &test_fn("one")),
    ]);
    let crate_linked = repo.link("crates/kestrike-tools", "../other", "link the crate");
    let crate_gone = repo.commit(&[], "remove a case", &["other/tests/one.rs"]);
    repo.reset(&repo.base);
    repo.change(&[
        ("elsewhere/tools.rs", "mod one;\n"),
        ("elsewhere/one.rs", &test_fn("one")),
    ]);
    let cases_linked = repo.link(CASES, "../../elsewhere", "link the cases");
    let cases_gone = repo.commit(&[], "remove a case", &["elsewhere/one.rs"]);
    repo.reset(&repo.base);
    let cases_module = repo.gitlink(CASES, "a submodule at the cases");
    let cases_later = repo.change(&[("src/later.rs", "fn later() {}\n")]);
    repo.reset(&repo.base);
    let crates_module = repo.gitlink("crates", "a submodule at crates");
    repo.git(&["rm", "-q", "--cached", "crates"]);
    let crates_later = repo.change(&[("src/later.rs", "fn later() {}\n")]);
    for (base, head, line) in [
        (
            &crate_linked,
            &crate_gone,
            format!(
                "{CASES} at {} lies under crates/kestrike-tools, which is a link",
                short(&crate_gone)
            ),
        ),
        (
            &cases_linked,
            &cases_gone,
            format!("{CASES} at {} is a link", short(&cases_gone)),
        ),
        (
            &cases_module,
            &cases_later,
            format!("{CASES} at {} is a submodule", short(&cases_later)),
        ),
        (
            &crates_module,
            &crates_later,
            format!(
                "{CASES} at {} lies under crates, which is a submodule",
                short(&crates_module)
            ),
        ),
    ] {
        repo.refused(base, head, &line);
    }
}

/// A refusal that holds a path, a request or Git's own standard error is one line: a blob that is not UTF-8
/// at a path with a carriage return, a failed Git call whose argument holds one, Git's standard error of many
/// lines, and an inventory value whose key holds a line feed.
#[test]
fn a_refusal_that_holds_a_line_break_is_written_escaped() {
    let repo = Repo::new("refusal-lines");
    repo.write("src/a\r::error::b.rs", b"// \xff\n");
    repo.git(&["add", "--", "src/a\r::error::b.rs"]);
    let blob = repo.commit(&[], "a byte outside UTF-8", &[]);
    let run = repo.scan_env(&["--base", &repo.base, "--head", &blob], &[("LC_ALL", "C")]);
    assert_eq!(run.outcome(), (Some(2), ""), "{}", run.stderr);
    assert_eq!(
        run.stderr,
        format!(
            "scan-weakened-tests: {blob}:src/a\\r::error::b.rs: invalid utf-8 sequence of 1 bytes \
             from index 3\n"
        )
    );
    let run = repo.scan_env(&["--base", "a\r::error::b"], &[("LC_ALL", "C")]);
    assert_eq!(run.outcome(), (Some(2), ""), "{}", run.stderr);
    assert_eq!(
        run.stderr,
        "scan-weakened-tests: git rev-parse --verify --end-of-options a\\r::error::b^{commit}: \
         fatal: Needed a single revision\n"
    );
    let run = repo.scan_env(
        &["--base", "no-such-revision"],
        &[("GIT_TRACE", "1"), ("LC_ALL", "C")],
    );
    assert_eq!(run.outcome(), (Some(2), ""), "{}", run.stderr);
    assert!(one_line(&run.stderr), "{}", run.stderr);
    assert!(run.stderr.contains("trace: "), "{}", run.stderr);
    assert!(
        run.stderr.ends_with("\\nfatal: Needed a single revision\n"),
        "{}",
        run.stderr
    );
    repo.reset(&repo.base);
    let old = repo.change(&[(INVENTORY, r#"{"a\n::x": {"seeds": 4}}"#)]);
    let new = repo.change(&[(INVENTORY, r#"{"a\n::x": {"seeds": "4"}}"#)]);
    repo.refused(
        &old,
        &new,
        &format!("{INVENTORY}: the value at a\\n::x.seeds changes from an integer to a text"),
    );
}

/// A code point that reorders or breaks a displayed line is written as `repr` writes it in a report line: a
/// bidirectional control, a line or paragraph separator and a byte order mark. A path of printable code
/// points outside ASCII keeps its bytes.
#[test]
fn a_bidirectional_control_in_a_path_is_written_escaped() {
    let repo = Repo::new("bidi-path");
    for (code, written) in [
        ('\u{202e}', "\\u202e"),
        ('\u{2066}', "\\u2066"),
        ('\u{200f}', "\\u200f"),
        ('\u{2028}', "\\u2028"),
        ('\u{2029}', "\\u2029"),
        ('\u{feff}', "\\ufeff"),
        ('\u{e9}', "\u{e9}"),
    ] {
        let head = repo.change(&[(
            &format!("src/a{code}b_tests.rs"),
            &format!("#[ignore]\n{}", test_fn("arrives")),
        )]);
        let run = repo.scan_head(&head);
        let line =
            format!("reports ignore-new:src/a{written}b_tests.rs arrives: absent -> #[ignore]\n");
        assert_eq!(run.outcome(), (Some(0), line.as_str()), "{}", run.stderr);
        repo.reset(&repo.base);
    }
}

impl Repo {
    fn add_bytes(&self, names: &[&[u8]]) -> String {
        use std::ffi::OsStr;
        for &name in names {
            let path = self.repo.join(OsStr::from_bytes(name));
            fs::create_dir_all(path.parent().expect("a file has a parent"))
                .expect("the parent is made");
            fs::write(&path, "fixture\n").expect("the file is written");
            let added = self
                .command("git")
                .args(["add", "--"])
                .arg(OsStr::from_bytes(name))
                .status()
                .expect("git starts");
            assert!(added.success());
        }
        self.commit(&[], "names outside UTF-8", &[])
    }
}

/// An unchanged name that is not UTF-8 beside an ancestor of a changed Rust file and beside the inventory
/// leaves the range as the base read it: exit 0, nothing on either stream.
#[test]
fn a_name_outside_utf8_beside_a_scanned_path_reads_as_before() {
    let repo = Repo::new("quiet-neighbors");
    let neighbors = repo.add_bytes(&[b"src/\xff", b"scripts/\xff"]);
    let changed = repo.change(&[("src/deep/x.rs", "fn x() {}\n")]);
    let run = repo.scan(&["--base", &neighbors, "--head", &changed]);
    assert_eq!(run.outcome(), (Some(0), ""), "{}", run.stderr);
    assert_eq!(run.stderr, "");
}

/// An unchanged name that is not UTF-8 in a fixture of the tools crate's test directory leaves a range that
/// changes nothing under that directory as the base read it.
#[test]
fn a_name_outside_utf8_in_an_unchanged_case_directory_reads_as_before() {
    let repo = Repo::new("quiet-cases");
    let fixture = repo.add_bytes(&[b"crates/kestrike-tools/tests/fixtures/\xff"]);
    let changed = repo.change(&[("src/later.rs", "fn later() {}\n")]);
    let run = repo.scan(&["--base", &fixture, "--head", &changed]);
    assert_eq!(run.outcome(), (Some(0), ""), "{}", run.stderr);
    assert_eq!(run.stderr, "");
}

/// A Rust path 1,900 directories deep, whose ancestors' names together pass the 2,621,440-byte argument
/// limit of a Linux host with an 8 MiB stack, reads as any other added file.
#[test]
fn a_path_whose_ancestors_pass_the_argument_limit_reads_as_before() {
    let repo = Repo::new("deep-path");
    let deep = format!("{}x.rs", "a/".repeat(1900));
    let ancestors: usize = (1..=1900).map(|depth| 2 * depth).sum();
    assert!(ancestors > 2_621_440);
    let blob = repo.git(&["rev-parse", &format!("{}:src/model.rs", repo.base)]);
    let entry = format!("100644,{blob},{deep}");
    repo.git(&["update-index", "--add", "--cacheinfo", &entry]);
    let head = repo.commit(&[], "a deep path", &[]);
    let run = repo.scan_head(&head);
    assert_eq!(run.outcome(), (Some(0), ""), "{}", run.stderr);
    assert_eq!(run.stderr, "");
}

impl Repo {
    fn git_stdin(&self, args: &[&str], input: &str) -> String {
        use std::io::Write;
        let mut child = self
            .command("git")
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("git starts");
        child
            .stdin
            .take()
            .expect("the input is piped")
            .write_all(input.as_bytes())
            .expect("the input is written");
        let output = child.wait_with_output().expect("git exits");
        assert!(output.status.success(), "git {args:?}");
        String::from_utf8(output.stdout)
            .expect("git writes UTF-8")
            .trim()
            .to_owned()
    }
}

/// An inventory entry that is a tree at either commit, the empty tree included, is refused as no file,
/// although an empty tree lists no path under it in the diff.
#[test]
fn an_inventory_that_is_an_empty_tree_at_either_commit_exits_two() {
    let repo = Repo::new("empty-tree-inventory");
    let empty = repo.git_stdin(&["mktree"], "");
    let scripts: String = repo
        .git(&["ls-tree", &repo.base, "scripts/"])
        .lines()
        .map(|line| {
            let (head, path) = line.split_once('\t').expect("a record holds a tab");
            let name = path
                .strip_prefix("scripts/")
                .expect("the path lies in scripts");
            if name == "test-inventory.json" {
                format!("040000 tree {empty}\t{name}\n")
            } else {
                format!("{head}\t{name}\n")
            }
        })
        .collect();
    let scripts = repo.git_stdin(&["mktree"], &scripts);
    let root: String = repo
        .git(&["ls-tree", &repo.base])
        .lines()
        .map(|line| {
            let (head, name) = line.split_once('\t').expect("a record holds a tab");
            if name == "scripts" {
                format!("040000 tree {scripts}\t{name}\n")
            } else {
                format!("{head}\t{name}\n")
            }
        })
        .collect();
    let root = repo.git_stdin(&["mktree"], &root);
    let tree = repo.git(&[
        "commit-tree",
        &root,
        "-p",
        &repo.base,
        "-m",
        "an empty tree",
    ]);
    let base_tree = format!("{}^{{tree}}", repo.base);
    let file = repo.git(&["commit-tree", &base_tree, "-p", &tree, "-m", "a file again"]);
    let line = format!("{INVENTORY} at {} is not a file", &tree[..12]);
    repo.refused(&repo.base, &tree, &line);
    repo.refused(&tree, &file, &line);
}
