use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use super::chaos_checks::{HOST_STOP_CASES, HOST_STOP_RUN};
use super::push::{Fixture, STUB};

const INPUT: &str = "scripts/host-stop-fixtures/operator.json";

fn row(fx: &Fixture) -> (String, String) {
    let held = fx.commit(&[(HOST_STOP_CASES, "")]);
    let head = fx.commit(&[(INPUT, "{}\n")]);
    (held, head)
}

fn own(fx: &Fixture) -> PathBuf {
    fx.top.join("target/tools/pre-push.d")
}

fn entries(directory: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(directory)
        .expect("the directory lists")
        .map(|entry| {
            entry
                .expect("the directory lists")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

fn in_own(fx: &Fixture, directory: &str) {
    let own = fs::canonicalize(own(fx)).expect("the tool's directory resolves");
    let directory = Path::new(directory);
    assert_eq!(directory.parent(), Some(own.as_path()));
    let name = directory
        .file_name()
        .expect("the worktree has a name")
        .to_string_lossy();
    assert!(name.starts_with("kestrike-pre-push-"), "{name}");
    assert!(!directory.exists(), "{name} is removed");
}

fn above(directory: &Path, entry: &Path) -> bool {
    let planted = fs::read(entry).expect("the planted entry reads");
    directory.ancestors().any(|ancestor| {
        fs::read(ancestor.join(".cargo/config.toml")).is_ok_and(|bytes| bytes == planted)
    })
}

#[test]
fn a_push_that_selects_the_row_with_tmpdir_unset_runs_it_under_the_checkout() {
    let mut fx = Fixture::new();
    let (held, head) = row(&fx);
    for value in [None, Some("")] {
        fx.clear();
        match value {
            Some(value) => fx.set("TMPDIR", value),
            None => fx.unset("TMPDIR"),
        }
        let run = fx.push(&[(&head, &held)]);
        assert_eq!(run.code, Some(0), "{value:?}: {}", run.stderr);
        assert_eq!(fx.ran(), [HOST_STOP_RUN], "{value:?}");
        let dirs = fx.cargo_dirs();
        assert_eq!(dirs.len(), 1, "{dirs:?}");
        in_own(&fx, &dirs[0]);
        let mode = fs::symlink_metadata(own(&fx))
            .expect("the tool's directory stands")
            .permissions()
            .mode();
        assert_eq!(mode & 0o7777, 0o700, "{mode:o}");
        assert_eq!(entries(&own(&fx)), ["lock"]);
        assert_eq!(fx.worktrees(), 1);
    }
}

#[test]
fn a_cargo_configuration_planted_in_the_scratch_parent_is_not_above_the_row_s_worktree() {
    let fx = Fixture::new();
    let planted = fx.tmp.join(".cargo/config.toml");
    fs::create_dir(fx.tmp.join(".cargo")).expect("the directory is made");
    fs::write(&planted, "[alias]\nplanted = \"version\"\n").expect("the entry is planted");
    let (held, head) = row(&fx);
    let run = fx.push(&[(&head, &held)]);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    let dirs = fx.cargo_dirs();
    assert_eq!(dirs.len(), 1, "{dirs:?}");
    assert!(!above(Path::new(&dirs[0]), &planted), "{dirs:?}");
    let plain = fx.commit(&[
        ("scripts/test-inventory.json", r#"{"rows": []}"#),
        ("scripts/test-select-tests.py", &format!("# env\n{STUB}")),
    ]);
    let run = fx.push(&[(&plain, &head)]);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    let logged = fs::read_to_string(fx.logged(".where")).expect("the check logs its directory");
    let directory = logged.lines().next().expect("the directory is logged");
    assert!(above(Path::new(directory), &planted), "{directory}");
}

#[test]
fn a_tip_with_no_cargo_row_keeps_its_worktree_under_the_scratch_parent() {
    let fx = Fixture::new();
    let plain = fx.commit(&[
        ("scripts/test-inventory.json", r#"{"rows": []}"#),
        ("scripts/test-select-tests.py", &format!("# env\n{STUB}")),
    ]);
    let run = fx.push(&[(&plain, &fx.base)]);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert_eq!(entries(&fx.top), ["Cargo.lock"]);
    let (held, head) = row(&fx);
    fx.clear();
    let run = fx.push(&[(&plain, &fx.base), (&head, &held)]);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    let tmp = fs::canonicalize(&fx.tmp).expect("the tool's TMPDIR resolves");
    let logged = fs::read_to_string(fx.logged(".where")).expect("the check logs its directory");
    let mut lines = logged.lines();
    let directory = Path::new(lines.next().expect("the directory is logged"));
    assert_eq!(directory.parent(), Some(tmp.as_path()), "{logged}");
    assert_eq!(lines.next(), Some("drwx------"), "{logged}");
    let dirs = fx.cargo_dirs();
    assert_eq!(dirs.len(), 1, "{dirs:?}");
    in_own(&fx, &dirs[0]);
    assert!(fx.left().is_empty(), "{:?}", fx.left());
    assert_eq!(fx.worktrees(), 1);
}

#[test]
fn every_check_of_a_tip_with_the_row_runs_in_the_one_worktree_under_the_checkout() {
    let fx = Fixture::new();
    let held = fx.commit(&[(HOST_STOP_CASES, "")]);
    let head = fx.commit(&[
        (INPUT, "{}\n"),
        ("scripts/test-inventory.json", r#"{"rows": []}"#),
        ("scripts/test-select-tests.py", &format!("# env\n{STUB}")),
    ]);
    let run = fx.push(&[(&head, &held)]);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert_eq!(
        fx.ran(),
        [
            "test-select-tests.py",
            "verify-receipts.py admit",
            HOST_STOP_RUN
        ]
    );
    let logged = fs::read_to_string(fx.logged(".where")).expect("the check logs its directory");
    let mut lines = logged.lines();
    let directory = lines.next().expect("the directory is logged");
    assert_eq!(fx.cargo_dirs(), [directory]);
    in_own(&fx, directory);
    assert_eq!(lines.next(), Some("drwx------"), "{logged}");
    assert!(fx.left().is_empty(), "{:?}", fx.left());
}

#[test]
fn an_entry_in_the_place_of_the_tool_s_directory_is_refused_with_its_line() {
    let fx = Fixture::new();
    let (held, head) = row(&fx);
    let tools = fx.top.join("target/tools");
    fs::create_dir_all(&tools).expect("the build directory is made");
    let own = own(&fx);
    let elsewhere = fx.temp.join("elsewhere");
    fs::create_dir(&elsewhere).expect("the directory is made");
    type Step = fn(&Path, &Path);
    let states: [(&str, Step, Step); 4] = [
        (
            "is a link",
            |own, elsewhere| symlink(elsewhere, own).expect("the link is made"),
            |own, _| fs::remove_file(own).expect("the link is removed"),
        ),
        (
            "is a link",
            |own, _| symlink("absent", own).expect("the link is made"),
            |own, _| fs::remove_file(own).expect("the link is removed"),
        ),
        (
            "is no directory",
            |own, _| fs::write(own, "").expect("the file is made"),
            |own, _| fs::remove_file(own).expect("the file is removed"),
        ),
        (
            "is writable by its group or by other users",
            |own, _| {
                fs::create_dir(own).expect("the directory is made");
                fs::set_permissions(own, fs::Permissions::from_mode(0o770))
                    .expect("the mode is set");
            },
            |own, _| fs::remove_dir(own).expect("the directory is removed"),
        ),
    ];
    for (state, make, clear) in states {
        make(&own, &elsewhere);
        let run = fx.push(&[(&head, &held)]);
        assert_eq!(run.code, Some(2), "{state}: {}", run.stderr);
        assert!(
            run.stderr.ends_with(&format!(
                "pre-push: the worktree directory {} {state}; remove it, and the next push makes \
                 it\n",
                own.display()
            )),
            "{state}: {}",
            run.stderr
        );
        assert_eq!(fx.ran(), Vec::<String>::new(), "{state}");
        assert_eq!(fx.worktrees(), 1, "{state}");
        assert!(entries(&elsewhere).is_empty(), "{state}");
        assert!(!tools.join("absent").exists(), "{state}");
        clear(&own, &elsewhere);
    }
    let run = fx.push(&[(&head, &held)]);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert_eq!(fx.ran(), [HOST_STOP_RUN]);
    fx.clear();
    let run = fx.push(&[(&head, &held)]);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert_eq!(fx.ran(), [HOST_STOP_RUN]);
    assert_eq!(entries(&own), ["lock"]);
}

#[test]
fn a_configuration_file_that_differs_from_the_tip_s_is_named_and_the_row_still_runs() {
    let fx = Fixture::new();
    let held = fx.commit(&[
        (HOST_STOP_CASES, ""),
        (".cargo/config.toml", "[alias]\ntip = \"version\"\n"),
    ]);
    let head = fx.commit(&[(INPUT, "{}\n")]);
    let note = |name: &str| {
        format!(
            "pre-push: {}: the working copy's {name} differs from the tip's, and the row's build \
             reads it beside the tip's\n",
            &head[..12]
        )
    };
    let noted = |fx: &Fixture| -> Vec<String> {
        fx.clear();
        let run = fx.push(&[(&head, &held)]);
        assert_eq!(run.code, Some(0), "{}", run.stderr);
        assert_eq!(fx.ran(), [HOST_STOP_RUN]);
        run.stderr
            .lines()
            .filter(|line| line.contains("the working copy's"))
            .map(|line| format!("{line}\n"))
            .collect()
    };
    let config = fx.top.join(".cargo/config.toml");
    assert_eq!(noted(&fx), [note(".cargo/config.toml")]);
    fs::create_dir(fx.top.join(".cargo")).expect("the directory is made");
    fs::write(&config, "[alias]\ntip = \"version\"\n").expect("the file is written");
    assert_eq!(noted(&fx), Vec::<String>::new());
    fs::write(&config, "[alias]\ntip = \"version\"\nown = \"version\"\n")
        .expect("the file is written");
    assert_eq!(noted(&fx), [note(".cargo/config.toml")]);
    fs::write(fx.top.join("rust-toolchain.toml"), "[toolchain]\n").expect("the file is written");
    assert_eq!(
        noted(&fx),
        [note(".cargo/config.toml"), note("rust-toolchain.toml")]
    );
    fs::write(&config, "[alias]\ntip = \"version\"\n").expect("the file is written");
    assert_eq!(noted(&fx), [note("rust-toolchain.toml")]);
    fs::remove_file(fx.top.join("rust-toolchain.toml")).expect("the file is removed");
    fs::create_dir(fx.top.join("rust-toolchain")).expect("the directory is made");
    assert_eq!(noted(&fx), [note("rust-toolchain")]);
    fs::remove_dir(fx.top.join("rust-toolchain")).expect("the directory is removed");
    let long = "#".repeat((1 << 20) + 1);
    fs::write(fx.top.join(".cargo/config"), &long).expect("the file is written");
    let both = fx.commit(&[(".cargo/config", &long), (INPUT, "{\"x\": 1}\n")]);
    fx.clear();
    let run = fx.push(&[(&both, &head)]);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert!(
        run.stderr.contains(&format!(
            "pre-push: {}: the working copy's .cargo/config differs from the tip's",
            &both[..12]
        )),
        "{}",
        run.stderr
    );
    assert_eq!(fx.ran(), [HOST_STOP_RUN]);
}

#[test]
fn a_worktree_under_the_working_copy_itself_is_added_and_removed_as_under_the_scratch_parent() {
    let mut fx = Fixture::new();
    fx.top = fx.repo.clone();
    let (held, head) = row(&fx);
    let run = fx.push(&[(&head, &held)]);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert_eq!(fx.ran(), [HOST_STOP_RUN]);
    let dirs = fx.cargo_dirs();
    assert_eq!(dirs.len(), 1, "{dirs:?}");
    in_own(&fx, &dirs[0]);
    assert_eq!(fx.worktrees(), 1);
    assert_eq!(fx.git(&["status", "--porcelain"]), "?? target/");
    assert_eq!(fx.git(&["rev-parse", "HEAD"]), head);
}
