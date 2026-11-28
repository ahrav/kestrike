use std::fs::{self, DirBuilder, File};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Stdio;

use super::chaos_checks::{HOST_STOP_CASES, HOST_STOP_RUN};
use super::push::{
    BINARY, Fixture, Tool, alive, finished, group_ended, process_id, signal, waited,
};

const INPUT: &str = "scripts/host-stop-fixtures/operator.json";
const WAITING: &str = "waiting for the lock";

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

fn start(fx: &Fixture, top: &Path, input: &str, errors: &Path) -> Tool {
    let errors = File::options()
        .write(true)
        .create_new(true)
        .open(errors)
        .expect("the file of the tool's standard error is made");
    let mut command = fx.command(BINARY);
    let mut child = command
        .arg(top)
        .args(["pre-push-checks", "origin", "url"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(errors)
        .spawn()
        .expect("the tool starts");
    let mut stdin = child.stdin.take().expect("standard input is piped");
    let tool = Tool::from(child);
    stdin
        .write_all(input.as_bytes())
        .expect("the ref lines are written");
    tool
}

fn written(errors: &Path) -> String {
    fs::read_to_string(errors).expect("the tool's standard error reads")
}

fn locked(file: &File) -> bool {
    // SAFETY: `flock` takes an open descriptor and integer flags and touches no memory of the caller.
    unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) == 0 }
}

fn released(file: File) -> File {
    // SAFETY: `flock` takes an open descriptor and integer flags and touches no memory of the caller.
    assert_eq!(unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) }, 0);
    file
}

fn opened(fx: &Fixture) -> File {
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(own(fx))
        .expect("the tool's directory is made");
    File::options()
        .write(true)
        .create(true)
        .truncate(false)
        .open(own(fx).join("lock"))
        .expect("the lock file opens")
}

fn marks(fx: &Fixture) -> usize {
    entries(&fx.temp)
        .iter()
        .filter(|name| name.starts_with("stub.log.unit."))
        .count()
}

struct Pair {
    tips: [String; 2],
    units: Vec<String>,
    errors: [String; 2],
}

fn pair(one_checkout: bool) -> Pair {
    let mut fx = Fixture::new();
    fx.set("STUB_BUILT", fx.temp.join("built"));
    let held = fx.commit(&[(HOST_STOP_CASES, "")]);
    let first = fx.commit(&[(INPUT, "{\"tip\": 1}\n")]);
    fx.git(&["checkout", "-q", "--detach", &held]);
    let second = fx.commit(&[(INPUT, "{\"tip\": 2}\n")]);
    let other = fx.temp.join("other");
    DirBuilder::new()
        .mode(0o700)
        .create(&other)
        .expect("the second checkout's top is made");
    let tops = [
        fx.top.clone(),
        if one_checkout { fx.top.clone() } else { other },
    ];
    let logs = [fx.temp.join("first.err"), fx.temp.join("second.err")];
    let a = start(&fx, &tops[0], &Fixture::input(&[(&first, &held)]), &logs[0]);
    assert!(waited(|| marks(&fx) == 1), "the first push's cargo starts");
    let b = start(
        &fx,
        &tops[1],
        &Fixture::input(&[(&second, &held)]),
        &logs[1],
    );
    if one_checkout {
        assert!(
            waited(|| written(&logs[1]).contains(WAITING)),
            "the second push waits for the lock: {}",
            written(&logs[1])
        );
        assert_eq!(marks(&fx), 1, "one cargo runs while the lock is held");
        fs::write(fx.logged(".release"), "").expect("the first push's cargo is released");
    }
    let codes = [finished(a).code, finished(b).code];
    let errors = [written(&logs[0]), written(&logs[1])];
    assert_eq!(codes, [Some(0), Some(0)], "{errors:?}");
    assert_eq!(fx.worktrees(), 1);
    let units = fs::read_to_string(fx.logged(".units")).expect("the stand-in logs each unit");
    Pair {
        tips: [first, second],
        units: units.lines().map(str::to_owned).collect(),
        errors,
    }
}

#[test]
fn two_pushes_of_one_checkout_each_run_what_their_own_tip_built() {
    let Pair {
        tips: [first, second],
        units,
        errors,
    } = pair(true);
    assert_eq!(
        units,
        [format!("{first} {first}"), format!("{second} {second}")]
    );
    assert!(!errors[0].contains(WAITING), "{}", errors[0]);
    assert_eq!(errors[1].matches(WAITING).count(), 1, "{}", errors[1]);
    let Pair {
        tips,
        units,
        errors,
    } = pair(false);
    assert_eq!(units.len(), 2, "{units:?}");
    let mixed: Vec<&String> = units
        .iter()
        .filter(|unit| {
            let (own, built) = unit.split_once(' ').expect("a unit names two tips");
            assert!(tips.iter().any(|tip| tip == built), "{unit}");
            own != built
        })
        .collect();
    assert_eq!(mixed.len(), 1, "{units:?}");
    assert!(
        !errors.iter().any(|text| text.contains(WAITING)),
        "{errors:?}"
    );
}

#[test]
fn a_push_that_waits_for_the_lock_ends_on_a_signal_or_runs_the_row_once_the_lock_is_free() {
    let fx = Fixture::new();
    let (held, head) = row(&fx);
    let input = Fixture::input(&[(&head, &held)]);
    let lock = opened(&fx);
    assert!(locked(&lock), "the case takes the lock");
    let errors = fx.temp.join("cancelled.err");
    let tool = start(&fx, &fx.top, &input, &errors);
    assert!(
        waited(|| written(&errors).contains(WAITING)),
        "{}",
        written(&errors)
    );
    signal(tool.id(), libc::SIGTERM);
    let run = finished(tool);
    assert_eq!(run.code, Some(128 + libc::SIGTERM), "{}", written(&errors));
    assert_eq!(fx.ran(), Vec::<String>::new());
    assert_eq!(fx.worktrees(), 1);
    assert_eq!(entries(&own(&fx)), ["lock"]);
    let errors = fx.temp.join("released.err");
    let tool = start(&fx, &fx.top, &input, &errors);
    assert!(
        waited(|| written(&errors).contains(WAITING)),
        "{}",
        written(&errors)
    );
    assert_eq!(fx.ran(), Vec::<String>::new());
    drop(released(lock));
    let run = finished(tool);
    assert_eq!(run.code, Some(0), "{}", written(&errors));
    assert_eq!(fx.ran(), [HOST_STOP_RUN]);
    assert_eq!(
        written(&errors).lines().last(),
        Some(
            format!(
                "pre-push: {}: waiting for the lock {}, which another push of this checkout holds",
                &head[..12],
                own(&fx).join("lock").display()
            )
            .as_str()
        )
    );
    assert_eq!(fx.worktrees(), 1);
    assert_eq!(entries(&own(&fx)), ["lock"]);
}

#[test]
fn a_signal_while_the_row_s_cargo_runs_ends_its_group_and_frees_the_lock() {
    let mut fx = Fixture::new();
    fx.set("STUB_HOLD", "1");
    let (held, head) = row(&fx);
    let errors = fx.temp.join("holder.err");
    let tool = start(&fx, &fx.top, &Fixture::input(&[(&head, &held)]), &errors);
    let leader = process_id(&fx.logged(".leader"));
    let probe = opened(&fx);
    assert!(
        !locked(&probe),
        "the row holds the lock while its cargo runs"
    );
    signal(tool.id(), libc::SIGTERM);
    let run = finished(tool);
    assert_eq!(run.code, Some(128 + libc::SIGTERM), "{}", written(&errors));
    assert!(group_ended(leader), "the row's cargo ends");
    assert!(locked(&probe), "the lock is free once the tool has ended");
    assert_eq!(fx.worktrees(), 1);
    assert_eq!(entries(&own(&fx)), ["lock"]);
}

#[test]
fn a_killed_push_frees_the_lock_and_leaves_its_worktree_registered_under_the_checkout() {
    let mut fx = Fixture::new();
    fx.set("STUB_HOLD", "1");
    let (held, head) = row(&fx);
    let errors = fx.temp.join("killed.err");
    let tool = start(&fx, &fx.top, &Fixture::input(&[(&head, &held)]), &errors);
    let leader = process_id(&fx.logged(".leader"));
    signal(tool.id(), libc::SIGKILL);
    let run = finished(tool);
    assert_eq!(run.code, None, "{}", written(&errors));
    assert!(alive(leader), "the row's cargo runs on in its own group");
    let probe = opened(&fx);
    assert!(
        locked(&probe),
        "the lock is free while that cargo still runs"
    );
    drop(released(probe));
    let left = entries(&own(&fx));
    assert_eq!(left.len(), 2, "{left:?}");
    assert!(left[0].starts_with("kestrike-pre-push-"), "{left:?}");
    assert_eq!(fx.worktrees(), 2);
    fx.unset("STUB_HOLD");
    let run = fx.push(&[(&head, &held)]);
    fs::write(fx.logged(".release"), "").expect("the first push's cargo is released");
    assert!(group_ended(leader), "the first push's cargo ends");
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert!(!run.stderr.contains(WAITING), "{}", run.stderr);
    assert_eq!(fx.ran(), [HOST_STOP_RUN, HOST_STOP_RUN]);
    assert_eq!(entries(&own(&fx)), left);
    let tree = own(&fx).join(&left[0]);
    fx.git(&[
        "worktree",
        "remove",
        "--force",
        "--force",
        tree.to_str().expect("the scratch path is UTF-8"),
    ]);
    assert_eq!(fx.worktrees(), 1);
    assert_eq!(entries(&own(&fx)), ["lock"]);
}

#[test]
fn a_lock_name_that_holds_a_link_or_a_directory_fails_the_row_before_cargo_starts() {
    let fx = Fixture::new();
    let (held, head) = row(&fx);
    drop(opened(&fx));
    let path = own(&fx).join("lock");
    fs::remove_file(&path).expect("the lock file is removed");
    let elsewhere = fx.temp.join("elsewhere");
    type Step = fn(&Path, &Path);
    let states: [(&str, Step, Step); 3] = [
        (
            "is a link",
            |path, elsewhere| symlink(elsewhere, path).expect("the link is made"),
            |path, _| fs::remove_file(path).expect("the link is removed"),
        ),
        (
            "is a link",
            |path, elsewhere| {
                fs::write(elsewhere, "").expect("the link's target is made");
                symlink(elsewhere, path).expect("the link is made");
            },
            |path, _| fs::remove_file(path).expect("the link is removed"),
        ),
        (
            "is no regular file",
            |path, _| fs::create_dir(path).expect("the directory is made"),
            |path, _| fs::remove_dir(path).expect("the directory is removed"),
        ),
    ];
    for (at, (state, make, clear)) in states.into_iter().enumerate() {
        make(&path, &elsewhere);
        let run = fx.push(&[(&head, &held)]);
        assert_eq!(run.code, Some(1), "{state}: {}", run.stderr);
        assert!(
            run.stderr.ends_with(&format!(
                "pre-push: failed: {HOST_STOP_RUN}: the lock {} {state}\n",
                path.display()
            )),
            "{state}: {}",
            run.stderr
        );
        assert_eq!(fx.ran(), Vec::<String>::new(), "{state}");
        assert_eq!(elsewhere.exists(), at > 0, "{state}");
        assert_eq!(fx.worktrees(), 1, "{state}");
        clear(&path, &elsewhere);
    }
    fs::write(&path, "kept\n").expect("the lock file is written");
    let run = fx.push(&[(&head, &held)]);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert_eq!(fx.ran(), [HOST_STOP_RUN]);
    assert_eq!(fs::read(&path).expect("the lock file reads"), b"kept\n");
}
