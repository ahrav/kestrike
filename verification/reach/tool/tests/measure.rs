//! `measure.sh` limits concurrent batches to the smaller of `BATCH_WORKERS`
//! and the count `nproc` reports. When SIGTERM or SIGINT ends the script,
//! or the batch pool ends with a failure, its batch workers exit too. The
//! script measures on an aarch64 host, from a checkout with no untracked
//! file, and merges a batch only when each of its roots completed a run of
//! the scheduled profile.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const RUSTC: &str = r#"#!/bin/sh
case "$*" in
-vV) echo "host: ${REACH_HOST:-aarch64-fixture}" ;;
*) echo "$REACH_FIXTURE/sysroot" ;;
esac
"#;

const NPROC: &str = "#!/bin/sh\necho 2\n";

const CARGO: &str = r#"#!/bin/sh
if [ "$1" = build ]; then
  printf '{"reason":"compiler-artifact","target":{"name":"campaign"},"executable":"%s/bin/campaign"}\n' \
    "$REACH_FIXTURE"
fi
"#;

const CAMPAIGN: &str = r#"#!/bin/sh
if [ "$1" = sim ]; then
  mkdir -p "$4/lib"
  cp "$REACH_FIXTURE/bin/worker" "$4/worker"
  printf '{"record":{"provenance":{"revision":"%s","dirty":false,"untracked":%s,"environment":{"RUSTFLAGS":"%s"}}}}' \
    "$(git -C "$REACH_FIXTURE/repo" rev-parse HEAD)" "${REACH_UNTRACKED:-0}" "$RUSTFLAGS" > "$4/build"
  exit
fi
while [ $# -gt 1 ]; do
  case $1 in
  --root) root=$2 ;;
  --profiles) profiles=$2 ;;
  --set) echo "$root $2" >> "$REACH_FIXTURE/sets" ;;
  esac
  shift
done
mkdir -p "$root/manifests"
for profile in $(echo "$profiles" | tr , ' '); do
  printf 'toolchain = t\nbuild = b\nexecutable = e\n' > "$root/manifests/$profile.manifest"
done
"#;

const WORKER: &str = r#"#!/bin/sh
echo profile > "$(echo "$LLVM_PROFILE_FILE" | sed "s/%p/$$/")"
if [ "$1" = --capabilities ]; then
  echo "profile: upload class=live"
  if [ -n "$REACH_RECOVERY" ]; then echo "profile: $REACH_RECOVERY class=recovery"; fi
  exit
fi
if [ "$REACH_MODE" = hold ]; then
  : > "$REACH_FIXTURE/held/$$"
  exec sleep 300
fi
mkdir "$REACH_FIXTURE/running/$$"
ls "$REACH_FIXTURE/running" | wc -l >> "$REACH_FIXTURE/peaks"
sleep 0.1
profile=$(basename "$2" .manifest)
block() {
  printf 'root: %s\ncode: %s\nterminal: %s\ncounts: %s\nprofile: %s\nend: %s\n' "$1" "$2" "$3" "$4" "$5" "$1"
}
echo "sweep: ready"
while read -r root; do
  mode=count
  if [ "$root" = 7 ]; then mode=$REACH_MODE; fi
  case $mode in
  refused) printf 'root: 7\ncode: 2\nrefused: Profile\nend: 7\n' ;;
  panicked) printf 'root: 7\ncode: 3\nrun: panicked at worker.rs\nend: 7\n' ;;
  unloadable) printf 'root: 7\ncode: 3\nload: Truncated\nend: 7\n' ;;
  infrastructure) block 7 3 "infrastructure cap" false "$profile" ;;
  disagreeing) block 7 0 "complete pass fired=03 required=03" false "$profile" ;;
  elsewhere) block 7 0 "complete pass fired=03 required=03" true other ;;
  twice) printf 'root: 7\ncode: 0\ncode: 1\nterminal: complete pass fired=03 required=03\ncounts: true\nprofile: %s\nend: 7\n' "$profile" ;;
  unsuccessful) block 7 1 "complete unsuccessful fired=03 required=03" false "$profile" ;;
  inconclusive) block 7 1 "complete inconclusive fired=03 required=03" false "$profile" ;;
  uncredited) block 7 1 "complete pass fired=03 required=03" false "$profile" ;;
  violation) block 7 1 "complete violation fired=03 required=03" false "$profile" ;;
  *) block "$root" 0 "complete pass fired=03 required=03" true "$profile" ;;
  esac
done
rmdir "$REACH_FIXTURE/running/$$"
"#;

const PROFDATA: &str = "#!/bin/sh\nfor last; do :; done\n: > \"$last\"\n";

const COV: &str = "#!/bin/sh\necho '{}'\n";

struct Host {
    root: PathBuf,
    script: Option<Child>,
}

impl Host {
    fn new(name: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("reach-measure-{}-{name}", std::process::id()));
        std::fs::create_dir(&root).expect("a new root");
        let host = Self { root, script: None };
        for directory in ["repo", "held", "running"] {
            std::fs::create_dir(host.root.join(directory)).expect("a new directory");
        }
        for (rel, text) in [
            ("bin/rustc", RUSTC),
            ("bin/nproc", NPROC),
            ("bin/cargo", CARGO),
            ("bin/campaign", CAMPAIGN),
            ("bin/worker", WORKER),
            (
                "sysroot/lib/rustlib/aarch64-fixture/bin/llvm-profdata",
                PROFDATA,
            ),
            ("sysroot/lib/rustlib/aarch64-fixture/bin/llvm-cov", COV),
        ] {
            let path = host.root.join(rel);
            std::fs::create_dir_all(path.parent().expect("a parent")).expect("a directory");
            std::fs::write(&path, text).expect("a script");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                .expect("an executable script");
        }
        host.git(&["init", "--quiet"]);
        host.git(&["commit", "--quiet", "--allow-empty", "--message", "fixture"]);
        host
    }

    fn git(&self, arguments: &[&str]) {
        let status = Command::new("git")
            .args([
                "-c",
                "user.name=reach",
                "-c",
                "user.email=reach@example.invalid",
            ])
            .args(arguments)
            .current_dir(self.root.join("repo"))
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .status()
            .expect("git runs");
        assert!(status.success(), "git {arguments:?}");
    }

    /// `measure` runs the script under the umask `REACH_UMASK` names, 022
    /// unless the caller sets it.
    fn measure(&self, mode: &str, workers: Option<&str>) -> Command {
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../measure.sh");
        let path = std::env::var("PATH").expect("a search path");
        let mut command = Command::new("sh");
        command
            .args(["-c", "umask \"$REACH_UMASK\" && exec \"$0\" \"$@\""])
            .arg(script)
            .arg("storage")
            .arg(self.root.join("state"))
            .arg(self.root.join("scratch"))
            .current_dir(self.root.join("repo"))
            .env(
                "PATH",
                format!("{}:{path}", self.root.join("bin").display()),
            )
            .env("REACH_FIXTURE", &self.root)
            .env("REACH_MODE", mode)
            .env("REACH_UMASK", "022")
            .env_remove("REACH_RECOVERY")
            .env_remove("REACH_HOST")
            .env_remove("REACH_UNTRACKED")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env_remove("BATCH_SECONDS")
            .env_remove("BATCH_WORKERS");
        if let Some(workers) = workers {
            command.env("BATCH_WORKERS", workers);
        }
        command
    }

    fn held(&self) -> Vec<String> {
        std::fs::read_dir(self.root.join("held"))
            .expect("the held directory")
            .map(|entry| {
                entry
                    .expect("a directory entry")
                    .file_name()
                    .into_string()
                    .expect("a process id")
            })
            .collect()
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        for pid in self.held() {
            let _ = Command::new("kill").args(["-s", "KILL", &pid]).status();
        }
        if let Some(mut script) = self.script.take() {
            let _ = script.kill();
            let _ = script.wait();
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn until(seconds: u64, mut done: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    while !done() {
        if Instant::now() > deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    true
}

fn running(pid: &str) -> bool {
    Path::new("/proc").join(pid).exists()
}

#[test]
fn the_batches_run_within_the_worker_bound_and_the_processor_count() {
    for (workers, bound) in [(None, 2), (Some("1"), 1), (Some("9"), 2)] {
        let host = Host::new(&format!("bound-{}", workers.unwrap_or("default")));
        let output = host
            .measure("count", workers)
            .output()
            .expect("the script runs");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(0), "{workers:?}: {stderr}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("upload: 50 of 50 roots pass"),
            "{workers:?}"
        );
        let peaks: Vec<usize> = std::fs::read_to_string(host.root.join("peaks"))
            .expect("the batches' counts")
            .lines()
            .map(|line| line.trim().parse().expect("a count"))
            .collect();
        assert_eq!(peaks.len(), 10, "{workers:?}");
        assert!(
            peaks.iter().all(|&count| count <= bound),
            "{workers:?}: {peaks:?}"
        );
    }
    for refused in ["0", "many"] {
        let host = Host::new(&format!("refused-{refused}"));
        let output = host
            .measure("count", Some(refused))
            .output()
            .expect("the script runs");
        assert_eq!(output.status.code(), Some(2), "{refused}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("BATCH_WORKERS"),
            "{refused}"
        );
        assert!(!host.root.join("state").exists(), "{refused}");
    }
}

#[test]
fn a_script_that_a_signal_ends_leaves_no_batch_worker() {
    for (signal, code) in [("TERM", 143), ("INT", 130)] {
        let mut host = Host::new(&format!("reap-{signal}"));
        let script = host
            .measure("hold", None)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("the script starts");
        let pid = script.id().to_string();
        host.script = Some(script);
        assert!(until(60, || host.held().len() >= 2), "{signal}: no batch");
        let held = host.held();
        let sent = Command::new("kill")
            .args(["-s", signal, &pid])
            .status()
            .expect("kill runs");
        assert!(sent.success(), "{signal}");
        assert!(
            until(10, || !held.iter().any(|pid| running(pid))),
            "{signal}: batch workers outlive the script"
        );
        let status = host
            .script
            .take()
            .expect("the script")
            .wait()
            .expect("the script ends");
        assert_eq!(status.code(), Some(code), "{signal}");
    }
}

/// A pool whose leader a signal kills reports that status while its
/// batches still run; the script ends each of them before it exits.
#[test]
fn a_pool_that_a_signal_kills_leaves_no_batch_worker() {
    let mut host = Host::new("pool");
    let script = host
        .measure("hold", None)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the script starts");
    let pid = script.id().to_string();
    host.script = Some(script);
    assert!(until(60, || host.held().len() >= 2), "no batch");
    let held = host.held();
    let killed = Command::new("pkill")
        .args(["-KILL", "-P", &pid, "-x", "xargs"])
        .status()
        .expect("pkill runs");
    assert!(killed.success(), "the script has no xargs child");
    let status = host
        .script
        .take()
        .expect("the script")
        .wait()
        .expect("the script ends");
    assert_eq!(status.code(), Some(137));
    assert!(
        until(10, || !held.iter().any(|pid| running(pid))),
        "batch workers outlive the script"
    );
}

/// Root 7 of the fixture's one profile prints the block its mode names.
/// A root whose run did not complete, ran another profile, or printed
/// fields that disagree stops the script before the run record.
#[test]
fn a_root_that_completed_no_run_of_its_profile_stops_the_script() {
    for mode in [
        "refused",
        "panicked",
        "unloadable",
        "infrastructure",
        "disagreeing",
        "elsewhere",
        "twice",
    ] {
        let host = Host::new(&format!("stop-{mode}"));
        let output = host.measure(mode, None).output().expect("the script runs");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "{mode}: {stderr}");
        assert!(
            stderr.contains("the batch upload 6: root 7 "),
            "{mode}: {stderr}"
        );
        assert!(!host.root.join("scratch/run.json").exists(), "{mode}");
    }
}

/// A complete run that does not count adds its coverage and no pass. The
/// script names a violating root on standard error and still measures.
#[test]
fn a_complete_root_that_does_not_count_is_merged_and_a_violation_is_named() {
    for mode in ["unsuccessful", "inconclusive", "uncredited", "violation"] {
        let host = Host::new(&format!("merge-{mode}"));
        let output = host.measure(mode, None).output().expect("the script runs");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(0), "{mode}: {stderr}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("upload: 49 of 50 roots pass"),
            "{mode}"
        );
        let merged =
            std::fs::read_to_string(host.root.join("scratch/merge.list")).expect("the merge list");
        assert_eq!(merged.lines().count(), 10, "{mode}");
        let named = stderr
            .matches("measure.sh: upload root 7 ended in a violation")
            .count();
        assert_eq!(
            named,
            if mode == "violation" { 2 } else { 0 },
            "{mode}: {stderr}"
        );
    }
}

#[test]
fn a_host_of_another_architecture_is_refused_before_any_directory() {
    let host = Host::new("architecture");
    let output = host
        .measure("count", None)
        .env("REACH_HOST", "x86_64-fixture")
        .output()
        .expect("the script runs");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("aarch64 host; this host is x86_64-fixture"),
        "{stderr}"
    );
    assert!(!host.root.join("state").exists());
}

#[test]
fn an_untracked_file_in_the_checkout_is_refused_before_any_directory() {
    let host = Host::new("untracked");
    host.git(&["config", "status.showUntrackedFiles", "no"]);
    std::fs::write(host.root.join("repo/stray.rs"), "").expect("an untracked file");
    let output = host
        .measure("count", None)
        .output()
        .expect("the script runs");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("untracked files"), "{stderr}");
    assert!(!host.root.join("state").exists());
}

#[test]
fn an_archive_built_beside_untracked_files_stops_the_script_before_the_run_record() {
    let host = Host::new("record");
    let output = host
        .measure("count", None)
        .env("REACH_UNTRACKED", "1")
        .output()
        .expect("the script runs");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("untracked 1"), "{stderr}");
    assert!(!host.root.join("scratch/run.json").exists());
}

#[test]
fn the_scratch_directory_is_owner_only_and_the_listing_names_the_recovery_profiles() {
    let host = Host::new("scratch");
    let output = host
        .measure("count", None)
        .env("REACH_UMASK", "000")
        .env("REACH_RECOVERY", "recovery-fixture")
        .output()
        .expect("the script runs");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stderr}");
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("recovery-fixture: 50 of 50 roots pass")
    );
    for directory in ["scratch", "state"] {
        let mode = std::fs::metadata(host.root.join(directory))
            .expect("the directory")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700, "{directory}");
    }
    let sets = std::fs::read_to_string(host.root.join("sets")).expect("the freezes' counts");
    assert!(
        sets.lines()
            .any(|line| line.ends_with("/state/restarts restarts=20")),
        "{sets}"
    );
    let run: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(host.root.join("scratch/run.json")).expect("the run record"),
    )
    .expect("a run record");
    assert_eq!(run["counts"]["recovery-fixture"], "restarts=20");
    assert_eq!(run["roots"], "1-50");
}
