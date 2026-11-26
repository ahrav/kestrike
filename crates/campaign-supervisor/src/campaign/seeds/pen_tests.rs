//! Pen tests run inside a delegated cgroup-v2 scope named by
//! `CAMPAIGN_CGROUP_ROOT`, each under its own child of that delegation.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use super::pen::{Limits, Pen, claim};
use crate::custody::{Custody, Timing};
use crate::store::cgroup::Root;
use crate::store::fixture::processes;

const LIMITS: Limits = Limits {
    memory: 64 << 20,
    processes: 16,
};

/// A cgroup root for one test, removed on drop.
pub(super) struct Delegation {
    delegation: PathBuf,
    pub(super) root: PathBuf,
}

impl Delegation {
    pub(super) fn new(label: &str) -> Self {
        let delegation = PathBuf::from(std::env::var_os("CAMPAIGN_CGROUP_ROOT").unwrap());
        fs::create_dir_all(delegation.join("controller")).unwrap();
        let root = delegation.join(format!("pen-{}-{label}", std::process::id()));
        fs::create_dir(&root).unwrap();
        Self { delegation, root }
    }

    pub(super) fn root(&self) -> Root {
        Root::open(&self.root).unwrap()
    }
}

impl Drop for Delegation {
    fn drop(&mut self) {
        fs::write(
            self.delegation.join("controller/cgroup.procs"),
            std::process::id().to_string(),
        )
        .unwrap();
        let _ = fs::write(self.root.join("cgroup.kill"), "1");
        // Child cgroups must be removed before their parent.
        fn remove(path: &Path) {
            if let Ok(entries) = fs::read_dir(path) {
                for entry in entries.flatten() {
                    if entry.file_type().unwrap().is_dir() {
                        remove(&entry.path());
                    }
                }
            }
            let _ = fs::remove_dir(path);
        }
        remove(&self.root);
    }
}

/// A shell that reads one line, then runs `script`: the line stands for a
/// sweep worker's first root, which it reads before it starts a run.
fn gated(script: &str) -> Child {
    Command::new("sh")
        .args(["-c", &format!("read go; {script}")])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

fn release(child: &mut Child) {
    child.stdin.take().unwrap().write_all(b"go\n").unwrap();
}

/// A worker whose memory use reaches the pen's limit after it entered the
/// pen is killed by the kernel, and the pen reports the kill once.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_worker_past_the_memory_limit_is_killed_and_reported_once() {
    let _processes = processes();
    let host = Delegation::new("memory");
    let pen = Pen::create(&host.root(), 0, LIMITS).unwrap();
    let mut worker = gated("exec tail /dev/zero");
    pen.admit(&worker).unwrap();
    assert!(!pen.out_of_memory().unwrap());
    release(&mut worker);
    assert_eq!(worker.wait().unwrap().signal(), Some(libc::SIGKILL));
    assert!(pen.out_of_memory().unwrap());
    assert!(!pen.out_of_memory().unwrap());
    assert!(!pen.empty().unwrap());
    pen.remove().unwrap();
}

/// A process a worker leaves running is killed when the pen is emptied,
/// and the pen then holds none.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn emptying_a_pen_kills_the_process_a_worker_left() {
    let _processes = processes();
    let host = Delegation::new("left");
    let pen = Pen::create(&host.root(), 0, LIMITS).unwrap();
    let mut worker = gated("sleep 600 & exit 0");
    pen.admit(&worker).unwrap();
    release(&mut worker);
    assert_eq!(worker.wait().unwrap().code(), Some(0));
    assert!(pen.empty().unwrap());
    assert!(!pen.empty().unwrap());
    assert!(!pen.out_of_memory().unwrap());
    pen.remove().unwrap();
}

/// A killed pen ends its worker and every process the worker started.
/// The worker prints its child's process ID before the kill, so the child
/// exists then, and the pen holds no process afterwards without a second
/// kill.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn killing_a_pen_ends_the_worker_and_its_children() {
    let _processes = processes();
    let host = Delegation::new("kill");
    let pen = Pen::create(&host.root(), 0, LIMITS).unwrap();
    let mut worker = Command::new("sh")
        .args(["-c", "read go; sleep 600 & echo $!; wait"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    pen.admit(&worker).unwrap();
    release(&mut worker);
    let mut started = String::new();
    BufReader::new(worker.stdout.take().unwrap())
        .read_line(&mut started)
        .unwrap();
    assert!(started.trim().parse::<u32>().is_ok(), "{started:?}");
    pen.kill().unwrap();
    assert_eq!(worker.wait().unwrap().signal(), Some(libc::SIGKILL));
    let events = host.root.join("sweep-0000/cgroup.events");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !fs::read_to_string(&events).unwrap().contains("populated 0") {
        assert!(Instant::now() < deadline, "the pen still holds a process");
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(!pen.out_of_memory().unwrap());
    pen.remove().unwrap();
}

/// An active claim protects its sweep's pens and workers from cleanup by
/// another sweep.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_second_sweep_is_refused_the_root_while_the_first_ones_worker_runs() {
    let _processes = processes();
    let host = Delegation::new("claim");
    let first = claim(&host.root).unwrap().unwrap();
    let pen = Pen::create(&first, 0, LIMITS).unwrap();
    let mut worker = gated("sleep 600");
    pen.admit(&worker).unwrap();
    assert!(claim(&host.root).unwrap().is_none());
    assert!(worker.try_wait().unwrap().is_none());
    pen.remove().unwrap();
    assert_eq!(worker.wait().unwrap().signal(), Some(libc::SIGKILL));
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn custody_on_the_root_keeps_no_account_of_a_pen() {
    let _processes = processes();
    let host = Delegation::new("custody");
    let root = claim(&host.root).unwrap().unwrap();
    let pen = Pen::create(&root, 0, LIMITS).unwrap();
    let custody = Custody::open(
        &host.root,
        Timing {
            poll: Duration::from_millis(1),
            kill_wait: Duration::from_secs(1),
            watchdog: Duration::from_secs(5),
        },
    )
    .unwrap();
    assert!(custody.unrecorded(&[], 8).unwrap().is_empty());
    pen.remove().unwrap();
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn claiming_a_root_removes_every_pen_an_earlier_sweep_left() {
    let _processes = processes();
    let host = Delegation::new("stale");
    let earlier = claim(&host.root).unwrap().unwrap();
    let stale = Pen::create(&earlier, 3, LIMITS).unwrap();
    let mut worker = gated("sleep 600");
    stale.admit(&worker).unwrap();
    drop(stale);
    drop(earlier);
    let root = claim(&host.root).unwrap().unwrap();
    assert!(root.children(8).unwrap().is_empty());
    assert_eq!(worker.wait().unwrap().signal(), Some(libc::SIGKILL));
}
