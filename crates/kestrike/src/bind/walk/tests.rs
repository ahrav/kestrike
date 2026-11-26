//! The procfs walk lists entries in a real directory, reads the start tick
//! from a `stat` file, and reads a process whose `task` entry is a symlink.

use std::ffi::CString;
use std::fs;
use std::os::unix::fs::symlink;

use super::super::fixture::Fixture;
use super::refused_attributes_tests::walked;
use super::{Directory, Node, Os, Procfs};

fn procfs(fixture: &Fixture) -> Procfs<'_> {
    let path = CString::new(fixture.host.proc.as_os_str().as_encoded_bytes()).unwrap();
    Procfs {
        root: Directory::open(libc::AT_FDCWD, &path).unwrap(),
        proc: &fixture.host.proc,
        own: false,
    }
}

/// A second listing through one open directory starts at the first entry
/// and visits every name again, and a name created between the two.
#[test]
fn a_second_listing_of_one_open_directory_visits_every_name_again() {
    let fixture = Fixture::new(4096);
    for name in 0..40 {
        fixture.file(&format!("listing/{name}"), "");
    }
    let path = CString::new(fixture.root.join("listing").as_os_str().as_encoded_bytes()).unwrap();
    let directory = Directory::open(libc::AT_FDCWD, &path).unwrap();
    let mut records = [0u8; 256];
    let mut list = || {
        let mut visited = Vec::new();
        directory
            .entries(&mut records, |name| {
                visited.push(name.to_str().unwrap().to_owned());
            })
            .unwrap();
        visited.sort_unstable();
        visited
    };
    let first = list();
    assert_eq!(first.len(), 40, "premise: the first listing is whole");
    fixture.file("listing/40", "");
    let mut expected = first;
    expected.push("40".to_owned());
    expected.sort_unstable();
    assert_eq!(list(), expected);
}

/// A process that has exited and awaits its parent, and a process under a
/// command name outside UTF-8 that holds a `)`, live or exited, each show
/// the listing the tick the leader started in, so a listing tells each from
/// a process the host gives its ID later. [`Os::started`] reports the start
/// tick of the live task and none of a task that has exited, whatever bytes
/// the name holds.
#[test]
fn a_listing_reads_the_start_tick_of_an_exited_leader_and_of_a_name_outside_utf8() {
    let fixture = Fixture::new(4096);
    let entry = |pid: u32, name: &[u8], state: &str, started: u64| {
        let task = fixture.host.proc.join(format!("{pid}/task/{pid}"));
        fs::create_dir_all(&task).unwrap();
        let mut stat = format!("{pid} (").into_bytes();
        stat.extend_from_slice(name);
        stat.extend_from_slice(
            format!(") {state} 1{} {started} 0 0\n", " 0".repeat(17)).as_bytes(),
        );
        fs::write(task.join("stat"), stat).unwrap();
    };
    entry(4242, b"exited", "Z", 777);
    entry(4243, b"\xff) \xfe", "S", 888);
    entry(4245, b"\xff) \xfe", "Z", 999);
    let os = procfs(&fixture);
    assert_eq!(os.leader_started(4242), Some(777));
    assert_eq!(os.started(4242, 4242), None, "the task has exited");
    assert_eq!(os.leader_started(4243), Some(888));
    assert_eq!(os.started(4243, 4243), Some(888), "the task is live");
    assert_eq!(os.leader_started(4245), Some(999));
    assert_eq!(os.started(4245, 4245), None, "the task has exited");
    assert_eq!(os.leader_started(4244), None, "no such process");
}

/// A `task` directory that is a link to itself answers `stat` with `ELOOP`,
/// and the walker returns `None` for process 62. The leader's `stat` entry
/// lies under `62/task`, so a listing reads no start tick for the process.
#[test]
fn a_thread_table_that_cannot_be_stat_ed_fails_the_walk() {
    const DEVICE: Node = Node::Device {
        block: true,
        major: 259,
        minor: 1,
    };
    let fixture = Fixture::new(4096);
    let os = procfs(&fixture);
    let task = fixture.host.proc.join("62/task");
    fs::create_dir_all(fixture.host.proc.join("62/fd")).unwrap();
    fs::create_dir_all(task.join("62")).unwrap();
    assert_eq!(
        walked(&os, 62, DEVICE),
        Some(Vec::new()),
        "premise: the walker reads a process whose `task` directory answers `stat`"
    );
    fs::remove_dir_all(&task).unwrap();
    symlink("task", &task).unwrap();
    assert_eq!(walked(&os, 62, DEVICE), None);
}
