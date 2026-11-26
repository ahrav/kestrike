//! The ring pass over fixture process tables: its choice of thread tables,
//! judged with the running kernel's `kcmp` over this process's own threads;
//! its reading of a process table that several reader threads share; and
//! its passes over one table, timed by the pass's own reads of a ring's
//! `fdinfo`, a FIFO for those reads.

use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use super::fixture::{
    Fixture, RELEASE, Slots, TRACER, hold_ring, make_fifo, release, ring_info, ring_info_listing,
};
use super::identity::IdentityError;
use super::rings::{Kernel, registered_files};
use crate::exact_child;

/// Bounds the case's fresh child, which runs two threads and three ring
/// passes over a fixture.
const CHILD_DEADLINE: Duration = Duration::from_secs(60);

// The case runs in a fresh child of the test executable that runs only this
// case, so `kcmp` compares this case's own threads and the thread that
// takes a private table copies no concurrent test's descriptors.
#[test]
fn a_thread_kcmp_reports_on_the_leader_s_table_is_left_to_the_reads_of_that_table() {
    exact_child::run(
        "bind::rings_tests::a_thread_kcmp_reports_on_the_leader_s_table_is_left_to_the_reads_of_that_table",
        CHILD_DEADLINE,
        a_thread_on_the_leader_s_table_is_left_to_the_reads_of_that_table,
    );
}

fn a_thread_on_the_leader_s_table_is_left_to_the_reads_of_that_table() {
    // The fixture's process is this test process, so `kcmp` compares its
    // real threads: one uses the leader's table and one holds its own after
    // `unshare(CLONE_FILES)`. procfs shows a shared table identically under
    // the leader and each thread on it, so a ring only in that thread's
    // fixture table is reported exactly when that table is read. Linux
    // assigns thread IDs below `PID_MAX_LIMIT`, which is 4,194,304 on 64-bit
    // hosts, so `kcmp` fails for thread ID 4,194,304 and the pass reads its
    // table.
    let pid = std::process::id();
    let reported = thread::scope(|scope| {
        let (sender, started) = mpsc::channel();
        let mut releases = Vec::new();
        for private in [false, true] {
            let (release, released) = mpsc::channel::<()>();
            releases.push(release);
            let sender = sender.clone();
            scope.spawn(move || {
                // SAFETY: `unshare` takes no memory arguments.
                let own = private && unsafe { libc::unshare(libc::CLONE_FILES) == 0 };
                // SAFETY: `gettid` takes no arguments.
                sender.send((own, unsafe { libc::gettid() })).unwrap();
                // The thread keeps its table until its release drops.
                let _ = released.recv();
            });
        }
        let threads: Vec<(bool, i32)> = started.iter().take(2).collect();
        assert!(
            threads.iter().any(|(own, _)| *own),
            "a thread unshared its table"
        );
        let pass = |status: &str| {
            let fixture = Fixture::new(4096);
            fixture.file("proc/self/status", status);
            hold_ring(&fixture, &pid.to_string(), 5, &ring_info(&["leader"]));
            for (own, tid) in &threads {
                let file = if *own { "own" } else { "shared" };
                hold_ring(
                    &fixture,
                    &format!("{pid}/task/{tid}"),
                    5,
                    &ring_info(&[file]),
                );
            }
            let uncompared = format!("{pid}/task/4194304");
            hold_ring(&fixture, &uncompared, 5, &ring_info(&["uncompared"]));
            fixture.host.registered(|_| true)
        };
        // One `NStgid` entry names this process's namespace. Two name a
        // procfs of an ancestor namespace, and none an older kernel's, so
        // the pass reads every thread's fixture table.
        [
            pass(&format!("Name:\ttest\nNStgid:\t{pid}\n{TRACER}")),
            pass(&format!("Name:\ttest\nNStgid:\t7\t{pid}\n{TRACER}")),
            pass(&format!("Name:\ttest\n{TRACER}")),
        ]
    });
    let names = |names: &[&str]| Some(names.iter().map(|name| (*name).to_owned()).collect());
    let every: Option<Vec<String>> = names(&["leader", "own", "shared", "uncompared"]);
    assert_eq!(
        reported,
        [
            names(&["leader", "own", "uncompared"]),
            every.clone(),
            every
        ]
    );
}

/// A process table of more processes than one reader takes is read by one
/// reader per eight processes, up to the host's parallelism and 32, and the
/// pass reports the registered files of every process's rings: here a ring in
/// the table under each even process's ID and in a thread's table of each odd
/// one.
#[test]
fn a_ring_of_every_process_is_reported_from_a_table_several_readers_share() {
    let fixture = Fixture::new(4096);
    let mut expected = Vec::new();
    for pid in 3000u32..3064 {
        let file = format!("file{pid}");
        let task = if pid.is_multiple_of(2) {
            pid.to_string()
        } else {
            format!("{pid}/task/{}", pid + 1000)
        };
        hold_ring(&fixture, &task, 5, &ring_info(&[&file]));
        expected.push(file);
    }
    assert_eq!(fixture.host.registered(|_| true), Some(expected));
}

/// A slot line after the count shows the kernel held the ring's lock, under
/// which it lists every filled slot, so a table that lists only its filled
/// slots reads whole: `SPARSE` is the shape Linux 6.14 prints for three
/// slots whose middle one holds `/tmp/a`. A count with no slot line after
/// it, as Linux 6.12 prints while a submission holds the lock, stays short.
/// A gapped table that holds the namespace leaves it in use.
#[test]
fn a_table_that_lists_only_its_filled_slots_is_read_whole() {
    const SPARSE: &str =
        "pos:\t0\nflags:\t02000002\nUserFiles:\t3\n    1: /tmp/a\nUserBufs:\t0\nPollList:\n";
    assert_eq!(registered_files(SPARSE, false), Some(vec!["a"]));
    let contended = "pos:\t0\nflags:\t02000002\nUserFiles:\t3\nUserBufs:\t0\nPollList:\n";
    assert_eq!(registered_files(contended, false), None);
    let fixture = Fixture::new(4096);
    let info = ring_info_listing(Slots::Filled, &["<none>", "/dev/nvme1n1", "<none>"]);
    hold_ring(&fixture, "4242", 5, &info);
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "{info}"
    );
}

/// A table of empty slots lists no slot line on Linux 6.14 and later, so
/// its count alone shows it whole only where the kernel prints the count
/// under the ring's lock, Linux 6.15 and later. The pass reads the release
/// from `sys/kernel/osrelease`; an older, unparsable or missing release
/// leaves such a table short.
#[test]
fn a_count_alone_is_a_whole_table_only_on_a_kernel_that_counts_under_the_lock() {
    let empty = ring_info_listing(Slots::Filled, &["<none>", "<none>"]);
    assert_eq!(registered_files(&empty, true), Some(Vec::new()));
    assert_eq!(registered_files(&empty, false), None);
    let registered = |osrelease: Option<&str>| {
        let fixture = Fixture::new(4096);
        let path = "proc/sys/kernel/osrelease";
        match osrelease {
            Some(text) => fixture.file(path, text),
            None => fs::remove_file(fixture.root.join(path)).unwrap(),
        }
        hold_ring(&fixture, "4242", 5, &empty);
        fixture.host.registered(|_| true)
    };
    for whole in ["6.15.0-1-aws\n", "6.16.1\n", "6.18.0-rc2\n", "7.0.0\n"] {
        assert_eq!(registered(Some(whole)), Some(Vec::new()), "{whole}");
    }
    let older = format!("{RELEASE}\n");
    for short in [
        Some("6.14.9\n"),
        Some(older.as_str()),
        Some("linux\n"),
        None,
    ] {
        assert_eq!(registered(short), None, "{short:?}");
    }
}

/// The release that tells whether a count alone shows a table whole is read
/// at `proc/sys/kernel/osrelease`. A mount the mount table lists at that
/// path shows its own text there, here a release that counts under the
/// lock, so an older kernel's short listing would read as an empty table.
/// The check has no answer under the cover; the same release with no mount
/// over it admits the namespace.
#[test]
fn a_release_a_mount_covers_does_not_show_a_count_alone_whole() {
    let empty = ring_info_listing(Slots::Filled, &["<none>", "<none>"]);
    let checked = |tail: &str| {
        let fixture = Fixture::new(4096);
        fixture.file("proc/sys/kernel/osrelease", "6.15.0-1-aws\n");
        fixture.file(
            "proc/self/mounts",
            &format!("/dev/nvme0n1p1 / xfs rw 0 0\nproc /proc proc rw 0 0\n{tail}"),
        );
        hold_ring(&fixture, "4242", 5, &empty);
        fixture.host.check_unused("nvme1n1").map(drop)
    };
    assert_eq!(
        checked(""),
        Ok(()),
        "premise: the release as the kernel shows it"
    );
    assert_eq!(
        checked("tmpfs /proc/sys/kernel/osrelease tmpfs rw 0 0\n"),
        Err(IdentityError::Unverifiable("processes")),
        "a covered release admitted"
    );
}

/// A kernel that prints a registered file's path prints an unlinked file's
/// with ` (deleted)` after it, the space escaped. A ring that registered
/// the namespace's node keeps that open device after the node is unlinked
/// and made again, so the name before the suffix counts as the device's.
#[test]
fn a_registered_node_that_was_unlinked_is_in_use() {
    let fixture = Fixture::new(4096);
    hold_ring(&fixture, "4242", 5, &ring_info(&["/var/log/other"]));
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Ok(()),
        "premise: a ring over another file"
    );
    hold_ring(
        &fixture,
        "4243",
        5,
        &ring_info(&["/dev/nvme1n1\\040(deleted)"]),
    );
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "a ring over the unlinked node of the namespace admitted"
    );
}

/// A round keeps each name its predicate accepts once, however many slots
/// and descriptors list it, and keeps no other name. The ring here is held
/// through five descriptors, each read on every pass over the table, and
/// its table registers the namespace in sixteen slots beside two other
/// files.
#[test]
fn a_round_keeps_each_matching_name_once_and_no_other_name() {
    let fixture = Fixture::new(4096);
    let mut files = vec!["/dev/nvme1n1"; 16];
    files.extend(["/var/log", "other"]);
    let info = ring_info(&files);
    for fd in 5..10 {
        hold_ring(&fixture, "4242", fd, &info);
    }
    let kernel = Kernel::read(&fixture.host.proc);
    let mut kept = BTreeSet::new();
    let round = fixture.host.ring_round(
        kernel,
        &|name: &str| name == "nvme1n1",
        &mut BTreeSet::new(),
        &mut kept,
    );
    assert_eq!(round, Some(()));
    let kept: Vec<&str> = kept.iter().map(String::as_str).collect();
    assert_eq!(kept, ["nvme1n1"]);
}

/// One table that cannot be read while its task is present fails the pass,
/// whichever reader of a shared process table takes its process: here the
/// `fd` entry of one process among sixty-four is a file.
#[test]
fn an_unreadable_table_among_many_fails_the_pass() {
    let fixture = Fixture::new(4096);
    for pid in 3000..3064 {
        hold_ring(&fixture, &pid.to_string(), 5, &ring_info(&["file"]));
    }
    assert_eq!(
        fixture.host.registered(|_| true),
        Some(vec!["file".to_owned()]),
        "premise: every table is readable"
    );
    let table = fixture.host.proc.join("3040/fd");
    fs::remove_dir_all(&table).unwrap();
    fs::write(&table, "").unwrap();
    assert_eq!(fixture.host.registered(|_| true), None);
}

/// A ring's `fdinfo` that lists fewer slots than its count, as the kernel
/// prints beside a submission that holds the ring's lock, is read again, and
/// the reading that lists the table whole decides. The first read of the
/// ring's `fdinfo`, a FIFO here, returns the count alone; every later read
/// lists the namespace.
#[test]
fn a_ring_table_listed_short_once_is_read_again() {
    let fixture = Fixture::new(4096);
    hold_ring(&fixture, "4242", 5, &ring_info(&["nvme1n1"]));
    let info = fixture.host.proc.join("4242/fdinfo/5");
    make_fifo(&info);
    let writer = {
        let info = info.clone();
        thread::spawn(move || {
            let mut sink = fs::OpenOptions::new().write(true).open(&info).unwrap();
            fs::remove_file(&info).unwrap();
            fs::write(&info, ring_info(&["nvme1n1"])).unwrap();
            let _sent = sink.write_all(b"pos:\t0\nUserFiles:\t1\nUserBufs:\t0\n");
        })
    };
    let checked = fixture.host.check_unused("nvme1n1").map(drop);
    let _reader = release(&info);
    writer.join().unwrap();
    assert_eq!(
        checked,
        Err(IdentityError::InUse("nvme1n1".into())),
        "a ring whose table one read listed short"
    );
}

/// A ring that holds the namespace registered and moves to an unlisted
/// descriptor number during every pass over its table shows a sign of a move
/// in each pass, so the ring reading goes on to its bound of passes and the
/// check has no answer. Each pass reads the `fdinfo` of an empty ring listed
/// first, a FIFO here, and the ring moves while that read waits, to a number
/// the pass's listing did not return, so its old number reads `ENOENT`. The
/// refusal shows that each pass that saw a number vanish was followed by
/// another, up to the bound.
#[test]
fn a_ring_that_moves_during_every_pass_leaves_the_check_without_an_answer() {
    let fixture = Fixture::new(4096);
    let table = fixture.root.join("proc/4242/fd");
    let info = fixture.root.join("proc/4242/fdinfo");
    for fd in [5, 9] {
        hold_ring(&fixture, "4242", fd, &ring_info(&[]));
    }
    let listed = |table: &Path| -> Vec<String> {
        fs::read_dir(table)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .filter(|name| name.bytes().all(|byte| byte.is_ascii_digit()))
            .collect()
    };
    let [pause, ring] = <[String; 2]>::try_from(listed(&table)).unwrap();
    fs::write(info.join(&ring), ring_info(&["nvme1n1"])).unwrap();
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "premise: the ring listed last is found"
    );
    let fifo = info.join(&pause);
    make_fifo(&fifo);
    let stop = Arc::new(AtomicBool::new(false));
    let writer = {
        let (fifo, table, info, pause, stop) = (
            fifo.clone(),
            table.clone(),
            info.clone(),
            pause.clone(),
            Arc::clone(&stop),
        );
        thread::spawn(move || {
            let shift = |from: &str, to: &str| {
                fs::rename(table.join(from), table.join(to)).unwrap();
                fs::rename(info.join(from), info.join(to)).unwrap();
            };
            let mut at = ring;
            let mut moves = 0u32;
            loop {
                let mut sink = fs::OpenOptions::new().write(true).open(&fifo).unwrap();
                if stop.load(Ordering::SeqCst) {
                    return (moves, at);
                }
                // The ring moves to a number the next listing yields after the empty ring.
                let mut moved = false;
                for number in 100 * (moves + 1)..100 * (moves + 2) {
                    let to = number.to_string();
                    shift(&at, &to);
                    if listed(&table) != [pause.clone(), to.clone()] {
                        fs::rename(table.join(&pause), table.join("renamed")).unwrap();
                        fs::rename(table.join("renamed"), table.join(&pause)).unwrap();
                    }
                    if listed(&table) == [pause.clone(), to.clone()] {
                        at = to;
                        moved = true;
                        break;
                    }
                    shift(&to, &at);
                }
                assert!(moved, "premise: no number lists after the empty ring");
                moves += 1;
                make_fifo(&fifo);
                let _sent = sink.write_all(ring_info(&[]).as_bytes());
            }
        })
    };
    let checked = fixture.host.check_unused("nvme1n1").map(drop);
    stop.store(true, Ordering::SeqCst);
    while !writer.is_finished() {
        release(&fifo);
        thread::yield_now();
    }
    let (moves, at) = writer.join().unwrap();
    fs::remove_file(&fifo).unwrap();
    fs::write(&fifo, ring_info(&[])).unwrap();
    assert!(
        moves >= 2,
        "premise: the ring moved during the check, {moves} times"
    );
    assert_eq!(
        fs::read_to_string(info.join(&at)).unwrap(),
        ring_info(&["nvme1n1"]),
        "premise: the ring holds the namespace under its last number"
    );
    assert_eq!(
        checked,
        Err(IdentityError::Unverifiable("processes")),
        "a ring that moved during every pass, {moves} times"
    );
}

/// A table whose passes each find rings at other numbers than the pass before,
/// with no descriptor vanishing, is read again until the bound of passes, and
/// the check then has no answer. The table lists a file, an empty ring, the
/// ring that holds the namespace and a second empty ring. In each pass, while
/// the first empty ring's `fdinfo`, a FIFO, is read, the holding ring moves
/// onto the file's number, which the pass has read, and its old number takes a
/// file in odd passes and an empty ring in even ones; while the second empty
/// ring's `fdinfo`, a FIFO, is read, the ring moves back. Every read succeeds,
/// the ring is a descriptor of the process at every instant, and no pass reads
/// it. The refusal shows that each pass whose ring numbers differ from the
/// pass before is followed by another, up to the bound.
#[test]
fn a_table_whose_rings_change_numbers_in_every_pass_leaves_the_check_without_an_answer() {
    let fixture = Fixture::new(4096);
    fixture.file("var/log", "");
    let log = fixture.root.join("var/log");
    let table = fixture.root.join("proc/4242/fd");
    let info = fixture.root.join("proc/4242/fdinfo");
    for fd in [5, 9, 13, 17] {
        hold_ring(&fixture, "4242", fd, &ring_info(&[]));
    }
    let listed = |table: &Path| -> Vec<String> {
        fs::read_dir(table)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .filter(|name| name.bytes().all(|byte| byte.is_ascii_digit()))
            .collect()
    };
    let order = listed(&table);
    let [file, first, ring, second] = <[String; 4]>::try_from(order.clone()).unwrap();
    // Puts `target` as the link at `number` in one step, which keeps the number's place in the listing.
    let staged = fixture.root.join("staged");
    let place = {
        let (table, staged, order) = (table.clone(), staged.clone(), order.clone());
        move |number: &str, target: &Path| {
            symlink(target, &staged).unwrap();
            fs::rename(&staged, table.join(number)).unwrap();
            let now: Vec<String> = fs::read_dir(&table)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().into_string().unwrap())
                .filter(|name| name.bytes().all(|byte| byte.is_ascii_digit()))
                .collect();
            assert_eq!(
                now, order,
                "premise: a replaced link keeps its place in the listing"
            );
        }
    };
    let ring_link = Path::new("anon_inode:[io_uring]");
    place(&file, &log);
    fs::remove_file(info.join(&file)).unwrap();
    fs::write(info.join(&ring), ring_info(&["nvme1n1"])).unwrap();
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "premise: the ring is found while nothing moves"
    );
    let (leave, back) = (info.join(&first), info.join(&second));
    make_fifo(&leave);
    make_fifo(&back);
    let stop = Arc::new(AtomicBool::new(false));
    let leaver = {
        let (leave, info, log, place, stop) = (
            leave.clone(),
            info.clone(),
            log.clone(),
            place.clone(),
            Arc::clone(&stop),
        );
        let (file, ring) = (file.clone(), ring.clone());
        thread::spawn(move || {
            let mut passes = 0u32;
            loop {
                let mut sink = fs::OpenOptions::new().write(true).open(&leave).unwrap();
                if stop.load(Ordering::SeqCst) {
                    return passes;
                }
                passes += 1;
                // The file's number holds the ring before the ring's old number lets it go.
                fs::write(info.join(&file), ring_info(&["nvme1n1"])).unwrap();
                place(&file, ring_link);
                if !passes.is_multiple_of(2) {
                    place(&ring, &log);
                    fs::remove_file(info.join(&ring)).unwrap();
                } else {
                    fs::write(info.join(&ring), ring_info(&[])).unwrap();
                }
                make_fifo(&leave);
                let _sent = sink.write_all(ring_info(&[]).as_bytes());
            }
        })
    };
    let returner = {
        let (back, info, log, place, stop) = (
            back.clone(),
            info.clone(),
            log.clone(),
            place.clone(),
            Arc::clone(&stop),
        );
        let (file, ring) = (file.clone(), ring.clone());
        thread::spawn(move || {
            loop {
                let mut sink = fs::OpenOptions::new().write(true).open(&back).unwrap();
                if stop.load(Ordering::SeqCst) {
                    return;
                }
                // The ring's old number holds the ring again before the file's number lets it go.
                fs::write(info.join(&ring), ring_info(&["nvme1n1"])).unwrap();
                place(&ring, ring_link);
                place(&file, &log);
                fs::remove_file(info.join(&file)).unwrap();
                make_fifo(&back);
                let _sent = sink.write_all(ring_info(&[]).as_bytes());
            }
        })
    };
    let checked = fixture.host.check_unused("nvme1n1").map(drop);
    stop.store(true, Ordering::SeqCst);
    while !(leaver.is_finished() && returner.is_finished()) {
        release(&leave);
        release(&back);
        thread::yield_now();
    }
    let passes = leaver.join().unwrap();
    returner.join().unwrap();
    assert!(
        passes >= 8,
        "premise: the ring moved in every pass, {passes} passes"
    );
    assert_eq!(
        checked,
        Err(IdentityError::Unverifiable("processes")),
        "a table whose rings changed numbers in each of {passes} passes"
    );
}

/// A process under an ID an earlier round listed with another start tick is
/// one no round listed, so a round reads its rings. Here the process under
/// the ID in the first round started in tick 5 and holds a ring with no
/// registered file; the process under the ID in the second round started in
/// tick 9 and holds a ring that registers the namespace.
#[test]
fn a_ring_of_a_process_under_a_reused_id_is_read() {
    let fixture = Fixture::new(4096);
    let kernel = Kernel::read(&fixture.host.proc);
    let namespace = |name: &str| name == "nvme1n1";
    let (mut seen, mut kept) = (BTreeSet::new(), BTreeSet::new());
    fixture.thread_started(4242, 4242, 5);
    hold_ring(&fixture, "4242", 5, &ring_info(&[]));
    let first = fixture
        .host
        .ring_round(kernel, &namespace, &mut seen, &mut kept);
    assert_eq!(first, Some(()));
    assert!(
        kept.is_empty(),
        "premise: the first process's ring is empty"
    );
    fs::remove_dir_all(fixture.host.proc.join("4242")).unwrap();
    fixture.thread_started(4242, 4242, 9);
    hold_ring(&fixture, "4242", 5, &ring_info(&["/dev/nvme1n1"]));
    let second = fixture
        .host
        .ring_round(kernel, &namespace, &mut seen, &mut kept);
    assert_eq!(second, Some(()));
    let kept: Vec<&str> = kept.iter().map(String::as_str).collect();
    assert_eq!(kept, ["nvme1n1"]);
}

/// A process without a start tick under an ID an earlier round listed
/// without one may be that round's process or one the host gave its ID
/// since, so the round fails and the pass has no answer. One listing of a
/// process without a start tick completes and reads its rings. A process
/// with a start tick under that ID is one no round listed, and a round that
/// lists it again with the same tick adds no process.
#[test]
fn a_process_without_a_start_tick_under_an_id_listed_without_one_fails_the_pass() {
    let fixture = Fixture::new(4096);
    let kernel = Kernel::read(&fixture.host.proc);
    let namespace = |name: &str| name == "nvme1n1";
    let round = |seen: &mut BTreeSet<_>| {
        let mut kept = BTreeSet::new();
        let round = fixture.host.ring_round(kernel, &namespace, seen, &mut kept);
        round.map(|()| kept.into_iter().collect::<Vec<_>>())
    };
    hold_ring(&fixture, "4242", 5, &ring_info(&["/dev/nvme1n1"]));
    let registered = Some(vec!["nvme1n1".to_owned()]);
    assert_eq!(
        fixture.host.registered(namespace),
        registered,
        "premise: the pass answers while the process shows a start tick"
    );
    fs::remove_file(fixture.host.proc.join("4242/task/4242/stat")).unwrap();
    let mut seen = BTreeSet::new();
    assert_eq!(round(&mut seen), registered, "one listing without a tick");
    assert_eq!(round(&mut seen), None, "a second listing without a tick");
    assert_eq!(fixture.host.registered(namespace), None);
    fixture.thread_started(4242, 4242, 9);
    assert_eq!(round(&mut seen), registered, "a process with a tick");
    assert_eq!(round(&mut seen), Some(Vec::new()), "the same process");
    assert_eq!(seen.len(), 2);
}
