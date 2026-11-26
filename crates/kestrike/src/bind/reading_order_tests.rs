//! The order of the in-use check's readings around the descriptor walk,
//! judged on fixture trees whose changes are timed by the check's own
//! reads: a use handed between a descriptor and a ring on either side of
//! the walk, and the one read of the kernel's symbol table whose answer
//! both layout readings take.

use std::fs;
use std::io::Write;
use std::os::unix::fs::symlink;
use std::thread;

use super::fixture::{Fixture, hold_ring, make_fifo, release, ring_info};
use super::identity::IdentityError;

/// A process that holds the namespace through a descriptor and, while the
/// descriptor walk runs, registers it with its ring and closes the descriptor
/// keeps the namespace open at every instant. The handoff happens while the
/// walk reads the uptime, a FIFO here: after the first ring reading, which
/// found the ring's table empty, and before the walk reads any descriptor
/// table. The ring reading after the walk alone finds the namespace.
#[test]
fn a_namespace_handed_from_a_descriptor_to_a_ring_during_the_walk_is_in_use() {
    let fixture = Fixture::new(4096);
    let node = fixture.host.dev.join("nvme1n1");
    hold_ring(&fixture, "4242", 5, &ring_info(&[]));
    let descriptor = fixture.host.proc.join("4242/fd/6");
    symlink(&node, &descriptor).unwrap();
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "premise: the descriptor alone is found"
    );
    let uptime = fixture.host.proc.join("uptime");
    make_fifo(&uptime);
    let info = fixture.host.proc.join("4242/fdinfo/5");
    let writer = {
        let (uptime, info, descriptor) = (uptime.clone(), info.clone(), descriptor.clone());
        thread::spawn(move || {
            let mut sink = fs::OpenOptions::new().write(true).open(&uptime).unwrap();
            fs::write(&info, ring_info(&["nvme1n1"])).unwrap();
            fs::remove_file(&descriptor).unwrap();
            let _sent = sink.write_all(b"100.00 400.00\n");
        })
    };
    let checked = fixture.host.check_unused("nvme1n1").map(drop);
    let _reader = release(&uptime);
    writer.join().unwrap();
    fs::remove_file(&uptime).unwrap();
    fs::write(&uptime, "100.00 400.00\n").unwrap();
    assert!(
        fs::symlink_metadata(&descriptor).is_err(),
        "premise: the handoff ran"
    );
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "premise: after the handoff the ring's registration alone is found"
    );
    assert_eq!(
        checked,
        Err(IdentityError::InUse("nvme1n1".into())),
        "a namespace in use at every instant of the check was admitted"
    );
}

/// A process whose ring holds the namespace registered and that, once the walk
/// has read its leader's table, installs the registered file as a descriptor
/// and removes it from the ring keeps the namespace open at every instant. The
/// handoff happens while the walk reads the start time of the process's other
/// thread, a FIFO here, which it reads after every descriptor of the leader's
/// table. The ring reading before the walk alone finds the namespace: the walk
/// has read the table, and the ring reading after the walk finds the ring's
/// table empty.
#[test]
fn a_namespace_handed_from_a_ring_to_a_descriptor_after_the_walk_read_its_table_is_in_use() {
    let fixture = Fixture::new(4096);
    let node = fixture.host.dev.join("nvme1n1");
    hold_ring(&fixture, "4242", 5, &ring_info(&["nvme1n1"]));
    for tid in [4242, 4243] {
        fs::create_dir_all(fixture.host.proc.join(format!("4242/task/{tid}/fd"))).unwrap();
    }
    fixture.thread_started(4242, 4243, 0);
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "premise: the ring's registration alone is found"
    );
    let stat = fixture.host.proc.join("4242/task/4243/stat");
    let started = fs::read_to_string(&stat).unwrap();
    make_fifo(&stat);
    let info = fixture.host.proc.join("4242/fdinfo/5");
    let descriptor = fixture.host.proc.join("4242/fd/6");
    let writer = {
        let (stat, info, node, descriptor) =
            (stat.clone(), info.clone(), node.clone(), descriptor.clone());
        thread::spawn(move || {
            let mut sink = fs::OpenOptions::new().write(true).open(&stat).unwrap();
            symlink(&node, &descriptor).unwrap();
            fs::write(&info, ring_info(&[])).unwrap();
            // Later reads of the start time find a file again.
            fs::remove_file(&stat).unwrap();
            fs::write(&stat, &started).unwrap();
            let _sent = sink.write_all(started.as_bytes());
        })
    };
    let checked = fixture.host.check_unused("nvme1n1").map(drop);
    let _reader = release(&stat);
    writer.join().unwrap();
    assert_eq!(
        fs::read_link(&descriptor).unwrap(),
        node,
        "premise: the handoff ran"
    );
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "premise: after the handoff the descriptor alone is found"
    );
    assert_eq!(
        checked,
        Err(IdentityError::InUse("nvme1n1".into())),
        "a namespace in use at every instant of the check was admitted"
    );
}

/// One check reads the kernel's symbol table once: the image's symbols are
/// the same at both layout readings, so the second takes the first's
/// answer. The table is a FIFO here, removed once its one read has opened
/// it and answered with a table that lists no built-in driver. The check
/// admits the namespace, and a check that finds no table has no answer.
#[test]
fn one_check_reads_the_symbol_table_once() {
    let fixture = Fixture::new(4096);
    let table = fixture.host.proc.join("kallsyms");
    make_fifo(&table);
    let writer = {
        let table = table.clone();
        thread::spawn(move || {
            let mut sink = fs::OpenOptions::new().write(true).open(&table).unwrap();
            fs::remove_file(&table).unwrap();
            let _sent = sink.write_all(b"ffffffff81000000 T _stext\n");
        })
    };
    let checked = fixture.host.check_unused("nvme1n1").map(drop);
    let _reader = release(&table);
    writer.join().unwrap();
    assert_eq!(checked, Ok(()), "a check that read the symbol table once");
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::Unverifiable("layouts")),
        "premise: a check that finds no symbol table has no answer"
    );
}

/// The first layout reading's refusal comes before the refusal of any
/// reading after it, though the symbol table is read beside those readings.
/// Here the kernel holds the block layout driver built in and the mount
/// table names a mount at a process's directory, which the check refuses
/// after the first layout reading.
#[test]
fn a_built_in_layout_driver_refuses_before_a_later_reading_does() {
    const COVERED: &str = "/dev/nvme0n1p1 / xfs rw 0 0\ntmpfs /proc/4242 tmpfs rw 0 0\n";
    let fixture = Fixture::new(4096);
    fixture.file("proc/self/mounts", COVERED);
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::Unverifiable("processes")),
        "premise: the covered process directory alone refuses"
    );
    fixture.file(
        "proc/kallsyms",
        "ffffffff81000000 T _stext\nffffffff8145e2a0 T bl_alloc_deviceid_node\n",
    );
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::Unverifiable("layouts"))
    );
}
