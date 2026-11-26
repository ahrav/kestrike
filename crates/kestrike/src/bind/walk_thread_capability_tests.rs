//! A process walk from a thread that cannot trace every process has no
//! answer.
//!
//! [`Host::opened`] promises every matching node some open descriptor refers
//! to, and `None` when the walker lacks `CAP_SYS_PTRACE`, because a procfs
//! mounted with `hidepid` then lists no process the walker may not trace.
//! Linux keeps capabilities per thread, and the walk's listing and walker
//! threads carry the credentials of the thread that calls `opened`. The
//! case walks from a thread that dropped `CAP_SYS_PTRACE` while the
//! process's first thread keeps it, over a `hidepid` procfs that hides the
//! one process holding the target, and the walk must return `None` rather
//! than an answer without the target. The sibling walks the same table from
//! a thread that keeps the capability and returns the target.
//!
//! The case needs a `hidepid` procfs and a full capability set, so a forked
//! copy of a fresh child of the test executable enters its own user, PID
//! and mount namespaces, and that copy's child, the first process of the
//! PID namespace, mounts the procfs and walks it. The holder marks itself
//! undumpable, which makes it untraceable by a process of its own user that
//! lacks the capability.
//!
//! The walk has no answer outside the initial user namespace, whatever the
//! calling thread holds. Every process the mounted procfs lists belongs to
//! the copy's user namespace, where the capability does trace it, so the
//! case binds over the walker's `self/ns` a directory whose `user` names the
//! user namespace the test started in. The walk then reads the initial
//! namespace there, as it does in the fixture's table, and the calling
//! thread's capability alone decides both walks.

use std::ffi::CString;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use super::fixture::Fixture;
use super::host::Host;
use super::walk::Node;
use crate::exact_child;

/// Bounds the fresh child, which builds one fixture and walks it twice.
const CHILD_DEADLINE: Duration = Duration::from_secs(60);

/// The bit of `CAP_SYS_PTRACE` in a capability set, from `linux/capability.h`.
const CAP_SYS_PTRACE: u32 = 19;
/// `_LINUX_CAPABILITY_VERSION_3`, whose sets span two 32-bit words.
const CAPABILITY_VERSION: u32 = 0x2008_0522;

/// Exit codes of the namespace copies.
const NO_NAMESPACE: i32 = 3;
const NO_MOUNT: i32 = 4;
const NO_INITIAL_NAMESPACE: i32 = 12;
const NO_HOLDER: i32 = 5;
const HOLDER_NOT_FOUND_WITH_CAPABILITY: i32 = 6;
const CAPABILITY_NOT_DROPPED: i32 = 7;
const NO_ANSWER_WITH_CAPABILITY: i32 = 11;
const HOLDER_NOT_HIDDEN: i32 = 8;
const ANSWERED_WITHOUT_TARGET: i32 = 9;
const ANSWERED_WITH_TARGET: i32 = 10;

/// The header of `capget` and `capset`, from `linux/capability.h`.
#[repr(C)]
struct CapabilityHeader {
    version: u32,
    pid: libc::c_int,
}

/// One 32-bit word of a task's capability sets.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapabilityWord {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// Removes `CAP_SYS_PTRACE` from the calling thread's effective and
/// permitted sets, and reports whether the kernel accepted it.
fn drop_ptrace_on_this_thread() -> bool {
    let header = CapabilityHeader {
        version: CAPABILITY_VERSION,
        pid: 0,
    };
    let mut sets = [CapabilityWord::default(); 2];
    // SAFETY: `header` is a valid version-3 header and `sets` is writable
    // for the two words that version fills.
    if unsafe { libc::syscall(libc::SYS_capget, &raw const header, sets.as_mut_ptr()) } != 0 {
        return false;
    }
    sets[0].effective &= !(1 << CAP_SYS_PTRACE);
    sets[0].permitted &= !(1 << CAP_SYS_PTRACE);
    // SAFETY: `header` and `sets` are valid for the version-3 call, which
    // changes only the calling thread's sets.
    unsafe { libc::syscall(libc::SYS_capset, &raw const header, sets.as_ptr()) == 0 }
}

/// Whether the `status` file at `path` reports `CAP_SYS_PTRACE` effective.
fn reports_ptrace(path: &Path) -> bool {
    std::fs::read_to_string(path).is_ok_and(|status| {
        status
            .lines()
            .find_map(|line| line.strip_prefix("CapEff:"))
            .and_then(|set| u64::from_str_radix(set.trim(), 16).ok())
            .is_some_and(|set| set & (1 << CAP_SYS_PTRACE) != 0)
    })
}

/// The environment variable that names the target the holder process holds.
const HOLDER_TARGET: &str = "KESTRIKE_WALK_HOLDER_TARGET";
/// The libtest ID of [`holder_process_entry`].
const HOLDER_ENTRY: &str = "bind::walk_thread_capability_tests::holder_process_entry";
/// The line the holder writes once it holds the target undumpable.
const HOLDING: &str = "holder: holding";

/// The body of the holder process, which [`undumpable_holder`] executes
/// with [`HOLDER_TARGET`] set: opens the target, marks the process
/// undumpable, reports it and waits to be killed. In any other run of the
/// test executable the variable is unset and this does nothing.
///
/// The holder executes inside the user namespace so that the kernel ties
/// its memory to that namespace, where the walker's capability applies; an
/// execution resets the dumpable flag, so the holder clears it afterward.
#[test]
fn holder_process_entry() {
    let Some(target) = std::env::var_os(HOLDER_TARGET) else {
        return;
    };
    let held = std::fs::File::open(target).unwrap();
    // SAFETY: `prctl(PR_SET_DUMPABLE)` takes no memory arguments.
    assert_eq!(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) }, 0);
    println!("{HOLDING}");
    std::io::stdout().flush().unwrap();
    loop {
        thread::park();
        let _ = &held;
    }
}

/// Starts a process of `executable`, this test executable, that holds
/// `target` open and marks itself undumpable. Returns it once it reports
/// holding the target.
fn undumpable_holder(executable: &Path, target: &Path) -> Option<Child> {
    let mut holder = Command::new(executable)
        .args(["--exact", HOLDER_ENTRY, "--nocapture", "--test-threads=1"])
        .env(HOLDER_TARGET, target)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let lines = BufReader::new(holder.stdout.take()?).lines();
    lines
        .map_while(Result::ok)
        .any(|line| line.contains(HOLDING))
        .then_some(holder)
}

/// Binds over the calling process's `self/ns` in the procfs at `mount` a
/// directory whose `user` is a link to `namespace`, an open `ns/user` file,
/// through this process's descriptor table. Reports whether the procfs then
/// names that namespace as this process's own.
fn names_user_namespace(mount: &Path, namespace: &File) -> bool {
    let names = mount.with_file_name("initial-ns");
    let link = mount.join(format!("self/fd/{}", namespace.as_raw_fd()));
    let linked = std::fs::create_dir(&names).is_ok()
        && std::os::unix::fs::symlink(link, names.join("user")).is_ok();
    let paths = (
        CString::new(names.as_os_str().as_bytes()),
        CString::new(mount.join("self/ns").as_os_str().as_bytes()),
    );
    let (Ok(from), Ok(over)) = paths else {
        return false;
    };
    // SAFETY: both paths are NUL-terminated strings that outlive the call,
    // and a bind mount reads no file system type or data.
    let bound = linked
        && unsafe {
            libc::mount(
                from.as_ptr(),
                over.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        } == 0;
    let inode = |file: std::io::Result<std::fs::Metadata>| file.ok().map(|meta| meta.ino());
    bound && inode(std::fs::metadata(mount.join("self/ns/user"))) == inode(namespace.metadata())
}

/// The exit code of the first process of the copy's PID namespace: walks
/// `host` over a `hidepid` procfs mounted at `mount`, first from a thread
/// that keeps `CAP_SYS_PTRACE` and then from one that dropped it, while a
/// process of `executable` holds `target`, identified as `node`, undumpable.
/// `initial` is the `ns/user` file of the user namespace the test started
/// in, which the procfs reports as this process's own.
fn walk_from_a_thread_without_the_capability(
    host: &Host,
    mount: &Path,
    executable: &Path,
    target: &Path,
    node: Node,
    initial: &File,
) -> i32 {
    let Ok(at) = CString::new(mount.as_os_str().as_bytes()) else {
        return NO_MOUNT;
    };
    // SAFETY: every pointer is a NUL-terminated string that outlives the call.
    let mounted = unsafe {
        libc::mount(
            c"proc".as_ptr(),
            at.as_ptr(),
            c"proc".as_ptr(),
            0,
            c"hidepid=2".as_ptr().cast(),
        )
    };
    if mounted != 0 {
        return NO_MOUNT;
    }
    if !names_user_namespace(mount, initial) {
        return NO_INITIAL_NAMESPACE;
    }
    let Some(holder) = undumpable_holder(executable, target) else {
        return NO_HOLDER;
    };
    let status = |task: &str| mount.join(task).join("status");
    let host = Host {
        proc: mount.to_path_buf(),
        ..host.clone()
    };
    let walk = || host.opened(|found| found == node);
    let with_capability = thread::scope(|scope| scope.spawn(walk).join());
    match with_capability {
        Ok(Some(found)) if found == [node] => {}
        Ok(None) => return NO_ANSWER_WITH_CAPABILITY,
        _ => return HOLDER_NOT_FOUND_WITH_CAPABILITY,
    }
    let without = thread::scope(|scope| {
        scope
            .spawn(|| {
                if !drop_ptrace_on_this_thread()
                    || reports_ptrace(&status("thread-self"))
                    || !reports_ptrace(&status("self"))
                {
                    return Err(CAPABILITY_NOT_DROPPED);
                }
                if mount.join(holder.id().to_string()).exists() {
                    return Err(HOLDER_NOT_HIDDEN);
                }
                Ok(walk())
            })
            .join()
    });
    match without {
        Ok(Ok(None)) => 0,
        Ok(Ok(Some(found))) if found.is_empty() => ANSWERED_WITHOUT_TARGET,
        Ok(Ok(Some(_))) => ANSWERED_WITH_TARGET,
        Ok(Err(code)) => code,
        Err(_) => 101,
    }
}

/// The exit code of the forked copy: enters its own user, PID and mount
/// namespaces and runs the walks in a child, the PID namespace's first
/// process, whose exit code it returns.
fn in_namespaces(walks: impl FnOnce() -> i32) -> i32 {
    // SAFETY: both calls read this process's credentials.
    let (user, group) = unsafe { (libc::geteuid(), libc::getegid()) };
    // SAFETY: `unshare` takes no memory arguments, and this forked copy has
    // one thread.
    if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWPID | libc::CLONE_NEWNS) } != 0 {
        return NO_NAMESPACE;
    }
    // The copy's user and group become the namespace's root, so files the
    // namespace's processes read and execute have an owner it can name.
    let mapped = std::fs::write("/proc/self/setgroups", "deny").is_ok()
        && std::fs::write("/proc/self/uid_map", format!("0 {user} 1")).is_ok()
        && std::fs::write("/proc/self/gid_map", format!("0 {group} 1")).is_ok();
    if !mapped {
        return NO_NAMESPACE;
    }
    // SAFETY: the child runs only `walks` and leaves through `_exit`.
    let first = unsafe { libc::fork() };
    if first == 0 {
        let code = std::panic::catch_unwind(std::panic::AssertUnwindSafe(walks));
        // SAFETY: `_exit` ends the child without running exit handlers.
        unsafe { libc::_exit(code.unwrap_or(101)) };
    }
    let mut status = 0;
    // SAFETY: `status` is a valid, writable `c_int`.
    if first < 0 || unsafe { libc::waitpid(first, &mut status, 0) } != first {
        return NO_NAMESPACE;
    }
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        102
    }
}

/// A walk from a thread without `CAP_SYS_PTRACE` over a procfs that hides
/// the target's one holder has no answer, where an answer without the
/// target would report the target unused.
#[test]
fn a_walk_from_a_thread_that_cannot_trace_every_process_has_no_answer() {
    exact_child::run(
        "bind::walk_thread_capability_tests::a_walk_from_a_thread_that_cannot_trace_every_process_has_no_answer",
        CHILD_DEADLINE,
        || {
            let fixture = Fixture::new(4096);
            let target = fixture.host.dev.join("held");
            std::fs::create_dir_all(&fixture.host.dev).unwrap();
            std::fs::write(&target, "").unwrap();
            let node = Host::node(&target).unwrap();
            let mount = fixture.root.join("hidden-proc");
            std::fs::create_dir_all(&mount).unwrap();
            let executable = std::env::current_exe().unwrap();
            let initial = File::open("/proc/self/ns/user").unwrap();
            // The inode the kernel gives the initial user namespace's file.
            // A walk started anywhere else has no answer with the capability
            // either, so the case has no premise there.
            if initial.metadata().unwrap().ino() != 0xEFFF_FFFD {
                eprintln!("not run: this test started outside the initial user namespace");
                return;
            }
            // SAFETY: the copy runs only `in_namespaces` and leaves through
            // `_exit`, so it never returns into this process's test harness.
            let copy = unsafe { libc::fork() };
            assert!(copy >= 0, "fork failed");
            if copy == 0 {
                let code = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    in_namespaces(|| {
                        walk_from_a_thread_without_the_capability(
                            &fixture.host,
                            &mount,
                            &executable,
                            &target,
                            node,
                            &initial,
                        )
                    })
                }));
                // SAFETY: `_exit` ends the copy without running the
                // harness's exit handlers.
                unsafe { libc::_exit(code.unwrap_or(101)) };
            }
            let mut status = 0;
            // SAFETY: `status` is a valid, writable `c_int`, and `copy` is
            // this process's child.
            assert_eq!(unsafe { libc::waitpid(copy, &mut status, 0) }, copy);
            assert!(libc::WIFEXITED(status), "the copy ended by a signal");
            match libc::WEXITSTATUS(status) {
                0 => {}
                // A host that refuses unprivileged user namespaces or the
                // procfs mount cannot hide the holder.
                NO_NAMESPACE => eprintln!("not run: this host refuses the namespaces"),
                NO_MOUNT => eprintln!("not run: this host refuses a hidepid procfs mount"),
                NO_INITIAL_NAMESPACE => {
                    panic!(
                        "premise: the procfs did not name the user namespace the test started in"
                    )
                }
                NO_HOLDER => panic!("premise: no undumpable process held the target"),
                HOLDER_NOT_FOUND_WITH_CAPABILITY => {
                    panic!("premise: the walk of a thread with the capability lacked the target")
                }
                NO_ANSWER_WITH_CAPABILITY => {
                    panic!("premise: the walk of a thread with the capability had no answer")
                }
                CAPABILITY_NOT_DROPPED => {
                    panic!("premise: the thread kept the capability or the process lost it")
                }
                HOLDER_NOT_HIDDEN => panic!("premise: the procfs showed the holder to the thread"),
                ANSWERED_WITHOUT_TARGET => panic!(
                    "a walk that could not trace the target's holder answered that nothing holds it"
                ),
                ANSWERED_WITH_TARGET => {
                    panic!("premise: the walk without the capability read the holder")
                }
                code => panic!("the copy exited {code}"),
            }
        },
    );
}
