//! The supervised side of a binder step: a child process connects a
//! [`Control`] to its supervisor's Unix socket, and every step of
//! [`checkpoint`](super::checkpoint), every driver write and every restoring
//! network command of the child's [`FakeKernel`](super::fixture::FakeKernel)
//! then stops twice.
//!
//! Before a step the child sends `ready` and waits for `execute`, whose
//! `accept` flag, when false, makes the step fail: a bind's driver write
//! returns `EIO`, and a preflight, second capture or group guard reads one
//! corrupted input, restored after the step. After the step the child sends `done`
//! with the step's result and waits for `advance`. A child waiting for
//! `advance` has completed the step and nothing after it, so a supervisor
//! that kills it there kills it between two steps. When the binder call
//! returns, the child sends `result` with the call's result.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::fixture::{RELEASE, group_of};

/// The bind's driver writes; a refused one fails the write itself.
const WRITES: [&str; 3] = ["setOverride", "unbind", "vfioBind"];
/// The bind steps whose refusal rolls the moved devices back inside the
/// same call.
pub(super) const ROLLED_BACK: [&str; 4] = ["secondCapture", "setOverride", "unbind", "vfioBind"];

/// One report of a child: `ready` before a step, `done` after it, or
/// `result` when the binder call returns. `device` is the PCI address a
/// driver step names, the command line of a network step, or empty.
/// `result` is `ok` or `refused` for a step and the call's result for
/// `result`. `guards` maps each device whose group guard the child holds
/// open to the guard's descriptor, inode and device number.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct Report {
    pub(super) kind: String,
    pub(super) phase: String,
    pub(super) device: String,
    pub(super) result: String,
    pub(super) guards: BTreeMap<String, (i32, u64, u64)>,
}

/// A supervisor's reply: `execute` before a step, with whether the step
/// may succeed, or `advance` after it.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct Command {
    pub(super) verb: String,
    pub(super) accept: bool,
}

/// A child's connection to its supervisor. `mode` is the binder call the
/// child runs, `bind` or `release`, and becomes `rollback` once a step of
/// [`ROLLED_BACK`] is refused, which names the driver writes and network
/// commands that follow.
struct Control {
    stream: BufReader<UnixStream>,
    root: PathBuf,
    mode: String,
    phase: String,
    device: String,
    corrupted: Option<(PathBuf, Vec<u8>)>,
    refuse_write: bool,
    guards: BTreeMap<String, (i32, u64, u64)>,
}

thread_local! {
    static CONTROL: RefCell<Option<Control>> = const { RefCell::new(None) };
}

impl Control {
    fn send(&mut self, kind: &str, result: &str) {
        // A guard closed since its step is no longer held.
        self.guards.retain(|_, (fd, inode, rdev)| {
            fs::metadata(format!("/proc/self/fd/{fd}"))
                .is_ok_and(|meta| meta.ino() == *inode && meta.rdev() == *rdev)
        });
        let report = Report {
            kind: kind.to_owned(),
            phase: self.phase.clone(),
            device: self.device.clone(),
            result: result.to_owned(),
            guards: self.guards.clone(),
        };
        let mut line = serde_json::to_string(&report).unwrap();
        line.push('\n');
        self.stream.get_mut().write_all(line.as_bytes()).unwrap();
    }

    fn receive(&mut self, verb: &str) -> Command {
        let mut line = String::new();
        let read = self.stream.read_line(&mut line).unwrap();
        assert!(read > 0, "the supervisor closed before its {verb}");
        let command: Command = serde_json::from_str(&line).unwrap();
        assert_eq!(command.verb, verb, "the supervisor's reply");
        command
    }
}

/// Connects this thread to the supervisor listening at `socket`. `root` is
/// the fixture tree and `mode` the binder call the thread runs.
pub(super) fn connect(root: PathBuf, socket: &str, mode: &str) {
    let stream = UnixStream::connect(socket).unwrap();
    CONTROL.set(Some(Control {
        stream: BufReader::new(stream),
        root,
        mode: mode.to_owned(),
        phase: String::new(),
        device: String::new(),
        corrupted: None,
        refuse_write: false,
        guards: BTreeMap::new(),
    }));
}

fn with<T>(run: impl FnOnce(&mut Control) -> T) -> Option<T> {
    CONTROL.with_borrow_mut(|control| control.as_mut().map(run))
}

/// Whether this thread connected a supervisor.
pub(super) fn connected() -> bool {
    with(|_| ()).is_some()
}

/// The connected thread's mode, or the empty string without a supervisor.
pub(super) fn mode() -> String {
    with(|control| control.mode.clone()).unwrap_or_default()
}

/// Stops before the step `phase` on `device` and arranges its refusal when
/// the supervisor does not accept it.
pub(super) fn before(phase: &str, device: &str) {
    with(|control| {
        control.phase = phase.to_owned();
        control.device = device.to_owned();
        control.send("ready", "");
        if control.receive("execute").accept {
            return;
        }
        if WRITES.contains(&phase) {
            control.refuse_write = true;
            return;
        }
        let path = control.root.join(match phase {
            "bindPreflight" => format!("boot/config-{RELEASE}"),
            "secondCapture" => format!("sys/bus/pci/devices/{device}/vendor"),
            "groupGuard" => format!("sys/class/vfio/noiommu-{}/dev", group_of(device)),
            _ => panic!("the step {phase} takes no refusal"),
        });
        let bytes = fs::read(&path).unwrap();
        fs::write(&path, "invalid\n").unwrap();
        control.corrupted = Some((path, bytes));
    });
}

/// Restores a corrupted input, reports the step's result and stops until
/// the supervisor advances.
pub(super) fn after(phase: &str, device: &str, ok: bool) {
    with(|control| {
        assert_eq!((&*control.phase, &*control.device), (phase, device));
        if let Some((path, bytes)) = control.corrupted.take() {
            fs::write(path, bytes).unwrap();
        }
        if !ok && ROLLED_BACK.contains(&phase) {
            control.mode = "rollback".to_owned();
        }
        control.send("done", if ok { "ok" } else { "refused" });
        control.receive("advance");
    });
}

/// Reports the binder call's result.
pub(super) fn returned(result: &str) {
    with(|control| control.send("result", result));
}

/// Notes the open group guard of `device`.
pub(super) fn guarded(device: &str, guard: &File) {
    with(|control| {
        let meta = guard.metadata().unwrap();
        let held = (guard.as_raw_fd(), meta.ino(), meta.rdev());
        control.guards.insert(device.to_owned(), held);
    });
}

/// Takes the refusal pending for the next driver write.
pub(super) fn write_refused() -> bool {
    with(|control| std::mem::take(&mut control.refuse_write)).unwrap_or(false)
}

/// Stops before the write of `value` to the driver control file `file` of
/// `device` and returns the step the thread's mode names the write, or
/// `None` without a supervisor.
pub(super) fn driver_before(device: &str, file: &str, value: &str) -> Option<&'static str> {
    let phase = match (mode().as_str(), file, value.trim()) {
        ("", ..) => return None,
        ("bind", "driver_override", _) => "setOverride",
        ("bind", "unbind", _) => "unbind",
        ("bind", "bind", _) => "vfioBind",
        ("release", "unbind", _) => "restoreUnbind",
        ("release", "bind", _) => "restoreBind",
        ("release", "driver_override", "") => "restoreOriginalOverride",
        ("release", "driver_override", _) => "restoreOverride",
        ("rollback", "unbind", _) => "rollbackUnbind",
        ("rollback", "bind", _) => "rollbackBind",
        ("rollback", "driver_override", "") => "rollbackOriginalOverride",
        ("rollback", "driver_override", _) => "rollbackOverride",
        (mode, ..) => panic!("a {mode} writes {file}"),
    };
    before(phase, device);
    Some(phase)
}

/// The step a release or a rollback runs the restoring command `line` as,
/// or `None` for the link listing a restore reads before its batch, for a
/// command of a bind and for a command of an unconnected thread.
pub(super) fn network_phase(mode: &str, line: &str) -> Option<&'static str> {
    if !line.starts_with("ip ") || line == "ip -o link show" {
        return None;
    }
    match mode {
        "release" => Some("networkBatch"),
        "rollback" => Some("rollbackNetworkBatch"),
        _ => None,
    }
}
