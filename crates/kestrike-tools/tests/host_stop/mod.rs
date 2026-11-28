#![cfg(target_os = "linux")]

mod evidence;
mod launch;
mod marks;
mod record;
mod signals;

use std::cell::RefCell;
use std::fs::{self, File};
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::thread;
use std::time::{Duration, Instant};

use kestrike_tools::host_stop::{Disk, Files, Links};
use kestrike_tools::temp_dir::make_temp_dir;

/// The variable that names the window a re-started test executable runs.
const ROLE: &str = "HOST_STOP_WINDOW";
/// The variable that names the directory a re-started test executable works in.
const PLACE: &str = "HOST_STOP_PLACE";
/// The longest wait for a file another process writes.
const MARKER_LIMIT: Duration = Duration::from_secs(30);

/// A directory the test process created with mode 0700, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        let parent = std::env::temp_dir()
            .canonicalize()
            .expect("the temporary directory resolves");
        let prefix = format!("kestrike-tools-host-stop-{label}-");
        Self(make_temp_dir(&prefix, &parent).expect("the scratch directory is made"))
    }

    fn dir(&self, name: &str) -> PathBuf {
        let path = self.0.join(name);
        fs::create_dir(&path).expect("the directory is made");
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The sorted names of the entries of `directory`.
fn listing(directory: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(directory)
        .expect("the directory lists")
        .map(|entry| {
            entry
                .expect("the directory lists")
                .file_name()
                .into_string()
                .expect("a UTF-8 name")
        })
        .collect();
    names.sort_unstable();
    names
}

/// `gone` holds once no process `pid` is left, a zombie included, since a zombie keeps `/proc/<pid>`.
fn gone(pid: u32) -> bool {
    match fs::symlink_metadata(Path::new("/proc").join(pid.to_string())) {
        Ok(_) => false,
        Err(error) if error.kind() == io::ErrorKind::NotFound => true,
        Err(error) => panic!("/proc/{pid}: {error}"),
    }
}

/// A newline marks a complete process ID record in `path`.
fn starts(path: &Path) -> Vec<u32> {
    let text = fs::read_to_string(path).unwrap_or_default();
    let mut pids = Vec::new();
    for line in text.split_inclusive('\n') {
        let Some(digits) = line.strip_suffix('\n') else {
            break;
        };
        pids.push(digits.parse().expect("a start line holds a process id"));
    }
    pids
}

fn first_start(path: &Path) -> u32 {
    let start = Instant::now();
    loop {
        if let Some(&pid) = starts(path).first() {
            return pid;
        }
        assert!(
            start.elapsed() < MARKER_LIMIT,
            "{} records a start within {MARKER_LIMIT:?}",
            path.display()
        );
        thread::sleep(Duration::from_millis(5));
    }
}

/// One file step [`Observed`] saw: the step's name and the descriptor or descriptors it acted on.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Seen {
    step: &'static str,
    fds: Vec<RawFd>,
    path: Option<PathBuf>,
}

/// A failure [`Observed`] plants: the `nth` call of `step`, counted from 1, fails with `errno`.
#[derive(Clone, Copy, Debug)]
struct Fault {
    step: &'static str,
    nth: usize,
    errno: i32,
}

/// The system's file steps, each logged before it runs, with the planted faults, a cap on the bytes
/// one write takes, a write that takes nothing, and a pause: at the `nth` call of a step the writer
/// creates the file `ready` and sleeps until it is killed.
#[derive(Default)]
struct Observed {
    seen: RefCell<Vec<Seen>>,
    faults: Vec<Fault>,
    write_cap: Option<usize>,
    stall: Option<usize>,
    overreport: bool,
    pause: Option<(&'static str, usize, PathBuf)>,
}

impl Observed {
    fn failing(faults: &[Fault]) -> Self {
        Self {
            faults: faults.to_vec(),
            ..Self::default()
        }
    }

    fn steps(&self) -> Vec<&'static str> {
        self.seen.borrow().iter().map(|seen| seen.step).collect()
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.borrow().clone()
    }

    /// `enter` logs the step and returns its planted failure, or pauses the writer at it.
    fn enter(&self, step: &'static str, fds: Vec<RawFd>, path: Option<&Path>) -> io::Result<()> {
        let mut seen = self.seen.borrow_mut();
        seen.push(Seen {
            step,
            fds,
            path: path.map(Path::to_path_buf),
        });
        let nth = seen.iter().filter(|seen| seen.step == step).count();
        drop(seen);
        if let Some((at, when, ready)) = &self.pause
            && *at == step
            && *when == nth
        {
            File::create(ready).expect("the ready file is made");
            loop {
                thread::sleep(Duration::from_secs(1));
            }
        }
        match self
            .faults
            .iter()
            .find(|fault| fault.step == step && fault.nth == nth)
        {
            Some(fault) => Err(io::Error::from_raw_os_error(fault.errno)),
            None => Ok(()),
        }
    }
}

impl Files for Observed {
    fn open_directory(&self, path: &Path, links: Links) -> io::Result<File> {
        self.enter("open_directory", vec![], Some(path))?;
        Disk.open_directory(path, links)
    }

    fn open_unnamed(&self, directory: &Path) -> io::Result<File> {
        self.enter("open_unnamed", vec![], Some(directory))?;
        let file = Disk.open_unnamed(directory)?;
        if let Some(seen) = self.seen.borrow_mut().last_mut() {
            seen.fds = vec![file.as_raw_fd()];
        }
        Ok(file)
    }

    fn write(&self, file: &File, bytes: &[u8]) -> io::Result<usize> {
        self.enter("write", vec![file.as_raw_fd()], None)?;
        let nth = self.steps().iter().filter(|step| **step == "write").count();
        if self.stall.is_some_and(|from| nth >= from) {
            return Ok(0);
        }
        let taken = self
            .write_cap
            .map_or(bytes.len(), |cap| cap.min(bytes.len()));
        let written = Disk.write(file, &bytes[..taken])?;
        Ok(if self.overreport {
            bytes.len() + 1
        } else {
            written
        })
    }

    fn fsync(&self, file: &File) -> io::Result<()> {
        self.enter("fsync", vec![file.as_raw_fd()], None)?;
        Disk.fsync(file)
    }

    fn fsync_directory(&self, directory: &File) -> io::Result<()> {
        self.enter("fsync_directory", vec![directory.as_raw_fd()], None)?;
        Disk.fsync_directory(directory)
    }

    fn link(&self, file: &File, directory: &File, name: &std::ffi::OsStr) -> io::Result<()> {
        self.enter("link", vec![file.as_raw_fd(), directory.as_raw_fd()], None)?;
        Disk.link(file, directory, name)
    }

    fn unlink(&self, directory: &File, name: &std::ffi::OsStr) -> io::Result<()> {
        self.enter("unlink", vec![directory.as_raw_fd()], None)?;
        Disk.unlink(directory, name)
    }

    fn try_lock(&self, directory: &File) -> io::Result<()> {
        self.enter("try_lock", vec![directory.as_raw_fd()], None)?;
        Disk.try_lock(directory)
    }

    fn lstat(&self, path: &Path) -> io::Result<fs::Metadata> {
        self.enter("lstat", vec![], Some(path))?;
        Disk.lstat(path)
    }

    fn exists(&self, path: &Path) -> bool {
        self.enter("exists", vec![], Some(path)).is_ok() && Disk.exists(path)
    }

    fn mkdir(&self, path: &Path) -> io::Result<()> {
        self.enter("mkdir", vec![], Some(path))?;
        Disk.mkdir(path)
    }

    fn rmdir(&self, path: &Path) -> io::Result<()> {
        self.enter("rmdir", vec![], Some(path))?;
        Disk.rmdir(path)
    }
}

/// `start_window` starts this test executable again for the test `name` alone, with `window` in
/// [`ROLE`] and `place` in [`PLACE`], under `/bin/sh` running `prefix` before it replaces itself with
/// the executable. The environment is the variables the window reads and nothing else.
fn start_window(name: &str, window: &str, place: &Path, prefix: &str) -> Command {
    let mut command = Command::new("/usr/bin/env");
    command
        .args(["--default-signal=INT,TERM", "/bin/sh", "-c"])
        .arg(format!("{prefix} exec \"$0\" \"$@\""))
        .arg(std::env::current_exe().expect("the test executable is known"))
        .args(["--exact", name, "--nocapture", "--test-threads", "1"])
        .env_clear()
        .env(ROLE, window)
        .env(PLACE, place)
        .env("TMPDIR", std::env::temp_dir());
    command
}

/// `passed` fails the case unless the window's run passed its one test.
fn passed(window: &str, output: &Output) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let shown = format!(
        "{window}: {}\n{stdout}{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "{shown}");
    assert!(stdout.contains("1 passed"), "{shown}");
}
