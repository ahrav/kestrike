//! Safe wrappers over the Linux system calls the standard library does not
//! expose. Every `unsafe` block of the crate is in this module. Each wrapper
//! passes only NUL-terminated names and buffers that outlive its call, and
//! takes sole ownership of each descriptor the kernel returns, so every
//! descriptor closes exactly once.

use std::ffi::CStr;
use std::fs::File;
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::time::Duration;

pub(crate) const TERM_SIGNAL: i32 = libc::SIGTERM;
pub(crate) const LIMIT_MAX: u64 = (1 << 63) - 2;
pub(crate) const CPU_HARD_MAX: u64 = u64::MAX / 1_000_000_000;

/// Writes every dirty page and inode of the filesystem holding `file` to
/// its device and waits for the writes to complete. On Linux 5.8 and
/// later, `syncfs` reports filesystem writeback errors recorded since the
/// previous `syncfs` call on the same open file description, or since
/// open on the first call.
pub(crate) fn sync_filesystem(file: &File) -> io::Result<()> {
    // SAFETY: file owns its open descriptor for the call's duration.
    result(unsafe { libc::syncfs(file.as_raw_fd()) })
}

pub(crate) fn free_space(file: &File) -> io::Result<(u64, u64, std::num::NonZeroU64)> {
    let mut value = MaybeUninit::<libc::statvfs>::zeroed();
    // SAFETY: value holds writable statvfs storage and file owns its descriptor.
    result(unsafe { libc::fstatvfs(file.as_raw_fd(), value.as_mut_ptr()) })?;
    // SAFETY: fstatvfs initialized value on success.
    let value = unsafe { value.assume_init() };
    available_space(value.f_bavail, value.f_favail, value.f_frsize)
}

fn available_space(
    blocks: u64,
    inodes: u64,
    size: u64,
) -> io::Result<(u64, u64, std::num::NonZeroU64)> {
    let fragment = std::num::NonZeroU64::new(size).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "filesystem fragment size is zero",
        )
    })?;
    Ok((blocks.saturating_mul(fragment.get()), inodes, fragment))
}

pub(crate) fn dispatch_limits(cpu: u64, output: u64) -> io::Result<()> {
    if cpu == 0 || output == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "resource budget is zero",
        ));
    }
    for (resource, label, requested, margin, maximum) in [
        (libc::RLIMIT_CPU, "cpu", cpu, 1, CPU_HARD_MAX),
        (libc::RLIMIT_FSIZE, "output", output, 0, LIMIT_MAX),
    ] {
        let bound = hard_limit(resource as u64)?.min(maximum);
        if requested
            .checked_add(margin)
            .is_none_or(|value| value > bound)
        {
            let largest = bound.saturating_sub(margin);
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{label} exceeds largest installable limit {largest}"),
            ));
        }
    }
    Ok(())
}

/// The resolution of every confined open: the name resolves beneath the
/// directory handle, follows no symlink or procfs magic link, and crosses
/// no mount point.
const CONFINED: u64 = libc::RESOLVE_BENEATH
    | libc::RESOLVE_NO_SYMLINKS
    | libc::RESOLVE_NO_MAGICLINKS
    | libc::RESOLVE_NO_XDEV;

fn result(code: libc::c_int) -> io::Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// # Safety
///
/// A nonnegative `fd` must be a new descriptor that nothing else owns.
unsafe fn owned(fd: libc::c_long) -> io::Result<File> {
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd =
        libc::c_int::try_from(fd).map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
    // SAFETY: the caller's contract.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Opens `name` beneath `dir` under the confined resolution, with
/// `O_CLOEXEC` added to `flags`.
pub(crate) fn open_beneath(
    dir: &File,
    name: &CStr,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> io::Result<File> {
    openat2(dir.as_raw_fd(), name, flags, mode, CONFINED)
}

/// Opens the directory at `path`, resolved from the working directory when
/// relative, with no symlink or procfs magic link followed in any
/// component, so a symlink anywhere in `path` fails with `ELOOP`; the open
/// is read-only with `O_DIRECTORY` and `O_CLOEXEC`.
pub(crate) fn open_dir_nofollow(path: &CStr) -> io::Result<File> {
    let flags = libc::O_RDONLY | libc::O_DIRECTORY;
    let resolve = libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS;
    openat2(libc::AT_FDCWD, path, flags, 0, resolve)
}

fn openat2(
    dir: libc::c_int,
    name: &CStr,
    flags: libc::c_int,
    mode: libc::mode_t,
    resolve: u64,
) -> io::Result<File> {
    // SAFETY: `open_how` is plain integers, for which all zeros is valid.
    let mut how: libc::open_how = unsafe { MaybeUninit::zeroed().assume_init() };
    how.flags = u64::from((flags | libc::O_CLOEXEC).cast_unsigned());
    how.mode = u64::from(mode);
    how.resolve = resolve;
    // SAFETY: `name` and `how` outlive the call, and the size is `how`'s.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dir,
            name.as_ptr(),
            &raw const how,
            size_of::<libc::open_how>(),
        )
    };
    // SAFETY: a nonnegative return is the new descriptor of this open.
    unsafe { owned(fd) }
}

/// Whether `dir` carries a default POSIX ACL, which entries created in it
/// would inherit. A filesystem without extended attributes carries none.
pub(crate) fn has_default_acl(dir: &File) -> io::Result<bool> {
    // SAFETY: the name is static and a zero size requests only the attribute's length.
    let size = unsafe {
        libc::fgetxattr(
            dir.as_raw_fd(),
            c"system.posix_acl_default".as_ptr(),
            std::ptr::null_mut(),
            0,
        )
    };
    if size >= 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ENODATA | libc::EOPNOTSUPP) => Ok(false),
        _ => Err(error),
    }
}

/// Removes the default POSIX ACL of `dir`, so entries created in it take
/// only their mode bits. A directory without one, or on a filesystem
/// without extended attributes, is left as it is.
pub(crate) fn clear_default_acl(dir: &File) -> io::Result<()> {
    // SAFETY: the directory descriptor and static attribute name outlive the call.
    let removed = result(unsafe {
        libc::fremovexattr(dir.as_raw_fd(), c"system.posix_acl_default".as_ptr())
    });
    match removed {
        Err(error) if matches!(error.raw_os_error(), Some(libc::ENODATA | libc::EOPNOTSUPP)) => {
            Ok(())
        }
        removed => removed,
    }
}

/// Opens the parent directory of the directory `dir` refers to.
pub(crate) fn open_parent(dir: &File) -> io::Result<File> {
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC;
    // SAFETY: the name is a NUL-terminated literal.
    let fd = unsafe { libc::openat(dir.as_raw_fd(), c"..".as_ptr(), flags) };
    // SAFETY: a nonnegative return is the new descriptor of this open.
    unsafe { owned(fd.into()) }
}

/// Creates directory `name` in `dir` with `mode`.
pub(crate) fn mkdir(dir: &File, name: &CStr, mode: libc::mode_t) -> io::Result<()> {
    // SAFETY: `name` outlives the call.
    result(unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), mode) })
}

/// Unlinks the non-directory entry `name` of `dir`.
pub(crate) fn unlink(dir: &File, name: &CStr) -> io::Result<()> {
    // SAFETY: `name` outlives the call.
    result(unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) })
}

pub(crate) fn rmdir(dir: &File, name: &CStr) -> io::Result<()> {
    // SAFETY: `name` outlives the call.
    result(unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) })
}

pub(crate) fn nonblocking(pipe: &impl AsRawFd) -> io::Result<()> {
    // SAFETY: the descriptor reference remains borrowed throughout both calls.
    let flags = unsafe { libc::fcntl(pipe.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: F_SETFL takes integer flags and touches no memory.
    result(unsafe { libc::fcntl(pipe.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) })
}

/// Renames `from` in `from_dir` to `to` in `to_dir`. With `noreplace`, an
/// existing `to` fails the rename with `EEXIST` and stays as it was.
pub(crate) fn rename(
    from_dir: &File,
    from: &CStr,
    to_dir: &File,
    to: &CStr,
    noreplace: bool,
) -> io::Result<()> {
    let flags = if noreplace { libc::RENAME_NOREPLACE } else { 0 };
    // SAFETY: both names outlive the call.
    result(unsafe {
        libc::renameat2(
            from_dir.as_raw_fd(),
            from.as_ptr(),
            to_dir.as_raw_fd(),
            to.as_ptr(),
            flags,
        )
    })
}

/// Closes `file`, reporting the error that `close` returns.
pub(crate) fn close(file: File) -> io::Result<()> {
    // SAFETY: `into_raw_fd` gives up ownership, so this is the one close.
    result(unsafe { libc::close(file.into_raw_fd()) })
}

/// The process's effective user ID.
pub(crate) fn euid() -> u32 {
    // SAFETY: `geteuid` takes no arguments and cannot fail.
    unsafe { libc::geteuid() }
}

/// The host's machine name as `uname` reports it, such as `x86_64`.
pub(crate) fn machine() -> io::Result<String> {
    let mut name = MaybeUninit::<libc::utsname>::zeroed();
    // SAFETY: `name` is a writable `utsname` that outlives the call.
    result(unsafe { libc::uname(name.as_mut_ptr()) })?;
    // SAFETY: a zeroed `utsname` is a valid value, and `uname` filled it.
    let name = unsafe { name.assume_init() };
    let machine = name.machine.map(|byte| byte.to_ne_bytes()[0]);
    let machine = CStr::from_bytes_until_nul(&machine)
        .map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
    Ok(machine.to_string_lossy().into_owned())
}

/// The ID of the mount `file` lies on, as `/proc/self/mountinfo` numbers it.
pub(crate) fn mount_id(file: &File) -> io::Result<u64> {
    let mut status = MaybeUninit::<libc::statx>::zeroed();
    // SAFETY: the empty name with `AT_EMPTY_PATH` queries `file` itself, and
    // `status` is a writable `statx` that outlives the call.
    result(unsafe {
        libc::statx(
            file.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH,
            libc::STATX_MNT_ID,
            status.as_mut_ptr(),
        )
    })?;
    // SAFETY: a zeroed `statx` is a valid value, and `statx` filled it.
    let status = unsafe { status.assume_init() };
    if status.stx_mask & libc::STATX_MNT_ID == 0 {
        return Err(io::Error::from_raw_os_error(libc::ENOSYS));
    }
    Ok(status.stx_mnt_id)
}

/// Reads the next entries of the directory `dir` refers to into `buffer`
/// as kernel `linux_dirent64` records, returning the bytes filled; 0 at
/// the end. Successive calls on one descriptor continue the listing.
pub(crate) fn entries(dir: &File, buffer: &mut [u8]) -> io::Result<usize> {
    // SAFETY: `buffer` is writable for its whole length during the call.
    let filled = unsafe {
        libc::syscall(
            libc::SYS_getdents64,
            dir.as_raw_fd(),
            buffer.as_mut_ptr(),
            buffer.len(),
        )
    };
    usize::try_from(filled).map_err(|_| io::Error::last_os_error())
}

/// Each entry name of the `linux_dirent64` records in `records`, the bytes
/// one [`entries`] call filled.
pub(crate) fn names(records: &[u8]) -> impl Iterator<Item = &[u8]> {
    // A record holds an 8-byte inode, an 8-byte offset, a 2-byte length, a
    // type byte, then the NUL-terminated name, padded to its length.
    let mut rest = records;
    std::iter::from_fn(move || {
        let length = usize::from(u16::from_ne_bytes([*rest.get(16)?, *rest.get(17)?]));
        let record = rest.get(19..length)?;
        rest = &rest[length..];
        Some(&record[..record.iter().position(|&byte| byte == 0)?])
    })
}

/// The interruption signals, SIGINT and SIGTERM, as a signal set.
fn interruptions() -> io::Result<libc::sigset_t> {
    let mut set = MaybeUninit::<libc::sigset_t>::zeroed();
    // SAFETY: `set` is a writable `sigset_t` that outlives each call, and
    // `sigemptyset` initializes it before `sigaddset` reads it.
    unsafe {
        result(libc::sigemptyset(set.as_mut_ptr()))?;
        result(libc::sigaddset(set.as_mut_ptr(), libc::SIGINT))?;
        result(libc::sigaddset(set.as_mut_ptr(), libc::SIGTERM))?;
        Ok(set.assume_init())
    }
}

/// Blocks SIGINT and SIGTERM in the calling thread, which threads it starts
/// later inherit, so each stays pending until [`interruption`] takes it. A
/// process-directed signal stays pending only while every thread blocks
/// it, so the process's first thread calls this before it starts another.
/// A spawned child inherits the mask; [`contain`] clears the worker's mask.
/// SIGCHLD uses its default disposition so exited children remain waitable.
pub(crate) fn block_interruptions() -> io::Result<()> {
    child_exits()?;
    mask(libc::SIG_BLOCK, &interruptions()?)
}

/// Sets the process's SIGCHLD disposition to its default, so an exited
/// child stays waitable; an inherited `SIG_IGN` would discard its status.
pub(crate) fn child_exits() -> io::Result<()> {
    let mut action = MaybeUninit::<libc::sigaction>::zeroed();
    // SAFETY: the writable action outlives both calls; SIG_DFL uses zero
    // flags and an empty mask. SIGCHLD's default preserves waitable exits.
    unsafe {
        result(libc::sigemptyset(&raw mut (*action.as_mut_ptr()).sa_mask))?;
        (*action.as_mut_ptr()).sa_sigaction = libc::SIG_DFL;
        result(libc::sigaction(
            libc::SIGCHLD,
            action.as_ptr(),
            std::ptr::null_mut(),
        ))?;
    }
    Ok(())
}

/// Applies `how` with `set` to the calling thread's signal mask.
fn mask(how: libc::c_int, set: &libc::sigset_t) -> io::Result<()> {
    // SAFETY: `set` outlives the call, and no old mask is requested.
    let code = unsafe { libc::pthread_sigmask(how, set, std::ptr::null_mut()) };
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code))
    }
}

/// Takes one pending SIGINT or SIGTERM, waiting up to `timeout` for one to
/// arrive; `None` when none did. The signals must be blocked, as
/// [`block_interruptions`] blocks them.
pub(crate) fn interruption(timeout: Duration) -> io::Result<Option<i32>> {
    let set = interruptions()?;
    let timeout = libc::timespec {
        tv_sec: libc::time_t::try_from(timeout.as_secs()).unwrap_or(libc::time_t::MAX),
        tv_nsec: libc::c_long::from(timeout.subsec_nanos().cast_signed()),
    };
    // SAFETY: `set` and `timeout` outlive the call, and no signal
    // information is requested.
    let taken =
        unsafe { libc::sigtimedwait(&raw const set, std::ptr::null_mut(), &raw const timeout) };
    if taken >= 0 {
        return Ok(Some(taken));
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::EAGAIN | libc::EINTR) => Ok(None),
        _ => Err(error),
    }
}

/// Makes the calling process the reaper of its orphaned descendants, so a
/// descendant whose parent exits becomes its child when this process is its nearest
/// subreaper ancestor.
pub(crate) fn child_subreaper() -> io::Result<()> {
    let (on, none): (libc::c_ulong, libc::c_ulong) = (1, 0);
    // SAFETY: `prctl` with this option takes integers and touches no memory.
    result(unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, on, none, none, none) })
}

/// Sets up `command` to start in a new process group of its own, the
/// group whose ID is its process ID, with a umask of 0o077, and
/// to receive SIGKILL when the thread that spawns it exits. The launcher
/// spawns from the process's first thread, whose exit ends the process. A
/// child whose parent died before the request took effect reports `ESRCH` before `exec`.
///
/// # Errors
///
/// A failed signal set construction, before `command` changes.
pub(crate) fn contain(command: &mut Command, directory: &std::path::Path) -> io::Result<()> {
    contain_parent(command, std::process::id(), Some(0o077))?;
    command.current_dir(directory);
    Ok(())
}

/// Sets up `command` to start as the leader of a new process group, with
/// the signal mask of the thread that spawns it, and to receive SIGKILL
/// when that thread exits, so the child ends with the process even when
/// a signal reaches the process's group alone. A child whose parent died
/// before the request took effect reports `ESRCH` before `exec`.
pub(crate) fn lead(command: &mut Command) {
    let parent = std::process::id();
    command.process_group(0);
    // SAFETY: pre_exec runs before exec; `parent_death` makes
    // async-signal-safe calls and allocates nothing.
    unsafe {
        command.pre_exec(move || parent_death(parent));
    }
}

pub(crate) fn working_directory(command: &mut Command, directory: &std::path::Path) {
    command.current_dir(directory);
}

/// Whether `status` is the end of a process that SIGINT or SIGTERM
/// killed, the two signals [`block_interruptions`] blocks.
pub(crate) fn interrupted(status: std::process::ExitStatus) -> bool {
    use std::os::unix::process::ExitStatusExt;
    matches!(status.signal(), Some(libc::SIGINT | libc::SIGTERM))
}

pub(crate) fn gate_setup(command: &mut Command) -> io::Result<()> {
    // SAFETY: getppid takes no pointers and returns this process's parent identity.
    let parent = unsafe { libc::getppid() }.cast_unsigned();
    contain_parent(command, parent, Some(0o077))
}

pub(crate) fn hardware_setup(command: &mut Command, directory: &std::path::Path) -> io::Result<()> {
    contain_parent(command, std::process::id(), None)?;
    command.current_dir(directory);
    Ok(())
}

fn contain_parent(
    command: &mut Command,
    parent: u32,
    umask: Option<libc::mode_t>,
) -> io::Result<()> {
    let mut unblocked = MaybeUninit::<libc::sigset_t>::zeroed();
    // SAFETY: the writable set outlives the call and is initialized by it.
    let unblocked = unsafe {
        result(libc::sigemptyset(unblocked.as_mut_ptr()))?;
        unblocked.assume_init()
    };
    command.process_group(0);
    // SAFETY: pre_exec runs before exec; its calls are async-signal-safe and allocate nothing.
    unsafe {
        command.pre_exec(move || {
            mask(libc::SIG_SETMASK, &unblocked)?;
            if let Some(umask) = umask {
                libc::umask(umask);
            }
            parent_death(parent)
        });
    }
    Ok(())
}

/// Whether child `pid` has exited, without reaping it, so its process ID
/// and its process group's ID stay reserved until it is reaped.
pub(crate) fn exited(pid: u32) -> io::Result<bool> {
    let pid = libc::id_t::from(pid);
    let mut info = MaybeUninit::<libc::siginfo_t>::zeroed();
    let flags = libc::WEXITED | libc::WNOHANG | libc::WNOWAIT;
    // SAFETY: `info` is a writable `siginfo_t` that outlives the call.
    result(unsafe { libc::waitid(libc::P_PID, pid, info.as_mut_ptr(), flags) })?;
    // SAFETY: a zeroed `siginfo_t` is a valid value, `waitid` filled it, and
    // with `WNOHANG` a child that has not changed state leaves `si_pid` 0.
    Ok(unsafe { info.assume_init().si_pid() } != 0)
}

/// Sends SIGKILL to every process of process group `group`; `false` when
/// the group holds no process.
pub(crate) fn kill_group(group: u32) -> io::Result<bool> {
    signal_group(group, libc::SIGKILL)
}

/// Whether process group `group` holds a process, a zombie included.
pub(crate) fn group_alive(group: u32) -> io::Result<bool> {
    signal_group(group, 0)
}

fn signal_group(group: u32, signal: i32) -> io::Result<bool> {
    let group = group_id(group)?;
    // SAFETY: `kill` takes integers and touches no memory.
    match result(unsafe { libc::kill(-group, signal) }) {
        Ok(()) => Ok(true),
        Err(error) if error.raw_os_error() == Some(libc::ESRCH) => Ok(false),
        Err(error) => Err(error),
    }
}

/// `group` as a process group ID; `EINVAL` for 0 and 1, whose negations
/// `kill` and `waitpid` read as the caller's group and every process.
fn group_id(group: u32) -> io::Result<libc::pid_t> {
    libc::pid_t::try_from(group)
        .ok()
        .filter(|group| *group > 1)
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))
}

/// Reaps one exited child of process group `group`; `false` when none is
/// ready or none is left.
pub(crate) fn reap_group(group: u32) -> io::Result<bool> {
    let group = group_id(group)?;
    let mut status = 0;
    // SAFETY: `status` is a writable integer that outlives the call.
    let reaped = unsafe { libc::waitpid(-group, &raw mut status, libc::WNOHANG) };
    if reaped >= 0 {
        return Ok(reaped > 0);
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ECHILD) => Ok(false),
        _ => Err(error),
    }
}

/// A child identity held by the kernel until descriptor-targeted reap.
#[derive(Debug)]
pub(crate) struct Process(File);

impl Process {
    pub(crate) fn open(child: &std::process::Child) -> io::Result<Self> {
        // SAFETY: pidfd_open takes integers and returns a fresh descriptor.
        let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id(), 0) };
        // SAFETY: a successful pidfd_open returns a fresh descriptor.
        unsafe { owned(descriptor) }.map(Self)
    }

    pub(crate) fn reap(&self) -> io::Result<Option<std::process::ExitStatus>> {
        let mut info = MaybeUninit::<libc::siginfo_t>::zeroed();
        // SAFETY: the writable siginfo and borrowed descriptor outlive waitid.
        result(unsafe {
            libc::waitid(
                libc::P_PIDFD,
                self.0.as_raw_fd().cast_unsigned(),
                info.as_mut_ptr(),
                libc::WEXITED | libc::WNOHANG,
            )
        })?;
        // SAFETY: zeroed siginfo_t is valid; waitid initializes child fields or leaves zero si_pid.
        let info = unsafe { info.assume_init() };
        // SAFETY: WEXITED reports the child-status union.
        if unsafe { info.si_pid() } == 0 {
            return Ok(None);
        }
        // SAFETY: WEXITED reports the child-status union.
        let status = unsafe { info.si_status() };
        child_status(info.si_code, status).map(Some)
    }
}

fn child_status(code: i32, status: i32) -> io::Result<std::process::ExitStatus> {
    use std::os::unix::process::ExitStatusExt;
    let raw = match code {
        libc::CLD_EXITED => status << 8,
        libc::CLD_KILLED => status,
        libc::CLD_DUMPED => status | 0x80,
        _ => return Err(io::Error::other("unexpected pidfd wait status")),
    };
    Ok(std::process::ExitStatus::from_raw(raw))
}

thread_local! {
    static SIGNALS_ACTIVE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Blocked interruption signals read on the owning thread's descriptor.
/// Drop preserves the owning thread's blocked interruption mask.
pub(crate) struct Signals {
    file: File,
    thread: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl Signals {
    pub(crate) fn open() -> io::Result<Self> {
        if SIGNALS_ACTIVE.get() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "thread already owns custody signals",
            ));
        }
        child_exits()?;
        let set = interruptions()?;
        let mut previous = MaybeUninit::<libc::sigset_t>::zeroed();
        // SAFETY: both signal sets outlive the call, which fills previous.
        let code = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &set, previous.as_mut_ptr()) };
        if code != 0 {
            return Err(io::Error::from_raw_os_error(code));
        }
        // SAFETY: zeroed sigset_t is valid; pthread_sigmask supplies the previous bits.
        let previous = unsafe { previous.assume_init() };
        // SAFETY: set outlives signalfd, which returns a new descriptor.
        let descriptor =
            unsafe { libc::signalfd(-1, &set, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK) };
        // SAFETY: a successful signalfd returns a fresh descriptor.
        let file = match unsafe { owned(descriptor.into()) } {
            Ok(file) => file,
            Err(error) => {
                mask(libc::SIG_SETMASK, &previous)?;
                return Err(error);
            }
        };
        SIGNALS_ACTIVE.set(true);
        Ok(Self {
            file,
            thread: std::marker::PhantomData,
        })
    }

    pub(crate) fn take(&self) -> io::Result<Option<i32>> {
        use std::io::Read;
        let mut bytes = [0; size_of::<libc::signalfd_siginfo>()];
        loop {
            match (&self.file).read(&mut bytes) {
                Ok(count) if count == bytes.len() => {
                    return Ok(Some(
                        u32::from_ne_bytes(bytes[..4].try_into().expect("four signal bytes"))
                            .cast_signed(),
                    ));
                }
                Ok(_) => return Err(io::Error::other("short signal descriptor read")),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
    }
}

impl Drop for Signals {
    fn drop(&mut self) {
        SIGNALS_ACTIVE.set(false);
    }
}

/// Descriptor references outlive each poll through the set's borrow lifetime.
pub(crate) struct PollSet<'a> {
    descriptors: Vec<libc::pollfd>,
    borrowed: std::marker::PhantomData<&'a File>,
}

impl<'a> PollSet<'a> {
    pub(crate) fn new(signals: &'a Signals) -> Self {
        Self {
            descriptors: vec![libc::pollfd {
                fd: signals.file.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            }],
            borrowed: std::marker::PhantomData,
        }
    }

    pub(crate) fn add(&mut self, process: Option<&'a Process>, events: &'a File) {
        if let Some(process) = process {
            self.descriptors.push(libc::pollfd {
                fd: process.0.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            });
        }
        self.descriptors.push(libc::pollfd {
            fd: events.as_raw_fd(),
            events: libc::POLLPRI | libc::POLLERR,
            revents: 0,
        });
    }

    pub(crate) fn poll(&mut self, timeout: Duration) -> io::Result<()> {
        let millis = timeout.as_nanos().div_ceil(1_000_000).min(i32::MAX as u128) as i32;
        // SAFETY: the vector stays writable and its descriptors stay borrowed during poll.
        let ready = unsafe {
            libc::poll(
                self.descriptors.as_mut_ptr(),
                self.descriptors.len() as libc::nfds_t,
                millis,
            )
        };
        if ready < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

pub(crate) fn descriptor_limit(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::EMFILE)
}

pub(crate) const KILL_SIGNAL: u64 = libc::SIGKILL as u64;
pub(crate) const STOP_SIGNALS: &[u64] = &[TERM_SIGNAL as u64, libc::SIGINT as u64];
pub(crate) const CPU_SIGNAL: i32 = libc::SIGXCPU;
pub(crate) const OUTPUT_SIGNAL: i32 = libc::SIGXFSZ;

pub(crate) fn cpu_limit() -> io::Result<u64> {
    hard_limit(libc::RLIMIT_CPU as u64)
}

pub(crate) fn file_limit() -> io::Result<u64> {
    hard_limit(libc::RLIMIT_FSIZE as u64)
}

/// Lowers the soft descriptor limit to `soft` open descriptors, keeping the
/// hard limit.
#[cfg(test)]
pub(crate) fn restrict_descriptor_limit(soft: u64) -> io::Result<()> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: limit is writable storage for one rlimit that outlives the call.
    result(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) })?;
    limit.rlim_cur = soft;
    // SAFETY: limit is initialized storage for one rlimit that outlives the call.
    result(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) })
}

#[cfg(test)]
pub(crate) fn restrict_file_limit(soft: u64, hard: u64) -> io::Result<()> {
    restrict_limit(libc::RLIMIT_FSIZE, soft, hard)
}

#[cfg(test)]
pub(crate) fn restrict_process_limit(soft: u64, hard: u64) -> io::Result<()> {
    restrict_limit(libc::RLIMIT_NPROC, soft, hard)
}

#[cfg(test)]
fn restrict_limit(resource: libc::__rlimit_resource_t, soft: u64, hard: u64) -> io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: soft,
        rlim_max: hard,
    };
    // SAFETY: limit is initialized storage for one rlimit that outlives the call.
    result(unsafe { libc::setrlimit(resource, &limit) })
}

pub(crate) fn controller_file_limit() -> io::Result<u64> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    crate::step::call(crate::step::Step::Limits, || {
        // SAFETY: limit is writable storage for one rlimit that outlives the call.
        result(unsafe { libc::getrlimit(libc::RLIMIT_FSIZE, &mut limit) })
    })?;
    if limit.rlim_cur < limit.rlim_max {
        limit.rlim_cur = limit.rlim_max;
        crate::step::call(crate::step::Step::Limits, || {
            // SAFETY: limit is initialized storage for one rlimit that outlives the call.
            result(unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &limit) })
        })?;
    }
    Ok(limit.rlim_max)
}

fn hard_limit(resource: u64) -> io::Result<u64> {
    let resource = resource
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid limit resource"))?;
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    crate::step::call(crate::step::Step::Limits, || {
        // SAFETY: limit is writable storage for one rlimit that outlives the call.
        result(unsafe { libc::getrlimit(resource, &mut limit) })
    })?;
    Ok(limit.rlim_max)
}

pub(crate) fn searchable(path: &std::path::Path) -> io::Result<()> {
    let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    // SAFETY: the NUL-terminated path outlives the effective-credential access query.
    result(unsafe { libc::faccessat(libc::AT_FDCWD, path.as_ptr(), libc::X_OK, libc::AT_EACCESS) })
}

pub(crate) fn gate_parent(
    command: &mut Command,
    directory: &std::path::Path,
    file_bytes: u64,
    cpu_seconds: u64,
) {
    command.current_dir(directory);
    let parent = std::process::id();
    // SAFETY: the child-side closure uses Linux syscall wrappers and a local rlimit.
    unsafe {
        command.pre_exec(move || {
            let limit = libc::rlimit {
                rlim_cur: file_bytes,
                rlim_max: file_bytes,
            };
            result(libc::setrlimit(libc::RLIMIT_FSIZE, &limit))?;
            let cpu = libc::rlimit {
                rlim_cur: cpu_seconds,
                rlim_max: cpu_seconds + 1,
            };
            result(libc::setrlimit(libc::RLIMIT_CPU, &cpu))?;
            parent_death(parent)
        });
    }
}

pub(crate) fn clear_parent_death() -> io::Result<()> {
    let none: libc::c_ulong = 0;
    // SAFETY: this prctl option takes integer arguments and clears kernel process state.
    result(unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, none, none, none, none) })
}

pub(crate) fn terminate_child(child: &mut std::process::Child) -> io::Result<bool> {
    if exited(child.id())? {
        return Ok(false);
    }
    let pid = libc::pid_t::try_from(child.id()).map_err(|_| io::ErrorKind::InvalidInput)?;
    // SAFETY: kill takes integer arguments.
    match result(unsafe { libc::kill(pid, libc::SIGTERM) }) {
        Err(error) if error.raw_os_error() == Some(libc::ESRCH) => Ok(false),
        result => result.map(|()| true),
    }
}

fn parent_death(parent: u32) -> io::Result<()> {
    let none: libc::c_ulong = 0;
    // SAFETY: this prctl option takes integer arguments and touches kernel process state.
    result(unsafe {
        libc::prctl(
            libc::PR_SET_PDEATHSIG,
            libc::SIGKILL as libc::c_ulong,
            none,
            none,
            none,
        )
    })?;
    // SAFETY: getppid takes no pointers and returns the current parent identity.
    if unsafe { libc::getppid() }.cast_unsigned() != parent {
        return Err(io::Error::from_raw_os_error(libc::ESRCH));
    }
    Ok(())
}

/// Checks that the descriptor lies on the unified cgroup filesystem.
pub(crate) fn cgroup_v2(file: &File) -> io::Result<bool> {
    let mut status = MaybeUninit::<libc::statfs>::zeroed();
    // SAFETY: status is writable and the descriptor stays borrowed during fstatfs.
    result(unsafe { libc::fstatfs(file.as_raw_fd(), status.as_mut_ptr()) })?;
    // SAFETY: fstatfs filled status.
    Ok(unsafe { status.assume_init() }.f_type == libc::CGROUP2_SUPER_MAGIC)
}

/// Makes FIFO `name` in `dir`. Tests make FIFOs in-process, since a child
/// process would hold the test's descriptors, and with them its locks,
/// from its fork until its exec.
#[cfg(test)]
pub(crate) fn mkfifo(dir: &File, name: &CStr) -> io::Result<()> {
    // SAFETY: `name` outlives the call.
    result(unsafe { libc::mkfifoat(dir.as_raw_fd(), name.as_ptr(), 0o600) })
}

/// Gives the calling thread its own working directory and umask, and sets
/// the umask to `mask`, so a test changes neither for other threads.
#[cfg(test)]
pub(crate) fn private_fs(mask: libc::mode_t) -> io::Result<()> {
    // SAFETY: `unshare` takes a flag and touches no memory of ours.
    result(unsafe { libc::unshare(libc::CLONE_FS) })?;
    // SAFETY: `umask` takes a mode and cannot fail.
    unsafe { libc::umask(mask) };
    Ok(())
}

#[cfg(test)]
pub(crate) fn interrupt(signal: i32) -> io::Result<()> {
    // SAFETY: raise sends the integer signal to the calling thread.
    result(unsafe { libc::raise(signal) })
}

/// The calling thread's kernel thread ID, for [`interrupt_thread`].
#[cfg(test)]
pub(crate) fn this_thread() -> libc::pid_t {
    // SAFETY: `gettid` takes no arguments and cannot fail.
    unsafe { libc::gettid() }
}

/// Sends `signal` to the thread of this process whose kernel thread ID is
/// `thread`, as [`this_thread`] returned it. `tgkill` returns `ESRCH` when
/// `thread` names no thread of this process. If another thread in this
/// process acquires the ID, `tgkill` targets that thread.
#[cfg(test)]
pub(crate) fn interrupt_thread(thread: libc::pid_t, signal: i32) -> io::Result<()> {
    // SAFETY: `tgkill` takes integers and touches no memory of ours.
    let sent = unsafe { libc::syscall(libc::SYS_tgkill, libc::getpid(), thread, signal) };
    result(i32::try_from(sent).unwrap_or(-1))
}

pub(crate) const CRASH_SIGNALS: &[u64] = &[
    libc::SIGILL as u64,
    libc::SIGTRAP as u64,
    libc::SIGABRT as u64,
    libc::SIGBUS as u64,
    libc::SIGFPE as u64,
    libc::SIGSEGV as u64,
    libc::SIGSYS as u64,
];

#[cfg(test)]
mod tests {
    #[test]
    fn terminating_an_exited_child_keeps_its_identity_reserved_until_reap() {
        let _processes = crate::store::fixture::processes();
        let mut child = std::process::Command::new("/bin/true").spawn().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !super::exited(child.id()).unwrap() {
            assert!(std::time::Instant::now() < deadline);
            std::thread::yield_now();
        }
        assert!(!super::terminate_child(&mut child).unwrap());
        assert!(super::exited(child.id()).unwrap());
        assert!(child.wait().unwrap().success());
    }

    #[test]
    fn zero_fragment_size_refuses_the_filesystem_space_query() {
        assert!(super::available_space(4, 3, 0).is_err());
        let (bytes, inodes, fragment) = super::available_space(4, 3, 4096).unwrap();
        assert_eq!((bytes, inodes, fragment.get()), (16384, 3, 4096));
    }

    #[test]
    fn gate_installs_the_cpu_soft_and_hard_limits() {
        let _processes = crate::store::fixture::processes();
        let case = crate::store::fixture::Case::new();
        let mut command = std::process::Command::new("/bin/sh");
        command.args(["-c", "ulimit -t; ulimit -H -t"]);
        super::gate_parent(&mut command, &case.root, 1 << 20, 5);
        let output = command.output().unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"5\n6\n");
    }

    use std::fs::File;

    use super::{entries, group_id, names};

    #[test]
    fn signals_keep_the_mask_and_queued_interruptions_after_drop() {
        let _processes = crate::store::fixture::processes();
        if std::env::var_os("CAMPAIGN_SIGNAL_MASK_CHILD").is_none() {
            // The child's libtest lines stay in the captured output, so the parent run reports
            // one summary per target.
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "sys::tests::signals_keep_the_mask_and_queued_interruptions_after_drop",
                    "--nocapture",
                ])
                .env("CAMPAIGN_SIGNAL_MASK_CHILD", "1")
                .output()
                .unwrap();
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                output.status.success() && stdout.contains("test result: ok. 1 passed;"),
                "{output:?}"
            );
            return;
        }
        assert_eq!(
            super::parent_death(u32::MAX).unwrap_err().raw_os_error(),
            Some(libc::ESRCH)
        );
        fn current() -> libc::sigset_t {
            let mut set = std::mem::MaybeUninit::zeroed();
            // SAFETY: a null input queries the mask into the writable output set.
            assert_eq!(
                unsafe { libc::pthread_sigmask(0, std::ptr::null(), set.as_mut_ptr()) },
                0
            );
            // SAFETY: zeroed sigset_t is valid; pthread_sigmask supplies the current bits.
            unsafe { set.assume_init() }
        }
        fn blocked(set: &libc::sigset_t, signal: i32) -> bool {
            // SAFETY: the initialized set outlives the signal-membership query.
            unsafe { libc::sigismember(set, signal) == 1 }
        }
        let before = current();
        let mut previous_limit = std::mem::MaybeUninit::<libc::rlimit>::zeroed();
        // SAFETY: getrlimit initializes the writable output structure.
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, previous_limit.as_mut_ptr()) },
            0
        );
        // SAFETY: getrlimit initialized the output structure.
        let previous_limit = unsafe { previous_limit.assume_init() };
        let no_files = libc::rlimit {
            rlim_cur: 0,
            rlim_max: previous_limit.rlim_max,
        };
        // SAFETY: the initialized limit remains borrowed through setrlimit.
        assert_eq!(
            unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &no_files) },
            0
        );
        let failed = super::Signals::open();
        // SAFETY: the saved limit remains borrowed through setrlimit.
        assert_eq!(
            unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &previous_limit) },
            0
        );
        assert!(matches!(failed, Err(error) if error.raw_os_error() == Some(libc::EMFILE)));
        for signal in [libc::SIGINT, libc::SIGTERM] {
            assert_eq!(blocked(&current(), signal), blocked(&before, signal));
        }
        let signals = super::Signals::open().unwrap();
        assert!(matches!(super::Signals::open(), Err(error)
            if error.kind() == std::io::ErrorKind::AlreadyExists));
        for signal in [libc::SIGINT, libc::SIGTERM] {
            assert!(blocked(&current(), signal));
            super::interrupt(signal).unwrap();
        }
        drop(signals);
        super::interrupt(libc::SIGTERM).unwrap();
        for signal in [libc::SIGINT, libc::SIGTERM] {
            assert!(blocked(&current(), signal));
        }
        let next = super::Signals::open().unwrap();
        let mut queued = [next.take().unwrap().unwrap(), next.take().unwrap().unwrap()];
        queued.sort();
        assert_eq!(queued, [libc::SIGINT, libc::SIGTERM]);
        assert_eq!(next.take().unwrap(), None);
        drop(next);
    }

    #[test]
    fn pidfd_status_preserves_exit_signal_and_core_dump_fields() {
        use std::os::unix::process::ExitStatusExt;
        let exited = super::child_status(libc::CLD_EXITED, 125).unwrap();
        assert_eq!(exited.code(), Some(125));
        assert_eq!(exited.signal(), None);
        let killed = super::child_status(libc::CLD_KILLED, libc::SIGKILL).unwrap();
        assert_eq!(killed.signal(), Some(libc::SIGKILL));
        assert!(!killed.core_dumped());
        let dumped = super::child_status(libc::CLD_DUMPED, libc::SIGSEGV).unwrap();
        assert_eq!(dumped.signal(), Some(libc::SIGSEGV));
        assert!(dumped.core_dumped());
        assert!(super::child_status(libc::CLD_STOPPED, libc::SIGSTOP).is_err());
    }

    /// Group IDs 0 and 1, which `kill` and `waitpid` read as the caller's
    /// group and every process once negated, and IDs past `pid_t` are
    /// refused before any call.
    #[test]
    fn group_ids_below_two_are_refused() {
        for refused in [0, 1, u32::MAX] {
            let error = group_id(refused).expect_err("the ID is refused");
            assert_eq!(error.raw_os_error(), Some(libc::EINVAL), "{refused}");
        }
        assert_eq!(group_id(2).expect("the ID is admitted"), 2);
    }

    /// One `linux_dirent64` record holding `name`, padded to `length`.
    fn record(name: &[u8], length: u16) -> Vec<u8> {
        let mut record = vec![0; 19];
        record[16..18].copy_from_slice(&length.to_ne_bytes());
        record.extend_from_slice(name);
        record.resize(usize::from(length), 0);
        record
    }

    /// Padded records decode in order; a record whose length is too small
    /// or runs past the buffer, or whose name has no NUL, ends the names
    /// instead of reading outside its record.
    #[test]
    fn records_decode_and_a_malformed_record_ends_the_names() {
        let mut buffer = record(b"a\0", 24);
        buffer.extend(record(b"bcd\0", 32));
        assert_eq!(names(&buffer).collect::<Vec<_>>(), [&b"a"[..], b"bcd"]);
        let mut zero = record(b"a\0", 24);
        zero[16..18].copy_from_slice(&0u16.to_ne_bytes());
        for malformed in [
            zero,
            record(b"a\0", 18),
            record(b"a\0", 24)[..20].to_vec(),
            record(b"abcde", 24),
        ] {
            assert_eq!(names(&malformed).count(), 0, "{malformed:?}");
        }
    }

    /// The listing call reports the kernel's error: a regular file is no
    /// directory.
    #[test]
    fn a_listing_of_a_regular_file_fails_with_enotdir() {
        let file = File::open(std::env::current_exe().expect("the test has a path"))
            .expect("the test executable opens");
        let error = entries(&file, &mut [0; 256]).expect_err("a file lists no entries");
        assert_eq!(error.raw_os_error(), Some(libc::ENOTDIR));
    }
}

#[cfg(test)]
mod controller_limit_tests {
    use super::*;
    #[test]
    fn a_controller_raises_its_soft_file_limit_before_a_bounded_write() {
        const CHILD: &str = "CAMPAIGN_CONTROLLER_FILE_LIMIT_TEST";
        if std::env::var_os(CHILD).is_some() {
            let limit = libc::rlimit {
                rlim_cur: 4096,
                rlim_max: 65536,
            };
            // SAFETY: limit is initialized storage for one rlimit that outlives the call.
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &limit) }, 0);
            assert_eq!(controller_file_limit().unwrap(), 65536);
            let case = crate::store::fixture::Case::new();
            let store = crate::store::Store::open(&case.state).unwrap();
            store
                .create_once(
                    store.root(),
                    &crate::store::Name::new("copy").unwrap(),
                    &vec![b'x'; 32768],
                )
                .unwrap();
            return;
        }
        let _processes = crate::store::fixture::processes();
        use std::os::unix::process::CommandExt;
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "sys::controller_limit_tests::a_controller_raises_its_soft_file_limit_before_a_bounded_write"])
            .process_group(0).env(CHILD, "1").output().unwrap();
        assert!(
            output.status.success(),
            "{:?}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
