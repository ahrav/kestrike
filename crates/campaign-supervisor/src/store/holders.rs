//! The processes that hold a directory's `flock`, read from `/proc/locks`.
//! Reading the table leaves every lock as it was, so a snapshot that names
//! the holders never makes a controller's `Store::open` fail with
//! [`Error::Busy`].
//!
//! The kernel removes an entry when its lock is unlocked or when the last
//! descriptor sharing the lock's open file description closes. The entry
//! names the pid that took the lock, so a child that inherited the
//! descriptor keeps the entry, and that pid, after the locker exits. A
//! descriptor opened close-on-exec stays in a child only between its fork
//! and its exec. The table lists only locks whose holders are visible in
//! the PID namespace of the procfs mounted at `/proc`, and numbers them in
//! that namespace.
//!
//! The table can change between the reads that return it, so an entry can
//! be missed or shown twice; a directory has at most one exclusive `flock`,
//! so a repeated exclusive entry is dropped. A holder's command is read
//! after its pid, so a holder that exits in between can leave a reused
//! pid's command beside its entry; the command is a label for display.
//!
//! A host fault such as `EIO` or `EMFILE` opening or reading the table or a
//! holder's command line is an error. Any other failure to open or read the
//! table, a table that is no regular file, and a table past 1 MiB leave the
//! holders unknown; any other failure for a command line, or a holder that
//! has exited, leaves that holder without a command.

use std::io::{self, Read};
use std::path::Path;

use super::error::host_fault;
use super::host::{open_host, read_host_sized};
use super::{Error, Unreadable};
use crate::step::{self, Step};

/// The largest `/proc/locks` a reader accepts; a larger table leaves the
/// holders unknown.
const LOCKS_BOUND: u64 = 1 << 20;

/// The buffer a table read starts with, since a `/proc` file reports no
/// size.
const LOCKS_CAPACITY: u64 = 64 << 10;

/// The most bytes of a holder's `/proc/<pid>/cmdline` a reader takes.
const CMDLINE_BOUND: u64 = 4096;

/// The longest command a holder reports.
const COMMAND_BOUND: usize = 64;

/// One process holding a directory's `flock`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Holder {
    /// The pid the table prints, in the PID namespace of the procfs at
    /// `/proc`; `None` when it prints zero, a negative number or no number.
    pub pid: Option<u32>,
    /// Whether the lock is exclusive; a shared lock is `false`.
    pub exclusive: bool,
    /// The holder's first argument after the program name, such as
    /// `dispatch`, when it is 1 to 64 bytes from `!` to `~` and a NUL ends
    /// it within the first 4096 bytes of the command line.
    pub command: Option<String>,
}

/// The holders of the `flock` on the directory whose device and inode are
/// `identity`: `Ok(Err)` with a reason when the holders are unknown, as the
/// module documentation lists.
///
/// # Errors
///
/// [`Error::Io`] for a host fault, as the module documentation lists.
pub(super) fn holders(identity: (u64, u64)) -> Result<Result<Vec<Holder>, String>, Error> {
    holders_in(Path::new("/proc/locks"), identity)
}

/// [`holders`] with the lock table read from `table`.
fn holders_in(table: &Path, identity: (u64, u64)) -> Result<Result<Vec<Holder>, String>, Error> {
    let (device, inode) = identity;
    let key = (libc::major(device), libc::minor(device), inode);
    let shown = table.display();
    let bytes = match read_host_sized(table, LOCKS_BOUND, LOCKS_CAPACITY) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return Ok(Err(format!("{shown} is absent"))),
        Err(Unreadable::Oversize) => return Ok(Err(format!("{shown} exceeds 1 MiB"))),
        Err(Unreadable::Io(error)) if host_fault(&error) => return Err(Error::Io(error)),
        Err(error) => return Ok(Err(format!("{shown}: {error}"))),
    };
    let text = String::from_utf8(bytes)
        .unwrap_or_else(|error| String::from_utf8_lossy(error.as_bytes()).into_owned());
    let mut holders = Vec::new();
    for (pid, exclusive) in entries(&text, key) {
        let command = match pid {
            Some(pid) => command(pid)?,
            None => None,
        };
        holders.push(Holder {
            pid,
            exclusive,
            command,
        });
    }
    Ok(Ok(holders))
}

/// The `(pid, exclusive)` pair of each granted `FLOCK` entry in `table`
/// whose `major:minor:inode` field names `key`, with only the first
/// exclusive entry kept. The table prints major and minor in hexadecimal
/// and the inode in decimal; a blocked waiter's line carries `->` after its
/// number and is skipped.
pub(super) fn entries(table: &str, key: (u32, u32, u64)) -> Vec<(Option<u32>, bool)> {
    let mut found = Vec::new();
    for line in table.lines() {
        let mut fields = line.split_ascii_whitespace().skip(1);
        let (Some("FLOCK"), Some(_), Some(mode), Some(pid), Some(id)) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            continue;
        };
        let exclusive = match mode {
            "WRITE" => true,
            "READ" => false,
            _ => continue,
        };
        let mut parts = id.split(':');
        let parsed = (
            parts.next().and_then(|v| u32::from_str_radix(v, 16).ok()),
            parts.next().and_then(|v| u32::from_str_radix(v, 16).ok()),
            parts.next().and_then(|v| v.parse::<u64>().ok()),
        );
        if parts.next().is_some() || parsed != (Some(key.0), Some(key.1), Some(key.2)) {
            continue;
        }
        if exclusive && found.iter().any(|&(_, seen)| seen) {
            continue;
        }
        found.push((pid.parse::<u32>().ok().filter(|&pid| pid > 0), exclusive));
    }
    found
}

/// The command [`Holder::command`] describes, from `/proc/<pid>/cmdline`;
/// `None` when the argument fails that rule or the open or read fails other
/// than by a host fault, `ESRCH` for an exited process included.
///
/// # Errors
///
/// [`Error::Io`] for a host fault opening or reading the file.
fn command(pid: u32) -> Result<Option<String>, Error> {
    let fault = |error: &io::Error| host_fault(error) && error.raw_os_error() != Some(libc::ESRCH);
    let opened = match open_host(Path::new(&format!("/proc/{pid}/cmdline"))) {
        Ok(opened) => opened,
        Err(Unreadable::Io(error)) if fault(&error) => return Err(Error::Io(error)),
        Err(_) => return Ok(None),
    };
    let mut bytes = Vec::with_capacity(CMDLINE_BOUND as usize);
    match step::call(Step::Read, || {
        (&opened.file).take(CMDLINE_BOUND).read_to_end(&mut bytes)
    }) {
        Ok(_) => Ok(argument(&bytes)),
        Err(error) if fault(&error) => Err(Error::Io(error)),
        Err(_) => Ok(None),
    }
}

/// The second NUL-terminated argument of `cmdline` under the rule
/// [`Holder::command`] states; a buffer that ends inside it has none.
pub(super) fn argument(cmdline: &[u8]) -> Option<String> {
    let mut arguments = cmdline.split(|&byte| byte == 0);
    arguments.next()?;
    let argument = arguments.next()?;
    arguments.next()?;
    (!argument.is_empty()
        && argument.len() <= COMMAND_BOUND
        && argument.iter().all(|byte| byte.is_ascii_graphic()))
    .then(|| String::from_utf8_lossy(argument).into_owned())
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::process::{Command, Stdio};

    use super::*;
    use crate::step::Outcome;
    use crate::store::fixture::{Case, processes, reread, scripted};

    const KEY: (u32, u32, u64) = (0x103, 0x2a, 131_074);

    /// Set in a child this module's tests start, naming the directory the
    /// child locks.
    const CHILD: &str = "CAMPAIGN_HOLDERS_TEST_CHILD";

    fn identity(path: &Path) -> (u64, u64) {
        let status = std::fs::metadata(path).unwrap();
        (status.dev(), status.ino())
    }

    #[test]
    fn only_granted_flock_entries_on_the_directory_are_holders() {
        let table = "\
1: FLOCK  ADVISORY  WRITE 41234 103:2a:131074 0 EOF
1: -> FLOCK  ADVISORY  WRITE 41300 103:2a:131074 0 EOF
2: POSIX  ADVISORY  WRITE 900 103:2a:131074 0 EOF
3: FLOCK  ADVISORY  READ 512 103:2a:131074 0 EOF
4: FLOCK  ADVISORY  WRITE 77 103:2a:131075 0 EOF
5: FLOCK  ADVISORY  WRITE 78 103:2b:131074 0 EOF
6: OFDLCK ADVISORY  READ -1 103:2a:131074 0 EOF
7: FLOCK  ADVISORY  WRITE -1 103:2a:131074 0 EOF
8: FLOCK  ADVISORY  READ 0 103:2a:131074 0 EOF
9: LEASE  ACTIVE    READ 600 103:2a:131074 0 EOF
";
        assert_eq!(
            entries(table, KEY),
            [(Some(41234), true), (Some(512), false), (None, false)],
            "a waiter, another lock kind, another inode or device, a lease and a second \
             exclusive entry are no holders; a negative or zero pid is none"
        );
    }

    #[test]
    fn a_repeated_exclusive_entry_is_one_holder_and_shared_entries_stay() {
        let table = "\
1: FLOCK  ADVISORY  WRITE 41234 103:2a:131074 0 EOF
1: FLOCK  ADVISORY  WRITE 41234 103:2a:131074 0 EOF
2: FLOCK  ADVISORY  READ 7 103:2a:131074 0 EOF
3: FLOCK  ADVISORY  READ 7 103:2a:131074 0 EOF
";
        assert_eq!(
            entries(table, KEY),
            [(Some(41234), true), (Some(7), false), (Some(7), false)]
        );
    }

    #[test]
    fn malformed_lines_and_identities_name_no_holder() {
        let table = "\
garbage
1: FLOCK  ADVISORY  WRITE 1
2: FLOCK  ADVISORY  UNLCK 2 103:2a:131074 0 EOF
3: FLOCK  ADVISORY  WRITE 3 103:2a:131074:9 0 EOF
4: FLOCK  ADVISORY  WRITE 4 zz:2a:131074 0 EOF
5: FLOCK  ADVISORY  WRITE 5 103:2a 0 EOF
";
        assert!(entries(table, KEY).is_empty());
    }

    #[test]
    fn the_command_is_the_terminated_graphic_first_argument() {
        assert_eq!(
            argument(b"/usr/bin/campaign\0dispatch\0--state\0/s\0").as_deref(),
            Some("dispatch")
        );
        assert_eq!(argument(b"/usr/bin/campaign\0"), None, "no argument");
        assert_eq!(argument(b"/usr/bin/campaign"), None, "no separator");
        assert_eq!(argument(b"campaign\0dispat"), None, "a read cut inside it");
        assert_eq!(argument(b"campaign\0\0x\0"), None, "an empty argument");
        assert_eq!(argument(b"campaign\0dis patch\0"), None, "a space");
        assert_eq!(
            argument(b"campaign\0dis\x1bpatch\0"),
            None,
            "a control byte"
        );
        let sized = |n: usize| [b"campaign\0".as_slice(), &vec![b'a'; n], b"\0"].concat();
        assert_eq!(argument(&sized(64)).map(|a| a.len()), Some(64), "64 bytes");
        assert_eq!(argument(&sized(65)), None, "longer than 64 bytes");
    }

    #[test]
    fn a_pid_that_names_no_process_has_no_command() {
        assert_eq!(command(u32::MAX).unwrap(), None);
    }

    #[test]
    fn a_refused_or_exited_command_line_is_no_command_and_a_host_fault_is_an_error() {
        let pid = std::process::id();
        let (clean, reached) = scripted([], || command(pid));
        clean.unwrap().unwrap();
        assert_eq!(reached, [Step::Open, Step::Stat, Step::Read]);
        for index in 0..reached.len() {
            for errno in [libc::EACCES, libc::ENOENT, libc::ESRCH] {
                let (result, _) = scripted([(index, Outcome::Errno(errno))], || command(pid));
                assert_eq!(result.unwrap().unwrap(), None, "{index} {errno}");
            }
            let (result, _) = scripted([(index, Outcome::Errno(libc::EIO))], || command(pid));
            assert!(matches!(result.unwrap(), Err(Error::Io(_))), "{index}");
        }
    }

    #[test]
    fn a_held_flock_names_this_process_and_its_mode() {
        let case = Case::new();
        let key = identity(&case.state);
        let expected = std::env::args().nth(1).filter(|argument| {
            (1..=64).contains(&argument.len()) && argument.bytes().all(|b| b.is_ascii_graphic())
        });
        let holder = |exclusive| Holder {
            pid: Some(std::process::id()),
            exclusive,
            command: expected.clone(),
        };
        let held = std::fs::File::open(&case.state).unwrap();
        let one = || reread(|| holders(key).unwrap().unwrap(), |found| found.len() == 1);
        assert_eq!(holders(key).unwrap().unwrap(), []);
        held.lock_shared().unwrap();
        assert_eq!(one(), [holder(false)]);
        held.unlock().unwrap();
        held.lock().unwrap();
        assert_eq!(one(), [holder(true)]);
        held.unlock().unwrap();
        assert_eq!(holders(key).unwrap().unwrap(), []);
    }

    /// The parent starts this test again as a child with [`CHILD`] set and
    /// `--exact` as its first argument; the child locks the directory,
    /// reports it, and holds the lock until its standard input closes.
    #[test]
    fn a_child_holder_reports_its_pid_and_first_argument() {
        if let Some(path) = std::env::var_os(CHILD) {
            let held = std::fs::File::open(path).unwrap();
            held.lock().unwrap();
            println!("holder locked");
            let _ = io::stdin().read_to_end(&mut Vec::new());
            return;
        }
        let _processes = processes();
        let case = Case::new();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "store::holders::tests::a_child_holder_reports_its_pid_and_first_argument",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, &case.state)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        // libtest prints the test's name on the line that the child's
        // report ends.
        assert!(
            lines.any(|line| line.unwrap().ends_with("holder locked")),
            "the child locks"
        );
        let found = reread(
            || holders(identity(&case.state)).unwrap().unwrap(),
            |found| found.len() == 1,
        );
        assert_eq!(
            found,
            [Holder {
                pid: Some(child.id()),
                exclusive: true,
                command: Some("--exact".into()),
            }]
        );
        drop(child.stdin.take());
        assert!(child.wait().unwrap().success());
    }

    #[test]
    fn an_absent_refused_oversized_or_irregular_table_leaves_the_holders_unknown() {
        let case = Case::new();
        let key = identity(&case.state);
        let unknown = |table: &Path| holders_in(table, key).unwrap().unwrap_err();
        assert!(unknown(&case.root.join("absent")).ends_with("is absent"));
        let big = case.root.join("big");
        std::fs::write(&big, vec![b'\n'; LOCKS_BOUND as usize + 1]).unwrap();
        assert!(unknown(&big).ends_with("exceeds 1 MiB"));
        std::fs::write(&big, vec![b'\n'; LOCKS_BOUND as usize]).unwrap();
        assert_eq!(holders_in(&big, key).unwrap().unwrap(), [], "at the bound");
        assert!(unknown(&case.state).contains("no regular file"));
        let table = case.root.join("locks");
        std::fs::write(&table, "").unwrap();
        for index in [0, 2] {
            let (result, reached) = scripted([(index, Outcome::Errno(libc::EACCES))], || {
                holders_in(&table, key)
            });
            let reason = result.unwrap().unwrap().unwrap_err();
            assert!(reason.contains("denied"), "{:?}: {reason}", reached[index]);
        }
        let refused = case.root.join("refused");
        std::fs::write(&refused, "").unwrap();
        std::fs::set_permissions(&refused, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::File::open(&refused).is_err() {
            assert!(
                unknown(&refused).contains("denied"),
                "{}",
                unknown(&refused)
            );
        }
    }

    #[test]
    fn a_host_fault_at_any_table_step_ends_the_read() {
        let case = Case::new();
        let key = identity(&case.state);
        let table = case.root.join("locks");
        std::fs::write(&table, "").unwrap();
        let (clean, reached) = scripted([], || holders_in(&table, key));
        assert_eq!(clean.unwrap().unwrap().unwrap(), []);
        assert_eq!(reached, [Step::Open, Step::Stat, Step::Read]);
        for (index, at) in reached.iter().enumerate() {
            let (result, _) = scripted([(index, Outcome::Errno(libc::EIO))], || {
                holders_in(&table, key)
            });
            assert!(
                matches!(result.unwrap(), Err(Error::Io(_))),
                "{index} {at:?}"
            );
        }
    }
}
