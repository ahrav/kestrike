//! `help.txt` holds the controller's contract, which `-h` prints.
//!
//! [`run`] installs the handlers for [`DELIVERED`] before it reads the arguments, so the record
//! covers the argument reading as well as the command; the handlers stand to the process's end.
//! One [`Context`] serves whichever command the arguments name: the seam
//! [`System`](crate::host_stop::System), the file steps of [`Disk`], a record over [`DELIVERED`],
//! both standard streams, the catalog under `top` and the judge's file size as both limits.
//!
//! `run` sets `SIGXFSZ` to be ignored, so a write past the file size limit fails with `EFBIG` and
//! reaches the command as an error; a child inherits that disposition. Just before the command's
//! entry, `run` sets a panic hook that prints nothing, so a panic the entry catches is reported by
//! the entry's one line alone.

pub const NAME: &str = "host-stop-controller";

#[cfg(target_os = "linux")]
mod command_line;

#[cfg(target_os = "linux")]
pub use command_line::{HELP, read};

#[cfg(target_os = "linux")]
use crate::host_stop::{DELIVERED, Disk};
#[cfg(target_os = "linux")]
use crate::host_stop_controller::Context;

/// `top` is the checkout's top level. Exit 0 is help; 2 is arguments `read` refuses, handlers that
/// fail to install or a `SIGXFSZ` that fails to be ignored; any other code is the command's.
#[cfg(target_os = "linux")]
pub fn run(top: &std::path::Path, args: &[std::ffi::OsString]) -> u8 {
    use std::ffi::OsString;
    use std::io::{self, Write};

    use crate::args::Parsed;
    use crate::gameday::{CATALOG, FILE_LIMIT};
    use crate::host_stop::{Record, install};
    use crate::host_stop_controller::entry;

    if let Err(error) = install(&DELIVERED) {
        let line =
            format!("{NAME}: the signal handlers are not installed: {error}; nothing written\n");
        let _ = io::stderr().write_all(line.as_bytes());
        return 2;
    }
    if let Err(error) = ignore_file_size_signal() {
        let line = format!("{NAME}: SIGXFSZ is not ignored: {error}; nothing written\n");
        let _ = io::stderr().write_all(line.as_bytes());
        return 2;
    }
    let env: Vec<(OsString, OsString)> = std::env::vars_os().collect();
    let (mut out, mut err) = (io::stdout(), io::stderr());
    let command = match read(args) {
        Parsed::Run(command) => command,
        Parsed::Help(help) => {
            let _ = out.write_all(help.as_bytes()).and_then(|()| out.flush());
            return 0;
        }
        Parsed::Refused { code, text } => {
            let _ = err.write_all(text.as_bytes()).and_then(|()| err.flush());
            return code;
        }
    };
    let mut seam = crate::host_stop::System;
    let mut record = Record::new(&DELIVERED);
    let catalog = top.join(CATALOG);
    let mut cx = Context {
        seam: &mut seam,
        files: &Disk,
        record: &mut record,
        env: &env,
        out: &mut out,
        err: &mut err,
        catalog: &catalog,
        top,
        file_limit: FILE_LIMIT,
        mark_limit: FILE_LIMIT,
    };
    std::panic::set_hook(Box::new(|_| {}));
    let code = entry(&command, &mut cx);
    let _ = out.flush();
    let _ = err.flush();
    code
}

/// Sets the disposition of `SIGXFSZ` to ignore it.
#[cfg(target_os = "linux")]
fn ignore_file_size_signal() -> std::io::Result<()> {
    // SAFETY: all-zero bytes are a valid `sigaction`; with `SIG_IGN` as its handler and an empty mask
    // it installs no code of this process, and `sigaction` reads `action`, which outlives the call,
    // and writes no old action, since that pointer is null.
    let status = unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = libc::SIG_IGN;
        libc::sigemptyset(&mut action.sa_mask);
        libc::sigaction(libc::SIGXFSZ, &action, std::ptr::null_mut())
    };
    if status == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// On a target other than Linux, `run` writes the Linux requirement to standard error and returns 2.
#[cfg(not(target_os = "linux"))]
pub fn run(_top: &std::path::Path, _args: &[std::ffi::OsString]) -> u8 {
    use std::io::Write;
    let _ =
        std::io::stderr().write_all(b"host-stop-controller: error: the controller needs Linux\n");
    2
}
