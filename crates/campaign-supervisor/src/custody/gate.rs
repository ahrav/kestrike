//! The `gate` subcommand: the process its parent spawns and moves into a
//! cgroup ahead of the program the cgroup limits. It waits on stdin for
//! the go byte, then execs the program's argv in its own process group
//! with parent death armed. The controller sends the go byte once the
//! attempt's started record is durable, and a sweep once the gate is in
//! its pen.
//! `exit::Gate` turns a failure before exec into exit 125.

use std::ffi::OsString;
use std::io::{self, Read};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

use crate::sys;

pub(crate) fn released(args: &[OsString]) -> io::Result<(&OsString, &[OsString])> {
    let [separator, program, rest @ ..] = args else {
        return Err(io::ErrorKind::InvalidInput.into());
    };
    if separator != "--" || program.is_empty() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut go = [0];
    io::stdin().read_exact(&mut go)?;
    if go != *b"G" {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok((program, rest))
}

pub(crate) fn run(args: &[OsString]) -> io::Result<std::convert::Infallible> {
    let (program, rest) = released(args)?;
    let mut command = Command::new(program);
    command.args(rest).stdin(Stdio::null());
    sys::gate_setup(&mut command)?;
    Err(command.exec())
}
