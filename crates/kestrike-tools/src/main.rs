//! The binary takes the checkout's top level and a tool name, runs the tool with the remaining arguments
//! and exits with the tool's code. A missing or unknown tool name exits 2.

use std::ffi::OsString;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use kestrike_tools::tools;

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let [top, tool, rest @ ..] = args.as_slice() else {
        let _ = writeln!(
            io::stderr(),
            "kestrike-tools: usage: kestrike-tools TOP TOOL [ARGUMENT ...]"
        );
        return ExitCode::from(2);
    };
    let Some(entry) = tool.to_str().and_then(tools::entry) else {
        let _ = writeln!(
            io::stderr(),
            "kestrike-tools: no tool is named {}; the tools are {}",
            tool.to_string_lossy(),
            tools::NAMES.join(", ")
        );
        return ExitCode::from(2);
    };
    ExitCode::from(entry(&PathBuf::from(top), rest))
}
