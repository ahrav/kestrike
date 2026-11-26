//! ```text
//! kestrike-inspect --image <path> --chunk-len <bytes> [--range <start>:<end>]
//! ```
//!
//! The command exits 0 when all candidates verify, empty windows included.
//! The process exits with status 1 when a candidate fails and status 2 for
//! a usage, open, size, read, or write error. Sizing accepts only a regular
//! file or a block device.
//! The scan covers the whole image by default.
//!
//! Arguments are read as OS strings: `--image` takes any path the OS can
//! name, its bytes passed through unchanged. Option names must be UTF-8,
//! `--chunk-len` is a decimal `u32`, and `--range` is two decimal `u64`
//! offsets with `start <= end <=` the image length.
//! Messages quote the path with its non-UTF-8 bytes escaped, so they name it
//! exactly. The image is only read.

use std::fmt::Display;
use std::fs::OpenOptions;
use std::io::{self, BufWriter, Seek, SeekFrom, Write};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::PathBuf;
use std::process::ExitCode;

use kestrike::storage::{Crc32c, RecordConfig, Window, inspect};

fn usage(message: &str) -> ExitCode {
    eprintln!(
        "kestrike-inspect: {message}; give --image <path> --chunk-len <bytes> [--range <start>:<end>]"
    );
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let (mut image, mut chunk_len, mut range) = (None::<PathBuf>, None, None);
    while let Some(arg) = args.next() {
        let Some(name) = arg.to_str() else {
            return usage(&format!("unknown argument {}", arg.display()));
        };
        if !matches!(name, "--image" | "--chunk-len" | "--range") {
            return usage(&format!("unknown argument {name}"));
        }
        let Some(value) = args.next() else {
            return usage(&format!("{name} needs a value"));
        };
        let text = || {
            value
                .to_str()
                .ok_or_else(|| usage(&format!("{name} needs UTF-8")))
        };
        let parsed = match name {
            "--image" => {
                image = Some(PathBuf::from(&value));
                Ok(())
            }
            "--chunk-len" => text().and_then(|text| match text.parse::<u32>() {
                Ok(len) => {
                    chunk_len = Some(len);
                    Ok(())
                }
                Err(_) => Err(usage("--chunk-len needs a byte count")),
            }),
            "--range" => text().and_then(|text| {
                match text
                    .split_once(':')
                    .and_then(|(a, b)| Some((a.parse::<u64>().ok()?, b.parse::<u64>().ok()?)))
                {
                    Some(bounds) => {
                        range = Some(bounds);
                        Ok(())
                    }
                    None => Err(usage("--range needs <start>:<end> byte offsets")),
                }
            }),
            _ => unreachable!("the name check above admits only these three"),
        };
        if let Err(code) = parsed {
            return code;
        }
    }
    let (Some(path), Some(chunk_len)) = (image, chunk_len) else {
        return usage("--image and --chunk-len are required");
    };
    // `Debug` escapes the bytes a path holds that are not UTF-8, so the
    // message names the path exactly.
    let shown = format!("{path:?}");
    let config = match (RecordConfig { chunk_len }).validate() {
        Ok(config) => config,
        Err(error) => return usage(&format!("--chunk-len {chunk_len}: {error:?}")),
    };
    // `O_NONBLOCK` keeps a FIFO with no writer from blocking the open, so
    // the file-type check below refuses it. Reads of a regular file or a
    // block device are unaffected by the flag.
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) => {
            eprintln!("kestrike-inspect: opening {shown}: {error}");
            return ExitCode::from(2);
        }
    };
    match file.metadata().map(|meta| meta.file_type()) {
        Ok(kind) if kind.is_file() || kind.is_block_device() => {}
        Ok(_) => {
            eprintln!("kestrike-inspect: sizing {shown}: not a regular file or block device");
            return ExitCode::from(2);
        }
        Err(error) => {
            eprintln!("kestrike-inspect: sizing {shown}: {error}");
            return ExitCode::from(2);
        }
    }
    let len = match file.seek(SeekFrom::End(0)) {
        Ok(len) => len,
        Err(error) => {
            eprintln!("kestrike-inspect: sizing {shown}: {error}");
            return ExitCode::from(2);
        }
    };
    let (start, end) = range.unwrap_or((0, len));
    let window = match Window::new(start, end, len) {
        Ok(window) => window,
        Err(error) => {
            return usage(&format!(
                "the range needs start <= end <= the image length: {error:?}"
            ));
        }
    };
    let mut out = BufWriter::new(io::stdout().lock());
    let mut output_failed = false;
    let mut emit =
        |line: &dyn Display| writeln!(out, "{line}").inspect_err(|_| output_failed = true);
    let result = emit(&format_args!("image {shown} ({len} bytes)"))
        .and_then(|()| inspect(&file, window, Crc32c::detect(), &config, |f| emit(&f)))
        .and_then(|report| emit(&report).map(|()| report));
    let result = result.and_then(|report| {
        out.flush()
            .inspect_err(|_| output_failed = true)
            .map(|()| report)
    });
    match result {
        Ok(report) if report.verified() => ExitCode::SUCCESS,
        Ok(_) => ExitCode::FAILURE,
        Err(error) => {
            let step = if output_failed {
                "writing the report of"
            } else {
                "reading"
            };
            eprintln!("kestrike-inspect: {step} {shown}: {error}");
            ExitCode::from(2)
        }
    }
}
