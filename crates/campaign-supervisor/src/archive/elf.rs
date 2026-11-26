//! ELF64 little-endian program-header reading. An archive holds an
//! executable for this host's machine, pins the program
//! interpreter it requests, and refuses an executable whose dynamic
//! section requests an audit module: the loader runs such a module before
//! the program and leaves it out of its library listing, so the archive
//! would hold no copy of that code. An `RPATH` without `RUNPATH` is refused in workers and libraries: the
//! loader searches it before the library path, so it would resolve
//! libraries outside the archive. The kernel runs the first interpreter
//! segment, so a file with two, or with a relative interpreter path that
//! the kernel and a command resolve against different directories, is
//! refused, and so is a file that needs libraries and names no
//! interpreter to map them.

use crate::store::Opened;

use super::Invalid;

const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
/// This host's `e_machine`, `None` on a machine the archive does not know.
const EM_NATIVE: Option<u16> = if cfg!(target_arch = "x86_64") {
    Some(62)
} else if cfg!(target_arch = "aarch64") {
    Some(183)
} else if cfg!(target_arch = "riscv64") {
    Some(243)
} else {
    None
};
/// The size of one ELF64 program header, the only size the kernel loads.
const PHDR_SIZE: u16 = 56;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const DT_NULL: u64 = 0;
const DT_NEEDED: u64 = 1;
const DT_RPATH: u64 = 15;
const DT_RUNPATH: u64 = 29;
const DT_DEPAUDIT: u64 = 0x6fff_fefb;
const DT_AUDIT: u64 = 0x6fff_fefc;

/// The most bytes of one interpreter or dynamic segment read; a linker
/// writes a few kilobytes for each.
const SEGMENT_BOUND: u64 = 1 << 20;

/// The interpreter path `executable` requests; `None` for a static one.
///
/// # Errors
///
/// [`Invalid::Audit`] for an audit request; [`Invalid::Elf`] for any
/// other refused file; [`Invalid::Io`] for a failed read.
pub(super) fn interpreter(executable: &Opened) -> Result<Option<String>, Invalid> {
    scan(executable, true)
}

pub(super) fn library(file: &Opened) -> Result<(), Invalid> {
    scan(file, false).map(drop)
}

fn scan(executable: &Opened, worker: bool) -> Result<Option<String>, Invalid> {
    let header = read(executable, 0, 64)?;
    if header[..4] != *b"\x7fELF" || header[4] != 2 || header[5] != 1 {
        return Err(Invalid::Elf("no ELF64 little-endian file".to_owned()));
    }
    let half = |at: usize| u16::from_le_bytes([header[at], header[at + 1]]);
    if !matches!(half(16), ET_EXEC | ET_DYN) {
        return Err(Invalid::Elf("no executable or shared object".to_owned()));
    }
    let Some(native) = EM_NATIVE else {
        let why = format!(
            "the host {} has no known ELF machine",
            std::env::consts::ARCH
        );
        return Err(Invalid::Elf(why));
    };
    if half(18) != native {
        return Err(Invalid::Elf(format!("built for machine {}", half(18))));
    }
    if half(54) != PHDR_SIZE {
        return Err(Invalid::Elf(
            "program headers of another size than ELF64's".to_owned(),
        ));
    }
    if half(56) == 0 {
        return Err(Invalid::Elf("no program header".to_owned()));
    }
    let size = u64::from(half(56)) * u64::from(PHDR_SIZE);
    if size > 65536 {
        return Err(Invalid::Elf(
            "program headers past their read bound".to_owned(),
        ));
    }
    let headers = read(executable, word(&header, 32), size)?;
    let mut executable_entry = false;
    let mut named = None;
    let mut needs = false;
    for entry in headers.as_chunks::<56>().0 {
        let kind = u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]);
        if kind == PT_LOAD {
            let flags = u32::from_le_bytes(entry[4..8].try_into().expect("header flags"));
            let start = word(entry, 16);
            let end = start.checked_add(word(entry, 32));
            executable_entry |= flags & 1 != 0
                && word(&header, 24) >= start
                && end.is_some_and(|end| word(&header, 24) < end);
        }
        if kind != PT_INTERP && kind != PT_DYNAMIC {
            continue;
        }
        let length = word(entry, 32);
        if length > SEGMENT_BOUND {
            return Err(Invalid::Elf("a segment past its read bound".to_owned()));
        }
        let segment = read(executable, word(entry, 8), length)?;
        if kind == PT_INTERP {
            if named.is_some() {
                return Err(Invalid::Elf("more than one interpreter segment".to_owned()));
            }
            named = Some(interpreter_path(&segment)?);
        } else {
            needs |= dynamic(&segment)?;
        }
    }
    if worker && needs && named.is_none() {
        return Err(Invalid::Elf(
            "it needs libraries and names no interpreter".to_owned(),
        ));
    }
    if worker && named.is_none() && !executable_entry {
        return Err(Invalid::Elf(
            "its entry point has no executable load mapping".to_owned(),
        ));
    }
    Ok(named)
}

/// The absolute path an interpreter segment names.
fn interpreter_path(segment: &[u8]) -> Result<String, Invalid> {
    let Some((&0, path)) = segment.split_last() else {
        return Err(Invalid::Elf("an unterminated interpreter path".to_owned()));
    };
    let path = String::from_utf8_lossy(path).into_owned();
    if !path.starts_with('/') {
        return Err(Invalid::Elf(format!(
            "the interpreter {path:?} is relative"
        )));
    }
    Ok(path)
}

/// Whether a dynamic segment names a needed library, after refusing an
/// audit request, an `RPATH` without `RUNPATH` and a segment with no terminating entry.
fn dynamic(segment: &[u8]) -> Result<bool, Invalid> {
    let (mut needs, mut rpath, mut runpath) = (false, false, false);
    for entry in segment.as_chunks::<16>().0 {
        match word(entry, 0) {
            DT_NULL => {
                if rpath && !runpath {
                    return Err(Invalid::Elf("it names an RPATH without RUNPATH".to_owned()));
                }
                return Ok(needs);
            }
            DT_NEEDED => needs = true,
            DT_AUDIT | DT_DEPAUDIT => return Err(Invalid::Audit),
            DT_RPATH => rpath = true,
            DT_RUNPATH => runpath = true,
            _ => {}
        }
    }
    Err(Invalid::Elf(
        "a dynamic section with no terminating entry".to_owned(),
    ))
}

fn word(bytes: &[u8], at: usize) -> u64 {
    let mut word = [0; 8];
    word.copy_from_slice(&bytes[at..at + 8]);
    u64::from_le_bytes(word)
}

fn read(file: &Opened, offset: u64, length: u64) -> Result<Vec<u8>, Invalid> {
    if offset
        .checked_add(length)
        .is_none_or(|end| i64::try_from(end).is_err())
    {
        return Err(Invalid::Elf("a truncated header or segment".to_owned()));
    }
    let length = usize::try_from(length).expect("a bounded segment fits in memory");
    let mut bytes = vec![0; length];
    match file.read_exact_at(&mut bytes, offset) {
        Ok(()) => Ok(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
            Err(Invalid::Elf("a truncated header or segment".to_owned()))
        }
        Err(error) => Err(Invalid::Io(error)),
    }
}
