//! The tool table and the case list of the `tools` test come from listings of `src/tools/` and `tests/`,
//! so adding a tool's or a case's files registers it.
//!
//! `OUT_DIR/tools.rs` declares one module for each tool root under `src/tools/` and ends with a `tools!`
//! call with the tool identifiers in entry-name order. `OUT_DIR/cases.rs` declares one module for each case
//! under `tests/` and the constant `CASES`, the entry names listed. An entry is `<id>.rs`, a regular file,
//! or `<id>/`, a directory that holds a regular file `mod.rs`, where `<id>` matches `[a-z][a-z0-9_]*`.
//! Each declaration's `#[path]` is the absolute path of the module's source file: `<id>.rs`, or
//! `<id>/mod.rs` for a directory entry.
//!
//! The script checks directories, links to directories, and entries matching `*.rs` when the first byte
//! of the entry's name differs from `.`. The script requires each checked entry to match `<id>.rs` or
//! `<id>/`. The script stops the build on the first mismatch and reports the entry's path. The script
//! checks entries in ascending order of their names' bytes, so for a fixed set of failing candidates it
//! reports the same path regardless of directory enumeration order. The script reads listings and file
//! types alone, so an untracked file counts as a tracked one does. It writes only under `OUT_DIR`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// For a directory module, `entry` names the directory and `root` is the absolute path of its `mod.rs`;
/// for a file module, both name the file.
struct Module {
    entry: String,
    id: String,
    root: String,
}

fn main() -> ExitCode {
    match write_lists() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("kestrike-tools build script: {message}");
            ExitCode::FAILURE
        }
    }
}

fn write_lists() -> Result<(), String> {
    let package = PathBuf::from(variable("CARGO_MANIFEST_DIR")?);
    let out = PathBuf::from(variable("OUT_DIR")?);
    for directory in ["src/tools", "tests"] {
        println!(
            "cargo::rerun-if-changed={}",
            package.join(directory).display()
        );
    }
    let moved = format!(
        "const _: () = assert!(same(env!(\"CARGO_MANIFEST_DIR\"), {:?}), \"the package moved after its \
         build script ran; remove the build directory\");\n",
        package.to_str().expect("CARGO_MANIFEST_DIR reads as UTF-8")
    );

    let tools = list(&package.join("src/tools"), "mod.rs", &["std", "tests"])?;
    let mut text = moved.clone();
    for tool in &tools {
        text.push_str(&format!(
            "#[path = {:?}]\npub mod {};\n",
            tool.root, tool.id
        ));
    }
    let ids: Vec<&str> = tools.iter().map(|tool| tool.id.as_str()).collect();
    text.push_str(&format!("tools!({});\n", ids.join(", ")));
    write(&out.join("tools.rs"), &text)?;

    let cases = list(&package.join("tests"), "tools.rs", &["std", "tools"])?;
    let mut text = moved;
    for case in &cases {
        text.push_str(&format!("#[path = {:?}]\nmod {};\n", case.root, case.id));
    }
    let entries: Vec<String> = cases
        .iter()
        .map(|case| format!("{:?}", case.entry))
        .collect();
    text.push_str(&format!(
        "const CASES: &[&str] = &[{}];\n",
        entries.join(", ")
    ));
    write(&out.join("cases.rs"), &text)
}

/// The strict and reserved keywords of edition 2024 that match `[a-z][a-z0-9_]*`; `list` refuses each as
/// a module name.
const KEYWORDS: &[&str] = &[
    "abstract", "as", "async", "await", "become", "box", "break", "const", "continue", "crate",
    "do", "dyn", "else", "enum", "extern", "false", "final", "fn", "for", "gen", "if", "impl",
    "in", "let", "loop", "macro", "match", "mod", "move", "mut", "override", "priv", "pub", "ref",
    "return", "self", "static", "struct", "super", "trait", "true", "try", "type", "typeof",
    "unsafe", "unsized", "use", "virtual", "where", "while", "yield",
];

/// `list` returns the modules of `directory`, other than the entry `skip`, in ascending order of their
/// entry names' bytes. `list` skips dot-prefixed names and keeps as candidates a directory, a link to one
/// and an entry matching `*.rs`; `list` classifies candidates in entry-name byte order and returns an
/// error with the path and the reason of the first that is invalid. `taken` holds the module names that
/// the including file reserves.
fn list(directory: &Path, skip: &str, taken: &[&str]) -> Result<Vec<Module>, String> {
    let prefix = directory
        .to_str()
        .expect("the directory joins UTF-8 names to CARGO_MANIFEST_DIR, which reads as UTF-8");
    let mut names = Vec::new();
    for entry in fs::read_dir(directory).map_err(|error| format!("{prefix}: {error}"))? {
        let name = entry
            .map_err(|error| format!("{prefix}: {error}"))?
            .file_name();
        if name != skip {
            names.push(name);
        }
    }
    names.sort_unstable();
    let mut modules: Vec<Module> = Vec::new();
    for name in names {
        let bytes = name.as_encoded_bytes();
        if bytes.starts_with(b".") {
            continue;
        }
        let path = directory.join(&name);
        let kind = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata.file_type(),
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(format!("{}: {error}", path.display())),
        };
        let linked_directory = kind.is_symlink()
            && !bytes.ends_with(b".rs")
            && match fs::metadata(&path) {
                Ok(to) => to.is_dir(),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                    ) =>
                {
                    false
                }
                Err(error) => return Err(format!("{}: {error}", path.display())),
            };
        if !(bytes.ends_with(b".rs") || kind.is_dir() || linked_directory) {
            continue;
        }
        let refuse = |reason: &str| {
            format!(
                "{}: {reason}; a directory, a link to one or a `*.rs` entry of {prefix} is a regular file <id>.rs \
                 or a directory <id>/ that holds a regular file mod.rs, with <id> matching [a-z][a-z0-9_]*",
                path.display()
            )
        };
        let Ok(name) = name.into_string() else {
            return Err(refuse("the name is not UTF-8"));
        };
        let (id, root) = if kind.is_symlink() {
            return Err(refuse("a link"));
        } else if kind.is_dir() {
            let root = format!("{prefix}/{name}/mod.rs");
            match fs::symlink_metadata(&root) {
                Ok(metadata) if metadata.is_file() => (name.clone(), root),
                Err(error) if error.kind() != io::ErrorKind::NotFound => {
                    return Err(format!("{root}: {error}"));
                }
                _ => return Err(refuse("a directory that holds no regular file mod.rs")),
            }
        } else if kind.is_file() {
            match name.strip_suffix(".rs") {
                Some(id) => (id.to_owned(), format!("{prefix}/{name}")),
                None => {
                    unreachable!("a regular file reaches this point only with a name ending in .rs")
                }
            }
        } else {
            return Err(refuse("neither a regular file nor a directory"));
        };
        if !is_module_name(&id) {
            return Err(refuse("the module name is outside [a-z][a-z0-9_]*"));
        }
        if KEYWORDS.contains(&id.as_str()) || taken.contains(&id.as_str()) {
            return Err(refuse(&format!(
                "the module name is a Rust keyword or one of {taken:?}, which the build reserves"
            )));
        }
        // Among valid entry names, `<id>` and `<id>.rs` sort consecutively because `.` sorts before every
        // valid identifier byte.
        if modules.last().is_some_and(|last| last.id == id) {
            return Err(refuse(&format!(
                "a file beside the directory {id}/ of the same module"
            )));
        }
        modules.push(Module {
            entry: name,
            id,
            root,
        });
    }
    Ok(modules)
}

/// `is_module_name` holds when `id` matches `[a-z][a-z0-9_]*`.
fn is_module_name(id: &str) -> bool {
    let mut bytes = id.bytes();
    bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn variable(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|error| format!("{name}: {error}"))
}

/// `write` writes `text` to a new file beside `path`, under the first free name of `.NAME.PID-N`, and
/// renames it over `path`, so an entry at `path` that is no regular file, a link included, is replaced or
/// refused and never written through.
fn write(path: &Path, text: &str) -> Result<(), String> {
    let failed = |at: &Path, error: std::io::Error| format!("{}: {error}", at.display());
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let parent = path.parent().unwrap_or(Path::new("."));
    for at in 0usize.. {
        let staged = parent.join(format!(".{name}.{}-{at}", std::process::id()));
        let mut file = match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staged)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(failed(&staged, error)),
        };
        let written = std::io::Write::write_all(&mut file, text.as_bytes())
            .map_err(|error| failed(&staged, error))
            .and_then(|()| fs::rename(&staged, path).map_err(|error| failed(path, error)));
        if written.is_err() {
            let _ = fs::remove_file(&staged);
        }
        return written;
    }
    unreachable!("an unbounded range yields a name")
}
