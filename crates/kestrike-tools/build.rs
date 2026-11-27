//! The tool table and the case list of the `tools` test come from listings of `src/tools/` and `tests/`,
//! so adding a tool's or a case's files registers it.
//!
//! `OUT_DIR/tools.rs` declares one module for each tool root under `src/tools/` and ends with a `tools!`
//! call with the tool identifiers in entry-name order. `OUT_DIR/cases.rs` declares one module for each case
//! under `tests/` and the constant `CASES`, the entry names listed. An entry is `<id>.rs`, a regular file,
//! or `<id>/`, a directory that holds a regular file `mod.rs`, where `<id>` matches `[a-z][a-z0-9_]*`.
//! Each declaration's `#[path]` is the entry's absolute path.
//!
//! The script skips the listing's root file (`src/tools/mod.rs` or `tests/tools.rs`). An invalid entry
//! stops the build with its path; entries are checked in ascending order of their names' bytes, so the
//! entry reported is the same on every file system. The script reads listings and file types alone, so an
//! untracked file counts as a tracked one does. It writes only under `OUT_DIR`.

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
    println!("cargo::rerun-if-changed=src/tools");
    println!("cargo::rerun-if-changed=tests");
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

    let tools = list(
        &package.join("src/tools"),
        "mod.rs",
        &["core", "std", "tests"],
    )?;
    let mut text = String::new();
    for tool in &tools {
        text.push_str(&format!(
            "#[path = {:?}]\npub mod {};\n",
            tool.root, tool.id
        ));
    }
    let ids: Vec<&str> = tools.iter().map(|tool| tool.id.as_str()).collect();
    text.push_str(&format!("tools!({});\n", ids.join(", ")));
    write(&out.join("tools.rs"), &text)?;

    let cases = list(
        &package.join("tests"),
        "tools.rs",
        &["core", "kestrike_tools", "std"],
    )?;
    let mut text = String::new();
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
/// entry names' bytes. It classifies the entries in that order, and the first entry that names no module,
/// or names a keyword or one of `taken`, the names the including file already resolves, makes `list`
/// return an error with the entry's path and the reason.
fn list(directory: &Path, skip: &str, taken: &[&str]) -> Result<Vec<Module>, String> {
    let shown = directory.display();
    let Some(prefix) = directory.to_str() else {
        return Err(format!("{shown}: the path is not UTF-8"));
    };
    let mut names = Vec::new();
    for entry in fs::read_dir(directory).map_err(|error| format!("{shown}: {error}"))? {
        let name = entry
            .map_err(|error| format!("{shown}: {error}"))?
            .file_name();
        if name != skip {
            names.push(name);
        }
    }
    names.sort_unstable();
    let mut modules: Vec<Module> = Vec::new();
    for name in names {
        let path = directory.join(&name);
        let refuse = |reason: &str| {
            format!(
                "{}: {reason}; an entry of {shown} is a regular file <id>.rs or a directory <id>/ that \
                 holds a regular file mod.rs, with <id> matching [a-z][a-z0-9_]*",
                path.display()
            )
        };
        let Ok(name) = name.into_string() else {
            return Err(refuse("the name is not UTF-8"));
        };
        let kind = fs::symlink_metadata(&path)
            .map_err(|error| format!("{}: {error}", path.display()))?
            .file_type();
        let (id, root) = if kind.is_symlink() {
            return Err(refuse("a link"));
        } else if kind.is_dir() {
            let root = path.join("mod.rs");
            match fs::symlink_metadata(&root) {
                Ok(metadata) if metadata.is_file() => {
                    (name.clone(), format!("{prefix}/{name}/mod.rs"))
                }
                Err(error) if error.kind() != io::ErrorKind::NotFound => {
                    return Err(format!("{}: {error}", root.display()));
                }
                _ => return Err(refuse("a directory that holds no regular file mod.rs")),
            }
        } else if kind.is_file() {
            match name.strip_suffix(".rs") {
                Some(id) => (id.to_owned(), format!("{prefix}/{name}")),
                None => return Err(refuse("a file whose name does not end in .rs")),
            }
        } else {
            return Err(refuse("neither a regular file nor a directory"));
        };
        if !is_module_name(&id) {
            return Err(refuse("the module name is outside [a-z][a-z0-9_]*"));
        }
        if KEYWORDS.contains(&id.as_str()) || taken.contains(&id.as_str()) {
            return Err(refuse(&format!(
                "the module name is a Rust keyword or one of {taken:?}, which the including file uses"
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

fn write(path: &Path, text: &str) -> Result<(), String> {
    fs::write(path, text).map_err(|error| format!("{}: {error}", path.display()))
}
