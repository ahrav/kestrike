//! The tool table and the case list of the `tools` test come from listings of `src/tools/` and `tests/`,
//! so a tool or a case is registered by adding its files.
//!
//! `OUT_DIR/tools.rs` declares one module for each tool root under `src/tools/` and ends with the `tools!`
//! call that `src/tools/mod.rs` defines and then includes. `OUT_DIR/cases.rs` declares one module for each
//! case under `tests/` and the constant `CASES`, the entry names listed; `tests/tools.rs` includes it. An
//! entry is `<id>.rs`, a regular file, or `<id>/`, a directory that holds a regular file `mod.rs`, where
//! `<id>` matches `[a-z][a-z0-9_]*`. Each declaration's `#[path]` is the entry's absolute path. The
//! directory's own root, `src/tools/mod.rs` or `tests/tools.rs`, is skipped, and any other entry stops the
//! build with its path. The script reads listings and file types alone, so an untracked file counts as a
//! tracked one does. It writes only under `OUT_DIR`.

use std::fs;
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

    let tools = list(&package.join("src/tools"), "mod.rs")?;
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

    let cases = list(&package.join("tests"), "tools.rs")?;
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

/// `list` returns the modules of `directory`, other than the entry `skip`, in ascending order of their
/// entry names' bytes. The first entry that names no module makes `list` return an error with the entry's
/// path and the reason.
fn list(directory: &Path, skip: &str) -> Result<Vec<Module>, String> {
    let shown = directory.display();
    let listing = fs::read_dir(directory).map_err(|error| format!("{shown}: {error}"))?;
    let mut modules = Vec::new();
    for entry in listing {
        let entry = entry.map_err(|error| format!("{shown}: {error}"))?;
        let path = entry.path();
        if entry.file_name() == skip {
            continue;
        }
        let refuse = |reason: &str| {
            format!(
                "{}: {reason}; an entry of {shown} is a regular file <id>.rs or a directory <id>/ that \
                 holds a regular file mod.rs, with <id> matching [a-z][a-z0-9_]*",
                path.display()
            )
        };
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
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
                Ok(metadata) if metadata.is_file() => (name.clone(), root),
                _ => return Err(refuse("a directory that holds no regular file mod.rs")),
            }
        } else if kind.is_file() {
            match name.strip_suffix(".rs") {
                Some(id) => (id.to_owned(), path.clone()),
                None => return Err(refuse("a file whose name does not end in .rs")),
            }
        } else {
            return Err(refuse("neither a regular file nor a directory"));
        };
        let mut bytes = id.bytes();
        let named = bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
            && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_');
        if !named {
            return Err(refuse("the module name is outside [a-z][a-z0-9_]*"));
        }
        let Some(root) = root.to_str().map(str::to_owned) else {
            return Err(refuse("the path is not UTF-8"));
        };
        modules.push(Module {
            entry: name,
            id,
            root,
        });
    }
    modules.sort_by(|a, b| a.entry.cmp(&b.entry));
    let mut ids: Vec<&str> = modules.iter().map(|module| module.id.as_str()).collect();
    ids.sort_unstable();
    if let Some(pair) = ids.windows(2).find(|pair| pair[0] == pair[1]) {
        return Err(format!(
            "{}: a file beside the directory {id}/ of the same module; a module is one of the two",
            directory.join(format!("{}.rs", pair[0])).display(),
            id = pair[0]
        ));
    }
    Ok(modules)
}

fn variable(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|error| format!("{name}: {error}"))
}

fn write(path: &Path, text: &str) -> Result<(), String> {
    fs::write(path, text).map_err(|error| format!("{}: {error}", path.display()))
}
