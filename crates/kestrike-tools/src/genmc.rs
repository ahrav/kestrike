//! A GenMC case build compiles the kernel package's files and the production files they include by
//! `#[path]`; [`package_sources`] lists them. A transcription check compares Rust texts in their
//! [`normalized`] form and finds an item's body by its header with [`bodies`].
//! `scripts/judge-genmc.py` holds the same rules for its own callers.
//!
//! Offsets are byte offsets. [`read_text`] decodes a file as UTF-8 and reads `\r\n` and a lone `\r` as
//! `\n`. [`walk`] lists every entry under a directory, hidden entries included, and enters each
//! directory it meets that is no link. It passes over a directory it may not list, and a link entry
//! whose target it may not look up stops it from entering that directory's later entries, in the order
//! the directory lists them.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;

use crate::classes::{SPACE, compiled, is_word};
use crate::paths::resolve;
use crate::rust_text::{Lexeme, lexemes};
use crate::text::strip_str;

/// A `#[path = "..."]` attribute at the start of a line, in the one spelling a case build's include scan
/// reads; group 1 is the path.
pub static INCLUDED: LazyLock<Regex> =
    LazyLock::new(|| compiled(&format!(r#"(?m)^{SPACE}*#\[path = "([^"]+)"\]"#)));

static SPACES: LazyLock<Regex> = LazyLock::new(|| compiled(&format!("{SPACE}+")));

static PUNCTUATION: LazyLock<Regex> = LazyLock::new(|| compiled(r" ?([^\p{L}\p{N}_ ]) ?"));

/// The text that stands for a lexeme of `kind` in [`code`].
pub fn lexeme_text(kind: Lexeme) -> &'static str {
    match kind {
        Lexeme::Comment | Lexeme::Unclosed => " ",
        Lexeme::String => "\"\"",
        Lexeme::Char => "''",
    }
}

/// `text` with each comment, a nested block comment whole, as one space, each string literal as `""` after
/// any `b` or `c` prefix and each char literal as `''`, so a delimiter inside a literal never closes a
/// scope or an argument list. A lifetime stays in the code, and a block comment that never closes runs to
/// the end of `text`. The result keeps no offsets of `text`.
pub fn code(text: &str) -> String {
    let mut pieces = String::with_capacity(text.len());
    let mut index = 0;
    for (kind, start, end) in lexemes(text) {
        pieces.push_str(&text[index..start]);
        pieces.push_str(lexeme_text(kind));
        index = end;
    }
    pieces.push_str(&text[index..]);
    pieces
}

/// [`code`] of `text` with each run of white space as one space, kept only where a word character stands
/// on both sides of it.
pub fn normalized(text: &str) -> String {
    let code = code(text);
    let spaced = SPACES.replace_all(&code, " ");
    strip_str(&PUNCTUATION.replace_all(&spaced, "$1")).to_owned()
}

/// The `{...}` bodies, in order, of the items in `text` whose header is `header`. A header counts where
/// neither a word character nor `.` stands before it and no word character after it. Its body is the
/// brace block that opens at the first `{` after it; a `;` before that brace, or a block that never
/// closes, gives it none.
pub fn bodies(text: &str, header: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut at = 0;
    while at <= text.len() {
        let Some(offset) = text[at..].find(header) else {
            break;
        };
        let start = at + offset;
        let end = start + header.len();
        let before = text[..start].chars().next_back();
        let after = text[end..].chars().next();
        if before.is_some_and(|c| is_word(c) || c == '.') || after.is_some_and(is_word) {
            at = start + text[start..].chars().next().map_or(1, char::len_utf8);
            continue;
        }
        at = if header.is_empty() {
            end + after.map_or(1, char::len_utf8)
        } else {
            end
        };
        if let Some(body) = body_after(text, end) {
            found.push(body.to_owned());
        }
    }
    found
}

/// The brace block that opens at the first `{` at or after `end`, unless a `;` comes first.
fn body_after(text: &str, end: usize) -> Option<&str> {
    let open = end + text[end..].find(['{', ';'])?;
    if text.as_bytes()[open] == b';' {
        return None;
    }
    let mut depth = 0_usize;
    for (offset, byte) in text.as_bytes()[open..].iter().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&text[open..=open + offset]);
                }
            }
            _ => {}
        }
    }
    None
}

/// The text of the file at `path`, decoded as UTF-8, with `\r\n` and a lone `\r` read as `\n`.
///
/// # Errors
///
/// `read_text` returns the error of opening or reading the file, and an error of kind
/// [`io::ErrorKind::InvalidData`] for bytes that are no UTF-8.
pub fn read_text(path: &Path) -> io::Result<String> {
    let text = fs::read_to_string(path)?;
    Ok(if text.contains('\r') {
        text.replace("\r\n", "\n").replace('\r', "\n")
    } else {
        text
    })
}

/// The text of `path`, relative to the checkout's top `top`, as [`read_text`] reads it.
///
/// # Errors
///
/// `read_source` returns the error [`read_text`] returns.
pub fn read_source(top: &Path, path: &str) -> io::Result<String> {
    read_text(&top.join(path))
}

/// Whether `error` is one that a lookup of a path reads as no such file: a missing component, a
/// component that is no directory, a bad descriptor or a link loop.
fn is_absent(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::ENOENT | libc::ENOTDIR | libc::EBADF | libc::ELOOP)
    )
}

/// Whether `path`, with links followed, is a regular file; a lookup that [`is_absent`] reads is no file.
///
/// # Errors
///
/// `is_file` returns every other error of the lookup.
pub fn is_file(path: &Path) -> io::Result<bool> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(metadata.is_file()),
        Err(error) if is_absent(&error) => Ok(false),
        Err(error) => Err(error),
    }
}

fn is_dir(path: &Path) -> io::Result<bool> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(metadata.is_dir()),
        Err(error) if is_absent(&error) => Ok(false),
        Err(error) => Err(error),
    }
}

/// The entries of the directory at `path` in the order it lists them, or `None` when the listing is
/// refused permission.
fn listing(path: &Path) -> io::Result<Option<Vec<fs::DirEntry>>> {
    match fs::read_dir(path).and_then(Iterator::collect::<io::Result<Vec<_>>>) {
        Ok(entries) => Ok(Some(entries)),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => Ok(None),
        Err(error) => Err(error),
    }
}

/// Each directory the walk lists under `root`: `root` first, then each subdirectory that is no link,
/// depth first.
fn directories(root: &Path, found: &mut Vec<PathBuf>) -> io::Result<()> {
    found.push(root.to_path_buf());
    let Some(entries) = listing(root)? else {
        return Ok(());
    };
    for entry in entries {
        let kind = match entry.file_type() {
            Ok(kind) => kind,
            Err(error) if is_absent(&error) => continue,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return Ok(()),
            Err(error) => return Err(error),
        };
        if kind.is_symlink() {
            match fs::metadata(entry.path()) {
                Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return Ok(()),
                Err(error) if !is_absent(&error) => return Err(error),
                _ => {}
            }
        } else if kind.is_dir() {
            directories(&entry.path(), found)?;
        }
    }
    Ok(())
}

/// Every entry under the directory `root` (files, directories and links), each once, in no stated order.
/// A `root` that is no directory has none.
///
/// # Errors
///
/// `walk` returns an error of a listing or a lookup other than a refused permission and those
/// [`is_file`] reads as absent.
pub fn walk(root: &Path) -> io::Result<Vec<PathBuf>> {
    if !is_dir(root)? {
        return Ok(Vec::new());
    }
    let mut starts = Vec::new();
    directories(root, &mut starts)?;
    let mut seen = BTreeSet::new();
    let mut found = Vec::new();
    for start in starts {
        let Some(entries) = listing(&start)? else {
            continue;
        };
        for entry in entries {
            let path = entry.path();
            if seen.insert(path.clone()) {
                found.push(path);
            }
        }
    }
    Ok(found)
}

/// Whether a component of `path` below `root` is named `target`, where build state stands.
pub fn under_target(path: &Path, root: &Path) -> bool {
    path.strip_prefix(root)
        .is_ok_and(|relative| relative.iter().any(|part| part == "target"))
}

/// The suffix of the last component of `path`, as bytes: from its last `.`, unless that `.` leads or
/// ends the name.
pub fn suffix(path: &Path) -> &[u8] {
    let name = path.file_name().map_or(&[][..], |name| name.as_bytes());
    match name.iter().rposition(|&byte| byte == b'.') {
        Some(at) if at > 0 && at < name.len() - 1 => &name[at..],
        _ => &[],
    }
}

/// The files a case build compiles: the regular files under `package`, links to one included, with
/// build state under a `target` component aside, in component order; then, each once and in component
/// order, the resolved paths of the `#[path]` attributes [`INCLUDED`] reads in the package's `.rs` files
/// that are none of those files.
///
/// # Errors
///
/// `package_sources` returns an error of [`walk`] or [`is_file`], of reading a `.rs` file of the
/// package ([`io::ErrorKind::InvalidData`] for one that is no UTF-8), and of [`resolve`], which refuses
/// an included path whose lookup meets a link loop.
pub fn package_sources(package: &Path) -> io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for path in walk(package)? {
        if is_file(&path)? && !under_target(&path, package) {
            files.push(path);
        }
    }
    files.sort();
    let mut included = BTreeSet::new();
    for path in &files {
        if suffix(path) != b".rs" {
            continue;
        }
        let text = read_text(path)?;
        let parent = path.parent().unwrap_or(Path::new(""));
        for found in INCLUDED.captures_iter(&text) {
            let target = found.get(1).expect("INCLUDED has group 1").as_str();
            included.insert(resolve(&parent.join(target))?);
        }
    }
    let listed: BTreeSet<&PathBuf> = files.iter().collect();
    let extra: Vec<PathBuf> = included
        .into_iter()
        .filter(|path| !listed.contains(path))
        .collect();
    files.extend(extra);
    Ok(files)
}

#[cfg(test)]
#[path = "genmc_tests.rs"]
mod tests;
