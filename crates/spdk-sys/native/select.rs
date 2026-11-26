//! Install records and their selection. A record holds an install's target
//! line (target, sanitizer and ordered compile flags), the digest of its
//! headers and the generated output its headers produce, and the lineage the
//! controlled native build records: the `Source`, `Patches`, `Build inputs`,
//! `Compilers` and `Configure` lines and one `Archive` line per archive.
//! Selection normalizes the install's include root, so a relocated install
//! matches the record of the same headers.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::string::{String, ToString};
use std::vec::Vec;
use std::{fs, io};

/// Stands in for the install's include root in a normalized target line.
pub const INCLUDE_ROOT: &str = "-I<includedir>";

/// The directory of install records under `src/generated`.
pub const INSTALLS: &str = "installs";

/// The directory of generated outputs under `src/generated`.
pub const OUTPUTS: &str = "outputs";

const TARGET: &str = "Target: ";
const HEADER_DIGEST: &str = "Header digest: ";
const OUTPUT: &str = "Output: ";
/// The lineage line prefixes, in [`Lineage::values`] order. A record with a
/// lineage holds each of them once with a nonempty value other than
/// `unrecorded` or `stale`, and one [`ARCHIVE`] line per distinct archive.
const LINEAGE: [&str; 5] = [
    "Source: ",
    "Patches: ",
    "Build inputs: ",
    "Compilers: ",
    "Configure: ",
];
const ARCHIVE: &str = "Archive: ";

/// The controlled native build's record of an install: `values[i]` is the
/// value of the `LINEAGE[i]` line, and `archives` maps each archive's file
/// name to its sha256.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Lineage {
    pub values: [String; 5],
    pub archives: BTreeMap<String, String>,
}

/// One checked-in install record.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Install {
    /// The record file under [`INSTALLS`].
    pub record: PathBuf,
    /// The install's target line, as [`flags_line`] forms it.
    pub target: String,
    /// The digest of the install's headers at generation.
    pub header_digest: String,
    /// The name of the output under [`OUTPUTS`] the install's headers generate.
    pub output: String,
    /// The controlled build's lineage, or `None` for a record with no lineage line.
    pub lineage: Option<Lineage>,
}

/// The lineage `text` records, or `None` when the record carries no lineage line.
///
/// # Errors
///
/// When `text` holds any lineage line and:
/// - a [`LINEAGE`] line is absent, repeated, empty, or holds `unrecorded` or `stale`;
/// - an `Archive: ` line is other than `<64 lowercase hex>  <path>`;
/// - two `Archive: ` lines name the same file;
/// - no `Archive: ` line is present.
pub fn lineage(text: &str) -> Result<Option<Lineage>, String> {
    let lines: Vec<&str> = text
        .lines()
        .filter(|line| {
            LINEAGE
                .iter()
                .chain([&ARCHIVE])
                .any(|prefix| line.starts_with(prefix))
        })
        .collect();
    if lines.is_empty() {
        return Ok(None);
    }
    let mut values = LINEAGE.map(|_| String::new());
    for (value, prefix) in values.iter_mut().zip(LINEAGE) {
        let found: Vec<&str> = lines
            .iter()
            .filter_map(|line| line.strip_prefix(prefix))
            .collect();
        match found.as_slice() {
            [""] => return Err(std::format!("the lineage line `{prefix}` is empty")),
            ["unrecorded" | "stale"] => {
                return Err(std::format!("the lineage line `{prefix}` names no digest"));
            }
            [one] => *value = one.to_string(),
            _ => {
                return Err(std::format!(
                    "the lineage records `{prefix}` {} times",
                    found.len()
                ));
            }
        }
    }
    let mut archives = BTreeMap::new();
    for line in lines.iter().filter_map(|line| line.strip_prefix(ARCHIVE)) {
        let (name, digest) = archive_digest(line).ok_or_else(|| {
            std::format!("the lineage line `{ARCHIVE}{line}` names no sha256 and file")
        })?;
        if archives.insert(name, digest).is_some() {
            return Err(std::format!(
                "the lineage line `{ARCHIVE}{line}` repeats an archive"
            ));
        }
    }
    if archives.is_empty() {
        return Err("the lineage records no `Archive: ` line".to_string());
    }
    Ok(Some(Lineage { values, archives }))
}

/// The file name and sha256 of one `sha256sum` line, `<64 lowercase hex>  <path>`.
fn archive_digest(line: &str) -> Option<(String, String)> {
    let (digest, path) = line.split_once("  ")?;
    let hex = digest.len() == 64
        && digest
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    let name = Path::new(path).file_name()?.to_str()?;
    hex.then(|| (name.to_string(), digest.to_string()))
}

/// The file name and sha256 of each of `files`, from one `sha256sum` run.
///
/// # Errors
///
/// When `sha256sum` fails to start or exits nonzero, or prints a line other
/// than `<64 lowercase hex>  <path>` or a line count other than `files.len()`.
pub fn sha256sums(files: &[PathBuf]) -> Result<Vec<(String, String)>, String> {
    let output = std::process::Command::new("sha256sum")
        .args(files)
        .output()
        .map_err(|e| std::format!("running sha256sum on the linked archives: {e}"))?;
    if !output.status.success() {
        return Err(std::format!(
            "sha256sum of the linked archives: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let digests = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| archive_digest(line).ok_or_else(|| std::format!("sha256sum printed `{line}`")))
        .collect::<Result<Vec<_>, _>>()?;
    if digests.len() != files.len() {
        return Err(std::format!(
            "sha256sum named {} digests for {} archives",
            digests.len(),
            files.len()
        ));
    }
    Ok(digests)
}

/// Checks each linked archive, as (file name, sha256), against the digest
/// `lineage` records for it in `record`. The lineage covers every static
/// archive of the install, so it may record archives absent from `linked`.
///
/// # Errors
///
/// Names the first linked archive that `lineage` lacks or records with a
/// different sha256.
pub fn check_archives(
    record: &Path,
    lineage: &Lineage,
    linked: &[(String, String)],
) -> Result<(), String> {
    for (name, digest) in linked {
        match lineage.archives.get(name) {
            None => {
                return Err(std::format!(
                    "{} records no digest for the linked archive {name}",
                    record.display()
                ));
            }
            Some(recorded) if recorded != digest => {
                return Err(std::format!(
                    "the linked archive {name} has sha256 {digest}, and {} records {recorded} from its \
                     controlled build; a changed archive needs a new controlled build record",
                    record.display()
                ));
            }
            Some(_) => {}
        }
    }
    Ok(())
}

/// The target line an install record holds for an install of `target`
/// with `sanitizer` (`Some("address")` for an ASan install) whose ordered
/// pkg-config flags are `cflags`.
pub fn flags_line(target: &str, sanitizer: Option<&str>, cflags: &[String]) -> String {
    match sanitizer {
        Some(sanitizer) => std::format!(
            "{TARGET}{target}. Sanitizer: {sanitizer}. Flags: {} -Inative",
            cflags.join(" ")
        ),
        None => std::format!("{TARGET}{target}. Flags: {} -Inative", cflags.join(" ")),
    }
}

/// `line` with its first `-I` token other than `-Inative`, the install's
/// include root, replaced by [`INCLUDE_ROOT`]; every other token stays as
/// recorded.
pub fn normalized(line: &str) -> String {
    let mut replaced = false;
    line.split(' ')
        .map(|token| {
            if !replaced && token.starts_with("-I") && token != "-Inative" {
                replaced = true;
                INCLUDE_ROOT.to_string()
            } else {
                token.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Checks that `cflags` opens with the install's include root `includedir`
/// and names it there alone, so the normalized line stands for the install.
pub fn include_root(cflags: &[String], includedir: &str) -> Result<(), String> {
    let root = std::format!("-I{includedir}");
    let roots = cflags.iter().filter(|flag| **flag == root).count();
    match (cflags.first().map(String::as_str), roots) {
        (Some(first), 1) if first == root => Ok(()),
        _ => Err(std::format!(
            "the install's flags {cflags:?} name its include root {root} {roots} times, \
             and the flags open with {:?}",
            cflags.first()
        )),
    }
}

/// A libdpdk install that links `-lasan` requires exactly one Rust sanitizer
/// selection: `address`, joined or as the two tokens `-Z sanitizer=address`.
pub fn sanitizer(native: &str, rust: &[String]) -> Result<Option<&'static str>, String> {
    if !native.split_whitespace().any(|token| token == "-lasan") {
        return Ok(None);
    }
    let mut sanitizers: Vec<&str> = Vec::new();
    let mut flags = rust.iter().map(String::as_str);
    while let Some(flag) = flags.next() {
        let value = match flag {
            "-Z" => flags
                .next()
                .and_then(|next| next.strip_prefix("sanitizer=")),
            _ => flag.strip_prefix("-Zsanitizer="),
        };
        sanitizers.extend(value.into_iter().flat_map(|list| list.split(',')));
    }
    match sanitizers.as_slice() {
        ["address"] => Ok(Some("address")),
        [] => Err(
            "the install's libdpdk links -lasan, so it was built with --enable-asan, \
             while the Rust flags select no sanitizer; build with \
             RUSTFLAGS=\"-Zsanitizer=address -Cforce-frame-pointers=yes\" and -Zbuild-std, \
             or select an ordinary install"
                .to_string(),
        ),
        other => Err(std::format!(
            "the install's libdpdk links -lasan while the Rust flags select sanitizers \
             {other:?}; it needs `address`, once"
        )),
    }
}

pub fn recorded(root: &Path) -> io::Result<Vec<Install>> {
    let mut recorded = Vec::new();
    for entry in fs::read_dir(root.join(INSTALLS))? {
        let record = entry?.path();
        let text = fs::read_to_string(&record)?;
        let line = |prefix: &str| {
            text.lines()
                .find(|line| line.starts_with(prefix))
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        std::format!("{} holds no `{prefix}` line", record.display()),
                    )
                })
        };
        let value = |prefix: &str| line(prefix).map(|line| line[prefix.len()..].to_string());
        let lineage = lineage(&text).map_err(|reason| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                std::format!("{}: {reason}", record.display()),
            )
        })?;
        recorded.push(Install {
            target: line(TARGET)?.to_string(),
            header_digest: value(HEADER_DIGEST)?,
            output: value(OUTPUT)?,
            record,
            lineage,
        });
    }
    recorded.sort();
    Ok(recorded)
}

/// Target-line selection tolerates relocation of the install's include root.
pub fn matching<'a>(wanted: &str, recorded: &'a [Install]) -> Vec<&'a Install> {
    let wanted = normalized(wanted);
    recorded
        .iter()
        .filter(|install| normalized(&install.target) == wanted)
        .collect()
}
