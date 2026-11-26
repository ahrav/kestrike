//! `reach` keeps `verification/reach/FAMILY.json`, the register of which
//! variants of the family's listed outcome enums a named simulation run
//! constructed, in step with `crates/kestrike/src/`. `sites` prints each
//! listed variant's construction sites. `measure` writes every row's state
//! from an `llvm-cov` export and a run record. `sync` adds an `unmeasured`
//! row for each new variant and drops the rows of removed variants, and
//! `sync --status` prints the `unmeasured` rows. `compare` prints each row
//! whose state or count differs in a fresh measurement and leaves the
//! register unchanged.

mod cfg;
mod coverage;
mod mapping;
mod modes;
mod register;
mod source;
#[cfg(test)]
mod tests;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use sha2::{Digest, Sha256};

/// `run.tool` identifies the measuring tool by the SHA-256 digest of these
/// length-prefixed Cargo and Rust files.
const SOURCES: [&[u8]; 9] = [
    include_bytes!("../Cargo.toml"),
    include_bytes!("../Cargo.lock"),
    include_bytes!("main.rs"),
    include_bytes!("cfg.rs"),
    include_bytes!("coverage.rs"),
    include_bytes!("mapping.rs"),
    include_bytes!("modes.rs"),
    include_bytes!("register.rs"),
    include_bytes!("source.rs"),
];

fn digest() -> String {
    let mut hasher = Sha256::new();
    for source in SOURCES {
        hasher.update((source.len() as u64).to_le_bytes());
        hasher.update(source);
    }
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

const USAGE: &str = "usage: reach sites FAMILY
       reach measure FAMILY --export EXPORT --run RUN
       reach sync FAMILY [--status]
       reach compare FAMILY --export EXPORT
options: --root DIR (the repository, by default the one holding this tool)";

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match run(&arguments) {
        Ok(output) => {
            print!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("reach: {error}");
            ExitCode::from(2)
        }
    }
}

struct Options {
    mode: String,
    family: String,
    root: PathBuf,
    export: Option<PathBuf>,
    run: Option<PathBuf>,
    status: bool,
}

fn options(arguments: &[String]) -> Result<Options, String> {
    let [mode, family, rest @ ..] = arguments else {
        return Err(USAGE.to_owned());
    };
    if !source::FAMILIES.contains(&family.as_str()) {
        return Err(format!(
            "{family}: the families are {}",
            source::FAMILIES.join(", ")
        ));
    }
    let mut options = Options {
        mode: mode.clone(),
        family: family.clone(),
        root: Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .canonicalize()
            .map_err(|error| format!("the repository root: {error}"))?,
        export: None,
        run: None,
        status: false,
    };
    let mut rest = rest.iter();
    while let Some(flag) = rest.next() {
        let mut value = || {
            rest.next()
                .map(PathBuf::from)
                .ok_or(format!("{flag} needs a value"))
        };
        match flag.as_str() {
            "--root" => options.root = value()?,
            "--export" => options.export = Some(value()?),
            "--run" => options.run = Some(value()?),
            "--status" => options.status = true,
            _ => return Err(format!("{flag}: unknown\n{USAGE}")),
        }
    }
    Ok(options)
}

/// `register_path` returns `ROOT/verification/reach/FAMILY.json` once
/// `verification` and `verification/reach` are directories and the register
/// is a regular file or absent, none of them a symbolic link, so every read
/// and write of the register stays beneath `root`. The check precedes the
/// reads and the rename; a link that another process of the same user puts
/// in place between them is followed.
fn register_path(root: &Path, family: &str) -> Result<PathBuf, String> {
    let mut path = root.to_path_buf();
    for directory in ["verification", "reach"] {
        path.push(directory);
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        if !metadata.is_dir() {
            return Err(format!(
                "{}: a symbolic link or no directory; the register stays beneath --root",
                path.display()
            ));
        }
    }
    path.push(format!("{family}.json"));
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) if !metadata.is_file() => Err(format!(
            "{}: a symbolic link or no regular file; the register stays beneath --root",
            path.display()
        )),
        Ok(_) => Ok(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(path),
        Err(error) => Err(format!("{}: {error}", path.display())),
    }
}

fn read_file(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))
}

fn run(arguments: &[String]) -> Result<String, String> {
    let options = options(arguments)?;
    let crate_root = options.root.join("crates/kestrike/src");
    let path = register_path(&options.root, &options.family)?;
    let family = options.family.as_str();
    if options.mode == "sync" && options.status {
        return Ok(modes::status(&register::Register::read(&read_file(
            &path,
        )?)?));
    }
    let read = |rel: &str| match std::fs::read_to_string(crate_root.join(rel)) {
        Ok(text) => Ok(Some(text)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("{rel}: {error}")),
    };
    let parsed = source::parse(&read)?;
    if options.mode != "sites" && !parsed.ambiguous.is_empty() {
        return Err(format!(
            "these paths name a variant of two or more enums; qualify them and run again:\n{}",
            parsed.ambiguous.join("\n")
        ));
    }
    let export = || -> Result<coverage::Coverage, String> {
        let export = options.export.as_deref().ok_or("--export is required")?;
        coverage::Coverage::read(&read_file(export)?)
    };
    match options.mode.as_str() {
        "sites" => Ok(sites(&parsed, family)),
        "measure" => {
            let run = options.run.as_deref().ok_or("--run is required")?;
            let mut run: register::Run =
                serde_json::from_str(&read_file(run)?).map_err(|error| format!("run: {error}"))?;
            run.tool = digest();
            let earlier = match std::fs::read_to_string(&path) {
                Ok(text) => Some(register::Register::read(&text)?),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => return Err(format!("{}: {error}", path.display())),
            };
            let measured = modes::measure(&parsed, &export()?, family, earlier.as_ref(), run)?;
            write(&path, &measured.render())?;
            let totals = &measured.totals;
            Ok(format!(
                "{}: {} rows, {} reached, {} unreached, {} unplaced\n",
                path.display(),
                totals.rows,
                totals.reached,
                totals.unreached,
                totals.unplaced
            ))
        }
        "sync" => {
            let earlier = register::Register::read(&read_file(&path)?)?;
            let synced = modes::sync(&parsed, family, &earlier);
            write(&path, &synced.register.render())?;
            let mut out = format!(
                "{}: {} added, {} removed\n",
                path.display(),
                synced.added.len(),
                synced.removed.len()
            );
            for name in &synced.added {
                out.push_str(&format!("added {name}\n"));
            }
            for name in &synced.removed {
                out.push_str(&format!("removed {name}\n"));
            }
            Ok(out)
        }
        "compare" => {
            let earlier = register::Register::read(&read_file(&path)?)?;
            let measured = modes::measure(
                &parsed,
                &export()?,
                family,
                Some(&earlier),
                earlier.run.clone(),
            )?;
            Ok(modes::compare(&earlier, &measured))
        }
        _ => Err(USAGE.to_owned()),
    }
}

fn write(path: &Path, text: &str) -> Result<(), String> {
    publish(path, text, std::io::Write::write_all)
}

/// `publish` writes `text` to a new file beside `path` with `fill`, then
/// renames it over `path`. On an error before the rename, `publish` leaves
/// `path` as it was and attempts to remove the file it created.
fn publish(
    path: &Path,
    text: &str,
    fill: impl FnOnce(&mut std::fs::File, &[u8]) -> std::io::Result<()>,
) -> Result<(), String> {
    let fail = |error: std::io::Error| format!("{}: {error}", path.display());
    let mut staged = path.as_os_str().to_owned();
    staged.push(format!(".{}.partial", std::process::id()));
    let staged = PathBuf::from(staged);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staged)
        .map_err(fail)?;
    let filled = fill(&mut file, text.as_bytes()).and_then(|()| file.sync_all());
    drop(file);
    match filled.and_then(|()| std::fs::rename(&staged, path)) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = std::fs::remove_file(&staged);
            Err(fail(error))
        }
    }
}

fn sites(parsed: &source::Source, family: &str) -> String {
    let mut out = String::new();
    for owner in parsed.listed(family) {
        let declared = &parsed.enums[owner];
        out.push_str(&format!("{} ({})\n", declared.path, declared.file));
        for variant in &declared.variants {
            out.push_str(&format!("  {}\n", variant.name));
            for site in parsed.sites_of(owner, &variant.name) {
                out.push_str(&format!(
                    "    {}:{}:{} {} {}\n",
                    site.file,
                    site.at.0,
                    site.at.1,
                    site.function,
                    site.form.name()
                ));
            }
        }
    }
    for path in &parsed.ambiguous {
        out.push_str(&format!("ambiguous {path}\n"));
    }
    out
}
