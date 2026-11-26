//! Publishing a built executable into a new archive.
//!
//! [`publish`] refuses an output that exists or that the loader's search
//! path cannot carry, reads the program interpreter the executable
//! requests and the libraries the interpreter resolves for it, all before
//! it writes anything. It then creates the output directory, opens a store
//! over it, and copies the executable, the lockfile and each library in
//! through create-once. The build record is created last, so a build
//! record exists only beside every file it names: a publication
//! interrupted before the record's rename leaves no record, and
//! [`Archive::load`] refuses the archive; one interrupted after it leaves
//! a complete archive. The store's own `.state` marker and `.staging`
//! directory sit beside the archive's entries. A source whose identity
//! changes between the build and the end of its copy, or that vanishes,
//! makes the publication incomplete, since its digest may describe
//! neither version. The published archive is verified in full before
//! `publish` returns.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

use super::{Archive, Error, Invalid, LIBRARIES, LOCK, RECORD, WORKER, elf, host, loader, name};
use crate::record::{Build, Digest, Hashing, Loader, Provenance, Text};
use crate::store::{self, Creation, Dir, Identity, Name, Opened, Store, create_dir, remove_dir};
use crate::sys;

/// The executable's permission bits: owner read and execute.
const EXECUTABLE_MODE: u32 = 0o500;
/// A library's or the lockfile's permission bits: owner read.
const DATA_MODE: u32 = 0o400;

/// A built executable to archive, with the exact lockfile bytes its build
/// resolved from and its provenance.
#[derive(Debug)]
pub struct Built {
    /// The host path of the built executable.
    pub executable: PathBuf,
    /// The built executable's identity when the build reported it; a
    /// publication of another version of the file is incomplete.
    pub identity: Identity,
    pub lock: Vec<u8>,
    pub provenance: Provenance,
}

/// Builds the worker with `cargo` and publishes it as the new archive
/// `output`, refusing an output that exists, that the loader's search
/// path cannot represent, or whose ancestor another user could replace
/// before the build starts. The caller gives this function ownership of
/// the process's SIGCHLD disposition, as the [module doc](super#sigchld)
/// states.
///
/// # Errors
///
/// As [`build`] and [`publish`].
pub fn archive(cargo: &Path, output: &Path) -> Result<Archive, Error> {
    super::vacant(output)?;
    let context = super::command::Context::open()?;
    let built = context.finish(super::build::build_archiving(
        cargo,
        std::env::vars_os().collect(),
        &context,
    ))?;
    let search = std::env::var_os("LD_LIBRARY_PATH");
    publish_scoped(output, &built, search.as_deref(), Some(&context))
}

/// Publishes `built` as the new archive `output` and verifies it. The
/// caller gives this function ownership of the process's SIGCHLD
/// disposition, as the [module doc](super#sigchld) states.
///
/// # Errors
///
/// - [`Error::Invalid`] for output-path, executable or library-policy refusals before writes, and for a refused output directory, which is removed.
/// - [`Error::Store`] for a store that fails to open for a reason other than a refusal, [`store::Error::Busy`] included, or fails after it opened, write failures included; the output directory stays in place.
/// - [`Error::Incomplete`] for failed source/interpreter reads or loader invocation, changed sources, failed output creation/removal, library-directory lookup, an existing entry during create-once, or failed closing verification.
pub fn publish(output: &Path, built: &Built) -> Result<Archive, Error> {
    let search = std::env::var_os("LD_LIBRARY_PATH");
    publish_with(output, built, search.as_deref())
}

pub(super) fn publish_with(
    output: &Path,
    built: &Built,
    search: Option<&std::ffi::OsStr>,
) -> Result<Archive, Error> {
    publish_scoped(output, built, search, None)
}

fn checkpoint(context: Option<&super::command::Context>) -> Result<(), Error> {
    if let Some(context) = context {
        context.check()?;
    }
    Ok(())
}

fn publish_scoped(
    output: &Path,
    built: &Built,
    search: Option<&std::ffi::OsStr>,
    context: Option<&super::command::Context>,
) -> Result<Archive, Error> {
    checkpoint(context)?;
    let output = super::vacant(output)?;
    let vanished =
        |path: &Path, why| Error::Incomplete(format!("{} is unreadable: {why}", path.display()));
    let executable =
        store::open_host(&built.executable).map_err(|why| vanished(&built.executable, why))?;
    if executable.identity() != built.identity {
        return Err(Error::Incomplete(format!(
            "{} changed after its build",
            built.executable.display()
        )));
    }
    let requested = elf::interpreter(&executable).map_err(|invalid| match invalid {
        Invalid::Io(error) => Error::Incomplete(format!(
            "{} failed its read: {error}",
            built.executable.display()
        )),
        invalid => invalid.into(),
    })?;
    let loader = match requested {
        None => None,
        Some(path) => {
            let refused =
                || Invalid::Elf(format!("the interpreter {path:?} is no printable ASCII"));
            let text = Text::new(&path).ok_or_else(refused)?;
            let sha256 = Digest::read(host(Path::new(&path))?).map_err(|error| {
                Error::Incomplete(format!("the interpreter {path} failed its read: {error}"))
            })?;
            Some(Loader { path: text, sha256 })
        }
    };
    let mut libraries = BTreeMap::new();
    if let Some(loader) = &loader {
        let resolved =
            loader::resolve_publishing(loader.path.as_str(), &built.executable, search, context);
        checkpoint(context)?;
        let found = resolved.map_err(|invalid| match invalid {
            Invalid::Io(error) => Error::Incomplete(format!("the loader listing failed: {error}")),
            invalid => Error::Invalid(invalid),
        })?;
        for (library, path) in found {
            checkpoint(context)?;
            let refused = || Invalid::Resolution(format!("{library} is no archive file name"));
            let name = Name::new(&library).ok_or_else(refused)?;
            let path = PathBuf::from(path);
            let source = store::open_host(&path).map_err(|why| vanished(&path, why))?;
            elf::library(&source).map_err(|invalid| match invalid {
                Invalid::Io(error) => {
                    Error::Incomplete(format!("{} failed its read: {error}", path.display()))
                }
                invalid => Error::Invalid(invalid),
            })?;
            libraries.insert(name, (path, source));
        }
    }
    let machine = sys::machine().map_err(Invalid::Io)?;
    let machine = Text::new(&machine).ok_or_else(|| {
        let why = format!("the host's machine name {machine:?} is no printable ASCII");
        Invalid::Io(io::Error::other(why))
    })?;
    checkpoint(context)?;
    match create_dir(&output) {
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Err(Invalid::Exists)?,
        made => made.map_err(|error| {
            Error::Incomplete(format!(
                "creating output {} failed: {error}",
                output.display()
            ))
        })?,
    }
    // A refusal precedes the store's first write, so the new directory is
    // still empty and is removed; any other failure leaves it in place.
    let store = match Store::open(&output) {
        Err(refused @ store::Error::Refused(_)) => {
            remove_dir(&output).map_err(|error| {
                Error::Incomplete(format!(
                    "the output was refused ({refused}); its removal failed: {error}"
                ))
            })?;
            return Err(Invalid::store(refused).into());
        }
        opened => opened?,
    };
    let root = store.root();
    checkpoint(context)?;
    let executable = copy(
        &store,
        root,
        &name(WORKER),
        &built.executable,
        executable,
        EXECUTABLE_MODE,
    )?;
    checkpoint(context)?;
    let lock = &mut &built.lock[..];
    created(store.copy_once(root, &name(LOCK), lock, DATA_MODE)?)?;
    checkpoint(context)?;
    created(store.mkdir(root, &name(LIBRARIES))?)?;
    let directory = store
        .open_dir(root, &name(LIBRARIES))
        .map_err(|why| Error::Incomplete(format!("the library directory: {why}")))?
        .ok_or_else(|| Error::Incomplete("the library directory vanished".to_owned()))?;
    let mut digests = BTreeMap::new();
    for (library, (path, source)) in libraries {
        checkpoint(context)?;
        let digest = copy(&store, &directory, &library, &path, source, DATA_MODE)?;
        let text = Text::new(library.as_str()).expect("a name is printable ASCII");
        digests.insert(text, digest);
    }
    let build = Build {
        executable,
        libraries: digests,
        loader,
        lock: Digest::of(&built.lock),
        machine,
        provenance: built.provenance.clone(),
    };
    checkpoint(context)?;
    let mut permission = Ok(());
    let publication = store.create_record_if(root, &name(RECORD), &build, || {
        permission = checkpoint(context);
        permission.is_ok()
    })?;
    permission?;
    created(publication.expect("a permitted publication returns its creation"))?;
    drop(store);
    let incomplete =
        |invalid: Invalid| Error::Incomplete(format!("the published archive: {invalid}"));
    let mut archive = Archive::load(&output).map_err(incomplete)?;
    // The verification is the command's check after its writes; the
    // command runs nothing from the archive, so no use follows it.
    archive.verify().map(drop).map_err(incomplete)?;
    Ok(archive)
}

/// Copies `source`, opened from host path `path`, to `target` in `dir`,
/// returning the digest of the bytes written.
fn copy(
    store: &Store,
    dir: &Dir,
    target: &Name,
    path: &Path,
    source: Opened,
    mode: u32,
) -> Result<Digest, Error> {
    let before = source.identity();
    let mut hashing = Hashing::new(source);
    created(store.copy_once(dir, target, &mut hashing, mode)?)?;
    let after = store::open_host(path).map_err(|why| {
        Error::Incomplete(format!(
            "{} is unreadable after its copy: {why}",
            path.display()
        ))
    })?;
    if after.identity() != before {
        return Err(Error::Incomplete(format!(
            "{} changed while it was copied",
            path.display()
        )));
    }
    Ok(hashing.finish())
}

/// A create in the new archive directory, which this command alone writes,
/// finds no entry of its name.
fn created(creation: Creation) -> Result<(), Error> {
    match creation {
        Creation::Created => Ok(()),
        Creation::Existing => Err(Error::Incomplete("an archive entry existed".to_owned())),
    }
}
