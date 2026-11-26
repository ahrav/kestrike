//! Provenance of the write-combining VFIO modules the ENA's low-latency
//! queues need, checked in full before any device binds, with the loaded
//! modules' identity checked again before each driver move, and the live
//! write-combining mapping of the ENA's prefetchable BAR once `vfio-pci`
//! holds the ENA and the poll-mode driver has probed it.
//!
//! An approved manifest names the kernel release, the SHA-256 of its build
//! configuration, the patch revision, and each approved module: its name,
//! its uncompressed file, the file's SHA-256 and the `srcversion` the file
//! declares. The running kernel must be that release with that
//! configuration recorded in `/boot`. With `CONFIG_IOMMUFD` and
//! `CONFIG_VFIO_DEVICE_CDEV` unset there, VFIO exposes the classic group
//! and container interface. The kernel's `drivers/vfio/Kconfig` selects
//! `VFIO_CONTAINER` (Linux 6.2 and later) and `VFIO_GROUP` (6.6 and later)
//! when `IOMMUFD=n`; an earlier kernel builds the classic interface as its
//! only one. The configuration also builds the backend the host's VFIO
//! mode uses: Type1 with a guest IOMMU, no-IOMMU without one. `vfio_pci`
//! must be approved and loaded; every loaded VFIO module that maps BARs for
//! user space must be approved; and each approved module's file must hash
//! to its digest and declare the `srcversion` the loaded module reports.
//! The declared `srcversion` is the first `srcversion=` entry in the file's
//! bytes, which the digest pins. The tool only reads module state.
//!
//! On x86_64 a matching identity proves the modules, not the mapping: PAT
//! can demote a requested write-combining mapping, so only the kernel's PAT
//! table shows that the BAR `vfio-pci` maps is write-combining. On aarch64
//! the guest's stage-1 mapping takes exactly the memory type
//! `vfio_pci_core`'s mmap requests, so the approved modules loaded with
//! their approved `srcversion` are the evidence: their mmap maps an ENA's
//! prefetchable BAR write-combining.

use std::fs;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use sha2::{Digest, Sha256};

use super::host::Host;

/// The VFIO modules on the path that maps a device's BARs for user space.
const VFIO_MODULES: [&str; 3] = ["vfio", "vfio_pci_core", "vfio_pci"];
const VFIO_UNSET: [&str; 2] = ["CONFIG_IOMMUFD", "CONFIG_VFIO_DEVICE_CDEV"];
/// The backend each VFIO mode needs: Type1, built in or as a module, with a
/// guest IOMMU; no-IOMMU, built in, without one.
const TYPE1: &str = "CONFIG_VFIO_IOMMU_TYPE1";
const NOIOMMU: &str = "CONFIG_VFIO_NOIOMMU";
/// `IORESOURCE_MEM` and `IORESOURCE_PREFETCH` of a sysfs `resource` line's flags.
const MEMORY: u64 = 0x200;
const PREFETCH: u64 = 0x2000;
/// The base address registers of a PCI function, which are the first lines
/// of its sysfs `resource` file. The expansion ROM, the virtual-function BARs
/// and the bridge windows follow them, and `vfio-pci` maps none of those for
/// user space.
const BARS: usize = 6;

/// One approved module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WcModule {
    pub name: String,
    pub file: PathBuf,
    pub sha256: String,
    pub srcversion: String,
}

/// The approved write-combining kernel and modules; the mappings file records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WcManifest {
    pub kernel: String,
    pub config_sha256: String,
    pub patch: String,
    pub modules: Vec<WcModule>,
}

/// Why the modules or mapping were refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WcError {
    /// The manifest is unreadable, a symbolic link, owned by a user other than root or writable by its group or other users, or a field is missing, repeated, unknown, empty or malformed.
    Manifest(&'static str),
    /// The running kernel's release or configuration digest differs.
    Kernel,
    /// The configuration assigns `CONFIG_IOMMUFD` or
    /// `CONFIG_VFIO_DEVICE_CDEV`, or omits the backend this host's VFIO mode
    /// uses; `iommu` when the IOMMU class that selects the mode is
    /// unreadable.
    Interface(&'static str),
    /// This module's file is unreadable, its digest differs, or it declares no `srcversion` or another one.
    Module(String),
    /// The manifest omits `vfio_pci`, or this VFIO module is loaded unapproved, or approved and not loaded with its `srcversion`.
    Loaded(String),
    /// No prefetchable memory BAR, or the PAT table shows no write-combining mapping covering it.
    Mapping,
    /// The PAT table is unreadable, the architecture offers no evidence of a mapping's memory type, or the device is not on `vfio-pci`.
    Unverifiable,
}

/// What shows the memory type of a user mapping of a device BAR on an architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MappingEvidence {
    /// x86_64: the kernel's PAT table lists each mapped range's memory type, and PAT can demote a requested
    /// write-combining mapping when another mapping of the range conflicts, so only the table proves it.
    PatTable,
    /// aarch64: the guest's stage-1 mapping takes exactly the memory type `vfio_pci_core`'s mmap requests,
    /// and the loaded module's identity shows what it requests. The hypervisor's stage-2 attributes lie
    /// outside the guest's view.
    LoadedModule,
    /// Every other architecture: the check stays unverifiable.
    Unavailable,
}

impl MappingEvidence {
    /// This build's architecture.
    pub(crate) const HOST: Self = if cfg!(target_arch = "x86_64") {
        Self::PatTable
    } else if cfg!(target_arch = "aarch64") {
        Self::LoadedModule
    } else {
        Self::Unavailable
    };
}

/// A module's name as sysfs lists it under `module`: nonempty, of ASCII alphanumerics and `_`. Such
/// a name is one path component, so the directory the loaded check reads for it lies in
/// `sys/module` and each loaded module has one spelling.
fn module_name(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

impl WcModule {
    /// `name:file:sha256:srcversion`, the manifest's and the mappings file's form, with the name a
    /// module name as sysfs lists one and the file absolute.
    pub(crate) fn parse(text: &str) -> Option<Self> {
        let mut parts = text.split(':');
        let module = Self {
            name: parts.next()?.to_owned(),
            file: PathBuf::from(parts.next()?),
            sha256: parts.next()?.to_owned(),
            srcversion: parts.next()?.to_owned(),
        };
        let filled = [&module.sha256, &module.srcversion]
            .iter()
            .all(|f| !f.is_empty());
        let formed = module_name(&module.name) && module.file.is_absolute();
        (parts.next().is_none() && filled && formed).then_some(module)
    }

    pub(crate) fn format(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            self.name,
            self.file.display(),
            self.sha256,
            self.srcversion
        )
    }
}

impl WcManifest {
    /// Parses a manifest: one `key=value` line each for `kernel`,
    /// `config_sha256` and `patch`, and one `module=` line per approved module.
    ///
    /// # Errors
    ///
    /// `Manifest` naming the first missing, repeated, unknown, empty or malformed field.
    pub fn parse(text: &str) -> Result<Self, WcError> {
        let (mut kernel, mut config, mut patch, mut modules) = (None, None, None, Vec::new());
        for line in text.lines().filter(|line| !line.trim().is_empty()) {
            let (key, value) = line.split_once('=').ok_or(WcError::Manifest("line"))?;
            let (slot, name) = match key {
                "kernel" => (&mut kernel, "kernel"),
                "config_sha256" => (&mut config, "config_sha256"),
                "patch" => (&mut patch, "patch"),
                "module" => {
                    let module = WcModule::parse(value)
                        .filter(|_| !value.contains('='))
                        .ok_or(WcError::Manifest("module"))?;
                    if modules.iter().any(|m: &WcModule| m.name == module.name) {
                        return Err(WcError::Manifest("module"));
                    }
                    modules.push(module);
                    continue;
                }
                _ => return Err(WcError::Manifest("key")),
            };
            // The mappings file records each value after one `=`, so a value holds none.
            if value.is_empty() || value.contains('=') || slot.replace(value.to_owned()).is_some() {
                return Err(WcError::Manifest(name));
            }
        }
        Ok(Self {
            kernel: kernel.ok_or(WcError::Manifest("kernel"))?,
            config_sha256: config.ok_or(WcError::Manifest("config_sha256"))?,
            patch: patch.ok_or(WcError::Manifest("patch"))?,
            modules,
        })
    }

    /// Reads and parses the manifest at `path` through one descriptor opened
    /// with `O_NOFOLLOW`, so the bytes parsed are the bytes of the file whose
    /// owner and mode were checked.
    ///
    /// # Errors
    ///
    /// `Manifest` naming `file` for a final-component symbolic link or a
    /// failed open, `fstat` or read, `mode` for group or other write
    /// permission, `owner` for an owner other than root, else as
    /// [`parse`](Self::parse).
    pub fn read(path: &Path) -> Result<Self, WcError> {
        let mut file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|_| WcError::Manifest("file"))?;
        let meta = file.metadata().map_err(|_| WcError::Manifest("file"))?;
        if meta.mode() & 0o022 != 0 {
            return Err(WcError::Manifest("mode"));
        }
        if meta.uid() != 0 {
            return Err(WcError::Manifest("owner"));
        }
        let mut text = String::new();
        file.read_to_string(&mut text)
            .map_err(|_| WcError::Manifest("file"))?;
        Self::parse(&text)
    }
}

/// The hex SHA-256 of `bytes`.
#[cfg(test)]
pub(crate) fn sha256(bytes: &[u8]) -> String {
    hex(Sha256::digest(bytes))
}

/// The values a kernel configuration's last `symbol=` lines assign to
/// `symbols`, scanned from the configuration's bytes fed in file order. A
/// symbol that is absent, or only in a `# symbol is not set` line, has the
/// value `None`. Each symbol must be a one-line name that `assign` can
/// match against the bytes before a line's first `=`.
///
/// Symbols that share their name through its second `_`, such as
/// `CONFIG_VFIO_GROUP` and `CONFIG_VFIO_NOIOMMU`, share one search of each
/// piece fed. The state holds the current partial line and the values found,
/// so its size follows the longest line, independent of the configuration's
/// length.
struct Settings<const N: usize> {
    symbols: [&'static str; N],
    /// A finder of `\n` followed by each distinct family: a symbol through
    /// its second `_`, or the whole symbol when it has fewer.
    families: Vec<memchr::memmem::Finder<'static>>,
    /// The bytes fed since the last newline, the line the next newline
    /// completes; the file's first line starts here.
    line: Vec<u8>,
    /// Each symbol's last assigned value, in `symbols` order.
    values: [Option<Vec<u8>>; N],
}

impl<const N: usize> Settings<N> {
    fn new(symbols: [&'static str; N]) -> Self {
        let mut families: Vec<&str> = symbols
            .iter()
            .map(|symbol| {
                symbol
                    .match_indices('_')
                    .nth(1)
                    .map_or(*symbol, |(at, _)| &symbol[..=at])
            })
            .collect();
        families.sort_unstable();
        families.dedup();
        let families = families
            .into_iter()
            .map(|family| {
                memchr::memmem::Finder::new(&[b"\n", family.as_bytes()].concat()).into_owned()
            })
            .collect();
        Self {
            symbols,
            families,
            line: Vec::new(),
            values: [const { None }; N],
        }
    }

    /// Scans the next bytes in file order.
    fn feed(&mut self, bytes: &[u8]) {
        let (Some(first), Some(last)) =
            (memchr::memchr(b'\n', bytes), memchr::memrchr(b'\n', bytes))
        else {
            self.line.extend_from_slice(bytes);
            return;
        };
        self.line.extend_from_slice(&bytes[..first]);
        // The carried line precedes every line of `whole`, so it is assigned
        // first and a later assignment in `whole` overwrites it.
        Self::assign(&self.symbols, &mut self.values, &self.line);
        // `whole` holds the lines `bytes` completes after its first newline,
        // each preceded by its newline. Each finder's pattern is `\n` and a
        // single-line family, so its matches are disjoint: the search visits
        // every whole line that starts with the family, in file order, and a
        // symbol of that family ends at its last assignment.
        let whole = &bytes[first..last];
        for family in &self.families {
            for at in family.find_iter(whole) {
                let rest = &whole[at + 1..];
                Self::assign(
                    &self.symbols,
                    &mut self.values,
                    &rest[..memchr::memchr(b'\n', rest).unwrap_or(rest.len())],
                );
            }
        }
        self.line.clear();
        self.line.extend_from_slice(&bytes[last + 1..]);
    }

    /// Scans the carried last line, which may lack a trailing newline, and
    /// returns each symbol's value in `symbols` order.
    fn finish(mut self) -> [Option<Vec<u8>>; N] {
        Self::assign(&self.symbols, &mut self.values, &self.line);
        self.values
    }

    /// Sets the value of each of `symbols` that `line` names before its first
    /// `=` to the bytes after it, overwriting an earlier value.
    fn assign(symbols: &[&str; N], values: &mut [Option<Vec<u8>>; N], line: &[u8]) {
        let Some(equals) = memchr::memchr(b'=', line) else {
            return;
        };
        let (name, value) = (&line[..equals], &line[equals + 1..]);
        for (slot, symbol) in values.iter_mut().zip(symbols) {
            if symbol.as_bytes() == name {
                *slot = Some(value.to_vec());
            }
        }
    }
}

/// `hex` renders `digest` as lowercase hex, two characters per byte.
pub(super) fn hex(digest: impl IntoIterator<Item = u8>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(64);
    for byte in digest {
        hex.push(char::from(HEX[usize::from(byte >> 4)]));
        hex.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    hex
}

/// The threads that hash module files while the calling thread checks the
/// kernel configuration and the loaded modules; threads claim module files
/// largest first.
const HELPERS: usize = 2;

/// The key of the `.modinfo` entry that declares a module's `srcversion`.
const SRCVERSION_KEY: &[u8] = b"srcversion=";

/// Whether the first `srcversion=` entry in bytes fed in file order has the
/// value `expected`, up to its NUL: whether an uncompressed module's
/// `.modinfo` declares that `srcversion`. The state holds at most
/// 2 * (`SRCVERSION_KEY.len()` - 1) bytes whatever the file holds.
pub(super) struct Declares<'a> {
    expected: &'a [u8],
    scan: Scan,
}

enum Scan {
    /// The key is unfound. The last bytes fed, at most one fewer than the
    /// key's length, carry over so a key split across chunks is found.
    Seeking(Vec<u8>),
    /// The key is found and this many value bytes equal a prefix of `expected`.
    Matching(usize),
    /// The value ended at its NUL or at a byte that differs from `expected`.
    Done(bool),
}

impl<'a> Declares<'a> {
    pub(super) fn new(expected: &'a str) -> Self {
        Self {
            expected: expected.as_bytes(),
            scan: Scan::Seeking(Vec::new()),
        }
    }

    /// Scans the next bytes in file order.
    pub(super) fn feed(&mut self, bytes: &[u8]) {
        let (matched, rest) = match &mut self.scan {
            Scan::Done(_) => return,
            Scan::Matching(matched) => (*matched, bytes),
            Scan::Seeking(tail) => {
                let keep = SRCVERSION_KEY.len() - 1;
                let split = tail.len();
                tail.extend_from_slice(&bytes[..bytes.len().min(keep)]);
                // `tail` holds fewer bytes than the key from each side, so a match in
                // it straddles the chunks and starts before any key wholly inside `bytes`.
                let start = memchr::memmem::find(tail, SRCVERSION_KEY)
                    .map(|at| at + SRCVERSION_KEY.len() - split)
                    .or_else(|| {
                        memchr::memmem::find(bytes, SRCVERSION_KEY)
                            .map(|at| at + SRCVERSION_KEY.len())
                    });
                let Some(start) = start else {
                    if bytes.len() >= keep {
                        tail.clear();
                        tail.extend_from_slice(&bytes[bytes.len() - keep..]);
                    } else {
                        tail.drain(..tail.len().saturating_sub(keep));
                    }
                    return;
                };
                (0, &bytes[start..])
            }
        };
        let end = memchr::memchr(0, rest);
        let value = &rest[..end.unwrap_or(rest.len())];
        self.scan = if !self.expected[matched..].starts_with(value) {
            Scan::Done(false)
        } else if end.is_some() {
            Scan::Done(matched + value.len() == self.expected.len())
        } else {
            Scan::Matching(matched + value.len())
        };
    }

    /// Whether the value ended at its NUL equal to `expected`.
    pub(super) fn declared(&self) -> bool {
        matches!(self.scan, Scan::Done(true))
    }
}

impl Host {
    /// Checks the running kernel and every VFIO module against `manifest`.
    /// Up to two scoped helper threads hash module files, largest first,
    /// while this thread checks the kernel and the loaded modules and then
    /// takes the files still unclaimed, or stops the queue if either check
    /// refuses. This thread reads every result after all threads return.
    ///
    /// # Errors
    ///
    /// In this order: `Kernel`, then `Interface`, then `Loaded` for the
    /// first loaded-state failure, then `Module` for the first file in
    /// manifest order that fails.
    pub fn check_wc(&self, manifest: &WcManifest) -> Result<(), WcError> {
        let matches: Vec<OnceLock<bool>> =
            manifest.modules.iter().map(|_| OnceLock::new()).collect();
        let mut jobs: Vec<_> = manifest
            .modules
            .iter()
            .enumerate()
            .map(|(index, module)| {
                let path = self.under_root(&module.file);
                (fs::metadata(&path).map_or(0, |meta| meta.len()), index)
            })
            .collect();
        // File size estimates hashing cost, so the largest files are taken
        // first. A file with unreadable metadata counts as empty.
        jobs.sort_unstable_by_key(|job| std::cmp::Reverse(job.0));
        let next = AtomicUsize::new(0);
        // `fetch_add` hands each job to one thread. The slots and the scope's
        // end publish the results, so the counter needs only `Relaxed`.
        let work = || {
            while let Some(&(_, index)) = jobs.get(next.fetch_add(1, Ordering::Relaxed)) {
                let module = &manifest.modules[index];
                let _ = matches[index].set(self.check_wc_module(module).is_ok());
            }
        };
        let checked = std::thread::scope(|scope| {
            for _ in 0..HELPERS.min(jobs.len()) {
                // `thread::scope` returns once every spawned closure returns,
                // so each handle drops unjoined. A failed spawn leaves its
                // jobs to the threads that run `work()`.
                let _ = std::thread::Builder::new().spawn_scoped(scope, work);
            }
            let checked = self.check_wc_running(manifest);
            if checked.is_err() {
                // A refusal empties the queue, so each helper stops after its current file.
                next.store(jobs.len(), Ordering::Relaxed);
            }
            work();
            checked
        });
        checked?;
        // Results are read in manifest order after the kernel and loaded
        // checks, so the error order holds whichever thread finishes first.
        match (0..manifest.modules.len()).find(|&index| matches[index].get() != Some(&true)) {
            Some(index) => Err(WcError::Module(manifest.modules[index].name.clone())),
            None => Ok(()),
        }
    }

    /// Checks the running kernel's release and the digest of its `/boot`
    /// configuration file against `manifest`, then the VFIO interface and
    /// backend. One read feeds each chunk to both the digest and the parse,
    /// so the settings checked come from the bytes the digest covers.
    ///
    /// # Errors
    ///
    /// - `Kernel`: the release is unreadable or differs from the manifest's,
    ///   a mount of the mount table [covers](Self::procfs_covered) the
    ///   release, which then prints the mount's text, or the mount table is
    ///   unreadable, or the configuration file is unreadable or its digest
    ///   differs.
    /// - `Interface` with the symbol: the configuration assigns
    ///   `CONFIG_IOMMUFD` or `CONFIG_VFIO_DEVICE_CDEV`.
    /// - `Interface("iommu")`: the IOMMU class that selects the mode is
    ///   unreadable.
    /// - `Interface` with the backend symbol: a guest IOMMU requires
    ///   `CONFIG_VFIO_IOMMU_TYPE1` built in or as a module; operation
    ///   without a guest IOMMU requires `CONFIG_VFIO_NOIOMMU` built in.
    fn check_wc_kernel(&self, manifest: &WcManifest) -> Result<(), WcError> {
        let printed = self.proc.join("sys/kernel/osrelease");
        let release = self.kernel_text(&printed).ok_or(WcError::Kernel)?;
        if release != manifest.kernel {
            return Err(WcError::Kernel);
        }
        let [iommufd, cdev] = VFIO_UNSET;
        let mut settings = Settings::new([iommufd, cdev, TYPE1, NOIOMMU]);
        let mut hasher = Sha256::new();
        let path = self.under_root(Path::new(&format!("/boot/config-{release}")));
        let read = Host::stream(&path, |chunk| {
            hasher.update(chunk);
            settings.feed(chunk);
        });
        if read.is_none() || hex(hasher.finalize()) != manifest.config_sha256 {
            return Err(WcError::Kernel);
        }
        let [iommufd, cdev, type1, noiommu] = settings.finish();
        if let Some((symbol, _)) = VFIO_UNSET
            .into_iter()
            .zip([iommufd, cdev])
            .find(|(_, value)| value.is_some())
        {
            return Err(WcError::Interface(symbol));
        }
        let (backend, value, module) = match self.guest_iommu() {
            Some(true) => (TYPE1, type1, true),
            Some(false) => (NOIOMMU, noiommu, false),
            None => return Err(WcError::Interface("iommu")),
        };
        match value.as_deref() {
            Some(b"y") => Ok(()),
            Some(b"m") if module => Ok(()),
            _ => Err(WcError::Interface(backend)),
        }
    }

    /// Checks the running kernel, its configuration's VFIO interface and
    /// backend, and the loaded VFIO modules against `manifest`, the state a
    /// release runs on; the module files themselves are checked at bind.
    ///
    /// # Errors
    ///
    /// In this order: `Kernel`, then `Interface`, then `Loaded` for the
    /// first loaded-state failure.
    pub fn check_wc_running(&self, manifest: &WcManifest) -> Result<(), WcError> {
        self.check_wc_kernel(manifest)?;
        self.check_wc_loaded(manifest)
    }

    /// Checks `module`'s file against its approved digest and `srcversion`.
    ///
    /// # Errors
    ///
    /// `Module` naming `module` for an unreadable file, a digest that differs,
    /// a file with no `srcversion=` entry, or a first entry whose value differs
    /// from `module`'s or reaches the file's end before its NUL.
    fn check_wc_module(&self, module: &WcModule) -> Result<(), WcError> {
        let (mut hasher, mut declares) = (Sha256::new(), Declares::new(&module.srcversion));
        let read = Host::stream(&self.under_root(&module.file), |chunk| {
            hasher.update(chunk);
            declares.feed(chunk);
        });
        if read.is_some() && hex(hasher.finalize()) == module.sha256 && declares.declared() {
            Ok(())
        } else {
            Err(WcError::Module(module.name.clone()))
        }
    }

    /// Checks that `vfio_pci` is approved, every loaded VFIO module that
    /// maps BARs is approved, and every approved module is loaded reporting
    /// its approved `srcversion`; the bind repeats this immediately before
    /// each driver move, and release runs it through
    /// [`check_wc_running`](Self::check_wc_running).
    ///
    /// # Errors
    ///
    /// `Loaded` naming the first module that fails. An unapproved VFIO
    /// module whose `initstate` cannot be observed, for any cause but its
    /// absence, fails as a loaded one; so does one whose `initstate` is
    /// missing under a mount of another type the mount table lists over it,
    /// or missing while the mount table cannot be read. An approved module
    /// whose `srcversion` a mount [covers](Self::sysfs_covered), or is read
    /// beside an unreadable mount table, fails as one that reports no
    /// `srcversion`.
    pub fn check_wc_loaded(&self, manifest: &WcManifest) -> Result<(), WcError> {
        let module = |name: &str| self.sys.join("module").join(name);
        let mounts = self.mount_table().ok();
        // `initstate` exists for every loaded module, including one with no `srcversion` attribute, so it judges the unapproved VFIO modules.
        // Only its observed absence shows a module unloaded: a stat that fails any other way leaves the module unobserved, and it counts as loaded.
        // A covering mount shows its own directory, not the kernel's, so a missing entry under one observes nothing.
        // Only the mount table shows such a mount, so a missing entry beside an unreadable table observes nothing either.
        let loaded = |name: &str| {
            let initstate = module(name).join("initstate");
            let Some(mounts) = mounts.as_deref() else {
                return true;
            };
            match self.shown(mounts, &initstate).and_then(fs::metadata) {
                Ok(_) => true,
                Err(error) => error.kind() != std::io::ErrorKind::NotFound,
            }
        };
        // A mount over a module's `srcversion` shows its own text, so the attribute counts only where a readable mount table shows no cover.
        let srcversion = |name: &str| {
            let path = module(name).join("srcversion");
            mounts
                .as_deref()
                .and_then(|mounts| self.shown(mounts, &path).ok())
                .and_then(Self::attribute)
        };
        if !manifest.modules.iter().any(|m| m.name == "vfio_pci") {
            return Err(WcError::Loaded("vfio_pci".into()));
        }
        for name in VFIO_MODULES {
            if !manifest.modules.iter().any(|m| m.name == name) && loaded(name) {
                return Err(WcError::Loaded(name.into()));
            }
        }
        // `srcversion` is an attribute of a loaded module, so a matching value also proves the module loaded.
        let differs = |m: &&WcModule| srcversion(&m.name).as_deref() != Some(m.srcversion.as_str());
        match manifest.modules.iter().find(differs) {
            Some(module) => Err(WcError::Loaded(module.name.clone())),
            None => Ok(()),
        }
    }

    /// Checks that `bdf` is on `vfio-pci` and its prefetchable memory BAR is
    /// mapped write-combining, by this architecture's [`MappingEvidence`]: on
    /// x86_64 a covering write-combining entry in the kernel's PAT table, on
    /// aarch64 the approved modules of `manifest` loaded with their approved
    /// `srcversion`, whose mmap maps an ENA's prefetchable BAR write-combining.
    /// The poll-mode driver maps the BAR when it probes the device, at
    /// environment initialization.
    ///
    /// # Errors
    ///
    /// `Mapping` for an unreadable `resource` file, no prefetchable BAR, or no covering write-combining entry;
    /// `Loaded` as [`check_wc_loaded`](Self::check_wc_loaded) on aarch64;
    /// `Unverifiable` for a device off `vfio-pci`, an unreadable mount
    /// table, a `resource` file or a PAT table a mount of the mount table
    /// [covers](Self::shown), an unreadable PAT table, or an architecture
    /// with no evidence.
    pub fn check_wc_mapping(&self, bdf: &str, manifest: &WcManifest) -> Result<(), WcError> {
        self.check_wc_mapping_by(bdf, manifest, MappingEvidence::HOST)
    }

    /// [`check_wc_mapping`](Self::check_wc_mapping) under `evidence`.
    pub(crate) fn check_wc_mapping_by(
        &self,
        bdf: &str,
        manifest: &WcManifest,
        evidence: MappingEvidence,
    ) -> Result<(), WcError> {
        // A mount over the device's driver link or its `resource` file
        // shows its own entries, so each counts only where the mount table,
        // read once for the check, shows none.
        let mounts = self.mount_table().map_err(|_| WcError::Unverifiable)?;
        if self.driver_link_in(&mounts, bdf).flatten().as_deref() != Some("vfio-pci") {
            return Err(WcError::Unverifiable);
        }
        let resources = self.pci(bdf).join("resource");
        let resources = (self.shown(&mounts, &resources))
            .map_err(|_| WcError::Unverifiable)
            .and_then(|shown| Host::read(shown).ok_or(WcError::Mapping))?;
        let hex = |text: &str| u64::from_str_radix(text.trim_start_matches("0x"), 16).ok();
        let (start, end) = resources
            .lines()
            .take(BARS)
            .find_map(|line| {
                let mut fields = line.split_whitespace().map(hex);
                let (start, end, flags) = (fields.next()??, fields.next()??, fields.next()??);
                (flags & (MEMORY | PREFETCH) == MEMORY | PREFETCH && end > start)
                    .then_some((start, end))
            })
            .ok_or(WcError::Mapping)?;
        match evidence {
            MappingEvidence::PatTable => {}
            MappingEvidence::LoadedModule => return self.check_wc_loaded(manifest),
            MappingEvidence::Unavailable => return Err(WcError::Unverifiable),
        }
        // The table sits in debugfs, mounted at `sys/kernel/debug`. A mount
        // inside that directory, or one over `sys/kernel`, shows its own
        // text there, so the table counts only where the mount table shows
        // neither.
        let path = self.sys.join("kernel/debug/x86/pat_memtype_list");
        let table = (self.shown(&mounts, &path).ok())
            .and_then(Host::read)
            .ok_or(WcError::Unverifiable)?;
        let covers = |line: &str| -> Option<bool> {
            let (_, rest) = line.split_once("[mem ")?;
            let (range, kind) = rest.split_once(']')?;
            let (low, high) = range.split_once('-')?;
            Some(kind.trim() == "write-combining" && hex(low)? <= start && end < hex(high)?)
        };
        // `covers` accepts a line only when its text after `]` trims to
        // `write-combining`, so this suffix test keeps every line it accepts.
        let write_combining = |line: &&str| line.trim_end().ends_with("write-combining");
        if table
            .lines()
            .filter(write_combining)
            .any(|line| covers(line) == Some(true))
        {
            Ok(())
        } else {
            Err(WcError::Mapping)
        }
    }
}
