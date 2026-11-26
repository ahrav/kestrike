//! Links the pinned SPDK install and its bundled DPDK statically and compiles
//! the C shims and the registry tests' probe program against the same headers
//! and flags.
//!
//! Discovery reads only the install's static pkg-config metadata, from
//! `SPDK_PKG_CONFIG_PATH` (default `/usr/local/lib/pkgconfig`). Every SPDK and
//! DPDK archive links with a scoped `+whole-archive` modifier, in the order the
//! metadata reports, because the NVMe PCIe transport, the PCI bus, the ENA PMD
//! and the ring mempool handlers register from constructors that a plain
//! static link drops without a link error. The build fails, naming the
//! prerequisite, when the metadata, an archive, the pinned version or the
//! headers the checked-in bindings were generated from are absent or differ,
//! and reruns when the metadata, a linked archive or an installed header
//! changes.
//!
//! Each supported install has a record in `src/generated/installs`, named
//! `<target triple>-<core>`, or `<target triple>-<core>-asan` for an install
//! built with `--enable-asan`, where the core is the one the install's
//! compile flags name. The record holds the install's target, sanitizer and
//! exact flags, the digest of its headers and the name of the output under
//! `src/generated/outputs` its headers generate; installs whose headers
//! generate the same bindings and layout tables share one output. The build
//! selects the record of the target, the sanitizer and the install's flags,
//! with the install's include root normalized, and an install no record
//! names fails the build.
//!
//! Under an ASan install every shim and probe compiles with address
//! sanitizer and frame pointers, the `asan` system library the install's
//! metadata names is dropped because the Rust sanitizer runtime supplies it,
//! the registry probes carry the target and sanitizer flags, and the crate
//! compiles with `cfg(spdk_sys_asan)`.

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::iter;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread::{self, JoinHandle};

#[path = "native/metadata.rs"]
mod metadata;
#[path = "native/select.rs"]
mod select;

const DEFAULT_PKG_CONFIG_PATH: &str = "/usr/local/lib/pkgconfig";
const PREREQUISITE: &str = "spdk-sys needs the SPDK v25.05.1 install with its bundled DPDK 25.03.0 \
     static archives, headers and pkg-config metadata (see crates/spdk-sys/src/lib.rs)";
const SPDK_MODULES: [&str; 2] = ["spdk_nvme", "spdk_env_dpdk"];
/// SPDK's record of the system libraries its archives call.
const SPDK_SYSTEM_MODULE: &str = "spdk_syslibs";
const DPDK_MODULE: &str = "libdpdk";
/// The install records and generated outputs, relative to the crate.
const GENERATED: &str = "src/generated";

fn main() {
    println!("cargo::rerun-if-env-changed=SPDK_PKG_CONFIG_PATH");
    for path in ["build.rs", "native", "regenerate.sh", GENERATED] {
        println!("cargo::rerun-if-changed={path}");
    }
    let target = env::var("TARGET").unwrap_or_default();
    let pc_path =
        env::var("SPDK_PKG_CONFIG_PATH").unwrap_or_else(|_| DEFAULT_PKG_CONFIG_PATH.into());
    println!("cargo::rerun-if-changed={pc_path}");
    let pc = PkgConfig { path: pc_path };

    let [nvme, env_dpdk] = SPDK_MODULES;
    let [
        libdir,
        includedir,
        cflags,
        spdk_libs,
        dpdk_libs,
        nvme_dirs,
        env_dirs,
    ] = pc.outputs([
        &["--variable=libdir", DPDK_MODULE],
        &["--variable=includedir", DPDK_MODULE],
        &["--cflags", DPDK_MODULE, nvme, env_dpdk],
        &["--static", "--libs", nvme, env_dpdk, SPDK_SYSTEM_MODULE],
        &["--static", "--libs", DPDK_MODULE],
        &["--libs-only-L", nvme],
        &["--libs-only-L", env_dpdk],
    ]);
    let libdir = PathBuf::from(libdir);
    for (module, dirs) in SPDK_MODULES.iter().zip([nvme_dirs, env_dirs]) {
        if !dirs
            .split_whitespace()
            .any(|dir| dir.strip_prefix("-L").map(Path::new) == Some(libdir.as_path()))
        {
            fail(&format!(
                "{module} does not link from libdpdk's libdir {}",
                libdir.display()
            ));
        }
    }
    let cflags: Vec<String> = cflags.split_whitespace().map(str::to_owned).collect();
    select::include_root(&cflags, &includedir).unwrap_or_else(|reason| fail(&reason));
    let sanitizer =
        select::sanitizer(&dpdk_libs, &rustflags()).unwrap_or_else(|reason| fail(&reason));
    println!("cargo::rustc-check-cfg=cfg(spdk_sys_asan)");
    if sanitizer.is_some() {
        println!("cargo::rustc-cfg=spdk_sys_asan");
    }
    println!(
        "cargo::rustc-env=SPDK_SYS_PROBE_FLAGS={}",
        probe_flags(&target, sanitizer).join("\x1f")
    );
    let install = select_install(&target, sanitizer, &cflags);
    let generated = Path::new(GENERATED)
        .join(select::OUTPUTS)
        .join(&install.output);
    let manifest_dir =
        env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| fail("CARGO_MANIFEST_DIR is unset"));
    println!(
        "cargo::rustc-env=SPDK_SYS_GENERATED={}",
        Path::new(&manifest_dir).join(&generated).display()
    );
    println!(
        "cargo::rustc-env=SPDK_SYS_INSTALL={}",
        Path::new(&manifest_dir).join(&install.record).display()
    );
    let version = Path::new(&includedir).join("spdk/version.h");
    let declared = fs::read_to_string(&version)
        .unwrap_or_else(|e| fail(&format!("reading {}: {e}", version.display())));
    metadata::check_spdk_version(&version, &declared).unwrap_or_else(|reason| fail(&reason));
    println!("cargo::rerun-if-changed={includedir}");
    let headers = Digest::start(
        "native/header-digest.sh",
        iter::once(includedir.as_str()).chain(cflags.iter().map(String::as_str)),
    );
    let generator = Digest::start("native/generator-digest.sh", iter::empty::<&str>());

    let plan = metadata::link_plan(&spdk_libs, &dpdk_libs, &libdir, sanitizer)
        .unwrap_or_else(|reason| fail(&reason));
    println!("cargo::rustc-link-search=native={}", libdir.display());
    let mut recorded = String::new();
    for archive in &plan.archives {
        println!("cargo::rustc-link-lib=static:+whole-archive,-bundle={archive}");
        let file = libdir.join(format!("lib{archive}.a"));
        println!("cargo::rerun-if-changed={}", file.display());
        let _ = writeln!(recorded, "archive {}", file.display());
    }
    for archive in &plan.bundled {
        println!("cargo::rustc-link-lib=static:-bundle={archive}");
        let file = libdir.join(format!("lib{archive}.a"));
        println!("cargo::rerun-if-changed={}", file.display());
        let _ = writeln!(recorded, "static {}", file.display());
    }
    for lib in &plan.system {
        println!("cargo::rustc-link-lib=dylib={lib}");
        let _ = writeln!(recorded, "system {lib}");
    }
    let lineage = LineageCheck::start(&install, &libdir, &plan);
    let out = PathBuf::from(env::var("OUT_DIR").unwrap_or_else(|_| fail("OUT_DIR is unset")));
    fs::write(out.join("link-plan.txt"), recorded)
        .unwrap_or_else(|e| fail(&format!("writing the link plan: {e}")));

    let compiled = compile_shim(&out, &generated, &cflags, &libdir, sanitizer);
    // A changed archive can also fail the shim compile's read of the PCI bus
    // size from librte_bus_pci.a, so the lineage check reports first.
    if let Some(lineage) = lineage {
        lineage.finish();
    }
    // A header mismatch can also break the shim compile, so the
    // generation-input check reports before the compile error, naming the
    // installed headers' digest and the record it differs from, or the
    // generator digest and the bindings file it differs from.
    check_generation_inputs(headers, generator, &target, &install, &generated);
    if let Err(e) = compiled {
        fail(&format!("compiling the native shim: {e}"));
    }
    println!("cargo::rustc-link-search=native={}", out.display());
    println!("cargo::rustc-link-lib=static=spdk_sys_shim");
    // The registry tests link their probes with the rustc that builds this crate.
    let rustc = env::var("RUSTC").unwrap_or_else(|_| fail("RUSTC is unset"));
    println!("cargo::rustc-env=SPDK_SYS_RUSTC={rustc}");
}

/// Sources archived into the shim library besides [`REGISTRY_SOURCE`].
const SHIM_SOURCES: [&str; 3] = ["shim.c", "mbuf.c", "mbuf_free.c"];
/// The registry query's source, which compiles with the installed PCI bus
/// object's size as `SPDK_SYS_PCI_BUS_SIZE`.
const REGISTRY_SOURCE: &str = "registry.c";
/// The registry tests' probe program, compiled beside the shims to
/// `OUT_DIR/probe.o` outside the shim archive.
const PROBE_SOURCE: &str = "probe.c";

/// Starts every source but [`REGISTRY_SOURCE`], reads the PCI bus object's
/// size while they compile, then starts the registry source and archives
/// every object but the probe's. Per-function and per-object sections let
/// the final link drop unused shims, and `-pipe` overlaps each source's
/// assembly with its compilation. Compiler stderr becomes cargo warnings
/// only when every source compiles.
fn compile_shim(
    out: &Path,
    generated: &Path,
    cflags: &[String],
    libdir: &Path,
    sanitizer: Option<&str>,
) -> Result<(), String> {
    let debug = env::var("DEBUG").as_deref() == Ok("true");
    let compile = |source: &'static str, define: Option<String>| {
        let object = out.join(source).with_extension("o");
        let mut cc = Command::new("cc");
        cc.arg("-c")
            .arg(Path::new("native").join(source))
            .args(["-Inative", "-O2", "-fPIC", "-pipe"])
            .arg(format!("-I{}", generated.display()))
            .args(["-ffunction-sections", "-fdata-sections", "-Wall", "-Wextra"])
            .args(cflags)
            .args(define)
            .arg("-o")
            .arg(&object)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(sanitizer) = sanitizer {
            // Frame pointers keep the shim's frame in a sanitizer report's
            // stack, so a report names the shim that made the access.
            cc.arg(format!("-fsanitize={sanitizer}"))
                .arg("-fno-omit-frame-pointer");
        }
        if debug || sanitizer.is_some() {
            cc.arg("-g");
        }
        (source, object, cc.spawn())
    };
    let mut compiles: Vec<_> = SHIM_SOURCES
        .into_iter()
        .chain([PROBE_SOURCE])
        .map(|source| compile(source, None))
        .collect();
    let mut failure = None;
    match pci_bus_size(libdir) {
        Ok(size) => compiles.push(compile(
            REGISTRY_SOURCE,
            Some(format!("-DSPDK_SYS_PCI_BUS_SIZE={size}")),
        )),
        Err(reason) => failure = Some(reason),
    }
    let mut objects = Vec::new();
    let mut warnings = String::new();
    for (source, object, child) in compiles {
        match child.and_then(Child::wait_with_output) {
            Ok(compiled) => {
                let diagnostics = String::from_utf8_lossy(&compiled.stderr);
                if !compiled.status.success() {
                    failure.get_or_insert_with(|| diagnostics.clone().into_owned());
                }
                warnings.push_str(&diagnostics);
            }
            Err(e) => {
                failure.get_or_insert_with(|| format!("running cc on native/{source}: {e}"));
            }
        }
        if source != PROBE_SOURCE {
            objects.push(object);
        }
    }
    if let Some(failure) = failure {
        return Err(failure);
    }
    for line in warnings.lines() {
        println!("cargo::warning={line}");
    }
    let archive = out.join("libspdk_sys_shim.a");
    let _ = fs::remove_file(&archive);
    let archived = Command::new("ar")
        .arg(bfd_target())
        .arg("crsD")
        .arg(&archive)
        .args(&objects)
        .output()
        .map_err(|e| format!("running ar: {e}"))?;
    if !archived.status.success() {
        return Err(String::from_utf8_lossy(&archived.stderr).into_owned());
    }
    Ok(())
}

struct Digest {
    script: &'static str,
    child: Child,
}

impl Digest {
    fn start<'a>(script: &'static str, args: impl IntoIterator<Item = &'a str>) -> Self {
        Command::new(script)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map(|child| Self { script, child })
            .unwrap_or_else(|e| fail(&format!("running {script}: {e}")))
    }

    fn finish(self) -> String {
        let script = self.script;
        let output = self
            .child
            .wait_with_output()
            .unwrap_or_else(|e| fail(&format!("running {script}: {e}")));
        if !output.status.success() {
            fail(&format!(
                "{script} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    }
}

/// The flags the registry tests' probe links with: the target, and under
/// a sanitizer its `-Zsanitizer` flag, so the probe carries the
/// configuration the archives were built for.
fn probe_flags(target: &str, sanitizer: Option<&str>) -> Vec<String> {
    iter::once(format!("--target={target}"))
        .chain(sanitizer.map(|sanitizer| format!("-Zsanitizer={sanitizer}")))
        .collect()
}

/// The Rust flags cargo passes to the compiler of this crate, read from
/// `CARGO_ENCODED_RUSTFLAGS`.
fn rustflags() -> Vec<String> {
    env::var("CARGO_ENCODED_RUSTFLAGS")
        .map(|flags| {
            flags
                .split('\x1f')
                .filter(|flag| !flag.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// The one record under `src/generated/installs` of `target`, `sanitizer`
/// and the install's compile flags, its include root normalized. An aarch64
/// install's flags name the build host's core (`-mcpu=neoverse-v1` on
/// Graviton3, `-mcpu=neoverse-v2` on Graviton4) and an x86_64 install's name
/// `-march=native` or the portable `-march=x86-64-v2`, and an ASan install
/// records its sanitizer, so each keeps its own record; the header digest is
/// checked against the chosen record afterwards.
fn select_install(target: &str, sanitizer: Option<&str>, cflags: &[String]) -> select::Install {
    let wanted = select::flags_line(target, sanitizer, cflags);
    let root = Path::new(GENERATED);
    let recorded = select::recorded(root)
        .unwrap_or_else(|e| fail(&format!("reading {}: {e}", root.display())));
    match select::matching(&wanted, &recorded).as_slice() {
        [install] => (*install).clone(),
        [] => {
            let lines: Vec<&String> = recorded
                .iter()
                .map(|install| &install.target)
                .filter(|line| line.starts_with(&format!("Target: {target}. ")))
                .collect();
            fail(&format!(
                "no install record names `{wanted}` (recorded for {target}: {lines:?}); \
                 run crates/spdk-sys/regenerate.sh on a host with this install"
            ))
        }
        several => {
            let records: Vec<&Path> = several
                .iter()
                .map(|install| install.record.as_path())
                .collect();
            fail(&format!(
                "several install records name `{wanted}`: {records:?}"
            ))
        }
    }
}

/// The archive lineage check, split so the linked archives hash on their
/// own thread while the shim compiles.
struct LineageCheck<'a> {
    install: &'a select::Install,
    lineage: &'a select::Lineage,
    digests: JoinHandle<Result<Vec<(String, String)>, String>>,
}

impl<'a> LineageCheck<'a> {
    fn start(
        install: &'a select::Install,
        libdir: &Path,
        plan: &metadata::LinkPlan,
    ) -> Option<Self> {
        let Some(lineage) = &install.lineage else {
            println!(
                "cargo::warning={} records no archive lineage from a controlled native build",
                install.record.display()
            );
            return None;
        };
        let files: Vec<PathBuf> = plan
            .archives
            .iter()
            .chain(&plan.bundled)
            .map(|archive| libdir.join(format!("lib{archive}.a")))
            .collect();
        let digests = thread::spawn(move || select::sha256sums(&files));
        Some(Self {
            install,
            lineage,
            digests,
        })
    }

    fn finish(self) {
        let linked = self
            .digests
            .join()
            .unwrap_or_else(|_| fail("the thread hashing the linked archives panicked"))
            .unwrap_or_else(|reason| fail(&reason));
        select::check_archives(&self.install.record, self.lineage, &linked)
            .unwrap_or_else(|reason| fail(&reason));
    }
}

fn check_generation_inputs(
    headers: Digest,
    generator: Digest,
    target: &str,
    install: &select::Install,
    generated: &Path,
) {
    let path = generated.join("bindings.rs");
    let bindings = fs::read_to_string(&path)
        .unwrap_or_else(|e| fail(&format!("reading {}: {e}", path.display())));
    let recorded = |prefix: &str| {
        bindings
            .lines()
            .find_map(|line| line.strip_prefix(prefix))
            .unwrap_or_else(|| fail(&format!("{} records no `{prefix}` line", path.display())))
    };
    let header_digest = headers.finish();
    if install.header_digest != header_digest {
        fail(&format!(
            "the installed headers (digest {header_digest}) differ from the ones {} records; \
             install the pinned release or regenerate the bindings",
            install.record.display()
        ));
    }
    let generator_digest = generator.finish();
    if recorded("// Generator digest: ") != generator_digest {
        fail(&format!(
            "{} was generated from other versions of the files native/generator-digest.sh \
             lists (current digest {generator_digest}); run crates/spdk-sys/regenerate.sh on a \
             host of {target}",
            path.display()
        ));
    }
    println!(
        "cargo::rustc-env=SPDK_SYS_PINS=SPDK {} DPDK {} header digest {header_digest}, \
         generator digest {generator_digest}.",
        recorded("// SPDK "),
        recorded("// Bundled DPDK "),
    );
}

/// The size of the exported `rte_pci_bus` object, which the registry
/// query's view of the PCI bus must match.
fn pci_bus_size(libdir: &Path) -> Result<String, String> {
    let archive = libdir.join("librte_bus_pci.a");
    let output = Command::new("nm")
        .arg(bfd_target())
        .args(["-S", "--defined-only"])
        .arg(&archive)
        .output()
        .map_err(|e| format!("running nm on {}: {e}", archive.display()))?;
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| {
            let mut parts = line.split_whitespace();
            let (_, size, kind, name) =
                (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
            (kind == "D" && name == "rte_pci_bus").then(|| format!("0x{size}"))
        })
        .ok_or_else(|| format!("{} defines no rte_pci_bus object", archive.display()))
}

/// The `--target` option naming the target's object format for `ar` and
/// `nm`; the build fails for an architecture other than `aarch64` and
/// `x86_64`. With the format named, binutils reads each input as that format
/// directly and skips the installed linker plugins, of which the LLVM plugin
/// loads all of LLVM.
fn bfd_target() -> &'static str {
    let target = env::var("TARGET").unwrap_or_default();
    match target.split('-').next() {
        Some("aarch64") => "--target=elf64-littleaarch64",
        Some("x86_64") => "--target=elf64-x86-64",
        _ => fail(&format!("no binutils object format for {target}")),
    }
}

/// pkg-config restricted to the install's metadata directory.
struct PkgConfig {
    path: String,
}

impl PkgConfig {
    /// Runs independent queries concurrently and returns their outputs in
    /// query order, failing on the first query, in that order, that fails.
    fn outputs<const N: usize>(&self, queries: [&[&str]; N]) -> [String; N] {
        queries
            .map(|args| (args, self.spawn(args)))
            .map(|(args, child)| self.finish(args, child))
    }

    fn spawn(&self, args: &[&str]) -> Child {
        Command::new("pkg-config")
            .args(args)
            .env("PKG_CONFIG_PATH", &self.path)
            .env("PKG_CONFIG_LIBDIR", &self.path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| fail(&format!("running pkg-config: {e}")))
    }

    fn finish(&self, args: &[&str], child: Child) -> String {
        let out = child
            .wait_with_output()
            .unwrap_or_else(|e| fail(&format!("running pkg-config: {e}")));
        if !out.status.success() {
            fail(&format!(
                "no usable pkg-config metadata in {} (pkg-config {}: {})",
                self.path,
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    }
}

fn fail(reason: &str) -> ! {
    eprintln!("error: {PREREQUISITE}: {reason}");
    std::process::exit(1);
}
