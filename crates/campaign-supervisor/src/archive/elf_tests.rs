//! Program-header reading over synthetic ELF64 files: the interpreter, an
//! audit request in the dynamic section, and malformed files; and the
//! archive of a static file and of one whose interpreter is a test
//! script.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use super::elf::interpreter;
use super::publish_tests::{built_from, flip_keeping_mtime};
use super::{Archive, Error, Invalid, publish};
use crate::step::Step;
use crate::store::fixture::{Case, processes, scripted};
use crate::store::open_host;

const PT_INTERP: u32 = 3;
const PT_DYNAMIC: u32 = 2;
const DT_NEEDED: u64 = 1;
const DT_RPATH: u64 = 15;
const DT_RUNPATH: u64 = 29;
const DT_DEPAUDIT: u64 = 0x6fff_fefb;
const DT_AUDIT: u64 = 0x6fff_fefc;

/// An ELF64 little-endian file whose program headers name `segments`, each
/// a type and its bytes, placed after the header table.
fn elf(segments: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let segments: Vec<_> = segments
        .iter()
        .cloned()
        .chain((!segments.is_empty()).then_some((1, vec![0; 1])))
        .collect();
    let mut header = vec![0; 64];
    header[..6].copy_from_slice(b"\x7fELF\x02\x01");
    header[16..18].copy_from_slice(&2u16.to_le_bytes());
    header[18..20].copy_from_slice(&native().to_le_bytes());
    header[32..40].copy_from_slice(&64u64.to_le_bytes());
    header[54..56].copy_from_slice(&56u16.to_le_bytes());
    let count = u16::try_from(segments.len()).expect("few segments");
    header[56..58].copy_from_slice(&count.to_le_bytes());
    let mut offset = 64 + 56 * segments.len() as u64;
    let mut body = Vec::new();
    for (kind, bytes) in &segments {
        let mut entry = vec![0; 56];
        entry[..4].copy_from_slice(&kind.to_le_bytes());
        entry[8..16].copy_from_slice(&offset.to_le_bytes());
        if *kind == 1 {
            entry[4..8].copy_from_slice(&1u32.to_le_bytes());
            let address = 0x400000 + offset;
            entry[16..24].copy_from_slice(&address.to_le_bytes());
            header[24..32].copy_from_slice(&address.to_le_bytes());
        }
        entry[32..40].copy_from_slice(&(bytes.len() as u64).to_le_bytes());
        header.extend(entry);
        body.extend_from_slice(bytes);
        offset += bytes.len() as u64;
    }
    header.extend(body);
    header
}

/// This host's `e_machine`.
fn native() -> u16 {
    match std::env::consts::ARCH {
        "x86_64" => 62,
        "aarch64" => 183,
        "riscv64" => 243,
        arch => panic!("no ELF machine number for {arch}"),
    }
}

fn dynamic(tags: &[u64]) -> (u32, Vec<u8>) {
    let bytes = tags
        .iter()
        .flat_map(|&tag| [tag.to_le_bytes(), [0; 8]])
        .flatten()
        .collect();
    (PT_DYNAMIC, bytes)
}

fn interp(path: &[u8]) -> (u32, Vec<u8>) {
    (PT_INTERP, path.to_vec())
}

fn read(case: &Case, bytes: &[u8]) -> Result<Option<String>, Invalid> {
    let path = case.root.join("executable");
    fs::write(&path, bytes).expect("it is written");
    interpreter(&open_host(&path).expect("it opens"))
}

/// The interpreter path is read without its terminator, a static file
/// names none, a `RUNPATH` is admitted, and an audit or dependency-audit
/// entry or an `RPATH` before the dynamic section's end is refused; one
/// after its end is not read.
#[test]
fn the_interpreter_is_read_and_an_audit_request_is_refused() {
    let case = Case::new();
    let ld = interp(b"/lib/ld.so\0");
    let linked = elf(&[ld.clone(), dynamic(&[DT_NEEDED, 0])]);
    assert_eq!(
        read(&case, &linked).expect("it reads").as_deref(),
        Some("/lib/ld.so")
    );
    assert_eq!(read(&case, &elf(&[dynamic(&[0])])).expect("it reads"), None);
    let runpath = elf(&[ld.clone(), dynamic(&[DT_NEEDED, DT_RUNPATH, 0])]);
    assert_eq!(
        read(&case, &runpath)
            .expect("RUNPATH is accepted")
            .as_deref(),
        Some("/lib/ld.so")
    );
    for tags in [[DT_RPATH, DT_RUNPATH, 0], [DT_RUNPATH, DT_RPATH, 0]] {
        assert_eq!(
            read(&case, &elf(&[ld.clone(), dynamic(&tags)]))
                .expect("RUNPATH disables RPATH")
                .as_deref(),
            Some("/lib/ld.so")
        );
    }
    let rpath = elf(&[ld.clone(), dynamic(&[DT_NEEDED, DT_RPATH, 0])]);
    assert!(
        matches!(read(&case, &rpath), Err(Invalid::Elf(why)) if why.contains("RPATH")),
        "an RPATH is refused"
    );
    for tag in [DT_AUDIT, DT_DEPAUDIT] {
        let audited = elf(&[ld.clone(), dynamic(&[DT_NEEDED, tag, 0])]);
        assert!(
            matches!(read(&case, &audited), Err(Invalid::Audit)),
            "{tag:x}"
        );
    }
    let ended = elf(&[ld, dynamic(&[DT_NEEDED, 0, DT_AUDIT, DT_RPATH])]);
    assert_eq!(
        read(&case, &ended)
            .expect("tags after NULL are ignored")
            .as_deref(),
        Some("/lib/ld.so")
    );
}

/// Another file kind, a 32-bit or big-endian file, a relocatable object,
/// a file for another machine, program headers of another size than
/// ELF64's or none, a segment past its read bound, a truncated header or
/// segment, an unterminated, relative or second interpreter path, a file
/// that needs libraries and names no interpreter, and a dynamic section
/// with no terminating entry or a partial one are refused, each for its
/// own reason.
#[test]
fn malformed_executables_are_refused() {
    let case = Case::new();
    let linked = elf(&[interp(b"/lib/ld.so\0")]);
    let mut narrow = linked.clone();
    narrow[4] = 1;
    let mut big = linked.clone();
    big[5] = 2;
    let mut object = linked.clone();
    object[16] = 1;
    let mut foreign = linked.clone();
    foreign[18..20].copy_from_slice(&(native() ^ 1).to_le_bytes());
    let mut short = linked.clone();
    short[54..56].copy_from_slice(&39u16.to_le_bytes());
    let mut long = linked.clone();
    long[54..56].copy_from_slice(&64u16.to_le_bytes());
    let mut oversize = linked.clone();
    oversize[64 + 32..64 + 40].copy_from_slice(&((1u64 << 20) + 1).to_le_bytes());
    let mut many = linked.clone();
    many[56..58].copy_from_slice(&1171u16.to_le_bytes());
    let mut xnum = linked.clone();
    xnum[56..58].copy_from_slice(&u16::MAX.to_le_bytes());
    let mut far = linked.clone();
    far[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
    let mut far_segment = linked.clone();
    far_segment[72..80].copy_from_slice(&(1u64 << 63).to_le_bytes());
    let (_, mut partial) = dynamic(&[1, 0]);
    partial.truncate(24);
    for (label, bytes, reason) in [
        ("script", b"#!/bin/sh\n".repeat(8), "no ELF64"),
        ("32-bit", narrow, "no ELF64"),
        ("big-endian", big, "no ELF64"),
        ("object", object, "no executable"),
        ("foreign", foreign, "built for machine"),
        ("short entries", short, "another size"),
        ("long entries", long, "another size"),
        ("no headers", elf(&[]), "no program header"),
        ("too many", many, "headers past"),
        ("extended count", xnum, "headers past"),
        ("far table", far, "truncated"),
        ("far segment", far_segment, "truncated"),
        (
            "short final header",
            linked[..64 + 56 + 40].to_vec(),
            "truncated",
        ),
        (
            "needs",
            elf(&[dynamic(&[DT_NEEDED, 0])]),
            "names no interpreter",
        ),
        ("oversize", oversize, "read bound"),
        ("short header", linked[..40].to_vec(), "truncated"),
        (
            "short segment",
            linked[..linked.len() - 2].to_vec(),
            "truncated",
        ),
        (
            "unterminated",
            elf(&[interp(b"/lib/ld.so")]),
            "unterminated",
        ),
        ("relative", elf(&[interp(b"ld.so\0")]), "is relative"),
        ("dotted", elf(&[interp(b"./ld.so\0")]), "is relative"),
        (
            "two interpreters",
            elf(&[interp(b"/lib/ld.so\0"), interp(b"/lib/other.so\0")]),
            "more than one",
        ),
        ("unended", elf(&[dynamic(&[1, 1])]), "no terminating"),
        ("partial", elf(&[(PT_DYNAMIC, partial)]), "no terminating"),
    ] {
        let refused = read(&case, &bytes);
        assert!(
            matches!(&refused, Err(Invalid::Elf(why)) if why.contains(reason)),
            "{label}: {refused:?}"
        );
    }
}

/// A static file names no interpreter, so its archive records no loader
/// and no library, and verifies before and after a use.
#[test]
fn a_static_executable_archives_with_no_loader_or_library() {
    let _processes = processes();
    let case = Case::new();
    let path = case.root.join("static");
    fs::write(&path, elf(&[dynamic(&[0])])).expect("it is written");
    let output = case.root.join("archive");
    let mut archive = publish(&output, &built_from(&path)).expect("it publishes");
    assert_eq!(archive.record().loader, None);
    assert!(archive.record().libraries.is_empty());
    archive
        .verify()
        .expect("it verifies")
        .finish()
        .expect("it verifies after the use");
}

/// An executable that requests an audit module is refused before the
/// archive's directory is created.
#[test]
fn an_audited_executable_is_refused_before_anything_is_written() {
    let case = Case::new();
    let path = case.root.join("audited");
    fs::write(
        &path,
        elf(&[interp(b"/lib/ld.so\0"), dynamic(&[DT_AUDIT, 0])]),
    )
    .expect("it is written");
    let built = super::publish_tests::built_from(&path);
    let output = case.root.join("archive");
    let refused = publish(&output, &built).expect_err("it is refused");
    assert!(
        matches!(refused, Error::Invalid(Invalid::Audit)),
        "{refused:?}"
    );
    assert!(!Path::new(&output).exists());
}

/// A dynamic executable whose interpreter is the shell script `script`,
/// in `case.root`: the script's path and the executable's.
fn scripted_worker(case: &Case, script: &str) -> (PathBuf, PathBuf) {
    let loader = case.root.join("loader");
    fs::write(&loader, script).expect("it is written");
    fs::set_permissions(&loader, fs::Permissions::from_mode(0o700)).expect("it is chmodded");
    let mut terminated = loader
        .to_str()
        .expect("the path is UTF-8")
        .as_bytes()
        .to_vec();
    terminated.push(0);
    let worker = case.root.join("dynamic");
    fs::write(&worker, elf(&[interp(&terminated), dynamic(&[0])])).expect("it is written");
    (loader, worker)
}

/// The host interpreter is part of the cache key: after a cache hit, a
/// same-size rewrite of the interpreter with its modification time
/// restored makes the next verification check its digest and refuse it.
#[test]
fn a_changed_interpreter_breaks_a_cache_hit() {
    let _processes = processes();
    let case = Case::new();
    let (loader, worker) = scripted_worker(&case, "#!/bin/sh\nexit 0\n");
    let output = case.root.join("archive");
    publish(&output, &built_from(&worker)).expect("it publishes");
    let mut archive = Archive::load(&output).expect("it loads");
    archive.verify().map(drop).expect("it verifies");
    let (hit, reached) = scripted([], || archive.verify().map(drop));
    hit.expect("nothing is scripted").expect("it verifies");
    assert!(
        !reached.contains(&Step::Read),
        "the second verification is a cache hit"
    );
    flip_keeping_mtime(&loader);
    let refused = archive.verify().map(drop);
    let named = loader.display().to_string();
    assert!(
        matches!(&refused, Err(Invalid::Digest(entry)) if *entry == named),
        "{refused:?}"
    );
}

/// An interpreter whose listing exits 0 but writes a diagnostic, such as a
/// missing symbol version, refuses the publication before anything is
/// written.
#[test]
fn a_listing_with_a_diagnostic_is_refused() {
    let _processes = processes();
    let case = Case::new();
    let script = "#!/bin/sh\necho 'version GLIBC_9 not found' >&2\nexit 0\n";
    let (_, worker) = scripted_worker(&case, script);
    let output = case.root.join("archive");
    let refused = publish(&output, &built_from(&worker)).expect_err("it is refused");
    assert!(
        matches!(&refused, Error::Invalid(Invalid::Resolution(why)) if why.contains("GLIBC_9")),
        "{refused:?}"
    );
    assert!(!output.exists());
}

/// An archive of two libraries, which a test interpreter lists from the
/// archive's library directory when that is the search path and from the
/// source directory otherwise: both are archived and recorded; after a
/// cache hit, a row the interpreter adds from a file outside the archive
/// refuses the next verification, since the resolution runs on every
/// verification; and a rewrite of the second library with its
/// modification time restored breaks the cache and refuses its digest.
#[test]
fn every_library_is_archived_and_the_resolution_reruns_on_a_cache_hit() {
    let _processes = processes();
    let case = Case::new();
    let root = case.root.canonicalize().expect("it resolves");
    let sources = root.join("sources");
    fs::create_dir(&sources).expect("it is made");
    for library in ["liba.so.1", "libb.so.1"] {
        fs::write(sources.join(library), elf(&[dynamic(&[0])])).expect("it is written");
    }
    let side = root.join("side");
    fs::write(&side, "").expect("it is written");
    let archived = root.join("archive/lib");
    let script = format!(
        "#!/bin/sh\n\
         d=\"${{LD_LIBRARY_PATH:-/missing-search-path}}\"\n\
         cat {side:?}\n\
         echo \"liba.so.1 => $d/liba.so.1 (0x1)\"\n\
         echo \"libb.so.1 => $d/libb.so.1 (0x2)\"\n"
    );
    let (_, worker) = scripted_worker(&case, &script);
    let output = root.join("archive");
    super::publish::publish_with(&output, &built_from(&worker), Some(sources.as_os_str()))
        .expect("it publishes");
    let mut archive = Archive::load(&output).expect("it loads");
    let names: Vec<&str> = archive
        .record()
        .libraries
        .keys()
        .map(|name| name.as_str())
        .collect();
    assert_eq!(names, ["liba.so.1", "libb.so.1"]);
    for library in ["liba.so.1", "libb.so.1"] {
        let copied = fs::read(archived.join(library)).expect("it is archived");
        assert_eq!(copied, elf(&[dynamic(&[0])]));
    }
    archive.verify().map(drop).expect("it verifies");
    let (hit, reached) = scripted([], || archive.verify().map(drop));
    hit.expect("nothing is scripted").expect("it verifies");
    assert!(
        !reached.contains(&Step::Read),
        "the second verification is a cache hit"
    );
    fs::write(&side, "\t/elsewhere/libpre.so (0x3)\n").expect("it is written");
    let (refused, reached) = scripted([], || archive.verify().map(drop));
    let refused = refused.expect("nothing is scripted");
    assert!(
        !reached.contains(&Step::Read),
        "the refused verification is a cache hit"
    );
    assert!(
        matches!(&refused, Err(Invalid::Resolution(why)) if why.contains("libpre.so")),
        "{refused:?}"
    );
    fs::write(&side, "").expect("it is emptied");
    archive.verify().map(drop).expect("it verifies again");
    flip_keeping_mtime(&archived.join("libb.so.1"));
    let refused = archive.verify().map(drop);
    assert!(
        matches!(&refused, Err(Invalid::Digest(entry)) if entry == "libb.so.1"),
        "{refused:?}"
    );
}

#[test]
fn a_dependency_free_dso_requires_an_executable_entry() {
    let case = Case::new();
    let mut bytes = elf(&[dynamic(&[0])]);
    bytes[16..18].copy_from_slice(&3u16.to_le_bytes());
    bytes[24..32].fill(0);
    assert!(matches!(read(&case, &bytes), Err(Invalid::Elf(why)) if why.contains("entry point")));
}

#[test]
fn a_library_rpath_is_refused_before_publication() {
    let _processes = processes();
    let case = Case::new();
    let library = case.root.join("liba.so");
    for tags in [[DT_RPATH, 0], [DT_AUDIT, 0]] {
        fs::write(&library, elf(&[dynamic(&tags)])).expect("library written");
        let script = format!("#!/bin/sh\necho 'liba.so => {} (0x1)'\n", library.display());
        let (_, worker) = scripted_worker(&case, &script);
        let output = case.root.join("archive");
        let refused = publish(&output, &built_from(&worker)).expect_err("library refused");
        assert_eq!(refused.exit(), crate::exit::Sim::Rejected);
        assert!(!output.exists());
        assert!(matches!(
            refused,
            Error::Invalid(Invalid::Audit | Invalid::Elf(_))
        ));
    }
}

#[test]
fn a_missing_listed_library_is_incomplete_before_writing() {
    let _processes = processes();
    let case = Case::new();
    let (_, worker) = scripted_worker(
        &case,
        "#!/bin/sh\necho 'libmissing.so => /missing-library.so (0x1)'\n",
    );
    let output = case.root.join("archive");
    let failed = publish(&output, &built_from(&worker)).expect_err("library missing");
    assert_eq!(failed.exit(), crate::exit::Sim::Incomplete);
    assert!(
        failed
            .to_string()
            .contains("/missing-library.so is unreadable"),
        "{failed}"
    );
    assert!(!output.exists());
}

#[cfg(target_arch = "x86_64")]
#[test]
fn a_static_worker_runs_from_its_verified_archive() {
    let _processes = processes();
    let case = Case::new();
    let mut bytes = vec![0u8; 120];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&(0x400000u64 + 120).to_le_bytes());
    bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
    bytes[64..68].copy_from_slice(&1u32.to_le_bytes());
    bytes[68..72].copy_from_slice(&5u32.to_le_bytes());
    bytes[80..88].copy_from_slice(&0x400000u64.to_le_bytes());
    bytes[112..120].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes.extend_from_slice(&[0xb8, 60, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05]);
    let size = bytes.len() as u64;
    bytes[96..104].copy_from_slice(&size.to_le_bytes());
    bytes[104..112].copy_from_slice(&size.to_le_bytes());
    let worker = case.root.join("worker");
    fs::write(&worker, bytes).expect("static worker written");
    let mut archive = publish(&case.root.join("archive"), &built_from(&worker)).expect("published");
    assert!(archive.record().loader.is_none());
    let approved = archive.verify().expect("verified");
    assert!(
        approved
            .command()
            .status()
            .expect("static worker runs")
            .success()
    );
    approved.finish().expect("archive verifies after use");
}
