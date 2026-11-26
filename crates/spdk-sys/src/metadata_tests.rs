//! Tests of the link plan and the release check over written metadata and
//! fixture libdirs of empty archive files.
//!
//! A plan test gives [`link_plan`] the static link metadata as text and a
//! libdir it made, and a release test gives [`check_spdk_version`] a header
//! as text; each compares the plan or the refusal. The last tests check the
//! fixture itself: how it names a new libdir and what it refuses to write
//! into. The native link itself runs in the crate's build, from the same
//! module.

use std::fs;
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::string::{String, ToString};
use std::sync::atomic::{AtomicU32, Ordering};
use std::vec::Vec;

use crate::metadata::{LinkPlan, SPDK_VERSION, check_spdk_version, link_plan};

/// libdpdk's static libs in the installed shape: the whole-archive scope,
/// then the same libraries offered dynamically and the system libraries.
const DPDK: &str = "-Wl,--whole-archive -L/opt/spdk/lib -l:librte_bus_pci.a \
     -l:librte_net_ena.a -l:librte_mempool_ring.a -l:librte_ethdev.a -l:librte_eal.a \
     -Wl,--no-whole-archive -Wl,--export-dynamic -Wl,--as-needed -lrte_ethdev -lrte_eal \
     -pthread -lm -ldl -lnuma";

/// SPDK's static libs for its NVMe, DPDK environment and system modules. It
/// names its build tree as search paths, its own and DPDK's libraries by
/// `-l`, and ISA-L's archive by its absolute build-tree path.
const SPDK: &str = "-L/opt/spdk/lib -L/tmp/build/spdk/dpdk/build/lib -lspdk_nvme \
     -lspdk_env_dpdk -lspdk_util -lspdk_log -lrte_eal -lrte_bus_pci -lrte_mempool_ring \
     /tmp/build/spdk/isa-l/.libs/libisal.a -pthread -lrt -luuid -lm -lnuma -lasan";

/// Every archive [`SPDK`] and [`DPDK`] name.
const ARCHIVES: [&str; 10] = [
    "spdk_nvme",
    "spdk_env_dpdk",
    "spdk_util",
    "spdk_log",
    "rte_bus_pci",
    "rte_net_ena",
    "rte_mempool_ring",
    "rte_ethdev",
    "rte_eal",
    "isal",
];

/// Puts an empty `lib<name>.a` in `dir` for each of `archives`.
///
/// # Errors
///
/// `AlreadyExists` when anything is at an archive's path, a link included,
/// so the fixture writes through no path it did not make.
fn populate_libdir(dir: &Path, archives: &[&str]) -> io::Result<()> {
    for archive in archives {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.join(std::format!("lib{archive}.a")))?;
    }
    Ok(())
}

/// Makes `dir` as a new directory without group or other access, holding an
/// empty `lib<name>.a` for each of `archives`.
///
/// # Errors
///
/// `AlreadyExists` when anything is at `dir` or at an archive's path, so the
/// fixture writes only into a directory it made and through no link.
fn make_libdir(dir: &Path, archives: &[&str]) -> io::Result<()> {
    fs::DirBuilder::new().mode(0o700).create(dir)?;
    populate_libdir(dir, archives)
}

/// Makes a new directory under `root`, without group or other access, named
/// for `case`, this process and the first count from `count` on whose name
/// is free. A name that is taken, such as one a run that ended early left
/// behind, is passed over and left as it is.
///
/// # Errors
///
/// The error of the directory's creation, other than `AlreadyExists`.
fn fresh_dir(root: &Path, case: &str, count: u32) -> io::Result<PathBuf> {
    for count in count.. {
        let dir = root.join(std::format!(
            "spdk-sys-metadata-{case}-{}-{count}",
            std::process::id()
        ));
        match fs::DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => return Ok(dir),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::ErrorKind::AlreadyExists.into())
}

/// A new libdir holding an empty `lib<name>.a` for each of `archives`, under
/// the crate's build output directory, which Cargo keeps inside the user's
/// target directory. The case, the process and a count name it, so tests
/// that run together and runs that overlap each make their own.
fn libdir(case: &str, archives: &[&str]) -> PathBuf {
    static MADE: AtomicU32 = AtomicU32::new(0);
    let dir = fresh_dir(
        Path::new(env!("OUT_DIR")),
        case,
        MADE.fetch_add(1, Ordering::Relaxed),
    )
    .unwrap();
    populate_libdir(&dir, archives).unwrap();
    dir
}

fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(ToString::to_string).collect()
}

fn refusal(spdk: &str, dpdk: &str, libdir: &Path) -> String {
    link_plan(spdk, dpdk, libdir, None).expect_err("the link plan accepted the metadata")
}

/// SPDK's archives keep SPDK's order and precede libdpdk's scope in its
/// order; each DPDK library SPDK or libdpdk offers dynamically links once,
/// as the scope's archive; the only dynamic libraries are system libraries,
/// each once.
#[test]
fn the_installed_metadata_links_every_spdk_and_dpdk_archive_whole_in_reported_order() {
    let dir = libdir("ordered", &ARCHIVES);
    let plan = link_plan(SPDK, DPDK, &dir, None).unwrap();
    assert_eq!(
        plan,
        LinkPlan {
            archives: names(&ARCHIVES[..9]),
            bundled: names(&["isal"]),
            system: names(&["rt", "uuid", "m", "numa", "asan", "dl"]),
        }
    );
    let _ = fs::remove_dir_all(&dir);
}

/// The Rust sanitizer runtime supplies `asan`, so only a sanitized plan
/// drops it, and it drops nothing else, whether SPDK's metadata names the
/// library or libdpdk's trailing libraries do.
#[test]
fn only_a_sanitized_plan_drops_the_installs_asan_library() {
    let dir = libdir("sanitized", &ARCHIVES);
    let spdk_without = SPDK.replace(" -lasan", "");
    let dpdk_with = std::format!("{DPDK} -lasan");
    assert!(!spdk_without.contains("asan"));
    for (spdk, dpdk, system) in [
        (SPDK, DPDK, ["rt", "uuid", "m", "numa", "asan", "dl"]),
        (
            spdk_without.as_str(),
            dpdk_with.as_str(),
            ["rt", "uuid", "m", "numa", "dl", "asan"],
        ),
    ] {
        let ordinary = link_plan(spdk, dpdk, &dir, None).unwrap();
        let sanitized = link_plan(spdk, dpdk, &dir, Some("address")).unwrap();
        assert_eq!(ordinary.system, names(&system));
        assert_eq!(sanitized.system, names(&["rt", "uuid", "m", "numa", "dl"]));
        assert_eq!(sanitized.archives, ordinary.archives);
        assert_eq!(sanitized.bundled, ordinary.bundled);
    }
    let _ = fs::remove_dir_all(&dir);
}

/// A DPDK library outside libdpdk's whole-archive scope would link a second,
/// partial DPDK copy, whether SPDK or libdpdk's own trailing libraries name
/// it.
#[test]
fn a_dpdk_library_outside_the_whole_archive_scope_is_refused() {
    let dir = libdir("outside", &ARCHIVES);
    let from_spdk = std::format!("{SPDK} -lrte_net_ixgbe");
    let from_dpdk = std::format!("{DPDK} -lrte_vhost");
    for (spdk, dpdk, library) in [
        (from_spdk.as_str(), DPDK, "rte_net_ixgbe"),
        (SPDK, from_dpdk.as_str(), "rte_vhost"),
    ] {
        assert_eq!(
            refusal(spdk, dpdk, &dir),
            std::format!("{library} is outside libdpdk's static whole-archive scope")
        );
    }
    let _ = fs::remove_dir_all(&dir);
}

/// A link token the plan cannot place is refused by name rather than passed
/// to the linker or dropped. A library name holds ASCII letters, digits and
/// underscores alone, in either spelling and for every family, whether or
/// not the libdir holds a file of the refused name.
#[test]
fn an_unrecognized_metadata_token_is_refused_by_name() {
    let plain = libdir("token", &ARCHIVES);
    let named = libdir(
        "token-files",
        &[
            &ARCHIVES[..],
            &[
                "spdk_a-b",
                "rte_a-b",
                "a-b",
                "spdk_a:b",
                "spdk_a\u{e9}b",
                "a:b",
            ],
        ]
        .concat(),
    );
    // `-lspdk_a/b` would name this file.
    fs::create_dir(named.join("libspdk_a")).unwrap();
    fs::write(named.join("libspdk_a/b.a"), "").unwrap();
    for token in [
        "-Wl,-rpath,/opt/spdk/lib",
        "-l:libspdk_nvme.a",
        "-lfoo.so",
        "-l",
        "/opt/spdk/lib/libisal.so",
        "/opt/spdk/lib/lib.a",
        "-framework",
        "-Wl,--whole-archive",
        "-lspdk_a-b",
        "-lrte_a-b",
        "-lrte_eal.so",
        "/opt/spdk/lib/libspdk_a-b.a",
        "/opt/spdk/lib/librte_a-b.a",
        "/opt/spdk/lib/liba-b.a",
        "-la:b",
        "-lspdk_a:b",
        "-lspdk_a/b",
        "-lspdk_a\u{e9}b",
        "/opt/spdk/lib/libspdk_a:b.a",
        "/opt/spdk/lib/libspdk_a\u{e9}b.a",
        "/opt/spdk/lib/liba:b.a",
    ] {
        let spdk = std::format!("{SPDK} {token}");
        for dir in [&plain, &named] {
            assert_eq!(
                refusal(&spdk, DPDK, dir),
                std::format!("unrecognized pkg-config link token {token}")
            );
        }
    }
    let _ = fs::remove_dir_all(&plain);
    let _ = fs::remove_dir_all(&named);
}

/// libdpdk's whole-archive scope holds only search paths and archives
/// spelled `-l:lib<name>.a` with a library name, so a library named by `-l`,
/// a shared object, an archive named by path and an archive whose name holds
/// another character are each refused by token. A metadata with no archive
/// in a scope links no DPDK at all.
#[test]
fn a_whole_archive_scope_other_than_static_archives_or_none_is_refused() {
    let dir = libdir("scope", &[&ARCHIVES[..], &["rte_a-b", "rte_a:b"]].concat());
    // `-l:libsub/rte_x.a` would name this file.
    fs::create_dir(dir.join("libsub")).unwrap();
    fs::write(dir.join("libsub/rte_x.a"), "").unwrap();
    for entry in [
        "-lrte_eal",
        "-l:librte_eal.so",
        "/opt/spdk/lib/librte_eal.a",
        "-l:lib.a",
        "-l:librte_a-b.a",
        "-l:librte_eal.a:x.a",
        "-l:librte_a:b.a",
        "-l:libsub/rte_x.a",
    ] {
        // The scope keeps `rte_eal`, so only the entry itself can refuse.
        let dpdk = DPDK.replace("-l:librte_eal.a", &std::format!("-l:librte_eal.a {entry}"));
        assert_eq!(
            refusal(SPDK, &dpdk, &dir),
            std::format!(
                "libdpdk's whole-archive scope holds {entry}, not a search path or a -l:lib<name>.a archive whose name holds ASCII letters, digits and underscores alone"
            )
        );
    }
    for dpdk in [
        "-lrte_eal -lm",
        "-Wl,--whole-archive -L/opt/spdk/lib -Wl,--no-whole-archive -lm",
    ] {
        assert_eq!(
            refusal("-lspdk_nvme", dpdk, &dir),
            "libdpdk's static metadata holds no archive in a whole-archive scope"
        );
    }
    let _ = fs::remove_dir_all(&dir);
}

/// Each archive the plan links, SPDK, DPDK or bundled, must be a file in
/// libdpdk's libdir.
#[test]
fn a_missing_static_archive_is_refused_by_path() {
    for missing in ["spdk_util", "rte_net_ena", "isal"] {
        let present: Vec<&str> = ARCHIVES.into_iter().filter(|a| *a != missing).collect();
        let dir = libdir(missing, &present);
        assert_eq!(
            refusal(SPDK, DPDK, &dir),
            std::format!(
                "missing static archive {}",
                dir.join(std::format!("lib{missing}.a")).display()
            )
        );
        let _ = fs::remove_dir_all(&dir);
    }
}

/// The pinned release's header passes; any other major, minor or patch
/// field, or a header missing one, is refused naming the header.
#[test]
fn an_spdk_release_other_than_the_pinned_one_is_refused() {
    let header = Path::new("/opt/spdk/include/spdk/version.h");
    let declare = |[major, minor, patch]: [&str; 3]| {
        std::format!(
            "#ifndef SPDK_VERSION_H\n#define SPDK_VERSION_H\n\
             #define SPDK_VERSION_MAJOR\t{major}\n#define SPDK_VERSION_MINOR\t{minor}\n\
             #define SPDK_VERSION_PATCH\t{patch}\n#define SPDK_VERSION_SUFFIX\t\"\"\n\
             #define SPDK_VERSION_NUM(major, minor, patch) \\\n"
        )
    };
    let refused = |found: [&str; 3]| {
        Err(std::format!(
            "{} declares SPDK {found:?}, expected {SPDK_VERSION:?}",
            header.display()
        ))
    };
    assert_eq!(check_spdk_version(header, &declare(SPDK_VERSION)), Ok(()));
    for other in [
        ["24", "5", "1"],
        ["25", "1", "0"],
        ["25", "5", "0"],
        ["25", "05", "1"],
    ] {
        assert_eq!(check_spdk_version(header, &declare(other)), refused(other));
    }
    let unpatched = declare(SPDK_VERSION).replace("#define SPDK_VERSION_PATCH\t1\n", "");
    assert!(!unpatched.contains("SPDK_VERSION_PATCH"));
    assert_eq!(
        check_spdk_version(header, &unpatched),
        refused(["25", "5", ""])
    );
    // A longer identifier that begins with a field's name is another macro.
    for (exact, longer, found) in [
        (
            "#define SPDK_VERSION_MAJOR\t25\n",
            "#define SPDK_VERSION_MAJOR25\n",
            ["", "5", "1"],
        ),
        (
            "#define SPDK_VERSION_MINOR\t5\n",
            "#define SPDK_VERSION_MINOR5\n",
            ["25", "", "1"],
        ),
        (
            "#define SPDK_VERSION_PATCH\t1\n",
            "#define SPDK_VERSION_PATCH1\n",
            ["25", "5", ""],
        ),
    ] {
        let pinned = declare(SPDK_VERSION);
        assert!(pinned.contains(exact));
        assert_eq!(
            check_spdk_version(header, &pinned.replace(exact, longer)),
            refused(found)
        );
    }
    // The exact definition decides, wherever a longer identifier stands.
    for (longer, other) in [
        ("#define SPDK_VERSION_MAJOR25\n", ["24", "5", "1"]),
        ("#define SPDK_VERSION_MINOR5\n", ["25", "4", "1"]),
        ("#define SPDK_VERSION_PATCH1\n", ["25", "5", "0"]),
    ] {
        let text = std::format!("{longer}{}", declare(other));
        assert_eq!(check_spdk_version(header, &text), refused(other));
    }
    let strings = std::format!(
        "#define SPDK_VERSION_MAJOR_STRING \"25\"\n#define SPDK_VERSION_PATCH_LEVEL 9\n{}",
        declare(SPDK_VERSION)
    );
    assert_eq!(check_spdk_version(header, &strings), Ok(()));
    let spaced = declare(SPDK_VERSION).replace('\t', "  ");
    assert_eq!(check_spdk_version(header, &spaced), Ok(()));
}

/// A scope archive whose name reaches a file outside the libdir is refused
/// by token: the name is a path here, with the directory it steps through
/// and the file it reaches both present, so only the name rule refuses it.
#[test]
fn a_scope_archive_name_that_leaves_the_libdir_is_refused() {
    let root = libdir("traversal", &[]);
    let dir = root.join("install");
    make_libdir(&dir, &ARCHIVES).unwrap();
    fs::create_dir(dir.join("lib")).unwrap();
    fs::write(root.join("outside.a"), "").unwrap();
    let entry = "-l:lib/../../outside.a";
    assert!(dir.join("lib/../../outside.a").is_file());
    let dpdk = DPDK.replace("-l:librte_eal.a", &std::format!("-l:librte_eal.a {entry}"));
    assert_eq!(
        refusal(SPDK, &dpdk, &dir),
        std::format!(
            "libdpdk's whole-archive scope holds {entry}, not a search path or a -l:lib<name>.a archive whose name holds ASCII letters, digits and underscores alone"
        )
    );
    let _ = fs::remove_dir_all(&root);
}

/// A library name may hold digits and uppercase letters, in every spelling:
/// a system library, SPDK archives named by `-l` and by path, and a scope
/// archive.
#[test]
fn a_library_name_with_digits_and_uppercase_letters_plans_in_every_spelling() {
    let dir = libdir(
        "names",
        &[&ARCHIVES[..], &["spdk_Nvme2", "spdk_Sock3", "rte_Net4"]].concat(),
    );
    let spdk = std::format!("{SPDK} -lspdk_Nvme2 /opt/spdk/lib/libspdk_Sock3.a -lfuse3 -lZ9");
    let dpdk = DPDK.replace("-l:librte_eal.a", "-l:librte_eal.a -l:librte_Net4.a");
    let plan = link_plan(&spdk, &dpdk, &dir, None).unwrap();
    let mut archives = names(&ARCHIVES[..4]);
    archives.extend(names(&["spdk_Nvme2", "spdk_Sock3"]));
    archives.extend(names(&ARCHIVES[4..9]));
    archives.push("rte_Net4".to_string());
    assert_eq!(plan.archives, archives);
    assert_eq!(plan.bundled, names(&["isal"]));
    assert_eq!(
        plan.system,
        names(&["rt", "uuid", "m", "numa", "asan", "fuse3", "Z9", "dl"])
    );
    let _ = fs::remove_dir_all(&dir);
}

/// The fixture makes its directory and each archive file itself. A path
/// that already exists is refused before any write and is left as it was:
/// an empty directory, a directory holding a link at an archive's path, a
/// link at the directory's path, and an archive named twice.
#[test]
fn a_fixture_directory_that_already_exists_is_refused_unwritten() {
    use std::os::unix::fs::PermissionsExt;
    let root = libdir("occupied", &[]);
    let sentinel = root.join("sentinel");
    fs::write(&sentinel, "kept").unwrap();
    let refused = |dir: &Path, archives: &[&str]| make_libdir(dir, archives).unwrap_err().kind();

    // An existing empty directory: only the directory's exclusive creation refuses it.
    let empty = root.join("empty");
    fs::create_dir(&empty).unwrap();
    assert_eq!(refused(&empty, &["isal"]), io::ErrorKind::AlreadyExists);
    assert_eq!(fs::read_dir(&empty).unwrap().count(), 0);

    // An existing directory holding a link at an archive's path.
    let install = root.join("install");
    fs::create_dir(&install).unwrap();
    std::os::unix::fs::symlink(&sentinel, install.join("libisal.a")).unwrap();
    assert_eq!(
        populate_libdir(&install, &["isal"]).map_err(|error| error.kind()),
        Err(io::ErrorKind::AlreadyExists)
    );
    assert_eq!(fs::read_link(install.join("libisal.a")).unwrap(), sentinel);

    // A link at the directory's path.
    let linked = root.join("linked");
    std::os::unix::fs::symlink(&empty, &linked).unwrap();
    assert_eq!(refused(&linked, &["isal"]), io::ErrorKind::AlreadyExists);
    assert_eq!(fs::read_link(&linked).unwrap(), empty);
    assert_eq!(fs::read_dir(&empty).unwrap().count(), 0);

    // A new directory and an archive named twice: the second creation of the file refuses.
    let twice = root.join("twice");
    assert_eq!(
        refused(&twice, &["isal", "isal"]),
        io::ErrorKind::AlreadyExists
    );
    let made = fs::metadata(&twice).unwrap();
    assert!(made.is_dir());
    assert_eq!(made.permissions().mode() & 0o077, 0);
    assert_eq!(fs::metadata(twice.join("libisal.a")).unwrap().len(), 0);

    assert_eq!(fs::read_to_string(&sentinel).unwrap(), "kept");
    let _ = fs::remove_dir_all(&root);
}

/// A libdir name that is taken is passed over: the fixture makes the next
/// free name and leaves the taken one, and what it holds, as they were.
#[test]
fn a_taken_fixture_name_is_passed_over_and_left_as_it_was() {
    let root = libdir("allocation", &[]);
    let name = |count: u32| {
        root.join(std::format!(
            "spdk-sys-metadata-case-{}-{count}",
            std::process::id()
        ))
    };
    fs::create_dir(name(7)).unwrap();
    let sentinel = name(7).join("sentinel");
    fs::write(&sentinel, "kept").unwrap();
    std::os::unix::fs::symlink(&sentinel, name(8)).unwrap();
    let made = fresh_dir(&root, "case", 7).unwrap();
    assert_eq!(made, name(9));
    assert_eq!(fs::read_dir(&made).unwrap().count(), 0);
    assert_eq!(fs::read_dir(name(7)).unwrap().count(), 1);
    assert_eq!(fs::read_to_string(&sentinel).unwrap(), "kept");
    assert_eq!(fs::read_link(name(8)).unwrap(), sentinel);
    // A root that cannot hold a directory is an error, not another try.
    let missing = fresh_dir(&root.join("absent"), "case", 0).unwrap_err();
    assert_eq!(missing.kind(), io::ErrorKind::NotFound);
    let _ = fs::remove_dir_all(&root);
}

/// An SPDK or DPDK archive SPDK's metadata names by path is the library of
/// its file name: a DPDK library outside libdpdk's scope meets the
/// second-copy refusal, one inside it links once as the scope's archive, and
/// an SPDK archive links whole. Only other archives, such as ISA-L's, link
/// plainly.
#[test]
fn an_spdk_or_dpdk_archive_named_by_path_links_whole_or_is_refused() {
    let dir = libdir(
        "by-path",
        &[&ARCHIVES[..], &["rte_net_ixgbe", "spdk_sock"]].concat(),
    );
    assert_eq!(
        refusal(
            &std::format!("{SPDK} /tmp/build/spdk/dpdk/build/lib/librte_net_ixgbe.a"),
            DPDK,
            &dir
        ),
        "rte_net_ixgbe is outside libdpdk's static whole-archive scope"
    );
    let spdk = std::format!(
        "{SPDK} /tmp/build/spdk/dpdk/build/lib/librte_eal.a /tmp/build/spdk/build/lib/libspdk_sock.a"
    );
    let plan = link_plan(&spdk, DPDK, &dir, None).unwrap();
    let mut archives = names(&ARCHIVES[..4]);
    archives.push("spdk_sock".to_string());
    archives.extend(names(&ARCHIVES[4..9]));
    assert_eq!(plan.archives, archives);
    assert_eq!(plan.bundled, names(&["isal"]));
    let _ = fs::remove_dir_all(&dir);
}
