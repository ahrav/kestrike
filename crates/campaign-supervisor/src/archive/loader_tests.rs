//! The program interpreter's `--list` output: which lines name an archived
//! library and which refuse the listing; and the environment a use's
//! command runs in.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;

use super::loader::{command, libraries};
use super::{Invalid, LIBRARY_BOUND};
use crate::store::fixture::processes;

const LOADER: &str = "/lib64/ld-linux-x86-64.so.2";
const LISTING: &str = concat!(
    "\tlinux-vdso.so.1 (0x00007ffc)\n",
    "\tlinux-vdso.so.1 =>  (0x00007ffd)\n",
    "\tlibm.so.6 => /lib/libm.so.6 (0x00007eff)\n",
    "\tlibc.so.6 => /lib/libc.so.6 (0x00007f00)\n",
    "\t/lib64/ld-linux-x86-64.so.2 (0x00007f01)\n",
    "\n",
);

/// The vDSO, in either form, the interpreter itself and an empty line are
/// left out, and each library resolved by name keeps its path; a library
/// mapped by its path, found nowhere, found at no path, listed twice or
/// listed bare, a truncated row and a row named like the vDSO but not it
/// are refused, and so is a listing of more libraries than an archive
/// holds.
#[test]
fn the_listing_admits_only_libraries_resolved_by_name() {
    let found = libraries(LISTING, LOADER).expect("the listing is admitted");
    let expected = BTreeMap::from([
        ("libc.so.6".to_owned(), "/lib/libc.so.6".to_owned()),
        ("libm.so.6".to_owned(), "/lib/libm.so.6".to_owned()),
    ]);
    assert_eq!(found, expected);
    for (label, line, reason) in [
        (
            "preloaded",
            "\t/usr/lib/libpreload.so (0x00007f02)\n",
            "mapped by its path",
        ),
        ("missing", "\tlibm.so.6 => not found\n", "found nowhere"),
        (
            "empty path",
            "\tlibm.so.6 =>  (0x00007f03)\n",
            "found nowhere",
        ),
        (
            "twice",
            "\tlibc.so.6 => /usr/lib/libc.so.6 (0x00007f04)\n",
            "listed twice",
        ),
        ("static", "statically linked\n", "needs no library"),
        ("bare", "\tlibz.so.1 (0x00007f05)\n", "listed at no path"),
        ("truncated", "\tlibz.so\n", "listed at no path"),
        (
            "vDSO-like bare",
            "\tlinux-vdso-helper.so.1 (0x00007f06)\n",
            "listed at no path",
        ),
        (
            "vDSO-like empty path",
            "\tlinux-vdso-helper.so.1 =>  (0x00007f07)\n",
            "found nowhere",
        ),
    ] {
        let refused = libraries(&format!("{LISTING}{line}"), LOADER);
        assert!(
            matches!(&refused, Err(Invalid::Resolution(why)) if why.contains(reason)),
            "{label}: {refused:?}"
        );
    }
    let rows = |count: usize| -> String {
        (0..count)
            .map(|at| format!("\tlib{at}.so => /lib/lib{at}.so (0x1)\n"))
            .collect()
    };
    let bounded = libraries(&rows(LIBRARY_BOUND), LOADER).expect("the bound is admitted");
    assert_eq!(bounded.len(), LIBRARY_BOUND);
    let refused = libraries(&rows(LIBRARY_BOUND + 1), LOADER);
    assert!(
        matches!(&refused, Err(Invalid::Resolution(why)) if why.contains("more than 256")),
        "{refused:?}"
    );
}

/// A use's command drops every inherited `LD_*` variable, a preload, an
/// audit module and a foreign library path included, and the loader's
/// tunables, keeps every other
/// variable, and sets the library path it names.
#[test]
fn a_command_drops_every_inherited_loader_variable() {
    let _processes = processes();
    let vars = [
        ("GLIBC_TUNABLES", "glibc.cpu.hwcaps=-AVX2"),
        ("LD_PRELOAD", "/tmp/preload.so"),
        ("LD_AUDIT", "/tmp/audit.so"),
        ("LD_LIBRARY_PATH", "/foreign"),
        ("KEPT", "value"),
    ]
    .map(|(name, value)| (OsString::from(name), OsString::from(value)));
    let ran = command(
        Path::new("/usr/bin/env"),
        Some("/archive/lib".as_ref()),
        vars.into_iter(),
    )
    .output()
    .expect("env runs");
    assert!(ran.status.success());
    let mut seen: Vec<String> = String::from_utf8(ran.stdout)
        .expect("env prints UTF-8")
        .lines()
        .map(str::to_owned)
        .collect();
    seen.sort();
    assert_eq!(seen, ["KEPT=value", "LD_LIBRARY_PATH=/archive/lib"]);
}

use super::loader::{resolve_before, system_preload};
use std::time::Duration;

#[test]
fn system_preloads_refuse_both_paths_and_bare_names() {
    for bytes in [b"".as_slice(), b" \t\n# comment\n"] {
        system_preload(bytes).expect("empty preload");
    }
    for bytes in [
        b"libexample.so".as_slice(),
        b"/lib/libexample.so\n",
        b"# comment\nlibexample.so # note",
    ] {
        assert!(matches!(system_preload(bytes), Err(Invalid::Resolution(_))));
    }
}

#[test]
fn listing_overflow_is_refused_and_deadlines_are_incomplete() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    let _processes = crate::store::fixture::processes();
    let case = crate::store::fixture::Case::new();
    let path = case.root.join("loader");
    for (script, deadline, reason) in [
        (
            "#!/bin/sh\nexec head -c 16777217 /dev/zero\n",
            Duration::from_secs(10),
            "output passes",
        ),
        (
            "#!/bin/sh\nexec sleep 30\n",
            Duration::from_millis(50),
            "deadline",
        ),
    ] {
        fs::write(&path, script).expect("fixture written");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("fixture executable");
        let failed = resolve_before(
            path.to_str().expect("UTF-8"),
            Path::new("/worker"),
            None,
            deadline,
        );
        match failed {
            Err(Invalid::Io(error)) if reason == "deadline" => {
                assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
                assert_eq!(Invalid::Io(error).exit(false), crate::exit::Sim::Incomplete);
            }
            Err(Invalid::Resolution(why)) if reason != "deadline" => assert!(why.contains(reason)),
            other => panic!("{reason}: {other:?}"),
        }
    }
}
