use std::path::Path;
use std::string::{String, ToString};
use std::vec::Vec;

use crate::select::{
    INCLUDE_ROOT, Install, flags_line, include_root, matching, recorded, sanitizer,
};

const X86: &str = "x86_64-unknown-linux-gnu";
const NATIVE: &str = "x86_64-unknown-linux-gnu-native";
const NATIVE_ASAN: &str = "x86_64-unknown-linux-gnu-native-asan";
const PORTABLE: &str = "x86_64-unknown-linux-gnu-x86-64-v2";

fn flags(include: &str, march: &str) -> Vec<String> {
    [include, "-include", "rte_config.h", march, "-mrtm"]
        .iter()
        .map(ToString::to_string)
        .collect()
}

fn installs() -> Vec<Install> {
    recorded(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src/generated")).unwrap()
}

fn name(install: &Install) -> String {
    install
        .record
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned()
}

fn selected(target: &str, sanitizer: Option<&str>, cflags: &[String]) -> Vec<String> {
    matching(&flags_line(target, sanitizer, cflags), &installs())
        .into_iter()
        .map(name)
        .collect()
}

/// The include root stands for the install's prefix alone, so the same
/// install at another prefix selects the record of its headers, in either
/// configuration.
#[test]
fn a_relocated_install_selects_the_record_of_its_flags_and_sanitizer() {
    for prefix in ["/opt/spdk-asan", "/home/builder/spdk/install", "/usr/local"] {
        let native = flags(&std::format!("-I{prefix}/include"), "-march=native");
        assert_eq!(selected(X86, None, &native), [NATIVE], "{prefix}");
        assert_eq!(
            selected(X86, Some("address"), &native),
            [NATIVE_ASAN],
            "{prefix}"
        );
        let portable = flags(&std::format!("-I{prefix}/include"), "-march=x86-64-v2");
        assert_eq!(selected(X86, None, &portable), [PORTABLE], "{prefix}");
    }
}

#[test]
fn another_core_target_or_sanitizer_selects_no_record() {
    let mut extra = flags("-I/usr/local/include", "-march=native");
    extra.push("-DNDEBUG".to_string());
    for (target, sanitizer, cflags) in [
        (X86, None, flags("-I/usr/local/include", "-march=x86-64-v3")),
        (
            X86,
            Some("address"),
            flags("-I/usr/local/include", "-march=x86-64-v2"),
        ),
        (
            X86,
            Some("thread"),
            flags("-I/usr/local/include", "-march=native"),
        ),
        (X86, None, extra),
        (
            "aarch64-unknown-linux-gnu",
            None,
            flags("-I/opt/spdk-v25.05.1-x86-64-v2/include", "-march=x86-64-v2"),
        ),
    ] {
        assert_eq!(
            selected(target, sanitizer, &cflags),
            Vec::<String>::new(),
            "{target} {sanitizer:?} {cflags:?}"
        );
    }
}

#[test]
fn no_two_records_name_one_install() {
    let installs = installs();
    assert_eq!(installs.len(), 5);
    for install in &installs {
        assert_eq!(
            matching(&install.target, &installs),
            [install],
            "{}",
            install.target
        );
        assert!(
            !install.target.contains(INCLUDE_ROOT),
            "{} records a real include root",
            install.target
        );
    }
    let asan: Vec<_> = installs
        .iter()
        .filter(|install| install.target.contains(" Sanitizer: address. "))
        .map(name)
        .collect();
    assert_eq!(asan, [NATIVE_ASAN]);
}

#[test]
fn the_install_s_flags_open_with_its_include_root_once() {
    let include = "/usr/local/include";
    assert_eq!(
        include_root(&flags("-I/usr/local/include", "-march=native"), include),
        Ok(())
    );
    let mut twice = flags("-I/usr/local/include", "-march=native");
    twice.push("-I/usr/local/include".to_string());
    let mut later = flags("-I/usr/local/include", "-march=native");
    later.insert(0, "-DX".to_string());
    for (cflags, expected) in [
        (
            flags("-I/opt/other/include", "-march=native"),
            "name its include root -I/usr/local/include 0 times",
        ),
        (twice, "2 times"),
        (later, "1 times, and the flags open with Some(\"-DX\")"),
        (Vec::new(), "open with None"),
    ] {
        let reason = include_root(&cflags, include).unwrap_err();
        assert!(reason.contains(expected), "{cflags:?}: {reason}");
    }
}

#[test]
fn an_asan_install_needs_rust_address_and_an_ordinary_install_takes_rust_only_sanitizers() {
    let asan_libs =
        "-L/opt/asan/lib -Wl,--whole-archive -l:librte_eal.a -Wl,--no-whole-archive -lasan -lm";
    let plain_libs =
        "-L/usr/local/lib -Wl,--whole-archive -l:librte_eal.a -Wl,--no-whole-archive -lm";
    let asan_rust = ["-Zsanitizer=address", "-Cforce-frame-pointers=yes"]
        .map(String::from)
        .to_vec();
    let plain_rust = ["-Copt-level=1"].map(String::from).to_vec();
    assert_eq!(sanitizer(asan_libs, &asan_rust), Ok(Some("address")));
    assert_eq!(sanitizer(plain_libs, &plain_rust), Ok(None));
    assert_eq!(sanitizer(plain_libs, &[]), Ok(None));
    let native_only = sanitizer(asan_libs, &plain_rust).unwrap_err();
    assert!(native_only.contains("links -lasan") && native_only.contains("no sanitizer"));
    assert_eq!(sanitizer(plain_libs, &asan_rust), Ok(None));
    let split = ["-Z", "sanitizer=address", "-C", "force-frame-pointers=yes"]
        .map(String::from)
        .to_vec();
    assert_eq!(sanitizer(asan_libs, &split), Ok(Some("address")));
    assert_eq!(sanitizer(plain_libs, &split), Ok(None));
    let thread = ["-Zsanitizer=thread".to_string()];
    assert_eq!(sanitizer(plain_libs, &thread), Ok(None));
    let thread = sanitizer(asan_libs, &thread).unwrap_err();
    assert!(thread.contains("[\"thread\"]"), "{thread}");
    let two = sanitizer(asan_libs, &["-Zsanitizer=address,leak".to_string()]).unwrap_err();
    assert!(two.contains("[\"address\", \"leak\"]"), "{two}");
    let twice = sanitizer(
        asan_libs,
        &["-Zsanitizer=address", "-Zsanitizer=address"].map(String::from),
    )
    .unwrap_err();
    assert!(twice.contains("[\"address\", \"address\"]"), "{twice}");
}

/// The `sha256sum` digest of each file, by file name, as the build script takes it.
fn digests(files: &[std::path::PathBuf]) -> Vec<(String, String)> {
    crate::select::sha256sums(files).unwrap()
}

/// A record's lineage lines for `archives`, as the controlled native build writes them.
fn lineage_text(archives: &[(String, String)]) -> String {
    let mut text = std::format!(
        "Target: x. Flags: -Inative\nHeader digest: {}\nOutput: o\nSource: SPDK a DPDK b\nPatches: {}\n\
         Build inputs: {}\nCompilers: GCC: (GNU) 11.5.0\nConfigure: {}\n",
        "1".repeat(64),
        "2".repeat(64),
        "3".repeat(64),
        "4".repeat(64)
    );
    for (name, digest) in archives {
        text.push_str(&std::format!("Archive: {digest}  {name}\n"));
    }
    text
}

/// In a temporary install, the lineage `native/install.sh measure` takes admits the archives it measured,
/// and one archive changed while the headers stay byte for byte the same is refused, naming that archive; so
/// is a linked archive the record does not list.
#[test]
fn a_changed_archive_under_unchanged_headers_fails_its_lineage() {
    let root = std::env::temp_dir().join(std::format!("spdk-sys-lineage-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let (lib, include) = (root.join("lib"), root.join("include"));
    std::fs::create_dir_all(&lib).unwrap();
    std::fs::create_dir_all(include.join("spdk")).unwrap();
    std::fs::write(
        include.join("spdk/config.h"),
        "#define SPDK_CONFIG_ARCH native\n",
    )
    .unwrap();
    std::fs::write(
        include.join("rte_build_config.h"),
        "#define RTE_MACHINE native\n",
    )
    .unwrap();
    let header = include.join("spdk/version.h");
    std::fs::write(&header, "#define SPDK_VERSION_MAJOR 25\n").unwrap();
    std::fs::write(root.join("x.c"), "int x;\n").unwrap();
    let run = |command: &mut std::process::Command| assert!(command.status().unwrap().success());
    run(std::process::Command::new("cc")
        .arg("-c")
        .arg(root.join("x.c"))
        .arg("-o")
        .arg(root.join("x.o")));
    let archives: Vec<_> = ["libspdk_nvme.a", "librte_eal.a", "librte_bus_pci.a"]
        .iter()
        .map(|name| {
            let path = lib.join(name);
            run(std::process::Command::new("ar")
                .arg("rcs")
                .arg(&path)
                .arg(root.join("x.o")));
            path
        })
        .collect();
    let measured = std::process::Command::new("bash")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("native/install.sh"))
        .args(["measure"])
        .args([&lib, &include, &root])
        .output()
        .unwrap();
    assert!(
        measured.status.success(),
        "{}",
        std::string::String::from_utf8_lossy(&measured.stderr)
    );
    let record = std::format!(
        "Target: x. Flags: -Inative\nHeader digest: {}\nOutput: o\nSource: SPDK a DPDK b\n{}",
        "1".repeat(64),
        // The temporary install holds no build inputs; the controlled build's record names their digest.
        std::string::String::from_utf8(measured.stdout)
            .unwrap()
            .replace(
                "Build inputs: unrecorded",
                &std::format!("Build inputs: {}", "3".repeat(64))
            )
    );
    let lineage = crate::select::lineage(&record).unwrap().unwrap();
    assert_eq!(
        lineage.archives,
        digests(&archives).into_iter().collect(),
        "the writer's archive lines are the reader's digests"
    );
    let path = Path::new("installs/test");
    assert_eq!(
        crate::select::check_archives(path, &lineage, &digests(&archives)),
        Ok(())
    );
    let headers = std::fs::read(&header).unwrap();
    let mut tampered = std::fs::read(&archives[1]).unwrap();
    tampered.push(0);
    std::fs::write(&archives[1], tampered).unwrap();
    assert_eq!(
        std::fs::read(&header).unwrap(),
        headers,
        "the headers stay identical"
    );
    let refused = crate::select::check_archives(path, &lineage, &digests(&archives)).unwrap_err();
    assert!(
        refused.starts_with("the linked archive librte_eal.a has sha256"),
        "{refused}"
    );
    assert!(
        refused.contains("a changed archive needs a new controlled build record"),
        "{refused}"
    );
    let extra = lib.join("librte_net_ena.a");
    std::fs::write(&extra, "!<arch>\n").unwrap();
    let unlisted = crate::select::check_archives(path, &lineage, &digests(&[extra])).unwrap_err();
    assert_eq!(
        unlisted,
        "installs/test records no digest for the linked archive librte_net_ena.a"
    );
    std::fs::remove_dir_all(&root).unwrap();
}

/// A record without lineage lines parses with none; a partial or malformed lineage refuses the record.
#[test]
fn a_lineage_needs_every_line_once_and_a_digest_per_archive() {
    assert_eq!(
        crate::select::lineage("Target: x\nHeader digest: d\nOutput: o\n"),
        Ok(None)
    );
    let archive = [("librte_eal.a".to_string(), "a".repeat(64))];
    let whole = lineage_text(&archive);
    assert!(crate::select::lineage(&whole).unwrap().is_some());
    for (broken, reason) in [
        (
            whole.replace("Source: SPDK a DPDK b\n", ""),
            "`Source: ` 0 times",
        ),
        (whole.clone() + "Patches: x\n", "`Patches: ` 2 times"),
        (
            whole.replace(&"a".repeat(64), "short"),
            "names no sha256 and file",
        ),
        (
            whole.clone() + &std::format!("Archive: {}  librte_eal.a\n", "b".repeat(64)),
            "repeats an archive",
        ),
        (lineage_text(&[]), "records no `Archive: ` line"),
    ] {
        let refused = crate::select::lineage(&broken).unwrap_err();
        assert!(refused.contains(reason), "{reason}: {refused}");
    }
    assert!(
        crate::select::lineage(&whole.replace("Source: SPDK a DPDK b", "Source: "))
            .unwrap_err()
            .contains("`Source: ` is empty")
    );
    assert!(
        crate::select::lineage(&whole.replace(&"a".repeat(64), &"A".repeat(64)))
            .unwrap_err()
            .contains("names no sha256"),
        "sha256sum prints lowercase digests"
    );
    assert!(!installs().is_empty(), "every checked-in record parses");
}

/// `native/install.sh build` records the version of the compiler `CC` selects, the one SPDK's
/// `configure` hands to `detect_cc.sh`, in `build-inputs.txt`. The stubs stand in for `git`, `make`
/// and the compilers up to the install step; the build then stops at `measure`, which finds no
/// headers in the empty prefix, after the build inputs are on disk.
#[test]
fn the_build_records_the_version_of_the_compiler_cc_selects() {
    let root =
        std::env::temp_dir().join(std::format!("spdk-sys-build-inputs-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let (stub, prefix) = (root.join("stub"), root.join("prefix"));
    std::fs::create_dir_all(&stub).unwrap();
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("native/install.sh");
    let text = std::fs::read_to_string(&script).unwrap();
    let commit = |name: &str| {
        text.lines()
            .find_map(|line| {
                line.strip_prefix(name)
                    .and_then(|rest| rest.strip_prefix('='))
            })
            .unwrap()
            .to_string()
    };
    let (spdk, dpdk) = (commit("SPDK_COMMIT"), commit("DPDK_COMMIT"));
    let executable = |name: &str, body: &str| {
        use std::os::unix::fs::PermissionsExt;
        let path = stub.join(name);
        std::fs::write(&path, std::format!("#!/usr/bin/env bash\n{body}")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    };
    executable(
        "git",
        &std::format!(
            "case \"$*\" in\n  clone*) mkdir -p \"${{@: -1}}\"; printf '#!/usr/bin/env bash\\n' > \"${{@: -1}}/configure\"; \
             chmod +x \"${{@: -1}}/configure\" ;;\n  *dpdk\\ rev-parse*) echo {dpdk} ;;\n  *rev-parse*) echo {spdk} ;;\nesac\n"
        ),
    );
    executable("make", "");
    executable("nproc", "echo 1\n");
    executable("cc", "echo 'stub cc 1.0'\n");
    executable("stubclang", "echo 'stub clang 2.0'\n");
    let path = std::format!("{}:{}", stub.display(), std::env::var("PATH").unwrap());
    let built = std::process::Command::new("bash")
        .arg(&script)
        .arg("build")
        .arg(&prefix)
        .env("PATH", path)
        .env("CC", "stubclang")
        .output()
        .unwrap();
    let inputs = std::fs::read_to_string(prefix.join("share/spdk-sys/build-inputs.txt"))
        .unwrap_or_else(|error| {
            std::panic!(
                "{error}: {}",
                std::string::String::from_utf8_lossy(&built.stderr)
            )
        });
    assert!(
        inputs.contains("\ncc stub clang 2.0\n"),
        "the compiler line names the compiler CC selects:\n{inputs}"
    );
    assert!(inputs.contains("\nenv CC=stubclang "), "{inputs}");
    std::fs::remove_dir_all(&root).unwrap();
}

/// `native/install.sh` runs from `crates/spdk-sys`, so a relative PREFIX, LIBDIR, INCLUDEDIR or DIR would
/// resolve against that directory and, for `build`, reach SPDK's `configure` from the build tree; a
/// `--prefix` or `--libdir` among the configure options would move the installation away from the PREFIX
/// the build then measures; and `measure` hashes every archive under `PREFIX/lib`, so an occupied PREFIX
/// would lend an earlier install's archives to this build's lineage. The script refuses each before it
/// clones, measures or writes anything.
#[test]
fn a_relative_path_a_destination_override_or_an_occupied_prefix_is_refused_before_any_work() {
    let root = std::env::temp_dir().join(std::format!("spdk-sys-relative-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let stub = root.join("stub");
    std::fs::create_dir_all(&stub).unwrap();
    let marker = root.join("git-ran");
    {
        use std::os::unix::fs::PermissionsExt;
        let git = stub.join("git");
        std::fs::write(
            &git,
            std::format!("#!/usr/bin/env bash\ntouch {}\nexit 1\n", marker.display()),
        )
        .unwrap();
        std::fs::set_permissions(&git, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("native/install.sh");
    let path = std::format!("{}:{}", stub.display(), std::env::var("PATH").unwrap());
    for (args, reason) in [
        (
            &["build", "opt/spdk", "--target-arch=x86-64-v2"][..],
            "is relative; name an absolute path",
        ),
        (
            &["record", "opt/spdk"],
            "is relative; name an absolute path",
        ),
        (
            &["measure", "/abs/lib", "include", "/abs/dir"],
            "is relative; name an absolute path",
        ),
        (
            &["build", "/opt/spdk", "--enable-asan", "--prefix=/elsewhere"],
            "the configure option --prefix=/elsewhere moves the installation away from PREFIX",
        ),
        (
            &["build", "/opt/spdk", "--libdir=/elsewhere/lib"],
            "the configure option --libdir=/elsewhere/lib moves the installation away from PREFIX",
        ),
    ] {
        let refused = std::process::Command::new("bash")
            .arg(&script)
            .args(args)
            .env("PATH", &path)
            .output()
            .unwrap();
        let stderr = std::string::String::from_utf8_lossy(&refused.stderr);
        assert!(!refused.status.success(), "{args:?}: {stderr}");
        assert!(stderr.contains(reason), "{args:?}: {stderr}");
    }
    let occupied = root.join("occupied");
    std::fs::create_dir_all(occupied.join("lib")).unwrap();
    std::fs::write(occupied.join("lib/librte_net_stale.a"), "!<arch>\n").unwrap();
    let refused = std::process::Command::new("bash")
        .arg(&script)
        .arg("build")
        .arg(&occupied)
        .env("PATH", &path)
        .output()
        .unwrap();
    let stderr = std::string::String::from_utf8_lossy(&refused.stderr);
    assert!(!refused.status.success(), "{stderr}");
    assert!(
        stderr.contains(&std::format!(
            "{} is occupied; the controlled build installs into an empty PREFIX",
            occupied.display()
        )),
        "{stderr}"
    );
    assert!(!marker.exists(), "a refused build reached git clone");
    std::fs::remove_dir_all(&root).unwrap();
}

/// `native/install.sh record` checks the controlled build's `build.txt` for exactly one nonempty `Source`
/// line, the line `select::lineage` requires once, and holds an install to the include-root rule its
/// readers apply (`select::include_root`, `scripts/rust-lane.sh`): the flags open with `-I<includedir>`
/// and name it once. Either failure refuses the install before anything is measured or written.
#[test]
fn record_checks_the_build_s_source_line_and_the_include_root_before_measuring() {
    let root = std::env::temp_dir().join(std::format!("spdk-sys-record-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let (pc, share) = (root.join("lib/pkgconfig"), root.join("share/spdk-sys"));
    std::fs::create_dir_all(&pc).unwrap();
    std::fs::create_dir_all(&share).unwrap();
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("native/install.sh");
    let record = || {
        let refused = std::process::Command::new("bash")
            .arg(&script)
            .arg("record")
            .arg(&root)
            .output()
            .unwrap();
        assert!(!refused.status.success());
        std::string::String::from_utf8(refused.stderr).unwrap()
    };
    for (build, reason) in [
        ("Patches: p\n", "names its Source 0 times"),
        (
            "Source: SPDK a DPDK b\nSource: SPDK a DPDK b\n",
            "names its Source 2 times",
        ),
        ("Source: \nPatches: p\n", "names an empty Source"),
    ] {
        std::fs::write(share.join("build.txt"), build).unwrap();
        let stderr = record();
        assert!(stderr.contains(reason), "{build:?}: {stderr}");
    }
    std::fs::write(share.join("build.txt"), "Source: SPDK a DPDK b\n").unwrap();
    for name in ["libdpdk", "spdk_nvme", "spdk_env_dpdk"] {
        std::fs::write(
            pc.join(std::format!("{name}.pc")),
            std::format!(
                "prefix={0}\nincludedir=${{prefix}}/include\nlibdir=${{prefix}}/lib\nName: {name}\n\
                 Description: {name}\nVersion: 1\nCflags: -I{0}/elsewhere -I${{includedir}} -mcpu=stub\n\
                 Libs: -L${{libdir}}\n",
                root.display()
            ),
        )
        .unwrap();
    }
    let stderr = record();
    assert!(
        stderr.contains(&std::format!(
            "the install's flags open with -I{0}/elsewhere, not its include root -I{0}/include",
            root.display()
        )),
        "{stderr}"
    );
    std::fs::remove_dir_all(&root).unwrap();
}
