use std::fs::{self, DirBuilder};
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use kestrike_tools::ownership::{
    PrivateError, foreign_toolchain_paths, make_private, shared_directories, traversed,
};

fn mode(path: &Path) -> u32 {
    fs::metadata(path).expect("the path exists").mode() & 0o7777
}

fn directory(path: &Path, mode: u32) {
    fs::create_dir_all(path).expect("the directory is made");
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("the mode is set");
}

fn file(path: &Path, mode: u32) {
    fs::write(path, "").expect("the file is written");
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("the mode is set");
}

struct Layout {
    base: PathBuf,
}

impl Layout {
    /// `new` checks the scratch directory's lineage with [`shared_directories`], against the process's
    /// real uid, then creates the layout's root with mode 0700 under a fresh name, so no other account
    /// reaches the shared entries the layout holds. A name that already exists is left as it is and the
    /// next name is tried.
    fn new(name: &str) -> Self {
        let scratch = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
        assert_eq!(
            fs::canonicalize(&scratch).ok().as_ref(),
            Some(&scratch),
            "the scratch directory's ancestors hold no link"
        );
        let shared = shared_directories(&scratch).expect("the scratch lineage reads");
        assert!(
            shared.is_empty(),
            "another user owns or can write {shared:?}; run the tests under a private directory"
        );
        let foreign = foreign_toolchain_paths(&scratch).expect("the scratch lineage reads");
        assert!(
            foreign.is_empty(),
            "another user can configure Cargo through {foreign:?}; run the tests under a private directory"
        );
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let base = loop {
            let at = NEXT.fetch_add(1, Ordering::Relaxed);
            let base = scratch.join(format!("ownership-{name}-{}-{at}", std::process::id()));
            match DirBuilder::new().mode(0o700).create(&base) {
                Ok(()) => break base,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("{}: {error}", base.display()),
            }
        };
        let at = |relative: &str| base.join(relative);
        directory(&at("group"), 0o775);
        directory(&at("group/inner"), 0o755);
        directory(&at("group/cargo"), 0o755);
        symlink("group", at("link")).expect("the link is made");
        directory(&at("private"), 0o755);
        symlink("private", at("link2")).expect("the link is made");
        directory(&at("into"), 0o755);
        directory(&at("into/work"), 0o755);
        symlink("../group/cargo", at("into/.cargo")).expect("the link is made");
        directory(&at("cfgfile"), 0o755);
        directory(&at("cfgfile/work"), 0o755);
        directory(&at("cfgfile/.cargo"), 0o755);
        file(&at("cfgfile/.cargo/config.toml"), 0o666);
        directory(&at("cfgdir"), 0o755);
        directory(&at("cfgdir/work"), 0o755);
        directory(&at("cfgdir/.cargo"), 0o777);
        directory(&at("dangle"), 0o755);
        directory(&at("dangle/work"), 0o755);
        symlink("missing", at("dangle/rust-toolchain")).expect("the link is made");
        directory(&at("clean"), 0o755);
        directory(&at("clean/work"), 0o755);
        directory(&at("clean/.cargo"), 0o755);
        file(&at("clean/.cargo/config.toml"), 0o644);
        symlink("loop", at("loop")).expect("the link is made");
        symlink(at("group"), at("abs")).expect("the link is made");
        directory(&at("group/sh"), 0o775);
        directory(&at("present"), 0o755);
        directory(&at("present-shared"), 0o775);
        file(&at("file"), 0o644);
        file(&at("file-shared"), 0o664);
        file(&at("group/inner/rust-toolchain.toml"), 0o644);
        directory(&at("group/.cargo"), 0o755);
        file(&at("group/.cargo/config"), 0o644);
        directory(&at("other-shared"), 0o757);
        directory(&at("cfgother"), 0o755);
        directory(&at("cfgother/work"), 0o755);
        directory(&at("cfgother/.cargo"), 0o755);
        file(&at("cfgother/.cargo/config.toml"), 0o646);
        directory(&at("owner"), 0o755);
        directory(&at("owner/work"), 0o755);
        symlink("/", at("owner/rust-toolchain")).expect("the link is made");
        Self { base }
    }

    fn at(&self, relative: &str) -> PathBuf {
        self.base.join(relative)
    }

    fn expand(&self, recorded: &[&str]) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        for &entry in recorded {
            if entry == "ANCESTORS" {
                let mut ancestors: Vec<PathBuf> = self
                    .base
                    .ancestors()
                    .skip(1)
                    .map(Path::to_path_buf)
                    .collect();
                ancestors.reverse();
                paths.extend(ancestors);
            } else {
                let base = self.base.to_str().expect("the scratch path is UTF-8");
                paths.push(PathBuf::from(entry.replacen("BASE", base, 1)));
            }
        }
        paths
    }
}

impl Drop for Layout {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

#[test]
fn shared_directories_names_a_group_writable_ancestor_and_a_link_into_one() {
    let layout = Layout::new("shared");
    #[rustfmt::skip]
    let rows: &[(&str, &str, &[&str])] = &[
        ("shared_directories(BASE/group/inner)", "group/inner", &["BASE/group"]),
        ("shared_directories(BASE/link/inner)", "link/inner", &["BASE/link"]),
        ("shared_directories(BASE/absent/x)", "absent/x", &[]),
        ("shared_directories(BASE/file/x)", "file/x", &[]),
        ("shared_directories(BASE/group/sh)", "group/sh", &["BASE/group/sh", "BASE/group"]),
        ("shared_directories(BASE/other-shared/x)", "other-shared/x", &["BASE/other-shared"]),
    ];
    for &(expression, path, python) in rows {
        let found =
            shared_directories(&layout.at(path)).expect("each stat succeeds or finds nothing");
        assert_eq!(found, layout.expand(python), "{expression}");
    }
    let base = layout.base.to_str().expect("the scratch path is UTF-8");
    #[rustfmt::skip]
    let spellings: [(&str, String, String); 2] = [
        ("shared_directories(Path('/' + BASE + '/group/./inner/'))", format!("/{base}/group/./inner/"), format!("/{base}/group")),
        ("shared_directories(Path('//' + BASE + '//group/inner/'))", format!("//{base}//group/inner/"), format!("{base}/group")),
    ];
    for (expression, path, python) in spellings {
        let found = shared_directories(Path::new(&path)).expect("each stat succeeds");
        let found: Vec<&std::ffi::OsStr> = found.iter().map(|path| path.as_os_str()).collect();
        assert_eq!(found, [python.as_str()], "{expression}");
    }
}

#[test]
fn traversed_follows_links_and_parents_and_stops_following_after_forty_links() {
    let layout = Layout::new("traversed");
    let looped: Vec<&str> = ["ANCESTORS"]
        .into_iter()
        .chain(["BASE"; 41])
        .chain(["BASE/loop"])
        .collect();
    #[rustfmt::skip]
    let rows: &[(&str, &str, &[&str])] = &[
        ("traversed(BASE/link/inner)", "link/inner", &["ANCESTORS", "BASE", "BASE", "BASE/group"]),
        ("traversed(BASE/group/../link/inner)", "group/../link/inner", &["ANCESTORS", "BASE", "BASE", "BASE", "BASE/group"]),
        ("traversed(BASE/loop/x)", "loop/x", &looped),
        ("traversed(BASE/abs/inner)", "abs/inner", &["ANCESTORS", "BASE", "ANCESTORS", "BASE", "BASE/group"]),
    ];
    for &(expression, path, python) in rows {
        let found = traversed(&layout.at(path)).expect("each link reads");
        assert_eq!(found, layout.expand(python), "{expression}");
    }
    let expression = "traversed(Path('drop' + BASE + '/link/inner'))";
    let base = layout.base.to_str().expect("the scratch path is UTF-8");
    assert_eq!(
        traversed(Path::new(&format!("drop{base}/link/inner"))).expect("each link reads"),
        layout.expand(&["ANCESTORS", "BASE", "BASE", "BASE/group"]),
        "{expression}"
    );
}

#[test]
fn foreign_toolchain_paths_names_each_entry_another_user_can_write() {
    let layout = Layout::new("foreign");
    #[rustfmt::skip]
    let rows: &[(&str, &str, &[&str])] = &[
        ("foreign_toolchain_paths(BASE/into/work)", "into/work", &["BASE/into/.cargo"]),
        ("foreign_toolchain_paths(BASE/cfgfile/work)", "cfgfile/work", &["BASE/cfgfile/.cargo/config.toml"]),
        ("foreign_toolchain_paths(BASE/cfgdir/work)", "cfgdir/work", &["BASE/cfgdir/.cargo"]),
        ("foreign_toolchain_paths(BASE/dangle/work)", "dangle/work", &["BASE/dangle/rust-toolchain"]),
        ("foreign_toolchain_paths(BASE/clean/work)", "clean/work", &[]),
        ("foreign_toolchain_paths(BASE/group/inner/work)", "group/inner/work",
         &["BASE/group", "BASE/group/inner/rust-toolchain.toml", "BASE/group/.cargo", "BASE/group/.cargo/config"]),
        ("foreign_toolchain_paths(BASE/cfgother/work)", "cfgother/work", &["BASE/cfgother/.cargo/config.toml"]),
    ];
    for &(expression, path, python) in rows {
        let found =
            foreign_toolchain_paths(&layout.at(path)).expect("each stat succeeds or finds nothing");
        assert_eq!(found, layout.expand(python), "{expression}");
    }
    let me = fs::metadata(&layout.base).expect("the root exists").uid();
    let root = fs::metadata("/").expect("the root directory exists");
    if me != 0 && root.uid() == 0 && root.mode() & 0o022 == 0 {
        let expression =
            "foreign_toolchain_paths(BASE/owner/work), with owner/rust-toolchain a link to /";
        let found = foreign_toolchain_paths(&layout.at("owner/work")).expect("each stat succeeds");
        assert_eq!(
            found,
            layout.expand(&["BASE/owner/rust-toolchain"]),
            "{expression}"
        );
    }
}

#[test]
fn make_private_creates_missing_directories_and_refuses_a_shared_one() {
    let layout = Layout::new("private");
    let shown = |relative: &str| {
        format!(
            "another user owns or can write {}",
            layout.at(relative).display()
        )
    };
    #[rustfmt::skip]
    let rows: &[(&str, &str, Option<&str>)] = &[
        ("make_private(BASE/new/a/b)", "new/a/b", None),
        ("make_private(BASE/present)", "present", None),
        ("make_private(BASE/present-shared)", "present-shared", Some("present-shared")),
        ("make_private(BASE/group/new)", "group/new", Some("group")),
        ("make_private(BASE/link2)", "link2", None),
        ("make_private(BASE/link)", "link", Some("link")),
        ("make_private(BASE/file)", "file", None),
        ("make_private(BASE/file-shared)", "file-shared", Some("file-shared")),
        ("make_private(BASE/new2/../x)", "new2/../x", None),
        ("make_private(BASE/other-shared)", "other-shared", Some("other-shared")),
    ];
    for &(expression, path, python) in rows {
        match (make_private(&layout.at(path)), python) {
            (Ok(()), None) => {}
            (Err(error @ PrivateError::Shared(_)), Some(shared)) => {
                assert_eq!(
                    error.to_string(),
                    shown(shared),
                    "{expression} raises PermissionError"
                );
            }
            (found, _) => panic!("{expression}: {found:?}"),
        }
    }
    #[rustfmt::skip]
    let modes: &[(&str, &str, u32)] = &[
        ("oct(os.stat(BASE/new).st_mode & 0o7777)", "new", 0o700),
        ("oct(os.stat(BASE/new/a).st_mode & 0o7777)", "new/a", 0o700),
        ("oct(os.stat(BASE/new/a/b).st_mode & 0o7777)", "new/a/b", 0o700),
        ("oct(os.stat(BASE/group/new).st_mode & 0o7777)", "group/new", 0o700),
        ("oct(os.stat(BASE/new2).st_mode & 0o7777)", "new2", 0o700),
        ("oct(os.stat(BASE/x).st_mode & 0o7777)", "x", 0o700),
        ("oct(os.stat(BASE/present).st_mode & 0o7777)", "present", 0o755),
        ("oct(os.stat(BASE/present-shared).st_mode & 0o7777)", "present-shared", 0o775),
        ("oct(os.stat(BASE/other-shared).st_mode & 0o7777)", "other-shared", 0o757),
    ];
    for &(expression, path, python) in modes {
        assert_eq!(mode(&layout.at(path)), python, "{expression}");
    }
    assert!(layout.at("file").is_file(), "(BASE/file).is_file() is True");
    #[rustfmt::skip]
    let links: &[(&str, &str, &str, u32)] = &[
        ("os.readlink(BASE/link2), oct(os.stat(BASE/private).st_mode & 0o7777)", "link2", "private", 0o755),
        ("os.readlink(BASE/link), oct(os.stat(BASE/group).st_mode & 0o7777)", "link", "group", 0o775),
    ];
    for &(expression, link, target, python) in links {
        assert_eq!(
            fs::read_link(layout.at(link)).ok(),
            Some(PathBuf::from(target)),
            "{expression}"
        );
        assert_eq!(mode(&layout.at(target)), python, "{expression}");
    }
}

#[test]
fn make_private_refuses_a_name_a_dangling_link_holds() {
    let layout = Layout::new("dangling");
    let expression = "make_private(BASE/dangle/rust-toolchain) raises FileExistsError";
    match make_private(&layout.at("dangle/rust-toolchain")) {
        Err(PrivateError::Io(error)) => {
            assert_eq!(
                error.error().kind(),
                io::ErrorKind::AlreadyExists,
                "{expression}"
            );
            assert_eq!(error.path(), layout.at("dangle/rust-toolchain"));
            let reason = error.error().to_string();
            let wrapped = PrivateError::Io(error);
            assert!(std::error::Error::source(&wrapped).is_none());
            assert_eq!(
                wrapped.to_string(),
                format!("{}: {reason}", layout.at("dangle/rust-toolchain").display())
            );
        }
        found => panic!("{expression}: {found:?}"),
    }
    assert!(
        fs::symlink_metadata(layout.at("dangle/rust-toolchain"))
            .is_ok_and(|status| status.is_symlink())
    );
    assert_eq!(
        fs::read_link(layout.at("dangle/rust-toolchain")).ok(),
        Some(PathBuf::from("missing")),
        "os.readlink(BASE/dangle/rust-toolchain) == 'missing'"
    );
    assert!(
        fs::symlink_metadata(layout.at("dangle/missing")).is_err(),
        "os.path.lexists(BASE/dangle/missing) is False"
    );
}

#[test]
fn make_private_creates_the_parents_of_a_name_holding_a_nul_and_refuses_the_name() {
    let layout = Layout::new("nul");
    let expression = "make_private(BASE/new/'a\\x00b') raises ValueError after it creates BASE/new";
    let path = layout.at("new/a\0b");
    match make_private(&path) {
        Err(PrivateError::Io(error)) => {
            assert_eq!(
                error.error().kind(),
                io::ErrorKind::InvalidInput,
                "{expression}"
            );
            assert_eq!(error.path(), path, "{expression}");
        }
        found => panic!("{expression}: {found:?}"),
    }
    assert!(layout.at("new").is_dir(), "{expression}");
    assert_eq!(mode(&layout.at("new")), 0o700, "{expression}");
}

#[test]
fn a_stat_error_other_than_absence_reaches_the_caller_with_its_path() {
    let layout = Layout::new("loop");
    let expression = "shared_directories(BASE/loop/x) raises OSError(40)";
    let error = shared_directories(&layout.at("loop/x")).expect_err(expression);
    assert_eq!(
        error.error().raw_os_error(),
        Some(libc::ELOOP),
        "{expression}"
    );
    assert_eq!(error.path(), layout.at("loop/x"));
    let expression = "make_private(BASE/group/sh) raises PermissionError";
    let shown = format!(
        "another user owns or can write {}, {}",
        layout.at("group/sh").display(),
        layout.at("group").display()
    );
    match make_private(&layout.at("group/sh")) {
        Err(error @ PrivateError::Shared(_)) => {
            assert_eq!(error.to_string(), shown, "{expression}")
        }
        found => panic!("{expression}: {found:?}"),
    }
}
