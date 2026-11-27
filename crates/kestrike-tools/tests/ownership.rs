use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};

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
    fn new(name: &str) -> Self {
        let scratch = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
        let uid = fs::metadata(&scratch)
            .expect("the scratch directory exists")
            .uid();
        let shared: Vec<&Path> = scratch
            .ancestors()
            .filter(|ancestor| {
                let status =
                    fs::metadata(ancestor).expect("an ancestor of the scratch directory exists");
                ![uid, 0].contains(&status.uid()) || status.mode() & 0o022 != 0
            })
            .collect();
        assert!(
            shared.is_empty(),
            "another user owns or can write {shared:?}; run the tests under a private directory"
        );
        let base = scratch.join(format!("ownership-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        directory(&base, 0o755);
        let at = |relative: &str| base.join(relative);
        directory(&at("group"), 0o775);
        directory(&at("group/inner"), 0o755);
        directory(&at("group/cargo"), 0o755);
        symlink("group", at("link")).expect("the link is made");
        directory(&at("private"), 0o755);
        symlink("private", at("link2")).expect("the link is made");
        directory(&at("into/work"), 0o755);
        symlink("../group/cargo", at("into/.cargo")).expect("the link is made");
        directory(&at("cfgfile/work"), 0o755);
        directory(&at("cfgfile/.cargo"), 0o755);
        file(&at("cfgfile/.cargo/config.toml"), 0o666);
        directory(&at("cfgdir/work"), 0o755);
        directory(&at("cfgdir/.cargo"), 0o777);
        directory(&at("dangle/work"), 0o755);
        symlink("missing", at("dangle/rust-toolchain")).expect("the link is made");
        directory(&at("clean/work"), 0o755);
        directory(&at("clean/.cargo"), 0o755);
        file(&at("clean/.cargo/config.toml"), 0o644);
        symlink("loop", at("loop")).expect("the link is made");
        directory(&at("present"), 0o755);
        directory(&at("present-shared"), 0o775);
        file(&at("file"), 0o644);
        file(&at("file-shared"), 0o664);
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
    ];
    for &(expression, path, python) in rows {
        let found =
            shared_directories(&layout.at(path)).expect("each stat succeeds or finds nothing");
        assert_eq!(found, layout.expand(python), "{expression}");
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
    ];
    for &(expression, path, python) in rows {
        let found = traversed(&layout.at(path)).expect("each link reads");
        assert_eq!(found, layout.expand(python), "{expression}");
    }
    let expression = "traversed(Path('a/b/c'))";
    let python = [PathBuf::from("/"), PathBuf::from("/b")];
    assert_eq!(traversed(Path::new("a/b/c")).expect("no link is read"), python, "{expression}");
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
        ("foreign_toolchain_paths(BASE/group/inner/work)", "group/inner/work", &["BASE/group"]),
    ];
    for &(expression, path, python) in rows {
        let found =
            foreign_toolchain_paths(&layout.at(path)).expect("each stat succeeds or finds nothing");
        assert_eq!(found, layout.expand(python), "{expression}");
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
        ("oct(os.stat(BASE/present).st_mode & 0o7777)", "present", 0o755),
        ("oct(os.stat(BASE/present-shared).st_mode & 0o7777)", "present-shared", 0o775),
    ];
    for &(expression, path, python) in modes {
        assert_eq!(mode(&layout.at(path)), python, "{expression}");
    }
    assert!(layout.at("file").is_file(), "(BASE/file).is_file() is True");
}

#[test]
fn make_private_refuses_a_name_a_dangling_link_holds() {
    let layout = Layout::new("dangling");
    let expression = "make_private(BASE/dangle/rust-toolchain) raises FileExistsError";
    match make_private(&layout.at("dangle/rust-toolchain")) {
        Err(PrivateError::Io(error)) => {
            assert_eq!(error.kind(), io::ErrorKind::AlreadyExists, "{expression}")
        }
        found => panic!("{expression}: {found:?}"),
    }
    assert!(
        fs::symlink_metadata(layout.at("dangle/rust-toolchain"))
            .is_ok_and(|status| status.is_symlink())
    );
}
