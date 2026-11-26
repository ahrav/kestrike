//! `reach` writes the mode's output to stdout and exits with 0 on success.
//! On failure, `reach` writes the error to stderr with the prefix `reach: `
//! and exits with 2.

use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const DISK: &str = "pub enum DiskError { Full, Gone(u8) }\nfn f() -> Result<(), DiskError> { Err(DiskError::Full) }\n";

const REGISTER: &str = r#"{
"run": {"commit":"","toolchain":"","flags":"","build":"","worker":"","profiles":[],"roots":"","counts":{},"no_pass":[],"tool":""},
"totals": {"rows":2,"reached":1,"unreached":0,"unplaced":1,"file-not-run":0,"function-not-entered":0,"not-constructed":0},
"live": {"unplaced":1},
"reasons": [
],
"rows": [
{"enum":"storage::disk::DiskError","variant":"Full","sites":[["storage/disk.rs","f","path"]],"state":"reached","count":3},
{"enum":"storage::disk::DiskError","variant":"Gone","sites":[],"state":"unplaced","cause":"no-site"}
]
}
"#;

struct Checkout(PathBuf);

impl Checkout {
    fn new(name: &str) -> Self {
        let root = (0..)
            .find_map(|next| {
                let root = std::env::temp_dir()
                    .join(format!("reach-cli-{}-{next}-{name}", std::process::id()));
                match std::fs::DirBuilder::new().mode(0o700).create(&root) {
                    Ok(()) => Some(root),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => None,
                    Err(error) => panic!("{}: {error}", root.display()),
                }
            })
            .expect("a free name");
        let checkout = Self(root);
        checkout.write("crates/kestrike/src/mod.rs", "pub mod storage;\n");
        checkout.write("crates/kestrike/src/storage/mod.rs", "pub mod disk;\n");
        checkout.write("crates/kestrike/src/storage/disk.rs", DISK);
        checkout.write("verification/reach/storage.json", REGISTER);
        checkout
    }

    fn write(&self, rel: &str, text: &str) -> PathBuf {
        let path = self.0.join(rel);
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("the tree is writable");
        std::fs::write(&path, text).expect("the file is writable");
        path
    }

    fn reach(&self, arguments: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_reach"))
            .args(arguments)
            .arg("--root")
            .arg(&self.0)
            .output()
            .expect("the binary runs")
    }
}

impl Drop for Checkout {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The export records `count` executions at the sole `DiskError::Full` site.
fn export(count: u64) -> String {
    let column = DISK
        .lines()
        .nth(1)
        .and_then(|line| line.find("DiskError::Full"))
        .expect("the site")
        + 1;
    let name = "/w/crates/kestrike/src/storage/disk.rs";
    format!(
        r#"{{"data":[{{"files":[{{"filename":"{name}","segments":[[2,{column},{count},true,true,false]],"summary":{{"lines":{{"covered":1}}}}}}],
        "functions":[{{"count":1,"regions":[[1,1,9,1,1,0,0,0]],"filenames":["{name}"]}}]}}]}}"#
    )
}

fn text(bytes: &[u8]) -> &str {
    std::str::from_utf8(bytes).expect("text")
}

fn path(path: &Path) -> &str {
    path.to_str().expect("a text path")
}

#[test]
fn the_binary_exits_zero_with_its_output_and_two_with_its_error() {
    let checkout = Checkout::new("status");
    let same = checkout.write("same.json", &export(3));
    let changed = checkout.write("changed.json", &export(5));
    for (export, printed) in [
        (&same, ""),
        (
            &changed,
            "storage::disk::DiskError::Full: reached 3 -> reached 5\n",
        ),
    ] {
        let compared = checkout.reach(&["compare", "storage", "--export", path(export)]);
        assert_eq!(compared.status.code(), Some(0));
        assert_eq!(text(&compared.stdout), printed);
        assert_eq!(text(&compared.stderr), "");
    }
    let status = checkout.reach(&["sync", "storage", "--status"]);
    assert_eq!(status.status.code(), Some(0));
    assert_eq!(text(&status.stdout), "unmeasured: 0\n");
    for arguments in [
        &["compare", "storage"][..],
        &["sync", "disk"],
        &["measure", "storage", "--export", path(&same)],
        &["report", "storage"],
    ] {
        let refused = checkout.reach(arguments);
        assert_eq!(refused.status.code(), Some(2), "{arguments:?}");
        assert_eq!(text(&refused.stdout), "", "{arguments:?}");
        assert!(
            text(&refused.stderr).starts_with("reach: "),
            "{arguments:?}"
        );
    }
    assert_eq!(
        std::fs::read_to_string(checkout.0.join("verification/reach/storage.json"))
            .expect("the register"),
        REGISTER
    );
}

#[test]
fn a_register_behind_a_symbolic_link_is_refused_and_left_as_it_was() {
    let checkout = Checkout::new("linked");
    let outside = Checkout::new("outside");
    let export = checkout.write("export.json", &export(5));
    let run = checkout.write("run.json", r#"{"commit":"","toolchain":"","flags":"","build":"","worker":"","profiles":[],"roots":"","counts":{},"no_pass":[]}"#);
    let reach = checkout.0.join("verification/reach");
    let register = checkout.0.join("verification/reach/storage.json");
    let foreign = outside.0.join("verification/reach/storage.json");
    let linked = [
        (reach.clone(), outside.0.join("verification/reach")),
        (register.clone(), foreign.clone()),
    ];
    for (link, target) in &linked {
        if link.is_dir() {
            std::fs::remove_dir_all(link).expect("remove the directory");
        } else {
            std::fs::remove_file(link).expect("remove the file");
        }
        std::os::unix::fs::symlink(target, link).expect("a link");
        for arguments in [
            &["sync", "storage"][..],
            &["sync", "storage", "--status"],
            &["compare", "storage", "--export", path(&export)],
            &[
                "measure",
                "storage",
                "--export",
                path(&export),
                "--run",
                path(&run),
            ],
        ] {
            let refused = checkout.reach(arguments);
            assert_eq!(refused.status.code(), Some(2), "{link:?} {arguments:?}");
            assert!(
                text(&refused.stderr).contains("a symbolic link"),
                "{link:?} {arguments:?}: {}",
                text(&refused.stderr)
            );
        }
        assert_eq!(
            std::fs::read_to_string(&foreign).expect("the foreign register"),
            REGISTER
        );
        std::fs::remove_file(link).expect("remove the link");
        if link == &reach {
            checkout.write("verification/reach/storage.json", REGISTER);
        }
    }
}
