//! The closed-clients guard over the workspace's sources. It holds two
//! rules, each judged over a map of workspace files so that a test can
//! plant a manifest or a source in a copy of the map.
//!
//! The dependency rule reads `crates/kestrike/Cargo.toml` and collects
//! the keys of its normal and build dependencies from every dependency table
//! form, target-specific tables included. The keys equal the `kestrike`
//! row of [`DEPENDENCIES`]. Each of those keys that names a workspace crate
//! is read the same way against that crate's own row, so a dependency that
//! enters Kestrike's tree through `spdk-sys` also fails the rule.
//! The rule reads normal and build dependencies; Cargo builds with
//! dev-dependencies only for tests, examples and benchmarks.
//!
//! The adapter rule reads the sources of every binary target of every
//! workspace member: each `src/main.rs`, each file under `src/bin/`, each
//! `path` a `[[bin]]` table names, and, recursively, each file that a
//! `mod NAME;` declaration in one of them resolves to. No identifier in
//! those files is a name in [`MUTATING_ADAPTERS`]. Each listed name must be
//! declared as a type by some workspace source, so a misspelled entry fails
//! the rule. The walk records a finding when a visited file contains a
//! `path` attribute, an `include!` call or an unterminated string literal,
//! or a `mod` declaration that resolves to no file. Past such a point the
//! walk cannot name every file the binary compiles.
//!
//! A change that adds an adapter whose calls change AWS state, such as an
//! EC2 client that creates, attaches or detaches volumes, adds the
//! adapter's type name to [`MUTATING_ADAPTERS`] in the same change; from
//! then on every binary source that names the type fails the rule. A change
//! that adds a dependency to Kestrike, or to a workspace crate among
//! its dependencies, fails the dependency rule until the same change adds
//! the key to that crate's row, so the row records each growth of the image
//! cache's dependency tree.
//!
//! [`MUTATING_ADAPTERS`] lists `VolumeActions`, the EC2 client of
//! `kestrike-aws` that creates, attaches and detaches volumes; no
//! workspace binary names it. The store table client `Table` of
//! `kestrike-aws` sends `PutItem` from `Table::write`. The reconciler
//! service constructs it in its library, `kestrike-reconciler`'s
//! `src/aws.rs`, which the service's `src/main.rs` reaches, so the adapter
//! rule does not judge that construction. These controls hold over the
//! service's writes:
//!
//! - Types: a `StandbyGate` closes the automated steps `record_standby`,
//!   `enroll_standby`, `reserve`, `release`, `designate`, `replacement`,
//!   `create_replacement`, `abandon` and `flip` of
//!   `failover::reconcile`, and an `OperatorRelease` closes the operator
//!   steps `release_hold` and `flip_for`. Their constructors
//!   `StandbyGate::qualified` and `OperatorRelease::diagnosed` compile only
//!   in this crate's test builds, and a `compile_fail` doctest on each type
//!   shows that another crate cannot construct either.
//! - Call path: the ungated steps `Reconciler::create_shard`, `provision`,
//!   `record_attach`, `add_spare`, `retire` and `retire_spare`, and the
//!   store client's writes `Client::create`, `create_shard`, `replace`,
//!   `replace_all`, `bump` and `take_over`, are public. The service moves
//!   its `Client` into a `Reconciler` and the `Reconciler` into a
//!   `ZoneLoop`, which exposes neither, and its `src/run.rs` calls
//!   `ZoneLoop::tick` and `ZoneLoop::deadline` only; a tick makes the
//!   survey's reads (SURVEY-WRITES-NOTHING). Review of that call path holds
//!   this control; no type or test rule here judges it.
//! - Tests: `kestrike-reconciler`'s `tests/service.rs` logs each
//!   `PutItem` its fake table receives, and
//!   `a_fixed_run_writes_nothing_and_exits_0_after_the_tick_a_stop_signal_interrupts`
//!   counts 0 over three ticks; the directory-reread and store-regression
//!   runs count 0 as well.
//! - Configuration outside this repository: the deployed instance role
//!   grants `dynamodb:DescribeTable` and `dynamodb:GetItem` on the store
//!   table and `ec2:DescribeVolumes`, `ec2:DescribeVolumeStatus` and
//!   `ec2:DescribeInstanceStatus`, as `docs/agents/reconciler.md` lists
//!   them. The policy is deployed with the role; this repository holds no
//!   copy of it and no check of it.
//!
//! Both rules judge names in source text. A listed dependency keeps passing
//! when its version, features, source or `package` field changes, though
//! each of those can change the resolved tree. A binary passes when it
//! reaches an adapter without naming its type: through a library function
//! that constructs one, a type alias, a re-export under another name, or a
//! macro that assembles the identifier. Text in comments and string
//! literals names nothing.
//! A binary source that names another type by a listed name fails the
//! adapter rule.
//!
//! The guard reads the workspace that the root `Cargo.toml` declares with
//! `members = ["crates/*"]`. A root manifest with another member list, or
//! with a `[package]` table, fails both rules.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use crate::oracle::guard_tests::{
    UNTERMINATED, attribute_names_path, manifest_dependencies, sources, tokens,
};

/// The keys of the normal and build dependencies that Kestrike and
/// each workspace crate among its dependencies declare, one row per crate.
/// Each row equals what that crate's `Cargo.toml` declares.
const DEPENDENCIES: &[(&str, &[&str])] = &[
    (
        "kestrike",
        &["libc", "memchr", "polyval", "sha2", "spdk-sys", "subtle"],
    ),
    ("spdk-sys", &[]),
];

/// The type names of the mutating AWS adapters that no workspace binary
/// constructs: clients whose calls change provider state. The adapter rule
/// fails every binary source that names one. `VolumeActions` sends
/// `CreateVolume`, `AttachVolume` and `DetachVolume`. The store table client
/// `Table` sends `PutItem` and stays off the list, because the reconciler
/// service constructs it; the module documentation records the controls
/// over that service's writes.
const MUTATING_ADAPTERS: &[&str] = &["VolumeActions"];

/// The crate whose dependencies the dependency rule pins.
const GUARDED: &str = "kestrike";

/// Workspace files keyed by their `/`-separated path relative to the
/// workspace root.
type Files = BTreeMap<String, String>;

/// Reads the root `Cargo.toml`, each `crates/*/Cargo.toml`, and every `.rs`
/// file under each of those crates' `src/` directories.
///
/// # Panics
///
/// If a directory or file the guard reads cannot be read.
fn workspace() -> Files {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = Files::new();
    files.insert(
        "Cargo.toml".to_owned(),
        fs::read_to_string(root.join("Cargo.toml")).unwrap(),
    );
    let mut found = Vec::new();
    for entry in fs::read_dir(root.join("crates")).unwrap() {
        let dir = entry.unwrap().path();
        let manifest = dir.join("Cargo.toml");
        if !manifest.is_file() {
            continue;
        }
        let name = dir.file_name().unwrap().to_str().unwrap();
        files.insert(
            format!("crates/{name}/Cargo.toml"),
            fs::read_to_string(manifest).unwrap(),
        );
        if dir.join("src").is_dir() {
            sources(&root, &dir.join("src"), &mut found);
        }
    }
    files.extend(found);
    files
}

/// Each string value of `key` on a `key = "value"` line inside a table
/// whose header line is `header`, in file order.
pub(crate) fn string_fields<'a>(manifest: &'a str, header: &str, key: &str) -> Vec<&'a str> {
    let mut inside = false;
    let mut found = Vec::new();
    for line in manifest.lines().map(str::trim) {
        if line.starts_with('[') {
            inside = line.split('#').next().unwrap_or("").trim() == header;
        } else if inside
            && let Some((name, value)) = line.split_once('=')
            && name.trim() == key
            && let Some((value, _)) = value
                .trim()
                .strip_prefix('"')
                .and_then(|v| v.split_once('"'))
        {
            found.push(value);
        }
    }
    found
}

/// The strings of the root manifest's `members` array, read from the line
/// that starts with `members` through the first line holding `]`.
fn workspace_members(manifest: &str) -> Vec<&str> {
    let mut lines = manifest
        .lines()
        .skip_while(|line| !line.trim_start().starts_with("members"));
    let mut text = Vec::new();
    for line in lines.by_ref() {
        text.push(line);
        if line.contains(']') {
            break;
        }
    }
    text.iter()
        .flat_map(|line| line.split('"').skip(1).step_by(2))
        .collect()
}

/// Maps each workspace member's package name to its directory.
///
/// # Errors
///
/// A finding when the root manifest's members differ from `crates/*`, when
/// the root manifest holds a `[package]` table, or when a member's
/// `[package]` table contains no `name = "..."` line.
fn members(files: &Files) -> Result<BTreeMap<String, String>, String> {
    let root = &files["Cargo.toml"];
    let listed = workspace_members(root);
    if listed != ["crates/*"] {
        return Err(format!(
            "Cargo.toml: workspace members {listed:?}, where the guard reads [\"crates/*\"]"
        ));
    }
    if root.lines().any(|line| line.trim() == "[package]") {
        return Err("Cargo.toml: a [package] table, whose targets the guard does not read".into());
    }
    let mut found = BTreeMap::new();
    for (path, text) in files {
        let Some(dir) = path.strip_suffix("/Cargo.toml") else {
            continue;
        };
        if dir
            .strip_prefix("crates/")
            .is_some_and(|name| !name.contains('/'))
        {
            let names = string_fields(text, "[package]", "name");
            let [name] = names.as_slice() else {
                return Err(format!("{path}: {} package names", names.len()));
            };
            found.insert((*name).to_owned(), dir.to_owned());
        }
    }
    Ok(found)
}

/// Each finding of the dependency rule over `files` against `pinned`. The
/// rule starts at [`GUARDED`] and follows each declared key that names a
/// workspace member. For each crate it reaches, a declared key outside the
/// crate's row, a row key the manifest does not declare, and a missing row
/// are findings, and so is a row for a crate the rule does not reach.
fn dependency_findings(files: &Files, pinned: &[(&str, &[&str])]) -> Vec<String> {
    let members = match members(files) {
        Ok(members) => members,
        Err(finding) => return vec![finding],
    };
    let mut findings = Vec::new();
    let mut reached = BTreeSet::new();
    let mut pending = vec![GUARDED.to_owned()];
    while let Some(krate) = pending.pop() {
        if !reached.insert(krate.clone()) {
            continue;
        }
        let Some(dir) = members.get(&krate) else {
            findings.push(format!("{krate} is no workspace member"));
            continue;
        };
        let manifest = format!("{dir}/Cargo.toml");
        let declared: BTreeSet<String> = manifest_dependencies(&files[&manifest])
            .into_iter()
            .filter(|(kind, _)| kind == "dependencies" || kind == "build-dependencies")
            .map(|(_, key)| key)
            .collect();
        match pinned.iter().find(|(name, _)| *name == krate) {
            None => findings.push(format!(
                "{manifest}: {krate} is a workspace crate among the dependencies of {GUARDED}, and DEPENDENCIES has no row for it"
            )),
            Some((_, row)) => {
                let row: BTreeSet<String> = row.iter().map(|key| (*key).to_owned()).collect();
                for key in declared.difference(&row) {
                    findings.push(format!(
                        "{manifest} declares {key}, which DEPENDENCIES does not pin for {krate}"
                    ));
                }
                for key in row.difference(&declared) {
                    findings.push(format!(
                        "DEPENDENCIES pins {key} for {krate}, which {manifest} does not declare"
                    ));
                }
            }
        }
        pending.extend(declared.into_iter().filter(|key| members.contains_key(key)));
    }
    for (krate, _) in pinned {
        if !reached.contains(*krate) {
            findings.push(format!(
                "DEPENDENCIES has a row for {krate}, which is outside the dependencies of {GUARDED}"
            ));
        }
    }
    findings
}

/// Each `mod NAME;` that `source` declares, as the names of the inline
/// modules enclosing the declaration and NAME, in file order.
///
/// # Errors
///
/// A finding for a `path` attribute, an `include!` call or an unterminated
/// string literal, each of which can bring in source text that the module
/// walk does not resolve.
fn declared_modules(source: &str) -> Result<Vec<(Vec<&str>, &str)>, String> {
    let tokens = tokens(source);
    let mut found = Vec::new();
    let mut inline: Vec<(&str, usize)> = Vec::new();
    let mut depth = 0;
    for (i, &token) in tokens.iter().enumerate() {
        let next = tokens.get(i + 1).copied().unwrap_or("");
        let after = tokens.get(i + 2).copied().unwrap_or("");
        match token {
            UNTERMINATED => return Err(UNTERMINATED.to_owned()),
            "#" if attribute_names_path(&tokens[i + 1..]) => {
                return Err("a `path` attribute, which the guard does not follow".to_owned());
            }
            "include" if next == "!" => {
                return Err("`include!`, which the guard does not follow".to_owned());
            }
            "mod" if after == ";" => {
                found.push((inline.iter().map(|&(name, _)| name).collect(), next));
            }
            "mod" if after == "{" => inline.push((next, depth)),
            "{" => depth += 1,
            "}" => {
                depth = depth.saturating_sub(1);
                if inline.last().is_some_and(|&(_, at)| at == depth) {
                    inline.pop();
                }
            }
            _ => {}
        }
    }
    Ok(found)
}

/// The binary sources of `members` in `files`, with the findings for the
/// sources the walk cannot follow.
///
/// The roots of each member are its `src/main.rs`, each `src/bin/NAME.rs`,
/// each `src/bin/NAME/main.rs` and each `path` of a `[[bin]]` table. The walk
/// resolves each `mod NAME;` as Cargo does: in a root or a `mod.rs` file,
/// against the file's directory; in any other file `F.rs`, against the
/// directory `F`; in both cases below the enclosing inline modules, to
/// `NAME.rs` or `NAME/mod.rs`. Every file under a member's `src/bin/` is a
/// binary source, reached or not.
fn binary_sources(
    files: &Files,
    members: &BTreeMap<String, String>,
) -> (BTreeSet<String>, Vec<String>) {
    let mut findings = Vec::new();
    let mut reached = BTreeSet::new();
    let mut pending = Vec::new();
    for dir in members.values() {
        let main = format!("{dir}/src/main.rs");
        if files.contains_key(&main) {
            pending.push((main, true));
        }
        let bin = format!("{dir}/src/bin/");
        for path in files.keys().filter(|path| path.starts_with(&bin)) {
            reached.insert(path.clone());
            let rest = &path[bin.len()..];
            if !rest.contains('/')
                || rest
                    .split_once('/')
                    .is_some_and(|(_, file)| file == "main.rs")
            {
                pending.push((path.clone(), true));
            }
        }
        let manifest = format!("{dir}/Cargo.toml");
        for path in string_fields(&files[&manifest], "[[bin]]", "path") {
            let path = format!("{dir}/{}", path.trim_start_matches("./"));
            if files.contains_key(&path) {
                pending.push((path, true));
            } else {
                findings.push(format!(
                    "{manifest}: binary source {path}, which the guard does not read"
                ));
            }
        }
    }
    let mut walked = BTreeSet::new();
    while let Some((path, root)) = pending.pop() {
        reached.insert(path.clone());
        if !walked.insert(path.clone()) {
            continue;
        }
        let base = if root || path.ends_with("/mod.rs") {
            path.rsplit_once('/').map_or("", |(dir, _)| dir)
        } else {
            path.strip_suffix(".rs").unwrap_or(&path)
        };
        match declared_modules(&files[&path]) {
            Err(finding) => findings.push(format!("{path}: {finding}")),
            Ok(modules) => {
                for (inline, name) in modules {
                    let dir = inline
                        .iter()
                        .fold(base.to_owned(), |dir, module| format!("{dir}/{module}"));
                    let candidates = [format!("{dir}/{name}.rs"), format!("{dir}/{name}/mod.rs")];
                    match candidates.into_iter().find(|file| files.contains_key(file)) {
                        Some(file) => pending.push((file, false)),
                        None => findings.push(format!("{path}: mod {name} resolves to no file")),
                    }
                }
            }
        }
    }
    (reached, findings)
}

/// Each finding of the adapter rule over `files` with `adapters` as the
/// listed names: a walk finding from [`binary_sources`], a binary source
/// that holds a listed name as an identifier, and a listed name that no
/// workspace source declares after `struct`, `enum`, `trait`, `type` or
/// `union`.
fn adapter_findings(files: &Files, adapters: &[&str]) -> Vec<String> {
    let members = match members(files) {
        Ok(members) => members,
        Err(finding) => return vec![finding],
    };
    let (reached, mut findings) = binary_sources(files, &members);
    for path in &reached {
        let tokens = tokens(&files[path]);
        for name in adapters {
            if tokens.contains(name) {
                findings.push(format!("{path} names the mutating adapter {name}"));
            }
        }
    }
    for name in adapters {
        let declared = files
            .iter()
            .filter(|(path, source)| path.ends_with(".rs") && source.contains(name))
            .any(|(_, source)| {
                tokens(source).windows(2).any(|pair| {
                    matches!(pair[0], "struct" | "enum" | "trait" | "type" | "union")
                        && pair[1] == *name
                })
            });
        if !declared {
            findings.push(format!(
                "MUTATING_ADAPTERS lists {name}, which no workspace source declares as a type"
            ));
        }
    }
    findings
}

/// `files` with `path`'s text replaced through `edit`, which must change it.
fn edited(mut files: Files, path: &str, edit: impl FnOnce(&str) -> String) -> Files {
    let text = files.get_mut(path).expect("a workspace file");
    let changed = edit(text);
    assert_ne!(&changed, text, "the plant edits {path}");
    *text = changed;
    files
}

/// `files` with each `(path, text)` of `plants` added or replaced.
fn planted(mut files: Files, plants: &[(&str, &str)]) -> Files {
    for (path, text) in plants {
        files.insert((*path).to_owned(), (*text).to_owned());
    }
    files
}

/// Kestrike's manifest, and `spdk-sys`'s, declare exactly the
/// normal and build dependencies their rows of [`DEPENDENCIES`] pin.
#[test]
fn kestrike_declares_only_its_pinned_dependencies() {
    let findings = dependency_findings(&workspace(), DEPENDENCIES);
    assert!(findings.is_empty(), "{findings:#?}");
}

/// No binary source of the workspace names a listed mutating adapter. The
/// walk reaches each member's `src/main.rs` and at least one module file
/// that a binary declares, so the rule reads more than the roots.
#[test]
fn no_binary_names_a_mutating_adapter() {
    let files = workspace();
    let findings = adapter_findings(&files, MUTATING_ADAPTERS);
    assert!(findings.is_empty(), "{findings:#?}");
    let (reached, _) = binary_sources(&files, &members(&files).unwrap());
    let mains: Vec<&String> = files
        .keys()
        .filter(|path| path.ends_with("/src/main.rs"))
        .collect();
    assert!(!mains.is_empty(), "the workspace holds no src/main.rs");
    for main in mains {
        assert!(reached.contains(main), "the walk misses {main}");
    }
    assert!(
        reached
            .iter()
            .any(|path| !path.ends_with("/src/main.rs") && !path.contains("/src/bin/")),
        "the walk follows no module: {reached:#?}"
    );
}

/// A dependency added to Kestrike's manifest fails the dependency
/// rule by its key, in each table form a normal or build dependency takes,
/// and so does one added to `spdk-sys` or one removed from Kestrike.
/// A dev-dependency added beside them passes.
#[test]
fn a_dependency_added_to_the_manifest_fails_the_dependency_rule() {
    const MANIFEST: &str = "crates/kestrike/Cargo.toml";
    let files = workspace();
    assert_eq!(dependency_findings(&files, DEPENDENCIES), [""; 0]);
    let in_table = edited(files.clone(), MANIFEST, |text| {
        text.replacen(
            "subtle = \"2.6.1\"\n",
            "subtle = \"2.6.1\"\nhmac = \"=0.13.0\"\n",
            1,
        )
    });
    assert_eq!(
        dependency_findings(&in_table, DEPENDENCIES),
        [format!(
            "{MANIFEST} declares hmac, which DEPENDENCIES does not pin for kestrike"
        )]
    );
    for (table, key) in [
        ("[dependencies]\nureq = \"3.5.2\"\n", "ureq"),
        ("[dependencies.tokio]\nversion = \"1\"\n", "tokio"),
        ("[build-dependencies]\ncc = \"1\"\n", "cc"),
        (
            "[target.'cfg(unix)'.build-dependencies]\nbindgen.workspace = true\n",
            "bindgen",
        ),
    ] {
        let added = edited(files.clone(), MANIFEST, |text| format!("{text}\n{table}"));
        assert_eq!(
            dependency_findings(&added, DEPENDENCIES),
            [format!(
                "{MANIFEST} declares {key}, which DEPENDENCIES does not pin for kestrike"
            )],
            "{table}"
        );
    }
    let member = edited(files.clone(), MANIFEST, |text| {
        format!("{text}\n[dependencies]\nkestrike-aws = {{ path = \"../kestrike-aws\" }}\n")
    });
    assert_eq!(
        dependency_findings(&member, DEPENDENCIES),
        [
            format!("{MANIFEST} declares kestrike-aws, which DEPENDENCIES does not pin for kestrike"),
            "crates/kestrike-aws/Cargo.toml: kestrike-aws is a workspace crate among the dependencies of kestrike, and DEPENDENCIES has no row for it".to_owned(),
        ]
    );
    let through_spdk = edited(files.clone(), "crates/spdk-sys/Cargo.toml", |text| {
        format!("{text}\n[dependencies]\nlibc = \"0.2.189\"\n")
    });
    assert_eq!(
        dependency_findings(&through_spdk, DEPENDENCIES),
        ["crates/spdk-sys/Cargo.toml declares libc, which DEPENDENCIES does not pin for spdk-sys"]
    );
    let removed = edited(files.clone(), MANIFEST, |text| {
        text.replacen("subtle = \"2.6.1\"\n", "", 1)
    });
    assert_eq!(
        dependency_findings(&removed, DEPENDENCIES),
        [format!(
            "DEPENDENCIES pins subtle for kestrike, which {MANIFEST} does not declare"
        )]
    );
    let dev_only = edited(files, MANIFEST, |text| {
        format!("{text}\n[dev-dependencies]\nproptest = \"1\"\n")
    });
    assert_eq!(dependency_findings(&dev_only, DEPENDENCIES), [""; 0]);
}

/// With a list of one made-up adapter name, a binary source that names it
/// fails the adapter rule: a crate's `src/main.rs`, a file under `src/bin/`,
/// a module of a module that `src/main.rs` declares, a module declared
/// inside an inline module, and a `mod.rs` module. The same name in a
/// library source, or in a comment or string literal of a binary, passes,
/// and every plant passes under an empty list.
#[test]
fn a_binary_that_names_a_listed_adapter_fails_the_adapter_rule() {
    const PLANTED: &str = "PlantedVolumeWriter";
    const MAIN: &str = "crates/kestrike-aws/src/main.rs";
    const BIN: &str = "crates/kestrike-aws/src/bin/actuate.rs";
    const SERVE: &str = "crates/kestrike-aws/src/serve.rs";
    const STEP: &str = "crates/kestrike-aws/src/serve/step.rs";
    const SERVE_MOD: &str = "crates/kestrike-aws/src/serve/mod.rs";
    const ACT: &str = "crates/kestrike-aws/src/tick/act.rs";
    let declaration = format!("pub struct {PLANTED};");
    let declared = planted(
        workspace(),
        &[("crates/kestrike-aws/src/planted.rs", &declaration)],
    );
    assert_eq!(adapter_findings(&declared, &[PLANTED]), [""; 0]);
    let names = format!("fn main() {{ let _ = kestrike_aws::{PLANTED}; }}");
    let uses = format!("use kestrike_aws::{PLANTED};");
    let cases: [(&[(&str, &str)], &str); 5] = [
        (&[(MAIN, &names)], MAIN),
        (&[(BIN, &names)], BIN),
        (
            &[
                (MAIN, "mod serve;\nfn main() {}"),
                (SERVE, "mod step;"),
                (STEP, &uses),
            ],
            STEP,
        ),
        (
            &[
                (MAIN, "mod tick {\n    pub mod act;\n}\nfn main() {}"),
                (ACT, &uses),
            ],
            ACT,
        ),
        (
            &[(MAIN, "mod serve;\nfn main() {}"), (SERVE_MOD, &uses)],
            SERVE_MOD,
        ),
    ];
    for (plants, named) in cases {
        let tree = planted(declared.clone(), plants);
        assert_eq!(
            adapter_findings(&tree, &[PLANTED]),
            [format!("{named} names the mutating adapter {PLANTED}")],
            "{plants:?}"
        );
        assert_eq!(adapter_findings(&tree, &[]), [""; 0], "{plants:?}");
    }
    let quiet_text = format!("// {PLANTED}\nfn main() {{ let _ = \"{PLANTED}\"; }}");
    let quiet = planted(declared, &[(MAIN, &quiet_text)]);
    assert_eq!(adapter_findings(&quiet, &[PLANTED]), [""; 0]);
    assert_eq!(
        adapter_findings(&workspace(), &[PLANTED]),
        [format!(
            "MUTATING_ADAPTERS lists {PLANTED}, which no workspace source declares as a type"
        )]
    );
}

#[test]
fn a_binary_that_names_the_volume_writer_fails_the_listed_adapters() {
    const MAIN: &str = "crates/kestrike-aws/src/main.rs";
    let tree = planted(
        workspace(),
        &[(
            MAIN,
            "fn main() { let _ = kestrike_aws::ec2::VolumeActions::new; }",
        )],
    );
    assert_eq!(
        adapter_findings(&tree, MUTATING_ADAPTERS),
        [format!("{MAIN} names the mutating adapter VolumeActions")]
    );
}

/// A binary source whose compiled text the walk cannot resolve fails the
/// adapter rule under an empty list: a `mod` declaration with no file, a
/// `path` attribute, an `include!` call, an unterminated string literal and
/// a `[[bin]]` path outside the files the guard reads. A root manifest with
/// another member list fails both rules.
#[test]
fn a_binary_source_the_walk_cannot_resolve_fails_the_adapter_rule() {
    const MAIN: &str = "crates/kestrike-aws/src/main.rs";
    let files = workspace();
    for (text, finding) in [
        (
            "mod absent;\nfn main() {}",
            "mod absent resolves to no file",
        ),
        (
            "#[path = \"../../kestrike/src/oracle/row.rs\"]\nmod row;\nfn main() {}",
            "a `path` attribute, which the guard does not follow",
        ),
        (
            "include!(\"actuate.rs\");",
            "`include!`, which the guard does not follow",
        ),
        ("fn main() { let _ = \"open; }", UNTERMINATED),
    ] {
        let tree = planted(files.clone(), &[(MAIN, text)]);
        assert_eq!(
            adapter_findings(&tree, &[]),
            [format!("{MAIN}: {finding}")],
            "{text}"
        );
    }
    let outside = edited(files.clone(), "crates/kestrike-aws/Cargo.toml", |text| {
        format!("{text}\n[[bin]]\nname = \"actuate\"\npath = \"tools/actuate.rs\"\n")
    });
    assert_eq!(
        adapter_findings(&outside, &[]),
        [
            "crates/kestrike-aws/Cargo.toml: binary source crates/kestrike-aws/tools/actuate.rs, which the guard does not read"
        ]
    );
    let widened = edited(files, "Cargo.toml", |text| {
        text.replacen("\"crates/*\"", "\"crates/*\", \"tools/*\"", 1)
    });
    let finding = r#"Cargo.toml: workspace members ["crates/*", "tools/*"], where the guard reads ["crates/*"]"#;
    assert_eq!(adapter_findings(&widened, &[]), [finding]);
    assert_eq!(dependency_findings(&widened, DEPENDENCIES), [finding]);
}

/// The dependency rule's reader keeps the kind of each table form, so the
/// rule can keep normal and build dependencies and drop dev-dependencies.
#[test]
fn manifest_dependencies_name_the_kind_of_each_table() {
    let manifest = r#"
[package]
name = "not-a-dependency"

[dependencies]
plain = "1"
# commented = "1"

[target.'cfg(all(target_os = "linux", target_pointer_width = "64"))'.dependencies]
linux-only = "1"

[dev-dependencies]
dev-only = "1"

[build_dependencies]
underscored = "1"

[target.'cfg(unix)'.build-dependencies.table-form]
version = "1"

[[bin]]
path = "src/main.rs"
"#;
    let found = manifest_dependencies(manifest);
    let kinds: Vec<(&str, &str)> = found
        .iter()
        .map(|(kind, key)| (kind.as_str(), key.as_str()))
        .collect();
    assert_eq!(
        kinds,
        [
            ("dependencies", "plain"),
            ("dependencies", "linux-only"),
            ("dev-dependencies", "dev-only"),
            ("build-dependencies", "underscored"),
            ("build-dependencies", "table-form"),
        ]
    );
}
