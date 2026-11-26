//! Each plant must trigger its Clippy expectation. The source check covers the reverse direction: each configured path must have a plant.

#[allow(dead_code, reason = "Clippy checks the plants at compile time")]
#[warn(clippy::disallowed_types)]
fn plants() {
    #[expect(clippy::disallowed_methods, reason = "plant for a clippy.toml entry")]
    let _ = std::time::Instant::now;
    #[expect(clippy::disallowed_methods, reason = "plant for a clippy.toml entry")]
    let _ = std::time::SystemTime::now;
    #[expect(clippy::disallowed_methods, reason = "plant for a clippy.toml entry")]
    let _ = libc::clock_gettime;
    #[expect(clippy::disallowed_methods, reason = "plant for a clippy.toml entry")]
    let _ = libc::getrandom;
    #[expect(clippy::disallowed_methods, reason = "plant for a clippy.toml entry")]
    let _ = std::hash::RandomState::new;
    #[expect(clippy::disallowed_methods, reason = "plant for a clippy.toml entry")]
    let _ = std::thread::spawn::<fn(), ()>;
    #[expect(clippy::disallowed_methods, reason = "plant for a clippy.toml entry")]
    let _ = std::thread::scope::<fn(&std::thread::Scope<'_, '_>), ()>;
    #[expect(clippy::disallowed_methods, reason = "plant for a clippy.toml entry")]
    let _ = std::thread::Builder::spawn::<fn(), ()>;
    #[expect(clippy::disallowed_methods, reason = "plant for a clippy.toml entry")]
    let _ = std::thread::Builder::spawn_scoped::<fn(), ()>;
    #[expect(clippy::disallowed_methods, reason = "plant for a clippy.toml entry")]
    let _ = std::thread::Scope::spawn::<fn(), ()>;
    #[expect(clippy::disallowed_methods, reason = "plant for a clippy.toml entry")]
    let _ = std::thread::sleep;
    #[expect(clippy::disallowed_methods, reason = "plant for a clippy.toml entry")]
    let _ = std::net::TcpStream::connect::<std::net::SocketAddr>;
    #[expect(clippy::disallowed_methods, reason = "plant for a clippy.toml entry")]
    let _ = std::net::TcpListener::bind::<std::net::SocketAddr>;
    #[expect(clippy::disallowed_methods, reason = "plant for a clippy.toml entry")]
    let _ = std::net::UdpSocket::bind::<std::net::SocketAddr>;
    #[expect(clippy::disallowed_methods, reason = "plant for a clippy.toml entry")]
    let _ = std::os::unix::net::UnixStream::connect::<&std::path::Path>;
    #[expect(clippy::disallowed_methods, reason = "plant for a clippy.toml entry")]
    let _ = std::os::unix::net::UnixListener::bind::<&std::path::Path>;
    #[expect(clippy::disallowed_methods, reason = "plant for a clippy.toml entry")]
    let _ = std::os::unix::net::UnixDatagram::bind::<&std::path::Path>;
    #[expect(clippy::disallowed_types, reason = "plant for a clippy.toml entry")]
    type Map = std::collections::HashMap<(), ()>;
    #[expect(clippy::disallowed_types, reason = "plant for a clippy.toml entry")]
    type Set = std::collections::HashSet<()>;
}

const METHOD: &str =
    r#"#[expect(clippy::disallowed_methods, reason = "plant for a clippy.toml entry")]"#;
const TYPE: &str =
    r#"#[expect(clippy::disallowed_types, reason = "plant for a clippy.toml entry")]"#;

fn unplanted(config: &str, source: &str) -> Vec<String> {
    const HEADER: [&str; 3] = [
        r#"#[allow(dead_code, reason = "Clippy checks the plants at compile time")]"#,
        "#[warn(clippy::disallowed_types)]",
        "fn plants() {",
    ];
    let mut problems = Vec::new();
    let mut plants = Vec::new();
    let lines: Vec<&str> = source.lines().collect();
    let start = lines.windows(3).position(|window| window == HEADER);
    if start.is_none() {
        problems.push("missing plants header".to_owned());
    }
    let mut body = start
        .map_or(&[][..], |start| &lines[start + HEADER.len()..])
        .iter()
        .take_while(|line| **line != "}");
    while let Some(attribute) = body.next() {
        let plant = body.next().copied().unwrap_or_default().trim();
        let planted = match attribute.trim() {
            METHOD => plant.strip_prefix("let _ = ").map(|path| ("methods", path)),
            TYPE => plant
                .split_once(" = ")
                .filter(|(alias, _)| alias.starts_with("type "))
                .map(|(_, path)| ("types", path)),
            _ => None,
        }
        .and_then(|(kind, path)| {
            let path = path.strip_suffix(';')?;
            (!path.contains(['/', ';', '"', '*'])).then_some((kind, path))
        });
        match planted {
            Some((kind, path)) => {
                let path = path.split('<').next().unwrap_or_default();
                plants.push((kind, path.trim_end_matches("::")));
            }
            None => problems.push(format!("malformed plant: {} {plant}", attribute.trim())),
        }
    }
    let mut list = None;
    let mut entries = Vec::new();
    for line in config.lines().map(str::trim) {
        match line {
            "" => {}
            _ if line.starts_with('#') => {}
            "disallowed-methods = [" => list = Some("methods"),
            "disallowed-types = [" => list = Some("types"),
            "]" => list = None,
            _ => {
                let entry = line
                    .strip_prefix("{ path = \"")
                    .and_then(|row| row.split_once("\", reason = \""))
                    .filter(|(_, reason)| {
                        reason
                            .strip_suffix("\" },")
                            .is_some_and(|reason| !reason.contains('"'))
                    });
                match (list, entry) {
                    (Some(kind), Some((path, _))) => entries.push((kind, path)),
                    _ => problems.push(format!("unexpected config line: {line}")),
                }
            }
        }
    }
    for (kind, path) in &entries {
        if !plants.contains(&(*kind, *path)) {
            problems.push(format!("missing {kind} plant: {path}"));
        }
    }
    for kind in ["methods", "types"] {
        if !entries.iter().any(|(listed, _)| *listed == kind) {
            problems.push(format!("empty disallowed-{kind}"));
        }
    }
    problems
}

#[test]
fn every_lint_entry_has_a_planted_use() {
    let _: fn() = plants;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    assert!(
        !root.join(".clippy.toml").exists(),
        "Clippy reads .clippy.toml in place of clippy.toml"
    );
    let config = std::fs::read_to_string(root.join("clippy.toml")).unwrap();
    let source = std::fs::read_to_string(root.join("src/sim/lint_tests.rs")).unwrap();
    assert_eq!(unplanted(&config, &source), Vec::<String>::new());

    let row = |path: &str| format!("    {{ path = \"{path}\", reason = \"r\" }},");
    let listed = |list: &str, row: &str| {
        let header = format!("disallowed-{list} = [\n");
        config.replacen(&header, &format!("{header}{row}\n"), 1)
    };
    let joined = format!(
        "{} {}",
        row("control::first"),
        row("control::second").trim()
    );
    let config_cases = [
        (
            listed("methods", &row("control::unplanted")),
            "missing methods plant: control::unplanted".to_owned(),
        ),
        (
            listed("methods", &row("std::collections::HashMap")),
            "missing methods plant: std::collections::HashMap".to_owned(),
        ),
        (
            listed("types", &row("std::time::Instant::now")),
            "missing types plant: std::time::Instant::now".to_owned(),
        ),
        (
            config.split("disallowed-types").next().unwrap().to_owned(),
            "empty disallowed-types".to_owned(),
        ),
        (
            listed("methods", &joined),
            format!("unexpected config line: {}", joined.trim()),
        ),
        (
            format!("{}\n{config}", row("control::outside")),
            format!("unexpected config line: {}", row("control::outside").trim()),
        ),
    ];
    for (edited, problem) in config_cases {
        assert_eq!(unplanted(&edited, &source), [problem]);
    }
    assert_eq!(
        unplanted("", &source),
        ["empty disallowed-methods", "empty disallowed-types"]
    );

    let method = format!("{METHOD}\n    let _ = std::time::Instant::now;");
    let alias = format!("{TYPE}\n    type Map = std::collections::HashMap<(), ()>;");
    let system = format!("{METHOD}\n    let _ = std::time::SystemTime::now;");
    let source_cases = [
        (
            source.replacen(&method, &method.replace("expect", "allow"), 1),
            "std::time::Instant::now",
        ),
        (
            source.replacen(&alias, &alias.replace("expect", "allow"), 1),
            "std::collections::HashMap",
        ),
        (
            source.replacen(&method, &format!("#[cfg(any())]\n    {method}"), 1),
            "std::time::Instant::now",
        ),
        (
            source.replacen(&method, &method.replace("let _", "// let _"), 1),
            "std::time::Instant::now",
        ),
        (
            source.replacen(&system, &format!("/*\n    {system}\n    */"), 1),
            "std::time::SystemTime::now",
        ),
        (
            source
                .replacen(
                    "let _ = libc::clock_gettime;",
                    "let _ = libc::clock_gettime; /*",
                    1,
                )
                .replacen("let _ = libc::getrandom;", "let _ = libc::getrandom; */", 1),
            "libc::clock_gettime",
        ),
        (
            source.replacen(
                "fn plants() {",
                "#[allow(unfulfilled_lint_expectations)]\nfn plants() {",
                1,
            ),
            "std::thread::sleep",
        ),
    ];
    for (edited, path) in source_cases {
        let problems = unplanted(&config, &edited);
        let missing = ["methods", "types"].map(|kind| format!("missing {kind} plant: {path}"));
        assert!(
            missing.iter().any(|problem| problems.contains(problem)),
            "{path}: {problems:?}"
        );
    }
}
