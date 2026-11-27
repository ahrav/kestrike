//! The cases that call the tool's readers: the debug-assertion entry, and the committed configuration
//! and workflow file against the tracked files.

use std::path::Path;
use std::process::Command;

use kestrike_tools::text::is_space;
use kestrike_tools::tools::mutants_diff::{debug_assertions, pins, stables};

use super::fixture::CONFIG;

#[test]
fn the_debug_assertion_entry_is_read_from_the_array_and_not_from_a_comment() {
    assert_eq!(debug_assertions(CONFIG), Ok(Some("false".to_owned())));
    let rows: [(&str, Option<&str>); 11] = [
        (
            "additional_cargo_args = [\n    \"--config\",\n    \"profile.dev.debug-assertions=true\", # why\n]\n",
            Some("true"),
        ),
        (
            "additional_cargo_args = ['--config', 'profile.dev.debug-assertions=true']\n",
            Some("true"),
        ),
        (
            "  additional_cargo_args = [\"--config\", \"profile.dev.debug-assertions=true\"]\n",
            Some("true"),
        ),
        (
            "additional_cargo_args = [\"--config=profile.dev.debug-assertions=true\"]\n",
            Some("true"),
        ),
        (
            "additional_cargo_args = [\"--config\", \"profile.dev.debug-assertions = true\"]\n",
            Some("true"),
        ),
        (
            "additional_cargo_args = [\"--config\", \"profile.dev.debug-assertions=false\", \"--config\",\n    \
             \"profile.dev.debug-assertions=true\"]\n",
            Some("true"),
        ),
        (
            "additional_cargo_args = [\"a]b\", \"--config\", \"profile.dev.debug-assertions=true\"]\n",
            Some("true"),
        ),
        (
            "\"additional_cargo_args\" = [\"--config\", \"profile.dev.debug-assertions=true\"]\n",
            Some("true"),
        ),
        (
            "'additional_cargo_args' = ['--config', 'profile.dev.debug-assertions=true']\n",
            Some("true"),
        ),
        (
            "additional_cargo_args = []  # \"profile.dev.debug-assertions=true\"\n",
            None,
        ),
        (
            "exclude_re = [\"profile.dev.debug-assertions=true\"]\n",
            None,
        ),
    ];
    for (text, value) in rows {
        assert_eq!(
            debug_assertions(text),
            Ok(value.map(str::to_owned)),
            "{text:?}"
        );
    }
    for text in [
        "additional_cargo_args = [\"--config\", \"profile.test.debug-assertions=true\"]\n",
        "additional_cargo_args = [profile]\n",
    ] {
        assert!(debug_assertions(text).is_err(), "{text:?}");
    }
}

/// One piece of an `exclude_globs` entry: `**/` takes zero or more whole directories, a final `/**` a
/// slash and the rest of the path, `*` a run of characters other than `/`, and `?` one of them.
#[derive(Clone, Copy, Debug)]
enum Piece {
    Literal(char),
    Directories,
    Rest,
    Star,
    One,
}

fn pieces(glob: &str) -> Vec<Piece> {
    let mut found = Vec::new();
    let mut rest = glob;
    while let Some(next) = rest.chars().next() {
        let (piece, used) = if rest.starts_with("**/") {
            (Piece::Directories, 3)
        } else if rest == "/**" {
            (Piece::Rest, 3)
        } else if next == '*' {
            (Piece::Star, 1)
        } else if next == '?' {
            (Piece::One, 1)
        } else {
            (Piece::Literal(next), next.len_utf8())
        };
        found.push(piece);
        rest = &rest[used..];
    }
    found
}

/// `matches` holds when `path` matches all of `pieces` from its start to its end.
fn matches(pieces: &[Piece], path: &str) -> bool {
    let Some((first, later)) = pieces.split_first() else {
        return path.is_empty();
    };
    match first {
        Piece::Literal(c) => path
            .strip_prefix(*c)
            .is_some_and(|rest| matches(later, rest)),
        Piece::Rest => path.starts_with('/'),
        Piece::One => path
            .chars()
            .next()
            .is_some_and(|c| c != '/' && matches(later, &path[c.len_utf8()..])),
        Piece::Star => {
            let end = path.find('/').unwrap_or(path.len());
            path.char_indices()
                .map(|(at, _)| at)
                .chain([path.len()])
                .take_while(|&at| at <= end)
                .any(|at| matches(later, &path[at..]))
        }
        Piece::Directories => {
            let cuts = std::iter::once(0).chain(path.match_indices('/').map(|(at, _)| at + 1));
            cuts.into_iter().any(|at| matches(later, &path[at..]))
        }
    }
}

/// `strings` returns the contents of the strings in either quote of `text`, refusing any character
/// outside them other than whitespace and commas.
fn strings(text: &str) -> Result<Vec<&str>, String> {
    let mut found = Vec::new();
    let mut rest = text;
    while let Some(next) = rest.chars().next() {
        if (next == '"' || next == '\'')
            && let Some(end) = rest[1..].find(next)
        {
            found.push(&rest[1..=end]);
            rest = &rest[end + 2..];
            continue;
        }
        if !(next == ',' || is_space(u32::from(next))) {
            return Err(format!("exclude_globs holds {next:?} outside its strings"));
        }
        rest = &rest[next.len_utf8()..];
    }
    Ok(found)
}

/// `exclude_globs` returns the body of the `exclude_globs` array: from its `[` to the first `]` that
/// starts a line, with comments removed.
fn exclude_globs(config: &str) -> Result<String, String> {
    let starts = std::iter::once(0).chain(config.match_indices('\n').map(|(at, _)| at + 1));
    let body = starts
        .filter_map(|start| {
            let rest = config[start..].strip_prefix("exclude_globs")?;
            let rest = rest
                .trim_start_matches(|c: char| is_space(u32::from(c)))
                .strip_prefix('=')?;
            rest.trim_start_matches(|c: char| is_space(u32::from(c)))
                .strip_prefix('[')
        })
        .find_map(|body| body.find("\n]").map(|end| &body[..=end]))
        .ok_or_else(|| "the configuration has no exclude_globs array".to_owned())?;
    Ok(body
        .split('\n')
        .map(|line| line.split_once('#').map_or(line, |(kept, _)| kept))
        .collect::<Vec<_>>()
        .join("\n"))
}

/// `unmatched_globs` returns the `exclude_globs` entries of `config` that match none of the `tracked`
/// paths.
fn unmatched_globs(config: &str, tracked: &[String]) -> Result<Vec<String>, String> {
    let body = exclude_globs(config)?;
    let globs = strings(&body)?;
    Ok(globs
        .into_iter()
        .filter(|glob| {
            let pieces = pieces(glob);
            !tracked
                .iter()
                .filter(|path| !path.is_empty())
                .any(|path| matches(&pieces, path))
        })
        .map(str::to_owned)
        .collect())
}

#[test]
fn every_exclusion_of_the_committed_configuration_matches_a_tracked_file() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let config = std::fs::read_to_string(root.join(".cargo/mutants.toml"))
        .expect("the configuration is UTF-8");
    assert_eq!(pins(&config).len(), 1, "the runner reads one pin line");
    assert_eq!(
        debug_assertions(&config),
        Ok(Some("false".to_owned())),
        "the runner reads the committed setting"
    );
    let workflow = std::fs::read_to_string(root.join(".github/workflows/agent-checks.yml"))
        .expect("the workflow is UTF-8");
    assert_eq!(
        stables(&workflow).len(),
        1,
        "the runner reads one STABLE pin"
    );
    let mut command = Command::new("git");
    command.args(["ls-files", "-z"]).current_dir(&root);
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("GIT_") {
            command.env_remove(name);
        }
    }
    let listed = command.output().expect("git starts");
    assert!(
        listed.status.success(),
        "{}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let tracked: Vec<String> = String::from_utf8(listed.stdout)
        .expect("UTF-8 paths")
        .split('\0')
        .map(str::to_owned)
        .collect();
    assert_eq!(unmatched_globs(&config, &tracked), Ok(Vec::new()));
    let opening = config
        .find("\nexclude_globs = [\n")
        .map(|at| at + "\nexclude_globs = [\n".len());
    let start = opening
        .or_else(|| {
            config
                .strip_prefix("exclude_globs = [\n")
                .map(|_| "exclude_globs = [\n".len())
        })
        .expect("the array opens a line");
    for (entry, dead) in [
        (
            "\"crates/kestrike/src/absent/**\"",
            "crates/kestrike/src/absent/**",
        ),
        (
            "'crates/kestrike/src/absent/**'",
            "crates/kestrike/src/absent/**",
        ),
        ("\"\"", ""),
    ] {
        let planted = format!(
            "{}    {entry}, # a reason\n{}",
            &config[..start],
            &config[start..]
        );
        assert_eq!(
            unmatched_globs(&planted, &tracked),
            Ok(vec![dead.to_owned()]),
            "{entry}"
        );
    }
    let bare = format!("{}    bare,\n{}", &config[..start], &config[start..]);
    assert!(unmatched_globs(&bare, &tracked).is_err());
}
