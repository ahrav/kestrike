//! The controller's Rust source, read with the crate's lexer: its calls go through `Controller::aws`
//! as the five calls alone, `Controller::aws` reaches the seam once, the seam `System` is named once,
//! in the tool's root, the one `launch` call stands in `src/host_stop/seam.rs` and holds the one
//! process start, and no other way to start a process or open a connection stands in the source.
//!
//! The scanned source is each production file under `src/host_stop/`, `src/host_stop_controller/`,
//! `src/gameday/` and the tool's root `src/tools/host_stop_controller/`: every `.rs` file there but
//! the unit test files (`*_tests.rs`) and the test support of `src/gameday/`. A `use` item names no
//! call, so the counts below pass over the tokens between `use` and its `;`.

use std::fs;
use std::path::{Path, PathBuf};

use kestrike_tools::rust_text::{Lexeme, lexemes};

/// The five calls, each as its first two words.
const FIVE: [(&str, &str); 5] = [
    ("cloudwatch", "describe-alarms"),
    ("ec2", "describe-instance-status"),
    ("ec2", "describe-instances"),
    ("ec2", "stop-instances"),
    ("sts", "get-caller-identity"),
];

const DIRECTORIES: [&str; 4] = [
    "src/host_stop",
    "src/host_stop_controller",
    "src/gameday",
    "src/tools/host_stop_controller",
];

#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    Ident(String),
    Str(String),
    Punct(char),
}

/// One scanned file: its path below the package and its tokens.
#[derive(Clone, Debug)]
struct Source {
    path: String,
    tokens: Vec<Token>,
}

fn package() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The tokens of `text`: identifiers, the contents of string literals and every other character
/// outside whitespace, comments, char literals and numbers.
fn tokens(text: &str) -> Vec<Token> {
    let mut found = Vec::new();
    let mut at = 0;
    for (kind, start, end) in lexemes(text) {
        code(&text[at..start], &mut found);
        if kind == Lexeme::String {
            let literal = &text[start..end];
            let open = literal
                .find('"')
                .expect("a string literal opens with a quote");
            let close = literal
                .rfind('"')
                .expect("a string literal closes with a quote");
            found.push(Token::Str(literal[open + 1..close].to_owned()));
        }
        at = end;
    }
    code(&text[at..], &mut found);
    found
}

fn code(text: &str, found: &mut Vec<Token>) {
    let mut chars = text.char_indices().peekable();
    while let Some((start, c)) = chars.next() {
        if c.is_alphanumeric() || c == '_' {
            let mut end = start + c.len_utf8();
            while let Some(&(at, next)) = chars.peek() {
                if !(next.is_alphanumeric() || next == '_') {
                    break;
                }
                end = at + next.len_utf8();
                chars.next();
            }
            if !c.is_ascii_digit() {
                found.push(Token::Ident(text[start..end].to_owned()));
            }
        } else if !c.is_whitespace() {
            found.push(Token::Punct(c));
        }
    }
}

/// The scanned files, in the order of their paths.
fn scanned() -> Vec<Source> {
    fn walk(dir: &Path, files: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(dir).expect("the directory lists") {
            let path = entry.expect("the directory lists").path();
            if path.is_dir() {
                walk(&path, files);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                files.push(path);
            }
        }
    }
    let mut files = Vec::new();
    for dir in DIRECTORIES {
        walk(&package().join(dir), &mut files);
    }
    files.sort();
    files
        .into_iter()
        .filter(|path| {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("");
            !name.ends_with("_tests.rs") && name != "test_support.rs"
        })
        .map(|path| Source {
            path: path
                .strip_prefix(package())
                .expect("under the package")
                .to_string_lossy()
                .into_owned(),
            tokens: tokens(&fs::read_to_string(&path).expect("the source reads")),
        })
        .collect()
}

fn ident(token: Option<&Token>, name: &str) -> bool {
    matches!(token, Some(Token::Ident(found)) if found == name)
}

fn punct(token: Option<&Token>, c: char) -> bool {
    token == Some(&Token::Punct(c))
}

/// The indices of `tokens` outside `use` items.
fn outside_use(tokens: &[Token]) -> Vec<usize> {
    let mut kept = Vec::new();
    let mut inside = false;
    for (at, token) in tokens.iter().enumerate() {
        if !inside && ident(Some(token), "use") {
            inside = true;
        }
        if !inside {
            kept.push(at);
        }
        if inside && punct(Some(token), ';') {
            inside = false;
        }
    }
    kept
}

/// Each place in `sources` where `name` stands as a free call, `name(` not after `.` or `fn`, a
/// path's last name included, with the file's path.
fn free_calls(sources: &[Source], name: &str) -> Vec<String> {
    let mut found = Vec::new();
    for source in sources {
        let t = &source.tokens;
        for at in outside_use(t) {
            let before = at.checked_sub(1).map(|b| &t[b]);
            if ident(t.get(at), name)
                && punct(t.get(at + 1), '(')
                && !punct(before, '.')
                && !ident(before, "fn")
            {
                found.push(source.path.clone());
            }
        }
    }
    found
}

/// Each place outside `use` items where the identifier `name` stands, with the file's path.
fn named(sources: &[Source], name: &str) -> Vec<String> {
    let mut found = Vec::new();
    for source in sources {
        for at in outside_use(&source.tokens) {
            if ident(source.tokens.get(at), name) {
                found.push(source.path.clone());
            }
        }
    }
    found
}

/// The tokens from the `(` at `open` to its matching `)`, split at the commas at depth one.
fn arguments(t: &[Token], open: usize) -> Vec<Vec<Token>> {
    let mut depth = 0usize;
    let mut args = vec![Vec::new()];
    for token in &t[open..] {
        match token {
            Token::Punct('(' | '[' | '{') => {
                depth += 1;
                if depth == 1 {
                    continue;
                }
            }
            Token::Punct(')' | ']' | '}') => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            Token::Punct(',') if depth == 1 => {
                args.push(Vec::new());
                continue;
            }
            _ => {}
        }
        args.last_mut()
            .expect("one argument stands")
            .push(token.clone());
    }
    args
}

/// Whether `t[b]` is `name` bound by `let name =` or `let mut name =`.
fn binds(t: &[Token], b: usize, name: &str) -> bool {
    let before = |back: usize| b.checked_sub(back).and_then(|at| t.get(at));
    let introduced =
        ident(before(1), "let") || (ident(before(1), "mut") && ident(before(2), "let"));
    ident(t.get(b), name) && introduced && punct(t.get(b + 1), '=')
}

/// The first two string literals in `tokens`.
fn words(tokens: &[Token]) -> Option<(String, String)> {
    let mut strings = tokens.iter().filter_map(|token| match token {
        Token::Str(text) => Some(text.clone()),
        _ => None,
    });
    Some((strings.next()?, strings.next()?))
}

/// A call site's first two words and the name after `Kind::`.
type Site = ((String, String), String);

/// Each `.aws(` call site of `sources`: its first two words and the name after `Kind::`. The first
/// argument is a slice literal or `&` and the name of a binding whose `let` before the site holds the
/// words.
fn call_sites(sources: &[Source]) -> Result<Vec<Site>, String> {
    let mut found = Vec::new();
    for source in sources {
        let t = &source.tokens;
        for at in 1..t.len() {
            if !(punct(t.get(at - 1), '.') && ident(t.get(at), "aws") && punct(t.get(at + 1), '('))
            {
                continue;
            }
            let args = arguments(t, at + 1);
            let [first, _, kind] = args.as_slice() else {
                return Err(format!(
                    "{}: a call of aws takes three arguments: {args:?}",
                    source.path
                ));
            };
            let words = match first.as_slice() {
                [Token::Punct('&'), Token::Ident(binding)] => {
                    let bound = (0..at).rev().find(|&b| binds(t, b, binding));
                    let Some(bound) = bound else {
                        return Err(format!(
                            "{}: {binding} is bound before its call",
                            source.path
                        ));
                    };
                    let end = (bound..at).find(|&e| punct(t.get(e), ';')).unwrap_or(at);
                    words(&t[bound..end])
                }
                [Token::Punct('&'), Token::Punct('['), ..] => words(first),
                other => return Err(format!("{}: aws is called with {other:?}", source.path)),
            };
            let Some(words) = words else {
                return Err(format!("{}: a call of aws names no two words", source.path));
            };
            let kind = match kind.as_slice() {
                [
                    Token::Ident(kind),
                    Token::Punct(':'),
                    Token::Punct(':'),
                    Token::Ident(name),
                ] if kind == "Kind" => name.clone(),
                other => {
                    return Err(format!(
                        "{}: aws is called with the kind {other:?}",
                        source.path
                    ));
                }
            };
            found.push((words, kind));
        }
    }
    Ok(found)
}

/// The five calls' check over `sources`, `Err` naming the first rule that fails.
fn five_calls(sources: &[Source]) -> Result<(), String> {
    let sites = call_sites(sources)?;
    let mut ops: Vec<(String, String)> = sites.iter().map(|(words, _)| words.clone()).collect();
    ops.sort();
    let five: Vec<(String, String)> = FIVE
        .iter()
        .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
        .collect();
    if ops != five {
        return Err(format!("the call sites name {ops:?}"));
    }
    let stops: Vec<&String> = sites
        .iter()
        .filter(|(_, kind)| kind != "Read")
        .map(|((_, op), _)| op)
        .collect();
    if stops != ["stop-instances"]
        || sites
            .iter()
            .any(|(_, kind)| kind != "Read" && kind != "Stop")
    {
        return Err(format!("the calls other than reads are {stops:?}"));
    }
    for source in sources {
        let t = &source.tokens;
        for at in outside_use(t) {
            if !ident(t.get(at), "aws") {
                continue;
            }
            let before = at.checked_sub(1).map(|b| &t[b]);
            let called = punct(before, '.') && punct(t.get(at + 1), '(');
            let defined = ident(before, "fn");
            if !called && !defined {
                return Err(format!(
                    "{}: aws is named other than in a call",
                    source.path
                ));
            }
        }
    }
    let replies = free_calls(sources, "reply");
    if replies != ["src/host_stop_controller/controller.rs"] {
        return Err(format!("the seam's reply is called in {replies:?}"));
    }
    let calls = method_calls(sources, "call");
    if calls != ["src/host_stop/call.rs"] {
        return Err(format!("a seam's call is made in {calls:?}"));
    }
    Ok(())
}

/// Each place in `sources` where `.name(` stands, with the file's path.
fn method_calls(sources: &[Source], name: &str) -> Vec<String> {
    let mut found = Vec::new();
    for source in sources {
        let t = &source.tokens;
        for at in 1..t.len() {
            if punct(t.get(at - 1), '.') && ident(t.get(at), name) && punct(t.get(at + 1), '(') {
                found.push(source.path.clone());
            }
        }
    }
    found
}

/// The seam's check over `sources`: `System` is named once, in the tool's root, outside its own
/// file and the layer's list of exports, and `launch` is called once, in the seam's file, and named
/// nowhere else as a value: each other `launch` is a binding, a member, a module or a definition of
/// that name.
fn named_once(sources: &[Source]) -> Result<(), String> {
    let others: Vec<Source> = sources
        .iter()
        .filter(|s| s.path != "src/host_stop/seam.rs" && s.path != "src/host_stop/mod.rs")
        .cloned()
        .collect();
    let system = named(&others, "System");
    if system != ["src/tools/host_stop_controller/mod.rs"] {
        return Err(format!("System is named in {system:?}"));
    }
    let launches = free_calls(sources, "launch");
    if launches != ["src/host_stop/seam.rs"] {
        return Err(format!("launch is called in {launches:?}"));
    }
    for source in sources {
        let t = &source.tokens;
        for at in outside_use(t) {
            if !ident(t.get(at), "launch") {
                continue;
            }
            let before = at.checked_sub(1).map(|b| &t[b]);
            let after = t.get(at + 1);
            let call_or_member = punct(after, '(') || punct(after, '.') || punct(after, ':');
            let binding = ident(before, "let") || ident(before, "mut");
            let access = punct(before, '.') || ident(before, "fn") || ident(before, "mod");
            if !(call_or_member || binding || access) {
                return Err(format!("{}: launch is named as a value", source.path));
            }
        }
    }
    Ok(())
}

/// The names of `libc` whose call starts a program, replaces this one, or loads code.
const LAUNCHES: [&str; 17] = [
    "fork",
    "vfork",
    "clone",
    "clone3",
    "execv",
    "execve",
    "execvp",
    "execvpe",
    "execl",
    "execle",
    "execlp",
    "fexecve",
    "posix_spawn",
    "posix_spawnp",
    "system",
    "popen",
    "dlopen",
];

/// The types of the standard library that open a connection.
const NETWORK_TYPES: [&str; 7] = [
    "TcpStream",
    "TcpListener",
    "UdpSocket",
    "UnixStream",
    "UnixListener",
    "UnixDatagram",
    "ToSocketAddrs",
];

/// The names of `libc` that open a connection.
const NETWORK_CALLS: [&str; 2] = ["socket", "connect"];

/// The library modules the scanned files may name by a `crate::` path, with the one item named where
/// only one may be: none of them starts a process.
const CRATE_MODULES: [(&str, Option<&str>); 13] = [
    ("args", None),
    ("classes", None),
    ("decimal", None),
    ("environ", None),
    ("fixtures", Some("close")),
    ("gameday", None),
    ("host_stop", None),
    ("host_stop_controller", None),
    ("json", None),
    ("paths", None),
    ("plants", Some("files")),
    ("python", None),
    ("text", None),
];

fn barred(name: &str) -> bool {
    LAUNCHES.contains(&name) || NETWORK_CALLS.contains(&name)
}

/// The process check over `sources`: `Command::new` stands once, in the launch's file, which alone
/// names `process`; no `use` renames an item of `std` or `libc` or takes a launch of `libc`; no
/// `libc` call starts a program or loads code, no `.exec(` replaces this one, no connection opens,
/// and each `crate::` path names a library module of [`CRATE_MODULES`].
fn one_launch(sources: &[Source]) -> Result<(), String> {
    let mut news = Vec::new();
    for source in sources {
        let t = &source.tokens;
        for at in 0..t.len() {
            let path = |name: &str| {
                ident(t.get(at), name) && punct(t.get(at + 1), ':') && punct(t.get(at + 2), ':')
            };
            if ident(t.get(at), "process") && source.path != "src/host_stop/launch.rs" {
                return Err(format!("{}: process is named", source.path));
            }
            if path("Command") && ident(t.get(at + 3), "new") {
                news.push(source.path.clone());
            }
            if path("libc")
                && let Some(Token::Ident(name)) = t.get(at + 3)
                && barred(name)
            {
                return Err(format!("{}: libc::{name} is called", source.path));
            }
            if path("crate")
                && let Some(Token::Ident(module)) = t.get(at + 3)
            {
                let allowed = CRATE_MODULES.iter().find(|(name, _)| name == module);
                let item = |name: &str| {
                    punct(t.get(at + 4), ':')
                        && punct(t.get(at + 5), ':')
                        && ident(t.get(at + 6), name)
                };
                match allowed {
                    Some((_, None)) => {}
                    Some((_, Some(only))) if item(only) => {}
                    _ => return Err(format!("{}: crate::{module} is named", source.path)),
                }
            }
            if path("std") && ident(t.get(at + 3), "net")
                || path("unix") && ident(t.get(at + 3), "net")
            {
                return Err(format!("{}: a network module is named", source.path));
            }
            if let Some(Token::Ident(name)) = t.get(at)
                && NETWORK_TYPES.contains(&name.as_str())
            {
                return Err(format!("{}: {name} is named", source.path));
            }
            if punct(t.get(at), '.') && ident(t.get(at + 1), "exec") && punct(t.get(at + 2), '(') {
                return Err(format!("{}: exec replaces the process", source.path));
            }
        }
        let mut item: Option<Vec<&Token>> = None;
        for token in t {
            if ident(Some(token), "use") {
                item = Some(Vec::new());
            }
            let Some(held) = item.as_mut() else {
                continue;
            };
            held.push(token);
            if punct(Some(token), ';') {
                let renames = held.iter().any(|token| ident(Some(token), "as"));
                let system = held
                    .iter()
                    .any(|token| ident(Some(token), "std") || ident(Some(token), "libc"));
                if renames && system {
                    return Err(format!(
                        "{}: a use item renames an item of std or libc",
                        source.path
                    ));
                }
                let libc = held.iter().any(|token| ident(Some(token), "libc"));
                let named = held
                    .iter()
                    .any(|token| matches!(token, Token::Ident(name) if barred(name)));
                if libc && named {
                    return Err(format!(
                        "{}: a use item takes a launch of libc",
                        source.path
                    ));
                }
                item = None;
            }
        }
    }
    if news != ["src/host_stop/launch.rs"] {
        return Err(format!("Command::new stands in {news:?}"));
    }
    Ok(())
}

/// The calls of the controller through `Controller::aws` are the five calls: the stop request
/// alone passes `Kind::Stop`, which turns the CLI's retries off, and every other call is a read.
/// `aws` is named only in a call or in its definition, `reply` reaches the seam once, from
/// `Controller::aws`, and a seam's `call` is made once, in `reply`.
#[test]
fn the_call_sites_are_the_five_calls() {
    let sources = scanned();
    assert!(
        sources
            .iter()
            .any(|s| s.path == "src/host_stop_controller/controller.rs")
    );
    five_calls(&sources).unwrap_or_else(|failed| panic!("{failed}"));
}

/// The seam `System` is named once, where the tool's root builds the seam, and the one `launch`
/// call stands in the seam's `call`.
#[test]
fn aws_cli_is_named_once_as_mains_default() {
    named_once(&scanned()).unwrap_or_else(|failed| panic!("{failed}"));
}

/// One `Command::new`, in the launch's file, which alone names `std::process`; no `libc` call that
/// starts a program, replaces this one or loads code, and no network interface.
#[test]
fn one_process_launch_and_no_other_way_out() {
    one_launch(&scanned()).unwrap_or_else(|failed| panic!("{failed}"));
}

/// Each launch written another way, appended to the scanned source as a file of its own, fails
/// the process check or the seam's check.
#[test]
fn the_scan_sees_a_launch_written_another_way() {
    let plants = [
        "use std::process::Command as Spawn;\n",
        "use std::process as p;\n",
        "fn f() { let _ = std::process::Command::new(\"aws\").spawn(); }\n",
        "fn f() { let _ = unsafe { libc::posix_spawnp(a, b, c, d, e, g) }; }\n",
        "fn f() { let _ = unsafe { libc::fork() }; }\n",
        "fn f() { let _ = std::net::TcpStream::connect(\"a:1\"); }\n",
        "fn f(record: &mut Record<'_>, call: &Call<'_>) { let _ = launch(record, call); }\n",
        "fn f(record: &mut Record<'_>, call: &Call<'_>) { let _ = System.call(record, call); }\n",
        "fn f() { let run = launch; }\n",
        "fn f(r: &mut Record<'_>, c: &Call<'_>) { let _ = crate::host_stop::launch(r, c); }\n",
        "fn f(r: &mut Record<'_>, c: &Call<'_>) { let _ = super::launch::launch(r, c); }\n",
        "use libc::{fork};\nfn f() { let _ = unsafe { fork() }; }\n",
        "use libc as c;\nfn f() { let _ = unsafe { c::fork() }; }\n",
        "fn f(e: &Environ, d: &Path) { let _ = crate::plants::git::text(e, d, &[]); }\n",
    ];
    let sources = scanned();
    assert_eq!(one_launch(&sources), Ok(()));
    assert_eq!(named_once(&sources), Ok(()));
    for plant in plants {
        let mut planted = sources.clone();
        planted.push(Source {
            path: "src/host_stop/plant.rs".to_owned(),
            tokens: tokens(plant),
        });
        assert!(
            one_launch(&planted).is_err() || named_once(&planted).is_err(),
            "{plant}"
        );
    }
    for site in [
        "fn f(&mut self) { let _ = self.aws(&[\"ec2\", \"start-instances\"], None, Kind::Read); }\n",
        "fn f(s: &mut System, r: &mut Record<'_>, c: &Call<'_>) { let _ = crate::host_stop::reply(s, r, c); }\n",
    ] {
        let mut calls = sources.clone();
        calls.push(Source {
            path: "src/host_stop_controller/plant.rs".to_owned(),
            tokens: tokens(site),
        });
        assert!(five_calls(&calls).is_err(), "{site}");
    }
}

/// The first statement of the tool root's `run` on Linux, after its `use` items, installs the signal
/// record's handlers, `if let Err(error) = install(&DELIVERED)`.
fn installs_first(source: &Source) -> Result<(), String> {
    let t = &source.tokens;
    let start = (0..t.len())
        .find(|&at| ident(t.get(at), "fn") && ident(t.get(at + 1), "run"))
        .ok_or("the root holds no fn run")?;
    let open = (start..t.len())
        .find(|&at| punct(t.get(at), '{'))
        .ok_or("fn run has no body")?;
    let kept = outside_use(t);
    let first = kept
        .into_iter()
        .find(|&at| at > open)
        .ok_or("fn run's body is empty")?;
    let expected = [
        Token::Ident("if".to_owned()),
        Token::Ident("let".to_owned()),
        Token::Ident("Err".to_owned()),
        Token::Punct('('),
        Token::Ident("error".to_owned()),
        Token::Punct(')'),
        Token::Punct('='),
        Token::Ident("install".to_owned()),
        Token::Punct('('),
        Token::Punct('&'),
        Token::Ident("DELIVERED".to_owned()),
        Token::Punct(')'),
    ];
    if t.get(first..first + expected.len()) == Some(&expected[..]) {
        Ok(())
    } else {
        Err(format!(
            "fn run starts with {:?}",
            t.get(first..first + expected.len())
        ))
    }
}

/// The tool's root installs the signal record's handlers as the first statement of its `run`, ahead
/// of the argument reading and of every other act of the run; a `run` that reads the environment
/// first fails the scan.
#[test]
fn the_roots_first_statement_installs_the_handlers() {
    let root = scanned()
        .into_iter()
        .find(|source| source.path == "src/tools/host_stop_controller/mod.rs")
        .expect("the root is scanned");
    installs_first(&root).unwrap_or_else(|failed| panic!("{failed}"));
    let planted = Source {
        path: root.path.clone(),
        tokens: tokens(
            "pub fn run(top: &Path, args: &[OsString]) -> u8 {\n    use std::io;\n    \
             let env: Vec<(OsString, OsString)> = std::env::vars_os().collect();\n    \
             if let Err(error) = install(&DELIVERED) {\n        return 2;\n    }\n    0\n}\n",
        ),
    };
    assert!(installs_first(&planted).is_err());
}
