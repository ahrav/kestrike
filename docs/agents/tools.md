# Tools

Read this before you start, add or change a tool under `crates/kestrike-tools`, port a script to one, or
change a Python file that a row of [Rules held twice](#rules-held-twice) names.
The repository's tools are modules of one Rust binary. A caller starts a tool through one launcher, and a
port keeps its script's contract.

## The command

```sh
bash scripts/tool.sh <tool> [argument ...]
```

`<tool>` is the stem of the script the tool replaces. Where two ported scripts share a stem, the name is the
script's directory, a hyphen and the stem. A caller that ran `python3 [-I] <path>/<stem>.py <arguments>`
runs `bash scripts/tool.sh <tool> <arguments>` and changes nothing else.

## The launcher

`scripts/tool.sh` finds the checkout's top level from its own file, with every link to the file or to a
directory above it resolved, so it runs from any directory and leaves the caller's working directory as it
is. The preparation below runs in a subshell, so its working variables, its working directory and the
environment it gives rustup and Cargo stay out of the final step. It runs each rustup and Cargo call in the
top level. Before the first, it makes a relative `RUSTUP_HOME` or `CARGO_HOME` absolute against the caller's
physical directory, since rustup and Cargo read a relative value against their own working directory, and
finds `rustup` on the caller's `PATH` from the caller's directory: it takes each entry as written, as
`exec` does, so a `~` stays a literal name, reads an empty entry as the caller's directory, and picks the
first executable regular file named `rustup`, passing over a shell function of that name. An unexported
`PATH` reads as `/bin:/usr/bin`, the C library's default. An empty `CARGO_HOME` stays empty, and an empty
`RUSTUP_HOME` is unset for the launcher's own rustup and Cargo calls; rustup and Cargo read both forms as
unset, and Cargo's rustc cache stays on. Before all of this, the launcher refuses where a variable it
clears or sets below, or `RUSTUP_HOME` or `CARGO_HOME`, is readonly in its own shell, as a `BASH_ENV`
file can make one: bash keeps a readonly variable's value when `unset`, `export` or an assignment of it
fails. It reads each variable's attributes in bash, set or unset. The launcher needs bash 4.4 or later,
for `mapfile -d`. On every call it:

1. Reads the stable toolchain that `.github/workflows/agent-checks.yml` pins as `STABLE`, and checks
   that `rustup toolchain list` names `<pin>-<host>` as the first word of a line. The launcher installs
   nothing. The workflow path must be a regular file once links are followed. A line ends at a line feed
   or a carriage return, so `\r\n` and a lone `\r` both end one. A line that holds, after spaces or tabs
   alone, `STABLE: "VALUE"` is a pin, where `VALUE` is one or more characters up to the first `"` on the
   line; text after that quote is allowed. Exactly one such line must stand in the file, and its `VALUE`
   must hold no whitespace. A NUL byte reads as the byte 0x02, an ordinary character. A read error after
   the file opened is refused as a file that cannot be opened is: after `mapfile` returns, the launcher
   reads one more byte and takes only the end of the file as a complete read.
2. Runs the pinned toolchain's own `cargo`, which `rustup which --toolchain <pin> cargo` names by an
   absolute path, with `RUSTC` set to the `rustc` beside it, so neither a `cargo` earlier on `PATH` nor a
   `build.rustc` in a Cargo configuration file replaces the pin. It builds the `kestrike-tools` binary for
   the host (`--target <host>`, which also takes the place of a configured `build.target`) into
   `target/tools/<host>/debug`, with the top level as the build's working directory, `RUSTUP_TOOLCHAIN` set
   to the pinned toolchain's full name `<pin>-<host>`, as the list named it, and `RUSTUP_AUTO_INSTALL=0`.
   For this build it clears `RUSTFLAGS`, `CARGO_ENCODED_RUSTFLAGS`, `RUSTDOCFLAGS`,
   `CARGO_ENCODED_RUSTDOCFLAGS`, every `CARGO_PROFILE_*`, every `CARGO_BUILD_*` except `CARGO_BUILD_JOBS`,
   every `CARGO_TARGET_*` (`CARGO_TARGET_DIR` included), `RUSTDOC`, `RUSTC_WRAPPER` and
   `RUSTC_WORKSPACE_WRAPPER`, and keeps the rest. It then sets `RUSTC_WRAPPER` and `RUSTC_WORKSPACE_WRAPPER`
   to `/usr/bin/env`, which outranks a wrapper a Cargo configuration file names and starts rustc with the
   same arguments and environment. Cargo keeps its cache of rustc's answers in
   `target/tools/.rustc_info.json` only when each wrapper is a file it can hash, and the empty value, which
   Cargo also reads as no wrapper, turns the cache off, so every call would run rustc's probes again. Where
   `/usr/bin/env` is no executable file, or the `rustc` path holds a `=`, which `env` would read as an
   assignment, both wrappers take the empty value instead. While `RUSTUP_HOME` is set, Cargo fingerprints
   rustc for that cache as `RUSTUP_HOME/toolchains/<RUSTUP_TOOLCHAIN>/bin/rustc`: the full name gives the
   path of rustup's own directory for the toolchain, and a bare pin gives no file, which turns the cache
   off. The launcher also sets `CARGO_BUILD_BUILD_DIR=target/tools`, which outranks a configured
   `build.build-dir`, so the build's fingerprints and lock stay under `target/tools`. With `--target`, the
   repository's `target.<cfg>.rustflags` apply to the binary and its dependencies and not to build scripts.
   A tool is then the same program whatever lane starts it. Ahead of Cargo, the launcher starts the pinned
   `rustc -vV` itself in the build's environment, and a rustc that exits nonzero or cannot start fails the
   call as a failed build does: with Cargo's cache, a call that compiles nothing starts no rustc of
   Cargo's, so this check is the one rustc start of a warm call. A toolchain whose `rustc -vV` succeeds
   while a later probe of Cargo's would fail is refused at the next call that compiles. Cargo writes the
   cache through a link at its path, so the launcher refuses, just before Cargo runs, where
   `target/tools/.rustc_info.json` exists and is not a regular file. Cargo stores a probe that ran and
   failed in that file and replays it while rustc's file stands unchanged, so a failed call removes the
   file where it is a regular file, and the next call probes rustc again.
3. Replaces itself with the binary, started as `kestrike-tools <top> <tool> <arguments>` in the caller's
   directory, with `<top>` the top level's canonical path. The binary gets the caller's environment as
   bash passes it on: bash, which runs the launcher, may set `PWD`, `OLDPWD`, `SHLVL` and `_`, and leaves
   every other variable as the caller set it, a relative `RUSTUP_HOME` and `CARGO_HOME` included.

The build prints nothing unless it fails. Cargo's fingerprint decides whether it compiles anything, and
Cargo's lock on `target/tools` makes a second caller wait for the first; that wait has no limit of its
own, so the caller's deadline counts it. The launcher keeps no record of its own of a current binary and
compares no file time: each call resolves the pinned toolchain, runs the one `cargo build` and starts the
binary that build left, and a failed build starts none. Cargo's lock orders the builds of two calls at
once in one checkout and covers the build alone. Where the two builds differ for the same host, the call
whose build ended first can start the binary the other's build left, and the call whose build ended last
starts its own. Two builds differ where the calls' `CARGO_HOME`, `HOME` or `RUSTUP_HOME` differ, or where
the sources are edited between the two builds. The fingerprint compares file times: a source changed
under an older time keeps the old binary until `target/tools` is removed. A first build in a clone writes
the untracked `Cargo.lock`.

The build reads Cargo configuration from the checkout, from each directory above it and from `CARGO_HOME`,
as a script was read from the checkout, so a checkout that another user can write, or one below a
directory another user can write, is no safe place to start a tool from. The launcher adds no check of
its own for that; a tool's own ownership checks run after the build.

### Failures

| Exit | Cause | Output |
| --- | --- | --- |
| 127 | A variable the launcher clears or sets is readonly in its shell | `tool.sh: the variable <name> is readonly` on standard error |
| 127 | The top level cannot be found | `tool.sh: cannot find the top level` |
| 127 | The workflow path is absent, a directory, a FIFO, a device or another file that is not a regular file once links are followed | `tool.sh: <path> is not a regular file` |
| 127 | The workflow is a regular file that cannot be opened, or a read of it fails | `tool.sh: cannot read <path>` |
| 127 | The workflow holds no pin line, two or more, or a pin whose value holds whitespace | `tool.sh: <path> pins no single STABLE toolchain` |
| 127 | No executable regular file named `rustup` stands on `PATH` | `tool.sh: no rustup on PATH` |
| 127 | `rustup show` names no single `Default host` | `tool.sh: rustup names no single host` |
| 127 | `rustup toolchain list` fails | `tool.sh: rustup lists no toolchains` |
| 127 | The list names no `<pin>-<host>`, `rustup which` fails or names no absolute path, or no executable `rustc` stands beside that `cargo` | `tool.sh: the pinned toolchain <pin>-<host> is not installed; install it with: rustup toolchain install <pin>`, `... has no cargo` or `... has no rustc` |
| 127 | `target/tools/.rustc_info.json` exists and is not a regular file: a link, a dangling link, a FIFO or a directory | `tool.sh: <path> is not a regular file` |
| 127 | The pinned `rustc -vV` exits nonzero or cannot start, or the build fails, a first dependency resolution without network included. A toolchain whose `rustc -vV` succeeds while a later probe of Cargo's fails is refused at the next call that compiles | rustc's or Cargo's output, then `tool.sh: the build of kestrike-tools failed`; the launcher removes a regular `target/tools/.rustc_info.json`, and the next call probes rustc and builds again |
| 127 | An entry of `src/tools/` or `tests/` is outside the rules of [Adding a tool](#adding-a-tool), a tool root lacks `NAME` or `run`, or two tools share a name | the build script's `kestrike-tools build script: <path>: <reason>` line or rustc's error, then the line above |
| 2 | The tool name is missing or names no tool | the binary's `kestrike-tools:` line on standard error |

Every other exit code is the tool's own, and no tool returns 127. The launcher exits 127 on its own
failures even when standard error is closed or full.

## Adding a tool

A port adds files. The package's `build.rs` lists `crates/kestrike-tools/src/tools/` and
`crates/kestrike-tools/tests/` whenever Cargo runs it and declares a module for each tool and case entry,
and each unit test file is declared by its owner, so no tool, case or
unit test file has a registration line. A port still adds one sorted `pub mod` line to
`crates/kestrike-tools/src/lib.rs` for a new library module and a line under `[dependencies]` of
`crates/kestrike-tools/Cargo.toml` for a dependency it needs. A port that brings rules from a Python file
that stays in the tree, a file its script loads included, adds a row to
[Rules held twice](#rules-held-twice).

1. Write the tool as one module under `crates/kestrike-tools/src/tools/`: a file `<module>.rs`, or a
   directory `<module>/` with `mod.rs`. Its root holds `pub const NAME: &str = "<tool>";` and the entry
   `pub fn run(top: &Path, args: &[OsString]) -> u8`, its own or re-exported with `pub use`. A root that
   needs its name in another constant takes it from `NAME`. `top` is the checkout's top level, which a
   script took from its own path. `NAMES` lists the names in ascending order of their bytes, whatever the
   module names.
2. Put a function that two tools share in a library module, declared with one `pub mod` line in
   `crates/kestrike-tools/src/lib.rs`, kept sorted.
3. Declare a unit test file in its owner with `#[cfg(test)] #[path = "<m>_tests.rs"] mod tests;`. From a
   library module's `mod.rs` the path is `"../<m>_tests.rs"`. A tool's own files, its unit test files
   included, stand inside its directory: rustc reads a tool root through `#[path]` and resolves a `mod`
   line or a relative `#[path]` inside it beside the root, and every `<id>.rs` directly under
   `src/tools/` is a tool. A tool with unit test files of its own is therefore a directory, whose
   `mod.rs` declares them with `#[cfg(test)] mod tests;` or
   `#[cfg(test)] #[path = "<m>_tests.rs"] mod tests;`. A test module
   whose items another test file uses is declared `pub(crate) mod tests;`, as
   `crates/kestrike-tools/src/paths.rs` declares the one that holds `Scratch`.
4. Add an integration case under `crates/kestrike-tools/tests/`: a file `<case>.rs`, or a directory
   `<case>/` with `mod.rs` and its helpers beside it. A file case declares no module file, since
   its `mod h;` would read `tests/h.rs`, itself a case; an inline `mod h { ... }` is fine. A helper
   that several cases share is a case directory of its own, which the others reach as `crate::<helper>`.
   Every case is a module of the one test executable `tools`, built from
   `crates/kestrike-tools/tests/tools.rs`, so a test `<rest>` of a case has the id `<case>::<rest>`, and
   one process runs every case: the tests of all cases run as threads of one libtest process, so a setting
   that applies to the whole process (the umask, the working directory, the environment, a signal
   disposition, a resource limit) is made in a child process the case starts, or it holds for every case.
   `scripts/test-inventory.json` lists the package's targets, `doc:kestrike_tools`, `kestrike_tools` and
   `tools`, and a case adds no line there. The test selection therefore counts the `tools` executable as a
   whole: a deleted case module is found by the weakened-test scan, whose blocking class `case-removed`
   names a case of the base that the head lacks (see
   [the pre-push checks](ci.md#pre-push-checks)), and whose report line names removed assertions. The
   reader of a regression target in `scripts/verify-receipts.py admit` resolves no case id of `tools`,
   so an intake record that names such a test waits for that script's own port.

In both directories the build script checks each entry whose name starts with a byte other than `.` and
that is a directory, a link to one, or named `*.rs`; the directory's own root (`src/tools/mod.rs`,
`tests/tools.rs`) is skipped. It passes over every other entry, so an editor's swap or lock file, a backup
`x.rs~`, a merge's `x.rs.orig`, `.gitkeep` and `README.md` change no generated list; a newer time on one
still reruns the build script and rebuilds the binary, so build output and links into it stand outside
both directories. A checked entry is a regular file `<id>.rs` or a directory `<id>/` that holds a regular
file `mod.rs`, with `<id>` matching `[a-z][a-z0-9_]*`. Any other checked entry stops the build with its
path: a directory without `mod.rs`, a link, a `*.rs` entry of another file type (a fifo, a socket, a
device), `<id>.rs` beside `<id>/`, a name outside the pattern, a Rust keyword, or a name the build
reserves: `std` and `tests` under `src/tools/`, which `src/tools/mod.rs` uses, and `std` and `tools` under
`tests/`: `std` is the path that `tests/tools.rs` uses, and `tools` is the name of that root file. The
build script reads listings, so an untracked file counts. A tool root without `NAME` or `run` is rustc's
unresolved-name error, and two tools of one name are rustc's `unreachable pattern` error.

`cargo fmt --all -- --check` reaches neither the tool roots nor the case files, since they are declared
through `include!`. The `rust-format` job and the rustfmt over every tracked Rust file that `AGENTS.md`
names format them.

A change under either directory reruns the build script, so the next call of `scripts/tool.sh`
rebuilds the binary. Cargo compares the times of the directories and their entries with its last run,
so an entry is missed when the directory and its entries all carry older times, as when an archive
that holds the directory is unpacked with its times: a missed tool's call exits 2 with the binary's
refusal, and a missed case fails `every_entry_of_tests_is_a_case` in
`crates/kestrike-tools/tests/tools.rs`. Removing `target/tools` repairs a missed tool, and removing the
test run's own build directory (Cargo's `build.build-dir`, the target directory unless it is set apart)
repairs a missed case. The generated declarations name each file by its
absolute path, and rustc's diagnostics and a panic's location name a tool or case file by it. The build
script watches the two directories by their absolute paths, so a checkout moved or copied with its
build directory reruns it at the next build, and each generated list asserts at compile time that
`CARGO_MANIFEST_DIR` is the package path it was written for: a list left from another place stops the
build with `the package moved after its build script ran; remove the build directory`.

The change that makes a tool startable deletes its script and the script's self-test with `git rm`, and
edits each caller's command text. The same change removes each row of
[Rules held twice](#rules-held-twice) that names a file it deletes.

## Rules held twice

Each row names a Rust module and a Python file that stays in the tree. The two hold the same rules and no
check reads both files, so an editor of one reads the other. Where an edit changes a rule a row lists,
change both files in one pull request and show that they agree on recorded inputs, or port the Python file
and remove its rows. A Python file stays when no ticket of its own port deletes it.

| Rust module | Python file that stays | Rules held in both |
| --- | --- | --- |
| `crates/kestrike-tools/src/fixtures/case.rs` | `quint/escrow_check.py` | The text of `case.qnt` for a case of the escrow model without mutations or extra text: `case::escrow` and `inputs`. |
| `crates/kestrike-tools/src/fixtures/case.rs` | `quint/gate_check.py` | The text of `case.qnt` for a case of the gate model without mutations or extra text: `case::gate` and `inputs`. |
| `crates/kestrike-tools/src/fixtures/case.rs` | `quint/grace_check.py` | The text of `case.qnt` for a case of the grace model without mutations or extra text: `case::bounded` and `inputs`. |
| `crates/kestrike-tools/src/fixtures/case.rs` | `quint/lookup_check.py` | The text of `case.qnt` for a case of the lookup model without mutations or extra text: `case::bounded` and `inputs`. |
| `crates/kestrike-tools/src/fixtures/case.rs` | `quint/marklog_check.py` | The text of `case.qnt` for a case of the marklog model without mutations or extra text: `case::marklog` and `inputs`. |
| `crates/kestrike-tools/src/fixtures/case.rs` | `quint/reclaim_check.py` | The text of `case.qnt` for a case of the reclaim model without mutations or extra text: `case::bounded` and `inputs`. |
| `crates/kestrike-tools/src/fixtures/case.rs` | `quint/register_check.py` | The text of `case.qnt` for a case of the register model without mutations or extra text: `case::bounded` and `inputs`. |
| `crates/kestrike-tools/src/gameday/` | `scripts/gameday-judge.py` | The rules that read a game-day package for GD-2, under the same names in both: `Refusal` and `need`; `read_file`; `decode` and `parsed`; `exact` and `shown`; `finite`, `encodable`, `calendar`, `member_of` and `conform`; `VERSION`, `REQUEST`, `PACKAGE_SCHEMA` and `LAYOUT`; `fleet_bound`, `declared_bound` and `check_package` with `FLEET_BOUNDS`; `gd2_entry`; `roles_reach`; and the constants they read, `CATALOG` and `FILE_LIMIT` among them. |
| `crates/kestrike-tools/src/git.rs` | `scripts/red-green.py` | The five Git variables that point Git at another repository, work tree, index or object store, in the order a refusal lists them: `REPOSITORY_VARIABLES` in the Rust module and `OVERRIDES` in the Python file. |
| `crates/kestrike-tools/src/json.rs` | `scripts/gameday-judge.py` | The strict JSON read, which refuses a repeated key, a constant that is no number, and a number with a fraction or an exponent whose value is not the shortest form of a finite double: `parse_strict` in the Rust module, and `DECODER` with `distinct_keys`, `no_constant` and `double` in the Python file. |
| `crates/kestrike-tools/src/ownership.rs` | `scripts/red-green.py` | The directory checks `shared_directories`, `traversed`, `make_private` and `foreign_toolchain_paths`, with `TOOLCHAIN_FILES` and `SHARED`, under the same names in both. |
| `crates/kestrike-tools/src/production_text.rs` | `scripts/classify-atomics.py` | The test-only reading of a Rust source: `closing`, `item_end`, `readings`, `macro_spans`, `own_comma`, `analyzed`, `spliced` and `blanked`, with the patterns `RUN`, `ITEM` and `PROVEN`, and `MACRO`, which the Rust module holds as `MACRO_DEFINITION` and `MACRO_BANG`. |
| `crates/kestrike-tools/src/python.rs` | `scripts/red-green.py` | The line printer `say`: the characters it escapes and the one newline it ends a line with. |
| `crates/kestrike-tools/src/rust_text.rs` | `scripts/classify-atomics.py` | `blank` and `code`, which blank a Rust source's comments and literal contents. |
| `crates/kestrike-tools/src/rust_text.rs` | `scripts/judge-rc11.py` | The lexer of Rust source: `lexemes` in the Rust module, `rust_lexemes` with `RUST_LEXEME` in the Python file, and `BLOCK_EDGE` in both. |
| `crates/kestrike-tools/src/tools/escrow_fixtures.rs` | `quint/escrow_check.py` | The four checked runs, each with its volume: the first four rows of `RECIPES` and `RUNS`. |
| `crates/kestrike-tools/src/tools/gate_fixtures.rs` | `quint/gate_check.py` | The four checked runs: the first four rows of `RECIPES` and `RUNS`, with `SUBMIT` in both. The turns up to a submitted report are `REPORTED` in the Python file and the macro `reported!` in the Rust module, whose constant `REPORTED` holds the macro's turns and is read by no recipe. The second checked run writes those turns out after its first turn in the Rust module. |
| `crates/kestrike-tools/src/tools/grace_fixtures.rs` | `quint/grace_check.py` | The four checked runs: the first four rows of `RECIPES` and `RUNS`. |
| `crates/kestrike-tools/src/tools/lookup_fixtures.rs` | `quint/lookup_check.py` | The three checked runs: the first three rows of `RECIPES` and `RUNS`. |
| `crates/kestrike-tools/src/tools/marklog_fixtures.rs` | `quint/marklog_check.py` | The three checked runs: the first three rows of `RECIPES` and `RUNS`. |
| `crates/kestrike-tools/src/tools/reclaim_fixtures.rs` | `quint/reclaim_check.py` | The four checked runs: the first four rows of `RECIPES` and `RUNS`. |
| `crates/kestrike-tools/src/tools/register_fixtures.rs` | `quint/register_check.py` | The three checked runs: the first three rows of `RECIPES` and `RUNS`. |

The checked runs of the seven rows under `crates/kestrike-tools/src/tools/` are each compared with the
committed replay traces: `scripts/test-quint-check.py` compares each run of `RUNS` with its trace's recipe,
and `crates/kestrike-tools/tests/fixture_writers.rs` compares each trace a tool writes with the committed
one. Neither compares which recipes are the checked runs, so the count in a row and in the comment on
`RECIPES` is kept by hand.

## What a port keeps

For the same inputs a tool returns the script's exit code and writes the script's bytes: every file, and
on each stream every line the script's own source composes. A port keeps the script's behavior, a defect
included; its test asserts that behavior and the defect is reported for a fix after the port.

A tool composes its own text where the Python interpreter composed the script's:

- An argument parser's usage block and help text, and the program name. The words after `error:` stay.
- The message and the class name of an exception. A traceback becomes one line `<tool>: <message>` with
  the script's exit code.

The pull request of each port lists every such place, and every other difference its side-by-side run
found.
