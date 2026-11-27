# Tools

Read this before you start, add or change a tool under `crates/kestrike-tools`, or port a script to one.
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
is. The preparation below runs in a subshell, so its working variables stay out of the environment of the
final step. On every call it:

1. Reads the stable toolchain that `.github/workflows/agent-checks.yml` pins as `STABLE`, and checks
   that `rustup toolchain list` names `<pin>-<host>` as the first word of a line. The launcher installs
   nothing.
2. Runs the pinned toolchain's own `cargo`, which `rustup which --toolchain <pin> cargo` names, with
   `RUSTC` set to the `rustc` beside it, so neither a `cargo` earlier on `PATH` nor a `build.rustc` in
   a Cargo configuration file replaces the pin. It builds the `kestrike-tools` binary for the host
   (`--target <host>`, which also takes the place of a configured `build.target`) into
   `target/tools/<host>/debug`, with the top level as the build's working directory, `RUSTUP_TOOLCHAIN`
   set to the pin and `RUSTUP_AUTO_INSTALL=0`. For this build it clears `RUSTFLAGS`,
   `CARGO_ENCODED_RUSTFLAGS`, `RUSTDOCFLAGS`, `CARGO_ENCODED_RUSTDOCFLAGS`, every `CARGO_PROFILE_*`,
   every `CARGO_BUILD_*` except `CARGO_BUILD_JOBS`, every `CARGO_TARGET_*` (`CARGO_TARGET_DIR`
   included), `RUSTDOC`, `RUSTC_WRAPPER` and `RUSTC_WORKSPACE_WRAPPER`, and keeps the rest. It then sets
   `RUSTC_WRAPPER` and `RUSTC_WORKSPACE_WRAPPER` to the empty value, which outranks a wrapper a Cargo
   configuration file names, and `CARGO_BUILD_BUILD_DIR=target/tools`, which outranks a configured
   `build.build-dir`, so the build's fingerprints and lock stay under `target/tools`. With `--target`, the
   repository's `target.<cfg>.rustflags` apply to the binary and its dependencies and not to build
   scripts. A tool is then the same program whatever lane starts it.
3. Replaces itself with the binary, started as `kestrike-tools <top> <tool> <arguments>`. The binary gets
   the caller's environment as bash passes it on: bash, which runs the launcher, may set `PWD`,
   `OLDPWD`, `SHLVL` and `_`, and leaves every other variable as the caller set it.

The build prints nothing unless it fails. Cargo's fingerprint decides whether it compiles anything, and
Cargo's lock on `target/tools` makes a second caller wait for the first; that wait has no limit of its
own, so the caller's deadline counts it. The fingerprint compares file times: a source changed under an
older time keeps the old binary until `target/tools` is removed. A first build in a clone writes the
untracked `Cargo.lock`.

### Failures

| Exit | Cause | Output |
| --- | --- | --- |
| 127 | `STABLE` is missing from the workflow, rustup names no single host, or the pin or its `cargo` or `rustc` is not installed | `tool.sh: <reason>` on standard error |
| 127 | The build fails, a first dependency resolution without network included | Cargo's output, then `tool.sh: the build of kestrike-tools failed`; the next call builds again |
| 127 | An entry of `src/tools/` or `tests/` is outside the rules of [Adding a tool](#adding-a-tool), a tool root lacks `NAME` or `run`, or two tools share a name | the build script's `kestrike-tools build script: <path>: <reason>` line or rustc's error, then the line above |
| 2 | The tool name is missing or names no tool | the binary's `kestrike-tools:` line on standard error |

Every other exit code is the tool's own, and no tool returns 127. The launcher exits 127 on its own
failures even when standard error is closed or full.

## Adding a tool

A port adds files. The package's `build.rs` lists `crates/kestrike-tools/src/tools/` and
`crates/kestrike-tools/tests/` on every build and declares a module for each entry, so no tool, case or
unit test file has a registration line. A port still adds one sorted `pub mod` line to
`crates/kestrike-tools/src/lib.rs` for a new library module and a line under `[dependencies]` of
`crates/kestrike-tools/Cargo.toml` for a dependency it needs.

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
   `mod.rs` declares them with `#[cfg(test)] mod tests;` or `#[path = "<m>_tests.rs"]`. A test module
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
   `tools`, and a case adds no line there.

In both directories the build script checks each entry whose name starts with a byte other than `.` and
that is a directory, a link to one, or named `*.rs`; the directory's own root (`src/tools/mod.rs`,
`tests/tools.rs`) is skipped. It passes over every other entry, so an editor's swap or lock file, a
backup `x.rs~`, a merge's `x.rs.orig`, `.gitkeep` and `README.md` leave the build as it is. A checked
entry is a regular file `<id>.rs` or a directory `<id>/` that holds a regular file `mod.rs`, with `<id>`
matching `[a-z][a-z0-9_]*`. Any other checked entry stops the build with its path: a directory without
`mod.rs`, a link, a `*.rs` entry of another file type (a fifo, a socket, a device), `<id>.rs` beside
`<id>/`, a name outside the pattern, a Rust keyword, or a name the build reserves: `std` and `tests`
under `src/tools/`, which `src/tools/mod.rs` uses, and `std` and `tools` under `tests/`, the path that
`tests/tools.rs` uses and the test executable's own name. The build script reads listings, so an
untracked file counts. A tool root without `NAME` or `run` is rustc's unresolved-name error, and two
tools of one name are rustc's `unreachable pattern` error.

`cargo fmt --all -- --check` reaches neither the tool roots nor the case files, since they are declared
through `include!`. The `rust-format` job and the rustfmt over every tracked Rust file that `AGENTS.md`
names format them.

A change under either directory reruns the build script, so the next call of `scripts/tool.sh`
rebuilds the binary. Cargo compares the times of the directories and their entries with its last run,
so an entry is missed when the directory and its entries all carry older times, as when an archive
that holds the directory is unpacked with its times: a missed tool's call exits 2 with the binary's
refusal, and a missed case fails `every_entry_of_tests_is_a_case` in
`crates/kestrike-tools/tests/tools.rs`. Removing `target/tools` repairs a missed tool, and removing the
test run's own target directory repairs a missed case. The generated declarations name each file by its
absolute path, so a copy of the checkout builds into a target directory of its own, and rustc's
diagnostics and a panic's location name a tool or case file by its absolute path.

The change that makes a tool startable deletes its script and the script's self-test with `git rm`, and
edits each caller's command text.

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
