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
| 2 | The tool name is missing or names no tool | the binary's `kestrike-tools:` line on standard error |

Every other exit code is the tool's own, and no tool returns 127. The launcher exits 127 on its own
failures even when standard error is closed or full.

## Adding a tool

1. Write the tool as one module under `crates/kestrike-tools/src/tools/`, a file or a directory with
   `mod.rs`, with the entry `pub fn run(top: &Path, args: &[OsString]) -> u8`. `top` is the checkout's
   top level, which a script took from its own path.
2. Register it with one line `"<tool>" => <module>,` in the `tools!` table of
   `crates/kestrike-tools/src/tools/mod.rs`, kept sorted by tool name. The macro declares the module and
   its dispatch entry.
3. Put a function that two tools share in a library module, declared with one `pub mod` line in
   `crates/kestrike-tools/src/lib.rs`, kept sorted.
4. Add one target line to the `kestrike-tools` entry of `scripts/test-inventory.json` for each new test
   target that Cargo lists for the package: a file directly under `crates/kestrike-tools/tests/`, named
   by its stem, or a directory there with a `main.rs`, named by the directory. A helper module that a
   test target includes adds no line. A target's name is unique across the workspace's crates.

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
