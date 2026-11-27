List and test the generated mutants of one commit range's kestrike lines.

Usage:
  bash scripts/tool.sh mutants-diff [--base REV] [--head REV]
      [--max-mutants N] [--shard K/N] [--tests=ARGS] [--artifacts DIR]
      [--cargo PATH]

The base defaults to the merge base of the head with `origin/main`, the head
to `HEAD`, `--max-mutants` to 40 and `--artifacts` to `target/mutants` under
the invoking checkout's top level. `--cargo PATH` replaces `cargo`; a path
with a `/` is resolved against the invoking directory. Write `--tests=ARGS`
with `=`, so a value that starts with `-` stays a value. Options are matched
by their full names only.

The run judges the head commit, in this order:

1. It requires `cargo mutants --version` to report the version of the line
   `# Tool pin: cargo-mutants VERSION` in the invoking checkout's
   `.cargo/mutants.toml`. It installs nothing.
2. It takes the lock `<artifacts>/build.lock`, so one run at a time uses an
   artifacts directory, and writes `git diff BASE HEAD --
   crates/kestrike/src` as `diff.patch` into a new run directory
   `<artifacts>/<run id>/`. The lock ends with the runner; after a runner
   stopped by SIGKILL, start the next run on that directory once the old
   tool has exited.
3. It adds a detached worktree of the head, with Git hooks disabled, in a new
   directory under the run directory. The invoking repository's checkout
   filters, line-ending conversion and sparse-checkout settings apply to it.
   When the invoking checkout has a `Cargo.lock` and the worktree holds no
   entry at that path, it copies that file into the worktree. For a nonempty
   diff it requires a root `Cargo.toml` in the worktree and lists the mutants
   with `-p kestrike --in-diff DIFF --list --json` into `list.json`, each
   mutant with its name, file and `diff`.
4. It runs `cargo mutants --in-place -p kestrike --in-diff DIFF` in the
   worktree, in its own process group, with `--lib -- --skip bind:: --skip
   native:: --skip soak` after the tool's first `--`, or the shell-split
   words of `--tests=ARGS` in their place. It sets
   `CARGO_PROFILE_DEV_OPT_LEVEL=1`, `CARGO_PROFILE_DEV_DEBUG=line-tables-only`,
   `RUSTUP_TOOLCHAIN` to the `STABLE` pin of
   `.github/workflows/agent-checks.yml`, `CARGO_TARGET_DIR` and
   `CARGO_BUILD_BUILD_DIR` to `<artifacts>/build`, and `PATH`'s entries,
   `CARGO_HOME` and `RUSTUP_HOME` to their values resolved against the
   invoking directory. It refuses an inherited
   `CARGO_MUTANTS_*` variable, a `CARGO_PROFILE_*` variable other than the two
   it sets, and a `*RUSTFLAGS` value that sets debug assertions; the rest of
   the environment passes through. The tool writes into the run directory's
   `tool/`, runs one mutant at a time, and on SIGTERM stops the process groups
   of its cargo commands before it exits.
5. It reads the tool's `outcomes.json`, writes `report.json` and prints the
   result line and one `missed:` line per missed mutant.

Cargo reads configuration from the worktree's ancestors, which are the
artifacts directory and its ancestors, so the runner refuses an artifacts
directory, the default included, that another user owns or can write, or one
with such an ancestor. It also refuses a `.cargo`, `.cargo/config.toml`,
`.cargo/config`, `rust-toolchain` or `rust-toolchain.toml` entry of one of
those directories that another user owns or can write: the entry or the file
or directory it resolves to has another owner, that target is writable by its
group or by all users, the target cannot be examined, or resolving the entry
passes through a directory, by any link on the way, that another user owns or
can write. Git runs with replace objects disabled and
without `GIT_DIFF_OPTS`. The diff is written as text with full object ids,
fixed prefixes, rename detection, the Myers algorithm, three lines of context
and no color, external diff, text conversion or path order, so those diff
settings of the user's configuration leave the patch unchanged; diff
attributes that select a hunk-header pattern still apply.

`--shard K/N` passes `K/N` unchanged to the listing and to the run; the tool
numbers shards 0 to N-1. The listed set is then the shard's slice, and
`--max-mutants` applies to that slice.

Every verdict comes from the per-mutant outcomes of `outcomes.json`. A
mutant is caught only when the run's baseline passed and the tool recorded it
caught; on a failed baseline, or a tool exit of 4, every listed mutant is
not-run. The counts are recomputed from those outcomes, and listed equals
caught plus missed plus timeout plus unviable plus not-run. A run with listed
mutants is complete only when the tool exited 0, 2 or 3, the baseline passed
and the set of judged mutants equals the listed set. A listing or outcome
file that repeats a mutant, an outcome file with a phase time that is not a
finite nonnegative number, a worktree configuration whose
`additional_cargo_args` the runner cannot read, and a worktree that remains
after the removal make the run incomplete.

`report.json` holds `base` and `head` (full commit ids), `diff_sha256` (the
file the tool read), `tool_version`, `config_sha256` (the worktree's
`.cargo/mutants.toml`, or null when it has none), `tests` (the arguments the
runner passes after the tool's first `--`; the worktree configuration's own
test settings, which `config_sha256` identifies, also apply), `machine` (the
architecture part of the `host:` triple that `cargo -vV` prints),
`debug_assertions` (the value of the last `profile.dev.debug-assertions=`
entry of the worktree configuration's `additional_cargo_args`, or null), `shard`
(`{"k": K, "n": N}` or null), `baseline` (`passed`, `failed` or null),
`tool_exit`, `mutants` (each listed mutant's `name`, `file`, `outcome` and
`phase_seconds`), `counts`, `flagged` (each file with one or more viable
mutants, judged and not unviable, all of them missed), `complete` and
`reason` (why the run is incomplete, or null).

`debug_assertions` records the configuration's entry. The setting the build
uses also depends on inputs outside that entry: rustflags in a Cargo
configuration file, a profile override in a manifest or a configuration file,
and a compiler wrapper can each turn debug assertions on for the build while
the field reads `false`.

The result line reads `mutants: HEAD against BASE on MACHINE: N listed, C
caught, M missed, T timeout, U unviable; complete`, where HEAD and BASE are
the first 12 characters of the commit ids, with `, shard K/N` after the
machine for a sharded run. An incomplete run ends it with `incomplete` and
prints the reason on the next line. An empty diff or an empty listing prints
`mutants: 0 listed`, writes a complete report with no mutant and starts no
build.

Each printed line stays one line: a control character, a line break included,
is printed escaped, and a lone surrogate of a name or a path that is not UTF-8
is printed as `\udXXX`; the rest of each line is UTF-8. `report.json`
holds each mutant's name as the tool gave it.

The runner handles SIGINT, SIGTERM and SIGHUP from before it creates the run
directory until it has read the tool's outcomes; from then on it ignores
them, so the worktree removal and the report complete. A signal that is
ignored when the runner starts stays ignored, so a run under `nohup` outlives
its terminal. The runner records the first handled signal and acts on it
between steps and while it waits for a child; a signal that arrives while a
process is being started is acted on once that process has started, and a
later signal changes nothing. The runner then stops the supervised process
group (the worktree add, the listing or the tool) with SIGTERM, then SIGKILL, removes the worktree, writes an incomplete
report and exits 1. Each supervised process receives SIGTERM when the runner
dies, so a runner stopped by SIGKILL also stops the tool; its worktree then
stays in the run directory and registered until `git worktree remove --force
--force` runs on that `worktree-*` path. Every other exit removes the
worktree with `git worktree remove --force --force`. The runner writes only
under the artifacts directory and in that worktree's entry in the
repository's Git directory, which the removal deletes, so with the default
artifacts directory, or one outside the checkout or ignored by it, the
invoking checkout's working tree and index stay as they were.

Exit 0 is a written report that reads `complete`, whatever it lists. Exit 1
is an incomplete run with a written report: a failed baseline, a failed
`git diff`, `git worktree add` or listing, a head without a root
`Cargo.toml`, a tool that exits outside 0, 2 and 3 or without a readable
outcome file, a judged set that differs from the listed set, a worktree that
remains, an unexpected runner error such as a run directory that refuses an
output file, or an interruption. When the artifacts directory refuses the
report, the runner prints that error in its place and exits 1. Exit 2 is
rejected input and writes no report: malformed arguments; a set `GIT_DIR`,
`GIT_WORK_TREE`, `GIT_INDEX_FILE`, `GIT_COMMON_DIR` or
`GIT_OBJECT_DIRECTORY`; an inherited variable that step 4 refuses; a
directory outside a Git checkout; an unknown revision or no merge base with
`origin/main`; a configuration without one pin line or a workflow without one
`STABLE` pin, or one of them unreadable; an absent tool or a `cargo -vV`
without a host; a tool version other than the pin; an artifacts directory
that cannot be resolved, that another user owns or can write, that has such a
Cargo or rustup entry in it or in an ancestor, or whose `build.lock` is not a
regular file the invoking user owns or is held by another run; or more listed
mutants than `--max-mutants`. Only the last of these reaches the worktree, and
none starts a build. The limit refusal takes precedence over a worktree that
remains: it exits 2, writes no report and names that worktree on standard
error.
