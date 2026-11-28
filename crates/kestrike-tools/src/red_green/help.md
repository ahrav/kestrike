Record that a regression test fails on a base commit and passes on a head commit.

The base defaults to the merge base of the head with `origin/main` and the
head to `HEAD`. Each `--carry` path names a regular file from the repository
root that the head holds; together they are the test files laid over the base.

The command creates a detached worktree of the base under the resolved path of
the temporary directory, `TMPDIR` when it is set and not empty and `/tmp`
otherwise, and overlays the carried paths with
`git checkout HEAD_ID -- PATHS`, where HEAD_ID is the head's full commit ID, so
the base leg's tree is the base commit plus exactly those files at the head's
blobs. It runs the base leg, then, on a red base, the head leg in a detached
worktree of the head. A leg is one run of `scripts/reproduce-test.py` in that
leg's worktree by the `python3` that `PATH` names, with `--attempts 1`, an
absolute `--artifacts` path and the same package, target, test ID, profile,
watchdog and cargo, each value joined to its flag. The legs run a copy, in the
temporary directory, of the runner and its selector as read from the
checkout's `scripts/` at startup, written afresh before each leg, and the
command judges the legs with the same bytes. A `--cargo` path that holds a
directory part is made absolute against the invoking directory. Git runs with
replace objects disabled and with inherited pathspec modes removed, and the
worktree and overlay steps run with Git hooks disabled. Before each leg runs,
the command compares the leg's worktree with the files its commit and the
carried paths name: every file, symlink and empty directory the worktree holds,
ignored and untracked ones included, and each one's kind, executable bit and
bytes. A leg whose tree differs is refused by the first differing path, so a
leg starts on the tree the receipt names. A checkout that a filter or a
line-ending conversion rewrites is refused this way. The runner's own Git
probes in a leg tree, such as `git status`, run after this comparison under
the invoking Git configuration.

Both legs build in one directory that only this command writes, set as both
`CARGO_TARGET_DIR` and `CARGO_BUILD_BUILD_DIR`: `target/red-green/build` in
the invoking checkout, or `red-green` under `CARGO_TARGET_DIR` when that is
set, made absolute. The command creates the directory and each missing
ancestor with mode 0700. The builds and tests of both legs write there, so a
file a test leaves under it reaches the head leg and later runs, as a file it
leaves in the temporary directory or the home directory does; a receipt is
evidence for a test whose result depends only on the tree it runs in. The
command holds an exclusive lock on the regular file `red-green.lock` in that
directory from before the base worktree is created until the command exits,
and empties the file once it holds the lock. A lock file that another user owns
or that its group or all users can write is refused. While another run holds
the lock, the command prints `red-green: waiting for another run that builds in
DIR` once and tries again at pauses of at most 20 ms. Each runner gets the lock
file as its standard input, and the builds, listings and tests it starts
inherit that and read end-of-file from it, so two runs build into the
directory one at a time while the command, a runner or a leg process that kept
that standard input is alive. A leg's result is the runner's last stdout line,
its verdict, and its stderr line `artifact: PATH` names the `artifact.json` of
the leg's own directory under the receipt. Both of the runner's streams are
read to their end as UTF-8, each invalid sequence replaced by U+FFFD, with
`\r\n` and `\r` read as `\n`.

The base is red only when the runner's verdict is reported for exit 1 and that
leg's `attempt-1.stdout` or `attempt-1.stderr` holds the `--expect` text within
one run of adjacent LF-separated lines that framing and backtraces leave.
Framing covers the lines libtest and the panic hook print around a failure,
the test ID's own lines and should_panic's echo of its expected text among
them. libtest's note that a should_panic test did not panic stays searchable as
that failure's own diagnostic. Every other line counts, the test's own prints
and other threads' panic messages included, so the text identifies the failing
assertion only as narrowly as the author chooses it. The head is green only on
a reported exit 0. Every other leg outcome is a refusal whose reason names the
leg and the outcome:

- base: a reported exit 1 without the text, a reported exit 0, exit 3 (a build
  failure, an absent integration target among them), exit 2 whose verdict holds
  `matched 0 listed` (the test is absent), exit 4 (a crash) and a reported
  exit 6 (a hang) each have their own reason; any other exit or verdict is
  quoted in the reason;
- head: a reported exit 1 has its own reason; any other exit or verdict is
  quoted in the reason;
- either leg: a red base or a green head whose own `artifact.json` or attempt
  output is missing from the receipt or unreadable has its own reason.

The receipt is the directory `target/red-green/RUN/` in the invoking checkout,
or `DIR/RUN/` under `--artifacts`, which this run creates; `RUN` is `local-`,
the wall clock's whole seconds, `-` and the process ID. It holds each leg's
runner artifact directory, unchanged, and `receipt.json`, which names both
commits, each carried path with its blob ID at the head, the SHA-256 of the
runner and its selector as read at startup under `scripts`, the SHA-256 of the
tool's executable under `tool`, or null where `/proc/self/exe` cannot be read,
each leg's `artifact.json` path and the SHA-256 of it and of each attempt
output file taken after the leg ends, the leg's exit, verdict and wall time on
the monotonic clock, the base streams that held the text, the result, and the
command that repeats the run from the repository root with both revisions as
full commit IDs. The base verdict reads the same attempt bytes that the
receipt hashes. A refused run writes its receipt with the legs that ran; the
head leg runs only on a red base. The stderr line `receipt: PATH` names the
file. The run directory and the file are created exclusively, so an existing
entry at either path makes the creation fail and stays as it is.

Exit 0 is proven, printed as `red-green: ID failed on BASE with "TEXT" and
passed on HEAD` after `receipt.json` is written. Exit 1 is refused, printed as
`red-green refused: REASON`; a build directory or a receipt directory that
cannot be created and a receipt that cannot be written are refusals. A runner
file that cannot be read at startup, a Git that cannot start before the run
directory exists, and any other failure outside these outcomes exit 1 with one
line `red-green: MESSAGE` on stderr. Result lines and the stderr lines that
name a path escape control characters, and each stream is written as UTF-8.
Exit 2 is rejected input, printed on stderr as `red-green rejected: REASON`
and found before any worktree or build: an option with no value or an empty
one, or a `--carry` that names no path; a set `GIT_DIR`, `GIT_WORK_TREE`,
`GIT_INDEX_FILE`, `GIT_COMMON_DIR` or `GIT_OBJECT_DIRECTORY`, which would
point the leg worktrees at another repository or index; a `.cargo`,
`.cargo/config.toml`, `.cargo/config`, `rust-toolchain` or
`rust-toolchain.toml` in the temporary directory or its ancestors, which Cargo
or rustup in a leg worktree would read, that another user owns or can write,
judged by the owner of the entry, by the owner and the group and world write
bits of the file or directory it resolves to, and by the directories that
resolving it passes through, every link on the way followed, or one of those
directories that a user other than the invoking user and root owns or that its
group or all users can write, where such an entry could appear while the legs
run; a start with SIGCHLD ignored, under which no child's exit can be read; a
build directory, or an ancestor of it, that such a user owns or that its group
or all users can write, where the files the legs build and run could be
replaced; an invoking directory outside a Git checkout; an unknown revision; a
default base with no merge base, which `--base` resolves; a base that is the
head or not its ancestor, since a receipt compares a commit with the history
that fixed it; a carried path the head does not hold as a regular file; a head
whose changes from the base all lie in carried paths or in base paths the
overlay of those replaces, since both legs would then run the same tree; an
empty or whitespace-only `--expect`, which every output holds, or one that is
part of the test ID, which framing lines print; a watchdog that is not a
positive number of seconds up to 9223372036; a receipt or build directory
whose symlinks loop; and a receipt directory the runner's one-line UTF-8
`artifact:` announcement cannot name. Argument syntax errors exit 2 with the
usage message.

The checks on the temporary directory and the build directory cover the
directories in which this command places the code the legs run. The legs run
the toolchain the invoking environment provides, through `PATH`, `--cargo`,
the Cargo home and the rustup home, and the command examines those locations
only where they are entries of the temporary directory's ancestors.

The invoking checkout keeps its index and working tree. The worktrees are
removed on exit by their own paths. SIGTERM, SIGHUP and SIGINT are recorded
whatever disposition the command inherited, the first of them counting, and
the command reads the record between its steps and at pauses of at most 20 ms
while it waits. On a signal before the legs end, the command sends a running
runner SIGTERM, which stops the runner's supervised process group, waits for
the runner to exit and both its streams to end, removes the worktrees and
exits 128 plus the signal number with no result line and no `receipt.json`. A
Git step outside the steps named below is killed on a signal. A signal that
lands while the temporary directory, a worktree or the overlay is being
created, or while the runner is being started, takes effect once that step
returns. A signal that lands after a runner exits waits until the command has
judged that leg: it takes effect before a head leg starts, and a run whose
last leg has ended finishes. The waits for the lock and for a runner have no
deadline: the lock's ends at the holder's release or a signal, and a runner's
at its exit and the end of both its streams.
