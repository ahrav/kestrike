Run each stored plant through a sweep and write the share that sweeps catch.

A plant is a directory `verification/plants/<id>/` that holds `plant.patch`,
a diff against the head that restores a fixed defect, and `plant.json`:
`id` (the directory's name), `row` (the defect's row in the table of fixed
defects the store draws on), `fix` (`pull_request` and `commit`), `files`
(the planted paths), `restores` (one sentence),
`proof` (the fix's regression test, which passes at the head and fails on the
plant), `expected` (the profiles the run sweeps for the plant, which the
guide's rule selects) and `miss_cause` (null, or `cause`, one of
`environment`, `workload`, `ordering` and `property`, with `evidence`, one
sentence). `docs/agents/simulation.md` ("Score the planted defects") gives the
rule for `expected` and the meaning of each cause. Plants stay patch files:
the runner applies them only in its scratch worktrees.

The run judges the invoking checkout's `HEAD`, and the plant store must match
it: a path under the store that `git status` reports, ignored files included,
is rejected, except one whose file name, leading dots removed, starts with
`score.json`, which the check passes over in a plant directory too. So a store
file staged as a rename to `score.json` passes that check, and the run writes
its score over it. The runner runs on Linux alone: it reads the umask the
score's file takes from the `Umask:` line of `/proc/thread-self/status`
before any worktree, and a host without it ends the run there with exit 4.
In that checkout the
run writes `verification/plants/score.json` and leaves the index, the refs,
the stash, the configuration and every other file as they were. Its Git
commands read no replacement object (`refs/replace`). Its work lies
in `--work`, by default a new directory under `$TMPDIR`, which it keeps as
the run's evidence. The work directory lies outside the checkout, on a mount
`campaign` accepts (xfs, or ext4 with a journal), under ancestors only the
invoking user or root can write. A run without `--work` needs a `$TMPDIR` of
that kind: under a shared one, such as `/tmp`, it is rejected. The run takes
the plants in two phases. Steps 1 and 2 run for every plant before step 3
runs for any, and between them the run removes the proof's worktree and
target directory, so no archive build shares the disk with them. For each
plant, in a detached worktree of the
head under `<work>/plants/<id>/` with Git hooks disabled, it:

1. checks with `git apply --check --index` that the patch applies; one that
   Git refuses (exit 1) is `does not apply` and no miss, and a check that
   fails otherwise leaves no verdict;
2. reruns the plant's `proof` with `scripts/reproduce-test.py --package
   kestrike --target lib --test PROOF --attempts 1` of the head, once on
   the head and once on the plant, in one more worktree of the head under
   `<work>/proof/` with the run's `Cargo.lock` and a Cargo target directory
   of its own, which Cargo resolves from (`CARGO_RESOLVER_LOCKFILE_PATH`).
   Both reruns run the head's `reproduce-test.py` and `select-tests.py` from
   copies under `<work>/proof/scripts/`, outside the tree a patch changes,
   and the run asks that copy, which `python3` loads, for the verdict texts
   of exits 0 and 1 in its `RESULTS` and whether its `reported` counts each
   rerun's last line beside its exit. Each rerun and each of those questions
   starts the first `python3` on `PATH`; a run that reaches no proof rerun
   starts none. The
   run first reruns on the head the proof of each plant whose patch applies,
   then applies each such plant there in turn, reruns its proof and resets
   the tree. A rerun counts when the tree still holds a regular `Cargo.lock`
   of the run's bytes after it and its exit of 0 or 1 stands beside the
   verdict line the helper prints last for that exit, `not reproduced` or
   `reproduced`. A plant whose proof's reruns both count, and do not exit 0
   on the head and 1 on the plant, is `not live`: `n` does not count it. Any
   other ending leaves the plant with no verdict: a build failure (3), a
   crash (4), a watchdog expiry (6), a rejected test ID (2), an exit of 0 or
   1 without its verdict line, a changed or missing `Cargo.lock`, or a helper
   that cannot start or prints no UTF-8 text. The lockfile is checked after a
   rerun whose output is UTF-8 text; a rerun that prints no UTF-8 text gets
   that no verdict before the check, so the next proof still reruns. A build failure on the head
   gives every proof not yet rerun there that reason. A setup of the proof's
   worktree or of the helper's check that fails, an apply or a reset there
   that fails, or a rerun whose check finds the `Cargo.lock` changed, leaves that plant
   and every later one with no verdict. When the proof's worktree or target
   directory remains after the phase, every plant that waits for its archive
   has no verdict;
3. applies the staged `plant.patch`, as the file stands at the apply, to the
   index, commits it on the detached head with the
   head's date, a fixed identity and the message `plant <id>`, so the planted
   commit depends on the head, the applied patch and the plant's id alone, writes the checkout's `Cargo.lock`, read once at the
   start, into the tree, so every archive of the run resolves the same
   dependencies, and builds the archive with `campaign sim archive`, under
   `CARGO_PROFILE_DEV_OPT_LEVEL=3` and `CARGO_PROFILE_DEV_DEBUG_ASSERTIONS=true`,
   with a Cargo target and build directory of its own that it removes after
   the build;
4. sweeps the `expected` profiles into a new root at default counts, under
   the campaign name `plant-<id>`, with `--workers` workers and `--for`
   seconds a sweep, again until each profile's `next` in `sweep-status` is
   at least `--runs`, for at most `--rounds` sweeps. `campaign sweep` bounds
   a sweep by time, so `--runs` is a floor, at least 300. A sweep that exits 1
   ends the loop;
5. runs `campaign confirm` when an expected profile's suspect of class
   `violation` or `panic` stands in the root's `suspects.jsonl`, and reads
   the findings `confirm` prints once its dispatch reports `queue_empty`, or
   holds at its `backlog` limit alone;
6. runs the seed of each such suspect that `confirm` turned into a finding of
   the suspect's class with `campaign sim run` on the archive of the
   unpatched head, under `<work>/base/`. The run prepares that archive at the
   first such seed and keeps it, or its failure, for every later seed; a
   failure before Git answers for its worktree, or a kept `Cargo.lock` that
   cannot be opened or read, gives that seed check alone no run, and the next
   seed check prepares the archive again, which ends at Git's refusal of the
   worktree's path when the first attempt added it. The check runs the sweep's manifest of the suspect's
   profile with the seed as its root and the base archive's pins, and only
   when that manifest, before the pins change, hashes to the confirmed job's
   `manifest_sha256`.

A plant's result, in this order:

- `not live`: both proof reruns count, as step 2 defines, and the proof exits
  1 on the head or 0 on the plant; the reason names both. The plant gets no
  archive and no sweep;
- `caught`: a suspect of class `violation` or `panic` in an expected profile
  that `confirm` turned into a finding of that class, whose seed passes
  (`sim run` exits 0 with the class `counts`) on the unpatched head's
  archive, and whose profile, run and seed have no `replay differs` line in
  the root's `suspects.jsonl`. A catch outranks every cause of no verdict
  below, the root's other suspects included, and its record lists each
  confirmed suspect whose seed does not pass on the head. A suspect whose
  replay differs gives no catch, since its seed does not determine its run;
  another suspect's seed can still catch. The sweep lists the first eight
  suspects of a key and counts the rest, so a profile whose status counts
  more suspects than the list holds under a `replay differs` key or under
  `other`, gives no count by key, or gives one that does not sum to its
  suspects or counts fewer under a key than the list holds, may hide a
  differing replay of any of its runs: no suspect of that profile gives a
  catch;
- `no verdict`: a cause of step 2 or a failed apply check; the sweep's
  replay of a confirmed suspect's run differs; the planted tree or the unpatched head does not build
  (`sim archive` exits 3) or `sim archive` exits another nonzero code; a
  `campaign` command exits with another code than 0 (or 1 for a sweep), or
  `confirm` leaves jobs queued; the suspect's seed ran on the unpatched head
  and did not pass (`sim run` exits 1 or 4 with a worker result), or its seed
  check did not run: its manifest differs from the confirmed job's, or `sim
  run` exits another code or prints no result; the root holds `alarm`,
  `no_pass`, `unreached` or `no_window` (the record names
  the key); `confirm` makes no finding of a suspect; the root holds any other
  suspect, in any profile, or `suspects.jsonl` lists one; a profile stays
  below the floor or has no run counted; the last sweep's exit disagrees with
  the root's verdict keys; the status names another campaign or counts than
  the default; a campaign output is malformed; or a step fails for another
  cause, which the reason names;
- `missed`: each expected profile reached the floor and the root holds no
  suspect. A plant with no expected profile is `missed` once its archive
  builds, with no sweep.

The score names the head commit and the sentence `k of n plants at commit
C`, where `n` counts the caught and the missed plants, a tally of the
results, `not_live`, the plants that are not live, and `settings`: the workers, the floor, the seconds and rounds of a
sweep, the base archive's build digest, the SHA-256 of the `campaign` binary
that judged the run, and the plants `--plant` selected (null for the whole
store). A run with `--plant` writes a score over the selected plants alone.
For each plant it holds `id`, `row`, `fix`, `files` and `proof` from its
record, the result and its reason, the proof's exits on the head and on the
plant, the planted commit and tree, the archive's
build digest, the campaign, the profiles, the counts, each profile's runs,
`next`, run range, passes and suspects, the root's control and history
totals, the verdict keys, the confirmed suspects whose seeds fail on the
head, the suspect behind a catch with its finding and its seed's ending on
the head, and for a miss its `miss_cause`. A swept miss is one sample: a
rerun at the same commit builds another archive and sweeps other seeds. The
base archive's digest is null when no seed check built it or its build failed.
The `campaign` digest is of the file read at the start; replacing the binary
during a run is unsupported. A reason names the work directory as `<work>`.

Exit 0: every plant is caught or missed and every miss has its cause. Exit 1:
a miss has no `miss_cause`. Exit 3: no miss lacks its cause, and a plant has
no verdict, is not live or has a patch that does not apply, so the score
counts fewer plants than the run selected. Exit 4: the run could not write its score, left a
worktree it could not remove or could not list, failed to write a line to standard
error, could not read its umask, or failed outside a plant. Exit 120: standard
output refused its last lines, the score's lines once the score is written,
which stays, or the help, with no score written. Exit 2:
rejected input, found before any worktree: a plant whose record or patch is
missing, no regular file or malformed, whose record or patch passes 1 MiB or
differs from the regular file `HEAD` holds, whose id is `score.json`, passes 245 bytes or is one `campaign` cannot take
in `plant-<id>`, whose `proof` holds a NUL or is no UTF-8 text, that names a
profile `campaign` cannot take, or whose
patch changes other paths than its `files` or renames, copies, deletes or changes a mode; a plant store that is
a link, differs from `HEAD` by a path the check above does not pass over
(ignored files included) or cannot be read;
an unknown `--plant`; a `--runs` below 300; a Git variable that points Git at
another repository or index; a checkout whose `Cargo.lock` is missing, a link or no regular file; a `--campaign`
that names no executable; a work directory inside the checkout, under an
ancestor another user can write, or one that cannot be created; or an
invoking directory outside a Git checkout. Exits 0, 1 and 3 write the score
and print its sentence and one `ID: RESULT (REASON)` line a plant. On
SIGINT, SIGTERM or SIGHUP the run records the first signal and ignores
further ones, starts no further child, sends the running `campaign` command
or proof rerun SIGTERM, waits for it, removes its
worktrees, names on standard error each one it could not remove or could not
list, and exits 128 plus the signal number without a score. A signal that
lands once the run has begun to write its score ends nothing: the run
finishes with its score and its own exit. A signal the run inherited as
ignored stays ignored. A Git command that runs when the signal arrives gets
SIGKILL and a wait of at most 10 s; a worktree add, a child's start, the
question to the head's copy of `reproduce-test.py` for its verdict check,
the removals of the proof's worktree and of an
archive's target directory, and the cleanup each run whole first. The proof's worktree and its target directory go after
the last proof rerun, or with the other worktrees when the run ends before
that; the run prints each one that remains.
