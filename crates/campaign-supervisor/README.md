# campaign-supervisor

`campaign` launches and supervises deterministic simulation testing (DST)
campaigns. It builds the simulation worker into an archive and runs it three
ways. A [sweep](#explore-seeds-with-a-sweep) runs seeds at the rate the
host's cores allow and keeps a record only for a run that needs one. A
[supervised campaign](#run-a-supervised-campaign) queues jobs, runs each
under cgroup custody, and records every result in one state directory,
which [`campaign-monitor`](../campaign-monitor/README.md) watches. A sweep
hands its suspects to the supervised path, where each listed suspect runs
as a supervised job that records a bundle and, when it fails, a finding
for triage. [`campaign fuzz`](#fuzz-the-archived-worker) runs the worker's
fuzz target under libFuzzer from a corpus that stays on disk.

`campaign` runs on 64-bit Linux only.

## Host requirements

- **Kernel.** Linux 5.14 or later. Attempt custody uses `cgroup.kill`, so
  `admit`, `dispatch`, `triage` and `calibrate` fail on older kernels.
- **State, archive and `sim` artifact directories.** Directories owned by
  you, mode 0700, on a read-write xfs mount or a journaled ext4 mount
  (`data=ordered` or `data=journal`, barriers on). Every ancestor must be a
  directory owned by root or by you, free of group and other write
  permission (or sticky), and not a symlink; a 0755 parent owned by a
  deployment account is refused. `campaign` refuses any other mount. This
  covers the state directory, the archive that `sim archive` writes, and the
  directory where `sim` commands write run artifacts (`--artifacts`, default
  `target/kestrike-sim` under the working directory). The state path
  must be printable ASCII, since `triage` records it. The archive path
  must be printable ASCII without `:`, `;` or `$`, since it becomes the
  worker's library search path. The process umask
  must keep every owner bit (`umask & 0700 == 0`), or the store is refused.
- **Delegated cgroup.** A user-owned cgroup-v2 directory whose
  `cgroup.controllers` lists `cpu`, `memory` and `pids`. Pass it as
  `--cgroup-root` or set `CAMPAIGN_CGROUP_ROOT`. Each command moves itself
  into `controller/` under that root and runs attempts in sibling groups, so
  the root must hold no other processes, except those of a `sweep` or a
  `fuzz` run, which keeps its own in the root's `sweep/` child. Every
  cgroup ancestor that sets `cpu.max`, `memory.max` or `pids.max` (a
  scope with `CPUQuota`, `MemoryMax` or `TasksMax`) must leave headroom:
  the aggregate for `slots + reserve_slots` attempts, one CPU,
  `tree_memory` bytes and `processes` pids each, plus one pid for the
  controller, must stay strictly below each ancestor limit, or
  `dispatch` and `calibrate` reject the configuration. Each command
  checks its own aggregate and counts no other command. Commands that
  run at once below one limited ancestor, on one root or in sibling
  scopes or roots, share that limit, so size it for their sum: the
  `--workers` cgroups of each sweep or fuzz run plus the
  `slots + reserve_slots` attempts of each supervised command. When the sum
  reaches an ancestor's memory limit, the kernel can kill a run that stayed
  below its own limit.

One way to get a delegated cgroup from systemd:

```sh
loginctl enable-linger "$USER"   # once per host; may need root
systemd-run --user --scope -p Delegate=yes --unit=dst -- bash
# In the new shell:
D=/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup)
cat "$D/cgroup.controllers"      # must list cpu, memory and pids
mkdir "$D/controller" && echo $$ > "$D/controller/cgroup.procs"
echo '+cpu +memory +pids' > "$D/cgroup.subtree_control"
mkdir "$D/campaign"
export CAMPAIGN_CGROUP_ROOT="$D/campaign"
```

The scope only gets the controllers systemd delegated to your user manager.
When `cgroup.controllers` lacks `cpu`, add, as root,
`/etc/systemd/system/user@.service.d/delegate.conf` holding
`[Service]` and `Delegate=cpu cpuset io memory pids`, run
`sudo systemctl daemon-reload`, then restart your user manager from your
own shell with `sudo systemctl restart "user@$(id -u).service"` (this
stops everything running under it; from a root shell `$(id -u)` is 0) or
reboot, and start the scope again. `Delegate=` applies when the
user manager starts, and with lingering enabled a logout does not stop it, so
logging out and in is not enough.

Run every `campaign` command below from that shell. The scope belongs to
your systemd user manager. `loginctl enable-linger` keeps the user manager
running after you log out. Without it, systemd stops the user manager after
your last session ends, and the scope and everything in it stop too. For
long runs, start a separate `tmux` server (`tmux -L dst`) or a new `screen`
session from this shell. Then `dispatch` runs inside the scope and inherits
`CAMPAIGN_CGROUP_ROOT`. A plain `tmux` call joins an already running server,
which is outside the scope.

## Explore seeds with a sweep

A sweep is the way to explore: it runs seeds for as long as you let it and
writes nothing for a run that passes.

```sh
cargo build --release -p campaign-supervisor
export PATH="$PWD/target/release:$PATH"
ROOT=/data/dst/sweep        # meets the state directory requirements above
ARCHIVE=/data/dst/archive-1 # must not exist yet

# Optimized worker with debug assertions on. The archive records the setting.
# A sweep whose --profiles include `upload` raises the alarm on a worker
# built without them, once it runs the `asserting` control, which runs
# past its assertion there. Other sweeps do not check the setting.
CARGO_PROFILE_DEV_OPT_LEVEL=3 campaign sim archive --output "$ARCHIVE"

campaign sweep --root "$ROOT" --archive "$ARCHIVE" --campaign "$(hostname)" \
  --profiles cluster-swarm,cluster-pressure,upload --workers 180
campaign sweep-status --root "$ROOT"
campaign confirm --root "$ROOT" --archive "$ARCHIVE"
```

`sweep` verifies the archive before the first run and after the last, and
starts `--workers` worker processes, 1 to 1024. It holds five descriptors
open for each worker, two for the worker's pipes and three for its cgroup,
so more than about 200 workers need a descriptor limit (`ulimit -n`) above
the common 1024; a sweep that passes its limit exits 4 with
`Too many open files`. Each worker runs one profile
for `--batch` seconds (default 30), taking one seed at a time and keeping
each run's bundle in memory, then is replaced by a new process for the next
profile in `--profiles`. A profile listed twice gets twice the batches. One
batch in 16 runs a control instead, as [below](#controls-in-a-sweep), and
one a scripted history, as [below](#histories-in-a-sweep). The
sweep stops on SIGINT, SIGTERM or after `--for SECONDS`, once each worker
finishes its current run. `--set KEY=COUNT` overrides a held count, as
`admit` takes it. `sweep` exits 2 for a campaign name or count `admit`
refuses, such as `--set root=N`, for a profile the worker does not list,
for a profile name that is a path or is longer than 242 bytes and for a
root inside the archive. A selected
profile with [required events](#events-reached-by-passing-runs) must
also have a `cluster:` declaration in the worker's capability listing. If an
otherwise valid listing omits that declaration, the sweep exits 2 before
binding the root or running a seed. A sweep runs a profile of any
class the worker lists, a `control`
profile or a history profile that expects a failure included, and
`confirm` refuses its suspects. It exits 2 for a history in `--profiles`
that expects a failure when the worker's listing declares none for it.

The root is a directory you own with mode 0700, which `sweep` creates when
it is absent, on a filesystem the state directory's rule accepts, since
`confirm` keeps a state directory under it, and its ancestors meet that
rule. `sweep` and `confirm` exit 2 for a root on another filesystem, such
as tmpfs. One sweep
holds a root at a time: a second `sweep` of the root exits 3. The
[checkpoint consistency checks](#events-reached-by-passing-runs) also hold a damaged root with exit 4. The sweep
exits 4, after stopping its workers, when `sweep.json` cannot be written,
when the root holds no `sweep.json` for the sweep to read its totals from
at its end, or when a worker ends before it prints its ready line or prints none
within 60 seconds, or within `--wall` seconds when that is shorter. The
worker's capability listing, which `sweep` reads before its first run,
has the same time and fails the sweep the same way, as does a listing
whose worker exits with another status than success. A worker that has not
exited that long after the end of its input, which ends its batch, is
killed, and the sweep goes on. The status a worker exits with after the
end of its input is not read, since each root it was sent was judged from
its block. A
sweep needs an archive whose worker prints `sweep: ready`; when a worker
fails this way, build a new archive and sweep a new root with it.

Run `n` of a profile uses the seed `campaign admit` derives from the same
archive for the same `--campaign`, profile, run and counts at its default
`--attempts`, so a swept run and that supervised job execute one manifest. Hosts that sweep under different
campaign names draw different seeds. `sweep.json` under the root holds
the archive's build, the sweep's `--campaign` and `--set` counts, and each
profile's next run number and totals, and a later sweep of the same root
with the same three continues from it; `--profiles` may differ. A root
takes one build, one campaign and one set of counts, because another of
any derives other seeds for the same runs: `sweep` writes them once the
worker's listing has accepted the profiles and counts, so a sweep the
listing refuses binds no root, and before a new root's first worker
starts. It exits 2 before it starts a worker when
`--archive` is another build than `sweep.json` names, or `--campaign` or
the `--set` values, compared as given, differ from it. Sweep a rebuilt
archive, another campaign or other counts into a new root. `sweep-status`
prints the campaign and the counts, which `admit` takes with a run number
from `uncredited_runs`.

`sweep.json` holds at most 16 MiB. Every selected profile, its controls,
and every automatically scheduled history contribute to that bound.
A sweep whose totals exceed it exits 4 and preserves its last checkpoint.
Keep that root and its suspect list for inspection, then start a fresh
root with a new campaign name. On a fresh root, selecting fewer profiles
can reduce selected-profile and associated-control totals. Every eligible
history still contributes. Resuming a root retains its existing totals.

A sweep whose archive fails the verification after its last run exits 4
and marks the root in `sweep.json`, since its runs may be of other bytes
than the build's. When the totals cannot be written, as when they would
pass the file's bound, the mark is written without them. `sweep`, `sweep-status` and `confirm` then exit 2 for
that root. Sweep a new root: the same archive, campaign and counts draw
the same seeds there. A sweep that is killed makes no closing
verification and leaves no mark.

| A run that | Is |
| --- | --- |
| passes with its witnesses | counted under `pass` |
| ends `unsuccessful` or `inconclusive`, or at the recorder's cap | counted under `uncredited` by its rule, with its first eight run numbers in `uncredited_runs` |
| completes a pass that does not count, as when its recovery ledger refuses the bundle | counted under `uncredited` as `inconclusive: uncredited pass, CAUSE` |
| ends in a violation, a panic, a refusal or another infrastructure terminal | a suspect |
| is a control's and ends in the control's failure | counted under `caught` |
| is a control's, and its plant took effect while no check failed | a suspect of class `control met no check`, or `control passed` when the worker reports a pass, counted under `missed` |
| is of a history that expects a failure, and ends in the failure its listing line declares | counted under `caught` |
| is of a history that expects a failure, and passes | a suspect of class `control passed`, counted under `missed` |
| prints a summary the supervisor's parser refuses or that names another profile, or exits with another code than its summary earns | a suspect |
| loses its worker after the kernel killed a process of the worker's cgroup for its memory use, at `--memory` or at the limit of an ancestor cgroup | a suspect of class `out of memory` |
| outlives `--wall` seconds (default 600) and has its worker's cgroup killed | a suspect of class `wall limit` |
| loses its worker for another cause, or whose worker prints another output than the run's block or more than 1 MiB | a suspect of class `worker ended during the run` |
| exits with another code or prints another summary when replayed | a suspect of class `replay differs` |

A batch of one of the `--profiles` or of a control starts by replaying
the last run that profile finished in such a batch of the current sweep,
when there is one. A history batch replays its own last finished run
once its worker has exited, as
[Histories in a sweep](#histories-in-a-sweep) describes. A fresh worker
runs the manifest `admit` derives for the same campaign, profile and run,
and must exit with the code and print the summary the sweep read. This
checks that the run is the supervised job of the same campaign, profile
and run, and that its
result is independent of the runs before it in its worker process.
`replays` counts every replay but one that SIGINT or SIGTERM ended. A profile or
control batch's `--batch` seconds start after its replay. A replay that prints more than 1 MiB is
ended, and its run is a suspect of class `worker ended during the run`.
A replay the sweep kills, at `--wall` seconds or when its worker has not
exited within the exit wait after its output ends, makes its run a
suspect of class `wall limit`.
A replay's worker runs with SIGINT and SIGTERM unblocked, so stopping the
sweep's systemd unit ends it. Such a replay was interrupted: it lists no
suspect and `replays` does not count it.
A replay whose gate fails before it starts the worker ends the sweep with
exit 4: it lists no suspect and `replays` does not count it.
A replay keeps its manifest and its bundle under `replays/` in the root
while it runs, and a sweep removes the files a killed sweep left there
when it starts.

A run whose replay differs is a suspect of class `replay differs`. Its
line in `suspects.jsonl` holds, under `first`, the digest and the ending
the sweep read for the run (`pass`, `caught`, an uncredited run's rule or
a suspect's class), beside the code and summary of its replay. `confirm`
admits it as any other suspect, and its job runs the same manifest in a
new process, as the replay did. When the run fails there, the job records
a finding. When it passes there, the job passes and records none, so the
disagreement shows in `suspects.jsonl` and under that class in
`suspect_keys`, whatever `confirm` reports. A line of any class that
would pass 16 MiB, the most `confirm` reads for one line, is written with
a null `summary` and `first`.

The first eight suspects of each profile, class and failure identity are
written to `suspects.jsonl`, and `suspect_keys` counts every suspect by
class and identity. A violation's identity is the one its summary prints,
and a panic's is its source location. A profile keys 256 identities; a
suspect of a later one is counted, and its first eight listed, under
`other`. It keys 256 uncredited rules the same way, and a rule or a class
and identity whose JSON form passes 256 bytes is cut there. Each line of
`suspects.jsonl` names under `key` the `suspect_keys` entry that counts
it, `other` included, so a reader can match each line to its count. A sweep that is killed loses the counts since its last write of
`sweep.json`, at most a few seconds of them, so the next sweep of the root
runs those seeds again and lists their suspects again; `confirm` admits a
suspect listed twice as one job. A suspect line that a kill cut short has
no newline: `confirm` does not read it, and the next sweep of the root
removes it before it lists anything. A run in progress at the kill whose
number the last write holds is not run again and is counted nowhere.

`confirm` admits each listed suspect it has not read yet as a supervised
job in `confirm/state` under the root and dispatches them, then prints the
dispatch counts and the state's findings. It exits 2 for a root no sweep
has written, as `sweep-status` does, and creates nothing there. Each
suspect line names the
build of the archive that ran it, and `confirm` exits 2 without admitting
or dispatching anything when `--archive` is another build than the
root's, since that archive derives other seeds for the same runs. A suspect `admit` refuses, such as a run of
a `control` profile, is counted under `refused`, with the first 16
reasons in `refused_reasons`, and later calls skip it. When the dispatch
stops on a refusal or a rejection, `confirm` prints its output and exits
as `dispatch` does, and the admitted jobs stay queued for the next
`confirm`. Its first call configures that state directory with `--slots`
attempts (default 8), also when that call then fails, as for an archive of
another build; later calls keep the stored configuration. Watch and
triage that state directory as [Monitor and triage](#monitor-and-triage)
describes.

That configuration gives each attempt `cpu=600` and `wall=600`, and each
job runs with its suspect's counts, so its manifest's `watchdog` count,
600 unless the sweep set it, bounds each worker of the attempt. A sweep's
`--wall` bounds one run inside a sweep worker and applies to the sweep
alone. To confirm runs that need more than these limits, sweep a new root
with `--set watchdog=SECONDS`, whose runs draw other seeds than this
root's, and install a configuration with a larger `cpu` and `wall` in that
root's `confirm/state` with `campaign configure`, which takes
every key that step 3 of
[Run a supervised campaign](#run-a-supervised-campaign) lists. Size both
for a whole attempt, which starts the worker more than once. A `confirm`
that finds a configuration in `confirm/state` keeps it and sets `--slots`
aside, and a configuration installed after a `confirm` applies to the
jobs dispatched after it.

`confirm` needs a delegated cgroup, from `--cgroup-root` or
`CAMPAIGN_CGROUP_ROOT`; with neither it runs itself in a new systemd user
scope with `Delegate=yes`, sends that run SIGTERM on the first SIGINT or
SIGTERM it receives, prints its output and then `{"exit":0}`. When that
run exits 2 or 3, `confirm` exits the same way, and it exits 4 when that
run fails for any other cause. A scoped `sweep` or `fuzz` ends the same
way, except that a sweep whose run exits 1 for `alarm`, `no_pass`,
`unreached` or `no_window`, and a fuzz whose run exits 1 for a missed
planted control, prints `{"exit":1}` and exits 1. `systemd-run` also exits
1 when it cannot start the scope, so that run writes `scope.TOKEN.verdict`
under the root, named for the token its outer command gave it, and the
outer command removes it. An exit 1
of the scoped run without that file exits 4, also on a root whose totals
carry the `alarm`, `no_pass`, `unreached` or `no_window` of an earlier
sweep.

`cluster-swarm` is the profile to give most of the workers. Its seed
selects the cluster's shape before it drives the run: the owner and key
counts, the object sizes, the hot key's weight, the GET concurrency, the
number and length of the fault phases, the link fault rates, the device
fault rates, whether a fault phase keeps its faults on until its operations
decided, and whether invalidation, cancellation, delayed transmit returns,
idle gaps and window compaction run. Its links lose, duplicate, reorder,
delay, replay and truncate datagrams and make send and receive calls return
would-block or fail, and its devices fail write and read commands with an
I/O error, after moving no byte or, as a torn write or a partial read, after
moving a prefix of whole sectors. Every device fault it draws is honest: the
device reports the command's failure. The summary's `faults_delivered`
counts the link faults and leaves the device faults out. Each shape draws whether its owners hold a
fenced coverage: each upload then names its cache version, and an
invalidation is the uploading client's INVALIDATE, which the owner
acknowledges once its coverage page write commits. Once the client
receives that acknowledgment, a GET issued later that returns a version
the INVALIDATE named fails the run, and so does that owner's index when
it binds one: then, when an upload's publication is collected, or at a
later stopped boundary. A shape whose owners hold no coverage, as every
cluster profile outside the swarm family runs, names cache version 0 in
each upload and invalidates by calling the owner when it invalidates.
Each cluster profile outside the swarm family declares one shape whose
only faults are
loss, duplication, reordering and delay, and its seed draws the owner
count, the key count and the hot key inside it.

### Controls in a sweep

A control is a profile that plants a wrong behavior in another profile's
scenario, such as a stale read or a leaked upload. The checks must catch
it. A sweep runs the controls of the profiles in `--profiles` in one batch
of every 16, starting with the root's second batch. `sweep.json` counts
the root's batches across its sweeps, so a sweep that ends inside its
first batch leaves the control batch to the next sweep. Each of those
batches runs
the control with the fewest such batches so far in the root's sweeps, and
among equals the first in the order of `--profiles` and of the table
below. `sweep.json` keeps each
control's count, so the sweeps of one `--profiles` value take its controls
in turn: the next sweep of the root takes first the control with the
fewest control batches begun, and does not start again at the first
control. The count is of control batches alone: a control's runs as one
of the `--profiles` do not raise it, and a sweep that is killed can
leave a batch counted whose first run was not. A control batch that
starts no run is not counted, so its control is the next one a control
batch runs: one the sweep's end keeps from its first run, and one whose
replay or worker fails the sweep before it. A sweep whose
`--profiles` names other profiles than the last one first runs the
controls the root's sweeps began least. Listing a control in `--profiles`
gives it more batches.

| Swept profile | Controls |
| --- | --- |
| `upload` | `planted`, `corrupted`, `acked`, `panicking`, `asserting`, `misread`, `staged-hit`, `leaked`, `uncounted` |
| `long` | `long-planted` |
| `rekey` | `rekey-stalled` |
| `cluster-broad` | `cluster-wrong-owner`, `cluster-stale-read`, `cluster-order-1`, `cluster-order-2`, `cluster-order-3` |
| `cluster-pressure` | `cluster-wrong-owner`, `cluster-stale-read`, `cluster-version-end` |
| `cluster-long` | `cluster-late-stale`, `cluster-late-leak`, `cluster-late-corrupt`, `cluster-version-end` |
| `cluster-swarm` | `cluster-swarm-wrong-owner`, `cluster-swarm-stale-read`, `cluster-swarm-late-stale`, `cluster-swarm-leak`, `cluster-swarm-corrupt`, `cluster-swarm-misread`, `cluster-swarm-unremoved` |
| `faulted`, `local`, `control`, `deferring`, `uncertain`, `failing`, `replacing`, `settled`, `boundary-tiny`, `boundary-collision`, `boundary-fragmentation`, `boundary-mixed-size`, `boundary-real-counter` | the profile's name with `-corrupted`, such as `local-corrupted` |
| `failing` | also `failing-hit`, `failing-exposed` |
| `uncertain` | also `uncertain-published` |
| `contended` | `contended-acked` |

`corrupted` and each `-corrupted` control run their profile's scenario
over a resident record whose payload byte changed before the run, which
the first stopped boundary must fail under the record-check rule. A
profile outside this table has no control, and a
sweep of only such profiles reports `controls.runs` 0. `sweep` exits 2
before any run when the archive's worker does not list a control of this
table for one of its profiles, as a worker built before that control
does, or lists it with another class than `control`: build the archive
from a checkout that has it. `calibrate` requires the controls of
[step 5](#run-a-supervised-campaign) alone: it runs none of the controls
the list below names, and no swarm, ordering or `-corrupted` control.

These controls plant at a result the client collects or, for `uncounted`,
at an owner's receive, and each is caught by one rule:

| Control | Plant | Rule |
| --- | --- | --- |
| `misread` | a complete GET hands its client a changed first byte | `a complete read returned bytes other than the label's content` |
| `cluster-swarm-misread` | a complete GET hands its client a changed last byte | `a GET returned bytes no upload of its key wrote` |
| `staged-hit` | a GET of the upload's key that ends `Missing` before the owner's index bound the key is handed the upload's object as a complete read | `a hit of a version no linearized fill published` |
| `uncounted` | at the first owner poll with a datagram due, the owner's test multiplexer drops the last lease its receive filled and reports one fewer | `a datagram a link delivered to an owner has no single account` |
| `leaked` | once the uploading client collects its publication, one payload unit is reserved from the owner's extent allocator and recorded in no slot; the conservation rule judges it at the end of that turn | `the free runs differ from the units no slot holds` |
| `failing-hit` | the GET of a key nothing was published under is handed another key's object as a complete read | `a hit of a version no linearized fill published` |
| `failing-exposed` | that GET ends `Missing` and is handed one byte | `a refused read exposed bytes` |
| `uncertain-published` | an upload whose outcome is unknown is collected as published | `an upload collected as published without its result` |
| `contended-acked` | an upload the owner refused `Contended` is collected as published | `an upload collected as published without its result` |
| `asserting` | a debug assertion fails once the upload publishes | the assertion's panic |

`leaked` is the conservation rule's one swept control. The rule compares
the owner storage's own tables with each other after every turn: the
extents its slots hold, the allocator's free runs, the slot ledger and the
index bindings. It raises five texts of its own and two binding texts the
boundary check also raises. `leaked` catches the free-run text, `the free
runs differ from the units no slot holds`. The rule's other four texts of
its own, `a slot word is malformed`, `a held extent overlaps another or
lies outside the volume`, `a ledger term differs from the slot words or
the free units` and `a resident slot has no binding`, have no swept
control, and `sweep-status` lists each of them as uncaught in scope
`boundary`. The list of texts a sweep may leave uncaught holds these
four, as [Rules in a sweep](#rules-in-a-sweep) says.

The worker reports whether a control's plant took effect: whether the
planted behavior did what a rule forbids, such as a wrong owner
completing a GET or a record's byte changing. A plant whose rule is
judged later takes effect at that judgment: a leaked request at the
healed probe of its owner, an upload reported published without its
result at the next clock move or when its run finishes, and a byte
changed during a run once a stopped boundary or the run's end finds its
record still bound. Apart from the suspects any run can end as, a control
run ends one of these ways:

- **Caught.** The run ends in the failure the control declares. It is
  counted under `caught` and leaves no file.
- **No effect.** The run finished before the plant took effect, for
  example a wrong owner in a cluster of one owner, or a key the run never
  read back. It ends `unsuccessful` under `the control's plant took no
  effect` and is counted under `uncredited`. It says nothing about the
  checks.
- **Missed.** The plant took effect and no check failed: the run ended
  `unsuccessful` under `the control's plant met no check`, or passed.
  The plant of `corrupted` and of a `-corrupted` control precedes its
  run, so any `unsuccessful` or `inconclusive` ending of one is missed
  too. The run is a suspect of
  class `control met no check` or `control passed` and is counted under
  `missed`. A control's replay that ends either way where its run did not
  is counted under `missed` too, beside its suspect of class `replay
  differs`.
- **Other.** The run stopped at a limit before its plant took effect,
  ended at the recorder's cap, or ended unsuccessful under another rule.
  It is counted under `uncredited`. The cap stands in place of the
  terminal the run reached, a violation included, so a capped run of
  `corrupted` or a `-corrupted` control is counted here. An archive whose
  worker reports
  no plant effect ends a cluster control's finished run with no failure
  under `the control met no check`, whether or not the plant took effect;
  that run is counted here as well. For such an archive no alarm reports
  a check that stopped catching a `cluster-` control: its runs move from
  `caught` to this ending, so compare each `cluster-` control's `caught`
  with its runs.

`sweep-status` sums these over the control profiles as `controls.caught`,
`controls.no_effect`, `controls.missed` and `controls.other`. Once a
control run was missed, the root's totals carry `alarm`, and that sweep
and every later sweep of the root exit 1. Treat the root's passes as
unproven until the missed control is explained. A control run that ends
in a violation other than its declared failure is a suspect of class
`violation` and raises no alarm.

Each swarm control plants its behavior in the shape its seed selects, the
same shape `cluster-swarm` runs for that seed. `cluster-swarm-leak` is
caught by the rule `a healed owner kept the resources of finished work`,
`cluster-swarm-misread` by `a GET returned bytes no upload of its key
wrote`, and each other swarm control by whichever Bytes or History check
meets it first. For `cluster-swarm-unremoved` that is most often `an owner
binds a version an acknowledged invalidation covered`, judged when the
acknowledgment arrives.

The three ordering controls run the `cluster-broad` shape with no minima.
Each watches the first upload (version 0) of the run's hot key and the GETs
of that key, through results the client sessions return: I(c), client c's
session accepts a GET of the key; R(c), client c's session returns the
outcome of a GET of the key; P, client 0's session reports version 0
published. The plant changes the last byte of one complete read of version
0, and the same turn's check fails it. At every depth the changed read is
decided after P; a read decided before P is never changed. That order is
common to the three controls and the depth column leaves it out:

| Control | Premise: every order holds | Plant | Rule | Depth | n | k |
| --- | --- | --- | --- | --- | --- | --- |
| `cluster-order-1` | I(c) before P | that GET's read of version 0 hands its client a changed last byte | `a GET returned bytes no upload of its key wrote` | 1 | 26 | 20,000 |
| `cluster-order-2` | I(0) before P; R(1) before R(0) | client 0's read is changed | the same rule | 2 | 26 | 20,000 |
| `cluster-order-3` | I(0) before P; I(0) before I(1); R(1) before R(0) | client 0's read is changed | the same rule | 3 | 26 | 20,000 |

An ordering control is caught only on a root whose run forms its premise;
every other finished run ends with no effect. Depth is the count of the
orders the premise column lists, which leaves out the order of P before
the changed read; n is the `actors` count the worker's listing holds for
the profile and k the default `turns` count. The three
numbers describe the plant's premise and are no input to a bound on the
caught rate. Each control measures how often a drawn run reaches a rare
interleaving of link deliveries with the upload. The chooser picks each
GET's issue, and with it I(0) before I(1) at depth 3; it can decide a GET
of client 1 through a CANCEL, and it orders the events that are ready at
one instant, a GET's issue and the collection of the upload's outcome
included. Link draws and the turn controller's clock rule decide when a
read or the publication report becomes ready. A GET accepted before P
completes with version 0 when the owner serves its read after the
publication, as when the links delay the read past it. In one probe of these three controls, roots 1 to 300 of each
at generator version 4 and the default counts, the plant acted in 14, 5
and 3 runs, and each of those runs was caught under the rule.

One order of the cache code was observed in no run of this controller: a
read of version 0 that completes before P. Earlier plants, whose premise
was that order and which this tree does not hold, acted in 0 of 300
`cluster-broad` roots and in 0 of 60,000 runs at the same generator
version and counts. That is a measurement over those roots, not a proof
that no selection reaches the order. The reason offered is the clock
rule: the clock moves only when nothing is runnable, and the collection
of an upload's outcome is runnable from the client poll that took the
result, so a run tends to collect the outcome before the link time a
later GET's data needs. The argument leaves three cases open: a healthy
link that delivers with zero delay, a follower woken at the publication,
and a read and the upload's outcome both ready at one instant, where the
chooser picks between them. Production can produce the order when the
uploading application collects its outcome late; this is an inference
from the session API. A defect that needs time to pass while a runnable
event waits is unlikely to be found by a sweep of this controller.

`asserting` fails a debug assertion once its upload publishes. A
worker built without debug assertions runs past it, so the control meets
no check there and the sweep raises the alarm. `asserting` is a control
of `upload` alone, so a sweep whose `--profiles` leave `upload` out does
not check the worker's debug assertions.

Each worker runs in a cgroup of its own with one CPU, `--memory` bytes
(default 2 GiB, with swap off) and `--processes` pids (default 64). The
sweep moves a worker into its cgroup before it sends the first seed, so
every run executes inside those limits. The capability listing, which
`sweep` reads before it starts a worker, runs in the sweep's own cgroup,
outside those limits; its bounds are its wait and the archive's output
bound. After each worker, the sweep kills any process left in the cgroup.
If the block stream stayed intact, at least one run finished, and the
monitor left the worker’s overdue flag clear, a process found at cleanup
makes the last finished run a `left a process` suspect. A replay that agrees with its run and leaves a process
makes that run a suspect of the same class. `sweep` needs a delegated cgroup
with the `cpu`, `memory` and `pids` controllers, as
[Host requirements](#host-requirements) describes, from `--cgroup-root` or
`CAMPAIGN_CGROUP_ROOT`. With neither it runs itself in a new systemd user
scope with `Delegate=yes`, as `confirm` does, and sends that run SIGTERM
on the first SIGINT or SIGTERM it receives. `sweep` checks its argument
ranges, campaign, profile names and counts before it makes the scope. The
checks that read the root, the archive or the listing run inside the
scope, for `confirm` too, so on a host that can start no scope either
command exits 4 before them. `sweep` exits 2 before any run
unless `--workers` cgroups of those limits, and the sweep's own
`--workers` plus one threads, stay below every limit of the cgroup root
and its ancestors. The sweep process's own memory and CPU time are
outside that check, as a supervised controller's are, so a limited
ancestor needs room for them.

The sweep runs in `sweep/controller/` under the cgroup root and keeps its
workers' cgroups beside it in `sweep/`. The supervised commands leave
`sweep/` alone, so `confirm`, `admit` and `dispatch` can use the same
cgroup root while a sweep runs. Neither side counts the other's limits:
under a limited ancestor, size the limit for both, as
[Host requirements](#host-requirements) describes. One sweep or fuzz run at a
time holds a cgroup root: a
second `sweep` on the same root exits 3 before any run. When a sweep
starts, it kills and removes every worker cgroup an earlier sweep left in
`sweep/`. A worker cgroup that holds a child cgroup cannot be removed:
the sweep exits 4, as a supervised command holds on an attempt's nested
cgroup, until that child is removed by hand.

Each worker leads its own process group, so a signal sent to the `sweep`
process's group, as a terminal's SIGHUP or SIGQUIT is, does not reach the
workers; the kernel kills each worker when the `sweep` thread that started
it ends, so none outlives a `sweep` that such a signal ended. That kill
reaches the worker alone: a process the worker started ends with the
`sweep` only when it arranges the same for itself, as the archived
worker's children do. `sweep` kills a worker
by killing its cgroup, which ends every process the worker started, and
kills the worker's process group when that kill fails.

Each worker runs in the environment of the archive's verified worker
command: the `sweep` process's variables except every `LD_*` variable and
`GLIBC_TUNABLES`, with the archive's library directory as the whole
`LD_LIBRARY_PATH`. `sweep` adds three glibc allocator settings,
`MALLOC_MMAP_THRESHOLD_`, `MALLOC_TRIM_THRESHOLD_` and `MALLOC_TOP_PAD_`.

### Histories in a sweep

A scripted history is a profile of class `history`: a script that drives
one scenario step by step, where the seed decides the order of the events
the script leaves open. The worker's listing says how each history ends:
`expected=pass`, `expected=violation` or `expected=unsuccessful`. A sweep
runs the histories its worker lists in one batch of every 16, starting
with the root's tenth batch, whatever `--profiles` names. Each of those
batches runs the history with the fewest such batches so far in the
root's sweeps, and among equals the first the worker lists, so the sweeps
of a root take the histories in turn as they take the controls. A history
batch that starts no run is not counted. Listing a history in
`--profiles` gives it more batches. Those batches add to its run totals
and leave its rotation count as it was; a history batch adds to both.
After a history batch, once its worker has exited or been killed and its
cgroup is empty, the sweep replays the last run the batch finished, in a
fresh process. It does so also when a later run of the batch lost its
worker. A batch that finished no run, and one that ends after the sweep
has stopped, on a signal, at `--for` or on a failure, replays nothing.

- A history that expects a pass is counted as any other profile is. A
  run of it that ends in a violation is a suspect, which `confirm`
  admits.
- A history that expects a failure is a control. A listing of capability
  version 4 declares its failure on a `fails` line: a violation of one
  obligation under one rule, or an unsuccessful ending under one witness.
  A complete unsuccessful run earns a history catch only when the
  declared witness is shorter than 41 bytes and equals the printed
  witness. A 41-byte prefix could name a longer witness, so declarations
  of 41 bytes or more remain uncredited. The current worker uses shorter
  labels for these histories. A capped or inconclusive run remains
  uncredited even when its output retains the declared witness.
  A run that ends in the declared complete failure is counted under `caught`. A run that
  passes, whether or not the pass counts, is a suspect of class
  `control passed`, is counted under `missed` and raises the alarm. A run that ends in a violation of
  another obligation or under another rule is a suspect of class
  `violation`, which raises no alarm and which `confirm` refuses. A run
  that ends unsuccessful another way, or inconclusive, is counted under
  `uncredited`.

A listing below version 4 declares no failure. A sweep of such an archive
runs the histories that expect a pass and no other, and exits 2 when
`--profiles` names a history that expects a failure.

The `--set` counts apply to every history the sweep runs. `sweep` exits 2
before any run when a count is below a listed history's held bound, and
when a listed history's name is no single path component or exceeds 242
bytes. This limit leaves room for `.manifest.tmp` in a directory entry.
A rejection for a count names the history, the count's key and the range
that history accepts.

`sweep-status` reports the root's histories under `histories`: `profiles`
is how many the root holds and `ran` how many of them have a run, beside
their `runs`, `pass`, `caught`, `missed`, `uncredited` and `suspects`.
While `ran` is below `profiles`, some histories remain at `runs=0`.
Rotation uses persisted dedicated-batch counts; `ran` counts histories
with a positive run total. Explicit profile runs and interrupted batches
can make those counts differ.
On a fresh root with N histories absent from `--profiles`, the last
history's first dedicated batch is number `10 + 16 * (N - 1)`, counted
from 1, provided each earlier history batch sent a root. For 164
histories this is batch 2618. With 180 workers it can start in the
fifteenth group of batches: after fourteen `--batch` intervals plus
startup and replay costs. Use this arithmetic for sizing. Elapsed time
also depends on worker scheduling and run completion. The number of
eligible histories depends on the archive.

The `alarm` counts missed controls and histories together. Read these
roots with a supervisor that supports history-control accounting; an older
reader can parse the file while omitting history misses from its alarm.
Root-level totals and rates include all profiles, controls and histories.
Histories print `operations: unavailable`, which contributes zero to
operation totals. Rates divide accumulated totals by elapsed sweep seconds.

### Profiles with no pass

A profile can stop earning anything while every check stays quiet. When
the cache refuses every upload, for example, each run of a profile that
needs one ends `unsuccessful` or `inconclusive` and is counted under
`uncredited`. `sweep-status` therefore lists under
`no_pass` each profile whose listed class is not control, with at least
64 runs in the root and none counted under `pass` or `caught`. A history
that expects a failure is judged here too, by its `caught` runs. `sweep`
exits 1 while the root's totals hold such a profile. The entry goes once
a run of the profile is counted under `pass` or, for a history that
expects a failure, under `caught`.

A profile that can pass in a sweep passes within far fewer than 64 runs.
The entry says that the profile earned nothing and leaves the cause to
be found. Common causes:

- The cache or the harness changed so that the scenario cannot complete.
  Read the profile's `uncredited` rules and `suspect_keys` in
  `sweep-status`, find which of the two it is, and classify it as
  [the simulation guide](../../docs/agents/simulation.md) directs.
- A history that expects a pass has a suspect in every run. Its
  regression failed; `confirm` its suspects.
- A history that expects a failure has no run counted under `caught`.
  Runs that end in another violation or a panic are suspects, which
  `confirm` refuses; capture one by hand, as the guide describes. Runs
  counted under `uncredited` name their rule there. A run under a
  declared unsuccessful witness of 41 bytes or longer is among them even
  when it ends as declared; the remedy is a shorter witness in both the
  history and its declaration, a new archive and a new root.
- The root's counts keep the profile from its goal. At the default
  `restarts` count of 1 a `recovery-` run may take its first cut and
  skips the cuts after it, so each swept run ends `inconclusive: goal`. A
  root takes one set of counts for every profile and history it runs, and
  the root that already holds 64 such runs keeps the entry. Leave them out
  of `--profiles` and sweep into a new root, under a new `--campaign` name
  for seeds the old root did not run. Or sweep the three in a root of
  their own with `--set restarts=20`, which lets a run of each take every
  cut; different counts already give different seeds.
  [Recovery crash windows](#recovery-crash-windows) gives that command and
  its `no_window` verdict.

One run counted under `pass` or `caught` keeps a profile off the list,
however its other runs ended. Its `pass` and `runs` in `sweep-status`
give its pass share, which the sweep compares with no baseline.

### Events reached by passing runs

In `sweep-status`, `profiles.<profile>` holds the checkpoint totals.
`witnesses` counts witnessed actions in parsed original-run summaries,
including those of uncredited runs and suspects. `covered`
counts passes with cluster lines in their summary. For each counter in a
coverage line with counts, `reached.<counter>.runs` counts the passes
that reported a positive count, and `total` sums the reported counts.
These counts saturate at `u64::MAX`. A pass with `coverage: unavailable`
increments `covered` and leaves `reached` unchanged. Replays leave all
three fields unchanged. Only original passes add to `covered` and `reached`.
A parsed summary from an original suspect run still contributes to
`refused_actions`. A suspect record can show the replay summary; the replay
adds no work or event reach. Any later suspect mark on a counted pass,
including a mark from replay or batch cleanup, preserves its original
counts. See `suspect_keys` for the recorded classes.

`sweep-status` derives `reach` from those totals. A profile with positive
`operations` or `covered` has an entry unless it is a control or a
scripted history marked `failing_history` in the checkpoint. A sweep sets
that flag for a history whose listing declares a failure on a `fails` line.
A history that expects a pass stays eligible. If an older checkpoint lacks
the flag for a history with a declared failure, status includes the history
when it has positive operations. Status drops that entry once a sweep
binds the history and replaces the checkpoint with the flag set.
Each eligible profile with a required-event row also has an entry when
`operations` and `covered` are both zero.

- `covered` repeats the covered-pass count when positive and also at zero
  for a profile with required events. With positive `covered`, `zero`
  lists, in summary order, each counter whose `runs` is zero or whose
  key is absent from `reached`. An empty list means each counter has a
  positive `runs` count. Different passes can account for different counters.
- `refused_actions` is `1 - witnesses / operations` when `operations` is
  positive. With consistent counts, it is the share of executed actions
  that went unwitnessed. A negative value indicates excess reported witnesses. Each cluster action earns one witness when its outcome code
  is positive; a refusal has code zero. The single-owner world has two exceptions: a rekey
  earns a witness only when it ends rekeyed or busy, and a session
  change earns one at delivery.
- `unread` is `(misses + refused) / (hits + misses + refused)` over
  event totals from covered passes. It appears when the denominator is
  positive. The GET counters cover the generated workload only. A cluster
  GET counted under `refused` was issued and witnessed. A GET action
  refused before issue contributes to `refused_actions` instead.

The coverage line and the `zero` list use this order:

| Counter | What it counts |
|---|---|
| `published` | Workload uploads whose collected outcome was published. |
| `hits` | Workload GETs that read one upload exactly and passed every check. |
| `misses` | Workload GETs with a missing outcome. A GET can precede the key's first publication or follow invalidation, displacement or expiry. |
| `refused` | Decided workload GETs that ended with a partial transfer, pressure response, failure, timeout or cancellation. |
| `invalidated` | Invalidations that removed the object bound to the requested key, or acknowledgments client 0 collects for tracked invalidations in versioned sessions. |
| `cancelled` | Cancels applied to undecided GETs. A cancelled GET contributes to `unread` through `refused` once its outcome is collected. |
| `cross` | Exact workload reads by a client that, with this read, has read from at least two owners. |
| `reused` | Collected publications still bound to a slot observed for an earlier publication at the same owner, including probe publications. |
| `healthy` | Healthy phases whose probes passed at every owner. |
| `faults` | Injected link fault records, including records of dropped datagrams. |

In `cluster-pressure`, `invalidated` and `cancelled` stay at zero: the
shape sets `invalidate` and `cancel` to false, so its workload generates
GETs and PUTs alone. The required-event table excuses both, and once the
profile has a covered pass, `zero` names them.
`cluster-broad` and `cluster-long` support all ten counters, as does
`cluster-swarm` across its members. For a swarm member, `cross` requires
one client to complete workload reads from at least two owners.
`invalidated` and `cancelled` require their respective actions to be
enabled. `faults` counts injected link faults; device faults alone leave
it at zero.

`reused` includes probe publications, so probes alone can reach it.
A positive `runs` count establishes only that a pass reached the event.
Use `rules.caught` for evidence that a check can fail.

When a sweep continues a checkpoint written before these counts existed,
`operations` and `pass` retain their earlier counts. `witnesses` and
`covered` start at zero, and `reached` starts empty. On continuation,
`zero` and `unread` use coverage recorded since the upgrade. `refused_actions` treats earlier
operations as unwitnessed. Before saturation and rounding, this
overstates the share by the earlier witnesses divided by all operations.
A supervisor from before the reach counts drops `witnesses`, `covered`
and `reached` when it rewrites the checkpoint. A supervisor that reports
reach then reads the two counts as zero and `reached` as `{}`. A writer
that predates `failing_history` also drops that flag on rewrite, even if
it preserves the reach totals. A declared failing history with positive
operations then regains its `refused_actions` entry until a current sweep
binds it and saves the flag.

`unreached` maps each profile with at least 64 covered passes and a missing
required event to its missing events, for example `{"cluster-pressure":["misses"]}`.
A missing event has zero reaching passes. The key appears only when at least
one profile has a nonempty list. `sweep` exits 1 while any
profile has an entry; `sweep-status` prints the same totals and exits 0.
One covered pass reaching an event clears it from the list, regardless of
how often later passes reach it. Read `reached.<event>.runs` for the cumulative
count. The [required-event table](src/campaign/seeds/required.rs) names
each of the ten counters of `cluster-swarm`, `cluster-broad` and
`cluster-pressure` once, in one of two states. Only a required counter
contributes to `unreached`, as above; the table holds its reaching passes
in the sweep that measured the row. An excused counter never lists under
`unreached`, and the table holds its reason. `zero` reports both states:
while `covered` is positive, it names each counter with zero reaching
passes, an excused counter included; while `covered` is 0, the profile has
no `zero` list. A counter is required when one sweep at the
default counts (`counts: {}`), with at least 2,000 covered passes of the
profile, had at least one reaching pass in eight. A counter is excused when
its reason names the workload step, the fault or the setting the counter
requires, which the profile's shape turns off. A required counter becomes
excused only with the repository owner's approval; the table's unit test
pins the excused pairs, so such a change also changes that test. The
chaos reach judges hold Python copies of the table's rows and excused pairs
and of the coverage counters in `chaos/judges/reach/shared.py`, and
`chaos/tests/test_reach.py` compares them with this table and with
`src/protocol/summary.rs`; run it after a change to either file.
The gate also applies with count overrides; the measurement describes the
default counts. A pass with `coverage: unavailable` increments `covered`
and leaves the event counters unchanged. If `covered` is positive and the entire
`reached` map is empty, every covered pass reported unavailable coverage.
For mixed coverage the checkpoint records aggregate counts. An individual
execution's worker summary identifies its coverage.

A checkpoint marked for a changed archive gives `sweep`, `sweep-status` and
`confirm` exit 2. On an unmarked checkpoint, the reader checks
`covered <= pass <= runs` for each profile. For each event, `event.runs` is
at most `covered` and its total is between `event.runs` and
`event.runs * u32::MAX`, inclusive. A failed check or a profile from the
[healthy catalog](src/campaign/calibration/controls.rs) marked as a control
holds all three commands with exit 4. Keep the root for inspection and sweep
a fresh root.

Status derives `unreached` from the reading supervisor's table. A change to
its event membership can change the displayed verdict for the same totals.
Reading the root leaves its checkpoint intact. Continuing it with a supervisor
that drops the reach totals restarts `covered` at zero and clears the entry.
A still-required event returns after 64 new covered passes miss it. A simulation
host binds each root to one build and uses that build's supervisor.

### Recovery crash windows

A crash window is a state where an interruption can occur before or after
a device-write step. This includes the state before the first workload write submission.
Each built-in recovery profile’s `windows` totals in `sweep-status` count
cuts by operation, site, occurrence, boundary, and failure class.

A cut counts when its recovery check passes, the planned failure class
runs, and queue disposal returns the planned drain or reset disposition
with zero pending commands. The captured held writes must match the
declared writes in count, order, and block range. For each 512-byte block,
the media comparison must attribute the result to one write and distinguish
the submitted bytes from the old bytes. The resulting pattern of landed
blocks must match the cut's planned mask. One counted cut covers the row
even when the table prescribes several landings there.

The worker uses the recorded manifest’s profile name to select its own
cut table. A successful ledger rebuild yields `stages:`, `limits:` and,
at capability version 5, `windows:`. The census is unavailable when the
manifest lacks a recognized recovery profile name or the rebuild fails.
With an `unrecorded` or `mismatched` ledger verdict, the census describes
the inspecting worker’s table. Coverage under the recording worker’s
table is unknown.

`stages:` counts cuts in planned, reached, activated, recovered, checked,
skipped order. A cut contributes to every stage it recorded. Its events
may end at any prefix through checked, or at skipped just after planned or
reached. `limits:` describes the failures and landings the model supports.
Campaign credit requires a matching recovery record, a complete pass with
`Restart` fired, and passing checks and matching measurements for every
required cut. Each required cut must be at a decided site.

The `windows:` line contains one or more `name=count` or `name=unplanned`
entries separated by single spaces. Each row has a unique, nonempty name.
`=` separates the name from its value. The parser rejects whitespace and
control characters in names. A count is the worker’s per-run total for the
row: `0` or an ASCII decimal beginning with `1` through `9`, within `u64`. Each counted cut passed its
recovery check and belongs to one row, so the parser rejects a line whose
counts sum to more than the `checked` stage total. Point rows follow operation, site code, occurrence,
boundary and failure class order. Bare site names follow in registry order. The sweep adds rows from a
`credited` or `inconclusive` ledger when the summary names the swept
profile and the exit code agrees with the run form. The sum under each stored
name saturates at `u64::MAX`. `windows_unplanned`
lists optional boundaries and registry sites outside the profile’s
descriptor points. Top-level `windows_missing` groups stored planned
names with a zero total by profile. It appears only for a nonempty list.
At `summary: 1`, workers at capability versions 1 through 4 report stage
totals and limits. With one of those listings, the supervisor rejects an added
`windows:` line as `Unknown("windows")`. With a version 5 listing, the supervisor
returns `Missing("windows")` if the recovery census omits the line. Window
coverage for versions 1 through 4 is unknown. The archive pins its worker, so a grammar change must increment
the governing version and the supervisor must continue to read the forms
emitted by retained workers.

The supervisor shortens window names, uncredited-rule keys and suspect
class-and-identity keys to at most 256 bytes of escaped JSON string contents. The checkpoint has a separate 16 MiB limit. Planned and
unplanned rows share a budget of 256 distinct names per profile; further
names go under `other`. A positive total under a shared prefix or `other`
can hide a zero-count row. Inspect or reproduce a contributing run with
the pinned worker to see that run’s full names and counts. Individual
sweep totals require the original rows from each contributing run.

At the default `restarts=1`, only the first cut in table order can run.
After its post-relaunch lookup finishes, the worker marks the remaining
cuts skipped. An earlier stop can leave a shorter ledger prefix. Once an
eligible run reports rows, every planned window after the first cut's has
a zero total and `windows_missing` lists it. The first cut's window stays
off the list once a contributing run counts a cut there.
`windows_missing` is diagnostic at every count.

Sweep the three recovery profiles, `recovery-16k`, `recovery-512` and
`recovery-torn`, with `--set restarts=20`, which lets a run of each take
every cut of its built-in table: `recovery-torn`'s holds 20 cuts and the
other two 4 each. A root binds one set of counts for every profile and
history it runs, so this sweep takes a root of its own:

```sh
campaign sweep --root "$ROOT-recovery" --archive "$ARCHIVE" \
  --campaign "$(hostname)" \
  --profiles recovery-16k,recovery-512,recovery-torn \
  --set restarts=20 --workers 28 --for 600
```

In a root whose counts set `restarts` to 20 or more, `sweep-status` and
the totals `campaign sweep` prints at its end add `no_window`. It maps
each profile with 64 runs or more to its planned windows with a zero
total, in the form of `windows_missing`, and appears only when it holds a
profile. A profile with an empty `windows` map stays off it, since its
coverage is unknown: inspect or reproduce a contributing run with the
pinned worker, as above, and check that the archive's worker is at
capability version 5. A total under a shortened name or `other`, as
described above, can sum a zero-count row with a positive one.
`profiles.<profile>.windows_folded` records each stored planned name
that holds a counted row stored under a name other than its own: the
SHA-256 of that row's full name while it is the only row there, and
`null` once a second distinct counted row, one under its own name
included, adds to the same total. `no_window` also lists each `null`
name, while `windows_missing` lists zero totals alone. A profile with
no such name stores `{}`. A checkpoint written before the record, or
rewritten by a supervisor without it, holds no `windows_folded` or
`null`; for such a profile `no_window` also lists `other` and each
stored name of 251 escaped bytes or more, which the supervisor could
have shortened, and it keeps doing so as later rows are counted. A
`null` name stays for the life of the root, and a new root of the same
archive folds the same rows again: the remedy is a worker whose planned
window names fit 256 escaped bytes and whose rows fit the budget of 256
names, its new archive and a new root. Otherwise the entry goes once
every planned window of the profile has a positive total.
The count of 20 and the floor of 64 runs, the one `no_pass` uses, are
ruled as they read, by the workstream's lead on the owner's delegation of
25 November 2026 (OQ-2.1 of `chaos/interview.md`, "Ruled for the owner").
The sweep exits 1 for `alarm`, `no_pass`, `unreached` or `no_window`.

An empty `windows` map means coverage is unknown. With reported totals,
a profile absent from `windows_missing` has a positive count for each
stored planned name. Coverage of other landings in the same row, steps
without a planned row, and interruptions at the attach’s RESET root
writes requires separate evidence.

### Recovery-profile write check

The [recovery world](../kestrike/src/net/world_tests/recovery.rs) checks
writes accepted from scene install through that incarnation’s Crash turn,
including delivered writes. The accepted writes may match a prefix of whole
child ranges. A shortened write is a range mismatch; the held-write check
catches missing children. The write check reports the first extra or
mismatching device range. Overflow anywhere in the capture since rebase takes
precedence, including overflow before install. Library tests read the write
diagnostics from the run. Sweeps judge recovery from the run outcome, Restart
check and recorded ledger.

Bootstrap rebases the capture after the attach’s two RESET root writes. Owner
startup and session opens precede scene install, as does the fixture’s key
publication on the first launch. Range comparison starts strictly after these
writes, at the next acceptance ordinal recorded at scene install, and ends
at that scene’s Crash snapshot. For a cut
that reaches Lookup, the comparison precedes its relaunch and recovered lookup.
In a completed full-table run the final Crash snapshot closes the last comparison; the
world then relaunches, performs its final recovered lookup and finishes. `Plant::Unmatched` shifts each expected child one block earlier in
both comparisons. The reported range is the range the device accepted.

A version 5 worker prints [crash-window counts](#recovery-crash-windows)
when it recognizes the recovery profile and rebuilds its ledger. The census and write
check leave a workload step unobserved if it has neither a descriptor point
nor a device write.

### Rules in a sweep

`rules.caught` groups caught control and failing-history runs by rule.
Each key is a full cataloged violation text, an unsuccessful witness as
printed in the summary (at most its first 41 bytes), or `panic:` followed
by the panic payload. Each value holds `runs`, the caught-run count, and
`controls`, the contributing profile names.

`rules.scopes` groups the worker's rule catalog by the check that raises
each rule, and gives each scope's `rules`, how many of them count as
`caught`, and the `uncaught` texts. An `uncaught` entry has zero catches
credited to that scope. Credit follows completed matching control results
and the catalog's first scope for each text, except that a scripted
history's catch of a text the catalog also lists under `history` counts
under `history`.
A passing result records the observed outcome; demonstrating that its
check can fail requires a caught control.

| Scope | Check | Judges |
| --- | --- | --- |
| `boundary` | the stopped-boundary and teardown observer | every single-owner and cluster run |
| `world` | the single-owner world's own checks: the bytes of each GET it collects, a publication it collects, a held update's heal | every single-owner run, for the GETs and the upload the world's own actions collect; a scripted history judges an outcome its own step collects |
| `cluster` | the cluster checker | every cluster run |
| `history` | a scripted history's own checks | that history's runs only |
| `oracle` | the oracle over recorded rows | the `recovery-` profiles, a few scripted histories and the tests that record rows; a sweep's other runs record no rows |

The `uncaught` lists matter for the checks each run reaches: `boundary`,
`world` and `cluster` for live profiles, and `history` and sometimes
`oracle` for scripted histories. Catalog order assigns a shared text to
its first scope. A catch of a world/oracle text counts under `world`;
a catch of a history/oracle text counts under `history`. A text listed
under `cluster` and `history` counts under `history` for a scripted
history's catch and under `cluster` for any other profile's. The assigned
scope reflects catalog order. Use captured failure evidence to identify
the producer. An oracle-only verdict, such as
the restart check, counts under `oracle`. In the `world` scope, `a hit of a version no linearized fill
published` judges a complete read of a key with no registered content,
and a complete read of the upload's key that the world collects before it
has seen the owner's index bind that key. The evidence is of the key and
stays once seen: a hit of a version the owner removed, or of a later
version of a key bound before, is judged by the oracle over recorded
rows, and a swept run of a live profile records none. The sweep reads
the catalog from the worker's `--rules` form, which a worker of
capability version 3 or later has; a
root swept with an earlier worker has no scope, and a violation's rule
lists as `unlisted rule` with its digest.

`ALLOWED` in `src/campaign/calibration/uncaught.rs` lists the texts a
sweep may leave uncaught, each row with a scope, a text or the whole
scope, and the reason. It holds seven rows: the conservation rule's four
texts with no swept control, named above under
[Controls in a sweep](#controls-in-a-sweep), two `history` texts of the
incident clock checks, `an owner turn sampled a tick other than its
projection` and `the held sample began at or past the deadline`, each of
which compares two values the test harness writes, and the whole `oracle`
scope, since only the `recovery-` profiles, a few scripted histories and
the tests that record rows give the oracle rows to judge. The key reads
a text the catalog repeats under a later scope under its first scope
alone, so the list holds no row for the later copy. A supervisor unit test requires
each row's scope in the worker's rule source and each row's text first
listed under that scope.

Once every history of the root has a run counted under `pass` or
`caught`, `sweep-status` and the totals `campaign sweep` prints at its end
add `unlisted_uncaught`, which maps each scope to its uncaught texts that
`ALLOWED` lacks, in catalog order, when there is at least one. Each text
stands under its first scope, and `rules.scopes.<scope>.uncaught` lists it
there too. A caught run of any profile keeps its text out of the key: a
text of `cluster` and `history` that only a scripted history caught stands
in `rules.scopes.cluster.uncaught` and outside the key. A root whose
worker lists no history meets the first condition
at once. A profile whose row in `sweep.json` has no `history` field may be
a history without a credited run, so the status of its root has no key.
Each sweep writes the field for its own profiles, controls and histories,
so a sweep of the root that names the profile adds it. An excerpt of one
scope:

```json
"unlisted_uncaught": {"boundary": ["two bindings name one slot"]}
```

Each print computes the key from the catalog and the catches that
`sweep.json` stores and from the `ALLOWED` list compiled into the printing
supervisor, so a supervisor with another list can print another key for
the same root. An absent key means that some history has no run counted
under `pass` or `caught`, that some profile's row has no `history` field,
or that `ALLOWED` holds every uncaught text of the stored catalog.
`histories.ran` counts the histories with a run of any ending, so it does
not tell the three apart: the `history`, `pass` and `caught` values of each
row under `profiles` in `sweep.json` name a row without the field and a
history without a credited run.

The key reports. The sweep's exit code reads the status keys `alarm`,
`no_pass`, `unreached` and `no_window` alone, as it does beside
`windows_missing`. Which texts a root catches depends on its seeds and
its profiles, since five of the swarm controls name no rule, so a text
in the key says that no caught control or failing history of the root
ended under it.

### Known findings in a sweep

The supervisor compiles in a table of open findings, `KNOWN` in
`src/campaign/known.rs`. A row registers a classified bug whose issue is
open: its `issue`, its `class`, its `pin`, the profiles whose suspects
it explains, and the obligation code and full rule text those suspects
fail. The pin is a scripted history that reaches the defect with no
plant and declares a violation of the row's obligation code under its
rule. A row lists a profile only when a run of that profile can reach
the defect's trigger. When the pin alone reaches it, the row's profile
list is empty: the row registers the pin and explains no suspect, so a
violation of its rule counts under `new_suspects` unless another row
explains it. The
protocol contract case fails while
`defects` in `src/campaign/known.rs` reports a row as invalid against the
worker's listing and rule catalog. A fix that changes the pin's ending under
root 3, the seed of the checks every history runs, fails those checks until
the pin is flipped to a pass, and a flipped pin fails the contract case
until the row is deleted. A family's seeded test can pin the history under
other roots as well, and the fix updates it.
[Act on each class](../../docs/agents/simulation.md#act-on-each-class)
says how to register a finding.

`sweep-status`, and `campaign sweep` when it ends, print two members
that split the root's `suspects`:

```json
"known": [{"issue": 225, "class": "correctness bug", "pin": "i14-held-count-open",
           "rule": "a GET returned bytes no upload of its key wrote",
           "suspects": 37, "keys": {"cluster-swarm": ["violation: 0201..."]}}],
"new_suspects": 3
```

- `known` holds one entry per row, in table order, and is absent while
  the table is empty. A row explains a suspect key of class `violation`
  whose failure identity, a check's violation or an oracle verdict,
  carries the row's obligation code and the SHA-256 of its rule, in one
  of the row's profiles. Each key counts under the first row that
  explains it. `keys` lists each of the row's profiles with the keys it
  explains there, an empty array when none matched, and `suspects` sums
  their counts. A row shows `suspects` 0 when no suspect key stored in
  the root matches it. A row with an empty profile list shows an empty
  `keys` object and `suspects` 0 for every root. A row whose obligation
  code is wrong matches no key and shows `suspects` 0 for every root.
- `new_suspects` is the root's `suspects` less the rows' `suspects`, at
  least 0, and is present for every root. A status without
  `new_suspects` was printed by a supervisor without the table; read each
  of its suspects as new.

The split is read from `sweep.json` at each print. `suspects`,
`suspect_keys`, `suspects.jsonl`, what `confirm` admits and the exit
code stay as they were, so a root swept by an earlier supervisor reads
the same way. Read the split within these limits:

- A `known` label says that a suspect failed the row's obligation and
  rule in one of the row's profiles. Whether the row's defect caused that
  suspect takes a replay to show.
- The table is compiled into the supervisor. A supervisor built from
  another commit than the root's archive can label the root's suspects
  wrongly, and a stored status document carries the split of the
  supervisor that printed it. On a simulation host the table and the
  worker come from one commit, because the runner takes `campaign` from
  each build it fetches.
- A finding that only a cluster shape reaches may have no scripted
  history. It gets no row of its own, and its suspects stay under
  `new_suspects` unless they fail another row's obligation and rule in
  one of that row's profiles.
- Suspects of any class other than `violation`, audit failures, and
  suspects counted under `other` stay under `new_suspects`.
  `sweep-status` lists a row whose rule the catalog stored in the root
  lacks as it lists any other row, so a row of another commit's table can
  show `suspects` 0 for that reason.

## Fuzz the archived worker

`campaign fuzz` runs the archived worker's `campaign` fuzz target under
libFuzzer for a set time, in one cgroup per worker, from a corpus that
stays on disk between runs. Each distinct failure becomes one directory
and one line. A run earns no receipt, lane result or obligation credit.
[The fuzz host](../../docs/agents/sim-hosts.md#fuzz-host) gives the build
and the service unit.

```sh
campaign fuzz --root "$ROOT" --archive "$ARCHIVE" --for 14400 --workers 8
campaign fuzz-status --root "$ROOT"
```

`fuzz` takes `--root DIR --archive DIR --for SECONDS [--workers N]
[--memory BYTES] [--processes N] [--cgroup-root DIR]`: 1 to 1024 workers,
1 by default, each in a cgroup with one CPU, `--memory` bytes (8 GiB by
default) and `--processes` processes (64 by default). The workers'
`-rss_limit_mb` is three quarters of `--memory` in MiB, 6144 by default.
It finds its cgroup root as `sweep` does, and it holds the lock
a sweep takes on that root's worker cgroups, so one delegated root runs a
sweep or a fuzz run at a time. The archive must be built with libFuzzer's
coverage counters. A root binds no build: build a new archive to follow
`main` and run it on the same root, and the corpus carries over. The root
and archive paths hold only the bytes `A-Za-z0-9/._=,-`, because
libFuzzer passes them to a shell when it merges. `fuzz-status --root DIR`
prints `fuzz.json`; it takes no lock and writes nothing, so it reads a
root while a run holds it.

### The fuzz root

```text
ROOT/fuzz.json        next run, the last run started and its build, control
                      counts, alarm, each key's count, failed merges in a row
ROOT/findings.jsonl   one line per key
ROOT/corpus/          libFuzzer's output directory
ROOT/failures/ID/     input, claim, bundle, rerun/, rerun.stderr, stderr.tail,
                      record.json
ROOT/control/         the last control's intake
ROOT/runs/N/          seeds/, wK/, wK.stderr, merge/, merge.stderr, merge.txt,
                      run.json
```

A run goes through these steps:

1. It claims the root and the cgroup root, verifies the archive and
   probes the archived worker with `-merge=1` and `-help=1`: a worker that
   refuses a merge exits 2, and a probe that cannot run or passes 60
   seconds exits 4. It restores the corpus when a kill cut a merge's
   swap, and makes `findings.jsonl` and the key counts agree with the
   failure directories. A root whose `alarm` is set or whose key table is
   full ends here with exit 4.
2. It files the failure files that the last run started left, as a run
   killed between a worker's failure and its intake leaves them, then
   takes run number `N`, writes the worker's seeds into `runs/N/seeds/`
   and keeps the last 16 run directories.
3. It runs the planted control: the `planted` target on the `upload` seed,
   filed under `control/`. The run goes on only when that failure is
   stored there and its rerun reproduces it. A control that is missed
   sets `alarm`, and `control/` then stays as that run stored it.
4. It starts the workers. Each runs
   `--fuzz campaign --artifacts runs/N/wK` with `-max_total_time`,
   `-max_len=65536`, `-timeout=60` and `-rss_limit_mb` on `corpus/`
   and the seeds. A worker whose output file passes 64 MiB, or that runs
   180 seconds past the deadline, is killed. A worker that fails is filed
   and replaced for the time left, and the 16th failed worker ends the
   run.
5. After a run that reached its deadline, one worker merges `corpus/`
   and the seeds into `corpus.new/` within 1,800 seconds. The corpus is
   replaced only when the merge exited 0 and wrote a file; otherwise
   `run.json` names the cause. A merge that exited 0 whose `corpus.new/`
   cannot be listed ends the run with exit 4 and no `run.json`, and so
   does a merge whose worker cannot start.
   `fuzz.json` counts the failed merges in a
   row of runs that ended at their deadline, and an adopted merge
   resets the count.
6. It verifies the archive again and writes `run.json`: the build, the
   times, the ending, each worker's exit, key and last counts line, the
   corpus's file counts before the run, after it and after the merge, and
   the merge's result and attempt count.

SIGINT or SIGTERM stops the workers; the run adopts no merge and, when
it closes without error, exits 0.

### Findings

A failed worker is filed under one key, the first of these that applies:

| Key | The worker left |
| --- | --- |
| the claim's text, cut at 256 bytes of its JSON form; a claim that is the text `other`, or starts with `claim: `, `worker: ` or `libfuzzer: `, is keyed `claim: ` and its text, cut alike | `first-failure.claim`: a violation, a harness defect or a panic that the worker judged and kept |
| `worker: input without a claim` | `first-failure.input` and no claim |
| `libfuzzer: timeout`, `libfuzzer: oom`, `libfuzzer: crash` | a `timeout-`, `oom-` or `crash-` file that libFuzzer wrote |
| `libfuzzer: other artifact` | another file that libFuzzer wrote, other than a `slow-unit-` file |
| `worker: killed at a bound` | nothing; the run killed it at the output or time bound |
| `worker: out of memory` | nothing; the kernel killed a process of its cgroup for memory |
| `worker: ended without an input` | nothing |

A worker that the run's stop signal ended is no failure. One memory cause
can appear as `libfuzzer: oom` or as `worker: out of memory`. The
workers' `-rss_limit_mb` lies a quarter below the cgroup limit, so
libFuzzer reports most such inputs first. The kernel kills the cgroup
when its charge reaches the limit before libFuzzer's check, which runs
once a second, or through memory outside the process's RSS.

The first failure of a key is run again once, alone, in a fresh process,
with its input as the only libFuzzer argument, and stored as
`failures/ID/`, where `ID` is the SHA-256 of the key. `rerun` in its line
and in `record.json` is `reproduced` (the same key and, when both runs
kept a bundle, the same digest of the bundle's records other than
checkpoints and diagnostics; for a key with no claim, a nonzero end with
no claim), `diverged`, `unreproduced` (exit 0) or `not run` (no input, a
stop before or during the rerun, or a failure of another build's run).
`record.json` names the run, the build digest, the archive build record's
`revision`, `toolchain`, `cargo`, `environment`, `dirty` and `untracked`,
and both argument lists; the record of a failure that another build's
run left omits those six build fields. A repeat of a key raises its count in
`fuzz.json` and adds no line. After intake, each corpus file with the
failing input's bytes is removed, since it would end every worker that
loads it. Triage a finding as
[the simulation guide](../../docs/agents/simulation.md#triage-a-fuzz-finding)
says.

A root keys 256 keys. The first failure with a new key past them is
stored under the key `other` and ends the run, and every later run of the
root exits 4 before it takes a run number, as every run of a root whose
`alarm` is set does. To go on, start a new root and
move the old root's `corpus/` into it. Keep the old root as the record:
it holds every finding and the missed control's `control/`.

`campaign fuzz` exits by this table:

| Code | Meaning |
| --- | --- |
| 0 | the run ended: at its deadline, by SIGINT or SIGTERM, after 16 failed workers, or at a full key table. `run.json` holds the ending |
| 1 | the planted control was missed: its worker passed, failed another way, was killed at its 600-second or 64 MiB bound, or its rerun did not reproduce it. `alarm` is set in `fuzz.json` and stays set, and no fuzz worker started. The checks let a known failure through, so a run that found nothing proves nothing until this is explained. Every later run of the root exits 4 before it takes a run number, so `control/` keeps what the missed control left |
| 2 | refused arguments, a root or archive path with a byte outside `A-Za-z0-9/._=,-`, a root inside the archive, a root that [the host requirements](#host-requirements) refuse, a cgroup root path that is relative, holds a `..` component or holds a non-printable byte, an archive inside the root, an archive that verification rejects, an archived worker that refuses the merge probe, workers whose summed limits reach a limit of the cgroup root or of an ancestor, or a control worker that printed no `inline 8-bit counters` line: the archive's worker has no coverage counters |
| 3 | another command holds the root or the cgroup root |
| 4 | a held record: a corpus past 65,536 files or with an entry that is no regular file, a root whose key table is full, a root whose `alarm` is set, a cgroup root without the cpu, memory and pids controllers, a worker or a worker cgroup that cannot start, a merge probe that cannot run or passes 60 seconds, a failure file of a worker that is no regular file or passes 64 MiB, an artifact directory that is no directory, a corpus that intake cannot list or read, a merge output that cannot be listed, an archive whose verification fails for another cause or that changed during the run, or a failed write. Inspect before retrying |

## Run a supervised campaign

Set up the paths once:

```sh
cargo build --release -p campaign-supervisor -p campaign-monitor
export PATH="$PWD/target/release:$PATH"
STATE=/data/dst/state       # on xfs or ext4
ARCHIVE=/data/dst/archive-1 # must not exist yet
SIM=/data/dst/sim           # run artifacts of sim commands
```

1. **Build the worker archive** from the current checkout. The archive pins
   the worker binary, toolchain, lockfile and revision.

   ```sh
   campaign sim archive --output "$ARCHIVE"
   ```

2. **List the profiles** the worker offers. `admit` accepts a profile marked
   `support=implemented campaign=unqualified` of class `live`, `recovery`,
   or `history` with `expected=pass`. It rejects `control` profiles and
   histories with another `expected` value; calibration runs only the
   `control` profiles that step 5's profiles declare. The sweep runs
   failing histories as controls; ordinary campaign admission rejects
   them. The command prints one JSON line, and
   the worker's listing is its `capabilities` field.

   ```sh
   campaign sim capabilities --archive "$ARCHIVE" --artifacts "$SIM" | jq -r .capabilities | grep '^profile:'
   ```

3. **Configure capacity.** Every key is required and positive. A
   configuration installs when its budgets cover its slots, as the table
   states for `cores`, `memory` and the `artifact_*` keys. Custody enforces
   one CPU, `tree_memory` bytes and `processes` pids on each attempt, so an
   attempt that exceeds its share ends in its own limit class.

   ```sh
   campaign configure --state "$STATE" \
     --set slots=1 --set reserve_slots=1 --set cores=4 \
     --set memory=8589934592 --set tree_memory=2147483648 \
     --set cpu=600 --set wall=900 --set processes=256 \
     --set attempt_output=67108864 --set attempt_inodes=1000 \
     --set artifact_bytes=68719476736 --set artifact_inodes=1000000 \
     --set backlog=100 --set retained_builds=1
   ```

   | Key | Meaning |
   | --- | --- |
   | `slots` | concurrent campaign attempts |
   | `reserve_slots` | concurrent triage steps, held apart from `slots` |
   | `cores`, `memory` | host budget; `slots + reserve_slots <= cores` and `(slots + reserve_slots) * tree_memory <= memory` |
   | `cpu`, `wall` | per-attempt CPU and wall-clock seconds |
   | `tree_memory`, `processes` | per-attempt cgroup memory bytes and pid limit |
   | `attempt_output`, `attempt_inodes` | per-attempt output bytes and files (inodes at most 4094) |
   | `artifact_bytes`, `artifact_inodes` | budget for the charged census of `jobs/`, `attempts/` and `probes/`; `dispatch` stops starting attempts before exceeding it, and each must cover `slots + reserve_slots` fork shares at twice `attempt_output` and twice `attempt_inodes` plus record overhead (15 MiB and 17 inodes per share); a targeted attempt consumes its job's fork shares |
   | `backlog` | `dispatch` and `calibrate` hold when this many failure pins have findings without a latest `resolved` disposition |
   | `retained_builds` | distinct queued archive builds `dispatch` serves at once; `admit` does not check it, and jobs from further builds wait behind a `retained_builds` pause |

   A fork share is one budget unit. An ordinary job has one share. A
   branch target has `1 + siblings * suffixes` shares, at most 65. An
   exploration target has `1 + sum(suffix_children^level for level in
   1..=suffix_depth)` shares; each level holds at most 128 nodes. The
   `target_shares` pause key reports that a targeted job needs more shares
   than available capacity.

   The state directory keeps each job's records in `jobs/<xx>/` and its
   attempts in `attempts/<xx>/<id>/<nnnn>/`, where `<xx>` is the first two
   characters of the job id. The fullest of the 256 shards reaches its bound
   first. An even fill gives a ceiling of about 5.59 million three-file jobs
   or 4.19 million four-file targeted jobs. Each pin adds one stored entry.
   Until a result exists, admission reserves the missing pin and result
   entries: two if neither exists, or one if the pin already exists. Delete an
   old development state directory, or configure a fresh one, before using
   this sharded layout. `storage` reports, for `jobs` and `attempts`, the
   entries of the fullest shard. `dispatch` loads and reconciles only jobs
   without a result record. The census still reads each job with attempts for
   its fork shares, backlog reads failure pins, and calibration recovery can
   read settled admissions when a plan is damaged. A dispatch-owned collect
   pass reads all settled records through its report snapshot; their holds can
   gate reclamation. `findings` and `report` also read settled records. A root
   entry that is not two lowercase hex digits or does not open as a directory,
   and a shard entry that names a job of another shard, are refused by
   `dispatch` in either root. `show` holds them under `jobs/`; `status` and
   `report` hold them in either root, and `status` lists each one's path as a
   held findings row and a release blocker. `findings` stops on them with the
   entry's path. When `attempts/<xx>` does not open as a directory, `dispatch`
   also refuses each unsettled job of that shard, and `status` sets
   `attempts_held` on each job row of that shard. A host fault opening a
   shard, such as `EIO` or `EMFILE`, fails the command instead of holding one
   entry.

   `dispatch` plans storage against a charged census, counted before the first
   start and updated in process as attempts conclude and settlements publish.
   A collect pass with deletions or a new reclaim marker invalidates that
   count; the next storage decision recounts it. Each entry of a `jobs/` shard
   is charged one inode and its length, each concluded attempt one
   `attempt_output` and `attempt_inodes` plus 15 MiB and 17 inodes of records,
   times its job's fork shares, each attempt `collect` reclaimed its records
   and at most 4 MiB and 6 inodes of `attempt_output` and `attempt_inodes` for
   the files its evidence directory keeps, times the same shares. The reduced
   charge requires a `reclaimed` record matching the attempt's finished and
   artifact records, retained files within their declared limits, and every
   named bulk file removed. Interrupted or damaged reclaims keep the concluded
   charge. A host read fault holds the census with the entry path. For each
   attempt with a `reclaimed` record, counting lists its controller, artifacts
   and evidence directories, reads its records and manifest, and checks
   retained file sizes and bulk removal. That startup cost follows the number
   of declared records and streams, with each listing bounded. An admission
   probe is charged its custody output budget, 8 MiB and 16 inodes, with its
   records uncharged. A corpus probe is charged the running-attempt charge. A
   running attempt is charged at twice `attempt_output` and `attempt_inodes`
   plus records, times its job's fork shares. The census charges only the
   entries of `jobs/`, `attempts/` and `probes/`; the shard directories and
   every other root and root file, `findings/`, `triage/`, `corpus/` and
   `calibrations/` among them, are covered by the measured free space only.
   `configure` accepts a lower `attempt_output` or `attempt_inodes` while
   attempts or corpus probes exist, and the census then charges the lower
   value to every concluded attempt and corpus probe, which undercounts those
   written under the higher budget. Custody samples output. An attempt or
   admission or corpus probe stopped for exceeding its output limits retains
   what it wrote between checks, so its directory can exceed its charge. The
   measured `disk` and `disk_inodes` dimensions cover the excess.

   The charged totals grow with every concluded attempt and every probe,
   a repeated `admit` included. `collect` lowers the measured `disk` and
   `disk_inodes` dimensions. Each removed admission probe lowers the charged
   `artifact_*` totals by 8 MiB and 16 inodes. Each completed attempt reclaim
   lowers its charge to records and kept report streams, counted by the next
   storage decision. When a storage dimension would pause a start and no
   attempt or triage step runs, `dispatch` runs one collect pass itself
   (see step 6). When collect reclaims nothing more, raise the exhausted
   `artifact_bytes` or `artifact_inodes` with `configure`. The following
   horizon estimate assumes one-share jobs and no attempt reclamation:
   `(artifact_bytes - job_bytes - probe_bytes - (slots + reserve_slots) *
   running) / concluded` attempts conclude before `artifact_bytes` pauses
   dispatch, where `running` and `concluded` are the two per-share byte
   charges above, `job_bytes` is the summed length of the `jobs/` entries,
   and `probe_bytes` is 8 MiB per admission probe plus `running` per corpus
   probe. Every `admit` adds its probe and job records to those terms.
   The same formula over inodes gives the `artifact_inodes` horizon:
   `job_inodes` is one per `jobs/` entry, `probe_inodes` is 16 per admission
   probe plus the in-flight inode charge per corpus probe, and the running
   and concluded terms use their per-share inode charges. Collect lowers
   the probe terms while retaining one removable verified source per build.

4. **Admit jobs.** Each `admit` probes the archive and queues one job for
   one profile and run number. Repeating the same request prints
   `"state":"existing"` and queues nothing.

   ```sh
   for run in 1 2 3 4; do
     campaign admit --state "$STATE" --archive "$ARCHIVE" \
       --profile upload --campaign nightly --run "$run" --attempts 3
   done
   ```

   `--set KEY=COUNT` overrides a profile's held count (for example
   `--set turns=64`). `--campaign calibration` is reserved.

   `admit` exits 4 before it creates a probe when `probes/` holds the scan
   bound of 65,536 entries, and before it writes a job when the job's
   entries and the settlement entries queued jobs reserve would take
   `jobs/<xx>` past the bound. The stderr count includes settlement reservations,
   so it can exceed the entry count in `show`. The line names the shard and
   bound, as step 6 describes. For `probes/` at exactly the bound, preview
   `campaign collect --state "$STATE" --dry-run`, then run it without
   `--dry-run` and retry admission. Collection permanently removes eligible
   attempt bulk and launcher logs as well as redundant probes. If probes
   remain at the bound, inspect `held` and `probes.kept`; retained corpus
   probes and listing sources can require a new state directory. A probes
   listing above the bound also holds collect before deletion. For that
   overflow or a full `jobs/<xx>` shard, preserve the held state directory
   and configure a new one with its own delegated cgroup root.

5. **Calibrate a profile (optional).** Calibration runs a `live` or
   pass-expecting `history` profile together with its declared fault
   controls and records the verdict and the capacity it measured for that
   archive build, profile and held counts. `campaign report` credits a
   profile from that record. Only a profile with declared controls can earn
   a `calibrated` record: today `upload`, `long`, `rekey`, `cluster-broad`
   and `cluster-long`. `cluster-pressure` declares controls but records a
   missing control for early slot reuse, so it stays `uncalibrated`. For
   any other `live` or pass-expecting `history` profile the run exits 0
   with `"verdict":"uncalibrated"`. `calibrate` refuses `recovery` and
   `control` profiles with exit 2. A control ends `unsuccessful` on a seed
   where its plant takes no effect, and that run's verdict is `refused`;
   calibrate again with another `--run`.

   ```sh
   campaign calibrate --state "$STATE" --archive "$ARCHIVE" --profile upload --run 1
   ```

   Pass `calibrate` the same `--set` overrides the queued jobs use, so the
   counts match.

6. **Dispatch.** `dispatch` starts queued jobs until none can start, waits
   for the running attempts and triage steps, then exits. It also runs
   automatic triage of failures in the reserve slots. Run it inside a `tmux`
   or `screen` session started from the delegated shell on long campaigns.

   ```sh
   campaign dispatch --state "$STATE" --archive "$ARCHIVE"
   ```

   When a storage dimension would pause a start and no attempt or triage
   step runs, `dispatch` first runs one collect pass through the same
   function as `campaign collect`. Dispatch gives the first pass of a
   consecutive run a budget of 256 deletions, counting a probe directory as
   one unit. It checks for a signal, a failed signal read or the window
   deadline before each attempt-file removal and before each whole
   probe-removal unit; a probe’s files finish as one unit. The snapshot and
   plan read the whole store, so the
   deletion budget bounds deleted units, with elapsed time depending on store
   size. Standalone `campaign collect` runs the full pass with an unlimited
   deletion budget and a stop predicate that stays clear.

   Dispatch then re-evaluates storage, recounting its census after deletions
   or a new reclaim marker. A marker-only reclaim can lower the charge while
   `collect_deletions` stays zero. It starts when every dimension clears. It
   pauses when only the measured `disk` or `disk_inodes` dimension still
   fires. It holds, exits 4 and prints `<dimension> exhausted and collect
   reclaims nothing; raise it with configure` when the pass reached its sweep
   and attempt plan's end and changed nothing, and an `artifact_*` dimension
   still fires. The first remaining held diagnostic is named after that remedy
   when present. A hold-gated pass, a busy hardware snapshot lock or
   insufficient reclaim-marker headroom leaves admission paused and
   `collect_finished` false. `collect --dry-run` previews identity and record
   holds. A real pass that lacks marker headroom names the attempt under
   `held` in standalone `campaign collect`, with required free bytes and
   inodes; restore free space and retry. Dispatch prints the pass totals and
   completion flag. Use standalone collect to inspect its held rows. SIGINT or
   SIGTERM, or the deadline, ends the window as `interrupted` or `deadline`.
   Store holds, undeclared record kinds and host faults hold dispatch with
   exit 4. While the window remains open, a productive pass that leaves a
   storage pause requests another pass on the next loop iteration. Each
   pass requested this way has twice the deletion budget of the pass before
   it: 256, 512, 1024 and so on. Every pass takes one whole-store snapshot,
   and ten consecutive passes delete up to 261,888 units. The
   budget returns to 256 once an attempt or triage step runs. Ordinary
   and triage admission share one pass per iteration; collection runs while
   every attempt and triage step is released. `collect_passes` counts
   attempted passes; `collect_deletions` sums deletions returned in pass
   outcomes. A pass that errors can leave earlier deletions outside that
   total. `collect_finished` gives the last attempted pass's completion flag,
   or `null` before any pass or on a collection error. Hardware lock
   contention, hold-gated plans, marker-headroom stops and a pass stopped by a
   failed signal read record an unfinished pass (`false`), while other errors
   record `null`.

   A job cannot start while admission is paused on a limit, when its fork
   shares exceed capacity, or when the queue holds jobs from another archive
   build. `dispatch` then exits 0 with jobs still queued. Exit 0 says nothing
   about the queue. `campaign status --state "$STATE"` does: a job whose
   `state` is `queued` or `waiting` has not settled. The JSON report
   `dispatch` prints explains why: `state` names the branch that ended the
   admission loop (`queue_empty`, `paused`, `held`, `deadline`,
   `max_attempts`, `interrupted` or `rejected`), and `paused` names every
   limit the run met (for example `artifact_bytes`, `artifact_inodes`, `disk`,
   `disk_inodes`, `retained_builds` or `archive`), including `slots` and
   `target_shares`, which clear on their own as attempts finish, and `unfit`
   samples excluded jobs. `paused` keeps a limit the window met and passed, so
   any final state can retain a non-empty `paused`; `state` alone names the
   final branch. `pauses` counts the start decisions each dimension paused.
   The report keeps the newest attempt completions in `completed` and the
   newest triage completions in `triage_completed`. Each list holds at most
   64 entries whose JSON encodings sum to at most 512 KiB, and drops its
   oldest entries past either limit; a completion larger than 512 KiB empties
   its list. `counts` holds the window's completions per class, triage ones
   under `triage`, so it can exceed the length of a list. Each diagnostic
   field (`unfit`, `calibration_held`, `triage_skipped`,
   `refusals`, `rejections`) keeps at most 16 rows. Maps keep the greatest 16
   ids in order; refusal and rejection lists keep their first rows, preserving
   the cause that stopped admission. `diagnostics_omitted` counts dropped row
   visits per field, so repeated visits can count the same id. Admission keeps
   its complete exclusion and skip sets separately from these report samples.
   Every report list remains bounded across a window. `storage.roots` maps
   each of `attempts`, `findings`, `jobs`, `probes` and `triage` that exists
   to its `entries` and the scan `bound` of 65,536. For `jobs` and `attempts`,
   `entries` counts the fullest shard; for the other roots, it counts
   top-level entries. `storage.free_bytes` and `storage.free_inodes` give
   measured free space; `campaign show` prints the same object. In a dispatch
   report `storage` is `null` when its measurement failed. `refusals` names
   the failure within its first 16 causes; further causes contribute to
   `diagnostics_omitted.refusals`. The charged census lists the `jobs/` and
   `attempts/` roots, each `jobs/<xx>` and `attempts/<xx>` shard, each
   `attempts/<xx>/<id>` history and `probes/`. Attempts with a `reclaimed`
   record also list their controller, artifacts and evidence directories for
   retained-file checks. A job's attempt listing can hold while every
   `storage.roots` count is below the bound. Clear the cause, then rerun
   `dispatch`: raise the named
   limit with `configure`, collect admission probes to lower charged artifact
   totals and reclaim settled attempt bulk, free disk space for `disk` or
   `disk_inodes`, or dispatch the other archive.

   The scan bound and `backlog` hold rather than pause: `dispatch` lets
   running attempts finish and records them, exits 4, and prints its
   `refusals` entries on one stderr line, each separated from the next by a
   semicolon and a space. The line carries the first 16 refusals; when more
   occurred it ends with `omitted refusals: <n>`. `triage`, `calibrate`
   and `corpus add` end their recovery hold line the same way. After a scan-bound hold or an artifact exhaustion
   hold `dispatch` starts nothing more. The exhaustion hold comes from a
   storage decision made while nothing runs. A job start reserves
   `reserve_slots` charges beyond its own and a triage step reserves none, so
   a job start can hold the window at a limit where a triage step fits; a
   window that reaches no job start runs that step. A `backlog` hold stops job
   starts only: automatic triage keeps
   running in the reserve slots, since a triage step adds no failure pin,
   and `dispatch` exits 4 once the running attempts and triage steps finish.
   `dispatch` checks `backlog` each time a queued job is about to start,
   so the hold appears in the first window that reaches a start. A
   charged census holds when a listing reaches the scan bound; other
   listings hold when they exceed it. The message is `<root> holds <n>
   entries at bound <b>; collect or shard` (`more than <b>` when a listing
   found more). The census names a `jobs/<xx>` or `attempts/<xx>` shard,
   or `attempts/<xx>/<id>` for a job's attempt listing; a full
   `findings/<id>` disposition directory or a `triage/<id>/steps` listing
   past the bound names that directory as the root. A charged census that
   fails to list, open or read an entry holds with
   `census of <path>: <cause>`, where `<path>` names what to repair: the
   `jobs`, `attempts` or `probes` root, a `jobs/<xx>` or `attempts/<xx>`
   shard, a `jobs/<xx>/<entry>` or `attempts/<xx>/<id>` entry, or the
   `jobs/<xx>/<id>.json` record. A `jobs/<xx>` or `attempts/<xx>` entry
   that does not open as a directory holds with `<path>` naming its root
   and the cause naming the entry:
   `census of jobs: a listing holds the foreign entry "jobs/<xx>"`.
   Host faults in reclaim evidence name the retained entry, including its
   artifact or manifest path. Damage or an overfull directory inside an
   attempt keeps its concluded charge; the census still holds on shard
   and history listing bounds. Other nested listings past the bound print
   `a listing exceeds its scan bound`. Each
   pending-finding listing is bounded on its own and prints
   `<root> holds <n> entries at bound <b>; collect or shard` past it. A
   measured whole-tree census used by `collect` and hardware admission
   holds at 64 levels of nesting with `a census found a directory nested
   64 levels deep`. Hardware admission compares measured bytes and inodes
   of every root against `artifact_*`, and holds past 65,536 total entries.
   These measured totals differ from dispatch's declared charges. The bound
   and the depth are fixed, so `configure` cannot raise them. A `jobs/<xx>`
   or `attempts/<xx>` shard reaches the bound at 65,536 entries, and
   `collect` removes no `jobs/` entry or attempt history, so neither
   `collect` nor any sharding command clears a shard at the bound: preserve
   the held state directory and configure a new one for further work.
   `backlog` counts the failure pins
   whose finding has no latest `resolved`
   disposition; at the limit `dispatch` and `calibrate` print `dispose
   findings or raise backlog`. Only a `resolved` disposition lowers the
   count, so `harness` and `release-blocker` leave it unchanged. Dispose
   the findings `resolved` with `campaign dispose` or raise `backlog` with
   `configure`.

   `--for SECONDS` is an admission deadline. A collect pass finishes its
   whole-store snapshot and plan before its next deletion check, so those
   reads can extend the window past the deadline. No attempt starts after
   it, and
   attempts still running at the deadline are killed and recorded as
   interrupted. An interrupted job stays queued while it has attempts left
   under its `--attempts` limit; when the deadline killed its last attempt,
   the interrupted result is final and the job leaves the queue.
   `--max-attempts N` stops starting attempts after N and lets running
   attempts finish. Rerun `dispatch` to continue; it reconciles what the
   previous run left.

   Only one controller holds the state directory at a time. `admit`,
   `calibrate`, `configure`, `triage` and `dispose` exit 3 while `dispatch`
   runs. Admit more jobs after it exits.

## Monitor and triage

Watch the campaign from another terminal while `dispatch` runs. A new
terminal starts without the setup block's variables, so set them again:

```sh
export PATH="$PWD/target/release:$PATH"   # from the checkout
STATE=/data/dst/state
campaign-monitor --state "$STATE"
```

See [`campaign-monitor`](../campaign-monitor/README.md) for the keys and
tabs. `campaign status --state "$STATE"` prints the same snapshot as JSON;
it takes no lock, so it runs beside `dispatch`.

After `dispatch` exits, return to the delegated shell (or its `tmux -L dst`
session) and act on findings; `triage` needs `CAMPAIGN_CGROUP_ROOT` and a
process inside the delegated cgroup:

```sh
campaign findings --state "$STATE"
campaign triage --state "$STATE" --from-run <finding> --step replay   # or rerun, reduce
campaign dispose --state "$STATE" --finding <finding> \
  --disposition resolved --evidence "fixed in <commit>"               # or harness, release-blocker
campaign report --state "$STATE"
```

`campaign collect --state "$STATE"` frees space. It removes empty probe
directories and redundant finished admission probes whose reservation and
cgroup are gone. `campaign report` declares each archive build's profiles
from the last completed probe, by name, whose capability listing verifies,
so collect keeps the last removable probe per build whose listing verifies
as a source. Without a verified probe, a verified attempt can supply the
build declaration. To parse and credit an inspection, the report uses the
selected attempt's bound listing when capabilities exits 0 without a signal
and the launcher records another worker phase. That phase establishes that
the capabilities phase passed its closing checks. For an eligible phase,
missing, non-UTF-8 or digest-mismatched stdout, or a refused listing, holds
the job. A host I/O fault reading the stream stops the report. Without an
eligible phase, the report can use a verified same-build listing. The chosen
listing must match the job's frozen capability version. The ordinary profile
row takes its declaration from the compatible build listing; a job can earn
credit under its own listing even if the profile row is undeclared.
A later verifying probe held for an extra entry can also
supply the report's declaration. Corpus probes stay. The sweep deletes only
the names the probe's records list: the evidence the artifact record names,
the launcher streams, `started`, `intent` and `finished`, then the directory.
A probe with a reservation, a live cgroup, no `finished` record, damaged
lifecycle records, an unlisted entry, a foreign mark, staged evidence,
evidence beside a missing nested `.state` marker, `artifacts` with no
`started` record, a stream missing after an earlier listed stream,
a started probe's `launcher.stdout` with no `launcher.stderr`, `artifacts`
beside a missing
launcher stream,
an oversized stream or a stream digest mismatch keeps its directory. `probes.kept`
lists each kept probe with `probe`, `code` and `reason`; `code` is
`listing-source` for a verified source, or the error's held code for a
refusal. `probes.removed` lists removed probe directories, or the directories a
real run would remove under `--dry-run`. `probes.swept`
is true when the sweep ran and false when a root-level hold skipped it. A rerun after a
kill finishes the same removal.

Collect then reclaims each matching attempt of a settled, untargeted
campaign job. It keeps attempts named by the job's pin, a captured finding,
a finding directory or a triage step, and every non-matching attempt.
Calibration jobs and targeted jobs keep their bulk; a targeted job's
judgment is read from its fork output. An unreadable artifact record keeps
its job's files and is reported, while other verified jobs remain collectible.
Unknown entries or staged evidence keep their own attempt's files. Retained stdout
must be declared by the artifact and fit the stream limit, and the kept
manifest must match its digest.

A reclaim deletes the artifact record's declared bundle and worker streams
and both launcher logs. It keeps every record, the artifact record and
manifest, and `inspect.stdout` and `capabilities.stdout`, which supply report
measurements and build declarations. Before deleting the first bulk file,
collect writes a create-once `reclaimed` record with the attempt number,
finished-record digest and bulk name list. A killed pass resumes that list
on rerun. A pass syncs an existing `reclaimed` record and its directory
again before deleting more bulk. A failed sync stops deletion.
An eligible attempt with empty bulk receives a `reclaimed` record even
when it has no files to delete. Readers that see the record read the kept
evidence records and report streams, and hold an attempt whose artifact
record names another attempt, command, manifest or build. They never hash
the reclaimed bulk.

Reclaiming is one-way for the state directory. A `campaign-supervisor`
build older than the `reclaimed` record requires the bundle and every
declared stream on disk, so its `report` holds each job that lost a bulk
file and its `collect` then keeps every attempt launcher log in place. Run
`collect --dry-run` to list the attempts under `reclaimed` before the first
real pass, and read that state directory afterwards only with a build that
knows the `reclaimed` record.

For unsettled or targeted campaign jobs, collect deletes launcher logs of
matching finished attempts when the job has neither a finding nor an
unfinished or non-matching attempt. An unsettled ordinary attempt's evidence
also passes the retained-file layout checks before its logs are deleted.
It takes the state directory's lock,
so it exits 3 while `dispatch` runs. The JSON lists all attempt bulk and
launcher-log removals under `entries`, their totals as `freed_bytes` and
`freed_inodes`, and the attempts whose marker publication or first removal
ran under
`reclaimed`, including partial groups and marker-only reclaims.
`held` names the rows that kept evidence in place. Probe removals appear
separately under `probes` and contribute to the whole-state `before` and
`after` counts. The freed and projected totals count attempt files only.

Collect checks the report snapshot and hardware lock before sweeping probes.
When `hardware/` exists, a pass holds that directory's lock shared until it
returns, in `campaign collect` and in a `dispatch` pass alike, so a `hardware`
command that opens `hardware/` as its controller during the pass exits 3.
Rerun it after the pass.
Root-level and state-wide holds stop all deletion. A subtree hold allows
unrelated admission probes to be swept. A verified settled campaign job's hold
and a queued targeted job's damaged frozen input keep that job's files; other
subtree holds stop attempt deletion. Every diagnostic row under `probes/`
allows the admission sweep; a surviving row stops attempt deletion. An empty
probe the sweep removes releases its report hold. Diagnostic subtree holds
exit 0; an undeclared state-root entry, a held store row or a host fault exits
4. Other root-level diagnostic holds exit 0 with `probes.swept` false and
every entry intact. A recheck, staged-file cleanup or removal error also exits
4 after any earlier deletions; those deletions remain, and a rerun finishes
the pass. Attempts with an existing `reclaimed` record and launcher-only
cleanup run before attempts that need a new record, so available cleanup runs
before record publication needs more space.

`--dry-run` verifies the snapshot and removal identities, changes no
entries, and reports the
totals of `entries` as `projected_bytes` and `projected_inodes`, and the
attempt paths whose marker publication or first removal was simulated
under `reclaimed`. Dispatch summarizes its passes with `collect_passes`,
`collect_deletions` and `collect_finished`. Standalone `campaign collect`
prints the `entries`, `reclaimed` and `held` rows for operator inspection.
A real pass checks free space before
writing a new reclaim marker, after removing that target’s interrupted
staged file. It stops before the write when one inode or the record’s
bytes rounded up to its filesystem allocation unit are unavailable,
names the attempt and missing
headroom under `held`, and exits 0. Free disk space and rerun collection.
Dry runs preserve staged files and preview removals without publishing
markers or checking allocation headroom. The free-space check estimates
allocation capacity; filesystem overhead or another writer can still
cause a publication error, which holds the controller with exit 4.
`collect` measures the whole state directory before it deletes and again
afterwards, as `before` and `after`; each is `null` when that walk passes
the scan bound, and collect still runs, since its own listings are bounded
per directory. When a measurement finds a directory nested 64 levels deep
or fails otherwise, `collect` exits 4, before its deletions for the first
measurement and after them for the second.

## Runbook

Here `in_flight` is the running-attempt charge from step 3, and `retained`
is its concluded-attempt charge. Both include the job's fork shares.

**Cgroup root.** `admit`, `calibrate`, `corpus add`, `dispatch` and
`triage` need the delegated cgroup-v2 directory from
[Host requirements](#host-requirements), named by `--cgroup-root` or
`CAMPAIGN_CGROUP_ROOT`. Give each active or unreconciled state directory
its own delegated root. The command moves itself into its `controller/`
child and creates one sibling group per attempt, probe or triage step.
Every process in the root outside its `sweep/` child, which a `sweep` or
a `fuzz` run owns, must belong to that controller's custody.

These refusals identify groups the selected state could not reconcile:
`cgroup without job record`, `unrecorded custody tree`,
`custody contains unrecorded probes`, `attempt cgroup remains before
settlement`, `attempt cgroup remains after reconciliation`, and
`cgroup lacks matching started`. An accompanying job refusal can identify
recorded ownership. Inspect the selected state's records and any other
state using that root, check for competing controllers, and preserve the
group's diagnostics. Remove a group manually only after proving it is
unused, empty and released. Stop on recorded or uncertain ownership,
populated groups or a failed check. Recorded or uncertain ownership blocks
manual removal. The state-directory owner must preserve the records and
group diagnostics and arrange repair before resuming that state. Further
work can use a new state directory with its own delegated root.

**Stopping the controller.** An interrupted attempt still spends one
attempt from the job's `--attempts` budget. A job interrupted on its last
allowed attempt settles with a final `interrupted` result and leaves the
queue, as step 6 explains. Send SIGTERM or SIGINT to `dispatch` to stop
new starts and record running attempts and triage steps as interrupted.
The window exits with state `interrupted`. A collect pass samples the signal
before each deletion unit and completes a unit already in progress. Its
whole-store snapshot and plan finish before that next check; their duration
grows with the store. Rerun dispatch to resume
jobs that remain unsettled. A stopped collect pass resumes on its next
pass or `campaign collect`. SIGKILL and other terminating signals besides
SIGINT and SIGTERM preserve already durable records and release the lock,
with no final report. A kill between cgroup creation and the `started`
record can leave `cgroup lacks matching started`. The attempt's `intent`
records ownership, so the ownership rule above blocks manual removal even
when `cgroup.events` reports `populated 0`. That state remains held for its
owner to repair; preserve it and use a new state directory and delegated
root for further work.

**Reading `storage`.** `dispatch`'s report and `campaign show` print
`storage`: `roots` gives top-level entries, the fullest shard for `jobs`
and `attempts`, against the scan `bound`; `free_bytes` and `free_inodes`
give measured free space. For a `probes` root near the bound or low disk
space, preview `campaign collect --state "$STATE" --dry-run`. A real run
permanently removes eligible settled attempt bulk and launcher logs as
well as redundant probes. Inspect `held` and `probes.kept` when collection
keeps a probe. Retained corpus probes and verified listing sources can
keep the root full; preserve the state and start a new one with a separate
delegated root if permitted cleanup leaves it at the bound. A diagnostic
hold requires inspection of its named evidence. Other roots near their
fixed bounds require a new state directory; measured disk headroom can
also be restored by freeing external files or adding capacity.

**Exit 4.** A bound message, `<root> holds <n> entries at bound <b>;
collect or shard`, identifies a full listing. `probes` at exactly the
bound can be collected with the preview and checks above. The form
`holds more than <b> entries at bound <b>` means the listing exceeds the
bound; collect refuses an overflowing probes listing before deleting.
For that overflow, or a full `jobs/<xx>` or `attempts/<xx>` shard or
`attempts/<xx>/<id>` attempt listing, preserve the held directory and
start a new state with its own delegated root. `findings` and `triage`
bounds come from capture and listing paths, while the charged census
reads `jobs`, `attempts` and `probes`. Preserve full finding and triage
roots and start a new state. `a listing exceeds its scan bound` names a
nested or aggregate listing failure: inspect the held state before
retrying. A backlog message, `dispose findings or raise backlog`, counts
unresolved failure pins; dispose them `resolved` with `campaign dispose`
or raise `backlog` with `configure`.

`<dimension> exhausted and collect reclaims nothing; raise it with
configure` means a completed pass that changed nothing left an
`artifact_*` limit full.
Inspect any appended collection diagnostic before raising it. `configure`
replaces the complete settings map. Read the current map at
`config.verified.config` in `campaign show`, carry every setting forward,
including optional `corpus_count` and `corpus_bytes`, and change the named
limit only. Measured `disk` and `disk_inodes` are filesystem headroom, separate from
the declared artifact budgets.

**Horizon.** About `(artifact_bytes - (slots + reserve_slots) * in_flight)
/ retained` one-share attempts conclude before `artifact_bytes` pauses
dispatch, where `in_flight` is the running-attempt charge, twice
`attempt_output` plus records, and `retained` is the charge of a
concluded attempt, one `attempt_output` plus records; collect lowers
`retained` to the reclaimed charge for each attempt it reclaims. The same
formula over the inode charges gives the `artifact_inodes` horizon. Job
records and probes subtract from both, as step 3 states.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | success |
| 1 | `sweep`'s root holds a missed control run, from this sweep or an earlier one of the root, and the totals it prints carry `alarm`; or a profile of the root whose class is not control, a history that expects a failure included, has 64 runs or more and none counted under `pass` or `caught`, and the totals carry `no_pass`; or a profile has at least 64 covered passes and zero reaching passes for a required event, and the totals carry `unreached`; or the root's counts set `restarts` to 20 or more, a profile with 64 runs or more has a planned crash window with a zero total or a total that sums distinct counted rows under a shortened name or `other`, and the totals carry `no_window`; or `fuzz`'s run missed its planted control, and the record it prints has the `ending` `control missed`. No other command exits 1: `calibrate` reports its outcome in the record's `verdict` field, and `dispatch` failures appear in `campaign findings` |
| 2 | arguments or an input record were refused |
| 3 | another controller holds the state directory, or another sweep holds the sweep's root, or another sweep or a fuzz run holds its cgroup root |
| 4 | a record or the store is held, or `admit`, `calibrate`, `collect` or `dispatch` reached the scan bound or `backlog`, or `dispatch` exhausted an artifact limit after an empty completed collect pass; `dispatch` records the attempts it was running before it exits. Inspect before retrying |

`campaign fuzz` has [its own table](#fuzz-the-archived-worker).

`campaign sim` commands use their own codes:

| Code | Meaning |
| --- | --- |
| 0 | the result counts; for `sim archive`, the archive is published and verified |
| 1 | the run completed with a result that earns no credit |
| 2 | refused arguments or inputs |
| 3 | the archive build failed |
| 4 | the run ended without a complete result; for `sim archive`, the archive earns no use |
| 5 | a signal stopped the run |
| 6 | the run outlived its watchdog |
